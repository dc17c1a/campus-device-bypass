package main

// UDP 门：nft 把 STUN（3478/5349/19302 三端口 + 跨端口标准魔数）与 UDP 80/8080 DNAT 到这里。
// serveUDP 先判 od.port == 80 → proxy/port80_udp，否则走 classifyUDP（标准魔数 + 变种包型）。
// 中继条件 verdict == "proxy" 即中继：STUN 形状全进 proxy，非 STUN 残渣才直连回源。
// 非 STUN（STUN 端口上的混淆包，如 119.147.3.x）-> 直连 dial。
// fail-closed：proxy 建连失败即丢包（gate_proxy_udp_fail），不回退直连。宁断不错放。

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	udpListenAddr = envStr("WD_UDP_LISTEN", "0.0.0.0:12348")
	// WD_UDP_FIXED_DST 仅调试：设为 ip:port 后跳过 origdst，直接用它当中继目的。
	// 默认空 = 生产行为（IP_RECVORIGDSTADDR 随包 cmsg，见 udpRecv）。procd 未设此 env，重启即关闭。
	udpFixedDst  = envStr("WD_UDP_FIXED_DST", "")
	udpAssocIdle = 120 * time.Second
	udpAssocMax  = 512
	udpMu        sync.Mutex
	udpTable     = map[string]*udpAssoc{}
)

type udpAssoc struct {
	key       string
	client    *net.UDPAddr
	dst       dstAddr
	up        *net.UDPConn
	tcp       net.Conn // proxy SOCKS5-UDP associate 控制连接；直连时为 nil
	toProxy   bool
	reason    string
	start     atomic.Int64 // unixnano（uclose dur 基准）
	last      atomic.Int64 // unixnano
	pkts      atomic.Uint64
	upPkts    atomic.Uint64
	downPkts  atomic.Uint64
	upBytes   atomic.Uint64
	downBytes atomic.Uint64
	closeOnce sync.Once
}

// classifyUDP 纯函数（可单测）：标准 STUN 魔数 / 变种包型 / 其他。
func classifyUDP(b []byte) (string, string) {
	if len(b) < 20 {
		return "direct", "udp_short"
	}
	// 标准 STUN：魔数 21 12 a4 42 + 首 2bit 为 0（排除 RTP/DTLS 等）。
	if b[4] == 0x21 && b[5] == 0x12 && b[6] == 0xa4 && b[7] == 0x42 && b[0]&0xC0 == 0x00 {
		return "proxy", "stun_udp"
	}
	// 变种 STUN（实测 110.43.86.x 系）：Binding Request 0001 / Response 0101，
	// transaction 配对，魔数位按流变化。0001/0101 + 20B 在随机流量中碰撞≈0，
	// 后果也只是绕路 proxy（可达），故首包即判。
	if (b[0] == 0x00 || b[0] == 0x01) && (b[1] == 0x01 || b[1] == 0x02) {
		return "proxy", "stun_udp_var"
	}
	return "direct", "udp_direct"
}

// udpVerdict 先判 od.port == 80 → proxy/port80_udp，否则走 classifyUDP。
// 8000-9000 兜底：STUN 形状保持原归因，仅 direct 残渣翻 proxy/default
// （fail-closed，assoc 失败即丢包；reason 复用 default）。
func udpVerdict(od dstAddr, b []byte) (string, string) {
	if od.port == 80 {
		return "proxy", "port80_udp"
	}
	v, r := classifyUDP(b)
	if v == "direct" && od.port >= 8000 && od.port <= 9000 {
		return "proxy", "default"
	}
	return v, r
}

// originalDstUDP 已废弃：getsockopt(SO_ORIGINAL_DST) 只能用在“已连接”套接字上
// （TCP accept 出来的每连接 socket，4 元组齐全，内核能定位 conntrack）。
// UDP 监听 socket 未连接、远端不确定，调它恒报 EPROTONOSUPPORT（实测 225+ 全灭，
// 与双栈/单栈无关——udp4 单栈同样失败）。UDP 取真实目的唯一正解是随包 cmsg，
// 见 enableRecvOrigDst + recvUDPPacket（IP_RECVORIGDSTADDR + recvmsg）。
// origDstFromSC 保留给 TCP 版 originalDst（main.go）用。
func originalDstUDP(c *net.UDPConn) (dstAddr, error) {
	return dstAddr{}, fmt.Errorf("udp origdst via getsockopt unsupported, use recvmsg cmsg")
}

// IP_RECVORIGDSTADDR / IP_ORIGDSTADDR（Linux 均为 20）：让内核把每个 UDP 包的
// 真实目的（DNAT 前）随包放在 cmsg 里。这是未连接 UDP 套接字取 origdst 的唯一正解。
const (
	ipRecvOrigDstAddr = 20
	ipOrigDstAddr     = 20
)

// enableRecvOrigDst 打开套接字的 IP_RECVORIGDSTADDR。
func enableRecvOrigDst(srv *net.UDPConn) error {
	sc, err := srv.SyscallConn()
	if err != nil {
		return err
	}
	var oerr error
	cerr := sc.Control(func(fd uintptr) {
		oerr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipRecvOrigDstAddr, 1)
	})
	if cerr != nil {
		return cerr
	}
	return oerr
}

// cmsgAlign = CMSG_ALIGN（64 位 Linux 按 8 对齐）。
func cmsgAlign(n int) int { return (n + 7) & ^7 }

// parseOrigDst 从 recvmsg 的 oob 里找 IP_ORIGDSTADDR，解析出 sockaddr_in。
// 纯函数，可单测。
func parseOrigDst(oob []byte) (dstAddr, bool) {
	hdrLen := int(unsafe.Sizeof(syscall.Cmsghdr{}))
	for len(oob) >= hdrLen {
		h := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if h.Len < uint64(hdrLen) {
			break
		}
		if int(h.Len) > len(oob) {
			break
		}
		if h.Level == syscall.IPPROTO_IP && h.Type == ipOrigDstAddr {
			d := oob[hdrLen:h.Len]
			if len(d) >= 8 && d[0] == 2 { // AF_INET
				port := int(binary.BigEndian.Uint16(d[2:4]))
				if port != 0 {
					return dstAddr{ip: net.IPv4(d[4], d[5], d[6], d[7]), port: port}, true
				}
			}
			return dstAddr{}, false
		}
		oob = oob[cmsgAlign(int(h.Len)):]
	}
	return dstAddr{}, false
}

// udpRecv 读一个包，返回载荷长度/源/真实目的。单 goroutine 循环内复用 buf/oob。
func udpRecv(srv *net.UDPConn, buf, oob []byte) (int, *net.UDPAddr, dstAddr, error) {
	sc, err := srv.SyscallConn()
	if err != nil {
		return 0, nil, dstAddr{}, err
	}
	var n, oobn int
	var from syscall.Sockaddr
	var rerr error
	cerr := sc.Read(func(fd uintptr) bool {
		var e error
		n, oobn, _, from, e = syscall.Recvmsg(int(fd), buf, oob, 0)
		if e == syscall.EAGAIN {
			return false
		}
		rerr = e
		return true
	})
	if cerr != nil {
		return 0, nil, dstAddr{}, cerr
	}
	if rerr != nil {
		return 0, nil, dstAddr{}, rerr
	}
	sa4, ok := from.(*syscall.SockaddrInet4)
	if !ok {
		return 0, nil, dstAddr{}, fmt.Errorf("udp src not inet4 %T", from)
	}
	caddr := &net.UDPAddr{IP: net.IPv4(sa4.Addr[0], sa4.Addr[1], sa4.Addr[2], sa4.Addr[3]), Port: sa4.Port}
	od, ok := parseOrigDst(oob[:oobn])
	if !ok {
		return n, caddr, dstAddr{}, fmt.Errorf("no origdst cmsg oobn=%d", oobn)
	}
	return n, caddr, od, nil
}

// origDstFromSC 给 TCP 版 originalDst（main.go）用：accept 出来的已连接 socket
// 上 SO_ORIGINAL_DST 正常工作。UDP 不许再调（见上）。
func origDstFromSC(sc syscall.RawConn) (dstAddr, error) {
	var sa struct {
		Family uint16
		Port   [2]byte
		Addr   [4]byte
		Zero   [8]byte
	}
	var serr error
	cerr := sc.Control(func(fd uintptr) {
		l := uint32(unsafe.Sizeof(sa))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&l)), 0)
		if e != 0 {
			serr = e
		}
	})
	if cerr != nil {
		return dstAddr{}, cerr
	}
	if serr != nil {
		return dstAddr{}, serr
	}
	port := int(binary.BigEndian.Uint16(sa.Port[:]))
	if sa.Family != 2 || port == 0 {
		return dstAddr{}, fmt.Errorf("origdst invalid family=%d port=%d", sa.Family, port)
	}
	return dstAddr{ip: net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]), port: port}, nil
}

// firstBytes 前 k 字节（日志用，避免大包刷屏）。
func firstBytes(b []byte, k int) []byte {
	if len(b) > k {
		return b[:k]
	}
	return b
}

func socks5UDPAssociate(proxy string, od dstAddr) (*net.UDPConn, net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	tc, err := d.Dial("tcp", proxy)
	if err != nil {
		return nil, nil, err
	}
	fail := func(e error) (*net.UDPConn, net.Conn, error) {
		tc.Close()
		return nil, nil, e
	}
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := tc.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(tc, r); err != nil {
		return fail(err)
	}
	if r[0] != 5 || r[1] != 0 {
		return fail(fmt.Errorf("socks udp greet %x", r))
	}
	// CMD=3 ASSOCIATE，地址填 0 由 server 分配 relay 端口。
	if _, err := tc.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(tc, hdr); err != nil {
		return fail(err)
	}
	if hdr[1] != 0 {
		return fail(fmt.Errorf("socks udp assoc rep=%d", hdr[1]))
	}
	var relay *net.UDPAddr
	switch hdr[3] {
	case 1:
		rest := make([]byte, 6)
		if _, err := io.ReadFull(tc, rest); err != nil {
			return fail(err)
		}
		relay = &net.UDPAddr{IP: net.IPv4(rest[0], rest[1], rest[2], rest[3]),
			Port: int(rest[4])<<8 | int(rest[5])}
	case 4:
		return fail(fmt.Errorf("socks udp relay ipv6 unsupported"))
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(tc, lb); err != nil {
			return fail(err)
		}
		rest := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(tc, rest); err != nil {
			return fail(err)
		}
		host := string(rest[:len(rest)-2])
		relay, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host,
			int(rest[len(rest)-2])<<8|int(rest[len(rest)-1])))
		if err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("socks udp atyp=%d", hdr[3]))
	}
	uc, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		return fail(err)
	}
	tc.SetDeadline(time.Time{})
	_ = od
	return uc, tc, nil
}

// socksEncap 封包：RSV(2)+FRAG(0)+ATYP(1)+IPv4+port+payload。
func socksEncap(dst dstAddr, p []byte) []byte {
	ip4 := dst.ip.To4()
	out := make([]byte, 10+len(p))
	out[3] = 1
	copy(out[4:8], ip4)
	out[8] = byte(dst.port >> 8)
	out[9] = byte(dst.port)
	copy(out[10:], p)
	return out
}

// socksDecap 解包，返回内层载荷。
func socksDecap(b []byte) ([]byte, error) {
	if len(b) < 10 || b[0] != 0 || b[1] != 0 || b[2] != 0 || b[3] != 1 {
		return nil, fmt.Errorf("bad socks udp hdr")
	}
	return b[10:], nil
}

func udpAssocKey(client *net.UDPAddr, od dstAddr) string {
	return client.String() + "|" + od.String()
}

// udpPump 回包：upstream -> client。
func udpPump(a *udpAssoc, srv *net.UDPConn) {
	defer a.close()
	rb := make([]byte, 65535)
	for {
		a.up.SetReadDeadline(time.Now().Add(udpAssocIdle))
		n, err := a.up.Read(rb)
		if err != nil {
			return
		}
		p := rb[:n]
		if a.toProxy {
			var derr error
			p, derr = socksDecap(p)
			if derr != nil {
				writeStat("gate_udp_decap_err", 1)
				continue
			}
		}
		a.last.Store(time.Now().UnixNano())
		a.pkts.Add(1)
		a.downPkts.Add(1)
		a.downBytes.Add(uint64(len(p)))
		if _, err := srv.WriteToUDP(p, a.client); err != nil {
			return
		}
	}
}

func (a *udpAssoc) emitUCloseOnce() {
	a.closeOnce.Do(func() {
		start := a.start.Load()
		if start == 0 {
			start = a.last.Load()
		}
		var durMs int64
		if start != 0 {
			durMs = time.Since(time.Unix(0, start)).Milliseconds()
			if durMs < 0 {
				durMs = 0
			}
		}
		src := ""
		if a.client != nil {
			src = a.client.String()
		}
		emitUCloseEvent("udp", src, a.dst, a.verdict(), a.reason, durMs,
			a.upPkts.Load(), a.downPkts.Load(), a.upBytes.Load(), a.downBytes.Load())
	})
}

func (a *udpAssoc) close() {
	udpMu.Lock()
	if cur, ok := udpTable[a.key]; ok && cur == a {
		delete(udpTable, a.key)
	}
	udpMu.Unlock()
	a.emitUCloseOnce()
	if a.up != nil {
		a.up.Close()
	}
	if a.tcp != nil {
		a.tcp.Close()
	}
}

// reapUDPAssoc 清理超 idle 的 assoc，返回清理数（可单测）。
func reapUDPAssoc(idle time.Duration) int {
	now := time.Now().UnixNano()
	var dead []*udpAssoc
	udpMu.Lock()
	for k, a := range udpTable {
		if time.Duration(now-a.last.Load()) > idle {
			delete(udpTable, k)
			dead = append(dead, a)
		}
	}
	udpMu.Unlock()
	for _, a := range dead {
		a.emitUCloseOnce()
		if a.up != nil {
			a.up.Close()
		}
		if a.tcp != nil {
			a.tcp.Close()
		}
	}
	return len(dead)
}

func serveUDP() {
	// udp4 即可（iot 只有 v4）。真实目的不走 getsockopt（监听 socket 上恒败），
	// 走 IP_RECVORIGDSTADDR 随包 cmsg，见 udpRecv。
	pc, err := net.ListenPacket("udp4", udpListenAddr)
	if err != nil {
		log.Printf("udp gate %s: %v (UDP门未启，TCP照常)", udpListenAddr, err)
		return
	}
	srv := pc.(*net.UDPConn)
	if err := enableRecvOrigDst(srv); err != nil {
		log.Printf("udp gate %s: RECVORIGDSTADDR fail %v (UDP门未启，TCP照常)", udpListenAddr, err)
		return
	}
	log.Printf("wxdet-gate udp on %s (proxySocks=%s)", udpListenAddr, proxySocks)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			if n := reapUDPAssoc(udpAssocIdle); n > 0 {
				writeStat("gate_udp_expire", n)
			}
		}
	}()
	buf := make([]byte, 65535)
	oob := make([]byte, 256)
	for {
		n, caddr, od, rerr := udpRecv(srv, buf, oob)
		if rerr != nil {
			writeStat("gate_udp_recv_err", 1)
			// 直写调试文件（绕开 logd，量小：STUN 级）。
			dbg := fmt.Sprintf("%d\t%s\tn=%d\tod=%s\terr=%v\tfirst=%x\n",
				time.Now().Unix(), caddr, n, od.String(), rerr, firstBytes(buf[:max(n, 0)], 16))
			if f, ferr := os.OpenFile("/tmp/wxdet/udp_err.log",
				os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
				f.WriteString(dbg)
				f.Close()
			}
			continue
		}
		if udpFixedDst != "" {
			if h, p, serr := net.SplitHostPort(udpFixedDst); serr == nil {
				if pip := net.ParseIP(h); pip != nil {
					if pn, perr := strconv.Atoi(p); perr == nil {
						od = dstAddr{ip: pip, port: pn}
					}
				}
			}
		}
		if od.port == 0 {
			writeStat("gate_udp_origdst_invalid", 1)
			continue
		}
		// 防环：真实目的永不该是本地/私网/链路地址（STUN/UDP 80 服务器恒为公网）。
		// 否则 direct-dial 会把包写回自己形成自激（自测 FIXED_DST 踩过一次，512 表打满）。
		if od.ip.IsLoopback() || od.ip.IsPrivate() || od.ip.IsLinkLocalUnicast() || od.ip.IsUnspecified() {
			writeStat("gate_udp_local_drop", 1)
			continue
		}
		verdict, reason := udpVerdict(od, buf[:n])
		key := udpAssocKey(caddr, od)
		udpMu.Lock()
		a, ok := udpTable[key]
		if ok {
			a.last.Store(time.Now().UnixNano())
		}
		over := !ok && len(udpTable) >= udpAssocMax
		udpMu.Unlock()
		if over {
			writeStat("gate_udp_table_full", 1)
			continue
		}
		if !ok {
			a = newUDPAssoc(srv, caddr, od, verdict, reason, buf[:n])
			if a == nil {
				continue // 建连失败已记 stat，本包丢弃（fail-closed）
			}
		}
		var out []byte
		if a.toProxy {
			ip4 := od.ip.To4()
			if ip4 == nil {
				continue
			}
			od4 := dstAddr{ip: ip4, port: od.port}
			out = socksEncap(od4, buf[:n])
		} else {
			out = buf[:n]
		}
		a.pkts.Add(1)
		a.upPkts.Add(1)
		a.upBytes.Add(uint64(n))
		if _, err := a.up.Write(out); err != nil {
			emitErrorEvent("udp", caddr.String(), od, "err", a.reason, err.Error())
			a.close()
			writeStat("gate_udp_write_err", 1)
		}
	}
}

// newUDPAssoc 建中继（proxy associate 或直连 dial），失败返回 nil（fail-closed：
// proxy assoc 失败即丢包，不回退直连）。
func newUDPAssoc(srv *net.UDPConn, client *net.UDPAddr, od dstAddr, verdict, reason string, first []byte) *udpAssoc {
	a := &udpAssoc{key: udpAssocKey(client, od), client: client, dst: od, reason: reason}
	now := time.Now().UnixNano()
	a.start.Store(now)
	a.last.Store(now)
	emitOpen("udp", client.String(), od, verdict, reason)
	relay := verdict == "proxy"
	if relay {
		up, tc, err := socks5UDPAssociate(proxySocks, od)
		if err != nil {
			writeStat("gate_proxy_udp_fail", 1)
			logGate(client.String(), od, "err", reason+"_proxy_fail", first)
			emitErrorEvent("udp", client.String(), od, "err", reason+"_proxy_fail", err.Error())
			log.Printf("udp %s -> %s proxy assoc fail (fail-closed): %v", client, od, err)
			return nil
		}
		a.up, a.tcp, a.toProxy = up, tc, true
	} else {
		ip4 := od.ip.To4()
		if ip4 == nil {
			emitErrorEvent("udp", client.String(), od, "err", reason, "non-ipv4 dst")
			return nil
		}
		up, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip4, Port: od.port})
		if err != nil {
			writeStat("gate_udp_dial_err", 1)
			emitErrorEvent("udp", client.String(), od, "err", reason, err.Error())
			return nil
		}
		a.up = up
	}
	udpMu.Lock()
	udpTable[a.key] = a
	udpMu.Unlock()
	writeStat("gate_udp_assoc", 1)
	if a.toProxy {
		writeStat("gate_proxy_udp", 1)
	} else {
		writeStat("gate_direct_udp", 1)
	}
	logGate(client.String(), od, a.verdict(), reason, first)
	go udpPump(a, srv)
	return a
}

func (a *udpAssoc) verdict() string {
	if a.toProxy {
		return "proxy"
	}
	return "direct"
}
