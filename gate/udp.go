package main

// UDP 门：serveUDP 经 udpVerdict 先判 STUN 形状（标准魔数+长度一致/变种形状，
// 任意端口命中即 proxy），非 STUN 再按端口：od.port <= 10000 → proxy/udp_proxy，
// >10000 → direct（classifyUDP 原样理由 udp_direct/udp_short）。
// 中继条件仍 verdict == "proxy" 即中继。verdict 面与旧版逐包一致，唯一差别是
// 低端口 STUN 包的 reason 由 udp_proxy 改记 stun_udp/stun_udp_var（统计更细）。
// fail-closed：proxy 建连失败即丢包（gate_proxy_udp_fail），不回退直连。宁断不错放。
// nft 不动——到不了 gate 的包仍走 TPROXY 原链路。

import (
	"encoding/binary"
	"errors"
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

// recv 错误调试日志（P2-11）：计数由 gate_udp_recv_err 逐包记，日志每进程每 5s
// 最多一条——旧版每个错包 open/close 一次文件，系统性问题会把 tmpfs 刷爆。
var (
	udpErrLogPath     = envStr("WD_UDP_ERR_LOG", "/tmp/wxdet/udp_err.log")
	udpErrLogNs       atomic.Int64
	udpErrLogInterval = int64(5 * time.Second)
)

// udpLocalDropLogNs 本机目的 UDP 丢弃的 gate.log 限速（纳秒时间戳）：计数每次都记，
// 日志 5s 最多一行（与 TCP 侧 logTCPLocalDrop 同口径）。背景：此前 UDP local_drop
// 只有 gate_udp_local_drop 计数器、零采样，22h 累积 2634 个不可归因。
var udpLocalDropLogNs atomic.Int64

func logUDPLocalDrop(src string, od dstAddr, first []byte) {
	now := time.Now().UnixNano()
	last := udpLocalDropLogNs.Load()
	if now-last < int64(5*time.Second) || !udpLocalDropLogNs.CompareAndSwap(last, now) {
		return
	}
	logGate("udp", src, od, "drop", "local_dst", first)
}

// udpErrLog 限速写调试行，返回是否真的落盘。
func udpErrLog(line string) bool { return udpErrLogAt(line, time.Now()) }

// udpErrLogAt 同上，时间可注入（单测）。
func udpErrLogAt(line string, now time.Time) bool {
	last := udpErrLogNs.Load()
	if now.UnixNano()-last < udpErrLogInterval {
		return false
	}
	if !udpErrLogNs.CompareAndSwap(last, now.UnixNano()) {
		return false
	}
	f, err := os.OpenFile(udpErrLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return false
	}
	f.WriteString(line)
	f.Close()
	return true
}

// udpAssoc 状态：建链中 / 就绪 / 已关闭。P2-10 起建链在后台 goroutine 里做，
// 建链期间的包进 pending 有界队列；升级只允许 pass→proxy 单向。
const (
	udpConnecting = iota
	udpReady
	udpClosed
)

// udpPendingMax 建链期间每个 assoc 暂存包上限（溢出丢弃 + gate_udp_pending_drop）。
const udpPendingMax = 8

type udpAssoc struct {
	key    string
	client *net.UDPAddr
	dst    dstAddr
	srv    *net.UDPConn

	start     atomic.Int64 // unixnano（uclose dur 基准）
	last      atomic.Int64 // unixnano
	pkts      atomic.Uint64
	upPkts    atomic.Uint64
	downPkts  atomic.Uint64
	upBytes   atomic.Uint64
	downBytes atomic.Uint64
	closeOnce sync.Once
	toProxy   atomic.Bool

	// mu 保护下面这些字段：up/tcp 会在建链完成与 pass→proxy 升级时换入换出，
	// pending 是建链期间的暂存队列，gen 是 pump 代次（升级后旧泵退出不关 assoc）。
	mu        sync.Mutex
	state     int
	up        *net.UDPConn
	tcp       net.Conn     // proxy SOCKS5-UDP associate 控制连接；直连时为 nil
	spoof     *net.UDPConn // 下行 spoof 发送口（bind 到 od.ip:od.port，见 spoofUDP）
	pending   [][]byte
	upgrading bool
	gen       int64
	reason    string
}

// classifyUDP 纯函数（可单测）：标准 STUN 魔数（+长度一致）/ 变种包型 / 其他。
func classifyUDP(b []byte) (string, string) {
	if len(b) < 20 {
		return "pass", "udp_short"
	}
	// 标准 STUN：魔数 21 12 a4 42 + 首 2bit 为 0（排除 RTP/DTLS 等）+
	// 长度一致（20+msgLen ≤ 包长，宽松口径，防随机碰撞）。
	if b[4] == 0x21 && b[5] == 0x12 && b[6] == 0xa4 && b[7] == 0x42 && b[0]&0xC0 == 0x00 {
		if ml := int(binary.BigEndian.Uint16(b[2:4])); 20+ml <= len(b) {
			return "proxy", "stun_udp"
		}
		return "pass", "udp_direct"
	}
	// 变种 STUN（某系）：Binding Request 0001 / Response 0101，
	// transaction 配对，魔数位按流变化。首包即判（后果只是绕路 proxy）。
	if (b[0] == 0x00 || b[0] == 0x01) && (b[1] == 0x01 || b[1] == 0x02) {
		return "proxy", "stun_udp_var"
	}
	return "pass", "udp_direct"
}

// udpVerdict 进门包总入口（v3：STUN 优先）：先看形状——STUN（标准/变种）
// 任意端口命中即 proxy（经代理入口）；非 STUN 再按端口：≤10000 →
// proxy/udp_proxy，>10000 → pass（classifyUDP 原样理由 udp_direct/udp_short）。
// nft 不动——到不了 gate 的包仍走 TPROXY 原链路。
func udpVerdict(od dstAddr, b []byte) (string, string) {
	if v, r := classifyUDP(b); v == "proxy" || od.port > 10000 {
		return v, r
	}
	return "proxy", "udp_proxy"
}

// originalDstUDP 已废弃：getsockopt(SO_ORIGINAL_DST) 只能用在“已连接”套接字上
// （TCP accept 出来的每连接 socket，4 元组齐全，内核能定位 conntrack）。
// UDP 监听 socket 未连接、远端不确定，调它恒报 EPROTONOSUPPORT（实测 225+ 全灭，
// 与双栈/单栈无关——udp4 单栈同样失败）。
// 另注意：IP_RECVORIGDSTADDR 在本机返回的是 NAT 后目的——
// DNAT 进门包的 cmsg 一律是 192.168.2.1:12348，经防环全进 local_drop、assoc 恒零。
// 故 DNAT+recvmsg 此路在本机不通（assoc 22h+ 零即实证）；UDP 进 gate 必须走 TPROXY
// （不改写目的）+ IP_TRANSPARENT，待修。现网 DNAT 4 规则进门包同样黑洞（切前即如此）。
// origDstFromSC 保留给 TCP 版 originalDst（main.go）用。
func originalDstUDP(c *net.UDPConn) (dstAddr, error) {
	return dstAddr{}, fmt.Errorf("udp origdst via getsockopt unsupported, use recvmsg cmsg")
}

// IP_RECVORIGDSTADDR / IP_ORIGDSTADDR（Linux 均为 20）：让内核把每个 UDP 包的
// 真实目的随包放在 cmsg 里。
// 警告：经 DNAT 进门的包，本机内核给的是 NAT 后目的
// （一律 192.168.2.1:12348，OUTPUT 重定向实测 cmsg=127.0.0.1:12348 亦然）；
// 只有 TPROXY（不改写目的）进门的 cmsg 才是真目的。DNAT 进门中继待修期间，
// parseOrigDst 照常解析（直发本机包的 cmsg 是准的，防环依赖它）。
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

// ipTransparent = IP_TRANSPARENT（Linux 19）：透明套接字开关。TPROXY  divert 的包
// 只投递给 TRANSPARENT 套接字；且只有 TPROXY（不改写目的）路径的 cmsg 才是真目的
// （DNAT 路径 cmsg 为 NAT 后目的，中继恒黑洞，故切 TPROXY 进门）。
// 需 CAP_NET_ADMIN（root），失败由调用方按 UDP 门未启处理（TCP 照常）。
const ipTransparent = 19

// enableTransparent 打开套接字的 IP_TRANSPARENT（TPROXY 投递前提）。
func enableTransparent(srv *net.UDPConn) error {
	sc, err := srv.SyscallConn()
	if err != nil {
		return err
	}
	var oerr error
	cerr := sc.Control(func(fd uintptr) {
		oerr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipTransparent, 1)
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
//
// P1-3：长度一律按无符号比较。旧版 `int(h.Len) > len(oob)` 在 h.Len 高位被置起
// （≥2^63，转 int64 为负）时会越过守卫，随后 `oob[cmsgAlign(int(h.Len)):]` 负下标
// panic（进程级宕机）。内核当前不会写这种 Len（oob 只来自 recvmsg），属防御性修复；
// 加了无符号校验后所有下标都落在 [hdrLen, len(oob)] 内。
func parseOrigDst(oob []byte) (dstAddr, bool) {
	hdrLen := int(unsafe.Sizeof(syscall.Cmsghdr{}))
	for len(oob) >= hdrLen {
		h := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if h.Len < uint64(hdrLen) || h.Len > uint64(len(oob)) {
			break
		}
		if h.Level == syscall.IPPROTO_IP && h.Type == ipOrigDstAddr {
			d := oob[hdrLen:int(h.Len)]
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
	// P2-6 同口径：回复头 VER=5 / RSV=0 必须成立（垃圾字节流不许被当成功 associate）。
	if hdr[0] != 5 {
		return fail(fmt.Errorf("socks udp assoc ver=%d", hdr[0]))
	}
	if hdr[2] != 0 {
		return fail(fmt.Errorf("socks udp assoc rsv=%d", hdr[2]))
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

// spoofUDP 建下行 spoof 发送口：IP_TRANSPARENT + bind 到对端地址
// （od.ip:od.port），下行经它 WriteToUDP，客户端看到的源即服务端地址。
// 背景（某握手期校验源的 UDP 应用）：旧下行经 :12348 监听口直回，源为
// 192.168.2.1:12348，握手期校验源的客户端拒收，10 探针耗尽即放弃；直出腿
// （源即服务端）30ms 即通。同一 od 多 assoc 复用同一地址 bind，需 SO_REUSEADDR
// （只发不收，不抢 up 腿的回包）。失败返回 err，调用方回退 a.srv（旧语义）。
func spoofUDP(od dstAddr) (*net.UDPConn, error) {
	ip4 := od.ip.To4()
	if ip4 == nil || od.port == 0 {
		return nil, fmt.Errorf("spoof needs ipv4 dst")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	done := false
	defer func() {
		if !done {
			syscall.Close(fd)
		}
	}()
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipTransparent, 1); err != nil {
		return nil, err
	}
	var addr [4]byte
	copy(addr[:], ip4)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: od.port, Addr: addr}); err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "udp-spoof")
	pc, err := net.FilePacketConn(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("spoof not udp")
	}
	done = true
	return uc, nil
}

// udpPump 回包：upstream -> client。
// 下行发送口优先 spoof（源即服务端，见上），无 spoof 回退 a.srv（旧语义）。
// gen 为泵代次（P2-9 升级会 ++gen 并另起新泵）：只有当代泵退出才 close assoc，
// 旧泵被换代后退出不得关掉新连接的 assoc。proxy 与建泵时的 socket 配对，升级后
// 旧泵仍按旧 socket（直连）语义处理，不会拿新 socket 的包去解封装。
func udpPump(a *udpAssoc, gen int64, proxy bool) {
	defer func() {
		a.mu.Lock()
		cur := a.gen
		a.mu.Unlock()
		if cur == gen {
			a.close()
		}
	}()
	rb := make([]byte, 65535)
	for {
		a.mu.Lock()
		up := a.up
		w := a.srv
		if a.spoof != nil {
			w = a.spoof
		}
		a.mu.Unlock()
		if up == nil || w == nil {
			return
		}
		up.SetReadDeadline(time.Now().Add(udpAssocIdle))
		n, err := up.Read(rb)
		if err != nil {
			return
		}
		p := rb[:n]
		if proxy {
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
		if _, err := w.WriteToUDP(p, a.client); err != nil {
			if w == a.srv {
				return
			}
			// spoof 口发送失败（如透明发送被环境拒绝）：降级回 srv（旧语义），
			// 关闭坏口避免每包重复失败；srv 也失败才退出 pump。
			writeStat("gate_udp_spoof_write_fail", 1)
			a.mu.Lock()
			if a.spoof != nil {
				a.spoof.Close()
				a.spoof = nil
			}
			srv := a.srv
			a.mu.Unlock()
			if srv == nil {
				return
			}
			if _, serr := srv.WriteToUDP(p, a.client); serr != nil {
				return
			}
		}
	}
}

// getReason 读当前 reason（升级会改写，故走锁）。
func (a *udpAssoc) getReason() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reason
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
		emitUCloseEvent("udp", src, a.dst, a.verdict(), a.getReason(), durMs,
			a.upPkts.Load(), a.downPkts.Load(), a.upBytes.Load(), a.downBytes.Load())
	})
}

// shutdown 收尾：置 closed、移表、关 socket；emit=false 用于建链失败（旧版失败
// 不产生 uclose，事件流保持一致）。幂等。
func (a *udpAssoc) shutdown(emit bool) {
	a.mu.Lock()
	if a.state == udpClosed {
		a.mu.Unlock()
		return
	}
	a.state = udpClosed
	up, tcp, spoof := a.up, a.tcp, a.spoof
	a.up, a.tcp, a.spoof = nil, nil, nil
	a.pending = nil
	a.mu.Unlock()
	udpMu.Lock()
	if cur, ok := udpTable[a.key]; ok && cur == a {
		delete(udpTable, a.key)
	}
	udpMu.Unlock()
	if emit {
		a.emitUCloseOnce()
	}
	if up != nil {
		up.Close()
	}
	if tcp != nil {
		tcp.Close()
	}
	if spoof != nil {
		spoof.Close()
	}
}

func (a *udpAssoc) close() { a.shutdown(true) }

// abort 建链失败收尾（P2-10：表里已先占位，失败必须移走，fail-closed 不回退直连）。
func (a *udpAssoc) abort() { a.shutdown(false) }

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
		a.close()
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
	// TPROXY 投递前提：非 TRANSPARENT 套接字收不到 divert 包；
	// 失败即 UDP 门未启（TCP 照常），fail-loud，绝不静默跑 DNAT 旧语义。
	if err := enableTransparent(srv); err != nil {
		log.Printf("udp gate %s: TRANSPARENT fail %v (UDP门未启，TCP照常)", udpListenAddr, err)
		return
	}
	log.Printf("wxdet-gate udp on %s (proxy=%s)", udpListenAddr, proxySocks)
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
			// 直写调试文件（绕开 logd）。P2-11：限速——旧版每个错包 open/close 一次
			// 文件，cmsg 缺失那类系统性问题会把 tmpfs 刷爆也没人看；计数照记、日志采样。
			udpErrLog(fmt.Sprintf("%d\t%s\tn=%d\tod=%s\terr=%v\tfirst=%x\n",
				time.Now().Unix(), caddr, n, od.String(), rerr, firstBytes(buf[:max(n, 0)], 16)))
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
			logUDPLocalDrop(caddr.String(), od, buf[:n])
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
			// P2-10：只建 assoc 壳入表，socks associate / DialUDP（最长 5s）在后台
			// goroutine 里做，绝不堵这条 recv 循环。
			a = startUDPAssoc(srv, caddr, od, verdict, reason, buf[:n])
		} else {
			// 已有 assoc 只允许 pass→proxy 单向升级（内部判定，proxy 不降级）。
			a.maybeUpgrade(verdict, reason, buf[:n])
		}
		// P2-13：这里只递**原始载荷**，封装决策下沉到 send 的锁内、按当时的腿做。
		// 锁外先判 toProxy 再写会撞上 upgradeProxy 换 socket 的窗口：那一刻 toProxy
		// 还是 false 但 up 已换成 proxy 的 SOCKS5-UDP socket，裸载荷缺
		// 00 00 00 01 头，对端只能丢。
		a.pkts.Add(1)
		a.upPkts.Add(1)
		a.upBytes.Add(uint64(n))
		if err := a.send(od, buf[:n]); err != nil {
			emitErrorEvent("udp", caddr.String(), od, "err", a.getReason(), err.Error())
			writeStat("gate_udp_write_err", 1)
			a.close()
		}
	}
}

// startUDPAssoc 建 assoc 壳并立即入表，真正的建链放后台 goroutine（P2-10）。
// 建链期间的包进有界队列；失败 fail-closed：丢包 + 移表，不回退直连（原语义）。
func startUDPAssoc(srv *net.UDPConn, client *net.UDPAddr, od dstAddr, verdict, reason string, first []byte) *udpAssoc {
	proxy := verdict == "proxy"
	a := &udpAssoc{key: udpAssocKey(client, od), client: client, dst: od, srv: srv,
		state: udpConnecting, reason: reason}
	// 下行 spoof 口与建链无关（纯本地 bind），同步建：失败回退 a.srv（旧语义），
	// 只计数不记事件（无 root/TRANSPARENT 的单测与开发环境恒走回退）。
	if sp, serr := spoofUDP(od); serr != nil {
		writeStat("gate_udp_spoof_fail", 1)
	} else {
		a.spoof = sp
	}
	a.toProxy.Store(proxy)
	now := time.Now().UnixNano()
	a.start.Store(now)
	a.last.Store(now)
	emitOpen("udp", client.String(), od, verdict, reason)
	udpMu.Lock()
	udpTable[a.key] = a
	udpMu.Unlock()
	go a.connect(proxy, first)
	return a
}

// connect 后台建链（proxy associate 或直连 dial）。成功 → 起 pump 并冲刷建链期间
// 积压的包；失败 → 计数 + 事件 + abort（移表关 socket，丢包不回退）。
func (a *udpAssoc) connect(proxy bool, first []byte) {
	var (
		up  *net.UDPConn
		tcp net.Conn
		err error
	)
	if proxy {
		up, tcp, err = socks5UDPAssociate(proxySocks, a.dst)
	} else if ip4 := a.dst.ip.To4(); ip4 == nil {
		err = fmt.Errorf("non-ipv4 dst")
	} else {
		up, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: ip4, Port: a.dst.port})
	}
	if err != nil {
		reason := a.getReason()
		if proxy {
			writeStat("gate_proxy_udp_fail", 1)
			reason += "_proxy_fail"
		} else {
			writeStat("gate_udp_dial_err", 1)
		}
		logGateErr("udp", a.client.String(), a.dst, "err", reason, err.Error(), first)
		emitErrorEvent("udp", a.client.String(), a.dst, "err", reason, err.Error())
		log.Printf("udp %s -> %s assoc fail (fail-closed): %v", a.client, a.dst, err)
		a.abort()
		return
	}
	a.mu.Lock()
	if a.state != udpConnecting {
		a.mu.Unlock()
		up.Close()
		if tcp != nil {
			tcp.Close()
		}
		return
	}
	a.up, a.tcp, a.state = up, tcp, udpReady
	pending := a.pending
	a.pending = nil
	gen := a.gen
	a.mu.Unlock()
	writeStat("gate_udp_assoc", 1)
	if proxy {
		writeStat("gate_proxy_udp", 1)
	} else {
		writeStat("gate_pass_udp", 1)
	}
	// TCP 侧 handleConn 有 gate_rsn_* 维度，UDP 侧此前只有 assoc 总数：
	// 建链成功即按创建时 reason 记一条，对齐口径（升级成功见 upgradeProxy）。
	writeStat("gate_rsn_"+a.getReason(), 1)
	logGate("udp", a.client.String(), a.dst, a.verdict(), a.getReason(), first)
	for _, p := range pending {
		out := a.encapFor(proxy, p)
		if out == nil {
			continue
		}
		if _, werr := up.Write(out); werr != nil {
			writeStat("gate_udp_write_err", 1)
			break
		}
	}
	go udpPump(a, gen, proxy)
}

// encapFor 按腿封装上行载荷：proxy 腿加 SOCKS5 UDP 请求头，直连腿原样返回；
// 目的非 v4 时返回 nil（调用方丢弃）。纯函数式辅助，无锁、只读 a.dst。
func (a *udpAssoc) encapFor(proxy bool, p []byte) []byte {
	if !proxy {
		return p
	}
	ip4 := a.dst.ip.To4()
	if ip4 == nil {
		return nil
	}
	return socksEncap(dstAddr{ip: ip4, port: a.dst.port}, p)
}

// send 投递一个**未封装**的上行载荷（P2-13：封装与写入必须在同一把锁内完成，
// 否则 upgradeProxy 的换腿窗口会把裸载荷写进 proxy socket）。建链中入有界队列
// （存原始字节，建链完成后按当时的腿封装冲刷），就绪按当前腿封装直写，已关闭
// 返回错误。快路径只多一次无竞争 mutex；直连腿零额外分配。
func (a *udpAssoc) send(od dstAddr, raw []byte) error {
	a.mu.Lock()
	switch a.state {
	case udpConnecting:
		if len(a.pending) >= udpPendingMax {
			a.mu.Unlock()
			writeStat("gate_udp_pending_drop", 1)
			return nil
		}
		q := make([]byte, len(raw))
		copy(q, raw)
		a.pending = append(a.pending, q)
		a.mu.Unlock()
		return nil
	case udpReady:
		// od 恒等于建 assoc 时的目的（5 元组键的一部分），封装按当前腿现算。
		out := a.encapFor(a.toProxy.Load(), raw)
		if out == nil {
			a.mu.Unlock()
			return nil
		}
		_, err := a.up.Write(out)
		a.mu.Unlock()
		return err
	default:
		a.mu.Unlock()
		return errUDPAssocClosed
	}
}

var errUDPAssocClosed = errors.New("udp assoc closed")

// maybeUpgrade：已有 assoc 收到 proxy 形状包时单向升级（pass→proxy）。
// proxy assoc 收到非 STUN 包绝不降级——粘性语义不变。
func (a *udpAssoc) maybeUpgrade(verdict, reason string, first []byte) {
	if verdict == "proxy" && !a.toProxy.Load() {
		a.upgradeProxy(reason, first)
	}
}

// upgradeProxy 把 pass assoc 升级成 proxy 中继：建 socks associate 同样**放后台**
// （P2-10：升级也是建链，不能堵 recv 循环；期间包继续走旧直连腿），成功后换 socket、
// ++gen（旧泵退出不关 assoc）并另起新泵。失败保持原直连中继，只计数记事件，不降级
// 不断流（原直连路径仍可用）。
func (a *udpAssoc) upgradeProxy(reason string, first []byte) {
	a.mu.Lock()
	if a.state != udpReady || a.toProxy.Load() || a.upgrading {
		a.mu.Unlock()
		return
	}
	a.upgrading = true
	a.mu.Unlock()
	go func() {
		up, tcp, err := socks5UDPAssociate(proxySocks, a.dst)
		if err != nil {
			a.mu.Lock()
			a.upgrading = false
			a.mu.Unlock()
			writeStat("gate_udp_upgrade_fail", 1)
			logGateErr("udp", a.client.String(), a.dst, "err", "udp_upgrade_proxy_fail", err.Error(), first)
			emitErrorEvent("udp", a.client.String(), a.dst, "err", "udp_upgrade_proxy_fail", err.Error())
			return
		}
		a.mu.Lock()
		if a.state != udpReady {
			a.upgrading = false
			a.mu.Unlock()
			up.Close()
			if tcp != nil {
				tcp.Close()
			}
			return
		}
		oldUp := a.up
		a.up, a.tcp, a.reason = up, tcp, reason
		a.toProxy.Store(true)
		a.gen++
		gen := a.gen
		a.upgrading = false
		a.mu.Unlock()
		writeStat("gate_udp_upgrade", 1)
		writeStat("gate_rsn_"+reason, 1)
		logGate("udp", a.client.String(), a.dst, "proxy", reason, first)
		if oldUp != nil {
			oldUp.Close() // 旧泵 Read 立刻返回；代次不符 → 不关 assoc
		}
		go udpPump(a, gen, true)
	}()
}

func (a *udpAssoc) verdict() string {
	if a.toProxy.Load() {
		return "proxy"
	}
	return "pass"
}
