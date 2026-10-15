package main

// UDP 侧硬化回归（P1-3 / P2-9 / P2-10 / P2-11）。

import (
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ---------- P1-3：cmsg 长度无符号校验（修复前 Len 高位被置起会 panic） ----------

func TestParseOrigDstLenOverflow(t *testing.T) {
	lens := []uint64{
		0x8000000000000000, 0xfffffffffffffff0, 0x8000000000000010,
		0xffffffffffffffff, 1 << 40, 1 << 62,
		0, 1, 8, 15, 16, 17, 24, 31, 33,
	}
	for _, l := range lens {
		b := make([]byte, 32)
		binary.LittleEndian.PutUint64(b[0:8], l)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseOrigDst(Len=0x%x) panic: %v", l, r)
				}
			}()
			if _, ok := parseOrigDst(b); ok {
				t.Errorf("Len=0x%x 不该解析成功", l)
			}
		}()
	}
	// 高位 ≥2^63 但 Content 又是合法 IP_ORIGDSTADDR 的形态也不许 panic（直接 break）。
	for _, l := range []uint64{0x8000000000000020, 0xffffffffffffffe0} {
		b := mkOrigDstCmsg([4]byte{74, 125, 250, 129}, 19302)
		binary.LittleEndian.PutUint64(b[0:8], l)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseOrigDst(Len=0x%x, 合法 content) panic: %v", l, r)
				}
			}()
			if _, ok := parseOrigDst(b); ok {
				t.Errorf("Len=0x%x 超 oob 不该解析成功", l)
			}
		}()
	}
	// 正常 cmsg 仍然工作（Len=32 边界）。
	if od, ok := parseOrigDst(mkOrigDstCmsg([4]byte{74, 125, 250, 129}, 19302)); !ok || od.port != 19302 {
		t.Fatalf("正常 cmsg 解析回归：%v %v", od, ok)
	}
}

// 全部网络面解析器 2 万条随机/变异输入 zero-panic（覆盖 P1-3 修复面）。
func TestParsersNoPanicSweep(t *testing.T) {
	oldStat := statFile
	statFile = nil // 纯判路，不落任何 stats
	defer func() { statFile = oldStat }()
	hits := map[string]int{}
	try := func(name string, f func()) {
		defer func() {
			if r := recover(); r != nil {
				hits[name]++
			}
		}()
		f()
	}
	rnd := rand.New(rand.NewSource(20261011))
	ports := []int{80, 443, 8000, 8080, 8443, 10000, 12347, 3478, 1}
	seedTLS := clientHello("dns.google.com")
	seedSTUN := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	seedCmsg := mkOrigDstCmsg([4]byte{1, 2, 3, 4}, 3478)
	for i := 0; i < 20000; i++ {
		n := rnd.Intn(1400)
		b := make([]byte, n)
		for j := range b {
			b[j] = byte(rnd.Intn(256))
		}
		switch i % 4 {
		case 0:
			if n >= len(seedTLS) {
				copy(b, seedTLS)
			}
		case 1:
			if n >= len(seedSTUN) {
				copy(b, seedSTUN)
			}
		case 2:
			if n >= len(seedCmsg) {
				copy(b, seedCmsg)
			}
		}
		if i%2 == 0 && n > 0 {
			for k := 0; k < 1+rnd.Intn(6); k++ {
				b[rnd.Intn(len(b))] = byte(rnd.Intn(256))
			}
		}
		od := dstAddr{ip: net.IPv4(byte(rnd.Intn(256)), byte(rnd.Intn(256)), byte(rnd.Intn(256)), byte(rnd.Intn(256))), port: ports[rnd.Intn(len(ports))]}
		try("classify", func() { classify(od, b) })
		try("classifyEx", func() { classifyEx(od, b) })
		try("isTLSClientHello", func() { isTLSClientHello(b) })
		try("isHTTPRequest", func() { isHTTPRequest(b) })
		try("httpHost", func() { httpHost(b) })
		try("httpPath", func() { httpPath(b) })
		try("httpUserAgent", func() { httpUserAgent(b) })
		try("hasRangeHeader", func() { hasRangeHeader(b) })
		try("headerBlock", func() { headerBlock(b) })
		try("dlExtHit", func() { dlExtHit(string(b)) })
		try("parseLineSet", func() { parseLineSet(b) })
		try("udpVerdict", func() { udpVerdict(od, b) })
		try("classifyUDP", func() { classifyUDP(b) })
		try("socksDecap", func() {
			if len(b) >= 10 {
				socksDecap(b)
			}
		})
		try("parseOrigDst", func() {
			if rnd.Intn(4) == 0 {
				parseOrigDst(b)
			}
		})
	}
	if len(hits) != 0 {
		t.Fatalf("解析器 panic：%v", hits)
	}
}

// ---------- P2-11：udp_err.log 限速 ----------

func TestUDPErrLogRateLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "udp_err.log")
	oldPath := udpErrLogPath
	oldNs := udpErrLogNs.Load()
	udpErrLogPath = p
	udpErrLogNs.Store(0)
	defer func() { udpErrLogPath = oldPath; udpErrLogNs.Store(oldNs) }()

	t0 := time.Unix(1791700000, 0)
	if !udpErrLogAt("line1\n", t0) {
		t.Fatal("首条应落盘")
	}
	if udpErrLogAt("line2\n", t0.Add(1*time.Second)) {
		t.Fatal("1s 内不该再写（P2-11 限速）")
	}
	if udpErrLogAt("line3\n", t0.Add(2*time.Second)) {
		t.Fatal("2s 内不该再写")
	}
	if !udpErrLogAt("line4\n", t0.Add(6*time.Second)) {
		t.Fatal("超 5s 应再写")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n != 2 {
		t.Fatalf("应只落 2 行，got %d: %q", n, b)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("文件应存在且有内容：%v", err)
	}
}

// ---------- P2-9 / P2-10 用的假 SOCKS5-UDP associate 服务 ----------

type fakeSocksUDP struct {
	ln     net.Listener
	relay  *net.UDPConn
	gate   chan struct{} // 非 nil：握手前等它关闭（模拟慢建链）
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	tcpN   int
	relayN int
}

func newFakeSocksUDP(t *testing.T, gate chan struct{}) *fakeSocksUDP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSocksUDP{ln: ln, relay: rp, gate: gate, done: make(chan struct{})}
	go f.serveTCP()
	go f.serveRelay()
	t.Cleanup(func() {
		f.once.Do(func() { close(f.done) })
		ln.Close()
		rp.Close()
	})
	return f
}

func (f *fakeSocksUDP) addr() string { return f.ln.Addr().String() }

func (f *fakeSocksUDP) relayCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.relayN
}

func (f *fakeSocksUDP) serveTCP() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			g := make([]byte, 3)
			if _, err := io.ReadFull(c, g); err != nil {
				return
			}
			if _, err := c.Write([]byte{5, 0}); err != nil {
				return
			}
			req := make([]byte, 10)
			if _, err := io.ReadFull(c, req); err != nil {
				return
			}
			if f.gate != nil {
				select {
				case <-f.gate:
				case <-f.done:
					return
				}
			}
			la := f.relay.LocalAddr().(*net.UDPAddr)
			ip := la.IP.To4()
			if _, err := c.Write([]byte{5, 0, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(la.Port >> 8), byte(la.Port)}); err != nil {
				return
			}
			f.mu.Lock()
			f.tcpN++
			f.mu.Unlock()
			<-f.done // 保持控制连接（gate 侧持有它）
		}(c)
	}
}

func (f *fakeSocksUDP) serveRelay() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := f.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.relayN++
		f.mu.Unlock()
		_, _ = f.relay.WriteToUDP(buf[:n], addr)
	}
}

// ---------- 测试小工具 ----------

func mustUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc.(*net.UDPConn)
}

func stunFirst() []byte {
	txn := []byte{0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1}
	out := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x00, 0x01}
	return append(out, txn...)
}

func waitUDPState(t *testing.T, a *udpAssoc, want int, d time.Duration) {
	t.Helper()
	dl := time.Now().Add(d)
	for {
		a.mu.Lock()
		st := a.state
		a.mu.Unlock()
		if st == want {
			return
		}
		if time.Now().After(dl) {
			t.Fatalf("assoc 状态未达 %d（现 %d）", want, st)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitProxy(t *testing.T, a *udpAssoc, d time.Duration) {
	t.Helper()
	dl := time.Now().Add(d)
	for {
		if a.toProxy.Load() {
			return
		}
		if time.Now().After(dl) {
			t.Fatalf("assoc 未升级到 proxy")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func readUDPN(c *net.UDPConn, n int, d time.Duration) [][]byte {
	var out [][]byte
	dl := time.Now().Add(d)
	for len(out) < n {
		c.SetReadDeadline(dl)
		buf := make([]byte, 2048)
		k, err := c.Read(buf)
		if err != nil {
			break
		}
		out = append(out, append([]byte(nil), buf[:k]...))
	}
	return out
}

// ---------- P2-10：建链移出 recv 循环（修复前 startUDPAssoc 会同步堵 5s） ----------

func TestUDPAssocSlowConnectDoesNotBlock(t *testing.T) {
	statsPath := tempStatFile(t)
	rel := make(chan struct{})
	f := newFakeSocksUDP(t, rel)
	oldProxy := proxySocks
	proxySocks = f.addr()
	defer func() { proxySocks = oldProxy }()

	srv := mustUDP(t)
	client := mustUDP(t)
	// od 用回环而非 TEST-NET：下行 spoof 口 bind 到 od，源为外部地址的包在
	// netns 沙箱里到不了回环（rpfilter，吃掉且无错）；生产是直连转发，无此问题。
	// 用回环才能端到端验证 spoof 下行；回退路径由 udp_test.go 另行覆盖。
	od := dstAddr{ip: net.ParseIP("127.0.0.1"), port: 3478}
	first := stunFirst()

	start := time.Now()
	a := startUDPAssoc(srv, client.LocalAddr().(*net.UDPAddr), od, "proxy", "stun_udp", first)
	if el := time.Since(start); el > 50*time.Millisecond {
		t.Fatalf("startUDPAssoc 必须立即返回（P2-10），耗时 %v", el)
	}
	if a == nil {
		t.Fatal("startUDPAssoc 不该返回 nil")
	}
	waitUDPState(t, a, udpConnecting, time.Second)

	// 建链期间的包进有界队列：前 8 个收下，第 9 个丢弃并计数。
	// P2-13 起 send 收**原始载荷**（封装在锁内按腿做），故这里不再预封装。
	raw := func(i int) []byte {
		return []byte{0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, byte(i)}
	}
	for i := 0; i < udpPendingMax; i++ {
		if err := a.send(od, raw(i)); err != nil {
			t.Fatalf("入队 %d: %v", i, err)
		}
	}
	if err := a.send(od, raw(99)); err != nil {
		t.Fatalf("溢出包应被静默丢弃（fail-closed）：%v", err)
	}
	if n := statSum(t, statsPath, "gate_udp_pending_drop"); n != 1 {
		t.Errorf("gate_udp_pending_drop=%d want 1", n)
	}
	if n := statSum(t, statsPath, "gate_udp_assoc"); n != 0 {
		t.Errorf("建链未完成不该计 gate_udp_assoc，got %d", n)
	}

	close(rel) // 放行慢建链
	waitUDPState(t, a, udpReady, 3*time.Second)
	if !a.toProxy.Load() {
		t.Fatal("proxy assoc 应 toProxy")
	}
	if n := statSum(t, statsPath, "gate_udp_assoc"); n != 1 {
		t.Errorf("gate_udp_assoc=%d want 1", n)
	}
	if n := statSum(t, statsPath, "gate_proxy_udp"); n != 1 {
		t.Errorf("gate_proxy_udp=%d want 1", n)
	}
	// 队列被冲刷：relay 收到 ≥8 个（并回给 client）。
	if got := f.relayCount(); got < udpPendingMax {
		t.Fatalf("积压包未冲刷到 relay：relayN=%d", got)
	}
	got := readUDPN(client, udpPendingMax, 3*time.Second)
	if len(got) != udpPendingMax {
		t.Fatalf("client 应收到 %d 个回包，got %d", udpPendingMax, len(got))
	}
	for _, p := range got {
		if len(p) != 13 || p[4] != 0x21 || p[5] != 0x12 {
			t.Fatalf("回包内容不对（应为解封装后的 STUN 载荷）：%x", p)
		}
	}
	a.close()
}

// ---------- P2-9：direct→proxy 单向升级 ----------

func TestUDPAssocUpgradePassToProxy(t *testing.T) {
	statsPath := tempStatFile(t)
	rel := make(chan struct{})
	f := newFakeSocksUDP(t, rel)
	oldProxy := proxySocks
	proxySocks = f.addr()
	defer func() { proxySocks = oldProxy }()

	// 直连腿：本地 UDP echo 当上游。
	up := mustUDP(t)
	var upN atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := up.ReadFromUDP(buf)
			if err != nil {
				return
			}
			upN.Add(1)
			_, _ = up.WriteToUDP(buf[:n], addr)
		}
	}()
	ua := up.LocalAddr().(*net.UDPAddr)
	od := dstAddr{ip: ua.IP, port: ua.Port}
	srv := mustUDP(t)
	client := mustUDP(t)
	first := stunFirst()

	a := startUDPAssoc(srv, client.LocalAddr().(*net.UDPAddr), od, "pass", "udp_direct", first)
	waitUDPState(t, a, udpReady, 3*time.Second)
	if a.toProxy.Load() {
		t.Fatal("direct 首包不该建 proxy")
	}
	// 直连腿可用：发一个裸包，回包回到 client。
	if err := a.send(od, []byte("direct-leg")); err != nil {
		t.Fatal(err)
	}
	if got := readUDPN(client, 1, 2*time.Second); len(got) != 1 || string(got[0]) != "direct-leg" {
		t.Fatalf("直连腿回包异常：%q", got)
	}
	// 后续包判 proxy（STUN 形状）→ 单向升级；升级建链同样必须异步（P2-10）。
	upStart := time.Now()
	a.maybeUpgrade("proxy", "stun_udp", first)
	if el := time.Since(upStart); el > 50*time.Millisecond {
		t.Fatalf("升级建链必须异步，maybeUpgrade 耗时 %v", el)
	}
	close(rel)
	waitProxy(t, a, 3*time.Second)
	if n := statSum(t, statsPath, "gate_udp_upgrade"); n != 1 {
		t.Errorf("gate_udp_upgrade=%d want 1", n)
	}
	if a.verdict() != "proxy" {
		t.Errorf("升级后 verdict=%s want proxy", a.verdict())
	}
	// 升级后走 proxy relay：封装包 → relay 收到 → 回包解封装回 client。
	directN := upN.Load()
	pay := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 9, 9, 9, 9}
	if err := a.send(od, pay); err != nil {
		t.Fatal(err)
	}
	got := readUDPN(client, 1, 3*time.Second)
	if len(got) != 1 || string(got[0]) != string(pay) {
		t.Fatalf("升级后回包应解封装为内层载荷：%q", got)
	}
	// relay 确实接手了（relayN ≥1 只可能来自 proxy 腿），且直连腿不再收到包。
	if n := f.relayCount(); n < 1 {
		t.Fatalf("proxy relay 应已接手：relayN=%d", n)
	}
	if n := upN.Load(); n != directN {
		t.Fatalf("升级后不该再走直连腿：upstream 收到 %d 个包（升级前 %d）", n, directN)
	}
	// 反向永不降级：非 STUN 判定不许把 proxy 打回 direct。
	a.maybeUpgrade("pass", "udp_direct", first)
	if !a.toProxy.Load() {
		t.Fatal("proxy assoc 不许被降级")
	}
	if n := statSum(t, statsPath, "gate_udp_upgrade"); n != 1 {
		t.Errorf("降级不该计升级：gate_udp_upgrade=%d", n)
	}
	a.close()
}

// 升级失败时保持直连中继可用（只计数记事件，不降级不断流）。
func TestUDPAssocUpgradeFailKeepsPass(t *testing.T) {
	statsPath := tempStatFile(t)
	oldProxy := proxySocks
	proxySocks = "127.0.0.1:1" // 必关端口：升级必败
	defer func() { proxySocks = oldProxy }()
	up := mustUDP(t)
	ua := up.LocalAddr().(*net.UDPAddr)
	od := dstAddr{ip: ua.IP, port: ua.Port}
	srv := mustUDP(t)
	client := mustUDP(t)
	a := startUDPAssoc(srv, client.LocalAddr().(*net.UDPAddr), od, "pass", "udp_direct", stunFirst())
	waitUDPState(t, a, udpReady, 3*time.Second)
	a.maybeUpgrade("proxy", "stun_udp", stunFirst())
	dl := time.Now().Add(3 * time.Second)
	for statSum(t, statsPath, "gate_udp_upgrade_fail") == 0 {
		if time.Now().After(dl) {
			t.Fatal("升级失败未计数 gate_udp_upgrade_fail")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if a.toProxy.Load() {
		t.Fatal("升级失败不该置 proxy")
	}
	if err := a.send(od, []byte("still-direct")); err != nil {
		t.Fatalf("升级失败后直连中继应仍可用：%v", err)
	}
	a.close()
}

// ---------- P2-13：封装决策必须在 send 的锁内（换腿窗口不许把裸载荷写进 proxy 腿） ----------

// 旧实现在 serveUDP 里锁外先判 toProxy 再调 send(out)：若 upgradeProxy 恰好在
// “Load 到取锁”之间把 up 换成 proxy 的 SOCKS5-UDP socket，已判为 direct 的裸载荷
// 就会被写进 proxy 腿——缺 00 00 00 01 头，对端只能丢。
// 本用例把不变量钉死：send 只收原始载荷，落到 proxy 腿的字节**必须**带 SOCKS5 头。
func TestUDPSendEncapDecidedUnderLock(t *testing.T) {
	tempStatFile(t)
	od := dstAddr{ip: net.ParseIP("203.0.113.9"), port: 3478}

	peerPass, peerProxy := mustUDP(t), mustUDP(t)
	upPass, err := net.DialUDP("udp", nil, peerPass.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer upPass.Close()
	upProxy, err := net.DialUDP("udp", nil, peerProxy.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer upProxy.Close()

	a := &udpAssoc{key: "p213|" + od.String(), dst: od, srv: mustUDP(t), state: udpReady}
	a.up = upPass
	a.last.Store(time.Now().UnixNano())

	// 直连腿：原始载荷原样落到直连对端。
	if err := a.send(od, []byte("raw-1")); err != nil {
		t.Fatal(err)
	}
	if got := readUDPN(peerPass, 1, 2*time.Second); len(got) != 1 || string(got[0]) != "raw-1" {
		t.Fatalf("直连腿应收到裸载荷，got %q", got)
	}

	// 模拟 upgradeProxy 的换腿（同序：锁内换 up + 置 toProxy），其间不加任何同步。
	a.mu.Lock()
	a.up = upProxy
	a.toProxy.Store(true)
	a.mu.Unlock()

	// 换腿后同一份原始载荷：必须被封装后落到 proxy 腿，且直连腿颗粒无收。
	if err := a.send(od, []byte("raw-2")); err != nil {
		t.Fatal(err)
	}
	if got := readUDPN(peerPass, 1, 300*time.Millisecond); len(got) != 0 {
		t.Fatalf("换腿后直连腿不该再收到包：%q", got)
	}
	got := readUDPN(peerProxy, 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("proxy 腿应收到 1 包，got %d", len(got))
	}
	want := socksEncap(od, []byte("raw-2"))
	if string(got[0]) != string(want) {
		t.Fatalf("proxy 腿必须收到封装后的包（裸载荷=旧实现的换腿窗口漏洞）\n got=%x\nwant=%x", got[0], want)
	}
	if dec, derr := socksDecap(got[0]); derr != nil || string(dec) != "raw-2" {
		t.Fatalf("proxy 腿包必须可解封装：%v %x", derr, dec)
	}
	a.close()
}

// ---------- IP_TRANSPARENT 开关（TPROXY 投递前提） ----------
func TestEnableTransparent(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback udp 不可用：%v", err)
	}
	defer pc.Close()
	srv := pc.(*net.UDPConn)
	err = enableTransparent(srv)
	if err == nil {
		return // root/CAP_NET_ADMIN：开关成功
	}
	// 非特权沙箱：只接受 EPERM/EACCES（开关本身语义正确，缺的是权限）；
	// 其他错误一律失败（拼错 level/opt 会在这里现形）。
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("enableTransparent 非权限错误：%v", err)
	}
	t.Logf("非特权环境，TRANSPARENT 返回 %v（生产 root 可设，跳过断言）", err)
}
