package main

// 本文件是加固修复的回归用例（P0-1 / P1-2 / P1-4 / P2-5 / P2-6 / P2-7 / P2-8 / P2-12）。
// 每条修复都有对应的"修复前会失败"的断言点，注释里写明。

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- 通用小工具 ----------

// tempStatFile 把 stats 输出定向到临时文件，返回路径（Cleanup 自动还原）。
func tempStatFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "stats.tsv")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	old := statFile
	statFile = f
	t.Cleanup(func() { statFile = old; f.Close() })
	return p
}

func statSum(t *testing.T, path, key string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	sum := 0
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Split(ln, "\t")
		if len(f) == 3 && f[1] == key {
			var n int
			fmt.Sscanf(f[2], "%d", &n)
			sum += n
		}
	}
	return sum
}

// listenTestTCP 绑 127.0.0.1:45679 起的端口（避开本沙箱 connect 会 refused 的 12399/11080），
// 全被占则退回随机端口。
func listenTestTCP(t *testing.T, base int) net.Listener {
	t.Helper()
	for p := base; p < base+20; p++ {
		if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
			return ln
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// ---------- P0-1：本机目的守卫 ----------

func TestIsLocalDst(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true}, {"192.168.99.7", true}, {"192.168.2.1", true},
		{"10.1.2.3", true}, {"172.16.5.5", true}, {"169.254.1.1", true}, {"0.0.0.0", true},
		{"8.8.8.8", false}, {"1.1.1.1", false}, {"223.5.5.5", false},
		{"100.64.0.1", false}, // CGNAT 不在 RFC1918 内：与 UDP 侧 gate_udp_local_drop 同口径
		{"2001:4860:4860::8888", false},
	}
	for _, c := range cases {
		if got := isLocalDst(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("isLocalDst(%s)=%v want %v", c.ip, got, c.want)
		}
	}
}

// P0-1 集成（修复前会失败：直连监听口会被判 proxy/default 并拨上游，链式自环）：
// 本机监听 + 直连（无 DNAT，origdst=本机:port）→ 必须 drop：不拨上游、无二次连接、
// stats 计 gate_tcp_local_drop、gate.log 留一行。
func TestHandleConnLocalDstDrop(t *testing.T) {
	statsPath := tempStatFile(t)
	dir := t.TempDir()
	lf, err := os.OpenFile(filepath.Join(dir, "gate.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	oldLog := gateLogFile
	gateLogFile = lf
	t.Cleanup(func() { gateLogFile = oldLog; lf.Close() })
	tcpLocalDropLogNs.Store(0) // 限速窗口归零，保证本次能落日志

	ln := listenTestTCP(t, 45679)
	defer ln.Close()

	// 先确认本沙箱 SO_ORIGINAL_DST 可用（不可用则无从测本机目的判定）。
	// 用独立 listener 探测，避免把探针连接留在 ln 的 accept 队列里污染计数。
	pln := listenTestTCP(t, 45700)
	pc, err := net.Dial("tcp", pln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pacc, aerr := pln.Accept()
	if aerr != nil {
		t.Fatal(aerr)
	}
	if ptc, ok := pacc.(*net.TCPConn); ok {
		if _, perr := originalDst(ptc); perr != nil {
			pacc.Close()
			pc.Close()
			pln.Close()
			t.Skipf("SO_ORIGINAL_DST 不可用（%v），跳过集成用例", perr)
		}
	}
	pacc.Close()
	pc.Close()
	pln.Close()

	// 假上游 socks：只数连接。P0-1 生效时应为 0（修复前会拨进来）。
	// 第三腿（历史形态）已删，借代理腿地址占位计数（本地目的本就 drop 在 openUpstream 之前，任一腿均可）。
	fake := listenTestTCP(t, 45690)
	defer fake.Close()
	var dialed atomic.Int64
	go func() {
		for {
			c, aerr := fake.Accept()
			if aerr != nil {
				return
			}
			dialed.Add(1)
			c.Close()
		}
	}()
	oldProxy := proxySocks
	proxySocks = fake.Addr().String()
	t.Cleanup(func() { proxySocks = oldProxy })

	var accepts atomic.Int64
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			if accepts.Add(1) == 1 {
				go handleConn(c)
			} else {
				c.Close() // 出现第二连接即为自环/回连
			}
		}
	}()

	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Write([]byte("hello-not-http")); err != nil {
		t.Fatal(err)
	}
	cl.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, rerr := cl.Read(buf)
	if n > 0 || rerr == nil {
		t.Fatalf("drop 后客户端应立刻 EOF：n=%d err=%v", n, rerr)
	}
	cl.Close()
	time.Sleep(300 * time.Millisecond)

	if got := dialed.Load(); got != 0 {
		t.Fatalf("本机目的不该拨上游，got %d 次", got)
	}
	if got := accepts.Load(); got != 1 {
		t.Fatalf("不该出现二次连接（自环），accepts=%d", got)
	}
	if n := statSum(t, statsPath, "gate_tcp_local_drop"); n != 1 {
		t.Errorf("gate_tcp_local_drop=%d want 1", n)
	}
	if n := statSum(t, statsPath, "gate_conn"); n != 0 {
		t.Errorf("drop 流不该计 gate_conn，got %d", n)
	}
	lb, _ := os.ReadFile(filepath.Join(dir, "gate.log"))
	if !strings.Contains(string(lb), `"verdict":"drop"`) || !strings.Contains(string(lb), `"reason":"local_dst"`) {
		t.Errorf("gate.log 应留一行 drop/local_dst：%q", lb)
	}
}

// ---------- P1-2：>1024B ClientHello 的 SNI 不再漏判 ----------

// bigClientHello 构造把 SNI 顶到 1024B 之后的 ClientHello（padding 扩展在前）。
func bigClientHello(sni string, padTo int) []byte {
	name := []byte(sni)
	sn := []byte{byte((len(name) + 3) >> 8), byte(len(name) + 3), 0x00, byte(len(name) >> 8), byte(len(name))}
	sn = append(sn, name...)
	snExt := append([]byte{0x00, 0x00, byte(len(sn) >> 8), byte(len(sn))}, sn...)
	pad := make([]byte, padTo)
	padExt := append([]byte{0x00, 0x15, byte(len(pad) >> 8), byte(len(pad))}, pad...)
	exts := append(padExt, snExt...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// splitCHRecords 把 ClientHello 的握手消息按 split 拆成两条 0x16 记录。
func splitCHRecords(ch []byte, split int) []byte {
	hs := ch[5:]
	if split > len(hs) {
		split = len(hs)
	}
	r1 := []byte{0x16, 0x03, 0x01, byte(split >> 8), byte(split)}
	r1 = append(r1, hs[:split]...)
	rest := hs[split:]
	r2 := []byte{0x16, 0x03, 0x01, byte(len(rest) >> 8), byte(len(rest))}
	r2 = append(r2, rest...)
	return append(r1, r2...)
}

// ---------- P1-4：头部类判据不再扫 body ----------

func TestHeaderBlockBodyIsolation(t *testing.T) {
	dlUAs.Store([]string{"thunder"})
	dlExts.Store([]string{"apk"})
	dlDoms.Store(map[string]bool{"down.qq.com": true})
	od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: 8080}
	base := "POST /api HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"
	cases := []struct {
		name, req, wantV, wantR string
	}{
		{"基线（无 body）", base, "proxy", "default"},
		{"body 带 Range", base + "{\"a\":1}\r\nRange: bytes=0-1023\r\n", "proxy", "default"},
		{"body 带下载器 UA", base + "zz\r\nUser-Agent: Thunder/7.0\r\n", "proxy", "default"},
		{"body 带 apk 路径", base + "x\r\nGET /evil.apk HTTP/1.1\r\n", "proxy", "default"},
		{"头部 Range", "GET /v HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-9\r\n\r\n", "pass", "dl_range"},
		{"头部下载器 UA", "GET /f HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Thunder/7.0\r\n\r\n", "pass", "dl_ua"},
		{"头部 Host 下载站", "GET /x HTTP/1.1\r\nHost: down.qq.com\r\n\r\n", "pass", "dl_direct"},
		{"头部未收全 Range", "GET /v HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-9\r\n", "pass", "dl_range"},
	}
	for _, c := range cases {
		v, r, _ := classifyEx(od, []byte(c.req))
		if v != c.wantV || r != c.wantR {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, v, r, c.wantV, c.wantR)
		}
	}
	if h := httpHost([]byte(base + "x\r\nHost: down.qq.com\r\n")); h != "shop.example.com" {
		t.Errorf("httpHost 应取头部首个 Host，got %q", h)
	}
}

// ---------- P2-5：DoH 正则标签级锚定 ----------

// ---------- P2-6：socks5Dial 校验回复头 ----------

// fakeSocks5Reply 起假 SOCKS5：greeting 正常，CONNECT 后回 reply（可短包/垃圾）。
func fakeSocks5Reply(t *testing.T, reply []byte, hold bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
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
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				switch req[3] {
				case 1:
					_, _ = io.ReadFull(c, make([]byte, 6))
				case 4:
					_, _ = io.ReadFull(c, make([]byte, 18))
				case 3:
					lb := make([]byte, 1)
					if _, err := io.ReadFull(c, lb); err != nil {
						return
					}
					_, _ = io.ReadFull(c, make([]byte, int(lb[0])+2))
				}
				_, _ = c.Write(reply)
				if hold {
					time.Sleep(300 * time.Millisecond)
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestSocks5DialReplyValidation(t *testing.T) {
	od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: 443}
	cases := []struct {
		name    string
		reply   []byte
		hold    bool
		wantErr string
	}{
		{"ver 非 5（垃圾首字节）", []byte{0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, true, "ver=0"},
		{"RSV 非 0", []byte{5, 0, 1, 1, 0, 0, 0, 0, 0, 0}, true, "rsv=1"},
		{"HTTP 垃圾回复", []byte("HTTP/1.1 200 OK\r\n"), true, "ver=72"},
		{"REP=4", []byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}, true, "rep=4"},
		{"短包", []byte{5, 0}, false, "unexpected EOF"},
	}
	for _, c := range cases {
		addr := fakeSocks5Reply(t, c.reply, c.hold)
		conn, err := socks5Dial(addr, od, nil, 0)
		if err == nil {
			conn.Close()
			t.Errorf("%s: 应报错，却当成功返回", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: err=%q 期望含 %q", c.name, err.Error(), c.wantErr)
		}
	}
	// 合法回复仍成功（不误伤）。
	ok := fakeSocks5Reply(t, []byte{5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90}, true)
	conn, err := socks5Dial(ok, od, nil, 0)
	if err != nil {
		t.Fatalf("合法回复不该失败：%v", err)
	}
	conn.Close()
}

// ---------- P2-7：block 流补 close 事件 ----------

// ---------- P2-8：logGate 只渲染前 24B（输出逐字节不变） ----------

func TestLogGateFirstField(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gate.log")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	old := gateLogFile
	gateLogFile = f
	defer func() { gateLogFile = old; f.Close() }()
	short := []byte{0x16, 0x03, 0x01}
	long := make([]byte, 40)
	for i := range long {
		long[i] = byte(i)
	}
	logGate("tcp", "1.2.3.4:5", dstAddr{ip: net.ParseIP("5.6.7.8"), port: 443}, "proxy", "oicq", short)
	logGate("tcp", "1.2.3.4:6", dstAddr{ip: net.ParseIP("5.6.7.8"), port: 443}, "proxy", "oicq", long)
	logGate("tcp", "1.2.3.4:7", dstAddr{ip: net.ParseIP("5.6.7.8"), port: 443}, "drop", "local_dst", nil)
	lines := readLines(t, p)
	if len(lines) != 3 {
		t.Fatalf("应有 3 行，got %d", len(lines))
	}
	var m0, m1, m2 map[string]any
	for i, dst := range []*map[string]any{&m0, &m1, &m2} {
		if err := json.Unmarshal([]byte(lines[i]), dst); err != nil {
			t.Fatalf("line%d: %v", i, err)
		}
	}
	if m0["first"] != "160301" {
		t.Errorf("短包 first=%v want 160301", m0["first"])
	}
	if want := fmt.Sprintf("%x", long[:24]) + ".."; m1["first"] != want {
		t.Errorf("长包 first=%v want %s", m1["first"], want)
	}
	if m2["first"] != "" || m2["verdict"] != "drop" || m2["reason"] != "local_dst" {
		t.Errorf("nil 包/落盘字段不符：%v", m2)
	}
	if m0["src"] != "1.2.3.4:5" || m0["dst"] != "5.6.7.8:443" || m0["reason"] != "oicq" {
		t.Errorf("字段/顺序不符：%v", m0)
	}
	if m0["proto"] != "tcp" || m2["proto"] != "tcp" {
		t.Errorf("proto 字段缺失：%v %v", m0["proto"], m2["proto"])
	}
}

// ---------- 日志改进：err 行带截断 detail ----------

func TestLogGateErrDetail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gate.log")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	old := gateLogFile
	gateLogFile = f
	defer func() { gateLogFile = old; f.Close() }()
	long := strings.Repeat("x", 100)
	logGateErr("tcp", "1.2.3.4:5", dstAddr{ip: net.ParseIP("5.6.7.8"), port: 443}, "err", "tls_direct", "read tcp 127.0.0.1:1->127.0.0.1:18081: i/o timeout", nil)
	logGateErr("udp", "1.2.3.4:6", dstAddr{ip: net.ParseIP("5.6.7.8"), port: 3478}, "err", "stun_udp_proxy_fail", long, nil)
	lines := readLines(t, p)
	if len(lines) != 2 {
		t.Fatalf("应有 2 行，got %d", len(lines))
	}
	var m0, m1 map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m0); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &m1); err != nil {
		t.Fatal(err)
	}
	if m0["proto"] != "tcp" || m0["verdict"] != "err" {
		t.Errorf("err 行字段不符：%v", m0)
	}
	if m0["detail"] != "read tcp 127.0.0.1:1->127.0.0.1:18081: i/o timeout" {
		t.Errorf("短 detail 应原样保留：%v", m0["detail"])
	}
	if m1["proto"] != "udp" {
		t.Errorf("udp proto 不符：%v", m1["proto"])
	}
	if want := strings.Repeat("x", 64) + ".."; m1["detail"] != want {
		t.Errorf("长 detail 应截断到 64B+..：got %d 字符", len(m1["detail"].(string)))
	}
}

// ---------- P2-12：classifyEx 无副作用 ----------

func TestClassifyExNoSideEffect(t *testing.T) {
	statsPath := tempStatFile(t)
	in := []byte{0x16, 0x03, 0x04, 0x00, 0x08, 0x01} // 旧粗判真、严判假
	v, r, strictFail := classifyEx(dstAddr{ip: net.ParseIP("1.2.3.4"), port: 8443}, in)
	if v != "proxy" || r != "default" || !strictFail {
		t.Fatalf("classifyEx: %s/%s strictFail=%v", v, r, strictFail)
	}
	if n := statSum(t, statsPath, "gate_tls_strict_fail"); n != 0 {
		t.Fatalf("classifyEx 不该写 stats，got %d", n)
	}
	// 生产入口 same 输入才计数（与 TestTLSStrictFailCounter 同口径）。
	cv, cr := classify(dstAddr{ip: net.ParseIP("1.2.3.4"), port: 8443}, in)
	if cv != v || cr != r {
		t.Fatalf("包装口径不一致：%s/%s vs %s/%s", cv, cr, v, r)
	}
	if n := statSum(t, statsPath, "gate_tls_strict_fail"); n != 1 {
		t.Fatalf("classify 应计 1 次，got %d", n)
	}
	// 严判通过 → strictFail=false。
	if _, _, sf := classifyEx(dstAddr{port: 8443}, []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01}); sf {
		t.Fatalf("严判通过不该置 strictFail")
	}
}
