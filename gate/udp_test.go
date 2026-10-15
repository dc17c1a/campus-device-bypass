package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func TestClassifyUDP(t *testing.T) {
	txn := []byte{0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1}
	stdReq := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, txn...)
	// stdResp 自洽包：msgLen 0x0030=48，20+48=68B（头 8B + txn 12B + 补 48B）。
	stdResp := append(append([]byte{0x01, 0x01, 0x00, 0x30, 0x21, 0x12, 0xa4, 0x42}, txn...), make([]byte, 48)...)
	// 长度不一致：声明 48B、实长 20B → direct/udp_direct。
	stdLenMismatch := append([]byte{0x00, 0x01, 0x00, 0x30, 0x21, 0x12, 0xa4, 0x42}, txn...)
	// 变种（某系）：0001/0101 + 按流魔数 + txn 配对
	varReq := append([]byte{0x00, 0x01, 0x00, 0x08, 0x01, 0x39, 0xf4, 0x5c}, txn...)
	varResp := append([]byte{0x01, 0x01, 0x00, 0x48, 0x01, 0x39, 0xf4, 0x5c}, txn...)
	// 混淆包（实测 119.147.3.59:3478）：20B 随机
	obf, _ := hex.DecodeString("3bcaac48c3eeefe893a6bcb5d39e90939eb4b3d1")
	rtp := bytes.Repeat([]byte{0x80}, 40) // RTP 首字节 10xxxxxx
	cases := []struct {
		name string
		in   []byte
		v, r string
	}{
		{"std-req", stdReq, "proxy", "stun_udp"},
		{"std-resp", stdResp, "proxy", "stun_udp"},
		{"std-len-mismatch", stdLenMismatch, "pass", "udp_direct"},
		{"var-req", varReq, "proxy", "stun_udp_var"},
		{"var-resp", varResp, "proxy", "stun_udp_var"},
		{"obf-3478", obf, "pass", "udp_direct"},
		{"rtp", rtp, "pass", "udp_direct"},
		{"short", []byte{0x00, 0x01, 0x02}, "pass", "udp_short"},
		{"empty", nil, "pass", "udp_short"},
	}
	for _, c := range cases {
		if v, r := classifyUDP(c.in); v != c.v || r != c.r {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, v, r, c.v, c.r)
		}
	}
}

func TestSocksEncapRoundTrip(t *testing.T) {
	od := dstAddr{ip: net.ParseIP("203.0.113.9"), port: 3478}
	pay := []byte{0x00, 0x01, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04}
	enc := socksEncap(od, pay)
	if len(enc) != 18 || enc[3] != 1 || enc[8] != 0x0d || enc[9] != 0x96 {
		t.Fatalf("encap hdr wrong: %x", enc[:10])
	}
	dec, err := socksDecap(enc)
	if err != nil || !bytes.Equal(dec, pay) {
		t.Fatalf("decap: %v %x", err, dec)
	}
	if _, err := socksDecap(enc[:9]); err == nil {
		t.Errorf("short decap should fail")
	}
	if _, err := socksDecap(append([]byte{0, 0, 0, 3}, pay...)); err == nil {
		t.Errorf("non-ipv4 atyp should fail")
	}
}

func TestReapUDPAssoc(t *testing.T) {
	a := &udpAssoc{key: "test|1.2.3.4:3478"}
	a.last.Store(time.Now().Add(-time.Hour).UnixNano())
	udpMu.Lock()
	udpTable[a.key] = a
	udpMu.Unlock()
	if n := reapUDPAssoc(time.Minute); n != 1 {
		t.Fatalf("reap got %d", n)
	}
	udpMu.Lock()
	_, ok := udpTable[a.key]
	udpMu.Unlock()
	if ok {
		t.Errorf("assoc not reaped")
	}
	if n := reapUDPAssoc(time.Minute); n != 0 {
		t.Errorf("empty reap got %d", n)
	}
}

func mkOrigDstCmsg(ip [4]byte, port int) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint64(b[0:8], 32)   // cmsg len
	binary.LittleEndian.PutUint32(b[8:12], 0)   // SOL_IP
	binary.LittleEndian.PutUint32(b[12:16], 20) // IP_ORIGDSTADDR
	binary.LittleEndian.PutUint16(b[16:18], 2)  // AF_INET
	binary.BigEndian.PutUint16(b[18:20], uint16(port))
	copy(b[20:24], ip[:])
	return b
}

func TestParseOrigDst(t *testing.T) {
	od, ok := parseOrigDst(mkOrigDstCmsg([4]byte{74, 125, 250, 129}, 19302))
	if !ok || od.port != 19302 || od.ip.String() != "74.125.250.129" {
		t.Fatalf("got %v %v", od, ok)
	}
	if _, ok := parseOrigDst(nil); ok {
		t.Errorf("nil oob should fail")
	}
	bad := mkOrigDstCmsg([4]byte{1, 2, 3, 4}, 3478)
	binary.LittleEndian.PutUint32(bad[12:16], 21) // wrong type
	if _, ok := parseOrigDst(bad); ok {
		t.Errorf("wrong cmsg type should fail")
	}
	if _, ok := parseOrigDst(mkOrigDstCmsg([4]byte{1, 2, 3, 4}, 3478)[:10]); ok {
		t.Errorf("truncated oob should fail")
	}
	zero := mkOrigDstCmsg([4]byte{1, 2, 3, 4}, 0)
	if _, ok := parseOrigDst(zero); ok {
		t.Errorf("zero port should fail")
	}
}

func TestUDPVerdictPortRule(t *testing.T) {
	txn := []byte{0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1}
	stdReq := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, txn...)
	obf, _ := hex.DecodeString("3bcaac48c3eeefe893a6bcb5d39e90939eb4b3d1")
	rtp := bytes.Repeat([]byte{0x80}, 40)
	od80 := dstAddr{ip: net.ParseIP("8.8.8.8"), port: 80}
	// ≤10000 非 STUN 走端口规则 proxy/udp_proxy；STUN 形状（v3 优先）记 stun_*。
	for _, p := range [][]byte{obf, rtp, {0x00, 0x01, 0x02}, nil, {}} {
		if v, r := udpVerdict(od80, p); v != "proxy" || r != "udp_proxy" {
			t.Errorf("port80 len=%d: got %s/%s want proxy/udp_proxy", len(p), v, r)
		}
	}
	if v, r := udpVerdict(od80, stdReq); v != "proxy" || r != "stun_udp" {
		t.Errorf("port80 stun: got %s/%s want proxy/stun_udp", v, r)
	}
	// 443 ≤10000：非 STUN 走端口规则，STUN 形状记 stun_*。
	od443 := dstAddr{ip: net.ParseIP("8.8.8.8"), port: 443}
	if v, r := udpVerdict(od443, stdReq); v != "proxy" || r != "stun_udp" {
		t.Errorf("443 stun: got %s/%s want proxy/stun_udp", v, r)
	}
	if v, r := udpVerdict(od443, obf); v != "proxy" || r != "udp_proxy" {
		t.Errorf("443 obf: got %s/%s want proxy/udp_proxy", v, r)
	}
	// >10000 按 STUN 形状判。
	od15000 := dstAddr{ip: net.ParseIP("8.8.8.8"), port: 15000}
	if v, r := udpVerdict(od15000, stdReq); v != "proxy" || r != "stun_udp" {
		t.Errorf("15000 stun: got %s/%s want proxy/stun_udp", v, r)
	}
	if v, r := udpVerdict(od15000, obf); v != "pass" || r != "udp_direct" {
		t.Errorf("15000 obf: got %s/%s want direct/udp_direct", v, r)
	}
}

func TestUDPVerdictBoundary10000(t *testing.T) {
	txn := []byte{0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1}
	stdReq := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, txn...)
	varReq := append([]byte{0x00, 0x01, 0x00, 0x08, 0x01, 0x39, 0xf4, 0x5c}, txn...)
	obf, _ := hex.DecodeString("3bcaac48c3eeefe893a6bcb5d39e90939eb4b3d1")
	short := []byte{0x01, 0x02}
	// ≤10000：非 STUN 一律 proxy/udp_proxy；STUN 形状（v3 优先）记 stun_udp
	//（stdReq 长 20B、msgLen 0，20+0≤20 自洽，照样先判形状）。
	for _, port := range []int{80, 3478, 8000, 8080, 9999, 10000} {
		od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: port}
		if v, r := udpVerdict(od, obf); v != "proxy" || r != "udp_proxy" {
			t.Errorf("port %d obf: got %s/%s want proxy/udp_proxy", port, v, r)
		}
		if v, r := udpVerdict(od, short); v != "proxy" || r != "udp_proxy" {
			t.Errorf("port %d short: got %s/%s want proxy/udp_proxy", port, v, r)
		}
		if v, r := udpVerdict(od, stdReq); v != "proxy" || r != "stun_udp" {
			t.Errorf("port %d stun: got %s/%s want proxy/stun_udp", port, v, r)
		}
		if v, r := udpVerdict(od, varReq); v != "proxy" || r != "stun_udp_var" {
			t.Errorf("port %d var: got %s/%s want proxy/stun_udp_var", port, v, r)
		}
	}
	// >10000 按形状判。
	for _, port := range []int{10001, 19302, 40000} {
		od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: port}
		if v, r := udpVerdict(od, obf); v != "pass" || r != "udp_direct" {
			t.Errorf("port %d obf: got %s/%s want direct/udp_direct", port, v, r)
		}
		if v, r := udpVerdict(od, short); v != "pass" || r != "udp_short" {
			t.Errorf("port %d short: got %s/%s want direct/udp_short", port, v, r)
		}
		if v, r := udpVerdict(od, stdReq); v != "proxy" || r != "stun_udp" {
			t.Errorf("port %d stun: got %s/%s want proxy/stun_udp", port, v, r)
		}
		if v, r := udpVerdict(od, varReq); v != "proxy" || r != "stun_udp_var" {
			t.Errorf("port %d var: got %s/%s want proxy/stun_udp_var", port, v, r)
		}
	}
}

func TestUDPVerdictCrossPortStunRelay(t *testing.T) {
	txn := []byte{0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1}
	stdReq := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, txn...)
	varReq := append([]byte{0x00, 0x01, 0x00, 0x08, 0x01, 0x39, 0xf4, 0x5c}, txn...)
	obf, _ := hex.DecodeString("3bcaac48c3eeefe893a6bcb5d39e90939eb4b3d1")
	// P2：跨端口 STUN（8000/1106 等非三端口）verdict==proxy 即中继，不再有端口门限。
	for _, port := range []int{8000, 1106, 443, 12348} {
		od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: port}
		if v, _ := udpVerdict(od, stdReq); v != "proxy" {
			t.Errorf("port %d std stun: verdict=%s want proxy (relay)", port, v)
		}
		if v, _ := udpVerdict(od, varReq); v != "proxy" {
			t.Errorf("port %d var stun: verdict=%s want proxy (relay)", port, v)
		}
		// ≤10000 走端口规则 proxy/udp_proxy，>10000 非 STUN 仍 direct。
		if port <= 10000 {
			if v, r := udpVerdict(od, obf); v != "proxy" || r != "udp_proxy" {
				t.Errorf("port %d obf: got %s/%s want proxy/udp_proxy", port, v, r)
			}
			continue
		}
		if v, _ := udpVerdict(od, obf); v != "pass" {
			t.Errorf("port %d obf: verdict=%s want direct", port, v)
		}
	}
	// 三端口 STUN 仍 proxy（行为不变）。
	for _, port := range []int{3478, 5349, 19302} {
		od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: port}
		if v, _ := udpVerdict(od, stdReq); v != "proxy" {
			t.Errorf("port %d std stun: verdict=%s want proxy", port, v)
		}
	}
}

// 注：isStunRelayPort 与 gate_stun_observe 已退役（P2 删端口门限，verdict==proxy 即中继）。
// 此处不再引用该函数（引用即编译失败）；中继语义由下述 fail-closed 回归用例覆盖。

func TestNewUDPAssocFailClosed(t *testing.T) {
	old := proxySocks
	proxySocks = "127.0.0.1:1" // 必关端口：assoc 必败
	defer func() { proxySocks = old }()
	txn := []byte{0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1}
	first := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, txn...)
	cases := []struct {
		name    string
		od      dstAddr
		verdict string
		reason  string
	}{
		{"cross-port-stun", dstAddr{ip: net.ParseIP("203.0.113.7"), port: 8000}, "proxy", "stun_udp"},
		{"tri-port-stun", dstAddr{ip: net.ParseIP("203.0.113.7"), port: 3478}, "proxy", "stun_udp"},
		{"udp80", dstAddr{ip: net.ParseIP("203.0.113.7"), port: 80}, "proxy", "udp_proxy"},
	}
	for i, c := range cases {
		client := &net.UDPAddr{IP: net.ParseIP("192.168.2.50"), Port: 40000 + i}
		a := startUDPAssoc(nil, client, c.od, c.verdict, c.reason, first)
		if a == nil {
			t.Errorf("%s: startUDPAssoc 不该返回 nil（失败是异步的）", c.name)
			continue
		}
		// P2-10 建链在后台，失败后自己移表：轮询等它消失（fail-closed 不留残表）。
		deadline := time.Now().Add(3 * time.Second)
		for {
			udpMu.Lock()
			_, in := udpTable[udpAssocKey(client, c.od)]
			udpMu.Unlock()
			if !in {
				break
			}
			if time.Now().After(deadline) {
				t.Errorf("%s: 失败 assoc 未移表（表泄漏）", c.name)
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !a.toProxy.Load() {
			t.Errorf("%s: proxy 建链失败不许回退 direct", c.name)
		}
	}
}

func TestSpoofUDPRejectsBadDst(t *testing.T) {
	// 非 v4 / 零端口一律拒绝（不碰 syscall，无权限也可跑）。
	if _, err := spoofUDP(dstAddr{}); err == nil {
		t.Errorf("spoofUDP(empty) 必须拒绝")
	}
	if _, err := spoofUDP(dstAddr{ip: net.ParseIP("::1"), port: 20501}); err == nil {
		t.Errorf("spoofUDP(v6) 必须拒绝")
	}
	if _, err := spoofUDP(dstAddr{ip: net.ParseIP("192.0.2.1"), port: 0}); err == nil {
		t.Errorf("spoofUDP(port 0) 必须拒绝")
	}
}

func TestSpoofUDPForeignBind(t *testing.T) {
	// 外部地址 bind 需 CAP_NET_ADMIN：无权限则跳过（生产 root 必过）。
	sp, err := spoofUDP(dstAddr{ip: net.ParseIP("192.0.2.1"), port: 54321})
	if err != nil {
		t.Skipf("无透明 bind 权限，跳过（生产环境 root 运行）: %v", err)
	}
	defer sp.Close()
	la, ok := sp.LocalAddr().(*net.UDPAddr)
	if !ok || !la.IP.Equal(net.ParseIP("192.0.2.1")) || la.Port != 54321 {
		t.Errorf("spoof 本地地址错误：%v", sp.LocalAddr())
	}
	// 同一地址二次 bind（多 assoc 复用 od）必须成功：SO_REUSEADDR。
	sp2, err := spoofUDP(dstAddr{ip: net.ParseIP("192.0.2.1"), port: 54321})
	if err != nil {
		t.Errorf("同 od 二次 bind 必须成功（SO_REUSEADDR）: %v", err)
	} else {
		sp2.Close()
	}
}

func TestUDPPumpSpoofsDownlinkSource(t *testing.T) {
	// 下行源必须是 spoof 口地址（服务端），而非 srv 监听口（握手期校验源的客户端会拒收）。
	newSock := func(t *testing.T) *net.UDPConn {
		t.Helper()
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return pc.(*net.UDPConn)
	}
	client := newSock(t)
	defer client.Close()
	srv := newSock(t)
	defer srv.Close()
	spoof := newSock(t) // 手工 spoof 口（回环本地地址，无需 TRANSPARENT）
	svc := newSock(t)
	defer svc.Close()
	up, err := net.DialUDP("udp", nil, svc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	a := &udpAssoc{
		key:    "test/spoof",
		client: client.LocalAddr().(*net.UDPAddr),
		dst:    dstAddr{ip: net.ParseIP("203.0.113.21"), port: 20501},
		srv:    srv,
		spoof:  spoof,
		state:  udpReady,
		up:     up,
	}
	payload := []byte{0x00, 0x00, 0x00, 0xff, 0x01, 0x02}
	go udpPump(a, a.gen, false)
	defer a.close()
	if _, err := svc.WriteToUDP(payload, up.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("svc 写入失败: %v", err)
	}
	buf := make([]byte, 1500)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client 未收到下行: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("载荷被改动")
	}
	if !from.IP.Equal(spoof.LocalAddr().(*net.UDPAddr).IP) || from.Port != spoof.LocalAddr().(*net.UDPAddr).Port {
		t.Errorf("下行源错误：got %v want spoof %v（srv 为 %v）", from, spoof.LocalAddr(), srv.LocalAddr())
	}
}

func TestUDPPumpFallsBackToSrv(t *testing.T) {
	// 无 spoof（bind 失败）时下行源回退 srv（旧语义）。
	newSock := func(t *testing.T) *net.UDPConn {
		t.Helper()
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return pc.(*net.UDPConn)
	}
	client := newSock(t)
	defer client.Close()
	srv := newSock(t)
	defer srv.Close()
	svc := newSock(t)
	defer svc.Close()
	up, err := net.DialUDP("udp", nil, svc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	a := &udpAssoc{
		key:    "test/fallback",
		client: client.LocalAddr().(*net.UDPAddr),
		dst:    dstAddr{ip: net.ParseIP("203.0.113.9"), port: 20501},
		srv:    srv,
		state:  udpReady,
		up:     up,
	}
	payload := []byte{0x01, 0x02, 0x03}
	go udpPump(a, a.gen, false)
	defer a.close()
	if _, err := svc.WriteToUDP(payload, up.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("svc 写入失败: %v", err)
	}
	buf := make([]byte, 1500)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client 未收到下行: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Errorf("载荷被改动")
	}
	if !from.IP.Equal(srv.LocalAddr().(*net.UDPAddr).IP) || from.Port != srv.LocalAddr().(*net.UDPAddr).Port {
		t.Errorf("回退下行源错误：got %v want srv %v", from, srv.LocalAddr())
	}
}
func TestNewUDPAssocPassStillDials(t *testing.T) {
	// verdict==direct 仍直连 dial（非 STUN 路径不受 P2-10 影响）。
	client := &net.UDPAddr{IP: net.ParseIP("192.168.2.51"), Port: 41111}
	od := dstAddr{ip: net.ParseIP("203.0.113.8"), port: 8000}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	srv := pc.(*net.UDPConn)
	a := startUDPAssoc(srv, client, od, "pass", "udp_direct", []byte{0x01, 0x02})
	if a == nil {
		t.Fatalf("direct assoc should dial")
	}
	defer a.close()
	// 建链异步：等它 ready。
	deadline := time.Now().Add(3 * time.Second)
	for {
		a.mu.Lock()
		st := a.state
		a.mu.Unlock()
		if st == udpReady || time.Now().After(deadline) {
			if st != udpReady {
				t.Fatalf("direct assoc 未就绪，state=%d", st)
			}
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if a.toProxy.Load() {
		t.Errorf("direct assoc must not set toProxy")
	}
}
