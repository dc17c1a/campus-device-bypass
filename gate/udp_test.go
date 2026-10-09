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
	stdResp := append([]byte{0x01, 0x01, 0x00, 0x30, 0x21, 0x12, 0xa4, 0x42}, txn...)
	// 变种（实测 110.43.86.135）：0001/0101 + 按流魔数 + txn 配对
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
		{"std-req", stdReq, "hezi", "stun_udp"},
		{"std-resp", stdResp, "hezi", "stun_udp"},
		{"var-req", varReq, "hezi", "stun_udp_var"},
		{"var-resp", varResp, "hezi", "stun_udp_var"},
		{"obf-3478", obf, "direct", "udp_direct"},
		{"rtp", rtp, "direct", "udp_direct"},
		{"short", []byte{0x00, 0x01, 0x02}, "direct", "udp_short"},
		{"empty", nil, "direct", "udp_short"},
	}
	for _, c := range cases {
		if v, r := classifyUDP(c.in); v != c.v || r != c.r {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, v, r, c.v, c.r)
		}
	}
}

func TestSocksEncapRoundTrip(t *testing.T) {
	od := dstAddr{ip: net.ParseIP("110.43.86.135"), port: 3478}
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

func TestUDPVerdictPort80(t *testing.T) {
	txn := []byte{0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1}
	stdReq := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, txn...)
	obf, _ := hex.DecodeString("3bcaac48c3eeefe893a6bcb5d39e90939eb4b3d1")
	rtp := bytes.Repeat([]byte{0x80}, 40)
	od80 := dstAddr{ip: net.ParseIP("8.8.8.8"), port: 80}
	// UDP 80 承接：任何载荷恒 hezi/port80_udp（不看 STUN 形状）。
	for _, p := range [][]byte{stdReq, obf, rtp, {0x00, 0x01, 0x02}, nil, {}} {
		if v, r := udpVerdict(od80, p); v != "hezi" || r != "port80_udp" {
			t.Errorf("port80 len=%d: got %s/%s want hezi/port80_udp", len(p), v, r)
		}
	}
	// 非 80 透传 classifyUDP。
	od443 := dstAddr{ip: net.ParseIP("8.8.8.8"), port: 443}
	if v, r := udpVerdict(od443, stdReq); v != "hezi" || r != "stun_udp" {
		t.Errorf("443 stun: got %s/%s want hezi/stun_udp", v, r)
	}
	if v, r := udpVerdict(od443, obf); v != "direct" || r != "udp_direct" {
		t.Errorf("443 obf: got %s/%s want direct/udp_direct", v, r)
	}
}

func TestUDPVerdictPort8000Range(t *testing.T) {
	txn := []byte{0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1}
	stdReq := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, txn...)
	obf, _ := hex.DecodeString("3bcaac48c3eeefe893a6bcb5d39e90939eb4b3d1")
	short := []byte{0x01, 0x02}
	// 范围内：短包/混淆包翻 hezi/default，STUN 保持原归因（8080 显式锁定）。
	for _, port := range []int{8000, 8080, 8500, 9000} {
		od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: port}
		if v, r := udpVerdict(od, obf); v != "hezi" || r != "default" {
			t.Errorf("port %d obf: got %s/%s want hezi/default", port, v, r)
		}
		if v, r := udpVerdict(od, short); v != "hezi" || r != "default" {
			t.Errorf("port %d short: got %s/%s want hezi/default", port, v, r)
		}
		if v, r := udpVerdict(od, stdReq); v != "hezi" || r != "stun_udp" {
			t.Errorf("port %d stun: got %s/%s want hezi/stun_udp", port, v, r)
		}
	}
	// 范围外：行为不变。
	for _, port := range []int{7999, 9001} {
		od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: port}
		if v, r := udpVerdict(od, obf); v != "direct" || r != "udp_direct" {
			t.Errorf("port %d obf: got %s/%s want direct/udp_direct", port, v, r)
		}
		if v, r := udpVerdict(od, short); v != "direct" || r != "udp_short" {
			t.Errorf("port %d short: got %s/%s want direct/udp_short", port, v, r)
		}
	}
}

func TestUDPVerdictCrossPortStunRelay(t *testing.T) {
	txn := []byte{0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1}
	stdReq := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, txn...)
	varReq := append([]byte{0x00, 0x01, 0x00, 0x08, 0x01, 0x39, 0xf4, 0x5c}, txn...)
	obf, _ := hex.DecodeString("3bcaac48c3eeefe893a6bcb5d39e90939eb4b3d1")
	// 跨端口 STUN（8000/1106 等非三端口）verdict==hezi 即中继，不设端口门限。
	for _, port := range []int{8000, 1106, 443, 12348} {
		od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: port}
		if v, _ := udpVerdict(od, stdReq); v != "hezi" {
			t.Errorf("port %d std stun: verdict=%s want hezi (relay)", port, v)
		}
		if v, _ := udpVerdict(od, varReq); v != "hezi" {
			t.Errorf("port %d var stun: verdict=%s want hezi (relay)", port, v)
		}
		// 8000-9000 兜底：非 STUN 残渣翻 hezi/default，范围外仍 direct。
		if port >= 8000 && port <= 9000 {
			if v, r := udpVerdict(od, obf); v != "hezi" || r != "default" {
				t.Errorf("port %d obf: got %s/%s want hezi/default", port, v, r)
			}
			continue
		}
		if v, _ := udpVerdict(od, obf); v != "direct" {
			t.Errorf("port %d obf: verdict=%s want direct", port, v)
		}
	}
	// 三端口 STUN 仍 hezi（行为不变）。
	for _, port := range []int{3478, 5349, 19302} {
		od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: port}
		if v, _ := udpVerdict(od, stdReq); v != "hezi" {
			t.Errorf("port %d std stun: verdict=%s want hezi", port, v)
		}
	}
}

// 注：中继不设端口门限，verdict==hezi 即中继；中继语义由下述 fail-closed 回归用例覆盖。

func TestNewUDPAssocFailClosed(t *testing.T) {
	old := heziSocks
	heziSocks = "127.0.0.1:1" // 必关端口：assoc 必败
	defer func() { heziSocks = old }()
	txn := []byte{0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1}
	first := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, txn...)
	cases := []struct {
		name    string
		od      dstAddr
		verdict string
		reason  string
	}{
		{"cross-port-stun", dstAddr{ip: net.ParseIP("203.0.113.7"), port: 8000}, "hezi", "stun_udp"},
		{"tri-port-stun", dstAddr{ip: net.ParseIP("203.0.113.7"), port: 3478}, "hezi", "stun_udp"},
		{"udp80", dstAddr{ip: net.ParseIP("203.0.113.7"), port: 80}, "hezi", "port80_udp"},
	}
	for i, c := range cases {
		client := &net.UDPAddr{IP: net.ParseIP("192.168.2.50"), Port: 40000 + i}
		if a := newUDPAssoc(nil, client, c.od, c.verdict, c.reason, first); a != nil {
			a.close()
			t.Errorf("%s: hezi down must return nil (fail-closed), got assoc", c.name)
		}
		udpMu.Lock()
		_, leaked := udpTable[udpAssocKey(client, c.od)]
		udpMu.Unlock()
		if leaked {
			t.Errorf("%s: failed assoc leaked table entry", c.name)
		}
	}
}

func TestNewUDPAssocDirectStillDials(t *testing.T) {
	// verdict==direct 仍直连 dial（非 STUN 路径不受影响）。
	client := &net.UDPAddr{IP: net.ParseIP("192.168.2.51"), Port: 41111}
	od := dstAddr{ip: net.ParseIP("203.0.113.8"), port: 8000}
	a := newUDPAssoc(nil, client, od, "direct", "udp_direct", []byte{0x01, 0x02})
	if a == nil {
		t.Fatalf("direct assoc should dial")
	}
	if a.toHezi {
		t.Errorf("direct assoc must not set toHezi")
	}
	a.close()
}
