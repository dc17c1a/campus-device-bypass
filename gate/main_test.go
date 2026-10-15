package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clientHello(sni string) []byte {
	name := []byte(sni)
	snBody := []byte{byte((len(name) + 3) >> 8), byte(len(name) + 3), 0x00, byte(len(name) >> 8), byte(len(name))}
	snBody = append(snBody, name...)
	snExt := []byte{0x00, 0x00, byte(len(snBody) >> 8), byte(len(snBody))}
	snExt = append(snExt, snBody...)
	exts := snExt
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func TestClassify(t *testing.T) {
	dlDoms.Store(map[string]bool{"down.qq.com": true, "down-update.qq.com": true, "wegame.gtimg.com": true, "download.windowsupdate.com": true, "dl.delivery.mp.microsoft.com": true, "repo.nzm.qq.com": true})
	dlUAs.Store([]string{"thunder", "qqdownload", "idm", "internet download manager", "aria2", "wegame", "valve/steam http client", "microsoft-delivery-optimization"})
	dlExts.Store([]string{"apk", "exe", "msi", "dmg", "iso", "zip", "rar", "7z", "tar.gz", "mp4", "flv", "ts", "m3u8", "mp3", "pdf"})
	dlQuerys.Store([]string{"x-oss-signature", "q-sign-algorithm", "response-content-disposition", "_upt"})
	pub80 := dstAddr{ip: net.ParseIP("8.8.8.8"), port: 80}
	cases := []struct {
		name    string
		od      dstAddr
		b       []byte
		verdict string
		reason  string
	}{
		{"tls-443", dstAddr{port: 443}, clientHello("example.com"), "pass", "tls_direct"},
		{"tls-8443", dstAddr{port: 8443}, clientHello("example.com"), "pass", "tls_direct"},
		{"tls-80", dstAddr{port: 80}, clientHello("example.com"), "pass", "tls_direct"},
		{"tls-former-doh-now-direct", dstAddr{port: 443}, clientHello("dns.google"), "pass", "tls_direct"},
		{"tls-rl-boundary-ok", dstAddr{port: 443}, []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}, "pass", "tls_direct"},
		{"tls-strict-minor-now-proxy", dstAddr{port: 443}, []byte{0x16, 0x03, 0x04, 0x00, 0x08, 0x01}, "proxy", "default"},
		{"tls-strict-b5-now-proxy", dstAddr{port: 5443}, []byte{0x16, 0x03, 0x01, 0x00, 0x08, 0x02}, "proxy", "default"},
		{"ex-mmtls-now-default", dstAddr{port: 443}, []byte{0x16, 0xf1, 0x00, 0x01}, "proxy", "default"},
		{"ex-oicq-now-default", dstAddr{port: 8000}, []byte{0x02, 0x30, 0x31}, "proxy", "default"},
		{"opaque-8000", dstAddr{port: 8000}, []byte{0x05, 0x7b, 0x08, 0x00, 0x01}, "proxy", "default"},
		{"opaque-7999-same", dstAddr{port: 7999}, []byte{0x05, 0x7b, 0x08, 0x00, 0x01}, "proxy", "default"},
		{"empty-silent", dstAddr{port: 9000}, []byte{}, "proxy", "default"},
		{"dl-host-80", dstAddr{port: 80}, []byte("GET /client.zip HTTP/1.1\r\nHost: down.qq.com\r\n\r\n"), "pass", "dl_direct"},
		{"dl-host-odd-port", dstAddr{port: 14000}, []byte("GET /patch.zip HTTP/1.1\r\nHost: down-update.qq.com\r\n\r\n"), "pass", "dl_direct"},
		{"dl-range", dstAddr{port: 8080}, []byte("GET /video.mp4 HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-1023\r\n\r\n"), "pass", "dl_range"},
		{"dl-range-keeps-priority-over-query", dstAddr{port: 8080}, []byte("GET /v?x-oss-signature=a HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-9\r\n\r\n"), "pass", "dl_range"},
		{"dl-query-oss", dstAddr{port: 8080}, []byte("GET /f?x-oss-signature=abc HTTP/1.1\r\nHost: example.com\r\n\r\n"), "pass", "dl_query"},
		{"dl-query-cos", dstAddr{port: 8080}, []byte("GET /f?q-sign-algorithm=sha1&q-ak=x HTTP/1.1\r\nHost: example.com\r\n\r\n"), "pass", "dl_query"},
		{"dl-query-attach", dstAddr{port: 80}, []byte("GET /f?response-content-disposition=attachment HTTP/1.1\r\nHost: example.com\r\n\r\n"), "pass", "dl_query"},
		{"dl-query-upyun", dstAddr{port: 8080}, []byte("GET /f?_upt=abc HTTP/1.1\r\nHost: example.com\r\n\r\n"), "pass", "dl_query"},
		{"query-generic-sign-nohit", dstAddr{port: 80}, []byte("GET /api?sign=abc&expires=123&token=x HTTP/1.1\r\nHost: example.com\r\n\r\n"), "proxy", "default"},
		{"dl-ua-thunder", dstAddr{port: 8080}, []byte("GET /file HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Thunder/7.0\r\n\r\n"), "pass", "dl_ua"},
		{"dl-ext-apk", dstAddr{port: 8080}, []byte("GET /app.apk HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"), "pass", "dl_ext"},
		{"http-nondl-is-proxy", dstAddr{port: 80}, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"), "proxy", "default"},
		{"http-former-kw-now-default", dstAddr{port: 80}, []byte("GET /x HTTP/1.1\r\nHost: www.douyin.com\r\n\r\n"), "proxy", "default"},
		{"not-http-binary", dstAddr{port: 80}, []byte("GARBAGE this is not http\r\n"), "proxy", "default"},
		{"port80-empty", pub80, []byte{}, "proxy", "default"},
		{"port80-pub-binary", pub80, []byte{0x00, 0x01, 0x02, 0x03}, "proxy", "default"},
	}
	for _, c := range cases {
		v, r := classify(c.od, c.b)
		if v != c.verdict || r != c.reason {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, v, r, c.verdict, c.reason)
		}
	}
}

func TestIsTLSClientHello(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"ok", []byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x01}, true},
		{"minor-00-ok", []byte{0x16, 0x03, 0x00, 0x00, 0x20, 0x01}, true},
		{"minor-03-ok", []byte{0x16, 0x03, 0x03, 0x00, 0x20, 0x01}, true},
		{"minor-04-bad", []byte{0x16, 0x03, 0x04, 0x00, 0x20, 0x01}, false},
		{"rl-0-bad", []byte{0x16, 0x03, 0x01, 0x00, 0x00, 0x01}, false},
		{"rl-1-ok", []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}, true},
		{"rl-3-ok", []byte{0x16, 0x03, 0x01, 0x00, 0x03, 0x01}, true},
		{"rl-4-ok", []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01}, true},
		{"rl-18432-ok", []byte{0x16, 0x03, 0x01, 0x48, 0x00, 0x01}, true},
		{"rl-18433-bad", []byte{0x16, 0x03, 0x01, 0x48, 0x01, 0x01}, false},
		{"b5-02-bad", []byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x02}, false},
		{"b5-00-bad", []byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x00}, false},
		{"b1-f1-bad", []byte{0x16, 0xf1, 0x00, 0x01, 0x00, 0x01}, false},
		{"len5-bad", []byte{0x16, 0x03, 0x01, 0x00, 0x04}, false},
	}
	for _, c := range cases {
		if got := isTLSClientHello(c.b); got != c.want {
			t.Errorf("%s: got %v want %v (b=%x)", c.name, got, c.want, c.b)
		}
	}
}

func TestTLSStrictFailCounter(t *testing.T) {
	dir := t.TempDir()
	old := statFile
	f, err := os.OpenFile(filepath.Join(dir, "stats.tsv"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	statFile = f
	defer func() { statFile = old; f.Close() }()
	// 旧粗判真、严判假（minor=0x04）→ 计数。
	if v, r := classify(dstAddr{port: 8443}, []byte{0x16, 0x03, 0x04, 0x00, 0x08, 0x01}); v != "proxy" || r != "default" {
		t.Fatalf("classify: got %s/%s want proxy/default", v, r)
	}
	// 严判真：不计数。
	classify(dstAddr{port: 8443}, []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01})
	b, err := os.ReadFile(filepath.Join(dir, "stats.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "gate_tls_strict_fail"); n != 1 {
		t.Fatalf("counter lines: got %d want 1 (file=%q)", n, b)
	}
}

func TestPeekClientShortRead(t *testing.T) {
	oldWait := peekWait
	peekWait = 200 * time.Millisecond
	defer func() { peekWait = oldWait }()
	buf := make([]byte, 1024)

	// TLS 短读补齐：先到 2B（16 03），20ms 后到其余；补齐到完整首包。
	c1, s1 := net.Pipe()
	defer c1.Close()
	defer s1.Close()
	hello := clientHello("peek.example.com")
	go func() {
		_, _ = s1.Write(hello[:2])
		time.Sleep(20 * time.Millisecond)
		_, _ = s1.Write(hello[2:])
	}()
	n := peekClient(c1, buf, 8443)
	if n != len(hello) {
		t.Fatalf("short-read fill: got n=%d want %d", n, len(hello))
	}
	if v, r := classify(dstAddr{port: 8443}, buf[:n]); v != "pass" || r != "tls_direct" {
		t.Fatalf("filled classify: got %s/%s want direct/tls_direct", v, r)
	}

	// mmtls 早停：16 f1 两字节即返回，不等补齐。
	c2, s2 := net.Pipe()
	defer c2.Close()
	defer s2.Close()
	go func() { _, _ = s2.Write([]byte{0x16, 0xf1}) }()
	start := time.Now()
	if n2 := peekClient(c2, buf, 8443); n2 != 2 || time.Since(start) > 100*time.Millisecond {
		t.Fatalf("mmtls early stop: n=%d elapsed=%v", n2, time.Since(start))
	}

	// oicq 单字节/短包：行为不变（0x02 不被 0x16 补齐分支吞掉）。
	c3, s3 := net.Pipe()
	defer c3.Close()
	defer s3.Close()
	go func() { _, _ = s3.Write([]byte{0x02, 0x30, 0x31}) }()
	if n3 := peekClient(c3, buf, 8443); n3 == 0 {
		t.Fatalf("oicq peek: got 0")
	}
}

func TestDLExtMatch(t *testing.T) {
	dlExts.Store([]string{"apk", "tar.gz", "7z", "flv"})
	for _, p := range []string{"/a.apk", "/a.APK", "/v.apk?sign=x", "/r.tar.gz", "/f.7z", "/x.flv"} {
		if !dlExtHit(p) {
			t.Errorf("should hit %s", p)
		}
	}
	for _, p := range []string{"/a.json", "/a.js", "/a.css", "/apk", "/x.apk/", "/index.html", ""} {
		if dlExtHit(p) {
			t.Errorf("should miss %s", p)
		}
	}
	dlUAs.Store([]string{"thunder", "internet download manager"})
	if !dlUAHit("Thunder/7.0") || !dlUAHit("Internet Download Manager/6.0") {
		t.Errorf("dl ua should hit")
	}
	if dlUAHit("Mozilla/5.0") {
		t.Errorf("dl ua should miss Mozilla")
	}
}

func TestDLReload(t *testing.T) {
	oldDom, oldUA, oldExt, oldQ := dlDomPath, dlUAPath, dlExtPath, dlQueryPath
	defer func() { dlDomPath, dlUAPath, dlExtPath, dlQueryPath = oldDom, oldUA, oldExt, oldQ }()
	dir := t.TempDir()
	dlDomPath = filepath.Join(dir, "dl-domains.txt")
	dlUAPath = filepath.Join(dir, "dl-ua.txt")
	dlExtPath = filepath.Join(dir, "dl-ext.txt")
	dlQueryPath = filepath.Join(dir, "dl-query.txt")
	if err := os.WriteFile(dlDomPath, []byte("down.qq.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dlUAPath, []byte("thunder\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dlExtPath, []byte("apk\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dlQueryPath, []byte("x-oss-signature\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if nd, nu, ne, nq := loadDLLists(); nd != 1 || nu != 1 || ne != 1 || nq != 1 {
		t.Fatalf("load: got %d/%d/%d/%d want 1/1/1/1", nd, nu, ne, nq)
	}
	if !dlDomainHit("a.down.qq.com") || dlDomainHit("example.com") {
		t.Fatalf("dl dom snapshot mismatch")
	}
	if !dlUAHit("x-thunder-y") || !dlExtHit("/a.apk") {
		t.Fatalf("dl snapshot mismatch")
	}
	if !dlQueryHit("/f?x-oss-signature=abc") || dlQueryHit("/api?sign=abc") {
		t.Fatalf("dl query snapshot mismatch")
	}
	if checkDLReload() {
		t.Fatalf("no-change reload should be false")
	}
	f, err := os.OpenFile(dlDomPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("example-dl.test\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	mt := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(dlDomPath, mt, mt); err != nil {
		t.Fatal(err)
	}
	if !checkDLReload() {
		t.Fatalf("changed reload should be true")
	}
	if !dlDomainHit("example-dl.test") || !dlDomainHit("down.qq.com") {
		t.Fatalf("snapshot mismatch after reload")
	}
}

// TestPeekClient80 证明 R8 opportunistic peek：完整 handleConn 需 origdst
// （conntrack SO_ORIGINAL_DST，net.Pipe 不可测），故此处测 peekClient 单元 +
// classify 组合：有数据→首包可达 dl_direct；静默→n=0 落 proxy/default。
func TestPeekClient80(t *testing.T) {
	oldWait := peekWait80
	oldDL := dlDomSnapshot()
	if oldDL == nil {
		oldDL = map[string]bool{}
	}
	peekWait80 = 20 * time.Millisecond
	dlDoms.Store(map[string]bool{"down.qq.com": true})
	defer func() { peekWait80 = oldWait; dlDoms.Store(oldDL) }()
	buf := make([]byte, 1024)
	// :80 有数据：短读拿到首包 → classify 可达 direct/dl_direct。
	c1, s1 := net.Pipe()
	defer c1.Close()
	defer s1.Close()
	payload := "GET /client.zip HTTP/1.1\r\nHost: down.qq.com\r\n\r\n"
	go func() { _, _ = s1.Write([]byte(payload)) }()
	n := peekClient(c1, buf, 80)
	if string(buf[:n]) != payload {
		t.Fatalf("80 peek data: got %q want %q", buf[:n], payload)
	}
	if v, r := classify(dstAddr{port: 80}, buf[:n]); v != "pass" || r != "dl_direct" {
		t.Fatalf("80 peek classify: got %s/%s want direct/dl_direct", v, r)
	}
	// :80 静默：超时落空 → proxy/default（fail-closed）。
	c2, s2 := net.Pipe()
	defer c2.Close()
	defer s2.Close()
	if n := peekClient(c2, buf, 80); n != 0 {
		t.Fatalf("80 silent peek: got n=%d want 0", n)
	}
	if v, r := classify(dstAddr{port: 80}, buf[:0]); v != "proxy" || r != "default" {
		t.Fatalf("80 empty classify: got %s/%s want proxy/default", v, r)
	}
	// 非 80 路径不受影响。
	c3, s3 := net.Pipe()
	defer c3.Close()
	defer s3.Close()
	go func() { _, _ = s3.Write([]byte("GET /x HTTP/1.1\r\n\r\n")) }()
	if n := peekClient(c3, buf, 8080); n == 0 {
		t.Fatalf("8080 peek: got 0")
	}
}

func TestParseLineSet(t *testing.T) {
	m := parseLineSet([]byte("# c\nDNS.Google\n0.0.0.0 doh.pub\n\n  x.example.com  \nbad line here\n"))
	if !(m["dns.google"] && m["doh.pub"] && m["x.example.com"]) || len(m) != 3 {
		t.Errorf("parse got %v", m)
	}
}

func TestDefProxySocksTargetsGroupInbound(t *testing.T) {
	// gate 判 proxy 的拨号目标必须是下游代理的 socks 入站（默认 127.0.0.1:10811），由代理侧做故障转移。
	if defProxySocks != "127.0.0.1:10811" {
		t.Fatalf("defProxySocks = %q, want 127.0.0.1:10811 (downstream proxy inbound)", defProxySocks)
	}
}

func TestRangeStrength(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"multi-segment", []byte("GET /v HTTP/1.1\r\nHost: e.com\r\nRange: bytes=0-99,200-299\r\n\r\n"), true},
		{"if-range", []byte("GET /v HTTP/1.1\r\nHost: e.com\r\nRange: bytes=0-\r\nIf-Range: \"abc\"\r\n\r\n"), true},
		{"nonzero-start", []byte("GET /v HTTP/1.1\r\nHost: e.com\r\nRange: bytes=1024-\r\n\r\n"), true},
		{"single-zero", []byte("GET /v HTTP/1.1\r\nHost: e.com\r\nRange: bytes=0-1023\r\n\r\n"), false},
		{"suffix-only", []byte("GET /v HTTP/1.1\r\nHost: e.com\r\nRange: bytes=-500\r\n\r\n"), false},
		{"no-range", []byte("GET /v HTTP/1.1\r\nHost: e.com\r\n\r\n"), false},
		{"range-in-body-only", []byte("POST /u HTTP/1.1\r\nHost: e.com\r\n\r\n{\"r\":\"Range: bytes=0-1,2-3\"}"), false},
	}
	for _, c := range cases {
		if got := rangeStrong(c.b); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
