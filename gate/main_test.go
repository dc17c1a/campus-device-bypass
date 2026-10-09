package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
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

// msfPkt 构造 MSF/Beacon 族测试包：u16be 首部为自述包长 decl，
// 08 00 命令族 + 07 06 07 62 常量尾，bufLen 模拟 peek 截断。
func msfPkt(decl, bufLen int) []byte {
	return msfPktB4(decl, bufLen, 0x07)
}

// msfPktB4 同上，b4 可取 {06,07,08}（同族三值）。
func msfPktB4(decl, bufLen int, b4 byte) []byte {
	b := make([]byte, bufLen)
	b[0] = byte(decl >> 8)
	b[1] = byte(decl)
	b[2] = 0x08
	b[3] = 0x00
	b[4] = b4
	b[5] = 0x06
	b[6] = 0x07
	b[7] = 0x62
	return b
}

// msfU32Pkt 构造 MSF 家族 u32be 变种测试包：u32be 包长 + 01 33 52 39
// + u32be 0 + 04 "MSF" + 05，bufLen 模拟 peek 截断（实测 443/8080/14000 通用）。
func msfU32Pkt(bufLen int) []byte {
	b := make([]byte, bufLen)
	binary.BigEndian.PutUint32(b[0:4], 21)
	if bufLen > 4 {
		b[4] = 0x01
	}
	if bufLen > 7 {
		b[5], b[6], b[7] = 0x33, 0x52, 0x39
	}
	if bufLen > 12 {
		b[12] = 0x04
	}
	if bufLen > 15 {
		copy(b[13:], "MSF")
	}
	if bufLen > 16 {
		b[16] = 0x05
	}
	return b
}

// typeCompressPkt 构造 TYPE_COMPRESS 变种测试包：u16be decl + 08 00 +
// b4/b5/b6 + offset 7 起 "TYPE_COMPRESS" 13 字节 ASCII，bufLen 模拟截断。
func typeCompressPkt(decl, bufLen int) []byte {
	b := make([]byte, bufLen)
	b[0] = byte(decl >> 8)
	b[1] = byte(decl)
	b[2] = 0x08
	b[3] = 0x00
	b[4] = 0x07
	b[5] = 0x06
	b[6] = 0x0d
	copy(b[7:], "TYPE_COMPRESS")
	return b
}

// zeroHdrPkt 构造 MSF 家族全零头变种测试包：00 00 00 len
// 00 00 00 c8（实测 QQ 8080：len=0x1a/0x20），bufLen 模拟截断。
func zeroHdrPkt(hdrLen byte, bufLen int) []byte {
	b := make([]byte, bufLen)
	b[3] = hdrLen
	if bufLen > 7 {
		b[7] = 0xc8
	}
	return b
}

// msf0806c73Pkt 构造 MSF 家族 0806 变种测试包：08 XX 08 00
// 07 06 0c 73（实测腾讯游戏鉴权 8081，XX 随包长变），bufLen 模拟截断。
func msf0806c73Pkt(b1 byte, bufLen int) []byte {
	b := make([]byte, bufLen)
	b[0] = 0x08
	b[1] = b1
	if bufLen > 2 {
		b[2] = 0x08
	}
	if bufLen > 4 {
		b[3], b[4] = 0x00, 0x07
	}
	if bufLen > 6 {
		b[5], b[6] = 0x06, 0x0c
	}
	if bufLen > 7 {
		b[7] = 0x73
	}
	return b
}

// stunPkt 构造长度前缀 STUN Binding 测试包：decl 为后随长度，
// bufLen 为实际缓冲（模拟截断）；STUN len 字段按 decl-20 回填以自洽。
func stunPkt(decl, bufLen int) []byte {
	b := make([]byte, bufLen)
	b[0] = byte(decl >> 8)
	b[1] = byte(decl)
	b[2] = 0x00
	b[3] = 0x01
	stunLen := decl - 20
	b[4] = byte(stunLen >> 8)
	b[5] = byte(stunLen)
	b[6] = 0x21
	b[7] = 0x12
	b[8] = 0xa4
	b[9] = 0x42
	return b
}

func TestXrayBindAddr(t *testing.T) {
	ip, port := xrayBindAddr(&net.TCPAddr{IP: net.ParseIP("192.168.2.111"), Port: 59630})
	if ip == nil || port != 59630 || !ip.Equal(net.ParseIP("127.0.0.111")) {
		t.Fatalf("lan map: got %v:%d", ip, port)
	}
	if ip, _ := xrayBindAddr(&net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 1234}); ip != nil {
		t.Fatalf("non-lan should be nil, got %v", ip)
	}
}

func TestClassify(t *testing.T) {
	kws.Store([]string{"douyincdn.com", "douyin.com", "qq.com", "mmtls", "com.ss.android.ugc.aweme", "micromessenger"})
	dlDoms.Store(map[string]bool{"down.qq.com": true, "down-update.qq.com": true, "wegame.gtimg.com": true, "down.anticheatexpert.com": true, "ctldl.windowsupdate.com": true, "download.windowsupdate.com": true, "dl.delivery.mp.microsoft.com": true, "st.dl.eccdnx.com": true, "dl.steam.clngaa.com": true, "gstore.val.smogfly.com": true, "xz.pphimalayanrt.com": true, "update.microsoft.com": true, "windowsupdate.microsoft.com": true, "officecdn.microsoft.com": true, "download.microsoft.com": true, "emdl.ws.microsoft.com": true, "mp.microsoft.com": true, "repo.nzm.qq.com": true})
	dlUAs.Store([]string{"thunder", "qqdownload", "idm", "internet download manager", "aria2", "wegame", "valve/steam http client", "microsoft-delivery-optimization"})
	dlExts.Store([]string{"apk", "exe", "msi", "dmg", "iso", "zip", "rar", "7z", "tar.gz", "mp4", "flv", "ts", "m3u8", "mp3", "pdf"})
	bsfDoms.Store(map[string]bool{"3gppnetwork.org": true})
	oldNoPlain := noPlainHeziPath
	noPlainHeziPath = filepath.Join(t.TempDir(), "no-plainhttp-hezi-absent")
	defer func() { noPlainHeziPath = oldNoPlain }()
	pub80 := dstAddr{ip: net.ParseIP("8.8.8.8"), port: 80}
	priv80 := dstAddr{ip: net.ParseIP("192.168.2.1"), port: 80}
	cases := []struct {
		name    string
		od      dstAddr
		b       []byte
		verdict string
		reason  string
	}{
		{"mmtls-ch", dstAddr{port: 443}, []byte{0x16, 0xf1, 0x00, 0x01}, "hezi", "mmtls"},
		{"mmtls-hb", dstAddr{port: 443}, []byte{0x19, 0xf1, 0x04}, "hezi", "mmtls"},
		{"tls-normal", dstAddr{port: 443}, []byte{0x16, 0x03, 0x01, 0x00}, "xray", "default"},
		{"tls-sni-kw", dstAddr{port: 443}, clientHello("sq.bls.mdt.qq.com"), "xray", "tls_direct"},
		{"tls-sni-other", dstAddr{port: 8443}, clientHello("example.com"), "xray", "tls_direct"},
		{"tls-sni-dns", dstAddr{port: 443}, clientHello("dns.google"), "block", "dns_block"},
		{"tls-sni-doh", dstAddr{port: 443}, clientHello("doh.pub"), "block", "dns_block"},
		{"tls-sni-dns-fp", dstAddr{port: 443}, clientHello("madnson.com"), "xray", "tls_direct"},
		{"oicq", dstAddr{port: 8000}, []byte{0x02, 0x30, 0x31}, "hezi", "oicq"},
		{"msf-trunc", dstAddr{port: 8081}, msfPkt(1403, 100), "hezi", "msf"},
		{"msf-exact", dstAddr{port: 443}, msfPkt(100, 100), "hezi", "msf"},
		{"msf-other-port", dstAddr{port: 14000}, msfPkt(2827, 512), "hezi", "msf"},
		{"msf-b4-08", dstAddr{port: 8081}, msfPktB4(0x03ef, 64, 0x08), "hezi", "msf"},
		{"msf-b4-06", dstAddr{port: 8081}, msfPktB4(200, 100, 0x06), "hezi", "msf"},
		{"msf-typecompress", dstAddr{port: 8081}, typeCompressPkt(64, 32), "hezi", "msf"},
		{"msf-typecompress-badlen", dstAddr{port: 8081}, typeCompressPkt(16, 32), "hezi", "default"},
		{"msf-badlen", dstAddr{port: 8081}, msfPkt(50, 100), "hezi", "default"},
		{"msf-badmagic", dstAddr{port: 8081}, []byte{0x05, 0x7b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, "hezi", "default"},
		{"msf-u32-exact", dstAddr{port: 8080}, msfU32Pkt(32), "hezi", "msf"},
		{"msf-u32-443", dstAddr{port: 443}, msfU32Pkt(64), "hezi", "msf"},
		{"msf-u32-14000", dstAddr{port: 14000}, msfU32Pkt(48), "hezi", "msf"},
		{"msf-u32-trunc", dstAddr{port: 8080}, msfU32Pkt(10), "hezi", "default"},
		{"msf-u32-badmagic", dstAddr{port: 8080}, func() []byte { b := msfU32Pkt(32); b[13], b[14], b[15] = 'X', 'Y', 'Z'; return b }(), "hezi", "default"},
		// 全零头变种（实测 QQ 8080）：两种实测 len 全端口命中。
		{"msf-zerohdr-20", dstAddr{port: 8080}, zeroHdrPkt(0x20, 32), "hezi", "msf"},
		{"msf-zerohdr-1a", dstAddr{port: 8080}, zeroHdrPkt(0x1a, 32), "hezi", "msf"},
		{"msf-zerohdr-14000", dstAddr{port: 14000}, zeroHdrPkt(0x20, 32), "hezi", "msf"},
		// 近失配放范围外，专验指纹精度（不受端口兜底干扰）。
		{"msf-zerohdr-badtype", dstAddr{port: 7999}, func() []byte { b := zeroHdrPkt(0x20, 32); b[7] = 0xc9; return b }(), "xray", "default"},
		{"msf-zerohdr-badzero", dstAddr{port: 9001}, func() []byte { b := zeroHdrPkt(0x20, 32); b[6] = 0x01; return b }(), "xray", "default"},
		// 0806 变种（实测腾讯游戏鉴权 8081）：XX 随包长，全端口命中。
		{"msf-0806-5a", dstAddr{port: 8081}, msf0806c73Pkt(0x5a, 32), "hezi", "msf"},
		{"msf-0806-aa", dstAddr{port: 8081}, msf0806c73Pkt(0xaa, 32), "hezi", "msf"},
		{"msf-0806-14000", dstAddr{port: 14000}, msf0806c73Pkt(0x7a, 32), "hezi", "msf"},
		// 近失配：b6/b7 回到 u16be 常量的是另一分支，不管；此处验真 miss。
		{"msf-0806-badb6", dstAddr{port: 7999}, func() []byte { b := msf0806c73Pkt(0x5a, 32); b[6] = 0x07; b[7] = 0x62; return b }(), "hezi", "msf"},
		{"msf-0806-badb0", dstAddr{port: 7999}, func() []byte { b := msf0806c73Pkt(0x5a, 32); b[0] = 0x09; return b }(), "xray", "default"},
		// 8000-9000 端口兜底：非 TLS 残渣翻 hezi/default，范围外不变。
		{"port8000-opaque", dstAddr{port: 8000}, []byte{0x05, 0x7b, 0x08, 0x00, 0x01}, "hezi", "default"},
		{"port8500-opaque", dstAddr{port: 8500}, []byte{0x05, 0x7b, 0x08, 0x00, 0x01}, "hezi", "default"},
		{"port9000-empty", dstAddr{port: 9000}, []byte{}, "hezi", "default"},
		{"port7999-opaque", dstAddr{port: 7999}, []byte{0x05, 0x7b, 0x08, 0x00, 0x01}, "xray", "default"},
		{"port9001-opaque", dstAddr{port: 9001}, []byte{0x05, 0x7b, 0x08, 0x00, 0x01}, "xray", "default"},
		{"stun-exact", dstAddr{port: 80}, stunPkt(172, 174), "hezi", "stun"},
		{"stun-trunc", dstAddr{port: 80}, stunPkt(500, 200), "hezi", "stun"},
		{"stun-badlen", dstAddr{port: 80}, stunPkt(100, 174), "hezi", "port80"},
		{"stun-badmagic", dstAddr{port: 80}, []byte{0x00, 0xac, 0x00, 0x01, 0x00, 0x98, 0x21, 0x12, 0xa4, 0x43, 0x00, 0x00}, "hezi", "port80"},
		{"http-nohost-kw", dstAddr{port: 80}, []byte("GET /pull-t3.douyincdn.com/x.flv HTTP/1.1\r\n\r\n"), "hezi", "http_path_kw"},
		{"http-iphhost-kw", dstAddr{port: 80}, []byte("GET /pull-t3.douyincdn.com/x.flv HTTP/1.1\r\nHost: 36.155.189.213\r\n\r\n"), "hezi", "http_path_kw"},
		{"http-domainhost-kw", dstAddr{port: 80}, []byte("GET /x HTTP/1.1\r\nHost: www.douyin.com\r\n\r\n"), "hezi", "http_host_kw"},
		{"http-random", dstAddr{port: 80}, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"), "hezi", "http_plain"},
		{"http-plain-8080", dstAddr{port: 8080}, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"), "hezi", "http_plain"},
		{"http-mmtls-path", dstAddr{port: 80}, []byte("POST /mmtls/49a6fef7 HTTP/1.1\r\nHost: 1.2.3.4\r\nUpgrade: mmtls\r\n\r\n"), "hezi", "http_path_kw"},
		{"not-http", dstAddr{port: 80}, []byte("GARBAGE this is not http\r\n"), "hezi", "port80"},
		{"port80-empty", pub80, []byte{}, "hezi", "port80"},
		{"port80-pub", pub80, []byte{0x00, 0x01, 0x02, 0x03}, "hezi", "port80"},
		{"port80-priv", priv80, []byte{0x00, 0x01, 0x02, 0x03}, "hezi", "port80"},
		{"dl-host-80", dstAddr{port: 80}, []byte("GET /client.zip HTTP/1.1\r\nHost: down.qq.com\r\n\r\n"), "xray", "dl_direct"},
		{"dl-host-8080", dstAddr{port: 8080}, []byte("GET /patch.zip HTTP/1.1\r\nHost: down-update.qq.com\r\n\r\n"), "xray", "dl_direct"},
		{"dl-beats-kw", dstAddr{port: 8080}, []byte("GET /pull-t3.douyincdn.com/x.flv HTTP/1.1\r\nHost: down.qq.com\r\n\r\n"), "xray", "dl_direct"},
		{"dl-host-wu", dstAddr{port: 80}, []byte("GET /d/msdownload/update/software/defu/2026/01/amd64/mpasdlis-1.1.26010.5.exe HTTP/1.1\r\nHost: download.windowsupdate.com\r\nUser-Agent: Windows-Update-Agent/10.0\r\n\r\n"), "xray", "dl_direct"},
		{"dl-host-msdo-sub", dstAddr{port: 80}, []byte("GET /filestreamingservice/files/a7cf3574-1bb5-434d-8bee-539230abfaa4 HTTP/1.1\r\nHost: 1d.tlu.dl.delivery.mp.microsoft.com\r\nUser-Agent: Microsoft-Delivery-Optimization/10.1\r\n\r\n"), "xray", "dl_direct"},
		{"dl-host-steamcdn", dstAddr{port: 80}, []byte("GET /depot/952062/chunk/361e359c03eb35e4fc7929d95d69eba5aba4c3b6 HTTP/1.1\r\nHost: st.dl.eccdnx.com\r\nUser-Agent: Valve/Steam HTTP Client 1.0\r\n\r\n"), "xray", "dl_direct"},
		{"dl-host-mssub", dstAddr{port: 80}, []byte("GET /v11.0/cabpool/mpasdlis-1.1.26010.5_amd64.exe HTTP/1.1\r\nHost: fe2cr.update.microsoft.com\r\n\r\n"), "xray", "dl_direct"},
		{"dl-host-officecdn", dstAddr{port: 80}, []byte("GET /pr/492350f6-3a01-4fdb-bb78-cc64fbc274fed/Office/Data/16.0.18730.20074/stream.x64.x-none.dat HTTP/1.1\r\nHost: officecdn.microsoft.com\r\n\r\n"), "xray", "dl_direct"},
		{"dl-host-ksord-rollback", dstAddr{port: 80}, []byte("POST / HTTP/1.1\r\nHost: shuc-pc-hunt.ksord.com\r\n\r\n"), "hezi", "http_plain"},
		{"dl-host-ocsp-rollback", dstAddr{port: 80}, []byte("GET /MFEwWzBNMEw5MDMxAzAJBgUrDgMCGgQUmYxW0BNS05NREU3TVRBMU1qST0N9 HTTP/1.1\r\nHost: ocsp.digicert.com\r\n\r\n"), "hezi", "http_plain"},
		{"dl-host-cmcm-rollback", dstAddr{port: 80}, []byte("POST /query?234947156 HTTP/1.1\r\nHost: rq.upgrade.cmpc.cmcm.com\r\nUser-Agent: Mozilla/4.0\r\n\r\n"), "hezi", "http_plain"},
		{"dl-host-reponzm", dstAddr{port: 80}, []byte("GET /rid.13148-r.29195/b62f3a1c HTTP/1.1\r\nHost: repo.nzm.qq.com\r\nRange: bytes=0-1048575\r\n\r\n"), "xray", "dl_direct"},
		{"dl-ua-steam-iphost", dstAddr{port: 80}, []byte("GET /st.dl.eccdnx.com/depot/952062/chunk/361e359 HTTP/1.1\r\nHost: 1.197.93.32\r\nUser-Agent: Valve/Steam HTTP Client 1.0\r\n\r\n"), "xray", "dl_ua"},
		{"dl-ua-do-wuhost", dstAddr{port: 80}, []byte("GET /phf/c/doc/ph/prod5/x HTTP/1.1\r\nHost: download.windowsupdate.com\r\nUser-Agent: Microsoft-Delivery-Optimization/10.1\r\n\r\n"), "xray", "dl_direct"},
		{"kw-beats-dlua", dstAddr{port: 80}, []byte("GET /pull-t3.douyincdn.com/x.flv HTTP/1.1\r\nHost: 1.2.3.4\r\nUser-Agent: Valve/Steam HTTP Client 1.0\r\n\r\n"), "hezi", "http_path_kw"},
		{"dl-range", dstAddr{port: 8080}, []byte("GET /video.mp4 HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-1023\r\n\r\n"), "xray", "dl_range"},
		{"dl-ua-thunder", dstAddr{port: 8080}, []byte("GET /file HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Thunder/7.0\r\n\r\n"), "xray", "dl_ua"},
		{"dl-ext-apk", dstAddr{port: 8080}, []byte("GET /app.apk HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"), "xray", "dl_ext"},
		{"dl-ext-query", dstAddr{port: 8080}, []byte("GET /v.apk?sign=abc HTTP/1.1\r\nHost: example.com\r\n\r\n"), "xray", "dl_ext"},
		{"kw-beats-dlext", dstAddr{port: 8000}, []byte("GET /x.flv HTTP/1.1\r\nHost: example.com\r\nUser-Agent: com.ss.android.ugc.aweme/31.2.0\r\n\r\n"), "hezi", "http_ua_kw"},
		{"bsf-80", dstAddr{port: 80}, []byte("GET / HTTP/1.1\r\nHost: bsf.mnc000.mcc460.pub.3gppnetwork.org\r\n\r\n"), "xray", "bsf_direct"},
		{"bsf-8080", dstAddr{port: 8080}, []byte("GET / HTTP/1.1\r\nHost: bsf.mnc000.mcc460.pub.3gppnetwork.org\r\nUser-Agent: Mozilla/5.0\r\n\r\n"), "xray", "bsf_direct"},
		{"http-kw-other-port", dstAddr{port: 8443}, []byte("GET /pull-t3.douyincdn.com/x.flv HTTP/1.1\r\n\r\n"), "hezi", "http_path_kw"},
		{"http-kw-8000", dstAddr{port: 8000}, []byte("GET /v1/resource HTTP/1.1\r\nHost: 36.155.189.213\r\nUser-Agent: com.ss.android.ugc.aweme/31.2.0\r\n\r\n"), "hezi", "http_ua_kw"},
		{"http-ua-aweme", dstAddr{port: 8000}, []byte("GET /x HTTP/1.1\r\nHost: 1.2.3.4\r\nUser-Agent: com.ss.android.ugc.aweme/31.2.0 (Linux; U; Android 14)\r\n\r\n"), "hezi", "http_ua_kw"},
		{"http-ua-mm", dstAddr{port: 443}, []byte("POST /mmtls/6001c704 HTTP/1.1\r\nHost: 5.6.7.8\r\nUser-Agent: MicroMessenger Client\r\n\r\n"), "hezi", "http_ua_kw"},
		{"http-ua-other", dstAddr{port: 80}, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"), "hezi", "http_plain"},
	}
	for _, c := range cases {
		v, r := classify(c.od, c.b)
		if v != c.verdict || r != c.reason {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, v, r, c.verdict, c.reason)
		}
	}
}

func TestPlainhttpEscape(t *testing.T) {
	kws.Store([]string{"qq.com"})
	dlDoms.Store(map[string]bool{"down.qq.com": true})
	bsfDoms.Store(map[string]bool{"3gppnetwork.org": true})
	old := noPlainHeziPath
	dir := t.TempDir()
	noPlainHeziPath = filepath.Join(dir, "no-plainhttp-hezi")
	defer func() { noPlainHeziPath = old }()
	plain := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	kw := []byte("GET /x HTTP/1.1\r\nHost: www.qq.com\r\n\r\n")
	dl := []byte("GET /x HTTP/1.1\r\nHost: down.qq.com\r\n\r\n")
	bsf := []byte("GET / HTTP/1.1\r\nHost: bsf.mnc000.mcc460.pub.3gppnetwork.org\r\n\r\n")
	// 逃生前：通判+80短路进 hezi，关键词/下载站/BSF 不变。
	for _, c := range []struct {
		name string
		od   dstAddr
		b    []byte
		v, r string
	}{
		{"plain", dstAddr{port: 8080}, plain, "hezi", "http_plain"},
		{"port80", dstAddr{port: 80}, []byte{0x00}, "hezi", "port80"},
		{"kw", dstAddr{port: 8080}, kw, "hezi", "http_host_kw"},
		{"dl", dstAddr{port: 8080}, dl, "xray", "dl_direct"},
		{"bsf", dstAddr{port: 8080}, bsf, "xray", "bsf_direct"},
	} {
		if v, r := classify(c.od, c.b); v != c.v || r != c.r {
			t.Fatalf("%s before escape: got %s/%s want %s/%s", c.name, v, r, c.v, c.r)
		}
	}
	if err := os.WriteFile(noPlainHeziPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	// 逃生后：通判+80短路回退 xray（reason 拼写不变），其余照旧。
	for _, c := range []struct {
		name string
		od   dstAddr
		b    []byte
		v, r string
	}{
		{"plain", dstAddr{port: 8080}, plain, "xray", "http_plain"},
		{"port80", dstAddr{port: 80}, []byte{0x00}, "xray", "port80"},
		{"kw", dstAddr{port: 8080}, kw, "hezi", "http_host_kw"},
		{"dl", dstAddr{port: 8080}, dl, "xray", "dl_direct"},
		{"bsf", dstAddr{port: 8080}, bsf, "xray", "bsf_direct"},
	} {
		if v, r := classify(c.od, c.b); v != c.v || r != c.r {
			t.Fatalf("%s after escape: got %s/%s want %s/%s", c.name, v, r, c.v, c.r)
		}
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
	oldDom, oldUA, oldExt, oldBSF := dlDomPath, dlUAPath, dlExtPath, bsfDomPath
	defer func() { dlDomPath, dlUAPath, dlExtPath, bsfDomPath = oldDom, oldUA, oldExt, oldBSF }()
	dir := t.TempDir()
	dlDomPath = filepath.Join(dir, "dl-domains.txt")
	dlUAPath = filepath.Join(dir, "dl-ua.txt")
	dlExtPath = filepath.Join(dir, "dl-ext.txt")
	bsfDomPath = filepath.Join(dir, "bsf-domains.txt")
	if err := os.WriteFile(dlDomPath, []byte("down.qq.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dlUAPath, []byte("thunder\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dlExtPath, []byte("apk\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bsfDomPath, []byte("3gppnetwork.org\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if nd, nu, ne, nb := loadDLLists(); nd != 1 || nu != 1 || ne != 1 || nb != 1 {
		t.Fatalf("load: got %d/%d/%d/%d want 1/1/1/1", nd, nu, ne, nb)
	}
	if !dlDomainHit("a.down.qq.com") || dlDomainHit("example.com") {
		t.Fatalf("dl dom snapshot mismatch")
	}
	if !dlUAHit("x-thunder-y") || !dlExtHit("/a.apk") || !bsfDomainHit("bsf.mnc000.mcc460.pub.3gppnetwork.org") {
		t.Fatalf("dl snapshot mismatch")
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

// TestPeekClient80 证明 :80 opportunistic 短读：完整 handleConn 需 origdst
// （conntrack SO_ORIGINAL_DST，net.Pipe 不可测），故此处测 peekClient 单元 +
// classify 组合：有数据→首包可达 dl_direct；静默→n=0 落 port80。
func TestPeekClient80(t *testing.T) {
	oldWait := peekWait80
	oldNoPlain := noPlainHeziPath
	oldDL := dlDomSnapshot()
	if oldDL == nil {
		oldDL = map[string]bool{}
	}
	peekWait80 = 20 * time.Millisecond
	noPlainHeziPath = filepath.Join(t.TempDir(), "no-plainhttp-hezi-absent")
	dlDoms.Store(map[string]bool{"down.qq.com": true})
	defer func() { peekWait80 = oldWait; noPlainHeziPath = oldNoPlain; dlDoms.Store(oldDL) }()
	buf := make([]byte, 1024)
	// :80 有数据：短读拿到首包 → classify 可达 xray/dl_direct。
	c1, s1 := net.Pipe()
	defer c1.Close()
	defer s1.Close()
	payload := "GET /client.zip HTTP/1.1\r\nHost: down.qq.com\r\n\r\n"
	go func() { _, _ = s1.Write([]byte(payload)) }()
	n := peekClient(c1, buf, 80)
	if string(buf[:n]) != payload {
		t.Fatalf("80 peek data: got %q want %q", buf[:n], payload)
	}
	if v, r := classify(dstAddr{port: 80}, buf[:n]); v != "xray" || r != "dl_direct" {
		t.Fatalf("80 peek classify: got %s/%s want xray/dl_direct", v, r)
	}
	// :80 静默：超时落空 → hezi/port80（fail-closed）。
	c2, s2 := net.Pipe()
	defer c2.Close()
	defer s2.Close()
	if n := peekClient(c2, buf, 80); n != 0 {
		t.Fatalf("80 silent peek: got n=%d want 0", n)
	}
	if v, r := classify(dstAddr{port: 80}, buf[:0]); v != "hezi" || r != "port80" {
		t.Fatalf("80 empty classify: got %s/%s want hezi/port80", v, r)
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

func TestDNSResolverIP(t *testing.T) {
	tls := []byte{0x16, 0x03, 0x01, 0x00}
	if v, r := classify(dstAddr{ip: net.ParseIP("223.5.5.5"), port: 443}, tls); v != "block" || r != "dns_block" {
		t.Errorf("resolver ip: got %s/%s", v, r)
	}
	if v, r := classify(dstAddr{ip: net.ParseIP("1.2.3.4"), port: 443}, tls); v != "xray" || r != "default" {
		t.Errorf("normal ip: got %s/%s", v, r)
	}
}

func TestDohMatch(t *testing.T) {
	set := map[string]bool{"dns.google": true, "doh.pub": true}
	for _, s := range []string{"dns.google", "x.dns.google", "DOH.PUB", "a.b.doh.pub", "dns.google."} {
		if !matchDohDomain(s, set) {
			t.Errorf("should hit %s", s)
		}
	}
	for _, s := range []string{"madnson.com", "dnspod.cn", "example.com", "", "notadoh"} {
		if matchDohDomain(s, set) {
			t.Errorf("should miss %s", s)
		}
	}
	for _, s := range []string{"x.alidns.com", "svr.doh.example.net", "doh-7.example.net"} {
		if !dohSNIRe.MatchString(s) {
			t.Errorf("regex should hit %s", s)
		}
	}
	if dohSNIRe.MatchString("madnson.com") {
		t.Errorf("regex should miss madnson.com")
	}
}

func TestParseLineSet(t *testing.T) {
	m := parseLineSet([]byte("# c\nDNS.Google\n0.0.0.0 doh.pub\n\n  x.example.com  \nbad line here\n"))
	if !(m["dns.google"] && m["doh.pub"] && m["x.example.com"]) || len(m) != 3 {
		t.Errorf("parse got %v", m)
	}
}

func TestKwReload(t *testing.T) {
	old := kwPath
	defer func() { kwPath = old }()
	kwPath = filepath.Join(t.TempDir(), "gate.kw")
	if err := os.WriteFile(kwPath, []byte("# comment\n\ndouyin.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if n := loadKeywords(); n != 1 {
		t.Fatalf("load: got %d want 1", n)
	}
	if !kwMatch("pull.douyin.com") || kwMatch("example.com") {
		t.Fatalf("snapshot mismatch after load")
	}
	if checkKwReload() {
		t.Fatalf("no-change reload should be false")
	}
	// 追加关键词并推进 mtime（部分文件系统 mtime 粒度粗，显式 Chtimes 保底）
	f, err := os.OpenFile(kwPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("newkw.example\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	mt := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(kwPath, mt, mt); err != nil {
		t.Fatal(err)
	}
	if !checkKwReload() {
		t.Fatalf("changed reload should be true")
	}
	if !kwMatch("x.newkw.example/y") || !kwMatch("pull.douyin.com") {
		t.Fatalf("snapshot mismatch after reload")
	}
	if checkKwReload() {
		t.Fatalf("second no-change reload should be false")
	}
}

// TestHeziMem 证明端点记忆：实锤端点静默复用可收敛进 hezi，未知端点
// 不受影响；:80 不记（本就 fail-closed）；TTL 过期失效。
func TestHeziMem(t *testing.T) {
	heziMemMu.Lock()
	heziMem = map[string]heziMemEnt{}
	heziMemMu.Unlock()
	qq := dstAddr{ip: net.ParseIP("14.17.83.207"), port: 8081}
	heziMemStore(qq, "oicq")
	if rsn, ok := heziMemLookup(qq); !ok || rsn != "oicq" {
		t.Fatalf("lookup hit: got %q,%v want oicq,true", rsn, ok)
	}
	unknown := dstAddr{ip: net.ParseIP("9.9.9.9"), port: 8081}
	if _, ok := heziMemLookup(unknown); ok {
		t.Fatalf("unknown endpoint should miss")
	}
	pub80 := dstAddr{ip: net.ParseIP("8.8.8.8"), port: 80}
	heziMemStore(pub80, "port80")
	if _, ok := heziMemLookup(pub80); ok {
		t.Fatalf(":80 should not be memorized")
	}
	heziMemMu.Lock()
	heziMem[heziMemKey(qq)] = heziMemEnt{reason: "oicq", ts: time.Now().Unix() - heziMemTTL - 1}
	heziMemMu.Unlock()
	if _, ok := heziMemLookup(qq); ok {
		t.Fatalf("expired entry should miss")
	}
}

func TestDefHeziSocksTargetsGroupInbound(t *testing.T) {
	// gate 判 hezi 的拨号目标必须是 sing-box 的 gate-hezi 入站（127.0.0.1:10811），
	// 由 sing-box 的 hezi 出口组负责多出口选择与故障转移。
	if defHeziSocks != "127.0.0.1:10811" {
		t.Fatalf("defHeziSocks = %q, want 127.0.0.1:10811 (sing-box gate-hezi inbound)", defHeziSocks)
	}
}
