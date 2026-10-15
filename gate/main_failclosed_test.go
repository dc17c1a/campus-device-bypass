package main

// 回归：pass 腿偶发直拨失败保持 **fail-closed**。
//
// 语义（被本文件钉死的三条）：
//  1. 每个 verdict 只拨**唯一**上游：direct→pass、proxy→proxySocks、无第三腿；
//  2. 该腿拨号失败 → 返回 nil（调用方直接 return，客户端被断流），
//     失败量进 gate_pass_fail / gate_proxy_fail + gate_dial_err；
//  3. **绝不改拨第二条腿**——所以反向验证很直接：把 openUpstream 的失败分支改成
//     "回退第三腿"，下面两个用例立刻转红（blackholeHits != 0）。
//
// 背景：2026-10-11 18:00–23:00 pass 上游直拨风暴期，gate_pass_fail 一度占
// 直通流量的显著比例。当时已定"保持 fail-closed 不回退
// proxy"，本轮复核（10-12）再次确认：宁可断流，也不许把标准 TLS 流量偷偷塞进隧道。

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSocks5OK 起一个"完全合法"的假 SOCKS5（greeting + IPv4 CONNECT 均成功应答），
// 并统计被拨次数。用它当 pass/proxy/第三腿黑洞的替身：只要有人拨进去就会被记一笔。
func fakeSocks5OK(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var hits atomic.Int64
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			hits.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				g := make([]byte, 3)
				if _, err := io.ReadFull(c, g); err != nil { // greeting
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}
				req := make([]byte, 10) // VER CMD RSV ATYP=1 + 4B IP + 2B PORT
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				time.Sleep(200 * time.Millisecond) // 连接存活到断言之后
			}(c)
		}
	}()
	return ln.Addr().String(), &hits
}

// tempGateLog 把 gate.log 指到临时文件（openUpstream 的 err 分支要落一行）。
func tempGateLog(t *testing.T) {
	t.Helper()
	lf, err := os.OpenFile(filepath.Join(t.TempDir(), "gate.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	old := gateLogFile
	gateLogFile = lf
	t.Cleanup(func() { gateLogFile = old; lf.Close() })
}

func TestPassLegFailIsFailClosed(t *testing.T) {
	statsPath := tempStatFile(t)
	tempGateLog(t)
	_ = tempEvents(t)

	brokenUA := fakeSocks5Reply(t, []byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}, true) // REP=4 host unreachable
	// 黑洞：起一个无人应拨的假 socks，gate 已无任何代码路径引用该地址，
	// hits 必为 0——结构性钉死"永不拨第三腿"。
	_, blackholeHits := fakeSocks5OK(t)
	proxyAddr, proxyHits := fakeSocks5OK(t)
	oldUA, oldProxy := passSocks, proxySocks
	passSocks, proxySocks = brokenUA, proxyAddr
	t.Cleanup(func() { passSocks, proxySocks = oldUA, oldProxy })

	od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: 443}
	head := clientHello("example.com")

	if up := openUpstream("pass", "tls_direct", od, "192.168.2.9:50000", 1, head); up != nil {
		up.Close()
		t.Fatal("pass 直拨失败却拿到上游连接：fail-closed 被破坏")
	}
	if n := statSum(t, statsPath, "gate_pass_fail"); n != 1 {
		t.Errorf("gate_pass_fail=%d want 1", n)
	}
	if n := statSum(t, statsPath, "gate_dial_err"); n != 1 {
		t.Errorf("gate_dial_err=%d want 1", n)
	}
	if n := blackholeHits.Load(); n != 0 {
		t.Errorf("fail-closed 被破坏：拨了本应无人引用的第三腿 %d 次", n)
	}
	if n := proxyHits.Load(); n != 0 {
		t.Errorf("fail-closed 被破坏：回退拨了 proxy %d 次", n)
	}

	// 正控：pass 正常时必须真的走 pass（证明上一步"没回退"不是因为压根没拨），
	// 且仍不碰第三腿黑洞/proxy。
	okUA, uaHits := fakeSocks5OK(t)
	passSocks = okUA
	up := openUpstream("pass", "tls_direct", od, "192.168.2.9:50001", 2, head)
	if up == nil {
		t.Fatal("pass 正常却拨不通：正控失败（选择逻辑坏了）")
	}
	up.Close()
	if n := uaHits.Load(); n != 1 {
		t.Errorf("pass 命中=%d want 1", n)
	}
	if n := blackholeHits.Load() + proxyHits.Load(); n != 0 {
		t.Errorf("direct 腿不该碰第三腿/proxy，却拨了 %d 次", n)
	}
}

func TestProxyDialFailIsFailClosed(t *testing.T) {
	statsPath := tempStatFile(t)
	tempGateLog(t)
	_ = tempEvents(t)

	brokenProxy := fakeSocks5Reply(t, []byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}, true)
	// 黑洞：起一个无人应拨的假 socks，gate 已无任何代码路径引用该地址，
	// hits 必为 0——结构性钉死"永不拨第三腿"。
	_, blackholeHits := fakeSocks5OK(t)
	uaAddr, uaHits := fakeSocks5OK(t)
	oldUA, oldProxy := passSocks, proxySocks
	passSocks, proxySocks = uaAddr, brokenProxy
	t.Cleanup(func() { passSocks, proxySocks = oldUA, oldProxy })

	od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: 443}
	if up := openUpstream("proxy", "default", od, "192.168.2.9:50002", 3, clientHello("example.com")); up != nil {
		up.Close()
		t.Fatal("proxy 拨号失败却拿到上游连接：fail-closed 被破坏")
	}
	if n := statSum(t, statsPath, "gate_proxy_fail"); n != 1 {
		t.Errorf("gate_proxy_fail=%d want 1", n)
	}
	if n := statSum(t, statsPath, "gate_dial_err"); n != 1 {
		t.Errorf("gate_dial_err=%d want 1", n)
	}
	if n := blackholeHits.Load(); n != 0 {
		t.Errorf("fail-closed 被破坏：proxy 失败拨了本应无人引用的第三腿 %d 次", n)
	}
	if n := uaHits.Load(); n != 0 {
		t.Errorf("fail-closed 被破坏：proxy 失败回退拨了 pass %d 次", n)
	}
}
