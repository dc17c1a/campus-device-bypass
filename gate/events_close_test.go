package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// close 行格式+字节+long 标记；closer 定义：先返回的 Copy 方向的源端即关闭方
// （client->server 先返回 => closer=client，反之 closer=server）。
func TestEventsCloseFormat(t *testing.T) {
	p := tempEvents(t)
	src := "192.168.2.50:40001"
	od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: 8080}
	emitCloseEvent("tcp", src, od, "hezi", "oicq", 1234, 100, 200, "client")
	lines := readLines(t, p)
	if len(lines) != 1 {
		t.Fatalf("close must emit 1 line, got %d", len(lines))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("close not json: %v", err)
	}
	if m["event"] != "close" || m["proto"] != "tcp" || m["src"] != src ||
		m["dst"] != od.String() || m["verdict"] != "hezi" || m["reason"] != "oicq" {
		t.Fatalf("close base mismatch: %v", m)
	}
	if int(m["dur_ms"].(float64)) != 1234 || int(m["up_B"].(float64)) != 100 ||
		int(m["down_B"].(float64)) != 200 || m["closer"] != "client" {
		t.Fatalf("close counters mismatch: %v", m)
	}
	if _, hasLong := m["long"]; hasLong {
		t.Fatalf("short close must not have long: %v", m)
	}
}

func TestEventsCloseLong(t *testing.T) {
	p := tempEvents(t)
	src := "192.168.2.50:40002"
	od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: 443}
	emitCloseEvent("tcp", src, od, "xray", "dl_direct", 60001, 0, 0, "server")
	lines := readLines(t, p)
	if len(lines) != 1 {
		t.Fatalf("long close must emit 1 line, got %d", len(lines))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("close not json: %v", err)
	}
	if int(m["dur_ms"].(float64)) != 60001 {
		t.Fatalf("dur mismatch: %v", m)
	}
	if int(m["long"].(float64)) != 1 {
		t.Fatalf("dur>60000 must have long=1: %v", m)
	}
	// 边界：60000 不加 long。
	emitCloseEvent("tcp", src, od, "xray", "dl_direct", 60000, 0, 0, "server")
	lines2 := readLines(t, p)
	// p 已有 1 行 long，再加 1 行边界行，共 2 行；最后一行无 long。
	if len(lines2) != 2 {
		t.Fatalf("boundary close lines=%d want 2", len(lines2))
	}
	var b map[string]any
	if err := json.Unmarshal([]byte(lines2[1]), &b); err != nil {
		t.Fatalf("boundary not json: %v", err)
	}
	if _, hasLong := b["long"]; hasLong {
		t.Fatalf("dur==60000 must not have long: %v", b)
	}
}

// relay 集成：计数 writer 包两端，字节数=实际传输，先关 client => closer=client。
func TestRelayCloseBytesAndCloser(t *testing.T) {
	p := tempEvents(t)
	// 真 TCP 对：client<->gateA，gateB<->upstream。relay(gateA, gateB)。
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnA.Close()
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnB.Close()
	type cres struct {
		c net.Conn
		e error
	}
	acCh := make(chan cres, 1)
	acB := make(chan cres, 1)
	go func() { c, e := lnA.Accept(); acCh <- cres{c, e} }()
	go func() { c, e := lnB.Accept(); acB <- cres{c, e} }()
	cli, err := net.Dial("tcp", lnA.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ups, err := net.Dial("tcp", lnB.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ups.Close()
	gA := (<-acCh).c.(*net.TCPConn)
	defer gA.Close()
	gB := (<-acB).c.(*net.TCPConn)
	defer gB.Close()
	src := cli.LocalAddr().String()
	od := dstAddr{ip: net.ParseIP("203.0.113.9"), port: 8080}
	start := time.Now()
	done := make(chan struct{})
	go func() {
		relay(gA, gB, src, od, "hezi", "oicq", start)
		close(done)
	}()
	// client->server 100B，server->client 200B，然后 client 先关写。
	upPayload := make([]byte, 100)
	downPayload := make([]byte, 200)
	if _, err := cli.Write(upPayload); err != nil {
		t.Fatal(err)
	}
	// upstream 读到 100B 后回 200B。
	buf := make([]byte, 300)
	n, err := ups.Read(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if n != 100 {
		t.Fatalf("upstream got %d want 100", n)
	}
	if _, err := ups.Write(downPayload); err != nil {
		t.Fatal(err)
	}
	// client 读到 200B 后主动半关，触发 client->server Copy 先 EOF。
	cbuf := make([]byte, 300)
	n2, err := cli.Read(cbuf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if n2 != 200 {
		t.Fatalf("client got %d want 200", n2)
	}
	if tc, ok := cli.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	} else {
		cli.Close()
	}
	// ups 延迟关闭，保证 client 侧 Copy 先返回（closer=client 确定性）；
	// 同时让第二个方向也能结束（relay 等双向）。
	go func() {
		time.Sleep(200 * time.Millisecond)
		if tc, ok := ups.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		time.Sleep(200 * time.Millisecond)
		ups.Close()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("relay did not finish after client CloseWrite")
	}
	// ups 侧也关，防泄漏（relay 已双向结束）。
	ups.Close()
	lines := readLines(t, p)
	if len(lines) != 1 {
		t.Fatalf("relay must emit 1 close line, got %d: %v", len(lines), lines)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("relay close not json: %v (%s)", err, lines[0])
	}
	if m["event"] != "close" || m["proto"] != "tcp" || m["verdict"] != "hezi" || m["reason"] != "oicq" {
		t.Fatalf("relay close base: %v", m)
	}
	if int(m["up_B"].(float64)) != 100 || int(m["down_B"].(float64)) != 200 {
		t.Fatalf("relay bytes: up=%v down=%v want 100/200 (%v)", m["up_B"], m["down_B"], m)
	}
	if m["closer"] != "client" {
		t.Fatalf("client-first-close must yield closer=client, got %v", m["closer"])
	}
}

func TestEventsCloseSkipsTLS(t *testing.T) {
	p := tempEvents(t)
	src := "192.168.2.50:40002"
	od := dstAddr{ip: net.ParseIP("1.2.3.4"), port: 443}
	emitCloseEvent("tcp", src, od, "xray", "tls_direct", 5000, 1000, 2000, "client")
	if lines := readLines(t, p); len(lines) != 0 {
		t.Fatalf("tls_direct close must not enter stream, got %d lines", len(lines))
	}
}
