package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tempStats 装一个临时 stats.tsv 到 statFile，返回路径与还原函数。
func tempStats(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "stats.tsv")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	old := statFile
	statFile = f
	t.Cleanup(func() { statFile = old; f.Close() })
	return p
}

// 直连面台账：累计 → 刷盘 → 清零；空累计不写行。
func TestLedgerFlushWritesDeltaAndResets(t *testing.T) {
	p := tempStats(t)
	ledgerClose.Store(0)
	ledgerUpB.Store(0)
	ledgerDownB.Store(0)
	ledgerDurMs.Store(0)

	// 空累计：一行都不写（保持 stats.tsv 干净）。
	ledgerFlush()
	if b, _ := os.ReadFile(p); len(b) != 0 {
		t.Fatalf("empty ledger must write nothing, got %q", b)
	}

	ledgerAdd(1200, 300, 900)
	ledgerAdd(800, 100, 500)
	ledgerFlush()
	got := string(mustRead(t, p))
	for _, want := range []string{
		"gate_tlsdirect_close\t2",
		"gate_tlsdirect_up_B\t400",
		"gate_tlsdirect_down_B\t1400",
		"gate_tlsdirect_dur_ms\t2000",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in stats:\n%s", want, got)
		}
	}

	// 刷完清零：再刷不产生新行（增量语义，消费者按 key 求和）。
	ledgerFlush()
	if n := strings.Count(string(mustRead(t, p)), "gate_tlsdirect_close"); n != 1 {
		t.Fatalf("second flush must not re-add close line, got %d lines", n)
	}
}

// relay 集成：tls_direct 流不进事件流，但字节必须进台账；proxy 流照旧进事件流。
func TestRelayTlsDirectGoesToLedgerNotEvents(t *testing.T) {
	ev := tempEvents(t)
	p := tempStats(t)
	ledgerClose.Store(0)
	ledgerUpB.Store(0)
	ledgerDownB.Store(0)
	ledgerDurMs.Store(0)

	cli, gA, ups, gB := tcpRelayPair(t)
	defer cli.Close()
	defer ups.Close()
	defer gA.Close()
	defer gB.Close()

	done := make(chan struct{})
	go func() {
		relay(gA, gB, cli.LocalAddr().String(), dstAddr{ip: net.ParseIP("203.0.113.7"), port: 443},
			"pass", "tls_direct", time.Now())
		close(done)
	}()

	up := make([]byte, 321)
	down := make([]byte, 654)
	if _, err := cli.Write(up); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(up))
	if _, err := ups.Read(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := ups.Write(down); err != nil {
		t.Fatal(err)
	}
	rbuf := make([]byte, len(down))
	if _, err := cli.Read(rbuf); err != nil {
		t.Fatal(err)
	}
	cli.Close()
	ups.Close()
	<-done

	if b := mustRead(t, ev); len(b) != 0 {
		t.Fatalf("tls_direct must not emit events, got %q", b)
	}
	ledgerFlush()
	got := string(mustRead(t, p))
	for _, want := range []string{
		"gate_tlsdirect_close\t1",
		"gate_tlsdirect_up_B\t321",
		"gate_tlsdirect_down_B\t654",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in stats:\n%s", want, got)
		}
	}
}

// 非 tls_direct（proxy）仍走事件流，且不进台账 —— 防两条路都写或都不写。
func TestRelayProxyStillEmitsEvents(t *testing.T) {
	ev := tempEvents(t)
	p := tempStats(t)
	ledgerClose.Store(0)

	cli, gA, ups, gB := tcpRelayPair(t)
	defer cli.Close()
	defer ups.Close()
	defer gA.Close()
	defer gB.Close()

	done := make(chan struct{})
	go func() {
		relay(gA, gB, cli.LocalAddr().String(), dstAddr{ip: net.ParseIP("203.0.113.8"), port: 443},
			"proxy", "oicq", time.Now())
		close(done)
	}()
	if _, err := cli.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := ups.Read(buf); err != nil {
		t.Fatal(err)
	}
	cli.Close()
	ups.Close()
	<-done

	if n := strings.Count(string(mustRead(t, ev)), "\"close\""); n != 1 {
		t.Fatalf("proxy close events=%d want 1", n)
	}
	ledgerFlush()
	if b := mustRead(t, p); len(b) != 0 {
		t.Fatalf("proxy must not touch pass ledger, got %q", b)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tcpRelayPair 造两对 loopback TCP：client<->gateA、gateB<->upstream，供 relay 直测。
func tcpRelayPair(t *testing.T) (cli, gA, ups, gB *net.TCPConn) {
	t.Helper()
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lnA.Close() })
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lnB.Close() })
	type cres struct {
		c net.Conn
		e error
	}
	acA := make(chan cres, 1)
	acB := make(chan cres, 1)
	go func() { c, e := lnA.Accept(); acA <- cres{c, e} }()
	go func() { c, e := lnB.Accept(); acB <- cres{c, e} }()
	c1, err := net.Dial("tcp", lnA.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c2, err := net.Dial("tcp", lnB.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c1.(*net.TCPConn), (<-acA).c.(*net.TCPConn), c2.(*net.TCPConn), (<-acB).c.(*net.TCPConn)
}
