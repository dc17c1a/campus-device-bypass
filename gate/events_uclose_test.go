package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// uclose 行：assoc 结束记 dur/up_pkts/down_pkts/up_B/down_B + 基字段。
func TestEventsUCloseLine(t *testing.T) {
	p := tempEvents(t)
	src := "192.168.2.50:41000"
	od := dstAddr{ip: net.ParseIP("203.0.113.7"), port: 3478}
	emitUCloseEvent("udp", src, od, "proxy", "stun_udp", 5000, 3, 2, 300, 400)
	lines := readLines(t, p)
	if len(lines) != 1 {
		t.Fatalf("uclose must emit 1 line, got %d", len(lines))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("uclose not json: %v", err)
	}
	if m["event"] != "uclose" || m["proto"] != "udp" || m["src"] != src ||
		m["dst"] != od.String() || m["verdict"] != "proxy" || m["reason"] != "stun_udp" {
		t.Fatalf("uclose base mismatch: %v", m)
	}
	if int(m["dur_ms"].(float64)) != 5000 || int(m["up_pkts"].(float64)) != 3 ||
		int(m["down_pkts"].(float64)) != 2 || int(m["up_B"].(float64)) != 300 ||
		int(m["down_B"].(float64)) != 400 {
		t.Fatalf("uclose counters mismatch: %v", m)
	}
}

// assoc.close() 恰 emit 一次 uclose（含计数），reap 不得重复。
func TestAssocCloseEmitsUCloseOnce(t *testing.T) {
	p := tempEvents(t)
	client := &net.UDPAddr{IP: net.ParseIP("192.168.2.51"), Port: 42000}
	od := dstAddr{ip: net.ParseIP("203.0.113.8"), port: 3478}
	a := &udpAssoc{key: udpAssocKey(client, od), client: client, dst: od, reason: "stun_udp"}
	a.start.Store(time.Now().Add(-2 * time.Second).UnixNano())
	a.last.Store(time.Now().UnixNano())
	a.toProxy = true
	a.upPkts.Store(2)
	a.downPkts.Store(1)
	a.upBytes.Store(120)
	a.downBytes.Store(60)
	udpMu.Lock()
	udpTable[a.key] = a
	udpMu.Unlock()
	a.close()
	// 第二次 close 不得重复。
	a.close()
	lines := readLines(t, p)
	if len(lines) != 1 {
		t.Fatalf("assoc close must emit exactly 1 uclose, got %d: %v", len(lines), lines)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("uclose not json: %v", err)
	}
	if m["event"] != "uclose" || m["proto"] != "udp" {
		t.Fatalf("uclose event/proto: %v", m)
	}
	if int(m["up_pkts"].(float64)) != 2 || int(m["down_pkts"].(float64)) != 1 ||
		int(m["up_B"].(float64)) != 120 || int(m["down_B"].(float64)) != 60 {
		t.Fatalf("uclose counters: %v", m)
	}
	if int(m["dur_ms"].(float64)) < 1500 || int(m["dur_ms"].(float64)) > 10000 {
		t.Fatalf("uclose dur_ms out of range: %v", m)
	}
	udpMu.Lock()
	_, leaked := udpTable[a.key]
	udpMu.Unlock()
	if leaked {
		t.Fatalf("closed assoc leaked table entry")
	}
}
