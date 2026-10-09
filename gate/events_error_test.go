package main

import (
	"encoding/json"
	"net"
	"testing"
)

// error 行：hezi_fail/*_fail 原样进流（event:error + detail）。
func TestEventsErrorLine(t *testing.T) {
	p := tempEvents(t)
	src := "192.168.2.50:43000"
	od := dstAddr{ip: net.ParseIP("203.0.113.7"), port: 8081}
	emitErrorEvent("tcp", src, od, "err", "oicq_hezi_fail", "dial tcp 127.0.0.1:18082: connect: connection refused")
	lines := readLines(t, p)
	if len(lines) != 1 {
		t.Fatalf("error must emit 1 line, got %d", len(lines))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("error not json: %v", err)
	}
	if m["event"] != "error" || m["proto"] != "tcp" || m["src"] != src ||
		m["dst"] != od.String() || m["verdict"] != "err" || m["reason"] != "oicq_hezi_fail" {
		t.Fatalf("error base mismatch: %v", m)
	}
	d, ok := m["detail"].(string)
	if !ok || d == "" {
		t.Fatalf("error missing detail: %v", m)
	}
	// reason 冻结：classify 行为不受事件流影响（抽查）。
	if v, r := classify(dstAddr{port: 8081}, msfPkt(1403, 100)); v != "hezi" || r != "msf" {
		t.Fatalf("classify frozen: got %s/%s", v, r)
	}
}
