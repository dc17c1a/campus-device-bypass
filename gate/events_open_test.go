package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper: point events stream at temp file, return path + cleanup.
func tempEvents(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "events.jsonl")
	oldPath := eventsPath
	oldFile := eventsFile
	eventsPath = p
	if err := initEvents(); err != nil {
		t.Fatalf("initEvents: %v", err)
	}
	t.Cleanup(func() {
		if eventsFile != nil {
			eventsFile.Close()
		}
		eventsPath = oldPath
		eventsFile = oldFile
	})
	return p
}

func readLines(t *testing.T, p string) []string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read events: %v", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// tls_direct 只走 stats 计数，不进流（过滤只看 reason，不看 verdict）；其余 reason 全进流。
func TestEventsOpenFilterTLS(t *testing.T) {
	p := tempEvents(t)
	src := "192.168.2.50:40000"
	odTLS := dstAddr{ip: net.ParseIP("1.2.3.4"), port: 443}
	emitOpen("tcp", src, odTLS, "pass", "tls_direct")
	if lines := readLines(t, p); len(lines) != 0 {
		t.Fatalf("tls_direct must not emit, got %d lines: %v", len(lines), lines)
	}
	odProxy := dstAddr{ip: net.ParseIP("1.2.3.4"), port: 8081}
	emitOpen("tcp", src, odProxy, "proxy", "mmtls")
	lines := readLines(t, p)
	if len(lines) != 1 {
		t.Fatalf("proxy open must emit 1 line, got %d", len(lines))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("open line not json: %v", err)
	}
	if m["event"] != "open" || m["proto"] != "tcp" || m["src"] != src ||
		m["dst"] != odProxy.String() || m["verdict"] != "proxy" || m["reason"] != "mmtls" {
		t.Fatalf("open fields mismatch: %v", m)
	}
	if _, ok := m["ts"]; !ok {
		t.Fatalf("open missing ts: %v", m)
	}
	// UDP open 同样进流（无 tls_direct 形态，抽查 stun_udp）。
	odUDP := dstAddr{ip: net.ParseIP("203.0.113.7"), port: 3478}
	emitOpen("udp", src, odUDP, "proxy", "stun_udp")
	lines = readLines(t, p)
	if len(lines) != 2 {
		t.Fatalf("udp open must append, got %d lines", len(lines))
	}
	var mu map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &mu); err != nil {
		t.Fatalf("udp open not json: %v", err)
	}
	if mu["proto"] != "udp" || mu["verdict"] != "proxy" || mu["reason"] != "stun_udp" {
		t.Fatalf("udp open fields: %v", mu)
	}
	// 过滤只看 reason：verdict 不参与——标准 TLS 直通的 pass/tls_direct 与换成
	// 任意其它 verdict 的 tls_direct 一律不进流；443/8000-10000 兜底的 proxy/default 照常进流。
	emitOpen("tcp", src, odTLS, "pass", "tls_direct")
	emitOpen("tcp", src, odTLS, "proxy", "tls_direct")
	if lines := readLines(t, p); len(lines) != 2 {
		t.Fatalf("tls_direct must not emit (reason-only filter), got %d lines", len(lines))
	}
	emitOpen("tcp", src, dstAddr{ip: net.ParseIP("1.2.3.4"), port: 8443}, "proxy", "default")
	lines = readLines(t, p)
	if len(lines) != 3 {
		t.Fatalf("proxy/default open must append, got %d lines", len(lines))
	}
	var mt map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &mt); err != nil {
		t.Fatalf("proxy/default open not json: %v", err)
	}
	if mt["verdict"] != "proxy" || mt["reason"] != "default" {
		t.Fatalf("proxy/default open fields: %v", mt)
	}
}
