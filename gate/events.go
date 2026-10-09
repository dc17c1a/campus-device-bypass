package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// 统一事件流：WD_EVENTS，默认 /tmp/wxdet/events.jsonl，O_APPEND。
// 与 gate.log/stats.tsv 共存，老文件一行不动；写入失败只记 stats，不影响转发。
// reason 冻结、fail-closed/fail-open 语义零改动（本文件只做落盘）。
var (
	eventsPath = envStr("WD_EVENTS", "/tmp/wxdet/events.jsonl")
	eventsFile *os.File
	eventsMu   sync.Mutex
)

func initEvents() error {
	os.MkdirAll(filepath.Dir(eventsPath), 0755)
	f, err := os.OpenFile(eventsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("warn: events %s: %v", eventsPath, err)
		return err
	}
	eventsMu.Lock()
	if eventsFile != nil {
		eventsFile.Close()
	}
	eventsFile = f
	eventsMu.Unlock()
	return nil
}

func emitEvent(m map[string]any) {
	if eventsFile == nil {
		return
	}
	b, err := json.Marshal(m)
	if err != nil {
		writeStat("gate_events_err", 1)
		return
	}
	b = append(b, '\n')
	eventsMu.Lock()
	_, werr := eventsFile.Write(b)
	eventsMu.Unlock()
	if werr != nil {
		writeStat("gate_events_err", 1)
	}
}

// shouldEmitOpen 过滤唯一例外：xray/tls_direct 只走 stats 计数，不进流。
func shouldEmitOpen(verdict, reason string) bool {
	return !(verdict == "xray" && reason == "tls_direct")
}

func emitOpen(proto, src string, od dstAddr, verdict, reason string) {
	if !shouldEmitOpen(verdict, reason) {
		return
	}
	emitEvent(map[string]any{
		"ts":      time.Now().Unix(),
		"event":   "open",
		"proto":   proto,
		"src":     src,
		"dst":     od.String(),
		"verdict": verdict,
		"reason":  reason,
	})
}

func emitCloseEvent(proto, src string, od dstAddr, verdict, reason string, durMs, upB, downB int64, closer string) {
	// tls_direct 不进流（与 open 同过滤，否则六成体量从 close 回流；
	// error 事件不受此限，错误永远进流）。
	if !shouldEmitOpen(verdict, reason) {
		return
	}
	m := map[string]any{
		"ts":      time.Now().Unix(),
		"event":   "close",
		"proto":   proto,
		"src":     src,
		"dst":     od.String(),
		"verdict": verdict,
		"reason":  reason,
		"dur_ms":  durMs,
		"up_B":    upB,
		"down_B":  downB,
		"closer":  closer,
	}
	if durMs > 60000 {
		m["long"] = 1
	}
	emitEvent(m)
}

func emitUCloseEvent(proto, src string, od dstAddr, verdict, reason string, durMs int64, upPkts, downPkts, upB, downB uint64) {
	emitEvent(map[string]any{
		"ts":        time.Now().Unix(),
		"event":     "uclose",
		"proto":     proto,
		"src":       src,
		"dst":       od.String(),
		"verdict":   verdict,
		"reason":    reason,
		"dur_ms":    durMs,
		"up_pkts":   upPkts,
		"down_pkts": downPkts,
		"up_B":      upB,
		"down_B":    downB,
	})
}

func emitErrorEvent(proto, src string, od dstAddr, verdict, reason, detail string) {
	emitEvent(map[string]any{
		"ts":      time.Now().Unix(),
		"event":   "error",
		"proto":   proto,
		"src":     src,
		"dst":     od.String(),
		"verdict": verdict,
		"reason":  reason,
		"detail":  detail,
	})
}

// countWriter 包连接写端计数（relay 两端各一）。单方向单 goroutine 写，
// 用 atomic 以便 relay 返回前无锁读；Write 错误仍返回已写字节数。
type countWriter struct {
	w io.Writer
	n *int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		atomic.AddInt64(c.n, int64(n))
	}
	return n, err
}
