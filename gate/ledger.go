package main

import (
	"sync/atomic"
	"time"
)

// 直连面（reason=tls_direct）台账：这类流不进事件流（体量最大，见 events.go
// shouldEmitOpen），但它占出网 TCP 的约七成 —— 不记就是黑盒：抗 DPI 的任何
// 裁定（例如要不要把 TLS 收进隧道、SNI 分片有没有用）都得先有这条面的
// 字节/时长基线。
//
// 落账方式：**聚合计数 + 每分钟一次增量刷盘**。不逐流落盘的原因：tls_direct
// 实测每 stats 窗口数千条，4 行/流会把 stats.tsv 撑爆并加速 4M 截断、反而缩短
// 观测窗口；增量刷盘是 4 行/分钟，粒度足够算字节与平均时长。
// 代价：进程被杀时最坏丢 1 分钟增量（restart 有秒级断流，量级可忽略）。
var (
	ledgerClose atomic.Int64 // 完成的直连流数
	ledgerUpB   atomic.Int64 // client→server 字节
	ledgerDownB atomic.Int64 // server→client 字节
	ledgerDurMs atomic.Int64 // 时长合计（配合 close 算均值）
)

func ledgerAdd(durMs, upB, downB int64) {
	ledgerClose.Add(1)
	ledgerUpB.Add(upB)
	ledgerDownB.Add(downB)
	ledgerDurMs.Add(durMs)
}

// ledgerFlush 把累计增量写进 stats.tsv 并清零；无流量时一行都不写（保持文件干净）。
// 导出给测试直接调用（生产由 startLedgerFlush 每分钟驱动）。
func ledgerFlush() {
	c := ledgerClose.Swap(0)
	if c == 0 {
		return
	}
	writeStat64("gate_tlsdirect_close", c)
	writeStat64("gate_tlsdirect_up_B", ledgerUpB.Swap(0))
	writeStat64("gate_tlsdirect_down_B", ledgerDownB.Swap(0))
	writeStat64("gate_tlsdirect_dur_ms", ledgerDurMs.Swap(0))
}

func startLedgerFlush(interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			ledgerFlush()
		}
	}()
}
