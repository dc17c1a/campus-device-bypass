//! 进程启动时一次性读取的环境配置。
//!
//! 逐字节复刻 Go 原版 `envStr`/`envInt` 的怪癖：
//! - `envStr` 仅在变量非空时采用，显式空串回退默认；值不做 trim、不做校验。
//! - `envInt` 仅在整串可被 `strconv.Atoi`/`i64::from_str` 解析时采用；失败（含空串、
//!   带 `ms` 后缀、含空白）一律回退默认。解析成功即原样采用，**不钳制**，`0` 与负数都合法。
//! - 全部 20 个变量只在此处读一次，运行期不再回读（后续热重载任务不得重读 env）。
//!
//! `Config` 的字段由后续任务消费，在本任务只有测试读取；消费方就位前非测试构建会被
//! `dead_code` 判定为未使用，故此处放行并在消费方接入后删除。

/// 进程级配置，字段名与 Go 原版变量同名。
pub struct Config {
    pub listen_addr: String,
    pub udp_listen_addr: String,
    pub pass_socks: String,
    pub proxy_socks: String,
    pub gate_log_path: String,
    pub stats_path: String,
    pub events_path: String,
    pub udp_err_log_path: String,
    /// `WD_PEEK_MS` 原样保存的有符号毫秒数（不钳制，负数保留）。
    ///
    /// 解释留给消费方：`<= 0` 表示「peek 立即以空缓冲返回」，等价于 Go 里
    /// `time.Duration(负值) * time.Millisecond` 造成的**过去** deadline（读立即超时）。
    /// 这样既复刻 Go 行为，又不会像 `as u64` 那样在 `Instant + Duration` 上溢出 panic。
    pub peek_ms: i64,
    /// `WD_PEEK80_MS`，语义同 [`Config::peek_ms`]。
    pub peek_ms80: i64,
    pub kw_poll_sec: i64,
    pub dl_dom_file: String,
    pub dl_ua_file: String,
    pub dl_ext_file: String,
    pub dl_query_file: String,
    pub udp_fixed_dst: String,
    pub udp_buf_kb: usize,
    pub tcp_buf_kb: usize,
    pub worker_threads: usize,
    /// TCP 中继空闲超时秒数（`WD_TCP_IDLE_SEC`，默认 300）。
    ///
    /// 任一方向连续无字节超过该时长即双向收尾，防止 FIN_WAIT2/CLOSE_WAIT
    /// 常驻把 fd 耗尽（2026-10-20 游戏登录 EMFILE 现场：gate 979/1024，
    /// 系统 FIN_WAIT2 750 + CLOSE_WAIT 437）。`<= 0` 表示禁用（旧语义，
    /// 仅测试用；生产保持默认）。
    pub tcp_idle_sec: i64,
}

/// 读取字符串环境变量：仅非空时采用，显式空串回退默认；不 trim、不校验。
pub fn env_str(k: &str, d: &str) -> String {
    match std::env::var(k) {
        Ok(v) if !v.is_empty() => v,
        _ => d.to_string(),
    }
}

/// 读取整数环境变量：整串可解析为 `i64` 即原样采用（0/负数不钳制），否则回退默认。
pub fn env_int(k: &str, d: i64) -> i64 {
    match std::env::var(k) {
        Ok(v) => v.parse::<i64>().unwrap_or(d),
        Err(_) => d,
    }
}

/// 新增调优变量专用：非正或不可解析一律回退默认，返回正数。
///
/// `WD_UDP_BUF_KB`/`WD_TCP_BUF_KB`/`WD_WORKER_THREADS` 是本重写新增的变量（Go 原版没有），
/// 其语义由我们定义：零/负的缓冲区大小或工作线程数没有意义。故这三个变量刻意**不**沿用
/// 16 个继承变量的「不钳制」风格，而是在解析时对非正值回退默认。
fn env_new_positive(k: &str, d: i64) -> usize {
    let n = env_int(k, d);
    if n > 0 { n as usize } else { d as usize }
}

/// 进程启动时调用一次；结果在进程生命周期内固定。
pub fn load() -> Config {
    Config {
        listen_addr: env_str("WD_LISTEN", "0.0.0.0:12347"),
        udp_listen_addr: env_str("WD_UDP_LISTEN", "0.0.0.0:12348"),
        pass_socks: env_str("WD_PASS_SOCKS", "127.0.0.1:18081"),
        proxy_socks: env_str("WD_PROXY_SOCKS", "127.0.0.1:10811"),
        gate_log_path: env_str("WD_LOG", "/tmp/wxdet/gate.log"),
        stats_path: env_str("WD_STATS", "/tmp/wxdet/stats.tsv"),
        events_path: env_str("WD_EVENTS", "/tmp/wxdet/events.jsonl"),
        udp_err_log_path: env_str("WD_UDP_ERR_LOG", "/tmp/wxdet/udp_err.log"),
        peek_ms: env_int("WD_PEEK_MS", 400),
        peek_ms80: env_int("WD_PEEK80_MS", 80),
        kw_poll_sec: env_int("WD_KW_POLL_SEC", 30),
        dl_dom_file: env_str("WD_DL_DOM_FILE", "/etc/wxdet/dl-domains.txt"),
        dl_ua_file: env_str("WD_DL_UA_FILE", "/etc/wxdet/dl-ua.txt"),
        dl_ext_file: env_str("WD_DL_EXT_FILE", "/etc/wxdet/dl-ext.txt"),
        dl_query_file: env_str("WD_DL_QUERY_FILE", "/etc/wxdet/dl-query.txt"),
        udp_fixed_dst: env_str("WD_UDP_FIXED_DST", ""),
        udp_buf_kb: env_new_positive("WD_UDP_BUF_KB", 2),
        tcp_buf_kb: env_new_positive("WD_TCP_BUF_KB", 8),
        worker_threads: env_new_positive("WD_WORKER_THREADS", 4),
        tcp_idle_sec: env_int("WD_TCP_IDLE_SEC", 300),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_semantics_and_defaults() {
        // --- env_str: 空串 = 默认，且不 trim ---
        unsafe { std::env::set_var("WD_TEST_EMPTY", "") };
        assert_eq!(env_str("WD_TEST_EMPTY", "fallback"), "fallback");
        unsafe { std::env::set_var("WD_TEST_EMPTY", " v ") };
        assert_eq!(env_str("WD_TEST_EMPTY", "fallback"), " v ", "不得 trim");
        unsafe { std::env::remove_var("WD_TEST_EMPTY") };

        // --- env_int: 解析失败回默认；0 与负数必须被采用，不钳制 ---
        unsafe { std::env::set_var("WD_TEST_INT", "abc") };
        assert_eq!(env_int("WD_TEST_INT", 400), 400);
        unsafe { std::env::set_var("WD_TEST_INT", "") };
        assert_eq!(env_int("WD_TEST_INT", 400), 400);
        unsafe { std::env::set_var("WD_TEST_INT", "0") };
        assert_eq!(env_int("WD_TEST_INT", 400), 0);
        unsafe { std::env::set_var("WD_TEST_INT", "-5") };
        assert_eq!(env_int("WD_TEST_INT", 400), -5);
        unsafe { std::env::set_var("WD_TEST_INT", "400ms") };
        assert_eq!(env_int("WD_TEST_INT", 400), 400, "Go Atoi 不接受后缀");
        unsafe { std::env::remove_var("WD_TEST_INT") };

        // --- R11: 负的 peek 毫秒必须原样保留（消费者按 <=0 = 立即空缓冲处理）---
        unsafe { std::env::set_var("WD_PEEK_MS", "-5") };
        assert_eq!(load().peek_ms, -5, "负数不得被钳制或回退");
        unsafe { std::env::remove_var("WD_PEEK_MS") };

        // --- R12: 新增调优变量非正/不可解析 → 回退默认（与继承变量刻意不同）---
        // 注：WD_TCP_IDLE_SEC 是新增但沿用 env_int（0/负=禁用，仅测试用），
        // 故不在此列；默认值与透传在下方单独断言。
        unsafe { std::env::set_var("WD_UDP_BUF_KB", "0") };
        assert_eq!(load().udp_buf_kb, 2);
        unsafe { std::env::remove_var("WD_UDP_BUF_KB") };
        unsafe { std::env::set_var("WD_TCP_BUF_KB", "-3") };
        assert_eq!(load().tcp_buf_kb, 8);
        unsafe { std::env::remove_var("WD_TCP_BUF_KB") };
        unsafe { std::env::set_var("WD_WORKER_THREADS", "0") };
        assert_eq!(load().worker_threads, 4);
        unsafe { std::env::remove_var("WD_WORKER_THREADS") };
        // WD_TCP_IDLE_SEC：默认 300；显式值原样透传（含 0/负=禁用）。
        unsafe { std::env::remove_var("WD_TCP_IDLE_SEC") };
        assert_eq!(load().tcp_idle_sec, 300);
        unsafe { std::env::set_var("WD_TCP_IDLE_SEC", "60") };
        assert_eq!(load().tcp_idle_sec, 60);
        unsafe { std::env::set_var("WD_TCP_IDLE_SEC", "0") };
        assert_eq!(load().tcp_idle_sec, 0);
        unsafe { std::env::remove_var("WD_TCP_IDLE_SEC") };
        // 正数仍被原样采用（防止「一律回默认」的反向 bug）
        unsafe { std::env::set_var("WD_TCP_BUF_KB", "64") };
        assert_eq!(load().tcp_buf_kb, 64);
        unsafe { std::env::remove_var("WD_TCP_BUF_KB") };

        // --- 默认值（先清掉真实 WD_*，避免宿主环境干扰）---
        for k in [
            "WD_LISTEN",
            "WD_UDP_LISTEN",
            "WD_PASS_SOCKS",
            "WD_PROXY_SOCKS",
            "WD_LOG",
            "WD_STATS",
            "WD_EVENTS",
            "WD_UDP_ERR_LOG",
            "WD_PEEK_MS",
            "WD_PEEK80_MS",
            "WD_KW_POLL_SEC",
            "WD_DL_DOM_FILE",
            "WD_DL_UA_FILE",
            "WD_DL_EXT_FILE",
            "WD_DL_QUERY_FILE",
            "WD_UDP_FIXED_DST",
            "WD_UDP_BUF_KB",
            "WD_TCP_BUF_KB",
            "WD_WORKER_THREADS",
            "WD_TCP_IDLE_SEC",
        ] {
            unsafe { std::env::remove_var(k) };
        }
        let c = load();
        assert_eq!(c.listen_addr, "0.0.0.0:12347");
        assert_eq!(c.udp_listen_addr, "0.0.0.0:12348");
        assert_eq!(c.pass_socks, "127.0.0.1:18081");
        assert_eq!(c.proxy_socks, "127.0.0.1:10811");
        assert_eq!(c.gate_log_path, "/tmp/wxdet/gate.log");
        assert_eq!(c.stats_path, "/tmp/wxdet/stats.tsv");
        assert_eq!(c.events_path, "/tmp/wxdet/events.jsonl");
        assert_eq!(c.udp_err_log_path, "/tmp/wxdet/udp_err.log");
        assert_eq!(c.peek_ms, 400);
        assert_eq!(c.peek_ms80, 80);
        assert_eq!(c.kw_poll_sec, 30);
        assert_eq!(c.dl_dom_file, "/etc/wxdet/dl-domains.txt");
        assert_eq!(c.dl_ua_file, "/etc/wxdet/dl-ua.txt");
        assert_eq!(c.dl_ext_file, "/etc/wxdet/dl-ext.txt");
        assert_eq!(c.dl_query_file, "/etc/wxdet/dl-query.txt");
        assert_eq!(c.udp_fixed_dst, "");
        assert_eq!(c.udp_buf_kb, 2);
        assert_eq!(c.tcp_buf_kb, 8);
        assert_eq!(c.worker_threads, 4);
        assert_eq!(c.tcp_idle_sec, 300);
    }
}
