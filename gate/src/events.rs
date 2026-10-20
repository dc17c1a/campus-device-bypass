//! events.jsonl 统一事件流：键序 = Go `json.Marshal(map)` 字典序，Go 式 HTML 转义。
//!
//! Consumed by Task 14/15 (TCP open/close/error) and Task 17/18 (UDP uclose/error); wired in Task 19.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::reason::{Reason, Verdict};

/// 关闭方向：先返回的 Copy 方向的源端。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closer {
    Client,
    Server,
}

impl Closer {
    pub fn as_str(self) -> &'static str {
        match self {
            Closer::Client => "client",
            Closer::Server => "server",
        }
    }
}

/// events.jsonl 全局句柄（Go 的 `eventsFile` + `eventsMu` 合一）。
static EVENTS_FILE: OnceLock<Mutex<Option<File>>> = OnceLock::new();

fn cell() -> &'static Mutex<Option<File>> {
    EVENTS_FILE.get_or_init(|| Mutex::new(None))
}

fn lock(m: &'static Mutex<Option<File>>) -> std::sync::MutexGuard<'static, Option<File>> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 打开事件流：父目录 `MkdirAll 0755`，文件 `O_APPEND|O_CREATE|O_WRONLY 0644`。
/// 失败只 warn（stderr），句柄置空——此后所有 emit 静默 no-op（Go `initEvents` 对等）。
/// 重复 init 替换旧句柄（测试按 tag 重定向）。
pub fn init(path: &str) {
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }
    match OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .open(path)
    {
        Ok(f) => {
            *lock(cell()) = Some(f);
        }
        Err(e) => {
            eprintln!("wxdet-gate: events init {path} failed: {e}; events disabled");
            *lock(cell()) = None;
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Go `encoding/json`（SetEscapeHTML）字符串转义：
/// `"`→`\"`、`\`→`\\`、`<`→`\u003c`、`>`→`\u003e`、`&`→`\u0026`、C0→`\u00xx`；
/// 其余（含非 ASCII）原样透传（§6.2：源头窄类型保证不可达，JSON 只需处理这几项）。
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '<' => o.push_str("\\u003c"),
            '>' => o.push_str("\\u003e"),
            '&' => o.push_str("\\u0026"),
            c if (c as u32) < 0x20 => {
                o.push_str(&format!("\\u00{:02x}", c as u32));
            }
            _ => o.push(c),
        }
    }
    o
}

fn write_line(line: String) {
    let mut slot = lock(cell());
    if let Some(f) = slot.as_mut()
        && f.write_all(line.as_bytes()).is_err()
    {
        crate::stats::write_stat("gate_events_err", 1);
    }
}

/// 过滤唯一例外（Go `shouldEmitOpen`）：只看 reason，不看 verdict。
pub fn should_emit_open(reason: &Reason) -> bool {
    reason.should_emit_open()
}

pub fn emit_open(proto: &str, src: &str, dst: &str, verdict: Verdict, reason: &Reason) {
    if !should_emit_open(reason) {
        return;
    }
    write_line(format!(
        "{{\"dst\":\"{}\",\"event\":\"open\",\"proto\":\"{}\",\"reason\":\"{}\",\"src\":\"{}\",\"ts\":{},\"verdict\":\"{}\"}}\n",
        esc(dst),
        esc(proto),
        esc(&reason.as_str()),
        esc(src),
        unix_now(),
        verdict.as_str(),
    ));
}

// 参数个数与 Go 的 emitCloseEvent 对齐，签名由任务契约冻结，不得打包。
#[allow(clippy::too_many_arguments)]
pub fn emit_close(
    proto: &str,
    src: &str,
    dst: &str,
    verdict: Verdict,
    reason: &Reason,
    dur_ms: u64,
    up_b: u64,
    down_b: u64,
    closer: Closer,
) {
    // tls_direct 不进流（与 open 同过滤；error 事件不受此限，永远进流）。
    if !should_emit_open(reason) {
        return;
    }
    let long = if dur_ms > 60000 { ",\"long\":1" } else { "" };
    write_line(format!(
        "{{\"closer\":\"{}\",\"down_B\":{},\"dst\":\"{}\",\"dur_ms\":{},\"event\":\"close\"{},\"proto\":\"{}\",\"reason\":\"{}\",\"src\":\"{}\",\"ts\":{},\"up_B\":{},\"verdict\":\"{}\"}}\n",
        closer.as_str(),
        down_b,
        esc(dst),
        dur_ms,
        long,
        esc(proto),
        esc(&reason.as_str()),
        esc(src),
        unix_now(),
        up_b,
        verdict.as_str(),
    ));
}

// 参数个数与 Go 的 emitUCloseEvent 对齐，签名由任务契约冻结，不得打包。
#[allow(clippy::too_many_arguments)]
pub fn emit_uclose(
    src: &str,
    dst: &str,
    verdict: Verdict,
    reason: &Reason,
    dur_ms: u64,
    up_pkts: u64,
    down_pkts: u64,
    up_b: u64,
    down_b: u64,
) {
    write_line(format!(
        "{{\"down_B\":{},\"down_pkts\":{},\"dst\":\"{}\",\"dur_ms\":{},\"event\":\"uclose\",\"proto\":\"udp\",\"reason\":\"{}\",\"src\":\"{}\",\"ts\":{},\"up_B\":{},\"up_pkts\":{},\"verdict\":\"{}\"}}\n",
        down_b,
        down_pkts,
        esc(dst),
        dur_ms,
        esc(&reason.as_str()),
        esc(src),
        unix_now(),
        up_b,
        up_pkts,
        verdict.as_str(),
    ));
}

pub fn emit_error(proto: &str, src: &str, dst: &str, reason: &Reason, detail: &str) {
    // error 永远进流，不过滤。verdict 恒为 "err"（Go 全部 6 处调用原文）。
    write_line(format!(
        "{{\"detail\":\"{}\",\"dst\":\"{}\",\"event\":\"error\",\"proto\":\"{}\",\"reason\":\"{}\",\"src\":\"{}\",\"ts\":{},\"verdict\":\"err\"}}\n",
        esc(detail),
        esc(dst),
        esc(proto),
        esc(&reason.as_str()),
        esc(src),
        unix_now(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reason::{Reason, TcpReason, UdpReason, Verdict};

    #[test]
    fn close_event_keys_are_lexicographically_ordered() {
        let _serial = crate::ledger::FILE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("wxdet-events-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl");
        let _ = std::fs::remove_file(&p);
        init(p.to_str().unwrap());
        emit_close(
            "tcp",
            "192.168.71.50:1",
            "1.2.3.4:443",
            Verdict::Proxy,
            &Reason::Tcp(TcpReason::Default),
            60001,
            10,
            20,
            Closer::Client,
        );
        let s = std::fs::read_to_string(&p).unwrap();
        let line = s.trim_end();
        // R22a：字节序 "down_B" < "dst"（'o' 0x6F < 's' 0x73），brief 原稿笔误已修正。
        const KEYS: [&str; 12] = [
            "\"closer\"",
            "\"down_B\"",
            "\"dst\"",
            "\"dur_ms\"",
            "\"event\"",
            "\"long\"",
            "\"proto\"",
            "\"reason\"",
            "\"src\"",
            "\"ts\"",
            "\"up_B\"",
            "\"verdict\"",
        ];
        let idx: Vec<(usize, &str)> = KEYS
            .iter()
            .map(|k| (line.find(k).unwrap_or_else(|| panic!("缺键 {k}")), *k))
            .collect();
        let mut sorted = idx.clone();
        sorted.sort_by_key(|(i, _)| *i);
        assert_eq!(
            idx, sorted,
            "键序必须是字典序（long 插在 event 与 proto 之间）"
        );
        assert!(line.contains("\"long\":1"));
    }

    #[test]
    fn long_flag_boundary_is_strictly_greater() {
        let _serial = crate::ledger::FILE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("wxdet-events-boundary");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl");
        let _ = std::fs::remove_file(&p);
        init(p.to_str().unwrap());
        emit_close(
            "tcp",
            "1.1.1.1:1",
            "2.2.2.2:2",
            Verdict::Proxy,
            &Reason::Tcp(TcpReason::Default),
            60000,
            0,
            0,
            Closer::Server,
        );
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(!s.contains("\"long\""), "60000 不得带 long");
    }

    #[test]
    fn tls_direct_open_and_close_are_filtered() {
        let _serial = crate::ledger::FILE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("wxdet-events-filter");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl");
        let _ = std::fs::remove_file(&p);
        init(p.to_str().unwrap());
        assert!(!should_emit_open(&Reason::Tcp(TcpReason::TlsDirect)));
        assert!(should_emit_open(&Reason::Tcp(TcpReason::Default)));
        assert!(should_emit_open(&Reason::Udp(UdpReason::StunUdp)));
        // error 永不过滤：即便 reason 是 tls_direct 也要写
        emit_error(
            "tcp",
            "1.1.1.1:1",
            "2.2.2.2:2",
            &Reason::Tcp(TcpReason::TlsDirect),
            "dial failed",
        );
        let s = std::fs::read_to_string(&p).unwrap();
        assert_eq!(s.lines().count(), 1);
    }

    #[test]
    fn html_characters_are_go_escaped() {
        let _serial = crate::ledger::FILE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("wxdet-events-html");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl");
        let _ = std::fs::remove_file(&p);
        init(p.to_str().unwrap());
        emit_error(
            "tcp",
            "1.1.1.1:1",
            "2.2.2.2:2",
            &Reason::Tcp(TcpReason::Default),
            "a<b>&c",
        );
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(
            s.contains("a\\u003cb\\u003e\\u0026c"),
            "必须 Go 式 HTML 转义: {s}"
        );
    }
}
