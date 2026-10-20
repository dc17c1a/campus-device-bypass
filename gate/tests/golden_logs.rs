//! Task 20: 日志/事件 golden 逐字节测试。
//!
//! R34 改编说明：brief Step 1 调用的 `render_gate_log` / `render_udp_err` /
//! `render_open` 纯渲染函数不存在（Task 7/9/10 建的是文件落盘 API），且另起渲染层会
//! 分叉格式逻辑。此处改为文件回环：调真实落盘 API → 读回文件 → 断言完整字节。
//! 唯一归一化的字段是 `ts`（写器内 `SystemTime::now()` 自取，无注入点）：
//! 其余字节（含 `dur_ms` / `up_B` / `down_B` / `long` / 键序 / HTML 转义 / 截断）
//! 全部按 brief 字面量逐字节钉死；`ts` 只断言结构（十进制 digits，位置见各 helper）。
//!
//! 二进制 crate 无 `[lib]`，集成测试无法 `use` 内部模块，故此处用 `#[path]`
//! 把真实源码模块直接编入本测试 crate —— 测的是同一份格式代码，不是分叉实现。
//! 每个文件输出用例全程持有 `ledger::FILE_TEST_LOCK`（既定模式），且按已知顺序规则
//! 先 `config_with_socks`（清陈旧文件）再 `reset_*`（重定向句柄）。
//!
//! `#[path]` 会把整模块（含其内部单测）编入本二进制，单测用不到的辅助函数
//! （如 fake socks / duplex）会触发 dead_code，故 crate 级放行（gate 用 `-D warnings`）。
#![allow(dead_code)]

#[path = "../src/config.rs"]
mod config;
#[path = "../src/events.rs"]
mod events;
#[path = "../src/ledger.rs"]
mod ledger;
#[path = "../src/log_gate.rs"]
mod log_gate;
#[path = "../src/quote.rs"]
mod quote;
#[path = "../src/reason.rs"]
mod reason;
#[path = "../src/stats.rs"]
mod stats;
#[path = "../src/testutil.rs"]
mod testutil;

use events::Closer;
use reason::{Reason, TcpReason, UdpReason, Verdict};

/// brief 期望字面量里写死的 ts 锚点；回环输出的真实 ts 归一化到它再比较。
const FIXED_TS: u64 = 1_750_000_000;

/// 把内容中唯一的 `"ts":<digits>` 数字段替换为 FIXED_TS。
/// 结构断言：恰出现一次、非空全 digits、后随 `,` 或 `}`。
fn normalize_json_ts(content: &str) -> String {
    let key = "\"ts\":";
    assert_eq!(
        content.matches(key).count(),
        1,
        "ts 必须恰出现一次: {content:?}"
    );
    let i = content.find(key).unwrap() + key.len();
    let digits = content[i..]
        .bytes()
        .take_while(|b| b.is_ascii_digit())
        .count();
    assert!(digits > 0, "ts 必须是非空十进制: {content:?}");
    let end = i + digits;
    assert!(
        matches!(content.as_bytes()[end], b',' | b'}'),
        "ts 后必须紧随 , 或 }}: {content:?}"
    );
    format!("{}{FIXED_TS}{}", &content[..i], &content[end..])
}

/// udp_err.log 首段是裸 unix 秒：校验全 digits 后归一化。
fn normalize_udp_err_ts(content: &str) -> String {
    let (ts, rest) = content.split_once('\t').expect("udp_err 首段必须是 ts");
    assert!(
        !ts.is_empty() && ts.bytes().all(|b| b.is_ascii_digit()),
        "首段必须是 unix 秒 digits: {content:?}"
    );
    assert!(
        rest.starts_with("192.168.71.50:51000\t"),
        "第 2 段是 client: {content:?}"
    );
    format!("{FIXED_TS}\t{rest}")
}

/// 断言文件恰一行且以换行结尾，返回该行（含 `\n`）。
fn single_line(content: &str) -> &str {
    assert!(content.ends_with('\n'), "行必须以换行结尾: {content:?}");
    assert_eq!(content.lines().count(), 1, "必须恰写一行: {content:?}");
    content
}

#[test]
fn gate_log_full_line_is_byte_exact() {
    let _serial = ledger::FILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tag = "golden-gate-line";
    let _cfg = testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
    testutil::reset_logs(tag);
    log_gate::log_gate(
        "tcp",
        "192.168.71.50:51000",
        "1.2.3.4:443",
        "pass",
        "tls_direct",
        &[0x16, 0x03, 0x01],
    );
    let content = testutil::read_gate_log(tag);
    let line = single_line(&content);
    assert!(
        line.starts_with("{\"ts\":"),
        "gate 行 ts 必须在首字段位置: {line:?}"
    );
    let want = "{\"ts\":1750000000,\"proto\":\"tcp\",\"src\":\"192.168.71.50:51000\",\"dst\":\"1.2.3.4:443\",\"verdict\":\"pass\",\"reason\":\"tls_direct\",\"first\":\"160301\"}\n";
    assert_eq!(normalize_json_ts(line), want);
}

#[test]
fn gate_log_first_24b_truncation_is_byte_exact() {
    let _serial = ledger::FILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tag = "golden-gate-trunc";
    let _cfg = testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
    testutil::reset_logs(tag);
    // 25B 输入：只取前 24B hex 并缀 `..`。
    let first: Vec<u8> = (0..25u8).collect();
    log_gate::log_gate(
        "tcp",
        "192.168.71.50:51000",
        "1.2.3.4:443",
        "pass",
        "tls_direct",
        &first,
    );
    let content = testutil::read_gate_log(tag);
    let line = single_line(&content);
    let want = "{\"ts\":1750000000,\"proto\":\"tcp\",\"src\":\"192.168.71.50:51000\",\"dst\":\"1.2.3.4:443\",\"verdict\":\"pass\",\"reason\":\"tls_direct\",\"first\":\"000102030405060708090a0b0c0d0e0f1011121314151617..\"}\n";
    assert_eq!(normalize_json_ts(line), want);
}

#[test]
fn gate_log_empty_first_is_byte_exact() {
    let _serial = ledger::FILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tag = "golden-gate-empty";
    let _cfg = testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
    testutil::reset_logs(tag);
    log_gate::log_gate(
        "tcp",
        "192.168.71.50:51000",
        "1.2.3.4:443",
        "pass",
        "tls_direct",
        &[],
    );
    let content = testutil::read_gate_log(tag);
    let line = single_line(&content);
    let want = "{\"ts\":1750000000,\"proto\":\"tcp\",\"src\":\"192.168.71.50:51000\",\"dst\":\"1.2.3.4:443\",\"verdict\":\"pass\",\"reason\":\"tls_direct\",\"first\":\"\"}\n";
    assert_eq!(normalize_json_ts(line), want);
}

#[test]
fn gate_log_err_line_truncation_and_order_is_byte_exact() {
    let _serial = ledger::FILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tag = "golden-gate-err";
    let _cfg = testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
    testutil::reset_logs(tag);
    // detail 100B → 64B 截断 + `..`；first 40B → 前 24B hex + `..`。
    let detail = "x".repeat(100);
    let first: Vec<u8> = (0..40u8).collect();
    log_gate::log_gate_err(
        "udp",
        "1.1.1.1:1",
        "2.2.2.2:2",
        "udp_upgrade_proxy_fail",
        &detail,
        &first,
    );
    let content = testutil::read_gate_log(tag);
    let line = single_line(&content);
    let i_reason = line.find("\"reason\"").expect("缺 reason");
    let i_detail = line.find("\"detail\"").expect("缺 detail");
    let i_first = line.find("\"first\"").expect("缺 first");
    assert!(
        i_reason < i_detail && i_detail < i_first,
        "字段顺序必须 reason→detail→first: {line:?}"
    );
    assert!(
        line.contains("\"verdict\":\"err\""),
        "err 行 verdict: {line:?}"
    );
    // detail 载荷：64 个 x + `..`。
    let want = "{\"ts\":1750000000,\"proto\":\"udp\",\"src\":\"1.1.1.1:1\",\"dst\":\"2.2.2.2:2\",\"verdict\":\"err\",\"reason\":\"udp_upgrade_proxy_fail\",\"detail\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx..\",\"first\":\"000102030405060708090a0b0c0d0e0f1011121314151617..\"}\n";
    assert_eq!(normalize_json_ts(line), want);
}

#[test]
fn udp_err_line_is_byte_exact() {
    let _serial = ledger::FILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tag = "golden-udp-err";
    let _cfg = testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
    testutil::reset_logs(tag);
    // 5s 限速三连：首写落盘，后两连写被限速，文件仍只一行。
    let first = log_gate::udp_err_log(
        "192.168.71.50:51000",
        42,
        "1.2.3.4:443",
        "no origdst cmsg",
        &[0xde, 0xad],
    );
    assert!(first, "首写必须落盘");
    for _ in 0..2 {
        let again = log_gate::udp_err_log(
            "192.168.71.50:51000",
            42,
            "1.2.3.4:443",
            "no origdst cmsg",
            &[0xde, 0xad],
        );
        assert!(!again, "5s 窗口内复写必须被限速");
    }
    let path = testutil::out_dir(tag).join("udp_err.log");
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let line = single_line(&content);
    // 固定 6 段：ts \t client \t n= \t od= \t err= \t first=
    let fields: Vec<&str> = line.trim_end().split('\t').collect();
    assert_eq!(fields.len(), 6, "udp_err 必须是 6 段: {line:?}");
    assert_eq!(fields[2], "n=42");
    assert_eq!(fields[3], "od=1.2.3.4:443");
    assert_eq!(fields[4], "err=no origdst cmsg");
    assert_eq!(fields[5], "first=dead");
    let want =
        "1750000000\t192.168.71.50:51000\tn=42\tod=1.2.3.4:443\terr=no origdst cmsg\tfirst=dead\n";
    assert_eq!(normalize_udp_err_ts(line), want);
}

#[test]
fn open_event_is_byte_exact() {
    let _serial = ledger::FILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tag = "golden-open";
    let _cfg = testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
    testutil::reset_events(tag);
    events::emit_open(
        "udp",
        "192.168.71.50:51000",
        "1.2.3.4:3478",
        Verdict::Proxy,
        &Reason::Udp(UdpReason::StunUdp),
    );
    let content = testutil::read_events(tag);
    let line = single_line(&content);
    let want = "{\"dst\":\"1.2.3.4:3478\",\"event\":\"open\",\"proto\":\"udp\",\"reason\":\"stun_udp\",\"src\":\"192.168.71.50:51000\",\"ts\":1750000000,\"verdict\":\"proxy\"}\n";
    assert_eq!(normalize_json_ts(line), want);
}

#[test]
fn close_event_long_flag_set_is_byte_exact() {
    let _serial = ledger::FILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tag = "golden-close-long";
    let _cfg = testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
    testutil::reset_events(tag);
    events::emit_close(
        "tcp",
        "192.168.71.50:51000",
        "1.2.3.4:443",
        Verdict::Proxy,
        &Reason::Tcp(TcpReason::Default),
        60001,
        10,
        20,
        Closer::Client,
    );
    let content = testutil::read_events(tag);
    let line = single_line(&content);
    // 键序字典序，`long` 插在 event 与 proto 之间。
    let want = "{\"closer\":\"client\",\"down_B\":20,\"dst\":\"1.2.3.4:443\",\"dur_ms\":60001,\"event\":\"close\",\"long\":1,\"proto\":\"tcp\",\"reason\":\"default\",\"src\":\"192.168.71.50:51000\",\"ts\":1750000000,\"up_B\":10,\"verdict\":\"proxy\"}\n";
    assert_eq!(normalize_json_ts(line), want);
}

#[test]
fn close_event_no_long_at_60000_is_byte_exact() {
    let _serial = ledger::FILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tag = "golden-close-plain";
    let _cfg = testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
    testutil::reset_events(tag);
    events::emit_close(
        "tcp",
        "1.1.1.1:1",
        "2.2.2.2:2",
        Verdict::Proxy,
        &Reason::Tcp(TcpReason::Default),
        60000,
        7,
        9,
        Closer::Server,
    );
    let content = testutil::read_events(tag);
    let line = single_line(&content);
    assert!(!line.contains("\"long\""), "60000 不得带 long: {line:?}");
    let want = "{\"closer\":\"server\",\"down_B\":9,\"dst\":\"2.2.2.2:2\",\"dur_ms\":60000,\"event\":\"close\",\"proto\":\"tcp\",\"reason\":\"default\",\"src\":\"1.1.1.1:1\",\"ts\":1750000000,\"up_B\":7,\"verdict\":\"proxy\"}\n";
    assert_eq!(normalize_json_ts(line), want);
}

#[test]
fn uclose_event_is_byte_exact() {
    let _serial = ledger::FILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tag = "golden-uclose";
    let _cfg = testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
    testutil::reset_events(tag);
    events::emit_uclose(
        "192.168.71.50:51000",
        "1.2.3.4:3478",
        Verdict::Proxy,
        &Reason::Udp(UdpReason::UdpProxy),
        1234,
        5,
        6,
        700,
        800,
    );
    let content = testutil::read_events(tag);
    let line = single_line(&content);
    let want = "{\"down_B\":800,\"down_pkts\":6,\"dst\":\"1.2.3.4:3478\",\"dur_ms\":1234,\"event\":\"uclose\",\"proto\":\"udp\",\"reason\":\"udp_proxy\",\"src\":\"192.168.71.50:51000\",\"ts\":1750000000,\"up_B\":700,\"up_pkts\":5,\"verdict\":\"proxy\"}\n";
    assert_eq!(normalize_json_ts(line), want);
}

#[test]
fn error_event_html_escape_is_byte_exact() {
    let _serial = ledger::FILE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tag = "golden-error";
    let _cfg = testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
    testutil::reset_events(tag);
    events::emit_error(
        "tcp",
        "1.1.1.1:1",
        "2.2.2.2:2",
        &Reason::Tcp(TcpReason::Default),
        "a<b>\"q\"\\&c",
    );
    let content = testutil::read_events(tag);
    let line = single_line(&content);
    // Go SetEscapeHTML：< → \u003c、> → \u003e、& → \u0026；" → \"、\ → \\。
    let want = "{\"detail\":\"a\\u003cb\\u003e\\\"q\\\"\\\\\\u0026c\",\"dst\":\"2.2.2.2:2\",\"event\":\"error\",\"proto\":\"tcp\",\"reason\":\"default\",\"src\":\"1.1.1.1:1\",\"ts\":1750000000,\"verdict\":\"err\"}\n";
    assert_eq!(normalize_json_ts(line), want);
}
