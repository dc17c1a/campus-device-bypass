// Task 14/15/16/17/18 consume this module (gate.log writers + 5s limiters);
// allow dead code until wired (R10).

//! gate.log / udp_err.log writers + three independent 5s rate limiters.
//!
//! Go authority: `logGate` / `logGateErr` / `firstBytes` / `tcpLocalDropLogNs`
//! in `main.go`, `logUDPLocalDrop` / `udpErrLog` / `udpErrLogAt` in `udp.go`.
//!
//! Line templates (field order is load-bearing — mining scripts parse them):
//! - normal: `{"ts":%d,"proto":%q,"src":%q,"dst":%q,"verdict":%q,"reason":%q,"first":%q}`
//! - err:    `{"ts":%d,"proto":%q,"src":%q,"dst":%q,"verdict":"err","reason":%q,"detail":%q,"first":%q}`
//! - udp_err (6 tab-separated fields):
//!   `{unix}\t{client}\tn={n}\tod={od}\terr={err}\tfirst={hex16}\n`
//!
//! `first` renders the first 24 bytes as lowercase hex + `..` when longer
//! (`quote::hex_prefix`); empty input renders `""`. `detail` truncates at
//! 64 bytes + `..` (`quote::trunc_detail`). udp_err `first` renders the
//! first 16 bytes with NO `..` suffix (`quote::hex_prefix16`).
//!
//! All gate.log writes hold `stats::io_lock()` (Go's `ioMu`) for mutual
//! exclusion with stats.tsv writes. The gate.log handle itself lives in this
//! module's own sink — it must NOT reuse `io_lock`'s `Option<File>` slot,
//! which belongs to stats.tsv.
//!
//! The three 5s limiters (TCP local-drop, UDP local-drop, udp_err) each own
//! an independent timestamp pair (not per-src): a process-wide `AtomicU64`
//! nanos timestamp (Go parity) fronted by a thread-local tier for parallel-
//! test isolation. A shared limiter across log types would silence one log
//! type due to another's traffic.
//!
//! Test isolation: `cargo test` runs tests on parallel threads of one
//! process while each test `init`s a DIFFERENT dir. `init` therefore records
//! its sink both as the process default (Go parity: single global used by
//! every production thread) and in thread-local storage; writers prefer the
//! calling thread's sink and fall back to the default. Production calls
//! `init` once, so every thread shares the default — exactly Go's globals.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::quote::{go_quote, hex_prefix, hex_prefix16, trunc_detail};

/// Log file locations. `gate_log` defaults to `$WD_LOG`, `udp_err_log` to
/// `$WD_UDP_ERR_LOG` (wired by a later task; kept as plain strings here).
pub struct LogPaths {
    pub gate_log: String,
    pub udp_err_log: String,
}

/// 5s rate-limit window in nanoseconds (Go: `int64(5*time.Second)`).
const LIMIT_NS: u64 = 5_000_000_000;

/// Limiter timestamps (unix nanos, 0 = never). Two tiers per log type:
///
/// - thread-local tier: the calling thread's own timestamp. `cargo test`
///   runs tests on parallel threads sharing one process; a foreign test's
///   `reset_rate_limits` must not revive THIS thread's just-consumed window
///   (that flaked `udp_err_log_format_and_5s_rate_limit` ~7%: two lines
///   instead of one). Foreign resets never touch this tier.
/// - process-wide tier: Go parity (`tcpLocalDropLogNs` / `udpLocalDropLogNs`
///   / `udpErrLogNs`) — one line per 5s no matter which thread floods.
///
/// `allow` consults the thread tier first and short-circuits: when the
/// thread tier denies, the global tier is untouched. When the thread tier
/// allows but the global tier denies (another thread just logged), the
/// thread timestamp stays consumed — benign over-suppression, no correctness
/// impact. `reset_rate_limits` zeroes the process-wide triple and the
/// CALLER's thread-local triple.
static G_TCP_DROP_NS: AtomicU64 = AtomicU64::new(0);
static G_UDP_DROP_NS: AtomicU64 = AtomicU64::new(0);
static G_UDP_ERR_NS: AtomicU64 = AtomicU64::new(0);
thread_local! {
    static L_TCP_DROP_NS: AtomicU64 = const { AtomicU64::new(0) };
    static L_UDP_DROP_NS: AtomicU64 = const { AtomicU64::new(0) };
    static L_UDP_ERR_NS: AtomicU64 = const { AtomicU64::new(0) };
}

/// One `init` generation: open gate.log handle + udp_err.log path.
struct Sink {
    /// `O_APPEND|O_CREATE|O_WRONLY 0644` handle (Go's `gateLogFile`).
    gate: Mutex<Option<File>>,
    /// udp_err.log path, opened per write like Go's `udpErrLogAt`.
    udp_err: Mutex<String>,
}

/// Process default sink (Go parity: every production thread shares it).
static DEFAULT_SINK: OnceLock<Mutex<Option<Arc<Sink>>>> = OnceLock::new();

thread_local! {
    // Calling thread's own sink (parallel-test isolation; see module docs).
    static TLS_SINK: RefCell<Option<Arc<Sink>>> = const { RefCell::new(None) };
}

fn default_cell() -> &'static Mutex<Option<Arc<Sink>>> {
    DEFAULT_SINK.get_or_init(|| Mutex::new(None))
}

fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Current thread's sink, else the process default (production path).
fn sink() -> Option<Arc<Sink>> {
    if let Some(s) = TLS_SINK.with(|c| c.borrow().clone()) {
        return Some(s);
    }
    lock(default_cell()).clone()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Open `gate.log` (`O_APPEND|O_CREATE|O_WRONLY 0644`) and record the
/// `udp_err.log` path (touched with the same flags, best-effort).
/// Creates the gate.log parent dir (`MkdirAll 0755`); the udp_err dir is
/// NEVER created (Go parity — its per-write open just fails until the dir
/// exists). Re-init replaces the handle. On gate.log failure only warns
/// (stderr) and later `log_gate*` calls are silent no-ops, like Go's
/// `nil`-file early return.
pub fn init(paths: &LogPaths) {
    if let Some(parent) = std::path::Path::new(&paths.gate_log).parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(parent);
    }
    let gate = match OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .open(&paths.gate_log)
    {
        Ok(f) => Some(f),
        Err(e) => {
            eprintln!(
                "wxdet-gate: gate log {} failed: {e}; gate log disabled",
                paths.gate_log
            );
            None
        }
    };
    // Touch udp_err.log with the same flags (no dir creation): mirrors the
    // brief's "各自 O_APPEND|O_CREATE|O_WRONLY 0644". Failures are silent —
    // the per-write open in `udp_err_log` reports nothing either.
    if let Ok(f) = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .open(&paths.udp_err_log)
    {
        drop(f);
    }
    let s = Arc::new(Sink {
        gate: Mutex::new(gate),
        udp_err: Mutex::new(paths.udp_err_log.clone()),
    });
    TLS_SINK.with(|c| *c.borrow_mut() = Some(s.clone()));
    *lock(default_cell()) = Some(s);
}

/// Test hook: zero the process-wide timestamps and the CALLER's
/// thread-local timestamps. Other threads' locals are untouched (parallel-
/// test isolation — see the tier docs above).
#[cfg(test)]
pub fn reset_rate_limits() {
    G_TCP_DROP_NS.store(0, Ordering::SeqCst);
    G_UDP_DROP_NS.store(0, Ordering::SeqCst);
    G_UDP_ERR_NS.store(0, Ordering::SeqCst);
    L_TCP_DROP_NS.with(|s| s.store(0, Ordering::SeqCst));
    L_UDP_DROP_NS.with(|s| s.store(0, Ordering::SeqCst));
    L_UDP_ERR_NS.with(|s| s.store(0, Ordering::SeqCst));
}

/// Single-attempt 5s gate on one `AtomicU64` nanos slot: returns true when
/// the caller may log.
/// (Go: `Load` + window check + one `CompareAndSwap`; a lost CAS means a
/// concurrent caller just logged, so we stay silent.)
fn allow_slot(slot: &AtomicU64, now: u64) -> bool {
    let last = slot.load(Ordering::SeqCst);
    if now.wrapping_sub(last) < LIMIT_NS {
        return false;
    }
    slot.compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

/// Two-tier 5s gate: thread-local tier first (short-circuit), then the
/// process-wide tier. See the tier docs on the statics above.
fn allow(local: &AtomicU64, global: &'static AtomicU64, now: u64) -> bool {
    if !allow_slot(local, now) {
        return false;
    }
    allow_slot(global, now)
}

fn write_gate_line(line: &str) {
    // Hold Go's shared ioMu across the write for exclusion with stats.tsv.
    let _io = lock(crate::stats::io_lock());
    if let Some(s) = sink()
        && let Some(f) = s.gate.lock().unwrap_or_else(|e| e.into_inner()).as_mut()
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Normal gate.log line. Silent no-op when never `init`ed / `init` failed.
pub fn log_gate(proto: &str, src: &str, dst: &str, verdict: &str, reason: &str, first: &[u8]) {
    let line = format!(
        "{{\"ts\":{},\"proto\":{},\"src\":{},\"dst\":{},\"verdict\":{},\"reason\":{},\"first\":{}}}\n",
        now_unix(),
        go_quote(proto),
        go_quote(src),
        go_quote(dst),
        go_quote(verdict),
        go_quote(reason),
        go_quote(&hex_prefix(first, 24)),
    );
    write_gate_line(&line);
}

/// err gate.log line: `verdict` is always `"err"`, with a 64B-truncated
/// `detail` field between `reason` and `first` (field order load-bearing).
pub fn log_gate_err(proto: &str, src: &str, dst: &str, reason: &str, detail: &str, first: &[u8]) {
    let line = format!(
        "{{\"ts\":{},\"proto\":{},\"src\":{},\"dst\":{},\"verdict\":\"err\",\"reason\":{},\"detail\":{},\"first\":{}}}\n",
        now_unix(),
        go_quote(proto),
        go_quote(src),
        go_quote(dst),
        go_quote(reason),
        go_quote(&trunc_detail(detail)),
        go_quote(&hex_prefix(first, 24)),
    );
    write_gate_line(&line);
}

/// TCP local-dst drop sampling: stats are counted by the caller every time,
/// gate.log gets at most one line per 5s (own timestamp).
pub fn log_tcp_local_drop(src: &str, dst: &str, first: &[u8]) {
    let ok = L_TCP_DROP_NS.with(|l| allow(l, &G_TCP_DROP_NS, now_nanos()));
    if !ok {
        return;
    }
    log_gate("tcp", src, dst, "drop", "local_dst", first);
}

/// UDP local-dst drop sampling: same 5s rule, INDEPENDENT timestamp from TCP.
pub fn log_udp_local_drop(src: &str, dst: &str, first: &[u8]) {
    let ok = L_UDP_DROP_NS.with(|l| allow(l, &G_UDP_DROP_NS, now_nanos()));
    if !ok {
        return;
    }
    log_gate("udp", src, dst, "drop", "local_dst", first);
}

/// udp_err.log debug line (6 tab-separated fields), 5s process-wide limit.
/// Opens/writes/closes per line like Go's `udpErrLogAt`. Returns whether the
/// line hit disk.
pub fn udp_err_log(client: &str, n: usize, od: &str, err: &str, first: &[u8]) -> bool {
    let ok = L_UDP_ERR_NS.with(|l| allow(l, &G_UDP_ERR_NS, now_nanos()));
    if !ok {
        return false;
    }
    let path = match sink() {
        Some(s) => s.udp_err.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        None => return false,
    };
    if path.is_empty() {
        return false;
    }
    let line = format!(
        "{}\t{}\tn={}\tod={}\terr={}\tfirst={}\n",
        now_unix(),
        client,
        n,
        od,
        err,
        hex_prefix16(first),
    );
    match OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .open(&path)
    {
        Ok(mut f) => f.write_all(line.as_bytes()).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
#[rustfmt::skip] // Brief mandates these three tests verbatim; skip reflow so `fmt --check` still passes.
mod tests {
    use super::{LogPaths, init, log_gate, log_gate_err, reset_rate_limits, udp_err_log};

    #[test]
    fn gate_log_line_is_exact() {
        let dir = std::env::temp_dir().join("wxdet-loggate-test");
        std::fs::create_dir_all(&dir).unwrap();
        let gp = dir.join("gate.log");
        let _ = std::fs::remove_file(&gp);
        init(&LogPaths { gate_log: gp.to_str().unwrap().into(), udp_err_log: dir.join("udp_err.log").to_str().unwrap().into() });
        reset_rate_limits();
        log_gate("tcp", "192.168.71.50:51000", "1.2.3.4:443", "pass", "tls_direct", &[0x16, 0x03, 0x01]);
        let s = std::fs::read_to_string(&gp).unwrap();
        assert!(s.contains("\"proto\":\"tcp\""));
        assert!(s.contains("\"src\":\"192.168.71.50:51000\""));
        assert!(s.contains("\"verdict\":\"pass\""));
        assert!(s.contains("\"reason\":\"tls_direct\""));
        assert!(s.contains("\"first\":\"160301\""));
        assert!(s.starts_with("{\"ts\":"));
    }

    #[test]
    fn err_line_has_detail_between_reason_and_first() {
        let dir = std::env::temp_dir().join("wxdet-loggate-test2");
        std::fs::create_dir_all(&dir).unwrap();
        let gp = dir.join("gate.log");
        let _ = std::fs::remove_file(&gp);
        init(&LogPaths { gate_log: gp.to_str().unwrap().into(), udp_err_log: dir.join("udp_err.log").to_str().unwrap().into() });
        reset_rate_limits();
        log_gate_err("udp", "1.1.1.1:1", "2.2.2.2:2", "udp_upgrade_proxy_fail", "socks udp assoc rep=4", &[]);
        let s = std::fs::read_to_string(&gp).unwrap();
        let i_reason = s.find("\"reason\"").unwrap();
        let i_detail = s.find("\"detail\"").unwrap();
        let i_first = s.find("\"first\"").unwrap();
        assert!(i_reason < i_detail && i_detail < i_first, "字段顺序必须 reason→detail→first");
        assert!(s.contains("\"verdict\":\"err\""));
    }

    #[test]
    fn udp_err_log_format_and_5s_rate_limit() {
        let dir = std::env::temp_dir().join("wxdet-udperr-test");
        std::fs::create_dir_all(&dir).unwrap();
        let up = dir.join("udp_err.log");
        let _ = std::fs::remove_file(&up);
        init(&LogPaths { gate_log: dir.join("gate.log").to_str().unwrap().into(), udp_err_log: up.to_str().unwrap().into() });
        reset_rate_limits();
        udp_err_log("192.168.71.50:51000", 42, "1.2.3.4:443", "no origdst cmsg", &[0xde, 0xad]);
        udp_err_log("192.168.71.50:51000", 42, "1.2.3.4:443", "no origdst cmsg", &[0xde, 0xad]);
        let s = std::fs::read_to_string(&up).unwrap();
        assert_eq!(s.lines().count(), 1, "5s 窗口内只许一行");
        // 固定 6 段：ts \t client \t n= \t od= \t err= \t first=
        let f: Vec<&str> = s.trim_end().split('\t').collect();
        assert_eq!(f.len(), 6);
        assert!(f[0].parse::<u64>().is_ok(), "第 1 段是 unix 秒");
        assert!(f[1].contains(':'), "第 2 段是 client ip:port");
        assert_eq!(f[2], "n=42");
        assert_eq!(f[3], "od=1.2.3.4:443");
        assert_eq!(f[4], "err=no origdst cmsg");
        assert_eq!(f[5], "first=dead");
    }
}
