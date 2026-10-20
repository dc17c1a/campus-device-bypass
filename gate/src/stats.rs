// Consumed by Task 9 (gate.log shares io_lock), Task 10 (classify stats wrapper),
// Task 14/15 (TCP call sites), Task 17/18 (UDP call sites, incl. gate_udp_buf_trunc).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// All stats.tsv key names, copied verbatim from design spec §6.1.
///
/// NOTE on the count (R17): §6.1 originally said "32 个键" but actually
/// enumerates 36 items. Of those, `gate_rsn_<reason>` is a family marker
/// (runtime keys are `gate_rsn_<tcp|udp reason>`, never the literal marker),
/// so there are 35 fixed keys. The four `gate_tlsdirect_*` keys are written
/// via `write_stat` by the later ledger task's flush path (`ledger.go`
/// `writeStat64`); they belong in this registry so later golden/ported tests
/// can assert the complete set. `write_stat` itself accepts any key — later
/// tasks (e.g. `gate_udp_buf_trunc` in Task 18) can emit keys not listed here.
#[cfg(test)]
pub const KEYS: [&str; 36] = [
    "gate_origdst_err",
    "gate_tcp_local_drop",
    "gate_conn",
    "gate_pass",
    "gate_proxy",
    "gate_rsn_<reason>",
    "gate_pass_fail",
    "gate_proxy_fail",
    "gate_dial_err",
    "gate_write_err",
    "gate_tls_strict_fail",
    "gate_range_strong",
    "gate_range_weak",
    "gate_dl_reload",
    "gate_events_err",
    "gate_tlsdirect_close",
    "gate_tlsdirect_up_B",
    "gate_tlsdirect_down_B",
    "gate_tlsdirect_dur_ms",
    "gate_udp_recv_err",
    "gate_udp_origdst_invalid",
    "gate_udp_local_drop",
    "gate_udp_table_full",
    "gate_udp_write_err",
    "gate_udp_pending_drop",
    "gate_udp_assoc",
    "gate_proxy_udp",
    "gate_pass_udp",
    "gate_proxy_udp_fail",
    "gate_udp_dial_err",
    "gate_udp_upgrade",
    "gate_udp_upgrade_fail",
    "gate_udp_expire",
    "gate_udp_decap_err",
    "gate_udp_spoof_fail",
    "gate_udp_spoof_write_fail",
];

/// Go's `statFile` + `ioMu` in one: the single global lock guarding stats.tsv.
/// `io_lock()` exposes this same mutex so Task 9's `log_gate` can share Go's
/// `ioMu` exclusion around gate.log writes.
static STAT_FILE: OnceLock<Mutex<Option<File>>> = OnceLock::new();

fn cell() -> &'static Mutex<Option<File>> {
    STAT_FILE.get_or_init(|| Mutex::new(None))
}

fn lock(m: &'static Mutex<Option<File>>) -> std::sync::MutexGuard<'static, Option<File>> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The single global I/O lock shared with gate.log (Go's `ioMu`).
/// Hold the returned guard across gate.log writes for mutual exclusion
/// with stats.tsv writes.
pub fn io_lock() -> &'static Mutex<Option<File>> {
    cell()
}

/// Open stats.tsv with `O_APPEND|O_CREATE|O_WRONLY 0644` (Go `os.OpenFile`
/// parity). Never creates parent directories. On failure only warns
/// (stderr) and leaves the handle empty — every later `write_stat` is then
/// a silent no-op, exactly like Go's `nil`-file early return.
/// Re-init replaces the handle (later tasks re-point per test tag).
pub fn init(path: &str) {
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
            eprintln!("wxdet-gate: stats init {path} failed: {e}; stats disabled");
            *lock(cell()) = None;
        }
    }
}

/// One delta line `{unix}\t{key}\t{n}\n` (Go `writeStat` format `%d\t%s\t%d\n`).
/// Silent no-op when the handle is empty (never `init`ed or `init` failed).
pub fn write_stat(key: &str, n: u64) {
    write_stat_tt(key, n, SystemTime::now());
}

/// `write_stat` with injectable timestamp (for tests).
pub fn write_stat_tt(key: &str, n: u64, t: SystemTime) {
    let unix = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut slot = lock(cell());
    if let Some(f) = slot.as_mut() {
        let line = format!("{unix}\t{key}\t{n}\n");
        let _ = f.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{KEYS, init, write_stat};

    #[test]
    fn stat_line_format_is_tsv_with_delta_value() {
        let dir = std::env::temp_dir().join("wxdet-stat-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("stats.tsv");
        let _ = std::fs::remove_file(&p);
        init(p.to_str().unwrap());
        write_stat("gate_udp_expire", 3);
        let s = std::fs::read_to_string(&p).unwrap();
        let f: Vec<&str> = s.trim_end().split('\t').collect();
        assert_eq!(f.len(), 3);
        assert!(f[0].parse::<u64>().is_ok());
        assert_eq!(f[1], "gate_udp_expire");
        assert_eq!(f[2], "3");
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn all_36_keys_present_and_unique() {
        let mut k = KEYS.to_vec();
        assert_eq!(k.len(), 36);
        let n = k.len();
        k.sort_unstable();
        k.dedup();
        assert_eq!(k.len(), n, "键名有重复");
    }
}
