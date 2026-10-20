//! tls_direct 直连面台账：聚合计数 + 增量刷盘，无流量时一行不写。
//!
//! Consumed by Task 15 (relay)/Task 16 (handle_conn)/Task 19 (signal flush + main wiring); wired in Task 19.

#[cfg(test)]
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Round-2 (R25): serializes Task-10's own file-output tests (the 4 events
/// tests + this ledger test + the 2 classify stats tests) against each other.
/// The events/stats handles are process-global: parallel tests re-pointing the
/// handle interleave init→write across tests by timing luck. Every Task-10
/// file-output test holds this guard for its whole body. Ordering vs the cell
/// locks is fixed (this lock outermost; production code never takes it), so no
/// deadlock; poisoning is recovered via `into_inner`.
/// NOTE: Task-8's stats test predates this lock and does not honor it — the
/// residual cross-task hazard is analyzed in the round-2 report.
///
/// R38: this used to be a process-local `static Mutex<()>`; the golden
/// integration binary (`tests/golden_logs.rs`, which `#[path]`-includes this
/// module) runs as a SEPARATE test process, so a per-process Mutex did not
/// serialize the two binaries against each other. It is now an flock-backed
/// cross-process lock: `lock()` takes an in-process `Mutex` (serializes
/// threads) and then `flock(LOCK_EX)` on a lock file under
/// `std::env::temp_dir()` (serializes processes; flock is the cross-process
/// mechanism by construction — no multi-process test needed, spawning test
/// processes from a test is flaky and slow). The temp dir respects per-worktree
/// `TMPDIR`, which is exactly the worktree isolation we want. The guard's
/// `Drop` releases the flock (explicit `LOCK_UN`, plus close releases it).
#[cfg(test)]
pub(crate) static FILE_TEST_LOCK: FileTestLock = FileTestLock::new();

/// Test-only cross-process serializing lock (R38). See `FILE_TEST_LOCK`.
#[cfg(test)]
pub(crate) struct FileTestLock {
    fallback: Mutex<()>,
}

/// Guard returned by [`FileTestLock::lock`]. Holds both the in-process mutex
/// guard and the open lock-file description; dropping it releases both.
#[cfg(test)]
pub(crate) struct FileTestLockGuard<'a> {
    _file: Option<std::fs::File>,
    _inner: std::sync::MutexGuard<'a, ()>,
}

/// Poison carrier mirroring `std::sync::PoisonError`: lets existing call sites
/// keep their `.lock().unwrap_or_else(|e| e.into_inner())` shape unchanged.
#[cfg(test)]
pub(crate) struct FileTestLockPoison<'a>(FileTestLockGuard<'a>);

#[cfg(test)]
impl<'a> FileTestLockPoison<'a> {
    pub fn into_inner(self) -> FileTestLockGuard<'a> {
        self.0
    }
}

#[cfg(test)]
impl Drop for FileTestLockGuard<'_> {
    fn drop(&mut self) {
        if let Some(f) = self._file.as_ref() {
            use std::os::unix::io::AsRawFd;
            // Explicit unlock; the subsequent close would release it anyway.
            unsafe {
                libc::flock(f.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

#[cfg(test)]
impl FileTestLock {
    const fn new() -> Self {
        Self {
            fallback: Mutex::new(()),
        }
    }

    /// Blocking acquire: in-process mutex first (fixed order everywhere, so no
    /// lock-order inversion), then cross-process `flock(LOCK_EX)`.
    pub fn lock(&self) -> Result<FileTestLockGuard<'_>, FileTestLockPoison<'_>> {
        let (inner, poisoned) = match self.fallback.lock() {
            Ok(g) => (g, false),
            Err(e) => (e.into_inner(), true),
        };
        let guard = FileTestLockGuard {
            _file: Self::flock_file(),
            _inner: inner,
        };
        if poisoned {
            Err(FileTestLockPoison(guard))
        } else {
            Ok(guard)
        }
    }

    /// Open (creating) the lock file and take `LOCK_EX`, blocking, retrying on
    /// EINTR. Returns `None` — with a one-line warning, never a panic — when
    /// the lock file cannot be created (e.g. read-only TMPDIR); the caller
    /// then serializes threads via the in-process mutex only.
    fn flock_file() -> Option<std::fs::File> {
        use std::os::unix::io::AsRawFd;
        let path = std::env::temp_dir().join("wxdet-gate-file-test.lock");
        // 内容无关的空锁文件：create（write+create+truncate）语义恰好满足需求，
        // 也避开 clippy::suspicious_open_options；truncate 不影响已持有的 flock。
        let file = match std::fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "warning: FILE_TEST_LOCK flock file unavailable ({}: {e}); using in-process mutex only",
                    path.display()
                );
                return None;
            }
        };
        loop {
            let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if r == 0 {
                return Some(file);
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("warning: FILE_TEST_LOCK flock failed ({err}); using in-process mutex only");
            return None;
        }
    }
}

/// 直连面（reason=tls_direct）台账：这类流不进事件流，但占出网 TCP 约七成。
/// 落账方式：聚合计数 + 增量刷盘（4 行/分钟），无流量时一行不写。
static LEDGER_CLOSE: AtomicU64 = AtomicU64::new(0); // 完成的直连流数
static LEDGER_UP_B: AtomicU64 = AtomicU64::new(0); // client→server 字节
static LEDGER_DOWN_B: AtomicU64 = AtomicU64::new(0); // server→client 字节
static LEDGER_DUR_MS: AtomicU64 = AtomicU64::new(0); // 时长合计（配合 close 算均值）

pub fn ledger_add(dur_ms: u64, up_b: u64, down_b: u64) {
    LEDGER_CLOSE.fetch_add(1, Ordering::Relaxed);
    LEDGER_UP_B.fetch_add(up_b, Ordering::Relaxed);
    LEDGER_DOWN_B.fetch_add(down_b, Ordering::Relaxed);
    LEDGER_DUR_MS.fetch_add(dur_ms, Ordering::Relaxed);
}

/// 把累计增量写进 stats.tsv 并清零；无流量时一行都不写（保持文件干净）。
/// 固定顺序：close → up_B → down_B → dur_ms。
pub fn ledger_flush() {
    let c = LEDGER_CLOSE.swap(0, Ordering::Relaxed);
    if c == 0 {
        return;
    }
    crate::stats::write_stat("gate_tlsdirect_close", c);
    crate::stats::write_stat(
        "gate_tlsdirect_up_B",
        LEDGER_UP_B.swap(0, Ordering::Relaxed),
    );
    crate::stats::write_stat(
        "gate_tlsdirect_down_B",
        LEDGER_DOWN_B.swap(0, Ordering::Relaxed),
    );
    crate::stats::write_stat(
        "gate_tlsdirect_dur_ms",
        LEDGER_DUR_MS.swap(0, Ordering::Relaxed),
    );
}

/// 测试用：四个原子计数归零。
#[cfg(test)]
pub fn reset() {
    LEDGER_CLOSE.store(0, Ordering::Relaxed);
    LEDGER_UP_B.store(0, Ordering::Relaxed);
    LEDGER_DOWN_B.store(0, Ordering::Relaxed);
    LEDGER_DUR_MS.store(0, Ordering::Relaxed);
}

pub fn start_ledger_flush(period: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            ledger_flush();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_flush_writes_nothing_when_empty() {
        let _serial = crate::ledger::FILE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join("wxdet-ledger-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("stats.tsv");
        let _ = std::fs::remove_file(&p);
        crate::stats::init(p.to_str().unwrap());
        reset();
        ledger_flush();
        assert!(!p.exists() || std::fs::read_to_string(&p).unwrap().is_empty());
        ledger_add(1000, 100, 200);
        ledger_add(1000, 300, 1200);
        ledger_flush();
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains("gate_tlsdirect_close\t2"));
        assert!(s.contains("gate_tlsdirect_up_B\t400"));
        assert!(s.contains("gate_tlsdirect_down_B\t1400"));
        assert!(s.contains("gate_tlsdirect_dur_ms\t2000"));
        // 固定顺序：close → up_B → down_B → dur_ms。
        let (mut last, mut ordered) = (0usize, true);
        for k in [
            "gate_tlsdirect_close",
            "gate_tlsdirect_up_B",
            "gate_tlsdirect_down_B",
            "gate_tlsdirect_dur_ms",
        ] {
            match s.find(k) {
                Some(i) if i >= last => last = i,
                _ => ordered = false,
            }
        }
        assert!(ordered, "台账四行必须按固定顺序落盘:\n{s}");
        ledger_flush();
        let s2 = std::fs::read_to_string(&p).unwrap();
        assert_eq!(s2.len(), s.len(), "二次 flush 不得重复写");
    }

    #[test]
    fn file_test_lock_blocks_second_thread_until_drop() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::time::{Duration, Instant};
        let entered = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let entered2 = entered.clone();
        let done2 = done.clone();
        let g = crate::ledger::FILE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let h = std::thread::spawn(move || {
            let _g2 = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            entered2.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            done2.store(true, Ordering::SeqCst);
        });
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !entered.load(Ordering::SeqCst),
            "第二个线程在锁未释放前不得进入"
        );
        drop(g);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "释放后第二个线程始终未能获得锁");
            std::thread::sleep(Duration::from_millis(10));
        }
        h.join().unwrap();
    }
}
