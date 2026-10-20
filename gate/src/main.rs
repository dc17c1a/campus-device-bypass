mod bufpool;
mod classify;
mod config;
mod events;
mod http;
mod ledger;
mod lists;
mod log_gate;
mod origdst;
mod quote;
mod reason;
mod socks5;
mod stats;
mod tcp;
mod testutil;
mod udp;

use std::sync::Arc;
use std::time::Duration;

/// 最终接线（Task 24 TCP 薄片 + Task 19：UDP 接入与信号处理）。
///
/// 启动顺序与 Go `main.go main` 一致：
/// `load_all`（日志 `dl lists: ...`）→ `stats::init` → `log_gate::init` →
/// `events::init` → TCP listen（失败 `listen %s: %v` + 退出码 1）。
/// 监听成功日志 `wxdet-gate listening on %s (proxy=%s pass=%s peek=%s)`；
/// accept 失败且非 closed → `accept: %v` + sleep 50ms 重试；
/// 每连接 `tokio::spawn(handle_conn(...))`；另起 `lists::watch`、
/// `ledger::start_ledger_flush(60s)`，以及 `WD_UDP_LISTEN` 非空非 `off` 时的
/// `udp::serve_udp`；SIGTERM/SIGINT → `ledger::ledger_flush()` 后退出
/// （唯一的 Go 行为改良：procd stop 不丢最后一分钟台账）。
/// 启动时自抬 NOFILE 软上限（2026-10-20 EMFILE 现场：soft 1024/hard 4096，
/// 游戏突发十几路并行即打满）。目标 65535，hard 不足则取 hard 上限；
/// 失败只 warn 不退出（init 脚本的 `limits nofile` 负责抬 hard）。
fn bump_nofile() {
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        let target: libc::rlim_t = 65535;
        let hard = lim.rlim_max;
        let want = if hard != libc::RLIM_INFINITY && hard < target {
            hard
        } else {
            target
        };
        if lim.rlim_cur < want {
            lim.rlim_cur = want;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                eprintln!(
                    "warn: setrlimit NOFILE to {want} failed: {}",
                    std::io::Error::last_os_error()
                );
            } else {
                eprintln!("bumped NOFILE soft to {want} (hard {hard})");
            }
        }
    }
}

fn main() {
    bump_nofile();
    let cfg = config::load();
    let mut marks: lists::Marks = std::collections::HashMap::new();
    let snapshot = lists::load_all(&cfg, &mut marks);
    eprintln!(
        "dl lists: dom={} ua={} ext={} query={}",
        snapshot.dom.len(),
        snapshot.ua.len(),
        snapshot.ext.len(),
        snapshot.query.len()
    );
    stats::init(&cfg.stats_path);
    log_gate::init(&log_gate::LogPaths {
        gate_log: cfg.gate_log_path.clone(),
        udp_err_log: cfg.udp_err_log_path.clone(),
    });
    events::init(&cfg.events_path);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.worker_threads)
        .enable_all()
        .build()
        .expect("tokio runtime build");
    rt.block_on(async_main(
        Arc::new(cfg),
        Arc::new(tokio::sync::RwLock::new(snapshot)),
        marks,
    ));
}

async fn async_main(
    cfg: Arc<config::Config>,
    shared: Arc<tokio::sync::RwLock<lists::DlLists>>,
    marks: lists::Marks,
) {
    let ln = match tokio::net::TcpListener::bind(cfg.listen_addr.as_str()).await {
        Ok(ln) => ln,
        Err(e) => {
            eprintln!("listen {}: {e}", cfg.listen_addr);
            std::process::exit(1);
        }
    };
    eprintln!(
        "wxdet-gate listening on {} (proxy={} pass={} peek={}ms)",
        cfg.listen_addr, cfg.proxy_socks, cfg.pass_socks, cfg.peek_ms
    );
    {
        let cfg_w = Arc::clone(&cfg);
        let shared_w = Arc::clone(&shared);
        tokio::spawn(async move {
            lists::watch(&cfg_w, shared_w, marks).await;
        });
    }
    ledger::start_ledger_flush(Duration::from_secs(60));
    if !cfg.udp_listen_addr.is_empty() && cfg.udp_listen_addr != "off" {
        let cfg_u = Arc::clone(&cfg);
        let shared_u = Arc::clone(&shared);
        tokio::spawn(async move {
            udp::serve_udp(cfg_u, shared_u).await;
        });
    }
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("sigterm handler");
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("sigint handler");
    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                ledger::ledger_flush();
                return;
            }
            _ = sigint.recv() => {
                ledger::ledger_flush();
                return;
            }
            res = ln.accept() => match res {
                Ok((raw, _)) => {
                    let cfg_c = Arc::clone(&cfg);
                    let shared_c = Arc::clone(&shared);
                    tokio::spawn(async move {
                        tcp::handle_conn(raw, cfg_c, shared_c).await;
                    });
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("closed") {
                        return;
                    }
                    // EMFILE（fd 耗尽）时 50ms 会空转刷屏：退避到 1s，给 idle 收尾让出 fd。
                    let emfile = msg.contains("Too many open files")
                        || msg.contains("os error 24");
                    eprintln!("accept: {e}");
                    let backoff = if emfile { 1000 } else { 50 };
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
            },
        }
    }
}

#[cfg(test)]
mod main_tests {
    use std::time::Duration;

    #[tokio::test]
    async fn sigterm_flushes_ledger_before_exit() {
        // 起进程 → ledger_add → SIGTERM → 退出后 stats.tsv 必须含 gate_tlsdirect_close
        let tag = "main-sigterm";
        // R26：串行锁只包"清文件→重定向/初装"段（与 udp 异步用例同口径），
        // 不跨 await（clippy await_holding_lock）；串行门内无并发文件竞争。
        let (cfg, shared, stats_path, port, marks) = {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut cfg = crate::testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
            // 空闲端口：先占后放，async_main 内再 bind（串行门内无并发绑定，竞态可忽略）。
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("probe port")
                .local_addr()
                .expect("probe addr")
                .port();
            cfg.listen_addr = format!("127.0.0.1:{port}");
            cfg.udp_listen_addr = "off".to_string();
            cfg.kw_poll_sec = 0;
            crate::ledger::reset();
            let stats_path = std::path::PathBuf::from(cfg.stats_path.clone());
            // 复制 main() 的初始化段（async_main 只含 listen 之后的部分）。
            crate::stats::init(&cfg.stats_path);
            crate::log_gate::init(&crate::log_gate::LogPaths {
                gate_log: cfg.gate_log_path.clone(),
                udp_err_log: cfg.udp_err_log_path.clone(),
            });
            crate::events::init(&cfg.events_path);
            let mut marks = std::collections::HashMap::new();
            let snapshot = crate::lists::load_all(&cfg, &mut marks);
            let shared = std::sync::Arc::new(tokio::sync::RwLock::new(snapshot));
            (std::sync::Arc::new(cfg), shared, stats_path, port, marks)
        };
        // 起进程：跑真实 async_main（TCP 接线 + 信号臂 + UDP-off 跳过）。
        let h = tokio::spawn(super::async_main(cfg, shared, marks));
        crate::testutil::wait_until(|| {
            std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok()
        })
        .await;
        assert!(
            std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok(),
            "gate 未在 2s 内监听"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        crate::ledger::ledger_add(1200, 300, 900);
        // 真 SIGTERM 发给自己：信号臂必须捕获 → flush → 返回（无信号臂则默认杀进程）。
        let rc = unsafe { libc::kill(std::process::id() as i32, libc::SIGTERM) };
        assert_eq!(rc, 0, "kill SIGTERM 失败");
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .expect("SIGTERM 后 5s 内必须退出")
            .expect("async_main join");
        let s = std::fs::read_to_string(&stats_path).unwrap_or_default();
        assert!(
            s.contains("gate_tlsdirect_close"),
            "退出后 stats.tsv 必须含台账行：{s:?}"
        );
    }
}
