//! Task 19 门集成测试：真实二进制子进程级断言。
//!
//! `CARGO_BIN_EXE_wxdet-gate` 由 cargo 在编译集成测试时注入，并保证二进制
//! 已按当前源码新鲜构建（杜绝单元测试里 `current_exe` 推导陈旧二进制的坑）。

use std::time::Duration;

/// 等子进程退出（上限 `limit`），超时则杀掉并失败。
fn wait_child(child: &mut std::process::Child, limit: Duration) -> std::process::ExitStatus {
    let start = std::time::Instant::now();
    loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            return st;
        }
        assert!(start.elapsed() < limit, "子进程未在 {limit:?} 内退出");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn listen_failure_message_is_verbatim() {
    // 占用端口后启动 → stderr 含 "listen %s: %v" 且退出码 1
    let holder = std::net::TcpListener::bind("127.0.0.1:0").expect("occupy port");
    let addr = holder.local_addr().expect("local addr");
    let bin = env!("CARGO_BIN_EXE_wxdet-gate");
    let dir = std::env::temp_dir().join(format!("wxdet-main-listen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut child = std::process::Command::new(bin)
        .env("WD_LISTEN", addr.to_string())
        .env("WD_UDP_LISTEN", "off")
        .env("WD_STATS", dir.join("stats.tsv"))
        .env("WD_LOG", dir.join("gate.log"))
        .env("WD_EVENTS", dir.join("events.jsonl"))
        .env("WD_UDP_ERR_LOG", dir.join("udp_err.log"))
        .env("WD_DL_DOM_FILE", dir.join("no-dom.txt"))
        .env("WD_DL_UA_FILE", dir.join("no-ua.txt"))
        .env("WD_DL_EXT_FILE", dir.join("no-ext.txt"))
        .env("WD_DL_QUERY_FILE", dir.join("no-query.txt"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn gate binary");
    let status = wait_child(&mut child, Duration::from_secs(10));
    let out = child.wait_with_output().expect("collect output");
    assert_eq!(status.code(), Some(1), "listen 失败必须退出码 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!("listen {addr}:")),
        "stderr 必须含 `listen %s: %v`（实得：{err})"
    );
}
