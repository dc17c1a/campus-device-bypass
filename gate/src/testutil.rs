// src/testutil.rs
#![cfg(test)]
// 被 Task 11（lists 热加载测试：config_for_test/out_dir/filetime_touch）/
// Task 12（socks5 测试：spawn_fake_socks/FakeSocksHits）/
// Task 14–16（TCP 测试：config_with_socks/reset_stats/stat_value/stat_lines/reset_events/read_events/duplex_pair）/
// Task 17–18（UDP 测试：reset_logs/read_gate_log）消费；Task 19 清扫时评估是否保留。
use crate::config::Config;

/// 返回一份不读环境的 Config，路径指向 temp_dir 下的独立子目录，便于测试注入。
pub fn config_for_test(tag: &str) -> Config {
    let dir = out_dir(tag);
    // 目录已存在则先清空其中的 4 个输出文件，保证用例间不串。
    for f in ["stats.tsv", "events.jsonl", "gate.log", "udp_err.log"] {
        let _ = std::fs::remove_file(dir.join(f));
    }
    Config {
        listen_addr: "0.0.0.0:12347".into(),
        udp_listen_addr: "0.0.0.0:12348".into(),
        pass_socks: "127.0.0.1:18081".into(),
        proxy_socks: "127.0.0.1:10811".into(),
        gate_log_path: dir.join("gate.log").to_str().unwrap().into(),
        stats_path: dir.join("stats.tsv").to_str().unwrap().into(),
        events_path: dir.join("events.jsonl").to_str().unwrap().into(),
        udp_err_log_path: dir.join("udp_err.log").to_str().unwrap().into(),
        peek_ms: 400,
        peek_ms80: 80,
        kw_poll_sec: 30,
        dl_dom_file: dir.join("dl-domains.txt").to_str().unwrap().into(),
        dl_ua_file: dir.join("dl-ua.txt").to_str().unwrap().into(),
        dl_ext_file: dir.join("dl-ext.txt").to_str().unwrap().into(),
        dl_query_file: dir.join("dl-query.txt").to_str().unwrap().into(),
        udp_fixed_dst: String::new(),
        udp_buf_kb: 2,
        tcp_buf_kb: 8,
        worker_threads: 4,
        tcp_idle_sec: 300,
    }
}

/// 同上但可指定两个 SOCKS 上游地址。
pub fn config_with_socks(tag: &str, pass: &str, proxy: &str) -> Config {
    let mut c = config_for_test(tag);
    c.pass_socks = pass.into();
    c.proxy_socks = proxy.into();
    c
}

/// 把 stats.tsv 指向 tag 对应的新文件并重新 init（清空旧内容）。返回该 tag 的输出目录。
pub fn reset_stats(tag: &str) -> std::path::PathBuf {
    let dir = out_dir(tag);
    let p = dir.join("stats.tsv");
    let _ = std::fs::remove_file(&p);
    crate::stats::init(p.to_str().unwrap());
    dir
}

/// 把 events.jsonl 指向 tag 对应的新文件并重新 init（清空旧内容）。返回该 tag 的输出目录。
pub fn reset_events(tag: &str) -> std::path::PathBuf {
    let dir = out_dir(tag);
    let p = dir.join("events.jsonl");
    let _ = std::fs::remove_file(&p);
    crate::events::init(p.to_str().unwrap());
    dir
}

/// 把 gate.log 与 udp_err.log 指向 tag 对应的新文件并重新 init，同时 reset_rate_limits()。
/// 返回该 tag 的输出目录。
pub fn reset_logs(tag: &str) -> std::path::PathBuf {
    let dir = out_dir(tag);
    let gate = dir.join("gate.log");
    let udp_err = dir.join("udp_err.log");
    let _ = std::fs::remove_file(&gate);
    let _ = std::fs::remove_file(&udp_err);
    crate::log_gate::init(&crate::log_gate::LogPaths {
        gate_log: gate.to_str().unwrap().into(),
        udp_err_log: udp_err.to_str().unwrap().into(),
    });
    crate::log_gate::reset_rate_limits();
    dir
}

/// tag 对应的输出目录（`temp_dir()/wxdet-test-<tag>/`），不存在则创建。
pub fn out_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wxdet-test-{tag}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 读 stats.tsv 中某键的**总和**（增量行求和），无则 0。
pub fn stat_value(tag: &str, key: &str) -> u64 {
    let p = out_dir(tag).join("stats.tsv");
    let s = std::fs::read_to_string(&p).unwrap_or_default();
    s.lines()
        .filter_map(|ln| {
            let mut f = ln.split('\t');
            let _ts = f.next()?;
            let k = f.next()?;
            let n: u64 = f.next()?.parse().ok()?;
            if k == key { Some(n) } else { None }
        })
        .sum()
}

/// 读 stats.tsv 中某键出现过的**行数**（用于断言"一行都不写"）。
pub fn stat_lines(tag: &str, key: &str) -> usize {
    let p = out_dir(tag).join("stats.tsv");
    let s = std::fs::read_to_string(&p).unwrap_or_default();
    s.lines()
        .filter(|ln| {
            let mut f = ln.split('\t');
            f.next();
            f.next() == Some(key)
        })
        .count()
}

/// 读 events.jsonl 全文（tag 对应的文件），无文件则空串。
pub fn read_events(tag: &str) -> String {
    std::fs::read_to_string(out_dir(tag).join("events.jsonl")).unwrap_or_default()
}

/// 读 gate.log 全文，无文件则空串。
pub fn read_gate_log(tag: &str) -> String {
    std::fs::read_to_string(out_dir(tag).join("gate.log")).unwrap_or_default()
}

/// 返回一对已互连的 TCP 流：(a, b)。需要"客户端 ↔ 中继 ↔ 服务端"时起两对：
/// `let (client, rel_a) = duplex_pair().await; let (rel_b, server) = duplex_pair().await;`
pub async fn duplex_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let (dial, acc) = tokio::join!(tokio::net::TcpStream::connect(addr), ln.accept());
    (dial.unwrap(), acc.unwrap().0)
}

/// 假 SOCKS5 上游被拨打的次数（用于钉死"绝不回退第二条腿"）。
#[derive(Default)]
pub struct FakeSocksHits {
    pub pass: std::sync::atomic::AtomicUsize,
    pub proxy: std::sync::atomic::AtomicUsize,
}

/// 起两个 SOCKS5 假上游。`pass_rep` 是 pass 腿 CONNECT 回复的 REP 字节（0=成功）；
/// `proxy_ok=false` 时 proxy 腿的监听直接关闭以模拟不可达。
/// 返回 `(pass_addr, proxy_addr, hits)`，地址形如 `"127.0.0.1:PORT"`。
/// 假上游必须实现：CONNECT 握手、UDP ASSOCIATE（回 ATYP=1 relay 地址）。
pub async fn spawn_fake_socks(
    pass_rep: u8,
    proxy_ok: bool,
) -> (String, String, std::sync::Arc<FakeSocksHits>) {
    use std::sync::atomic::Ordering;
    let hits = std::sync::Arc::new(FakeSocksHits::default());

    // pass 腿：完整握手。CONNECT 成功（rep==0）后回显隧道字节，覆盖成功路径的用法。
    let pass_ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pass_addr = pass_ln.local_addr().unwrap().to_string();
    {
        let hits = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = pass_ln.accept().await else {
                    return;
                };
                let hits = hits.clone();
                tokio::spawn(async move {
                    serve_fake_socks_conn(s, &hits.pass, pass_rep).await;
                });
            }
        });
    }

    // proxy 腿：proxy_ok=false 时监听直接关闭，拨号即拒接，模拟不可达。
    let proxy_addr = if proxy_ok {
        let proxy_ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = proxy_ln.local_addr().unwrap().to_string();
        let hits = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = proxy_ln.accept().await else {
                    return;
                };
                let hits = hits.clone();
                tokio::spawn(async move {
                    // proxy 腿 CONNECT 恒成功（rep=0）。
                    serve_fake_socks_conn(s, &hits.proxy, 0).await;
                });
            }
        });
        a
    } else {
        // 占一个端口后立即释放：返回的地址上无监听，拨号得 connection refused。
        let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = tmp.local_addr().unwrap().to_string();
        drop(tmp);
        a
    };
    // 让 accept 循环先跑起来，避免首个拨号竞态。
    tokio::task::yield_now().await;
    let _ = Ordering::SeqCst;
    (pass_addr, proxy_addr, hits)
}

/// 单条假上游连接：问候 + 请求。CONNECT 按 `rep` 回复（同时计 hits）；
/// UDP ASSOCIATE 回 ATYP=1 的 127.0.0.1 relay 地址后保持连接（排空对端）。
async fn serve_fake_socks_conn(
    s: tokio::net::TcpStream,
    hits: &std::sync::atomic::AtomicUsize,
    rep: u8,
) {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut r, mut w) = s.into_split();
    // 问候：VER + NMETHODS + METHODS，固定回 [0x05, 0x00]（无认证）。
    let mut g = [0u8; 2];
    if r.read_exact(&mut g).await.is_err() {
        return;
    }
    let n = g[1] as usize;
    let mut methods = vec![0u8; n];
    if r.read_exact(&mut methods).await.is_err() {
        return;
    }
    if w.write_all(&[0x05, 0x00]).await.is_err() {
        return;
    }
    // 请求：VER CMD RSV ATYP ADDR PORT。
    let mut h = [0u8; 4];
    if r.read_exact(&mut h).await.is_err() {
        return;
    }
    let rest = match h[3] {
        0x01 => 4 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            if r.read_exact(&mut l).await.is_err() {
                return;
            }
            // 域名长度字节已消费，剩下 域名 + PORT。
            l[0] as usize + 2
        }
        0x04 => 16 + 2,
        _ => return,
    };
    let mut tail = vec![0u8; rest];
    if r.read_exact(&mut tail).await.is_err() {
        return;
    }
    hits.fetch_add(1, Ordering::SeqCst);
    if h[1] == 0x03 {
        // UDP ASSOCIATE：回 ATYP=1 relay 地址（本机随机 UDP 口），后排空保持。
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p = udp.local_addr().unwrap().port();
        let _ = w
            .write_all(&[
                0x05,
                0x00,
                0x00,
                0x01,
                127,
                0,
                0,
                1,
                (p >> 8) as u8,
                p as u8,
            ])
            .await;
        let mut buf = [0u8; 1500];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }
    // CONNECT：按参数 REP 回复；成功则回显隧道。
    let _ = w
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await;
    if rep != 0 {
        return;
    }
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if w.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// 起一个延迟回复的假 proxy 上游，用于制造 connecting 窗口。
pub async fn spawn_fake_socks_delayed(
    rep: u8,
    delay: std::time::Duration,
) -> (String, String, std::sync::Arc<FakeSocksHits>) {
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let hits = std::sync::Arc::new(FakeSocksHits::default());

    // pass 腿：与 spawn_fake_socks 同语义（rep 控制 CONNECT 回复）。
    let pass_ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pass_addr = pass_ln.local_addr().unwrap().to_string();
    {
        let hits = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = pass_ln.accept().await else {
                    return;
                };
                let hits = hits.clone();
                tokio::spawn(async move {
                    serve_fake_socks_conn(s, &hits.pass, rep).await;
                });
            }
        });
    }

    // proxy 腿：完整 ASSOCIATE 握手后延迟 `delay` 再回成功，制造 connecting 窗口。
    let proxy_ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_ln.local_addr().unwrap().to_string();
    {
        let hits = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = proxy_ln.accept().await else {
                    return;
                };
                let hits = hits.clone();
                tokio::spawn(async move {
                    let (mut r, mut w) = s.into_split();
                    let mut g = [0u8; 2];
                    if r.read_exact(&mut g).await.is_err() {
                        return;
                    }
                    let n = g[1] as usize;
                    let mut methods = vec![0u8; n];
                    if r.read_exact(&mut methods).await.is_err() {
                        return;
                    }
                    if w.write_all(&[0x05, 0x00]).await.is_err() {
                        return;
                    }
                    // ASSOCIATE 请求固定 10B（VER CMD RSV ATYP + 6B 全零地址）。
                    let mut h = [0u8; 4];
                    if r.read_exact(&mut h).await.is_err() {
                        return;
                    }
                    if h[1] != 0x03 {
                        return;
                    }
                    let mut tail = [0u8; 6];
                    if r.read_exact(&mut tail).await.is_err() {
                        return;
                    }
                    hits.proxy.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let p = udp.local_addr().unwrap().port();
                    let _ = w
                        .write_all(&[
                            0x05,
                            0x00,
                            0x00,
                            0x01,
                            127,
                            0,
                            0,
                            1,
                            (p >> 8) as u8,
                            p as u8,
                        ])
                        .await;
                    // udp 由本 task 持有（对端中继口存活，冲刷包有处可去）；
                    // 保持 TCP 控制连接，排空对端。
                    let mut buf = [0u8; 1500];
                    loop {
                        match r.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });
    }
    tokio::task::yield_now().await;
    let _ = Ordering::SeqCst;
    (pass_addr, proxy_addr, hits)
}

/// 一根不绑定真实现的 UDP "监听口"，供 assoc 持有。
pub async fn fake_udp_srv() -> std::sync::Arc<tokio::net::UdpSocket> {
    std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap())
}

/// 轮询等待条件成立（上限 2s），用于等后台建链完成。
pub async fn wait_until<F: FnMut() -> bool>(mut f: F) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Round-2 (R22c 收尾)：reset_logs 必须把 gate.log 重定向到 tag 目录并可读回。
    // 结构确定性：同线程调用（init 写调用线程的 TLS sink，log_gate 读同一
    // sink），且 log_gate 是非限速路径，无跨线程限速器干扰，无需串行锁。
    #[test]
    fn reset_logs_wires_gate_log_round_trip() {
        let tag = "logs_wire";
        let dir = reset_logs(tag);
        assert_eq!(dir, out_dir(tag));
        crate::log_gate::log_gate(
            "tcp",
            "1.1.1.1:1",
            "2.2.2.2:2",
            "pass",
            "tls_direct",
            &[0x16, 0x03, 0x01],
        );
        let s = read_gate_log(tag);
        assert!(s.contains("\"proto\":\"tcp\""), "gate.log 回读: {s}");
        assert!(s.contains("\"src\":\"1.1.1.1:1\""), "gate.log 回读: {s}");
        assert!(s.contains("\"verdict\":\"pass\""), "gate.log 回读: {s}");
        assert!(
            s.contains("\"reason\":\"tls_direct\""),
            "gate.log 回读: {s}"
        );
        assert!(s.contains("\"first\":\"160301\""), "gate.log 回读: {s}");
        assert!(s.starts_with("{\"ts\":"), "gate.log 回读: {s}");
    }
}
