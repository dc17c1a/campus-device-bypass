//! Task 21：内存归因 A/B 测量线束（本机 x86_64 环回，归因专用）。
//!
//! 口径声明：本文件的数字**只用于**「语言贡献 vs 设计贡献」的分离，
//! **不得作为**「省了多少内存」的绝对证据。绝对证据是 Task 24 的上机实测
//! （A53 真机 + 真实上游），见 `tools/ab_report.md` 与 `tools/stage-b-report.md`。
//!
//! 运行（默认 `cargo test` 只跑快单测，不起进程）：
//! ```bash
//! export TMPDIR=/tmp/opencode/wt-t21-tmp PATH="$HOME/.cargo/bin:$PATH"
//! cd src/wxdet-gate-rs
//! cargo build --release
//! (cd ../wxdet-gate && go build -o /tmp/opencode/wt-t21-tmp/gate-go .)
//! WXDET_AB_SOAK=1 WXDET_GO_BIN=/tmp/opencode/wt-t21-tmp/gate-go \
//!   cargo test --release --test ab_memory -- --ignored --nocapture
//! # 满表口径：另加 WXDET_AB_TCP_N=512 WXDET_AB_UDP_N=512
//! ```
//!
//! 设计：
//! - 假 SOCKS5 上游（纯 std）：CONNECT 回成功后 echo；UDP ASSOCIATE 回
//!   127.0.0.1 relay 地址后黑洞（gate 侧 assoc 靠客户端周期包活着，idle 120s）。
//! - 本机回环别名 `203.0.113.9/32 dev lo`（TEST-NET-3，公网类别）：门 TCP/UDP
//!   均监听 `203.0.113.9:443`，客户端直打该地址。直连门端口时 origdst 必为本机
//!   地址，双门都会按防自环逻辑 drop（`local_dst`），形不成 relay 常驻态；
//!   挂公网类别别名后 origdst=203.0.113.9:443，双门行为一致（Go 先套 FIXED_DST、
//!   Rust 先判本机——本口径下两者收敛到同一值，无分歧）。`iptables OUTPUT
//!   REDIRECT` 在本容器 netns 对本地产生包无效（已实测：规则计数涨但 SYN 无
//!   回复，conntrack 停在 SYN_SENT），故不用 NAT。别名仅影响 TEST-NET-3，不管生产。
//! - 负载：N 条 TCP（发垃圾首包 → proxy/default → 拨假 proxy 腿 → relay 常驻）
//!   + M 条 UDP（每 assoc 独立源端口周期发包，打到同一 REDIRECT 目的）。
//! - 取 `/proc/<pid>/status` 的 RssAnon / VmRSS / VmHWM / VmSwap。
//! - 门侧断言：`stats.tsv` 里 `gate_conn >= TCP_N` 且 `gate_udp_assoc >= UDP_N`，
//!   否则负载没落地、取样无效，直接失败（避免静默测了个空载）。

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// /proc 取样
// ---------------------------------------------------------------------------

/// 四个内存口径（kB，与 /proc status 单位一致）。
#[derive(Debug, Clone, Copy, Default)]
struct MemSample {
    rss_anon: u64,
    vm_rss: u64,
    vm_hwm: u64,
    vm_swap: u64,
    threads: u64,
}

impl MemSample {
    /// 解析 `/proc/<pid>/status` 文本；缺键为 0（VmSwap 在老内核可能缺失）。
    fn parse(text: &str) -> MemSample {
        let mut s = MemSample::default();
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let (Some(k), Some(v)) = (it.next(), it.next()) else {
                continue;
            };
            let n: u64 = v.parse().unwrap_or(0);
            match k {
                "RssAnon:" => s.rss_anon = n,
                "VmRSS:" => s.vm_rss = n,
                "VmHWM:" => s.vm_hwm = n,
                "VmSwap:" => s.vm_swap = n,
                "Threads:" => s.threads = n,
                _ => {}
            }
        }
        s
    }

    /// 对同一进程连续采 `rounds` 次（间隔 `gap`），返回均值（HWM 取末次）。
    fn sample(pid: u32, rounds: usize, gap: Duration) -> MemSample {
        let mut acc = MemSample::default();
        let mut last = MemSample::default();
        for i in 0..rounds {
            if i > 0 {
                std::thread::sleep(gap);
            }
            let text = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            last = MemSample::parse(&text);
            acc.rss_anon += last.rss_anon;
            acc.vm_rss += last.vm_rss;
            acc.vm_swap += last.vm_swap;
            acc.threads = last.threads;
        }
        let n = rounds.max(1) as u64;
        MemSample {
            rss_anon: acc.rss_anon / n,
            vm_rss: acc.vm_rss / n,
            vm_hwm: last.vm_hwm,
            vm_swap: acc.vm_swap / n,
            threads: last.threads,
        }
    }
}

// ---------------------------------------------------------------------------
// 假 SOCKS5 上游（纯 std 阻塞实现）
// ---------------------------------------------------------------------------

fn read_exact(s: &mut std::net::TcpStream, mut n: usize, buf: &mut Vec<u8>) -> std::io::Result<()> {
    buf.clear();
    buf.reserve(n);
    let mut tmp = [0u8; 512];
    while n > 0 {
        let want = tmp.len().min(n);
        let k = s.read(&mut tmp[..want])?;
        if k == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "fake socks eof",
            ));
        }
        buf.extend_from_slice(&tmp[..k]);
        n -= k;
    }
    Ok(())
}

/// 单条假上游连接：问候 + CONNECT/ASSOCIATE。CONNECT 成功后 echo；
/// ASSOCIATE 回 127.0.0.1 relay（黑洞接收）后保持 TCP 直到对端关闭。
fn serve_fake_conn(mut s: std::net::TcpStream) {
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let mut buf = Vec::new();
    if read_exact(&mut s, 2, &mut buf).is_err() {
        return;
    }
    let nm = buf[1] as usize;
    if read_exact(&mut s, nm, &mut buf).is_err() {
        return;
    }
    if s.write_all(&[0x05, 0x00]).is_err() {
        return;
    }
    if read_exact(&mut s, 4, &mut buf).is_err() {
        return;
    }
    let (cmd, atyp) = (buf[1], buf[3]);
    let rest = match atyp {
        0x01 => 6,
        0x03 => {
            let mut l = [0u8; 1];
            if s.read_exact(&mut l).is_err() {
                return;
            }
            l[0] as usize + 2
        }
        0x04 => 18,
        _ => return,
    };
    if read_exact(&mut s, rest, &mut buf).is_err() {
        return;
    }
    if cmd == 0x01 {
        // CONNECT 成功。
        if s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .is_err()
        {
            return;
        }
        // echo 隧道：relay 泵有活可干，连接常驻。
        let mut tmp = [0u8; 4096];
        loop {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => return,
                Ok(k) => {
                    if s.write_all(&tmp[..k]).is_err() {
                        return;
                    }
                }
            }
        }
    } else if cmd == 0x03 {
        // UDP ASSOCIATE：relay 黑洞 + TCP 保持。
        let u = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(u) => u,
            Err(_) => return,
        };
        let port = u.local_addr().map(|a| a.port()).unwrap_or(0);
        let rep = [
            0x05,
            0x00,
            0x00,
            0x01,
            127,
            0,
            0,
            1,
            (port >> 8) as u8,
            (port & 0xff) as u8,
        ];
        if s.write_all(&rep).is_err() {
            return;
        }
        std::thread::spawn(move || {
            let mut tmp = [0u8; 2048];
            loop {
                match u.recv_from(&mut tmp) {
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });
        let mut tmp = [0u8; 256];
        loop {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }
}

/// 启动假上游（TCP 监听 127.0.0.1:0），返回地址串。后台线程常驻到进程结束。
fn spawn_fake_socks() -> String {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").expect("fake socks bind");
    let addr = ln.local_addr().expect("fake socks addr").to_string();
    std::thread::spawn(move || {
        for s in ln.incoming().flatten() {
            std::thread::spawn(move || serve_fake_conn(s));
        }
    });
    addr
}

// ---------------------------------------------------------------------------
// 门进程启停 + 负载驱动
// ---------------------------------------------------------------------------

fn wait_tcp(addr: &str, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if std::net::TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// REDIRECT 目的（TEST-NET-3 文档地址，公网类别，双门本地判都不拦）。
const REDIR_DST: &str = "203.0.113.9";
/// 门固定端口：TCP 443（与生产端口形态一致），UDP 1443（必须与 443 不同，
/// 否则 spoof 口与 serve 口同地址双 bind 成功，客户端包被分流到无人读的
/// spoof 口，serve 循环静默丢包——同口实测 assoc 到达 2~9/32 不定，分口 32/32）。
const GATE_TCP_PORT: u16 = 443;
const GATE_UDP_PORT: u16 = 1443;

fn ip_cmd(args: &[&str]) -> bool {
    std::process::Command::new("ip")
        .args(["addr"])
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 回环挂公网类别别名（幂等：已存在也算成功）。
fn alias_setup() -> bool {
    ip_cmd(&["replace", "203.0.113.9/32", "dev", "lo"]) && {
        // 可达性自检：别名必须本地可达，否则 origdst 仍走 eth0。
        std::process::Command::new("ip")
            .args(["addr", "show", "dev", "lo"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(REDIR_DST))
            .unwrap_or(false)
    }
}

fn alias_teardown() {
    ip_cmd(&["del", "203.0.113.9/32", "dev", "lo"]);
}

struct GateProc {
    child: std::process::Child,
    dir: std::path::PathBuf,
}

impl GateProc {
    fn spawn(
        bin: &str,
        tcp_port: u16,
        udp_port: u16,
        extra_env: &[(&str, &str)],
        seq: usize,
    ) -> GateProc {
        let dir = std::env::temp_dir().join(format!("wxdet-ab-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("ab temp dir");
        for name in ["dom.txt", "ua.txt", "ext.txt", "query.txt"] {
            std::fs::write(dir.join(name), "").expect("dl stub file");
        }
        let mut cmd = std::process::Command::new(bin);
        cmd.env("WD_LISTEN", format!("{REDIR_DST}:{tcp_port}"))
            .env("WD_UDP_LISTEN", format!("{REDIR_DST}:{udp_port}"))
            .env("WD_LOG", dir.join("gate.log"))
            .env("WD_STATS", dir.join("stats.tsv"))
            .env("WD_EVENTS", dir.join("events.jsonl"))
            .env("WD_UDP_ERR_LOG", dir.join("udp_err.log"))
            .env("WD_DL_DOM_FILE", dir.join("dom.txt"))
            .env("WD_DL_UA_FILE", dir.join("ua.txt"))
            .env("WD_DL_EXT_FILE", dir.join("ext.txt"))
            .env("WD_DL_QUERY_FILE", dir.join("query.txt"))
            .env("WD_UDP_FIXED_DST", "203.0.113.9:443")
            .env("WD_KW_POLL_SEC", "3600")
            .stdout(std::process::Stdio::null());
        if std::env::var("WXDET_AB_VERBOSE").as_deref() == Ok("1") {
            cmd.stderr(std::process::Stdio::inherit());
        } else {
            cmd.stderr(std::process::Stdio::null());
        }
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        // 清掉宿主可能带入的调优变量（默认口径必须干净）。
        if !extra_env.iter().any(|(k, _)| *k == "WD_UDP_BUF_KB") {
            cmd.env_remove("WD_UDP_BUF_KB");
        }
        if !extra_env.iter().any(|(k, _)| *k == "WD_TCP_BUF_KB") {
            cmd.env_remove("WD_TCP_BUF_KB");
        }
        let child = cmd.spawn().expect("spawn gate binary");
        GateProc { child, dir }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn kill(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// 负载守卫：N 条常驻 TCP + M 个周期发包 UDP；`stop` 即停。
struct Load {
    stop: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
    tcp_ok: Arc<std::sync::atomic::AtomicUsize>,
    udp_ok: Arc<std::sync::atomic::AtomicUsize>,
    udp_sent: Arc<std::sync::atomic::AtomicUsize>,
    udp_send_err: Arc<std::sync::atomic::AtomicUsize>,
}

impl Load {
    fn start(gate_tcp: String, gate_udp: String, tcp_n: usize, udp_n: usize) -> Load {
        let stop = Arc::new(AtomicBool::new(false));
        let tcp_ok = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let udp_ok = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let udp_sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let udp_send_err = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        // TCP：首包垃圾 32B（非 TLS、非 GET → proxy/default → 拨假 proxy 腿），
        // 后每 2s 补 1B，relay 常驻。首包按 (i%64)*25ms 错峰，避免 512 齐发
        // 瞬间打爆门端 socket 读缓冲（rcvbuf 满则内核静默丢包，无统计）。
        for i in 0..tcp_n {
            let (gate, stop, ok) = (gate_tcp.clone(), stop.clone(), tcp_ok.clone());
            handles.push(std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis((i % 64) as u64 * 25));
                let mut s = match std::net::TcpStream::connect(gate.as_str()) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                if s.write_all(b"PkzipTestPayload-0123456789-abcdef").is_err() {
                    return;
                }
                ok.fetch_add(1, Ordering::SeqCst);
                s.set_read_timeout(Some(Duration::from_millis(300))).ok();
                let mut one = [0u8; 1];
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_secs(2));
                    if s.write_all(b"x").is_err() {
                        return;
                    }
                    let _ = s.read(&mut one);
                }
            }));
        }
        // UDP：每 assoc 独立源端口，周期发 32B 包（FIXED_DST 下直接建 assoc）。
        // UDP：同 TCP 错峰首包；周期 500ms（丢包自愈更快，不影响"常驻"语义）。
        for i in 0..udp_n {
            let (gate, stop, ok, sent, serr) = (
                gate_udp.clone(),
                stop.clone(),
                udp_ok.clone(),
                udp_sent.clone(),
                udp_send_err.clone(),
            );
            handles.push(std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis((i % 64) as u64 * 25));
                let s = match std::net::UdpSocket::bind("127.0.0.1:0") {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let payload = [0xabu8; 32];
                // 首包即建 assoc；失败也继续周期发（建链竞态自愈）。
                // 只统计发送结果：send_to 错误（ENOBUFS 等）是本机负载假象，
                // 必须与"门侧未建 assoc"区分开。
                match s.send_to(&payload, gate.as_str()) {
                    Ok(_) => {
                        sent.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => {
                        serr.fetch_add(1, Ordering::SeqCst);
                    }
                }
                ok.fetch_add(1, Ordering::SeqCst);
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(500));
                    match s.send_to(&payload, gate.as_str()) {
                        Ok(_) => {
                            sent.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(_) => {
                            serr.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }));
        }
        // 等首包打出（建链需要时间），调用方另有 settle。
        std::thread::sleep(Duration::from_secs(1));
        Load {
            stop,
            handles,
            tcp_ok,
            udp_ok,
            udp_sent,
            udp_send_err,
        }
    }

    fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        for h in self.handles {
            h.join().ok();
        }
    }
}

struct CaseResult {
    label: String,
    idle: MemSample,
    loaded: MemSample,
    tcp_held: usize,
    udp_held: usize,
}

/// 门侧断言：relay 真落地（`gate_conn`/`gate_udp_assoc` 行数），否则取样无效。
fn verify_gate_stats(dir: &std::path::Path, label: &str, tcp_n: usize, udp_n: usize) {
    let text = std::fs::read_to_string(dir.join("stats.tsv")).unwrap_or_default();
    let mut conn = 0;
    let mut assoc = 0;
    for line in text.lines() {
        if line.contains("gate_conn") {
            conn += 1;
        }
        if line.contains("gate_udp_assoc") {
            assoc += 1;
        }
    }
    // 注意：`gate_proxy_fail` 等键也含 "gate_" 前缀但与 `gate_conn` 不重合；
    // `gate_conn` 只在 relay 建链成功时记（双门同口径）。
    assert!(
        conn >= tcp_n,
        "{label}: 门侧 TCP relay 未落地（gate_conn={conn} < {tcp_n}），RSS 取样无效"
    );
    assert!(
        assoc >= udp_n,
        "{label}: 门侧 UDP assoc 未落地（gate_udp_assoc={assoc} < {udp_n}），RSS 取样无效"
    );
}

fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

/// 单配置：假上游地址注入双腿 env → 起门（`REDIR_DST:443`，别名由调用方备好）
/// → idle 取样 → 打负载 → 取样 → 拆。门侧 relay 计数不断言在这里由 verify 保证。
fn run_case_with_fake(bin: &str, label: &str, extra_env: &[(&str, &str)]) -> CaseResult {
    static CASE_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = CASE_SEQ.fetch_add(1, Ordering::SeqCst);
    // temp 目录用 seq 区分（同 pid 同端口串行跑，目录名必须唯一）。
    let tcp_n = env_usize("WXDET_AB_TCP_N", 32);
    let udp_n = env_usize("WXDET_AB_UDP_N", 32);
    let settle = Duration::from_secs(env_usize("WXDET_AB_SETTLE_S", 2) as u64);

    let fake = spawn_fake_socks();
    let target_tcp = format!("{REDIR_DST}:{GATE_TCP_PORT}");
    let target_udp = format!("{REDIR_DST}:{GATE_UDP_PORT}");
    let mut full: Vec<(String, String)> = extra_env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    // TCP 垃圾流走 proxy 腿，UDP assoc 走 proxy 腿：双腿同指一个假上游。
    full.push(("WD_PASS_SOCKS".to_string(), fake.clone()));
    full.push(("WD_PROXY_SOCKS".to_string(), fake));
    let full_ref: Vec<(&str, &str)> = full.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut gate = GateProc::spawn(bin, GATE_TCP_PORT, GATE_UDP_PORT, &full_ref, seq);
    assert!(
        wait_tcp(&target_tcp, Duration::from_secs(15)),
        "{label}: 门未起监听 {target_tcp}（bin={bin}）"
    );
    std::thread::sleep(settle);
    let idle = MemSample::sample(gate.pid(), 3, Duration::from_secs(1));

    let load = Load::start(target_tcp, target_udp, tcp_n, udp_n);
    std::thread::sleep(settle + Duration::from_secs(2));
    let loaded = MemSample::sample(gate.pid(), 3, Duration::from_secs(1));
    let tcp_held = load.tcp_ok.load(Ordering::SeqCst);
    let udp_held = load.udp_ok.load(Ordering::SeqCst);
    let udp_sent = load.udp_sent.load(Ordering::SeqCst);
    let udp_send_err = load.udp_send_err.load(Ordering::SeqCst);
    load.stop();
    let log_dir = gate.dir.clone();
    gate.kill();
    eprintln!(
        "{label}: tcp_held={tcp_held}/{tcp_n} udp_held={udp_held}/{udp_n} udp_sent={udp_sent} udp_send_err={udp_send_err} logdir={}",
        log_dir.display(),
    );
    verify_gate_stats(&log_dir, label, tcp_n, udp_n);

    // （进度行已在 verify 前用 eprintln 打出；汇总表见 ab_soak_three_way 尾部。）
    CaseResult {
        label: label.to_string(),
        idle,
        loaded,
        tcp_held,
        udp_held,
    }
}

// ---------------------------------------------------------------------------
// 快单测（默认 cargo test 运行，不起任何进程）
// ---------------------------------------------------------------------------

#[test]
fn status_parse_fixture() {
    let text = "Name:\twxdet-gate\nThreads:\t6\nVmHWM:\t   12340 kB\nVmRSS:\t   10000 kB\n\
                RssAnon:\t    8000 kB\nVmSwap:\t      12 kB\n";
    let s = MemSample::parse(text);
    assert_eq!(s.rss_anon, 8000);
    assert_eq!(s.vm_rss, 10000);
    assert_eq!(s.vm_hwm, 12340);
    assert_eq!(s.vm_swap, 12);
    assert_eq!(s.threads, 6);
    // 缺键 → 0，不 panic。
    let s2 = MemSample::parse("Name:\tx\nThreads:\t1\n");
    assert_eq!(
        (s2.rss_anon, s2.vm_rss, s2.vm_hwm, s2.vm_swap),
        (0, 0, 0, 0)
    );
}

#[test]
fn fake_socks_connect_echo() {
    let addr = spawn_fake_socks();
    let mut s = std::net::TcpStream::connect(&addr).expect("connect fake");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // 问候。
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).unwrap();
    assert_eq!(r, [0x05, 0x00]);
    // CONNECT 1.2.3.4:80。
    s.write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
        .unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(&rep[0..3], &[0x05, 0x00, 0x00]);
    // echo。
    s.write_all(b"ping").unwrap();
    let mut e = [0u8; 4];
    s.read_exact(&mut e).unwrap();
    assert_eq!(&e, b"ping");
}

#[test]
fn fake_socks_associate_relay() {
    let addr = spawn_fake_socks();
    let mut s = std::net::TcpStream::connect(&addr).expect("connect fake");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).unwrap();
    assert_eq!(r, [0x05, 0x00]);
    // ASSOCIATE。
    s.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(&rep[0..4], &[0x05, 0x00, 0x00, 0x01]);
    let port = ((rep[8] as u16) << 8) | rep[9] as u16;
    assert!(port != 0, "relay 端口必须非零");
    // relay 黑洞可达。
    let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    u.send_to(&[0xabu8; 16], format!("127.0.0.1:{port}"))
        .unwrap();
}

// ---------------------------------------------------------------------------
// 重测量（#[ignore] + WXDET_AB_SOAK=1 双门，默认不跑）
// ---------------------------------------------------------------------------

/// 三 run 归因：Go 基线 / Rust 生产口径 / Rust Go-mirror 口径。
/// 重负载（默认 32+32；满表另加 WXDET_AB_TCP_N=512 WXDET_AB_UDP_N=512）。
/// 需 root（回环挂 `REDIR_DST/32` 别名），跑完摘掉。
#[test]
#[ignore]
fn ab_soak_three_way() {
    if std::env::var("WXDET_AB_SOAK").as_deref() != Ok("1") {
        eprintln!("skip: 需要 WXDET_AB_SOAK=1（见文件头用法）");
        return;
    }
    assert!(alias_setup(), "回环别名 {REDIR_DST}/32 挂载失败（需 root）");
    let go_bin = std::env::var("WXDET_GO_BIN")
        .unwrap_or_else(|_| "/tmp/opencode/wt-t21-tmp/gate-go".to_string());
    assert!(
        std::path::Path::new(&go_bin).exists(),
        "Go 基线二进制不存在：{go_bin}（先 go build）"
    );
    let rs_bin = env!("CARGO_BIN_EXE_wxdet-gate");
    // WXDET_AB_ONLY=go|prod|gomirror：单跑一 run（排障用，默认三 run 全跑）。
    let only = std::env::var("WXDET_AB_ONLY").unwrap_or_default();
    let mut out = Vec::new();
    if only.is_empty() || only == "go" {
        out.push(run_case_with_fake(&go_bin, "go-baseline", &[]));
    }
    if only.is_empty() || only == "prod" {
        out.push(run_case_with_fake(rs_bin, "rust-prod(2K/8K)", &[]));
    }
    if only.is_empty() || only == "gomirror" {
        out.push(run_case_with_fake(
            rs_bin,
            "rust-gomirror(64K/32K)",
            &[("WD_UDP_BUF_KB", "64"), ("WD_TCP_BUF_KB", "32")],
        ));
    }
    println!(
        "\n口径 TCP_N={} UDP_N={}（环境 WXDET_AB_TCP_N/WXDET_AB_UDP_N）",
        env_usize("WXDET_AB_TCP_N", 32),
        env_usize("WXDET_AB_UDP_N", 32)
    );
    println!(
        "label | idle_anon idle_rss idle_hwm swap | load_anon load_rss load_hwm swap | tcp udp"
    );
    for c in &out {
        println!(
            "{} | {} {} {} {} | {} {} {} {} | {}/{}",
            c.label,
            c.idle.rss_anon,
            c.idle.vm_rss,
            c.idle.vm_hwm,
            c.idle.vm_swap,
            c.loaded.rss_anon,
            c.loaded.vm_rss,
            c.loaded.vm_hwm,
            c.loaded.vm_swap,
            c.tcp_held,
            c.udp_held,
        );
    }
    alias_teardown();
}
