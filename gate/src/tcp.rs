// TCP 前半：客户端首包 peek + fail-closed 上游拨号（Task 14）。
//
// Go  authority：`main.go` `peekClient`/`peekTLSMore`（§36 短读补齐）/
// `openUpstream`（§41 fail-closed）与 `main_failclosed_test.go`。
//
// Consumed by Task 16（handleConn 装配：peek→classify→open→relay）；
// 接线前保持非测试构建通过（R10）。

use std::net::SocketAddrV4;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::events::Closer;
use crate::lists::DlLists;
use crate::reason::{Reason, TcpReason, Verdict};

/// 全局连接序号（Go `connSeq`）：`fetch_add + 1`，首连接 id 为 1。
static CONN_SEQ: AtomicU64 = AtomicU64::new(0);

/// 上游连接：按 verdict 只拨其一，成功携带已握手完的隧道流。
pub enum Upstream {
    Pass(TcpStream),
    Proxy(TcpStream),
}

/// 单次限时读：绝对 deadline 内等可读后 `try_read` 一次。
/// 返回 `Some(m)`（`m==0` 为对端 EOF/关闭）；超时或硬错返回 `None`。
/// `&TcpStream` 即可（`readable`/`try_read` 均为 `&self` 方法）。
async fn read_once(c: &TcpStream, buf: &mut [u8], budget: Duration) -> Option<usize> {
    let dl = tokio::time::Instant::now() + budget;
    loop {
        match c.try_read(buf) {
            Ok(m) => return Some(m),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return None,
        }
        let rem = dl.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return None;
        }
        if tokio::time::timeout(rem, c.readable()).await.is_err() {
            return None;
        }
    }
}

/// Go `shouldPeekMore`：首字节声明"后面还有字节"时续读。
fn should_peek_more(b0: u8) -> bool {
    if b0 == 0x02 {
        return true;
    }
    matches!(b0, 0x15 | 0x16 | 0x17 | 0x19)
}

/// 阻塞读客户端首包（最多 1024B），返回已读字节。
///
/// - `:80` 用 opportunistic 短读（预算 `cfg.peek_ms80`，默认 80ms），只读一次；
/// - 其余端口预算 `cfg.peek_ms`（默认 400ms）：`n==1 && should_peek_more` 时
///   续读一次（预算 150ms）；`n in [2,6) && 0x16 && b[1]!=0xF1` 时在 150ms
///   预算内补齐到 6B（TLS 严判需 `16 03 … 01` 六字节）；
/// - 预算 `<= 0`（R11）立即返回空缓冲（等价于 Go 过去 deadline 的立即超时，
///   且不做 `as u64`/溢出性 Duration 算术）。
pub async fn peek_client(c: &TcpStream, port: u16, cfg: &Config) -> Vec<u8> {
    // R11：有符号毫秒，非正 ⇒ 立即空返回（Go 过去 deadline 的立即超时；
    // 禁止 `as u64` 与溢出性 Duration 算术）。
    let budget_ms = if port == 80 {
        cfg.peek_ms80
    } else {
        cfg.peek_ms
    };
    if budget_ms <= 0 {
        return Vec::new();
    }
    let budget = Duration::from_millis(budget_ms as u64);
    let mut buf = [0u8; 1024];
    let mut n = match read_once(c, &mut buf[..], budget).await {
        Some(m) if m > 0 => m,
        // 超时 / EOF / 对端无数据关闭：n=0 落 proxy/default（fail-closed）。
        _ => return Vec::new(),
    };
    // :80 短读：只读一次，不续读。
    if port != 80 && n == 1 && should_peek_more(buf[0]) {
        let extra = read_once(c, &mut buf[n..], Duration::from_millis(150)).await;
        if let Some(k) = extra
            && k > 0
        {
            n += k;
        }
    }
    if port != 80 && (2..6).contains(&n) && buf[0] == 0x16 && buf[1] != 0xF1 {
        // §36 短读补齐：TLS 严判需 6 字节（16 03 … 01），同一 150ms 预算内续读。
        let dl = tokio::time::Instant::now() + Duration::from_millis(150);
        while n < 6 {
            let rem = dl.saturating_duration_since(tokio::time::Instant::now());
            if rem.is_zero() {
                break;
            }
            match read_once(c, &mut buf[n..], rem).await {
                Some(k) if k > 0 => n += k,
                _ => break,
            }
        }
    }
    buf[..n].to_vec()
}

/// 按 verdict 拨**唯一**上游；返回 `None` 表示本连接已收尾（fail-closed 断流）。
///
/// - `Pass` → `cfg.pass_socks`，失败记 `gate_pass_fail` + `gate_dial_err`，
///   err 行 reason 不变；
/// - `Proxy` → `cfg.proxy_socks`，失败记 `gate_proxy_fail` + `gate_dial_err`，
///   err 行 reason 加 `_proxy_fail` 后缀；
/// - 失败另写 error 事件 + 措辞逐字的 stderr 行；**绝无第二条腿**。
/// - `seq` 为连接序号（Go `connSeq`，stderr `#%d` 用）。
/// - `src`/`od`/`head` 仅用于日志（err 行 + stderr 行 + error 事件），
///   拨号本身只需代理地址 + 目的地址。
#[allow(clippy::too_many_arguments)]
pub async fn open_upstream(
    cfg: &Config,
    verdict: Verdict,
    reason: TcpReason,
    src: &str,
    od: SocketAddrV4,
    seq: u64,
    head: &[u8],
) -> Option<Upstream> {
    // Go `socks5Dial` 的 5s 建连+握手预算。
    const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
    let dst = od.to_string();
    match verdict {
        Verdict::Proxy => {
            match crate::socks5::socks5_connect(&cfg.proxy_socks, od, DIAL_TIMEOUT).await {
                Ok(s) => Some(Upstream::Proxy(s)),
                Err(e) => {
                    let detail = e.to_string();
                    // R3：verdict 硬编码 "err"（emit_error/log_gate_err 内部处理），
                    // reason 加 _proxy_fail 后缀。
                    let r = Reason::TcpProxyFail(reason);
                    crate::stats::write_stat("gate_proxy_fail", 1);
                    crate::stats::write_stat("gate_dial_err", 1);
                    crate::log_gate::log_gate_err("tcp", src, &dst, &r.as_str(), &detail, head);
                    crate::events::emit_error("tcp", src, &dst, &r, &detail);
                    eprintln!("#{seq} {src} -> {dst} proxy dial fail (fail-closed): {detail}");
                    None
                }
            }
        }
        Verdict::Pass => {
            match crate::socks5::socks5_connect(&cfg.pass_socks, od, DIAL_TIMEOUT).await {
                Ok(s) => Some(Upstream::Pass(s)),
                Err(e) => {
                    let detail = e.to_string();
                    let r = Reason::Tcp(reason);
                    crate::stats::write_stat("gate_pass_fail", 1);
                    crate::stats::write_stat("gate_dial_err", 1);
                    crate::log_gate::log_gate_err("tcp", src, &dst, &r.as_str(), &detail, head);
                    crate::events::emit_error("tcp", src, &dst, &r, &detail);
                    eprintln!("#{seq} {src} -> {dst} dial: {detail}");
                    None
                }
            }
        }
    }
}

/// 双向转发 + 分方向计数 + closer 判定 + close/台账分流（Task 15）。
///
/// Go authority：`main.go` `relay`（`countWriter` 包两端 → `io.Copy` 双向 →
/// 先返回方向定 closer → `shouldEmitOpen` 真则 `emitCloseEvent`，假（`tls_direct`）
/// 则 `ledgerAdd`）。
///
/// - `a` 是客户端侧（client↔relay），`b` 是上游侧（relay↔server）；
///   `up_B` = client→server，`down_B` = server→client，各自独立累计。
/// - 缓冲按方向各借一个（`bufpool::get(buf_size)`，调用方传
///   `cfg.tcp_buf_kb * 1024`，默认 8KB），无论拷贝正常
///   结束还是中途出错都归还（`put` 在返回前执行）。
/// - `closer` 语义与 Go 一致：哪个方向的拷贝先返回，其读端即关闭方
///   （up 先返 ⇒ closer=client，反之 server）；**两个方向都结束后**才 emit/落账。
/// - `should_emit_open(reason)` 为真 → `emit_close`；为假（`tls_direct`）→
///   `ledger_add`。二者互斥：同一连接绝不双写、绝不双漏。
/// - 缓冲大小由调用方（`handle_conn`）从所持 `cfg` 传入；`relay` 自身不再回读
///   环境（spec §6.1：env 只在启动时读一次）。
#[allow(clippy::too_many_arguments)]
pub async fn relay(
    a: TcpStream,
    b: TcpStream,
    src: String,
    od: SocketAddrV4,
    verdict: Verdict,
    reason: Reason,
    start: std::time::Instant,
    buf_size: usize,
    idle: Option<Duration>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dst = od.to_string();
    let (ar, aw) = a.into_split();
    let (br, bw) = b.into_split();

    /// 单方向拷贝：读到 EOF（`Ok(0)`）/任一硬错/空闲超时即结束，
    /// 返回该方向字节数。`idle` 为 `Some(d)` 时每次 `read` 设 `d` 超时
    /// （有字节即重置；连续无字节超 `d` 即收尾，防 FIN_WAIT2/CLOSE_WAIT 常驻）。
    /// `None` = 不设超时（旧语义，仅测试用）。
    /// 缓冲函数内借还：正常结束与中途 `break` 都经过 `put`。
    async fn pump(
        mut r: tokio::net::tcp::OwnedReadHalf,
        mut w: tokio::net::tcp::OwnedWriteHalf,
        buf_size: usize,
        idle: Option<Duration>,
    ) -> u64 {
        let mut buf = crate::bufpool::get(buf_size);
        buf.resize(buf_size, 0);
        let mut n_total: u64 = 0;
        loop {
            let rd = r.read(&mut buf);
            let got = if let Some(d) = idle {
                match tokio::time::timeout(d, rd).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => n,
                }
            } else {
                match rd.await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                }
            };
            n_total += got as u64;
            if w.write_all(&buf[..got]).await.is_err() {
                break;
            }
        }
        crate::bufpool::put(buf);
        // Go `CloseWrite` 对等：半关写端，让对端读到 EOF 后其方向也结束。
        let _ = w.shutdown().await;
        n_total
    }

    // `true` = up（client→server）先结束 ⇒ closer=client。
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bool>(2);
    let tx_down = tx.clone();
    let up_h = tokio::spawn(async move {
        let n = pump(ar, bw, buf_size, idle).await;
        let _ = tx.send(true).await;
        n
    });
    let down_h = tokio::spawn(async move {
        let n = pump(br, aw, buf_size, idle).await;
        let _ = tx_down.send(false).await;
        n
    });
    let first_up = rx.recv().await.unwrap_or(true);
    let closer = if first_up {
        Closer::Client
    } else {
        Closer::Server
    };
    // 两方向都必须结束才落账/emit（Go `<-done` 两次对等）。
    let (up_b, down_b) = match tokio::join!(up_h, down_h) {
        (Ok(u), Ok(d)) => (u, d),
        _ => return,
    };
    let _ = rx.recv().await;
    let dur_ms = start.elapsed().as_millis() as u64;
    if crate::events::should_emit_open(&reason) {
        crate::events::emit_close(
            "tcp", &src, &dst, verdict, &reason, dur_ms, up_b, down_b, closer,
        );
    } else {
        crate::ledger::ledger_add(dur_ms, up_b, down_b);
    }
}

/// 全链路接线（Go `main.go handleConn`）：严格顺序 ——
///
/// `TCP_NODELAY` → `tcp_original_dst`（失败记 `gate_origdst_err` + stderr
/// `#id src origdst: err`，**不写 gate.log**）→ `is_local_dst` 命中则记
/// `gate_tcp_local_drop` + 限速 `log_tcp_local_drop` 后返回 → `peek_client` →
/// `classify` → `emit_open` → `open_upstream`（`None` 直接返回）→ 首包写上游
/// （失败记 `gate_write_err` + error 事件）→ `gate_conn`/`gate_pass|proxy`/
/// `gate_rsn_<reason>` + `log_gate` → `relay`。
///
/// 每步失败模式钉死：计数、日志或静默返回——绝不 panic，绝不第二次拨号。
/// `raw` 全程持有：origdst 只借 fd 做 `getsockopt`（无 dup/close），
/// relay 接管所有权后函数结束，无 fd 先关后用。
pub async fn handle_conn(raw: TcpStream, cfg: Arc<Config>, shared: Arc<RwLock<DlLists>>) {
    use std::os::unix::io::AsRawFd;
    use tokio::io::AsyncWriteExt;

    let _ = raw.set_nodelay(true);
    let id = CONN_SEQ.fetch_add(1, Ordering::SeqCst) + 1;
    let src = raw
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| String::from("unknown"));
    let start = std::time::Instant::now();

    let od = match crate::origdst::tcp_original_dst(raw.as_raw_fd()) {
        Ok(od) => od,
        Err(e) => {
            crate::stats::write_stat("gate_origdst_err", 1);
            eprintln!("#{id} {src} origdst: {e}");
            return;
        }
    };
    if crate::bufpool::is_local_dst(&std::net::IpAddr::V4(*od.ip())) {
        crate::stats::write_stat("gate_tcp_local_drop", 1);
        crate::log_gate::log_tcp_local_drop(&src, &od.to_string(), &[]);
        return;
    }

    let head = peek_client(&raw, od.port(), &cfg).await;
    let (verdict, treason) = {
        let dl = shared.read().await;
        let out = crate::classify::classify(&head, &dl);
        (out.verdict, out.reason)
    };
    let reason = Reason::Tcp(treason);
    let dst = od.to_string();
    crate::events::emit_open("tcp", &src, &dst, verdict, &reason);
    let up = match open_upstream(&cfg, verdict, treason, &src, od, id, &head).await {
        Some(u) => u,
        None => return,
    };
    let mut ups = match up {
        Upstream::Pass(s) => s,
        Upstream::Proxy(s) => s,
    };
    if !head.is_empty()
        && let Err(e) = ups.write_all(&head).await
    {
        crate::stats::write_stat("gate_write_err", 1);
        crate::events::emit_error("tcp", &src, &dst, &reason, &e.to_string());
        return;
    }
    crate::stats::write_stat("gate_conn", 1);
    crate::stats::write_stat(&format!("gate_{}", verdict.as_str()), 1);
    crate::stats::write_stat(&format!("gate_rsn_{}", treason.as_str()), 1);
    crate::log_gate::log_gate("tcp", &src, &dst, verdict.as_str(), treason.as_str(), &head);
    let idle = if cfg.tcp_idle_sec > 0 {
        Some(Duration::from_secs(cfg.tcp_idle_sec as u64))
    } else {
        None
    };
    relay(
        raw,
        ups,
        src,
        od,
        verdict,
        reason,
        start,
        cfg.tcp_buf_kb * 1024,
        idle,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn pass_verdict_failure_is_fail_closed() {
        // pass 假上游回 REP=4；proxy 假上游正常
        let (pass, proxy, hits) = crate::testutil::spawn_fake_socks(4, true).await;
        let cfg = crate::testutil::config_with_socks("pass_failclosed", &pass, &proxy);
        crate::testutil::reset_stats("pass_failclosed");
        crate::testutil::reset_logs("pass_failclosed");
        crate::testutil::reset_events("pass_failclosed");
        let out = open_upstream(
            &cfg,
            Verdict::Pass,
            TcpReason::TlsDirect,
            "1.1.1.1:1",
            "2.2.2.2:443".parse().unwrap(),
            1,
            &[],
        )
        .await;
        assert!(out.is_none(), "fail-closed：必须返回 None");
        assert_eq!(
            crate::testutil::stat_value("pass_failclosed", "gate_pass_fail"),
            1
        );
        assert_eq!(
            crate::testutil::stat_value("pass_failclosed", "gate_dial_err"),
            1
        );
        assert_eq!(hits.proxy.load(Ordering::SeqCst), 0, "不得回退 proxy");
        assert_eq!(hits.pass.load(Ordering::SeqCst), 1, "只拨一次 pass");
        // R3 适配：err 行 reason 不变（无 _proxy_fail 后缀）
        let g = crate::testutil::read_gate_log("pass_failclosed");
        assert!(
            g.contains("\"reason\":\"tls_direct\""),
            "pass err 行 reason 必须不变: {g}"
        );
        assert!(!g.contains("_proxy_fail"), "pass 不得加后缀: {g}");
        let ev = crate::testutil::read_events("pass_failclosed");
        assert!(
            ev.contains("\"reason\":\"tls_direct\""),
            "pass error 事件 reason 必须不变: {ev}"
        );
    }

    #[tokio::test]
    async fn proxy_verdict_failure_is_fail_closed() {
        let (pass, proxy, hits) = crate::testutil::spawn_fake_socks(0, false).await;
        let cfg = crate::testutil::config_with_socks("proxy_failclosed", &pass, &proxy);
        crate::testutil::reset_stats("proxy_failclosed");
        crate::testutil::reset_logs("proxy_failclosed");
        crate::testutil::reset_events("proxy_failclosed");
        let out = open_upstream(
            &cfg,
            Verdict::Proxy,
            TcpReason::Default,
            "1.1.1.1:1",
            "2.2.2.2:443".parse().unwrap(),
            3,
            &[],
        )
        .await;
        assert!(out.is_none(), "fail-closed：必须返回 None");
        assert_eq!(
            crate::testutil::stat_value("proxy_failclosed", "gate_proxy_fail"),
            1
        );
        assert_eq!(
            crate::testutil::stat_value("proxy_failclosed", "gate_dial_err"),
            1
        );
        assert_eq!(hits.pass.load(Ordering::SeqCst), 0, "不得回退 pass");
        // 注：proxy_ok=false 时假上游直接无监听（拨号即拒接），服务端侧无 hits
        // 可计；"只拨一次"由 gate_proxy_fail==1 + gate_dial_err==1 钉死
        // （一次失败路径恰写一次，多拨一次计数即为 2）。
        // R3 适配：proxy err 行 reason 加 _proxy_fail 后缀
        let g = crate::testutil::read_gate_log("proxy_failclosed");
        assert!(
            g.contains("\"reason\":\"default_proxy_fail\""),
            "proxy err 行 reason 必须加后缀: {g}"
        );
        let ev = crate::testutil::read_events("proxy_failclosed");
        assert!(
            ev.contains("\"reason\":\"default_proxy_fail\""),
            "proxy error 事件 reason 必须加后缀: {ev}"
        );
    }

    #[tokio::test]
    async fn peek_nonpositive_budget_returns_empty_immediately() {
        // R11：非正预算立即空返回（等价于 Go 过去 deadline 的立即超时）
        let (a, _b) = crate::testutil::duplex_pair().await;
        let mut cfg = crate::testutil::config_for_test("peek_nonpos");
        cfg.peek_ms = 0;
        cfg.peek_ms80 = -5;
        let got = peek_client(&a, 443, &cfg).await;
        assert!(got.is_empty(), "peek_ms=0 必须立即空返回");
        let got80 = peek_client(&a, 80, &cfg).await;
        assert!(got80.is_empty(), "peek_ms80<0 必须立即空返回");
    }

    #[tokio::test]
    async fn peek_80_returns_first_read_only() {
        // :80 短读：只读一次，不续读
        let (a, mut b) = crate::testutil::duplex_pair().await;
        tokio::io::AsyncWriteExt::write_all(&mut b, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let cfg = crate::testutil::config_for_test("peek_80");
        let got = peek_client(&a, 80, &cfg).await;
        assert_eq!(got, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    #[tokio::test]
    async fn peek_non80_continues_single_byte_tls_prefix() {
        // 非 80：首读 1B(0x16)→should_peek_more→150ms 内续读补齐
        let (a, mut b) = crate::testutil::duplex_pair().await;
        tokio::io::AsyncWriteExt::write_all(&mut b, &[0x16])
            .await
            .unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ =
                tokio::io::AsyncWriteExt::write_all(&mut b, &[0x03, 0x01, 0x00, 0x00, 0x01]).await;
        });
        let cfg = crate::testutil::config_for_test("peek_tls1b");
        let got = peek_client(&a, 443, &cfg).await;
        assert_eq!(got, vec![0x16, 0x03, 0x01, 0x00, 0x00, 0x01]);
    }

    #[tokio::test]
    async fn peek_non80_short_tls_prefix_pads_to_six() {
        // §36：首读 3B(16 03 …)→150ms 预算内续读到 6B
        let (a, mut b) = crate::testutil::duplex_pair().await;
        tokio::io::AsyncWriteExt::write_all(&mut b, &[0x16, 0x03, 0x01])
            .await
            .unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = tokio::io::AsyncWriteExt::write_all(&mut b, &[0x00, 0x6f, 0x01]).await;
        });
        let cfg = crate::testutil::config_for_test("peek_tls3b");
        let got = peek_client(&a, 443, &cfg).await;
        assert_eq!(got, vec![0x16, 0x03, 0x01, 0x00, 0x6f, 0x01]);
    }

    /// Task 15：客户端先半关 → closer 必须是 client；分方向字节精确；
    /// proxy 不走台账（防双写）。
    #[tokio::test]
    async fn relay_counts_bytes_and_reports_closer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tag = "relay_count";
        let dir = {
            // 文件句柄是进程全局的：init 重定向阶段持串行锁；网络 I/O 期间释放
            //（clippy await_holding_lock 禁止 guard 跨 await；串行门 R26 下无竞态）。
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            crate::testutil::reset_stats(tag);
            let dir = crate::testutil::reset_events(tag);
            crate::ledger::reset();
            dir
        };
        let (mut client, rel_a) = crate::testutil::duplex_pair().await;
        let (rel_b, mut server) = crate::testutil::duplex_pair().await;
        let h = tokio::spawn(relay(
            rel_a,
            rel_b,
            "1.1.1.1:1".into(),
            "2.2.2.2:443".parse().unwrap(),
            Verdict::Proxy,
            Reason::Tcp(TcpReason::Default),
            std::time::Instant::now(),
            8 * 1024,
            None,
        ));
        // 先把两个方向的数据都 rendezvous，再半关（Go TestRelayCloseBytesAndCloser 对等）。
        client.write_all(&[0u8; 100]).await.unwrap();
        let mut tmp = vec![0u8; 100];
        server.read_exact(&mut tmp).await.unwrap();
        server.write_all(&[0u8; 200]).await.unwrap();
        let mut tmp2 = vec![0u8; 200];
        client.read_exact(&mut tmp2).await.unwrap();
        client.shutdown().await.unwrap(); // 客户端半关 → closer 必须是 client
        tokio::time::sleep(Duration::from_millis(200)).await;
        server.shutdown().await.unwrap();
        h.await.unwrap();
        {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // 事件流恰一行 close
            let s = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
            assert_eq!(s.lines().count(), 1, "relay 必须恰发一行 close: {s}");
            let line = s.trim_end();
            assert!(
                line.contains("\"closer\":\"client\""),
                "closer 必须是 client: {line}"
            );
            assert!(line.contains("\"up_B\":100"), "up_B 必须 100: {line}");
            assert!(line.contains("\"down_B\":200"), "down_B 必须 200: {line}");
            // proxy 不走台账：台账四键合计必须为 0 行
            assert!(
                !std::fs::read_to_string(dir.join("stats.tsv"))
                    .unwrap_or_default()
                    .contains("gate_tlsdirect"),
                "proxy 不得进台账"
            );
        }
    }

    /// Task 15：reason=tls_direct → 事件流 0 行；ledger_flush 后 stats 含
    /// gate_tlsdirect_close / up_B / down_B / dur_ms 四行，且字节与写入一致。
    #[tokio::test]
    async fn tls_pass_relay_goes_to_ledger_not_events() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tag = "relay_tlsdirect";
        let dir = {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            crate::testutil::reset_stats(tag);
            let dir = crate::testutil::reset_events(tag);
            crate::ledger::reset();
            dir
        };
        let (mut client, rel_a) = crate::testutil::duplex_pair().await;
        let (rel_b, mut server) = crate::testutil::duplex_pair().await;
        let h = tokio::spawn(relay(
            rel_a,
            rel_b,
            "1.1.1.1:1".into(),
            "2.2.2.2:443".parse().unwrap(),
            Verdict::Pass,
            Reason::Tcp(TcpReason::TlsDirect),
            std::time::Instant::now(),
            8 * 1024,
            None,
        ));
        client.write_all(&[7u8; 321]).await.unwrap();
        let mut tmp = vec![0u8; 321];
        server.read_exact(&mut tmp).await.unwrap();
        server.write_all(&[9u8; 654]).await.unwrap();
        let mut tmp2 = vec![0u8; 654];
        client.read_exact(&mut tmp2).await.unwrap();
        client.shutdown().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        server.shutdown().await.unwrap();
        h.await.unwrap();
        {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let ev = std::fs::read_to_string(dir.join("events.jsonl")).unwrap_or_default();
            assert!(ev.is_empty(), "tls_direct 不得进事件流: {ev}");
            crate::ledger::ledger_flush();
            let st = std::fs::read_to_string(dir.join("stats.tsv")).unwrap_or_default();
            for want in [
                "gate_tlsdirect_close\t1",
                "gate_tlsdirect_up_B\t321",
                "gate_tlsdirect_down_B\t654",
                "gate_tlsdirect_dur_ms\t",
            ] {
                assert!(st.contains(want), "台账缺 {want:?}:\n{st}");
            }
        }
    }

    /// Task 16：本机目的守卫集成（Go `TestHandleConnLocalDstDrop` 对等）：
    /// 自建监听口 + 直连（无 DNAT，origdst=本机:port）→ 必须 drop：
    /// 客户端立即 EOF；不拨上游（dialed==0）；accepts==1；
    /// gate_tcp_local_drop=1；gate_conn=0；gate.log 含 drop/local_dst。
    #[tokio::test]
    async fn local_dst_connection_is_dropped_without_dialing() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tag = "handle_local_drop";

        // 假上游：只计数。P0-1 生效时应为 0（drop 在 open_upstream 之前）。
        let fake = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fake_addr = fake.local_addr().unwrap().to_string();
        let dialed = Arc::new(AtomicUsize::new(0));
        let d2 = dialed.clone();
        tokio::spawn(async move {
            loop {
                let Ok((c, _)) = fake.accept().await else {
                    return;
                };
                d2.fetch_add(1, Ordering::SeqCst);
                drop(c);
            }
        });

        let cfg = Arc::new(crate::testutil::config_with_socks(
            tag, &fake_addr, &fake_addr,
        ));
        // 注意：config_for_test 会清掉 tag 目录的 4 个输出文件，故 resets 必须在其后，
        // 否则 stats/gate.log 句柄指向被删的 inode、写入全丢（unlinked fd）。
        crate::testutil::reset_stats(tag);
        crate::testutil::reset_logs(tag);
        let shared = Arc::new(tokio::sync::RwLock::new(crate::lists::DlLists::default()));

        // 生产监听口的等价物：本测试自建 listener，只 accept 一次并走 handle_conn。
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let a2 = accepts.clone();
        let h = tokio::spawn(async move {
            let (c, _) = ln.accept().await.unwrap();
            a2.fetch_add(1, Ordering::SeqCst);
            handle_conn(c, cfg, shared).await;
        });

        let mut cl = tokio::net::TcpStream::connect(addr).await.unwrap();
        cl.write_all(b"hello-not-http").await.unwrap();
        let mut buf = [0u8; 16];
        // Go `TestHandleConnLocalDstDrop` 对等：服务端从不读、直接关闭。
        // 客户端 hello 若已进服务端接收队列则收 RST，否则收 FIN（EOF）——
        // 二者皆为"立刻断开"，收到任何字节或 3s 无返回才算失败。
        match tokio::time::timeout(Duration::from_secs(3), cl.read(&mut buf)).await {
            Ok(Ok(0)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("drop 后客户端应立刻断开（EOF 或 RST），got {other:?}"),
        }
        drop(cl);
        h.await.unwrap();

        assert_eq!(dialed.load(Ordering::SeqCst), 0, "本机目的不该拨上游");
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "不该出现二次连接（自环）"
        );
        assert_eq!(
            crate::testutil::stat_value(tag, "gate_tcp_local_drop"),
            1,
            "gate_tcp_local_drop 必须为 1"
        );
        assert_eq!(
            crate::testutil::stat_value(tag, "gate_conn"),
            0,
            "drop 流不该计 gate_conn"
        );
        let g = crate::testutil::read_gate_log(tag);
        assert!(
            g.contains("\"verdict\":\"drop\""),
            "gate.log 应留 drop 行: {g}"
        );
        assert!(
            g.contains("\"reason\":\"local_dst\""),
            "gate.log 应留 local_dst 行: {g}"
        );
    }

    /// EMFILE 回归：双向静默超 idle 即收尾，不永久占 fd。
    /// 2026-10-20 游戏现场：FIN_WAIT2 750 + CLOSE_WAIT 437 耗尽 1024。
    #[tokio::test]
    async fn relay_idle_timeout_closes_stalled_connection() {
        let tag = "relay_idle";
        let dir = {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            crate::testutil::reset_stats(tag);
            let dir = crate::testutil::reset_events(tag);
            crate::ledger::reset();
            dir
        };
        let (_client, rel_a) = crate::testutil::duplex_pair().await;
        let (_server, rel_b) = crate::testutil::duplex_pair().await;
        // 两端都不发字节、不关闭：无超时会永久挂起；100ms 超时必须 5s 内返回。
        let h = tokio::spawn(relay(
            rel_a,
            rel_b,
            "1.1.1.1:1".into(),
            "2.2.2.2:443".parse().unwrap(),
            Verdict::Proxy,
            Reason::Tcp(TcpReason::Default),
            std::time::Instant::now(),
            8 * 1024,
            Some(Duration::from_millis(100)),
        ));
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .expect("idle 超时 5s 内必须收尾")
            .unwrap();
        let _serial = crate::ledger::FILE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ev = std::fs::read_to_string(dir.join("events.jsonl")).unwrap_or_default();
        assert_eq!(ev.lines().count(), 1, "idle 收尾也必须恰发一条 close: {ev}");
    }

    /// Task 15：reason=default → 事件流恰 1 条 close；台账四键合计 0 行（防双写/双漏）。
    #[tokio::test]
    async fn proxy_relay_emits_event_and_no_ledger_double_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tag = "relay_proxy";
        let dir = {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            crate::testutil::reset_stats(tag);
            let dir = crate::testutil::reset_events(tag);
            crate::ledger::reset();
            dir
        };
        let (mut client, rel_a) = crate::testutil::duplex_pair().await;
        let (rel_b, mut server) = crate::testutil::duplex_pair().await;
        let h = tokio::spawn(relay(
            rel_a,
            rel_b,
            "1.1.1.1:1".into(),
            "2.2.2.2:443".parse().unwrap(),
            Verdict::Proxy,
            Reason::Tcp(TcpReason::Default),
            std::time::Instant::now(),
            8 * 1024,
            None,
        ));
        client.write_all(b"ping").await.unwrap();
        let mut tmp = [0u8; 4];
        server.read_exact(&mut tmp).await.unwrap();
        client.shutdown().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        server.shutdown().await.unwrap();
        h.await.unwrap();
        {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let ev = std::fs::read_to_string(dir.join("events.jsonl")).unwrap_or_default();
            assert_eq!(ev.lines().count(), 1, "proxy 必须恰发一条 close: {ev}");
            assert!(ev.contains("\"close\""), "proxy 事件必须是 close: {ev}");
            crate::ledger::ledger_flush();
            for k in [
                "gate_tlsdirect_close",
                "gate_tlsdirect_up_B",
                "gate_tlsdirect_down_B",
                "gate_tlsdirect_dur_ms",
            ] {
                assert_eq!(
                    crate::testutil::stat_lines(tag, k),
                    0,
                    "proxy 不得进台账（{k} 必须 0 行）"
                );
            }
        }
    }
}
