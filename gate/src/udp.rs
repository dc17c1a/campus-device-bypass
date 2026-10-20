// UDP assoc 上半：状态机 + 建壳/建链 + pending + spoof + 自清理（Task 17）。
//
// Go authority：`udp.go` `udpAssoc`/`startUDPAssoc`/`send`/`shutdown`/`abort`/
// `spoofUDP`/`reapUDPAssoc`。下半（Task 18）：serve_udp 收包循环 + pump 回包 +
// maybeUpgrade 单向升级 + 表上限 512 enforcement。
//
// Consumed by Task 19 (main wiring: serve_udp/reap); Task 19 removes this allow.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::{TcpStream, UdpSocket};

use crate::config::Config;
use crate::reason::{Reason, Verdict};

/// assoc 状态：建链中 / 就绪 / 已关闭（Go `udpConnecting/udpReady/udpClosed` 对等）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpState {
    Connecting,
    Ready,
    Closed,
}

/// 建链期间每 assoc 暂存包上限（Go `udpPendingMax`）：溢出静默丢弃 + `gate_udp_pending_drop`。
const PENDING_MAX: usize = 8;

/// 投递错误：只有"已关闭"一种可达业务错误（串与 Go `errUDPAssocClosed` 逐字一致，
/// 直接进入 error 事件 detail）；`Io` 兜底传输层硬错（`try_send` 口径）。
#[derive(Debug)]
pub enum UdpSendErr {
    Closed,
    Io(std::io::Error),
}

impl std::fmt::Display for UdpSendErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpSendErr::Closed => write!(f, "udp assoc closed"),
            UdpSendErr::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for UdpSendErr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UdpSendErr::Closed => None,
            UdpSendErr::Io(e) => Some(e),
        }
    }
}

/// Go `udpAssoc.mu` 保护的全部可变字段（state/up/tcp/spoof/pending/upgrading/reason）。
/// `up`/`spoof` 用 `Arc` 装：Task 18 的 pump 换代持有与下行发送需要跨锁共享
/// （Go 裸指针由 GC 兜底）；`reason` 建壳一次写入，单向升级时改写（Go 同为 mu 保护）。
struct AssocMu {
    state: UdpState,
    up: Option<Arc<UdpSocket>>,
    tcp: Option<TcpStream>,
    spoof: Option<Arc<UdpSocket>>,
    pending: VecDeque<Vec<u8>>,
    upgrading: bool,
    reason: Reason,
}

/// UDP 中继 assoc（Go `udpAssoc` 对等）。
///
/// 不变量（本任务钉死，Task 18 继承）：
/// - `to_proxy` 建壳时由 verdict 一次定死（粘性），建链失败**绝不**回退 pass；
/// - `reason` 建壳时一次写入（Task 18 的单向升级改写时再套锁）；
/// - 计数器只增不减，`close_once` 保证 uclose 至多一行。
pub struct UdpAssoc {
    pub(crate) key: String,
    pub(crate) client: SocketAddrV4,
    pub(crate) dst: SocketAddrV4,
    pub(crate) srv: Arc<UdpSocket>,
    mu: Mutex<AssocMu>,
    to_proxy: AtomicBool,
    // pump 代次（Go `gen`；edition 2024 保留关键字故改名）：Task 18 的升级
    // ++generation 并另起新泵，旧泵按代次不符退出且不关 assoc。
    generation: AtomicI64,
    /// 泵起始缓冲字节数（`cfg.udp_buf_kb * 1024`，建壳时一次定死；截断即翻倍，
    /// 见 [`next_buf_size`]）。
    buf_start: usize,
    start_ns: AtomicI64,
    last_ns: AtomicI64,
    up_pkts: AtomicU64,
    down_pkts: AtomicU64,
    up_bytes: AtomicU64,
    down_bytes: AtomicU64,
    close_once: std::sync::Once,
}

impl UdpAssoc {
    /// 当前状态（R2 访问器：测试断言 ready/closed 用）。
    #[cfg(test)]
    pub fn state(&self) -> UdpState {
        self.mu.lock().unwrap_or_else(|e| e.into_inner()).state
    }

    /// 建壳 verdict 是否 proxy（R2 访问器：失败自清理后仍须为 true，不断言回退）。
    #[cfg(test)]
    pub fn to_proxy(&self) -> bool {
        self.to_proxy.load(Ordering::SeqCst)
    }

    /// 当前 reason 快照（升级改写后取当时值；uclose/写错事件用）。
    pub(crate) fn reason_cloned(&self) -> Reason {
        self.mu.lock().unwrap_or_else(|e| e.into_inner()).reason
    }

    fn emit_uclose_once(&self) {
        self.close_once.call_once(|| {
            let start = self.start_ns.load(Ordering::SeqCst);
            let base = if start == 0 {
                self.last_ns.load(Ordering::SeqCst)
            } else {
                start
            };
            let mut dur_ms = 0u64;
            if base != 0 {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or(0);
                dur_ms = (now - base).max(0) as u64 / 1_000_000;
            }
            let verdict = if self.to_proxy.load(Ordering::SeqCst) {
                Verdict::Proxy
            } else {
                Verdict::Pass
            };
            // uclose 的 reason 取当时值（建壳原因；单向升级改写后取新值）。
            let reason = self.mu.lock().unwrap_or_else(|e| e.into_inner()).reason;
            let reason = Reason::Udp(match reason {
                Reason::Udp(r) => r,
                Reason::UdpProxyFail(r) => r,
                // UDP assoc 恒携 Udp 原因；其余分支不可达，保总数。
                _ => crate::reason::UdpReason::UdpDirect,
            });
            crate::events::emit_uclose(
                &self.client.to_string(),
                &self.dst.to_string(),
                verdict,
                &reason,
                dur_ms,
                self.up_pkts.load(Ordering::SeqCst),
                self.down_pkts.load(Ordering::SeqCst),
                self.up_bytes.load(Ordering::SeqCst),
                self.down_bytes.load(Ordering::SeqCst),
            );
        });
    }
}

/// assoc 全局表（R2）：Task 18 起归 `serve_udp` 收包循环所有——建壳入表、
/// 每包查表/刷新 `last`、表上限 512 enforcement、30s reap 清理共用此表。
pub(crate) struct UdpTable {
    inner: Mutex<HashMap<String, Arc<UdpAssoc>>>,
}

impl UdpTable {
    fn insert(&self, key: String, a: &Arc<UdpAssoc>) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, Arc::clone(a));
    }

    fn get(&self, key: &str) -> Option<Arc<UdpAssoc>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .map(Arc::clone)
    }

    fn remove_if_current(&self, a: &Arc<UdpAssoc>) {
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cur) = m.get(&a.key)
            && Arc::ptr_eq(cur, a)
        {
            m.remove(&a.key);
        }
    }

    /// 当前表长（生产收包循环表满判定 + R2 测试访问器经 [`udp_table_len`] 间接用）。
    /// 无 `is_empty` 配对：调用方只有"满/非满"阈值比较，不需要 emptiness 语义。
    #[allow(clippy::len_without_is_empty)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

static UDP_TABLE: OnceLock<UdpTable> = OnceLock::new();

fn table() -> &'static UdpTable {
    UDP_TABLE.get_or_init(|| UdpTable {
        inner: Mutex::new(HashMap::new()),
    })
}

/// 当前 assoc 表长（R2 访问器：失败自清理断言用）。
#[cfg(test)]
pub(crate) fn udp_table_len() -> usize {
    table().len()
}

/// assoc 键（Go `udpAssocKey`）：`"<client>|<dst>"`，`SocketAddrV4` Display 口径。
fn udp_assoc_key(client: SocketAddrV4, od: SocketAddrV4) -> String {
    format!("{client}|{od}")
}

/// 建壳 + 立即入表，真正的建链放后台（Go `startUDPAssoc` 对等，P2-10）。
///
/// 必须 <50ms 返回：同步只做 spoof 本地 bind（失败回退 `srv`，只记
/// `gate_udp_spoof_fail`）→ `to_proxy = verdict == Proxy` → `emit_open` → 入表 →
/// `tokio::spawn` 建链。建链期间的包由 [`udp_send`] 进有界队列。
pub async fn start_udp_assoc(
    cfg: &Config,
    srv: Arc<UdpSocket>,
    client: SocketAddrV4,
    od: SocketAddrV4,
    verdict: Verdict,
    reason: Reason,
    first: &[u8],
) -> Arc<UdpAssoc> {
    let proxy = verdict == Verdict::Proxy;
    let key = udp_assoc_key(client, od);
    // 下行 spoof 口与建链无关（纯本地 bind），同步建：失败回退 a.srv（旧语义），
    // 只计数不记事件（无 root/TRANSPARENT 的单测与开发环境恒走回退）。
    let spoof = match spoof_udp(od).await {
        Ok(s) => Some(Arc::new(s)),
        Err(_) => {
            crate::stats::write_stat("gate_udp_spoof_fail", 1);
            None
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let a = Arc::new(UdpAssoc {
        key: key.clone(),
        client,
        dst: od,
        srv,
        mu: Mutex::new(AssocMu {
            state: UdpState::Connecting,
            up: None,
            tcp: None,
            spoof,
            pending: VecDeque::new(),
            upgrading: false,
            reason,
        }),
        to_proxy: AtomicBool::new(proxy),
        generation: AtomicI64::new(0),
        buf_start: cfg.udp_buf_kb.saturating_mul(1024),
        start_ns: AtomicI64::new(now),
        last_ns: AtomicI64::new(now),
        up_pkts: AtomicU64::new(0),
        down_pkts: AtomicU64::new(0),
        up_bytes: AtomicU64::new(0),
        down_bytes: AtomicU64::new(0),
        close_once: std::sync::Once::new(),
    });
    let cs = client.to_string();
    let ds = od.to_string();
    crate::events::emit_open("udp", &cs, &ds, verdict, &a.reason_cloned());
    table().insert(key, &a);
    {
        let a = Arc::clone(&a);
        let proxy_socks = cfg.proxy_socks.clone();
        let first = first.to_vec();
        tokio::spawn(async move {
            connect_assoc(&a, &proxy_socks, proxy, first).await;
        });
    }
    a
}

/// 后台建链（Go `(a *udpAssoc) connect` 对等）：proxy → `socks5_udp_associate`；
/// pass → 本地 bind + `connect(dst)`（`od` 类型恒为 `SocketAddrV4`，
/// 非 v4 在类型层面不可达，无需 Go 式的 `To4` 拒绝分支）。
///
/// 成功 → 换入 socket、`state=ready`、取 pending → 按固定顺序记统计 →
/// `log_gate` → 冲刷积压（按当时腿封装，首个写错即停）→ 回包 pump 归 Task 18。
/// 失败 → fail-closed：计数 + `log_gate_err` + `emit_error` + stderr 措辞行 +
/// `shutdown(emit=false)`（移表关 socket，**不发 uclose**，不回退）。
async fn connect_assoc(a: &Arc<UdpAssoc>, proxy_socks: &str, proxy: bool, first: Vec<u8>) {
    enum Up {
        Proxy(Arc<UdpSocket>, TcpStream),
        Pass(Arc<UdpSocket>),
    }
    let built: Result<Up, String> = if proxy {
        match crate::socks5::socks5_udp_associate(proxy_socks, Duration::from_secs(5)).await {
            Ok((u, t)) => Ok(Up::Proxy(Arc::new(u), t)),
            Err(e) => Err(e.to_string()),
        }
    } else {
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(u) => match u.connect(std::net::SocketAddr::V4(a.dst)).await {
                Ok(()) => Ok(Up::Pass(Arc::new(u))),
                Err(e) => Err(e.to_string()),
            },
            Err(e) => Err(e.to_string()),
        }
    };
    let (up_sock, tcp_opt) = match built {
        Ok(Up::Proxy(u, t)) => (u, Some(t)),
        Ok(Up::Pass(u)) => (u, None),
        Err(detail) => {
            let cs = a.client.to_string();
            let ds = a.dst.to_string();
            if proxy {
                crate::stats::write_stat("gate_proxy_udp_fail", 1);
                // R3：proxy 失败行 reason 加 `_proxy_fail` 后缀（TCP `open_upstream` 同口径）。
                let cur = a.reason_cloned();
                let fr = match cur {
                    Reason::Udp(r) => Reason::UdpProxyFail(r),
                    Reason::UdpProxyFail(r) => Reason::UdpProxyFail(r),
                    // UDP 建壳恒携 Udp 原因；其余分支不可达，保总数。
                    _ => Reason::UdpUpgradeProxyFail,
                };
                crate::log_gate::log_gate_err("udp", &cs, &ds, &fr.as_str(), &detail, &first);
                crate::events::emit_error("udp", &cs, &ds, &fr, &detail);
            } else {
                crate::stats::write_stat("gate_udp_dial_err", 1);
                let cur = a.reason_cloned();
                crate::log_gate::log_gate_err("udp", &cs, &ds, &cur.as_str(), &detail, &first);
                crate::events::emit_error("udp", &cs, &ds, &cur, &detail);
            }
            eprintln!("udp {cs} -> {ds} assoc fail (fail-closed): {detail}");
            shutdown(a, false).await;
            return;
        }
    };
    // 成功：state 已非 connecting（期间被关）→ 关掉新 socket 直接 return。
    let pending = {
        let mut mu = a.mu.lock().unwrap_or_else(|e| e.into_inner());
        if mu.state != UdpState::Connecting {
            drop(mu);
            drop(up_sock);
            drop(tcp_opt);
            return;
        }
        mu.up = Some(Arc::clone(&up_sock));
        mu.tcp = tcp_opt;
        mu.state = UdpState::Ready;
        std::mem::take(&mut mu.pending)
    };
    // 预热可写就绪：udp_send 经 try_send（同步）投递，首包若抢在任何 poll
    // 之前会撞上空就绪缓存而误报 WouldBlock；此处 await 一次 writable 把该位
    // 实质化（成功不清除，后续 try_send 直达 syscall）。
    let _ = tokio::time::timeout(Duration::from_secs(5), up_sock.writable()).await;
    // 统计顺序不可换：assoc → proxy|pass → rsn → log_gate（TCP handle_conn 同口径）。
    crate::stats::write_stat("gate_udp_assoc", 1);
    if proxy {
        crate::stats::write_stat("gate_proxy_udp", 1);
    } else {
        crate::stats::write_stat("gate_pass_udp", 1);
    }
    let cs = a.client.to_string();
    let ds = a.dst.to_string();
    let rsn = a.reason_cloned();
    let rsn = rsn.as_str();
    crate::stats::write_stat(&format!("gate_rsn_{rsn}"), 1);
    let verdict = if a.to_proxy.load(Ordering::SeqCst) {
        Verdict::Proxy
    } else {
        Verdict::Pass
    };
    crate::log_gate::log_gate("udp", &cs, &ds, verdict.as_str(), &rsn, &first);
    for p in &pending {
        let out = if proxy {
            crate::socks5::socks_encap(a.dst, p)
        } else {
            p.to_vec()
        };
        if up_sock.send(&out).await.is_err() {
            crate::stats::write_stat("gate_udp_write_err", 1);
            break;
        }
    }
    // 回包 pump（Go `go udpPump` 对等）：建链成功即按当前代次起泵。
    let generation = a.generation.load(Ordering::SeqCst);
    tokio::spawn(udp_pump(Arc::clone(a), generation, proxy));
}

/// 投递一个**未封装**的上行载荷（Go `(a *udpAssoc) send` 对等，P2-13）。
///
/// - connecting：`len<8` 深拷贝入队返回 Ok；`>=8` 写 `gate_udp_pending_drop` 返回 Ok
///   （静默丢弃，无背压，不关 assoc）；
/// - ready：在锁内按 `to_proxy` 现算封装后写（proxy 加 SOCKS5 UDP 头，直连零分配直写）；
/// - closed：`UdpSendErr::Closed`。
pub fn udp_send(a: &Arc<UdpAssoc>, raw: &[u8]) -> Result<(), UdpSendErr> {
    let mut mu = a.mu.lock().unwrap_or_else(|e| e.into_inner());
    match mu.state {
        UdpState::Connecting => {
            if mu.pending.len() >= PENDING_MAX {
                drop(mu);
                crate::stats::write_stat("gate_udp_pending_drop", 1);
                return Ok(());
            }
            mu.pending.push_back(raw.to_vec());
            Ok(())
        }
        UdpState::Ready => {
            let proxy = a.to_proxy.load(Ordering::SeqCst);
            let Some(ref up) = mu.up else {
                return Err(UdpSendErr::Closed);
            };
            // Go 同款：封装与写入在同一把锁内完成，撞不上换腿窗口。
            let r = if proxy {
                let out = crate::socks5::socks_encap(a.dst, raw);
                up.try_send(&out)
            } else {
                up.try_send(raw)
            };
            r.map(|_| ()).map_err(UdpSendErr::Io)
        }
        UdpState::Closed => Err(UdpSendErr::Closed),
    }
}

/// 当前上行腿快照（I3 重试用）：只克隆 `Arc`，不碰 state；调用方在锁外 await。
fn up_snapshot(a: &Arc<UdpAssoc>) -> Option<Arc<UdpSocket>> {
    a.mu.lock()
        .unwrap_or_else(|e| e.into_inner())
        .up
        .as_ref()
        .map(Arc::clone)
}

/// 唤醒 parked 在该 fd 上的 reader（回包泵的 `readable().timeout(120s)`）。
/// `shutdown` 不关 fd（关闭仍由 `Arc` drop 完成），只让 epoll 就绪位就绪，
/// 泵随即看到“代次不符/`up` 已空”条件退出。已有代次门做正确性兜底，
/// 此处只为把退出从“等足 120s”提前到“立即”。fd 已关等失败一律忽略。
fn wake_socket(fd: std::os::unix::io::RawFd) {
    // SAFETY：fd 为本 assoc 持有的活 socket（调用时仍在 Arc 内），只做 shutdown。
    unsafe {
        libc::shutdown(fd, libc::SHUT_RDWR);
    }
}

/// 收尾同步内核（Go `(a *udpAssoc) shutdown` 对等）：置 closed、移表、关 socket；
/// `emit=false` 用于建链失败（旧版失败不产生 uclose，事件流保持一致）。幂等。
fn shutdown_sync(a: &Arc<UdpAssoc>, emit: bool) {
    // 先快照待唤醒的 fd：shutdown 只唤醒 parked reader，不关 fd，
    // 与稍后锁内 `None` 覆盖（Arc drop 真关 fd）正交，可安全组合。
    let wake: Vec<std::os::unix::io::RawFd> = {
        let mu = a.mu.lock().unwrap_or_else(|e| e.into_inner());
        if mu.state == UdpState::Closed {
            return;
        }
        [
            mu.up.as_ref().map(|s| s.as_raw_fd()),
            mu.tcp.as_ref().map(|s| s.as_raw_fd()),
            mu.spoof.as_ref().map(|s| s.as_raw_fd()),
        ]
        .into_iter()
        .flatten()
        .collect()
    };
    {
        let mut mu = a.mu.lock().unwrap_or_else(|e| e.into_inner());
        if mu.state == UdpState::Closed {
            return;
        }
        mu.state = UdpState::Closed;
        mu.up = None;
        mu.tcp = None;
        mu.spoof = None;
        mu.pending.clear();
    }
    for fd in wake {
        wake_socket(fd);
    }
    table().remove_if_current(a);
    if emit {
        a.emit_uclose_once();
    }
    // socket 在锁内以 `None` 覆盖即关闭（emit 只读计数器/字符串，
    // 与关闭顺序无关；Go 先 emit 后关，此处等价）。
}

/// 收尾：置 closed、移表、关 socket；`emit=false` 用于建链失败（旧版失败不产生
/// uclose）。幂等。async 外壳供后台建链调用；[`reap`] 经同步内核复用同一语义。
#[allow(clippy::unused_async)]
pub async fn shutdown(a: &Arc<UdpAssoc>, emit: bool) {
    shutdown_sync(a, emit);
}

/// 清理超 idle 的 assoc，返回清理数（Go `reapUDPAssoc` 对等）。
///
/// 过期判定 `now - last > idle`（纳秒 wall 时钟，与建壳/收包的 `last` 同源）；
/// 移除后逐个 `shutdown(emit=true)`（正常 uclose 事件流）。
#[cfg(test)]
pub fn reap(table: &mut HashMap<String, Arc<UdpAssoc>>, idle: Duration) -> usize {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let idle_ns = idle.as_nanos().min(i64::MAX as u128) as i64;
    let mut dead = Vec::new();
    table.retain(|_, a| {
        if now - a.last_ns.load(Ordering::SeqCst) > idle_ns {
            dead.push(Arc::clone(a));
            false
        } else {
            true
        }
    });
    for a in &dead {
        shutdown_sync(a, true);
    }
    dead.len()
}

// ===== Task 18：表上限 / pump / 单向升级 / reap / serve_udp =====

/// 新 key 建壳上限（Go `udpAssocMax`）：`len(table) >= 512` 时整包丢弃，
/// 只记 `gate_udp_table_full`（无 assoc、无事件）。enforcement 落在
/// [`serve_udp`] 的每包查表分支（Task 17 只定义了 cap 未 enforcement）。
const UDP_ASSOC_MAX: usize = 512;

/// assoc idle 上限（Go `udpAssocIdle`）与 reap 周期（serve_udp 内 30s ticker）。
const UDP_ASSOC_IDLE: Duration = Duration::from_secs(120);
const REAP_INTERVAL: Duration = Duration::from_secs(30);

/// 单进程 wall-clock 纳秒（与建壳/收包/serve 循环的 `last` 同源）。
pub(crate) fn udp_now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// 惰性缓冲下一级：2→4→8→16→64 KB 阶梯（16KB 以下翻倍，以上直封 64KB 顶）。
///
/// 策略（本重写相对 Go 的核心内存优化）：泵缓冲起于 `cfg.udp_buf_kb * 1024`
/// （默认 2KB），只在 `recvmsg` 报 `MSG_TRUNC` 时翻一级、计
/// `gate_udp_buf_trunc`、**丢弃该包**后重试，封顶 64KB。此后同代次内不再收缩
/// （语音/视频包长一旦变大通常保持，收缩只会制造反复截断）。
/// 成本：满表 512 assoc 默认共 1MB（Go 每泵常驻 64KB → 约 32MB，
/// 常驻内存从 33.5MB 降至 ~1MB 即来自此处）。
fn next_buf_size(cur: usize) -> usize {
    const CAP: usize = 65535;
    if cur >= CAP {
        return CAP;
    }
    if cur < 16 * 1024 {
        (cur * 2).min(CAP)
    } else {
        CAP
    }
}

/// 回包泵（Go `udpPump` 对等）：upstream → client。
///
/// 下行发送口优先 spoof（源即服务端）；无 spoof 回退 `srv`（旧语义）。
/// `generation` 为泵代次：只有当代泵退出才关 assoc；旧泵每轮先查代次，
/// 换代即退（不迁新腿、不关 assoc）。
/// `proxy` 与建泵时的 socket 配对（升级后旧泵仍按旧直连语义读旧 socket）。
/// 退出条件：代次不符、任一读错（含 120s 无回包超时）或 `up` 被置空；
/// 出口按代次相等才 `shutdown(true)`（旧泵退出不关新连接）。
pub async fn udp_pump(a: Arc<UdpAssoc>, generation: i64, proxy: bool) {
    pump_loop(&a, generation, proxy).await;
    if a.generation.load(Ordering::SeqCst) == generation {
        shutdown(&a, true).await;
    }
}

/// 泵主循环（读侧）：每次读前设 120s deadline；proxy 先 `socks_decap`
/// （失败记 `gate_udp_decap_err` 并 continue，**不更新** last）；成功才更新
/// last/downPkts/downBytes；下行优先 spoof，写失败记
/// `gate_udp_spoof_write_fail` + 关 spoof 置空 + 回退 srv 重写一次，
/// srv 也失败则退出。
///
/// 读经 [`crate::origdst::udp_recvmsg`]（R5：`UdpSocket::recv` 报不出
/// `MSG_TRUNC`，惰性增长依赖该标志）。已连接上腿无 cmsg 期望，oob 仅占位。
async fn pump_loop(a: &Arc<UdpAssoc>, generation: i64, proxy: bool) {
    let mut size = a.buf_start.clamp(1, 65535);
    let mut buf = vec![0u8; size];
    let mut oob = [0u8; 64];
    let client = std::net::SocketAddr::V4(a.client);
    loop {
        // 代次门：换代后旧泵必须退出，绝不迁到新腿（旧泵持旧 socket 的 Arc，
        // drop(old) 关不掉 fd；若继续循环会读到新 proxy 腿却按 proxy=false
        // 语义处理——不解封装、与新泵分流下行）。门在读 mu.up 之前。
        if a.generation.load(Ordering::SeqCst) != generation {
            return;
        }
        let (up, w) = {
            let mu = a.mu.lock().unwrap_or_else(|e| e.into_inner());
            let w = mu
                .spoof
                .as_ref()
                .map(Arc::clone)
                .unwrap_or_else(|| Arc::clone(&a.srv));
            (mu.up.as_ref().map(Arc::clone), w)
        };
        let Some(up) = up else {
            return;
        };
        // 经 try_io 直读 raw fd：成功即处理；WouldBlock 时 try_io 已清掉
        // tokio 内部就绪位（raw 读绕过 try_recv，若只调 readable() 会因就绪位
        // 常置位空转饿死运行时），再等 120s 就绪后重试。
        let n = match up.try_io(tokio::io::Interest::READABLE, || {
            crate::origdst::udp_recvmsg(up.as_raw_fd(), &mut buf, &mut oob)
        }) {
            Ok((_n, _, _, true)) => {
                crate::stats::write_stat("gate_udp_buf_trunc", 1);
                size = next_buf_size(size);
                buf.resize(size, 0);
                continue;
            }
            Ok((n, _, _, false)) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                match tokio::time::timeout(UDP_ASSOC_IDLE, up.readable()).await {
                    Ok(Ok(())) => continue,
                    _ => return,
                }
            }
            Err(_) => return,
        };
        let payload: &[u8] = if proxy {
            match crate::socks5::socks_decap(&buf[..n]) {
                Ok(inner) => inner,
                Err(_) => {
                    crate::stats::write_stat("gate_udp_decap_err", 1);
                    continue;
                }
            }
        } else {
            &buf[..n]
        };
        a.last_ns.store(udp_now_ns(), Ordering::SeqCst);
        a.down_pkts.fetch_add(1, Ordering::SeqCst);
        a.down_bytes
            .fetch_add(payload.len() as u64, Ordering::SeqCst);
        if w.send_to(payload, client).await.is_err() {
            if Arc::ptr_eq(&w, &a.srv) {
                return;
            }
            // spoof 口发送失败（如透明发送被环境拒绝）：降级回 srv（旧语义），
            // 关闭坏口避免每包重复失败；srv 也失败才退出 pump。
            crate::stats::write_stat("gate_udp_spoof_write_fail", 1);
            {
                let mut mu = a.mu.lock().unwrap_or_else(|e| e.into_inner());
                if mu.spoof.is_some() {
                    mu.spoof = None;
                }
            }
            if a.srv.send_to(payload, client).await.is_err() {
                return;
            }
        }
    }
}

/// 单向升级触发器（Go `maybeUpgrade` 对等）：ALL THREE 同时成立才升级——
/// verdict==Proxy && `!to_proxy` && `state==Ready && !upgrading`。
/// 建链（`socks5_udp_associate`，最长 5s）放后台，绝不堵调用方；期间包继续
/// 走旧直连腿。proxy assoc 收到 pass 包永不降级（粘性语义不变）。
///
/// 成功：锁内换 `up`/`tcp`/`reason`、`to_proxy=true`、`generation+=1`，
/// 写 `gate_udp_upgrade` + `gate_rsn_<新reason>` + `log_gate`，关旧 socket，
/// 另起新泵（旧泵代次不符，退出时不关 assoc）。
/// 失败：`gate_udp_upgrade_fail` + reason 固定 `udp_upgrade_proxy_fail`，
/// 保持直连（旧腿仍可用）。
#[allow(clippy::unused_async)]
pub async fn maybe_upgrade(
    a: Arc<UdpAssoc>,
    cfg: &Config,
    verdict: Verdict,
    reason: Reason,
    first: &[u8],
) {
    if verdict != Verdict::Proxy || a.to_proxy.load(Ordering::SeqCst) {
        return;
    }
    {
        let mut mu = a.mu.lock().unwrap_or_else(|e| e.into_inner());
        if mu.state != UdpState::Ready || a.to_proxy.load(Ordering::SeqCst) || mu.upgrading {
            return;
        }
        mu.upgrading = true;
    }
    let proxy_socks = cfg.proxy_socks.clone();
    let first = first.to_vec();
    tokio::spawn(async move {
        match crate::socks5::socks5_udp_associate(&proxy_socks, Duration::from_secs(5)).await {
            Err(e) => {
                {
                    let mut mu = a.mu.lock().unwrap_or_else(|e| e.into_inner());
                    mu.upgrading = false;
                }
                crate::stats::write_stat("gate_udp_upgrade_fail", 1);
                let fr = Reason::UdpUpgradeProxyFail;
                let detail = e.to_string();
                let cs = a.client.to_string();
                let ds = a.dst.to_string();
                crate::log_gate::log_gate_err("udp", &cs, &ds, &fr.as_str(), &detail, &first);
                crate::events::emit_error("udp", &cs, &ds, &fr, &detail);
            }
            Ok((up, tcp)) => {
                let (old, new_generation) = {
                    let mut mu = a.mu.lock().unwrap_or_else(|e| e.into_inner());
                    if mu.state != UdpState::Ready {
                        mu.upgrading = false;
                        drop(mu);
                        drop(up);
                        drop(tcp);
                        return;
                    }
                    // P2-13：封装决策与换腿在同一把锁内——send 按当时腿现算，
                    // 不存在裸载荷落进 proxy socket 的窗口。
                    let old = mu.up.replace(Arc::new(up));
                    mu.tcp = Some(tcp);
                    mu.reason = reason;
                    a.to_proxy.store(true, Ordering::SeqCst);
                    let new_generation = a.generation.fetch_add(1, Ordering::SeqCst) + 1;
                    mu.upgrading = false;
                    (old, new_generation)
                };
                crate::stats::write_stat("gate_udp_upgrade", 1);
                crate::stats::write_stat(&format!("gate_rsn_{}", reason.as_str()), 1);
                let cs = a.client.to_string();
                let ds = a.dst.to_string();
                crate::log_gate::log_gate("udp", &cs, &ds, "proxy", &reason.as_str(), &first);
                // 唤醒 parked 在旧腿上的旧泵：它持有旧 fd 的 Arc 克隆，
                // 光 drop(old) 关不掉 fd（引用仍在旧泵手里），必须先 shutdown
                // 让它的 readable() 就绪返回，再由代次门退出。shutdown 不关 fd，
                // 与旧泵退出时 drop 克隆正交。
                if let Some(ref old_up) = old {
                    wake_socket(old_up.as_raw_fd());
                }
                drop(old);
                tokio::spawn(udp_pump(a, new_generation, true));
            }
        }
    });
}

/// 全局表 idle 清理（Go `reapUDPAssoc` 对等）：`now-last > idle` 移表 +
/// `shutdown(true)`，返回清理数。调用方（[`serve_udp`] 的 30s ticker）
/// 在 n>0 时记 `gate_udp_expire`=n。单元语义由 [`reap`] 的 HashMap 版钉死。
pub(crate) fn reap_udp_global(idle: Duration) -> usize {
    let now = udp_now_ns();
    let idle_ns = idle.as_nanos().min(i64::MAX as u128) as i64;
    let mut dead = Vec::new();
    {
        let mut m = table().inner.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, a| {
            if now - a.last_ns.load(Ordering::SeqCst) > idle_ns {
                dead.push(Arc::clone(a));
                false
            } else {
                true
            }
        });
    }
    for a in &dead {
        shutdown_sync(a, true);
    }
    dead.len()
}

/// 每包 od 门控顺序（Go `udp.go:663-682` 对等，不可换）：
/// 1. `WD_UDP_FIXED_DST` 非空且解析成功 → 覆盖 od（"跳过 origdst"）；
/// 2. `od.port == 0` → `OrigInvalid`；
/// 3. `is_local_dst` → `LocalDrop`。
///
/// 之后的 verdict/查表/建壳都对覆盖后的 od 算。解析失败保持原 od。
fn gate_udp_od(
    od: SocketAddrV4,
    fixed_dst: &str,
) -> Result<SocketAddrV4, (SocketAddrV4, &'static str)> {
    let mut od = od;
    if !fixed_dst.is_empty()
        && let Ok(fixed) = fixed_dst.parse::<SocketAddrV4>()
    {
        od = fixed;
    }
    if od.port() == 0 {
        return Err((od, "origdst_invalid"));
    }
    if crate::bufpool::is_local_dst(&IpAddr::V4(*od.ip())) {
        return Err((od, "local_drop"));
    }
    Ok(od)
}

/// 收包硬错路径：计数 `gate_udp_recv_err` + 采样调试日志（Go `udpErrLog`
/// 5s 限速口径）。
fn recv_err_log(client: &str, n: usize, od: &str, err: &str, first: &[u8]) {
    crate::stats::write_stat("gate_udp_recv_err", 1);
    crate::log_gate::udp_err_log(client, n, od, err, first);
}

/// UDP 门总入口（Go `serveUDP` 对等）。
///
/// `WD_UDP_LISTEN` 为 `""`/`"off"` → 直接 return（TCP 照常）。
/// 建监听：`socket(AF_INET, SOCK_DGRAM)` → `SO_REUSEADDR` →
/// `IP_RECVORIGDSTADDR`（失败 `udp gate %s: RECVORIGDSTADDR fail %v
/// (UDP门未启，TCP照常)` + return）→ `IP_TRANSPARENT`（失败同名措辞换
/// `TRANSPARENT`）→ `bind`。成功日志 `wxdet-gate udp on %s (proxy=%s)`。
///
/// 单次 recv 循环，`recvmsg` 用 65535 缓冲 + 256B oob（**全局唯一固定 64KB**；
/// 泵侧用惰性缓冲）。每包顺序（不可换，Go `udp.go:663-682`）：`WD_UDP_FIXED_DST`
/// 非空且解析成功 → 覆盖 od；`od.port==0` → `gate_udp_origdst_invalid`；
/// `is_local_dst` → `gate_udp_local_drop` + 限速日志（均见 [`gate_udp_od`]）；
/// 表满 → `gate_udp_table_full`；verdict → 建壳（新 key）/升级（旧 key）→
/// 计数 → `udp_send`。
pub async fn serve_udp(cfg: Arc<Config>, _shared: Arc<tokio::sync::RwLock<crate::lists::DlLists>>) {
    let listen = cfg.udp_listen_addr.clone();
    if listen.is_empty() || listen == "off" {
        return;
    }
    let std_sock = match udp_gate_bind(&listen) {
        Ok(s) => s,
        Err(m) => {
            eprintln!("{m}");
            return;
        }
    };
    let srv = match UdpSocket::from_std(std_sock) {
        Ok(u) => Arc::new(u),
        Err(e) => {
            eprintln!("udp gate {listen}: {e} (UDP门未启，TCP照常)");
            return;
        }
    };
    eprintln!("wxdet-gate udp on {listen} (proxy={})", cfg.proxy_socks);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REAP_INTERVAL);
        loop {
            ticker.tick().await;
            let n = reap_udp_global(UDP_ASSOC_IDLE);
            if n > 0 {
                crate::stats::write_stat("gate_udp_expire", n as u64);
            }
        }
    });
    let fd = srv.as_raw_fd();
    let mut buf = vec![0u8; 65535];
    let mut oob = vec![0u8; 256];
    loop {
        // 经 try_io 直读 raw fd（理由同 pump_loop：raw 读必须配 try_io 清就绪位，
        // 否则 readable() 常置位空转）。WouldBlock → 等就绪后重试。
        let (n, client, od) = match srv.try_io(tokio::io::Interest::READABLE, || {
            crate::origdst::udp_recvmsg(fd, &mut buf, &mut oob)
        }) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if srv.readable().await.is_err() {
                    crate::stats::write_stat("gate_udp_recv_err", 1);
                }
                continue;
            }
            Err(e) => {
                recv_err_log("unknown", 0, "0.0.0.0:0", &e.to_string(), &[]);
                continue;
            }
            Ok((n, client, None, _)) => {
                let end = n.min(buf.len());
                recv_err_log(
                    &client.to_string(),
                    n,
                    "0.0.0.0:0",
                    "no origdst cmsg",
                    &buf[..end],
                );
                continue;
            }
            Ok((n, client, Some(od), _)) => (n, client, od),
        };
        let now = udp_now_ns();
        let od = match gate_udp_od(od, &cfg.udp_fixed_dst) {
            Ok(od) => od,
            Err((eff, "origdst_invalid")) => {
                let _ = eff;
                crate::stats::write_stat("gate_udp_origdst_invalid", 1);
                continue;
            }
            Err((eff, _)) => {
                crate::stats::write_stat("gate_udp_local_drop", 1);
                crate::log_gate::log_udp_local_drop(
                    &client.to_string(),
                    &eff.to_string(),
                    &buf[..n.min(buf.len())],
                );
                continue;
            }
        };
        let key = udp_assoc_key(client, od);
        let hit = table().get(&key);
        if hit.is_none() && table().len() >= UDP_ASSOC_MAX {
            crate::stats::write_stat("gate_udp_table_full", 1);
            continue;
        }
        let (verdict, ureason) = crate::classify::udp_verdict(od.port(), &buf[..n.min(buf.len())]);
        let reason = Reason::Udp(ureason);
        let a = match hit {
            Some(a) => {
                a.last_ns.store(now, Ordering::SeqCst);
                maybe_upgrade(
                    Arc::clone(&a),
                    &cfg,
                    verdict,
                    reason,
                    &buf[..n.min(buf.len())],
                )
                .await;
                a
            }
            None => {
                start_udp_assoc(
                    &cfg,
                    Arc::clone(&srv),
                    client,
                    od,
                    verdict,
                    reason,
                    &buf[..n.min(buf.len())],
                )
                .await
            }
        };
        a.up_pkts.fetch_add(1, Ordering::SeqCst);
        a.up_bytes.fetch_add(n as u64, Ordering::SeqCst);
        if let Err(e) = udp_send(&a, &buf[..n.min(buf.len())]) {
            // I3：瞬时 WouldBlock（发送缓冲 momentarily 满）不得直接判死——
            // Go 阻塞 Write 会自然 ride through。此处已在锁外（udp_send 返回后），
            // 故可 await 可写后重试一次；重试仍失败才走致命路径。真错误与
            // Closed 照旧直接致命。重试与换腿窗口：udp_send 每次在锁内按当时腿
            // 现算封装，重试包不可能以错腿语义发出。
            let transient =
                matches!(&e, UdpSendErr::Io(io) if io.kind() == std::io::ErrorKind::WouldBlock);
            let recovered = transient
                && match up_snapshot(&a) {
                    Some(up) => {
                        let _ = tokio::time::timeout(Duration::from_secs(1), up.writable()).await;
                        udp_send(&a, &buf[..n.min(buf.len())]).is_ok()
                    }
                    None => false,
                };
            if !recovered {
                let r = a.reason_cloned();
                crate::events::emit_error(
                    "udp",
                    &client.to_string(),
                    &od.to_string(),
                    &r,
                    &e.to_string(),
                );
                crate::stats::write_stat("gate_udp_write_err", 1);
                shutdown(&a, true).await;
            }
        }
    }
}

/// UDP 门监听 socket：raw 建 fd → `SO_REUSEADDR` → `IP_RECVORIGDSTADDR` →
/// `IP_TRANSPARENT` → `bind`（顺序与 [`serve_udp`] 文档一致）。
/// 任一步失败返回已格式化的 stderr 行（调用方直接 `eprintln!` 后 return）。
fn udp_gate_bind(listen: &str) -> Result<std::net::UdpSocket, String> {
    use std::os::unix::io::FromRawFd;
    let gate_down =
        |e: &dyn std::fmt::Display| format!("udp gate {listen}: {e} (UDP门未启，TCP照常)");
    let addr: SocketAddrV4 = listen
        .parse()
        .map_err(|e| gate_down(&e as &dyn std::fmt::Display))?;
    // SAFETY：fd 建后即由守卫持有，任一 early-return 关 fd（Go 无此路径，Rust RAII）。
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(gate_down(&std::io::Error::last_os_error()));
    }
    struct Guard(std::os::unix::io::RawFd);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let guard = Guard(fd);
    let one: libc::c_int = 1;
    // SAFETY：one 指向合法 c_int，长度匹配。
    let rc = unsafe {
        libc::setsockopt(
            guard.0,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(gate_down(&std::io::Error::last_os_error()));
    }
    if let Err(e) = crate::origdst::enable_recv_orig_dst(guard.0) {
        return Err(format!(
            "udp gate {listen}: RECVORIGDSTADDR fail {e} (UDP门未启，TCP照常)"
        ));
    }
    if let Err(e) = crate::origdst::enable_transparent(guard.0) {
        return Err(format!(
            "udp gate {listen}: TRANSPARENT fail {e} (UDP门未启，TCP照常)"
        ));
    }
    // s_addr 为网络字节序：内存字节恰为 ip 四元组（`from_ne_bytes`）。
    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY：sa 指向合法 sockaddr_in，长度匹配。
    let rc = unsafe {
        libc::bind(
            guard.0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(gate_down(&std::io::Error::last_os_error()));
    }
    // SAFETY：fd 已 bind 成功，转交 std socket；forget 守卫避免 double-close。
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(guard.0) };
    std::mem::forget(guard);
    // tokio 只接管非阻塞 std socket（失败时 std_sock 析构关 fd）。
    std_sock.set_nonblocking(true).map_err(|e| gate_down(&e))?;
    Ok(std_sock)
}

/// 建下行 spoof 发送口（Go `spoofUDP` 对等）：`IP_TRANSPARENT` + bind 到对端地址
/// （`od.ip:od.port`），下行经它发出时客户端看到的源即服务端地址。
///
/// 同一 od 多 assoc 复用同一地址 bind，需 `SO_REUSEADDR`（只发不收，不抢 up 腿
/// 的回包）。任一步失败关 fd；调用方（建壳）回退 `srv`（旧语义）。
/// 非 v4 在类型层面不可表达（`SocketAddrV4`）；port 0 拒绝，串
/// `spoof needs ipv4 dst`（Go 原文）。
pub async fn spoof_udp(od: SocketAddrV4) -> std::io::Result<UdpSocket> {
    use std::os::unix::io::FromRawFd;
    if od.port() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "spoof needs ipv4 dst",
        ));
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // RAII：任一 early-return 关 fd（Go `done` 旗标对等）。
    struct FdGuard(std::os::unix::io::RawFd);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let guard = FdGuard(fd);
    let one: libc::c_int = 1;
    let r = unsafe {
        libc::setsockopt(
            guard.0,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    const IP_TRANSPARENT: libc::c_int = 19;
    let r = unsafe {
        libc::setsockopt(
            guard.0,
            libc::IPPROTO_IP,
            IP_TRANSPARENT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // s_addr 为网络字节序：内存字节恰为 ip 四元组（`from_ne_bytes`）。
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: od.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(od.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    let r = unsafe {
        libc::bind(
            guard.0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(guard.0) };
    std::mem::forget(guard);
    // tokio 只接管非阻塞 std socket（失败时 std_sock 析构关 fd）。
    std_sock.set_nonblocking(true)?;
    UdpSocket::from_std(std_sock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reason::{Reason, UdpReason, Verdict};
    use std::net::SocketAddrV4;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn slow_connect_does_not_block_and_pending_caps_at_8() {
        let tag = "udp_slow_connect";
        // 假 proxy 上游会延迟回复 ASSOCIATE，制造 connecting 窗口
        let (_, proxy, _hits) =
            crate::testutil::spawn_fake_socks_delayed(0, Duration::from_millis(300)).await;
        // R26：串行锁内做"清文件→重定向"（config_with_socks 先清文件，
        // 再 reset_* 重定向句柄；顺序反了读到的是已 unlink 的旧句柄）。
        let cfg = {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let cfg = crate::testutil::config_with_socks(tag, "127.0.0.1:1", &proxy);
            crate::testutil::reset_stats(tag);
            crate::testutil::reset_logs(tag);
            crate::testutil::reset_events(tag);
            cfg
        };
        let srv = crate::testutil::fake_udp_srv().await;
        let client: SocketAddrV4 = "192.168.71.50:51000".parse().unwrap();
        let od: SocketAddrV4 = "1.2.3.4:3478".parse().unwrap();

        let t = Instant::now();
        let a = start_udp_assoc(
            &cfg,
            srv,
            client,
            od,
            Verdict::Proxy,
            Reason::Udp(UdpReason::UdpProxy),
            &[],
        )
        .await;
        assert!(t.elapsed() < Duration::from_millis(50), "建壳必须立即返回");
        assert_eq!(
            crate::testutil::stat_value(tag, "gate_udp_assoc"),
            0,
            "connecting 期不得计 assoc"
        );
        for i in 0..8 {
            assert!(
                udp_send(&a, &[i as u8; 13]).is_ok(),
                "第 {} 个应入队",
                i + 1
            );
        }
        assert!(udp_send(&a, &[9u8; 13]).is_ok(), "第 9 个静默丢弃但返回 Ok");
        assert_eq!(crate::testutil::stat_value(tag, "gate_udp_pending_drop"), 1);
        assert_eq!(
            crate::testutil::read_events(tag).lines().count(),
            1,
            "只有 open，还没 uclose"
        );

        // 放行后：ready、gate_udp_assoc=1、gate_proxy_udp=1，且 pending 已被冲刷
        crate::testutil::wait_until(|| crate::testutil::stat_value(tag, "gate_udp_assoc") == 1)
            .await;
        assert_eq!(crate::testutil::stat_value(tag, "gate_proxy_udp"), 1);
        assert_eq!(a.state(), UdpState::Ready);
        // 收尾移表：本表是进程级全局，残留会串扰后继用例的表长断言；
        // 所有 brief 断言已在此行前完成。
        shutdown(&a, true).await;
    }

    #[tokio::test]
    async fn proxy_assoc_failure_self_removes_and_stays_proxy() {
        let tag = "udp_proxy_fail";
        // proxy 上游指向关闭端口
        let cfg = {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let cfg = crate::testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
            crate::testutil::reset_stats(tag);
            crate::testutil::reset_logs(tag);
            crate::testutil::reset_events(tag);
            cfg
        };
        let srv = crate::testutil::fake_udp_srv().await;
        let client: SocketAddrV4 = "192.168.71.50:51001".parse().unwrap();
        let od: SocketAddrV4 = "1.2.3.4:3478".parse().unwrap();

        let a = start_udp_assoc(
            &cfg,
            srv,
            client,
            od,
            Verdict::Proxy,
            Reason::Udp(UdpReason::StunUdp),
            &[],
        )
        .await;
        crate::testutil::wait_until(|| {
            crate::testutil::stat_value(tag, "gate_proxy_udp_fail") == 1
        })
        .await;
        assert_eq!(udp_table_len(), 0, "失败后必须自己移表");
        assert!(a.to_proxy(), "不得回退 pass");
        // open + error 两行，且**不发 uclose**
        let s = crate::testutil::read_events(tag);
        assert_eq!(s.lines().count(), 2, "必须是 open + error：{s}");
        assert!(s.contains("\"event\":\"error\""));
        assert!(!s.contains("\"event\":\"uclose\""));
    }

    #[tokio::test]
    async fn spoof_rejects_bad_dst_and_allows_second_bind() {
        assert!(
            spoof_udp("1.2.3.4:0".parse().unwrap()).await.is_err(),
            "port 0 必须拒绝"
        );
        // 非 v4 在类型层面已不可表达（SocketAddrV4），故只需覆盖 port 0 与二次 bind
        let a = spoof_udp("1.2.3.4:5000".parse().unwrap()).await;
        if a.is_err() {
            return; // 无 CAP_NET_ADMIN/root 环境跳过（与 Go TestSpoofUDPForeignBind 同口径）
        }
        assert!(
            spoof_udp("1.2.3.4:5000".parse().unwrap()).await.is_ok(),
            "SO_REUSEADDR 允许二次 bind"
        );
    }

    /// `reap` 语义钉死（Task 18 的 30s 清理勾子依赖）：超 idle 的移表+计数+uclose，
    /// 新鲜的保留，空表返回 0。后台建链用 5s 延迟假上游钉在 connecting，
    /// 两个 assoc 的新旧全由 `last_ns` 显式控制，无时间竞态。
    #[tokio::test]
    async fn reap_removes_only_idle_entries() {
        use std::collections::HashMap;
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        let tag = "udp_reap";
        let (_, proxy, _hits) =
            crate::testutil::spawn_fake_socks_delayed(0, Duration::from_secs(5)).await;
        let (cfg, dir) = {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let cfg = crate::testutil::config_with_socks(tag, "127.0.0.1:1", &proxy);
            let dir = crate::testutil::reset_stats(tag);
            crate::testutil::reset_logs(tag);
            crate::testutil::reset_events(tag);
            (cfg, dir)
        };
        let srv = crate::testutil::fake_udp_srv().await;
        let mk = |port: u16| {
            let cfg = &cfg;
            let srv = Arc::clone(&srv);
            async move {
                start_udp_assoc(
                    cfg,
                    srv,
                    format!("192.168.71.50:{port}").parse().unwrap(),
                    "1.2.3.4:3478".parse().unwrap(),
                    Verdict::Proxy,
                    Reason::Udp(UdpReason::UdpProxy),
                    &[],
                )
                .await
            }
        };
        let fresh = mk(51010).await;
        let old = mk(51011).await;
        // 背景建链 5s 后才就绪：此刻两个都是 connecting，last 都新鲜。
        // 把 old 的 last 拨到 1h 前（子模块可写父结构体私有字段）。
        old.last_ns.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| (d.as_nanos() as i64).saturating_sub(3_600_000_000_000))
                .unwrap_or(0),
            Ordering::SeqCst,
        );
        let mut m = HashMap::new();
        m.insert(fresh.key.clone(), Arc::clone(&fresh));
        m.insert(old.key.clone(), Arc::clone(&old));
        assert_eq!(reap(&mut HashMap::new(), Duration::from_secs(120)), 0);
        assert_eq!(reap(&mut m, Duration::from_secs(120)), 1);
        assert!(m.contains_key(&fresh.key));
        assert!(!m.contains_key(&old.key));
        assert_eq!(old.state(), UdpState::Closed);
        // old 的 uclose 已发（open×2 + uclose×1）；fresh 不动。
        let s = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        assert_eq!(s.lines().count(), 3, "应为 open×2 + uclose×1：{s}");
        // 收尾：fresh 仍在全局表，移掉以免串扰他例的表长断言。
        shutdown(&fresh, true).await;
    }

    /// 127.0.0.1 回显 UDP 对端：原样弹回收到的包；返回（地址，收包计数）。
    async fn spawn_udp_echo() -> (SocketAddrV4, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = match s.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let hits = Arc::new(AtomicUsize::new(0));
        let h = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut b = vec![0u8; 65535];
            loop {
                let Ok((n, from)) = s.recv_from(&mut b).await else {
                    return;
                };
                h.fetch_add(1, Ordering::SeqCst);
                if s.send_to(&b[..n], &from).await.is_err() {
                    return;
                }
            }
        });
        (addr, hits)
    }

    /// proxy 假上游：ASSOCIATE 回一个"原样弹回封装包"的中继口。
    /// 返回（proxy 地址，中继收包计数，末包原文）。
    async fn spawn_proxy_echo_relay() -> (
        String,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<Mutex<Vec<u8>>>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rport = relay.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let last = Arc::new(Mutex::new(Vec::new()));
        {
            let hits = Arc::clone(&hits);
            let last = Arc::clone(&last);
            tokio::spawn(async move {
                let mut b = vec![0u8; 65535];
                loop {
                    let Ok((n, from)) = relay.recv_from(&mut b).await else {
                        return;
                    };
                    hits.fetch_add(1, Ordering::SeqCst);
                    *last.lock().unwrap_or_else(|e| e.into_inner()) = b[..n].to_vec();
                    if relay.send_to(&b[..n], &from).await.is_err() {
                        return;
                    }
                }
            });
        }
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = ln.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = ln.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut g = [0u8; 3];
                    if c.read_exact(&mut g).await.is_err() {
                        return;
                    }
                    if c.write_all(&[5, 0]).await.is_err() {
                        return;
                    }
                    let mut req = [0u8; 10];
                    if c.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let _ = c
                        .write_all(&[
                            5,
                            0,
                            0,
                            1,
                            127,
                            0,
                            0,
                            1,
                            (rport >> 8) as u8,
                            (rport & 0xff) as u8,
                        ])
                        .await;
                    let mut b = [0u8; 1500];
                    loop {
                        match c.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });
        (proxy, hits, last)
    }

    fn v4_of(sa: std::net::SocketAddr) -> SocketAddrV4 {
        match sa {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        }
    }

    fn stun_req() -> Vec<u8> {
        vec![
            0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87,
            0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1,
        ]
    }

    #[tokio::test]
    async fn upgrade_is_one_way_and_encap_decided_under_lock() {
        use std::sync::atomic::Ordering;
        let tag = "udp_upgrade_oneway";
        let (echo_addr, echo_hits) = spawn_udp_echo().await;
        let (proxy_addr, relay_hits, relay_last) = spawn_proxy_echo_relay().await;
        let cfg = {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let cfg = crate::testutil::config_with_socks(tag, "127.0.0.1:1", &proxy_addr);
            crate::testutil::reset_stats(tag);
            crate::testutil::reset_logs(tag);
            crate::testutil::reset_events(tag);
            cfg
        };
        let srv = crate::testutil::fake_udp_srv().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_v4 = v4_of(client.local_addr().unwrap());
        // pass 建立后喂直连腿裸包 → 对端收到裸载荷
        let a = start_udp_assoc(
            &cfg,
            srv,
            client_v4,
            echo_addr,
            Verdict::Pass,
            Reason::Udp(UdpReason::UdpDirect),
            b"pass-leg",
        )
        .await;
        crate::testutil::wait_until(|| a.state() == UdpState::Ready).await;
        assert!(!a.to_proxy());
        udp_send(&a, b"raw-1").unwrap();
        let mut rb = [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut rb))
            .await
            .expect("直连腿回包超时")
            .unwrap();
        assert_eq!(&rb[..n], b"raw-1", "直连腿必须收到裸载荷");
        // 触发升级（喂 STUN 形状包）→ gate_udp_upgrade=1
        let stun = stun_req();
        maybe_upgrade(
            Arc::clone(&a),
            &cfg,
            Verdict::Proxy,
            Reason::Udp(UdpReason::StunUdp),
            &stun,
        )
        .await;
        crate::testutil::wait_until(|| a.to_proxy()).await;
        assert_eq!(
            crate::testutil::stat_value(tag, "gate_udp_upgrade"),
            1,
            "升级必须计 1 次"
        );
        assert_eq!(
            crate::testutil::stat_value(tag, "gate_rsn_stun_udp"),
            1,
            "升级必须记新 reason 维度"
        );
        // 再喂同一原始载荷 → 必须带 SOCKS5 头落到 proxy 腿，直连腿颗粒无收
        let direct_n = echo_hits.load(Ordering::SeqCst);
        udp_send(&a, b"raw-1").unwrap();
        crate::testutil::wait_until(|| relay_hits.load(Ordering::SeqCst) >= 1).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            echo_hits.load(Ordering::SeqCst),
            direct_n,
            "升级后直连腿不得再收到包"
        );
        let last = relay_last.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            last,
            crate::socks5::socks_encap(echo_addr, b"raw-1"),
            "proxy 腿必须收到封装后的包（裸载荷=换腿窗口漏洞）"
        );
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut rb))
            .await
            .expect("升级后回包超时")
            .unwrap();
        assert_eq!(&rb[..n], b"raw-1", "升级后回包应解封装为内层载荷");
        // 再喂 pass 判定包 → 不得降级，升级计数不增
        maybe_upgrade(
            Arc::clone(&a),
            &cfg,
            Verdict::Pass,
            Reason::Udp(UdpReason::UdpDirect),
            b"raw-1",
        )
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(a.to_proxy(), "proxy assoc 不许被降级");
        assert_eq!(
            crate::testutil::stat_value(tag, "gate_udp_upgrade"),
            1,
            "降级不该计升级"
        );
        shutdown(&a, true).await;
    }

    #[tokio::test]
    async fn upgrade_failure_keeps_direct_usable() {
        let tag = "udp_upgrade_failkeep";
        let (echo_addr, _hits) = spawn_udp_echo().await;
        // 必关端口：升级必败
        let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = tmp.local_addr().unwrap().to_string();
        drop(tmp);
        let cfg = {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let cfg = crate::testutil::config_with_socks(tag, "127.0.0.1:1", &dead);
            crate::testutil::reset_stats(tag);
            crate::testutil::reset_logs(tag);
            crate::testutil::reset_events(tag);
            cfg
        };
        let srv = crate::testutil::fake_udp_srv().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_v4 = v4_of(client.local_addr().unwrap());
        let a = start_udp_assoc(
            &cfg,
            srv,
            client_v4,
            echo_addr,
            Verdict::Pass,
            Reason::Udp(UdpReason::UdpDirect),
            b"still-pass",
        )
        .await;
        crate::testutil::wait_until(|| a.state() == UdpState::Ready).await;
        // proxy 腿不可达：gate_udp_upgrade_fail>=1，to_proxy=false，直连 send 仍可用
        let stun = stun_req();
        maybe_upgrade(
            Arc::clone(&a),
            &cfg,
            Verdict::Proxy,
            Reason::Udp(UdpReason::StunUdp),
            &stun,
        )
        .await;
        crate::testutil::wait_until(|| {
            crate::testutil::stat_value(tag, "gate_udp_upgrade_fail") >= 1
        })
        .await;
        assert!(!a.to_proxy(), "升级失败不该置 proxy");
        udp_send(&a, b"still-pass").unwrap();
        let mut rb = [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut rb))
            .await
            .expect("升级失败后直连回包超时")
            .unwrap();
        assert_eq!(&rb[..n], b"still-pass", "升级失败后直连中继应仍可用");
        // 且 reason 必须是字面量 udp_upgrade_proxy_fail
        let g = crate::testutil::read_gate_log(tag);
        assert!(
            g.contains("udp_upgrade_proxy_fail"),
            "gate.log err 行 reason 必须是 udp_upgrade_proxy_fail: {g}"
        );
        let ev = crate::testutil::read_events(tag);
        assert!(
            ev.contains("udp_upgrade_proxy_fail"),
            "error 事件 reason 必须是 udp_upgrade_proxy_fail: {ev}"
        );
        shutdown(&a, true).await;
    }

    #[tokio::test]
    async fn pump_prefers_spoof_for_downlink_source() {
        // 有 spoof 时下行源 == spoof 口地址；无 spoof 时 == srv。
        async fn pump_case(
            with_spoof: bool,
        ) -> (
            std::net::SocketAddr,
            Option<std::net::SocketAddr>,
            std::net::SocketAddr,
        ) {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_v4 = v4_of(client.local_addr().unwrap());
            let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let srv_sa = srv.local_addr().unwrap();
            let svc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            up.connect(svc.local_addr().unwrap()).await.unwrap();
            let up_peer = up.local_addr().unwrap();
            let spoof_sa = if with_spoof {
                let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let sa = s.local_addr().unwrap();
                Some((Arc::new(s), sa))
            } else {
                None
            };
            let (spoof_opt, spoof_addr) = match spoof_sa {
                Some((s, sa)) => (Some(s), Some(sa)),
                None => (None, None),
            };
            let now = udp_now_ns();
            let a = Arc::new(UdpAssoc {
                key: format!("pump-spoof-{with_spoof}"),
                client: client_v4,
                dst: "203.0.113.9:20501".parse().unwrap(),
                srv: Arc::new(srv),
                mu: Mutex::new(AssocMu {
                    state: UdpState::Ready,
                    up: Some(Arc::new(up)),
                    tcp: None,
                    spoof: spoof_opt,
                    pending: VecDeque::new(),
                    upgrading: false,
                    reason: Reason::Udp(UdpReason::UdpDirect),
                }),
                to_proxy: AtomicBool::new(false),
                generation: AtomicI64::new(0),
                buf_start: 2048,
                start_ns: AtomicI64::new(now),
                last_ns: AtomicI64::new(now),
                up_pkts: AtomicU64::new(0),
                down_pkts: AtomicU64::new(0),
                up_bytes: AtomicU64::new(0),
                down_bytes: AtomicU64::new(0),
                close_once: std::sync::Once::new(),
            });
            tokio::spawn(udp_pump(Arc::clone(&a), 0, false));
            let payload = b"downlink-probe";
            svc.send_to(payload, up_peer).await.unwrap();
            let mut rb = [0u8; 1500];
            let (n, from) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut rb))
                .await
                .expect("下行超时")
                .unwrap();
            assert_eq!(&rb[..n], payload, "下行载荷不得被改动");
            shutdown(&a, true).await;
            (from, spoof_addr, srv_sa)
        }
        let tag = "udp_pump_spoof";
        {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let _cfg = crate::testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
            crate::testutil::reset_stats(tag);
            crate::testutil::reset_logs(tag);
            crate::testutil::reset_events(tag);
        }
        let (from, spoof_addr, srv_sa) = pump_case(true).await;
        assert_eq!(
            from,
            spoof_addr.unwrap(),
            "有 spoof 时下行源必须是 spoof 口（srv 为 {srv_sa}，实得 {from}）"
        );
        let (from, _, srv_sa) = pump_case(false).await;
        assert_eq!(from, srv_sa, "无 spoof 时下行源必须回退 srv（实得 {from}）");
    }

    #[test]
    fn buf_growth_ladder_and_cap() {
        // 惰性缓冲阶梯（2→4→8→16→64KB）+ 封顶分支的纯函数单测：16KB 以下翻倍，
        // 16KB（含）以上直封顶，达到/超过 CAP 后恒为 CAP。
        assert_eq!(next_buf_size(1024), 2048);
        assert_eq!(next_buf_size(2048), 4096);
        assert_eq!(next_buf_size(4096), 8192);
        assert_eq!(next_buf_size(8192), 16384);
        assert_eq!(next_buf_size(16384), 65535);
        assert_eq!(next_buf_size(32768), 65535);
        assert_eq!(next_buf_size(65535), 65535);
        assert_eq!(next_buf_size(1_000_000), 65535);
    }

    #[tokio::test]
    async fn old_pump_exits_on_generation_mismatch() {
        // Finding 1 回归：旧泵每轮先查代次，换代即退，绝不迁到新腿。
        // 无此门时旧泵重读 mu.up 会迁到新腿继续泵水，JoinHandle 永不完成。
        // 注：此处只换 up＋代次＋1（与 maybe_upgrade 成功分支同序），不翻
        // to_proxy——代次门在任何 proxy 逻辑之前求值，与腿语义正交。
        use std::sync::atomic::Ordering;
        let tag = "udp_old_pump_exit";
        let (echo_b, _) = spawn_udp_echo().await;
        {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let _cfg = crate::testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
            crate::testutil::reset_stats(tag);
            crate::testutil::reset_logs(tag);
            crate::testutil::reset_events(tag);
        }
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_v4 = v4_of(client.local_addr().unwrap());
        let srv = crate::testutil::fake_udp_srv().await;
        // 腿 A：直连回显对端。peer 由 Arc 共享——既做回显，又充当唤醒源
        // （up_a 为 connected socket，内核只收 peer 来包，第三方直发必被过滤，
        // 故唤醒包必须经 peer 发出）。
        let peer_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer_a_addr = peer_a.local_addr().unwrap();
        {
            let peer_a = Arc::clone(&peer_a);
            tokio::spawn(async move {
                let mut b = vec![0u8; 65535];
                loop {
                    match peer_a.recv_from(&mut b).await {
                        Ok((n, from)) => {
                            if peer_a.send_to(&b[..n], &from).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
        let up_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        up_a.connect(peer_a_addr).await.unwrap();
        let _ = up_a.writable().await;
        let up_a_local = up_a.local_addr().unwrap();
        let now = udp_now_ns();
        let a = Arc::new(UdpAssoc {
            key: "old-pump-exit".into(),
            client: client_v4,
            dst: v4_of(peer_a_addr),
            srv,
            mu: Mutex::new(AssocMu {
                state: UdpState::Ready,
                up: Some(Arc::new(up_a)),
                tcp: None,
                spoof: None,
                pending: VecDeque::new(),
                upgrading: false,
                reason: Reason::Udp(UdpReason::UdpDirect),
            }),
            to_proxy: AtomicBool::new(false),
            generation: AtomicI64::new(0),
            buf_start: 512,
            start_ns: AtomicI64::new(now),
            last_ns: AtomicI64::new(now),
            up_pkts: AtomicU64::new(0),
            down_pkts: AtomicU64::new(0),
            up_bytes: AtomicU64::new(0),
            down_bytes: AtomicU64::new(0),
            close_once: std::sync::Once::new(),
        });
        let h_old = tokio::spawn(udp_pump(Arc::clone(&a), 0, false));
        // 基线：旧泵活着并服务。
        udp_send(&a, b"alive").unwrap();
        let mut rb = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut rb))
            .await
            .expect("基线回包超时")
            .unwrap();
        assert_eq!(&rb[..n], b"alive");
        // 模拟升级换腿：锁内换 up＋代次+1（顺序与 maybe_upgrade 成功分支一致）。
        let up_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        up_b.connect(std::net::SocketAddr::V4(echo_b))
            .await
            .unwrap();
        let _ = up_b.writable().await;
        {
            let mut mu = a.mu.lock().unwrap_or_else(|e| e.into_inner());
            mu.up = Some(Arc::new(up_b));
            a.generation.fetch_add(1, Ordering::SeqCst);
        }
        let h_new = tokio::spawn(udp_pump(Arc::clone(&a), 1, false));
        // 唤醒 parked 在旧腿上的旧泵：唤醒包必须经 peer 发出（connected
        // socket 过滤非 peer 源）。有代次门则它在循环顶部直接返回；
        // 无门则它重读 mu.up 迁到新腿，h_old 永不完成。
        peer_a.send_to(b"wake", up_a_local).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), h_old)
            .await
            .expect("旧泵必须换代即退（否则已迁到新腿）")
            .unwrap();
        // 旧泵退出不得关 assoc：新泵照常服务新腿。
        assert_eq!(a.state(), UdpState::Ready);
        udp_send(&a, b"via-new").unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut rb))
            .await
            .expect("新泵回包超时")
            .unwrap();
        assert_eq!(&rb[..n], b"via-new");
        shutdown(&a, true).await;
        h_new.abort();
    }

    #[tokio::test]
    async fn shutdown_wakes_parked_pumps_bounded() {
        // I1 回归（churn 证据）：N 个 assoc 的泵全部静默 parked 在
        // `readable().timeout(120s)` 上时，逐个 shutdown 后所有泵必须在有界
        // 时间内退出，而非等足 120s 再关。修复前 shutdown 只 drop `Arc`，
        // 旧泵手持克隆 fd 继续 park（fd/64KB 缓冲滞留），本断言 5s 超时失败。
        let tag = "udp_churn_wake";
        {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let _cfg = crate::testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
            crate::testutil::reset_stats(tag);
            crate::testutil::reset_logs(tag);
            crate::testutil::reset_events(tag);
        }
        const N: usize = 8;
        let mut assocs = Vec::new();
        let mut handles = Vec::new();
        for i in 0..N {
            // 回显对端：只收不主动发，泵无包可读即 park（与 idle assoc 同态）。
            let peer = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            {
                let peer = Arc::clone(&peer);
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65535];
                    loop {
                        match peer.recv_from(&mut b).await {
                            Ok((n, from)) => {
                                if peer.send_to(&b[..n], &from).await.is_err() {
                                    return;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                });
            }
            let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            up.connect(peer.local_addr().unwrap()).await.unwrap();
            let _ = up.writable().await;
            let srv = crate::testutil::fake_udp_srv().await;
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_v4 = v4_of(client.local_addr().unwrap());
            let now = udp_now_ns();
            let a = Arc::new(UdpAssoc {
                key: format!("churn-wake-{i}"),
                client: client_v4,
                dst: v4_of(peer.local_addr().unwrap()),
                srv,
                mu: Mutex::new(AssocMu {
                    state: UdpState::Ready,
                    up: Some(Arc::new(up)),
                    tcp: None,
                    spoof: None,
                    pending: VecDeque::new(),
                    upgrading: false,
                    reason: Reason::Udp(UdpReason::UdpDirect),
                }),
                to_proxy: AtomicBool::new(false),
                generation: AtomicI64::new(0),
                buf_start: 2048,
                start_ns: AtomicI64::new(now),
                last_ns: AtomicI64::new(now),
                up_pkts: AtomicU64::new(0),
                down_pkts: AtomicU64::new(0),
                up_bytes: AtomicU64::new(0),
                down_bytes: AtomicU64::new(0),
                close_once: std::sync::Once::new(),
            });
            handles.push(tokio::spawn(udp_pump(Arc::clone(&a), 0, false)));
            assocs.push(a);
        }
        // 给泵留足进入 readable() park 的时间（零流量，必 park 不退出）。
        tokio::time::sleep(Duration::from_millis(300)).await;
        let t = std::time::Instant::now();
        for a in &assocs {
            shutdown(a, true).await;
        }
        for h in handles {
            tokio::time::timeout(Duration::from_secs(5), h)
                .await
                .expect("泵必须在 shutdown 后 5s 内退出（否则仍在 park 滞留 fd/缓冲）")
                .unwrap();
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "N={N} 泵总退出耗时必须有界"
        );
        for a in &assocs {
            assert_eq!(a.state(), UdpState::Closed);
        }
    }

    #[tokio::test]
    async fn buffer_grows_lazily_from_configured_start() {
        // 本沙箱回环 UDP 仅能承载 ≤1200B 的包（>1400B 静默丢弃，send 仍报 Ok），
        // 故增长夹具取小步：buf_start=512B → big=1000B（可达但容不下）→
        // 截断丢弃+计数 → 缓冲 512→1024 → 重发 big 直通。
        let tag = "udp_buf_grow";
        let (echo_addr, _hits) = spawn_udp_echo().await;
        let cfg = {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let cfg = crate::testutil::config_with_socks(tag, "127.0.0.1:1", "127.0.0.1:1");
            crate::testutil::reset_stats(tag);
            crate::testutil::reset_logs(tag);
            crate::testutil::reset_events(tag);
            cfg
        };
        // 起始按 cfg.udp_buf_kb（建壳装配不断言泵行为，只查字段）。
        assert_eq!(cfg.udp_buf_kb, 2);
        let srv = crate::testutil::fake_udp_srv().await;
        let client_probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_probe_v4 = v4_of(client_probe.local_addr().unwrap());
        let wired = start_udp_assoc(
            &cfg,
            srv,
            client_probe_v4,
            echo_addr,
            Verdict::Pass,
            Reason::Udp(UdpReason::UdpDirect),
            b"base",
        )
        .await;
        assert_eq!(
            wired.buf_start,
            cfg.udp_buf_kb * 1024,
            "泵缓冲必须起于配置值"
        );
        shutdown(&wired, true).await;
        // 增长行为夹具：手工 assoc（buf_start=512），直连回显对端。
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_v4 = v4_of(client.local_addr().unwrap());
        let srv = crate::testutil::fake_udp_srv().await;
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        up.connect(std::net::SocketAddr::V4(echo_addr))
            .await
            .unwrap();
        // 首个 try_send 前实质化可写位（见 connect_assoc 预热注释）。
        let _ = up.writable().await;
        let now = udp_now_ns();
        let a = Arc::new(UdpAssoc {
            key: "buf-grow".into(),
            client: client_v4,
            dst: echo_addr,
            srv,
            mu: Mutex::new(AssocMu {
                state: UdpState::Ready,
                up: Some(Arc::new(up)),
                tcp: None,
                spoof: None,
                pending: VecDeque::new(),
                upgrading: false,
                reason: Reason::Udp(UdpReason::UdpDirect),
            }),
            to_proxy: AtomicBool::new(false),
            generation: AtomicI64::new(0),
            buf_start: 512,
            start_ns: AtomicI64::new(now),
            last_ns: AtomicI64::new(now),
            up_pkts: AtomicU64::new(0),
            down_pkts: AtomicU64::new(0),
            up_bytes: AtomicU64::new(0),
            down_bytes: AtomicU64::new(0),
            close_once: std::sync::Once::new(),
        });
        tokio::spawn(udp_pump(Arc::clone(&a), 0, false));
        // 基线小包直通
        udp_send(&a, b"tiny").unwrap();
        let mut rb = vec![0u8; 65535];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut rb))
            .await
            .expect("基线回包超时")
            .unwrap();
        assert_eq!(&rb[..n], b"tiny");
        // 喂一个超过起始容量的包 → gate_udp_buf_trunc>=1 且该包被丢弃
        let big = vec![0xABu8; 1000];
        udp_send(&a, &big).unwrap();
        crate::testutil::wait_until(|| crate::testutil::stat_value(tag, "gate_udp_buf_trunc") >= 1)
            .await;
        assert_eq!(
            crate::testutil::stat_value(tag, "gate_udp_buf_trunc"),
            1,
            "截断必须恰计 1 次"
        );
        let silent =
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut rb)).await;
        assert!(silent.is_err(), "截断包必须丢弃，client 颗粒无收");
        // 缓冲已增长：重发同一包（1000B ≤ 1024）现在直通
        udp_send(&a, &big).unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut rb))
            .await
            .expect("增长后回包超时")
            .unwrap();
        assert_eq!(n, 1000, "增长后的缓冲必须容下 1000B");
        assert!(rb[..n].iter().all(|&b| b == 0xAB));
        assert_eq!(
            crate::testutil::stat_value(tag, "gate_udp_buf_trunc"),
            1,
            "容下后不得再截断"
        );
        shutdown(&a, true).await;
    }

    #[test]
    fn fixed_dst_override_runs_before_port_and_local_checks() {
        // Go udp.go:663-682 回归：fixed 覆盖必须先于 port==0 与 local 判定。
        // 旧顺序下 (a)(b) 会分别被记 origdst_invalid / local_drop 而丢包。
        let fixed = "223.5.5.5:853";
        // (a) 真实 od 端口为 0，但 fixed 有效 → 按 fixed 放行。
        let r = super::gate_udp_od("10.0.0.1:0".parse().unwrap(), fixed);
        assert_eq!(
            r,
            Ok(fixed.parse().unwrap()),
            "fixed 有效时 port 0 不得判无效"
        );
        // (b) 真实 od 为私网/回环，但 fixed 为公网 → 按 fixed 放行，不得 local_drop。
        for raw in ["192.168.1.1:5000", "127.0.0.1:5000", "10.0.0.1:5000"] {
            let r = super::gate_udp_od(raw.parse().unwrap(), fixed);
            assert_eq!(
                r,
                Ok(fixed.parse().unwrap()),
                "fixed 有效时 {raw} 不得 local_drop"
            );
        }
        // (c) 无 fixed 时原判定不变：port 0 → invalid，私网 → local_drop。
        assert_eq!(
            super::gate_udp_od("10.0.0.1:0".parse().unwrap(), "")
                .unwrap_err()
                .1,
            "origdst_invalid"
        );
        assert_eq!(
            super::gate_udp_od("192.168.1.1:5000".parse().unwrap(), "")
                .unwrap_err()
                .1,
            "local_drop"
        );
        // (d) fixed 非法 → 保持原 od 再判定（私网仍 local_drop）。
        assert_eq!(
            super::gate_udp_od("192.168.1.1:5000".parse().unwrap(), "not-an-addr")
                .unwrap_err()
                .1,
            "local_drop"
        );
        // (e) fixed 本身私网 → 覆盖后仍按覆盖值判 local_drop。
        assert_eq!(
            super::gate_udp_od("8.8.8.8:53".parse().unwrap(), "10.0.0.9:53")
                .unwrap_err()
                .1,
            "local_drop"
        );
        // (f) 无 fixed 的公网包正常放行。
        assert_eq!(
            super::gate_udp_od("8.8.8.8:53".parse().unwrap(), ""),
            Ok("8.8.8.8:53".parse().unwrap())
        );
    }
}
