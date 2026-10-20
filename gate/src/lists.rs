//! 下载站名单类型、解析与热加载。
//!
//! 解析逐字节复刻 Go 原版 `parseLineSet` / `parseKeywords`
//!（`src/wxdet-gate/main.go`）；热加载复刻 `loadDLLists` / `checkDLReload` /
//! `watchDLLists`：`mtime+size` 变更检测、缺失文件不算变更、单文件失败告警并
//! 保留该文件的旧快照、`kw_poll_sec<=0` 关闭轮询。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::RwLock;

use crate::config::Config;

/// 下载站名单快照：域名集合精确/子域后缀匹配，ua/ext/query 为保序小写 token 表。
#[derive(Default)]
pub struct DlLists {
    pub dom: HashSet<String>,
    pub ua: Vec<String>,
    pub ext: Vec<String>,
    pub query: Vec<String>,
}

/// 每个名单文件的读取水位：`(mtime, size)`，键为 `Config` 中的路径字符串。
///
/// 对齐 Go `dlMarks[path] = fileMark{mod, size}`；**只比较、不承载名单内容**。
pub type Marks = HashMap<String, (SystemTime, u64)>;

/// 解析域名名单：行小写 → trim → 去一个尾点 → `split_whitespace`；
/// 恰 2 段且首段为 hosts 占位 IP（`0.0.0.0`/`127.0.0.1`/`::`）取第二段，
/// 否则必须恰 1 段；空串或 `#` 前缀丢弃。
///
/// Go 口径（`parseLineSet`）：逐行 `\n` 切分；单段行保留尾点原文（匹配侧
/// `matchDomainSuffix` 会去点），此处按任务口径统一去点，匹配语义一致。
pub fn parse_line_set(b: &[u8]) -> HashSet<String> {
    let mut m = HashSet::new();
    for ln in String::from_utf8_lossy(b).split('\n') {
        let ln = ln.trim().to_lowercase();
        let ln = ln.strip_suffix('.').unwrap_or(&ln);
        let f: Vec<&str> = ln.split_whitespace().collect();
        let ln = if f.len() == 2 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1" || f[0] == "::") {
            f[1]
        } else if f.len() != 1 {
            continue;
        } else {
            ln
        };
        if !ln.is_empty() && !ln.starts_with('#') {
            m.insert(ln.to_string());
        }
    }
    m
}

/// 解析关键词文件：trim → 小写；空行 / `#` 丢弃；保序返回 `Vec<String>`。
pub fn parse_keywords(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for ln in String::from_utf8_lossy(b).split('\n') {
        let ln = ln.trim().to_lowercase();
        if !ln.is_empty() && !ln.starts_with('#') {
            out.push(ln);
        }
    }
    out
}

/// 成功读入后记录该文件的水位（对齐 Go `noteDLMark`：读后 `Stat` 取 `mtime+size`）。
fn note_mark(marks: &mut Marks, path: &str) {
    if let Ok(md) = std::fs::metadata(path)
        && let Ok(mtime) = md.modified()
    {
        marks.insert(path.to_string(), (mtime, md.len()));
    }
}

/// 把 4 个名单文件读入 `target`：单文件成功才覆盖该字段并更新其 mark；
/// 单文件失败只告警（措辞对齐 Go `warn: dl <kind> file %s: %v`），该字段保留旧值。
///
/// 返回本次成功读入的各文件条数（对齐 Go `loadDLLists` 返回值：失败文件计 0，
/// 即使 `target` 中保留了该文件的旧快照）。
fn reload_into(
    cfg: &Config,
    marks: &mut Marks,
    target: &mut DlLists,
) -> (usize, usize, usize, usize) {
    let mut nd = 0;
    let mut nu = 0;
    let mut ne = 0;
    let mut nq = 0;
    match std::fs::read(&cfg.dl_dom_file) {
        Ok(b) => {
            target.dom = parse_line_set(&b);
            nd = target.dom.len();
            note_mark(marks, &cfg.dl_dom_file);
        }
        Err(e) => eprintln!("warn: dl dom file {}: {}", cfg.dl_dom_file, e),
    }
    match std::fs::read(&cfg.dl_ua_file) {
        Ok(b) => {
            target.ua = parse_keywords(&b);
            nu = target.ua.len();
            note_mark(marks, &cfg.dl_ua_file);
        }
        Err(e) => eprintln!("warn: dl ua file {}: {}", cfg.dl_ua_file, e),
    }
    match std::fs::read(&cfg.dl_ext_file) {
        Ok(b) => {
            target.ext = parse_keywords(&b);
            ne = target.ext.len();
            note_mark(marks, &cfg.dl_ext_file);
        }
        Err(e) => eprintln!("warn: dl ext file {}: {}", cfg.dl_ext_file, e),
    }
    match std::fs::read(&cfg.dl_query_file) {
        Ok(b) => {
            target.query = parse_keywords(&b);
            nq = target.query.len();
            note_mark(marks, &cfg.dl_query_file);
        }
        Err(e) => eprintln!("warn: dl query file {}: {}", cfg.dl_query_file, e),
    }
    (nd, nu, ne, nq)
}

/// 读全部 4 个名单（启动与重载共用）：返回全新快照，**成功读入的文件才更新 mark**。
///
/// 单文件失败告警且该字段留空（启动时无旧值，即为空）；热加载路径如需
/// “失败保留旧快照”请用 `watch`（内部走 `reload_into` 就地合并）。
pub fn load_all(cfg: &Config, marks: &mut Marks) -> DlLists {
    let mut out = DlLists::default();
    reload_into(cfg, marks, &mut out);
    out
}

/// 只比较、不改 mark：任一**存在**的文件满足（无 mark ｜ `mtime` 变新 ｜ `size`
/// 变化）即报 changed；**文件缺失（`metadata` 失败）不算变更**，直接跳过。
pub fn check_reload(cfg: &Config, marks: &Marks) -> bool {
    for p in [
        &cfg.dl_dom_file,
        &cfg.dl_ua_file,
        &cfg.dl_ext_file,
        &cfg.dl_query_file,
    ] {
        let md = match std::fs::metadata(p) {
            Ok(md) => md,
            Err(_) => continue,
        };
        let mtime = match md.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        match marks.get(p.as_str()) {
            None => return true,
            Some(&(mt, sz)) => {
                if mtime > mt || md.len() != sz {
                    return true;
                }
            }
        }
    }
    false
}

/// 单步重载（`watch` 每轮 tick 与测试共用）：有变更则就地重载、`dl reloaded`
/// 日志、`gate_dl_reload` 计数 +1，返回是否发生重载；无变更则什么都不做。
fn reload_if_changed(cfg: &Config, marks: &mut Marks, target: &mut DlLists) -> bool {
    if !check_reload(cfg, marks) {
        return false;
    }
    let (nd, nu, ne, nq) = reload_into(cfg, marks, target);
    eprintln!("dl reloaded: dom={nd} ua={nu} ext={ne} query={nq}");
    crate::stats::write_stat("gate_dl_reload", 1);
    true
}

/// 名单热加载轮询（对齐 Go `watchDLLists`）：`kw_poll_sec <= 0` 直接返回。
///
/// 入口直进轮询（对齐 Go：启动初装是 `main` 的 `loadDLLists`，属 Task 24；
/// `watch` 内不做初装、不写 `shared`、不打 `dl lists` 日志）。每 `kw_poll_sec`
/// 秒先无锁 `check_reload`（只读文件水位与本地 marks，不碰 `shared`，读连接
/// 不受影响），无变更直接下一轮；有变更才升级为写锁走 `reload_if_changed`
/// （内含二次确认；计数取本次成功读入数、失败文件记 0；单文件失败保留该
/// 文件的旧快照，其余文件照常更新）。绝不断连接。
/// 调用方把 `main` 里 `load_all` 已填充的 `marks` 按值传入（与 Go 共用进程级
/// `dlMarks` 同效：首轮 tick 无真变更即静默；R39 修复前此处曾用空水位，
/// 导致每次启动首 tick 误报 `dl reloaded` + `gate_dl_reload`）。
pub async fn watch(cfg: &Config, shared: Arc<RwLock<DlLists>>, mut marks: Marks) {
    if cfg.kw_poll_sec <= 0 {
        return;
    }
    let mut timer = tokio::time::interval(Duration::from_secs(cfg.kw_poll_sec as u64));
    // `interval` 首 tick 立即就绪；消费掉以对齐 Go `time.NewTicker` 语义（首轮等足整周期）。
    timer.tick().await;
    loop {
        timer.tick().await;
        if !check_reload(cfg, &marks) {
            continue;
        }
        let mut guard = shared.write().await;
        reload_if_changed(cfg, &mut marks, &mut guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[cfg(test)]
    fn out_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join("wxdet-gate-rs").join(tag);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // Task 10 的共享 testutil 尚未就位，此处内联同名等价实现，仅本模块测试使用。
    // 默认值与 `config::load()` 的回退值逐字一致，且不读取任何真实 `WD_*` 环境变量。
    #[cfg(test)]
    fn config_for_test(tag: &str) -> Config {
        let dir = out_dir(tag);
        Config {
            listen_addr: "0.0.0.0:12347".to_string(),
            udp_listen_addr: "0.0.0.0:12348".to_string(),
            pass_socks: "127.0.0.1:18081".to_string(),
            proxy_socks: "127.0.0.1:10811".to_string(),
            gate_log_path: "/tmp/wxdet/gate.log".to_string(),
            stats_path: "/tmp/wxdet/stats.tsv".to_string(),
            events_path: "/tmp/wxdet/events.jsonl".to_string(),
            udp_err_log_path: "/tmp/wxdet/udp_err.log".to_string(),
            peek_ms: 400,
            peek_ms80: 80,
            kw_poll_sec: 30,
            dl_dom_file: dir.join("dl-domains.txt").to_string_lossy().into_owned(),
            dl_ua_file: dir.join("dl-ua.txt").to_string_lossy().into_owned(),
            dl_ext_file: dir.join("dl-ext.txt").to_string_lossy().into_owned(),
            dl_query_file: dir.join("dl-query.txt").to_string_lossy().into_owned(),
            udp_fixed_dst: String::new(),
            udp_buf_kb: 2,
            tcp_buf_kb: 8,
            worker_threads: 4,
            tcp_idle_sec: 300,
        }
    }

    // Task 10 的共享 testutil 尚未就位，此处内联同名等价实现：只改 mtime，atime 保持。
    #[cfg(test)]
    fn filetime_touch(path: &std::path::Path, t: std::time::SystemTime) {
        use std::os::unix::ffi::OsStrExt;
        let d = t
            .duration_since(std::time::UNIX_EPOCH)
            .expect("touch time before epoch");
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: d.as_secs() as libc::time_t,
                tv_nsec: d.subsec_nanos() as libc::c_long,
            },
        ];
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let r = unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(r, 0, "utimensat failed");
    }

    #[test]
    fn parse_line_set_matches_go() {
        let m = parse_line_set(
            b"# c\nDNS.Google\n0.0.0.0 doh.pub\n\n  x.example.com  \nbad line here\n",
        );
        assert!(m.contains("dns.google"));
        assert!(m.contains("doh.pub"));
        assert!(m.contains("x.example.com"));
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn parse_line_set_hosts_and_dots() {
        // 127.0.0.1 / :: 占位取第二段；单段尾点去点；纯注释与多段丢弃。
        let m = parse_line_set(
            b"127.0.0.1 a.test\n:: b.test\nUPPER.TEST.\n# full comment\none two three\n",
        );
        assert!(m.contains("a.test"));
        assert!(m.contains("b.test"));
        assert!(m.contains("upper.test"));
        assert_eq!(m.len(), 3);
        // 非占位 IP 开头的双段行丢弃。
        let m2 = parse_line_set(b"1.2.3.4 evil.test\n");
        assert!(m2.is_empty());
    }

    #[test]
    fn parse_keywords_ordered_lower() {
        let v = parse_keywords(b"# comment\nThunder\n\n  QQDownload  \n#x\naria2\n");
        assert_eq!(v, vec!["thunder", "qqdownload", "aria2"]);
    }

    #[test]
    fn reload_detects_change_and_preserves_old_entries() {
        let tag = "lists_reload";
        let dir = out_dir(tag);
        let dom = dir.join("dl-domains.txt");
        std::fs::write(&dom, "a.example.com\n").unwrap();
        let mut cfg = config_for_test(tag);
        cfg.dl_dom_file = dom.to_str().unwrap().into();
        let mut marks = Marks::new();
        let l1 = load_all(&cfg, &mut marks);
        assert!(l1.dom.contains("a.example.com"), "解析必须命中域名");
        // load_all 已为成功读入的文件写入 mark → 此刻应判无变更
        assert!(!check_reload(&cfg, &marks), "无变更不得报 changed");
        // 追加并显式把 mtime 推后 2s（有些文件系统 mtime 精度粗，必须显式推）
        let mut f = std::fs::OpenOptions::new().append(true).open(&dom).unwrap();
        use std::io::Write;
        writeln!(f, "b.example.com").unwrap();
        drop(f);
        filetime_touch(
            &dom,
            std::time::SystemTime::now() + std::time::Duration::from_secs(2),
        );
        assert!(check_reload(&cfg, &marks), "mtime+size 变更必须被检出");
        let l2 = load_all(&cfg, &mut marks);
        assert!(l2.dom.contains("a.example.com"), "旧条目必须保留");
        assert!(l2.dom.contains("b.example.com"), "新条目必须生效");
        assert!(
            !check_reload(&cfg, &marks),
            "重载后 mark 已更新，不得再报变更"
        );
    }

    #[test]
    fn missing_file_is_not_a_change_and_keeps_old_snapshot() {
        let tag = "lists_missing";
        let dir = out_dir(tag);
        let mut cfg = config_for_test(tag);
        cfg.dl_dom_file = dir.join("nope.txt").to_str().unwrap().into();
        let mut marks = Marks::new();
        assert!(!check_reload(&cfg, &marks), "文件缺失不算变更");
        let l = load_all(&cfg, &mut marks);
        assert!(l.dom.is_empty(), "缺失文件的名单为空");
        assert!(
            !marks.contains_key(&cfg.dl_dom_file),
            "失败读入的文件不得写 mark"
        );
    }

    #[tokio::test]
    async fn poll_sec_zero_disables_watch() {
        let tag = "lists_poll0";
        let mut cfg = config_for_test(tag);
        cfg.kw_poll_sec = 0;
        // kw_poll_sec<=0 时 watch 必须立即返回、不注册任何定时器
        let shared = Arc::new(RwLock::new(DlLists::default()));
        let t = std::time::Instant::now();
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            watch(&cfg, shared, Marks::new()),
        )
        .await
        .expect("watch 必须在 <=200ms 内返回");
        assert!(t.elapsed() < std::time::Duration::from_millis(50));
    }

    #[tokio::test]
    async fn watch_does_not_clobber_shared_before_first_tick() {
        // 对齐 Go watchDLLists：watch 内无启动初装。4 个文件全部缺失（缺失不算
        // 变更，永不触发重载），若 watch 仍做初装，哨兵会被同步清空。
        let tag = "lists_noinit";
        let mut cfg = config_for_test(tag);
        cfg.kw_poll_sec = 1;
        let shared = Arc::new(RwLock::new(DlLists::default()));
        shared
            .write()
            .await
            .dom
            .insert("sentinel.example".to_string());
        tokio::select! {
            _ = watch(&cfg, shared.clone(), Marks::new()) => panic!("watch 不得自行返回"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {}
        }
        assert!(
            shared.read().await.dom.contains("sentinel.example"),
            "watch 不得在启动时初装覆盖 shared"
        );
    }

    #[tokio::test]
    async fn watch_with_startup_marks_first_tick_is_quiet() {
        // C1 回归（R39）：main 把 load_all 已填充的 marks 按值传入 watch 后，
        // 无文件变更时首轮 tick 必须静默——不得打 `dl reloaded`，不得写
        // `gate_dl_reload`。空水位（修复前行为）下同一场景必误报。
        let tag = "lists_first_tick_quiet";
        let dir = out_dir(tag);
        let dom = dir.join("dl-domains.txt");
        std::fs::write(&dom, "a.example.com\n").unwrap();
        let mut cfg = config_for_test(tag);
        cfg.dl_dom_file = dom.to_str().unwrap().into();
        cfg.kw_poll_sec = 1;
        // 生产启动顺序：load_all 填充 marks → 快照入 shared → marks 移交 watch。
        let mut marks = Marks::new();
        let snapshot = load_all(&cfg, &mut marks);
        assert!(!check_reload(&cfg, &marks), "初装后必须无变更");
        let shared = Arc::new(RwLock::new(snapshot));
        {
            let _serial = crate::ledger::FILE_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // O_APPEND 语义：先删旧文件，避免同容器重复跑时残留行串扰断言。
            let _ = std::fs::remove_file(dir.join("stats.tsv"));
            crate::stats::init(dir.join("stats.tsv").to_str().unwrap());
        }
        // kw_poll_sec=1：等足首轮 tick（~1s）再加余量，期间无文件变更。
        // watch 借 cfg（`&Config`），spawn 要求 'static，故用 select! 内联跑
        // （与 `watch_does_not_clobber_shared_before_first_tick` 同构）。
        tokio::select! {
            _ = watch(&cfg, shared, marks) => panic!("watch 不得自行返回"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(1600)) => {}
        }
        let s = std::fs::read_to_string(dir.join("stats.tsv")).unwrap_or_default();
        assert!(
            !s.lines().any(|l| l.contains("gate_dl_reload")),
            "首轮 tick 无变更不得写 gate_dl_reload: {s:?}"
        );
    }

    #[test]
    fn reload_counts_failed_file_as_zero_and_keeps_old_snapshot() {
        // 对齐 Go loadDLLists 返回值口径：失败文件计数为 0，但旧快照保留。
        let tag = "lists_partial";
        let dir = out_dir(tag);
        let dom = dir.join("dl-domains.txt");
        std::fs::write(&dom, "a.example.com\n").unwrap();
        let mut cfg = config_for_test(tag);
        cfg.dl_dom_file = dom.to_str().unwrap().into();
        cfg.dl_ua_file = dir.join("nope-ua.txt").to_str().unwrap().into();
        let mut marks = Marks::new();
        let mut live = DlLists {
            ua: vec!["stale-token".to_string()],
            ..Default::default()
        };
        let (nd, nu, ne, nq) = reload_into(&cfg, &mut marks, &mut live);
        assert_eq!((nd, nu, ne, nq), (1, 0, 0, 0));
        assert!(live.dom.contains("a.example.com"));
        assert_eq!(live.ua, vec!["stale-token"], "失败文件保留旧快照");
        assert!(marks.contains_key(&cfg.dl_dom_file));
        assert!(!marks.contains_key(&cfg.dl_ua_file));
    }

    #[test]
    fn reload_path_writes_gate_dl_reload_exactly_once() {
        // 无后台 watch、无 sleep：同步驱动 `reload_if_changed`（与 `watch`
        // 每轮 tick 共用同一函数，覆盖的是同一行计数代码）。
        // 全局 stats 句柄与 stats::tests 共享，干扰只能来自对方测试全程唯
        // 一的一次 `init`：每次迭代先重 init 再制造新变更后同步驱动，
        // init→write_stat 之间是无 await 的直连代码；对方单个时间点至多落
        // 入一个迭代的窗口，至多浪费一次迭代——成功只取决于“某次迭代观测到
        // +1”，不依赖任何时序调参，也不靠多跑几次证明。
        let tag = "lists_dlreload_stat";
        let dir = out_dir(tag);
        let dom = dir.join("dl-domains.txt");
        let mut cfg = config_for_test(tag);
        cfg.dl_dom_file = dom.to_str().unwrap().into();
        let stat_path = dir.join("stats.tsv");
        let _ = std::fs::remove_file(&stat_path);
        // 按 key 过滤：即使对方测试的行误落本文件（不同 key），读数不受影响。
        let count_hits = || {
            std::fs::read_to_string(&stat_path)
                .map(|s| s.lines().filter(|l| l.contains("gate_dl_reload")).count())
                .unwrap_or(0)
        };

        let mut marks = Marks::new();
        let mut live = DlLists::default();
        let mut observed = count_hits();
        for i in 0..10 {
            crate::stats::init(stat_path.to_str().unwrap());
            // 内容长度随迭代严格递增：size 变化必被检出，不依赖 mtime 精度。
            std::fs::write(&dom, format!("t{i}.example.com\n{}", "y".repeat(i))).unwrap();
            assert!(
                reload_if_changed(&cfg, &mut marks, &mut live),
                "刚制造变更，必触发重载"
            );
            let now = count_hits();
            if now == observed + 1 {
                observed = now;
                break;
            }
            // 读数未涨：本次 init→write 窗口内撞上对方唯一的 init，本次行
            // 落到了对方文件；下次迭代重 init 后重试（对方已跑完，不再干扰）。
        }
        assert_eq!(observed, 1, "同步重载必须恰写一条 gate_dl_reload=1");
        let s = std::fs::read_to_string(&stat_path).unwrap();
        let hits: Vec<&str> = s.lines().filter(|l| l.contains("gate_dl_reload")).collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].ends_with("\tgate_dl_reload\t1"));
    }
}
