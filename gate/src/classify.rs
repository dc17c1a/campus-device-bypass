//! TCP 判路：纯函数决策树（Task 5）。
//!
//! 逐字节复刻 Go 原版 `classifyEx` / `isTLSClientHello` / `looksLikeTLSRecord`
//!（`src/wxdet-gate/main.go`）。`classify_ex` 是纯函数：无日志、无统计、
//! 无环境读取，可被 fuzz-sweep 与差分测试直接调用；统计包装层 `classify`
//! 留给 Task 10（stats 模块就位后）。
//!
//! 决策顺序不可换：
//! ① `is_tls_client_hello` → pass/tls_direct；② Host 命中 dl-domains →
//! pass/dl_direct；③ Range → pass/dl_range；④ query → pass/dl_query；
//! ⑤ UA → pass/dl_ua；⑥ ext → pass/dl_ext；⑦ 兜底 proxy/default。

use crate::http::{
    RangeStrength, dl_ext_hit, dl_query_hit, dl_ua_hit, has_range_header, http_host, http_path,
    http_user_agent, is_http_request, match_domain_suffix, range_strength,
};
use crate::lists::DlLists;
use crate::reason::{TcpReason, UdpReason, Verdict};

/// 纯判路输出：`strict_fail` 为观测位（旧粗判真、严判假），不改变判路；
/// `range_strength` 只在 reason 为 `DlRange` 时为 `Some(..)`。
#[derive(Debug)]
pub struct ClassifyOut {
    pub verdict: Verdict,
    pub reason: TcpReason,
    pub strict_fail: bool,
    pub range_strength: Option<RangeStrength>,
}

/// 旧粗判（`looksLikeTLSRecord`）：`16 03` 前缀 + ≥6B。保留仅用于观测对照。
pub fn looks_like_tls_record(b: &[u8]) -> bool {
    b.len() >= 6 && b[0] == 0x16 && b[1] == 0x03
}

/// 严判（`isTLSClientHello`）：粗判基础上要求记录层 minor ≤ 0x03、
/// 记录长度 ∈ [1, 16384+2048=18432]、握手类型 b[5] == 0x01。
pub fn is_tls_client_hello(b: &[u8]) -> bool {
    if !looks_like_tls_record(b) {
        return false;
    }
    if b[2] > 0x03 {
        return false;
    }
    let rl = (u16::from(b[3]) << 8) | u16::from(b[4]);
    if !(1..=18432).contains(&rl) {
        return false;
    }
    b[5] == 0x01
}

/// 纯判路（`classifyEx`）：无副作用。判路端口无关（Go 原版 `_ = od`）。
pub fn classify_ex(b: &[u8], dl: &DlLists) -> ClassifyOut {
    if is_tls_client_hello(b) {
        return ClassifyOut {
            verdict: Verdict::Pass,
            reason: TcpReason::TlsDirect,
            strict_fail: false,
            range_strength: None,
        };
    }
    let strict_fail = looks_like_tls_record(b) && !is_tls_client_hello(b);
    if is_http_request(b) {
        let host = http_host(b);
        if !host.is_empty() && match_domain_suffix(&host, &dl.dom) {
            return ClassifyOut {
                verdict: Verdict::Pass,
                reason: TcpReason::DlDirect,
                strict_fail,
                range_strength: None,
            };
        }
        if has_range_header(b) {
            return ClassifyOut {
                verdict: Verdict::Pass,
                reason: TcpReason::DlRange,
                strict_fail,
                range_strength: range_strength(b),
            };
        }
        let path = http_path(b);
        if !path.is_empty() && dl_query_hit(&path, &dl.query) {
            return ClassifyOut {
                verdict: Verdict::Pass,
                reason: TcpReason::DlQuery,
                strict_fail,
                range_strength: None,
            };
        }
        let ua = http_user_agent(b);
        if !ua.is_empty() && dl_ua_hit(&ua, &dl.ua) {
            return ClassifyOut {
                verdict: Verdict::Pass,
                reason: TcpReason::DlUa,
                strict_fail,
                range_strength: None,
            };
        }
        if !path.is_empty() && dl_ext_hit(&path, &dl.ext) {
            return ClassifyOut {
                verdict: Verdict::Pass,
                reason: TcpReason::DlExt,
                strict_fail,
                range_strength: None,
            };
        }
    }
    ClassifyOut {
        verdict: Verdict::Proxy,
        reason: TcpReason::Default,
        strict_fail,
        range_strength: None,
    }
}

/// 生产入口（Task 10，R1）：判路本体是无副作用的 `classify_ex`；
/// 仅在此落统计：严判失败记 `gate_tls_strict_fail`；`dl_range` 按强弱记
/// `gate_range_strong`/`gate_range_weak`（只做观测分级，不改判路）。
pub fn classify(b: &[u8], dl: &DlLists) -> ClassifyOut {
    let out = classify_ex(b, dl);
    if out.strict_fail {
        crate::stats::write_stat("gate_tls_strict_fail", 1);
    }
    if out.reason == TcpReason::DlRange {
        match out.range_strength {
            Some(RangeStrength::Strong) => crate::stats::write_stat("gate_range_strong", 1),
            _ => crate::stats::write_stat("gate_range_weak", 1),
        }
    }
    out
}

/// UDP 包型判路（`classifyUDP`）：标准 STUN 魔数（+长度一致）/ 变种包型 / 其他。
///
/// 顺序不可换：`len<20` 先短路（之后才可安全索引 `b[..8]`）；标准 STUN
/// （魔数 `21 12 a4 42` + 首 2bit 为 0 排除 RTP/DTLS 等 + `20+msgLen <= len`，
/// 长度恰好相等也算 STUN）→ proxy/stun_udp；魔数命中但长度不一致 →
/// pass/udp_direct；变种 STUN（首字节 `00/01` + 次字节 `01/02`）→
/// proxy/stun_udp_var；其余 → pass/udp_direct。
pub fn classify_udp(b: &[u8]) -> (Verdict, UdpReason) {
    if b.len() < 20 {
        return (Verdict::Pass, UdpReason::UdpShort);
    }
    if b[4] == 0x21 && b[5] == 0x12 && b[6] == 0xa4 && b[7] == 0x42 && b[0] & 0xC0 == 0x00 {
        let ml = (u16::from(b[2]) << 8) | u16::from(b[3]);
        if 20 + (ml as usize) <= b.len() {
            return (Verdict::Proxy, UdpReason::StunUdp);
        }
        return (Verdict::Pass, UdpReason::UdpDirect);
    }
    if (b[0] == 0x00 || b[0] == 0x01) && (b[1] == 0x01 || b[1] == 0x02) {
        return (Verdict::Proxy, UdpReason::StunUdpVar);
    }
    (Verdict::Pass, UdpReason::UdpDirect)
}

/// UDP 进门包总入口（`udpVerdict`，STUN 优先）：先看形状——STUN（标准/变种）
/// 任意端口命中即 proxy（原样返回）；非 STUN 再按端口：`port>10000` →
/// pass（`classify_udp` 原样理由 udp_direct/udp_short），否则 →
/// proxy/udp_proxy。
pub fn udp_verdict(port: u16, b: &[u8]) -> (Verdict, UdpReason) {
    let (v, r) = classify_udp(b);
    if v == Verdict::Proxy || port > 10000 {
        return (v, r);
    }
    (Verdict::Proxy, UdpReason::UdpProxy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::header_block;
    use crate::lists::parse_line_set;

    /// Go `clientHello` 的判路等价前缀：记录头 [16 03 01 len_hi len_lo]
    /// + 握手类型 0x01。分类器只读前 6 字节，其余载荷不影响判路。
    fn client_hello() -> Vec<u8> {
        vec![0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x03, 0x03]
    }

    /// Go `TestClassify` 的名单快照。
    fn go_dl() -> DlLists {
        DlLists {
            dom: [
                "down.qq.com",
                "down-update.qq.com",
                "wegame.gtimg.com",
                "download.windowsupdate.com",
                "dl.delivery.mp.microsoft.com",
                "repo.nzm.qq.com",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            ua: [
                "thunder",
                "qqdownload",
                "idm",
                "internet download manager",
                "aria2",
                "wegame",
                "valve/steam http client",
                "microsoft-delivery-optimization",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            ext: [
                "apk", "exe", "msi", "dmg", "iso", "zip", "rar", "7z", "tar.gz", "mp4", "flv",
                "ts", "m3u8", "mp3", "pdf",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            query: [
                "x-oss-signature",
                "q-sign-algorithm",
                "response-content-disposition",
                "_upt",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }

    #[test]
    fn tls_strict_boundaries() {
        let mk = |minor: u8, rl: u16, ht: u8| {
            vec![0x16, 0x03, minor, (rl >> 8) as u8, (rl & 0xff) as u8, ht]
        };
        assert!(is_tls_client_hello(&mk(0x00, 1, 0x01)));
        assert!(is_tls_client_hello(&mk(0x03, 18432, 0x01)));
        assert!(!is_tls_client_hello(&mk(0x04, 1, 0x01))); // minor > 3
        assert!(!is_tls_client_hello(&mk(0x03, 0, 0x01))); // 记录长 0
        assert!(!is_tls_client_hello(&mk(0x03, 18433, 0x01))); // 记录长超界
        assert!(!is_tls_client_hello(&mk(0x03, 1, 0x02))); // 非 ClientHello
        assert!(!is_tls_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x01])); // 5 字节
        assert!(!is_tls_client_hello(&[0x16, 0xf1, 0x01, 0x00, 0x01, 0x01]));
    }

    #[test]
    fn range_wins_over_query() {
        let dl = DlLists {
            query: vec!["oss".into()],
            ..Default::default()
        };
        let req = b"GET /x?oss=1 HTTP/1.1\r\nHost: dl.example.com\r\nRange: bytes=0-1023\r\n\r\n";
        let out = classify_ex(req, &dl);
        assert_eq!(out.reason, TcpReason::DlRange);
        assert_eq!(out.range_strength, Some(RangeStrength::Weak));
    }

    #[test]
    fn strict_fail_recorded_when_coarse_tls_fails_strict() {
        let dl = DlLists::default();
        let b = [0x16u8, 0x03, 0x04, 0x00, 0x01, 0x01];
        let out = classify_ex(&b, &dl);
        assert_eq!(out.verdict, Verdict::Proxy);
        assert_eq!(out.reason, TcpReason::Default);
        assert!(out.strict_fail);
    }

    // 移植 Go TestIsTLSClientHello 全 14 例。
    #[test]
    fn is_tls_client_hello_matches_go_table() {
        let cases: &[(&str, &[u8], bool)] = &[
            ("ok", &[0x16, 0x03, 0x01, 0x00, 0x20, 0x01], true),
            ("minor-00-ok", &[0x16, 0x03, 0x00, 0x00, 0x20, 0x01], true),
            ("minor-03-ok", &[0x16, 0x03, 0x03, 0x00, 0x20, 0x01], true),
            ("minor-04-bad", &[0x16, 0x03, 0x04, 0x00, 0x20, 0x01], false),
            ("rl-0-bad", &[0x16, 0x03, 0x01, 0x00, 0x00, 0x01], false),
            ("rl-1-ok", &[0x16, 0x03, 0x01, 0x00, 0x01, 0x01], true),
            ("rl-3-ok", &[0x16, 0x03, 0x01, 0x00, 0x03, 0x01], true),
            ("rl-4-ok", &[0x16, 0x03, 0x01, 0x00, 0x04, 0x01], true),
            ("rl-18432-ok", &[0x16, 0x03, 0x01, 0x48, 0x00, 0x01], true),
            ("rl-18433-bad", &[0x16, 0x03, 0x01, 0x48, 0x01, 0x01], false),
            ("b5-02-bad", &[0x16, 0x03, 0x01, 0x00, 0x20, 0x02], false),
            ("b5-00-bad", &[0x16, 0x03, 0x01, 0x00, 0x20, 0x00], false),
            ("b1-f1-bad", &[0x16, 0xf1, 0x00, 0x01, 0x00, 0x01], false),
            ("len5-bad", &[0x16, 0x03, 0x01, 0x00, 0x04], false),
        ];
        for (name, b, want) in cases {
            assert_eq!(is_tls_client_hello(b), *want, "用例: {name}");
        }
    }

    // 移植 Go TestClassify 全 26 例（经 classify_ex；od 端口无关，判路只看首包）。
    #[test]
    fn classify_matches_go_table() {
        let dl = go_dl();
        let hello = client_hello();
        let cases: &[(&str, Vec<u8>, Verdict, TcpReason)] = &[
            ("tls-443", hello.clone(), Verdict::Pass, TcpReason::TlsDirect),
            ("tls-8443", hello.clone(), Verdict::Pass, TcpReason::TlsDirect),
            ("tls-80", hello.clone(), Verdict::Pass, TcpReason::TlsDirect),
            (
                "tls-former-doh-now-pass",
                hello.clone(),
                Verdict::Pass,
                TcpReason::TlsDirect,
            ),
            (
                "tls-rl-boundary-ok",
                vec![0x16, 0x03, 0x01, 0x00, 0x01, 0x01],
                Verdict::Pass,
                TcpReason::TlsDirect,
            ),
            (
                "tls-strict-minor-now-proxy",
                vec![0x16, 0x03, 0x04, 0x00, 0x08, 0x01],
                Verdict::Proxy,
                TcpReason::Default,
            ),
            (
                "tls-strict-b5-now-proxy",
                vec![0x16, 0x03, 0x01, 0x00, 0x08, 0x02],
                Verdict::Proxy,
                TcpReason::Default,
            ),
            (
                "ex-mmtls-now-default",
                vec![0x16, 0xf1, 0x00, 0x01],
                Verdict::Proxy,
                TcpReason::Default,
            ),
            (
                "ex-oicq-now-default",
                vec![0x02, 0x30, 0x31],
                Verdict::Proxy,
                TcpReason::Default,
            ),
            (
                "opaque-8000",
                vec![0x05, 0x7b, 0x08, 0x00, 0x01],
                Verdict::Proxy,
                TcpReason::Default,
            ),
            (
                "opaque-7999-same",
                vec![0x05, 0x7b, 0x08, 0x00, 0x01],
                Verdict::Proxy,
                TcpReason::Default,
            ),
            ("empty-silent", vec![], Verdict::Proxy, TcpReason::Default),
            (
                "dl-host-80",
                b"GET /client.zip HTTP/1.1\r\nHost: down.qq.com\r\n\r\n".to_vec(),
                Verdict::Pass,
                TcpReason::DlDirect,
            ),
            (
                "dl-host-odd-port",
                b"GET /patch.zip HTTP/1.1\r\nHost: down-update.qq.com\r\n\r\n".to_vec(),
                Verdict::Pass,
                TcpReason::DlDirect,
            ),
            (
                "dl-range",
                b"GET /video.mp4 HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-1023\r\n\r\n"
                    .to_vec(),
                Verdict::Pass,
                TcpReason::DlRange,
            ),
            (
                "dl-range-keeps-priority-over-query",
                b"GET /v?x-oss-signature=a HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-9\r\n\r\n"
                    .to_vec(),
                Verdict::Pass,
                TcpReason::DlRange,
            ),
            (
                "dl-query-oss",
                b"GET /f?x-oss-signature=abc HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
                Verdict::Pass,
                TcpReason::DlQuery,
            ),
            (
                "dl-query-cos",
                b"GET /f?q-sign-algorithm=sha1&q-ak=x HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    .to_vec(),
                Verdict::Pass,
                TcpReason::DlQuery,
            ),
            (
                "dl-query-attach",
                b"GET /f?response-content-disposition=attachment HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    .to_vec(),
                Verdict::Pass,
                TcpReason::DlQuery,
            ),
            (
                "dl-query-upyun",
                b"GET /f?_upt=abc HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
                Verdict::Pass,
                TcpReason::DlQuery,
            ),
            (
                "query-generic-sign-nohit",
                b"GET /api?sign=abc&expires=123&token=x HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    .to_vec(),
                Verdict::Proxy,
                TcpReason::Default,
            ),
            (
                "dl-ua-thunder",
                b"GET /file HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Thunder/7.0\r\n\r\n"
                    .to_vec(),
                Verdict::Pass,
                TcpReason::DlUa,
            ),
            (
                "dl-ext-apk",
                b"GET /app.apk HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                    .to_vec(),
                Verdict::Pass,
                TcpReason::DlExt,
            ),
            (
                "http-nondl-is-proxy",
                b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
                Verdict::Proxy,
                TcpReason::Default,
            ),
            (
                "http-former-kw-now-default",
                b"GET /x HTTP/1.1\r\nHost: www.douyin.com\r\n\r\n".to_vec(),
                Verdict::Proxy,
                TcpReason::Default,
            ),
            (
                "not-http-binary",
                b"GARBAGE this is not http\r\n".to_vec(),
                Verdict::Proxy,
                TcpReason::Default,
            ),
            // Go 的 port80-empty / port80-pub-binary：空包与随机二进制一律 proxy/default。
            ("port80-empty", vec![], Verdict::Proxy, TcpReason::Default),
            (
                "port80-pub-binary",
                vec![0x00, 0x01, 0x02, 0x03],
                Verdict::Proxy,
                TcpReason::Default,
            ),
        ];
        assert_eq!(cases.len(), 28, "Go TestClassify 全表行数");
        for (name, b, verdict, reason) in cases {
            let out = classify_ex(b, &dl);
            assert_eq!(out.verdict, *verdict, "verdict 用例: {name}");
            assert_eq!(out.reason, *reason, "reason 用例: {name}");
        }
    }

    #[test]
    fn range_strength_some_only_for_dl_range() {
        let dl = go_dl();
        let range_req =
            b"GET /video.mp4 HTTP/1.1\r\nHost: example.com\r\nRange: bytes=1024-\r\n\r\n";
        let out = classify_ex(range_req, &dl);
        assert_eq!(out.reason, TcpReason::DlRange);
        assert_eq!(out.range_strength, Some(RangeStrength::Strong));
        // 非 dl_range 一律 None（含 strict_fail 置位的 proxy/default）。
        let tls_fail = classify_ex(&[0x16, 0x03, 0x04, 0x00, 0x08, 0x01], &dl);
        assert!(tls_fail.strict_fail);
        assert_eq!(tls_fail.range_strength, None);
        let plain = classify_ex(
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            &dl,
        );
        assert_eq!(plain.range_strength, None);
    }

    // 移植 Go TestClassifyExNoSideEffect：classify_ex 纯无副作用，同输入走生产入口才计数。
    #[test]
    fn classify_ex_no_side_effect() {
        let _serial = crate::ledger::FILE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tag = "classify_noside";
        crate::testutil::reset_stats(tag);
        let dl = DlLists::default();
        let b = [0x16u8, 0x03, 0x04, 0x00, 0x08, 0x01]; // 旧粗判真、严判假
        let out = classify_ex(&b, &dl);
        assert_eq!(out.verdict, Verdict::Proxy);
        assert_eq!(out.reason, TcpReason::Default);
        assert!(out.strict_fail);
        assert_eq!(
            crate::testutil::stat_value(tag, "gate_tls_strict_fail"),
            0,
            "classify_ex 不该写 stats"
        );
        // 生产入口同输入才计数，且判路口径一致。
        let prod = classify(&b, &dl);
        assert_eq!(prod.verdict, out.verdict);
        assert_eq!(prod.reason, out.reason);
        assert_eq!(
            crate::testutil::stat_value(tag, "gate_tls_strict_fail"),
            1,
            "classify 应计 1 次"
        );
        // 严判通过 → strict_fail=false。
        assert!(!classify_ex(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x01], &dl).strict_fail);
    }

    // 移植 Go TestTLSStrictFailCounter + Range 强弱分级计数。
    #[test]
    fn tls_strict_fail_counter() {
        let _serial = crate::ledger::FILE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tag = "classify_strictfail";
        crate::testutil::reset_stats(tag);
        let dl = DlLists::default();
        // 旧粗判真、严判假（minor=0x04）→ 计数；判路 proxy/default。
        let out = classify(&[0x16, 0x03, 0x04, 0x00, 0x08, 0x01], &dl);
        assert_eq!(out.verdict, Verdict::Proxy);
        assert_eq!(out.reason, TcpReason::Default);
        // 严判真：不计数。
        let ok = classify(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x01], &dl);
        assert_eq!(ok.verdict, Verdict::Pass);
        assert_eq!(ok.reason, TcpReason::TlsDirect);
        assert_eq!(
            crate::testutil::stat_lines(tag, "gate_tls_strict_fail"),
            1,
            "计数行必须恰 1"
        );
        // Range 强弱只做观测分级，不改判路。
        let weak = classify(
            b"GET /video.mp4 HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-1023\r\n\r\n",
            &dl,
        );
        assert_eq!(weak.reason, TcpReason::DlRange);
        let strong = classify(
            b"GET /video.mp4 HTTP/1.1\r\nHost: example.com\r\nRange: bytes=1024-\r\n\r\n",
            &dl,
        );
        assert_eq!(strong.reason, TcpReason::DlRange);
        assert_eq!(crate::testutil::stat_value(tag, "gate_range_weak"), 1);
        assert_eq!(crate::testutil::stat_value(tag, "gate_range_strong"), 1);
    }

    fn stun_txn() -> Vec<u8> {
        vec![
            0x1d, 0xbd, 0x82, 0x61, 0xaa, 0x87, 0x29, 0x89, 0x4a, 0xac, 0x9e, 0xe1,
        ]
    }

    fn std_req() -> Vec<u8> {
        let mut v = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42];
        v.extend_from_slice(&stun_txn());
        v
    }

    fn var_req() -> Vec<u8> {
        let mut v = vec![0x00, 0x01, 0x00, 0x08, 0x01, 0x39, 0xf4, 0x5c];
        v.extend_from_slice(&stun_txn());
        v
    }

    /// 某 STUN 端口上的 20B 随机混淆包（实测形状），非 STUN。
    fn obf_pkt() -> Vec<u8> {
        vec![
            0x3b, 0xca, 0xac, 0x48, 0xc3, 0xee, 0xef, 0xe8, 0x93, 0xa6, 0xbc, 0xb5, 0xd3, 0x9e,
            0x90, 0x93, 0x9e, 0xb4, 0xb3, 0xd1,
        ]
    }

    // 移植 Go TestClassifyUDP 全 9 例。
    #[test]
    fn classify_udp_matches_go_table() {
        let mut std_resp = vec![0x01, 0x01, 0x00, 0x30, 0x21, 0x12, 0xa4, 0x42];
        std_resp.extend_from_slice(&stun_txn());
        std_resp.extend(vec![0u8; 48]);
        let mut std_len_mismatch = vec![0x00, 0x01, 0x00, 0x30, 0x21, 0x12, 0xa4, 0x42];
        std_len_mismatch.extend_from_slice(&stun_txn());
        let mut var_resp = vec![0x01, 0x01, 0x00, 0x48, 0x01, 0x39, 0xf4, 0x5c];
        var_resp.extend_from_slice(&stun_txn());
        let cases: &[(&str, Vec<u8>, Verdict, UdpReason)] = &[
            ("std-req", std_req(), Verdict::Proxy, UdpReason::StunUdp),
            ("std-resp", std_resp, Verdict::Proxy, UdpReason::StunUdp),
            (
                "std-len-mismatch",
                std_len_mismatch,
                Verdict::Pass,
                UdpReason::UdpDirect,
            ),
            ("var-req", var_req(), Verdict::Proxy, UdpReason::StunUdpVar),
            ("var-resp", var_resp, Verdict::Proxy, UdpReason::StunUdpVar),
            ("obf-3478", obf_pkt(), Verdict::Pass, UdpReason::UdpDirect),
            ("rtp", vec![0x80u8; 40], Verdict::Pass, UdpReason::UdpDirect),
            (
                "short",
                vec![0x00, 0x01, 0x02],
                Verdict::Pass,
                UdpReason::UdpShort,
            ),
            ("empty", vec![], Verdict::Pass, UdpReason::UdpShort),
        ];
        assert_eq!(cases.len(), 9, "Go TestClassifyUDP 全表行数");
        for (name, b, verdict, reason) in cases {
            assert_eq!(classify_udp(b), (*verdict, *reason), "用例: {name}");
        }
    }

    // 移植 Go TestUDPVerdictPortRule。
    #[test]
    fn udp_verdict_port_rule_matches_go() {
        let obf = obf_pkt();
        let rtp = [0x80u8; 40];
        let short = [0x00u8, 0x01, 0x02];
        // ≤10000 非 STUN 走端口规则 proxy/udp_proxy；STUN 形状记 stun_*。
        for port in [80u16, 443] {
            for b in [&obf[..], &rtp[..], &short[..], &[][..]] {
                assert_eq!(
                    udp_verdict(port, b),
                    (Verdict::Proxy, UdpReason::UdpProxy),
                    "port {port} len={}",
                    b.len()
                );
            }
            assert_eq!(
                udp_verdict(port, &std_req()),
                (Verdict::Proxy, UdpReason::StunUdp),
                "port {port} stun"
            );
        }
        // >10000 按 STUN 形状判。
        assert_eq!(
            udp_verdict(15000, &std_req()),
            (Verdict::Proxy, UdpReason::StunUdp)
        );
        assert_eq!(
            udp_verdict(15000, &obf),
            (Verdict::Pass, UdpReason::UdpDirect)
        );
    }

    #[test]
    fn port_boundary_10000() {
        let non_stun = [0u8; 40];
        let (v, r) = udp_verdict(10000, &non_stun);
        assert_eq!((v, r), (Verdict::Proxy, UdpReason::UdpProxy));
        let (v, r) = udp_verdict(10001, &non_stun);
        assert_eq!((v, r), (Verdict::Pass, UdpReason::UdpDirect));
        let short: [u8; 10] = [0u8; 10];
        let (v, r) = udp_verdict(10001, &short);
        assert_eq!((v, r), (Verdict::Pass, UdpReason::UdpShort));
        let (v, r) = udp_verdict(10000, &short);
        assert_eq!((v, r), (Verdict::Proxy, UdpReason::UdpProxy));
    }

    #[test]
    fn stun_shape_wins_on_any_port() {
        let mut p = [0u8; 20];
        p[0] = 0x00;
        p[1] = 0x01;
        p[2] = 0x00;
        p[3] = 0x00;
        p[4] = 0x21;
        p[5] = 0x12;
        p[6] = 0xa4;
        p[7] = 0x42;
        for port in [443u16, 3478, 5349, 19302, 12348, 8000, 15000] {
            assert_eq!(classify_udp(&p).0, Verdict::Proxy, "port {port}");
        }
        // 魔数匹配但长度不一致 → pass/udp_direct
        p[2] = 0xff;
        p[3] = 0xff;
        assert_eq!(classify_udp(&p), (Verdict::Pass, UdpReason::UdpDirect));
    }

    // 移植 Go TestUDPVerdictCrossPortStunRelay。
    #[test]
    fn udp_verdict_cross_port_stun_relay() {
        let obf = obf_pkt();
        // 跨端口 STUN（8000/1106 等非三端口）verdict==proxy 即中继，不再有端口门限。
        for port in [8000u16, 1106, 443, 12348] {
            assert_eq!(udp_verdict(port, &std_req()).0, Verdict::Proxy);
            assert_eq!(udp_verdict(port, &var_req()).0, Verdict::Proxy);
            if port <= 10000 {
                assert_eq!(
                    udp_verdict(port, &obf),
                    (Verdict::Proxy, UdpReason::UdpProxy),
                    "port {port} obf"
                );
            } else {
                assert_eq!(udp_verdict(port, &obf).0, Verdict::Pass);
            }
        }
        // 三端口 STUN 仍 proxy（行为不变）。
        for port in [3478u16, 5349, 19302] {
            assert_eq!(udp_verdict(port, &std_req()).0, Verdict::Proxy);
        }
    }

    #[test]
    fn parsers_never_panic() {
        // 固定 seed 扫射；移植 TestParsersNoPanicSweep
        let mut s: u64 = 20261011;
        let mut next = || {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (s >> 33) as u32
        };
        let dl = DlLists::default();
        for _ in 0..20000 {
            let n = (next() % 200) as usize;
            let b: Vec<u8> = (0..n).map(|_| (next() & 0xff) as u8).collect();
            let _ = classify_ex(&b, &dl);
            let _ = classify_udp(&b);
            let _ = udp_verdict((next() & 0xffff) as u16, &b);
            let _ = is_tls_client_hello(&b);
            let _ = is_http_request(&b);
            let _ = http_host(&b);
            let _ = http_path(&b);
            let _ = http_user_agent(&b);
            let _ = header_block(&b);
            let _ = parse_line_set(&b);
            let _ = range_strength(&b);
        }
    }
}
