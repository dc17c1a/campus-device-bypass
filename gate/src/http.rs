//! 明文 HTTP 特征抽取：TCP 分类器（Task 5）的纯函数输入层。
//!
//! 逐字节复刻 Go 原版 `isHTTPRequest` / `headerBlock` / `httpHost` / `httpPath` /
//! `httpUserAgent` / `hasRangeHeader` / `rangeStrong` / `matchDomainSuffix` /
//! `dlExtHit` / `dlQueryHit` / `dlUAHit`（`src/wxdet-gate/main.go`）。
//!
//! 核心不变量：一切头部类判据只看 [`header_block`]（首个 `\r\n\r\n` 之前），
//! 请求体里的 `Range:` / `User-Agent:` 永远翻转不了判路（见
//! `body_does_not_flip_verdict` 与 Go `TestHeaderBlockBodyIsolation`）。

use std::collections::HashSet;

/// Range 头的值语义分级（只做观测计数，不改判路）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeStrength {
    Strong,
    Weak,
}

const HTTP_METHODS: [&str; 8] = [
    "GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE ", "PATCH ", "CONNECT ",
];

/// 方法行语义校验：首行以标准请求方法（含尾空格）开头，挡随机二进制。
///
/// Go 口径：`len(b) >= 4`，取首个 `\n` 之前的行整体 `to_uppercase` 后做前缀匹配；
/// h2c 的 `PRI * HTTP/2.0` 不在方法表里，穿过通判走他路。
pub fn is_http_request(b: &[u8]) -> bool {
    if b.len() < 4 {
        return false;
    }
    let text = String::from_utf8_lossy(b);
    let line = match text.find('\n') {
        Some(i) => &text[..i],
        None => &text,
    };
    let up = line.to_uppercase();
    HTTP_METHODS.iter().any(|m| up.starts_with(m))
}

/// 只留 HTTP 头部块（首个 `\r\n\r\n` 之前）。
///
/// 没有该分隔符就返回整段，保持"头部还没收全"的现有语义：未收全的头部
/// 仍参与判定（见 `header_not_fully_received_still_sees_range`）。
pub fn header_block(b: &[u8]) -> &[u8] {
    const SEP: &[u8] = b"\r\n\r\n";
    if let Some(i) = b.windows(SEP.len()).position(|w| w == SEP) {
        return &b[..i];
    }
    b
}

/// 首行（去尾 `\r`）。Go `httpFirstLine` 的直译，内部使用。
fn first_line(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(header_block(b));
    let line = match s.find('\n') {
        Some(i) => &s[..i],
        None => &s,
    };
    line.strip_suffix('\r').unwrap_or(line).to_string()
}

/// 提取 Host 头（小写、去端口、去尾点；无头返回空串，IP 字面原样返回）。
///
/// Go 口径：在小写化后的头部块里找 `"\nhost:"`，取值到行尾，去 `\r`、
/// trim；`net.SplitHostPort` 成功才去端口，最后去一个尾点。
pub fn http_host(b: &[u8]) -> String {
    let lower = String::from_utf8_lossy(header_block(b)).to_lowercase();
    let i = match lower.find("\nhost:") {
        Some(i) => i,
        None => return String::new(),
    };
    let mut rest = &lower[i + "\nhost:".len()..];
    if let Some(j) = rest.find('\n') {
        rest = &rest[..j];
    }
    let host = rest.strip_suffix('\r').unwrap_or(rest).trim();
    let bare = split_host(host);
    bare.strip_suffix('.').unwrap_or(bare).to_string()
}

/// `net.SplitHostPort` 的成功分支：`host:port` 去端口，失败（无端口、裸
/// IPv6、无括号多冒号等）原样返回。输入已小写化，此处不做大小写处理。
fn split_host(host: &str) -> &str {
    if let Some(inner) = host.strip_prefix('[') {
        // "[v6]:port" 形：必须有配对 ']' 且紧跟 ':'。
        if let Some(end) = inner.find(']')
            && inner[end + 1..].starts_with(':')
        {
            return &inner[..end];
        }
        return host;
    }
    // 无括号形：恰好一个 ':' 才拆（对应 Go 的缺端口 / 冒号过多报错分支）。
    if host.chars().filter(|&c| c == ':').count() == 1
        && let Some(i) = host.find(':')
    {
        return &host[..i];
    }
    host
}

/// 提取请求路径（方法行第二段；绝对 URL 原样返回，后缀匹配照常工作）。
pub fn http_path(b: &[u8]) -> String {
    let line = first_line(b);
    let mut parts = line.trim().splitn(3, ' ');
    match (parts.next(), parts.next()) {
        (_, Some(p)) => p.to_string(),
        _ => String::new(),
    }
}

/// 是否带 `Range:` 头（断点续传/音视频 seek 信号；调用方已保证 is_http_request）。
pub fn has_range_header(b: &[u8]) -> bool {
    String::from_utf8_lossy(header_block(b))
        .to_lowercase()
        .contains("\nrange:")
}

/// Range 值语义分级：多段逗号 / `If-Range` / 首字节非零即强信号；
/// 单段 `bytes=0-` 与 `bytes=-N` 尾段为弱信号。只看头部块。
///
/// 无 `Range:` 头返回 `None`（对应 Go 返回 `false` 的分支；调用方
/// classify 只在已命中 `dl_range` 时计数，`None` 不会流入计数器）。
pub fn range_strength(b: &[u8]) -> Option<RangeStrength> {
    let lower = String::from_utf8_lossy(header_block(b)).to_lowercase();
    let i = lower.find("\nrange:")?;
    let mut rest = &lower[i + "\nrange:".len()..];
    if let Some(j) = rest.find('\n') {
        rest = &rest[..j];
    }
    let val = rest.trim();
    if val.contains(',') {
        return Some(RangeStrength::Strong);
    }
    if lower.contains("\nif-range:") {
        return Some(RangeStrength::Strong);
    }
    let mut v = val;
    if let Some(k) = v.find('=') {
        v = v[k + 1..].trim();
    }
    if v.starts_with('-') {
        return Some(RangeStrength::Weak);
    }
    let mut digits = String::new();
    for c in v.chars() {
        if !c.is_ascii_digit() {
            break;
        }
        digits.push(c);
    }
    if digits.trim_start_matches('0').is_empty() {
        Some(RangeStrength::Weak)
    } else {
        Some(RangeStrength::Strong)
    }
}

/// 提取 HTTP 请求的 `User-Agent` 头值（小写去首尾空格）。
///
/// 要求载荷以标准请求方法开头（`len(b) >= 14 && is_http_request`），
/// 过滤随机二进制偶然含头字样的情况。
pub fn http_user_agent(b: &[u8]) -> String {
    if b.len() < 14 {
        return String::new();
    }
    if !is_http_request(b) {
        return String::new();
    }
    let lower = String::from_utf8_lossy(header_block(b)).to_lowercase();
    let i = match lower.find("\nuser-agent:") {
        Some(i) => i,
        None => return String::new(),
    };
    let mut rest = &lower[i + "\nuser-agent:".len()..];
    if let Some(j) = rest.find('\n') {
        rest = &rest[..j];
    }
    rest.trim().to_string()
}

/// 精确或子域后缀命中（下载站域名名单用）。
///
/// Go 口径：trim → 去一个尾点 → 小写；空串不命中；先精确，再对每个 `.`
/// 位置判后缀。
pub fn match_domain_suffix(host: &str, set: &HashSet<String>) -> bool {
    let t = host.trim();
    let t = t.strip_suffix('.').unwrap_or(t);
    let s = t.to_lowercase();
    if s.is_empty() {
        return false;
    }
    if set.contains(&s) {
        return true;
    }
    let sb = s.as_bytes();
    for i in 0..sb.len() {
        if sb[i] == b'.' && set.contains(&s[i + 1..]) {
            return true;
        }
    }
    false
}

/// 二进制/媒体 URL 后缀命中（大小写不敏感，`?query`/`#frag` 剥离；
/// `tar.gz` 类多段以后缀全串匹配；名单条目去空格、去一个前导点）。
pub fn dl_ext_hit(path: &str, exts: &[String]) -> bool {
    let mut p = path.to_lowercase();
    if let Some(i) = p.find('?') {
        p.truncate(i);
    }
    if let Some(i) = p.find('#') {
        p.truncate(i);
    }
    for e in exts {
        let norm = e.trim().to_lowercase();
        let e = norm.strip_prefix('.').unwrap_or(&norm);
        if e.is_empty() {
            continue;
        }
        let mut suf = String::with_capacity(e.len() + 1);
        suf.push('.');
        suf.push_str(e);
        if p.ends_with(&suf) {
            return true;
        }
    }
    false
}

/// URL query 预签名/强制下载参数子串命中（路径侧大小写不敏感；名单条目
/// 由加载方保证小写，此处按 Go 原版逐字节 `Contains`，不二次归一化条目）。
pub fn dl_query_hit(path: &str, tokens: &[String]) -> bool {
    let s = path.to_lowercase();
    tokens
        .iter()
        .any(|t| !t.is_empty() && s.contains(t.as_str()))
}

/// 下载器 UA token 子串命中（UA 侧大小写不敏感；条目口径同上）。
pub fn dl_ua_hit(ua: &str, tokens: &[String]) -> bool {
    let s = ua.to_lowercase();
    tokens
        .iter()
        .any(|t| !t.is_empty() && s.contains(t.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exts() -> Vec<String> {
        [".apk", "tar.gz", ".7z", ".flv"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn dl_ext_hit_matches_go_truth_table() {
        let exts = exts();
        for p in [
            "/a.apk",
            "/a.APK",
            "/v.apk?sign=x",
            "/r.tar.gz",
            "/f.7z",
            "/x.flv",
        ] {
            assert!(dl_ext_hit(p, &exts), "应命中: {p}");
        }
        for p in [
            "/a.json",
            "/a.js",
            "/a.css",
            "/apk",
            "/x.apk/",
            "/index.html",
            "",
        ] {
            assert!(!dl_ext_hit(p, &exts), "不应命中: {p}");
        }
    }

    #[test]
    fn body_does_not_flip_verdict() {
        let req = b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\nbody-\nRange: bytes=0-1\nUser-Agent: Thunder\n/x.apk";
        assert!(!has_range_header(req));
        assert!(!dl_ua_hit(&http_user_agent(req), &["thunder".into()]));
    }

    #[test]
    fn header_not_fully_received_still_sees_range() {
        let req = b"GET /x HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-1\r\n";
        assert!(has_range_header(req));
    }

    // 移植 Go TestRangeStrength 的真值表。Go 返回 bool：true=强；
    // false 拆成两种：Range 头存在=弱，不存在=None（body 隔离）。
    #[test]
    fn range_strength_matches_go_truth_table() {
        let strong = [
            "GET /v HTTP/1.1\r\nHost: e.com\r\nRange: bytes=0-99,200-299\r\n\r\n",
            "GET /v HTTP/1.1\r\nHost: e.com\r\nRange: bytes=0-\r\nIf-Range: \"abc\"\r\n\r\n",
            "GET /v HTTP/1.1\r\nHost: e.com\r\nRange: bytes=1024-\r\n\r\n",
        ];
        for r in strong {
            assert_eq!(
                range_strength(r.as_bytes()),
                Some(RangeStrength::Strong),
                "应强: {r:?}"
            );
        }
        let weak = [
            "GET /v HTTP/1.1\r\nHost: e.com\r\nRange: bytes=0-1023\r\n\r\n",
            "GET /v HTTP/1.1\r\nHost: e.com\r\nRange: bytes=-500\r\n\r\n",
        ];
        for r in weak {
            assert_eq!(
                range_strength(r.as_bytes()),
                Some(RangeStrength::Weak),
                "应弱: {r:?}"
            );
        }
        let none = [
            "GET /v HTTP/1.1\r\nHost: e.com\r\n\r\n",
            "POST /u HTTP/1.1\r\nHost: e.com\r\n\r\n{\"r\":\"Range: bytes=0-1,2-3\"}",
        ];
        for r in none {
            assert_eq!(range_strength(r.as_bytes()), None, "应无: {r:?}");
        }
    }

    // 移植 Go TestDLExtMatch 后半：UA 大小写不敏感命中。
    #[test]
    fn dl_ua_hit_case_insensitive() {
        let uas: Vec<String> = ["thunder", "internet download manager"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(dl_ua_hit("Thunder/7.0", &uas));
        assert!(dl_ua_hit("Internet Download Manager/6.0", &uas));
        assert!(!dl_ua_hit("Mozilla/5.0", &uas));
    }

    #[test]
    fn is_http_request_gates_methods() {
        for m in [
            "GET", "POST", "HEAD", "PUT", "OPTIONS", "DELETE", "PATCH", "CONNECT",
        ] {
            let req = format!("{m} /x HTTP/1.1\r\nHost: e.com\r\n\r\n");
            assert!(is_http_request(req.as_bytes()), "应接受: {m}");
            let lower = format!("{} /x HTTP/1.1\r\n", m.to_lowercase());
            assert!(is_http_request(lower.as_bytes()), "应大小写不敏感: {m}");
        }
        // h2c 的 PRI 不在方法表里，必须穿过。
        assert!(!is_http_request(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
        assert!(!is_http_request(b"GARBAGE this is not http\r\n"));
        assert!(!is_http_request(b"GET"));
        assert!(!is_http_request(b""));
    }

    #[test]
    fn http_host_parsing_quirks() {
        assert_eq!(
            http_host(b"GET /x HTTP/1.1\r\nHost: Down.QQ.com.\r\n\r\n"),
            "down.qq.com"
        );
        assert_eq!(
            http_host(b"GET /x HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"),
            "example.com"
        );
        assert_eq!(
            http_host(b"GET /x HTTP/1.1\r\nHost: 1.2.3.4:80\r\n\r\n"),
            "1.2.3.4"
        );
        assert_eq!(
            http_host(b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            "example.com"
        );
        assert_eq!(http_host(b"GET /x HTTP/1.1\r\n\r\n"), "");
        // body 里的第二个 Host 不得覆盖头部首个。
        assert_eq!(
            http_host(
                b"POST /api HTTP/1.1\r\nHost: shop.example.com\r\n\r\nx\r\nHost: down.qq.com\r\n"
            ),
            "shop.example.com"
        );
    }

    #[test]
    fn http_path_takes_second_segment() {
        assert_eq!(
            http_path(b"GET /app.apk?x=1 HTTP/1.1\r\nHost: e.com\r\n\r\n"),
            "/app.apk?x=1"
        );
        assert_eq!(
            http_path(b"GET http://e.com/f HTTP/1.1\r\n\r\n"),
            "http://e.com/f"
        );
        assert_eq!(http_path(b"GARBAGE\r\n"), "");
    }

    #[test]
    fn http_user_agent_gates_and_extracts() {
        assert_eq!(
            http_user_agent(b"GET /f HTTP/1.1\r\nHost: e.com\r\nUser-Agent: Thunder/7.0\r\n\r\n"),
            "thunder/7.0"
        );
        // 太短 / 非 HTTP / 无头一律空串。
        assert_eq!(http_user_agent(b"GET /f HTTP/1"), "");
        assert_eq!(http_user_agent(b"GARBAGE User-Agent: Thunder\r\nxxxx"), "");
        assert_eq!(
            http_user_agent(b"GET /f HTTP/1.1\r\nHost: e.com\r\n\r\n"),
            ""
        );
        // body 里的 UA 不得漏出。
        assert_eq!(
            http_user_agent(b"POST /u HTTP/1.1\r\nHost: e.com\r\n\r\nx\nUser-Agent: Thunder\r\n"),
            ""
        );
    }

    #[test]
    fn match_domain_suffix_semantics() {
        let set: HashSet<String> = ["down.qq.com", "example-dl.test"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(match_domain_suffix("down.qq.com", &set));
        assert!(match_domain_suffix("a.down.qq.com", &set));
        assert!(match_domain_suffix("DOWN.QQ.COM.", &set));
        assert!(match_domain_suffix("  a.down.qq.com  ", &set));
        assert!(!match_domain_suffix("example.com", &set));
        assert!(!match_domain_suffix("notdown.qq.com", &set));
        assert!(!match_domain_suffix("", &set));
        assert!(!match_domain_suffix("   ", &set));
    }

    #[test]
    fn dl_query_hit_substring() {
        let q: Vec<String> = ["x-oss-signature", "q-sign-algorithm"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(dl_query_hit("/f?x-oss-signature=abc", &q));
        assert!(dl_query_hit("/F?X-OSS-SIGNATURE=abc", &q));
        assert!(!dl_query_hit("/api?sign=abc", &q));
    }
}
