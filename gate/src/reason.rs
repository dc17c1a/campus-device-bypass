//! 类型化的 verdict / reason 字面量。
//!
//! 这些字符串会原样出现在 `gate.log`、`stats.tsv` 的键与 `events.jsonl` 事件里，
//! 因此全部收敛为枚举，保证与 Go 原版逐字节一致，杜绝自由拼接产生的笔误。
//!
//! 本模块是全局共享词汇表，在消费方（classify/stats/events/tcp/udp）就位前
//! 只有测试引用它，非测试构建下会被 `dead_code` 判定为未使用；待这些任务接入后
//! 该 allow 即可删除。

use std::borrow::Cow;

/// 拨号判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Proxy,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Proxy => "proxy",
        }
    }
}

/// TCP 流量的分流原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpReason {
    TlsDirect,
    DlDirect,
    DlRange,
    DlQuery,
    DlUa,
    DlExt,
    Default,
}

impl TcpReason {
    pub fn as_str(self) -> &'static str {
        match self {
            TcpReason::TlsDirect => "tls_direct",
            TcpReason::DlDirect => "dl_direct",
            TcpReason::DlRange => "dl_range",
            TcpReason::DlQuery => "dl_query",
            TcpReason::DlUa => "dl_ua",
            TcpReason::DlExt => "dl_ext",
            TcpReason::Default => "default",
        }
    }
}

/// UDP 流量的分流原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpReason {
    StunUdp,
    StunUdpVar,
    UdpProxy,
    UdpDirect,
    UdpShort,
}

impl UdpReason {
    pub fn as_str(self) -> &'static str {
        match self {
            UdpReason::StunUdp => "stun_udp",
            UdpReason::StunUdpVar => "stun_udp_var",
            UdpReason::UdpProxy => "udp_proxy",
            UdpReason::UdpDirect => "udp_direct",
            UdpReason::UdpShort => "udp_short",
        }
    }
}

/// 复合 reason：裸原因，以及两个运行期派生的失败形态。
#[derive(Debug, Clone, Copy)]
pub enum Reason {
    Tcp(TcpReason),
    Udp(UdpReason),
    TcpProxyFail(TcpReason),
    UdpProxyFail(UdpReason),
    UdpUpgradeProxyFail,
}

impl Reason {
    pub fn as_str(&self) -> Cow<'static, str> {
        match self {
            Reason::Tcp(r) => Cow::Borrowed(r.as_str()),
            Reason::Udp(r) => Cow::Borrowed(r.as_str()),
            Reason::TcpProxyFail(r) => format!("{}_proxy_fail", r.as_str()).into(),
            Reason::UdpProxyFail(r) => format!("{}_proxy_fail", r.as_str()).into(),
            Reason::UdpUpgradeProxyFail => Cow::Borrowed("udp_upgrade_proxy_fail"),
        }
    }

    /// 是否进入 events 流：只按 reason 字面量比对，不看 verdict。
    pub fn should_emit_open(&self) -> bool {
        !matches!(self, Reason::Tcp(TcpReason::TlsDirect))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_literals_are_exact() {
        assert_eq!(Verdict::Pass.as_str(), "pass");
        assert_eq!(Verdict::Proxy.as_str(), "proxy");
        assert_eq!(TcpReason::TlsDirect.as_str(), "tls_direct");
        assert_eq!(TcpReason::DlDirect.as_str(), "dl_direct");
        assert_eq!(TcpReason::DlRange.as_str(), "dl_range");
        assert_eq!(TcpReason::DlQuery.as_str(), "dl_query");
        assert_eq!(TcpReason::DlUa.as_str(), "dl_ua");
        assert_eq!(TcpReason::DlExt.as_str(), "dl_ext");
        assert_eq!(TcpReason::Default.as_str(), "default");
        assert_eq!(UdpReason::StunUdp.as_str(), "stun_udp");
        assert_eq!(UdpReason::StunUdpVar.as_str(), "stun_udp_var");
        assert_eq!(UdpReason::UdpProxy.as_str(), "udp_proxy");
        assert_eq!(UdpReason::UdpDirect.as_str(), "udp_direct");
        assert_eq!(UdpReason::UdpShort.as_str(), "udp_short");
    }

    #[test]
    fn proxy_fail_suffixes_base_reason() {
        assert_eq!(
            Reason::TcpProxyFail(TcpReason::DlRange).as_str(),
            "dl_range_proxy_fail"
        );
        assert_eq!(
            Reason::UdpProxyFail(UdpReason::StunUdp).as_str(),
            "stun_udp_proxy_fail"
        );
        assert_eq!(
            Reason::UdpUpgradeProxyFail.as_str(),
            "udp_upgrade_proxy_fail"
        );
    }

    #[test]
    fn emit_open_filter_is_reason_only() {
        assert!(!Reason::Tcp(TcpReason::TlsDirect).should_emit_open());
        // 同一个 tls_direct 加失败后缀后必须进流（Go 只按 reason 字面量比对）
        assert!(Reason::TcpProxyFail(TcpReason::TlsDirect).should_emit_open());
        assert!(Reason::Tcp(TcpReason::DlDirect).should_emit_open());
        assert!(Reason::Udp(UdpReason::StunUdp).should_emit_open());
    }
}
