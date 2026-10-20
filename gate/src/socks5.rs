//! SOCKS5 CONNECT / UDP ASSOCIATE + UDP 中继封包/解包。
//!
//! 字节布局与 Go 原版（`main.go` `socks5Dial`、`udp.go`
//! `socks5UDPAssociate`/`socksEncap`/`socksDecap`）逐字节一致；
//! 13 条错误串经 `Display` 逐字产出（spec §6.1），直接进入
//! `gate.log` detail 字段与 stderr，拼写即生产可视行为。
//!
//! Consumed by Task 14 (TCP `socks5_connect` dial path) and
//! Task 17/18 (UDP `socks5_udp_associate` + encap/decap path);
//! until those land nothing outside tests references this module.
//! Task 19 removes this allow.
// Task 14/17/18 消费本模块（CONNECT 拨号 / UDP ASSOCIATE / encap·decap）。

use std::fmt;
use std::io;
use std::net::SocketAddrV4;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// SOCKS5 协议错误。`Display` 输出与 Go 原版逐字一致。
#[derive(Debug)]
pub enum SocksErr {
    Greet([u8; 2]),
    ReplyVer(u8),
    ReplyRsv(u8),
    ReplyRep(u8),
    Atyp(u8),
    UdpGreet([u8; 2]),
    UdpAssocVer(u8),
    UdpAssocRsv(u8),
    UdpAssocRep(u8),
    UdpRelayIpv6,
    UdpAtyp(u8),
    #[cfg(test)]
    NonIpv4Dst(String),
    BadUdpHdr,
    Io(io::Error),
}

impl fmt::Display for SocksErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocksErr::Greet(r) => write!(f, "socks greet {:02x}{:02x}", r[0], r[1]),
            SocksErr::ReplyVer(v) => write!(f, "socks reply ver={v}"),
            SocksErr::ReplyRsv(v) => write!(f, "socks reply rsv={v}"),
            SocksErr::ReplyRep(v) => write!(f, "socks rep={v}"),
            SocksErr::Atyp(v) => write!(f, "socks atyp={v}"),
            SocksErr::UdpGreet(r) => write!(f, "socks udp greet {:02x}{:02x}", r[0], r[1]),
            SocksErr::UdpAssocVer(v) => write!(f, "socks udp assoc ver={v}"),
            SocksErr::UdpAssocRsv(v) => write!(f, "socks udp assoc rsv={v}"),
            SocksErr::UdpAssocRep(v) => write!(f, "socks udp assoc rep={v}"),
            SocksErr::UdpRelayIpv6 => write!(f, "socks udp relay ipv6 unsupported"),
            SocksErr::UdpAtyp(v) => write!(f, "socks udp atyp={v}"),
            #[cfg(test)]
            SocksErr::NonIpv4Dst(s) => write!(f, "non-ipv4 dst {s}"),
            SocksErr::BadUdpHdr => write!(f, "bad socks udp hdr"),
            SocksErr::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SocksErr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SocksErr::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SocksErr {
    fn from(e: io::Error) -> Self {
        SocksErr::Io(e)
    }
}

fn timed_out() -> SocksErr {
    SocksErr::Io(io::Error::from(io::ErrorKind::TimedOut))
}

/// 封包：RSV(2)+FRAG(0)+ATYP(1)+IPv4+port+payload，输出恒为 `10+len(p)`。
pub fn socks_encap(dst: SocketAddrV4, p: &[u8]) -> Vec<u8> {
    let ip = dst.ip().octets();
    let port = dst.port().to_be_bytes();
    let mut out = Vec::with_capacity(10 + p.len());
    out.extend_from_slice(&[0, 0, 0, 1]);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&port);
    out.extend_from_slice(p);
    out
}

/// 解包，返回内层载荷。要求 `len>=10` 且头四字节为 `[0,0,0,1]`。
pub fn socks_decap(b: &[u8]) -> Result<&[u8], SocksErr> {
    if b.len() < 10 || b[0] != 0 || b[1] != 0 || b[2] != 0 || b[3] != 1 {
        return Err(SocksErr::BadUdpHdr);
    }
    Ok(&b[10..])
}

/// SOCKS5 CONNECT：问候 `{5,1,0}` → 读 2B 要求 `5,0`；
/// 请求 `{5,1,0,1,ip4,port_be}`；回复头 4B 按 VER→RSV→REP 顺序校验
/// （顺序不可换），再按 ATYP 跳过 BND（1→6B、4→18B、3→(1+L)+2B）与 2B 端口。
/// 整个握手共用一个 `timeout`（含 TCP 建连）。
pub async fn socks5_connect(
    proxy: &str,
    dst: SocketAddrV4,
    timeout: Duration,
) -> Result<TcpStream, SocksErr> {
    async fn run(proxy: &str, dst: SocketAddrV4) -> Result<TcpStream, SocksErr> {
        let mut s = TcpStream::connect(proxy).await?;
        let _ = s.set_nodelay(true);
        s.write_all(&[5, 1, 0]).await?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await?;
        if r != [5, 0] {
            return Err(SocksErr::Greet(r));
        }
        let ip = dst.ip().octets();
        let port = dst.port().to_be_bytes();
        s.write_all(&[5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], port[0], port[1]])
            .await?;
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await?;
        if hdr[0] != 5 {
            return Err(SocksErr::ReplyVer(hdr[0]));
        }
        if hdr[2] != 0 {
            return Err(SocksErr::ReplyRsv(hdr[2]));
        }
        if hdr[1] != 0 {
            return Err(SocksErr::ReplyRep(hdr[1]));
        }
        match hdr[3] {
            1 => {
                let mut rest = [0u8; 6];
                s.read_exact(&mut rest).await?;
            }
            4 => {
                let mut rest = [0u8; 18];
                s.read_exact(&mut rest).await?;
            }
            3 => {
                let mut lb = [0u8; 1];
                s.read_exact(&mut lb).await?;
                let mut rest = vec![0u8; lb[0] as usize + 2];
                s.read_exact(&mut rest).await?;
            }
            a => return Err(SocksErr::Atyp(a)),
        }
        Ok(s)
    }
    match tokio::time::timeout(timeout, run(proxy, dst)).await {
        Ok(r) => r,
        Err(_) => Err(timed_out()),
    }
}

/// SOCKS5 UDP ASSOCIATE：问候同 CONNECT；请求
/// `{5,3,0,1,0,0,0,0,0,0}`（地址填 0，由 server 分配 relay 端口）；
/// 回复头同口径按 VER→RSV→REP 校验；relay ATYP=4 直接
/// `UdpRelayIpv6`（Go 同语义：不建 IPv6 中继口）。
/// 返回 `(已 connect 到 relay 的 UDP 口, 保活 TCP 控制连接)`。
/// 整个握手共用一个 `timeout`（含 TCP 建连与域名解析）。
pub async fn socks5_udp_associate(
    proxy: &str,
    timeout: Duration,
) -> Result<(UdpSocket, TcpStream), SocksErr> {
    async fn run(proxy: &str) -> Result<(UdpSocket, TcpStream), SocksErr> {
        let mut tc = TcpStream::connect(proxy).await?;
        let _ = tc.set_nodelay(true);
        tc.write_all(&[5, 1, 0]).await?;
        let mut r = [0u8; 2];
        tc.read_exact(&mut r).await?;
        if r != [5, 0] {
            return Err(SocksErr::UdpGreet(r));
        }
        tc.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut hdr = [0u8; 4];
        tc.read_exact(&mut hdr).await?;
        if hdr[0] != 5 {
            return Err(SocksErr::UdpAssocVer(hdr[0]));
        }
        if hdr[2] != 0 {
            return Err(SocksErr::UdpAssocRsv(hdr[2]));
        }
        if hdr[1] != 0 {
            return Err(SocksErr::UdpAssocRep(hdr[1]));
        }
        let relay = match hdr[3] {
            1 => {
                let mut rest = [0u8; 6];
                tc.read_exact(&mut rest).await?;
                let ip = std::net::Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
                let port = u16::from_be_bytes([rest[4], rest[5]]);
                std::net::SocketAddr::V4(SocketAddrV4::new(ip, port))
            }
            4 => return Err(SocksErr::UdpRelayIpv6),
            3 => {
                let mut lb = [0u8; 1];
                tc.read_exact(&mut lb).await?;
                let mut rest = vec![0u8; lb[0] as usize + 2];
                tc.read_exact(&mut rest).await?;
                let n = rest.len();
                let port = u16::from_be_bytes([rest[n - 2], rest[n - 1]]);
                let host = String::from_utf8_lossy(&rest[..n - 2]).into_owned();
                let mut addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
                addrs.next().ok_or_else(|| {
                    SocksErr::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "socks udp relay resolve empty",
                    ))
                })?
            }
            a => return Err(SocksErr::UdpAtyp(a)),
        };
        let uc = UdpSocket::bind("0.0.0.0:0").await?;
        uc.connect(relay).await?;
        Ok((uc, tc))
    }
    match tokio::time::timeout(timeout, run(proxy)).await {
        Ok(r) => r,
        Err(_) => Err(timed_out()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn encap_layout_is_exact() {
        let dst: SocketAddrV4 = "1.2.3.4:3478".parse().unwrap();
        let e = socks_encap(dst, &[0xaa; 8]);
        assert_eq!(e.len(), 18);
        assert_eq!(&e[0..4], &[0, 0, 0, 1]);
        assert_eq!(&e[4..8], &[1, 2, 3, 4]);
        assert_eq!(e[8], 0x0d); // 3478 >> 8
        assert_eq!(e[9], 0x96); // 3478 & 0xff
        assert_eq!(socks_decap(&e).unwrap(), &[0xaa; 8]);
    }

    #[test]
    fn decap_rejects_short_and_wrong_atyp() {
        assert!(socks_decap(&[0u8; 9]).is_err());
        let mut b = vec![0u8, 0, 0, 3, 1, 2, 3, 4, 0, 0];
        b[3] = 3;
        assert_eq!(
            socks_decap(&b).unwrap_err().to_string(),
            "bad socks udp hdr"
        );
    }

    #[test]
    fn greeting_and_reply_error_strings_are_verbatim() {
        assert_eq!(
            SocksErr::Greet([0x00, 0x00]).to_string(),
            "socks greet 0000"
        );
        assert_eq!(SocksErr::ReplyVer(0).to_string(), "socks reply ver=0");
        assert_eq!(SocksErr::ReplyRsv(1).to_string(), "socks reply rsv=1");
        assert_eq!(SocksErr::ReplyRep(4).to_string(), "socks rep=4");
        assert_eq!(SocksErr::Atyp(9).to_string(), "socks atyp=9");
        assert_eq!(
            SocksErr::UdpGreet([0, 0]).to_string(),
            "socks udp greet 0000"
        );
        assert_eq!(
            SocksErr::UdpAssocVer(0).to_string(),
            "socks udp assoc ver=0"
        );
        assert_eq!(
            SocksErr::UdpAssocRsv(1).to_string(),
            "socks udp assoc rsv=1"
        );
        assert_eq!(
            SocksErr::UdpAssocRep(4).to_string(),
            "socks udp assoc rep=4"
        );
        assert_eq!(
            SocksErr::UdpRelayIpv6.to_string(),
            "socks udp relay ipv6 unsupported"
        );
        assert_eq!(SocksErr::UdpAtyp(9).to_string(), "socks udp atyp=9");
        assert_eq!(
            SocksErr::NonIpv4Dst("x".into()).to_string(),
            "non-ipv4 dst x"
        );
    }

    /// 假 CONNECT 对端：问候正常，回固定 reply；同时录下客户端发来的
    /// greeting 与请求字节，供调用方断言线序布局。
    async fn fake_connect_peer(
        reply: Vec<u8>,
    ) -> (String, tokio::sync::oneshot::Receiver<(Vec<u8>, Vec<u8>)>) {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let Ok((mut c, _)) = ln.accept().await else {
                return;
            };
            let mut g = [0u8; 3];
            if c.read_exact(&mut g).await.is_err() {
                return;
            }
            if c.write_all(&[5, 0]).await.is_err() {
                return;
            }
            let mut head = [0u8; 4];
            if c.read_exact(&mut head).await.is_err() {
                return;
            }
            let tail_len = match head[3] {
                1 => 6,
                4 => 18,
                3 => {
                    let mut lb = [0u8; 1];
                    if c.read_exact(&mut lb).await.is_err() {
                        return;
                    }
                    lb[0] as usize + 2
                }
                _ => 0,
            };
            let mut tail = vec![0u8; tail_len];
            if c.read_exact(&mut tail).await.is_err() {
                return;
            }
            let mut req = head.to_vec();
            req.extend_from_slice(&tail);
            let _ = tx.send((g.to_vec(), req));
            let _ = c.write_all(&reply).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn connect_sends_exact_bytes_and_succeeds() {
        let (addr, rx) = fake_connect_peer(vec![5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90]).await;
        let dst: SocketAddrV4 = "1.2.3.4:443".parse().unwrap();
        let r = socks5_connect(&addr, dst, Duration::from_secs(5)).await;
        assert!(r.is_ok(), "valid reply must succeed: {r:?}");
        let (greet, req) = rx.await.expect("peer must see full handshake");
        assert_eq!(greet, vec![5, 1, 0]);
        assert_eq!(req, vec![5, 1, 0, 1, 1, 2, 3, 4, 0x01, 0xbb]);
    }

    #[tokio::test]
    async fn connect_reply_check_order_is_ver_rsv_rep() {
        let dst: SocketAddrV4 = "1.2.3.4:443".parse().unwrap();
        // 三个字段全错时必须报 VER（顺序不可换）。
        let (addr, _) = fake_connect_peer(vec![0, 9, 9, 9, 0, 0, 0, 0, 0, 0]).await;
        assert_eq!(
            socks5_connect(&addr, dst, Duration::from_secs(5))
                .await
                .unwrap_err()
                .to_string(),
            "socks reply ver=0"
        );
        // VER 对但 RSV/REP 错 → 报 RSV。
        let (addr, _) = fake_connect_peer(vec![5, 9, 1, 9, 0, 0, 0, 0, 0, 0]).await;
        assert_eq!(
            socks5_connect(&addr, dst, Duration::from_secs(5))
                .await
                .unwrap_err()
                .to_string(),
            "socks reply rsv=1"
        );
        // VER/RSV 对、REP 错 → 报 REP。
        let (addr, _) = fake_connect_peer(vec![5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        assert_eq!(
            socks5_connect(&addr, dst, Duration::from_secs(5))
                .await
                .unwrap_err()
                .to_string(),
            "socks rep=4"
        );
        // 头对但 ATYP 未知 → 报 ATYP。
        let (addr, _) = fake_connect_peer(vec![5, 0, 0, 9, 0, 0, 0, 0, 0, 0]).await;
        assert_eq!(
            socks5_connect(&addr, dst, Duration::from_secs(5))
                .await
                .unwrap_err()
                .to_string(),
            "socks atyp=9"
        );
        // 短包 → io 错误（Go 口径 "unexpected EOF"，Rust 为系统 io 文本）。
        let (addr, _) = fake_connect_peer(vec![5, 0]).await;
        assert!(
            socks5_connect(&addr, dst, Duration::from_secs(5))
                .await
                .is_err()
        );
    }

    /// 假 ASSOCIATE 对端：问候正常，断言请求为全零地址，回指向 `relay_port` 的 relay。
    async fn fake_associate_peer(relay_port: u16, hdr4: Vec<u8>) -> String {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let Ok((mut c, _)) = ln.accept().await else {
                return;
            };
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
            assert_eq!(req, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
            let mut reply = hdr4;
            if reply.len() == 4 {
                reply.extend_from_slice(&[
                    127,
                    0,
                    0,
                    1,
                    (relay_port >> 8) as u8,
                    (relay_port & 0xff) as u8,
                ]);
            }
            let _ = c.write_all(&reply).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        });
        addr
    }

    #[tokio::test]
    async fn udp_associate_round_trips_through_relay() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        let addr = fake_associate_peer(relay_port, vec![5, 0, 0, 1]).await;
        let (uc, _tcp) = socks5_udp_associate(&addr, Duration::from_secs(5))
            .await
            .expect("associate must succeed");
        let dst: SocketAddrV4 = "192.0.2.1:3478".parse().unwrap();
        uc.send(&socks_encap(dst, b"raw-2")).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
            .await
            .expect("relay must get packet")
            .unwrap();
        assert_eq!(socks_decap(&buf[..n]).unwrap(), b"raw-2");
    }

    #[tokio::test]
    async fn udp_associate_rejects_bad_reply() {
        // relay ATYP=4 → 直接拒绝（Go 同语义）。
        let addr = fake_associate_peer(0, vec![5, 0, 0, 4]).await;
        assert_eq!(
            socks5_udp_associate(&addr, Duration::from_secs(5))
                .await
                .unwrap_err()
                .to_string(),
            "socks udp relay ipv6 unsupported"
        );
        // VER 错优先于一切。
        let addr = fake_associate_peer(0, vec![0, 9, 9, 9]).await;
        assert_eq!(
            socks5_udp_associate(&addr, Duration::from_secs(5))
                .await
                .unwrap_err()
                .to_string(),
            "socks udp assoc ver=0"
        );
        // REP 错。
        let addr = fake_associate_peer(0, vec![5, 4, 0, 1]).await;
        assert_eq!(
            socks5_udp_associate(&addr, Duration::from_secs(5))
                .await
                .unwrap_err()
                .to_string(),
            "socks udp assoc rep=4"
        );
    }
}
