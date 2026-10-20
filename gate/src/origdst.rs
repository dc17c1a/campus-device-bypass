//! 原目的地址（origdst）raw-socket 层：TCP `SO_ORIGINAL_DST` 与 UDP `recvmsg` cmsg。
//!
//! Go 权威：`udp.go` `origDstFromSC`（TCP）与 `parseOrigDst` / `enableRecvOrigDst` /
//! `enableTransparent`（UDP），以及加固测试 `TestParseOrigDst` 与
//! `TestParseOrigDstLenOverflow`。
//!
//! cmsg 长度一律按无符号比较：恶意 `Len`（如 `1<<63`、`u64::MAX`，转有符号为负）
//! 必须安全失败，绝不 panic、下标越界（release 设 `panic = "abort"`，一次 panic
//! 即杀死整个网关）。游标推进用 `checked_add` 守卫。
//!
//! 本模块的公开函数暂无消费方（Task 16 接 TCP `tcp_original_dst`、Task 18 接 UDP
//! `udp_recvmsg`/`enable_*` 做透明泵），非测试构建下 whole-module 视为未使用；
//! 待上述任务接入后该 allow 即可删除（Task 19 统一清理）。

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::RawFd;

/// `SO_ORIGINAL_DST`（level `SOL_IP`=0，opt 80）。
const SO_ORIGINAL_DST: libc::c_int = 80;
/// `IP_RECVORIGDSTADDR`（level `IPPROTO_IP`=0，opt 20）。
const IP_RECVORIGDSTADDR: libc::c_int = 20;
/// `IP_TRANSPARENT`（level `IPPROTO_IP`，opt 19）：TPROXY 投递前提。
const IP_TRANSPARENT: libc::c_int = 19;
/// 64 位 cmsghdr 头长：len(8) + level(4) + type(4) = 16。
const CMSGHDR_LEN: usize = 16;

/// `tcp_original_dst` 的错误：非法 family/port（串与 Go 逐字节一致）或系统调用失败。
#[derive(Debug)]
pub enum OrigDstErr {
    Invalid { family: u16, port: u16 },
    Sys(std::io::Error),
}

impl fmt::Display for OrigDstErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrigDstErr::Invalid { family, port } => {
                write!(f, "origdst invalid family={family} port={port}")
            }
            OrigDstErr::Sys(e) => write!(f, "origdst getsockopt: {e}"),
        }
    }
}

impl std::error::Error for OrigDstErr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OrigDstErr::Invalid { .. } => None,
            OrigDstErr::Sys(e) => Some(e),
        }
    }
}

/// TCP：已连接 socket 上 `getsockopt(SOL_IP, SO_ORIGINAL_DST)` 取 conntrack 原目的。
///
/// 解析 `{family:u16(本机序), port:be16, addr:4B, zero:8B}`；
/// `family != 2(AF_INET) || port == 0` → `OrigDstErr::Invalid`。
pub fn tcp_original_dst(fd: RawFd) -> Result<SocketAddrV4, OrigDstErr> {
    let mut raw = [0u8; 16];
    let mut len = raw.len() as libc::socklen_t;
    // SAFETY：raw 16 字节可写，len 指向合法 socklen_t；getsockopt 成功时填回实际长度。
    let rc = unsafe {
        libc::getsockopt(
            fd,
            0, /* SOL_IP */
            SO_ORIGINAL_DST,
            raw.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(OrigDstErr::Sys(std::io::Error::last_os_error()));
    }
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    if family != 2 || port == 0 {
        return Err(OrigDstErr::Invalid { family, port });
    }
    let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
    Ok(SocketAddrV4::new(ip, port))
}

/// UDP：在套接字上打开 `IP_RECVORIGDSTADDR`，使内核随包附带 `IP_ORIGDSTADDR` cmsg。
pub fn enable_recv_orig_dst(fd: RawFd) -> std::io::Result<()> {
    set_ip_int(fd, IP_RECVORIGDSTADDR)
}

/// 在套接字上打开 `IP_TRANSPARENT`（TPROXY 投递前提，需 CAP_NET_ADMIN）。
pub fn enable_transparent(fd: RawFd) -> std::io::Result<()> {
    set_ip_int(fd, IP_TRANSPARENT)
}

fn set_ip_int(fd: RawFd, opt: libc::c_int) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY：one 指向合法 c_int，长度匹配。
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            opt,
            (&one as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// cmsg 对齐（64 位 Linux 按 8 对齐）；溢出时返回 `None` 由调用方终止遍历。
fn cmsg_align(n: usize) -> Option<usize> {
    n.checked_add(7).map(|v| v & !7)
}

/// UDP：从 `recvmsg` 的 oob 控制消息中找 `level==0 && type==20(IP_ORIGDSTADDR)`，
/// 解析出 sockaddr_in。纯函数，绝不 panic：任何非法形状返回 `None`。
///
/// 规则（与 Go `parseOrigDst` 一致）：
/// - `Len` 用无符号比较，必须 `>= 16 && <= oob.len()`，否则立即 break；
/// - 命中类型但内容非法（数据 `< 8`、非 `AF_INET`、端口 0）→ `None`（整体失败，
///   不继续找下一个）；
/// - 游标推进用 `checked_add`，溢出/越界即 break。
pub fn udp_parse_orig_dst(oob: &[u8]) -> Option<SocketAddrV4> {
    let mut off: usize = 0;
    while oob.len().checked_sub(off).is_some_and(|r| r >= CMSGHDR_LEN) {
        let base = &oob[off..];
        let len = u64::from_ne_bytes(base[0..8].try_into().ok()?) as usize;
        let level = i32::from_ne_bytes(base[8..12].try_into().ok()?);
        let typ = i32::from_ne_bytes(base[12..16].try_into().ok()?);
        // 无符号长度守卫：恶意 Len（≥2^63 等）转有符号为负会越过旧守卫，
        // 这里一律按 usize 比较，非法立即 break，绝不索引。
        if len < CMSGHDR_LEN {
            break;
        }
        let remain = oob.len() - off;
        if len > remain {
            break;
        }
        if level == 0 && typ == 20 {
            let d = &oob[off + CMSGHDR_LEN..off + len];
            if d.len() >= 8 && d[0] == 2 {
                let port = u16::from_be_bytes([d[2], d[3]]);
                if port != 0 {
                    let ip = Ipv4Addr::new(d[4], d[5], d[6], d[7]);
                    return Some(SocketAddrV4::new(ip, port));
                }
            }
            return None;
        }
        let next = cmsg_align(len)?;
        off = off.checked_add(next)?;
    }
    None
}

/// UDP：一次 `recvmsg`，返回 `(载荷长, 源, Option<原目的>, truncated)`。
///
/// `truncated` 为 `MSG_TRUNC` 标志（Task 18 的泵依赖它做溢出丢弃判断）；
/// `Option<原目的>` 由 [`udp_parse_orig_dst`] 解析，无 cmsg 时为 `None`。
pub fn udp_recvmsg(
    fd: RawFd,
    buf: &mut [u8],
    oob: &mut [u8],
) -> std::io::Result<(usize, SocketAddrV4, Option<SocketAddrV4>, bool)> {
    let mut src: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_name = (&mut src as *mut libc::sockaddr_in).cast::<libc::c_void>();
    hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = oob.as_mut_ptr().cast::<libc::c_void>();
    // musl 的 `msg_controllen` 是 `socklen_t`（u32），glibc 是 `size_t`：
    // 用推断型别转换保证双目标可编译（oob 为小缓冲，截断无实际风险）。
    hdr.msg_controllen = oob.len() as _;
    // SAFETY：iov/msg_name/msg_control 均指向存活的本地缓冲；flags 传 0。
    let n = unsafe { libc::recvmsg(fd, &mut hdr, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let octets = src.sin_addr.s_addr.to_ne_bytes();
    let src_addr = SocketAddrV4::new(
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
        u16::from_be(src.sin_port),
    );
    let oobn = (hdr.msg_controllen as usize).min(oob.len());
    let orig = udp_parse_orig_dst(&oob[..oobn]);
    let truncated = (hdr.msg_flags & libc::MSG_TRUNC) != 0;
    Ok((n as usize, src_addr, orig, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_cmsg(level: i32, typ: i32, data: &[u8]) -> Vec<u8> {
        // cmsghdr: len(8) level(4) type(4) 于 64 位 = 16 字节头
        let len = 16 + data.len();
        let mut v = Vec::new();
        v.extend_from_slice(&(len as u64).to_ne_bytes());
        v.extend_from_slice(&level.to_ne_bytes());
        v.extend_from_slice(&typ.to_ne_bytes());
        v.extend_from_slice(data);
        while v.len() % 8 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn parses_valid_origdst_cmsg() {
        let mut d = vec![0u8; 16];
        d[0] = 2; // AF_INET
        d[2] = 0x4b;
        d[3] = 0x66; // port 19302 (= 0x4B66)
        d[4..8].copy_from_slice(&[74, 125, 250, 129]);
        let oob = build_cmsg(0, 20, &d);
        let a = udp_parse_orig_dst(&oob).expect("应解析成功");
        assert_eq!(a.to_string(), "74.125.250.129:19302");
    }

    #[test]
    fn rejects_malformed_and_never_panics() {
        assert!(udp_parse_orig_dst(&[]).is_none());
        assert!(udp_parse_orig_dst(&[0u8; 8]).is_none());
        let mut d = vec![0u8; 16];
        d[0] = 2;
        assert!(
            udp_parse_orig_dst(&build_cmsg(0, 20, &d)).is_none(),
            "端口 0 必须拒绝"
        );
        let mut d2 = vec![0u8; 16];
        d2[0] = 10; // 非 AF_INET
        d2[2] = 0x4b;
        d2[3] = 0x4e;
        assert!(udp_parse_orig_dst(&build_cmsg(0, 20, &d2)).is_none());
        assert!(
            udp_parse_orig_dst(&build_cmsg(0, 21, &d)).is_none(),
            "类型不符"
        );
    }

    #[test]
    fn huge_cmsg_len_does_not_panic_or_parse() {
        for bad in [1u64 << 63, u64::MAX, 1u64 << 40, 1u64 << 62] {
            let mut v = bad.to_ne_bytes().to_vec();
            v.extend_from_slice(&0i32.to_ne_bytes());
            v.extend_from_slice(&20i32.to_ne_bytes());
            v.extend_from_slice(&[0u8; 16]);
            assert!(udp_parse_orig_dst(&v).is_none(), "len={bad} 必须安全失败");
        }
    }
}
