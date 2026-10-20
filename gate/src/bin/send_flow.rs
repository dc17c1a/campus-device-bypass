use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::FromRawFd;

/// `send_flow` 测试发送器：绑定源地址 → connect → 写完 stdin →
/// `shutdown(Write)` → 读到 EOF 或 10s 超时 → 退出码 0。
///
/// brief 原型用 `std::net::TcpSocket`，但本仓库工具链（stable 1.99.1）的
/// `std` 尚无 `TcpSocket`（仍为 unstable 特性，实测 `rustc` 直接拒收），
/// 故此处用已有的 `libc` 依赖做 `socket`+`bind`（源地址，端口 0），
/// 建连成功后交还 `std::net::TcpStream`：系统调用序列与可观察行为一致，
/// 无新增依赖。
fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(
        a.len() == 4 || a.len() == 5,
        "usage: send_flow <src-ip> <dst-ip> <dst-port> [--hold-ms N]"
    );
    let src_ip: IpAddr = a[1].parse().expect("bad src-ip");
    let dst: SocketAddr = format!("{}:{}", a[2], a[3]).parse().expect("bad dst");
    let mut hold_ms: u64 = 0;
    if a.len() == 5 {
        hold_ms = a[4]
            .strip_prefix("--hold-ms=")
            .expect("want --hold-ms=N")
            .parse()
            .expect("bad hold");
    }
    let mut payload = Vec::new();
    std::io::stdin().read_to_end(&mut payload).expect("stdin");
    let mut c = dial_from(src_ip, dst);
    c.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("timeout");
    if hold_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(hold_ms));
    } else {
        c.write_all(&payload).expect("write");
        c.shutdown(std::net::Shutdown::Write).expect("half-close");
    }
    let mut buf = [0u8; 4096];
    loop {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
}

/// 建连：`socket` + `bind(src, 0)` + 阻塞 `connect(dst)`，返回已连接的
/// `TcpStream`（仅 IPv4；测试流量全为 v4，与原型 `TcpSocket::new_v4` 同口径）。
fn dial_from(src: IpAddr, dst: SocketAddr) -> std::net::TcpStream {
    let IpAddr::V4(src4) = src else {
        panic!("bad src-ip (v4 only): {src}");
    };
    let SocketAddr::V4(dst4) = dst else {
        panic!("bad dst (v4 only): {dst}");
    };
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "socket");
    let bind_addr = sockaddr_in(src4, 0);
    let rc = unsafe {
        libc::bind(
            fd,
            &bind_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert!(rc == 0, "bind src");
    let conn_addr = sockaddr_in(*dst4.ip(), dst4.port());
    let rc = unsafe {
        libc::connect(
            fd,
            &conn_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert!(rc == 0, "connect");
    unsafe { std::net::TcpStream::from_raw_fd(fd) }
}

fn sockaddr_in(ip: std::net::Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    }
}
