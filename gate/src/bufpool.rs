// TCP 缓冲池：relay 双向拷贝的借出/归还缓冲（Task 15）。
//
// Go  authority：`main.go` `relay` 的两端拷贝缓冲（Go 侧每连接 `make`，
// Rust 侧改由池复用，大小仍取 `cfg.tcp_buf_kb * 1024`，默认 8KB）。
//
// Consumed by Task 16（handle_conn 装配：relay 借缓冲）；接线前保持非测试构建通过（R10）。

use std::net::IpAddr;
use std::sync::Mutex;

/// 池上限：最多保留 64 个缓冲（brief 冻结值）。
const MAX_POOL: usize = 64;

static POOL: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

fn lock() -> std::sync::MutexGuard<'static, Vec<Vec<u8>>> {
    POOL.lock().unwrap_or_else(|e| e.into_inner())
}

/// 从池里取容量 ≥ `size` 的缓冲；池空（或无足够大者）则新建。
pub fn get(size: usize) -> Vec<u8> {
    let mut pool = lock();
    if let Some(i) = pool.iter().rposition(|v| v.capacity() >= size) {
        return pool.swap_remove(i);
    }
    Vec::with_capacity(size)
}

/// 归还缓冲：先 `clear` 保留容量；池已有 64 个则直接丢弃（不收缩、不 panic）。
pub fn put(mut v: Vec<u8>) {
    v.clear();
    let mut pool = lock();
    if pool.len() < MAX_POOL {
        pool.push(v);
    }
}

/// 测试用：当前池内缓冲个数。
#[cfg(test)]
pub fn pool_len() -> usize {
    lock().len()
}

/// 测试用：清空池。
#[cfg(test)]
pub fn reset_pool() {
    lock().clear();
}

/// 本机目的守卫（Go `main.go isLocalDst`）：loopback / private（10/8、
/// 172.16/12、192.168/16）/ link-local unicast（v4 169.254/16，v6 fe80::/10）/
/// unspecified；**不含** CGNAT `100.64/10`（与 Go `IsPrivate` 同为 RFC1918 口径）。
///
/// 纯谓词：只判地址类别，不看端口。置于本模块仅因计划如此指定（Task 16），
/// 非池逻辑，不做他用。
pub fn is_local_dst(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_loopback() || a.is_private() || a.is_link_local() || a.is_unspecified()
        }
        IpAddr::V6(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || a.is_unique_local()
                || a.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_reuses_buffers_and_caps_at_64() {
        reset_pool();
        let a = get(8192);
        assert!(a.capacity() >= 8192);
        put(a);
        assert_eq!(pool_len(), 1);
        for _ in 0..100 {
            put(vec![0u8; 8192]);
        }
        assert!(pool_len() <= 64, "池上限 64，实际 {}", pool_len());
    }

    #[test]
    fn put_does_not_shrink_capacity() {
        reset_pool();
        let v = Vec::with_capacity(16384);
        put(v);
        let again = get(16384);
        assert!(again.capacity() >= 16384, "归还后容量必须保留");
    }

    #[test]
    fn is_local_dst_matches_go_semantics() {
        for s in [
            "127.0.0.1",
            "192.168.71.223",
            "192.168.2.1",
            "10.0.0.1",
            "172.16.0.1",
            "169.254.1.1",
            "0.0.0.0",
        ] {
            assert!(is_local_dst(&s.parse().unwrap()), "{s} 应判本机");
        }
        for s in ["8.8.8.8", "1.1.1.1", "223.5.5.5", "100.64.0.1"] {
            assert!(
                !is_local_dst(&s.parse().unwrap()),
                "{s} 不得判本机（CGNAT 不拦）"
            );
        }
    }
}
