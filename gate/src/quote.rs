// Consumed by Task 9 (gate.log / udp_err.log rendering).

/// Go `strconv.Quote` ASCII-equivalent: returns the string WITH surrounding
/// double quotes. Handles exactly the reachable value domain (spec section
/// 6.2): `"` -> `\"`, `\` -> `\\`, newline/tab/CR short escapes, other C0
/// controls and DEL (0x7f) -> `\xNN` (lowercase hex). Chars >= 0x80 are
/// pushed through unchanged (defensive only — unreachable in practice, but
/// must not panic or mangle; char-wise iteration keeps UTF-8 intact).
pub fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\0'..='\u{1f}' | '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", c as u8));
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Lowercase hex of the first `max` bytes; appends `..` ONLY when the input
/// is longer than `max` bytes.
pub fn hex_prefix(b: &[u8], max: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let n = b.len().min(max);
    let mut out = String::with_capacity(n * 2 + 2);
    for &byte in &b[..n] {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    if b.len() > max {
        out.push_str("..");
    }
    out
}

/// Lowercase hex of the first 16 bytes (udp_err use), never suffixed
/// with `..`. Short inputs yield only the available bytes' hex — no
/// padding, no panic.
pub fn hex_prefix16(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let n = b.len().min(16);
    let mut out = String::with_capacity(n * 2);
    for &byte in &b[..n] {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Truncates at 64 BYTES (not chars), appending `..` when longer. The cut
/// backs off to a UTF-8 char boundary so non-ASCII input cannot panic
/// (value domain is ASCII in practice).
pub fn trunc_detail(s: &str) -> String {
    const MAX: usize = 64;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut end = MAX;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 2);
    out.push_str(&s[..end]);
    out.push_str("..");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_matches_go_for_our_value_domain() {
        assert_eq!(go_quote("192.168.71.223:12347"), "\"192.168.71.223:12347\"");
        assert_eq!(go_quote(""), "\"\"");
        assert_eq!(go_quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(go_quote("a\\b"), "\"a\\\\b\"");
        assert_eq!(go_quote("a\nb"), "\"a\\nb\"");
        assert_eq!(go_quote("\u{7f}"), "\"\\x7f\"");
    }

    #[test]
    fn hex_truncation_appends_dotdot() {
        assert_eq!(hex_prefix(&[0x16, 0x03, 0x01], 24), "160301");
        let b: Vec<u8> = (0..40).collect();
        let s = hex_prefix(&b, 24);
        assert!(s.ends_with(".."));
        assert_eq!(s.len(), 48 + 2);
        assert_eq!(hex_prefix(&[], 24), "");
        assert_eq!(hex_prefix16(&b), "000102030405060708090a0b0c0d0e0f");
    }

    #[test]
    fn detail_truncates_at_64_bytes() {
        let short = "socks reply rep=4";
        assert_eq!(trunc_detail(short), short);
        let long = "x".repeat(100);
        let out = trunc_detail(&long);
        assert_eq!(out.len(), 64 + 2);
        assert!(out.ends_with(".."));
    }
}
