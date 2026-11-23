//! Small helpers: random ids and tokens, hashes, constant-time compare.

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// `n` random bytes as lowercase hex.
pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("the operating system's random generator failed");
    HEXLOWER.encode(&b)
}

/// 256 random bits as base64url without padding (43 characters), the token
/// format of the sync API.
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("the operating system's random generator failed");
    BASE64URL_NOPAD.encode(&b)
}

/// SHA-256 of a string as lowercase hex (how tokens and tickets are stored).
pub fn sha256_hex(s: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(s.as_bytes()))
}

/// Compares two secrets without leaking where they differ: both are hashed
/// first, so their lengths do not matter either.
pub fn same_secret(a: &str, b: &str) -> bool {
    let x = Sha256::digest(a.as_bytes());
    let y = Sha256::digest(b.as_bytes());
    x.ct_eq(&y).into()
}

/// base64url SHA-256 of DER bytes: a certificate fingerprint as join links
/// carry it (43 characters).
pub fn fingerprint(der: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(der))
}

pub fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A token or ticket: base64url, 43 to 128 characters.
pub fn is_token(s: &str) -> bool {
    (43..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Milliseconds since 1970.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_have_the_api_format() {
        let t = random_token();
        assert_eq!(t.len(), 43);
        assert!(is_token(&t));
        assert!(is_hex(&random_hex(16), 32));
    }

    #[test]
    fn secrets_compare() {
        assert!(same_secret("abc", "abc"));
        assert!(!same_secret("abc", "abd"));
        assert!(!same_secret("abc", "abcd"));
    }
}
