//! The Large File extension's resume digest (fogWraith
//! Capabilities-Large-File.md, "Resume Digest"): binds a resumed raw upload
//! to the exact partial, at the exact length, that the server holds.

use sha2::{Digest, Sha256};

/// The window a server hashes unless it states a larger one.
pub const DEFAULT_WINDOW: u64 = 65_536;
pub const ENCODED_LEN: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    WindowMismatch,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WindowMismatch => {
                f.write_str("resume digest window does not fit the upload offset")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Build the 40-byte resume digest over `window`, the partial's last
/// `window.len()` bytes before `offset`. The server picks the window: at least
/// `min(offset, DEFAULT_WINDOW)` bytes and no more than `offset`. A client
/// checking a server's digest hashes the length the server stated
/// ([`window_len`]) rather than assuming the default.
pub fn encode(offset: u64, window: &[u8]) -> Result<[u8; ENCODED_LEN], Error> {
    let len = window.len() as u64;
    if len < offset.min(DEFAULT_WINDOW) || len > offset {
        return Err(Error::WindowMismatch);
    }
    let mut hasher = Sha256::new();
    hasher.update(offset.to_be_bytes());
    hasher.update(window);
    let mut out = [0; ENCODED_LEN];
    out[..8].copy_from_slice(&len.to_be_bytes());
    out[8..].copy_from_slice(&hasher.finalize());
    Ok(out)
}

/// The window length a digest states.
pub fn window_len(digest: &[u8; ENCODED_LEN]) -> u64 {
    u64::from_be_bytes(digest[..8].try_into().expect("eight bytes"))
}

/// Validate a peer echo against a digest freshly recomputed from the partial.
pub fn matches(expected: &[u8; ENCODED_LEN], echoed: &[u8; ENCODED_LEN]) -> bool {
    // Keep the comparison's work independent of the first differing byte.
    expected
        .iter()
        .zip(echoed)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_binds_offset_and_exact_window() {
        let digest = encode(3, b"abc").unwrap();
        assert_eq!(&digest[..8], &3u64.to_be_bytes());
        assert!(matches(&digest, &digest));
        assert!(!matches(&digest, &encode(3, b"abd").unwrap()));
        assert_eq!(encode(4, b"abc"), Err(Error::WindowMismatch));
    }

    #[test]
    fn long_partial_uses_only_the_declared_window() {
        let window = vec![0x5a; DEFAULT_WINDOW as usize];
        let digest = encode(DEFAULT_WINDOW + 10, &window).unwrap();
        assert_eq!(window_len(&digest), DEFAULT_WINDOW);
    }

    #[test]
    fn a_server_may_state_a_larger_window() {
        let window = vec![0x5a; DEFAULT_WINDOW as usize + 1];
        let digest = encode(DEFAULT_WINDOW + 10, &window).unwrap();
        assert_eq!(window_len(&digest), DEFAULT_WINDOW + 1);
        // Never shorter than the default, never longer than the partial.
        assert_eq!(
            encode(DEFAULT_WINDOW + 10, &window[..DEFAULT_WINDOW as usize - 1]),
            Err(Error::WindowMismatch)
        );
        assert_eq!(encode(3, b"abcd"), Err(Error::WindowMismatch));
    }

    #[test]
    fn error_implements_standard_error_traits() {
        fn assert_error<T: std::error::Error>() {}

        assert_error::<Error>();
        assert_eq!(
            Error::WindowMismatch.to_string(),
            "resume digest window does not fit the upload offset"
        );
    }
}
