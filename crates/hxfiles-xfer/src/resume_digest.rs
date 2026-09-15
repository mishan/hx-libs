//! Digest binding a resumed raw upload to the partial held by the server.

use sha2::{Digest, Sha256};

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
                f.write_str("resume digest window length does not match the upload offset")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Build the 40-byte resume digest from the exact trailing window.
pub fn encode(offset: u64, window: &[u8]) -> Result<[u8; ENCODED_LEN], Error> {
    if window.len() as u64 != offset.min(DEFAULT_WINDOW) {
        return Err(Error::WindowMismatch);
    }
    let mut hasher = Sha256::new();
    hasher.update(offset.to_be_bytes());
    hasher.update(window);
    let mut out = [0; ENCODED_LEN];
    out[..8].copy_from_slice(&(window.len() as u64).to_be_bytes());
    out[8..].copy_from_slice(&hasher.finalize());
    Ok(out)
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
        assert_eq!(&digest[..8], &DEFAULT_WINDOW.to_be_bytes());
    }

    #[test]
    fn error_implements_standard_error_traits() {
        fn assert_error<T: std::error::Error>() {}

        assert_error::<Error>();
        assert_eq!(
            Error::WindowMismatch.to_string(),
            "resume digest window length does not match the upload offset"
        );
    }
}
