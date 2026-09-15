//! Safe, consumer-neutral Hotline file-transfer wire primitives.
//!
//! This crate owns byte shapes, not sockets or filesystems. Callers stream
//! fork bytes between the prefix and suffix returned by [`ffo::encode`].

#![forbid(unsafe_code)]

pub mod ffo;
pub mod htxf;
pub mod resume_digest;
pub mod rflt;

/// Checked subtraction used for every resumed fork.
pub fn remaining(total: u64, offset: u64) -> Result<u64, RangeError> {
    total
        .checked_sub(offset)
        .ok_or(RangeError { total, offset })
}

/// A resume offset outside the fork it addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeError {
    pub total: u64,
    pub offset: u64,
}

impl core::fmt::Display for RangeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "offset {} exceeds length {}", self.offset, self.total)
    }
}

impl std::error::Error for RangeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resumed_ranges_are_checked() {
        assert_eq!(remaining(9, 4), Ok(5));
        assert_eq!(remaining(9, 9), Ok(0));
        assert_eq!(
            remaining(9, 10),
            Err(RangeError {
                total: 9,
                offset: 10
            })
        );
    }
}
