//! HTXF transfer-subchannel handshake framing.

pub const MAGIC: [u8; 4] = *b"HTXF";
pub const BASE_LEN: usize = 16;
pub const SIZE64_LEN: usize = 8;
pub const RESUME_DIGEST_LEN: usize = 40;
pub const FLAG_LARGE_FILE: u16 = 0x0001;
pub const FLAG_SIZE64: u16 = 0x0002;
pub const FLAG_RESUME: u16 = 0x0004;
pub const KNOWN_FLAGS: u16 = FLAG_LARGE_FILE | FLAG_SIZE64 | FLAG_RESUME;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadMagic,
    UnsupportedFlags(u16),
    FlagRelationship,
    LengthOverflow,
    LengthMismatch,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated HTXF preamble"),
            Self::BadMagic => f.write_str("invalid HTXF magic"),
            Self::UnsupportedFlags(flags) => {
                write!(f, "unsupported HTXF flags: {flags:#06x}")
            }
            Self::FlagRelationship => f.write_str("invalid HTXF flag relationship"),
            Self::LengthOverflow => f.write_str("HTXF length exceeds the selected encoding"),
            Self::LengthMismatch => f.write_str("HTXF legacy and extended lengths disagree"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preamble {
    pub reference: u32,
    pub transfer_len: u64,
    pub type_code: u16,
    pub flags: u16,
    pub resume_digest: Option<[u8; RESUME_DIGEST_LEN]>,
}

impl Preamble {
    pub fn large(&self) -> bool {
        self.flags & FLAG_LARGE_FILE != 0
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        validate_flags(self.flags, self.resume_digest.is_some())?;
        let has_size64 = self.flags & FLAG_SIZE64 != 0;
        if !has_size64 && self.transfer_len > u32::MAX as u64 {
            return Err(Error::LengthOverflow);
        }
        let mut out = Vec::with_capacity(encoded_len(self.flags)?);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.reference.to_be_bytes());
        let legacy_len = if has_size64 {
            0
        } else {
            self.transfer_len as u32
        };
        out.extend_from_slice(&legacy_len.to_be_bytes());
        out.extend_from_slice(&self.type_code.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        if has_size64 {
            out.extend_from_slice(&self.transfer_len.to_be_bytes());
        }
        if let Some(digest) = self.resume_digest {
            out.extend_from_slice(&digest);
        }
        Ok(out)
    }
}

pub fn encoded_len(flags: u16) -> Result<usize, Error> {
    // mhxd reads this half of the word as `__reserved` and ignores it; the
    // rejection here is deliberate. Each flag declares a fixed-size block after
    // the header, so a reader cannot skip one it does not recognize (Large File
    // extension, "Handshake Flags and Length"). Period clients send zero.
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Error::UnsupportedFlags(flags & !KNOWN_FLAGS));
    }
    Ok(BASE_LEN
        + if flags & FLAG_SIZE64 != 0 {
            SIZE64_LEN
        } else {
            0
        }
        + if flags & FLAG_RESUME != 0 {
            RESUME_DIGEST_LEN
        } else {
            0
        })
}

pub fn parse(bytes: &[u8]) -> Result<(Preamble, usize), Error> {
    let base = bytes.get(..BASE_LEN).ok_or(Error::Truncated)?;
    if base[..4] != MAGIC {
        return Err(Error::BadMagic);
    }
    let flags = u16::from_be_bytes(base[14..16].try_into().expect("two bytes"));
    let need = encoded_len(flags)?;
    let full = bytes.get(..need).ok_or(Error::Truncated)?;
    validate_flags(flags, flags & FLAG_RESUME != 0)?;
    let legacy_len = u32::from_be_bytes(base[8..12].try_into().expect("four bytes"));
    let mut at = BASE_LEN;
    let transfer_len = if flags & FLAG_SIZE64 != 0 {
        let n = u64::from_be_bytes(full[at..at + 8].try_into().expect("eight bytes"));
        at += 8;
        if legacy_len != 0 && u64::from(legacy_len) != n {
            return Err(Error::LengthMismatch);
        }
        n
    } else {
        u64::from(legacy_len)
    };
    let resume_digest = if flags & FLAG_RESUME != 0 {
        let mut digest = [0; RESUME_DIGEST_LEN];
        digest.copy_from_slice(&full[at..at + RESUME_DIGEST_LEN]);
        Some(digest)
    } else {
        None
    };
    Ok((
        Preamble {
            reference: u32::from_be_bytes(base[4..8].try_into().expect("four bytes")),
            transfer_len,
            type_code: u16::from_be_bytes(base[12..14].try_into().expect("two bytes")),
            flags,
            resume_digest,
        },
        need,
    ))
}

fn validate_flags(flags: u16, has_digest: bool) -> Result<(), Error> {
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Error::UnsupportedFlags(flags & !KNOWN_FLAGS));
    }
    if flags & (FLAG_SIZE64 | FLAG_RESUME) != 0 && flags & FLAG_LARGE_FILE == 0 {
        return Err(Error::FlagRelationship);
    }
    if has_digest != (flags & FLAG_RESUME != 0) {
        return Err(Error::FlagRelationship);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_legacy_and_large_vectors() {
        let legacy = Preamble {
            reference: 0x1122_3344,
            transfer_len: 5,
            type_code: 1,
            flags: 0,
            resume_digest: None,
        }
        .encode()
        .unwrap();
        assert_eq!(
            legacy,
            [
                b"HTXF".as_slice(),
                &0x1122_3344u32.to_be_bytes(),
                &5u32.to_be_bytes(),
                &1u16.to_be_bytes(),
                &0u16.to_be_bytes()
            ]
            .concat()
        );
        assert_eq!(parse(&legacy).unwrap().0.transfer_len, 5);

        let big = 0x1_0000_0005;
        let large = Preamble {
            reference: 7,
            transfer_len: big,
            type_code: 1,
            flags: FLAG_LARGE_FILE | FLAG_SIZE64,
            resume_digest: None,
        }
        .encode()
        .unwrap();
        assert_eq!(large.len(), 24);
        assert_eq!(&large[8..12], &[0; 4]);
        assert_eq!(&large[16..24], &big.to_be_bytes());
        assert_eq!(parse(&large).unwrap().0.transfer_len, big);
    }

    #[test]
    fn extension_lengths_and_flag_relationships_are_strict() {
        let digest = [0x5a; RESUME_DIGEST_LEN];
        let p = Preamble {
            reference: 1,
            transfer_len: 9,
            type_code: 2,
            flags: FLAG_LARGE_FILE | FLAG_SIZE64 | FLAG_RESUME,
            resume_digest: Some(digest),
        }
        .encode()
        .unwrap();
        assert_eq!(p.len(), 64);
        assert_eq!(parse(&p).unwrap().0.resume_digest, Some(digest));
        assert_eq!(parse(&p[..63]), Err(Error::Truncated));
        assert_eq!(encoded_len(0x8000), Err(Error::UnsupportedFlags(0x8000)));
        assert_eq!(
            Preamble {
                reference: 1,
                transfer_len: 1,
                type_code: 0,
                flags: FLAG_SIZE64,
                resume_digest: None
            }
            .encode(),
            Err(Error::FlagRelationship)
        );
    }
}
