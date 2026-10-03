//! The algorithms HOPE negotiates, by their wire labels, and the lists that
//! carry them.

/// The MAC that authenticates the login and derives the keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mac {
    Sha256,
    Sha1,
    Md5,
}

/// The transport cipher. None negotiated is HMAC authentication over a
/// plaintext transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// Blowfish OFB-64, with the per-transaction rekey marker.
    Blowfish,
    /// ChaCha20-Poly1305 records.
    ChaCha20Poly1305,
}

/// The transport compression, applied beneath the cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Despite the name, a zlib (RFC 1950) stream, flushed in full at each unit.
    Gzip,
    /// An LZ4 frame per write.
    Lz4,
    /// A Zstandard frame per write; needs the `zstd` feature.
    Zstd,
}

impl Compression {
    /// Whether this build has it: ZSTD only with the `zstd` feature. What
    /// a build lacks it neither offers nor accepts.
    pub fn available(self) -> bool {
        self != Compression::Zstd || cfg!(feature = "zstd")
    }
}

impl Mac {
    /// Strongest first: what a client offers, and the order a server
    /// prefers.
    pub const ALL: [Mac; 3] = [Mac::Sha256, Mac::Sha1, Mac::Md5];

    pub fn label(self) -> &'static [u8] {
        match self {
            Mac::Sha256 => b"HMAC-SHA256",
            Mac::Sha1 => b"HMAC-SHA1",
            Mac::Md5 => b"HMAC-MD5",
        }
    }

    pub fn from_label(label: &[u8]) -> Option<Self> {
        Mac::ALL.into_iter().find(|m| m.label() == label)
    }

    /// The MAC of `text` under `key`.
    pub fn mac(self, key: &[u8], text: &[u8]) -> Vec<u8> {
        let mut md = [0u8; 32];
        let name = std::str::from_utf8(self.label()).expect("labels are ASCII");
        let len = hxcrypto::hash::hmac_xxx(&mut md, key, text, name) as usize;
        assert!(len > 0, "every Mac is one hxcrypto knows");
        md[..len].to_vec()
    }
}

impl Cipher {
    pub fn label(self) -> &'static [u8] {
        match self {
            Cipher::Blowfish => b"BLOWFISH",
            Cipher::ChaCha20Poly1305 => b"CHACHA20-POLY1305",
        }
    }

    pub fn from_label(label: &[u8]) -> Option<Self> {
        [Cipher::Blowfish, Cipher::ChaCha20Poly1305]
            .into_iter()
            .find(|c| c.label() == label)
    }
}

impl Compression {
    pub fn label(self) -> &'static [u8] {
        match self {
            Compression::Gzip => b"GZIP",
            Compression::Lz4 => b"LZ4",
            Compression::Zstd => b"ZSTD",
        }
    }

    pub fn from_label(label: &[u8]) -> Option<Self> {
        [Compression::Gzip, Compression::Lz4, Compression::Zstd]
            .into_iter()
            .find(|c| c.label() == label)
    }
}

/// An algorithm list as HOPE sends it: a big-endian u16 count, then each
/// label behind a one-byte length. `None` for a label too long for that.
pub fn encode_list(labels: &[&[u8]]) -> Option<Vec<u8>> {
    let count = u16::try_from(labels.len()).ok()?;
    let mut out = count.to_be_bytes().to_vec();
    for l in labels {
        out.push(u8::try_from(l.len()).ok()?);
        out.extend_from_slice(l);
    }
    Some(out)
}

/// The labels of an encoded list, or `None` for one that does not parse.
pub fn parse_list(buf: &[u8]) -> Option<Vec<Vec<u8>>> {
    // A list has a handful of entries; a count far past that is a reply
    // trying to make us allocate.
    const MAX_ENTRIES: usize = 64;
    let count = u16::from_be_bytes([*buf.first()?, *buf.get(1)?]) as usize;
    if count > MAX_ENTRIES {
        return None;
    }
    let mut rest = &buf[2..];
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let (&len, tail) = rest.split_first()?;
        let label = tail.get(..len as usize)?;
        out.push(label.to_vec());
        rest = &tail[len as usize..];
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_is_the_count_then_each_label_behind_its_length() {
        let list = encode_list(&[b"HMAC-SHA256", b"HMAC-SHA1", b"HMAC-MD5"]).unwrap();
        assert_eq!(list, b"\x00\x03\x0bHMAC-SHA256\x09HMAC-SHA1\x08HMAC-MD5");
        assert_eq!(
            parse_list(&list).unwrap(),
            [&b"HMAC-SHA256"[..], b"HMAC-SHA1", b"HMAC-MD5"]
        );
        assert_eq!(encode_list(&[]).unwrap(), [0, 0]);
    }

    #[test]
    fn lists_that_do_not_add_up_are_refused() {
        for bad in [
            &b""[..],
            b"\x00",
            b"\x00\x03\x05hello",
            b"\x00\x01\x09short",
            b"\xff\xff",
        ] {
            assert_eq!(parse_list(bad), None, "{bad:?}");
        }
        assert_eq!(encode_list(&[&[b'x'; 256]]), None);
    }
}
