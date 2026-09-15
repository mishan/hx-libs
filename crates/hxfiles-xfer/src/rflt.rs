//! Resume Fork List encoding and compatibility parsing.

pub const HEADER_LEN: usize = 42;
pub const ENTRY_LEN: usize = 16;
pub const CANONICAL_LEN: usize = HEADER_LEN + 2 * ENTRY_LEN;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Resume {
    pub data: u32,
    pub resource: u32,
}

/// Parse the fixed offsets used by deployed clients. Old GtkHx releases sent
/// imperfect headers, so the magic, version, and fork count are advisory; an
/// offset is accepted only when all of its bytes are present.
pub fn parse_compatible(bytes: &[u8]) -> Resume {
    Resume {
        data: bytes
            .get(46..50)
            .map(|v| u32::from_be_bytes(v.try_into().expect("four bytes")))
            .unwrap_or(0),
        resource: bytes
            .get(62..66)
            .map(|v| u32::from_be_bytes(v.try_into().expect("four bytes")))
            .unwrap_or(0),
    }
}

pub fn encode(resume: Resume) -> [u8; CANONICAL_LEN] {
    let mut out = [0; CANONICAL_LEN];
    out[..4].copy_from_slice(b"RFLT");
    out[4..6].copy_from_slice(&1u16.to_be_bytes());
    out[40..42].copy_from_slice(&2u16.to_be_bytes());
    out[42..46].copy_from_slice(b"DATA");
    out[46..50].copy_from_slice(&resume.data.to_be_bytes());
    out[58..62].copy_from_slice(b"MACR");
    out[62..66].copy_from_slice(&resume.resource.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_vector_round_trips() {
        let value = Resume {
            data: 0x1122_3344,
            resource: 0x5566_7788,
        };
        let bytes = encode(value);
        assert_eq!(&bytes[..4], b"RFLT");
        assert_eq!(bytes.len(), 74);
        assert_eq!(parse_compatible(&bytes), value);
    }

    #[test]
    fn historical_short_and_malformed_records_are_bounded() {
        let mut short = [0; 50];
        short[46..50].copy_from_slice(&7u32.to_be_bytes());
        assert_eq!(
            parse_compatible(&short),
            Resume {
                data: 7,
                resource: 0
            }
        );
        short[..4].copy_from_slice(b"oops");
        assert_eq!(parse_compatible(&short).data, 7);
        assert_eq!(parse_compatible(&short[..49]), Resume::default());
    }
}
