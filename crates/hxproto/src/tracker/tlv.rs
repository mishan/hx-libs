//! Tracker v3 TLV fields: the ids, a strict reader and a writer.
//!
//! Every v3 extension block — a listing record's trailer, a registration's
//! extension, an acknowledgment — is a `u16` count followed by that many
//! `{id: u16, len: u16, value: len bytes}` entries, all big-endian.

use std::fmt;

/// `"H3"`: opens the v3 extension block of a registration datagram and of
/// an acknowledgment.
pub const EXT_MAGIC: u16 = 0x4833;

/// Field ids. The blocks follow the specification's grouping.
pub mod id {
    /// Registration: remove this server from the listing.
    pub const DEREGISTER: u16 = 0x0010;

    // Addressing (0x01xx).
    pub const ADDRESS_IPV6: u16 = 0x0100;
    pub const HOSTNAME: u16 = 0x0101;

    // Descriptive (0x02xx).
    pub const SERVER_SOFTWARE: u16 = 0x0200;
    pub const COUNTRY_CODE: u16 = 0x0201;
    pub const REGION: u16 = 0x0202;
    pub const LANGUAGE: u16 = 0x0203;
    pub const MAX_USERS: u16 = 0x0204;
    pub const MATURITY: u16 = 0x0205;
    pub const UPTIME: u16 = 0x0206;
    pub const RULES_URL: u16 = 0x0207;
    pub const BANNER_URL: u16 = 0x0208;
    pub const ICON_URL: u16 = 0x0209;
    pub const LINK_DOWN_MBIT: u16 = 0x020a;
    pub const LINK_UP_MBIT: u16 = 0x020b;
    pub const TIMEZONE_OFFSET: u16 = 0x020c;
    pub const CONTACT_URL: u16 = 0x020d;
    pub const SERVER_LAUNCHED: u16 = 0x020e;
    pub const MIN_PROTOCOL_VERSION: u16 = 0x0210;
    pub const PEAK_24H: u16 = 0x0211;
    pub const AVG_24H: u16 = 0x0212;

    // Capabilities (0x03xx).
    pub const PROTOCOL_VERSION: u16 = 0x0300;
    pub const SUPPORTS_HOPE: u16 = 0x0301;
    pub const SUPPORTS_TLS: u16 = 0x0302;
    pub const TLS_PORT: u16 = 0x0303;
    pub const SUPPORTS_INLINE_MEDIA: u16 = 0x0304;
    pub const SUPPORTS_VOICE: u16 = 0x0305;
    pub const SUPPORTS_LARGE_FILES: u16 = 0x0306;
    pub const SUPPORTS_IPV6: u16 = 0x0307;
    pub const HOPE_CIPHERS: u16 = 0x0309;
    pub const TAGS: u16 = 0x0310;

    // Content index (0x04xx).
    pub const NEWS_COUNT: u16 = 0x0450;
    pub const MSGBOARD_COUNT: u16 = 0x0451;
    pub const FILES_COUNT: u16 = 0x0452;
    pub const TOTAL_FILE_SIZE: u16 = 0x0453;
    pub const LAST_NEWS_TIME: u16 = 0x0454;
    pub const LAST_CHAT_TIME: u16 = 0x0455;

    // Privacy and visibility (0x05xx).
    pub const PRIVATE_LISTING: u16 = 0x0500;
    pub const LISTING_CATEGORY: u16 = 0x0501;
    pub const LANGUAGE_STRICT: u16 = 0x0502;

    // Set by the tracker, not the server (0x06xx).
    pub const IS_PROMOTED: u16 = 0x0600;
    pub const FIRST_SEEN: u16 = 0x0601;
    pub const LAST_HEARTBEAT: u16 = 0x0602;
    pub const VERIFIED_ONLINE: u16 = 0x0603;

    // Registration security and acknowledgment (0x08xx).
    pub const REG_TOKEN: u16 = 0x0800;
    pub const HMAC_SHA256: u16 = 0x0801;
    pub const NONCE: u16 = 0x0802;
    pub const ERROR_MSG: u16 = 0x0810;
    pub const TRACKER_NAME: u16 = 0x0811;

    // Client listing authentication (0x082x).
    pub const AUTH_LOGIN: u16 = 0x0820;
    pub const AUTH_PASS: u16 = 0x0821;

    // Listing-request query fields (0x10xx).
    pub const SEARCH_TEXT: u16 = 0x1001;
    pub const PAGE_OFFSET: u16 = 0x1010;
    pub const PAGE_LIMIT: u16 = 0x1011;
}

/// One field, borrowing its value from the block it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub id: u16,
    pub value: &'a [u8],
}

/// Read exactly `count` fields from `buf`, which must hold nothing else.
///
/// `None` if a field is truncated, fewer than `count` fit, or bytes are
/// left over: a block whose declared count and length disagree is not
/// trustworthy in any part.
pub fn read_all(buf: &[u8], count: u16) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::with_capacity(usize::from(count));
    let mut off = 0usize;
    for _ in 0..count {
        let (tlv, next) = read_at(buf, off)?;
        out.push(tlv);
        off = next;
    }
    (off == buf.len()).then_some(out)
}

/// Read one field at `buf[off..]`, returning it and the offset after it.
/// `None` if the header or the value runs past the end.
pub fn read_at(buf: &[u8], off: usize) -> Option<(Tlv<'_>, usize)> {
    let rest = buf.get(off..)?;
    let header = rest.get(..4)?;
    let id = u16::from_be_bytes([header[0], header[1]]);
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let value = rest.get(4..4 + len)?;
    Some((Tlv { id, value }, off + 4 + len))
}

/// Why a field could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvError {
    /// The value is longer than a `u16` length can say.
    ValueTooLong { id: u16, len: usize },
    /// The block already holds `u16::MAX` fields.
    TooManyFields,
}

impl fmt::Display for TlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlvError::ValueTooLong { id, len } => {
                write!(
                    f,
                    "tracker v3 field 0x{id:04x} is {len} bytes; at most 65535 fit"
                )
            }
            TlvError::TooManyFields => f.write_str("too many tracker v3 fields"),
        }
    }
}

impl std::error::Error for TlvError {}

/// Builds a TLV block: the entries, and a count of them for the `u16`
/// that precedes the block on the wire.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TlvWriter {
    bytes: Vec<u8>,
    count: u16,
}

impl TlvWriter {
    pub fn new() -> TlvWriter {
        TlvWriter::default()
    }

    /// Append one field.
    pub fn push(&mut self, id: u16, value: &[u8]) -> Result<(), TlvError> {
        let len = u16::try_from(value.len()).map_err(|_| TlvError::ValueTooLong {
            id,
            len: value.len(),
        })?;
        let count = self.count.checked_add(1).ok_or(TlvError::TooManyFields)?;
        self.bytes.extend_from_slice(&id.to_be_bytes());
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(value);
        self.count = count;
        Ok(())
    }

    pub fn push_u8(&mut self, id: u16, value: u8) -> Result<(), TlvError> {
        self.push(id, &[value])
    }

    pub fn push_u16(&mut self, id: u16, value: u16) -> Result<(), TlvError> {
        self.push(id, &value.to_be_bytes())
    }

    pub fn push_i16(&mut self, id: u16, value: i16) -> Result<(), TlvError> {
        self.push(id, &value.to_be_bytes())
    }

    pub fn push_u32(&mut self, id: u16, value: u32) -> Result<(), TlvError> {
        self.push(id, &value.to_be_bytes())
    }

    pub fn push_u64(&mut self, id: u16, value: u64) -> Result<(), TlvError> {
        self.push(id, &value.to_be_bytes())
    }

    /// A flag, as the single byte `1`. The specification reads any
    /// non-zero value as set; absence means unset, so there is no `0`
    /// form to write.
    pub fn push_flag(&mut self, id: u16) -> Result<(), TlvError> {
        self.push(id, &[1])
    }

    pub fn push_str(&mut self, id: u16, value: &str) -> Result<(), TlvError> {
        self.push(id, value.as_bytes())
    }

    /// Fields written so far.
    pub fn count(&self) -> u16 {
        self.count
    }

    /// The entries, without the count.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The count and the entries.
    pub fn into_parts(self) -> (u16, Vec<u8>) {
        (self.count, self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_the_spec_layout() {
        let mut w = TlvWriter::new();
        w.push_u16(id::TLS_PORT, 5600).unwrap();
        w.push_flag(id::SUPPORTS_TLS).unwrap();
        w.push_str(id::REGION, "Oslo").unwrap();
        assert_eq!(w.count(), 3);
        assert_eq!(
            w.bytes(),
            [
                &[0x03, 0x03, 0x00, 0x02, 0x15, 0xe0][..],
                &[0x03, 0x02, 0x00, 0x01, 0x01],
                &[0x02, 0x02, 0x00, 0x04, b'O', b's', b'l', b'o'],
            ]
            .concat()
        );
    }

    #[test]
    fn reads_back_what_it_writes() {
        let mut w = TlvWriter::new();
        w.push_u32(id::UPTIME, 7).unwrap();
        w.push(id::NONCE, &[]).unwrap();
        let (count, bytes) = w.into_parts();
        let fields = read_all(&bytes, count).unwrap();
        assert_eq!(
            fields,
            vec![
                Tlv {
                    id: id::UPTIME,
                    value: &[0, 0, 0, 7]
                },
                Tlv {
                    id: id::NONCE,
                    value: &[]
                },
            ]
        );
    }

    #[test]
    fn a_count_that_disagrees_with_the_bytes_is_rejected() {
        let mut w = TlvWriter::new();
        w.push_u8(id::MATURITY, 1).unwrap();
        w.push_u8(id::LISTING_CATEGORY, 2).unwrap();
        let bytes = w.bytes().to_vec();
        assert!(read_all(&bytes, 2).is_some());
        assert!(read_all(&bytes, 1).is_none(), "leftover bytes");
        assert!(read_all(&bytes, 3).is_none(), "too few fields");
        assert!(
            read_all(&bytes[..bytes.len() - 1], 2).is_none(),
            "truncated value"
        );
        assert!(read_all(&[], 0).is_some());
    }

    #[test]
    fn values_past_u16_are_refused() {
        let mut w = TlvWriter::new();
        let big = vec![0u8; 65_536];
        assert_eq!(
            w.push(id::TAGS, &big),
            Err(TlvError::ValueTooLong {
                id: id::TAGS,
                len: 65_536
            })
        );
        assert_eq!(w.count(), 0, "a refused field leaves no trace");
        assert!(w.push(id::TAGS, &big[..65_535]).is_ok());
    }
}
