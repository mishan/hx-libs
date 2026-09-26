//! [`TrackerMeta`]: the typed view of a server's v3 fields.
//!
//! One type for both directions. A registering server fills one in and
//! [`encode`](TrackerMeta::encode)s it into its datagram; a listing client
//! [`decode`](TrackerMeta::decode)s each record's trailer into one. A
//! tracker does both, and adds the tracker-injected fields (0x06xx).
//!
//! Decoding follows the specification's forward-compatibility rules, the
//! same ones GtkHx's C decoder applied before it moved here:
//!
//! - Unknown ids are skipped; a newer peer's fields never break an older
//!   reader.
//! - A repeated id: the last one wins.
//! - A number whose value is the wrong width reads as 0 (the field is
//!   still present). Truncating an overlong value, or zero-extending a
//!   short one, would invent a number the sender never sent. The one
//!   exception is `TOTAL_FILE_SIZE`: the specification corrected it from
//!   `u32` to `u64`, and a 4-byte value is read as the older form.
//! - An IPv6 address of the wrong width is dropped: there is no zero
//!   address worth keeping.
//! - A flag is set if any byte of its value is non-zero.
//! - Maturity and listing category are closed vocabularies: an unknown
//!   value reads as the first entry, as the specification requires.
//! - Strings are UTF-8 by specification; invalid sequences are replaced
//!   with U+FFFD rather than rejecting the record.

use super::tlv::{self, id, TlvError, TlvWriter};

/// Content maturity (0x0205). Unknown values read as [`Maturity::General`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Maturity {
    #[default]
    General = 0,
    Teen = 1,
    Mature = 2,
    Adult = 3,
}

impl Maturity {
    /// The value for a wire byte, clamping an unknown one to `General`.
    pub fn from_wire(raw: u8) -> Maturity {
        match raw {
            1 => Maturity::Teen,
            2 => Maturity::Mature,
            3 => Maturity::Adult,
            _ => Maturity::General,
        }
    }
}

/// Listing category (0x0501). Unknown values read as
/// [`Category::Unspecified`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Category {
    #[default]
    Unspecified = 0,
    General = 1,
    Development = 2,
    Archive = 3,
    Warez = 4,
    Gaming = 5,
    Media = 6,
    Education = 7,
    Research = 8,
    FileSharing = 9,
    Social = 10,
    Security = 11,
    Creative = 12,
}

impl Category {
    /// The value for a wire byte, clamping an unknown one to
    /// `Unspecified`.
    pub fn from_wire(raw: u8) -> Category {
        use Category::*;
        match raw {
            1 => General,
            2 => Development,
            3 => Archive,
            4 => Warez,
            5 => Gaming,
            6 => Media,
            7 => Education,
            8 => Research,
            9 => FileSharing,
            10 => Social,
            11 => Security,
            12 => Creative,
            _ => Unspecified,
        }
    }
}

/// Every v3 field that describes a server. `None` / `false` means the
/// field is absent. Flags have no "present but unset" state on the wire:
/// a writer only sends the ones that are set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrackerMeta {
    // Addressing (0x01xx).
    pub ipv6: Option<[u8; 16]>,
    pub hostname: Option<String>,

    // Descriptive (0x02xx).
    pub server_software: Option<String>,
    /// ISO 3166-1 alpha-2.
    pub country_code: Option<String>,
    pub region: Option<String>,
    /// ISO 639-1.
    pub language: Option<String>,
    pub max_users: Option<u16>,
    pub maturity: Option<Maturity>,
    pub uptime_secs: Option<u32>,
    pub rules_url: Option<String>,
    pub banner_url: Option<String>,
    pub icon_url: Option<String>,
    pub link_down_mbit: Option<u32>,
    pub link_up_mbit: Option<u32>,
    /// Signed minutes from UTC.
    pub timezone_offset_min: Option<i16>,
    pub contact_url: Option<String>,
    /// Unix time.
    pub server_launched: Option<u32>,
    pub min_protocol_version: Option<u16>,
    pub peak_24h: Option<u16>,
    pub avg_24h: Option<u16>,

    // Capabilities (0x03xx).
    pub protocol_version: Option<u16>,
    pub supports_hope: bool,
    pub supports_tls: bool,
    pub tls_port: Option<u16>,
    pub supports_inline_media: bool,
    pub supports_voice: bool,
    pub supports_large_files: bool,
    pub supports_ipv6: bool,
    /// Comma-separated cipher names.
    pub hope_ciphers: Option<String>,
    /// Comma-separated.
    pub tags: Option<String>,

    // Content index (0x04xx).
    pub news_count: Option<u32>,
    pub msgboard_count: Option<u32>,
    pub files_count: Option<u32>,
    /// Bytes. `u64` on the wire; see the module notes for 4-byte values.
    pub total_file_size: Option<u64>,
    /// Unix time.
    pub last_news_time: Option<u32>,
    /// Unix time, public chat only.
    pub last_chat_time: Option<u32>,

    // Privacy and visibility (0x05xx).
    pub private_listing: bool,
    pub listing_category: Option<Category>,
    /// Informational only.
    pub language_strict: bool,

    // Set by the tracker, not the server (0x06xx).
    pub is_promoted: bool,
    /// Unix time.
    pub first_seen: Option<u32>,
    /// Unix time.
    pub last_heartbeat: Option<u32>,
    pub verified_online: bool,
}

fn u8_of(v: &[u8]) -> u8 {
    match v {
        [b] => *b,
        _ => 0,
    }
}

fn u16_of(v: &[u8]) -> u16 {
    <[u8; 2]>::try_from(v).map_or(0, u16::from_be_bytes)
}

fn i16_of(v: &[u8]) -> i16 {
    <[u8; 2]>::try_from(v).map_or(0, i16::from_be_bytes)
}

fn u32_of(v: &[u8]) -> u32 {
    <[u8; 4]>::try_from(v).map_or(0, u32::from_be_bytes)
}

/// `TOTAL_FILE_SIZE`: 8 bytes, or the 4 an implementation from before the
/// specification's correction sends.
fn size_of_files(v: &[u8]) -> u64 {
    match v.len() {
        8 => <[u8; 8]>::try_from(v).map_or(0, u64::from_be_bytes),
        4 => u64::from(u32_of(v)),
        _ => 0,
    }
}

fn flag_of(v: &[u8]) -> bool {
    v.iter().any(|&b| b != 0)
}

fn string_of(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

impl TrackerMeta {
    /// Decode a trailer of `count` fields, as a v3 listing record carries.
    /// `None` if the block itself is malformed (see [`tlv::read_all`]);
    /// individual field values never fail, per the module rules.
    pub fn decode(buf: &[u8], count: u16) -> Option<TrackerMeta> {
        let mut m = TrackerMeta::default();
        for f in tlv::read_all(buf, count)? {
            m.apply(f.id, f.value);
        }
        Some(m)
    }

    /// Fold one field into `self`. Unknown ids are ignored.
    pub fn apply(&mut self, field: u16, v: &[u8]) {
        match field {
            id::ADDRESS_IPV6 => self.ipv6 = <[u8; 16]>::try_from(v).ok(),
            id::HOSTNAME => self.hostname = Some(string_of(v)),

            id::SERVER_SOFTWARE => self.server_software = Some(string_of(v)),
            id::COUNTRY_CODE => self.country_code = Some(string_of(v)),
            id::REGION => self.region = Some(string_of(v)),
            id::LANGUAGE => self.language = Some(string_of(v)),
            id::MAX_USERS => self.max_users = Some(u16_of(v)),
            id::MATURITY => self.maturity = Some(Maturity::from_wire(u8_of(v))),
            id::UPTIME => self.uptime_secs = Some(u32_of(v)),
            id::RULES_URL => self.rules_url = Some(string_of(v)),
            id::BANNER_URL => self.banner_url = Some(string_of(v)),
            id::ICON_URL => self.icon_url = Some(string_of(v)),
            id::LINK_DOWN_MBIT => self.link_down_mbit = Some(u32_of(v)),
            id::LINK_UP_MBIT => self.link_up_mbit = Some(u32_of(v)),
            id::TIMEZONE_OFFSET => self.timezone_offset_min = Some(i16_of(v)),
            id::CONTACT_URL => self.contact_url = Some(string_of(v)),
            id::SERVER_LAUNCHED => self.server_launched = Some(u32_of(v)),
            id::MIN_PROTOCOL_VERSION => self.min_protocol_version = Some(u16_of(v)),
            id::PEAK_24H => self.peak_24h = Some(u16_of(v)),
            id::AVG_24H => self.avg_24h = Some(u16_of(v)),

            id::PROTOCOL_VERSION => self.protocol_version = Some(u16_of(v)),
            id::SUPPORTS_HOPE => self.supports_hope = flag_of(v),
            id::SUPPORTS_TLS => self.supports_tls = flag_of(v),
            id::TLS_PORT => self.tls_port = Some(u16_of(v)),
            id::SUPPORTS_INLINE_MEDIA => self.supports_inline_media = flag_of(v),
            id::SUPPORTS_VOICE => self.supports_voice = flag_of(v),
            id::SUPPORTS_LARGE_FILES => self.supports_large_files = flag_of(v),
            id::SUPPORTS_IPV6 => self.supports_ipv6 = flag_of(v),
            id::HOPE_CIPHERS => self.hope_ciphers = Some(string_of(v)),
            id::TAGS => self.tags = Some(string_of(v)),

            id::NEWS_COUNT => self.news_count = Some(u32_of(v)),
            id::MSGBOARD_COUNT => self.msgboard_count = Some(u32_of(v)),
            id::FILES_COUNT => self.files_count = Some(u32_of(v)),
            id::TOTAL_FILE_SIZE => self.total_file_size = Some(size_of_files(v)),
            id::LAST_NEWS_TIME => self.last_news_time = Some(u32_of(v)),
            id::LAST_CHAT_TIME => self.last_chat_time = Some(u32_of(v)),

            id::PRIVATE_LISTING => self.private_listing = flag_of(v),
            id::LISTING_CATEGORY => {
                self.listing_category = Some(Category::from_wire(u8_of(v)));
            }
            id::LANGUAGE_STRICT => self.language_strict = flag_of(v),

            id::IS_PROMOTED => self.is_promoted = flag_of(v),
            id::FIRST_SEEN => self.first_seen = Some(u32_of(v)),
            id::LAST_HEARTBEAT => self.last_heartbeat = Some(u32_of(v)),
            id::VERIFIED_ONLINE => self.verified_online = flag_of(v),
            _ => {}
        }
    }

    /// Append every present field to `w`, in ascending id order, with the
    /// widths the specification gives. A listing category of
    /// [`Category::Unspecified`] is left out, as the specification requires;
    /// otherwise decoding the result gives back an equal value.
    pub fn encode(&self, w: &mut TlvWriter) -> Result<(), TlvError> {
        fn s(w: &mut TlvWriter, field: u16, v: &Option<String>) -> Result<(), TlvError> {
            v.as_deref().map_or(Ok(()), |v| w.push_str(field, v))
        }
        fn n16(w: &mut TlvWriter, field: u16, v: Option<u16>) -> Result<(), TlvError> {
            v.map_or(Ok(()), |v| w.push_u16(field, v))
        }
        fn n32(w: &mut TlvWriter, field: u16, v: Option<u32>) -> Result<(), TlvError> {
            v.map_or(Ok(()), |v| w.push_u32(field, v))
        }
        fn f(w: &mut TlvWriter, field: u16, v: bool) -> Result<(), TlvError> {
            if v {
                w.push_flag(field)
            } else {
                Ok(())
            }
        }

        if let Some(v) = &self.ipv6 {
            w.push(id::ADDRESS_IPV6, v)?;
        }
        s(w, id::HOSTNAME, &self.hostname)?;

        s(w, id::SERVER_SOFTWARE, &self.server_software)?;
        s(w, id::COUNTRY_CODE, &self.country_code)?;
        s(w, id::REGION, &self.region)?;
        s(w, id::LANGUAGE, &self.language)?;
        n16(w, id::MAX_USERS, self.max_users)?;
        if let Some(v) = self.maturity {
            w.push_u8(id::MATURITY, v as u8)?;
        }
        n32(w, id::UPTIME, self.uptime_secs)?;
        s(w, id::RULES_URL, &self.rules_url)?;
        s(w, id::BANNER_URL, &self.banner_url)?;
        s(w, id::ICON_URL, &self.icon_url)?;
        n32(w, id::LINK_DOWN_MBIT, self.link_down_mbit)?;
        n32(w, id::LINK_UP_MBIT, self.link_up_mbit)?;
        if let Some(v) = self.timezone_offset_min {
            w.push_i16(id::TIMEZONE_OFFSET, v)?;
        }
        s(w, id::CONTACT_URL, &self.contact_url)?;
        n32(w, id::SERVER_LAUNCHED, self.server_launched)?;
        n16(w, id::MIN_PROTOCOL_VERSION, self.min_protocol_version)?;
        n16(w, id::PEAK_24H, self.peak_24h)?;
        n16(w, id::AVG_24H, self.avg_24h)?;

        n16(w, id::PROTOCOL_VERSION, self.protocol_version)?;
        f(w, id::SUPPORTS_HOPE, self.supports_hope)?;
        f(w, id::SUPPORTS_TLS, self.supports_tls)?;
        n16(w, id::TLS_PORT, self.tls_port)?;
        f(w, id::SUPPORTS_INLINE_MEDIA, self.supports_inline_media)?;
        f(w, id::SUPPORTS_VOICE, self.supports_voice)?;
        f(w, id::SUPPORTS_LARGE_FILES, self.supports_large_files)?;
        f(w, id::SUPPORTS_IPV6, self.supports_ipv6)?;
        s(w, id::HOPE_CIPHERS, &self.hope_ciphers)?;
        s(w, id::TAGS, &self.tags)?;

        n32(w, id::NEWS_COUNT, self.news_count)?;
        n32(w, id::MSGBOARD_COUNT, self.msgboard_count)?;
        n32(w, id::FILES_COUNT, self.files_count)?;
        if let Some(v) = self.total_file_size {
            w.push_u64(id::TOTAL_FILE_SIZE, v)?;
        }
        n32(w, id::LAST_NEWS_TIME, self.last_news_time)?;
        n32(w, id::LAST_CHAT_TIME, self.last_chat_time)?;

        f(w, id::PRIVATE_LISTING, self.private_listing)?;
        if let Some(v) = self
            .listing_category
            .filter(|v| *v != Category::Unspecified)
        {
            w.push_u8(id::LISTING_CATEGORY, v as u8)?;
        }
        f(w, id::LANGUAGE_STRICT, self.language_strict)?;

        f(w, id::IS_PROMOTED, self.is_promoted)?;
        n32(w, id::FIRST_SEEN, self.first_seen)?;
        n32(w, id::LAST_HEARTBEAT, self.last_heartbeat)?;
        f(w, id::VERIFIED_ONLINE, self.verified_online)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(fields: &[(u16, &[u8])]) -> (Vec<u8>, u16) {
        let mut w = TlvWriter::new();
        for (field, value) in fields {
            w.push(*field, value).unwrap();
        }
        let (count, bytes) = w.into_parts();
        (bytes, count)
    }

    #[test]
    fn an_empty_trailer_is_all_absent() {
        assert_eq!(TrackerMeta::decode(&[], 0), Some(TrackerMeta::default()));
    }

    #[test]
    fn decodes_every_kind_of_field() {
        let (bytes, count) = block(&[
            (id::SERVER_SOFTWARE, b"hxd/2.0"),
            (id::MAX_USERS, &[0x01, 0x2c]),
            (id::TIMEZONE_OFFSET, &(-300i16).to_be_bytes()),
            (id::UPTIME, &[0, 0, 0x0e, 0x10]),
            (id::SUPPORTS_TLS, &[1]),
            (id::TLS_PORT, &5600u16.to_be_bytes()),
            (id::MATURITY, &[2]),
            (id::LISTING_CATEGORY, &[5]),
            (id::VERIFIED_ONLINE, &[0, 7]),
        ]);
        let m = TrackerMeta::decode(&bytes, count).unwrap();
        assert_eq!(m.server_software.as_deref(), Some("hxd/2.0"));
        assert_eq!(m.max_users, Some(300));
        assert_eq!(m.timezone_offset_min, Some(-300));
        assert_eq!(m.uptime_secs, Some(3600));
        assert!(m.supports_tls);
        assert_eq!(m.tls_port, Some(5600));
        assert_eq!(m.maturity, Some(Maturity::Mature));
        assert_eq!(m.listing_category, Some(Category::Gaming));
        assert!(m.verified_online, "any non-zero byte sets a flag");
        assert!(!m.supports_voice);
    }

    #[test]
    fn forward_compatibility_rules() {
        let (bytes, count) = block(&[
            (0x7777, b"from the future"),
            (id::REGION, b"first"),
            (id::REGION, b"second"),
            (id::MAX_USERS, &[0, 0, 1]),
            (id::MATURITY, &[9]),
            (id::LISTING_CATEGORY, &[200]),
            (id::SUPPORTS_VOICE, &[0]),
            (id::COUNTRY_CODE, &[0x4e, 0xff, 0x4f]),
        ]);
        let m = TrackerMeta::decode(&bytes, count).unwrap();
        assert_eq!(m.region.as_deref(), Some("second"), "the last repeat wins");
        assert_eq!(m.max_users, Some(0), "a wrong width reads as present, zero");
        assert_eq!(m.maturity, Some(Maturity::General), "clamped");
        assert_eq!(m.listing_category, Some(Category::Unspecified), "clamped");
        assert!(!m.supports_voice, "an all-zero flag is unset");
        assert_eq!(m.country_code.as_deref(), Some("N\u{fffd}O"));
    }

    #[test]
    fn total_file_size_is_u64_and_reads_the_old_u32_form() {
        let big = 5_000_000_000u64;
        let (bytes, count) = block(&[(id::TOTAL_FILE_SIZE, &big.to_be_bytes())]);
        let m = TrackerMeta::decode(&bytes, count).unwrap();
        assert_eq!(m.total_file_size, Some(big));
        let (bytes, count) = block(&[(id::TOTAL_FILE_SIZE, &7u32.to_be_bytes())]);
        assert_eq!(
            TrackerMeta::decode(&bytes, count).unwrap().total_file_size,
            Some(7)
        );

        let mut w = TlvWriter::new();
        TrackerMeta {
            total_file_size: Some(big),
            ..TrackerMeta::default()
        }
        .encode(&mut w)
        .unwrap();
        let (count, bytes) = w.into_parts();
        let fields = tlv::read_all(&bytes, count).unwrap();
        assert_eq!(fields[0].value.len(), 8, "the specification's width");
    }

    #[test]
    fn an_unspecified_category_is_not_sent() {
        let mut w = TlvWriter::new();
        TrackerMeta {
            listing_category: Some(Category::Unspecified),
            ..TrackerMeta::default()
        }
        .encode(&mut w)
        .unwrap();
        assert_eq!(w.count(), 0);
    }

    #[test]
    fn a_malformed_trailer_is_refused_whole() {
        let (bytes, count) = block(&[(id::REGION, b"Oslo")]);
        assert!(TrackerMeta::decode(&bytes, count + 1).is_none());
        assert!(TrackerMeta::decode(&bytes[..bytes.len() - 1], count).is_none());
    }

    #[test]
    fn encode_then_decode_is_identity() {
        let m = TrackerMeta {
            ipv6: Some([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            hostname: Some("hotline.example".into()),
            server_software: Some("hxd-ng/0.9".into()),
            country_code: Some("NO".into()),
            language: Some("nb".into()),
            max_users: Some(0),
            maturity: Some(Maturity::General),
            uptime_secs: Some(12),
            timezone_offset_min: Some(-60),
            protocol_version: Some(190),
            supports_tls: true,
            tls_port: Some(5600),
            supports_voice: true,
            tags: Some("retro,files".into()),
            files_count: Some(4),
            total_file_size: Some(1 << 40),
            private_listing: true,
            listing_category: Some(Category::Creative),
            is_promoted: true,
            first_seen: Some(1_700_000_000),
            ..TrackerMeta::default()
        };
        let mut w = TlvWriter::new();
        m.encode(&mut w).unwrap();
        let (count, bytes) = w.into_parts();
        assert_eq!(TrackerMeta::decode(&bytes, count), Some(m));
    }

    #[test]
    fn encodes_in_ascending_id_order_with_spec_widths() {
        let m = TrackerMeta {
            tls_port: Some(5600),
            region: Some("x".into()),
            maturity: Some(Maturity::Teen),
            supports_tls: true,
            ..TrackerMeta::default()
        };
        let mut w = TlvWriter::new();
        m.encode(&mut w).unwrap();
        let (count, bytes) = w.into_parts();
        let fields = tlv::read_all(&bytes, count).unwrap();
        let shape: Vec<(u16, usize)> = fields.iter().map(|f| (f.id, f.value.len())).collect();
        assert_eq!(
            shape,
            vec![
                (id::REGION, 1),
                (id::MATURITY, 1),
                (id::SUPPORTS_TLS, 1),
                (id::TLS_PORT, 2),
            ]
        );
    }
}
