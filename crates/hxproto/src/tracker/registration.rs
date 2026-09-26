//! Registration: the UDP datagram a server sends a tracker, and the v3
//! acknowledgment a tracker may send back.
//!
//! ```text
//! version     u16     0x0001 or 0x0003
//! port        u16     the server's TCP port
//! users       u16     users online
//! reserved    u16     0
//! pass_id     u32     the server's registration id
//! name        u8 len + bytes
//! description u8 len + bytes
//! password    u8 len + bytes      the tracker's password, if it has one
//!
//! v3 only:
//! magic       u16     0x4833, "H3"
//! count       u16     + that many TLV fields
//! ```
//!
//! The text fields are bytes here, because their encoding depends on the
//! version: Mac Roman for v1 in practice, UTF-8 for v3. The caller
//! converts (see [`crate::text`]).
//!
//! A v3 datagram can be authenticated: a random `NONCE` field, then an
//! `HMAC_SHA256` field computed over the whole datagram with that field's
//! value zeroed. [`build_v3`] lays both out and leaves the MAC to a
//! caller-supplied signer, so this crate needs no crypto.

use std::fmt;

use super::tlv::{self, id, Tlv, TlvError, TlvWriter, EXT_MAGIC};
use super::{VERSION_V1, VERSION_V3};

/// The largest payload one UDP datagram can carry.
pub const MAX_DATAGRAM: usize = 65_507;

/// Length of the v3 `NONCE` value.
pub const NONCE_LEN: usize = 8;
/// Length of the v3 `HMAC_SHA256` value.
pub const HMAC_LEN: usize = 32;

/// The fields every registration carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration<'a> {
    pub port: u16,
    pub users: u16,
    pub pass_id: u32,
    pub name: &'a [u8],
    pub description: &'a [u8],
    pub password: &'a [u8],
}

/// Why a datagram could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationError {
    /// A text field is longer than its one-byte length allows.
    FieldTooLong { field: &'static str, len: usize },
    /// A TLV field could not be written.
    Tlv(TlvError),
    /// The datagram would not fit in one UDP packet.
    TooLarge { len: usize },
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistrationError::FieldTooLong { field, len } => {
                write!(f, "tracker {field} is {len} bytes; at most 255 fit")
            }
            RegistrationError::Tlv(e) => e.fmt(f),
            RegistrationError::TooLarge { len } => write!(
                f,
                "tracker registration is {len} bytes; UDP permits at most {MAX_DATAGRAM}"
            ),
        }
    }
}

impl std::error::Error for RegistrationError {}

impl From<TlvError> for RegistrationError {
    fn from(e: TlvError) -> Self {
        RegistrationError::Tlv(e)
    }
}

fn base(version: u16, r: &Registration<'_>) -> Result<Vec<u8>, RegistrationError> {
    let fields = [
        ("name", r.name),
        ("description", r.description),
        ("password", r.password),
    ];
    for (field, value) in fields {
        if value.len() > usize::from(u8::MAX) {
            return Err(RegistrationError::FieldTooLong {
                field,
                len: value.len(),
            });
        }
    }
    let mut p = Vec::with_capacity(15 + r.name.len() + r.description.len() + r.password.len());
    p.extend_from_slice(&version.to_be_bytes());
    p.extend_from_slice(&r.port.to_be_bytes());
    p.extend_from_slice(&r.users.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&r.pass_id.to_be_bytes());
    for (_, value) in fields {
        p.push(value.len() as u8);
        p.extend_from_slice(value);
    }
    Ok(p)
}

/// A v1 datagram. At most 780 bytes, so it always fits.
pub fn build_v1(r: &Registration<'_>) -> Result<Vec<u8>, RegistrationError> {
    base(VERSION_V1, r)
}

/// Authentication for a v3 datagram.
pub struct Auth<'s> {
    /// Fresh random bytes for every datagram; the tracker uses them to
    /// refuse replays.
    pub nonce: [u8; NONCE_LEN],
    /// Computes HMAC-SHA256 over the bytes it is given, with the shared
    /// secret.
    pub sign: &'s mut dyn FnMut(&[u8]) -> [u8; HMAC_LEN],
}

/// A v3 datagram: the base fields, then `fields`, then the registration
/// token if the tracker issued one, then — when `auth` is given — the nonce
/// and the HMAC, which must come last because it covers everything before
/// it.
pub fn build_v3(
    r: &Registration<'_>,
    fields: &TlvWriter,
    token: Option<&[u8]>,
    auth: Option<Auth<'_>>,
) -> Result<Vec<u8>, RegistrationError> {
    let mut ext = fields.clone();
    if let Some(token) = token {
        ext.push(id::REG_TOKEN, token)?;
    }
    if let Some(auth) = &auth {
        ext.push(id::NONCE, &auth.nonce)?;
        ext.push(id::HMAC_SHA256, &[0; HMAC_LEN])?;
    }
    let (count, bytes) = ext.into_parts();

    let mut p = base(VERSION_V3, r)?;
    p.extend_from_slice(&EXT_MAGIC.to_be_bytes());
    p.extend_from_slice(&count.to_be_bytes());
    p.extend_from_slice(&bytes);
    if p.len() > MAX_DATAGRAM {
        return Err(RegistrationError::TooLarge { len: p.len() });
    }
    if let Some(auth) = auth {
        let mac = (auth.sign)(&p);
        let at = p.len() - HMAC_LEN;
        p[at..].copy_from_slice(&mac);
    }
    Ok(p)
}

/// A parsed datagram, borrowing from the packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<'a> {
    pub version: u16,
    pub registration: Registration<'a>,
    /// The v3 fields, when the datagram has an extension block.
    pub fields: Option<Vec<Tlv<'a>>>,
}

/// Parse a datagram, as a tracker receives it. `None` if it is truncated,
/// or if a v3 extension block is malformed or followed by stray bytes.
/// A datagram with nothing after the password is valid in any version.
pub fn parse(packet: &[u8]) -> Option<Parsed<'_>> {
    let head = packet.get(..12)?;
    let version = u16::from_be_bytes([head[0], head[1]]);
    let port = u16::from_be_bytes([head[2], head[3]]);
    let users = u16::from_be_bytes([head[4], head[5]]);
    let pass_id = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
    let mut off = 12;
    let mut pascal = || {
        let len = usize::from(*packet.get(off)?);
        let value = packet.get(off + 1..off + 1 + len)?;
        off += 1 + len;
        Some(value)
    };
    let name = pascal()?;
    let description = pascal()?;
    let password = pascal()?;
    let fields = match packet.get(off..)? {
        [] => None,
        [m0, m1, c0, c1, rest @ ..] if u16::from_be_bytes([*m0, *m1]) == EXT_MAGIC => {
            Some(tlv::read_all(rest, u16::from_be_bytes([*c0, *c1]))?)
        }
        _ => return None,
    };
    Some(Parsed {
        version,
        registration: Registration {
            port,
            users,
            pass_id,
            name,
            description,
            password,
        },
        fields,
    })
}

/// For a tracker verifying an authenticated datagram: the bytes to MAC —
/// the packet with its HMAC value zeroed — and the MAC it carries. `None`
/// if the datagram does not parse or its last field is not an
/// `HMAC_SHA256` of the right length.
pub fn hmac_input(packet: &[u8]) -> Option<(Vec<u8>, [u8; HMAC_LEN])> {
    let parsed = parse(packet)?;
    let last = parsed.fields?.pop()?;
    if last.id != id::HMAC_SHA256 || last.value.len() != HMAC_LEN {
        return None;
    }
    let at = packet.len() - HMAC_LEN;
    let mac = <[u8; HMAC_LEN]>::try_from(&packet[at..]).ok()?;
    let mut zeroed = packet.to_vec();
    zeroed[at..].fill(0);
    Some((zeroed, mac))
}

/// A v3 acknowledgment's status byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AckStatus {
    Ok,
    Denied,
    Banned,
    Quota,
    Full,
    Invalid,
    Error,
}

impl AckStatus {
    pub fn from_wire(raw: u8) -> Option<AckStatus> {
        Some(match raw {
            0x00 => AckStatus::Ok,
            0x01 => AckStatus::Denied,
            0x02 => AckStatus::Banned,
            0x03 => AckStatus::Quota,
            0x04 => AckStatus::Full,
            0x05 => AckStatus::Invalid,
            0xff => AckStatus::Error,
            _ => return None,
        })
    }

    pub fn to_wire(self) -> u8 {
        match self {
            AckStatus::Ok => 0x00,
            AckStatus::Denied => 0x01,
            AckStatus::Banned => 0x02,
            AckStatus::Quota => 0x03,
            AckStatus::Full => 0x04,
            AckStatus::Invalid => 0x05,
            AckStatus::Error => 0xff,
        }
    }

    /// Lower-case name, for logs.
    pub fn name(self) -> &'static str {
        match self {
            AckStatus::Ok => "ok",
            AckStatus::Denied => "denied",
            AckStatus::Banned => "banned",
            AckStatus::Quota => "quota",
            AckStatus::Full => "full",
            AckStatus::Invalid => "invalid",
            AckStatus::Error => "error",
        }
    }
}

/// A v3 acknowledgment.
///
/// ```text
/// magic     u16   0x4833
/// status    u8
/// interval  u16   seconds until the next registration is expected
/// count     u16   + that many TLV fields
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub status: AckStatus,
    pub interval: u16,
    /// Send this back as `REG_TOKEN` in later registrations.
    pub token: Option<Vec<u8>>,
    pub error: Option<String>,
    pub tracker_name: Option<String>,
}

/// Why an acknowledgment could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckError {
    Truncated,
    BadMagic,
    UnknownStatus(u8),
    /// The field block is malformed, or bytes follow it.
    BadFields,
    /// A text field is not UTF-8.
    NotUtf8 {
        field: u16,
    },
}

impl fmt::Display for AckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AckError::Truncated => f.write_str("v3 acknowledgment is shorter than 7 bytes"),
            AckError::BadMagic => f.write_str("v3 acknowledgment has bad magic"),
            AckError::UnknownStatus(s) => write!(f, "unknown v3 acknowledgment status 0x{s:02x}"),
            AckError::BadFields => f.write_str("v3 acknowledgment fields are malformed"),
            AckError::NotUtf8 { field } => {
                write!(f, "v3 acknowledgment field 0x{field:04x} is not UTF-8")
            }
        }
    }
}

impl std::error::Error for AckError {}

/// Parse an acknowledgment. Unknown fields are skipped.
pub fn parse_ack(packet: &[u8]) -> Result<Ack, AckError> {
    let head = packet.get(..7).ok_or(AckError::Truncated)?;
    if u16::from_be_bytes([head[0], head[1]]) != EXT_MAGIC {
        return Err(AckError::BadMagic);
    }
    let status = AckStatus::from_wire(head[2]).ok_or(AckError::UnknownStatus(head[2]))?;
    let interval = u16::from_be_bytes([head[3], head[4]]);
    let count = u16::from_be_bytes([head[5], head[6]]);
    let fields = tlv::read_all(&packet[7..], count).ok_or(AckError::BadFields)?;
    let text = |f: &Tlv<'_>| {
        std::str::from_utf8(f.value)
            .map(str::to_owned)
            .map_err(|_| AckError::NotUtf8 { field: f.id })
    };
    let mut ack = Ack {
        status,
        interval,
        token: None,
        error: None,
        tracker_name: None,
    };
    for f in &fields {
        match f.id {
            id::REG_TOKEN => ack.token = Some(f.value.to_vec()),
            id::ERROR_MSG => ack.error = Some(text(f)?),
            id::TRACKER_NAME => ack.tracker_name = Some(text(f)?),
            _ => {}
        }
    }
    Ok(ack)
}

/// Build an acknowledgment, as a tracker sends it.
pub fn build_ack(ack: &Ack) -> Result<Vec<u8>, TlvError> {
    let mut w = TlvWriter::new();
    if let Some(token) = &ack.token {
        w.push(id::REG_TOKEN, token)?;
    }
    if let Some(error) = &ack.error {
        w.push_str(id::ERROR_MSG, error)?;
    }
    if let Some(name) = &ack.tracker_name {
        w.push_str(id::TRACKER_NAME, name)?;
    }
    let (count, bytes) = w.into_parts();
    let mut p = Vec::with_capacity(7 + bytes.len());
    p.extend_from_slice(&EXT_MAGIC.to_be_bytes());
    p.push(ack.status.to_wire());
    p.extend_from_slice(&ack.interval.to_be_bytes());
    p.extend_from_slice(&count.to_be_bytes());
    p.extend_from_slice(&bytes);
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> Registration<'static> {
        Registration {
            port: 5500,
            users: 3,
            pass_id: 0x0102_0304,
            name: b"Name",
            description: b"Desc",
            password: b"",
        }
    }

    #[test]
    fn v1_is_the_classic_layout() {
        assert_eq!(
            build_v1(&reg()).unwrap(),
            [
                &[0x00, 0x01, 0x15, 0x7c, 0x00, 0x03, 0x00, 0x00][..],
                &[0x01, 0x02, 0x03, 0x04],
                &[4, b'N', b'a', b'm', b'e'],
                &[4, b'D', b'e', b's', b'c'],
                &[0],
            ]
            .concat()
        );
    }

    #[test]
    fn text_past_255_bytes_is_refused() {
        let long = [b'x'; 256];
        let r = Registration {
            description: &long,
            ..reg()
        };
        assert_eq!(
            build_v1(&r),
            Err(RegistrationError::FieldTooLong {
                field: "description",
                len: 256
            })
        );
    }

    #[test]
    fn v3_carries_fields_token_nonce_and_a_mac_over_the_zeroed_packet() {
        let mut fields = TlvWriter::new();
        fields.push_u16(id::PROTOCOL_VERSION, 190).unwrap();
        let mut seen = Vec::new();
        let mut sign = |bytes: &[u8]| {
            seen = bytes.to_vec();
            [0xab; HMAC_LEN]
        };
        let p = build_v3(
            &reg(),
            &fields,
            Some(b"tok"),
            Some(Auth {
                nonce: [7; NONCE_LEN],
                sign: &mut sign,
            }),
        )
        .unwrap();

        let parsed = parse(&p).unwrap();
        assert_eq!(parsed.version, VERSION_V3);
        assert_eq!(parsed.registration, reg());
        let ids: Vec<u16> = parsed.fields.unwrap().iter().map(|f| f.id).collect();
        assert_eq!(
            ids,
            vec![
                id::PROTOCOL_VERSION,
                id::REG_TOKEN,
                id::NONCE,
                id::HMAC_SHA256
            ]
        );

        let (zeroed, mac) = hmac_input(&p).unwrap();
        assert_eq!(mac, [0xab; HMAC_LEN]);
        assert_eq!(
            zeroed, seen,
            "the signer saw exactly what a verifier recomputes"
        );
        assert!(zeroed.ends_with(&[0; HMAC_LEN]));
    }

    #[test]
    fn v3_without_auth_has_no_mac_to_verify() {
        let p = build_v3(&reg(), &TlvWriter::new(), None, None).unwrap();
        assert_eq!(parse(&p).unwrap().fields, Some(vec![]));
        assert!(hmac_input(&p).is_none());
    }

    #[test]
    fn oversized_v3_is_refused_before_signing() {
        let mut fields = TlvWriter::new();
        fields.push(id::TAGS, &[b't'; 65_000]).unwrap();
        fields.push(id::RULES_URL, &[b'u'; 1_000]).unwrap();
        let mut sign = |_: &[u8]| -> [u8; HMAC_LEN] { panic!("must not sign") };
        let err = build_v3(
            &reg(),
            &fields,
            None,
            Some(Auth {
                nonce: [0; NONCE_LEN],
                sign: &mut sign,
            }),
        );
        assert!(matches!(err, Err(RegistrationError::TooLarge { .. })));
    }

    #[test]
    fn parse_refuses_stray_bytes_and_bad_blocks() {
        let mut p = build_v1(&reg()).unwrap();
        assert!(parse(&p[..p.len() - 1]).is_none(), "truncated");
        p.push(0xee);
        assert!(parse(&p).is_none(), "stray byte after the password");

        let mut v3 = build_v3(&reg(), &TlvWriter::new(), Some(b"t"), None).unwrap();
        v3.push(0);
        assert!(parse(&v3).is_none(), "trailing byte after the fields");
    }

    #[test]
    fn ack_round_trips() {
        let ack = Ack {
            status: AckStatus::Quota,
            interval: 600,
            token: Some(vec![1, 2, 3]),
            error: Some("slow down".into()),
            tracker_name: Some("Tracker".into()),
        };
        assert_eq!(parse_ack(&build_ack(&ack).unwrap()), Ok(ack));
    }

    #[test]
    fn ack_errors() {
        assert_eq!(parse_ack(&[0x48, 0x33, 0]), Err(AckError::Truncated));
        assert_eq!(
            parse_ack(&[0x48, 0x34, 0, 0, 0, 0, 0]),
            Err(AckError::BadMagic)
        );
        assert_eq!(
            parse_ack(&[0x48, 0x33, 0x42, 0, 0, 0, 0]),
            Err(AckError::UnknownStatus(0x42))
        );
        assert_eq!(
            parse_ack(&[0x48, 0x33, 0, 0, 0, 0, 0, 9]),
            Err(AckError::BadFields)
        );
        let mut w = TlvWriter::new();
        w.push(id::ERROR_MSG, &[0xff]).unwrap();
        let (count, bytes) = w.into_parts();
        let mut p = vec![0x48, 0x33, 0xff, 0, 30];
        p.extend_from_slice(&count.to_be_bytes());
        p.extend_from_slice(&bytes);
        assert_eq!(
            parse_ack(&p),
            Err(AckError::NotUtf8 {
                field: id::ERROR_MSG
            })
        );
    }
}
