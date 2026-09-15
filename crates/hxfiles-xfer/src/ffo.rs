//! Flattened File Object (`FILP`) encoding and parsing.

use crate::{remaining, RangeError};

pub const FFO_HEADER_LEN: usize = 24;
pub const FORK_HEADER_LEN: usize = 16;
pub const INFO_FIXED_LEN: usize = 74;
pub const MAX_NAME_LEN: usize = 128;
pub const MAX_COMMENT_LEN: usize = 255;
/// The largest INFO fork [`parse_info`] accepts: the fixed fields, a maximal
/// name, and a maximal comment.
pub const MAX_INFO_LEN: usize = INFO_FIXED_LEN + MAX_NAME_LEN + MAX_COMMENT_LEN;
pub const HFS_MAC_HEADER_DELTA: u32 = 3_029_529_600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadVersion,
    BadFork,
    NameTooLong,
    CommentTooLong,
    InfoTooLong,
    SizeOverflow,
    Range(RangeError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated => f.write_str("truncated FILP data"),
            Error::BadVersion => f.write_str("unsupported FILP version"),
            Error::BadFork => f.write_str("invalid FILP fork header"),
            Error::NameTooLong => f.write_str("FILP filename exceeds 128 bytes"),
            Error::CommentTooLong => f.write_str("FILP comment exceeds 255 bytes"),
            Error::InfoTooLong => write!(f, "FILP INFO fork exceeds {MAX_INFO_LEN} bytes"),
            Error::SizeOverflow => f.write_str("FILP size exceeds the selected wire encoding"),
            Error::Range(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<RangeError> for Error {
    fn from(value: RangeError) -> Self {
        Error::Range(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkHeader {
    pub tag: [u8; 4],
    pub length: u64,
}

pub fn pack_fork_header(
    tag: &[u8; 4],
    length: u64,
    large: bool,
) -> Result<[u8; FORK_HEADER_LEN], Error> {
    if !large && length > u32::MAX as u64 {
        return Err(Error::SizeOverflow);
    }
    let mut out = [0; FORK_HEADER_LEN];
    out[..4].copy_from_slice(tag);
    if large {
        out[4..8].copy_from_slice(&(length >> 32).to_be_bytes()[4..]);
    }
    out[12..16].copy_from_slice(&(length as u32).to_be_bytes());
    Ok(out)
}

/// Parse a fork header. In legacy mode only the tag and the 32-bit length are
/// read: mhxd ignores the compression and reserved fields, so a period peer
/// that leaves junk in them still transfers. Large-file mode repurposes the
/// compression field as the high half of the length and the extension keeps
/// the reserved field zero, so there a nonzero one is rejected rather than
/// guessed at.
pub fn parse_fork_header(bytes: &[u8], large: bool) -> Result<ForkHeader, Error> {
    let marker: &[u8; FORK_HEADER_LEN] = bytes
        .get(..FORK_HEADER_LEN)
        .ok_or(Error::Truncated)?
        .try_into()
        .expect("sixteen bytes");
    if large && marker[8..12] != [0; 4] {
        return Err(Error::BadFork);
    }
    let mut tag = [0; 4];
    tag.copy_from_slice(&marker[..4]);
    Ok(ForkHeader {
        tag,
        length: fork_len(marker, large),
    })
}

pub fn hfs_m_to_htime(wire: [u8; 4]) -> [u8; 4] {
    u32::from_be_bytes(wire)
        .wrapping_sub(HFS_MAC_HEADER_DELTA)
        .to_be_bytes()
}

pub fn hfs_h_to_mtime(wire: [u8; 4]) -> [u8; 4] {
    u32::from_be_bytes(wire)
        .wrapping_add(HFS_MAC_HEADER_DELTA)
        .to_be_bytes()
}

/// Bytes to read after the 40-byte FFO and INFO fork headers: the INFO fork
/// itself plus the DATA fork header that follows it. `b38`/`b39` are the low
/// half of the INFO fork's length, which is all period clients read. mhxd's
/// `(b38 ? 0x100 : 0) + b39` agrees with this for every length up to
/// [`MAX_INFO_LEN`], and anything longer is rejected before a caller sizes a
/// read from it.
pub fn info_block_len(b38: u8, b39: u8) -> Result<usize, Error> {
    let info_len = usize::from(u16::from_be_bytes([b38, b39]));
    if info_len > MAX_INFO_LEN {
        return Err(Error::InfoTooLong);
    }
    Ok(info_len + FORK_HEADER_LEN)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata<'a> {
    pub name: &'a [u8],
    pub type_code: [u8; 4],
    pub creator: [u8; 4],
    pub comment: &'a [u8],
    /// Seconds in Hotline's header epoch, stored in the low half of the
    /// eight-byte FFO date field after conversion to the Mac epoch.
    pub create_time: u32,
    pub modify_time: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forks {
    pub data_len: u64,
    pub data_offset: u64,
    pub resource_len: u64,
    pub resource_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// FFO header, INFO header/data, and DATA header.
    pub prefix: Vec<u8>,
    /// MACR header; callers append the remaining resource bytes after it.
    pub resource_header: [u8; FORK_HEADER_LEN],
    pub data_remaining: u64,
    pub resource_remaining: u64,
    pub transfer_len: u64,
}

pub fn encode(metadata: &Metadata<'_>, forks: Forks, large: bool) -> Result<Encoded, Error> {
    if metadata.name.len() > MAX_NAME_LEN {
        return Err(Error::NameTooLong);
    }
    if metadata.comment.len() > MAX_COMMENT_LEN {
        return Err(Error::CommentTooLong);
    }
    let data_remaining = remaining(forks.data_len, forks.data_offset)?;
    let resource_remaining = remaining(forks.resource_len, forks.resource_offset)?;
    if !large && (data_remaining > u32::MAX as u64 || resource_remaining > u32::MAX as u64) {
        return Err(Error::SizeOverflow);
    }

    let info_len = INFO_FIXED_LEN
        .checked_add(metadata.name.len())
        .and_then(|n| n.checked_add(metadata.comment.len()))
        .ok_or(Error::SizeOverflow)?;
    let prefix_len = FFO_HEADER_LEN
        .checked_add(FORK_HEADER_LEN)
        .and_then(|n| n.checked_add(info_len))
        .and_then(|n| n.checked_add(FORK_HEADER_LEN))
        .ok_or(Error::SizeOverflow)?;
    let transfer_len = u64::try_from(prefix_len)
        .ok()
        .and_then(|n| n.checked_add(data_remaining))
        .and_then(|n| n.checked_add(FORK_HEADER_LEN as u64))
        .and_then(|n| n.checked_add(resource_remaining))
        .ok_or(Error::SizeOverflow)?;
    if !large && transfer_len > u32::MAX as u64 {
        return Err(Error::SizeOverflow);
    }

    let mut out = Vec::with_capacity(prefix_len);
    out.extend_from_slice(b"FILP");
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0; 16]);
    // Period clients expect a trailing zero MACR marker even when this says
    // INFO + DATA. A non-empty resource fork is the third declared fork.
    out.extend_from_slice(&(if resource_remaining == 0 { 2u16 } else { 3 }).to_be_bytes());
    out.extend_from_slice(&pack_fork_header(b"INFO", info_len as u64, large)?);

    let mut info = vec![0; info_len];
    info[..4].copy_from_slice(b"AMAC");
    info[4..8].copy_from_slice(&metadata.type_code);
    info[8..12].copy_from_slice(&metadata.creator);
    info[56..60].copy_from_slice(&hfs_h_to_mtime(metadata.create_time.to_be_bytes()));
    info[64..68].copy_from_slice(&hfs_h_to_mtime(metadata.modify_time.to_be_bytes()));
    info[70..72].copy_from_slice(&(metadata.name.len() as u16).to_be_bytes());
    info[72..72 + metadata.name.len()].copy_from_slice(metadata.name);
    let comment_at = 72 + metadata.name.len();
    info[comment_at..comment_at + 2]
        .copy_from_slice(&(metadata.comment.len() as u16).to_be_bytes());
    info[comment_at + 2..].copy_from_slice(metadata.comment);
    out.extend_from_slice(&info);
    out.extend_from_slice(&pack_fork_header(b"DATA", data_remaining, large)?);

    Ok(Encoded {
        prefix: out,
        resource_header: pack_fork_header(b"MACR", resource_remaining, large)?,
        data_remaining,
        resource_remaining,
        transfer_len,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInfo {
    /// The sender's platform tag, `AMAC` or `MWIN` from period peers. Reported,
    /// never validated: see [`parse_info`].
    pub platform: [u8; 4],
    pub type_creator: [u8; 8],
    pub create_time: u32,
    pub modify_time: u32,
    pub name: Vec<u8>,
    pub comment: Vec<u8>,
}

pub fn parse_info(info: &[u8]) -> Result<ParsedInfo, Error> {
    if info.len() < INFO_FIXED_LEN {
        return Err(Error::Truncated);
    }
    // The platform tag is not checked. Windows clients and servers send
    // `MWIN`, and mhxd never looks at the field; rejecting anything but
    // `AMAC` would refuse their transfers.
    let mut platform = [0; 4];
    platform.copy_from_slice(&info[..4]);
    let name_len = u16::from_be_bytes(info[70..72].try_into().expect("two bytes")) as usize;
    if name_len > MAX_NAME_LEN {
        return Err(Error::NameTooLong);
    }
    let comment_at = 72usize.checked_add(name_len).ok_or(Error::SizeOverflow)?;
    let comment_len = u16::from_be_bytes(
        info.get(comment_at..comment_at + 2)
            .ok_or(Error::Truncated)?
            .try_into()
            .expect("two bytes"),
    ) as usize;
    if comment_len > MAX_COMMENT_LEN {
        return Err(Error::CommentTooLong);
    }
    let comment_start = comment_at + 2;
    let comment_end = comment_start
        .checked_add(comment_len)
        .ok_or(Error::SizeOverflow)?;
    let mut type_creator = [0; 8];
    type_creator.copy_from_slice(&info[4..12]);
    Ok(ParsedInfo {
        platform,
        type_creator,
        create_time: u32::from_be_bytes(hfs_m_to_htime(
            info[56..60].try_into().expect("four bytes"),
        )),
        modify_time: u32::from_be_bytes(hfs_m_to_htime(
            info[64..68].try_into().expect("four bytes"),
        )),
        name: info[72..comment_at].to_vec(),
        comment: info
            .get(comment_start..comment_end)
            .ok_or(Error::Truncated)?
            .to_vec(),
    })
}

/// Decode a fork length with the period client's permissive semantics.
/// Reserved bytes and a large high half are ignored in legacy mode.
pub fn fork_len(marker: &[u8; FORK_HEADER_LEN], large: bool) -> u64 {
    let low = u32::from_be_bytes(marker[12..16].try_into().expect("four bytes")) as u64;
    let high = if large {
        u32::from_be_bytes(marker[4..8].try_into().expect("four bytes")) as u64
    } else {
        0
    };
    (high << 32) | low
}

/// Fields extracted by GtkHx's receive worker from an INFO block followed by
/// its DATA fork header. Kept as a safe value type so its C facade can remain
/// entirely in the consumer repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilpInfo {
    pub type_creator: [u8; 8],
    pub create_time: [u8; 4],
    pub modify_time: [u8; 4],
    pub comment: Vec<u8>,
    pub data_fork_len: u64,
}

pub fn parse_filp_info(info_and_data_header: &[u8], large: bool) -> Result<FilpInfo, Error> {
    let data_header_at = info_and_data_header
        .len()
        .checked_sub(FORK_HEADER_LEN)
        .ok_or(Error::Truncated)?;
    let info = parse_info(&info_and_data_header[..data_header_at])?;
    let marker: &[u8; FORK_HEADER_LEN] = info_and_data_header[data_header_at..]
        .try_into()
        .expect("slice was split at one fork header");
    if &marker[..4] != b"DATA" {
        return Err(Error::BadFork);
    }
    Ok(FilpInfo {
        type_creator: info.type_creator,
        create_time: info.create_time.to_be_bytes(),
        modify_time: info.modify_time.to_be_bytes(),
        comment: info.comment,
        data_fork_len: fork_len(marker, large),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata<'a>(name: &'a [u8], comment: &'a [u8]) -> Metadata<'a> {
        Metadata {
            name,
            type_code: *b"TEXT",
            creator: *b"ttxt",
            comment,
            create_time: 7,
            modify_time: 9,
        }
    }

    const NO_FORKS: Forks = Forks {
        data_len: 0,
        data_offset: 0,
        resource_len: 0,
        resource_offset: 0,
    };

    #[test]
    fn legacy_filp_vector_has_variable_name_and_trailing_macr() {
        let encoded = encode(
            &metadata(b"notes.txt", b"source"),
            Forks {
                data_len: 5,
                ..NO_FORKS
            },
            false,
        )
        .unwrap();
        assert_eq!(&encoded.prefix[..4], b"FILP");
        assert_eq!(&encoded.prefix[24..28], b"INFO");
        let info_len = INFO_FIXED_LEN + 9 + 6;
        assert_eq!(
            parse_fork_header(&encoded.prefix[24..40], false)
                .unwrap()
                .length,
            info_len as u64
        );
        let info = parse_info(&encoded.prefix[40..40 + info_len]).unwrap();
        assert_eq!(info.platform, *b"AMAC");
        assert_eq!(info.name, b"notes.txt");
        assert_eq!(info.comment, b"source");
        assert_eq!(&encoded.prefix[40 + info_len..44 + info_len], b"DATA");
        assert_eq!(&encoded.resource_header[..4], b"MACR");
        assert_eq!(encoded.transfer_len, encoded.prefix.len() as u64 + 5 + 16);
    }

    #[test]
    fn info_length_agrees_with_period_readers_and_is_bounded() {
        assert_eq!(info_block_len(0, 0x5a), Ok(0x5a + FORK_HEADER_LEN));
        assert_eq!(info_block_len(1, 0x23), Ok(0x123 + FORK_HEADER_LEN));
        assert_eq!(
            info_block_len(0x01, 0xc9),
            Ok(MAX_INFO_LEN + FORK_HEADER_LEN)
        );
        assert_eq!(info_block_len(0x01, 0xca), Err(Error::InfoTooLong));
        assert_eq!(info_block_len(0xb8, 0xb9), Err(Error::InfoTooLong));
    }

    #[test]
    fn windows_platform_info_parses() {
        let encoded = encode(&metadata(b"notes.txt", b"source"), NO_FORKS, false).unwrap();
        let info_len = INFO_FIXED_LEN + b"notes.txt".len() + b"source".len();
        let mut info = encoded.prefix[40..40 + info_len].to_vec();
        info[..4].copy_from_slice(b"MWIN");

        let parsed = parse_info(&info).unwrap();
        assert_eq!(parsed.platform, *b"MWIN");
        assert_eq!(parsed.name, b"notes.txt");
        assert_eq!(parsed.comment, b"source");
    }

    #[test]
    fn legacy_fork_headers_ignore_what_period_readers_ignore() {
        let mut header = pack_fork_header(b"DATA", 5, false).unwrap();
        header[4..12].copy_from_slice(&[0xa5; 8]);
        assert_eq!(
            parse_fork_header(&header, false),
            Ok(ForkHeader {
                tag: *b"DATA",
                length: 5
            })
        );
        // Large-file mode reads 4..8 as the high half and keeps 8..12 zero.
        assert_eq!(parse_fork_header(&header, true), Err(Error::BadFork));
    }

    #[test]
    fn size_overflow_message_describes_the_selected_encoding() {
        assert_eq!(
            Error::SizeOverflow.to_string(),
            "FILP size exceeds the selected wire encoding"
        );
    }

    #[test]
    fn large_fork_vector_reconstructs_high_and_low_halves() {
        let length = 0x1_4000_0005;
        let header = pack_fork_header(b"DATA", length, true).unwrap();
        assert_eq!(&header[4..8], &1u32.to_be_bytes());
        assert_eq!(&header[12..16], &0x4000_0005u32.to_be_bytes());
        assert_eq!(parse_fork_header(&header, true).unwrap().length, length);
        // A legacy reader ignores the repurposed compression/high-half field.
        assert_eq!(
            parse_fork_header(&header, false).unwrap().length,
            0x4000_0005
        );
    }

    #[test]
    fn legacy_fork_headers_reject_lengths_the_wire_cannot_carry() {
        assert_eq!(
            pack_fork_header(b"DATA", u32::MAX as u64 + 1, false),
            Err(Error::SizeOverflow)
        );
    }

    #[test]
    fn sparse_large_fixture_needs_no_large_allocation() {
        let encoded = encode(
            &metadata(b"huge.bin", b""),
            Forks {
                data_len: 0x1_0000_0020,
                data_offset: 0x1_0000_0000,
                ..NO_FORKS
            },
            true,
        )
        .unwrap();
        assert_eq!(encoded.data_remaining, 32);
        assert!(encoded.prefix.len() < 256);
    }

    #[test]
    fn legacy_transfer_size_includes_container_overhead() {
        assert_eq!(
            encode(
                &metadata(b"x", b""),
                Forks {
                    data_len: u32::MAX as u64,
                    ..NO_FORKS
                },
                false,
            )
            .unwrap_err(),
            Error::SizeOverflow
        );
    }

    #[test]
    fn lengths_and_ranges_fail_closed() {
        assert!(matches!(
            encode(&metadata(&[b'x'; 129], b""), NO_FORKS, false),
            Err(Error::NameTooLong)
        ));
        assert!(matches!(
            encode(&metadata(b"x", &[b'x'; 256]), NO_FORKS, false),
            Err(Error::CommentTooLong)
        ));
        assert!(matches!(
            encode(
                &metadata(b"x", b""),
                Forks {
                    data_len: 1,
                    data_offset: 2,
                    ..NO_FORKS
                },
                false
            ),
            Err(Error::Range(_))
        ));
        assert!(matches!(
            encode(
                &metadata(b"x", b""),
                Forks {
                    data_len: u32::MAX as u64 + 1,
                    ..NO_FORKS
                },
                false
            ),
            Err(Error::SizeOverflow)
        ));
    }
}
