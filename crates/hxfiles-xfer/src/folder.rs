//! The per-item dialog of a folder transfer (Hotline.md, Download Folder and
//! Upload Folder; Capabilities-Large-File, "Folder Transfer Wire Format").
//!
//! Each item is announced by a header naming its path relative to the folder,
//! the same structure in both directions; the receiver answers with an
//! action. A file's flattened object follows a send or a resume, behind a
//! 4-byte size.

/// Send this item whole.
pub const ACTION_SEND: u16 = 1;
/// Send this item from the offsets in the RFLT that follows, behind its own
/// 2-byte length.
pub const ACTION_RESUME: u16 = 2;
/// Announce the next item: after a folder, after a finished file, or in
/// place of one.
pub const ACTION_NEXT: u16 = 3;

/// The longest RFLT a resume may carry. mhxd and GtkHx read no more, and the
/// canonical record is 74 bytes.
pub const MAX_RESUME_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    TrailingBytes,
    EmptyPath,
    EmptyName,
    NameTooLong,
    TooLong,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated folder item header",
            Self::TrailingBytes => "folder item header longer than its path",
            Self::EmptyPath => "folder item with no path",
            Self::EmptyName => "folder item path with an empty name",
            Self::NameTooLong => "folder item name longer than 255 bytes",
            Self::TooLong => "folder item header longer than 65535 bytes",
        })
    }
}

impl std::error::Error for Error {}

/// One item: a folder, or a file whose object follows, at `path` below the
/// folder being transferred. Names are wire bytes, in whatever encoding the
/// connection reads text in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub folder: bool,
    pub path: Vec<Vec<u8>>,
}

impl Item {
    /// The header as it crosses the wire, its 2-byte length first.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.path.is_empty() {
            return Err(Error::EmptyPath);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&u16::from(self.folder).to_be_bytes());
        let count = u16::try_from(self.path.len()).map_err(|_| Error::TooLong)?;
        body.extend_from_slice(&count.to_be_bytes());
        for name in &self.path {
            if name.is_empty() {
                return Err(Error::EmptyName);
            }
            let len = u8::try_from(name.len()).map_err(|_| Error::NameTooLong)?;
            body.extend_from_slice(&[0, 0, len]);
            body.extend_from_slice(name);
        }
        let len = u16::try_from(body.len()).map_err(|_| Error::TooLong)?;
        let mut out = Vec::with_capacity(2 + body.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parse the `len` bytes that follow a header's length. Any type but 1 is
    /// a file, as mhxd and GtkHx read it, and each name's two leading bytes
    /// are ignored. A header must hold exactly its path: a length that
    /// disagrees with it would desynchronize whatever follows.
    pub fn parse(body: &[u8]) -> Result<Item, Error> {
        let field = |at: usize| -> Result<u16, Error> {
            body.get(at..at + 2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .ok_or(Error::Truncated)
        };
        let folder = field(0)? == 1;
        let count = field(2)?;
        if count == 0 {
            return Err(Error::EmptyPath);
        }
        let mut at = 4;
        let mut path = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let len = usize::from(*body.get(at + 2).ok_or(Error::Truncated)?);
            if len == 0 {
                return Err(Error::EmptyName);
            }
            let name = body.get(at + 3..at + 3 + len).ok_or(Error::Truncated)?;
            path.push(name.to_vec());
            at += 3 + len;
        }
        if at != body.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(Item { folder, path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_round_trips_as_gtkhx_writes_it() {
        let item = Item {
            folder: false,
            path: vec![b"nested".to_vec(), b"beta.txt".to_vec()],
        };
        let wire = item.encode().unwrap();
        assert_eq!(
            wire,
            [
                &[0, 24, 0, 0, 0, 2, 0, 0, 6][..],
                b"nested",
                &[0, 0, 8],
                b"beta.txt"
            ]
            .concat()
        );
        assert_eq!(Item::parse(&wire[2..]), Ok(item));
    }

    #[test]
    fn readers_are_lenient_where_deployed_peers_are_and_no_further() {
        // An unknown type is a file, and the reserved bytes are not read.
        assert_eq!(
            Item::parse(&[0, 7, 0, 1, 0xff, 0xff, 1, b'a']),
            Ok(Item {
                folder: false,
                path: vec![b"a".to_vec()]
            })
        );
        assert_eq!(Item::parse(&[0, 1, 0, 0]), Err(Error::EmptyPath));
        assert_eq!(Item::parse(&[0, 0, 0, 1, 0, 0, 0]), Err(Error::EmptyName));
        assert_eq!(
            Item::parse(&[0, 0, 0, 1, 0, 0, 2, b'a']),
            Err(Error::Truncated)
        );
        assert_eq!(
            Item::parse(&[0, 0, 0, 1, 0, 0, 1, b'a', 0]),
            Err(Error::TrailingBytes)
        );
        assert_eq!(Item::parse(&[0, 0]), Err(Error::Truncated));
    }

    #[test]
    fn names_a_header_cannot_carry_are_refused() {
        let item = |path: Vec<Vec<u8>>| Item { folder: true, path }.encode();
        assert_eq!(item(vec![]), Err(Error::EmptyPath));
        assert_eq!(item(vec![vec![]]), Err(Error::EmptyName));
        assert_eq!(item(vec![vec![b'x'; 256]]), Err(Error::NameTooLong));
        assert!(item(vec![vec![b'x'; 255]]).is_ok());
    }
}
