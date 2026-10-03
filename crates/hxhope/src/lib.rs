//! HOPE, the Hotline secure login, with no I/O of its own.
//!
//! A HOPE login is two LOGIN transactions in place of one. The client's
//! first offers what it can do and carries no credentials; the server
//! answers with its choices and a session key. The client's second carries
//! the login and a MAC of the password under that key, and from its answer
//! on, both directions run through the transport they agreed: a cipher
//! (Blowfish OFB-64 or ChaCha20-Poly1305), a compression beneath it, either,
//! both or neither.
//!
//! [`client`] is the client's side of that and [`server`] the server's;
//! each ends in a [`Transport`], the codec the rest of the connection's
//! bytes go through, and [`Negotiated`], what was agreed. A
//! ChaCha20-Poly1305 session also yields the [`TransferKeys`] its file
//! transfers are encrypted with.
//!
//! **The negotiated wire format is not ours to change.** What goes out
//! here is what the servers still running (mhxd, Janus) were tested
//! against, field for field.

pub mod alg;
pub mod client;
mod compress;
mod keys;
pub mod server;
mod transport;

#[cfg(test)]
mod tests;

pub use alg::{Cipher, Compression, Mac};
pub use keys::TransferKeys;
pub use transport::{Random, Role, Transport};

/// What was agreed.
#[derive(Debug, Clone)]
pub struct Negotiated {
    pub mac: Mac,
    pub cipher: Option<Cipher>,
    pub compression: Option<Compression>,
    /// With ChaCha20-Poly1305, what file transfers derive their keys from.
    pub transfer_keys: Option<TransferKeys>,
}

/// Why a handshake, or the transport after it, failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The other side's transaction is not the one HOPE expects there.
    Malformed(String),
    /// An algorithm this side does not have, or did not offer.
    Unsupported(String),
    /// The password's MAC, or the login's, did not match.
    BadCredentials,
    /// The transport's bytes stopped making sense: a record that does not
    /// authenticate, a stream that does not decompress.
    Transport(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "HOPE: {what}"),
            Error::Unsupported(what) => write!(f, "HOPE: unsupported {what}"),
            Error::BadCredentials => f.write_str("HOPE: the credentials do not match"),
            Error::Transport(what) => write!(f, "HOPE transport: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// The fields HOPE adds to LOGIN and its reply.
pub mod tag {
    pub const APP_ID: u16 = 0x0e01;
    pub const APP_STRING: u16 = 0x0e02;
    pub const SESSION_KEY: u16 = 0x0e03;
    pub const MAC_ALG: u16 = 0x0e04;
    /// The server's direction, and in step 2 the client's echo of it.
    pub const S_CIPHER_ALG: u16 = 0x0ec1;
    pub const C_CIPHER_ALG: u16 = 0x0ec2;
    pub const S_CIPHER_MODE: u16 = 0x0ec3;
    pub const S_COMPRESS_ALG: u16 = 0x0ec9;
    pub const C_COMPRESS_ALG: u16 = 0x0eca;
}

/// LOGIN's opcode.
const LOGIN: u32 = 107;

/// A transaction's fields, the last of each tag winning.
fn field(frame: &[u8], tag: u16) -> Option<&[u8]> {
    hxproto::wire::ChunkIter::over_message(frame, frame.len())
        .filter(|c| c.tag == tag)
        .last()
        .map(|c| c.data)
}

fn opcode(frame: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(frame.get(..4)?.try_into().ok()?))
}

/// `None` for a field longer than its 16-bit length.
fn pack(opcode: u32, trans: u32, fields: &[(u16, &[u8])]) -> Option<Vec<u8>> {
    use hxproto::build::{pack_message, pack_message_size, PackChunk};
    let chunks: Vec<PackChunk<'_>> = fields
        .iter()
        .map(|&(tag, data)| PackChunk { tag, data })
        .collect();
    let mut out = vec![0u8; pack_message_size(&chunks)];
    pack_message(&mut out, opcode, trans, 0, &chunks)?;
    Some(out)
}

/// What a step-2 LOGIN field holds when it is not a MAC: the login with
/// every byte inverted, as a plain LOGIN carries it.
fn obfuscate(login: &[u8]) -> Vec<u8> {
    login.iter().map(|b| !b).collect()
}
