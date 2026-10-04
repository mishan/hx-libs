//! The transport a HOPE login agrees: what each side's bytes go through
//! from the step-2 reply on. Sending, a compression and then a cipher;
//! receiving, the cipher undone and then the compression.
//!
//! Blowfish carries a rekey marker. A sender may stamp a count of 1..63
//! into the high byte of a transaction's type, encrypt the header, turn
//! its key that many HMAC rounds against the session key, and encrypt the
//! body with the new key; the receiver sees the count as it decrypts the
//! header and turns its key to match. So a Blowfish transport without
//! compression works a transaction at a time. Under a compression the
//! cipher sees compressed bytes with no transactions to find, and neither
//! side marks: the servers that compress (mhxd) never do.

use hxcrypto::aead::{AeadState, AEAD_MAX_FRAME_SIZE, AEAD_TAG_SIZE};
use hxcrypto::stream::BlowfishOfb64State;

use crate::alg::{Cipher, Compression, Mac};
use crate::compress::{self, Compressor, Decompressor};
use crate::keys::Chain;
use crate::Error;

/// A source of random bytes. The transport draws on it only to decide
/// where Blowfish's rekey markers go, never for key material.
pub type Random = Box<dyn FnMut(&mut [u8]) + Send>;

/// Which side of the connection a transport is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

const HDR: usize = 22;
/// The largest transaction body the Blowfish framing takes; past this the
/// keystream has gone astray.
const MAX_BODY: usize = 1024 * 1024;
const AEAD_MAX_PLAINTEXT: usize = AEAD_MAX_FRAME_SIZE as usize - AEAD_TAG_SIZE;

/// One direction's Blowfish: its key turns at each marker.
struct Blowfish {
    // Boxed: a key schedule is some 4 KiB, beside the others' few words.
    state: Box<BlowfishOfb64State>,
    key: Vec<u8>,
}

impl Blowfish {
    fn new(key: &[u8]) -> Result<Self, Error> {
        Ok(Blowfish {
            state: BlowfishOfb64State::new(key)
                .map(Box::new)
                .ok_or_else(|| Error::Transport("a Blowfish key out of range".into()))?,
            key: key.to_vec(),
        })
    }

    /// Turn the key `rounds` HMAC rounds against the session key. The OFB
    /// position carries on across it.
    fn rekey(&mut self, rounds: u8, session_key: &[u8], mac: Mac) -> Result<(), Error> {
        for _ in 0..rounds {
            self.key = mac.mac(&self.key, session_key);
        }
        if self.state.set_key(&self.key) {
            Ok(())
        } else {
            Err(Error::Transport("a Blowfish key out of range".into()))
        }
    }
}

/// A transaction's body length, from the header's data size: offset 16,
/// this fragment's, which counts the field count's two bytes.
fn body_len(hdr: &[u8]) -> Result<usize, Error> {
    let size = u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;
    match size.checked_sub(2) {
        Some(n) if n <= MAX_BODY => Ok(n),
        _ => Err(Error::Transport(format!(
            "a transaction of {size} bytes (the Blowfish keystream has gone astray)"
        ))),
    }
}

enum Seal {
    None,
    /// `marks` draws the markers; `None` under a compression.
    Blowfish {
        bf: Blowfish,
        marks: Option<Random>,
        /// A transaction not yet whole.
        partial: Vec<u8>,
    },
    Aead(AeadState),
}

enum Open {
    None,
    /// `frames` is whether to read transactions, and so markers.
    Blowfish {
        bf: Blowfish,
        frames: bool,
        hdr: Vec<u8>,
        body: usize,
    },
    Aead {
        state: AeadState,
        pending: Vec<u8>,
    },
}

/// The codec between a session and its socket, once HOPE has agreed one.
pub struct Transport {
    mac: Mac,
    session_key: Vec<u8>,
    compress: Option<Compressor>,
    seal: Seal,
    open: Open,
    decompress: Option<Decompressor>,
}

impl Transport {
    pub(crate) fn new(
        role: Role,
        mac: Mac,
        cipher: Option<Cipher>,
        compression: Option<Compression>,
        session_key: &[u8],
        chain: &Chain,
        random: Random,
    ) -> Result<Transport, Error> {
        let (compress, decompress) = match compression {
            Some(c) => {
                let (c, d) = compress::pair(c)?;
                (Some(c), Some(d))
            }
            None => (None, None),
        };
        // The spec's encode key is the server's.
        let (send_key, recv_key) = match role {
            Role::Client => (&chain.decode, &chain.encode),
            Role::Server => (&chain.encode, &chain.decode),
        };
        let (seal, open) = match cipher {
            None => (Seal::None, Open::None),
            Some(Cipher::Blowfish) => (
                Seal::Blowfish {
                    bf: Blowfish::new(send_key)?,
                    marks: compression.is_none().then_some(random),
                    partial: Vec::new(),
                },
                Open::Blowfish {
                    bf: Blowfish::new(recv_key)?,
                    frames: compression.is_none(),
                    hdr: Vec::with_capacity(HDR),
                    body: 0,
                },
            ),
            Some(Cipher::ChaCha20Poly1305) => {
                let (to_server, to_client) = chain.aead(session_key);
                let (send, recv) = match role {
                    Role::Client => (to_server, to_client),
                    Role::Server => (to_client, to_server),
                };
                (
                    Seal::Aead(send),
                    Open::Aead {
                        state: recv,
                        pending: Vec::new(),
                    },
                )
            }
        };
        Ok(Transport {
            mac,
            session_key: session_key.to_vec(),
            compress,
            seal,
            open,
            decompress,
        })
    }

    /// What to write for `plain`, which is whole transactions when the
    /// transport is Blowfish without compression. One call is one unit:
    /// one compression flush or frame, one ChaCha20-Poly1305 record.
    pub fn encode(&mut self, plain: &[u8]) -> Result<Vec<u8>, Error> {
        if plain.is_empty() {
            return Ok(Vec::new());
        }
        let compressed;
        let bytes = match self.compress.as_mut() {
            Some(c) => {
                compressed = c.encode(plain)?;
                &compressed[..]
            }
            None => plain,
        };
        match &mut self.seal {
            Seal::None => Ok(bytes.to_vec()),
            Seal::Blowfish {
                bf, marks: None, ..
            } => {
                let mut out = bytes.to_vec();
                bf.state.crypt_in_place(&mut out);
                Ok(out)
            }
            Seal::Blowfish {
                bf,
                marks: Some(random),
                partial,
            } => {
                partial.extend_from_slice(bytes);
                let mut out = Vec::with_capacity(partial.len());
                let mut at = 0;
                while partial.len() - at >= HDR {
                    let end = at + HDR + body_len(&partial[at..])?;
                    if partial.len() < end {
                        break;
                    }
                    let frame = &mut partial[at..end];
                    // The odds and the count are the original client's: a
                    // nibble that fires on 2, 7 or 13, then six bits, or if
                    // those are zero, five more plus one.
                    let mut r = [0u8; 3];
                    random(&mut r);
                    let rounds = if matches!(r[0] >> 4, 2 | 7 | 13) {
                        match r[1] >> 2 {
                            0 => (r[2] >> 3) + 1,
                            n => n,
                        }
                    } else {
                        0
                    };
                    frame[0] |= rounds;
                    let (hdr, body) = frame.split_at_mut(HDR);
                    bf.state.crypt_in_place(hdr);
                    if rounds > 0 {
                        bf.rekey(rounds, &self.session_key, self.mac)?;
                    }
                    bf.state.crypt_in_place(body);
                    out.extend_from_slice(hdr);
                    out.extend_from_slice(body);
                    at = end;
                }
                partial.drain(..at);
                Ok(out)
            }
            Seal::Aead(state) => {
                let mut out = Vec::new();
                for piece in bytes.chunks(AEAD_MAX_PLAINTEXT) {
                    let at = out.len();
                    out.resize(at + 4 + piece.len() + AEAD_TAG_SIZE, 0);
                    state
                        .seal(piece, &mut out[at..])
                        .ok_or_else(|| Error::Transport("a record that does not seal".into()))?;
                }
                Ok(out)
            }
        }
    }

    /// Take what arrived, in whatever pieces, and add its plaintext to
    /// `out`.
    pub fn decode(&mut self, wire: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let mut deciphered = Vec::new();
        let into = if self.decompress.is_some() {
            &mut deciphered
        } else {
            &mut *out
        };
        match &mut self.open {
            Open::None => into.extend_from_slice(wire),
            Open::Blowfish {
                bf, frames: false, ..
            } => {
                let at = into.len();
                into.extend_from_slice(wire);
                bf.state.crypt_in_place(&mut into[at..]);
            }
            Open::Blowfish {
                bf,
                frames: true,
                hdr,
                body,
            } => {
                let mut rest = wire;
                while !rest.is_empty() {
                    if *body > 0 {
                        let n = (*body).min(rest.len());
                        let at = into.len();
                        into.extend_from_slice(&rest[..n]);
                        bf.state.crypt_in_place(&mut into[at..]);
                        *body -= n;
                        rest = &rest[n..];
                        continue;
                    }
                    let n = (HDR - hdr.len()).min(rest.len());
                    let at = hdr.len();
                    hdr.extend_from_slice(&rest[..n]);
                    bf.state.crypt_in_place(&mut hdr[at..]);
                    rest = &rest[n..];
                    if hdr.len() == HDR {
                        let rounds = std::mem::take(&mut hdr[0]);
                        if rounds > 0 {
                            bf.rekey(rounds, &self.session_key, self.mac)?;
                        }
                        *body = body_len(hdr)?;
                        into.extend_from_slice(hdr);
                        hdr.clear();
                    }
                }
            }
            Open::Aead { state, pending } => {
                pending.extend_from_slice(wire);
                let mut at = 0;
                while pending.len() - at >= 4 {
                    let Some(size) = AeadState::peek_frame_size(&pending[at..]) else {
                        return Err(Error::Transport("a record of impossible length".into()));
                    };
                    if pending.len() - at < size {
                        break;
                    }
                    let start = into.len();
                    into.resize(start + size - 4 - AEAD_TAG_SIZE, 0);
                    state
                        .open(&pending[at..at + size], &mut into[start..])
                        .ok_or_else(|| {
                            Error::Transport("a record that does not authenticate".into())
                        })?;
                    at += size;
                }
                pending.drain(..at);
            }
        }
        if let Some(d) = self.decompress.as_mut() {
            d.decode(&deciphered, out)?;
        }
        Ok(())
    }

    /// Nothing part way through on the receiving side: a stream that ends
    /// now ends between units.
    pub fn idle(&self) -> bool {
        let open = match &self.open {
            Open::None => true,
            Open::Blowfish { hdr, body, .. } => hdr.is_empty() && *body == 0,
            Open::Aead { pending, .. } => pending.is_empty(),
        };
        open && self.decompress.as_ref().is_none_or(Decompressor::idle)
    }
}
