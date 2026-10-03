//! A client's side of the handshake: [`step1`], then [`step2`] from the
//! server's answer to it.

use hxproto::messages::tag as hl;

use crate::alg::{encode_list, parse_list, Cipher, Compression, Mac};
use crate::keys::{Chain, TransferKeys};
use crate::transport::{Random, Role, Transport};
use crate::{field, obfuscate, pack, tag, Error, Negotiated, LOGIN};

/// What a client offers, in the order it prefers.
#[derive(Debug, Clone)]
pub struct Offer {
    pub macs: Vec<Mac>,
    /// None offered asks for HMAC authentication over a plaintext
    /// transport.
    pub ciphers: Vec<Cipher>,
    pub compressions: Vec<Compression>,
    /// Four bytes naming the client, an OSType.
    pub app_id: [u8; 4],
    /// Sent when `Some`, even empty.
    pub app_string: Option<Vec<u8>>,
}

impl Offer {
    /// Every MAC, no cipher, no compression.
    pub fn new(app_id: [u8; 4]) -> Offer {
        Offer {
            macs: Mac::ALL.to_vec(),
            ciphers: Vec::new(),
            compressions: Vec::new(),
            app_id,
            app_string: None,
        }
    }
}

/// Who logs in, and what step 2 says about them.
#[derive(Debug, Clone)]
pub struct Login<'a> {
    pub login: &'a [u8],
    pub password: &'a [u8],
    pub name: &'a [u8],
    pub icon: u16,
    /// 0 leaves it out.
    pub version: u16,
    pub caps: u16,
}

/// Step 2, and what the rest of the connection runs through once it is
/// sent.
pub struct Established {
    pub step2: Vec<u8>,
    pub transport: Transport,
    pub negotiated: Negotiated,
}

fn labels<T: Copy>(items: &[T], label: impl Fn(T) -> &'static [u8]) -> Vec<&'static [u8]> {
    items.iter().map(|&i| label(i)).collect()
}

fn list(labels: &[&[u8]]) -> Result<Vec<u8>, Error> {
    encode_list(labels).ok_or_else(|| Error::Malformed("an algorithm list too long".into()))
}

/// Step 1: a LOGIN with no credentials, saying what this client can do.
pub fn step1(offer: &Offer, trans: u32) -> Result<Vec<u8>, Error> {
    let macs = list(&labels(&offer.macs, Mac::label))?;
    let ciphers = list(&labels(&offer.ciphers, Cipher::label))?;
    let usable: Vec<Compression> = offer
        .compressions
        .iter()
        .copied()
        .filter(|c| c.available())
        .collect();
    let compressions = list(&labels(&usable, Compression::label))?;
    // The login and password are each a single zero byte, not empty: mhxd
    // and Janus take an empty pair for a plaintext guest login, and answer
    // it as one.
    let mut fields: Vec<(u16, &[u8])> = vec![
        (hl::LOGIN, &[0]),
        (hl::PASSWORD, &[0]),
        (tag::MAC_ALG, &macs),
        (tag::APP_ID, &offer.app_id),
    ];
    if let Some(s) = &offer.app_string {
        fields.push((tag::APP_STRING, s));
    }
    fields.push((tag::C_CIPHER_ALG, &ciphers));
    if !usable.is_empty() {
        fields.push((tag::C_COMPRESS_ALG, &compressions));
    }
    fields.push((tag::SESSION_KEY, &[]));
    pack(LOGIN, trans, &fields).ok_or_else(|| Error::Malformed("step 1 too long".into()))
}

/// The one choice an algorithm list in the reply makes: `None` for an
/// absent or zero-length field, and for a list of no entries when
/// `none_listed` says such a list means none.
fn choice<T>(
    reply: &[u8],
    tag: u16,
    what: &str,
    none_listed: bool,
    parse: impl Fn(&[u8]) -> Option<T>,
) -> Result<Option<T>, Error> {
    let Some(data) = field(reply, tag).filter(|d| !d.is_empty()) else {
        return Ok(None);
    };
    let first = parse_list(data)
        .ok_or_else(|| Error::Malformed(format!("the {what} list does not parse")))?
        .into_iter()
        .next();
    let Some(first) = first else {
        return if none_listed {
            Ok(None)
        } else {
            Err(Error::Malformed(format!("the {what} list is empty")))
        };
    };
    parse(&first)
        .map(Some)
        .ok_or_else(|| Error::Unsupported(format!("{what} {:?}", String::from_utf8_lossy(&first))))
}

/// Step 2, from the server's answer to step 1 (a successful one: a refusal
/// is the caller's to report), and the transport that starts once it is
/// sent.
pub fn step2(
    offer: &Offer,
    reply: &[u8],
    who: &Login<'_>,
    trans: u32,
    random: Random,
) -> Result<Established, Error> {
    let session_key = field(reply, tag::SESSION_KEY)
        .ok_or_else(|| Error::Malformed("the server answered with no session key".into()))?;
    // The server picks from what was offered; a pick from outside it is
    // not answered.
    let mac = choice(reply, tag::MAC_ALG, "MAC", false, |l| {
        Mac::from_label(l).filter(|m| offer.macs.contains(m))
    })?
    .ok_or_else(|| Error::Malformed("the server chose no MAC".into()))?;
    // An absent or zero-length field is no cipher; a list naming none is
    // not something a server sends, and is taken for a broken reply rather
    // than a quiet downgrade to plaintext.
    let cipher = choice(reply, tag::S_CIPHER_ALG, "cipher", false, |l| {
        Cipher::from_label(l).filter(|c| offer.ciphers.contains(c))
    })?;
    // A compression goes on only when it was asked for. Having offered
    // some, a server choosing one not offered fails the login; one that
    // offered none ignores whatever the server says. "NONE", as mhxd's own
    // client names it, an empty name and an empty list are none.
    let compression = if offer.compressions.is_empty() {
        None
    } else {
        choice(reply, tag::S_COMPRESS_ALG, "compression", true, |l| {
            if l.is_empty() || l == b"NONE" {
                return Some(None);
            }
            Compression::from_label(l)
                .filter(|c| c.available() && offer.compressions.contains(c))
                .map(Some)
        })?
        .flatten()
    };
    // The mode is the cipher's own: Blowfish is a stream, ChaCha20-Poly1305
    // records are AEAD (Janus says so; mhxd says nothing, which is
    // STREAM). A server naming the other is not answered.
    let mode = field(reply, tag::S_CIPHER_MODE).unwrap_or(b"STREAM");
    if let Some(c) = cipher {
        let ours: &[u8] = match c {
            Cipher::Blowfish => b"STREAM",
            Cipher::ChaCha20Poly1305 => b"AEAD",
        };
        if field(reply, tag::S_CIPHER_MODE).is_some_and(|m| m != ours) {
            return Err(Error::Unsupported(format!(
                "cipher mode {:?} for {:?}",
                String::from_utf8_lossy(mode),
                c
            )));
        }
    }

    let chain = Chain::new(mac, who.password, session_key);
    // A server that echoes the MAC's name as the login wants the login as
    // a MAC too (mhxd); one that does not wants it as a plain LOGIN
    // carries it (Janus).
    let login = if field(reply, hl::LOGIN) == Some(mac.label()) {
        mac.mac(who.login, session_key)
    } else {
        obfuscate(who.login)
    };

    let cipher_echo = cipher.map(|c| list(&[c.label()])).transpose()?;
    let compression_echo = compression.map(|c| list(&[c.label()])).transpose()?;
    let icon = who.icon.to_be_bytes();
    let version = who.version.to_be_bytes();
    let caps = who.caps.to_be_bytes();
    let mut fields: Vec<(u16, &[u8])> =
        vec![(hl::LOGIN, &login), (hl::PASSWORD, &chain.password_mac)];
    // No cipher is an absent field: mhxd closes on a present one that
    // names none.
    if let Some(c) = &cipher_echo {
        fields.push((tag::S_CIPHER_ALG, c));
    }
    if let Some(c) = &compression_echo {
        fields.push((tag::S_COMPRESS_ALG, c));
    }
    // Name and icon always, even empty: mhxd drops a step 2 without them.
    fields.push((hl::NAME, who.name));
    fields.push((hl::ICON, &icon));
    if who.version != 0 {
        fields.push((hl::VERSION, &version));
    }
    if mode != b"STREAM" {
        fields.push((tag::S_CIPHER_MODE, mode));
    }
    fields.push((hl::CAPABILITIES, &caps));
    let step2 =
        pack(LOGIN, trans, &fields).ok_or_else(|| Error::Malformed("step 2 too long".into()))?;

    let transport = Transport::new(
        Role::Client,
        mac,
        cipher,
        compression,
        session_key,
        &chain,
        random,
    )?;
    let transfer_keys = (cipher == Some(Cipher::ChaCha20Poly1305)).then(|| {
        let (to_server, to_client) = chain.aead(session_key);
        TransferKeys::new(session_key, &to_server, &to_client)
    });
    Ok(Established {
        step2,
        transport,
        negotiated: Negotiated {
            mac,
            cipher,
            compression,
            transfer_keys,
        },
    })
}
