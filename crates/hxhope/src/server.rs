//! A server's side of the handshake: [`answer`] a client's step 1, then
//! read its step 2 ([`Server::step2`]), find whose login it names
//! ([`Step2::names`]) and check their password ([`Server::accept`]).
//!
//! Choosing follows mhxd: of each list the client sent, the first this
//! server has. The step-1 reply echoes the chosen MAC's name as its login,
//! which asks the client for its login as a MAC, so that a login name
//! never crosses the wire, even obfuscated.

use hxproto::messages::tag as hl;

use crate::alg::{encode_list, parse_list, Cipher, Compression, Mac};
use crate::keys::{Chain, TransferKeys};
use crate::transport::{Random, Role, Transport};
use crate::{field, opcode, pack, tag, Error, Negotiated, LOGIN};

/// The reply's opcode.
const TASK: u32 = 0x0001_0000;

/// What a server can do.
#[derive(Debug, Clone)]
pub struct Policy {
    pub macs: Vec<Mac>,
    pub ciphers: Vec<Cipher>,
    pub compressions: Vec<Compression>,
    /// Refuse a client with no cipher in common, rather than authenticate
    /// it over plaintext.
    pub require_cipher: bool,
}

/// Whether a LOGIN is HOPE's step 1: its login a single zero byte.
pub fn is_step1(frame: &[u8]) -> bool {
    opcode(frame) == Some(LOGIN) && field(frame, hl::LOGIN) == Some(&[0])
}

/// The handshake between the step-1 reply and step 2.
#[derive(Debug, Clone)]
pub struct Server {
    require_cipher: bool,
    mac: Mac,
    cipher: Option<Cipher>,
    compression: Option<Compression>,
    session_key: Vec<u8>,
}

/// What a client's step 2 says.
#[derive(Debug, Clone)]
pub struct Step2 {
    login: Vec<u8>,
    password_mac: Vec<u8>,
    cipher: Option<Vec<u8>>,
    compression: Option<Vec<u8>>,
    pub name: Vec<u8>,
    pub icon: u16,
    /// 0 when it said none.
    pub version: u16,
    pub caps: u16,
}

/// The first label in the client's list at `tag` that `have` says yes to.
fn pick<T>(step1: &[u8], tag: u16, have: impl Fn(&[u8]) -> Option<T>) -> Option<T> {
    parse_list(field(step1, tag)?)?.iter().find_map(|l| have(l))
}

fn one(label: Option<&'static [u8]>) -> Vec<u8> {
    // mhxd's form for "none": the field present and empty.
    label.map_or_else(Vec::new, |l| encode_list(&[l]).expect("labels are short"))
}

/// Answer step 1 on `trans` with `session_key`, which the caller makes
/// random (mhxd puts the address the client reached in its first bytes).
pub fn answer(
    policy: &Policy,
    step1: &[u8],
    session_key: [u8; 64],
    trans: u32,
) -> Result<(Server, Vec<u8>), Error> {
    if !is_step1(step1) {
        return Err(Error::Malformed("not a step 1".into()));
    }
    let mac = pick(step1, tag::MAC_ALG, |l| {
        Mac::from_label(l).filter(|m| policy.macs.contains(m))
    })
    .ok_or_else(|| Error::Unsupported("MAC: none in common".into()))?;
    let cipher = pick(step1, tag::C_CIPHER_ALG, |l| {
        Cipher::from_label(l).filter(|c| policy.ciphers.contains(c))
    });
    if cipher.is_none() && policy.require_cipher {
        return Err(Error::Unsupported("cipher: none in common".into()));
    }
    let compression = pick(step1, tag::C_COMPRESS_ALG, |l| {
        Compression::from_label(l).filter(|c| c.available() && policy.compressions.contains(c))
    });

    let macs = one(Some(mac.label()));
    let ciphers = one(cipher.map(Cipher::label));
    let compressions = one(compression.map(Compression::label));
    // Both directions' fields, the same, as mhxd sends them.
    let reply = pack(
        TASK,
        trans,
        &[
            (hl::LOGIN, mac.label()),
            (tag::MAC_ALG, &macs),
            (tag::S_CIPHER_ALG, &ciphers),
            (tag::C_CIPHER_ALG, &ciphers),
            (tag::S_COMPRESS_ALG, &compressions),
            (tag::C_COMPRESS_ALG, &compressions),
            (tag::SESSION_KEY, &session_key),
        ],
    )
    .expect("the reply's fields are short");
    Ok((
        Server {
            require_cipher: policy.require_cipher,
            mac,
            cipher,
            compression,
            session_key: session_key.to_vec(),
        },
        reply,
    ))
}

fn u16_field(frame: &[u8], tag: u16) -> u16 {
    field(frame, tag)
        .and_then(|d| d.try_into().ok())
        .map_or(0, u16::from_be_bytes)
}

/// Equal, without stopping at the first difference.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Server {
    /// Read the client's step 2.
    pub fn step2(&self, frame: &[u8]) -> Result<Step2, Error> {
        if opcode(frame) != Some(LOGIN) {
            return Err(Error::Malformed("not a step 2".into()));
        }
        let password_mac = field(frame, hl::PASSWORD)
            .ok_or_else(|| Error::Malformed("step 2 has no password".into()))?;
        Ok(Step2 {
            login: field(frame, hl::LOGIN).unwrap_or_default().to_vec(),
            password_mac: password_mac.to_vec(),
            cipher: field(frame, tag::S_CIPHER_ALG).map(<[u8]>::to_vec),
            compression: field(frame, tag::S_COMPRESS_ALG).map(<[u8]>::to_vec),
            name: field(frame, hl::NAME).unwrap_or_default().to_vec(),
            icon: u16_field(frame, hl::ICON),
            version: u16_field(frame, hl::VERSION),
            caps: u16_field(frame, hl::CAPABILITIES),
        })
    }

    /// Check `password` against step 2 and start the transport. The reply
    /// to step 2, the login's, goes out through it: from here on, both
    /// directions do.
    pub fn accept(
        self,
        step2: &Step2,
        password: &[u8],
        random: Random,
    ) -> Result<(Transport, Negotiated), Error> {
        let chain = Chain::new(self.mac, password, &self.session_key);
        if !same(&chain.password_mac, &step2.password_mac) {
            return Err(Error::BadCredentials);
        }
        // What the client echoes is what it will run: nothing for none,
        // and nothing other than what was chosen.
        let echoed = |echo: &Option<Vec<u8>>, chosen: Option<&'static [u8]>| match echo {
            None => Ok(None),
            Some(e) if chosen.is_some_and(|c| *e == one(Some(c))) => Ok(chosen),
            Some(_) => Err(Error::Malformed("step 2 echoes what was not chosen".into())),
        };
        let cipher = echoed(&step2.cipher, self.cipher.map(Cipher::label))?.and(self.cipher);
        // A step 1 reply can be stripped of its cipher on the way; a server
        // that requires one refuses a step 2 that runs without it.
        if cipher.is_none() && self.require_cipher {
            return Err(Error::Unsupported("cipher: step 2 runs none".into()));
        }
        let compression = echoed(&step2.compression, self.compression.map(Compression::label))?
            .and(self.compression);
        let transport = Transport::new(
            Role::Server,
            self.mac,
            cipher,
            compression,
            &self.session_key,
            &chain,
            random,
        )?;
        let transfer_keys = (cipher == Some(Cipher::ChaCha20Poly1305))
            .then(|| TransferKeys::new(&self.session_key, &chain));
        Ok((
            transport,
            Negotiated {
                mac: self.mac,
                cipher,
                compression,
                transfer_keys,
            },
        ))
    }
}

impl Step2 {
    /// Whether this step 2 logs in as `login`; an empty login is the guest
    /// account's. A server asks of each account it has, as mhxd does.
    ///
    /// The step-1 reply asked for the login as a MAC, and only that is
    /// taken, as mhxd takes it: an obfuscated name is no more than the name,
    /// and a reply stripped of its request on the way would otherwise get
    /// one. A step 2 with no login at all is the guest, as on mhxd.
    pub fn names(&self, server: &Server, login: &[u8]) -> bool {
        if self.login.is_empty() {
            return login.is_empty();
        }
        same(&self.login, &server.mac.mac(login, &server.session_key))
    }
}
