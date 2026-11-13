//! Key backup (`docs/identity-registrar.md` §9): the identity seed sealed
//! under a passphrase or a recovery code, for a registrar to keep and a
//! device with no other copy to fetch.
//!
//! A registrar holds the envelope and the hash of an `auth_key`; it can
//! read neither the seed nor the secret. The `auth_key` and the sealing
//! key come from one Argon2id derivation over a salt chosen fresh at each
//! seal, so replacing an envelope always replaces what fetches it. A
//! device asks the registrar for the salt first, and a registrar answers
//! that for a handle with no envelope as it would for one with, under a
//! salt only it can make ([`Kdf::decoy`]).

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::attestation::is_host;
use crate::cbor::{self, map, Value};
use crate::error::Error;
use crate::keys::{IdentityKey, PublicKey};
use crate::signed::{self, Envelope, VERSION};

pub const DOMAIN: &str = "hl-identity/envelope/v1";
pub const PUT_DOMAIN: &str = "hl-identity/envelope-put/v1";
const DECOY_DOMAIN: &str = "hl-identity/envelope-decoy/v1";
pub const MAX_BYTES: usize = 1024;
pub const PUT_MAX_BYTES: usize = 2048;
pub const KDF_MAX_BYTES: usize = 128;

/// What a secret is, and which envelope of an identity's two it opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Passphrase = 1,
    RecoveryCode = 2,
}

impl Kind {
    fn from_u64(n: u64) -> Result<Kind, Error> {
        match n {
            1 => Ok(Kind::Passphrase),
            2 => Ok(Kind::RecoveryCode),
            _ => Err(Error::BadField("kind")),
        }
    }
}

/// The secret an envelope is sealed under.
#[derive(Clone, Copy)]
pub enum Secret<'a> {
    Passphrase(&'a str),
    RecoveryCode(&'a RecoveryCode),
}

impl Secret<'_> {
    pub fn kind(&self) -> Kind {
        match self {
            Secret::Passphrase(_) => Kind::Passphrase,
            Secret::RecoveryCode(_) => Kind::RecoveryCode,
        }
    }

    /// NFC, so a passphrase typed on two keyboards that compose an accent
    /// differently is one passphrase. Reserved up front, at NFC's most, so
    /// no reallocation leaves a piece of it behind; the normalizer's own
    /// buffer for a long run of combining marks is beyond reach.
    fn bytes(&self) -> Zeroizing<String> {
        match self {
            Secret::Passphrase(p) => {
                let mut s = Zeroizing::new(String::with_capacity(p.len() * 3));
                s.extend(p.nfc());
                s
            }
            Secret::RecoveryCode(c) => c.0.clone(),
        }
    }
}

/// Argon2id's parameters and salt. `m` is in KiB. v1 has one set of
/// parameters, so a reader is never asked to spend what a registrar
/// chose, and only the salt varies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kdf {
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub salt: [u8; 16],
}

impl Kdf {
    /// v1's parameters: §9.1's floor, which a phone can afford.
    pub const V1: (u32, u32, u32) = (64 * 1024, 3, 1);

    /// v1's parameters under a fresh salt, for a seal.
    pub fn fresh() -> Kdf {
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).expect("OS CSPRNG unavailable");
        Kdf::with_salt(salt)
    }

    fn with_salt(salt: [u8; 16]) -> Kdf {
        let (m, t, p) = Kdf::V1;
        Kdf { m, t, p, salt }
    }

    /// What a registrar answers a salt lookup with for a handle that has
    /// no envelope of this kind: the same every time, so asking twice
    /// tells nothing, and unpredictable without `secret`, the registrar's
    /// own. `handle` is folded as the registrar folds it for uniqueness.
    pub fn decoy(secret: &[u8; 32], handle: &str, kind: Kind) -> Kdf {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("any key length");
        mac.update(DECOY_DOMAIN.as_bytes());
        mac.update(&[0]);
        mac.update(handle.to_ascii_lowercase().as_bytes());
        mac.update(&[0, kind as u8]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&mac.finalize().into_bytes()[..16]);
        Kdf::with_salt(salt)
    }

    fn value(&self) -> Value {
        map(vec![
            ("alg", Some(Value::Text("argon2id".into()))),
            ("m", Some(Value::Uint(self.m.into()))),
            ("t", Some(Value::Uint(self.t.into()))),
            ("p", Some(Value::Uint(self.p.into()))),
            ("salt", Some(Value::Bytes(self.salt.to_vec()))),
        ])
    }

    /// The salt lookup's answer, as CBOR.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.value())
    }

    pub fn parse(bytes: &[u8]) -> Result<Kdf, Error> {
        if bytes.len() > KDF_MAX_BYTES {
            return Err(Error::TooLarge);
        }
        Kdf::from_value(&cbor::decode_canonical(bytes)?)
    }

    /// Closed: the map is unsigned, so a key this version does not define
    /// is refused rather than left for another reader to give a meaning.
    fn from_value(v: &Value) -> Result<Kdf, Error> {
        let bad = Error::BadField("kdf");
        let Value::Map(entries) = v else {
            return Err(bad);
        };
        let known = ["alg", "m", "p", "salt", "t"];
        if entries.len() != known.len()
            || entries
                .iter()
                .any(|(k, _)| !matches!(k, Value::Text(k) if known.contains(&k.as_str())))
        {
            return Err(bad);
        }
        if signed::text(v, "alg")? != "argon2id" {
            return Err(bad);
        }
        let small = |k| u32::try_from(signed::uint(v, k)?).map_err(|_| Error::BadField("kdf"));
        let kdf = Kdf {
            m: small("m")?,
            t: small("t")?,
            p: small("p")?,
            salt: signed::bytes(v, "salt")?
                .try_into()
                .map_err(|_| Error::BadField("kdf"))?,
        };
        if (kdf.m, kdf.t, kdf.p) != Kdf::V1 {
            return Err(bad);
        }
        Ok(kdf)
    }
}

/// The two keys one derivation makes: `enc` seals and never leaves the
/// device; `auth` is what a fetch presents. A device derives them once,
/// from the salt the lookup gave, and opens what the fetch returns with
/// the same keys.
pub struct Keys {
    kind: Kind,
    kdf: Kdf,
    enc: Zeroizing<[u8; 32]>,
    auth: Zeroizing<[u8; 32]>,
}

impl Keys {
    /// Argon2id over the secret, 64 bytes, split into `enc` and `auth`.
    pub fn derive(secret: &Secret, kdf: Kdf) -> Result<Keys, Error> {
        if (kdf.m, kdf.t, kdf.p) != Kdf::V1 {
            return Err(Error::BadField("kdf"));
        }
        let params =
            Params::new(kdf.m, kdf.t, kdf.p, Some(64)).map_err(|_| Error::BadField("kdf"))?;
        let mut okm = Zeroizing::new([0u8; 64]);
        // argon2 leaves the memory it allocates itself as it was, and its
        // last block is enough to recompute the keys.
        let mut blocks = Zeroizing::new(vec![Block::default(); params.block_count()]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(
                secret.bytes().as_bytes(),
                &kdf.salt,
                &mut *okm,
                &mut *blocks,
            )
            .map_err(|_| Error::BadField("kdf"))?;
        let (mut enc, mut auth) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
        enc.copy_from_slice(&okm[..32]);
        auth.copy_from_slice(&okm[32..]);
        Ok(Keys {
            kind: secret.kind(),
            kdf,
            enc,
            auth,
        })
    }

    pub fn auth(&self) -> &[u8; 32] {
        &self.auth
    }

    /// What the registrar stores and compares a fetch's `auth` against.
    pub fn auth_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.auth[..]).into()
    }
}

fn aad(identity: &PublicKey) -> Vec<u8> {
    let mut aad = DOMAIN.as_bytes().to_vec();
    aad.push(0);
    aad.extend_from_slice(identity);
    aad
}

/// The §9.1 object. Unsigned: the AEAD, bound to the identity's key, is
/// its integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEnvelope {
    pub kind: Kind,
    pub kdf: Kdf,
    pub nonce: [u8; 24],
    pub ct: [u8; 48],
}

impl KeyEnvelope {
    /// Seal `identity`'s seed under `secret`, with a fresh salt and nonce.
    /// The keys come back for the put ([`EnvelopePut::store`]).
    pub fn seal(identity: &IdentityKey, secret: &Secret) -> Result<(KeyEnvelope, Keys), Error> {
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG unavailable");
        Self::seal_under(identity, secret, Kdf::fresh(), nonce)
    }

    /// [`KeyEnvelope::seal`] with a chosen salt and nonce, for test
    /// vectors: one salt and one secret make one key, so a nonce used
    /// twice under it gives the seed away.
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn seal_with(
        identity: &IdentityKey,
        secret: &Secret,
        salt: [u8; 16],
        nonce: [u8; 24],
    ) -> Result<(KeyEnvelope, Keys), Error> {
        Self::seal_under(identity, secret, Kdf::with_salt(salt), nonce)
    }

    fn seal_under(
        identity: &IdentityKey,
        secret: &Secret,
        kdf: Kdf,
        nonce: [u8; 24],
    ) -> Result<(KeyEnvelope, Keys), Error> {
        // With the salt published, an empty passphrase is one anybody can
        // fetch for.
        if matches!(secret, Secret::Passphrase(p) if p.trim().is_empty()) {
            return Err(Error::BadField("passphrase"));
        }
        let keys = Keys::derive(secret, kdf)?;
        let ct = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*keys.enc))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &*identity.seed(),
                    aad: &aad(&identity.public()),
                },
            )
            .expect("sealing 32 bytes cannot fail");
        let env = KeyEnvelope {
            kind: keys.kind,
            kdf,
            nonce,
            ct: ct.try_into().expect("32 bytes and a tag"),
        };
        Ok((env, keys))
    }

    /// The identity key, if `keys` are this envelope's and it was sealed
    /// for `identity`. The keys are the ones the fetch was made with, so
    /// an envelope under another salt than the lookup gave is refused
    /// rather than derived for again.
    pub fn open(&self, identity: &PublicKey, keys: &Keys) -> Result<IdentityKey, Error> {
        if keys.kdf != self.kdf {
            return Err(Error::BadField("kdf"));
        }
        if keys.kind != self.kind {
            return Err(Error::OpenFailed);
        }
        let seed = Zeroizing::new(
            XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*keys.enc))
                .decrypt(
                    XNonce::from_slice(&self.nonce),
                    Payload {
                        msg: &self.ct,
                        aad: &aad(identity),
                    },
                )
                .map_err(|_| Error::OpenFailed)?,
        );
        let key =
            IdentityKey::from_seed(seed.as_slice().try_into().map_err(|_| Error::OpenFailed)?);
        if key.public() != *identity {
            return Err(Error::OpenFailed);
        }
        Ok(key)
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("kind", Some(Value::Uint(self.kind as u64))),
            ("kdf", Some(self.kdf.value())),
            ("nonce", Some(Value::Bytes(self.nonce.to_vec()))),
            ("ct", Some(Value::Bytes(self.ct.to_vec()))),
        ]))
    }

    /// Decode and bound, the parameters v1's, before anything is derived.
    pub fn parse(bytes: &[u8]) -> Result<KeyEnvelope, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let v = cbor::decode_canonical(bytes)?;
        let version = signed::uint(&v, "v")?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let fixed = |k| signed::bytes(&v, k).map_err(|_| Error::BadField(k));
        Ok(KeyEnvelope {
            kind: Kind::from_u64(signed::uint(&v, "kind")?)?,
            kdf: Kdf::from_value(v.get("kdf").ok_or(Error::MissingField("kdf"))?)?,
            nonce: fixed("nonce")?
                .try_into()
                .map_err(|_| Error::BadField("nonce"))?,
            ct: fixed("ct")?.try_into().map_err(|_| Error::BadField("ct"))?,
        })
    }
}

/// `PUT <envelopes>` (§9.2): store, replace or delete one kind of an
/// identity's envelopes at one registrar. Signed by the identity key
/// alone, and naming the registrar so that a put made for one cannot be
/// replayed at another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopePut {
    pub identity: PublicKey,
    pub registrar: String,
    pub kind: Kind,
    pub time: u64,
    /// Present exactly when `envelope` is.
    pub auth_hash: Option<[u8; 32]>,
    pub envelope: Option<Vec<u8>>,
}

impl EnvelopePut {
    /// Store `envelope`, opened with `keys` first so that what is stored
    /// is what those keys will fetch and open again.
    pub fn store(
        identity: &IdentityKey,
        registrar: &str,
        time: u64,
        envelope: &KeyEnvelope,
        keys: &Keys,
    ) -> Result<Vec<u8>, Error> {
        envelope.open(&identity.public(), keys)?;
        EnvelopePut {
            identity: identity.public(),
            registrar: registrar.into(),
            kind: envelope.kind,
            time,
            auth_hash: Some(keys.auth_hash()),
            envelope: Some(envelope.encode()),
        }
        .sign(identity)
    }

    pub fn delete(
        identity: &IdentityKey,
        registrar: &str,
        kind: Kind,
        time: u64,
    ) -> Result<Vec<u8>, Error> {
        EnvelopePut {
            identity: identity.public(),
            registrar: registrar.into(),
            kind,
            time,
            auth_hash: None,
            envelope: None,
        }
        .sign(identity)
    }

    /// Parses back what it signs, so a request no registrar would read is
    /// an error here.
    fn sign(&self, identity: &IdentityKey) -> Result<Vec<u8>, Error> {
        let unsigned = map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("registrar", Some(Value::Text(self.registrar.clone()))),
            ("kind", Some(Value::Uint(self.kind as u64))),
            ("time", Some(Value::Uint(self.time))),
            (
                "auth_hash",
                self.auth_hash.map(|h| Value::Bytes(h.to_vec())),
            ),
            ("envelope", self.envelope.clone().map(Value::Bytes)),
        ]);
        let bytes = signed::seal(unsigned, |body| identity.sign(PUT_DOMAIN, body));
        Self::parse(&bytes)?;
        Ok(bytes)
    }

    /// Decode, bound and verify. The registrar's checks — its own host,
    /// attested, unfrozen, the clock, replay — are its own.
    pub fn parse(bytes: &[u8]) -> Result<EnvelopePut, Error> {
        if bytes.len() > PUT_MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let put = EnvelopePut {
            identity: signed::bytes32(v, "identity")?,
            registrar: signed::text(v, "registrar")?,
            kind: Kind::from_u64(signed::uint(v, "kind")?)?,
            time: signed::uint(v, "time")?,
            auth_hash: signed::opt_bytes32(v, "auth_hash")?,
            envelope: signed::opt_bytes(v, "envelope")?,
        };
        if !is_host(&put.registrar) {
            return Err(Error::BadField("registrar"));
        }
        if put.auth_hash.is_some() != put.envelope.is_some() {
            return Err(Error::BadField("auth_hash"));
        }
        if let Some(e) = &put.envelope {
            if KeyEnvelope::parse(e)?.kind != put.kind {
                return Err(Error::BadField("kind"));
            }
        }
        env.verify(&put.identity, PUT_DOMAIN)?;
        Ok(put)
    }
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 20 Crockford base32 characters (100 bits) from the OS CSPRNG, shown
/// once as four groups of five and never stored (§9.3).
pub struct RecoveryCode(Zeroizing<String>);

impl RecoveryCode {
    pub fn generate() -> RecoveryCode {
        let mut bytes = Zeroizing::new([0u8; 20]);
        getrandom::getrandom(&mut *bytes).expect("OS CSPRNG unavailable");
        RecoveryCode(Zeroizing::new(
            bytes
                .iter()
                .map(|b| CROCKFORD[usize::from(b & 31)] as char)
                .collect(),
        ))
    }

    /// As typed: case, spaces, hyphens and the Crockford confusables
    /// (`O`→`0`, `I`/`L`→`1`) forgiven, since it is read off paper.
    pub fn parse(typed: &str) -> Option<RecoveryCode> {
        let mut code = Zeroizing::new(String::with_capacity(20));
        for c in typed.chars().filter(|c| !matches!(c, ' ' | '-')) {
            let c = match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            if !c.is_ascii() || !CROCKFORD.contains(&(c as u8)) {
                return None;
            }
            // Past 20 the push would reallocate and leave a whole code in
            // memory nothing wipes.
            if code.len() == 20 {
                return None;
            }
            code.push(c);
        }
        (code.len() == 20).then(|| RecoveryCode(code))
    }

    /// The four groups of five, for the one time it is shown.
    pub fn display(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(23));
        for (i, c) in self.0.chars().enumerate() {
            if i > 0 && i % 5 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> IdentityKey {
        IdentityKey::from_seed(&[7; 32])
    }

    /// As a device does it: the salt from the lookup, then the keys.
    fn open(env: &KeyEnvelope, id: &IdentityKey, secret: &Secret) -> Result<IdentityKey, Error> {
        env.open(&id.public(), &Keys::derive(secret, env.kdf)?)
    }

    #[test]
    fn a_secret_opens_what_it_sealed_and_nothing_else_does() {
        let id = identity();
        let code = RecoveryCode::generate();
        let stranger = IdentityKey::from_seed(&[8; 32]);
        for (secret, wrong) in [
            (
                Secret::Passphrase("correct horse"),
                Secret::Passphrase("wrong horse"),
            ),
            (Secret::RecoveryCode(&code), Secret::Passphrase(&code.0)),
        ] {
            let (env, _) = KeyEnvelope::seal(&id, &secret).unwrap();
            let env = KeyEnvelope::parse(&env.encode()).unwrap();
            assert_eq!(open(&env, &id, &secret).unwrap().public(), id.public());
            assert_eq!(open(&env, &id, &wrong).err(), Some(Error::OpenFailed));
            assert_eq!(
                open(&env, &stranger, &secret).err(),
                Some(Error::OpenFailed)
            );
        }
    }

    #[test]
    fn a_passphrase_is_one_however_its_accents_were_typed() {
        let id = identity();
        let (env, _) = KeyEnvelope::seal(&id, &Secret::Passphrase("caf\u{e9}")).unwrap();
        assert!(open(&env, &id, &Secret::Passphrase("cafe\u{301}")).is_ok());
    }

    #[test]
    fn a_reseal_under_the_same_secret_is_fetched_by_another_key() {
        let id = identity();
        let secret = Secret::Passphrase("same");
        let (a, ka) = KeyEnvelope::seal(&id, &secret).unwrap();
        let (b, kb) = KeyEnvelope::seal(&id, &secret).unwrap();
        assert_ne!(ka.auth_hash(), kb.auth_hash());
        assert_eq!(
            b.open(&id.public(), &ka).err(),
            Some(Error::BadField("kdf"))
        );
        assert!(a.open(&id.public(), &ka).is_ok());
    }

    #[test]
    fn an_empty_passphrase_is_refused() {
        for p in ["", "   "] {
            assert_eq!(
                KeyEnvelope::seal(&identity(), &Secret::Passphrase(p)).err(),
                Some(Error::BadField("passphrase"))
            );
        }
    }

    #[test]
    fn a_decoy_is_the_same_each_time_and_its_registrars_alone() {
        let ours = [1; 32];
        let decoy = Kdf::decoy(&ours, "alice", Kind::Passphrase);
        assert_eq!(Kdf::decoy(&ours, "Alice", Kind::Passphrase), decoy);
        assert_eq!((decoy.m, decoy.t, decoy.p), Kdf::V1);
        for other in [
            Kdf::decoy(&[2; 32], "alice", Kind::Passphrase),
            Kdf::decoy(&ours, "bob", Kind::Passphrase),
            Kdf::decoy(&ours, "alice", Kind::RecoveryCode),
        ] {
            assert_ne!(other.salt, decoy.salt);
        }
    }

    #[test]
    fn a_put_is_bounded_before_it_is_decoded() {
        assert_eq!(
            EnvelopePut::parse(&[0; PUT_MAX_BYTES + 1]),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn a_store_holds_only_what_its_keys_open() {
        let id = identity();
        let (env, keys) = KeyEnvelope::seal(&id, &Secret::Passphrase("p")).unwrap();
        let (_, other) = KeyEnvelope::seal(&id, &Secret::Passphrase("p")).unwrap();
        let put = EnvelopePut::store(&id, "hl.example", 1_700_000_000, &env, &keys).unwrap();
        let put = EnvelopePut::parse(&put).unwrap();
        assert_eq!(put.auth_hash, Some(keys.auth_hash()));
        assert_eq!(
            EnvelopePut::store(&id, "hl.example", 1_700_000_000, &env, &other).err(),
            Some(Error::BadField("kdf"))
        );
        let stranger = IdentityKey::from_seed(&[8; 32]);
        assert_eq!(
            EnvelopePut::store(&stranger, "hl.example", 1_700_000_000, &env, &keys).err(),
            Some(Error::OpenFailed)
        );
        assert_eq!(
            EnvelopePut::store(&id, "hl.example:443", 1_700_000_000, &env, &keys).err(),
            Some(Error::BadField("registrar"))
        );
    }

    #[test]
    fn a_recovery_code_reads_back_as_typed_off_paper() {
        let code = RecoveryCode::generate();
        let shown = code.display();
        assert_eq!(shown.len(), 23);
        let typed = shown.to_lowercase().replace('0', "o").replace('-', " ");
        assert_eq!(RecoveryCode::parse(&typed).unwrap().display(), shown);
        assert!(RecoveryCode::parse("ABCDE-FGHJK-MNPQR-STVW").is_none());
        assert!(RecoveryCode::parse("ABCDE-FGHJK-MNPQR-STVWU").is_none());
        assert!(RecoveryCode::parse("ABCDE-FGHJK-MNPQR-STVWX-Y").is_none());
    }
}
