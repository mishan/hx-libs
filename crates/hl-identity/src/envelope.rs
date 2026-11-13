//! Key backup (`docs/identity-registrar.md` §9): the identity seed sealed
//! under a passphrase or a recovery code, for a registrar to keep and a
//! device with no other copy to fetch.
//!
//! A registrar holds the envelope and the hash of an `auth_key`; it can
//! read neither the seed nor the secret. The `auth_key` and the sealing
//! key come from one Argon2id derivation, so a device that knows only
//! the handle and the secret must be able to make it before it holds the
//! envelope. The salt is therefore derived from the registrar, the
//! handle and the kind, and v1's parameters are fixed.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::cbor::{self, map, Value};
use crate::error::Error;
use crate::keys::{IdentityKey, PublicKey};
use crate::signed::{self, Envelope, VERSION};

pub const DOMAIN: &str = "hl-identity/envelope/v1";
pub const PUT_DOMAIN: &str = "hl-identity/envelope-put/v1";
const SALT_DOMAIN: &str = "hl-identity/envelope-salt/v1";
pub const MAX_BYTES: usize = 1024;
pub const PUT_MAX_BYTES: usize = 2048;

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
    /// differently is one passphrase.
    /// Reserved up front, at NFC's most, so no reallocation leaves a
    /// piece of the passphrase behind.
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

/// Argon2id's parameters and salt. `m` is in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kdf {
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub salt: [u8; 16],
}

impl Kdf {
    /// What a registrar accepts at the least (§9.1), and v1's parameters.
    pub const FLOOR: (u32, u32, u32) = (64 * 1024, 3, 1);
    /// What a reader will spend at the most: a registrar serving more
    /// could exhaust a phone's memory, or its patience, before the
    /// envelope fails to open.
    pub const CEILING: (u32, u32, u32) = (1024 * 1024, 16, 8);

    /// v1's parameters, with the salt for this handle at this registrar.
    /// `registrar` is its §3 `host` — a hostname, no scheme, no port — and
    /// `handle` the name as registered; anything else is another salt, and
    /// an envelope nobody can fetch.
    pub fn for_handle(registrar: &str, handle: &str, kind: Kind) -> Kdf {
        let mut h = Sha256::new();
        for part in [
            SALT_DOMAIN,
            &registrar.to_ascii_lowercase(),
            &handle.to_ascii_lowercase(),
        ] {
            h.update(part.as_bytes());
            h.update([0]);
        }
        h.update([kind as u8]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&h.finalize()[..16]);
        let (m, t, p) = Kdf::FLOOR;
        Kdf { m, t, p, salt }
    }

    fn check(&self) -> Result<(), Error> {
        let ((m0, t0, p0), (m1, t1, p1)) = (Kdf::FLOOR, Kdf::CEILING);
        if !(m0..=m1).contains(&self.m)
            || !(t0..=t1).contains(&self.t)
            || !(p0..=p1).contains(&self.p)
        {
            return Err(Error::BadField("kdf"));
        }
        Ok(())
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

    fn from_value(v: &Value) -> Result<Kdf, Error> {
        if signed::text(v, "alg")? != "argon2id" {
            return Err(Error::BadField("kdf"));
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
        kdf.check()?;
        Ok(kdf)
    }
}

/// The two keys one derivation makes: `enc` seals and never leaves the
/// device; `auth` is what a fetch presents. A device derives them once,
/// before the fetch, and opens what comes back with the same keys.
pub struct Keys {
    kind: Kind,
    kdf: Kdf,
    enc: Zeroizing<[u8; 32]>,
    auth: Zeroizing<[u8; 32]>,
}

impl Keys {
    pub fn auth(&self) -> &[u8; 32] {
        &self.auth
    }

    /// What the registrar stores and compares a fetch's `auth` against.
    pub fn auth_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.auth[..]).into()
    }
}

/// The keys for `handle`'s envelope of `secret`'s kind at `registrar`
/// ([`Kdf::for_handle`]): Argon2id over the secret, 64 bytes, split
/// into `enc` and `auth`.
pub fn keys(registrar: &str, handle: &str, secret: &Secret) -> Result<Keys, Error> {
    derive(secret, Kdf::for_handle(registrar, handle, secret.kind()))
}

fn derive(secret: &Secret, kdf: Kdf) -> Result<Keys, Error> {
    kdf.check()?;
    let params = Params::new(kdf.m, kdf.t, kdf.p, Some(64)).map_err(|_| Error::BadField("kdf"))?;
    let mut okm = Zeroizing::new([0u8; 64]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret.bytes().as_bytes(), &kdf.salt, &mut *okm)
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
    /// Seal `identity`'s seed under `secret` for `handle` at `registrar`,
    /// with a fresh nonce. The salt and parameters are v1's for them, so
    /// what is stored is what a device with only the handle and the
    /// secret can fetch. The keys come back for the put's `auth_hash`.
    pub fn seal(
        identity: &IdentityKey,
        registrar: &str,
        handle: &str,
        secret: &Secret,
    ) -> Result<(KeyEnvelope, Keys), Error> {
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).expect("OS CSPRNG unavailable");
        Self::seal_with_nonce(identity, registrar, handle, secret, nonce)
    }

    /// [`KeyEnvelope::seal`] with a chosen nonce, for test vectors. A
    /// nonce used twice under one key gives the seed away.
    #[doc(hidden)]
    pub fn seal_with_nonce(
        identity: &IdentityKey,
        registrar: &str,
        handle: &str,
        secret: &Secret,
        nonce: [u8; 24],
    ) -> Result<(KeyEnvelope, Keys), Error> {
        let keys = keys(registrar, handle, secret)?;
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
            kdf: keys.kdf,
            nonce,
            ct: ct.try_into().expect("32 bytes and a tag"),
        };
        Ok((env, keys))
    }

    /// The identity key, if `keys` are this envelope's and it was sealed
    /// for `identity`. The keys are the ones the fetch was made with, so
    /// an envelope whose salt or parameters are not what they were
    /// derived for is refused rather than derived for again: a registrar
    /// cannot make a device spend more than the fetch already did.
    pub fn open(&self, identity: &PublicKey, keys: &Keys) -> Result<IdentityKey, Error> {
        if keys.kdf != self.kdf {
            return Err(Error::BadField("kdf"));
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

    /// For a registrar at a put: an envelope that is not v1's for this
    /// handle is one no fetch could ever be made for.
    pub fn check_for(&self, registrar: &str, handle: &str) -> Result<(), Error> {
        if self.kdf == Kdf::for_handle(registrar, handle, self.kind) {
            Ok(())
        } else {
            Err(Error::BadField("kdf"))
        }
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

    /// Decode and bound, the parameters within [`Kdf::FLOOR`] and
    /// [`Kdf::CEILING`] before anything is derived.
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

/// `PUT <envelopes>` (§9.2): store, replace or, with no `envelope`,
/// delete one kind of an identity's envelopes. Signed by the identity
/// key alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopePut {
    pub identity: PublicKey,
    pub kind: Kind,
    pub time: u64,
    /// Present exactly when `envelope` is.
    pub auth_hash: Option<[u8; 32]>,
    pub envelope: Option<Vec<u8>>,
}

impl EnvelopePut {
    /// Parses back what it signs, so a request no registrar would read is
    /// an error here.
    pub fn sign(&self, identity: &IdentityKey) -> Result<Vec<u8>, Error> {
        assert_eq!(
            identity.public(),
            self.identity,
            "signing an envelope put with a key that is not its identity"
        );
        let unsigned = map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
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

    /// Decode, bound and verify. The registrar's checks — attested,
    /// unfrozen, the clock, replay — are its own.
    pub fn parse(bytes: &[u8]) -> Result<EnvelopePut, Error> {
        if bytes.len() > PUT_MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let put = EnvelopePut {
            identity: signed::bytes32(v, "identity")?,
            kind: Kind::from_u64(signed::uint(v, "kind")?)?,
            time: signed::uint(v, "time")?,
            auth_hash: signed::opt_bytes32(v, "auth_hash")?,
            envelope: signed::opt_bytes(v, "envelope")?,
        };
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

    fn kdf() -> Kdf {
        Kdf::for_handle("hl.example", "alice", Kind::Passphrase)
    }

    fn seal(id: &IdentityKey, secret: &Secret) -> KeyEnvelope {
        KeyEnvelope::seal(id, "hl.example", "alice", secret)
            .unwrap()
            .0
    }

    fn open(env: &KeyEnvelope, id: &IdentityKey, secret: &Secret) -> Result<IdentityKey, Error> {
        env.open(&id.public(), &keys("hl.example", "alice", secret).unwrap())
    }

    #[test]
    fn a_passphrase_opens_what_it_sealed_and_nothing_else_does() {
        let id = identity();
        let env = seal(&id, &Secret::Passphrase("correct horse"));
        let env = KeyEnvelope::parse(&env.encode()).unwrap();
        let opened = open(&env, &id, &Secret::Passphrase("correct horse")).unwrap();
        assert_eq!(opened.public(), id.public());
        let stranger = IdentityKey::from_seed(&[8; 32]);
        for (who, secret) in [
            (&id, Secret::Passphrase("wrong horse")),
            (&stranger, Secret::Passphrase("correct horse")),
        ] {
            assert_eq!(open(&env, who, &secret).err(), Some(Error::OpenFailed));
        }
    }

    #[test]
    fn a_passphrase_is_one_however_its_accents_were_typed() {
        let id = identity();
        let env = seal(&id, &Secret::Passphrase("caf\u{e9}"));
        assert!(open(&env, &id, &Secret::Passphrase("cafe\u{301}")).is_ok());
    }

    #[test]
    fn the_salt_is_the_handles_whatever_its_case() {
        assert_eq!(
            Kdf::for_handle("HL.example", "Alice", Kind::Passphrase),
            kdf()
        );
        for other in [
            Kdf::for_handle("hl.example", "bob", Kind::Passphrase),
            Kdf::for_handle("other.example", "alice", Kind::Passphrase),
            Kdf::for_handle("hl.example", "alice", Kind::RecoveryCode),
        ] {
            assert_ne!(other.salt, kdf().salt);
        }
    }

    #[test]
    fn an_envelope_not_v1s_for_the_handle_is_refused_without_deriving_again() {
        let id = identity();
        let secret = Secret::Passphrase("p");
        let env = seal(&id, &secret);
        assert_eq!(env.check_for("hl.example", "alice"), Ok(()));
        assert_eq!(
            env.check_for("hl.example", "bob"),
            Err(Error::BadField("kdf"))
        );
        let bobs = keys("hl.example", "bob", &secret).unwrap();
        assert_eq!(
            env.open(&id.public(), &bobs).err(),
            Some(Error::BadField("kdf"))
        );
        let stronger = KeyEnvelope {
            kdf: Kdf { t: 4, ..env.kdf },
            ..env.clone()
        };
        assert_eq!(
            stronger.check_for("hl.example", "alice"),
            Err(Error::BadField("kdf"))
        );
        assert_eq!(
            open(&stronger, &id, &secret).err(),
            Some(Error::BadField("kdf"))
        );
    }

    #[test]
    fn parameters_outside_the_floor_and_ceiling_are_refused_before_deriving() {
        let env = seal(&identity(), &Secret::Passphrase("p"));
        for (m, t, p) in [
            (Kdf::FLOOR.0 - 1, 3, 1),
            (Kdf::CEILING.0 + 1, 3, 1),
            (Kdf::FLOOR.0, 2, 1),
            (Kdf::FLOOR.0, Kdf::CEILING.1 + 1, 1),
            (Kdf::FLOOR.0, 3, Kdf::CEILING.2 + 1),
        ] {
            let bad = KeyEnvelope {
                kdf: Kdf { m, t, p, ..env.kdf },
                ..env.clone()
            };
            assert_eq!(
                KeyEnvelope::parse(&bad.encode()),
                Err(Error::BadField("kdf")),
                "{m} {t} {p}"
            );
        }
    }

    #[test]
    fn an_envelope_is_bounded_before_it_is_decoded() {
        assert_eq!(
            KeyEnvelope::parse(&[0; MAX_BYTES + 1]),
            Err(Error::TooLarge)
        );
        assert_eq!(
            EnvelopePut::parse(&[0; PUT_MAX_BYTES + 1]),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn a_put_carries_a_hash_exactly_when_it_carries_an_envelope() {
        let id = identity();
        let (env, keys) =
            KeyEnvelope::seal(&id, "hl.example", "alice", &Secret::Passphrase("p")).unwrap();
        let put = EnvelopePut {
            identity: id.public(),
            kind: Kind::Passphrase,
            time: 1_700_000_000,
            auth_hash: Some(keys.auth_hash()),
            envelope: Some(env.encode()),
        };
        assert_eq!(EnvelopePut::parse(&put.sign(&id).unwrap()).unwrap(), put);
        let delete = EnvelopePut {
            auth_hash: None,
            envelope: None,
            ..put.clone()
        };
        assert!(delete.sign(&id).is_ok());
        let unhashed = EnvelopePut {
            auth_hash: None,
            ..put.clone()
        };
        assert_eq!(unhashed.sign(&id), Err(Error::BadField("auth_hash")));
        let mislabeled = EnvelopePut {
            kind: Kind::RecoveryCode,
            ..put
        };
        assert_eq!(mislabeled.sign(&id), Err(Error::BadField("kind")));
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
    }

    #[test]
    fn a_recovery_code_opens_only_its_own_kind() {
        let id = identity();
        let code = RecoveryCode::generate();
        let env = seal(&id, &Secret::RecoveryCode(&code));
        assert!(open(&env, &id, &Secret::RecoveryCode(&code)).is_ok());
        assert_eq!(
            open(&env, &id, &Secret::Passphrase(&code.0)).err(),
            Some(Error::BadField("kdf"))
        );
    }
}
