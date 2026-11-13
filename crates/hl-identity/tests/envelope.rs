//! The key envelope's vectors in `vectors/identity-test-vectors.json`
//! (`docs/identity-registrar.md` §9, §15): one envelope of each kind for
//! `keys.identity`, every input in the clear, the put that stores it,
//! and the envelopes a reader refuses. Regenerate with
//! `cargo test -p hl-identity --test envelope -- --ignored generate`.

mod common;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hl_identity::cbor::{self, map, Value};
use hl_identity::envelope::{self, Kdf, Kind, Secret};
use hl_identity::{EnvelopePut, IdentityKey, KeyEnvelope, RecoveryCode};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

use common::json::{from_json, obj_mut, render, upsert, J};

const VECTORS: &str = include_str!("../vectors/identity-test-vectors.json");
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vectors/identity-test-vectors.json"
);

const REGISTRAR: &str = "hl.example";
const HANDLE: &str = "alice";
const TIME: u64 = 1_757_117_000;
/// Decomposed, as some keyboards type it: the derivation reads its NFC.
const PASSPHRASE: &str = "Gru\u{308}\u{df}e, cafe\u{301}";
const CODE: &str = "7K3M9-QXW2P-HD4TR-B8VNC";
const CODE_TYPED: &str = "7k3m9 qxw2p hd4tr b8vnc";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn str_of<'a>(j: &'a Json, k: &str) -> &'a str {
    j[k].as_str().unwrap_or_else(|| panic!("{k}"))
}

fn identity(v: &Json) -> IdentityKey {
    let seed: [u8; 32] = unhex(str_of(&v["keys"]["identity"], "seed_hex"))
        .try_into()
        .unwrap();
    IdentityKey::from_seed(&seed)
}

/// Argon2id here rather than through the crate, so the split into
/// `enc_key` and `auth_key` is checked rather than restated.
fn okm(secret: &[u8], kdf: &Kdf) -> [u8; 64] {
    let mut out = [0u8; 64];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(kdf.m, kdf.t, kdf.p, Some(64)).unwrap(),
    )
    .hash_password_into(secret, &kdf.salt, &mut out)
    .unwrap();
    out
}

struct Case {
    kind: Kind,
    secret_utf8: String,
    nonce: [u8; 24],
}

fn cases() -> [Case; 2] {
    [
        Case {
            kind: Kind::Passphrase,
            secret_utf8: PASSPHRASE.into(),
            nonce: std::array::from_fn(|i| i as u8),
        },
        Case {
            kind: Kind::RecoveryCode,
            secret_utf8: CODE.into(),
            nonce: std::array::from_fn(|i| 0x20 + i as u8),
        },
    ]
}

fn with_secret<R>(case: &Case, f: impl FnOnce(&Secret) -> R) -> R {
    match case.kind {
        Kind::Passphrase => f(&Secret::Passphrase(&case.secret_utf8)),
        Kind::RecoveryCode => f(&Secret::RecoveryCode(
            &RecoveryCode::parse(&case.secret_utf8).unwrap(),
        )),
    }
}

/// What the derivation reads: NFC for a passphrase, the 20 characters
/// alone for a code.
fn derived_from(case: &Case) -> Vec<u8> {
    match case.kind {
        Kind::Passphrase => "Gr\u{fc}\u{df}e, caf\u{e9}".as_bytes().to_vec(),
        Kind::RecoveryCode => CODE.replace('-', "").into_bytes(),
    }
}

/// The salt as the notes give it, apart from the crate's.
fn salt(kind: Kind) -> [u8; 16] {
    let mut h = Sha256::new();
    for part in ["hl-identity/envelope-salt/v1", REGISTRAR, HANDLE] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    h.update([kind as u8]);
    h.finalize()[..16].try_into().unwrap()
}

fn entry(id: &IdentityKey, case: &Case) -> Json {
    let (m, t, p) = Kdf::FLOOR;
    let kdf = Kdf {
        m,
        t,
        p,
        salt: salt(case.kind),
    };
    let (env, keys) = with_secret(case, |s| {
        KeyEnvelope::seal_with_nonce(id, REGISTRAR, HANDLE, s, case.nonce).unwrap()
    });
    assert_eq!(env.kdf, kdf);
    let okm = okm(&derived_from(case), &kdf);
    let put = EnvelopePut {
        identity: id.public(),
        kind: case.kind,
        time: TIME,
        auth_hash: Some(keys.auth_hash()),
        envelope: Some(env.encode()),
    }
    .sign(id)
    .unwrap();
    json!({
        "kind": case.kind as u64,
        "secret": case.secret_utf8,
        "derived_from_hex": hex(&derived_from(case)),
        "salt_hex": hex(&kdf.salt),
        "kdf": { "alg": "argon2id", "m": kdf.m, "t": kdf.t, "p": kdf.p },
        "nonce_hex": hex(&case.nonce),
        "enc_key_hex": hex(&okm[..32]),
        "auth_key_hex": hex(&okm[32..]),
        "auth_hash_hex": hex(&Sha256::digest(&okm[32..])),
        "envelope_hex": hex(&env.encode()),
        "put_signed_hex": hex(&put),
    })
}

fn rejects(id: &IdentityKey) -> Json {
    let (good, _) = KeyEnvelope::seal_with_nonce(
        id,
        REGISTRAR,
        HANDLE,
        &Secret::Passphrase("reject"),
        [9; 24],
    )
    .unwrap();
    let kdf = good.kdf;
    let kdf_map = |alg: &str, m: u32, t: u32, p: u32, salt: &[u8]| {
        map(vec![
            ("alg", Some(Value::Text(alg.into()))),
            ("m", Some(Value::Uint(m.into()))),
            ("t", Some(Value::Uint(t.into()))),
            ("p", Some(Value::Uint(p.into()))),
            ("salt", Some(Value::Bytes(salt.to_vec()))),
        ])
    };
    let raw = |kind: u64, kdf: Value, nonce: &[u8], ct: &[u8]| {
        cbor::encode(&map(vec![
            ("v", Some(Value::Uint(1))),
            ("kind", Some(Value::Uint(kind))),
            ("kdf", Some(kdf)),
            ("nonce", Some(Value::Bytes(nonce.to_vec()))),
            ("ct", Some(Value::Bytes(ct.to_vec()))),
        ]))
    };
    let with_kdf =
        |alg: &str, m, t, p| raw(1, kdf_map(alg, m, t, p, &kdf.salt), &good.nonce, &good.ct);
    let ((m0, t0, _), (m1, t1, p1)) = (Kdf::FLOOR, Kdf::CEILING);
    let kdf_bad = "bad field `kdf`";
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "m below the floor",
            with_kdf("argon2id", m0 - 1, kdf.t, kdf.p),
            kdf_bad,
        ),
        (
            "t below the floor",
            with_kdf("argon2id", kdf.m, t0 - 1, kdf.p),
            kdf_bad,
        ),
        (
            "m above the ceiling",
            with_kdf("argon2id", m1 + 1, kdf.t, kdf.p),
            kdf_bad,
        ),
        (
            "t above the ceiling",
            with_kdf("argon2id", kdf.m, t1 + 1, kdf.p),
            kdf_bad,
        ),
        (
            "p above the ceiling",
            with_kdf("argon2id", kdf.m, kdf.t, p1 + 1),
            kdf_bad,
        ),
        (
            "another Argon2",
            with_kdf("argon2i", kdf.m, kdf.t, kdf.p),
            kdf_bad,
        ),
        (
            "a salt of 15 bytes",
            raw(
                1,
                kdf_map("argon2id", kdf.m, kdf.t, kdf.p, &kdf.salt[..15]),
                &good.nonce,
                &good.ct,
            ),
            kdf_bad,
        ),
        (
            "a nonce of 23 bytes",
            raw(
                1,
                kdf_map("argon2id", kdf.m, kdf.t, kdf.p, &kdf.salt),
                &good.nonce[..23],
                &good.ct,
            ),
            "bad field `nonce`",
        ),
        (
            "a kind this version does not define",
            raw(
                3,
                kdf_map("argon2id", kdf.m, kdf.t, kdf.p, &kdf.salt),
                &good.nonce,
                &good.ct,
            ),
            "bad field `kind`",
        ),
        (
            "ct without its tag",
            raw(
                1,
                kdf_map("argon2id", kdf.m, kdf.t, kdf.p, &kdf.salt),
                &good.nonce,
                &good.ct[..32],
            ),
            "bad field `ct`",
        ),
        (
            "past 1 KiB",
            vec![0; envelope::MAX_BYTES + 1],
            "object too large",
        ),
    ];
    Json::Array(
        cases
            .into_iter()
            .map(|(name, bytes, error)| {
                json!({ "name": name, "envelope_hex": hex(&bytes), "error": error })
            })
            .collect(),
    )
}

fn notes() -> Json {
    json!([
        "Key envelopes (identity-registrar.md §9) for keys.identity, registered as `handle` at `registrar`. Byte strings are lowercase hex.",
        "salt = SHA-256(\"hl-identity/envelope-salt/v1\" || 0x00 || lowercase(registrar) || 0x00 || lowercase(handle) || 0x00 || kind as one byte)[0..16]. kdf is v1's, the floor.",
        "okm = Argon2id(derived_from, salt, m KiB, t, p, 64 bytes); enc_key = okm[0..32], auth_key = okm[32..64], auth_hash = SHA-256(auth_key). derived_from is the passphrase's UTF-8 in NFC (secret is typed decomposed), or the recovery code's 20 characters, uppercase, without its hyphens. A reader derives the keys once, before it fetches, and opens what comes back with them: an envelope whose kdf is not the one it derived with is refused, not derived for again.",
        "ct = XChaCha20-Poly1305(enc_key, nonce, aad = \"hl-identity/envelope/v1\" || 0x00 || identity public key, the identity seed).",
        "put_signed_hex is the PUT request storing it, signed by keys.identity under hl-identity/envelope-put/v1 at `time`.",
        "Every reject is refused when the envelope is parsed, before anything is derived."
    ])
}

fn vectors() -> Json {
    serde_json::from_str(VECTORS).unwrap()
}

#[test]
fn envelopes_derive_seal_and_open_as_the_file_says() {
    let v = vectors();
    let e = &v["envelope"];
    assert_eq!(
        (str_of(e, "registrar"), str_of(e, "handle")),
        (REGISTRAR, HANDLE)
    );
    let id = identity(&v);
    for (case, want) in cases().iter().zip(e["cases"].as_array().unwrap()) {
        assert_eq!(&entry(&id, case), want);
        let bytes = unhex(str_of(want, "envelope_hex"));
        let env = KeyEnvelope::parse(&bytes).unwrap();
        let keys = with_secret(case, |s| envelope::keys(REGISTRAR, HANDLE, s)).unwrap();
        let opened = env.open(&id.public(), &keys).unwrap();
        assert_eq!(*opened.seed(), *id.seed());
        let put = EnvelopePut::parse(&unhex(str_of(want, "put_signed_hex"))).unwrap();
        assert_eq!(put.envelope.as_deref(), Some(&bytes[..]));
        assert_eq!(
            put.auth_hash.map(|h| hex(&h)).as_deref(),
            Some(str_of(want, "auth_hash_hex"))
        );
        let mut aad = envelope::DOMAIN.as_bytes().to_vec();
        aad.push(0);
        aad.extend_from_slice(&id.public());
        let seed = XChaCha20Poly1305::new_from_slice(&unhex(str_of(want, "enc_key_hex")))
            .unwrap()
            .decrypt(
                XNonce::from_slice(&env.nonce),
                Payload {
                    msg: &env.ct,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(seed, *id.seed());
    }
}

#[test]
fn a_recovery_code_typed_off_paper_opens_its_envelope() {
    let v = vectors();
    let want = &v["envelope"]["cases"][1];
    let env = KeyEnvelope::parse(&unhex(str_of(want, "envelope_hex"))).unwrap();
    let typed = RecoveryCode::parse(CODE_TYPED).unwrap();
    let keys = envelope::keys(REGISTRAR, HANDLE, &Secret::RecoveryCode(&typed)).unwrap();
    assert!(env.open(&identity(&v).public(), &keys).is_ok());
}

#[test]
fn envelope_rejects() {
    let v = vectors();
    let id = identity(&v);
    assert_eq!(v["envelope"]["rejects"], rejects(&id));
    for r in v["envelope"]["rejects"].as_array().unwrap() {
        let got = KeyEnvelope::parse(&unhex(str_of(r, "envelope_hex"))).unwrap_err();
        assert_eq!(got.to_string(), str_of(r, "error"), "{}", str_of(r, "name"));
    }
}

#[test]
#[ignore = "writes vectors/identity-test-vectors.json"]
fn generate() {
    let text = std::fs::read_to_string(PATH).unwrap();
    let mut file: J = serde_json::from_str(&text).unwrap();
    assert_eq!(
        render(&file),
        text,
        "the file is written as this generator writes it"
    );
    let id = identity(&serde_json::from_str(&text).unwrap());
    let block = json!({
        "notes": notes(),
        "registrar": REGISTRAR,
        "handle": HANDLE,
        "identity": "keys.identity",
        "time": TIME,
        "cases": cases().iter().map(|c| entry(&id, c)).collect::<Vec<_>>(),
        "rejects": rejects(&id),
        "domains": { "envelope": envelope::DOMAIN, "put": envelope::PUT_DOMAIN },
    });
    upsert(obj_mut(&mut file), "envelope", from_json(&block), false);
    std::fs::write(PATH, render(&file)).unwrap();
}
