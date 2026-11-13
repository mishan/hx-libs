//! The key envelope's vectors in `vectors/identity-test-vectors.json`
//! (`docs/identity-registrar.md` §9, §15): one envelope of each kind for
//! `keys.identity`, every input in the clear, the salt lookup's answer,
//! the puts that store and delete it, a registrar's decoy salt, and what
//! a reader refuses. Regenerate with
//! `cargo test -p hl-identity --test envelope -- --ignored generate`.

mod common;

use argon2::{Algorithm, Argon2, AssociatedData, Params, ParamsBuilder, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use hl_identity::cbor::{self, map, Value};
use hl_identity::envelope::{self, Kdf, Keys, Kind, Secret};
use hl_identity::{EnvelopePut, IdentityKey, KeyEnvelope, RecoveryCode};
use hmac::{Hmac, Mac};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

use common::json::{from_json, obj_mut, render, upsert, J};

const VECTORS: &str = include_str!("../vectors/identity-test-vectors.json");
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vectors/identity-test-vectors.json"
);

const REGISTRAR: &str = "hl.example";
const TIME: u64 = 1_757_117_000;
/// Decomposed, as some keyboards type it: the derivation reads its NFC.
const PASSPHRASE: &str = "Gru\u{308}\u{df}e, cafe\u{301}";
const CODE: &str = "7K3M9-QXW2P-HD4TR-B8VNC";
const CODE_TYPED: &str = "7k3m9 qxw2p hd4tr b8vnc";
const DECOY_SECRET: [u8; 32] = [0x5a; 32];

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
fn okm(secret: &[u8], salt: &[u8]) -> [u8; 64] {
    let (m, t, p) = Kdf::V1;
    let mut out = [0u8; 64];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(m, t, p, Some(64)).unwrap(),
    )
    .hash_password_into(secret, salt, &mut out)
    .unwrap();
    out
}

struct Case {
    kind: Kind,
    secret: &'static str,
    /// What the derivation reads: NFC for a passphrase, the 20 characters
    /// alone for a code.
    derived_from: &'static str,
    salt: [u8; 16],
    nonce: [u8; 24],
}

fn cases() -> [Case; 2] {
    [
        Case {
            kind: Kind::Passphrase,
            secret: PASSPHRASE,
            derived_from: "Gr\u{fc}\u{df}e, caf\u{e9}",
            salt: std::array::from_fn(|i| 0x40 + i as u8),
            nonce: std::array::from_fn(|i| i as u8),
        },
        Case {
            kind: Kind::RecoveryCode,
            secret: CODE,
            derived_from: "7K3M9QXW2PHD4TRB8VNC",
            salt: std::array::from_fn(|i| 0x60 + i as u8),
            nonce: std::array::from_fn(|i| 0x20 + i as u8),
        },
    ]
}

fn with_secret<R>(case: &Case, f: impl FnOnce(&Secret) -> R) -> R {
    match case.kind {
        Kind::Passphrase => f(&Secret::Passphrase(case.secret)),
        Kind::RecoveryCode => f(&Secret::RecoveryCode(
            &RecoveryCode::parse(case.secret).unwrap(),
        )),
    }
}

fn entry(id: &IdentityKey, case: &Case) -> Json {
    let (env, keys) = with_secret(case, |s| {
        KeyEnvelope::seal_with(id, s, case.salt, case.nonce).unwrap()
    });
    let okm = okm(case.derived_from.as_bytes(), &case.salt);
    json!({
        "kind": case.kind as u64,
        "secret": case.secret,
        "derived_from_hex": hex(case.derived_from.as_bytes()),
        "salt_hex": hex(&case.salt),
        "kdf_hex": hex(&env.kdf.encode()),
        "nonce_hex": hex(&case.nonce),
        "enc_key_hex": hex(&okm[..32]),
        "auth_key_hex": hex(&okm[32..]),
        "auth_hash_hex": hex(&Sha256::digest(&okm[32..])),
        "envelope_hex": hex(&env.encode()),
        "store_signed_hex": hex(&EnvelopePut::store(id, REGISTRAR, TIME, &env, &keys).unwrap()),
        "delete_signed_hex": hex(&EnvelopePut::delete(id, REGISTRAR, case.kind, TIME).unwrap()),
    })
}

fn decoy() -> Json {
    json!({
        "secret_hex": hex(&DECOY_SECRET),
        "handle": "Bob",
        "kind": 1,
        "kdf_hex": hex(&Kdf::decoy(&DECOY_SECRET, "Bob", Kind::Passphrase).encode()),
    })
}

fn kdf_map(entries: Vec<(&str, Value)>) -> Value {
    map(entries.into_iter().map(|(k, v)| (k, Some(v))).collect())
}

fn v1_kdf(salt: &[u8]) -> Vec<(&'static str, Value)> {
    let (m, t, p) = Kdf::V1;
    vec![
        ("alg", Value::Text("argon2id".into())),
        ("m", Value::Uint(m.into())),
        ("t", Value::Uint(t.into())),
        ("p", Value::Uint(p.into())),
        ("salt", Value::Bytes(salt.to_vec())),
    ]
}

fn set(
    mut entries: Vec<(&'static str, Value)>,
    key: &'static str,
    v: Value,
) -> Vec<(&'static str, Value)> {
    entries.retain(|(k, _)| *k != key);
    entries.push((key, v));
    entries
}

/// Envelopes refused when parsed, before anything is derived.
fn rejects(good: &KeyEnvelope) -> Json {
    let raw = |kind: u64, kdf: Value, nonce: &[u8], ct: &[u8]| {
        cbor::encode(&map(vec![
            ("v", Some(Value::Uint(1))),
            ("kind", Some(Value::Uint(kind))),
            ("kdf", Some(kdf)),
            ("nonce", Some(Value::Bytes(nonce.to_vec()))),
            ("ct", Some(Value::Bytes(ct.to_vec()))),
        ]))
    };
    let salt = good.kdf.salt;
    let with_kdf = |kdf| raw(1, kdf_map(kdf), &good.nonce, &good.ct);
    let (m, t, p) = Kdf::V1;
    let kdf = "bad field `kdf`";
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "m other than v1's",
            with_kdf(set(v1_kdf(&salt), "m", Value::Uint((m * 2).into()))),
            kdf,
        ),
        (
            "t other than v1's",
            with_kdf(set(v1_kdf(&salt), "t", Value::Uint((t + 1).into()))),
            kdf,
        ),
        (
            "p other than v1's",
            with_kdf(set(v1_kdf(&salt), "p", Value::Uint((p + 1).into()))),
            kdf,
        ),
        (
            "another Argon2",
            with_kdf(set(v1_kdf(&salt), "alg", Value::Text("argon2i".into()))),
            kdf,
        ),
        (
            "a key kdf does not define",
            with_kdf(set(v1_kdf(&salt), "secret", Value::Uint(1))),
            kdf,
        ),
        ("a salt of 15 bytes", with_kdf(v1_kdf(&salt[..15])), kdf),
        (
            "a nonce of 23 bytes",
            raw(1, kdf_map(v1_kdf(&salt)), &good.nonce[..23], &good.ct),
            "bad field `nonce`",
        ),
        (
            "a kind this version does not define",
            raw(3, kdf_map(v1_kdf(&salt)), &good.nonce, &good.ct),
            "bad field `kind`",
        ),
        (
            "ct without its tag",
            raw(1, kdf_map(v1_kdf(&salt)), &good.nonce, &good.ct[..32]),
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
            .map(|(name, bytes, error)| json!({ "name": name, "envelope_hex": hex(&bytes), "error": error }))
            .collect(),
    )
}

/// Envelopes that parse, opened with keys derived from `cases[0]`'s
/// passphrase under the kdf the lookup gave.
fn open_rejects(good: &KeyEnvelope) -> Json {
    let other = IdentityKey::from_seed(&[0x11; 32]);
    let (theirs, _) = KeyEnvelope::seal_with(
        &other,
        &Secret::Passphrase(PASSPHRASE),
        good.kdf.salt,
        [3; 24],
    )
    .unwrap();
    json!([
        {
            "name": "an envelope under another salt than the lookup gave: refused, not derived for again",
            "envelope_hex": hex(&good.encode()),
            "lookup_kdf_hex": hex(&Kdf::decoy(&DECOY_SECRET, "alice", Kind::Passphrase).encode()),
            "error": "bad field `kdf`",
        },
        {
            "name": "an envelope sealed for another identity",
            "envelope_hex": hex(&theirs.encode()),
            "lookup_kdf_hex": hex(&good.kdf.encode()),
            "error": "sealed message does not open",
        },
    ])
}

fn put_rejects(id: &IdentityKey, good: &KeyEnvelope) -> Json {
    let signing = SigningKey::from_bytes(&id.seed());
    let signed =
        |registrar: &str, kind: u64, auth_hash: Option<[u8; 32]>, envelope: Option<Vec<u8>>| {
            let unsigned = map(vec![
                ("v", Some(Value::Uint(1))),
                ("identity", Some(Value::Bytes(id.public().to_vec()))),
                ("registrar", Some(Value::Text(registrar.into()))),
                ("kind", Some(Value::Uint(kind))),
                ("time", Some(Value::Uint(TIME))),
                ("auth_hash", auth_hash.map(|h| Value::Bytes(h.to_vec()))),
                ("envelope", envelope.map(Value::Bytes)),
            ]);
            let body = cbor::encode(&unsigned);
            let mut input = envelope::PUT_DOMAIN.as_bytes().to_vec();
            input.push(0);
            input.extend_from_slice(&body);
            let sig = signing.sign(&input).to_bytes();
            let Value::Map(mut entries) = unsigned else {
                unreachable!()
            };
            entries.push((Value::Text("sig".into()), Value::Bytes(sig.to_vec())));
            cbor::encode(&Value::Map(entries))
        };
    let env = Some(good.encode());
    let hash = Some([7; 32]);
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "a kind other than its envelope's",
            signed(REGISTRAR, 2, hash, env.clone()),
            "bad field `kind`",
        ),
        (
            "an envelope without its auth_hash",
            signed(REGISTRAR, 1, None, env.clone()),
            "bad field `auth_hash`",
        ),
        (
            "a registrar with a port",
            signed("hl.example:443", 1, hash, env),
            "bad field `registrar`",
        ),
    ];
    Json::Array(
        cases
            .into_iter()
            .map(|(name, bytes, error)| json!({ "name": name, "put_hex": hex(&bytes), "error": error }))
            .collect(),
    )
}

fn notes() -> Json {
    json!([
        "Key envelopes (identity-registrar.md §9) for keys.identity at `registrar`. Byte strings are lowercase hex.",
        "kdf_hex is the salt lookup's answer: CBOR {alg: \"argon2id\", m: 65536, t: 3, p: 1, salt}. v1 has those parameters alone; any other, and any other key, is refused. Each seal draws a fresh 16-byte salt.",
        "okm = Argon2id(derived_from, salt, m KiB, t, p, 64 bytes); enc_key = okm[0..32], auth_key = okm[32..64], auth_hash = SHA-256(auth_key). derived_from is the passphrase's UTF-8 in NFC (secret is typed decomposed), or the recovery code's 20 characters, uppercase, without its hyphens.",
        "ct = XChaCha20-Poly1305(enc_key, nonce, aad = \"hl-identity/envelope/v1\" || 0x00 || identity public key, the identity seed).",
        "store_signed_hex and delete_signed_hex are the PUT requests storing and deleting it, signed by keys.identity under hl-identity/envelope-put/v1 at `time`, naming `registrar`.",
        "decoy: the lookup's answer for a handle with no envelope of that kind. salt = HMAC-SHA-256(secret, \"hl-identity/envelope-decoy/v1\" || 0x00 || lowercase(handle) || 0x00 || kind as one byte)[0..16], v1's parameters.",
        "A reader derives the keys once, from the lookup's kdf, fetches with auth_key and opens what comes back with the same keys: open_rejects are envelopes that parse and are refused at open, the first without deriving under its own kdf.",
        "argon2id_rfc9106 is RFC 9106 §5.3's Argon2id test vector, for checking an Argon2id implementation apart from these objects."
    ])
}

/// RFC 9106 §5.3.
fn argon2id_rfc9106() -> Json {
    json!({
        "password_hex": hex(&[1; 32]),
        "salt_hex": hex(&[2; 16]),
        "secret_hex": hex(&[3; 8]),
        "associated_data_hex": hex(&[4; 12]),
        "m": 32, "t": 3, "p": 4,
        "tag_hex": "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
    })
}

fn vectors() -> Json {
    serde_json::from_str(VECTORS).unwrap()
}

#[test]
fn envelopes_derive_seal_and_open_as_the_file_says() {
    let v = vectors();
    let e = &v["envelope"];
    assert_eq!(str_of(e, "registrar"), REGISTRAR);
    let id = identity(&v);
    for (case, want) in cases().iter().zip(e["cases"].as_array().unwrap()) {
        assert_eq!(&entry(&id, case), want);
        let bytes = unhex(str_of(want, "envelope_hex"));
        let env = KeyEnvelope::parse(&bytes).unwrap();
        let lookup = Kdf::parse(&unhex(str_of(want, "kdf_hex"))).unwrap();
        assert_eq!(lookup.salt.to_vec(), unhex(str_of(want, "salt_hex")));
        let keys = with_secret(case, |s| Keys::derive(s, lookup)).unwrap();
        assert_eq!(hex(&keys.auth_hash()), str_of(want, "auth_hash_hex"));
        assert_eq!(*env.open(&id.public(), &keys).unwrap().seed(), *id.seed());
        let store = EnvelopePut::parse(&unhex(str_of(want, "store_signed_hex"))).unwrap();
        assert_eq!(store.envelope.as_deref(), Some(&bytes[..]));
        assert_eq!(store.registrar, REGISTRAR);
        assert_eq!(
            store.auth_hash.map(|h| hex(&h)).as_deref(),
            Some(str_of(want, "auth_hash_hex"))
        );
        let delete = EnvelopePut::parse(&unhex(str_of(want, "delete_signed_hex"))).unwrap();
        assert_eq!((delete.envelope, delete.auth_hash), (None, None));
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
    let keys = Keys::derive(&Secret::RecoveryCode(&typed), env.kdf).unwrap();
    assert!(env.open(&identity(&v).public(), &keys).is_ok());
}

#[test]
fn a_decoy_is_the_hmac_the_file_says() {
    let v = vectors();
    let d = &v["envelope"]["decoy"];
    assert_eq!(*d, decoy());
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&unhex(str_of(d, "secret_hex"))).unwrap();
    mac.update(b"hl-identity/envelope-decoy/v1\0bob\0\x01");
    let kdf = Kdf::parse(&unhex(str_of(d, "kdf_hex"))).unwrap();
    assert_eq!(kdf.salt[..], mac.finalize().into_bytes()[..16]);
}

#[test]
fn envelope_rejects() {
    let v = vectors();
    let id = identity(&v);
    let e = &v["envelope"];
    let good = KeyEnvelope::parse(&unhex(str_of(&e["cases"][0], "envelope_hex"))).unwrap();
    assert_eq!(e["rejects"], rejects(&good));
    for r in e["rejects"].as_array().unwrap() {
        let got = KeyEnvelope::parse(&unhex(str_of(r, "envelope_hex"))).unwrap_err();
        assert_eq!(got.to_string(), str_of(r, "error"), "{}", str_of(r, "name"));
    }
    assert_eq!(e["open_rejects"], open_rejects(&good));
    for r in e["open_rejects"].as_array().unwrap() {
        let env = KeyEnvelope::parse(&unhex(str_of(r, "envelope_hex"))).unwrap();
        let lookup = Kdf::parse(&unhex(str_of(r, "lookup_kdf_hex"))).unwrap();
        let keys = Keys::derive(&Secret::Passphrase(PASSPHRASE), lookup).unwrap();
        let got = env.open(&id.public(), &keys).unwrap_err();
        assert_eq!(got.to_string(), str_of(r, "error"), "{}", str_of(r, "name"));
    }
    assert_eq!(e["put_rejects"], put_rejects(&id, &good));
    for r in e["put_rejects"].as_array().unwrap() {
        let got = EnvelopePut::parse(&unhex(str_of(r, "put_hex"))).unwrap_err();
        assert_eq!(got.to_string(), str_of(r, "error"), "{}", str_of(r, "name"));
    }
}

#[test]
fn argon2id_is_rfc_9106s() {
    let v = vectors();
    let a = &v["envelope"]["argon2id_rfc9106"];
    assert_eq!(*a, argon2id_rfc9106());
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&unhex(str_of(a, "associated_data_hex"))).unwrap())
        .build()
        .unwrap();
    let secret = unhex(str_of(a, "secret_hex"));
    let mut tag = [0u8; 32];
    Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
        .unwrap()
        .hash_password_into(
            &unhex(str_of(a, "password_hex")),
            &unhex(str_of(a, "salt_hex")),
            &mut tag,
        )
        .unwrap();
    assert_eq!(hex(&tag), str_of(a, "tag_hex"));
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
    let all = cases();
    let good = with_secret(&all[0], |s| {
        KeyEnvelope::seal_with(&id, s, all[0].salt, all[0].nonce)
    })
    .unwrap()
    .0;
    let block = json!({
        "notes": notes(),
        "registrar": REGISTRAR,
        "identity": "keys.identity",
        "time": TIME,
        "cases": all.iter().map(|c| entry(&id, c)).collect::<Vec<_>>(),
        "decoy": decoy(),
        "rejects": rejects(&good),
        "open_rejects": open_rejects(&good),
        "put_rejects": put_rejects(&id, &good),
        "argon2id_rfc9106": argon2id_rfc9106(),
        "domains": { "envelope": envelope::DOMAIN, "put": envelope::PUT_DOMAIN },
    });
    upsert(obj_mut(&mut file), "envelope", from_json(&block), false);
    std::fs::write(PATH, render(&file)).unwrap();
}
