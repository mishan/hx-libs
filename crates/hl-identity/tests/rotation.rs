//! The rotation carrying its successor's first commitment, `next`, in
//! `vectors/identity-test-vectors.json`: `rotate_next`, and the rejects
//! whose `next` commits back to either key. The generator signs without
//! this crate's signers; the check holds the crate to the bytes.
//!
//! Regenerate with
//! `cargo test -p hl-identity --test rotation -- --ignored generate`.

mod common;

use ed25519_dalek::{Signer, SigningKey};
use hl_identity::cbor::{self, map, Value};
use hl_identity::registrar::ROTATE_DOMAIN;
use hl_identity::{IdentityKey, Record, Rotation};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

use common::json::{from_json, obj_mut, render, upsert, J};

const VECTORS: &str = include_str!("../vectors/identity-test-vectors.json");
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vectors/identity-test-vectors.json"
);
/// `rotate`'s time.
const ROTATED: u64 = 1_757_203_240;

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

fn seed(name: &str) -> [u8; 32] {
    let b = match name {
        "identity" => 0x01,
        "successor" => 0x04,
        "successor_successor" => 0x09,
        other => panic!("no seed for {other}"),
    };
    [b; 32]
}

fn pk(name: &str) -> [u8; 32] {
    SigningKey::from_bytes(&seed(name))
        .verifying_key()
        .to_bytes()
}

fn fp(name: &str) -> [u8; 32] {
    Sha256::digest(pk(name)).into()
}

fn input(domain: &str, body: &[u8]) -> Vec<u8> {
    [domain.as_bytes(), &[0], body].concat()
}

/// keys.identity rotating to keys.successor, committing it to `next`.
fn rotation(next: &str) -> (Json, Vec<u8>) {
    let unsigned = map(vec![
        ("v", Some(Value::Uint(1))),
        ("identity", Some(Value::Bytes(pk("identity").to_vec()))),
        ("successor", Some(Value::Bytes(pk("successor").to_vec()))),
        ("time", Some(Value::Uint(ROTATED))),
        ("next", Some(Value::Bytes(fp(next).to_vec()))),
    ]);
    let body = cbor::encode(&unsigned);
    let sig_input = input(ROTATE_DOMAIN, &body);
    let ack_input = input(&format!("{ROTATE_DOMAIN}/ack"), &body);
    let s = SigningKey::from_bytes(&seed("identity")).sign(&sig_input);
    let a = SigningKey::from_bytes(&seed("successor")).sign(&ack_input);
    let Value::Map(mut entries) = unsigned else {
        unreachable!()
    };
    for (k, b) in [("sig", s), ("ack", a)] {
        entries.push((Value::Text(k.into()), Value::Bytes(b.to_bytes().to_vec())));
    }
    let bytes = cbor::encode(&Value::Map(entries));
    let e = json!({
        "ack_hex": hex(&a.to_bytes()),
        "ack_input_hex": hex(&ack_input),
        "domain": ROTATE_DOMAIN,
        "fields": {
            "identity": hex(&pk("identity")),
            "next": hex(&fp(next)),
            "successor": hex(&pk("successor")),
            "time": ROTATED,
            "v": 1,
        },
        "note": "`rotate` with `next`: SHA-256 of keys.successor_successor, the successor's first commitment, under both signatures. Absent, the rotation commits to nothing. A `next` equal to SHA-256 of `identity` or of `successor` is refused.",
        "signature_hex": hex(&s.to_bytes()),
        "signature_input_hex": hex(&sig_input),
        "signed_hex": hex(&bytes),
        "unsigned_hex": hex(&body),
    });
    (e, bytes)
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
    let top = obj_mut(&mut file);
    upsert(
        top,
        "rotate_next",
        from_json(&rotation("successor_successor").0),
        false,
    );

    let (_, rejects) = top.iter_mut().find(|(k, _)| k == "rejects").unwrap();
    let J::Arr(rejects) = rejects else {
        panic!("rejects is not an array")
    };
    for (name, next) in [
        ("rotation whose next commits to the predecessor", "identity"),
        (
            "rotation whose next commits to the successor itself",
            "successor",
        ),
    ] {
        let reject = from_json(&json!({
            "error": "BadField(\"next\")",
            "hex": hex(&rotation(next).1),
            "name": name,
            "object": "rotate",
        }));
        let named = |r: &J| matches!(r, J::Obj(e) if e.iter().any(|(k, v)| k == "name" && *v == J::Str(name.into())));
        match rejects.iter_mut().find(|r| named(r)) {
            Some(r) => *r = reject,
            None => rejects.push(reject),
        }
    }
    std::fs::write(PATH, render(&file)).unwrap();
}

#[test]
fn rotate_next_vector() {
    let v: Json = serde_json::from_str(VECTORS).unwrap();
    let e = &v["rotate_next"];
    let f = &e["fields"];
    let r = Rotation {
        identity: unhex32(f["identity"].as_str().unwrap()),
        successor: unhex32(f["successor"].as_str().unwrap()),
        time: f["time"].as_u64().unwrap(),
        next: Some(unhex32(f["next"].as_str().unwrap())),
    };
    assert_eq!(r.next, Some(fp("successor_successor")));
    let signed = unhex(e["signed_hex"].as_str().unwrap());
    let pred = IdentityKey::from_seed(&seed("identity"));
    let succ = IdentityKey::from_seed(&seed("successor"));
    assert_eq!(r.sign(&pred, &succ).unwrap(), signed);
    assert_eq!(Rotation::parse(&signed).unwrap(), r);
    assert_eq!(Record::parse(&signed, None).unwrap(), Record::Rotate(r));
    let unsigned = unhex(e["unsigned_hex"].as_str().unwrap());
    let value = cbor::decode_canonical(&signed).unwrap();
    assert_eq!(cbor::encode(&value.without("sig").without("ack")), unsigned);
    assert_eq!(
        unhex(e["signature_input_hex"].as_str().unwrap()),
        input(ROTATE_DOMAIN, &unsigned)
    );
    assert_eq!(
        unhex(e["ack_input_hex"].as_str().unwrap()),
        input(&format!("{ROTATE_DOMAIN}/ack"), &unsigned)
    );
}
