//! Device epochs in `vectors/identity-test-vectors.json`: a device
//! certificate carrying `epoch`, and the rejects whose `epoch` is 0 or
//! past the bound. The generator signs without this crate's signers; the
//! checks hold the crate to the bytes.
//!
//! Regenerate with
//! `cargo test -p hl-identity --test device_epoch -- --ignored generate`.

mod common;

use ed25519_dalek::{Signer, SigningKey};
use hl_identity::cbor::{self, map, Value};
use hl_identity::cert::EPOCH_MAX;
use hl_identity::{cert, DeviceCert, Error, IdentityKey};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

use common::json::{from_json, obj_mut, render, upsert, J};

const VECTORS: &str = include_str!("../vectors/identity-test-vectors.json");
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vectors/identity-test-vectors.json"
);
/// `device_cert_epoch`'s epoch.
const EPOCH: u64 = 3;

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

fn vectors() -> Json {
    serde_json::from_str(VECTORS).unwrap()
}

fn seed(name: &str) -> [u8; 32] {
    let b = match name {
        "identity" => 0x01,
        other => panic!("no seed for {other}"),
    };
    [b; 32]
}

fn input(domain: &str, body: &[u8]) -> Vec<u8> {
    [domain.as_bytes(), &[0], body].concat()
}

/// `unsigned` signed by `signer` under `domain`, and its vector entry.
fn signed(
    domain: &str,
    unsigned: Value,
    fields: Json,
    signer: &str,
    note: &str,
) -> (Json, Vec<u8>) {
    let body = cbor::encode(&unsigned);
    let sig_input = input(domain, &body);
    let s = SigningKey::from_bytes(&seed(signer)).sign(&sig_input);
    let Value::Map(mut entries) = unsigned else {
        unreachable!()
    };
    entries.push((
        Value::Text("sig".into()),
        Value::Bytes(s.to_bytes().to_vec()),
    ));
    let bytes = cbor::encode(&Value::Map(entries));
    let e = json!({
        "domain": domain,
        "fields": fields,
        "hash_hex": hex(&Sha256::digest(&bytes)),
        "note": note,
        "signature_hex": hex(&s.to_bytes()),
        "signature_input_hex": hex(&sig_input),
        "signed_hex": hex(&bytes),
        "unsigned_hex": hex(&body),
    });
    (e, bytes)
}

/// The `device_cert` vector's certificate with `epoch` written as given.
fn cert_with_epoch(old: &Json, epoch: u64, note: &str) -> (Json, Vec<u8>) {
    let f = &old["device_cert"]["fields"];
    let b = |k: &str| Value::Bytes(unhex(f[k].as_str().unwrap()));
    let u = |k: &str| Value::Uint(f[k].as_u64().unwrap());
    let unsigned = map(vec![
        ("v", Some(Value::Uint(1))),
        ("identity", Some(b("identity"))),
        ("device", Some(b("device"))),
        ("device_enc", Some(b("device_enc"))),
        ("issued", Some(u("issued"))),
        ("expires", Some(u("expires"))),
        ("caps", Some(u("caps"))),
        (
            "name",
            Some(Value::Text(f["name"].as_str().unwrap().into())),
        ),
        ("epoch", Some(Value::Uint(epoch))),
    ]);
    let mut fields = f.clone();
    fields["epoch"] = json!(epoch);
    signed(cert::DOMAIN, unsigned, fields, "identity", note)
}

fn put_reject(rejects: &mut Vec<J>, name: &str, object: &str, error: &str, bytes: &[u8]) {
    let reject = from_json(&json!({
        "error": error,
        "hex": hex(bytes),
        "name": name,
        "object": object,
    }));
    let named = |r: &J| matches!(r, J::Obj(e) if e.iter().any(|(k, v)| k == "name" && *v == J::Str(name.into())));
    match rejects.iter_mut().find(|r| named(r)) {
        Some(r) => *r = reject,
        None => rejects.push(reject),
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
    let old: Json = serde_json::from_str(&text).unwrap();
    let top = obj_mut(&mut file);
    for (name, epoch, note) in [
        ("device_cert_epoch", EPOCH, "`device_cert` issued in device epoch 3. Absent, `epoch` is 0, and 0 is never written. A floor of 4 or more refuses it; one of 3 or less does not."),
        ("device_cert_epoch_max", EPOCH_MAX, "`device_cert` in device epoch 2^63 - 1, the largest a reader accepts."),
    ] {
        upsert(top, name, from_json(&cert_with_epoch(&old, epoch, note).0), false);
    }

    let (_, rejects) = top.iter_mut().find(|(k, _)| k == "rejects").unwrap();
    let J::Arr(rejects) = rejects else {
        panic!("rejects is not an array")
    };
    for (name, epoch) in [
        ("device certificate with epoch 0 written", 0),
        ("device certificate with epoch 2^63", 1 << 63),
    ] {
        let bytes = cert_with_epoch(&old, epoch, "").1;
        put_reject(rejects, name, "device_cert", "BadField(\"epoch\")", &bytes);
    }
    std::fs::write(PATH, render(&file)).unwrap();
}

/// The bytes a vector entry states, held to its own fields.
fn check_entry(e: &Json, domain: &str, public: &[u8; 32]) -> Vec<u8> {
    let signed = unhex(e["signed_hex"].as_str().unwrap());
    let unsigned = unhex(e["unsigned_hex"].as_str().unwrap());
    let value = cbor::decode_canonical(&signed).unwrap();
    assert_eq!(cbor::encode(&value.without("sig")), unsigned);
    assert_eq!(
        unhex(e["signature_input_hex"].as_str().unwrap()),
        input(domain, &unsigned)
    );
    let sig: [u8; 64] = unhex(e["signature_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    hl_identity::keys::verify_domain(public, domain, &unsigned, &sig).unwrap();
    assert_eq!(
        unhex(e["hash_hex"].as_str().unwrap()),
        Sha256::digest(&signed).to_vec()
    );
    signed
}

#[test]
fn device_cert_epoch_vectors() {
    let v = vectors();
    for (name, epoch) in [
        ("device_cert_epoch", EPOCH),
        ("device_cert_epoch_max", EPOCH_MAX),
    ] {
        check_cert(&v[name], epoch);
    }
}

fn check_cert(e: &Json, epoch: u64) {
    let f = &e["fields"];
    let id = IdentityKey::from_seed(&seed("identity"));
    let signed = check_entry(e, cert::DOMAIN, &id.public());
    let dc = DeviceCert {
        identity: unhex32(f["identity"].as_str().unwrap()),
        device: unhex32(f["device"].as_str().unwrap()),
        device_enc: unhex32(f["device_enc"].as_str().unwrap()),
        issued: f["issued"].as_u64().unwrap(),
        expires: f["expires"].as_u64().unwrap(),
        caps: f["caps"].as_u64(),
        name: f["name"].as_str().map(str::to_owned),
        epoch: f["epoch"].as_u64().unwrap(),
    };
    assert_eq!(dc.epoch, epoch);
    assert_eq!(dc.sign(&id), signed);
    assert_eq!(DeviceCert::parse(&signed).unwrap(), dc);
}

#[test]
fn a_certificate_without_an_epoch_is_epoch_zero() {
    let v = vectors();
    let signed = unhex(v["device_cert"]["signed_hex"].as_str().unwrap());
    let old = DeviceCert::parse(&signed).unwrap();
    assert_eq!(old.epoch, 0);
    assert_eq!(old.check_floor(0), Ok(()));
    assert_eq!(old.check_floor(1), Err(Error::BelowFloor));
    // The same certificate but for its epoch.
    let new = DeviceCert::parse(&unhex(
        v["device_cert_epoch"]["signed_hex"].as_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(DeviceCert { epoch: 0, ..new }, old);
}
