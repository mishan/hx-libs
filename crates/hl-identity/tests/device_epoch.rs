//! Device epochs in `vectors/identity-test-vectors.json`: a device
//! certificate carrying `epoch`, the device epoch record, a per-identity
//! list carrying it, a device revocation signed by a device in epoch 1,
//! and the rejects. The generator signs without this crate's signers; the
//! checks hold the crate to the bytes.
//!
//! Regenerate with
//! `cargo test -p hl-identity --test device_epoch -- --ignored generate`.

mod common;

use ed25519_dalek::{Signer, SigningKey};
use hl_identity::cbor::{self, map, Value};
use hl_identity::cert::EPOCH_MAX;
use hl_identity::registrar::{DEVICE_EPOCH_DOMAIN, RECORDS_DOMAIN, REVOKE_DEVICE_DOMAIN};
use hl_identity::{
    cert, DeviceCert, DeviceEpoch, DeviceKey, DeviceRevocation, Error, IdentityKey, ListKind,
    Record, RegistrarKeys, ServerKey, SignedList,
};
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
/// `device_epoch`'s floor, which revokes `device_cert` and
/// `device_cert_epoch` both.
const FLOOR: u64 = 4;
/// `device_epoch`'s time, after every record in `records`.
const RESET: u64 = 1_757_203_270;
/// The epoch of `revoke_device_by_epoch_device`'s signer.
const SIGNER_EPOCH: u64 = 1;
/// The seq `records_device_epoch` gives `device_epoch`.
const SEQ: u64 = 7;

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
        "device" => 0x02,
        "registrar" => 0x03,
        other => panic!("no seed for {other}"),
    };
    [b; 32]
}

fn pk(name: &str) -> [u8; 32] {
    SigningKey::from_bytes(&seed(name))
        .verifying_key()
        .to_bytes()
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

/// keys.identity's device epoch record: `epoch`, and `extra` keys beside
/// it, signed by `signer`.
fn device_epoch(
    epoch: u64,
    extra: Vec<(&str, Option<Value>)>,
    signer: &str,
    note: &str,
) -> (Json, Vec<u8>) {
    let mut entries = vec![
        ("v", Some(Value::Uint(1))),
        ("identity", Some(Value::Bytes(pk("identity").to_vec()))),
        ("epoch", Some(Value::Uint(epoch))),
        ("time", Some(Value::Uint(RESET))),
    ];
    entries.extend(extra);
    let fields = json!({
        "epoch": epoch,
        "identity": hex(&pk("identity")),
        "time": RESET,
        "v": 1,
    });
    let (mut e, bytes) = signed(DEVICE_EPOCH_DOMAIN, map(entries), fields, signer, note);
    e["signer"] = json!(signer);
    (e, bytes)
}

/// `revoke_device_by_device` signed by keys.device with a certificate
/// issued in epoch 1, otherwise the one that vector carries.
fn revocation_by_epoch_device(old: &Json) -> (Json, Vec<u8>) {
    let f = &old["revoke_device_by_device"]["fields"];
    let old_cert = cbor::decode_canonical(&unhex(f["signer_cert"].as_str().unwrap())).unwrap();
    let Value::Map(mut cert) = old_cert.without("sig") else {
        unreachable!()
    };
    cert.push((Value::Text("epoch".into()), Value::Uint(SIGNER_EPOCH)));
    let cert = signed(cert::DOMAIN, Value::Map(cert), json!({}), "identity", "").1;
    let b = |k: &str| Value::Bytes(unhex(f[k].as_str().unwrap()));
    let u = |k: &str| Value::Uint(f[k].as_u64().unwrap());
    let unsigned = map(vec![
        ("v", Some(Value::Uint(1))),
        ("identity", Some(b("identity"))),
        ("device", Some(b("device"))),
        ("time", Some(u("time"))),
        ("until", Some(u("until"))),
        ("reason", Some(u("reason"))),
        ("signer", Some(b("signer"))),
        ("signer_cert", Some(Value::Bytes(cert.clone()))),
    ]);
    let mut fields = f.clone();
    fields["signer_cert"] = json!(hex(&cert));
    signed(
        REVOKE_DEVICE_DOMAIN,
        unsigned,
        fields,
        "device",
        "`revoke_device_by_device` with a `signer_cert` issued in device epoch 1, its `time` inside that certificate's window. A reader holding a floor of 2 or more for keys.identity ignores it whatever its `time`; at a floor of 1 or less it stands.",
    )
}

/// keys.identity's per-identity list carrying `device_epoch` alone.
fn records_with(record: &[u8]) -> (Json, Vec<u8>) {
    let fp: [u8; 32] = Sha256::digest(pk("identity")).into();
    let unsigned = map(vec![
        ("v", Some(Value::Uint(1))),
        ("registrar", Some(Value::Text("hl.example".into()))),
        ("issued", Some(Value::Uint(RESET + 30))),
        ("expires", Some(Value::Uint(RESET + 30 + 3600))),
        ("fingerprint", Some(Value::Bytes(fp.to_vec()))),
        (
            "entries",
            Some(Value::Array(vec![Value::Array(vec![
                Value::Uint(SEQ),
                Value::Bytes(record.to_vec()),
            ])])),
        ),
    ]);
    let fields = json!({
        "entries": [[SEQ, hex(record)]],
        "expires": RESET + 30 + 3600,
        "fingerprint": hex(&fp),
        "issued": RESET + 30,
        "registrar": "hl.example",
        "v": 1,
    });
    signed(
        RECORDS_DOMAIN,
        unsigned,
        fields,
        "registrar",
        "keys.identity's per-identity list carrying `device_epoch`, signed by keys.registrar. An identity has at most one device epoch record in a list: a higher one replaces it.",
    )
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
    let device = Some(Value::Bytes(pk("device").to_vec()));
    for (name, error, bytes) in [
        (
            "device epoch record with epoch 0",
            "BadField(\"epoch\")",
            device_epoch(0, vec![], "identity", "").1,
        ),
        (
            "device epoch record signed by a device key",
            "BadSignature",
            device_epoch(FLOOR, vec![], "device", "").1,
        ),
        (
            "device epoch record carrying device",
            "BadField(\"device\")",
            device_epoch(FLOOR, vec![("device", device)], "identity", "").1,
        ),
    ] {
        put_reject(rejects, name, "device_epoch", error, &bytes);
    }
    let (record, record_bytes) = device_epoch(FLOOR, vec![], "identity", "keys.identity's device epoch record: every device certificate of keys.identity whose `epoch` is below 4 is revoked, `device_cert` (absent, so 0) and `device_cert_epoch` (3) among them. Signed by the identity key; a device signature is never valid on it. A reader from before this record reads it as an identity revocation, whose signature fails, and skips it.");
    upsert(top, "device_epoch", from_json(&record), false);
    let max = device_epoch(EPOCH_MAX, vec![], "identity", "`device_epoch` at 2^63 - 1, the largest a reader accepts. It revokes every certificate of keys.identity but one in that same epoch, such as `device_cert_epoch_max`.");
    upsert(top, "device_epoch_max", from_json(&max.0), false);
    upsert(
        top,
        "records_device_epoch",
        from_json(&records_with(&record_bytes).0),
        false,
    );
    upsert(
        top,
        "revoke_device_by_epoch_device",
        from_json(&revocation_by_epoch_device(&old).0),
        false,
    );
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

#[test]
fn device_epoch_vectors() {
    let v = vectors();
    let cert =
        |name: &str| DeviceCert::parse(&unhex(v[name]["signed_hex"].as_str().unwrap())).unwrap();
    let id = IdentityKey::from_seed(&seed("identity"));
    for (name, epoch) in [("device_epoch", FLOOR), ("device_epoch_max", EPOCH_MAX)] {
        let e = &v[name];
        let f = &e["fields"];
        assert_eq!(e["signer"], "identity");
        let signed = check_entry(e, DEVICE_EPOCH_DOMAIN, &id.public());
        let r = DeviceEpoch {
            identity: unhex32(f["identity"].as_str().unwrap()),
            epoch: f["epoch"].as_u64().unwrap(),
            time: f["time"].as_u64().unwrap(),
        };
        assert_eq!(r.epoch, epoch);
        assert_eq!(r.sign(&id).unwrap(), signed);
        assert_eq!(DeviceEpoch::parse(&signed).unwrap(), r);
        assert_eq!(
            Record::parse(&signed, None).unwrap(),
            Record::DeviceEpoch(r.clone())
        );
        for c in ["device_cert", "device_cert_epoch"] {
            assert!(r.revokes(&cert(c)), "{name} {c}");
        }
        assert!(!r.revokes(&cert("device_cert_epoch_max")), "{name}");
    }
}

#[test]
fn device_epoch_rejects_fail_as_records_too() {
    let v = vectors();
    for (name, error) in [
        ("device epoch record with epoch 0", Error::BadField("epoch")),
        (
            "device epoch record signed by a device key",
            Error::BadSignature,
        ),
    ] {
        let r = v["rejects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap();
        let bytes = unhex(r["hex"].as_str().unwrap());
        assert_eq!(Record::parse(&bytes, None), Err(error), "{name}");
    }
}

#[test]
fn records_device_epoch_vector() {
    let v = vectors();
    let e = &v["records_device_epoch"];
    let reg = ServerKey::from_seed(&seed("registrar"));
    let signed = check_entry(e, RECORDS_DOMAIN, &reg.public());
    let keys = [reg.public()];
    let rk = RegistrarKeys {
        host: "hl.example",
        keys: &keys,
    };
    let list = SignedList::parse(&signed, ListKind::Records, rk).unwrap();
    assert_eq!(list.sign(ListKind::Records, &reg), signed);
    let id = IdentityKey::from_seed(&seed("identity"));
    assert_eq!(list.fingerprint, Some(id.fingerprint().0));
    let record = unhex(v["device_epoch"]["signed_hex"].as_str().unwrap());
    assert_eq!(list.entries, vec![(SEQ, record.clone())]);
    assert_eq!(
        Record::parse(&record, Some(rk)).unwrap(),
        Record::DeviceEpoch(DeviceEpoch::parse(&record).unwrap())
    );
}

#[test]
fn a_device_below_the_floor_revokes_nothing() {
    let v = vectors();
    let e = &v["revoke_device_by_epoch_device"];
    let f = &e["fields"];
    let dev = DeviceKey::from_seed(&seed("device"));
    let signed = check_entry(e, REVOKE_DEVICE_DOMAIN, &dev.public());
    let cert_bytes = unhex(f["signer_cert"].as_str().unwrap());
    let r = DeviceRevocation {
        identity: unhex32(f["identity"].as_str().unwrap()),
        device: unhex32(f["device"].as_str().unwrap()),
        time: f["time"].as_u64().unwrap(),
        until: f["until"].as_u64().unwrap(),
        reason: f["reason"].as_u64(),
        signer: None,
        signer_cert: None,
    };
    assert_eq!(r.sign_as_device(&dev, cert_bytes.clone()).unwrap(), signed);
    let Record::RevokeDevice(back) = Record::parse(&signed, None).unwrap() else {
        panic!("not a device revocation")
    };
    let cert = DeviceCert::parse(&cert_bytes).unwrap();
    assert!((cert.issued..=cert.expires).contains(&back.time));
    assert_eq!(back.signer_epoch(), Some(SIGNER_EPOCH));
    assert_eq!(back.check_signer_floor(SIGNER_EPOCH), Ok(()));
    assert_eq!(
        back.check_signer_floor(SIGNER_EPOCH + 1),
        Err(Error::BelowFloor)
    );

    // One the identity signed is never below a floor.
    let by_id = unhex(v["revoke_device"]["signed_hex"].as_str().unwrap());
    let by_id = DeviceRevocation::parse(&by_id).unwrap();
    assert_eq!(by_id.signer_epoch(), None);
    assert_eq!(by_id.check_signer_floor(u64::MAX), Ok(()));
}
