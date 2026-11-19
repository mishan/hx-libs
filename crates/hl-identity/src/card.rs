//! The user card (`docs/hotline-ng-identity.md` §3.4).
//!
//! A card is the identity's public face: display name, icon, profile, and
//! the attestations it chooses to carry. Servers cache the exact bytes and
//! re-serve them; the `updated` field is the only thing that lets a newer
//! card replace an older one.

use std::collections::BTreeMap;

use crate::attestation::Attestation;
use crate::cbor::{map, Value};
use crate::error::Error;
use crate::keys::{IdentityKey, PublicKey};
use crate::signed::{self, Envelope, VERSION};

pub const DOMAIN: &str = "hl-identity/card/v1";

/// Encoded size limit (§3.4).
pub const MAX_BYTES: usize = 16 * 1024;
/// Display-name length limits in characters (§3.4).
pub const NAME_MAX_CHARS: usize = 32;
/// Profile text limit in bytes (§3.4).
pub const PROFILE_MAX_BYTES: usize = 2048;
/// How many attestations one card may embed (§3.4). Generous for a user
/// with several registrars, and a bound on what one card costs to
/// verify — the size limit alone allowed dozens.
pub const MAX_ATTESTATIONS: usize = 8;

/// Every key this version reads. Any other text key is [`Card::extra`].
const KNOWN: [&str; 11] = [
    "v",
    "identity",
    "updated",
    "name",
    "icon",
    "profile",
    "attestations",
    "vouches",
    "links",
    "successor",
    "sig",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub identity: PublicKey,
    pub updated: u64,
    /// Display name. Callers are expected to NFC-normalise before
    /// signing; this crate checks length and refuses invisible
    /// characters, but does not normalise, so two cards can carry
    /// visually identical names with different code points. §3.4 says
    /// so rather than requiring normalisation a verifier would have to
    /// perform on bytes it must re-serve unchanged. Servers that enforce
    /// reserved names should normalise on their side too.
    pub name: String,
    pub icon: Option<u64>,
    pub profile: Option<String>,
    /// Attestations that parsed and whose embedded signature verified
    /// against their embedded registrar key. Confirming the registrar key
    /// is the caller's job ([`Attestation::verify_registrar`]).
    pub attestations: Vec<Attestation>,
    /// Every attestation the card embeds, as signed and in order,
    /// including those of a `v` this version does not read: the array
    /// to hand [`Card::sign`] again, filtered as the caller means, so
    /// signing a card again keeps what a newer registrar issued. Only
    /// [`Card::attestations`] were verified; never count these.
    pub embedded_attestations: Vec<Value>,
    /// Vouch objects, unparsed — the federation spec defines them. Kept
    /// as values so a server that doesn't implement vouches can still
    /// re-serve the card byte-exactly (it already does; this is for
    /// callers that want to inspect them).
    pub vouches: Vec<Value>,
    pub links: Vec<String>,
    /// `SHA-256` of a successor identity public key the user has
    /// pre-committed to (threat model, "stolen identity key"). Once a
    /// card carries one, later cards for the same identity must carry
    /// the same value; servers refuse a card that changes it. Rotation
    /// to any other key is then refused wherever this card was cached,
    /// which is what makes the commitment worth anything: an attacker
    /// with the identity key can sign a new commitment but cannot make
    /// caches forget the old one.
    pub successor: Option<[u8; 32]>,
    /// Top-level text keys this version does not know, as signed
    /// (§3.1), so a card parsed and signed again keeps what a newer
    /// client added. A top-level key that is not text is not kept, so
    /// signing again drops it. A key [`Card`] has a field for is never
    /// written from here, and the card's size limit is the bound on what
    /// this holds.
    pub extra: BTreeMap<String, Value>,
}

impl Card {
    /// A minimal card: identity, name, and the time. Everything else is
    /// set by the caller before signing.
    pub fn new(identity: &IdentityKey, name: impl Into<String>, updated: u64) -> Self {
        Card {
            identity: identity.public(),
            updated,
            name: name.into(),
            icon: None,
            profile: None,
            attestations: Vec::new(),
            embedded_attestations: Vec::new(),
            vouches: Vec::new(),
            links: Vec::new(),
            successor: None,
            extra: BTreeMap::new(),
        }
    }

    /// Build the unsigned map. `attestations` must already be signed
    /// values (see [`Attestation::signed_value`]) because the card's
    /// signer usually isn't the registrar.
    fn unsigned(&self, attestations: Vec<Value>) -> Value {
        let fields = vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("updated", Some(Value::Uint(self.updated))),
            ("name", Some(Value::Text(self.name.clone()))),
            ("icon", self.icon.map(Value::Uint)),
            ("profile", self.profile.clone().map(Value::Text)),
            (
                "attestations",
                if attestations.is_empty() {
                    None
                } else {
                    Some(Value::Array(attestations))
                },
            ),
            (
                "vouches",
                if self.vouches.is_empty() {
                    None
                } else {
                    Some(Value::Array(self.vouches.clone()))
                },
            ),
            (
                "links",
                if self.links.is_empty() {
                    None
                } else {
                    Some(Value::Array(
                        self.links.iter().cloned().map(Value::Text).collect(),
                    ))
                },
            ),
            (
                "successor",
                self.successor.map(|s| Value::Bytes(s.to_vec())),
            ),
        ];
        // Every field's key, written or absent, so an empty field can't
        // be filled from `extra` either.
        let ours: Vec<&str> = fields.iter().map(|(k, _)| *k).chain(["sig"]).collect();
        let Value::Map(mut entries) = map(fields) else {
            unreachable!("map builds a map")
        };
        entries.extend(
            self.extra
                .iter()
                .filter(|(k, _)| !ours.contains(&k.as_str()))
                .map(|(k, v)| (Value::Text(k.clone()), v.clone())),
        );
        Value::Map(entries)
    }

    /// Sign with the identity key. `attestations` are the signed
    /// attestation objects to embed (the `attestations` field on `self`
    /// is ignored here, since parsed attestations have lost their
    /// signatures; so is `embedded_attestations`, which is what to pass
    /// to keep them all). Returns [`Error::TooLarge`] rather than a card no
    /// server will accept.
    pub fn sign(&self, identity: &IdentityKey, attestations: Vec<Value>) -> Result<Vec<u8>, Error> {
        // `assert!`, not `debug_assert!` (AGENTS.md): a wire invariant a
        // release build must not skip. Skipping it returns `Ok` holding a
        // card whose signature verifies against nothing.
        assert_eq!(
            identity.public(),
            self.identity,
            "signing a card with a key that is not its identity"
        );
        self.check_fields()?;
        if attestations.len() > MAX_ATTESTATIONS {
            return Err(Error::BadField("attestations"));
        }
        let bytes = signed::seal(self.unsigned(attestations), |body| {
            identity.sign(DOMAIN, body)
        });
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        // `extra` and `vouches` are the caller's values, and one nested
        // too deep or holding a duplicate key encodes to a card `parse`
        // refuses.
        crate::cbor::decode_canonical(&bytes)?;
        Ok(bytes)
    }

    fn check_fields(&self) -> Result<(), Error> {
        let chars = self.name.chars().count();
        if chars == 0 || chars > NAME_MAX_CHARS {
            return Err(Error::BadField("name"));
        }
        // A name is what a person is called, so it has to contain
        // something: `"   "` passed every other check here — the space is
        // exempt from the invisible table because "Alice Anderson" needs
        // it — and became a blank row in every user list, or an account
        // name on a server with `new_accounts = create`. Leading and
        // trailing space go for the same reason `admin ` beside `admin`
        // is a spoof.
        //
        // A display name sits next to handles and logins in every
        // client; the same invisible characters that spoof a handle
        // spoof it (§3.4).
        if !crate::names::is_shown_name(&self.name) {
            return Err(Error::BadField("name"));
        }
        if self
            .profile
            .as_ref()
            .is_some_and(|p| p.len() > PROFILE_MAX_BYTES)
        {
            return Err(Error::BadField("profile"));
        }
        Ok(())
    }

    /// Decode, check size and fields, verify the card signature against
    /// the embedded identity key, then parse each attestation.
    ///
    /// The card's own envelope is verified *first*, and its own fields
    /// are read and checked before any attestation's signature is.
    /// Verifying the attestations first meant a card with a garbage
    /// signature and ~55 self-signed attestations cost ~57 Ed25519
    /// verifications to reject, which is a cheap way to spend a server's
    /// CPU; checking them before the name meant a card that fails on its
    /// name still bought `MAX_ATTESTATIONS` of them. One signature says
    /// whether the rest is worth looking at, and the free checks come
    /// before the paid ones.
    ///
    /// An attestation this version can't read is left out of
    /// `attestations`, unverified, rather than failing the card
    /// (§5.2 step 5): a registrar that starts issuing v2
    /// attestations would otherwise lock its users out of every v1
    /// server. One that parses but doesn't verify, or that is about a
    /// different identity, still fails the card — the signer embedded it;
    /// the identity check happens before that attestation's signature is
    /// looked at, for the same reason the card's envelope comes first.
    pub fn parse(bytes: &[u8]) -> Result<Card, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let identity: PublicKey = signed::bytes32(v, "identity")?;
        env.verify(&identity, DOMAIN)?;

        // Everything that costs no signature check first: the count,
        // the card's own required fields, and (inside `from_value`)
        // whose attestation this is. A 16 KiB card fits dozens of
        // minimal attestations, so a card that verifies its own envelope
        // and then fails could otherwise buy an Ed25519 verification per
        // attestation with one unauthenticated request — and a card with
        // a 33-character name is going to fail either way.
        let embedded = signed::opt_array(v, "attestations")?;
        if embedded.len() > MAX_ATTESTATIONS {
            return Err(Error::BadField("attestations"));
        }
        let links = signed::opt_array(v, "links")?
            .into_iter()
            .map(|l| match l {
                Value::Text(s) => Ok(s),
                _ => Err(Error::BadField("links")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut card = Card {
            identity,
            updated: signed::uint(v, "updated")?,
            name: signed::text(v, "name")?,
            icon: signed::opt_uint(v, "icon")?,
            profile: signed::opt_text(v, "profile")?,
            attestations: Vec::new(),
            embedded_attestations: embedded.clone(),
            vouches: signed::opt_array(v, "vouches")?,
            links,
            successor: signed::opt_bytes32(v, "successor")?,
            extra: unknown(v),
        };
        card.check_fields()?;
        for value in embedded {
            match Attestation::from_value(value, &identity) {
                Ok(a) => card.attestations.push(a),
                Err(Error::UnsupportedVersion(v)) => {
                    // Not ours to read; the card is still the user's.
                    let _ = v;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(card)
    }
}

/// The text keys of `v` this version does not know. A key that is not
/// text names nothing §3.4 could define, and is not kept.
fn unknown(v: &Value) -> BTreeMap<String, Value> {
    let Value::Map(entries) = v else {
        return BTreeMap::new();
    };
    entries
        .iter()
        .filter_map(|(k, v)| match k {
            Value::Text(k) if !KNOWN.contains(&k.as_str()) => Some((k.clone(), v.clone())),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ServerKey;

    #[test]
    fn round_trip_with_attestation() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let att = Attestation {
            identity: id.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "alice".into(),
            registered: 1_600_000_000,
            issued: 1_700_000_000,
            expires: 1_800_000_000,
            level: None,
        };
        let mut card = Card::new(&id, "Alice", 1_700_000_001);
        card.icon = Some(128);
        card.profile = Some("hxd-ng".into());
        card.links = vec!["https://alice.example.com".into()];
        card.vouches = vec![map(vec![("v", Some(Value::Uint(1)))])];
        card.successor = Some([0x5a; 32]);
        card.extra.insert("future".into(), Value::Uint(42));
        let bytes = card.sign(&id, vec![att.signed_value(&reg)]).unwrap();
        card.embedded_attestations = vec![att.signed_value(&reg)];
        card.attestations = vec![att];
        assert_eq!(Card::parse(&bytes).unwrap(), card);
    }

    #[test]
    fn successor_round_trips() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let mut card = Card::new(&id, "Alice", 10);
        card.successor = Some([0x5a; 32]);
        let back = Card::parse(&card.sign(&id, vec![]).unwrap()).unwrap();
        assert_eq!(back.successor, Some([0x5a; 32]));
    }

    #[test]
    fn attestation_for_another_identity_is_rejected() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let other = IdentityKey::from_seed(&[2u8; 32]);
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let att = Attestation {
            identity: other.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "someone".into(),
            registered: 1,
            issued: 2,
            expires: 3,
            level: None,
        };
        let card = Card::new(&id, "Alice", 10);
        let bytes = card.sign(&id, vec![att.signed_value(&reg)]).unwrap();
        assert_eq!(Card::parse(&bytes), Err(Error::KeyMismatch));
    }

    /// Alice's attestation, as signed and as a newer registrar might
    /// issue it.
    fn known_and_newer(id: &IdentityKey) -> (Attestation, Value, Value) {
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let att = Attestation {
            identity: id.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "alice".into(),
            registered: 1_600_000_000,
            issued: 1_700_000_000,
            expires: 1_800_000_000,
            level: None,
        };
        // Take the signed attestation and bump its `v`; the signature no
        // longer matches, but the version check comes first.
        let crate::cbor::Value::Map(mut entries) = att.signed_value(&reg) else {
            panic!("attestations are maps")
        };
        for (k, v) in &mut entries {
            if *k == crate::cbor::Value::Text("v".into()) {
                *v = crate::cbor::Value::Uint(2);
            }
        }
        let future = crate::cbor::Value::Map(entries);
        let known = att.signed_value(&reg);
        (att, known, future)
    }

    #[test]
    fn an_attestation_this_version_cannot_read_is_kept_not_counted() {
        // §5.2 step 5. A registrar that starts issuing v2 attestations
        // would otherwise lock its users out of every v1 server, and a
        // client signing the card again would strip them.
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let (att, known, newer) = known_and_newer(&id);
        for embedded in [
            vec![known.clone(), newer.clone()],
            vec![newer.clone(), known.clone()],
        ] {
            let bytes = Card::new(&id, "Alice", 10)
                .sign(&id, embedded.clone())
                .unwrap();
            let back = Card::parse(&bytes).unwrap();
            assert_eq!(
                back.attestations,
                vec![att.clone()],
                "the v1 one alone counts"
            );
            assert_eq!(back.embedded_attestations, embedded);
            let again = back.sign(&id, back.embedded_attestations.clone());
            assert_eq!(again.unwrap(), bytes);
        }
    }

    /// `newer` with its entries in reverse order: another `Value`, the
    /// same encoding.
    fn reversed(newer: &Value) -> Value {
        let Value::Map(entries) = newer else {
            unreachable!("attestations are maps")
        };
        Value::Map(entries.iter().rev().cloned().collect())
    }

    #[test]
    fn an_unread_attestation_passed_again_is_embedded_once() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let (_, known, newer) = known_and_newer(&id);
        let bytes = Card::new(&id, "Alice", 10)
            .sign(&id, vec![known.clone(), newer.clone()])
            .unwrap();
        let again = Card::parse(&bytes)
            .unwrap()
            .sign(&id, vec![known, reversed(&newer)])
            .unwrap();
        assert_eq!(again, bytes);
    }

    /// Alice's attestation for `handle`, as a v1 registrar signs it.
    fn issued(id: &IdentityKey, handle: &str, issued: u64) -> Value {
        let reg = ServerKey::from_seed(&[3u8; 32]);
        Attestation {
            identity: id.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: handle.into(),
            registered: 1_600_000_000,
            issued,
            expires: 1_800_000_000,
            level: None,
        }
        .signed_value(&reg)
    }

    #[test]
    fn a_renewed_handle_leaves_no_unread_attestation_behind() {
        // As a client renews one: every embedded attestation as signed,
        // less any for the handle, then the fresh one, up to the cap.
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let (_, _, newer) = known_and_newer(&id);
        let fresh = issued(&id, "alice", 1_750_000_000);
        let others: Vec<Value> = (1..MAX_ATTESTATIONS)
            .map(|n| issued(&id, &format!("alt{n}"), 1_700_000_000))
            .collect();
        for others in [vec![], others] {
            let embedded = [vec![newer.clone()], others.clone()].concat();
            let card = Card::new(&id, "Alice", 10).sign(&id, embedded).unwrap();
            let card = Card::parse(&card).unwrap();
            let mut renewed = card.embedded_attestations.clone();
            renewed.retain(|v| v.get("handle") != Some(&Value::Text("alice".into())));
            renewed.push(fresh.clone());
            let again = Card::parse(&card.sign(&id, renewed.clone()).unwrap()).unwrap();
            assert_eq!(
                again.embedded_attestations,
                renewed,
                "{} others",
                others.len()
            );
        }
    }

    #[test]
    fn the_cards_own_signature_is_checked_before_the_attestations() {
        // A garbage-signature card with 50 attestations should cost one
        // verification to reject, not 51.
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let att = Attestation {
            identity: id.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "alice".into(),
            registered: 1_600_000_000,
            issued: 1_700_000_000,
            expires: 1_800_000_000,
            level: None,
        };
        // Each embedded attestation is fine; the card's own sig is not.
        let atts: Vec<_> = (0..8).map(|_| att.signed_value(&reg)).collect();
        let mut bytes = Card::new(&id, "Alice", 10).sign(&id, atts).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xff;
        assert_eq!(Card::parse(&bytes), Err(Error::BadSignature));
    }

    #[test]
    fn a_card_may_not_buy_verifications_with_attestations() {
        // The card's envelope verifies, so the loop is reached — and
        // everything that costs nothing is checked first: how many, and
        // whose. Both used to be decided after every embedded signature
        // had been verified, and a 16 KiB card holds dozens.
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let other = IdentityKey::from_seed(&[7u8; 32]);
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let att = |about: &IdentityKey| Attestation {
            identity: about.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "alice".into(),
            registered: 1_600_000_000,
            issued: 1_700_000_000,
            expires: 1_800_000_000,
            level: None,
        };
        let many: Vec<_> = (0..MAX_ATTESTATIONS + 1)
            .map(|_| att(&id).signed_value(&reg))
            .collect();
        assert_eq!(
            Card::new(&id, "Alice", 10).sign(&id, many.clone()).err(),
            Some(Error::BadField("attestations"))
        );
        // Signing one anyway — an attacker signs their own card — is
        // refused on the way in, which is the side that matters.
        let over = signed::seal(Card::new(&id, "Alice", 10).unsigned(many), |body| {
            id.sign(DOMAIN, body)
        });
        assert_eq!(
            Card::parse(&over).err(),
            Some(Error::BadField("attestations"))
        );

        // Signed by a real registrar, but about someone else.
        let bytes = Card::new(&id, "Alice", 10)
            .sign(&id, vec![att(&other).signed_value(&reg)])
            .unwrap();
        assert_eq!(Card::parse(&bytes), Err(Error::KeyMismatch));
    }

    #[test]
    fn a_display_name_may_not_hide_characters() {
        // `admin\u{200b}` renders as `admin` — the card's name sits next
        // to logins and handles in every client that shows one.
        let id = IdentityKey::from_seed(&[1u8; 32]);
        // Space is exempt from the table ("Alice Anderson"), so it is
        // refused separately: a name of nothing but spaces is a blank
        // row in every user list, and a trailing one is `admin ` next
        // to `admin`.
        for name in [
            "admin\u{200b}",
            "ad\u{202e}min",
            "alice\u{feff}",
            " ",
            "   ",
            "admin ",
            " admin",
        ] {
            assert_eq!(
                Card::new(&id, name, 10).sign(&id, vec![]),
                Err(Error::BadField("name")),
                "{name:?}"
            );
        }
        assert!(Card::new(&id, "Alice Anderson", 10)
            .sign(&id, vec![])
            .is_ok());
    }

    #[test]
    fn the_cards_own_fields_are_checked_before_any_attestation() {
        // Ordering, pinned: a card that fails on its own name must not
        // first buy `MAX_ATTESTATIONS` signature verifications. The
        // attestations here are garbage-signed, so *if* they were
        // verified first the error would be theirs; the name's error is
        // the assertion.
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let att = Attestation {
            identity: id.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "alice".into(),
            registered: 10,
            issued: 20,
            expires: 30,
            level: None,
        };
        let mut signed = att.signed_value(&reg);
        // Corrupt the signature so verifying it would fail.
        if let Value::Map(entries) = &mut signed {
            for (k, v) in entries.iter_mut() {
                if k == &Value::Text("sig".into()) {
                    *v = Value::Bytes(vec![0u8; 64]);
                }
            }
        }
        let mut card = Card::new(&id, "x".repeat(NAME_MAX_CHARS + 1), 10);
        card.updated = 10;
        let bytes = signed::seal(
            card.unsigned(vec![signed.clone(), signed.clone()]),
            |body| id.sign(DOMAIN, body),
        );
        assert_eq!(
            Card::parse(&bytes),
            Err(Error::BadField("name")),
            "the free checks come before the paid ones"
        );
    }

    /// Alice's card as a newer client signed it, with a key this
    /// version does not know.
    fn with_future_key(id: &IdentityKey) -> Vec<u8> {
        let Value::Map(mut entries) = Card::new(id, "Alice", 10).unsigned(vec![]) else {
            unreachable!()
        };
        entries.push((
            Value::Text("future".into()),
            map(vec![("n", Some(Value::Uint(42)))]),
        ));
        signed::seal(Value::Map(entries), |b| id.sign(DOMAIN, b))
    }

    #[test]
    fn an_unknown_key_survives_signing_again() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let bytes = with_future_key(&id);
        let again = Card::parse(&bytes).unwrap().sign(&id, vec![]).unwrap();
        assert_eq!(again, bytes);
    }

    #[test]
    fn unknown_fields_are_kept_and_signed() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let mut bytes = with_future_key(&id);
        let mut expect = Card::new(&id, "Alice", 10);
        expect
            .extra
            .insert("future".into(), map(vec![("n", Some(Value::Uint(42)))]));
        assert_eq!(Card::parse(&bytes).unwrap(), expect);
        // The key, then `{"n": 42}`: a map head, "n", and 42's two bytes.
        let at = bytes.windows(6).position(|w| w == b"future").unwrap() + 6 + 4;
        assert_eq!(bytes[at], 42);
        bytes[at] = 43;
        assert_eq!(Card::parse(&bytes), Err(Error::BadSignature));
    }

    #[test]
    fn a_known_key_cannot_ride_in_extra() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let mut card = Card::new(&id, "Alice", 10);
        for (k, v) in [
            ("name", Value::Text("Mallory".into())),
            ("icon", Value::Uint(1)),
            ("v", Value::Uint(2)),
            ("sig", Value::Bytes(vec![0; 64])),
        ] {
            card.extra.insert(k.into(), v);
        }
        let back = Card::parse(&card.sign(&id, vec![]).unwrap()).unwrap();
        assert_eq!(back, Card::new(&id, "Alice", 10));
    }

    #[test]
    fn a_card_parse_would_refuse_is_not_signed() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let twice = Value::Map(vec![
            (Value::Text("a".into()), Value::Uint(1)),
            (Value::Text("a".into()), Value::Uint(2)),
        ]);
        let deep = (0..9).fold(Value::Uint(0), |v, _| Value::Array(vec![v]));
        for (value, error) in [
            (twice, crate::cbor::CborError::NotCanonical),
            (deep, crate::cbor::CborError::TooDeep),
        ] {
            let mut card = Card::new(&id, "Alice", 10);
            card.extra.insert("future".into(), value);
            assert_eq!(card.sign(&id, vec![]), Err(Error::Cbor(error)));
        }
    }

    #[test]
    fn size_and_name_limits() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let card = Card::new(&id, "", 10);
        assert_eq!(card.sign(&id, vec![]), Err(Error::BadField("name")));
        let card = Card::new(&id, "x".repeat(33), 10);
        assert_eq!(card.sign(&id, vec![]), Err(Error::BadField("name")));
        let mut card = Card::new(&id, "Alice", 10);
        card.profile = Some("p".repeat(PROFILE_MAX_BYTES + 1));
        assert_eq!(card.sign(&id, vec![]), Err(Error::BadField("profile")));
        let mut card = Card::new(&id, "Alice", 10);
        card.links = (0..600)
            .map(|i| format!("https://example.com/{i:030}"))
            .collect();
        assert_eq!(card.sign(&id, vec![]), Err(Error::TooLarge));
    }
}
