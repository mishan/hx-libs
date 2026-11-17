//! The successor code's vectors in `vectors/identity-test-vectors.json`:
//! seeds and the codes they are written down as, each with the commitment
//! a card makes to it and what typing one off paper may do to it and still
//! read back; what reads as no code at all; and the misreadings a reader
//! holding the commitment mends. Regenerate with
//! `cargo test -p hl-identity --test successor -- --ignored generate`.

mod common;

use hl_identity::{Fingerprint, IdentityKey, SuccessorCode};
use serde_json::{json, Value as Json};

use common::json::{from_json, obj_mut, render, upsert, J};

const VECTORS: &str = include_str!("../vectors/identity-test-vectors.json");
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vectors/identity-test-vectors.json"
);
const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    (0..32)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

const SEEDS: [[u8; 32]; 4] = [[0; 32], [0xff; 32], [0x5a; 32], {
    let mut seed = [0; 32];
    let mut i = 0;
    while i < 32 {
        seed[i] = i as u8;
        i += 1;
    }
    seed
}];

fn code_of(seed: &[u8; 32]) -> String {
    SuccessorCode::of(&IdentityKey::from_seed(seed))
        .display()
        .to_string()
}

/// A code's 54 symbols after `S1`, as one string.
fn symbols(code: &str) -> String {
    code.trim_start_matches("S1-").replace('-', "")
}

/// `symbols` with the one at `at` made `new`, written as a code.
fn with(symbols: &str, at: usize, new: char) -> String {
    let mut s: Vec<char> = symbols.chars().collect();
    s[at] = new;
    format!("S1{}", s.into_iter().collect::<String>())
}

/// The symbol at `at`, another of the alphabet, by `step`.
fn other(symbols: &str, at: usize, step: usize) -> char {
    let v = ALPHABET.find(symbols.chars().nth(at).unwrap()).unwrap();
    ALPHABET.as_bytes()[(v + step) % 32] as char
}

/// What paper does to a code that still reads back as it: lower case,
/// spaces for hyphens, and each of the confusables.
fn garbled(code: &str) -> Vec<String> {
    vec![
        code.to_lowercase(),
        code.replace('-', " "),
        code.replace('-', "").replace('0', "O").replace('1', "l"),
        code.replace('1', "I"),
    ]
}

fn cases() -> Json {
    SEEDS
        .iter()
        .map(|seed| {
            let code = code_of(seed);
            json!({
                "seed_hex": hex(seed),
                "code": code,
                "commitment_hex": hex(&SuccessorCode::of(&IdentityKey::from_seed(seed)).commitment()),
                "typed": garbled(&code),
            })
        })
        .collect()
}

/// Codes that read as none, each with why.
fn rejects() -> Json {
    let s = symbols(&code_of(&SEEDS[2]));
    let last = ALPHABET.find(s.chars().nth(51).unwrap()).unwrap();
    let pad = |bit: usize| with(&s, 51, ALPHABET.as_bytes()[last | bit] as char);
    let fingerprint = Fingerprint::of(&IdentityKey::from_seed(&SEEDS[2]).public()).to_string();
    json!([
        { "name": "short", "typed": format!("S1{}", &s[..53]) },
        { "name": "long", "typed": format!("S1{s}0") },
        { "name": "off the alphabet", "typed": with(&s, 0, 'U') },
        { "name": "padding bit 1 set", "typed": pad(1) },
        { "name": "padding bit 2 set", "typed": pad(2) },
        { "name": "padding bit 4 set", "typed": pad(4) },
        { "name": "padding bit 8 set", "typed": pad(8) },
        { "name": "check symbols not the seed's", "typed": with(&s, 52, other(&s, 52, 1)) },
        { "name": "no S1", "typed": s.clone() },
        { "name": "another version", "typed": format!("S2{s}") },
        { "name": "a fingerprint", "typed": fingerprint },
        { "name": "non-ASCII", "typed": with(&s, 0, '\u{e9}') },
        { "name": "an asterisk", "typed": with(&s, 0, '*') },
        { "name": "empty", "typed": "" },
    ])
}

/// Misreadings a reader with the commitment mends, and one it cannot.
fn mended() -> Json {
    let seed = SEEDS[3];
    let s = symbols(&code_of(&seed));
    json!([
        { "name": "a seed symbol misread", "typed": with(&s, 10, other(&s, 10, 7)), "seed_hex": hex(&seed) },
        { "name": "a check symbol misread", "typed": with(&s, 53, other(&s, 53, 3)), "seed_hex": hex(&seed) },
        { "name": "a symbol off the alphabet", "typed": with(&s, 30, 'U'), "seed_hex": hex(&seed) },
        {
            "name": "two symbols misread",
            "typed": with(&symbols(&with(&s, 10, other(&s, 10, 7))[2..]), 20, other(&s, 20, 5)),
            "seed_hex": null,
        },
    ])
}

fn notes() -> Json {
    json!([
        "A successor code is the 32-byte seed of the successor identity key a card commits to, written down: S1, then 54 symbols of Crockford base32 (0123456789ABCDEFGHJKMNPQRSTVWXYZ). The first 52 are the seed's 256 bits, most significant bit first, the last of them with its four low bits zero; the last 2 are the first 10 bits of SHA-256(\"hl-identity/successor-code/v1\" || seed). It is shown as S1- and the 54 in groups of five joined by hyphens.",
        "A reader forgives case, spaces, hyphens and O for 0, I and L for 1, as for a recovery code. Anything else off the alphabet, no S1 at its start, a number of symbols other than 56 with it, a last seed symbol with any of its four low bits set, or check symbols other than the seed's read as no code.",
        "commitment = SHA-256(the successor key's public key), what a card's successor and a registration's successor hold. A reader that has the commitment reads a code whose seed does not match it again with each seed symbol in turn taken for each other symbol, or with its one symbol off the alphabet taken for each, and takes the reading that matches; a misread check symbol leaves the seed as typed.",
    ])
}

fn vectors() -> Json {
    serde_json::from_str(VECTORS).unwrap()
}

#[test]
fn a_successor_code_is_its_seed_written_down_and_read_back() {
    let v = vectors();
    let s = &v["successor_code"];
    assert_eq!(s["cases"], cases());
    for case in s["cases"].as_array().unwrap() {
        let seed = unhex32(case["seed_hex"].as_str().unwrap());
        let code = case["code"].as_str().unwrap();
        assert_eq!(code_of(&seed), code);
        let typed = case["typed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap());
        for typed in std::iter::once(code).chain(typed) {
            let read =
                SuccessorCode::parse(typed).unwrap_or_else(|| panic!("{typed} did not read"));
            assert_eq!(*read.key().seed(), seed, "{typed}");
            assert_eq!(
                hex(&read.commitment()),
                case["commitment_hex"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn what_is_no_successor_code_reads_as_none() {
    let v = vectors();
    let r = &v["successor_code"]["rejects"];
    assert_eq!(*r, rejects());
    for reject in r.as_array().unwrap() {
        let typed = reject["typed"].as_str().unwrap();
        assert!(SuccessorCode::parse(typed).is_none(), "{}", reject["name"]);
    }
}

#[test]
fn a_reader_holding_the_commitment_mends_one_misread_symbol_and_no_more() {
    let v = vectors();
    let m = &v["successor_code"]["mended"];
    assert_eq!(*m, mended());
    let seed = SEEDS[3];
    let commitment = SuccessorCode::of(&IdentityKey::from_seed(&seed)).commitment();
    for case in m.as_array().unwrap() {
        let typed = case["typed"].as_str().unwrap();
        assert!(
            SuccessorCode::parse(typed).is_none(),
            "{} read without the commitment",
            case["name"]
        );
        let read = SuccessorCode::parse_for(typed, &commitment).map(|c| hex(&*c.key().seed()));
        assert_eq!(
            read.as_deref(),
            case["seed_hex"].as_str(),
            "{}",
            case["name"]
        );
    }
    let other = SuccessorCode::of(&IdentityKey::from_seed(&SEEDS[2])).commitment();
    assert!(
        SuccessorCode::parse_for(&code_of(&seed), &other).is_none(),
        "another card's"
    );
}

#[test]
fn every_seed_reads_back_as_itself() {
    for _ in 0..300 {
        let code = SuccessorCode::generate();
        let shown = code.display();
        let read = SuccessorCode::parse(&shown).unwrap();
        assert_eq!(*read.key().seed(), *code.key().seed(), "{}", *shown);
        assert!(SuccessorCode::parse_for(&shown, &code.commitment()).is_some());
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
    let block = json!({
        "notes": notes(),
        "cases": cases(),
        "rejects": rejects(),
        "mended": mended(),
        "domain": "hl-identity/successor-code/v1",
    });
    upsert(
        obj_mut(&mut file),
        "successor_code",
        from_json(&block),
        false,
    );
    std::fs::write(PATH, render(&file)).unwrap();
}
