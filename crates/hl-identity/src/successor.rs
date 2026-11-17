//! A successor identity key written down (`docs/hotline-ng-identity.md`
//! §3.4, `docs/identity-registrar.md` §5.4): the seed of the key a card
//! commits to, shown once when the commitment is made and typed back in
//! at rotation, so the key itself need be kept nowhere but on paper.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::envelope::CROCKFORD;
use crate::{Fingerprint, IdentityKey};

/// What a successor code begins with: `S` for successor and `1` for this
/// form, both of the alphabet so the reading that forgives case and the
/// confusables reads them too. A fingerprint and a recovery code have
/// none, and are of another length, so neither reads as a successor code.
const PREFIX: [u8; 2] = *b"S1";
/// The seed's 256 bits, the last symbol's four low bits zero.
const SEED_SYMBOLS: usize = 52;
/// Ten bits of a hash of the seed, so a symbol misread is noticed.
const CHECK_SYMBOLS: usize = 2;
const SYMBOLS: usize = SEED_SYMBOLS + CHECK_SYMBOLS;
const CHECK_DOMAIN: &[u8] = b"hl-identity/successor-code/v1";

/// A successor identity key's seed, as it is written down: `S1`, then
/// Crockford base32 of the seed and two check symbols, in groups of five.
pub struct SuccessorCode(Zeroizing<[u8; 32]>);

impl SuccessorCode {
    /// A new successor key's code.
    pub fn generate() -> SuccessorCode {
        SuccessorCode::of(&IdentityKey::generate())
    }

    /// The code `key` is written down as.
    pub fn of(key: &IdentityKey) -> SuccessorCode {
        SuccessorCode(key.seed())
    }

    /// The key the code reads as. A caller holding the card it is for
    /// checks the code against the card's commitment first, as
    /// [`SuccessorCode::parse_for`] does: the check symbols catch most
    /// misreadings, not all.
    pub fn key(&self) -> IdentityKey {
        IdentityKey::from_seed(&self.0)
    }

    /// What a card or a registration commits to of it: the SHA-256 of its
    /// public key, as [`crate::Rotation::commitment`] names it.
    pub fn commitment(&self) -> [u8; 32] {
        commitment(&self.0)
    }

    /// As typed: case, spaces, hyphens and the Crockford confusables
    /// (`O` for `0`, `I` and `L` for `1`) forgiven, as for a recovery
    /// code, since it is read off paper. Anything else off the alphabet,
    /// no `S1` before it, a length other than its own, bits past the seed
    /// or check symbols that are not the seed's read as none.
    pub fn parse(typed: &str) -> Option<SuccessorCode> {
        let symbols = symbols(typed)?;
        if symbols.contains(&UNKNOWN) {
            return None;
        }
        let seed = seed_of(&symbols)?;
        (symbols[SEED_SYMBOLS..] == check(&seed)).then_some(SuccessorCode(seed))
    }

    /// As [`SuccessorCode::parse`], for the card whose `commitment` the
    /// code is to be: a code that is not it is read again with each of
    /// its symbols in turn taken for any other, or one symbol off the
    /// alphabet for each, and the one reading the commitment matches is
    /// given; none if no single symbol mends it.
    pub fn parse_for(typed: &str, commitment: &[u8; 32]) -> Option<SuccessorCode> {
        let mut symbols = symbols(typed)?;
        let unknown: Vec<usize> = (0..SYMBOLS).filter(|&i| symbols[i] == UNKNOWN).collect();
        let matches = |s: &[u8]| seed_of(s).filter(|seed| self::commitment(seed) == *commitment);
        match unknown[..] {
            [] => {
                if let Some(seed) = matches(&symbols) {
                    return Some(SuccessorCode(seed));
                }
                for at in 0..SEED_SYMBOLS {
                    let read = symbols[at];
                    for v in (0..32).filter(|&v| v != read) {
                        symbols[at] = v;
                        if let Some(seed) = matches(&symbols) {
                            return Some(SuccessorCode(seed));
                        }
                    }
                    symbols[at] = read;
                }
                None
            }
            // A check symbol unread leaves the seed as it was typed.
            [at] if at >= SEED_SYMBOLS => matches(&symbols).map(SuccessorCode),
            [at] => (0..32).find_map(|v| {
                symbols[at] = v;
                matches(&symbols).map(SuccessorCode)
            }),
            _ => None,
        }
    }

    /// `S1` and the groups of five, for the one time it is shown.
    pub fn display(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(4 + SYMBOLS + SYMBOLS / 5));
        out.push_str("S1-");
        let mut symbols = Zeroizing::new(Vec::with_capacity(SYMBOLS));
        let (mut acc, mut bits) = (0u32, 0u32);
        for &b in self.0.iter() {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                symbols.push(((acc >> bits) & 31) as u8);
            }
            acc &= (1 << bits) - 1;
        }
        symbols.push(((acc << (5 - bits)) & 31) as u8);
        symbols.extend_from_slice(&check(&self.0));
        for (i, &v) in symbols.iter().enumerate() {
            if i > 0 && i % 5 == 0 {
                out.push('-');
            }
            out.push(CROCKFORD[usize::from(v)] as char);
        }
        out
    }
}

/// A symbol typed off the alphabet.
const UNKNOWN: u8 = 0xff;

/// The symbols after `S1`, as typed, one off the alphabet [`UNKNOWN`];
/// none without `S1`, or of another number.
fn symbols(typed: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut all = Zeroizing::new(Vec::with_capacity(PREFIX.len() + SYMBOLS));
    for c in typed.chars().filter(|c| !matches!(c, ' ' | '-')) {
        let c = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        // Refused before a push past its capacity would move the symbols
        // and leave them, unwiped, where they were.
        if all.len() == all.capacity() {
            return None;
        }
        let v = CROCKFORD.iter().position(|&x| c.is_ascii() && x == c as u8);
        all.push(v.map_or(UNKNOWN, |v| v as u8));
    }
    let prefix = PREFIX.map(|p| CROCKFORD.iter().position(|&x| x == p).unwrap() as u8);
    if all.len() != PREFIX.len() + SYMBOLS || all[..2] != prefix {
        return None;
    }
    Some(Zeroizing::new(all[2..].to_vec()))
}

/// The seed the first [`SEED_SYMBOLS`] symbols carry; none if they carry
/// bits past it, or one is unknown.
fn seed_of(symbols: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for &v in &symbols[..SEED_SYMBOLS] {
        if v == UNKNOWN {
            return None;
        }
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            seed[n] = (acc >> bits) as u8;
            n += 1;
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(seed)
}

/// The check symbols: the first ten bits of SHA-256 of the domain and
/// the seed.
fn check(seed: &[u8; 32]) -> [u8; CHECK_SYMBOLS] {
    let h = Sha256::new()
        .chain_update(CHECK_DOMAIN)
        .chain_update(seed)
        .finalize();
    let bits = (u16::from(h[0]) << 2) | (u16::from(h[1]) >> 6);
    [(bits >> 5) as u8, (bits & 31) as u8]
}

fn commitment(seed: &[u8; 32]) -> [u8; 32] {
    Fingerprint::of(&IdentityKey::from_seed(seed).public()).0
}
