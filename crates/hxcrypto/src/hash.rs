//! HMAC and plain hashes, as HOPE names them.
//!
//! [`hmac_xxx`] takes a key, a text and an algorithm name, writes the MAC or
//! hash to `md` and returns the digest length, or 0 for an algorithm it does
//! not know:
//!
//!   - "SHA1" / "HMAC-SHA1"     → 20-byte digest
//!   - "MD5" / "HMAC-MD5"       → 16-byte digest
//!   - "SHA256" / "HMAC-SHA256" → 32-byte digest
//!
//! The unprefixed variants ("SHA1", "MD5", "SHA256") compute a plain hash over
//! key||text — NOT RFC 2104 HMAC. This is the pre-HOPE password challenge
//! construction that some servers expect. Don't "fix" it. The tests below
//! pin the legacy-construction byte output explicitly so a future "consistency
//! cleanup" can't quietly rewrite the branch into proper HMAC and silently
//! break HOPE login against legacy servers.

use digest::Digest;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;

/// Compute a MAC or plain hash depending on `macalg`; the digest length, or
/// 0 for an unknown algorithm. `md` is the largest digest any of them makes.
pub fn hmac_xxx(md: &mut [u8; 32], key: &[u8], text: &[u8], macalg: &str) -> u16 {
    hmac_xxx_inner(md, key, text, macalg)
}

/// Inner implementation that works on safe slices.
fn hmac_xxx_inner(md: &mut [u8], key: &[u8], text: &[u8], macalg: &str) -> u16 {
    match macalg {
        "HMAC-SHA1" => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(text);
            let result = mac.finalize().into_bytes();
            md[..20].copy_from_slice(&result);
            20
        }
        "HMAC-MD5" => {
            let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(text);
            let result = mac.finalize().into_bytes();
            md[..16].copy_from_slice(&result);
            16
        }
        "HMAC-SHA256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(text);
            let result = mac.finalize().into_bytes();
            md[..32].copy_from_slice(&result);
            32
        }
        "SHA1" => {
            // Plain hash: key || text (pre-HOPE challenge construction)
            let mut hasher = Sha1::new();
            hasher.update(key);
            hasher.update(text);
            let result = hasher.finalize();
            md[..20].copy_from_slice(&result);
            20
        }
        "MD5" => {
            let mut hasher = Md5::new();
            hasher.update(key);
            hasher.update(text);
            let result = hasher.finalize();
            md[..16].copy_from_slice(&result);
            16
        }
        "SHA256" => {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(text);
            let result = hasher.finalize();
            md[..32].copy_from_slice(&result);
            32
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 2104 (MD5), RFC 2202 (SHA-1) and RFC 4231 (SHA-256) test cases.
    #[test]
    fn hmac_matches_the_rfc_vectors() {
        let hi = b"Hi There".as_slice();
        let jefe = b"what do ya want for nothing?".as_slice();
        let dd = [0xddu8; 50];
        let cases: [(&str, &[u8], &[u8], &str); 8] = [
            (
                "HMAC-MD5",
                &[0x0b; 16],
                hi,
                "9294727a3638bb1c13f48ef8158bfc9d",
            ),
            (
                "HMAC-MD5",
                b"Jefe",
                jefe,
                "750c783e6ab0b503eaa86e310a5db738",
            ),
            (
                "HMAC-MD5",
                &[0xaa; 16],
                &dd,
                "56be34521d144c88dbb8c733f0e8b3f6",
            ),
            (
                "HMAC-SHA1",
                &[0x0b; 20],
                hi,
                "b617318655057264e28bc0b6fb378c8ef146be00",
            ),
            (
                "HMAC-SHA1",
                b"Jefe",
                jefe,
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
            (
                "HMAC-SHA1",
                &[0xaa; 20],
                &dd,
                "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            ),
            (
                "HMAC-SHA256",
                &[0x0b; 20],
                hi,
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                "HMAC-SHA256",
                b"Jefe",
                jefe,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
        ];
        for (alg, key, text, want) in cases {
            let mut md = [0u8; 32];
            let len = hmac_xxx(&mut md, key, text, alg) as usize;
            assert_eq!(md[..len], hex(want), "{alg}");
        }
    }

    #[test]
    fn plain_sha256_of_nothing_is_the_empty_digest() {
        let mut md = [0u8; 32];
        assert_eq!(hmac_xxx(&mut md, b"", b"", "SHA256"), 32);
        assert_eq!(
            md.to_vec(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    /* The next three tests pin the legacy `key||text` construction
     * against hand-computed digest bytes — NOT a "compare against
     * another impl of the same construction" round-trip, because the
     * point is to catch any future "consistency fix" that quietly
     * rewrites the branch into proper HMAC. The wire contract is
     * what the pre-HOPE Hotline servers compute for password
     * challenges; we negotiate compatibility, not correctness. The
     * expected vectors come from running the system tools against
     * the concatenated string:
     *
     *   echo -n "keytext" | sha1sum
     *   echo -n "keytext" | md5sum
     *   echo -n "keytext" | sha256sum
     */

    #[test]
    fn legacy_sha1_key_concat_text_byte_pin() {
        // SHA1("key" || "text") = SHA1("keytext")
        let mut md = [0u8; 32];
        let len = hmac_xxx_inner(&mut md, b"key", b"text", "SHA1");
        assert_eq!(len, 20);
        let expected: [u8; 20] = [
            0x5c, 0x87, 0x61, 0x12, 0xf0, 0x80, 0x63, 0x68, 0x30, 0xc6, 0xe9, 0x7b, 0x95, 0x84,
            0x75, 0x56, 0x34, 0x50, 0xe3, 0xcb,
        ];
        assert_eq!(&md[..20], &expected);
    }

    #[test]
    fn legacy_md5_key_concat_text_byte_pin() {
        // MD5("key" || "text") = MD5("keytext")
        let mut md = [0u8; 32];
        let len = hmac_xxx_inner(&mut md, b"key", b"text", "MD5");
        assert_eq!(len, 16);
        let expected: [u8; 16] = [
            0x0b, 0xd4, 0xdf, 0x0a, 0x4e, 0x17, 0xec, 0xa1, 0xc4, 0xb0, 0xcc, 0x69, 0xc3, 0x21,
            0x8e, 0x12,
        ];
        assert_eq!(&md[..16], &expected);
    }

    #[test]
    fn legacy_sha256_key_concat_text_byte_pin() {
        // SHA256("key" || "text") = SHA256("keytext")
        let mut md = [0u8; 32];
        let len = hmac_xxx_inner(&mut md, b"key", b"text", "SHA256");
        assert_eq!(len, 32);
        let expected: [u8; 32] = [
            0x8f, 0xf7, 0x3e, 0x3c, 0x08, 0xbe, 0x05, 0x31, 0xd9, 0xa0, 0x48, 0x99, 0xff, 0x3a,
            0x84, 0x99, 0x98, 0x73, 0x31, 0x9b, 0x03, 0x12, 0x33, 0x5a, 0xd3, 0xbe, 0x49, 0x20,
            0xc7, 0x13, 0x6a, 0xf2,
        ];
        assert_eq!(&md[..32], &expected);
    }

    #[test]
    fn unknown_algorithm_returns_zero() {
        let mut md = [0u8; 32];
        for alg in ["HAVAL", "HMAC-HAVAL", ""] {
            assert_eq!(hmac_xxx(&mut md, b"k", b"t", alg), 0);
        }
    }
}
