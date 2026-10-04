//! Blowfish in 64-bit OFB mode, HOPE's stream cipher. ChaCha20-Poly1305,
//! the stronger choice a server can make, is [`crate::aead`].

mod blowfish_ofb;

pub use blowfish_ofb::{BlowfishOfb64State, BLOWFISH_OFB64_BLOCK_SIZE};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blowfish_crypt_in_place_matches_crypt() {
        // crypt_in_place should produce the same bytes as crypt
        // against fresh state, byte-for-byte. Different scratch
        // shapes — single big call vs. byte-at-a-time — should
        // also agree, validating that the OFB state advances
        // identically.
        let key = b"keymaterial!!!";
        let plaintext: &[u8] = b"The quick brown fox jumps over the lazy dog";

        // Reference: classic two-buffer crypt.
        let mut ref_state = BlowfishOfb64State::new(key).expect("valid key");
        let mut reference = vec![0u8; plaintext.len()];
        ref_state.crypt(plaintext, &mut reference);

        // crypt_in_place, single big call.
        let mut state1 = BlowfishOfb64State::new(key).expect("valid key");
        let mut buf1 = plaintext.to_vec();
        state1.crypt_in_place(&mut buf1);
        assert_eq!(buf1, reference);

        // crypt_in_place, byte at a time — proves OFB state
        // advances per byte.
        let mut state2 = BlowfishOfb64State::new(key).expect("valid key");
        let mut buf2 = plaintext.to_vec();
        for i in 0..buf2.len() {
            state2.crypt_in_place(&mut buf2[i..i + 1]);
        }
        assert_eq!(buf2, reference);

        // Symmetric: decrypt in place using a fresh state.
        let mut decrypt_state = BlowfishOfb64State::new(key).expect("valid key");
        decrypt_state.crypt_in_place(&mut buf1);
        assert_eq!(buf1, plaintext);
    }

    #[test]
    fn blowfish_ofb64_roundtrip() {
        let key = b"blowfishkey";
        let plaintext = b"Hotline protocol data that spans multiple blocks!";

        let mut state1 = BlowfishOfb64State::new(key).expect("valid key");
        let mut ciphertext = vec![0u8; plaintext.len()];
        state1.crypt(plaintext, &mut ciphertext);

        assert_ne!(&ciphertext[..], &plaintext[..]);

        // OFB is symmetric with the same state — need a fresh state
        let mut state2 = BlowfishOfb64State::new(key).expect("valid key");
        let mut decrypted = vec![0u8; plaintext.len()];
        state2.crypt(&ciphertext, &mut decrypted);
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn blowfish_ofb64_incremental() {
        // Verify that encrypting byte-by-byte produces the same result
        // as encrypting all at once (important for the wire protocol).
        let key = b"incrementaltest";
        let plaintext = b"0123456789abcdef0123";

        // All at once
        let mut state1 = BlowfishOfb64State::new(key).expect("valid key");
        let mut full = vec![0u8; plaintext.len()];
        state1.crypt(plaintext, &mut full);

        // Byte by byte
        let mut state2 = BlowfishOfb64State::new(key).expect("valid key");
        let mut incremental = vec![0u8; plaintext.len()];
        for i in 0..plaintext.len() {
            state2.crypt(&plaintext[i..i + 1], &mut incremental[i..i + 1]);
        }

        assert_eq!(full, incremental);
    }

    #[test]
    fn blowfish_rekey_does_not_reset_ivec() {
        // The wire protocol requires that rekeying only changes the key
        // schedule but does NOT reset the OFB ivec/num state.
        let key1 = b"initial_key_1234";
        let key2 = b"rotated_key_5678";
        let data = [0x42u8; 32];

        // Encrypt 8 bytes to advance ivec, then rekey
        let mut state = BlowfishOfb64State::new(key1).expect("valid key");
        let mut throwaway = [0u8; 8];
        state.crypt(&data[..8], &mut throwaway);

        // Now rekey — ivec/num should stay where they are
        assert!(state.set_key(key2));
        let mut out_after_rekey = [0u8; 8];
        state.crypt(&data[..8], &mut out_after_rekey);

        // Compare against a fresh state with key2 that also encrypted 8 bytes
        // first — this should NOT match because the fresh state has a zeroed
        // ivec while the rekeyed state has the advanced ivec from key1.
        let mut fresh = BlowfishOfb64State::new(key2).expect("valid key");
        let mut out_fresh = [0u8; 8];
        fresh.crypt(&data[..8], &mut out_fresh);

        assert_ne!(out_after_rekey, out_fresh);
    }

    #[test]
    fn blowfish_new_rejects_invalid_key_lengths() {
        // 0-byte and 57+-byte keys are outside Blowfish's accepted range.
        assert!(BlowfishOfb64State::new(&[]).is_none());
        let oversized = vec![0u8; 57];
        assert!(BlowfishOfb64State::new(&oversized).is_none());
    }

    #[test]
    fn blowfish_set_key_returns_false_on_invalid_length() {
        let mut state = BlowfishOfb64State::new(b"valid").expect("valid key");
        assert!(!state.set_key(&[]));
        let oversized = vec![0u8; 57];
        assert!(!state.set_key(&oversized));
    }
}
