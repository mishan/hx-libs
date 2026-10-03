//! ChaCha20-Poly1305, HOPE's AEAD cipher: the record codec with its
//! deterministic nonces, and the HKDF-SHA256 derivations of the session's
//! and each file transfer's keys.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// Maximum AEAD frame size (ciphertext + tag). 16 MiB cap.
pub const AEAD_MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Poly1305 tag size.
pub const AEAD_TAG_SIZE: usize = 16;

/// Length prefix size (big-endian u32).
pub const AEAD_LENGTH_PREFIX: usize = 4;

/// Direction byte for nonce: server → client.
pub const AEAD_DIR_SERVER_TO_CLIENT: u8 = 0x00;

/// Direction byte for nonce: client → server.
pub const AEAD_DIR_CLIENT_TO_SERVER: u8 = 0x01;

/// AEAD state for one direction of a connection. Neither copied nor
/// cloned, and its counter not settable: two states at one counter under
/// one key would seal two records under one nonce.
pub struct AeadState {
    key: [u8; 32],
    counter: u64,
    dir: u8,
}

impl AeadState {
    /// A direction's state, at the first record.
    pub fn new(key: [u8; 32], dir: u8) -> Self {
        AeadState {
            key,
            counter: 0,
            dir,
        }
    }

    /// The key, for deriving others from it.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn dir(&self) -> u8 {
        self.dir
    }

    /// How many records have been sealed or opened.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    fn build_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0] = self.dir;
        // bytes 1..3 = 0x000000
        // bytes 4..11 = counter (big-endian u64)
        nonce[4] = (self.counter >> 56) as u8;
        nonce[5] = (self.counter >> 48) as u8;
        nonce[6] = (self.counter >> 40) as u8;
        nonce[7] = (self.counter >> 32) as u8;
        nonce[8] = (self.counter >> 24) as u8;
        nonce[9] = (self.counter >> 16) as u8;
        nonce[10] = (self.counter >> 8) as u8;
        nonce[11] = self.counter as u8;
        nonce
    }

    /// Seal `plaintext` into a framed AEAD record in `out`:
    /// `[4-byte BE body_len][ciphertext+tag]` where `body_len =
    /// plaintext.len() + AEAD_TAG_SIZE`. Increments the counter on
    /// success. Returns the framed length, or `None` if `out` is too
    /// small or the plaintext exceeds the frame cap.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut [u8]) -> Option<usize> {
        if plaintext.len() > (AEAD_MAX_FRAME_SIZE as usize) - AEAD_TAG_SIZE {
            return None;
        }
        let framed_len = AEAD_LENGTH_PREFIX + plaintext.len() + AEAD_TAG_SIZE;
        if out.len() < framed_len {
            return None;
        }
        // Length prefix = ciphertext + tag (excludes the 4-byte prefix).
        let body_len = (plaintext.len() + AEAD_TAG_SIZE) as u32;
        out[0] = (body_len >> 24) as u8;
        out[1] = (body_len >> 16) as u8;
        out[2] = (body_len >> 8) as u8;
        out[3] = body_len as u8;

        let nonce_bytes = self.build_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let key = Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);
        let payload = Payload {
            msg: plaintext,
            aad: &[],
        };
        match cipher.encrypt(nonce, payload) {
            Ok(ct) => {
                out[AEAD_LENGTH_PREFIX..AEAD_LENGTH_PREFIX + ct.len()].copy_from_slice(&ct);
                self.counter += 1;
                Some(framed_len)
            }
            Err(_) => None,
        }
    }

    /// Total framed size (4-byte prefix + body) from a buffer's
    /// length prefix, or `None` if `framed` is shorter than the prefix
    /// or the declared body length is out of range. Lets a streaming
    /// reader learn how many bytes make one frame before it has them
    /// all.
    pub fn peek_frame_size(framed: &[u8]) -> Option<usize> {
        if framed.len() < AEAD_LENGTH_PREFIX {
            return None;
        }
        let body_len = ((framed[0] as u32) << 24)
            | ((framed[1] as u32) << 16)
            | ((framed[2] as u32) << 8)
            | (framed[3] as u32);
        if body_len < AEAD_TAG_SIZE as u32 || body_len > AEAD_MAX_FRAME_SIZE {
            return None;
        }
        Some(AEAD_LENGTH_PREFIX + body_len as usize)
    }

    /// Open one complete framed record from the front of `framed`
    /// (which must hold at least `peek_frame_size` bytes). Writes the
    /// plaintext to `out`, increments the counter, and returns the
    /// plaintext length — or `None` on a short/oversized frame, a
    /// too-small `out`, or an authentication failure.
    pub fn open(&mut self, framed: &[u8], out: &mut [u8]) -> Option<usize> {
        let frame_total = Self::peek_frame_size(framed)?;
        if framed.len() < frame_total {
            return None;
        }
        let pt_len = frame_total - AEAD_LENGTH_PREFIX - AEAD_TAG_SIZE;
        if out.len() < pt_len {
            return None;
        }
        let nonce_bytes = self.build_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let key = Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);
        let ct_and_tag = &framed[AEAD_LENGTH_PREFIX..frame_total];
        let payload = Payload {
            msg: ct_and_tag,
            aad: &[],
        };
        match cipher.decrypt(nonce, payload) {
            Ok(pt) => {
                out[..pt_len].copy_from_slice(&pt);
                self.counter += 1;
                Some(pt_len)
            }
            Err(_) => None,
        }
    }
}

// ---- HKDF-SHA256 --------------------------------------------------------

/// One-shot HKDF-SHA256: extract + expand. `false`, with `out` zeroed, only
/// past RFC 5869's output cap (255 × 32 bytes); every HOPE use asks for 32.
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> bool {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    match hk.expand(info, out) {
        Ok(()) => true,
        Err(_) => {
            for byte in out.iter_mut() {
                *byte = 0;
            }
            false
        }
    }
}

// ---- Key derivation -----------------------------------------------------

/// A session's two AEAD states, `(client → server, server → client)`, from
/// its HOPE session key and the two keys of the HMAC chain as the spec names
/// them. The labels are wire-pinned: they are what keeps the two directions'
/// keystreams apart, and the server derives the same.
pub fn derive_session_keys(
    session_key: &[u8],
    spec_encode_key: &[u8],
    spec_decode_key: &[u8],
) -> (AeadState, AeadState) {
    let mut to_server = [0u8; 32];
    let mut to_client = [0u8; 32];
    // The spec's encode key is the server's outbound one.
    assert!(hkdf_sha256(
        session_key,
        spec_encode_key,
        b"hope-chacha-encode",
        &mut to_client
    ));
    assert!(hkdf_sha256(
        session_key,
        spec_decode_key,
        b"hope-chacha-decode",
        &mut to_server
    ));
    (
        AeadState::new(to_server, AEAD_DIR_CLIENT_TO_SERVER),
        AeadState::new(to_client, AEAD_DIR_SERVER_TO_CLIENT),
    )
}

/// The AEAD states of the file transfer `ref_num`, `(client → server,
/// server → client)`, from the session key and the control connection's two
/// directions' keys.
pub fn derive_transfer_keys(
    session_key: &[u8],
    to_server_key: &[u8; 32],
    to_client_key: &[u8; 32],
    ref_num: u32,
) -> (AeadState, AeadState) {
    // ft_base_key = HKDF(ikm = encode_key_256 || decode_key_256,
    //                     salt = session_key, info = "hope-file-transfer"),
    // the spec's encode key being the server's outbound one.
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(to_client_key);
    ikm[32..].copy_from_slice(to_server_key);
    let mut base = [0u8; 32];
    assert!(hkdf_sha256(
        session_key,
        &ikm,
        b"hope-file-transfer",
        &mut base
    ));

    // transfer_key = HKDF(ikm = ft_base_key, salt = ref (4 bytes BE),
    //                      info = "hope-ft-ref")
    let mut key = [0u8; 32];
    assert!(hkdf_sha256(
        &ref_num.to_be_bytes(),
        &base,
        b"hope-ft-ref",
        &mut key
    ));
    (
        AeadState::new(key, AEAD_DIR_CLIENT_TO_SERVER),
        AeadState::new(key, AEAD_DIR_SERVER_TO_CLIENT),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(key: u8, counter: u64, dir: u8) -> AeadState {
        AeadState {
            key: [key; 32],
            counter,
            dir,
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let mut encode_state = st(0x42, 0, AEAD_DIR_CLIENT_TO_SERVER);
        let mut decode_state = st(0x42, 0, AEAD_DIR_CLIENT_TO_SERVER);
        let plaintext = b"Hello, Hotline AEAD!";
        let mut framed = vec![0u8; AEAD_LENGTH_PREFIX + plaintext.len() + AEAD_TAG_SIZE];

        assert_eq!(
            encode_state.seal(plaintext, &mut framed),
            Some(framed.len())
        );
        assert_eq!(encode_state.counter, 1);
        assert_eq!(AeadState::peek_frame_size(&framed), Some(framed.len()));

        let mut decrypted = vec![0u8; plaintext.len()];
        assert_eq!(
            decode_state.open(&framed, &mut decrypted),
            Some(plaintext.len())
        );
        assert_eq!(&decrypted, plaintext);
        assert_eq!(decode_state.counter, 1);
    }

    #[test]
    fn peek_frame_size_reads_the_prefix() {
        // body_len = 36: 20 bytes of plaintext and the tag.
        assert_eq!(AeadState::peek_frame_size(&[0, 0, 0, 0x24]), Some(4 + 36));
        assert_eq!(AeadState::peek_frame_size(&[0, 0]), None);
        assert_eq!(AeadState::peek_frame_size(&[0, 0, 0, 15]), None, "no tag");
        assert_eq!(
            AeadState::peek_frame_size(&[0x01, 0, 0, 1]),
            None,
            "too big"
        );
    }

    #[test]
    fn open_fails_on_tampered_frame() {
        let mut state = st(0x42, 0, AEAD_DIR_CLIENT_TO_SERVER);
        let plaintext = b"secret data";
        let mut framed = vec![0u8; AEAD_LENGTH_PREFIX + plaintext.len() + AEAD_TAG_SIZE];
        assert!(state.seal(plaintext, &mut framed).is_some());

        framed[AEAD_LENGTH_PREFIX] ^= 0xff;
        state.counter = 0;
        let mut decrypted = vec![0u8; plaintext.len()];
        assert_eq!(state.open(&framed, &mut decrypted), None);
        assert_eq!(state.counter, 0, "a failed open does not advance");
    }

    const SESSION_TO_SERVER: &str =
        "7156926a9534a434e91f763df5476427c20e652c6742434657f17d2f7178fc79";
    const SESSION_TO_CLIENT: &str =
        "45a549fa557b85a422e6bb33229bda6bc1b52012e95ee44e9619160deb1ff954";
    const TRANSFER: &str = "e8f4f771f9796711963da12bdd5e6dc30c0941581564605865e9eb061ec7e0d2";

    fn hex(k: &[u8]) -> String {
        k.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The keys a HOPE server derives too, pinned to the values the
    /// implementation every rig server has been tested against produced.
    #[test]
    fn session_and_transfer_keys_are_the_ones_servers_derive() {
        let (to_server, to_client) = derive_session_keys(&[0xaa; 64], &[0xbb; 20], &[0xcc; 20]);
        assert_eq!(
            (to_server.dir, to_client.dir),
            (AEAD_DIR_CLIENT_TO_SERVER, AEAD_DIR_SERVER_TO_CLIENT)
        );
        assert_eq!(hex(&to_server.key), SESSION_TO_SERVER);
        assert_eq!(hex(&to_client.key), SESSION_TO_CLIENT);

        let (xe, xd) =
            derive_transfer_keys(&[0xaa; 64], &to_server.key, &to_client.key, 0x01020304);
        assert_eq!(xe.key, xd.key);
        assert_eq!(hex(&xe.key), TRANSFER);
    }

    #[test]
    fn hkdf_sha256_oversized_output_fails_without_panicking() {
        // RFC 5869 caps HKDF-Expand output at 255 * 32 = 8160 bytes.
        let mut huge_out = vec![0xffu8; 8161];
        assert!(!hkdf_sha256(b"salt", b"ikm", b"info", &mut huge_out));
        assert!(huge_out.iter().all(|&b| b == 0));

        let mut at_limit = vec![0u8; 8160];
        assert!(hkdf_sha256(b"salt", b"ikm", b"info", &mut at_limit));
        assert!(at_limit.iter().any(|&b| b != 0));
    }
}
