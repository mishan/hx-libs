//! The keys a HOPE login derives, the same on both sides.

use hxcrypto::aead::{derive_session_keys, derive_transfer_keys, AeadState};

use crate::alg::Mac;

/// The HMAC chain over the password, as the spec names its links:
///
/// ```text
/// password_mac = MAC(password, session key)
/// encode       = MAC(password, password_mac)
/// decode       = MAC(password, encode)
/// ```
///
/// The spec's encode key is the server's: a server encrypts with it and a
/// client decrypts with it.
pub(crate) struct Chain {
    pub password_mac: Vec<u8>,
    pub encode: Vec<u8>,
    pub decode: Vec<u8>,
}

impl Chain {
    pub fn new(mac: Mac, password: &[u8], session_key: &[u8]) -> Chain {
        let password_mac = mac.mac(password, session_key);
        let encode = mac.mac(password, &password_mac);
        let decode = mac.mac(password, &encode);
        Chain {
            password_mac,
            encode,
            decode,
        }
    }

    /// The ChaCha20-Poly1305 states, `(client → server, server → client)`.
    pub fn aead(&self, session_key: &[u8]) -> (AeadState, AeadState) {
        derive_session_keys(session_key, &self.encode, &self.decode)
    }
}

/// What a file transfer over a ChaCha20-Poly1305 session derives its keys
/// from. The session key stays in here.
#[derive(Clone)]
pub struct TransferKeys {
    session_key: Vec<u8>,
    to_server: [u8; 32],
    to_client: [u8; 32],
}

impl TransferKeys {
    pub(crate) fn new(session_key: &[u8], to_server: &AeadState, to_client: &AeadState) -> Self {
        TransferKeys {
            session_key: session_key.to_vec(),
            to_server: *to_server.key(),
            to_client: *to_client.key(),
        }
    }

    /// The states of transfer `ref_num`, `(client → server, server →
    /// client)`.
    pub fn transfer(&self, ref_num: u32) -> (AeadState, AeadState) {
        derive_transfer_keys(&self.session_key, &self.to_server, &self.to_client, ref_num)
    }
}

impl std::fmt::Debug for TransferKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransferKeys(..)")
    }
}
