//! The crypto primitives behind HOPE, the Hotline secure login, and the
//! transports it negotiates.
//!
//! - [`hash`] — MD5 / SHA-1 / SHA-256 and the HMAC dispatcher, including the
//!   legacy `key||text` branches that HOPE login against old servers needs.
//!   Those are pinned byte-for-byte by tests; do not "fix" them into RFC 2104.
//! - [`stream`] — Blowfish OFB-64.
//! - [`aead`] — ChaCha20-Poly1305 records and their HKDF-SHA256 keys.
//!
//! **The negotiated wire format is not ours to change** — only the
//! implementation underneath it. 1.2 / 1.5 / 1.9 compatibility is a hard
//! requirement.

pub mod aead;
pub mod hash;
pub mod stream;
