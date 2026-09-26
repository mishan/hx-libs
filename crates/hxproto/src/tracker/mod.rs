//! Hotline tracker protocol, HTRK v1 and v3, for all three roles.
//!
//! A tracker keeps a list of Hotline servers. Servers **register** with it
//! over UDP; clients **list** it over TCP. Both directions share one
//! vocabulary — the v3 TLV fields that describe a server — so both live
//! here, and a server's advertisement and a client's decoded listing are
//! the same [`TrackerMeta`] type.
//!
//! - [`tlv`] — the field ids, a strict reader and a writer.
//! - [`meta`] — [`TrackerMeta`], the typed view of those fields, with
//!   [`TrackerMeta::decode`] for a listing record's trailer and
//!   [`TrackerMeta::encode`] for a registration.
//! - [`registration`] — the UDP registration datagram, v1 and v3
//!   (including the v3 HMAC slot), and the v3 acknowledgment.
//! - [`listing`] — the TCP listing exchange: the v3 handshake probe,
//!   request, response header and records, and the v1 reply.
//!
//! The format is recorded in GtkHx's `docs/tracker-protocol.md` (listing)
//! and hxd-ng's `docs/tracker-registration.md` (registration); the
//! upstream specification is fogWraith's `Tracker.md` and
//! `Tracker-Protocol-v3.md`.
//!
//! No I/O and no crypto here. The v3 registration HMAC is computed by a
//! caller-supplied signer, so this crate stays dependency-free.

pub mod listing;
pub mod meta;
pub mod registration;
pub mod tlv;

pub use meta::{Category, Maturity, TrackerMeta};

/// Protocol version for the original tracker wire.
pub const VERSION_V1: u16 = 0x0001;
/// Protocol version some v1-era trackers answer with.
pub const VERSION_V2: u16 = 0x0002;
/// Protocol version for tracker v3.
pub const VERSION_V3: u16 = 0x0003;

/// Default TCP port for listings.
pub const LISTING_PORT: u16 = 5498;
/// Default UDP port for registrations.
pub const REGISTRATION_PORT: u16 = 5499;
