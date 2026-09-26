//! Listing: the TCP exchange a client uses to fetch a tracker's servers.
//!
//! The codec lives in [`crate::parse`], where it grew up; this module is
//! its front door alongside the rest of the tracker protocol. See GtkHx's
//! `docs/tracker-protocol.md` for the v3 probe-and-fallback a client needs,
//! because real v1 trackers never answer a v3 handshake.
//!
//! A v3 record's metadata trailer decodes with
//! [`TrackerMeta::decode`](super::TrackerMeta::decode).

pub use crate::parse::tracker_v3 as consts;
pub use crate::parse::{
    pack_tracker_v3_handshake as pack_v3_handshake,
    pack_tracker_v3_listing_request_simple as pack_v3_listing_request,
    parse_tracker_header as parse_v1_header, parse_tracker_record_fixed as parse_v1_record_fixed,
    parse_tracker_v3_handshake_response as parse_v3_handshake_response,
    parse_tracker_v3_record as parse_v3_record,
    parse_tracker_v3_response_header as parse_v3_response_header,
    tracker_normalize_text as normalize_v1_text, tracker_record_is_padding as is_v1_padding,
    TrackerRecordFixed as V1RecordFixed, TrackerV3HandshakeResponse as V3HandshakeResponse,
    TrackerV3Record as V3Record, TrackerV3ResponseHeader as V3ResponseHeader,
};

/// v3 handshake feature bits.
pub mod features {
    pub const IPV6: u16 = 0x0001;
    pub const QUERY: u16 = 0x0002;
    pub const CLIENT_AUTH: u16 = 0x0004;
    pub const REG_ACK: u16 = 0x0008;
    pub const HMAC: u16 = 0x0010;
}
