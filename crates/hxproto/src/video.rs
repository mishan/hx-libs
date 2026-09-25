//! Video extension wire protocol (hxd-ng `docs/capabilities-video.md`,
//! drafted in the shape of a fogWraith capability document).
//!
//! Video rides the voice extension: the same peer connection, the same
//! 602 / 603 / 604 SDP and ICE transactions, the same room. What this
//! module adds is the five control transactions and their fields:
//!
//! | Opcode | Direction | Fields |
//! |---|---|---|
//! | 607 `VIDEO_START` | C→S | `CHAT_ID` + `VIDEO_KIND` |
//! | 608 `VIDEO_STOP` | C→S | `CHAT_ID` [+ `VIDEO_KIND`] |
//! | 609 `VIDEO_STATE` | C→S | `CHAT_ID` + `VIDEO_KIND` + `VIDEO_PAUSED` |
//! | 610 `VIDEO_SUBSCRIBE` | C→S | `CHAT_ID` [+ `VIDEO_SUBSCRIPTIONS`] |
//! | 611 `VIDEO_STATUS` | S→C | `CHAT_ID` + `VIDEO_PUBLISHERS` + `VIDEO_CODEC` |
//!
//! The 607 reply echoes `CHAT_ID` and `VIDEO_KIND` and adds
//! `VIDEO_CODEC`; it carries **no SDP**. The offer adding the publisher's
//! send section follows as an ordinary 602. The LOGIN reply carries one
//! `VIDEO_LIMITS` field per kind the server supports; see [`Limits`] and
//! [`crate::parse::parse_login`].
//!
//! Builders follow [`crate::voice`]: they fill caller-provided `HxChunk`
//! and scratch slices and return the chunk count, 0 on a validation
//! failure. Parsers walk borrowed bytes and never allocate.

use crate::build::HxChunk;
use crate::messages::tag;
use crate::wire::ChunkIter;

/// Capability bit 10, `CAPABILITY_VIDEO`, as a `DATA_CAPABILITIES` mask.
/// It depends on bit 2 (`CAPABILITY_VOICE`): a client never sets it
/// without voice, and a server never echoes it without voice.
pub const CAP_VIDEO: u64 = 1 << 10;

/// Access bit 59: may publish a camera.
pub const ACCESS_VIDEO_CHAT: u32 = 59;
/// Access bit 60: may publish a screen share. Deliberately separate from
/// the camera bit — showing a desktop is a different trust decision.
pub const ACCESS_SCREEN_SHARE: u32 = 60;

/// VP8's id in the publishers blob. Video codec ids are their own number
/// space: id 0 is PCMU in the voice participants blob and VP8 here, and
/// the two must never share a lookup table.
pub const CODEC_VP8: u16 = 0;

/// The payload type every video section uses, camera and screen alike.
pub const VP8_PAYLOAD_TYPE: u8 = 96;

/// Bit 0 of a publication's flags word.
pub const FLAG_PAUSED: u16 = 0x0001;

/// Bytes per `DATA_VIDEO_PUBLISHERS` entry.
pub const PUBLISHER_STRIDE: usize = 8;
/// Bytes per `DATA_VIDEO_SUBSCRIPTIONS` entry.
pub const SUBSCRIPTION_STRIDE: usize = 4;
/// Bytes in a `DATA_VIDEO_LIMITS` field in this revision. Longer fields
/// are accepted and the excess ignored.
pub const LIMITS_LEN: usize = 16;

/// A stream kind. Zero is invalid on the wire so a zeroed field is caught
/// rather than read as a camera; 3 (screen audio) is reserved, not
/// defined, and parses as `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum VideoKind {
    Camera = 1,
    Screen = 2,
}

impl VideoKind {
    /// Both defined kinds, in wire order.
    pub const ALL: [VideoKind; 2] = [VideoKind::Camera, VideoKind::Screen];

    /// Decode a wire value; `None` for 0 and every reserved value.
    pub fn from_wire(v: u16) -> Option<VideoKind> {
        match v {
            1 => Some(VideoKind::Camera),
            2 => Some(VideoKind::Screen),
            _ => None,
        }
    }

    /// The wire value.
    pub fn wire(self) -> u16 {
        self as u16
    }
}

/// One entry of `DATA_VIDEO_PUBLISHERS`: a publication, live or paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publication {
    pub user_id: u16,
    pub kind: VideoKind,
    pub flags: u16,
    pub codec_id: u16,
}

impl Publication {
    /// Flags bit 0. A paused publication still holds its slot and its
    /// mid; a client shows it as present-but-paused.
    pub fn is_paused(&self) -> bool {
        self.flags & FLAG_PAUSED != 0
    }

    /// Encode as one `DATA_VIDEO_PUBLISHERS` entry. The field is these
    /// entries back to back; a server builds it by concatenation.
    pub fn to_bytes(&self) -> [u8; PUBLISHER_STRIDE] {
        let mut b = [0u8; PUBLISHER_STRIDE];
        b[0..2].copy_from_slice(&self.user_id.to_be_bytes());
        b[2..4].copy_from_slice(&self.kind.wire().to_be_bytes());
        b[4..6].copy_from_slice(&self.flags.to_be_bytes());
        b[6..8].copy_from_slice(&self.codec_id.to_be_bytes());
        b
    }
}

/// Walk a `DATA_VIDEO_PUBLISHERS` blob: eight-byte entries,
/// `uid | kind | flags | codec id`, big-endian. A trailing partial entry
/// is ignored, as the spec requires, and so is an entry of a kind this
/// revision does not define — a later revision's screen audio costs this
/// client that one entry, not the list.
pub fn parse_video_publishers(blob: &[u8]) -> impl Iterator<Item = Publication> + '_ {
    blob.chunks_exact(PUBLISHER_STRIDE).filter_map(|c| {
        Some(Publication {
            user_id: u16::from_be_bytes([c[0], c[1]]),
            kind: VideoKind::from_wire(u16::from_be_bytes([c[2], c[3]]))?,
            flags: u16::from_be_bytes([c[4], c[5]]),
            codec_id: u16::from_be_bytes([c[6], c[7]]),
        })
    })
}

/// One stream a client wants to receive: a user's camera or screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Stream {
    pub user_id: u16,
    pub kind: VideoKind,
}

/// Walk a `DATA_VIDEO_SUBSCRIPTIONS` blob, four bytes an entry. The
/// client never receives this field; the parser exists so the builder's
/// output can be checked against the same reading a server makes.
pub fn parse_video_subscriptions(blob: &[u8]) -> impl Iterator<Item = Stream> + '_ {
    blob.chunks_exact(SUBSCRIPTION_STRIDE).filter_map(|c| {
        Some(Stream {
            user_id: u16::from_be_bytes([c[0], c[1]]),
            kind: VideoKind::from_wire(u16::from_be_bytes([c[2], c[3]]))?,
        })
    })
}

/// A `DATA_VIDEO_LIMITS` field: the server's ceiling for one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub kind: VideoKind,
    pub max_width: u16,
    pub max_height: u16,
    pub max_fps: u16,
    /// Bits per second.
    pub max_bitrate: u32,
    /// Publication slots of this kind per room.
    pub max_per_room: u16,
}

impl Limits {
    /// Decode one field. Shorter than [`LIMITS_LEN`] or an undefined kind
    /// is `None`; anything past the sixteenth byte is a later revision's
    /// and is ignored.
    pub fn parse(data: &[u8]) -> Option<Limits> {
        if data.len() < LIMITS_LEN {
            return None;
        }
        let u16_at = |i: usize| u16::from_be_bytes([data[i], data[i + 1]]);
        Some(Limits {
            kind: VideoKind::from_wire(u16_at(0))?,
            max_width: u16_at(2),
            max_height: u16_at(4),
            max_fps: u16_at(6),
            max_bitrate: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            max_per_room: u16_at(12),
        })
    }

    /// Encode as the sixteen bytes of this revision, reserved pair zero.
    pub fn to_bytes(&self) -> [u8; LIMITS_LEN] {
        let mut b = [0u8; LIMITS_LEN];
        b[0..2].copy_from_slice(&self.kind.wire().to_be_bytes());
        b[2..4].copy_from_slice(&self.max_width.to_be_bytes());
        b[4..6].copy_from_slice(&self.max_height.to_be_bytes());
        b[6..8].copy_from_slice(&self.max_fps.to_be_bytes());
        b[8..12].copy_from_slice(&self.max_bitrate.to_be_bytes());
        b[12..14].copy_from_slice(&self.max_per_room.to_be_bytes());
        b
    }
}

// ---- Outgoing builders -------------------------------------------------

fn chat_id_chunk(cid: u32, scratch: &mut [u8]) -> HxChunk {
    scratch[0..4].copy_from_slice(&cid.to_be_bytes());
    HxChunk {
        tag: tag::CHAT_ID,
        len: 4,
        data: scratch.as_ptr(),
    }
}

/// Build chunks for `VIDEO_START` (607): `CHAT_ID` + `VIDEO_KIND`.
/// Scratch usage: 6 bytes.
pub fn build_video_start_chunks(
    cid: u32,
    kind: VideoKind,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    if chunks.len() < 2 || scratch.len() < 6 {
        return 0;
    }
    scratch[4..6].copy_from_slice(&kind.wire().to_be_bytes());
    chunks[0] = chat_id_chunk(cid, scratch);
    chunks[1] = HxChunk {
        tag: tag::VIDEO_KIND,
        len: 2,
        data: scratch[4..6].as_ptr(),
    };
    2
}

/// Build chunks for `VIDEO_STOP` (608): `CHAT_ID`, plus `VIDEO_KIND` when
/// `kind` is given. `None` stops every publication this client holds in
/// the room. Scratch usage: 6 bytes.
pub fn build_video_stop_chunks(
    cid: u32,
    kind: Option<VideoKind>,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    let need = if kind.is_some() { 2 } else { 1 };
    if chunks.len() < need || scratch.len() < 6 {
        return 0;
    }
    chunks[0] = chat_id_chunk(cid, scratch);
    if let Some(k) = kind {
        scratch[4..6].copy_from_slice(&k.wire().to_be_bytes());
        chunks[1] = HxChunk {
            tag: tag::VIDEO_KIND,
            len: 2,
            data: scratch[4..6].as_ptr(),
        };
    }
    need
}

/// Build chunks for `VIDEO_STATE` (609): `CHAT_ID` + `VIDEO_KIND` +
/// `VIDEO_PAUSED`. Scratch usage: 8 bytes.
pub fn build_video_state_chunks(
    cid: u32,
    kind: VideoKind,
    paused: bool,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    if chunks.len() < 3 || scratch.len() < 8 {
        return 0;
    }
    scratch[4..6].copy_from_slice(&kind.wire().to_be_bytes());
    scratch[6..8].copy_from_slice(&(paused as u16).to_be_bytes());
    chunks[0] = chat_id_chunk(cid, scratch);
    chunks[1] = HxChunk {
        tag: tag::VIDEO_KIND,
        len: 2,
        data: scratch[4..6].as_ptr(),
    };
    chunks[2] = HxChunk {
        tag: tag::VIDEO_PAUSED,
        len: 2,
        data: scratch[6..8].as_ptr(),
    };
    3
}

/// Scratch bytes [`build_video_subscribe_chunks`] needs for `n` streams.
pub fn video_subscribe_scratch_len(n: usize) -> usize {
    4 + n * SUBSCRIPTION_STRIDE
}

/// Build chunks for `VIDEO_SUBSCRIBE` (610): `CHAT_ID` and the complete
/// desired set as `VIDEO_SUBSCRIPTIONS`. An empty `streams` still sends
/// the field, zero-length — "no video at all" said explicitly rather
/// than by omission, which the spec treats the same way.
///
/// Scratch usage: [`video_subscribe_scratch_len`]. A set too large for
/// one field's 16-bit length is rejected.
pub fn build_video_subscribe_chunks(
    cid: u32,
    streams: &[Stream],
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    let blob_len = streams.len() * SUBSCRIPTION_STRIDE;
    if chunks.len() < 2
        || blob_len > u16::MAX as usize
        || scratch.len() < video_subscribe_scratch_len(streams.len())
    {
        return 0;
    }
    for (i, s) in streams.iter().enumerate() {
        let at = 4 + i * SUBSCRIPTION_STRIDE;
        scratch[at..at + 2].copy_from_slice(&s.user_id.to_be_bytes());
        scratch[at + 2..at + 4].copy_from_slice(&s.kind.wire().to_be_bytes());
    }
    chunks[0] = chat_id_chunk(cid, scratch);
    chunks[1] = HxChunk {
        tag: tag::VIDEO_SUBSCRIPTIONS,
        len: blob_len as u16,
        data: scratch[4..].as_ptr(),
    };
    2
}

// ---- Inbound -----------------------------------------------------------

/// The fields a 611 notification or a 607 reply carries. Borrowed from
/// the caller's message buffer; absent fields stay `None`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct VideoReply<'a> {
    pub cid: u32,
    pub kind: Option<u16>,
    pub codec: Option<&'a [u8]>,
    pub publishers: Option<&'a [u8]>,
}

/// Walk a video reply or 611 body once. Unknown tags are ignored.
pub fn parse_video_reply(buf: &[u8], len: usize) -> VideoReply<'_> {
    let mut out = VideoReply::default();
    for chunk in ChunkIter::over_message(buf, len) {
        match chunk.tag {
            tag::CHAT_ID => out.cid = chunk.as_uint(),
            // Exactly two bytes: a wider field is malformed, and reading
            // its low word would turn `00 01 00 01` into a camera.
            tag::VIDEO_KIND => {
                out.kind = <[u8; 2]>::try_from(chunk.data).ok().map(u16::from_be_bytes)
            }
            tag::VIDEO_CODEC => out.codec = Some(chunk.data),
            tag::VIDEO_PUBLISHERS => out.publishers = Some(chunk.data),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; crate::HL_HDR_LEN];
        v.extend_from_slice(payload);
        v
    }

    fn chunk(tag: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + data.len());
        v.extend_from_slice(&tag.to_be_bytes());
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    fn bytes(c: &HxChunk) -> &[u8] {
        unsafe { std::slice::from_raw_parts(c.data, c.len as usize) }
    }

    #[test]
    fn kind_zero_and_reserved_are_rejected() {
        assert_eq!(VideoKind::from_wire(0), None);
        assert_eq!(VideoKind::from_wire(1), Some(VideoKind::Camera));
        assert_eq!(VideoKind::from_wire(2), Some(VideoKind::Screen));
        assert_eq!(VideoKind::from_wire(3), None, "screen audio is reserved");
        assert_eq!(VideoKind::Camera.wire(), 1);
        assert_eq!(VideoKind::Screen.wire(), 2);
    }

    #[test]
    fn capability_and_access_bits_match_spec() {
        assert_eq!(CAP_VIDEO, 0x0400);
        assert_eq!(ACCESS_VIDEO_CHAT, 59);
        assert_eq!(ACCESS_SCREEN_SHARE, 60);
    }

    #[test]
    fn publishers_blob_matches_the_spec_bytes() {
        // uid 12's live camera and paused screen, both VP8. Byte for
        // byte, so a change to either direction has to be deliberate.
        let blob = [0, 12, 0, 1, 0, 0, 0, 0, 0, 12, 0, 2, 0, 1, 0, 0];
        let ps: Vec<_> = parse_video_publishers(&blob).collect();
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0].user_id, 12);
        assert_eq!(ps[0].kind, VideoKind::Camera);
        assert!(!ps[0].is_paused());
        assert_eq!(ps[1].kind, VideoKind::Screen);
        assert!(ps[1].is_paused());
        assert_eq!(ps[1].codec_id, CODEC_VP8);
        let back: Vec<u8> = ps.iter().flat_map(|p| p.to_bytes()).collect();
        assert_eq!(back, blob);
    }

    #[test]
    fn publishers_ignore_partial_and_reserved_entries() {
        // uid 7 camera, uid 8 screen-audio (reserved), then 5 stray bytes.
        let blob = [
            0, 7, 0, 1, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0, 0, 0, 0, 9, 0, 1, 0,
        ];
        let ps: Vec<_> = parse_video_publishers(&blob).collect();
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].user_id, 7);
        assert_eq!(parse_video_publishers(&[]).count(), 0);
    }

    #[test]
    fn limits_parse_accepts_longer_fields() {
        let l = Limits {
            kind: VideoKind::Screen,
            max_width: 1920,
            max_height: 1080,
            max_fps: 15,
            max_bitrate: 2_500_000,
            max_per_room: 1,
        };
        let b = l.to_bytes();
        assert_eq!(&b[14..16], &[0, 0], "reserved pair is zero");
        assert_eq!(Limits::parse(&b), Some(l));
        let mut longer = b.to_vec();
        longer.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(Limits::parse(&longer), Some(l));
        assert_eq!(Limits::parse(&b[..15]), None);
        let mut kind0 = b;
        kind0[1] = 0;
        assert_eq!(Limits::parse(&kind0), None);
    }

    #[test]
    fn start_builds_chat_id_and_kind() {
        let mut chunks = [HxChunk::EMPTY; 2];
        let mut scratch = [0u8; 6];
        let hc = build_video_start_chunks(42, VideoKind::Screen, &mut chunks, &mut scratch);
        assert_eq!(hc, 2);
        assert_eq!(chunks[0].tag, tag::CHAT_ID);
        assert_eq!(bytes(&chunks[0]), &42u32.to_be_bytes());
        assert_eq!(chunks[1].tag, tag::VIDEO_KIND);
        assert_eq!(bytes(&chunks[1]), &[0, 2]);
        let mut short = [0u8; 5];
        assert_eq!(
            build_video_start_chunks(42, VideoKind::Camera, &mut chunks, &mut short),
            0
        );
    }

    #[test]
    fn stop_omits_kind_to_stop_everything() {
        let mut chunks = [HxChunk::EMPTY; 2];
        let mut scratch = [0u8; 6];
        assert_eq!(
            build_video_stop_chunks(7, None, &mut chunks, &mut scratch),
            1
        );
        assert_eq!(chunks[0].tag, tag::CHAT_ID);
        let hc = build_video_stop_chunks(7, Some(VideoKind::Camera), &mut chunks, &mut scratch);
        assert_eq!(hc, 2);
        assert_eq!(bytes(&chunks[1]), &[0, 1]);
    }

    #[test]
    fn state_carries_the_paused_word() {
        let mut chunks = [HxChunk::EMPTY; 3];
        let mut scratch = [0u8; 8];
        let hc = build_video_state_chunks(1, VideoKind::Camera, true, &mut chunks, &mut scratch);
        assert_eq!(hc, 3);
        assert_eq!(chunks[2].tag, tag::VIDEO_PAUSED);
        assert_eq!(bytes(&chunks[2]), &[0, 1]);
        build_video_state_chunks(1, VideoKind::Camera, false, &mut chunks, &mut scratch);
        assert_eq!(bytes(&chunks[2]), &[0, 0]);
    }

    #[test]
    fn subscribe_round_trips_through_the_server_reading() {
        let want = [
            Stream {
                user_id: 5,
                kind: VideoKind::Camera,
            },
            Stream {
                user_id: 9,
                kind: VideoKind::Screen,
            },
        ];
        let mut chunks = [HxChunk::EMPTY; 2];
        let mut scratch = vec![0u8; video_subscribe_scratch_len(want.len())];
        let hc = build_video_subscribe_chunks(3, &want, &mut chunks, &mut scratch);
        assert_eq!(hc, 2);
        assert_eq!(chunks[1].tag, tag::VIDEO_SUBSCRIPTIONS);
        assert_eq!(bytes(&chunks[1]), &[0, 5, 0, 1, 0, 9, 0, 2]);
        let back: Vec<_> = parse_video_subscriptions(bytes(&chunks[1])).collect();
        assert_eq!(back, want);
    }

    #[test]
    fn subscribe_empty_set_is_a_zero_length_field() {
        let mut chunks = [HxChunk::EMPTY; 2];
        let mut scratch = [0u8; 4];
        let hc = build_video_subscribe_chunks(3, &[], &mut chunks, &mut scratch);
        assert_eq!(hc, 2);
        assert_eq!(chunks[1].len, 0);
    }

    #[test]
    fn subscribe_rejects_short_scratch() {
        let one = [Stream {
            user_id: 1,
            kind: VideoKind::Camera,
        }];
        let mut chunks = [HxChunk::EMPTY; 2];
        let mut scratch = [0u8; 7];
        assert_eq!(
            build_video_subscribe_chunks(3, &one, &mut chunks, &mut scratch),
            0
        );
    }

    #[test]
    fn status_parse_extracts_every_field() {
        let mut body = Vec::new();
        body.extend(chunk(tag::CHAT_ID, &77u32.to_be_bytes()));
        body.extend(chunk(tag::VIDEO_PUBLISHERS, &[0, 4, 0, 1, 0, 0, 0, 0]));
        body.extend(chunk(tag::VIDEO_CODEC, b"VP8"));
        let buf = frame(&body);
        let r = parse_video_reply(&buf, buf.len());
        assert_eq!(r.cid, 77);
        assert_eq!(r.codec, Some(&b"VP8"[..]));
        assert_eq!(parse_video_publishers(r.publishers.unwrap()).count(), 1);
        assert_eq!(r.kind, None);
    }

    #[test]
    fn reply_kind_must_be_two_bytes() {
        let mut body = Vec::new();
        body.extend(chunk(tag::VIDEO_KIND, &[0, 2]));
        let buf = frame(&body);
        assert_eq!(parse_video_reply(&buf, buf.len()).kind, Some(2));
        let mut body = Vec::new();
        body.extend(chunk(tag::VIDEO_KIND, &[0, 1, 0, 1]));
        let buf = frame(&body);
        assert_eq!(parse_video_reply(&buf, buf.len()).kind, None);
    }
}
