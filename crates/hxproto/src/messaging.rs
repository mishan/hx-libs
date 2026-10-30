//! Instant messaging extension wire protocol (fogWraith
//! `Capabilities-Messaging.md`), with the drafts built on and beside it:
//! message requests (`Capabilities-Messaging-Requests.md`), version 2 of
//! messaging identity (`Capabilities-Messaging-Identity.md`) and device
//! proof (`Capabilities-Device-Proof.md`). The drafts' numbers are
//! reserved for them, not adopted.
//!
//! This is the wire alone: the numbers, the grouped shapes a listing
//! carries, and the client's requests. Who may send what, and when, is
//! the caller's. Opcodes are in [`ClientHdr`](crate::messages::ClientHdr)
//! and [`ServerHdr`](crate::messages::ServerHdr), field tags in [`tag`];
//! user-to-user file transfer (814–817), calls (818–821) and buddy icons
//! (827, 828) have their numbers there and nothing here.
//!
//! ## Groups
//!
//! A transaction's fields are a flat list, so a listing is split by a
//! delimiter: every field after one, up to the next or the end, belongs
//! to it. That includes the reused fields — a [`tag::NAME`] in an entry
//! is that entry's friend's name, not the transaction's.
//!
//! | Shape | Delimiter | Parser |
//! |---|---|---|
//! | Get Roster (800) reply, Find User (822) and User Search (823) replies | `FRIEND_LOGIN` | [`parse_roster`] |
//! | Roster Entry (801), Friend Request (804), Presence Changed (809) | one `FRIEND_LOGIN` | [`parse_entry`] |
//! | Get Message Requests (829) reply | `FRIEND_LOGIN`, then `MESSAGE_GUID` within | [`parse_message_requests`] |
//! | Present Friendships (833) reply | `FRIENDSHIP_HASH` | [`parse_present_friendships`] |
//! | Get Friendships (834) reply | `FRIENDSHIP_HASH` or `FRIEND_IDENTITY` | [`parse_friendships`] |
//!
//! An entry group is complete, not incremental: a client replaces what it
//! holds for the Login with what arrives, and an absent field is one the
//! entry does not have. [`RosterEntry`] is that whole entry, and
//! [`RosterEntry::encode`] is how a server writes one.
//!
//! Fields before the first delimiter are the listing's own (a reason
//! code, a count, a cursor), never an entry's. Parsers check what
//! [`ChunkIter`] lets pass: a field cut short, a known field of the wrong
//! width, or one repeated within its group is [`Malformed`], not dropped.
//! Unknown fields are ignored, as the extension requires. Parsers borrow
//! from the message, never allocate, and check all of it before they
//! return, so the iterators they hand back cannot fail.
//!
//! ## Builders
//!
//! Builders follow [`crate::voice`]: they fill caller-provided `HxChunk`
//! and scratch slices and return the chunk count, 0 on a validation
//! failure. None needs more than [`SCRATCH_LEN`] bytes of scratch. Get
//! Roster (800), the first page of Get Message Requests (829) and a Clear
//! Message Requests (831) of everything carry no fields and have no
//! builder: they go bare.

use crate::build::{capabilities_encode, HxChunk};
use crate::messages::tag;
use crate::parse::capabilities_decode;
use crate::wire::{Chunk, ChunkIter, Encoder};
use crate::HL_HDR_LEN;

/// Capability bit 6, `CAPABILITY_MESSAGING`: the extension's master
/// switch. Nothing else here is sent unless the server echoed it.
pub const CAP_MESSAGING: u64 = 1 << 6;
/// Capability bit 7, `CAPABILITY_DIRECT_TRANSFER`. Only beside bit 6.
pub const CAP_DIRECT_TRANSFER: u64 = 1 << 7;
/// Capability bit 8, `CAPABILITY_MESSENGER_SESSION`: a pure messenger,
/// hidden from the classic user list. Only beside bit 6.
pub const CAP_MESSENGER_SESSION: u64 = 1 << 8;
/// Capability bit 13, `CAPABILITY_IDENTITY` (identity draft, version 1).
/// Only beside bit 6.
pub const CAP_IDENTITY: u64 = 1 << 13;
/// Capability bit 14, `CAPABILITY_DEVICE_PROOF` (device proof draft).
/// Independent of every other bit.
pub const CAP_DEVICE_PROOF: u64 = 1 << 14;
/// Capability bit 15, `CAPABILITY_FRIENDSHIPS` (identity draft, version
/// 2). Only beside bits 6 and 13.
pub const CAP_FRIENDSHIPS: u64 = 1 << 15;

/// Access bit 58, `AccessMessaging`, in the legacy 8-byte bitmap.
pub const ACCESS_MESSAGING: u32 = 58;

/// What a client assumes when the login reply leaves out
/// [`tag::MAX_MESSAGE_BYTES`], or sends 0.
pub const DEFAULT_MAX_MESSAGE_BYTES: u32 = 4096;
/// The default for [`tag::MAX_ROSTER_SIZE`].
pub const DEFAULT_MAX_ROSTER_SIZE: u32 = 500;
/// The default for [`tag::MAX_OFFLINE_QUEUE`].
pub const DEFAULT_MAX_OFFLINE_QUEUE: u32 = 500;
/// The default for [`tag::MAX_ICON_DIMENSION`], when buddy icons are
/// offered at all.
pub const DEFAULT_MAX_ICON_DIMENSION: u32 = 64;

/// Bytes in a message or transfer GUID.
pub const GUID_LEN: usize = 16;
/// Bytes in a buddy icon hash.
pub const ICON_HASH_LEN: usize = 16;
/// Bytes in a fingerprint, a friendship or pair hash, and the hash a
/// sealed message names its key by.
pub const HASH_LEN: usize = 32;
/// Most bytes in a detached signed message.
pub const MAX_SIGNED_LEN: usize = 1020;
/// Most bytes in a sealed message.
pub const MAX_SEALED_LEN: usize = 17_152;
/// Most bytes in a device certificate, under either tag.
pub const MAX_DEVICE_CERT_LEN: usize = 512;
/// Most bytes in an offer or a withdrawal.
pub const MAX_OFFER_LEN: usize = 1024;
/// Most bytes in a friendship: an offer and its acceptance.
pub const MAX_FRIENDSHIP_LEN: usize = 2080;
/// Most objects Present Friendships (833) carries, and most questions
/// Get Friendships (834) asks.
pub const MAX_FRIENDSHIP_OBJECTS: usize = 32;
/// Most bytes in a [`tag::PROOF_HOST`]: a 253-byte name, a kept trailing
/// dot and `:65535`.
pub const MAX_PROOF_HOST_LEN: usize = 260;
/// Most bytes in a device proof, and in a server challenge.
pub const MAX_DEVICE_PROOF_LEN: usize = 576;
/// Most bytes in a user card.
pub const MAX_USER_CARD_LEN: usize = 16_384;
/// Most languages a profile carries.
pub const MAX_LANGUAGES: usize = 3;

/// Scratch bytes enough for every builder in this module.
pub const SCRATCH_LEN: usize = 16;

macro_rules! wire_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $v:ident = $n:literal,)+ }) => {
        $(#[$m])*
        #[non_exhaustive]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u16)]
        pub enum $name {
            $($(#[$vm])* $v = $n,)+
        }

        impl $name {
            /// Decode a wire value; `None` for one this revision does not
            /// define.
            pub fn from_wire(v: u16) -> Option<$name> {
                match v {
                    $($n => Some($name::$v),)+
                    _ => None,
                }
            }

            /// The wire value.
            pub fn wire(self) -> u16 {
                self as u16
            }
        }
    };
}

wire_enum! {
    /// [`tag::PRESENCE_STATE`].
    PresenceState {
        /// Only ever reported for a friend: disconnected, or `Invisible`.
        /// A client never sets it for itself.
        Offline = 0,
        Online = 1,
        Away = 2,
        /// Appears offline to friends; still receives everything.
        Invisible = 3,
        Busy = 4,
    }
}

wire_enum! {
    /// [`tag::ROSTER_STATE`].
    RosterState {
        /// In a Roster Entry (801) alone: delete the row.
        Removed = 0,
        PendingOut = 1,
        PendingIn = 2,
        Accepted = 3,
        Blocked = 4,
    }
}

wire_enum! {
    /// [`tag::ACK_TYPE`].
    AckType {
        Delivered = 1,
        Read = 2,
    }
}

wire_enum! {
    /// [`tag::TYPING_STATE`].
    TypingState {
        Stopped = 0,
        Started = 1,
    }
}

wire_enum! {
    /// [`tag::REASON_CODE`]. The reply header's error code says whether a
    /// request failed; this only says why, or how it succeeded.
    ReasonCode {
        Ok = 0,
        AccountNotFound = 1,
        NotMessagingEnabled = 2,
        Blocked = 3,
        AlreadyFriends = 4,
        RequestPending = 5,
        NotFriends = 6,
        /// A success: stored for later delivery.
        OfflineQueued = 7,
        OfflineUndeliverable = 8,
        QueueFull = 9,
        RateLimited = 10,
        NotDiscoverable = 11,
        RosterFull = 12,
        MessageTooLong = 13,
        InvalidImage = 14,
        /// Identity draft.
        NoDeviceKeys = 15,
        /// Identity draft.
        BadSignature = 16,
        /// Message requests draft: a success, held until the recipient
        /// acts.
        Requested = 17,
        /// Identity draft, version 2.
        Withdrawn = 18,
        /// Identity draft, version 2.
        Stale = 19,
    }
}

wire_enum! {
    /// [`tag::REQUEST_ACTION`], in Answer Message Request (830).
    RequestAction {
        Approve = 1,
        Delete = 2,
        EndApproval = 3,
    }
}

wire_enum! {
    /// [`tag::PROFILE_GENDER`]. A value this revision does not define is
    /// stored as `Unspecified`, never refused.
    Gender {
        Unspecified = 0,
        Female = 1,
        Male = 2,
        Other = 3,
    }
}

/// [`tag::PROFILE_BIRTHDATE`]: each part 0 when not given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Birthdate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl Birthdate {
    /// Decode the four bytes; `None` for another length or an impossible
    /// month or day.
    pub fn parse(data: &[u8]) -> Option<Birthdate> {
        let b: [u8; 4] = data.try_into().ok()?;
        let d = Birthdate {
            year: u16::from_be_bytes([b[0], b[1]]),
            month: b[2],
            day: b[3],
        };
        d.is_possible().then_some(d)
    }

    /// The four bytes, `year:2 | month:1 | day:1`.
    pub fn to_bytes(self) -> [u8; 4] {
        let y = self.year.to_be_bytes();
        [y[0], y[1], self.month, self.day]
    }

    /// Whether the given parts can name a day. A day of February 29 is
    /// possible when the year is not given, since some year it was.
    fn is_possible(self) -> bool {
        let leap = self.year == 0
            || (self.year % 4 == 0 && (self.year % 100 != 0 || self.year % 400 == 0));
        let days = match self.month {
            0 => 31,
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            1..=12 => 31,
            _ => return false,
        };
        self.day <= days
    }
}

/// Why a parser refused a message.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// The message ends inside a field, or before its header does.
    Truncated,
    /// A field of a group came before the field that opens one.
    NoDelimiter(u16),
    /// A field this shape knows, at a length its type does not allow.
    Width(u16),
    /// A field the shape requires is absent.
    Missing(u16),
    /// A field that appears once per group appeared again.
    Repeated(u16),
    /// A field in a group that does not take it.
    Misplaced(u16),
}

// ---- Framing -------------------------------------------------------------

/// The fields of a message, every one checked to fit: [`ChunkIter`]
/// stops quietly at a field cut short, which in a listing would read as
/// a shorter list.
fn body(buf: &[u8], len: usize) -> Result<&[u8], Malformed> {
    let end = len.min(buf.len());
    if end < HL_HDR_LEN {
        return Err(Malformed::Truncated);
    }
    let body = &buf[HL_HDR_LEN..end];
    let mut pos = 0;
    while pos < body.len() {
        let hdr = body.get(pos..pos + 4).ok_or(Malformed::Truncated)?;
        pos += 4 + u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        if pos > body.len() {
            return Err(Malformed::Truncated);
        }
    }
    Ok(body)
}

/// The field at `pos` of a checked body, and where the next begins.
fn field_at(body: &[u8], pos: usize) -> Option<(Chunk<'_>, usize)> {
    let c = ChunkIter::at(body, pos).next()?;
    Some((c, pos + 4 + c.data.len()))
}

fn next_delimiter(body: &[u8], mut pos: usize, delim: fn(u16) -> bool) -> usize {
    while let Some((c, next)) = field_at(body, pos) {
        if delim(c.tag) {
            return pos;
        }
        pos = next;
    }
    body.len()
}

/// The groups of a checked body: each delimiter, and the fields after it
/// up to the next delimiter or the end.
#[derive(Debug, Clone)]
struct Groups<'a> {
    body: &'a [u8],
    pos: usize,
    delim: fn(u16) -> bool,
}

/// Split a checked body into what comes before its first delimiter, and
/// its groups.
fn split(body: &[u8], delim: fn(u16) -> bool) -> (&[u8], Groups<'_>) {
    let start = next_delimiter(body, 0, delim);
    (
        &body[..start],
        Groups {
            body,
            pos: start,
            delim,
        },
    )
}

impl<'a> Iterator for Groups<'a> {
    type Item = (Chunk<'a>, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let (head, after) = field_at(self.body, self.pos)?;
        let end = next_delimiter(self.body, after, self.delim);
        self.pos = end;
        Some((head, &self.body[after..end]))
    }
}

fn fields(group: &[u8]) -> ChunkIter<'_> {
    ChunkIter::at(group, 0)
}

/// A UInt16 field, or the 4 bytes a Hotline integer is often sent as,
/// when its value fits.
fn u16_of(c: &Chunk<'_>) -> Result<u16, Malformed> {
    match c.data.len() {
        2 | 4 => u16::try_from(c.as_uint()).map_err(|_| Malformed::Width(c.tag)),
        _ => Err(Malformed::Width(c.tag)),
    }
}

/// A UInt32 field, or the 2 bytes a Hotline integer that fits in them
/// may be sent as.
fn u32_of(c: &Chunk<'_>) -> Result<u32, Malformed> {
    match c.data.len() {
        2 | 4 => Ok(c.as_uint()),
        _ => Err(Malformed::Width(c.tag)),
    }
}

fn u64_of(c: &Chunk<'_>) -> Result<u64, Malformed> {
    <[u8; 8]>::try_from(c.data)
        .map(u64::from_be_bytes)
        .map_err(|_| Malformed::Width(c.tag))
}

fn fixed<'a, const N: usize>(c: &Chunk<'a>) -> Result<&'a [u8; N], Malformed> {
    <&[u8; N]>::try_from(c.data).map_err(|_| Malformed::Width(c.tag))
}

fn once<T>(slot: &mut Option<T>, tag: u16, v: T) -> Result<(), Malformed> {
    if slot.is_some() {
        return Err(Malformed::Repeated(tag));
    }
    *slot = Some(v);
    Ok(())
}

fn login_of<'a>(head: &Chunk<'a>) -> Result<&'a [u8], Malformed> {
    if head.data.is_empty() {
        return Err(Malformed::Width(head.tag));
    }
    Ok(head.data)
}

fn fits(b: &[u8]) -> bool {
    b.len() <= u16::MAX as usize
}

// ---- Roster entries ------------------------------------------------------

/// One entry group, opened by [`tag::FRIEND_LOGIN`]: a roster entry
/// (800, 801), a friend request (804), a presence change (809), or a
/// discovery result (822, 823). Each carries the subset its transaction
/// gives; an absent field is one the entry does not have. Strings are in
/// the connection's text encoding; enumerations are kept as sent, so a
/// state a later revision adds is not lost.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RosterEntry<'a> {
    pub login: &'a [u8],
    pub nickname: Option<&'a [u8]>,
    /// See [`RosterEntry::roster_state`].
    pub state: Option<u16>,
    /// See [`RosterEntry::presence_state`].
    pub presence: Option<u16>,
    pub status_text: Option<&'a [u8]>,
    pub capabilities: Option<u64>,
    /// [`tag::NAME`]: the name the friend goes by.
    pub name: Option<&'a [u8]>,
    pub icon_hash: Option<&'a [u8; ICON_HASH_LEN]>,
    /// Identity draft: the fingerprint of the identity linked to the
    /// account.
    pub identity: Option<&'a [u8; HASH_LEN]>,
    /// Identity draft version 2: the friendships the parties presented,
    /// one or two.
    pub friendship_hashes: [Option<&'a [u8; HASH_LEN]>; 2],
    /// Identity draft version 2: the withdrawal a `Removed` entry carries.
    pub withdrawal: Option<&'a [u8]>,
    /// A friend request's note (804).
    pub note: Option<&'a [u8]>,
    /// Identity draft version 2: a friend request's offer (804).
    pub offer: Option<&'a [u8]>,
}

impl<'a> RosterEntry<'a> {
    pub fn roster_state(&self) -> Option<RosterState> {
        self.state.and_then(RosterState::from_wire)
    }

    pub fn presence_state(&self) -> Option<PresenceState> {
        self.presence.and_then(PresenceState::from_wire)
    }

    fn from_group(head: Chunk<'a>, group: &'a [u8]) -> Result<Self, Malformed> {
        let mut e = RosterEntry {
            login: login_of(&head)?,
            ..RosterEntry::default()
        };
        for c in fields(group) {
            let t = c.tag;
            match t {
                tag::FRIEND_NICKNAME => once(&mut e.nickname, t, c.data)?,
                tag::ROSTER_STATE => once(&mut e.state, t, u16_of(&c)?)?,
                tag::PRESENCE_STATE => once(&mut e.presence, t, u16_of(&c)?)?,
                tag::PRESENCE_STATUS_TEXT => once(&mut e.status_text, t, c.data)?,
                // Read however wide, as the login's is: the spec types it
                // UInt16, which cannot carry a capability past bit 15.
                tag::FRIEND_CAPABILITIES => {
                    once(&mut e.capabilities, t, capabilities_decode(c.data))?
                }
                tag::NAME => once(&mut e.name, t, c.data)?,
                tag::BUDDY_ICON_HASH => once(&mut e.icon_hash, t, fixed(&c)?)?,
                tag::FRIEND_IDENTITY => once(&mut e.identity, t, fixed(&c)?)?,
                tag::FRIENDSHIP_HASH => {
                    let h = fixed(&c)?;
                    let slot = e
                        .friendship_hashes
                        .iter_mut()
                        .find(|s| s.is_none())
                        .ok_or(Malformed::Repeated(t))?;
                    *slot = Some(h);
                }
                tag::FRIEND_WITHDRAW => once(&mut e.withdrawal, t, c.data)?,
                tag::REQUEST_NOTE => once(&mut e.note, t, c.data)?,
                tag::FRIEND_OFFER => once(&mut e.offer, t, c.data)?,
                _ => {}
            }
        }
        Ok(e)
    }

    /// Append the entry's fields to `out`, [`tag::FRIEND_LOGIN`] first, and
    /// return how many there were; `None`, with nothing written, for an
    /// empty Login or a field too long for its 16-bit length. One routine
    /// for a snapshot entry and a delta, so the two are byte-identical as
    /// the extension asks.
    pub fn encode(&self, out: &mut Encoder) -> Option<u16> {
        let texts = [
            Some(self.login),
            self.nickname,
            self.status_text,
            self.name,
            self.withdrawal,
            self.note,
            self.offer,
        ];
        if self.login.is_empty() || !texts.iter().flatten().all(|t| fits(t)) {
            return None;
        }
        let mut caps = [0u8; 8];
        let mut n = 0u16;
        let mut put = |t: u16, data: &[u8]| {
            out.put_chunk(t, data);
            n += 1;
        };
        put(tag::FRIEND_LOGIN, self.login);
        if let Some(v) = self.nickname {
            put(tag::FRIEND_NICKNAME, v);
        }
        if let Some(v) = self.state {
            put(tag::ROSTER_STATE, &v.to_be_bytes());
        }
        if let Some(v) = self.presence {
            put(tag::PRESENCE_STATE, &v.to_be_bytes());
        }
        if let Some(v) = self.status_text {
            put(tag::PRESENCE_STATUS_TEXT, v);
        }
        // The narrowest width, which is the spec's UInt16 for every
        // capability that fits in one.
        if let Some(v) = self.capabilities {
            put(tag::FRIEND_CAPABILITIES, capabilities_encode(v, &mut caps));
        }
        if let Some(v) = self.name {
            put(tag::NAME, v);
        }
        if let Some(v) = self.icon_hash {
            put(tag::BUDDY_ICON_HASH, v);
        }
        if let Some(v) = self.identity {
            put(tag::FRIEND_IDENTITY, v);
        }
        for h in self.friendship_hashes.iter().flatten() {
            put(tag::FRIENDSHIP_HASH, *h);
        }
        if let Some(v) = self.withdrawal {
            put(tag::FRIEND_WITHDRAW, v);
        }
        if let Some(v) = self.note {
            put(tag::REQUEST_NOTE, v);
        }
        if let Some(v) = self.offer {
            put(tag::FRIEND_OFFER, v);
        }
        Some(n)
    }
}

fn is_friend_login(t: u16) -> bool {
    t == tag::FRIEND_LOGIN
}

/// A listing of entry groups: a Get Roster (800) reply, or a Find User
/// (822) or User Search (823) reply.
#[derive(Debug, Clone)]
pub struct Roster<'a> {
    /// The reason code that precedes the entries, where there is one.
    pub reason: Option<u16>,
    groups: Groups<'a>,
}

impl<'a> Roster<'a> {
    /// The entries, in the order sent.
    pub fn entries(&self) -> impl Iterator<Item = RosterEntry<'a>> + 'a {
        self.groups
            .clone()
            .filter_map(|(head, group)| RosterEntry::from_group(head, group).ok())
    }
}

/// Parse a listing of entry groups from the whole message (`buf`, with
/// `len` valid bytes, header included). What comes before the first
/// [`tag::FRIEND_LOGIN`] is the listing's, never an entry's: its reason
/// code is kept and the rest ignored, as the extension's Reply Shape has
/// it.
pub fn parse_roster(buf: &[u8], len: usize) -> Result<Roster<'_>, Malformed> {
    let (prelude, groups) = split(body(buf, len)?, is_friend_login);
    let mut reason = None;
    for c in fields(prelude) {
        if c.tag == tag::REASON_CODE {
            once(&mut reason, c.tag, u16_of(&c)?)?;
        }
    }
    for (head, group) in groups.clone() {
        RosterEntry::from_group(head, group)?;
    }
    Ok(Roster { reason, groups })
}

/// Parse a transaction that carries one entry: a Roster Entry (801), a
/// Friend Request (804) or a Presence Changed (809). Its fields may come
/// in any order, since a lone entry needs no delimiter; a second
/// [`tag::FRIEND_LOGIN`] is malformed.
pub fn parse_entry(buf: &[u8], len: usize) -> Result<RosterEntry<'_>, Malformed> {
    let body = body(buf, len)?;
    let mut logins = fields(body).filter(|c| is_friend_login(c.tag));
    let head = logins.next().ok_or(Malformed::Missing(tag::FRIEND_LOGIN))?;
    if logins.next().is_some() {
        return Err(Malformed::Repeated(tag::FRIEND_LOGIN));
    }
    RosterEntry::from_group(head, body)
}

// ---- Message requests ----------------------------------------------------

/// A Get Message Requests (829) reply: what precedes its groups, then a
/// group per sender and per approval.
#[derive(Debug, Clone)]
pub struct MessageRequests<'a> {
    /// The caller's own setting, on the first page.
    pub takes_requests: Option<bool>,
    /// On the first page, the requests and friend requests dropped since
    /// the last listing.
    pub dropped: Option<u32>,
    /// Where there is another page.
    pub cursor: Option<&'a [u8]>,
    groups: Groups<'a>,
}

impl<'a> MessageRequests<'a> {
    /// Senders oldest first, then approvals.
    pub fn groups(&self) -> impl Iterator<Item = RequestGroup<'a>> + 'a {
        self.groups
            .clone()
            .filter_map(|(head, group)| RequestGroup::from_group(head, group).ok())
    }
}

/// One group of a Get Message Requests reply: a sender with its waiting
/// messages, or an approval, given or held, with none.
#[derive(Debug, Clone)]
pub struct RequestGroup<'a> {
    pub login: &'a [u8],
    pub identity: Option<&'a [u8; HASH_LEN]>,
    /// [`RosterState::Accepted`] on an approval.
    pub state: Option<u16>,
    group: &'a [u8],
}

impl<'a> RequestGroup<'a> {
    pub fn is_approval(&self) -> bool {
        self.state == Some(RosterState::Accepted.wire()) && self.messages().next().is_none()
    }

    /// The waiting messages, oldest first.
    pub fn messages(&self) -> impl Iterator<Item = RequestMessage<'a>> + 'a {
        split(self.group, is_message_guid)
            .1
            .filter_map(|(head, msg)| RequestMessage::from_group(head, msg).ok())
    }

    fn from_group(head: Chunk<'a>, group: &'a [u8]) -> Result<Self, Malformed> {
        let mut g = RequestGroup {
            login: login_of(&head)?,
            identity: None,
            state: None,
            group,
        };
        let mut in_message = false;
        for c in fields(group) {
            let t = c.tag;
            match t {
                tag::FRIEND_IDENTITY | tag::ROSTER_STATE if in_message => {
                    return Err(Malformed::Misplaced(t))
                }
                tag::FRIEND_IDENTITY => once(&mut g.identity, t, fixed(&c)?)?,
                tag::ROSTER_STATE => once(&mut g.state, t, u16_of(&c)?)?,
                tag::MESSAGE_GUID => in_message = true,
                _ if is_message_field(t) && !in_message => return Err(Malformed::NoDelimiter(t)),
                _ => {}
            }
        }
        for (head, msg) in split(group, is_message_guid).1 {
            RequestMessage::from_group(head, msg)?;
        }
        Ok(g)
    }
}

fn is_message_guid(t: u16) -> bool {
    t == tag::MESSAGE_GUID
}

fn is_message_field(t: u16) -> bool {
    matches!(
        t,
        tag::MESSAGE_BODY | tag::MESSAGE_TIMESTAMP | tag::MESSAGE_SIGNED
    )
}

/// One waiting message of a request, opened by its [`tag::MESSAGE_GUID`],
/// which with the sender names it for a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestMessage<'a> {
    pub guid: &'a [u8; GUID_LEN],
    pub body: &'a [u8],
    /// Unix seconds.
    pub timestamp: u64,
    /// Identity draft: the signed form, detached, where it was signed.
    pub signed: Option<&'a [u8]>,
}

impl<'a> RequestMessage<'a> {
    fn from_group(head: Chunk<'a>, group: &'a [u8]) -> Result<Self, Malformed> {
        let guid = fixed(&head)?;
        let (mut body, mut timestamp, mut signed) = (None, None, None);
        for c in fields(group) {
            match c.tag {
                tag::MESSAGE_BODY => once(&mut body, c.tag, c.data)?,
                tag::MESSAGE_TIMESTAMP => once(&mut timestamp, c.tag, u64_of(&c)?)?,
                tag::MESSAGE_SIGNED => once(&mut signed, c.tag, c.data)?,
                _ => {}
            }
        }
        Ok(RequestMessage {
            guid,
            body: body.ok_or(Malformed::Missing(tag::MESSAGE_BODY))?,
            timestamp: timestamp.ok_or(Malformed::Missing(tag::MESSAGE_TIMESTAMP))?,
            signed,
        })
    }

    /// Append the message's fields to `out`, its GUID first, and return
    /// how many there were; `None`, with nothing written, for a field too
    /// long for its 16-bit length.
    pub fn encode(&self, out: &mut Encoder) -> Option<u16> {
        if !fits(self.body) || !self.signed.is_none_or(fits) {
            return None;
        }
        out.put_chunk(tag::MESSAGE_GUID, self.guid)
            .put_chunk(tag::MESSAGE_BODY, self.body)
            .put_chunk(tag::MESSAGE_TIMESTAMP, &self.timestamp.to_be_bytes());
        if let Some(s) = self.signed {
            out.put_chunk(tag::MESSAGE_SIGNED, s);
        }
        Some(3 + u16::from(self.signed.is_some()))
    }
}

/// Parse a Get Message Requests (829) reply from the whole message, in
/// the draft's order: the listing's fields, then each group's own, then
/// its messages. A group's or a message's field before what opens it, a
/// group's field among its messages, or a message without its body or
/// timestamp, is malformed.
pub fn parse_message_requests(buf: &[u8], len: usize) -> Result<MessageRequests<'_>, Malformed> {
    let (prelude, groups) = split(body(buf, len)?, is_friend_login);
    let mut out = MessageRequests {
        takes_requests: None,
        dropped: None,
        cursor: None,
        groups,
    };
    for c in fields(prelude) {
        let t = c.tag;
        match t {
            tag::TAKES_REQUESTS => once(&mut out.takes_requests, t, u16_of(&c)? != 0)?,
            tag::REQUEST_COUNT => once(&mut out.dropped, t, u32_of(&c)?)?,
            tag::REQUEST_CURSOR => once(&mut out.cursor, t, c.data)?,
            _ if is_message_field(t)
                || matches!(
                    t,
                    tag::MESSAGE_GUID | tag::FRIEND_IDENTITY | tag::ROSTER_STATE
                ) =>
            {
                return Err(Malformed::NoDelimiter(t))
            }
            _ => {}
        }
    }
    for (head, group) in out.groups.clone() {
        RequestGroup::from_group(head, group)?;
    }
    Ok(out)
}

// ---- Friendships ---------------------------------------------------------

fn is_friendship_hash(t: u16) -> bool {
    t == tag::FRIENDSHIP_HASH
}

/// One object's outcome in a Present Friendships (833) reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presented<'a> {
    /// The friendship hash, or for a withdrawal its pair hash.
    pub hash: &'a [u8; HASH_LEN],
    /// See [`Presented::reason_code`].
    pub reason: u16,
    /// The withdrawal behind a `Withdrawn`, where there is one.
    pub withdrawal: Option<&'a [u8]>,
}

impl Presented<'_> {
    pub fn reason_code(&self) -> Option<ReasonCode> {
        ReasonCode::from_wire(self.reason)
    }
}

/// A Present Friendships (833) reply.
#[derive(Debug, Clone)]
pub struct PresentFriendships<'a> {
    groups: Groups<'a>,
}

impl<'a> PresentFriendships<'a> {
    pub fn outcomes(&self) -> impl Iterator<Item = Presented<'a>> + 'a {
        self.groups
            .clone()
            .filter_map(|(head, group)| presented(head, group).ok())
    }
}

fn presented<'a>(head: Chunk<'a>, group: &'a [u8]) -> Result<Presented<'a>, Malformed> {
    let (mut reason, mut withdrawal) = (None, None);
    for c in fields(group) {
        match c.tag {
            tag::REASON_CODE => once(&mut reason, c.tag, u16_of(&c)?)?,
            tag::FRIEND_WITHDRAW => once(&mut withdrawal, c.tag, c.data)?,
            _ => {}
        }
    }
    Ok(Presented {
        hash: fixed(&head)?,
        reason: reason.ok_or(Malformed::Missing(tag::REASON_CODE))?,
        withdrawal,
    })
}

/// Parse a Present Friendships (833) reply from the whole message: a
/// group per object, each with its reason code.
pub fn parse_present_friendships(
    buf: &[u8],
    len: usize,
) -> Result<PresentFriendships<'_>, Malformed> {
    let (_, groups) = split(body(buf, len)?, is_friendship_hash);
    for (head, group) in groups.clone() {
        presented(head, group)?;
    }
    Ok(PresentFriendships { groups })
}

/// One answer in a Get Friendships (834) reply, delimited by the field it
/// answers.
#[derive(Debug, Clone)]
pub enum FriendshipAnswer<'a> {
    /// A friendship hash, and the friendship where the caller may have
    /// it.
    Friendship {
        hash: &'a [u8; HASH_LEN],
        friendship: Option<&'a [u8]>,
    },
    /// A fingerprint, and the rotation records behind it.
    Rotations {
        identity: &'a [u8; HASH_LEN],
        records: Rotations<'a>,
    },
}

/// A fingerprint's rotation records, in chain order.
#[derive(Debug, Clone)]
pub struct Rotations<'a>(ChunkIter<'a>);

impl<'a> Iterator for Rotations<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        self.0
            .by_ref()
            .find(|c| c.tag == tag::IDENTITY_ROTATION)
            .map(|c| c.data)
    }
}

/// A Get Friendships (834) reply.
#[derive(Debug, Clone)]
pub struct Friendships<'a> {
    groups: Groups<'a>,
}

impl<'a> Friendships<'a> {
    pub fn answers(&self) -> impl Iterator<Item = FriendshipAnswer<'a>> + 'a {
        self.groups
            .clone()
            .filter_map(|(head, group)| answer(head, group).ok())
    }
}

fn answer<'a>(head: Chunk<'a>, group: &'a [u8]) -> Result<FriendshipAnswer<'a>, Malformed> {
    if head.tag == tag::FRIEND_IDENTITY {
        if let Some(c) = fields(group).find(|c| c.tag == tag::FRIENDSHIP) {
            return Err(Malformed::Misplaced(c.tag));
        }
        return Ok(FriendshipAnswer::Rotations {
            identity: fixed(&head)?,
            records: Rotations(fields(group)),
        });
    }
    let mut friendship = None;
    for c in fields(group) {
        match c.tag {
            tag::FRIENDSHIP => once(&mut friendship, c.tag, c.data)?,
            tag::IDENTITY_ROTATION => return Err(Malformed::Misplaced(c.tag)),
            _ => {}
        }
    }
    Ok(FriendshipAnswer::Friendship {
        hash: fixed(&head)?,
        friendship,
    })
}

/// Parse a Get Friendships (834) reply from the whole message.
pub fn parse_friendships(buf: &[u8], len: usize) -> Result<Friendships<'_>, Malformed> {
    let (_, groups) = split(body(buf, len)?, |t| {
        t == tag::FRIENDSHIP_HASH || t == tag::FRIEND_IDENTITY
    });
    for (head, group) in groups.clone() {
        answer(head, group)?;
    }
    Ok(Friendships { groups })
}

// ---- Server limits -------------------------------------------------------

/// The server limits a login reply advertises beside a confirmed
/// [`CAP_MESSAGING`], each as sent. The accessors give what a client
/// should hold the user to.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_message_bytes: Option<u32>,
    pub max_roster_size: Option<u32>,
    pub max_offline_queue: Option<u32>,
    pub max_icon_bytes: Option<u32>,
    pub max_icon_dimension: Option<u32>,
    pub max_request_messages: Option<u32>,
}

/// An advertised limit, or the default where it is absent or 0, which for
/// these is not a meaningful value.
fn or_default(v: Option<u32>, default: u32) -> u32 {
    v.filter(|&v| v != 0).unwrap_or(default)
}

impl Limits {
    /// Pick the limits out of a login reply (`buf`, with `len` valid
    /// bytes, header included). A field of a width a UInt32 cannot have
    /// is read as absent, as [`crate::parse::parse_login`] reads one,
    /// leaving the client at the default rather than refusing the login;
    /// a limit sent twice is read as the last of a width it can have,
    /// for the same reason.
    pub fn extract(buf: &[u8], len: usize) -> Limits {
        let mut out = Limits::default();
        for c in ChunkIter::over_message(buf, len) {
            let slot = match c.tag {
                tag::MAX_MESSAGE_BYTES => &mut out.max_message_bytes,
                tag::MAX_ROSTER_SIZE => &mut out.max_roster_size,
                tag::MAX_OFFLINE_QUEUE => &mut out.max_offline_queue,
                tag::MAX_ICON_BYTES => &mut out.max_icon_bytes,
                tag::MAX_ICON_DIMENSION => &mut out.max_icon_dimension,
                tag::MAX_REQUEST_MESSAGES => &mut out.max_request_messages,
                _ => continue,
            };
            if let Ok(v) = u32_of(&c) {
                *slot = Some(v);
            }
        }
        out
    }

    /// Most bytes in a message's encoded body, not its characters.
    pub fn message_bytes(&self) -> u32 {
        or_default(self.max_message_bytes, DEFAULT_MAX_MESSAGE_BYTES)
    }

    pub fn roster_size(&self) -> u32 {
        or_default(self.max_roster_size, DEFAULT_MAX_ROSTER_SIZE)
    }

    pub fn offline_queue(&self) -> u32 {
        or_default(self.max_offline_queue, DEFAULT_MAX_OFFLINE_QUEUE)
    }

    /// The icon byte limit, or `None` where the server has no buddy
    /// icons: its absence says so, rather than calling for a default.
    pub fn icon_bytes(&self) -> Option<u32> {
        self.max_icon_bytes
    }

    pub fn icon_dimension(&self) -> u32 {
        or_default(self.max_icon_dimension, DEFAULT_MAX_ICON_DIMENSION)
    }

    /// Messages a request may hold, or `None` where the server takes no
    /// message requests: its absence says so.
    pub fn request_messages(&self) -> Option<u32> {
        self.max_request_messages
    }

    /// Append the limits that are set to `out` and return how many.
    pub fn encode(&self, out: &mut Encoder) -> u16 {
        let all = [
            (tag::MAX_MESSAGE_BYTES, self.max_message_bytes),
            (tag::MAX_ROSTER_SIZE, self.max_roster_size),
            (tag::MAX_OFFLINE_QUEUE, self.max_offline_queue),
            (tag::MAX_ICON_BYTES, self.max_icon_bytes),
            (tag::MAX_ICON_DIMENSION, self.max_icon_dimension),
            (tag::MAX_REQUEST_MESSAGES, self.max_request_messages),
        ];
        let mut n = 0;
        for (t, v) in all {
            if let Some(v) = v {
                out.put_chunk(t, &v.to_be_bytes());
                n += 1;
            }
        }
        n
    }
}

// ---- Outgoing builders ---------------------------------------------------

/// Fills a builder's chunks: payloads in place, integers copied into its
/// scratch. Integer chunks get their pointers only once every integer is
/// written, so no pointer is taken into scratch that is written after.
struct Fill<'c> {
    chunks: &'c mut [HxChunk],
    n: usize,
    scratch: &'c mut [u8],
    used: usize,
    ints: [(usize, usize); 4],
    n_ints: usize,
}

impl Fill<'_> {
    fn put(&mut self, tag: u16, data: &[u8]) -> Option<()> {
        let len = u16::try_from(data.len()).ok()?;
        *self.chunks.get_mut(self.n)? = HxChunk {
            tag,
            len,
            data: data.as_ptr(),
        };
        self.n += 1;
        Some(())
    }

    fn put_int(&mut self, tag: u16, be: &[u8]) -> Option<()> {
        let at = self.used;
        self.scratch.get_mut(at..at + be.len())?.copy_from_slice(be);
        *self.ints.get_mut(self.n_ints)? = (self.n, at);
        *self.chunks.get_mut(self.n)? = HxChunk {
            tag,
            len: be.len() as u16,
            data: std::ptr::null(),
        };
        self.used += be.len();
        self.n_ints += 1;
        self.n += 1;
        Some(())
    }
}

fn build(
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
    fill: impl FnOnce(&mut Fill<'_>) -> Option<()>,
) -> usize {
    let mut f = Fill {
        chunks,
        n: 0,
        scratch,
        used: 0,
        ints: [(0, 0); 4],
        n_ints: 0,
    };
    if fill(&mut f).is_none() {
        return 0;
    }
    for &(slot, at) in &f.ints[..f.n_ints] {
        f.chunks[slot].data = f.scratch[at..].as_ptr();
    }
    f.n
}

fn nonempty(b: &[u8]) -> Option<&[u8]> {
    (!b.is_empty()).then_some(b)
}

fn at_most(b: &[u8], max: usize) -> Option<&[u8]> {
    (b.len() <= max).then_some(b)
}

/// Whom a request names: a Login, or, where the identity draft allows it
/// in place of one, a fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who<'a> {
    Login(&'a [u8]),
    Identity(&'a [u8; HASH_LEN]),
}

fn put_who(f: &mut Fill<'_>, who: Who<'_>) -> Option<()> {
    match who {
        Who::Login(l) => f.put(tag::FRIEND_LOGIN, nonempty(l)?),
        Who::Identity(fp) => f.put(tag::FRIEND_IDENTITY, fp),
    }
}

/// Add Friend (802): `login`, with an optional note and, from a device
/// that makes portable friendships, an offer. Up to 3 chunks.
pub fn build_add_friend_chunks(
    login: &[u8],
    note: Option<&[u8]>,
    offer: Option<&[u8]>,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::FRIEND_LOGIN, nonempty(login)?)?;
        if let Some(n) = note {
            f.put(tag::REQUEST_NOTE, n)?;
        }
        if let Some(o) = offer {
            f.put(tag::FRIEND_OFFER, at_most(o, MAX_OFFER_LEN)?)?;
        }
        Some(())
    })
}

/// Remove Friend (803). `who` is a fingerprint only for a party the
/// caller holds no Login for (identity draft, hidden links). An `offer`
/// cancels that upgrade offer alone; a `withdrawal` ends the friendship
/// everywhere it is presented. The two mean different things, so both
/// together are refused. Up to 2 chunks.
pub fn build_remove_friend_chunks(
    who: Who<'_>,
    offer: Option<&[u8]>,
    withdrawal: Option<&[u8]>,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        (offer.is_none() || withdrawal.is_none()).then_some(())?;
        put_who(f, who)?;
        if let Some(o) = offer {
            f.put(tag::FRIEND_OFFER, at_most(o, MAX_OFFER_LEN)?)?;
        }
        if let Some(w) = withdrawal {
            f.put(tag::FRIEND_WITHDRAW, at_most(w, MAX_OFFER_LEN)?)?;
        }
        Some(())
    })
}

/// Friend Response (805): accept `login`'s request, with the whole
/// `friendship` when accepting an offer, or reject it, which sends no
/// state. A friendship beside a rejection is refused. Up to 3 chunks.
pub fn build_friend_response_chunks(
    login: &[u8],
    accept: bool,
    friendship: Option<&[u8]>,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::FRIEND_LOGIN, nonempty(login)?)?;
        if accept {
            f.put_int(
                tag::ROSTER_STATE,
                &RosterState::Accepted.wire().to_be_bytes(),
            )?;
        }
        if let Some(fs) = friendship {
            accept.then_some(())?;
            f.put(tag::FRIENDSHIP, at_most(fs, MAX_FRIENDSHIP_LEN)?)?;
        }
        Some(())
    })
}

/// Block User (806), with a withdrawal from a device that makes portable
/// friendships. Up to 2 chunks.
pub fn build_block_user_chunks(
    login: &[u8],
    withdrawal: Option<&[u8]>,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::FRIEND_LOGIN, nonempty(login)?)?;
        if let Some(w) = withdrawal {
            f.put(tag::FRIEND_WITHDRAW, at_most(w, MAX_OFFER_LEN)?)?;
        }
        Some(())
    })
}

/// A request that names one Login and nothing else: Unblock User (807)
/// and Get User Info (825). 1 chunk.
pub fn build_login_only_chunks(login: &[u8], chunks: &mut [HxChunk], scratch: &mut [u8]) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::FRIEND_LOGIN, nonempty(login)?)
    })
}

/// Set Presence (808).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presence<'a> {
    /// Never [`PresenceState::Offline`], which a client does not set for
    /// itself.
    pub state: PresenceState,
    /// `None` leaves the stored text as it is; `Some(b"")` clears it. The
    /// two are different requests.
    pub status_text: Option<&'a [u8]>,
    pub discoverable: Option<bool>,
    /// Message requests draft.
    pub takes_requests: Option<bool>,
}

/// Set Presence (808). Up to 4 chunks.
pub fn build_set_presence_chunks(
    p: &Presence<'_>,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        (p.state != PresenceState::Offline).then_some(())?;
        f.put_int(tag::PRESENCE_STATE, &p.state.wire().to_be_bytes())?;
        if let Some(t) = p.status_text {
            f.put(tag::PRESENCE_STATUS_TEXT, t)?;
        }
        if let Some(d) = p.discoverable {
            f.put_int(tag::DISCOVERABLE, &u16::from(d).to_be_bytes())?;
        }
        if let Some(t) = p.takes_requests {
            f.put_int(tag::TAKES_REQUESTS, &u16::from(t).to_be_bytes())?;
        }
        Some(())
    })
}

/// What an instant message carries, in one of the identity draft's
/// forms; only `Plain` without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImContent<'a> {
    Plain(&'a [u8]),
    /// The body, and its signed form, detached.
    Signed {
        body: &'a [u8],
        signed: &'a [u8],
    },
    /// Sealed to one device: no body travels beside it.
    Sealed {
        sealed: &'a [u8],
        sealed_to: &'a [u8; HASH_LEN],
    },
}

/// IM Send (810).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImSend<'a> {
    pub to: &'a [u8],
    pub guid: &'a [u8; GUID_LEN],
    pub content: ImContent<'a>,
}

/// IM Send (810). Up to 4 chunks.
pub fn build_im_send_chunks(m: &ImSend<'_>, chunks: &mut [HxChunk], scratch: &mut [u8]) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::FRIEND_LOGIN, nonempty(m.to)?)?;
        f.put(tag::MESSAGE_GUID, m.guid)?;
        match m.content {
            ImContent::Plain(body) => f.put(tag::MESSAGE_BODY, body),
            ImContent::Signed { body, signed } => {
                f.put(tag::MESSAGE_BODY, body)?;
                f.put(tag::MESSAGE_SIGNED, at_most(signed, MAX_SIGNED_LEN)?)
            }
            ImContent::Sealed { sealed, sealed_to } => {
                f.put(tag::MESSAGE_SEALED, at_most(sealed, MAX_SEALED_LEN)?)?;
                f.put(tag::MESSAGE_SEALED_TO, sealed_to)
            }
        }
    })
}

/// IM Acknowledge (812): a receipt for `guid`, to its `sender`. 3 chunks.
pub fn build_im_ack_chunks(
    guid: &[u8; GUID_LEN],
    ack: AckType,
    sender: &[u8],
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::MESSAGE_GUID, guid)?;
        f.put_int(tag::ACK_TYPE, &ack.wire().to_be_bytes())?;
        f.put(tag::FRIEND_LOGIN, nonempty(sender)?)
    })
}

/// IM Typing (813) to `login`. 2 chunks.
pub fn build_im_typing_chunks(
    login: &[u8],
    state: TypingState,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::FRIEND_LOGIN, nonempty(login)?)?;
        f.put_int(tag::TYPING_STATE, &state.wire().to_be_bytes())
    })
}

/// Find User (822), by exact Login or by fingerprint. 1 chunk.
pub fn build_find_user_chunks(who: Who<'_>, chunks: &mut [HxChunk], scratch: &mut [u8]) -> usize {
    build(chunks, scratch, |f| put_who(f, who))
}

/// User Search (823). 1 chunk.
pub fn build_user_search_chunks(query: &[u8], chunks: &mut [HxChunk], scratch: &mut [u8]) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::SEARCH_QUERY, nonempty(query)?)
    })
}

/// Set Friend Nickname (824): an empty `nickname` clears the alias, and is
/// still sent. 2 chunks.
pub fn build_set_friend_nickname_chunks(
    login: &[u8],
    nickname: &[u8],
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::FRIEND_LOGIN, nonempty(login)?)?;
        f.put(tag::FRIEND_NICKNAME, nickname)
    })
}

/// Set User Info (826): the caller's whole profile, which replaces what
/// the server holds; an absent field clears that entry.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Profile<'a> {
    pub nickname: Option<&'a [u8]>,
    pub first_name: Option<&'a [u8]>,
    pub last_name: Option<&'a [u8]>,
    pub email: Option<&'a [u8]>,
    pub gender: Option<Gender>,
    pub birthdate: Option<Birthdate>,
    pub country: Option<&'a [u8]>,
    pub postcode: Option<&'a [u8]>,
    /// At most [`MAX_LANGUAGES`].
    pub languages: &'a [&'a [u8]],
}

/// Set User Info (826). Up to 11 chunks; an impossible birth date or
/// more than [`MAX_LANGUAGES`] languages is refused.
pub fn build_set_profile_chunks(
    p: &Profile<'_>,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        (p.languages.len() <= MAX_LANGUAGES).then_some(())?;
        let texts = [
            (tag::PROFILE_NICKNAME, p.nickname),
            (tag::PROFILE_FIRST_NAME, p.first_name),
            (tag::PROFILE_LAST_NAME, p.last_name),
            (tag::PROFILE_EMAIL, p.email),
        ];
        for (t, v) in texts {
            if let Some(v) = v {
                f.put(t, v)?;
            }
        }
        if let Some(g) = p.gender {
            f.put_int(tag::PROFILE_GENDER, &g.wire().to_be_bytes())?;
        }
        if let Some(d) = p.birthdate {
            d.is_possible().then_some(())?;
            f.put_int(tag::PROFILE_BIRTHDATE, &d.to_bytes())?;
        }
        for (t, v) in [
            (tag::PROFILE_COUNTRY, p.country),
            (tag::PROFILE_POSTCODE, p.postcode),
        ] {
            if let Some(v) = v {
                f.put(t, v)?;
            }
        }
        for l in p.languages {
            f.put(tag::PROFILE_LANGUAGE, l)?;
        }
        Some(())
    })
}

/// Get Message Requests (829) for the page after the first, at the
/// `cursor` the previous page gave. 1 chunk.
pub fn build_get_message_requests_chunks(
    cursor: &[u8],
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::REQUEST_CURSOR, nonempty(cursor)?)
    })
}

/// Answer Message Request (830). 2 chunks.
pub fn build_answer_message_request_chunks(
    login: &[u8],
    action: RequestAction,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        f.put(tag::FRIEND_LOGIN, nonempty(login)?)?;
        f.put_int(tag::REQUEST_ACTION, &action.wire().to_be_bytes())
    })
}

/// Clear Message Requests (831) within a span of Unix seconds, either
/// end open. With neither end the request clears everything and has no
/// fields, so this refuses it. Up to 2 chunks.
pub fn build_clear_message_requests_chunks(
    since: Option<u64>,
    before: Option<u64>,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        (since.is_some() || before.is_some()).then_some(())?;
        if let Some(s) = since {
            f.put_int(tag::SPAN_SINCE, &s.to_be_bytes())?;
        }
        if let Some(b) = before {
            f.put_int(tag::SPAN_BEFORE, &b.to_be_bytes())?;
        }
        Some(())
    })
}

/// An object Present Friendships (833) carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presentation<'a> {
    Friendship(&'a [u8]),
    Withdrawal(&'a [u8]),
}

/// Present Friendships (833): one to [`MAX_FRIENDSHIP_OBJECTS`] objects,
/// in the order given. One chunk each.
pub fn build_present_friendships_chunks(
    objects: &[Presentation<'_>],
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        (1..=MAX_FRIENDSHIP_OBJECTS)
            .contains(&objects.len())
            .then_some(())?;
        for o in objects {
            match *o {
                Presentation::Friendship(b) => {
                    f.put(tag::FRIENDSHIP, at_most(b, MAX_FRIENDSHIP_LEN)?)?
                }
                Presentation::Withdrawal(b) => {
                    f.put(tag::FRIEND_WITHDRAW, at_most(b, MAX_OFFER_LEN)?)?
                }
            }
        }
        Some(())
    })
}

/// A question Get Friendships (834) asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriendshipQuery<'a> {
    /// A friendship, by its hash.
    Hash(&'a [u8; HASH_LEN]),
    /// The rotation records behind a fingerprint.
    Identity(&'a [u8; HASH_LEN]),
}

/// Get Friendships (834): one to [`MAX_FRIENDSHIP_OBJECTS`] questions.
/// One chunk each.
pub fn build_get_friendships_chunks(
    asked: &[FriendshipQuery<'_>],
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        (1..=MAX_FRIENDSHIP_OBJECTS)
            .contains(&asked.len())
            .then_some(())?;
        for q in asked {
            match *q {
                FriendshipQuery::Hash(h) => f.put(tag::FRIENDSHIP_HASH, h)?,
                FriendshipQuery::Identity(fp) => f.put(tag::FRIEND_IDENTITY, fp)?,
            }
        }
        Some(())
    })
}

/// Get Device Challenge (1020): the `host` dialed, port included, in the
/// identity spec's form of a host. 1 chunk.
pub fn build_get_device_challenge_chunks(
    host: &[u8],
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        f.put(
            tag::PROOF_HOST,
            at_most(nonempty(host)?, MAX_PROOF_HOST_LEN)?,
        )
    })
}

/// Prove Device (1021): the proof and the device's certificate, and the
/// user card unless the server already holds it. Up to 3 chunks.
pub fn build_prove_device_chunks(
    proof: &[u8],
    cert: &[u8],
    card: Option<&[u8]>,
    chunks: &mut [HxChunk],
    scratch: &mut [u8],
) -> usize {
    build(chunks, scratch, |f| {
        f.put(
            tag::DEVICE_PROOF,
            at_most(nonempty(proof)?, MAX_DEVICE_PROOF_LEN)?,
        )?;
        f.put(
            tag::DEVICE_CERT,
            at_most(nonempty(cert)?, MAX_DEVICE_CERT_LEN)?,
        )?;
        if let Some(c) = card {
            f.put(tag::USER_CARD, at_most(nonempty(c)?, MAX_USER_CARD_LEN)?)?;
        }
        Some(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type Fields = Vec<(u16, Vec<u8>)>;

    fn chunk(tag: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + data.len());
        v.extend_from_slice(&tag.to_be_bytes());
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    fn message(fields: &[(u16, &[u8])]) -> Vec<u8> {
        let mut v = vec![0u8; HL_HDR_LEN];
        for (t, d) in fields {
            v.extend(chunk(*t, d));
        }
        v
    }

    fn with_body(body: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; HL_HDR_LEN];
        v.extend_from_slice(body);
        v
    }

    /// What a builder filled, or `None` when it refused.
    fn run(f: impl FnOnce(&mut [HxChunk], &mut [u8]) -> usize) -> Option<Fields> {
        let mut chunks: Vec<HxChunk> = (0..40).map(|_| HxChunk::EMPTY).collect();
        let mut scratch = [0u8; SCRATCH_LEN];
        let hc = f(&mut chunks, &mut scratch);
        (hc > 0).then(|| {
            chunks[..hc]
                .iter()
                .map(|c| {
                    // SAFETY: the builder pointed `data` at `len` bytes of an
                    // input or of `scratch`, both alive here.
                    let d = unsafe { std::slice::from_raw_parts(c.data, c.len as usize) };
                    (c.tag, d.to_vec())
                })
                .collect()
        })
    }

    fn owned(fields: &[(u16, &[u8])]) -> Fields {
        fields.iter().map(|(t, d)| (*t, d.to_vec())).collect()
    }

    #[test]
    fn a_removal_matches_the_spec_bytes() {
        // Roster Entry (801), byte for byte: FRIEND_LOGIN "bob", then
        // ROSTER_STATE Removed and nothing else.
        let m = with_body(&[
            0x06, 0x00, 0x00, 0x03, b'b', b'o', b'b', 0x06, 0x04, 0x00, 0x02, 0x00, 0x00,
        ]);
        let e = parse_entry(&m, m.len()).unwrap();
        assert_eq!(
            e,
            RosterEntry {
                login: b"bob",
                state: Some(0),
                ..RosterEntry::default()
            }
        );
        assert_eq!(e.roster_state(), Some(RosterState::Removed));
    }

    #[test]
    fn a_roster_gives_each_entry_its_own_fields() {
        let hash = [9u8; ICON_HASH_LEN];
        let m = message(&[
            // A Hotline integer in 4 bytes, as servers often send one.
            (tag::REASON_CODE, &[0, 0, 0, 0]),
            // Before any entry: the listing's, never the first friend's.
            (tag::NAME, b"stray"),
            (tag::ROSTER_STATE, &[0, 4]),
            (tag::FRIEND_LOGIN, b"alice"),
            (tag::FRIEND_NICKNAME, b"Al"),
            (tag::ROSTER_STATE, &[0, 3]),
            (tag::PRESENCE_STATE, &[0, 2]),
            (tag::PRESENCE_STATUS_TEXT, b"lunch"),
            (tag::FRIEND_CAPABILITIES, &[0x00, 0x46]),
            (tag::NAME, b"Alice A."),
            (tag::BUDDY_ICON_HASH, &hash),
            (tag::FRIEND_LOGIN, b"bob"),
            (tag::ROSTER_STATE, &[0, 2]),
            (tag::FRIEND_LOGIN, b"carol"),
            (tag::ROSTER_STATE, &[0, 3]),
            // Offline: no presence or capabilities, but the account's
            // name and status text all the same.
            (tag::PRESENCE_STATUS_TEXT, b"away till May"),
            (tag::NAME, b"Carol"),
            (0x7777, b"a field from a later revision"),
        ]);
        let r = parse_roster(&m, m.len()).unwrap();
        assert_eq!(r.reason, Some(ReasonCode::Ok.wire()));
        let e: Vec<_> = r.entries().collect();
        assert_eq!(e.len(), 3);
        assert_eq!(
            e[0],
            RosterEntry {
                login: b"alice",
                nickname: Some(b"Al"),
                state: Some(3),
                presence: Some(2),
                status_text: Some(b"lunch"),
                capabilities: Some(CAP_MESSAGING | 0x06),
                name: Some(b"Alice A."),
                icon_hash: Some(&hash),
                ..RosterEntry::default()
            }
        );
        assert_eq!(e[0].presence_state(), Some(PresenceState::Away));
        assert_eq!(
            e[1],
            RosterEntry {
                login: b"bob",
                state: Some(2),
                ..RosterEntry::default()
            }
        );
        assert_eq!(e[2].name, Some(&b"Carol"[..]));
        assert_eq!(e[2].presence, None);
        assert_eq!(e[2].status_text, Some(&b"away till May"[..]));
    }

    #[test]
    fn an_empty_roster_has_no_entries() {
        let m = message(&[]);
        assert_eq!(parse_roster(&m, m.len()).unwrap().entries().count(), 0);
    }

    #[test]
    fn a_friends_capabilities_are_read_as_the_logins_are() {
        let m = message(&[
            (tag::FRIEND_LOGIN, b"alice"),
            (tag::FRIEND_CAPABILITIES, &[0x00, 0x01, 0x00, 0x44]),
        ]);
        let e = parse_entry(&m, m.len()).unwrap();
        assert_eq!(e.capabilities, Some((1 << 16) | 0x44));
    }

    #[test]
    fn a_lone_entry_may_come_in_any_order() {
        let m = message(&[
            (tag::ROSTER_STATE, &[0, 0, 0, 3]),
            (tag::NAME, b"Alice"),
            (tag::FRIEND_LOGIN, b"alice"),
        ]);
        assert_eq!(
            parse_entry(&m, m.len()).unwrap(),
            RosterEntry {
                login: b"alice",
                state: Some(3),
                name: Some(b"Alice"),
                ..RosterEntry::default()
            }
        );
    }

    #[test]
    fn a_friend_request_carries_its_note_and_offer() {
        let fp = [6u8; HASH_LEN];
        let request = RosterEntry {
            login: b"erin",
            identity: Some(&fp),
            note: Some(b"we met at the meetup"),
            offer: Some(b"offer"),
            ..RosterEntry::default()
        };
        let mut enc = Encoder::new();
        assert_eq!(request.encode(&mut enc), Some(4));
        let m = with_body(enc.as_slice());
        assert_eq!(parse_entry(&m, m.len()).unwrap(), request);
    }

    #[test]
    fn malformed_entries_are_refused() {
        let login: (u16, &[u8]) = (tag::FRIEND_LOGIN, b"alice");
        let mut cut_header = message(&[login]);
        cut_header.extend_from_slice(&[0x06, 0x04, 0x00]);
        let mut cut_data = message(&[login]);
        cut_data.extend_from_slice(&[0x06, 0x04, 0x00, 0x02, 0x00]);
        let h = [1u8; HASH_LEN];
        let cases: Vec<(&str, Vec<u8>, Malformed)> = vec![
            (
                "shorter than a header",
                vec![0u8; HL_HDR_LEN - 1],
                Malformed::Truncated,
            ),
            ("a field header cut short", cut_header, Malformed::Truncated),
            ("a field's data cut short", cut_data, Malformed::Truncated),
            (
                "an entry without its login",
                message(&[(tag::ROSTER_STATE, &[0, 3]), (tag::NAME, b"x")]),
                Malformed::Missing(tag::FRIEND_LOGIN),
            ),
            (
                "no entry at all",
                message(&[(tag::REASON_CODE, &[0, 0])]),
                Malformed::Missing(tag::FRIEND_LOGIN),
            ),
            (
                "two entries where one belongs",
                message(&[login, (tag::FRIEND_LOGIN, b"bob")]),
                Malformed::Repeated(tag::FRIEND_LOGIN),
            ),
            (
                "an empty login",
                message(&[(tag::FRIEND_LOGIN, b"")]),
                Malformed::Width(tag::FRIEND_LOGIN),
            ),
            (
                "a state of three bytes",
                message(&[login, (tag::ROSTER_STATE, &[0, 0, 3])]),
                Malformed::Width(tag::ROSTER_STATE),
            ),
            (
                "a state of four bytes past a UInt16",
                message(&[login, (tag::ROSTER_STATE, &[0, 1, 0, 0])]),
                Malformed::Width(tag::ROSTER_STATE),
            ),
            (
                "a short fingerprint",
                message(&[login, (tag::FRIEND_IDENTITY, &[1; HASH_LEN - 1])]),
                Malformed::Width(tag::FRIEND_IDENTITY),
            ),
            (
                "an alias given twice",
                message(&[
                    login,
                    (tag::FRIEND_NICKNAME, b"a"),
                    (tag::FRIEND_NICKNAME, b"b"),
                ]),
                Malformed::Repeated(tag::FRIEND_NICKNAME),
            ),
            (
                "three friendships",
                message(&[
                    login,
                    (tag::FRIENDSHIP_HASH, &h),
                    (tag::FRIENDSHIP_HASH, &h),
                    (tag::FRIENDSHIP_HASH, &h),
                ]),
                Malformed::Repeated(tag::FRIENDSHIP_HASH),
            ),
        ];
        for (what, m, want) in cases {
            assert_eq!(parse_entry(&m, m.len()).err(), Some(want), "{what}");
        }
    }

    #[test]
    fn one_bad_entry_refuses_the_roster() {
        let m = message(&[
            (tag::FRIEND_LOGIN, b"alice"),
            (tag::ROSTER_STATE, &[0, 3]),
            (tag::FRIEND_LOGIN, b"bob"),
            (tag::ROSTER_STATE, &[3]),
        ]);
        assert_eq!(
            parse_roster(&m, m.len()).err(),
            Some(Malformed::Width(tag::ROSTER_STATE))
        );
    }

    #[test]
    fn an_encoded_entry_parses_back_whole() {
        let (icon, fp, h1, h2) = (
            [2u8; ICON_HASH_LEN],
            [3u8; HASH_LEN],
            [4u8; HASH_LEN],
            [5u8; HASH_LEN],
        );
        let full = RosterEntry {
            login: b"alice",
            nickname: Some(b"Al"),
            state: Some(RosterState::Accepted.wire()),
            presence: Some(PresenceState::Busy.wire()),
            status_text: Some(b""),
            capabilities: Some(CAP_MESSAGING | (1 << 16)),
            name: Some(b"Alice"),
            icon_hash: Some(&icon),
            identity: Some(&fp),
            friendship_hashes: [Some(&h1), Some(&h2)],
            withdrawal: None,
            note: None,
            offer: None,
        };
        let removal = RosterEntry {
            login: b"bob",
            state: Some(RosterState::Removed.wire()),
            withdrawal: Some(b"withdrawal"),
            ..RosterEntry::default()
        };
        let mut enc = Encoder::new();
        assert_eq!(full.encode(&mut enc), Some(11));
        assert_eq!(removal.encode(&mut enc), Some(3));
        let m = with_body(enc.as_slice());
        let back: Vec<_> = parse_roster(&m, m.len()).unwrap().entries().collect();
        assert_eq!(back, [full, removal]);
        // Bit 16 needs the 4-byte width.
        let caps = ChunkIter::over_message(&m, m.len())
            .find(|c| c.tag == tag::FRIEND_CAPABILITIES)
            .unwrap();
        assert_eq!(caps.data, &[0x00, 0x01, 0x00, 0x40]);

        let mut enc = Encoder::new();
        assert_eq!(RosterEntry::default().encode(&mut enc), None);
        let long = vec![0u8; u16::MAX as usize + 1];
        let too_long = RosterEntry {
            login: b"alice",
            status_text: Some(&long),
            ..RosterEntry::default()
        };
        assert_eq!(too_long.encode(&mut enc), None);
        assert!(enc.as_slice().is_empty());
    }

    #[test]
    fn message_requests_list_senders_then_approvals() {
        let (fp, g1, g2) = ([7u8; HASH_LEN], [1u8; GUID_LEN], [2u8; GUID_LEN]);
        let (t1, t2) = (
            1_798_000_000u64.to_be_bytes(),
            1_798_000_060u64.to_be_bytes(),
        );
        let m = message(&[
            (tag::TAKES_REQUESTS, &[0, 1]),
            (tag::REQUEST_COUNT, &[0, 0, 0, 2]),
            (tag::REQUEST_CURSOR, b"page 2"),
            (tag::FRIEND_LOGIN, b"carol"),
            (tag::FRIEND_IDENTITY, &fp),
            (tag::MESSAGE_GUID, &g1),
            (tag::MESSAGE_BODY, b"hi"),
            (tag::MESSAGE_TIMESTAMP, &t1),
            (tag::MESSAGE_GUID, &g2),
            (tag::MESSAGE_BODY, b"are you there?"),
            (tag::MESSAGE_TIMESTAMP, &t2),
            (tag::MESSAGE_SIGNED, b"detached"),
            (tag::FRIEND_LOGIN, b"dave"),
            (tag::ROSTER_STATE, &[0, 3]),
        ]);
        let r = parse_message_requests(&m, m.len()).unwrap();
        assert_eq!(r.takes_requests, Some(true));
        assert_eq!(r.dropped, Some(2));
        assert_eq!(r.cursor, Some(&b"page 2"[..]));
        let groups: Vec<_> = r.groups().collect();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].login, b"carol");
        assert_eq!(groups[0].identity, Some(&fp));
        assert!(!groups[0].is_approval());
        let msgs: Vec<_> = groups[0].messages().collect();
        assert_eq!(
            msgs,
            [
                RequestMessage {
                    guid: &g1,
                    body: b"hi",
                    timestamp: 1_798_000_000,
                    signed: None,
                },
                RequestMessage {
                    guid: &g2,
                    body: b"are you there?",
                    timestamp: 1_798_000_060,
                    signed: Some(b"detached"),
                },
            ]
        );
        assert_eq!(groups[1].login, b"dave");
        assert!(groups[1].is_approval());
        assert_eq!(groups[1].messages().count(), 0);

        // A server's own messages read back the same.
        let mut enc = Encoder::new();
        enc.put_chunk(tag::FRIEND_LOGIN, b"carol");
        for msg in &msgs {
            msg.encode(&mut enc).unwrap();
        }
        let m = with_body(enc.as_slice());
        let r = parse_message_requests(&m, m.len()).unwrap();
        let back: Vec<_> = r.groups().next().unwrap().messages().collect();
        assert_eq!(back, msgs);
        assert_eq!((r.takes_requests, r.dropped, r.cursor), (None, None, None));
    }

    #[test]
    fn malformed_message_requests_are_refused() {
        let g = [1u8; GUID_LEN];
        let ts = 5u64.to_be_bytes();
        let sender: (u16, &[u8]) = (tag::FRIEND_LOGIN, b"carol");
        let cases: Vec<(&str, Vec<u8>, Malformed)> = vec![
            (
                "a body before its message's guid",
                message(&[sender, (tag::MESSAGE_BODY, b"hi"), (tag::MESSAGE_GUID, &g)]),
                Malformed::NoDelimiter(tag::MESSAGE_BODY),
            ),
            (
                "a message before any sender",
                message(&[(tag::MESSAGE_GUID, &g), (tag::MESSAGE_BODY, b"hi")]),
                Malformed::NoDelimiter(tag::MESSAGE_GUID),
            ),
            (
                "a message without its time",
                message(&[sender, (tag::MESSAGE_GUID, &g), (tag::MESSAGE_BODY, b"hi")]),
                Malformed::Missing(tag::MESSAGE_TIMESTAMP),
            ),
            (
                "a message without its body",
                message(&[
                    sender,
                    (tag::MESSAGE_GUID, &g),
                    (tag::MESSAGE_TIMESTAMP, &ts),
                ]),
                Malformed::Missing(tag::MESSAGE_BODY),
            ),
            (
                "a short guid",
                message(&[
                    sender,
                    (tag::MESSAGE_GUID, &g[1..]),
                    (tag::MESSAGE_BODY, b"hi"),
                    (tag::MESSAGE_TIMESTAMP, &ts),
                ]),
                Malformed::Width(tag::MESSAGE_GUID),
            ),
            (
                "a time of four bytes",
                message(&[
                    sender,
                    (tag::MESSAGE_GUID, &g),
                    (tag::MESSAGE_BODY, b"hi"),
                    (tag::MESSAGE_TIMESTAMP, &ts[4..]),
                ]),
                Malformed::Width(tag::MESSAGE_TIMESTAMP),
            ),
            (
                "two cursors",
                message(&[(tag::REQUEST_CURSOR, b"a"), (tag::REQUEST_CURSOR, b"b")]),
                Malformed::Repeated(tag::REQUEST_CURSOR),
            ),
            (
                "a group's state before any sender",
                message(&[(tag::ROSTER_STATE, &[0, 3]), sender]),
                Malformed::NoDelimiter(tag::ROSTER_STATE),
            ),
            (
                "a sender's fingerprint among its messages",
                message(&[
                    sender,
                    (tag::MESSAGE_GUID, &g),
                    (tag::MESSAGE_BODY, b"hi"),
                    (tag::MESSAGE_TIMESTAMP, &ts),
                    (tag::FRIEND_IDENTITY, &[7; HASH_LEN]),
                ]),
                Malformed::Misplaced(tag::FRIEND_IDENTITY),
            ),
        ];
        for (what, m, want) in cases {
            assert_eq!(
                parse_message_requests(&m, m.len()).err(),
                Some(want),
                "{what}"
            );
        }
    }

    #[test]
    fn friendship_replies_group_by_what_they_answer() {
        let (a, b, fp) = ([1u8; HASH_LEN], [2u8; HASH_LEN], [3u8; HASH_LEN]);
        let m = message(&[
            (tag::FRIENDSHIP_HASH, &a),
            (tag::REASON_CODE, &[0, 0]),
            (tag::FRIENDSHIP_HASH, &b),
            (tag::REASON_CODE, &[0, 18]),
            (tag::FRIEND_WITHDRAW, b"the withdrawal"),
        ]);
        let out: Vec<_> = parse_present_friendships(&m, m.len())
            .unwrap()
            .outcomes()
            .collect();
        assert_eq!(out.len(), 2);
        assert_eq!(
            (out[0].hash, out[0].reason_code()),
            (&a, Some(ReasonCode::Ok))
        );
        assert_eq!(out[1].reason_code(), Some(ReasonCode::Withdrawn));
        assert_eq!(out[1].withdrawal, Some(&b"the withdrawal"[..]));

        let m = message(&[
            (tag::FRIENDSHIP_HASH, &a),
            (tag::FRIENDSHIP, b"offer and acceptance"),
            // Withheld: a hash the caller was never sent.
            (tag::FRIENDSHIP_HASH, &b),
            (tag::FRIEND_IDENTITY, &fp),
            (tag::IDENTITY_ROTATION, b"first"),
            (tag::IDENTITY_ROTATION, b"second"),
        ]);
        let answers: Vec<_> = parse_friendships(&m, m.len()).unwrap().answers().collect();
        assert_eq!(answers.len(), 3);
        assert!(matches!(
            answers[0],
            FriendshipAnswer::Friendship { hash, friendship: Some(f) }
                if hash == &a && f == b"offer and acceptance"
        ));
        assert!(matches!(
            answers[1],
            FriendshipAnswer::Friendship { hash, friendship: None } if hash == &b
        ));
        let FriendshipAnswer::Rotations { identity, records } = answers[2].clone() else {
            panic!("{:?}", answers[2]);
        };
        assert_eq!(identity, &fp);
        assert_eq!(records.collect::<Vec<_>>(), [&b"first"[..], b"second"]);
    }

    #[test]
    fn malformed_friendship_replies_are_refused() {
        type Parse = fn(&[u8]) -> Option<Malformed>;
        let present: Parse = |m| parse_present_friendships(m, m.len()).err();
        let get: Parse = |m| parse_friendships(m, m.len()).err();
        let h = [1u8; HASH_LEN];
        let cases: Vec<(&str, Parse, Vec<u8>, Malformed)> = vec![
            (
                "an outcome without its reason",
                present,
                message(&[(tag::FRIENDSHIP_HASH, &h)]),
                Malformed::Missing(tag::REASON_CODE),
            ),
            (
                "an outcome with two reasons",
                present,
                message(&[
                    (tag::FRIENDSHIP_HASH, &h),
                    (tag::REASON_CODE, &[0, 0]),
                    (tag::REASON_CODE, &[0, 18]),
                ]),
                Malformed::Repeated(tag::REASON_CODE),
            ),
            (
                "a rotation answering a hash",
                get,
                message(&[(tag::FRIENDSHIP_HASH, &h), (tag::IDENTITY_ROTATION, b"r")]),
                Malformed::Misplaced(tag::IDENTITY_ROTATION),
            ),
            (
                "a hash answered with two friendships",
                get,
                message(&[
                    (tag::FRIENDSHIP_HASH, &h),
                    (tag::FRIENDSHIP, b"f"),
                    (tag::FRIENDSHIP, b"g"),
                ]),
                Malformed::Repeated(tag::FRIENDSHIP),
            ),
            (
                "a friendship answering a fingerprint",
                get,
                message(&[(tag::FRIEND_IDENTITY, &h), (tag::FRIENDSHIP, b"f")]),
                Malformed::Misplaced(tag::FRIENDSHIP),
            ),
            (
                "a short hash",
                get,
                message(&[(tag::FRIENDSHIP_HASH, &h[1..])]),
                Malformed::Width(tag::FRIENDSHIP_HASH),
            ),
        ];
        for (what, parse, m, want) in cases {
            assert_eq!(parse(&m), Some(want), "{what}");
        }
    }

    #[test]
    fn a_fingerprint_may_have_no_rotations() {
        let fp = [3u8; HASH_LEN];
        let m = message(&[(tag::FRIEND_IDENTITY, &fp)]);
        let answers: Vec<_> = parse_friendships(&m, m.len()).unwrap().answers().collect();
        let [FriendshipAnswer::Rotations { identity, records }] = &answers[..] else {
            panic!("{answers:?}");
        };
        assert_eq!(*identity, &fp);
        assert_eq!(records.clone().count(), 0);
    }

    #[test]
    fn an_accepted_group_with_messages_is_not_an_approval() {
        let g = [1u8; GUID_LEN];
        let m = message(&[
            (tag::FRIEND_LOGIN, b"carol"),
            (tag::ROSTER_STATE, &[0, 3]),
            (tag::MESSAGE_GUID, &g),
            (tag::MESSAGE_BODY, b"hi"),
            (tag::MESSAGE_TIMESTAMP, &5u64.to_be_bytes()),
        ]);
        let r = parse_message_requests(&m, m.len()).unwrap();
        let group = r.groups().next().unwrap();
        assert!(!group.is_approval());
        assert_eq!(group.messages().count(), 1);
    }

    #[test]
    fn a_message_too_long_for_its_field_is_not_encoded() {
        let g = [1u8; GUID_LEN];
        let long = vec![0u8; u16::MAX as usize + 1];
        let msg = RequestMessage {
            guid: &g,
            body: &long,
            timestamp: 5,
            signed: None,
        };
        let mut enc = Encoder::new();
        assert_eq!(msg.encode(&mut enc), None);
        assert!(enc.as_slice().is_empty());
    }

    #[test]
    fn a_limit_sent_twice_is_read_as_the_last_it_can_read() {
        let m = message(&[
            (tag::MAX_MESSAGE_BYTES, &[0, 0, 0x10, 0]),
            (tag::MAX_MESSAGE_BYTES, &[0, 0, 0x20, 0]),
            // A width no UInt32 has does not undo the one before it.
            (tag::MAX_MESSAGE_BYTES, &[0, 0, 0x30]),
        ]);
        assert_eq!(Limits::extract(&m, m.len()).message_bytes(), 0x2000);
    }

    #[test]
    fn limits_fall_back_to_the_defaults() {
        let none = Limits::extract(&message(&[]), HL_HDR_LEN);
        assert_eq!(
            (
                none.message_bytes(),
                none.roster_size(),
                none.offline_queue(),
                none.icon_bytes(),
                none.icon_dimension(),
                none.request_messages(),
            ),
            (4096, 500, 500, None, 64, None)
        );

        let m = message(&[
            (tag::SERVERNAME, b"Server"),
            (tag::CAPABILITIES, &[0x00, 0x42]),
            (tag::MAX_MESSAGE_BYTES, &[0, 0, 0x20, 0]),
            // 0 is no value for these three: the default stands.
            (tag::MAX_ROSTER_SIZE, &[0, 0, 0, 0]),
            // A Hotline integer that fits in 2 bytes may come in 2.
            (tag::MAX_OFFLINE_QUEUE, &[0, 100]),
            (tag::MAX_ICON_BYTES, &[0, 0, 0x80, 0]),
            // No UInt32 has 3 bytes: read as absent.
            (tag::MAX_ICON_DIMENSION, &[0, 0, 96]),
            (tag::MAX_REQUEST_MESSAGES, &[0, 0, 0, 3]),
        ]);
        let l = Limits::extract(&m, m.len());
        assert_eq!(
            (
                l.message_bytes(),
                l.roster_size(),
                l.offline_queue(),
                l.icon_bytes(),
                l.icon_dimension(),
                l.request_messages(),
            ),
            (8192, 500, 100, Some(0x8000), 64, Some(3))
        );

        let mut enc = Encoder::new();
        assert_eq!(l.encode(&mut enc), 5);
        let back = with_body(enc.as_slice());
        assert_eq!(Limits::extract(&back, back.len()), l);
    }

    #[test]
    fn builders_lay_out_the_spec_fields() {
        let (guid, fp, h) = ([0xab; GUID_LEN], [0xcd; HASH_LEN], [0xef; HASH_LEN]);
        let langs: [&[u8]; 3] = [b"en", b"ru", b"mi"];
        let cases: Vec<(&str, Option<Fields>, Fields)> = vec![
            (
                "802 with a note",
                run(|c, s| build_add_friend_chunks(b"bob", Some(b"hi"), None, c, s)),
                owned(&[(tag::FRIEND_LOGIN, b"bob"), (tag::REQUEST_NOTE, b"hi")]),
            ),
            (
                "803 by login, canceling an offer",
                run(|c, s| build_remove_friend_chunks(Who::Login(b"bob"), Some(b"o"), None, c, s)),
                owned(&[(tag::FRIEND_LOGIN, b"bob"), (tag::FRIEND_OFFER, b"o")]),
            ),
            (
                "806 with a withdrawal",
                run(|c, s| build_block_user_chunks(b"bob", Some(b"w"), c, s)),
                owned(&[(tag::FRIEND_LOGIN, b"bob"), (tag::FRIEND_WITHDRAW, b"w")]),
            ),
            (
                "810 plain",
                run(|c, s| {
                    let m = ImSend {
                        to: b"bob",
                        guid: &guid,
                        content: ImContent::Plain(b"hello"),
                    };
                    build_im_send_chunks(&m, c, s)
                }),
                owned(&[
                    (tag::FRIEND_LOGIN, b"bob"),
                    (tag::MESSAGE_GUID, &guid),
                    (tag::MESSAGE_BODY, b"hello"),
                ]),
            ),
            (
                "822 by fingerprint",
                run(|c, s| build_find_user_chunks(Who::Identity(&fp), c, s)),
                owned(&[(tag::FRIEND_IDENTITY, &fp)]),
            ),
            (
                "1021 without a card",
                run(|c, s| build_prove_device_chunks(b"proof", b"cert", None, c, s)),
                owned(&[(tag::DEVICE_PROOF, b"proof"), (tag::DEVICE_CERT, b"cert")]),
            ),
            (
                "802 with an offer",
                run(|c, s| build_add_friend_chunks(b"bob", None, Some(b"offer"), c, s)),
                owned(&[(tag::FRIEND_LOGIN, b"bob"), (tag::FRIEND_OFFER, b"offer")]),
            ),
            (
                "803 by fingerprint, withdrawing",
                run(|c, s| build_remove_friend_chunks(Who::Identity(&fp), None, Some(b"w"), c, s)),
                owned(&[(tag::FRIEND_IDENTITY, &fp), (tag::FRIEND_WITHDRAW, b"w")]),
            ),
            (
                "805 accepting an offer",
                run(|c, s| build_friend_response_chunks(b"bob", true, Some(b"fs"), c, s)),
                owned(&[
                    (tag::FRIEND_LOGIN, b"bob"),
                    (tag::ROSTER_STATE, &[0, 3]),
                    (tag::FRIENDSHIP, b"fs"),
                ]),
            ),
            (
                "805 rejecting, with no state",
                run(|c, s| build_friend_response_chunks(b"bob", false, None, c, s)),
                owned(&[(tag::FRIEND_LOGIN, b"bob")]),
            ),
            (
                "806",
                run(|c, s| build_block_user_chunks(b"bob", None, c, s)),
                owned(&[(tag::FRIEND_LOGIN, b"bob")]),
            ),
            (
                "807 or 825",
                run(|c, s| build_login_only_chunks(b"bob", c, s)),
                owned(&[(tag::FRIEND_LOGIN, b"bob")]),
            ),
            (
                "808 clearing the status, with every preference",
                run(|c, s| {
                    let p = Presence {
                        state: PresenceState::Away,
                        status_text: Some(b""),
                        discoverable: Some(true),
                        takes_requests: Some(false),
                    };
                    build_set_presence_chunks(&p, c, s)
                }),
                owned(&[
                    (tag::PRESENCE_STATE, &[0, 2]),
                    (tag::PRESENCE_STATUS_TEXT, b""),
                    (tag::DISCOVERABLE, &[0, 1]),
                    (tag::TAKES_REQUESTS, &[0, 0]),
                ]),
            ),
            (
                "808 leaving the status as it is",
                run(|c, s| {
                    let p = Presence {
                        state: PresenceState::Online,
                        status_text: None,
                        discoverable: None,
                        takes_requests: None,
                    };
                    build_set_presence_chunks(&p, c, s)
                }),
                owned(&[(tag::PRESENCE_STATE, &[0, 1])]),
            ),
            (
                "810 signed",
                run(|c, s| {
                    let m = ImSend {
                        to: b"bob",
                        guid: &guid,
                        content: ImContent::Signed {
                            body: b"hello",
                            signed: b"sig",
                        },
                    };
                    build_im_send_chunks(&m, c, s)
                }),
                owned(&[
                    (tag::FRIEND_LOGIN, b"bob"),
                    (tag::MESSAGE_GUID, &guid),
                    (tag::MESSAGE_BODY, b"hello"),
                    (tag::MESSAGE_SIGNED, b"sig"),
                ]),
            ),
            (
                "810 sealed, with no body beside it",
                run(|c, s| {
                    let m = ImSend {
                        to: b"bob",
                        guid: &guid,
                        content: ImContent::Sealed {
                            sealed: b"box",
                            sealed_to: &h,
                        },
                    };
                    build_im_send_chunks(&m, c, s)
                }),
                owned(&[
                    (tag::FRIEND_LOGIN, b"bob"),
                    (tag::MESSAGE_GUID, &guid),
                    (tag::MESSAGE_SEALED, b"box"),
                    (tag::MESSAGE_SEALED_TO, &h),
                ]),
            ),
            (
                "812",
                run(|c, s| build_im_ack_chunks(&guid, AckType::Read, b"bob", c, s)),
                owned(&[
                    (tag::MESSAGE_GUID, &guid),
                    (tag::ACK_TYPE, &[0, 2]),
                    (tag::FRIEND_LOGIN, b"bob"),
                ]),
            ),
            (
                "813",
                run(|c, s| build_im_typing_chunks(b"bob", TypingState::Started, c, s)),
                owned(&[(tag::FRIEND_LOGIN, b"bob"), (tag::TYPING_STATE, &[0, 1])]),
            ),
            (
                "822 by login",
                run(|c, s| build_find_user_chunks(Who::Login(b"bob"), c, s)),
                owned(&[(tag::FRIEND_LOGIN, b"bob")]),
            ),
            (
                "823",
                run(|c, s| build_user_search_chunks(b"bo", c, s)),
                owned(&[(tag::SEARCH_QUERY, b"bo")]),
            ),
            (
                "824 clearing the alias",
                run(|c, s| build_set_friend_nickname_chunks(b"bob", b"", c, s)),
                owned(&[(tag::FRIEND_LOGIN, b"bob"), (tag::FRIEND_NICKNAME, b"")]),
            ),
            (
                "826, every field",
                run(|c, s| {
                    let p = Profile {
                        nickname: Some(b"Bobby"),
                        first_name: Some(b"Robert"),
                        last_name: Some(b"Tables"),
                        email: Some(b"bob@example.org"),
                        postcode: Some(b"6011"),
                        gender: Some(Gender::Other),
                        birthdate: Some(Birthdate {
                            year: 0,
                            month: 12,
                            day: 25,
                        }),
                        country: Some(b"NZ"),
                        languages: &langs,
                    };
                    build_set_profile_chunks(&p, c, s)
                }),
                owned(&[
                    (tag::PROFILE_NICKNAME, b"Bobby"),
                    (tag::PROFILE_FIRST_NAME, b"Robert"),
                    (tag::PROFILE_LAST_NAME, b"Tables"),
                    (tag::PROFILE_EMAIL, b"bob@example.org"),
                    (tag::PROFILE_GENDER, &[0, 3]),
                    (tag::PROFILE_BIRTHDATE, &[0, 0, 12, 25]),
                    (tag::PROFILE_COUNTRY, b"NZ"),
                    (tag::PROFILE_POSTCODE, b"6011"),
                    (tag::PROFILE_LANGUAGE, b"en"),
                    (tag::PROFILE_LANGUAGE, b"ru"),
                    (tag::PROFILE_LANGUAGE, b"mi"),
                ]),
            ),
            (
                "829's next page",
                run(|c, s| build_get_message_requests_chunks(b"page 2", c, s)),
                owned(&[(tag::REQUEST_CURSOR, b"page 2")]),
            ),
            (
                "830",
                run(|c, s| {
                    build_answer_message_request_chunks(b"bob", RequestAction::EndApproval, c, s)
                }),
                owned(&[(tag::FRIEND_LOGIN, b"bob"), (tag::REQUEST_ACTION, &[0, 3])]),
            ),
            (
                "831 over a closed span",
                run(|c, s| build_clear_message_requests_chunks(Some(1), Some(0x0102), c, s)),
                owned(&[
                    (tag::SPAN_SINCE, &1u64.to_be_bytes()),
                    (tag::SPAN_BEFORE, &0x0102u64.to_be_bytes()),
                ]),
            ),
            (
                "833 in the order given",
                run(|c, s| {
                    let o = [
                        Presentation::Withdrawal(b"w"),
                        Presentation::Friendship(b"f"),
                    ];
                    build_present_friendships_chunks(&o, c, s)
                }),
                owned(&[(tag::FRIEND_WITHDRAW, b"w"), (tag::FRIENDSHIP, b"f")]),
            ),
            (
                "834",
                run(|c, s| {
                    let q = [FriendshipQuery::Hash(&h), FriendshipQuery::Identity(&fp)];
                    build_get_friendships_chunks(&q, c, s)
                }),
                owned(&[(tag::FRIENDSHIP_HASH, &h), (tag::FRIEND_IDENTITY, &fp)]),
            ),
            (
                "1020",
                run(|c, s| build_get_device_challenge_chunks(b"hl.example.org:5500", c, s)),
                owned(&[(tag::PROOF_HOST, b"hl.example.org:5500")]),
            ),
            (
                "1021 with its card",
                run(|c, s| build_prove_device_chunks(b"proof", b"cert", Some(b"card"), c, s)),
                owned(&[
                    (tag::DEVICE_PROOF, b"proof"),
                    (tag::DEVICE_CERT, b"cert"),
                    (tag::USER_CARD, b"card"),
                ]),
            ),
        ];
        for (what, got, want) in cases {
            assert_eq!(got, Some(want), "{what}");
        }
    }

    #[test]
    fn builders_refuse_what_the_spec_does_not_allow() {
        let guid = [0u8; GUID_LEN];
        let h = [0u8; HASH_LEN];
        let four: [&[u8]; 4] = [b"en", b"ru", b"fr", b"de"];
        let big = vec![0u8; MAX_SEALED_LEN + 1];
        let many = vec![FriendshipQuery::Hash(&h); MAX_FRIENDSHIP_OBJECTS + 1];
        let cases: Vec<(&str, Option<Fields>)> = vec![
            (
                "802 to nobody",
                run(|c, s| build_add_friend_chunks(b"", None, None, c, s)),
            ),
            (
                "802 with an offer past its size",
                run(|c, s| {
                    build_add_friend_chunks(b"bob", None, Some(&big[..MAX_OFFER_LEN + 1]), c, s)
                }),
            ),
            (
                "803 canceling an offer and withdrawing at once",
                run(|c, s| {
                    build_remove_friend_chunks(Who::Login(b"bob"), Some(b"o"), Some(b"w"), c, s)
                }),
            ),
            (
                "805 rejecting with a friendship",
                run(|c, s| build_friend_response_chunks(b"bob", false, Some(b"fs"), c, s)),
            ),
            (
                "808 setting ourselves offline",
                run(|c, s| {
                    let p = Presence {
                        state: PresenceState::Offline,
                        status_text: None,
                        discoverable: None,
                        takes_requests: None,
                    };
                    build_set_presence_chunks(&p, c, s)
                }),
            ),
            (
                "808 into too few chunks",
                run(|c, s| {
                    let p = Presence {
                        state: PresenceState::Online,
                        status_text: Some(b"x"),
                        discoverable: Some(true),
                        takes_requests: Some(true),
                    };
                    build_set_presence_chunks(&p, &mut c[..3], s)
                }),
            ),
            (
                "808 with too little scratch",
                run(|c, s| {
                    let p = Presence {
                        state: PresenceState::Online,
                        status_text: None,
                        discoverable: Some(true),
                        takes_requests: Some(true),
                    };
                    build_set_presence_chunks(&p, c, &mut s[..5])
                }),
            ),
            (
                "810 sealed past its size",
                run(|c, s| {
                    let m = ImSend {
                        to: b"bob",
                        guid: &guid,
                        content: ImContent::Sealed {
                            sealed: &big,
                            sealed_to: &h,
                        },
                    };
                    build_im_send_chunks(&m, c, s)
                }),
            ),
            (
                "810 signed past its size",
                run(|c, s| {
                    let m = ImSend {
                        to: b"bob",
                        guid: &guid,
                        content: ImContent::Signed {
                            body: b"hi",
                            signed: &big[..MAX_SIGNED_LEN + 1],
                        },
                    };
                    build_im_send_chunks(&m, c, s)
                }),
            ),
            (
                "823 searching for nothing",
                run(|c, s| build_user_search_chunks(b"", c, s)),
            ),
            (
                "826 with four languages",
                run(|c, s| {
                    let p = Profile {
                        languages: &four,
                        ..Profile::default()
                    };
                    build_set_profile_chunks(&p, c, s)
                }),
            ),
            (
                "829 with an empty cursor",
                run(|c, s| build_get_message_requests_chunks(b"", c, s)),
            ),
            (
                "831 of everything, which goes bare",
                run(|c, s| build_clear_message_requests_chunks(None, None, c, s)),
            ),
            (
                "833 of nothing",
                run(|c, s| build_present_friendships_chunks(&[], c, s)),
            ),
            (
                "834 past its count",
                run(|c, s| build_get_friendships_chunks(&many, c, s)),
            ),
            (
                "1020 past the longest host",
                run(|c, s| build_get_device_challenge_chunks(&big[..MAX_PROOF_HOST_LEN + 1], c, s)),
            ),
            (
                "1021 without its certificate",
                run(|c, s| build_prove_device_chunks(b"proof", b"", None, c, s)),
            ),
        ];
        for (what, got) in cases {
            assert_eq!(got, None, "{what}");
        }
    }

    #[test]
    fn a_birth_date_needs_a_possible_month_and_day() {
        let cases: &[(u16, u8, u8, bool)] = &[
            (1985, 0, 14, true),
            (0, 0, 0, true),
            (1985, 1, 31, true),
            (1985, 4, 30, true),
            (1985, 4, 31, false),
            (1985, 2, 28, true),
            (1985, 2, 29, false),
            (1984, 2, 29, true),
            (1900, 2, 29, false),
            (2000, 2, 29, true),
            // No year given: some year had a February 29.
            (0, 2, 29, true),
            (0, 2, 30, false),
            (1985, 0, 32, false),
            (1985, 12, 31, true),
            (1985, 13, 1, false),
        ];
        for &(year, month, day, possible) in cases {
            let d = Birthdate { year, month, day };
            let want = possible.then_some(d);
            assert_eq!(Birthdate::parse(&d.to_bytes()), want, "{d:?}");
            let p = Profile {
                birthdate: Some(d),
                ..Profile::default()
            };
            let built = run(|c, s| build_set_profile_chunks(&p, c, s));
            assert_eq!(built.is_some(), possible, "{d:?}");
        }
        assert_eq!(Birthdate::parse(&[0x07, 0xc1, 1]), None);
    }
}
