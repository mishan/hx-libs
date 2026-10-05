//! A Hotline client session over the classic control connection, with no
//! I/O of its own.
//!
//! [`Session`] is the protocol between a socket and an application: the
//! TRTP handshake, the login, the agreement and what a server expects to
//! see after it, transaction ids and the replies that answer them, the
//! keep-alive, and the receive side turned into [`Event`]s. It never
//! touches a socket, a clock or a thread. The caller moves bytes and time
//! in and out:
//!
//! ```text
//! let mut s = Session::new(config, now_ms);
//! loop {
//!     write(s.take_outgoing());
//!     s.feed(&read_some(), now_ms()); // whatever arrived, in any pieces
//!     s.tick(now_ms());               // keep-alive and the timers
//!     while let Some(e) = s.poll_event() { … }
//! }
//! ```
//!
//! so the same session runs over a TCP socket in a native client, over a
//! WebSocket to a relay in a browser, or over a scripted byte stream in a
//! test. [`Session::next_deadline`] says when `tick` next has work to do,
//! and [`Session::disconnected`] is how the session learns the socket is
//! gone.
//!
//! The behavior follows GtkHx's, which is what the servers still running
//! are tested against: the login carries no nickname, which goes with the
//! agreement instead (or, to a 1.2 server that has no agreement, in a user
//! change); a 1.5+ server gets nothing else until the agreement is
//! answered, or two seconds have passed without one; an agreement with no
//! text is answered at once, and one with text waits for [`Session::agree`].
//!
//! Text crosses this API as UTF-8. On the wire it is Mac Roman, or UTF-8
//! when the server agreed to the Text-Encoding capability, and line breaks
//! are the classic CR; the session converts both ways.
//!
//! A client with receive handlers of its own sets [`Config::raw`]: the
//! session then keeps the handshake, the login, the agreement, the
//! transaction ids and the keep-alive, and the domains named in
//! [`Config::handled`], and hands everything else over whole. That is how
//! a client moves onto the session a piece at a time.
//!
//! With the `hope` feature, `Session::with_hope` logs in with HOPE, the
//! secure login, and runs the rest of the connection through the cipher
//! and compression it agrees (hx-libs' `hxhope`): `feed` takes the
//! socket's bytes and `take_outgoing` gives them, whatever the transport.
//! A client that has no use for HOPE leaves the feature off, and with it
//! the ciphers and compressors.
//!
//! What is not here yet: file transfers (a folder's listing is here; its
//! contents are not), and the extensions other than chat history and the
//! media a chat line carries (voice, video, uploading and fetching media,
//! GIF icons). [`Session::request`] sends any transaction and hands its
//! reply back whole, for what has no method of its own.

pub mod frame;
mod hope;
pub mod request;

use std::collections::{HashMap, VecDeque};

use hxproto::dispatch::{route, HandlerKind};
use hxproto::inline_media;
use hxproto::messages::{tag, ClientHdr};
use hxproto::parse;

use frame::{FrameError, FrameReader, Transaction};
use request::Request;

/// What a client sends to open the connection: "TRTP" "HOTL", version 1,
/// subversion 2.
pub const CLIENT_MAGIC: &[u8; 12] = b"TRTPHOTL\x00\x01\x00\x02";
/// What a server answers when it accepts it.
pub const SERVER_MAGIC: &[u8; 8] = b"TRTP\x00\x00\x00\x00";

/// The client version a login claims. GtkHx's: past mhxd's gates for the
/// keep-alive (150) and the banner (151).
pub const CLIENT_VERSION: u16 = 254;

/// Capability bits (the login's 0x01F0 field).
pub mod cap {
    pub const LARGE_FILES: u16 = 0x0001;
    pub const TEXT_ENCODING: u16 = 0x0002;
    pub const VOICE: u16 = 0x0004;
    pub const INLINE_MEDIA: u16 = 0x0008;
    pub const CHAT_HISTORY: u16 = 0x0010;
}

/// The trans the login goes out on, as GtkHx sends it.
const LOGIN_TRANS: u32 = 1;
/// Longest chat or message body, as GtkHx caps the ones it receives.
const MAX_BODY: usize = 8192;
const MAX_NAME: usize = 128;
const MAX_NICK: usize = 31;
const MAX_SUBJECT: usize = 255;
const MAX_NEWS: usize = 65535;
/// The field a folder listing carries one of per entry.
const FILE_LIST_ENTRY: u16 = 0x00c8;
/// Large-Files companions, each following the entry it belongs to: the
/// exact size of a file, and the exact item count of a folder.
const FILE_SIZE_64: u16 = 0x01f1;
const FOLDER_ITEMS_64: u16 = 0x01f4;
/// How many transactions a server may send before answering the login,
/// as GtkHx allows. Past that it is not a slow server but a broken one.
const MAX_EARLY: usize = 32;
/// How many unanswered requests are remembered. Some requests are never
/// answered by some servers; past this the oldest are forgotten.
const MAX_PENDING: u32 = 4096;

/// How a session logs in and behaves. [`Config::guest`] is the common case.
#[derive(Debug, Clone)]
pub struct Config {
    /// Empty for the guest account.
    pub login: String,
    pub password: String,
    pub nick: String,
    pub icon: u16,
    /// Sent as the login's version; [`CLIENT_VERSION`] unless a test needs
    /// to look like something older.
    pub version: u16,
    /// Capabilities to offer. The session itself understands
    /// [`cap::TEXT_ENCODING`], the media a chat line carries under
    /// [`cap::INLINE_MEDIA`], and [`cap::CHAT_HISTORY`]; offering others
    /// means the caller handles what they bring, through
    /// [`Session::request`] and [`Event::Unhandled`].
    pub caps: u16,
    /// Give up if the login has not been answered by then. `u64::MAX`
    /// never does.
    pub handshake_timeout_ms: u64,
    /// How long a 1.5+ server has, after the login reply, to send its
    /// agreement before the session stops waiting for one. `u64::MAX`
    /// waits for ever.
    pub agreement_wait_ms: u64,
    /// Ping a 1.5+ server after this long without sending anything.
    /// `u64::MAX` never does.
    pub keepalive_ms: u64,
    /// The caller has receive handlers of its own. Every transaction
    /// reaches it whole: replies as [`Event::Reply`], everything else as
    /// [`Event::Unhandled`]. The exceptions are the domains
    /// [`Config::handled`] names, the replies the caller
    /// [`Session::expect`]s, and the reply to the session's own
    /// keep-alive, refusals included, which the caller never sent and so
    /// is no news. The session still drives the login, the agreement and
    /// the keep-alive, and numbers every transaction; the user list and
    /// every request are the caller's, numbered by [`Session::take_trans`]
    /// and sent through [`Session::send_raw`].
    pub raw: bool,
    /// In raw mode, the domains the session handles as it does when not
    /// raw, so that what they bring arrives as events rather than whole.
    /// None, unless the caller asks. A session that is not raw handles
    /// every domain it knows, whatever this says.
    pub handled: Handled,
}

/// Domains of what a server sends unasked, for [`Config::handled`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handled(u32);

impl Handled {
    pub const NONE: Handled = Handled(0);
    /// Chat lines, invitations to private chat, and chat subjects.
    pub const CHAT: Handled = Handled(1);
    /// Users arriving, changing and leaving, on the server and in each
    /// private chat.
    pub const USERS: Handled = Handled(2);
    /// Private messages, broadcasts, and the server's parting words.
    pub const MSG: Handled = Handled(4);
    /// What is added to 1.2 flat news, as the server announces it.
    pub const NEWS: Handled = Handled(8);
    pub const ALL: Handled = Handled(u32::MAX);

    pub fn contains(self, other: Handled) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Handled {
    type Output = Handled;

    fn bitor(self, other: Handled) -> Handled {
        Handled(self.0 | other.0)
    }
}

impl Config {
    pub fn guest(nick: &str) -> Self {
        Config {
            login: String::new(),
            password: String::new(),
            nick: nick.into(),
            icon: 414,
            version: CLIENT_VERSION,
            caps: cap::TEXT_ENCODING,
            handshake_timeout_ms: 30_000,
            agreement_wait_ms: 2_000,
            keepalive_ms: 60_000,
            raw: false,
            handled: Handled::NONE,
        }
    }

    pub fn account(nick: &str, login: &str, password: &str) -> Self {
        Config {
            login: login.into(),
            password: password.into(),
            ..Config::guest(nick)
        }
    }
}

/// What the login reply said about the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// 0 for a 1.0/1.2 server, which sends none.
    pub version: u16,
    pub name: Option<String>,
    /// Our uid, when the server said.
    pub uid: Option<u16>,
    /// What the server agreed to, of what was offered.
    pub caps: u16,
}

/// One user on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub uid: u16,
    pub icon: u16,
    /// The status bits: 1 away, 2 admin, 4 refuses messages, 8 refuses
    /// chat invitations. `None` in a change that left them out, which
    /// means they did not change.
    pub status: Option<u16>,
    pub name: String,
    /// The Colored-Nicknames 0x00RRGGBB, when the server sent one.
    pub color: Option<u32>,
}

/// One entry in a folder listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// The name, for showing.
    pub name: String,
    /// The name as the server sent it, for naming the entry back to it:
    /// a name decoded for show does not always encode back to the same
    /// bytes, and a folder named by different ones is not found.
    pub name_bytes: Vec<u8>,
    pub folder: bool,
    /// Bytes for a file; for a folder, how many items it holds. Exact past
    /// 4 GiB only where the server sent the Large-Files companion fields,
    /// which it does when the login offered [`cap::LARGE_FILES`]; otherwise
    /// the classic field's `u32::MAX`.
    pub size: u64,
    /// The classic Mac type and creator codes as they are on the wire,
    /// e.g. `*b"TEXT"` and `*b"ttxt"`. A folder's creator is usually zeros.
    pub type_code: [u8; 4],
    pub creator: [u8; 4],
}

/// One entry in a threaded-news listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsItem {
    /// The name, for showing.
    pub name: String,
    /// The name as the server sent it, for naming it back; see
    /// [`FileEntry::name_bytes`].
    pub name_bytes: Vec<u8>,
    /// A bundle holds categories and bundles; a category holds articles.
    pub bundle: bool,
}

/// One article in a category listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Article {
    pub id: u32,
    /// 0 for a thread's first article.
    pub parent: u32,
    pub subject: String,
    pub poster: String,
    /// The classic Mac date: a base year and seconds into it.
    pub year: u16,
    pub seconds: u32,
    /// The type of its first part, as the server sent it; empty when it
    /// has none. [`Session::news_article`] asks for text/plain whatever
    /// this says.
    pub mime: Vec<u8>,
}

/// The picture a chat line carries, under [`cap::INLINE_MEDIA`]: the
/// handle to fetch it by and what the server says of it. The sizes are
/// hints for a placeholder, not to be trusted over the picture itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMedia {
    pub id: Vec<u8>,
    /// The MIME type, as the server sent it.
    pub mime: Vec<u8>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub bytes: Option<u32>,
}

/// One line of a chat's history, under [`cap::CHAT_HISTORY`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub message_id: u64,
    /// Seconds since 1970, UTC.
    pub timestamp: i64,
    /// 1 an emote, 2 from the server, 4 deleted.
    pub flags: u16,
    pub icon: u16,
    pub nick: String,
    pub text: String,
}

impl HistoryEntry {
    /// One entry as a history reply packs it; `None` when it does not hold
    /// together. Its line breaks and control bytes are read as a live chat
    /// line's are.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let e = parse::parse_history_entry(data)?;
        let mut text = e.message.to_vec();
        hxproto::sanitize::cr2lf(&mut text);
        hxproto::sanitize::strip_ansi(&mut text);
        Some(HistoryEntry {
            message_id: e.message_id,
            timestamp: e.timestamp,
            flags: e.flags,
            icon: e.icon_id,
            nick: text_in(e.nick),
            text: text_in(&text),
        })
    }
}

/// What the reply to a raw caller's request is to become:
/// [`Session::expect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// A request for chat `cid`'s history: an [`Event::ChatHistory`].
    ChatHistory { cid: u32 },
    /// An invitation to private chat: nothing, once it worked.
    ChatInvite,
    /// A request for the user list: an [`Event::UserList`].
    UserList,
    /// A new private chat: an [`Event::ChatCreated`].
    ChatCreate,
    /// Joining private chat `cid`: an [`Event::ChatJoined`].
    ChatJoin { cid: u32 },
    /// A private message: nothing, once it worked.
    Message,
    /// 1.2 flat news: an [`Event::NewsFile`].
    NewsFile,
    /// What a threaded-news bundle holds: an [`Event::NewsListing`].
    NewsListing,
    /// The articles in a category: an [`Event::NewsCategory`].
    NewsCategory,
    /// One article's text: an [`Event::NewsArticle`].
    NewsArticle,
    /// A change to news of either kind — a post, an article, a bundle or
    /// category made or deleted: nothing, once it worked.
    NewsChange,
}

/// Why the session ended. The caller closes the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Closed {
    /// The server answered the handshake with something other than TRTP,
    /// or with an error code (in the last four bytes).
    BadMagic([u8; 8]),
    /// The login was refused; the server's reason, if it gave one.
    LoginRefused(Option<String>),
    /// No login reply within [`Config::handshake_timeout_ms`].
    Timeout,
    /// The stream stopped making sense.
    Protocol(String),
    /// A transaction claimed more bytes than the session takes: the
    /// claimed size. Refused before anything is allocated for it.
    TooLarge(u32),
    /// The caller said the transport ended ([`Session::disconnected`]).
    Hangup,
}

/// Something the server said, or something that happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    LoggedIn(ServerInfo),
    /// The server's agreement, waiting for [`Session::agree`]. An empty
    /// agreement is answered without asking.
    Agreement(String),
    /// The session is logged in and has sent what a server expects after
    /// the login; requests may follow.
    Ready,
    /// A chat line. One that came with half of its media is dropped, as
    /// the extension says.
    Chat {
        cid: u32,
        uid: u16,
        text: String,
        media: Option<ChatMedia>,
    },
    /// An invitation to private chat `cid`, from `uid`.
    ChatInvite {
        cid: u32,
        uid: u16,
        name: String,
    },
    ChatSubject {
        cid: u32,
        subject: String,
    },
    /// The reply to a request for a chat's history; `has_more` when there
    /// is more before what it holds.
    ChatHistory {
        trans: u32,
        cid: u32,
        entries: Vec<HistoryEntry>,
        has_more: bool,
    },
    /// A private message, and the picture it carries where the server
    /// agreed to inline media. One that came with half of its media is
    /// dropped, as a chat line is.
    Message {
        uid: u16,
        from: String,
        text: String,
        media: Option<ChatMedia>,
    },
    /// A broadcast, or a message from the server itself; who sent it, when
    /// the server says.
    Broadcast {
        uid: u16,
        from: String,
        text: String,
    },
    /// The server's parting words before it disconnects us.
    Disconnecting(String),
    /// The reply to [`Session::user_list`], or the one sent after login;
    /// the public chat's subject, when the server sent one.
    UserList {
        trans: u32,
        users: Vec<User>,
        subject: Option<String>,
    },
    /// The reply to [`Session::chat_create`]: the new chat, and us in it.
    ChatCreated {
        trans: u32,
        cid: u32,
        user: User,
    },
    /// The reply to [`Session::chat_join`]: who is in the chat, and its
    /// subject when the server sent one.
    ChatJoined {
        trans: u32,
        cid: u32,
        users: Vec<User>,
        subject: Option<String>,
    },
    UserChanged {
        cid: u32,
        user: User,
    },
    UserLeft {
        cid: u32,
        uid: u16,
    },
    /// What the server says about us.
    SelfInfo {
        uid: u16,
        icon: u16,
        access: Option<u64>,
    },
    UserInfo {
        trans: u32,
        name: String,
        info: String,
    },
    /// What a folder holds.
    FileList {
        trans: u32,
        files: Vec<FileEntry>,
    },
    /// The whole of 1.2 flat news.
    NewsFile {
        trans: u32,
        text: String,
    },
    /// One new 1.2 flat news entry.
    NewsPosted(String),
    NewsListing {
        trans: u32,
        items: Vec<NewsItem>,
    },
    NewsCategory {
        trans: u32,
        articles: Vec<Article>,
    },
    NewsArticle {
        trans: u32,
        text: String,
    },
    /// A request that went wrong; the server's reason, if it gave one.
    Failed {
        trans: u32,
        reason: Option<String>,
    },
    /// The reply to [`Session::request`], whole; [`fields`] reads it. In
    /// raw mode, every reply.
    Reply {
        trans: u32,
        frame: Vec<u8>,
    },
    /// A transaction this session has no use for, whole; [`fields`] reads
    /// it. In raw mode, everything the server sends unasked that
    /// [`Config::handled`] leaves to the caller.
    Unhandled {
        opcode: u32,
        frame: Vec<u8>,
    },
    /// With [`Session::set_tap`], each transaction as it arrived, before
    /// the session acts on it, in plaintext whatever the transport: for a
    /// protocol trace.
    Received(Vec<u8>),
    Closed(Closed),
}

/// Why a request could not be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not logged in yet, or no longer.
    NotReady,
    /// A field too long for its 16-bit length.
    TooLong,
    /// [`Session::agree`] with no agreement waiting for an answer.
    NoAgreement,
    /// [`Session::send_raw`] given something that is not one whole
    /// transaction.
    Malformed,
    /// The server did not agree to the capability the request needs.
    NotAgreed,
    /// [`Session::expect`] on a trans already awaiting its reply.
    InUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for the server's magic.
    Magic,
    /// HOPE's step 1 sent, waiting for its reply.
    HopeStep1,
    /// Login sent, waiting for its reply.
    Login,
    LoggedIn,
    Closed,
}

/// What a sent request's reply should become.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    UserInfo,
    FileList,
    /// Replies nobody reads: the agreement, a message, a news post. Their
    /// errors still surface.
    Quiet,
    /// The keep-alive ping; its answer is not read, and its failure is
    /// not news.
    Keepalive,
    Raw,
    Expected(Expect),
}

pub struct Session {
    cfg: Config,
    state: State,
    magic: Vec<u8>,
    reader: FrameReader,
    /// What arrived before the login reply, replayed after it.
    early: Vec<Transaction>,
    out: Vec<u8>,
    events: VecDeque<Event>,
    trans: u32,
    pending: HashMap<u32, Pending>,
    server: Option<ServerInfo>,
    utf8: bool,
    now: u64,
    /// `None` when the configured timeout is too long to say.
    handshake_deadline: Option<u64>,
    /// When to stop waiting for an agreement; `None` once settled.
    agreement_deadline: Option<u64>,
    /// An agreement with text is showing and has not been answered. Until
    /// it is, a 1.5+ server is sent nothing else.
    awaiting_agree: bool,
    agreed: bool,
    ready: bool,
    /// The trans of the user list sent once the login settled.
    roster_trans: Option<u32>,
    last_sent: u64,
    /// A request was sent outside `feed` and `tick`, which carry the time,
    /// so `last_sent` waits for the next reading of the clock.
    unstamped: bool,
    /// Inside `feed` or `tick`: `now` is the current time.
    clocked: bool,
    /// The trans the login's reply answers: HOPE's step 2, or the LOGIN.
    login_trans: u32,
    /// HOPE's offer and its randomness, until step 2 goes.
    hope: Option<hope::Pending>,
    /// What HOPE agreed, and the transport it runs through. `out` is
    /// plaintext for it; `before_transport` was queued before it began,
    /// and goes as it is.
    #[cfg(feature = "hope")]
    negotiated: Option<hope::Negotiated>,
    transport: Option<hope::Transport>,
    before_transport: Vec<u8>,
    tap: bool,
}

impl Session {
    /// A session that has queued its handshake; take it with
    /// [`Session::take_outgoing`] once the socket is open.
    pub fn new(cfg: Config, now_ms: u64) -> Self {
        let handshake_deadline = now_ms.checked_add(cfg.handshake_timeout_ms);
        Session {
            cfg,
            state: State::Magic,
            magic: Vec::new(),
            reader: FrameReader::new(),
            early: Vec::new(),
            out: CLIENT_MAGIC.to_vec(),
            events: VecDeque::new(),
            trans: LOGIN_TRANS + 1,
            pending: HashMap::new(),
            server: None,
            utf8: false,
            now: now_ms,
            handshake_deadline,
            agreement_deadline: None,
            awaiting_agree: false,
            agreed: false,
            ready: false,
            roster_trans: None,
            last_sent: now_ms,
            unstamped: false,
            clocked: false,
            login_trans: LOGIN_TRANS,
            hope: None,
            #[cfg(feature = "hope")]
            negotiated: None,
            transport: None,
            before_transport: Vec::new(),
            tap: false,
        }
    }

    /// A session that logs in with HOPE: `offer` in step 1 on the login's
    /// trans, the credentials in step 2 on the next, and from step 2's
    /// reply on, everything through the transport the server chose.
    /// `random` decides where Blowfish's rekey markers go.
    #[cfg(feature = "hope")]
    pub fn with_hope(
        cfg: Config,
        offer: hxhope::client::Offer,
        random: hxhope::Random,
        now_ms: u64,
    ) -> Self {
        let mut s = Session::new(cfg, now_ms);
        s.login_trans = s.take_trans();
        s.hope = Some((offer, random));
        s
    }

    /// Bytes to write to the socket, in order. Empty when there is nothing.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        let plain = std::mem::take(&mut self.out);
        let mut bytes = std::mem::take(&mut self.before_transport);
        match self.transport.as_mut().map(|t| t.encode(&plain)) {
            None => bytes.extend_from_slice(&plain),
            Some(Ok(encoded)) => bytes.extend_from_slice(&encoded),
            Some(Err(e)) => self.close(Closed::Protocol(e.to_string())),
        }
        bytes
    }

    /// What [`Session::take_outgoing`] is about to send, before a HOPE
    /// transport makes ciphertext of it: for a protocol trace.
    pub fn pending_plaintext(&self) -> Vec<u8> {
        [&self.before_transport[..], &self.out[..]].concat()
    }

    /// The trans the login goes out on, which its reply carries: HOPE's
    /// step 2 under [`Session::with_hope`].
    pub fn login_trans(&self) -> u32 {
        self.login_trans
    }

    /// What HOPE agreed, once step 2 has gone.
    #[cfg(feature = "hope")]
    pub fn negotiated(&self) -> Option<&hxhope::Negotiated> {
        self.negotiated.as_ref()
    }

    /// Whether each transaction is also handed over as it arrives, as
    /// [`Event::Received`].
    pub fn set_tap(&mut self, on: bool) {
        self.tap = on;
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// The trans the user list sent with [`Event::Ready`] went out on: its
    /// answer is an [`Event::UserList`] or an [`Event::Failed`] with this
    /// trans, which tells a refusal of the list from a refusal of anything
    /// else sent at login. `None` in raw mode, where the list is the
    /// caller's.
    pub fn roster_trans(&self) -> Option<u32> {
        self.roster_trans
    }

    /// The server, once the login has been answered.
    pub fn server(&self) -> Option<&ServerInfo> {
        self.server.as_ref()
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Whether a transport that ends now ends part way through a
    /// transaction: cut off, rather than closed.
    pub fn mid_transaction(&self) -> bool {
        !self.reader.is_idle()
            || (self.state == State::Magic && !self.magic.is_empty())
            || self.transport.as_ref().is_some_and(|t| !t.idle())
    }

    /// When [`Session::tick`] next has something to do.
    pub fn next_deadline(&self) -> Option<u64> {
        match self.state {
            State::Closed => None,
            State::Magic | State::HopeStep1 | State::Login => self.handshake_deadline,
            State::LoggedIn => {
                let keepalive = self.keepalive_due();
                match (self.agreement_deadline, keepalive) {
                    (Some(a), Some(k)) => Some(a.min(k)),
                    (a, k) => a.or(k),
                }
            }
        }
    }

    /// Whatever arrived from the server, in whatever pieces it came, and
    /// when. The time matters: it is when the wait for an agreement
    /// starts.
    pub fn feed(&mut self, bytes: &[u8], now_ms: u64) {
        self.clock(now_ms);
        self.clocked = true;
        match self.transport.as_mut() {
            None => self.feed_clocked(bytes),
            Some(t) => {
                let mut plain = Vec::new();
                match t.decode(bytes, &mut plain) {
                    Ok(()) => self.feed_clocked(&plain),
                    Err(e) => self.close(Closed::Protocol(e.to_string())),
                }
            }
        }
        self.clocked = false;
    }

    fn feed_clocked(&mut self, mut bytes: &[u8]) {
        if self.state == State::Magic {
            let want = SERVER_MAGIC.len() - self.magic.len();
            let take = want.min(bytes.len());
            self.magic.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.magic.len() < SERVER_MAGIC.len() {
                return;
            }
            if self.magic != SERVER_MAGIC {
                let mut got = [0u8; 8];
                got.copy_from_slice(&self.magic);
                self.close(Closed::BadMagic(got));
                return;
            }
            if let Some(pending) = &self.hope {
                match hope::step1(pending, LOGIN_TRANS) {
                    Ok(step1) => {
                        self.out.extend_from_slice(&step1);
                        self.stamp_sent();
                        self.state = State::HopeStep1;
                    }
                    Err(e) => self.close(Closed::Protocol(e)),
                }
            } else {
                self.state = State::Login;
                let caps = self.cfg.caps;
                // Credentials go as typed, in UTF-8, as GtkHx sends them; a
                // server compares them as bytes.
                let login = request::login(
                    self.cfg.login.as_bytes(),
                    self.cfg.password.as_bytes(),
                    self.cfg.icon,
                    self.cfg.version,
                    caps,
                );
                self.send_frame(&login, LOGIN_TRANS);
            }
        }
        if self.state == State::Closed {
            return;
        }
        self.reader.push(bytes);
        loop {
            let next = self.reader.next_transaction();
            for trans in self.reader.take_abandoned() {
                match self.pending.remove(&trans) {
                    // The keep-alive's failure is no news, as with a whole
                    // reply. A raw caller hears of any other reply only as
                    // the whole frame, which a cut-short one never becomes;
                    // a failure on a trans it neither sent nor expected (the
                    // session's own agree, say) is nothing it can act on.
                    None | Some(Pending::Keepalive) => {}
                    Some(p) if self.cfg.raw && !matches!(p, Pending::Expected(_)) => {}
                    Some(_) => self.events.push_back(Event::Failed {
                        trans,
                        reason: Some("the server's reply was cut short".into()),
                    }),
                }
            }
            match next {
                Ok(Some(t)) => {
                    if self.tap {
                        self.events.push_back(Event::Received(t.buf.clone()));
                    }
                    self.dispatch(t);
                    if self.state == State::Closed {
                        return;
                    }
                }
                Ok(None) => return,
                Err(FrameError::TooLarge(n)) => {
                    self.close(Closed::TooLarge(n));
                    return;
                }
            }
        }
    }

    /// The time, for the handshake deadline, the wait for an agreement,
    /// and the keep-alive.
    pub fn tick(&mut self, now_ms: u64) {
        self.clock(now_ms);
        self.clocked = true;
        self.tick_clocked(now_ms);
        self.clocked = false;
    }

    fn tick_clocked(&mut self, now_ms: u64) {
        match self.state {
            State::Closed => {}
            State::Magic | State::HopeStep1 | State::Login => {
                if self.handshake_deadline.is_some_and(|d| now_ms >= d) {
                    self.close(Closed::Timeout);
                }
            }
            State::LoggedIn => {
                if self.agreement_deadline.is_some_and(|d| now_ms >= d) {
                    // Neither an agreement nor anything else that settles
                    // it: carry on as if there were none, as GtkHx does.
                    self.agreement_deadline = None;
                    self.after_agreement();
                }
                if self.keepalive_due().is_some_and(|d| now_ms >= d) {
                    self.send(
                        &Request::new(ClientHdr::Ping as u32),
                        Some(Pending::Keepalive),
                    );
                }
            }
        }
    }

    /// The transport ended, by either side. The session is over; a new
    /// connection takes a new session.
    pub fn disconnected(&mut self) {
        if self.state != State::Closed {
            self.close(Closed::Hangup);
        }
    }

    // ---- Requests ------------------------------------------------------

    /// The name and icon the agreement, or a 1.2 server's user change, goes
    /// with from now on: a raw caller's own user changes are not seen here.
    /// Nothing is sent.
    pub fn set_identity(&mut self, nick: &str, icon: u16) {
        self.cfg.nick = nick.into();
        self.cfg.icon = icon;
    }

    /// Answer the agreement the server showed. The name and icon go with
    /// it: this is where the server learns them.
    pub fn agree(&mut self) -> Result<(), Error> {
        if self.state != State::LoggedIn {
            return Err(Error::NotReady);
        }
        if !self.awaiting_agree {
            return Err(Error::NoAgreement);
        }
        self.send_agree()
    }

    /// Public chat. Chat is not answered, but a server that refuses it
    /// says so with a failure on the trans returned here.
    pub fn chat(&mut self, text: &str) -> Result<u32, Error> {
        self.chat_in(0, text, 0)
    }

    /// An emote: "/me waves" as the server formats it.
    pub fn emote(&mut self, text: &str) -> Result<u32, Error> {
        self.chat_in(0, text, 1)
    }

    /// Chat in a private chat room; `cid` 0 is the public chat.
    pub fn chat_in(&mut self, cid: u32, text: &str, style: u16) -> Result<u32, Error> {
        self.ensure_ready()?;
        let body = self.body_out(text);
        let r = request::chat(&body, cid, style).ok_or(Error::TooLong)?;
        Ok(self.send(&r, None))
    }

    /// A private message; the trans its reply will carry.
    pub fn message(&mut self, uid: u16, text: &str) -> Result<u32, Error> {
        self.ensure_ready()?;
        let body = self.body_out(text);
        let r = request::msg(uid, &body).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Quiet)))
    }

    pub fn user_list(&mut self) -> Result<u32, Error> {
        self.ensure_ready()?;
        Ok(self.send(
            &Request::new(ClientHdr::UserGetList as u32),
            Some(Pending::Expected(Expect::UserList)),
        ))
    }

    pub fn user_info(&mut self, uid: u16) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::user_info(uid).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::UserInfo)))
    }

    /// Change the name and icon others see. Servers do not answer this
    /// one; the change comes back as an [`Event::UserChanged`] for us.
    pub fn set_nick(&mut self, nick: &str, icon: u16) -> Result<u32, Error> {
        self.ensure_ready()?;
        let name = text_out(nick, self.utf8);
        let r = request::user_change(&name, icon).ok_or(Error::TooLong)?;
        self.cfg.nick = nick.into();
        self.cfg.icon = icon;
        Ok(self.send(&r, None))
    }

    /// Open a private chat with `uid`.
    pub fn chat_create(&mut self, uid: u16) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::chat_create(uid).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Expected(Expect::ChatCreate))))
    }

    /// Invite `uid` into private chat `cid`.
    pub fn chat_invite(&mut self, cid: u32, uid: u16) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::chat_invite(cid, uid).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Expected(Expect::ChatInvite))))
    }

    /// Join private chat `cid`.
    pub fn chat_join(&mut self, cid: u32) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::chat_id_only(ClientHdr::ChatJoin, cid).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Expected(Expect::ChatJoin { cid }))))
    }

    /// Leave private chat `cid`.
    pub fn chat_part(&mut self, cid: u32) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::chat_id_only(ClientHdr::ChatPart, cid).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Quiet)))
    }

    /// Turn down an invitation to private chat `cid`.
    pub fn chat_decline(&mut self, cid: u32) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::chat_id_only(ClientHdr::ChatDecline, cid).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Quiet)))
    }

    pub fn chat_subject(&mut self, cid: u32, subject: &str) -> Result<u32, Error> {
        self.ensure_ready()?;
        let subject = text_out(subject, self.utf8);
        let r = request::chat_subject(cid, &subject).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Quiet)))
    }

    /// Up to `limit` lines of chat `cid`'s history, older than
    /// `before` or newer than `after`; 0 leaves each to the server. Only
    /// where the server agreed to [`cap::CHAT_HISTORY`]: an older one may
    /// refuse an opcode it does not know, or hang up on it.
    pub fn chat_history(
        &mut self,
        cid: u32,
        before: u64,
        after: u64,
        limit: u16,
    ) -> Result<u32, Error> {
        self.ensure_ready()?;
        if !self.agreed(cap::CHAT_HISTORY) {
            return Err(Error::NotAgreed);
        }
        let r = request::chat_history(cid, before, after, limit).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Expected(Expect::ChatHistory { cid }))))
    }

    /// 1.2 flat news, all of it.
    pub fn news_file(&mut self) -> Result<u32, Error> {
        self.ensure_ready()?;
        Ok(self.send(
            &Request::new(ClientHdr::NewsGetFile as u32),
            Some(Pending::Expected(Expect::NewsFile)),
        ))
    }

    /// Add an entry to 1.2 flat news.
    pub fn post_news(&mut self, text: &str) -> Result<u32, Error> {
        self.ensure_ready()?;
        let body = self.body_out(text);
        let r = request::news_post(&body).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Quiet)))
    }

    // Each path-taking request comes twice: by name, encoded as this
    // session sends text, and by the bytes a listing gave (`name_bytes`),
    // which name a thing back to the server exactly. Empty components are
    // skipped, so `&[""]` is the root. A component longer than 255 bytes
    // is `TooLong`.

    /// What a threaded-news bundle holds; the root is `&[]`.
    pub fn news_listing(&mut self, path: &[&str]) -> Result<u32, Error> {
        let path = self.path_out(path);
        self.news_listing_raw(&path.iter().map(Vec::as_slice).collect::<Vec<_>>())
    }

    pub fn news_listing_raw(&mut self, path: &[&[u8]]) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::news_list(ClientHdr::NewsListDir, path).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Expected(Expect::NewsListing))))
    }

    /// The articles in a threaded-news category.
    pub fn news_category(&mut self, path: &[&str]) -> Result<u32, Error> {
        let path = self.path_out(path);
        self.news_category_raw(&path.iter().map(Vec::as_slice).collect::<Vec<_>>())
    }

    pub fn news_category_raw(&mut self, path: &[&[u8]]) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::news_list(ClientHdr::NewsListCategory, path).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Expected(Expect::NewsCategory))))
    }

    /// One article's text.
    pub fn news_article(&mut self, path: &[&str], id: u32) -> Result<u32, Error> {
        let path = self.path_out(path);
        self.news_article_raw(&path.iter().map(Vec::as_slice).collect::<Vec<_>>(), id)
    }

    pub fn news_article_raw(&mut self, path: &[&[u8]], id: u32) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::news_article(path, id).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Expected(Expect::NewsArticle))))
    }

    /// Post an article to a threaded-news category, in reply to article
    /// `parent`, or 0 to start a thread.
    pub fn news_post_article(
        &mut self,
        path: &[&str],
        parent: u32,
        subject: &str,
        text: &str,
    ) -> Result<u32, Error> {
        let path = self.path_out(path);
        let path: Vec<&[u8]> = path.iter().map(Vec::as_slice).collect();
        self.news_post_article_raw(&path, parent, subject, text)
    }

    pub fn news_post_article_raw(
        &mut self,
        path: &[&[u8]],
        parent: u32,
        subject: &str,
        text: &str,
    ) -> Result<u32, Error> {
        self.ensure_ready()?;
        let (subject, body) = (text_out(subject, self.utf8), self.body_out(text));
        let r = request::news_post_article(path, parent, &subject, &body).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Quiet)))
    }

    /// Delete article `id` from a category.
    pub fn news_delete_article(&mut self, path: &[&str], id: u32) -> Result<u32, Error> {
        let path = self.path_out(path);
        self.news_delete_article_raw(&path.iter().map(Vec::as_slice).collect::<Vec<_>>(), id)
    }

    pub fn news_delete_article_raw(&mut self, path: &[&[u8]], id: u32) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::news_delete_article(path, id).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Quiet)))
    }

    /// Delete a bundle or a category, and everything in it.
    pub fn news_delete(&mut self, path: &[&str]) -> Result<u32, Error> {
        let path = self.path_out(path);
        self.news_delete_raw(&path.iter().map(Vec::as_slice).collect::<Vec<_>>())
    }

    pub fn news_delete_raw(&mut self, path: &[&[u8]]) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::news_delete(path).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Quiet)))
    }

    /// Make a bundle named `name` in the bundle at `path`.
    pub fn news_create_bundle(&mut self, path: &[&str], name: &str) -> Result<u32, Error> {
        let path = self.path_out(path);
        self.news_create_bundle_raw(&path.iter().map(Vec::as_slice).collect::<Vec<_>>(), name)
    }

    pub fn news_create_bundle_raw(&mut self, path: &[&[u8]], name: &str) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r =
            request::news_create_bundle(path, &text_out(name, self.utf8)).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Quiet)))
    }

    /// Make a category named `name` in the bundle at `path`.
    pub fn news_create_category(&mut self, path: &[&str], name: &str) -> Result<u32, Error> {
        let path = self.path_out(path);
        self.news_create_category_raw(&path.iter().map(Vec::as_slice).collect::<Vec<_>>(), name)
    }

    pub fn news_create_category_raw(&mut self, path: &[&[u8]], name: &str) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::news_create_category(path, &text_out(name, self.utf8))
            .ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::Quiet)))
    }

    /// What the folder at `path` holds; the root is `&[]`. The reply
    /// does not say which folder it lists; the caller keeps the trans.
    pub fn file_list(&mut self, path: &[&str]) -> Result<u32, Error> {
        let path = self.path_out(path);
        self.file_list_raw(&path.iter().map(Vec::as_slice).collect::<Vec<_>>())
    }

    pub fn file_list_raw(&mut self, path: &[&[u8]]) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::file_list(path).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::FileList)))
    }

    /// The trans for a transaction the caller builds itself, for
    /// [`Session::send_raw`]. Nothing else the session sends uses it.
    /// It may be taken before the login is answered: the caller can
    /// number a request before the session lets it go.
    pub fn take_trans(&mut self) -> u32 {
        let trans = self.trans;
        // 0 is a trans like any other to a server, but the original client
        // never used it, and skipping it costs nothing.
        self.trans = self.trans.wrapping_add(1).max(1);
        trans
    }

    /// One whole transaction the caller built on a trans from
    /// [`Session::take_trans`], sent as it is; raw mode only, once logged
    /// in. It may go before the agreement is answered, which a 1.5+
    /// server may hold against it.
    pub fn send_raw(&mut self, frame: &[u8]) -> Result<(), Error> {
        if !self.cfg.raw || self.state != State::LoggedIn {
            return Err(Error::NotReady);
        }
        let len = |at: usize| {
            u32::from_be_bytes([frame[at], frame[at + 1], frame[at + 2], frame[at + 3]])
        };
        if frame.len() < 22 || len(16) as usize != frame.len() - 20 {
            return Err(Error::Malformed);
        }
        self.out.extend_from_slice(frame);
        self.stamp_sent();
        Ok(())
    }

    /// The reply to the raw transaction on `trans` becomes what `what`
    /// says, or [`Event::Failed`]: never [`Event::Reply`]. Before the
    /// transaction goes, so that its reply cannot come first.
    /// Raw mode only, and on a trans of the caller's own: one the session
    /// awaits a reply on is not the caller's to take over.
    pub fn expect(&mut self, trans: u32, what: Expect) -> Result<(), Error> {
        if !self.cfg.raw {
            return Err(Error::NotReady);
        }
        if self.pending.contains_key(&trans) {
            return Err(Error::InUse);
        }
        self.remember(trans, Pending::Expected(what));
        Ok(())
    }

    /// Any transaction. Its reply comes back as [`Event::Reply`], or
    /// [`Event::Failed`].
    pub fn request(&mut self, req: &Request) -> Result<u32, Error> {
        self.ensure_ready()?;
        if req.pack(0).is_none() {
            return Err(Error::TooLong);
        }
        Ok(self.send(req, Some(Pending::Raw)))
    }

    /// Text as this session sends it: in the negotiated encoding.
    pub fn encode(&self, text: &str) -> Vec<u8> {
        text_out(text, self.utf8)
    }

    /// Text as this session receives it.
    pub fn decode(&self, bytes: &[u8]) -> String {
        text_in(bytes)
    }

    // ---- The receive side ----------------------------------------------

    fn dispatch(&mut self, t: Transaction) {
        let kind = route(t.type_);
        if matches!(self.state, State::HopeStep1 | State::Login) && kind != HandlerKind::Task {
            // Some servers (RetroMac, MacDomain) send their self-info or
            // the agreement before answering the login. Nothing can act on
            // them until it is answered, so they wait for it.
            if self.early.len() >= MAX_EARLY {
                self.close(Closed::Protocol(format!(
                    "{MAX_EARLY} transactions and still no login reply"
                )));
                return;
            }
            self.early.push(t);
            return;
        }
        if self.cfg.raw && kind != HandlerKind::Task && !self.handles(kind) {
            // Handed over before it is acted on: it came before what
            // answering it sets off.
            self.events.push_back(Event::Unhandled {
                opcode: t.type_,
                frame: t.buf.clone(),
            });
            if kind == HandlerKind::Agreement {
                self.agreement(&t);
            }
            return;
        }
        let len = t.buf.len();
        match kind {
            HandlerKind::Task => self.reply(t),
            HandlerKind::Chat => {
                let Ok(media) = self.media(&t.buf) else {
                    return;
                };
                let c = parse::parse_chat(&t.buf, len, MAX_BODY);
                let text = self.decode(c.text());
                self.events.push_back(Event::Chat {
                    cid: c.cid,
                    uid: c.uid,
                    text,
                    media,
                });
            }
            HandlerKind::ChatInvite => {
                let i = parse::parse_chat_invite(&t.buf, len, MAX_NICK);
                let name = field_text(&i.name);
                self.events.push_back(Event::ChatInvite {
                    cid: i.cid,
                    uid: i.uid,
                    name,
                });
            }
            HandlerKind::ChatSubject => {
                let s = parse::parse_chat_subject(&t.buf, len, MAX_SUBJECT);
                let subject = field_text(&s.subject);
                self.events.push_back(Event::ChatSubject {
                    cid: s.cid,
                    subject,
                });
            }
            HandlerKind::Msg => {
                let m = parse::parse_msg(&t.buf, len, MAX_NAME, MAX_BODY);
                let (from, text) = (field_text(&m.name), self.decode(&m.msg));
                // A broadcast arrives as its own opcode, or as a message
                // from uid 0 on servers that have no such opcode.
                if t.type_ == 0x163 || m.uid == 0 {
                    self.events.push_back(Event::Broadcast {
                        uid: m.uid,
                        from,
                        text,
                    });
                } else if let Ok(media) = self.media(&t.buf) {
                    self.events.push_back(Event::Message {
                        uid: m.uid,
                        from,
                        text,
                        media,
                    });
                }
            }
            HandlerKind::PoliteQuit => {
                let m = parse::parse_msg(&t.buf, len, MAX_NAME, MAX_BODY);
                let text = self.decode(&m.msg);
                self.events.push_back(Event::Disconnecting(text));
            }
            HandlerKind::UserChange => {
                let c = parse::parse_user_change(&t.buf, len, MAX_NICK);
                self.events.push_back(Event::UserChanged {
                    cid: c.cid,
                    user: changed_user(&c),
                });
            }
            HandlerKind::UserPart => {
                let p = parse::parse_user_part(&t.buf, len);
                self.events.push_back(Event::UserLeft {
                    cid: p.cid,
                    uid: p.uid,
                });
            }
            HandlerKind::UserSelfInfo => {
                let s = parse::parse_selfinfo(&t.buf, len);
                self.events.push_back(Event::SelfInfo {
                    uid: s.uid,
                    icon: s.icon,
                    access: (s.seen & parse::SELFINFO_ACCESS != 0).then_some(s.access),
                });
            }
            HandlerKind::NewsPost => {
                for entry in parse::news_post_chunks(&t.buf, len, MAX_NEWS) {
                    let text = self.decode(&entry);
                    self.events.push_back(Event::NewsPosted(text));
                }
            }
            HandlerKind::Agreement => self.agreement(&t),
            _ => self.events.push_back(Event::Unhandled {
                opcode: t.type_,
                frame: t.buf,
            }),
        }
    }

    fn agreement(&mut self, t: &Transaction) {
        // It settles the wait whatever it says.
        self.agreement_deadline = None;
        if self.agreed {
            return;
        }
        let (kind, body) = parse::parse_agreement(&t.buf, t.buf.len(), MAX_NEWS);
        match kind {
            parse::AgreementResult::Ok if !body.is_empty() => {
                self.awaiting_agree = true;
                let text = self.decode(&body);
                self.events.push_back(Event::Agreement(text));
            }
            // A 1.0/1.2 server has no agree to answer with; it got the
            // name in a user change. One that says it has no agreement is
            // a 1.5 server hiding its version, as mhxd can, and is
            // answered: on some, the agree finishes the login.
            parse::AgreementResult::Missing if self.version() == 0 => {}
            // Nothing to show: answer it at once, as GtkHx does.
            _ => {
                let _ = self.send_agree();
            }
        }
    }

    fn reply(&mut self, t: Transaction) {
        // The first reply is the login's, whatever trans it carries: some
        // servers answer it on 0, and GtkHx takes it the same way.
        #[cfg(feature = "hope")]
        if self.state == State::HopeStep1 {
            self.hope_reply(t);
            return;
        }
        if self.state == State::Login {
            self.login_reply(t);
            return;
        }
        let pending = self.pending.remove(&t.trans);
        if self.cfg.raw && !matches!(pending, Some(Pending::Expected(_))) {
            // The session's own too, so the caller sees their refusals;
            // all but the keep-alive's, which are no news to anyone.
            if pending != Some(Pending::Keepalive) {
                self.events.push_back(Event::Reply {
                    trans: t.trans,
                    frame: t.buf,
                });
            }
            return;
        }
        let len = t.buf.len();
        if t.is_error() {
            let reason = parse::parse_task_error(&t.buf, len, MAX_BODY).map(|r| self.decode(&r));
            // The keep-alive's own failures are noise: a server older than
            // 1.8.5 answers a ping with an error.
            if pending != Some(Pending::Keepalive) {
                self.events.push_back(Event::Failed {
                    trans: t.trans,
                    reason,
                });
            }
            return;
        }
        match pending {
            Some(Pending::Expected(Expect::UserList)) => {
                self.events.push_back(Event::UserList {
                    trans: t.trans,
                    users: listed_users(&t.buf),
                    subject: listed_subject(&t.buf),
                });
            }
            Some(Pending::Expected(Expect::ChatCreate)) => {
                let c = parse::parse_user_change(&t.buf, len, MAX_NICK);
                self.events.push_back(Event::ChatCreated {
                    trans: t.trans,
                    cid: c.cid,
                    user: changed_user(&c),
                });
            }
            Some(Pending::Expected(Expect::ChatJoin { cid })) => {
                self.events.push_back(Event::ChatJoined {
                    trans: t.trans,
                    cid,
                    users: listed_users(&t.buf),
                    subject: listed_subject(&t.buf),
                });
            }
            Some(Pending::UserInfo) => {
                let i = parse::parse_user_info(&t.buf, len, MAX_NICK, 4096);
                let (name, info) = (field_text(&i.name), self.decode(&i.info));
                self.events.push_back(Event::UserInfo {
                    trans: t.trans,
                    name,
                    info,
                });
            }
            Some(Pending::Expected(Expect::NewsFile)) => {
                let text = parse::parse_news_file(&t.buf, len, MAX_NEWS)
                    .map(|b| self.decode(&b))
                    .unwrap_or_default();
                self.events.push_back(Event::NewsFile {
                    trans: t.trans,
                    text,
                });
            }
            Some(Pending::Expected(Expect::NewsListing)) => {
                let items = parse::parse_dirlist(&t.buf, len)
                    .entries
                    .into_iter()
                    .map(|e| NewsItem {
                        name: field_text(&e.name),
                        name_bytes: e.name,
                        bundle: e.kind == parse::NewsDirKind::Folder,
                    })
                    .collect();
                self.events.push_back(Event::NewsListing {
                    trans: t.trans,
                    items,
                });
            }
            Some(Pending::Expected(Expect::NewsCategory)) => {
                let articles = parse::parse_catlist(&t.buf, len)
                    .map(|c| c.posts)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|p| Article {
                        id: p.postid,
                        parent: p.parentid,
                        subject: field_text(&p.subject),
                        poster: field_text(&p.sender),
                        year: p.date_base_year,
                        seconds: p.date_seconds,
                        mime: p
                            .parts
                            .into_iter()
                            .next()
                            .map(|m| m.mime_type)
                            .unwrap_or_default(),
                    })
                    .collect();
                self.events.push_back(Event::NewsCategory {
                    trans: t.trans,
                    articles,
                });
            }
            Some(Pending::Expected(Expect::NewsArticle)) => {
                let a = parse::parse_news_thread_reply(&t.buf, len, MAX_NEWS);
                let text = a.text.map(|b| self.decode(&b)).unwrap_or_default();
                self.events.push_back(Event::NewsArticle {
                    trans: t.trans,
                    text,
                });
            }
            Some(Pending::FileList) => {
                let mut files: Vec<FileEntry> = Vec::new();
                // Whether the last field was an entry, which a companion
                // that follows belongs to. Matched by place, not count: a
                // server sends one only for the entries that need it.
                let mut after_entry = false;
                for c in hxproto::wire::ChunkIter::over_message(&t.buf, len) {
                    match c.tag {
                        FILE_LIST_ENTRY => {
                            after_entry = false;
                            // hxproto's parser takes the field with its
                            // header, as it sits in the frame.
                            let mut field = Vec::with_capacity(4 + c.data.len());
                            field.extend_from_slice(&c.tag.to_be_bytes());
                            field.extend_from_slice(&(c.data.len() as u16).to_be_bytes());
                            field.extend_from_slice(c.data);
                            // A malformed entry is skipped; its neighbors
                            // still list.
                            if let Some((e, _)) = parse::parse_file_list_entry(&field, 0) {
                                files.push(FileEntry {
                                    name: self.decode(e.name),
                                    name_bytes: e.name.to_vec(),
                                    folder: e.ftype == parse::FTYPE_FLDR,
                                    size: u64::from(e.fsize),
                                    type_code: e.ftype.to_be_bytes(),
                                    creator: e.fcreator.to_be_bytes(),
                                });
                                after_entry = true;
                            }
                        }
                        FILE_SIZE_64 | FOLDER_ITEMS_64 if after_entry && c.data.len() == 8 => {
                            let mut v = [0u8; 8];
                            v.copy_from_slice(c.data);
                            if let Some(last) = files.last_mut() {
                                last.size = u64::from_be_bytes(v);
                            }
                        }
                        _ => after_entry = false,
                    }
                }
                self.events.push_back(Event::FileList {
                    trans: t.trans,
                    files,
                });
            }
            Some(Pending::Raw) => self.events.push_back(Event::Reply {
                trans: t.trans,
                frame: t.buf,
            }),
            Some(Pending::Expected(Expect::ChatHistory { cid })) => {
                let mut entries = Vec::new();
                let mut has_more = false;
                for c in hxproto::wire::ChunkIter::over_message(&t.buf, len) {
                    match c.tag {
                        // A malformed entry is skipped; its neighbors
                        // still read.
                        tag::HISTORY_ENTRY => entries.extend(HistoryEntry::parse(c.data)),
                        tag::HISTORY_HAS_MORE => {
                            if let Some(&b) = c.data.first() {
                                has_more = b != 0;
                            }
                        }
                        _ => {}
                    }
                }
                self.events.push_back(Event::ChatHistory {
                    trans: t.trans,
                    cid,
                    entries,
                    has_more,
                });
            }
            // Answered, and nothing in the answer to read.
            Some(Pending::Quiet)
            | Some(Pending::Keepalive)
            | Some(Pending::Expected(Expect::ChatInvite))
            | Some(Pending::Expected(Expect::Message))
            | Some(Pending::Expected(Expect::NewsChange))
            | None => {}
        }
    }

    fn login_reply(&mut self, t: Transaction) {
        let len = t.buf.len();
        if t.is_error() {
            let reason = parse::parse_task_error(&t.buf, len, MAX_BODY).map(|r| text_in(&r));
            if self.cfg.raw {
                self.events.push_back(Event::Reply {
                    trans: t.trans,
                    frame: t.buf,
                });
            }
            self.close(Closed::LoginRefused(reason));
            return;
        }
        let mut name = vec![0u8; u16::MAX as usize];
        let (info, n) = parse::parse_login(&t.buf, len, &mut name);
        let caps = (info.caps as u16) & self.cfg.caps;
        self.utf8 = caps & cap::TEXT_ENCODING != 0;
        let has = |bit| info.seen & bit != 0;
        let server = ServerInfo {
            version: if has(parse::LOGIN_SEEN_VERSION) {
                info.version
            } else {
                0
            },
            name: has(parse::LOGIN_SEEN_SERVERNAME).then(|| self.decode(&name[..n])),
            uid: has(parse::LOGIN_SEEN_UID).then_some(info.uid),
            caps,
        };
        let version = server.version;
        self.server = Some(server.clone());
        self.state = State::LoggedIn;
        if self.cfg.raw {
            self.events.push_back(Event::Reply {
                trans: t.trans,
                frame: t.buf,
            });
        }
        self.events.push_back(Event::LoggedIn(server));
        if version == 0 {
            // A 1.0/1.2 server: no agreement flow, and the name has to be
            // sent on its own. The fetches follow at once.
            let name = text_out(&self.cfg.nick, self.utf8);
            if let Some(r) = request::user_change(&name, self.cfg.icon) {
                self.send(&r, Some(Pending::Quiet));
            }
        } else {
            // Too long a wait to say is no deadline: wait for the agreement.
            self.agreement_deadline = self.now.checked_add(self.cfg.agreement_wait_ms);
        }
        // What came before the reply goes before what follows the login.
        for t in std::mem::take(&mut self.early) {
            self.dispatch(t);
            if self.state == State::Closed {
                return;
            }
        }
        if version == 0 {
            self.after_agreement();
        }
    }

    /// HOPE's step-1 reply: send step 2, and run what follows through the
    /// transport the server chose.
    #[cfg(feature = "hope")]
    fn hope_reply(&mut self, t: Transaction) {
        if t.is_error() {
            let reason =
                parse::parse_task_error(&t.buf, t.buf.len(), MAX_BODY).map(|r| text_in(&r));
            self.close(Closed::LoginRefused(reason));
            return;
        }
        let pending = self.hope.take().expect("step 1 went with an offer");
        let who = hope::Login {
            login: self.cfg.login.as_bytes(),
            password: self.cfg.password.as_bytes(),
            name: self.cfg.nick.as_bytes(),
            icon: self.cfg.icon,
            version: self.cfg.version,
            caps: self.cfg.caps,
        };
        match hope::step2(pending, &t.buf, &who, self.login_trans) {
            Ok((step2, transport, negotiated)) => {
                // Everything queued so far goes as it is; after step 2,
                // through the transport.
                self.before_transport.append(&mut self.out);
                self.before_transport.extend_from_slice(&step2);
                self.stamp_sent();
                self.transport = Some(transport);
                self.negotiated = Some(negotiated);
                self.state = State::Login;
            }
            Err(e) => self.close(Closed::Protocol(e)),
        }
    }

    fn send_agree(&mut self) -> Result<(), Error> {
        if self.agreed {
            return Ok(());
        }
        let name = text_out(&self.cfg.nick, self.utf8);
        let r = request::agree(&name, self.cfg.icon).ok_or(Error::TooLong)?;
        self.send(&r, Some(Pending::Quiet));
        self.agreed = true;
        self.awaiting_agree = false;
        self.agreement_deadline = None;
        self.after_agreement();
        Ok(())
    }

    /// What a server expects once the login is settled: the user list.
    fn after_agreement(&mut self) {
        if self.ready {
            return;
        }
        self.ready = true;
        if self.cfg.raw {
            self.events.push_back(Event::Ready);
            return;
        }
        let trans = self.send(
            &Request::new(ClientHdr::UserGetList as u32),
            Some(Pending::Expected(Expect::UserList)),
        );
        self.roster_trans = Some(trans);
        self.events.push_back(Event::Ready);
    }

    // ---- Plumbing ------------------------------------------------------

    fn version(&self) -> u16 {
        self.server.as_ref().map_or(0, |s| s.version)
    }

    fn agreed(&self, bit: u16) -> bool {
        self.server.as_ref().is_some_and(|s| s.caps & bit != 0)
    }

    /// The picture a chat line or a message carries, where inline media was
    /// agreed; `Err` when only half of it came, and the whole is dropped,
    /// as the extension says.
    fn media(&self, frame: &[u8]) -> Result<Option<ChatMedia>, ()> {
        if !self.agreed(cap::INLINE_MEDIA) {
            return Ok(None);
        }
        let fields = hxproto::wire::ChunkIter::over_message(frame, frame.len());
        match inline_media::extract_chat_media_meta(fields) {
            Ok(m) => Ok(m.map(|m| ChatMedia {
                id: m.id.to_vec(),
                mime: m.type_.to_vec(),
                width: m.width,
                height: m.height,
                bytes: m.bytes,
            })),
            Err(inline_media::MediaMetaError::OnlyOnePresent) => Err(()),
        }
    }

    /// Whether a raw session acts on `kind` itself.
    fn handles(&self, kind: HandlerKind) -> bool {
        let domain = match kind {
            HandlerKind::Chat | HandlerKind::ChatInvite | HandlerKind::ChatSubject => Handled::CHAT,
            HandlerKind::UserChange | HandlerKind::UserPart => Handled::USERS,
            HandlerKind::Msg | HandlerKind::PoliteQuit => Handled::MSG,
            HandlerKind::NewsPost => Handled::NEWS,
            _ => return false,
        };
        self.cfg.handled.contains(domain)
    }

    /// Whether this server is kept alive: a 1.5+ server (mhxd's gate is
    /// 150), as GtkHx does. Older servers are sent nothing unasked.
    fn pings(&self) -> bool {
        self.version() >= 150
    }

    /// Read the clock: the time only moves forward, and a send since the
    /// last reading is stamped with this one.
    fn clock(&mut self, now_ms: u64) {
        self.now = self.now.max(now_ms);
        if self.unstamped {
            self.last_sent = self.now;
            self.unstamped = false;
        }
    }

    /// When the next ping is due, if one ever is. `keepalive_ms` too long
    /// to add is never.
    fn keepalive_due(&self) -> Option<u64> {
        if !(self.ready && self.pings()) {
            return None;
        }
        // A request sent since the clock was read pushes it off from the
        // next reading, which is no earlier than now.
        let base = if self.unstamped {
            self.now
        } else {
            self.last_sent
        };
        base.checked_add(self.cfg.keepalive_ms)
    }

    fn ensure_ready(&self) -> Result<(), Error> {
        if self.state == State::LoggedIn && self.ready && !self.cfg.raw {
            Ok(())
        } else {
            Err(Error::NotReady)
        }
    }

    /// Send on the next trans, remembering what its reply is for.
    fn send(&mut self, req: &Request, pending: Option<Pending>) -> u32 {
        let trans = self.take_trans();
        if let Some(p) = pending {
            self.remember(trans, p);
        }
        self.send_frame(req, trans);
        trans
    }

    fn remember(&mut self, trans: u32, p: Pending) {
        if self.pending.len() as u32 >= MAX_PENDING {
            let newest = trans;
            self.pending
                .retain(|t, _| newest.wrapping_sub(*t) < MAX_PENDING / 2);
        }
        self.pending.insert(trans, p);
    }

    fn send_frame(&mut self, req: &Request, trans: u32) {
        let bytes = req
            .pack(trans)
            .expect("requests are length-checked when built");
        self.out.extend_from_slice(&bytes);
        self.stamp_sent();
    }

    fn stamp_sent(&mut self) {
        if self.clocked {
            self.last_sent = self.now;
        } else {
            self.unstamped = true;
        }
    }

    fn body_out(&self, text: &str) -> Vec<u8> {
        // The classic line break is CR.
        let text = text.replace("\r\n", "\r").replace('\n', "\r");
        text_out(&text, self.utf8)
    }

    fn path_out(&self, path: &[&str]) -> Vec<Vec<u8>> {
        path.iter().map(|p| text_out(p, self.utf8)).collect()
    }

    fn close(&mut self, why: Closed) {
        self.state = State::Closed;
        self.pending.clear();
        self.events.push_back(Event::Closed(why));
    }
}

fn text_out(text: &str, utf8: bool) -> Vec<u8> {
    if utf8 {
        text.as_bytes().to_vec()
    } else {
        hxproto::text::from_utf8(text)
    }
}

/// A user as a user change, or a new chat's reply, describes them.
fn changed_user(c: &parse::UserChange) -> User {
    User {
        uid: c.uid,
        icon: c.icon,
        status: c.got_color.then_some(c.color),
        name: field_text(&c.name),
        color: c.got_nick_color.then_some(c.nick_color),
    }
}

/// The users a user list, or a join's reply, lists. A malformed entry is
/// skipped; its neighbors still list.
fn listed_users(frame: &[u8]) -> Vec<User> {
    hxproto::wire::ChunkIter::over_message(frame, frame.len())
        .filter(|c| c.tag == tag::USER_LIST)
        .filter_map(|c| parse::parse_user_list_record(c.data, MAX_NICK))
        .map(|r| User {
            uid: r.uid,
            icon: r.icon,
            status: Some(r.color),
            name: field_text(&r.name),
            color: r.nick_color,
        })
        .collect()
}

/// The subject a user list, or a join's reply, carries: the last one sent,
/// capped before decoding as a subject change is.
fn listed_subject(frame: &[u8]) -> Option<String> {
    hxproto::wire::ChunkIter::over_message(frame, frame.len())
        .filter(|c| c.tag == tag::CHAT_SUBJECT)
        .last()
        .map(|c| field_text(&c.data[..c.data.len().min(MAX_SUBJECT)]))
}

/// A name or subject: up to its first NUL, as GtkHx has always cut them,
/// then decoded, so what follows the NUL cannot change how the rest reads.
fn field_text(bytes: &[u8]) -> String {
    text_in(bytes.split(|&b| b == 0).next().unwrap_or_default())
}

fn text_in(bytes: &[u8]) -> String {
    // UTF-8 where it is valid, Mac Roman where it is not, whatever was
    // negotiated: servers that never negotiated still send UTF-8, and
    // servers that did still relay Mac Roman from classic clients.
    hxproto::text::to_utf8(bytes)
}

/// The fields of a whole transaction, as [`Event::Reply`] and
/// [`Event::Unhandled`] carry it: (tag, data), in order.
pub fn fields(frame: &[u8]) -> Vec<(u16, Vec<u8>)> {
    hxproto::wire::ChunkIter::over_message(frame, frame.len())
        .map(|c| (c.tag, c.data.to_vec()))
        .collect()
}

#[cfg(test)]
mod tests;
