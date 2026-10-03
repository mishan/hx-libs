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
//! transaction ids and the keep-alive, and hands everything else over
//! whole. That is how a client moves onto the session a piece at a time.
//!
//! What is not here yet: HOPE, the transport ciphers and compression,
//! file transfers (a folder's listing is here; its contents are not),
//! and the extensions (voice, video, inline media, chat history, GIF
//! icons). [`Session::request`] sends any transaction and hands its reply
//! back whole, for what has no method of its own.

pub mod frame;
pub mod request;

use std::collections::{HashMap, VecDeque};

use hxproto::dispatch::{route, HandlerKind};
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
    /// Capabilities to offer. The session itself understands only
    /// [`cap::TEXT_ENCODING`]; offering others means the caller handles
    /// what they bring, through [`Session::request`] and
    /// [`Event::Unhandled`].
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
    /// The caller has receive handlers of its own: every transaction
    /// reaches it whole, every reply as [`Event::Reply`] and everything
    /// else as [`Event::Unhandled`]. The session still drives the login,
    /// the agreement and the keep-alive, and numbers every transaction;
    /// the user list and every request are the caller's, numbered by
    /// [`Session::take_trans`] and sent through [`Session::send_raw`].
    pub raw: bool,
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
    Chat {
        cid: u32,
        uid: u16,
        text: String,
    },
    /// A private message.
    Message {
        uid: u16,
        from: String,
        text: String,
    },
    /// A broadcast, or a message from the server itself.
    Broadcast(String),
    /// The server's parting words before it disconnects us.
    Disconnecting(String),
    /// The reply to [`Session::user_list`], or the one sent after login.
    UserList(Vec<User>),
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
    /// it. In raw mode, everything the server sends unasked.
    Unhandled {
        opcode: u32,
        frame: Vec<u8>,
    },
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for the server's magic.
    Magic,
    /// Login sent, waiting for its reply.
    Login,
    LoggedIn,
    Closed,
}

/// What a sent request's reply should become.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    UserList,
    UserInfo,
    NewsFile,
    NewsListing,
    NewsCategory,
    NewsArticle,
    FileList,
    /// Replies nobody reads: the agreement, a message, a news post. Their
    /// errors still surface.
    Quiet,
    /// The keep-alive ping; its answer is not read, and its failure is
    /// not news.
    Keepalive,
    Raw,
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
        }
    }

    /// A session whose login the caller has already sent, as HOPE does in
    /// two steps of its own: the next reply it is fed is the login's, and
    /// it numbers what it sends after that from `next_trans`.
    pub fn logging_in(cfg: Config, next_trans: u32, now_ms: u64) -> Self {
        let mut s = Session::new(cfg, now_ms);
        s.out.clear();
        s.state = State::Login;
        s.trans = next_trans.max(1);
        s
    }

    /// Bytes to write to the socket, in order. Empty when there is nothing.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
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
        !self.reader.is_idle() || (self.state == State::Magic && !self.magic.is_empty())
    }

    /// When [`Session::tick`] next has something to do.
    pub fn next_deadline(&self) -> Option<u64> {
        match self.state {
            State::Closed => None,
            State::Magic | State::Login => self.handshake_deadline,
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
        self.feed_clocked(bytes);
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
        if self.state == State::Closed {
            return;
        }
        self.reader.push(bytes);
        loop {
            let next = self.reader.next_transaction();
            for trans in self.reader.take_abandoned() {
                if self.pending.remove(&trans).is_some() {
                    self.events.push_back(Event::Failed {
                        trans,
                        reason: Some("the server's reply was cut short".into()),
                    });
                }
            }
            match next {
                Ok(Some(t)) => {
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
            State::Magic | State::Login => {
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
            Some(Pending::UserList),
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

    /// 1.2 flat news, all of it.
    pub fn news_file(&mut self) -> Result<u32, Error> {
        self.ensure_ready()?;
        Ok(self.send(
            &Request::new(ClientHdr::NewsGetFile as u32),
            Some(Pending::NewsFile),
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
        Ok(self.send(&r, Some(Pending::NewsListing)))
    }

    /// The articles in a threaded-news category.
    pub fn news_category(&mut self, path: &[&str]) -> Result<u32, Error> {
        let path = self.path_out(path);
        self.news_category_raw(&path.iter().map(Vec::as_slice).collect::<Vec<_>>())
    }

    pub fn news_category_raw(&mut self, path: &[&[u8]]) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::news_list(ClientHdr::NewsListCategory, path).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::NewsCategory)))
    }

    /// One article's text.
    pub fn news_article(&mut self, path: &[&str], id: u32) -> Result<u32, Error> {
        let path = self.path_out(path);
        self.news_article_raw(&path.iter().map(Vec::as_slice).collect::<Vec<_>>(), id)
    }

    pub fn news_article_raw(&mut self, path: &[&[u8]], id: u32) -> Result<u32, Error> {
        self.ensure_ready()?;
        let r = request::news_article(path, id).ok_or(Error::TooLong)?;
        Ok(self.send(&r, Some(Pending::NewsArticle)))
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
        if self.state == State::Login && kind != HandlerKind::Task {
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
        if self.cfg.raw && kind != HandlerKind::Task {
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
                let c = parse::parse_chat(&t.buf, len, MAX_BODY);
                let text = self.decode(c.text());
                self.events.push_back(Event::Chat {
                    cid: c.cid,
                    uid: c.uid,
                    text,
                });
            }
            HandlerKind::Msg => {
                let m = parse::parse_msg(&t.buf, len, MAX_NAME, MAX_BODY);
                let text = self.decode(&m.msg);
                // A broadcast arrives as its own opcode, or as a message
                // from uid 0 on servers that have no such opcode.
                if t.type_ == 0x163 || m.uid == 0 {
                    self.events.push_back(Event::Broadcast(text));
                } else {
                    let from = self.decode(&m.name);
                    self.events.push_back(Event::Message {
                        uid: m.uid,
                        from,
                        text,
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
                let user = User {
                    uid: c.uid,
                    icon: c.icon,
                    status: c.got_color.then_some(c.color),
                    name: self.decode(&c.name),
                    color: c.got_nick_color.then_some(c.nick_color),
                };
                self.events
                    .push_back(Event::UserChanged { cid: c.cid, user });
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
        if self.state == State::Login {
            self.login_reply(t);
            return;
        }
        let pending = self.pending.remove(&t.trans);
        if self.cfg.raw {
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
            Some(Pending::UserList) => {
                let mut users = Vec::new();
                for c in hxproto::wire::ChunkIter::over_message(&t.buf, len) {
                    if c.tag != tag::USER_LIST {
                        continue;
                    }
                    if let Some(r) = parse::parse_user_list_record(c.data, MAX_NICK) {
                        users.push(User {
                            uid: r.uid,
                            icon: r.icon,
                            status: Some(r.color),
                            name: self.decode(&r.name),
                            color: r.nick_color,
                        });
                    }
                }
                self.events.push_back(Event::UserList(users));
            }
            Some(Pending::UserInfo) => {
                let i = parse::parse_user_info(&t.buf, len, MAX_NICK, 4096);
                let (name, info) = (self.decode(&i.name), self.decode(&i.info));
                self.events.push_back(Event::UserInfo {
                    trans: t.trans,
                    name,
                    info,
                });
            }
            Some(Pending::NewsFile) => {
                let text = parse::parse_news_file(&t.buf, len, MAX_NEWS)
                    .map(|b| self.decode(&b))
                    .unwrap_or_default();
                self.events.push_back(Event::NewsFile {
                    trans: t.trans,
                    text,
                });
            }
            Some(Pending::NewsListing) => {
                let items = parse::parse_dirlist(&t.buf, len)
                    .entries
                    .into_iter()
                    .map(|e| NewsItem {
                        name: self.decode(&e.name),
                        name_bytes: e.name,
                        bundle: e.kind == parse::NewsDirKind::Folder,
                    })
                    .collect();
                self.events.push_back(Event::NewsListing {
                    trans: t.trans,
                    items,
                });
            }
            Some(Pending::NewsCategory) => {
                let articles = parse::parse_catlist(&t.buf, len)
                    .map(|c| c.posts)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|p| Article {
                        id: p.postid,
                        parent: p.parentid,
                        subject: self.decode(&p.subject),
                        poster: self.decode(&p.sender),
                        year: p.date_base_year,
                        seconds: p.date_seconds,
                    })
                    .collect();
                self.events.push_back(Event::NewsCategory {
                    trans: t.trans,
                    articles,
                });
            }
            Some(Pending::NewsArticle) => {
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
            // Answered, and nothing in the answer to read.
            Some(Pending::Quiet) | Some(Pending::Keepalive) | None => {}
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
            Some(Pending::UserList),
        );
        self.roster_trans = Some(trans);
        self.events.push_back(Event::Ready);
    }

    // ---- Plumbing ------------------------------------------------------

    fn version(&self) -> u16 {
        self.server.as_ref().map_or(0, |s| s.version)
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
            if self.pending.len() as u32 >= MAX_PENDING {
                let newest = trans;
                self.pending
                    .retain(|t, _| newest.wrapping_sub(*t) < MAX_PENDING / 2);
            }
            self.pending.insert(trans, p);
        }
        self.send_frame(req, trans);
        trans
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
