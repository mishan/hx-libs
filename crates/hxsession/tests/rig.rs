//! The session against real servers: GtkHx's Docker rig (its
//! `tests/COMPOSE.md`), reached over plain TCP with a blocking loop around
//! the session. `cargo test -p hxsession --features rig`; `HX_RIG_SERVERS`
//! (comma-separated names) narrows the list.

#![cfg(feature = "rig")]

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[cfg(feature = "hope")]
use hxhope::{Cipher, Compression};
use hxproto::messages::tag;
use hxsession::request::Request;
use hxsession::{cap, Config, Event, Session};

const SERVERS: &[(&str, &str)] = &[
    ("mhxd", "127.0.0.1:5500"),
    ("janus", "127.0.0.1:5510"),
    ("hxd-ng", "127.0.0.1:5520"),
    ("hlservd", "127.0.0.1:5530"),
];

const WAIT: Duration = Duration::from_secs(15);

fn servers() -> Vec<(&'static str, &'static str)> {
    let only = std::env::var("HX_RIG_SERVERS").ok();
    let picked: Vec<_> = SERVERS
        .iter()
        .copied()
        .filter(|(n, _)| {
            only.as_deref()
                .is_none_or(|o| o.split(',').any(|x| x == *n))
        })
        .collect();
    assert!(!picked.is_empty(), "HX_RIG_SERVERS names no rig server");
    picked
}

/// A session on a socket, and the loop that moves bytes and time.
struct Client {
    name: &'static str,
    s: Session,
    sock: TcpStream,
    start: Instant,
}

impl Client {
    fn connect(name: &'static str, addr: &str, s: Session) -> Client {
        let sock = TcpStream::connect(addr).unwrap_or_else(|e| panic!("{name} at {addr}: {e}"));
        sock.set_nodelay(true).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let start = Instant::now();
        Client {
            name,
            s,
            sock,
            start,
        }
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// One turn of the loop: write what is queued, read what has come
    /// (waiting a moment for it), and move the clock. Returns the events
    /// that came of it.
    fn step(&mut self) -> Vec<Event> {
        self.flush();
        let mut buf = [0u8; 16 * 1024];
        match self.sock.read(&mut buf) {
            Ok(0) => panic!("{}: the server hung up", self.name),
            Ok(n) => {
                let now = self.now();
                self.s.feed(&buf[..n], now)
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => panic!("{}: {e}", self.name),
        }
        let now = self.now();
        self.s.tick(now);
        let events: Vec<Event> = std::iter::from_fn(|| self.s.poll_event()).collect();
        for e in &events {
            if let Event::Closed(why) = e {
                panic!("{}: closed: {why:?}", self.name);
            }
        }
        // What the session queued in answer goes out now, not whenever
        // this client is next pumped.
        self.flush();
        events
    }

    /// Step until an event `want` matches, returning it.
    fn until(&mut self, what: &str, want: impl Fn(&Event) -> bool) -> Event {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(e) = self.step().into_iter().find(|e| want(e)) {
                return e;
            }
            assert!(
                Instant::now() < deadline,
                "{}: no {what} within {WAIT:?}",
                self.name
            );
        }
    }

    fn flush(&mut self) {
        let out = self.s.take_outgoing();
        if !out.is_empty() {
            self.sock.write_all(&out).unwrap();
        }
    }

    fn login(name: &'static str, addr: &str, nick: &str) -> Client {
        Client::login_as(name, addr, Session::new(Config::guest(nick), 0))
    }

    fn login_as(name: &'static str, addr: &str, s: Session) -> Client {
        Client::login_seeing(name, addr, s).0
    }

    /// As [`Client::login_as`], with every event up to the session being
    /// ready.
    fn login_seeing(name: &'static str, addr: &str, s: Session) -> (Client, Vec<Event>) {
        let mut c = Client::connect(name, addr, s);
        let mut seen = Vec::new();
        let deadline = Instant::now() + WAIT;
        while !seen.iter().any(|e| matches!(e, Event::Ready)) {
            for e in c.step() {
                // An agreement with text waits for the user, who here
                // agrees.
                if let Event::Agreement(_) = e {
                    c.s.agree().unwrap();
                }
                seen.push(e);
            }
            assert!(Instant::now() < deadline, "{name}: never ready");
        }
        (c, seen)
    }
}

/// The uid `nick` has, as `c` is told in the user list it asks for.
fn uid_of(c: &mut Client, nick: &str) -> u16 {
    // Asked again until it is there: the other's agree may still be on its
    // way.
    let deadline = Instant::now() + WAIT;
    loop {
        c.s.user_list().unwrap();
        let Event::UserList { users, .. } =
            c.until("the user list", |e| matches!(e, Event::UserList { .. }))
        else {
            unreachable!()
        };
        if let Some(u) = users.iter().find(|u| u.name == nick) {
            return u.uid;
        }
        assert!(Instant::now() < deadline, "{}: {nick} never listed", c.name);
    }
}

/// Wait until `nick` has left, as the user list `c` asks for says.
fn until_gone(c: &mut Client, nick: &str) {
    let deadline = Instant::now() + WAIT;
    loop {
        let t = c.s.user_list().unwrap();
        let Event::UserList { users, .. } = c.until(
            "the user list",
            |e| matches!(e, Event::UserList { trans, .. } if *trans == t),
        ) else {
            unreachable!()
        };
        if users.iter().all(|u| u.name != nick) {
            return;
        }
        assert!(Instant::now() < deadline, "{}: {nick} never left", c.name);
    }
}

fn nick(server: &str, who: &str) -> String {
    // Unique per run, and inside every server's 31-byte cap.
    let n = std::process::id() % 100_000;
    format!("{who}{n}{}", &server[..2])
}

#[test]
fn log_in_chat_and_message_on_every_server() {
    for (name, addr) in servers() {
        let (na, nb) = (nick(name, "a"), nick(name, "b"));
        let mut a = Client::login(name, addr, &na);
        let mut b = Client::login(name, addr, &nb);

        // Each appears in the list the other asks for.
        b.s.user_list().unwrap();
        let Event::UserList { users, .. } = b.until(
            "the user list",
            |e| matches!(e, Event::UserList { users, .. } if users.iter().any(|u| u.name == na)),
        ) else {
            unreachable!()
        };
        let a_uid = users.iter().find(|u| u.name == na).unwrap().uid;

        // Public chat crosses, text intact.
        let line = format!("hello from {na}, café");
        a.s.chat(&line).unwrap();
        a.flush();
        b.until(
            "a's chat",
            |e| matches!(e, Event::Chat { text, .. } if text.contains(&line)),
        );

        // A private message reaches the one it was sent to.
        // A private message reaches the one it was sent to — or the server
        // says why not: hlservd's guest account may not send them.
        let t = b.s.message(a_uid, "psst").unwrap();
        let deadline = Instant::now() + WAIT;
        let outcome = 'wait: loop {
            for e in a.step() {
                if matches!(&e, Event::Message { text, from, .. } if text == "psst" && *from == nb)
                {
                    break 'wait "delivered".to_owned();
                }
            }
            for e in b.step() {
                if let Event::Failed { trans, reason } = e {
                    if trans == t {
                        let reason =
                            reason.unwrap_or_else(|| panic!("{name}: refused without a reason"));
                        break 'wait format!("refused: {reason}");
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "{name}: the message went nowhere"
            );
        };

        // And leaving is noticed.
        drop(b);
        a.until("b leaving", |e| matches!(e, Event::UserLeft { .. }));
        eprintln!("{name}: login, user list, chat, leave; message {outcome}");
    }
}

#[test]
fn a_broadcast_reaches_everyone_on_every_server() {
    for (name, addr) in servers() {
        let (na, nb) = (nick(name, "s"), nick(name, "r"));
        // The rig's hxd-ng has no account that may broadcast: there, the
        // refusal is what is checked.
        let cfg = if name == "hxd-ng" {
            Config::guest(&na)
        } else {
            Config::account(&na, "admin", "")
        };
        let mut a = Client::login_as(name, addr, Session::new(cfg, 0));
        let mut b = Client::login(name, addr, &nb);

        let text = format!("{nb}: rebooting, café");
        let t = a.s.broadcast(&text).unwrap();
        let deadline = Instant::now() + WAIT;
        let outcome = 'wait: loop {
            for e in b.step() {
                if let Event::Broadcast {
                    from, text: got, ..
                } = e
                {
                    if got == text {
                        break 'wait format!("from {from:?}");
                    }
                }
            }
            for e in a.step() {
                if let Event::Failed { trans, reason } = e {
                    if trans == t {
                        assert_eq!(name, "hxd-ng", "{name}: refused: {reason:?}");
                        let reason =
                            reason.unwrap_or_else(|| panic!("{name}: refused without a reason"));
                        break 'wait format!("refused: {reason}");
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "{name}: the broadcast went nowhere"
            );
        };
        eprintln!("{name}: broadcast {outcome}");
    }
}

/// What the server says of us and of another user, a kick refused and
/// one that worked, and an account made, read, changed and deleted, as an
/// admin; where there is no admin (hxd-ng), the refusals. The servers
/// that give our uid in the login reply leave it out of the self-info.
#[test]
fn users_kicks_and_accounts_on_every_server() {
    for (name, addr) in servers() {
        let (na, nb) = (nick(name, "k"), nick(name, "v"));
        let admin = name != "hxd-ng";
        let cfg = if admin {
            Config::account(&na, "admin", "")
        } else {
            Config::guest(&na)
        };
        let (mut a, seen) = Client::login_seeing(name, addr, Session::new(cfg, 0));
        let me = match seen
            .into_iter()
            .find(|e| matches!(e, Event::SelfInfo { .. }))
        {
            Some(e) => e,
            None => a.until("our self-info", |e| matches!(e, Event::SelfInfo { .. })),
        };
        let Event::SelfInfo { uid, access, .. } = me else {
            unreachable!()
        };
        assert!(access.is_some(), "{name}: no access in {me:?}");
        let a_uid = uid_of(&mut a, &na);
        assert!(uid.is_none_or(|u| u == a_uid), "{name}: {me:?}");

        let mut b = Client::login(name, addr, &nb);
        let b_uid = uid_of(&mut a, &nb);
        let t = a.s.user_info(b_uid).unwrap();
        a.until(
            "b's info",
            |e| matches!(e, Event::UserInfo { trans, name, .. } if *trans == t && *name == nb),
        );

        let t = b.s.kick(a_uid, false).unwrap();
        b.until(
            "a guest's kick refused",
            |e| matches!(e, Event::Failed { trans, reason: Some(_) } if *trans == t),
        );
        let t = a.s.kick(b_uid, false).unwrap();
        if !admin {
            a.until(
                "the kick refused",
                |e| matches!(e, Event::Failed { trans, reason: Some(_) } if *trans == t),
            );
            // Account requests are refused too; one is enough, as each
            // costs a guest towards hxd-ng's flood limit.
            let t = a.s.account_read(b"guest").unwrap();
            a.until(
                "the account refused",
                |e| matches!(e, Event::Failed { trans, reason: Some(_) } if *trans == t),
            );
            eprintln!("{name}: self-info, user info, kicks and accounts refused");
            continue;
        }
        // b leaves, before the kick is answered or after it.
        let (mut kicked, mut left) = (false, false);
        let deadline = Instant::now() + WAIT;
        while !(kicked && left) {
            for e in a.step() {
                kicked |= matches!(e, Event::Kicked { trans } if trans == t);
                left |= matches!(e, Event::UserLeft { uid, .. } if uid == b_uid);
            }
            assert!(
                Instant::now() < deadline,
                "{name}: kicked {kicked}, left {left}"
            );
        }
        drop(b);

        let login = format!("hx{}{}", std::process::id() % 100_000, &name[..2]);
        let read = |a: &mut Client| {
            let t = a.s.account_read(login.as_bytes()).unwrap();
            match a.until("the account", |e| {
                matches!(e, Event::Account { trans, .. } | Event::Failed { trans, .. } if *trans == t)
            }) {
                Event::Account { account, .. } => Some(account),
                _ => None,
            }
        };
        let access = 0x6060_0c00_0000_0000;
        // 0x8E is Mac Roman é, and comes back as it went.
        let t =
            a.s.account_create(login.as_bytes(), b"pw", b"Ren\x8e", access)
                .unwrap();
        assert_eq!(changed(&mut a, t), Ok(()), "{name}: create");
        let got = read(&mut a).unwrap_or_else(|| panic!("{name}: not made"));
        assert_eq!(
            (&got.login[..], &got.name[..], got.access),
            (login.as_bytes(), &b"Ren\x8e"[..], Some(access)),
            "{name}"
        );
        // No password leaves the one it had.
        let t = a.s.account_save(login.as_bytes(), b"", b"Ren", 0).unwrap();
        assert_eq!(changed(&mut a, t), Ok(()), "{name}: save");
        let got = read(&mut a).unwrap_or_else(|| panic!("{name}: gone"));
        assert_eq!(
            (&got.name[..], got.access),
            (&b"Ren"[..], Some(0)),
            "{name}"
        );
        let nu = nick(name, "u");
        Client::login_as(
            name,
            addr,
            Session::new(Config::account(&nu, &login, "pw"), 0),
        );
        // Deleted only once no one is logged in with it: mhxd can crash
        // deleting an account in use (GtkHx's docs/mhxd-bugs.md).
        until_gone(&mut a, &nu);
        let t = a.s.account_delete(login.as_bytes()).unwrap();
        assert_eq!(changed(&mut a, t), Ok(()), "{name}: delete");
        assert_eq!(read(&mut a), None, "{name}: still there");
        eprintln!("{name}: self-info, user info, kicks and an account");
    }
}

#[test]
fn news_answers_on_every_server() {
    for (name, addr) in servers() {
        let mut c = Client::login(name, addr, &nick(name, "n"));

        // 1.2 flat news: the file, or a reason a guest may not read it.
        let t = c.s.news_file().unwrap();
        let got = c.until("the flat news reply", |e| {
            matches!(e, Event::NewsFile { trans, .. } | Event::Failed { trans, .. } if *trans == t)
        });
        eprintln!("{name}: flat news: {}", summary(&got));

        // 1.5 threaded news: the root bundle.
        let t = c.s.news_listing(&[]).unwrap();
        let got = c.until("the threaded news reply", |e| {
            matches!(e, Event::NewsListing { trans, .. } | Event::Failed { trans, .. } if *trans == t)
        });
        eprintln!("{name}: threaded news root: {}", summary(&got));
        // Walk into the first category there is, and read its first article.
        if let Event::NewsListing { items, .. } = got {
            if let Some(cat) = items.iter().find(|i| !i.bundle) {
                let t = c.s.news_category(&[cat.name.as_str()]).unwrap();
                let got = c.until("the category", |e| {
                    matches!(e, Event::NewsCategory { trans, .. } | Event::Failed { trans, .. } if *trans == t)
                });
                eprintln!("{name}: category {:?}: {}", cat.name, summary(&got));
                if let Event::NewsCategory { articles, .. } = got {
                    if let Some(a) = articles.first() {
                        let t = c.s.news_article(&[cat.name.as_str()], a.id).unwrap();
                        let got = c.until("the article", |e| {
                            matches!(e, Event::NewsArticle { trans, .. } | Event::Failed { trans, .. } if *trans == t)
                        });
                        eprintln!("{name}: article {:?}: {}", a.subject, summary(&got));
                    }
                }
            }
        }
    }
}

/// Whether the request on `t`, which has nothing to say once it worked,
/// worked: the user list asked for after it is answered after it, so no
/// refusal by then means it did.
fn worked(c: &mut Client, t: u32) -> Result<(), Option<String>> {
    let list = c.s.user_list().unwrap();
    match c.until("the answer", |e| {
        matches!(e, Event::Failed { trans, .. } if *trans == t)
            || matches!(e, Event::UserList { trans, .. } if *trans == list)
    }) {
        Event::Failed { reason, .. } => Err(reason),
        _ => Ok(()),
    }
}

/// Whether an account change on `t` worked, as its own answer says.
fn changed(c: &mut Client, t: u32) -> Result<(), Option<String>> {
    match c.until("the answer", |e| {
        matches!(e, Event::Failed { trans, .. } | Event::AccountChanged { trans } if *trans == t)
    }) {
        Event::Failed { reason, .. } => Err(reason),
        _ => Ok(()),
    }
}

/// Posting to news and changing it, as an admin, where the server has
/// news; where it has none (hxd-ng), its refusals. Only what the test
/// itself posts is checked: the long-lived rig's seed news drifts.
#[test]
fn news_posts_and_changes_on_every_server() {
    for (name, addr) in servers() {
        let (na, nb) = (nick(name, "p"), nick(name, "q"));
        // The rig's hxd-ng has no admin account, and no news to refuse it.
        let cfg = if name == "hxd-ng" {
            Config::guest(&na)
        } else {
            Config::account(&na, "admin", "")
        };
        let mut a = Client::login_as(name, addr, Session::new(cfg, 0));
        let mut b = Client::login(name, addr, &nb);
        let refused = |c: &mut Client, t: u32, what: &str| {
            let got = c.until(
                what,
                |e| matches!(e, Event::Failed { trans, .. } if *trans == t),
            );
            assert_eq!(name, "hxd-ng", "{name}: {what}: {got:?}");
        };

        // Flat news: a post reaches the others, and is in the file. The
        // user list's answer says the server is done with b's agree, which
        // a post that comes first can miss.
        let t = b.s.user_list().unwrap();
        b.until(
            "b's user list",
            |e| matches!(e, Event::UserList { trans, .. } if *trans == t),
        );
        let flat = format!("{na} was here, café");
        let t = a.s.post_news(&flat).unwrap();
        a.flush();
        if name == "hxd-ng" {
            refused(&mut a, t, "the flat post refused");
        } else {
            b.until(
                "the flat post",
                |e| matches!(e, Event::NewsPosted(text) if text.contains(&flat)),
            );
            let t = b.s.news_file().unwrap();
            b.until(
                "the flat news with the post",
                |e| matches!(e, Event::NewsFile { trans, text } if *trans == t && text.contains(&flat)),
            );
        }

        // Threaded news: a category made at the root, an article and a
        // reply in it, read back, and all of it deleted again.
        let cat = format!("{na} café");
        let t = a.s.news_create_category(&[], &cat).unwrap();
        let listed = |c: &mut Client| {
            let t = c.s.news_listing(&[]).unwrap();
            let Event::NewsListing { items, .. } = c.until(
                "the root",
                |e| matches!(e, Event::NewsListing { trans, .. } if *trans == t),
            ) else {
                unreachable!()
            };
            items.iter().any(|i| i.name == cat && !i.bundle)
        };
        if name == "hxd-ng" {
            refused(&mut a, t, "the category refused");
            eprintln!("{name}: news refused");
            continue;
        }
        assert!(listed(&mut a), "{name}: {cat:?} not listed");
        let subject = format!("{na}'s news");
        let t =
            a.s.news_post_article(&[&cat], 0, &subject, "one\ntwo, café")
                .unwrap();
        assert_eq!(worked(&mut a, t), Ok(()), "{name}");
        let read = |c: &mut Client| {
            let t = c.s.news_category(&[&cat]).unwrap();
            let Event::NewsCategory { articles, .. } = c.until(
                "the category",
                |e| matches!(e, Event::NewsCategory { trans, .. } if *trans == t),
            ) else {
                unreachable!()
            };
            articles
        };
        let articles = read(&mut b);
        let first = articles
            .iter()
            .find(|x| x.subject == subject)
            .unwrap_or_else(|| panic!("{name}: {subject:?} not in {articles:?}"))
            .clone();
        assert_eq!(
            (first.poster.as_str(), first.parent, &first.mime[..]),
            (na.as_str(), 0, &b"text/plain"[..]),
            "{name}"
        );
        let t = b.s.news_article(&[&cat], first.id).unwrap();
        let got = b.until("the article", |e| {
            matches!(e, Event::NewsArticle { trans, .. } | Event::Failed { trans, .. } if *trans == t)
        });
        // mhxd ends it with a line break of its own.
        assert!(
            matches!(&got, Event::NewsArticle { text, .. } if text.trim_end() == "one\ntwo, café"),
            "{name}: {got:?}"
        );
        let t =
            a.s.news_post_article(&[&cat], first.id, "Re", "and three")
                .unwrap();
        assert_eq!(worked(&mut a, t), Ok(()), "{name}");
        let articles = read(&mut b);
        assert!(
            articles
                .iter()
                .any(|x| x.parent == first.id && x.subject == "Re"),
            "{name}: no reply in {articles:?}"
        );
        let t = a.s.news_delete_article(&[&cat], first.id).unwrap();
        assert_eq!(worked(&mut a, t), Ok(()), "{name}");
        assert!(
            read(&mut b).iter().all(|x| x.id != first.id),
            "{name}: the article is still there"
        );
        let t = a.s.news_delete(&[&cat]).unwrap();
        assert_eq!(worked(&mut a, t), Ok(()), "{name}");
        assert!(!listed(&mut a), "{name}: {cat:?} is still there");

        let bundle = format!("{na} bundle");
        let t = a.s.news_create_bundle(&[], &bundle).unwrap();
        assert_eq!(worked(&mut a, t), Ok(()), "{name}");
        let t = a.s.news_create_category(&[&bundle], "inside").unwrap();
        assert_eq!(worked(&mut a, t), Ok(()), "{name}");
        let t = b.s.news_listing(&[&bundle]).unwrap();
        b.until(
            "the bundle",
            |e| matches!(e, Event::NewsListing { trans, items } if *trans == t && items.iter().any(|i| i.name == "inside")),
        );
        let t = a.s.news_delete(&[&bundle]).unwrap();
        assert_eq!(worked(&mut a, t), Ok(()), "{name}");
        eprintln!("{name}: flat and threaded news posted and read back");
    }
}

/// What each rig server's file area holds at its root, by name, and a
/// folder in it with something inside — or `None` where the server has
/// no file area and says so. From GtkHx's rig seed (its
/// `tests/COMPOSE.md`); a long-lived container that has drifted from its
/// seed fails here first.
fn file_area(server: &str) -> Option<(&'static [&'static str], Option<&'static str>)> {
    match server {
        "mhxd" => Some((
            &["integration_seed.txt", "test.txt", "test_folder"],
            Some("test_folder"),
        )),
        "janus" => Some((
            &["integration_seed.txt", "test.txt", "test_folder"],
            Some("test_folder"),
        )),
        "hlservd" => Some((&["test.txt"], None)),
        _ => None,
    }
}

/// Held by a test that changes the root folder, and by one that reads it
/// twice and compares.
static ROOT: Mutex<()> = Mutex::new(());

#[test]
fn files_list_on_every_server() {
    let _root = ROOT.lock().unwrap_or_else(|e| e.into_inner());
    for (name, addr) in servers() {
        let mut c = Client::login(name, addr, &nick(name, "f"));
        let t = c.s.file_list(&[]).unwrap();
        let got = c.until("the root listing", |e| {
            matches!(e, Event::FileList { trans, .. } | Event::Failed { trans, .. } if *trans == t)
        });
        eprintln!("{name}: root folder: {}", summary(&got));
        let Some((names, folder)) = file_area(name) else {
            assert!(
                matches!(
                    got,
                    Event::Failed {
                        reason: Some(_),
                        ..
                    }
                ),
                "{name}: {got:?}"
            );
            continue;
        };
        let Event::FileList { files, .. } = got else {
            panic!("{name}: the root did not list: {got:?}")
        };
        for want in names {
            assert!(
                files.iter().any(|f| f.name == *want),
                "{name}: no {want} in {files:?}"
            );
        }
        // Every entry the server sent was read: the same listing, taken
        // whole, has as many entry fields as there are files.
        let raw = Request::new(200).field(0x00ca, vec![0, 0]);
        let t = c.s.request(&raw).unwrap();
        let Event::Reply { frame, .. } = c.until(
            "the raw listing",
            |e| matches!(e, Event::Reply { trans, .. } if *trans == t),
        ) else {
            unreachable!()
        };
        let entries = hxsession::fields(&frame)
            .iter()
            .filter(|(tag, _)| *tag == 0x00c8)
            .count();
        assert_eq!(entries, files.len(), "{name}: entries parsed");

        if let Some(folder) = folder {
            let f = files.iter().find(|f| f.name == folder).unwrap();
            assert!(f.folder && f.size > 0, "{name}: {f:?}");
            // Opened by the bytes the server gave its name.
            let t = c.s.file_list_raw(&[&f.name_bytes]).unwrap();
            let got = c.until("a folder's listing", |e| {
                matches!(e, Event::FileList { trans, .. } | Event::Failed { trans, .. } if *trans == t)
            });
            eprintln!("{name}: folder {folder:?}: {}", summary(&got));
            let Event::FileList { files: inside, .. } = got else {
                panic!("{name}: {folder} did not list: {got:?}")
            };
            assert_eq!(
                inside.len() as u64,
                f.size,
                "{name}: {folder} holds what its entry said"
            );
        }
    }
}

/// Claim the transfer `reference` on the transfer port and hang up, as
/// a cancelled transfer does, and wait until the server has let it go:
/// mhxd keeps a global transfer slot for good for a reference never
/// claimed (GtkHx's `docs/mhxd-bugs.md`), and holds every transfer once
/// twenty are gone.
fn cancel_transfer(name: &str, addr: &str, reference: u32) {
    let addr: SocketAddr = addr.parse().unwrap();
    let xfer = SocketAddr::new(addr.ip(), addr.port() + 1);
    let mut preamble = [0u8; 24];
    let n = hxproto::build::build_htxf_preamble(&mut preamble, reference, 0, 0, 0, false);
    let mut sock = TcpStream::connect(xfer).unwrap_or_else(|e| panic!("{name} at {xfer}: {e}"));
    sock.write_all(&preamble[..n]).unwrap();
    sock.shutdown(Shutdown::Write).unwrap();
    sock.set_read_timeout(Some(WAIT)).unwrap();
    let mut sink = [0u8; 4096];
    loop {
        match sock.read(&mut sink) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::ConnectionReset => break,
            Err(e) => panic!("{name}: transfer {reference:#x} never closed: {e}"),
        }
    }
}

/// A request, sent.
type Ask<'a> = dyn Fn(&mut Session) -> Result<u32, hxsession::Error> + 'a;

/// The answer to the file request on `t`: its event, or its refusal.
fn file_answer(c: &mut Client, t: u32) -> Event {
    c.until("the answer", |e| match e {
        Event::FileList { trans, .. }
        | Event::FileInfo { trans, .. }
        | Event::FileChanged { trans }
        | Event::Transfer { trans, .. }
        | Event::Failed { trans, .. } => *trans == t,
        _ => false,
    })
}

/// Files changed and transfers asked for, as an admin, in a scratch
/// folder made at the root and deleted again; where there is no file
/// area (hxd-ng), its refusals. The session offers no Text-Encoding, so
/// its names go as Mac Roman, and one named by bytes alone goes back as
/// the listing gave it. No transfer connection is opened: what is
/// checked is the server's answer to the asking.
#[test]
fn files_change_and_transfers_are_asked_for_on_every_server() {
    let _root = ROOT.lock().unwrap_or_else(|e| e.into_inner());
    for (name, addr) in servers() {
        let na = nick(name, "x");
        let cfg = Config {
            caps: cap::LARGE_FILES,
            ..if name == "hxd-ng" {
                Config::guest(&na)
            } else {
                Config::account(&na, "admin", "")
            }
        };
        let mut c = Client::login_as(name, addr, Session::new(cfg, 0));
        assert_eq!(c.s.server().unwrap().caps & cap::TEXT_ENCODING, 0, "{name}");
        let scratch = format!("{na} files");
        let root = [scratch.as_str()];
        let changed = |c: &mut Client, t: u32, what: &str| {
            let got = file_answer(c, t);
            assert!(
                matches!(got, Event::FileChanged { .. }),
                "{name}: {what}: {got:?}"
            );
        };
        let listed = |c: &mut Client, path: &[&str]| {
            let t = c.s.file_list(path).unwrap();
            match file_answer(c, t) {
                Event::FileList { files, .. } => files,
                got => panic!("{name}: {path:?} did not list: {got:?}"),
            }
        };

        let t = c.s.file_mkdir(&[], &scratch).unwrap();
        if file_area(name).is_none() {
            // Each asked for once the one before is answered: `until`
            // passes over what else came in the same read.
            let mut refusals = vec![file_answer(&mut c, t)];
            let asks: [&Ask; 8] = [
                &|s| s.file_info(&[], "test.txt"),
                &|s| s.file_delete(&[], &scratch),
                &|s| s.file_set_info(&[], &scratch, Some("x"), Some("x")),
                &|s| s.file_move(&[], &scratch, &["x"]),
                &|s| s.file_download(&[], "test.txt"),
                &|s| s.file_upload(&[], "up.txt", 5),
                &|s| s.folder_download(&[], &scratch),
                &|s| s.folder_upload(&[], &scratch, 5, 1),
            ];
            for ask in asks {
                let t = ask(&mut c.s).unwrap();
                refusals.push(file_answer(&mut c, t));
            }
            for got in refusals {
                assert!(
                    matches!(
                        got,
                        Event::Failed {
                            reason: Some(_),
                            ..
                        }
                    ),
                    "{name}: {got:?}"
                );
            }
            eprintln!("{name}: file changes and transfers refused");
            continue;
        }
        changed(&mut c, t, "the scratch folder");
        let t = c.s.file_mkdir(&root, "one").unwrap();
        changed(&mut c, t, "a folder in it");
        assert!(
            listed(&mut c, &root)
                .iter()
                .any(|f| f.name == "one" && f.folder),
            "{name}: one not listed"
        );

        let info = |c: &mut Client, item: &str| {
            let t = c.s.file_info(&root, item).unwrap();
            match file_answer(c, t) {
                Event::FileInfo { info, .. } => info,
                got => panic!("{name}: no info on {item}: {got:?}"),
            }
        };
        assert_eq!(info(&mut c, "one").name, "one", "{name}");
        let note = "a note\nline two, café";
        let t = c.s.file_set_info(&root, "one", None, Some(note)).unwrap();
        changed(&mut c, t, "the comment");
        assert_eq!(info(&mut c, "one").comment, note, "{name}");
        let t = c.s.file_set_info(&root, "one", Some("two"), None).unwrap();
        changed(&mut c, t, "the rename");
        let files = listed(&mut c, &root);
        assert!(
            files.iter().any(|f| f.name == "two") && files.iter().all(|f| f.name != "one"),
            "{name}: not renamed: {files:?}"
        );
        let t = c.s.file_mkdir(&root, "dst").unwrap();
        changed(&mut c, t, "the destination");
        let t = c.s.file_move(&root, "two", &[&scratch, "dst"]).unwrap();
        changed(&mut c, t, "the move");
        assert!(
            listed(&mut c, &[&scratch, "dst"])
                .iter()
                .any(|f| f.name == "two"),
            "{name}: not moved"
        );

        // A name only Mac Roman spells, named back by its bytes.
        let t =
            c.s.file_mkdir_raw(&[scratch.as_bytes()], b"caf\x8e")
                .unwrap();
        changed(&mut c, t, "the Mac Roman folder");
        let files = listed(&mut c, &root);
        let cafe = files
            .iter()
            .find(|f| f.name == "café")
            .unwrap_or_else(|| panic!("{name}: café not in {files:?}"));
        assert_eq!(cafe.name_bytes, b"caf\x8e", "{name}");
        let t =
            c.s.file_info_raw(&[scratch.as_bytes()], &cafe.name_bytes)
                .unwrap();
        let got = file_answer(&mut c, t);
        assert!(
            matches!(&got, Event::FileInfo { info, .. } if info.name == "café"),
            "{name}: {got:?}"
        );
        let t =
            c.s.file_delete_raw(&[scratch.as_bytes()], &cafe.name_bytes)
                .unwrap();
        changed(&mut c, t, "the Mac Roman folder deleted");

        let transfer = |c: &mut Client, t: u32, what: &str| match file_answer(c, t) {
            Event::Transfer { transfer, .. } => {
                assert_ne!(transfer.reference, 0, "{name}: {what}: {transfer:?}");
                cancel_transfer(name, addr, transfer.reference);
                transfer
            }
            got => panic!("{name}: {what}: {got:?}"),
        };
        // mhxd sends no reference for an empty folder: there is nothing
        // to send.
        let t = c.s.folder_download(&root, "dst").unwrap();
        transfer(&mut c, t, "the folder download");
        let t = c.s.folder_upload(&root, "up", 10, 1).unwrap();
        transfer(&mut c, t, "the folder upload");
        let t = c.s.file_download(&[], "test.txt").unwrap();
        let got = transfer(&mut c, t, "the download");
        assert_ne!(got.size, 0, "{name}: {got:?}");
        let t = c.s.file_upload(&root, "up.txt", 5).unwrap();
        transfer(&mut c, t, "the upload");

        let t = c.s.file_delete(&[], &scratch).unwrap();
        changed(&mut c, t, "the scratch folder deleted");
        assert!(
            listed(&mut c, &[]).iter().all(|f| f.name != scratch),
            "{name}: {scratch:?} is still there"
        );
        eprintln!("{name}: files made, read, changed and deleted; transfers asked for");
    }
}

/// A 4×4 red PNG, small enough to send whole.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x08, 0x02, 0x00, 0x00, 0x00, 0x26, 0x93, 0x09,
    0x29, 0x00, 0x00, 0x00, 0x10, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
    0x47, 0x0c, 0xc4, 0x71, 0x00, 0xae, 0x93, 0x0f, 0xf1, 0x38, 0x5e, 0x8c, 0x11, 0x00, 0x00, 0x00,
    0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

/// Private chat between two sessions: the invitation a new chat sends, a
/// decline and an invitation again, the join, a subject and a line in
/// it. Where the server keeps chat history, a public line read back from
/// it; where it relays pictures, one carried on a chat line.
#[test]
fn chat_invitations_subjects_history_and_media_on_every_server() {
    for (name, addr) in servers() {
        let (na, nb) = (nick(name, "c"), nick(name, "d"));
        let caps = cap::TEXT_ENCODING | cap::CHAT_HISTORY | cap::INLINE_MEDIA;
        let session = |nick: &str| {
            Session::new(
                Config {
                    caps,
                    ..Config::guest(nick)
                },
                0,
            )
        };
        let mut a = Client::login_as(name, addr, session(&na));
        let mut b = Client::login_as(name, addr, session(&nb));
        let agreed = a.s.server().unwrap().caps;
        let b_uid = uid_of(&mut a, &nb);

        let line = format!("{na} for the record");
        a.s.chat(&line).unwrap();
        a.flush();
        b.until(
            "the public line",
            |e| matches!(e, Event::Chat { cid: 0, text, .. } if text.contains(&line)),
        );
        if agreed & cap::CHAT_HISTORY != 0 {
            let t = a.s.chat_history(0, 0, 0, 50).unwrap();
            let got = a.until("the history", |e| {
                matches!(e, Event::ChatHistory { trans, .. } | Event::Failed { trans, .. } if *trans == t)
            });
            let Event::ChatHistory {
                cid: 0, entries, ..
            } = got
            else {
                panic!("{name}: {got:?}")
            };
            assert!(
                entries.iter().any(|e| e.text.contains(&line)),
                "{name}: {line:?} not in {entries:?}"
            );
            eprintln!("{name}: history of {} lines", entries.len());
        }

        if agreed & cap::INLINE_MEDIA != 0 {
            let upload = Request::new(750)
                .field(tag::CHAT_MEDIA_PAYLOAD, PNG)
                .field(tag::CHAT_MEDIA_DECLARED_TYPE, &b"image/png"[..])
                .field(tag::CHAT_MEDIA_PART_FINAL, vec![1]);
            let t = a.s.request(&upload).unwrap();
            let Event::Reply { frame, .. } = a.until("the upload", |e| {
                matches!(e, Event::Reply { trans, .. } | Event::Failed { trans, .. } if *trans == t)
            }) else {
                panic!("{name}: the picture was refused")
            };
            let field = |want: u16| {
                hxsession::fields(&frame)
                    .into_iter()
                    .find(|(t, _)| *t == want)
                    .map(|(_, d)| d)
                    .unwrap_or_else(|| panic!("{name}: no {want:#x} in the upload's reply"))
            };
            let (id, mime) = (field(tag::CHAT_MEDIA_ID), field(tag::CHAT_MEDIA_TYPE));
            let seen = format!("{na} attached");
            let chat = Request::new(105)
                .field(tag::BODY, seen.as_bytes())
                .field(tag::CHAT_MEDIA_ID, id.clone())
                .field(tag::CHAT_MEDIA_TYPE, mime.clone());
            a.s.request(&chat).unwrap();
            a.flush();
            let Event::Chat { media, .. } = b.until(
                "the line with the picture",
                |e| matches!(e, Event::Chat { text, .. } if text.contains(&seen)),
            ) else {
                unreachable!()
            };
            let media = media.unwrap_or_else(|| panic!("{name}: the line came without it"));
            assert_eq!((media.id, media.mime), (id, mime), "{name}");
            eprintln!("{name}: a picture on a chat line");
        }

        let t = a.s.chat_create(b_uid).unwrap();
        let got = a.until("the new chat", |e| {
            matches!(e, Event::ChatCreated { trans, .. } | Event::Failed { trans, .. } if *trans == t)
        });
        let Event::ChatCreated { cid, user, .. } = got else {
            eprintln!("{name}: private chat: {}", summary(&got));
            continue;
        };
        assert_ne!(cid, 0, "{name}: the new chat has no id");
        assert_eq!(user.name, na, "{name}");
        let invited = |b: &mut Client| {
            b.until(
                "the invitation",
                |e| matches!(e, Event::ChatInvite { cid: c, name, .. } if *c == cid && *name == na),
            )
        };
        invited(&mut b);
        b.s.chat_decline(cid).unwrap();
        b.flush();
        a.s.chat_invite(cid, b_uid).unwrap();
        a.flush();
        invited(&mut b);
        let t = b.s.chat_join(cid).unwrap();
        let Event::ChatJoined {
            cid: joined, users, ..
        } = b.until(
            "the join",
            |e| matches!(e, Event::ChatJoined { trans, .. } if *trans == t),
        )
        else {
            unreachable!()
        };
        assert_eq!(joined, cid, "{name}");
        assert!(
            users.iter().any(|u| u.name == na),
            "{name}: {na} not in {users:?}"
        );

        let subject = format!("{na}'s plans, café");
        a.s.chat_subject(cid, &subject).unwrap();
        a.flush();
        b.until(
            "the subject",
            |e| matches!(e, Event::ChatSubject { cid: c, subject: s } if *c == cid && *s == subject),
        );
        let inside = format!("{na} in private");
        a.s.chat_in(cid, &inside, 0).unwrap();
        a.flush();
        b.until(
            "the private line",
            |e| matches!(e, Event::Chat { cid: c, text, .. } if *c == cid && text.contains(&inside)),
        );
        b.s.chat_part(cid).unwrap();
        b.flush();
        a.until(
            "b leaving the chat",
            |e| matches!(e, Event::UserLeft { cid: c, .. } if *c == cid),
        );
        eprintln!("{name}: invitation, decline, invitation, join, subject, line, part");
    }
}

/// A 1×1 GIF89a.
const GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

impl Client {
    /// As [`Client::until`], but `None` once `wait` has passed with no
    /// such event: for a server that may never answer.
    fn within(&mut self, wait: Duration, want: impl Fn(&Event) -> bool) -> Option<Event> {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if let Some(e) = self.step().into_iter().find(|e| want(e)) {
                return Some(e);
            }
        }
        None
    }
}

/// The banner, GIF icons, and a picture up and down again, on the
/// servers that have each. A server without the GIF-icons extension may
/// refuse its requests or never answer them; one without a banner to
/// send over a transfer connection refuses it, or grants nothing.
#[test]
fn banners_icons_and_pictures_on_every_server() {
    for (name, addr) in servers() {
        let (na, nb) = (nick(name, "i"), nick(name, "j"));
        let session = |nick: &str| {
            Session::new(
                Config {
                    caps: cap::INLINE_MEDIA,
                    ..Config::guest(nick)
                },
                0,
            )
        };
        let mut a = Client::login_as(name, addr, session(&na));
        let mut b = Client::login_as(name, addr, session(&nb));

        // A server whose banner is a URL may not answer at all.
        let t = a.s.banner().unwrap();
        match a.within(Duration::from_secs(3), |e| {
            matches!(e, Event::Transfer { trans, .. } | Event::Failed { trans, .. } if *trans == t)
        }) {
            Some(Event::Transfer { transfer, .. }) if transfer.reference != 0 => {
                assert_ne!(transfer.size, 0, "{name}: a banner of no size");
                cancel_transfer(name, addr, transfer.reference);
                eprintln!("{name}: a banner of {} bytes", transfer.size);
            }
            e => eprintln!(
                "{name}: no banner to fetch: {}",
                e.as_ref().map_or("no answer".into(), summary)
            ),
        }

        let t = a.s.icon_list().unwrap();
        let answered = |trans: u32| {
            move |e: &Event| {
                matches!(e, Event::IconList { trans: t, .. } | Event::Icon { trans: t, .. }
                    | Event::Failed { trans: t, .. } if *t == trans)
            }
        };
        match a.within(Duration::from_secs(3), answered(t)) {
            Some(Event::IconList { .. }) => {}
            other => {
                eprintln!(
                    "{name}: no GIF icons: {}",
                    other.as_ref().map_or("no answer".into(), summary)
                );
                continue;
            }
        }
        let a_uid = uid_of(&mut b, &na);
        let icon = |b: &mut Client| {
            let t = b.s.icon(a_uid).unwrap();
            match b.until("the icon", answered(t)) {
                Event::Icon { icon, .. } => icon,
                e => panic!("{name}: {}", summary(&e)),
            }
        };
        a.s.icon_set(GIF).unwrap();
        a.flush();
        // The server tells everyone of the change, the one who made it too.
        a.until("the icon set", |e| {
            matches!(e, Event::Unhandled { opcode: 1864, .. })
        });
        assert_eq!(icon(&mut b).gif, GIF, "{name}");
        let t = b.s.icon_list().unwrap();
        let Event::IconList { icons, .. } = b.until("the icons", answered(t)) else {
            panic!("{name}: the icons were refused")
        };
        assert!(
            icons.iter().any(|i| i.uid == a_uid && i.gif == GIF),
            "{name}: {na}'s icon not in {icons:?}"
        );
        a.s.icon_set(b"").unwrap();
        a.flush();
        a.until("the icon cleared", |e| {
            matches!(e, Event::Unhandled { opcode: 1864, .. })
        });
        assert!(icon(&mut b).gif.is_empty(), "{name}: the icon stayed");
        eprintln!("{name}: a GIF icon set, read, listed and cleared");

        if a.s.server().unwrap().caps & cap::INLINE_MEDIA == 0 {
            continue;
        }
        let pictured = |trans: u32| {
            move |e: &Event| {
                matches!(e, Event::MediaUploaded { trans: t, .. } | Event::MediaPart { trans: t, .. }
                    | Event::MediaFailed { trans: t, .. } if *t == trans)
            }
        };
        let t = a.s.media_upload(PNG, Some(b"image/png")).unwrap();
        let Event::MediaUploaded { media, .. } = a.until("the upload", pictured(t)) else {
            panic!("{name}: the picture was refused")
        };
        assert!(media.mime.starts_with(b"image/"), "{name}: {media:?}");
        // Whoever sees the picture on a chat line may fetch it.
        let line = format!("{na} pictured");
        let chat = Request::new(105)
            .field(tag::BODY, line.as_bytes())
            .field(tag::CHAT_MEDIA_ID, media.id.clone())
            .field(tag::CHAT_MEDIA_TYPE, media.mime.clone());
        a.s.request(&chat).unwrap();
        a.flush();
        b.until(
            "the line with the picture",
            |e| matches!(e, Event::Chat { text, .. } if text.contains(&line)),
        );
        let mut got = Vec::new();
        let mut part = None;
        loop {
            let t = b.s.media_download(&media.id, part).unwrap();
            let Event::MediaPart { part: p, .. } = b.until("the picture", pictured(t)) else {
                panic!("{name}: the download was refused")
            };
            got.extend_from_slice(&p.payload);
            if p.last {
                break;
            }
            part = Some(part.map_or(1, |n| n + 1));
            assert!(
                part.unwrap() < p.parts,
                "{name}: more parts than {}",
                p.parts
            );
        }
        assert!(got.starts_with(b"\x89PNG"), "{name}: not a PNG");

        let t = a.s.media_upload(&[0; 1024], None).unwrap();
        let Event::MediaFailed { code, reason, .. } = a.until("the refusal", pictured(t)) else {
            panic!("{name}: a picture of zeros went up")
        };
        eprintln!("{name}: a picture up and down; zeros refused ({code:?}, {reason:?})");
    }
}

fn summary(e: &Event) -> String {
    match e {
        Event::NewsFile { text, .. } => format!("{} bytes", text.len()),
        Event::FileList { files, .. } => format!("{} entries", files.len()),
        Event::NewsListing { items, .. } => format!("{} items", items.len()),
        Event::NewsCategory { articles, .. } => format!("{} articles", articles.len()),
        Event::NewsArticle { text, .. } => format!("{} bytes", text.len()),
        Event::Failed { reason, .. } => format!("refused: {reason:?}"),
        other => format!("{other:?}"),
    }
}

/// The HOPE logins the rig's servers take: mhxd's Blowfish and its zlib
/// compression, its HMAC login over plaintext, and Janus's ChaCha20-Poly1305
/// with and without its compressions (ZSTD too, in GtkHx's suite, which
/// builds with it).
#[cfg(feature = "hope")]
const HOPE: &[(&str, Option<Cipher>, Option<Compression>)] = &[
    ("mhxd", None, None),
    ("mhxd", None, Some(Compression::Gzip)),
    ("mhxd", Some(Cipher::Blowfish), None),
    ("mhxd", Some(Cipher::Blowfish), Some(Compression::Gzip)),
    ("janus", Some(Cipher::Blowfish), None),
    ("janus", Some(Cipher::Blowfish), Some(Compression::Gzip)),
    ("janus", Some(Cipher::ChaCha20Poly1305), None),
    (
        "janus",
        Some(Cipher::ChaCha20Poly1305),
        Some(Compression::Lz4),
    ),
    (
        "janus",
        Some(Cipher::ChaCha20Poly1305),
        Some(Compression::Gzip),
    ),
];

/// A HOPE session's chat reaches a plain one, and the plain one's comes
/// back through the transport; the user list, the largest reply here,
/// comes through it too.
#[cfg(feature = "hope")]
#[test]
fn hope_logs_in_and_chats_on_every_server_that_has_it() {
    let servers = servers();
    for &(name, cipher, compression) in HOPE {
        let Some(&(_, addr)) = servers.iter().find(|(n, _)| *n == name) else {
            continue;
        };
        let what = format!("{name} {cipher:?} {compression:?}");
        let offer = hxhope::client::Offer {
            ciphers: cipher.into_iter().collect(),
            compressions: compression.into_iter().collect(),
            ..hxhope::client::Offer::new(*b"TEST")
        };
        let mut seed = std::process::id();
        let random = Box::new(move |buf: &mut [u8]| {
            for b in buf {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                *b = (seed >> 16) as u8;
            }
        });
        let (nh, np) = (nick(name, "h"), nick(name, "p"));
        let session = Session::with_hope(Config::guest(&nh), offer, random, 0);
        let mut h = Client::login_as(name, addr, session);
        let n = h.s.negotiated().expect("HOPE was negotiated");
        assert_eq!((n.cipher, n.compression), (cipher, compression), "{what}");
        let mut p = Client::login(name, addr, &np);

        // p's agree may still be on its way when p is ready, and a list
        // asked for before the server has it says nothing of p: ask again.
        let deadline = Instant::now() + WAIT;
        'listed: loop {
            h.s.user_list().unwrap();
            let Event::UserList { users, .. } =
                h.until("the user list", |e| matches!(e, Event::UserList { .. }))
            else {
                unreachable!()
            };
            if users.iter().any(|u| u.name == np) {
                break 'listed;
            }
            assert!(Instant::now() < deadline, "{what}: {np} never listed");
        }
        let line = format!("{nh} over HOPE");
        h.s.chat(&line).unwrap();
        h.flush();
        p.until(
            "the HOPE chat",
            |e| matches!(e, Event::Chat { text, .. } if text.contains(&line)),
        );
        let back = format!("{np} back");
        p.s.chat(&back).unwrap();
        p.flush();
        h.until(
            "the chat back",
            |e| matches!(e, Event::Chat { text, .. } if text.contains(&back)),
        );
        eprintln!("{what}: login, user list, chat both ways");
    }
}
