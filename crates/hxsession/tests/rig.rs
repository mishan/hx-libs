//! The session against real servers: GtkHx's Docker rig (its
//! `tests/COMPOSE.md`), reached over plain TCP with a blocking loop around
//! the session. `cargo test -p hxsession --features rig`; `HX_RIG_SERVERS`
//! (comma-separated names) narrows the list.

#![cfg(feature = "rig")]

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
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
        let mut c = Client::connect(name, addr, s);
        let first = c.until("the agreement or readiness", |e| {
            matches!(e, Event::Agreement(_) | Event::Ready)
        });
        // An agreement with text waits for the user, who here agrees.
        if let Event::Agreement(_) = first {
            c.s.agree().unwrap();
            c.until("the session to be ready", |e| matches!(e, Event::Ready));
        }
        c
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
        let t =
            a.s.request(&Request::new(0x163).field(tag::BODY, text.clone().into_bytes()))
                .unwrap();
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

#[test]
fn files_list_on_every_server() {
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
