//! The session against real servers: GtkHx's Docker rig (its
//! `tests/COMPOSE.md`), reached over plain TCP with a blocking loop around
//! the session. `cargo test -p hxsession --features rig`; `HX_RIG_SERVERS`
//! (comma-separated names) narrows the list.

#![cfg(feature = "rig")]

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use hxsession::request::Request;
use hxsession::{Config, Event, Session};

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
    fn connect(name: &'static str, addr: &str, cfg: Config) -> Client {
        let sock = TcpStream::connect(addr).unwrap_or_else(|e| panic!("{name} at {addr}: {e}"));
        sock.set_nodelay(true).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let start = Instant::now();
        Client {
            name,
            s: Session::new(cfg, 0),
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
        let mut c = Client::connect(name, addr, Config::guest(nick));
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
        let Event::UserList(users) = b.until(
            "the user list",
            |e| matches!(e, Event::UserList(u) if u.iter().any(|u| u.name == na)),
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
