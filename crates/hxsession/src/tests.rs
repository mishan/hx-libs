//! The session against a scripted server: what it sends, in what order, and
//! what it makes of what it is sent.

use super::*;
use crate::frame::FrameReader;

const T0: u64 = 1_000_000;
const TASK: u32 = 0x0001_0000;

/// A transaction as a server writes it.
fn server(type_: u32, trans: u32, flag: u32, fields: &[(u16, &[u8])]) -> Vec<u8> {
    let req = Request {
        opcode: type_,
        fields: fields.iter().map(|(t, d)| (*t, d.to_vec())).collect(),
    };
    let mut bytes = req.pack(trans).unwrap();
    bytes[8..12].copy_from_slice(&flag.to_be_bytes());
    bytes
}

/// What the session sent since last asked, as (opcode, trans, fields).
/// (opcode, trans, fields)
type Sent = (u32, u32, Vec<(u16, Vec<u8>)>);

fn sent(s: &mut Session) -> Vec<Sent> {
    let bytes = s.take_outgoing();
    let mut r = FrameReader::new();
    r.push(&bytes);
    let mut out = Vec::new();
    while let Some(t) = r.next_transaction().unwrap() {
        let fields = hxproto::wire::ChunkIter::over_message(&t.buf, t.buf.len())
            .map(|c| (c.tag, c.data.to_vec()))
            .collect();
        out.push((t.type_, t.trans, fields));
    }
    out
}

fn opcodes(s: &mut Session) -> Vec<u32> {
    sent(s).into_iter().map(|(op, _, _)| op).collect()
}

fn events(s: &mut Session) -> Vec<Event> {
    std::iter::from_fn(|| s.poll_event()).collect()
}

/// A session past the magic, with its login sent and taken.
fn logging_in(cfg: Config) -> Session {
    let mut s = Session::new(cfg, T0);
    assert_eq!(s.take_outgoing(), CLIENT_MAGIC);
    s.feed(SERVER_MAGIC, T0);
    let login = sent(&mut s);
    assert_eq!(login.len(), 1);
    assert_eq!((login[0].0, login[0].1), (107, 1));
    s
}

fn login_reply(version: Option<u16>, caps: Option<u16>) -> Vec<u8> {
    let v = version.map(u16::to_be_bytes);
    let c = caps.map(u16::to_be_bytes);
    let mut fields: Vec<(u16, &[u8])> = vec![(tag::SERVERNAME, b"Scripted")];
    if let Some(v) = &v {
        fields.push((tag::VERSION, v));
    }
    if let Some(c) = &c {
        fields.push((tag::CAPABILITIES, c));
    }
    server(TASK, 1, 0, &fields)
}

/// A 1.5 session through an empty agreement, with what that sent taken.
fn ready() -> Session {
    let mut s = logging_in(Config::guest("me"));
    s.feed(&login_reply(Some(190), Some(cap::TEXT_ENCODING)), T0);
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), T0);
    assert_eq!(opcodes(&mut s), [121, 300]);
    events(&mut s);
    s
}

#[test]
fn the_login_carries_no_nickname() {
    let mut s = Session::new(Config::account("Nick", "guest", "pw"), T0);
    s.take_outgoing();
    // The magic may arrive in pieces, and the login waits for all of it.
    s.feed(b"TRTP", T0);
    assert!(s.take_outgoing().is_empty());
    s.feed(b"\0\0\0\0", T0);
    let login = sent(&mut s);
    let fields = &login[0].2;
    assert!(fields.iter().all(|(t, _)| *t != tag::NAME));
    assert!(fields.contains(&(
        tag::LOGIN,
        request::login(b"guest", b"", 0, 0, 0).fields[0].1.clone()
    )));
    assert!(fields.contains(&(tag::VERSION, CLIENT_VERSION.to_be_bytes().to_vec())));
}

#[test]
fn a_refused_handshake_closes() {
    let mut s = Session::new(Config::guest("me"), T0);
    s.feed(b"TRTP\0\0\0\x01", T0);
    assert_eq!(
        events(&mut s),
        [Event::Closed(Closed::BadMagic(*b"TRTP\0\0\0\x01"))]
    );
    assert!(s.is_closed());
}

#[test]
fn a_1_5_server_waits_for_the_agreement_to_be_answered() {
    let mut s = logging_in(Config::guest("me"));
    s.feed(&login_reply(Some(190), None), T0);
    assert!(
        matches!(&events(&mut s)[..], [Event::LoggedIn(i)] if i.version == 190 && i.name.as_deref() == Some("Scripted"))
    );
    // Nothing goes out before the agreement is answered.
    assert!(s.take_outgoing().is_empty());
    assert_eq!(s.user_list(), Err(Error::NotReady));

    s.feed(
        &server(0x6d, 0, 0, &[(tag::BODY, b"Be nice.\rReally.")]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [Event::Agreement("Be nice.\nReally.".into())]
    );
    // Showing it stops the clock: the user takes as long as they take.
    s.tick(T0 + 60_000);
    assert!(s.take_outgoing().is_empty());

    s.agree().unwrap();
    let out = sent(&mut s);
    assert_eq!(out[0].0, 121);
    assert!(out[0].2.contains(&(tag::NAME, b"me".to_vec())));
    assert!(out[0].2.contains(&(tag::OPTIONS, vec![0, 0])));
    assert_eq!(out[1].0, 300);
    assert_eq!(events(&mut s), [Event::Ready]);
}

#[test]
fn an_empty_agreement_is_answered_at_once() {
    let mut s = logging_in(Config::guest("me"));
    s.feed(&login_reply(Some(190), None), T0);
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), T0);
    assert_eq!(opcodes(&mut s), [121, 300]);
    assert!(events(&mut s).contains(&Event::Ready));
}

#[test]
fn a_1_5_server_that_sends_no_agreement_is_not_waited_on_forever() {
    let mut s = logging_in(Config::guest("me"));
    s.feed(&login_reply(Some(190), None), T0);
    s.tick(T0 + 1_999);
    assert!(s.take_outgoing().is_empty());
    assert_eq!(s.next_deadline(), Some(T0 + 2_000));
    s.tick(T0 + 2_000);
    // GtkHx's fallback: the fetches, and no agree nobody asked for.
    assert_eq!(opcodes(&mut s), [300]);
    assert!(events(&mut s).contains(&Event::Ready));
}

#[test]
fn a_1_2_server_gets_the_name_in_a_user_change() {
    let mut s = logging_in(Config::guest("me"));
    s.feed(&login_reply(None, None), T0);
    let out = sent(&mut s);
    assert_eq!(out.iter().map(|o| o.0).collect::<Vec<_>>(), [304, 300]);
    assert!(out[0].2.contains(&(tag::NAME, b"me".to_vec())));
    assert_eq!(s.server().unwrap().version, 0);
}

#[test]
fn what_arrives_before_the_login_reply_waits_for_it() {
    let mut s = logging_in(Config::guest("me"));
    s.feed(&server(0x162, 0, 0, &[]), T0);
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), T0);
    assert!(events(&mut s).is_empty());
    assert!(s.take_outgoing().is_empty());
    s.feed(&login_reply(Some(151), None), T0);
    let ev = events(&mut s);
    assert!(matches!(ev[0], Event::LoggedIn(_)));
    assert!(matches!(ev[1], Event::SelfInfo { .. }));
    assert_eq!(opcodes(&mut s), [121, 300]);
}

#[test]
fn a_refused_login_closes_with_the_reason() {
    let mut s = logging_in(Config::guest("me"));
    s.feed(
        &server(TASK, 1, 1, &[(tag::TASK_ERROR, b"Incorrect login.")]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [Event::Closed(Closed::LoginRefused(Some(
            "Incorrect login.".into()
        )))]
    );
}

#[test]
fn an_unanswered_login_times_out() {
    let mut s = logging_in(Config::guest("me"));
    s.tick(T0 + 29_999);
    assert!(events(&mut s).is_empty());
    s.tick(T0 + 30_000);
    assert_eq!(events(&mut s), [Event::Closed(Closed::Timeout)]);
}

#[test]
fn replies_find_their_requests() {
    let mut s = ready();
    // The post-login user list went out on trans 3: login 1, agree 2.
    assert_eq!(s.roster_trans(), Some(3));
    let users = [
        &[0, 5, 0, 1, 0, 2, 0, 3, b'b', b'o', b'b'][..],
        &[0, 6, 0, 9, 0, 0, 0, 2, b'm', b'e', 0, 0x11, 0x22, 0x33][..],
    ];
    s.feed(
        &server(
            TASK,
            3,
            0,
            &[(tag::USER_LIST, users[0]), (tag::USER_LIST, users[1])],
        ),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [Event::UserList {
            trans: 3,
            users: vec![
                User {
                    uid: 5,
                    icon: 1,
                    status: Some(2),
                    name: "bob".into(),
                    color: None
                },
                User {
                    uid: 6,
                    icon: 9,
                    status: Some(0),
                    name: "me".into(),
                    color: Some(0x112233)
                },
            ],
            subject: None,
        }]
    );

    let info = s.user_info(5).unwrap();
    let news = s.news_file().unwrap();
    assert_eq!((info, news), (4, 5));
    // Out of order, as a server may answer.
    s.feed(&server(TASK, news, 0, &[(tag::NEWS, b"first\rsecond")]), T0);
    s.feed(
        &server(TASK, info, 0, &[(tag::NAME, b"bob"), (tag::BODY, b"idle")]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [
            Event::NewsFile {
                trans: news,
                text: "first\nsecond".into()
            },
            Event::UserInfo {
                trans: info,
                name: "bob".into(),
                info: "idle".into()
            },
        ]
    );
    // A reply nobody asked for is nobody's business.
    s.feed(&server(TASK, 99, 0, &[]), T0);
    assert!(events(&mut s).is_empty());
}

#[test]
fn a_failed_request_says_why() {
    let mut s = ready();
    let t = s.message(5, "hi").unwrap();
    s.feed(
        &server(TASK, t, 1, &[(tag::TASK_ERROR, b"Refuses messages.")]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [Event::Failed {
            trans: t,
            reason: Some("Refuses messages.".into())
        }]
    );
}

#[test]
fn pushes_become_events() {
    let mut s = ready();
    s.feed(
        &server(
            0x6a,
            0,
            0,
            &[(tag::BODY, b"\r    bob:  hi"), (tag::UID, &[0, 5])],
        ),
        T0,
    );
    s.feed(
        &server(
            0x68,
            0,
            0,
            &[
                (tag::UID, &[0, 5]),
                (tag::NAME, b"bob"),
                (tag::BODY, b"psst"),
            ],
        ),
        T0,
    );
    s.feed(&server(0x163, 0, 0, &[(tag::BODY, b"Rebooting")]), T0);
    s.feed(
        &server(
            0x12d,
            0,
            0,
            &[
                (tag::UID, &[0, 7]),
                (tag::ICON, &[0, 2]),
                (tag::NAME, b"amy"),
            ],
        ),
        T0,
    );
    s.feed(&server(0x12e, 0, 0, &[(tag::UID, &[0, 7])]), T0);
    s.feed(&server(0x66, 0, 0, &[(tag::NEWS, b"a new post")]), T0);
    s.feed(&server(0x6f, 0, 0, &[(tag::BODY, b"Bye.")]), T0);
    s.feed(&server(0x7a, 0, 0, &[]), T0);
    let ev = events(&mut s);
    assert_eq!(
        ev[..7],
        [
            Event::Chat {
                cid: 0,
                uid: 5,
                text: "    bob:  hi".into(),
                media: None
            },
            Event::Message {
                uid: 5,
                from: "bob".into(),
                text: "psst".into(),
                media: None
            },
            Event::Broadcast {
                uid: 0,
                from: String::new(),
                text: "Rebooting".into()
            },
            Event::UserChanged {
                cid: 0,
                user: User {
                    uid: 7,
                    icon: 2,
                    status: None,
                    name: "amy".into(),
                    color: None
                },
            },
            Event::UserLeft { cid: 0, uid: 7 },
            Event::NewsPosted("a new post".into()),
            Event::Disconnecting("Bye.".into()),
        ]
    );
    assert!(matches!(ev[7], Event::Unhandled { opcode: 0x7a, .. }));
}

#[test]
fn text_follows_the_negotiated_encoding() {
    // Text-Encoding agreed: UTF-8 both ways.
    let mut s = ready();
    s.chat("café\nok").unwrap();
    let out = sent(&mut s);
    assert!(out[0]
        .2
        .contains(&(tag::BODY, "café\rok".as_bytes().to_vec())));

    // Not agreed: Mac Roman, where é is 0x8E.
    let mut s = logging_in(Config::guest("me"));
    s.feed(&login_reply(None, None), T0);
    sent(&mut s);
    s.chat("café").unwrap();
    assert!(sent(&mut s)[0]
        .2
        .contains(&(tag::BODY, b"caf\x8e".to_vec())));
    s.feed(&server(0x6a, 0, 0, &[(tag::BODY, b"\rcaf\x8e")]), T0);
    assert!(events(&mut s).contains(&Event::Chat {
        cid: 0,
        uid: 0,
        text: "café".into(),
        media: None
    }));
}

#[test]
fn a_quiet_connection_is_kept_alive() {
    // A 1.5+ server is pinged.
    let mut s = ready();
    assert_eq!(s.next_deadline(), Some(T0 + 60_000));
    s.tick(T0 + 59_999);
    assert!(s.take_outgoing().is_empty());
    s.tick(T0 + 60_000);
    let ping = sent(&mut s);
    assert_eq!(ping[0].0, 500);
    // An old server answers a ping with an error, which is no news.
    s.feed(&server(TASK, ping[0].1, 1, &[(tag::TASK_ERROR, b"?")]), T0);
    assert!(events(&mut s).is_empty());
    // Anything sent puts the next one off.
    s.tick(T0 + 100_000);
    s.chat("hi").unwrap();
    s.tick(T0 + 120_000);
    assert_eq!(opcodes(&mut s), [105]);

    // A 1.2 server is sent nothing unasked, as GtkHx does.
    let mut s = logging_in(Config::guest("me"));
    s.feed(&login_reply(None, None), T0);
    sent(&mut s);
    events(&mut s);
    assert_eq!(s.next_deadline(), None);
    s.tick(T0 + 600_000);
    assert!(s.take_outgoing().is_empty());
}

#[test]
fn threaded_news_walks_down_from_the_root() {
    let mut s = ready();
    let t = s.news_listing(&[]).unwrap();
    let out = sent(&mut s);
    assert_eq!(out[0].0, 370);
    assert!(out[0].2.is_empty());
    s.feed(
        &server(
            TASK,
            t,
            0,
            &[(
                tag::NEWSFOLDERITEM,
                &[0, 1, 0, 0, 0, 4, b'N', b'e', b'w', b's'],
            )],
        ),
        T0,
    );
    let ev = events(&mut s);
    assert!(
        matches!(&ev[..], [Event::NewsListing { items, .. }] if items.len() == 1),
        "{ev:?}"
    );

    s.news_category(&["News", "General"]).unwrap();
    let out = sent(&mut s);
    assert_eq!(out[0].0, 371);
    assert_eq!(
        out[0].2,
        [(
            tag::NEWSPATH,
            [&[0, 2, 0, 0, 4][..], b"News", &[0, 0, 7], b"General"].concat()
        )]
    );
    s.news_article(&["News", "General"], 3).unwrap();
    let out = sent(&mut s);
    assert_eq!(out[0].0, 400);
    assert!(out[0]
        .2
        .contains(&(tag::THREADID, 3u32.to_be_bytes().to_vec())));
}

#[test]
fn requests_wait_for_the_session_to_be_ready() {
    let mut s = logging_in(Config::guest("me"));
    assert_eq!(s.chat("hi"), Err(Error::NotReady));
    assert_eq!(s.agree(), Err(Error::NotReady));
    assert!(s.take_outgoing().is_empty());
}

// ---- What the review of the first version found ----------------------

#[test]
fn the_agreement_wait_starts_when_the_reply_arrives_not_at_the_last_tick() {
    // An event-driven caller: nothing ticks between the session's birth
    // and the login reply, which takes its time over a relay.
    let mut s = logging_in(Config::guest("me"));
    s.feed(&login_reply(Some(190), None), T0 + 2_500);
    assert_eq!(s.next_deadline(), Some(T0 + 4_500));
    s.tick(T0 + 2_600);
    assert!(s.take_outgoing().is_empty(), "nothing before the agreement");
    s.feed(&server(0x6d, 0, 0, &[(tag::BODY, b"Rules.")]), T0 + 3_000);
    assert!(events(&mut s).contains(&Event::Agreement("Rules.".into())));

    // Agreeing long after: the keep-alive counts from the agree, not from
    // whenever the clock was last read.
    s.tick(T0 + 90_000);
    s.agree().unwrap();
    assert_eq!(opcodes(&mut s), [121, 300]);
    s.tick(T0 + 90_001);
    assert!(
        s.take_outgoing().is_empty(),
        "no ping right after the agree"
    );
    assert_eq!(s.next_deadline(), Some(T0 + 150_001));
}

#[test]
fn a_server_that_never_answers_the_login_cannot_flood_the_session() {
    let mut s = logging_in(Config::guest("me"));
    for _ in 0..MAX_EARLY {
        s.feed(&server(0x6a, 0, 0, &[(tag::BODY, b"spam")]), T0);
    }
    assert!(!s.is_closed());
    s.feed(&server(0x6a, 0, 0, &[(tag::BODY, b"spam")]), T0);
    assert!(matches!(
        events(&mut s)[..],
        [Event::Closed(Closed::Protocol(_))]
    ));
}

#[test]
fn the_login_reply_is_the_first_reply_whatever_its_trans() {
    let mut s = logging_in(Config::guest("me"));
    let mut reply = login_reply(Some(190), None);
    reply[4..8].copy_from_slice(&0u32.to_be_bytes());
    s.feed(&reply, T0);
    assert!(matches!(events(&mut s)[..], [Event::LoggedIn(_)]));

    let mut s = logging_in(Config::guest("me"));
    s.feed(
        &server(TASK, 0, 1, &[(tag::TASK_ERROR, b"You are banned.")]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [Event::Closed(Closed::LoginRefused(Some(
            "You are banned.".into()
        )))]
    );
}

#[test]
fn a_1_2_server_gets_the_name_even_when_an_agreement_came_first() {
    // One that says there is none is a 1.5 server hiding its version.
    let mut s = logging_in(Config::guest("me"));
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), T0);
    s.feed(&login_reply(None, None), T0);
    assert_eq!(opcodes(&mut s), [304, 121, 300]);

    // One with text is shown, and does not hold the session up.
    let mut s = logging_in(Config::guest("me"));
    s.feed(&server(0x6d, 0, 0, &[(tag::BODY, b"Rules.")]), T0);
    s.feed(&login_reply(None, None), T0);
    assert_eq!(opcodes(&mut s), [304, 300]);
    let ev = events(&mut s);
    assert!(ev.contains(&Event::Ready));
    assert!(ev.contains(&Event::Agreement("Rules.".into())));
}

#[test]
fn agree_needs_an_agreement_to_answer() {
    let mut s = logging_in(Config::guest("me"));
    s.feed(&login_reply(Some(190), None), T0);
    // Inside the wait, before the server has shown anything.
    assert_eq!(s.agree(), Err(Error::NoAgreement));
    assert!(s.take_outgoing().is_empty());
    // And the agreement that then arrives is still shown.
    s.feed(&server(0x6d, 0, 0, &[(tag::BODY, b"Rules.")]), T0);
    assert!(events(&mut s).contains(&Event::Agreement("Rules.".into())));
    s.agree().unwrap();
    assert_eq!(s.agree(), Err(Error::NoAgreement));
}

#[test]
fn configured_times_do_not_overflow() {
    let cfg = Config {
        keepalive_ms: u64::MAX,
        agreement_wait_ms: u64::MAX,
        handshake_timeout_ms: u64::MAX,
        ..Config::guest("me")
    };
    let mut s = logging_in(cfg);
    s.feed(&login_reply(Some(190), None), u64::MAX - 5);
    s.tick(u64::MAX);
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), u64::MAX);
    assert_eq!(opcodes(&mut s), [121, 300]);
    s.tick(u64::MAX);
    assert!(s.take_outgoing().is_empty());
}

#[test]
fn unanswered_requests_are_not_remembered_forever() {
    let mut s = ready();
    // mhxd never answers a user change: it is not tracked at all.
    let before = s.pending.len();
    s.set_nick("new", 1).unwrap();
    assert_eq!(s.pending.len(), before);
    for _ in 0..(MAX_PENDING * 3) {
        s.user_info(1).unwrap();
    }
    assert!(s.pending.len() <= MAX_PENDING as usize);
}

#[test]
fn a_cut_short_reply_fails_its_request() {
    let mut s = ready();
    let t = s.news_file().unwrap();
    let whole = [&2u16.to_be_bytes()[..], &[0, 0x65, 0, 50], &[b'n'; 50]].concat();
    let total = whole.len() as u32;
    // The first part, then the same trans starting over with a different
    // size: the first can never finish.
    let frag = |data: &[u8], total: u32| {
        let mut f = Vec::new();
        f.extend_from_slice(&TASK.to_be_bytes());
        f.extend_from_slice(&t.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes());
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&(data.len() as u32).to_be_bytes());
        f.extend_from_slice(data);
        f
    };
    s.feed(&frag(&whole[..20], total), T0);
    s.feed(&frag(&whole[..20], total + 1), T0);
    assert!(events(&mut s)
        .iter()
        .any(|e| matches!(e, Event::Failed { trans, reason: Some(_) } if *trans == t)));
}

#[test]
fn chat_says_which_trans_a_refusal_would_carry() {
    let mut s = ready();
    let t = s.chat("hi").unwrap();
    s.feed(
        &server(TASK, t, 1, &[(tag::TASK_ERROR, b"No chat for you.")]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [Event::Failed {
            trans: t,
            reason: Some("No chat for you.".into())
        }]
    );
}

#[test]
fn a_hangup_ends_the_session() {
    let mut s = ready();
    s.disconnected();
    assert_eq!(events(&mut s), [Event::Closed(Closed::Hangup)]);
    assert_eq!(s.next_deadline(), None);
    assert_eq!(s.chat("hi"), Err(Error::NotReady));
    s.disconnected();
    assert!(events(&mut s).is_empty());
}

#[test]
fn credentials_go_as_typed() {
    let mut s = Session::new(Config::account("me", "zoë", "pässword"), T0);
    s.take_outgoing();
    s.feed(SERVER_MAGIC, T0);
    let login = sent(&mut s);
    assert!(login[0]
        .2
        .contains(&(tag::LOGIN, "zoë".bytes().map(|b| !b).collect())));
}

#[test]
fn fields_read_back_a_reply() {
    let frame = server(TASK, 3, 0, &[(tag::NAME, b"x"), (tag::UID, &[0, 1])]);
    assert_eq!(
        fields(&frame),
        [(tag::NAME, b"x".to_vec()), (tag::UID, vec![0, 1])]
    );
}

/// One folder-listing entry: type, creator, size, then the name after its
/// script code and length.
fn entry(ftype: &[u8; 4], creator: &[u8; 4], size: u32, script: u16, name: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(ftype);
    e.extend_from_slice(creator);
    e.extend_from_slice(&size.to_be_bytes());
    e.extend_from_slice(&[0, 0, 0, 0]);
    e.extend_from_slice(&script.to_be_bytes());
    e.extend_from_slice(&(name.len() as u16).to_be_bytes());
    e.extend_from_slice(name);
    e
}

#[test]
fn a_folder_lists_its_files() {
    let mut s = ready();
    let t = s.file_list(&[]).unwrap();
    let out = sent(&mut s);
    assert_eq!(out[0].0, 200);
    // The root still goes as a DIR, an empty one, as GtkHx sends it.
    assert_eq!(out[0].2, [(tag::DIR, vec![0, 0])]);
    // As real servers send a folder: zeros for its creator.
    let a = entry(b"fldr", &[0; 4], 3, 0, b"Uploads");
    let b = entry(b"TEXT", b"ttxt", 1234, 0, b"read me");
    // Between them, a field this session has no use for.
    s.feed(
        &server(TASK, t, 0, &[(0x00c8, &a), (0x0099, b"x"), (0x00c8, &b)]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [Event::FileList {
            trans: t,
            files: vec![
                FileEntry {
                    name: "Uploads".into(),
                    name_bytes: b"Uploads".to_vec(),
                    folder: true,
                    size: 3,
                    type_code: *b"fldr",
                    creator: [0; 4],
                },
                FileEntry {
                    name: "read me".into(),
                    name_bytes: b"read me".to_vec(),
                    folder: false,
                    size: 1234,
                    type_code: *b"TEXT",
                    creator: *b"ttxt",
                },
            ],
        }]
    );

    // A nested folder, spelled out: a count, then per name two zeros, a
    // length and the name.
    s.file_list(&["Uploads", "new"]).unwrap();
    assert_eq!(
        sent(&mut s)[0].2,
        [(
            tag::DIR,
            [&[0, 2, 0, 0, 7][..], b"Uploads", &[0, 0, 3], b"new"].concat()
        )]
    );
}

#[test]
fn an_empty_folder_lists_nothing_and_a_refusal_says_why() {
    let mut s = ready();
    let t = s.file_list(&["Uploads"]).unwrap();
    s.feed(&server(TASK, t, 0, &[]), T0);
    assert_eq!(
        events(&mut s),
        [Event::FileList {
            trans: t,
            files: vec![]
        }]
    );
    let t = s.file_list(&[]).unwrap();
    s.feed(
        &server(TASK, t, 1, &[(tag::TASK_ERROR, b"No files here.")]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [Event::Failed {
            trans: t,
            reason: Some("No files here.".into())
        }]
    );
}

#[test]
fn a_bad_entry_is_skipped_and_its_neighbors_list() {
    let mut s = ready();
    let t = s.file_list(&[]).unwrap();
    let good = entry(b"TEXT", b"ttxt", 1, 0, b"a");
    let short = vec![0u8; 10];
    s.feed(
        &server(
            TASK,
            t,
            0,
            &[(0x00c8, &good), (0x00c8, &short), (0x00c8, &good)],
        ),
        T0,
    );
    let ev = events(&mut s);
    assert!(matches!(&ev[..], [Event::FileList { files, .. }] if files.len() == 2));
}

#[test]
fn large_files_get_their_exact_size_from_the_field_after_them() {
    let mut s = ready();
    let t = s.file_list(&[]).unwrap();
    let big = entry(b"BINA", b"????", u32::MAX, 0, b"disk image");
    let small = entry(b"TEXT", b"ttxt", 5, 0, b"note");
    let folder = entry(b"fldr", &[0; 4], u32::MAX, 0, b"huge");
    let exact = (6u64 << 30).to_be_bytes();
    let items = 70_000u64.to_be_bytes();
    // A companion only where one is needed, as Janus sends them.
    s.feed(
        &server(
            TASK,
            t,
            0,
            &[
                (0x00c8, &big),
                (0x01f1, &exact),
                (0x00c8, &small),
                (0x00c8, &folder),
                (0x01f4, &items),
            ],
        ),
        T0,
    );
    let ev = events(&mut s);
    let Event::FileList { files, .. } = &ev[0] else {
        panic!("{ev:?}")
    };
    assert_eq!(
        files.iter().map(|f| f.size).collect::<Vec<_>>(),
        [6u64 << 30, 5, 70_000]
    );
}

#[test]
fn names_go_back_as_the_server_sent_them() {
    // A server that never agreed to UTF-8 but sends it anyway: "café"
    // decodes from its UTF-8 bytes, and re-encoding the name would send
    // Mac Roman ones it does not know.
    let mut s = logging_in(Config::guest("me"));
    s.feed(&login_reply(None, None), T0);
    sent(&mut s);
    events(&mut s);
    let t = s.file_list(&[]).unwrap();
    sent(&mut s);
    let cafe = entry(b"fldr", &[0; 4], 0, 0, "café".as_bytes());
    s.feed(&server(TASK, t, 0, &[(0x00c8, &cafe)]), T0);
    let ev = events(&mut s);
    let Event::FileList { files, .. } = &ev[0] else {
        panic!("{ev:?}")
    };
    assert_eq!(files[0].name, "café");
    assert_ne!(s.encode(&files[0].name), files[0].name_bytes);
    s.file_list_raw(&[&files[0].name_bytes]).unwrap();
    assert_eq!(
        sent(&mut s)[0].2,
        [(tag::DIR, [&[0, 1, 0, 0, 5][..], "café".as_bytes()].concat())]
    );
    // A name in another script still lists.
    let t = s.file_list(&[]).unwrap();
    let kana = entry(b"TEXT", b"ttxt", 1, 1, b"\x83\x41");
    s.feed(&server(TASK, t, 0, &[(0x00c8, &kana)]), T0);
    assert!(matches!(&events(&mut s)[..], [Event::FileList { files, .. }] if files.len() == 1));
}

#[test]
fn a_path_too_long_to_send_is_refused_not_cut() {
    let mut s = ready();
    let long = "x".repeat(256);
    assert_eq!(s.file_list(&[&long]), Err(Error::TooLong));
    assert_eq!(s.news_category(&[&long]), Err(Error::TooLong));
    assert!(s.take_outgoing().is_empty());
}

// ---- Raw mode ----------------------------------------------------------

/// Raw, handling no domain unless asked: as raw was before there were
/// domains.
fn raw() -> Config {
    Config {
        raw: true,
        ..Config::guest("me")
    }
}

/// A transaction as the caller of a raw session builds it.
fn caller(opcode: u32, trans: u32) -> Vec<u8> {
    Request::new(opcode).pack(trans).unwrap()
}

#[test]
fn raw_hands_over_the_login_reply_and_what_came_before_it() {
    let mut s = logging_in(raw());
    let selfinfo = server(0x162, 0, 0, &[]);
    s.feed(&selfinfo, T0);
    assert!(events(&mut s).is_empty());
    let reply = login_reply(Some(190), None);
    s.feed(&reply, T0);
    let ev = events(&mut s);
    assert_eq!(
        ev[0],
        Event::Reply {
            trans: 1,
            frame: reply
        }
    );
    assert!(matches!(&ev[1], Event::LoggedIn(i) if i.version == 190));
    assert_eq!(
        ev[2],
        Event::Unhandled {
            opcode: 0x162,
            frame: selfinfo
        }
    );
    assert_eq!(ev.len(), 3);
}

#[test]
fn raw_answers_an_empty_agreement_and_leaves_the_user_list_to_the_caller() {
    let mut s = logging_in(raw());
    s.feed(&login_reply(Some(190), None), T0);
    events(&mut s);
    let agreement = server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]);
    s.feed(&agreement, T0);
    let out = sent(&mut s);
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].0, out[0].1), (121, 2));
    assert_eq!(
        events(&mut s),
        [
            Event::Unhandled {
                opcode: 0x6d,
                frame: agreement
            },
            Event::Ready
        ]
    );
    assert_eq!(s.roster_trans(), None);
    let refusal = server(TASK, 2, 1, &[(tag::TASK_ERROR, b"No.")]);
    s.feed(&refusal, T0);
    assert_eq!(
        events(&mut s),
        [Event::Reply {
            trans: 2,
            frame: refusal
        }]
    );
}

#[test]
fn raw_shows_an_agreement_and_answers_it_when_told() {
    let mut s = logging_in(raw());
    s.feed(&login_reply(Some(190), None), T0);
    events(&mut s);
    s.feed(&server(0x6d, 0, 0, &[(tag::BODY, b"Be nice.")]), T0);
    let ev = events(&mut s);
    assert!(matches!(ev[0], Event::Unhandled { opcode: 0x6d, .. }));
    assert_eq!(ev[1], Event::Agreement("Be nice.".into()));
    assert!(s.take_outgoing().is_empty());
    s.agree().unwrap();
    assert_eq!(opcodes(&mut s), [121]);
    assert_eq!(events(&mut s), [Event::Ready]);
}

#[test]
fn raw_still_names_us_to_a_1_2_server_and_waits_on_no_agreement() {
    let mut s = logging_in(raw());
    s.feed(&login_reply(None, None), T0);
    let out = sent(&mut s);
    assert_eq!(
        out.iter().map(|o| (o.0, o.1)).collect::<Vec<_>>(),
        [(304, 2)]
    );
    assert!(events(&mut s).contains(&Event::Ready));
    assert_eq!(s.next_deadline(), None);
}

#[test]
fn raw_sends_what_the_caller_built_and_hands_back_its_answer() {
    let mut s = logging_in(raw());
    // Numbered before the login is answered, but not sent until then: the
    // server would not take it.
    let trans = s.take_trans();
    let frame = caller(300, trans);
    assert_eq!(s.send_raw(&frame), Err(Error::NotReady));
    s.feed(&login_reply(Some(190), None), T0);
    events(&mut s);

    s.send_raw(&frame).unwrap();
    assert_eq!(s.take_outgoing(), frame);

    let refusal = server(TASK, trans, 1, &[(tag::TASK_ERROR, b"No.")]);
    s.feed(&refusal, T0);
    assert_eq!(
        events(&mut s),
        [Event::Reply {
            trans,
            frame: refusal
        }]
    );
    let chat = server(0x6a, 0, 0, &[(tag::BODY, b"hi")]);
    s.feed(&chat, T0);
    assert_eq!(
        events(&mut s),
        [Event::Unhandled {
            opcode: 0x6a,
            frame: chat
        }]
    );
}

#[test]
fn raw_leaves_requests_to_the_caller_but_keeps_the_connection_alive() {
    let mut s = logging_in(raw());
    s.feed(&login_reply(Some(190), None), T0);
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), T0);
    sent(&mut s);
    events(&mut s);
    assert_eq!(s.user_list(), Err(Error::NotReady));
    assert_eq!(s.chat("hi"), Err(Error::NotReady));

    // What the caller sends puts the ping off, as the session's own does,
    // from the next reading of the clock.
    let t = s.take_trans();
    s.send_raw(&caller(300, t)).unwrap();
    s.take_outgoing();
    s.tick(T0 + 30_000);
    assert_eq!(s.next_deadline(), Some(T0 + 90_000));
    s.tick(T0 + 90_000);
    let ping = sent(&mut s);
    assert_eq!(ping.len(), 1);
    assert_eq!(ping[0].0, 500);
    // Its answer, even a refusal, is the session's alone.
    s.feed(&server(TASK, ping[0].1, 1, &[(tag::TASK_ERROR, b"?")]), T0);
    assert!(events(&mut s).is_empty());

    // A 1.2 server is not pinged in raw mode either.
    let mut s = logging_in(raw());
    s.feed(&login_reply(None, None), T0);
    assert_eq!(s.next_deadline(), None);
}

#[test]
fn a_trans_taken_before_the_magic_is_not_the_logins() {
    let mut s = Session::new(raw(), T0);
    let early = s.take_trans();
    s.take_outgoing();
    s.feed(SERVER_MAGIC, T0);
    let login = sent(&mut s);
    assert_eq!((login[0].0, login[0].1), (107, 1));
    assert_ne!(early, 1);
}

#[test]
fn raw_takes_only_whole_transactions() {
    let mut s = logging_in(raw());
    s.feed(&login_reply(Some(190), None), T0);
    s.take_outgoing();
    // A cut-off frame, a frame and a half.
    let whole = caller(300, s.take_trans());
    assert_eq!(s.send_raw(&whole[..21]), Err(Error::Malformed));
    assert_eq!(
        s.send_raw(&[whole.clone(), whole.clone()].concat()),
        Err(Error::Malformed)
    );
    assert!(s.take_outgoing().is_empty());
    s.send_raw(&whole).unwrap();

    s.disconnected();
    assert_eq!(s.send_raw(&whole), Err(Error::NotReady));
    assert_eq!(ready().send_raw(&whole), Err(Error::NotReady), "not raw");
}

#[test]
fn raw_agrees_as_whoever_the_caller_has_become() {
    let mut s = logging_in(raw());
    s.feed(&login_reply(Some(190), None), T0);
    s.feed(&server(0x6d, 0, 0, &[(tag::BODY, b"Be nice.")]), T0);
    s.set_identity("renamed", 9);
    s.agree().unwrap();
    let out = sent(&mut s);
    assert!(out[0].2.contains(&(tag::NAME, b"renamed".to_vec())));
    assert!(out[0].2.contains(&(tag::ICON, 9u16.to_be_bytes().to_vec())));
}

#[test]
fn raw_hands_over_a_refused_login_before_closing() {
    let mut s = logging_in(raw());
    let refusal = server(TASK, 1, 1, &[(tag::TASK_ERROR, b"No.")]);
    s.feed(&refusal, T0);
    assert_eq!(
        events(&mut s),
        [
            Event::Reply {
                trans: 1,
                frame: refusal
            },
            Event::Closed(Closed::LoginRefused(Some("No.".into())))
        ]
    );
}

#[test]
fn raw_stops_waiting_for_an_agreement_without_sending_anything() {
    let mut s = logging_in(raw());
    s.feed(&login_reply(Some(190), None), T0);
    events(&mut s);
    s.tick(T0 + 2_000);
    assert!(s.take_outgoing().is_empty());
    assert_eq!(events(&mut s), [Event::Ready]);
}

#[test]
fn raw_holds_an_early_agreement_for_the_login_reply() {
    let mut s = logging_in(raw());
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), T0);
    assert!(s.take_outgoing().is_empty());
    s.feed(&login_reply(Some(190), None), T0);
    assert_eq!(opcodes(&mut s), [121]);
    let ev = events(&mut s);
    assert!(matches!(ev[1], Event::LoggedIn(_)));
    assert!(matches!(ev[2], Event::Unhandled { opcode: 0x6d, .. }));
    assert_eq!(ev[3], Event::Ready);
}

#[test]
fn a_transaction_too_large_to_take_closes_saying_how_large() {
    let mut s = ready();
    let mut huge = server(0x6a, 0, 0, &[]);
    let claim = (frame::MAX_TRANSACTION as u32 + 1).to_be_bytes();
    huge[12..16].copy_from_slice(&claim);
    huge[16..20].copy_from_slice(&claim);
    s.feed(&huge, T0);
    assert_eq!(
        events(&mut s),
        [Event::Closed(Closed::TooLarge(
            frame::MAX_TRANSACTION as u32 + 1
        ))]
    );
}

#[test]
fn the_session_says_when_the_stream_stopped_part_way() {
    let mut s = Session::new(Config::guest("me"), T0);
    assert!(!s.mid_transaction());
    s.feed(b"TRTP", T0);
    assert!(s.mid_transaction());

    let mut s = ready();
    let chat = server(0x6a, 0, 0, &[(tag::BODY, b"hello")]);
    s.feed(&chat[..10], T0);
    assert!(s.mid_transaction());
    s.feed(&chat[10..], T0);
    assert!(!s.mid_transaction());
}

// ---- Chat ----------------------------------------------------------------

/// A raw session through an empty agreement, handling `handled`, its login
/// having agreed to `caps`.
fn raw_ready(handled: Handled, caps: u16) -> Session {
    let mut s = logging_in(Config {
        handled,
        caps: cap::TEXT_ENCODING | cap::INLINE_MEDIA | cap::CHAT_HISTORY,
        ..raw()
    });
    s.feed(&login_reply(Some(190), Some(caps)), T0);
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), T0);
    sent(&mut s);
    events(&mut s);
    s
}

#[test]
fn raw_hands_over_only_what_handled_leaves_to_the_caller() {
    let chat = server(
        0x6a,
        0,
        0,
        &[(tag::BODY, b"\rbob:  hi"), (tag::UID, &[0, 5])],
    );
    let invite = server(
        0x71,
        0,
        0,
        &[
            (tag::CHAT_ID, &[0, 0, 0, 9]),
            (tag::UID, &[0, 5]),
            (tag::NAME, b"bob"),
        ],
    );
    let subject = server(
        0x77,
        0,
        0,
        &[(tag::CHAT_ID, &[0, 0, 0, 9]), (tag::CHAT_SUBJECT, b"Plans")],
    );
    let user = server(0x12d, 0, 0, &[(tag::UID, &[0, 5]), (tag::NAME, b"bob")]);
    let msg = server(
        0x68,
        0,
        0,
        &[
            (tag::UID, &[0, 5]),
            (tag::NAME, b"bob"),
            (tag::BODY, b"psst"),
        ],
    );
    let quit = server(0x6f, 0, 0, &[(tag::BODY, b"Bye.")]);
    let news = server(0x66, 0, 0, &[(tag::NEWS, b"Up\rlate")]);
    let part = server(
        0x76,
        0,
        0,
        &[(tag::UID, &[0, 5]), (tag::CHAT_ID, &[0, 0, 0, 9])],
    );
    let whole = |opcode: u32, frame: &[u8]| Event::Unhandled {
        opcode,
        frame: frame.to_vec(),
    };
    let chat_events = [
        Event::Chat {
            cid: 0,
            uid: 5,
            text: "bob:  hi".into(),
            media: None,
        },
        Event::ChatInvite {
            cid: 9,
            uid: 5,
            name: "bob".into(),
        },
        Event::ChatSubject {
            cid: 9,
            subject: "Plans".into(),
        },
    ];
    let user_events = [
        Event::UserChanged {
            cid: 0,
            user: User {
                uid: 5,
                icon: 0,
                status: None,
                name: "bob".into(),
                color: None,
            },
        },
        Event::UserLeft { cid: 9, uid: 5 },
    ];
    let chat_whole = [
        whole(0x6a, &chat),
        whole(0x71, &invite),
        whole(0x77, &subject),
    ];
    let users_whole = [whole(0x12d, &user), whole(0x76, &part)];
    let msg_events = [
        Event::Message {
            uid: 5,
            from: "bob".into(),
            text: "psst".into(),
            media: None,
        },
        Event::Disconnecting("Bye.".into()),
    ];
    let msg_whole = [whole(0x68, &msg), whole(0x6f, &quit)];
    let news_events = [Event::NewsPosted("Up\nlate".into())];
    let news_whole = [whole(0x66, &news)];
    let cases = [
        (
            Handled::NONE,
            [&chat_whole[..], &users_whole, &msg_whole, &news_whole].concat(),
        ),
        (
            Handled::CHAT,
            [&chat_events[..], &users_whole, &msg_whole, &news_whole].concat(),
        ),
        (
            Handled::USERS,
            [&chat_whole[..], &user_events, &msg_whole, &news_whole].concat(),
        ),
        (
            Handled::MSG,
            [&chat_whole[..], &users_whole, &msg_events, &news_whole].concat(),
        ),
        (
            Handled::NEWS,
            [&chat_whole[..], &users_whole, &msg_whole, &news_events].concat(),
        ),
        (
            Handled::CHAT | Handled::USERS | Handled::MSG | Handled::NEWS,
            [&chat_events[..], &user_events, &msg_events, &news_events].concat(),
        ),
    ];
    for (handled, want) in cases {
        let mut s = raw_ready(handled, 0);
        for frame in [&chat, &invite, &subject, &user, &part, &msg, &quit, &news] {
            s.feed(frame, T0);
        }
        assert_eq!(events(&mut s), want, "{handled:?}");
    }
}

#[test]
fn names_and_subjects_read_in_either_encoding() {
    let mut s = raw_ready(Handled::CHAT, 0);
    // 0x8E is Mac Roman é; "é" in UTF-8 is not Mac Roman.
    for name in [&b"Ren\x8E"[..], "René".as_bytes()] {
        s.feed(
            &server(
                0x71,
                0,
                0,
                &[(tag::CHAT_ID, &[0, 0, 0, 1]), (tag::NAME, name)],
            ),
            T0,
        );
        s.feed(
            &server(
                0x77,
                0,
                0,
                &[(tag::CHAT_ID, &[0, 0, 0, 1]), (tag::CHAT_SUBJECT, name)],
            ),
            T0,
        );
        assert_eq!(
            events(&mut s),
            [
                Event::ChatInvite {
                    cid: 1,
                    uid: 0,
                    name: "René".into()
                },
                Event::ChatSubject {
                    cid: 1,
                    subject: "René".into()
                },
            ]
        );
    }
}

#[test]
fn a_chat_line_carries_its_media_where_it_was_agreed() {
    let id: (u16, &[u8]) = (tag::CHAT_MEDIA_ID, b"h1");
    let mime: (u16, &[u8]) = (tag::CHAT_MEDIA_TYPE, b"image/png");
    let width: (u16, &[u8]) = (tag::CHAT_MEDIA_WIDTH, &[0, 0, 3, 32]);
    let body: (u16, &[u8]) = (tag::BODY, b"look");
    let png = ChatMedia {
        id: b"h1".to_vec(),
        mime: b"image/png".to_vec(),
        width: Some(800),
        height: None,
        bytes: None,
    };
    let cases = [
        (
            "present",
            cap::INLINE_MEDIA,
            vec![body, id, mime, width],
            Some(Some(png)),
        ),
        ("absent", cap::INLINE_MEDIA, vec![body], Some(None)),
        ("orphaned id", cap::INLINE_MEDIA, vec![body, id], None),
        ("orphaned type", cap::INLINE_MEDIA, vec![body, mime], None),
        ("not agreed", 0, vec![body, id], Some(None)),
    ];
    for (what, caps, fields, want) in cases {
        let mut s = raw_ready(Handled::CHAT, caps);
        s.feed(&server(0x6a, 0, 0, &fields), T0);
        let got = events(&mut s);
        match want {
            Some(media) => assert_eq!(
                got,
                [Event::Chat {
                    cid: 0,
                    uid: 0,
                    text: "look".into(),
                    media
                }],
                "{what}"
            ),
            None => assert!(got.is_empty(), "{what}: dropped whole"),
        }
    }
}

#[test]
fn a_message_carries_its_media_where_it_was_agreed() {
    let from: [(u16, &[u8]); 3] = [
        (tag::UID, &[0, 5]),
        (tag::NAME, b"bob"),
        (tag::BODY, b"look"),
    ];
    let id: (u16, &[u8]) = (tag::CHAT_MEDIA_ID, b"h1");
    let mime: (u16, &[u8]) = (tag::CHAT_MEDIA_TYPE, b"image/png");
    let png = ChatMedia {
        id: b"h1".to_vec(),
        mime: b"image/png".to_vec(),
        width: None,
        height: None,
        bytes: None,
    };
    let cases = [
        (
            "present",
            cap::INLINE_MEDIA,
            vec![id, mime],
            Some(Some(png)),
        ),
        ("orphaned id", cap::INLINE_MEDIA, vec![id], None),
        ("not agreed", 0, vec![id], Some(None)),
    ];
    for (what, caps, media_fields, want) in cases {
        let mut s = raw_ready(Handled::MSG, caps);
        s.feed(
            &server(0x68, 0, 0, &[&from[..], &media_fields].concat()),
            T0,
        );
        let got = events(&mut s);
        match want {
            Some(media) => assert_eq!(
                got,
                [Event::Message {
                    uid: 5,
                    from: "bob".into(),
                    text: "look".into(),
                    media
                }],
                "{what}"
            ),
            None => assert!(got.is_empty(), "{what}: dropped whole"),
        }
    }
}

#[test]
fn a_broadcast_names_its_sender_when_the_server_does() {
    let mut s = raw_ready(Handled::MSG, 0);
    let fields: [(u16, &[u8]); 3] = [
        (tag::UID, &[0, 5]),
        (tag::NAME, b"admin"),
        (tag::BODY, b"Rebooting"),
    ];
    s.feed(&server(0x163, 0, 0, &fields), T0);
    s.feed(&server(0x68, 0, 0, &fields[2..]), T0);
    assert_eq!(
        events(&mut s),
        [
            Event::Broadcast {
                uid: 5,
                from: "admin".into(),
                text: "Rebooting".into()
            },
            Event::Broadcast {
                uid: 0,
                from: String::new(),
                text: "Rebooting".into()
            },
        ]
    );
}

#[test]
fn a_sender_s_name_and_a_user_s_info_name_end_at_their_first_nul() {
    // As a nickname does: what follows the NUL is not UTF-8.
    let name = &b"Ren\xC3\xA9\0\xFF"[..];
    let mut s = ready();
    let t = s.user_info(5).unwrap();
    s.feed(
        &server(
            0x68,
            0,
            0,
            &[(tag::UID, &[0, 5]), (tag::NAME, name), (tag::BODY, b"hi")],
        ),
        T0,
    );
    s.feed(&server(TASK, t, 0, &[(tag::NAME, name)]), T0);
    let got = events(&mut s);
    assert!(
        matches!(&got[..], [Event::Message { from, .. }, Event::UserInfo { name, .. }]
            if from == "René" && name == "René"),
        "{got:?}"
    );
}

/// A history entry as a server packs it.
fn history_entry(id: u64, flags: u16, nick: &[u8], text: &[u8]) -> Vec<u8> {
    [
        &id.to_be_bytes()[..],
        &1_700_000_000i64.to_be_bytes(),
        &flags.to_be_bytes(),
        &7u16.to_be_bytes(),
        &(nick.len() as u16).to_be_bytes(),
        nick,
        &(text.len() as u16).to_be_bytes(),
        text,
    ]
    .concat()
}

#[test]
fn an_expected_reply_becomes_its_event_and_the_rest_stay_whole() {
    let mut s = raw_ready(Handled::CHAT, cap::CHAT_HISTORY);
    let [history, invite, message, other] = [(); 4].map(|_| s.take_trans());
    s.expect(history, Expect::ChatHistory { cid: 4 }).unwrap();
    s.expect(invite, Expect::ChatInvite).unwrap();
    s.expect(message, Expect::Message).unwrap();
    for t in [history, invite, message, other] {
        s.send_raw(&caller(700, t)).unwrap();
    }

    let first = history_entry(10, 0, b"ann", b"one\rtwo \x1b[1m");
    let second = history_entry(11, 1, b"Ren\x8E", "caf\u{e9}".as_bytes());
    s.feed(
        &server(
            TASK,
            history,
            0,
            &[
                (tag::HISTORY_ENTRY, &first),
                (tag::HISTORY_ENTRY, &first[..20]),
                (tag::HISTORY_ENTRY, &second),
                (tag::HISTORY_HAS_MORE, &[1]),
                // Says nothing, so changes nothing.
                (tag::HISTORY_HAS_MORE, &[]),
            ],
        ),
        T0,
    );
    s.feed(&server(TASK, invite, 0, &[]), T0);
    s.feed(&server(TASK, message, 0, &[]), T0);
    let reply = server(TASK, other, 0, &[]);
    s.feed(&reply, T0);
    let entry = |message_id, flags, nick: &str, text: &str| HistoryEntry {
        message_id,
        timestamp: 1_700_000_000,
        flags,
        icon: 7,
        nick: nick.into(),
        text: text.into(),
    };
    assert_eq!(
        events(&mut s),
        [
            Event::ChatHistory {
                trans: history,
                cid: 4,
                entries: vec![
                    entry(10, 0, "ann", "one\ntwo [[1m"),
                    entry(11, 1, "René", "café"),
                ],
                has_more: true,
            },
            Event::Reply {
                trans: other,
                frame: reply
            },
        ]
    );
}

#[test]
fn news_replies_expected_become_events() {
    let mut s = raw_ready(Handled::NEWS, 0);
    let [file, listing, category, article, change, refused] = [(); 6].map(|_| s.take_trans());
    for (t, what) in [
        (file, Expect::NewsFile),
        (listing, Expect::NewsListing),
        (category, Expect::NewsCategory),
        (article, Expect::NewsArticle),
        (change, Expect::NewsChange),
        (refused, Expect::NewsChange),
    ] {
        s.expect(t, what).unwrap();
        s.send_raw(&caller(370, t)).unwrap();
    }
    // A name ends at its first NUL, as a nickname does; 0x8E is Mac Roman é.
    let bundle = [&[0, 2, 0, 0, 6][..], b"Ren\x8E\0\xFF"].concat();
    let post = [
        &[0, 0, 0, 7][..],   // its id
        &[0x07, 0xea, 0, 0], // 2026
        &[0, 0, 0, 60],      // a minute in
        &[0, 0, 0, 3],       // replying to 3
        &[0, 0, 0, 0],       // flags
        &[0, 1],             // one part
        &[4],                // subject
        b"Re\0x",
        &[3], // poster
        b"amy",
        &[10], // the part's type
        b"text/plain",
        &[0, 2], // and size
    ]
    .concat();
    let catlist = [&[0, 0, 0, 0, 0, 0, 0, 1, 0, 0][..], &post].concat();
    s.feed(&server(TASK, file, 0, &[(tag::NEWS, b"one\rtwo")]), T0);
    s.feed(
        &server(TASK, listing, 0, &[(tag::CATEGORYITEM, &bundle)]),
        T0,
    );
    s.feed(&server(TASK, category, 0, &[(tag::CATLIST, &catlist)]), T0);
    s.feed(
        &server(TASK, article, 0, &[(tag::NEWSDATA, b"caf\x8E")]),
        T0,
    );
    s.feed(&server(TASK, change, 0, &[]), T0);
    s.feed(
        &server(TASK, refused, 1, &[(tag::TASK_ERROR, b"Not allowed.")]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [
            Event::NewsFile {
                trans: file,
                text: "one\ntwo".into()
            },
            Event::NewsListing {
                trans: listing,
                items: vec![NewsItem {
                    name: "René".into(),
                    name_bytes: b"Ren\x8E\0\xFF".to_vec(),
                    bundle: true
                }]
            },
            Event::NewsCategory {
                trans: category,
                articles: vec![Article {
                    id: 7,
                    parent: 3,
                    subject: "Re".into(),
                    poster: "amy".into(),
                    year: 2026,
                    seconds: 60,
                    mime: b"text/plain".to_vec()
                }]
            },
            Event::NewsArticle {
                trans: article,
                text: "café".into()
            },
            Event::Failed {
                trans: refused,
                reason: Some("Not allowed.".into())
            },
        ]
    );
}

#[test]
fn news_changes_go_as_gtkhx_sends_them() {
    let mut s = ready();
    let path = [0, 1, 0, 0, 4, b'N', b'e', b'w', b's'].to_vec();
    s.news_post_article(&["News"], 3, "Re: hi", "one\ntwo")
        .unwrap();
    s.news_delete_article(&["News"], 7).unwrap();
    s.news_delete(&["News"]).unwrap();
    s.news_create_bundle(&[], "Old").unwrap();
    s.news_create_category(&["News"], "Café").unwrap();
    let got: Vec<_> = sent(&mut s).into_iter().map(|(op, _, f)| (op, f)).collect();
    assert_eq!(
        got,
        [
            (
                410,
                vec![
                    (tag::NEWSPATH, path.clone()),
                    (tag::NEWSFLAGS, 0u32.to_be_bytes().to_vec()),
                    (tag::NEWSTYPE, b"text/plain".to_vec()),
                    (tag::NEWSSUBJECT, b"Re: hi".to_vec()),
                    (tag::NEWSDATA, b"one\rtwo".to_vec()),
                    (tag::THREADID, 3u32.to_be_bytes().to_vec()),
                ]
            ),
            (
                411,
                vec![
                    (tag::NEWSPATH, path.clone()),
                    (tag::THREADID, 7u32.to_be_bytes().to_vec()),
                ]
            ),
            (380, vec![(tag::NEWSPATH, path.clone())]),
            (
                381,
                vec![
                    (tag::NEWSPATH, vec![0, 0]),
                    (tag::FILE_NAME, b"Old".to_vec())
                ]
            ),
            (
                382,
                vec![
                    (tag::NEWSPATH, path),
                    (tag::CATEGORY, "Café".as_bytes().to_vec())
                ]
            ),
        ]
    );
}

#[test]
fn the_user_list_and_a_chat_s_create_and_join_replies_become_events() {
    let mut s = raw_ready(Handled::USERS, 0);
    let [list, create, join, bare] = [(); 4].map(|_| s.take_trans());
    s.expect(list, Expect::UserList).unwrap();
    s.expect(create, Expect::ChatCreate).unwrap();
    s.expect(join, Expect::ChatJoin { cid: 9 }).unwrap();
    s.expect(bare, Expect::ChatJoin { cid: 4 }).unwrap();
    for (opcode, t) in [(300, list), (112, create), (115, join), (115, bare)] {
        s.send_raw(&caller(opcode, t)).unwrap();
    }
    let ann = &[0, 5, 0, 1, 0, 2, 0, 3, b'a', b'n', b'n'][..];
    let rene = &[
        0, 6, 0, 9, 0, 0, 0, 4, b'R', b'e', b'n', 0x8e, 0, 0x11, 0x22, 0x33,
    ][..];
    s.feed(
        &server(
            TASK,
            list,
            0,
            &[(tag::USER_LIST, ann), (tag::USER_LIST, &ann[..5])],
        ),
        T0,
    );
    s.feed(
        &server(
            TASK,
            create,
            0,
            &[
                (tag::CHAT_ID, &[0, 0, 0, 9]),
                (tag::UID, &[0, 6]),
                (tag::ICON, &[0, 9]),
                (tag::NAME, b"Ren\x8E"),
            ],
        ),
        T0,
    );
    s.feed(
        &server(
            TASK,
            join,
            0,
            &[
                (tag::USER_LIST, ann),
                (tag::USER_LIST, rene),
                (tag::CHAT_SUBJECT, b"Caf\x8E"),
            ],
        ),
        T0,
    );
    s.feed(&server(TASK, bare, 0, &[]), T0);
    let user = |uid, icon, status, name: &str, color| User {
        uid,
        icon,
        status,
        name: name.into(),
        color,
    };
    let (ann, rene) = (
        user(5, 1, Some(2), "ann", None),
        user(6, 9, Some(0), "René", Some(0x112233)),
    );
    assert_eq!(
        events(&mut s),
        [
            Event::UserList {
                trans: list,
                users: vec![ann.clone()],
                subject: None,
            },
            Event::ChatCreated {
                trans: create,
                cid: 9,
                user: user(6, 9, None, "René", None),
            },
            Event::ChatJoined {
                trans: join,
                cid: 9,
                users: vec![ann, rene],
                subject: Some("Café".into()),
            },
            Event::ChatJoined {
                trans: bare,
                cid: 4,
                users: vec![],
                subject: None,
            },
        ]
    );
}

#[test]
fn a_name_or_subject_ends_at_its_first_nul_before_it_is_decoded() {
    // What follows the NUL is not UTF-8; read whole, the name would be
    // taken for Mac Roman.
    let name = &b"Ren\xC3\xA9\0\xFF"[..];
    let mut s = raw_ready(Handled::CHAT | Handled::USERS, 0);
    let [list, join] = [(); 2].map(|_| s.take_trans());
    s.expect(list, Expect::UserList).unwrap();
    s.expect(join, Expect::ChatJoin { cid: 9 }).unwrap();
    for (opcode, t) in [(300, list), (115, join)] {
        s.send_raw(&caller(opcode, t)).unwrap();
    }
    let record = [&[0, 5, 0, 1, 0, 0, 0, name.len() as u8][..], name].concat();
    let cid = &[0, 0, 0, 9][..];
    let pushes = [
        server(0x71, 0, 0, &[(tag::CHAT_ID, cid), (tag::NAME, name)]),
        server(
            0x77,
            0,
            0,
            &[(tag::CHAT_ID, cid), (tag::CHAT_SUBJECT, name)],
        ),
        server(0x12d, 0, 0, &[(tag::UID, &[0, 5]), (tag::NAME, name)]),
        server(
            TASK,
            list,
            0,
            &[(tag::USER_LIST, &record), (tag::CHAT_SUBJECT, name)],
        ),
        server(TASK, join, 0, &[(tag::CHAT_SUBJECT, name)]),
    ];
    for p in &pushes {
        s.feed(p, T0);
    }
    let rene = User {
        uid: 5,
        icon: 1,
        status: Some(0),
        name: "René".into(),
        color: None,
    };
    assert_eq!(
        events(&mut s),
        [
            Event::ChatInvite {
                cid: 9,
                uid: 0,
                name: "René".into()
            },
            Event::ChatSubject {
                cid: 9,
                subject: "René".into()
            },
            Event::UserChanged {
                cid: 0,
                user: User {
                    icon: 0,
                    status: None,
                    ..rene.clone()
                }
            },
            Event::UserList {
                trans: list,
                users: vec![rene],
                subject: Some("René".into()),
            },
            Event::ChatJoined {
                trans: join,
                cid: 9,
                users: vec![],
                subject: Some("René".into()),
            },
        ]
    );
}

#[test]
fn a_joined_chat_s_subject_is_cut_to_255_bytes_before_it_is_decoded() {
    let mut s = raw_ready(Handled::USERS, 0);
    let join = s.take_trans();
    s.expect(join, Expect::ChatJoin { cid: 9 }).unwrap();
    s.send_raw(&caller(115, join)).unwrap();
    // The cut falls inside the é, which leaves a byte that is not UTF-8:
    // the subject reads as Mac Roman, where 0xC3 is √.
    let subject = ["a".repeat(254), "é".into()].concat();
    s.feed(
        &server(TASK, join, 0, &[(tag::CHAT_SUBJECT, subject.as_bytes())]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [Event::ChatJoined {
            trans: join,
            cid: 9,
            users: vec![],
            subject: Some(["a".repeat(254), "√".into()].concat()),
        }]
    );
}

/// A reply to `trans` that never finishes: its first part, then the same
/// trans starting over with a different size.
fn cut_short(trans: u32) -> Vec<u8> {
    let frag = |total: u32| {
        let head = [TASK, trans, 0, total, 10].map(u32::to_be_bytes).concat();
        [head, vec![0; 10]].concat()
    };
    [frag(40), frag(41)].concat()
}

#[test]
fn a_cut_short_reply_to_the_keep_alive_is_no_news() {
    let mut s = ready();
    s.tick(T0 + 60_000);
    let ping = sent(&mut s);
    assert_eq!(ping[0].0, 500);
    s.feed(&cut_short(ping[0].1), T0 + 60_000);
    assert_eq!(events(&mut s), []);
}

/// The session's own agree, cut short, has no whole frame to hand a raw
/// caller, and a failure on a trans the caller never sent is nothing it
/// could act on: it hears nothing, as it hears nothing of an agree that
/// works until its frame arrives.
#[test]
fn a_raw_caller_hears_nothing_of_the_sessions_own_reply_cut_short() {
    let mut s = logging_in(raw());
    s.feed(&login_reply(Some(190), None), T0);
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), T0);
    let agree = sent(&mut s);
    assert_eq!(agree[0].0, 121);
    events(&mut s);
    s.feed(&cut_short(agree[0].1), T0);
    assert_eq!(events(&mut s), []);
}

#[test]
fn only_a_raw_caller_expects_and_only_on_its_own_trans() {
    let mut s = ready();
    assert_eq!(s.expect(99, Expect::ChatInvite), Err(Error::NotReady));

    let mut s = logging_in(raw());
    s.feed(&login_reply(Some(190), None), T0);
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), T0);
    let agree = sent(&mut s)[0].1;
    events(&mut s);
    assert_eq!(s.expect(agree, Expect::ChatInvite), Err(Error::InUse));
    // Still the session's: its refusal reaches the caller whole.
    let refusal = server(TASK, agree, 1, &[(tag::TASK_ERROR, b"No.")]);
    s.feed(&refusal, T0);
    assert_eq!(
        events(&mut s),
        [Event::Reply {
            trans: agree,
            frame: refusal
        }]
    );
    let mine = s.take_trans();
    assert_eq!(s.expect(mine, Expect::ChatInvite), Ok(()));
    assert_eq!(s.expect(mine, Expect::ChatInvite), Err(Error::InUse));
}

#[test]
fn an_expected_reply_that_fails_says_why() {
    let mut s = raw_ready(Handled::CHAT, 0);
    let (refused, cut) = (s.take_trans(), s.take_trans());
    s.expect(refused, Expect::ChatInvite).unwrap();
    s.expect(cut, Expect::ChatHistory { cid: 0 }).unwrap();
    s.feed(
        &server(TASK, refused, 1, &[(tag::TASK_ERROR, b"Not here.")]),
        T0,
    );
    s.feed(&cut_short(cut), T0);
    assert_eq!(
        events(&mut s),
        [
            Event::Failed {
                trans: refused,
                reason: Some("Not here.".into())
            },
            Event::Failed {
                trans: cut,
                reason: Some("the server's reply was cut short".into())
            },
        ]
    );
}

#[test]
fn a_tap_hands_over_each_transaction_before_what_it_sets_off() {
    let mut s = raw_ready(Handled::CHAT, 0);
    s.set_tap(true);
    let chat = server(0x6a, 0, 0, &[(tag::BODY, b"hi")]);
    let user = server(0x12d, 0, 0, &[]);
    s.feed(&[chat.clone(), user.clone()].concat(), T0);
    let ev = events(&mut s);
    assert_eq!(ev[0], Event::Received(chat));
    assert!(matches!(ev[1], Event::Chat { .. }));
    assert_eq!(ev[2], Event::Received(user.clone()));
    assert_eq!(
        ev[3],
        Event::Unhandled {
            opcode: 0x12d,
            frame: user
        }
    );
    assert_eq!(ev.len(), 4);
}

#[test]
fn history_needs_the_server_to_have_agreed() {
    let mut s = ready();
    assert_eq!(s.chat_history(0, 0, 0, 50), Err(Error::NotAgreed));
    assert_eq!(sent(&mut s), []);
}

#[test]
fn chat_requests_go_as_gtkhx_sends_them() {
    let mut s = logging_in(Config {
        caps: cap::TEXT_ENCODING | cap::CHAT_HISTORY,
        ..Config::guest("me")
    });
    s.feed(
        &login_reply(Some(190), Some(cap::TEXT_ENCODING | cap::CHAT_HISTORY)),
        T0,
    );
    s.feed(&server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[1])]), T0);
    sent(&mut s);
    events(&mut s);
    let cid = (tag::CHAT_ID, vec![0, 0, 0, 9]);
    let want: Vec<Sent> = vec![
        (112, s.chat_create(5).unwrap(), vec![(tag::UID, vec![0, 5])]),
        (
            113,
            s.chat_invite(9, 5).unwrap(),
            vec![cid.clone(), (tag::UID, vec![0, 5])],
        ),
        (114, s.chat_decline(9).unwrap(), vec![cid.clone()]),
        (115, s.chat_join(9).unwrap(), vec![cid.clone()]),
        (116, s.chat_part(9).unwrap(), vec![cid.clone()]),
        (
            120,
            s.chat_subject(9, "café").unwrap(),
            vec![cid, (tag::CHAT_SUBJECT, "café".as_bytes().to_vec())],
        ),
        (
            700,
            s.chat_history(0, 0, 0, 50).unwrap(),
            vec![
                (tag::CHANNEL_ID, vec![0, 0, 0, 0]),
                (tag::HISTORY_LIMIT, vec![0, 50]),
            ],
        ),
    ];
    assert_eq!(sent(&mut s), want);

    // The history's reply is read; the invite's says nothing unless refused.
    let (invite, history) = (want[1].1, want[6].1);
    s.feed(&server(TASK, invite, 0, &[]), T0);
    s.feed(
        &server(TASK, history, 0, &[(tag::HISTORY_HAS_MORE, &[0])]),
        T0,
    );
    assert_eq!(
        events(&mut s),
        [Event::ChatHistory {
            trans: history,
            cid: 0,
            entries: vec![],
            has_more: false
        }]
    );
}

// ---- HOPE ----------------------------------------------------------------

#[cfg(feature = "hope")]
mod hope {
    use super::*;

    use hxhope::server::Policy;
    use hxhope::{Cipher, Compression, Mac, Transport};

    /// Marks about one transaction in five, either way.
    fn random() -> hxhope::Random {
        let mut i = 0usize;
        Box::new(move |buf: &mut [u8]| {
            for b in buf {
                *b = [0x20, 0x0c, 0, 0x10, 0, 0, 0x70, 0, 0x30][i % 9];
                i += 1;
            }
        })
    }

    fn offer(cipher: Option<Cipher>, compression: Option<Compression>) -> hxhope::client::Offer {
        hxhope::client::Offer {
            ciphers: cipher.into_iter().collect(),
            compressions: compression.into_iter().collect(),
            ..hxhope::client::Offer::new(*b"TEST")
        }
    }

    fn policy() -> Policy {
        Policy {
            macs: Mac::ALL.to_vec(),
            ciphers: vec![Cipher::Blowfish, Cipher::ChaCha20Poly1305],
            compressions: [Compression::Gzip, Compression::Lz4, Compression::Zstd]
                .into_iter()
                .filter(|c| c.available())
                .collect(),
            require_cipher: false,
        }
    }

    /// The far side of a HOPE login: hxhope's server, and once step 2 is in,
    /// its transport.
    struct HopeServer {
        reader: FrameReader,
        transport: Option<Transport>,
    }

    impl HopeServer {
        fn new() -> Self {
            HopeServer {
                reader: FrameReader::new(),
                transport: None,
            }
        }

        /// What the session sent since last asked, as transactions.
        fn hear(&mut self, s: &mut Session) -> Vec<Transaction> {
            let wire = s.take_outgoing();
            let wire = wire.strip_prefix(CLIENT_MAGIC.as_slice()).unwrap_or(&wire);
            let mut plain = Vec::new();
            match self.transport.as_mut() {
                Some(t) => t.decode(wire, &mut plain).unwrap(),
                None => plain.extend_from_slice(wire),
            }
            self.reader.push(&plain);
            std::iter::from_fn(|| self.reader.next_transaction().unwrap()).collect()
        }

        fn say(&mut self, s: &mut Session, plain: &[u8]) {
            let wire = match self.transport.as_mut() {
                Some(t) => t.encode(plain).unwrap(),
                None => plain.to_vec(),
            };
            s.feed(&wire, T0);
        }

        /// Answer the magic and step 1, take step 2 and accept it, and answer
        /// it as the login. Returns step 1's and step 2's trans.
        fn log_in(&mut self, s: &mut Session, policy: &Policy) -> (u32, u32) {
            s.feed(SERVER_MAGIC, T0);
            let step1 = self.hear(s).remove(0);
            let (hs, reply) =
                hxhope::server::answer(policy, &step1.buf, [7; 64], step1.trans).unwrap();
            self.say(s, &reply);
            let step2 = self.hear(s).remove(0);
            let fields = hs.step2(&step2.buf).unwrap();
            assert!(fields.names(&hs, b""), "the guest's login");
            let (t, _) = hs.accept(&fields, b"", random()).unwrap();
            self.transport = Some(t);
            self.say(s, &login_reply(Some(190), None));
            (step1.trans, step2.trans)
        }
    }

    #[test]
    fn hope_logs_in_and_chats_through_every_transport() {
        let mut compressions = vec![None, Some(Compression::Gzip), Some(Compression::Lz4)];
        if cfg!(feature = "zstd") {
            compressions.push(Some(Compression::Zstd));
        }
        for cipher in [None, Some(Cipher::Blowfish), Some(Cipher::ChaCha20Poly1305)] {
            for &compression in &compressions {
                let what = format!("{cipher:?} {compression:?}");
                let mut s = Session::with_hope(
                    Config::guest("me"),
                    offer(cipher, compression),
                    random(),
                    T0,
                );
                let mut srv = HopeServer::new();
                assert_eq!(srv.log_in(&mut s, &policy()), (1, 2), "{what}");
                let n = s.negotiated().expect("negotiated");
                assert_eq!((n.cipher, n.compression), (cipher, compression), "{what}");
                srv.say(&mut s, &server(0x6d, 0, 0, &[(tag::NOAGREEMENT, &[0, 1])]));
                let agree = srv.hear(&mut s);
                assert_eq!(
                    agree.iter().map(|t| (t.type_, t.trans)).collect::<Vec<_>>(),
                    [(121, 3), (300, 4)],
                    "{what}: the agree and the user list, numbered on from step 2"
                );
                for i in 0..20u8 {
                    srv.say(&mut s, &server(0x6a, 0, 0, &[(tag::BODY, &[b'a' + i; 40])]));
                    s.chat(&format!("line {i}")).unwrap();
                }
                let chats = events(&mut s)
                    .into_iter()
                    .filter(|e| matches!(e, Event::Chat { .. }))
                    .count();
                assert_eq!(chats, 20, "{what}");
                assert_eq!(srv.hear(&mut s).len(), 20, "{what}");
                assert!(!s.mid_transaction() && !s.is_closed(), "{what}");
            }
        }
    }

    /// Step 2 goes out as it is, ahead of the transport; a trace of what is
    /// about to go out sees it.
    #[test]
    fn step_2_is_in_what_is_about_to_go_out() {
        let mut s = Session::with_hope(
            Config::guest("me"),
            offer(Some(Cipher::Blowfish), None),
            random(),
            T0,
        );
        s.take_outgoing();
        s.feed(SERVER_MAGIC, T0);
        let step1 = s.take_outgoing();
        let (_, reply) = hxhope::server::answer(&policy(), &step1, [7; 64], 1).unwrap();
        s.feed(&reply, T0);
        let pending = s.pending_plaintext();
        assert_eq!(pending, s.take_outgoing(), "step 2 is plaintext");
        assert_eq!(u32::from_be_bytes(pending[4..8].try_into().unwrap()), 2);
    }

    #[test]
    fn a_hope_session_and_its_raw_caller_number_from_one_counter() {
        let mut s = Session::with_hope(raw(), offer(Some(Cipher::Blowfish), None), random(), T0);
        assert_eq!(s.login_trans(), 2);
        let early = s.take_trans();
        assert_eq!(early, 3, "numbered past both steps before either goes");
        let mut srv = HopeServer::new();
        srv.log_in(&mut s, &policy());
        let replies: Vec<u32> = events(&mut s)
            .into_iter()
            .filter_map(|e| match e {
                Event::Reply { trans, .. } => Some(trans),
                _ => None,
            })
            .collect();
        assert_eq!(
            replies,
            [1],
            "step 2's reply is the login's; step 1's is not handed over"
        );
        s.send_raw(&caller(300, early)).unwrap();
        let trans: Vec<u32> = srv.hear(&mut s).iter().map(|t| t.trans).collect();
        assert_eq!(trans, [early]);
    }

    #[test]
    fn a_tap_under_hope_hands_over_plaintext() {
        let mut s = Session::with_hope(
            Config::guest("me"),
            offer(Some(Cipher::ChaCha20Poly1305), Some(Compression::Gzip)),
            random(),
            T0,
        );
        s.set_tap(true);
        let mut srv = HopeServer::new();
        srv.log_in(&mut s, &policy());
        events(&mut s);
        let chat = server(0x6a, 0, 0, &[(tag::BODY, b"hi")]);
        srv.say(&mut s, &chat);
        assert_eq!(events(&mut s)[0], Event::Received(chat));
    }

    #[test]
    fn a_hope_login_the_server_will_not_have_closes() {
        // Refused at step 1, with the reason.
        let mut s = Session::with_hope(Config::guest("me"), offer(None, None), random(), T0);
        s.take_outgoing();
        s.feed(SERVER_MAGIC, T0);
        s.take_outgoing();
        s.feed(
            &server(TASK, 1, 1, &[(tag::TASK_ERROR, b"No HOPE here.")]),
            T0,
        );
        assert_eq!(
            events(&mut s),
            [Event::Closed(Closed::LoginRefused(Some(
                "No HOPE here.".into()
            )))]
        );

        // Answered as a plain login: no session key, so no HOPE.
        let mut s = Session::with_hope(Config::guest("me"), offer(None, None), random(), T0);
        s.take_outgoing();
        s.feed(SERVER_MAGIC, T0);
        s.take_outgoing();
        s.feed(&login_reply(Some(190), None), T0);
        assert!(matches!(
            &events(&mut s)[..],
            [Event::Closed(Closed::Protocol(_))]
        ));
    }

    #[test]
    fn a_hope_transport_that_stops_making_sense_closes() {
        let mut s = Session::with_hope(
            Config::guest("me"),
            offer(Some(Cipher::ChaCha20Poly1305), None),
            random(),
            T0,
        );
        let mut srv = HopeServer::new();
        srv.log_in(&mut s, &policy());
        events(&mut s);
        let mut record = srv
            .transport
            .as_mut()
            .unwrap()
            .encode(&server(0x6a, 0, 0, &[]))
            .unwrap();
        record[10] ^= 1;
        s.feed(&record, T0);
        assert!(matches!(
            &events(&mut s)[..],
            [Event::Closed(Closed::Protocol(_))]
        ));
    }
}
