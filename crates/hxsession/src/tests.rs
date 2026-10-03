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
        [Event::UserList(vec![
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
        ])]
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
                text: "    bob:  hi".into()
            },
            Event::Message {
                uid: 5,
                from: "bob".into(),
                text: "psst".into()
            },
            Event::Broadcast("Rebooting".into()),
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
        text: "café".into()
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
fn a_raw_session_and_its_caller_number_from_one_counter() {
    // As after HOPE's two steps, the login on 1 and the second on 2.
    let mut s = Session::logging_in(raw(), 3, T0);
    assert_eq!(s.take_trans(), 3);
    let mut reply = login_reply(Some(190), None);
    reply[4..8].copy_from_slice(&2u32.to_be_bytes());
    s.feed(&reply, T0);
    s.feed(&server(0x6d, 0, 0, &[(tag::BODY, b"Be nice.")]), T0);
    assert_eq!(s.take_trans(), 4);
    s.agree().unwrap();
    assert_eq!(s.take_trans(), 6);
    let trans: Vec<u32> = sent(&mut s).iter().map(|o| o.1).collect();
    assert_eq!(trans, [5]);
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
