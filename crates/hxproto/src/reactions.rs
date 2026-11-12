//! The Reactions draft (`Capabilities-Reactions.md`, capability bit 19,
//! not adopted): its numbers, the packed key, summary and reader's own
//! keys, the login reply's limits, and the groups of Reaction Changed
//! (711) and of Get Reactions' (712) reply. Field tags are in
//! [`tag`]; targets are [`crate::target`]'s, and the reason codes the
//! family shares [`crate::structured_chat`]'s.
//!
//! A 711 or a 712 reply is a list of groups, each opened by a
//! [`tag::TARGET`] and running to the next. A group that does not hold
//! together, or names a target or an action this crate does not read, is
//! skipped and the rest are read.

use crate::messages::tag;
use crate::target::Target;
use crate::wire::{Chunk, ChunkIter};

/// Send Reaction: add, remove or clear.
pub const SEND: u32 = 710;
/// Reaction Changed, the server's push.
pub const CHANGED: u32 = 711;
/// Get Reactions: summaries, and who reacted.
pub const GET: u32 = 712;

/// Most bytes of UTF-8 in an emoji key.
pub const MAX_KEY_BYTES: usize = 64;

/// A Get Chat History (700) entry's sub-field: the line's summary.
pub const SUBFIELD_REACTIONS: u16 = 0x0021;
/// A Get Chat History (700) entry's sub-field: the reader's own keys.
pub const SUBFIELD_REACTIONS_MINE: u16 = 0x0023;

// [`tag::REACTION_ACTION`]'s values: 3 is a moderator's clear in a
// request and a cleared target in a 711.
pub const ADD: u16 = 1;
pub const REMOVE: u16 = 2;
pub const CLEAR: u16 = 3;
pub const SUMMARY: u16 = 4;

// The draft's reason codes, beside the family's.
pub const INVALID_KEY: u16 = 3;
pub const TOO_MANY_KEYS: u16 = 4;
pub const TOO_MANY_OF_YOURS: u16 = 5;

// [`tag::REACTION_TARGETS`]' bits: `1 << kind`, and bit 6 for kind 5
// with its stored bit set.
pub const TARGETS_LINES: u16 = 1 << 1;
pub const TARGETS_IMS: u16 = 1 << 2;
pub const TARGETS_EPHEMERAL: u16 = 1 << 4;
/// Kind 5 with its reference's stored bit clear.
pub const TARGETS_UNSTORED_PMS: u16 = 1 << 5;
/// Kind 5 with its reference's stored bit set: bit 6, which is no kind.
pub const TARGETS_STORED_PMS: u16 = 1 << 6;

const EMOJI: u8 = 1;
const SERVER: u8 = 2;

/// What a reaction is made with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Key {
    /// One emoji, compared byte for byte; a sender sends it
    /// fully-qualified (`crate::emoji::qualify`).
    Emoji(String),
    /// One of the server's own emoji, by its id (the Server Emoji draft).
    Server(u32),
}

impl Key {
    /// The packed form, or `None` for an emoji of no bytes or of more
    /// than [`MAX_KEY_BYTES`]. That it is one grapheme is the sender's to
    /// check.
    pub fn pack(&self) -> Option<Vec<u8>> {
        match self {
            Key::Emoji(s) if (1..=MAX_KEY_BYTES).contains(&s.len()) => {
                Some([&[EMOJI][..], s.as_bytes()].concat())
            }
            Key::Emoji(_) => None,
            Key::Server(id) => Some([&[SERVER][..], &id.to_be_bytes()].concat()),
        }
    }

    pub fn parse(b: &[u8]) -> Option<Self> {
        match b.split_first()? {
            (&EMOJI, s) if (1..=MAX_KEY_BYTES).contains(&s.len()) => {
                Some(Key::Emoji(std::str::from_utf8(s).ok()?.to_owned()))
            }
            (&SERVER, id) => Some(Key::Server(u32::from_be_bytes(id.try_into().ok()?))),
            _ => None,
        }
    }
}

/// A target's reactions, the same for every reader: each key and its
/// count, in the order the keys were first added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub entries: Vec<(Key, u32)>,
}

impl Summary {
    /// `None` for one that runs past its bytes or short of them, or holds
    /// a key that does not parse: it is read whole or not at all, since
    /// part of one would show the wrong counts.
    pub fn parse(b: &[u8]) -> Option<Self> {
        let (n, mut rest) = b.split_first_chunk::<2>()?;
        let n = u16::from_be_bytes(*n);
        let mut entries = Vec::with_capacity(usize::from(n).min(rest.len() / 6));
        for _ in 0..n {
            let (count, after) = rest.split_first_chunk::<4>()?;
            let (len, after) = after.split_first_chunk::<2>()?;
            let len = usize::from(u16::from_be_bytes(*len));
            let key = Key::parse(after.get(..len)?)?;
            entries.push((key, u32::from_be_bytes(*count)));
            rest = &after[len..];
        }
        rest.is_empty().then_some(Summary { entries })
    }
}

/// The keys the reader's account holds on a target, as indexes into its
/// [`Summary`]'s entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mine(pub Vec<u8>);

impl Mine {
    pub fn parse(b: &[u8]) -> Option<Self> {
        let (&n, indexes) = b.split_first()?;
        (indexes.len() == usize::from(n)).then(|| Mine(indexes.to_vec()))
    }

    /// Does the reader hold the summary's entry `index`?
    pub fn holds(&self, index: usize) -> bool {
        self.0.iter().any(|&i| usize::from(i) == index)
    }
}

/// What a login reply says beside a confirmed bit 19.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The `TARGETS_*` bits.
    pub targets: u16,
    pub max_keys: Option<u32>,
    pub max_per_user: Option<u32>,
}

/// A UInt16 or UInt32 field, at either width a Hotline integer is sent
/// as.
pub(crate) fn uint(c: &Chunk<'_>) -> Option<u32> {
    matches!(c.data.len(), 2 | 4).then(|| c.as_uint())
}

impl Limits {
    /// Pick the limits out of a login reply (`buf`, with `len` valid
    /// bytes, header included). `None` without [`tag::REACTION_TARGETS`],
    /// which the draft requires: a server that leaves it out says nothing
    /// a client can react to.
    pub fn extract(buf: &[u8], len: usize) -> Option<Limits> {
        let (mut targets, mut max_keys, mut max_per_user) = (None, None, None);
        for c in ChunkIter::over_message(buf, len) {
            let slot = match c.tag {
                tag::REACTION_TARGETS => {
                    targets = uint(&c).and_then(|v| u16::try_from(v).ok()).or(targets);
                    continue;
                }
                tag::MAX_REACTION_KEYS => &mut max_keys,
                tag::MAX_REACTIONS_PER_USER => &mut max_per_user,
                _ => continue,
            };
            *slot = uint(&c).or(*slot);
        }
        Some(Limits {
            targets: targets?,
            max_keys,
            max_per_user,
        })
    }

    /// Does the server take reactions on `target`'s kind?
    pub fn takes(&self, target: &Target) -> bool {
        let bit = match target {
            Target::Line { .. } => TARGETS_LINES,
            Target::Im { .. } => TARGETS_IMS,
            Target::Ephemeral { .. } => TARGETS_EPHEMERAL,
            Target::Pm { stored: false, .. } => TARGETS_UNSTORED_PMS,
            Target::Pm { stored: true, .. } => TARGETS_STORED_PMS,
        };
        self.targets & bit != 0
    }
}

/// One group of a Reaction Changed (711).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Group {
    /// The target's reactions now: a line's or a stored message's.
    Summary {
        target: Target,
        summary: Summary,
        mine: Mine,
    },
    /// Every reaction on a line taken by a moderator.
    Cleared { target: Target },
    /// One key added or taken away: an instant message's, whose reactor
    /// `from` names by Login, or an unstored message's.
    Change {
        target: Target,
        add: bool,
        key: Key,
        from: Option<Vec<u8>>,
    },
}

/// One group of Get Reactions' (712) reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Got {
    pub target: Target,
    pub summary: Summary,
    pub mine: Mine,
    /// Who holds the key asked for, newest first, each by the nick they
    /// reacted under, as the wire has it.
    pub nicks: Vec<Vec<u8>>,
}

/// Each group's target, as sent, and its fields.
fn groups<'a>(fields: impl IntoIterator<Item = Chunk<'a>>) -> Vec<(&'a [u8], Vec<Chunk<'a>>)> {
    let mut out: Vec<(&[u8], Vec<Chunk>)> = Vec::new();
    for c in fields {
        match (c.tag, out.last_mut()) {
            (tag::TARGET, _) => out.push((c.data, Vec::new())),
            (_, Some((_, group))) => group.push(c),
            (_, None) => {}
        }
    }
    out
}

fn field<'a>(group: &[Chunk<'a>], t: u16) -> Option<&'a [u8]> {
    group.iter().find(|c| c.tag == t).map(|c| c.data)
}

/// A summary and the reader's keys on it, each where it was sent: in a
/// group, or in a Get Chat History entry's sub-fields. An absent mine is
/// none of the reader's; one that does not parse loses the summary too,
/// and an index past the summary's entries names nothing.
pub fn parse_summary_and_mine(summary: &[u8], mine: Option<&[u8]>) -> Option<(Summary, Mine)> {
    let mut mine = match mine {
        Some(b) => Mine::parse(b)?,
        None => Mine::default(),
    };
    let summary = Summary::parse(summary)?;
    mine.0.retain(|&i| usize::from(i) < summary.entries.len());
    Some((summary, mine))
}

fn summary_and_mine(group: &[Chunk<'_>]) -> Option<(Summary, Mine)> {
    parse_summary_and_mine(
        field(group, tag::REACTION_SUMMARY)?,
        field(group, tag::REACTION_MINE),
    )
}

/// A Reaction Changed's groups, in the order sent, from its fields
/// (`ChunkIter::over_message` over the frame).
pub fn parse_changed<'a>(fields: impl IntoIterator<Item = Chunk<'a>>) -> Vec<Group> {
    groups(fields)
        .into_iter()
        .filter_map(|(target, group)| {
            let target = Target::parse(target)?;
            let action = group
                .iter()
                .find(|c| c.tag == tag::REACTION_ACTION)
                .and_then(uint)?;
            match u16::try_from(action).ok()? {
                SUMMARY => {
                    let (summary, mine) = summary_and_mine(&group)?;
                    Some(Group::Summary {
                        target,
                        summary,
                        mine,
                    })
                }
                CLEAR => Some(Group::Cleared { target }),
                a @ (ADD | REMOVE) => Some(Group::Change {
                    target,
                    add: a == ADD,
                    key: Key::parse(field(&group, tag::REACTION_KEY)?)?,
                    from: field(&group, tag::FRIEND_LOGIN).map(<[u8]>::to_vec),
                }),
                _ => None,
            }
        })
        .collect()
}

/// Get Reactions' reply's groups, in the order sent, from its fields.
pub fn parse_got<'a>(fields: impl IntoIterator<Item = Chunk<'a>>) -> Vec<Got> {
    groups(fields)
        .into_iter()
        .filter_map(|(target, group)| {
            let target = Target::parse(target)?;
            let (summary, mine) = summary_and_mine(&group)?;
            let nicks = group
                .iter()
                .filter(|c| c.tag == tag::NAME)
                .map(|c| c.data.to_vec())
                .collect();
            Some(Got {
                target,
                summary,
                mine,
                nicks,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const THUMBS: &str = "\u{1F44D}";

    fn thumbs() -> Key {
        Key::Emoji(THUMBS.into())
    }

    /// A summary of a thumbs up three times and server emoji 0x01020304
    /// once, as the draft lays it out.
    fn two_keys() -> Vec<u8> {
        [
            &[0, 2][..],
            &[0, 0, 0, 3],
            &[0, 5],
            &[1, 0xf0, 0x9f, 0x91, 0x8d],
            &[0, 0, 0, 1],
            &[0, 5],
            &[2, 1, 2, 3, 4],
        ]
        .concat()
    }

    fn two() -> Summary {
        Summary {
            entries: vec![(thumbs(), 3), (Key::Server(0x0102_0304), 1)],
        }
    }

    fn lobby(id: u64) -> Vec<u8> {
        Target::Line { channel: 0, id }.pack().unwrap()
    }

    fn chunk(tag: u16, data: &[u8]) -> Chunk<'_> {
        Chunk { tag, data }
    }

    #[test]
    fn keys_pack_as_the_draft_lays_them_out_and_read_back() {
        let longest = THUMBS.repeat(16);
        for (key, bytes) in [
            (thumbs(), vec![1, 0xf0, 0x9f, 0x91, 0x8d]),
            (
                Key::Emoji(longest.clone()),
                [&[1][..], longest.as_bytes()].concat(),
            ),
            (Key::Server(0x0102_0304), vec![2, 1, 2, 3, 4]),
        ] {
            assert_eq!(key.pack().as_deref(), Some(&bytes[..]), "{key:?}");
            assert_eq!(Key::parse(&bytes), Some(key));
        }
    }

    #[test]
    fn keys_outside_the_layout_are_neither_packed_nor_read() {
        let past = "a".repeat(MAX_KEY_BYTES + 1);
        assert_eq!(Key::Emoji(String::new()).pack(), None);
        assert_eq!(Key::Emoji(past.clone()).pack(), None);
        for (case, bytes) in [
            ("no kind", vec![]),
            ("an empty emoji", vec![1]),
            (
                "an emoji past the bound",
                [&[1][..], past.as_bytes()].concat(),
            ),
            ("not UTF-8", vec![1, 0xff]),
            ("a server's cut short", vec![2, 1, 2, 3]),
            ("a server's run long", vec![2, 1, 2, 3, 4, 5]),
            ("an unknown kind", vec![3, b'a']),
        ] {
            assert_eq!(Key::parse(&bytes), None, "{case}");
        }
    }

    #[test]
    fn a_summary_and_mine_read_as_the_draft_lays_them_out() {
        assert_eq!(Summary::parse(&two_keys()), Some(two()));
        assert_eq!(Summary::parse(&[0, 0]), Some(Summary::default()));
        assert_eq!(Mine::parse(&[2, 0, 1]), Some(Mine(vec![0, 1])));
        assert_eq!(Mine::parse(&[0]), Some(Mine::default()));
    }

    #[test]
    fn a_summary_or_mine_that_does_not_hold_together_is_not_read() {
        let whole = two_keys();
        let bad_key = [&[0, 1, 0, 0, 0, 1, 0, 1][..], &[1]].concat();
        for (case, bytes) in [
            ("empty", vec![]),
            ("a count cut short", vec![0]),
            ("an entry past the bytes", whole[..whole.len() - 1].to_vec()),
            (
                "more entries than said",
                [&[0, 1][..], &whole[2..]].concat(),
            ),
            ("an entry cut in its header", vec![0, 1, 0, 0, 0, 1, 0]),
            ("a key that does not parse", bad_key),
        ] {
            assert_eq!(Summary::parse(&bytes), None, "{case}");
        }
        for (case, bytes) in [
            ("empty", &[][..]),
            ("cut short", &[2, 0]),
            ("run long", &[1, 0, 1]),
        ] {
            assert_eq!(Mine::parse(bytes), None, "mine {case}");
        }
    }

    #[test]
    fn mine_names_only_the_summarys_entries() {
        assert_eq!(
            parse_summary_and_mine(&two_keys(), Some(&[3, 1, 9, 2])),
            Some((two(), Mine(vec![1])))
        );
    }

    fn login_reply(fields: &[(u16, &[u8])]) -> Vec<u8> {
        let mut buf = vec![0; crate::HL_HDR_LEN];
        for (t, d) in fields {
            buf.extend_from_slice(&t.to_be_bytes());
            buf.extend_from_slice(&(d.len() as u16).to_be_bytes());
            buf.extend_from_slice(d);
        }
        buf
    }

    #[test]
    fn the_login_replys_limits_are_read_and_need_the_targets() {
        let targets: (u16, &[u8]) = (tag::REACTION_TARGETS, &[0, 0x52]);
        let keys: (u16, &[u8]) = (tag::MAX_REACTION_KEYS, &[0, 0, 0, 20]);
        let per_user: (u16, &[u8]) = (tag::MAX_REACTIONS_PER_USER, &[0, 5]);
        let limits = |max_keys, max_per_user| {
            Some(Limits {
                targets: 0x52,
                max_keys,
                max_per_user,
            })
        };
        for (case, fields, want) in [
            (
                "all three",
                vec![targets, keys, per_user],
                limits(Some(20), Some(5)),
            ),
            ("the targets alone", vec![targets], limits(None, None)),
            (
                "the targets in four bytes",
                vec![(tag::REACTION_TARGETS, &[0, 0, 0, 0x52][..])],
                limits(None, None),
            ),
            (
                "a limit of a width no integer has",
                vec![targets, (tag::MAX_REACTION_KEYS, &[0, 0, 20][..])],
                limits(None, None),
            ),
            ("no targets", vec![keys, per_user], None),
            (
                "targets of a width no integer has",
                vec![(tag::REACTION_TARGETS, &[0x52][..])],
                None,
            ),
            (
                "targets past a UInt16",
                vec![(tag::REACTION_TARGETS, &[0, 1, 0, 0x52][..])],
                None,
            ),
        ] {
            let buf = login_reply(&fields);
            assert_eq!(Limits::extract(&buf, buf.len()), want, "{case}");
        }
    }

    #[test]
    fn a_kind_is_taken_where_its_bit_is_set() {
        let pm = |stored| Target::Pm {
            stored,
            reference: [3; 16],
        };
        for (target, bit) in [
            (Target::Line { channel: 0, id: 1 }, TARGETS_LINES),
            (
                Target::Im {
                    guid: [7; 16],
                    sender: b"bob".to_vec(),
                },
                TARGETS_IMS,
            ),
            (Target::Ephemeral { chat: 5, id: 1 }, TARGETS_EPHEMERAL),
            (pm(false), TARGETS_UNSTORED_PMS),
            (pm(true), TARGETS_STORED_PMS),
        ] {
            let with = |targets| Limits {
                targets,
                max_keys: None,
                max_per_user: None,
            };
            assert!(with(bit).takes(&target), "{target:?}");
            assert!(!with(!bit).takes(&target), "{target:?} without its bit");
        }
    }

    #[test]
    fn a_711s_groups_are_read_in_order_and_one_that_does_not_parse_is_skipped() {
        let summary = two_keys();
        let action = |a: u16| a.to_be_bytes();
        let (sum, clear, add, remove, five) = (
            action(SUMMARY),
            action(CLEAR),
            action(ADD),
            action(REMOVE),
            action(5),
        );
        let im = Target::Im {
            guid: [7; 16],
            sender: b"amy".to_vec(),
        };
        let im_bytes = im.pack().unwrap();
        let key = thumbs().pack().unwrap();
        let signed = [&[3][..], &[0; 80]].concat();
        let l: Vec<_> = (0..8).map(lobby).collect();
        let fields = [
            // Before the first target: the reply's own, never a group's.
            chunk(tag::CHAT_REASON, &[0, 0]),
            chunk(tag::TARGET, &l[1]),
            chunk(tag::REACTION_ACTION, &sum),
            chunk(tag::REACTION_SUMMARY, &summary),
            chunk(tag::REACTION_MINE, &[2, 1, 9]),
            chunk(tag::TARGET, &l[2]),
            chunk(tag::REACTION_ACTION, &sum),
            chunk(tag::REACTION_SUMMARY, &[0, 0]),
            chunk(tag::TARGET, &l[3]),
            chunk(tag::REACTION_ACTION, &clear),
            chunk(tag::TARGET, &signed),
            chunk(tag::REACTION_ACTION, &clear),
            chunk(tag::TARGET, &l[4]),
            chunk(tag::REACTION_ACTION, &five),
            chunk(tag::TARGET, &l[5]),
            chunk(tag::REACTION_ACTION, &sum),
            chunk(tag::REACTION_SUMMARY, &summary[..summary.len() - 1]),
            chunk(tag::TARGET, &l[6]),
            chunk(tag::REACTION_ACTION, &sum),
            chunk(tag::REACTION_SUMMARY, &summary),
            chunk(tag::REACTION_MINE, &[2, 0]),
            chunk(tag::TARGET, &im_bytes),
            chunk(tag::REACTION_ACTION, &add),
            chunk(tag::REACTION_KEY, &key),
            chunk(tag::FRIEND_LOGIN, b"bob"),
            chunk(tag::TARGET, &im_bytes),
            chunk(tag::REACTION_ACTION, &remove),
            chunk(tag::REACTION_KEY, &[1]),
            chunk(tag::FRIEND_LOGIN, b"bob"),
            chunk(tag::TARGET, &l[7]),
            chunk(tag::REACTION_SUMMARY, &summary),
            chunk(tag::TARGET, &im_bytes),
            chunk(tag::REACTION_ACTION, &remove),
            chunk(tag::REACTION_KEY, &key),
            chunk(tag::FRIEND_LOGIN, b"bob"),
        ];
        let line = |id| Target::Line { channel: 0, id };
        let change = |add| Group::Change {
            target: im.clone(),
            add,
            key: thumbs(),
            from: Some(b"bob".to_vec()),
        };
        let want = vec![
            Group::Summary {
                target: line(1),
                summary: two(),
                mine: Mine(vec![1]),
            },
            Group::Summary {
                target: line(2),
                summary: Summary::default(),
                mine: Mine::default(),
            },
            Group::Cleared { target: line(3) },
            change(true),
            change(false),
        ];
        assert_eq!(parse_changed(fields.iter().copied()), want);
        // A server splits a batch between groups, never inside one, so
        // each frame reads alone.
        let at = 12;
        assert_eq!(fields[at].tag, tag::TARGET);
        let split = [
            parse_changed(fields[..at].iter().copied()),
            parse_changed(fields[at..].iter().copied()),
        ]
        .concat();
        assert_eq!(split, want);
    }

    #[test]
    fn a_712_replys_groups_carry_who_reacted() {
        let summary = two_keys();
        let l: Vec<_> = (0..5).map(lobby).collect();
        let fields = [
            chunk(tag::TARGET, &l[1]),
            chunk(tag::REACTION_SUMMARY, &summary),
            chunk(tag::REACTION_MINE, &[1, 0]),
            chunk(tag::NAME, b"amy"),
            chunk(tag::NAME, b"bob"),
            chunk(tag::TARGET, &l[2]),
            chunk(tag::REACTION_SUMMARY, &[0, 0]),
            chunk(tag::TARGET, &[9]),
            chunk(tag::REACTION_SUMMARY, &[0, 0]),
            chunk(tag::TARGET, &l[3]),
            chunk(tag::NAME, b"cy"),
            chunk(tag::TARGET, &l[4]),
            chunk(tag::REACTION_SUMMARY, &summary),
            chunk(tag::REACTION_MINE, &[1]),
        ];
        let line = |id| Target::Line { channel: 0, id };
        assert_eq!(
            parse_got(fields.iter().copied()),
            [
                Got {
                    target: line(1),
                    summary: two(),
                    mine: Mine(vec![0]),
                    nicks: vec![b"amy".to_vec(), b"bob".to_vec()],
                },
                Got {
                    target: line(2),
                    summary: Summary::default(),
                    mine: Mine::default(),
                    nicks: vec![],
                },
            ]
        );
    }
}
