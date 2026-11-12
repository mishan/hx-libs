//! The Replies draft (`Capabilities-Replies.md`, capability bit 18, not
//! adopted): its numbers and the login reply's target kinds. A reply's
//! target is [`crate::target`]'s, in [`tag::REPLY_TO`]; field tags are in
//! [`tag`], and the by-id Get Chat History request is
//! [`crate::build::build_get_chat_history_ids_chunks`].

use crate::messages::tag;
use crate::target::Target;
use crate::wire::ChunkIter;

/// Set Notifications: the notification types a session wants.
pub const SET_NOTIFICATIONS: u32 = 717;
/// Notification, the server's push to a line's author.
pub const NOTIFICATION: u32 = 718;

/// A Get Chat History (700) entry's sub-field, and a live line's: the
/// packed target the line answers.
pub const SUBFIELD_REPLY_TO: u16 = 0x0020;

/// Most [`tag::LINE_ID`]s one Get Chat History request may name.
pub const MAX_IDS: usize = 50;

/// [`tag::REPLY_TARGETS`]: the target kinds a server keeps in
/// [`tag::REPLY_TO`], as `1 << kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Targets(pub u16);

impl Targets {
    /// Pick the kinds out of a login reply (`buf`, with `len` valid bytes,
    /// header included). `None` without the field, which the draft
    /// requires beside bit 18: a server that leaves it out keeps no
    /// replies.
    pub fn extract(buf: &[u8], len: usize) -> Option<Targets> {
        ChunkIter::over_message(buf, len)
            .filter(|c| c.tag == tag::REPLY_TARGETS)
            .filter_map(|c| crate::reactions::uint(&c).and_then(|v| u16::try_from(v).ok()))
            .last()
            .map(Targets)
    }

    /// Does the server keep a reply to `target`'s kind? By kind alone: which
    /// private messages take one is the server's to say by dropping it.
    pub fn takes(&self, target: &Target) -> bool {
        self.0 & (1 << target.kind()) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::{pack_message, PackChunk};

    fn login_reply(fields: &[(u16, &[u8])]) -> Vec<u8> {
        let chunks: Vec<_> = fields
            .iter()
            .map(|&(tag, data)| PackChunk { tag, data })
            .collect();
        let mut out = vec![0u8; 1024];
        let n = pack_message(&mut out, 0x10000, 1, 0, &chunks).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn the_target_kinds_are_read_at_either_width_and_absent_without_the_field() {
        for (case, fields, want) in [
            ("absent", &[(tag::NOTIFY_TYPES, &[0, 1][..])][..], None),
            ("u16", &[(tag::REPLY_TARGETS, &[0, 0x12][..])], Some(0x12)),
            (
                "u32",
                &[(tag::REPLY_TARGETS, &[0, 0, 0, 0x32][..])],
                Some(0x32),
            ),
            ("past u16", &[(tag::REPLY_TARGETS, &[0, 1, 0, 0][..])], None),
            ("an odd width", &[(tag::REPLY_TARGETS, &[0x12][..])], None),
        ] {
            let b = login_reply(fields);
            assert_eq!(Targets::extract(&b, b.len()), want.map(Targets), "{case}");
        }
    }

    #[test]
    fn a_kind_is_taken_where_its_bit_is_set() {
        let line = Target::Line { channel: 0, id: 1 };
        let im = Target::Im {
            guid: [1; 16],
            sender: b"bob".to_vec(),
        };
        let ephemeral = Target::Ephemeral { chat: 7, id: 1 };
        let pm = |stored| Target::Pm {
            stored,
            reference: [2; 16],
        };
        for (bits, target, want) in [
            (1 << 1, &line, true),
            (!(1 << 1), &line, false),
            (1 << 2, &im, true),
            (!(1 << 2), &im, false),
            (1 << 4, &ephemeral, true),
            (!(1 << 4), &ephemeral, false),
            (1 << 5, &pm(true), true),
            (1 << 5, &pm(false), true),
            (!(1 << 5), &pm(true), false),
        ] {
            assert_eq!(Targets(bits).takes(target), want, "{bits:#x} {target:?}");
        }
    }
}
