//! The packed target of the Replies draft (`Capabilities-Replies.md`,
//! not adopted): what a reply, a reaction or a notification names, in
//! [`tag::TARGET`](crate::messages::tag::TARGET) and the fields that
//! share its layout. Integers are big-endian.

/// The most bytes a packed target may take.
pub const MAX_LEN: usize = 128;

const LINE: u8 = 1;
const IM: u8 = 2;
const EPHEMERAL: u8 = 4;
const PM: u8 = 5;

/// A private message reference's flag for one the server stores.
const STORED: u8 = 1;

/// One target, of a kind this crate reads. Kind 3, a signed object, is
/// not one: a reader ignores a kind it does not know.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    /// Kind 1: a kept line, `channel` 0 for public chat.
    Line { channel: u32, id: u64 },
    /// Kind 2: an instant message, by its guid and its sender's Login as
    /// the wire has it.
    Im { guid: [u8; 16], sender: Vec<u8> },
    /// Kind 4: a line by the id a chat numbers its lines with.
    Ephemeral { chat: u32, id: u64 },
    /// Kind 5: a private message by its reference.
    Pm { stored: bool, reference: [u8; 16] },
}

impl Target {
    /// The kind number the draft gives it, as a login reply's target
    /// kinds name it (`1 << kind`).
    pub fn kind(&self) -> u8 {
        match self {
            Target::Line { .. } => LINE,
            Target::Im { .. } => IM,
            Target::Ephemeral { .. } => EPHEMERAL,
            Target::Pm { .. } => PM,
        }
    }

    /// The packed form, or `None` for an instant message whose Login is
    /// empty or would take it past [`MAX_LEN`].
    pub fn pack(&self) -> Option<Vec<u8>> {
        let line = |kind: u8, chat: u32, id: u64| {
            [&[kind][..], &chat.to_be_bytes(), &id.to_be_bytes()].concat()
        };
        Some(match self {
            Target::Line { channel, id } => line(LINE, *channel, *id),
            Target::Ephemeral { chat, id } => line(EPHEMERAL, *chat, *id),
            Target::Im { guid, sender } => {
                if sender.is_empty() || 18 + sender.len() > MAX_LEN {
                    return None;
                }
                [&[IM][..], guid, &[sender.len() as u8], sender].concat()
            }
            Target::Pm { stored, reference } => {
                [&[PM, u8::from(*stored) * STORED][..], reference].concat()
            }
        })
    }

    /// A packed target, or `None` for one of a kind this crate does not
    /// read or that does not hold its kind's layout exactly.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() > MAX_LEN {
            return None;
        }
        let (&kind, rest) = b.split_first()?;
        let line = || {
            let (chat, id) = rest.split_first_chunk::<4>()?;
            Some((
                u32::from_be_bytes(*chat),
                u64::from_be_bytes(id.try_into().ok()?),
            ))
        };
        match kind {
            LINE => line().map(|(channel, id)| Target::Line { channel, id }),
            EPHEMERAL => line().map(|(chat, id)| Target::Ephemeral { chat, id }),
            IM => {
                let (guid, rest) = rest.split_first_chunk::<16>()?;
                let (&len, sender) = rest.split_first()?;
                (len != 0 && sender.len() == usize::from(len)).then(|| Target::Im {
                    guid: *guid,
                    sender: sender.to_vec(),
                })
            }
            PM => parse_pm_id(rest).map(|(stored, reference)| Target::Pm { stored, reference }),
            _ => None,
        }
    }
}

/// A private message's reference as [`tag::PM_ID`](crate::messages::tag::PM_ID)
/// carries it, and a kind 5 target after its kind: whether the server
/// stores the message, and its 16 bytes. `None` for any other length.
pub fn parse_pm_id(b: &[u8]) -> Option<(bool, [u8; 16])> {
    let (&flags, reference) = b.split_first()?;
    Some((flags & STORED != 0, reference.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(kind: u8, chat: u32, id: u64) -> Vec<u8> {
        [&[kind][..], &chat.to_be_bytes(), &id.to_be_bytes()].concat()
    }

    fn im(sender: &[u8]) -> Target {
        Target::Im {
            guid: [7; 16],
            sender: sender.to_vec(),
        }
    }

    #[test]
    fn each_kind_packs_as_the_draft_lays_it_out_and_reads_back() {
        let longest = vec![b'a'; MAX_LEN - 18];
        for (target, bytes) in [
            (
                Target::Line { channel: 0, id: 9 },
                vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
            ),
            (
                Target::Ephemeral {
                    chat: 0x0102_0304,
                    id: 0x0506_0708_090a_0b0c,
                },
                vec![4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            ),
            (im(b"bob"), [&[2][..], &[7; 16], &[3], b"bob"].concat()),
            (
                im(&longest),
                [&[2][..], &[7; 16], &[110], &longest].concat(),
            ),
            (
                Target::Pm {
                    stored: true,
                    reference: [3; 16],
                },
                [&[5, 1][..], &[3; 16]].concat(),
            ),
            (
                Target::Pm {
                    stored: false,
                    reference: [3; 16],
                },
                [&[5, 0][..], &[3; 16]].concat(),
            ),
        ] {
            assert_eq!(target.pack().as_deref(), Some(&bytes[..]), "{target:?}");
            assert_eq!(Target::parse(&bytes), Some(target));
        }
    }

    #[test]
    fn a_login_the_layout_cannot_carry_is_not_packed() {
        assert_eq!(im(b"").pack(), None);
        assert_eq!(im(&[b'a'; MAX_LEN - 17]).pack(), None);
    }

    #[test]
    fn what_does_not_hold_its_layout_is_not_read() {
        let pm = [&[5, 1][..], &[3; 16]].concat();
        for (case, bytes) in [
            ("empty", vec![]),
            ("signed", [&[3][..], &[0; 80]].concat()),
            ("an unknown kind", line(9, 0, 9)),
            ("a line cut short", line(1, 0, 9)[..12].to_vec()),
            ("a line run long", [line(1, 0, 9), vec![0]].concat()),
            ("an ephemeral line cut short", line(4, 0, 9)[..12].to_vec()),
            ("a message cut short", pm[..17].to_vec()),
            ("a message run long", [pm, vec![0]].concat()),
            ("a guid cut short", [&[2][..], &[7; 15]].concat()),
            ("no login", [&[2][..], &[7; 16], &[0]].concat()),
            (
                "a login cut short",
                [&[2][..], &[7; 16], &[3], b"bo"].concat(),
            ),
            (
                "a login run long",
                [&[2][..], &[7; 16], &[1], b"bo"].concat(),
            ),
            (
                "past the bound",
                [&[2][..], &[7; 16], &[111], &[b'a'; 111]].concat(),
            ),
        ] {
            assert_eq!(Target::parse(&bytes), None, "{case}");
        }
    }
}
