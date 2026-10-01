//! Cutting the control stream into transactions.
//!
//! Every frame on the wire is a 20-byte head — type, trans, flag,
//! TotalSize, DataSize — followed by DataSize bytes. For an ordinary
//! transaction the first two of those bytes are the field count, which is
//! why the 22-byte "header" everyone else talks about counts it.
//!
//! A frame is delimited by DataSize (`len2`), never TotalSize (`len`). The
//! two are equal unless a server split a large transaction across several
//! frames, and framing by TotalSize then reads past the end of the first
//! one and loses the stream — the desync GtkHx met on large news replies.
//! A split transaction repeats TotalSize and its trans in every fragment,
//! each fragment carries its own DataSize, and only the first fragment's
//! data begins with the field count; the fragments are joined here until
//! TotalSize bytes have arrived, as the original client did. Clients never
//! split what they send, and nor does anything that uses this crate.

use hxproto::HL_HDR_LEN;

/// The fixed part of a frame before its data: type, trans, flag, len, len2.
const HEAD_LEN: usize = 20;

/// The largest transaction accepted, data included. A frame that claims
/// more is a desync or a hostile server, not a message.
pub const MAX_TRANSACTION: usize = 1 << 20;

/// One whole transaction: the 22-byte header and its fields, with `len`
/// and `len2` both equal to the data size whatever the wire said, so the
/// hxproto parsers can walk it like any other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub type_: u32,
    pub trans: u32,
    pub flag: u32,
    pub buf: Vec<u8>,
}

impl Transaction {
    /// Whether the server marked this a failed request (`flag & 1`).
    pub fn is_error(&self) -> bool {
        self.flag & 1 != 0
    }
}

/// Why the stream can no longer be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// A frame or a split transaction claimed more than [`MAX_TRANSACTION`].
    TooLarge(u32),
}

struct Partial {
    head: [u8; HEAD_LEN],
    total: usize,
    data: Vec<u8>,
}

/// How many split transactions may be in flight at once. A server answers
/// requests in turn, so more than a couple is a broken or hostile stream;
/// past this the oldest is given up on.
const MAX_PARTIALS: usize = 4;

/// Buffers the bytes as they arrive and hands back whole transactions.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
    at: usize,
    /// Split transactions being joined, oldest first, by trans.
    partials: Vec<(u32, Partial)>,
    /// The trans of split transactions given up on before they finished,
    /// for the caller to fail the requests they answered.
    abandoned: Vec<u32>,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Whether `data` (a frame's data: a field count, then the fields) holds
/// exactly the fields its count announces — a whole message, whatever the
/// header's TotalSize claims.
fn is_whole(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let count = u16::from_be_bytes([data[0], data[1]]);
    let mut at = 2usize;
    for _ in 0..count {
        if data.len() < at + 4 {
            return false;
        }
        at += 4 + u16::from_be_bytes([data[at + 2], data[at + 3]]) as usize;
    }
    at == data.len()
}

impl FrameReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// The trans of split transactions abandoned since last asked: a
    /// second first fragment on the same trans, or more in flight than
    /// [`MAX_PARTIALS`]. Their requests will get no other answer.
    pub fn take_abandoned(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.abandoned)
    }

    pub fn push(&mut self, bytes: &[u8]) {
        // Compact before growing, so a long session's buffer stays the size
        // of what is outstanding rather than of everything ever read.
        if self.at > 0 && self.at == self.buf.len() {
            self.buf.clear();
            self.at = 0;
        } else if self.at > 64 * 1024 {
            self.buf.drain(..self.at);
            self.at = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole transaction, `Ok(None)` when more bytes are needed.
    pub fn next_transaction(&mut self) -> Result<Option<Transaction>, FrameError> {
        loop {
            let avail = &self.buf[self.at..];
            if avail.len() < HEAD_LEN {
                return Ok(None);
            }
            let len = be32(&avail[12..16]);
            let len2 = be32(&avail[16..20]);
            if len2 as usize > MAX_TRANSACTION {
                return Err(FrameError::TooLarge(len2));
            }
            // A fragment of a split transaction says so in its header:
            // TotalSize past this frame's DataSize. It is exactly DataSize
            // long, however short. Any other frame occupies at least the
            // 22 bytes that hold its field count.
            let split = len > len2;
            let data_len = if split {
                len2 as usize
            } else {
                (len2 as usize).max(HL_HDR_LEN - HEAD_LEN)
            };
            if avail.len() < HEAD_LEN + data_len {
                return Ok(None);
            }
            let mut head = [0u8; HEAD_LEN];
            head.copy_from_slice(&avail[..HEAD_LEN]);
            let data = avail[HEAD_LEN..HEAD_LEN + data_len].to_vec();
            self.at += HEAD_LEN + data_len;
            let trans = be32(&head[4..8]);
            if !split {
                return Ok(Some(assemble(head, &data)));
            }
            if len as usize > MAX_TRANSACTION {
                return Err(FrameError::TooLarge(len));
            }

            // A later fragment of one already being joined: its data is
            // raw, so it is appended without a look at what it holds.
            if let Some(i) = self
                .partials
                .iter()
                .position(|(t, p)| *t == trans && p.total == len as usize)
            {
                let p = &mut self.partials[i].1;
                p.data.extend_from_slice(&data);
                if p.data.len() < p.total {
                    continue;
                }
                let (_, p) = self.partials.remove(i);
                return Ok(Some(assemble(p.head, &p.data[..p.total])));
            }

            // A frame whose fields already fill it is whole, whatever
            // TotalSize says: some server counting its header twice is
            // likelier than a split that happens to end on a field
            // boundary with every announced field in it — which would be
            // whole anyway.
            if is_whole(&data) {
                return Ok(Some(assemble(head, &data)));
            }

            // An empty fragment that continues nothing starts nothing.
            if data.is_empty() {
                continue;
            }
            // The first fragment of a split transaction.
            if let Some(i) = self.partials.iter().position(|(t, _)| *t == trans) {
                self.partials.remove(i);
                self.abandoned.push(trans);
            }
            if self.partials.len() >= MAX_PARTIALS {
                let (t, _) = self.partials.remove(0);
                self.abandoned.push(t);
            }
            self.partials.push((
                trans,
                Partial {
                    head,
                    total: len as usize,
                    data,
                },
            ));
        }
    }
}

fn assemble(head: [u8; HEAD_LEN], data: &[u8]) -> Transaction {
    let mut buf = Vec::with_capacity(HEAD_LEN + data.len());
    buf.extend_from_slice(&head);
    let n = (data.len() as u32).to_be_bytes();
    buf[12..16].copy_from_slice(&n);
    buf[16..20].copy_from_slice(&n);
    buf.extend_from_slice(data);
    if buf.len() < HL_HDR_LEN {
        buf.resize(HL_HDR_LEN, 0);
    }
    Transaction {
        type_: be32(&head[0..4]),
        trans: be32(&head[4..8]),
        flag: be32(&head[8..12]),
        buf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One frame as a server writes it: a head and `data`, with TotalSize
    /// `total` (the data size when `None`).
    fn frame(type_: u32, trans: u32, total: Option<u32>, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&type_.to_be_bytes());
        out.extend_from_slice(&trans.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&total.unwrap_or(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// A field count and one field.
    fn body(tag: u16, field: &[u8]) -> Vec<u8> {
        let mut out = 1u16.to_be_bytes().to_vec();
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field);
        out
    }

    #[test]
    fn frames_come_back_whatever_the_reads_were() {
        let mut wire = frame(0x6a, 0, None, &body(0x65, b"hello"));
        wire.extend(frame(0x6a, 0, None, &body(0x65, b"world")));
        let mut r = FrameReader::new();
        let mut got = Vec::new();
        // One byte at a time: every boundary a read could fall on.
        for b in &wire {
            r.push(std::slice::from_ref(b));
            while let Some(t) = r.next_transaction().unwrap() {
                got.push(t);
            }
        }
        assert_eq!(got.len(), 2);
        let chat = hxproto::parse::parse_chat(&got[1].buf, got[1].buf.len(), 64);
        assert_eq!(chat.text(), b"world");
    }

    #[test]
    fn a_split_transaction_is_joined() {
        // One 1000-byte news reply cut in three, the way a fragmenting
        // server sends it: TotalSize in each, the field count only in the
        // first.
        let news: Vec<u8> = (0..994u32).map(|i| b'a' + (i % 26) as u8).collect();
        let whole = body(0x65, &news);
        assert_eq!(whole.len(), 1000);
        let total = Some(whole.len() as u32);
        let mut wire = frame(0x1_0000, 7, total, &whole[..300]);
        // Another transaction in between passes straight through.
        wire.extend(frame(0x6a, 0, None, &body(0x65, b"meanwhile")));
        wire.extend(frame(0x1_0000, 7, total, &whole[300..700]));
        wire.extend(frame(0x1_0000, 7, total, &whole[700..]));
        wire.extend(frame(0x6a, 0, None, &body(0x65, b"after")));
        let mut r = FrameReader::new();
        r.push(&wire);
        let a = r.next_transaction().unwrap().unwrap();
        assert_eq!(a.type_, 0x6a);
        let b = r.next_transaction().unwrap().unwrap();
        assert_eq!((b.type_, b.trans), (0x1_0000, 7));
        assert_eq!(
            hxproto::parse::parse_news_file(&b.buf, b.buf.len(), 4096).unwrap(),
            news
        );
        let c = r.next_transaction().unwrap().unwrap();
        assert_eq!(
            hxproto::parse::parse_chat(&c.buf, c.buf.len(), 64).text(),
            b"after"
        );
        assert!(r.next_transaction().unwrap().is_none());
    }

    #[test]
    fn a_huge_claim_is_refused_before_any_allocation() {
        let mut r = FrameReader::new();
        let mut head = frame(0x6a, 0, None, &[]);
        head[16..20].copy_from_slice(&(MAX_TRANSACTION as u32 + 1).to_be_bytes());
        r.push(&head);
        assert!(matches!(r.next_transaction(), Err(FrameError::TooLarge(_))));

        let mut r = FrameReader::new();
        r.push(&frame(0x1_0000, 1, Some(u32::MAX), &body(0x65, b"x")));
        assert!(matches!(r.next_transaction(), Err(FrameError::TooLarge(_))));
    }

    /// All the transactions in `wire`, read in one go.
    fn all(wire: &[u8]) -> (Vec<Transaction>, Vec<u32>) {
        let mut r = FrameReader::new();
        r.push(wire);
        let mut out = Vec::new();
        while let Some(t) = r.next_transaction().unwrap() {
            out.push(t);
        }
        (out, r.take_abandoned())
    }

    #[test]
    fn a_last_fragment_of_a_byte_or_none_keeps_the_stream_in_step() {
        for tail in [0usize, 1] {
            let whole = body(0x65, b"abcdefghij");
            let cut = whole.len() - tail;
            let total = Some(whole.len() as u32);
            let mut wire = frame(0x1_0000, 4, total, &whole[..cut]);
            wire.extend(frame(0x1_0000, 4, total, &whole[cut..]));
            wire.extend(frame(0x6a, 0, None, &body(0x65, b"next")));
            let (got, abandoned) = all(&wire);
            assert!(abandoned.is_empty());
            if tail == 0 {
                // An empty fragment after a first one that already held
                // everything: the first was whole, and the empty one is
                // the start of nothing.
                assert_eq!(got.len(), 2);
                assert_eq!(got[0].buf[20..], whole[..]);
            } else {
                assert_eq!(got.len(), 2, "tail {tail}");
                assert_eq!(got[0].buf[20..], whole[..]);
            }
            let last = got.last().unwrap();
            assert_eq!(
                hxproto::parse::parse_chat(&last.buf, last.buf.len(), 64).text(),
                b"next"
            );
        }
    }

    #[test]
    fn a_first_fragment_too_short_for_its_field_count_is_joined() {
        let whole = body(0x65, b"xyz");
        let total = Some(whole.len() as u32);
        let mut wire = frame(0x1_0000, 4, total, &whole[..1]);
        wire.extend(frame(0x1_0000, 4, total, &whole[1..]));
        let (got, _) = all(&wire);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].buf[20..], whole[..]);
    }

    #[test]
    fn overlapping_splits_both_finish() {
        let a = body(0x65, &[b'a'; 50]);
        let b = body(0x65, &[b'b'; 70]);
        let (ta, tb) = (Some(a.len() as u32), Some(b.len() as u32));
        let mut wire = frame(0x1_0000, 1, ta, &a[..20]);
        wire.extend(frame(0x1_0000, 2, tb, &b[..20]));
        wire.extend(frame(0x1_0000, 1, ta, &a[20..]));
        wire.extend(frame(0x1_0000, 2, tb, &b[20..]));
        let (got, abandoned) = all(&wire);
        assert_eq!(got.iter().map(|t| t.trans).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(got[0].buf[20..], a[..]);
        assert_eq!(got[1].buf[20..], b[..]);
        assert!(abandoned.is_empty());
    }

    #[test]
    fn a_whole_frame_with_an_overstated_total_is_delivered() {
        // TotalSize two past DataSize, as a server counting its field
        // count twice would send: the fields fill the frame, so it is
        // whole, and what follows is read as it should be.
        let whole = body(0x65, b"hi");
        let mut wire = frame(0x1_0000, 1, Some(whole.len() as u32 + 2), &whole);
        wire.extend(frame(0x6a, 0, None, &body(0x65, b"after")));
        let (got, _) = all(&wire);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].buf[20..], whole[..]);
    }

    #[test]
    fn abandoned_splits_are_reported() {
        let a = body(0x65, &[b'a'; 50]);
        let total = a.len() as u32;
        let ta = Some(total);
        // The same trans starting again leaves the first unfinished.
        let mut wire = frame(0x1_0000, 1, ta, &a[..20]);
        wire.extend(frame(0x1_0000, 1, Some(total + 1), &a[..20]));
        // And more in flight than are kept: the oldest goes.
        for t in 10..(10 + MAX_PARTIALS as u32) {
            wire.extend(frame(0x1_0000, t, ta, &a[..20]));
        }
        let (got, abandoned) = all(&wire);
        assert!(got.is_empty());
        assert_eq!(abandoned, [1, 1]);
    }
}
