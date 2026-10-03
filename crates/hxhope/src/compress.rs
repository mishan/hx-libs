//! The compression layer of a HOPE transport, a direction at a time: what
//! one `encode` is given goes out as one unit (a full flush, an LZ4 frame,
//! a Zstandard frame), and what arrives decompresses as it comes.

use flate2::{FlushCompress, FlushDecompress, Status};

use crate::alg::Compression;
use crate::Error;

/// The most one `decode` call may produce. A transaction is at most 1 MiB;
/// this is room for a burst of them, and a ceiling on what a compression
/// bomb gets out of us.
const MAX_OUTPUT: usize = 16 * 1024 * 1024;
/// The most undecoded input held waiting for the rest of an LZ4 frame.
const MAX_PENDING: usize = 16 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;

fn broken(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Transport(format!("{what}: {e}"))
}

pub(crate) enum Compressor {
    Gzip(flate2::Compress),
    Lz4,
    #[cfg(feature = "zstd")]
    Zstd,
}

pub(crate) enum Decompressor {
    Gzip(flate2::Decompress),
    Lz4(Lz4Frames),
    #[cfg(feature = "zstd")]
    Zstd(zstd::stream::raw::Decoder<'static>),
}

pub(crate) fn pair(c: Compression) -> Result<(Compressor, Decompressor), Error> {
    Ok(match c {
        Compression::Gzip => (
            Compressor::Gzip(flate2::Compress::new(flate2::Compression::default(), true)),
            Decompressor::Gzip(flate2::Decompress::new(true)),
        ),
        Compression::Lz4 => (Compressor::Lz4, Decompressor::Lz4(Lz4Frames::default())),
        #[cfg(feature = "zstd")]
        Compression::Zstd => (
            Compressor::Zstd,
            Decompressor::Zstd(zstd::stream::raw::Decoder::new().map_err(|e| broken("zstd", e))?),
        ),
        #[cfg(not(feature = "zstd"))]
        Compression::Zstd => return Err(Error::Unsupported("ZSTD".into())),
    })
}

impl Compressor {
    pub fn encode(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Compressor::Gzip(c) => {
                // deflateBound, and room for the flush's empty block.
                let mut out = Vec::with_capacity(input.len() + input.len() / 16384 * 5 + 64);
                let mut pos = 0;
                loop {
                    let before = c.total_in();
                    // A full flush: each unit starts the dictionary afresh,
                    // so what one batch says says nothing of the next.
                    c.compress_vec(&input[pos..], &mut out, FlushCompress::Full)
                        .map_err(|e| broken("gzip", e))?;
                    pos += (c.total_in() - before) as usize;
                    // Flushed, with room left over: nothing is held back.
                    if pos == input.len() && out.len() < out.capacity() {
                        return Ok(out);
                    }
                    out.reserve(out.capacity().max(64));
                }
            }
            Compressor::Lz4 => {
                use std::io::Write;
                let mut enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
                enc.write_all(input).map_err(|e| broken("lz4", e))?;
                enc.finish().map_err(|e| broken("lz4", e))
            }
            #[cfg(feature = "zstd")]
            Compressor::Zstd => zstd::bulk::compress(input, 0).map_err(|e| broken("zstd", e)),
        }
    }
}

impl Decompressor {
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let start = out.len();
        match self {
            Decompressor::Gzip(d) => {
                let mut pos = 0;
                loop {
                    let (before_in, before_out) = (d.total_in(), d.total_out());
                    out.reserve(CHUNK);
                    let status = d
                        .decompress_vec(&input[pos..], out, FlushDecompress::Sync)
                        .map_err(|e| broken("gzip", e))?;
                    let consumed = (d.total_in() - before_in) as usize;
                    let produced = (d.total_out() - before_out) as usize;
                    pos += consumed;
                    if out.len() - start > MAX_OUTPUT {
                        return Err(Error::Transport("gzip: too much from too little".into()));
                    }
                    if status == Status::StreamEnd && pos < input.len() {
                        return Err(Error::Transport(
                            "gzip: bytes after the stream's end".into(),
                        ));
                    }
                    // Output space left unused, all input taken: drained.
                    if pos == input.len() && out.len() < out.capacity() {
                        return Ok(());
                    }
                    if consumed == 0 && produced == 0 {
                        return Err(Error::Transport("gzip: the stream is stuck".into()));
                    }
                }
            }
            Decompressor::Lz4(f) => {
                f.pending.extend_from_slice(input);
                while let Some(end) = f.frame_end()? {
                    f.decodes += 1;
                    let (plain, used) = lz4_frame(&f.pending[..end])?
                        .ok_or_else(|| Error::Transport("lz4: a frame cut short".into()))?;
                    if used != end {
                        return Err(Error::Transport(
                            "lz4: the frame does not end where its blocks say".into(),
                        ));
                    }
                    out.extend_from_slice(&plain);
                    f.pending.drain(..end);
                    f.scanned = None;
                    if out.len() - start > MAX_OUTPUT {
                        return Err(Error::Transport("lz4: too much from too little".into()));
                    }
                }
                if f.pending.len() > MAX_PENDING {
                    return Err(Error::Transport("lz4: a frame that never ends".into()));
                }
                Ok(())
            }
            #[cfg(feature = "zstd")]
            Decompressor::Zstd(d) => {
                use zstd::stream::raw::{InBuffer, Operation, OutBuffer};
                let mut src = InBuffer::around(input);
                loop {
                    let at = out.len();
                    out.resize(at + CHUNK, 0);
                    let mut dst = OutBuffer::around(&mut out[at..]);
                    d.run(&mut src, &mut dst).map_err(|e| broken("zstd", e))?;
                    let produced = dst.pos();
                    out.truncate(at + produced);
                    if out.len() - start > MAX_OUTPUT {
                        return Err(Error::Transport("zstd: too much from too little".into()));
                    }
                    if src.pos() == input.len() && produced < CHUNK {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Nothing held part way through a unit.
    pub fn idle(&self) -> bool {
        match self {
            Decompressor::Lz4(f) => f.pending.is_empty(),
            _ => true,
        }
    }
}

/// The LZ4 frame arriving, and how far into it its blocks are known: a
/// frame is decoded once, when its end has come, rather than tried again
/// with every piece of it.
#[derive(Default)]
pub(crate) struct Lz4Frames {
    pending: Vec<u8>,
    /// Where the next block's size is, once the frame header is read.
    scanned: Option<usize>,
    block_checksums: bool,
    content_checksum: bool,
    /// Frames decoded, for the tests.
    decodes: usize,
}

impl Lz4Frames {
    /// The length of the frame at the front of `pending`, once all of it
    /// is there. Walks only what arrived since it last looked.
    fn frame_end(&mut self) -> Result<Option<usize>, Error> {
        let p = &self.pending;
        let mut at = match self.scanned {
            Some(at) => at,
            None => {
                // Magic, FLG, BD, the optional content size and dictionary
                // id, and the header checksum.
                if p.len() < 7 {
                    return Ok(None);
                }
                if p[..4] != [0x04, 0x22, 0x4d, 0x18] {
                    return Err(Error::Transport("lz4: not a frame".into()));
                }
                let flg = p[4];
                self.block_checksums = flg & 0x10 != 0;
                self.content_checksum = flg & 0x04 != 0;
                7 + if flg & 0x08 != 0 { 8 } else { 0 } + if flg & 0x01 != 0 { 4 } else { 0 }
            }
        };
        loop {
            self.scanned = Some(at);
            let Some(size) = p.get(at..at + 4) else {
                return Ok(None);
            };
            let size = u32::from_le_bytes(size.try_into().expect("four bytes"));
            if size == 0 {
                let end = at + 4 + if self.content_checksum { 4 } else { 0 };
                return Ok((p.len() >= end).then_some(end));
            }
            at += 4 + (size & 0x7fff_ffff) as usize + if self.block_checksums { 4 } else { 0 };
        }
    }
}

/// One whole LZ4 frame from the front of `bytes` and how many bytes it
/// took, or `None` while it is still arriving.
fn lz4_frame(bytes: &[u8]) -> Result<Option<(Vec<u8>, usize)>, Error> {
    use std::io::Read;

    const MAGIC: [u8; 4] = [0x04, 0x22, 0x4d, 0x18];
    if bytes.len() < MAGIC.len() {
        return Ok(None);
    }
    if bytes[..4] != MAGIC {
        return Err(Error::Transport("lz4: not a frame".into()));
    }

    /// Says "no more yet" where a slice would say "end": the decoder
    /// takes an end as the frame's, whole or not.
    struct Partial<'a> {
        bytes: &'a [u8],
        pos: usize,
    }
    impl Read for Partial<'_> {
        fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
            let rest = &self.bytes[self.pos..];
            if rest.is_empty() {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let n = rest.len().min(dst.len());
            dst[..n].copy_from_slice(&rest[..n]);
            self.pos += n;
            Ok(n)
        }
    }

    let mut dec = lz4_flex::frame::FrameDecoder::new(Partial { bytes, pos: 0 });
    let mut plain = Vec::new();
    let mut chunk = vec![0u8; CHUNK];
    loop {
        match dec.read(&mut chunk) {
            Ok(0) => return Ok(Some((plain, dec.into_inner().pos))),
            Ok(n) => {
                if plain.len() + n > MAX_OUTPUT {
                    return Err(Error::Transport("lz4: too much from too little".into()));
                }
                plain.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(broken("lz4", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn algorithms() -> Vec<Compression> {
        let mut v = vec![Compression::Gzip, Compression::Lz4];
        if cfg!(feature = "zstd") {
            v.push(Compression::Zstd);
        }
        v
    }

    /// Each unit decodes to what went in, however the bytes are cut on the
    /// way: a byte at a time, and all at once.
    #[test]
    fn what_is_encoded_decodes_in_any_pieces() {
        let units: [&[u8]; 3] = [b"hello", &[0x5a; 70_000], b""];
        for alg in algorithms() {
            for cut in [1, usize::MAX] {
                let (mut c, mut d) = pair(alg).unwrap();
                let mut wire = Vec::new();
                for u in units {
                    wire.extend(c.encode(u).unwrap());
                }
                let mut out = Vec::new();
                for piece in wire.chunks(cut.min(wire.len())) {
                    d.decode(piece, &mut out).unwrap();
                }
                assert_eq!(out, units.concat(), "{alg:?} cut {cut}");
                assert!(d.idle());
            }
        }
    }

    /// A frame that arrives a byte at a time is decoded once, when it is
    /// all there, not again with every byte.
    #[test]
    fn an_lz4_frame_trickling_in_is_decoded_once() {
        let unit: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let (mut c, mut d) = pair(Compression::Lz4).unwrap();
        let wire = c.encode(&unit).unwrap();
        let mut out = Vec::new();
        for b in &wire {
            d.decode(std::slice::from_ref(b), &mut out).unwrap();
        }
        assert_eq!(out, unit);
        let Decompressor::Lz4(f) = &d else {
            unreachable!()
        };
        assert_eq!(f.decodes, 1);
    }

    #[test]
    fn a_bomb_is_refused() {
        for alg in algorithms() {
            let (mut c, mut d) = pair(alg).unwrap();
            let wire = c.encode(&vec![0u8; MAX_OUTPUT + 1]).unwrap();
            assert!(d.decode(&wire, &mut Vec::new()).is_err(), "{alg:?}");
        }
    }

    #[test]
    fn garbage_is_refused() {
        for alg in algorithms() {
            let (_, mut d) = pair(alg).unwrap();
            assert!(d.decode(&[0xff; 64], &mut Vec::new()).is_err(), "{alg:?}");
        }
    }
}
