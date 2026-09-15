//! The idiomatic native HFS-sidecar API.
//!
//! Explicit [`Config`], `&Path` inputs, `io::Result` / owned [`HfsInfo`]
//! outputs. Byte-faithful to `hfs.c`'s CAP / AppleDouble / Netatalk layouts.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::suffix::suffix_type_creator;

// ---------- portable OS-string / path seams ----------
//
// hfs.c is Unix C. This crate keeps its byte-exact behavior on Unix while also
// compiling and running on Windows; the helpers below are the only places that
// touch platform-specific surface, so the rest of the module reads the same on
// every target.

/// Borrow an `OsStr`'s platform-encoded bytes. On Unix these are the raw path
/// bytes (identical to the old `OsStrExt::as_bytes`); on Windows they're WTF-8.
/// The sidecar logic only splits on and appends ASCII, which every supported
/// encoding preserves, so a round-trip through [`os_from_bytes`] is faithful.
fn os_bytes(s: &OsStr) -> &[u8] {
    s.as_encoded_bytes()
}

/// Rebuild an `OsString` from bytes produced by [`os_bytes`] with only
/// ASCII-boundary edits — exactly the `dir` + `/` + `name` + `suffix` splice in
/// [`sidecar`].
fn os_from_bytes(bytes: Vec<u8>) -> OsString {
    // SAFETY: `bytes` come from `os_bytes` (valid platform encoding) with ASCII
    // bytes inserted only at ASCII boundaries, which preserves validity — the
    // documented precondition of `from_encoded_bytes_unchecked`.
    unsafe { OsString::from_encoded_bytes_unchecked(bytes) }
}

/// Whether `b` splits the directory from the name for sidecar computation. Unix
/// honors *only* the caller's `dir_char`, byte-exact with hfs.c's
/// `for (i…) if (path[i] == dir_char)` loop. Other platforms additionally treat
/// their native separators (`/` and `\`) as splits, so a real Windows path still
/// locates its sibling sidecar.
#[cfg(unix)]
fn is_sep(b: u8, dir_char: u8) -> bool {
    b == dir_char
}
#[cfg(not(unix))]
fn is_sep(b: u8, dir_char: u8) -> bool {
    (dir_char.is_ascii() && b == dir_char) || b == b'/' || b == b'\\'
}

/// Apply a Unix file mode to `opts` on platforms that model one; a no-op on
/// Windows, whose `OpenOptions` has no mode concept.
#[cfg(unix)]
pub(crate) fn with_mode(opts: &mut OpenOptions, mode: u32) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(mode);
}
#[cfg(not(unix))]
pub(crate) fn with_mode(_opts: &mut OpenOptions, _mode: u32) {}

/// Maximum Finder comment length the on-disk formats hold.
pub const MAX_COMMENT: usize = 200;

/// The native path-length ceiling — the upper bound of the C `MAXPATHLEN`
/// (`PATH_MAX` clamped to 4095). The native API doesn't write into a fixed C
/// buffer (it returns a heap `PathBuf`), so this is just a rejection limit. A
/// consumer's C shim that fills a caller's `char buf[MAXPATHLEN]` has to apply
/// its platform's own bound.
pub const MAXPATHLEN: usize = 4095;

/// The AppleDouble / CAP on-disk constants (`hfs.h`).
pub(crate) mod format {
    // AppleDouble header-entry ids.
    pub const HDR_COMNT: u32 = 4;
    pub const HDR_OLDI: u32 = 7;
    pub const HDR_DATES: u32 = 8;
    pub const HDR_FINFO: u32 = 9;
    pub const HDR_RSRC: u32 = 2;
    pub const HDR_MAX: u16 = 16;

    pub const DBL_MAGIC: u32 = 0x0005_1607;
    pub const HDR_VERSION_1: u32 = 0x0001_0000;
    pub const HDR_VERSION_2: u32 = 0x0002_0000;

    pub const SIZEOF_HDR_DESCR: usize = 12;
    pub const SIZEOF_DBL_HDR: usize = 26;
    pub const SIZEOF_CAP_INFO: usize = 300;

    // CAP fixed record magic bytes + date bitmap.
    pub const CAP_MAGIC1: u8 = 0xFF;
    pub const CAP_VERSION: u8 = 0x10;
    pub const CAP_MAGIC: u8 = 0xDA;
    pub const CAP_DMAGIC: u8 = 0xDA;
    pub const CAP_MDATE: u8 = 0x01;
    pub const CAP_CDATE: u8 = 0x02;

    // Offsets into the 300-byte CAP record (struct hfs_cap_info).
    pub const CAP_OFF_FNDR: usize = 0; // fi_fndr[32] — type[4]+creator[4]+…
    pub const CAP_OFF_MAGIC1: usize = 34;
    pub const CAP_OFF_VERSION: usize = 35;
    pub const CAP_OFF_MAGIC: usize = 36;
    pub const CAP_OFF_COMLN: usize = 84;
    pub const CAP_OFF_COMNT: usize = 85; // fi_comnt[200]
    pub const CAP_OFF_DATEMAGIC: usize = 285;
    pub const CAP_OFF_DATEVALID: usize = 286;
    pub const CAP_OFF_CTIME: usize = 287; // fi_ctime[4], fi_mtime[4], fi_utime[4]
}

use format::*;

/// Seconds between the Unix epoch (1970) and the "header" epoch (2000).
const HTIME_OFFSET: i64 = 946_684_800;

/// The sidecar layout a [`Config`] reads / writes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fork {
    /// aufs "CAP": a `.rsrc` fork file + a fixed 300-byte `.fndrinfo` record.
    Cap,
    /// AppleDouble v2 (`.fndrinfo` holds header + all forks).
    Double,
    /// Netatalk (AppleDouble v1 magic).
    Netatalk,
}

/// Reader/writer configuration. Mirrors `hfs.c`'s process-global `cfg`, but
/// passed explicitly. `dir_char` is the path separator used to locate the
/// sidecar's directory (the C global `dir_char`, default `/`).
#[derive(Clone, Debug)]
pub struct Config {
    pub fork: Fork,
    pub file_perm: u32,
    pub dir_perm: u32,
    pub comment: Option<Vec<u8>>,
    pub dir_char: u8,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            fork: Fork::Cap,
            file_perm: 0o600,
            dir_perm: 0o700,
            comment: None,
            dir_char: b'/',
        }
    }
}

/// Decoded Finder metadata. `type_creator` is the 8-byte type+creator pair;
/// `create_time` / `modify_time` are the raw 4-byte "header" (2000-epoch,
/// big-endian) timestamps as stored on disk; `comment` is at most
/// [`MAX_COMMENT`] bytes.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct HfsInfo {
    pub type_creator: [u8; 8],
    pub create_time: [u8; 4],
    pub modify_time: [u8; 4],
    /// Resource-fork length. CAP stores the fork in a normal file and can
    /// represent a full `u64`; AppleDouble descriptor lengths remain `u32`.
    pub rsrclen: u64,
    pub comment: Vec<u8>,
}

// ---------- Sidecar path computation ----------

fn sidecar(path: &Path, dir_char: u8, suffix: &[u8]) -> io::Result<PathBuf> {
    let p = os_bytes(path.as_os_str());
    // hfs.c: `if (len + 16 >= MAXPATHLEN) return ENAMETOOLONG;`
    if p.len() + 16 >= MAXPATHLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path too long for HFS sidecar",
        ));
    }
    // Split at the last separator, including a root separator at index 0. The
    // original C loop skipped index 0 and accidentally treated `/file` as a
    // relative path (`.//file.fndrinfo`).
    // On Unix `is_sep` matches only `dir_char`, so the split is byte-exact with
    // hfs.c; on other targets it additionally accepts `/` and `\` (see is_sep),
    // which is a deliberate divergence so native Windows paths still split.
    let split = (0..p.len()).rev().find(|&i| is_sep(p[i], dir_char));
    let (dir, name): (&[u8], &[u8]) = match split {
        Some(i) => (&p[..i], &p[i + 1..]),
        None => (b".", p),
    };
    // The join separator is always `/`, regardless of dir_char (as in hfs.c).
    let mut out = Vec::with_capacity(dir.len() + 1 + name.len() + suffix.len());
    out.extend_from_slice(dir);
    out.push(b'/');
    out.extend_from_slice(name);
    out.extend_from_slice(suffix);
    Ok(PathBuf::from(os_from_bytes(out)))
}

/// The `.fndrinfo` sidecar path for `path`.
pub fn finderinfo_path(path: &Path, dir_char: u8) -> io::Result<PathBuf> {
    sidecar(path, dir_char, b".fndrinfo")
}

/// The `.rsrc` sidecar path for `path`.
pub fn resource_path(path: &Path, dir_char: u8) -> io::Result<PathBuf> {
    sidecar(path, dir_char, b".rsrc")
}

// ---------- AppleDouble descriptor table ----------

#[derive(Clone, Copy)]
struct Descr {
    id: u32,
    offset: u32,
    length: u32,
}

impl Descr {
    fn from_bytes(b: &[u8]) -> Descr {
        Descr {
            id: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            offset: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            length: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        }
    }
    fn write_bytes(&self, b: &mut [u8]) {
        b[0..4].copy_from_slice(&self.id.to_be_bytes());
        b[4..8].copy_from_slice(&self.offset.to_be_bytes());
        b[8..12].copy_from_slice(&self.length.to_be_bytes());
    }
}

/// Read and validate the AppleDouble descriptor table from an open
/// `.fndrinfo`. An empty file has no record; a non-empty malformed container is
/// rejected so callers never mistake arbitrary bytes for an embedded fork.
fn read_dbl_descrs(f: &mut File) -> io::Result<Option<Vec<Descr>>> {
    let file_len = f.metadata()?.len();
    if file_len == 0 {
        return Ok(None);
    }
    if file_len < SIZEOF_DBL_HDR as u64 {
        return Err(invalid_appledouble("truncated AppleDouble header"));
    }
    f.seek(SeekFrom::Start(0))?;
    let mut hdr = [0u8; SIZEOF_DBL_HDR];
    f.read_exact(&mut hdr)?;
    let magic = u32::from_be_bytes(hdr[0..4].try_into().expect("four bytes"));
    let version = u32::from_be_bytes(hdr[4..8].try_into().expect("four bytes"));
    if magic != DBL_MAGIC || !matches!(version, HDR_VERSION_1 | HDR_VERSION_2) {
        return Err(invalid_appledouble("invalid AppleDouble magic or version"));
    }
    let entries = u16::from_be_bytes([hdr[24], hdr[25]]);
    if entries > HDR_MAX {
        return Err(invalid_appledouble("too many AppleDouble descriptors"));
    }
    let table_len = SIZEOF_HDR_DESCR
        .checked_mul(entries as usize)
        .ok_or_else(|| invalid_appledouble("AppleDouble descriptor table overflows"))?;
    let table_end = SIZEOF_DBL_HDR
        .checked_add(table_len)
        .ok_or_else(|| invalid_appledouble("AppleDouble descriptor table overflows"))?;
    if file_len < table_end as u64 {
        return Err(invalid_appledouble(
            "truncated AppleDouble descriptor table",
        ));
    }
    let mut tbl = vec![0u8; table_len];
    f.read_exact(&mut tbl)?;
    let descrs = (0..entries as usize)
        .map(|i| Descr::from_bytes(&tbl[SIZEOF_HDR_DESCR * i..]))
        .collect::<Vec<_>>();
    validate_descrs(&descrs, file_len)?;
    Ok(Some(descrs))
}

/// Check a descriptor table against the container it describes. The known
/// metadata entries must be long enough for what the readers take from them,
/// and every non-empty entry must lie after the table, inside the file, and
/// apart from the others. An empty entry holds no bytes, so where it points is
/// not checked: `resource_open` lets an empty resource fork grow only when it
/// sits exactly at the end of the container.
fn validate_descrs(descrs: &[Descr], file_len: u64) -> io::Result<()> {
    let table_end = (SIZEOF_DBL_HDR + SIZEOF_HDR_DESCR * descrs.len()) as u64;
    let mut ranges = Vec::with_capacity(descrs.len());
    for d in descrs {
        if matches!(d.id, HDR_OLDI | HDR_DATES | HDR_FINFO) && d.length < 8 {
            return Err(invalid_appledouble(
                "AppleDouble metadata descriptor is too short",
            ));
        }
        if d.length == 0 {
            continue;
        }
        let start = u64::from(d.offset);
        let end = start + u64::from(d.length);
        if start < table_end || end > file_len {
            return Err(invalid_appledouble(
                "AppleDouble descriptor lies outside the container",
            ));
        }
        ranges.push((start, end));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(invalid_appledouble("AppleDouble descriptors overlap"));
    }
    Ok(())
}

fn invalid_appledouble(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// `read` exactly `buf.len()` bytes, or `None` if the file was shorter (the C
/// `if (r != SIZEOF_…) goto funkdat;` pattern — a short read is "no record",
/// not an error).
fn read_exact_or_none(f: &mut File, buf: &mut [u8]) -> io::Result<Option<()>> {
    let mut got = 0;
    while got < buf.len() {
        match f.read(&mut buf[got..]) {
            Ok(0) => return Ok(None),
            Ok(n) => got += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(Some(()))
}

// ---------- type / creator ----------

/// The 8-byte type+creator for `path`: read from the sidecar's Finder info if
/// present + non-empty, else derived from the file extension.
pub fn type_creator(cfg: &Config, path: &Path) -> [u8; 8] {
    if let Ok(info) = finderinfo_path(path, cfg.dir_char) {
        if let Ok(mut f) = File::open(&info) {
            if let Some(tc) = read_type_creator(cfg.fork, &mut f) {
                if tc[0..4] != [0; 4] && tc[4..8] != [0; 4] {
                    return tc;
                }
            }
        }
    }
    suffix_type_creator(os_bytes(path.as_os_str()))
}

fn read_type_creator(fork: Fork, f: &mut File) -> Option<[u8; 8]> {
    match fork {
        Fork::Cap => {
            let mut buf = [0u8; 8];
            read_exact_or_none(f, &mut buf).ok()??;
            Some(buf)
        }
        Fork::Double | Fork::Netatalk => {
            let descrs = read_dbl_descrs(f).ok()??;
            for d in descrs {
                if d.id == HDR_FINFO {
                    f.seek(SeekFrom::Start(d.offset as u64)).ok()?;
                    let mut buf = [0u8; 8];
                    read_exact_or_none(f, &mut buf).ok()??;
                    return Some(buf);
                }
            }
            None
        }
    }
}

// ---------- Finder info read ----------

/// Read the Finder metadata for `path`, applying the same fallbacks as
/// `hfsinfo_read`: extension-derived type/creator when absent, the data file's
/// mtime for missing dates, and `cfg.comment` for a missing comment.
pub fn hfsinfo_read(cfg: &Config, path: &Path) -> HfsInfo {
    let mut fi = HfsInfo::default();

    if let Ok(info) = finderinfo_path(path, cfg.dir_char) {
        if let Ok(mut f) = File::open(&info) {
            match cfg.fork {
                Fork::Cap => read_cap_info(&mut f, &mut fi),
                Fork::Double | Fork::Netatalk => read_dbl_info(&mut f, &mut fi),
            }
        }
    }

    if cfg.fork == Fork::Cap {
        fi.rsrclen = resource_len(cfg, path);
    }

    // Fallbacks.
    if fi.type_creator[0..4] == [0; 4] || fi.type_creator[4..8] == [0; 4] {
        fi.type_creator = suffix_type_creator(os_bytes(path.as_os_str()));
    }
    if fi.create_time == [0; 4] || fi.modify_time == [0; 4] {
        if let Ok(meta) = std::fs::metadata(path) {
            if let Some(htime) = meta.modified().ok().and_then(header_time) {
                if fi.create_time == [0; 4] {
                    fi.create_time = htime;
                }
                if fi.modify_time == [0; 4] {
                    fi.modify_time = htime;
                }
            }
        }
    }
    if fi.comment.is_empty() {
        if let Some(c) = &cfg.comment {
            let n = c.len().min(MAX_COMMENT);
            fi.comment = c[..n].to_vec();
        }
    }
    fi
}

fn header_time(time: std::time::SystemTime) -> Option<[u8; 4]> {
    let unix_secs = match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).ok()?,
        Err(error) => i64::try_from(error.duration().as_secs())
            .ok()?
            .checked_neg()?,
    };
    let seconds = unix_secs.checked_sub(HTIME_OFFSET)?;
    Some(i32::try_from(seconds).ok()?.to_be_bytes())
}

fn read_cap_info(f: &mut File, fi: &mut HfsInfo) {
    let mut buf = [0u8; SIZEOF_CAP_INFO];
    if read_exact_or_none(f, &mut buf).ok().flatten().is_none() {
        return;
    }
    if let Some(decoded) = decode_cap_info(&buf) {
        *fi = decoded;
    }
}

/// Decode one fixed-size CAP Finder-info record without performing I/O.
///
/// Capability-oriented consumers use this with file handles they opened
/// relative to their own directory authority, so parsing a sidecar never
/// requires turning an untrusted relative path back into an ambient path.
pub fn decode_cap_info(buf: &[u8]) -> Option<HfsInfo> {
    if buf.len() < SIZEOF_CAP_INFO
        || buf[CAP_OFF_MAGIC1] != CAP_MAGIC1
        || buf[CAP_OFF_VERSION] != CAP_VERSION
        || buf[CAP_OFF_MAGIC] != CAP_MAGIC
    {
        return None;
    }
    let mut fi = HfsInfo::default();
    fi.type_creator
        .copy_from_slice(&buf[CAP_OFF_FNDR..CAP_OFF_FNDR + 8]);
    let datevalid = if buf[CAP_OFF_DATEMAGIC] == CAP_DMAGIC {
        buf[CAP_OFF_DATEVALID]
    } else {
        0
    };
    if datevalid & CAP_CDATE != 0 {
        fi.create_time
            .copy_from_slice(&buf[CAP_OFF_CTIME..CAP_OFF_CTIME + 4]);
    }
    if datevalid & CAP_MDATE != 0 {
        fi.modify_time
            .copy_from_slice(&buf[CAP_OFF_CTIME + 4..CAP_OFF_CTIME + 8]);
    }
    let comln = (buf[CAP_OFF_COMLN] as usize).min(MAX_COMMENT);
    fi.comment = buf[CAP_OFF_COMNT..CAP_OFF_COMNT + comln].to_vec();
    Some(fi)
}

fn read_dbl_info(f: &mut File, fi: &mut HfsInfo) {
    let Ok(Some(descrs)) = read_dbl_descrs(f) else {
        return;
    };
    for d in descrs {
        if f.seek(SeekFrom::Start(d.offset as u64)).is_err() {
            continue;
        }
        match d.id {
            HDR_COMNT => {
                let n = (d.length as usize).min(MAX_COMMENT);
                let mut c = vec![0u8; n];
                if read_exact_or_none(f, &mut c).ok().flatten().is_some() {
                    fi.comment = c;
                }
            }
            HDR_OLDI | HDR_DATES => {
                let mut t = [0u8; 8];
                if read_exact_or_none(f, &mut t).ok().flatten().is_some() {
                    fi.create_time.copy_from_slice(&t[0..4]);
                    fi.modify_time.copy_from_slice(&t[4..8]);
                }
            }
            HDR_FINFO => {
                let mut tc = [0u8; 8];
                if read_exact_or_none(f, &mut tc).ok().flatten().is_some() {
                    fi.type_creator = tc;
                }
            }
            HDR_RSRC => fi.rsrclen = u64::from(d.length),
            _ => {}
        }
    }
}

// ---------- Finder info write ----------

/// Encode the fixed-size CAP `.fndrinfo` record for `fi` without performing
/// I/O.
pub fn encode_cap_info(fi: &HfsInfo) -> [u8; SIZEOF_CAP_INFO] {
    let mut b = [0u8; SIZEOF_CAP_INFO];
    b[CAP_OFF_MAGIC1] = CAP_MAGIC1;
    b[CAP_OFF_VERSION] = CAP_VERSION;
    b[CAP_OFF_MAGIC] = CAP_MAGIC;
    b[CAP_OFF_DATEMAGIC] = CAP_DMAGIC;
    b[CAP_OFF_DATEVALID] = CAP_MDATE | CAP_CDATE;
    b[CAP_OFF_FNDR..CAP_OFF_FNDR + 8].copy_from_slice(&fi.type_creator);
    b[CAP_OFF_CTIME..CAP_OFF_CTIME + 4].copy_from_slice(&fi.create_time);
    b[CAP_OFF_CTIME + 4..CAP_OFF_CTIME + 8].copy_from_slice(&fi.modify_time);
    let comln = fi.comment.len().min(MAX_COMMENT);
    b[CAP_OFF_COMLN] = comln as u8;
    b[CAP_OFF_COMNT..CAP_OFF_COMNT + comln].copy_from_slice(&fi.comment[..comln]);
    b
}

/// Write the Finder metadata for `path` into its sidecar.
///
/// For AppleDouble and Netatalk, [`HfsInfo::rsrclen`] becomes the resource
/// descriptor's length exactly, as in hfs.c, so passing zero forgets a fork
/// that was written. A new container holds no resource bytes yet, so a fork is
/// recorded in two steps: write the metadata with `rsrclen` zero, write the
/// fork through [`resource_open`], then write the metadata again with the
/// fork's [`ResourceFork::len`]. A comment whose length differs from the stored
/// one rewrites the container rather than failing.
pub fn hfsinfo_write(cfg: &Config, path: &Path, fi: &HfsInfo) -> io::Result<()> {
    let info = finderinfo_path(path, cfg.dir_char)?;
    match cfg.fork {
        Fork::Cap => {
            // Like hfs.c: O_RDWR|O_CREAT (no O_TRUNC) — overwrite the first 300
            // bytes from offset 0, leaving any trailing bytes intact.
            let mut f = open_rw_create(&info, cfg.file_perm)?;
            f.write_all(&encode_cap_info(fi))?;
            f.sync_all()?;
            Ok(())
        }
        Fork::Double | Fork::Netatalk => write_dbl_info(cfg, &info, fi),
    }
}

fn write_dbl_info(cfg: &Config, info: &Path, fi: &HfsInfo) -> io::Result<()> {
    let comlen = fi.comment.len().min(MAX_COMMENT) as u32;
    let rsrclen: u32 = fi.rsrclen.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "AppleDouble resource fork exceeds its 32-bit descriptor",
        )
    })?;

    let mut f = open_rw_create(info, cfg.file_perm)?;
    let Some(mut descrs) = read_dbl_descrs(&mut f)? else {
        // A fresh container cannot truthfully advertise resource bytes which
        // have not been written yet.
        if rsrclen != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "new AppleDouble resource fork has no backing bytes",
            ));
        }
        return write_dbl_entries(cfg, &mut f, &fresh_dbl_descrs(comlen), fi);
    };

    let mut has_resource = false;
    for d in &mut descrs {
        if d.id == HDR_RSRC {
            d.length = rsrclen;
            has_resource = true;
        }
    }
    if rsrclen != 0 && !has_resource {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AppleDouble container has no resource-fork descriptor",
        ));
    }
    // The replacement resource length must be backed and must not run into
    // another entry. Check before touching any payload or header byte.
    validate_descrs(&descrs, f.metadata()?.len())?;

    if descrs
        .iter()
        .any(|d| d.id == HDR_COMNT && d.length != comlen)
    {
        return relayout_dbl(cfg, info, f, &descrs, fi, comlen);
    }
    write_dbl_entries(cfg, &mut f, &descrs, fi)
}

/// The table hfs.c writes into a new container: comment, dates and Finder
/// info packed after it, then an empty resource fork at the end, where it can
/// grow.
fn fresh_dbl_descrs(comlen: u32) -> Vec<Descr> {
    const NENTRIES: usize = 4;
    let base = (SIZEOF_DBL_HDR + SIZEOF_HDR_DESCR * NENTRIES) as u32;
    vec![
        Descr {
            id: HDR_COMNT,
            offset: base,
            length: comlen,
        },
        Descr {
            id: HDR_DATES,
            offset: base + comlen,
            length: 8,
        },
        Descr {
            id: HDR_FINFO,
            offset: base + comlen + 8,
            length: 8,
        },
        Descr {
            id: HDR_RSRC,
            offset: base + comlen + 8 + 8,
            length: 0,
        },
    ]
}

/// Write `fi` into the entries `descrs` place, then the header naming them.
/// The caller has already validated `descrs` against the container.
fn write_dbl_entries(cfg: &Config, f: &mut File, descrs: &[Descr], fi: &HfsInfo) -> io::Result<()> {
    let comlen = fi.comment.len().min(MAX_COMMENT);
    // Write each entry's payload at its offset (mirrors hfsinfo_write's loop).
    for d in descrs {
        if f.seek(SeekFrom::Start(d.offset as u64)).is_err() {
            continue;
        }
        match d.id {
            // Write the comment on every call (both the fresh and the existing-
            // header path). hfs.c has a `if (r == SIZEOF_HFS_DBL_HDR) break;`
            // guard here, but `r` is the descriptor-read result (12*entries) on
            // the existing path and the header-read result on the fresh path —
            // never exactly 26 at this point — so the guard is dead and the C
            // always writes the comment.
            HDR_COMNT => {
                f.write_all(&fi.comment[..comlen])?;
            }
            HDR_OLDI | HDR_DATES => {
                let mut t = [0u8; 8];
                t[0..4].copy_from_slice(&fi.create_time);
                t[4..8].copy_from_slice(&fi.modify_time);
                f.write_all(&t)?;
            }
            HDR_FINFO => {
                f.write_all(&fi.type_creator)?;
            }
            HDR_RSRC => {}
            _ => {}
        }
    }

    // Header (magic + version + descriptor table) last.
    let version = if cfg.fork == Fork::Netatalk {
        HDR_VERSION_1
    } else {
        HDR_VERSION_2
    };
    let mut hdr = vec![0u8; SIZEOF_DBL_HDR + SIZEOF_HDR_DESCR * descrs.len()];
    hdr[0..4].copy_from_slice(&DBL_MAGIC.to_be_bytes());
    hdr[4..8].copy_from_slice(&version.to_be_bytes());
    hdr[24..26].copy_from_slice(&(descrs.len() as u16).to_be_bytes());
    for (i, d) in descrs.iter().enumerate() {
        d.write_bytes(&mut hdr[SIZEOF_DBL_HDR + SIZEOF_HDR_DESCR * i..]);
    }
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&hdr)?;
    f.sync_all()?;
    Ok(())
}

/// Rewrite a container whose comment changes length, since the entries after
/// it cannot move in place. Entries are packed in table order with the
/// resource fork last, so it can still grow. Entries this module does not own
/// are copied byte for byte, and Finder info or dates longer than the eight
/// bytes written here keep their tails. The rewrite goes to a scratch file
/// that replaces the container only once it is complete, so a failure leaves
/// the original untouched. The resource fork is copied as well: that is the
/// cost of a comment edit, which is rare next to the transfers that write forks.
fn relayout_dbl(
    cfg: &Config,
    info: &Path,
    mut old: File,
    descrs: &[Descr],
    fi: &HfsInfo,
    comlen: u32,
) -> io::Result<()> {
    let mut placed = descrs.to_vec();
    let resource_last = (0..placed.len())
        .filter(|&i| placed[i].id != HDR_RSRC)
        .chain((0..placed.len()).filter(|&i| placed[i].id == HDR_RSRC))
        .collect::<Vec<_>>();
    let mut next = (SIZEOF_DBL_HDR + SIZEOF_HDR_DESCR * placed.len()) as u64;
    for i in resource_last {
        if placed[i].id == HDR_COMNT {
            placed[i].length = comlen;
        }
        placed[i].offset = u32::try_from(next).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "relaid-out AppleDouble container exceeds its 32-bit offsets",
            )
        })?;
        next += u64::from(placed[i].length);
    }

    let scratch = relayout_path(info);
    let result = (|| -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        with_mode(&mut opts, cfg.file_perm);
        let mut new = opts.open(&scratch)?;
        for (from, to) in descrs.iter().zip(&placed) {
            if to.id == HDR_COMNT || to.length == 0 {
                continue;
            }
            old.seek(SeekFrom::Start(u64::from(from.offset)))?;
            new.seek(SeekFrom::Start(u64::from(to.offset)))?;
            let copied = io::copy(&mut (&mut old).take(u64::from(to.length)), &mut new)?;
            if copied != u64::from(to.length) {
                return Err(invalid_appledouble(
                    "AppleDouble container shrank during relayout",
                ));
            }
        }
        write_dbl_entries(cfg, &mut new, &placed, fi)
    })();
    drop(old);
    let result = result.and_then(|()| std::fs::rename(&scratch, info));
    if result.is_err() {
        let _ = std::fs::remove_file(&scratch);
    }
    result
}

/// A scratch sibling for [`relayout_dbl`], unique within this process so two
/// rewrites never share one. `create_new` keeps it from clobbering anything.
fn relayout_path(info: &Path) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut name = info.as_os_str().to_owned();
    name.push(format!(
        ".{}-{}.relayout",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    PathBuf::from(name)
}

// ---------- comment ----------

/// The Finder comment length stored for `path` (`<= MAX_COMMENT`), falling back
/// to `cfg.comment`'s length.
pub fn comment_len(cfg: &Config, path: &Path) -> usize {
    let mut len = 0usize;
    if let Ok(info) = finderinfo_path(path, cfg.dir_char) {
        if let Ok(mut f) = File::open(&info) {
            len = match cfg.fork {
                Fork::Cap => {
                    let mut buf = [0u8; SIZEOF_CAP_INFO];
                    if read_exact_or_none(&mut f, &mut buf)
                        .ok()
                        .flatten()
                        .is_some()
                    {
                        (buf[CAP_OFF_COMLN] as usize).min(MAX_COMMENT)
                    } else {
                        0
                    }
                }
                Fork::Double | Fork::Netatalk => read_dbl_descrs(&mut f)
                    .ok()
                    .flatten()
                    .map(|ds| {
                        ds.iter()
                            .filter(|d| d.id == HDR_COMNT)
                            .map(|d| (d.length as usize).min(MAX_COMMENT))
                            .next_back()
                            .unwrap_or(0)
                    })
                    .unwrap_or(0),
            };
        }
    }
    if len == 0 {
        if let Some(c) = &cfg.comment {
            len = c.len().min(MAX_COMMENT);
        }
    }
    len
}

/// Write a Finder comment for `path`. Like `hfs.c`, only the CAP layout is
/// supported (AppleDouble / Netatalk are a no-op).
pub fn comment_write(cfg: &Config, path: &Path, comment: &[u8]) -> io::Result<()> {
    if cfg.fork != Fork::Cap {
        return Ok(());
    }
    let info = finderinfo_path(path, cfg.dir_char)?;
    let comlen = comment.len().min(MAX_COMMENT);

    let mut f = open_rw_create(&info, cfg.file_perm)?;
    // Preserve an existing record, or synthesize a fresh one with suffix-derived
    // type/creator (matching hfs.c's comment_write).
    let mut buf = [0u8; SIZEOF_CAP_INFO];
    if read_exact_or_none(&mut f, &mut buf)
        .ok()
        .flatten()
        .is_none()
        || decode_cap_info(&buf).is_none()
    {
        buf = [0u8; SIZEOF_CAP_INFO];
        buf[CAP_OFF_MAGIC1] = CAP_MAGIC1;
        buf[CAP_OFF_VERSION] = CAP_VERSION;
        buf[CAP_OFF_MAGIC] = CAP_MAGIC;
        buf[CAP_OFF_DATEMAGIC] = CAP_DMAGIC;
        let tc = suffix_type_creator(os_bytes(path.as_os_str()));
        buf[CAP_OFF_FNDR..CAP_OFF_FNDR + 8].copy_from_slice(&tc);
    }
    buf[CAP_OFF_COMLN] = comlen as u8;
    buf[CAP_OFF_COMNT..CAP_OFF_COMNT + comlen].copy_from_slice(&comment[..comlen]);
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&buf)?;
    f.sync_all()?;
    Ok(())
}

// ---------- resource fork ----------

/// Explicit open policy for [`resource_open`].
///
/// `std::fs::OpenOptions` deliberately exposes no accessors. Keeping the
/// policy here lets AppleDouble open its container without applying
/// destructive whole-file options such as `truncate` to an embedded fork.
#[derive(Clone, Debug, Default)]
pub struct ResourceOpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    mode: Option<u32>,
    #[cfg(unix)]
    custom_flags: i32,
}

impl ResourceOpenOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }

    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }

    pub fn append(&mut self, append: bool) -> &mut Self {
        self.append = append;
        self
    }

    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }

    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }

    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }

    pub fn mode(&mut self, mode: u32) -> &mut Self {
        self.mode = Some(mode);
        self
    }

    #[cfg(unix)]
    pub fn custom_flags(&mut self, flags: i32) -> &mut Self {
        self.custom_flags = flags;
        self
    }

    fn std_options(&self, embedded: bool) -> io::Result<OpenOptions> {
        #[cfg(unix)]
        let has_custom_flags = self.custom_flags != 0;
        #[cfg(not(unix))]
        let has_custom_flags = false;
        // `create` is accepted for an embedded fork and not applied. The fork
        // lives inside a container `hfsinfo_write` makes, so a missing
        // container means no fork, where hfs.c's O_CREAT left an empty,
        // unreadable one behind and failed anyway. Callers ported from open(2)
        // pass O_CREAT for every fork (mhxd and GtkHx both do), so refusing it
        // would refuse them. Options that could rewrite the whole container
        // are still refused.
        if embedded && (self.truncate || self.append || self.create_new || has_custom_flags) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "whole-file or raw open options are not valid for an embedded resource fork",
            ));
        }
        let mut opts = OpenOptions::new();
        // Parsing an embedded descriptor table needs read access internally.
        // ResourceFork still enforces the caller's requested access below.
        opts.read(self.read || embedded)
            .write(self.write || self.append)
            .append(self.append)
            .truncate(self.truncate)
            .create(self.create && !embedded)
            .create_new(self.create_new);
        if let Some(mode) = self.mode {
            with_mode(&mut opts, mode);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(self.custom_flags);
        }
        Ok(opts)
    }
}

/// An open resource fork whose seek coordinates are relative to the fork.
///
/// For CAP this is a normal file with base zero. For AppleDouble and Netatalk
/// it prevents resumed transfers from interpreting a fork offset as a
/// container offset and overwriting the header.
#[derive(Debug)]
pub struct ResourceFork {
    file: File,
    start: u64,
    position: u64,
    length: u64,
    readable: bool,
    writable: bool,
    append: bool,
    max_length: u64,
}

impl ResourceFork {
    fn new(
        mut file: File,
        start: u64,
        length: u64,
        readable: bool,
        writable: bool,
        append: bool,
        max_length: u64,
    ) -> io::Result<Self> {
        if length > max_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource-fork length exceeds its storage format",
            ));
        }
        let position = if append { length } else { 0 };
        let physical = start.checked_add(position).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "resource-fork seek overflows")
        })?;
        file.seek(SeekFrom::Start(physical))?;
        Ok(Self {
            file,
            start,
            position,
            length,
            readable,
            writable,
            append,
            max_length,
        })
    }

    /// Recover the underlying file at its current physical position.
    ///
    /// This exists for compatibility shims that hand an already-positioned
    /// descriptor to legacy code. Native callers should retain ResourceFork so
    /// seeks remain fork-relative.
    pub fn into_file(self) -> File {
        self.file
    }

    /// The fork's length, including bytes written through this handle. An
    /// AppleDouble descriptor changes only when this is recorded with
    /// [`hfsinfo_write`].
    pub fn len(&self) -> u64 {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    fn physical_offset(&self, logical: u64) -> io::Result<u64> {
        self.start.checked_add(logical).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "resource-fork seek overflows")
        })
    }
}

impl Read for ResourceFork {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.readable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "resource fork was not opened for reading",
            ));
        }
        let remaining = self.length.saturating_sub(self.position);
        let limit = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        if limit == 0 {
            return Ok(0);
        }
        let n = self.file.read(&mut buf[..limit])?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Write for ResourceFork {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "resource fork was not opened for writing",
            ));
        }
        if self.append {
            self.position = self.length;
            let physical = self.physical_offset(self.position)?;
            self.file.seek(SeekFrom::Start(physical))?;
        }
        let limit = usize::try_from(
            self.max_length
                .saturating_sub(self.position)
                .min(buf.len() as u64),
        )
        .unwrap_or(buf.len());
        if limit == 0 {
            return Ok(0);
        }
        let n = self.file.write(&buf[..limit])?;
        self.position = self.position.checked_add(n as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource-fork position overflows",
            )
        })?;
        self.length = self.length.max(self.position);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for ResourceFork {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let logical = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(delta) => self.length.checked_add_signed(delta).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "resource-fork seek is out of range",
                )
            })?,
            SeekFrom::Current(delta) => {
                self.position.checked_add_signed(delta).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "resource-fork seek is out of range",
                    )
                })?
            }
        };
        if logical > self.max_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource-fork seek exceeds its storage format",
            ));
        }
        let physical = self.physical_offset(logical)?;
        self.file.seek(SeekFrom::Start(physical))?;
        self.position = logical;
        Ok(logical)
    }
}

/// The resource fork length for `path` (CAP: the `.rsrc` file size; AppleDouble:
/// the RSRC descriptor's length).
pub fn resource_len(cfg: &Config, path: &Path) -> u64 {
    match cfg.fork {
        Fork::Cap => resource_path(path, cfg.dir_char)
            .ok()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0),
        Fork::Double | Fork::Netatalk => {
            let Ok(info) = finderinfo_path(path, cfg.dir_char) else {
                return 0;
            };
            let Ok(mut f) = File::open(&info) else {
                return 0;
            };
            read_dbl_descrs(&mut f)
                .ok()
                .flatten()
                .and_then(|ds| {
                    ds.iter()
                        .find(|d| d.id == HDR_RSRC)
                        .map(|d| d.length as u64)
                })
                .unwrap_or(0)
        }
    }
}

/// Open the resource fork for `path` using the caller-provided `opts`, or return
/// `None` if there is no resource fork.
///
/// `opts` carries the full open policy. Destructive whole-file options are
/// rejected for AppleDouble and Netatalk because their resource fork is only
/// one region of the container; `create` is accepted there but never makes a
/// container. A missing file (when `opts` doesn't create) yields `None`, not
/// an error (the C returns -1 and the caller skips the fork).
///
/// Writing an AppleDouble fork does not record its length. Pass
/// [`ResourceFork::len`] to [`hfsinfo_write`] once the fork is written.
pub fn resource_open(
    cfg: &Config,
    path: &Path,
    opts: &ResourceOpenOptions,
) -> io::Result<Option<ResourceFork>> {
    match cfg.fork {
        Fork::Cap => {
            let rsrc = resource_path(path, cfg.dir_char)?;
            let std_opts = opts.std_options(false)?;
            let Some(f) = open_or_none(&std_opts, &rsrc)? else {
                return Ok(None);
            };
            let len = f.metadata()?.len();
            Ok(Some(ResourceFork::new(
                f,
                0,
                len,
                opts.read,
                opts.write || opts.append,
                opts.append,
                u64::MAX,
            )?))
        }
        Fork::Double | Fork::Netatalk => {
            let info = finderinfo_path(path, cfg.dir_char)?;
            let std_opts = opts.std_options(true)?;
            let Some(mut f) = open_or_none(&std_opts, &info)? else {
                return Ok(None);
            };
            let Some(descrs) = read_dbl_descrs(&mut f)? else {
                return Ok(None);
            };
            let file_len = f.metadata()?.len();
            for d in descrs {
                if d.id == HDR_RSRC {
                    let end = u64::from(d.offset) + u64::from(d.length);
                    return Ok(Some(ResourceFork::new(
                        f,
                        u64::from(d.offset),
                        u64::from(d.length),
                        opts.read,
                        opts.write || opts.append,
                        false,
                        if end == file_len {
                            u64::from(u32::MAX)
                        } else {
                            u64::from(d.length)
                        },
                    )?));
                }
            }
            Ok(None)
        }
    }
}

/// Open `path` with `opts`, mapping a missing *target file* to `Ok(None)` — the
/// "no resource fork, skip" case. A `NotFound` whose *parent directory* is what's
/// missing is a real error (a wrong path, or a create that can't land) and is
/// propagated rather than silently swallowed.
fn open_or_none(opts: &OpenOptions, path: &Path) -> io::Result<Option<File>> {
    match opts.open(path) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => match path.parent() {
            // Parent exists (or is the implicit cwd) → the file itself is
            // missing: the documented skip case.
            Some(dir) if !dir.as_os_str().is_empty() && !dir.exists() => Err(e),
            _ => Ok(None),
        },
        Err(e) => Err(e),
    }
}

// ---------- open helpers ----------

fn open_rw_create(path: &Path, perm: u32) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    with_mode(&mut opts, perm);
    opts.open(path)
}

#[cfg(test)]
mod tests;
