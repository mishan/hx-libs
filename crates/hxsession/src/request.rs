//! The requests a session sends, as owned values.
//!
//! Where hxproto has a builder for an opcode it is used, so these are the
//! bytes GtkHx sends; the builders are shaped for a C caller, and
//! [`Request::from_built`] copies what one filled into something that owns
//! its bytes.

use hxproto::build::{self, HxChunk, PackChunk};
use hxproto::messages::{tag, ClientHdr};

/// One request: the transaction type and its fields, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub opcode: u32,
    pub fields: Vec<(u16, Vec<u8>)>,
}

impl Request {
    pub fn new(opcode: u32) -> Self {
        Request {
            opcode,
            fields: Vec::new(),
        }
    }

    pub fn field(mut self, tag: u16, data: impl Into<Vec<u8>>) -> Self {
        self.fields.push((tag, data.into()));
        self
    }

    /// Copy what an hxproto builder filled. `hc` is its return: the number
    /// of chunks filled, or 0 when it refused the input.
    fn from_built(opcode: ClientHdr, chunks: &[HxChunk], hc: usize) -> Option<Self> {
        if hc == 0 {
            return None;
        }
        let fields = chunks[..hc]
            .iter()
            .map(|c| {
                let data = if c.data.is_null() || c.len == 0 {
                    Vec::new()
                } else {
                    // SAFETY: the builder pointed `data` at `len` bytes of an
                    // input or scratch buffer that outlives this call.
                    unsafe { std::slice::from_raw_parts(c.data, c.len as usize) }.to_vec()
                };
                (c.tag, data)
            })
            .collect();
        Some(Request {
            opcode: opcode as u32,
            fields,
        })
    }

    /// The whole frame for transaction `trans`, or `None` if a field is
    /// longer than its 16-bit length can say or there are too many.
    pub fn pack(&self, trans: u32) -> Option<Vec<u8>> {
        let chunks: Vec<PackChunk<'_>> = self
            .fields
            .iter()
            .map(|(tag, data)| PackChunk { tag: *tag, data })
            .collect();
        let mut out = vec![0u8; build::pack_message_size(&chunks)];
        let n = build::pack_message(&mut out, self.opcode, trans, 0, &chunks)?;
        out.truncate(n);
        Some(out)
    }
}

/// The Hotline credential obfuscation: every byte inverted.
fn obfuscate(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| !x).collect()
}

/// Longest login or password sent, as GtkHx caps them.
const MAX_CREDENTIAL: usize = 64;

/// LOGIN (107), as GtkHx sends it on the plain path: the login always,
/// everything else only when it says something. The nickname is not sent
/// here — it goes with the agreement, or in a user change to a server too
/// old for one — which is what every server GtkHx is tested against
/// expects.
pub fn login(login: &[u8], password: &[u8], icon: u16, version: u16, caps: u16) -> Request {
    let login = &login[..login.len().min(MAX_CREDENTIAL)];
    let password = &password[..password.len().min(MAX_CREDENTIAL)];
    let mut r = Request::new(ClientHdr::Login as u32).field(tag::LOGIN, obfuscate(login));
    if !password.is_empty() {
        r = r.field(tag::PASSWORD, obfuscate(password));
    }
    if icon != 0 {
        r = r.field(tag::ICON, icon.to_be_bytes());
    }
    if version != 0 {
        r = r.field(tag::VERSION, version.to_be_bytes());
    }
    if caps != 0 {
        r = r.field(tag::CAPABILITIES, caps.to_be_bytes());
    }
    r
}

/// AGREEMENTAGREE (121): icon, name and options, always all three —
/// Mobius drops a client whose agree leaves the options out.
pub fn agree(name: &[u8], icon: u16) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY, HxChunk::EMPTY, HxChunk::EMPTY];
    let mut scratch = [0u8; 4];
    let req = build::AgreementAgreeRequest {
        icon,
        display_name: name,
        options: 0,
    };
    let hc = build::build_agreement_agree_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::AgreementAgree, &chunks, hc)
}

/// USER_CHANGE (304): the name and icon others see.
pub fn user_change(name: &[u8], icon: u16) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY, HxChunk::EMPTY, HxChunk::EMPTY];
    let mut scratch = [0u8; 6];
    let req = build::UserChangeRequest {
        icon,
        name,
        nick_color: None,
    };
    let hc = build::build_user_change_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::UserChange, &chunks, hc)
}

/// CHAT (105) to the public chat (`cid` 0) or a private one. `style` 1 is
/// an emote.
pub fn chat(body: &[u8], cid: u32, style: u16) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY, HxChunk::EMPTY, HxChunk::EMPTY];
    let mut scratch = [0u8; 6];
    let req = build::ChatRequest { cid, style, body };
    let hc = build::build_chat_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::Chat, &chunks, hc)
}

/// CHAT_CREATE (112): a private chat with `uid`.
pub fn chat_create(uid: u16) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY];
    let mut scratch = [0u8; 2];
    let hc = build::build_chat_create_chunks(uid, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::ChatCreate, &chunks, hc)
}

/// CHAT_INVITE (113): `uid` into chat `cid`.
pub fn chat_invite(cid: u32, uid: u16) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY, HxChunk::EMPTY];
    let mut scratch = [0u8; 6];
    let hc = build::build_chat_invite_chunks(cid, uid, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::ChatInvite, &chunks, hc)
}

/// CHAT_JOIN (115), CHAT_PART (116) or CHAT_DECLINE (114), which carry
/// only the chat.
pub fn chat_id_only(opcode: ClientHdr, cid: u32) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY];
    let mut scratch = [0u8; 4];
    let hc = build::build_chat_join_chunks(cid, &mut chunks, &mut scratch);
    Request::from_built(opcode, &chunks, hc)
}

/// CHAT_SUBJECT (120).
pub fn chat_subject(cid: u32, subject: &[u8]) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY, HxChunk::EMPTY];
    let mut scratch = [0u8; 4];
    let req = build::ChatSubjectRequest { cid, subject };
    let hc = build::build_chat_subject_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::ChatSubject, &chunks, hc)
}

/// GET_CHAT_HISTORY (700); a cursor or limit of 0 is left out.
pub fn chat_history(cid: u32, before: u64, after: u64, limit: u16) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY; 4];
    let mut scratch = [0u8; 22];
    let req = build::GetChatHistoryRequest {
        channel_id: cid,
        before,
        after,
        limit,
    };
    let hc = build::build_get_chat_history_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::GetChatHistory, &chunks, hc)
}

/// MSG (108): a private message.
pub fn msg(uid: u16, body: &[u8]) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY, HxChunk::EMPTY];
    let mut scratch = [0u8; 2];
    let req = build::MsgRequest { uid, body };
    let hc = build::build_msg_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::Msg, &chunks, hc)
}

/// USER_GETINFO (303).
pub fn user_info(uid: u16) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY];
    let mut scratch = [0u8; 2];
    let hc = build::build_user_getinfo_chunks(uid, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::UserGetInfo, &chunks, hc)
}

/// NEWS_POST (103): add to 1.2 flat news.
pub fn news_post(body: &[u8]) -> Option<Request> {
    let mut chunks = [HxChunk::EMPTY];
    let hc = build::build_news_post_chunks(body, &mut chunks);
    Request::from_built(ClientHdr::NewsPost, &chunks, hc)
}

/// Encode a path as a file DIR or a threaded-news path: a count, then
/// per component two zero bytes, a length byte and the name. Empty
/// components are skipped, as GtkHx skips them.
///
/// `None` when a component is longer than its length byte can say, or
/// the whole is longer than a field can hold. Cutting it to fit instead
/// would name some other folder — a sibling that shares the first 255
/// bytes, or an ancestor — and list that as if it were the one asked for.
pub fn path(components: &[&[u8]]) -> Option<Vec<u8>> {
    let mut out = vec![0u8, 0u8];
    let mut count: u16 = 0;
    for part in components.iter().filter(|p| !p.is_empty()) {
        let len = u8::try_from(part.len()).ok()?;
        out.extend_from_slice(&[0, 0, len]);
        out.extend_from_slice(part);
        count = count.checked_add(1)?;
    }
    if out.len() > u16::MAX as usize {
        return None;
    }
    out[..2].copy_from_slice(&count.to_be_bytes());
    Some(out)
}

/// FILE_LIST (200) for a folder; the root is `&[]`. The folder always
/// goes as a DIR, an empty one for the root, as GtkHx sends it.
pub fn file_list(path: &[&[u8]]) -> Option<Request> {
    let encoded = self::path(path)?;
    let mut chunks = [HxChunk::EMPTY];
    let hc = build::build_file_list_chunks(&encoded, &mut chunks);
    Request::from_built(ClientHdr::FileList, &chunks, hc)
}

/// The DIR of the folder at `path`, or none for the root, which GtkHx
/// leaves out of the requests that name an item in its own field. `None`
/// when the path is too long to send.
fn dir_below_root(path: &[&[u8]]) -> Option<Option<Vec<u8>>> {
    if path.iter().all(|p| p.is_empty()) {
        return Some(None);
    }
    self::path(path).map(Some)
}

/// FILE_GETINFO (206): `name`, in the folder at `path`.
pub fn file_info(path: &[&[u8]], name: &[u8]) -> Option<Request> {
    let dir = dir_below_root(path)?;
    let mut chunks = [HxChunk::EMPTY; 2];
    let hc = build::build_file_getinfo_chunks(name, dir.as_deref(), &mut chunks);
    Request::from_built(ClientHdr::FileGetInfo, &chunks, hc)
}

/// FILE_MKDIR (205): folder `name`, in the folder at `path`. The new
/// folder is named by the DIR alone, its whole path.
pub fn file_mkdir(path: &[&[u8]], name: &[u8]) -> Option<Request> {
    let encoded = self::path(&[path, &[name]].concat())?;
    let mut chunks = [HxChunk::EMPTY];
    let hc = build::build_file_mkdir_chunks(&encoded, &mut chunks);
    Request::from_built(ClientHdr::FileMkdir, &chunks, hc)
}

/// FILE_DELETE (204): `name`, in the folder at `path`. GtkHx names its
/// folder even at the root, with an empty DIR.
pub fn file_delete(path: &[&[u8]], name: &[u8]) -> Option<Request> {
    let encoded = self::path(path)?;
    let mut chunks = [HxChunk::EMPTY; 2];
    let hc = build::build_file_delete_chunks(name, Some(&encoded), &mut chunks);
    Request::from_built(ClientHdr::FileDelete, &chunks, hc)
}

/// FILE_SETINFO (207): rename `name`, in the folder at `path`, and set
/// its comment, each when given; the folder goes as for a delete. A
/// rename to the name it has goes as none: Janus 2.0.13 and earlier
/// refuse it, and the comment with it.
pub fn file_set_info(
    path: &[&[u8]],
    name: &[u8],
    rename: Option<&[u8]>,
    comment: Option<&[u8]>,
) -> Option<Request> {
    let encoded = self::path(path)?;
    let req = build::FileSetInfoRequest {
        name,
        rename: rename.filter(|r| *r != name),
        comment,
        dir: Some(&encoded),
    };
    let mut chunks = [HxChunk::EMPTY; 4];
    let hc = build::build_file_setinfo_chunks(&req, &mut chunks);
    Request::from_built(ClientHdr::FileSetInfo, &chunks, hc)
}

/// FILE_MOVE (208): `name`, from the folder at `path` into the one at
/// `to`, keeping its name. Both folders always go, the root as an empty
/// DIR.
pub fn file_move(path: &[&[u8]], name: &[u8], to: &[&[u8]]) -> Option<Request> {
    let (from, to) = (self::path(path)?, self::path(to)?);
    let req = build::FileMoveRequest {
        name,
        dir: &from,
        dir_rename: &to,
    };
    let mut chunks = [HxChunk::EMPTY; 3];
    let hc = build::build_file_move_chunks(&req, &mut chunks);
    Request::from_built(ClientHdr::FileMove, &chunks, hc)
}

/// FILE_GET (202): download `name`, in the folder at `path`, from the
/// start.
pub fn file_download(path: &[&[u8]], name: &[u8]) -> Option<Request> {
    let dir = dir_below_root(path)?;
    let req = build::FileGetRequest {
        name,
        dir: dir.as_deref(),
        rflt: None,
    };
    let mut chunks = [HxChunk::EMPTY; 3];
    let hc = build::build_file_get_chunks(&req, &mut chunks);
    Request::from_built(ClientHdr::FileGet, &chunks, hc)
}

/// FILE_PUT (203): upload `size` bytes as `name`, into the folder at
/// `path`. The classic size field stops at 4 GiB; with `large` (the
/// server agreed to Large Files) the exact size goes beside it.
pub fn file_upload(path: &[&[u8]], name: &[u8], size: u64, large: bool) -> Option<Request> {
    let dir = dir_below_root(path)?;
    let req = build::FilePutRequest {
        name,
        dir: dir.as_deref(),
        has_preview: false,
        size: size.min(u64::from(u32::MAX)) as u32,
        size64: large.then_some(size),
    };
    let mut chunks = [HxChunk::EMPTY; 5];
    let mut scratch = [0u8; 12];
    let hc = build::build_file_put_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::FilePut, &chunks, hc)
}

/// FILE_GETFOLDER (210): download folder `name`, in the folder at `path`.
pub fn folder_download(path: &[&[u8]], name: &[u8]) -> Option<Request> {
    let dir = dir_below_root(path)?;
    let mut chunks = [HxChunk::EMPTY; 2];
    let hc = build::build_file_getfolder_chunks(name, dir.as_deref(), &mut chunks);
    Request::from_built(ClientHdr::FileGetFolder, &chunks, hc)
}

/// FILE_PUTFOLDER (213): upload folder `name`, of `items` files and
/// `size` bytes in all, into the folder at `path`. The server shows the
/// totals in its queue; the size stops at 4 GiB.
pub fn folder_upload(path: &[&[u8]], name: &[u8], size: u64, items: u32) -> Option<Request> {
    let dir = dir_below_root(path)?;
    let req = build::FilePutFolderRequest {
        name,
        dir: dir.as_deref(),
        size: size.min(u64::from(u32::MAX)) as u32,
        nfiles: items,
    };
    let mut chunks = [HxChunk::EMPTY; 4];
    let mut scratch = [0u8; 8];
    let hc = build::build_file_putfolder_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::FilePutFolder, &chunks, hc)
}

/// NEWS_LISTDIR (370) or NEWS_LISTCATEGORY (371). The root is asked for
/// with no path at all.
pub fn news_list(opcode: ClientHdr, path: &[&[u8]]) -> Option<Request> {
    let mut r = Request::new(opcode as u32);
    if !path.is_empty() {
        r = r.field(tag::NEWSPATH, self::path(path)?);
    }
    Some(r)
}

/// GETTHREAD (400): one article, as text.
pub fn news_article(path: &[&[u8]], id: u32) -> Option<Request> {
    let encoded = self::path(path)?;
    let mut chunks = [HxChunk::EMPTY, HxChunk::EMPTY, HxChunk::EMPTY];
    let mut scratch = [0u8; 4];
    let req = build::NewsGetThreadRequest {
        path: &encoded,
        threadid: id,
        mime_type: b"text/plain",
    };
    let hc = build::build_news_getthread_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::GetThread, &chunks, hc)
}

/// POSTTHREAD (410): an article, in reply to `parent`, or 0 to start a
/// thread; plain text, with no flags, as GtkHx posts it.
pub fn news_post_article(
    path: &[&[u8]],
    parent: u32,
    subject: &[u8],
    text: &[u8],
) -> Option<Request> {
    let encoded = self::path(path)?;
    let mut chunks = [HxChunk::EMPTY; 6];
    let mut scratch = [0u8; 8];
    let req = build::NewsPostThreadRequest {
        path: &encoded,
        flags: 0,
        mime_type: b"text/plain",
        subject,
        text,
        thread_id: parent,
    };
    let hc = build::build_news_post_thread_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::PostThread, &chunks, hc)
}

/// DELETETHREAD (411): one article.
pub fn news_delete_article(path: &[&[u8]], id: u32) -> Option<Request> {
    let encoded = self::path(path)?;
    let mut chunks = [HxChunk::EMPTY; 2];
    let mut scratch = [0u8; 4];
    let req = build::NewsDeleteThreadRequest {
        path: &encoded,
        threadid: id,
    };
    let hc = build::build_news_delete_thread_chunks(&req, &mut chunks, &mut scratch);
    Request::from_built(ClientHdr::DeleteThread, &chunks, hc)
}

/// DELNEWSDIRCAT (380): a bundle or a category.
pub fn news_delete(path: &[&[u8]]) -> Option<Request> {
    let encoded = self::path(path)?;
    let mut chunks = [HxChunk::EMPTY];
    let hc = build::build_news_delete_chunks(&encoded, &mut chunks);
    Request::from_built(ClientHdr::NewsDelete, &chunks, hc)
}

/// MAKENEWSDIR (381): bundle `name`, in the bundle at `path`.
pub fn news_create_bundle(path: &[&[u8]], name: &[u8]) -> Option<Request> {
    let encoded = self::path(path)?;
    let mut chunks = [HxChunk::EMPTY; 2];
    let req = build::NewsMakeDirRequest {
        path: &encoded,
        name,
    };
    let hc = build::build_news_mkdir_chunks(&req, &mut chunks);
    Request::from_built(ClientHdr::NewsMkdir, &chunks, hc)
}

/// MAKECATEGORY (382): category `name`, in the bundle at `path`.
pub fn news_create_category(path: &[&[u8]], name: &[u8]) -> Option<Request> {
    let encoded = self::path(path)?;
    let mut chunks = [HxChunk::EMPTY; 2];
    let req = build::NewsMakeCategoryRequest {
        path: &encoded,
        name,
    };
    let hc = build::build_news_mkcat_chunks(&req, &mut chunks);
    Request::from_built(ClientHdr::NewsMkCategory, &chunks, hc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_says_only_what_it_has() {
        let r = login(b"", b"", 0, 0, 0);
        assert_eq!(r.fields, vec![(tag::LOGIN, vec![])]);
        let r = login(b"ab", b"c", 414, 254, 2);
        assert_eq!(
            r.fields,
            vec![
                (tag::LOGIN, vec![!b'a', !b'b']),
                (tag::PASSWORD, vec![!b'c']),
                (tag::ICON, 414u16.to_be_bytes().to_vec()),
                (tag::VERSION, 254u16.to_be_bytes().to_vec()),
                (tag::CAPABILITIES, 2u16.to_be_bytes().to_vec()),
            ]
        );
    }

    #[test]
    fn agree_always_carries_options() {
        let r = agree(b"nick", 7).unwrap();
        assert_eq!(r.opcode, 121);
        assert!(r.fields.contains(&(tag::OPTIONS, vec![0, 0])));
        assert!(r.fields.contains(&(tag::NAME, b"nick".to_vec())));
    }

    #[test]
    fn a_frame_packs_with_its_field_count() {
        let bytes = msg(3, b"hi").unwrap().pack(9).unwrap();
        let h = hxproto::parse::Header::parse(&bytes).unwrap();
        assert_eq!((h.type_, h.trans, h.hc), (108, 9, 2));
        assert_eq!(h.len as usize, bytes.len() - 20);
        assert_eq!(h.len, h.len2);
    }

    #[test]
    fn news_paths_encode_like_file_paths() {
        assert_eq!(path(&[]), Some(vec![0, 0]));
        assert_eq!(
            path(&[b"News", b"", b"Misc"]).unwrap(),
            [&[0, 2, 0, 0, 4][..], b"News", &[0, 0, 4], b"Misc"].concat()
        );
        // A component too long for its length byte is refused, not cut.
        assert_eq!(path(&[&[b'a'; 256]]), None);
        assert!(path(&[&[b'a'; 255]]).is_some());
        // The root is no path at all.
        assert!(news_list(ClientHdr::NewsListDir, &[])
            .unwrap()
            .fields
            .is_empty());
    }
}
