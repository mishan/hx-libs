//! The reason codes the Structured Chat draft (`Capabilities-Structured-Chat.md`,
//! not adopted) defines for its family of drafts, in
//! [`tag::CHAT_REASON`](crate::messages::tag::CHAT_REASON). The drafts
//! built on it add codes of their own beside these, as
//! [`crate::reactions`] does.

pub const OK: u16 = 0;
/// The target does not exist, was removed, or is out of the caller's
/// reach, which are not told apart.
pub const NO_SUCH_TARGET: u16 = 1;
pub const NOT_ALLOWED: u16 = 2;
pub const RATE_LIMITED: u16 = 6;
/// A malformed target, or a kind the server does not accept.
pub const INVALID_TARGET: u16 = 12;
pub const TOO_MANY_TARGETS: u16 = 13;
