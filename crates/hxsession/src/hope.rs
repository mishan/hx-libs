//! What the session needs of HOPE, behind the `hope` feature. Without it
//! the types are empty, so the byte path that would run through a HOPE
//! transport is the same code, and never has one.

#[cfg(feature = "hope")]
mod with {
    pub use hxhope::{Negotiated, Transport};

    /// HOPE's offer and its randomness, until step 2 goes.
    pub type Pending = (hxhope::client::Offer, hxhope::Random);

    pub fn step1(p: &Pending, trans: u32) -> Result<Vec<u8>, String> {
        hxhope::client::step1(&p.0, trans).map_err(|e| e.to_string())
    }

    /// Step 2, the transport after it, and what was agreed.
    pub fn step2(
        p: Pending,
        reply: &[u8],
        who: &hxhope::client::Login<'_>,
        trans: u32,
    ) -> Result<(Vec<u8>, Transport, Negotiated), String> {
        let (offer, random) = p;
        let est =
            hxhope::client::step2(&offer, reply, who, trans, random).map_err(|e| e.to_string())?;
        Ok((est.step2, est.transport, est.negotiated))
    }

    pub use hxhope::client::Login;
}

#[cfg(not(feature = "hope"))]
mod with {
    use std::convert::Infallible;

    pub enum Transport {}
    pub enum Pending {}

    impl Transport {
        pub fn encode(&mut self, _: &[u8]) -> Result<Vec<u8>, Infallible> {
            match *self {}
        }
        pub fn decode(&mut self, _: &[u8], _: &mut Vec<u8>) -> Result<(), Infallible> {
            match *self {}
        }
        pub fn idle(&self) -> bool {
            match *self {}
        }
    }

    pub fn step1(p: &Pending, _: u32) -> Result<Vec<u8>, String> {
        match *p {}
    }
}

pub(crate) use with::*;
