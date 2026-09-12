//! Safe, consumer-neutral HFS metadata sidecar support.
//!
//! This crate preserves the CAP, AppleDouble, and Netatalk layouts used by
//! classic Hotline clients. Process-global configuration and C ABI adapters
//! belong in consumer repositories.

pub mod hfs;
mod suffix;

pub use hfs::{Config, Fork, HfsInfo, MAX_COMMENT};
