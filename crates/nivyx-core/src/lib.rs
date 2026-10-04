//! Platform-independent core of Nivyx. No I/O, no globals, no unsafe code.
#![forbid(unsafe_code)]

pub mod config;
pub mod dns;
pub mod netid;
pub mod quic;
pub mod redact;
pub mod stats;
pub mod strategy;
pub mod tls;
