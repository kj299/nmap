//! `core::headers` — per-protocol packet header parsers and serializers.
//!
//! Each submodule ports one nmap `libnetutil` header class into a pure Rust parser
//! built on [`crate::bytes::Cursor`]: `parse(&[u8]) -> Result<Header>` (the
//! untrusted-input edge, fuzzed + differential'd against the C oracle harness),
//! plus serialization and checksum where the C builds packets. No `unsafe`, no
//! struct-overlay pointer casts, no fixed buffers — a truncated or hostile packet
//! degrades to a parse error, never UB (the M4 threat-model requirement).

pub mod ipv4;
pub mod tcp;
pub mod udp;
