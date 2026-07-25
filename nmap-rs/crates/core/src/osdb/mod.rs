//! OS-detection fingerprint database — the pure `core` half of nmap's `-O`.
//!
//! Ports `osscan.cc`: the `nmap-os-db` expression language ([`expr`]), and later the DB
//! parser, the observed-fingerprint model, and the match scoring. Everything here is a
//! total function of its inputs, so it is Miri-checkable and directly fuzzable — which
//! matters because `--osscandb` makes the database **attacker-supplyable**, and the
//! observed values fed into it come off the wire.

pub mod expr;
pub mod model;
pub mod parse;
pub mod score;
