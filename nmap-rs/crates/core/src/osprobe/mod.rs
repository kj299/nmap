//! IPv4 OS-detection probes — the pure `core` half of `osscan2.cc`.
//!
//! nmap fingerprints an operating system by sending a fixed, carefully chosen battery of
//! probes and recording exactly how the stack replies. The probes are deliberately
//! peculiar — unusual TCP option orders, undersized windows, illegal flag combinations,
//! an ICMP echo with a non-zero code — because it is the *disagreements* between stacks
//! on undefined or under-specified behaviour that carry the identifying signal.
//!
//! [`build`] constructs those probes. The response side (turning replies into the
//! `SEQ`/`OPS`/`WIN`/`ECN`/`T1`–`T7`/`U1`/`IE` attributes that
//! [`crate::osdb::score`] consumes) follows in a later slice.

pub mod analyze;
pub mod build;
pub mod seq;
pub mod tcpreply;
