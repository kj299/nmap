//! `nmap-core` — the platform-agnostic heart of the nmap port. This is where
//! MOST of the translated C logic lives: data model, target/port parsing, the
//! scan-result model, timing math, and output rendering.
//!
//! `#![forbid(unsafe_code)]` is the single highest-leverage line in the project
//! (the kit retrospective's finding). It makes "is the unsafe contained?" a
//! compile-time fact: nothing here can reach for `unsafe`, so all memory-safety
//! risk is pushed into `nmap-sys`, where the audit harness enforces a `// SAFETY:`
//! on every block. Keep this crate dependency-light.
#![forbid(unsafe_code)]

pub mod log;
pub mod model;
pub mod options;
pub mod targets;
pub mod trace;

pub use model::{Host, HostState, Port, PortState, Protocol, Reason, ScanResults, ServiceInfo};
pub use options::{parse_args, RunConfig};
pub use targets::{parse_target, Ipv4Ranges, TargetParseError, TargetSpec};
