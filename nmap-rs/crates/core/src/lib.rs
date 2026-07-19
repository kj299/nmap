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

pub mod bytes;
pub mod checksum;
pub mod congestion;
pub mod engine;
pub mod log;
pub mod matcher;
pub mod model;
pub mod options;
pub mod output;
pub mod pcre_translate;
pub mod ports;
pub mod probedb;
pub mod servicescan;
pub mod targets;
pub mod timing;
pub mod trace;
pub mod versioninfo;

pub use congestion::{PerfVars, TimingVals};
pub use engine::{GroupScheduler, HostScheduler, Probe, RateLimiter, RateVerdict};
pub use matcher::{CompileWarning, CompiledDb, CompiledProbe, CompiledRule, MatchOutcome};
pub use model::{Host, HostState, Port, PortState, Protocol, Reason, ScanResults, ServiceInfo};
pub use options::{parse_args, RunConfig};
pub use output::{render_grepable, render_normal, render_xml, ScanMeta};
pub use pcre_translate::translate as pcre_translate;
pub use ports::{parse_port_spec, PortList, PortSpecError, ServiceTable};
pub use probedb::{MatchRule, Probe as ServiceProbe, ProbeDb, ProbeProtocol, ProbeWarning};
pub use servicescan::{MatchKind, ProbeRef, Resolution, Scheduler as ServiceScheduler};
pub use targets::{parse_target, Ipv4Ranges, TargetParseError, TargetSpec};
pub use timing::{TimeoutInfo, TimingParams, TimingTemplate};
pub use versioninfo::{build as build_version_info, VersionInfo};
