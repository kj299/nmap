//! `nmap-sys` — the unsafe/FFI quarantine and the home of OS I/O. Every `unsafe`
//! in the whole project lives here, and every block carries a `// SAFETY:` the
//! audit harness enforces.
//!
//! Two patterns will carry almost all the weight once FFI lands (both proven in
//! the kit retrospective):
//!   1. RAII wrappers for every OS resource — acquire in `new`, release in
//!      `Drop` (the `OwnedHandle` / `PrivilegeGuard` shape). Arrives with the
//!      Npcap / `windows`-crate bindings in Milestone 4.
//!   2. Small audited safe fns over raw FFI — the `unsafe` a few lines behind a
//!      safe signature, with its invariants written down.
//!
//! For the Milestone-1 connect scan there is **no `unsafe`**: [`net`] and
//! [`scan`] wrap tokio's safe socket/task APIs, so the unsafe-audit gate reports
//! 0 for this crate.

pub mod net;
pub mod scan;

pub use scan::{connect_scan, ConnectScanConfig};
