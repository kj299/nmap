//! SYN scan (`-sS`) entry point. The event loop itself lives in [`crate::group`] — this
//! module only picks the per-scan keys and names the [`SynKind`] behavior, so the SYN
//! scan shares one audited driver with every other raw scan instead of carrying its own
//! copy. **No `unsafe`**.
//!
//! [`SynKind`]: crate::group::SynKind

// Only the `pcap` entry point below uses these; without the feature this module is
// empty, and an ungated import would be an unused-import warning (CI runs `-D warnings`).
#[cfg(feature = "pcap")]
use std::net::IpAddr;

#[cfg(feature = "pcap")]
use nmap_core::timing::TimingTemplate;

/// Run a SYN scan over several targets with route/source selection and pcap capture —
/// the CLI-facing entry point (feature `pcap`). Targets sharing an egress route are
/// scanned concurrently through one capture. One [`nmap_core::model::Host`] per target,
/// in order.
///
/// # Errors
/// Propagates a raw-socket / capture-open error (notably `PermissionDenied`) and any
/// interface-enumeration error.
#[cfg(feature = "pcap")]
pub async fn syn_scan_targets(
    targets: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_parallelism: usize,
) -> std::io::Result<nmap_core::model::ScanResults> {
    // One per-scan sequence mask for the whole scan (base ports are drawn per
    // route-group inside the engine).
    let (seqmask, _base) = crate::route::random_scan_keys();
    let kind = crate::group::SynKind { seqmask };
    crate::group::group_scan_targets(&kind, targets, ports, template, max_parallelism).await
}
