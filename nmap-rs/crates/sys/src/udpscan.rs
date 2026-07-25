//! UDP scan (`-sU`) entry point. The event loop itself lives in [`crate::group`] — this
//! module only picks the per-scan keys and names the [`UdpKind`] behavior, so the UDP
//! scan shares one audited driver with every other raw scan instead of carrying its own
//! copy. **No `unsafe`**.
//!
//! [`UdpKind`]: crate::group::UdpKind

// Only the `pcap` entry point below uses these; without the feature this module is
// empty, and an ungated import would be an unused-import warning (CI runs `-D warnings`).
#[cfg(feature = "pcap")]
use std::net::IpAddr;

#[cfg(feature = "pcap")]
use nmap_core::payload::UdpPayloads;
#[cfg(feature = "pcap")]
use nmap_core::timing::TimingTemplate;

/// Run a UDP scan over several targets with route/source selection and pcap capture —
/// the CLI-facing entry point (feature `pcap`). Targets sharing an egress route are
/// scanned concurrently through one capture. One [`nmap_core::model::Host`] per target,
/// in order.
///
/// `payloads` supplies the protocol-specific probe payloads (see
/// [`nmap_core::payload`]); pass [`UdpPayloads::empty`] to send bare datagrams.
///
/// # Errors
/// Propagates a raw-socket / capture-open error (notably `PermissionDenied`) and any
/// interface-enumeration error.
#[cfg(feature = "pcap")]
pub async fn udp_scan_targets(
    targets: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_parallelism: usize,
    payloads: UdpPayloads,
) -> std::io::Result<nmap_core::model::ScanResults> {
    // UDP has no sequence to mask; the base port alone encodes the attempt.
    let kind = crate::group::UdpKind::new(payloads);
    crate::group::group_scan_targets(&kind, targets, ports, template, max_parallelism).await
}
