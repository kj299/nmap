//! Shared by the privileged e2e tests.

use std::net::Ipv4Addr;

/// The loopback interface, as the route to 127.0.0.1 names it: `lo` on
/// Linux, `lo0` on the BSDs (FreeBSD's F7).
pub fn loopback() -> String {
    nmap_sys::route::route_for(Ipv4Addr::LOCALHOST)
        .expect("enumerate interfaces")
        .expect("a route to 127.0.0.1")
        .iface
}

/// Asserts that the IP header checksum a capture shows is the kernel's:
/// valid, or zero where the kernel leaves it to an interface that offloads
/// it. FreeBSD's `ip_output` zeroes `ip_sum` and computes it only for an
/// interface without `CSUM_IP` in its `if_hwassist`; `lo0` claims it, so a
/// capture there shows 0, for C nmap's probes as for the port's.
#[allow(
    dead_code,
    reason = "used by the three on-the-wire tests, not by every e2e binary"
)]
pub fn assert_ip_checksum_is_the_kernels(header: &[u8], label: &str) {
    let offloaded = cfg!(target_os = "freebsd") && header.get(10..12) == Some(&[0u8, 0][..]);
    assert!(
        nmap_core::checksum::in_cksum(header) == 0 || offloaded,
        "{label}: invalid IP checksum on the wire"
    );
}
