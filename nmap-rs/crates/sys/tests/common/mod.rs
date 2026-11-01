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
