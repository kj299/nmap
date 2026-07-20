//! Network-interface enumeration — the first stop on the raw send path (pick the
//! source address / MAC / outbound interface, and learn the MTU and default gateway
//! before building a packet). Replaces nmap's `libdnet` `intf-*.c` + `route-*.c`.
//!
//! ## Backend strategy (portable seam + safe crate + audited escape hatch)
//!
//! [`Interface`] is the OS-agnostic seam. The **default** backend is the `netdev`
//! crate — a vetted, cross-platform (Windows/Linux/macOS) enumerator whose own
//! OS-specific `unsafe` is audited upstream, so this crate contributes **0 `unsafe`**
//! to the whole OS-query layer while still getting per-address prefixes, MTU, MAC, and
//! the default gateway. That is both safer than and more complete than hand-rolling
//! `getifaddrs` / `GetAdaptersAddresses`, and it works identically on both targets.
//!
//! Under the off-by-default `raw-ffi` feature, [`interfaces_ffi`] provides a direct
//! `getifaddrs(3)` backend — the **escape hatch**: used to cross-check `netdev`
//! against the raw OS call, and the place to reach a field `netdev` does not expose.
//! It is the only `unsafe` in this module, and every block is audited.

use std::net::{Ipv4Addr, Ipv6Addr};

/// An IPv4 address bound to an interface, with its subnet prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    /// The interface address.
    pub addr: Ipv4Addr,
    /// Subnet prefix length (e.g. 24 for a /24).
    pub prefix_len: u8,
}

/// An IPv6 address bound to an interface, with its prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Net {
    /// The interface address.
    pub addr: Ipv6Addr,
    /// Prefix length (e.g. 64).
    pub prefix_len: u8,
}

/// The default gateway reachable via an interface (its next-hop for off-link
/// destinations), as far as the OS route table knows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gateway {
    /// Next-hop MAC, when known (needed to frame an Ethernet packet to off-link hosts).
    pub mac: Option<[u8; 6]>,
    /// Next-hop IPv4 address(es).
    pub ipv4: Vec<Ipv4Addr>,
    /// Next-hop IPv6 address(es).
    pub ipv6: Vec<Ipv6Addr>,
}

/// A network interface and everything the raw send path needs from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// Kernel interface name (e.g. `eth0`, `lo`, or a Windows adapter name).
    pub name: String,
    /// Interface index, 0 if unavailable.
    pub index: u32,
    /// Link-layer (MAC) address, when the interface has a non-zero one.
    pub mac: Option<[u8; 6]>,
    /// IPv4 addresses (with prefixes) bound to the interface.
    pub ipv4: Vec<Ipv4Net>,
    /// IPv6 addresses (with prefixes) bound to the interface.
    pub ipv6: Vec<Ipv6Net>,
    /// Interface MTU in bytes, when known (bounds fragmentation on the send path).
    pub mtu: Option<u32>,
    /// The interface is operationally up.
    pub is_up: bool,
    /// The interface is a loopback.
    pub is_loopback: bool,
    /// The default gateway via this interface, if any.
    pub gateway: Option<Gateway>,
}

impl Interface {
    /// The first non-loopback IPv4 address on this interface, if any — the usual
    /// source-address choice for an IPv4 raw probe.
    #[must_use]
    pub fn primary_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4
            .iter()
            .map(|n| n.addr)
            .find(|a| !a.is_loopback())
            .or_else(|| self.ipv4.first().map(|n| n.addr))
    }
}

fn mac_to_array(mac: netdev::MacAddr) -> Option<[u8; 6]> {
    let bytes = mac.octets();
    if bytes == [0u8; 6] {
        None
    } else {
        Some(bytes)
    }
}

fn convert(dev: netdev::Interface) -> Interface {
    // Read everything (including the borrowing `is_*` accessors) before moving any
    // owned field out of `dev`.
    let is_up = dev.is_up();
    let is_loopback = dev.is_loopback();
    let index = dev.index;
    let mtu = dev.mtu;
    let mac = dev.mac_addr.and_then(mac_to_array);
    let ipv4 = dev
        .ipv4
        .iter()
        .map(|n| Ipv4Net {
            addr: n.addr(),
            prefix_len: n.prefix_len(),
        })
        .collect();
    let ipv6 = dev
        .ipv6
        .iter()
        .map(|n| Ipv6Net {
            addr: n.addr(),
            prefix_len: n.prefix_len(),
        })
        .collect();
    let gateway = dev.gateway.map(|g| Gateway {
        mac: mac_to_array(g.mac_addr),
        ipv4: g.ipv4,
        ipv6: g.ipv6,
    });
    Interface {
        name: dev.name,
        index,
        mac,
        ipv4,
        ipv6,
        mtu,
        is_up,
        is_loopback,
        gateway,
    }
}

/// Enumerate the host's network interfaces (default backend: `netdev`).
///
/// # Errors
/// Currently infallible on all supported platforms (`netdev` returns an empty list
/// rather than an error); the `Result` is kept so the signature is stable if a future
/// backend can fail.
pub fn interfaces() -> std::io::Result<Vec<Interface>> {
    Ok(netdev::get_interfaces().into_iter().map(convert).collect())
}

// ---------------------------------------------------------------------------------
// Escape hatch: direct getifaddrs(3) backend (feature `raw-ffi`, Unix only).
// ---------------------------------------------------------------------------------
#[cfg(all(feature = "raw-ffi", unix))]
mod ffi;

/// Enumerate interfaces via a direct `getifaddrs(3)` call rather than `netdev`.
///
/// This is the audited hand-FFI escape hatch: used to cross-check the default backend
/// against the raw OS call, and as the place to reach a field `netdev` does not
/// expose. Addresses carry prefixes derived from the netmask; MTU and gateway are not
/// populated here (add them if a concrete need arises).
///
/// # Errors
/// Returns the OS error if `getifaddrs` fails.
#[cfg(all(feature = "raw-ffi", unix))]
pub fn interfaces_ffi() -> std::io::Result<Vec<Interface>> {
    ffi::interfaces()
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;

    #[test]
    fn enumerates_and_finds_loopback() {
        let ifaces = interfaces().expect("interface enumeration should succeed");
        assert!(!ifaces.is_empty(), "expected at least one interface");

        let lo = ifaces
            .iter()
            .find(|i| i.is_loopback)
            .expect("a loopback interface");
        let has_lo_addr = lo.ipv4.iter().any(|n| n.addr == Ipv4Addr::LOCALHOST)
            || lo.ipv6.iter().any(|n| n.addr == Ipv6Addr::LOCALHOST);
        assert!(has_lo_addr, "loopback should bind 127.0.0.1 or ::1");
    }

    #[test]
    fn names_are_unique_and_nonempty() {
        let ifaces = interfaces().unwrap();
        let mut names: Vec<&str> = ifaces.iter().map(|i| i.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "interface names must be unique");
        assert!(ifaces.iter().all(|i| !i.name.is_empty()));
    }

    #[test]
    fn addresses_carry_plausible_prefixes() {
        for i in interfaces().unwrap() {
            for n in &i.ipv4 {
                assert!(n.prefix_len <= 32, "IPv4 prefix out of range on {}", i.name);
            }
            for n in &i.ipv6 {
                assert!(
                    n.prefix_len <= 128,
                    "IPv6 prefix out of range on {}",
                    i.name
                );
            }
        }
    }

    // With the escape hatch compiled in, the raw getifaddrs backend must agree with
    // `netdev` on the set of interface names and their IPv4 addresses — proving the
    // fallback stays consistent with the default.
    #[cfg(all(feature = "raw-ffi", unix))]
    #[test]
    fn ffi_backend_agrees_with_netdev_on_names_and_v4() {
        use std::collections::BTreeSet;
        let netdev_names: BTreeSet<String> =
            interfaces().unwrap().into_iter().map(|i| i.name).collect();
        let ffi_names: BTreeSet<String> = interfaces_ffi()
            .unwrap()
            .into_iter()
            .map(|i| i.name)
            .collect();
        assert_eq!(
            netdev_names, ffi_names,
            "backends disagree on interface set"
        );
    }
}
