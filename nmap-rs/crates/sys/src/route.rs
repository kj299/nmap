//! Minimal route + source-address selection for the raw scans, plus the per-scan
//! random keys. A small port of nmap's `nmap_route_dst` (`tcpip.cc`): pick the egress
//! interface and source IPv4 for a target, so the raw driver knows what capture
//! device to open and what source address to stamp on its probes.
//!
//! **No `unsafe`** — built entirely on the safe [`crate::netif`] enumeration. This is
//! deliberately simple (on-link match, then the default-gateway interface); full
//! longest-prefix routing-table lookup is a later refinement.

use std::io::{self, Read};
use std::net::Ipv4Addr;

use crate::netif;

/// The egress interface and source address chosen for a target.
#[derive(Debug, Clone)]
pub struct Route {
    /// Capture/egress interface name (e.g. `"lo"`, `"eth0"`).
    pub iface: String,
    /// Source IPv4 address to stamp on outgoing probes.
    pub src: Ipv4Addr,
    /// Whether a capture on `iface` includes a link-layer header (Ethernet/loopback →
    /// `true`; a bare-IP datalink → `false`). Defaults to `true`, which is correct for
    /// Linux `lo` and Ethernet — the datalinks this port currently parses.
    pub eth_included: bool,
}

/// True if `target` is inside the network `net_addr/prefix`.
#[must_use]
pub fn in_subnet(net_addr: Ipv4Addr, prefix_len: u8, target: Ipv4Addr) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }
    // Build the prefix mask; `prefix_len` is 1..=32 here, so `32 - prefix_len` is
    // 0..=31 and the shift is well-defined (a /32 shifts by 0 → all-ones mask).
    let shift = 32u32.wrapping_sub(u32::from(prefix_len));
    let mask: u32 = u32::MAX.wrapping_shl(shift);
    (u32::from(net_addr) & mask) == (u32::from(target) & mask)
}

/// Choose the egress interface + source IPv4 for `target`.
///
/// Order: a loopback target → the loopback interface; else an interface whose subnet
/// contains the target (on-link); else the first up, non-loopback interface that has a
/// default gateway. Returns `None` if nothing suitable is up.
///
/// # Errors
/// Propagates an error from interface enumeration.
pub fn route_for(target: Ipv4Addr) -> io::Result<Option<Route>> {
    let ifaces = netif::interfaces()?;

    if target.is_loopback() {
        if let Some(i) = ifaces.iter().find(|i| i.is_loopback && i.is_up) {
            let src = i.primary_ipv4().unwrap_or(Ipv4Addr::LOCALHOST);
            return Ok(Some(Route {
                iface: i.name.clone(),
                src,
                eth_included: true,
            }));
        }
    }

    // On-link: an interface whose subnet contains the target.
    for i in &ifaces {
        if !i.is_up || i.is_loopback {
            continue;
        }
        for net in &i.ipv4 {
            if in_subnet(net.addr, net.prefix_len, target) {
                return Ok(Some(Route {
                    iface: i.name.clone(),
                    src: net.addr,
                    eth_included: true,
                }));
            }
        }
    }

    // Off-link: the first up, non-loopback interface with a default gateway.
    for i in &ifaces {
        if i.is_up && !i.is_loopback && i.gateway.is_some() {
            if let Some(src) = i.primary_ipv4() {
                return Ok(Some(Route {
                    iface: i.name.clone(),
                    src,
                    eth_included: true,
                }));
            }
        }
    }

    Ok(None)
}

/// Draw the per-scan random keys: the 32-bit sequence mask and the base TCP source
/// port. nmap seeds these once per scan from the OS RNG; we read `/dev/urandom`
/// directly to avoid pulling in an RNG dependency (Unix — where the raw scans run).
///
/// The base port is placed in a high ephemeral range clear of typical scanned service
/// ports, leaving room above it for the per-attempt source-port encoding.
#[must_use]
pub fn random_scan_keys() -> (u32, u16) {
    let mut buf = [0u8; 6];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        // A short read just leaves some bytes zero — still a valid (if weaker) key.
        let _ = f.read_exact(&mut buf);
    }
    let seqmask = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let raw = u16::from_ne_bytes([buf[4], buf[5]]);
    // 40000..=59999: above common service ports, well below the u16 ceiling so the
    // encoded source-port range base..base+max_tryno cannot wrap.
    let base_port = 40000u16.wrapping_add(raw % 20000);
    (seqmask, base_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_membership() {
        let net = Ipv4Addr::new(192, 168, 1, 0);
        assert!(in_subnet(net, 24, Ipv4Addr::new(192, 168, 1, 42)));
        assert!(!in_subnet(net, 24, Ipv4Addr::new(192, 168, 2, 42)));
        // /32 matches only itself.
        assert!(in_subnet(
            Ipv4Addr::new(10, 0, 0, 5),
            32,
            Ipv4Addr::new(10, 0, 0, 5)
        ));
        assert!(!in_subnet(
            Ipv4Addr::new(10, 0, 0, 5),
            32,
            Ipv4Addr::new(10, 0, 0, 6)
        ));
        // /0 matches everything.
        assert!(in_subnet(
            Ipv4Addr::UNSPECIFIED,
            0,
            Ipv4Addr::new(8, 8, 8, 8)
        ));
    }

    #[cfg_attr(miri, ignore = "reads /dev/urandom")]
    #[test]
    fn base_port_is_in_the_high_range() {
        // Regardless of the random draw, the base stays in [40000, 59999].
        let (_, base) = random_scan_keys();
        assert!((40000..60000).contains(&base), "base {base} out of range");
    }

    #[cfg_attr(miri, ignore = "reads /dev/urandom + enumerates interfaces")]
    #[test]
    fn loopback_routes_to_a_loopback_iface() {
        // On any host with `lo` up, a loopback target routes to a loopback interface.
        if let Ok(Some(r)) = route_for(Ipv4Addr::LOCALHOST) {
            assert!(r.src.is_loopback() || r.iface == "lo");
        }
    }
}
