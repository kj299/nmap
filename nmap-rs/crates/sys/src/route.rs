//! Minimal route + source-address selection for the raw scans, plus the per-scan
//! random keys. A small port of nmap's `nmap_route_dst` (`tcpip.cc`): pick the egress
//! interface and source IPv4 for a target, so the raw driver knows what capture
//! device to open and what source address to stamp on its probes.
//!
//! **No `unsafe`** — built entirely on the safe [`crate::netif`] enumeration. This is
//! deliberately simple (on-link match, then the default-gateway interface); full
//! longest-prefix routing-table lookup is a later refinement. Ledgered as
//! `route-minimal-onlink-then-gateway`.
//!
//! [`route_for6`] is the IPv6 counterpart, and carries more than its IPv4 sibling: the
//! IPv6 send path is layer 2 (Linux has no `IPV6_HDRINCL`), so it must also report the
//! **next hop** whose MAC has to be resolved, and whether the target is directly
//! connected — which is what gates the `NS` probe in the OS-detection battery.

use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

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

/// The reachability scope of an IPv6 address. Unlike IPv4, a source address may not
/// be paired with a destination of a different scope: a link-local destination must be
/// answered from a link-local source, and a global destination from a global one. nmap
/// gets this for free by reading the OS route table (each route carries its own device
/// address); selecting the source ourselves means classifying explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope6 {
    /// Loopback, or interface-local multicast — never leaves the host.
    Loopback,
    /// `fe80::/10`, or link-local multicast — valid only on one link.
    LinkLocal,
    /// Everything else, including unique-local (`fc00::/7`), which is routed like a
    /// global address even though it is not globally reachable.
    Global,
}

/// Classify an IPv6 address for source-address selection.
#[must_use]
pub fn scope_of(addr: Ipv6Addr) -> Scope6 {
    if addr.is_loopback() {
        return Scope6::Loopback;
    }
    let o = addr.octets();
    if o[0] == 0xff {
        // Multicast: the low nibble of the second byte is the scope field (RFC 4291
        // §2.7). 1 is interface-local, 2 link-local; larger scopes route like a global
        // address. Not a scan target, but classified rather than mishandled.
        return match o[1] & 0x0f {
            0x1 => Scope6::Loopback,
            0x2 => Scope6::LinkLocal,
            _ => Scope6::Global,
        };
    }
    // fe80::/10.
    if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
        return Scope6::LinkLocal;
    }
    Scope6::Global
}

/// True if `target` is inside the network `net_addr/prefix`.
#[must_use]
pub fn in_subnet6(net_addr: Ipv6Addr, prefix_len: u8, target: Ipv6Addr) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 128 {
        return false;
    }
    // `prefix_len` is 1..=128 here, so the shift is 0..=127 and well-defined (a /128
    // shifts by 0 → all-ones mask).
    let shift = 128u32.wrapping_sub(u32::from(prefix_len));
    let mask: u128 = u128::MAX.wrapping_shl(shift);
    (u128::from(net_addr) & mask) == (u128::from(target) & mask)
}

/// The egress interface, source address and next hop chosen for an IPv6 target.
///
/// Carries more than its IPv4 [`Route`] sibling because the IPv6 send path is layer 2:
/// the driver frames its own Ethernet header, so it needs the source MAC and the
/// address whose MAC must be resolved by neighbor discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route6 {
    /// Capture/egress interface name.
    pub iface: String,
    /// Source IPv6 address to stamp on outgoing probes.
    pub src: Ipv6Addr,
    /// The interface's link-layer address — the Ethernet source.
    pub src_mac: Option<[u8; 6]>,
    /// The address whose MAC the link-layer send needs: the target itself when it is
    /// on-link, otherwise the gateway.
    pub next_hop: Ipv6Addr,
    /// The next hop's MAC when the OS already knows it (a gateway entry), saving a
    /// neighbor solicitation.
    pub next_hop_mac: Option<[u8; 6]>,
    /// Whether the target is on the same link. Gates the `NS` probe in the
    /// OS-detection battery (`Build6Params::directly_connected`).
    pub directly_connected: bool,
    /// Whether a capture on `iface` includes a link-layer header.
    pub eth_included: bool,
}

/// Pick a source address on `iface` matching `scope`.
fn source_for_scope(iface: &netif::Interface, scope: Scope6) -> Option<Ipv6Addr> {
    iface
        .ipv6
        .iter()
        .map(|n| n.addr)
        .find(|a| scope_of(*a) == scope)
}

/// Choose the route for `target` from an explicit interface list.
///
/// Split out from [`route_for6`] so the whole decision is a pure function of the
/// interface table and can be tested against synthetic topologies rather than against
/// whatever the CI host happens to have configured.
///
/// Order mirrors [`route_for`], with the C's `direct_connect` rule (`route_dst_generic`
/// treats a route as direct when its gateway is unset, equals the device address, or
/// equals the destination): a loopback target → the loopback interface; else an
/// interface with a **same-scope** prefix containing the target (on-link, next hop is
/// the target); else the first up, non-loopback interface holding an IPv6 default
/// gateway (off-link, next hop is that gateway).
#[must_use]
pub fn choose_route6(ifaces: &[netif::Interface], target: Ipv6Addr) -> Option<Route6> {
    let scope = scope_of(target);

    if scope == Scope6::Loopback {
        if let Some(i) = ifaces.iter().find(|i| i.is_loopback && i.is_up) {
            return Some(Route6 {
                iface: i.name.clone(),
                src: source_for_scope(i, Scope6::Loopback).unwrap_or(Ipv6Addr::LOCALHOST),
                src_mac: i.mac,
                next_hop: target,
                next_hop_mac: None,
                directly_connected: true,
                eth_included: true,
            });
        }
    }

    // On-link: an interface with a prefix containing the target. The source must come
    // from the same scope as the target, not merely from the same interface — an
    // interface typically holds both a link-local and a global address.
    for i in ifaces {
        if !i.is_up || i.is_loopback {
            continue;
        }
        for net in &i.ipv6 {
            if scope_of(net.addr) != scope {
                continue;
            }
            if in_subnet6(net.addr, net.prefix_len, target) {
                return Some(Route6 {
                    iface: i.name.clone(),
                    src: net.addr,
                    src_mac: i.mac,
                    next_hop: target,
                    next_hop_mac: None,
                    directly_connected: true,
                    eth_included: true,
                });
            }
        }
    }

    // A link-local target that matched no prefix has no route: it cannot be reached
    // through a gateway by definition, so falling through would pick a global source
    // for a link-local destination and send a packet that cannot be answered.
    if scope == Scope6::LinkLocal {
        return None;
    }

    // Off-link: the first up, non-loopback interface holding an IPv6 default gateway.
    for i in ifaces {
        if !i.is_up || i.is_loopback {
            continue;
        }
        let Some(gw) = i.gateway.as_ref() else {
            continue;
        };
        let Some(&next_hop) = gw.ipv6.first() else {
            continue;
        };
        if let Some(src) = source_for_scope(i, Scope6::Global) {
            return Some(Route6 {
                iface: i.name.clone(),
                src,
                src_mac: i.mac,
                next_hop,
                next_hop_mac: gw.mac,
                directly_connected: false,
                eth_included: true,
            });
        }
    }

    None
}

/// Choose the egress interface, source IPv6 and next hop for `target`.
///
/// # Errors
/// Propagates an error from interface enumeration.
pub fn route_for6(target: Ipv6Addr) -> io::Result<Option<Route6>> {
    Ok(choose_route6(&netif::interfaces()?, target))
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

    // ---- IPv6 ----

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().expect("ipv6 literal")
    }

    /// A synthetic interface, so the routing decision is tested against a known
    /// topology rather than against whatever the CI host is configured with.
    fn iface(
        name: &str,
        mac: Option<[u8; 6]>,
        addrs: &[(&str, u8)],
        gw: Option<(&str, Option<[u8; 6]>)>,
    ) -> netif::Interface {
        netif::Interface {
            name: name.to_string(),
            index: 1,
            mac,
            ipv4: Vec::new(),
            ipv6: addrs
                .iter()
                .map(|(a, p)| netif::Ipv6Net {
                    addr: v6(a),
                    prefix_len: *p,
                })
                .collect(),
            mtu: Some(1500),
            is_up: true,
            is_loopback: name == "lo",
            gateway: gw.map(|(a, m)| netif::Gateway {
                mac: m,
                ipv4: Vec::new(),
                ipv6: vec![v6(a)],
            }),
        }
    }

    const MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c];
    const GWMAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    fn topology() -> Vec<netif::Interface> {
        vec![
            iface("lo", None, &[("::1", 128)], None),
            iface(
                "eth0",
                Some(MAC),
                &[("fe80::20c:29ff:fe1a:2b3c", 64), ("2001:db8:1::5", 64)],
                Some(("fe80::1", Some(GWMAC))),
            ),
        ]
    }

    #[test]
    fn scope_classification() {
        assert_eq!(scope_of(v6("::1")), Scope6::Loopback);
        assert_eq!(scope_of(v6("fe80::1")), Scope6::LinkLocal);
        // febf:: is still inside fe80::/10.
        assert_eq!(scope_of(v6("febf::1")), Scope6::LinkLocal);
        // fec0:: is outside it (the old site-local block, now just global).
        assert_eq!(scope_of(v6("fec0::1")), Scope6::Global);
        assert_eq!(scope_of(v6("2001:db8::1")), Scope6::Global);
        // Unique-local routes like a global address.
        assert_eq!(scope_of(v6("fd00::1")), Scope6::Global);
        // Multicast carries its scope in the low nibble of the second byte.
        assert_eq!(scope_of(v6("ff01::1")), Scope6::Loopback);
        assert_eq!(scope_of(v6("ff02::1:ff00:1")), Scope6::LinkLocal);
        assert_eq!(scope_of(v6("ff0e::1")), Scope6::Global);
    }

    #[test]
    fn subnet6_membership() {
        assert!(in_subnet6(v6("2001:db8:1::5"), 64, v6("2001:db8:1::99")));
        assert!(!in_subnet6(v6("2001:db8:1::5"), 64, v6("2001:db8:2::99")));
        // /128 matches only itself.
        assert!(in_subnet6(v6("::1"), 128, v6("::1")));
        assert!(!in_subnet6(v6("::1"), 128, v6("::2")));
        // /0 matches everything; >128 matches nothing.
        assert!(in_subnet6(Ipv6Addr::UNSPECIFIED, 0, v6("2001:db8::1")));
        assert!(!in_subnet6(v6("2001:db8::"), 129, v6("2001:db8::1")));
        // A prefix that splits inside a byte.
        assert!(in_subnet6(v6("2001:db8::"), 33, v6("2001:db8:7fff::1")));
        assert!(!in_subnet6(v6("2001:db8::"), 33, v6("2001:db9::1")));
    }

    #[test]
    fn loopback_target_takes_the_loopback_interface() {
        let r = choose_route6(&topology(), v6("::1")).expect("a route to ::1");
        assert_eq!(r.iface, "lo");
        assert_eq!(r.src, v6("::1"));
        assert!(r.directly_connected);
        assert_eq!(r.next_hop, v6("::1"));
    }

    #[test]
    fn on_link_global_target_is_directly_connected() {
        let r = choose_route6(&topology(), v6("2001:db8:1::99")).expect("a route");
        assert_eq!(r.iface, "eth0");
        assert_eq!(
            r.src,
            v6("2001:db8:1::5"),
            "a global source for a global target"
        );
        assert_eq!(r.src_mac, Some(MAC));
        assert!(r.directly_connected);
        // On-link: the next hop to resolve is the target itself, not the gateway.
        assert_eq!(r.next_hop, v6("2001:db8:1::99"));
        assert_eq!(r.next_hop_mac, None);
    }

    #[test]
    fn off_link_target_goes_via_the_gateway() {
        let r = choose_route6(&topology(), v6("2001:db8:ffff::1")).expect("a route");
        assert_eq!(r.iface, "eth0");
        assert_eq!(r.src, v6("2001:db8:1::5"));
        assert!(!r.directly_connected, "not on any of our prefixes");
        assert_eq!(
            r.next_hop,
            v6("fe80::1"),
            "resolve the gateway, not the target"
        );
        assert_eq!(
            r.next_hop_mac,
            Some(GWMAC),
            "a known gateway MAC saves a solicitation"
        );
    }

    // A link-local destination must be answered from a link-local source. Pairing a
    // global source with it would send a packet that cannot be answered.
    #[test]
    fn link_local_target_gets_a_link_local_source() {
        let r = choose_route6(&topology(), v6("fe80::dead:beef")).expect("a route");
        assert_eq!(r.iface, "eth0");
        assert_eq!(r.src, v6("fe80::20c:29ff:fe1a:2b3c"));
        assert_eq!(scope_of(r.src), Scope6::LinkLocal);
        assert!(r.directly_connected);
    }

    // A link-local target off every configured prefix has no route at all: it cannot
    // be reached through a gateway, so falling through to one would pick a global
    // source for a link-local destination.
    #[test]
    fn unreachable_link_local_target_has_no_route() {
        let ifaces = vec![
            iface("lo", None, &[("::1", 128)], None),
            iface(
                "eth0",
                Some(MAC),
                &[("2001:db8:1::5", 64)],
                Some(("fe80::1", Some(GWMAC))),
            ),
        ];
        assert_eq!(choose_route6(&ifaces, v6("fe80::dead:beef")), None);
    }

    #[test]
    fn no_gateway_and_no_matching_prefix_means_no_route() {
        let ifaces = vec![iface("eth0", Some(MAC), &[("2001:db8:1::5", 64)], None)];
        assert_eq!(choose_route6(&ifaces, v6("2001:db8:ffff::1")), None);
    }

    #[test]
    fn a_down_interface_is_never_chosen() {
        let mut ifaces = topology();
        ifaces[1].is_up = false;
        assert_eq!(choose_route6(&ifaces, v6("2001:db8:1::99")), None);
    }

    #[cfg_attr(miri, ignore = "reads /dev/urandom + enumerates interfaces")]
    #[test]
    fn loopback6_routes_to_a_loopback_iface() {
        // On any host with `lo` up, ::1 routes to a loopback interface.
        if let Ok(Some(r)) = route_for6(Ipv6Addr::LOCALHOST) {
            assert!(r.src.is_loopback() || r.iface == "lo");
            assert!(r.directly_connected);
        }
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
