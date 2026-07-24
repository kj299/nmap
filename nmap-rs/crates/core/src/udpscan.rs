//! UDP-scan probe construction and response matching — the pure `core` half of the
//! `-sU` scan. Ports the UDP-specific pieces of nmap's `scan_engine_raw.cc`: the UDP
//! probe build and the two ways a UDP probe is answered —
//!
//!   * a **direct UDP datagram** back from the target → the port is **open**
//!     (`ER_UDPRESPONSE`);
//!   * an **ICMP port-unreachable** (type 3 code 3) whose *embedded* packet is our
//!     probe → the port is **closed** (`ER_PORTUNREACH`); other ICMP unreachable /
//!     time-exceeded codes → **filtered**.
//!
//! Nothing back at all → `open|filtered` (the driver's default). This module is a
//! total function of its inputs — no clock, no I/O, no randomness — so it is
//! Miri-checkable and [`match_udp_response`] is fuzzed directly against hostile frames.
//!
//! Matching reuses the SYN scan's per-attempt source-port encoding
//! ([`crate::synscan::sport_encode`]): the attempt is recovered from the datagram's
//! destination port (our source port) or, for an ICMP error, from the **embedded**
//! probe's source port. The pcap BPF filter scopes capture to our encoded
//! source-port range plus ICMP, so our own outgoing datagrams never match.
//!
//! ## Scope / divergences (ledgered in `DIVERGENCES.md`)
//!
//! * `udpscan-empty-payload` — the probe carries an empty payload. nmap sends
//!   protocol-specific payloads for well-known UDP ports (`payload.cc`) which elicit
//!   replies from more services; without them some open UDP ports read as
//!   `open|filtered`. A safe, less-complete first slice; the payload DB is a follow-up.
//! * Inherits `validate-ipv4-only-for-now`.

use crate::build::{build_udp_raw, BuildError, Ipv4Spec};
use crate::classify::{classify_icmp, classify_udp_response, PortState, ScanType};
use crate::packet_parser::{parse_packet, Header};
use crate::recv_validate::validate_packet;
use crate::synscan::sport_encode;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_UDP: u8 = 17;
/// Fixed ICMPv4 header length; the embedded packet begins after it.
const ICMP_HEADER_LEN: usize = 8;
/// Minimum IPv4 header length.
const IP_MIN: usize = 20;
/// Bytes of a UDP header we read (source + dest ports).
const UDP_PORTS_LEN: usize = 4;

/// The UDP probe payload. Empty for this slice (see `udpscan-empty-payload`).
pub const UDP_PROBE_PAYLOAD: &[u8] = &[];

/// Build a raw UDP probe packet for `(dport, tryno)`, encoding the attempt in the
/// source port exactly as the SYN scan does.
///
/// # Errors
/// Propagates [`BuildError`] from [`build_udp_raw`] (only reachable via malformed
/// `spec.options`).
pub fn build_udp_probe(
    spec: &Ipv4Spec,
    base_port: u16,
    dport: u16,
    tryno: u32,
) -> Result<Vec<u8>, BuildError> {
    let sport = sport_encode(base_port, tryno);
    build_udp_raw(spec, sport, dport, UDP_PROBE_PAYLOAD)
}

/// The per-scan constants a captured reply is matched against.
#[derive(Debug, Clone, Copy)]
pub struct UdpMatchCtx {
    /// Base UDP source port (the `tryno == 0` source port).
    pub base_port: u16,
    /// Highest attempt number in flight.
    pub max_tryno: u32,
    /// The target address, to decide `from_target` for ICMP classification.
    pub target: [u8; 4],
}

/// A captured packet matched to an outstanding UDP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpReply {
    /// The scanned port that answered.
    pub port: u16,
    /// Which attempt this reply answers.
    pub tryno: u32,
    /// The port state the reply implies.
    pub state: PortState,
}

/// Decide whether a captured frame answers one of our UDP probes, and to what state.
///
/// Handles a direct UDP datagram (→ open) and an ICMP unreachable/time-exceeded whose
/// embedded packet is one of our probes (port-unreach → closed, else filtered).
/// Returns `None` for anything else. Total on all input — the primary fuzz target of
/// the UDP receive path.
#[must_use]
pub fn match_udp_response(frame: &[u8], eth_included: bool, ctx: &UdpMatchCtx) -> Option<UdpReply> {
    let ip_off = ipv4_offset(frame, eth_included)?;
    let ip = frame.get(ip_off..)?;
    let v = validate_packet(ip).ok()?;
    let src_ip: [u8; 4] = ip.get(12..16)?.try_into().ok()?;

    match v.proto {
        IPPROTO_UDP => {
            // A direct datagram: its source port is the scanned port, its destination
            // is our encoded source port (→ the attempt).
            let udp = ip.get(v.data_offset..)?;
            if udp.len() < UDP_PORTS_LEN {
                return None;
            }
            let scanned = u16::from_be_bytes([udp[0], udp[1]]);
            let our_sport = u16::from_be_bytes([udp[2], udp[3]]);
            let tryno = attempt_from_sport(our_sport, ctx)?;
            Some(UdpReply {
                port: scanned,
                tryno,
                state: classify_udp_response(),
            })
        }
        IPPROTO_ICMP => {
            let icmp = ip.get(v.data_offset..)?;
            if icmp.len() < ICMP_HEADER_LEN {
                return None;
            }
            let (icmp_type, icmp_code) = (icmp[0], icmp[1]);
            // The ICMP error quotes our original probe after the 8-byte ICMP header.
            let embedded = icmp.get(ICMP_HEADER_LEN..)?;
            let (embedded_sport, embedded_dport) = embedded_udp_ports(embedded)?;
            let tryno = attempt_from_sport(embedded_sport, ctx)?;
            let from_target = src_ip == ctx.target;
            let state = classify_icmp(ScanType::Udp, icmp_type, icmp_code, from_target)?;
            Some(UdpReply {
                port: embedded_dport,
                tryno,
                state,
            })
        }
        _ => None,
    }
}

/// Recover the attempt number from an encoded source port, rejecting ports outside our
/// range.
fn attempt_from_sport(sport: u16, ctx: &UdpMatchCtx) -> Option<u32> {
    let tryno = u32::from(sport.wrapping_sub(ctx.base_port));
    (tryno <= ctx.max_tryno).then_some(tryno)
}

/// Parse `(src_port, dst_port)` out of the IPv4+UDP packet embedded in an ICMP error.
/// The quote may be truncated to the first 8 bytes of the UDP header, which still
/// covers both ports. Returns `None` unless it is a well-formed IPv4/UDP quote.
fn embedded_udp_ports(embedded: &[u8]) -> Option<(u16, u16)> {
    if embedded.len() < IP_MIN {
        return None;
    }
    if embedded[0] >> 4 != 4 {
        return None; // not IPv4
    }
    let ihl = usize::from(embedded[0] & 0x0F).checked_mul(4)?;
    if ihl < IP_MIN || embedded[9] != IPPROTO_UDP {
        return None;
    }
    let udp = embedded.get(ihl..)?;
    if udp.len() < UDP_PORTS_LEN {
        return None;
    }
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    Some((sport, dport))
}

/// Byte offset of the IPv4 header inside a captured frame.
fn ipv4_offset(frame: &[u8], eth_included: bool) -> Option<usize> {
    let mut off = 0usize;
    for h in parse_packet(frame, eth_included) {
        if matches!(h, Header::Ipv4(_)) {
            return Some(off);
        }
        off = off.checked_add(h.len())?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::build_tcp_raw;

    fn ctx() -> UdpMatchCtx {
        UdpMatchCtx {
            base_port: 40000,
            max_tryno: 11,
            target: [10, 0, 0, 2],
        }
    }

    /// Prepend a 14-byte Ethernet header (IPv4 ethertype) to an IP packet.
    fn framed(ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f.extend_from_slice(ip);
        f
    }

    #[test]
    fn build_udp_probe_encodes_the_attempt_in_the_source_port() {
        let spec = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 0x1234);
        let pkt = build_udp_probe(&spec, 40000, 53, 3).unwrap();
        let v = validate_packet(&pkt).unwrap();
        assert_eq!(v.proto, IPPROTO_UDP);
        let udp = &pkt[v.data_offset..];
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 40003); // sport = base + tryno
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 53); // dport
    }

    #[test]
    fn direct_datagram_is_open() {
        // Target → us: src = scanned port 53, dst = our sport (base + 0).
        let spec = Ipv4Spec::new([10, 0, 0, 2], [10, 0, 0, 1], 64, 0x1);
        let ip = build_udp_raw(&spec, 53, 40000, b"reply").unwrap();
        let m = match_udp_response(&framed(&ip), true, &ctx()).unwrap();
        assert_eq!(m.port, 53);
        assert_eq!(m.tryno, 0);
        assert_eq!(m.state, PortState::Open);
    }

    /// Build an ICMP type/code error quoting an embedded IPv4/UDP probe (our sport →
    /// scanned dport), from `src` toward us.
    fn icmp_quoting(
        src: [u8; 4],
        icmp_type: u8,
        icmp_code: u8,
        our_sport: u16,
        dport: u16,
    ) -> Vec<u8> {
        // The embedded probe: our original UDP datagram to the target.
        let pspec = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 0x2);
        let probe = build_udp_raw(&pspec, our_sport, dport, &[]).unwrap();
        // ICMP message = 8-byte header + the quoted probe.
        let mut icmp = vec![icmp_type, icmp_code, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&probe);
        // Wrap in an IPv4 header from `src` (proto 1 = ICMP) via the TCP builder's IP
        // path is unavailable; hand-build a minimal IPv4 header.
        let mut ip = vec![
            0x45,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            64,
            IPPROTO_ICMP,
            0,
            0,
            src[0],
            src[1],
            src[2],
            src[3],
            10,
            0,
            0,
            1,
        ];
        let total = u16::try_from(ip.len().saturating_add(icmp.len())).unwrap();
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&icmp);
        ip
    }

    #[test]
    fn icmp_port_unreachable_from_target_is_closed() {
        let ip = icmp_quoting([10, 0, 0, 2], 3, 3, 40002, 53);
        let m = match_udp_response(&framed(&ip), true, &ctx()).unwrap();
        assert_eq!(m.port, 53);
        assert_eq!(m.tryno, 2);
        assert_eq!(m.state, PortState::Closed);
    }

    #[test]
    fn icmp_admin_prohibited_is_filtered() {
        let ip = icmp_quoting([10, 0, 0, 2], 3, 13, 40000, 53);
        let m = match_udp_response(&framed(&ip), true, &ctx()).unwrap();
        assert_eq!(m.state, PortState::Filtered);
    }

    #[test]
    fn port_unreachable_from_a_router_is_filtered_not_closed() {
        // Same error but from a different source (not the target) → filtered.
        let ip = icmp_quoting([192, 168, 0, 1], 3, 3, 40000, 53);
        let m = match_udp_response(&framed(&ip), true, &ctx()).unwrap();
        assert_eq!(m.state, PortState::Filtered);
    }

    #[test]
    fn out_of_range_and_malformed_are_ignored() {
        // Datagram to a dst port outside our encoded range.
        let spec = Ipv4Spec::new([10, 0, 0, 2], [10, 0, 0, 1], 64, 0x1);
        let ip = build_udp_raw(&spec, 53, 50000, b"x").unwrap();
        assert!(match_udp_response(&framed(&ip), true, &ctx()).is_none());
        // Truncated frames.
        assert!(match_udp_response(&[], true, &ctx()).is_none());
        assert!(match_udp_response(&[0u8; 14], true, &ctx()).is_none());
        // A TCP packet (not our protocol) is ignored.
        let tspec = Ipv4Spec::new([10, 0, 0, 2], [10, 0, 0, 1], 64, 0x1);
        let tcp = build_tcp_raw(&tspec, 53, 40000, 1, 0, 0, 0x02, 1024, 0, &[], &[]).unwrap();
        assert!(match_udp_response(&framed(&tcp), true, &ctx()).is_none());
    }
}
