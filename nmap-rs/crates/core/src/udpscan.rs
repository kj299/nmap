//! UDP-scan probe construction and response matching — the pure `core` half of the
//! `-sU` scan. Ports the UDP-specific pieces of nmap's `scan_engine_raw.cc`: the UDP
//! probe build and the two ways a UDP probe is answered —
//!
//!   * a **direct UDP datagram** back from the target → the port is **open**
//!     (`ER_UDPRESPONSE`);
//!   * an **ICMP port-unreachable** (type 3 code 3) whose *embedded* packet is our
//!     probe → the port is **closed** (`ER_PORTUNREACH`); other ICMP unreachable /
//!     time-exceeded codes → **filtered**. A port-unreachable is only *closed* when it
//!     comes from the host the quoted probe was addressed to; from anywhere else
//!     (a router) it is *filtered*.
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
//! ## Which host a reply is about
//!
//! [`UdpReply::src_ip`] names the **scanned host the reply concerns**, so one matcher
//! can serve a whole host group (see `nmap_sys::group`). For a direct datagram that is
//! simply the reply's source address. For an ICMP error it is the **destination of the
//! quoted probe** — the host we sent it to — *not* the ICMP sender, which is legitimately
//! an intermediate router. `from_target` (which decides port-unreachable → *closed*
//! rather than *filtered*) is then just "the ICMP came from the host it quotes a probe
//! to", needing no external knowledge of what is being scanned.
//!
//! ## Scope / divergences (ledgered in `DIVERGENCES.md`)
//!
//! * Protocol-specific probe payloads live in [`crate::payload`]; pass one to
//!   [`build_udp_probe_with`]. [`build_udp_probe`] keeps the bare, zero-length datagram
//!   for callers that have no payload table (and for the on-the-wire differential).
//! * Matches IPv4 and IPv6 replies: [`match_udp_response`] is generic over the
//!   [`IpFamily`]. The engine sends IPv6 UDP probes to every target since IPv6 scans
//!   step e (`ipv6-raw-port-scans-unported`, resolved).

use crate::build::{BuildError, ProbeSpec};
use crate::classify::{classify_udp_response, PortState, ScanType};
use crate::icmp_quote::IPPROTO_UDP;
use crate::ipfamily::IpFamily;
use crate::model::Reason;
use crate::synscan::sport_encode;
/// Bytes of a UDP header we read (source + dest ports).
const UDP_PORTS_LEN: usize = 4;

/// The payload of a *bare* UDP probe — empty. Ports with a protocol-specific payload
/// registered in [`crate::payload`] send that instead (see [`build_udp_probe_with`]).
pub const UDP_PROBE_PAYLOAD: &[u8] = &[];

/// Build a raw UDP probe packet for `(dport, tryno)`, encoding the attempt in the
/// source port exactly as the SYN scan does.
///
/// # Errors
/// Propagates [`BuildError`] from [`build_udp_raw`] (only reachable via malformed
/// `spec.options`).
pub fn build_udp_probe<S: ProbeSpec>(
    spec: &S,
    base_port: u16,
    dport: u16,
    tryno: u32,
) -> Result<Vec<u8>, BuildError> {
    build_udp_probe_with(spec, base_port, dport, tryno, UDP_PROBE_PAYLOAD)
}

/// Build a raw UDP probe carrying an explicit `payload` — the protocol-specific payload
/// [`crate::payload`] registers for the port. Otherwise identical to [`build_udp_probe`]:
/// the attempt is encoded in the source port, so every payload sent for one logical
/// probe shares that source port (as nmap does).
///
/// # Errors
/// Propagates [`BuildError`] from [`build_udp_raw`] — notably when the payload would
/// push the datagram past the maximum packet size, which is rejected rather than
/// truncated.
pub fn build_udp_probe_with<S: ProbeSpec>(
    spec: &S,
    base_port: u16,
    dport: u16,
    tryno: u32,
    payload: &[u8],
) -> Result<Vec<u8>, BuildError> {
    let sport = sport_encode(base_port, tryno);
    spec.udp_probe(sport, dport, payload)
}

/// The per-scan constants a captured reply is matched against. Deliberately carries no
/// target address — see the module docs on which host a reply is about. `A` is the
/// address family ([`IpFamily`]).
#[derive(Debug, Clone, Copy)]
pub struct UdpMatchCtx<A = [u8; 4]> {
    /// Our own source address. An ICMP error is only about a probe of ours if the packet
    /// it quotes was sent *from* here — the C's "If it didn't come from us, we don't
    /// care."
    pub our_ip: A,
    /// Base UDP source port (the `tryno == 0` source port).
    pub base_port: u16,
    /// Highest attempt number in flight.
    pub max_tryno: u32,
}

/// A captured packet matched to an outstanding UDP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpReply<A = [u8; 4]> {
    /// The scanned host this reply is about: the sender for a direct datagram, or the
    /// destination of the quoted probe for an ICMP error.
    pub src_ip: A,
    /// The scanned port that answered.
    pub port: u16,
    /// Which attempt this reply answers.
    pub tryno: u32,
    /// The port state the reply implies.
    pub state: PortState,
    /// Why: `udp-response` for a datagram, or the specific ICMP unreachable code.
    pub reason: Reason,
}

/// Decide whether a captured frame answers one of our UDP probes, and to what state.
///
/// Handles a direct UDP datagram (→ open) and an ICMP error whose embedded packet is
/// one of our probes (port-unreach from the target → closed, else filtered, by the
/// family's classifier). The family is the context's. Returns `None` for anything
/// else. Total on all input — the primary fuzz target of the UDP receive path.
#[must_use]
pub fn match_udp_response<A: IpFamily>(
    frame: &[u8],
    eth_included: bool,
    ctx: &UdpMatchCtx<A>,
) -> Option<UdpReply<A>> {
    let r = A::received(frame, eth_included)?;

    match r.v.proto {
        IPPROTO_UDP => {
            // A direct datagram: its source port is the scanned port, its destination
            // is our encoded source port (→ the attempt).
            let udp = r.transport()?;
            if udp.len() < UDP_PORTS_LEN {
                return None;
            }
            let scanned = u16::from_be_bytes([udp[0], udp[1]]);
            let our_sport = u16::from_be_bytes([udp[2], udp[3]]);
            let tryno = attempt_from_sport(our_sport, ctx)?;
            Some(UdpReply {
                src_ip: r.src,
                port: scanned,
                tryno,
                state: classify_udp_response(),
                reason: Reason::UdpResponse,
            })
        }
        p if p == A::ICMP => {
            let quote = A::quote(&r)?;
            if quote.proto != IPPROTO_UDP {
                return None; // an error about something other than our UDP probe
            }
            // The quoted packet must be one *we* sent.
            if quote.quoted_src != ctx.our_ip {
                return None;
            }
            let tryno = attempt_from_sport(quote.sport, ctx)?;
            let state = A::classify_error(ScanType::Udp, &quote)?;
            Some(UdpReply {
                // The verdict belongs to the host we probed, not to whoever relayed it.
                src_ip: quote.quoted_dst,
                port: quote.dport,
                tryno,
                state,
                reason: A::error_reason(&quote),
            })
        }
        _ => None,
    }
}

/// Recover the attempt number from an encoded source port, rejecting ports outside our
/// range.
fn attempt_from_sport<A>(sport: u16, ctx: &UdpMatchCtx<A>) -> Option<u32> {
    let tryno = u32::from(sport.wrapping_sub(ctx.base_port));
    (tryno <= ctx.max_tryno).then_some(tryno)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::{build_udp_raw, Ipv4Spec};
    use crate::recv_validate::validate_packet;

    const IPPROTO_ICMP: u8 = 1;
    use crate::build::build_tcp_raw;

    fn ctx() -> UdpMatchCtx {
        UdpMatchCtx {
            our_ip: [10, 0, 0, 1],
            base_port: 40000,
            max_tryno: 11,
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
        // A direct datagram is about the host that sent it.
        assert_eq!(m.src_ip, [10, 0, 0, 2]);
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
        // Still attributed to the host we probed, not to the router that answered.
        assert_eq!(m.src_ip, [10, 0, 0, 2]);
    }

    #[test]
    fn icmp_error_is_attributed_to_the_quoted_destination() {
        // A host that answers with an error quoting a probe we sent to a *different*
        // host cannot launder that into a verdict about itself: the reply is attributed
        // to the quoted destination, and — since sender != quoted destination — the
        // port-unreachable reads as filtered rather than closed.
        let ip = icmp_quoting([10, 0, 0, 9], 3, 3, 40000, 53);
        let m = match_udp_response(&framed(&ip), true, &ctx()).unwrap();
        assert_eq!(m.src_ip, [10, 0, 0, 2], "attributed to the probed host");
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

    // ---- IPv6 ----

    mod v6 {
        use super::super::*;
        use crate::ipfamily::test6::*;

        fn ctx6() -> UdpMatchCtx<[u8; 16]> {
            UdpMatchCtx {
                our_ip: US6,
                base_port: 40000,
                max_tryno: 11,
            }
        }

        fn our_probe(src: [u8; 16], port: u16, tryno: u16) -> Vec<u8> {
            ipv6(
                src,
                TARGET6,
                17,
                &[],
                &udp(40000u16.wrapping_add(tryno), port, b"\x00\x01"),
            )
        }

        #[test]
        fn a_datagram_back_is_open() {
            let pkt = ipv6(TARGET6, US6, 17, &[], &udp(53, 40002, b"answer"));
            let m = match_udp_response(&eth(&pkt), true, &ctx6()).unwrap();
            assert_eq!(
                (m.src_ip, m.port, m.tryno, m.state, m.reason),
                (TARGET6, 53, 2, PortState::Open, Reason::UdpResponse)
            );
            // Behind a destination-options header too.
            let pkt = ipv6(TARGET6, US6, 60, &dstopts(17), &udp(53, 40000, b""));
            assert!(match_udp_response(&pkt, false, &ctx6()).is_some());
            // Not to one of our ports.
            let pkt = ipv6(TARGET6, US6, 17, &[], &udp(53, 39999, b""));
            assert!(match_udp_response(&pkt, false, &ctx6()).is_none());
        }

        #[test]
        fn port_unreachable_is_closed_from_the_target_and_filtered_from_a_router() {
            let probe = our_probe(US6, 161, 1);
            let err = icmpv6_error(TARGET6, 1, 4, None, &[], &probe);
            let m = match_udp_response(&err, false, &ctx6()).unwrap();
            assert_eq!(
                (m.src_ip, m.port, m.tryno, m.state, m.reason),
                (TARGET6, 161, 1, PortState::Closed, Reason::PortUnreach)
            );
            let err = icmpv6_error(ROUTER6, 1, 4, None, &[], &probe);
            let m = match_udp_response(&err, false, &ctx6()).unwrap();
            assert_eq!((m.src_ip, m.state), (TARGET6, PortState::Filtered));
        }

        #[test]
        fn other_errors_are_filtered_or_ignored() {
            let probe = our_probe(US6, 161, 0);
            for (c, reason) in [
                (0, Reason::NoRoute),
                (1, Reason::AdminProhibited),
                (2, Reason::BeyondScope),
                (3, Reason::HostUnreach),
                (5, Reason::AdminProhibited),
                (6, Reason::RejectRoute),
            ] {
                let err = icmpv6_error(TARGET6, 1, c, None, &[], &probe);
                let m = match_udp_response(&err, false, &ctx6()).unwrap();
                assert_eq!((m.state, m.reason), (PortState::Filtered, reason), "1/{c}");
            }
            // D2: an erroneous-header-field report from the target is not open.
            let err = icmpv6_error(TARGET6, 4, 0, None, &[], &probe);
            let m = match_udp_response(&err, false, &ctx6()).unwrap();
            assert_eq!(
                (m.state, m.reason),
                (PortState::Filtered, Reason::ParamProblem)
            );
            let err = icmpv6_error(TARGET6, 4, 1, None, &[], &probe);
            assert_eq!(
                match_udp_response(&err, false, &ctx6()).unwrap().state,
                PortState::Filtered
            );
            // Q5, Q6.
            for (t, c) in [(3, 0), (2, 0), (1, 9), (4, 2)] {
                let err = icmpv6_error(TARGET6, t, c, None, &[], &probe);
                assert!(
                    match_udp_response(&err, false, &ctx6()).is_none(),
                    "{t}/{c}"
                );
            }
        }

        #[test]
        fn quotes_must_be_of_our_udp_probes() {
            // A quoted TCP segment.
            let tcp = ipv6(US6, TARGET6, 6, &[], &tcp(40000, 161, 1, 0, 0x02, 1024));
            let err = icmpv6_error(TARGET6, 1, 4, None, &[], &tcp);
            assert!(match_udp_response(&err, false, &ctx6()).is_none());
            // From someone else.
            let err = icmpv6_error(TARGET6, 1, 4, None, &[], &our_probe(ROUTER6, 161, 0));
            assert!(match_udp_response(&err, false, &ctx6()).is_none());
            // Behind extension headers on both sides.
            let probe = ipv6(US6, TARGET6, 60, &dstopts(17), &udp(40003, 161, b""));
            let err = icmpv6_error(TARGET6, 1, 4, Some(60), &dstopts(58), &probe);
            let m = match_udp_response(&err, false, &ctx6()).unwrap();
            assert_eq!((m.port, m.tryno, m.state), (161, 3, PortState::Closed));
            // An IPv4 context does not read it.
            assert!(match_udp_response(&err, false, &super::ctx()).is_none());
        }

        /// A UDP probe built for IPv6, payload included, matched by its own quote.
        #[test]
        fn our_ipv6_udp_probe_is_recognised_in_an_icmpv6_quote() {
            use crate::build::Ipv6Spec;
            let probe =
                build_udp_probe_with(&Ipv6Spec::new(US6, TARGET6), 40000, 161, 2, b"\x30\x26")
                    .unwrap();
            let v = crate::recv_validate::validate_packet(&probe).unwrap();
            assert_eq!(
                (v.version, v.proto, probe.len(), probe[7]),
                (6, 17, 50, 255)
            );
            let err = icmpv6_error(TARGET6, 1, 4, None, &[], &probe);
            let m = match_udp_response(&err, false, &ctx6()).unwrap();
            assert_eq!((m.port, m.tryno, m.state), (161, 2, PortState::Closed));
        }

        #[test]
        fn every_truncation_is_handled() {
            let err = eth(&icmpv6_error(
                TARGET6,
                1,
                4,
                Some(60),
                &dstopts(58),
                &our_probe(US6, 161, 0),
            ));
            for n in 0..=err.len() {
                let _ = match_udp_response(&err[..n], true, &ctx6());
            }
        }
    }
}
