//! Matching an IPv6 response to the probe that provoked it — ports the IPv6 path of
//! nmap's `PacketParser::is_response` (`libnetutil/PacketParser.cc`), the function
//! `FPProbe::isResponse` delegates to.
//!
//! The IPv6 OS-detection driver sends 17 heterogeneous probes and captures whatever the
//! host sends back. To attribute a captured packet to the probe it answers, nmap does not
//! trust source ports alone — a TCP RST, a UDP reply, an ICMPv6 echo reply, and an ICMPv6
//! *error message quoting our probe* are all matched by re-deriving the identifying
//! fields. [`is_response`] reproduces that decision for an IPv6 sent probe.
//!
//! ## Scope: the sent packet is always ours
//!
//! `is_response`'s first argument is a probe **this scanner built** — always one of the
//! [`crate::build6`] battery: TCP, UDP, an ICMPv6 echo, or an ICMPv6 Neighbor
//! Solicitation. A hostile host cannot make us send anything else, so only those four
//! sent-types are ported; any other sent upper-layer protocol returns `false`
//! (ledgered `fp6-match-only-battery-sent-types`). The **received** packet, by contrast,
//! is attacker-controlled and handled in full generality: it is parsed totally by
//! [`crate::packet_parser`], and every field the match reads is bounds-checked, so a
//! crafted reply can cause a no-match but never a panic or an out-of-bounds read.
//!
//! ## What is compared
//!
//! After confirming both packets are IPv6 and that the response's addresses are the
//! mirror of the probe's (source ⇄ destination), the upper-layer header is located (the
//! first TCP / UDP / ICMPv6 after any extension headers) and matched by kind:
//!
//! * **sent TCP/UDP** → a response of the same protocol matches when the ports mirror
//!   (`sent.sport == rcvd.dport && rcvd.sport == sent.dport`).
//! * **sent ICMPv6 echo** → a direct **echo reply** with the same id and sequence.
//! * **sent ICMPv6 Neighbor Solicitation** → a **Neighbor Advertisement** with the
//!   solicited (`S`) flag set and the same target address.
//!
//! ## An ICMPv6 error never matches — reproduced from the C, not fixed
//!
//! `is_response` has elaborate code to match an ICMPv6 **error** message by the datagram
//! it quotes — but that code never succeeds in nmap. It searches for the quoted transport
//! header with `dynamic_cast<NetworkLayerElement *>(...)`, and `TCPHeader`, `UDPHeader`
//! and `ICMPv6Header` all derive from `TransportLayerElement` / `ICMPHeader`, **not**
//! `NetworkLayerElement`, so the cast yields `NULL` and the function returns `false`. The
//! differential confirms it: over the whole battery, nmap matches every direct reply and
//! **not one** ICMPv6 error quote. This port reproduces that — a received ICMPv6 error is
//! never a match — for two reasons: the IPv6 `fpmodel` was trained on fingerprints built
//! with this behaviour, so matching an error would desync our classification from nmap's;
//! and it is the *safer* reading anyway, since an off-path attacker can forge an ICMPv6
//! error far more easily than a genuine transport reply, and refusing to attribute one to
//! a probe denies that injection. Ledgered `fp6-match-icmp-error-never-matches`.

use crate::headers::icmpv6::{
    Icmpv6Header, ICMPV6_ECHO, ICMPV6_ECHOREPLY, ICMPV6_NGHBRADVERT, ICMPV6_NGHBRSOLICIT,
};
use crate::headers::ipv6::Ipv6Header;
use crate::packet_parser::{parse_packet, Header};

/// The outer IPv6 header of a packet and the index of its first transport/ICMPv6 layer.
struct Located<'a> {
    ip: &'a Ipv6Header,
    l4: &'a Header,
}

/// Find the outer IPv6 header and the first TCP/UDP/ICMPv6 layer after it, skipping any
/// extension headers. `None` if the packet is not IPv6, or has no such layer, or hits an
/// IPv4/ICMPv4 header first (not a shape the IPv6 matcher handles).
fn locate(headers: &[Header]) -> Option<Located<'_>> {
    let (ip_index, ip) = headers.iter().enumerate().find_map(|(i, h)| match h {
        Header::Ipv6(v6) => Some((i, v6)),
        _ => None,
    })?;
    for h in headers.iter().skip(ip_index.saturating_add(1)) {
        match h {
            Header::Tcp(_) | Header::Udp(_) | Header::Icmpv6(_) => {
                return Some(Located { ip, l4: h })
            }
            Header::Ipv4(_) | Header::Icmpv4(_) => return None,
            _ => continue,
        }
    }
    None
}

/// Whether an ICMPv6 type is one of the four error messages that quote the triggering
/// datagram — nmap's `ICMPv6Header::isError`.
fn is_error(icmp_type: u8) -> bool {
    matches!(icmp_type, 1..=4)
}

/// `(identifier, sequence)` of an ICMPv6 echo/echo-reply, from its 4-byte body.
fn echo_id_seq(icmp: &Icmpv6Header) -> Option<(u16, u16)> {
    let id = u16::from_be_bytes([*icmp.body.first()?, *icmp.body.get(1)?]);
    let seq = u16::from_be_bytes([*icmp.body.get(2)?, *icmp.body.get(3)?]);
    Some((id, seq))
}

/// The 16-byte target address of a Neighbor Solicitation/Advertisement (after the four
/// reserved/flag bytes).
fn nd_target(icmp: &Icmpv6Header) -> Option<&[u8]> {
    icmp.body.get(4..20)
}

/// The `S` (solicited) flag of a Neighbor Advertisement — bit `0x40` of the first flag
/// byte, matching `getFlags() & 0x40`.
fn na_solicited(icmp: &Icmpv6Header) -> bool {
    icmp.body.first().is_some_and(|f| f & 0x40 != 0)
}

/// Does `rcvd` answer the probe `sent`? Both are raw packets starting at the IPv6 header
/// (no link framing), as captured. Total on any `rcvd`.
#[must_use]
pub fn is_response(sent: &[u8], rcvd: &[u8]) -> bool {
    let sent_headers = parse_packet(sent, false);
    let rcvd_headers = parse_packet(rcvd, false);
    let (Some(s), Some(r)) = (locate(&sent_headers), locate(&rcvd_headers)) else {
        return false;
    };

    // The response must come from the host we probed and be addressed to us.
    if r.ip.src != s.ip.dst || r.ip.dst != s.ip.src {
        return false;
    }

    match s.l4 {
        Header::Icmpv6(sent_icmp) => match_icmp_sent(sent_icmp, &r),
        Header::Tcp(_) | Header::Udp(_) => match_transport_sent(&s, &r),
        // Unreachable: the battery only sends TCP/UDP/ICMPv6 probes.
        _ => false,
    }
}

/// Match when the probe was an ICMPv6 echo or Neighbor Solicitation.
fn match_icmp_sent(sent_icmp: &Icmpv6Header, r: &Located) -> bool {
    let Header::Icmpv6(rcvd_icmp) = r.l4 else {
        return false;
    };

    // A received ICMPv6 error is never a match (see the module docs: nmap's own code
    // cannot match one, and reproducing that keeps us in step with the trained model and
    // rejects forged errors).
    if is_error(rcvd_icmp.icmp_type) {
        return false;
    }

    // A direct informational reply.
    match sent_icmp.icmp_type {
        ICMPV6_ECHO => {
            rcvd_icmp.icmp_type == ICMPV6_ECHOREPLY
                && echo_id_seq(sent_icmp) == echo_id_seq(rcvd_icmp)
        }
        ICMPV6_NGHBRSOLICIT => {
            rcvd_icmp.icmp_type == ICMPV6_NGHBRADVERT
                && na_solicited(rcvd_icmp)
                && nd_target(sent_icmp) == nd_target(rcvd_icmp)
        }
        _ => false,
    }
}

/// Match when the probe was TCP or UDP.
fn match_transport_sent(s: &Located, r: &Located) -> bool {
    let (sent_sport, sent_dport) = ports(s.l4).expect("sent is TCP/UDP here");

    match r.l4 {
        // A direct transport reply of the *same* protocol: ports must mirror.
        Header::Tcp(t) if matches!(s.l4, Header::Tcp(_)) => {
            sent_sport == t.dport && t.sport == sent_dport
        }
        Header::Udp(u) if matches!(s.l4, Header::Udp(_)) => {
            sent_sport == u.dport && u.sport == sent_dport
        }
        // A received ICMPv6 error is never a match (see the module docs).
        _ => false,
    }
}

/// The source/destination ports of a TCP or UDP header, or `None` for anything else.
fn ports(h: &Header) -> Option<(u16, u16)> {
    match h {
        Header::Tcp(t) => Some((t.sport, t.dport)),
        Header::Udp(u) => Some((u.sport, u.dport)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const US: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    const THEM: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];
    const OTHER: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
    ];

    fn ipv6(src: [u8; 16], dst: [u8; 16], nh: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x60, 0x01, 0x23, 0x45]);
        p.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        p.push(nh);
        p.push(64);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(payload);
        p
    }

    fn tcp(sport: u16, dport: u16) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&[0; 8]); // seq, ack
        t.push(0x50); // data offset 5
        t.push(0x14); // RST+ACK
        t.extend_from_slice(&[0; 6]); // window, cksum, urg
        t
    }

    fn icmp6(t: u8, code: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![t, code, 0, 0];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn tcp_reply_with_mirrored_ports_matches() {
        let sent = ipv6(US, THEM, 6, &tcp(33000, 22));
        let reply = ipv6(THEM, US, 6, &tcp(22, 33000));
        assert!(is_response(&sent, &reply));
    }

    #[test]
    fn tcp_reply_with_wrong_source_host_does_not_match() {
        let sent = ipv6(US, THEM, 6, &tcp(33000, 22));
        let reply = ipv6(OTHER, US, 6, &tcp(22, 33000));
        assert!(!is_response(&sent, &reply));
    }

    #[test]
    fn tcp_reply_with_unmirrored_ports_does_not_match() {
        let sent = ipv6(US, THEM, 6, &tcp(33000, 22));
        let reply = ipv6(THEM, US, 6, &tcp(33000, 22));
        assert!(!is_response(&sent, &reply));
    }

    #[test]
    fn echo_reply_with_matching_id_seq_matches() {
        let echo = icmp6(128, 0, &[0xab, 0xcd, 0x12, 0x34, 0, 0, 0, 0]);
        let reply = icmp6(129, 0, &[0xab, 0xcd, 0x12, 0x34, 0, 0, 0, 0]);
        let sent = ipv6(US, THEM, 58, &echo);
        let rcvd = ipv6(THEM, US, 58, &reply);
        assert!(is_response(&sent, &rcvd));
    }

    #[test]
    fn echo_reply_with_wrong_seq_does_not_match() {
        let echo = icmp6(128, 0, &[0xab, 0xcd, 0x12, 0x34, 0, 0, 0, 0]);
        let reply = icmp6(129, 0, &[0xab, 0xcd, 0x99, 0x99, 0, 0, 0, 0]);
        assert!(!is_response(
            &ipv6(US, THEM, 58, &echo),
            &ipv6(THEM, US, 58, &reply)
        ));
    }

    #[test]
    fn neighbor_advert_needs_the_solicited_flag_and_target() {
        // NS target = THEM; NA carries flags + target.
        let ns = icmp6(135, 0, &{
            let mut b = vec![0u8; 4];
            b.extend_from_slice(&THEM);
            b
        });
        let na = |flags: u8, target: [u8; 16]| {
            icmp6(136, 0, &{
                let mut b = vec![flags, 0, 0, 0];
                b.extend_from_slice(&target);
                b
            })
        };
        let sent = ipv6(US, THEM, 58, &ns);
        assert!(is_response(&sent, &ipv6(THEM, US, 58, &na(0x40, THEM))));
        assert!(!is_response(&sent, &ipv6(THEM, US, 58, &na(0x00, THEM)))); // no S flag
        assert!(!is_response(&sent, &ipv6(THEM, US, 58, &na(0x40, OTHER)))); // wrong target
    }

    /// The C's `dynamic_cast` bug means a received ICMPv6 error never matches. A
    /// destination-unreachable that quotes our exact TCP probe is still a non-match.
    #[test]
    fn an_icmp_error_quoting_our_probe_never_matches() {
        let probe_tcp = tcp(33000, 22);
        let quoted = ipv6(US, THEM, 6, &probe_tcp);
        let mut err_body = vec![0u8; 4]; // unused field
        err_body.extend_from_slice(&quoted);
        let err = icmp6(1, 0, &err_body); // destination unreachable
        let sent = ipv6(US, THEM, 6, &probe_tcp);
        let rcvd = ipv6(THEM, US, 58, &err);
        assert!(!is_response(&sent, &rcvd));
    }

    #[test]
    fn total_on_garbage_received_packets() {
        let sent = ipv6(US, THEM, 6, &tcp(33000, 22));
        for len in 0..80usize {
            let rcvd: Vec<u8> = (0..len).map(|i| u8::try_from(i & 0xff).unwrap()).collect();
            let _ = is_response(&sent, &rcvd); // must not panic
        }
    }
}
