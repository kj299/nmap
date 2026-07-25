//! Parsing the probe **quoted inside an ICMP error** — the primitive every raw scan needs
//! to turn "some router sent me an ICMP unreachable" into "that is the answer to *this*
//! probe of *that* host".
//!
//! An ICMPv4 destination-unreachable (type 3) or time-exceeded (type 11) carries, after
//! its 8-byte header, a copy of the packet that provoked it: the original IPv4 header
//! plus at least the first 8 bytes of its transport header. Those 8 bytes are exactly
//! enough for the source port, destination port, and — for TCP — the sequence number, so
//! a scan can tie the error back to the attempt it answers.
//!
//! ## The three addresses, and why they are not interchangeable
//!
//! * **`sender`** — who sent the error. Legitimately an intermediate *router*, not the
//!   host being scanned.
//! * **`quoted_src`** — the source of the packet being quoted. This must be **our own**
//!   address; if it is not, the error is not about a packet we sent, and the C says so
//!   plainly: *"If it didn't come from us, we don't care."*
//! * **`quoted_dst`** — where our probe was going: the **host the verdict belongs to**.
//!   Never `sender`, which may be a router several hops away.
//!
//! [`Quote::from_target`] is then just `sender == quoted_dst` — "the error came from the
//! host it quotes a probe to" — which is what promotes a port-unreachable from *filtered*
//! to *closed*. This mirrors nmap's `scan_engine_raw.cc`, which looks the host up by
//! `encaps_hdr.dst` and computes `from_target` against the outer source.
//!
//! Total on all input: every field is bounds-checked, and a malformed or truncated quote
//! yields `None` rather than a panic. Reached from the fuzzed matchers of all three raw
//! scans.

use crate::model::Reason;
use crate::packet_parser::{parse_packet, Header};
use crate::recv_validate::validate_packet;

/// ICMPv4 destination unreachable — quotes the packet that could not be delivered.
pub const ICMP_DEST_UNREACH: u8 = 3;
/// ICMPv4 time exceeded — quotes the packet whose TTL ran out.
pub const ICMP_TIME_EXCEEDED: u8 = 11;

/// IP protocol number of a TCP quote, for comparing against [`Quote::proto`].
pub const IPPROTO_TCP: u8 = 6;
/// IP protocol number of a UDP quote, for comparing against [`Quote::proto`].
pub const IPPROTO_UDP: u8 = 17;

const IPPROTO_ICMP: u8 = 1;
/// Minimum IPv4 header length.
const IP_MIN: usize = 20;
/// Fixed ICMPv4 header length; the quoted packet begins after it.
const ICMP_HEADER_LEN: usize = 8;
/// Bytes of the quoted transport header the C requires: enough for both ports, and for
/// TCP the sequence number ("UDP hdr, or TCP hdr up to seq #").
const QUOTED_TRANSPORT_MIN: usize = 8;

/// An ICMP error together with the probe it quotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quote {
    /// ICMP type — only [`ICMP_DEST_UNREACH`] or [`ICMP_TIME_EXCEEDED`] are produced.
    pub icmp_type: u8,
    /// ICMP code, interpreted per scan type by [`crate::classify::classify_icmp`].
    pub icmp_code: u8,
    /// Who sent the error; may be an intermediate router.
    pub sender: [u8; 4],
    /// Source of the quoted packet — must be our own address to be relevant.
    pub quoted_src: [u8; 4],
    /// Destination of the quoted packet: the scanned host this verdict belongs to.
    pub quoted_dst: [u8; 4],
    /// IP protocol of the quoted packet (6 = TCP, 17 = UDP).
    pub proto: u8,
    /// Source port of the quoted packet — our per-attempt encoded port.
    pub sport: u16,
    /// Destination port of the quoted packet — the scanned port.
    pub dport: u16,
    /// The quoted TCP sequence number, when the quote is TCP and long enough to include
    /// it. `None` for UDP (whose header has no sequence).
    pub seq: Option<u32>,
}

impl Quote {
    /// Whether the error came from the very host our probe was addressed to, as opposed
    /// to a router on the way. Only then is a port-unreachable authoritative.
    #[must_use]
    pub fn from_target(&self) -> bool {
        self.sender == self.quoted_dst
    }
}

/// Parse a captured frame as an ICMP error quoting one of our probes.
///
/// Returns `None` unless the frame is a well-formed IPv4/ICMP type-3 or type-11 message
/// whose quoted packet is IPv4 with at least [`QUOTED_TRANSPORT_MIN`] bytes of transport
/// header — the same acceptance the C applies before it searches for a matching probe.
#[must_use]
pub fn parse_icmp_error(frame: &[u8], eth_included: bool) -> Option<Quote> {
    let ip_off = ipv4_offset(frame, eth_included)?;
    let ip = frame.get(ip_off..)?;
    let v = validate_packet(ip).ok()?;
    if v.proto != IPPROTO_ICMP {
        return None;
    }
    let sender: [u8; 4] = ip.get(12..16)?.try_into().ok()?;

    let icmp = ip.get(v.data_offset..)?;
    if icmp.len() < ICMP_HEADER_LEN {
        return None;
    }
    let (icmp_type, icmp_code) = (icmp[0], icmp[1]);
    // Only these two quote the offending packet; anything else cannot be matched.
    if icmp_type != ICMP_DEST_UNREACH && icmp_type != ICMP_TIME_EXCEEDED {
        return None;
    }

    let quoted = icmp.get(ICMP_HEADER_LEN..)?;
    if quoted.len() < IP_MIN || quoted[0] >> 4 != 4 {
        return None; // not a (complete enough) IPv4 quote
    }
    let ihl = usize::from(quoted[0] & 0x0F).checked_mul(4)?;
    if ihl < IP_MIN {
        return None;
    }
    let proto = quoted[9];
    let quoted_src: [u8; 4] = quoted.get(12..16)?.try_into().ok()?;
    let quoted_dst: [u8; 4] = quoted.get(16..20)?.try_into().ok()?;

    let transport = quoted.get(ihl..)?;
    if transport.len() < QUOTED_TRANSPORT_MIN {
        return None;
    }
    let sport = u16::from_be_bytes([transport[0], transport[1]]);
    let dport = u16::from_be_bytes([transport[2], transport[3]]);
    // Bytes 4..8 are the TCP sequence number; for UDP they are length + checksum, which
    // carry no attempt information, so only TCP reports a sequence.
    let seq = (proto == IPPROTO_TCP)
        .then(|| u32::from_be_bytes([transport[4], transport[5], transport[6], transport[7]]));

    Some(Quote {
        icmp_type,
        icmp_code,
        sender,
        quoted_src,
        quoted_dst,
        proto,
        sport,
        dport,
        seq,
    })
}

/// The reason nmap reports for an ICMP error, port of `portreasons.cc: icmp_to_reason`
/// (the ICMPv4 arm, restricted to the quoting types).
///
/// Note the three *prohibited* codes are three distinct reasons in nmap, not one:
/// 9 is `net-prohibited`, 10 `host-prohibited`, 13 `admin-prohibited`.
#[must_use]
pub fn icmp_to_reason(icmp_type: u8, icmp_code: u8) -> Reason {
    match icmp_type {
        ICMP_DEST_UNREACH => match icmp_code {
            0 => Reason::NetUnreach,
            1 => Reason::HostUnreach,
            2 => Reason::ProtoUnreach,
            3 => Reason::PortUnreach,
            9 => Reason::NetProhibited,
            10 => Reason::HostProhibited,
            13 => Reason::AdminProhibited,
            _ => Reason::DestUnreach,
        },
        ICMP_TIME_EXCEEDED => Reason::TimeExceeded,
        _ => Reason::Unknown,
    }
}

/// Byte offset of the IPv4 header inside a captured frame, or `None` if the frame has no
/// IPv4 layer. Shared by every raw-scan matcher (each used to carry its own copy).
#[must_use]
pub fn ipv4_offset(frame: &[u8], eth_included: bool) -> Option<usize> {
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
    use crate::build::{build_tcp_raw, build_udp_raw, Ipv4Spec};

    const US: [u8; 4] = [10, 0, 0, 1];
    const TARGET: [u8; 4] = [10, 0, 0, 2];
    const ROUTER: [u8; 4] = [192, 168, 0, 1];

    fn framed(ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f.extend_from_slice(ip);
        f
    }

    /// An ICMP `type`/`code` error from `sender`, quoting `quoted` (a full IP packet).
    fn icmp_error(sender: [u8; 4], icmp_type: u8, icmp_code: u8, quoted: &[u8]) -> Vec<u8> {
        let mut icmp = vec![icmp_type, icmp_code, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(quoted);
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
            sender[0],
            sender[1],
            sender[2],
            sender[3],
            US[0],
            US[1],
            US[2],
            US[3],
        ];
        let total = u16::try_from(ip.len().saturating_add(icmp.len())).unwrap();
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&icmp);
        framed(&ip)
    }

    fn udp_probe(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        build_udp_raw(&Ipv4Spec::new(src, dst, 64, 1), sport, dport, &[]).unwrap()
    }

    fn tcp_probe(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, seq: u32) -> Vec<u8> {
        build_tcp_raw(
            &Ipv4Spec::new(src, dst, 64, 1),
            sport,
            dport,
            seq,
            0,
            0,
            0x02,
            1024,
            0,
            &[],
            &[],
        )
        .unwrap()
    }

    #[test]
    fn parses_a_udp_quote_and_its_three_addresses() {
        let probe = udp_probe(US, TARGET, 40000, 53);
        let q = parse_icmp_error(&icmp_error(TARGET, 3, 3, &probe), true).unwrap();
        assert_eq!(q.icmp_type, 3);
        assert_eq!(q.icmp_code, 3);
        assert_eq!(q.sender, TARGET);
        assert_eq!(q.quoted_src, US, "the quote's source is us");
        assert_eq!(
            q.quoted_dst, TARGET,
            "the quote's destination is the target"
        );
        assert_eq!(q.proto, 17);
        assert_eq!(q.sport, 40000);
        assert_eq!(q.dport, 53);
        assert_eq!(q.seq, None, "UDP carries no sequence");
        assert!(q.from_target(), "sender == quoted destination");
    }

    #[test]
    fn parses_a_tcp_quote_including_the_sequence() {
        let probe = tcp_probe(US, TARGET, 40001, 80, 0xDEAD_BEEF);
        let q = parse_icmp_error(&icmp_error(TARGET, 3, 13, &probe), true).unwrap();
        assert_eq!(q.proto, 6);
        assert_eq!(q.sport, 40001);
        assert_eq!(q.dport, 80);
        assert_eq!(q.seq, Some(0xDEAD_BEEF), "TCP sequence is recoverable");
    }

    #[test]
    fn an_error_relayed_by_a_router_is_not_from_target() {
        let probe = udp_probe(US, TARGET, 40000, 53);
        let q = parse_icmp_error(&icmp_error(ROUTER, 3, 3, &probe), true).unwrap();
        assert_eq!(q.sender, ROUTER);
        assert_eq!(
            q.quoted_dst, TARGET,
            "the verdict still belongs to the target"
        );
        assert!(
            !q.from_target(),
            "a router's port-unreachable is not authoritative"
        );
    }

    #[test]
    fn a_quote_of_someone_elses_packet_is_visible_as_such() {
        // Quote a packet we never sent (source is not us). The parser reports it
        // faithfully; callers reject it by comparing `quoted_src` to their own address.
        let probe = udp_probe(ROUTER, TARGET, 40000, 53);
        let q = parse_icmp_error(&icmp_error(TARGET, 3, 3, &probe), true).unwrap();
        assert_eq!(q.quoted_src, ROUTER);
        assert_ne!(q.quoted_src, US, "callers must reject this");
    }

    #[test]
    fn only_quoting_icmp_types_are_accepted() {
        let probe = udp_probe(US, TARGET, 40000, 53);
        // Echo request/reply and friends carry no quote to match against.
        for t in [0u8, 4, 5, 8, 12, 13, 14, 30, 255] {
            assert!(
                parse_icmp_error(&icmp_error(TARGET, t, 0, &probe), true).is_none(),
                "type {t} must not parse as a quoting error"
            );
        }
        assert!(parse_icmp_error(&icmp_error(TARGET, 3, 0, &probe), true).is_some());
        assert!(parse_icmp_error(&icmp_error(TARGET, 11, 0, &probe), true).is_some());
    }

    #[test]
    fn truncated_and_malformed_quotes_are_rejected_not_panicked() {
        let probe = udp_probe(US, TARGET, 40000, 53);
        let full = icmp_error(TARGET, 3, 3, &probe);
        // Every truncation of a valid frame must be handled.
        for n in 0..full.len() {
            let _ = parse_icmp_error(&full[..n], true);
        }
        // A quote with fewer than 8 transport bytes is rejected (the C's rule).
        let short_quote = &probe[..probe.len().min(20 + 7)];
        assert!(parse_icmp_error(&icmp_error(TARGET, 3, 3, short_quote), true).is_none());
        // A quote that is not IPv4.
        let mut not_v4 = probe.clone();
        not_v4[0] = 0x65;
        assert!(parse_icmp_error(&icmp_error(TARGET, 3, 3, &not_v4), true).is_none());
        // A quote claiming an IHL below the minimum.
        let mut bad_ihl = probe.clone();
        bad_ihl[0] = 0x43;
        assert!(parse_icmp_error(&icmp_error(TARGET, 3, 3, &bad_ihl), true).is_none());
        // Empty and header-only frames.
        assert!(parse_icmp_error(&[], true).is_none());
        assert!(parse_icmp_error(&[0u8; 14], true).is_none());
    }

    #[test]
    fn a_non_icmp_frame_is_not_a_quote() {
        let tcp = tcp_probe(TARGET, US, 80, 40000, 1);
        assert!(parse_icmp_error(&framed(&tcp), true).is_none());
        let udp = udp_probe(TARGET, US, 53, 40000);
        assert!(parse_icmp_error(&framed(&udp), true).is_none());
    }

    #[test]
    fn ipv4_offset_finds_the_layer_with_and_without_ethernet() {
        let ip = udp_probe(US, TARGET, 40000, 53);
        assert_eq!(ipv4_offset(&framed(&ip), true), Some(14));
        assert_eq!(ipv4_offset(&ip, false), Some(0));
        assert_eq!(ipv4_offset(&[], false), None);
    }
}
