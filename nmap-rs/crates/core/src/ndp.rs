//! IPv6 Neighbor Discovery — the pure half of next-hop MAC resolution.
//!
//! A full-packet IPv6 send has to go out at **layer 2**: Linux has no `IPV6_HDRINCL`,
//! so unlike the IPv4 path there is no raw socket that will accept a caller-built IPv6
//! header and route it. The driver must frame its own Ethernet header, which means it
//! must know the next hop's MAC. This module is the pure decision layer for that:
//! build the Neighbor Solicitation, and decide whether a captured frame answers it.
//!
//! Ports the NDP half of `netutil.cc`: `doND` (frame construction, addressing) and
//! `read_ns_reply_pcap` + `accept_ns` (reply validation). The blocking send/retransmit
//! loop lives in `sys`; everything decided from bytes lives here, where it is tested
//! and fuzzed.
//!
//! # Two nmap defects deliberately **not** reproduced
//!
//! Both are in the reply path, and both are reachable by any host on the local link
//! (an unsolicited, malformed ICMPv6 type-136 frame is enough — it need not be from
//! the target, since the address check happens *after* the bytes are read):
//!
//! 1. **Out-of-bounds read of the target address.** `accept_ns` only checks that the
//!    capture holds the 40-byte IPv6 header plus the 4-byte ICMPv6 header. But
//!    `read_ns_reply_pcap` then does an unconditional
//!    `memcpy(&senderIP->sin6_addr, &na->icmpv6_target, 16)` from
//!    `offset + 44 + 4`, reading up to **20 bytes past the captured data** — the
//!    bounds check that *is* present guards only the option fields, inside an `if`
//!    the `memcpy` sits outside of. The bytes read are whatever the pcap ring buffer
//!    holds next (an adjacent packet), and they become the `senderIP` that `doND`
//!    compares against the target to decide whether to accept the reply.
//!    [`parse_neighbor_advertisement`] bounds every field and returns `None` on a
//!    short frame.
//!
//! 2. **A neighbor advertisement is accepted without a link-layer address.** The
//!    target link-layer address option is *optional* in an advertisement (RFC 4861
//!    §4.4), and `read_ns_reply_pcap` reports its absence through `has_mac` — which
//!    `doND` accepts as an out-parameter and then **never reads**. On such a reply
//!    `doND` returns `true` with the caller's `targetmac` buffer never written, and
//!    `getNextHopMAC` caches those uninitialised stack bytes as the next-hop MAC.
//!    Here the MAC is an [`Option`], so "no address" is unrepresentable as success:
//!    [`resolve_from_frame`] yields a MAC only when one was actually present.
//!
//! Both are ledgered in `DIVERGENCES.md`.

use crate::checksum::ipv6_pseudoheader_cksum;

/// ICMPv6 Neighbor Solicitation.
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
/// ICMPv6 Neighbor Advertisement.
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;
/// `IPPROTO_ICMPV6`.
pub const NH_ICMPV6: u8 = 58;
/// `ETH_TYPE_IPV6`.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Ethernet header length.
pub const ETH_HDR_LEN: usize = 14;
/// Fixed IPv6 header length.
pub const IP6_HDR_LEN: usize = 40;
/// Base ICMPv6 header length (type, code, checksum).
pub const ICMPV6_HDR_LEN: usize = 4;

/// Length of the solicitation frame nmap puts on the wire:
/// Ethernet + IPv6 + ICMPv6 + 4 reserved + 16 target + 8 option.
pub const NS_FRAME_LEN: usize = ETH_HDR_LEN + IP6_HDR_LEN + ICMPV6_HDR_LEN + 4 + 16 + 8;

/// ICMPv6 payload length of a solicitation: 4 header + 4 reserved + 16 target + 8 option.
const NS_ICMP_LEN: usize = ICMPV6_HDR_LEN + 4 + 16 + 8;

/// Source link-layer address option (used in a solicitation).
const OPT_SOURCE_LINK_ADDR: u8 = 1;
/// Target link-layer address option (used in an advertisement).
const OPT_TARGET_LINK_ADDR: u8 = 2;
/// Option length, in 8-octet units — 1 for an Ethernet address.
const OPT_LEN_ETHER: u8 = 1;

/// The solicited-node multicast address for `target`: `ff02::1:ff` followed by the
/// target's low 3 bytes (RFC 4861 §2.3).
///
/// Copies `doND`'s construction: a 13-byte prefix overwritten onto a copy of the
/// target, leaving the last three bytes in place.
#[must_use]
pub fn solicited_node_multicast(target: [u8; 16]) -> [u8; 16] {
    let mut out = target;
    let prefix: [u8; 13] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff];
    out[0..13].copy_from_slice(&prefix);
    out
}

/// The Ethernet multicast MAC for `target`'s solicited-node group: `33:33:ff` followed
/// by the target's low 3 bytes (RFC 2464 §7).
#[must_use]
pub fn solicited_node_mac(target: [u8; 16]) -> [u8; 6] {
    [0x33, 0x33, 0xff, target[13], target[14], target[15]]
}

/// Build the complete Ethernet frame for a Neighbor Solicitation asking who owns
/// `target`, sent from `src_ip`/`src_mac`.
///
/// Mirrors `doND`'s frame: destination is the solicited-node multicast (MAC and IPv6),
/// **hop limit 255** — required by RFC 4861 §7.1.1, since a receiver must reject any
/// solicitation that could have been forwarded by a router — traffic class and flow
/// label 0, and a source link-layer address option carrying `src_mac`.
#[must_use]
pub fn build_neighbor_solicitation(
    src_mac: [u8; 6],
    src_ip: [u8; 16],
    target: [u8; 16],
) -> [u8; NS_FRAME_LEN] {
    let dst_ip = solicited_node_multicast(target);
    let mut frame = [0u8; NS_FRAME_LEN];

    // Ethernet header.
    frame[0..6].copy_from_slice(&solicited_node_mac(target));
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

    // IPv6 header. Unlike the OS-detection battery, the solicitation carries no flow
    // label: `doND` passes traffic class 0 and flow label 0.
    let vtf: u32 = 6u32 << 28;
    frame[14..18].copy_from_slice(&vtf.to_be_bytes());
    let payload_len = u16::try_from(NS_ICMP_LEN).unwrap_or(u16::MAX);
    frame[18..20].copy_from_slice(&payload_len.to_be_bytes());
    frame[20] = NH_ICMPV6;
    frame[21] = 255;
    frame[22..38].copy_from_slice(&src_ip);
    frame[38..54].copy_from_slice(&dst_ip);

    // ICMPv6 solicitation: type, code, checksum, 4 reserved, target, option.
    frame[54] = ICMPV6_NEIGHBOR_SOLICITATION;
    frame[55] = 0;
    // frame[56..58] is the checksum, left zero while it is computed.
    // frame[58..62] is the reserved field, zero.
    frame[62..78].copy_from_slice(&target);
    frame[78] = OPT_SOURCE_LINK_ADDR;
    frame[79] = OPT_LEN_ETHER;
    frame[80..86].copy_from_slice(&src_mac);

    let sum = ipv6_pseudoheader_cksum(src_ip, dst_ip, NH_ICMPV6, &frame[54..NS_FRAME_LEN]);
    frame[56..58].copy_from_slice(&sum.to_be_bytes());
    frame
}

/// A parsed Neighbor Advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborAdvert {
    /// The address the advertisement is *about* — the one `doND` matches against the
    /// address it solicited.
    pub target: [u8; 16],
    /// The advertised link-layer address, when the optional target link-layer address
    /// option is present. `None` is a legal advertisement, not an error — but it
    /// resolves nothing.
    pub mac: Option<[u8; 6]>,
}

/// Parse a captured link-layer frame as a Neighbor Advertisement.
///
/// `offset` is the start of the IPv6 header within `frame` (the datalink header
/// length, as the capture reports it). Returns `None` unless the frame really is a
/// well-formed, complete advertisement.
///
/// This is the port of `accept_ns` + the body of `read_ns_reply_pcap`, with the
/// unbounded target read replaced by a checked one — see the module docs, divergence 1.
#[must_use]
pub fn parse_neighbor_advertisement(frame: &[u8], offset: usize) -> Option<NeighborAdvert> {
    // `accept_ns`: the capture must hold the IPv6 header and the ICMPv6 header.
    let icmp_start = offset.checked_add(IP6_HDR_LEN)?;
    let nd_start = icmp_start.checked_add(ICMPV6_HDR_LEN)?;
    let icmp = frame.get(icmp_start..nd_start)?;
    if icmp[0] != ICMPV6_NEIGHBOR_ADVERTISEMENT || icmp[1] != 0 {
        return None;
    }

    // The advertisement body: 4 flag bytes, the 16-byte target, then the option.
    let nd = frame.get(nd_start..)?;
    // DIVERGENCE 1: the C reads these 16 bytes unconditionally, past the capture if
    // the frame is short. `get` makes a truncated advertisement a non-match instead.
    let target: [u8; 16] = nd.get(4..20)?.try_into().ok()?;

    // The C inspects exactly this one fixed position rather than walking the option
    // list, so an advertisement whose first option is something else carries no MAC
    // as far as nmap is concerned. Copied as-is: it costs nothing but a retransmit.
    let mac = match (nd.get(20), nd.get(21), nd.get(22..28)) {
        (Some(&OPT_TARGET_LINK_ADDR), Some(&OPT_LEN_ETHER), Some(m)) => {
            Some(<[u8; 6]>::try_from(m).ok()?)
        }
        _ => None,
    };

    Some(NeighborAdvert { target, mac })
}

/// Decide whether a captured frame resolves `target`'s link-layer address.
///
/// The whole point of the exchange: `Some(mac)` only for a well-formed advertisement,
/// *about the address we asked about*, that actually carries a link-layer address.
///
/// This is where divergence 2 lands. `doND` sets `foundit` on any advertisement whose
/// target matches, without consulting `has_mac`, so an advertisement with no option
/// leaves the caller's MAC buffer untouched and still reports success. Returning the
/// MAC by value makes that outcome unrepresentable.
#[must_use]
pub fn resolve_from_frame(frame: &[u8], offset: usize, target: [u8; 16]) -> Option<[u8; 6]> {
    let na = parse_neighbor_advertisement(frame, offset)?;
    if na.target != target {
        return None;
    }
    na.mac
}

/// The capture filter `doND` installs: advertisements addressed to our own MAC.
///
/// Copies the C's format exactly, including the colon-less MAC — libpcap accepts a
/// bare 12-hex-digit address, and the `ip6[6:1]`/`ip6[40:1]` byte tests are how the C
/// reaches the ICMPv6 type (libpcap has no `icmp6[...]` accessor for IPv6, and the
/// tests only hold when there are no extension headers).
#[must_use]
pub fn na_bpf_filter(src_mac: [u8; 6]) -> String {
    format!(
        "ether dst {:02X}{:02X}{:02X}{:02X}{:02X}{:02X} and icmp6 and ip6[6:1] = {} and ip6[40:1] = {}",
        src_mac[0],
        src_mac[1],
        src_mac[2],
        src_mac[3],
        src_mac[4],
        src_mac[5],
        NH_ICMPV6,
        ICMPV6_NEIGHBOR_ADVERTISEMENT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC_MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c];
    const SRC_IP: [u8; 16] = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x0c, 0x29, 0xff, 0xfe, 0x1a, 0x2b, 0x3c,
    ];
    const TARGET: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef,
    ];

    #[test]
    fn solicited_node_address_and_mac() {
        // ff02::1:ff<low 3 bytes>.
        let m = solicited_node_multicast(TARGET);
        assert_eq!(
            m,
            [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, 0xad, 0xbe, 0xef]
        );
        // 33:33:ff:<low 3 bytes>.
        assert_eq!(
            solicited_node_mac(TARGET),
            [0x33, 0x33, 0xff, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn solicitation_frame_layout() {
        let f = build_neighbor_solicitation(SRC_MAC, SRC_IP, TARGET);
        assert_eq!(f.len(), 86);
        // Ethernet.
        assert_eq!(&f[0..6], &[0x33, 0x33, 0xff, 0xad, 0xbe, 0xef]);
        assert_eq!(&f[6..12], &SRC_MAC);
        assert_eq!(&f[12..14], &[0x86, 0xdd]);
        // IPv6: version 6, no traffic class, no flow label.
        assert_eq!(&f[14..18], &[0x60, 0x00, 0x00, 0x00]);
        assert_eq!(&f[18..20], &32u16.to_be_bytes());
        assert_eq!(f[20], NH_ICMPV6);
        // RFC 4861 requires 255 so the receiver can prove the packet was not routed.
        assert_eq!(f[21], 255);
        assert_eq!(&f[22..38], &SRC_IP);
        assert_eq!(&f[38..54], &solicited_node_multicast(TARGET));
        // ICMPv6.
        assert_eq!(f[54], ICMPV6_NEIGHBOR_SOLICITATION);
        assert_eq!(f[55], 0);
        assert_eq!(&f[58..62], &[0, 0, 0, 0], "reserved must be zero");
        assert_eq!(&f[62..78], &TARGET);
        // Source link-layer address option.
        assert_eq!(f[78], OPT_SOURCE_LINK_ADDR);
        assert_eq!(f[79], OPT_LEN_ETHER);
        assert_eq!(&f[80..86], &SRC_MAC);
    }

    #[test]
    fn solicitation_checksum_verifies() {
        let f = build_neighbor_solicitation(SRC_MAC, SRC_IP, TARGET);
        // Summing a segment that already carries its checksum yields zero.
        let dst = solicited_node_multicast(TARGET);
        assert_eq!(
            ipv6_pseudoheader_cksum(SRC_IP, dst, NH_ICMPV6, &f[54..]),
            0,
            "checksum should verify over the ICMPv6 segment"
        );
    }

    /// A well-formed advertisement, as an Ethernet frame.
    fn advert(target: [u8; 16], mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR_LEN + IP6_HDR_LEN];
        f[12] = 0x86;
        f[13] = 0xdd;
        f[ETH_HDR_LEN + 6] = NH_ICMPV6;
        f.push(ICMPV6_NEIGHBOR_ADVERTISEMENT);
        f.push(0); // code
        f.extend_from_slice(&[0, 0]); // checksum
        f.extend_from_slice(&[0x60, 0, 0, 0]); // flags: solicited + override
        f.extend_from_slice(&target);
        if let Some(m) = mac {
            f.push(OPT_TARGET_LINK_ADDR);
            f.push(OPT_LEN_ETHER);
            f.extend_from_slice(&m);
        }
        f
    }

    #[test]
    fn parses_a_complete_advertisement() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let f = advert(TARGET, Some(mac));
        let na = parse_neighbor_advertisement(&f, ETH_HDR_LEN).expect("should parse");
        assert_eq!(na.target, TARGET);
        assert_eq!(na.mac, Some(mac));
        assert_eq!(resolve_from_frame(&f, ETH_HDR_LEN, TARGET), Some(mac));
    }

    #[test]
    fn rejects_wrong_type_and_code() {
        let mut f = advert(TARGET, Some([1; 6]));
        f[ETH_HDR_LEN + IP6_HDR_LEN] = ICMPV6_NEIGHBOR_SOLICITATION;
        assert_eq!(parse_neighbor_advertisement(&f, ETH_HDR_LEN), None);

        let mut f = advert(TARGET, Some([1; 6]));
        f[ETH_HDR_LEN + IP6_HDR_LEN + 1] = 3; // non-zero code
        assert_eq!(parse_neighbor_advertisement(&f, ETH_HDR_LEN), None);
    }

    #[test]
    fn an_advertisement_about_another_address_resolves_nothing() {
        let f = advert(TARGET, Some([1; 6]));
        let mut other = TARGET;
        other[15] ^= 0xff;
        assert_eq!(resolve_from_frame(&f, ETH_HDR_LEN, other), None);
    }

    // DIVERGENCE 1. The C's `accept_ns` admits any frame holding the IPv6 + ICMPv6
    // headers, then reads 16 target bytes from offset+48 unconditionally. Every
    // truncation between those two points is an out-of-bounds read there; here each
    // one is simply not a match.
    #[test]
    fn truncated_advertisement_is_never_read_past_the_end() {
        let full = advert(TARGET, Some([0xab; 6]));
        // The C's own admission threshold: 14 + 40 + 4.
        let c_accepts_from = ETH_HDR_LEN + IP6_HDR_LEN + ICMPV6_HDR_LEN;
        // The last length at which the C would read past the captured bytes.
        let c_reads_past_until = c_accepts_from + 4 + 16;
        for len in c_accepts_from..c_reads_past_until {
            let short = &full[..len];
            assert_eq!(
                parse_neighbor_advertisement(short, ETH_HDR_LEN),
                None,
                "a {len}-byte capture must not parse"
            );
            assert_eq!(resolve_from_frame(short, ETH_HDR_LEN, TARGET), None);
        }
        // At exactly the target's end it parses, with no MAC — the option is absent.
        let exact = &full[..c_reads_past_until];
        let na = parse_neighbor_advertisement(exact, ETH_HDR_LEN).expect("target complete");
        assert_eq!(na.target, TARGET);
        assert_eq!(na.mac, None);
    }

    // DIVERGENCE 2. An advertisement with no target link-layer address option is legal
    // (RFC 4861 §4.4) and resolves nothing. `doND` ignores `has_mac` and reports
    // success anyway, leaving the caller's MAC buffer uninitialised; here the absence
    // is carried in the type and cannot be mistaken for a resolved address.
    #[test]
    fn advertisement_without_a_link_layer_address_resolves_nothing() {
        let f = advert(TARGET, None);
        let na = parse_neighbor_advertisement(&f, ETH_HDR_LEN).expect("still an advertisement");
        assert_eq!(na.target, TARGET, "it is about the right address");
        assert_eq!(na.mac, None, "but carries no link-layer address");
        assert_eq!(
            resolve_from_frame(&f, ETH_HDR_LEN, TARGET),
            None,
            "so it must not resolve the next hop"
        );
    }

    #[test]
    fn a_wrong_option_carries_no_address() {
        let mut f = advert(TARGET, Some([0x11; 6]));
        // Source link-layer address (1) where a target link-layer address (2) belongs.
        let opt = ETH_HDR_LEN + IP6_HDR_LEN + ICMPV6_HDR_LEN + 4 + 16;
        f[opt] = OPT_SOURCE_LINK_ADDR;
        assert_eq!(resolve_from_frame(&f, ETH_HDR_LEN, TARGET), None);
        // A length other than 1 (8 octets) is likewise not an Ethernet address.
        let mut f = advert(TARGET, Some([0x11; 6]));
        f[opt + 1] = 2;
        assert_eq!(resolve_from_frame(&f, ETH_HDR_LEN, TARGET), None);
    }

    #[test]
    fn offsets_past_the_frame_do_not_panic() {
        let f = advert(TARGET, Some([1; 6]));
        assert_eq!(parse_neighbor_advertisement(&f, usize::MAX), None);
        assert_eq!(parse_neighbor_advertisement(&f, f.len()), None);
        assert_eq!(parse_neighbor_advertisement(&[], 0), None);
    }

    #[test]
    fn filter_matches_the_c_format() {
        assert_eq!(
            na_bpf_filter([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            "ether dst 001122334455 and icmp6 and ip6[6:1] = 58 and ip6[40:1] = 136"
        );
    }
}
