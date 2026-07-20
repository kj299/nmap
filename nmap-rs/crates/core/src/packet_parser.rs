//! Multi-header packet parser. Ports nmap's `PacketParser::parse_packet`
//! (`PacketParser.cc`) — the state machine that walks a raw frame layer by layer,
//! chaining the single-header parsers in [`crate::headers`] (ethernet → L3 → L4)
//! by following each header's `ethertype` / IP protocol / `next_header`.
//!
//! ## What this fixes about the C
//!
//! The C returns a pointer into a function-local `static pkt_type_t
//! this_packet[MAX_HEADERS_IN_PACKET+1]` array — a non-reentrant, non-thread-safe
//! design where a second call clobbers the first call's result while a caller still
//! holds it (the `parser-owned-return` divergence, see `DIVERGENCES.md`). This port
//! returns an **owned [`Vec<Header>`]**: reentrant, `Send`, and each layer carries
//! its fully-parsed typed header rather than a bare `(type, length)` pair, so callers
//! get the TCP flags / ICMP type / addresses directly without re-parsing.
//!
//! ## Scope (the ported-header subset)
//!
//! This walks only the headers M4 has ported: Ethernet, ARP, IPv4, IPv6, TCP, UDP,
//! ICMPv4. Where the C would descend into a header this port does not yet have
//! (ICMPv6, the IPv6 extension-header chain, SCTP, …), the remainder degrades to a
//! single [`Header::Raw`] rather than being sub-parsed. That is a conservative,
//! *safer* divergence — never a parse of un-audited bytes — logged in
//! `DIVERGENCES.md` and to be tightened as those modules land (M5+).
//!
//! Like the C, the walk is bounded at [`MAX_HEADERS_IN_PACKET`] headers (a hostile
//! IP-in-IP-in-IP… nest cannot spin the loop) and is TOTAL on any input: a truncated
//! or malformed header ends the walk with the unparsed tail recorded as `Raw`, never
//! a panic.

use crate::headers::{arp, ethernet, icmpv4, ipv4, ipv6, tcp, udp};

/// Maximum number of headers the walk will record before stopping, matching the C
/// `#define MAX_HEADERS_IN_PACKET 32`. Bounds a maliciously deep encapsulation nest.
pub const MAX_HEADERS_IN_PACKET: usize = 32;

// ---- Dispatch constants (mirrored from libnetutil) ------------------------------
// Ethertypes (EthernetHeader.h).
const ETHTYPE_IPV4: u16 = 0x0800;
const ETHTYPE_ARP: u16 = 0x0806;
const ETHTYPE_IPV6: u16 = 0x86DD;
// IP next-protocol numbers (PacketElement.h HEADER_TYPE_*).
const PROTO_ICMPV4: u8 = 1;
const PROTO_IPV4: u8 = 4;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_IPV6: u8 = 41;
// ARP heuristic constants (used when no Ethernet header framed the packet).
const HDR_ETH10MB: u16 = 1;
const ARP_PROTO_IPV4: u16 = 0x0800;
const ETH_ADDR_LEN: u8 = 6;
const IPV4_ADDR_LEN: u8 = 4;

/// One parsed protocol header in a packet's layer stack. `Raw` captures trailing
/// application data or the unparsed tail left by a truncated/unknown header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    /// Link-layer Ethernet II frame header (14 bytes).
    Ethernet(ethernet::EthernetHeader),
    /// ARP header (28 bytes).
    Arp(arp::ArpHeader),
    /// IPv4 header (20–60 bytes).
    Ipv4(ipv4::Ipv4Header),
    /// IPv6 base header (40 bytes).
    Ipv6(ipv6::Ipv6Header),
    /// TCP header (20–60 bytes).
    Tcp(tcp::TcpHeader),
    /// UDP header (8 bytes).
    Udp(udp::UdpHeader),
    /// ICMPv4 header (8/12/20 bytes, type-dependent).
    Icmpv4(icmpv4::Icmpv4Header),
    /// Application payload or an unparsed/unknown tail, of the given byte length.
    Raw {
        /// Number of trailing bytes this record covers.
        len: usize,
    },
}

impl Header {
    /// Bytes this header occupies on the wire — the amount the walk advanced by.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Header::Ethernet(h) => h.header_len(),
            Header::Arp(h) => h.header_len(),
            Header::Ipv4(h) => h.header_len(),
            Header::Ipv6(h) => h.header_len(),
            Header::Tcp(h) => h.header_len(),
            Header::Udp(h) => h.header_len(),
            Header::Icmpv4(h) => h.header_len(),
            Header::Raw { len } => *len,
        }
    }

    /// A zero-length header. (Present so `len()` doesn't trip clippy's `len_without_is_empty`;
    /// a real parsed header is never empty, but a `Raw { len: 0 }` conceptually could be.)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Canonical short token for this layer (`eth`/`arp`/`ip4`/`ip6`/`tcp`/`udp`/
    /// `icmp`/`raw`) — the projection alphabet shared with the C differential oracle.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            Header::Ethernet(_) => "eth",
            Header::Arp(_) => "arp",
            Header::Ipv4(_) => "ip4",
            Header::Ipv6(_) => "ip6",
            Header::Tcp(_) => "tcp",
            Header::Udp(_) => "udp",
            Header::Icmpv4(_) => "icmp",
            Header::Raw { .. } => "raw",
        }
    }
}

/// What the walk expects to parse next. Mirrors the C `(next_layer, expected)` pair;
/// `Network` re-derives IPv4-vs-IPv6 from the version nibble exactly as the C does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    Ethernet,
    Arp,
    Network,
    Tcp,
    Udp,
    Icmpv4,
    Application,
}

/// Parse a raw packet into its owned layer stack.
///
/// `eth_included` selects the starting layer: `true` for a frame captured with its
/// Ethernet header (start at the link layer), `false` for a packet captured at the
/// network layer (e.g. a raw IP socket), matching the C `eth_included` argument.
///
/// Total on all input: never panics, always returns (possibly a single `Raw`).
#[must_use]
pub fn parse_packet(buf: &[u8], eth_included: bool) -> Vec<Header> {
    let mut headers: Vec<Header> = Vec::new();
    let mut pos: usize = 0;
    let mut finished = false;
    let mut unknown = false;

    let mut next = if eth_included {
        Next::Ethernet
    } else {
        Next::Network
    };

    while headers.len() < MAX_HEADERS_IN_PACKET && pos < buf.len() && !finished {
        let rest = &buf[pos..];
        match next {
            // --- Link layer: Ethernet ------------------------------------------
            Next::Ethernet => {
                let Ok(h) = ethernet::EthernetHeader::parse(rest) else {
                    unknown = true;
                    break;
                };
                next = match h.ethertype {
                    ETHTYPE_IPV4 | ETHTYPE_IPV6 => Next::Network,
                    ETHTYPE_ARP => Next::Arp,
                    _ => Next::Application,
                };
                pos = pos.saturating_add(h.header_len());
                headers.push(Header::Ethernet(h));
            }
            // --- Link layer: ARP -----------------------------------------------
            Next::Arp => {
                let Ok(h) = arp::ArpHeader::parse(rest) else {
                    unknown = true;
                    break;
                };
                let consumed = h.header_len();
                pos = pos.saturating_add(consumed);
                headers.push(Header::Arp(h));
                if pos < buf.len() {
                    next = Next::Application;
                } else {
                    finished = true;
                }
            }
            // --- Network layer: IPv4 / IPv6 (version-dispatched) ---------------
            Next::Network => {
                // The C requires >= IP_HEADER_LEN (20) just to read the version
                // byte; a shorter remainder is an unknown header.
                if rest.len() < ipv4::IP_HEADER_LEN {
                    unknown = true;
                    break;
                }
                let version = rest[0] >> 4;
                if version == 4 {
                    let Ok(h) = ipv4::Ipv4Header::parse(rest) else {
                        unknown = true;
                        break;
                    };
                    next = match h.protocol {
                        PROTO_ICMPV4 => Next::Icmpv4,
                        PROTO_TCP => Next::Tcp,
                        PROTO_UDP => Next::Udp,
                        PROTO_IPV4 | PROTO_IPV6 => Next::Network,
                        _ => Next::Application,
                    };
                    pos = pos.saturating_add(h.header_len());
                    headers.push(Header::Ipv4(h));
                } else if version == 6 {
                    let Ok(h) = ipv6::Ipv6Header::parse(rest) else {
                        unknown = true;
                        break;
                    };
                    next = match h.next_header {
                        PROTO_TCP => Next::Tcp,
                        PROTO_UDP => Next::Udp,
                        PROTO_IPV4 | PROTO_IPV6 => Next::Network,
                        // ICMPv6, IPv6 extension headers, SCTP, … have no ported
                        // parser yet — degrade the remainder to Raw (DIVERGENCES.md).
                        _ => Next::Application,
                    };
                    pos = pos.saturating_add(h.header_len());
                    headers.push(Header::Ipv6(h));
                } else {
                    // Bogus IP version: fall through to the application layer, which
                    // records the remainder as raw (matching the C, no `unknown`).
                    next = Next::Application;
                }
            }
            // --- Transport layer: TCP ------------------------------------------
            Next::Tcp => {
                let Ok(h) = tcp::TcpHeader::parse(rest) else {
                    unknown = true;
                    break;
                };
                pos = pos.saturating_add(h.header_len());
                headers.push(Header::Tcp(h));
                next = Next::Application;
            }
            // --- Transport layer: UDP ------------------------------------------
            Next::Udp => {
                let Ok(h) = udp::UdpHeader::parse(rest) else {
                    unknown = true;
                    break;
                };
                pos = pos.saturating_add(h.header_len());
                headers.push(Header::Udp(h));
                next = Next::Application;
            }
            // --- Transport layer: ICMPv4 ---------------------------------------
            Next::Icmpv4 => {
                let Ok(h) = icmpv4::Icmpv4Header::parse(rest) else {
                    unknown = true;
                    break;
                };
                // Error-report ICMP types embed the offending IPv4 packet; the walk
                // continues into it. Everything else is misc payload → raw.
                next = match h.icmp_type {
                    // UNREACH, SOURCEQUENCH, REDIRECT, TIMXCEED, PARAMPROB
                    3 | 4 | 5 | 11 | 12 => Next::Network,
                    _ => Next::Application,
                };
                pos = pos.saturating_add(h.header_len());
                headers.push(Header::Icmpv4(h));
            }
            // --- Application layer: raw, with the headerless-ARP heuristic ------
            Next::Application => {
                // The C sniffs for an ARP packet that arrived without an Ethernet
                // frame by shape (Ethernet/IPv4/6/4 address widths).
                if let Ok(h) = arp::ArpHeader::parse(rest) {
                    if h.hardware_type == HDR_ETH10MB
                        && h.protocol_type == ARP_PROTO_IPV4
                        && h.hw_addr_len == ETH_ADDR_LEN
                        && h.proto_addr_len == IPV4_ADDR_LEN
                    {
                        let consumed = h.header_len();
                        pos = pos.saturating_add(consumed);
                        headers.push(Header::Arp(h));
                        if pos < buf.len() {
                            next = Next::Application;
                        } else {
                            finished = true;
                        }
                        continue;
                    }
                }
                let remaining = buf.len().saturating_sub(pos);
                headers.push(Header::Raw { len: remaining });
                pos = buf.len();
                finished = true;
            }
        }
    }

    // A header that failed to validate leaves its bytes (and the rest of the packet)
    // as raw application data — but only if we still have room in the stack.
    if unknown && headers.len() < MAX_HEADERS_IN_PACKET {
        let remaining = buf.len().saturating_sub(pos);
        if remaining > 0 {
            headers.push(Header::Raw { len: remaining });
        }
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(hs: &[Header]) -> Vec<&'static str> {
        hs.iter().map(Header::kind_str).collect()
    }

    /// Build eth(IPv4) + IPv4(TCP) + TCP + 4-byte payload.
    fn eth_ip_tcp() -> Vec<u8> {
        let mut p = Vec::new();
        // Ethernet: dst, src, ethertype=IPv4.
        p.extend_from_slice(&[0x11; 6]);
        p.extend_from_slice(&[0x22; 6]);
        p.extend_from_slice(&ETHTYPE_IPV4.to_be_bytes());
        // IPv4: v4/ihl5, tos0, totlen(don't-care), id, flags, ttl, proto=TCP, ck, src, dst.
        let ip_start = p.len();
        p.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, PROTO_TCP, 0x00, 0x00,
        ]);
        p.extend_from_slice(&[10, 0, 0, 1]);
        p.extend_from_slice(&[10, 0, 0, 2]);
        debug_assert_eq!(p.len().saturating_sub(ip_start), 20);
        // TCP: sport, dport, seq(4), ack(4), offset=5<<4, flags, win, ck, urg.
        p.extend_from_slice(&[0x00, 0x50, 0x01, 0xbb]);
        p.extend_from_slice(&[0, 0, 0, 1]);
        p.extend_from_slice(&[0, 0, 0, 0]);
        p.extend_from_slice(&[0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Payload.
        p.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        p
    }

    #[test]
    fn walks_eth_ipv4_tcp_payload() {
        let p = eth_ip_tcp();
        let hs = parse_packet(&p, true);
        assert_eq!(kinds(&hs), ["eth", "ip4", "tcp", "raw"]);
        assert_eq!(hs[0].len(), 14);
        assert_eq!(hs[1].len(), 20);
        assert_eq!(hs[2].len(), 20);
        assert_eq!(hs[3], Header::Raw { len: 4 });
        // Total consumed == packet length.
        assert_eq!(hs.iter().map(Header::len).sum::<usize>(), p.len());
    }

    #[test]
    fn network_start_skips_ethernet() {
        let p = eth_ip_tcp();
        let ip_only = &p[14..];
        let hs = parse_packet(ip_only, false);
        assert_eq!(kinds(&hs), ["ip4", "tcp", "raw"]);
    }

    #[test]
    fn ipv6_udp_chain() {
        let mut p = Vec::new();
        p.push(0x60); // version 6
        p.extend_from_slice(&[0x00, 0x00, 0x00]); // tc/flow
        p.extend_from_slice(&[0x00, 0x08]); // payload len
        p.push(PROTO_UDP); // next header = UDP
        p.push(0x40); // hop limit
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // UDP: sport, dport, ulen=8, checksum.
        p.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);
        let hs = parse_packet(&p, false);
        assert_eq!(kinds(&hs), ["ip6", "udp"]);
        assert_eq!(hs[0].len(), 40);
        assert_eq!(hs[1].len(), 8);
    }

    #[test]
    fn ipv6_icmpv6_degrades_to_raw_not_subparsed() {
        // next_header = 58 (ICMPv6): C would parse it; we have no ICMPv6 parser, so
        // the remainder is Raw. Documented divergence — verify it holds.
        let mut p = vec![0x60, 0, 0, 0, 0x00, 0x04, 58, 0x40];
        p.extend_from_slice(&[0u8; 16]);
        p.extend_from_slice(&[0u8; 16]);
        p.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // would-be ICMPv6
        let hs = parse_packet(&p, false);
        assert_eq!(kinds(&hs), ["ip6", "raw"]);
        assert_eq!(hs[1], Header::Raw { len: 4 });
    }

    #[test]
    fn icmp_unreachable_embeds_ipv4() {
        // IPv4(proto=ICMP) + ICMP type=3 (unreach, 8-byte header) + embedded IPv4.
        let mut p = Vec::new();
        p.extend_from_slice(&[
            0x45,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            PROTO_ICMPV4,
            0x00,
            0x00,
        ]);
        p.extend_from_slice(&[10, 0, 0, 1]);
        p.extend_from_slice(&[10, 0, 0, 2]);
        // ICMP: type=3, code=1, checksum, unused(4).
        p.extend_from_slice(&[3, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Embedded original IPv4 header (proto=UDP), 20 bytes.
        p.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, PROTO_UDP, 0x00, 0x00,
        ]);
        p.extend_from_slice(&[10, 0, 0, 2]);
        p.extend_from_slice(&[10, 0, 0, 1]);
        // The embedded IPv4 header consumes the final 20 bytes exactly, so there is
        // no trailing payload after it.
        let hs = parse_packet(&p, false);
        assert_eq!(kinds(&hs), ["ip4", "icmp", "ip4"]);
    }

    #[test]
    fn headerless_arp_detected_at_application_layer() {
        // A bare ARP packet (no Ethernet), started at the network layer: version
        // nibble is 0 → bogus → application layer → ARP heuristic catches it.
        let mut p = Vec::new();
        p.extend_from_slice(&HDR_ETH10MB.to_be_bytes()); // hrd = 1
        p.extend_from_slice(&ARP_PROTO_IPV4.to_be_bytes()); // pro = 0x0800
        p.push(ETH_ADDR_LEN); // hln = 6
        p.push(IPV4_ADDR_LEN); // pln = 4
        p.extend_from_slice(&[0x00, 0x01]); // opcode = request
        p.extend_from_slice(&[0u8; 20]); // sha/sip/tha/tip
        assert_eq!(p.len(), 28);
        let hs = parse_packet(&p, false);
        assert_eq!(kinds(&hs), ["arp"]);
    }

    #[test]
    fn truncated_transport_becomes_raw_tail() {
        // eth + IPv4(TCP) but only 10 bytes of TCP (needs 20) → IPv4 then raw.
        let mut p = eth_ip_tcp();
        p.truncate(14 + 20 + 10);
        let hs = parse_packet(&p, true);
        assert_eq!(kinds(&hs), ["eth", "ip4", "raw"]);
        assert_eq!(hs[2], Header::Raw { len: 10 });
    }

    #[test]
    fn empty_input_yields_no_headers() {
        assert!(parse_packet(&[], true).is_empty());
        assert!(parse_packet(&[], false).is_empty());
    }

    #[test]
    fn deep_ip_in_ip_nest_is_bounded() {
        // A stack of IPv4(proto=IPv4) headers deeper than MAX_HEADERS_IN_PACKET must
        // stop at the bound, never loop unboundedly.
        let mut p = Vec::new();
        for _ in 0..64 {
            p.extend_from_slice(&[
                0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, PROTO_IPV4, 0x00, 0x00,
            ]);
            p.extend_from_slice(&[10, 0, 0, 1]);
            p.extend_from_slice(&[10, 0, 0, 2]);
        }
        let hs = parse_packet(&p, false);
        assert_eq!(hs.len(), MAX_HEADERS_IN_PACKET);
    }

    #[test]
    fn truncation_sweep_never_panics() {
        let p = eth_ip_tcp();
        for n in 0..=p.len() {
            let _ = parse_packet(&p[..n], true);
            let _ = parse_packet(&p[..n], false);
        }
    }
}
