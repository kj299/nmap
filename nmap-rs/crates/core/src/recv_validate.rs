//! Receive-side packet validation. Ports nmap's `validatepkt()` + `validateTCPhdr()`
//! (`tcpip.cc`), the gate `readip_pcap()` runs on every captured frame before it is
//! handed to the scan engine.
//!
//! This is a pure predicate over **untrusted network input** (a captured packet an
//! attacker fully controls), so it is the highest-value fuzz/differential target of
//! the receive path. It answers: is this a well-formed, non-fragmented IPv4 or IPv6
//! packet whose L4 header (and, for TCP, its option list) is structurally sound —
//! and if so, where the L4 header starts and how many bytes are really packet
//! (capping the link-layer CRC trailer that pcap also captures)?
//!
//! ## IPv6
//!
//! The IPv6 path walks the extension headers as `ipv6_get_data` does
//! (`netutil.cc:689`, [`ipv6_payload`]): hop-by-hop, destination options and
//! routing headers are skipped by their `(Hdr Ext Len + 1) * 8` bytes, and the
//! chain must end in a protocol the C knows as upper-layer (TCP, UDP, ICMP,
//! ICMPv6, SCTP, no-next-header). Two things are fixed rather than reproduced,
//! as decided for the IPv6 scan milestone (`docs/IPV6-SCAN-ANALYSIS.md` D3, Q4):
//!
//! - **Fragments.** The C walks a fragment header like any other extension, by
//!   the `(reserved + 1) * 8` its length rule reads from the reserved byte, and
//!   never rejects a fragment, so a later fragment's payload, mid-segment bytes,
//!   is read as a transport header. Here a fragment header is its fixed 8 bytes,
//!   and one with a nonzero offset is rejected, as the IPv4 path rejects it
//!   (`recv-validate6-non-initial-fragment`).
//! - **The trailer.** The C trims the length by comparing the upper-layer bytes
//!   with `ip6_plen`, which also counts the extension headers, so with extension
//!   headers present a link-layer trailer is trimmed short or not at all. Here
//!   the packet ends at 40 + `ip6_plen` (`recv-validate6-trailer-trim`).
//!
//! Total on all input: every path returns; no panic, no unchecked index, no unsigned
//! underflow (the exact class the C `OPTLEN_IS` macro guards against by hand).

/// IPv4 fixed header length.
const IP_HEADER_LEN: usize = 20;
/// TCP fixed header length.
const TCP_HEADER_LEN: usize = 20;
/// UDP fixed header length.
const UDP_HEADER_LEN: usize = 8;
/// IPv4 fragment-offset mask (low 13 bits of the flags/frag word).
const IP_OFFMASK: u16 = 0x1FFF;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
/// IPv6 fixed header length (`sizeof(struct ip6_hdr)`).
const IPV6_HEADER_LEN: usize = 40;
/// An extension header's smallest size, and the unit of its length field.
const IPV6_EXT_UNIT: usize = 8;
// The extension headers `ipv6_is_extension_header` walks (`netutil.cc:650`).
const IP_PROTO_HOPOPTS: u8 = 0;
const IP_PROTO_ROUTING: u8 = 43;
const IP_PROTO_FRAGMENT: u8 = 44;
const IP_PROTO_DSTOPTS: u8 = 60;
// The rest of `ipv6_is_upperlayer`'s set (`netutil.cc:671`), with TCP and UDP.
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_ICMPV6: u8 = 58;
const IP_PROTO_NONE: u8 = 59;
const IP_PROTO_SCTP: u8 = 132;

/// Why a captured packet was rejected. Mirrors the `validatepkt`/`validateTCPhdr`
/// rejection points (the C only distinguishes them in `--debug` logging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Fewer than 20 bytes — not even a full IPv4 header.
    TooShort,
    /// IP version was neither 4 nor 6.
    BadVersion(u8),
    /// The IHL field is < 5 words or runs past the captured bytes.
    BadIpHeaderLen,
    /// A non-initial fragment (fragment offset != 0). The C drops these for IPv4;
    /// for IPv6 it does not, and the port does (module docs).
    Fragment,
    /// An IPv6 extension header runs past the captured bytes, or nothing follows
    /// the chain (`ipv6_get_data` returns NULL).
    Ipv6ChainTruncated,
    /// The IPv6 chain ends in a protocol `ipv6_is_upperlayer` does not know.
    Ipv6UnknownPayload(u8),
    /// A TCP packet whose payload is shorter than the fixed TCP header.
    IncompleteTcpHeader,
    /// A TCP option list that is malformed (bad length, overrun, wrong fixed size).
    BadTcpOptions,
    /// A UDP packet whose payload is shorter than the fixed UDP header.
    IncompleteUdpHeader,
}

/// A captured packet that passed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validated {
    /// IP version: 4 or 6.
    pub version: u8,
    /// Upper-layer protocol number (`ip_p`; for IPv6, the last next-header).
    pub proto: u8,
    /// Where the L4 header begins: the IPv4 header length (`ihl * 4`), or the
    /// IPv6 header plus its extension headers.
    pub data_offset: usize,
    /// The real packet length: `min(captured, ip_total_length)` for IPv4,
    /// `min(captured, 40 + ip6_plen)` for IPv6. The C caps the caller's length
    /// here so a link-layer CRC trailer counted by pcap is not mistaken for
    /// packet data. A length field that ends the packet inside its own headers
    /// can put this below `data_offset`; the transport checks above ran on the
    /// captured bytes, as the C's do.
    pub captured_len: usize,
}

/// Validate a captured IPv4 or IPv6 packet. Ports `validatepkt()`
/// (`tcpip.cc:1274`), with the IPv6 fixes the module docs describe.
///
/// # Errors
/// The [`Reject`] naming why the packet is refused.
pub fn validate_packet(buf: &[u8]) -> Result<Validated, Reject> {
    if buf.len() < IP_HEADER_LEN {
        return Err(Reject::TooShort);
    }
    let version = buf[0] >> 4;
    if version == 6 {
        return validate_ipv6(buf);
    }
    if version != 4 {
        return Err(Reject::BadVersion(version));
    }

    // ipv4_get_data: IHL bounds, then the L4 data length.
    let ihl = buf[0] & 0x0F;
    let header_len = usize::from(ihl).saturating_mul(4);
    if header_len < IP_HEADER_LEN || header_len > buf.len() {
        return Err(Reject::BadIpHeaderLen);
    }
    let datalen = buf.len().saturating_sub(header_len);

    // Reject non-initial fragments.
    let ip_off = u16::from_be_bytes([buf[6], buf[7]]);
    if (ip_off & IP_OFFMASK) != 0 {
        return Err(Reject::Fragment);
    }

    // Cap the reported length to the IP total-length field (drop CRC trailers).
    let iplen = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    let captured_len = buf.len().min(iplen);

    let proto = buf[9];
    validate_l4(proto, &buf[header_len..], datalen)?;

    Ok(Validated {
        version: 4,
        proto,
        data_offset: header_len,
        captured_len,
    })
}

/// `validatepkt`'s IPv6 path (`tcpip.cc:1310`).
fn validate_ipv6(buf: &[u8]) -> Result<Validated, Reject> {
    if buf.len() < IPV6_HEADER_LEN {
        return Err(Reject::TooShort);
    }
    let (proto, data_offset) = ipv6_payload(buf)?;
    let data = buf.get(data_offset..).ok_or(Reject::Ipv6ChainTruncated)?;
    // The packet ends at its header plus the payload length; anything captured
    // past that is a link-layer trailer (`recv-validate6-trailer-trim`).
    let plen = usize::from(u16::from_be_bytes([buf[4], buf[5]]));
    let captured_len = buf.len().min(IPV6_HEADER_LEN.saturating_add(plen));
    validate_l4(proto, data, data.len())?;
    Ok(Validated {
        version: 6,
        proto,
        data_offset,
        captured_len,
    })
}

/// The transport checks `validatepkt` makes after either IP version
/// (`tcpip.cc:1333`): a TCP header and a sound option list, or a UDP header.
/// `datalen` is the captured length after the IP header(s), as the C measures it.
fn validate_l4(proto: u8, data: &[u8], datalen: usize) -> Result<(), Reject> {
    match proto {
        IPPROTO_TCP => {
            if datalen < TCP_HEADER_LEN {
                return Err(Reject::IncompleteTcpHeader);
            }
            if !validate_tcp_header(data) {
                return Err(Reject::BadTcpOptions);
            }
        }
        IPPROTO_UDP if datalen < UDP_HEADER_LEN => {
            return Err(Reject::IncompleteUdpHeader);
        }
        _ => {}
    }
    Ok(())
}

/// Walk an IPv6 packet's extension headers to its upper-layer payload: the
/// payload's protocol and where it starts. Ports `ipv6_get_data`
/// (`netutil.cc:689`, `ipv6_get_data_primitive` with `upperlayer_only`), with
/// the fragment rule fixed (module docs).
///
/// The walk is bounded by the buffer: each step moves at least 8 bytes, and a
/// header that claims more than is left ends it.
///
/// # Errors
/// [`Reject::TooShort`] under 40 bytes; [`Reject::Fragment`] for a non-initial
/// fragment; [`Reject::Ipv6ChainTruncated`] when a header runs past the buffer or
/// nothing follows the chain; [`Reject::Ipv6UnknownPayload`] when the chain ends
/// in a protocol the C does not take as upper-layer.
pub fn ipv6_payload(buf: &[u8]) -> Result<(u8, usize), Reject> {
    if buf.len() < IPV6_HEADER_LEN {
        return Err(Reject::TooShort);
    }
    let end = buf.len();
    let mut nxt = buf[6];
    let mut p = IPV6_HEADER_LEN;
    while p < end && is_extension_header(nxt) {
        // Every extension header carries at least its next-header and length
        // bytes in its first 8 (`if (p + 8 > end) return NULL`).
        let ext = buf
            .get(p..p.saturating_add(IPV6_EXT_UNIT))
            .ok_or(Reject::Ipv6ChainTruncated)?;
        let len = if nxt == IP_PROTO_FRAGMENT {
            // Offset in 8-byte units: the top 13 bits of bytes 2..4.
            if u16::from_be_bytes([ext[2], ext[3]]) >> 3 != 0 {
                return Err(Reject::Fragment);
            }
            IPV6_EXT_UNIT
        } else {
            usize::from(ext[1])
                .saturating_add(1)
                .saturating_mul(IPV6_EXT_UNIT)
        };
        nxt = ext[0];
        p = p.saturating_add(len);
    }
    if p >= end {
        return Err(Reject::Ipv6ChainTruncated);
    }
    if !is_upper_layer(nxt) {
        return Err(Reject::Ipv6UnknownPayload(nxt));
    }
    Ok((nxt, p))
}

/// `ipv6_is_extension_header` (`netutil.cc:650`).
fn is_extension_header(nxt: u8) -> bool {
    matches!(
        nxt,
        IP_PROTO_HOPOPTS | IP_PROTO_DSTOPTS | IP_PROTO_ROUTING | IP_PROTO_FRAGMENT
    )
}

/// `ipv6_is_upperlayer` (`netutil.cc:671`).
fn is_upper_layer(nxt: u8) -> bool {
    matches!(
        nxt,
        IP_PROTO_NONE | IPPROTO_TCP | IPPROTO_UDP | IP_PROTO_ICMP | IP_PROTO_ICMPV6 | IP_PROTO_SCTP
    )
}

/// Validate a TCP header including its option list. Ports `validateTCPhdr()`.
///
/// `tcp` is the TCP header + options + payload (length already checked >= 20 by the
/// caller for the receive path, but this is total for any slice). Returns `true` iff
/// the data-offset and every option length are internally consistent — the safe
/// re-implementation of the C `OPTLEN_IS` underflow-guard dance.
#[must_use]
pub fn validate_tcp_header(tcp: &[u8]) -> bool {
    if tcp.len() < TCP_HEADER_LEN {
        return false;
    }
    // Data offset (high nibble of byte 12) in bytes.
    let hdrlen = usize::from(tcp[12] >> 4).saturating_mul(4);
    if hdrlen > tcp.len() || hdrlen < TCP_HEADER_LEN {
        return false;
    }
    // Walk the options region [20, hdrlen).
    let opts = &tcp[TCP_HEADER_LEN..hdrlen];
    let mut pos = 0usize;
    while opts.len().saturating_sub(pos) > 1 {
        let kind = opts[pos];
        // The declared length byte for this option (safe: pos+1 < len by the guard).
        let optlen_byte = usize::from(opts[pos.saturating_add(1)]);
        let remaining = opts.len().saturating_sub(pos);

        // Each arm computes the next position or rejects. `consume_fixed` requires the
        // declared length byte to equal `expected` (the C `OPTLEN_IS(expected)`).
        let next = match kind {
            0 => return true,                 // EOL: options end.
            1 => Some(pos.saturating_add(1)), // NOP: single byte.
            2 => consume_fixed(4, remaining, optlen_byte, pos),
            3 => consume_fixed(3, remaining, optlen_byte, pos),
            4 => consume_fixed(2, remaining, optlen_byte, pos),
            5 => {
                // SACK: length byte must be 2 + a positive multiple of 8.
                let blocks = optlen_byte.saturating_sub(2);
                if optlen_byte < 2 || blocks == 0 || blocks % 8 != 0 {
                    return false;
                }
                consume_variable(optlen_byte, remaining, pos)
            }
            8 => consume_fixed(10, remaining, optlen_byte, pos),
            14 => consume_fixed(3, remaining, optlen_byte, pos),
            _ => consume_variable(optlen_byte, remaining, pos),
        };
        match next {
            Some(p) => pos = p,
            None => return false,
        }
    }

    // One byte left: must be NOP or EOL. Zero bytes left: valid.
    if opts.len().saturating_sub(pos) == 1 {
        return opts[pos] == 0 || opts[pos] == 1;
    }
    true
}

/// The fixed-length `OPTLEN_IS(expected)` case: consume exactly `expected` bytes,
/// requiring the option's declared length byte to equal `expected`.
fn consume_fixed(
    expected: usize,
    remaining: usize,
    optlen_byte: usize,
    pos: usize,
) -> Option<usize> {
    if expected == 0 || remaining < expected || optlen_byte != expected {
        None
    } else {
        pos.checked_add(expected)
    }
}

/// The variable-length `OPTLEN_IS(optlen_byte)` case: consume the option's own
/// declared length, requiring it to be non-zero and to fit the remaining bytes.
fn consume_variable(optlen_byte: usize, remaining: usize, pos: usize) -> Option<usize> {
    if optlen_byte == 0 || remaining < optlen_byte {
        None
    } else {
        pos.checked_add(optlen_byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid IPv4+TCP packet (ihl 5, proto TCP, no options), total_length
    /// set to the full length.
    fn ipv4_tcp(total_len: u16, tcp: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x45,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            0x00,
            0x40,
            IPPROTO_TCP,
            0x00,
            0x00,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
        ];
        let [hi, lo] = total_len.to_be_bytes();
        p[2] = hi;
        p[3] = lo;
        p.extend_from_slice(tcp);
        p
    }

    fn tcp_hdr(data_offset_words: u8, options: &[u8]) -> Vec<u8> {
        let mut t = vec![
            0x00,
            0x50,
            0x01,
            0xbb,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            data_offset_words << 4,
            0x10,
            0x20,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        t.extend_from_slice(options);
        t
    }

    #[test]
    fn accepts_plain_tcp() {
        let tcp = tcp_hdr(5, &[]);
        let pkt = ipv4_tcp(40, &tcp);
        let v = validate_packet(&pkt).unwrap();
        assert_eq!(v.proto, IPPROTO_TCP);
        assert_eq!(v.data_offset, 20);
        assert_eq!(v.captured_len, 40);
    }

    #[test]
    fn caps_captured_len_to_total_length() {
        // total_length says 40 but we captured 44 (a 4-byte Ethernet CRC trailer).
        let tcp = tcp_hdr(5, &[]);
        let mut pkt = ipv4_tcp(40, &tcp);
        pkt.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let v = validate_packet(&pkt).unwrap();
        assert_eq!(v.captured_len, 40, "trailer must be trimmed");
    }

    #[test]
    fn rejects_fragment() {
        let tcp = tcp_hdr(5, &[]);
        let mut pkt = ipv4_tcp(40, &tcp);
        pkt[6] = 0x00;
        pkt[7] = 0x10; // fragment offset = 16 (nonzero)
        assert_eq!(validate_packet(&pkt), Err(Reject::Fragment));
    }

    #[test]
    fn rejects_short_and_bad_version() {
        assert_eq!(validate_packet(&[0u8; 10]), Err(Reject::TooShort));
        let mut pkt = ipv4_tcp(40, &tcp_hdr(5, &[]));
        pkt[0] = 0x75; // version 7
        assert_eq!(validate_packet(&pkt), Err(Reject::BadVersion(7)));
    }

    // ---- IPv6 ----

    /// An IPv6 packet: header (payload length from `plen`, or the payload's own),
    /// then `chain` (extension headers, already encoded), then `payload`.
    fn ipv6(first_nxt: u8, chain: &[u8], payload: &[u8], plen: Option<u16>) -> Vec<u8> {
        let body = chain.len().saturating_add(payload.len());
        let plen = plen.unwrap_or_else(|| u16::try_from(body).expect("short test packet"));
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&plen.to_be_bytes());
        p.push(first_nxt);
        p.push(64);
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        p.extend_from_slice(chain);
        p.extend_from_slice(payload);
        p
    }

    /// An options-style extension header (hop-by-hop, destination options,
    /// routing): `units` of 8 bytes, `Hdr Ext Len` = units - 1, padded with zeros.
    fn ext(next: u8, units: u8) -> Vec<u8> {
        let mut h = vec![0u8; usize::from(units) * 8];
        h[0] = next;
        h[1] = units.saturating_sub(1);
        h
    }

    /// A fragment header: `offset` in 8-byte units, `more` the M flag.
    fn frag(next: u8, reserved: u8, offset: u16, more: bool) -> Vec<u8> {
        let word = (offset << 3) | u16::from(more);
        let mut h = vec![next, reserved];
        h.extend_from_slice(&word.to_be_bytes());
        h.extend_from_slice(&[0, 0, 0x12, 0x34]);
        h
    }

    #[test]
    fn ipv6_tcp_udp_icmpv6_are_accepted_after_the_header() {
        let tcp = tcp_hdr(5, &[]);
        let v = validate_packet(&ipv6(IPPROTO_TCP, &[], &tcp, None)).unwrap();
        assert_eq!(
            (v.version, v.proto, v.data_offset, v.captured_len),
            (6, 6, 40, 60)
        );
        let v = validate_packet(&ipv6(IPPROTO_UDP, &[], &[0; 8], None)).unwrap();
        assert_eq!((v.proto, v.data_offset), (17, 40));
        let v = validate_packet(&ipv6(IP_PROTO_ICMPV6, &[], &[128, 0, 0, 0], None)).unwrap();
        assert_eq!((v.proto, v.data_offset), (58, 40));
    }

    #[test]
    fn ipv6_walks_hop_by_hop_destination_and_routing_headers() {
        let mut chain = ext(IP_PROTO_DSTOPTS, 1);
        chain.extend(ext(IP_PROTO_ROUTING, 2));
        chain.extend(ext(IPPROTO_TCP, 3));
        let v = validate_packet(&ipv6(IP_PROTO_HOPOPTS, &chain, &tcp_hdr(5, &[]), None)).unwrap();
        assert_eq!((v.proto, v.data_offset), (6, 40 + 8 + 16 + 24));
    }

    // D3: a first fragment (offset 0) carries the transport header and is
    // walked; any later one is refused, as the IPv4 path refuses it. The header
    // is 8 bytes whatever its reserved byte says.
    #[test]
    fn ipv6_first_fragments_pass_and_later_ones_are_refused() {
        let tcp = tcp_hdr(5, &[]);
        for more in [true, false] {
            let pkt = ipv6(
                IP_PROTO_FRAGMENT,
                &frag(IPPROTO_TCP, 0, 0, more),
                &tcp,
                None,
            );
            assert_eq!(
                validate_packet(&pkt).unwrap().data_offset,
                48,
                "more={more}"
            );
        }
        for offset in [1, 185, 0x1fff] {
            let pkt = ipv6(
                IP_PROTO_FRAGMENT,
                &frag(IPPROTO_TCP, 0, offset, false),
                &tcp,
                None,
            );
            assert_eq!(
                validate_packet(&pkt),
                Err(Reject::Fragment),
                "offset {offset}"
            );
        }
        // The C would skip (reserved + 1) * 8 = 24 bytes here, into the TCP header.
        let pkt = ipv6(
            IP_PROTO_FRAGMENT,
            &frag(IPPROTO_TCP, 2, 0, true),
            &tcp,
            None,
        );
        assert_eq!(validate_packet(&pkt).unwrap().data_offset, 48);
        // Behind another extension header too.
        let mut chain = ext(IP_PROTO_FRAGMENT, 1);
        chain.extend(frag(IPPROTO_UDP, 0, 3, false));
        let pkt = ipv6(IP_PROTO_HOPOPTS, &chain, &[0; 8], None);
        assert_eq!(validate_packet(&pkt), Err(Reject::Fragment));
    }

    #[test]
    fn ipv6_chains_that_run_out_are_refused() {
        // Under 40 bytes.
        assert_eq!(
            validate_packet(&ipv6(IPPROTO_TCP, &[], &[], None)[..39]),
            Err(Reject::TooShort)
        );
        // No payload at all, even with no-next-header.
        assert_eq!(
            validate_packet(&ipv6(IP_PROTO_NONE, &[], &[], None)),
            Err(Reject::Ipv6ChainTruncated)
        );
        // An extension header with fewer than 8 bytes left.
        let pkt = ipv6(IP_PROTO_HOPOPTS, &[IPPROTO_TCP, 0, 0, 0], &[], None);
        assert_eq!(validate_packet(&pkt), Err(Reject::Ipv6ChainTruncated));
        // One whose length runs past the end.
        let mut long = ext(IPPROTO_TCP, 1);
        long[1] = 9;
        let pkt = ipv6(IP_PROTO_DSTOPTS, &long, &tcp_hdr(5, &[]), None);
        assert_eq!(validate_packet(&pkt), Err(Reject::Ipv6ChainTruncated));
        // The chain ends exactly at the end of the packet.
        let pkt = ipv6(IP_PROTO_DSTOPTS, &ext(IPPROTO_TCP, 1), &[], None);
        assert_eq!(validate_packet(&pkt), Err(Reject::Ipv6ChainTruncated));
    }

    #[test]
    fn ipv6_chain_must_end_in_an_upper_layer_protocol() {
        for nxt in [
            IPPROTO_TCP,
            IPPROTO_UDP,
            IP_PROTO_ICMP,
            IP_PROTO_ICMPV6,
            IP_PROTO_SCTP,
            IP_PROTO_NONE,
        ] {
            let pkt = ipv6(nxt, &[], &tcp_hdr(5, &[]), None);
            assert!(validate_packet(&pkt).is_ok(), "{nxt}");
        }
        // ESP, AH, IPv6-in-IPv6, mobility: not upper-layer to the C.
        for nxt in [50, 51, 41, 135] {
            let pkt = ipv6(nxt, &[], &[0; 24], None);
            assert_eq!(
                validate_packet(&pkt),
                Err(Reject::Ipv6UnknownPayload(nxt)),
                "{nxt}"
            );
        }
    }

    #[test]
    fn ipv6_transport_checks_are_the_ipv4_ones() {
        let pkt = ipv6(IPPROTO_TCP, &[], &[0; 10], None);
        assert_eq!(validate_packet(&pkt), Err(Reject::IncompleteTcpHeader));
        let pkt = ipv6(IPPROTO_UDP, &[], &[0; 4], None);
        assert_eq!(validate_packet(&pkt), Err(Reject::IncompleteUdpHeader));
        // MSS with a wrong length byte, behind a destination-options header.
        let tcp = tcp_hdr(6, &[0x02, 0x05, 0x05, 0xb4]);
        let pkt = ipv6(IP_PROTO_DSTOPTS, &ext(IPPROTO_TCP, 1), &tcp, None);
        assert_eq!(validate_packet(&pkt), Err(Reject::BadTcpOptions));
    }

    // Q4: the packet ends at 40 + ip6_plen, extension headers or not; the C
    // trims short of that when extension headers are present.
    #[test]
    fn ipv6_trailer_is_trimmed_to_the_payload_length() {
        let mut tcp = tcp_hdr(5, &[]);
        tcp.extend_from_slice(&[0xee; 6]); // a 6-byte link-layer trailer
        let v = validate_packet(&ipv6(IPPROTO_TCP, &[], &tcp, Some(20))).unwrap();
        assert_eq!(v.captured_len, 60);
        let v = validate_packet(&ipv6(
            IP_PROTO_HOPOPTS,
            &ext(IPPROTO_TCP, 2),
            &tcp,
            Some(36),
        ))
        .unwrap();
        assert_eq!((v.data_offset, v.captured_len), (56, 76));
        // A payload length larger than what was captured leaves the capture as is.
        let v = validate_packet(&ipv6(IPPROTO_TCP, &[], &tcp_hdr(5, &[]), Some(1000))).unwrap();
        assert_eq!(v.captured_len, 60);
    }

    #[test]
    fn ipv6_walk_is_total() {
        let mut chain = ext(IP_PROTO_ROUTING, 2);
        chain.extend(frag(IP_PROTO_DSTOPTS, 0, 0, true));
        chain.extend(ext(IPPROTO_TCP, 1));
        let base = ipv6(
            IP_PROTO_HOPOPTS,
            &chain,
            &tcp_hdr(6, &[2, 4, 5, 0xb4]),
            None,
        );
        for n in 0..=base.len() {
            let _ = validate_packet(&base[..n]);
        }
        // Every byte of the chain at every value.
        for i in 40..72 {
            for b in [0u8, 1, 43, 44, 59, 60, 0x7f, 0xff] {
                let mut p = base.clone();
                p[i] = b;
                if let Ok(v) = validate_packet(&p) {
                    assert!(v.data_offset >= 40 && v.data_offset < p.len());
                }
            }
        }
    }

    #[test]
    fn valid_tcp_options_accepted() {
        // MSS(4) + SACK-permitted(2) + NOP + WScale(3) = 10 bytes -> offset 30/4=... 30 not /4.
        // Pad to 12 bytes with EOL so hdrlen = 32 (offset 8 words).
        let opts = [
            0x02, 0x04, 0x05, 0xb4, // MSS 1460
            0x04, 0x02, // SACK permitted
            0x01, // NOP
            0x03, 0x03, 0x07, // WScale 7
            0x00, 0x00, // EOL pad
        ];
        let tcp = tcp_hdr(8, &opts); // 20 + 12 = 32 = 8 words
        let pkt = ipv4_tcp(52, &tcp);
        assert!(validate_packet(&pkt).is_ok());
        assert!(validate_tcp_header(&tcp));
    }

    #[test]
    fn rejects_mss_with_wrong_length_byte() {
        // MSS option claiming length 3 (must be 4). hdrlen 24 (6 words).
        let opts = [0x02, 0x03, 0x05, 0xb4];
        let tcp = tcp_hdr(6, &opts);
        assert!(!validate_tcp_header(&tcp));
        let pkt = ipv4_tcp(44, &tcp);
        assert_eq!(validate_packet(&pkt), Err(Reject::BadTcpOptions));
    }

    #[test]
    fn rejects_option_overrunning_header() {
        // An option (kind 8, timestamp) claiming length 10 but only 4 option bytes.
        let opts = [0x08, 0x0a, 0x00, 0x00];
        let tcp = tcp_hdr(6, &opts);
        assert!(!validate_tcp_header(&tcp));
    }

    #[test]
    fn rejects_sack_with_bad_block_length() {
        // SACK (kind 5) length 6 -> (6-2)=4, 4%8 != 0 -> reject. hdrlen 28 (7 words).
        let opts = [0x05, 0x06, 0, 0, 0, 0, 0, 0];
        let tcp = tcp_hdr(7, &opts);
        assert!(!validate_tcp_header(&tcp));
    }

    #[test]
    fn zero_length_option_does_not_loop() {
        // A bogus option with declared length 0 must be rejected, not spin forever.
        let opts = [0x09, 0x00, 0x00, 0x00];
        let tcp = tcp_hdr(6, &opts);
        assert!(!validate_tcp_header(&tcp));
    }

    #[test]
    fn incomplete_l4_headers_rejected() {
        // proto TCP but only 10 bytes after IP header.
        let mut pkt = ipv4_tcp(30, &[0u8; 10]);
        pkt[9] = IPPROTO_TCP;
        assert_eq!(validate_packet(&pkt), Err(Reject::IncompleteTcpHeader));
        // proto UDP but only 4 bytes.
        let mut pkt = ipv4_tcp(24, &[0u8; 4]);
        pkt[9] = IPPROTO_UDP;
        assert_eq!(validate_packet(&pkt), Err(Reject::IncompleteUdpHeader));
    }

    #[test]
    fn total_validation_never_panics() {
        let base = ipv4_tcp(60, &tcp_hdr(10, &[0xff; 20]));
        for n in 0..=base.len() {
            let _ = validate_packet(&base[..n]);
        }
        for b in 0u16..=511 {
            let opts: Vec<u8> = (0..16)
                .map(|i| u8::try_from(b.wrapping_add(i) & 0xFF).unwrap_or(0))
                .collect();
            let _ = validate_tcp_header(&opts);
        }
    }
}
