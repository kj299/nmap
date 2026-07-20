//! Packet construction — the raw send path. Ports nmap's `build_*_raw` family
//! (`tcpip.cc`): assemble a complete IPv4 wire packet (IP header + options + L4
//! header + options + payload) with correct checksums, ready to hand to the raw
//! socket / Npcap injector.
//!
//! ## What this fixes about the C
//!
//! The C builders are *impure* in three ways this port removes, each ledgered in
//! `DIVERGENCES.md`:
//!
//! * **`build-no-static-myttl`** — `build_ip_raw` holds a function-local
//!   `static int myttl` (`tcpip.cc:524`), a reentrancy landmine. This port threads
//!   every field as an explicit parameter; nothing is retained between calls.
//! * **`build-explicit-fields-no-magic`** — the C injects hidden randomness and
//!   silent defaults (`ttl == -1` → random TTL, `seq == 0 && SYN` → random ISN,
//!   `window == 0` → 1024). Randomness at the construction layer is untestable and
//!   non-reproducible; this port takes concrete values and the caller (the scan
//!   driver, at the edge) supplies any randomness. Matches the semantics of nmap's
//!   own `libnetutil` header-class setters.
//! * **`send-payload-no-silent-truncation`** — `build_icmp_raw` copies the payload
//!   into a fixed `pingpkt.data[1500]` via `MIN(dlen, datalen)` (`tcpip.cc:965`),
//!   silently dropping the overflow; and `build_ip_raw` narrows `int packetlen` into
//!   a `u16` IP length, silently wrapping past 65535. This port sizes the output to
//!   the payload and returns [`BuildError::PayloadTooLarge`] rather than truncate or
//!   wrap. It also replaces the C `fatal()` on an unknown ICMP type with a returned
//!   [`BuildError::UnknownIcmpType`] — a library never aborts the process.

use crate::checksum;
use crate::headers::ipv4::{Ipv4Header, IP_HEADER_LEN};
use crate::headers::tcp::TcpHeader;
use crate::headers::udp::{UdpHeader, UDP_HEADER_LEN};

/// IP protocol numbers for the builders here.
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

/// Largest value the IPv4 total-length field can hold.
const MAX_IP_TOTAL_LEN: usize = u16::MAX as usize;

/// Why a packet could not be built. Every variant is a case the C handled by
/// aborting, silently truncating, or silently wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// IP options length is not a multiple of 4 (the header measures length in
    /// 32-bit words, so options must be word-aligned). C: `assert(ipoptlen % 4 == 0)`.
    IpOptionsNotAligned(usize),
    /// TCP options length is not a multiple of 4. C: `fatal(...)`.
    TcpOptionsNotAligned(usize),
    /// IP options exceed the 40-byte maximum (IHL tops out at 15 words = 60 bytes,
    /// i.e. 40 bytes of options past the 20-byte fixed header).
    IpOptionsTooLong(usize),
    /// TCP options exceed the 40-byte maximum (data offset tops out at 15 words).
    TcpOptionsTooLong(usize),
    /// The assembled packet would exceed the 65535-byte IPv4 total-length field.
    PayloadTooLarge(usize),
    /// An ICMP type/code this builder does not construct. C: `fatal(...)`.
    UnknownIcmpType {
        /// The requested ICMP type.
        typ: u8,
        /// The requested ICMP code.
        code: u8,
    },
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BuildError::IpOptionsNotAligned(n) => {
                write!(f, "IP options length {n} is not a multiple of 4")
            }
            BuildError::TcpOptionsNotAligned(n) => {
                write!(f, "TCP options length {n} is not a multiple of 4")
            }
            BuildError::IpOptionsTooLong(n) => write!(f, "IP options length {n} exceeds 40"),
            BuildError::TcpOptionsTooLong(n) => write!(f, "TCP options length {n} exceeds 40"),
            BuildError::PayloadTooLarge(n) => {
                write!(f, "assembled packet length {n} exceeds 65535")
            }
            BuildError::UnknownIcmpType { typ, code } => {
                write!(f, "unsupported ICMP type/code {typ}/{code}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// The IPv4-header parameters shared by every builder. Concrete values only — no
/// sentinel means "randomize" (see `build-explicit-fields-no-magic`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Spec {
    /// Source address (raw 4 bytes).
    pub src: [u8; 4],
    /// Destination address (raw 4 bytes).
    pub dst: [u8; 4],
    /// Time-to-live.
    pub ttl: u8,
    /// IP identification field.
    pub ipid: u16,
    /// Type-of-service byte.
    pub tos: u8,
    /// Set the Don't-Fragment flag.
    pub df: bool,
    /// IP options (must be a multiple of 4 bytes, at most 40).
    pub options: Vec<u8>,
    /// Corrupt the L4 checksum by one (nmap `--badsum`), for firewall probing.
    pub bad_sum: bool,
}

impl Ipv4Spec {
    /// A spec with no options, DF clear, valid checksums — the common case.
    #[must_use]
    pub fn new(src: [u8; 4], dst: [u8; 4], ttl: u8, ipid: u16) -> Ipv4Spec {
        Ipv4Spec {
            src,
            dst,
            ttl,
            ipid,
            tos: 0,
            df: false,
            options: Vec::new(),
            bad_sum: false,
        }
    }

    fn validate_options(&self) -> Result<(), BuildError> {
        let n = self.options.len();
        if n % 4 != 0 {
            return Err(BuildError::IpOptionsNotAligned(n));
        }
        if n > 40 {
            return Err(BuildError::IpOptionsTooLong(n));
        }
        Ok(())
    }
}

/// Wrap an already-built L4 segment in an IPv4 header (options, correct IHL, total
/// length, and header checksum). Ports `build_ip_raw` + `fill_ip_raw`.
pub fn build_ip_raw(spec: &Ipv4Spec, proto: u8, payload: &[u8]) -> Result<Vec<u8>, BuildError> {
    spec.validate_options()?;
    let optlen = spec.options.len();
    // ihl is (20 + optlen) / 4 words; optlen is a checked multiple of 4 <= 40, so
    // ihl is in 5..=15 and fits a u8.
    let header_len = IP_HEADER_LEN.saturating_add(optlen);
    let total = header_len.checked_add(payload.len());
    let total = match total {
        Some(t) if t <= MAX_IP_TOTAL_LEN => t,
        _ => return Err(BuildError::PayloadTooLarge(usize::MAX)),
    };
    // ihl in words: header_len/4, provably 5..=15.
    let ihl = u8::try_from(header_len / 4).unwrap_or(5);
    // total fits u16 (checked above).
    let total_length = u16::try_from(total).unwrap_or(u16::MAX);

    let mut ip = Ipv4Header {
        version: 4,
        ihl,
        tos: spec.tos,
        total_length,
        id: spec.ipid,
        flags_frag: if spec.df { 0x4000 } else { 0 },
        ttl: spec.ttl,
        protocol: proto,
        checksum: 0,
        src: spec.src,
        dst: spec.dst,
        options: spec.options.clone(),
    };
    ip.checksum = ip.computed_checksum();

    let mut out = ip.serialize();
    out.extend_from_slice(payload);
    Ok(out)
}

/// Apply the `--badsum` corruption: decrement the checksum by one (wrapping),
/// exactly as `build_icmp_raw` does. A zero-then-corrupt still differs from a valid sum.
fn apply_bad_sum(sum: u16, bad: bool) -> u16 {
    if bad {
        sum.wrapping_sub(1)
    } else {
        sum
    }
}

/// Build a complete raw TCP/IPv4 packet. Ports `build_tcp_raw` (+ `build_tcp`).
/// `tcpopt` must be a multiple of 4 bytes (at most 40); `data` is the payload.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_raw(
    spec: &Ipv4Spec,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    reserved: u8,
    flags: u8,
    window: u16,
    urp: u16,
    tcpopt: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, BuildError> {
    let optn = tcpopt.len();
    if optn % 4 != 0 {
        return Err(BuildError::TcpOptionsNotAligned(optn));
    }
    if optn > 40 {
        return Err(BuildError::TcpOptionsTooLong(optn));
    }
    // data_offset = 5 + optn/4 words, provably 5..=15.
    let data_offset = u8::try_from(5usize.saturating_add(optn / 4)).unwrap_or(5);

    let mut tcp = TcpHeader {
        sport,
        dport,
        seq,
        ack,
        data_offset,
        reserved: reserved & 0x0F,
        flags,
        window,
        checksum: 0,
        urgent_ptr: urp,
        options: tcpopt.to_vec(),
    };
    tcp.checksum = apply_bad_sum(
        tcp.computed_checksum(spec.src, spec.dst, data),
        spec.bad_sum,
    );

    let mut segment = tcp.serialize();
    segment.extend_from_slice(data);
    build_ip_raw(spec, IPPROTO_TCP, &segment)
}

/// Build a complete raw UDP/IPv4 packet. Ports `build_udp_raw` (+ `build_udp`).
pub fn build_udp_raw(
    spec: &Ipv4Spec,
    sport: u16,
    dport: u16,
    data: &[u8],
) -> Result<Vec<u8>, BuildError> {
    let total = UDP_HEADER_LEN.checked_add(data.len());
    let length = match total {
        Some(t) if t <= MAX_IP_TOTAL_LEN => u16::try_from(t).unwrap_or(u16::MAX),
        _ => return Err(BuildError::PayloadTooLarge(usize::MAX)),
    };
    let mut udp = UdpHeader {
        sport,
        dport,
        length,
        checksum: 0,
    };
    udp.checksum = apply_bad_sum(
        udp.computed_checksum(spec.src, spec.dst, data),
        spec.bad_sum,
    );

    let mut segment = udp.serialize();
    segment.extend_from_slice(data);
    build_ip_raw(spec, IPPROTO_UDP, &segment)
}

/// Build a complete raw ICMPv4/IPv4 packet. Ports `build_icmp_raw` for the three
/// query types nmap constructs: echo request (type 8), timestamp request (13/0),
/// and address-mask request (17/0). Unlike the C, an unsupported type returns
/// [`BuildError::UnknownIcmpType`] instead of `fatal()`, and an oversized payload
/// returns [`BuildError::PayloadTooLarge`] instead of silently truncating.
pub fn build_icmp_raw(
    spec: &Ipv4Spec,
    ptype: u8,
    pcode: u8,
    id: u16,
    seq: u16,
    data: &[u8],
) -> Result<Vec<u8>, BuildError> {
    // Fixed portion after type/code/checksum/id/seq, per type. The C zero-fills a
    // type-specific region between the id/seq fields and the caller data.
    let fixed_tail: usize = match (ptype, pcode) {
        (8, _) => 0,   // echo request: 8-byte header, no fixed tail
        (13, 0) => 12, // timestamp request: 20-byte header (12 zero bytes)
        (17, 0) => 4,  // address-mask request: 12-byte header (4 zero bytes)
        _ => {
            return Err(BuildError::UnknownIcmpType {
                typ: ptype,
                code: pcode,
            })
        }
    };

    // Header layout: type(1) code(1) checksum(2) id(2) seq(2) [fixed_tail zeros] [data].
    let body_len = 8usize
        .checked_add(fixed_tail)
        .and_then(|n| n.checked_add(data.len()));
    let body_len = match body_len {
        Some(n) if n <= MAX_IP_TOTAL_LEN => n,
        _ => return Err(BuildError::PayloadTooLarge(usize::MAX)),
    };

    let mut icmp = Vec::with_capacity(body_len);
    icmp.push(ptype);
    icmp.push(pcode);
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.resize(icmp.len().saturating_add(fixed_tail), 0);
    icmp.extend_from_slice(data);

    let sum = apply_bad_sum(checksum::in_cksum(&icmp), spec.bad_sum);
    let sum_be = sum.to_be_bytes();
    // Write the checksum into bytes 2..4 (always present).
    if let Some(slot) = icmp.get_mut(2..4) {
        slot.copy_from_slice(&sum_be);
    }

    build_ip_raw(spec, IPPROTO_ICMP, &icmp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_parser::{parse_packet, Header};

    fn spec() -> Ipv4Spec {
        Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 0x1234)
    }

    /// A built packet must parse back to the intended layer stack, and every checksum
    /// must verify (in_cksum over a valid header returns 0).
    fn assert_parses_as(pkt: &[u8], kinds: &[&str]) {
        let hs = parse_packet(pkt, false);
        let got: Vec<&str> = hs.iter().map(Header::kind_str).collect();
        assert_eq!(got, kinds, "layer stack mismatch");
    }

    #[test]
    fn tcp_syn_roundtrips_and_checksums_valid() {
        let pkt = build_tcp_raw(
            &spec(),
            40000,
            80,
            0x1111_2222,
            0,
            0,
            0x02,
            1024,
            0,
            &[],
            &[],
        )
        .unwrap();
        assert_parses_as(&pkt, &["ip4", "tcp"]);
        // Full IP header checksum verifies to zero.
        assert_eq!(checksum::in_cksum(&pkt[..20]), 0);
        // Parse the TCP header and re-verify its pseudo-header checksum.
        let hs = parse_packet(&pkt, false);
        if let Header::Tcp(t) = &hs[1] {
            assert_eq!(t.sport, 40000);
            assert_eq!(t.dport, 80);
            assert_eq!(t.flags, 0x02);
            assert_eq!(
                t.computed_checksum([10, 0, 0, 1], [10, 0, 0, 2], &[]),
                t.checksum
            );
        } else {
            panic!("expected TCP header");
        }
    }

    #[test]
    fn tcp_with_options_and_payload() {
        // MSS option (kind 2, len 4, value 1460) padded to 4 bytes, + 3-byte payload.
        let pkt = build_tcp_raw(
            &spec(),
            1234,
            443,
            1,
            2,
            0,
            0x18,
            8192,
            0,
            &[0x02, 0x04, 0x05, 0xb4],
            &[0xaa, 0xbb, 0xcc],
        )
        .unwrap();
        assert_parses_as(&pkt, &["ip4", "tcp", "raw"]);
        let hs = parse_packet(&pkt, false);
        assert_eq!(hs[1].len(), 24); // 20 + 4 options
        assert_eq!(hs[2], Header::Raw { len: 3 });
    }

    #[test]
    fn udp_roundtrips_and_length_correct() {
        let pkt = build_udp_raw(&spec(), 53, 5353, &[1, 2, 3, 4]).unwrap();
        assert_parses_as(&pkt, &["ip4", "udp", "raw"]);
        let hs = parse_packet(&pkt, false);
        if let Header::Udp(u) = &hs[1] {
            assert_eq!(u.length, 12); // 8 + 4
            assert_eq!(
                u.computed_checksum([10, 0, 0, 1], [10, 0, 0, 2], &[1, 2, 3, 4]),
                u.checksum
            );
        } else {
            panic!("expected UDP header");
        }
    }

    #[test]
    fn icmp_echo_timestamp_mask_lengths() {
        let echo = build_icmp_raw(&spec(), 8, 0, 0x1111, 0x2222, &[]).unwrap();
        assert_parses_as(&echo, &["ip4", "icmp"]);
        assert_eq!(parse_packet(&echo, false)[1].len(), 8);
        assert_eq!(checksum::in_cksum(&echo[20..]), 0);

        let ts = build_icmp_raw(&spec(), 13, 0, 1, 2, &[]).unwrap();
        assert_eq!(parse_packet(&ts, false)[1].len(), 20);

        let mask = build_icmp_raw(&spec(), 17, 0, 1, 2, &[]).unwrap();
        assert_eq!(parse_packet(&mask, false)[1].len(), 12);
    }

    #[test]
    fn ip_options_widen_the_header() {
        let mut s = spec();
        s.options = vec![0x01, 0x01, 0x01, 0x00]; // 4 bytes of NOP/EOL
        let pkt = build_udp_raw(&s, 1, 2, &[]).unwrap();
        let hs = parse_packet(&pkt, false);
        assert_eq!(hs[0].len(), 24); // 20 + 4 options
        assert_eq!(checksum::in_cksum(&pkt[..24]), 0);
    }

    #[test]
    fn bad_sum_corrupts_the_l4_checksum() {
        let good = build_tcp_raw(&spec(), 1, 2, 3, 4, 0, 2, 1024, 0, &[], &[]).unwrap();
        let mut s = spec();
        s.bad_sum = true;
        let bad = build_tcp_raw(&s, 1, 2, 3, 4, 0, 2, 1024, 0, &[], &[]).unwrap();
        assert_ne!(good, bad, "badsum must change the packet");
        // Only the TCP checksum field (bytes 36..38) should differ.
        assert_eq!(good[..36], bad[..36]);
        assert_eq!(good[38..], bad[38..]);
    }

    #[test]
    fn rejects_misaligned_and_oversized_options() {
        assert_eq!(
            build_tcp_raw(&spec(), 1, 2, 3, 4, 0, 2, 1, 0, &[0, 0, 0], &[]),
            Err(BuildError::TcpOptionsNotAligned(3))
        );
        let mut s = spec();
        s.options = vec![0u8; 6];
        assert_eq!(
            build_udp_raw(&s, 1, 2, &[]),
            Err(BuildError::IpOptionsNotAligned(6))
        );
    }

    #[test]
    fn unknown_icmp_type_errors_not_panics() {
        assert_eq!(
            build_icmp_raw(&spec(), 99, 0, 0, 0, &[]),
            Err(BuildError::UnknownIcmpType { typ: 99, code: 0 })
        );
    }

    #[test]
    fn oversized_payload_rejected_not_truncated() {
        let huge = vec![0u8; 65536];
        assert!(matches!(
            build_udp_raw(&spec(), 1, 2, &huge),
            Err(BuildError::PayloadTooLarge(_))
        ));
    }
}
