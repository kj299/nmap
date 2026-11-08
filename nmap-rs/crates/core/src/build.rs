//! Packet construction — the raw send path. Ports nmap's `build_*_raw` family
//! (`tcpip.cc`): assemble a complete IPv4 wire packet (IP header + options + L4
//! header + options + payload) with correct checksums, ready to hand to the raw
//! socket / Npcap injector. [`build_tcp_raw_ipv6`] and [`build_udp_raw_ipv6`] do the
//! same behind an IPv6 header, for the IPv6 port scans (`build_tcp_raw_ipv6`,
//! `build_udp_raw_ipv6`, `tcpip.cc:657`, `:786`).
//!
//! ## IPv6
//!
//! [`Ipv6Spec::new`] is what nmap's scan engine sends (`scan_engine_raw.cc:1235`,
//! `:1278`): traffic class 0, flow label 0, no extension headers, and hop limit
//! **255**. That last is a C quirk reproduced on purpose (`build6-scan-hop-limit-255`):
//! the engine passes `o.ttl`, whose unset value is -1, to a `u8` parameter, so it
//! arrives as 255 and `build_ipv6_raw`'s random 37–59 branch never runs. `--ttl`
//! sets it as for IPv4.
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
/// Largest value the IPv6 payload-length field can hold (no jumbograms).
const MAX_IPV6_PAYLOAD_LEN: usize = u16::MAX as usize;
/// IPv6 fixed header length.
const IPV6_HEADER_LEN: usize = 40;
/// The hop limit nmap's IPv6 scan probes carry when `--ttl` is not given.
pub const SCAN_HOP_LIMIT: u8 = 255;

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

/// Operator overrides for the IP layer of every probe a scan sends —
/// nmap's `--ttl`, `--badsum` and `-S`.
///
/// One struct rather than three parameters because it threads through the whole
/// raw-scan stack (`syn`/`udp`/`flag` entry points → `group_scan_targets` → the
/// per-probe `Ipv4Spec`), and those signatures were already five arguments long.
///
/// `Default` is "change nothing", so a scan that names none of these builds
/// byte-identical packets to one compiled before these options existed. That is
/// worth stating because it is what makes the wiring safe: the override is
/// applied at exactly one site, and its absence is the previous behaviour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketOverrides {
    /// `--ttl N`: IP time-to-live for every probe. `None` leaves the scan's default.
    pub ttl: Option<u8>,
    /// `--badsum`: corrupt the L4 checksum, so only a host that ignores checksums
    /// (typically a firewall or IDS, not a real stack) replies.
    pub bad_sum: bool,
    /// `-S addr`: claim this IPv4 source address instead of the routed one.
    /// Replies will go to whatever really owns it, so this is only useful when
    /// the operator can observe that traffic.
    pub spoof_src: Option<[u8; 4]>,
    /// `-6 -S addr`: the same for IPv6 probes. With `-6`, nmap reads `-S` as an
    /// IPv6 address (`resolve(..., o.af())`, `nmap.cc:1463`), so a scan carries
    /// one of the two, never both.
    pub spoof_src6: Option<[u8; 16]>,
}

impl PacketOverrides {
    /// True when nothing is overridden — lets a caller skip the raw-scan warning.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl Ipv4Spec {
    /// Apply operator overrides, if any. The single site where `--ttl`,
    /// `--badsum` and `-S` take effect.
    #[must_use]
    pub fn with_overrides(mut self, o: PacketOverrides) -> Ipv4Spec {
        if let Some(ttl) = o.ttl {
            self.ttl = ttl;
        }
        if o.bad_sum {
            self.bad_sum = true;
        }
        if let Some(src) = o.spoof_src {
            self.src = src;
        }
        self
    }

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
        if !n.is_multiple_of(4) {
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

/// Apply the `--badsum` corruption as the C does it. Every `o.badsum` site in
/// `tcpip.cc` runs `--sum` on the checksum as a host-order `u16`, though the field
/// holds network-order bytes. On the little-endian machines nmap runs on, that takes
/// one from the checksum's **first byte on the wire**, borrowing from the second
/// when it is 0: a valid 0x3260 goes out as 0x3160, not 0x325F. The port does what
/// such a machine does, on every host (`build-badsum-host-order-decrement`).
fn apply_bad_sum(sum: u16, bad: bool) -> u16 {
    if bad {
        let host = u16::from_le_bytes(sum.to_be_bytes()).wrapping_sub(1);
        u16::from_be_bytes(host.to_le_bytes())
    } else {
        sum
    }
}

/// `--badsum` for a TCP or UDP checksum, as `ipv4_cksum` and `ipv6_cksum` apply it
/// (`tcpip.cc:445`, `:462`): decrement ([`apply_bad_sum`]), and for UDP send a zero
/// as `0xFFFF`, since a zero UDP checksum means "none" and would not be bad at all.
fn apply_bad_l4_sum(sum: u16, bad: bool, proto: u8) -> u16 {
    let sum = apply_bad_sum(sum, bad);
    if bad && proto == IPPROTO_UDP && sum == 0 {
        0xFFFF
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
    if !optn.is_multiple_of(4) {
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
    tcp.checksum = apply_bad_l4_sum(
        tcp.computed_checksum(spec.src, spec.dst, data),
        spec.bad_sum,
        IPPROTO_TCP,
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
    udp.checksum = apply_bad_l4_sum(
        udp.computed_checksum(spec.src, spec.dst, data),
        spec.bad_sum,
        IPPROTO_UDP,
    );

    let mut segment = udp.serialize();
    segment.extend_from_slice(data);
    build_ip_raw(spec, IPPROTO_UDP, &segment)
}

/// The IPv6-header parameters of a scan probe: `build_ipv6_raw`'s arguments
/// (`tcpip.cc:549`) and `ipv6_cksum`'s `--badsum`. Concrete values only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Spec {
    /// Source address.
    pub src: [u8; 16],
    /// Destination address.
    pub dst: [u8; 16],
    /// Traffic class (the scan engine sends 0).
    pub traffic_class: u8,
    /// Flow label, the low 20 bits (the scan engine sends 0).
    pub flow_label: u32,
    /// Hop limit.
    pub hop_limit: u8,
    /// Corrupt the L4 checksum by one (nmap `--badsum`).
    pub bad_sum: bool,
}

impl Ipv6Spec {
    /// What nmap's IPv6 scan probes carry: traffic class 0, flow label 0, hop limit
    /// [`SCAN_HOP_LIMIT`] (module docs), valid checksums.
    #[must_use]
    pub fn new(src: [u8; 16], dst: [u8; 16]) -> Ipv6Spec {
        Ipv6Spec {
            src,
            dst,
            traffic_class: 0,
            flow_label: 0,
            hop_limit: SCAN_HOP_LIMIT,
            bad_sum: false,
        }
    }

    /// Apply `--ttl` (as the hop limit), `--badsum` and `-6 -S`
    /// ([`PacketOverrides::spoof_src6`]; an IPv4 `-S` does not apply here).
    #[must_use]
    pub fn with_overrides(mut self, o: PacketOverrides) -> Ipv6Spec {
        if let Some(ttl) = o.ttl {
            self.hop_limit = ttl;
        }
        if o.bad_sum {
            self.bad_sum = true;
        }
        if let Some(src) = o.spoof_src6 {
            self.src = src;
        }
        self
    }
}

/// Put an IPv6 header in front of an already-built upper-layer packet. Ports
/// `build_ipv6_raw` (`tcpip.cc:549`, `ip6_pack_hdr`), with the hop limit concrete.
///
/// # Errors
/// [`BuildError::PayloadTooLarge`] when `payload` is longer than the payload-length
/// field can say (the C narrows it to a `u16` without a word).
pub fn build_ipv6_raw(
    spec: &Ipv6Spec,
    next_header: u8,
    payload: &[u8],
) -> Result<Vec<u8>, BuildError> {
    let Ok(plen) = u16::try_from(payload.len()) else {
        return Err(BuildError::PayloadTooLarge(payload.len()));
    };
    let vtf =
        (6u32 << 28) | (u32::from(spec.traffic_class) << 20) | (spec.flow_label & 0x000F_FFFF);
    let mut out = Vec::with_capacity(IPV6_HEADER_LEN.saturating_add(payload.len()));
    out.extend_from_slice(&vtf.to_be_bytes());
    out.extend_from_slice(&plen.to_be_bytes());
    out.push(next_header);
    out.push(spec.hop_limit);
    out.extend_from_slice(&spec.src);
    out.extend_from_slice(&spec.dst);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Build a complete raw TCP/IPv6 packet. Ports `build_tcp_raw_ipv6` (+ `build_tcp`,
/// `ipv6_cksum`). `tcpopt` must be a multiple of 4 bytes (at most 40).
///
/// # Errors
/// As [`build_tcp_raw`] for the options; [`BuildError::PayloadTooLarge`] past the
/// payload-length field.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_raw_ipv6(
    spec: &Ipv6Spec,
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
    let segment = tcp_segment(
        sport, dport, seq, ack, reserved, flags, window, urp, tcpopt, data,
    )?;
    let segment = checksummed(segment, spec, IPPROTO_TCP, 16);
    build_ipv6_raw(spec, IPPROTO_TCP, &segment)
}

/// Build a complete raw UDP/IPv6 packet. Ports `build_udp_raw_ipv6` (+ `build_udp`,
/// `ipv6_cksum`, which never sends a zero UDP checksum).
///
/// # Errors
/// [`BuildError::PayloadTooLarge`] past the UDP length or payload-length field.
pub fn build_udp_raw_ipv6(
    spec: &Ipv6Spec,
    sport: u16,
    dport: u16,
    data: &[u8],
) -> Result<Vec<u8>, BuildError> {
    let length = match UDP_HEADER_LEN.checked_add(data.len()) {
        Some(t) if t <= MAX_IPV6_PAYLOAD_LEN => u16::try_from(t).unwrap_or(u16::MAX),
        _ => return Err(BuildError::PayloadTooLarge(usize::MAX)),
    };
    let mut segment = UdpHeader {
        sport,
        dport,
        length,
        checksum: 0,
    }
    .serialize();
    segment.extend_from_slice(data);
    let segment = checksummed(segment, spec, IPPROTO_UDP, 6);
    build_ipv6_raw(spec, IPPROTO_UDP, &segment)
}

/// The IP layer of a scan probe: [`Ipv4Spec`] or [`Ipv6Spec`]. The SYN, UDP and
/// flag-scan probe builders are generic over it, so what they put in the TCP or UDP
/// header is the same code for both families, as it is in the C
/// (`sendIPScanProbe`, `scan_engine_raw.cc:1166`).
pub trait ProbeSpec {
    /// A TCP probe: no reserved bits, no urgent pointer, as the scan engine sends.
    ///
    /// # Errors
    /// The family builder's [`BuildError`].
    #[allow(clippy::too_many_arguments)]
    fn tcp_probe(
        &self,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        tcpopt: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, BuildError>;

    /// A UDP probe carrying `data`.
    ///
    /// # Errors
    /// The family builder's [`BuildError`].
    fn udp_probe(&self, sport: u16, dport: u16, data: &[u8]) -> Result<Vec<u8>, BuildError>;
}

impl ProbeSpec for Ipv4Spec {
    fn tcp_probe(
        &self,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        tcpopt: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, BuildError> {
        build_tcp_raw(
            self, sport, dport, seq, ack, 0, flags, window, 0, tcpopt, data,
        )
    }

    fn udp_probe(&self, sport: u16, dport: u16, data: &[u8]) -> Result<Vec<u8>, BuildError> {
        build_udp_raw(self, sport, dport, data)
    }
}

impl ProbeSpec for Ipv6Spec {
    fn tcp_probe(
        &self,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        tcpopt: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, BuildError> {
        build_tcp_raw_ipv6(
            self, sport, dport, seq, ack, 0, flags, window, 0, tcpopt, data,
        )
    }

    fn udp_probe(&self, sport: u16, dport: u16, data: &[u8]) -> Result<Vec<u8>, BuildError> {
        build_udp_raw_ipv6(self, sport, dport, data)
    }
}

/// A TCP header (checksum zero) and its data, as `build_tcp` lays it out.
#[allow(clippy::too_many_arguments)]
fn tcp_segment(
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
    if !optn.is_multiple_of(4) {
        return Err(BuildError::TcpOptionsNotAligned(optn));
    }
    if optn > 40 {
        return Err(BuildError::TcpOptionsTooLong(optn));
    }
    let data_offset = u8::try_from(5usize.saturating_add(optn / 4)).unwrap_or(5);
    let mut segment = TcpHeader {
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
    }
    .serialize();
    segment.extend_from_slice(data);
    Ok(segment)
}

/// Fill a segment's checksum (at `at`) over the IPv6 pseudo-header, as `ipv6_cksum`
/// does, `--badsum` included.
fn checksummed(mut segment: Vec<u8>, spec: &Ipv6Spec, proto: u8, at: usize) -> Vec<u8> {
    let sum = checksum::ipv6_pseudoheader_cksum(spec.src, spec.dst, proto, &segment);
    let sum = apply_bad_l4_sum(sum, spec.bad_sum, proto);
    if let Some(slot) = segment.get_mut(at..at.saturating_add(2)) {
        slot.copy_from_slice(&sum.to_be_bytes());
    }
    segment
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
    /// The default override changes nothing — the property that makes wiring
    /// these options safe. A scan naming none of them must build byte-identical
    /// packets to one built before the options existed.
    #[test]
    fn default_overrides_are_a_no_op() {
        let base = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 0x1234);
        assert_eq!(
            base.clone().with_overrides(PacketOverrides::default()),
            base
        );
        assert!(PacketOverrides::default().is_empty());
    }

    #[test]
    fn each_override_changes_only_its_own_field() {
        let base = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 0x1234);

        let t = base.clone().with_overrides(PacketOverrides {
            ttl: Some(7),
            ..Default::default()
        });
        assert_eq!(t.ttl, 7);
        assert_eq!(
            (t.src, t.dst, t.bad_sum),
            (base.src, base.dst, base.bad_sum)
        );

        let b = base.clone().with_overrides(PacketOverrides {
            bad_sum: true,
            ..Default::default()
        });
        assert!(b.bad_sum);
        assert_eq!((b.ttl, b.src), (base.ttl, base.src));

        let s = base.clone().with_overrides(PacketOverrides {
            spoof_src: Some([192, 0, 2, 9]),
            ..Default::default()
        });
        assert_eq!(s.src, [192, 0, 2, 9]);
        assert_eq!((s.dst, s.ttl), (base.dst, base.ttl));
    }

    /// `--ttl 0` is a real value, not "unset". C accepts 0..=255 inclusive, and a
    /// TTL of 0 is a legitimate probe (the first hop must drop it), so `Option`
    /// carries presence and 0 stays meaningful.
    #[test]
    fn a_ttl_of_zero_is_applied_not_ignored() {
        let base = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 1);
        let out = base.with_overrides(PacketOverrides {
            ttl: Some(0),
            ..Default::default()
        });
        assert_eq!(out.ttl, 0);
    }

    /// The overrides compose, and the spoofed source reaches the built packet
    /// rather than stopping at the spec.
    #[test]
    fn overrides_reach_the_wire() {
        let spec = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 0x1234).with_overrides(
            PacketOverrides {
                ttl: Some(13),
                bad_sum: true,
                spoof_src: Some([192, 0, 2, 9]),
                spoof_src6: None,
            },
        );
        let pkt = build_tcp_raw(&spec, 1234, 80, 1, 0, 0, 0x02, 1024, 0, &[], &[]).expect("builds");
        assert_eq!(pkt[8], 13, "TTL byte");
        assert_eq!(&pkt[12..16], &[192, 0, 2, 9], "source address");
        // And the same probe without bad_sum differs only in the L4 checksum.
        let clean = Ipv4Spec::new([192, 0, 2, 9], [10, 0, 0, 2], 13, 0x1234);
        let clean_pkt =
            build_tcp_raw(&clean, 1234, 80, 1, 0, 0, 0x02, 1024, 0, &[], &[]).expect("builds");
        assert_ne!(pkt, clean_pkt, "--badsum must change the bytes");
    }

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

    // ---- IPv6 ----

    const SRC6: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const DST6: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    /// The sum over the pseudo-header and a segment whose checksum is filled in:
    /// 0 when the checksum is right (the folded sum is all ones).
    fn residue6(pkt: &[u8], nxt: u8) -> u16 {
        let mut acc = checksum::Accumulator::new();
        let len = u32::try_from(pkt.len().saturating_sub(40)).unwrap();
        acc.add(&pkt[8..40]);
        acc.add(&len.to_be_bytes());
        acc.add(&[0, 0, 0, nxt]);
        acc.add(&pkt[40..]);
        acc.finish()
    }

    #[test]
    fn scan_probes_carry_hop_limit_255_and_no_class_or_label() {
        let spec = Ipv6Spec::new(SRC6, DST6);
        assert_eq!(spec.hop_limit, SCAN_HOP_LIMIT);
        let pkt = build_tcp_raw_ipv6(
            &spec,
            40000,
            80,
            7,
            0,
            0,
            0x02,
            1024,
            0,
            &[2, 4, 5, 0xb4],
            &[],
        )
        .unwrap();
        assert_eq!(&pkt[0..4], &[0x60, 0, 0, 0], "version 6, class 0, label 0");
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 24, "payload length");
        assert_eq!((pkt[6], pkt[7]), (6, 255), "next header, hop limit");
        assert_eq!((&pkt[8..24], &pkt[24..40]), (&SRC6[..], &DST6[..]));
        let v = crate::recv_validate::validate_packet(&pkt).unwrap();
        assert_eq!(
            (v.version, v.proto, v.data_offset, v.captured_len),
            (6, 6, 40, 64)
        );
        assert_eq!(
            residue6(&pkt, 6),
            0,
            "TCP checksum over the IPv6 pseudo-header"
        );
        // Class and label are placed where the header puts them, if ever set.
        let mut s = spec;
        s.traffic_class = 0xAB;
        s.flow_label = 0xF_FFFF;
        let pkt = build_ipv6_raw(&s, 59, &[]).unwrap();
        assert_eq!(&pkt[0..4], &[0x6A, 0xBF, 0xFF, 0xFF]);
    }

    #[test]
    fn udp_over_ipv6_has_a_checksum_and_a_length() {
        let spec = Ipv6Spec::new(SRC6, DST6);
        let pkt = build_udp_raw_ipv6(&spec, 40000, 53, b"payload").unwrap();
        assert_eq!(u16::from_be_bytes([pkt[44], pkt[45]]), 15, "UDP length");
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 15, "payload length");
        assert_eq!(residue6(&pkt, 17), 0);
        assert_ne!(&pkt[46..48], &[0, 0], "IPv6 UDP always carries a checksum");
    }

    #[test]
    fn ttl_and_badsum_apply_to_ipv6_probes() {
        let base = Ipv6Spec::new(SRC6, DST6);
        assert_eq!(base.with_overrides(PacketOverrides::default()), base);
        let s = base.with_overrides(PacketOverrides {
            ttl: Some(0),
            bad_sum: true,
            spoof_src: Some([192, 0, 2, 9]),
            spoof_src6: None,
        });
        assert_eq!(
            (s.hop_limit, s.bad_sum, s.src),
            (0, true, SRC6),
            "no IPv4 -S here"
        );
        // `-6 -S` is the IPv6 source, and nothing else changes; an IPv4 spec
        // ignores it in turn.
        let spoofed = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let o6 = PacketOverrides {
            spoof_src6: Some(spoofed),
            ..Default::default()
        };
        assert_eq!(
            base.with_overrides(o6),
            Ipv6Spec {
                src: spoofed,
                ..base
            }
        );
        let v4 = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 1);
        assert_eq!(v4.clone().with_overrides(o6), v4);
        let wire = build_udp_raw_ipv6(&base.with_overrides(o6), 1, 2, b"").unwrap();
        assert_eq!(&wire[8..24], &spoofed, "the source on the wire");
        let good = build_tcp_raw_ipv6(&base, 1, 2, 3, 4, 0, 0x10, 1024, 0, &[], b"x").unwrap();
        let bad = build_tcp_raw_ipv6(&s, 1, 2, 3, 4, 0, 0x10, 1024, 0, &[], b"x").unwrap();
        assert_eq!(bad[7], 0);
        // The first checksum byte on the wire is one less (module docs).
        let host = |p: &[u8]| u16::from_le_bytes([p[56], p[57]]);
        assert_eq!(host(&bad), host(&good).wrapping_sub(1));
        assert_eq!(&good[40..56], &bad[40..56]);
    }

    /// `--badsum` takes one from the checksum's first byte on the wire, borrowing
    /// from the second, as the C does on a little-endian host.
    #[test]
    fn badsum_decrements_the_checksum_in_host_order() {
        assert_eq!(apply_bad_sum(0x3260, true), 0x3160);
        assert_eq!(apply_bad_sum(0x0060, true), 0xFF5F, "borrow");
        assert_eq!(apply_bad_sum(0x0001, true), 0xFF00);
        assert_eq!(apply_bad_sum(0x0100, true), 0x0000);
        assert_eq!(apply_bad_l4_sum(0x0100, true, IPPROTO_TCP), 0x0000);
        assert_eq!(apply_bad_l4_sum(0x0100, true, IPPROTO_UDP), 0xFFFF);
        assert_eq!(apply_bad_sum(0x3260, false), 0x3260);
    }

    /// As in the C, `--badsum` on a TCP checksum of 0x0000 sends 0xFFFF, the other
    /// ones'-complement zero, so that one packet in 65,536 still verifies.
    #[test]
    #[cfg_attr(miri, ignore = "searches up to 65,536 checksums")]
    fn badsum_on_a_zero_tcp_checksum_still_verifies_as_in_the_c() {
        let mut v6 = Ipv6Spec::new(SRC6, DST6);
        for n in 0u16..=u16::MAX {
            v6.bad_sum = false;
            let data = n.to_be_bytes();
            let good = build_tcp_raw_ipv6(&v6, 1, 2, 3, 4, 0, 0x10, 1024, 0, &[], &data).unwrap();
            if good[56..58] == [0, 0] {
                v6.bad_sum = true;
                let bad =
                    build_tcp_raw_ipv6(&v6, 1, 2, 3, 4, 0, 0x10, 1024, 0, &[], &data).unwrap();
                assert_eq!(&bad[56..58], &[0xFF, 0xFF]);
                assert_eq!(residue6(&bad, 6), 0, "still verifies");
                return;
            }
        }
        panic!("no payload gave a zero TCP checksum");
    }

    /// `--badsum` on UDP never yields 0 ("no checksum"), in either family: the C
    /// sends 0xFFFF instead (`ipv4_cksum`, `ipv6_cksum`). The decrement reaches 0
    /// from a valid checksum whose wire bytes are `01 00`.
    #[test]
    #[cfg_attr(miri, ignore = "searches up to 65,536 checksums")]
    fn badsum_never_sends_a_zero_udp_checksum() {
        let mut v4 = spec();
        let mut v6 = Ipv6Spec::new(SRC6, DST6);
        let at4 = 26;
        let at6 = 46;
        let mut seen = (false, false);
        for n in 0u16..=u16::MAX {
            let data = n.to_be_bytes();
            v4.bad_sum = false;
            let p4 = build_udp_raw(&v4, 1, 2, &data).unwrap();
            if !seen.0 && u16::from_be_bytes([p4[at4], p4[at4 + 1]]) == 0x0100 {
                v4.bad_sum = true;
                let b = build_udp_raw(&v4, 1, 2, &data).unwrap();
                assert_eq!(&b[at4..at4 + 2], &[0xFF, 0xFF], "IPv4");
                seen.0 = true;
            }
            v6.bad_sum = false;
            let p6 = build_udp_raw_ipv6(&v6, 1, 2, &data).unwrap();
            if !seen.1 && u16::from_be_bytes([p6[at6], p6[at6 + 1]]) == 0x0100 {
                v6.bad_sum = true;
                let b = build_udp_raw_ipv6(&v6, 1, 2, &data).unwrap();
                assert_eq!(&b[at6..at6 + 2], &[0xFF, 0xFF], "IPv6");
                seen.1 = true;
            }
            if seen == (true, true) {
                return;
            }
        }
        panic!("no payload gave a checksum of 0x0100: {seen:?}");
    }

    #[test]
    fn ipv6_builders_refuse_what_the_c_would_truncate() {
        let spec = Ipv6Spec::new(SRC6, DST6);
        assert!(matches!(
            build_tcp_raw_ipv6(&spec, 1, 2, 3, 4, 0, 2, 1, 0, &[1, 1, 1], &[]),
            Err(BuildError::TcpOptionsNotAligned(3))
        ));
        assert!(matches!(
            build_tcp_raw_ipv6(&spec, 1, 2, 3, 4, 0, 2, 1, 0, &[1; 44], &[]),
            Err(BuildError::TcpOptionsTooLong(44))
        ));
        let huge = vec![0u8; 65_536];
        assert!(matches!(
            build_udp_raw_ipv6(&spec, 1, 2, &huge),
            Err(BuildError::PayloadTooLarge(_))
        ));
        assert!(matches!(
            build_tcp_raw_ipv6(&spec, 1, 2, 3, 4, 0, 2, 1, 0, &[], &huge[..65_516]),
            Err(BuildError::PayloadTooLarge(_))
        ));
        assert!(build_tcp_raw_ipv6(&spec, 1, 2, 3, 4, 0, 2, 1, 0, &[], &huge[..65_515]).is_ok());
    }
}
