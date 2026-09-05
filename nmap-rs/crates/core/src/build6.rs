//! Construction of the 17 IPv6 OS-detection probes — ports `FPHost6::build_probe_list`
//! and its `make_tcp` helper from `FPEngine.cc`.
//!
//! The battery, in the order nmap sends it:
//!
//! | Probe | Packet |
//! |-------|--------|
//! | `S1`–`S6` | six SYNs with different options and windows, sequence numbers one apart (the "timed" probes) |
//! | `IE1` | ICMPv6 echo (code 9) behind a hop-by-hop options header, with a 120-byte payload |
//! | `IE2` | ICMPv6 echo behind a deliberately mis-ordered hop-by-hop → dstopts → routing → hop-by-hop chain |
//! | `NS` | ICMPv6 Neighbor Solicitation — **only when the target is on-link** |
//! | `U1` | UDP carrying 300 `'C'` bytes to a closed port |
//! | `TECN` | SYN+CWR+ECE with a tiny window and an odd urgent pointer |
//! | `T2`–`T7` | six more crafted TCP probes (the "untimed" ones) |
//!
//! Like [`crate::osprobe::build`] for IPv4, everything here is a **total function of its
//! inputs**: no randomness, no clock, no I/O. The driver supplies the random bases in
//! [`Build6Params`], so every byte on the wire is pinned by a test and the module is
//! fuzzable.
//!
//! ## Faithful reproduction of nmap's send list, including its skips
//!
//! A probe aimed at an open (or closed) TCP port is **silently dropped** when the scan
//! never found such a port — exactly as the C's `if (... < 0) continue;`. The `NS` probe
//! is emitted only for a directly-connected target. So [`build_probes`] returns *only the
//! probes nmap would actually send*, in nmap's order, and the driver keys responses by
//! the returned [`crate::fp6::Fp6Probe`].
//!
//! Two input quirks preserved from the C, because a divergence would change the packets:
//! the `TECN` probe carries an **ACK of 0** where every other TCP probe carries a fresh
//! random value (so [`Build6Params::tcp_acks`] slot 6 is ignored); and `NS` uses a **hop
//! limit of 255** regardless of the scan's chosen hop limit (RFC 4861 requires it, and a
//! router that decremented it would make the target discard the solicitation).

use crate::checksum::ipv6_pseudoheader_cksum;
use crate::fp6::Fp6Probe;

/// nmap's `OSDETECT_FLOW_LABEL` — the fixed 20-bit flow label every probe carries, so
/// the response analysis can tell whether the target echoes it.
pub const FLOW_LABEL: u32 = 0x12345;

/// IPv6 next-header / protocol numbers used when chaining the probe packets.
const NH_HOPOPT: u8 = 0;
const NH_TCP: u8 = 6;
const NH_UDP: u8 = 17;
const NH_ROUTING: u8 = 43;
const NH_ICMPV6: u8 = 58;
const NH_DSTOPTS: u8 = 60;

/// ICMPv6 message types the battery uses.
const ICMPV6_ECHO: u8 = 128;
const ICMPV6_NGHBRSOLICIT: u8 = 135;

/// The `U1` UDP payload: 300 bytes of `'C'` (`0x43`), as in the C's
/// `memset(payloadbuf, 0x43, 300)`.
const UDP_PAYLOAD_LEN: usize = 300;
const UDP_PAYLOAD_BYTE: u8 = 0x43;
/// The `IE1` echo payload: 120 zero bytes.
const IE1_PAYLOAD_LEN: usize = 120;

/// Which TCP port state a probe is aimed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortKind {
    Open,
    Closed,
}

/// One row of nmap's `TCP_DESCS` table (`FPEngine.cc`), transcribed byte for byte.
struct TcpDesc {
    id: Fp6Probe,
    window: u16,
    flags: u8,
    port: PortKind,
    urgent_ptr: u16,
    options: &'static [u8],
}

/// The 13 TCP probe descriptors, in the C's table order (`S1`–`S6`, `TECN`, `T2`–`T7`).
/// Index 6 is `TECN`; the timed loop sends indices 0–5 and the untimed loop 7–12, with
/// `TECN` slotted between the ICMPv6/UDP probes and the untimed TCP probes.
const TCP_DESCS: [TcpDesc; 13] = [
    TcpDesc {
        id: Fp6Probe::S1,
        window: 1,
        flags: 0x02,
        port: PortKind::Open,
        urgent_ptr: 0,
        options: &[
            0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x05, 0xb4, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
        ],
    },
    TcpDesc {
        id: Fp6Probe::S2,
        window: 63,
        flags: 0x02,
        port: PortKind::Open,
        urgent_ptr: 0,
        options: &[
            0x02, 0x04, 0x05, 0x78, 0x03, 0x03, 0x00, 0x04, 0x02, 0x08, 0x0A, 0xff, 0xff, 0xff,
            0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    },
    TcpDesc {
        id: Fp6Probe::S3,
        window: 4,
        flags: 0x02,
        port: PortKind::Open,
        urgent_ptr: 0,
        options: &[
            0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x03,
            0x05, 0x01, 0x02, 0x04, 0x02, 0x80,
        ],
    },
    TcpDesc {
        id: Fp6Probe::S4,
        window: 4,
        flags: 0x02,
        port: PortKind::Open,
        urgent_ptr: 0,
        options: &[
            0x04, 0x02, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03,
            0x0A, 0x00,
        ],
    },
    TcpDesc {
        id: Fp6Probe::S5,
        window: 16,
        flags: 0x02,
        port: PortKind::Open,
        urgent_ptr: 0,
        options: &[
            0x02, 0x04, 0x02, 0x18, 0x04, 0x02, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x03, 0x03, 0x0A, 0x00,
        ],
    },
    TcpDesc {
        id: Fp6Probe::S6,
        window: 512,
        flags: 0x02,
        port: PortKind::Open,
        urgent_ptr: 0,
        options: &[
            0x02, 0x04, 0x01, 0x09, 0x04, 0x02, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00,
        ],
    },
    TcpDesc {
        id: Fp6Probe::Tecn,
        window: 3,
        flags: 0xc2,
        port: PortKind::Open,
        urgent_ptr: 63477,
        options: &[
            0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x01, 0x01,
        ],
    },
    TcpDesc {
        id: Fp6Probe::T2,
        window: 128,
        flags: 0x00,
        port: PortKind::Open,
        urgent_ptr: 0,
        options: &[
            0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
        ],
    },
    TcpDesc {
        id: Fp6Probe::T3,
        window: 256,
        flags: 0x2b,
        port: PortKind::Open,
        urgent_ptr: 0,
        options: &[
            0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
        ],
    },
    TcpDesc {
        id: Fp6Probe::T4,
        window: 1024,
        flags: 0x10,
        port: PortKind::Open,
        urgent_ptr: 0,
        options: &[
            0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
        ],
    },
    TcpDesc {
        id: Fp6Probe::T5,
        window: 31337,
        flags: 0x02,
        port: PortKind::Closed,
        urgent_ptr: 0,
        options: &[
            0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
        ],
    },
    TcpDesc {
        id: Fp6Probe::T6,
        window: 32768,
        flags: 0x10,
        port: PortKind::Closed,
        urgent_ptr: 0,
        options: &[
            0x03, 0x03, 0x0A, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
        ],
    },
    TcpDesc {
        id: Fp6Probe::T7,
        window: 65535,
        flags: 0x29,
        port: PortKind::Closed,
        urgent_ptr: 0,
        options: &[
            0x03, 0x03, 0x0f, 0x01, 0x02, 0x04, 0x01, 0x09, 0x08, 0x0A, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
        ],
    },
];

/// The number of TCP descriptors that are "timed" SEQ probes (`NUM_FP_TIMEDPROBES_IPv6`),
/// sent before the ICMPv6/UDP probes.
const NUM_TIMED_TCP: usize = 6;

/// Everything `build_probe_list()` reads from `FPHost6` member state or `NmapOps`.
#[derive(Debug, Clone)]
pub struct Build6Params {
    /// Source address (the interface address the scan sends from).
    pub src: [u8; 16],
    /// Target address.
    pub dst: [u8; 16],
    /// Open TCP port to aim the `OPEN` probes at, or `None` if the scan found none
    /// (which drops those probes, as the C's `open_port_tcp < 0` does).
    pub open_tcp_port: Option<u16>,
    /// Closed TCP port for the `CLSD` probes, or `None`.
    pub closed_tcp_port: Option<u16>,
    /// Closed UDP port for `U1`.
    pub closed_udp_port: u16,
    /// Base source port for the TCP probes; probe *i* uses `tcp_port_base + i`.
    pub tcp_port_base: u16,
    /// Source port for `U1`.
    pub udp_port_base: u16,
    /// Base sequence number; TCP probe *i* uses `tcp_seq_base + i` (wrapping).
    pub tcp_seq_base: u32,
    /// Per-descriptor ACK values. Slot 6 (`TECN`) is ignored — `TECN` always sends 0.
    pub tcp_acks: [u32; 13],
    /// Hop limit for every probe except `NS`, which always uses 255.
    pub hop_limit: u8,
    /// ICMPv6 echo sequence for `IE1`; `IE2` uses this plus one.
    pub icmp_seq: u16,
    /// Whether the target is on the same link — gates the `NS` probe.
    pub directly_connected: bool,
}

/// A built probe: its identity and the wire bytes from the IPv6 header onward (no
/// Ethernet frame — the driver adds link framing if the interface needs it).
#[derive(Debug, Clone)]
pub struct Probe6 {
    pub id: Fp6Probe,
    pub packet: Vec<u8>,
}

/// Build the IPv6 OS-detection battery for `params`, returning only the probes nmap
/// would send, in nmap's order.
#[must_use]
pub fn build_probes(params: &Build6Params) -> Vec<Probe6> {
    let mut out = Vec::with_capacity(17);

    // Timed TCP probes: S1-S6.
    for i in 0..NUM_TIMED_TCP {
        push_tcp(&mut out, params, i);
    }

    // ICMPv6 probes IE1 and IE2, then NS (on-link only).
    out.push(Probe6 {
        id: Fp6Probe::Ie1,
        packet: build_ie1(params),
    });
    out.push(Probe6 {
        id: Fp6Probe::Ie2,
        packet: build_ie2(params),
    });
    if params.directly_connected {
        out.push(Probe6 {
            id: Fp6Probe::Ns,
            packet: build_ns(params),
        });
    }

    // UDP probe U1.
    out.push(Probe6 {
        id: Fp6Probe::U1,
        packet: build_u1(params),
    });

    // TECN (descriptor index 6), then the untimed TCP probes T2-T7.
    push_tcp(&mut out, params, NUM_TIMED_TCP);
    for i in (NUM_TIMED_TCP + 1)..TCP_DESCS.len() {
        push_tcp(&mut out, params, i);
    }

    out
}

/// Append TCP descriptor `i` if the scan has the port state it targets.
fn push_tcp(out: &mut Vec<Probe6>, params: &Build6Params, i: usize) {
    let Some(desc) = TCP_DESCS.get(i) else { return };
    let dport = match desc.port {
        PortKind::Open => params.open_tcp_port,
        PortKind::Closed => params.closed_tcp_port,
    };
    let Some(dport) = dport else { return };

    // TECN always uses ACK 0; every other probe uses its supplied random ACK.
    let ack = if i == NUM_TIMED_TCP {
        0
    } else {
        params.tcp_acks.get(i).copied().unwrap_or(0)
    };
    let seq = params
        .tcp_seq_base
        .wrapping_add(u32::try_from(i).unwrap_or(0));
    let sport = params
        .tcp_port_base
        .wrapping_add(u16::try_from(i).unwrap_or(0));

    let packet = build_tcp(params, desc, sport, dport, seq, ack);
    out.push(Probe6 {
        id: desc.id,
        packet,
    });
}

/// A 40-byte IPv6 base header. `payload_len` is the length of everything after it, and
/// `next_header` selects the first following header.
fn ipv6_header(
    src: [u8; 16],
    dst: [u8; 16],
    next_header: u8,
    hop_limit: u8,
    payload_len: u16,
) -> [u8; 40] {
    let mut h = [0u8; 40];
    // version 6, then the 20-bit flow label (traffic class stays 0).
    let vtf: u32 = (6u32 << 28) | (FLOW_LABEL & 0x000f_ffff);
    h[0..4].copy_from_slice(&vtf.to_be_bytes());
    h[4..6].copy_from_slice(&payload_len.to_be_bytes());
    h[6] = next_header;
    h[7] = hop_limit;
    h[8..24].copy_from_slice(&src);
    h[24..40].copy_from_slice(&dst);
    h
}

/// Build one TCP-over-IPv6 probe — the port of `make_tcp`.
fn build_tcp(
    params: &Build6Params,
    desc: &TcpDesc,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    // Options are pre-padded to a 4-byte boundary in the table, so the data offset is
    // exact. (Every table entry's length is a multiple of 4.)
    let data_offset = 5u8.saturating_add(u8::try_from(desc.options.len() / 4).unwrap_or(0));
    let tcp_len = 20usize.saturating_add(desc.options.len());

    let mut tcp = Vec::with_capacity(tcp_len);
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(data_offset << 4); // reserved nibble is 0
    tcp.push(desc.flags);
    tcp.extend_from_slice(&desc.window.to_be_bytes());
    tcp.extend_from_slice(&[0, 0]); // checksum placeholder
    tcp.extend_from_slice(&desc.urgent_ptr.to_be_bytes());
    tcp.extend_from_slice(desc.options);

    let sum = ipv6_pseudoheader_cksum(params.src, params.dst, NH_TCP, &tcp);
    write_checksum(&mut tcp, 16, sum);

    let plen = u16::try_from(tcp.len()).unwrap_or(u16::MAX);
    let mut pkt = ipv6_header(params.src, params.dst, NH_TCP, params.hop_limit, plen).to_vec();
    pkt.extend_from_slice(&tcp);
    pkt
}

/// An ICMPv6 echo header (8 bytes): type, code, checksum, id `0xabcd`, sequence.
fn icmp_echo(code: u8, seq: u16) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = ICMPV6_ECHO;
    h[1] = code;
    // h[2..4] checksum placeholder
    h[4..6].copy_from_slice(&0xabcdu16.to_be_bytes());
    h[6..8].copy_from_slice(&seq.to_be_bytes());
    h
}

/// A hop-by-hop or destination-options header carrying nmap's default `reset()` content:
/// a single PadN option of four zero bytes, giving an 8-byte header.
fn ext_options(next_header: u8) -> [u8; 8] {
    // next_header, hdr_ext_len=0, then PadN(type 1, len 4, four zero data bytes).
    [next_header, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]
}

/// A routing header in nmap's `reset()` state: 8 bytes, all fields zero but the next
/// header — type 0, segments-left 0, four reserved zero bytes.
fn routing_header(next_header: u8) -> [u8; 8] {
    [next_header, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}

/// `IE1`: echo (code 9) behind one hop-by-hop header, with a 120-byte zero payload.
fn build_ie1(params: &Build6Params) -> Vec<u8> {
    let hbh = ext_options(NH_ICMPV6);
    let mut icmp = icmp_echo(9, params.icmp_seq).to_vec();
    icmp.extend(std::iter::repeat_n(0u8, IE1_PAYLOAD_LEN));
    let sum = ipv6_pseudoheader_cksum(params.src, params.dst, NH_ICMPV6, &icmp);
    write_checksum(&mut icmp, 2, sum);

    let payload_len = hbh.len().saturating_add(icmp.len());
    let mut pkt = ipv6_header(
        params.src,
        params.dst,
        NH_HOPOPT,
        params.hop_limit,
        u16::try_from(payload_len).unwrap_or(u16::MAX),
    )
    .to_vec();
    pkt.extend_from_slice(&hbh);
    pkt.extend_from_slice(&icmp);
    pkt
}

/// `IE2`: echo (code 0, sequence +1) behind the deliberately mis-ordered chain
/// hop-by-hop → destination-options → routing → hop-by-hop. No payload.
fn build_ie2(params: &Build6Params) -> Vec<u8> {
    let hbh1 = ext_options(NH_DSTOPTS);
    let dstopts = ext_options(NH_ROUTING);
    let routing = routing_header(NH_HOPOPT);
    let hbh2 = ext_options(NH_ICMPV6);
    let mut icmp = icmp_echo(0, params.icmp_seq.wrapping_add(1)).to_vec();
    let sum = ipv6_pseudoheader_cksum(params.src, params.dst, NH_ICMPV6, &icmp);
    write_checksum(&mut icmp, 2, sum);

    let payload_len = hbh1
        .len()
        .saturating_add(dstopts.len())
        .saturating_add(routing.len())
        .saturating_add(hbh2.len())
        .saturating_add(icmp.len());
    let mut pkt = ipv6_header(
        params.src,
        params.dst,
        NH_HOPOPT,
        params.hop_limit,
        u16::try_from(payload_len).unwrap_or(u16::MAX),
    )
    .to_vec();
    pkt.extend_from_slice(&hbh1);
    pkt.extend_from_slice(&dstopts);
    pkt.extend_from_slice(&routing);
    pkt.extend_from_slice(&hbh2);
    pkt.extend_from_slice(&icmp);
    pkt
}

/// `NS`: a Neighbor Solicitation for the target, hop limit 255 (RFC 4861).
fn build_ns(params: &Build6Params) -> Vec<u8> {
    // 24-byte NS: type, code, checksum, 4 reserved bytes, 16-byte target address.
    let mut icmp = Vec::with_capacity(24);
    icmp.push(ICMPV6_NGHBRSOLICIT);
    icmp.push(0x00);
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&[0, 0, 0, 0]); // reserved
    icmp.extend_from_slice(&params.dst); // target address
    let sum = ipv6_pseudoheader_cksum(params.src, params.dst, NH_ICMPV6, &icmp);
    write_checksum(&mut icmp, 2, sum);

    let mut pkt = ipv6_header(
        params.src,
        params.dst,
        NH_ICMPV6,
        255,
        u16::try_from(icmp.len()).unwrap_or(u16::MAX),
    )
    .to_vec();
    pkt.extend_from_slice(&icmp);
    pkt
}

/// `U1`: UDP with 300 `'C'` bytes to the closed port.
fn build_u1(params: &Build6Params) -> Vec<u8> {
    let total = 8usize.saturating_add(UDP_PAYLOAD_LEN);
    let mut udp = Vec::with_capacity(total);
    udp.extend_from_slice(&params.udp_port_base.to_be_bytes());
    udp.extend_from_slice(&params.closed_udp_port.to_be_bytes());
    udp.extend_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend(std::iter::repeat_n(UDP_PAYLOAD_BYTE, UDP_PAYLOAD_LEN));

    let sum = ipv6_pseudoheader_cksum(params.src, params.dst, NH_UDP, &udp);
    write_checksum(&mut udp, 6, sum);

    let mut pkt = ipv6_header(
        params.src,
        params.dst,
        NH_UDP,
        params.hop_limit,
        u16::try_from(udp.len()).unwrap_or(u16::MAX),
    )
    .to_vec();
    pkt.extend_from_slice(&udp);
    pkt
}

/// Write a big-endian checksum into `buf` at `offset`, if there is room.
fn write_checksum(buf: &mut [u8], offset: usize, sum: u16) {
    let bytes = sum.to_be_bytes();
    if let Some(slot) = buf.get_mut(offset..offset.saturating_add(2)) {
        slot.copy_from_slice(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::ipv6_pseudoheader_cksum;

    fn base_params() -> Build6Params {
        Build6Params {
            src: "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            dst: "2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            open_tcp_port: Some(22),
            closed_tcp_port: Some(1),
            closed_udp_port: 42,
            tcp_port_base: 33000,
            udp_port_base: 34000,
            tcp_seq_base: 0x1234_5678,
            tcp_acks: [
                101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
            ],
            hop_limit: 64,
            icmp_seq: 0x1234,
            directly_connected: true,
        }
    }

    fn ids(probes: &[Probe6]) -> Vec<Fp6Probe> {
        probes.iter().map(|p| p.id).collect()
    }

    #[test]
    fn full_battery_is_seventeen_probes_in_nmap_order() {
        let probes = build_probes(&base_params());
        use Fp6Probe::*;
        assert_eq!(
            ids(&probes),
            vec![S1, S2, S3, S4, S5, S6, Ie1, Ie2, Ns, U1, Tecn, T2, T3, T4, T5, T6, T7]
        );
    }

    #[test]
    fn a_missing_open_port_drops_every_open_probe_but_keeps_the_rest() {
        let mut p = base_params();
        p.open_tcp_port = None;
        let got = ids(&build_probes(&p));
        // S1-S6, TECN, T2-T4 target the open port; T5-T7 the closed port; IE/NS/U1 neither.
        use Fp6Probe::*;
        assert_eq!(got, vec![Ie1, Ie2, Ns, U1, T5, T6, T7]);
    }

    #[test]
    fn a_missing_closed_port_drops_only_t5_t6_t7() {
        let mut p = base_params();
        p.closed_tcp_port = None;
        let got = ids(&build_probes(&p));
        use Fp6Probe::*;
        assert_eq!(
            got,
            vec![S1, S2, S3, S4, S5, S6, Ie1, Ie2, Ns, U1, Tecn, T2, T3, T4]
        );
    }

    #[test]
    fn ns_is_sent_only_when_directly_connected() {
        let mut p = base_params();
        p.directly_connected = false;
        assert!(!ids(&build_probes(&p)).contains(&Fp6Probe::Ns));
        p.directly_connected = true;
        assert!(ids(&build_probes(&p)).contains(&Fp6Probe::Ns));
    }

    /// Every probe starts with a well-formed 40-byte IPv6 header whose payload-length
    /// field equals the actual remainder, and carries the fixed flow label.
    #[test]
    fn every_probe_has_a_consistent_ipv6_header() {
        for probe in build_probes(&base_params()) {
            let pkt = &probe.packet;
            assert!(pkt.len() >= 40, "{:?} too short", probe.id);
            assert_eq!(pkt[0] >> 4, 6, "{:?} not version 6", probe.id);
            let flow = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]) & 0x000f_ffff;
            assert_eq!(flow, FLOW_LABEL, "{:?} wrong flow label", probe.id);
            let plen = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            assert_eq!(plen, pkt.len() - 40, "{:?} payload length off", probe.id);
        }
    }

    #[test]
    fn ns_uses_hop_limit_255_and_others_use_the_scan_value() {
        for probe in build_probes(&base_params()) {
            let hlim = probe.packet[7];
            if probe.id == Fp6Probe::Ns {
                assert_eq!(hlim, 255);
            } else {
                assert_eq!(hlim, 64, "{:?}", probe.id);
            }
        }
    }

    /// The transport checksum in each probe must verify: recomputing over the L4 span
    /// with the checksum field zeroed reproduces the stored value.
    // The offsets come from packets this same module just built, so the indexing and the
    // small additions are all in range by construction.
    #[allow(clippy::arithmetic_side_effects)]
    #[test]
    fn transport_checksums_verify() {
        let p = base_params();
        for probe in build_probes(&p) {
            let pkt = &probe.packet;
            // Locate the L4 span: skip the 40-byte IPv6 header and any extension headers.
            let (l4_off, nxt) = skip_ext_headers(pkt);
            let l4 = &pkt[l4_off..];
            let (sum_off, proto) = match nxt {
                NH_TCP => (16usize, NH_TCP),
                NH_UDP => (6usize, NH_UDP),
                NH_ICMPV6 => (2usize, NH_ICMPV6),
                other => panic!("{:?} unexpected upper protocol {other}", probe.id),
            };
            let mut span = l4.to_vec();
            span[sum_off] = 0;
            span[sum_off + 1] = 0;
            let want = ipv6_pseudoheader_cksum(p.src, p.dst, proto, &span);
            let got = u16::from_be_bytes([l4[sum_off], l4[sum_off + 1]]);
            assert_eq!(got, want, "{:?} checksum does not verify", probe.id);
        }
    }

    /// Walk past the extension-header chain (hop-by-hop, dstopts, routing) that IE1/IE2
    /// place before the ICMPv6 header. Returns the offset of the upper-layer header and
    /// its protocol number.
    // Walks a packet this module built, whose extension-header lengths and chain are
    // known-good, so the offset additions cannot overflow or run past the buffer.
    #[allow(clippy::arithmetic_side_effects)]
    fn skip_ext_headers(pkt: &[u8]) -> (usize, u8) {
        let mut nxt = pkt[6];
        let mut off = 40usize;
        while matches!(nxt, NH_HOPOPT | NH_DSTOPTS | NH_ROUTING) {
            let ext_len = (usize::from(pkt[off + 1]) + 1) * 8;
            nxt = pkt[off];
            off += ext_len;
        }
        (off, nxt)
    }

    // Fixed offsets into packets this module built.
    #[allow(clippy::arithmetic_side_effects)]
    #[test]
    fn tecn_carries_ack_zero_and_others_carry_their_slot() {
        let p = base_params();
        for probe in build_probes(&p) {
            let (l4_off, nxt) = skip_ext_headers(&probe.packet);
            if nxt != NH_TCP {
                continue;
            }
            let ack = u32::from_be_bytes([
                probe.packet[l4_off + 8],
                probe.packet[l4_off + 9],
                probe.packet[l4_off + 10],
                probe.packet[l4_off + 11],
            ]);
            if probe.id == Fp6Probe::Tecn {
                assert_eq!(ack, 0, "TECN must carry ACK 0");
            } else {
                assert_ne!(ack, 0, "{:?} should carry its random ACK", probe.id);
            }
        }
    }

    #[test]
    fn u1_carries_300_c_bytes() {
        let probes = build_probes(&base_params());
        let u1 = probes.iter().find(|p| p.id == Fp6Probe::U1).unwrap();
        // 40 IPv6 + 8 UDP + 300 payload.
        assert_eq!(u1.packet.len(), 348);
        assert!(u1.packet[48..].iter().all(|&b| b == 0x43));
    }
}
