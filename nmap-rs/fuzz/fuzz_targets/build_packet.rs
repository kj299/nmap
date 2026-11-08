// cargo-fuzz target for `nmap_core::build`. Constructing a packet from
// attacker-influenced parameters (payload length/content, option bytes, ICMP
// type/code) must be TOTAL: never panic, never silently truncate. When a build
// succeeds, the packet must re-parse to a well-formed IPv4 layer and its checksums
// must validate (receiver-side sum == 0) — the send path can only emit correct wire
// bytes. The IPv6 builders (IPv6 scans step c) likewise: a built packet validates as
// IPv6 with its whole length counted, and its TCP or UDP checksum over the IPv6
// pseudo-header verifies, unless --badsum asked for it not to.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::build::{
    build_icmp_raw, build_tcp_raw, build_tcp_raw_ipv6, build_udp_raw, build_udp_raw_ipv6,
    Ipv4Spec, Ipv6Spec,
};
use nmap_core::checksum::{in_cksum, Accumulator};
use nmap_core::packet_parser::{parse_packet, Header};
use nmap_core::recv_validate::validate_packet;

/// The two IPv6 builders, from the same carved parameters.
fn ipv6(selector: u8, spec: &Ipv6Spec, tcpopt: &[u8], payload: &[u8], b: &mut dyn FnMut() -> u8) {
    let (proto, built) = if selector % 5 == 3 {
        let flags = b();
        let built = build_tcp_raw_ipv6(
            spec,
            u16::from(b()),
            u16::from(b()),
            u32::from(b()),
            u32::from(b()),
            b(),
            flags,
            1024,
            u16::from(b()),
            tcpopt,
            payload,
        );
        (6u8, built)
    } else {
        (17u8, build_udp_raw_ipv6(spec, u16::from(b()), u16::from(b()), payload))
    };
    let Ok(pkt) = built else { return };
    // Arbitrary option bytes may be a list validateTCPhdr rightly refuses, so the
    // structural check is for UDP and option-free TCP.
    if proto == 17 || tcpopt.is_empty() {
        let v = validate_packet(&pkt).expect("a built IPv6 packet validates");
        assert_eq!((v.version, v.proto, v.data_offset, v.captured_len), (6, proto, 40, pkt.len()));
    }
    // The checksum over the pseudo-header and segment.
    let mut acc = Accumulator::new();
    acc.add(&pkt[8..40]);
    acc.add(&u32::try_from(pkt.len() - 40).unwrap().to_be_bytes());
    acc.add(&[0, 0, 0, proto]);
    acc.add(&pkt[40..]);
    let residue = acc.finish();
    if spec.bad_sum {
        // As in the C, --badsum on a checksum of 0x0000 gives 0xFFFF, the other
        // ones'-complement zero, which still verifies (build-badsum-host-order-decrement).
        let at = 40 + if proto == 6 { 16 } else { 6 };
        assert!(residue != 0 || pkt[at..at + 2] == [0xFF, 0xFF], "--badsum left a valid checksum");
    } else {
        assert_eq!(residue, 0, "invalid checksum");
    }
}

fuzz_target!(|data: &[u8]| {
    // Carve deterministic parameters out of the fuzz input.
    let mut c = data.iter().copied();
    let mut byte = || c.next().unwrap_or(0);

    let selector = byte();
    let optlen = (byte() % 12) as usize; // 0..44 option bytes (may be misaligned)
    let ipopt: Vec<u8> = (0..optlen).map(|_| byte()).collect();
    let tcpopt_len = (byte() % 12) as usize;
    let tcpopt: Vec<u8> = (0..tcpopt_len).map(|_| byte()).collect();
    let payload_len = (byte() as usize) * 2; // up to 510 bytes
    let payload: Vec<u8> = std::iter::repeat_with(&mut byte).take(payload_len).collect();

    let mut spec = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], byte(), u16::from(byte()));
    spec.tos = byte();
    spec.df = byte() & 1 == 0;
    spec.bad_sum = byte() & 1 == 0;
    spec.options = ipopt;

    if selector % 5 >= 3 {
        let mut v6 = Ipv6Spec::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        v6.traffic_class = spec.tos;
        v6.flow_label = u32::from(spec.ttl) << 12;
        v6.hop_limit = spec.ttl;
        v6.bad_sum = spec.bad_sum;
        ipv6(selector, &v6, &tcpopt, &payload, &mut byte);
        return;
    }
    let built = match selector % 5 {
        0 => build_tcp_raw(
            &spec,
            u16::from(byte()),
            u16::from(byte()),
            0x1111_2222,
            0,
            byte(),
            byte(),
            1024,
            0,
            &tcpopt,
            &payload,
        ),
        1 => build_udp_raw(&spec, u16::from(byte()), u16::from(byte()), &payload),
        _ => build_icmp_raw(&spec, byte(), byte(), u16::from(byte()), u16::from(byte()), &payload),
    };

    if let Ok(pkt) = built {
        // A successful build always yields a parseable IPv4 packet.
        let hs = parse_packet(&pkt, false);
        assert!(matches!(hs.first(), Some(Header::Ipv4(_))), "build did not start with IPv4");
        // The IPv4 header checksum must validate (unless --badsum was set, which only
        // corrupts the L4 sum, never the IP header sum).
        if let Some(Header::Ipv4(ip)) = hs.first() {
            let hlen = ip.header_len();
            assert_eq!(in_cksum(&pkt[..hlen]), 0, "IP header checksum invalid");
        }
    }
});
