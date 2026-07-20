// cargo-fuzz target for `nmap_core::build`. Constructing a packet from
// attacker-influenced parameters (payload length/content, option bytes, ICMP
// type/code) must be TOTAL: never panic, never silently truncate. When a build
// succeeds, the packet must re-parse to a well-formed IPv4 layer and its checksums
// must validate (receiver-side sum == 0) — the send path can only emit correct wire
// bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::build::{build_icmp_raw, build_tcp_raw, build_udp_raw, Ipv4Spec};
use nmap_core::checksum::in_cksum;
use nmap_core::packet_parser::{parse_packet, Header};

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

    let built = match selector % 3 {
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
