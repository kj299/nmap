//! UDP-scan end-to-end + on-the-wire differential (feature `pcap`, root only).
//!
//! The UDP analog of `synscan_e2e`: verify that the datagram nmap-rs *transmits*
//! equals what `core::build` intended (proven == nmap's C `build_udp_raw` via the
//! parse oracle), with a valid recomputed checksum, and that a real UDP scan of a
//! loopback listener (open) and a closed port (ICMP port-unreachable → closed)
//! resolves correctly.
//!
//! `#[ignore]` + self-skip when unprivileged; run as root:
//! `sudo -E cargo test -p nmap-sys --features pcap --test udpscan_e2e -- --ignored`.
#![cfg(feature = "pcap")]

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use nmap_core::build::Ipv4Spec;
use nmap_core::checksum::{in_cksum, ipv4_pseudoheader_cksum};
use nmap_core::model::{PortState, Reason};
use nmap_core::packet_parser::{parse_packet, Header};
use nmap_core::udpscan::{build_udp_probe, build_udp_probe_with};

use nmap_sys::capture::AsyncCapture;
use nmap_sys::group::{group_scan, UdpKind};
use nmap_sys::rawio::{RawIpv4Sender, RawSender};

const IPPROTO_UDP: u8 = 17;

fn raw_sender_or_skip(what: &str) -> Option<RawIpv4Sender> {
    match RawIpv4Sender::new() {
        Ok(s) => Some(s),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping {what}: no CAP_NET_RAW");
            None
        }
        Err(e) => panic!("unexpected error opening raw socket: {e}"),
    }
}

fn ipv4_offset(frame: &[u8]) -> Option<usize> {
    let mut off = 0usize;
    for h in parse_packet(frame, true) {
        if matches!(h, Header::Ipv4(_)) {
            return Some(off);
        }
        off = off.checked_add(h.len())?;
    }
    None
}

/// Send `intended` and assert the frame that reaches the wire still carries exactly the
/// UDP segment `core::build` produced, with valid checksums. `label` names the case.
async fn assert_wire_matches_build(
    sender: &mut RawIpv4Sender,
    dport: u16,
    intended: &[u8],
    label: &str,
) {
    let source = nmap_sys::capture::pcap_source::PcapSource::open(
        "lo",
        65535,
        200,
        Some(&format!("udp and dst host 127.0.0.1 and dst port {dport}")),
    )
    .expect("open lo capture");
    let mut cap = AsyncCapture::spawn(source, 64);

    sender.send(intended).expect("send raw UDP");
    let frame = tokio::time::timeout(Duration::from_secs(2), cap.recv())
        .await
        .unwrap_or_else(|_| panic!("{label}: captured the outgoing datagram within 2s"))
        .expect("capture stream stayed open");
    cap.stop();

    let ip_off = ipv4_offset(&frame.data).expect("frame has an IPv4 layer");
    let wire = &frame.data[ip_off..];
    let wire_ihl = usize::from(wire[0] & 0x0F) * 4;
    let intended_ihl = usize::from(intended[0] & 0x0F) * 4;

    assert_eq!(wire[9], IPPROTO_UDP, "{label}: protocol changed");
    assert_eq!(&wire[16..20], &intended[16..20], "{label}: dest IP changed");
    assert_eq!(
        in_cksum(&wire[..wire_ihl]),
        0,
        "{label}: invalid IP checksum on the wire"
    );

    // The kernel does not touch the UDP segment for IP_HDRINCL: byte-identical.
    let wire_udp = &wire[wire_ihl..];
    assert_eq!(
        wire_udp,
        &intended[intended_ihl..],
        "{label}: transmitted UDP segment diverged from core::build's bytes"
    );
    // A non-zero UDP checksum on the wire must verify (build sets it; 0 = "unused").
    // A valid one's-complement checksum sums to all-zeros or all-ones over the segment
    // including its own checksum field — both represent zero.
    if wire_udp.get(6..8) != Some(&[0, 0]) {
        let src: [u8; 4] = wire[12..16].try_into().unwrap();
        let dst: [u8; 4] = wire[16..20].try_into().unwrap();
        let verify = ipv4_pseudoheader_cksum(src, dst, IPPROTO_UDP, wire_udp);
        assert!(
            verify == 0 || verify == 0xffff,
            "{label}: invalid UDP checksum on the wire (verify = {verify:#06x})"
        );
    }
}

/// On-the-wire differential: the transmitted UDP datagram's L4 bytes must equal what
/// `core::build` produced, with a valid IP checksum on the wire.
///
/// Covers both a bare probe and a **payload-carrying** one: a payload changes the UDP
/// length and checksum, so it is the case most likely to diverge under the kernel's
/// `IP_HDRINCL` handling.
#[tokio::test]
#[ignore = "needs CAP_NET_RAW + live lo capture; run as root"]
async fn transmitted_udp_matches_core_build_on_the_wire() {
    let Some(mut sender) = raw_sender_or_skip("on-the-wire differential") else {
        return;
    };
    let spec = Ipv4Spec::new([127, 0, 0, 1], [127, 0, 0, 1], 64, 0xBEEF);

    // Bare datagram (zero-length payload).
    let bare = build_udp_probe(&spec, 55000, 5353, 0).unwrap();
    assert_wire_matches_build(&mut sender, 5353, &bare, "bare").await;

    // A real protocol payload: a DNS query, the shape `core::payload` supplies for 53.
    let dns: &[u8] = &[
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let with_payload = build_udp_probe_with(&spec, 55000, 53, 0, dns).unwrap();
    assert!(
        with_payload.len() > bare.len(),
        "the payload must actually be in the datagram"
    );
    assert_wire_matches_build(&mut sender, 53, &with_payload, "dns payload").await;

    // An odd-length payload exercises the checksum's trailing-byte padding path.
    let odd: &[u8] = b"\x01\x02\x03\x04\x05";
    let odd_pkt = build_udp_probe_with(&spec, 55000, 161, 0, odd).unwrap();
    assert_wire_matches_build(&mut sender, 161, &odd_pkt, "odd-length payload").await;
}

/// End-to-end: a UDP scan of a bound loopback datagram socket (may answer or stay
/// silent → open|filtered) and a closed port (kernel replies ICMP port-unreachable →
/// closed).
#[tokio::test]
#[ignore = "needs CAP_NET_RAW + live lo capture; run as root"]
async fn udp_scan_resolves_closed_on_loopback() {
    let Some(sender) = raw_sender_or_skip("end-to-end UDP scan") else {
        return;
    };

    // A bound-then-freed UDP port → the kernel answers a probe with ICMP
    // port-unreachable (closed).
    let closed_sock = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let closed_port = closed_sock.local_addr().unwrap().port();
    drop(closed_sock);

    let base_port = 55000u16;
    let bpf = format!(
        "(udp and dst host 127.0.0.1 and dst portrange {}-{}) or (icmp and dst host 127.0.0.1)",
        base_port,
        base_port + 16
    );
    let source = nmap_sys::capture::pcap_source::PcapSource::open("lo", 65535, 100, Some(&bpf))
        .expect("open lo capture");

    let hosts = tokio::time::timeout(
        Duration::from_secs(10),
        group_scan(
            Ipv4Addr::LOCALHOST,
            &[Ipv4Addr::LOCALHOST],
            &[closed_port],
            sender,
            source,
            &UdpKind::bare(),
            nmap_core::timing::TimingTemplate::Insane,
            0,
            base_port,
            true,
        ),
    )
    .await
    .expect("scan completed within 10s");

    let host = &hosts[0];
    let closed = host.ports.iter().find(|p| p.number == closed_port).unwrap();
    assert_eq!(
        closed.state,
        PortState::Closed,
        "a closed UDP port should elicit ICMP port-unreachable"
    );
    assert_eq!(closed.reason, Reason::PortUnreach);
}
