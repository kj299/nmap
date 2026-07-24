//! SYN-scan end-to-end + **on-the-wire differential** (feature `pcap`, root only).
//!
//! These are the two gates M4's per-module suite could not provide, and the target the
//! M4 retrospective named: the privileged send/capture path had no check that the
//! frame nmap-rs *actually transmits* — after the kernel's `IP_HDRINCL` fixups — is the
//! frame it intended. `core::build`'s output is already proven byte-equal to nmap's C
//! `build_tcp_raw` (via `core/tests/build_differential.rs` against the real
//! `PacketParser` oracle). So verifying the **captured wire frame equals
//! `core::build`'s bytes, modulo the kernel-owned IP fields, with valid recomputed
//! checksums** transitively proves the sys send path puts C-equivalent bytes on the
//! wire — closing the gap without a second C oracle.
//!
//! Both tests need `CAP_NET_RAW` (raw socket) + a live `lo` capture, so they are
//! `#[ignore]` and self-skip when unprivileged; CI (unprivileged) stays green. Run for
//! real as root: `sudo -E cargo test -p nmap-sys --features pcap --test synscan_e2e -- --ignored`.
#![cfg(feature = "pcap")]

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use nmap_core::build::Ipv4Spec;
use nmap_core::checksum::{in_cksum, ipv4_pseudoheader_cksum};
use nmap_core::model::{HostState, PortState, Reason};
use nmap_core::packet_parser::{parse_packet, Header};
use nmap_core::synscan::build_syn_probe;

use nmap_sys::capture::AsyncCapture;
use nmap_sys::rawio::{RawIpv4Sender, RawSender};
use nmap_sys::synscan::{syn_scan, SynScanConfig};

const IPPROTO_TCP: u8 = 6;

/// Try to open a raw sender; return `None` (skip the test) when unprivileged.
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

/// Locate the IPv4 header offset within a captured (link-framed) frame.
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

/// On-the-wire differential: what nmap-rs transmits must equal what `core::build`
/// intended (which equals nmap's C), modulo the kernel-owned IP checksum, with valid
/// recomputed checksums on the wire.
#[tokio::test]
#[ignore = "needs CAP_NET_RAW + live lo capture; run as root"]
async fn transmitted_syn_matches_core_build_on_the_wire() {
    let Some(mut sender) = raw_sender_or_skip("on-the-wire differential") else {
        return;
    };

    // A concrete SYN probe. Non-zero IP id so the kernel preserves it under IP_HDRINCL.
    let dport = 9; // discard — need not be open; we only inspect our own egress
    let spec = Ipv4Spec::new([127, 0, 0, 1], [127, 0, 0, 1], 64, 0xBEEF);
    let intended = build_syn_probe(&spec, 55000, dport, 0, 0x1357_9BDF).unwrap();

    // Capture only our outgoing probe (destination = the scanned port).
    let source = nmap_sys::capture::pcap_source::PcapSource::open(
        "lo",
        65535,
        200,
        Some(&format!("tcp and dst host 127.0.0.1 and dst port {dport}")),
    )
    .expect("open lo capture");
    let mut cap = AsyncCapture::spawn(source, 64);

    sender.send(&intended).expect("send raw SYN");

    let frame = tokio::time::timeout(Duration::from_secs(2), cap.recv())
        .await
        .expect("captured the outgoing SYN within 2s")
        .expect("capture stream stayed open");
    cap.stop();

    let ip_off = ipv4_offset(&frame.data).expect("frame has an IPv4 layer");
    let wire = &frame.data[ip_off..];
    let intended_ihl = usize::from(intended[0] & 0x0F) * 4;
    let wire_ihl = usize::from(wire[0] & 0x0F) * 4;
    assert_eq!(
        wire_ihl, intended_ihl,
        "IP header length changed on the wire"
    );

    // Kernel-owned IP fields aside, the header must match what we built.
    assert_eq!(&wire[12..16], &intended[12..16], "source IP changed");
    assert_eq!(&wire[16..20], &intended[16..20], "dest IP changed");
    assert_eq!(wire[8], intended[8], "TTL changed");
    assert_eq!(wire[9], IPPROTO_TCP, "protocol changed");
    assert_eq!(&wire[2..4], &intended[2..4], "IP total-length changed");
    assert_eq!(
        &wire[4..6],
        &intended[4..6],
        "IP id not preserved under IP_HDRINCL"
    );

    // The IP checksum on the wire must be valid (kernel recomputes it).
    assert_eq!(
        in_cksum(&wire[..wire_ihl]),
        0,
        "invalid IP checksum on the wire"
    );

    // The kernel does NOT touch the TCP segment for IP_HDRINCL: the exact bytes
    // core::build produced (proven == nmap's C build_tcp_raw) must reach the wire.
    let wire_tcp = &wire[wire_ihl..];
    let intended_tcp = &intended[intended_ihl..];
    assert_eq!(
        wire_tcp, intended_tcp,
        "transmitted TCP segment diverged from core::build's bytes"
    );

    // And that segment's checksum must be valid over the IPv4 pseudo-header.
    let src: [u8; 4] = wire[12..16].try_into().unwrap();
    let dst: [u8; 4] = wire[16..20].try_into().unwrap();
    assert_eq!(
        ipv4_pseudoheader_cksum(src, dst, IPPROTO_TCP, wire_tcp),
        0,
        "invalid TCP checksum on the wire"
    );
}

/// End-to-end functional proof: a real SYN scan of a loopback listener (open) and a
/// bound-then-freed port (closed), asserting the resolved `PortState`.
#[tokio::test]
#[ignore = "needs CAP_NET_RAW + live lo capture; run as root"]
async fn syn_scan_resolves_open_and_closed_on_loopback() {
    let Some(sender) = raw_sender_or_skip("end-to-end SYN scan") else {
        return;
    };

    // A live listener → the kernel answers our SYN with SYN/ACK (open).
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let open_port = listener.local_addr().unwrap().port();
    // A bound-then-freed port → the kernel answers with RST (closed).
    let closed = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);

    // Encoded source-port range well clear of the scanned ports; the BPF filter scopes
    // capture to it so our own outgoing SYNs are excluded (the self-probe guard).
    let base_port = 55000u16;
    let config = SynScanConfig {
        ports: vec![open_port, closed_port],
        template: nmap_core::timing::TimingTemplate::Insane,
        max_parallelism: 0,
        eth_included: true,
        base_port,
        seqmask: 0x2468_ACE0,
    };
    let bpf = format!(
        "tcp and dst host 127.0.0.1 and dst portrange {}-{}",
        base_port,
        base_port + 16
    );
    let source = nmap_sys::capture::pcap_source::PcapSource::open("lo", 65535, 100, Some(&bpf))
        .expect("open lo capture");

    let host = tokio::time::timeout(
        Duration::from_secs(10),
        syn_scan(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            sender,
            source,
            &config,
        ),
    )
    .await
    .expect("scan completed within 10s");

    assert_eq!(host.state, HostState::Up);
    let open = host.ports.iter().find(|p| p.number == open_port).unwrap();
    assert_eq!(open.state, PortState::Open, "listener port should be Open");
    assert_eq!(open.reason, Reason::ConnAccept);
    let closed = host.ports.iter().find(|p| p.number == closed_port).unwrap();
    assert_eq!(
        closed.state,
        PortState::Closed,
        "freed port should be Closed"
    );
    assert_eq!(closed.reason, Reason::Reset);
}
