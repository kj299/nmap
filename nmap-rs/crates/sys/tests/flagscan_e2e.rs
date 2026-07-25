//! Flag-scan end-to-end + on-the-wire differential (feature `pcap`, root only).
//!
//! Verifies the transmitted flag probe is byte-identical to what `core::build`
//! produced (with a valid IP checksum on the wire), and that real ACK/FIN scans of a
//! closed loopback port resolve correctly (RST → unfiltered for ACK, closed for FIN).
//!
//! `#[ignore]` + self-skip when unprivileged; run as root:
//! `sudo -E cargo test -p nmap-sys --features pcap --test flagscan_e2e -- --ignored`.
#![cfg(feature = "pcap")]

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use nmap_core::build::Ipv4Spec;
use nmap_core::checksum::in_cksum;
use nmap_core::classify::ScanType;
use nmap_core::flagscan::{build_flag_probe, flags_for};
use nmap_core::model::{PortState, Reason};
use nmap_core::packet_parser::{parse_packet, Header};

use nmap_sys::capture::AsyncCapture;
use nmap_sys::group::{group_scan, FlagKind};
use nmap_sys::rawio::{RawIpv4Sender, RawSender};

const IPPROTO_TCP: u8 = 6;

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

/// On-the-wire differential for an ACK probe: transmitted TCP segment byte-identical to
/// `core::build`'s output, valid IP checksum on the wire.
#[tokio::test]
#[ignore = "needs CAP_NET_RAW + live lo capture; run as root"]
async fn transmitted_flag_probe_matches_core_build_on_the_wire() {
    let Some(mut sender) = raw_sender_or_skip("on-the-wire differential") else {
        return;
    };

    let dport = 9;
    let flags = flags_for(ScanType::Ack).unwrap();
    let spec = Ipv4Spec::new([127, 0, 0, 1], [127, 0, 0, 1], 64, 0xBEEF);
    let intended = build_flag_probe(&spec, 55000, dport, 0, 0x1234, flags).unwrap();

    let source = nmap_sys::capture::pcap_source::PcapSource::open(
        "lo",
        65535,
        200,
        Some(&format!("tcp and dst host 127.0.0.1 and dst port {dport}")),
    )
    .expect("open lo capture");
    let mut cap = AsyncCapture::spawn(source, 64);

    sender.send(&intended).expect("send raw flag probe");
    let frame = tokio::time::timeout(Duration::from_secs(2), cap.recv())
        .await
        .expect("captured the outgoing probe within 2s")
        .expect("capture stream stayed open");
    cap.stop();

    let ip_off = ipv4_offset(&frame.data).expect("frame has an IPv4 layer");
    let wire = &frame.data[ip_off..];
    let wire_ihl = usize::from(wire[0] & 0x0F) * 4;
    let intended_ihl = usize::from(intended[0] & 0x0F) * 4;

    assert_eq!(wire[9], IPPROTO_TCP, "protocol changed");
    assert_eq!(&wire[16..20], &intended[16..20], "dest IP changed");
    assert_eq!(
        in_cksum(&wire[..wire_ihl]),
        0,
        "invalid IP checksum on the wire"
    );
    assert_eq!(
        &wire[wire_ihl..],
        &intended[intended_ihl..],
        "transmitted TCP segment diverged from core::build's bytes"
    );
    // The probe carries the requested flags and no options.
    assert_eq!(wire[wire_ihl + 13], flags, "flags changed on the wire");
}

/// End-to-end: ACK and FIN scans of a closed loopback port both elicit a RST → ACK
/// reports `unfiltered`, FIN reports `closed`.
#[tokio::test]
#[ignore = "needs CAP_NET_RAW + live lo capture; run as root"]
async fn ack_and_fin_scans_resolve_a_closed_port() {
    for (scan, expect) in [
        (ScanType::Ack, PortState::Unfiltered),
        (ScanType::Fin, PortState::Closed),
    ] {
        let Some(sender) = raw_sender_or_skip("end-to-end flag scan") else {
            return;
        };
        let closed = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);

        let base_port = 55000u16;
        let bpf = format!(
            "tcp and dst host 127.0.0.1 and dst portrange {}-{}",
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
                &FlagKind {
                    scan,
                    seqmask: 0x2468_ACE0,
                },
                nmap_core::timing::TimingTemplate::Insane,
                0,
                base_port,
                true,
            ),
        )
        .await
        .expect("scan completed within 10s");

        let p = hosts[0]
            .ports
            .iter()
            .find(|p| p.number == closed_port)
            .unwrap();
        assert_eq!(p.state, expect, "{scan:?} on a closed port");
        assert_eq!(p.reason, Reason::Reset);
    }
}
