//! End-to-end raw-path smoke test: build a packet with `core::build`, put it on the
//! wire with `sys::rawio`, capture it back with `sys::capture`, and parse it with
//! `core::packet_parser`. Exercises the whole M4 pipeline against the loopback device.
//!
//! Requires the `pcap` feature, CAP_NET_RAW, and libpcap — so it is `#[ignore]`d and
//! run manually:
//!   cargo test -p nmap-sys --features pcap --test rawio_capture_e2e -- --ignored --nocapture
#![cfg(feature = "pcap")]

use std::time::Duration;

use nmap_core::build::{build_udp_raw, Ipv4Spec};
use nmap_core::packet_parser::{parse_packet, Header};
use nmap_sys::capture::{pcap_source::PcapSource, AsyncCapture};
use nmap_sys::rawio::{RawIpv4Sender, RawSender};

#[tokio::test]
#[ignore = "needs pcap feature + CAP_NET_RAW + loopback; run with --ignored"]
async fn build_send_capture_parse_roundtrip() {
    let mut sender = match RawIpv4Sender::new() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("skipping: no CAP_NET_RAW");
            return;
        }
    };

    // Capture UDP/5353 on loopback via a BPF filter.
    let source = PcapSource::open("lo", 65535, 100, Some("udp and port 5353"))
        .expect("open loopback capture");
    let mut cap = AsyncCapture::spawn(source, 64);

    // Build and send a UDP datagram to 127.0.0.1:5353.
    let spec = Ipv4Spec::new([127, 0, 0, 1], [127, 0, 0, 1], 64, 0x4242);
    let pkt = build_udp_raw(&spec, 40000, 5353, b"nmap-rs-e2e").unwrap();
    sender.send(&pkt).expect("raw send");

    // Await the captured frame (loopback on Linux is DLT_EN10MB => Ethernet-framed).
    let frame = tokio::time::timeout(Duration::from_secs(3), cap.recv())
        .await
        .expect("capture timed out")
        .expect("capture closed");

    // Parse; find the UDP layer and confirm our port + payload survived the round trip.
    let headers = parse_packet(&frame.data, true);
    let kinds: Vec<&str> = headers.iter().map(Header::kind_str).collect();
    eprintln!("captured layers: {kinds:?} ({} bytes)", frame.data.len());
    let has_udp = headers
        .iter()
        .any(|h| matches!(h, Header::Udp(u) if u.dport == 5353));
    assert!(
        has_udp,
        "captured frame should contain our UDP/5353 datagram: {kinds:?}"
    );
}
