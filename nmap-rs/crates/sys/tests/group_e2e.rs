//! Multi-host group scan end-to-end (feature `pcap`, root only).
//!
//! Scans two loopback hosts (127.0.0.1 and 127.0.0.2), each with its own open port,
//! through the shared group engine and confirms replies are demultiplexed to the right
//! host by source IP.
//!
//! `#[ignore]` + self-skip when unprivileged; run as root:
//! `sudo -E cargo test -p nmap-sys --features pcap --test group_e2e -- --ignored`.
#![cfg(feature = "pcap")]

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use nmap_core::model::{HostState, PortState};
use nmap_core::timing::TimingTemplate;

use nmap_sys::group::{group_scan, SynKind};
use nmap_sys::rawio::RawIpv4Sender;

fn raw_sender_or_skip() -> Option<RawIpv4Sender> {
    match RawIpv4Sender::new() {
        Ok(s) => Some(s),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping group e2e: no CAP_NET_RAW");
            None
        }
        Err(e) => panic!("unexpected error opening raw socket: {e}"),
    }
}

#[tokio::test]
#[ignore = "needs CAP_NET_RAW + live lo capture; run as root"]
async fn two_loopback_hosts_scanned_as_one_group() {
    let Some(sender) = raw_sender_or_skip() else {
        return;
    };

    // A listener on each loopback host → the kernel answers our SYN with SYN/ACK.
    let l1 = tokio::net::TcpListener::bind((Ipv4Addr::new(127, 0, 0, 1), 0))
        .await
        .unwrap();
    let p1 = l1.local_addr().unwrap().port();
    let l2 = tokio::net::TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .unwrap();
    let p2 = l2.local_addr().unwrap().port();

    let base_port = 55000u16;
    let seqmask = 0x1357_9BDF;
    let kind = SynKind { seqmask };
    // Both hosts reply to our source (127.0.0.1); the filter covers both.
    let bpf = format!(
        "tcp and dst host 127.0.0.1 and dst portrange {}-{}",
        base_port,
        base_port + 16
    );
    let source =
        nmap_sys::capture::pcap_source::PcapSource::open("lo", 65535, 100, Some(&bpf)).unwrap();

    // Scan p1 on both hosts and p2 on both hosts; only the owning host has each open.
    let targets = [Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 2)];
    let hosts = tokio::time::timeout(
        Duration::from_secs(10),
        group_scan(
            Ipv4Addr::new(127, 0, 0, 1),
            &targets,
            &[p1, p2],
            sender,
            source,
            &kind,
            TimingTemplate::Insane,
            0,
            base_port,
            true,
        ),
    )
    .await
    .expect("group scan completed within 10s");

    assert_eq!(hosts.len(), 2);
    let h1 = &hosts[0];
    let h2 = &hosts[1];
    assert_eq!(h1.state, HostState::Up);
    assert_eq!(h2.state, HostState::Up);
    // p1 is open on 127.0.0.1, p2 is open on 127.0.0.2 — the demux must not cross them.
    assert_eq!(
        h1.ports.iter().find(|p| p.number == p1).unwrap().state,
        PortState::Open,
        "p1 should be open on host .1"
    );
    assert_eq!(
        h2.ports.iter().find(|p| p.number == p2).unwrap().state,
        PortState::Open,
        "p2 should be open on host .2"
    );
}
