//! IPv6 raw port scans end to end on `::1` (IPv6 scans step d; feature `pcap`, root
//! only).
//!
//! - Every raw scan type, through the CLI's own entry points (route, loopback sender,
//!   capture filter, engine), against a listening and a closed TCP port and a bound and
//!   a closed UDP port.
//! - The SYN probe on the wire is byte-identical to `core::build`'s, framed for the
//!   loopback as `LinkFraming::for_loopback` says.
//!
//! `#[ignore]` + self-skip without privilege or without IPv6 on the loopback; with
//! `REQUIRE_IPV6=1` (as CI runs them) a missing IPv6 loopback fails instead, so the
//! tests cannot pass by skipping. Run as root:
//! `sudo -E cargo test -p nmap-sys --features pcap --test scan6_e2e -- --ignored`.
#![cfg(feature = "pcap")]

use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use nmap_core::build::{Ipv6Spec, PacketOverrides};
use nmap_core::classify::ScanType;
use nmap_core::model::{Host, PortState, Protocol, Reason};
use nmap_core::payload::UdpPayloads;
use nmap_core::synscan::build_syn_probe;
use nmap_core::timing::{TimingParams, TimingTemplate};

use nmap_sys::capture::pcap_source::PcapSource;
use nmap_sys::capture::{AsyncCapture, PacketSource};
use nmap_sys::group::{group_scan, SynKind};
use nmap_sys::rawio::pcap_sender::PcapSender;
use nmap_sys::rawio::{FramingSender, LinkFraming, RawIpv4Sender};

const LO6: Ipv6Addr = Ipv6Addr::LOCALHOST;

/// Whether to run: privileged, and `::1` usable. Panics, rather than skipping, when
/// `REQUIRE_IPV6` is set and the loopback has no IPv6.
fn ready(what: &str) -> bool {
    match RawIpv4Sender::new() {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping {what}: no CAP_NET_RAW");
            return false;
        }
        Err(e) => panic!("unexpected error opening a raw socket: {e}"),
    }
    if let Err(e) = std::net::TcpListener::bind((LO6, 0)) {
        assert!(
            std::env::var_os("REQUIRE_IPV6").is_none(),
            "REQUIRE_IPV6 is set, but ::1 is unusable: {e}"
        );
        eprintln!("skipping {what}: no IPv6 on the loopback ({e})");
        return false;
    }
    true
}

/// A port nothing listens on, for `kind` sockets on `::1`.
fn closed_port(udp: bool) -> u16 {
    if udp {
        std::net::UdpSocket::bind((LO6, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    } else {
        std::net::TcpListener::bind((LO6, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}

fn params() -> (TimingTemplate, TimingParams) {
    let t = TimingTemplate::Aggressive;
    (t, TimingParams::for_template(t))
}

fn port(host: &Host, number: u16, proto: Protocol) -> (PortState, Reason) {
    let p = host
        .ports
        .iter()
        .find(|p| p.number == number && p.protocol == proto)
        .unwrap_or_else(|| panic!("{number}/{proto:?} resolved: {:?}", host.ports));
    (p.state, p.reason)
}

/// Every raw scan type, through the entry points the CLI calls, on `::1`.
#[tokio::test]
#[ignore = "needs CAP_NET_RAW + IPv6 on the loopback; run as root"]
async fn every_raw_scan_type_resolves_ports_on_ipv6_loopback() {
    if !ready("the IPv6 scans of ::1") {
        return;
    }
    let listener = std::net::TcpListener::bind((LO6, 0)).unwrap();
    let open_tcp = listener.local_addr().unwrap().port();
    let closed_tcp = closed_port(false);
    let (template, params) = params();
    let targets = [IpAddr::V6(LO6)];
    let in_time = Duration::from_secs(60);

    // TCP: the states every stack agrees on (the differential against 7.94 covers the
    // rest, port by port).
    let syn = tokio::time::timeout(
        in_time,
        nmap_sys::synscan::syn_scan_targets(
            &targets,
            &[open_tcp, closed_tcp],
            template,
            params,
            0,
            PacketOverrides::default(),
        ),
    )
    .await
    .expect("-sS finished")
    .expect("-sS ran");
    let h = &syn.hosts[0];
    assert_eq!(h.address, IpAddr::V6(LO6));
    assert_eq!(
        port(h, open_tcp, Protocol::Tcp),
        (PortState::Open, Reason::ConnAccept),
        "-sS open"
    );
    assert_eq!(
        port(h, closed_tcp, Protocol::Tcp),
        (PortState::Closed, Reason::Reset),
        "-sS closed"
    );

    for (scan, open_want, closed_want) in [
        (
            ScanType::Ack,
            Some(PortState::Unfiltered),
            PortState::Unfiltered,
        ),
        (
            ScanType::Fin,
            Some(PortState::OpenFiltered),
            PortState::Closed,
        ),
        (
            ScanType::Null,
            Some(PortState::OpenFiltered),
            PortState::Closed,
        ),
        (
            ScanType::Xmas,
            Some(PortState::OpenFiltered),
            PortState::Closed,
        ),
        // The window and the stack's answer to FIN/ACK vary by OS; a closed port is
        // reset everywhere.
        (ScanType::Window, None, PortState::Closed),
        (ScanType::Maimon, None, PortState::Closed),
    ] {
        let r = tokio::time::timeout(
            in_time,
            nmap_sys::flagscan::flag_scan_targets(
                scan,
                &targets,
                &[open_tcp, closed_tcp],
                template,
                params,
                0,
                PacketOverrides::default(),
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{scan:?} finished"))
        .unwrap_or_else(|e| panic!("{scan:?} ran: {e}"));
        let h = &r.hosts[0];
        assert_eq!(
            port(h, closed_tcp, Protocol::Tcp),
            (closed_want, Reason::Reset),
            "{scan:?} closed"
        );
        if let Some(want) = open_want {
            assert_eq!(port(h, open_tcp, Protocol::Tcp).0, want, "{scan:?} open");
        }
    }

    // UDP: a bound socket that never answers, and a closed port, which the kernel
    // answers with an ICMPv6 port unreachable.
    let bound = std::net::UdpSocket::bind((LO6, 0)).unwrap();
    let open_udp = bound.local_addr().unwrap().port();
    let closed_udp = closed_port(true);
    let udp = tokio::time::timeout(
        in_time,
        nmap_sys::udpscan::udp_scan_targets(
            &targets,
            &[open_udp, closed_udp],
            template,
            params,
            0,
            UdpPayloads::empty(),
            PacketOverrides::default(),
        ),
    )
    .await
    .expect("-sU finished")
    .expect("-sU ran");
    let h = &udp.hosts[0];
    assert_eq!(
        port(h, closed_udp, Protocol::Udp),
        (PortState::Closed, Reason::PortUnreach),
        "-sU closed"
    );
    assert_eq!(
        port(h, open_udp, Protocol::Udp),
        (PortState::OpenFiltered, Reason::NoResponse),
        "-sU open"
    );
    drop((listener, bound));
}

/// The SYN probe on the wire is `core::build`'s, byte for byte, in the loopback's
/// framing; and its RST is matched.
#[tokio::test]
#[ignore = "needs CAP_NET_RAW + IPv6 on the loopback; run as root"]
async fn transmitted_ipv6_syn_probe_matches_core_build_on_the_wire() {
    if !ready("the IPv6 on-the-wire check") {
        return;
    }
    let route = nmap_sys::route::route_for6(LO6)
        .expect("enumerate interfaces")
        .expect("a route to ::1");
    assert!(route.loopback);
    let link = PcapSender::open(&route.iface).expect("open the loopback for sending");
    let dlt = link.datalink();
    let framing = LinkFraming::for_loopback(dlt, route.src_mac).expect("a loopback framing");
    let sender = FramingSender::new(link, framing);

    let dport = closed_port(false);
    let (base, seqmask) = (55100u16, 0x0F1E_2D3C);
    // Our own outgoing probe, to the scanned port.
    let wire_cap = PcapSource::open(
        &route.iface,
        65535,
        100,
        Some(&format!("ip6 and dst host ::1 and tcp dst port {dport}")),
    )
    .expect("open the probe capture");
    let wire_eth = wire_cap.eth_included();
    let mut wire = AsyncCapture::spawn(wire_cap, 64);

    let filter =
        <Ipv6Addr as nmap_sys::group::ScanFamily>::reply_filter(route.src, Protocol::Tcp, base, 16);
    let source = PcapSource::open(&route.iface, 65535, 100, Some(&filter)).expect("capture");
    let eth = source.eth_included();
    let (template, params) = params();
    let hosts = tokio::time::timeout(
        Duration::from_secs(20),
        group_scan(
            route.src,
            &[LO6],
            &[dport],
            sender,
            source,
            &SynKind { seqmask },
            template,
            params,
            0,
            base,
            eth,
            PacketOverrides::default(),
        ),
    )
    .await
    .expect("the scan finished");
    assert_eq!(
        port(&hosts[0], dport, Protocol::Tcp),
        (PortState::Closed, Reason::Reset)
    );

    let frame = tokio::time::timeout(Duration::from_secs(2), wire.recv())
        .await
        .expect("captured the outgoing probe")
        .expect("the capture stayed open");
    wire.stop();
    let ip = if wire_eth {
        assert_eq!(&frame.data[12..14], &[0x86, 0xDD], "Ethernet type");
        &frame.data[14..]
    } else {
        &frame.data[..]
    };
    let intended = build_syn_probe(
        &Ipv6Spec::new(route.src.octets(), LO6.octets()),
        base,
        dport,
        0,
        seqmask,
    )
    .unwrap();
    assert_eq!(ip, &intended[..], "the probe on the wire is core::build's");
}
