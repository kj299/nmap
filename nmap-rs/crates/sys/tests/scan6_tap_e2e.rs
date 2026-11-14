//! IPv6 raw port scans over Ethernet against a scripted link (IPv6 scans step e;
//! feature `pcap`, Linux, root only).
//!
//! `tap_neighbor.py` puts an IPv6 link behind a TAP interface: a host that answers like
//! Linux, a silent address, a gateway with a host behind it, and a silent gateway. The
//! kernel needs no IPv6: the scan's own neighbor discovery, per-destination Ethernet
//! framing, capture and matching run over a real Ethernet interface, with the routes
//! the kernel would give handed in (`group_scan_targets_routed`). What 7.94 does on
//! the same shapes is checked on the wire in CI (a veth pair into a network namespace);
//! this checks every outcome the engine decides, including the two that namespace
//! cannot show (a gateway, and a silent one).
//!
//! `#[ignore]` + self-skip without root, `/dev/net/tun` or python3; with `REQUIRE_TAP=1`
//! (as CI runs it) a missing piece fails instead. Run as root:
//! `sudo -E cargo test -p nmap-sys --features pcap --test scan6_tap_e2e -- --ignored`.
#![cfg(all(feature = "pcap", target_os = "linux"))]

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use nmap_core::build::PacketOverrides;
use nmap_core::classify::ScanType;
use nmap_core::model::{Host, HostState, PortState, Protocol, Reason, ScanResults};
use nmap_core::payload::UdpPayloads;
use nmap_core::timing::{TimingParams, TimingTemplate};

use nmap_sys::group::{group_scan_targets_routed, FlagKind, RawScanKind, SynKind, UdpKind};
use nmap_sys::rawio::RawIpv4Sender;
use nmap_sys::route::{Route, Route6};

const IFACE: &str = "nrs6tap0";
const OPEN_TCP: u16 = 18122;
const CLOSED_TCP: u16 = 18199;
const UDP_OPEN: u16 = 18153;
const UDP_CLOSED: u16 = 18154;

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

/// Root, `/dev/net/tun` and python3, or skip (fail under `REQUIRE_TAP`).
fn ready() -> bool {
    let missing = if !matches!(RawIpv4Sender::new(), Ok(_)) {
        Some("CAP_NET_RAW")
    } else if !std::path::Path::new("/dev/net/tun").exists() {
        Some("/dev/net/tun")
    } else if Command::new("python3").arg("-c").arg("1").status().is_err() {
        Some("python3")
    } else {
        None
    };
    match missing {
        None => true,
        Some(what) => {
            assert!(
                std::env::var_os("REQUIRE_TAP").is_none(),
                "REQUIRE_TAP is set, but there is no {what}"
            );
            eprintln!("skipping the TAP link scans: no {what}");
            false
        }
    }
}

/// The scripted link, up and answering. `ext` puts a destination-options header in
/// front of every reply.
struct Link {
    child: Child,
}

impl Link {
    fn start(ext: bool) -> Link {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tap_neighbor.py");
        let ports = [OPEN_TCP, CLOSED_TCP, UDP_OPEN, UDP_CLOSED].map(|p| p.to_string());
        let mut child = Command::new("python3")
            .arg(script)
            .arg(IFACE)
            .args(&ports)
            .arg("300")
            .env("EXT", if ext { "1" } else { "0" })
            .stdout(Stdio::piped())
            .spawn()
            .expect("start the scripted link");
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ready", "the scripted link came up");
        Link { child }
    }

    /// Stop the link and return its summary: `(solicited, replies, misframed)`.
    fn stop(self) -> (u32, u32, u32) {
        let _ = Command::new("kill")
            .arg(self.child.id().to_string())
            .status();
        let out = self.child.wait_with_output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let field = |k: &str| -> u32 {
            text.split_whitespace()
                .find_map(|w| w.strip_prefix(&format!("{k}=")))
                .unwrap_or_else(|| panic!("{k} in {text:?}"))
                .parse()
                .unwrap()
        };
        (field("solicited"), field("replies"), field("misframed"))
    }
}

/// The routes the kernel would give, were the link configured: our address
/// fd00:6e7::1/64 on the TAP interface, a default route by fd00:6e7::fe, and
/// 2001:db8:2::/48 by fd00:6e7::fd.
fn route6(target: Ipv6Addr) -> std::io::Result<Option<Route6>> {
    let mac = std::fs::read_to_string(format!("/sys/class/net/{IFACE}/address"))?;
    let bytes: Vec<u8> = mac
        .trim()
        .split(':')
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect();
    let on_link = target.segments()[..4] == [0xfd00, 0x6e7, 0, 0];
    let next_hop = if on_link {
        target
    } else if target.segments()[1..3] == [0xdb8, 2] {
        v6("fd00:6e7::fd")
    } else {
        v6("fd00:6e7::fe")
    };
    Ok(Some(Route6 {
        iface: IFACE.into(),
        src: v6("fd00:6e7::1"),
        src_mac: Some(bytes.try_into().unwrap()),
        next_hop,
        next_hop_mac: None,
        directly_connected: on_link,
        loopback: false,
    }))
}

fn no_ipv4(_: Ipv4Addr) -> std::io::Result<Option<Route>> {
    Ok(None)
}

async fn scan<K: RawScanKind>(kind: &K, targets: &[Ipv6Addr], ports: &[u16]) -> ScanResults {
    let t = TimingTemplate::Aggressive;
    let ips: Vec<IpAddr> = targets.iter().copied().map(IpAddr::V6).collect();
    tokio::time::timeout(
        Duration::from_secs(60),
        group_scan_targets_routed(
            kind,
            &ips,
            ports,
            (t, TimingParams::for_template(t), 0),
            PacketOverrides::default(),
            no_ipv4,
            route6,
        ),
    )
    .await
    .expect("the scan finished")
    .expect("the scan ran")
}

fn port(host: &Host, number: u16, proto: Protocol) -> (PortState, Reason) {
    let p = host
        .ports
        .iter()
        .find(|p| p.number == number && p.protocol == proto)
        .unwrap_or_else(|| panic!("{number}/{proto:?} on {}: {:?}", host.address, host.ports));
    (p.state, p.reason)
}

/// Every outcome, with and without extension headers on the replies.
#[tokio::test]
#[ignore = "needs root, /dev/net/tun and python3"]
async fn ipv6_scans_over_ethernet_resolve_neighbors_and_ports() {
    if !ready() {
        return;
    }
    for ext in [false, true] {
        let link = Link::start(ext);
        let (near, silent, far, unreachable) = (
            v6("fd00:6e7::2"),
            v6("fd00:6e7::3"),
            v6("2001:db8:1::5"),
            v6("2001:db8:2::5"),
        );
        let r = scan(
            &SynKind {
                seqmask: 0x1357_2468,
            },
            &[near, silent, far, unreachable],
            &[OPEN_TCP, CLOSED_TCP],
        )
        .await;
        let [h_near, h_silent, h_far, h_unreachable] = &r.hosts[..] else {
            panic!("{} hosts", r.hosts.len());
        };
        let tcp = |h, p| port(h, p, Protocol::Tcp);
        // On the link and advertised: up, nd-response, and scanned.
        assert_eq!(
            (h_near.state, h_near.reason),
            (HostState::Up, Some(Reason::NdResponse)),
            "ext {ext}"
        );
        assert_eq!(tcp(h_near, OPEN_TCP), (PortState::Open, Reason::ConnAccept));
        assert_eq!(tcp(h_near, CLOSED_TCP), (PortState::Closed, Reason::Reset));
        // On the link and silent: down, no-response, and not scanned.
        assert_eq!(
            (h_silent.state, h_silent.reason),
            (HostState::Down, Some(Reason::NoResponse))
        );
        assert!(h_silent.ports.is_empty());
        // Behind the gateway, through its MAC.
        assert_eq!(tcp(h_far, OPEN_TCP), (PortState::Open, Reason::ConnAccept));
        assert_eq!(tcp(h_far, CLOSED_TCP), (PortState::Closed, Reason::Reset));
        assert_eq!(h_far.reason, None, "no ND ping for an off-link host");
        // Behind a silent gateway: scanned, nothing sent, the no-response defaults.
        for p in [OPEN_TCP, CLOSED_TCP] {
            assert_eq!(
                tcp(h_unreachable, p),
                (PortState::Filtered, Reason::NoResponse)
            );
        }

        let ack = scan(
            &FlagKind {
                scan: ScanType::Ack,
                seqmask: 7,
            },
            &[near, far],
            &[OPEN_TCP, CLOSED_TCP],
        )
        .await;
        for h in &ack.hosts {
            for p in [OPEN_TCP, CLOSED_TCP] {
                assert_eq!(
                    tcp(h, p),
                    (PortState::Unfiltered, Reason::Reset),
                    "{}",
                    h.address
                );
            }
        }
        let fin = scan(
            &FlagKind {
                scan: ScanType::Fin,
                seqmask: 7,
            },
            &[near],
            &[OPEN_TCP, CLOSED_TCP],
        )
        .await;
        assert_eq!(tcp(&fin.hosts[0], OPEN_TCP).0, PortState::OpenFiltered);
        assert_eq!(
            tcp(&fin.hosts[0], CLOSED_TCP),
            (PortState::Closed, Reason::Reset)
        );

        let udp = scan(
            &UdpKind::new(UdpPayloads::empty()),
            &[near, far],
            &[UDP_OPEN, UDP_CLOSED],
        )
        .await;
        for h in &udp.hosts {
            assert_eq!(
                port(h, UDP_CLOSED, Protocol::Udp),
                (PortState::Closed, Reason::PortUnreach),
                "{}",
                h.address
            );
            assert_eq!(port(h, UDP_OPEN, Protocol::Udp).0, PortState::OpenFiltered);
        }

        let (solicited, replies, misframed) = link.stop();
        assert_eq!(misframed, 0, "every probe went to its own next hop's MAC");
        assert!(
            solicited > 0 && replies > 0,
            "{solicited} solicited, {replies} replies"
        );
    }
}
