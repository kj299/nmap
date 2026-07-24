//! UDP-scan driver — the privileged `-sU` event loop. The UDP analog of
//! [`crate::synscan`]: it drives the pure [`nmap_core::engine::HostScheduler`] over a
//! raw sender and a captured reply stream, building UDP probes with
//! [`nmap_core::udpscan`] and matching replies (direct datagram → open, ICMP
//! port-unreachable → closed, other ICMP → filtered) back to their probes. **No
//! `unsafe`**.
//!
//! Two differences from the SYN driver: the capture filter is `(udp ...) or icmp`
//! (an ICMP error is addressed to our source IP, not our port), and a probe with **no
//! reply** resolves to `open|filtered` — nmap's UDP default — rather than `filtered`.
//! Single-host this slice, matching the SYN driver's scope.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use nmap_core::build::Ipv4Spec;
use nmap_core::classify::PortState as ClassState;
use nmap_core::engine::{HostScheduler, Probe};
use nmap_core::model::{Host, HostState, Port, PortState, Protocol, Reason};
use nmap_core::timing::{TimingParams, TimingTemplate};
use nmap_core::udpscan::{build_udp_probe, match_udp_response, UdpMatchCtx};

use crate::capture::{AsyncCapture, PacketSource};
use crate::rawio::RawSender;

/// Default TTL for outgoing probes.
const DEFAULT_TTL: u8 = 64;
/// Capture channel depth.
const CAPTURE_CAPACITY: usize = 1024;
/// Fallback wait when nothing is outstanding but the host is not done.
const IDLE_WAIT: Duration = Duration::from_millis(50);

/// What to UDP-scan on one host and how.
#[derive(Clone, Debug)]
pub struct UdpScanConfig {
    /// UDP ports to probe.
    pub ports: Vec<u16>,
    /// Timing template (`-T0..-T5`).
    pub template: TimingTemplate,
    /// Hard ceiling on concurrent probes (`0` = template default).
    pub max_parallelism: usize,
    /// Whether the capture delivers a link-layer header.
    pub eth_included: bool,
    /// Base UDP source port; the capture BPF filter must scope to this range.
    pub base_port: u16,
}

/// Map a resolved UDP reply state to the reason nmap reports for it.
fn reason_for(state: ClassState) -> Reason {
    match state {
        ClassState::Open => Reason::UdpResponse,   // "udp-response"
        ClassState::Closed => Reason::PortUnreach, // "port-unreach"
        _ => Reason::NoResponse,
    }
}

/// Run a single-host UDP scan, driving the pure scheduler over a raw sender and a
/// captured reply stream. Generic over sender/source so tests use in-memory mocks.
pub async fn udp_scan<S, P>(
    src: Ipv4Addr,
    target: Ipv4Addr,
    mut sender: S,
    source: P,
    config: &UdpScanConfig,
) -> Host
where
    S: RawSender,
    P: PacketSource,
{
    let max_par = u32::try_from(config.max_parallelism).unwrap_or(u32::MAX);
    let params = TimingParams::for_template(config.template);
    let max_tryno = params.max_retransmissions;
    let mut sched = HostScheduler::with_params(&config.ports, config.template, params, 0, max_par);
    let mctx = UdpMatchCtx {
        base_port: config.base_port,
        max_tryno,
        target: target.octets(),
    };

    let mut capture = AsyncCapture::spawn(source, CAPTURE_CAPACITY);
    let start = Instant::now();
    let mut outstanding: HashMap<(u16, u32), (i64, i64)> = HashMap::new();
    let mut finals: Vec<(u16, PortState, Reason)> = Vec::new();
    let mut ipid: u16 = config.base_port;

    loop {
        while sched.may_send() {
            let Some(probe) = sched.next_probe() else {
                break;
            };
            ipid = ipid.wrapping_add(1);
            let spec = Ipv4Spec::new(src.octets(), target.octets(), DEFAULT_TTL, ipid);
            match build_udp_probe(&spec, config.base_port, probe.port, probe.tryno) {
                Ok(pkt) => {
                    let _ = sender.send(&pkt);
                    let now = now_us(start);
                    outstanding.insert(
                        (probe.port, probe.tryno),
                        (now, now.saturating_add(sched.probe_timeout_us())),
                    );
                }
                Err(_) => {
                    let before = sched.resolved();
                    sched.on_timeout(probe);
                    if sched.resolved() > before {
                        // A build failure can't tell us open-vs-closed → open|filtered.
                        finals.push((probe.port, PortState::OpenFiltered, Reason::NoResponse));
                    }
                }
            }
        }

        if sched.is_done() && outstanding.is_empty() {
            break;
        }

        let now = now_us(start);
        let next_deadline = outstanding.values().map(|(_, d)| *d).min();
        let sleep_dur = next_deadline
            .map(|d| micros_to_duration(d.saturating_sub(now)))
            .unwrap_or(IDLE_WAIT);

        tokio::select! {
            frame = capture.recv() => {
                if let Some(f) = frame {
                    if let Some(reply) = match_udp_response(&f.data, config.eth_included, &mctx) {
                        if let Some((send_us, _)) = outstanding.remove(&(reply.port, reply.tryno)) {
                            let rtt = now_us(start).saturating_sub(send_us).max(1);
                            sched.on_reply(Probe { port: reply.port, tryno: reply.tryno }, rtt);
                            finals.push((reply.port, reply.state.into(), reason_for(reply.state)));
                        }
                    }
                }
            }
            () = tokio::time::sleep(sleep_dur) => {
                let now = now_us(start);
                let expired: Vec<(u16, u32)> = outstanding
                    .iter()
                    .filter(|(_, (_, d))| *d <= now)
                    .map(|(k, _)| *k)
                    .collect();
                for key in expired {
                    outstanding.remove(&key);
                    let before = sched.resolved();
                    sched.on_timeout(Probe { port: key.0, tryno: key.1 });
                    if sched.resolved() > before {
                        // No reply after every retransmission → open|filtered (UDP default).
                        finals.push((key.0, PortState::OpenFiltered, Reason::NoResponse));
                    }
                }
            }
        }
    }

    capture.stop();

    // A UDP host is "up" if anything answered (open or closed); all-open|filtered alone
    // is not proof of life.
    let up = finals
        .iter()
        .any(|(_, s, _)| matches!(s, PortState::Open | PortState::Closed));
    let mut host = Host::new(
        IpAddr::V4(target),
        if up { HostState::Up } else { HostState::Down },
    );
    for (port, state, reason) in finals {
        host.ports
            .push(Port::new(port, Protocol::Udp, state, reason));
    }
    host.ports.sort_by_key(|p| (p.protocol, p.number));
    host
}

/// Run a UDP scan over several targets with route/source selection and pcap capture —
/// the CLI-facing entry point (feature `pcap`). One [`Host`] per target in order.
///
/// # Errors
/// Propagates a raw-socket / capture-open error (notably `PermissionDenied`) and any
/// interface-enumeration error.
#[cfg(feature = "pcap")]
pub async fn udp_scan_targets(
    targets: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_parallelism: usize,
) -> std::io::Result<nmap_core::model::ScanResults> {
    use crate::capture::pcap_source::PcapSource;
    use crate::rawio::RawIpv4Sender;
    use crate::route::{random_scan_keys, route_for};
    use nmap_core::model::ScanResults;

    drop(RawIpv4Sender::new()?);

    let mut results = ScanResults::new();
    for &ip in targets {
        let IpAddr::V4(v4) = ip else {
            results.hosts.push(Host::new(ip, HostState::Down));
            continue;
        };
        let Some(route) = route_for(v4)? else {
            results.hosts.push(Host::new(ip, HostState::Down));
            continue;
        };
        // Only the base port is used from the keys (UDP has no sequence to mask).
        let (_seqmask, base_port) = random_scan_keys();
        let config = UdpScanConfig {
            ports: ports.to_vec(),
            template,
            max_parallelism,
            eth_included: route.eth_included,
            base_port,
        };
        let sender = RawIpv4Sender::new()?;
        // Match our datagrams' replies (to our source-port range) and any ICMP error.
        let bpf = format!(
            "(udp and dst host {} and dst portrange {}-{}) or (icmp and dst host {})",
            route.src,
            base_port,
            base_port.saturating_add(16),
            route.src
        );
        let socket = PcapSource::open(&route.iface, 65535, 100, Some(&bpf))?;
        results
            .hosts
            .push(udp_scan(route.src, v4, sender, socket, &config).await);
    }
    Ok(results)
}

fn now_us(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_micros()).unwrap_or(i64::MAX)
}

fn micros_to_duration(us: i64) -> Duration {
    Duration::from_micros(u64::try_from(us).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nmap_core::build::build_udp_raw;
    use nmap_core::udpscan::build_udp_probe;
    use std::sync::{Arc, Mutex};

    struct MockSource {
        frames: Arc<Mutex<Vec<Vec<u8>>>>,
    }
    impl PacketSource for MockSource {
        fn next_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            if let Some(f) = self.frames.lock().unwrap().pop() {
                Ok(Some(f))
            } else {
                std::thread::sleep(Duration::from_micros(200));
                Ok(None)
            }
        }
    }

    #[derive(Default)]
    struct MockSender {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }
    impl RawSender for MockSender {
        fn send(&mut self, packet: &[u8]) -> std::io::Result<usize> {
            self.sent.lock().unwrap().push(packet.to_vec());
            Ok(packet.len())
        }
    }

    fn cfg(ports: Vec<u16>) -> UdpScanConfig {
        UdpScanConfig {
            ports,
            template: TimingTemplate::Insane,
            max_parallelism: 0,
            eth_included: true,
            base_port: 40000,
        }
    }

    fn framed(ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f.extend_from_slice(ip);
        f
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn direct_datagram_resolves_open() {
        let c = cfg(vec![53]);
        // Target → us: src port 53 (scanned), dst = our sport (base + 0).
        let spec = Ipv4Spec::new([127, 0, 0, 1], [127, 0, 0, 1], 64, 0x1);
        let reply = build_udp_raw(&spec, 53, 40000, b"hi").unwrap();
        let source = MockSource {
            frames: Arc::new(Mutex::new(vec![framed(&reply)])),
        };
        let host = udp_scan(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            MockSender::default(),
            source,
            &c,
        )
        .await;
        let p = host.ports.iter().find(|p| p.number == 53).unwrap();
        assert_eq!(p.state, PortState::Open);
        assert_eq!(p.reason, Reason::UdpResponse);
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn no_reply_resolves_open_filtered() {
        // Idle link → the UDP default open|filtered, and the loop must terminate.
        let c = cfg(vec![9999]);
        let source = MockSource {
            frames: Arc::new(Mutex::new(Vec::new())),
        };
        let host = udp_scan(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            MockSender::default(),
            source,
            &c,
        )
        .await;
        let p = host.ports.iter().find(|p| p.number == 9999).unwrap();
        assert_eq!(p.state, PortState::OpenFiltered);
        assert_eq!(p.reason, Reason::NoResponse);
    }

    #[test]
    fn probe_is_a_udp_datagram() {
        let spec = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 1);
        let pkt = build_udp_probe(&spec, 40000, 53, 0).unwrap();
        assert!(!pkt.is_empty());
    }
}
