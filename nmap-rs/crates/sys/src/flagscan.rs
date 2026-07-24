//! Stateless TCP flag-scan driver — the privileged event loop shared by `-sA`, `-sW`,
//! `-sM`, `-sF`, `-sN`, and `-sX`. Parametrized by [`nmap_core::classify::ScanType`]:
//! it builds the scan's probe with [`nmap_core::flagscan`], matches RST replies, and
//! resolves a no-response port to that scan's default state
//! ([`nmap_core::classify::default_port_state`]). The UDP/SYN driver shape, generalized
//! over the flag combination. **No `unsafe`**.
//!
//! Single host per call this slice, matching the SYN/UDP drivers.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use nmap_core::build::Ipv4Spec;
use nmap_core::classify::{default_port_state, ScanType};
use nmap_core::engine::{HostScheduler, Probe};
use nmap_core::flagscan::{build_flag_probe, flags_for, match_flag_response, FlagMatchCtx};
use nmap_core::model::{Host, HostState, Port, PortState as MPortState, Protocol, Reason};
use nmap_core::timing::{TimingParams, TimingTemplate};

use crate::capture::{AsyncCapture, PacketSource};
use crate::rawio::RawSender;

const DEFAULT_TTL: u8 = 64;
const CAPTURE_CAPACITY: usize = 1024;
const IDLE_WAIT: Duration = Duration::from_millis(50);

/// What to flag-scan on one host and how.
#[derive(Clone, Debug)]
pub struct FlagScanConfig {
    /// Which flag scan (`Ack`/`Window`/`Maimon`/`Fin`/`Null`/`Xmas`).
    pub scan: ScanType,
    /// TCP ports to probe.
    pub ports: Vec<u16>,
    /// Timing template (`-T0..-T5`).
    pub template: TimingTemplate,
    /// Hard ceiling on concurrent probes (`0` = template default).
    pub max_parallelism: usize,
    /// Whether the capture delivers a link-layer header.
    pub eth_included: bool,
    /// Base TCP source port; the capture BPF filter must scope to this range.
    pub base_port: u16,
}

/// Run a single-host flag scan. Generic over sender/source so tests use mocks.
pub async fn flag_scan<S, P>(
    src: Ipv4Addr,
    target: Ipv4Addr,
    mut sender: S,
    source: P,
    config: &FlagScanConfig,
) -> Host
where
    S: RawSender,
    P: PacketSource,
{
    let flags = flags_for(config.scan).unwrap_or(0);
    let max_par = u32::try_from(config.max_parallelism).unwrap_or(u32::MAX);
    let params = TimingParams::for_template(config.template);
    let max_tryno = params.max_retransmissions;
    let mut sched = HostScheduler::with_params(&config.ports, config.template, params, 0, max_par);
    let mctx = FlagMatchCtx {
        scan: config.scan,
        base_port: config.base_port,
        max_tryno,
    };
    // A no-response port resolves to this scan's default (ACK/Window → filtered;
    // FIN/Null/Xmas/Maimon → open|filtered).
    let default_state: MPortState = default_port_state(config.scan, false).into();

    let mut capture = AsyncCapture::spawn(source, CAPTURE_CAPACITY);
    let start = Instant::now();
    let mut outstanding: HashMap<(u16, u32), (i64, i64)> = HashMap::new();
    let mut finals: Vec<(u16, MPortState, Reason)> = Vec::new();
    let mut ipid: u16 = config.base_port;

    loop {
        while sched.may_send() {
            let Some(probe) = sched.next_probe() else {
                break;
            };
            ipid = ipid.wrapping_add(1);
            let spec = Ipv4Spec::new(src.octets(), target.octets(), DEFAULT_TTL, ipid);
            // seqmask is unused by flag matching (no reflection); pass the ipid as a
            // cheap per-probe salt for the sequence field.
            match build_flag_probe(
                &spec,
                config.base_port,
                probe.port,
                probe.tryno,
                u32::from(ipid),
                flags,
            ) {
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
                        finals.push((probe.port, default_state, Reason::NoResponse));
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
                    if let Some(reply) = match_flag_response(&f.data, config.eth_included, &mctx) {
                        if let Some((send_us, _)) = outstanding.remove(&(reply.port, reply.tryno)) {
                            let rtt = now_us(start).saturating_sub(send_us).max(1);
                            sched.on_reply(Probe { port: reply.port, tryno: reply.tryno }, rtt);
                            // Every flag-scan verdict comes from an RST.
                            finals.push((reply.port, reply.state.into(), Reason::Reset));
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
                        finals.push((key.0, default_state, Reason::NoResponse));
                    }
                }
            }
        }
    }

    capture.stop();

    // Any RST proves the host is up; an all-default result (no replies) does not.
    let up = finals.iter().any(|(_, _, r)| *r == Reason::Reset);
    let mut host = Host::new(
        IpAddr::V4(target),
        if up { HostState::Up } else { HostState::Down },
    );
    for (port, state, reason) in finals {
        host.ports
            .push(Port::new(port, Protocol::Tcp, state, reason));
    }
    host.ports.sort_by_key(|p| (p.protocol, p.number));
    host
}

/// Run a flag scan over several targets with route/source selection + pcap capture —
/// the CLI-facing entry point (feature `pcap`). One [`Host`] per target in order.
///
/// # Errors
/// Propagates a raw-socket / capture-open error (notably `PermissionDenied`) and any
/// interface-enumeration error.
#[cfg(feature = "pcap")]
pub async fn flag_scan_targets(
    scan: ScanType,
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
        let (_seqmask, base_port) = random_scan_keys();
        let config = FlagScanConfig {
            scan,
            ports: ports.to_vec(),
            template,
            max_parallelism,
            eth_included: route.eth_included,
            base_port,
        };
        let sender = RawIpv4Sender::new()?;
        let bpf = format!(
            "tcp and dst host {} and dst portrange {}-{}",
            route.src,
            base_port,
            base_port.saturating_add(16)
        );
        let socket = PcapSource::open(&route.iface, 65535, 100, Some(&bpf))?;
        results
            .hosts
            .push(flag_scan(route.src, v4, sender, socket, &config).await);
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
    use nmap_core::build::build_tcp_raw;
    use nmap_core::synscan::sport_encode;
    use std::sync::{Arc, Mutex};

    const TH_RST: u8 = 0x04;
    const TH_ACK: u8 = 0x10;

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

    fn cfg(scan: ScanType, ports: Vec<u16>) -> FlagScanConfig {
        FlagScanConfig {
            scan,
            ports,
            template: TimingTemplate::Insane,
            max_parallelism: 0,
            eth_included: true,
            base_port: 40000,
        }
    }

    fn rst_reply(scanned: u16, flags: u8, window: u16) -> Vec<u8> {
        let spec = Ipv4Spec::new([127, 0, 0, 1], [127, 0, 0, 1], 64, 0x9);
        let seg = build_tcp_raw(
            &spec,
            scanned,
            sport_encode(40000, 0),
            1,
            0,
            0,
            flags,
            window,
            0,
            &[],
            &[],
        )
        .unwrap();
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f.extend_from_slice(&seg);
        f
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn ack_scan_rst_resolves_unfiltered() {
        let c = cfg(ScanType::Ack, vec![80]);
        let frames = Arc::new(Mutex::new(vec![rst_reply(80, TH_RST | TH_ACK, 0)]));
        let host = flag_scan(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            MockSender::default(),
            MockSource { frames },
            &c,
        )
        .await;
        let p = host.ports.iter().find(|p| p.number == 80).unwrap();
        assert_eq!(p.state, MPortState::Unfiltered);
        assert_eq!(p.reason, Reason::Reset);
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn fin_scan_no_reply_is_open_filtered() {
        let c = cfg(ScanType::Fin, vec![1234]);
        let host = flag_scan(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            MockSender::default(),
            MockSource {
                frames: Arc::new(Mutex::new(Vec::new())),
            },
            &c,
        )
        .await;
        let p = host.ports.iter().find(|p| p.number == 1234).unwrap();
        assert_eq!(p.state, MPortState::OpenFiltered);
        assert_eq!(p.reason, Reason::NoResponse);
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn ack_scan_no_reply_is_filtered() {
        let c = cfg(ScanType::Ack, vec![1234]);
        let host = flag_scan(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            MockSender::default(),
            MockSource {
                frames: Arc::new(Mutex::new(Vec::new())),
            },
            &c,
        )
        .await;
        let p = host.ports.iter().find(|p| p.number == 1234).unwrap();
        assert_eq!(p.state, MPortState::Filtered);
    }
}
