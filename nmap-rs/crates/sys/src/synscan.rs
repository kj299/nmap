//! SYN-scan driver — the privileged `-sS` event loop. Turns the pure
//! [`nmap_core::synscan`] encoding/matching and [`nmap_core::engine::HostScheduler`]
//! decisions into real raw sends and captured replies. Every *decision* (which probe,
//! when to retransmit, is the host done, what state does a reply imply) lives in
//! `core`; this module performs only the I/O and feeds outcomes back. **No `unsafe`**
//! (the raw socket and capture are the safe `socket2` / `pcap` wrappers).
//!
//! Unlike the connect driver, send and receive are **decoupled**: one
//! [`RawSender`](crate::rawio::RawSender) puts SYNs on the wire while a single
//! [`AsyncCapture`] stream feeds every reply back, and the loop `select!`s the
//! capture against the earliest probe timeout. A captured frame is tied to its probe
//! by [`nmap_core::synscan::match_syn_response`]; the pcap BPF filter is scoped to our
//! encoded source-port range so our own outgoing SYNs never come back as replies
//! (the loopback self-probe guard — see the `core::synscan` docs).
//!
//! This first slice scans a **single host**. A multi-host group (one shared capture
//! demultiplexed by source address, as nmap's `ultra_scan` does) is a follow-up,
//! mirroring how the connect scan landed single-host in M1 before the M2 group loop.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use nmap_core::build::Ipv4Spec;
use nmap_core::classify::PortState as ClassState;
use nmap_core::engine::{HostScheduler, Probe};
use nmap_core::model::{Host, HostState, Port, PortState, Protocol, Reason};
use nmap_core::synscan::{build_syn_probe, match_syn_response, MatchCtx};
use nmap_core::timing::{TimingParams, TimingTemplate};

use crate::capture::{AsyncCapture, PacketSource};
use crate::rawio::RawSender;

/// Default TTL for outgoing probes (nmap uses `o.ttl`, default 64 on Unix).
const DEFAULT_TTL: u8 = 64;
/// Capture channel depth — bounds how many un-processed frames buffer.
const CAPTURE_CAPACITY: usize = 1024;
/// Fallback wait when nothing is outstanding but the host is not done (a state the
/// congestion gate makes unreachable in practice; a short sleep keeps the loop live).
const IDLE_WAIT: Duration = Duration::from_millis(50);

/// What to SYN-scan on one host and how. The per-scan `base_port` / `seqmask` are the
/// randomness nmap draws once per scan; the caller (CLI) supplies them so the driver
/// stays deterministic and testable, and so they match the capture's BPF filter.
#[derive(Clone, Debug)]
pub struct SynScanConfig {
    /// TCP ports to probe.
    pub ports: Vec<u16>,
    /// Timing template (`-T0..-T5`) driving congestion control, RTO, and retry cap.
    pub template: TimingTemplate,
    /// Hard ceiling on concurrent probes (`--max-parallelism`; `0` = template default).
    pub max_parallelism: usize,
    /// Whether the capture delivers a link-layer header (pcap on lo/Ethernet → `true`).
    pub eth_included: bool,
    /// Base TCP source port; the `tryno == 0` source port. The capture BPF filter must
    /// be `tcp and dst portrange base..base+max_retransmissions`.
    pub base_port: u16,
    /// Per-scan random sequence mask ([`nmap_core::synscan::seq32_encode`]).
    pub seqmask: u32,
}

/// Map a resolved TCP reply state to the reason nmap reports for it.
fn reason_for(state: ClassState) -> Reason {
    match state {
        ClassState::Open => Reason::ConnAccept, // "syn-ack"
        ClassState::Closed => Reason::Reset,    // "reset"
        _ => Reason::NoResponse,
    }
}

/// Run a single-host SYN scan, driving the pure scheduler over a raw sender and a
/// captured reply stream. Returns the populated [`Host`]. Generic over the sender and
/// capture source so tests drive it with in-memory mocks.
pub async fn syn_scan<S, P>(
    src: Ipv4Addr,
    target: Ipv4Addr,
    mut sender: S,
    source: P,
    config: &SynScanConfig,
) -> Host
where
    S: RawSender,
    P: PacketSource,
{
    let max_par = u32::try_from(config.max_parallelism).unwrap_or(u32::MAX);
    let params = TimingParams::for_template(config.template);
    let max_tryno = params.max_retransmissions;
    let mut sched = HostScheduler::with_params(&config.ports, config.template, params, 0, max_par);
    let mctx = MatchCtx {
        base_port: config.base_port,
        seqmask: config.seqmask,
        max_tryno,
    };

    let mut capture = AsyncCapture::spawn(source, CAPTURE_CAPACITY);
    let start = Instant::now();
    // (send_us, deadline_us) per in-flight (port, tryno). Mirrors the scheduler's
    // active set so a timeout can be detected without a per-probe future.
    let mut outstanding: HashMap<(u16, u32), (i64, i64)> = HashMap::new();
    let mut finals: Vec<(u16, PortState, Reason)> = Vec::new();
    // Per-probe IP-ID. On loopback the value is immaterial (the BPF filter excludes
    // self-probes); a counter avoids pulling in an RNG dependency here.
    let mut ipid: u16 = config.base_port;

    loop {
        // Launch every probe the congestion window currently permits.
        while sched.may_send() {
            let Some(probe) = sched.next_probe() else {
                break;
            };
            ipid = ipid.wrapping_add(1);
            let spec = Ipv4Spec::new(src.octets(), target.octets(), DEFAULT_TTL, ipid);
            match build_syn_probe(
                &spec,
                config.base_port,
                probe.port,
                probe.tryno,
                config.seqmask,
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
                    // Unreachable for the fixed SYN options, but never wedge the loop:
                    // release the scheduler slot as a timed-out attempt.
                    let before = sched.resolved();
                    sched.on_timeout(probe);
                    if sched.resolved() > before {
                        finals.push((probe.port, PortState::Filtered, Reason::NoResponse));
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
                    if let Some(reply) = match_syn_response(&f.data, config.eth_included, &mctx) {
                        if let Some((send_us, _)) =
                            outstanding.remove(&(reply.port, reply.tryno))
                        {
                            let rtt = now_us(start).saturating_sub(send_us).max(1);
                            sched.on_reply(Probe { port: reply.port, tryno: reply.tryno }, rtt);
                            finals.push((reply.port, reply.state.into(), reason_for(reply.state)));
                        }
                    }
                }
                // A `None` means the capture ended; the timeout path still drives the
                // remaining probes to resolution, so the loop always terminates.
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
                        finals.push((key.0, PortState::Filtered, Reason::NoResponse));
                    }
                }
            }
        }
    }

    capture.stop();

    let up = finals
        .iter()
        .any(|(_, s, _)| matches!(s, PortState::Open | PortState::Closed));
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

/// Run a SYN scan over several targets, doing route/source selection, per-scan key
/// generation, and pcap capture setup — the CLI-facing entry point (feature `pcap`).
///
/// Returns one [`Host`] per target in order (a `Down` placeholder for an IPv6 target
/// or one with no route, keeping the result aligned with the input). A
/// `PermissionDenied` from opening the raw socket propagates so the caller can fall
/// back to a connect scan.
///
/// # Errors
/// Propagates a raw-socket / capture-open error (notably `PermissionDenied` without
/// `CAP_NET_RAW`) and any interface-enumeration error.
#[cfg(feature = "pcap")]
pub async fn syn_scan_targets(
    targets: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_parallelism: usize,
) -> std::io::Result<nmap_core::model::ScanResults> {
    use crate::capture::pcap_source::PcapSource;
    use crate::rawio::RawIpv4Sender;
    use crate::route::{random_scan_keys, route_for};
    use nmap_core::model::ScanResults;

    // Probe raw-socket capability up front; PermissionDenied here is the fallback signal.
    drop(RawIpv4Sender::new()?);

    let mut results = ScanResults::new();
    for &ip in targets {
        let IpAddr::V4(v4) = ip else {
            // IPv6 SYN scan awaits the IPv6 receive path (validate-ipv4-only-for-now).
            results.hosts.push(Host::new(ip, HostState::Down));
            continue;
        };
        let Some(route) = route_for(v4)? else {
            results.hosts.push(Host::new(ip, HostState::Down));
            continue;
        };
        let (seqmask, base_port) = random_scan_keys();
        let config = SynScanConfig {
            ports: ports.to_vec(),
            template,
            max_parallelism,
            eth_included: route.eth_included,
            base_port,
            seqmask,
        };
        let sender = RawIpv4Sender::new()?;
        let bpf = format!(
            "tcp and dst host {} and dst portrange {}-{}",
            route.src,
            base_port,
            base_port.saturating_add(16)
        );
        let source = PcapSource::open(&route.iface, 65535, 100, Some(&bpf))?;
        results
            .hosts
            .push(syn_scan(route.src, v4, sender, source, &config).await);
    }
    Ok(results)
}

/// Microseconds since the scan started, saturating into `i64`.
fn now_us(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_micros()).unwrap_or(i64::MAX)
}

/// Convert a µs count into a `Duration`, clamping a non-positive value to zero.
fn micros_to_duration(us: i64) -> Duration {
    Duration::from_micros(u64::try_from(us).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nmap_core::build::build_tcp_raw;
    use nmap_core::synscan::{seq32_encode, sport_encode};
    use std::sync::{Arc, Mutex};

    const TH_SYN: u8 = 0x02;
    const TH_ACK: u8 = 0x10;
    const TH_RST: u8 = 0x04;

    /// A scripted capture source: yields the queued reply frames, then reports an idle
    /// link (`Ok(None)` after a short sleep, like the real pcap source).
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

    /// A sender that records frames without transmitting.
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

    fn cfg(ports: Vec<u16>) -> SynScanConfig {
        SynScanConfig {
            ports,
            template: TimingTemplate::Normal,
            max_parallelism: 0,
            eth_included: true,
            base_port: 40000,
            seqmask: 0xABCD_1234,
        }
    }

    /// Build a link-framed reply from `target` back to us for a `tryno == 0` probe.
    fn reply(cfg: &SynScanConfig, scanned_port: u16, flags: u8) -> Vec<u8> {
        let our_seq = seq32_encode(cfg.seqmask, 0);
        let ack = if flags & TH_ACK != 0 {
            our_seq.wrapping_add(1)
        } else {
            0
        };
        let spec = Ipv4Spec::new([127, 0, 0, 1], [127, 0, 0, 1], 64, 0x4242);
        let seg = build_tcp_raw(
            &spec,
            scanned_port,
            sport_encode(cfg.base_port, 0),
            999,
            ack,
            0,
            flags,
            8192,
            0,
            &[],
            &[],
        )
        .unwrap();
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08; // IPv4 ethertype
        frame.extend_from_slice(&seg);
        frame
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn resolves_open_and_closed_from_scripted_replies() {
        let c = cfg(vec![80, 81]);
        // Open port 80 → SYN/ACK; closed port 81 → RST/ACK.
        let frames = Arc::new(Mutex::new(vec![
            reply(&c, 81, TH_RST | TH_ACK),
            reply(&c, 80, TH_SYN | TH_ACK),
        ]));
        let source = MockSource {
            frames: Arc::clone(&frames),
        };
        let sender = MockSender::default();
        let sent = Arc::clone(&sender.sent);

        let host = syn_scan(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, sender, source, &c).await;

        assert_eq!(host.state, HostState::Up);
        let open = host.ports.iter().find(|p| p.number == 80).unwrap();
        assert_eq!(open.state, PortState::Open);
        assert_eq!(open.reason, Reason::ConnAccept);
        let closed = host.ports.iter().find(|p| p.number == 81).unwrap();
        assert_eq!(closed.state, PortState::Closed);
        assert_eq!(closed.reason, Reason::Reset);
        // At least one SYN was actually sent per port.
        assert!(sent.lock().unwrap().len() >= 2);
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn no_reply_resolves_filtered_after_retries() {
        // A single port with an idle link (no scripted frames) must resolve Filtered
        // and terminate — the retransmit/timeout path must not hang. Paranoid-but-fast:
        // use the Insane template so the retry cap (2) and short RTO keep the test quick.
        let mut c = cfg(vec![1234]);
        c.template = TimingTemplate::Insane;
        let source = MockSource {
            frames: Arc::new(Mutex::new(Vec::new())),
        };
        let host = syn_scan(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            MockSender::default(),
            source,
            &c,
        )
        .await;
        let p = host.ports.iter().find(|p| p.number == 1234).unwrap();
        assert_eq!(p.state, PortState::Filtered);
        assert_eq!(p.reason, Reason::NoResponse);
    }
}
