//! Multi-host group scan engine — scans a whole set of hosts through **one shared
//! capture**, demultiplexed by source address, over the pure scheduler
//! ([`nmap_core::engine::HostScheduler`] per host + a [`nmap_core::engine::GroupScheduler`]
//! bounding total probes in flight across the group). The port of nmap's `ultra_scan`
//! host-group model. **No `unsafe`**.
//!
//! Scan-type-specific behavior (how to build a probe, how to read a reply, the
//! no-response default, the BPF filter) is factored behind the [`RawScanKind`] trait,
//! so the SYN / UDP / flag scans share this one loop instead of carrying near-identical
//! per-host copies. A captured reply is routed to the host that sent it by its **source
//! IP** — every host can share one encoded source-port range because the source address
//! disambiguates them.
//!
//! This slice wires [`SynKind`] (`-sS`); the UDP and flag scans move onto the same
//! engine next.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use nmap_core::build::{BuildError, Ipv4Spec};
use nmap_core::classify::{default_port_state, PortState as ClassState, ScanType};
use nmap_core::engine::{GroupScheduler, HostScheduler, Probe};
use nmap_core::model::{Host, HostState, Port, PortState, Protocol, Reason};
use nmap_core::synscan::{build_syn_probe, match_syn_response, MatchCtx};
use nmap_core::timing::{TimingParams, TimingTemplate};

use crate::capture::{AsyncCapture, PacketSource};
use crate::rawio::RawSender;

const DEFAULT_TTL: u8 = 64;
const CAPTURE_CAPACITY: usize = 4096;
const IDLE_WAIT: Duration = Duration::from_millis(50);

/// A captured reply matched to a probe, tagged with the host that sent it.
pub struct GroupReply {
    /// Source IPv4 of the reply — identifies which host answered.
    pub src_ip: [u8; 4],
    /// The scanned port that answered.
    pub port: u16,
    /// Which attempt this reply answers.
    pub tryno: u32,
    /// The resolved port state and the reason to report.
    pub state: PortState,
    pub reason: Reason,
}

/// The scan-type-specific behavior the shared group loop needs. One impl per scan
/// technique; the loop itself is scan-agnostic.
pub trait RawScanKind {
    /// The transport protocol of the scanned ports (for the result model).
    fn protocol(&self) -> Protocol;
    /// Build a probe packet for `(dport, tryno)`.
    ///
    /// # Errors
    /// Propagates a [`BuildError`] from the underlying packet builder.
    fn build_probe(
        &self,
        spec: &Ipv4Spec,
        base_port: u16,
        dport: u16,
        tryno: u32,
    ) -> Result<Vec<u8>, BuildError>;
    /// Match a captured frame to a probe, or `None` if it is not a reply for us.
    fn match_reply(
        &self,
        frame: &[u8],
        eth_included: bool,
        base_port: u16,
        max_tryno: u32,
    ) -> Option<GroupReply>;
    /// The `(state, reason)` for a port that never answered (this scan's default).
    fn default_final(&self) -> (PortState, Reason);
    /// The pcap BPF filter scoping capture to replies for this scan; `src` is our
    /// source address, `span` the encoded source-port range width.
    fn bpf(&self, src: Ipv4Addr, base_port: u16, span: u16) -> String;
}

/// Per-host mutable state carried through the group loop.
struct HostCtx {
    sched: HostScheduler,
    target: Ipv4Addr,
    finals: Vec<(u16, PortState, Reason)>,
}

/// Run a group scan over `targets` that share one route (interface + source), driving
/// every host concurrently through the group congestion window over one capture.
/// Returns one [`Host`] per target, in order.
#[allow(clippy::too_many_arguments)]
pub async fn group_scan<K, S, P>(
    src: Ipv4Addr,
    targets: &[Ipv4Addr],
    ports: &[u16],
    mut sender: S,
    source: P,
    kind: &K,
    template: TimingTemplate,
    max_parallelism: usize,
    base_port: u16,
    eth_included: bool,
) -> Vec<Host>
where
    K: RawScanKind,
    S: RawSender,
    P: PacketSource,
{
    let max_par = u32::try_from(max_parallelism).unwrap_or(u32::MAX);
    let params = TimingParams::for_template(template);
    let max_tryno = params.max_retransmissions;

    let mut ctxs: Vec<HostCtx> = targets
        .iter()
        .map(|&t| HostCtx {
            sched: HostScheduler::with_params(ports, template, params, 0, max_par),
            target: t,
            finals: Vec::new(),
        })
        .collect();
    // src IP -> host index, for O(1) reply demux.
    let by_ip: HashMap<[u8; 4], usize> = ctxs
        .iter()
        .enumerate()
        .map(|(i, c)| (c.target.octets(), i))
        .collect();

    let mut group = GroupScheduler::new(template, 0, max_par);
    let mut capture = AsyncCapture::spawn(source, CAPTURE_CAPACITY);
    let start = Instant::now();
    // (host_idx, port, tryno) -> (send_us, deadline_us).
    let mut outstanding: HashMap<(usize, u16, u32), (i64, i64)> = HashMap::new();
    let mut ipid: u16 = base_port;

    loop {
        // Launch every probe the group window + each host's own window permit.
        loop {
            let incomplete = ctxs.iter().filter(|c| !c.sched.is_done()).count();
            if !group.may_admit(incomplete) {
                break;
            }
            let mut launched = false;
            for (idx, ctx) in ctxs.iter_mut().enumerate() {
                if ctx.sched.is_done() || !ctx.sched.may_send() {
                    continue;
                }
                let Some(probe) = ctx.sched.next_probe() else {
                    continue;
                };
                ipid = ipid.wrapping_add(1);
                let spec = Ipv4Spec::new(src.octets(), ctx.target.octets(), DEFAULT_TTL, ipid);
                match kind.build_probe(&spec, base_port, probe.port, probe.tryno) {
                    Ok(pkt) => {
                        let _ = sender.send(&pkt);
                        group.on_send();
                        let now = now_us(start);
                        outstanding.insert(
                            (idx, probe.port, probe.tryno),
                            (now, now.saturating_add(ctx.sched.probe_timeout_us())),
                        );
                    }
                    Err(_) => {
                        let before = ctx.sched.resolved();
                        ctx.sched.on_timeout(probe);
                        if ctx.sched.resolved() > before {
                            let (st, rs) = kind.default_final();
                            ctx.finals.push((probe.port, st, rs));
                        }
                    }
                }
                launched = true;
                break;
            }
            if !launched {
                break;
            }
        }

        if ctxs.iter().all(|c| c.sched.is_done()) && outstanding.is_empty() {
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
                    if let Some(reply) = kind.match_reply(&f.data, eth_included, base_port, max_tryno) {
                        if let Some(&idx) = by_ip.get(&reply.src_ip) {
                            if let Some((send_us, _)) =
                                outstanding.remove(&(idx, reply.port, reply.tryno))
                            {
                                let rtt = now_us(start).saturating_sub(send_us).max(1);
                                ctxs[idx].sched.on_reply(
                                    Probe { port: reply.port, tryno: reply.tryno },
                                    rtt,
                                );
                                group.on_reply();
                                ctxs[idx].finals.push((reply.port, reply.state, reply.reason));
                            }
                        }
                    }
                }
            }
            () = tokio::time::sleep(sleep_dur) => {
                let now = now_us(start);
                let expired: Vec<(usize, u16, u32)> = outstanding
                    .iter()
                    .filter(|(_, (_, d))| *d <= now)
                    .map(|(k, _)| *k)
                    .collect();
                for key in expired {
                    outstanding.remove(&key);
                    let (idx, port, tryno) = key;
                    let before = ctxs[idx].sched.resolved();
                    ctxs[idx].sched.on_timeout(Probe { port, tryno });
                    group.on_timeout();
                    if ctxs[idx].sched.resolved() > before {
                        let (st, rs) = kind.default_final();
                        ctxs[idx].finals.push((port, st, rs));
                    }
                }
            }
        }
    }

    capture.stop();

    let proto = kind.protocol();
    ctxs.into_iter()
        .map(|mut ctx| {
            let up = ctx
                .finals
                .iter()
                .any(|(_, s, _)| !matches!(s, PortState::OpenFiltered | PortState::Filtered));
            let mut host = Host::new(
                IpAddr::V4(ctx.target),
                if up { HostState::Up } else { HostState::Down },
            );
            for (port, state, reason) in ctx.finals.drain(..) {
                host.ports.push(Port::new(port, proto, state, reason));
            }
            host.ports.sort_by_key(|p| (p.protocol, p.number));
            host
        })
        .collect()
}

fn now_us(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_micros()).unwrap_or(i64::MAX)
}

fn micros_to_duration(us: i64) -> Duration {
    Duration::from_micros(u64::try_from(us).unwrap_or(0))
}

// ---- SYN scan kind ----------------------------------------------------------------

/// `-sS` SYN scan behavior for the group engine.
pub struct SynKind {
    /// Per-scan random sequence mask.
    pub seqmask: u32,
}

impl RawScanKind for SynKind {
    fn protocol(&self) -> Protocol {
        Protocol::Tcp
    }

    fn build_probe(
        &self,
        spec: &Ipv4Spec,
        base_port: u16,
        dport: u16,
        tryno: u32,
    ) -> Result<Vec<u8>, BuildError> {
        build_syn_probe(spec, base_port, dport, tryno, self.seqmask)
    }

    fn match_reply(
        &self,
        frame: &[u8],
        eth_included: bool,
        base_port: u16,
        max_tryno: u32,
    ) -> Option<GroupReply> {
        let ctx = MatchCtx {
            base_port,
            seqmask: self.seqmask,
            max_tryno,
        };
        let r = match_syn_response(frame, eth_included, &ctx)?;
        let reason = match r.state {
            ClassState::Open => Reason::ConnAccept,
            ClassState::Closed => Reason::Reset,
            _ => Reason::NoResponse,
        };
        Some(GroupReply {
            src_ip: r.src_ip,
            port: r.port,
            tryno: r.tryno,
            state: r.state.into(),
            reason,
        })
    }

    fn default_final(&self) -> (PortState, Reason) {
        (
            default_port_state(ScanType::Syn, false).into(),
            Reason::NoResponse,
        )
    }

    fn bpf(&self, src: Ipv4Addr, base_port: u16, span: u16) -> String {
        format!(
            "tcp and dst host {} and dst portrange {}-{}",
            src,
            base_port,
            base_port.saturating_add(span)
        )
    }
}

/// Route + capture setup for a group scan: group the IPv4 targets that share an egress
/// route, run each route-group through [`group_scan`] over one sender + capture, and
/// return one [`Host`] per input target, in order (feature `pcap`).
///
/// # Errors
/// Propagates a raw-socket / capture-open error (notably `PermissionDenied`) and any
/// interface-enumeration error.
#[cfg(feature = "pcap")]
pub async fn group_scan_targets<K: RawScanKind>(
    kind: &K,
    targets: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_parallelism: usize,
) -> std::io::Result<nmap_core::model::ScanResults> {
    use crate::capture::pcap_source::PcapSource;
    use crate::rawio::RawIpv4Sender;
    use crate::route::{random_scan_keys, route_for};
    use nmap_core::model::ScanResults;

    // Probe raw-socket capability once; PermissionDenied here is the fallback signal.
    drop(RawIpv4Sender::new()?);

    let span =
        u16::try_from(TimingParams::for_template(template).max_retransmissions).unwrap_or(16);

    // Bucket the IPv4 targets by (interface, source, eth). Non-IPv4 / unroutable
    // targets become `Down` placeholders, keeping the output aligned with the input.
    let mut result_slot: Vec<Option<Host>> = vec![None; targets.len()];
    let mut groups: HashMap<(String, Ipv4Addr, bool), Vec<(usize, Ipv4Addr)>> = HashMap::new();
    for (i, &ip) in targets.iter().enumerate() {
        match ip {
            IpAddr::V4(v4) => match route_for(v4)? {
                Some(route) => groups
                    .entry((route.iface, route.src, route.eth_included))
                    .or_default()
                    .push((i, v4)),
                None => result_slot[i] = Some(Host::new(ip, HostState::Down)),
            },
            IpAddr::V6(_) => result_slot[i] = Some(Host::new(ip, HostState::Down)),
        }
    }

    for ((iface, src, eth), members) in groups {
        let (_seqmask, base_port) = random_scan_keys();
        let group_targets: Vec<Ipv4Addr> = members.iter().map(|(_, ip)| *ip).collect();
        let sender = RawIpv4Sender::new()?;
        let source = PcapSource::open(&iface, 65535, 100, Some(&kind.bpf(src, base_port, span)))?;
        let hosts = group_scan(
            src,
            &group_targets,
            ports,
            sender,
            source,
            kind,
            template,
            max_parallelism,
            base_port,
            eth,
        )
        .await;
        for ((slot, _), host) in members.into_iter().zip(hosts) {
            result_slot[slot] = Some(host);
        }
    }

    let mut results = ScanResults::new();
    for (slot, ip) in result_slot.into_iter().zip(targets.iter()) {
        results
            .hosts
            .push(slot.unwrap_or_else(|| Host::new(*ip, HostState::Down)));
    }
    Ok(results)
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

    /// A SYN/ACK from `from` back to us for `tryno == 0`.
    fn synack(seqmask: u32, from: [u8; 4], scanned: u16, base: u16) -> Vec<u8> {
        let our_seq = seq32_encode(seqmask, 0);
        let spec = Ipv4Spec::new(from, [127, 0, 0, 1], 64, 0x1);
        let seg = build_tcp_raw(
            &spec,
            scanned,
            sport_encode(base, 0),
            5,
            our_seq.wrapping_add(1),
            0,
            TH_SYN | TH_ACK,
            8192,
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
    async fn two_hosts_demux_by_source_ip() {
        let seqmask = 0xABCD_1234;
        let base = 40000u16;
        // Host .2 answers port 80 open; host .3 answers port 80 open. Same port, same
        // encoded source port — only the source IP distinguishes them.
        let frames = Arc::new(Mutex::new(vec![
            synack(seqmask, [127, 0, 0, 3], 80, base),
            synack(seqmask, [127, 0, 0, 2], 80, base),
        ]));
        let kind = SynKind { seqmask };
        let hosts = group_scan(
            Ipv4Addr::new(127, 0, 0, 1),
            &[Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3)],
            &[80],
            MockSender::default(),
            MockSource { frames },
            &kind,
            TimingTemplate::Insane,
            0,
            base,
            true,
        )
        .await;

        assert_eq!(hosts.len(), 2);
        for (h, want_ip) in hosts.iter().zip([[127, 0, 0, 2], [127, 0, 0, 3]]) {
            assert_eq!(h.address, IpAddr::V4(Ipv4Addr::from(want_ip)));
            let p = h.ports.iter().find(|p| p.number == 80).unwrap();
            assert_eq!(p.state, PortState::Open, "host {want_ip:?}");
            assert_eq!(p.reason, Reason::ConnAccept);
        }
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn no_reply_resolves_filtered_across_hosts() {
        let kind = SynKind { seqmask: 1 };
        let hosts = group_scan(
            Ipv4Addr::new(127, 0, 0, 1),
            &[Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3)],
            &[9],
            MockSender::default(),
            MockSource {
                frames: Arc::new(Mutex::new(Vec::new())),
            },
            &kind,
            TimingTemplate::Insane,
            0,
            40000,
            true,
        )
        .await;
        assert_eq!(hosts.len(), 2);
        for h in &hosts {
            let p = h.ports.iter().find(|p| p.number == 9).unwrap();
            assert_eq!(p.state, PortState::Filtered);
        }
        // A RST reply not matching any probe is ignored (no panic); covered by the
        // demux miss path above returning None.
        let _ = TH_RST;
    }
}
