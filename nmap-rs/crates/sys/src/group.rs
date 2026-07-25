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
//! Every raw scan runs on this one engine: [`SynKind`] (`-sS`), [`UdpKind`] (`-sU`), and
//! [`FlagKind`] (`-sA`/`-sW`/`-sM`/`-sF`/`-sN`/`-sX`). A single host is just a group of
//! one, so there is no separate per-host driver to keep in step.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use nmap_core::build::{BuildError, Ipv4Spec};
use nmap_core::classify::{default_port_state, PortState as ClassState, ScanType};
use nmap_core::engine::{GroupScheduler, HostScheduler, Probe};
use nmap_core::flagscan::{build_flag_probe, flags_for, match_flag_response, FlagMatchCtx};
use nmap_core::model::{Host, HostState, Port, PortState, Protocol, Reason};
use nmap_core::payload::UdpPayloads;
use nmap_core::synscan::{build_syn_probe, match_syn_response, MatchCtx};
use nmap_core::timing::{TimingParams, TimingTemplate};
use nmap_core::udpscan::{build_udp_probe_with, match_udp_response, UdpMatchCtx};

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
    /// Build the packet(s) one logical probe of `(dport, tryno)` puts on the wire.
    ///
    /// Usually exactly one. The UDP scan sends **several** — one per payload registered
    /// for the port, all sharing the encoded source port — which is why this returns a
    /// list rather than a single packet. An empty list is treated as a build failure.
    ///
    /// # Errors
    /// Propagates a [`BuildError`] from the underlying packet builder.
    fn build_probes(
        &self,
        spec: &Ipv4Spec,
        base_port: u16,
        dport: u16,
        tryno: u32,
    ) -> Result<Vec<Vec<u8>>, BuildError>;
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
                match kind.build_probes(&spec, base_port, probe.port, probe.tryno) {
                    // One logical probe, one outstanding entry, however many datagrams
                    // it takes — a reply is matched by (port, tryno), and for UDP we
                    // cannot tell which payload provoked it anyway.
                    Ok(pkts) if !pkts.is_empty() => {
                        for pkt in &pkts {
                            let _ = sender.send(pkt);
                        }
                        group.on_send();
                        let now = now_us(start);
                        outstanding.insert(
                            (idx, probe.port, probe.tryno),
                            (now, now.saturating_add(ctx.sched.probe_timeout_us())),
                        );
                    }
                    // A build error, or a kind that produced nothing to send: this
                    // attempt cannot be made, so retire it as a timeout would.
                    Ok(_) | Err(_) => {
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

    fn build_probes(
        &self,
        spec: &Ipv4Spec,
        base_port: u16,
        dport: u16,
        tryno: u32,
    ) -> Result<Vec<Vec<u8>>, BuildError> {
        Ok(vec![build_syn_probe(
            spec,
            base_port,
            dport,
            tryno,
            self.seqmask,
        )?])
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

// ---- UDP scan kind ----------------------------------------------------------------

/// `-sU` UDP scan behavior for the group engine.
///
/// Three things differ from the TCP kinds: the capture filter must also admit **ICMP**
/// (an error is addressed to our source *address*, carrying no port of ours in its own
/// header), a port that never answers is `open|filtered` rather than `filtered`, and one
/// logical probe sends **one datagram per registered payload** for the port.
pub struct UdpKind {
    /// Protocol-specific probe payloads by port, derived from `nmap-service-probes`.
    /// [`UdpPayloads::empty`] reproduces the bare-datagram behavior.
    pub payloads: UdpPayloads,
}

impl UdpKind {
    /// A UDP scan sending protocol-specific payloads from `payloads`.
    #[must_use]
    pub fn new(payloads: UdpPayloads) -> Self {
        Self { payloads }
    }

    /// A UDP scan sending bare, zero-length datagrams.
    #[must_use]
    pub fn bare() -> Self {
        Self {
            payloads: UdpPayloads::empty(),
        }
    }
}

impl RawScanKind for UdpKind {
    fn protocol(&self) -> Protocol {
        Protocol::Udp
    }

    fn build_probes(
        &self,
        spec: &Ipv4Spec,
        base_port: u16,
        dport: u16,
        tryno: u32,
    ) -> Result<Vec<Vec<u8>>, BuildError> {
        // One datagram per payload, all from the same encoded source port — nmap's
        // `for (i < MAX(udp_payload_count(dport), 1))` loop. A port with no registered
        // payload still gets one empty datagram.
        //
        // A payload that cannot be built (only reachable if it would overflow the maximum
        // packet size) is skipped rather than suppressing its siblings; the probe fails
        // only if nothing at all could be built, which the caller retires as a timeout.
        let mut pkts = Vec::new();
        let mut last_err = None;
        for payload in self.payloads.probe_payloads(dport) {
            match build_udp_probe_with(spec, base_port, dport, tryno, payload) {
                Ok(pkt) => pkts.push(pkt),
                Err(e) => last_err = Some(e),
            }
        }
        match last_err {
            Some(e) if pkts.is_empty() => Err(e),
            _ => Ok(pkts),
        }
    }

    fn match_reply(
        &self,
        frame: &[u8],
        eth_included: bool,
        base_port: u16,
        max_tryno: u32,
    ) -> Option<GroupReply> {
        let ctx = UdpMatchCtx {
            base_port,
            max_tryno,
        };
        let r = match_udp_response(frame, eth_included, &ctx)?;
        let reason = match r.state {
            ClassState::Open => Reason::UdpResponse,
            ClassState::Closed => Reason::PortUnreach,
            _ => Reason::NoResponse,
        };
        // `src_ip` is the *quoted* destination for an ICMP error, so an error relayed by
        // a router is still attributed to the host we probed.
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
            default_port_state(ScanType::Udp, false).into(),
            Reason::NoResponse,
        )
    }

    fn bpf(&self, src: Ipv4Addr, base_port: u16, span: u16) -> String {
        format!(
            "(udp and dst host {} and dst portrange {}-{}) or (icmp and dst host {})",
            src,
            base_port,
            base_port.saturating_add(span),
            src
        )
    }
}

// ---- Stateless TCP flag scan kinds --------------------------------------------------

/// `-sA` / `-sW` / `-sM` / `-sF` / `-sN` / `-sX` behavior for the group engine — one
/// impl for all six, parametrized by the scan type (which fixes both the probe's flag
/// combination and how a RST-or-silence is read).
pub struct FlagKind {
    /// Which flag scan this is.
    pub scan: ScanType,
    /// Per-scan random sequence mask.
    pub seqmask: u32,
}

impl RawScanKind for FlagKind {
    fn protocol(&self) -> Protocol {
        Protocol::Tcp
    }

    fn build_probes(
        &self,
        spec: &Ipv4Spec,
        base_port: u16,
        dport: u16,
        tryno: u32,
    ) -> Result<Vec<Vec<u8>>, BuildError> {
        // A non-flag scan type would be a caller bug; an all-clear (Null-scan) probe is
        // the safe reading, never a panic on the scan path.
        let flags = flags_for(self.scan).unwrap_or(0);
        Ok(vec![build_flag_probe(
            spec,
            base_port,
            dport,
            tryno,
            self.seqmask,
            flags,
        )?])
    }

    fn match_reply(
        &self,
        frame: &[u8],
        eth_included: bool,
        base_port: u16,
        max_tryno: u32,
    ) -> Option<GroupReply> {
        let ctx = FlagMatchCtx {
            scan: self.scan,
            base_port,
            max_tryno,
        };
        let r = match_flag_response(frame, eth_included, &ctx)?;
        Some(GroupReply {
            src_ip: r.src_ip,
            port: r.port,
            tryno: r.tryno,
            state: r.state.into(),
            // Every flag-scan reply we act on is a RST, whatever state it implies.
            reason: Reason::Reset,
        })
    }

    fn default_final(&self) -> (PortState, Reason) {
        (
            default_port_state(self.scan, false).into(),
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
    use nmap_core::build::{build_tcp_raw, build_udp_raw};
    use nmap_core::synscan::{seq32_encode, sport_encode};
    use std::sync::{Arc, Mutex};

    const TH_SYN: u8 = 0x02;
    const TH_ACK: u8 = 0x10;
    const TH_RST: u8 = 0x04;

    /// Our address in every unit test; replies are addressed back to it.
    const US: [u8; 4] = [127, 0, 0, 1];

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

    /// Wrap an IP packet in a 14-byte Ethernet header (IPv4 ethertype).
    fn framed(ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f.extend_from_slice(ip);
        f
    }

    /// A TCP reply from `from` back to us for `tryno == 0`, with arbitrary flags/window.
    fn tcp_reply(
        seqmask: u32,
        from: [u8; 4],
        scanned: u16,
        base: u16,
        flags: u8,
        window: u16,
    ) -> Vec<u8> {
        let our_seq = seq32_encode(seqmask, 0);
        let spec = Ipv4Spec::new(from, US, 64, 0x1);
        let seg = build_tcp_raw(
            &spec,
            scanned,
            sport_encode(base, 0),
            5,
            our_seq.wrapping_add(1),
            0,
            flags,
            window,
            0,
            &[],
            &[],
        )
        .unwrap();
        framed(&seg)
    }

    /// A SYN/ACK from `from` back to us for `tryno == 0`.
    fn synack(seqmask: u32, from: [u8; 4], scanned: u16, base: u16) -> Vec<u8> {
        tcp_reply(seqmask, from, scanned, base, TH_SYN | TH_ACK, 8192)
    }

    /// A UDP datagram from `from`'s `scanned` port back to our `tryno == 0` source port.
    fn udp_reply(from: [u8; 4], scanned: u16, base: u16) -> Vec<u8> {
        let spec = Ipv4Spec::new(from, US, 64, 0x1);
        framed(&build_udp_raw(&spec, scanned, sport_encode(base, 0), b"hi").unwrap())
    }

    /// An ICMP type/code error *sent by* `sender`, quoting the UDP probe we sent to
    /// `probed`'s `scanned` port. `sender == probed` is the ordinary case; a different
    /// sender models an intermediate router.
    fn icmp_error(
        sender: [u8; 4],
        probed: [u8; 4],
        icmp_type: u8,
        icmp_code: u8,
        scanned: u16,
        base: u16,
    ) -> Vec<u8> {
        let pspec = Ipv4Spec::new(US, probed, 64, 0x2);
        let probe = build_udp_raw(&pspec, sport_encode(base, 0), scanned, &[]).unwrap();
        let mut icmp = vec![icmp_type, icmp_code, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&probe);
        let mut ip = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, /* proto ICMP */
            0, 0, sender[0], sender[1], sender[2], sender[3], US[0], US[1], US[2], US[3],
        ];
        let total = u16::try_from(ip.len().saturating_add(icmp.len())).unwrap();
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&icmp);
        framed(&ip)
    }

    /// Drive `group_scan` over `targets` with scripted reply frames.
    async fn run<K: RawScanKind>(
        kind: &K,
        targets: &[Ipv4Addr],
        ports: &[u16],
        base: u16,
        frames: Vec<Vec<u8>>,
    ) -> Vec<Host> {
        group_scan(
            Ipv4Addr::from(US),
            targets,
            ports,
            MockSender::default(),
            MockSource {
                frames: Arc::new(Mutex::new(frames)),
            },
            kind,
            TimingTemplate::Insane,
            0,
            base,
            true,
        )
        .await
    }

    /// Look up one port's resolved state on one host.
    fn port_of(hosts: &[Host], host_idx: usize, number: u16) -> &Port {
        hosts[host_idx]
            .ports
            .iter()
            .find(|p| p.number == number)
            .expect("port resolved")
    }

    // ---- SYN --------------------------------------------------------------------

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
        let hosts = run(
            &SynKind { seqmask },
            &[Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3)],
            &[80],
            base,
            vec![
                synack(seqmask, [127, 0, 0, 3], 80, base),
                synack(seqmask, [127, 0, 0, 2], 80, base),
            ],
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
    async fn syn_rst_resolves_closed() {
        let seqmask = 0x5555_AAAA;
        let base = 40000u16;
        let target = Ipv4Addr::new(127, 0, 0, 2);
        let hosts = run(
            &SynKind { seqmask },
            &[target],
            &[81],
            base,
            vec![tcp_reply(
                seqmask,
                target.octets(),
                81,
                base,
                TH_RST | TH_ACK,
                0,
            )],
        )
        .await;
        let p = port_of(&hosts, 0, 81);
        assert_eq!(p.state, PortState::Closed);
        assert_eq!(p.reason, Reason::Reset);
        assert_eq!(hosts[0].state, HostState::Up);
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn no_reply_resolves_filtered_across_hosts() {
        let hosts = run(
            &SynKind { seqmask: 1 },
            &[Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3)],
            &[9],
            40000,
            Vec::new(),
        )
        .await;
        assert_eq!(hosts.len(), 2);
        for h in &hosts {
            let p = h.ports.iter().find(|p| p.number == 9).unwrap();
            assert_eq!(p.state, PortState::Filtered);
        }
    }

    // ---- UDP --------------------------------------------------------------------

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn udp_datagram_resolves_open() {
        let base = 40000u16;
        let target = Ipv4Addr::new(127, 0, 0, 2);
        let hosts = run(
            &UdpKind::bare(),
            &[target],
            &[53],
            base,
            vec![udp_reply(target.octets(), 53, base)],
        )
        .await;
        let p = port_of(&hosts, 0, 53);
        assert_eq!(p.state, PortState::Open);
        assert_eq!(p.reason, Reason::UdpResponse);
        assert_eq!(p.protocol, Protocol::Udp);
    }

    /// Decode `(dest_port, payload)` out of a built IPv4/UDP datagram.
    fn udp_dport_and_payload(pkt: &[u8]) -> (u16, Vec<u8>) {
        let v = nmap_core::recv_validate::validate_packet(pkt).expect("valid IPv4 packet");
        let udp = &pkt[v.data_offset..];
        let dport = u16::from_be_bytes([udp[2], udp[3]]);
        (dport, udp[8..].to_vec())
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn udp_probe_sends_one_datagram_per_registered_payload() {
        use nmap_core::payload::UdpPayloads;
        use nmap_core::probedb::ProbeDb;

        // Port 53 has two payloads, port 161 one, port 9999 none.
        let db = ProbeDb::parse(concat!(
            "Probe UDP A q|\\x01\\x02\\x03|\nports 53\n",
            "Probe UDP B q|\\x04\\x05|\nports 53,161\n",
        ));
        let payloads = UdpPayloads::from_probe_db(&db);
        assert_eq!(payloads.count(53), 2, "test fixture sanity");

        let sent = Arc::new(Mutex::new(Vec::new()));
        let sender = MockSender {
            sent: Arc::clone(&sent),
        };
        // No replies: every port retransmits and then resolves open|filtered. We only
        // care about what went on the wire.
        let _ = group_scan(
            Ipv4Addr::from(US),
            &[Ipv4Addr::new(127, 0, 0, 2)],
            &[53, 161, 9999],
            sender,
            MockSource {
                frames: Arc::new(Mutex::new(Vec::new())),
            },
            &UdpKind::new(payloads),
            TimingTemplate::Insane,
            0,
            40000,
            true,
        )
        .await;

        // Group the distinct payloads observed per destination port.
        let mut by_port: HashMap<u16, Vec<Vec<u8>>> = HashMap::new();
        for pkt in sent.lock().unwrap().iter() {
            let (dport, payload) = udp_dport_and_payload(pkt);
            let seen = by_port.entry(dport).or_default();
            if !seen.contains(&payload) {
                seen.push(payload);
            }
        }

        let mut p53 = by_port.remove(&53).expect("port 53 was probed");
        p53.sort();
        assert_eq!(
            p53,
            vec![vec![0x01, 0x02, 0x03], vec![0x04, 0x05]],
            "both registered payloads for 53 must reach the wire"
        );
        assert_eq!(
            by_port.remove(&161).expect("port 161 was probed"),
            vec![vec![0x04, 0x05]],
            "port 161's single payload"
        );
        assert_eq!(
            by_port.remove(&9999).expect("port 9999 was probed"),
            vec![Vec::<u8>::new()],
            "a port with no payload still gets one bare datagram"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn bare_udp_kind_sends_a_single_empty_datagram() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let _ = group_scan(
            Ipv4Addr::from(US),
            &[Ipv4Addr::new(127, 0, 0, 2)],
            &[53],
            MockSender {
                sent: Arc::clone(&sent),
            },
            MockSource {
                frames: Arc::new(Mutex::new(Vec::new())),
            },
            &UdpKind::bare(),
            TimingTemplate::Insane,
            0,
            40000,
            true,
        )
        .await;
        // Every datagram is empty and addressed to 53 — no payload table, no extras.
        for pkt in sent.lock().unwrap().iter() {
            let (dport, payload) = udp_dport_and_payload(pkt);
            assert_eq!(dport, 53);
            assert!(payload.is_empty(), "bare kind must not attach a payload");
        }
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn udp_no_reply_is_open_filtered() {
        let hosts = run(
            &UdpKind::bare(),
            &[Ipv4Addr::new(127, 0, 0, 2)],
            &[9999],
            40000,
            Vec::new(),
        )
        .await;
        let p = port_of(&hosts, 0, 9999);
        assert_eq!(p.state, PortState::OpenFiltered);
        assert_eq!(p.reason, Reason::NoResponse);
        // open|filtered alone is not proof of life.
        assert_eq!(hosts[0].state, HostState::Down);
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn udp_icmp_errors_demux_by_the_quoted_destination() {
        let base = 40000u16;
        let h2 = Ipv4Addr::new(127, 0, 0, 2);
        let h3 = Ipv4Addr::new(127, 0, 0, 3);
        // .2 answers its own probe with a port-unreachable → closed.
        // .3's probe is answered by a *router*, which is not proof the port is closed —
        // and the verdict must still land on .3, the host we probed, not on the router.
        let hosts = run(
            &UdpKind::bare(),
            &[h2, h3],
            &[53],
            base,
            vec![
                icmp_error([192, 168, 0, 1], h3.octets(), 3, 3, 53, base),
                icmp_error(h2.octets(), h2.octets(), 3, 3, 53, base),
            ],
        )
        .await;
        assert_eq!(port_of(&hosts, 0, 53).state, PortState::Closed);
        assert_eq!(port_of(&hosts, 0, 53).reason, Reason::PortUnreach);
        assert_eq!(port_of(&hosts, 1, 53).state, PortState::Filtered);
    }

    // ---- Stateless TCP flag scans ------------------------------------------------

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn ack_scan_rst_resolves_unfiltered() {
        let base = 40000u16;
        let target = Ipv4Addr::new(127, 0, 0, 2);
        let hosts = run(
            &FlagKind {
                scan: ScanType::Ack,
                seqmask: 7,
            },
            &[target],
            &[80],
            base,
            vec![tcp_reply(7, target.octets(), 80, base, TH_RST | TH_ACK, 0)],
        )
        .await;
        let p = port_of(&hosts, 0, 80);
        assert_eq!(p.state, PortState::Unfiltered);
        assert_eq!(p.reason, Reason::Reset);
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn window_scan_reads_the_reply_window() {
        let base = 40000u16;
        let target = Ipv4Addr::new(127, 0, 0, 2);
        // A non-zero window on the RST means open for `-sW`; zero means closed.
        for (window, want) in [(8192u16, PortState::Open), (0, PortState::Closed)] {
            let hosts = run(
                &FlagKind {
                    scan: ScanType::Window,
                    seqmask: 7,
                },
                &[target],
                &[80],
                base,
                vec![tcp_reply(
                    7,
                    target.octets(),
                    80,
                    base,
                    TH_RST | TH_ACK,
                    window,
                )],
            )
            .await;
            assert_eq!(port_of(&hosts, 0, 80).state, want, "window {window}");
        }
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn flag_scan_no_reply_defaults_are_per_scan_type() {
        // `-sA` treats silence as filtered; `-sF` cannot tell open from filtered.
        for (scan, want) in [
            (ScanType::Ack, PortState::Filtered),
            (ScanType::Fin, PortState::OpenFiltered),
        ] {
            let hosts = run(
                &FlagKind { scan, seqmask: 7 },
                &[Ipv4Addr::new(127, 0, 0, 2)],
                &[1234],
                40000,
                Vec::new(),
            )
            .await;
            let p = port_of(&hosts, 0, 1234);
            assert_eq!(p.state, want, "{scan:?}");
            assert_eq!(p.reason, Reason::NoResponse);
        }
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn flag_scan_demuxes_two_hosts() {
        let base = 40000u16;
        let h2 = Ipv4Addr::new(127, 0, 0, 2);
        let h3 = Ipv4Addr::new(127, 0, 0, 3);
        // Only .3 answers; .2's silence must not be filled in by .3's RST.
        let hosts = run(
            &FlagKind {
                scan: ScanType::Fin,
                seqmask: 7,
            },
            &[h2, h3],
            &[80],
            base,
            vec![tcp_reply(7, h3.octets(), 80, base, TH_RST | TH_ACK, 0)],
        )
        .await;
        assert_eq!(port_of(&hosts, 0, 80).state, PortState::OpenFiltered);
        assert_eq!(port_of(&hosts, 1, 80).state, PortState::Closed);
    }
}
