//! Multi-host group scan engine — scans a whole set of hosts through **one shared
//! capture**, demultiplexed by source address, over the pure scheduler
//! ([`nmap_core::engine::HostScheduler`] per host + a [`nmap_core::engine::GroupScheduler`]
//! bounding total probes in flight across the group). The port of nmap's `ultra_scan`
//! host-group model. **No `unsafe`**.
//!
//! Scan-type-specific behavior (how to build a probe, how to read a reply, the
//! no-response default) is factored behind the [`RawScanKind`] trait, so the SYN / UDP /
//! flag scans share this one loop instead of carrying near-identical per-host copies. A
//! captured reply is routed to the host that sent it by its **source IP** — every host can
//! share one encoded source-port range because the source address disambiguates them.
//!
//! Every raw scan runs on this one engine: [`SynKind`] (`-sS`), [`UdpKind`] (`-sU`), and
//! [`FlagKind`] (`-sA`/`-sW`/`-sM`/`-sF`/`-sN`/`-sX`). A single host is just a group of
//! one, so there is no separate per-host driver to keep in step.
//!
//! **Both IP families run on it** (IPv6 scans step d). nmap's `ultra_scan` is one loop
//! for IPv4 and IPv6: `sendIPScanProbe` builds either family's packet from the same
//! choices and `get_pcap_result` reads either family's reply. The engine is generic over
//! a [`ScanFamily`], implemented by the address type itself ([`Ipv4Addr`],
//! [`Ipv6Addr`]); a family supplies only what differs: its probe spec, its capture
//! filter ([`ScanFamily::reply_filter`]) and, through `core::ipfamily`, how its replies
//! are read. The kinds are written once for both.

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use nmap_core::build::{BuildError, Ipv4Spec, Ipv6Spec, PacketOverrides, ProbeSpec};
use nmap_core::classify::{default_port_state, ScanType};
use nmap_core::engine::{GroupScheduler, HostScheduler, Probe};
use nmap_core::flagscan::{build_flag_probe, flags_for, match_flag_response, FlagMatchCtx};
use nmap_core::ipfamily::IpFamily;
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

/// An IP family the engine scans, implemented by its address type ([`Ipv4Addr`],
/// [`Ipv6Addr`]). See the module docs.
pub trait ScanFamily: Copy + Eq + Hash + Debug + Display + Into<IpAddr> + Send + Sync {
    /// The address as the core matchers take it (`[u8; 4]`, `[u8; 16]`), which is what
    /// reads this family's replies (`core::ipfamily`).
    type Octets: IpFamily + Hash;
    /// The spec this family's probes are built from.
    type Spec: ProbeSpec;

    /// The address's bytes.
    fn octets(self) -> Self::Octets;

    /// The spec of one probe from `src` to `dst`: what the scan engine sends, then the
    /// operator's `overrides`. The one site where `--ttl`, `--badsum` and `-S` take
    /// effect. `ipid` is the IPv4 identification; IPv6 has none.
    fn probe_spec(src: Self, dst: Self, ipid: u16, overrides: PacketOverrides) -> Self::Spec;

    /// The capture filter for replies to `src`: `proto` datagrams to our encoded source
    /// ports `base_port..=base_port + span`, and the family's ICMP errors (an error
    /// quoting our probe is addressed to our *address* and carries no port of ours in
    /// its own header, so a port-scoped filter alone would drop it and the port would
    /// fall back to the no-response default).
    fn reply_filter(src: Self, proto: Protocol, base_port: u16, span: u16) -> String;
}

/// libpcap's name for a scanned transport, and its IP protocol number.
fn transport(proto: Protocol) -> (&'static str, u8) {
    match proto {
        Protocol::Tcp => ("tcp", 6),
        Protocol::Udp => ("udp", 17),
        Protocol::Sctp => ("sctp", 132),
    }
}

impl ScanFamily for Ipv4Addr {
    type Octets = [u8; 4];
    type Spec = Ipv4Spec;

    fn octets(self) -> [u8; 4] {
        Ipv4Addr::octets(&self)
    }

    fn probe_spec(src: Self, dst: Self, ipid: u16, overrides: PacketOverrides) -> Ipv4Spec {
        Ipv4Spec::new(src.octets(), dst.octets(), DEFAULT_TTL, ipid).with_overrides(overrides)
    }

    fn reply_filter(src: Self, proto: Protocol, base_port: u16, span: u16) -> String {
        format!(
            "({} and dst host {} and dst portrange {}-{}) or (icmp and dst host {})",
            transport(proto).0,
            src,
            base_port,
            base_port.saturating_add(span),
            src
        )
    }
}

impl ScanFamily for Ipv6Addr {
    type Octets = [u8; 16];
    type Spec = Ipv6Spec;

    fn octets(self) -> [u8; 16] {
        Ipv6Addr::octets(&self)
    }

    fn probe_spec(src: Self, dst: Self, _ipid: u16, overrides: PacketOverrides) -> Ipv6Spec {
        Ipv6Spec::new(src.octets(), dst.octets()).with_overrides(overrides)
    }

    /// Written over the fixed header's bytes rather than libpcap's `tcp`/`udp` and
    /// `portrange`, which see only the first next header (or a fragment header and
    /// then it) and read ports at offset 40. A reply whose first next header is our
    /// transport must be to one of our source ports, as for IPv4. Anything whose first
    /// next header is neither TCP nor UDP is let through: ICMPv6, and a reply behind
    /// extension headers, whose ports only the walk can find. The matchers validate
    /// and match every packet, so letting more through changes nothing they decide
    /// (`scan6-filter-admits-extension-headers`).
    fn reply_filter(src: Self, proto: Protocol, base_port: u16, span: u16) -> String {
        format!(
            "dst host {} and ((ip6[6:1] = {} and ip6[42:2] >= {} and ip6[42:2] <= {}) \
             or (ip6[6:1] != 6 and ip6[6:1] != 17))",
            src,
            transport(proto).1,
            base_port,
            base_port.saturating_add(span),
        )
    }
}

/// A captured reply matched to a probe, tagged with the host that sent it.
pub struct GroupReply<A = [u8; 4]> {
    /// Source address of the reply — identifies which host answered. For an ICMP error
    /// it is the quoted destination, so an error a router relays is still attributed to
    /// the host we probed.
    pub src_ip: A,
    /// The scanned port that answered.
    pub port: u16,
    /// Which attempt this reply answers.
    pub tryno: u32,
    /// The resolved port state and the reason to report.
    pub state: PortState,
    pub reason: Reason,
}

/// The per-scan constants every matcher needs, gathered so the trait method does not grow
/// a parameter per scan feature.
#[derive(Debug, Clone, Copy)]
pub struct MatchParams<A = [u8; 4]> {
    /// Our own source address — required to confirm that the packet quoted inside an ICMP
    /// error is one we actually sent.
    pub our_ip: A,
    /// Base source port; the attempt is `sport - base_port`.
    pub base_port: u16,
    /// Highest attempt number in flight.
    pub max_tryno: u32,
}

/// The scan-type-specific behavior the shared group loop needs. One impl per scan
/// technique, for both families; the loop itself is scan-agnostic.
pub trait RawScanKind {
    /// The transport protocol of the scanned ports (for the result model, and the
    /// capture filter).
    fn protocol(&self) -> Protocol;
    /// Build the packet(s) one logical probe of `(dport, tryno)` puts on the wire, in
    /// `spec`'s family.
    ///
    /// Usually exactly one. The UDP scan sends **several** — one per payload registered
    /// for the port, all sharing the encoded source port — which is why this returns a
    /// list rather than a single packet. An empty list is treated as a build failure.
    ///
    /// # Errors
    /// Propagates a [`BuildError`] from the underlying packet builder.
    fn build_probes<S: ProbeSpec>(
        &self,
        spec: &S,
        base_port: u16,
        dport: u16,
        tryno: u32,
    ) -> Result<Vec<Vec<u8>>, BuildError>;
    /// Match a captured frame to a probe, or `None` if it is not a reply for us. The
    /// family is `params`': an IPv4 scan reads IPv4 replies and ICMPv4 errors, an IPv6
    /// scan IPv6 replies and ICMPv6 errors.
    fn match_reply<A: IpFamily>(
        &self,
        frame: &[u8],
        eth_included: bool,
        params: &MatchParams<A>,
    ) -> Option<GroupReply<A>>;
    /// The `(state, reason)` for a port that never answered (this scan's default).
    fn default_final(&self) -> (PortState, Reason);
}

/// Per-host mutable state carried through the group loop.
struct HostCtx<A> {
    sched: HostScheduler,
    target: A,
    finals: Vec<(u16, PortState, Reason)>,
    /// `--scan-delay`: earliest time (microseconds since the scan started) this
    /// host may be probed again. Per host, as nmap's scan delay is — `-T0`
    /// waits five minutes between probes *to a host*.
    next_send_us: i64,
}

/// Run a group scan over `targets` that share one route (interface + source), driving
/// every host concurrently through the group congestion window over one capture.
/// Returns one [`Host`] per target, in order. The family is the addresses' (`src`'s):
/// `S` must put that family's packets on the wire, and `P` capture its replies.
#[allow(clippy::too_many_arguments)]
pub async fn group_scan<A, K, S, P>(
    src: A,
    targets: &[A],
    ports: &[u16],
    mut sender: S,
    source: P,
    kind: &K,
    template: TimingTemplate,
    params: TimingParams,
    max_parallelism: usize,
    base_port: u16,
    eth_included: bool,
    overrides: PacketOverrides,
) -> Vec<Host>
where
    A: ScanFamily,
    K: RawScanKind,
    S: RawSender,
    P: PacketSource,
{
    let max_par = u32::try_from(max_parallelism).unwrap_or(u32::MAX);
    // `params` arrives resolved (template + explicit --*-rtt-timeout /
    // --max-retries / --scan-delay). It used to be re-derived from the template
    // right here, which silently dropped every explicit knob.
    let max_tryno = params.max_retransmissions;
    let scan_delay_us = params.scan_delay_ms.max(0).saturating_mul(1000);
    // `--min-parallelism`; the CLI used to pass a hardcoded 0 here.
    let min_par = params.min_parallelism;
    let match_params = MatchParams {
        our_ip: src.octets(),
        base_port,
        max_tryno,
    };

    let mut ctxs: Vec<HostCtx<A>> = targets
        .iter()
        .map(|&t| HostCtx {
            sched: HostScheduler::with_params(ports, template, params, min_par, max_par),
            target: t,
            finals: Vec::new(),
            next_send_us: 0,
        })
        .collect();
    // src IP -> host index, for O(1) reply demux.
    let by_ip: HashMap<A::Octets, usize> = ctxs
        .iter()
        .enumerate()
        .map(|(i, c)| (c.target.octets(), i))
        .collect();

    let mut group = GroupScheduler::new(template, min_par, max_par);
    let mut capture = AsyncCapture::spawn(source, CAPTURE_CAPACITY);
    let start = Instant::now();
    // (host_idx, port, tryno) -> (send_us, deadline_us).
    let mut outstanding: HashMap<(usize, u16, u32), (i64, i64)> = HashMap::new();
    let mut ipid: u16 = base_port;
    // Once the capture has ended (a pcap read error), `recv` is ready at once
    // with `None` forever: polling it would spin this loop until the next
    // probe deadline. The error is kept for `-d`.
    let mut capture_live = true;

    loop {
        // Launch every probe the group window + each host's own window permit.
        loop {
            let incomplete = ctxs.iter().filter(|c| !c.sched.is_done()).count();
            if !group.may_admit(incomplete) {
                break;
            }
            let mut launched = false;
            let now_launch = now_us(start);
            for (idx, ctx) in ctxs.iter_mut().enumerate() {
                if ctx.sched.is_done() || !ctx.sched.may_send() {
                    continue;
                }
                // `--scan-delay`: skip this host, not the whole group, so one
                // host's delay does not stall the others.
                if ctx.next_send_us > now_launch {
                    continue;
                }
                let Some(probe) = ctx.sched.next_probe() else {
                    continue;
                };
                ipid = ipid.wrapping_add(1);
                // The one site where --ttl / --badsum / -S take effect. A default
                // `overrides` leaves these bytes exactly as before the options
                // existed, which is what makes the wiring safe to review.
                let spec = A::probe_spec(src, ctx.target, ipid, overrides);
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
                        ctx.next_send_us = now.saturating_add(scan_delay_us);
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
        // Wake for whichever comes first: the next probe timeout, or the moment
        // a scan-delayed host is allowed to send again. Leaving the delay out
        // would sleep for IDLE_WAIT with work ready, making a delayed scan
        // slower than it was asked to be.
        let next_deadline = outstanding
            .values()
            .map(|(_, d)| *d)
            .chain(
                ctxs.iter()
                    .filter(|c| !c.sched.is_done() && c.next_send_us > now)
                    .map(|c| c.next_send_us),
            )
            .min();
        let sleep_dur = next_deadline
            .map(|d| micros_to_duration(d.saturating_sub(now)))
            .unwrap_or(IDLE_WAIT);

        tokio::select! {
            frame = capture.recv(), if capture_live => {
                if frame.is_none() {
                    capture_live = false;
                    nmap_core::debug!(
                        1,
                        "packet capture ended: {}",
                        capture.error().unwrap_or_else(|| "closed".into())
                    );
                }
                if let Some(f) = frame {
                    if let Some(reply) = kind.match_reply(&f.data, eth_included, &match_params) {
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
                ctx.target.into(),
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

    fn build_probes<S: ProbeSpec>(
        &self,
        spec: &S,
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

    fn match_reply<A: IpFamily>(
        &self,
        frame: &[u8],
        eth_included: bool,
        params: &MatchParams<A>,
    ) -> Option<GroupReply<A>> {
        let ctx = MatchCtx {
            our_ip: params.our_ip,
            base_port: params.base_port,
            seqmask: self.seqmask,
            max_tryno: params.max_tryno,
        };
        let r = match_syn_response(frame, eth_included, &ctx)?;
        Some(GroupReply {
            src_ip: r.src_ip,
            port: r.port,
            tryno: r.tryno,
            state: r.state.into(),
            // The matcher reports how it matched — `syn-ack`, `reset`, or the specific
            // ICMP unreachable code — rather than the driver guessing from the state.
            reason: r.reason,
        })
    }

    fn default_final(&self) -> (PortState, Reason) {
        (
            default_port_state(ScanType::Syn, false).into(),
            Reason::NoResponse,
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

    fn build_probes<S: ProbeSpec>(
        &self,
        spec: &S,
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

    fn match_reply<A: IpFamily>(
        &self,
        frame: &[u8],
        eth_included: bool,
        params: &MatchParams<A>,
    ) -> Option<GroupReply<A>> {
        let ctx = UdpMatchCtx {
            our_ip: params.our_ip,
            base_port: params.base_port,
            max_tryno: params.max_tryno,
        };
        let r = match_udp_response(frame, eth_included, &ctx)?;
        // `src_ip` is the *quoted* destination for an ICMP error, so an error relayed by
        // a router is still attributed to the host we probed.
        Some(GroupReply {
            src_ip: r.src_ip,
            port: r.port,
            tryno: r.tryno,
            state: r.state.into(),
            reason: r.reason,
        })
    }

    fn default_final(&self) -> (PortState, Reason) {
        (
            default_port_state(ScanType::Udp, false).into(),
            Reason::NoResponse,
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

    fn build_probes<S: ProbeSpec>(
        &self,
        spec: &S,
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

    fn match_reply<A: IpFamily>(
        &self,
        frame: &[u8],
        eth_included: bool,
        params: &MatchParams<A>,
    ) -> Option<GroupReply<A>> {
        let ctx = FlagMatchCtx {
            scan: self.scan,
            our_ip: params.our_ip,
            base_port: params.base_port,
            seqmask: self.seqmask,
            max_tryno: params.max_tryno,
        };
        let r = match_flag_response(frame, eth_included, &ctx)?;
        Some(GroupReply {
            src_ip: r.src_ip,
            port: r.port,
            tryno: r.tryno,
            state: r.state.into(),
            reason: r.reason,
        })
    }

    fn default_final(&self) -> (PortState, Reason) {
        (
            default_port_state(self.scan, false).into(),
            Reason::NoResponse,
        )
    }
}

/// Route + capture setup for a group scan: group the targets that share an egress route,
/// run each route-group through [`group_scan`] over one sender + capture, and return one
/// [`Host`] per input target, in order (feature `pcap`).
///
/// IPv4 goes out an `IP_HDRINCL` raw socket. IPv6 goes out at layer 2, framed for its
/// link ([`scan_route_group6`]): over a loopback with no neighbor to find, over Ethernet
/// to each target's next hop as neighbor discovery finds it, over a link with no
/// link-layer addresses as it is. A target that has no route is reported down, as for
/// IPv4.
///
/// # Errors
/// Propagates a raw-socket / capture-open error (notably `PermissionDenied`) and any
/// interface-enumeration error. `Unsupported` for an IPv6 route over a datalink nmap
/// does not send on, or over an Ethernet interface with no MAC.
#[cfg(feature = "pcap")]
pub async fn group_scan_targets<K: RawScanKind>(
    kind: &K,
    targets: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    params: TimingParams,
    max_parallelism: usize,
    overrides: PacketOverrides,
) -> std::io::Result<nmap_core::model::ScanResults> {
    use crate::route::{route_for, route_for6};
    let timing = (template, params, max_parallelism);
    group_scan_targets_routed(
        kind, targets, ports, timing, overrides, route_for, route_for6,
    )
    .await
}

/// [`group_scan_targets`] with the routes given: `route4` and `route6` stand in for the
/// host's route table. For a privileged test of a link whose routes the kernel cannot
/// hold (an IPv6 neighbor on a TAP interface in a kernel without IPv6).
///
/// # Errors
/// As [`group_scan_targets`].
#[cfg(feature = "pcap")]
pub async fn group_scan_targets_routed<K: RawScanKind>(
    kind: &K,
    targets: &[IpAddr],
    ports: &[u16],
    (template, params, max_parallelism): (TimingTemplate, TimingParams, usize),
    overrides: PacketOverrides,
    route4: impl FnMut(Ipv4Addr) -> std::io::Result<Option<crate::route::Route>>,
    route6: impl FnMut(Ipv6Addr) -> std::io::Result<Option<crate::route::Route6>>,
) -> std::io::Result<nmap_core::model::ScanResults> {
    use crate::rawio::RawIpv4Sender;
    use nmap_core::model::ScanResults;

    // Probe raw-socket capability once; PermissionDenied here is the fallback signal.
    // The same privilege opens the IPv6 path's capture handle for sending.
    drop(RawIpv4Sender::new()?);

    let span = u16::try_from(params.max_retransmissions).unwrap_or(16);

    // Unroutable targets become `Down` placeholders, keeping the output aligned with
    // the input.
    let buckets = bucket_targets(targets, route4, route6)?;
    let mut result_slot: Vec<Option<Host>> = vec![None; targets.len()];
    let run = RouteGroupRun {
        ports,
        template,
        params,
        max_parallelism,
        span,
        overrides,
    };
    for ((iface, src), members) in buckets.v4 {
        let sender = RawIpv4Sender::new()?;
        run.scan(kind, &iface, src, &members, sender, &mut result_slot)
            .await?;
    }
    for ((iface, src), group) in buckets.v6 {
        scan_route_group6(&run, kind, &iface, src, &group, &mut result_slot).await?;
    }

    let mut results = ScanResults::new();
    for (slot, ip) in result_slot.into_iter().zip(targets.iter()) {
        results
            .hosts
            .push(slot.unwrap_or_else(|| Host::new(*ip, HostState::Down)));
    }
    Ok(results)
}

/// A scan's targets by route: the route-groups of each family, keyed by (interface,
/// source), each member with its slot in the input. A target with no route is in
/// neither, and is reported down.
#[cfg(any(feature = "pcap", test))]
#[derive(Debug, Default)]
struct Buckets {
    v4: HashMap<(String, Ipv4Addr), Vec<(usize, Ipv4Addr)>>,
    v6: HashMap<(String, Ipv6Addr), Group6>,
}

/// An IPv6 route-group: the targets that leave by one interface from one source.
#[cfg(any(feature = "pcap", test))]
#[derive(Debug, Default)]
struct Group6 {
    /// The interface's MAC, which Ethernet (and Linux's loopback) framing needs.
    src_mac: Option<[u8; 6]>,
    /// The route is a loopback: the targets are this host's own addresses.
    loopback: bool,
    members: Vec<Member6>,
}

/// One IPv6 target of a route-group.
#[cfg(any(feature = "pcap", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Member6 {
    /// Its place in the scan's input.
    slot: usize,
    target: Ipv6Addr,
    /// The address whose MAC its frames go to: the target itself when on-link, the
    /// gateway otherwise.
    next_hop: Ipv6Addr,
    /// The next hop's MAC when the OS already knows it (a gateway's entry).
    next_hop_mac: Option<[u8; 6]>,
    /// On-link: neighbor discovery of the target itself decides whether it is up.
    directly_connected: bool,
}

/// Group `targets` by the routes `route4` and `route6` give them.
///
/// # Errors
/// A route lookup's error.
#[cfg(any(feature = "pcap", test))]
fn bucket_targets(
    targets: &[IpAddr],
    mut route4: impl FnMut(Ipv4Addr) -> std::io::Result<Option<crate::route::Route>>,
    mut route6: impl FnMut(Ipv6Addr) -> std::io::Result<Option<crate::route::Route6>>,
) -> std::io::Result<Buckets> {
    let mut b = Buckets::default();
    for (i, &ip) in targets.iter().enumerate() {
        match ip {
            IpAddr::V4(v4) => {
                if let Some(route) = route4(v4)? {
                    b.v4.entry((route.iface, route.src))
                        .or_default()
                        .push((i, v4));
                }
            }
            IpAddr::V6(v6) => {
                if let Some(route) = route6(v6)? {
                    let group =
                        b.v6.entry((route.iface, route.src))
                            .or_insert_with(|| Group6 {
                                src_mac: route.src_mac,
                                loopback: route.loopback,
                                members: Vec::new(),
                            });
                    group.members.push(Member6 {
                        slot: i,
                        target: v6,
                        next_hop: route.next_hop,
                        next_hop_mac: route.next_hop_mac,
                        directly_connected: route.directly_connected,
                    });
                }
            }
        }
    }
    Ok(b)
}

/// What neighbor discovery decided for an Ethernet route-group.
#[cfg(any(feature = "pcap", test))]
#[derive(Debug, Default, PartialEq, Eq)]
struct NeighborPlan {
    /// Each scanned target's next-hop MAC, for [`crate::rawio::NeighborSender`].
    macs: HashMap<[u8; 16], [u8; 6]>,
    /// The targets to scan.
    scan: Vec<(usize, Ipv6Addr)>,
    /// On-link targets that advertised themselves: up, `nd-response`.
    advertised: Vec<usize>,
    /// On-link targets that never answered: down, `no-response`, and not scanned.
    silent: Vec<usize>,
    /// Off-link targets whose gateway never answered. They are scanned all the same,
    /// and their probes, which cannot be framed, go nowhere.
    behind_a_silent_gateway: Vec<Ipv6Addr>,
}

/// Decide each member's fate from the MACs neighbor discovery `found` (by next hop).
///
/// This is what 7.94 does on Unix, where its scan probes leave through a raw socket and
/// the kernel resolves the next hop. An on-link target is first put to the implicit ND
/// ping (`targets.cc`'s `arpping`, `PING_SCAN_ND`), even under `-Pn` (only
/// `--disable-arp-ping` skips it): an advertisement makes it up, `nd-response`, and
/// silence makes it down, so it is not scanned. An off-link target gets no such ping.
/// When its gateway cannot be resolved, the kernel drops every probe and the target's
/// ports take their no-response defaults, which is what happens here too.
#[cfg(any(feature = "pcap", test))]
fn plan_neighbors(members: &[Member6], found: &HashMap<[u8; 16], [u8; 6]>) -> NeighborPlan {
    let mut plan = NeighborPlan::default();
    for m in members {
        let mac = m
            .next_hop_mac
            .or_else(|| found.get(&m.next_hop.octets()).copied());
        match (mac, m.directly_connected) {
            (Some(mac), on_link) => {
                plan.macs.insert(m.target.octets(), mac);
                plan.scan.push((m.slot, m.target));
                if on_link {
                    plan.advertised.push(m.slot);
                }
            }
            (None, true) => plan.silent.push(m.slot),
            (None, false) => {
                plan.scan.push((m.slot, m.target));
                plan.behind_a_silent_gateway.push(m.target);
            }
        }
    }
    plan
}

/// What every route-group of one scan shares.
#[cfg(feature = "pcap")]
struct RouteGroupRun<'a> {
    ports: &'a [u16],
    template: TimingTemplate,
    params: TimingParams,
    max_parallelism: usize,
    span: u16,
    overrides: PacketOverrides,
}

#[cfg(feature = "pcap")]
impl RouteGroupRun<'_> {
    /// Scan the `members` routed out `iface` from `src` through `sender`, with a capture
    /// of their replies on `iface`, and put each host in its slot.
    async fn scan<A: ScanFamily, K: RawScanKind, S: RawSender>(
        &self,
        kind: &K,
        iface: &str,
        src: A,
        members: &[(usize, A)],
        sender: S,
        result_slot: &mut [Option<Host>],
    ) -> std::io::Result<()> {
        use crate::capture::pcap_source::PcapSource;
        use crate::route::random_scan_keys;

        let (_seqmask, base_port) = random_scan_keys();
        let group_targets: Vec<A> = members.iter().map(|(_, ip)| *ip).collect();
        let filter = A::reply_filter(src, kind.protocol(), base_port, self.span);
        let source = PcapSource::open(iface, 65535, 100, Some(&filter))?;
        // Ethernet framing or not is the capture's datalink to say (FreeBSD's
        // lo0 is DLT_NULL).
        let eth = source.eth_included();
        let hosts = group_scan(
            src,
            &group_targets,
            self.ports,
            sender,
            source,
            kind,
            self.template,
            self.params,
            self.max_parallelism,
            base_port,
            eth,
            self.overrides,
        )
        .await;
        for ((slot, _), host) in members.iter().zip(hosts) {
            if let Some(s) = result_slot.get_mut(*slot) {
                *s = Some(host);
            }
        }
        Ok(())
    }
}

/// Scan one IPv6 route-group, framed for its link. An IPv6 probe goes out at layer 2
/// through a capture handle on the interface ([`crate::rawio`]):
///
/// - over a loopback, framed as the loopback takes it, with no neighbor to find
///   ([`crate::rawio::LinkFraming::for_loopback`]);
/// - over Ethernet, to each target's next hop, whose MAC neighbor discovery finds for
///   the whole group at once ([`crate::ndp::resolve_many`]); [`plan_neighbors`] then
///   decides which targets are up, down or unreachable, as 7.94 does;
/// - over a link with no link-layer addresses (a raw-IP tunnel, a BSD `DLT_NULL`
///   tunnel), as it is.
///
/// # Errors
/// The capture handles' open errors; `Unsupported` for a datalink nmap does not send
/// on, or an Ethernet interface with no MAC to send from.
#[cfg(feature = "pcap")]
async fn scan_route_group6<K: RawScanKind>(
    run: &RouteGroupRun<'_>,
    kind: &K,
    iface: &str,
    src: Ipv6Addr,
    group: &Group6,
    result_slot: &mut [Option<Host>],
) -> std::io::Result<()> {
    use crate::capture::pcap_source::PcapSource;
    use crate::rawio::pcap_sender::PcapSender;
    use crate::rawio::{FramingSender, LinkFraming, NeighborSender};
    use std::io::{Error, ErrorKind};

    let all: Vec<(usize, Ipv6Addr)> = group.members.iter().map(|m| (m.slot, m.target)).collect();
    let mut link = PcapSender::open(iface)?;
    let dlt = link.datalink();
    let unsupported = || {
        Error::new(
            ErrorKind::Unsupported,
            format!("{iface}: unsupported datalink {dlt} for sending"),
        )
    };
    if group.loopback {
        let framing = LinkFraming::for_loopback(dlt, group.src_mac).ok_or_else(unsupported)?;
        let sender = FramingSender::new(link, framing);
        return run.scan(kind, iface, src, &all, sender, result_slot).await;
    }
    if dlt != 1 {
        let framing = LinkFraming::for_datalink(dlt, || Err(Error::other("not Ethernet")))?
            .ok_or_else(unsupported)?;
        let sender = FramingSender::new(link, framing);
        return run.scan(kind, iface, src, &all, sender, result_slot).await;
    }

    let src_mac = group.src_mac.ok_or_else(|| {
        Error::new(
            ErrorKind::Unsupported,
            format!("{iface} has no MAC; cannot frame an IPv6 probe at layer 2"),
        )
    })?;
    let unknown: Vec<[u8; 16]> = group
        .members
        .iter()
        .filter(|m| m.next_hop_mac.is_none())
        .map(|m| m.next_hop.octets())
        .collect();
    let found = if unknown.is_empty() {
        HashMap::new()
    } else {
        let filter = crate::ndp::bpf_filter(src_mac);
        let nd_source = PcapSource::open(iface, 65535, 25, Some(&filter))?;
        crate::ndp::resolve_many(&mut link, nd_source, src_mac, src.octets(), &unknown).await
    };
    let plan = plan_neighbors(&group.members, &found);
    for target in &plan.behind_a_silent_gateway {
        nmap_core::debug!(
            1,
            "no neighbor advertisement from the gateway to {target}; its probes cannot be sent"
        );
    }
    if !plan.scan.is_empty() {
        let sender = NeighborSender::new(link, src_mac, plan.macs.clone());
        run.scan(kind, iface, src, &plan.scan, sender, result_slot)
            .await?;
    }
    for &slot in &plan.advertised {
        if let Some(Some(host)) = result_slot.get_mut(slot) {
            host.state = HostState::Up;
            host.reason = Some(Reason::NdResponse);
        }
    }
    for &slot in &plan.silent {
        if let (Some(s), Some(m)) = (
            result_slot.get_mut(slot),
            group.members.iter().find(|m| m.slot == slot),
        ) {
            let mut host = Host::new(IpAddr::V6(m.target), HostState::Down);
            host.reason = Some(Reason::NoResponse);
            *s = Some(host);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nmap_core::build::{build_tcp_raw, build_tcp_raw_ipv6, build_udp_raw, build_udp_raw_ipv6};
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
            TimingParams::for_template(TimingTemplate::Insane),
            0,
            base,
            true,
            Default::default(),
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

    /// A capture that fails on its first read.
    struct FailingSource;
    impl PacketSource for FailingSource {
        fn next_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            Err(std::io::Error::other("the BPF device went away"))
        }
    }

    /// A capture that fails ends the scan as silence does: every port times
    /// out, within the template's bound. (Its `recv` is then ready with `None`
    /// at once, every time; the loop stops polling it rather than spin on it
    /// until the next probe deadline.)
    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn a_capture_that_fails_does_not_hang_the_scan() {
        let targets = [Ipv4Addr::new(127, 0, 0, 2)];
        let scan = group_scan(
            Ipv4Addr::from(US),
            &targets,
            &[9, 10],
            MockSender::default(),
            FailingSource,
            &SynKind { seqmask: 1 },
            TimingTemplate::Insane,
            TimingParams::for_template(TimingTemplate::Insane),
            0,
            40000,
            true,
            Default::default(),
        );
        let hosts = tokio::time::timeout(Duration::from_secs(30), scan)
            .await
            .expect("the scan ends");
        for port in [9, 10] {
            assert_eq!(port_of(&hosts, 0, port).state, PortState::Filtered);
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
            TimingParams::for_template(TimingTemplate::Insane),
            0,
            40000,
            true,
            Default::default(),
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
            TimingParams::for_template(TimingTemplate::Insane),
            0,
            40000,
            true,
            Default::default(),
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

    /// An ICMP type/code error from `sender`, quoting the TCP probe we sent to `probed`'s
    /// `dport` as attempt 0 with `flags`.
    fn icmp_quoting_tcp(
        sender: [u8; 4],
        probed: [u8; 4],
        (icmp_type, icmp_code): (u8, u8),
        dport: u16,
        base: u16,
        seqmask: u32,
        flags: u8,
    ) -> Vec<u8> {
        let spec = Ipv4Spec::new(US, probed, 64, 0x2);
        let probe = build_tcp_raw(
            &spec,
            sport_encode(base, 0),
            dport,
            seq32_encode(seqmask, 0),
            0,
            0,
            flags,
            1024,
            0,
            &[],
            &[],
        )
        .unwrap();
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

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn icmp_error_resolves_a_syn_port_as_filtered() {
        let base = 40000u16;
        let seqmask = 0x0BAD_F00D;
        let target = Ipv4Addr::new(127, 0, 0, 2);
        let hosts = run(
            &SynKind { seqmask },
            &[target],
            &[443],
            base,
            vec![icmp_quoting_tcp(
                target.octets(),
                target.octets(),
                (3, 13),
                443,
                base,
                seqmask,
                TH_SYN,
            )],
        )
        .await;
        let p = port_of(&hosts, 0, 443);
        assert_eq!(p.state, PortState::Filtered);
        // The specific code is reported, not a generic "no-response".
        assert_eq!(p.reason, Reason::AdminProhibited);
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn icmp_error_upgrades_a_fin_scan_port_from_open_filtered() {
        // `-sF`'s no-response default is open|filtered; the ICMP error is the only way to
        // learn the port is actually filtered. This is the back-fill's whole point.
        let base = 40000u16;
        let seqmask = 0x0BAD_F00D;
        let target = Ipv4Addr::new(127, 0, 0, 2);
        let kind = FlagKind {
            scan: ScanType::Fin,
            seqmask,
        };
        let flags = nmap_core::flagscan::flags_for(ScanType::Fin).unwrap();

        // Without the error the port is open|filtered ...
        let quiet = run(&kind, &[target], &[443], base, Vec::new()).await;
        assert_eq!(port_of(&quiet, 0, 443).state, PortState::OpenFiltered);

        // ... and with it, filtered.
        let hosts = run(
            &kind,
            &[target],
            &[443],
            base,
            vec![icmp_quoting_tcp(
                target.octets(),
                target.octets(),
                (3, 1),
                443,
                base,
                seqmask,
                flags,
            )],
        )
        .await;
        let p = port_of(&hosts, 0, 443);
        assert_eq!(p.state, PortState::Filtered);
        assert_eq!(p.reason, Reason::HostUnreach);
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn icmp_error_from_a_router_is_attributed_to_the_probed_host() {
        // A router relays the error for host .3; it must not land on .2.
        let base = 40000u16;
        let seqmask = 0x0BAD_F00D;
        let h2 = Ipv4Addr::new(127, 0, 0, 2);
        let h3 = Ipv4Addr::new(127, 0, 0, 3);
        let hosts = run(
            &SynKind { seqmask },
            &[h2, h3],
            &[443],
            base,
            vec![icmp_quoting_tcp(
                [192, 168, 0, 1],
                h3.octets(),
                (3, 0),
                443,
                base,
                seqmask,
                TH_SYN,
            )],
        )
        .await;
        // Both end up filtered (that is .2's default), but only .3 has an ICMP reason.
        assert_eq!(
            port_of(&hosts, 0, 443).reason,
            Reason::NoResponse,
            "host .2"
        );
        assert_eq!(
            port_of(&hosts, 1, 443).reason,
            Reason::NetUnreach,
            "host .3"
        );
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

    // ---- IPv6 (IPv6 scans step d) -----------------------------------------------

    /// Our address in the IPv6 tests: 2001:db8::1. The engine does not route, so
    /// any addresses do.
    const US6: [u8; 16] = v6(1);

    const fn v6(last: u8) -> [u8; 16] {
        [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last,
        ]
    }

    /// Wrap an IP packet in a 14-byte Ethernet header with the IPv6 type.
    fn framed6(ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x86, 0xDD]);
        f.extend_from_slice(ip);
        f
    }

    /// A bare IPv6 packet from `src` to `dst`: `first` names what follows the fixed
    /// header, `chain` is extension headers already encoded, then `payload`.
    fn ipv6(src: [u8; 16], dst: [u8; 16], first: u8, chain: &[u8], payload: &[u8]) -> Vec<u8> {
        let plen = u16::try_from(chain.len().saturating_add(payload.len())).unwrap();
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&plen.to_be_bytes());
        p.extend_from_slice(&[first, 64]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(chain);
        p.extend_from_slice(payload);
        p
    }

    /// `pkt` (an IPv6 packet with no extension headers) with a one-unit
    /// destination-options header put in front of its upper layer.
    fn behind_dstopts(pkt: &[u8]) -> Vec<u8> {
        let mut chain = vec![pkt[6], 0, 1, 4, 0, 0, 0, 0];
        chain.extend_from_slice(&pkt[40..]);
        let src: [u8; 16] = pkt[8..24].try_into().unwrap();
        let dst: [u8; 16] = pkt[24..40].try_into().unwrap();
        ipv6(src, dst, 60, &[], &chain)
    }

    /// The bare IPv6 TCP reply from `from` to our `tryno == 0` source port.
    fn tcp_reply6_bare(
        seqmask: u32,
        from: [u8; 16],
        scanned: u16,
        base: u16,
        flags: u8,
        window: u16,
    ) -> Vec<u8> {
        build_tcp_raw_ipv6(
            &Ipv6Spec::new(from, US6),
            scanned,
            sport_encode(base, 0),
            5,
            seq32_encode(seqmask, 0).wrapping_add(1),
            0,
            flags,
            window,
            0,
            &[],
            &[],
        )
        .unwrap()
    }

    fn tcp_reply6(
        seqmask: u32,
        from: [u8; 16],
        scanned: u16,
        base: u16,
        flags: u8,
        window: u16,
    ) -> Vec<u8> {
        framed6(&tcp_reply6_bare(
            seqmask, from, scanned, base, flags, window,
        ))
    }

    /// An ICMPv6 `icmp_type`/`icmp_code` error from `sender` to us, quoting `quoted`.
    fn icmp6_error(sender: [u8; 16], (icmp_type, icmp_code): (u8, u8), quoted: &[u8]) -> Vec<u8> {
        let mut msg = vec![icmp_type, icmp_code, 0, 0, 0, 0, 0, 0];
        msg.extend_from_slice(quoted);
        framed6(&ipv6(sender, US6, 58, &[], &msg))
    }

    /// Drive `group_scan` over IPv6 `targets` with scripted reply frames. Returns the
    /// hosts and every packet the engine sent.
    async fn run6<K: RawScanKind>(
        kind: &K,
        targets: &[Ipv6Addr],
        ports: &[u16],
        base: u16,
        frames: Vec<Vec<u8>>,
        overrides: PacketOverrides,
    ) -> (Vec<Host>, Vec<Vec<u8>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let hosts = group_scan(
            Ipv6Addr::from(US6),
            targets,
            ports,
            MockSender {
                sent: Arc::clone(&sent),
            },
            MockSource {
                frames: Arc::new(Mutex::new(frames)),
            },
            kind,
            TimingTemplate::Insane,
            TimingParams::for_template(TimingTemplate::Insane),
            0,
            base,
            true,
            overrides,
        )
        .await;
        let sent = sent.lock().unwrap().clone();
        (hosts, sent)
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn ipv6_hosts_demux_by_source_address() {
        let seqmask = 0xABCD_1234;
        let base = 40000u16;
        let (h2, h3) = (Ipv6Addr::from(v6(2)), Ipv6Addr::from(v6(3)));
        // .2 is open, .3 closed, on the same port and encoded source port.
        let (hosts, _) = run6(
            &SynKind { seqmask },
            &[h2, h3],
            &[80],
            base,
            vec![
                tcp_reply6(seqmask, v6(3), 80, base, TH_RST | TH_ACK, 0),
                tcp_reply6(seqmask, v6(2), 80, base, TH_SYN | TH_ACK, 8192),
            ],
            PacketOverrides::default(),
        )
        .await;
        assert_eq!(hosts[0].address, IpAddr::V6(h2));
        assert_eq!(hosts[1].address, IpAddr::V6(h3));
        let (p2, p3) = (port_of(&hosts, 0, 80), port_of(&hosts, 1, 80));
        assert_eq!((p2.state, p2.reason), (PortState::Open, Reason::ConnAccept));
        assert_eq!((p3.state, p3.reason), (PortState::Closed, Reason::Reset));
        assert_eq!(hosts[0].state, HostState::Up);
    }

    /// What an IPv6 scan puts on the wire is step c's probe, for the right host:
    /// hop limit 255 unless `--ttl` says otherwise, and `--badsum` applied.
    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn ipv6_probes_are_step_cs_with_the_operators_options() {
        let seqmask = 0x0102_0304;
        let base = 41000u16;
        let target = Ipv6Addr::from(v6(2));
        for (overrides, hop_limit) in [
            (PacketOverrides::default(), 255u8),
            (
                PacketOverrides {
                    ttl: Some(9),
                    bad_sum: true,
                    ..PacketOverrides::default()
                },
                9,
            ),
        ] {
            let (_, sent) = run6(
                &SynKind { seqmask },
                &[target],
                &[443],
                base,
                Vec::new(),
                overrides,
            )
            .await;
            assert!(!sent.is_empty());
            for (tryno, pkt) in (0u32..).zip(&sent) {
                let spec = Ipv6Spec::new(US6, v6(2)).with_overrides(overrides);
                let want = build_syn_probe(&spec, base, 443, tryno, seqmask).unwrap();
                assert_eq!(pkt, &want, "attempt {tryno}");
                assert_eq!(pkt[7], hop_limit);
                let v = nmap_core::recv_validate::validate_packet(pkt).unwrap();
                assert_eq!((v.version, v.proto), (6, 6));
            }
        }
    }

    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn ipv6_udp_icmpv6_errors_by_sender_and_datagrams() {
        let base = 40000u16;
        let (h2, h3, h4) = (
            Ipv6Addr::from(v6(2)),
            Ipv6Addr::from(v6(3)),
            Ipv6Addr::from(v6(4)),
        );
        let probe = |to: [u8; 16]| {
            nmap_core::udpscan::build_udp_probe(&Ipv6Spec::new(US6, to), base, 53, 0).unwrap()
        };
        let reply = build_udp_raw_ipv6(&Ipv6Spec::new(v6(4), US6), 53, base, b"hi").unwrap();
        let (hosts, _) = run6(
            &UdpKind::bare(),
            &[h2, h3, h4],
            &[53],
            base,
            vec![
                // .3's probe is answered by a router: filtered, and on .3.
                icmp6_error(v6(0xfe), (1, 4), &probe(v6(3))),
                // .2 answers its own: port unreachable from the target is closed.
                icmp6_error(v6(2), (1, 4), &probe(v6(2))),
                // .4 sends a datagram back.
                framed6(&reply),
            ],
            PacketOverrides::default(),
        )
        .await;
        let p = |i| port_of(&hosts, i, 53);
        assert_eq!(
            (p(0).state, p(0).reason),
            (PortState::Closed, Reason::PortUnreach)
        );
        assert_eq!(
            (p(1).state, p(1).reason),
            (PortState::Filtered, Reason::PortUnreach)
        );
        assert_eq!(
            (p(2).state, p(2).reason),
            (PortState::Open, Reason::UdpResponse)
        );
    }

    /// D2: parameter problem code 0 on a TCP probe is filtered, not open.
    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn ipv6_parameter_problem_is_filtered_and_no_route_is_its_own_reason() {
        let seqmask = 0x0BAD_F00D;
        let base = 40000u16;
        let probe = build_syn_probe(&Ipv6Spec::new(US6, v6(2)), base, 443, 0, seqmask).unwrap();
        for (err, reason) in [
            ((4, 0), Reason::ParamProblem),
            ((1, 0), Reason::NoRoute),
            ((1, 1), Reason::AdminProhibited),
        ] {
            let (hosts, _) = run6(
                &SynKind { seqmask },
                &[Ipv6Addr::from(v6(2))],
                &[443],
                base,
                vec![icmp6_error(v6(2), err, &probe)],
                PacketOverrides::default(),
            )
            .await;
            let p = port_of(&hosts, 0, 443);
            assert_eq!(
                (p.state, p.reason),
                (PortState::Filtered, reason),
                "{err:?}"
            );
        }
    }

    /// A reply behind an extension header reaches the matcher (the filter lets it
    /// through, `ipv6_filter_*`), which walks to it.
    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn ipv6_a_reply_behind_destination_options_is_matched() {
        let base = 40000u16;
        let reply = tcp_reply6_bare(7, v6(2), 80, base, TH_RST | TH_ACK, 0);
        let (hosts, _) = run6(
            &FlagKind {
                scan: ScanType::Ack,
                seqmask: 7,
            },
            &[Ipv6Addr::from(v6(2))],
            &[80],
            base,
            vec![framed6(&behind_dstopts(&reply))],
            PacketOverrides::default(),
        )
        .await;
        let p = port_of(&hosts, 0, 80);
        assert_eq!((p.state, p.reason), (PortState::Unfiltered, Reason::Reset));
    }

    /// Each family's scan reads only its own family: an IPv4 reply from the
    /// IPv4-mapped form of the target answers nothing in an IPv6 scan, and the
    /// flag scans keep their own no-response defaults.
    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn ipv6_scans_read_only_ipv6_replies() {
        let base = 40000u16;
        let mapped = Ipv6Addr::from(Ipv4Addr::new(127, 0, 0, 2).to_ipv6_mapped().octets());
        for (scan, want) in [
            (ScanType::Fin, PortState::OpenFiltered),
            (ScanType::Window, PortState::Filtered),
        ] {
            let (hosts, _) = run6(
                &FlagKind { scan, seqmask: 7 },
                &[mapped],
                &[80],
                base,
                vec![tcp_reply(7, [127, 0, 0, 2], 80, base, TH_RST | TH_ACK, 0)],
                PacketOverrides::default(),
            )
            .await;
            let p = port_of(&hosts, 0, 80);
            assert_eq!((p.state, p.reason), (want, Reason::NoResponse), "{scan:?}");
        }
    }

    /// Without a link header, as FreeBSD's `lo0` delivers once its `DLT_NULL`
    /// family is stripped.
    #[cfg_attr(
        miri,
        ignore = "spawns a capture thread; miri cannot run real threads/time"
    )]
    #[tokio::test]
    async fn ipv6_replies_without_a_link_header() {
        let seqmask = 0x1111_2222;
        let base = 40000u16;
        let hosts = group_scan(
            Ipv6Addr::from(US6),
            &[Ipv6Addr::from(v6(2))],
            &[22],
            MockSender::default(),
            MockSource {
                frames: Arc::new(Mutex::new(vec![tcp_reply6_bare(
                    seqmask,
                    v6(2),
                    22,
                    base,
                    TH_SYN | TH_ACK,
                    1024,
                )])),
            },
            &SynKind { seqmask },
            TimingTemplate::Insane,
            TimingParams::for_template(TimingTemplate::Insane),
            0,
            base,
            false,
            PacketOverrides::default(),
        )
        .await;
        assert_eq!(port_of(&hosts, 0, 22).state, PortState::Open);
    }

    // ---- Routing a scan's targets -------------------------------------------------

    fn route6(iface: &str, src: [u8; 16], loopback: bool) -> crate::route::Route6 {
        crate::route::Route6 {
            iface: iface.into(),
            src: Ipv6Addr::from(src),
            src_mac: Some([0; 6]),
            next_hop: Ipv6Addr::from(v6(0xfe)),
            next_hop_mac: None,
            directly_connected: true,
            loopback,
        }
    }

    /// IPv6 targets join one route-group per (interface, source), each with what its
    /// route says about its next hop; an unroutable one is left out (down); the IPv4
    /// targets keep their own groups.
    #[test]
    fn targets_are_grouped_by_family_and_route() {
        let lo6 = Ipv6Addr::LOCALHOST;
        let own6 = Ipv6Addr::from(v6(0x10));
        let (near, far) = (
            Ipv6Addr::from(v6(0x20)),
            Ipv6Addr::from(0xfd00_u128 << 112 | 7),
        );
        let none6 = Ipv6Addr::from(v6(0x99));
        let v4 = Ipv4Addr::new(127, 0, 0, 2);
        let targets = [
            IpAddr::V6(lo6),
            IpAddr::V4(v4),
            IpAddr::V6(own6),
            IpAddr::V6(none6),
            IpAddr::V6(lo6),
            IpAddr::V6(near),
            IpAddr::V6(far),
        ];
        let b = bucket_targets(
            &targets,
            |t| {
                Ok(Some(crate::route::Route {
                    iface: "lo".into(),
                    src: t,
                }))
            },
            |t| {
                Ok(if t == lo6 {
                    Some(route6("lo", lo6.octets(), true))
                } else if t == own6 {
                    // An address of our own goes over the loopback from itself.
                    Some(route6("lo", own6.octets(), true))
                } else if t == near {
                    Some(crate::route::Route6 {
                        next_hop: near,
                        ..route6("eth0", US6, false)
                    })
                } else if t == far {
                    Some(crate::route::Route6 {
                        next_hop_mac: Some([7; 6]),
                        directly_connected: false,
                        ..route6("eth0", US6, false)
                    })
                } else {
                    None
                })
            },
        )
        .unwrap();
        assert_eq!(b.v4.len(), 1);
        assert_eq!(b.v4[&("lo".to_string(), v4)], vec![(1, v4)]);
        assert_eq!(b.v6.len(), 3);
        let slots = |key: (&str, Ipv6Addr)| -> Vec<usize> {
            b.v6[&(key.0.to_string(), key.1)]
                .members
                .iter()
                .map(|m| m.slot)
                .collect()
        };
        assert_eq!(slots(("lo", lo6)), vec![0, 4]);
        assert_eq!(slots(("lo", own6)), vec![2]);
        let eth = &b.v6[&("eth0".to_string(), Ipv6Addr::from(US6))];
        assert!(!eth.loopback && b.v6[&("lo".to_string(), lo6)].loopback);
        assert_eq!(
            eth.members,
            vec![
                Member6 {
                    slot: 5,
                    target: near,
                    next_hop: near,
                    next_hop_mac: None,
                    directly_connected: true,
                },
                Member6 {
                    slot: 6,
                    target: far,
                    next_hop: Ipv6Addr::from(v6(0xfe)),
                    next_hop_mac: Some([7; 6]),
                    directly_connected: false,
                },
            ]
        );
    }

    #[test]
    fn a_route_lookup_error_is_the_scans_error() {
        let err = bucket_targets(
            &[IpAddr::V6(Ipv6Addr::from(v6(0x20)))],
            |_| Ok(None),
            |_| Err(std::io::Error::other("no interfaces")),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "no interfaces");
    }

    fn member(
        slot: usize,
        last: u8,
        next_hop: u8,
        known: Option<[u8; 6]>,
        on_link: bool,
    ) -> Member6 {
        Member6 {
            slot,
            target: Ipv6Addr::from(v6(last)),
            next_hop: Ipv6Addr::from(v6(next_hop)),
            next_hop_mac: known,
            directly_connected: on_link,
        }
    }

    /// 7.94 on Unix: an on-link target is up when it advertises itself and down (not
    /// scanned) when silent; an off-link one is scanned through its gateway, whose
    /// known MAC needs no solicitation, and is scanned even when the gateway is silent.
    #[test]
    fn neighbor_discovery_decides_who_is_up_and_where_frames_go() {
        let gw = 0xfe;
        let members = [
            member(0, 2, 2, None, true),                // on-link, advertised
            member(1, 3, 3, None, true),                // on-link, silent
            member(2, 0x40, gw, None, false),           // behind the gateway, which answered
            member(3, 0x41, gw, None, false),           // the same gateway
            member(4, 0x50, 0xfd, Some([5; 6]), false), // gateway MAC already known
            member(5, 0x60, 0xfc, None, false),         // behind a silent gateway
        ];
        let found = HashMap::from([(v6(2), [2; 6]), (v6(gw), [0xfe; 6])]);
        let plan = plan_neighbors(&members, &found);
        assert_eq!(plan.advertised, vec![0]);
        assert_eq!(plan.silent, vec![1]);
        let scanned: Vec<usize> = plan.scan.iter().map(|(s, _)| *s).collect();
        assert_eq!(scanned, vec![0, 2, 3, 4, 5]);
        assert_eq!(plan.behind_a_silent_gateway, vec![Ipv6Addr::from(v6(0x60))]);
        assert_eq!(
            plan.macs,
            HashMap::from([
                (v6(2), [2; 6]),
                (v6(0x40), [0xfe; 6]),
                (v6(0x41), [0xfe; 6]),
                (v6(0x50), [5; 6]),
            ]),
            "frames go to each target's own next hop; none for the silent gateway's"
        );
    }

    // ---- The capture filters, compiled and run by libpcap -----------------------

    #[cfg(feature = "pcap")]
    mod filters {
        use super::*;

        const TCP: u8 = 6;
        const UDP: u8 = 17;

        /// Whether `filter`, compiled by libpcap for datalink `dlt`, admits the IP
        /// packet `ip` framed for that link.
        fn admits(dlt: i32, filter: &str, ip: &[u8]) -> bool {
            let cap = pcap::Capture::dead(pcap::Linktype(dlt)).expect("a dead capture");
            let prog = cap.compile(filter, true).expect("the filter compiles");
            let six = ip[0] >> 4 == 6;
            let frame = match dlt {
                1 => {
                    let mut f = vec![0u8; 12];
                    f.extend_from_slice(if six { &[0x86, 0xDD] } else { &[0x08, 0x00] });
                    f.extend_from_slice(ip);
                    f
                }
                0 => {
                    // A live capture's filter checks for the platform's own
                    // AF_INET6 (libpcap's gencode), which on the BSDs is what
                    // lo0 carries (`NULL_AF_INET6`): 28 on FreeBSD.
                    let af = if six { socket2::Domain::IPV6.into() } else { 2 };
                    let mut f = i32::to_ne_bytes(af).to_vec();
                    f.extend_from_slice(ip);
                    f
                }
                other => panic!("datalink {other}"),
            };
            prog.filter(&frame)
        }

        /// An IPv6 packet from `src` to `dst` whose upper layer is `proto` with
        /// destination port `dport`.
        fn l4_6(src: [u8; 16], dst: [u8; 16], proto: u8, dport: u16) -> Vec<u8> {
            let spec = Ipv6Spec::new(src, dst);
            match proto {
                TCP => {
                    build_tcp_raw_ipv6(&spec, 80, dport, 1, 2, 0, TH_RST, 0, 0, &[], &[]).unwrap()
                }
                UDP => build_udp_raw_ipv6(&spec, 53, dport, b"x").unwrap(),
                _ => unreachable!(),
            }
        }

        #[test]
        #[cfg_attr(miri, ignore = "calls into libpcap")]
        fn ipv6_filter_admits_our_ports_icmpv6_and_extension_headers() {
            let us = Ipv6Addr::from(US6);
            let (base, span) = (40000u16, 10u16);
            for dlt in [1, 0] {
                for (proto, other) in [(Protocol::Tcp, UDP), (Protocol::Udp, TCP)] {
                    let mine = transport(proto).1;
                    let f = Ipv6Addr::reply_filter(us, proto, base, span);
                    let ok = |ip: &[u8]| admits(dlt, &f, ip);
                    let why = format!("{proto:?} on datalink {dlt}: {f}");
                    // Our transport, to each end of our source-port range.
                    assert!(ok(&l4_6(v6(2), US6, mine, base)), "{why}");
                    assert!(ok(&l4_6(v6(2), US6, mine, base + span)), "{why}");
                    // ... and not past either end, nor the other transport.
                    assert!(!ok(&l4_6(v6(2), US6, mine, base - 1)), "{why}");
                    assert!(!ok(&l4_6(v6(2), US6, mine, base + span + 1)), "{why}");
                    assert!(!ok(&l4_6(v6(2), US6, other, base)), "{why}");
                    // Nor to anyone but us (our own probe to the target).
                    assert!(!ok(&l4_6(US6, v6(2), mine, base)), "{why}");
                    // ICMPv6 to us.
                    let err = ipv6(v6(0xfe), US6, 58, &[], &[1, 4, 0, 0, 0, 0, 0, 0]);
                    assert!(ok(&err), "{why}");
                    // A reply behind an extension header, to any port: the walk
                    // decides. Destination options, hop-by-hop, a fragment header.
                    let deep = behind_dstopts(&l4_6(v6(2), US6, mine, 9));
                    assert!(ok(&deep), "{why}");
                    let mut hop = deep.clone();
                    hop[6] = 0;
                    assert!(ok(&hop), "{why}");
                    let mut frag = deep.clone();
                    frag[6] = 44;
                    assert!(ok(&frag), "{why}");
                    // Nothing of the other family, even to our ports.
                    let v4 = build_udp_raw(&Ipv4Spec::new([10, 0, 0, 2], US, 64, 1), 53, base, b"")
                        .unwrap();
                    assert!(!ok(&v4), "{why}");
                }
            }
        }

        /// The IPv4 filter is the one the engine always used.
        #[test]
        #[cfg_attr(miri, ignore = "calls into libpcap")]
        fn ipv4_filter_is_unchanged() {
            let us = Ipv4Addr::from(US);
            assert_eq!(
                Ipv4Addr::reply_filter(us, Protocol::Tcp, 40000, 16),
                "(tcp and dst host 127.0.0.1 and dst portrange 40000-40016) \
                 or (icmp and dst host 127.0.0.1)"
            );
            assert_eq!(
                Ipv4Addr::reply_filter(us, Protocol::Udp, 65530, 16),
                "(udp and dst host 127.0.0.1 and dst portrange 65530-65535) \
                 or (icmp and dst host 127.0.0.1)"
            );
            let f = Ipv4Addr::reply_filter(us, Protocol::Udp, 40000, 16);
            let spec = Ipv4Spec::new([127, 0, 0, 2], US, 64, 1);
            for dlt in [1, 0] {
                assert!(admits(
                    dlt,
                    &f,
                    &build_udp_raw(&spec, 53, 40001, b"").unwrap()
                ));
                assert!(!admits(
                    dlt,
                    &f,
                    &build_udp_raw(&spec, 53, 39999, b"").unwrap()
                ));
                // IPv6 is not admitted by an IPv4 scan's filter.
                assert!(!admits(dlt, &f, &l4_6(v6(2), US6, UDP, 40001)));
            }
        }
    }
}
