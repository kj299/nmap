//! The privileged OS-detection driver — the I/O half of `os_scan_ipv4`.
//!
//! Everything this module decides has already been ported as a pure function: the probes
//! come from [`nmap_core::osprobe::build`], replies are attributed by
//! [`nmap_core::osprobe::demux`], the fingerprint is assembled by
//! [`nmap_core::osprobe::assemble`], scored by [`nmap_core::osdb::score`], and the round
//! policy lives in [`nmap_core::osscan`]. What is left here is *sending and waiting*.
//! **No `unsafe`** — the raw socket and capture handles are already safe abstractions.
//!
//! ## Why this is not a [`crate::group::RawScanKind`]
//!
//! The M4 group engine looked like the obvious host, but it is *port-keyed* throughout:
//! its scheduler walks a port list, `next_probe()` yields a `(port, tryno)` pair,
//! outstanding probes are keyed by that pair, and a finished port produces a
//! `(PortState, Reason)`. OS detection matches none of that — it sends 23 **heterogeneous**
//! probes at one or two ports and produces replies for thirteen different extractors, not
//! port states.
//!
//! More decisively, the two want opposite pacing. A congestion window exists to send as
//! fast as the network allows; the six `SEQ` probes must instead be sent **no faster than
//! one per 100 ms** ([`SEQ_PROBE_DELAY`]), because `makeTSeqFP` derives the ISN rate and
//! timestamp frequency from the actual elapsed send times. Firing them as fast as a window
//! permitted would not merely be impolite — it would corrupt the fingerprint, and
//! [`nmap_core::osscan::submission_reason`] would then reject the result via
//! `max_timing_ratio`. So this driver reuses the layer below the engine — [`AsyncCapture`],
//! [`RawSender`] and the timeout math — with its own schedule.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use nmap_core::ipid::get_ipid_sequence_16;
use nmap_core::osdb::model::FingerPrintDb;
use nmap_core::osdb::score::{match_fingerprint, MatchResults, GUESS_THRESHOLD};
use nmap_core::osprobe::assemble::{
    assemble, IeReplies, Observation, Responses, TcpProbeReply, NUM_T_PROBES,
};
use nmap_core::osprobe::build::{build_probe, OsProbe, ProbeParams, NUM_SEQ_SAMPLES};
use nmap_core::osprobe::demux::{demux, tcp_timestamp, Demuxed, ProbeReply};
use nmap_core::osprobe::icmpreply::U1Sent;
use nmap_core::osprobe::seq::{analyze_seq, estimate_uptime, SeqInputs, SeqReply, Uptime};
use nmap_core::osprobe::tcpreply::ProbeContext;
use nmap_core::osscan::{best_round, Round, SeqReport};

use crate::capture::{AsyncCapture, PacketSource};
use crate::rawio::RawSender;

/// Minimum spacing between the six `SEQ` probes, from the C's `OS_SEQ_PROBE_DELAY`.
///
/// This is a floor, not a target: `hostSeqSendOK` refuses to send before it elapses. The
/// ISN-rate and timestamp-frequency analysis is computed from the real send times, so
/// sending faster produces a *wrong* fingerprint rather than a faster one.
pub const SEQ_PROBE_DELAY: Duration = Duration::from_millis(100);
/// The ideal total span of the six `SEQ` probes — five gaps of [`SEQ_PROBE_DELAY`].
/// `timingRatio` is the observed span divided by this.
pub const IDEAL_SEQ_SPAN: Duration = Duration::from_millis(500);

/// How long to keep listening after the last probe before giving up on stragglers.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(1500);
/// Capture backlog.
const CAPTURE_CAPACITY: usize = 2048;

/// One round's raw outcome, before it is turned into a fingerprint.
#[derive(Debug, Clone, Default)]
pub struct RoundCapture {
    /// Replies collected, keyed by the probe each answers.
    pub replies: HashMap<OsProbe, ProbeReply>,
    /// IP IDs from replies on the open TCP port, in probe order.
    pub tcp_ipids: Vec<u16>,
    /// IP IDs from replies on the closed TCP port.
    pub closed_tcp_ipids: Vec<u16>,
    /// IP IDs from the ICMP echo replies.
    pub icmp_ipids: Vec<u16>,
    /// When each `SEQ` probe was actually sent, microseconds from scan start.
    pub seq_send_times: Vec<u64>,
    /// Observed span of the six `SEQ` probes, for `timingRatio`.
    pub seq_span: Option<Duration>,
    /// Probes that could not be sent at all.
    pub unsent: Vec<OsProbe>,
}

impl RoundCapture {
    /// The C's `timingRatio()`: how much longer the `SEQ` probes actually took than they
    /// should have. Far from 1.0 means the ISN analysis cannot be trusted.
    ///
    /// Returns 0.0 when the probes were never sent, matching the C's early return when
    /// there is no open TCP port.
    #[must_use]
    pub fn timing_ratio(&self) -> f64 {
        match self.seq_span {
            Some(span) => span.as_secs_f64() / IDEAL_SEQ_SPAN.as_secs_f64(),
            None => 0.0,
        }
    }
}

/// The `SEQ` analysis inputs for one round.
///
/// Shared by [`to_responses`] (which feeds the fingerprint) and [`seq_report`] (which
/// feeds the `-O` report), so the two can never disagree about what was observed.
#[must_use]
pub fn seq_inputs(capture: &RoundCapture, params: &ProbeParams) -> SeqInputs {
    // The SEQ samples, in probe order. A missing reply leaves a hole rather than shifting
    // the others, because the analysis reads the gaps between consecutive samples.
    let replies = (0..NUM_SEQ_SAMPLES)
        .map(|i| {
            let t = match capture.replies.get(&OsProbe::Seq(i)) {
                Some(ProbeReply::Tcp(t)) => t,
                _ => return None,
            };
            Some(SeqReply {
                isn: t.seq,
                ip_id: 0,
                timestamp: tcp_timestamp(&t.segment).unwrap_or(0),
                sent_usec: capture.seq_send_times.get(usize::from(i)).copied()?,
            })
        })
        .collect();

    SeqInputs {
        replies,
        tcp_ipids: capture.tcp_ipids.clone(),
        closed_tcp_ipids: capture.closed_tcp_ipids.clone(),
        icmp_ipids: capture.icmp_ipids.clone(),
        ts_class: nmap_core::osprobe::seq::TsClass::Unknown,
        is_localhost: params.src == params.dst,
        scan_delay_ms: 0,
    }
}

/// The sequence-prediction facts `-O` reports, plus the uptime inferred from the
/// timestamp clock.
///
/// The C keeps these on the target (`currenths->seq`) as a side effect of building the
/// fingerprint; here they are derived explicitly from the same inputs.
///
/// `scan_epoch` is the wall-clock second the scan started, supplied by the caller. The
/// driver deliberately reads **no clock of its own**: `SystemTime::now()` is exactly the
/// impurity `estimate_uptime` takes a parameter to avoid, and calling it here made every
/// driver test unrunnable under Miri, whose isolation refuses a host clock. Passing it in
/// keeps the round deterministic and the tests real. The C anchors on the first `SEQ`
/// probe's send time; the difference is the few hundred milliseconds between scan start
/// and that probe, against an uptime reported in days.
#[must_use]
pub fn seq_report(
    capture: &RoundCapture,
    params: &ProbeParams,
    scan_epoch: Option<i64>,
) -> (SeqReport, Option<Uptime>) {
    let inputs = seq_inputs(capture, params);
    let analysis = analyze_seq(&inputs);
    let samples: Vec<&SeqReply> = inputs.replies.iter().flatten().collect();

    let report = SeqReport {
        // The C's `si.responses`: how many of the six SEQ probes were answered. Both
        // sequence gates and all three value lists are bounded by it.
        responses: analysis.responses,
        seqs: samples.iter().map(|r| r.isn).collect(),
        ipids: capture.tcp_ipids.clone(),
        timestamps: samples.iter().map(|r| r.timestamp).collect(),
        // `si.index` is the same number the `SP` attribute hex-encodes.
        index: analysis.sp_index.unwrap_or(0),
        ipid_class: get_ipid_sequence_16(
            &capture
                .tcp_ipids
                .iter()
                .map(|v| u32::from(*v))
                .collect::<Vec<u32>>(),
            inputs.is_localhost,
        ),
    };

    // Without a wall-clock anchor there is nothing to date a boot against.
    let uptime = scan_epoch.and_then(|epoch| estimate_uptime(&inputs, epoch));
    (report, uptime)
}

/// Turn a round's captured replies into the structure the assembler consumes.
#[must_use]
pub fn to_responses(capture: &RoundCapture, params: &ProbeParams, ctx: ProbeContext) -> Responses {
    let tcp_of = |probe: OsProbe| match capture.replies.get(&probe) {
        Some(ProbeReply::Tcp(t)) => Some(t.clone()),
        _ => None,
    };

    let ie = match (
        capture.replies.get(&OsProbe::Ie(0)),
        capture.replies.get(&OsProbe::Ie(1)),
    ) {
        // `DFI` and `CD` are comparisons, so one echo reply carries no `IE` evidence.
        (Some(ProbeReply::Echo(a)), Some(ProbeReply::Echo(b))) => Some(IeReplies {
            probe0: *a,
            probe1: *b,
            t_ttl: b.ttl,
        }),
        _ => None,
    };

    let u1 = match capture.replies.get(&OsProbe::U1) {
        Some(ProbeReply::UdpError(u)) => Some(u.clone()),
        _ => None,
    };

    Responses {
        seq: seq_inputs(capture, params),
        ops: (0..NUM_SEQ_SAMPLES)
            .map(|i| tcp_of(OsProbe::Ops(i)).map(|t| t.segment))
            .collect(),
        win: (0..NUM_SEQ_SAMPLES)
            .map(|i| tcp_of(OsProbe::Ops(i)).map(|t| t.window))
            .collect(),
        ecn: tcp_of(OsProbe::Ecn),
        t: (1..=u8::try_from(NUM_T_PROBES).unwrap_or(7))
            .map(|n| {
                tcp_of(OsProbe::T(n)).map(|reply| TcpProbeReply {
                    reply,
                    ctx: ProbeContext {
                        sent_seq: ctx.sent_seq,
                        sent_ack: ctx.sent_ack,
                    },
                })
            })
            .collect(),
        u1,
        u1_sent: Some(U1Sent {
            sport: params.udp_port_base,
            dport: params.closed_udp_port.unwrap_or(0),
            udp_checksum: udp_checksum_of_probe(params),
            ttl: params.udp_ttl,
        }),
        ie,
        open_tcp_port: params.open_tcp_port,
        closed_tcp_port: params.closed_tcp_port,
    }
}

/// The UDP checksum the `U1` probe actually carried.
///
/// `RUCK` compares the quoted checksum against *this exact value*, so it is read back out
/// of the packet we built rather than recomputed — a target that alters the datagram and
/// recomputes a fresh valid checksum must still be caught.
fn udp_checksum_of_probe(params: &ProbeParams) -> u16 {
    build_probe(OsProbe::U1, params)
        .ok()
        .and_then(|pkt| {
            let ihl = usize::from(*pkt.first()? & 0x0f).checked_mul(4)?;
            let off = ihl.checked_add(6)?;
            Some(u16::from_be_bytes([
                *pkt.get(off)?,
                *pkt.get(off.checked_add(1)?)?,
            ]))
        })
        .unwrap_or(0)
}

/// Run one round of the probe battery against a host and collect what comes back.
///
/// The `SEQ` probes go first and are paced at [`SEQ_PROBE_DELAY`]; the rest follow as fast
/// as they can be written. Then the capture is drained until `DRAIN_TIMEOUT` passes with
/// nothing arriving.
pub async fn run_round<S, P>(
    sender: &mut S,
    source: P,
    params: &ProbeParams,
    eth_included: bool,
) -> RoundCapture
where
    S: RawSender,
    P: PacketSource,
{
    let mut capture = AsyncCapture::spawn(source, CAPTURE_CAPACITY);
    let mut out = RoundCapture::default();
    let start = Instant::now();

    // The six SEQ probes, paced. Their send times are recorded because the ISN-rate
    // analysis divides by the real elapsed intervals, not the intended ones.
    let mut first_seq = None;
    let mut last_seq: Option<Instant> = None;
    for i in 0..NUM_SEQ_SAMPLES {
        // Wait until 100 ms have passed *since the previous probe left*, not 100 ms plus
        // however long the intervening work took. The C gates on exactly this
        // (`hostSeqSendOK`: `packTime = now - lastProbeSent; if (packTime < maxWait) wait
        // until lastProbeSent + maxWait`). Sleeping a flat 100 ms and then draining makes
        // every interval overshoot, which inflates `timingRatio` — and a ratio above 1.4
        // makes the run reject its own fingerprint as untrustworthy.
        if let Some(previous) = last_seq {
            // Checked throughout: `Instant` addition can overflow, and subtracting a
            // later instant from an earlier one would panic.
            if let Some(deadline) = previous.checked_add(SEQ_PROBE_DELAY) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    tokio::time::sleep(remaining).await;
                }
            }
        }
        let probe = OsProbe::Seq(i);
        match build_probe(probe, params) {
            Ok(pkt) => {
                let sent_at = Instant::now();
                if sender.send(&pkt).is_err() {
                    out.unsent.push(probe);
                    continue;
                }
                let usec = u64::try_from(sent_at.duration_since(start).as_micros()).unwrap_or(0);
                out.seq_send_times.push(usec);
                first_seq.get_or_insert(sent_at);
                last_seq = Some(sent_at);
            }
            Err(_) => out.unsent.push(probe),
        }
        // Drain what has already arrived, so replies to early SEQ probes are not lost to
        // channel backpressure during the pacing window. This happens inside the interval
        // — the next probe's deadline is measured from the send above, not from here.
        while let Ok(Some(frame)) =
            tokio::time::timeout(Duration::from_millis(0), capture.recv()).await
        {
            record(&mut out, &frame.data, eth_included, params);
        }
    }
    if let (Some(a), Some(b)) = (first_seq, last_seq) {
        out.seq_span = Some(b.duration_since(a));
    }

    // Everything else, back to back.
    for probe in OsProbe::all() {
        if matches!(probe, OsProbe::Seq(_)) {
            continue;
        }
        match build_probe(probe, params) {
            Ok(pkt) => {
                if sender.send(&pkt).is_err() {
                    out.unsent.push(probe);
                }
            }
            Err(_) => out.unsent.push(probe),
        }
    }

    // Drain until nothing has arrived for DRAIN_TIMEOUT (or the capture ended).
    while let Ok(Some(frame)) = tokio::time::timeout(DRAIN_TIMEOUT, capture.recv()).await {
        record(&mut out, &frame.data, eth_included, params);
    }
    capture.stop();
    out
}

/// Attribute one frame and file it under the probe it answers.
fn record(out: &mut RoundCapture, frame: &[u8], eth_included: bool, params: &ProbeParams) {
    let Some(Demuxed {
        probe,
        reply,
        ip_id,
    }) = demux(frame, eth_included, params)
    else {
        return;
    };

    // The IP-ID counters are kept apart on purpose: stacks commonly use a different
    // counter for open-port TCP, closed-port TCP and ICMP, and comparing them is what the
    // `CI`/`II`/`SS` attributes measure. Mixing them would erase the signal.
    match probe {
        OsProbe::Seq(_) | OsProbe::Ops(_) | OsProbe::Ecn | OsProbe::T(1..=4) => {
            out.tcp_ipids.push(ip_id);
        }
        OsProbe::T(_) => out.closed_tcp_ipids.push(ip_id),
        OsProbe::Ie(_) => out.icmp_ipids.push(ip_id),
        OsProbe::U1 => {}
    }

    // First reply wins: a retransmission or a duplicate must not overwrite the sample the
    // timing analysis was measured against.
    out.replies.entry(probe).or_insert(reply);
}

/// Run one round and assemble the observed fingerprint.
pub async fn scan_host<S, P>(
    sender: &mut S,
    source: P,
    params: &ProbeParams,
    eth_included: bool,
) -> (Observation, RoundCapture)
where
    S: RawSender,
    P: PacketSource,
{
    let capture = run_round(sender, source, params, eth_included).await;
    let ctx = ProbeContext {
        sent_seq: params.tcp_seq_base,
        sent_ack: params.tcp_ack,
    };
    let responses = to_responses(&capture, params, ctx);
    (assemble(&responses), capture)
}

/// Maximum OS-detection rounds, from the C's `o.maxOSTries()` default.
pub const MAX_OS_TRIES: usize = 5;

/// One host's finished OS detection.
#[derive(Debug, Clone)]
pub struct OsScanResult {
    /// The round whose fingerprint is reported.
    pub best: usize,
    /// Every round's observation, in order.
    pub rounds: Vec<Observation>,
    /// Every round's match results, aligned with `rounds`.
    pub matches: Vec<MatchResults>,
    /// Every round's sequence-prediction facts, aligned with `rounds`.
    pub seq: Vec<SeqReport>,
    /// Every round's inferred uptime, aligned with `rounds`. `None` where the target's
    /// timestamps could not date a boot.
    pub uptime: Vec<Option<Uptime>>,
    /// The worst timing ratio seen across the rounds, feeding `submission_reason`.
    pub max_timing_ratio: f64,
    /// Probes that could not be sent in the last round attempted.
    pub unsent: Vec<OsProbe>,
}

impl OsScanResult {
    /// The reported round's observation.
    #[must_use]
    pub fn observation(&self) -> Option<&Observation> {
        self.rounds.get(self.best)
    }
    /// The reported round's sequence-prediction facts.
    #[must_use]
    pub fn best_seq(&self) -> Option<&SeqReport> {
        self.seq.get(self.best)
    }
    /// The reported round's inferred uptime.
    #[must_use]
    pub fn best_uptime(&self) -> Option<Uptime> {
        self.uptime.get(self.best).copied().flatten()
    }
    /// The reported round's match results.
    #[must_use]
    pub fn best_matches(&self) -> Option<&MatchResults> {
        self.matches.get(self.best)
    }
}

/// Run OS detection against one host, retrying until it matches or the tries run out.
///
/// Ports the loop in `os_scan_ipv4`: each round sends the whole battery afresh, because a
/// probe dropped in one round may be answered in the next. A round that scores a **perfect
/// match** ends the scan (`endRound`'s completion test); otherwise the best round across
/// all attempts is reported (`findBestFPs`). Both decisions live in
/// [`nmap_core::osscan`] and are called here rather than re-derived.
///
/// `open_source` is called once per round to obtain a fresh capture — a round consumes its
/// capture, so it cannot be shared.
pub async fn scan_host_rounds<S, P, F>(
    sender: &mut S,
    mut open_source: F,
    params: &ProbeParams,
    eth_included: bool,
    db: &FingerPrintDb,
    max_tries: usize,
    scan_epoch: Option<i64>,
) -> OsScanResult
where
    S: RawSender,
    P: PacketSource,
    F: FnMut() -> std::io::Result<P>,
{
    let mut rounds: Vec<Observation> = Vec::new();
    let mut matches: Vec<MatchResults> = Vec::new();
    let mut seq: Vec<SeqReport> = Vec::new();
    let mut uptime: Vec<Option<Uptime>> = Vec::new();
    let mut policy_rounds: Vec<Round> = Vec::new();
    let mut max_timing_ratio = 0.0f64;
    let mut unsent = Vec::new();

    for _ in 0..max_tries.max(1) {
        let Ok(source) = open_source() else { break };
        let (observation, capture) = scan_host(sender, source, params, eth_included).await;

        // Recorded per round: the ratio describes how far the SEQ probes drifted from
        // their intended spacing, and a later good round does not undo an earlier bad one.
        max_timing_ratio = max_timing_ratio.max(capture.timing_ratio());
        unsent = capture.unsent.clone();

        let result = match_fingerprint(&observation.fingerprint, db, GUESS_THRESHOLD);
        let round = Round {
            fingerprint: observation.fingerprint.clone(),
            matches: result.clone(),
        };
        let conclusive = round.is_conclusive();

        let (round_seq, round_uptime) = seq_report(&capture, params, scan_epoch);
        seq.push(round_seq);
        uptime.push(round_uptime);

        rounds.push(observation);
        matches.push(result);
        policy_rounds.push(round);

        // A perfect match ends the scan; retrying could only find the same answer again.
        if conclusive {
            break;
        }
    }

    let best = best_round(&policy_rounds).unwrap_or(0);
    OsScanResult {
        best,
        rounds,
        matches,
        seq,
        uptime,
        max_timing_ratio,
        unsent,
    }
}

/// Run OS detection against one already-scanned host, end to end.
///
/// Resolves the route, picks the probe ports from the scan's own results, opens a fresh
/// capture per round, and returns the reported observation with everything
/// [`nmap_core::osscan::render`] needs.
///
/// # Errors
/// Returns `PermissionDenied` without raw-socket privilege, or another OS error if the
/// route cannot be resolved or the capture cannot be opened.
#[cfg(feature = "pcap")]
pub async fn os_scan_host(
    target: std::net::Ipv4Addr,
    ports: &[nmap_core::model::Port],
    db: &FingerPrintDb,
    max_tries: usize,
) -> std::io::Result<(OsScanResult, nmap_core::osscan::ProbePorts, ProbeParams)> {
    use crate::capture::pcap_source::PcapSource;
    use crate::rawio::RawIpv4Sender;
    use crate::route::route_for;
    use nmap_core::osscan::select_probe_ports;

    let mut sender = RawIpv4Sender::new()?;
    let route = route_for(target)?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no route to target")
    })?;

    // The probe ports come from what the scan actually found, not from a guess, wherever
    // the scan found anything usable.
    let selected = select_probe_ports(ports, rand_u32());
    let params = ProbeParams {
        src: route.src.octets(),
        dst: target.octets(),
        ttl: 64,
        // The C randomises the U1 TTL separately as `(time % 14) + 51`.
        udp_ttl: 57,
        ip_id: 0x1042,
        tcp_port_base: 33000u16.wrapping_add(u16::try_from(rand_u32() % 32261).unwrap_or(0)),
        udp_port_base: 33000u16.wrapping_add(u16::try_from(rand_u32() % 32261).unwrap_or(0)),
        tcp_seq_base: rand_u32(),
        tcp_ack: rand_u32(),
        icmp_echo_id: u16::try_from(rand_u32() & 0xffff).unwrap_or(0x1234),
        icmp_echo_seq: nmap_core::osprobe::build::ICMP_ECHO_SEQ,
        open_tcp_port: selected.open_tcp,
        closed_tcp_port: selected.closed_tcp,
        closed_udp_port: selected.closed_udp,
    };

    let iface = route.iface.clone();
    let filter = bpf_filter(&params);
    // The one clock read on this path, taken here rather than inside the round so the
    // driver itself stays deterministic and Miri-testable.
    let scan_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok());
    let result = scan_host_rounds(
        &mut sender,
        || PcapSource::open(&iface, 65535, 100, Some(&filter)),
        &params,
        route.eth_included,
        db,
        max_tries,
        scan_epoch,
    )
    .await;
    Ok((result, selected, params))
}

/// A scan-scoped random value. The probe identifiers must be unpredictable to a target
/// that would otherwise recognise and special-case our battery.
#[cfg(feature = "pcap")]
fn rand_u32() -> u32 {
    crate::route::random_scan_keys().0
}

/// Convenience: the target address a [`ProbeParams`] points at.
#[must_use]
pub fn target_of(params: &ProbeParams) -> Ipv4Addr {
    Ipv4Addr::from(params.dst)
}

/// Which source ports the battery will use, for building a capture filter.
#[must_use]
pub fn bpf_filter(params: &ProbeParams) -> String {
    let src = Ipv4Addr::from(params.src);
    let dst = Ipv4Addr::from(params.dst);
    let lo = params.tcp_port_base;
    let hi = lo.wrapping_add(19);
    format!("src host {dst} and dst host {src} and (icmp or (tcp and dst portrange {lo}-{hi}))")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rawio::MockSender;
    use nmap_core::osdb::model::TestId;
    use nmap_core::osprobe::build::ICMP_ECHO_SEQ;
    use std::io;
    use std::sync::{Arc, Mutex};

    fn params() -> ProbeParams {
        ProbeParams {
            src: [10, 0, 0, 1],
            dst: [10, 0, 0, 2],
            ttl: 64,
            udp_ttl: 57,
            ip_id: 0x1111,
            tcp_port_base: 40000,
            udp_port_base: 44444,
            tcp_seq_base: 0x1000_0000,
            tcp_ack: 0,
            icmp_echo_id: 0x1234,
            icmp_echo_seq: ICMP_ECHO_SEQ,
            open_tcp_port: Some(22),
            closed_tcp_port: Some(1),
            closed_udp_port: Some(65000),
        }
    }

    /// A packet source that replays a scripted list of frames, then reports idle.
    struct Scripted {
        frames: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl PacketSource for Scripted {
        fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            let mut f = self.frames.lock().unwrap_or_else(|e| e.into_inner());
            if f.is_empty() {
                // Idle: the driver's drain timeout ends the round.
                std::thread::sleep(Duration::from_millis(5));
                Ok(None)
            } else {
                Ok(Some(f.remove(0)))
            }
        }
    }

    fn ipv4(p: &ProbeParams, proto: u8, ttl: u8, ip_id: u16, df: bool, payload: &[u8]) -> Vec<u8> {
        let total = 20usize.saturating_add(payload.len());
        let mut v = vec![0u8; 20];
        v[0] = 0x45;
        v[2..4].copy_from_slice(&u16::try_from(total).unwrap_or(0).to_be_bytes());
        v[4..6].copy_from_slice(&ip_id.to_be_bytes());
        if df {
            v[6] = 0x40;
        }
        v[8] = ttl;
        v[9] = proto;
        v[12..16].copy_from_slice(&p.dst);
        v[16..20].copy_from_slice(&p.src);
        v.extend_from_slice(payload);
        v
    }

    fn tcp(dport: u16, seq: u32, ack: u32, flags: u8, window: u16) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&22u16.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&window.to_be_bytes());
        t
    }

    #[tokio::test]
    async fn the_whole_battery_goes_on_the_wire() {
        let p = params();
        let mut sender = MockSender::default();
        let source = Scripted {
            frames: Arc::new(Mutex::new(Vec::new())),
        };
        let capture = run_round(&mut sender, source, &p, false).await;

        // All 23 probes, and nothing failed to build with every port available.
        assert_eq!(sender.sent.len(), 23, "expected the full battery");
        assert!(capture.unsent.is_empty(), "unsent: {:?}", capture.unsent);
        assert_eq!(capture.seq_send_times.len(), usize::from(NUM_SEQ_SAMPLES));
    }

    #[tokio::test]
    async fn the_seq_probes_are_paced_not_blasted() {
        let p = params();
        let mut sender = MockSender::default();
        let source = Scripted {
            frames: Arc::new(Mutex::new(Vec::new())),
        };
        let started = Instant::now();
        let capture = run_round(&mut sender, source, &p, false).await;
        let elapsed = started.elapsed();

        // Five gaps of 100 ms is the floor; sending faster would corrupt the ISN-rate and
        // timestamp-frequency analysis, not merely finish sooner.
        assert!(
            elapsed >= IDEAL_SEQ_SPAN,
            "battery finished in {elapsed:?}, faster than the 500 ms SEQ floor"
        );
        let span = capture.seq_span.expect("a span for six probes");
        assert!(span >= IDEAL_SEQ_SPAN, "SEQ span {span:?} below the floor");

        // timingRatio is the observed span over the ideal, so it must be at least ~1.
        let ratio = capture.timing_ratio();
        assert!(
            ratio >= 0.99,
            "timing ratio {ratio} implies impossible pacing"
        );
    }

    #[tokio::test]
    async fn a_missing_open_port_leaves_those_probes_unsent_rather_than_silent() {
        // Without an open TCP port the SEQ/OPS/ECN/T1-T4 probes cannot be built. They must
        // be reported as unsent, so the assembler can tell "never asked" from "no answer".
        let mut p = params();
        p.open_tcp_port = None;
        let mut sender = MockSender::default();
        let source = Scripted {
            frames: Arc::new(Mutex::new(Vec::new())),
        };
        let capture = run_round(&mut sender, source, &p, false).await;

        assert!(capture.unsent.contains(&OsProbe::Seq(0)));
        assert!(capture.unsent.contains(&OsProbe::Ecn));
        assert!(capture.unsent.contains(&OsProbe::T(1)));
        // T5-T7, IE and U1 need only the closed ports, so they still go out.
        assert!(!capture.unsent.contains(&OsProbe::T(5)));
        assert!(!capture.unsent.contains(&OsProbe::U1));
    }

    #[tokio::test]
    async fn replies_are_attributed_and_reach_the_fingerprint() {
        let p = params();
        // Answer T5 and one echo probe; leave the rest silent.
        let t5_port = nmap_core::osprobe::build::source_port(OsProbe::T(5), &p).expect("port");
        let mut echo = vec![0u8; 8];
        echo[4..6].copy_from_slice(&p.icmp_echo_id.to_be_bytes());
        echo[6..8].copy_from_slice(&p.icmp_echo_seq.to_be_bytes());

        let frames = vec![
            ipv4(
                &p,
                6,
                61,
                0x2a,
                true,
                &tcp(t5_port, 0, 0x1000_0001, 0x14, 0),
            ),
            ipv4(&p, 1, 61, 0x2b, false, &echo),
        ];
        let mut sender = MockSender::default();
        let source = Scripted {
            frames: Arc::new(Mutex::new(frames)),
        };
        let (observation, capture) = scan_host(&mut sender, source, &p, false).await;

        assert!(
            capture.replies.contains_key(&OsProbe::T(5)),
            "T5 reply not attributed: {:?}",
            capture.replies.keys().collect::<Vec<_>>()
        );
        // T5 answers on the closed port, so its IP ID belongs to the closed-port counter.
        assert_eq!(capture.closed_tcp_ipids, vec![0x2a]);
        assert_eq!(capture.icmp_ipids, vec![0x2b]);

        // T5 answered, so the fingerprint records a response for it...
        let t5 = observation.fingerprint.test(TestId::T5).expect("T5 test");
        assert_eq!(t5.get("R"), Some("Y"));
        // ...while a probe that was sent and ignored is recorded as silent.
        let t6 = observation.fingerprint.test(TestId::T6).expect("T6 test");
        assert_eq!(t6.get("R"), Some("N"));
        // Only one echo reply arrived, and IE is a comparison of two, so it carries no
        // evidence and must fall back to silence rather than half an answer.
        let ie = observation.fingerprint.test(TestId::Ie).expect("IE test");
        assert_eq!(ie.get("R"), Some("N"));
    }

    /// A minimal SYN/ACK carrying a TCP timestamp option — enough for the SEQ analysis,
    /// which reads the ISN from the header and the timestamp out of the options.
    fn seq_reply(seq: u32, tsval: u32) -> nmap_core::osprobe::tcpreply::TcpReply {
        let mut segment = vec![0u8; 20];
        segment[4..8].copy_from_slice(&seq.to_be_bytes());
        // Data offset 8 words (20 header + 12 options); SYN|ACK.
        segment[12] = 8 << 4;
        segment[13] = 0x12;
        segment[14..16].copy_from_slice(&1024u16.to_be_bytes());
        // NOP, NOP, Timestamp(kind 8, len 10, tsval, tsecr).
        segment.extend_from_slice(&[0x01, 0x01, 0x08, 0x0a]);
        segment.extend_from_slice(&tsval.to_be_bytes());
        segment.extend_from_slice(&0u32.to_be_bytes());
        nmap_core::osprobe::tcpreply::TcpReply {
            df: false,
            ttl: 64,
            window: 1024,
            seq,
            ack: 0,
            flags: 0x12,
            reserved: 0,
            urgent_ptr: 0,
            segment,
        }
    }

    // The uptime path, end to end through the driver, with a FIXED epoch — so it proves
    // determinism as well as correctness. Reading a clock here is what broke Miri.
    #[test]
    fn seq_report_is_a_deterministic_function_of_its_inputs() {
        let params = params();
        let mut capture = RoundCapture::default();
        // Six SEQ replies whose timestamp advances 10 ticks per 100 ms = 100 Hz, with a
        // first value of 360_000 ticks — one hour of uptime.
        for i in 0..NUM_SEQ_SAMPLES {
            let n = u32::from(i);
            capture.seq_send_times.push(u64::from(n) * 100_000);
            capture.replies.insert(
                OsProbe::Seq(i),
                ProbeReply::Tcp(seq_reply(1000 + n, 360_000 + n * 10)),
            );
        }

        let epoch = 1_700_000_000i64;
        let (report, uptime) = seq_report(&capture, &params, Some(epoch));

        assert_eq!(report.seqs.len(), usize::from(NUM_SEQ_SAMPLES));
        assert_eq!(report.timestamps.first().copied(), Some(360_000));
        let u = uptime.expect("a 100 Hz clock at 360000 ticks is one hour of uptime");
        assert_eq!(u.seconds, 3600);
        assert_eq!(u.lastboot, epoch - 3600);

        // Same inputs, same answer — no hidden clock.
        assert_eq!(seq_report(&capture, &params, Some(epoch)).1, uptime);
        // No anchor, no boot time: the report still stands, the uptime does not.
        let (report2, none) = seq_report(&capture, &params, None);
        assert_eq!(none, None);
        assert_eq!(report2.timestamps, report.timestamps);
    }

    #[tokio::test]
    async fn a_duplicate_reply_does_not_replace_the_first() {
        let p = params();
        let port = nmap_core::osprobe::build::source_port(OsProbe::T(5), &p).expect("port");
        let frames = vec![
            ipv4(&p, 6, 61, 1, true, &tcp(port, 0, 0x1000_0001, 0x14, 111)),
            // A retransmission with a different window must not overwrite the first.
            ipv4(&p, 6, 61, 2, true, &tcp(port, 0, 0x1000_0001, 0x14, 999)),
        ];
        let mut sender = MockSender::default();
        let source = Scripted {
            frames: Arc::new(Mutex::new(frames)),
        };
        let capture = run_round(&mut sender, source, &p, false).await;
        match capture.replies.get(&OsProbe::T(5)) {
            Some(ProbeReply::Tcp(t)) => {
                assert_eq!(t.window, 111, "a duplicate overwrote the first")
            }
            other => panic!("expected a T5 TCP reply, got {other:?}"),
        }
    }

    #[test]
    fn timing_ratio_reports_zero_when_nothing_was_sent() {
        // Matches the C's early return when there is no open TCP port.
        assert_eq!(RoundCapture::default().timing_ratio(), 0.0);
        let stretched = RoundCapture {
            seq_span: Some(Duration::from_millis(1000)),
            ..Default::default()
        };
        assert!((stretched.timing_ratio() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn the_filter_scopes_capture_to_this_host_and_our_ports() {
        let f = bpf_filter(&params());
        assert!(f.contains("src host 10.0.0.2"), "{f}");
        assert!(f.contains("dst host 10.0.0.1"), "{f}");
        assert!(f.contains("40000-40019"), "{f}");
        assert!(f.contains("icmp"), "{f}");
    }
}
