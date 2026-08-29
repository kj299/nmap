//! The privileged IPv6 OS-detection driver — the I/O half of `FPHost6`.
//!
//! Every decision this module drives has already been ported as a pure function and gated
//! by a differential: the probes come from [`nmap_core::build6`], a captured packet is
//! attributed to the probe it answers by [`nmap_core::fp6_match::is_response`], the feature
//! vector is built by [`nmap_core::fp6::vectorize`], and the classifier is
//! [`nmap_core::fpmodel`]. What is left here is *sending and waiting* — and, like the IPv4
//! [`crate::osscan`] driver, it is generic over [`RawSender`] and [`PacketSource`] so the
//! whole round can be exercised with mocks. **No `unsafe`.**
//!
//! ## Pacing mirrors the IPv4 SEQ discipline
//!
//! The six SEQ probes (`S1`–`S6`) are the "timed" battery: nmap derives an inter-send ISN
//! rate from their *actual* send spacing, so they are sent no faster than one per
//! [`SEQ_PROBE_DELAY`], measured from the previous send (not a flat sleep, which would
//! overshoot). Everything else goes back to back.
//!
//! ## Distance is localhost / direct / none — the hop-limit path is dead
//!
//! nmap's `FPHost6::finish` computes a hop-limit distance from the `IE2` and `U1`
//! responses via `get_encapsulated_hoplimit`, which needs an ICMPv6 **error** quoting an
//! inner IPv6 datagram. But `is_response` never attributes an ICMPv6 error to any probe
//! (the `dynamic_cast` bug ported in [`nmap_core::fp6_match`]), and `IE2`'s echo reply is
//! informational (no encapsulated packet), so that path yields `-1` every time. The driver
//! therefore sets distance from locality alone — `0` for localhost, `1` for a
//! directly-connected target, `None` otherwise — which is exactly what nmap ends up with.
//! Ledgered `fp6-distance-hoplimit-path-is-dead`.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

use nmap_core::build6::{build_probes, Build6Params, Probe6};
use nmap_core::fp6::{DistMethod, Fp6Observation, Fp6Probe, Fp6Response};
use nmap_core::fp6_match::is_response;
use nmap_core::fpmodel::{classify, Fp6Results, FpModel};

use crate::capture::{AsyncCapture, PacketSource};
use crate::rawio::RawSender;

/// Minimum spacing between the six SEQ probes, from nmap's OS-detection timing. Shares the
/// IPv4 value; the ISN-rate analysis is measured from real send times, so sending faster
/// corrupts the fingerprint rather than speeding it up.
pub const SEQ_PROBE_DELAY: Duration = Duration::from_millis(100);

/// How long to keep listening after the last probe before giving up on stragglers.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(1500);
/// Capture backlog.
const CAPTURE_CAPACITY: usize = 2048;
/// The SEQ probes, in send order — the ones that must be paced.
const SEQ_PROBES: [Fp6Probe; 6] = [
    Fp6Probe::S1,
    Fp6Probe::S2,
    Fp6Probe::S3,
    Fp6Probe::S4,
    Fp6Probe::S5,
    Fp6Probe::S6,
];

/// A probe as sent: its identity, wire bytes, and the wall-clock time it left. The send
/// time matters only for the SEQ probes (the ISN-rate feature divides by their spacing).
struct SentProbe {
    probe: Probe6,
    sent_sec: i64,
    sent_usec: i64,
    answered: bool,
}

/// Split a `SystemTime` into whole seconds and microseconds since the epoch, matching the
/// `struct timeval` nmap records per probe.
fn timeval(now: SystemTime) -> (i64, i64) {
    match now.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => (
            i64::try_from(d.as_secs()).unwrap_or(0),
            i64::from(d.subsec_micros()),
        ),
        Err(_) => (0, 0),
    }
}

/// Strip a link-layer header if the capture includes one, yielding the packet from the
/// IPv6 header onward — what [`is_response`] expects.
fn network_layer(frame: &[u8], eth_included: bool) -> &[u8] {
    if eth_included {
        frame.get(14..).unwrap_or(&[])
    } else {
        frame
    }
}

/// Send the IPv6 battery for `params` and collect the responses, attributing each captured
/// frame to the probe it answers. Generic over the sender and capture source so a test can
/// drive it with mocks.
pub async fn run_round<S, P>(
    sender: &mut S,
    source: P,
    params: &Build6Params,
    eth_included: bool,
) -> HashMap<Fp6Probe, Fp6Response>
where
    S: RawSender,
    P: PacketSource,
{
    let battery = build_probes(params);
    let mut sent: Vec<SentProbe> = Vec::with_capacity(battery.len());
    let mut capture = AsyncCapture::spawn(source, CAPTURE_CAPACITY);
    let mut responses: HashMap<Fp6Probe, Fp6Response> = HashMap::new();

    // The SEQ probes first, paced; then everything else back to back.
    let (seq, rest): (Vec<&Probe6>, Vec<&Probe6>) =
        battery.iter().partition(|p| SEQ_PROBES.contains(&p.id));

    let mut last_seq: Option<Instant> = None;
    for probe in seq {
        if let Some(previous) = last_seq {
            if let Some(deadline) = previous.checked_add(SEQ_PROBE_DELAY) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    tokio::time::sleep(remaining).await;
                }
            }
        }
        send_probe(sender, probe, &mut sent);
        last_seq = Some(Instant::now());
        // Drain what has already arrived, inside the pacing window.
        drain_ready(&mut capture, &mut sent, &mut responses, eth_included).await;
    }
    for probe in rest {
        send_probe(sender, probe, &mut sent);
    }

    // Drain until nothing has arrived for DRAIN_TIMEOUT (or the capture ended).
    while let Ok(Some(frame)) = tokio::time::timeout(DRAIN_TIMEOUT, capture.recv()).await {
        attribute(&frame.data, &mut sent, &mut responses, eth_included);
    }
    capture.stop();
    responses
}

/// Send one probe, recording its wire time.
fn send_probe<S: RawSender>(sender: &mut S, probe: &Probe6, sent: &mut Vec<SentProbe>) {
    let (sec, usec) = timeval(SystemTime::now());
    // A send error just means this probe goes unanswered; keep going with the rest.
    let _ = sender.send(&probe.packet);
    sent.push(SentProbe {
        probe: probe.clone(),
        sent_sec: sec,
        sent_usec: usec,
        answered: false,
    });
}

/// Drain frames already queued (zero-timeout), attributing each.
async fn drain_ready(
    capture: &mut AsyncCapture,
    sent: &mut [SentProbe],
    responses: &mut HashMap<Fp6Probe, Fp6Response>,
    eth_included: bool,
) {
    while let Ok(Some(frame)) = tokio::time::timeout(Duration::from_millis(0), capture.recv()).await
    {
        attribute(&frame.data, sent, responses, eth_included);
    }
}

/// Attribute one captured frame to the first outstanding probe it answers.
fn attribute(
    frame: &[u8],
    sent: &mut [SentProbe],
    responses: &mut HashMap<Fp6Probe, Fp6Response>,
    eth_included: bool,
) {
    let net = network_layer(frame, eth_included);
    for entry in sent.iter_mut() {
        if entry.answered {
            continue;
        }
        if is_response(&entry.probe.packet, net) {
            responses
                .entry(entry.probe.id)
                .or_insert_with(|| Fp6Response {
                    packet: net.to_vec(),
                    sent_sec: entry.sent_sec,
                    sent_usec: entry.sent_usec,
                });
            entry.answered = true;
            return;
        }
    }
}

/// The BPF capture filter for an IPv6 OS-detection scan of `params`: frames from the
/// target to us that are either ICMPv6 (echo replies, neighbor advertisements, and the
/// error messages the U1/T probes can draw) or TCP replies to one of the 13 TCP probes'
/// source ports. Mirrors the IPv4 [`crate::osscan::bpf_filter`]; the UDP `U1` probe draws
/// only ICMPv6 errors, so no UDP clause is needed.
#[must_use]
pub fn bpf_filter(params: &Build6Params) -> String {
    let src = fmt_ipv6(params.src);
    let dst = fmt_ipv6(params.dst);
    let lo = params.tcp_port_base;
    let hi = lo.wrapping_add(12); // 13 TCP probes: base .. base+12
    format!("src host {dst} and dst host {src} and (icmp6 or (tcp and dst portrange {lo}-{hi}))")
}

/// Render 16 address bytes as a colon-grouped IPv6 literal for a BPF expression.
fn fmt_ipv6(addr: [u8; 16]) -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::from(addr)
}

/// How far the target is, as [`FPHost6::finish`] resolves it for IPv6 (the hop-limit path
/// being dead — see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locality {
    /// The scan targets the local host.
    Localhost,
    /// The target is on the same link.
    DirectlyConnected,
    /// The target is remote (distance stays unknown for IPv6).
    Remote,
}

impl Locality {
    /// The `(distance, method)` pair this locality yields.
    fn distance(self) -> (i32, DistMethod) {
        match self {
            Locality::Localhost => (0, DistMethod::Localhost),
            Locality::DirectlyConnected => (1, DistMethod::Direct),
            Locality::Remote => (-1, DistMethod::None),
        }
    }
}

/// Assemble the [`Fp6Observation`] from a round's responses and the target's locality.
#[must_use]
pub fn assemble_observation(
    responses: HashMap<Fp6Probe, Fp6Response>,
    locality: Locality,
) -> Fp6Observation {
    let (distance, method) = locality.distance();
    let mut obs = Fp6Observation::new(distance, method);
    for (probe, response) in responses {
        obs.insert(probe, response);
    }
    obs
}

/// Run one round, assemble the observation, and classify it.
pub async fn scan_host<S, P>(
    sender: &mut S,
    source: P,
    params: &Build6Params,
    eth_included: bool,
    locality: Locality,
    model: &FpModel,
) -> (Fp6Observation, Fp6Results)
where
    S: RawSender,
    P: PacketSource,
{
    let responses = run_round(sender, source, params, eth_included).await;
    let observation = assemble_observation(responses, locality);
    let raw = nmap_core::fp6::vectorize(&observation);
    let results = classify(model, &raw);
    (observation, results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rawio::MockSender;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// A capture source that yields a fixed script of frames, then idles.
    struct ScriptedSource {
        frames: Arc<Mutex<std::vec::IntoIter<Vec<u8>>>>,
        hold_until: Instant,
        held: bool,
    }
    impl ScriptedSource {
        /// `hold` delays the first frame, so a reply to a *non-SEQ* probe (sent only after
        /// the ~600 ms of SEQ pacing) lands in the final drain — the way a real reply
        /// would — rather than being seen before its probe is sent.
        fn new(frames: Vec<Vec<u8>>, hold: Duration) -> Self {
            ScriptedSource {
                frames: Arc::new(Mutex::new(frames.into_iter())),
                hold_until: Instant::now()
                    .checked_add(hold)
                    .unwrap_or_else(Instant::now),
                held: false,
            }
        }
    }
    impl PacketSource for ScriptedSource {
        fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            if !self.held {
                let now = Instant::now();
                if now < self.hold_until {
                    std::thread::sleep(Duration::from_millis(2));
                    return Ok(None);
                }
                self.held = true;
            }
            let next = self.frames.lock().unwrap().next();
            match next {
                Some(f) => Ok(Some(f)),
                // End after the scripted frames so the capture channel closes and the
                // drain loop returns promptly instead of waiting out DRAIN_TIMEOUT.
                None => Err(io::Error::other("end of script")),
            }
        }
    }
    /// Frames for a SEQ-probe reply can arrive immediately (S1 is sent first).
    const NOW: Duration = Duration::from_millis(0);
    /// Frames for a non-SEQ-probe reply must wait out the SEQ pacing window.
    const AFTER_BATTERY: Duration = Duration::from_millis(650);

    const US: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    const THEM: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    fn params() -> Build6Params {
        Build6Params {
            src: US,
            dst: THEM,
            open_tcp_port: Some(22),
            closed_tcp_port: Some(1),
            closed_udp_port: 42,
            tcp_port_base: 33000,
            udp_port_base: 34000,
            tcp_seq_base: 0x1000,
            tcp_acks: [7; 13],
            hop_limit: 64,
            icmp_seq: 0x1234,
            directly_connected: true,
        }
    }

    fn ipv6(src: [u8; 16], dst: [u8; 16], nh: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0x01, 0x23, 0x45];
        p.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        p.push(nh);
        p.push(64);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(payload);
        p
    }

    fn tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&[0; 8]);
        t.push(0x50);
        t.push(flags);
        t.extend_from_slice(&[0; 6]);
        t
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg_attr(
        miri,
        ignore = "spawns a real capture thread and reads the system clock; Miri supports neither"
    )]
    async fn a_synacked_open_port_is_attributed_to_s1() {
        let p = params();
        // S1 is the first SEQ probe: sport = tcp_port_base + 0 = 33000, dport = open = 22.
        let reply = ipv6(THEM, US, 6, &tcp(22, 33000, 0x12)); // SYN+ACK
        let source = ScriptedSource::new(vec![reply], NOW);
        let mut sender = MockSender::default();

        let responses = run_round(&mut sender, source, &p, false).await;
        assert!(
            responses.contains_key(&Fp6Probe::S1),
            "S1 SYN/ACK not attributed; got {:?}",
            responses.keys().collect::<Vec<_>>()
        );
        // The whole battery was sent (17 probes for a fully-populated, on-link target).
        assert_eq!(sender.sent.len(), 17);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg_attr(
        miri,
        ignore = "spawns a real capture thread and reads the system clock; Miri supports neither"
    )]
    async fn an_echo_reply_is_attributed_to_ie1() {
        let p = params();
        // IE1 echo: code 9, id 0xabcd, seq = icmp_seq (0x1234). Reply mirrors id/seq.
        let mut echo_reply = vec![129u8, 0, 0, 0];
        echo_reply.extend_from_slice(&[0xab, 0xcd, 0x12, 0x34]);
        let reply = ipv6(THEM, US, 58, &echo_reply);
        let hold = AFTER_BATTERY;
        let responses = run_round(
            &mut MockSender::default(),
            ScriptedSource::new(vec![reply], hold),
            &p,
            false,
        )
        .await;
        assert!(responses.contains_key(&Fp6Probe::Ie1));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg_attr(
        miri,
        ignore = "spawns a real capture thread and reads the system clock; Miri supports neither"
    )]
    async fn an_icmp_error_is_never_attributed() {
        let p = params();
        // A destination-unreachable quoting our U1 probe: nmap (and the port) never match it.
        let quoted = ipv6(US, THEM, 17, &{
            let mut u = Vec::new();
            u.extend_from_slice(&34000u16.to_be_bytes());
            u.extend_from_slice(&42u16.to_be_bytes());
            u.extend_from_slice(&[0x01, 0x34, 0, 0]);
            u
        });
        let mut err = vec![1u8, 0, 0, 0, 0, 0, 0, 0];
        err.extend_from_slice(&quoted);
        let reply = ipv6(THEM, US, 58, &err);
        let hold = AFTER_BATTERY;
        let responses = run_round(
            &mut MockSender::default(),
            ScriptedSource::new(vec![reply], hold),
            &p,
            false,
        )
        .await;
        assert!(
            !responses.contains_key(&Fp6Probe::U1),
            "an ICMPv6 error must not be attributed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg_attr(
        miri,
        ignore = "spawns a real capture thread and reads the system clock; Miri supports neither"
    )]
    async fn a_frame_from_the_wrong_host_is_ignored() {
        let p = params();
        let other = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
        ];
        let reply = ipv6(other, US, 6, &tcp(22, 33000, 0x12));
        let hold = NOW;
        let responses = run_round(
            &mut MockSender::default(),
            ScriptedSource::new(vec![reply], hold),
            &p,
            false,
        )
        .await;
        assert!(responses.is_empty());
    }

    #[test]
    fn locality_maps_to_the_distance_finish_would_set() {
        assert_eq!(Locality::Localhost.distance(), (0, DistMethod::Localhost));
        assert_eq!(
            Locality::DirectlyConnected.distance(),
            (1, DistMethod::Direct)
        );
        assert_eq!(Locality::Remote.distance(), (-1, DistMethod::None));
    }

    #[test]
    fn the_capture_filter_scopes_to_the_target_and_our_ports() {
        let f = bpf_filter(&params());
        assert!(f.contains("src host 2001:db8::2"), "{f}");
        assert!(f.contains("dst host 2001:db8::1"), "{f}");
        assert!(f.contains("icmp6"), "{f}");
        assert!(f.contains("dst portrange 33000-33012"), "{f}");
    }

    #[test]
    fn assemble_observation_carries_distance_and_responses() {
        let mut responses = HashMap::new();
        responses.insert(
            Fp6Probe::S1,
            Fp6Response {
                packet: vec![0x60; 40],
                sent_sec: 1,
                sent_usec: 2,
            },
        );
        let obs = assemble_observation(responses, Locality::DirectlyConnected);
        assert_eq!(obs.distance, 1);
        assert_eq!(obs.distance_method, DistMethod::Direct);
        assert!(obs.get(Fp6Probe::S1).is_some());
    }
}
