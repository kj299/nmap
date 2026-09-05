//! IPv6 fingerprint vectorization — nmap's `vectorize()` from `FPEngine.cc`.
//!
//! The IPv6 OS classifier ([`crate::fpmodel`]) works on a fixed 695-element feature
//! vector. This module builds that vector from the probe responses a host returned:
//! the payload length, traffic class and hop limit of each of the 17 IPv6 probes; an
//! inter-send ISN rate derived from the six SEQ probes; the window, flags and options
//! of each of the 13 TCP probes; and the type and code of each of the 3 ICMPv6 probes.
//! [`crate::fpmodel::classify`] then turns that vector into an OS guess.
//!
//! Every feature starts at the sentinel `-1`, which [`crate::fpmodel::apply_scale`]
//! leaves untouched — so a probe that went unanswered, or a field a response omitted,
//! contributes "no evidence" rather than a fabricated value. That sentinel is the whole
//! reason #71 had to fix `apply_scale`; here is where it originates.
//!
//! ## Faithfulness to a C quirk that must be preserved, not "fixed"
//!
//! `tcpopt_vectorize` writes an option's opcode and length into the feature vector
//! **before** the bounds check that stops after 16 options. A TCP segment carrying a
//! 17th option therefore overwrites the *first* option's length slot with the 17th
//! option's opcode, and then the walk stops. This is a genuine oddity, but it is
//! **not** a memory error — every index it can reach stays inside the 695-element
//! vector (the worst case, the last TCP probe, reaches index 685) — and the model was
//! trained against vectors built exactly this way. Diverging would make our
//! classification disagree with nmap's for no safety benefit, so the quirk is
//! reproduced deliberately and marked below, the same posture taken for the
//! routing-header length quirk in [`crate::headers::ipv6ext`]. A hostile 40-byte
//! option field cannot make the writes leave the vector, so reproducing it is safe.

use std::collections::HashMap;

use crate::headers::icmpv6::Icmpv6Header;
use crate::headers::ipv6::Ipv6Header;
use crate::headers::tcp::TcpHeader;
use crate::packet_parser::{parse_packet, Header};

/// The feature-vector length nmap's model expects (`get_nr_feature(&FPModel)`).
///
/// 17 IPv6 probes × 3 + 1 ISR + 13 TCP probes × 49 + 3 ICMPv6 probes × 2 = 695.
pub const N_FEATURE: usize = 695;

/// How many TCP options `tcpopt_vectorize` records before the walk stops
/// (`MODEL_NUM_OPTS`). The opcode of the 17th option lands on the first option's
/// length slot; see the module docs.
const MODEL_NUM_OPTS: usize = 16;

/// The absent-attribute sentinel every feature is initialised to.
const ABSENT: f64 = -1.0;

/// The 17 probes whose IPv6 header (payload length / traffic class / hop limit) is
/// vectorized, in the order `IPV6_PROBE_NAMES` gives them.
const IPV6_PROBE_ORDER: [Fp6Probe; 17] = [
    Fp6Probe::S1,
    Fp6Probe::S2,
    Fp6Probe::S3,
    Fp6Probe::S4,
    Fp6Probe::S5,
    Fp6Probe::S6,
    Fp6Probe::Ie1,
    Fp6Probe::Ie2,
    Fp6Probe::Ns,
    Fp6Probe::U1,
    Fp6Probe::Tecn,
    Fp6Probe::T2,
    Fp6Probe::T3,
    Fp6Probe::T4,
    Fp6Probe::T5,
    Fp6Probe::T6,
    Fp6Probe::T7,
];

/// The 13 probes whose TCP header is vectorized, in `TCP_PROBE_NAMES` order.
const TCP_PROBE_ORDER: [Fp6Probe; 13] = [
    Fp6Probe::S1,
    Fp6Probe::S2,
    Fp6Probe::S3,
    Fp6Probe::S4,
    Fp6Probe::S5,
    Fp6Probe::S6,
    Fp6Probe::Tecn,
    Fp6Probe::T2,
    Fp6Probe::T3,
    Fp6Probe::T4,
    Fp6Probe::T5,
    Fp6Probe::T6,
    Fp6Probe::T7,
];

/// The 3 probes whose ICMPv6 header is vectorized, in `ICMPV6_PROBE_NAMES` order.
const ICMPV6_PROBE_ORDER: [Fp6Probe; 3] = [Fp6Probe::Ie1, Fp6Probe::Ie2, Fp6Probe::Ns];

/// The six SEQ probes, whose ISNs and send times give the ISR feature.
const SEQ_PROBE_ORDER: [Fp6Probe; 6] = [
    Fp6Probe::S1,
    Fp6Probe::S2,
    Fp6Probe::S3,
    Fp6Probe::S4,
    Fp6Probe::S5,
    Fp6Probe::S6,
];

/// How the target's hop distance was measured — nmap's `enum dist_calc_method`
/// (`osscan.h`), in the same numeric order. Only whether it is `None`, and whether it
/// is `Icmp`/`Traceroute`, changes the hop-limit rounding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistMethod {
    None,
    Localhost,
    Direct,
    Icmp,
    Traceroute,
}

/// One of the 17 IPv6 OS-detection probes, identified the way nmap identifies them —
/// by name. The `S`* probes are the SEQ battery; `IE1`/`IE2`/`NS` are the ICMPv6
/// probes; `U1` is the UDP probe; `TECN`/`T2`–`T7` are the crafted TCP probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fp6Probe {
    S1,
    S2,
    S3,
    S4,
    S5,
    S6,
    Ie1,
    Ie2,
    Ns,
    U1,
    Tecn,
    T2,
    T3,
    T4,
    T5,
    T6,
    T7,
}

impl Fp6Probe {
    /// The probe's nmap id (`"S1"`, `"IE1"`, `"NS"`, `"U1"`, `"TECN"`, `"T2"`, …).
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Fp6Probe::S1 => "S1",
            Fp6Probe::S2 => "S2",
            Fp6Probe::S3 => "S3",
            Fp6Probe::S4 => "S4",
            Fp6Probe::S5 => "S5",
            Fp6Probe::S6 => "S6",
            Fp6Probe::Ie1 => "IE1",
            Fp6Probe::Ie2 => "IE2",
            Fp6Probe::Ns => "NS",
            Fp6Probe::U1 => "U1",
            Fp6Probe::Tecn => "TECN",
            Fp6Probe::T2 => "T2",
            Fp6Probe::T3 => "T3",
            Fp6Probe::T4 => "T4",
            Fp6Probe::T5 => "T5",
            Fp6Probe::T6 => "T6",
            Fp6Probe::T7 => "T7",
        }
    }

    /// Parse a probe id, or `None` if it is not one of the 17.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Fp6Probe> {
        Some(match id {
            "S1" => Fp6Probe::S1,
            "S2" => Fp6Probe::S2,
            "S3" => Fp6Probe::S3,
            "S4" => Fp6Probe::S4,
            "S5" => Fp6Probe::S5,
            "S6" => Fp6Probe::S6,
            "IE1" => Fp6Probe::Ie1,
            "IE2" => Fp6Probe::Ie2,
            "NS" => Fp6Probe::Ns,
            "U1" => Fp6Probe::U1,
            "TECN" => Fp6Probe::Tecn,
            "T2" => Fp6Probe::T2,
            "T3" => Fp6Probe::T3,
            "T4" => Fp6Probe::T4,
            "T5" => Fp6Probe::T5,
            "T6" => Fp6Probe::T6,
            "T7" => Fp6Probe::T7,
            _ => return None,
        })
    }
}

/// A response received for one probe: the packet as captured (starting at the IPv6
/// header, the way `PacketParser::split` sees it) and the time the probe was sent.
///
/// The send time matters only for the six SEQ probes, where the span between the first
/// and last SEQ send divides the summed ISN deltas to give the ISR feature.
#[derive(Debug, Clone)]
pub struct Fp6Response {
    /// Received packet bytes, from the IPv6 header onward.
    pub packet: Vec<u8>,
    /// Whole-seconds part of the probe's send time.
    pub sent_sec: i64,
    /// Microseconds part of the probe's send time.
    pub sent_usec: i64,
}

/// The complete set of responses from one host, plus the measured hop distance — the
/// input to [`vectorize`], mirroring the fields of `FingerPrintResultsIPv6` that
/// `vectorize()` reads.
#[derive(Debug, Clone)]
pub struct Fp6Observation {
    responses: HashMap<Fp6Probe, Fp6Response>,
    /// Measured hop distance to the target (`FPR->distance`).
    pub distance: i32,
    /// How that distance was measured (`FPR->distance_calculation_method`).
    pub distance_method: DistMethod,
}

impl Fp6Observation {
    /// A new observation with no responses yet.
    #[must_use]
    pub fn new(distance: i32, distance_method: DistMethod) -> Fp6Observation {
        Fp6Observation {
            responses: HashMap::new(),
            distance,
            distance_method,
        }
    }

    /// Record the response received for `probe` (replacing any earlier one).
    pub fn insert(&mut self, probe: Fp6Probe, response: Fp6Response) {
        self.responses.insert(probe, response);
    }

    /// The response recorded for `probe`, if any.
    #[must_use]
    pub fn get(&self, probe: Fp6Probe) -> Option<&Fp6Response> {
        self.responses.get(&probe)
    }
}

/// The parsed layers of one probe response, plus its send time — the Rust stand-in for
/// the `FPPacket` nmap keeps in its `resps` map.
struct Parsed {
    headers: Vec<Header>,
    sent_sec: i64,
    sent_usec: i64,
}

impl Parsed {
    fn ipv6(&self) -> Option<&Ipv6Header> {
        self.headers.iter().find_map(|h| match h {
            Header::Ipv6(ip) => Some(ip),
            _ => None,
        })
    }

    fn tcp(&self) -> Option<&TcpHeader> {
        self.headers.iter().find_map(|h| match h {
            Header::Tcp(t) => Some(t),
            _ => None,
        })
    }

    fn icmpv6(&self) -> Option<&Icmpv6Header> {
        self.headers.iter().find_map(|h| match h {
            Header::Icmpv6(i) => Some(i),
            _ => None,
        })
    }
}

/// Build the 695-element feature vector for one host's responses — nmap's `vectorize`.
///
/// Feeds [`crate::fpmodel::classify`]. Every element defaults to the `-1` absent
/// sentinel; a probe with no response leaves all of its features at `-1`.
// The index arithmetic here walks a fixed 695-element layout by constant strides that
// sum to exactly N_FEATURE; every index is bounded by construction (proved by the
// debug_assert at the end and by the vectorize differential), so the checked-arithmetic
// lint is waived for readability, as elsewhere in the crate for bounded index walks.
#[allow(clippy::arithmetic_side_effects)]
#[must_use]
pub fn vectorize(obs: &Fp6Observation) -> Vec<f64> {
    // Parse each response once. `PacketParser::split` is called on every stored
    // response in the C; here parsing is total, so a malformed response simply yields
    // no IPv6/TCP/ICMPv6 header and all its features stay at the sentinel.
    let mut parsed: HashMap<Fp6Probe, Parsed> = HashMap::new();
    for (&probe, response) in &obs.responses {
        parsed.insert(
            probe,
            Parsed {
                headers: parse_packet(&response.packet, false),
                sent_sec: response.sent_sec,
                sent_usec: response.sent_usec,
            },
        );
    }

    let mut features = vec![ABSENT; N_FEATURE];
    let mut idx = 0usize;

    // --- IPv6 header features: plen, tc, hlim for each of the 17 probes ------------
    for probe in IPV6_PROBE_ORDER {
        let ipv6 = parsed.get(&probe).and_then(Parsed::ipv6);
        features[idx] = vectorize_plen(ipv6);
        features[idx + 1] = vectorize_tc(ipv6);
        features[idx + 2] = vectorize_hlim(ipv6, obs.distance, obs.distance_method);
        idx += 3;
    }

    // --- TCP: the ISN rate over the SEQ probes ------------------------------------
    features[idx] = vectorize_isr(&parsed);
    idx += 1;

    // --- TCP header features: 49 per probe ----------------------------------------
    for probe in TCP_PROBE_ORDER {
        let Some(tcp) = parsed.get(&probe).and_then(Parsed::tcp) else {
            // No TCP header: the whole 49-feature block stays at the sentinel.
            idx += 49;
            continue;
        };

        features[idx] = f64::from(tcp.window);
        idx += 1;

        // The 12 low flag bits of `getFlags16()` (data-offset nibble masked off):
        // FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, then the reserved/NS bits.
        let flags16 = (u16::from(tcp.reserved & 0x0F) << 8) | u16::from(tcp.flags);
        let mut mask: u16 = 0x001;
        while mask <= 0x800 {
            features[idx] = f64::from(u8::from(flags16 & mask != 0));
            idx += 1;
            mask <<= 1;
        }

        // The option block starts here. Options are written relative to `base`, which
        // lets the C's 17th-option quirk fall out naturally (see the module docs);
        // `idx` is then advanced past the whole fixed-size block.
        let base = idx;
        let (mss, sackok, wscale) = vectorize_tcp_options(&mut features, base, &tcp.options);
        idx += MODEL_NUM_OPTS * 2;

        features[idx] = int_feature(mss);
        features[idx + 1] = int_feature(sackok);
        features[idx + 2] = int_feature(wscale);
        // `(float)window / mss`, computed in f32 exactly as the C does before the
        // result is widened to the f64 feature slot.
        features[idx + 3] = if mss > 0 {
            f64::from(f32::from(tcp.window) / mss as f32)
        } else {
            ABSENT
        };
        idx += 4;
    }

    // --- ICMPv6 header features: type and code for each of the 3 probes ------------
    for probe in ICMPV6_PROBE_ORDER {
        let icmp = parsed.get(&probe).and_then(Parsed::icmpv6);
        features[idx] = vectorize_icmpv6_type(icmp);
        features[idx + 1] = vectorize_icmpv6_code(icmp);
        idx += 2;
    }

    debug_assert_eq!(idx, N_FEATURE, "feature count drifted from the model");
    features
}

/// `-1` for the absent sentinel (`< 0`), else the integer as an `f64`.
fn int_feature(v: i64) -> f64 {
    if v < 0 {
        ABSENT
    } else {
        v as f64
    }
}

/// IPv6 payload length, or `-1` when there is no IPv6 header (`vectorize_plen`).
fn vectorize_plen(ipv6: Option<&Ipv6Header>) -> f64 {
    ipv6.map_or(ABSENT, |ip| f64::from(ip.payload_length))
}

/// IPv6 traffic class, or `-1` (`vectorize_tc`).
fn vectorize_tc(ipv6: Option<&Ipv6Header>) -> f64 {
    ipv6.map_or(ABSENT, |ip| f64::from(ip.traffic_class()))
}

/// IPv6 hop limit, adjusted for distance and rounded to the nearest common initial
/// value (`vectorize_hlim`). Returns `-1` when there is no IPv6 header or the value is
/// too far from any of 32/64/128/255 to attribute.
fn vectorize_hlim(ipv6: Option<&Ipv6Header>, target_distance: i32, method: DistMethod) -> f64 {
    let Some(ipv6) = ipv6 else {
        return ABSENT;
    };
    // Signed throughout, as in the C: the distance adjustment can push the value past
    // 255, and the rounding windows are inclusive on both ends.
    let mut hlim = i32::from(ipv6.hop_limit);

    // Signed, wrapping arithmetic: matches the C's `int` overflow behaviour on an
    // extreme distance and cannot panic. In every real and tested range no wrap occurs.
    let er_lim: i32 = if method != DistMethod::None {
        if matches!(method, DistMethod::Traceroute | DistMethod::Icmp) && target_distance > 0 {
            hlim = hlim.wrapping_add(target_distance.wrapping_sub(1));
        }
        5
    } else {
        20
    };

    for base in [32i32, 64, 128, 255] {
        if base.wrapping_sub(er_lim) <= hlim && hlim <= base.wrapping_add(5) {
            return f64::from(base);
        }
    }
    ABSENT
}

/// The inter-send ISN rate over the SEQ probes (`vectorize_isr`): the summed
/// consecutive ISN deltas divided by the span between the first and last SEQ send.
/// `-1` when fewer than two SEQ probes returned a TCP header.
// Bounded: `seqs`/`times` have at most 6 entries and the timeval fields come from a
// capture, so none of the small additions or the `len - 1` can overflow in practice.
#[allow(clippy::arithmetic_side_effects)]
fn vectorize_isr(parsed: &HashMap<Fp6Probe, Parsed>) -> f64 {
    let mut seqs: Vec<u32> = Vec::with_capacity(SEQ_PROBE_ORDER.len());
    let mut times: Vec<(i64, i64)> = Vec::with_capacity(SEQ_PROBE_ORDER.len());

    for probe in SEQ_PROBE_ORDER {
        let Some(p) = parsed.get(&probe) else {
            continue;
        };
        let Some(tcp) = p.tcp() else {
            continue;
        };
        seqs.push(tcp.seq);
        times.push((p.sent_sec, p.sent_usec));
    }

    if seqs.len() < 2 {
        return ABSENT;
    }

    // Each consecutive ISN delta is a wrapping u32 subtraction (an unsigned span),
    // accumulated as f64 — exactly the C's `sum += seqs[i+1] - seqs[i]`.
    let mut sum = 0.0f64;
    for pair in seqs.windows(2) {
        sum += f64::from(pair[1].wrapping_sub(pair[0]));
    }

    let last = times[times.len() - 1];
    let first = times[0];
    // TIMEVAL_FSEC_SUBTRACT: whole seconds plus microsecond fraction, in f64. A zero
    // span yields ±inf / NaN exactly as the C's floating-point division would.
    let t = (last.0 - first.0) as f64 + (last.1 - first.1) as f64 / 1_000_000.0;
    sum / t
}

/// ICMPv6 type, or `-1` when there is no ICMPv6 header (`vectorize_icmpv6_type`).
fn vectorize_icmpv6_type(icmp: Option<&Icmpv6Header>) -> f64 {
    icmp.map_or(ABSENT, |i| f64::from(i.icmp_type))
}

/// ICMPv6 code, or `-1` (`vectorize_icmpv6_code`).
fn vectorize_icmpv6_code(icmp: Option<&Icmpv6Header>) -> f64 {
    icmp.map_or(ABSENT, |i| f64::from(i.code))
}

/// Walk a TCP segment's options into the 32-slot option block that begins at `base`
/// (16 opcode slots, then 16 length slots), returning `(mss, sackok, wscale)` with `-1`
/// for any that did not appear. Ports `TCPOptions::foreachOpt` driving
/// `tcpopt_vectorize`.
///
/// Two behaviours are inherited from the C on purpose:
///  * an End-of-List option (0) is treated as a single byte and the walk **continues**
///    past it, unlike a strict RFC reader — nmap's `foreachOpt` does the same;
///  * the opcode/length are written *before* the 16-option cap is checked, so a 17th
///    option overwrites the first option's length slot and then the walk stops (see the
///    module docs). Every index reached stays inside the feature vector.
// Bounded: `pos` only ever advances by an option length that fits in `options`
// (checked before use), and `base + optnum (+ 16)` reaches at most base + 32, which the
// caller has proven is inside the feature vector.
#[allow(clippy::arithmetic_side_effects)]
fn vectorize_tcp_options(features: &mut [f64], base: usize, options: &[u8]) -> (i64, i64, i64) {
    let mut mss: i64 = -1;
    let mut sackok: i64 = -1;
    let mut wscale: i64 = -1;

    let mut optnum = 0usize;
    let mut pos = 0usize;
    while pos < options.len() {
        let remaining = options.len() - pos;
        let op = options[pos];

        // End-of-list (0) and no-op (1) are single bytes with no length field; every
        // other option is TLV and needs a valid, in-bounds length or the walk stops
        // (foreachOpt's `return false`).
        let oplen = if op == 0 || op == 1 {
            1usize
        } else {
            if remaining < 2 {
                break;
            }
            let len = usize::from(options[pos + 1]);
            if len < 2 || len > remaining {
                break;
            }
            len
        };

        // tcpopt_vectorize writes both slots first. optnum tops out at 16, so
        // base + optnum + MODEL_NUM_OPTS reaches at most base + 32, which the caller
        // has proven is inside the vector.
        features[base + optnum] = f64::from(op);
        features[base + optnum + MODEL_NUM_OPTS] = as_usize_to_f64(oplen);

        // MSS/SACK-permitted/window-scale record the first well-formed instance. `data`
        // in the C points at the option start, so its `data[2]`/`data[3]` are the first
        // two payload bytes here.
        if op == 2 && oplen == 4 && mss == -1 {
            mss = (i64::from(options[pos + 2]) << 8) + i64::from(options[pos + 3]);
        } else if op == 4 && oplen == 2 && sackok == -1 {
            sackok = 1;
        } else if op == 3 && oplen == 3 && wscale == -1 {
            wscale = i64::from(options[pos + 2]);
        }

        // Post-increment compare: options 0..=15 continue, the 16-indexed option is
        // the last one processed before the walk stops.
        let keep_going = optnum < MODEL_NUM_OPTS;
        optnum += 1;
        if !keep_going {
            break;
        }

        pos += oplen;
    }

    (mss, sackok, wscale)
}

/// A small option length (1..=40) as an `f64`; the value always fits exactly.
fn as_usize_to_f64(v: usize) -> f64 {
    // Option lengths are bounded by the 40-byte option area, well within f64's exact
    // integer range; the conversion cannot lose precision.
    v as f64
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// A 40-byte IPv6 header with the given next-header, hop limit, traffic class and
    /// payload length.
    fn ipv6(next: u8, hlim: u8, tc: u8, plen: u16) -> Vec<u8> {
        let mut b = Vec::with_capacity(40);
        b.push(0x60 | (tc >> 4));
        b.push((tc & 0x0F) << 4);
        b.extend_from_slice(&[0, 0]); // rest of flow label
        b.extend_from_slice(&plen.to_be_bytes());
        b.push(next);
        b.push(hlim);
        b.extend_from_slice(&[0u8; 32]); // src + dst
        b
    }

    /// A TCP segment with the given window, flags byte, reserved nibble, seq and options.
    fn tcp(window: u16, flags: u8, reserved: u8, seq: u32, options: &[u8]) -> Vec<u8> {
        let mut opts = options.to_vec();
        while !opts.len().is_multiple_of(4) {
            opts.push(1); // NOP pad
        }
        let offset = u8::try_from(5 + opts.len() / 4).unwrap();
        let mut b = Vec::new();
        b.extend_from_slice(&[0, 80]); // sport
        b.extend_from_slice(&[1, 187]); // dport
        b.extend_from_slice(&seq.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]); // ack
        b.push((offset << 4) | (reserved & 0x0F));
        b.push(flags);
        b.extend_from_slice(&window.to_be_bytes());
        b.extend_from_slice(&[0, 0]); // checksum
        b.extend_from_slice(&[0, 0]); // urgent
        b.extend_from_slice(&opts);
        b
    }

    fn resp(packet: Vec<u8>) -> Fp6Response {
        Fp6Response {
            packet,
            sent_sec: 0,
            sent_usec: 0,
        }
    }

    /// Index of the first feature of TCP probe `n` (0 = S1) in the 695-vector:
    /// 51 IPv6 features + 1 ISR + n*49.
    fn tcp_base(n: usize) -> usize {
        51 + 1 + n * 49
    }

    #[test]
    fn vector_is_always_the_model_length() {
        let obs = Fp6Observation::new(-1, DistMethod::None);
        assert_eq!(vectorize(&obs).len(), N_FEATURE);
    }

    #[test]
    fn an_empty_observation_is_all_sentinel() {
        let obs = Fp6Observation::new(3, DistMethod::Icmp);
        assert!(vectorize(&obs).iter().all(|&x| x == -1.0));
    }

    #[test]
    fn a_zero_length_response_degrades_to_sentinel_not_a_panic() {
        // nmap asserts every stored response parses to non-NULL and would abort() on a
        // zero-length one. The port has no such buffer to parse, finds no header, and
        // leaves the features at the sentinel — the `fp6-empty-response-no-abort`
        // divergence. This must never panic.
        let mut obs = Fp6Observation::new(-1, DistMethod::None);
        obs.insert(Fp6Probe::S1, resp(Vec::new()));
        assert!(vectorize(&obs).iter().all(|&x| x == -1.0));
    }

    #[test]
    fn s1_ipv6_fields_land_in_the_first_three_slots() {
        let mut pkt = ipv6(6, 64, 0x24, 20);
        pkt.extend_from_slice(&tcp(0, 0, 0, 0, &[]));
        let mut obs = Fp6Observation::new(-1, DistMethod::None);
        obs.insert(Fp6Probe::S1, resp(pkt));
        let v = vectorize(&obs);
        assert_eq!(v[0], 20.0, "plen");
        assert_eq!(v[1], f64::from(0x24u8), "tc");
        assert_eq!(v[2], 64.0, "hlim rounds to 64");
    }

    #[test]
    fn hop_limit_rounds_to_the_nearest_common_ttl() {
        // With no distance method, er_lim is 20, so 44..69 all round to 64.
        for (hlim, want) in [
            (30u8, 32.0),
            (44u8, 64.0),
            (69u8, 64.0),
            (250u8, 255.0),
            (10u8, -1.0),
        ] {
            let mut obs = Fp6Observation::new(-1, DistMethod::None);
            obs.insert(Fp6Probe::S1, resp(ipv6(59, hlim, 0, 0)));
            assert_eq!(vectorize(&obs)[2], want, "hlim {hlim}");
        }
    }

    #[test]
    fn distance_lifts_the_hop_limit_only_for_icmp_and_traceroute() {
        // A received hlim of 58 with a distance of 6 measured by ICMP: 58 + 6 - 1 = 63,
        // which rounds to 64. Under DIST_METHOD_DIRECT the adjustment is skipped, and
        // 58 with er_lim 5 (a method is set) still rounds to 64 here — so use a value
        // that only reaches a bucket *with* the lift to show the difference.
        let mut icmp = Fp6Observation::new(6, DistMethod::Icmp);
        icmp.insert(Fp6Probe::S1, resp(ipv6(59, 120, 0, 0))); // 120 + 5 = 125 -> 128
        assert_eq!(vectorize(&icmp)[2], 128.0);

        // 120 with a method set (er_lim 5) but no lift: 123..133 window is 128, so 120
        // is below it -> -1 without the +distance.
        let mut direct = Fp6Observation::new(6, DistMethod::Direct);
        direct.insert(Fp6Probe::S1, resp(ipv6(59, 120, 0, 0)));
        assert_eq!(vectorize(&direct)[2], -1.0);
    }

    #[test]
    fn tcp_window_flags_and_options_populate_the_block() {
        // MSS 1460, SACK permitted, window scale 7, timestamp.
        let opts = [
            2, 4, 0x05, 0xB4, // MSS 1460
            4, 2, // SACK OK
            3, 3, 7, // WScale 7
        ];
        let mut pkt = ipv6(6, 64, 0, 0);
        // SYN|ACK = 0x12, reserved nibble 0.
        pkt.extend_from_slice(&tcp(29200, 0x12, 0, 0, &opts));
        let mut obs = Fp6Observation::new(-1, DistMethod::None);
        obs.insert(Fp6Probe::S1, resp(pkt));
        let v = vectorize(&obs);
        let b = tcp_base(0);
        assert_eq!(v[b], 29200.0, "window");
        // flags16 low bits: SYN(0x002) and ACK(0x010) set -> feature[b+2] and [b+5].
        assert_eq!(v[b + 1], 0.0, "FIN");
        assert_eq!(v[b + 2], 1.0, "SYN");
        assert_eq!(v[b + 5], 1.0, "ACK");
        // Option block starts at b+13: opcodes then lengths.
        let ob = b + 13;
        assert_eq!(v[ob], 2.0, "opt0 kind = MSS");
        assert_eq!(v[ob + MODEL_NUM_OPTS], 4.0, "opt0 len = 4");
        // mss/sackok/wscale/ratio at the end of the block.
        assert_eq!(v[b + 45], 1460.0, "mss");
        assert_eq!(v[b + 46], 1.0, "sackok");
        assert_eq!(v[b + 47], 7.0, "wscale");
        assert_eq!(
            v[b + 48],
            f64::from(29200.0f32 / 1460.0f32),
            "window/mss in f32"
        );
    }

    #[test]
    fn end_of_list_does_not_stop_the_option_walk() {
        // An EOL (0) between two NOPs: nmap's foreachOpt records the EOL and keeps
        // walking, so all three options appear.
        let opts = [1u8, 0, 1];
        let mut pkt = ipv6(6, 64, 0, 0);
        pkt.extend_from_slice(&tcp(1, 0, 0, 0, &opts));
        let mut obs = Fp6Observation::new(-1, DistMethod::None);
        obs.insert(Fp6Probe::S1, resp(pkt));
        let v = vectorize(&obs);
        let ob = tcp_base(0) + 13;
        assert_eq!(v[ob], 1.0, "opt0 = NOP");
        assert_eq!(v[ob + 1], 0.0, "opt1 = EOL (walk continued)");
        // opt2 is a NOP, but note the padding: tcp() pads to a 4-byte boundary with
        // NOPs, so several trailing NOPs follow — the point is the EOL didn't stop us.
        assert_eq!(v[ob + 2], 1.0, "opt2 = NOP after EOL");
    }

    #[test]
    fn the_seventeenth_option_overwrites_the_first_options_length_slot() {
        // 16 NOPs then a distinctive TLV option: the 17th option's opcode is written
        // into the first option's length slot (base+16), reproducing the C's
        // write-before-cap quirk, and the walk then stops.
        let mut opts = vec![1u8; 16]; // options 0..15 are NOPs
        opts.extend_from_slice(&[0x77, 2]); // option 16: opcode 0x77, len 2
        let mut pkt = ipv6(6, 64, 0, 0);
        pkt.extend_from_slice(&tcp(1, 0, 0, 0, &opts));
        let mut obs = Fp6Observation::new(-1, DistMethod::None);
        obs.insert(Fp6Probe::S1, resp(pkt));
        let v = vectorize(&obs);
        let ob = tcp_base(0) + 13;
        // Option 0's length slot (ob+16) now holds option 16's opcode, 0x77.
        assert_eq!(
            v[ob + 16],
            f64::from(0x77u8),
            "17th opcode overwrote opt0 length"
        );
        // Option 0's opcode slot still holds the NOP.
        assert_eq!(v[ob], 1.0);
    }

    #[test]
    fn isr_is_the_isn_rate_over_the_seq_probes() {
        // Two SEQ probes 0.5s apart with ISNs 1000 apart -> rate 2000/s.
        let mut obs = Fp6Observation::new(-1, DistMethod::None);
        let mut s1 = ipv6(6, 64, 0, 0);
        s1.extend_from_slice(&tcp(0, 0, 0, 1000, &[]));
        let mut s2 = ipv6(6, 64, 0, 0);
        s2.extend_from_slice(&tcp(0, 0, 0, 2000, &[]));
        obs.insert(
            Fp6Probe::S1,
            Fp6Response {
                packet: s1,
                sent_sec: 10,
                sent_usec: 0,
            },
        );
        obs.insert(
            Fp6Probe::S2,
            Fp6Response {
                packet: s2,
                sent_sec: 10,
                sent_usec: 500_000,
            },
        );
        assert_eq!(vectorize(&obs)[51], 2000.0);
    }

    #[test]
    fn isr_needs_two_seq_responses() {
        let mut obs = Fp6Observation::new(-1, DistMethod::None);
        let mut s1 = ipv6(6, 64, 0, 0);
        s1.extend_from_slice(&tcp(0, 0, 0, 1000, &[]));
        obs.insert(Fp6Probe::S1, resp(s1));
        assert_eq!(vectorize(&obs)[51], -1.0, "one SEQ probe = no rate");
    }

    #[test]
    fn isr_zero_span_is_infinite_and_zero_over_zero_is_nan() {
        // Same send time, different ISNs -> +inf (the C's floating division).
        let mut inf_obs = Fp6Observation::new(-1, DistMethod::None);
        let mut a = ipv6(6, 64, 0, 0);
        a.extend_from_slice(&tcp(0, 0, 0, 1000, &[]));
        let mut b = ipv6(6, 64, 0, 0);
        b.extend_from_slice(&tcp(0, 0, 0, 2000, &[]));
        inf_obs.insert(
            Fp6Probe::S1,
            Fp6Response {
                packet: a,
                sent_sec: 5,
                sent_usec: 5,
            },
        );
        inf_obs.insert(
            Fp6Probe::S2,
            Fp6Response {
                packet: b,
                sent_sec: 5,
                sent_usec: 5,
            },
        );
        assert!(vectorize(&inf_obs)[51].is_infinite());

        // Same send time AND same ISN -> 0/0 -> NaN, matching the C.
        let mut nan_obs = Fp6Observation::new(-1, DistMethod::None);
        let mut c = ipv6(6, 64, 0, 0);
        c.extend_from_slice(&tcp(0, 0, 0, 7, &[]));
        let mut d = ipv6(6, 64, 0, 0);
        d.extend_from_slice(&tcp(0, 0, 0, 7, &[]));
        nan_obs.insert(
            Fp6Probe::S1,
            Fp6Response {
                packet: c,
                sent_sec: 5,
                sent_usec: 5,
            },
        );
        nan_obs.insert(
            Fp6Probe::S2,
            Fp6Response {
                packet: d,
                sent_sec: 5,
                sent_usec: 5,
            },
        );
        assert!(vectorize(&nan_obs)[51].is_nan());
    }

    #[test]
    fn icmpv6_type_and_code_are_the_last_six_features() {
        let mut body = vec![129u8, 3, 0, 0]; // echo reply, code 3
        body.extend_from_slice(&[0u8; 4]);
        let mut pkt = ipv6(58, 64, 0, u16::try_from(body.len()).unwrap());
        pkt.extend_from_slice(&body);
        let mut obs = Fp6Observation::new(-1, DistMethod::None);
        obs.insert(Fp6Probe::Ie1, resp(pkt));
        let v = vectorize(&obs);
        // IE1 is the first of the three ICMPv6 probes -> features 689, 690.
        assert_eq!(v[689], 129.0, "IE1 type");
        assert_eq!(v[690], 3.0, "IE1 code");
    }

    #[test]
    fn probe_ids_round_trip() {
        for p in IPV6_PROBE_ORDER {
            assert_eq!(Fp6Probe::from_id(p.id()), Some(p));
        }
        assert_eq!(Fp6Probe::from_id("nope"), None);
    }
}
