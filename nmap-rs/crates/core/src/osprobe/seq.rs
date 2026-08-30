//! The `SEQ` fingerprint test — the port of `makeTSeqFP` from `osscan2.cc`.
//!
//! Six SYNs are sent to an open port at fixed intervals, and the replies are mined for
//! three independent signals about how the target's stack generates numbers:
//!
//! * **ISN generation** (`SP`, `GCD`, `ISR`) — how fast the initial sequence number
//!   climbs and how predictable that climb is. A stack whose ISNs advance by a constant,
//!   or by a small multiple, is both identifiable *and* vulnerable to sequence
//!   prediction, which is why nmap reports it.
//! * **IP-ID generation** (`TI`, `CI`, `II`, `SS`) — classified separately for replies
//!   from an open TCP port, a closed TCP port, and ICMP, because many stacks use
//!   different counters for each. `SS` records whether the TCP and ICMP counters are
//!   *shared*.
//! * **TCP timestamp generation** (`TS`) — the clock frequency behind the timestamp
//!   option, bucketed into the frequencies real systems actually use.
//!
//! Everything here is a total function of the samples: the caller supplies the replies
//! and the send times, so there is no clock and no I/O.

use crate::ipid::{get_ipid_sequence_16, IpidSequence};
use crate::osdb::model::{FingerTest, TestId};

/// Number of `SEQ` samples, matching the C's `NUM_SEQ_SAMPLES`.
pub const NUM_SEQ_SAMPLES: usize = 6;

/// Minimum replies before the ISN analysis is attempted, from the C's
/// `hss->si.responses >= 4`. Fewer samples cannot support a standard deviation.
const MIN_ISN_RESPONSES: usize = 4;

/// The C skips the ISN analysis entirely when `--scan-delay` exceeds this, because the
/// probes are then too far apart in time for the rate to mean anything.
const MAX_SCAN_DELAY_MS: u64 = 1000;

/// One `SEQ` probe's reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqReply {
    /// The initial sequence number from the SYN/ACK.
    pub isn: u32,
    /// The reply's IP identification field.
    pub ip_id: u16,
    /// The TCP timestamp value echoed back, or `0` when the option was absent or zero.
    pub timestamp: u32,
    /// When the probe that produced this reply was *sent*, in microseconds from any
    /// fixed origin. Only differences are used.
    pub sent_usec: u64,
}

/// What reply processing already concluded about the timestamp option, before the
/// frequency analysis runs. Ports the C's `si.ts_seqclass` as set in `processTSeqResp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TsClass {
    /// Nothing concluded yet — run the frequency analysis.
    #[default]
    Unknown,
    /// At least one reply carried a timestamp of zero.
    Zero,
    /// At least one reply carried no timestamp option at all.
    Unsupported,
}

/// Everything the `SEQ` test needs.
///
/// The three IP-ID arrays are separate because stacks commonly use different counters
/// for open-port TCP, closed-port TCP and ICMP; comparing them is the whole point of the
/// `CI`, `II` and `SS` attributes.
#[derive(Debug, Clone, Default)]
pub struct SeqInputs {
    /// Replies to the six `SEQ` probes, in probe order. `None` where no reply arrived.
    pub replies: Vec<Option<SeqReply>>,
    /// IP IDs from replies on the **open** TCP port.
    pub tcp_ipids: Vec<u16>,
    /// IP IDs from replies on a **closed** TCP port.
    pub closed_tcp_ipids: Vec<u16>,
    /// IP IDs from ICMP replies.
    pub icmp_ipids: Vec<u16>,
    /// What reply processing concluded about timestamps.
    pub ts_class: TsClass,
    /// Whether the target is the local host, which loosens the IP-ID classifier.
    pub is_localhost: bool,
    /// `--scan-delay` in milliseconds.
    pub scan_delay_ms: u64,
}

/// The `SEQ` test's attribute values. `None` means the C would not have set the
/// attribute at all, which the scorer treats as "not specified" rather than as a
/// mismatch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeqTest {
    /// ISN predictability index, hex-formatted for the fingerprint attribute.
    pub sp: Option<String>,
    /// The same index as a number. The C keeps it in `si.index` and hex-formats it for
    /// the `SP` attribute; `-O` reports the number directly as the sequence-prediction
    /// difficulty, so both forms are carried rather than parsed back out of the hex.
    pub sp_index: Option<u32>,
    /// Greatest common divisor of the ISN differences.
    pub gcd: Option<String>,
    /// ISN counter rate.
    pub isr: Option<String>,
    /// IP-ID generation on the open TCP port.
    pub ti: Option<String>,
    /// IP-ID generation on a closed TCP port.
    pub ci: Option<String>,
    /// IP-ID generation for ICMP.
    pub ii: Option<String>,
    /// Whether the TCP and ICMP IP-ID counters are shared.
    pub ss: Option<String>,
    /// TCP timestamp frequency class.
    pub ts: Option<String>,
    /// How many of the six probes were answered.
    pub responses: usize,
}

impl SeqTest {
    /// Render as a [`FingerTest`] the scorer can match against the database.
    #[must_use]
    pub fn to_finger_test(&self) -> FingerTest {
        let mut t = FingerTest::new(TestId::Seq);
        let pairs = [
            ("SP", &self.sp),
            ("GCD", &self.gcd),
            ("ISR", &self.isr),
            ("TI", &self.ti),
            ("CI", &self.ci),
            ("II", &self.ii),
            ("SS", &self.ss),
            ("TS", &self.ts),
        ];
        for (name, value) in pairs {
            if let (Some(i), Some(v)) = (TestId::Seq.attr_index(name), value.as_ref()) {
                if let Some(slot) = t.values.get_mut(i) {
                    *slot = Some(v.clone());
                }
            }
        }
        t
    }
}

/// The C's `MOD_DIFF`: the smaller of the two wrapping differences, so a counter that
/// wrapped between samples still reports a small step.
fn mod_diff(a: u32, b: u32) -> u32 {
    a.wrapping_sub(b).min(b.wrapping_sub(a))
}

/// Greatest common divisor across a slice, porting `gcd_n_uint`.
///
/// Returns `1` for an empty slice and `0` when every value is zero — the latter is how
/// the caller detects a constant ISN, so it must not be "corrected" to 1.
fn gcd_n_uint(values: &[u32]) -> u32 {
    let Some((&first, rest)) = values.split_first() else {
        return 1;
    };
    let mut a = first;
    for &next in rest {
        let (mut x, mut y) = if a < next { (next, a) } else { (a, next) };
        while y != 0 {
            // `y` is non-zero by the loop condition, so the remainder is defined.
            let r = x.checked_rem(y).unwrap_or(0);
            x = y;
            y = r;
        }
        a = x;
    }
    a
}

/// `round(log2(v) * 8)`, saturating at zero.
///
/// The C writes `(unsigned int)(log(v) / log(2.0) * 8 + 0.5)`. When `v < 1` the logarithm
/// is negative and converting a negative double to an unsigned integer type is
/// **undefined behaviour**; when `v` is zero it is `-inf`, which is worse. Saturating at
/// zero keeps the value in range without changing any result the C defines — a rate
/// below 1 would have to come from probes more than a second apart with a one-step ISN
/// advance.
fn log2_times_8(v: f64) -> u32 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    let scaled = v.log2() * 8.0 + 0.5;
    if scaled <= 0.0 {
        return 0;
    }
    // Truncation toward zero, as the C's cast does. `u32::MAX` is unreachable for any
    // rate a real counter can produce, but bounds the conversion regardless.
    if scaled >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        // Bounded above by the branch and below by the `<= 0.0` guard, so truncating
        // toward zero — what the C's cast does — is in range and well defined.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            scaled as u32
        }
    }
}

/// Uppercase hex without leading zeros, matching the C's `cp_hex` (`"%X"`).
fn hex(v: u32) -> String {
    format!("{v:X}")
}

/// Run the `SEQ` analysis.
#[must_use]
pub fn analyze_seq(inputs: &SeqInputs) -> SeqTest {
    let mut out = SeqTest::default();

    // Compact the replies, dropping unanswered slots. The C does this in place over
    // parallel arrays; the shape here makes the "no reply" case explicit.
    let samples: Vec<SeqReply> = inputs.replies.iter().flatten().copied().collect();
    out.responses = samples.len();

    // Consecutive differences, and the elapsed time between the probes that produced
    // them. A zero elapsed time is bumped to one microsecond because it is a divisor.
    let mut seq_diffs: Vec<u32> = Vec::new();
    let mut ts_diffs: Vec<u32> = Vec::new();
    let mut usec_diffs: Vec<u64> = Vec::new();
    let mut seq_rates: Vec<f64> = Vec::new();
    for pair in samples.windows(2) {
        let (prev, cur) = (pair[0], pair[1]);
        let usec = cur.sent_usec.saturating_sub(prev.sent_usec).max(1);
        seq_diffs.push(mod_diff(cur.isn, prev.isn));
        ts_diffs.push(mod_diff(cur.timestamp, prev.timestamp));
        usec_diffs.push(usec);
        // ISN advance per second.
        let rate = f64::from(mod_diff(cur.isn, prev.isn)) * 1_000_000.0 / usec as f64;
        seq_rates.push(rate);
    }

    isn_analysis(inputs, &seq_diffs, &seq_rates, &mut out);
    ipid_analysis(inputs, &mut out);
    timestamp_analysis(inputs, &samples, &ts_diffs, &usec_diffs, &mut out);

    out
}

/// `SP`, `GCD` and `ISR` — the ISN-predictability half.
fn isn_analysis(inputs: &SeqInputs, seq_diffs: &[u32], seq_rates: &[f64], out: &mut SeqTest) {
    // Too few replies, or probes spread too far apart in time, and the C reports nothing
    // rather than a number it does not trust.
    if out.responses < MIN_ISN_RESPONSES || inputs.scan_delay_ms > MAX_SCAN_DELAY_MS {
        return;
    }
    let n = seq_rates.len();
    if n == 0 {
        return;
    }

    let seq_avg_rate = seq_rates.iter().sum::<f64>() / n as f64;
    let seq_gcd = gcd_n_uint(seq_diffs);

    let (index, rate) = if seq_gcd == 0 {
        // Every difference was zero: a constant ISN. Maximally predictable.
        (0u32, 0u32)
    } else {
        // Normally the rate standard deviation is *not* divided by the GCD, because
        // doing so would produce an artificially low value roughly one time in 32 —
        // whenever the sampled ISNs all happen to be even. But a stack that genuinely
        // uses a large step (64000, say) would otherwise look wildly variable. The C's
        // compromise is to divide only when the GCD is large enough to be deliberate.
        let div_gcd = if seq_gcd > 9 { f64::from(seq_gcd) } else { 1.0 };
        let mut variance = 0.0f64;
        for r in seq_rates {
            let d = r / div_gcd - seq_avg_rate / div_gcd;
            variance += d * d;
        }
        // Divided by (samples - 1), the sample rather than population estimator: these
        // six probes are a subset of the counter's whole behaviour.
        let denom = out.responses.saturating_sub(2);
        if denom > 0 {
            variance /= denom as f64;
        }
        let stddev = variance.sqrt();
        // A standard deviation at or below 1 is reported as index 0 rather than as a
        // negative logarithm.
        let index = if stddev <= 1.0 {
            0
        } else {
            log2_times_8(stddev)
        };
        (index, log2_times_8(seq_avg_rate))
    };

    out.sp = Some(hex(index));
    out.sp_index = Some(index);
    out.gcd = Some(hex(seq_gcd));
    out.isr = Some(hex(rate));
}

/// `TI`, `CI`, `II` and `SS` — the IP-ID half.
fn ipid_analysis(inputs: &SeqInputs, out: &mut SeqTest) {
    // The classifier needs more evidence from the open-port samples than from the
    // others, because those drive the headline "IP ID sequence" report.
    let classify = |ipids: &[u16], min: usize| -> IpidSequence {
        if ipids.len() >= min {
            let widened: Vec<u32> = ipids.iter().map(|&v| u32::from(v)).collect();
            get_ipid_sequence_16(&widened, inputs.is_localhost)
        } else {
            IpidSequence::Unknown
        }
    };

    let tcp_class = classify(&inputs.tcp_ipids, 3);
    let closed_class = classify(&inputs.closed_tcp_ipids, 2);
    let icmp_class = classify(&inputs.icmp_ipids, 2);

    out.ti = ipid_aval(tcp_class, &inputs.tcp_ipids);
    out.ci = ipid_aval(closed_class, &inputs.closed_tcp_ipids);
    out.ii = ipid_aval(icmp_class, &inputs.icmp_ipids);

    // `SS` only means anything when both counters are climbing; otherwise "shared" is
    // not a question that can be asked.
    let incremental = |c: IpidSequence| {
        matches!(
            c,
            IpidSequence::Incr | IpidSequence::BrokenIncr | IpidSequence::Rpi
        )
    };
    if !incremental(tcp_class) || !incremental(icmp_class) {
        return;
    }
    let (Some(&tcp_first), Some(&tcp_last)) = (inputs.tcp_ipids.first(), inputs.tcp_ipids.last())
    else {
        return;
    };
    let Some(&icmp_first) = inputs.icmp_ipids.first() else {
        return;
    };
    let steps = inputs.tcp_ipids.len().saturating_sub(1);
    if steps == 0 {
        return;
    }
    // Average step of the TCP counter. The C computes this in `u32` and would divide by
    // zero if only one TCP sample survived — unreachable there because the classifier
    // needs three, but guarded here rather than relying on that coupling.
    let Ok(steps) = u32::try_from(steps) else {
        return;
    };
    let avg = u32::from(tcp_last)
        .wrapping_sub(u32::from(tcp_first))
        .checked_div(steps)
        .unwrap_or(0);
    // If the ICMP counter's first value falls close above the TCP counter's last, the
    // two are plausibly the same counter.
    let threshold = u32::from(tcp_last).wrapping_add(avg.wrapping_mul(3));
    out.ss = Some(if u32::from(icmp_first) < threshold {
        "S".to_owned()
    } else {
        "O".to_owned()
    });
}

/// The `TI`/`CI`/`II` attribute value for a classification, porting
/// `make_aval_ipid_seq`. `None` omits the attribute entirely.
fn ipid_aval(class: IpidSequence, ipids: &[u16]) -> Option<String> {
    match class {
        // A constant counter is reported as its actual value, which is far more
        // identifying than the mere fact of being constant.
        IpidSequence::Constant => Some(hex(u32::from(ipids.first().copied().unwrap_or(0)))),
        IpidSequence::Incr | IpidSequence::IncrBy2 => Some("I".to_owned()),
        IpidSequence::BrokenIncr => Some("BI".to_owned()),
        IpidSequence::Rpi => Some("RI".to_owned()),
        IpidSequence::Rd => Some("RD".to_owned()),
        IpidSequence::Zero => Some("Z".to_owned()),
        IpidSequence::Unknown => None,
    }
}

/// `TS` — the timestamp-frequency half.
fn timestamp_analysis(
    inputs: &SeqInputs,
    samples: &[SeqReply],
    ts_diffs: &[u32],
    usec_diffs: &[u64],
    out: &mut SeqTest,
) {
    match inputs.ts_class {
        TsClass::Zero => {
            out.ts = Some("0".to_owned());
            return;
        }
        TsClass::Unsupported => {
            out.ts = Some("U".to_owned());
            return;
        }
        TsClass::Unknown => {}
    }
    if samples.len() < 2 || ts_diffs.is_empty() {
        return;
    }

    // Average timestamp increments per second.
    let n = ts_diffs.len();
    let mut avg_hz = 0.0f64;
    for (diff, usec) in ts_diffs.iter().zip(usec_diffs.iter()) {
        let seconds = *usec as f64 / 1_000_000.0;
        if seconds > 0.0 {
            avg_hz += f64::from(*diff) / seconds / n as f64;
        }
    }

    if avg_hz <= 0.0 {
        // No detectable increment and no earlier verdict: the C leaves the class
        // `TS_SEQ_UNKNOWN`, whose `switch` has no arm, so no attribute is set.
        return;
    }

    // The bucket boundaries are deliberately not powers of two. The C "cheats a little
    // to make the classes correspond more closely to common real-life frequencies
    // (particularly 100) which aren't powers of two", and the sampling window is short
    // enough that slow clocks need a wide bucket to be caught at all.
    let value = if avg_hz <= 5.66 {
        // Would mathematically be 1.4–2.82; widened to 0–5.66 so a 2 Hz clock is caught
        // despite the short sampling window.
        1
    } else if avg_hz > 70.0 && avg_hz <= 150.0 {
        // Mathematically 90.51–181, moved to align with the very common 100 Hz.
        7
    } else if avg_hz > 150.0 && avg_hz <= 350.0 {
        // Mathematically 181–362, moved to align with 200 Hz.
        8
    } else {
        // Everything else: base-2 logarithm rounded to the nearest integer.
        let scaled = avg_hz.log2() + 0.5;
        if scaled <= 0.0 {
            0
        } else {
            log2_round(avg_hz)
        }
    };
    out.ts = Some(hex(value));
}

/// How long the target has been up, inferred from its TCP timestamp clock.
///
/// Ports the `si.lastboot` derivation at the end of `HostOsScan::makeTSeqFP`
/// (`osscan2.cc`). The idea: if the timestamp counter ticks at a known frequency, the
/// *first* value observed divided by that frequency is how long the counter has been
/// running — which is how long the host has been up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uptime {
    /// Seconds of uptime implied by the first reply's timestamp. **Zero when the
    /// claim was rejected as implausible** — the C clamps anything over two years to
    /// 0 and still records a boot time, so the host reads as "just booted" rather
    /// than as unknown. Reproduced: see `DIVERGENCES.md`.
    pub seconds: u64,
    /// Epoch second at which the host appears to have booted: the first `SEQ` probe's
    /// send time minus `seconds`.
    pub lastboot: i64,
}

/// Two years. The C rejects any longer claim as a lie.
const MAX_PLAUSIBLE_UPTIME_SECS: u64 = 63_072_000;

/// Infer the target's uptime from the `SEQ` replies' timestamps.
///
/// `first_probe_epoch` is the wall-clock second at which the first `SEQ` probe was
/// *sent* (the C's `seq_send_times[0].tv_sec`); it is a parameter rather than a clock
/// read so this stays a pure function.
///
/// Returns `None` exactly where the C leaves `si.lastboot` at 0 and so prints no
/// uptime at all: fewer than two responses, or reply processing already concluded the
/// timestamps were zero or unsupported.
#[must_use]
pub fn estimate_uptime(inputs: &SeqInputs, first_probe_epoch: i64) -> Option<Uptime> {
    // `if (hss->si.ts_seqclass == TS_SEQ_UNKNOWN && hss->si.responses >= 2)`.
    if inputs.ts_class != TsClass::Unknown {
        return None;
    }
    let samples: Vec<SeqReply> = inputs.replies.iter().flatten().copied().collect();
    if samples.len() < 2 {
        return None;
    }

    // Average timestamp increments per second, over consecutive replies — the same
    // quantity the `TS` attribute uses, but graded by a *different* ladder below.
    let n = samples.len().saturating_sub(1);
    let mut avg_hz = 0.0f64;
    for pair in samples.windows(2) {
        let (prev, cur) = (pair[0], pair[1]);
        let usec = cur.sent_usec.saturating_sub(prev.sent_usec).max(1);
        let seconds = usec as f64 / 1_000_000.0;
        if seconds > 0.0 && n > 0 {
            avg_hz += f64::from(mod_diff(cur.timestamp, prev.timestamp)) / seconds / n as f64;
        }
    }

    let first_ts = u64::from(samples[0].timestamp);
    // The C's uptime ladder. Note it is NOT the `TS` attribute ladder: the bounds are
    // strict, and the 724..1448 bucket has no counterpart there.
    let mut seconds = if avg_hz > 0.0 && avg_hz < 5.66 {
        first_ts / 2
    } else if avg_hz > 70.0 && avg_hz < 150.0 {
        first_ts / 100
    } else if avg_hz > 724.0 && avg_hz < 1448.0 {
        first_ts / 1000
    } else if avg_hz > 0.0 {
        // `(unsigned int)(0.5 + avg_ts_hz)` — truncation, so round-half-up. Reaching
        // here requires `avg_hz >= 5.66` (anything smaller and positive took the first
        // branch), so the divisor is at least 6 and the C cannot divide by zero. The
        // guard below costs nothing and makes that argument unnecessary to trust.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the C's `(unsigned int)(0.5 + avg_ts_hz)` truncates on purpose —                       that truncation IS the round-half-up, so reproducing it is the                       point rather than an accident to be guarded against"
        )]
        let divisor = (0.5 + avg_hz) as u64;
        // Unreachable in practice: getting here needs `avg_hz >= 5.66`, so the divisor
        // is at least 6. Checked anyway so the argument need not be trusted.
        first_ts.checked_div(divisor)?
    } else {
        // No detectable increment: the C leaves the class unknown, so no uptime and —
        // because `lastboot` is only assigned inside this block — no boot time either.
        0
    };

    if seconds > MAX_PLAUSIBLE_UPTIME_SECS {
        // "Up 2 years? Perhaps, but they're probably lying."
        seconds = 0;
    }

    Some(Uptime {
        seconds,
        // `hss->si.lastboot = hss->seq_send_times[0].tv_sec - uptime;`
        lastboot: first_probe_epoch.saturating_sub(i64::try_from(seconds).unwrap_or(i64::MAX)),
    })
}

/// `round(log2(v))`, saturating at zero — the same undefined-conversion guard as
/// [`log2_times_8`], for the `TS` fallback bucket.
fn log2_round(v: f64) -> u32 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    let scaled = v.log2() + 0.5;
    if scaled <= 0.0 {
        0
    } else if scaled >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        // Bounded on both sides by the branches above, as in `log2_times_8`.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            scaled as u32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Six replies whose ISNs advance by `step` every 100 ms.
    fn linear(step: u32, count: usize) -> SeqInputs {
        let mut replies = Vec::new();
        for i in 0..count {
            let i32b = u32::try_from(i).unwrap_or(0);
            replies.push(Some(SeqReply {
                isn: 0x1000_0000u32.wrapping_add(step.wrapping_mul(i32b)),
                ip_id: u16::try_from(i).unwrap_or(0).wrapping_add(1000),
                timestamp: i32b.wrapping_mul(100),
                sent_usec: u64::from(i32b).wrapping_mul(100_000),
            }));
        }
        SeqInputs {
            replies,
            ..SeqInputs::default()
        }
    }

    #[test]
    fn a_constant_isn_is_reported_as_gcd_zero_and_maximum_predictability() {
        let inputs = linear(0, 6);
        let t = analyze_seq(&inputs);
        assert_eq!(t.responses, 6);
        assert_eq!(t.gcd.as_deref(), Some("0"), "every difference was zero");
        assert_eq!(t.sp.as_deref(), Some("0"), "perfectly predictable");
        assert_eq!(t.isr.as_deref(), Some("0"));
    }

    #[test]
    fn a_perfectly_linear_counter_has_a_low_predictability_index() {
        // Constant step: the rate never varies, so the standard deviation is zero and
        // the index is 0 — the classic "trivially predictable" result.
        let t = analyze_seq(&linear(64_000, 6));
        assert_eq!(t.gcd.as_deref(), Some("FA00"), "64000 in uppercase hex");
        assert_eq!(t.sp.as_deref(), Some("0"));
        // 64000 per 100 ms = 640000/s; log2(640000)*8 + 0.5 truncated.
        let expected = super::log2_times_8(640_000.0);
        assert_eq!(t.isr.as_deref(), Some(hex(expected).as_str()));
    }

    #[test]
    fn fewer_than_four_replies_yields_no_isn_attributes() {
        for count in 0..MIN_ISN_RESPONSES {
            let t = analyze_seq(&linear(1000, count));
            assert_eq!(t.responses, count);
            assert_eq!(t.sp, None, "{count} replies");
            assert_eq!(t.gcd, None);
            assert_eq!(t.isr, None);
        }
        // Four is enough.
        let t = analyze_seq(&linear(1000, 4));
        assert!(t.sp.is_some() && t.gcd.is_some() && t.isr.is_some());
    }

    #[test]
    fn a_long_scan_delay_suppresses_the_isn_analysis() {
        let mut inputs = linear(1000, 6);
        inputs.scan_delay_ms = MAX_SCAN_DELAY_MS + 1;
        let t = analyze_seq(&inputs);
        assert_eq!(t.responses, 6, "the replies are still counted");
        assert_eq!(t.sp, None, "but the rate would be meaningless");
        inputs.scan_delay_ms = MAX_SCAN_DELAY_MS;
        assert!(
            analyze_seq(&inputs).sp.is_some(),
            "the boundary is inclusive"
        );
    }

    #[test]
    fn unanswered_probes_are_dropped_not_counted_as_zero() {
        // Gaps must compact, or a missing reply would look like a huge backwards jump.
        let mut inputs = linear(1000, 6);
        inputs.replies[1] = None;
        inputs.replies[3] = None;
        let t = analyze_seq(&inputs);
        assert_eq!(t.responses, 4);
        // The survivors are probes 0, 2, 4 and 5, so the steps are 2000, 2000, 1000 —
        // real gaps in the sampling, not a counter that jumped backwards to zero.
        assert_eq!(t.gcd.as_deref(), Some(&hex(1000)[..]));
    }

    #[test]
    fn the_gcd_is_divided_out_only_when_it_is_large() {
        // Two runs with identical relative jitter, one with a small step and one with a
        // large one. The large-GCD run divides the deviation out and so looks far more
        // predictable; the small-GCD run does not. This is the C's deliberate
        // compromise, and it is the reason SP is not simply a function of the ratios.
        let build = |steps: [u32; 5]| {
            let mut replies = Vec::new();
            let mut isn = 0x1000_0000u32;
            for (i, step) in steps.iter().enumerate() {
                replies.push(Some(SeqReply {
                    isn,
                    ip_id: 0,
                    timestamp: 0,
                    sent_usec: (i as u64).wrapping_mul(100_000),
                }));
                isn = isn.wrapping_add(*step);
            }
            replies.push(Some(SeqReply {
                isn,
                ip_id: 0,
                timestamp: 0,
                sent_usec: 500_000,
            }));
            SeqInputs {
                replies,
                ..SeqInputs::default()
            }
        };
        let small = analyze_seq(&build([2, 4, 2, 4, 2]));
        let large = analyze_seq(&build([20_000, 40_000, 20_000, 40_000, 20_000]));
        assert_eq!(small.gcd.as_deref(), Some("2"));
        assert_eq!(large.gcd.as_deref(), Some(&hex(20_000)[..]));
        let sp = |t: &SeqTest| u32::from_str_radix(t.sp.as_deref().unwrap_or("0"), 16).unwrap_or(0);
        assert!(
            sp(&large) < sp(&small),
            "a large GCD is divided out, so SP should drop: large={} small={}",
            sp(&large),
            sp(&small)
        );
    }

    #[test]
    fn the_isn_rate_never_goes_negative_where_the_c_would_be_undefined() {
        // Probes an hour apart with a one-step advance give a rate well below 1, whose
        // logarithm is negative. The C converts that to `unsigned int` — undefined.
        let replies: Vec<Option<SeqReply>> = (0..6u16)
            .map(|i| {
                Some(SeqReply {
                    isn: 0x1000_0000u32.wrapping_add(u32::from(i)),
                    ip_id: 0,
                    timestamp: 0,
                    sent_usec: u64::from(i).wrapping_mul(3_600_000_000),
                })
            })
            .collect();
        let t = analyze_seq(&SeqInputs {
            replies,
            ..SeqInputs::default()
        });
        assert_eq!(t.isr.as_deref(), Some("0"), "saturated, not wrapped");
        assert_eq!(t.gcd.as_deref(), Some("1"));
    }

    #[test]
    fn identical_send_times_do_not_divide_by_zero() {
        let replies: Vec<Option<SeqReply>> = (0..6u16)
            .map(|i| {
                Some(SeqReply {
                    isn: 0x1000_0000u32.wrapping_add(u32::from(i) * 1000),
                    ip_id: 0,
                    timestamp: 0,
                    sent_usec: 0,
                })
            })
            .collect();
        let t = analyze_seq(&SeqInputs {
            replies,
            ..SeqInputs::default()
        });
        assert!(t.isr.is_some(), "the C bumps a zero interval to 1 usec");
    }

    #[test]
    fn a_wrapped_isn_counter_reports_the_small_step() {
        // MOD_DIFF takes the smaller of the two wrapping differences, so a counter that
        // rolls over mid-run still shows its true step rather than a near-4-billion jump.
        let replies = vec![
            Some(SeqReply {
                isn: u32::MAX - 1000,
                ip_id: 0,
                timestamp: 0,
                sent_usec: 0,
            }),
            Some(SeqReply {
                isn: 1000,
                ip_id: 0,
                timestamp: 0,
                sent_usec: 100_000,
            }),
            Some(SeqReply {
                isn: 3001,
                ip_id: 0,
                timestamp: 0,
                sent_usec: 200_000,
            }),
            Some(SeqReply {
                isn: 5002,
                ip_id: 0,
                timestamp: 0,
                sent_usec: 300_000,
            }),
        ];
        let t = analyze_seq(&SeqInputs {
            replies,
            ..SeqInputs::default()
        });
        // Steps: 2001, 2001, 2001 — the wrap contributes 2001, not 4294965296.
        assert_eq!(t.gcd.as_deref(), Some(&hex(2001)[..]));
    }

    fn with_ipids(tcp: Vec<u16>, closed: Vec<u16>, icmp: Vec<u16>) -> SeqInputs {
        SeqInputs {
            tcp_ipids: tcp,
            closed_tcp_ipids: closed,
            icmp_ipids: icmp,
            ..SeqInputs::default()
        }
    }

    #[test]
    fn ip_id_classes_render_as_the_c_tokens() {
        let t = analyze_seq(&with_ipids(
            vec![100, 101, 102, 103],
            vec![0, 0, 0],
            vec![7, 7, 7],
        ));
        assert_eq!(t.ti.as_deref(), Some("I"), "incremental");
        assert_eq!(t.ci.as_deref(), Some("Z"), "all zero");
        // A constant counter reports its value, not merely "constant".
        assert_eq!(t.ii.as_deref(), Some("7"));
    }

    #[test]
    fn too_few_ip_id_samples_omit_the_attribute() {
        // The open-port test needs three samples, the other two need two.
        let t = analyze_seq(&with_ipids(vec![100, 101], vec![5], vec![9]));
        assert_eq!(t.ti, None, "two open-port samples are not enough");
        assert_eq!(t.ci, None);
        assert_eq!(t.ii, None);
        let t = analyze_seq(&with_ipids(vec![100, 101, 102], vec![5, 6], vec![9, 10]));
        assert!(t.ti.is_some() && t.ci.is_some() && t.ii.is_some());
    }

    #[test]
    fn shared_counters_are_detected_only_when_both_are_incremental() {
        // TCP climbing 100..103 and ICMP starting at 104 — the same counter.
        let t = analyze_seq(&with_ipids(
            vec![100, 101, 102, 103],
            vec![],
            vec![104, 105, 106],
        ));
        assert_eq!(t.ss.as_deref(), Some("S"));

        // ICMP far above the TCP counter: separate counters.
        let t = analyze_seq(&with_ipids(
            vec![100, 101, 102, 103],
            vec![],
            vec![50000, 50001, 50002],
        ));
        assert_eq!(t.ss.as_deref(), Some("O"));

        // ICMP constant rather than incremental: the question does not apply.
        let t = analyze_seq(&with_ipids(vec![100, 101, 102, 103], vec![], vec![7, 7, 7]));
        assert_eq!(t.ss, None);
    }

    #[test]
    fn timestamp_verdicts_from_reply_processing_short_circuit_the_frequency_analysis() {
        let mut inputs = linear(1000, 6);
        inputs.ts_class = TsClass::Zero;
        assert_eq!(analyze_seq(&inputs).ts.as_deref(), Some("0"));
        inputs.ts_class = TsClass::Unsupported;
        assert_eq!(analyze_seq(&inputs).ts.as_deref(), Some("U"));
    }

    #[test]
    fn timestamp_frequencies_land_in_the_buckets_real_systems_use() {
        // Build six replies whose timestamps advance at `hz`, 100 ms apart.
        // The test drives whole-number tick counts; the conversion is bounded by the
        // small `hz` values used below.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let at_hz = |hz: f64| {
            let replies: Vec<Option<SeqReply>> = (0..6u16)
                .map(|i| {
                    Some(SeqReply {
                        isn: 0x1000_0000u32.wrapping_add(u32::from(i).wrapping_mul(1000)),
                        ip_id: 0,
                        timestamp: (f64::from(i) * hz / 10.0) as u32,
                        sent_usec: u64::from(i).wrapping_mul(100_000),
                    })
                })
                .collect();
            analyze_seq(&SeqInputs {
                replies,
                ..SeqInputs::default()
            })
            .ts
        };
        assert_eq!(at_hz(2.0).as_deref(), Some("1"), "2 Hz");
        assert_eq!(at_hz(100.0).as_deref(), Some("7"), "100 Hz");
        assert_eq!(at_hz(200.0).as_deref(), Some("8"), "200 Hz");
        // 1000 Hz falls through to the logarithm: round(log2(1000)) = 10 = 0xA.
        assert_eq!(at_hz(1000.0).as_deref(), Some("A"), "1000 Hz");
    }

    #[test]
    fn a_stopped_timestamp_clock_sets_no_attribute() {
        // Timestamps present but never advancing, with no earlier verdict: the C's
        // switch has no arm for TS_SEQ_UNKNOWN, so nothing is recorded.
        let replies: Vec<Option<SeqReply>> = (0..6u16)
            .map(|i| {
                Some(SeqReply {
                    isn: 0x1000_0000u32.wrapping_add(u32::from(i) * 1000),
                    ip_id: 0,
                    timestamp: 12345,
                    sent_usec: u64::from(i).wrapping_mul(100_000),
                })
            })
            .collect();
        let t = analyze_seq(&SeqInputs {
            replies,
            ..SeqInputs::default()
        });
        assert_eq!(t.ts, None);
    }

    #[test]
    fn no_replies_at_all_produces_an_empty_test() {
        let t = analyze_seq(&SeqInputs::default());
        assert_eq!(t, SeqTest::default());
        assert_eq!(t.responses, 0);
    }

    #[test]
    fn the_result_renders_into_a_scorable_finger_test() {
        let mut inputs = linear(1000, 6);
        inputs.tcp_ipids = vec![100, 101, 102, 103];
        inputs.icmp_ipids = vec![104, 105];
        inputs.ts_class = TsClass::Unsupported;
        let t = analyze_seq(&inputs);
        let ft = t.to_finger_test();
        assert_eq!(ft.id, TestId::Seq);
        assert_eq!(ft.values.len(), TestId::Seq.attrs().len());
        assert_eq!(ft.get("GCD"), t.gcd.as_deref());
        assert_eq!(ft.get("TI"), Some("I"));
        assert_eq!(ft.get("TS"), Some("U"));
        // An attribute the analysis did not set stays unspecified rather than empty.
        assert_eq!(ft.get("CI"), None);
    }

    #[test]
    fn gcd_helper_matches_the_c_edge_cases() {
        assert_eq!(gcd_n_uint(&[]), 1, "empty is 1, as the C returns");
        assert_eq!(gcd_n_uint(&[0, 0, 0]), 0, "all zero is 0, meaning constant");
        assert_eq!(gcd_n_uint(&[12]), 12);
        assert_eq!(gcd_n_uint(&[12, 18]), 6);
        assert_eq!(gcd_n_uint(&[12, 18, 30]), 6);
        assert_eq!(gcd_n_uint(&[0, 5]), 5);
        assert_eq!(gcd_n_uint(&[7, 13]), 1);
        assert_eq!(gcd_n_uint(&[u32::MAX, u32::MAX]), u32::MAX);
    }

    #[test]
    fn mod_diff_takes_the_shorter_way_round() {
        assert_eq!(mod_diff(10, 3), 7);
        assert_eq!(mod_diff(3, 10), 7);
        assert_eq!(
            mod_diff(0, u32::MAX),
            1,
            "one step backwards across the wrap"
        );
        assert_eq!(mod_diff(5, 5), 0);
    }
    /// Six replies whose timestamp advances by `per_probe` each 100 ms, starting at
    /// `first_ts` — i.e. a clock running at `per_probe * 10` Hz.
    fn ts_series(first_ts: u32, per_probe: u32) -> SeqInputs {
        let replies = (0..6u32)
            .map(|i| {
                Some(SeqReply {
                    isn: 1000u32.saturating_add(i),
                    ip_id: 0,
                    timestamp: first_ts.saturating_add(per_probe.saturating_mul(i)),
                    sent_usec: u64::from(i) * 100_000,
                })
            })
            .collect();
        SeqInputs {
            replies,
            ts_class: TsClass::Unknown,
            ..SeqInputs::default()
        }
    }

    #[test]
    fn uptime_divides_the_first_timestamp_by_the_detected_frequency() {
        // 10 ticks per 100 ms = 100 Hz, so the ladder's 70..150 bucket divides by 100.
        let u = estimate_uptime(&ts_series(360_000, 10), 1_000_000_000).expect("uptime");
        assert_eq!(u.seconds, 3600, "360000 ticks at 100 Hz is one hour");
        assert_eq!(u.lastboot, 1_000_000_000 - 3600);

        // 0.2 ticks per 100 ms would be 2 Hz; use 1 tick per 500 ms via wider spacing.
        let mut slow = ts_series(7200, 0);
        for (i, r) in slow.replies.iter_mut().flatten().enumerate() {
            r.timestamp = 7200 + u32::try_from(i).unwrap();
            r.sent_usec = u64::try_from(i).unwrap() * 500_000;
        }
        let u = estimate_uptime(&slow, 0).expect("uptime");
        assert_eq!(u.seconds, 3600, "2 Hz clock divides by 2");

        // 100 ticks per 100 ms = 1000 Hz, the 724..1448 bucket.
        let u = estimate_uptime(&ts_series(3_600_000, 100), 0).expect("uptime");
        assert_eq!(u.seconds, 3600);
    }

    // The C rejects a claim over two years as a lie, sets uptime to 0, and *still*
    // records a boot time — so the host reads as "just booted", not as unknown.
    // The C rejects a claim over two years, sets uptime to 0, and *still* records a
    // boot time — so the host reads as "just booted", not as unknown.
    //
    // Only a slow clock can trigger it at all: the timestamp is a u32, so at 100 Hz the
    // largest expressible uptime is u32::MAX/100 = 1.36 years and at 1000 Hz just 50
    // days. The clamp is reachable through the 2 Hz branch (up to 68 years) and the
    // low end of the fallback bucket, which is why this uses the 2 Hz series.
    #[test]
    fn an_implausible_uptime_is_clamped_but_still_dates_a_boot() {
        let mut slow = ts_series(0, 0);
        for (i, r) in slow.replies.iter_mut().flatten().enumerate() {
            // 1 tick per 500 ms = 2 Hz; a first timestamp implying ~3.2 years.
            r.timestamp = 200_000_000 + u32::try_from(i).unwrap();
            r.sent_usec = u64::try_from(i).unwrap() * 500_000;
        }
        let u = estimate_uptime(&slow, 1_000_000_000).expect("uptime");
        assert_eq!(u.seconds, 0, "over two years is rejected");
        assert_eq!(u.lastboot, 1_000_000_000, "lastboot is still set");
    }

    #[test]
    fn no_uptime_without_usable_timestamps() {
        // Reply processing already concluded the timestamps were zero or absent: the C
        // never enters the block, so lastboot stays 0 and nothing is printed.
        for class in [TsClass::Zero, TsClass::Unsupported] {
            let mut inputs = ts_series(360_000, 10);
            inputs.ts_class = class;
            assert_eq!(estimate_uptime(&inputs, 0), None, "{class:?}");
        }
        // Fewer than two responses.
        let mut thin = ts_series(360_000, 10);
        thin.replies = vec![thin.replies[0], None, None, None, None, None];
        assert_eq!(estimate_uptime(&thin, 0), None);
        assert_eq!(estimate_uptime(&SeqInputs::default(), 0), None);
    }

    #[test]
    fn a_motionless_clock_dates_the_boot_to_now() {
        // avg_hz == 0: no branch fires, uptime stays 0, and the C still assigns
        // lastboot = send time.
        let u = estimate_uptime(&ts_series(500, 0), 12_345).expect("uptime");
        assert_eq!(u.seconds, 0);
        assert_eq!(u.lastboot, 12_345);
    }

    #[test]
    fn uptime_never_panics_on_extreme_inputs() {
        // Saturating construction: the point is the analysis, not the fixture.
        let replies = (0..6u32)
            .map(|i| {
                Some(SeqReply {
                    isn: u32::MAX,
                    ip_id: 0,
                    timestamp: u32::MAX.wrapping_sub(i),
                    // Identical send times: the elapsed-time divisor is floored at 1 us.
                    sent_usec: 0,
                })
            })
            .collect();
        let inputs = SeqInputs {
            replies,
            ts_class: TsClass::Unknown,
            ..SeqInputs::default()
        };
        let _ = estimate_uptime(&inputs, i64::MIN);
        let _ = estimate_uptime(&inputs, i64::MAX);
        let _ = estimate_uptime(&inputs, 0);
    }
}
