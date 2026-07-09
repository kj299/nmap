//! Scan timing — RTT estimation and the `-T0..-T5` timing templates. The Rust
//! analog of `timing.cc` (`adjust_timeouts2` / `initialize_timeout_info`) and
//! the timing-template table in `nmap.cc` / `NmapOps.cc`.
//!
//! For Milestone 1's connect scan the relevant outputs are the per-probe
//! **timeout** (how long to wait on a connect before giving up) and the
//! **parallelism** / **scan-delay** knobs. All math is fixed-point microseconds
//! (`i64`), matching nmap; there is no floating point and no `unsafe`.

/// Clamp `val` to `[min, max]` — nmap's `box(min, max, val)`. Unlike
/// `i64::clamp`, this does not panic when `min > max` (it returns `min`),
/// mirroring the C helper's behavior.
fn box_clamp(min: i64, max: i64, val: i64) -> i64 {
    if val < min {
        min
    } else if val > max {
        max
    } else {
        val
    }
}

/// Smoothed round-trip-time estimate and derived timeout, in microseconds — a
/// port of C `struct timeout_info`. `srtt`/`rttvar` are `-1` until the first
/// sample initializes them (as in `initialize_timeout_info`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeoutInfo {
    /// Smoothed RTT estimate (µs), or `-1` before the first sample.
    pub srtt: i64,
    /// RTT variance (µs), or `-1` before the first sample.
    pub rttvar: i64,
    /// Current timeout threshold (µs).
    pub timeout: i64,
}

impl TimeoutInfo {
    /// A fresh estimator whose timeout starts at the template's initial RTT
    /// timeout (`initialize_timeout_info`: `srtt = rttvar = -1`).
    pub fn new(params: &TimingParams) -> Self {
        Self {
            srtt: -1,
            rttvar: -1,
            // stored in ms; the estimator works in µs.
            timeout: params.initial_rtt_timeout_ms.saturating_mul(1000),
        }
    }

    /// Fold one observed round-trip `delta` (µs, `received - sent`) into the
    /// estimate — a direct port of `adjust_timeouts2` (Jacobson/Karels), then
    /// clamped to the template's `[min, max]` RTT timeout. Bogus samples are
    /// ignored exactly as the C does.
    // All arithmetic is bounded: samples are gated to < 8 s, srtt/rttvar are
    // capped at ~2.3 s, so the sums/shifts stay far inside i64.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn adjust(&mut self, mut delta: i64, params: &TimingParams) {
        // pcap/gettimeofday skew can make delta slightly negative; nmap treats a
        // small negative as 10 ms.
        if delta < 0 && delta > -50000 {
            delta = 10000;
        }

        if self.srtt == -1 && self.rttvar == -1 {
            self.srtt = delta;
            self.rttvar = box_clamp(5000, 2000000, self.srtt);
            self.timeout = self.srtt + (self.rttvar << 2);
        } else {
            // Discard implausible samples (as C does) rather than skew the mean:
            // C's `delta >= 8000000 || delta < 0`, i.e. delta not in [0, 8s).
            if !(0..8_000_000).contains(&delta) {
                return;
            }
            let rttdelta = delta - self.srtt;
            if rttdelta > 1500000 && rttdelta > 3 * self.srtt + 2 * self.rttvar {
                return;
            }
            self.srtt += rttdelta >> 3;
            self.rttvar += (rttdelta.abs() - self.rttvar) >> 2;
            self.timeout = self.srtt + (self.rttvar << 2);
        }

        if self.rttvar > 2300000 {
            self.rttvar = 2000000;
        }

        self.timeout = box_clamp(
            params.min_rtt_timeout_ms.saturating_mul(1000),
            params.max_rtt_timeout_ms.saturating_mul(1000),
            self.timeout,
        );
    }
}

/// The `-T` timing templates, Paranoid (0) … Insane (5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingTemplate {
    Paranoid,
    Sneaky,
    Polite,
    Normal,
    Aggressive,
    Insane,
}

impl TimingTemplate {
    /// From a numeric `-T` level (0–5).
    pub fn from_level(level: u8) -> Option<Self> {
        Some(match level {
            0 => TimingTemplate::Paranoid,
            1 => TimingTemplate::Sneaky,
            2 => TimingTemplate::Polite,
            3 => TimingTemplate::Normal,
            4 => TimingTemplate::Aggressive,
            5 => TimingTemplate::Insane,
            _ => return None,
        })
    }

    /// From a `-T` name (case-insensitive), e.g. `"Aggressive"`.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "paranoid" => TimingTemplate::Paranoid,
            "sneaky" => TimingTemplate::Sneaky,
            "polite" => TimingTemplate::Polite,
            "normal" => TimingTemplate::Normal,
            "aggressive" => TimingTemplate::Aggressive,
            "insane" => TimingTemplate::Insane,
            _ => return None,
        })
    }
}

/// Timing knobs derived from a template (the subset an unprivileged connect
/// scan needs). RTT timeouts and scan delay are in **milliseconds** (as nmap
/// stores them); the estimator scales to microseconds internally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimingParams {
    pub min_rtt_timeout_ms: i64,
    pub max_rtt_timeout_ms: i64,
    pub initial_rtt_timeout_ms: i64,
    /// Max concurrent probes; `0` means "auto / unbounded" (nmap default).
    pub max_parallelism: u32,
    pub scan_delay_ms: i64,
    pub max_tcp_scan_delay_ms: i64,
    pub max_retransmissions: u32,
}

impl Default for TimingParams {
    /// The `-T3` (Normal) defaults: `MIN/MAX/INITIAL_RTT_TIMEOUT`,
    /// `MAX_TCP_SCAN_DELAY`, unbounded parallelism, no scan delay.
    fn default() -> Self {
        Self {
            min_rtt_timeout_ms: 100,      // MIN_RTT_TIMEOUT
            max_rtt_timeout_ms: 10000,    // MAX_RTT_TIMEOUT
            initial_rtt_timeout_ms: 1000, // INITIAL_RTT_TIMEOUT
            max_parallelism: 0,
            scan_delay_ms: 0,
            max_tcp_scan_delay_ms: 1000, // MAX_TCP_SCAN_DELAY
            max_retransmissions: 10,
        }
    }
}

impl TimingParams {
    /// Build the params for a template, applying nmap's exact setter
    /// interactions (raising/lowering the sibling RTT bounds as needed).
    pub fn for_template(t: TimingTemplate) -> Self {
        let mut p = TimingParams::default();
        match t {
            TimingTemplate::Normal => {}
            TimingTemplate::Paranoid => {
                p.max_parallelism = 1;
                p.scan_delay_ms = 300_000;
                p.set_initial_rtt(300_000);
            }
            TimingTemplate::Sneaky => {
                p.max_parallelism = 1;
                p.scan_delay_ms = 15_000;
                p.set_initial_rtt(15_000);
            }
            TimingTemplate::Polite => {
                p.max_parallelism = 1;
                p.scan_delay_ms = 400;
            }
            TimingTemplate::Aggressive => {
                p.set_min_rtt(100);
                p.set_max_rtt(1250);
                p.set_initial_rtt(500);
                p.max_tcp_scan_delay_ms = 10;
                p.max_retransmissions = 6;
            }
            TimingTemplate::Insane => {
                p.set_min_rtt(50);
                p.set_max_rtt(300);
                p.set_initial_rtt(250);
                p.max_tcp_scan_delay_ms = 5;
                p.max_retransmissions = 2;
            }
        }
        p
    }

    /// `setInitialRttTimeout`: also raises max / lowers min to stay consistent.
    fn set_initial_rtt(&mut self, ms: i64) {
        self.initial_rtt_timeout_ms = ms;
        if ms > self.max_rtt_timeout_ms {
            self.max_rtt_timeout_ms = ms;
        }
        if ms < self.min_rtt_timeout_ms {
            self.min_rtt_timeout_ms = ms;
        }
    }

    /// `setMaxRttTimeout`: also lowers min / initial if they exceed the new max.
    fn set_max_rtt(&mut self, ms: i64) {
        self.max_rtt_timeout_ms = ms;
        if ms < self.min_rtt_timeout_ms {
            self.min_rtt_timeout_ms = ms;
        }
        if ms < self.initial_rtt_timeout_ms {
            self.initial_rtt_timeout_ms = ms;
        }
    }

    /// `setMinRttTimeout`: also raises max / initial if they are below the new min.
    fn set_min_rtt(&mut self, ms: i64) {
        self.min_rtt_timeout_ms = ms;
        if ms > self.max_rtt_timeout_ms {
            self.max_rtt_timeout_ms = ms;
        }
        if ms > self.initial_rtt_timeout_ms {
            self.initial_rtt_timeout_ms = ms;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_clamp_matches_nmap_box() {
        assert_eq!(box_clamp(5000, 2000000, 100), 5000); // below min
        assert_eq!(box_clamp(5000, 2000000, 3_000_000), 2000000); // above max
        assert_eq!(box_clamp(5000, 2000000, 50000), 50000); // in range
        assert_eq!(box_clamp(100, 50, 75), 100); // min > max → min (no panic)
    }

    #[test]
    fn first_sample_initializes_like_c() {
        let p = TimingParams::default();
        let mut to = TimeoutInfo::new(&p);
        assert_eq!(to.srtt, -1);
        assert_eq!(to.timeout, 1_000_000); // initial 1000 ms → µs
                                           // First sample: srtt = delta, rttvar = clamp(5000,2e6,srtt), to=srtt+4*rttvar
        to.adjust(20000, &p); // 20 ms RTT
        assert_eq!(to.srtt, 20000);
        assert_eq!(to.rttvar, 20000); // 20000 within [5000, 2e6]
                                      // srtt + (rttvar<<2) = 20000 + 80000 = 100000, clamped to [100ms,10s]µs
        assert_eq!(to.timeout, 100_000);
    }

    #[test]
    fn timeout_is_clamped_to_min() {
        let p = TimingParams::default();
        let mut to = TimeoutInfo::new(&p);
        to.adjust(1000, &p); // 1 ms RTT → tiny timeout, clamped up to min 100 ms
        assert_eq!(to.timeout, 100_000); // min_rtt_timeout 100 ms in µs
    }

    #[test]
    fn subsequent_samples_smooth_the_estimate() {
        let p = TimingParams::default();
        let mut to = TimeoutInfo::new(&p);
        to.adjust(100000, &p); // init srtt=100000
        let before = to.srtt;
        to.adjust(200000, &p); // rttdelta=100000; srtt += 100000>>3 = 12500
        assert_eq!(to.srtt, before + 12500);
    }

    #[test]
    fn bogus_samples_are_ignored() {
        let p = TimingParams::default();
        let mut to = TimeoutInfo::new(&p);
        to.adjust(50000, &p);
        let snapshot = to;
        to.adjust(9_000_000, &p); // >= 8 s → ignored
        assert_eq!(to, snapshot);
    }

    #[test]
    fn small_negative_delta_becomes_10ms() {
        let p = TimingParams::default();
        let mut to = TimeoutInfo::new(&p);
        to.adjust(-20000, &p); // small negative → treated as 10000 µs
        assert_eq!(to.srtt, 10000);
    }

    #[test]
    fn templates_match_nmap() {
        let normal = TimingParams::for_template(TimingTemplate::Normal);
        assert_eq!(
            (
                normal.min_rtt_timeout_ms,
                normal.max_rtt_timeout_ms,
                normal.initial_rtt_timeout_ms
            ),
            (100, 10000, 1000)
        );
        assert_eq!(normal.max_parallelism, 0);

        let paranoid = TimingParams::for_template(TimingTemplate::Paranoid);
        assert_eq!(paranoid.max_parallelism, 1);
        assert_eq!(paranoid.scan_delay_ms, 300_000);
        // set_initial_rtt(300000) also raised max to 300000.
        assert_eq!(paranoid.initial_rtt_timeout_ms, 300_000);
        assert_eq!(paranoid.max_rtt_timeout_ms, 300_000);
        assert_eq!(paranoid.min_rtt_timeout_ms, 100);

        let aggressive = TimingParams::for_template(TimingTemplate::Aggressive);
        assert_eq!(
            (
                aggressive.min_rtt_timeout_ms,
                aggressive.max_rtt_timeout_ms,
                aggressive.initial_rtt_timeout_ms
            ),
            (100, 1250, 500)
        );
        assert_eq!(aggressive.max_retransmissions, 6);

        let insane = TimingParams::for_template(TimingTemplate::Insane);
        assert_eq!(
            (
                insane.min_rtt_timeout_ms,
                insane.max_rtt_timeout_ms,
                insane.initial_rtt_timeout_ms
            ),
            (50, 300, 250)
        );
        assert_eq!(insane.max_retransmissions, 2);
    }

    #[test]
    fn template_lookup_by_level_and_name() {
        assert_eq!(
            TimingTemplate::from_level(0),
            Some(TimingTemplate::Paranoid)
        );
        assert_eq!(TimingTemplate::from_level(3), Some(TimingTemplate::Normal));
        assert_eq!(TimingTemplate::from_level(5), Some(TimingTemplate::Insane));
        assert_eq!(TimingTemplate::from_level(6), None);
        assert_eq!(
            TimingTemplate::from_name("AGGRESSIVE"),
            Some(TimingTemplate::Aggressive)
        );
        assert_eq!(TimingTemplate::from_name("bogus"), None);
    }
}
