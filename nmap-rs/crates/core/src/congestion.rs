//! Congestion control for the scan engine — the Rust port of nmap's
//! `ultra_timing_vals` / `scan_performance_vars` (`timing.cc`). This is the
//! TCP-style AIMD (additive-increase / multiplicative-decrease) controller that
//! bounds how many probes are in flight: a **congestion window** (`cwnd`, in
//! probes) grows on every reply and collapses on a detected drop, with a
//! slow-start / congestion-avoidance split at `ssthresh`.
//!
//! Milestone 2 spike: this module is ported *first and in isolation* because the
//! retransmission/congestion math is the subtle, hazardous part of the engine
//! (PLAYBOOK Phase 4 "spike the scary module"). It is **pure** — no clock, no
//! I/O — so it is exhaustively unit-testable and its results are pinned to the C
//! arithmetic. The async driver (Milestone 2, later) calls `ack`/`drop` on these
//! values; the engine never reaches for a socket through this type.
//!
//! Safety over the C: `cwnd` is held `>= low_cwnd >= 1` by construction, so the
//! congestion-avoidance divide `ca_incr / cwnd` can never divide by zero; and
//! `cc_scale` is only reachable after `num_replies_received` has been
//! incremented, so its ratio is never `x/0`. The C relies on an `assert()` for
//! the latter; here the invariant is structural (see [`TimingVals::ack`]).

use crate::timing::TimingTemplate;

/// Tuning constants for the controller — the port of `scan_performance_vars`,
/// filled by `scan_performance_vars::init()`. Independent of any single host or
/// group; shared across the whole scan.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PerfVars {
    /// Lowest `cwnd` allowed (also the loss-window `cwnd` is reset to on a host
    /// drop). Always `>= 1`.
    pub low_cwnd: i32,
    /// Initial per-host congestion window.
    pub host_initial_cwnd: i32,
    /// Initial group congestion window.
    pub group_initial_cwnd: i32,
    /// Never keep more than this many probes outstanding.
    pub max_cwnd: i32,
    /// Probes added per reply in slow-start mode.
    pub slow_incr: i32,
    /// Probes added per (roughly) RTT in congestion-avoidance mode.
    pub ca_incr: i32,
    /// Cap on the congestion-window increment scaling factor.
    pub cc_scale_max: i32,
    /// Initial slow-start threshold.
    pub initial_ssthresh: i32,
    /// Group `cwnd` is divided by this on any drop.
    pub group_drop_cwnd_divisor: f64,
    /// Group `ssthresh` drop divisor.
    pub group_drop_ssthresh_divisor: f64,
    /// Host `ssthresh` drop divisor.
    pub host_drop_ssthresh_divisor: f64,
}

impl PerfVars {
    /// Port of `scan_performance_vars::init()`. `min_parallelism` /
    /// `max_parallelism` are nmap's `-T`/`--min-parallelism`/`--max-parallelism`
    /// (`0` = "unset", taking nmap's defaults of `1` and `300`). The template
    /// level scales `ca_incr` and the ssthresh drop divisor.
    pub fn new(template: TimingTemplate, min_parallelism: u32, max_parallelism: u32) -> Self {
        let low_cwnd: i32 = if min_parallelism != 0 {
            // -1 avoids the i32::MAX -> cast issue; parallelism fits i32 in practice.
            min_parallelism.min(i32::MAX as u32) as i32
        } else {
            1
        };
        let max_cwnd: i32 = if max_parallelism != 0 {
            low_cwnd.max(max_parallelism.min(i32::MAX as u32) as i32)
        } else {
            low_cwnd.max(300)
        };
        // box(low_cwnd, max_cwnd, 10) — clamp the literal 10 into the window.
        // Both bounds are i32, so the result is i32 by construction (done in i32
        // space to avoid a truncating i64→i32 cast). Matches nmap's `box`,
        // including the `min > max → min` degenerate case.
        let group_initial_cwnd = if 10 < low_cwnd {
            low_cwnd
        } else if 10 > max_cwnd {
            max_cwnd
        } else {
            10
        };

        let level = template.level();
        let ca_incr = if level < 4 { 1 } else { 2 };
        // ssthresh drop divisor grows gentler as timing gets more aggressive.
        let ssthresh_divisor = if level <= 3 {
            3.0 / 2.0
        } else if level <= 4 {
            4.0 / 3.0
        } else {
            5.0 / 4.0
        };

        PerfVars {
            low_cwnd,
            host_initial_cwnd: group_initial_cwnd,
            group_initial_cwnd,
            max_cwnd,
            slow_incr: 1,
            ca_incr,
            cc_scale_max: 50,
            initial_ssthresh: 75,
            group_drop_cwnd_divisor: 2.0,
            group_drop_ssthresh_divisor: ssthresh_divisor,
            host_drop_ssthresh_divisor: ssthresh_divisor,
        }
    }
}

/// Per-host or per-group congestion state — the port of `ultra_timing_vals`.
/// `cwnd` is a probe count carried as `f64` (fractional growth accumulates
/// across replies, exactly as in C).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TimingVals {
    /// Congestion window, in probes. Invariant: `>= perf.low_cwnd >= 1`.
    pub cwnd: f64,
    /// Slow-start threshold: `cwnd < ssthresh` ⇒ slow start, else congestion
    /// avoidance.
    pub ssthresh: i32,
    /// Replies we'd expect if every sent probe answered (incremented on
    /// send-accounting by the engine, not here).
    pub num_replies_expected: i32,
    /// Replies actually received.
    pub num_replies_received: i32,
    /// Count of updates (reply receipts) — diagnostic, mirrors C `num_updates`.
    pub num_updates: i32,
}

impl TimingVals {
    /// A freshly-initialized host window (`cwnd = host_initial_cwnd`).
    pub fn new_host(perf: &PerfVars) -> Self {
        TimingVals::with_cwnd(perf.host_initial_cwnd, perf.initial_ssthresh)
    }

    /// A freshly-initialized group window (`cwnd = group_initial_cwnd`).
    pub fn new_group(perf: &PerfVars) -> Self {
        TimingVals::with_cwnd(perf.group_initial_cwnd, perf.initial_ssthresh)
    }

    fn with_cwnd(cwnd: i32, ssthresh: i32) -> Self {
        TimingVals {
            cwnd: f64::from(cwnd),
            ssthresh,
            num_replies_expected: 0,
            num_replies_received: 0,
            num_updates: 0,
        }
    }

    /// Congestion-window increment scaling — the port of
    /// `ultra_timing_vals::cc_scale`. Scales increments up when we've received
    /// fewer replies than expected (probes are being lost/delayed), capped at
    /// `cc_scale_max`.
    ///
    /// Caller must ensure `num_replies_received >= 1`; [`ack`](Self::ack)
    /// guarantees this by incrementing first, so the ratio is never `x/0`.
    fn cc_scale(&self, perf: &PerfVars) -> f64 {
        debug_assert!(self.num_replies_received > 0, "cc_scale before any reply");
        let received = self.num_replies_received.max(1);
        let ratio = f64::from(self.num_replies_expected) / f64::from(received);
        ratio.min(f64::from(perf.cc_scale_max))
    }

    /// Update the window for the receipt of a reply — the port of
    /// `ultra_timing_vals::ack`. `scale` (default `1.0`) lets a caller weight a
    /// single ack (used by group updates in the C for multi-probe responses).
    pub fn ack(&mut self, perf: &PerfVars, scale: f64) {
        self.num_replies_received = self.num_replies_received.saturating_add(1);
        self.num_updates = self.num_updates.saturating_add(1);

        if self.cwnd < f64::from(self.ssthresh) {
            // Slow start: grow by up to `slow_incr` per ack, then don't overshoot
            // ssthresh.
            self.cwnd += f64::from(perf.slow_incr) * self.cc_scale(perf) * scale;
            if self.cwnd > f64::from(self.ssthresh) {
                self.cwnd = f64::from(self.ssthresh);
            }
        } else {
            // Congestion avoidance: ~1 extra probe per RTT. cwnd >= low_cwnd >= 1,
            // so this divide is always well-defined.
            self.cwnd += f64::from(perf.ca_incr) / self.cwnd * self.cc_scale(perf) * scale;
        }
        if self.cwnd > f64::from(perf.max_cwnd) {
            self.cwnd = f64::from(perf.max_cwnd);
        }
    }

    /// Update the window for a host-level drop (a probe timed out) — the port of
    /// `ultra_timing_vals::drop`. Aggressive: `cwnd` collapses to the loss
    /// window and `ssthresh` halves relative to what was in flight.
    pub fn drop(&mut self, in_flight: u32, perf: &PerfVars) {
        self.cwnd = f64::from(perf.low_cwnd);
        self.ssthresh = ssthresh_from_flight(in_flight, perf.host_drop_ssthresh_divisor);
    }

    /// Update the window for a group-level drop — the port of
    /// `ultra_timing_vals::drop_group`. Gentler than [`drop`](Self::drop):
    /// `cwnd` is divided rather than reset, so one host's loss doesn't stall the
    /// whole group.
    pub fn drop_group(&mut self, in_flight: u32, perf: &PerfVars) {
        let divided = self.cwnd / perf.group_drop_cwnd_divisor;
        self.cwnd = f64::from(perf.low_cwnd).max(divided);
        self.ssthresh = ssthresh_from_flight(in_flight, perf.group_drop_ssthresh_divisor);
    }
}

/// `max(in_flight / divisor, 2)` truncated to `i32` — the shared ssthresh-drop
/// computation from `drop`/`drop_group`. `divisor` is always `>= 1` (set from
/// the timing level), so the result is finite and non-negative before the floor.
fn ssthresh_from_flight(in_flight: u32, divisor: f64) -> i32 {
    let dropped = f64::from(in_flight) / divisor;
    let floored = dropped.max(2.0);
    // floored is in [2, in_flight]; in_flight is a u32 probe count that never
    // approaches i32::MAX in practice, but clamp defensively rather than let an
    // `as` cast wrap.
    if floored >= f64::from(i32::MAX) {
        i32::MAX
    } else {
        // Bounded to [2, i32::MAX) by the checks above and finite (divisor >= 1),
        // so this truncation cannot wrap or lose the integer part.
        #[allow(clippy::cast_possible_truncation)]
        let ss = floored as i32;
        ss
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Constants pinned to `scan_performance_vars::init()` for the default -T3.
    #[test]
    fn perf_defaults_match_nmap_t3() {
        let p = PerfVars::new(TimingTemplate::Normal, 0, 0);
        assert_eq!(p.low_cwnd, 1);
        assert_eq!(p.max_cwnd, 300);
        assert_eq!(p.group_initial_cwnd, 10); // box(1,300,10)
        assert_eq!(p.host_initial_cwnd, 10);
        assert_eq!(p.slow_incr, 1);
        assert_eq!(p.ca_incr, 1); // level 3 < 4
        assert_eq!(p.cc_scale_max, 50);
        assert_eq!(p.initial_ssthresh, 75);
        assert_eq!(p.group_drop_cwnd_divisor, 2.0);
        assert_eq!(p.group_drop_ssthresh_divisor, 1.5); // 3/2
        assert_eq!(p.host_drop_ssthresh_divisor, 1.5);
    }

    #[test]
    fn perf_level_scaling_matches_nmap() {
        // ca_incr: 1 for T0..T3, 2 for T4/T5.
        assert_eq!(PerfVars::new(TimingTemplate::Aggressive, 0, 0).ca_incr, 2);
        assert_eq!(PerfVars::new(TimingTemplate::Insane, 0, 0).ca_incr, 2);
        assert_eq!(PerfVars::new(TimingTemplate::Polite, 0, 0).ca_incr, 1);
        // ssthresh divisor: 3/2 (<=T3), 4/3 (T4), 5/4 (T5).
        assert_eq!(
            PerfVars::new(TimingTemplate::Aggressive, 0, 0).host_drop_ssthresh_divisor,
            4.0 / 3.0
        );
        assert_eq!(
            PerfVars::new(TimingTemplate::Insane, 0, 0).host_drop_ssthresh_divisor,
            5.0 / 4.0
        );
    }

    #[test]
    fn parallelism_bounds_box_the_initial_window() {
        // --min-parallelism 20 --max-parallelism 5 → low=20, max=max(20,5)=20,
        // group_initial = box(20,20,10) = 20.
        let p = PerfVars::new(TimingTemplate::Normal, 20, 5);
        assert_eq!(p.low_cwnd, 20);
        assert_eq!(p.max_cwnd, 20);
        assert_eq!(p.group_initial_cwnd, 20);
        // --max-parallelism 50 → box(1,50,10) = 10.
        let p2 = PerfVars::new(TimingTemplate::Normal, 0, 50);
        assert_eq!(p2.max_cwnd, 50);
        assert_eq!(p2.group_initial_cwnd, 10);
    }

    #[test]
    fn slow_start_grows_then_caps_at_ssthresh() {
        let perf = PerfVars::new(TimingTemplate::Normal, 0, 0);
        let mut t = TimingVals::new_host(&perf); // cwnd=10, ssthresh=75
        t.num_replies_expected = 1;
        // First ack: received 1, expected 1 → cc_scale=1, slow start:
        // cwnd = 10 + 1*1*1 = 11.
        t.ack(&perf, 1.0);
        assert_eq!(t.cwnd, 11.0);
        assert_eq!(t.num_replies_received, 1);
    }

    #[test]
    fn cc_scale_boosts_when_replies_lag_expected() {
        let perf = PerfVars::new(TimingTemplate::Normal, 0, 0);
        let mut t = TimingVals::new_host(&perf); // cwnd=10 < ssthresh=75
                                                 // Expected far exceeds received → scale = expected/received, capped 50.
        t.num_replies_expected = 10;
        // received becomes 1 in ack → scale = min(10/1, 50) = 10.
        t.ack(&perf, 1.0);
        assert_eq!(t.cwnd, 20.0); // 10 + 1*10*1
    }

    #[test]
    fn cc_scale_is_capped_at_cc_scale_max() {
        let perf = PerfVars::new(TimingTemplate::Normal, 0, 0);
        let mut t = TimingVals::new_host(&perf);
        t.num_replies_expected = 1000; // ratio 1000/1 → capped at 50
        t.ack(&perf, 1.0);
        assert_eq!(t.cwnd, 60.0); // 10 + 1*50*1
    }

    #[test]
    fn congestion_avoidance_increment_is_small() {
        let perf = PerfVars::new(TimingTemplate::Normal, 0, 0);
        let mut t = TimingVals::with_cwnd(75, 75); // cwnd == ssthresh → CA mode
        t.num_replies_expected = 1;
        // CA: cwnd += ca_incr/cwnd * cc_scale = 1/75 * 1 ≈ 0.01333.
        t.ack(&perf, 1.0);
        assert!((t.cwnd - (75.0 + 1.0 / 75.0)).abs() < 1e-9);
    }

    #[test]
    fn ack_never_exceeds_max_cwnd() {
        let perf = PerfVars::new(TimingTemplate::Normal, 0, 50); // max_cwnd=50
        let mut t = TimingVals::with_cwnd(50, 75);
        t.num_replies_expected = 1000;
        t.ack(&perf, 1.0);
        assert_eq!(t.cwnd, 50.0); // clamped to max_cwnd
    }

    #[test]
    fn host_drop_resets_to_loss_window() {
        let perf = PerfVars::new(TimingTemplate::Normal, 0, 0);
        let mut t = TimingVals::with_cwnd(40, 75);
        t.drop(30, &perf);
        assert_eq!(t.cwnd, 1.0); // low_cwnd
        assert_eq!(t.ssthresh, 20); // max(30/1.5, 2) = 20
    }

    #[test]
    fn group_drop_is_gentler_than_host_drop() {
        let perf = PerfVars::new(TimingTemplate::Normal, 0, 0);
        let mut t = TimingVals::with_cwnd(40, 75);
        t.drop_group(30, &perf);
        assert_eq!(t.cwnd, 20.0); // max(1, 40/2.0) = 20, not reset to 1
        assert_eq!(t.ssthresh, 20); // max(30/1.5, 2) = 20
    }

    #[test]
    fn ssthresh_floor_is_two() {
        let perf = PerfVars::new(TimingTemplate::Normal, 0, 0);
        let mut t = TimingVals::with_cwnd(5, 75);
        t.drop(1, &perf); // 1/1.5 = 0.67 → floored to 2
        assert_eq!(t.ssthresh, 2);
    }

    #[test]
    fn cwnd_stays_at_least_one_so_ca_divide_is_safe() {
        // After a host drop cwnd == low_cwnd (>=1); a CA-mode ack then divides by
        // it. Prove no panic / no non-finite result across a long sequence.
        let perf = PerfVars::new(TimingTemplate::Normal, 0, 0);
        let mut t = TimingVals::new_host(&perf);
        t.num_replies_expected = 5;
        for i in 0..1000 {
            if i % 7 == 0 {
                // cwnd is bounded to [1, max_cwnd=300] here; a plain probe count.
                #[allow(clippy::cast_possible_truncation)]
                let in_flight = t.cwnd as u32;
                t.drop(in_flight, &perf);
            } else {
                t.ack(&perf, 1.0);
            }
            t.num_replies_expected = t.num_replies_expected.saturating_add(1);
            assert!(
                t.cwnd.is_finite() && t.cwnd >= 1.0,
                "cwnd invariant broken: {}",
                t.cwnd
            );
        }
    }
}
