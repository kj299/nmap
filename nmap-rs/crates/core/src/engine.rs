//! Scan-engine scheduling — the pure decision core of nmap's `ultra_scan`
//! (`scan_engine.cc`), split from all I/O. This is the "brain" the async driver
//! (Milestone 2, `sys`) will call: given what has come back so far, it decides
//! **whether another probe may be launched now**, **which probe** that is, and
//! **when the host is finished** — driving the congestion window
//! ([`crate::congestion`]) and the RTT-timeout estimator ([`crate::timing`]).
//!
//! Three pieces, all pure:
//!   - [`HostScheduler`] — the per-host scheduler: the congestion gate
//!     `cwnd >= num_probes_active + 0.5` (nmap's `HostScanStats::sendOK`), the
//!     retransmission queue with a per-port try cap (`allowedTryno`), and the
//!     completion test.
//!   - [`GroupScheduler`] — the cross-host congestion window (`GroupScanStats`),
//!     bounding *total* probes in flight across a multi-host group.
//!   - [`RateLimiter`] — `--min-rate` / `--max-rate` pacing (`probeSent` +
//!     `sendOK`), expressed over integer-µs timestamps the driver supplies.
//!
//! Purity is the safety story: no sockets, no `Instant::now()`, so every
//! transition is a total function of (state, event) and is exhaustively testable.
//! The caller (the `sys` driver) owns the clock and feeds elapsed times in as
//! plain integers; this module never blocks or reaches for I/O.

use std::collections::VecDeque;

use crate::congestion::{PerfVars, TimingVals};
use crate::timing::{TimeoutInfo, TimingParams, TimingTemplate};

/// One outstanding probe: a port and which attempt this is (`0` = first try).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub port: u16,
    /// Attempt number, 0-based. `tryno + 1 == max_tries` is the last attempt.
    pub tryno: u32,
}

/// Per-host probe scheduler — the port of the scheduling subset of
/// `HostScanStats`. Drives one host's ports through the congestion-controlled
/// send/retransmit loop.
#[derive(Clone, Debug)]
pub struct HostScheduler {
    perf: PerfVars,
    params: TimingParams,
    /// Host congestion window.
    timing: TimingVals,
    /// Host RTT / probe-timeout estimator.
    to: TimeoutInfo,
    /// Total attempts allowed per port (`1 + max_retransmissions`).
    max_tries: u32,
    /// Ports not yet tried (each enters at `tryno 0`).
    fresh: VecDeque<u16>,
    /// Probes that timed out and need another attempt.
    retransmit: VecDeque<Probe>,
    /// Probes currently in flight (`num_probes_active`).
    active: u32,
    /// Ports that reached a definitive outcome (a reply, or exhausted retries).
    resolved: u32,
    /// Total ports to scan.
    total: u32,
}

impl HostScheduler {
    /// Build a scheduler for `ports` under a `-T` template. Congestion constants
    /// come from [`PerfVars::new`]; the per-port try cap and timeout bounds come
    /// from the template's [`TimingParams`].
    pub fn new(ports: &[u16], template: TimingTemplate) -> Self {
        let params = TimingParams::for_template(template);
        Self::with_params(ports, template, params, 0, 0)
    }

    /// Like [`new`](Self::new) but with explicit `--min-parallelism` /
    /// `--max-parallelism` (`0` = nmap default) feeding the congestion window.
    pub fn with_params(
        ports: &[u16],
        template: TimingTemplate,
        params: TimingParams,
        min_parallelism: u32,
        max_parallelism: u32,
    ) -> Self {
        let perf = PerfVars::new(template, min_parallelism, max_parallelism);
        let timing = TimingVals::new_host(&perf);
        let to = TimeoutInfo::new(&params);
        // At least one attempt; `max_retransmissions` additional tries.
        let max_tries = params.max_retransmissions.saturating_add(1);
        let total = u32::try_from(ports.len()).unwrap_or(u32::MAX);
        HostScheduler {
            perf,
            params,
            timing,
            to,
            max_tries,
            fresh: ports.iter().copied().collect(),
            retransmit: VecDeque::new(),
            active: 0,
            resolved: 0,
            total,
        }
    }

    /// Is there any probe waiting to be sent (fresh port or pending retransmit)?
    fn has_work(&self) -> bool {
        !self.fresh.is_empty() || !self.retransmit.is_empty()
    }

    /// May another probe be launched right now? The port of the congestion gate
    /// in `HostScanStats::sendOK`: the window must have room
    /// (`cwnd >= num_probes_active + 0.5`) **and** there must be work to do.
    /// (The wall-clock scan-delay / rate-limit gates are the driver's job.)
    pub fn may_send(&self) -> bool {
        self.timing.cwnd >= f64::from(self.active) + 0.5 && self.has_work()
    }

    /// Take the next probe to send, or `None` if the gate is closed or there is
    /// no work. Retransmits are preferred over fresh ports (as in nmap, pending
    /// retries drain before new ports open). Marks the probe in flight.
    pub fn next_probe(&mut self) -> Option<Probe> {
        if !self.may_send() {
            return None;
        }
        let probe = if let Some(p) = self.retransmit.pop_front() {
            p
        } else {
            // has_work() guaranteed a fresh port if the retransmit queue is empty.
            Probe {
                port: self.fresh.pop_front()?,
                tryno: 0,
            }
        };
        self.active = self.active.saturating_add(1);
        Some(probe)
    }

    /// Record a reply to an in-flight probe: the port is resolved, the RTT
    /// (`rtt_us`, microseconds) folds into the timeout estimate, and the
    /// congestion window grows (`ultra_timing_vals::ack`).
    pub fn on_reply(&mut self, _probe: Probe, rtt_us: i64) {
        debug_assert!(self.active > 0, "reply with no probe in flight");
        self.active = self.active.saturating_sub(1);
        // A resolution: expected grows whether or not it was a reply (drop path
        // grows it too), matching nmap's cc-scale accounting.
        self.timing.num_replies_expected = self.timing.num_replies_expected.saturating_add(1);
        self.timing.ack(&self.perf, 1.0);
        self.to.adjust(rtt_us, &self.params);
        self.resolved = self.resolved.saturating_add(1);
    }

    /// Record that an in-flight probe timed out: the congestion window drops
    /// (`ultra_timing_vals::drop`), and the port is re-queued for another attempt
    /// unless it has exhausted `max_tries`, in which case it resolves (no answer).
    pub fn on_timeout(&mut self, probe: Probe) {
        debug_assert!(self.active > 0, "timeout with no probe in flight");
        // `in_flight` for the drop is the count at detection (includes this one).
        let in_flight = self.active;
        self.active = self.active.saturating_sub(1);
        self.timing.num_replies_expected = self.timing.num_replies_expected.saturating_add(1);
        self.timing.drop(in_flight, &self.perf);

        if probe.tryno.saturating_add(1) < self.max_tries {
            self.retransmit.push_back(Probe {
                port: probe.port,
                tryno: probe.tryno.saturating_add(1),
            });
        } else {
            // Out of retries: the port is resolved with no response.
            self.resolved = self.resolved.saturating_add(1);
        }
    }

    /// The current per-probe timeout in microseconds (the estimator's `timeout`).
    pub fn probe_timeout_us(&self) -> i64 {
        self.to.timeout
    }

    /// Probes in flight right now.
    pub fn in_flight(&self) -> u32 {
        self.active
    }

    /// The current congestion window (probes).
    pub fn cwnd(&self) -> f64 {
        self.timing.cwnd
    }

    /// Ports that have reached a definitive outcome.
    pub fn resolved(&self) -> u32 {
        self.resolved
    }

    /// Is the host scan finished? Every port resolved and nothing left in flight
    /// or queued.
    pub fn is_done(&self) -> bool {
        self.active == 0 && !self.has_work() && self.resolved >= self.total
    }
}

/// Cross-host congestion control — the port of the scheduling subset of nmap's
/// `GroupScanStats`. When more than one host is still being scanned, a shared
/// **group** congestion window bounds the *total* probes in flight across all
/// hosts, so a large host group can't collectively overrun the network even
/// though each host's own window is small. Pure — the driver owns the clock.
#[derive(Clone, Debug)]
pub struct GroupScheduler {
    perf: PerfVars,
    timing: TimingVals,
    /// Total probes in flight across all hosts in the group.
    active: u32,
}

impl GroupScheduler {
    /// A fresh group window under a `-T` template (`cwnd = group_initial_cwnd`).
    pub fn new(template: TimingTemplate, min_parallelism: u32, max_parallelism: u32) -> Self {
        let perf = PerfVars::new(template, min_parallelism, max_parallelism);
        let timing = TimingVals::new_group(&perf);
        GroupScheduler {
            perf,
            timing,
            active: 0,
        }
    }

    /// May the group admit another probe right now? Mirrors the group congestion
    /// gate in `GroupScanStats::sendOK`: with fewer than two hosts still
    /// incomplete, the group defers entirely to per-host control (returns
    /// `true`); otherwise the group window must have room
    /// (`cwnd >= active + 0.5`). The wall-clock rate/pacing gates are the
    /// driver's job (see [`RateLimiter`]).
    pub fn may_admit(&self, incomplete_hosts: usize) -> bool {
        if incomplete_hosts < 2 {
            return true;
        }
        self.timing.cwnd >= f64::from(self.active) + 0.5
    }

    /// Account a probe launched into the group.
    pub fn on_send(&mut self) {
        self.active = self.active.saturating_add(1);
    }

    /// A reply resolved a probe somewhere in the group: free a slot and grow the
    /// group window.
    pub fn on_reply(&mut self) {
        self.active = self.active.saturating_sub(1);
        self.timing.num_replies_expected = self.timing.num_replies_expected.saturating_add(1);
        self.timing.ack(&self.perf, 1.0);
    }

    /// A probe in the group timed out: free the slot and drop the group window —
    /// **gently** (`drop_group`, `cwnd /= 2`), so one host's loss doesn't stall
    /// the whole group.
    pub fn on_timeout(&mut self) {
        let in_flight = self.active;
        self.active = self.active.saturating_sub(1);
        self.timing.num_replies_expected = self.timing.num_replies_expected.saturating_add(1);
        self.timing.drop_group(in_flight, &self.perf);
    }

    /// Probes in flight across the group.
    pub fn in_flight(&self) -> u32 {
        self.active
    }

    /// The group congestion window (probes).
    pub fn cwnd(&self) -> f64 {
        self.timing.cwnd
    }
}

/// What the [`RateLimiter`] says about sending a probe at a given instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateVerdict {
    /// `--max-rate` says it's too soon; don't send until the returned time (µs
    /// since scan start).
    TooEarly(i64),
    /// `--min-rate` says we're behind schedule; send now regardless of the
    /// congestion window.
    MustSend,
    /// No rate constraint forces the decision; defer to congestion control.
    Ok,
}

/// Send-rate pacing — the port of the `--min-rate` / `--max-rate` bookkeeping in
/// `GroupScanStats::probeSent` + `sendOK`. Pure: all times are integer
/// microseconds relative to scan start; the driver supplies "now".
///
/// `--max-rate` spaces sends at least `1e6 / rate` µs apart (the threshold may
/// slip into the past so bursts can catch up). `--min-rate` forces a send once
/// the schedule falls behind. Absent either flag the corresponding path is inert.
#[derive(Clone, Copy, Debug)]
pub struct RateLimiter {
    /// Minimum µs between sends for `--max-rate` (`0` = no max-rate).
    max_rate_add: i64,
    /// Scheduling interval for `--min-rate` (`0` = no min-rate).
    min_rate_add: i64,
    /// Earliest next send (µs since start); only meaningful with `--max-rate`.
    send_no_earlier_than: i64,
    /// Latest next send (µs since start); only meaningful with `--min-rate`.
    send_no_later_than: i64,
}

impl RateLimiter {
    /// Build from optional `--min-rate` / `--max-rate` (probes per second). A
    /// non-positive or non-finite rate is treated as "unset".
    pub fn new(min_rate: Option<f64>, max_rate: Option<f64>) -> Self {
        RateLimiter {
            max_rate_add: rate_interval_us(max_rate),
            min_rate_add: rate_interval_us(min_rate),
            send_no_earlier_than: 0,
            send_no_later_than: 0,
        }
    }

    /// Whether any rate flag is active (else this limiter is a no-op).
    pub fn is_active(&self) -> bool {
        self.max_rate_add != 0 || self.min_rate_add != 0
    }

    /// Advance the schedule after a probe is sent at `now_us` — the port of
    /// `probeSent`.
    pub fn record_send(&mut self, now_us: i64) {
        if self.max_rate_add != 0 {
            // May slip into the past so the scheduler can catch up to max rate.
            self.send_no_earlier_than = self.send_no_earlier_than.saturating_add(self.max_rate_add);
        }
        if self.min_rate_add != 0 {
            // Pull a future deadline back to now so slack can't lower the rate.
            if self.send_no_later_than > now_us {
                self.send_no_later_than = now_us;
            }
            self.send_no_later_than = self.send_no_later_than.saturating_add(self.min_rate_add);
        }
    }

    /// The pacing verdict at `now_us` — the port of the rate branches of
    /// `sendOK`. `--max-rate` too-early wins over everything; then `--min-rate`
    /// behind-schedule forces a send; otherwise defer to congestion control.
    pub fn verdict(&self, now_us: i64) -> RateVerdict {
        if self.max_rate_add != 0 && self.send_no_earlier_than > now_us {
            return RateVerdict::TooEarly(self.send_no_earlier_than);
        }
        if self.min_rate_add != 0 && self.send_no_later_than <= now_us {
            return RateVerdict::MustSend;
        }
        RateVerdict::Ok
    }
}

/// `1e6 / rate` µs as an `i64`, or `0` for an unset / invalid rate. Bounded and
/// finite by construction, so no truncating cast can wrap.
fn rate_interval_us(rate: Option<f64>) -> i64 {
    match rate {
        Some(r) if r.is_finite() && r > 0.0 => {
            let us = (1_000_000.0 / r).round();
            if us >= i64::MAX as f64 {
                i64::MAX
            } else if us < 1.0 {
                // Sub-microsecond spacing: at least 1 µs so the interval is real.
                1
            } else {
                // In [1, i64::MAX) and finite — exact integer part, no wrap.
                #[allow(clippy::cast_possible_truncation)]
                let v = us as i64;
                v
            }
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sched(nports: u16) -> HostScheduler {
        let ports: Vec<u16> = (1..=nports).collect();
        HostScheduler::new(&ports, TimingTemplate::Normal)
    }

    #[test]
    fn gate_opens_up_to_cwnd_then_closes() {
        // Default host cwnd is 10 (box(1,300,10)); the gate allows floor(cwnd-0.5)
        // = 10 probes in flight before it closes.
        let mut s = sched(50);
        let mut sent = 0;
        while let Some(_p) = s.next_probe() {
            sent += 1;
            if sent > 100 {
                break;
            }
        }
        assert_eq!(sent, 10, "cwnd=10 gate should allow exactly 10 in flight");
        assert_eq!(s.in_flight(), 10);
        assert!(!s.may_send(), "gate closed at cwnd");
    }

    #[test]
    fn reply_frees_a_slot_and_grows_cwnd() {
        let mut s = sched(50);
        s.timing_expected_seed();
        let p = s.next_probe().unwrap();
        let before = s.cwnd();
        s.on_reply(p, 5_000);
        assert_eq!(s.in_flight(), 0);
        assert!(s.cwnd() > before, "ack grows cwnd in slow start");
        assert_eq!(s.resolved(), 1);
    }

    #[test]
    fn timeout_requeues_until_tries_exhausted_then_resolves() {
        // One port, exercise the whole retransmit ladder.
        let mut s = HostScheduler::new(&[80], TimingTemplate::Normal);
        let max = s.max_tries;
        assert!(max >= 1);
        let mut seen_trynos = Vec::new();
        for _ in 0..max {
            let p = s.next_probe().expect("a probe should be available");
            seen_trynos.push(p.tryno);
            s.on_timeout(p);
        }
        // Attempts were tryno 0,1,2,... up to max-1.
        assert_eq!(seen_trynos, (0..max).collect::<Vec<_>>());
        // After the last try times out, the port resolves and the host is done.
        assert!(s.next_probe().is_none());
        assert_eq!(s.resolved(), 1);
        assert!(s.is_done());
    }

    #[test]
    fn a_drop_collapses_the_window() {
        let mut s = sched(50);
        // Fill the window, then time one out — cwnd must collapse to low_cwnd.
        let mut probes = Vec::new();
        while let Some(p) = s.next_probe() {
            probes.push(p);
        }
        assert_eq!(s.in_flight(), 10);
        s.on_timeout(probes[0]);
        assert_eq!(s.cwnd(), 1.0, "host drop resets cwnd to low_cwnd");
        // Window is now 1 while 9 are still active → gate stays shut.
        assert!(!s.may_send());
    }

    #[test]
    fn full_scan_of_all_replies_resolves_every_port() {
        let mut s = sched(25);
        let mut guard = 0;
        while !s.is_done() {
            guard += 1;
            assert!(guard < 10_000, "scheduler failed to converge");
            if let Some(p) = s.next_probe() {
                s.on_reply(p, 4_000);
            }
        }
        assert_eq!(s.resolved(), 25);
        assert_eq!(s.in_flight(), 0);
    }

    #[test]
    fn mixed_replies_and_timeouts_still_converge() {
        // Every other probe times out (and retransmits) — must still finish with
        // every port resolved, no underflow/overflow, bounded steps.
        let mut s = sched(30);
        let mut i = 0u32;
        let mut guard = 0;
        while !s.is_done() {
            guard += 1;
            assert!(guard < 1_000_000, "did not converge");
            if let Some(p) = s.next_probe() {
                if i % 2 == 0 {
                    s.on_timeout(p);
                } else {
                    s.on_reply(p, 3_000);
                }
                i = i.wrapping_add(1);
            }
        }
        assert_eq!(s.resolved(), 30);
        assert!(s.in_flight() == 0);
    }

    #[test]
    fn probe_timeout_starts_at_template_initial() {
        let s = sched(1);
        // -T3 initial RTT timeout is 1000 ms = 1_000_000 µs.
        assert_eq!(s.probe_timeout_us(), 1_000_000);
    }

    #[test]
    fn empty_port_set_is_immediately_done() {
        let s = HostScheduler::new(&[], TimingTemplate::Normal);
        assert!(s.is_done());
        assert_eq!(s.resolved(), 0);
    }

    // Test helper: seed a small expected count so cc_scale has a defined ratio.
    impl HostScheduler {
        fn timing_expected_seed(&mut self) {
            self.timing.num_replies_expected = 1;
        }
    }

    // ---- GroupScheduler ----

    #[test]
    fn group_defers_to_host_below_two_incomplete_hosts() {
        let mut g = GroupScheduler::new(TimingTemplate::Normal, 0, 0);
        // Saturate the group window well past cwnd.
        for _ in 0..100 {
            g.on_send();
        }
        // With 0 or 1 incomplete hosts, the group never blocks (host control runs).
        assert!(g.may_admit(0));
        assert!(g.may_admit(1));
        // With 2+, the (now overfull) window blocks.
        assert!(!g.may_admit(2));
    }

    #[test]
    fn group_gate_bounds_total_in_flight_at_cwnd() {
        let mut g = GroupScheduler::new(TimingTemplate::Normal, 0, 0); // group cwnd 10
        let mut admitted = 0;
        while g.may_admit(5) {
            g.on_send();
            admitted += 1;
            if admitted > 100 {
                break;
            }
        }
        assert_eq!(admitted, 10, "group cwnd=10 bounds total in flight");
        assert_eq!(g.in_flight(), 10);
    }

    #[test]
    fn group_drop_is_gentle_not_a_reset() {
        let mut g = GroupScheduler::new(TimingTemplate::Normal, 0, 0);
        for _ in 0..10 {
            g.on_send();
        }
        g.on_timeout(); // drop_group: cwnd 10 -> max(1, 10/2) = 5
        assert_eq!(g.cwnd(), 5.0);
        assert_eq!(g.in_flight(), 9);
    }

    // ---- RateLimiter ----

    #[test]
    fn no_rate_flags_is_inert() {
        let r = RateLimiter::new(None, None);
        assert!(!r.is_active());
        assert_eq!(r.verdict(0), RateVerdict::Ok);
        assert_eq!(r.verdict(1_000_000), RateVerdict::Ok);
    }

    #[test]
    fn max_rate_spaces_sends_apart() {
        // 1000 probes/sec → 1000 µs spacing.
        let mut r = RateLimiter::new(None, Some(1000.0));
        assert!(r.is_active());
        // At start, sending is allowed.
        assert_eq!(r.verdict(0), RateVerdict::Ok);
        r.record_send(0); // next-earliest advances to 1000 µs
        match r.verdict(500) {
            RateVerdict::TooEarly(t) => assert_eq!(t, 1000),
            v => panic!("expected TooEarly, got {v:?}"),
        }
        // At/after the interval it's allowed again.
        assert_eq!(r.verdict(1000), RateVerdict::Ok);
    }

    #[test]
    fn min_rate_forces_a_send_when_behind() {
        // 100 probes/sec → 10_000 µs interval.
        let mut r = RateLimiter::new(Some(100.0), None);
        // send_no_later_than starts at 0; at now=0 it's <= now → MustSend.
        assert_eq!(r.verdict(0), RateVerdict::MustSend);
        r.record_send(0); // deadline pulled to 0 then +10_000 → 10_000
        assert_eq!(r.verdict(5_000), RateVerdict::Ok); // ahead of schedule
        assert_eq!(r.verdict(10_000), RateVerdict::MustSend); // deadline reached
    }

    #[test]
    fn max_rate_too_early_takes_precedence_over_min() {
        // A (nonsensical but valid) window where max spacing exceeds min interval.
        let mut r = RateLimiter::new(Some(100.0), Some(1000.0));
        r.record_send(0); // no_earlier=1000, no_later pulled to 0 then +10_000
                          // now=500: max says too-early (500 < 1000) → TooEarly wins over any min.
        assert_eq!(r.verdict(500), RateVerdict::TooEarly(1000));
    }

    #[test]
    fn rate_interval_handles_edges() {
        assert_eq!(rate_interval_us(None), 0);
        assert_eq!(rate_interval_us(Some(0.0)), 0);
        assert_eq!(rate_interval_us(Some(-5.0)), 0);
        assert_eq!(rate_interval_us(Some(f64::NAN)), 0);
        assert_eq!(rate_interval_us(Some(1000.0)), 1000);
        // Absurdly high rate → sub-µs spacing floored to 1 µs, never 0.
        assert_eq!(rate_interval_us(Some(1e12)), 1);
    }
}
