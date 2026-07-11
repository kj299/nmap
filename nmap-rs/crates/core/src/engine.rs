//! Scan-engine scheduling — the pure decision core of nmap's `ultra_scan`
//! (`scan_engine.cc`), split from all I/O. This is the "brain" the async driver
//! (Milestone 2, `sys`) will call: given what has come back so far, it decides
//! **whether another probe may be launched now**, **which probe** that is, and
//! **when the host is finished** — driving the congestion window
//! ([`crate::congestion`]) and the RTT-timeout estimator ([`crate::timing`]).
//!
//! Milestone-2 scope: the **per-host** scheduler for the connect path. It owns
//! the congestion gate `cwnd >= num_probes_active + 0.5` (nmap's
//! `HostScanStats::sendOK`), the retransmission queue with a per-port try cap
//! (`allowedTryno`), and the completion test. The **group**-level scheduler
//! (cross-host `cwnd` bounding, min-rate pacing) and the wall-clock scan-delay /
//! rate-limit paths live with the driver in the next slice — they need a clock,
//! which this pure module deliberately does not have.
//!
//! Purity is the safety story: no sockets, no `Instant::now()`, so every
//! transition is a total function of (state, event) and is exhaustively testable.
//! The caller supplies elapsed times as plain integers.

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
}
