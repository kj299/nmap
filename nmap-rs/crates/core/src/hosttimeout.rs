//! The per-host timeout clock: `--host-timeout`'s stopwatch.
//!
//! A port of `Target::startTimeOutClock`, `stopTimeOutClock` and `timedOut`
//! (`Target.cc:420-453`, the `host_timeout_nfo` of `Target.h`). Each target
//! carries one. Each phase that works on the host starts it, and stops it when
//! the host is done or out of time, so the budget is spent only while the host
//! is being worked on: not between phases, and not while other groups are
//! scanned (`docs/M7-CUTOVER-ANALYSIS.md` §2).
//!
//! The arithmetic is C's, so a verdict near the boundary is the same:
//!
//! * time is a `struct timeval`, seconds and microseconds ([`Timeval`]);
//! * an interval is `TIMEVAL_MSEC_SUBTRACT` (`nbase/nbase.h:191`): whole
//!   seconds times 1,000 plus the microsecond difference divided by 1,000,
//!   truncated toward zero ([`msec_subtract`]);
//! * the milliseconds used accumulate over every start/stop pair, each
//!   truncated on its own;
//! * a host is out of time when the milliseconds used, the running interval
//!   included, are **strictly greater** than the budget; a budget of 0 means
//!   none.
//!
//! The time source is the caller's: this module never reads a clock, so it is
//! tested, and Miri-checked, with any times at all.
//!
//! ## Scope / divergences
//!
//! * C asserts that the clock is not started twice or stopped while stopped.
//!   Here both are no-ops: an engine that would trip the assertion keeps the
//!   first start, and a stray stop changes nothing. Neither path is reachable
//!   from the engines, which start a host's clock once per phase.
//! * C's milliseconds are `unsigned long`, so an interval that came out negative
//!   (a wall clock stepped back between start and stop) would wrap to a huge
//!   value and time the host out at once. The port's engines read a monotonic
//!   clock, so the interval cannot be negative; if one is, it counts as 0, and
//!   the sums saturate rather than wrap.

/// A point in time as C's `struct timeval` holds it: seconds and microseconds.
///
/// Only differences between two of these matter, so the epoch is the caller's:
/// the engines measure from the start of the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Timeval {
    /// Whole seconds (`tv_sec`).
    pub sec: i64,
    /// Microseconds within the second, 0 to 999,999 (`tv_usec`).
    pub usec: i64,
}

impl Timeval {
    /// The time `micros` microseconds after the epoch, split as a `timeval`.
    /// A negative count is taken as 0.
    #[must_use]
    pub fn from_micros(micros: i64) -> Self {
        let m = micros.max(0);
        Timeval {
            sec: m / 1_000_000,
            usec: m % 1_000_000,
        }
    }
}

/// `TIMEVAL_MSEC_SUBTRACT(a, b)` (`nbase/nbase.h:191`): the milliseconds from
/// `b` to `a`, as `(a.sec - b.sec) * 1000 + (a.usec - b.usec) / 1000`, the
/// division truncating toward zero. So 1.000999 s to 2.000000 s is 1,000 ms,
/// not 999: the microsecond part, -999, divides to 0.
#[must_use]
pub fn msec_subtract(a: Timeval, b: Timeval) -> i64 {
    let secs = a.sec.saturating_sub(b.sec).saturating_mul(1000);
    let usecs = a.usec.saturating_sub(b.usec) / 1000;
    secs.saturating_add(usecs)
}

/// One host's timeout clock (`struct host_timeout_nfo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HostClock {
    /// The budget in milliseconds (`o.host_timeout`); 0 is none.
    budget_ms: u64,
    /// Milliseconds used over every interval stopped so far (`msecs_used`).
    used_ms: u64,
    /// When the running interval began (`toclock_start`), if it is running.
    running_since: Option<Timeval>,
    /// The second the clock was first started (`host_start`), for the XML
    /// `starttime`.
    host_start: Option<i64>,
    /// The second the clock was last stopped (`host_end`), for the XML
    /// `endtime`.
    host_end: Option<i64>,
}

impl HostClock {
    /// A stopped clock with nothing used, against a budget of `budget_ms`
    /// milliseconds (`--host-timeout`); 0 is no budget, under which the host
    /// never times out.
    #[must_use]
    pub fn new(budget_ms: u64) -> Self {
        HostClock {
            budget_ms,
            ..HostClock::default()
        }
    }

    /// The budget this clock was made with, in milliseconds.
    #[must_use]
    pub fn budget_ms(&self) -> u64 {
        self.budget_ms
    }

    /// `startTimeOutClock`: start an interval at `now`. The first start also
    /// records the host's start time. Starting a running clock changes nothing
    /// (C asserts it is stopped).
    pub fn start(&mut self, now: Timeval) {
        if self.running_since.is_some() {
            return;
        }
        self.running_since = Some(now);
        if self.host_start.is_none() {
            self.host_start = Some(now.sec);
        }
    }

    /// `stopTimeOutClock`: end the running interval at `now`, adding its
    /// milliseconds to those used, and record the host's end time. Stopping a
    /// stopped clock changes nothing (C asserts it is running).
    pub fn stop(&mut self, now: Timeval) {
        let Some(since) = self.running_since.take() else {
            return;
        };
        self.used_ms = self.used_ms.saturating_add(interval_ms(now, since));
        self.host_end = Some(now.sec);
    }

    /// Whether the clock is running (`timeOutClockRunning`).
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running_since.is_some()
    }

    /// The milliseconds used by `now`: every stopped interval, and the running
    /// one up to `now`.
    #[must_use]
    pub fn used_ms(&self, now: Timeval) -> u64 {
        match self.running_since {
            Some(since) => self.used_ms.saturating_add(interval_ms(now, since)),
            None => self.used_ms,
        }
    }

    /// `timedOut`: whether the host has used more than its budget by `now`.
    /// Strictly more: a host that has used exactly its budget is still in time.
    /// With no budget, never.
    #[must_use]
    pub fn timed_out(&self, now: Timeval) -> bool {
        self.budget_ms != 0 && self.used_ms(now) > self.budget_ms
    }

    /// The time from `now` until the host would time out, in microseconds,
    /// if its clock is running and it has a budget: the moment its used
    /// milliseconds pass the budget. `None` when it cannot time out from here
    /// (no budget, or the clock is stopped). An engine sleeps no later than
    /// this so the deadline is kept (decision D4).
    #[must_use]
    pub fn micros_until_timeout(&self, now: Timeval) -> Option<i64> {
        let since = self.running_since?;
        if self.budget_ms == 0 {
            return None;
        }
        if self.timed_out(now) {
            return Some(0);
        }
        // The first instant at which used > budget: budget + 1 whole
        // milliseconds into the interval, less what was used before it. The
        // truncation of `msec_subtract` means that is at least that many
        // milliseconds after `since`, so waking then and checking is enough.
        let before = i64::try_from(self.used_ms).unwrap_or(i64::MAX);
        let budget = i64::try_from(self.budget_ms).unwrap_or(i64::MAX);
        let left_ms = budget.saturating_add(1).saturating_sub(before).max(0);
        let elapsed_us = micros_between(now, since);
        Some(
            left_ms
                .saturating_mul(1000)
                .saturating_sub(elapsed_us)
                .max(0),
        )
    }

    /// The second the clock was first started (`StartTime`), if ever.
    #[must_use]
    pub fn start_time(&self) -> Option<i64> {
        self.host_start
    }

    /// The second the clock was last stopped (`EndTime`), if ever.
    #[must_use]
    pub fn end_time(&self) -> Option<i64> {
        self.host_end
    }
}

/// An interval's milliseconds as C adds them to `msecs_used`; one that comes
/// out negative counts as 0 (see the module's divergences).
fn interval_ms(now: Timeval, since: Timeval) -> u64 {
    u64::try_from(msec_subtract(now, since)).unwrap_or(0)
}

/// The exact microseconds from `since` to `now`, for scheduling a wake-up.
fn micros_between(now: Timeval, since: Timeval) -> i64 {
    now.sec
        .saturating_sub(since.sec)
        .saturating_mul(1_000_000)
        .saturating_add(now.usec.saturating_sub(since.usec))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(sec: i64, usec: i64) -> Timeval {
        Timeval { sec, usec }
    }

    /// `TIMEVAL_MSEC_SUBTRACT`'s truncation, both signs of the microsecond part.
    #[test]
    fn intervals_truncate_as_c_does() {
        assert_eq!(msec_subtract(at(2, 0), at(1, 0)), 1000);
        assert_eq!(msec_subtract(at(1, 999), at(1, 0)), 0);
        assert_eq!(msec_subtract(at(1, 1999), at(1, 0)), 1);
        // -999 µs divides to 0, toward zero: 1,000, not 999.
        assert_eq!(msec_subtract(at(2, 0), at(1, 999)), 1000);
        // -1,000 µs divides to -1: 999.
        assert_eq!(msec_subtract(at(2, 0), at(1, 1000)), 999);
        assert_eq!(Timeval::from_micros(2_000_999), at(2, 999));
        assert_eq!(Timeval::from_micros(-5), at(0, 0));
    }

    /// No budget never times out, however long the clock runs.
    #[test]
    fn a_zero_budget_is_none() {
        let mut c = HostClock::new(0);
        c.start(at(0, 0));
        assert!(!c.timed_out(at(1_000_000, 0)));
        assert_eq!(c.micros_until_timeout(at(5, 0)), None);
    }

    /// Strictly greater: exactly the budget is in time, one millisecond more is
    /// not.
    #[test]
    fn the_budget_is_exceeded_only_past_it() {
        let mut c = HostClock::new(1000);
        c.start(at(10, 0));
        assert!(!c.timed_out(at(11, 0)), "1,000 ms of 1,000 is in time");
        assert!(!c.timed_out(at(11, 999)), "still 1,000 ms by truncation");
        assert!(c.timed_out(at(11, 1000)), "1,001 ms");
    }

    /// The milliseconds used accumulate over intervals, each truncated on its
    /// own, and a stopped clock spends nothing.
    #[test]
    fn intervals_accumulate_and_a_stopped_clock_spends_nothing() {
        let mut c = HostClock::new(10);
        // Three intervals of 3.9 ms each: 3 ms apiece, 9 in all, not 11.7.
        for k in 0..3 {
            c.start(at(k, 0));
            c.stop(at(k, 3900));
        }
        assert_eq!(c.used_ms(at(100, 0)), 9);
        assert!(
            !c.timed_out(at(100, 0)),
            "stopped: the hour between counts nothing"
        );
        c.start(at(200, 0));
        assert!(!c.timed_out(at(200, 1999)), "9 + 1 = 10, not past 10");
        assert!(c.timed_out(at(200, 2000)), "9 + 2 = 11");
        assert!(c.is_running());
    }

    /// Start and end times are the first start's second and the last stop's.
    #[test]
    fn start_and_end_times_are_the_first_start_and_last_stop() {
        let mut c = HostClock::new(0);
        assert_eq!((c.start_time(), c.end_time()), (None, None));
        c.start(at(5, 500));
        c.stop(at(6, 0));
        c.start(at(9, 0));
        c.stop(at(12, 1));
        assert_eq!((c.start_time(), c.end_time()), (Some(5), Some(12)));
    }

    /// A second start keeps the first; a stray stop changes nothing.
    #[test]
    fn a_double_start_or_stray_stop_changes_nothing() {
        let mut c = HostClock::new(100);
        c.stop(at(1, 0));
        assert_eq!(c, HostClock::new(100));
        c.start(at(1, 0));
        c.start(at(50, 0));
        assert_eq!(c.used_ms(at(1, 50_000)), 50, "timed from the first start");
    }

    /// An interval that comes out negative counts as nothing, and sums saturate.
    #[test]
    fn a_backward_interval_counts_as_nothing() {
        let mut c = HostClock::new(1);
        c.start(at(10, 0));
        c.stop(at(9, 0));
        assert_eq!(c.used_ms(at(0, 0)), 0);
        let mut big = HostClock::new(u64::MAX);
        big.start(at(0, 0));
        assert!(!big.timed_out(at(i64::MAX, 0)));
    }

    /// The wake-up time is when the host would first be out of time, and the
    /// host is out of time then and not before.
    #[test]
    fn the_wake_up_is_the_deadline() {
        let mut c = HostClock::new(1000);
        c.stop(at(0, 0));
        assert_eq!(c.micros_until_timeout(at(0, 0)), None, "stopped");
        c.start(at(3, 0));
        c.stop(at(3, 400_000)); // 400 ms used
        c.start(at(7, 0));
        let wait = c.micros_until_timeout(at(7, 100_000)).unwrap();
        // 601 ms into this interval is 1,001 ms in all: 501 ms from now.
        assert_eq!(wait, 501_000);
        let deadline = Timeval::from_micros(7_100_000 + wait);
        assert!(c.timed_out(deadline));
        assert!(!c.timed_out(Timeval::from_micros(7_100_000 + wait - 1000)));
        assert_eq!(c.micros_until_timeout(deadline), Some(0));
    }
}
