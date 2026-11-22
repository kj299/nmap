//! The time `--host-timeout` clocks are read with (`core::hosttimeout`).
//!
//! One monotonic epoch for the whole process, so a host's clock, started by
//! one phase and stopped by another, measures every interval against the same
//! origin. Monotonic, so an interval cannot come out negative, which a wall
//! clock stepped back between a start and a stop could make it (the divergence
//! `core::hosttimeout` notes).

use std::sync::OnceLock;
use std::time::Instant;

use nmap_core::hosttimeout::Timeval;

/// The epoch: the first time any clock was read.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Now, as a `timeval` since the epoch.
#[must_use]
pub fn now() -> Timeval {
    let micros = i64::try_from(epoch().elapsed().as_micros()).unwrap_or(i64::MAX);
    Timeval::from_micros(micros)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_does_not_go_back() {
        let a = now();
        let b = now();
        assert!(b >= a);
    }
}
