//! Leveled diagnostic logging driven by `-v`/`-d` — the analog of nmap's
//! `o.verbose` / `o.debugging` (both `u8`, 0..=10). This is the developer- and
//! operator-facing troubleshooting facility, pulled forward **before** the
//! scan modules so every module built after it can emit leveled diagnostics
//! (kit retrospective habit #5: make the first hang diagnosable in minutes).
//!
//! Complements [`crate::trace`] (env-gated via `NMAP_RS_TRACE`, always
//! available — used by the differential harness where no args are passed).
//!
//! **Routing:** [`verbose!`](crate::verbose) and [`debug!`](crate::debug) write
//! to **stderr**, so raising verbosity never pollutes the stdout that the
//! differential harness compares. User-facing verbose *scan* output (nmap's
//! `-v` stdout lines) is the output module's job and is matched there; this
//! facility is for diagnostics.

use std::sync::OnceLock;

static LEVELS: OnceLock<Levels> = OnceLock::new();

#[derive(Clone, Copy)]
struct Levels {
    verbose: u8,
    debugging: u8,
}

/// Set the global verbosity/debugging levels once, at startup, from the parsed
/// [`crate::options::RunConfig`]. Only the first call takes effect; later calls
/// are ignored (levels are process-wide and fixed after arg parsing).
pub fn init(verbose: u8, debugging: u8) {
    let _ = LEVELS.set(Levels { verbose, debugging });
}

/// Current verbosity level (0 until [`init`] runs).
pub fn verbosity() -> u8 {
    LEVELS.get().map_or(0, |l| l.verbose)
}

/// Current debugging level (0 until [`init`] runs).
pub fn debugging() -> u8 {
    LEVELS.get().map_or(0, |l| l.debugging)
}

/// Emit a diagnostic line to stderr iff the current verbosity is at least
/// `$lvl`. Off by default (verbosity 0), so a plain run is silent on stderr.
#[macro_export]
macro_rules! verbose {
    ($lvl:expr, $($arg:tt)*) => {{
        if $crate::log::verbosity() >= $lvl {
            eprintln!("{}", format_args!($($arg)*));
        }
    }};
}

/// Emit a debug line to stderr iff the current debugging level is at least
/// `$lvl`. Prefixed so it is distinguishable from verbose output.
#[macro_export]
macro_rules! debug {
    ($lvl:expr, $($arg:tt)*) => {{
        if $crate::log::debugging() >= $lvl {
            eprintln!("[nmap-rs debug] {}", format_args!($($arg)*));
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: LEVELS is a process-global OnceLock; tests here avoid calling init()
    // so they don't race the global. The macros must compile and never panic
    // regardless of whether init() has run.
    #[test]
    fn levels_default_to_zero_and_macros_are_silent() {
        // Not initialized in this test process path → 0.
        assert_eq!(verbosity(), 0);
        assert_eq!(debugging(), 0);
        // Must compile and not panic; produce no output at level 0.
        verbose!(1, "should not print {}", 1);
        debug!(1, "should not print {}", 2);
    }
}
