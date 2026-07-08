//! TRACE — an env-gated phase logger, scaffolded on **day one** (kit retrospective
//! habit #5: in winlsof, tracing was added reactively at hang-fix step 4 of 5;
//! having it from the start makes the first hang diagnosable in minutes).
//!
//! Enable by setting the `NMAP_RS_TRACE` environment variable to any value. Output
//! goes to stderr so it never pollutes the scan output that the differential
//! harness diffs. Dependency-free by design (this crate is `forbid(unsafe_code)`
//! and keeps its trusted surface small).

use std::sync::OnceLock;

static ENABLED: OnceLock<bool> = OnceLock::new();

/// Whether TRACE logging is on (checked once, then cached).
pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var_os("NMAP_RS_TRACE").is_some())
}

/// Emit a trace line to stderr iff `NMAP_RS_TRACE` is set. Use for phase
/// boundaries and any potentially-blocking operation (the liveness-diagnosis path).
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {{
        if $crate::trace::enabled() {
            eprintln!("[nmap-rs TRACE] {}", format_args!($($arg)*));
        }
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn trace_macro_is_silent_by_default_and_never_panics() {
        // Must compile and run without panicking regardless of env state.
        crate::trace!("phase {} started with {} targets", "discovery", 3);
    }
}
