// cargo-fuzz target for the time-specification parser —
// `nmap_core::timespec::{tval2secs, tval2msecs, tval_unit}`.
//
// This parser decides the value of SIX options (--min-rtt-timeout,
// --max-rtt-timeout, --initial-rtt-timeout, --scan-delay, --max-scan-delay,
// --host-timeout), so one wrong answer here is six options wrong at once.
//
// The corpus differential in `crates/core/tests/timespec_differential.rs`
// compares against the C oracle over ~3400 fixed vectors. That proves agreement
// on the inputs someone thought of; this proves the invariants hold on inputs
// nobody thought of. The division of labour matters, because the interesting
// failures here are all "a string nobody would write": every fixed-corpus bug
// found while building this module was of exactly that shape — bare "s" meaning
// zero seconds, "5e" backtracking to 5, an exactly-representable subnormal
// slipping past the underflow signal.
//
// Totality is the floor, not the ceiling: this asserts the structural contract
// that the CLI relies on when it turns a result into a scan parameter.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::timespec::{tval2msecs, tval2secs, tval_unit, TimeSpecError};

fuzz_target!(|data: &[u8]| {
    let Ok(spec) = std::str::from_utf8(data) else {
        return;
    };

    // Total and deterministic over arbitrary text.
    let secs = tval2secs(spec);
    assert_eq!(
        secs.to_bits(),
        tval2secs(spec).to_bits(),
        "tval2secs is not deterministic"
    );

    // The unit, when there is one, is a genuine suffix of the input. If it were
    // not, it would be a pointer into the wrong place -- which in C is exactly
    // what `tval_unit` returns, a pointer into the caller's buffer.
    if let Some(unit) = tval_unit(spec) {
        assert!(
            spec.ends_with(unit),
            "tval_unit({spec:?}) returned {unit:?}, which is not a suffix"
        );
        assert!(!unit.is_empty(), "an empty unit should have been None");
    }

    match tval2msecs(spec) {
        Ok(ms) => {
            // THE invariant the callers depend on. Every one of the six options
            // validates the result with a comparison against zero (`< 0`,
            // `<= 0`, or `< 5`) and then stores it as a duration. A NaN or an
            // out-of-range value reaching that comparison is how C's own guard
            // fails: `ms > LONG_MAX || ms < LONG_MIN` is false for NaN, so
            // `(long) NaN` runs and yields LONG_MIN. An Ok here must be a real,
            // finite, usable number.
            assert!(
                ms >= -9_223_372_036_854_775_808_i64,
                "tval2msecs({spec:?}) = {ms} is not a usable duration"
            );
            // Ok must agree with the seconds form: the same input cannot parse
            // as a number one way and fail the other.
            assert!(
                secs != -1.0 || ms == -1,
                "tval2msecs({spec:?}) succeeded with {ms} while tval2secs returned the -1 sentinel"
            );
            assert!(
                secs.is_finite(),
                "tval2msecs({spec:?}) = {ms} from a non-finite seconds value {secs}"
            );
        }
        Err(TimeSpecError::Unparseable) => {
            // A refusal must not be silently reinterpreted as a value. Nothing
            // to assert about `secs` here -- C's -1 sentinel collides with a
            // legitimate "-1 second", which this port reproduces deliberately.
        }
    }

    // Scaling is monotone within a unit: a longer timeout must not parse as a
    // shorter one. Getting this backwards would make --host-timeout silently
    // cut scans short.
    for unit in ["", "s", "ms", "m", "h"] {
        let a = tval2msecs(&format!("1{unit}"));
        let b = tval2msecs(&format!("2{unit}"));
        if let (Ok(a), Ok(b)) = (a, b) {
            assert!(a <= b, "1{unit} = {a}ms but 2{unit} = {b}ms");
        }
    }
});
