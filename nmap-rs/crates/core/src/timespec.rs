//! Time specifications — nmap's `tval2secs` / `tval2msecs` / `tval_unit`.
//!
//! This is the shared parser behind six of the options M7.7 implements:
//! `--min-rtt-timeout`, `--max-rtt-timeout`, `--initial-rtt-timeout`,
//! `--scan-delay`, `--max-scan-delay` and `--host-timeout`. Getting it wrong
//! gets six options wrong at once, which is why it is ported against a verbatim
//! C oracle (`tests/differential/m7/oracle/tval_oracle.c`) rather than from a
//! reading of the C.
//!
//! # Why this is not "parse a number and a suffix"
//!
//! The number is parsed by C's `strtod`, and `strtod` accepts a great deal more
//! than a plain decimal. All of these are real, accepted inputs to `nmap`:
//!
//! ```text
//! 0x10        16 seconds      (hex literal)
//! 0x1p10      1024 seconds    (hex with a binary exponent)
//! 1e3ms       1 second        (decimal exponent, then a unit)
//! +5          5 seconds       (leading sign)
//! "  5"       5 seconds       (leading whitespace)
//! 5MS         5 milliseconds  (units are case-insensitive)
//! 5H          5 hours
//! ```
//!
//! and these are rejected, for reasons that are not obvious either:
//!
//! ```text
//! "5 ms"      the space is part of the tail, which must match a unit exactly
//! 5e          strtod backtracks to "5", leaving the tail "e", which is no unit
//! 5.5.5       backtracks to "5.5", tail ".5"
//! 1e-400      underflow sets ERANGE, which the C treats as unparseable
//! 1e309       overflow, likewise
//! ```
//!
//! A hand-written "digits, then an optional suffix" would accept the second
//! list and reject the first, and no amount of plausible-looking test data
//! would have revealed it. The fuzz target `timespec` cross-checks this module
//! against the C oracle over arbitrary bytes.
//!
//! # The two places this deliberately does NOT match C
//!
//! `tval2msecs` guards its `double`→`long` conversion with
//!
//! ```c
//! if (ms > LONG_MAX || ms < LONG_MIN)
//!     return -1;
//! return (long) ms;
//! ```
//!
//! which is wrong twice, and both are reachable from the command line:
//!
//! 1. **NaN passes the guard.** Every comparison with NaN is false, so
//!    `--host-timeout nan` falls through to `(long) NaN` — undefined behaviour.
//!    On x86-64 it yields `LONG_MIN`.
//! 2. **`LONG_MAX` is not representable as a `double`.** It converts to 2^63,
//!    so `ms == 2^63` is not *greater than* `LONG_MAX` and also falls through
//!    to a conversion that overflows. `--host-timeout 9223372036854775.808`
//!    reaches it; again `LONG_MIN` in practice.
//!
//! Both were confirmed by running the oracle, not inferred:
//!
//! ```text
//! $ printf '%s\0' nan 9223372036854775.808 | ./tval_oracle
//! nan                     -9223372036854775808    (null)
//! 9223372036854776        -9223372036854775808    (null)
//! ```
//!
//! This port returns [`TimeSpecError::Unparseable`] for both. That is a
//! divergence in the returned *number* and not in any observable behaviour:
//! all six callers reject a negative (`< 0`, `<= 0`, or `< 5`), so C's
//! `LONG_MIN` and this port's error both end as the same refusal. Mirroring the
//! UB would mean reproducing a bug to preserve a value nothing can observe.
//! Recorded in `DIVERGENCES.md`.

/// Why a time specification could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeSpecError {
    /// The string is not a number followed by an optional known unit — C's
    /// `-1` return. This also covers overflow and underflow, which set `errno`
    /// and which C treats as unparseable rather than as a clamp.
    Unparseable,
}

/// The whitespace `strtod` skips, which is C's `isspace` in the "C" locale.
fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// The outcome of a `strtod` call: the value, the byte offset of the tail, and
/// whether `errno` would have been set to `ERANGE`.
struct Strtod {
    value: f64,
    /// Offset of the first byte not consumed. When no conversion was performed
    /// this is 0, because C leaves `endptr == nptr` — *not* past the
    /// whitespace it skipped.
    tail: usize,
    range_error: bool,
}

/// A port of C's `strtod` restricted to what it must do here: find the longest
/// valid numeric prefix, convert it, and report the tail.
///
/// When no conversion can be performed, C returns **0** and sets `endptr` back
/// to `nptr` — it does not fail. That is not a detail: it is why `nmap
/// --host-timeout s` is accepted and means *zero seconds*. The tail is then the
/// whole string, `"s"` matches the seconds suffix, and the value is the 0 that
/// `strtod` returned. Confirmed against the oracle:
///
/// ```text
/// $ printf '%s\0' s m ms | ./tval_oracle
/// 0000000000000000        0       73
/// 0000000000000000        0       6d
/// 0000000000000000        0       6d73
/// ```
///
/// Note that `endptr` is reset to the *start of the string*, before any
/// whitespace `strtod` skipped — so `" s"` has the tail `" s"`, which matches no
/// unit and is rejected, while `"s"` is accepted. Returning `None` here (the
/// obvious reading of "parse failed") made this port reject all seven bare-unit
/// spellings that C accepts.
// Index arithmetic throughout this scanner is bounded by `b.len()` and only
// ever advances; the exponent arithmetic saturates explicitly where it can
// overflow. Same justification, and same allow, as `options::parse_args`.
#[allow(clippy::arithmetic_side_effects)]
fn strtod(s: &str) -> Strtod {
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() && is_c_space(b[i]) {
        i += 1;
    }
    let negative = match b.get(i) {
        Some(b'+') => {
            i += 1;
            false
        }
        Some(b'-') => {
            i += 1;
            true
        }
        _ => false,
    };
    let after_sign = i;

    // "inf" / "infinity", case-insensitive. Longest match wins, so "infinity"
    // is preferred over the "inf" prefix of it.
    if let Some(len) =
        match_ci(&b[after_sign..], b"infinity").or_else(|| match_ci(&b[after_sign..], b"inf"))
    {
        return Strtod {
            value: if negative {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            },
            tail: after_sign + len,
            range_error: false,
        };
    }

    // "nan", optionally followed by a parenthesised char sequence.
    if let Some(len) = match_ci(&b[after_sign..], b"nan") {
        let mut end = after_sign + len;
        if b.get(end) == Some(&b'(') {
            if let Some(close) = b[end..].iter().position(|&c| c == b')') {
                end += close + 1;
            }
        }
        // The sign of a NaN is not observable through any caller here.
        return Strtod {
            value: f64::NAN,
            tail: end,
            range_error: false,
        };
    }

    // Hex: 0x / 0X followed by at least one hex digit in the mantissa. glibc
    // accepts a hex literal with no binary exponent even though C99 requires
    // one ("0x10" is 16), and the oracle confirms it.
    if b.get(i) == Some(&b'0') && matches!(b.get(i + 1), Some(b'x' | b'X')) {
        if let Some(parsed) = parse_hex(b, i + 2, negative) {
            return parsed;
        }
        // "0x" with no hex digits: strtod converts just the "0" and leaves the
        // tail at the "x". The oracle shows `0x` -> value 0, tail "x".
        return Strtod {
            value: if negative { -0.0 } else { 0.0 },
            tail: i + 1,
            range_error: false,
        };
    }

    parse_decimal(s, b, i, negative).unwrap_or(Strtod {
        value: 0.0,
        tail: 0,
        range_error: false,
    })
}

/// Case-insensitive prefix match; returns the matched length.
fn match_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() >= needle.len()
        && hay[..needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        Some(needle.len())
    } else {
        None
    }
}

/// Decimal: `digits [ . [digits] ] [ (e|E) [sign] digits ]`, or `. digits ...`.
/// The exponent is only consumed when at least one digit follows it — which is
/// why `"5e"` parses as 5 with the tail `"e"` rather than failing outright.
#[allow(clippy::arithmetic_side_effects)]
fn parse_decimal(s: &str, b: &[u8], start: usize, negative: bool) -> Option<Strtod> {
    let mut i = start;
    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let int_digits = i - int_start;

    let mut frac_digits = 0usize;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let frac_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        frac_digits = i - frac_start;
    }
    if int_digits == 0 && frac_digits == 0 {
        return None;
    }
    let mantissa_end = i;

    if matches!(b.get(i), Some(b'e' | b'E')) {
        let mut j = i + 1;
        if matches!(b.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        let exp_start = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > exp_start {
            i = j;
        }
    }
    let tail = i;

    // Hand the exact matched text to Rust's parser, which is correctly rounded
    // and agrees with glibc's strtod on decimal input. The leading sign is
    // included so that "-0" yields negative zero, as the oracle shows.
    let text = &s[if negative { start - 1 } else { start }..tail];
    let value: f64 = text.parse().ok()?;

    Some(Strtod {
        value,
        tail,
        range_error: decimal_range_error(value, &b[start..mantissa_end]),
    })
}

/// `errno == ERANGE` for a decimal conversion: it overflowed to infinity, or it
/// underflowed — flushed to zero, or landed on a subnormal inexactly.
///
/// The inexactness condition is what the IEEE underflow signal actually says,
/// and glibc follows it: an *exact* subnormal does not set `ERANGE`. The oracle
/// shows both halves —
///
/// ```text
/// 1e-323      -> -1                   (subnormal, inexact)
/// 0x1p-1030   -> 0x0000100000000000   (subnormal, exact, no error)
/// ```
///
/// For a decimal literal this port treats every nonzero subnormal as inexact.
/// That is not quite the rule, but the gap is unreachable: a decimal
/// `d * 10^-k` is exactly a binary float only when `5^k` divides `d`, and a
/// subnormal needs `k >= 308`, so `d` would have to carry at least 216
/// significant digits. The hex path, where exact subnormals are easy to write,
/// does the real test instead.
fn decimal_range_error(value: f64, mantissa: &[u8]) -> bool {
    if value.is_infinite() {
        return true;
    }
    if value == 0.0 {
        return mantissa.iter().any(|c| c.is_ascii_digit() && *c != b'0');
    }
    value.abs() < f64::MIN_POSITIVE
}

/// Hex: `hexdigits [ . [hexdigits] ] [ (p|P) [sign] digits ]` after the `0x`.
///
/// The mantissa is accumulated into a `u128` with a sticky bit for anything
/// past 128 bits, then scaled by a power of two. `m as f64` rounds once,
/// correctly, and multiplying by an exact power of two is exact whenever the
/// result is normal — so this is correctly rounded across the normal range.
#[allow(clippy::arithmetic_side_effects)]
fn parse_hex(b: &[u8], start: usize, negative: bool) -> Option<Strtod> {
    let mut i = start;
    let mut mantissa: u128 = 0;
    let mut exp: i32 = 0;
    let mut sticky = false;
    let mut digits = 0usize;

    let push = |nib: u32, mantissa: &mut u128, exp: &mut i32, sticky: &mut bool| {
        if *mantissa >> 124 != 0 {
            // No room: account for the digit's weight and remember that
            // something nonzero fell off the end.
            *exp += 4;
            if nib != 0 {
                *sticky = true;
            }
        } else {
            *mantissa = (*mantissa << 4) | u128::from(nib);
        }
    };

    while i < b.len() {
        let Some(nib) = (b[i] as char).to_digit(16) else {
            break;
        };
        push(nib, &mut mantissa, &mut exp, &mut sticky);
        digits += 1;
        i += 1;
    }
    if b.get(i) == Some(&b'.') {
        let save = i;
        i += 1;
        let mut frac = 0usize;
        while i < b.len() {
            let Some(nib) = (b[i] as char).to_digit(16) else {
                break;
            };
            push(nib, &mut mantissa, &mut exp, &mut sticky);
            exp -= 4;
            frac += 1;
            i += 1;
        }
        if frac == 0 && digits == 0 {
            // "0x.": no mantissa digits at all, so there is no hex conversion
            // and strtod falls back to converting the leading "0".
            let _ = save;
            return None;
        }
        digits += frac;
    }
    if digits == 0 {
        return None;
    }

    if matches!(b.get(i), Some(b'p' | b'P')) {
        let mut j = i + 1;
        let mut neg_exp = false;
        match b.get(j) {
            Some(b'+') => j += 1,
            Some(b'-') => {
                neg_exp = true;
                j += 1;
            }
            _ => {}
        }
        let exp_start = j;
        let mut val: i64 = 0;
        while j < b.len() && b[j].is_ascii_digit() {
            val = val
                .saturating_mul(10)
                .saturating_add(i64::from(b[j] - b'0'));
            j += 1;
        }
        if j > exp_start {
            let signed = if neg_exp { -val } else { val };
            exp = exp.saturating_add(i32::try_from(signed).unwrap_or(if neg_exp {
                i32::MIN
            } else {
                i32::MAX
            }));
            i = j;
        }
    }

    if sticky {
        // Keep the dropped-bits information out of the round-to-even decision
        // by forcing the low bit, which is what a sticky bit is for.
        mantissa |= 1;
    }

    let value = scale_pow2(mantissa as f64, exp);
    let value = if negative { -value } else { value };

    // The true value is `mantissa * 2^exp`. It is representable exactly when no
    // digit fell off the top (`sticky`) and its lowest set bit is still at or
    // above 2^-1074, the smallest subnormal. An exact subnormal does not raise
    // the IEEE underflow signal, so glibc leaves `errno` alone -- which is why
    // `0x1p-1030` is a valid time specification and `1e-323` is not.
    let exact = !sticky && mantissa != 0 && {
        let lowest_set_bit = exp.saturating_add(mantissa.trailing_zeros() as i32);
        lowest_set_bit >= -1074
    };
    let underflowed = value == 0.0 || value.abs() < f64::MIN_POSITIVE;

    Some(Strtod {
        value,
        tail: i,
        range_error: value.is_infinite() || (mantissa != 0 && underflowed && !exact),
    })
}

/// Multiply by 2^exp without overflowing the exponent range mid-way.
// `exp` is stepped by at most 1023 per iteration and the loop conditions bound
// it; the final shift is in range because `exp` is within [-1022, 1023] there.
#[allow(clippy::arithmetic_side_effects)]
fn scale_pow2(mut v: f64, mut exp: i32) -> f64 {
    while exp > 1023 {
        v *= f64::from_bits(0x7FE0_0000_0000_0000); // 2^1023
        exp -= 1023;
    }
    while exp < -1022 {
        v *= f64::from_bits(0x0010_0000_0000_0000); // 2^-1022
        exp += 1022;
    }
    v * f64::from_bits(((exp + 1023) as u64) << 52)
}

/// The unit portion of a time specification (`"ms"`, `"s"`, `"m"`, `"h"`), or
/// `None` when there was a parse error or no unit is present.
///
/// This is C's `tval_unit`, and the CLI uses it for the "since April 2010 the
/// default unit is seconds" guard: a bare number large enough to look like a
/// mistake is refused, but the same value *with* a unit is honoured.
pub fn tval_unit(spec: &str) -> Option<&str> {
    let parsed = strtod(spec);
    if spec.is_empty() || parsed.range_error || parsed.tail >= spec.len() {
        return None;
    }
    Some(&spec[parsed.tail..])
}

/// A time specification as a count of seconds — C's `tval2secs`.
///
/// Returns C's `-1.0` sentinel on failure. That sentinel collides with the
/// legitimate value "minus one second", and this port reproduces the collision
/// rather than fixing it, because [`tval2msecs`] is built on top of the
/// collision (`if (s == -1) return -1;`) and every caller rejects negatives
/// anyway. Prefer [`tval2msecs`] in new code.
pub fn tval2secs(spec: &str) -> f64 {
    let parsed = strtod(spec);
    if spec.is_empty() || parsed.range_error {
        return -1.0;
    }
    let tail = &spec[parsed.tail..];
    if tail.eq_ignore_ascii_case("ms") {
        parsed.value / 1000.0
    } else if tail.is_empty() || tail.eq_ignore_ascii_case("s") {
        parsed.value
    } else if tail.eq_ignore_ascii_case("m") {
        parsed.value * 60.0
    } else if tail.eq_ignore_ascii_case("h") {
        parsed.value * 60.0 * 60.0
    } else {
        -1.0
    }
}

/// A time specification as whole milliseconds — C's `tval2msecs`.
///
/// Returns `Err` where C returns its `-1` sentinel, and additionally for the
/// two inputs where C's range guard lets an out-of-range `double` reach a
/// conversion (see the module docs). Every caller treats both as a refusal, so
/// the observable behaviour is the same.
pub fn tval2msecs(spec: &str) -> Result<i64, TimeSpecError> {
    let s = tval2secs(spec);
    // C: `if (s == -1) return -1;` — the sentinel check, which also swallows a
    // genuine "-1 second". Mirrored exactly.
    if s == -1.0 {
        return Err(TimeSpecError::Unparseable);
    }
    let ms = s * 1000.0;
    // C's guard is `ms > LONG_MAX || ms < LONG_MIN`, which misses NaN and the
    // exact value 2^63. This is the corrected form: anything that is not a
    // number, or that will not survive the conversion, is a refusal. The bounds
    // are half-open at the top because `i64::MAX` is not representable as an
    // `f64` — 2^63 is the first value above it, and it is exactly the one C's
    // `>` lets through.
    const MIN: f64 = -9_223_372_036_854_775_808.0; // -2^63, exactly i64::MIN
    const LIMIT: f64 = 9_223_372_036_854_775_808.0; // 2^63, one past i64::MAX
    if !ms.is_finite() || !(MIN..LIMIT).contains(&ms) {
        return Err(TimeSpecError::Unparseable);
    }
    // In range and finite by the check above, so the cast is exact in the
    // integral part and truncates the fraction, which is what C's `(long)` does.
    #[allow(clippy::cast_possible_truncation)]
    Ok(ms as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seven bare unit spellings C accepts as "zero". `strtod` performs no
    /// conversion, returns 0, and resets the tail to the start of the string —
    /// so the whole string is the unit and the value is that 0.
    ///
    /// Reading `strtod`'s "no conversion" as a parse failure (the obvious
    /// reading) made this port reject all seven. The corpus differential caught
    /// it; this pins it.
    #[test]
    fn a_bare_unit_is_zero_not_an_error() {
        for spec in ["s", "S", "ms", "MS", "mS", "m", "M", "h", "H"] {
            assert_eq!(tval2msecs(spec), Ok(0), "{spec:?} should be zero");
            assert_eq!(tval_unit(spec), Some(spec));
        }
        // But the tail is reset to the START of the string, before any
        // whitespace, so a leading space makes the unit " s" — which matches
        // nothing and is rejected.
        assert_eq!(tval2msecs(" s"), Err(TimeSpecError::Unparseable));
    }

    /// The two inputs that reach C's undefined `double` -> `long` conversion.
    /// C's guard is `ms > LONG_MAX || ms < LONG_MIN`, which is false for NaN
    /// and false for exactly 2^63 (because `LONG_MAX` converts to 2^63).
    #[test]
    fn the_inputs_that_are_undefined_in_c_are_refused_here() {
        for spec in ["nan", "NAN", "nan(123)", "9223372036854775.808"] {
            assert_eq!(
                tval2msecs(spec),
                Err(TimeSpecError::Unparseable),
                "{spec:?} must not produce a number"
            );
        }
    }

    /// `strtod` accepts a good deal more than a decimal, and all of it reaches
    /// nmap's command line.
    #[test]
    fn strtod_shaped_inputs_parse_as_c_does() {
        assert_eq!(tval2msecs("0x10"), Ok(16_000)); // hex, 16 seconds
        assert_eq!(tval2msecs("0x1p10"), Ok(1_024_000)); // hex, binary exponent
        assert_eq!(tval2msecs("1e3ms"), Ok(1_000)); // exponent, then a unit
        assert_eq!(tval2msecs("+5"), Ok(5_000));
        assert_eq!(tval2msecs("  5"), Ok(5_000)); // leading whitespace
        assert_eq!(tval2msecs("5H"), Ok(18_000_000)); // units are case-insensitive
    }

    /// And rejects things that look acceptable. `5e` is the interesting one:
    /// `strtod` backtracks over the incomplete exponent, leaving the tail "e",
    /// which matches no unit.
    #[test]
    fn near_misses_are_rejected_as_c_rejects_them() {
        for spec in ["5 ms", "5e", "5.5.5", "1e-400", "1e309", "5h5", "abc", ""] {
            assert_eq!(
                tval2msecs(spec),
                Err(TimeSpecError::Unparseable),
                "{spec:?} should not parse"
            );
        }
    }

    /// An exactly-representable subnormal does not raise the IEEE underflow
    /// signal, so glibc leaves `errno` alone and the value is accepted; an
    /// inexact one sets ERANGE and is not.
    #[test]
    fn only_inexact_underflow_is_an_error() {
        assert_eq!(tval2msecs("0x1p-1030"), Ok(0), "exact subnormal");
        assert_eq!(
            tval2msecs("1e-323"),
            Err(TimeSpecError::Unparseable),
            "inexact subnormal"
        );
    }
}
