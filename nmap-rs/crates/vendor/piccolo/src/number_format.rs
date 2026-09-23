//! Lua's number-to-string conversion.
//!
//! Ported from `tostringbuff` in `liblua/lobject.c`, which is what `tostring`,
//! `print`, and the `..` operator all reach for a float. Rust's own `Display`
//! for `f64` is not a substitute: it is shortest-round-trip and never uses
//! exponent notation, so it renders `1.0` as `1` (indistinguishable from the
//! integer), `1.0 / 3.0` with 16 significant digits rather than 14, and `1e300`
//! as a three-hundred-and-one-digit numeral.
//!
//! Integers are not ported, because `lua_integer2str` is `"%lld"` and Rust's
//! `Display` for `i64` already agrees with it over the whole type.

use std::fmt::{self, Write as _};

/// `LUA_NUMBER_FMT` — `"%.14g"` for `LUA_FLOAT_DOUBLE`, `liblua/luaconf.h:480`.
const FLOAT_PRECISION: usize = 14;

/// Renders `n` exactly as Lua's `tostring` would.
pub fn display_float(n: f64) -> impl fmt::Display {
    FloatDisplay(n)
}

struct FloatDisplay(f64);

impl fmt::Display for FloatDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `tostringbuff` formats into a buffer and then inspects it, so we do
        // too, rather than trying to predict the `.0` from the value.
        let mut buf = String::new();
        format_g(&mut buf, self.0, FLOAT_PRECISION)?;
        if looks_like_int(&buf) {
            // `buff[len++] = lua_getlocaledecpoint(); buff[len++] = '0';`.
            // The C reads the radix character from the locale. Hardcoding '.'
            // is checked, not assumed: nmap never *sets* a locale -- its one
            // `setlocale` call, `main.cc:120`, passes NULL and is a query -- so
            // the process stays in "C", where the radix character is '.'. No
            // shipped script or nselib module calls `os.setlocale` either.
            buf.push_str(".0");
        }
        f.write_str(&buf)
    }
}

/// The `strspn(buff, "-0123456789")` test in `tostringbuff`: true when the
/// formatted float carries no radix character and no exponent, and so would be
/// read back as an integer.
fn looks_like_int(s: &str) -> bool {
    s.bytes().all(|b| b == b'-' || b.is_ascii_digit())
}

/// `printf("%.*g", precision, n)`, per C99 7.21.6.1p8.
fn format_g(out: &mut impl fmt::Write, n: f64, precision: usize) -> fmt::Result {
    // glibc spells these out rather than going through the digit generator,
    // and prints the sign bit of a NaN.
    if n.is_nan() {
        return out.write_str(if n.is_sign_negative() { "-nan" } else { "nan" });
    }
    if n.is_infinite() {
        return out.write_str(if n.is_sign_negative() { "-inf" } else { "inf" });
    }

    // "Let P equal the precision ... if the precision is zero, it is taken as
    // 1." `%.14g` never takes this branch, but the conversion is the C's.
    let p = precision.max(1);

    // "Let X be the exponent of the conversion" — style `e`, and therefore the
    // exponent *after* rounding to P significant digits: 9.9999999999999999
    // rounds to 1.0000000000000e+01, and it is that 1 that is compared below.
    let mut scientific = String::new();
    write!(scientific, "{:.*e}", p - 1, n)?;
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("`{:e}` always writes an exponent");
    let x: i32 = exponent
        .parse()
        .expect("`{:e}` always writes a decimal exponent");

    // "If P > X >= -4, the conversion is with style f and precision P - 1 - X.
    // Otherwise, the conversion is with style e and precision P - 1."
    if x < -4 || x >= p as i32 {
        out.write_str(trim_fraction(mantissa))?;
        // C prints the exponent with a sign and at least two digits; Rust's
        // `{:e}` prints neither, which is why this is not just `scientific`.
        write!(
            out,
            "e{}{:02}",
            if x < 0 { '-' } else { '+' },
            x.unsigned_abs()
        )
    } else {
        // The branch bounds X to -4..p, so this subtraction cannot go negative
        // and the precision cannot exceed P + 3.
        let fixed_precision = p as i32 - 1 - x;
        debug_assert!((0..=p as i32 + 3).contains(&fixed_precision));
        let mut fixed = String::new();
        write!(fixed, "{:.*}", fixed_precision as usize, n)?;
        out.write_str(trim_fraction(&fixed))
    }
}

/// "Finally, unless the # flag is used, any trailing zeros are removed from the
/// fractional portion of the result and the decimal-point character is removed
/// if there is no fractional portion remaining."
fn trim_fraction(s: &str) -> &str {
    // Without this guard the trim would eat the trailing zeros of an integral
    // result: `100` is not `1`.
    if !s.contains('.') {
        return s;
    }
    s.trim_end_matches('0').trim_end_matches('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spot values taken from nmap's own Lua; the exhaustive comparison against
    /// it lives in the M6.0 differential corpus.
    #[test]
    fn matches_puc_lua_on_the_shapes_that_differ() {
        for (value, expected) in [
            // The `.0` that Rust's `Display` does not add.
            (1.0, "1.0"),
            (-1.0, "-1.0"),
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (100.0, "100.0"),
            // Style f, kept because P > X >= -4.
            (0.5, "0.5"),
            (0.1, "0.1"),
            (0.0001, "0.0001"),
            // 14 significant digits, not 16.
            (1.0 / 3.0, "0.33333333333333"),
            (std::f64::consts::PI, "3.1415926535898"),
            // The style f / style e boundary: 1e13 has exactly 14 digits and
            // stays fixed; 1e14 has 15 and does not.
            (1e13, "10000000000000.0"),
            (1e14, "1e+14"),
            (99999999999999.0, "99999999999999.0"),
            // Style e, with the two-digit exponent C requires.
            (1e-5, "1e-05"),
            (1e100, "1e+100"),
            (1e-300, "1e-300"),
            (5e-324, "4.9406564584125e-324"),
            (1.5e-10, "1.5e-10"),
            (-1e20, "-1e+20"),
            (9007199254740992.0, "9.007199254741e+15"),
            (123456789012345.0, "1.2345678901234e+14"),
            // Not "inf" with a ".0" stuck on the end.
            (f64::INFINITY, "inf"),
            (f64::NEG_INFINITY, "-inf"),
        ] {
            assert_eq!(
                display_float(value).to_string(),
                expected,
                "{value:?} ({:#018x})",
                value.to_bits()
            );
        }
        assert_eq!(display_float(f64::NAN.copysign(1.0)).to_string(), "nan");
        assert_eq!(display_float(f64::NAN.copysign(-1.0)).to_string(), "-nan");
    }

    /// The one assumption this port rests on that the C standard does not
    /// state: that Rust's float formatter breaks a rounding tie the same way
    /// glibc's does.
    ///
    /// A tie needs a double whose exact decimal expansion has its last nonzero
    /// digit at significant position 15, which happens only for values with
    /// short binary expansions. `2^-21` is exactly `4.76837158203125e-7` -- 15
    /// significant digits, the last of them a 5 with nothing after it -- so
    /// rounding it to 14 is a true tie. Both round to even and leave the `2`;
    /// rounding half away from zero would give `...813e-07`.
    ///
    /// Every power of two is in the differential corpus for this reason, which
    /// is how this is known rather than assumed.
    #[test]
    fn rounding_ties_go_to_even_as_glibc_does() {
        assert_eq!(
            display_float(2f64.powi(-21)).to_string(),
            "4.7683715820312e-07"
        );
        assert_eq!(
            display_float(2f64.powi(-23)).to_string(),
            "1.1920928955078e-07"
        );
        assert_eq!(
            display_float(2f64.powi(-25)).to_string(),
            "2.9802322387695e-08"
        );
    }

    #[test]
    fn trimming_does_not_eat_integral_zeros() {
        assert_eq!(trim_fraction("100"), "100");
        assert_eq!(trim_fraction("1.000"), "1");
        assert_eq!(trim_fraction("1.500"), "1.5");
        assert_eq!(trim_fraction("-0.000"), "-0");
        assert_eq!(trim_fraction("0"), "0");
    }

    #[test]
    fn the_looks_like_int_test_is_the_c_strspn() {
        assert!(looks_like_int("100"));
        assert!(looks_like_int("-0"));
        assert!(!looks_like_int("1.5"));
        assert!(!looks_like_int("1e+14"));
        assert!(!looks_like_int("inf"));
        assert!(!looks_like_int("-nan"));
    }
}
