//! `string.rep`, ported from `liblua/lstrlib.c:150-174`.
//!
//! Small, but the one function in the string library whose output size is
//! chosen by its arguments alone: `("x"):rep(2^31)` asks for two gigabytes.
//! The C refuses a result longer than `MAXSIZE` (`INT_MAX`) with "resulting
//! string too large", checking `l + lsep` and `(l + lsep) * n` without
//! overflowing; this port checks the same bound with checked arithmetic, and
//! grows its buffer with `try_reserve`, so a result under the bound that the
//! system still refuses is the catchable "not enough memory".

/// `MAXSIZE` (`lstrlib.c:49`): `INT_MAX` on every platform this port targets.
const MAXSIZE: usize = i32::MAX as usize;

/// Why `string.rep` raised: `luaL_error`, which names no argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepError(pub &'static str);

/// `string.rep(s, n [, sep])`: `n` copies of `s` with `sep` between them;
/// empty for `n <= 0`.
pub fn rep(s: &[u8], n: i64, sep: &[u8]) -> Result<Vec<u8>, RepError> {
    let Ok(n) = usize::try_from(n) else {
        return Ok(Vec::new()); // n <= 0 (or past usize, which n > 0 cannot be)
    };
    let total = result_len(s.len(), n, sep.len())?;
    if total == 0 {
        // Empty `s` and `sep`, or `n == 0`. For the first, the C still runs
        // its copy loop `n` times, up to 2^63; the answer is the empty string
        // either way.
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    if !piccolo::budget::allows(total) {
        return Err(RepError("not enough memory"));
    }
    out.try_reserve_exact(total)
        .map_err(|_| RepError("not enough memory"))?;
    for i in 0..n {
        if i > 0 {
            out.extend_from_slice(sep);
        }
        out.extend_from_slice(s);
    }
    Ok(out)
}

/// The length of `n` copies of an `l`-byte string joined by an `lsep`-byte
/// separator, or the C's refusal. Split out so the bound can be tested on
/// both sides without building a two-gigabyte string.
fn result_len(l: usize, n: usize, lsep: usize) -> Result<usize, RepError> {
    let Some(limit) = MAXSIZE.checked_div(n) else {
        return Ok(0); // n == 0
    };
    // `l + lsep < l || l + lsep > MAXSIZE / n`: the C's test, exactly.
    let unit = l.checked_add(lsep);
    if unit.is_none_or(|u| u > limit) {
        return Err(RepError("resulting string too large"));
    }
    // n copies of s and n - 1 of sep: at most n * (l + lsep), which the test
    // just bounded by MAXSIZE.
    Ok(l.saturating_mul(n)
        .saturating_add(lsep.saturating_mul(n.saturating_sub(1))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_with_and_without_a_separator() {
        assert_eq!(rep(b"ab", 3, b"").unwrap(), b"ababab");
        assert_eq!(rep(b"ab", 3, b", ").unwrap(), b"ab, ab, ab");
        assert_eq!(rep(b"ab", 1, b"-").unwrap(), b"ab");
        assert_eq!(rep(b"", 5, b"").unwrap(), b"");
        assert_eq!(rep(b"", 3, b"x").unwrap(), b"xx");
    }

    #[test]
    fn non_positive_counts_are_empty() {
        for n in [0, -1, i64::MIN] {
            assert_eq!(rep(b"ab", n, b"-").unwrap(), b"");
        }
    }

    #[test]
    fn the_size_limit_is_the_cs() {
        // Exactly INT_MAX fits the test; one more byte does not.
        assert_eq!(
            rep(b"x", i64::from(i32::MAX) + 1, b"").unwrap_err().0,
            "resulting string too large"
        );
        assert_eq!(
            rep(b"ab", i64::MAX, b"").unwrap_err().0,
            "resulting string too large"
        );
        // The separator counts once per copy in the test, as in the C.
        assert_eq!(
            rep(b"x", i64::from(i32::MAX) / 2 + 1, b"y").unwrap_err().0,
            "resulting string too large"
        );
        // An empty unit repeated any number of times is fine.
        assert_eq!(rep(b"", i64::MAX, b"").unwrap(), b"");
    }

    #[test]
    fn the_bound_is_inclusive() {
        let max = i32::MAX as usize;
        // A unit of exactly MAXSIZE / n is accepted, one more byte is not.
        assert_eq!(result_len(1, max, 0), Ok(max));
        assert!(result_len(2, max, 0).is_err());
        assert_eq!(result_len(1000, max / 1000, 0), Ok(max / 1000 * 1000));
        assert!(result_len(1001, max / 1000, 0).is_err());
        // The separator counts once per copy in the test, once less in the
        // result.
        assert_eq!(result_len(1, max / 2, 1), Ok(max / 2 * 2 - 1));
        assert!(result_len(1, max / 2 + 1, 1).is_err());
        // l + lsep overflowing is refused, not wrapped.
        assert!(result_len(usize::MAX, 1, 1).is_err());
        assert_eq!(result_len(5, 0, 5), Ok(0));
    }
}
