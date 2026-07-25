//! The `nmap-os-db` expression matcher — a port of `expr_match()` from `osscan.cc`.
//!
//! Every attribute in `nmap-os-db` is a small pattern that an *observed* fingerprint
//! value is tested against. The language is compact but fiddly:
//!
//! | form | meaning | example |
//! |---|---|---|
//! | literal | exact match | `Z` |
//! | `A\|B\|C` | alternation | `S\|A\|AS` |
//! | `a-b` | inclusive hex range | `1-6` |
//! | `>n` / `<n` | hex comparison | `>400` |
//! | `X[expr]Y` | nested sub-expression over a hex run | `M[>500]ST11W[1-5]` |
//!
//! Hex values compare by **length first, then lexicographically**, after stripping
//! leading zeros — so `100 > FF` even though `'1' < 'F'`.
//!
//! The C is 200 lines of raw pointer walking whose author labelled it
//! `/* OHHHH YEEEAAAAAHHHH!#!@#$!% */`. This port therefore keeps the C's control flow
//! recognizable (so the differential is meaningful) while making every read bounds-safe:
//! [`byte_at`] reproduces reading a C string's NUL terminator, and [`strncmp_at`]
//! reproduces `strncmp`'s stop-at-NUL over slices. Verified against a verbatim
//! transcription of the C in `tests/differential/m5/oracle/expr_oracle.cc`.
//!
//! ## Divergences (ledgered in `DIVERGENCES.md`)
//!
//! * `osdb-expr-unterminated-nest-no-abort` — an expression with `[` and no `]` makes
//!   the C `assert(q1)` fire (**abort**, i.e. a denial of service on a malformed or
//!   hostile database); with `NDEBUG` — how release builds ship — the assert is compiled
//!   out and the code computes `q1 - nest` and `q1 + 1` from a `NULL` `q1`, which is
//!   undefined behavior. This port treats an unterminated `[` as **no match** and keeps
//!   scanning the remaining alternatives.
//!
//! ## Faithfully reproduced C quirks
//!
//! Two behaviors look like bugs but are load-bearing for matching the shipped database,
//! so they are reproduced deliberately and pinned by the differential:
//!
//! * **`vlen` persists across alternatives.** The C declares `subval` inside the
//!   alternation loop (so it resets each iteration) but `vlen` is the function
//!   parameter, so a leading-zero strip in one alternative permanently shortens the
//!   value seen by every later alternative.
//! * **Nested runs are greedy over hex digits.** `M[1-6]…` against `M5B4…` consumes
//!   `5B4` as one hex run (`B` is a hex digit), so the nested sub-expression is tested
//!   against the whole run, not just the first digit.

use core::cmp::Ordering;

/// Read a byte as C would read a NUL-terminated string: past the end is `\0`.
///
/// The values and expressions here originate as C strings and never contain an interior
/// NUL, so treating "past the end" as `\0` is exactly the C's view of the same buffer.
#[inline]
fn byte_at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// ASCII hex digit, matching C's `isxdigit` in the C locale.
#[inline]
fn is_xdigit(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// `strncmp(&a[ai], &b[bi], n)` with C string semantics: compare unsigned bytes, stop
/// early on a shared NUL, and treat the end of a slice as NUL.
fn strncmp_at(a: &[u8], ai: usize, b: &[u8], bi: usize, n: usize) -> Ordering {
    for k in 0..n {
        let ca = byte_at(a, ai.saturating_add(k));
        let cb = byte_at(b, bi.saturating_add(k));
        match ca.cmp(&cb) {
            Ordering::Equal => {
                if ca == 0 {
                    return Ordering::Equal; // both hit the terminator together
                }
            }
            other => return other,
        }
    }
    Ordering::Equal
}

/// Index of the first `needle` in `hay[from..to]`, as C's `strchr_p`.
fn find(hay: &[u8], from: usize, to: usize, needle: u8) -> Option<usize> {
    if from > to || from > hay.len() {
        return None;
    }
    let end = to.min(hay.len());
    hay.get(from..end)?
        .iter()
        .position(|&b| b == needle)
        .map(|off| from.saturating_add(off))
}

/// Does the observed value `val` match the database expression `expr`?
///
/// `do_nested` enables `[...]` sub-expressions; the C only sets it for the tests whose
/// values are TCP-option strings (`OPS`, and the `O` attributes), and clears it for the
/// one level of recursion, so nesting is never deeper than one level.
///
/// Total on all input: never panics, never reads out of bounds, and recursion is bounded
/// at depth 1 by construction.
#[must_use]
pub fn expr_match(val: &[u8], expr: &[u8], do_nested: bool) -> bool {
    let explen = expr.len();
    // Both empty matches; an empty expression matches only an empty value.
    if explen == 0 {
        return val.is_empty();
    }

    // NOTE: `vlen` deliberately lives outside the alternation loop — see the module docs
    // on the C quirk this reproduces.
    let mut vlen = val.len();
    let mut p: usize = 0;
    let p_end = explen;

    loop {
        // `subval` resets every alternative (it is block-scoped in the C).
        let mut subval: usize = 0;
        let q_init = find(expr, p, p_end, b'|');
        let mut q = q_init;
        let mut nest = find(expr, p, q.unwrap_or(p_end), b'[');

        // An empty value can only match an empty alternative.
        if vlen == 0 {
            if q == Some(p) || p == p_end {
                return true;
            } else if nest.is_none() {
                match q {
                    Some(qq) => {
                        p = qq.saturating_add(1);
                        continue;
                    }
                    None => return false,
                }
            }
            // Otherwise fall through to the nesting logic, as the C does.
        }

        if do_nested && nest.is_some() {
            let mut failed = false;
            // Walk each `[...]` group, e.g. `M[>500]ST11W[1-5]`.
            while let Some(nst) = nest {
                let Some(q1) = find(expr, nst, p_end, b']') else {
                    // C: `assert(q1)` — abort in a debug build, UB under NDEBUG.
                    // A malformed expression simply does not match here.
                    return false;
                };
                if let Some(qq) = q {
                    if qq < q1 {
                        // "AB[C|D]E|XYZ" — the '|' was inside the group.
                        q = find(expr, q1, p_end, b'|');
                    }
                }
                // The literal run before the group must match exactly.
                let lead = nst.saturating_sub(p);
                if strncmp_at(expr, p, val, subval, lead) != Ordering::Equal {
                    failed = true;
                    break;
                }
                let inner_start = nst.saturating_add(1);
                subval = subval.saturating_add(lead);
                // The group is tested against the whole following hex run (greedy).
                let mut nlen = 0usize;
                while is_xdigit(byte_at(val, subval.saturating_add(nlen))) {
                    nlen = nlen.saturating_add(1);
                }
                p = q1.saturating_add(1);

                let inner_ok = nlen > 0
                    && inner_start <= q1
                    && expr_match(
                        val.get(subval..subval.saturating_add(nlen))
                            .unwrap_or_default(),
                        expr.get(inner_start..q1).unwrap_or_default(),
                        // One level only — matches the C, and bounds the recursion.
                        false,
                    );
                if inner_ok {
                    subval = subval.saturating_add(nlen);
                    nest = find(expr, p, q.unwrap_or(p_end), b'[');
                } else {
                    failed = true;
                    break;
                }
            }

            if !failed {
                // No groups left: the remainder must match exactly, and consume the rest
                // of both the value and the expression.
                let rest = vlen.saturating_sub(subval);
                if explen.saturating_sub(p) == rest
                    && strncmp_at(val, subval, expr, p, rest) == Ordering::Equal
                {
                    return true;
                }
            }
            match q {
                Some(qq) => {
                    p = qq.saturating_add(1);
                    continue;
                }
                None => return false,
            }
        }

        // Length of this alternative within the expression.
        let mut sublen = match q {
            Some(qq) => qq.saturating_sub(p),
            None => explen.saturating_sub(p),
        };

        if is_xdigit(byte_at(val, subval)) {
            // Strip leading zeros from the value (mutating `vlen`, as the C does).
            while byte_at(val, subval) == b'0' && vlen > 1 {
                subval = subval.saturating_add(1);
                vlen = vlen.saturating_sub(1);
            }

            if byte_at(expr, p) == b'>' {
                // Skip the '>' and any leading zeros of the bound.
                loop {
                    p = p.saturating_add(1);
                    sublen = sublen.saturating_sub(1);
                    if !(byte_at(expr, p) == b'0' && sublen > 1) {
                        break;
                    }
                }
                // Longer hex string wins; equal length falls back to lexicographic.
                if vlen > sublen
                    || (vlen == sublen
                        && strncmp_at(val, subval, expr, p, vlen) == Ordering::Greater)
                {
                    return true;
                }
            } else if byte_at(expr, p) == b'<' {
                loop {
                    p = p.saturating_add(1);
                    sublen = sublen.saturating_sub(1);
                    if !(byte_at(expr, p) == b'0' && sublen > 1) {
                        break;
                    }
                }
                if vlen < sublen
                    || (vlen == sublen && strncmp_at(val, subval, expr, p, vlen) == Ordering::Less)
                {
                    return true;
                }
            } else if is_xdigit(byte_at(expr, p)) {
                // Strip leading zeros from the (low end of the) bound.
                while sublen > 1 && byte_at(expr, p) == b'0' {
                    p = p.saturating_add(1);
                    sublen = sublen.saturating_sub(1);
                }
                if let Some(dash) = find(expr, p, q.unwrap_or(p_end), b'-') {
                    let mut lo = p;
                    if dash == lo {
                        // Leading '-' (a range starting at the stripped zero).
                        lo = lo.saturating_sub(1);
                        sublen = sublen.saturating_add(1);
                    }
                    let lo_len = dash.saturating_sub(lo);
                    if vlen > lo_len
                        || (vlen == lo_len
                            && strncmp_at(val, subval, expr, lo, vlen) != Ordering::Less)
                    {
                        let mut hi = dash.saturating_add(1);
                        sublen = sublen.saturating_sub(lo_len.saturating_add(1));
                        while sublen > 1 && byte_at(expr, hi) == b'0' {
                            hi = hi.saturating_add(1);
                            sublen = sublen.saturating_sub(1);
                        }
                        if vlen < sublen
                            || (vlen == sublen
                                && strncmp_at(val, subval, expr, hi, vlen) != Ordering::Greater)
                        {
                            return true;
                        }
                    }
                    // A range that did not match: this alternative is done.
                    match q {
                        Some(qq) => {
                            p = qq.saturating_add(1);
                            continue;
                        }
                        None => return false,
                    }
                }
                // Not a range — fall through to the plain comparison below.
                if vlen == sublen && strncmp_at(expr, p, val, subval, vlen) == Ordering::Equal {
                    return true;
                }
                match q {
                    Some(qq) => {
                        p = qq.saturating_add(1);
                        continue;
                    }
                    None => return false,
                }
            } else {
                // Value is hex but the expression starts with neither a digit nor </>.
                match q {
                    Some(qq) => {
                        p = qq.saturating_add(1);
                        continue;
                    }
                    None => return false,
                }
            }
            // The >/< branches fall through to `next_expr`.
            match q {
                Some(qq) => {
                    p = qq.saturating_add(1);
                    continue;
                }
                None => return false,
            }
        }

        // Plain literal comparison.
        if vlen == sublen && strncmp_at(expr, p, val, subval, vlen) == Ordering::Equal {
            return true;
        }
        match q {
            Some(qq) => {
                p = qq.saturating_add(1);
                continue;
            }
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: match `&str` inputs.
    fn m(val: &str, expr: &str, nested: bool) -> bool {
        expr_match(val.as_bytes(), expr.as_bytes(), nested)
    }

    #[test]
    fn literal_and_empty() {
        assert!(m("A", "A", false));
        assert!(!m("A", "B", false));
        assert!(m("", "", false));
        assert!(!m("A", "", false));
        assert!(!m("", "A", false));
    }

    #[test]
    fn alternation() {
        assert!(m("S", "S|A|AS", false));
        assert!(m("A", "S|A|AS", false));
        assert!(m("AS", "S|A|AS", false));
        assert!(!m("R", "S|A|AS", false));
        // An empty alternative matches an empty value.
        assert!(m("", "A|", false));
    }

    #[test]
    fn hex_ranges_compare_by_length_then_lexicographically() {
        assert!(m("5", "1-9", false));
        assert!(m("1", "1-9", false));
        assert!(m("9", "1-9", false));
        assert!(!m("A", "1-9", false));
        // 100 > FF because it is longer, not because '1' > 'F'.
        assert!(m("100", ">FF", false));
        assert!(!m("FF", ">100", false));
    }

    #[test]
    fn comparisons() {
        assert!(m("500", ">400", false));
        assert!(!m("400", ">400", false));
        assert!(m("300", "<400", false));
        assert!(!m("400", "<400", false));
    }

    #[test]
    fn leading_zeros_are_normalized() {
        assert!(m("0005", "5", false));
        assert!(m("5", "0005", false));
        assert!(m("0100", ">FF", false));
    }

    #[test]
    fn nested_groups_need_the_nested_flag() {
        // Greedy hex run: "5" is the whole run before 'S'.
        assert!(m("M5ST11", "M[1-6]ST11", true));
        assert!(!m("M9ST11", "M[1-6]ST11", true));
        // Without do_nested the brackets are literal, so it cannot match.
        assert!(!m("M5ST11", "M[1-6]ST11", false));
    }

    #[test]
    fn nested_run_is_greedy_over_hex_digits() {
        // 'B' is a hex digit, so the run is "5B4" and the group is tested against all
        // three characters — reproducing the C exactly (see the module docs).
        assert!(!m("M5B4ST11", "M[1-6]ST11", true));
    }

    #[test]
    fn unterminated_nest_is_no_match_not_abort() {
        // The C asserts here (abort) / is UB under NDEBUG. We simply do not match.
        assert!(!m("A5", "A[1-9", true));
        assert!(!m("ABCDEF", "A[B[C", true));
        assert!(!m("5", "[", true));
        assert!(!m("M5B4", "M[1-6]B[4", true));
    }

    #[test]
    fn is_total_on_hostile_input() {
        // A pile of shapes that have historically broken pointer-walking matchers.
        let exprs = [
            "", "|", "||", "[", "]", "[]", "-", "--", ">", "<", ">|", "<|", "1-", "-1", "0-0",
            "[|]", "A[", "[A", "A|[", ">0", "<0", "00", "[1-", "1-2-3", "|-|", ">|<", "[[[[",
            "]]]]", "A[1-9]|B", "[0-F]",
        ];
        let vals = [
            "", "0", "5", "A", "FF", "000", "M5B4ST11", "\u{7f}", "zz", "-", "|",
        ];
        for e in exprs {
            for v in vals {
                for nested in [false, true] {
                    // The contract is simply: it returns.
                    let _ = m(v, e, nested);
                }
            }
        }
    }

    #[test]
    fn real_shapes_from_the_shipped_database() {
        // Values/expressions in the style nmap-os-db actually uses.
        assert!(m("Z", "Z", false));
        assert!(m("S", "S|Z", false));
        assert!(m("7F", "7F", false));
        assert!(m("40", "40|3C", false));
        assert!(m("FFFF", ">7FFF", false));
        assert!(m("8", "1-C", false));
    }
}
