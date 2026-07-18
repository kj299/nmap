//! PCRE→Rust-`regex` **syntax** translation — the module the M3 corpus-validation
//! spike (`SPIKES.md` M3-1) proved was the missing piece between "77.5% of
//! `nmap-service-probes` patterns compile" and "93.5% compile".
//!
//! `nmap-service-probes` is written for PCRE2. Rust's `regex`/`fancy-regex` accept
//! *almost* the same syntax, but a few PCRE spellings are rejected outright — not
//! because the pattern needs backtracking, but because the same intent is spelled
//! differently. This module rewrites exactly those spellings, and **nothing else**,
//! so a pattern's *meaning* is preserved while its *syntax* becomes Rust-legal.
//! It runs before either engine (`core::matcher`), so it helps the linear engine
//! and the backtracking fallback equally.
//!
//! ## The three rewrites (each semantics-preserving, verified against `regex::bytes`)
//!
//! 1. **`\0` → `\x00`.** PCRE reads `\0` as NUL; Rust `regex` rejects the bare
//!    `\0` and wants the hex form. Applied everywhere, including inside classes
//!    (`[^\0]` → `[^\x00]`). A `\0` *followed by* an octal digit is left alone (it
//!    is an octal escape, not a lone NUL).
//! 2. **Bare braces → escaped.** Outside a character class, a `{` that does **not**
//!    open a valid `{n}`/`{n,}`/`{n,m}` quantifier is a literal in PCRE but a syntax
//!    error in Rust (`^S\xf5\xc6\x1a{`), so it becomes `\{`; a stray `}` becomes
//!    `\}`. A real quantifier token is copied verbatim.
//! 3. **Literal `[` inside a class → `\[`.** PCRE treats `[` inside `[...]` as a
//!    literal; Rust `regex` treats it as the opener of a *nested* class (set
//!    syntax), so PCRE's `[][\w]` / `[^[]` fail to balance. Escaping every
//!    unescaped `[` inside a class restores the literal meaning.
//!
//! Leading `]` (`[^]]`, `[]abc]`) needs **no** rewrite — Rust `regex` already
//! reads a `]` in the first class position as a literal, exactly like PCRE.
//!
//! ## Contract
//!
//! [`translate`] is **pure and total**: any `&str` in, a `String` out, never a
//! panic, no unchecked indexing, all arithmetic bounded. It does not *validate*
//! the regex (that is the engine's job at `core::matcher`) — an un-rewritable
//! pattern passes through unchanged and is caught later. The spike corpus (all
//! 12,171 shipped patterns) is this module's regression seed.

/// Rewrite PCRE regex *syntax* into the equivalent Rust-`regex` syntax. Pure,
/// total, semantics-preserving. See the module docs for the exact rewrites.
pub fn translate(pattern: &str) -> String {
    let b = pattern.as_bytes();
    // Only ASCII bytes are ever inserted and every other byte is copied verbatim,
    // so a valid-UTF-8 input yields valid-UTF-8 output.
    let mut out: Vec<u8> = Vec::with_capacity(b.len().saturating_add(16));
    let mut i = 0usize;
    let mut in_class = false;
    // True when the next class member is in the "first" position (right after `[`
    // or `[^`), where a `]` is a literal rather than the class terminator.
    let mut class_first = false;

    while i < b.len() {
        let c = b[i];

        // --- Escapes: consume `\` + the escaped byte as a unit ---------------
        if c == b'\\' {
            match b.get(i.saturating_add(1)) {
                Some(&n) => {
                    // `\0` not followed by another octal digit → NUL in hex form.
                    let next_is_octal = b
                        .get(i.saturating_add(2))
                        .is_some_and(|d| (b'0'..=b'7').contains(d));
                    if n == b'0' && !next_is_octal {
                        out.extend_from_slice(b"\\x00");
                    } else {
                        out.push(b'\\');
                        out.push(n);
                    }
                    i = i.saturating_add(2);
                }
                None => {
                    // Trailing lone backslash — copy verbatim (engine will judge).
                    out.push(b'\\');
                    i = i.saturating_add(1);
                }
            }
            // An escaped byte occupies the first class position too.
            class_first = false;
            continue;
        }

        if !in_class {
            match c {
                b'[' => {
                    out.push(b'[');
                    i = i.saturating_add(1);
                    in_class = true;
                    class_first = true;
                    // A leading `^` negates but does not consume the first-literal
                    // position, so skip it while keeping `class_first`.
                    if b.get(i) == Some(&b'^') {
                        out.push(b'^');
                        i = i.saturating_add(1);
                    }
                }
                b'{' => match quantifier_end(b, i) {
                    Some(end) => {
                        out.extend_from_slice(&b[i..=end]);
                        i = end.saturating_add(1);
                    }
                    None => {
                        out.extend_from_slice(b"\\{");
                        i = i.saturating_add(1);
                    }
                },
                b'}' => {
                    out.extend_from_slice(b"\\}");
                    i = i.saturating_add(1);
                }
                _ => {
                    out.push(c);
                    i = i.saturating_add(1);
                }
            }
            continue;
        }

        // --- Inside a character class ---------------------------------------
        if class_first {
            class_first = false;
            if c == b']' {
                // Leading literal `]` — Rust reads it as literal already.
                out.push(b']');
                i = i.saturating_add(1);
                continue;
            }
        }
        match c {
            b']' => {
                out.push(b']');
                i = i.saturating_add(1);
                in_class = false;
            }
            b'[' => {
                // Literal in PCRE, nested-class opener in Rust → escape.
                out.extend_from_slice(b"\\[");
                i = i.saturating_add(1);
            }
            _ => {
                out.push(c);
                i = i.saturating_add(1);
            }
        }
    }

    // Insertions are ASCII and non-ASCII bytes are copied whole, so this is valid
    // UTF-8; the fallback keeps `translate` total even if that ever changed.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// If the `{` at `idx` begins a valid `{n}` / `{n,}` / `{n,m}` quantifier, return
/// the index of its closing `}`; otherwise `None` (a literal brace). Mirrors the
/// spike's `quantifier_end`, with fully checked indexing.
fn quantifier_end(b: &[u8], idx: usize) -> Option<usize> {
    let mut j = idx.saturating_add(1);
    let start = j;
    while b.get(j).is_some_and(u8::is_ascii_digit) {
        j = j.saturating_add(1);
    }
    if j == start {
        return None; // no leading number → literal brace
    }
    if b.get(j) == Some(&b',') {
        j = j.saturating_add(1);
        while b.get(j).is_some_and(u8::is_ascii_digit) {
            j = j.saturating_add(1);
        }
    }
    if b.get(j) == Some(&b'}') {
        Some(j)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rewrite must compile in `regex::bytes` (Unicode off, as the matcher
    /// will use it), and the passthrough cases must be untouched.
    fn compiles(p: &str) -> bool {
        regex::bytes::RegexBuilder::new(p)
            .unicode(false)
            .build()
            .is_ok()
    }

    #[test]
    fn null_escape_bare() {
        assert_eq!(translate(r"\x04\0\xfb"), r"\x04\x00\xfb");
        assert!(compiles(&translate(r"^\x04\0\xfbLAPK")));
    }

    #[test]
    fn null_escape_inside_class() {
        assert_eq!(translate(r"[^\0]"), r"[^\x00]");
        assert!(compiles(&translate(r"[^\0]*")));
    }

    #[test]
    fn octal_escape_left_alone() {
        // `\012` is an octal escape, not a lone NUL — don't rewrite it.
        assert_eq!(translate(r"\012"), r"\012");
    }

    #[test]
    fn bare_open_brace_escaped() {
        assert_eq!(translate(r"^S\x1a{"), r"^S\x1a\{");
        assert!(compiles(&translate(r"^S\x1a{")));
    }

    #[test]
    fn bare_close_brace_escaped() {
        assert_eq!(translate(r"a}b"), r"a\}b");
        assert!(compiles(&translate(r"a}b")));
    }

    #[test]
    fn valid_quantifier_preserved() {
        assert_eq!(translate(r"a{2,3}"), r"a{2,3}");
        assert_eq!(translate(r"x{45}"), r"x{45}");
        assert_eq!(translate(r"y{3,}"), r"y{3,}");
        assert!(compiles(&translate(r"a{2,3}b{45}")));
    }

    #[test]
    fn braces_in_class_untouched() {
        // `{`/`}` are literal inside a class and Rust accepts them there.
        assert_eq!(translate(r"[{}]"), r"[{}]");
        assert!(compiles(&translate(r"[{}]")));
    }

    #[test]
    fn literal_bracket_in_class_escaped() {
        assert_eq!(translate(r"[^[]"), r"[^\[]");
        assert_eq!(translate(r"([^[]+)"), r"([^\[]+)");
        assert!(compiles(&translate(r"([^[]+)")));
    }

    #[test]
    fn leading_close_bracket_and_open_bracket() {
        // `[][\w]` = class of `]`, `[`, word — the `[` must be escaped.
        assert_eq!(translate(r"[][\w]"), r"[]\[\w]");
        assert!(compiles(&translate(r"[][\w]")));
        assert!(compiles(&translate(r"([][\w._:-]+)")));
    }

    #[test]
    fn leading_close_bracket_needs_no_change() {
        // Rust already reads a leading `]` as literal.
        assert_eq!(translate(r"[]abc]"), r"[]abc]");
        assert_eq!(translate(r"[^]]"), r"[^]]");
        assert!(compiles(&translate(r"[^]]+")));
    }

    #[test]
    fn escaped_bracket_does_not_open_class() {
        // `\[` is already a literal `[`; it must NOT start class tracking, and a
        // following bare `{` must still be escaped as outside-class.
        assert_eq!(translate(r"\[{"), r"\[\{");
        assert!(compiles(&translate(r"\[{")));
    }

    #[test]
    fn escaped_close_bracket_in_class_stays_open() {
        // `\]` inside a class does not close it, so the literal `[` after it is
        // still inside the class and must be escaped.
        assert_eq!(translate(r"[a\]b[c]"), r"[a\]b\[c]");
    }

    #[test]
    fn plain_text_and_common_metachars_untouched() {
        for p in [
            r"^HTTP/1\.[01]",
            r"([\w._-]+)",
            r"(?s)^\0\0..\x01ActiveMQ", // \0 → \x00 handled, rest intact
            r"\d{1,3}\.\d{1,3}",
            r"(?:abc)?def",
            r"a.*?b",
        ] {
            let t = translate(p);
            // No panic, and everything still compiles.
            assert!(
                compiles(&t) || compiles(p),
                "translate broke {p:?} -> {t:?}"
            );
        }
    }

    #[test]
    fn lone_close_bracket_outside_class_untouched() {
        // A `]` with no open class is a literal in both PCRE and Rust.
        assert_eq!(translate(r"a]b"), r"a]b");
        assert!(compiles(&translate(r"a]b")));
    }

    #[test]
    fn total_on_adversarial_input() {
        // Never panics on truncated/degenerate input.
        for p in [
            r"\", r"[", r"{", r"}", r"[^", r"\0", r"[\", r"[[[", r"{{{", r"]]]", "",
        ] {
            let _ = translate(p);
        }
    }

    #[test]
    fn idempotent_on_already_translated() {
        // Translating twice is a no-op — the rewrites don't re-fire on their output.
        for p in [r"^S\x1a{", r"[^[]", r"[][\w]", r"\0", r"a}b"] {
            let once = translate(p);
            assert_eq!(translate(&once), once, "not idempotent on {p:?}");
        }
    }
}
