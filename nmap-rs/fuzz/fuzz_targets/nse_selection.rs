// cargo-fuzz target for `nmap_core::nse::selection::matches`.
//
// The `--script` expression grammar decides which scripts a run selects. nmap
// evaluates it with LPeg, which has a fixed backtrack stack and raises a Lua
// error when it runs out; this port has no such ceiling, so totality is on the
// port to prove:
//
//   * matching is TOTAL for any rule, filename and category list -- no panic,
//     no unbounded recursion, no quadratic-or-worse blowup;
//   * the result is deterministic, so nothing depends on allocation addresses
//     or iteration order;
//   * the declared bounds are honoured, and a refusal is always one of the
//     three declared reasons.
//
// The recursion check earns its keep. The grammar's three alternatives all
// begin by parsing the same `value`, so transcribing them literally re-parses
// it up to four times per level and makes nested parentheses cost 4^depth --
// 160ms at eight parentheses, before that was folded into a single pass. The C
// has the same shape and is saved only by its low LPeg ceiling.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::selection::{
    basename_of, matches, normalize, split_arg, Entry, SelectionError, MAX_NESTING, MAX_RULE_LEN,
};

/// Carve the input into a rule, a filename and up to eight categories.
///
/// A NUL separates the fields, which keeps the corpus readable and lets the
/// fuzzer discover structure by editing bytes rather than by guessing a length
/// prefix. NUL is outside the grammar's path character class, so it cannot
/// appear inside a rule that parses -- using it as the separator costs no
/// coverage.
fn carve(data: &[u8]) -> (&[u8], &[u8], Vec<&[u8]>) {
    let mut parts = data.split(|&b| b == 0);
    let rule = parts.next().unwrap_or(b"");
    let filename = parts.next().unwrap_or(b"");
    let categories: Vec<&[u8]> = parts.take(8).collect();
    (rule, filename, categories)
}

/// The bytes LPeg's `locale().space` accepts. Rust's `is_ascii_whitespace`
/// is NOT the same set -- it omits the vertical tab (0x0b) -- so asserting with
/// it would be asserting against a different definition than the port uses.
fn is_lua_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ')
}

fuzz_target!(|data: &[u8]| {
    let (rule, filename, categories) = carve(data);

    // `basename_of` is total and never grows its input.
    let basename = basename_of(filename);
    assert!(basename.len() <= filename.len());
    assert!(!basename.contains(&b'/') && !basename.contains(&b'\\'));

    let entry = Entry::from_filename(filename, &categories);
    assert_eq!(entry.basename, basename);

    let first = matches(rule, &entry);

    // Deterministic: the same inputs give the same answer, every time.
    assert_eq!(first, matches(rule, &entry), "matching is not deterministic");

    match first {
        Ok(selection) => {
            // A rule that selects nothing cannot claim to have selected by
            // name for a reason that matters, but the reverse IS allowed: a
            // glob can match inside a negated branch, so `by_name` without
            // `matched` is legitimate and deliberately not asserted against.
            let _ = selection.matched;
            let _ = selection.by_name;
        }
        Err(SelectionError::TooLong) => {
            assert!(rule.len() > MAX_RULE_LEN, "TooLong for a rule within bounds");
        }
        Err(SelectionError::TooDeep) => {
            // Reaching the depth bound requires at least that many nesting
            // characters in the rule.
            assert!(
                rule.len() >= MAX_NESTING / 2,
                "TooDeep for a rule too short to nest that far"
            );
        }
        Err(SelectionError::NotAnExpression) => {}
    }

    // Normalisation peels exactly ONE `+`, so it is deliberately not idempotent:
    // `++safe` normalises to `+safe`, and normalising that again gives `safe`.
    // The fuzzer found this by asserting the stronger property, which the C does
    // not have either -- reaching for idempotence here would have meant
    // "fixing" the port away from `nse_main.lua:726`. What does hold is that a
    // result which no longer starts with `+` is a fixed point.
    if let Some(normalised) = normalize(rule) {
        assert!(!normalised.text.is_empty());
        // A normalised rule has no leading or trailing whitespace left, and is
        // always a contiguous piece of the input.
        assert!(!is_lua_space(normalised.text[0]));
        assert!(!is_lua_space(normalised.text[normalised.text.len() - 1]));
        assert!(normalised.text.len() <= rule.len());

        match normalize(normalised.text) {
            Some(again) if normalised.text[0] == b'+' => {
                assert!(again.forced, "a leading `+` should be peeled on the next pass");
            }
            Some(again) => {
                assert_eq!(
                    again.text, normalised.text,
                    "a rule with no `+` left should be a fixed point"
                );
                assert!(!again.forced);
            }
            // A second pass CAN empty the rule, but only in one way: `++`
            // normalises to a bare `+`, which then normalises away. The fuzzer
            // found this too.
            None => assert_eq!(
                normalised.text, b"+",
                "only a bare `+` may normalise away on the second pass"
            ),
        }
    }

    // Splitting an argument loses nothing: re-joining with commas is exact.
    let pieces = split_arg(data);
    assert!(!pieces.is_empty(), "split_arg always yields at least one rule");
    assert_eq!(
        pieces.len(),
        data.iter().filter(|&&b| b == b',').count() + 1,
        "split_arg produced the wrong number of rules"
    );
    let rejoined = pieces.join(&b","[..]);
    assert_eq!(rejoined, data, "split_arg is not a lossless split");
    for piece in &pieces {
        assert!(!piece.contains(&b','), "a split rule still contains a comma");
    }
});
