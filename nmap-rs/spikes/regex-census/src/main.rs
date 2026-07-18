//! M3 corpus-validation spike — compile every `nmap-service-probes` match
//! pattern through Rust's `regex` (linear-time, no backtracking) and, on
//! rejection, through `fancy-regex` (bounded backtracking for lookaround /
//! backrefs). Turns the Phase-0 feature-grep estimate (~7% need backtracking)
//! into real accept/reject numbers, and surfaces any pattern *neither* engine
//! accepts — the set that would need a divergence or a break-glass PCRE2 path.
//!
//! Usage: regex-census [PATH_TO_nmap-service-probes]   (default ./nmap-service-probes)
//!
//! Measurement only — it compiles, it does not match. This is a spike: its
//! output is a finding, not shipped code.

use std::fmt::Write as _;

#[derive(Default)]
struct Tally {
    total: usize,
    regex_ok: usize,
    fancy_only: usize,
    both_fail: usize,
    fancy_fail_samples: Vec<String>,
    both_fail_samples: Vec<String>,
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nmap-service-probes".to_string());
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {path:?}: {e}");
            std::process::exit(2);
        }
    };

    let mut t = Tally::default();
    for line in text.lines() {
        let Some((pattern, flags)) = extract_match_regex(line) else {
            continue;
        };
        t.total += 1;
        // Service banners are raw BYTES, not UTF-8 — so the engine that matters
        // is `regex::bytes` with Unicode mode OFF (so `.` and classes range over
        // bytes and `\xff` is a byte, not a codepoint). nmap flags: 'i' = caseless,
        // 's' = dotall.
        let caseless = flags.contains('i');
        let dotall = flags.contains('s');
        // SPIKE FINDING: nmap-service-probes is PCRE syntax; Rust `regex` differs
        // in small but pervasive ways. A minimal translation pass recovers most of
        // the "failures" that are syntax, not semantics — quantifying how much is
        // the point of this run. Toggle with env REGEX_CENSUS_RAW=1 to see raw.
        let pattern = if std::env::var("REGEX_CENSUS_RAW").is_ok() {
            pattern
        } else {
            translate_pcre_to_rust(&pattern)
        };
        let regex_bytes_ok = regex::bytes::RegexBuilder::new(&pattern)
            .unicode(false)
            .case_insensitive(caseless)
            .dot_matches_new_line(dotall)
            .build()
            .is_ok();

        if regex_bytes_ok {
            t.regex_ok += 1;
            continue;
        }
        // Fallback: fancy-regex (bounded backtracking) — but it is `&str`-only,
        // so express flags inline. A binary pattern that also needs backtracking
        // is the genuinely hard set (tracked separately).
        let mut prefix = String::new();
        if caseless {
            prefix.push_str("(?i)");
        }
        if dotall {
            prefix.push_str("(?s)");
        }
        let full = format!("{prefix}{pattern}");
        if fancy_regex::Regex::new(&full).is_ok() {
            t.fancy_only += 1;
            if t.fancy_fail_samples.len() < 12 {
                t.fancy_fail_samples.push(truncate(&full));
            }
        } else {
            t.both_fail += 1;
            if t.both_fail_samples.len() < 20 {
                t.both_fail_samples.push(truncate(&full));
            }
        }
    }

    if t.total == 0 {
        eprintln!("error: no match/softmatch patterns found in {path:?} (wrong file?)");
        std::process::exit(2);
    }
    report(&t);
    // The spike's gate: nothing may be un-portable without an explicit plan.
    if t.both_fail > 0 {
        eprintln!(
            "\nNOTE: {} pattern(s) compile in NEITHER engine — each needs a \
             DIVERGENCES.md entry or the break-glass PCRE2 path.",
            t.both_fail
        );
    }
}

/// Extract the regex body and trailing flags from a `match`/`softmatch` line.
/// Format: `match <svc> m<DELIM><regex><DELIM><flags> <version template...>`.
/// The delimiter is the punctuation char right after `m`; `\<DELIM>` inside the
/// body is an escaped literal, not the terminator.
fn extract_match_regex(line: &str) -> Option<(String, String)> {
    let rest = line
        .strip_prefix("match ")
        .or_else(|| line.strip_prefix("softmatch "))?;
    // Skip the service name and any whitespace up to `m<DELIM>`.
    let m_idx = rest.find(" m").map(|i| i + 1)?;
    let after_m = &rest[m_idx + 1..]; // char after 'm'
    let mut chars = after_m.char_indices();
    let (_, delim) = chars.next()?;
    if delim.is_alphanumeric() {
        return None; // not a delimiter form we understand
    }
    let body = &after_m[delim.len_utf8()..];
    let mut pattern = String::new();
    let mut escaped = false;
    let mut end = None;
    for (i, c) in body.char_indices() {
        if escaped {
            pattern.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            pattern.push(c);
            escaped = true;
            continue;
        }
        if c == delim {
            end = Some(i);
            break;
        }
        pattern.push(c);
    }
    let end = end?;
    // Flags are the run of ascii letters immediately after the closing delimiter.
    let tail = &body[end + delim.len_utf8()..];
    let flags: String = tail
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    Some((pattern, flags))
}

/// Minimal PCRE→Rust-`regex` syntax translation — enough to quantify how much of
/// the "failure" set is syntax rather than genuine backtracking need. This is the
/// spike's core finding: nmap uses a handful of PCRE spellings Rust rejects.
///   - `\0` (null) → `\x00`         (Rust needs the hex form)
///   - a bare `{`/`}` that isn't part of a `{n}`/`{n,}`/`{n,m}` quantifier → escaped
/// A production port would grow this into `core::pcre_translate` with a full
/// test corpus; here it exists only to size the work.
fn translate_pcre_to_rust(pat: &str) -> String {
    let b = pat.as_bytes();
    let mut out = String::with_capacity(pat.len() + 8);
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'\\' && i + 1 < b.len() {
            let n = b[i + 1];
            // `\0` not followed by another octal digit → null byte in hex form.
            if n == b'0' && !(i + 2 < b.len() && b[i + 2].is_ascii_digit()) {
                out.push_str("\\x00");
                i += 2;
                continue;
            }
            // keep any other escape verbatim (two bytes)
            out.push('\\');
            out.push(n as char);
            i += 2;
            continue;
        }
        if c == b'{' {
            if let Some(end) = quantifier_end(b, i) {
                // Copy the whole `{n,m}` token verbatim so its `}` stays a closer.
                for &q in &b[i..=end] {
                    out.push(q as char);
                }
                i = end + 1;
                continue;
            }
            out.push_str("\\{"); // bare literal brace
            i += 1;
            continue;
        }
        if c == b'}' {
            // Any `}` reached here is bare (quantifier closers were consumed above).
            out.push_str("\\}");
            i += 1;
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out
}

/// If the `{` at `idx` begins a valid `{n}` / `{n,}` / `{n,m}` quantifier, return
/// the index of its closing `}`; else `None` (a literal brace).
fn quantifier_end(b: &[u8], idx: usize) -> Option<usize> {
    let mut j = idx + 1;
    let start = j;
    while j < b.len() && b[j].is_ascii_digit() {
        j += 1;
    }
    if j == start {
        return None; // no leading number → literal brace
    }
    if j < b.len() && b[j] == b',' {
        j += 1;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
    }
    if j < b.len() && b[j] == b'}' {
        Some(j)
    } else {
        None
    }
}

fn truncate(s: &str) -> String {
    let max = 88;
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

fn report(t: &Tally) {
    let pct = |n: usize| 100.0 * n as f64 / t.total as f64;
    let mut out = String::new();
    let _ = writeln!(out, "nmap-service-probes regex corpus — engine census");
    let _ = writeln!(out, "  total match/softmatch patterns : {}", t.total);
    let _ = writeln!(
        out,
        "  compile in `regex::bytes` (linear): {:6}  ({:.2}%)",
        t.regex_ok,
        pct(t.regex_ok)
    );
    let _ = writeln!(
        out,
        "  need `fancy-regex` (backtracking) : {:6}  ({:.2}%)",
        t.fancy_only,
        pct(t.fancy_only)
    );
    let _ = writeln!(
        out,
        "  compile in NEITHER engine        : {:6}  ({:.2}%)",
        t.both_fail,
        pct(t.both_fail)
    );
    print!("{out}");

    if !t.fancy_fail_samples.is_empty() {
        println!("\nsample patterns that need the backtracking fallback:");
        for s in &t.fancy_fail_samples {
            println!("    {s}");
        }
    }
    if !t.both_fail_samples.is_empty() {
        println!("\npatterns rejected by BOTH engines (need triage):");
        for s in &t.both_fail_samples {
            println!("    {s}");
        }
    }
}
