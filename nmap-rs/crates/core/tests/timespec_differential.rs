//! Time-specification differential: `core::timespec` must agree with nmap's
//! `tval2secs` / `tval2msecs` / `tval_unit` for every vector in
//! `tests/differential/m7/tval_vectors/`. Golden from `tval_oracle` (the C-side
//! verbatim transcription of `nbase/nbase_misc.c`).
//!
//! The corpus mixes hand-picked cases (every claim the module's docs make, plus
//! the two inputs that reach C's undefined `double`->`long` conversion) with a
//! systematic number x unit x decoration cross-product and several thousand
//! random strings over the alphabet that matters — digits, signs, dots, `e`,
//! `x`, `p`, and the unit letters.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::timespec::{tval2msecs, tval2secs, tval_unit, TimeSpecError};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/m7/tval_vectors")
}

/// The oracle emits the double's raw IEEE bits, so the comparison is exact and
/// no printf-format reimplementation sits between the two sides. NaN payloads
/// are normalised: C's `(double) NAN` and Rust's `f64::NAN` need not share a
/// bit pattern, and nothing downstream can observe the difference.
fn bits(v: f64) -> String {
    if v.is_nan() {
        return "nan".to_string();
    }
    format!("{:016x}", v.to_bits())
}

#[test]
fn timespec_matches_the_c_oracle_over_the_corpus() {
    let dir = vectors_dir();
    let corpus = fs::read(dir.join("corpus.bin")).expect("corpus.bin — run build_tval_oracle.sh");
    let golden = fs::read_to_string(dir.join("golden.txt")).expect("golden.txt");

    let mut records: Vec<&[u8]> = corpus.split(|b| *b == 0).collect();
    // The corpus ends with a separator, so the split yields a trailing empty
    // record the oracle's loop does not emit.
    if records.last().is_some_and(|r| r.is_empty()) {
        records.pop();
    }
    let lines: Vec<&str> = golden.lines().collect();
    assert_eq!(
        records.len(),
        lines.len(),
        "corpus and golden disagree on record count"
    );

    let mut mismatches = Vec::new();
    for (rec, line) in records.iter().zip(&lines) {
        let Ok(spec) = std::str::from_utf8(rec) else {
            continue;
        };
        let mut cols = line.split('\t');
        let (c_secs, c_msecs, c_unit) = (
            cols.next().unwrap_or(""),
            cols.next().unwrap_or(""),
            cols.next().unwrap_or(""),
        );

        // Any NaN bit pattern normalises to "nan": strtod's `nan(123)` form
        // puts 123 in the payload, and no caller can observe a payload.
        let c_secs = match u64::from_str_radix(c_secs, 16) {
            Ok(b) if f64::from_bits(b).is_nan() => "nan".to_string(),
            _ => c_secs.to_string(),
        };
        let r_secs = bits(tval2secs(spec));
        if r_secs != c_secs {
            mismatches.push(format!("tval2secs({spec:?}): C={c_secs} rust={r_secs}"));
        }

        let c_ms: i64 = c_msecs.parse().unwrap_or(0);
        match tval2msecs(spec) {
            Ok(v) => {
                if v != c_ms {
                    mismatches.push(format!("tval2msecs({spec:?}): C={c_ms} rust={v}"));
                }
            }
            Err(TimeSpecError::Unparseable) => {
                // C's -1, or one of the two values its broken range guard lets
                // through to an undefined conversion. Every caller rejects a
                // negative, so a refusal here must line up with a negative
                // there -- and must never hide a value C would have accepted.
                if c_ms >= 0 {
                    mismatches.push(format!(
                        "tval2msecs({spec:?}): rust refused but C returned {c_ms}, which callers accept"
                    ));
                }
            }
        }

        // The unit is hex in the golden: it is a suffix of the record, so it
        // can contain a tab or a newline and would otherwise break the framing.
        let r_unit = match tval_unit(spec) {
            None => "-".to_string(),
            Some(u) => u.bytes().map(|b| format!("{b:02x}")).collect(),
        };
        if r_unit != c_unit {
            mismatches.push(format!("tval_unit({spec:?}): C={c_unit} rust={r_unit}"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} of {} vectors diverge from the C oracle:\n{}",
        mismatches.len(),
        records.len(),
        mismatches
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
