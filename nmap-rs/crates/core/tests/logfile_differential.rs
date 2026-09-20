//! Output-filename differential: `core::logfile::expand` must agree with
//! nmap's `logfilename` for every vector in
//! `tests/differential/m7/logfile_vectors/`. Golden from `logfile_oracle`
//! (the C-side verbatim transcription of `output.cc`).
//!
//! The corpus targets the three rules a reimplementation gets wrong — an
//! unrecognised escape drops the `%` and keeps the letter, `%%` is `%`, a
//! trailing `%` vanishes — by crossing every recognised conversion with every
//! unrecognised one, and adding several thousand random strings over the
//! alphabet that matters.
//!
//! The instant is pinned (`EPOCH`) so the golden does not depend on when it was
//! generated, and both sides read UTC.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::logfile::expand;

/// The instant both sides expand against. Any fixed value does; this one is
/// 2026-09-10T00:26:40Z, which has a two-digit month, day, hour and minute and
/// a nonzero second, so a swapped field shows up instead of cancelling out.
const EPOCH: i64 = 1_789_000_000;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/m7/logfile_vectors")
}

#[test]
fn logfilename_matches_the_c_oracle_over_the_corpus() {
    let dir = vectors_dir();
    let corpus = fs::read(dir.join("corpus.bin")).expect("corpus.bin");
    let golden = fs::read_to_string(dir.join("golden.txt")).expect("golden.txt");

    let mut records: Vec<&[u8]> = corpus.split(|b| *b == 0).collect();
    if records.last().is_some_and(|r| r.is_empty()) {
        records.pop();
    }
    let lines: Vec<&str> = golden.lines().collect();
    assert_eq!(records.len(), lines.len(), "corpus/golden record count");

    let mut mismatches = Vec::new();
    for (rec, line) in records.iter().zip(&lines) {
        let Ok(spec) = std::str::from_utf8(rec) else {
            continue;
        };
        // The golden is hex: a filename may contain a tab or a newline, and
        // this corpus deliberately includes both.
        let want = String::from_utf8_lossy(
            &(0..line.len() / 2)
                .filter_map(|i| u8::from_str_radix(line.get(i * 2..i * 2 + 2)?, 16).ok())
                .collect::<Vec<u8>>(),
        )
        .into_owned();
        let got = expand(spec, EPOCH);
        if got != want {
            mismatches.push(format!("expand({spec:?}): C={want:?} rust={got:?}"));
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
