//! Corpus/differential gate for `core::osdb::parse` against the **real** 5.1 MB
//! `nmap-os-db` shipped in the C tree.
//!
//! The oracle is the file's own ground truth: the C parser, on a well-formed database,
//! builds exactly one record per `Fingerprint` line, one classification per `Class`
//! line, one CPE per `CPE` line, and one test per `TEST(...)` line — no line dropped.
//! Those counts are what `grep -c` over the file yields, which is what the C must also
//! produce, so agreement is a real cross-check rather than self-consistency.
//!
//! Ground truth (from the shipped file):
//! ```text
//!   Fingerprint records : 6108
//!   Class lines         : 7100
//!   CPE lines           : 6968
//!   MatchPoints blocks  :    1
//!   TEST(...) lines     : 79417   (only SEQ OPS WIN ECN T1-T7 U1 IE occur), of which
//!                                   13 belong to the MatchPoints block, leaving 79404
//!                                   attached to fingerprint records
//!   total lines         : 116271
//! ```
//!
//! A clean file must parse with **zero warnings** — any warning here is a real
//! divergence from the C parser to investigate.
//!
//! Skipped under Miri: it reads a real file, and Miri's filesystem isolation *aborts*
//! rather than returning `Err` (the unit suite in `osdb::parse` is what Miri
//! interrogates).
#![cfg(not(miri))]

use nmap_core::osdb::model::{FingerPrintDb, TestId};

/// Locate the shipped database relative to this crate (repo-root sibling of `nmap-rs/`).
/// Skips (does not fail) if absent, so a stripped checkout still builds.
fn load_corpus() -> Option<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nmap-os-db");
    std::fs::read_to_string(path).ok()
}

const FINGERPRINTS: usize = 6108;
const CLASS_LINES: usize = 7100;
const CPE_LINES: usize = 6968;
/// `TEST(...)` lines attached to fingerprint records. The file has 79,417 in total; the
/// first 13 are the MatchPoints block, which becomes the scoring table rather than any
/// record's tests (verified: the block holds exactly one line per test).
const TEST_LINES: usize = 79_404;

#[test]
fn parses_the_shipped_database_with_no_warnings() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-os-db not found; skipping osdb corpus");
        return;
    };
    let db = FingerPrintDb::parse(&text);

    for w in db.warnings.iter().take(5) {
        eprintln!("unexpected warning at line {}: {}", w.line, w.message);
    }
    assert!(
        db.warnings.is_empty(),
        "the shipped database must parse cleanly, got {} warnings",
        db.warnings.len()
    );

    assert_eq!(db.prints.len(), FINGERPRINTS, "Fingerprint record count");
    assert!(
        db.match_points.is_some(),
        "MatchPoints block must be parsed"
    );

    let classes: usize = db.prints.iter().map(|p| p.classes.len()).sum();
    assert_eq!(classes, CLASS_LINES, "Class line count");

    let cpes: usize = db
        .prints
        .iter()
        .flat_map(|p| p.classes.iter())
        .map(|c| c.cpe.len())
        .sum();
    assert_eq!(cpes, CPE_LINES, "CPE line count");

    let tests: usize = db.prints.iter().map(|p| p.tests.len()).sum();
    assert_eq!(tests, TEST_LINES, "TEST(...) line count");
}

#[test]
fn every_record_is_well_formed() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-os-db not found; skipping osdb corpus");
        return;
    };
    let db = FingerPrintDb::parse(&text);
    if db.prints.is_empty() {
        return;
    }

    for fp in &db.prints {
        assert!(!fp.os_name.is_empty(), "line {}: empty OS name", fp.line);
        assert!(fp.line > 0, "record has no line number");
        assert!(
            !fp.tests.is_empty(),
            "line {}: record {:?} has no tests",
            fp.line,
            fp.os_name
        );
        // Every test must be one of the 13 and carry the right number of slots.
        for t in &fp.tests {
            assert_eq!(
                t.values.len(),
                t.id.attrs().len(),
                "line {}: {} has the wrong slot count",
                fp.line,
                t.id.name()
            );
        }
        // A record's tests are distinct — the C stores them in a fixed-size array
        // indexed by test id, so a duplicate would silently overwrite.
        let mut ids: Vec<TestId> = fp.tests.iter().map(|t| t.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "line {}: duplicate test", fp.line);
    }
}

#[test]
fn match_points_are_populated_and_drive_the_totals() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-os-db not found; skipping osdb corpus");
        return;
    };
    let db = FingerPrintDb::parse(&text);
    let Some(mp) = db.match_points.as_ref() else {
        panic!("no MatchPoints block parsed");
    };

    // Spot-check the weights against the file's own MatchPoints block.
    assert_eq!(
        mp.get(TestId::Seq, TestId::Seq.attr_index("SP").unwrap()),
        25
    );
    assert_eq!(
        mp.get(TestId::Seq, TestId::Seq.attr_index("TI").unwrap()),
        100
    );
    assert_eq!(
        mp.get(TestId::Ops, TestId::Ops.attr_index("O1").unwrap()),
        20
    );
    assert_eq!(
        mp.get(TestId::Win, TestId::Win.attr_index("W1").unwrap()),
        15
    );
    assert_eq!(mp.get(TestId::T1, TestId::T1.attr_index("R").unwrap()), 100);

    // Every weight the block defines is positive, and every record accumulated a
    // non-zero denominator — a zero would make the scorer divide by nothing.
    for fp in &db.prints {
        assert!(
            fp.num_points > 0,
            "line {}: record {:?} has no points available",
            fp.line,
            fp.os_name
        );
    }
}

#[test]
fn attribute_values_are_matchable_expressions() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-os-db not found; skipping osdb corpus");
        return;
    };
    let db = FingerPrintDb::parse(&text);
    if db.prints.is_empty() {
        return;
    }

    // Every value in the database must be something `expr_match` can evaluate without
    // panicking — this ties the parser to the matcher over the real corpus. `OPS`/`O*`
    // values are the ones the C evaluates with nesting enabled.
    let mut evaluated = 0usize;
    for fp in &db.prints {
        for t in &fp.tests {
            for (i, value) in t.values.iter().enumerate() {
                let Some(v) = value else { continue };
                let nested = t.id == TestId::Ops || t.id.attrs()[i] == "O";
                for probe in ["", "0", "5", "FF", "M5B4ST11NW7"] {
                    let _ =
                        nmap_core::osdb::expr::expr_match(probe.as_bytes(), v.as_bytes(), nested);
                }
                evaluated += 1;
            }
        }
    }
    assert!(
        evaluated > 100_000,
        "expected to evaluate the whole database, only saw {evaluated} values"
    );
}
