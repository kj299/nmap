//! Corpus gate for `core::osdb::score` against the **real** 5.1 MB `nmap-os-db`, driven
//! by a concrete observed fingerprint.
//!
//! There is no cheap C oracle here — `compare_fingerprints` lives in `osscan.cc`, which
//! pulls in nmap's global option object and most of the tree. So the gate is built from
//! properties that must hold for *any* correct scorer, checked over all 6,108 records:
//!
//!  * every accuracy is a real number in `0.0..=1.0`;
//!  * results are sorted descending, capped, and carry one entry per OS name;
//!  * **the early-exit optimisation never changes a reported answer** — for every record,
//!    the thresholded score either equals the exact score, or is itself below the
//!    threshold (so the record was going to be rejected either way).
//!
//! That last property is the one that matters: it is precisely the argument that makes
//! the C's `max_mismatch` shortcut sound, and it is checked here against every record in
//! the shipped database rather than argued on paper.
//!
//! Skipped under Miri (reads a real file; Miri's filesystem isolation aborts rather than
//! returning `Err`). The unit suite in `osdb::score` is what Miri interrogates.
#![cfg(not(miri))]

use nmap_core::osdb::model::{FingerPrint, FingerPrintDb, MatchPoints};
use nmap_core::osdb::score::{
    compare_fingerprints, match_fingerprint, MatchResults, ScanOutcome, GUESS_THRESHOLD,
    MAX_FP_RESULTS,
};

fn load_corpus() -> Option<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nmap-os-db");
    std::fs::read_to_string(path).ok()
}

/// A concrete observed fingerprint — the kind `osscan2` produces from live probe
/// responses. This is a Linux 3.x-shaped fingerprint: every value is literal, with no
/// expression syntax, exactly as an observation is.
const OBSERVED: &str = "\
Fingerprint observed
SEQ(SP=105%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)
";

fn observed() -> FingerPrint {
    let parsed = FingerPrintDb::parse(OBSERVED);
    assert!(
        parsed.warnings.is_empty(),
        "the observed fingerprint must parse cleanly: {:?}",
        parsed.warnings
    );
    parsed
        .prints
        .into_iter()
        .next()
        .expect("observed fingerprint")
}

/// Invariants every result set must satisfy, whatever the input.
fn check_result_shape(r: &MatchResults) {
    assert!(r.matches.len() <= MAX_FP_RESULTS, "result list overflowed");
    assert!(r.num_perfect_matches <= r.matches.len());

    let mut names: Vec<&str> = Vec::new();
    for (i, m) in r.matches.iter().enumerate() {
        assert!(
            m.accuracy.is_finite() && (0.0..=1.0).contains(&m.accuracy),
            "accuracy {} out of range for {:?}",
            m.accuracy,
            m.os_name
        );
        if let Some(prev) = r.matches.get(i.wrapping_sub(1)) {
            if i > 0 {
                assert!(
                    prev.accuracy >= m.accuracy,
                    "results are not sorted descending at index {i}"
                );
            }
        }
        assert!(
            !names.contains(&m.os_name.as_str()),
            "duplicate OS name in results: {:?}",
            m.os_name
        );
        names.push(&m.os_name);
    }

    let perfect = r.matches.iter().filter(|m| m.accuracy == 1.0).count();
    if r.outcome != Some(ScanOutcome::TooManyMatches) {
        assert_eq!(
            perfect, r.num_perfect_matches,
            "num_perfect_matches disagrees with the list"
        );
    }
}

#[test]
fn scores_the_shipped_database_and_finds_the_right_family() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-os-db not found; skipping osdb score corpus");
        return;
    };
    let db = FingerPrintDb::parse(&text);
    assert!(db.match_points.is_some(), "MatchPoints block required");
    let obs = observed();

    let r = match_fingerprint(&obs, &db, GUESS_THRESHOLD);
    check_result_shape(&r);

    assert_eq!(
        r.outcome,
        Some(ScanOutcome::Success),
        "a realistic Linux fingerprint should match something"
    );
    let best = r.matches.first().expect("at least one match");
    assert!(
        best.accuracy >= GUESS_THRESHOLD,
        "best match {:?} scored only {}",
        best.os_name,
        best.accuracy
    );
    // The observation is Linux-shaped, so the leaders should be Linux. This is the
    // end-to-end signal that the weights, the expression matcher and the ranking all
    // line up — a scorer with, say, the numerator and denominator confused would still
    // satisfy every structural invariant above but fail here.
    for m in r.matches.iter().take(5) {
        eprintln!("{:.4}  {}", m.accuracy, m.os_name);
    }
    let top: Vec<&str> = r
        .matches
        .iter()
        .take(5)
        .map(|m| m.os_name.as_str())
        .collect();
    assert!(
        top.iter().any(|n| n.contains("Linux")),
        "expected Linux among the top matches, got {top:?}"
    );

    // The index must point back at the record that produced the score.
    for m in &r.matches {
        assert_eq!(db.prints[m.index].os_name, m.os_name);
    }
}

#[test]
fn the_early_exit_never_changes_a_reported_answer() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-os-db not found; skipping osdb score corpus");
        return;
    };
    let db = FingerPrintDb::parse(&text);
    let Some(points) = db.match_points.as_ref() else {
        return;
    };
    let obs = observed();

    let mut exact_above_threshold = 0usize;
    for reference in &db.prints {
        let full = compare_fingerprints(reference, &obs, points, 0.0);
        let fast = compare_fingerprints(reference, &obs, points, GUESS_THRESHOLD);
        assert!(
            full.is_finite() && (0.0..=1.0).contains(&full),
            "line {}: exact score {full} out of range",
            reference.line
        );
        if full >= GUESS_THRESHOLD {
            assert_eq!(
                fast, full,
                "line {}: the early exit must not truncate a qualifying score",
                reference.line
            );
            exact_above_threshold += 1;
        } else {
            // Note the early-exit score is *not* a lower bound: abandoning the remaining
            // tests drops their mismatches too, so the partial ratio can sit above the
            // exact one. What is guaranteed is that it stays below the threshold, which
            // is all the caller is allowed to conclude from it.
            assert!(
                fast == full || fast < GUESS_THRESHOLD,
                "line {}: early-exit score {fast} (exact {full}) reached the threshold",
                reference.line
            );
        }
    }
    assert!(
        exact_above_threshold > 0,
        "no record cleared the threshold, so the invariant was never exercised"
    );
}

#[test]
fn a_zero_threshold_admits_everything_without_aborting() {
    // The C's insertion scan `fatal()`s when a zero-scoring record is admitted, which a
    // zero threshold makes reachable. Over the real database that path is taken for real.
    let Some(text) = load_corpus() else {
        eprintln!("nmap-os-db not found; skipping osdb score corpus");
        return;
    };
    let db = FingerPrintDb::parse(&text);
    let obs = observed();

    let r = match_fingerprint(&obs, &db, 0.0);
    check_result_shape(&r);
    assert_ne!(r.outcome, Some(ScanOutcome::NoMatches));
    assert_eq!(
        r.matches.len(),
        MAX_FP_RESULTS,
        "a zero threshold should fill the list"
    );
}

#[test]
fn an_empty_observation_scores_nothing_against_the_whole_database() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-os-db not found; skipping osdb score corpus");
        return;
    };
    let db = FingerPrintDb::parse(&text);

    // No observed attributes means no shared attributes anywhere: every record scores 0.
    let r = match_fingerprint(&FingerPrint::default(), &db, GUESS_THRESHOLD);
    assert_eq!(r.outcome, Some(ScanOutcome::NoMatches));
    assert!(r.matches.is_empty());

    // And with the weights removed, even a good observation scores nothing.
    let stripped = FingerPrintDb {
        match_points: Some(MatchPoints::default()),
        prints: db.prints,
        warnings: Vec::new(),
    };
    let r = match_fingerprint(&observed(), &stripped, GUESS_THRESHOLD);
    assert_eq!(r.outcome, Some(ScanOutcome::NoMatches));
}
