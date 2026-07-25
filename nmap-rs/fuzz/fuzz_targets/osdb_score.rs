// cargo-fuzz target for `nmap_core::osdb::score`.
//
// Both sides of the scorer are attacker-influenced. The reference database comes from
// `--osscandb <file>`, and the observed fingerprint is built from probe responses that
// a target host chooses freely — so a hostile host picks the observed values and, in the
// worst case, a hostile file picks the expressions they are matched against.
//
// The C has three ways to die on this path: `AVal_match` fatal()s on a negative point
// value, `match_fingerprint` fatal()s when its fixed-size insertion scan finds no slot
// (reachable whenever a zero-scoring record is admitted), and it dereferences
// `DB->MatchPoints` with no null check. The contract enforced here is that scoring is
// TOTAL — any database and any observation produce a result and never panic — plus the
// structural invariants the caller relies on.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::osdb::model::{FingerPrint, FingerPrintDb};
use nmap_core::osdb::score::{
    compare_fingerprints, match_fingerprint, ScanOutcome, GUESS_THRESHOLD, MAX_FP_RESULTS,
};

// Splits the input into the reference database and the observed fingerprint. Inputs with
// no separator are scored against an empty observation, which is itself worth exercising.
const SEP: &str = "\n%%%\n";

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (db_text, obs_text) = text.split_once(SEP).unwrap_or((text, ""));

    let db = FingerPrintDb::parse(db_text);
    let observed = FingerPrintDb::parse(obs_text)
        .prints
        .into_iter()
        .next()
        .unwrap_or_default();

    // A NaN or out-of-range threshold must be handled, not turned into the C's undefined
    // double-to-unsigned-long conversion. 0.0 is the value that makes the C's fatal()
    // insertion path reachable.
    for threshold in [GUESS_THRESHOLD, 0.0, 1.0, -1.0, 2.0, f64::NAN, f64::INFINITY] {
        let r = match_fingerprint(&observed, &db, threshold);

        assert!(r.matches.len() <= MAX_FP_RESULTS);
        assert!(r.num_perfect_matches <= r.matches.len());

        let mut previous = f64::INFINITY;
        for m in &r.matches {
            assert!(
                m.accuracy.is_finite() && (0.0..=1.0).contains(&m.accuracy),
                "accuracy out of range"
            );
            assert!(previous >= m.accuracy, "results not sorted descending");
            previous = m.accuracy;
            // The index must address a real record, and name it correctly.
            let reference = &db.prints[m.index];
            assert_eq!(reference.os_name, m.os_name);
            // One entry per OS name.
            assert_eq!(
                r.matches.iter().filter(|o| o.os_name == m.os_name).count(),
                1,
                "duplicate OS name in results"
            );
        }

        if r.matches.is_empty() {
            assert!(matches!(
                r.outcome,
                Some(ScanOutcome::NoMatches) | Some(ScanOutcome::TooManyMatches)
            ));
        }
    }

    // Direct scoring, including the degenerate pairings the driver above may never reach.
    if let Some(points) = db.match_points.as_ref() {
        let empty = FingerPrint::default();
        for reference in db.prints.iter().take(64) {
            let exact = compare_fingerprints(reference, &observed, points, 0.0);
            assert!(exact.is_finite() && (0.0..=1.0).contains(&exact));

            // The early exit must never keep a score that would have qualified, and must
            // never invent one that reaches the bar. (It is deliberately not a lower
            // bound — abandoning the remaining tests drops their mismatches too.)
            let fast = compare_fingerprints(reference, &observed, points, GUESS_THRESHOLD);
            assert!(fast.is_finite() && (0.0..=1.0).contains(&fast));
            if exact >= GUESS_THRESHOLD {
                assert_eq!(fast, exact, "early exit truncated a qualifying score");
            } else {
                assert!(
                    fast == exact || fast < GUESS_THRESHOLD,
                    "early-exit score reached the threshold"
                );
            }

            assert_eq!(compare_fingerprints(reference, &empty, points, 0.0), 0.0);
            assert_eq!(compare_fingerprints(&empty, reference, points, 0.0), 0.0);
        }
    }
});
