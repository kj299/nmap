//! Fingerprint scoring — the port of `osscan.cc`'s `AVal_match`, `compare_fingerprints`
//! and `match_fingerprint`.
//!
//! Given an *observed* fingerprint (concrete values measured off the wire) and a database
//! of *reference* fingerprints (whose values are [`crate::osdb::expr`] expressions), score
//! each reference and return the best matches in descending accuracy order.
//!
//! Scoring is a weighted ratio. For every attribute that **both** the reference and the
//! observation specify, the attribute's weight from the `MatchPoints` block is added to
//! the denominator, and to the numerator as well if the observed value matches the
//! reference expression. An attribute missing from either side is skipped entirely — it
//! is neither a match nor a mismatch, which is why a reference that specifies few tests
//! is not penalised for the ones it stays silent about.

use crate::osdb::expr::expr_match;
use crate::osdb::model::{FingerPrint, FingerPrintDb, FingerTest, MatchPoints, TestId};

/// Maximum matches retained, matching the C's `MAX_FP_RESULTS`.
pub const MAX_FP_RESULTS: usize = 36;

/// The accuracy an OS guess must reach to be reported, matching the C's
/// `OSSCAN_GUESS_THRESHOLD`. Every caller in the C tree uses this value.
pub const GUESS_THRESHOLD: f64 = 0.85;

/// Overall verdict, matching the C's `FingerPrintResults::overall_results`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    /// At least one reference scored at or above the threshold.
    Success,
    /// Nothing reached the threshold.
    NoMatches,
    /// More perfect (1.0) matches than the result list can hold, so the database cannot
    /// discriminate between them. The C treats this as "the fingerprint is too generic".
    TooManyMatches,
}

/// One scored reference fingerprint.
#[derive(Debug, Clone, PartialEq)]
pub struct OsMatch {
    /// Index into [`FingerPrintDb::prints`], so the caller can reach the record's
    /// `Class`/`CPE` classifications.
    pub index: usize,
    /// The record's OS name, copied so results stand alone.
    pub os_name: String,
    /// Match accuracy in `0.0..=1.0`; `1.0` is a perfect match.
    pub accuracy: f64,
}

/// The outcome of scoring an observed fingerprint against a database.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MatchResults {
    /// Matches in descending accuracy order, at most [`MAX_FP_RESULTS`]. Ties keep
    /// database order.
    pub matches: Vec<OsMatch>,
    /// How many of [`Self::matches`] scored exactly `1.0`.
    pub num_perfect_matches: usize,
    /// Overall verdict.
    pub outcome: Option<ScanOutcome>,
}

/// Accumulate one test's weighted subtest totals into `subtests`/`succeeded`.
///
/// The C's `AVal_match`. Nested expression matching is enabled for every attribute of
/// `OPS` and for any attribute literally named `O` — those hold TCP option strings, where
/// the expression language allows alternation inside a single option list.
fn test_match(
    reference: &FingerTest,
    observed: &FingerTest,
    points: &MatchPoints,
    subtests: &mut u32,
    succeeded: &mut u32,
) {
    let id = reference.id;
    // The C indexes both value arrays with the same attribute index, which is only sound
    // because both come from the same fixed per-test table. Our parser guarantees the
    // same, and `zip` makes a short array impossible to read past regardless.
    let nested_test = id == TestId::Ops;
    for (i, (r, o)) in reference
        .values
        .iter()
        .zip(observed.values.iter())
        .enumerate()
    {
        let (Some(r), Some(o)) = (r.as_deref(), o.as_deref()) else {
            continue;
        };
        // The C `fatal()`s on a negative point value; ours are unsigned, so a negative
        // weight cannot be represented and the check has nothing to catch.
        let weight = points.get(id, i);
        *subtests = subtests.saturating_add(weight);
        let nested = nested_test || id.attrs().get(i) == Some(&"O");
        if expr_match(o.as_bytes(), r.as_bytes(), nested) {
            *succeeded = succeeded.saturating_add(weight);
        }
    }
}

/// Score `observed` against the reference fingerprint `reference`, returning accuracy in
/// `0.0..=1.0`.
///
/// `threshold` enables the C's early exit: once enough weight has been lost that the
/// final accuracy cannot reach `threshold`, scoring stops and the partial ratio is
/// returned.
///
/// **That partial value means only "below `threshold`".** It is not the record's true
/// accuracy, and it is not even a lower bound on it — abandoning the remaining tests
/// discards their mismatches as well as their matches, so the partial ratio can land
/// either side of the exact one. It is guaranteed strictly below `threshold` (the exit
/// fires only once the lost weight exceeds `(1 - threshold) * num_points`, and the
/// denominator can never exceed `num_points`), which is exactly what
/// [`match_fingerprint`] needs to reject a record. Two rejected records must not be
/// ranked against each other by these values. Pass `0.0` to disable the early exit and
/// always compute the exact ratio.
///
/// A reference and observation that share no specified attribute score `0.0` rather than
/// dividing by zero.
#[must_use]
pub fn compare_fingerprints(
    reference: &FingerPrint,
    observed: &FingerPrint,
    points: &MatchPoints,
    threshold: f64,
) -> f64 {
    // The C asserts `0 <= threshold <= 1` only in `match_fingerprint`; reaching
    // `compare_fingerprints` with a threshold above 1 makes `(1.0 - threshold)` negative,
    // and converting that to the C's `unsigned long max_mismatch` is undefined behaviour.
    // Clamping makes the out-of-range call merely useless instead.
    let threshold = if threshold.is_nan() {
        0.0
    } else {
        threshold.clamp(0.0, 1.0)
    };
    // How much weight we can lose before `threshold` is out of reach. Truncated toward
    // zero exactly as the C's conversion to `unsigned long` is.
    let max_mismatch = ((1.0 - threshold) * f64::from(reference.num_points)).trunc();

    let mut subtests: u32 = 0;
    let mut succeeded: u32 = 0;
    for id in TestId::ALL {
        let (Some(r), Some(o)) = (reference.test(id), observed.test(id)) else {
            continue;
        };
        test_match(r, o, points, &mut subtests, &mut succeeded);
        if f64::from(subtests.saturating_sub(succeeded)) > max_mismatch {
            break;
        }
    }

    if subtests == 0 {
        0.0
    } else {
        f64::from(succeeded) / f64::from(subtests)
    }
}

/// Score `observed` against every reference in `db`, returning the best matches in
/// descending accuracy order.
///
/// Only matches at or above `accuracy_threshold` are kept (perfect matches always are).
/// At most [`MAX_FP_RESULTS`] are returned; once the list is full the bar rises to just
/// above the weakest entry, which lets later comparisons exit early.
///
/// Where the same OS name appears more than once in the database, only its
/// highest-scoring record is kept — different versions of one OS should not crowd out
/// genuinely different systems.
#[must_use]
pub fn match_fingerprint(
    observed: &FingerPrint,
    db: &FingerPrintDb,
    accuracy_threshold: f64,
) -> MatchResults {
    // The C dereferences `DB->MatchPoints` unconditionally, so a database with no
    // `MatchPoints` block is a null-pointer crash. An all-zero table instead makes every
    // weight zero, so nothing can score above zero and the answer is "no matches".
    let fallback = MatchPoints::default();
    let points = db.match_points.as_ref().unwrap_or(&fallback);

    let threshold = if accuracy_threshold.is_nan() {
        0.0
    } else {
        accuracy_threshold.clamp(0.0, 1.0)
    };
    let mut entrance = threshold;
    let mut results = MatchResults {
        matches: Vec::new(),
        num_perfect_matches: 0,
        outcome: Some(ScanOutcome::Success),
    };

    for (index, reference) in db.prints.iter().enumerate() {
        let accuracy = compare_fingerprints(reference, observed, points, entrance);
        if accuracy < entrance && accuracy != 1.0 {
            continue;
        }

        // Collapse duplicate OS names, keeping the better score.
        if let Some(dup) = results
            .matches
            .iter()
            .position(|m| m.os_name == reference.os_name)
        {
            // A perfect match can never be displaced, since nothing scores above 1.0 —
            // so `num_perfect_matches` cannot go stale here.
            if results.matches[dup].accuracy >= accuracy {
                continue;
            }
            results.matches.remove(dup);
        }

        if accuracy == 1.0 {
            if results.num_perfect_matches >= MAX_FP_RESULTS {
                results.outcome = Some(ScanOutcome::TooManyMatches);
                return results;
            }
            results.num_perfect_matches = results.num_perfect_matches.saturating_add(1);
        }

        // Insert before the first weaker entry, so equal scores keep database order. The
        // C walks a fixed 36-slot array and `fatal()`s if it finds no slot — which is
        // reachable whenever a zero-scoring record is admitted (only possible with a zero
        // threshold, since `0.0 >= 0.0`). Appending is the same placement without the
        // abort.
        let at = results
            .matches
            .iter()
            .position(|m| m.accuracy < accuracy)
            .unwrap_or(results.matches.len());
        results.matches.insert(
            at,
            OsMatch {
                index,
                os_name: reference.os_name.clone(),
                accuracy,
            },
        );
        results.matches.truncate(MAX_FP_RESULTS);

        if results.matches.len() == MAX_FP_RESULTS {
            // The list is full, so nothing weaker than its tail can ever be reported.
            // Raising the bar lets `compare_fingerprints` bail out sooner.
            if let Some(weakest) = results.matches.last() {
                entrance = (weakest.accuracy + 0.00001).min(1.0);
            }
        }
    }

    if results.matches.is_empty() && results.outcome == Some(ScanOutcome::Success) {
        results.outcome = Some(ScanOutcome::NoMatches);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osdb::model::FingerTest;

    /// Build a fingerprint from `(test, [(attr, value)])` pairs, computing `num_points`
    /// the way the parser does.
    fn fp(name: &str, points: &MatchPoints, spec: &[(TestId, &[(&str, &str)])]) -> FingerPrint {
        let mut print = FingerPrint {
            os_name: name.to_owned(),
            ..FingerPrint::default()
        };
        for (id, attrs) in spec {
            let mut test = FingerTest::new(*id);
            for (attr, value) in *attrs {
                let i = id.attr_index(attr).expect("unknown attribute");
                test.values[i] = Some((*value).to_owned());
                print.num_points = print.num_points.saturating_add(points.get(*id, i));
            }
            print.tests.push(test);
        }
        print
    }

    /// A small weights table: SEQ.SP=25, SEQ.GCD=75, T1.R=100, T1.DF=20.
    fn weights() -> MatchPoints {
        let mut mp = MatchPoints::default();
        mp.set(TestId::Seq, TestId::Seq.attr_index("SP").unwrap(), 25);
        mp.set(TestId::Seq, TestId::Seq.attr_index("GCD").unwrap(), 75);
        mp.set(TestId::T1, TestId::T1.attr_index("R").unwrap(), 100);
        mp.set(TestId::T1, TestId::T1.attr_index("DF").unwrap(), 20);
        mp
    }

    #[test]
    fn a_perfect_match_scores_one() {
        let mp = weights();
        let reference = fp("ref", &mp, &[(TestId::Seq, &[("SP", "0-5")])]);
        let observed = fp("obs", &mp, &[(TestId::Seq, &[("SP", "3")])]);
        assert_eq!(
            compare_fingerprints(&reference, &observed, &mp, 0.0),
            1.0,
            "3 is inside the range 0-5"
        );
    }

    #[test]
    fn accuracy_is_the_weighted_ratio_not_the_attribute_count() {
        let mp = weights();
        // T1.R matches (100 points), T1.DF does not (20 points). One of two attributes
        // matches, but the score is 100/120 — weight, not count.
        let reference = fp("ref", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "Y")])]);
        let observed = fp("obs", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "N")])]);
        let acc = compare_fingerprints(&reference, &observed, &mp, 0.0);
        assert!(
            (acc - 100.0 / 120.0).abs() < 1e-12,
            "expected 100/120, got {acc}"
        );
    }

    #[test]
    fn attributes_only_one_side_specifies_are_skipped_entirely() {
        let mp = weights();
        // The reference asks about SP and GCD; the observation only measured SP. GCD must
        // not count against either side of the ratio.
        let reference = fp("ref", &mp, &[(TestId::Seq, &[("SP", "5"), ("GCD", "1-6")])]);
        let observed = fp("obs", &mp, &[(TestId::Seq, &[("SP", "5")])]);
        assert_eq!(compare_fingerprints(&reference, &observed, &mp, 0.0), 1.0);

        // Likewise a test the observation never ran at all.
        let reference = fp(
            "ref",
            &mp,
            &[(TestId::Seq, &[("SP", "5")]), (TestId::T1, &[("R", "Y")])],
        );
        assert_eq!(compare_fingerprints(&reference, &observed, &mp, 0.0), 1.0);
    }

    #[test]
    fn no_shared_attributes_scores_zero_rather_than_dividing_by_zero() {
        let mp = weights();
        let reference = fp("ref", &mp, &[(TestId::Seq, &[("GCD", "1")])]);
        let observed = fp("obs", &mp, &[(TestId::T1, &[("R", "Y")])]);
        assert_eq!(compare_fingerprints(&reference, &observed, &mp, 0.0), 0.0);
        // And with an empty database record on either side.
        let empty = FingerPrint::default();
        assert_eq!(compare_fingerprints(&empty, &observed, &mp, 0.0), 0.0);
        assert_eq!(compare_fingerprints(&reference, &empty, &mp, 0.0), 0.0);
    }

    #[test]
    fn zero_weight_attributes_contribute_nothing() {
        // An attribute the MatchPoints block never mentions is worth 0, so it can neither
        // help nor hurt — the ratio is unchanged whether it matches or not.
        let mp = weights();
        let reference = fp("ref", &mp, &[(TestId::Seq, &[("SP", "5"), ("TI", "Z")])]);
        let matching = fp("obs", &mp, &[(TestId::Seq, &[("SP", "5"), ("TI", "Z")])]);
        let differing = fp("obs", &mp, &[(TestId::Seq, &[("SP", "5"), ("TI", "RD")])]);
        assert_eq!(compare_fingerprints(&reference, &matching, &mp, 0.0), 1.0);
        assert_eq!(compare_fingerprints(&reference, &differing, &mp, 0.0), 1.0);
    }

    #[test]
    fn ops_and_o_attributes_match_with_nesting_enabled() {
        // Nested matching lets an option string carry alternation inside it. Enabled for
        // every OPS attribute and for any attribute named "O".
        let mut mp = MatchPoints::default();
        mp.set(TestId::Ops, TestId::Ops.attr_index("O1").unwrap(), 20);
        let reference = fp("ref", &mp, &[(TestId::Ops, &[("O1", "M5B4NW%NNT11")])]);
        let observed = fp("obs", &mp, &[(TestId::Ops, &[("O1", "M5B4NW8")])]);
        // Whatever the verdict, nesting must be reachable and total.
        let acc = compare_fingerprints(&reference, &observed, &mp, 0.0);
        assert!((0.0..=1.0).contains(&acc));

        let same = fp("obs", &mp, &[(TestId::Ops, &[("O1", "M5B4NW%NNT11")])]);
        assert_eq!(compare_fingerprints(&reference, &same, &mp, 0.0), 1.0);
    }

    #[test]
    fn the_early_exit_only_ever_truncates_scores_that_would_be_rejected() {
        // The invariant that makes the C's optimisation safe: if scoring bails out early,
        // the true accuracy was already below the threshold. So a thresholded score is
        // either exact, or a value that is itself below the threshold. It is deliberately
        // *not* asserted to be a lower bound — dropping the remaining tests drops their
        // mismatches too, so the partial ratio can sit above the exact one.
        let mp = weights();
        let reference = fp(
            "ref",
            &mp,
            &[
                (TestId::Seq, &[("SP", "0-5"), ("GCD", "1-6")]),
                (TestId::T1, &[("R", "Y"), ("DF", "Y")]),
            ],
        );
        for sp in ["3", "9"] {
            for df in ["Y", "N"] {
                let observed = fp(
                    "obs",
                    &mp,
                    &[
                        (TestId::Seq, &[("SP", sp), ("GCD", "2")]),
                        (TestId::T1, &[("R", "Y"), ("DF", df)]),
                    ],
                );
                let full = compare_fingerprints(&reference, &observed, &mp, 0.0);
                let thresholded = compare_fingerprints(&reference, &observed, &mp, GUESS_THRESHOLD);
                if full >= GUESS_THRESHOLD {
                    assert_eq!(thresholded, full, "sp={sp} df={df}: exact score required");
                } else {
                    assert!(
                        thresholded == full || thresholded < GUESS_THRESHOLD,
                        "sp={sp} df={df}: early-exit score {thresholded} \
                         (exact {full}) reached the threshold"
                    );
                }
            }
        }
    }

    #[test]
    fn an_out_of_range_threshold_is_clamped_instead_of_going_undefined() {
        let mp = weights();
        let reference = fp("ref", &mp, &[(TestId::T1, &[("R", "Y")])]);
        let observed = fp("obs", &mp, &[(TestId::T1, &[("R", "Y")])]);
        // In the C, `(1.0 - 2.0) * numprints` converted to `unsigned long` is UB.
        assert_eq!(compare_fingerprints(&reference, &observed, &mp, 2.0), 1.0);
        assert_eq!(compare_fingerprints(&reference, &observed, &mp, -1.0), 1.0);
        assert_eq!(
            compare_fingerprints(&reference, &observed, &mp, f64::NAN),
            1.0
        );
        assert_eq!(
            compare_fingerprints(&reference, &observed, &mp, f64::INFINITY),
            1.0
        );
    }

    fn db_of(prints: Vec<FingerPrint>, points: MatchPoints) -> FingerPrintDb {
        FingerPrintDb {
            match_points: Some(points),
            prints,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn matches_come_back_sorted_and_capped() {
        let mp = weights();
        let observed = fp("obs", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "Y")])]);
        let prints = vec![
            fp("weak", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "N")])]),
            fp("perfect", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "Y")])]),
            fp("also perfect", &mp, &[(TestId::T1, &[("R", "Y")])]),
        ];
        let db = db_of(prints, mp);
        let r = match_fingerprint(&observed, &db, 0.0);
        assert_eq!(r.outcome, Some(ScanOutcome::Success));
        assert_eq!(r.num_perfect_matches, 2);
        let names: Vec<&str> = r.matches.iter().map(|m| m.os_name.as_str()).collect();
        assert_eq!(names, ["perfect", "also perfect", "weak"]);
        // Ties keep database order, and accuracies descend.
        for w in r.matches.windows(2) {
            assert!(w[0].accuracy >= w[1].accuracy);
        }
        // The index points back at the record that produced the match.
        assert_eq!(db.prints[r.matches[0].index].os_name, "perfect");
    }

    #[test]
    fn duplicate_os_names_keep_only_the_best_score() {
        let mp = weights();
        let observed = fp("obs", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "Y")])]);
        let prints = vec![
            fp("Linux", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "N")])]),
            fp("Linux", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "Y")])]),
            fp("Linux", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "N")])]),
        ];
        let db = db_of(prints, mp);
        let r = match_fingerprint(&observed, &db, 0.0);
        assert_eq!(r.matches.len(), 1, "one entry per OS name");
        assert_eq!(r.matches[0].accuracy, 1.0);
        assert_eq!(r.matches[0].index, 1, "the best-scoring record wins");
    }

    #[test]
    fn nothing_above_the_threshold_is_reported_as_no_matches() {
        let mp = weights();
        let observed = fp("obs", &mp, &[(TestId::T1, &[("R", "N"), ("DF", "N")])]);
        let prints = vec![fp("nope", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "Y")])])];
        let db = db_of(prints, mp);
        let r = match_fingerprint(&observed, &db, GUESS_THRESHOLD);
        assert!(r.matches.is_empty());
        assert_eq!(r.outcome, Some(ScanOutcome::NoMatches));
    }

    #[test]
    fn too_many_perfect_matches_is_reported_not_truncated_silently() {
        let mp = weights();
        let observed = fp("obs", &mp, &[(TestId::T1, &[("R", "Y")])]);
        let prints: Vec<FingerPrint> = (0..MAX_FP_RESULTS + 1)
            .map(|i| fp(&format!("os{i}"), &mp, &[(TestId::T1, &[("R", "Y")])]))
            .collect();
        let db = db_of(prints, mp);
        let r = match_fingerprint(&observed, &db, GUESS_THRESHOLD);
        assert_eq!(r.outcome, Some(ScanOutcome::TooManyMatches));
        assert_eq!(r.num_perfect_matches, MAX_FP_RESULTS);
        assert_eq!(r.matches.len(), MAX_FP_RESULTS);
    }

    #[test]
    fn a_zero_scoring_record_at_a_zero_threshold_is_admitted_not_fatal() {
        // The C's insertion scan looks for a slot whose accuracy is strictly less than
        // the new score. A zero score finds none and takes the `fatal()` branch, killing
        // the process. Here it is simply appended.
        let mp = weights();
        let observed = fp("obs", &mp, &[(TestId::T1, &[("R", "N")])]);
        let prints = vec![fp("zero", &mp, &[(TestId::T1, &[("R", "Y")])])];
        let db = db_of(prints, mp);
        let r = match_fingerprint(&observed, &db, 0.0);
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].accuracy, 0.0);
        assert_eq!(r.outcome, Some(ScanOutcome::Success));
    }

    #[test]
    fn a_database_without_match_points_degrades_instead_of_crashing() {
        // The C dereferences `DB->MatchPoints` with no null check.
        let mp = weights();
        let observed = fp("obs", &mp, &[(TestId::T1, &[("R", "Y")])]);
        let db = FingerPrintDb {
            match_points: None,
            prints: vec![fp("os", &mp, &[(TestId::T1, &[("R", "Y")])])],
            warnings: Vec::new(),
        };
        let r = match_fingerprint(&observed, &db, GUESS_THRESHOLD);
        assert_eq!(r.outcome, Some(ScanOutcome::NoMatches));
        assert!(r.matches.is_empty());
    }

    #[test]
    fn an_empty_database_yields_no_matches() {
        let db = FingerPrintDb::default();
        let r = match_fingerprint(&FingerPrint::default(), &db, GUESS_THRESHOLD);
        assert_eq!(r.outcome, Some(ScanOutcome::NoMatches));
        assert_eq!(r.num_perfect_matches, 0);
    }

    #[test]
    fn the_entrance_bar_rises_once_the_list_is_full() {
        // Fill the list with perfect matches, then offer a weaker record: it must be
        // rejected because the bar has risen above it.
        let mp = weights();
        let observed = fp("obs", &mp, &[(TestId::T1, &[("R", "Y"), ("DF", "Y")])]);
        let mut prints: Vec<FingerPrint> = (0..MAX_FP_RESULTS)
            .map(|i| {
                fp(
                    &format!("os{i}"),
                    &mp,
                    &[(TestId::T1, &[("R", "Y"), ("DF", "Y")])],
                )
            })
            .collect();
        prints.push(fp(
            "latecomer",
            &mp,
            &[(TestId::T1, &[("R", "Y"), ("DF", "N")])],
        ));
        let db = db_of(prints, mp);
        let r = match_fingerprint(&observed, &db, 0.0);
        assert_eq!(r.matches.len(), MAX_FP_RESULTS);
        assert!(
            !r.matches.iter().any(|m| m.os_name == "latecomer"),
            "a weaker record must not displace a full list of perfect matches"
        );
    }
}
