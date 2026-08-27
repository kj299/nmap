// cargo-fuzz target for `nmap_core::fpmodel` — the IPv6 OS classifier.
//
// The feature vector is derived from probe responses the target chooses, so a hostile
// host steers every number that reaches this arithmetic. The C hands the same values to
// liblinear; this port does the arithmetic itself, which means it also owns the failure
// modes liblinear would have had.
//
// Enforced: classification is TOTAL for any vector — including NaN, infinities and
// lengths on either side of the model's width — the results are capped, sorted and
// correctly named, novelty is never claimed for a label with no class, and the accept
// rule (exactly one perfect match AND novelty under threshold) always holds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::fpmodel::{classify, FpModel, MAX_FP_RESULTS, NOVELTY_THRESHOLD};
use std::sync::OnceLock;

static MODEL: OnceLock<FpModel> = OnceLock::new();

fn model() -> &'static FpModel {
    MODEL.get_or_init(|| FpModel::load().expect("embedded model loads"))
}

fuzz_target!(|data: &[u8]| {
    let m = model();

    // Eight bytes per feature, with a few bit patterns forced to the degenerate values a
    // pure-random stream would essentially never produce.
    let mut features: Vec<f64> = data
        .chunks(8)
        .map(|c| {
            let mut b = [0u8; 8];
            b[..c.len()].copy_from_slice(c);
            let raw = f64::from_le_bytes(b);
            match b[0] % 16 {
                0 => f64::NAN,
                1 => f64::INFINITY,
                2 => f64::NEG_INFINITY,
                3 => -1.0, // nmap's "attribute absent"
                4 => 0.0,
                5 => f64::MAX,
                6 => f64::MIN_POSITIVE,
                _ => raw,
            }
        })
        .collect();
    // Exercise both sides of the model's width, and the exact boundary.
    if data.first().is_some_and(|b| b % 3 == 0) {
        features.truncate(m.n_feature().saturating_sub(1));
    }

    let r = classify(m, &features);

    assert!(r.matches.len() <= MAX_FP_RESULTS, "results overflowed the cap");
    assert!(r.num_perfect_matches <= r.matches.len());

    let mut previous = f64::INFINITY;
    for x in &r.matches {
        assert!(x.label < m.n_class(), "result names a nonexistent class");
        assert_eq!(
            x.os_name,
            m.name(x.label).unwrap_or_default(),
            "result carries the wrong OS name"
        );
        // Every reported accuracy is a real probability. A NaN or infinite feature makes
        // the decision value non-finite; that must score as no evidence, never leak into
        // the output as a printed "NaN%" or poison the ordering. (The fuzzer found
        // exactly this: the first draft propagated NaN straight through.)
        assert!(
            x.accuracy.is_finite() && (0.0..=1.0).contains(&x.accuracy),
            "accuracy {} out of range",
            x.accuracy
        );
        assert!(previous >= x.accuracy, "results not sorted descending");
        previous = x.accuracy;
    }

    // The accept rule that separates an answer from a guess.
    if r.success {
        assert_eq!(r.num_perfect_matches, 1, "success without a single clear match");
        let n = r.novelty.expect("success must report novelty");
        assert!(n.is_finite(), "success on a non-finite novelty");
        assert!(n < NOVELTY_THRESHOLD, "success above the novelty threshold");
    } else {
        assert_eq!(r.num_perfect_matches, 0, "matches claimed without success");
    }

    // Out-of-range labels never produce a distance — the C's assert here checks the
    // wrong bound and vanishes under NDEBUG.
    assert_eq!(m.novelty_of(&features, m.n_class()), None);
    assert_eq!(m.novelty_of(&features, usize::MAX), None);

    // Deterministic.
    assert_eq!(classify(m, &features), r, "classification is not deterministic");
});
