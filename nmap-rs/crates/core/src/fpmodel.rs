//! The IPv6 OS-classification model — nmap's compiled-in logistic-regression classifier.
//!
//! IPv4 OS detection matches an observed fingerprint against a database of expressions
//! ([`crate::osdb`]). IPv6 detection works completely differently: nmap ships a **trained
//! linear model** and classifies a 695-element feature vector against 101 OS classes.
//!
//! ## No liblinear
//!
//! The C hands this work to **liblinear**, a bundled third-party C++ library, and the
//! model itself is a 2.8 MB generated `.cc` file compiled into the binary. But the only
//! liblinear entry point nmap uses for prediction is `predict_values`, and for this model
//! that reduces to a **dot product** — the model is linear, `bias` is negative (so there
//! is no bias column), and the solver is ordinary logistic regression. So the whole
//! dependency collapses to a few lines of arithmetic here, and liblinear leaves the trust
//! boundary entirely. See `fp6-no-liblinear` in `DIVERGENCES.md`.
//!
//! The model data is extracted from `FPModel.cc` by `tools/extract_fpmodel.py` into a
//! little-endian `f64` blob and embedded with `include_bytes!`. Values are copied
//! verbatim, so predictions are bit-identical to the C's.

/// The embedded model, in the layout `tools/extract_fpmodel.py` writes.
const BLOB: &[u8] = include_bytes!("../data/fpmodel.bin");

/// Magic + format version, so a stale or truncated blob fails loudly at load rather than
/// silently classifying against garbage.
const MAGIC: &[u8; 8] = b"NMFP6\0\0\x01";

/// Variance substituted when a class has none, from the C's `novelty_of`.
///
/// A zero variance means every training sample for that class had the same value there.
/// Dividing by it would be a division by zero; the C substitutes a small constant, which
/// makes any deviation on that feature count heavily — deliberately, because such a class
/// wants more submissions.
const DEFAULT_VARIANCE: f64 = 0.01;

/// Novelty above which even a top match is discarded, from the C's `FP_NOVELTY_THRESHOLD`.
pub const NOVELTY_THRESHOLD: f64 = 15.0;

/// A match must score at least this fraction of the best to count as a perfect match.
const PERFECT_MATCH_RATIO: f64 = 0.90;

/// Maximum matches reported, matching the C's `MAX_FP_RESULTS`.
pub const MAX_FP_RESULTS: usize = 8;

/// Why the embedded model could not be read. Only reachable if the blob is corrupt or
/// the extractor and this module disagree — both are build-time facts, so this is a
/// consistency check rather than a runtime input path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    /// Not the expected format or version.
    BadMagic,
    /// The blob ended before the declared tables did.
    Truncated,
    /// A class name was not valid UTF-8.
    BadName,
}

/// nmap's trained IPv6 classifier.
pub struct FpModel {
    n_class: usize,
    n_feature: usize,
    /// `(a, b)` per feature; a raw value `x` scales to `(x + a) * b`.
    scale: Vec<[f64; 2]>,
    /// Per-class feature means, `n_class` rows of `n_feature`.
    mean: Vec<f64>,
    /// Per-class feature variances, same shape.
    variance: Vec<f64>,
    /// Weights in liblinear's layout: feature-major, `n_class` columns.
    w: Vec<f64>,
    /// OS name per class label.
    names: Vec<String>,
}

/// Deliberately hand-written rather than derived: the tables hold ~210,000 `f64`s, and a
/// derived `Debug` would dump all of them into any log line that happened to include the
/// model. The shape is what a reader actually wants.
impl std::fmt::Debug for FpModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FpModel")
            .field("n_class", &self.n_class)
            .field("n_feature", &self.n_feature)
            .finish_non_exhaustive()
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ModelError> {
        let end = self.pos.checked_add(n).ok_or(ModelError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(ModelError::Truncated)?;
        self.pos = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, ModelError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, ModelError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn f64s(&mut self, count: usize) -> Result<Vec<f64>, ModelError> {
        let bytes = count.checked_mul(8).ok_or(ModelError::Truncated)?;
        let s = self.take(bytes)?;
        Ok(s.chunks_exact(8)
            .map(|c| f64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
            .collect())
    }
}

impl FpModel {
    /// Parse the embedded model.
    ///
    /// # Errors
    /// Returns [`ModelError`] if the blob is not the expected format — a build
    /// consistency failure, not an input-validation path.
    pub fn load() -> Result<FpModel, ModelError> {
        Self::parse(BLOB)
    }

    fn parse(blob: &[u8]) -> Result<FpModel, ModelError> {
        let mut r = Reader { buf: blob, pos: 0 };
        if r.take(8)? != MAGIC {
            return Err(ModelError::BadMagic);
        }
        let n_class = r.u32()? as usize;
        let n_feature = r.u32()? as usize;
        // A degenerate header would make every later length zero and yield a model that
        // classifies everything identically; reject it rather than load it.
        if n_class == 0 || n_feature == 0 {
            return Err(ModelError::Truncated);
        }
        let cells = n_class
            .checked_mul(n_feature)
            .ok_or(ModelError::Truncated)?;

        let flat = r.f64s(n_feature.checked_mul(2).ok_or(ModelError::Truncated)?)?;
        let scale = flat.chunks_exact(2).map(|c| [c[0], c[1]]).collect();
        let mean = r.f64s(cells)?;
        let variance = r.f64s(cells)?;
        let w = r.f64s(cells)?;

        let count = r.u32()? as usize;
        if count != n_class {
            return Err(ModelError::Truncated);
        }
        let mut names = Vec::with_capacity(count);
        for _ in 0..count {
            let len = usize::from(r.u16()?);
            let bytes = r.take(len)?;
            names.push(
                std::str::from_utf8(bytes)
                    .map_err(|_| ModelError::BadName)?
                    .to_owned(),
            );
        }

        Ok(FpModel {
            n_class,
            n_feature,
            scale,
            mean,
            variance,
            w,
            names,
        })
    }

    /// Number of OS classes.
    #[must_use]
    pub fn n_class(&self) -> usize {
        self.n_class
    }

    /// Length of a feature vector.
    #[must_use]
    pub fn n_feature(&self) -> usize {
        self.n_feature
    }

    /// The OS name for a label, or `None` if out of range.
    #[must_use]
    pub fn name(&self, label: usize) -> Option<&str> {
        self.names.get(label).map(String::as_str)
    }

    /// Scale a raw feature vector in place — the C's `apply_scale`, `x' = (x + a) * b`.
    ///
    /// Features beyond the model's width are ignored rather than scaled against a
    /// neighbouring feature's parameters.
    pub fn apply_scale(&self, features: &mut [f64]) {
        for (x, ab) in features.iter_mut().zip(self.scale.iter()) {
            *x = (*x + ab[0]) * ab[1];
        }
    }

    /// Per-class decision values — the C's `predict_values` for this model.
    ///
    /// liblinear stores weights feature-major with one column per class, so this is
    /// `values[c] = Σ_f w[f * n_class + c] * features[f]`. The C guards `idx <= n`
    /// because "the dimension of testing data may exceed that of training"; here the
    /// iteration is bounded by the model's own width, which cannot run off the weights.
    #[must_use]
    pub fn predict_values(&self, features: &[f64]) -> Vec<f64> {
        let mut values = vec![0.0f64; self.n_class];
        for (f, &x) in features.iter().enumerate().take(self.n_feature) {
            let base = f.saturating_mul(self.n_class);
            let Some(row) = self.w.get(base..base.saturating_add(self.n_class)) else {
                break;
            };
            for (v, &weight) in values.iter_mut().zip(row) {
                *v += weight * x;
            }
        }
        values
    }

    /// How far an observation sits from a class's training samples — the C's `novelty_of`.
    ///
    /// A diagonal Mahalanobis distance: per-feature deviation from the class mean, scaled
    /// by that feature's variance. nmap stores only per-feature variances rather than full
    /// covariance matrices, to keep the model to `n` entries per class instead of `n²`.
    ///
    /// Returns `None` for a label with no such class. The C `assert`s `label < nr_feature`
    /// here — the wrong bound, since the arrays it then indexes have `nr_class` rows
    /// (695 vs 101). With `NDEBUG` the assert vanishes entirely. See
    /// `fp6-novelty-label-bound` in `DIVERGENCES.md`.
    #[must_use]
    pub fn novelty_of(&self, features: &[f64], label: usize) -> Option<f64> {
        let start = label.checked_mul(self.n_feature)?;
        let end = start.checked_add(self.n_feature)?;
        let means = self.mean.get(start..end)?;
        let variances = self.variance.get(start..end)?;

        let mut sum = 0.0f64;
        for ((&x, &m), &v) in features
            .iter()
            .take(self.n_feature)
            .zip(means)
            .zip(variances)
        {
            let d = x - m;
            // Zero variance means the training samples were identical there; the C
            // substitutes a small constant rather than dividing by zero.
            let v = if v == 0.0 { DEFAULT_VARIANCE } else { v };
            sum += d * d / v;
        }
        Some(sum.sqrt())
    }
}

/// One classification result.
#[derive(Debug, Clone, PartialEq)]
pub struct Fp6Match {
    /// Class label.
    pub label: usize,
    /// OS name.
    pub os_name: String,
    /// Logistic probability of the decision value.
    pub accuracy: f64,
}

/// The outcome of classifying an observation.
#[derive(Debug, Clone, PartialEq)]
pub struct Fp6Results {
    /// Best matches, descending by probability, capped at [`MAX_FP_RESULTS`].
    pub matches: Vec<Fp6Match>,
    /// How many count as perfect.
    pub num_perfect_matches: usize,
    /// Whether the classification is reportable.
    pub success: bool,
    /// Novelty of the top match, when a single perfect match was found.
    pub novelty: Option<f64>,
}

/// The logistic transform of a decision value, with a defined answer for every input.
///
/// `exp` of a large negative value underflows to 0 and of a large positive one saturates,
/// which are the right limits. A **non-finite** decision value is different in kind: it
/// means the arithmetic had no answer, usually because a feature arrived as NaN or an
/// infinity. That is not evidence for the class, so it scores zero.
///
/// ## Divergence — `fp6-nan-score-is-no-evidence`
///
/// The C propagates such a value straight into `1.0/(1.0+exp(-v))` and on into two places
/// that cannot cope with it. First, `label_prob_cmp` decides order with `>` and `<`, both
/// of which are false for NaN, so it reports "equal" for a NaN against everything while
/// the other elements retain a strict order — **not a strict weak ordering, which makes
/// the `qsort` call undefined behaviour**. Second, the value reaches the user as a
/// printed accuracy percentage. Scoring it zero keeps the sort total and the output
/// meaningful, and cannot promote a class the model gave no answer for.
fn probability(value: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    let p = 1.0 / (1.0 + (-value).exp());
    // Guard the transform itself as well: the only way out of [0,1] is a non-finite
    // intermediate, and a probability outside that range would corrupt every comparison
    // downstream.
    if p.is_finite() {
        p.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// Classify a **raw** (unscaled) feature vector — the C's `classify`.
///
/// The acceptance rule is deliberately strict, and worth stating because it is the whole
/// difference between a guess and an answer: a result is reported **only** when exactly
/// one class comes within 90% of the best probability *and* that class's novelty is below
/// [`NOVELTY_THRESHOLD`]. Several close classes means the model cannot separate them; high
/// novelty means the observation is unlike anything the model was trained on, so a
/// confident-looking probability would still be meaningless.
#[must_use]
pub fn classify(model: &FpModel, raw_features: &[f64]) -> Fp6Results {
    let mut features = raw_features.to_vec();
    features.resize(model.n_feature(), 0.0);
    model.apply_scale(&mut features);

    let values = model.predict_values(&features);
    let mut scored: Vec<(usize, f64)> = values
        .iter()
        .enumerate()
        .map(|(i, &v)| (i, probability(v)))
        .collect();
    // Descending. `total_cmp` is a *total* order, so the sort is well-defined for any
    // input. The C sorts with `qsort` and a comparator that returns 0 whenever either
    // side is NaN — see `fp6-nan-score-is-no-evidence`.
    scored.sort_by(|a, b| b.1.total_cmp(&a.1));

    let best = scored.first().map_or(0.0, |s| s.1);
    let mut matches = Vec::new();
    let mut num_perfect_matches = 0;
    for (label, prob) in scored.iter().take(MAX_FP_RESULTS) {
        matches.push(Fp6Match {
            label: *label,
            os_name: model.name(*label).unwrap_or_default().to_owned(),
            accuracy: *prob,
        });
        if *prob >= PERFECT_MATCH_RATIO * best {
            num_perfect_matches = matches.len();
        }
    }

    // Exactly one perfect match, and it must not be too novel.
    let (success, novelty) = if num_perfect_matches == 1 {
        let label = matches.first().map_or(0, |m| m.label);
        let n = model.novelty_of(&features, label);
        (n.is_some_and(|n| n < NOVELTY_THRESHOLD), n)
    } else {
        (false, None)
    };
    if !success {
        num_perfect_matches = 0;
    }

    Fp6Results {
        matches,
        num_perfect_matches,
        success,
        novelty,
    }
}

/// Excluded from Miri. Every test here loads the embedded model — parsing ~210,000 `f64`s
/// and then doing 695x101 dot products — which Miri interprets one operation at a time and
/// takes many minutes over. The cost buys nothing: `core` is `#![forbid(unsafe_code)]`, so
/// there is no unsafe for Miri to find UB in, and out-of-bounds indexing or overflow would
/// already panic under the ordinary debug test run. Same reasoning as the corpus tests
/// that read `nmap-os-db`.
#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;

    fn model() -> FpModel {
        FpModel::load().expect("the embedded model must load")
    }

    #[test]
    fn the_embedded_model_has_nmaps_shape() {
        let m = model();
        assert_eq!(m.n_class(), 101);
        assert_eq!(m.n_feature(), 695);
        // Names are present and in label order.
        assert_eq!(m.name(0), Some("Linux 2.6.38 - 3.2"));
        assert_eq!(m.name(100), Some("VxWorks 6.5"));
        assert_eq!(
            m.name(101),
            None,
            "an out-of-range label must not name a class"
        );
    }

    #[test]
    fn a_corrupt_blob_is_rejected_rather_than_loaded() {
        // Every one of these would otherwise classify against garbage, silently.
        assert_eq!(FpModel::parse(b"").unwrap_err(), ModelError::Truncated);
        assert_eq!(
            FpModel::parse(b"NOTAMODEL").unwrap_err(),
            ModelError::BadMagic
        );

        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&695u32.to_le_bytes());
        assert_eq!(
            FpModel::parse(&header).unwrap_err(),
            ModelError::Truncated,
            "zero classes would make every table empty"
        );

        // A truncated body must not yield a short-but-usable model.
        let good = BLOB;
        for cut in [16, 1024, good.len() / 2, good.len() - 1] {
            assert!(
                FpModel::parse(&good[..cut]).is_err(),
                "a blob cut at {cut} was accepted"
            );
        }
    }

    #[test]
    fn scaling_ignores_features_past_the_models_width() {
        let m = model();
        // A longer vector must not read scale parameters belonging to another feature.
        let mut long = vec![1.0f64; m.n_feature() + 5];
        m.apply_scale(&mut long);
        assert_eq!(
            &long[m.n_feature()..],
            &[1.0; 5],
            "features beyond the model were altered"
        );
    }

    #[test]
    fn novelty_rejects_a_label_with_no_class() {
        let m = model();
        let features = vec![0.0f64; m.n_feature()];
        assert!(m.novelty_of(&features, 0).is_some());
        assert!(m.novelty_of(&features, m.n_class() - 1).is_some());
        // The C `assert`s `label < nr_feature` here — 695, not the 101 rows the arrays
        // actually have — so labels 101..694 read out of bounds. And with NDEBUG the
        // assert is gone entirely. Here they are simply `None`.
        assert_eq!(m.novelty_of(&features, m.n_class()), None);
        assert_eq!(m.novelty_of(&features, 694), None);
        assert_eq!(m.novelty_of(&features, usize::MAX), None);
    }

    #[test]
    fn novelty_is_zero_at_a_class_mean_and_grows_with_distance() {
        let m = model();
        // Reconstruct class 0's mean vector; distance from it must be zero.
        let mean: Vec<f64> = m.mean[..m.n_feature()].to_vec();
        let at_mean = m.novelty_of(&mean, 0).expect("class 0");
        assert!(
            at_mean.abs() < 1e-9,
            "novelty at the mean should be 0, got {at_mean}"
        );

        let mut moved = mean.clone();
        moved[0] += 1.0;
        let nearby = m.novelty_of(&moved, 0).expect("class 0");
        assert!(
            nearby > at_mean,
            "moving away from the mean must raise novelty"
        );
    }

    #[test]
    fn predict_values_is_linear_and_zero_at_the_origin() {
        let m = model();
        // No bias column (the model's `bias` is negative), so an all-zero vector gives
        // all-zero decision values. This is what makes the dot-product replacement valid.
        let zeros = vec![0.0f64; m.n_feature()];
        assert!(m.predict_values(&zeros).iter().all(|&v| v == 0.0));

        // Scaling the input scales every decision value by the same factor.
        let x: Vec<f64> = (0..m.n_feature()).map(|i| ((i % 7) as f64) - 3.0).collect();
        let a = m.predict_values(&x);
        let doubled: Vec<f64> = x.iter().map(|v| v * 2.0).collect();
        let b = m.predict_values(&doubled);
        for (i, (&p, &q)) in a.iter().zip(&b).enumerate() {
            assert!(
                (q - 2.0 * p).abs() <= 1e-6 * q.abs().max(1.0),
                "class {i} not linear"
            );
        }
    }

    #[test]
    fn a_short_feature_vector_is_padded_not_misread() {
        let m = model();
        // classify() must not read past a short vector or shift features leftward.
        let r = classify(&m, &[]);
        assert_eq!(r.matches.len(), MAX_FP_RESULTS);
        let same = classify(&m, &vec![0.0f64; m.n_feature()]);
        assert_eq!(
            r.matches.first().map(|x| x.label),
            same.matches.first().map(|x| x.label),
            "an empty vector should behave as an all-zero one"
        );
    }

    #[test]
    fn classification_is_capped_sorted_and_named() {
        let m = model();
        let features: Vec<f64> = (0..m.n_feature()).map(|i| (i % 3) as f64).collect();
        let r = classify(&m, &features);

        assert_eq!(r.matches.len(), MAX_FP_RESULTS, "results must be capped");
        let mut previous = f64::INFINITY;
        for x in &r.matches {
            assert!(x.accuracy.is_finite() && (0.0..=1.0).contains(&x.accuracy));
            assert!(previous >= x.accuracy, "results not sorted descending");
            previous = x.accuracy;
            assert_eq!(x.os_name, m.name(x.label).unwrap_or_default());
        }
    }

    #[test]
    fn a_result_is_reported_only_on_one_clear_and_familiar_match() {
        let m = model();
        // An observation nothing resembles: many classes score alike and/or novelty is
        // huge. Either way the answer must be withheld rather than guessed.
        let wild = vec![1e6f64; m.n_feature()];
        let r = classify(&m, &wild);
        assert!(
            !r.success,
            "a wildly novel observation must not be reported"
        );
        assert_eq!(r.num_perfect_matches, 0);

        // The accept rule is: exactly one perfect match AND novelty under the threshold.
        // Whenever success is claimed, both must hold.
        for probe in [0.0f64, 0.5, 1.0, -1.0] {
            let r = classify(&m, &vec![probe; m.n_feature()]);
            if r.success {
                assert_eq!(r.num_perfect_matches, 1, "success needs exactly one match");
                let n = r.novelty.expect("success reports novelty");
                assert!(n < NOVELTY_THRESHOLD, "success with novelty {n}");
            } else {
                assert_eq!(r.num_perfect_matches, 0);
            }
        }
    }

    #[test]
    fn a_non_finite_feature_scores_as_no_evidence() {
        // Found by the fuzz target: a NaN or infinite feature makes the decision value
        // non-finite, and the first draft propagated that into `accuracy` as NaN. The C
        // does the same and then sorts with a comparator that reports "equal" for every
        // NaN pair — not a strict weak ordering, so its `qsort` call is UB.
        let m = model();
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let r = classify(&m, &vec![bad; m.n_feature()]);
            for x in &r.matches {
                assert!(
                    x.accuracy.is_finite() && (0.0..=1.0).contains(&x.accuracy),
                    "{bad} produced accuracy {}",
                    x.accuracy
                );
            }
            assert!(
                !r.success,
                "{bad} must not yield a reportable classification"
            );
            assert_eq!(r.num_perfect_matches, 0);
        }

        // A single poisoned feature among good ones must not be reportable either.
        let mut mixed = vec![0.0f64; m.n_feature()];
        mixed[17] = f64::NAN;
        for x in &classify(&m, &mixed).matches {
            assert!(
                x.accuracy.is_finite(),
                "one NaN feature poisoned the output"
            );
        }
    }

    #[test]
    fn classification_is_deterministic() {
        let m = model();
        let features: Vec<f64> = (0..m.n_feature())
            .map(|i| f64::from(u32::try_from(i).unwrap_or(0)) / 700.0)
            .collect();
        assert_eq!(classify(&m, &features), classify(&m, &features));
    }
}
