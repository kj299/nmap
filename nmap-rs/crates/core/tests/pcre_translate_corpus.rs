//! Corpus regression for `core::pcre_translate` against the real 2.5 MB
//! `nmap-service-probes`. This is the productionized form of the M3-1 spike
//! (`SPIKES.md`): parse every `match`/`softmatch` pattern with `core::probedb`,
//! run it through `translate`, and compile the result in `regex::bytes` (the
//! engine `core::matcher` will use). It pins two facts the spike established:
//!
//!   * translation raises linear-engine acceptance from ~77.5% to ~93.5%, and
//!   * `translate` never panics on any real pattern.
//!
//! Skipped under Miri (filesystem isolation aborts `std::fs`); the unit suite in
//! `pcre_translate.rs` is what Miri interrogates.
#![cfg(not(miri))]

use nmap_core::pcre_translate::translate;
use nmap_core::probedb::ProbeDb;

fn load_corpus() -> Option<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nmap-service-probes");
    std::fs::read_to_string(path).ok()
}

fn compiles(pattern: &str, caseless: bool, dotall: bool) -> bool {
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .case_insensitive(caseless)
        .dot_matches_new_line(dotall)
        .build()
        .is_ok()
}

/// Collect every `(pattern, ignorecase, dotall)` across all probes.
fn all_patterns(db: &ProbeDb) -> Vec<(String, bool, bool)> {
    let mut out = Vec::new();
    for probe in db.null_probe.iter().chain(db.probes.iter()) {
        for m in &probe.matches {
            out.push((m.pattern.clone(), m.ignorecase, m.dotall));
        }
    }
    out
}

#[test]
fn translation_raises_linear_acceptance_to_93pct() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-service-probes not found; skipping pcre_translate corpus");
        return;
    };
    let db = ProbeDb::parse(&text);
    let patterns = all_patterns(&db);
    assert_eq!(patterns.len(), 12171, "expected the full corpus");

    let mut raw_ok = 0usize;
    let mut translated_ok = 0usize;
    for (pat, caseless, dotall) in &patterns {
        if compiles(pat, *caseless, *dotall) {
            raw_ok += 1;
        }
        // `translate` must never panic on any real pattern (totality).
        let t = translate(pat);
        if compiles(&t, *caseless, *dotall) {
            translated_ok += 1;
        }
    }

    let total = patterns.len();
    let raw_pct = 100.0 * raw_ok as f64 / total as f64;
    let tr_pct = 100.0 * translated_ok as f64 / total as f64;
    eprintln!(
        "pcre_translate corpus: raw {raw_ok}/{total} ({raw_pct:.2}%) -> translated \
         {translated_ok}/{total} ({tr_pct:.2}%)"
    );

    // Baselines from the spike (M3-1): raw ~77.5%, translated ~93.5%. Assert the
    // measured recovery is at least that — a regression here means a rewrite
    // stopped firing or started breaking patterns.
    assert!(
        raw_ok >= 9433,
        "raw acceptance regressed below the spike baseline: {raw_ok} < 9433"
    );
    assert!(
        translated_ok >= 11380,
        "translated acceptance regressed below the spike baseline (93.5%): \
         {translated_ok} < 11380"
    );
    // Translation must never make a pattern *worse*.
    assert!(
        translated_ok >= raw_ok,
        "translation reduced acceptance: {translated_ok} < {raw_ok}"
    );
}

#[test]
fn translate_is_total_over_the_corpus() {
    let Some(text) = load_corpus() else {
        return;
    };
    let db = ProbeDb::parse(&text);
    // No panic on any real pattern, and translation is idempotent on its output.
    for (pat, _, _) in all_patterns(&db) {
        let once = translate(&pat);
        assert_eq!(translate(&once), once, "not idempotent on {pat:?}");
    }
}
