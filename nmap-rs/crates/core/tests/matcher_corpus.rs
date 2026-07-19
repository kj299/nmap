//! Corpus gate for `core::matcher` against the real 2.5 MB `nmap-service-probes`.
//! Compiles every shipped `match`/`softmatch` rule through the hybrid engine and
//! pins the engine split the M3-1 spike predicted: the overwhelming majority land
//! on the linear engine, a small minority on the bounded-backtracking fallback,
//! and only a tiny residual compiles in neither (dropped with a warning, never a
//! crash). Also exercises `test` on representative real banners end-to-end.
//!
//! Skipped under Miri (filesystem isolation aborts `std::fs`); the unit suite in
//! `matcher.rs` is what Miri interrogates.
#![cfg(not(miri))]

use nmap_core::matcher::CompiledDb;
use nmap_core::probedb::ProbeDb;

fn load_corpus() -> Option<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nmap-service-probes");
    std::fs::read_to_string(path).ok()
}

#[test]
fn whole_db_compiles_with_bounded_residual() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-service-probes not found; skipping matcher corpus");
        return;
    };
    let db = ProbeDb::parse(&text);
    let compiled = CompiledDb::compile(&db);

    // Count compiled rules across NULL + all probes.
    let compiled_rules: usize = compiled
        .null_probe
        .iter()
        .chain(compiled.probes.iter())
        .map(|p| p.rule_count())
        .sum();
    let dropped = compiled.warnings.len();
    let total = compiled_rules + dropped;

    eprintln!(
        "matcher corpus: {compiled_rules} compiled, {dropped} dropped, {total} total \
         ({:.2}% coverage)",
        100.0 * compiled_rules as f64 / total as f64
    );

    // Every match/softmatch line is accounted for (compiled or explicitly dropped).
    assert_eq!(
        total, 12171,
        "every rule is compiled or ledgered, none lost"
    );

    // The spike measured ~93.6% linear-compilable; with the backtracking fallback
    // the residual (neither engine, or empty-matching) must be a small handful.
    // Pin a generous ceiling so a real regression (engine wiring broke) trips it,
    // without being brittle to a crate-version behavior tweak.
    assert!(
        dropped <= 40,
        "far more rules dropped than the spike's residual (~9): {dropped}"
    );
    // And the bulk must actually compile.
    assert!(
        compiled_rules >= 12130,
        "coverage regressed: only {compiled_rules}/12171 compiled"
    );

    // Every dropped rule carries a service name + reason (never a silent drop).
    for w in &compiled.warnings {
        assert!(!w.service.is_empty());
        assert!(!w.reason.is_empty());
    }
}

#[test]
fn matches_representative_real_banners() {
    let Some(text) = load_corpus() else {
        return;
    };
    let db = ProbeDb::parse(&text);
    let compiled = CompiledDb::compile(&db);

    // The NULL probe carries the banner-only rules (SSH, FTP, SMTP, …). Feed it a
    // few well-known greetings and confirm a plausible service comes back. We
    // assert on the *service label*, not an exact rule, so this is robust to DB
    // updates.
    let null = compiled.null_probe.as_ref().expect("NULL probe compiled");

    let cases: &[(&[u8], &str)] = &[
        (b"SSH-2.0-OpenSSH_9.6\r\n", "ssh"),
        (b"220 (vsFTPd 3.0.5)\r\n", "ftp"),
    ];
    for (banner, expected_service) in cases {
        match null.test(banner) {
            Some(out) => assert_eq!(
                out.service(),
                *expected_service,
                "banner {banner:?} matched {} not {expected_service}",
                out.service()
            ),
            None => panic!("no match for {banner:?} (expected {expected_service})"),
        }
    }
}

#[test]
fn matching_is_total_over_hostile_banners_against_the_real_db() {
    let Some(text) = load_corpus() else {
        return;
    };
    let db = ProbeDb::parse(&text);
    let compiled = CompiledDb::compile(&db);
    let null = compiled.null_probe.as_ref().unwrap();

    // A pile of adversarial banners against every real rule must never panic or
    // hang (the backtrack limit bounds the fancy engine).
    let banners: &[&[u8]] = &[
        &[],
        &[0u8; 8192],
        &[0xffu8; 8192],
        b"\x00\x01\x02\x03\x04\x05\x06\x07",
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!",
    ];
    for b in banners {
        let _ = null.test(b);
        for p in &compiled.probes {
            let _ = p.matches(b);
        }
    }
}
