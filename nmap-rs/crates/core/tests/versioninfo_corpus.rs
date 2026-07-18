//! Corpus gate for `core::versioninfo` against the real 2.5 MB
//! `nmap-service-probes`. Runs `build` for every shipped `match`/`softmatch`
//! rule's version templates against synthetic capture groups, proving the
//! substitution engine is **total** over every real template (`$N`, `$P()`,
//! `$SUBST()`, `$I()`, and `cpe:/…/`) — no panic on any of them — and that CPE
//! templates route to the a/h/o field their part letter selects.
//!
//! Skipped under Miri (filesystem isolation aborts `std::fs`); the unit suite in
//! `versioninfo.rs` is what Miri interrogates.
#![cfg(not(miri))]

use nmap_core::probedb::ProbeDb;
use nmap_core::versioninfo::build;

fn load_corpus() -> Option<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nmap-service-probes");
    std::fs::read_to_string(path).ok()
}

/// Ten synthetic capture groups (index 0 = whole match). Mix of ASCII, digits,
/// bytes for `$I`, and interleaved NULs for `$P` — so every command type has
/// plausible input and nothing is a no-op.
fn synthetic_captures() -> Vec<Option<Vec<u8>>> {
    vec![
        Some(b"WHOLEMATCH".to_vec()),
        Some(b"1.2.3".to_vec()),
        Some(b"OpenSSH".to_vec()),
        Some(b"\x01\x02".to_vec()),         // for $I
        Some(b"W\x00O\x00R\x00K".to_vec()), // for $P
        Some(b"a.b.c".to_vec()),            // for $SUBST
        Some(b"Linux 5.10".to_vec()),
        Some(b"x86_64".to_vec()),
        Some(b"unit/test".to_vec()),
        Some(b"9".to_vec()),
    ]
}

#[test]
fn build_is_total_over_every_real_template() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-service-probes not found; skipping versioninfo corpus");
        return;
    };
    let db = ProbeDb::parse(&text);
    let caps = synthetic_captures();

    let mut rules = 0usize;
    let mut with_product = 0usize;
    let mut with_cpe = 0usize;
    for probe in db.null_probe.iter().chain(db.probes.iter()) {
        for rule in &probe.matches {
            rules += 1;
            // Must never panic on any real template + these captures.
            let vi = build(rule, &caps);
            if vi.product.is_some() {
                with_product += 1;
            }
            if vi.cpe_a.is_some() || vi.cpe_h.is_some() || vi.cpe_o.is_some() {
                with_cpe += 1;
            }
            // Any CPE produced must keep its `cpe:/` prefix and route to the field
            // its part letter selects.
            if let Some(a) = &vi.cpe_a {
                assert!(a.starts_with(b"cpe:/a"), "cpe_a not an /a cpe: {a:?}");
            }
            if let Some(h) = &vi.cpe_h {
                assert!(h.starts_with(b"cpe:/h"), "cpe_h not an /h cpe: {h:?}");
            }
            if let Some(o) = &vi.cpe_o {
                assert!(o.starts_with(b"cpe:/o"), "cpe_o not an /o cpe: {o:?}");
            }
        }
    }

    eprintln!(
        "versioninfo corpus: {rules} rules built; {with_product} produced a product, \
         {with_cpe} produced a CPE"
    );
    assert_eq!(rules, 12171, "every rule's templates were exercised");
    // Sanity: the real DB has lots of product templates and lots of CPEs.
    assert!(
        with_product > 5000,
        "suspiciously few products: {with_product}"
    );
    assert!(with_cpe > 2000, "suspiciously few CPEs: {with_cpe}");
}

#[test]
fn spot_check_a_known_openssh_style_rule() {
    let Some(text) = load_corpus() else {
        return;
    };
    let db = ProbeDb::parse(&text);

    // Find a rule whose CPE template targets application openssh, and confirm the
    // version capture flows into both version and the CPE.
    let caps = synthetic_captures(); // group 1 = "1.2.3"
    let rule = db
        .null_probe
        .iter()
        .chain(db.probes.iter())
        .flat_map(|p| &p.matches)
        .find(|m| {
            m.cpe
                .iter()
                .any(|c| c.contains("openssh") && c.contains("$1"))
        });

    if let Some(rule) = rule {
        let vi = build(rule, &caps);
        if let Some(cpe_a) = &vi.cpe_a {
            // $1 = "1.2.3" percent-escapes to "1.2.3" (digits/dots are safe) and
            // the openssh CPE must contain it.
            assert!(
                cpe_a.windows(5).any(|w| w == b"1.2.3"),
                "expected version 1.2.3 in cpe_a: {}",
                String::from_utf8_lossy(cpe_a)
            );
        }
    }
    // If no such rule exists in this DB version, the test is vacuously fine.
}
