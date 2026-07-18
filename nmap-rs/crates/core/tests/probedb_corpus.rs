//! Differential/regression gate for `core::probedb` against the **real** 2.5 MB
//! `nmap-service-probes` shipped in the C tree.
//!
//! The oracle is the C parser (`parse_nmap_service_probe_file`): on this file it
//! builds exactly one NULL probe, N non-NULL probes, and one `MatchRule` per
//! `match`/`softmatch` line — no line dropped, since the shipped file is
//! well-formed. We assert our structural counts equal the file's ground truth
//! (the same counts a `grep -c` over the file yields, which is what the C parser
//! must also produce). A clean file must parse with **zero warnings** — any
//! warning here is a real divergence from the C parser to investigate.
//!
//! Ground truth (from the shipped file):
//!   Probe lines      : 187  (103 TCP + 84 UDP)
//!   NULL probe       :   1
//!   match  lines     : 11968
//!   softmatch lines  :   203
//!   Exclude          :   1  (T:9100-9107)
//!
//! Skipped under Miri: this is a differential/regression gate that reads a real
//! file, not a UB check (the unit suite in `probedb.rs` is what Miri interrogates).
//! Miri runs with filesystem isolation, under which `std::fs` *aborts* rather than
//! returning an `Err` — so the whole file is `cfg`-excluded from a Miri build.
#![cfg(not(miri))]

use nmap_core::model::Protocol;
use nmap_core::probedb::{ProbeDb, ProbeProtocol};

/// Locate the shipped probe file relative to this crate (repo-root sibling of
/// `nmap-rs/`). Skips (does not fail) if absent, so the unit suite still runs in
/// a stripped checkout.
fn load_corpus() -> Option<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nmap-service-probes");
    std::fs::read_to_string(path).ok()
}

#[test]
fn corpus_structural_counts_match_c_oracle() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-service-probes not found; skipping corpus differential");
        return;
    };
    let db = ProbeDb::parse(&text);

    // A well-formed file must parse cleanly — no localized skips.
    assert!(
        db.warnings.is_empty(),
        "expected 0 warnings on the shipped file, got {}: {:?}",
        db.warnings.len(),
        &db.warnings[..db.warnings.len().min(5)]
    );

    // Exactly one NULL probe, and it is the empty-string TCP one.
    let null = db.null_probe.as_ref().expect("NULL probe present");
    assert!(null.is_null_probe());
    assert_eq!(null.protocol, ProbeProtocol::Tcp);
    assert_eq!(null.name, "NULL");

    // 187 Probe lines − 1 NULL = 186 non-NULL probes.
    assert_eq!(db.probes.len(), 186, "non-NULL probe count");

    // Protocol split: 103 TCP total − 1 NULL = 102 TCP non-NULL; 84 UDP.
    let tcp = db
        .probes
        .iter()
        .filter(|p| p.protocol == ProbeProtocol::Tcp)
        .count();
    let udp = db
        .probes
        .iter()
        .filter(|p| p.protocol == ProbeProtocol::Udp)
        .count();
    assert_eq!(tcp, 102, "non-NULL TCP probes");
    assert_eq!(udp, 84, "UDP probes");

    // One MatchRule per match/softmatch line, across all probes (incl. NULL).
    let all_probes = std::iter::once(null).chain(db.probes.iter());
    let (mut hard, mut soft) = (0usize, 0usize);
    for p in all_probes {
        for m in &p.matches {
            if m.soft {
                soft += 1;
            } else {
                hard += 1;
            }
        }
    }
    assert_eq!(hard, 11968, "hard match rules");
    assert_eq!(soft, 203, "softmatch rules");
    assert_eq!(hard + soft, 12171, "total match rules");

    // Exclude directive: T:9100-9107.
    assert!(db.excluded_seen);
    for port in 9100..=9107 {
        assert!(db.is_excluded(port, Protocol::Tcp), "port {port} excluded");
    }
    assert!(!db.is_excluded(9099, Protocol::Tcp));
    assert!(!db.is_excluded(9108, Protocol::Tcp));
}

#[test]
fn every_match_rule_has_a_nonempty_pattern_and_service() {
    let Some(text) = load_corpus() else {
        return;
    };
    let db = ProbeDb::parse(&text);
    let all = db.null_probe.iter().chain(db.probes.iter());
    for p in all {
        for m in &p.matches {
            assert!(!m.service.is_empty(), "empty service in probe {}", p.name);
            assert!(!m.pattern.is_empty(), "empty pattern in probe {}", p.name);
        }
    }
}
