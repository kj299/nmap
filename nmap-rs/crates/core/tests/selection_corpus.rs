//! M6.2 whole-corpus conformance: every rule against all 611 shipped scripts.
//!
//! The hand-written corpus in `selection_differential.rs` pins the grammar's
//! corners. This is the broader gate, and the one that says something about
//! real use: it takes the script index nmap actually ships, evaluates 45
//! realistic `--script` rules against every entry in it, and requires the same
//! answer nmap's own LPeg gave — 27,495 independent verdicts, none of them
//! chosen to be interesting.
//!
//! The golden (`m62_sweep_golden.txt`) records per rule how many scripts
//! matched, how many were selected by name, and a SHA-256 over the matching
//! filenames in index order. The digest is what makes this exact rather than
//! statistical: two different selections of the same size cannot agree.
//!
//! Note what supplies the input. The entries come from
//! `core::nse::script::parse_script_db` — the M6.1 parser — so a regression
//! there shows up here too, and the two milestones are checked together against
//! the same shipped file.

#![cfg(not(miri))] // reads the C tree from disk; Miri has no filesystem

use std::path::{Path, PathBuf};

use nmap_core::nse::script::parse_script_db;
use nmap_core::nse::selection::{matches, Entry};
use nmap_core::sigstore::digest::{to_hex, Sha256};

fn tree_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repository layout")
        .to_path_buf()
}

fn golden() -> Vec<(Vec<u8>, usize, usize, String)> {
    let path = tree_root().join("nmap-rs/tests/differential/m6/m62_sweep_golden.txt");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (run regen_m62.sh)", path.display()));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let rule = (0..f[0].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&f[0][i..i.saturating_add(2)], 16).expect("hex"))
                .collect();
            (
                rule,
                f[1].parse().expect("count"),
                f[2].parse().expect("count"),
                f[3].to_owned(),
            )
        })
        .collect()
}

#[test]
fn selection_over_the_shipped_index_matches_nmaps_own_lpeg() {
    let root = tree_root();
    let raw = std::fs::read(root.join("scripts/script.db")).expect("scripts/script.db is readable");
    let db = parse_script_db(&raw).expect("the shipped index parses");
    let entries = db.entries();
    assert!(
        entries.len() >= 600,
        "expected the full shipped index, got {}",
        entries.len()
    );

    let rules = golden();
    assert!(rules.len() >= 40, "sweep golden shrank to {}", rules.len());

    for (rule, want_matched, want_by_name, want_digest) in &rules {
        let mut matched = 0usize;
        let mut by_name = 0usize;
        let mut hasher = Sha256::new();
        let mut first = true;

        for entry in entries {
            let cats: Vec<&[u8]> = entry.categories().iter().map(Vec::as_slice).collect();
            let e = Entry::from_filename(entry.filename(), &cats);
            let sel = matches(rule, &e).unwrap_or_else(|err| {
                panic!(
                    "rule {:?} failed to parse against {:?}: {err:?}",
                    String::from_utf8_lossy(rule),
                    String::from_utf8_lossy(entry.filename())
                )
            });
            if sel.matched {
                matched += 1;
                if !first {
                    hasher.update(b"\n");
                }
                hasher.update(entry.filename());
                first = false;
            }
            if sel.by_name {
                by_name += 1;
            }
        }

        let shown = String::from_utf8_lossy(rule).into_owned();
        assert_eq!(matched, *want_matched, "rule {shown:?}: matched count");
        assert_eq!(by_name, *want_by_name, "rule {shown:?}: by_name count");
        assert_eq!(
            to_hex(&hasher.finish()),
            *want_digest,
            "rule {shown:?}: the two selections are the same size but differ"
        );
    }
}

/// The grouping trap, measured on the shipped index rather than argued about.
///
/// `safe and not intrusive or vuln` reads to most people as
/// `(safe and not intrusive) or vuln`. The grammar means
/// `safe and (not intrusive or vuln)`, and on the real corpus the two select
/// materially different sets — which is why this port reproduces the C's
/// grouping instead of "fixing" it.
#[test]
fn the_grouping_trap_changes_the_selected_set_on_real_data() {
    let root = tree_root();
    let raw = std::fs::read(root.join("scripts/script.db")).expect("readable");
    let db = parse_script_db(&raw).expect("parses");

    let count = |rule: &[u8]| {
        db.entries()
            .iter()
            .filter(|entry| {
                let cats: Vec<&[u8]> = entry.categories().iter().map(Vec::as_slice).collect();
                matches(rule, &Entry::from_filename(entry.filename(), &cats))
                    .expect("parses")
                    .matched
            })
            .count()
    };

    let as_written = count(b"safe and not intrusive or vuln");
    let as_expected = count(b"(safe and not intrusive) or vuln");
    assert_ne!(
        as_written, as_expected,
        "the grouping trap should be visible on the shipped index"
    );
    assert_eq!(as_written, 350);
    assert_eq!(as_expected, 421);
}

/// The case asymmetry, likewise measured.
///
/// A category name folds case; a filename glob does not. `--script SAFE`
/// selects 352 scripts and `--script Http-*` selects none.
#[test]
fn categories_fold_case_but_globs_do_not_on_real_data() {
    let root = tree_root();
    let raw = std::fs::read(root.join("scripts/script.db")).expect("readable");
    let db = parse_script_db(&raw).expect("parses");

    let count = |rule: &[u8]| {
        db.entries()
            .iter()
            .filter(|entry| {
                let cats: Vec<&[u8]> = entry.categories().iter().map(Vec::as_slice).collect();
                matches(rule, &Entry::from_filename(entry.filename(), &cats))
                    .expect("parses")
                    .matched
            })
            .count()
    };

    assert_eq!(count(b"safe"), count(b"SAFE"));
    assert!(count(b"http-*") > 0);
    assert_eq!(count(b"Http-*"), 0);
}
