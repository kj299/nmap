//! Differential gate for `core::osdb::expr` against nmap's real `expr_match()`.
//!
//! The oracle (`tests/differential/m5/oracle/expr_oracle.cc`) is a **verbatim**
//! transcription of `expr_match()` from `osscan.cc` plus its one dependency,
//! `strchr_p()` from nbase — both self-contained pointer walkers with no nmap globals.
//! The committed golden pairs each case in `expr_cases.tsv` with the C's outcome.
//!
//! Cases come from three sources (see `oracle/gen_expr_cases.py`): every shape the
//! expression grammar has including degenerate ones, real expressions and values
//! harvested from the shipped 5 MB `nmap-os-db`, and a deterministic pseudo-random
//! cross-product built from the grammar's own tokens.
//!
//! The golden has **three** outcomes, not two. `ABORT` records that the C *died* on
//! that input — its `assert(q1)` firing on an expression with `[` and no `]`. Those
//! cases are the ledgered divergence `osdb-expr-unterminated-nest-no-abort`: the port
//! must return a value rather than abort, and it must not panic.
//!
//! Regenerate (offline, requires g++):
//!   ./tests/differential/m5/oracle/build_expr_oracle.sh
//!   cd tests/differential/m5 && python3 oracle/gen_expr_cases.py ../../../../nmap-os-db > expr_cases.tsv
//!   ./oracle/expr_oracle < expr_cases.tsv > expr_golden.txt
//!
//! Skipped under Miri: it reads committed files, and Miri's filesystem isolation
//! *aborts* rather than returning `Err` (the unit suite in `osdb::expr` is what Miri
//! interrogates).
#![cfg(not(miri))]

use nmap_core::osdb::expr::expr_match;

/// Load the case/golden pair, or `None` in a stripped checkout.
fn load() -> Option<(Vec<String>, Vec<String>)> {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/differential/m5/");
    let cases = std::fs::read_to_string(format!("{base}expr_cases.tsv")).ok()?;
    let golden = std::fs::read_to_string(format!("{base}expr_golden.txt")).ok()?;
    Some((
        cases.lines().map(str::to_owned).collect(),
        golden.lines().map(str::to_owned).collect(),
    ))
}

/// Split a case line into `(do_nested, val, expr)`.
fn parse_case(line: &str) -> Option<(bool, &str, &str)> {
    let mut it = line.splitn(3, '\t');
    let nested = it.next()? != "0";
    let val = it.next()?;
    let expr = it.next()?;
    Some((nested, val, expr))
}

#[test]
fn matches_the_c_on_every_case_the_c_survives() {
    let Some((cases, golden)) = load() else {
        eprintln!("expr differential corpus not found; skipping");
        return;
    };
    assert_eq!(cases.len(), golden.len(), "case/golden length mismatch");
    assert!(cases.len() > 20_000, "corpus unexpectedly small");

    let mut compared = 0usize;
    let mut aborts = 0usize;
    let mut matched = 0usize;

    for (i, (line, want)) in cases.iter().zip(golden.iter()).enumerate() {
        let Some((nested, val, expr)) = parse_case(line) else {
            panic!("case {i} is malformed: {line:?}");
        };
        let got = expr_match(val.as_bytes(), expr.as_bytes(), nested);

        match want.as_str() {
            "ABORT" => {
                // The C aborts here; we only require that we produced a value.
                aborts += 1;
                let _ = got;
            }
            "0" | "1" => {
                let want_bool = want == "1";
                assert_eq!(
                    got, want_bool,
                    "case {i} diverged: do_nested={nested} val={val:?} expr={expr:?} \
                     (C said {want_bool}, we said {got})"
                );
                compared += 1;
                if want_bool {
                    matched += 1;
                }
            }
            other => panic!("case {i}: unexpected golden token {other:?}"),
        }
    }

    // Guard against a corpus that degenerates into "everything is false": the gate is
    // only meaningful if a healthy number of cases actually match.
    assert!(
        matched > 1_000,
        "only {matched} positive matches — corpus lost its discriminating power"
    );
    eprintln!("expr differential: {compared} compared ({matched} matches), {aborts} C-aborts");
}

#[test]
fn the_c_aborts_where_we_return_a_value() {
    let Some((cases, golden)) = load() else {
        eprintln!("expr differential corpus not found; skipping");
        return;
    };
    // The abort cases are the whole point of the divergence; make sure the corpus
    // actually contains them and that every one is an unterminated '[' under nesting.
    let mut aborts = 0usize;
    for (line, want) in cases.iter().zip(golden.iter()) {
        if want != "ABORT" {
            continue;
        }
        aborts += 1;
        let (nested, val, expr) = parse_case(line).expect("well-formed case");
        assert!(
            nested,
            "the C only reaches the assert with do_nested: {expr:?}"
        );
        assert!(
            expr.contains('['),
            "an aborting expression must contain '[': {expr:?}"
        );
        // Our port is total: it returns, and (by construction) declines to match.
        assert!(
            !expr_match(val.as_bytes(), expr.as_bytes(), nested),
            "unterminated nest should not match: val={val:?} expr={expr:?}"
        );
    }
    assert!(
        aborts > 100,
        "expected the corpus to exercise the C's abort path, saw {aborts}"
    );
}
