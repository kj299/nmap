//! SHA-256 differential against the system `sha256sum`.
//!
//! `core::sigstore::digest` is a hand-rolled SHA-256, carried in-tree rather than
//! taken as a dependency (see that module's docs for the trade). The only gate worth
//! having on such a thing is agreement with an independent, widely-exercised
//! implementation — so the golden in `tests/differential/s/sha256_golden.txt` is
//! produced by GNU coreutils' `sha256sum`, and `regen_sha256.sh --check` re-derives
//! it on every CI run.
//!
//! Comparing against a second hand-rolled implementation would prove only that the
//! two agree with each other. This proves agreement with the thing everyone else
//! uses.
//!
//! The corpus is weighted toward the padding and buffering boundaries, because that
//! is where this actually went wrong: the first draft reset the buffer length to
//! zero whenever a call was fully consumed topping up a partial block, which made
//! `finish` spin forever.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::sigstore::digest::{to_hex, Sha256};

fn s_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/s")
        .canonicalize()
        .expect("s differential dir")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let d = std::str::from_utf8(pair).expect("hex digits are ascii");
            u8::from_str_radix(d, 16).unwrap_or_else(|_| panic!("bad hex `{d}`"))
        })
        .collect()
}

#[test]
fn every_case_matches_the_system_sha256sum() {
    let dir = s_dir();
    let cases = fs::read_to_string(dir.join("sha256_cases.txt")).expect("committed corpus");
    let golden = fs::read_to_string(dir.join("sha256_golden.txt")).expect("committed golden");
    let mut golden = golden.lines();
    let mut compared = 0usize;

    for line in cases.lines() {
        let mut parts = line.split_whitespace();
        let id = parts.next().expect("case id");
        let data = parts.next().map(unhex).unwrap_or_default();

        let expected_line = golden.next().expect("golden has a line for every case");
        let (gid, expected) = expected_line
            .split_once(' ')
            .expect("golden line is `<id> <digest>`");
        assert_eq!(gid, id, "golden is out of order with the corpus");

        let got = to_hex(&Sha256::digest(&data));
        assert_eq!(
            got, expected,
            "case `{id}` ({} bytes) diverges from sha256sum\n  sha256sum: {expected}\n  ours:      {got}",
            data.len()
        );

        // The streaming path must agree with the one-shot path on the same input --
        // it is a different code path through the same algorithm, and the one that
        // has already had a bug.
        if !data.is_empty() {
            let mut h = Sha256::new();
            let mid = data.len() / 2;
            h.update(&data[..mid]);
            h.update(&data[mid..]);
            assert_eq!(to_hex(&h.finish()), expected, "case `{id}` streamed in two");
        }

        compared = compared.saturating_add(1);
    }

    assert!(golden.next().is_none(), "golden has unconsumed cases");
    assert!(compared >= 600, "only {compared} cases compared");
    eprintln!("sha256 differential: {compared} cases match the system sha256sum");
}
