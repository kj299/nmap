//! Ed25519 / minisign differential against the OpenSSL CLI.
//!
//! `core::sigstore::verify` consumes signatures; this proves it consumes the ones
//! an *independent* implementation produces, and refuses that implementation's
//! near-misses. Every signature in `tests/differential/s/minisign_cases.txt` was
//! made by `openssl pkeyutl -sign -rawin`, and `regen_minisign.sh --check`
//! re-derives the whole corpus on every CI run — including the Rust fixtures the
//! unit tests use, so those cannot drift from it either.
//!
//! The generator refuses to emit anything unless OpenSSL first reproduces the
//! RFC 8032 section 7.1 vectors byte for byte, so a green run here rests on a
//! toolchain that has been checked against the standard rather than against
//! itself.
//!
//! # The two directions this checks
//!
//! **Soundness.** No case OpenSSL rejects may be accepted here. That is the
//! property whose failure would be a vulnerability, and it is asserted for every
//! row rather than only the ones designed to test it.
//!
//! **Deliberate strictness.** Some rows carry a genuine, OpenSSL-verified
//! signature that this port refuses anyway — prehashed mode, non-canonical base64,
//! bytes appended after line 4, a UTF-8 trusted comment. Those are the divergences
//! argued in `DIVERGENCES.md`, and the exact set is pinned below: adding one
//! without recording it fails this test, which is the point.
#![cfg(not(miri))]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use nmap_core::sigstore::verify::{verify_manifest, KeyRing};

fn s_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/s")
        .canonicalize()
        .expect("s differential dir")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let d = std::str::from_utf8(pair).expect("hex digits are ascii");
            u8::from_str_radix(d, 16).unwrap_or_else(|_| panic!("bad hex `{d}`"))
        })
        .collect()
}

struct Case {
    name: String,
    pubkey: String,
    manifest: Vec<u8>,
    signature: Vec<u8>,
    note: String,
    oracle: String,
    expected: String,
}

fn corpus() -> Vec<Case> {
    let dir = s_dir();
    let cases = fs::read_to_string(dir.join("minisign_cases.txt")).expect("cases");
    let golden = fs::read_to_string(dir.join("minisign_golden.txt")).expect("golden");

    let verdicts: Vec<(String, String, String)> = golden
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let mut f = l.split('\t');
            (
                f.next().expect("name").to_owned(),
                f.next().expect("oracle").to_owned(),
                f.next().expect("expected").to_owned(),
            )
        })
        .collect();

    let parsed: Vec<Case> = cases
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .zip(verdicts)
        .map(|(l, (gname, oracle, expected))| {
            let mut f = l.split('\t');
            let name = f.next().expect("name").to_owned();
            assert_eq!(name, gname, "corpus and golden are out of step");
            Case {
                name,
                pubkey: f.next().expect("pubkey").to_owned(),
                manifest: unhex(f.next().expect("manifest")),
                signature: unhex(f.next().expect("minisig")),
                note: f.next().unwrap_or("").to_owned(),
                oracle,
                expected,
            }
        })
        .collect();
    assert!(parsed.len() >= 30, "corpus shrank to {}", parsed.len());
    parsed
}

/// What this port does with one case: a key it refuses is a rejection too.
fn verdict(case: &Case) -> Result<(), String> {
    let ring = KeyRing::from_minisign_b64_lines([case.pubkey.as_bytes()])
        .map_err(|e| format!("key: {e}"))?;
    verify_manifest(&ring, &case.manifest, &case.signature)
        .map(|_| ())
        .map_err(|e| format!("{e}"))
}

#[test]
fn every_case_reaches_the_verdict_the_golden_records() {
    let mut failures = Vec::new();
    for case in corpus() {
        let got = verdict(&case);
        let got_label = if got.is_ok() { "ACCEPT" } else { "REJECT" };
        if got_label != case.expected {
            failures.push(format!(
                "{}: expected {}, got {} ({}) -- {}",
                case.name,
                case.expected,
                got_label,
                got.err().unwrap_or_default(),
                case.note
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn nothing_openssl_rejects_is_ever_accepted_here() {
    // The soundness direction. A failure of this assertion is a vulnerability,
    // not a style disagreement, so it is checked on every row.
    for case in corpus() {
        if case.oracle == "OPENSSL_FAIL" {
            assert!(
                verdict(&case).is_err(),
                "{}: OpenSSL rejects this signature and we accepted it -- {}",
                case.name,
                case.note
            );
        }
    }
}

#[test]
fn everything_openssl_accepts_is_accepted_unless_the_divergence_is_recorded() {
    // The exact set of cases where a genuine, OpenSSL-verified signature is
    // refused anyway. Each is argued in DIVERGENCES.md. A new entry appearing
    // here without being added to this list fails the test — which is how an
    // accidental incompatibility is told apart from a deliberate one.
    let recorded: BTreeSet<&str> = [
        "small_order_r",
        "transplanted_envelope",
        "tampered_global_signature",
        "rewritten_trusted_comment",
        "prehashed_mode",
        "non_canonical_b64_signature",
        "non_canonical_b64_global",
        "appended_junk",
        "missing_global_signature",
        "stray_carriage_return",
        "unknown_envelope_field",
        "envelope_too_new",
        "serial_mismatch",
        "envelope_version_not_first",
        "duplicate_envelope_field",
        "envelope_missing_serial",
        "bad_untrusted_prefix",
        "bad_trusted_prefix",
        "non_ascii_trusted_comment",
        "oversized_trusted_comment",
    ]
    .into_iter()
    .collect();

    let mut found = BTreeSet::new();
    for case in corpus() {
        if case.oracle == "OPENSSL_OK" && verdict(&case).is_err() {
            found.insert(case.name);
        }
    }
    let found: BTreeSet<&str> = found.iter().map(String::as_str).collect();

    let unrecorded: Vec<_> = found.difference(&recorded).collect();
    assert!(
        unrecorded.is_empty(),
        "these carry a valid signature and were refused, but are not recorded as \
         deliberate divergences: {unrecorded:?}"
    );
    let stale: Vec<_> = recorded.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "recorded as divergences but no longer refused: {stale:?}"
    );
}

#[test]
fn the_corpus_covers_both_verdicts_and_every_fault_class() {
    let cases = corpus();
    let accepts = cases.iter().filter(|c| c.expected == "ACCEPT").count();
    let rejects = cases.iter().filter(|c| c.expected == "REJECT").count();
    assert!(accepts >= 5, "only {accepts} accepting cases");
    assert!(rejects >= 20, "only {rejects} rejecting cases");
    // A corpus of only-invalid signatures would pass a verifier that rejects
    // everything, so pin that the oracle really did produce good ones too.
    let oracle_ok = cases.iter().filter(|c| c.oracle == "OPENSSL_OK").count();
    assert!(oracle_ok >= 20, "only {oracle_ok} OpenSSL-valid signatures");
}
