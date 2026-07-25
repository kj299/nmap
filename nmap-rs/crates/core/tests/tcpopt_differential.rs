//! TCP-option-summary differential for `core::osprobe::analyze::tcp_option_string`
//! against nmap's **real** encoder.
//!
//! The oracle (`oracle/parse_oracle tcpopt`) carries `tcpopt_string_ctx` and
//! `tcpopt_tostring` copied verbatim from `osscan2.cc`, driven by the `TCPOptions` walk
//! from `libnetutil/TCPHeader.cc`. Only `get_tcpopt_string`'s wrapper is re-expressed,
//! because the original is a `HostOsScan` method.
//!
//! This value is the `OPS` test's `O1`–`O6` and the `O` attribute of `ECN` and `T1`–`T7`,
//! so it is matched against every database entry by `osdb::expr`. Getting it subtly wrong
//! would not fail loudly — it would quietly identify the wrong operating system.
//!
//! Corpus regeneration (offline, requires the C oracle built once via `oracle/build.sh`):
//! ```text
//!   python3 tests/differential/m5/gen_tcpopt_cases.py
//!   while IFS= read -r line; do
//!     printf '%s' "$line" | tests/differential/m4/oracle/parse_oracle tcpopt \
//!       | tr '\n' '|'; echo
//!   done < tcpopt_cases.txt > tcpopt_golden.txt
//! ```
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::osprobe::analyze::tcp_option_string;

fn m5_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m5")
        .canonicalize()
        .expect("m5 differential dir")
}

fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .chars()
        .filter_map(|c| c.to_digit(16))
        .filter_map(|d| u8::try_from(d).ok())
        .collect();
    digits
        .chunks(2)
        .map(|p| (p[0] << 4) | p.get(1).copied().unwrap_or(0))
        .collect()
}

/// Render our result in the oracle's line format.
fn project(segment: &[u8]) -> String {
    match tcp_option_string(segment) {
        Ok(s) => format!("tcpopt len={} str={}|result ok|", s.len(), s),
        Err(_) => "result err:-1|".to_owned(),
    }
}

#[test]
fn option_summaries_match_the_c_encoder() {
    let dir = m5_dir();
    let cases = fs::read_to_string(dir.join("tcpopt_cases.txt")).expect("tcpopt_cases.txt");
    let golden = fs::read_to_string(dir.join("tcpopt_golden.txt")).expect("tcpopt_golden.txt");

    let cases: Vec<&str> = cases.lines().collect();
    let golden: Vec<&str> = golden.lines().collect();
    assert_eq!(
        cases.len(),
        golden.len(),
        "case and golden files are out of step"
    );
    assert!(cases.len() > 300, "corpus is suspiciously small");

    let mut ok = 0usize;
    let mut err = 0usize;
    for (i, (case, want)) in cases.iter().zip(golden.iter()).enumerate() {
        let bytes = unhex(case);
        let got = project(&bytes);
        assert_eq!(
            got,
            *want,
            "case {} ({}): Rust encoder != C encoder",
            i + 1,
            case
        );
        if want.contains("result ok") {
            ok += 1;
        } else {
            err += 1;
        }
    }

    // Both paths must be genuinely exercised — a corpus that had drifted to all-errors
    // would still pass every assertion above while testing almost nothing.
    assert!(ok > 200, "only {ok} cases produced a summary");
    assert!(err > 100, "only {err} cases were rejected");
    eprintln!(
        "{ok} summaries, {err} rejections across {} cases",
        cases.len()
    );
}

#[test]
fn nmaps_own_probe_options_summarise_the_way_the_c_reads_them() {
    // The first cases in the corpus are nmap's own `prbOpts[]` blocks, so the encoder is
    // pinned against the exact option sets the scanner puts on the wire.
    let dir = m5_dir();
    let cases = fs::read_to_string(dir.join("tcpopt_cases.txt")).expect("tcpopt_cases.txt");
    let first = cases.lines().next().expect("at least one case");
    let summary = tcp_option_string(&unhex(first)).expect("nmap's own options must parse");
    assert!(
        summary.contains('M') && summary.contains('W') && summary.contains('T'),
        "the first probe block carries MSS, window scale and a timestamp, got {summary:?}"
    );
}
