//! SEQ-analysis differential for `core::osprobe::seq` against nmap's own arithmetic.
//!
//! The oracle (`oracle/seq_oracle`) carries `gcd_n_uint`, the ISN rate/standard-deviation
//! block and the timestamp-frequency bucketing copied **verbatim** from `makeTSeqFP` in
//! `osscan2.cc`; only the surrounding `HostOsScan` plumbing is replaced by a stdin
//! driver, because the original is a method on a class that pulls in most of nmap.
//!
//! This is the most numerically delicate module in M5: `SP`, `GCD` and `ISR` come out of
//! floating-point logarithms and a standard deviation with a deliberate
//! divide-only-when-large quirk, and the `TS` buckets have hand-tuned non-power-of-two
//! boundaries. A transcription slip would not crash — it would shift a fingerprint by a
//! notch and mis-identify hosts.
//!
//! IP-ID classification (`TI`/`CI`/`II`) is deliberately out of scope here: it lives in
//! `core::ipid`, which carries its own C-oracle differential from M4.
//!
//! Corpus regeneration (offline):
//! ```text
//!   g++ -O2 -o tests/differential/m5/oracle/seq_oracle \
//!       tests/differential/m5/oracle/seq_oracle.cc -lm
//!   python3 tests/differential/m5/gen_seq_cases.py
//!   tests/differential/m5/oracle/seq_oracle < seq_cases.txt > seq_golden.txt
//! ```
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::osprobe::seq::{analyze_seq, SeqInputs, SeqReply};

fn m5_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m5")
        .canonicalize()
        .expect("m5 differential dir")
}

/// Parse one case line: `<scan_delay_ms> <n> <isn>:<usec>:<ts> ...`
fn parse_case(line: &str) -> SeqInputs {
    let mut it = line.split_whitespace();
    let scan_delay_ms: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let _n: usize = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let replies: Vec<Option<SeqReply>> = it
        .map(|field| {
            let mut parts = field.split(':');
            let isn = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let sent_usec = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let timestamp = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            Some(SeqReply {
                isn,
                ip_id: 0,
                timestamp,
                sent_usec,
            })
        })
        .collect();
    SeqInputs {
        replies,
        scan_delay_ms,
        ..SeqInputs::default()
    }
}

/// Render in the oracle's line format. A `-` is an attribute the C never set.
fn project(inputs: &SeqInputs) -> String {
    let t = analyze_seq(inputs);
    let f = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".to_owned());
    format!(
        "SP={} GCD={} ISR={} TS={}",
        f(&t.sp),
        f(&t.gcd),
        f(&t.isr),
        f(&t.ts)
    )
}

/// Value of a `KEY=` field in a projection line.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(key)
        .nth(1)
        .map(|r| r.split(' ').next().unwrap_or(""))
}

/// The projection line with its ISR field removed, for comparing everything else.
fn strip_isr(line: &str) -> String {
    line.split(' ')
        .filter(|f| !f.starts_with("ISR="))
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn seq_analysis_matches_the_c_arithmetic() {
    let dir = m5_dir();
    let cases = fs::read_to_string(dir.join("seq_cases.txt")).expect("seq_cases.txt");
    let golden = fs::read_to_string(dir.join("seq_golden.txt")).expect("seq_golden.txt");

    let cases: Vec<&str> = cases.lines().collect();
    let golden: Vec<&str> = golden.lines().collect();
    assert_eq!(
        cases.len(),
        golden.len(),
        "case and golden files are out of step"
    );
    assert!(cases.len() > 300, "corpus is suspiciously small");

    let mut with_isn = 0usize;
    let mut with_ts = 0usize;
    let mut ledgered_ub = 0usize;
    for (i, (case, want)) in cases.iter().zip(golden.iter()).enumerate() {
        let inputs = parse_case(case);
        let got = project(&inputs);

        // Ledgered divergence `seq-isr-no-negative-cast` (DIVERGENCES.md): when the ISN
        // rate falls below 1 per second, the C evaluates
        // `(unsigned int)(log2(rate) * 8 + 0.5)` on a NEGATIVE double. That conversion is
        // undefined behaviour; in practice it wraps, and the golden records the wrapped
        // value (anything at or above 0x80000000 is one). We saturate to 0 instead.
        if let Some(isr) = field(want, "ISR=") {
            if isr != "-" {
                if let Ok(v) = u32::from_str_radix(isr, 16) {
                    if v >= 0x8000_0000 {
                        assert_eq!(
                            field(&got, "ISR="),
                            Some("0"),
                            "case {} ({}): expected the saturated ISR for the C's \
                             out-of-range conversion",
                            i + 1,
                            case
                        );
                        // Everything else in the line must still agree exactly.
                        assert_eq!(
                            strip_isr(&got),
                            strip_isr(want),
                            "case {} ({}): only ISR may diverge here",
                            i + 1,
                            case
                        );
                        ledgered_ub += 1;
                        with_isn += 1;
                        if !want.contains("TS=-") {
                            with_ts += 1;
                        }
                        continue;
                    }
                }
            }
        }

        assert_eq!(
            got,
            *want,
            "case {} ({}): Rust analysis != C arithmetic",
            i + 1,
            case
        );
        if !want.contains("SP=-") {
            with_isn += 1;
        }
        if !want.contains("TS=-") {
            with_ts += 1;
        }
    }
    // The undefined conversion must actually be reachable, or the ledger entry would be
    // documenting a case the corpus never produces.
    assert!(
        ledgered_ub > 0,
        "the C's out-of-range ISR conversion was never exercised"
    );
    eprintln!("{ledgered_ub} cases hit the C's undefined ISR conversion");

    // Both analyses must be genuinely exercised, or a corpus that had drifted to
    // all-skipped cases would pass while testing nothing.
    assert!(with_isn > 100, "only {with_isn} cases ran the ISN analysis");
    assert!(
        with_ts > 30,
        "only {with_ts} cases ran the timestamp analysis"
    );
    eprintln!(
        "{with_isn} ISN analyses, {with_ts} timestamp analyses across {} cases",
        cases.len()
    );
}

#[test]
fn every_timestamp_bucket_is_represented_in_the_corpus() {
    // The TS boundaries are hand-tuned and non-monotonic in log space, so the corpus has
    // to actually straddle them. Assert the distinct bucket values seen.
    let dir = m5_dir();
    let golden = fs::read_to_string(dir.join("seq_golden.txt")).expect("seq_golden.txt");
    let mut seen: Vec<&str> = golden
        .lines()
        .filter_map(|l| l.split("TS=").nth(1))
        .filter(|v| *v != "-")
        .collect();
    seen.sort_unstable();
    seen.dedup();
    for want in ["1", "7", "8"] {
        assert!(
            seen.contains(&want),
            "bucket TS={want} missing from the corpus, saw {seen:?}"
        );
    }
    assert!(
        seen.len() >= 6,
        "expected several distinct TS values, saw {seen:?}"
    );
}
