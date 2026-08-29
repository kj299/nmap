//! fp6 vectorize differential: `core::fp6::vectorize` must build a bit-identical
//! 695-element feature vector to nmap's real `vectorize()` (`FPEngine.cc`), pasted
//! verbatim into `tests/differential/m5/oracle/fp6_vectorize_oracle.cc` and linked
//! against the real libnetutil packet parser.
//!
//! The corpus (`fp6_vectorize_cases.txt`) is a set of probe-response observations;
//! the golden (`fp6_vectorize_golden.txt`) is the oracle's output, one line per case,
//! each value the raw IEEE-754 bit pattern of the corresponding `f64` — so the
//! comparison is exact, catching a wrong NaN, a sign, or a last-bit rounding drift.
//!
//! Regenerate both from the C with
//! `tests/differential/m5/oracle/build_fp6_vectorize_oracle.sh` +
//! `gen_fp6_vectorize_cases.py`; CI re-derives and diffs them so the golden cannot
//! drift into agreeing with a paraphrase (the #70 failure mode).
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::fp6::{vectorize, DistMethod, Fp6Observation, Fp6Probe, Fp6Response, N_FEATURE};

fn m5_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m5")
        .canonicalize()
        .expect("m5 differential dir")
}

fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u32> = s
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_digit(16).unwrap())
        .collect();
    digits
        .chunks_exact(2)
        .map(|p| u8::try_from((p[0] << 4) | p[1]).unwrap())
        .collect()
}

fn method_from(n: i32) -> DistMethod {
    match n {
        0 => DistMethod::None,
        1 => DistMethod::Localhost,
        2 => DistMethod::Direct,
        3 => DistMethod::Icmp,
        4 => DistMethod::Traceroute,
        other => panic!("unknown distance method {other}"),
    }
}

/// Parse one `case`…`end` block into an observation.
fn parse_case(lines: &[&str]) -> Fp6Observation {
    let mut distance = -1i32;
    let mut method = DistMethod::None;
    let mut responses: Vec<(Fp6Probe, Fp6Response)> = Vec::new();

    for line in lines {
        if let Some(rest) = line.strip_prefix("distance ") {
            distance = rest.trim().parse().expect("distance");
        } else if let Some(rest) = line.strip_prefix("method ") {
            method = method_from(rest.trim().parse().expect("method"));
        } else if let Some(rest) = line.strip_prefix("resp ") {
            let mut it = rest.splitn(4, ' ');
            let id = it.next().expect("probe id");
            let sec: i64 = it.next().expect("sec").parse().expect("sec");
            let usec: i64 = it.next().expect("usec").parse().expect("usec");
            let hex = it.next().unwrap_or("");
            if let Some(probe) = Fp6Probe::from_id(id) {
                responses.push((
                    probe,
                    Fp6Response {
                        packet: unhex(hex),
                        sent_sec: sec,
                        sent_usec: usec,
                    },
                ));
            }
        }
    }

    let mut obs = Fp6Observation::new(distance, method);
    for (probe, resp) in responses {
        obs.insert(probe, resp);
    }
    obs
}

#[test]
fn vectorize_matches_the_c_oracle_bit_for_bit() {
    let dir = m5_dir();
    let cases = fs::read_to_string(dir.join("fp6_vectorize_cases.txt")).expect("cases");
    let golden = fs::read_to_string(dir.join("fp6_vectorize_golden.txt")).expect("golden");

    // Split the corpus into case blocks.
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in cases.lines() {
        let line = line.trim_end();
        if line == "case" {
            if let Some(b) = current.take() {
                blocks.push(b);
            }
            current = Some(Vec::new());
        } else if line == "end" {
            if let Some(b) = current.take() {
                blocks.push(b);
            }
        } else if let Some(b) = current.as_mut() {
            b.push(line);
        }
    }

    let golden_lines: Vec<&str> = golden.lines().collect();
    assert_eq!(
        blocks.len(),
        golden_lines.len(),
        "case count {} != golden line count {}",
        blocks.len(),
        golden_lines.len()
    );
    assert!(
        blocks.len() >= 1500,
        "expected the full corpus, got {}",
        blocks.len()
    );

    for (n, (block, gold)) in blocks.iter().zip(golden_lines.iter()).enumerate() {
        let obs = parse_case(block);
        let got = vectorize(&obs);
        assert_eq!(got.len(), N_FEATURE);

        let want: Vec<u64> = gold
            .split_whitespace()
            .skip(1) // the leading "v"
            .map(|t| u64::from_str_radix(t, 16).expect("hex bits"))
            .collect();
        assert_eq!(
            want.len(),
            N_FEATURE,
            "golden case {n} has {} values",
            want.len()
        );

        for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(
                g.to_bits(),
                *w,
                "case {n} feature {i} differs: rust {:016x} ({g}) vs C {w:016x}",
                g.to_bits()
            );
        }
    }
    eprintln!(
        "fp6 vectorize differential: {} cases match the C oracle",
        blocks.len()
    );
}
