//! IP-ID sequence-classification differential: `core::ipid` must produce the same
//! class as nmap's `get_ipid_sequence_16`/`_32` (`osscan2.cc`) for every sequence in
//! `ipid_cases.txt`. Golden from `ipid_oracle` (a near-verbatim copy of the C
//! functions). The corpus spans all classes (incr / incr-by-2 / broken / rpi / rd /
//! constant / zero) at 16 and 32 bits, localhost and not, plus edge cases (16-bit
//! wrap, near-threshold jumps, u32 extremes).
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::ipid::{get_ipid_sequence_16, get_ipid_sequence_32, IpidSequence};

fn tok(s: IpidSequence) -> &'static str {
    match s {
        IpidSequence::Unknown => "unknown",
        IpidSequence::Incr => "incr",
        IpidSequence::BrokenIncr => "broken_incr",
        IpidSequence::Rpi => "rpi",
        IpidSequence::Rd => "rd",
        IpidSequence::Constant => "constant",
        IpidSequence::Zero => "zero",
        IpidSequence::IncrBy2 => "incr_by_2",
    }
}

fn m4_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m4")
        .canonicalize()
        .expect("m4 differential dir")
}

fn rust_result(fields: &[&str]) -> String {
    let bits: u32 = fields[0].parse().unwrap();
    let islocal = fields[1] == "1";
    let n: usize = fields[2].parse().unwrap();
    let ipids: Vec<u32> = fields
        .iter()
        .skip(3)
        .take(n)
        .map(|f| f.parse().unwrap())
        .collect();
    let r = if bits == 16 {
        get_ipid_sequence_16(&ipids, islocal)
    } else {
        get_ipid_sequence_32(&ipids, islocal)
    };
    tok(r).to_string()
}

#[test]
fn ipid_matches_c_oracle_over_the_corpus() {
    let dir = m4_dir();
    let cases = fs::read_to_string(dir.join("ipid_cases.txt")).expect("ipid_cases.txt");
    let golden = fs::read_to_string(dir.join("ipid_golden.txt")).expect("ipid_golden.txt");

    let case_lines: Vec<&str> = cases.lines().filter(|l| !l.trim().is_empty()).collect();
    let gold_lines: Vec<&str> = golden.lines().collect();
    assert_eq!(
        case_lines.len(),
        gold_lines.len(),
        "case/golden count mismatch"
    );
    assert!(case_lines.len() >= 60, "expected the full ipid corpus");

    let mut checked = 0;
    for (case, want) in case_lines.iter().zip(gold_lines.iter()) {
        let fields: Vec<&str> = case.split_whitespace().collect();
        let got = rust_result(&fields);
        assert_eq!(
            &got, want,
            "ipid classification diverges from the C oracle for `{case}`: rust={got} c={want}"
        );
        checked += 1;
    }
    eprintln!("ipid differential: {checked} sequences match the C oracle");
}
