//! Scan-response classification differential: `core::classify` must produce the same
//! port state as nmap's `scan_engine_raw.cc` / `set_default_port_state` decision logic
//! for **every** `(scan, response)` combination. The oracle
//! (`oracle/classify_oracle.cc`) is a line-annotated transcription of those branches;
//! `classify_cases.txt` enumerates the full matrix (default states, all 256 TCP flag
//! bytes × 2 windows, ICMP type×code×from_target, SCTP chunks), and
//! `classify_golden.txt` is its output. This is an exhaustive check, not a sample.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::classify::{
    classify_icmp, classify_sctp, classify_tcp, default_port_state, PortState, ScanType,
};

fn scan(s: &str) -> ScanType {
    match s {
        "syn" => ScanType::Syn,
        "connect" => ScanType::Connect,
        "ack" => ScanType::Ack,
        "window" => ScanType::Window,
        "maimon" => ScanType::Maimon,
        "fin" => ScanType::Fin,
        "null" => ScanType::Null,
        "xmas" => ScanType::Xmas,
        "udp" => ScanType::Udp,
        "ipproto" => ScanType::IpProto,
        "sctpinit" => ScanType::SctpInit,
        "sctpcookie" => ScanType::SctpCookieEcho,
        other => panic!("unknown scan token {other}"),
    }
}

fn tok(s: PortState) -> &'static str {
    match s {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::Unfiltered => "unfiltered",
        PortState::OpenFiltered => "openfiltered",
        PortState::ClosedFiltered => "closedfiltered",
        PortState::Unknown => "unknown",
    }
}

fn opt_tok(s: Option<PortState>) -> String {
    s.map_or_else(|| "none".to_string(), |st| tok(st).to_string())
}

fn m4_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m4")
        .canonicalize()
        .expect("m4 differential dir")
}

fn rust_result(fields: &[&str]) -> String {
    let sc = scan(fields[1]);
    match fields[0] {
        "default" => {
            let defeat = fields[2] == "1";
            tok(default_port_state(sc, defeat)).to_string()
        }
        "tcp" => {
            let flags = fields[2].parse::<u16>().unwrap();
            let window = fields[3].parse::<u16>().unwrap();
            opt_tok(classify_tcp(sc, u8::try_from(flags).unwrap_or(0), window))
        }
        "icmp" => {
            let t = fields[2].parse::<u8>().unwrap();
            let c = fields[3].parse::<u8>().unwrap();
            let from_target = fields[4] == "1";
            opt_tok(classify_icmp(sc, t, c, from_target))
        }
        "sctp" => {
            let chunk = fields[2].parse::<u8>().unwrap();
            opt_tok(classify_sctp(sc, chunk))
        }
        other => panic!("unknown case kind {other}"),
    }
}

#[test]
fn classify_matches_c_oracle_over_the_full_matrix() {
    let dir = m4_dir();
    let cases = fs::read_to_string(dir.join("classify_cases.txt")).expect("classify_cases.txt");
    let golden = fs::read_to_string(dir.join("classify_golden.txt")).expect("classify_golden.txt");

    let case_lines: Vec<&str> = cases.lines().collect();
    let gold_lines: Vec<&str> = golden.lines().collect();
    assert_eq!(
        case_lines.len(),
        gold_lines.len(),
        "cases and golden line counts differ"
    );
    assert!(case_lines.len() >= 12_000, "expected the full matrix");

    let mut checked = 0;
    for (case, want) in case_lines.iter().zip(gold_lines.iter()) {
        let fields: Vec<&str> = case.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let got = rust_result(&fields);
        assert_eq!(
            &got, want,
            "classify diverges from the C oracle for case `{case}`: rust={got} c={want}"
        );
        checked += 1;
    }
    eprintln!("classify differential: {checked} cases match the C oracle");
}
