//! IPv6 response-matching differential: `core::fp6_match::is_response` must return the
//! same match/nomatch verdict as nmap's real `PacketParser::is_response` for every
//! (sent probe, candidate response) pair in the corpus.
//!
//! The oracle (`tests/differential/m5/oracle/fp6match_oracle`) links nmap's own
//! `PacketParser::is_response` and the full libnetutil parser it walks. The corpus pairs
//! each real build6 battery probe with the genuine response nmap would attribute to it
//! and with near-miss non-responses (mirrored addresses but wrong ports / id / seq /
//! target / solicited flag, an error quoting the wrong datagram, a reply from the wrong
//! host). The committed corpus + golden are re-derived from the C on every CI run by
//! `regen_fp6match.sh --check`, so they cannot drift.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::fp6_match::is_response;

fn m5_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m5")
        .canonicalize()
        .expect("m5 differential dir")
}

fn unhex(s: &str) -> Vec<u8> {
    let d: Vec<u32> = s
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_digit(16).unwrap())
        .collect();
    d.chunks_exact(2)
        .map(|p| u8::try_from((p[0] << 4) | p[1]).unwrap())
        .collect()
}

#[test]
fn fp6_match_matches_c_oracle_over_the_corpus() {
    let dir = m5_dir();
    let cases = fs::read_to_string(dir.join("fp6match_cases.txt")).expect("fp6match_cases.txt");
    let golden = fs::read_to_string(dir.join("fp6match_golden.txt")).expect("fp6match_golden.txt");
    let verdicts: Vec<&str> = golden
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2)) // "case N <verdict>"
        .collect();

    let mut i = 0usize;
    let mut matches = 0usize;
    for line in cases.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let sent = unhex(it.next().unwrap());
        let rcvd = unhex(it.next().unwrap());
        let got = is_response(&sent, &rcvd);
        let want = verdicts[i] == "match";
        assert_eq!(
            got,
            want,
            "case {} disagrees with the C oracle (rust={got}, c={})\n  sent={}\n  rcvd={}",
            i + 1,
            verdicts[i],
            it.clone().count(),
            line
        );
        if want {
            matches += 1;
        }
        i += 1;
    }
    assert!(i >= 240, "expected the full corpus, checked {i}");
    assert!(
        matches >= 40,
        "corpus should contain real matches, found {matches}"
    );
    eprintln!("fp6_match differential: {i} pairs agree with the C oracle ({matches} matches)");
}
