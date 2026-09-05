//! NDP differential: the Neighbor Solicitation `core::ndp` builds must be
//! **byte-identical** to the frame nmap's `doND()` transmits, and its reading of a
//! Neighbor Advertisement must reach the same verdict as nmap's `accept_ns()` +
//! `read_ns_reply_pcap()` — everywhere the C's behavior is actually defined.
//!
//! The oracle (`tests/differential/m5/oracle/ndp_oracle`) pastes those three functions
//! verbatim and packs the frame with the real libdnet macros (`eth_pack_hdr`,
//! `ip6_pack_hdr`, `icmpv6_pack_hdr_ns_mac`) and the real `ip6_checksum`, so the golden
//! records where nmap's own code puts each byte rather than where this port thinks it
//! should. `regen_ndp.sh --check` re-derives the corpus on every CI run.
//!
//! # The gap in the corpus is the point
//!
//! `accept_ns` admits a capture of `offset+44` bytes; `read_ns_reply_pcap` then reads
//! the 16-byte target at `offset+48..offset+64` **unconditionally**. Captures in that
//! gap make the C read past the captured data, so there is no defined behavior to
//! record and the generator emits none. This test asserts agreement on the defined
//! domain; [`rejects_every_capture_in_the_cs_out_of_bounds_gap`] covers the gap by
//! asserting the Rust rejects all of it.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::ndp::{
    build_neighbor_solicitation, parse_neighbor_advertisement, ETH_HDR_LEN, ICMPV6_HDR_LEN,
    IP6_HDR_LEN,
};

fn m5_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m5")
        .canonicalize()
        .expect("m5 differential dir")
}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let d = std::str::from_utf8(pair).expect("hex digits are ascii");
            u8::from_str_radix(d, 16).expect("hex")
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fixed<const N: usize>(s: &str) -> [u8; N] {
    let v = unhex(s);
    assert_eq!(v.len(), N, "expected {N} bytes in {s}");
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

/// Render a case the way the oracle prints its verdict, so the two are compared as
/// strings and any difference shows up as the exact field that diverged.
fn rust_verdict(case: &str) -> String {
    let f: Vec<&str> = case.split_whitespace().collect();
    match f[0] {
        "ns" => {
            let mac = fixed::<6>(f[1]);
            let src = fixed::<16>(f[2]);
            let tgt = fixed::<16>(f[3]);
            format!("ns {}", hex(&build_neighbor_solicitation(mac, src, tgt)))
        }
        "na" => {
            let offset: usize = f[1].parse().expect("offset");
            let frame = unhex(f[2]);
            match parse_neighbor_advertisement(&frame, offset) {
                None => "na nomatch".to_string(),
                Some(na) => {
                    let mac = match na.mac {
                        Some(m) => hex(&m),
                        None => "none".to_string(),
                    };
                    format!("na match target={} mac={}", hex(&na.target), mac)
                }
            }
        }
        other => panic!("unrecognised case kind {other}"),
    }
}

#[test]
fn matches_the_c_oracle() {
    let dir = m5_dir();
    let cases = fs::read_to_string(dir.join("ndp_cases.txt")).expect("ndp_cases.txt");
    let golden = fs::read_to_string(dir.join("ndp_golden.txt")).expect("ndp_golden.txt");

    let cases: Vec<&str> = cases
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .collect();
    let golden: Vec<&str> = golden.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        cases.len(),
        golden.len(),
        "corpus and golden are different lengths"
    );
    assert!(cases.len() >= 60, "corpus unexpectedly small");

    let mut diffs = Vec::new();
    for (case, want) in cases.iter().zip(golden.iter()) {
        let got = rust_verdict(case);
        if got != *want {
            diffs.push(format!("case: {case}\n  C:    {want}\n  rust: {got}"));
        }
    }
    assert!(
        diffs.is_empty(),
        "{} of {} NDP cases diverge from nmap:\n{}",
        diffs.len(),
        cases.len(),
        diffs.join("\n")
    );
}

/// The C's out-of-bounds window, asserted from the Rust side because the C has no
/// defined behavior to compare against there. Every capture length between what
/// `accept_ns` admits and what `read_ns_reply_pcap` reads must be a clean rejection.
#[test]
fn rejects_every_capture_in_the_cs_out_of_bounds_gap() {
    let dir = m5_dir();
    let cases = fs::read_to_string(dir.join("ndp_cases.txt")).expect("ndp_cases.txt");
    // Take a real advertisement out of the corpus and truncate it across the gap.
    let full = cases
        .lines()
        .filter(|l| l.starts_with("na 14 "))
        .map(|l| unhex(l.split_whitespace().nth(2).unwrap()))
        .find(|f| f.len() >= ETH_HDR_LEN + IP6_HDR_LEN + ICMPV6_HDR_LEN + 4 + 16 + 8)
        .expect("a complete advertisement in the corpus");

    let accepts_from = ETH_HDR_LEN + IP6_HDR_LEN + ICMPV6_HDR_LEN;
    let reads_until = accepts_from + 4 + 16;
    for len in accepts_from..reads_until {
        assert_eq!(
            parse_neighbor_advertisement(&full[..len], ETH_HDR_LEN),
            None,
            "a {len}-byte capture is inside the C's out-of-bounds window and must be rejected"
        );
    }
}
