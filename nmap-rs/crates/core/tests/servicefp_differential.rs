//! Service-fingerprint differential: what `core::servicefp` builds must be
//! **byte-identical** to what nmap's own builder produces.
//!
//! The oracle (`tests/differential/s/oracle/servicefp_oracle.cc`) pastes
//! `addServiceChar`, `addServiceString`, `addToServiceFingerprint` and
//! `getServiceFingerprint` verbatim from `service_scan.cc:1663-1795`, with three
//! mechanical changes marked at their sites: the `ServiceNFO::` qualifiers and
//! fields become file scope, the header's globals and `localtime()` become
//! per-case inputs, and `o.debugging` becomes a per-case flag. The format string
//! and the escape ladder are untouched.
//!
//! Making the header an input is what buys a **byte-exact** comparison rather than
//! "equal after stripping the parts that move" — the OS differential has to do the
//! latter because the C reads its clock inside the code under test.
//!
//! `regen_servicefp.sh --check` re-derives both the corpus and the golden from the
//! C on every CI run, so neither can drift into agreeing with this port instead of
//! with nmap.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::servicefp::{FingerprintHeader, Proto, ServiceFingerprint};

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

fn proto_of(s: &str) -> Proto {
    match s {
        "TCP" => Proto::Tcp,
        "UDP" => Proto::Udp,
        "SCTP" => Proto::Sctp,
        other => panic!("unknown proto `{other}`"),
    }
}

/// The oracle escapes newline and backslash when printing, so each case is one
/// golden line. Apply the same mapping before comparing.
fn escape_like_oracle(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out
}

#[test]
fn every_case_matches_nmaps_own_builder_byte_for_byte() {
    let dir = s_dir();
    let cases = fs::read_to_string(dir.join("servicefp_cases.txt")).expect("committed corpus");
    let golden = fs::read_to_string(dir.join("servicefp_golden.txt")).expect("committed golden");
    let mut golden = golden.lines();

    let mut fp: Option<ServiceFingerprint> = None;
    let mut id = String::new();
    let mut compared = 0usize;

    for line in cases.lines() {
        if let Some(rest) = line.strip_prefix("CASE ") {
            let f: Vec<&str> = rest.split_whitespace().collect();
            assert_eq!(f.len(), 11, "malformed CASE line: {line}");
            id = f[0].to_owned();
            let header = FingerprintHeader {
                port: f[1].parse().expect("port"),
                proto: proto_of(f[2]),
                version: f[3].to_owned(),
                platform: f[4].to_owned(),
                intensity: f[5].parse().expect("intensity"),
                ssl_tunnel: f[6] != "0",
                month: f[7].parse().expect("mon"),
                day: f[8].parse().expect("mday"),
                time: f[9].parse().expect("time"),
            };
            fp = Some(ServiceFingerprint::new(header, f[10] != "0"));
        } else if let Some(rest) = line.strip_prefix("RESP ") {
            let (probe, hex) = rest.split_once(' ').expect("RESP <probe> <hex>");
            let bytes = unhex(hex);
            fp.as_mut()
                .expect("RESP before CASE")
                .add_response(probe, &bytes);
        } else if line == "FINISH" {
            let built = fp.take().expect("FINISH before CASE");
            let got = match built.finish() {
                None => "NONE".to_owned(),
                Some(s) => escape_like_oracle(&s),
            };
            let expected_line = golden.next().expect("golden has a line for every case");
            let (gid, expected) = expected_line
                .split_once(' ')
                .expect("golden line is `<id> <fingerprint>`");
            assert_eq!(gid, id, "golden is out of order with the corpus");
            assert_eq!(
                got, expected,
                "case `{id}` diverges from nmap's builder\n  C:    {expected}\n  Rust: {got}"
            );
            compared = compared.saturating_add(1);
        }
    }

    assert!(golden.next().is_none(), "golden has unconsumed cases");
    assert!(compared >= 400, "only {compared} cases compared");
    eprintln!("servicefp differential: {compared} cases byte-exact vs the C");
}
