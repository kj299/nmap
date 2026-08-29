//! IPv6 probe-battery differential: every packet `core::build6::build_probes` emits must
//! be **byte-identical** to what nmap's own `FPHost6::build_probe_list()` produces for
//! the same inputs.
//!
//! The oracle (`tests/differential/m5/oracle/build6_oracle`) pastes nmap's
//! `build_probe_list` verbatim and links the real libnetutil header classes — including
//! real `ipv6_pseudoheader_cksum` (a builder must compute real checksums; the parse
//! oracles' zero-returning stub would make the golden assert a paraphrase of the C). The
//! committed corpus + golden are regenerated from that oracle on every CI run by
//! `regen_build6.sh --check`, so they cannot drift.
//!
//! Byte identity is the strongest gate available here: it catches a wrong option byte, a
//! wrong window, a mis-ordered extension header, a checksum computed over the wrong span,
//! or a probe emitted (or skipped) in the wrong circumstance — every way the battery can
//! be silently wrong while still "looking like" OS-detection traffic.
#![cfg(not(miri))]

use std::fs;
use std::net::Ipv6Addr;
use std::path::PathBuf;

use nmap_core::build6::{build_probes, Build6Params};
use nmap_core::fp6::Fp6Probe;

fn m5_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m5")
        .canonicalize()
        .expect("m5 differential dir")
}

/// Parse one corpus line into `Build6Params`. The field order matches the oracle's
/// `main()`: src dst open_tcp closed_tcp closed_udp tcp_base udp_base seqbase hoplimit
/// icmp_seq directly_connected ack0..ack12.
fn parse_case(line: &str) -> Build6Params {
    let f: Vec<&str> = line.split_whitespace().collect();
    let addr = |s: &str| s.parse::<Ipv6Addr>().unwrap().octets();
    let port = |s: &str| {
        let v: i64 = s.parse().unwrap();
        if v < 0 {
            None
        } else {
            Some(u16::try_from(v).unwrap())
        }
    };
    let mut acks = [0u32; 13];
    for (a, field) in acks.iter_mut().zip(&f[11..]) {
        *a = field.parse().unwrap();
    }
    Build6Params {
        src: addr(f[0]),
        dst: addr(f[1]),
        open_tcp_port: port(f[2]),
        closed_tcp_port: port(f[3]),
        closed_udp_port: u16::try_from(f[4].parse::<i64>().unwrap()).unwrap(),
        tcp_port_base: f[5].parse().unwrap(),
        udp_port_base: f[6].parse().unwrap(),
        tcp_seq_base: f[7].parse().unwrap(),
        hop_limit: u8::try_from(f[8].parse::<u32>().unwrap()).unwrap(),
        icmp_seq: u16::try_from(f[9].parse::<u32>().unwrap()).unwrap(),
        directly_connected: f[10] != "0",
        tcp_acks: acks,
    }
}

fn probe_token(p: Fp6Probe) -> String {
    p.id().to_string()
}

#[test]
fn build6_matches_c_oracle_over_the_corpus() {
    let dir = m5_dir();
    let cases = fs::read_to_string(dir.join("build6_cases.txt")).expect("build6_cases.txt");
    let golden = fs::read_to_string(dir.join("build6_golden.txt")).expect("build6_golden.txt");

    // Render the Rust side into the same "case N / probe ID hex" shape as the golden.
    let mut got = String::new();
    let mut caseno = 0usize;
    for line in cases.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        caseno += 1;
        got.push_str(&format!("case {caseno}\n"));
        for probe in build_probes(&parse_case(line)) {
            got.push_str(&format!("probe {} ", probe_token(probe.id)));
            for b in &probe.packet {
                got.push_str(&format!("{b:02x}"));
            }
            got.push('\n');
        }
    }

    assert!(
        caseno >= 400,
        "expected the full build6 corpus, got {caseno}"
    );
    if got != golden {
        let (g, w): (Vec<&str>, Vec<&str>) = (golden.lines().collect(), got.lines().collect());
        let at = g
            .iter()
            .zip(w.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(g.len().min(w.len()));
        let lo = at.saturating_sub(4);
        panic!(
            "build6 diverges from the C oracle at golden line {at}\n--- rust ---\n{}\n--- c oracle ---\n{}",
            w.get(lo..at.saturating_add(4)).unwrap_or_default().join("\n"),
            g.get(lo..at.saturating_add(4)).unwrap_or_default().join("\n"),
        );
    }
    eprintln!("build6 differential: {caseno} cases, byte-exact against the C oracle");
}
