//! Multi-header packet differential: the Rust `core::packet_parser::parse_packet`
//! must produce the same canonical layer projection as nmap's real
//! `PacketParser::parse_packet` for every vector in
//! `tests/differential/m4/pkt_vectors/`. Golden from the C oracle
//! (`oracle/parse_oracle pkt_eth|pkt_ip`).
//!
//! Filename convention (shared with the oracle golden-generation): a stem starting
//! with `eth` is parsed with an Ethernet frame (`eth_included = true`); anything else
//! starts at the network layer. The corpus is restricted to chains within the
//! M4-ported header set so the C and Rust walks agree exactly; the ICMPv6 /
//! IPv6-extension-header degrade-to-raw divergence is covered by unit tests.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::packet_parser::{parse_packet, Header};

fn project(buf: &[u8], eth_included: bool) -> String {
    let hs = parse_packet(buf, eth_included);
    let mut s = format!("pkt nhdrs={}\n", hs.len());
    let mut off = 0usize;
    for (i, h) in hs.iter().enumerate() {
        s.push_str(&format!(
            "hdr {i} {} off={off} len={}\n",
            h.kind_str(),
            h.len()
        ));
        off = off.saturating_add(h.len());
    }
    s.push_str("result ok\n");
    s
}

fn m4_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m4")
        .canonicalize()
        .expect("m4 differential dir")
}

fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u32> = s
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_digit(16).unwrap())
        .collect();
    digits
        .chunks_exact(2)
        .map(|pair| u8::try_from((pair[0] << 4) | pair[1]).unwrap())
        .collect()
}

#[test]
fn packet_parser_matches_c_oracle_over_the_corpus() {
    let dir = m4_dir();
    let vec_dir = dir.join("pkt_vectors");
    let gold_dir = dir.join("pkt_golden");

    let mut entries: Vec<_> = fs::read_dir(&vec_dir)
        .expect("read pkt_vectors")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "hex"))
        .collect();
    entries.sort();

    let mut checked = 0;
    for hexpath in entries {
        let name = hexpath.file_stem().unwrap().to_string_lossy().into_owned();
        let eth_included = name.starts_with("eth");
        let bytes = unhex(&fs::read_to_string(&hexpath).unwrap());
        let want = fs::read_to_string(gold_dir.join(format!("{name}.proj")))
            .unwrap_or_else(|_| panic!("missing golden for {name}"));
        let got = project(&bytes, eth_included);
        assert_eq!(
            got, want,
            "packet projection diverges from the C oracle for `{name}` (eth_included={eth_included})\n\
             --- rust ---\n{got}\n--- c oracle ---\n{want}"
        );
        checked += 1;
    }
    assert!(
        checked >= 17,
        "expected the full pkt corpus, checked {checked}"
    );
    eprintln!("packet_parser differential: {checked} vectors match the C oracle");
}

/// The projected total consumed length must always equal the packet length (the walk
/// accounts for every byte via a trailing `Raw` when needed) — except when the header
/// bound truncates coverage, which the corpus does not hit.
#[test]
fn projection_covers_every_byte() {
    let dir = m4_dir();
    let vec_dir = dir.join("pkt_vectors");
    for entry in fs::read_dir(&vec_dir).expect("read pkt_vectors") {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|x| x != "hex") {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let eth_included = name.starts_with("eth");
        let bytes = unhex(&fs::read_to_string(&path).unwrap());
        let hs = parse_packet(&bytes, eth_included);
        let total: usize = hs.iter().map(Header::len).sum();
        assert_eq!(total, bytes.len(), "byte accounting off for {name}");
    }
}
