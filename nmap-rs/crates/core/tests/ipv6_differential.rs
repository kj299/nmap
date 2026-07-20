//! IPv6 header differential: the Rust `core::headers::ipv6` parser must produce the
//! same canonical projection as nmap's real `IPv6Header` for every vector in
//! `tests/differential/m4/ip6_vectors/`. Golden from the C oracle
//! (`oracle/parse_oracle ip6`). Notably includes a `tc_flow_set` vector that
//! exercises the bit-packed version/traffic-class/flow-label decode.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::headers::ipv6::{Ipv6Header, ParseError};

fn hex16(a: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in a {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn project(buf: &[u8]) -> String {
    match Ipv6Header::parse(buf) {
        Ok(h) => format!(
            "hdr 0 ip6 len={}\n  ip6 ver={} tc={} flow={} plen={} nh={} hlim={} src={} dst={}\nresult ok\n",
            h.header_len(),
            h.version(),
            h.traffic_class(),
            h.flow_label(),
            h.payload_length,
            h.next_header,
            h.hop_limit,
            hex16(&h.src),
            hex16(&h.dst),
        ),
        Err(ParseError::Truncated { .. }) => "result err:truncated\n".to_string(),
    }
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
fn ipv6_parser_matches_c_oracle_over_the_corpus() {
    let dir = m4_dir();
    let vec_dir = dir.join("ip6_vectors");
    let gold_dir = dir.join("ip6_golden");

    let mut entries: Vec<_> = fs::read_dir(&vec_dir)
        .expect("read ip6_vectors")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "hex"))
        .collect();
    entries.sort();

    let mut checked = 0;
    for hexpath in entries {
        let name = hexpath.file_stem().unwrap().to_string_lossy().into_owned();
        let bytes = unhex(&fs::read_to_string(&hexpath).unwrap());
        let want = fs::read_to_string(gold_dir.join(format!("{name}.proj")))
            .unwrap_or_else(|_| panic!("missing golden for {name}"));
        let got = project(&bytes);
        assert_eq!(
            got, want,
            "IPv6 projection diverges from the C oracle for `{name}`\n\
             --- rust ---\n{got}\n--- c oracle ---\n{want}"
        );
        checked += 1;
    }
    assert!(
        checked >= 8,
        "expected the full ip6 corpus, checked {checked}"
    );
    eprintln!("ipv6 differential: {checked} vectors match the C oracle");
}
