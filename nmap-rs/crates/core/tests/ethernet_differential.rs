//! Ethernet header differential: the Rust `core::headers::ethernet` parser must
//! produce the same canonical projection as nmap's real `EthernetHeader` for every
//! vector in `tests/differential/m4/eth_vectors/`. Golden from the C oracle
//! (`oracle/parse_oracle eth`). Same structure as the other header differentials.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::headers::ethernet::{EthernetHeader, ParseError};

fn mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

fn project(buf: &[u8]) -> String {
    match EthernetHeader::parse(buf) {
        Ok(h) => format!(
            "hdr 0 eth len={}\n  eth dst={} src={} type=0x{:04x}\nresult ok\n",
            h.header_len(),
            mac(&h.dst),
            mac(&h.src),
            h.ethertype,
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
fn ethernet_parser_matches_c_oracle_over_the_corpus() {
    let dir = m4_dir();
    let vec_dir = dir.join("eth_vectors");
    let gold_dir = dir.join("eth_golden");

    let mut entries: Vec<_> = fs::read_dir(&vec_dir)
        .expect("read eth_vectors")
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
            "Ethernet projection diverges from the C oracle for `{name}`\n\
             --- rust ---\n{got}\n--- c oracle ---\n{want}"
        );
        checked += 1;
    }
    assert!(
        checked >= 8,
        "expected the full eth corpus, checked {checked}"
    );
    eprintln!("ethernet differential: {checked} vectors match the C oracle");
}
