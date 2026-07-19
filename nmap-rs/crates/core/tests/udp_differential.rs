//! UDP header differential: the Rust `core::headers::udp` parser must produce the
//! same canonical projection as nmap's real `UDPHeader` for every vector in
//! `tests/differential/m4/udp_vectors/`. Golden from the C oracle
//! (`oracle/parse_oracle udp`). Same structure as the ipv4/tcp differentials.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::headers::udp::{ParseError, UdpHeader};

fn project(buf: &[u8]) -> String {
    match UdpHeader::parse(buf) {
        Ok(h) => format!(
            "hdr 0 udp len={}\n  udp sport={} dport={} ulen={}\nresult ok\n",
            h.header_len(),
            h.sport,
            h.dport,
            h.length,
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
fn udp_parser_matches_c_oracle_over_the_corpus() {
    let dir = m4_dir();
    let vec_dir = dir.join("udp_vectors");
    let gold_dir = dir.join("udp_golden");

    let mut entries: Vec<_> = fs::read_dir(&vec_dir)
        .expect("read udp_vectors")
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
            "UDP projection diverges from the C oracle for `{name}`\n\
             --- rust ---\n{got}\n--- c oracle ---\n{want}"
        );
        checked += 1;
    }
    assert!(
        checked >= 5,
        "expected the full udp corpus, checked {checked}"
    );
    eprintln!("udp differential: {checked} vectors match the C oracle");
}
