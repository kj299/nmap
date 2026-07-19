//! TCP header differential: the Rust `core::headers::tcp` parser must produce the
//! same canonical projection as nmap's real `TCPHeader` (C `libnetutil`) for every
//! vector in `tests/differential/m4/tcp_vectors/`.
//!
//! Golden in `tcp_golden/` produced by the C oracle (`oracle/parse_oracle tcp`).
//! Same structure as `ipv4_differential.rs`: the C validated every vector first,
//! this test replays the comparison without the C toolchain. Skipped under Miri.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::headers::tcp::{ParseError, TcpHeader};

fn project(buf: &[u8]) -> String {
    match TcpHeader::parse(buf) {
        Ok(h) => format!(
            "hdr 0 tcp len={}\n  tcp sport={} dport={} flags=0x{:02x} off={} win={} seq={} ack={}\nresult ok\n",
            h.header_len(),
            h.sport, h.dport, h.flags, h.data_offset, h.window, h.seq, h.ack,
        ),
        Err(ParseError::Truncated { .. }) => "result err:truncated\n".to_string(),
        Err(ParseError::OffsetTooSmall(_)) | Err(ParseError::OffsetExceedsBuffer { .. }) => {
            "result err:invalid\n".to_string()
        }
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
fn tcp_parser_matches_c_oracle_over_the_corpus() {
    let dir = m4_dir();
    let vec_dir = dir.join("tcp_vectors");
    let gold_dir = dir.join("tcp_golden");

    let mut entries: Vec<_> = fs::read_dir(&vec_dir)
        .expect("read tcp_vectors")
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
            "TCP projection diverges from the C oracle for `{name}`\n\
             --- rust ---\n{got}\n--- c oracle ---\n{want}"
        );
        checked += 1;
    }
    assert!(checked >= 10, "expected the full tcp corpus, checked {checked}");
    eprintln!("tcp differential: {checked} vectors match the C oracle");
}
