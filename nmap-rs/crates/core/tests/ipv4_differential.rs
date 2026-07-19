//! IPv4 header differential: the Rust `core::headers::ipv4` parser must produce the
//! same canonical projection as nmap's real `IPv4Header` (C `libnetutil`) for every
//! vector in `tests/differential/m4/ipv4_vectors/`.
//!
//! The golden projections in `ipv4_golden/` were produced by running the C oracle
//! (`tests/differential/m4/oracle/parse_oracle`, built via `build.sh`) over the same
//! vectors — so "validate every vector against the C first" (kit Phase 2) is
//! satisfied: this test replays that comparison without needing the C toolchain at
//! test time. Regenerate the golden with `oracle/build.sh && run over ipv4_vectors`
//! when the projection format or the C reference changes.
//!
//! Skipped under Miri (reads files from disk).
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::headers::ipv4::{Ipv4Header, ParseError};

/// The shared canonical projection (see tests/differential/m4/README.md). The C
/// oracle emits exactly this; the Rust parser must match it byte-for-byte.
fn project(buf: &[u8]) -> String {
    match Ipv4Header::parse(buf) {
        Ok(h) => format!(
            "hdr 0 ip4 len={}\n  ip4 src={}.{}.{}.{} dst={}.{}.{}.{} proto={} ihl={} totlen={}\nresult ok\n",
            h.header_len(),
            h.src[0], h.src[1], h.src[2], h.src[3],
            h.dst[0], h.dst[1], h.dst[2], h.dst[3],
            h.protocol, h.ihl, h.total_length,
        ),
        // The C collapses all validate() rejections to one OP_FAILURE; storeRecvData
        // fails only on < 20 bytes. Map the finer Rust errors onto that binary shape.
        Err(ParseError::Truncated { .. }) => "result err:truncated\n".to_string(),
        Err(ParseError::BadVersion(_))
        | Err(ParseError::HeaderLenTooSmall(_))
        | Err(ParseError::HeaderLenExceedsBuffer { .. }) => "result err:invalid\n".to_string(),
    }
}

fn m4_dir() -> PathBuf {
    // crates/core -> ../../tests/differential/m4
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
fn ipv4_parser_matches_c_oracle_over_the_corpus() {
    let dir = m4_dir();
    let vec_dir = dir.join("ipv4_vectors");
    let gold_dir = dir.join("ipv4_golden");

    let mut checked = 0;
    let mut entries: Vec<_> = fs::read_dir(&vec_dir)
        .expect("read ipv4_vectors")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "hex"))
        .collect();
    entries.sort();

    for hexpath in entries {
        let name = hexpath.file_stem().unwrap().to_string_lossy().into_owned();
        let bytes = unhex(&fs::read_to_string(&hexpath).unwrap());
        let want = fs::read_to_string(gold_dir.join(format!("{name}.proj")))
            .unwrap_or_else(|_| panic!("missing golden for {name}"));
        let got = project(&bytes);
        assert_eq!(
            got, want,
            "IPv4 projection diverges from the C oracle for vector `{name}`\n\
             --- rust ---\n{got}\n--- c oracle ---\n{want}"
        );
        checked += 1;
    }
    assert!(
        checked >= 15,
        "expected the full ipv4 corpus, checked {checked}"
    );
    eprintln!("ipv4 differential: {checked} vectors match the C oracle");
}
