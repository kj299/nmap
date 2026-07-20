//! Receive-validation differential: `core::recv_validate::validate_packet` must reach
//! the same accept/reject decision (and, on accept, the same capped length / protocol
//! / data offset) as nmap's `validatepkt()` + `validateTCPhdr()` for every vector in
//! `tests/differential/m4/validate_vectors/`. Golden from `validate_oracle` (the C-side
//! transcription). The corpus stresses the untrusted TCP-option walk with well-formed
//! and malformed option lists.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::recv_validate::validate_packet;

fn project(buf: &[u8]) -> String {
    match validate_packet(buf) {
        Ok(v) => format!(
            "accept caplen={} proto={} doff={}\n",
            v.captured_len, v.proto, v.data_offset
        ),
        Err(_) => "reject\n".to_string(),
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
fn validate_matches_c_oracle_over_the_corpus() {
    let dir = m4_dir();
    let vec_dir = dir.join("validate_vectors");
    let gold_dir = dir.join("validate_golden");

    let mut entries: Vec<_> = fs::read_dir(&vec_dir)
        .expect("read validate_vectors")
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
            "recv_validate diverges from the C oracle for `{name}`\n\
             --- rust ---\n{got}\n--- c oracle ---\n{want}"
        );
        checked += 1;
    }
    assert!(
        checked >= 18,
        "expected the full validate corpus, checked {checked}"
    );
    eprintln!("recv_validate differential: {checked} vectors match the C oracle");
}
