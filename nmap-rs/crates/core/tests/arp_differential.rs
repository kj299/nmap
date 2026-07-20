//! ARP header differential: the Rust `core::headers::arp` parser must produce the
//! same canonical projection as nmap's real `ARPHeader` for every vector in
//! `tests/differential/m4/arp_vectors/`. Golden from the C oracle
//! (`oracle/parse_oracle arp`). Same structure as the other header differentials.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::headers::arp::{ArpHeader, ParseError};

fn mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

fn ip(a: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

fn project(buf: &[u8]) -> String {
    match ArpHeader::parse(buf) {
        Ok(h) => format!(
            "hdr 0 arp len={}\n  arp hrd={} pro=0x{:04x} hln={} pln={} op={} sha={} sip={} tha={} tip={}\nresult ok\n",
            h.header_len(),
            h.hardware_type,
            h.protocol_type,
            h.hw_addr_len,
            h.proto_addr_len,
            h.opcode,
            mac(&h.sender_mac()),
            ip(&h.sender_ip()),
            mac(&h.target_mac()),
            ip(&h.target_ip()),
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
fn arp_parser_matches_c_oracle_over_the_corpus() {
    let dir = m4_dir();
    let vec_dir = dir.join("arp_vectors");
    let gold_dir = dir.join("arp_golden");

    let mut entries: Vec<_> = fs::read_dir(&vec_dir)
        .expect("read arp_vectors")
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
            "ARP projection diverges from the C oracle for `{name}`\n\
             --- rust ---\n{got}\n--- c oracle ---\n{want}"
        );
        checked += 1;
    }
    assert!(
        checked >= 6,
        "expected the full arp corpus, checked {checked}"
    );
    eprintln!("arp differential: {checked} vectors match the C oracle");
}
