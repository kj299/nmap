//! Receive-validation differential: `core::recv_validate::validate_packet` must reach
//! the same accept/reject decision (and, on accept, the same capped length / protocol
//! / data offset) as nmap's `validatepkt()` + `validateTCPhdr()` for every vector in
//! `tests/differential/m4/validate_vectors/` and every packet in
//! `validate_random_vectors.txt`. Golden from `validate_oracle` (the C-side
//! transcription, with netutil.cc's own IPv6 walk compiled in). The corpus stresses
//! the untrusted TCP-option walk and the IPv6 extension-header walk with well-formed
//! and malformed input.
//!
//! Two IPv6 behaviours are fixed rather than reproduced (docs/IPV6-SCAN-ANALYSIS.md
//! D3, Q4). Where they apply the golden is still the C's; the hand vectors pin the
//! port's answer beside it, and the random corpus checks each class against its rule.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::recv_validate::{validate_packet, Reject};

/// Hand vectors where the port fixes the C instead of following it: the vector,
/// the C's projection (its committed golden, held here so a change to it is seen),
/// the port's, and the ledger entry that records why.
const PINNED: &[(&str, &str, &str, &str)] = &[
    // A later fragment: the C reads its mid-segment payload as a transport header.
    (
        "v6_frag_later_tcp",
        "accept caplen=83 proto=6 doff=48",
        "reject",
        "recv-validate6-non-initial-fragment",
    ),
    (
        "v6_frag_later_udp",
        "accept caplen=64 proto=17 doff=48",
        "reject",
        "recv-validate6-non-initial-fragment",
    ),
    // A first fragment with reserved byte 2: the C skips 24 bytes, not 8.
    (
        "v6_frag_reserved_tcp",
        "accept caplen=88 proto=6 doff=64",
        "accept caplen=88 proto=6 doff=48",
        "recv-validate6-non-initial-fragment",
    ),
    // Extension headers and a trailer: the C trims nothing, or too little.
    (
        "v6_hop_tcp_trailer_untrimmed",
        "accept caplen=82 proto=6 doff=56",
        "accept caplen=76 proto=6 doff=56",
        "recv-validate6-trailer-trim",
    ),
    (
        "v6_hop_tcp_trailer_short",
        "accept caplen=76 proto=6 doff=48",
        "accept caplen=68 proto=6 doff=48",
        "recv-validate6-trailer-trim",
    ),
];

fn project(buf: &[u8]) -> String {
    match validate_packet(buf) {
        Ok(v) => format!(
            "accept caplen={} proto={} doff={}\n",
            v.captured_len, v.proto, v.data_offset
        ),
        Err(_) => "reject\n".to_string(),
    }
}

/// The projection's fields, for an accept.
fn accepted(proj: &str) -> Option<(usize, u8, usize)> {
    let rest = proj.trim().strip_prefix("accept ")?;
    let mut fields = rest
        .split(' ')
        .map(|f| f.split_once('=').expect("key=value").1);
    let mut next = || fields.next().expect("three fields");
    Some((
        next().parse().unwrap(),
        next().parse().unwrap(),
        next().parse().unwrap(),
    ))
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
        if PINNED.iter().any(|p| p.0 == name) {
            continue; // the_fixed_ipv6_cases_are_pinned
        }
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
        checked >= 50,
        "expected the full validate corpus, checked {checked}"
    );
    eprintln!("recv_validate differential: {checked} vectors match the C oracle");
}

#[test]
fn the_fixed_ipv6_cases_are_pinned() {
    let dir = m4_dir();
    let ledger = fs::read_to_string(dir.join("../../../DIVERGENCES.md")).expect("ledger");
    for &(name, c, port, id) in PINNED {
        let bytes =
            unhex(&fs::read_to_string(dir.join(format!("validate_vectors/{name}.hex"))).unwrap());
        let golden = fs::read_to_string(dir.join(format!("validate_golden/{name}.proj"))).unwrap();
        assert_eq!(golden.trim(), c, "the C's answer for `{name}` changed");
        assert_eq!(
            project(&bytes).trim(),
            port,
            "the port's answer for `{name}`"
        );
        assert_ne!(c, port, "`{name}` is pinned but does not diverge");
        assert!(
            ledger.contains(&format!("`{id}`")),
            "{id} is not in DIVERGENCES.md"
        );
        if id == "recv-validate6-non-initial-fragment" && port == "reject" {
            assert_eq!(validate_packet(&bytes), Err(Reject::Fragment), "{name}");
        }
    }
}

/// The random IPv6 corpus (`gen_validate_random.py`). Each packet is in one of
/// three classes, and the port must meet that class's rule:
///
/// - **frag** (tagged by the generator's mirror of the C walk): the C walks past
///   a fragment header with a nonzero offset. The port refuses it as a fragment.
/// - **trim**: the C accepts, extension headers precede the payload, and more was
///   captured than 40 + `ip6_plen`. The port agrees on protocol and data offset,
///   and ends the packet at 40 + `ip6_plen`; the C's length is checked against its
///   own rule, so the class is what the ledger says it is.
/// - **same**: everything else. The port matches the C exactly.
#[test]
fn validate_matches_c_oracle_over_the_random_ipv6_corpus() {
    let dir = m4_dir();
    let vectors = fs::read_to_string(dir.join("validate_random_vectors.txt")).expect("vectors");
    let golden = fs::read_to_string(dir.join("validate_random_golden.txt")).expect("golden");
    assert_eq!(
        vectors.lines().count(),
        golden.lines().count(),
        "corpus and golden differ in length"
    );

    let (mut same, mut trim, mut frag, mut frag_read_by_c) = (0, 0, 0, 0);
    for (i, (line, want)) in vectors.lines().zip(golden.lines()).enumerate() {
        let (tag, hex) = line.split_once(' ').expect("`<tag> <hex>`");
        let pkt = unhex(hex);
        match tag {
            "frag" => {
                assert_eq!(
                    validate_packet(&pkt),
                    Err(Reject::Fragment),
                    "line {}: {hex}",
                    i + 1
                );
                frag += 1;
                if want.starts_with("accept") {
                    frag_read_by_c += 1;
                }
            }
            "-" => {
                let expected = match accepted(want) {
                    Some((c_len, proto, doff)) if doff > 40 => {
                        let plen = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
                        if 40 + plen < pkt.len() {
                            // validatepkt: `if (datalen > iplen) *len -= datalen - iplen`.
                            let datalen = pkt.len() - doff;
                            let c_rule = if datalen > plen {
                                doff + plen
                            } else {
                                pkt.len()
                            };
                            assert_eq!(c_len, c_rule, "line {}: not the C's trim", i + 1);
                            trim += 1;
                            format!("accept caplen={} proto={proto} doff={doff}\n", 40 + plen)
                        } else {
                            same += 1;
                            format!("{want}\n")
                        }
                    }
                    _ => {
                        same += 1;
                        format!("{want}\n")
                    }
                };
                assert_eq!(project(&pkt), expected, "line {}: {hex}", i + 1);
            }
            other => panic!("line {}: unknown tag {other:?}", i + 1),
        }
    }
    // Each class is populated, and the C really does read later fragments.
    assert!(
        same >= 2500 && trim >= 200 && frag >= 300,
        "same {same}, trim {trim}, frag {frag}"
    );
    assert!(
        frag_read_by_c >= 100,
        "the C accepted only {frag_read_by_c} later fragments"
    );
    eprintln!(
        "recv_validate random IPv6: {same} match the C; {trim} trimmed to ip6_plen; \
         {frag} later fragments refused ({frag_read_by_c} of them accepted by the C)"
    );
}
