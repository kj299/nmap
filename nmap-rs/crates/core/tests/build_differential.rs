//! Build differential: every packet `core::build` assembles must decode, under
//! nmap's **real** `PacketParser` (the committed C-oracle golden) and under the Rust
//! parser, to the same layer projection. This ties the send path to the C via the
//! already-trusted parse oracle (a builder is verified by an independent decoder),
//! rather than a bespoke reverse oracle that would have to re-implement nmap's
//! checksum quirks. Field *values* are covered transitively — `build` fills the same
//! `Ipv4Header`/`TcpHeader`/`UdpHeader` structs whose `serialize()` each passed its
//! own per-header C differential — and checksum *values* are covered by the
//! receiver-side "sums to zero" unit tests in `core::build`.
//!
//! Golden regeneration (offline, requires the C oracle built once):
//!   REGEN_BUILD_VECTORS=1 cargo test -p nmap-core --test build_differential regen -- --ignored
//!   for f in tests/differential/m4/build_vectors/*.hex; do
//!     oracle/parse_oracle pkt_ip < "$f" > "build_golden/$(basename "$f" .hex).proj"
//!   done
//! The committed golden is authoritative only after confirming the C oracle decodes
//! each case to its intended structure (asserted below via EXPECTED).
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::build::{build_icmp_raw, build_tcp_raw, build_udp_raw, Ipv4Spec};
use nmap_core::packet_parser::{parse_packet, Header};

fn spec() -> Ipv4Spec {
    Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 0x1234)
}

/// (name, built bytes, intended layer stack). One entry per differential case.
fn cases() -> Vec<(&'static str, Vec<u8>, Vec<&'static str>)> {
    let mut opt_spec = spec();
    opt_spec.options = vec![0x01, 0x01, 0x01, 0x00]; // 4 bytes of IP options
    vec![
        (
            "tcp_syn",
            build_tcp_raw(
                &spec(),
                40000,
                80,
                0x1111_2222,
                0,
                0,
                0x02,
                1024,
                0,
                &[],
                &[],
            )
            .unwrap(),
            vec!["ip4", "tcp"],
        ),
        (
            "tcp_syn_mss_payload",
            build_tcp_raw(
                &spec(),
                1234,
                443,
                1,
                2,
                0,
                0x18,
                8192,
                0,
                &[0x02, 0x04, 0x05, 0xb4],
                &[0xaa, 0xbb, 0xcc],
            )
            .unwrap(),
            vec!["ip4", "tcp", "raw"],
        ),
        (
            "udp_empty",
            build_udp_raw(&spec(), 53, 5353, &[]).unwrap(),
            vec!["ip4", "udp"],
        ),
        (
            "udp_data",
            build_udp_raw(&spec(), 53, 5353, &[1, 2, 3, 4]).unwrap(),
            vec!["ip4", "udp", "raw"],
        ),
        (
            "icmp_echo",
            build_icmp_raw(&spec(), 8, 0, 0x1111, 0x2222, &[]).unwrap(),
            vec!["ip4", "icmp"],
        ),
        (
            "icmp_timestamp",
            build_icmp_raw(&spec(), 13, 0, 1, 2, &[]).unwrap(),
            vec!["ip4", "icmp"],
        ),
        (
            "icmp_mask",
            build_icmp_raw(&spec(), 17, 0, 1, 2, &[]).unwrap(),
            vec!["ip4", "icmp"],
        ),
        (
            "ip_options_udp",
            build_udp_raw(&opt_spec, 1, 2, &[9, 9]).unwrap(),
            vec!["ip4", "udp", "raw"],
        ),
    ]
}

fn project(buf: &[u8]) -> String {
    let hs = parse_packet(buf, false);
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

#[test]
fn built_packets_match_c_oracle_decode() {
    let gold_dir = m4_dir().join("build_golden");
    for (name, bytes, expected) in cases() {
        // Independent decoder #1: nmap's real PacketParser, via the committed golden.
        let want = fs::read_to_string(gold_dir.join(format!("{name}.proj")))
            .unwrap_or_else(|_| panic!("missing golden for {name} (run the REGEN step)"));
        let got = project(&bytes);
        assert_eq!(got, want, "build `{name}`: Rust decode != C-oracle golden");

        // The golden must encode the intended structure (authoritative check).
        let kinds: Vec<&str> = parse_packet(&bytes, false)
            .iter()
            .map(Header::kind_str)
            .collect();
        assert_eq!(kinds, expected, "build `{name}`: unexpected layer stack");
    }
}

/// Offline: dump each case's bytes to `build_vectors/<name>.hex` for golden
/// regeneration through the C oracle. Ignored by default.
#[test]
#[ignore = "regeneration helper; run with REGEN_BUILD_VECTORS=1"]
fn regen() {
    if std::env::var("REGEN_BUILD_VECTORS").is_err() {
        return;
    }
    let vec_dir = m4_dir().join("build_vectors");
    fs::create_dir_all(&vec_dir).unwrap();
    for (name, bytes, _) in cases() {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(vec_dir.join(format!("{name}.hex")), format!("{hex}\n")).unwrap();
    }
    eprintln!("wrote build vectors to {}", vec_dir.display());
}
