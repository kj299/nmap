//! OS-probe differential: every packet `core::osprobe::build` assembles must decode,
//! under nmap's **real** `IPv4Header`/`TCPHeader`/`UDPHeader`/`ICMPv4Header` classes, to
//! exactly the fields the C's probe battery specifies.
//!
//! The projection here is deliberately richer than the generic M4 build differential.
//! The OS probes are *defined* by the fields that one omits: the TOS byte, the DF flag,
//! the IP ID, the TTL, the exact TCP option bytes, the urgent pointer and the reserved
//! bits are the entire identifying signal. A projection that dropped them would pass
//! while the probes were silently wrong, which is the failure mode that matters — a
//! subtly malformed battery still produces a fingerprint, just the wrong one.
//!
//! The oracle (`oracle/parse_oracle osprobe`) links nmap's own header classes, so a
//! match means nmap itself reads our bytes as the intended probe.
//!
//! Golden regeneration (offline, requires the C oracle built once via `oracle/build.sh`):
//! ```text
//!   REGEN_OSPROBE_VECTORS=1 cargo test -p nmap-core --test osprobe_differential regen -- --ignored
//!   for f in tests/differential/m5/osprobe_vectors/*.hex; do
//!     tests/differential/m4/oracle/parse_oracle osprobe < "$f" \
//!       > "tests/differential/m5/osprobe_golden/$(basename "$f" .hex).proj"
//!   done
//! ```
//! The committed golden is authoritative only after confirming the C oracle decodes each
//! case to its intended structure — which the assertions in `core::osprobe::build`'s unit
//! suite establish independently.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::headers::ipv4::Ipv4Header;
use nmap_core::headers::tcp::TcpHeader;
use nmap_core::headers::udp::UdpHeader;
use nmap_core::osprobe::build::{build_probe, OsProbe, ProbeParams, ICMP_ECHO_SEQ};

/// Fixed parameters so the vectors are reproducible. The C draws these randomly at scan
/// start; pinning them is what makes a byte-for-byte differential possible at all.
fn params() -> ProbeParams {
    ProbeParams {
        src: [10, 0, 0, 1],
        dst: [10, 0, 0, 2],
        ttl: 255,
        udp_ttl: 57,
        ip_id: 0xBEEF,
        tcp_port_base: 40000,
        udp_port_base: 41000,
        tcp_seq_base: 0x1000_0000,
        tcp_ack: 0xAAAA_BBBB,
        icmp_echo_id: 0x1234,
        icmp_echo_seq: ICMP_ECHO_SEQ,
        open_tcp_port: Some(22),
        closed_tcp_port: Some(1),
        closed_udp_port: Some(43210),
    }
}

/// Stable file-safe name for each probe.
fn probe_name(p: OsProbe) -> String {
    match p {
        OsProbe::Seq(i) => format!("seq{i}"),
        OsProbe::Ops(i) => format!("ops{i}"),
        OsProbe::Ecn => "ecn".to_owned(),
        OsProbe::T(n) => format!("t{n}"),
        OsProbe::Ie(i) => format!("ie{i}"),
        OsProbe::U1 => "u1".to_owned(),
    }
}

fn cases() -> Vec<(String, Vec<u8>)> {
    let p = params();
    OsProbe::all()
        .into_iter()
        .map(|probe| {
            let bytes =
                build_probe(probe, &p).unwrap_or_else(|e| panic!("{}: {e}", probe_name(probe)));
            (probe_name(probe), bytes)
        })
        .collect()
}

/// Reproduce the C oracle's `osprobe` projection from the Rust parsers.
fn project(buf: &[u8]) -> String {
    let Ok(ip) = Ipv4Header::parse(buf) else {
        return "result err:invalid\n".to_owned();
    };
    let mut s = format!(
        "ip4 src={}.{}.{}.{} dst={}.{}.{}.{} ihl={} tos={} totlen={} id={} df={} ttl={} proto={}\n",
        ip.src[0],
        ip.src[1],
        ip.src[2],
        ip.src[3],
        ip.dst[0],
        ip.dst[1],
        ip.dst[2],
        ip.dst[3],
        ip.ihl,
        ip.tos,
        ip.total_length,
        ip.id,
        u8::from(ip.df()),
        ip.ttl,
        ip.protocol
    );

    let off = usize::from(ip.ihl).saturating_mul(4);
    let l4 = buf.get(off..).unwrap_or_default();

    match ip.protocol {
        6 => {
            let Ok(tcp) = TcpHeader::parse(l4) else {
                return "result err:tcp\n".to_owned();
            };
            s.push_str(&format!(
                "tcp sport={} dport={} seq={} ack={} off={} reserved={} flags=0x{:02x} \
                 win={} urp={} optlen={}\n",
                tcp.sport,
                tcp.dport,
                tcp.seq,
                tcp.ack,
                tcp.data_offset,
                tcp.reserved,
                tcp.flags,
                tcp.window,
                tcp.urgent_ptr,
                tcp.options.len()
            ));
            s.push_str("tcpopts ");
            for b in &tcp.options {
                s.push_str(&format!("{b:02x}"));
            }
            s.push('\n');
        }
        17 => {
            let Ok(udp) = UdpHeader::parse(l4) else {
                return "result err:udp\n".to_owned();
            };
            s.push_str(&format!(
                "udp sport={} dport={} ulen={}\n",
                udp.sport, udp.dport, udp.length
            ));
            let data = l4.get(8..).unwrap_or_default();
            let first = data.first().copied().unwrap_or(0);
            let uniform = u8::from(data.iter().all(|&b| b == first));
            s.push_str(&format!(
                "udpdata len={} byte={:02x} uniform={}\n",
                data.len(),
                if data.is_empty() { 0 } else { first },
                uniform
            ));
        }
        1 => {
            // The C's ICMPv4Header exposes type/code/id/seq; echo requests keep id and
            // seq in the two 16-bit words after the checksum.
            if l4.len() < 8 {
                return "result err:icmp\n".to_owned();
            }
            let id = u16::from_be_bytes([l4[4], l4[5]]);
            let seq = u16::from_be_bytes([l4[6], l4[7]]);
            s.push_str(&format!(
                "icmp type={} code={} id={} seq={}\n",
                l4[0], l4[1], id, seq
            ));
            let data = l4.get(8..).unwrap_or_default();
            let allzero = u8::from(data.iter().all(|&b| b == 0));
            s.push_str(&format!(
                "icmpdata len={} allzero={}\n",
                data.len(),
                allzero
            ));
        }
        _ => return "result err:proto\n".to_owned(),
    }

    s.push_str("result ok\n");
    s
}

fn m5_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m5")
        .canonicalize()
        .expect("m5 differential dir")
}

#[test]
fn built_probes_match_the_c_oracle_decode() {
    let gold_dir = m5_dir().join("osprobe_golden");
    let all = cases();
    assert_eq!(all.len(), 23, "6 SEQ + 6 OPS + ECN + 7 T + 2 IE + U1");

    for (name, bytes) in all {
        let want = fs::read_to_string(gold_dir.join(format!("{name}.proj")))
            .unwrap_or_else(|_| panic!("missing golden for {name} (run the REGEN step)"));
        let got = project(&bytes);
        assert_eq!(got, want, "probe `{name}`: Rust decode != C-oracle golden");
        assert!(
            want.ends_with("result ok\n"),
            "probe `{name}`: the C oracle rejected our packet"
        );
    }
}

/// Offline: dump each probe's bytes for golden regeneration through the C oracle.
#[test]
#[ignore = "regeneration helper; run with REGEN_OSPROBE_VECTORS=1"]
fn regen() {
    if std::env::var("REGEN_OSPROBE_VECTORS").is_err() {
        return;
    }
    let vec_dir = m5_dir().join("osprobe_vectors");
    fs::create_dir_all(&vec_dir).unwrap();
    for (name, bytes) in cases() {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        fs::write(vec_dir.join(format!("{name}.hex")), format!("{hex}\n")).unwrap();
    }
    eprintln!("wrote osprobe vectors to {}", vec_dir.display());
}
