//! IPv6 scan-probe differential (IPv6 scans step c): every packet the port builds for
//! an IPv6 scan must be **byte-identical** to the one nmap's own `build_tcp_raw_ipv6`
//! / `build_udp_raw_ipv6` builds from the same inputs. The golden comes from
//! `scanprobe6_oracle`, which compiles those functions out of `tcpip.cc` (with
//! `netutil.cc`'s checksum and `scan_engine_raw.cc`'s encoders) and transcribes how
//! `sendIPScanProbe` chooses their arguments.
//!
//! - `probe` lines go through the port's scan-probe builders
//!   (`build_syn_probe_with`, `build_flag_probe_with`, `build_udp_probe_with`), so
//!   the scan engine's choices are checked too: the attempt in the sequence or, for
//!   a probe with the ACK flag, in the acknowledgment; the MSS option on a SYN;
//!   window 1024; hop limit 255 when `--ttl` is not given (`o.ttl` = -1 arriving as
//!   a `u8`, `build6-scan-hop-limit-255`).
//! - `tcp` / `udp` lines go through the builders themselves.
#![cfg(not(miri))]

use std::fs;
use std::path::PathBuf;

use nmap_core::build::{
    build_tcp_raw_ipv6, build_udp_raw_ipv6, Ipv6Spec, PacketOverrides, SCAN_HOP_LIMIT,
};
use nmap_core::classify::ScanType;
use nmap_core::flagscan::{build_flag_probe_with, flags_for};
use nmap_core::synscan::build_syn_probe_with;
use nmap_core::udpscan::build_udp_probe_with;

fn m4_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m4")
        .canonicalize()
        .expect("m4 differential dir")
}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn addr(s: &str) -> [u8; 16] {
    unhex(s).try_into().expect("16-byte address")
}

fn num<T: std::str::FromStr>(s: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    s.parse().expect("number")
}

fn scan(s: &str) -> Option<ScanType> {
    Some(match s {
        "syn" => ScanType::Syn,
        "ack" => ScanType::Ack,
        "window" => ScanType::Window,
        "maimon" => ScanType::Maimon,
        "fin" => ScanType::Fin,
        "null" => ScanType::Null,
        "xmas" => ScanType::Xmas,
        "udp" => return None,
        other => panic!("unknown scan {other}"),
    })
}

/// The packet the port builds for one case line.
fn build(f: &[&str]) -> Vec<u8> {
    match f[0] {
        "tcp" => {
            let spec = Ipv6Spec {
                src: addr(f[1]),
                dst: addr(f[2]),
                traffic_class: num(f[3]),
                flow_label: num(f[4]),
                hop_limit: num(f[5]),
                bad_sum: f[16] == "1",
            };
            build_tcp_raw_ipv6(
                &spec,
                num(f[6]),
                num(f[7]),
                num(f[8]),
                num(f[9]),
                num::<u16>(f[10]).to_be_bytes()[1],
                num(f[11]),
                num(f[12]),
                num(f[13]),
                &unhex(f[14]),
                &unhex(f[15]),
            )
            .unwrap()
        }
        "udp" => {
            let spec = Ipv6Spec {
                src: addr(f[1]),
                dst: addr(f[2]),
                traffic_class: num(f[3]),
                flow_label: num(f[4]),
                hop_limit: num(f[5]),
                bad_sum: f[9] == "1",
            };
            build_udp_raw_ipv6(&spec, num(f[6]), num(f[7]), &unhex(f[8])).unwrap()
        }
        "probe" => {
            // What a scan does: the scan engine's spec, then the operator's options.
            let ttl: i32 = num(f[4]);
            let overrides = PacketOverrides {
                ttl: (ttl >= 0).then(|| u8::try_from(ttl).unwrap()),
                bad_sum: f[10] == "1",
                spoof_src: None,
            };
            let spec = Ipv6Spec::new(addr(f[2]), addr(f[3])).with_overrides(overrides);
            if ttl < 0 {
                assert_eq!(spec.hop_limit, SCAN_HOP_LIMIT);
            }
            let (base, dport, tryno, mask) = (num(f[5]), num(f[6]), num(f[7]), num(f[8]));
            let data = unhex(f[9]);
            match scan(f[1]) {
                Some(ScanType::Syn) => {
                    build_syn_probe_with(&spec, base, dport, tryno, mask, &data).unwrap()
                }
                Some(s) => {
                    let flags = flags_for(s).unwrap();
                    build_flag_probe_with(&spec, base, dport, tryno, mask, flags, &data).unwrap()
                }
                None => build_udp_probe_with(&spec, base, dport, tryno, &data).unwrap(),
            }
        }
        other => panic!("unknown case kind {other}"),
    }
}

#[test]
fn ipv6_scan_probes_are_byte_identical_to_nmaps() {
    let dir = m4_dir();
    let cases = fs::read_to_string(dir.join("scanprobe6_cases.txt")).expect("cases");
    let golden = fs::read_to_string(dir.join("scanprobe6_golden.txt")).expect("golden");
    assert_eq!(cases.lines().count(), golden.lines().count());

    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for (i, (case, want)) in cases.lines().zip(golden.lines()).enumerate() {
        let f: Vec<&str> = case.split_whitespace().collect();
        let got = hex(&build(&f));
        assert_eq!(got, want, "line {}: `{case}`", i + 1);
        let key = if f[0] == "probe" {
            format!("probe {}", f[1])
        } else {
            f[0].to_string()
        };
        *counts.entry(key).or_default() += 1;
    }
    // Every scan type, and the builders on their own, are exercised.
    for k in [
        "probe syn",
        "probe ack",
        "probe window",
        "probe maimon",
        "probe fin",
        "probe null",
        "probe xmas",
        "probe udp",
    ] {
        assert!(counts.get(k).copied().unwrap_or(0) >= 80, "{k}: {counts:?}");
    }
    assert!(counts["tcp"] >= 600 && counts["udp"] >= 300, "{counts:?}");
    eprintln!("IPv6 scan probes: {counts:?}, all byte-identical to nmap's");
}
