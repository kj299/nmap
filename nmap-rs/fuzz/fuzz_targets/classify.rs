// cargo-fuzz target for `nmap_core::classify`. These are pure, total decision
// functions over already-typed values (the packet parsing that produces them is
// fuzzed separately in parse_*/validate_packet), so the exhaustive differential is
// the real coverage; this target just guarantees totality under arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::classify::{
    classify_icmp, classify_sctp, classify_tcp, classify_udp_response, default_port_state, ScanType,
};

fuzz_target!(|data: &[u8]| {
    let scans = [
        ScanType::Syn, ScanType::Connect, ScanType::Ack, ScanType::Window, ScanType::Maimon,
        ScanType::Fin, ScanType::Null, ScanType::Xmas, ScanType::Udp, ScanType::IpProto,
        ScanType::SctpInit, ScanType::SctpCookieEcho,
    ];
    let sc = scans[usize::from(data.first().copied().unwrap_or(0)) % scans.len()];
    let a = data.get(1).copied().unwrap_or(0);
    let b = data.get(2).copied().unwrap_or(0);
    let ft = data.get(3).copied().unwrap_or(0) & 1 == 0;
    let win = u16::from(data.get(4).copied().unwrap_or(0));

    let _ = default_port_state(sc, ft);
    let _ = classify_tcp(sc, a, win);
    let _ = classify_icmp(sc, a, b, ft);
    let _ = classify_sctp(sc, a);
    let _ = classify_udp_response();
});
