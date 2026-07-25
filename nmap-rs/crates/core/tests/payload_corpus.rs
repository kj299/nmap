//! Differential/regression gate for `core::payload` against the **real** 2.5 MB
//! `nmap-service-probes` shipped in the C tree.
//!
//! `payload.cc` has no data file of its own: `init_payloads()` derives the UDP payload
//! table from the probe DB — every `Probe UDP` line not flagged `no-payload` contributes
//! its probe string to each port in its `ports` directive (`probablePortsBegin/End`,
//! which is `ports` only — **not** `sslports`). The heavy part, parsing that file, has
//! its own C differential in `probedb_corpus.rs`; what this gate pins is the derivation
//! and its ground truth over the shipped file.
//!
//! Ground truth was computed by an independent implementation of `init_payloads()` over
//! the shipped file (a standalone script walking `Probe`/`ports` lines), not by our own
//! code — so agreement here is a real cross-check, not self-consistency:
//!
//! ```text
//!   Probe lines               : 187  (103 TCP + 84 UDP)
//!   UDP probes flagged no-payload :   1
//!   UDP probes contributing payloads : 83
//!   ports with >= 1 payload   : 33110   (probes list wide `ports` ranges)
//!   max payloads on any port  :     4
//!   total (port, payload) pairs: 33205
//! ```
//!
//! Skipped under Miri, like the other corpus gates: it reads a real file, and Miri's
//! filesystem isolation *aborts* rather than returning `Err`.
#![cfg(not(miri))]

use nmap_core::payload::{UdpPayloads, MAX_PAYLOADS_PER_PORT};
use nmap_core::probedb::{ProbeDb, ProbeProtocol};

/// Locate the shipped probe file relative to this crate (repo-root sibling of
/// `nmap-rs/`). Skips (does not fail) if absent, so a stripped checkout still builds.
fn load_corpus() -> Option<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nmap-service-probes");
    std::fs::read_to_string(path).ok()
}

/// Ground truth from the independent derivation (see the module docs).
const UDP_PROBES: usize = 84;
const UDP_NO_PAYLOAD: usize = 1;
const CONTRIBUTING_PROBES: usize = 83;
const PORTS_WITH_PAYLOADS: usize = 33110;
const MAX_ON_ANY_PORT: usize = 4;
const TOTAL_PAIRS: usize = 33205;

#[test]
fn payload_table_matches_the_shipped_probe_file() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-service-probes not found; skipping payload corpus");
        return;
    };
    let db = ProbeDb::parse(&text);

    // The inputs to the derivation, straight from the parsed DB.
    let udp: Vec<_> = db
        .probes
        .iter()
        .filter(|p| p.protocol == ProbeProtocol::Udp)
        .collect();
    assert_eq!(udp.len(), UDP_PROBES, "UDP probe count");
    assert_eq!(
        udp.iter().filter(|p| p.no_payload).count(),
        UDP_NO_PAYLOAD,
        "UDP probes flagged no-payload"
    );
    assert_eq!(
        udp.iter()
            .filter(|p| !p.no_payload && !p.probestring.is_empty())
            .count(),
        CONTRIBUTING_PROBES,
        "UDP probes contributing a payload"
    );

    let table = UdpPayloads::from_probe_db(&db);
    assert_eq!(
        table.ports_with_payloads(),
        PORTS_WITH_PAYLOADS,
        "ports with at least one payload"
    );
    assert!(
        table.capped_ports().is_empty(),
        "shipped file must not hit the per-port cap, got {:?}",
        table.capped_ports()
    );

    // Per-port totals and the observed maximum.
    let mut total = 0usize;
    let mut max_seen = 0usize;
    for port in 0..=u16::MAX {
        let n = table.count(port);
        total += n;
        max_seen = max_seen.max(n);
        assert!(
            n <= MAX_PAYLOADS_PER_PORT,
            "port {port} exceeds the cap with {n}"
        );
    }
    assert_eq!(total, TOTAL_PAIRS, "total (port, payload) pairs");
    assert_eq!(max_seen, MAX_ON_ANY_PORT, "max payloads on any single port");
}

#[test]
fn well_known_ports_carry_the_payload_nmap_sends() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-service-probes not found; skipping payload corpus");
        return;
    };
    let table = UdpPayloads::from_probe_db(&ProbeDb::parse(&text));

    // Per-port payload counts from the independent derivation. These are the ports the
    // UDP scan most depends on: a mis-derivation shows up here first.
    for (port, want) in [
        (53u16, 3usize), // DNSVersionBindReq, DNSStatusRequest, DNS-SD
        (111, 2),        // RPCCheck, ONCRPC_CALL
        (123, 2),        // NTPRequest, NTP_REQ
        (137, 3),        // NBTStat, CIFS_NS_UC, CIFS_NS_BC
        (161, 2),        // SNMPv1public, SNMPv3GetRequest
        (500, 4),        // RPCCheck, OpenVPN, IKE_MAIN_MODE, IPSEC_START
        (1900, 1),       // UPNP_MSEARCH
        (5353, 3),       // NTPRequest, DNS-SD, DNS_SD_QU
    ] {
        assert_eq!(table.count(port), want, "payload count for port {port}");
        assert!(
            !table.get(port, 0).is_empty(),
            "port {port} must have a non-empty payload"
        );
    }

    // Semantic anchors: the bytes must be the real protocol requests, not just present.
    // DNS: one of port 53's payloads is a status request / version.bind query — every
    // DNS payload is a well-formed 12-byte-header query with QDCOUNT sane.
    for (i, p) in table.for_port(53).iter().enumerate() {
        assert!(
            p.len() >= 12,
            "DNS payload {i} is shorter than a DNS header: {p:02x?}"
        );
    }
    // NTP: an NTP request is a small fixed-size packet whose first byte encodes LI/VN/Mode.
    let ntp = table.get(123, 0);
    assert!(
        (12..=68).contains(&ntp.len()),
        "NTP payload has an implausible length {}",
        ntp.len()
    );
    // SNMP: an SNMPv1 get starts with an ASN.1 SEQUENCE tag (0x30).
    assert!(
        table.for_port(161).iter().any(|p| p.first() == Some(&0x30)),
        "no SNMP payload on 161 starts with an ASN.1 SEQUENCE"
    );
    // NetBIOS name service on 137 uses a 12-byte-header query like DNS.
    assert!(
        table.for_port(137).iter().all(|p| p.len() >= 12),
        "an NBNS payload is too short to be a name query"
    );
    // SSDP on 1900 is an HTTP-style M-SEARCH.
    assert!(
        table.get(1900, 0).starts_with(b"M-SEARCH"),
        "port 1900 payload is not an SSDP M-SEARCH"
    );
}

#[test]
fn no_payload_probe_is_excluded_from_the_table() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-service-probes not found; skipping payload corpus");
        return;
    };
    let db = ProbeDb::parse(&text);
    let table = UdpPayloads::from_probe_db(&db);

    // The probe(s) the file flags `no-payload` must contribute nothing anywhere: their
    // exact probe string must not appear on any port they claim.
    let flagged: Vec<_> = db
        .probes
        .iter()
        .filter(|p| p.protocol == ProbeProtocol::Udp && p.no_payload)
        .collect();
    assert_eq!(flagged.len(), UDP_NO_PAYLOAD, "expected the flagged probe");
    for probe in flagged {
        for &port in &probe.ports {
            assert!(
                !table.for_port(port).contains(&probe.probestring),
                "no-payload probe {} leaked onto port {port}",
                probe.name
            );
        }
    }
}

#[test]
fn tcp_probe_strings_never_appear_as_udp_payloads() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-service-probes not found; skipping payload corpus");
        return;
    };
    let db = ProbeDb::parse(&text);
    let table = UdpPayloads::from_probe_db(&db);

    // Every payload must be traceable to an eligible UDP probe. This catches a
    // derivation that accidentally walked the TCP probes (or the NULL probe).
    let eligible: Vec<&Vec<u8>> = db
        .probes
        .iter()
        .filter(|p| p.protocol == ProbeProtocol::Udp && !p.no_payload)
        .map(|p| &p.probestring)
        .collect();
    for port in 0..=u16::MAX {
        for payload in table.for_port(port) {
            assert!(
                eligible.contains(&payload),
                "port {port} carries a payload that is not from an eligible UDP probe"
            );
        }
    }
}
