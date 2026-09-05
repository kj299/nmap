//! Corpus gate for the observed-fingerprint assembler and renderer, against the **real**
//! 5.1 MB `nmap-os-db`.
//!
//! Two properties are checked here, and they cover the two directions this code has to be
//! right in:
//!
//! 1. **The renderer is the parser's exact inverse.** For every one of the ~6,100 shipped
//!    records, rendering its tests and parsing the result back must reproduce the tests
//!    byte for byte. This is the property that makes a submitted fingerprint meaningful:
//!    what nmap prints for an unrecognised host is what a maintainer later parses into the
//!    database, so any asymmetry silently corrupts submissions. It also exercises every
//!    attribute value shape the real file contains — ranges, alternations, empty values —
//!    rather than the handful a unit test would invent.
//!
//! 2. **An assembled observation scores against the real database.** Probe replies are
//!    synthesised for a Linux-shaped host, run through [`assemble`], and matched. The
//!    result must be well-formed and must actually identify the host.
//!
//! Skipped under Miri (reads a real file; Miri's filesystem isolation aborts rather than
//! returning `Err`). The unit suites in `osprobe::assemble` and `osdb::model` are what
//! Miri interrogates.
#![cfg(not(miri))]

use nmap_core::checksum::in_cksum;
use nmap_core::osdb::model::{FingerPrintDb, TestId};
use nmap_core::osdb::score::{match_fingerprint, GUESS_THRESHOLD};
use nmap_core::osprobe::assemble::{assemble, IeReplies, Responses, TcpProbeReply, NUM_T_PROBES};
use nmap_core::osprobe::build::{UDP_IP_ID, UDP_PATTERN_BYTE};
use nmap_core::osprobe::icmpreply::{EchoReply, U1Sent, UdpErrorReply};
use nmap_core::osprobe::seq::{SeqInputs, SeqReply};
use nmap_core::osprobe::tcpreply::{ProbeContext, TcpReply};

fn load_corpus() -> Option<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nmap-os-db");
    std::fs::read_to_string(path).ok()
}

/// Rendering a record's tests and reading them back must return exactly what went in.
#[test]
fn every_shipped_fingerprint_survives_a_render_parse_round_trip() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-os-db not found; skipping");
        return;
    };
    let db = FingerPrintDb::parse(&text);
    assert!(
        db.prints.len() > 5_000,
        "expected the real database, got {} records",
        db.prints.len()
    );
    assert!(
        db.warnings.is_empty(),
        "the shipped database must parse cleanly: {:?}",
        &db.warnings[..db.warnings.len().min(4)]
    );

    let mut checked = 0usize;
    for print in &db.prints {
        // Render just the tests, then wrap them in a minimal record so the parser will
        // read them back the same way it read the original.
        let rendered = print.render_tests();
        let round_tripped = FingerPrintDb::parse(&format!("Fingerprint x\n{rendered}"));
        assert!(
            round_tripped.warnings.is_empty(),
            "rendering {:?} (line {}) produced text the parser rejects: {:?}\n{rendered}",
            print.os_name,
            print.line,
            round_tripped.warnings
        );
        let back = round_tripped
            .prints
            .first()
            .unwrap_or_else(|| panic!("no record parsed back for {:?}", print.os_name));

        assert_eq!(
            back.tests, print.tests,
            "round trip changed the tests of {:?} (line {})\n{rendered}",
            print.os_name, print.line
        );
        checked += 1;
    }
    assert!(checked > 5_000, "only checked {checked} records");
}

/// Rendering is canonical: tests come out in `TestID` order and each appears once, so two
/// runs that saw the same things produce identical text.
#[test]
fn rendering_is_canonical_and_reparses_in_order() {
    let Some(text) = load_corpus() else {
        return;
    };
    let db = FingerPrintDb::parse(&text);
    for print in db.prints.iter().take(500) {
        let rendered = print.render_tests();
        let mut previous: Option<usize> = None;
        for line in rendered.lines() {
            let name = line.split('(').next().unwrap_or_default();
            let id = TestId::from_name(name)
                .unwrap_or_else(|| panic!("rendered an unknown test name {name:?}"));
            if let Some(p) = previous {
                assert!(
                    id.index() > p,
                    "tests rendered out of order in {:?}",
                    print.os_name
                );
            }
            previous = Some(id.index());
        }
        // Rendering twice must not drift.
        assert_eq!(rendered, print.render_tests());
    }
}

/// TTL the synthesised host's packets arrive with; it started at 64 and crossed 3 hops.
const OBSERVED_TTL: u8 = 61;
/// What the `U1` probe was sent with.
const SENT: U1Sent = U1Sent {
    sport: 0x9d3b,
    dport: 0x9d3c,
    udp_checksum: 0x1234,
    ttl: 64,
};

/// A `U1` quote that echoes our probe back **untouched** — every `R*` attribute should
/// come back `G`, and the quoted TTL gives the true hop count.
///
/// Built field by field rather than copied from a fixture so the all-`G` path is only
/// reached by genuinely reproducing what the probe put on the wire: our fixed IP ID, a
/// valid header checksum, the checksum we sent, and an unbroken payload pattern.
fn faithful_u1(quoted_ttl: u8) -> UdpErrorReply {
    let mut quote = vec![UDP_PATTERN_BYTE; 328];
    quote[0] = 0x45; // IPv4, IHL 5
    quote[1] = 0;
    quote[2] = 0x01; // total length 328 == U1's sent length
    quote[3] = 0x48;
    quote[4] = u8::try_from(UDP_IP_ID >> 8).unwrap_or(0);
    quote[5] = u8::try_from(UDP_IP_ID & 0xff).unwrap_or(0);
    quote[6] = 0;
    quote[7] = 0;
    quote[8] = quoted_ttl;
    quote[9] = 17; // UDP
    quote[10] = 0; // checksum, filled in below
    quote[11] = 0;
    quote[12..20].fill(0); // src/dst addresses

    // A valid IP header checksum, so RIPCK reports `G` rather than `Z` or `I`.
    let mut header = [0u8; 20];
    header.copy_from_slice(&quote[..20]);
    let ck = in_cksum(&header);
    quote[10] = u8::try_from(ck >> 8).unwrap_or(0);
    quote[11] = u8::try_from(ck & 0xff).unwrap_or(0);
    // UDP header: our ports, our length, our checksum. Payload stays the pattern byte.
    quote[20] = u8::try_from(SENT.sport >> 8).unwrap_or(0);
    quote[21] = u8::try_from(SENT.sport & 0xff).unwrap_or(0);
    quote[22] = u8::try_from(SENT.dport >> 8).unwrap_or(0);
    quote[23] = u8::try_from(SENT.dport & 0xff).unwrap_or(0);
    quote[24] = 0x01; // UDP length 308
    quote[25] = 0x34;
    quote[26] = u8::try_from(SENT.udp_checksum >> 8).unwrap_or(0);
    quote[27] = u8::try_from(SENT.udp_checksum & 0xff).unwrap_or(0);

    UdpErrorReply {
        outer_df: false,
        outer_ttl: OBSERVED_TTL,
        outer_total_len: 356,
        icmp_unused: 0,
        quote,
    }
}

/// A full TCP segment: 20-byte header with the data offset set past `options`, which is
/// what option extraction reads. Passing bare option bytes would be misread as a header.
fn segment(options: &[u8]) -> Vec<u8> {
    let mut seg = vec![0u8; 20];
    seg.extend_from_slice(options);
    while !seg.len().is_multiple_of(4) {
        seg.push(0x01); // NOP-pad to a 4-byte boundary
    }
    let offset = u8::try_from(seg.len() / 4).unwrap_or(5);
    seg[12] = offset << 4;
    seg
}

/// The option set a Linux SYN/ACK carries: MSS 1460, SACK permitted, timestamp, NOP,
/// window scale 7.
fn linux_options() -> Vec<u8> {
    let mut o = vec![0x02, 0x04, 0x05, 0xb4, 0x04, 0x02];
    o.extend_from_slice(&[0x08, 0x0a, 0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x13, 0x88]);
    o.extend_from_slice(&[0x01, 0x03, 0x03, 0x07]);
    o
}

/// Replies shaped like a Linux host three hops away.
fn linux_responses() -> Responses {
    let ctx = ProbeContext {
        sent_seq: 0x1000,
        sent_ack: 0x2000,
    };
    let reply = |flags: u8, window: u16, seq: u32, ack: u32, options: &[u8]| TcpReply {
        df: true,
        ttl: OBSERVED_TTL,
        window,
        seq,
        ack,
        flags,
        reserved: 0,
        urgent_ptr: 0,
        segment: segment(options),
    };
    let probe = |flags: u8, window: u16, seq: u32, ack: u32| TcpProbeReply {
        reply: reply(flags, window, seq, ack, &[]),
        ctx,
    };

    Responses {
        seq: SeqInputs {
            replies: (0..6u32)
                .map(|i| {
                    Some(SeqReply {
                        // A rising, non-uniformly-spaced ISN series: a GCD of 1 and a
                        // wide spread, as a randomised stack produces.
                        isn: 0x4a3f_0000u32.wrapping_add(i.wrapping_mul(0x0031_7d5b) ^ (i << 3)),
                        ip_id: 0,
                        timestamp: 100_000u32.wrapping_add(i.wrapping_mul(102)),
                        sent_usec: u64::from(i) * 100_000,
                    })
                })
                .collect(),
            tcp_ipids: vec![0; 6],
            closed_tcp_ipids: vec![0; 3],
            icmp_ipids: vec![4_000, 4_001, 4_002],
            ..Default::default()
        },
        ops: vec![Some(segment(&linux_options())); 6],
        win: vec![Some(0x7120); 6],
        // ECN reply: SYN/ACK with ECE set and CWR clear.
        ecn: Some(reply(0x52, 0x7210, 0xdead_beef, 0x1001, &linux_options())),
        t: {
            let mut v: Vec<Option<TcpProbeReply>> = vec![None; NUM_T_PROBES];
            // T1: SYN/ACK — seq unrelated to what we sent, ack one past our seq.
            v[0] = Some(probe(0x12, 0x7120, 0xdead_beef, 0x1001));
            // T4/T6: bare RST echoing our ack as its seq, with no ack of its own.
            v[3] = Some(probe(0x04, 0, 0x2000, 0));
            v[5] = Some(probe(0x04, 0, 0x2000, 0));
            // T5/T7: RST/ACK with a zero seq.
            v[4] = Some(probe(0x14, 0, 0, 0x1001));
            v[6] = Some(probe(0x14, 0, 0, 0x1001));
            v
        },
        u1: Some(faithful_u1(61)),
        u1_sent: Some(SENT),
        ie: Some(IeReplies {
            probe0: EchoReply {
                df: false,
                icmp_code: 9,
                ttl: OBSERVED_TTL,
            },
            probe1: EchoReply {
                df: false,
                icmp_code: 0,
                ttl: OBSERVED_TTL,
            },
            t_ttl: OBSERVED_TTL,
        }),
        open_tcp_port: Some(22),
        closed_tcp_port: Some(1),
    }
}

/// The end-to-end path: synthesised replies -> assembled fingerprint -> rendered text ->
/// parsed back -> scored against the real database.
#[test]
fn an_assembled_observation_renders_reparses_and_scores() {
    let observation = assemble(&linux_responses());

    // The U1 quote gave a true hop count, so every TTL is reconstructed rather than
    // guessed: T is the initial TTL and TG is absent everywhere.
    assert_eq!(observation.distance, Some(4));
    for test in &observation.fingerprint.tests {
        assert!(
            test.get("TG").is_none(),
            "{} fell back to a TG guess despite a known distance",
            test.id.name()
        );
    }
    assert_eq!(
        observation
            .fingerprint
            .test(TestId::T1)
            .and_then(|t| t.get("T")),
        Some("40"),
        "61 observed + 3 hops should reconstruct to an initial TTL of 0x40"
    );

    // Every probe we could send is accounted for: answered or explicitly silent.
    for id in [
        TestId::Ecn,
        TestId::T1,
        TestId::T2,
        TestId::T3,
        TestId::T4,
        TestId::T5,
        TestId::T6,
        TestId::T7,
        TestId::U1,
        TestId::Ie,
    ] {
        let test = observation
            .fingerprint
            .test(id)
            .unwrap_or_else(|| panic!("{} missing entirely", id.name()));
        assert!(
            test.get("R").is_some(),
            "{} must record whether it responded",
            id.name()
        );
    }
    // T2 and T3 got no reply, so they must say so rather than go missing.
    for id in [TestId::T2, TestId::T3] {
        assert_eq!(
            observation.fingerprint.test(id).and_then(|t| t.get("R")),
            Some("N")
        );
    }

    // The rendered observation must survive the same round trip a submission does.
    let rendered = observation.fingerprint.render_tests();
    let reparsed = FingerPrintDb::parse(&format!("Fingerprint observed\n{rendered}"));
    assert!(
        reparsed.warnings.is_empty(),
        "an assembled fingerprint must render to parseable text: {:?}\n{rendered}",
        reparsed.warnings
    );
    assert_eq!(
        reparsed.prints.first().map(|p| &p.tests),
        Some(&observation.fingerprint.tests),
        "assembled fingerprint changed across a render/parse round trip\n{rendered}"
    );

    // And it must score cleanly against the real database.
    let Some(text) = load_corpus() else {
        eprintln!("nmap-os-db not found; skipping the scoring half");
        return;
    };
    let db = FingerPrintDb::parse(&text);
    let results = match_fingerprint(&observation.fingerprint, &db, GUESS_THRESHOLD);
    let mut previous = f64::INFINITY;
    for m in &results.matches {
        assert!(
            m.accuracy.is_finite() && (0.0..=1.0).contains(&m.accuracy),
            "accuracy out of range for {:?}",
            m.os_name
        );
        assert!(previous >= m.accuracy, "results not sorted descending");
        previous = m.accuracy;
    }
    // The whole point of the pipeline: a faithfully-observed Linux host is identified as
    // Linux, at nmap's own guess threshold rather than merely "somewhere in the list".
    let best = results
        .matches
        .first()
        .expect("a well-formed Linux-shaped observation must match something");
    assert!(
        best.accuracy >= GUESS_THRESHOLD,
        "best match {:?} scored {:.4}, below the {GUESS_THRESHOLD} threshold",
        best.os_name,
        best.accuracy
    );
    assert!(
        best.os_name.to_lowercase().contains("linux"),
        "expected a Linux entry to lead, got: {:?}",
        results
            .matches
            .iter()
            .map(|m| (&m.os_name, m.accuracy))
            .take(5)
            .collect::<Vec<_>>()
    );
}

/// A host that answered nothing still produces a scoreable fingerprint rather than
/// panicking or scoring as a perfect match for something.
#[test]
fn a_silent_host_still_assembles_and_scores() {
    let observation = assemble(&Responses {
        open_tcp_port: Some(22),
        closed_tcp_port: Some(1),
        ..Default::default()
    });
    let rendered = observation.fingerprint.render_tests();
    assert!(rendered.contains("T1(R=N)"), "got:\n{rendered}");

    let Some(text) = load_corpus() else {
        return;
    };
    let db = FingerPrintDb::parse(&text);
    let results = match_fingerprint(&observation.fingerprint, &db, GUESS_THRESHOLD);
    assert_eq!(
        results.num_perfect_matches, 0,
        "a host that said nothing must not perfectly match a real OS"
    );
}
