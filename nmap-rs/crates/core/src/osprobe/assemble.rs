//! Assembling the observed fingerprint — a port of the C's `makeFP`.
//!
//! Every other module in [`super`] turns *one* reply into *one* piece of evidence. This is
//! the module that puts them together: it runs the three aggregate analyses
//! (`SEQ`/`OPS`/`WIN`), collects the per-reply tests, and produces the single
//! [`FingerPrint`] that [`crate::osdb::score`] matches against `nmap-os-db`.
//!
//! Two pieces of cross-test bookkeeping live here, and both are easy to get wrong:
//!
//! * **Silence is evidence.** A probe that went unanswered is recorded as `R=N`, not
//!   omitted — a stack that stays quiet where others reply is exactly what the database
//!   keys on. But `R=N` may only be recorded when the probe was actually *sendable*: the
//!   `ECN`/`T1`–`T4` probes need an open TCP port and `T5`–`T7` need a closed one, so with
//!   no such port the test is left **absent** rather than claimed as silence.
//!
//! * **The TTL post-pass.** Per-reply extraction stores the *observed* TTL in `T`, which
//!   is not what the database holds. Once `U1` yields the true hop count, every test's `T`
//!   is rewritten to the reconstructed initial TTL; without it, each test instead gets a
//!   rounded `TG` guess and `T` is dropped. See
//!   [`finalize_ttl`][super::tcpreply::finalize_ttl].

use super::icmpreply::{ie_test, u1_test, EchoReply, U1Sent, UdpErrorReply};
use super::seq::{analyze_seq, SeqInputs, SeqTest};
use super::tcpreply::{
    ecn_test, finalize_ttl, initial_ttl_guess, ops_test, t_test, win_test, ProbeContext, TcpReply,
};
use crate::osdb::model::{FingerPrint, FingerTest, TestId};

/// Number of `T1`–`T7` probes.
pub const NUM_T_PROBES: usize = 7;
/// Number of `OPS`/`WIN` probes; both read the same six SEQ-probe replies.
pub const NUM_OPS_PROBES: usize = 6;

/// A TCP reply together with the probe that produced it, which the sequence- and
/// acknowledgement-relation attributes are computed against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpProbeReply {
    /// The received segment.
    pub reply: TcpReply,
    /// What we sent, for the `S`/`A` relations.
    pub ctx: ProbeContext,
}

/// The two `IE` echo replies. The pair is only usable together — `DFI` and `CD` are
/// *comparisons*, so one reply carries no `IE` evidence at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IeReplies {
    /// Reply to the first echo probe (sent with DF set, ICMP code 9).
    pub probe0: EchoReply,
    /// Reply to the second echo probe (sent with DF clear, ICMP code 0).
    pub probe1: EchoReply,
    /// TTL to record in `T` — the C uses the TTL of whichever reply arrived second.
    pub t_ttl: u8,
}

/// Everything one host's probe battery came back with.
///
/// Each field is `None`/empty where no reply arrived, which is meaningful rather than
/// merely missing: [`assemble`] turns unanswered *sendable* probes into `R=N`.
#[derive(Debug, Clone, Default)]
pub struct Responses {
    /// Inputs to the `SEQ` analysis (ISNs, IP IDs, timestamps).
    pub seq: SeqInputs,
    /// TCP option strings from the six `OPS` replies, in probe order.
    pub ops: Vec<Option<Vec<u8>>>,
    /// Advertised windows from the six `WIN` replies, in probe order.
    pub win: Vec<Option<u16>>,
    /// Reply to the `ECN` probe.
    pub ecn: Option<TcpReply>,
    /// Replies to `T1`–`T7`, in probe order.
    pub t: Vec<Option<TcpProbeReply>>,
    /// The ICMP port-unreachable elicited by the `U1` probe.
    pub u1: Option<UdpErrorReply>,
    /// What the `U1` probe put on the wire, needed to judge the quote.
    pub u1_sent: Option<U1Sent>,
    /// The two `IE` echo replies.
    pub ie: Option<IeReplies>,
    /// An open TCP port, if the scan found one. Gates the `ECN`/`T1`–`T4` probes.
    pub open_tcp_port: Option<u16>,
    /// A closed TCP port, if the scan found one. Gates the `T5`–`T7` probes.
    pub closed_tcp_port: Option<u16>,
}

/// The assembled observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The fingerprint to score against the database.
    pub fingerprint: FingerPrint,
    /// The `SEQ` analysis, kept separately because `-O` reports some of it directly.
    pub seq: SeqTest,
    /// True hop count from the `U1` quote, if we got one.
    pub distance: Option<u8>,
    /// Fallback hop count inferred from the first observed TTL, used for the reported
    /// network distance when `U1` gave no answer. Never feeds the fingerprint itself.
    pub distance_guess: Option<u8>,
}

/// Whether an unanswered probe may be recorded as `R=N`.
///
/// The C gates this on having a port to send to (`makeFP`'s index ranges). Claiming
/// silence from a probe that was never sent would be inventing evidence: the database
/// would be told the host declined to answer something we never asked.
fn silence_is_evidence(id: TestId, r: &Responses) -> bool {
    match id {
        TestId::Ecn | TestId::T1 | TestId::T2 | TestId::T3 | TestId::T4 => {
            r.open_tcp_port.is_some()
        }
        TestId::T5 | TestId::T6 | TestId::T7 => r.closed_tcp_port.is_some(),
        // `U1` and `IE` carry their own ports/protocol, so they are always sendable.
        TestId::U1 | TestId::Ie => true,
        // The aggregates have no `R` attribute; an incomplete set is simply absent.
        TestId::Seq | TestId::Ops | TestId::Win => false,
    }
}

/// Build the per-reply test for one of the post-aggregate tests, or `None` if no usable
/// reply arrived.
fn extracted(id: TestId, r: &Responses, distance: &mut Option<u8>) -> Option<FingerTest> {
    match id {
        TestId::Ecn => r.ecn.as_ref().map(ecn_test),
        TestId::T1
        | TestId::T2
        | TestId::T3
        | TestId::T4
        | TestId::T5
        | TestId::T6
        | TestId::T7 => {
            // `T1` is index 0 of the probe array, `T7` index 6.
            let n = id.index().checked_sub(TestId::T1.index())?;
            let probe = r.t.get(n)?.as_ref()?;
            let number = u8::try_from(n.checked_add(1)?).ok()?;
            t_test(number, &probe.reply, &probe.ctx)
        }
        TestId::U1 => {
            let reply = r.u1.as_ref()?;
            let sent = r.u1_sent.as_ref()?;
            let result = u1_test(reply, sent)?;
            // The hop count the whole fingerprint's TTL reconstruction depends on.
            *distance = result.distance;
            Some(result.test)
        }
        TestId::Ie => {
            let ie = r.ie.as_ref()?;
            Some(ie_test(&ie.probe0, &ie.probe1, ie.t_ttl))
        }
        TestId::Seq | TestId::Ops | TestId::Win => None,
    }
}

/// Turn a host's collected replies into the fingerprint to score — the C's `makeFP`.
#[must_use]
pub fn assemble(r: &Responses) -> Observation {
    let mut fingerprint = FingerPrint::default();

    // The three aggregates. `SEQ` is always emitted (the C's `makeTSeqFP` always builds
    // it); `OPS`/`WIN` need all six replies or they are left absent entirely — note they
    // get no `R=N` fallback, because they have no `R` attribute to carry it.
    let seq = analyze_seq(&r.seq);
    let mut tests = vec![seq.to_finger_test()];
    if let Some(ops) = ops_test(&r.ops) {
        tests.push(ops);
    }
    if let Some(win) = win_test(&r.win) {
        tests.push(win);
    }

    // `U1` must be extracted before anything is finalized: it is what produces the hop
    // count that every other test's `T` is rewritten against. Running the tests in
    // `TestId::ALL` order puts `U1` (index 11) after the tests that depend on it, so the
    // distance is collected in this pass and applied in a second one below.
    let mut distance = None;
    for id in TestId::ALL {
        if let Some(test) = extracted(id, r, &mut distance) {
            tests.push(test);
        } else if silence_is_evidence(id, r) {
            // The probe was sent and nothing came back. That is a finding, not a gap.
            let mut test = FingerTest::new(id);
            test.set("R", "N");
            tests.push(test);
        }
    }

    // Second pass: resolve every `T` now that the hop count is known (or known absent).
    // The guess is taken from the first observed TTL, before any of them are rewritten.
    let mut distance_guess = None;
    for test in &mut tests {
        if let Some(observed) = test.get("T").and_then(|v| u32::from_str_radix(v, 16).ok()) {
            if distance_guess.is_none() {
                let ttl = u8::try_from(observed).unwrap_or(u8::MAX);
                let guess = initial_ttl_guess(ttl).saturating_sub(u16::from(ttl));
                distance_guess = Some(u8::try_from(guess).unwrap_or(u8::MAX));
            }
        }
        finalize_ttl(test, distance);
    }

    tests.sort_by_key(|t| t.id.index());
    fingerprint.tests = tests;

    Observation {
        fingerprint,
        seq,
        distance,
        distance_guess,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osprobe::seq::SeqReply;

    /// A plain SYN/ACK-shaped reply.
    fn tcp_reply(ttl: u8) -> TcpReply {
        TcpReply {
            df: true,
            ttl,
            window: 0x1c84,
            seq: 0x4000_0000,
            ack: 0x1001,
            flags: 0x12, // SYN|ACK
            reserved: 0,
            urgent_ptr: 0,
            segment: Vec::new(),
        }
    }

    fn probe_reply(ttl: u8) -> TcpProbeReply {
        TcpProbeReply {
            reply: tcp_reply(ttl),
            ctx: ProbeContext {
                sent_seq: 0x1000,
                sent_ack: 0,
            },
        }
    }

    /// A `U1` quote that echoes our probe back untouched, which is what yields a distance.
    fn faithful_u1(sent: &U1Sent, outer_ttl: u8, quoted_ttl: u8) -> UdpErrorReply {
        let mut quote = vec![0u8; 28 + 300];
        quote[0] = 0x45; // IPv4, IHL 5
        quote[2] = 0x01; // total length 328
        quote[3] = 0x48;
        quote[8] = quoted_ttl;
        quote[9] = 17; // UDP
        quote[20] = (sent.sport >> 8) as u8;
        quote[21] = (sent.sport & 0xff) as u8;
        quote[22] = (sent.dport >> 8) as u8;
        quote[23] = (sent.dport & 0xff) as u8;
        UdpErrorReply {
            outer_df: false,
            outer_ttl,
            outer_total_len: 356,
            icmp_unused: 0,
            quote,
        }
    }

    fn sent() -> U1Sent {
        U1Sent {
            sport: 0x9d3b,
            dport: 0x9d3c,
            udp_checksum: 0x1234,
            ttl: 64,
        }
    }

    #[test]
    fn seq_is_always_present_even_with_no_replies() {
        let o = assemble(&Responses::default());
        assert!(
            o.fingerprint.test(TestId::Seq).is_some(),
            "SEQ must always be emitted"
        );
    }

    #[test]
    fn ops_and_win_need_all_six_replies() {
        let mut r = Responses {
            ops: vec![Some(vec![0x01, 0x01]); 6],
            win: vec![Some(0x1c84); 6],
            ..Default::default()
        };
        let o = assemble(&r);
        assert!(o.fingerprint.test(TestId::Ops).is_some());
        assert!(o.fingerprint.test(TestId::Win).is_some());

        // One missing reply drops the whole aggregate — and must NOT become `R=N`,
        // because OPS/WIN have no `R` attribute to carry that claim.
        r.ops[3] = None;
        r.win[5] = None;
        let o = assemble(&r);
        assert!(o.fingerprint.test(TestId::Ops).is_none());
        assert!(o.fingerprint.test(TestId::Win).is_none());
    }

    #[test]
    fn silence_is_recorded_only_for_probes_we_could_send() {
        // No ports at all: the TCP tests are absent, not silent.
        let o = assemble(&Responses::default());
        for id in [TestId::Ecn, TestId::T1, TestId::T4, TestId::T5, TestId::T7] {
            assert!(
                o.fingerprint.test(id).is_none(),
                "{} must be absent with no port to probe",
                id.name()
            );
        }
        // U1 and IE carry their own ports, so silence from them is always evidence.
        for id in [TestId::U1, TestId::Ie] {
            assert_eq!(o.fingerprint.test(id).and_then(|t| t.get("R")), Some("N"));
        }

        // An open port makes ECN/T1-T4 sendable; T5-T7 still are not.
        let open = Responses {
            open_tcp_port: Some(22),
            ..Default::default()
        };
        let o = assemble(&open);
        for id in [TestId::Ecn, TestId::T1, TestId::T2, TestId::T3, TestId::T4] {
            assert_eq!(
                o.fingerprint.test(id).and_then(|t| t.get("R")),
                Some("N"),
                "{} should be recorded silent",
                id.name()
            );
        }
        for id in [TestId::T5, TestId::T6, TestId::T7] {
            assert!(o.fingerprint.test(id).is_none(), "{}", id.name());
        }

        // A closed port makes T5-T7 sendable.
        let closed = Responses {
            closed_tcp_port: Some(1),
            ..Default::default()
        };
        let o = assemble(&closed);
        for id in [TestId::T5, TestId::T6, TestId::T7] {
            assert_eq!(o.fingerprint.test(id).and_then(|t| t.get("R")), Some("N"));
        }
        for id in [TestId::Ecn, TestId::T1] {
            assert!(o.fingerprint.test(id).is_none());
        }
    }

    #[test]
    fn u1_distance_rewrites_every_ttl() {
        let s = sent();
        // Sent with TTL 64, quoted back at 61 => 64 - 61 + 1 = 4 hops.
        let r = Responses {
            open_tcp_port: Some(22),
            closed_tcp_port: Some(1),
            t: {
                let mut v = vec![None; NUM_T_PROBES];
                v[0] = Some(probe_reply(0x3d)); // observed TTL 61
                v
            },
            u1: Some(faithful_u1(&s, 0x3d, 61)),
            u1_sent: Some(s),
            ..Default::default()
        };
        let o = assemble(&r);
        assert_eq!(o.distance, Some(4));

        // T = observed + distance - 1 = 61 + 3 = 64 (0x40), and TG must be gone.
        let t1 = o.fingerprint.test(TestId::T1).expect("T1");
        assert_eq!(t1.get("T"), Some("40"));
        assert_eq!(t1.get("TG"), None);

        // The same correction applies to U1's own T.
        let u1 = o.fingerprint.test(TestId::U1).expect("U1");
        assert_eq!(u1.get("T"), Some("40"));
        assert_eq!(u1.get("TG"), None);
    }

    #[test]
    fn without_u1_every_test_falls_back_to_a_guess() {
        let r = Responses {
            open_tcp_port: Some(22),
            t: {
                let mut v = vec![None; NUM_T_PROBES];
                v[0] = Some(probe_reply(0x3d)); // 61
                v
            },
            ..Default::default()
        };
        let o = assemble(&r);
        assert_eq!(o.distance, None);
        // 61 rounds up to an initial TTL of 64, so the guessed distance is 3.
        assert_eq!(o.distance_guess, Some(3));

        let t1 = o.fingerprint.test(TestId::T1).expect("T1");
        assert_eq!(t1.get("TG"), Some("40"));
        assert_eq!(
            t1.get("T"),
            None,
            "an uncorrected observed TTL must not be left in T"
        );
    }

    #[test]
    fn t_and_tg_are_mutually_exclusive_across_every_test() {
        let s = sent();
        for u1 in [None, Some(faithful_u1(&s, 0x40, 61))] {
            let r = Responses {
                open_tcp_port: Some(22),
                closed_tcp_port: Some(1),
                t: (0..NUM_T_PROBES).map(|_| Some(probe_reply(0x40))).collect(),
                ecn: Some(tcp_reply(0x40)),
                ie: Some(IeReplies {
                    probe0: EchoReply {
                        df: true,
                        icmp_code: 9,
                        ttl: 0x40,
                    },
                    probe1: EchoReply {
                        df: false,
                        icmp_code: 0,
                        ttl: 0x40,
                    },
                    t_ttl: 0x40,
                }),
                u1,
                u1_sent: Some(s),
                ..Default::default()
            };
            let o = assemble(&r);
            for test in &o.fingerprint.tests {
                let has_t = test.get("T").is_some();
                let has_tg = test.get("TG").is_some();
                assert!(
                    !(has_t && has_tg),
                    "{} carries both T and TG",
                    test.id.name()
                );
            }
        }
    }

    #[test]
    fn tests_are_emitted_in_canonical_order() {
        let r = Responses {
            open_tcp_port: Some(22),
            closed_tcp_port: Some(1),
            ops: vec![Some(vec![0x01]); 6],
            win: vec![Some(1); 6],
            ..Default::default()
        };
        let o = assemble(&r);
        let indices: Vec<usize> = o.fingerprint.tests.iter().map(|t| t.id.index()).collect();
        let mut sorted = indices.clone();
        sorted.sort_unstable();
        assert_eq!(indices, sorted, "tests must render in TestID order");
        // And no test appears twice.
        sorted.dedup();
        assert_eq!(sorted.len(), indices.len(), "duplicate test emitted");
    }

    #[test]
    fn a_seq_observation_reaches_the_seq_test() {
        let r = Responses {
            seq: SeqInputs {
                replies: (0..6)
                    .map(|i| {
                        Some(SeqReply {
                            isn: 1000 + i * 500,
                            ip_id: u16::try_from(i).unwrap_or(0),
                            timestamp: 0,
                            sent_usec: u64::from(i) * 100_000,
                        })
                    })
                    .collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        let o = assemble(&r);
        let seq = o.fingerprint.test(TestId::Seq).expect("SEQ");
        assert!(seq.get("GCD").is_some(), "a real ISN series must yield GCD");
        assert_eq!(o.seq.responses, 6);
    }
}
