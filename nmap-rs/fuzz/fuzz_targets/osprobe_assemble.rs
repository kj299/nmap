// cargo-fuzz target for `nmap_core::osprobe::assemble` and the fingerprint renderer.
//
// A hostile target chooses every reply this assembler consumes — and, through the `U1`
// quote, chooses the hop distance that rewrites *every other test's* TTL. That makes this
// the one place where a single attacker-supplied byte reaches all thirteen tests, so the
// invariants below are cross-cutting rather than per-test.
//
// Enforced:
//   * assembly is TOTAL — any combination of replies produces a fingerprint, never a panic;
//   * `T` and `TG` stay mutually exclusive in every test, so one observation is never
//     scored twice;
//   * silence is only ever claimed for a probe that had a port to go to;
//   * tests are canonical — sorted, deduplicated;
//   * the rendered fingerprint always parses back to exactly what was rendered, which is
//     what makes a submitted fingerprint trustworthy.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::osdb::model::{FingerPrintDb, TestId};
use nmap_core::osprobe::assemble::{assemble, IeReplies, Responses, TcpProbeReply, NUM_T_PROBES};
use nmap_core::osprobe::icmpreply::{EchoReply, U1Sent, UdpErrorReply};
use nmap_core::osprobe::seq::{SeqInputs, SeqReply};
use nmap_core::osprobe::tcpreply::{ProbeContext, TcpReply};

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.wrapping_add(1);
        b
    }
    fn u16(&mut self) -> u16 {
        u16::from(self.u8()) << 8 | u16::from(self.u8())
    }
    fn u32(&mut self) -> u32 {
        u32::from(self.u16()) << 16 | u32::from(self.u16())
    }
    fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }
    /// `None` about a third of the time, so unanswered probes are explored too.
    fn maybe<T>(&mut self, value: T) -> Option<T> {
        if self.u8() % 3 == 0 {
            None
        } else {
            Some(value)
        }
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.u8()).collect()
    }
}

fn tcp_reply(c: &mut Cursor) -> TcpReply {
    let len = usize::from(c.u8() % 64);
    TcpReply {
        df: c.bool(),
        ttl: c.u8(),
        window: c.u16(),
        seq: c.u32(),
        ack: c.u32(),
        flags: c.u8(),
        reserved: c.u8(),
        urgent_ptr: c.u16(),
        segment: c.bytes(len),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor { data, pos: 0 };

    let ctx = ProbeContext {
        sent_seq: c.u32(),
        sent_ack: c.u32(),
    };
    let sent = U1Sent {
        sport: c.u16(),
        dport: c.u16(),
        udp_checksum: c.u16(),
        ttl: c.u8(),
    };

    let open_tcp_port = { let p = c.u16(); c.maybe(p) };
    let closed_tcp_port = { let p = c.u16(); c.maybe(p) };

    let responses = Responses {
        seq: SeqInputs {
            replies: (0..6)
                .map(|_| {
                    let r = SeqReply {
                        isn: c.u32(),
                        ip_id: c.u16(),
                        timestamp: c.u32(),
                        sent_usec: u64::from(c.u32()),
                    };
                    c.maybe(r)
                })
                .collect(),
            tcp_ipids: (0..3).map(|_| c.u16()).collect(),
            closed_tcp_ipids: (0..3).map(|_| c.u16()).collect(),
            icmp_ipids: (0..2).map(|_| c.u16()).collect(),
            is_localhost: c.bool(),
            scan_delay_ms: u64::from(c.u16()),
            ..Default::default()
        },
        ops: (0..6)
            .map(|_| {
                let n = usize::from(c.u8() % 48);
                let b = c.bytes(n);
                c.maybe(b)
            })
            .collect(),
        win: (0..6)
            .map(|_| {
                let w = c.u16();
                c.maybe(w)
            })
            .collect(),
        ecn: {
            let r = tcp_reply(&mut c);
            c.maybe(r)
        },
        t: (0..NUM_T_PROBES)
            .map(|_| {
                let p = TcpProbeReply {
                    reply: tcp_reply(&mut c),
                    ctx,
                };
                c.maybe(p)
            })
            .collect(),
        u1: {
            // The whole tail is the quote, so the fuzzer controls the IHL that decides
            // where the quoted UDP header starts and how far the payload runs.
            let quote = c.data.get(c.pos..).unwrap_or_default().to_vec();
            let r = UdpErrorReply {
                outer_df: c.bool(),
                outer_ttl: c.u8(),
                outer_total_len: c.u16(),
                icmp_unused: c.u32(),
                quote,
            };
            c.maybe(r)
        },
        u1_sent: Some(sent),
        ie: {
            let ie = IeReplies {
                probe0: EchoReply {
                    df: c.bool(),
                    icmp_code: c.u8(),
                    ttl: c.u8(),
                },
                probe1: EchoReply {
                    df: c.bool(),
                    icmp_code: c.u8(),
                    ttl: c.u8(),
                },
                t_ttl: c.u8(),
            };
            c.maybe(ie)
        },
        open_tcp_port,
        closed_tcp_port,
    };

    let observation = assemble(&responses);
    let fp = &observation.fingerprint;

    let mut previous: Option<usize> = None;
    for test in &fp.tests {
        // Canonical order, no duplicates.
        if let Some(p) = previous {
            assert!(test.id.index() > p, "tests out of order or duplicated");
        }
        previous = Some(test.id.index());

        // One observation must never be scored as two pieces of evidence.
        assert!(
            !(test.get("T").is_some() && test.get("TG").is_some()),
            "{} carries both T and TG",
            test.id.name()
        );

        // Silence may only be claimed where a probe could actually be sent.
        if test.get("R") == Some("N") {
            let sendable = match test.id {
                TestId::Ecn | TestId::T1 | TestId::T2 | TestId::T3 | TestId::T4 => {
                    responses.open_tcp_port.is_some()
                }
                TestId::T5 | TestId::T6 | TestId::T7 => responses.closed_tcp_port.is_some(),
                _ => true,
            };
            assert!(
                sendable,
                "{} claimed silence from a probe that was never sent",
                test.id.name()
            );
        }
    }

    // A hop count above the TTL we sent is nonsense and must not be reported.
    if let Some(d) = observation.distance {
        assert!(d <= sent.ttl.saturating_add(1), "impossible hop distance {d}");
    }

    // Determinism: the same replies must always produce the same fingerprint.
    assert_eq!(assemble(&responses).fingerprint, *fp, "not deterministic");

    // The rendered fingerprint must survive the round trip a submission depends on.
    let rendered = fp.render_tests();
    let reparsed = FingerPrintDb::parse(&format!("Fingerprint f\n{rendered}"));
    assert!(
        reparsed.warnings.is_empty(),
        "rendered unparseable text: {rendered:?} -> {:?}",
        reparsed.warnings
    );
    if let Some(back) = reparsed.prints.first() {
        assert_eq!(back.tests, fp.tests, "render/parse round trip lost data");
    }
});
