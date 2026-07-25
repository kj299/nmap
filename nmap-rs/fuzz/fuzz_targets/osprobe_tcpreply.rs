// cargo-fuzz target for `nmap_core::osprobe::tcpreply`.
//
// The whole input is a TCP segment received from the target during OS detection, so the
// host chooses every byte — including the data offset that decides where options end and
// payload begins, and the RST payload whose CRC becomes a fingerprint attribute.
//
// Enforced: extraction is TOTAL for any segment, every attribute a test defines is
// populated (a silently-skipped slot would quietly lower every comparison's accuracy),
// `T` and `TG` stay mutually exclusive through finalization, and the result is
// deterministic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::osdb::model::FingerTest;
use nmap_core::osprobe::tcpreply::{
    ecn_test, finalize_ttl, ops_test, t_test, win_test, ProbeContext, TcpReply,
};

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
}

/// Attributes resolved later by `finalize_ttl`, so per-reply extraction may leave them
/// unset.
const DEFERRED: [&str; 1] = ["TG"];

/// T1 shares its reply with the SEQ probes, so its window and options are carried by the
/// WIN and OPS tests instead.
const T1_OMITS: [&str; 2] = ["W", "O"];

fn check_complete(test: &FingerTest, is_t1: bool) {
    for attr in test.id.attrs() {
        if DEFERRED.contains(attr) || (is_t1 && T1_OMITS.contains(attr)) {
            continue;
        }
        assert!(
            test.get(attr).is_some(),
            "{} attribute {attr} left unset",
            test.id.name()
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor { data, pos: 0 };

    let ctx = ProbeContext {
        sent_seq: c.u32(),
        sent_ack: c.u32(),
    };
    let n = c.u8();
    let reply = TcpReply {
        df: c.u8() & 1 == 1,
        ttl: c.u8(),
        window: c.u16(),
        seq: c.u32(),
        ack: c.u32(),
        flags: c.u8(),
        reserved: c.u8(),
        urgent_ptr: c.u16(),
        segment: c.data.get(c.pos..).unwrap_or_default().to_vec(),
    };

    // The fuzzer-chosen index, including the out-of-range ones the C asserts on.
    if let Some(t) = t_test(n, &reply, &ctx) {
        check_complete(&t, n == 1);
        assert_eq!(t_test(n, &reply, &ctx), Some(t.clone()), "not deterministic");

        // Finalization must set exactly one of T and TG, never both.
        for distance in [None, Some(0u8), Some(1), Some(30), Some(255)] {
            let mut f = t.clone();
            finalize_ttl(&mut f, distance);
            let has_t = f.get("T").is_some();
            let has_tg = f.get("TG").is_some();
            assert!(
                has_t != has_tg,
                "T and TG must be mutually exclusive (T={has_t}, TG={has_tg})"
            );
            // Idempotent enough not to corrupt itself if applied twice with the same
            // answer — the driver must not be able to double-count one observation.
            let mut again = f.clone();
            finalize_ttl(&mut again, distance);
            if distance.is_none() {
                assert_eq!(again.get("TG"), f.get("TG"));
            }
        }
    }

    for t in [1u8, 2, 7] {
        if let Some(test) = t_test(t, &reply, &ctx) {
            check_complete(&test, t == 1);
        }
    }

    let e = ecn_test(&reply);
    check_complete(&e, false);
    assert_eq!(ecn_test(&reply), e, "not deterministic");

    // The six-reply aggregates: all present, and one missing.
    let windows: Vec<Option<u16>> = (0..6).map(|_| Some(c.u16())).collect();
    if let Some(w) = win_test(&windows) {
        assert_eq!(w.values.len(), w.id.attrs().len());
        for v in &w.values {
            assert!(v.is_some(), "a complete WIN test must fill every slot");
        }
    }
    let mut partial = windows.clone();
    partial[0] = None;
    assert!(win_test(&partial).is_none(), "a partial WIN must be rejected");

    let segs: Vec<Option<Vec<u8>>> = (0..6).map(|_| Some(reply.segment.clone())).collect();
    if let Some(o) = ops_test(&segs) {
        assert_eq!(o.values.len(), o.id.attrs().len());
    }
});
