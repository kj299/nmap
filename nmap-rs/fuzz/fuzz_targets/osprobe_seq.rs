// cargo-fuzz target for `nmap_core::osprobe::seq::analyze_seq`.
//
// Every input is chosen by the target host: the ISNs, the IP IDs and the timestamps all
// come off the wire, and a host is free to make them adversarial — identical, wrapping,
// maximal, or arranged to drive the rate to zero or infinity.
//
// The C's exposure here is arithmetic rather than memory: a division by
// `responses - 2` (fine, gated on >= 4), a division by `time_usec_diffs[i]` (bumped to 1
// first), a division by `good_tcp_ipid_num - 1` in the shared-counter test, and three
// conversions of a `double` to an integer type where a negative or infinite value is
// undefined.
//
// Enforced: the analysis is TOTAL, every attribute it emits is well-formed uppercase hex
// or one of the fixed tokens, and it is deterministic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::osprobe::seq::{analyze_seq, SeqInputs, SeqReply, TsClass};

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
    fn u64(&mut self) -> u64 {
        u64::from(self.u32()) << 32 | u64::from(self.u32())
    }
}

/// Tokens the analysis may emit besides uppercase hex.
const TOKENS: [&str; 6] = ["I", "BI", "RI", "RD", "Z", "U"];

fn well_formed(value: &Option<String>) -> bool {
    let Some(v) = value else { return true };
    if TOKENS.contains(&v.as_str()) || v == "S" || v == "O" {
        return true;
    }
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor { data, pos: 0 };

    let n = usize::from(c.u8() % 8);
    let mut replies = Vec::new();
    for _ in 0..n {
        let present = c.u8() & 1 == 1;
        let reply = SeqReply {
            isn: c.u32(),
            ip_id: c.u16(),
            timestamp: c.u32(),
            sent_usec: c.u64(),
        };
        replies.push(present.then_some(reply));
    }

    fn ipids(c: &mut Cursor<'_>, count: usize) -> Vec<u16> {
        (0..count).map(|_| c.u16()).collect()
    }
    let n_tcp = usize::from(c.u8() % 8);
    let tcp_ipids = ipids(&mut c, n_tcp);
    let n_closed = usize::from(c.u8() % 8);
    let closed_tcp_ipids = ipids(&mut c, n_closed);
    let n_icmp = usize::from(c.u8() % 8);
    let icmp_ipids = ipids(&mut c, n_icmp);

    let ts_class = match c.u8() % 3 {
        0 => TsClass::Unknown,
        1 => TsClass::Zero,
        _ => TsClass::Unsupported,
    };

    let inputs = SeqInputs {
        replies,
        tcp_ipids,
        closed_tcp_ipids,
        icmp_ipids,
        ts_class,
        is_localhost: c.u8() & 1 == 1,
        scan_delay_ms: c.u64(),
    };

    let t = analyze_seq(&inputs);

    for (name, value) in [
        ("SP", &t.sp),
        ("GCD", &t.gcd),
        ("ISR", &t.isr),
        ("TI", &t.ti),
        ("CI", &t.ci),
        ("II", &t.ii),
        ("SS", &t.ss),
        ("TS", &t.ts),
    ] {
        assert!(well_formed(value), "{name} = {value:?} is not a legal value");
    }

    // The three ISN attributes are set together or not at all — the scorer would
    // otherwise weigh a partial SEQ test against a complete database entry.
    let isn_set = [&t.sp, &t.gcd, &t.isr].map(Option::is_some);
    assert!(
        isn_set.iter().all(|b| *b) || isn_set.iter().all(|b| !*b),
        "SP/GCD/ISR must be all-or-nothing: {isn_set:?}"
    );

    // Rendering into a FingerTest must keep the slot count the scorer expects.
    let ft = t.to_finger_test();
    assert_eq!(ft.values.len(), ft.id.attrs().len());

    // Deterministic: no clock, no randomness.
    assert_eq!(analyze_seq(&inputs), t);
});
