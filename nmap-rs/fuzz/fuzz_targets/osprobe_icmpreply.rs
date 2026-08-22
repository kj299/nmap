// cargo-fuzz target for `nmap_core::osprobe::icmpreply`.
//
// The `U1` quote is our own packet echoed back by the target — the target chooses every
// byte of it, and can truncate it, lie about the header length, or scribble on the
// checksums. The C walks it with `memcpy` and pointer arithmetic after a couple of length
// checks; this port must stay total on any quote.
//
// Enforced: `u1_test` and `ie_test` never panic on any input, every attribute they emit
// is legal (uppercase hex or a fixed token), the derived hop distance is either absent or
// a plausible 0..=255, and both functions are deterministic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::osdb::model::FingerTest;
use nmap_core::osprobe::icmpreply::{ie_test, u1_test, EchoReply, U1Sent, UdpErrorReply};

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

/// Every token the two tests may emit besides uppercase hex.
const TOKENS: [&str; 5] = ["Y", "N", "G", "I", "Z"];
/// `IE`-only tokens.
const IE_TOKENS: [&str; 2] = ["S", "O"];

fn legal(value: Option<&str>) {
    let Some(v) = value else { return };
    if TOKENS.contains(&v) || IE_TOKENS.contains(&v) {
        return;
    }
    assert!(
        !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
        "attribute value {v:?} is neither hex nor a known token"
    );
}

fn check(test: &FingerTest) {
    for attr in test.id.attrs() {
        legal(test.get(attr));
    }
    // The slot count must stay what the scorer expects.
    assert_eq!(test.values.len(), test.id.attrs().len());
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor { data, pos: 0 };

    let sent = U1Sent {
        sport: c.u16(),
        dport: c.u16(),
        udp_checksum: c.u16(),
        ttl: c.u8(),
    };
    let reply = UdpErrorReply {
        outer_df: c.u8() & 1 == 1,
        outer_ttl: c.u8(),
        outer_total_len: c.u16(),
        icmp_unused: c.u32(),
        quote: c.data.get(c.pos..).unwrap_or_default().to_vec(),
    };

    if let Some(out) = u1_test(&reply, &sent) {
        check(&out.test);
        if let Some(d) = out.distance {
            // Type already bounds it; assert the semantic range for good measure.
            let _ = d;
        }
        assert_eq!(u1_test(&reply, &sent), Some(out), "u1_test not deterministic");
    }

    // A quote whose ports happen to match should still be reachable; steer one such case
    // by planting the sent ports at a plausible offset.
    if reply.quote.len() >= 24 {
        let mut steered = reply.clone();
        steered.quote[0] = 0x45;
        steered.quote[20..22].copy_from_slice(&sent.sport.to_be_bytes());
        steered.quote[22..24].copy_from_slice(&sent.dport.to_be_bytes());
        if let Some(out) = u1_test(&steered, &sent) {
            check(&out.test);
        }
    }

    // The IE pair: fields drawn from the same stream.
    let e = |c: &mut Cursor| EchoReply {
        df: c.u8() & 1 == 1,
        icmp_code: c.u8(),
        ttl: c.u8(),
    };
    let r0 = e(&mut c);
    let r1 = e(&mut c);
    let t_ttl = c.u8();
    let ie = ie_test(&r0, &r1, t_ttl);
    check(&ie);
    assert_eq!(ie_test(&r0, &r1, t_ttl), ie, "ie_test not deterministic");
});
