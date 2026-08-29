// cargo-fuzz target for `nmap_core::fp6::vectorize`.
//
// vectorize turns a set of attacker-influenced probe responses into the 695-element
// feature vector the IPv6 classifier consumes. It must be TOTAL — any bytes for any
// probe, any distance, produce a full-length vector and never panic (in particular the
// 17th-TCP-option write and the option-block indices must stay inside the vector) — and
// DETERMINISTIC. A responder chooses these packets, so this is an untrusted-input edge.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::fp6::{vectorize, DistMethod, Fp6Observation, Fp6Probe, Fp6Response, N_FEATURE};

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
    fn u32(&mut self) -> u32 {
        u32::from(self.u8()) << 24
            | u32::from(self.u8()) << 16
            | u32::from(self.u8()) << 8
            | u32::from(self.u8())
    }
    fn take(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.u8()).collect()
    }
}

const PROBES: [Fp6Probe; 17] = [
    Fp6Probe::S1,
    Fp6Probe::S2,
    Fp6Probe::S3,
    Fp6Probe::S4,
    Fp6Probe::S5,
    Fp6Probe::S6,
    Fp6Probe::Ie1,
    Fp6Probe::Ie2,
    Fp6Probe::Ns,
    Fp6Probe::U1,
    Fp6Probe::Tecn,
    Fp6Probe::T2,
    Fp6Probe::T3,
    Fp6Probe::T4,
    Fp6Probe::T5,
    Fp6Probe::T6,
    Fp6Probe::T7,
];

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor { data, pos: 0 };

    let distance = c.u32() as i32;
    let method = match c.u8() % 5 {
        0 => DistMethod::None,
        1 => DistMethod::Localhost,
        2 => DistMethod::Direct,
        3 => DistMethod::Icmp,
        _ => DistMethod::Traceroute,
    };
    let mut obs = Fp6Observation::new(distance, method);

    // Up to one response per probe. A leading bitmask picks which probes respond, then
    // each gets a length-prefixed packet body (never zero length — that is the C's
    // abort case and a Rust-only degrade covered by a unit test, not this invariant).
    let present = c.u32();
    for (i, &probe) in PROBES.iter().enumerate() {
        if present & (1 << i) == 0 {
            continue;
        }
        let len = usize::from(c.u8()) + 1;
        let packet = c.take(len);
        obs.insert(
            probe,
            Fp6Response {
                packet,
                sent_sec: i64::from(c.u32()),
                sent_usec: i64::from(c.u32() % 1_000_000),
            },
        );
    }

    let v = vectorize(&obs);
    assert_eq!(v.len(), N_FEATURE, "wrong feature-vector length");
    // Determinism: the same observation always yields the same vector.
    let again = vectorize(&obs);
    assert_eq!(
        v.iter().map(|x| x.to_bits()).collect::<Vec<_>>(),
        again.iter().map(|x| x.to_bits()).collect::<Vec<_>>(),
        "vectorize is not deterministic"
    );
});
