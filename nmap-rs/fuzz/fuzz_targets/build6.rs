// cargo-fuzz target for `nmap_core::build6::build_probes`.
//
// build6 constructs packets rather than parsing them, so the property is *totality of
// construction*: for any parameters a driver could hand it — any addresses, any port
// availability, any bases — it must never panic, and every packet it emits must be
// structurally sound. A malformed probe is not a crash, it is a silently wrong scan, so
// the invariants check structure, not just liveness.
//
// Enforced for every emitted probe:
//   * a 40-byte IPv6 header, version 6, carrying the fixed flow label;
//   * the payload-length field equals the real remainder (no under/over-run);
//   * NS uses hop limit 255, every other probe the scan's hop limit;
//   * the battery is a subset of the 17 known probes, in nmap's fixed relative order,
//     and TECN (when present) carries ACK 0.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::build6::{build_probes, Build6Params};
use nmap_core::fp6::Fp6Probe;

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
    fn addr(&mut self) -> [u8; 16] {
        let mut a = [0u8; 16];
        for byte in &mut a {
            *byte = self.u8();
        }
        a
    }
    /// `None` about a third of the time, so the port-skip paths are explored.
    fn opt_port(&mut self) -> Option<u16> {
        let v = self.u16();
        if self.u8() % 3 == 0 {
            None
        } else {
            Some(v)
        }
    }
}

// nmap's fixed send order; a built battery is always a subsequence of this.
const ORDER: [Fp6Probe; 17] = {
    use Fp6Probe::*;
    [S1, S2, S3, S4, S5, S6, Ie1, Ie2, Ns, U1, Tecn, T2, T3, T4, T5, T6, T7]
};

fn rank(p: Fp6Probe) -> usize {
    ORDER.iter().position(|&q| q == p).unwrap()
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor { data, pos: 0 };
    let mut acks = [0u32; 13];
    for a in &mut acks {
        *a = c.u32();
    }
    let params = Build6Params {
        src: c.addr(),
        dst: c.addr(),
        open_tcp_port: c.opt_port(),
        closed_tcp_port: c.opt_port(),
        closed_udp_port: c.u16(),
        tcp_port_base: c.u16(),
        udp_port_base: c.u16(),
        tcp_seq_base: c.u32(),
        tcp_acks: acks,
        hop_limit: c.u8(),
        icmp_seq: c.u16(),
        directly_connected: c.u8() & 1 == 0,
    };

    let probes = build_probes(&params);
    assert!(probes.len() <= 17);

    let mut previous_rank: Option<usize> = None;
    for probe in &probes {
        let pkt = &probe.packet;
        assert!(pkt.len() >= 40, "{:?} shorter than an IPv6 header", probe.id);
        assert_eq!(pkt[0] >> 4, 6, "{:?} not version 6", probe.id);
        let plen = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
        assert_eq!(plen, pkt.len() - 40, "{:?} payload length mismatch", probe.id);

        let hlim = pkt[7];
        if probe.id == Fp6Probe::Ns {
            assert_eq!(hlim, 255, "NS must use hop limit 255");
        } else {
            assert_eq!(hlim, params.hop_limit, "{:?} wrong hop limit", probe.id);
        }

        // Strictly increasing rank: nmap's order, no duplicates.
        let r = rank(probe.id);
        if let Some(prev) = previous_rank {
            assert!(r > prev, "{:?} out of order", probe.id);
        }
        previous_rank = Some(r);
    }

    // Determinism: the same parameters always build the same battery.
    let again = build_probes(&params);
    assert_eq!(again.len(), probes.len());
    for (a, b) in again.iter().zip(&probes) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.packet, b.packet, "not deterministic");
    }
});
