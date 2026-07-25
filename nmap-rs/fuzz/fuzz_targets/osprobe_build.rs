// cargo-fuzz target for `nmap_core::osprobe::build`.
//
// The probe parameters are not attacker-controlled in the usual sense, but several are
// derived from the *target's* observed behaviour — the open and closed ports come from a
// prior scan of the host, so a host that steers a scan toward unusual port numbers steers
// these inputs. The C reacts to out-of-range probe indices with `assert()` (process
// abort) and to missing ports with a silent early `return`, so the interesting contract
// is that neither is possible here.
//
// Enforced: building is TOTAL for every parameter combination and every probe index; a
// success always yields a well-formed IPv4 packet whose length agrees with its header;
// and building is deterministic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::headers::ipv4::Ipv4Header;
use nmap_core::osprobe::build::{build_probe, source_port, OsProbe, ProbeParams};

/// Little cursor over the fuzzer's bytes — avoids pulling `arbitrary` into the fuzz
/// crate's dependency set just to build a parameter struct.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
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
    fn opt_port(&mut self) -> Option<u16> {
        let present = self.u8() & 1 == 1;
        let p = self.u16();
        present.then_some(p)
    }
}

fn probe_of(kind: u8, index: u8) -> OsProbe {
    match kind % 6 {
        0 => OsProbe::Seq(index),
        1 => OsProbe::Ops(index),
        2 => OsProbe::Ecn,
        3 => OsProbe::T(index),
        4 => OsProbe::Ie(index),
        _ => OsProbe::U1,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor { data, pos: 0 };
    let params = ProbeParams {
        src: [c.u8(), c.u8(), c.u8(), c.u8()],
        dst: [c.u8(), c.u8(), c.u8(), c.u8()],
        ttl: c.u8(),
        udp_ttl: c.u8(),
        ip_id: c.u16(),
        tcp_port_base: c.u16(),
        udp_port_base: c.u16(),
        tcp_seq_base: c.u32(),
        tcp_ack: c.u32(),
        icmp_echo_id: c.u16(),
        icmp_echo_seq: c.u16(),
        open_tcp_port: c.opt_port(),
        closed_tcp_port: c.opt_port(),
        closed_udp_port: c.opt_port(),
    };
    let (kind, index) = (c.u8(), c.u8());


    // The fuzzer-chosen probe, including indices the C would `assert()` on.
    let chosen = probe_of(kind, index);
    let mut probes = vec![chosen];
    probes.extend(OsProbe::all());

    for probe in probes {
        let _ = source_port(probe, &params);

        let Ok(bytes) = build_probe(probe, &params) else {
            continue;
        };

        // A built probe must be a parseable IPv4 packet whose stated length matches the
        // buffer we produced — a mismatch would be silently truncated on the wire.
        let ip = Ipv4Header::parse(&bytes).expect("a built probe must parse as IPv4");
        assert_eq!(
            usize::from(ip.total_length),
            bytes.len(),
            "{probe:?}: IP total length disagrees with the buffer"
        );
        assert_eq!(ip.src, params.src);
        assert_eq!(ip.dst, params.dst);
        assert!(matches!(ip.protocol, 1 | 6 | 17), "{probe:?}: bad protocol");
        assert!(usize::from(ip.ihl) * 4 <= bytes.len());

        // Deterministic: no clock, no randomness.
        let again = build_probe(probe, &params).expect("second build must also succeed");
        assert_eq!(bytes, again, "{probe:?}: build is not deterministic");
    }
});
