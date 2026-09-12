// cargo-fuzz target for `nmap_core::osprobe::demux` — attributing a captured OS-detection
// reply to the probe that caused it.
//
// This module is reached from exactly one place, `nmap_sys::osscan::record`, and until
// M7.1 nothing fuzzed it. That is how it was missed: the sweep that built the other 47
// targets walked `nmap_core`'s public parsers, and this one *looks* like an internal
// helper of the sys driver rather than a parser in its own right. It is a parser, and its
// own module doc says so plainly — "everything here is a pure function of the frame bytes,
// which are entirely attacker-chosen: a hostile target picks every field it echoes".
//
// Getting attribution wrong is worse than dropping the reply. A reply recorded against the
// wrong test silently produces a fingerprint that matches the wrong OS — there is no error
// path, just a confident wrong answer. So totality is necessary here but not sufficient,
// and this target asserts the two attribution invariants the module promises:
//
//   * a `Demuxed` is returned ONLY for a frame whose source address is the host we probed,
//     so another host's traffic on the shared capture can never enter this fingerprint;
//   * the probe named is one the battery actually sends — nothing is "forced into the
//     nearest slot" when it does not match.
//
// `tcp_timestamp` is fuzzed alongside it because it walks the TCP option list, and an
// option-length byte below 2 would not advance the cursor. The code carries an explicit
// guard for that; this target is what proves the guard is complete rather than merely
// present, since a non-terminating walk is a hang, not a panic, and no unit test would
// notice it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::osprobe::build::{OsProbe, ProbeParams};
use nmap_core::osprobe::demux::{demux, tcp_timestamp};

/// Little cursor over the fuzzer's bytes — same shape as `osprobe_build`'s, and for the
/// same reason: building a parameter struct is not worth pulling `arbitrary` into the
/// fuzz crate's dependency set.
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
    fn opt_port(&mut self) -> Option<u16> {
        let present = self.u8() & 1 == 1;
        let p = self.u16();
        present.then_some(p)
    }
}

/// The IPv4 source address of `frame`, read the same way `demux` reads it.
///
/// Deliberately a second, independent implementation rather than a call into the crate:
/// checking `demux`'s host filter against the very function `demux` uses to apply it would
/// assert nothing. Returns `None` when the frame is too short to carry one.
fn source_addr(frame: &[u8], eth_included: bool) -> Option<[u8; 4]> {
    let off = if eth_included { 14usize } else { 0 };
    // An Ethernet frame only carries IPv4 when its EtherType says so; `demux` resolves
    // this through `ipv4_offset`, which also rejects a non-4 IP version nibble.
    if eth_included && frame.get(12..14) != Some(&[0x08, 0x00]) {
        return None;
    }
    let ip = frame.get(off..)?;
    if ip.first()? >> 4 != 4 {
        return None;
    }
    let src = ip.get(12..16)?;
    Some([src[0], src[1], src[2], src[3]])
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
    // One more byte picks the datalink, so the fuzzer explores both the Ethernet-included
    // capture (the usual case) and the raw-IP one, rather than only whichever we hardcode.
    let eth_included = c.u8() & 1 == 1;
    let frame = data.get(c.pos..).unwrap_or(&[]);

    // Totality: no panic, no unbounded recursion, for any frame at any datalink.
    let first = demux(frame, eth_included, &params);

    // Deterministic: nothing here may depend on allocation addresses or iteration order.
    assert_eq!(
        first,
        demux(frame, eth_included, &params),
        "demux is not deterministic"
    );

    if let Some(d) = first {
        // --- attribution invariant 1: it is this host's reply ------------------------
        // A frame that matched must have come from the address we probed. If this ever
        // fails, one host's replies are being folded into another host's fingerprint on
        // the shared capture.
        assert_eq!(
            source_addr(frame, eth_included),
            Some(params.dst),
            "demux matched a frame that did not come from the probed host"
        );

        // --- attribution invariant 2: the probe is one we actually sent --------------
        // The battery is a fixed set. A reply is either attributable to a member of it or
        // it is not ours; there is no nearest-slot fallback.
        assert!(
            OsProbe::all().contains(&d.probe),
            "demux named {:?}, which the battery never sends",
            d.probe
        );

        // The U1 probe is only ever answered by an ICMP error, and the IE probes only by
        // an echo reply. A TCP reply attributed to either would mean the quoted-datagram
        // walk crossed into the wrong arm.
        match d.probe {
            OsProbe::U1 => assert!(
                matches!(d.reply, nmap_core::osprobe::demux::ProbeReply::UdpError(_)),
                "U1 attributed a non-ICMP-error reply"
            ),
            OsProbe::Ie(_) => assert!(
                matches!(d.reply, nmap_core::osprobe::demux::ProbeReply::Echo(_)),
                "IE attributed a non-echo reply"
            ),
            _ => assert!(
                matches!(d.reply, nmap_core::osprobe::demux::ProbeReply::Tcp(_)),
                "{:?} attributed a non-TCP reply",
                d.probe
            ),
        }
    }

    // The TCP option walk, driven directly as well as through `demux`. Passing the whole
    // remaining buffer as a "segment" is deliberate: the option list is the part an
    // attacker shapes most freely, and reaching it through `demux` first requires getting
    // a dozen earlier fields right, which wastes the fuzzer's budget on scaffolding.
    let ts = tcp_timestamp(frame);
    assert_eq!(
        ts,
        tcp_timestamp(frame),
        "tcp_timestamp is not deterministic"
    );
});
