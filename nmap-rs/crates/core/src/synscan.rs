//! SYN-scan probe encoding and response matching — the pure `core` half of the
//! `-sS` scan. Ports the SYN-specific pieces of nmap's `scan_engine_raw.cc`: the
//! per-attempt source-port / sequence encoding (`sport_encode` / `seq32_encode`),
//! the SYN probe construction, and `tcp_probe_match` (deciding whether a captured
//! packet answers an outstanding probe, and to what port state).
//!
//! Everything here is a **total function of its inputs** — no clock, no I/O, no
//! randomness. The driver ([`crate::engine::HostScheduler`] + the `sys` loop) owns
//! the randomness (the per-scan `seqmask` / `base_port` / per-probe `ipid`) and the
//! clock, and feeds them in. That keeps this module Miri-checkable and lets
//! [`match_syn_response`] be fuzzed directly against hostile captured frames.
//!
//! ## Response matching (how a reply is tied back to its probe)
//!
//! nmap varies the TCP **source port** per retransmission (`sport_encode(base,
//! tryno) = base + tryno`) and mirrors the attempt number into the 32-bit
//! **sequence** (`seq32_encode`), which the target reflects in its ACK
//! (`ack == our_seq + 1`). We recover the attempt from the reply's *destination*
//! port (= the source port we sent from) and, when the reply ACKs, confirm it
//! reflects our sequence. The scanned port is simply the reply's TCP *source* port.
//!
//! The driver's pcap BPF filter is scoped to `tcp and dst portrange
//! base..base+max_tryno`, so a reply's destination port lands in our encoded range
//! while our *own* outgoing SYN (destination = the scanned service port) never does.
//! That excludes the loopback self-probe at the kernel — the role nmap's ipid
//! self-probe guard (`scan_engine_raw.cc:1675`) plays — so this matcher needs no
//! self-probe special-case.
//!
//! ## Scope / divergences (ledgered in `DIVERGENCES.md`)
//!
//! * `synscan-icmp-match-deferred` — the C also maps an ICMP unreachable/time-exceeded
//!   whose embedded packet is one of our probes to `PORT_FILTERED`
//!   (`scan_engine_raw.cc:1888`). This first slice matches TCP replies (open/closed)
//!   and leaves ICMP-derived *filtered* to the no-response default; wiring the
//!   embedded-probe ICMP match is a follow-up (`classify_icmp` already exists).
//! * Inherits `validate-ipv4-only-for-now` from [`crate::recv_validate`].

use crate::build::{build_tcp_raw, BuildError, Ipv4Spec};
use crate::classify::{classify_tcp, PortState, ScanType, TH_ACK};
use crate::packet_parser::{parse_packet, Header};
use crate::recv_validate::validate_packet;

/// TCP flag for a bare SYN probe.
const TH_SYN: u8 = 0x02;
/// IP protocol number for TCP (the only L4 this matcher resolves; see scope note).
const IPPROTO_TCP: u8 = 6;
/// Minimum bytes of a TCP header we must read (ports/seq/ack/flags/window).
const TCP_MIN: usize = 20;

/// The SYN probe's TCP options: MSS = 1460 (`\x02\x04\x05\xb4`), the same
/// `TCP_SYN_PROBE_OPTIONS` nmap attaches to every SYN-bearing probe
/// (`scan_engine_raw.cc:1212`, `nmap.h`).
pub const TCP_SYN_PROBE_OPTIONS: [u8; 4] = [0x02, 0x04, 0x05, 0xb4];

/// The TCP window a SYN probe advertises. nmap's `build_tcp` rewrites a `0` window to
/// `1024`; this port carries no such magic (`build-explicit-fields-no-magic`), so the
/// driver passes the concrete value nmap would have used.
pub const SYN_WINDOW: u16 = 1024;

/// Encode the per-attempt TCP source port: `base_port + tryno`
/// (`scan_engine_raw.cc:265` `sport_encode`). Each retransmission uses a distinct
/// source port so a late reply can be tied to the exact attempt.
#[must_use]
pub fn sport_encode(base_port: u16, tryno: u32) -> u16 {
    // tryno is a small attempt counter (<= max retransmissions, ~11); take its low
    // 16 bits like the C's `tryno.opaque` and add with wraparound.
    let low = u16::try_from(tryno & 0xFFFF).unwrap_or(0);
    base_port.wrapping_add(low)
}

/// Encode the 32-bit TCP sequence carrying the attempt number, mirrored into both
/// halves and XOR-masked with the per-scan random `seqmask`
/// (`scan_engine_raw.cc:229` `seq32_encode`). The target reflects `seq + 1` in its
/// ACK, which [`seq32_decode`] reverses.
#[must_use]
pub fn seq32_encode(seqmask: u32, tryno: u32) -> u32 {
    let nfo = tryno & 0xFFFF;
    (nfo.wrapping_shl(16).wrapping_add(nfo)) ^ seqmask
}

/// Reverse [`seq32_encode`]: recover the attempt number from a (masked) sequence,
/// returning `None` if the two 16-bit halves disagree — i.e. this is not a value we
/// produced (`scan_engine_raw.cc:245` `seq32_decode`).
#[must_use]
pub fn seq32_decode(seqmask: u32, seq: u32) -> Option<u32> {
    let v = seq ^ seqmask;
    let hi = v >> 16;
    let lo = v & 0xFFFF;
    if hi == lo {
        Some(hi)
    } else {
        None
    }
}

/// Build a complete raw SYN probe packet for `(dport, tryno)`.
///
/// The IPv4 fields (src/dst/ttl/ipid/tos) come from `spec`; the caller supplies the
/// per-scan `base_port` and `seqmask` and the per-probe `tryno`. Sets `flags = SYN`,
/// `window = 1024`, and the MSS option — the exact wire shape of an nmap `-sS` probe.
///
/// # Errors
/// Propagates [`BuildError`] from [`build_tcp_raw`] (only reachable via a malformed
/// `spec.options`; the fixed SYN options here are always well-formed).
pub fn build_syn_probe(
    spec: &Ipv4Spec,
    base_port: u16,
    dport: u16,
    tryno: u32,
    seqmask: u32,
) -> Result<Vec<u8>, BuildError> {
    let sport = sport_encode(base_port, tryno);
    let seq = seq32_encode(seqmask, tryno);
    build_tcp_raw(
        spec,
        sport,
        dport,
        seq,
        0, // ack
        0, // reserved
        TH_SYN,
        SYN_WINDOW,
        0, // urgent pointer
        &TCP_SYN_PROBE_OPTIONS,
        &[],
    )
}

/// The per-scan constants a captured reply is matched against.
#[derive(Debug, Clone, Copy)]
pub struct MatchCtx {
    /// Base TCP source port (the `tryno == 0` source port).
    pub base_port: u16,
    /// Per-scan random sequence mask.
    pub seqmask: u32,
    /// Highest attempt number in flight — replies decoding past this are not ours.
    pub max_tryno: u32,
}

/// A captured packet matched to an outstanding SYN probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynReply {
    /// The scanned port that answered (the reply's TCP source port).
    pub port: u16,
    /// Which attempt this reply answers (for RTT accounting / retransmit bookkeeping).
    pub tryno: u32,
    /// The port state the reply implies (`Open` on SYN/ACK or bare SYN, `Closed` on RST).
    pub state: PortState,
}

/// Decide whether a captured frame answers one of our SYN probes, and to what state.
///
/// `eth_included` is `true` when the capture delivers a link-layer header (pcap on a
/// loopback/Ethernet device) — the frame is walked to the IPv4 layer either way.
/// Returns `None` for anything that is not a well-formed IPv4/TCP reply decoding to
/// an in-range attempt (malformed, fragment, IPv6, ICMP, or a stray packet). Total on
/// all input — the primary fuzz target of the receive path.
#[must_use]
pub fn match_syn_response(frame: &[u8], eth_included: bool, ctx: &MatchCtx) -> Option<SynReply> {
    // Locate the IPv4 header within the (possibly link-framed) capture.
    let ip_off = ipv4_offset(frame, eth_included)?;
    let ip = frame.get(ip_off..)?;

    // Validate the IPv4 packet as untrusted input (bounds, fragment, TCP options).
    let v = validate_packet(ip).ok()?;
    if v.proto != IPPROTO_TCP {
        return None; // ICMP-derived filtered is deferred (see scope note).
    }

    // The TCP header begins at `data_offset`; `validate_packet` guarantees >= 20
    // bytes of it are present for a TCP packet.
    let tcp = ip.get(v.data_offset..)?;
    if tcp.len() < TCP_MIN {
        return None;
    }
    let resp_sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let resp_dport = u16::from_be_bytes([tcp[2], tcp[3]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let flags = tcp[13];
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);

    // Recover the attempt from our encoded source port (the reply's destination).
    let tryno = u32::from(resp_dport.wrapping_sub(ctx.base_port));
    if tryno > ctx.max_tryno {
        return None;
    }

    // When the reply ACKs (SYN/ACK, RST/ACK), confirm it reflects our sequence
    // (`ack == our_seq + 1`); a bare SYN (split handshake) carries no ACK to check.
    if flags & TH_ACK != 0 {
        match seq32_decode(ctx.seqmask, ack.wrapping_sub(1)) {
            Some(t) if t == tryno => {}
            _ => return None,
        }
    }

    let state = classify_tcp(ScanType::Syn, flags, window)?;
    Some(SynReply {
        port: resp_sport,
        tryno,
        state,
    })
}

/// Byte offset of the IPv4 header inside a captured frame, walking the parsed layer
/// stack and summing the lengths of any link/lower headers before it. `None` if the
/// frame has no IPv4 layer.
fn ipv4_offset(frame: &[u8], eth_included: bool) -> Option<usize> {
    let mut off = 0usize;
    for h in parse_packet(frame, eth_included) {
        if matches!(h, Header::Ipv4(_)) {
            return Some(off);
        }
        off = off.checked_add(h.len())?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sport_encode_varies_per_attempt() {
        assert_eq!(sport_encode(40000, 0), 40000);
        assert_eq!(sport_encode(40000, 1), 40001);
        assert_eq!(sport_encode(40000, 5), 40005);
    }

    #[test]
    fn seq32_round_trips_the_tryno() {
        let seqmask = 0xDEAD_BEEF;
        for tryno in 0..=11u32 {
            let seq = seq32_encode(seqmask, tryno);
            assert_eq!(seq32_decode(seqmask, seq), Some(tryno));
        }
    }

    #[test]
    fn seq32_decode_rejects_a_foreign_sequence() {
        // A sequence whose halves disagree after unmasking is not one we produced.
        let seqmask = 0x0000_0000;
        assert_eq!(seq32_decode(seqmask, 0x0001_0002), None);
    }

    #[test]
    fn build_syn_probe_is_a_parseable_syn() {
        let spec = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 0x1234);
        let pkt = build_syn_probe(&spec, 40000, 80, 0, 0xABCD_1234).unwrap();
        // Parse it back (raw IP, no link header) and confirm IPv4 + TCP with SYN.
        let layers = parse_packet(&pkt, false);
        assert!(matches!(layers.first(), Some(Header::Ipv4(_))));
        let v = validate_packet(&pkt).unwrap();
        assert_eq!(v.proto, IPPROTO_TCP);
        let tcp = &pkt[v.data_offset..];
        assert_eq!(tcp[13] & TH_SYN, TH_SYN);
        assert_eq!(tcp[13] & TH_ACK, 0);
        // MSS option present.
        assert_eq!(&tcp[20..24], &TCP_SYN_PROBE_OPTIONS);
    }

    /// Build a synthetic reply frame: a 14-byte Ethernet header + an IPv4/TCP segment
    /// from the target back to us. `sport`/`dport` are the reply's ports (source =
    /// scanned port, dest = our encoded source port); `ack` reflects our sequence.
    fn reply_frame(sport: u16, dport: u16, flags: u8, ack: u32) -> Vec<u8> {
        let spec = Ipv4Spec::new([10, 0, 0, 2], [10, 0, 0, 1], 64, 0x9999);
        let seg =
            build_tcp_raw(&spec, sport, dport, 12345, ack, 0, flags, 8192, 0, &[], &[]).unwrap();
        let mut frame = vec![0u8; 14]; // dummy Ethernet header
        frame[12] = 0x08; // ethertype IPv4
        frame[13] = 0x00;
        frame.extend_from_slice(&seg);
        frame
    }

    fn ctx() -> MatchCtx {
        MatchCtx {
            base_port: 40000,
            seqmask: 0xABCD_1234,
            max_tryno: 11,
        }
    }

    #[test]
    fn matches_synack_as_open() {
        // Probe was tryno 0: our seq = seq32_encode(mask, 0); reply acks seq+1 and
        // comes back to our source port (base + 0).
        let our_seq = seq32_encode(ctx().seqmask, 0);
        let frame = reply_frame(
            80,
            sport_encode(40000, 0),
            TH_SYN | TH_ACK,
            our_seq.wrapping_add(1),
        );
        let m = match_syn_response(&frame, true, &ctx()).unwrap();
        assert_eq!(m.port, 80);
        assert_eq!(m.tryno, 0);
        assert_eq!(m.state, PortState::Open);
    }

    #[test]
    fn matches_rst_as_closed() {
        const TH_RST: u8 = 0x04;
        let our_seq = seq32_encode(ctx().seqmask, 2);
        let frame = reply_frame(
            81,
            sport_encode(40000, 2),
            TH_RST | TH_ACK,
            our_seq.wrapping_add(1),
        );
        let m = match_syn_response(&frame, true, &ctx()).unwrap();
        assert_eq!(m.port, 81);
        assert_eq!(m.tryno, 2);
        assert_eq!(m.state, PortState::Closed);
    }

    #[test]
    fn matches_bare_syn_split_handshake_as_open() {
        // A bare SYN reply (no ACK) — split-handshake open; no seq reflection to check.
        let frame = reply_frame(82, sport_encode(40000, 1), TH_SYN, 0);
        let m = match_syn_response(&frame, true, &ctx()).unwrap();
        assert_eq!(m.port, 82);
        assert_eq!(m.state, PortState::Open);
    }

    #[test]
    fn rejects_synack_with_wrong_sequence_reflection() {
        // Right ports, but the ACK does not reflect our sequence → not our probe.
        let frame = reply_frame(80, sport_encode(40000, 0), TH_SYN | TH_ACK, 0xFFFF_FFFF);
        assert!(match_syn_response(&frame, true, &ctx()).is_none());
    }

    #[test]
    fn rejects_reply_to_a_port_outside_our_range() {
        // Destination port far outside [base, base+max_tryno] → decodes past max.
        let frame = reply_frame(80, 50000, TH_SYN | TH_ACK, 0);
        assert!(match_syn_response(&frame, true, &ctx()).is_none());
    }

    #[test]
    fn ignores_non_ip_and_truncated_frames() {
        assert!(match_syn_response(&[], true, &ctx()).is_none());
        assert!(match_syn_response(&[0u8; 8], true, &ctx()).is_none());
        // An Ethernet header with no IP payload.
        assert!(match_syn_response(&[0u8; 14], true, &ctx()).is_none());
    }
}
