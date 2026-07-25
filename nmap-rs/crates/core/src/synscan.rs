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
//! Two kinds of answer are matched. A **TCP** reply gives open (SYN/ACK) or closed
//! (RST). An **ICMP** type-3/11 error quoting our probe means *filtered* somewhere on the
//! path; because the quote carries our original packet, the encoded sequence is
//! recoverable there and is verified. [`match_tcp_icmp_error`] implements that arm and is
//! shared with the stateless flag scans, whose quote-matching rules are identical.
//!
//! ## Scope / divergences (ledgered in `DIVERGENCES.md`)
//!
//! * Inherits `validate-ipv4-only-for-now` from [`crate::recv_validate`].

use crate::build::{build_tcp_raw, BuildError, Ipv4Spec};
use crate::classify::{classify_icmp, classify_tcp, PortState, ScanType, TH_ACK};
use crate::icmp_quote::{icmp_to_reason, ipv4_offset, parse_icmp_error, IPPROTO_TCP as QUOTED_TCP};
use crate::model::Reason;
use crate::recv_validate::validate_packet;

/// TCP flag for a bare SYN probe.
const TH_SYN: u8 = 0x02;
/// IP protocol number for TCP — a direct reply to our probe.
const IPPROTO_TCP: u8 = 6;
/// IP protocol number for ICMP — an error quoting our probe.
const IPPROTO_ICMP: u8 = 1;
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
    /// Our own source address. An ICMP error only concerns us if the packet it quotes was
    /// sent from here — the C's "If it didn't come from us, we don't care."
    pub our_ip: [u8; 4],
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
    /// The host that answered (the reply's IPv4 source address), for multi-host demux.
    pub src_ip: [u8; 4],
    /// The scanned port that answered (the reply's TCP source port).
    pub port: u16,
    /// Which attempt this reply answers (for RTT accounting / retransmit bookkeeping).
    pub tryno: u32,
    /// The port state the reply implies (`Open` on SYN/ACK or bare SYN, `Closed` on RST).
    pub state: PortState,
    /// Why: the reply kind that decided it, so the driver need not re-derive it from the
    /// state (an ICMP-derived *filtered* reports the specific unreachable code).
    pub reason: Reason,
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
    if v.proto == IPPROTO_ICMP {
        // An ICMP error quoting our SYN: the port is filtered somewhere on the path.
        let m = match_tcp_icmp_error(frame, eth_included, ScanType::Syn, ctx)?;
        return Some(SynReply {
            src_ip: m.src_ip,
            port: m.port,
            tryno: m.tryno,
            state: m.state,
            reason: m.reason,
        });
    }
    if v.proto != IPPROTO_TCP {
        return None;
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

    let src_ip: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
    let state = classify_tcp(ScanType::Syn, flags, window)?;
    let reason = match state {
        PortState::Open => Reason::ConnAccept, // "syn-ack"
        PortState::Closed => Reason::Reset,
        _ => Reason::Unknown,
    };
    Some(SynReply {
        src_ip,
        port: resp_sport,
        tryno,
        state,
        reason,
    })
}

/// An ICMP error matched to one of our outstanding **TCP** probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpIcmpMatch {
    /// The scanned host the verdict belongs to: the destination of the quoted probe.
    pub src_ip: [u8; 4],
    /// The scanned port, from the quoted probe's destination port.
    pub port: u16,
    /// Which attempt the quoted probe was.
    pub tryno: u32,
    /// The state the error implies for this scan type (filtered, for every TCP scan).
    pub state: PortState,
    /// The specific ICMP reason nmap reports (`host-unreach`, `admin-prohibited`, ...).
    pub reason: Reason,
}

/// Match an ICMP error that quotes one of our TCP probes — shared by the SYN scan and
/// every stateless flag scan, which differ only in the [`ScanType`] passed to
/// [`classify_icmp`].
///
/// Ports the ICMP arm of nmap's `scan_engine_raw.cc` probe search:
///   * the quote must be TCP, and its **source must be us** ("If it didn't come from us,
///     we don't care");
///   * the attempt comes from the quoted source port, and — unlike a RST, which reflects
///     no sequence of ours — the quote *contains our original packet*, so the encoded
///     sequence is verifiable and is verified (the C compares `th_seq` to
///     `probe->tcpseq()`);
///   * the verdict is attributed to the **quoted destination**, so an error relayed by a
///     router still lands on the host we probed.
///
/// Returns `None` for anything that is not an ICMP error about one of our probes, or
/// whose type/code carries no verdict. Total on all input.
#[must_use]
pub fn match_tcp_icmp_error(
    frame: &[u8],
    eth_included: bool,
    scan: ScanType,
    ctx: &MatchCtx,
) -> Option<TcpIcmpMatch> {
    let quote = parse_icmp_error(frame, eth_included)?;
    if quote.proto != QUOTED_TCP || quote.quoted_src != ctx.our_ip {
        return None;
    }
    let tryno = u32::from(quote.sport.wrapping_sub(ctx.base_port));
    if tryno > ctx.max_tryno {
        return None;
    }
    // Our own packet is quoted back, so our encoded sequence must be there verbatim.
    if quote.seq != Some(seq32_encode(ctx.seqmask, tryno)) {
        return None;
    }
    let state = classify_icmp(scan, quote.icmp_type, quote.icmp_code, quote.from_target())?;
    Some(TcpIcmpMatch {
        src_ip: quote.quoted_dst,
        port: quote.dport,
        tryno,
        state,
        reason: icmp_to_reason(quote.icmp_type, quote.icmp_code),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_parser::{parse_packet, Header};

    /// Our address in these tests; replies and quotes are built around it.
    const OUR_IP: [u8; 4] = [10, 0, 0, 1];
    /// The scanned host.
    const TARGET: [u8; 4] = [10, 0, 0, 2];
    /// An intermediate router, which is not the target.
    const ROUTER: [u8; 4] = [192, 168, 0, 1];

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
            our_ip: OUR_IP,
            base_port: 40000,
            seqmask: 0xABCD_1234,
            max_tryno: 11,
        }
    }

    /// An ICMP `type`/`code` error from `sender`, quoting a SYN probe we sent from
    /// `quoted_src` to `quoted_dst`'s `dport` as attempt `tryno`.
    fn icmp_quoting_our_syn(
        sender: [u8; 4],
        icmp_type: u8,
        icmp_code: u8,
        quoted_src: [u8; 4],
        quoted_dst: [u8; 4],
        dport: u16,
        tryno: u32,
    ) -> Vec<u8> {
        let spec = Ipv4Spec::new(quoted_src, quoted_dst, 64, 0x1234);
        let probe = build_syn_probe(&spec, 40000, dport, tryno, ctx().seqmask).unwrap();
        let mut icmp = vec![icmp_type, icmp_code, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&probe);
        let mut ip = vec![
            0x45,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            64,
            IPPROTO_ICMP,
            0,
            0,
            sender[0],
            sender[1],
            sender[2],
            sender[3],
            OUR_IP[0],
            OUR_IP[1],
            OUR_IP[2],
            OUR_IP[3],
        ];
        let total = u16::try_from(ip.len().saturating_add(icmp.len())).unwrap();
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&icmp);
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f.extend_from_slice(&ip);
        f
    }

    #[test]
    fn icmp_error_quoting_our_syn_is_filtered() {
        // Every unreachable code, and time-exceeded, read as filtered for a SYN scan.
        for (t, c) in [
            (3u8, 0u8),
            (3, 1),
            (3, 2),
            (3, 3),
            (3, 9),
            (3, 10),
            (3, 13),
            (11, 0),
        ] {
            let frame = icmp_quoting_our_syn(TARGET, t, c, OUR_IP, TARGET, 443, 3);
            let m = match_syn_response(&frame, true, &ctx())
                .unwrap_or_else(|| panic!("type {t} code {c} should match"));
            assert_eq!(m.state, PortState::Filtered, "type {t} code {c}");
            assert_eq!(m.port, 443, "the scanned port comes from the quote");
            assert_eq!(m.tryno, 3, "the attempt comes from the quoted source port");
            assert_eq!(m.src_ip, TARGET, "attributed to the host we probed");
        }
    }

    #[test]
    fn icmp_error_relayed_by_a_router_still_lands_on_the_target() {
        let frame = icmp_quoting_our_syn(ROUTER, 3, 1, OUR_IP, TARGET, 443, 0);
        let m = match_syn_response(&frame, true, &ctx()).unwrap();
        assert_eq!(m.src_ip, TARGET, "not the router that sent the error");
        assert_eq!(m.state, PortState::Filtered);
    }

    #[test]
    fn icmp_error_quoting_someone_elses_packet_is_ignored() {
        // The quoted packet's source is not us → not about a probe of ours. This is the
        // C's "If it didn't come from us, we don't care."
        let frame = icmp_quoting_our_syn(TARGET, 3, 3, ROUTER, TARGET, 443, 0);
        assert!(match_syn_response(&frame, true, &ctx()).is_none());
    }

    #[test]
    fn icmp_error_with_a_foreign_sequence_is_ignored() {
        // Same ports, but the quoted probe carries a sequence we never generated: the
        // quote contains our original packet, so the encoding must be present verbatim.
        let mut frame = icmp_quoting_our_syn(TARGET, 3, 3, OUR_IP, TARGET, 443, 0);
        // The quoted TCP sequence sits after: eth(14) + outer ip(20) + icmp(8) +
        // quoted ip(20) + quoted sport/dport(4).
        let seq_off = 14 + 20 + 8 + 20 + 4;
        frame[seq_off..seq_off + 4].copy_from_slice(&0xFFFF_0000u32.to_be_bytes());
        assert!(match_syn_response(&frame, true, &ctx()).is_none());
    }

    #[test]
    fn icmp_error_with_an_out_of_range_attempt_is_ignored() {
        // Quoted source port far outside base..base+max_tryno.
        let frame = icmp_quoting_our_syn(TARGET, 3, 3, OUR_IP, TARGET, 443, 5000);
        assert!(match_syn_response(&frame, true, &ctx()).is_none());
    }

    #[test]
    fn icmp_error_quoting_a_udp_packet_is_not_ours() {
        // A UDP quote cannot answer a SYN probe (the C checks the quoted protocol).
        let spec = Ipv4Spec::new(OUR_IP, TARGET, 64, 1);
        let udp = crate::build::build_udp_raw(&spec, 40000, 53, &[]).unwrap();
        let mut icmp = vec![3u8, 3, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&udp);
        let mut ip = vec![
            0x45,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            64,
            IPPROTO_ICMP,
            0,
            0,
            TARGET[0],
            TARGET[1],
            TARGET[2],
            TARGET[3],
            OUR_IP[0],
            OUR_IP[1],
            OUR_IP[2],
            OUR_IP[3],
        ];
        let total = u16::try_from(ip.len().saturating_add(icmp.len())).unwrap();
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&icmp);
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f.extend_from_slice(&ip);
        assert!(match_syn_response(&f, true, &ctx()).is_none());
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
