//! Stateless TCP **flag-scan** probe construction and response matching — the pure
//! `core` half of `-sA` (ACK), `-sW` (Window), `-sM` (Maimon), `-sF` (FIN), `-sN`
//! (Null), and `-sX` (Xmas). One generalized module rather than six near-copies: every
//! one of these sends a single TCP probe with a fixed flag combination and reads the
//! target's RST-or-silence, which [`crate::classify::classify_tcp`] already maps per
//! scan type. Ports the flag-scan slice of `scan_engine_raw.cc`.
//!
//! Total function of its inputs — no clock, no I/O, no randomness (the driver injects
//! the per-scan `base_port`/`seqmask`/`ipid`). Miri-checkable; [`match_flag_response`]
//! is fuzzed against hostile frames.
//!
//! ## Matching (why it is simpler than the SYN scan)
//!
//! A flag-scan reply is an **RST** (or nothing). Per RFC 793, a RST answering a probe
//! that carried an ACK takes its sequence from our *ack* field and sets no ack of its
//! own — so, unlike a SYN/ACK, it does **not** reflect our sequence. The match
//! therefore keys purely on the reply's destination port (= our per-attempt encoded
//! source port, [`crate::synscan::sport_encode`]); the driver's pcap BPF filter scopes
//! capture to that range, so our own outgoing probes (destined to the scanned service
//! port) never come back as replies.
//!
//! An **ICMP** error is a second kind of answer: a type-3/11 message quoting our probe
//! means the port is *filtered* somewhere on the path. That quote contains our original
//! packet, so — unlike a RST — our encoded sequence *is* recoverable and is verified.
//! Handled by [`crate::synscan::match_tcp_icmp_error`], shared with the SYN scan because
//! the quote-matching rules are identical.
//!
//! ## Scope / divergences
//!
//! Inherits `validate-ipv4-only-for-now`.

use crate::build::{build_tcp_raw, BuildError, Ipv4Spec};
use crate::classify::{classify_tcp, PortState, ScanType, TH_ACK};
use crate::icmp_quote::ipv4_offset;
use crate::model::Reason;
use crate::recv_validate::validate_packet;
use crate::synscan::{match_tcp_icmp_error, seq32_encode, sport_encode, MatchCtx};

// TCP flag bits not already exported by `classify`.
const TH_FIN: u8 = 0x01;
const TH_PSH: u8 = 0x08;
const TH_URG: u8 = 0x20;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_ICMP: u8 = 1;
const TCP_MIN: usize = 20;

/// The window a flag probe advertises. Immaterial to classification (the Window scan
/// reads the *reply's* window, not ours); a concrete value, since `build_tcp_raw`
/// carries no magic default.
const FLAG_WINDOW: u16 = 1024;

/// The TCP flags nmap sets for each stateless flag scan, or `None` if `scan` is not one
/// (SYN/connect/UDP/etc. have their own drivers).
#[must_use]
pub fn flags_for(scan: ScanType) -> Option<u8> {
    Some(match scan {
        ScanType::Ack | ScanType::Window => TH_ACK,
        ScanType::Maimon => TH_FIN | TH_ACK,
        ScanType::Fin => TH_FIN,
        ScanType::Null => 0,
        ScanType::Xmas => TH_FIN | TH_PSH | TH_URG,
        _ => return None,
    })
}

/// Build a raw TCP flag-scan probe for `(dport, tryno)` with the given `flags`. Carries
/// no TCP options (only SYN-bearing probes get the MSS option). The attempt is encoded
/// in the source port; the sequence uses the same encoding for uniqueness (the reply is
/// not required to reflect it — see the module docs).
///
/// # Errors
/// Propagates [`BuildError`] from [`build_tcp_raw`] (only reachable via malformed
/// `spec.options`).
pub fn build_flag_probe(
    spec: &Ipv4Spec,
    base_port: u16,
    dport: u16,
    tryno: u32,
    seqmask: u32,
    flags: u8,
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
        flags,
        FLAG_WINDOW,
        0, // urgent pointer
        &[],
        &[],
    )
}

/// The per-scan constants a captured reply is matched against.
#[derive(Debug, Clone, Copy)]
pub struct FlagMatchCtx {
    /// Which flag scan this is — selects the [`classify_tcp`] interpretation.
    pub scan: ScanType,
    /// Our own source address, for validating the packet quoted in an ICMP error.
    pub our_ip: [u8; 4],
    /// Base TCP source port (the `tryno == 0` source port).
    pub base_port: u16,
    /// Per-scan random sequence mask — verifiable in an ICMP quote (which contains our
    /// original packet) even though a RST reflects no sequence of ours.
    pub seqmask: u32,
    /// Highest attempt number in flight.
    pub max_tryno: u32,
}

/// A captured packet matched to an outstanding flag probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagReply {
    /// Source IPv4 of the reply — which scanned host answered. Lets one matcher serve a
    /// whole host group (see `nmap_sys::group`).
    pub src_ip: [u8; 4],
    /// The scanned port that answered (the reply's TCP source port).
    pub port: u16,
    /// Which attempt this reply answers.
    pub tryno: u32,
    /// The port state the reply implies (per the scan type).
    pub state: PortState,
    /// Why: `reset` for a RST, or the specific ICMP unreachable code for an error.
    pub reason: Reason,
}

/// Decide whether a captured frame answers one of our flag probes, and to what state.
/// Returns `None` for anything that is not a well-formed IPv4/TCP reply decoding to an
/// in-range attempt with flags meaningful for this scan. Total on all input.
#[must_use]
pub fn match_flag_response(
    frame: &[u8],
    eth_included: bool,
    ctx: &FlagMatchCtx,
) -> Option<FlagReply> {
    let ip_off = ipv4_offset(frame, eth_included)?;
    let ip = frame.get(ip_off..)?;
    let v = validate_packet(ip).ok()?;
    if v.proto == IPPROTO_ICMP {
        // An ICMP error quoting our probe: filtered, whichever flag scan this is. Shared
        // with the SYN scan, since the quote-matching rules are identical.
        let sctx = MatchCtx {
            our_ip: ctx.our_ip,
            base_port: ctx.base_port,
            seqmask: ctx.seqmask,
            max_tryno: ctx.max_tryno,
        };
        let m = match_tcp_icmp_error(frame, eth_included, ctx.scan, &sctx)?;
        return Some(FlagReply {
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
    let src_ip: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
    let tcp = ip.get(v.data_offset..)?;
    if tcp.len() < TCP_MIN {
        return None;
    }
    let resp_sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let resp_dport = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);

    let tryno = u32::from(resp_dport.wrapping_sub(ctx.base_port));
    if tryno > ctx.max_tryno {
        return None;
    }
    // A flag-scan reply carries no usable sequence reflection (see module docs); the
    // scan-type-specific verdict comes straight from the flags/window.
    let state = classify_tcp(ctx.scan, flags, window)?;
    Some(FlagReply {
        src_ip,
        port: resp_sport,
        tryno,
        state,
        // Every flag-scan reply we act on is a RST, whatever state it implies.
        reason: Reason::Reset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TH_RST: u8 = 0x04;

    const US: [u8; 4] = [10, 0, 0, 1];
    const SEQMASK: u32 = 0x1234_5678;

    fn ctx(scan: ScanType) -> FlagMatchCtx {
        FlagMatchCtx {
            scan,
            our_ip: US,
            base_port: 40000,
            seqmask: SEQMASK,
            max_tryno: 11,
        }
    }

    /// A reply from the target back to us: source = scanned port, dest = our sport.
    fn reply(scanned: u16, tryno: u32, flags: u8, window: u16) -> Vec<u8> {
        let spec = Ipv4Spec::new([10, 0, 0, 2], [10, 0, 0, 1], 64, 0x9);
        let seg = build_tcp_raw(
            &spec,
            scanned,
            sport_encode(40000, tryno),
            123,
            0,
            0,
            flags,
            window,
            0,
            &[],
            &[],
        )
        .unwrap();
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f.extend_from_slice(&seg);
        f
    }

    /// An ICMP type/code error from `sender`, quoting the flag probe we sent to
    /// `TARGET`'s `dport` as attempt `tryno`.
    fn icmp_quoting_our_probe(
        sender: [u8; 4],
        icmp_type: u8,
        icmp_code: u8,
        scan: ScanType,
        dport: u16,
        tryno: u32,
    ) -> Vec<u8> {
        const TARGET: [u8; 4] = [10, 0, 0, 2];
        let spec = Ipv4Spec::new(US, TARGET, 64, 0x1234);
        let flags = flags_for(scan).unwrap();
        let probe = build_flag_probe(&spec, 40000, dport, tryno, SEQMASK, flags).unwrap();
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
            US[0],
            US[1],
            US[2],
            US[3],
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
    fn icmp_error_makes_every_flag_scan_report_filtered() {
        // The back-fill's payoff: for FIN/Null/Xmas/Maimon an unanswered port defaults to
        // open|filtered, so an ICMP error is the only way to learn it is *filtered*.
        for scan in [
            ScanType::Ack,
            ScanType::Window,
            ScanType::Maimon,
            ScanType::Fin,
            ScanType::Null,
            ScanType::Xmas,
        ] {
            let frame = icmp_quoting_our_probe([10, 0, 0, 2], 3, 13, scan, 80, 2);
            let m = match_flag_response(&frame, true, &ctx(scan))
                .unwrap_or_else(|| panic!("{scan:?} should match its ICMP error"));
            assert_eq!(m.state, PortState::Filtered, "{scan:?}");
            assert_eq!(m.port, 80);
            assert_eq!(m.tryno, 2);
            assert_eq!(m.src_ip, [10, 0, 0, 2]);
        }
    }

    #[test]
    fn icmp_error_quoting_someone_elses_probe_is_ignored() {
        // A quote whose source is not us, faked by rewriting the quoted source address.
        let mut frame = icmp_quoting_our_probe([10, 0, 0, 2], 3, 3, ScanType::Fin, 80, 0);
        let quoted_src_off = 14 + 20 + 8 + 12; // eth + outer ip + icmp + quoted ip src
        frame[quoted_src_off..quoted_src_off + 4].copy_from_slice(&[9, 9, 9, 9]);
        assert!(match_flag_response(&frame, true, &ctx(ScanType::Fin)).is_none());
    }

    #[test]
    fn icmp_error_with_a_foreign_sequence_is_ignored() {
        let mut frame = icmp_quoting_our_probe([10, 0, 0, 2], 3, 3, ScanType::Ack, 80, 0);
        let seq_off = 14 + 20 + 8 + 20 + 4;
        frame[seq_off..seq_off + 4].copy_from_slice(&0x1111_2222u32.to_be_bytes());
        assert!(match_flag_response(&frame, true, &ctx(ScanType::Ack)).is_none());
    }

    #[test]
    fn every_flag_scan_has_a_flag_set() {
        for s in [
            ScanType::Ack,
            ScanType::Window,
            ScanType::Maimon,
            ScanType::Fin,
            ScanType::Null,
            ScanType::Xmas,
        ] {
            assert!(flags_for(s).is_some(), "{s:?} should be a flag scan");
        }
        assert_eq!(flags_for(ScanType::Syn), None);
        assert_eq!(flags_for(ScanType::Udp), None);
        // Distinct flag combinations.
        assert_eq!(flags_for(ScanType::Fin), Some(0x01));
        assert_eq!(flags_for(ScanType::Null), Some(0x00));
        assert_eq!(flags_for(ScanType::Xmas), Some(0x01 | 0x08 | 0x20));
        assert_eq!(flags_for(ScanType::Maimon), Some(0x01 | 0x10));
    }

    #[test]
    fn ack_scan_rst_is_unfiltered() {
        let m = match_flag_response(&reply(80, 0, TH_RST | TH_ACK, 0), true, &ctx(ScanType::Ack))
            .unwrap();
        assert_eq!(m.port, 80);
        assert_eq!(m.state, PortState::Unfiltered);
    }

    #[test]
    fn window_scan_reads_the_reply_window() {
        // RST with a non-zero window → open; zero window → closed (BSD-derived quirk).
        let open = match_flag_response(
            &reply(80, 1, TH_RST | TH_ACK, 512),
            true,
            &ctx(ScanType::Window),
        )
        .unwrap();
        assert_eq!(open.state, PortState::Open);
        let closed = match_flag_response(
            &reply(80, 1, TH_RST | TH_ACK, 0),
            true,
            &ctx(ScanType::Window),
        )
        .unwrap();
        assert_eq!(closed.state, PortState::Closed);
    }

    #[test]
    fn fin_null_xmas_rst_is_closed() {
        for scan in [
            ScanType::Fin,
            ScanType::Null,
            ScanType::Xmas,
            ScanType::Maimon,
        ] {
            let m =
                match_flag_response(&reply(81, 2, TH_RST | TH_ACK, 0), true, &ctx(scan)).unwrap();
            assert_eq!(m.state, PortState::Closed, "{scan:?} RST should be closed");
            assert_eq!(m.tryno, 2);
        }
    }

    #[test]
    fn non_rst_and_out_of_range_are_ignored() {
        // A stray SYN/ACK is not a flag-scan verdict for FIN/etc.
        assert!(match_flag_response(&reply(80, 0, 0x12, 0), true, &ctx(ScanType::Fin)).is_none());
        // Destination outside our encoded range.
        assert!(
            match_flag_response(&reply(80, 50, TH_RST, 0), true, &ctx(ScanType::Ack)).is_none()
        );
        // Truncated frames.
        assert!(match_flag_response(&[], true, &ctx(ScanType::Ack)).is_none());
        assert!(match_flag_response(&[0u8; 14], true, &ctx(ScanType::Ack)).is_none());
    }

    #[test]
    fn build_flag_probe_sets_the_requested_flags_no_options() {
        let spec = Ipv4Spec::new([10, 0, 0, 1], [10, 0, 0, 2], 64, 0x1234);
        let flags = flags_for(ScanType::Xmas).unwrap();
        let pkt = build_flag_probe(&spec, 40000, 80, 0, 0xABCD, flags).unwrap();
        let v = validate_packet(&pkt).unwrap();
        let tcp = &pkt[v.data_offset..];
        assert_eq!(tcp[13], flags);
        // data offset = 5 words (20 bytes) → no options.
        assert_eq!((tcp[12] >> 4) * 4, 20);
    }
}
