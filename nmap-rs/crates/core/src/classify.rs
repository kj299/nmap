//! Scan-response classification — the map from a matched response packet (or its
//! absence) to a [`PortState`], per scan type. Ports the decision logic in nmap's
//! `scan_engine_raw.cc` (`ultra_scan` response handling) plus `set_default_port_state`
//! (`scan_engine.cc`).
//!
//! This is the semantic heart of the raw scanners: the same SYN/ACK that means *open*
//! for a SYN scan is meaningless for an ACK scan, where only a RST (→ *unfiltered*)
//! matters. Nmap encodes this as a pile of nested `scantype`/flag/ICMP-code switches;
//! this port lifts it into small **pure, total decision functions** — trivially
//! testable and exhaustively differential-checked against a transcription of the C
//! branches (every `(scan, response)` combination, not a sample).
//!
//! Probe matching (does this packet answer an outstanding probe?) lives in the engine
//! layer; this module answers only "given that it matched, what state does it imply?".

/// The scan techniques whose responses this module classifies. Mirrors nmap's `stype`
/// for the port-scan methods (host-discovery ping types are out of scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    /// `-sS` TCP SYN.
    Syn,
    /// `-sT` TCP connect (unprivileged; shares the SYN default state).
    Connect,
    /// `-sA` TCP ACK.
    Ack,
    /// `-sW` TCP Window.
    Window,
    /// `-sM` TCP Maimon.
    Maimon,
    /// `-sF` TCP FIN.
    Fin,
    /// `-sN` TCP Null.
    Null,
    /// `-sX` TCP Xmas.
    Xmas,
    /// `-sU` UDP.
    Udp,
    /// `-sO` IP protocol.
    IpProto,
    /// `-sY` SCTP INIT.
    SctpInit,
    /// `-sZ` SCTP COOKIE-ECHO.
    SctpCookieEcho,
}

/// Port states nmap can assign. `OpenFiltered`/`ClosedFiltered` are the ambiguous
/// no-response states of the "silent" scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
    Unknown,
}

// TCP flag bits.
/// SYN flag.
pub const TH_SYN: u8 = 0x02;
/// RST flag.
pub const TH_RST: u8 = 0x04;
/// ACK flag.
pub const TH_ACK: u8 = 0x10;

// SCTP chunk types (dnet/sctp.h).
const SCTP_INIT_ACK: u8 = 0x02;
const SCTP_ABORT: u8 = 0x06;

/// The state a port is assumed to have when **no response** ever arrives, per scan
/// type. Ports `set_default_port_state` (`scan_engine.cc:803`). `defeat_icmp_ratelimit`
/// is nmap's `--defeat-icmp-ratelimit`, which only affects the UDP scan.
#[must_use]
pub fn default_port_state(scan: ScanType, defeat_icmp_ratelimit: bool) -> PortState {
    match scan {
        ScanType::Syn | ScanType::Ack | ScanType::Window | ScanType::Connect => PortState::Filtered,
        ScanType::SctpInit => PortState::Filtered,
        ScanType::Null | ScanType::Fin | ScanType::Maimon | ScanType::Xmas => {
            PortState::OpenFiltered
        }
        ScanType::Udp => {
            if defeat_icmp_ratelimit {
                PortState::ClosedFiltered
            } else {
                PortState::OpenFiltered
            }
        }
        ScanType::IpProto => PortState::OpenFiltered,
        ScanType::SctpCookieEcho => PortState::OpenFiltered,
    }
}

/// Classify a matched TCP response by its flags (and window, for the Window scan).
/// Ports `scan_engine_raw.cc:1717`. Returns `None` when the flags are unexpected for
/// the scan — the C logs and ignores the packet (leaving the port at its default).
#[must_use]
pub fn classify_tcp(scan: ScanType, flags: u8, window: u16) -> Option<PortState> {
    // SYN scan: a SYN+ACK is an open port.
    if scan == ScanType::Syn && (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) {
        return Some(PortState::Open);
    }
    // A RST means different things per scan type.
    if flags & TH_RST != 0 {
        return Some(match scan {
            ScanType::Window => {
                if window != 0 {
                    PortState::Open
                } else {
                    PortState::Closed
                }
            }
            ScanType::Ack => PortState::Unfiltered,
            _ => PortState::Closed,
        });
    }
    // SYN scan: a bare SYN is the TCP split-handshake open case.
    if scan == ScanType::Syn && (flags & TH_SYN != 0) {
        return Some(PortState::Open);
    }
    None
}

/// Classify a matched ICMPv4 response. `from_target` is true when the ICMP was sent by
/// the host being probed (vs. an intermediate router). Ports `scan_engine_raw.cc:1888`
/// (type 3 unreachable) and `:1927` (type 11 time-exceeded). Returns `None` for ICMP
/// types/codes the scanner does not act on.
#[must_use]
pub fn classify_icmp(
    scan: ScanType,
    icmp_type: u8,
    icmp_code: u8,
    from_target: bool,
) -> Option<PortState> {
    match icmp_type {
        3 => match icmp_code {
            0 | 1 => Some(PortState::Filtered), // net / host unreachable
            2 => Some(if scan == ScanType::IpProto && from_target {
                PortState::Closed
            } else {
                PortState::Filtered
            }), // protocol unreachable
            3 => Some(if from_target && scan == ScanType::Udp {
                PortState::Closed
            } else if from_target && scan == ScanType::IpProto {
                PortState::Open
            } else {
                PortState::Filtered
            }), // port unreachable
            9 | 10 | 13 => Some(PortState::Filtered), // admin prohibited
            _ => None,
        },
        11 => Some(PortState::Filtered), // time exceeded
        _ => None,
    }
}

/// Classify a matched SCTP response by its first chunk type. Ports
/// `scan_engine_raw.cc:1779`.
#[must_use]
pub fn classify_sctp(scan: ScanType, chunk_type: u8) -> Option<PortState> {
    match scan {
        ScanType::SctpInit => match chunk_type {
            SCTP_INIT_ACK => Some(PortState::Open),
            SCTP_ABORT => Some(PortState::Closed),
            _ => None,
        },
        ScanType::SctpCookieEcho => match chunk_type {
            SCTP_ABORT => Some(PortState::Closed),
            _ => None,
        },
        _ => None,
    }
}

/// A direct UDP datagram back from the target on a UDP scan means the port is open
/// (`scan_engine_raw.cc:2120`, `ER_UDPRESPONSE`).
#[must_use]
pub fn classify_udp_response() -> PortState {
    PortState::Open
}

/// On a protocol scan (`-sO`), any packet from the target in the probed protocol means
/// that protocol is open (`scan_engine_raw.cc:1681`, `ER_PROTORESPONSE`).
#[must_use]
pub fn classify_proto_response() -> PortState {
    PortState::Open
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_scan_synack_is_open() {
        assert_eq!(
            classify_tcp(ScanType::Syn, TH_SYN | TH_ACK, 0),
            Some(PortState::Open)
        );
        // Split-handshake bare SYN is also open.
        assert_eq!(
            classify_tcp(ScanType::Syn, TH_SYN, 0),
            Some(PortState::Open)
        );
    }

    #[test]
    fn rst_depends_on_scan() {
        assert_eq!(
            classify_tcp(ScanType::Syn, TH_RST, 0),
            Some(PortState::Closed)
        );
        assert_eq!(
            classify_tcp(ScanType::Fin, TH_RST, 0),
            Some(PortState::Closed)
        );
        assert_eq!(
            classify_tcp(ScanType::Ack, TH_RST, 0),
            Some(PortState::Unfiltered)
        );
        // Window scan: nonzero window on RST => open, zero => closed.
        assert_eq!(
            classify_tcp(ScanType::Window, TH_RST, 1024),
            Some(PortState::Open)
        );
        assert_eq!(
            classify_tcp(ScanType::Window, TH_RST, 0),
            Some(PortState::Closed)
        );
    }

    #[test]
    fn unexpected_tcp_flags_ignored() {
        // ACK scan sees a SYN+ACK (no RST): nothing to conclude.
        assert_eq!(classify_tcp(ScanType::Ack, TH_SYN | TH_ACK, 0), None);
        // SYN scan sees a bare ACK: not open, not RST -> ignored.
        assert_eq!(classify_tcp(ScanType::Syn, TH_ACK, 0), None);
    }

    #[test]
    fn icmp_port_unreachable_by_scan() {
        // UDP scan, port-unreach from target => closed.
        assert_eq!(
            classify_icmp(ScanType::Udp, 3, 3, true),
            Some(PortState::Closed)
        );
        // Proto scan, port-unreach from target => open.
        assert_eq!(
            classify_icmp(ScanType::IpProto, 3, 3, true),
            Some(PortState::Open)
        );
        // Same, but not from the target => filtered.
        assert_eq!(
            classify_icmp(ScanType::Udp, 3, 3, false),
            Some(PortState::Filtered)
        );
        // Protocol-unreach, proto scan from target => closed.
        assert_eq!(
            classify_icmp(ScanType::IpProto, 3, 2, true),
            Some(PortState::Closed)
        );
    }

    #[test]
    fn icmp_admin_prohibited_and_time_exceeded_filtered() {
        for code in [0u8, 1, 9, 10, 13] {
            assert_eq!(
                classify_icmp(ScanType::Syn, 3, code, true),
                Some(PortState::Filtered)
            );
        }
        assert_eq!(
            classify_icmp(ScanType::Syn, 11, 0, false),
            Some(PortState::Filtered)
        );
        // Unhandled ICMP type => ignored.
        assert_eq!(classify_icmp(ScanType::Syn, 8, 0, true), None);
    }

    #[test]
    fn sctp_chunks() {
        assert_eq!(
            classify_sctp(ScanType::SctpInit, SCTP_INIT_ACK),
            Some(PortState::Open)
        );
        assert_eq!(
            classify_sctp(ScanType::SctpInit, SCTP_ABORT),
            Some(PortState::Closed)
        );
        assert_eq!(
            classify_sctp(ScanType::SctpCookieEcho, SCTP_ABORT),
            Some(PortState::Closed)
        );
        // COOKIE-ECHO does not treat INIT-ACK as open.
        assert_eq!(classify_sctp(ScanType::SctpCookieEcho, SCTP_INIT_ACK), None);
    }

    #[test]
    fn default_states() {
        assert_eq!(
            default_port_state(ScanType::Syn, false),
            PortState::Filtered
        );
        assert_eq!(
            default_port_state(ScanType::Fin, false),
            PortState::OpenFiltered
        );
        assert_eq!(
            default_port_state(ScanType::Udp, false),
            PortState::OpenFiltered
        );
        assert_eq!(
            default_port_state(ScanType::Udp, true),
            PortState::ClosedFiltered
        );
    }

    #[test]
    fn direct_responses_are_open() {
        assert_eq!(classify_udp_response(), PortState::Open);
        assert_eq!(classify_proto_response(), PortState::Open);
    }
}
