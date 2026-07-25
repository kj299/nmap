//! Construction of the 16 IPv4 OS-detection probes — ports `HostOsScan::sendTSeqProbe`,
//! `sendTOpsProbe`, `sendTEcnProbe`, `sendT1_7Probe`, `sendTIcmpProbe`, `sendTUdpProbe`
//! and the three low-level senders they call.
//!
//! The probe battery, in the order the C sends it:
//!
//! | Probe | Packet | Target port |
//! |-------|--------|-------------|
//! | `SEQ` ×6 | SYN, six different option sets and windows, sequence numbers one apart | open TCP |
//! | `OPS`/`WIN` ×6 | the same six packets, but all sharing one sequence number | open TCP |
//! | `ECN` | SYN+CWR+ECE with a reserved bit set and an odd urgent pointer | open TCP |
//! | `T1`–`T4` | SYN, null, SYN+FIN+URG+PSH, ACK | open TCP |
//! | `T5`–`T7` | SYN, ACK, FIN+PSH+URG | closed TCP |
//! | `IE` ×2 | ICMP echo, one with a non-zero code and DF set | — |
//! | `U1` | UDP carrying 300 `'C'` bytes | closed UDP |
//!
//! The six `SEQ` probes differ only in their options and window, and their sequence
//! numbers advance by one so the target's replies can be lined up with the probes that
//! caused them; that is what makes the ISN-generation analysis possible. The `OPS`
//! probes repeat the same six packets from a *different* source-port range with a
//! *constant* sequence number, so they can be re-sent to recover option and window data
//! without disturbing the sequence analysis.
//!
//! Everything here is a total function of its inputs: no randomness, no clock, no I/O.
//! The driver supplies the random bases in [`ProbeParams`], which keeps this module
//! fuzzable and lets a test pin every byte on the wire.

use crate::build::{build_icmp_raw, build_tcp_raw, build_udp_raw, BuildError, Ipv4Spec};
use crate::headers::tcp::{TH_ACK, TH_CWR, TH_ECE, TH_FIN, TH_PSH, TH_SYN, TH_URG};

/// Number of `SEQ` samples, matching the C's `NUM_SEQ_SAMPLES`.
pub const NUM_SEQ_SAMPLES: u8 = 6;

/// ICMP echo request.
const ICMP_ECHO: u8 = 8;
/// `IP_TOS_DEFAULT`.
const TOS_DEFAULT: u8 = 0x00;
/// `IP_TOS_RELIABILITY` — the second `IE` probe sets it to see whether the TOS byte is
/// echoed back.
const TOS_RELIABILITY: u8 = 0x04;

/// Fixed ICMP sequence number the C uses for the first `IE` probe (`icmpEchoSeq = 295`).
/// The second probe uses this plus one.
pub const ICMP_ECHO_SEQ: u16 = 295;

/// Payload length of the first and second `IE` probes. The two differ so a stack that
/// pads or truncates is visible.
const IE_DATA_LENS: [u16; 2] = [120, 150];

/// Bytes of `'C'` the `U1` probe carries.
pub const UDP_DATA_LEN: usize = 300;
/// The byte `U1` fills its payload with (`'C'`).
pub const UDP_PATTERN_BYTE: u8 = 0x43;
/// `U1`'s IP ID is a fixed constant in the C, not random — the response analysis relies
/// on being able to recognise it in the ICMP quote.
pub const UDP_IP_ID: u16 = 0x1042;

/// TCP options for each probe slot, transcribed from the C's `prbOpts[]`.
///
/// Slots 0–5 are the `SEQ`/`OPS` probes, 6 is `ECN`, and 7–12 are `T2`–`T7` (`T1` reuses
/// slot 0). The `\xff\xff\xff\xff` inside each timestamp option is the TSval nmap sends;
/// the following zeros are TSecr.
const PROBE_OPTIONS: [&[u8]; 13] = [
    // SEQ 1: WScale(10), NOP, MSS(1460), Timestamp, SACK permitted
    b"\x03\x03\x0A\x01\x02\x04\x05\xb4\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    // SEQ 2: MSS(1400), WScale(0), SACK permitted, Timestamp, EOL
    b"\x02\x04\x05\x78\x03\x03\x00\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x00",
    // SEQ 3: Timestamp, NOP, NOP, WScale(5), NOP, MSS(640)
    b"\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x01\x01\x03\x03\x05\x01\x02\x04\x02\x80",
    // SEQ 4: SACK permitted, Timestamp, WScale(10), EOL
    b"\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00",
    // SEQ 5: MSS(536), SACK permitted, Timestamp, WScale(10), EOL
    b"\x02\x04\x02\x18\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00",
    // SEQ 6: MSS(265), SACK permitted, Timestamp
    b"\x02\x04\x01\x09\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00",
    // ECN: WScale(10), NOP, MSS(1460), SACK permitted, NOP, NOP
    b"\x03\x03\x0A\x01\x02\x04\x05\xb4\x04\x02\x01\x01",
    // T2..T6 all share one option set: WScale(10), NOP, MSS(265), Timestamp, SACK perm.
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    // T7 differs in one byte: WScale(15) rather than WScale(10).
    b"\x03\x03\x0f\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
];

/// TCP window size for each probe slot, transcribed from the C's `prbWindowSz[]`.
/// Numbering matches [`PROBE_OPTIONS`]. The values are deliberately strange — a stack
/// that clamps, rounds or ignores the advertised window reveals itself.
const PROBE_WINDOWS: [u16; 13] = [1, 63, 4, 4, 16, 512, 3, 128, 256, 1024, 31337, 32768, 65535];

/// Which probe to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OsProbe {
    /// Sequence-generation sample `0..6`, sent to the open TCP port.
    Seq(u8),
    /// Option/window resend `0..6`, sent to the open TCP port. Same packet shape as
    /// [`OsProbe::Seq`] but from a different source port and with a fixed sequence
    /// number, so re-sending it cannot corrupt the sequence analysis.
    Ops(u8),
    /// Explicit-congestion-notification probe, sent to the open TCP port.
    Ecn,
    /// `T1`–`T7`, numbered `1..=7`. `T1`–`T4` go to the open port, `T5`–`T7` to a closed
    /// one.
    T(u8),
    /// ICMP echo probe `0` or `1`.
    Ie(u8),
    /// UDP probe to a closed port.
    U1,
}

impl OsProbe {
    /// Every probe, in the order the C sends them.
    #[must_use]
    pub fn all() -> Vec<OsProbe> {
        let mut v = Vec::new();
        for i in 0..NUM_SEQ_SAMPLES {
            v.push(OsProbe::Seq(i));
        }
        for i in 0..NUM_SEQ_SAMPLES {
            v.push(OsProbe::Ops(i));
        }
        v.push(OsProbe::Ecn);
        for n in 1..=7u8 {
            v.push(OsProbe::T(n));
        }
        v.push(OsProbe::Ie(0));
        v.push(OsProbe::Ie(1));
        v.push(OsProbe::U1);
        v
    }

    /// Slot into [`PROBE_OPTIONS`]/[`PROBE_WINDOWS`], for the TCP probes.
    fn slot(self) -> Option<usize> {
        match self {
            OsProbe::Seq(i) | OsProbe::Ops(i) if i < NUM_SEQ_SAMPLES => Some(usize::from(i)),
            OsProbe::Ecn => Some(6),
            // T1 reuses the first SEQ packet; T2..T7 take slots 7..12.
            OsProbe::T(1) => Some(0),
            OsProbe::T(n) if (2..=7).contains(&n) => Some(usize::from(n).saturating_add(5)),
            _ => None,
        }
    }
}

/// Everything the driver must decide before a probe can be built.
///
/// The C keeps these in `HostOsScan`/`HostOsScanStats` and derives several of them from
/// `get_random_*()` and `time()` at scan start. They are inputs here so that building a
/// probe is a pure function — the same parameters always produce the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeParams {
    /// Source address.
    pub src: [u8; 4],
    /// Target address.
    pub dst: [u8; 4],
    /// TTL for the TCP and ICMP probes.
    ///
    /// The C passes `o.ttl` through to an 8-bit header field with no translation, so its
    /// default of `-1` reaches the wire as 255. There is no sentinel here: the driver
    /// decides and says so, per the ledgered `build-explicit-fields-no-magic`.
    pub ttl: u8,
    /// TTL for the `U1` probe, which the C randomises separately (`(time % 14) + 51`).
    pub udp_ttl: u8,
    /// IP ID for the TCP and ICMP probes; the C draws a fresh random one per packet.
    /// `U1` ignores this and uses the fixed [`UDP_IP_ID`].
    pub ip_id: u16,
    /// Base source port for the TCP probes. Each probe takes a distinct offset from it,
    /// which is how a reply is attributed to the probe that caused it.
    pub tcp_port_base: u16,
    /// Source port for the `U1` probe.
    pub udp_port_base: u16,
    /// Base TCP sequence number. `SEQ` probe `i` uses `tcp_seq_base + i`; every other
    /// probe uses `tcp_seq_base` unchanged.
    pub tcp_seq_base: u32,
    /// TCP acknowledgement number shared by the probes that carry one.
    pub tcp_ack: u32,
    /// ICMP identifier for the first `IE` probe; the second uses this plus one.
    pub icmp_echo_id: u16,
    /// ICMP sequence for the first `IE` probe; the second uses this plus one. Normally
    /// [`ICMP_ECHO_SEQ`].
    pub icmp_echo_seq: u16,
    /// A port found open, required by the `SEQ`, `OPS`, `ECN` and `T1`–`T4` probes.
    pub open_tcp_port: Option<u16>,
    /// A port found closed, required by `T5`–`T7`.
    pub closed_tcp_port: Option<u16>,
    /// A UDP port believed closed, required by `U1`.
    pub closed_udp_port: Option<u16>,
}

/// Why a probe could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// The probe needs an open TCP port and none was found. The C returns silently here,
    /// leaving the caller unable to tell "not sent" from "sent".
    NoOpenTcpPort,
    /// The probe needs a closed TCP port and none was found.
    NoClosedTcpPort,
    /// The probe needs a closed UDP port and none was found.
    NoClosedUdpPort,
    /// The probe index is out of range. The C `assert()`s, aborting the process.
    UnknownProbe(OsProbe),
    /// Packet construction failed.
    Build(BuildError),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::NoOpenTcpPort => write!(f, "no open TCP port for this probe"),
            ProbeError::NoClosedTcpPort => write!(f, "no closed TCP port for this probe"),
            ProbeError::NoClosedUdpPort => write!(f, "no closed UDP port for this probe"),
            ProbeError::UnknownProbe(p) => write!(f, "no such OS probe: {p:?}"),
            ProbeError::Build(e) => write!(f, "packet build failed: {e}"),
        }
    }
}

impl std::error::Error for ProbeError {}

impl From<BuildError> for ProbeError {
    fn from(e: BuildError) -> Self {
        ProbeError::Build(e)
    }
}

/// The source port a probe is sent from, or `None` for the `IE` probes, which carry no
/// port and are matched by their ICMP identifier instead.
///
/// The offsets are what let a reply be attributed to its probe, so they are part of the
/// wire contract and are shared with the response analysis.
#[must_use]
pub fn source_port(probe: OsProbe, params: &ProbeParams) -> Option<u16> {
    let base = params.tcp_port_base;
    // The C computes these as `int` and passes them to a `u16` parameter, so a base near
    // the top of the range truncates rather than saturating. `wrapping_add` reproduces
    // that exactly. (With the C's own base of `33000 + rand % 32261` it cannot happen.)
    let offset = match probe {
        OsProbe::Seq(i) if i < NUM_SEQ_SAMPLES => u16::from(i),
        OsProbe::Ops(i) if i < NUM_SEQ_SAMPLES => u16::from(NUM_SEQ_SAMPLES).wrapping_add(i.into()),
        OsProbe::Ecn => u16::from(NUM_SEQ_SAMPLES).wrapping_add(6),
        OsProbe::T(n) if (1..=7).contains(&n) => u16::from(NUM_SEQ_SAMPLES)
            .wrapping_add(7)
            .wrapping_add(u16::from(n).wrapping_sub(1)),
        OsProbe::U1 => return Some(params.udp_port_base),
        _ => return None,
    };
    Some(base.wrapping_add(offset))
}

/// Build one probe's packet bytes, ready to hand to the raw sender.
///
/// Returns an error rather than silently sending nothing when a required port is
/// missing: the C's senders `return` early in that case, so the driver cannot distinguish
/// "no open port, probe skipped" from "probe sent, no reply" — and a skipped probe and an
/// unanswered probe mean different things to the fingerprint.
pub fn build_probe(probe: OsProbe, params: &ProbeParams) -> Result<Vec<u8>, ProbeError> {
    match probe {
        OsProbe::Seq(i) if i < NUM_SEQ_SAMPLES => {
            // Sequence numbers advance by one across the six samples so replies can be
            // matched back to the probe that produced them.
            build_tcp(
                probe,
                params,
                open_port(params)?,
                params.tcp_seq_base.wrapping_add(u32::from(i)),
                params.tcp_ack,
                0,
                TH_SYN,
                0,
                false,
            )
        }
        OsProbe::Ops(i) if i < NUM_SEQ_SAMPLES => build_tcp(
            probe,
            params,
            open_port(params)?,
            params.tcp_seq_base,
            params.tcp_ack,
            0,
            TH_SYN,
            0,
            false,
        ),
        // Reserved bit 3 set and a nonsense urgent pointer, on top of the ECN flags.
        OsProbe::Ecn => build_tcp(
            probe,
            params,
            open_port(params)?,
            params.tcp_seq_base,
            0,
            8,
            TH_CWR | TH_ECE | TH_SYN,
            63477,
            false,
        ),
        OsProbe::T(1) => build_tcp(
            probe,
            params,
            open_port(params)?,
            params.tcp_seq_base,
            params.tcp_ack,
            0,
            TH_SYN,
            0,
            false,
        ),
        // T2: no flags at all — a null packet to an open port, with DF set.
        OsProbe::T(2) => build_tcp(
            probe,
            params,
            open_port(params)?,
            params.tcp_seq_base,
            params.tcp_ack,
            0,
            0,
            0,
            true,
        ),
        // T3: an illegal flag soup to an open port.
        OsProbe::T(3) => build_tcp(
            probe,
            params,
            open_port(params)?,
            params.tcp_seq_base,
            params.tcp_ack,
            0,
            TH_SYN | TH_FIN | TH_URG | TH_PSH,
            0,
            false,
        ),
        OsProbe::T(4) => build_tcp(
            probe,
            params,
            open_port(params)?,
            params.tcp_seq_base,
            params.tcp_ack,
            0,
            TH_ACK,
            0,
            true,
        ),
        OsProbe::T(5) => build_tcp(
            probe,
            params,
            closed_tcp_port(params)?,
            params.tcp_seq_base,
            params.tcp_ack,
            0,
            TH_SYN,
            0,
            false,
        ),
        OsProbe::T(6) => build_tcp(
            probe,
            params,
            closed_tcp_port(params)?,
            params.tcp_seq_base,
            params.tcp_ack,
            0,
            TH_ACK,
            0,
            true,
        ),
        OsProbe::T(7) => build_tcp(
            probe,
            params,
            closed_tcp_port(params)?,
            params.tcp_seq_base,
            params.tcp_ack,
            0,
            TH_FIN | TH_PSH | TH_URG,
            0,
            false,
        ),
        OsProbe::Ie(i) if i < 2 => build_ie(params, i),
        OsProbe::U1 => build_u1(params),
        other => Err(ProbeError::UnknownProbe(other)),
    }
}

fn open_port(params: &ProbeParams) -> Result<u16, ProbeError> {
    params.open_tcp_port.ok_or(ProbeError::NoOpenTcpPort)
}

fn closed_tcp_port(params: &ProbeParams) -> Result<u16, ProbeError> {
    params.closed_tcp_port.ok_or(ProbeError::NoClosedTcpPort)
}

#[allow(clippy::too_many_arguments)]
fn build_tcp(
    probe: OsProbe,
    params: &ProbeParams,
    dport: u16,
    seq: u32,
    ack: u32,
    reserved: u8,
    flags: u8,
    urp: u16,
    df: bool,
) -> Result<Vec<u8>, ProbeError> {
    let slot = probe.slot().ok_or(ProbeError::UnknownProbe(probe))?;
    let options = PROBE_OPTIONS
        .get(slot)
        .ok_or(ProbeError::UnknownProbe(probe))?;
    let window = PROBE_WINDOWS
        .get(slot)
        .copied()
        .ok_or(ProbeError::UnknownProbe(probe))?;
    let sport = source_port(probe, params).ok_or(ProbeError::UnknownProbe(probe))?;

    let mut spec = Ipv4Spec::new(params.src, params.dst, params.ttl, params.ip_id);
    spec.tos = TOS_DEFAULT;
    spec.df = df;

    Ok(build_tcp_raw(
        &spec,
        sport,
        dport,
        seq,
        ack,
        reserved,
        flags,
        window,
        urp,
        options,
        &[],
    )?)
}

fn build_ie(params: &ProbeParams, index: u8) -> Result<Vec<u8>, ProbeError> {
    // Probe 0 sets DF and an ICMP code of 9 (undefined for echo request); probe 1 sets a
    // non-default TOS and a legal code. The pair separates stacks that echo the code
    // back from those that zero it, and reveals whether DF and TOS are reflected.
    let (tos, df, code, id, seq, datalen) = if index == 0 {
        (
            TOS_DEFAULT,
            true,
            9u8,
            params.icmp_echo_id,
            params.icmp_echo_seq,
            IE_DATA_LENS[0],
        )
    } else {
        (
            TOS_RELIABILITY,
            false,
            0u8,
            params.icmp_echo_id.wrapping_add(1),
            params.icmp_echo_seq.wrapping_add(1),
            IE_DATA_LENS[1],
        )
    };

    let mut spec = Ipv4Spec::new(params.src, params.dst, params.ttl, params.ip_id);
    spec.tos = tos;
    spec.df = df;

    // The C passes a NULL data pointer with a non-zero length, which `build_icmp_raw`
    // turns into that many zero bytes.
    let data = vec![0u8; usize::from(datalen)];
    Ok(build_icmp_raw(&spec, ICMP_ECHO, code, id, seq, &data)?)
}

fn build_u1(params: &ProbeParams) -> Result<Vec<u8>, ProbeError> {
    let dport = params.closed_udp_port.ok_or(ProbeError::NoClosedUdpPort)?;

    // The C rejects a zero source or destination port here rather than building the
    // packet, so a caller that forgot to set one gets nothing sent.
    if params.udp_port_base == 0 || dport == 0 {
        return Err(ProbeError::NoClosedUdpPort);
    }

    let mut spec = Ipv4Spec::new(params.src, params.dst, params.udp_ttl, UDP_IP_ID);
    spec.tos = TOS_DEFAULT;
    spec.df = false;

    let data = vec![UDP_PATTERN_BYTE; UDP_DATA_LEN];
    Ok(build_udp_raw(&spec, params.udp_port_base, dport, &data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::ipv4::Ipv4Header;
    use crate::headers::tcp::TcpHeader;
    use crate::headers::udp::UdpHeader;

    fn params() -> ProbeParams {
        ProbeParams {
            src: [10, 0, 0, 1],
            dst: [10, 0, 0, 2],
            ttl: 255,
            udp_ttl: 57,
            ip_id: 0xBEEF,
            tcp_port_base: 40000,
            udp_port_base: 41000,
            tcp_seq_base: 0x1000_0000,
            tcp_ack: 0xAAAA_BBBB,
            icmp_echo_id: 0x1234,
            icmp_echo_seq: ICMP_ECHO_SEQ,
            open_tcp_port: Some(22),
            closed_tcp_port: Some(1),
            closed_udp_port: Some(43210),
        }
    }

    /// Parse a built packet back into its IPv4 and TCP headers.
    fn tcp_of(bytes: &[u8]) -> (Ipv4Header, TcpHeader) {
        let ip = Ipv4Header::parse(bytes).expect("ipv4 parses");
        let offset = usize::from(ip.ihl).saturating_mul(4);
        let tcp = TcpHeader::parse(&bytes[offset..]).expect("tcp parses");
        (ip, tcp)
    }

    #[test]
    fn the_battery_covers_every_probe_with_a_distinct_source_port() {
        let all = OsProbe::all();
        // 6 SEQ + 6 OPS + ECN + T1..T7 + 2 IE + U1 = 23 builders. nmap's documented
        // "16 probes" counts what a clean round actually puts on the wire: T1 comes
        // free from the first SEQ reply and the OPS/WIN data from the SEQ replies, so
        // the OPS six and T1 are resends used only when those replies never arrived.
        assert_eq!(all.len(), 23);
        // Every probe must build, and no two may share a source port.
        let p = params();
        let mut ports = Vec::new();
        for probe in &all {
            let pkt = build_probe(*probe, &p).unwrap_or_else(|e| panic!("{probe:?}: {e}"));
            assert!(!pkt.is_empty());
            if let Some(sp) = source_port(*probe, &p) {
                assert!(
                    !ports.contains(&sp),
                    "{probe:?}: source port {sp} already used"
                );
                ports.push(sp);
            }
        }
        // The two IE probes are the only ones without a port.
        assert_eq!(ports.len(), all.len() - 2);
    }

    #[test]
    fn seq_probes_advance_the_sequence_number_but_ops_probes_do_not() {
        let p = params();
        for i in 0..NUM_SEQ_SAMPLES {
            let (_, seq_tcp) = tcp_of(&build_probe(OsProbe::Seq(i), &p).unwrap());
            assert_eq!(
                seq_tcp.seq,
                p.tcp_seq_base.wrapping_add(u32::from(i)),
                "SEQ {i} sequence number"
            );

            let (_, ops_tcp) = tcp_of(&build_probe(OsProbe::Ops(i), &p).unwrap());
            assert_eq!(
                ops_tcp.seq, p.tcp_seq_base,
                "OPS {i} must reuse the base sequence number"
            );

            // Otherwise the two are the same packet shape.
            assert_eq!(seq_tcp.window, ops_tcp.window);
            assert_eq!(seq_tcp.options, ops_tcp.options);
            assert_eq!(seq_tcp.flags, TH_SYN);
            assert_eq!(ops_tcp.flags, TH_SYN);
            // ...sent from different ports, so their replies never collide.
            assert_ne!(seq_tcp.sport, ops_tcp.sport);
        }
    }

    #[test]
    fn source_ports_follow_the_c_layout() {
        let p = params();
        let base = p.tcp_port_base;
        assert_eq!(source_port(OsProbe::Seq(0), &p), Some(base));
        assert_eq!(source_port(OsProbe::Seq(5), &p), Some(base + 5));
        assert_eq!(source_port(OsProbe::Ops(0), &p), Some(base + 6));
        assert_eq!(source_port(OsProbe::Ops(5), &p), Some(base + 11));
        assert_eq!(source_port(OsProbe::Ecn, &p), Some(base + 12));
        assert_eq!(source_port(OsProbe::T(1), &p), Some(base + 13));
        assert_eq!(source_port(OsProbe::T(7), &p), Some(base + 19));
        assert_eq!(source_port(OsProbe::U1, &p), Some(p.udp_port_base));
        assert_eq!(source_port(OsProbe::Ie(0), &p), None);
        assert_eq!(source_port(OsProbe::Ie(1), &p), None);
    }

    #[test]
    fn windows_and_options_match_the_c_tables() {
        let p = params();
        let expected_windows = [1u16, 63, 4, 4, 16, 512];
        for (i, want) in expected_windows.iter().enumerate() {
            let idx = u8::try_from(i).unwrap();
            let (_, tcp) = tcp_of(&build_probe(OsProbe::Seq(idx), &p).unwrap());
            assert_eq!(tcp.window, *want, "SEQ {i} window");
            assert_eq!(tcp.options, PROBE_OPTIONS[i], "SEQ {i} options");
        }
        let (_, ecn) = tcp_of(&build_probe(OsProbe::Ecn, &p).unwrap());
        assert_eq!(ecn.window, 3);
        let (_, t7) = tcp_of(&build_probe(OsProbe::T(7), &p).unwrap());
        assert_eq!(t7.window, 65535);
        // T7 is the only probe whose window scale is 15 rather than 10.
        assert_eq!(t7.options[2], 0x0f);
        let (_, t2) = tcp_of(&build_probe(OsProbe::T(2), &p).unwrap());
        assert_eq!(t2.options[2], 0x0A);
    }

    #[test]
    fn each_t_probe_carries_its_distinctive_flags() {
        let p = params();
        let cases: [(u8, u8); 7] = [
            (1, TH_SYN),
            (2, 0),
            (3, TH_SYN | TH_FIN | TH_URG | TH_PSH),
            (4, TH_ACK),
            (5, TH_SYN),
            (6, TH_ACK),
            (7, TH_FIN | TH_PSH | TH_URG),
        ];
        for (n, flags) in cases {
            let (_, tcp) = tcp_of(&build_probe(OsProbe::T(n), &p).unwrap());
            assert_eq!(tcp.flags, flags, "T{n} flags");
        }
    }

    #[test]
    fn t1_to_t4_hit_the_open_port_and_t5_to_t7_a_closed_one() {
        let p = params();
        for n in 1..=4u8 {
            let (_, tcp) = tcp_of(&build_probe(OsProbe::T(n), &p).unwrap());
            assert_eq!(tcp.dport, 22, "T{n} must probe the open port");
        }
        for n in 5..=7u8 {
            let (_, tcp) = tcp_of(&build_probe(OsProbe::T(n), &p).unwrap());
            assert_eq!(tcp.dport, 1, "T{n} must probe a closed port");
        }
    }

    #[test]
    fn dont_fragment_is_set_on_exactly_the_probes_the_c_sets_it_on() {
        let p = params();
        let df_set = [OsProbe::T(2), OsProbe::T(4), OsProbe::T(6), OsProbe::Ie(0)];
        for probe in OsProbe::all() {
            let bytes = build_probe(probe, &p).unwrap();
            let ip = Ipv4Header::parse(&bytes).expect("ipv4 parses");
            assert_eq!(
                ip.df(),
                df_set.contains(&probe),
                "{probe:?}: DF flag disagrees with the C"
            );
        }
    }

    #[test]
    fn the_ecn_probe_sets_a_reserved_bit_and_a_nonsense_urgent_pointer() {
        let p = params();
        let (_, tcp) = tcp_of(&build_probe(OsProbe::Ecn, &p).unwrap());
        assert_eq!(tcp.flags, TH_CWR | TH_ECE | TH_SYN);
        assert_eq!(tcp.reserved, 8, "reserved bit 3 must be set");
        assert_eq!(tcp.urgent_ptr, 63477);
        // ECN is the only TCP probe with a zero acknowledgement number.
        assert_eq!(tcp.ack, 0);
        for probe in OsProbe::all() {
            if matches!(probe, OsProbe::Ecn | OsProbe::Ie(_) | OsProbe::U1) {
                continue;
            }
            let (_, other) = tcp_of(&build_probe(probe, &p).unwrap());
            assert_eq!(other.ack, p.tcp_ack, "{probe:?} acknowledgement number");
            assert_eq!(other.reserved, 0, "{probe:?} must not set a reserved bit");
        }
    }

    #[test]
    fn the_two_ie_probes_differ_in_code_tos_and_length() {
        let p = params();
        let first = build_probe(OsProbe::Ie(0), &p).unwrap();
        let second = build_probe(OsProbe::Ie(1), &p).unwrap();

        let ip0 = Ipv4Header::parse(&first).expect("ipv4");
        let ip1 = Ipv4Header::parse(&second).expect("ipv4");
        assert_eq!(ip0.tos, TOS_DEFAULT);
        assert_eq!(ip1.tos, TOS_RELIABILITY);
        assert!(ip0.df());
        assert!(!ip1.df());

        let body = |pkt: &[u8], ip: &Ipv4Header| {
            let off = usize::from(ip.ihl).saturating_mul(4);
            pkt[off..].to_vec()
        };
        let b0 = body(&first, &ip0);
        let b1 = body(&second, &ip1);
        assert_eq!(b0[0], ICMP_ECHO);
        assert_eq!(b0[1], 9, "the first IE probe uses an undefined echo code");
        assert_eq!(b1[1], 0);
        assert_eq!(u16::from_be_bytes([b0[4], b0[5]]), p.icmp_echo_id);
        assert_eq!(
            u16::from_be_bytes([b1[4], b1[5]]),
            p.icmp_echo_id.wrapping_add(1)
        );
        assert_eq!(u16::from_be_bytes([b0[6], b0[7]]), ICMP_ECHO_SEQ);
        assert_eq!(u16::from_be_bytes([b1[6], b1[7]]), ICMP_ECHO_SEQ + 1);
        // 8-byte ICMP header plus the payload, which is all zero bytes.
        assert_eq!(b0.len(), 8 + 120);
        assert_eq!(b1.len(), 8 + 150);
        assert!(b0[8..].iter().all(|&b| b == 0));
        assert!(b1[8..].iter().all(|&b| b == 0));
    }

    #[test]
    fn the_udp_probe_carries_three_hundred_c_bytes_and_a_fixed_ip_id() {
        let p = params();
        let pkt = build_probe(OsProbe::U1, &p).unwrap();
        let ip = Ipv4Header::parse(&pkt).expect("ipv4");
        assert_eq!(ip.id, UDP_IP_ID, "U1's IP ID is fixed, not random");
        assert_eq!(ip.ttl, p.udp_ttl, "U1 has its own TTL");
        assert!(!ip.df());

        let off = usize::from(ip.ihl).saturating_mul(4);
        let udp = UdpHeader::parse(&pkt[off..]).expect("udp");
        assert_eq!(udp.sport, p.udp_port_base);
        assert_eq!(udp.dport, 43210);
        assert_eq!(usize::from(udp.length), 8 + UDP_DATA_LEN);
        let data = &pkt[off + 8..];
        assert_eq!(data.len(), UDP_DATA_LEN);
        assert!(data.iter().all(|&b| b == UDP_PATTERN_BYTE));
    }

    #[test]
    fn the_tcp_and_icmp_probes_share_the_callers_ttl_and_ip_id() {
        let p = params();
        for probe in OsProbe::all() {
            if probe == OsProbe::U1 {
                continue;
            }
            let bytes = build_probe(probe, &p).unwrap();
            let ip = Ipv4Header::parse(&bytes).expect("ipv4");
            assert_eq!(ip.ttl, p.ttl, "{probe:?} TTL");
            assert_eq!(ip.id, p.ip_id, "{probe:?} IP ID");
            assert_eq!(ip.src, p.src);
            assert_eq!(ip.dst, p.dst);
        }
    }

    #[test]
    fn a_missing_port_is_an_error_not_a_silently_skipped_probe() {
        // The C's senders `return` early when the port they need is missing, so the
        // caller cannot tell an unsent probe from an unanswered one.
        let mut p = params();
        p.open_tcp_port = None;
        for probe in [
            OsProbe::Seq(0),
            OsProbe::Ops(3),
            OsProbe::Ecn,
            OsProbe::T(1),
            OsProbe::T(4),
        ] {
            assert_eq!(
                build_probe(probe, &p),
                Err(ProbeError::NoOpenTcpPort),
                "{probe:?}"
            );
        }
        // The probes that do not need an open port still build.
        for probe in [OsProbe::T(5), OsProbe::Ie(0), OsProbe::U1] {
            assert!(build_probe(probe, &p).is_ok(), "{probe:?}");
        }

        let mut p = params();
        p.closed_tcp_port = None;
        for n in 5..=7u8 {
            assert_eq!(
                build_probe(OsProbe::T(n), &p),
                Err(ProbeError::NoClosedTcpPort)
            );
        }
        assert!(build_probe(OsProbe::T(1), &p).is_ok());

        let mut p = params();
        p.closed_udp_port = None;
        assert_eq!(
            build_probe(OsProbe::U1, &p),
            Err(ProbeError::NoClosedUdpPort)
        );
    }

    #[test]
    fn a_zero_port_is_rejected_the_way_the_c_rejects_it() {
        let mut p = params();
        p.closed_udp_port = Some(0);
        assert_eq!(
            build_probe(OsProbe::U1, &p),
            Err(ProbeError::NoClosedUdpPort)
        );
        let mut p = params();
        p.udp_port_base = 0;
        assert_eq!(
            build_probe(OsProbe::U1, &p),
            Err(ProbeError::NoClosedUdpPort)
        );
    }

    #[test]
    fn an_out_of_range_probe_index_is_an_error_not_an_abort() {
        // Each of these hits an `assert()` in the C.
        let p = params();
        for probe in [
            OsProbe::Seq(NUM_SEQ_SAMPLES),
            OsProbe::Seq(255),
            OsProbe::Ops(NUM_SEQ_SAMPLES),
            OsProbe::T(0),
            OsProbe::T(8),
            OsProbe::Ie(2),
        ] {
            assert_eq!(
                build_probe(probe, &p),
                Err(ProbeError::UnknownProbe(probe)),
                "{probe:?}"
            );
            assert_eq!(source_port(probe, &p), None, "{probe:?}");
        }
    }

    #[test]
    fn building_is_deterministic() {
        // No clock, no randomness: the same parameters must always produce the same
        // bytes. This is what makes the probes reproducible in a differential run.
        let p = params();
        for probe in OsProbe::all() {
            let a = build_probe(probe, &p).unwrap();
            let b = build_probe(probe, &p).unwrap();
            assert_eq!(a, b, "{probe:?}");
        }
    }

    #[test]
    fn port_offsets_wrap_rather_than_saturate() {
        // The C computes the offsets as `int` and truncates into a `u16` parameter.
        let mut p = params();
        p.tcp_port_base = 65530;
        assert_eq!(source_port(OsProbe::Seq(0), &p), Some(65530));
        assert_eq!(
            source_port(OsProbe::T(7), &p),
            Some(65530u16.wrapping_add(19))
        );
        assert!(build_probe(OsProbe::T(7), &p).is_ok());
    }
}
