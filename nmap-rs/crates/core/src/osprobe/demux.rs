//! Attributing a captured reply to the probe that caused it.
//!
//! The OS-detection battery puts 23 differently-shaped packets on the wire at once, and
//! the replies come back interleaved on a shared capture. Before any of them can be
//! analysed they must be matched to the probe that provoked them — and getting that wrong
//! is worse than dropping the reply, because an attribute recorded against the wrong test
//! silently produces a fingerprint that matches the wrong OS.
//!
//! Each probe carries its own identity on the wire, so attribution never has to guess:
//!
//! * **TCP** probes each use a distinct **source** port ([`source_port`]), so a reply's
//!   *destination* port names the probe.
//! * **`IE`** echo probes carry an ICMP identifier and sequence; the second uses the
//!   first's values plus one.
//! * **`U1`** is found by the UDP source port **quoted back inside** the ICMP error.
//!
//! Everything here is a pure function of the frame bytes, which are entirely
//! attacker-chosen: a hostile target picks every field it echoes. Parsing is therefore
//! done with checked slicing throughout, and anything that does not match a probe we
//! actually sent yields `None` rather than being forced into the nearest slot.

use super::build::{source_port, OsProbe, ProbeParams};
use super::icmpreply::{EchoReply, UdpErrorReply};
use super::tcpreply::TcpReply;
use crate::icmp_quote::ipv4_offset;

/// ICMP type for an echo reply.
const ICMP_ECHO_REPLY: u8 = 0;
/// ICMP type/code for a destination-unreachable, port-unreachable error.
const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_CODE_PORT_UNREACH: u8 = 3;
/// IP protocol numbers we probe with.
const PROTO_TCP: u8 = 6;
const PROTO_ICMP: u8 = 1;
/// Minimum IPv4 header length.
const IP_MIN_HEADER: usize = 20;
/// Minimum TCP header length.
const TCP_MIN_HEADER: usize = 20;
/// The Don't-Fragment bit within the IPv4 flags/fragment field.
const IP_FLAG_DF: u16 = 0x4000;

/// A reply, in the shape the matching analysis expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeReply {
    /// A TCP segment, answering a `SEQ`/`OPS`/`ECN`/`T1`–`T7` probe.
    Tcp(TcpReply),
    /// An ICMP echo reply, answering an `IE` probe.
    Echo(EchoReply),
    /// An ICMP port-unreachable, answering the `U1` probe.
    UdpError(UdpErrorReply),
}

/// A reply matched to its probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demuxed {
    /// Which probe this answers.
    pub probe: OsProbe,
    /// The reply itself.
    pub reply: ProbeReply,
    /// IP identification from the reply's own header, which the `SEQ` test's `TI`/`CI`/`II`
    /// attributes classify.
    pub ip_id: u16,
}

fn be16(buf: &[u8], off: usize) -> Option<u16> {
    let hi = *buf.get(off)?;
    let lo = *buf.get(off.checked_add(1)?)?;
    Some(u16::from(hi) << 8 | u16::from(lo))
}

fn be32(buf: &[u8], off: usize) -> Option<u32> {
    let hi = be16(buf, off)?;
    let lo = be16(buf, off.checked_add(2)?)?;
    Some(u32::from(hi) << 16 | u32::from(lo))
}

/// The TCP timestamp option's `TSval`, or `None` when the option is absent.
///
/// The `SEQ` test's `TS` attribute is a *frequency*, derived from how these values advance
/// between probes, so the driver needs the raw number rather than the rendered attribute.
#[must_use]
pub fn tcp_timestamp(segment: &[u8]) -> Option<u32> {
    let data_offset = usize::from(segment.get(12)? >> 4).checked_mul(4)?;
    if data_offset < TCP_MIN_HEADER {
        return None;
    }
    let options = segment.get(TCP_MIN_HEADER..data_offset)?;
    let mut i = 0usize;
    while i < options.len() {
        match options.get(i)? {
            // End of option list.
            0 => return None,
            // No-op: one byte, no length field.
            1 => i = i.checked_add(1)?,
            kind => {
                let len = usize::from(*options.get(i.checked_add(1)?)?);
                // A length below 2 would not advance, so the walk would never terminate.
                if len < 2 {
                    return None;
                }
                if *kind == 8 && len >= 10 {
                    return be32(options, i.checked_add(2)?);
                }
                i = i.checked_add(len)?;
            }
        }
    }
    None
}

/// Match one captured frame to the probe it answers.
///
/// Returns `None` for anything that is not a reply to a probe we sent — including frames
/// from another host, protocols we did not probe with, and replies whose identifying port
/// or ICMP identifier does not correspond to any probe in the battery.
#[must_use]
pub fn demux(frame: &[u8], eth_included: bool, params: &ProbeParams) -> Option<Demuxed> {
    let off = ipv4_offset(frame, eth_included)?;
    let ip = frame.get(off..)?;

    // The reply must come from the host we probed; otherwise it belongs to someone else's
    // conversation and attributing it here would corrupt this host's fingerprint.
    let src = ip.get(12..16)?;
    if src != params.dst.as_slice() {
        return None;
    }

    let ihl = usize::from(ip.first()? & 0x0f).checked_mul(4)?;
    if ihl < IP_MIN_HEADER {
        return None;
    }
    let ip_id = be16(ip, 4)?;
    let flags_frag = be16(ip, 6)?;
    let df = flags_frag & IP_FLAG_DF != 0;
    let ttl = *ip.get(8)?;
    let total_len = be16(ip, 2)?;
    let protocol = *ip.get(9)?;
    let payload = ip.get(ihl..)?;

    match protocol {
        PROTO_TCP => demux_tcp(payload, params, df, ttl, ip_id),
        PROTO_ICMP => demux_icmp(payload, params, df, ttl, ip_id, total_len),
        // We never probe with anything else, so a reply carrying another protocol is not
        // ours to interpret.
        _ => None,
    }
}

/// A TCP reply, identified by the destination port it came back to.
fn demux_tcp(
    segment: &[u8],
    params: &ProbeParams,
    df: bool,
    ttl: u8,
    ip_id: u16,
) -> Option<Demuxed> {
    let dport = be16(segment, 2)?;
    // Which probe used that source port? Only the TCP probes are candidates.
    let probe = OsProbe::all().into_iter().find(|&p| {
        !matches!(p, OsProbe::U1 | OsProbe::Ie(_)) && source_port(p, params) == Some(dport)
    })?;

    let data_offset = usize::from(segment.get(12)? >> 4).checked_mul(4)?;
    if data_offset < TCP_MIN_HEADER || segment.len() < TCP_MIN_HEADER {
        return None;
    }

    let reply = TcpReply {
        df,
        ttl,
        window: be16(segment, 14)?,
        seq: be32(segment, 4)?,
        ack: be32(segment, 8)?,
        flags: *segment.get(13)?,
        // The four reserved bits sit in the low nibble of byte 12.
        reserved: segment.get(12)? & 0x0f,
        urgent_ptr: be16(segment, 18)?,
        segment: segment.to_vec(),
    };
    Some(Demuxed {
        probe,
        reply: ProbeReply::Tcp(reply),
        ip_id,
    })
}

/// An ICMP reply: either an `IE` echo reply or the `U1` port-unreachable.
fn demux_icmp(
    icmp: &[u8],
    params: &ProbeParams,
    df: bool,
    ttl: u8,
    ip_id: u16,
    total_len: u16,
) -> Option<Demuxed> {
    let icmp_type = *icmp.first()?;
    let icmp_code = *icmp.get(1)?;

    if icmp_type == ICMP_ECHO_REPLY {
        // The two echo probes are told apart by the identifier and sequence we chose; the
        // second probe used the first's values plus one.
        let id = be16(icmp, 4)?;
        let seq = be16(icmp, 6)?;
        let probe = if id == params.icmp_echo_id && seq == params.icmp_echo_seq {
            OsProbe::Ie(0)
        } else if id == params.icmp_echo_id.wrapping_add(1)
            && seq == params.icmp_echo_seq.wrapping_add(1)
        {
            OsProbe::Ie(1)
        } else {
            return None;
        };
        return Some(Demuxed {
            probe,
            reply: ProbeReply::Echo(EchoReply { df, icmp_code, ttl }),
            ip_id,
        });
    }

    if icmp_type == ICMP_DEST_UNREACH && icmp_code == ICMP_CODE_PORT_UNREACH {
        // Everything after the 8-byte ICMP header is our own datagram, echoed back.
        let quote = icmp.get(8..)?;
        // Confirm it really is our `U1` probe before claiming it: the quoted UDP source
        // port must be the one we sent from. `u1_test` re-checks both ports against what
        // was sent, so a quote that merely looks plausible here is still rejected there.
        let quoted_ihl = usize::from(quote.first()? & 0x0f).checked_mul(4)?;
        if quoted_ihl < IP_MIN_HEADER {
            return None;
        }
        let quoted_sport = be16(quote, quoted_ihl)?;
        if quoted_sport != params.udp_port_base {
            return None;
        }
        return Some(Demuxed {
            probe: OsProbe::U1,
            reply: ProbeReply::UdpError(UdpErrorReply {
                outer_df: df,
                outer_ttl: ttl,
                outer_total_len: total_len,
                icmp_unused: be32(icmp, 4)?,
                quote: quote.to_vec(),
            }),
            ip_id,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osprobe::build::{build_probe, ICMP_ECHO_SEQ};

    fn params() -> ProbeParams {
        ProbeParams {
            src: [10, 0, 0, 1],
            dst: [10, 0, 0, 2],
            ttl: 64,
            udp_ttl: 57,
            ip_id: 0x1111,
            tcp_port_base: 40000,
            udp_port_base: 44444,
            tcp_seq_base: 0x1000_0000,
            tcp_ack: 0,
            icmp_echo_id: 0x1234,
            icmp_echo_seq: ICMP_ECHO_SEQ,
            open_tcp_port: Some(22),
            closed_tcp_port: Some(1),
            closed_udp_port: Some(65000),
        }
    }

    /// A bare IPv4 packet with the given protocol and payload.
    fn ipv4(p: &ProbeParams, proto: u8, ttl: u8, ip_id: u16, df: bool, payload: &[u8]) -> Vec<u8> {
        let total = 20usize.saturating_add(payload.len());
        let mut v = vec![0u8; 20];
        v[0] = 0x45;
        v[2] = u8::try_from(total >> 8).unwrap_or(0);
        v[3] = u8::try_from(total & 0xff).unwrap_or(0);
        v[4] = u8::try_from(ip_id >> 8).unwrap_or(0);
        v[5] = u8::try_from(ip_id & 0xff).unwrap_or(0);
        if df {
            v[6] = 0x40;
        }
        v[8] = ttl;
        v[9] = proto;
        v[12..16].copy_from_slice(&p.dst); // from the target
        v[16..20].copy_from_slice(&p.src);
        v.extend_from_slice(payload);
        v
    }

    /// A TCP segment addressed back to `dport`.
    fn tcp(dport: u16, seq: u32, ack: u32, flags: u8, window: u16) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&22u16.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&window.to_be_bytes());
        t
    }

    #[test]
    fn every_tcp_probe_is_attributed_to_itself() {
        let p = params();
        // Each TCP probe used a distinct source port, so its reply must come back to
        // exactly that probe — never to a neighbour.
        for probe in OsProbe::all() {
            let Some(sport) = source_port(probe, &p) else {
                continue;
            };
            if matches!(probe, OsProbe::U1 | OsProbe::Ie(_)) {
                continue;
            }
            let frame = ipv4(&p, PROTO_TCP, 61, 7, true, &tcp(sport, 99, 1, 0x12, 1024));
            let d = demux(&frame, false, &p).unwrap_or_else(|| panic!("{probe:?} not matched"));
            assert_eq!(d.probe, probe, "reply attributed to the wrong probe");
            assert_eq!(d.ip_id, 7);
            match d.reply {
                ProbeReply::Tcp(t) => {
                    assert_eq!(t.seq, 99);
                    assert_eq!(t.window, 1024);
                    assert!(t.df);
                    assert_eq!(t.ttl, 61);
                }
                other => panic!("expected a TCP reply, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_reply_from_another_host_is_never_attributed() {
        let p = params();
        let sport = source_port(OsProbe::Seq(0), &p).expect("port");
        let mut frame = ipv4(&p, PROTO_TCP, 61, 7, true, &tcp(sport, 1, 1, 0x12, 1));
        // Same port, different source address: it belongs to someone else's conversation.
        frame[12..16].copy_from_slice(&[10, 0, 0, 99]);
        assert!(demux(&frame, false, &p).is_none());
    }

    #[test]
    fn an_unknown_port_matches_no_probe() {
        let p = params();
        let frame = ipv4(&p, PROTO_TCP, 61, 7, true, &tcp(9999, 1, 1, 0x12, 1));
        assert!(demux(&frame, false, &p).is_none());
    }

    #[test]
    fn the_two_echo_probes_are_told_apart() {
        let p = params();
        let echo = |id: u16, seq: u16, code: u8| {
            let mut i = vec![0u8; 8];
            i[0] = ICMP_ECHO_REPLY;
            i[1] = code;
            i[4..6].copy_from_slice(&id.to_be_bytes());
            i[6..8].copy_from_slice(&seq.to_be_bytes());
            i
        };

        let f0 = ipv4(
            &p,
            PROTO_ICMP,
            61,
            3,
            false,
            &echo(p.icmp_echo_id, p.icmp_echo_seq, 0),
        );
        let d0 = demux(&f0, false, &p).expect("first echo");
        assert_eq!(d0.probe, OsProbe::Ie(0));

        let f1 = ipv4(
            &p,
            PROTO_ICMP,
            61,
            3,
            true,
            &echo(
                p.icmp_echo_id.wrapping_add(1),
                p.icmp_echo_seq.wrapping_add(1),
                9,
            ),
        );
        let d1 = demux(&f1, false, &p).expect("second echo");
        assert_eq!(d1.probe, OsProbe::Ie(1));
        match d1.reply {
            ProbeReply::Echo(e) => {
                assert!(e.df);
                assert_eq!(e.icmp_code, 9);
            }
            other => panic!("expected an echo reply, got {other:?}"),
        }

        // An echo reply we did not solicit is not ours.
        let stray = ipv4(&p, PROTO_ICMP, 61, 3, false, &echo(0xbeef, 1, 0));
        assert!(demux(&stray, false, &p).is_none());
    }

    #[test]
    fn u1_is_found_by_the_quoted_source_port() {
        let p = params();
        // Quote back a plausible copy of our own UDP probe.
        let mut quote = vec![0u8; 28];
        quote[0] = 0x45;
        quote[9] = 17;
        quote[20..22].copy_from_slice(&p.udp_port_base.to_be_bytes());
        quote[22..24].copy_from_slice(&65000u16.to_be_bytes());

        let mut icmp = vec![0u8; 8];
        icmp[0] = ICMP_DEST_UNREACH;
        icmp[1] = ICMP_CODE_PORT_UNREACH;
        icmp.extend_from_slice(&quote);

        let frame = ipv4(&p, PROTO_ICMP, 57, 5, false, &icmp);
        let d = demux(&frame, false, &p).expect("U1");
        assert_eq!(d.probe, OsProbe::U1);
        match d.reply {
            ProbeReply::UdpError(u) => {
                assert_eq!(u.outer_ttl, 57);
                assert_eq!(u.quote.len(), 28);
                assert!(!u.outer_df);
            }
            other => panic!("expected a UDP error, got {other:?}"),
        }

        // A quote naming a port we never sent from is not our probe.
        let mut wrong = icmp.clone();
        wrong[8 + 20..8 + 22].copy_from_slice(&1234u16.to_be_bytes());
        let frame = ipv4(&p, PROTO_ICMP, 57, 5, false, &wrong);
        assert!(demux(&frame, false, &p).is_none());
    }

    #[test]
    fn other_icmp_types_are_ignored() {
        let p = params();
        // Time-exceeded is a real ICMP error but answers none of our probes.
        let mut icmp = vec![0u8; 8];
        icmp[0] = 11;
        icmp.extend_from_slice(&[0x45, 0, 0, 28, 0, 0, 0, 0, 0, 17, 0, 0]);
        let frame = ipv4(&p, PROTO_ICMP, 61, 1, false, &icmp);
        assert!(demux(&frame, false, &p).is_none());
    }

    #[test]
    fn truncated_frames_are_rejected_without_panicking() {
        let p = params();
        let sport = source_port(OsProbe::Seq(0), &p).expect("port");
        let full = ipv4(&p, PROTO_TCP, 61, 7, true, &tcp(sport, 1, 1, 0x12, 1));
        // Every prefix must be handled; none may panic.
        for n in 0..full.len() {
            let _ = demux(&full[..n], false, &p);
        }
        assert!(demux(&[], false, &p).is_none());
    }

    #[test]
    fn the_timestamp_option_is_found_wherever_it_sits() {
        // MSS, NOP, then timestamp: the walk must skip variable-length options correctly.
        let mut seg = vec![0u8; 20];
        let opts: Vec<u8> = vec![
            0x02, 0x04, 0x05, 0xb4, // MSS
            0x01, // NOP
            0x08, 0x0a, 0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x13, 0x88, // TS
            0x00, // EOL
        ];
        seg.extend_from_slice(&opts);
        while seg.len() % 4 != 0 {
            seg.push(0);
        }
        let off = u8::try_from(seg.len() / 4).unwrap_or(5);
        seg[12] = off << 4;
        assert_eq!(tcp_timestamp(&seg), Some(0x2710));

        // No options at all.
        let mut bare = vec![0u8; 20];
        bare[12] = 5 << 4;
        assert_eq!(tcp_timestamp(&bare), None);

        // A zero-length option must not spin forever.
        let mut bad = vec![0u8; 20];
        bad.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
        bad[12] = 6 << 4;
        assert_eq!(tcp_timestamp(&bad), None);
    }

    #[test]
    fn a_built_probes_reply_round_trips_through_its_own_source_port() {
        // Tie demux to the builder: take the port the builder actually put on the wire
        // and confirm a reply to it comes back to the same probe.
        let p = params();
        for probe in [
            OsProbe::Seq(3),
            OsProbe::Ops(5),
            OsProbe::Ecn,
            OsProbe::T(4),
        ] {
            let packet = build_probe(probe, &p).expect("probe builds");
            // Source port is bytes 20..22 of the built IPv4+TCP packet.
            let sport = u16::from_be_bytes([packet[20], packet[21]]);
            assert_eq!(Some(sport), source_port(probe, &p));
            let frame = ipv4(&p, PROTO_TCP, 61, 1, true, &tcp(sport, 1, 1, 0x12, 1));
            assert_eq!(demux(&frame, false, &p).map(|d| d.probe), Some(probe));
        }
    }
}
