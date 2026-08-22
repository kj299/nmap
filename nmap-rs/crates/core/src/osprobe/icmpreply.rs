//! Attribute extraction from ICMP-shaped probe replies — ports `processTUdpResp`
//! (the `U1` test) and `processTIcmpResp` (the `IE` test) from `osscan2.cc`.
//!
//! Both replies are ICMP: `U1` is the *port-unreachable* error the target sends when the
//! `U1` probe hits a closed UDP port, and `IE` is the pair of *echo replies* the two `IE`
//! probes elicit. Between them they carry two things nothing else in the battery does:
//!
//! * how faithfully the target **quotes back** the packet we sent it (`U1`), which
//!   exposes stacks that mangle the IP ID, recompute a checksum, or truncate the data;
//! * the true **hop distance** to the target — the `U1` quote contains our packet's TTL
//!   *as it arrived*, and the difference from the TTL we sent is the hop count. That
//!   number is what lets [`crate::osprobe::tcpreply::finalize_ttl`] turn every test's
//!   observed TTL into the initial TTL the database stores, so `U1` is load-bearing for
//!   the whole fingerprint even though it contributes only one test itself.
//!
//! The quoted packet is attacker-controlled — a hostile target chooses exactly how to
//! echo our probe back — so the quote is parsed with checked slicing throughout, and a
//! malformed quote yields `None` rather than a panic.

use crate::checksum::in_cksum;
use crate::osdb::model::{FingerTest, TestId};
use crate::osprobe::build::{UDP_DATA_LEN, UDP_IP_ID, UDP_PATTERN_BYTE};

/// Total length of the `U1` datagram we send: 20-byte IP header + 8-byte UDP header +
/// the payload. A quote returning exactly this length reflected our packet untouched,
/// which the `RIPL` attribute records as the "good" value `G`.
const U1_SENT_IP_LEN: u16 = 328;
/// Tie the literal above to the source constant without a truncating cast: 28 + 300 = 328.
const _: () = assert!(28 + UDP_DATA_LEN == U1_SENT_IP_LEN as usize);

/// What the `U1` probe put on the wire, needed to judge how faithfully the target quoted
/// it back. The driver fills this from the datagram it built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U1Sent {
    /// Source port of the probe.
    pub sport: u16,
    /// Destination (closed) port of the probe.
    pub dport: u16,
    /// The UDP checksum we placed on the probe. `RUCK` compares the quoted checksum
    /// against *this exact value* — as the C does — so a target that alters the packet
    /// and recomputes a fresh valid checksum is still caught, which recomputing from the
    /// quote would miss.
    pub udp_checksum: u16,
    /// TTL the probe was sent with, for the hop-distance calculation.
    pub ttl: u8,
}

/// The received ICMP port-unreachable error, split into the outer header fields this
/// analysis reads and the raw **quoted** datagram (our original packet, as the target
/// echoed it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpErrorReply {
    /// Don't-Fragment on the *error*'s IP header.
    pub outer_df: bool,
    /// TTL of the *error*'s IP header.
    pub outer_ttl: u8,
    /// Total length of the *error*'s IP datagram (`IPL`).
    pub outer_total_len: u16,
    /// The 4-byte "unused" field of the ICMP dest-unreachable message (`UN`); a
    /// conforming stack leaves it zero.
    pub icmp_unused: u32,
    /// The quoted original IP datagram — everything after the 8-byte ICMP header. This is
    /// our own `U1` packet as the target chose to echo it, and is fully attacker-shaped.
    pub quote: Vec<u8>,
}

/// The outcome of the `U1` analysis: the `U1` test plus the derived hop distance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U1Result {
    /// The `U1` fingerprint test.
    pub test: FingerTest,
    /// Hops to the target, or `None` if the quote's TTL made the count nonsensical.
    /// Feeds [`crate::osprobe::tcpreply::finalize_ttl`] for **every** test's TTL.
    pub distance: Option<u8>,
}

/// One `IE` echo reply's fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoReply {
    /// Don't-Fragment on the reply's IP header.
    pub df: bool,
    /// The reply's ICMP code.
    pub icmp_code: u8,
    /// The reply's IP TTL.
    pub ttl: u8,
}

/// Uppercase hex without leading zeros, matching the C's `cp_hex`.
fn hex(v: u32) -> String {
    format!("{v:X}")
}

/// Set `attr` on `test`, ignoring an attribute the test does not define.
fn set(test: &mut FingerTest, attr: &str, value: String) {
    if let Some(i) = test.id.attr_index(attr) {
        if let Some(slot) = test.values.get_mut(i) {
            *slot = Some(value);
        }
    }
}

/// Read a big-endian `u16` at `off`, or `None` if it runs past the end.
fn be16(buf: &[u8], off: usize) -> Option<u16> {
    let hi = *buf.get(off)?;
    let lo = *buf.get(off.checked_add(1)?)?;
    Some(u16::from(hi) << 8 | u16::from(lo))
}

/// Build the `U1` test from a received ICMP port-unreachable, or `None` if the quote is
/// too short, has an implausible header length, or does not quote back the ports we sent.
///
/// The C `assert`s the ICMP type/code is 3/3 before entry; the caller is expected to have
/// dispatched on that, so this takes the quote directly.
#[must_use]
pub fn u1_test(reply: &UdpErrorReply, sent: &U1Sent) -> Option<U1Result> {
    let quote = reply.quote.as_slice();

    // The quote must hold at least a minimal IP header (20) plus a UDP header (8).
    if quote.len() < 28 {
        return None;
    }
    // Quoted IP header length, from its IHL nibble. Below 20 is malformed; the UDP header
    // must also fit after it.
    let ihl = usize::from(quote.first().copied().unwrap_or(0) & 0x0f).saturating_mul(4);
    if ihl < 20 || quote.len() < ihl.saturating_add(8) {
        return None;
    }

    // The quoted UDP ports must be the ones we sent, or this is not our probe's echo.
    let quoted_sport = be16(quote, ihl)?;
    let quoted_dport = be16(quote, ihl.saturating_add(2))?;
    if quoted_sport != sent.sport || quoted_dport != sent.dport {
        return None;
    }

    let mut test = FingerTest::new(TestId::U1);
    set(&mut test, "R", "Y".to_owned());
    set(
        &mut test,
        "DF",
        if reply.outer_df { "Y" } else { "N" }.to_owned(),
    );
    set(&mut test, "T", hex(u32::from(reply.outer_ttl)));
    // How large the returned error datagram is, and whether the unused ICMP field leaked.
    set(&mut test, "IPL", hex(u32::from(reply.outer_total_len)));
    set(&mut test, "UN", hex(reply.icmp_unused));

    // Returned IP total length: the shipped fingerprints record `G` for an untouched
    // echo and the literal value otherwise.
    let quoted_ip_len = be16(quote, 2)?;
    set(
        &mut test,
        "RIPL",
        if quoted_ip_len == U1_SENT_IP_LEN {
            "G".to_owned()
        } else {
            hex(u32::from(quoted_ip_len))
        },
    );

    // Returned IP ID: `G` if the fixed value we sent survived, else the value we got.
    let quoted_ip_id = be16(quote, 4)?;
    set(
        &mut test,
        "RID",
        if quoted_ip_id == UDP_IP_ID {
            "G".to_owned()
        } else {
            hex(u32::from(quoted_ip_id))
        },
    );

    set(&mut test, "RIPCK", ripck(quote));
    set(&mut test, "RUCK", ruck(quote, ihl, sent.udp_checksum));
    set(&mut test, "RUD", rud(quote, ihl));

    // Hop distance: the TTL we sent minus the TTL the packet had when the target quoted
    // it, plus one. The quote's TTL is attacker-chosen, so a value above what we sent
    // would make the C's `int` go negative; here it yields `None` rather than a bogus
    // hop count that would then corrupt every test's TTL.
    let quoted_ttl = quote.get(8).copied().unwrap_or(0);
    let distance = i32::from(sent.ttl)
        .checked_sub(i32::from(quoted_ttl))
        .and_then(|d| d.checked_add(1))
        .filter(|d| (0..=255).contains(d))
        .and_then(|d| u8::try_from(d).ok());

    Some(U1Result { test, distance })
}

/// The `RIPCK` attribute: whether the quoted IP header's checksum still validates.
///
/// `Z` when the field is zero, `G` when it recomputes correctly, `I` when the target
/// modified the header (or its checksum) so the two disagree.
fn ripck(quote: &[u8]) -> String {
    let Some(stored) = be16(quote, 10) else {
        return "I".to_owned();
    };
    if stored == 0 {
        return "Z".to_owned();
    }
    let Some(header) = quote.get(..20) else {
        return "I".to_owned();
    };
    // Recompute over the 20-byte header with the checksum field zeroed.
    let mut buf = [0u8; 20];
    buf.copy_from_slice(header);
    buf[10] = 0;
    buf[11] = 0;
    if in_cksum(&buf) == stored {
        "G".to_owned()
    } else {
        "I".to_owned()
    }
}

/// The `RUCK` attribute: `G` when the quoted UDP checksum still equals the one we placed
/// on the probe, else the quoted value in hex. A stack that clears or recomputes the
/// checksum reveals itself.
fn ruck(quote: &[u8], ihl: usize, sent_checksum: u16) -> String {
    let Some(stored) = be16(quote, ihl.saturating_add(6)) else {
        return "0".to_owned();
    };
    if stored == sent_checksum {
        "G".to_owned()
    } else {
        hex(u32::from(stored))
    }
}

/// The `RUD` attribute: `G` if the quoted UDP payload is our unbroken pattern, `I` if any
/// byte was altered.
fn rud(quote: &[u8], ihl: usize) -> String {
    let data_start = ihl.saturating_add(8);
    let data = quote.get(data_start..).unwrap_or_default();
    if data.iter().all(|&b| b == UDP_PATTERN_BYTE) {
        "G".to_owned()
    } else {
        "I".to_owned()
    }
}

/// Build the `IE` test from the two echo replies.
///
/// `probe0` and `probe1` are the replies to the first and second `IE` probes **by probe
/// number**, which is what the `DFI`/`CD` comparisons key on — the first probe was sent
/// with DF set and an ICMP code of 9, the second with DF clear and code 0, so `S`
/// ("same as the sender used") means each reply echoed its own probe's value.
///
/// `t_ttl` is the TTL recorded in `T`. The C uses the TTL of whichever reply arrived
/// **second** (the one that completed the pair); the caller, which sees arrival order,
/// supplies it. In practice both replies come from the same host moments apart and carry
/// the same TTL.
#[must_use]
pub fn ie_test(probe0: &EchoReply, probe1: &EchoReply, t_ttl: u8) -> FingerTest {
    let mut test = FingerTest::new(TestId::Ie);
    set(&mut test, "R", "Y".to_owned());

    // DFI: how the two replies handled Don't-Fragment relative to the probes.
    let dfi = match (probe0.df, probe1.df) {
        (true, true) => "Y",   // both set it
        (true, false) => "S",  // each echoed the sender's setting
        (false, false) => "N", // neither set it
        (false, true) => "O",  // anything else
    };
    set(&mut test, "DFI", dfi.to_owned());

    set(&mut test, "T", hex(u32::from(t_ttl)));

    // CD: how the two replies set the ICMP code.
    let cd = if probe0.icmp_code == probe1.icmp_code {
        if probe0.icmp_code == 0 {
            "Z".to_owned()
        } else {
            hex(u32::from(probe0.icmp_code))
        }
    } else if probe0.icmp_code == 9 && probe1.icmp_code == 0 {
        "S".to_owned() // each echoed the code its probe carried
    } else {
        "O".to_owned()
    };
    set(&mut test, "CD", cd);

    test
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::ipv4_pseudoheader_cksum;

    const SENT_SPORT: u16 = 41000;
    const SENT_DPORT: u16 = 43210;
    const SENT_TTL: u8 = 57;

    /// The UDP checksum the reference `quote()` builds, so `RUCK` sees a match.
    fn sent_udp_checksum() -> u16 {
        let mut udp = vec![0u8; 8 + UDP_DATA_LEN];
        udp[0..2].copy_from_slice(&SENT_SPORT.to_be_bytes());
        udp[2..4].copy_from_slice(&SENT_DPORT.to_be_bytes());
        udp[4..6].copy_from_slice(&u16::try_from(8 + UDP_DATA_LEN).unwrap_or(0).to_be_bytes());
        for b in udp.iter_mut().skip(8) {
            *b = UDP_PATTERN_BYTE;
        }
        ipv4_pseudoheader_cksum([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp)
    }

    fn sent() -> U1Sent {
        U1Sent {
            sport: SENT_SPORT,
            dport: SENT_DPORT,
            udp_checksum: sent_udp_checksum(),
            ttl: SENT_TTL,
        }
    }

    /// Build a well-formed quoted `U1` datagram: 20-byte IP header + 8-byte UDP header +
    /// `data_len` pattern bytes, with valid IP and UDP checksums, and `arrived_ttl` as
    /// the TTL the target saw. Returns the quote bytes.
    fn quote(arrived_ttl: u8, data_len: usize) -> Vec<u8> {
        let total = 28usize.saturating_add(data_len);
        let udp_len = 8usize.saturating_add(data_len);
        let mut ip = [0u8; 20];
        ip[0] = 0x45; // version 4, IHL 5
        ip[2..4].copy_from_slice(&u16::try_from(total).unwrap_or(0).to_be_bytes());
        ip[4..6].copy_from_slice(&UDP_IP_ID.to_be_bytes());
        ip[8] = arrived_ttl;
        ip[9] = 17; // UDP
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        let ipck = in_cksum(&ip);
        ip[10..12].copy_from_slice(&ipck.to_be_bytes());

        let mut udp = vec![0u8; udp_len];
        udp[0..2].copy_from_slice(&SENT_SPORT.to_be_bytes());
        udp[2..4].copy_from_slice(&SENT_DPORT.to_be_bytes());
        udp[4..6].copy_from_slice(&u16::try_from(udp_len).unwrap_or(0).to_be_bytes());
        for b in udp.iter_mut().skip(8) {
            *b = UDP_PATTERN_BYTE;
        }
        let uck = ipv4_pseudoheader_cksum([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp);
        udp[6..8].copy_from_slice(&uck.to_be_bytes());

        let mut q = ip.to_vec();
        q.extend_from_slice(&udp);
        q
    }

    fn reply(arrived_ttl: u8, data_len: usize) -> UdpErrorReply {
        UdpErrorReply {
            outer_df: true,
            outer_ttl: 64,
            outer_total_len: 56,
            icmp_unused: 0,
            quote: quote(arrived_ttl, data_len),
        }
    }

    #[test]
    fn a_faithfully_quoted_probe_scores_every_good_value() {
        // The target echoed our packet untouched: every "returned" attribute is G, and
        // the untouched data is G too.
        let r = reply(50, UDP_DATA_LEN);
        let out = u1_test(&r, &sent()).expect("a valid quote");
        let t = &out.test;
        assert_eq!(t.get("R"), Some("Y"));
        assert_eq!(t.get("DF"), Some("Y"));
        assert_eq!(t.get("RIPL"), Some("G"), "the full sent length came back");
        assert_eq!(t.get("RID"), Some("G"), "our IP ID survived");
        assert_eq!(
            t.get("RIPCK"),
            Some("G"),
            "the quoted IP checksum validates"
        );
        assert_eq!(t.get("RUCK"), Some("G"), "the quoted UDP checksum matches");
        assert_eq!(t.get("RUD"), Some("G"), "the payload is unbroken");
        assert_eq!(t.get("UN"), Some("0"));
    }

    #[test]
    fn the_hop_distance_is_the_ttl_we_lost_plus_one() {
        // Sent at 57, arrived at 50: seven hops of decrement, distance 8.
        let out = u1_test(&reply(50, UDP_DATA_LEN), &sent()).unwrap();
        assert_eq!(out.distance, Some(SENT_TTL - 50 + 1));
        // Arrived at the TTL we sent (zero hops, e.g. localhost): distance 1.
        let out = u1_test(&reply(SENT_TTL, UDP_DATA_LEN), &sent()).unwrap();
        assert_eq!(out.distance, Some(1));
    }

    #[test]
    fn a_lying_ttl_yields_no_distance_rather_than_a_negative_one() {
        // A quote claiming a higher TTL than we sent would make the C's int go negative
        // and then corrupt every test's TTL through finalize_ttl.
        let out = u1_test(&reply(SENT_TTL + 10, UDP_DATA_LEN), &sent()).unwrap();
        assert_eq!(out.distance, None);
    }

    #[test]
    fn a_modified_ip_id_is_reported_as_its_value() {
        let mut r = reply(50, UDP_DATA_LEN);
        r.quote[4..6].copy_from_slice(&0xABCDu16.to_be_bytes());
        // The IP checksum is now stale, so RIPCK becomes I and RID the literal value.
        let t = u1_test(&r, &sent()).unwrap().test;
        assert_eq!(t.get("RID"), Some("ABCD"));
        assert_eq!(t.get("RIPCK"), Some("I"), "the header no longer checksums");
    }

    #[test]
    fn a_zero_ip_checksum_is_z_not_i() {
        let mut r = reply(50, UDP_DATA_LEN);
        r.quote[10] = 0;
        r.quote[11] = 0;
        assert_eq!(u1_test(&r, &sent()).unwrap().test.get("RIPCK"), Some("Z"));
    }

    #[test]
    fn a_truncated_returned_length_is_reported_literally() {
        // The target sent back less of our packet than we transmitted.
        let r = reply(50, 100);
        let t = u1_test(&r, &sent()).unwrap().test;
        assert_eq!(t.get("RIPL"), Some(&hex(u32::from(28 + 100u16))[..]));
    }

    #[test]
    fn a_mangled_payload_byte_flips_rud_to_i() {
        let mut r = reply(50, UDP_DATA_LEN);
        let last = r.quote.len() - 1;
        r.quote[last] ^= 0xFF;
        assert_eq!(u1_test(&r, &sent()).unwrap().test.get("RUD"), Some("I"));
    }

    #[test]
    fn a_modified_udp_checksum_is_reported_as_its_value() {
        let mut r = reply(50, UDP_DATA_LEN);
        let ihl = 20;
        r.quote[ihl + 6..ihl + 8].copy_from_slice(&0x1234u16.to_be_bytes());
        assert_eq!(u1_test(&r, &sent()).unwrap().test.get("RUCK"), Some("1234"));
    }

    #[test]
    fn a_quote_for_the_wrong_ports_is_rejected() {
        let mut r = reply(50, UDP_DATA_LEN);
        // Change the quoted source port so it no longer matches our probe.
        r.quote[20..22].copy_from_slice(&12345u16.to_be_bytes());
        assert!(u1_test(&r, &sent()).is_none());
    }

    #[test]
    fn a_short_or_malformed_quote_is_rejected_not_panicked() {
        let s = sent();
        for len in 0..28usize {
            let r = UdpErrorReply {
                outer_df: false,
                outer_ttl: 1,
                outer_total_len: 0,
                icmp_unused: 0,
                quote: vec![0x45; len],
            };
            assert!(u1_test(&r, &s).is_none(), "len {len}");
        }
        // A plausible length but an IHL claiming a header longer than the quote.
        let mut r = reply(50, UDP_DATA_LEN);
        r.quote[0] = 0x4f; // IHL 15 => 60-byte header
        r.quote.truncate(40);
        assert!(u1_test(&r, &s).is_none());
    }

    #[test]
    fn the_unused_icmp_field_is_reported_when_it_leaks() {
        let mut r = reply(50, UDP_DATA_LEN);
        r.icmp_unused = 0xDEAD_BEEF;
        assert_eq!(
            u1_test(&r, &sent()).unwrap().test.get("UN"),
            Some("DEADBEEF")
        );
    }

    #[test]
    fn every_u1_attribute_is_populated() {
        // A silently unset slot would be skipped by the scorer.
        let t = u1_test(&reply(50, UDP_DATA_LEN), &sent()).unwrap().test;
        for attr in t.id.attrs() {
            if *attr == "TG" {
                continue; // resolved later by finalize_ttl
            }
            assert!(t.get(attr).is_some(), "U1 attribute {attr} unset");
        }
    }

    fn echo(df: bool, code: u8, ttl: u8) -> EchoReply {
        EchoReply {
            df,
            icmp_code: code,
            ttl,
        }
    }

    #[test]
    fn ie_reads_the_two_replies_relative_to_the_two_probes() {
        // Probe 0 was sent with DF set and code 9; probe 1 with DF clear and code 0.
        // A stack that echoes each probe's values back is the "S" case.
        let t = ie_test(&echo(true, 9, 64), &echo(false, 0, 64), 64);
        assert_eq!(t.get("R"), Some("Y"));
        assert_eq!(t.get("DFI"), Some("S"), "each echoed its probe's DF");
        assert_eq!(t.get("CD"), Some("S"), "each echoed its probe's code");
        assert_eq!(t.get("T"), Some("40"));
    }

    #[test]
    fn ie_dfi_covers_every_combination() {
        assert_eq!(
            ie_test(&echo(true, 0, 1), &echo(true, 0, 1), 1).get("DFI"),
            Some("Y")
        );
        assert_eq!(
            ie_test(&echo(true, 0, 1), &echo(false, 0, 1), 1).get("DFI"),
            Some("S")
        );
        assert_eq!(
            ie_test(&echo(false, 0, 1), &echo(false, 0, 1), 1).get("DFI"),
            Some("N")
        );
        assert_eq!(
            ie_test(&echo(false, 0, 1), &echo(true, 0, 1), 1).get("DFI"),
            Some("O")
        );
    }

    #[test]
    fn ie_cd_distinguishes_matching_echoed_and_other_codes() {
        // Both zero.
        assert_eq!(
            ie_test(&echo(true, 0, 1), &echo(true, 0, 1), 1).get("CD"),
            Some("Z")
        );
        // Both the same non-zero value: that value in hex.
        assert_eq!(
            ie_test(&echo(true, 5, 1), &echo(true, 5, 1), 1).get("CD"),
            Some("5")
        );
        // The echoed-the-probe case (9, 0).
        assert_eq!(
            ie_test(&echo(true, 9, 1), &echo(true, 0, 1), 1).get("CD"),
            Some("S")
        );
        // Anything else.
        assert_eq!(
            ie_test(&echo(true, 3, 1), &echo(true, 7, 1), 1).get("CD"),
            Some("O")
        );
    }

    #[test]
    fn every_ie_attribute_is_populated() {
        let t = ie_test(&echo(true, 9, 64), &echo(false, 0, 64), 64);
        for attr in t.id.attrs() {
            if *attr == "TG" {
                continue;
            }
            assert!(t.get(attr).is_some(), "IE attribute {attr} unset");
        }
    }
}
