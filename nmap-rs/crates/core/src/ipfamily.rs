//! The two IP families a raw scan's replies arrive in, as the scan matchers see them.
//!
//! nmap's `get_pcap_result` (`scan_engine_raw.cc:1602`) handles IPv4 and IPv6 in one
//! loop: the TCP and UDP checks are the same for both, and only the ICMP arm differs
//! (ICMPv4 at `:1807`, ICMPv6 at `:1933`). The port keeps that shape. Each matcher
//! ([`crate::synscan`], [`crate::udpscan`], [`crate::flagscan`]) is generic over an
//! [`IpFamily`], implemented by the address type itself (`[u8; 4]`, `[u8; 16]`), so
//! its transport checks are written once and the families cannot drift apart. What a
//! family supplies is only what differs:
//!
//! - where its packet is in a captured frame ([`IpFamily::received`]);
//! - its ICMP protocol number, and how an error's quote is read
//!   ([`IpFamily::quote`]);
//! - how an error is classified and which reason it reports
//!   ([`IpFamily::classify_error`], [`IpFamily::error_reason`]).
//!
//! The IPv4 side keeps exactly the behavior the matchers had before IPv6 (it locates
//! the first IPv4 header the packet walk finds, and reads an ICMP message to the end
//! of the capture); the IPv6 side takes the outermost header only, and reads to the
//! packet's own end (`recv-validate6-trailer-trim`).

use crate::classify::{classify_icmp, classify_icmpv6, PortState, ScanType};
use crate::icmp_quote::{
    icmp_to_reason, icmpv6_to_reason, ipv4_offset, ipv6_packet, parse_icmp_message,
    parse_icmpv6_message, Quote,
};
use crate::model::Reason;
use crate::recv_validate::{validate_packet, Validated};

/// A captured packet of one family that passed [`validate_packet`].
#[derive(Debug, Clone, Copy)]
pub struct Received<'a, A> {
    /// The packet's source address: the host that sent it.
    pub src: A,
    /// The IP packet, from its header to the end of the capture.
    pub ip: &'a [u8],
    /// What validation found: the upper-layer protocol, where it starts, the length.
    pub v: Validated,
}

impl<'a, A> Received<'a, A> {
    /// The transport header and what follows it, to the end of the capture.
    #[must_use]
    pub fn transport(&self) -> Option<&'a [u8]> {
        self.ip.get(self.v.data_offset..)
    }
}

/// An IP family, implemented by its address type. See the module docs.
pub trait IpFamily: Copy + Eq + core::fmt::Debug {
    /// The family's ICMP protocol number: 1 for ICMPv4, 58 for ICMPv6.
    const ICMP: u8;

    /// This family's packet in a captured frame, validated, or `None` when the frame
    /// holds no such packet or it fails validation.
    fn received(frame: &[u8], eth_included: bool) -> Option<Received<'_, Self>>;

    /// The ICMP error a received packet carries, with the probe it quotes. Call only
    /// when `r.v.proto == Self::ICMP`.
    fn quote(r: &Received<'_, Self>) -> Option<Quote<Self>>;

    /// The port state an ICMP error implies for `scan`, or `None` for none.
    fn classify_error(scan: ScanType, q: &Quote<Self>) -> Option<PortState>;

    /// The reason the port reports for an ICMP error.
    fn error_reason(q: &Quote<Self>) -> Reason;
}

impl IpFamily for [u8; 4] {
    const ICMP: u8 = 1;

    fn received(frame: &[u8], eth_included: bool) -> Option<Received<'_, Self>> {
        let ip = frame.get(ipv4_offset(frame, eth_included)?..)?;
        let v = validate_packet(ip).ok()?;
        if v.version != 4 {
            return None;
        }
        let src: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
        Some(Received { src, ip, v })
    }

    fn quote(r: &Received<'_, Self>) -> Option<Quote<Self>> {
        parse_icmp_message(r.src, r.transport()?)
    }

    fn classify_error(scan: ScanType, q: &Quote<Self>) -> Option<PortState> {
        classify_icmp(scan, q.icmp_type, q.icmp_code, q.from_target())
    }

    fn error_reason(q: &Quote<Self>) -> Reason {
        icmp_to_reason(q.icmp_type, q.icmp_code)
    }
}

impl IpFamily for [u8; 16] {
    const ICMP: u8 = 58;

    fn received(frame: &[u8], eth_included: bool) -> Option<Received<'_, Self>> {
        let ip = ipv6_packet(frame, eth_included)?;
        let v = validate_packet(ip).ok()?;
        if v.version != 6 {
            return None;
        }
        let src: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
        Some(Received { src, ip, v })
    }

    fn quote(r: &Received<'_, Self>) -> Option<Quote<Self>> {
        // To the packet's own end, as the C reads it after validatepkt's trim.
        parse_icmpv6_message(r.src, r.ip.get(r.v.data_offset..r.v.captured_len)?)
    }

    fn classify_error(scan: ScanType, q: &Quote<Self>) -> Option<PortState> {
        classify_icmpv6(scan, q.icmp_type, q.icmp_code, q.from_target())
    }

    fn error_reason(q: &Quote<Self>) -> Reason {
        icmpv6_to_reason(q.icmp_type, q.icmp_code)
    }
}

/// Builders for crafted IPv6 replies, shared by the matchers' unit tests.
#[cfg(test)]
pub(crate) mod test6 {
    /// Our address in the IPv6 tests: 2001:db8::1.
    pub const US6: [u8; 16] = addr(1);
    /// The scanned host: 2001:db8::2.
    pub const TARGET6: [u8; 16] = addr(2);
    /// A router on the way: 2001:db8::fe.
    pub const ROUTER6: [u8; 16] = addr(0xfe);

    const fn addr(last: u8) -> [u8; 16] {
        [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last,
        ]
    }

    /// An IPv6 packet from `src` to `dst`: `first` is the header after the fixed
    /// one, `chain` the extension headers (already encoded), then `payload`.
    pub fn ipv6(src: [u8; 16], dst: [u8; 16], first: u8, chain: &[u8], payload: &[u8]) -> Vec<u8> {
        let plen = u16::try_from(chain.len().saturating_add(payload.len())).expect("short");
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&plen.to_be_bytes());
        p.push(first);
        p.push(64);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(chain);
        p.extend_from_slice(payload);
        p
    }

    /// A destination-options header of one 8-byte unit, followed by `next`.
    pub fn dstopts(next: u8) -> Vec<u8> {
        vec![next, 0, 1, 4, 0, 0, 0, 0]
    }

    /// A fragment header followed by `next`, `offset` in 8-byte units.
    pub fn fragment(next: u8, offset: u16) -> Vec<u8> {
        let mut h = vec![next, 0];
        h.extend_from_slice(&(offset << 3).to_be_bytes());
        h.extend_from_slice(&[0, 0, 0, 7]);
        h
    }

    /// Prepend an Ethernet header with the IPv6 type.
    pub fn eth(ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x86, 0xDD]);
        f.extend_from_slice(ip);
        f
    }

    /// A 20-byte TCP header (no options; checksums are not validated).
    pub fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, window: u16) -> Vec<u8> {
        let mut t = Vec::with_capacity(20);
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&seq.to_be_bytes());
        t.extend_from_slice(&ack.to_be_bytes());
        t.push(5 << 4);
        t.push(flags);
        t.extend_from_slice(&window.to_be_bytes());
        t.extend_from_slice(&[0, 0, 0, 0]);
        t
    }

    /// An 8-byte UDP header and `payload`.
    pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let len = u16::try_from(payload.len().saturating_add(8)).expect("short");
        let mut u = Vec::new();
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&len.to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(payload);
        u
    }

    /// An ICMPv6 `icmp_type`/`icmp_code` error from `sender` to us, quoting `quoted`
    /// (a whole IPv6 packet), behind `chain` extension headers of its own.
    pub fn icmpv6_error(
        sender: [u8; 16],
        icmp_type: u8,
        icmp_code: u8,
        chain_first: Option<u8>,
        chain: &[u8],
        quoted: &[u8],
    ) -> Vec<u8> {
        let mut msg = vec![icmp_type, icmp_code, 0, 0, 0, 0, 0, 0];
        msg.extend_from_slice(quoted);
        ipv6(sender, US6, chain_first.unwrap_or(58), chain, &msg)
    }
}

#[cfg(test)]
mod tests {
    use super::test6::*;
    use super::*;

    #[test]
    fn ipv6_is_located_bare_or_behind_ethernet_and_never_tunnelled() {
        let pkt = ipv6(TARGET6, US6, 6, &[], &tcp(80, 40000, 1, 2, 0x12, 1024));
        let bare = <[u8; 16]>::received(&pkt, false).unwrap();
        assert_eq!(
            (bare.src, bare.v.proto, bare.v.data_offset),
            (TARGET6, 6, 40)
        );
        let frame = eth(&pkt);
        let framed = <[u8; 16]>::received(&frame, true).unwrap();
        assert_eq!(framed.src, TARGET6);
        // Ethernet with the IPv4 type, or an IPv4 header: not an IPv6 packet.
        let mut v4type = eth(&pkt);
        v4type[12..14].copy_from_slice(&[0x08, 0x00]);
        assert!(<[u8; 16]>::received(&v4type, true).is_none());
        assert!(
            <[u8; 16]>::received(&pkt, true).is_none(),
            "no Ethernet header"
        );
        // IPv6 inside IPv4 (protocol 41) is not an IPv6 reply.
        let mut v4 = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 41, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
        ];
        let total = u16::try_from(v4.len() + pkt.len()).unwrap();
        v4[2..4].copy_from_slice(&total.to_be_bytes());
        v4.extend_from_slice(&pkt);
        assert!(<[u8; 16]>::received(&v4, false).is_none());
        // And an IPv6 packet is not an IPv4 one.
        assert!(<[u8; 4]>::received(&pkt, false).is_none());
    }

    #[test]
    fn icmpv6_quotes_are_read_to_the_packets_own_end() {
        let probe = ipv6(US6, TARGET6, 17, &[], &udp(40000, 53, &[]));
        let mut err = icmpv6_error(TARGET6, 1, 4, None, &[], &probe);
        let r = <[u8; 16]>::received(&err, false).unwrap();
        let q = <[u8; 16]>::quote(&r).unwrap();
        assert_eq!(
            (q.sender, q.quoted_src, q.quoted_dst),
            (TARGET6, US6, TARGET6)
        );
        assert_eq!((q.proto, q.sport, q.dport, q.seq), (17, 40000, 53, None));
        assert_eq!(<[u8; 16]>::error_reason(&q), Reason::PortUnreach);
        // A payload length that ends the packet inside the quoted UDP header: the
        // bytes past it are a trailer, not quote.
        let plen = u16::try_from(8 + 40 + 7).unwrap();
        err[4..6].copy_from_slice(&plen.to_be_bytes());
        let r = <[u8; 16]>::received(&err, false).unwrap();
        assert!(<[u8; 16]>::quote(&r).is_none());
    }
}
