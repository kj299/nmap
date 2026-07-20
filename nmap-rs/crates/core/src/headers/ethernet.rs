//! Ethernet II header parse. Ports nmap's `EthernetHeader` (`EthernetHeader.{cc,h}`).
//!
//! A fixed 14-byte L2 frame header (dst MAC, src MAC, ethertype); the C
//! `validate()` only checks the stored length is 14, so parsing succeeds for any
//! input with at least 14 bytes. This is the outermost header the packet parser
//! sees on a captured frame; its `ethertype` selects the next layer (IPv4/ARP/IPv6).

use crate::bytes::Cursor;
use core::fmt;

/// Ethernet II header length (fixed), in bytes.
pub const ETH_HEADER_LEN: usize = 14;
/// MAC address length, in bytes.
pub const ETHER_ADDR_LEN: usize = 6;

// Ethertypes nmap enumerates (the ones the parser dispatches on).
pub const ETHTYPE_IPV4: u16 = 0x0800;
pub const ETHTYPE_ARP: u16 = 0x0806;
pub const ETHTYPE_IPV6: u16 = 0x86DD;
/// 802.1Q customer VLAN tag (the frame carries a 4-byte tag before the real type).
pub const ETHTYPE_CTAG: u16 = 0x8100;

/// Why an Ethernet header failed to parse. A 14-byte frame has no field-validity
/// rejection beyond "enough bytes".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than [`ETH_HEADER_LEN`] bytes were available.
    Truncated { needed: usize, available: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { needed, available } => {
                write!(f, "ethernet: truncated (need {needed}, have {available})")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed Ethernet II header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetHeader {
    /// Destination MAC.
    pub dst: [u8; ETHER_ADDR_LEN],
    /// Source MAC.
    pub src: [u8; ETHER_ADDR_LEN],
    /// Ethertype selecting the next layer.
    pub ethertype: u16,
}

impl EthernetHeader {
    /// Ethernet headers are always [`ETH_HEADER_LEN`] bytes; the L3 payload follows.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        ETH_HEADER_LEN
    }

    /// Parse an Ethernet header from the front of `buf`. Succeeds for any input with
    /// at least 14 bytes (matching the C `validate()`).
    pub fn parse(buf: &[u8]) -> Result<EthernetHeader, ParseError> {
        if buf.len() < ETH_HEADER_LEN {
            return Err(ParseError::Truncated {
                needed: ETH_HEADER_LEN,
                available: buf.len(),
            });
        }
        let trunc = || ParseError::Truncated {
            needed: ETH_HEADER_LEN,
            available: buf.len(),
        };
        let mut c = Cursor::new(buf);
        let dst = c.read_array::<6>().map_err(|_| trunc())?;
        let src = c.read_array::<6>().map_err(|_| trunc())?;
        let ethertype = c.read_be_u16().map_err(|_| trunc())?;
        Ok(EthernetHeader {
            dst,
            src,
            ethertype,
        })
    }

    /// Serialize the 14-byte header.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ETH_HEADER_LEN);
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.ethertype.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> [u8; 14] {
        [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst
            0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src
            0x08, 0x00, // ethertype IPv4
        ]
    }

    #[test]
    fn parses_fields() {
        let h = EthernetHeader::parse(&sample()).unwrap();
        assert_eq!(h.dst, [0x02, 0, 0, 0, 0, 0x01]);
        assert_eq!(h.src, [0x02, 0, 0, 0, 0, 0x02]);
        assert_eq!(h.ethertype, ETHTYPE_IPV4);
        assert_eq!(h.header_len(), 14);
    }

    #[test]
    fn serialize_roundtrips() {
        let b = sample();
        assert_eq!(EthernetHeader::parse(&b).unwrap().serialize(), b.to_vec());
    }

    #[test]
    fn recognizes_arp_and_ipv6_ethertypes() {
        let mut b = sample();
        b[12] = 0x08;
        b[13] = 0x06;
        assert_eq!(EthernetHeader::parse(&b).unwrap().ethertype, ETHTYPE_ARP);
        b[12] = 0x86;
        b[13] = 0xDD;
        assert_eq!(EthernetHeader::parse(&b).unwrap().ethertype, ETHTYPE_IPV6);
    }

    #[test]
    fn extra_bytes_after_header_are_payload() {
        let mut b = sample().to_vec();
        b.extend_from_slice(&[0x45, 0x00]); // start of an IPv4 header
        let h = EthernetHeader::parse(&b).unwrap();
        assert_eq!(h.header_len(), 14);
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(
            EthernetHeader::parse(&[0u8; 13]),
            Err(ParseError::Truncated {
                needed: 14,
                available: 13
            })
        );
        assert!(matches!(
            EthernetHeader::parse(&[]),
            Err(ParseError::Truncated { available: 0, .. })
        ));
    }

    #[test]
    fn truncation_sweep_never_panics() {
        let full = sample();
        for n in 0..=full.len() {
            let _ = EthernetHeader::parse(&full[..n]);
        }
    }
}
