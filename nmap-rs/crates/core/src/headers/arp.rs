//! ARP header parse. Ports nmap's `ARPHeader` (`ARPHeader.{cc,h}`).
//!
//! A fixed 28-byte header: hardware type, protocol type, hw/proto address lengths,
//! opcode, and a 20-byte address block. The C `validate()` only checks the stored
//! length is 28, so parse succeeds for any input with at least 28 bytes. The 20-byte
//! block holds sender/target hardware+protocol addresses; nmap's getters assume the
//! common Ethernet/IPv4 layout (6-byte MAC, 4-byte IP), which the accessors here
//! reproduce.

use crate::bytes::Cursor;
use core::fmt;

/// ARP header length (fixed), in bytes.
pub const ARP_HEADER_LEN: usize = 28;

// Hardware types (subset).
pub const HDR_ETH10MB: u16 = 1;
pub const HDR_IEEE802: u16 = 6;

// Opcodes (subset nmap enumerates).
pub const OP_ARP_REQUEST: u16 = 1;
pub const OP_ARP_REPLY: u16 = 2;
pub const OP_RARP_REQUEST: u16 = 3;
pub const OP_RARP_REPLY: u16 = 4;

/// Protocol type for IPv4 (matches the Ethernet IPv4 ethertype).
pub const ARP_PROTO_IPV4: u16 = 0x0800;

/// Why an ARP header failed to parse. A fixed 28-byte header has no field-validity
/// rejection beyond "enough bytes".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than [`ARP_HEADER_LEN`] bytes were available.
    Truncated { needed: usize, available: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { needed, available } => {
                write!(f, "arp: truncated (need {needed}, have {available})")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed ARP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpHeader {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    pub opcode: u16,
    /// The 20-byte address block: sender MAC(6) + sender IP(4) + target MAC(6) +
    /// target IP(4) in the standard Ethernet/IPv4 layout.
    pub data: [u8; 20],
}

impl ArpHeader {
    /// ARP headers are always [`ARP_HEADER_LEN`] bytes.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        ARP_HEADER_LEN
    }

    /// Sender hardware address (Ethernet/IPv4 layout: `data[0..6]`).
    #[must_use]
    pub fn sender_mac(&self) -> [u8; 6] {
        let mut m = [0u8; 6];
        m.copy_from_slice(&self.data[0..6]);
        m
    }

    /// Sender protocol address (Ethernet/IPv4 layout: `data[6..10]`).
    #[must_use]
    pub fn sender_ip(&self) -> [u8; 4] {
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.data[6..10]);
        a
    }

    /// Target hardware address (Ethernet/IPv4 layout: `data[10..16]`).
    #[must_use]
    pub fn target_mac(&self) -> [u8; 6] {
        let mut m = [0u8; 6];
        m.copy_from_slice(&self.data[10..16]);
        m
    }

    /// Target protocol address (Ethernet/IPv4 layout: `data[16..20]`).
    #[must_use]
    pub fn target_ip(&self) -> [u8; 4] {
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.data[16..20]);
        a
    }

    /// Parse an ARP header from the front of `buf`. Succeeds for any input with at
    /// least 28 bytes (matching the C `validate()`).
    pub fn parse(buf: &[u8]) -> Result<ArpHeader, ParseError> {
        if buf.len() < ARP_HEADER_LEN {
            return Err(ParseError::Truncated {
                needed: ARP_HEADER_LEN,
                available: buf.len(),
            });
        }
        let trunc = || ParseError::Truncated {
            needed: ARP_HEADER_LEN,
            available: buf.len(),
        };
        let mut c = Cursor::new(buf);
        let hardware_type = c.read_be_u16().map_err(|_| trunc())?;
        let protocol_type = c.read_be_u16().map_err(|_| trunc())?;
        let hw_addr_len = c.read_u8().map_err(|_| trunc())?;
        let proto_addr_len = c.read_u8().map_err(|_| trunc())?;
        let opcode = c.read_be_u16().map_err(|_| trunc())?;
        let data = c.read_array::<20>().map_err(|_| trunc())?;
        Ok(ArpHeader {
            hardware_type,
            protocol_type,
            hw_addr_len,
            proto_addr_len,
            opcode,
            data,
        })
    }

    /// Serialize the 28-byte header.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ARP_HEADER_LEN);
        out.extend_from_slice(&self.hardware_type.to_be_bytes());
        out.extend_from_slice(&self.protocol_type.to_be_bytes());
        out.push(self.hw_addr_len);
        out.push(self.proto_addr_len);
        out.extend_from_slice(&self.opcode.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ARP request: who-has 10.0.0.2 tell 10.0.0.1.
    fn arp_request() -> [u8; 28] {
        [
            0x00, 0x01, // hrd = Ethernet
            0x08, 0x00, // pro = IPv4
            0x06, 0x04, // hln=6, pln=4
            0x00, 0x01, // op = request
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // sender MAC
            0x0A, 0x00, 0x00, 0x01, // sender IP 10.0.0.1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC (unknown)
            0x0A, 0x00, 0x00, 0x02, // target IP 10.0.0.2
        ]
    }

    #[test]
    fn parses_request_fields() {
        let h = ArpHeader::parse(&arp_request()).unwrap();
        assert_eq!(h.hardware_type, HDR_ETH10MB);
        assert_eq!(h.protocol_type, ARP_PROTO_IPV4);
        assert_eq!(h.hw_addr_len, 6);
        assert_eq!(h.proto_addr_len, 4);
        assert_eq!(h.opcode, OP_ARP_REQUEST);
        assert_eq!(h.sender_mac(), [0x02, 0, 0, 0, 0, 0x01]);
        assert_eq!(h.sender_ip(), [10, 0, 0, 1]);
        assert_eq!(h.target_mac(), [0, 0, 0, 0, 0, 0]);
        assert_eq!(h.target_ip(), [10, 0, 0, 2]);
        assert_eq!(h.header_len(), 28);
    }

    #[test]
    fn serialize_roundtrips() {
        let b = arp_request();
        assert_eq!(ArpHeader::parse(&b).unwrap().serialize(), b.to_vec());
    }

    #[test]
    fn parses_reply_opcode() {
        let mut b = arp_request();
        b[7] = 0x02; // op = reply
        assert_eq!(ArpHeader::parse(&b).unwrap().opcode, OP_ARP_REPLY);
    }

    #[test]
    fn extra_bytes_after_header_are_ignored() {
        let mut b = arp_request().to_vec();
        b.extend_from_slice(&[0xFF; 18]); // trailing padding to min Ethernet frame
        let h = ArpHeader::parse(&b).unwrap();
        assert_eq!(h.header_len(), 28);
        assert_eq!(h.target_ip(), [10, 0, 0, 2]);
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(
            ArpHeader::parse(&[0u8; 27]),
            Err(ParseError::Truncated {
                needed: 28,
                available: 27
            })
        );
        assert!(matches!(
            ArpHeader::parse(&[]),
            Err(ParseError::Truncated { available: 0, .. })
        ));
    }

    #[test]
    fn truncation_sweep_never_panics() {
        let full = arp_request();
        for n in 0..=full.len() {
            let _ = ArpHeader::parse(&full[..n]);
        }
    }
}
