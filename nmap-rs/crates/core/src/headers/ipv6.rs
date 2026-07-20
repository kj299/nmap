//! IPv6 header parse. Ports nmap's `IPv6Header` (`IPv6Header.{cc,h}`).
//!
//! A fixed 40-byte header: a bit-packed version(4) / traffic-class(8) / flow-label(20)
//! word, payload length, next header, hop limit, and two 16-byte addresses. The C
//! `validate()` only checks the stored length is 40, so parse succeeds for any input
//! with at least 40 bytes. The IPv6 **extension-header chain** (hop-by-hop, routing,
//! fragment, dstopts) is NOT part of this header class — it is walked by the packet
//! parser using `next_header`; this module ports only the fixed base header.

use crate::bytes::Cursor;
use core::fmt;

/// IPv6 base header length (fixed), in bytes.
pub const IPV6_HEADER_LEN: usize = 40;

/// Why an IPv6 header failed to parse. A fixed 40-byte header has no field-validity
/// rejection beyond "enough bytes".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than [`IPV6_HEADER_LEN`] bytes were available.
    Truncated { needed: usize, available: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { needed, available } => {
                write!(f, "ipv6: truncated (need {needed}, have {available})")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed IPv6 base header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Header {
    /// The raw 4-byte version/traffic-class/flow-label word (decode via the
    /// accessors). Kept raw so serialization round-trips exactly.
    pub vtf: [u8; 4],
    /// Payload length field (bytes following this header).
    pub payload_length: u16,
    /// Next-header type (upper-layer protocol or the first extension header).
    pub next_header: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// Source address (raw 16 bytes).
    pub src: [u8; 16],
    /// Destination address (raw 16 bytes).
    pub dst: [u8; 16],
}

impl Ipv6Header {
    /// The base header is always [`IPV6_HEADER_LEN`] bytes; extension headers or the
    /// upper-layer payload follow.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        IPV6_HEADER_LEN
    }

    /// IP version — 6 for a well-formed IPv6 header (the high nibble of byte 0).
    #[must_use]
    pub fn version(&self) -> u8 {
        self.vtf[0] >> 4
    }

    /// 8-bit traffic class (low nibble of byte 0 + high nibble of byte 1).
    #[must_use]
    pub fn traffic_class(&self) -> u8 {
        // Compute in u32 to avoid any shift/truncation ambiguity, then narrow the
        // provably-8-bit result.
        let tc = (u32::from(self.vtf[0] & 0x0F) << 4) | u32::from(self.vtf[1] >> 4);
        u8::try_from(tc & 0xFF).unwrap_or(0)
    }

    /// 20-bit flow label (low nibble of byte 1 + bytes 2-3).
    #[must_use]
    pub fn flow_label(&self) -> u32 {
        (u32::from(self.vtf[1] & 0x0F) << 16)
            | (u32::from(self.vtf[2]) << 8)
            | u32::from(self.vtf[3])
    }

    /// Parse an IPv6 base header from the front of `buf`. Succeeds for any input with
    /// at least 40 bytes (matching the C `validate()`).
    pub fn parse(buf: &[u8]) -> Result<Ipv6Header, ParseError> {
        if buf.len() < IPV6_HEADER_LEN {
            return Err(ParseError::Truncated {
                needed: IPV6_HEADER_LEN,
                available: buf.len(),
            });
        }
        let trunc = || ParseError::Truncated {
            needed: IPV6_HEADER_LEN,
            available: buf.len(),
        };
        let mut c = Cursor::new(buf);
        let vtf = c.read_array::<4>().map_err(|_| trunc())?;
        let payload_length = c.read_be_u16().map_err(|_| trunc())?;
        let next_header = c.read_u8().map_err(|_| trunc())?;
        let hop_limit = c.read_u8().map_err(|_| trunc())?;
        let src = c.read_array::<16>().map_err(|_| trunc())?;
        let dst = c.read_array::<16>().map_err(|_| trunc())?;
        Ok(Ipv6Header {
            vtf,
            payload_length,
            next_header,
            hop_limit,
            src,
            dst,
        })
    }

    /// Serialize the 40-byte base header.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IPV6_HEADER_LEN);
        out.extend_from_slice(&self.vtf);
        out.extend_from_slice(&self.payload_length.to_be_bytes());
        out.push(self.next_header);
        out.push(self.hop_limit);
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.dst);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TCP-over-IPv6 base header: version 6, tclass 0, flow 0, plen 20, nh 6
    /// (TCP), hlim 64, src 2001:db8::1, dst 2001:db8::2.
    fn sample() -> [u8; 40] {
        let mut b = [0u8; 40];
        b[0] = 0x60; // version 6, tclass hi 0
                     // b[1..4] = 0 -> tclass 0, flow 0
        b[4] = 0x00;
        b[5] = 0x14; // payload length 20
        b[6] = 0x06; // next header = TCP
        b[7] = 0x40; // hop limit 64
        b[8] = 0x20;
        b[9] = 0x01;
        b[10] = 0x0d;
        b[11] = 0xb8; // src 2001:0db8::
        b[23] = 0x01; // src ...::1
        b[24] = 0x20;
        b[25] = 0x01;
        b[26] = 0x0d;
        b[27] = 0xb8; // dst 2001:0db8::
        b[39] = 0x02; // dst ...::2
        b
    }

    #[test]
    fn parses_fixed_fields() {
        let h = Ipv6Header::parse(&sample()).unwrap();
        assert_eq!(h.version(), 6);
        assert_eq!(h.traffic_class(), 0);
        assert_eq!(h.flow_label(), 0);
        assert_eq!(h.payload_length, 20);
        assert_eq!(h.next_header, 6);
        assert_eq!(h.hop_limit, 64);
        assert_eq!(h.src[0..4], [0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(h.src[15], 0x01);
        assert_eq!(h.dst[15], 0x02);
        assert_eq!(h.header_len(), 40);
    }

    #[test]
    fn serialize_roundtrips() {
        let b = sample();
        assert_eq!(Ipv6Header::parse(&b).unwrap().serialize(), b.to_vec());
    }

    #[test]
    fn decodes_traffic_class_and_flow_label_bits() {
        // version=6, tclass=0xAB, flow=0x1_2345.
        // byte0 = 6<<4 | (0xAB>>4)=0x0A -> 0x6A
        // byte1 = (0xAB&0x0F)<<4 | (flow>>16 &0x0F)=0x01 -> 0xB1
        // byte2 = 0x23, byte3 = 0x45
        let mut b = sample();
        b[0] = 0x6A;
        b[1] = 0xB1;
        b[2] = 0x23;
        b[3] = 0x45;
        let h = Ipv6Header::parse(&b).unwrap();
        assert_eq!(h.version(), 6);
        assert_eq!(h.traffic_class(), 0xAB);
        assert_eq!(h.flow_label(), 0x1_2345);
    }

    #[test]
    fn extension_header_nexthdr_is_exposed_not_walked() {
        // next_header = 0 (hop-by-hop options) — this module reports it; the chain
        // walk is the packet parser's job.
        let mut b = sample();
        b[6] = 0x00;
        assert_eq!(Ipv6Header::parse(&b).unwrap().next_header, 0);
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(
            Ipv6Header::parse(&[0u8; 39]),
            Err(ParseError::Truncated {
                needed: 40,
                available: 39
            })
        );
        assert!(matches!(
            Ipv6Header::parse(&[]),
            Err(ParseError::Truncated { available: 0, .. })
        ));
    }

    #[test]
    fn truncation_sweep_never_panics() {
        let full = sample();
        for n in 0..=full.len() {
            let _ = Ipv6Header::parse(&full[..n]);
        }
    }
}
