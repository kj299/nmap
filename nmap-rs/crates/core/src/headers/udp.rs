//! UDP header parse + serialize + checksum. Ports nmap's `UDPHeader`
//! (`UDPHeader.{cc,h}`).
//!
//! The UDP header is a fixed 8 bytes; the C `validate()` only checks the stored
//! length is 8, so parsing succeeds for any input with at least 8 bytes. The
//! notable part is the checksum: nmap's `UDPHeader::setSum` assembles the segment
//! into a **fixed stack buffer `u8 aux[65535-8]` (65527 bytes)** and then calls
//! `dumpToBinaryBuffer(aux, 65536-8)` — passing `maxlen = 65528`, **one byte larger
//! than the buffer** (`UDPHeader.cc:197,209`). A UDP datagram whose total length is
//! 65528 therefore overflows the stack buffer by one byte (CWE-121). This port
//! computes the checksum over a growing `Vec` sized from a single source, so there
//! is no fixed destination and the overflow class does not exist — the deliberate,
//! safer-than-C divergence `udp-checksum-no-fixed-buffer` in `DIVERGENCES.md`.

use crate::bytes::Cursor;
use crate::checksum::ipv4_pseudoheader_cksum;
use core::fmt;

/// UDP header length (fixed), in bytes.
pub const UDP_HEADER_LEN: usize = 8;
/// IP protocol number for UDP.
pub const IP_PROTO_UDP: u8 = 17;

/// Why a UDP header failed to parse. UDP has no field-validity rejection beyond
/// "enough bytes", so truncation is the only failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than [`UDP_HEADER_LEN`] bytes were available.
    Truncated { needed: usize, available: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { needed, available } => {
                write!(f, "udp: truncated (need {needed}, have {available})")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed UDP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub sport: u16,
    pub dport: u16,
    /// UDP length field on the wire (header + data), as stated — not re-derived.
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    /// UDP headers are always [`UDP_HEADER_LEN`] bytes; the payload follows.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        UDP_HEADER_LEN
    }

    /// Parse a UDP header from the front of `buf`. Succeeds for any input with at
    /// least 8 bytes (matching the C, whose `validate()` only checks the 8-byte
    /// store succeeded).
    pub fn parse(buf: &[u8]) -> Result<UdpHeader, ParseError> {
        if buf.len() < UDP_HEADER_LEN {
            return Err(ParseError::Truncated {
                needed: UDP_HEADER_LEN,
                available: buf.len(),
            });
        }
        let trunc = || ParseError::Truncated {
            needed: UDP_HEADER_LEN,
            available: buf.len(),
        };
        let mut c = Cursor::new(buf);
        let sport = c.read_be_u16().map_err(|_| trunc())?;
        let dport = c.read_be_u16().map_err(|_| trunc())?;
        let length = c.read_be_u16().map_err(|_| trunc())?;
        let checksum = c.read_be_u16().map_err(|_| trunc())?;
        Ok(UdpHeader {
            sport,
            dport,
            length,
            checksum,
        })
    }

    /// Serialize the 8-byte header, writing `checksum` as stored.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(UDP_HEADER_LEN);
        out.extend_from_slice(&self.sport.to_be_bytes());
        out.extend_from_slice(&self.dport.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
        out.extend_from_slice(&self.checksum.to_be_bytes());
        out
    }

    /// The RFC 768 checksum over the IPv4 pseudo-header + this header + `payload`,
    /// with the checksum field zeroed and the RFC 768 zero→`0xFFFF` rule applied.
    ///
    /// **`udp-checksum-no-fixed-buffer`:** the C `setSum` assembles the segment into
    /// a fixed `aux[65527]` stack buffer with a `maxlen` of 65528 and overflows it by
    /// one byte on a max-size datagram. Here the segment is a growing `Vec` whose
    /// length *is* its capacity — there is no fixed destination and no overflow.
    #[must_use]
    pub fn computed_checksum(&self, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> u16 {
        let mut seg = Vec::with_capacity(UDP_HEADER_LEN.saturating_add(payload.len()));
        seg.extend_from_slice(&self.sport.to_be_bytes());
        seg.extend_from_slice(&self.dport.to_be_bytes());
        seg.extend_from_slice(&self.length.to_be_bytes());
        seg.extend_from_slice(&[0u8, 0u8]); // checksum field zeroed
        seg.extend_from_slice(payload);
        ipv4_pseudoheader_cksum(src, dst, IP_PROTO_UDP, &seg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> [u8; 8] {
        // sport 53, dport 53, ulen 8, checksum 0
        [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]
    }

    #[test]
    fn parses_all_fields() {
        let h = UdpHeader::parse(&sample()).unwrap();
        assert_eq!(h.sport, 53);
        assert_eq!(h.dport, 53);
        assert_eq!(h.length, 8);
        assert_eq!(h.checksum, 0);
        assert_eq!(h.header_len(), 8);
    }

    #[test]
    fn serialize_roundtrips() {
        let b = sample();
        assert_eq!(UdpHeader::parse(&b).unwrap().serialize(), b.to_vec());
    }

    #[test]
    fn extra_bytes_after_header_are_ignored_by_parse() {
        // A UDP header with payload bytes trailing — parse reads only the 8 header
        // bytes and succeeds (the payload is the caller's to slice at header_len).
        let mut b = sample().to_vec();
        b.extend_from_slice(b"payload");
        let h = UdpHeader::parse(&b).unwrap();
        assert_eq!(h.sport, 53);
        assert_eq!(h.header_len(), 8);
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(
            UdpHeader::parse(&[0u8; 7]),
            Err(ParseError::Truncated {
                needed: 8,
                available: 7
            })
        );
        assert!(matches!(
            UdpHeader::parse(&[]),
            Err(ParseError::Truncated { available: 0, .. })
        ));
    }

    #[test]
    fn checksum_matches_manual_pseudo_header() {
        let h = UdpHeader::parse(&sample()).unwrap();
        let ck = h.computed_checksum([192, 168, 0, 1], [192, 168, 0, 199], &[]);
        let mut seg = h.serialize();
        seg[6] = 0;
        seg[7] = 0;
        assert_eq!(
            ck,
            crate::checksum::ipv4_pseudoheader_cksum(
                [192, 168, 0, 1],
                [192, 168, 0, 199],
                17,
                &seg
            )
        );
    }

    #[test]
    fn max_size_datagram_checksum_does_not_overflow() {
        // The exact case that overflows the C's fixed aux[65527] stack buffer: a UDP
        // datagram whose total length is 65528. Here it just computes a value — no
        // fixed destination, no panic (udp-checksum-no-fixed-buffer).
        let h = UdpHeader {
            sport: 1,
            dport: 2,
            length: 65528,
            checksum: 0,
        };
        let payload = vec![0xABu8; 65528 - UDP_HEADER_LEN];
        let _ = h.computed_checksum([10, 0, 0, 1], [10, 0, 0, 2], &payload);
    }

    #[test]
    fn truncation_sweep_never_panics() {
        let full = sample();
        for n in 0..=full.len() {
            let _ = UdpHeader::parse(&full[..n]);
        }
    }
}
