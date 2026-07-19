//! ICMPv4 header parse. Ports nmap's `ICMPv4Header` (`ICMPv4Header.{cc,h}`).
//!
//! ICMP's header length is **type-dependent**: `validate()` computes
//! `getICMPHeaderLengthFromType(type)` and requires that many bytes. The C default
//! for an unknown type is 8 bytes (no abort) — so the class parser is total. This
//! port reproduces that exact type→length map and the length check over a
//! [`Cursor`], staying total on every input including hostile/unknown types (the
//! M4 threat-model property; the separate `netutil.cc::icmp_get_data` DoS, where the
//! C `netutil_fatal()`s on a crafted type, is a different function tracked by
//! `parse-no-fatal-on-hostile` and closed when that function is ported).

use crate::bytes::Cursor;
use core::fmt;

/// Standard ICMP header length (type + code + checksum + 4-byte rest), in bytes.
pub const ICMP_STD_HEADER_LEN: usize = 8;

// ICMP type numbers (subset nmap enumerates).
pub const ICMP_ECHOREPLY: u8 = 0;
pub const ICMP_UNREACH: u8 = 3;
pub const ICMP_SOURCEQUENCH: u8 = 4;
pub const ICMP_REDIRECT: u8 = 5;
pub const ICMP_ECHO: u8 = 8;
pub const ICMP_ROUTERADVERT: u8 = 9;
pub const ICMP_ROUTERSOLICIT: u8 = 10;
pub const ICMP_TIMXCEED: u8 = 11;
pub const ICMP_PARAMPROB: u8 = 12;
pub const ICMP_TSTAMP: u8 = 13;
pub const ICMP_TSTAMPREPLY: u8 = 14;
pub const ICMP_INFO: u8 = 15;
pub const ICMP_INFOREPLY: u8 = 16;
pub const ICMP_MASK: u8 = 17;
pub const ICMP_MASKREPLY: u8 = 18;
pub const ICMP_TRACEROUTE: u8 = 30;

/// The header length ICMP type `t` implies, per nmap's
/// `getICMPHeaderLengthFromType`. Unknown types map to the standard 8 (the C's
/// default — a non-RFC type is treated as an 8-byte header, never an abort).
#[must_use]
pub fn header_len_for_type(t: u8) -> usize {
    match t {
        ICMP_TSTAMP | ICMP_TSTAMPREPLY | ICMP_TRACEROUTE => 20,
        ICMP_MASK | ICMP_MASKREPLY => 12,
        _ => ICMP_STD_HEADER_LEN,
    }
}

/// Why an ICMPv4 header failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than [`ICMP_STD_HEADER_LEN`] bytes were available (C: storeRecvData).
    Truncated { needed: usize, available: usize },
    /// The type's required header length exceeded the bytes available
    /// (C: `length < getICMPHeaderLengthFromType(type)`).
    TypeLenExceedsBuffer { header_len: usize, available: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { needed, available } => {
                write!(f, "icmpv4: truncated (need {needed}, have {available})")
            }
            ParseError::TypeLenExceedsBuffer {
                header_len,
                available,
            } => {
                write!(f, "icmpv4: type needs {header_len} bytes, have {available}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed ICMPv4 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv4Header {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    /// The 4 bytes after the checksum (id+seq for echo, unused for unreach, etc.),
    /// as raw bytes — interpretation is type-specific.
    pub rest: [u8; 4],
    /// Bytes this header occupies per its type (`header_len_for_type`).
    header_len: usize,
}

impl Icmpv4Header {
    /// Bytes this header occupies — where the payload begins.
    #[must_use]
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// Echo/echo-reply identifier (`rest[0..2]`), meaningful only for those types.
    #[must_use]
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.rest[0], self.rest[1]])
    }

    /// Echo/echo-reply sequence (`rest[2..4]`), meaningful only for those types.
    #[must_use]
    pub fn seq(&self) -> u16 {
        u16::from_be_bytes([self.rest[2], self.rest[3]])
    }

    /// Parse an ICMPv4 header, applying nmap's type-dependent length rule. Total on
    /// every input — an unknown/hostile type parses as an 8-byte header (never a
    /// panic or abort).
    pub fn parse(buf: &[u8]) -> Result<Icmpv4Header, ParseError> {
        if buf.len() < ICMP_STD_HEADER_LEN {
            return Err(ParseError::Truncated {
                needed: ICMP_STD_HEADER_LEN,
                available: buf.len(),
            });
        }
        let trunc = || ParseError::Truncated {
            needed: ICMP_STD_HEADER_LEN,
            available: buf.len(),
        };
        let mut c = Cursor::new(buf);
        let icmp_type = c.read_u8().map_err(|_| trunc())?;
        let code = c.read_u8().map_err(|_| trunc())?;
        let checksum = c.read_be_u16().map_err(|_| trunc())?;
        let rest = c.read_array::<4>().map_err(|_| trunc())?;

        let header_len = header_len_for_type(icmp_type);
        if header_len > buf.len() {
            return Err(ParseError::TypeLenExceedsBuffer {
                header_len,
                available: buf.len(),
            });
        }

        Ok(Icmpv4Header {
            icmp_type,
            code,
            checksum,
            rest,
            header_len,
        })
    }

    /// Serialize the standard 8-byte header (type, code, checksum, rest). Types with
    /// a longer header carry the extra bytes in the payload the caller appends.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ICMP_STD_HEADER_LEN);
        out.push(self.icmp_type);
        out.push(self.code);
        out.extend_from_slice(&self.checksum.to_be_bytes());
        out.extend_from_slice(&self.rest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Echo request: type 8, code 0, id 0x1234, seq 0x0001.
    fn echo() -> [u8; 8] {
        [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]
    }

    #[test]
    fn parses_echo() {
        let h = Icmpv4Header::parse(&echo()).unwrap();
        assert_eq!(h.icmp_type, ICMP_ECHO);
        assert_eq!(h.code, 0);
        assert_eq!(h.header_len(), 8);
        assert_eq!(h.id(), 0x1234);
        assert_eq!(h.seq(), 0x0001);
    }

    #[test]
    fn serialize_roundtrips_the_std_header() {
        let b = echo();
        assert_eq!(Icmpv4Header::parse(&b).unwrap().serialize(), b.to_vec());
    }

    #[test]
    fn port_unreachable_parses() {
        // type 3 code 3 — 8-byte header + (payload of the offending packet).
        let mut b = vec![0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[0xDE; 20]); // trailing original-packet bytes
        let h = Icmpv4Header::parse(&b).unwrap();
        assert_eq!(h.icmp_type, ICMP_UNREACH);
        assert_eq!(h.code, 3);
        assert_eq!(h.header_len(), 8);
    }

    #[test]
    fn timestamp_needs_20_bytes() {
        // type 13 requires a 20-byte header.
        let short = [0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // only 8 bytes
        assert_eq!(
            Icmpv4Header::parse(&short),
            Err(ParseError::TypeLenExceedsBuffer {
                header_len: 20,
                available: 8
            })
        );
        let mut full = short.to_vec();
        full.extend_from_slice(&[0u8; 12]); // now 20 bytes
        assert_eq!(Icmpv4Header::parse(&full).unwrap().header_len(), 20);
    }

    #[test]
    fn address_mask_needs_12_bytes() {
        let mut b = vec![ICMP_MASK, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            Icmpv4Header::parse(&b),
            Err(ParseError::TypeLenExceedsBuffer { header_len: 12, .. })
        ));
        b.extend_from_slice(&[0u8; 4]); // 12 bytes
        assert_eq!(Icmpv4Header::parse(&b).unwrap().header_len(), 12);
    }

    #[test]
    fn unknown_hostile_type_parses_as_8_byte_header_never_panics() {
        // The parse-no-fatal-on-hostile property for this parser: a non-RFC type is
        // an 8-byte header (matching the C default), NOT an abort. The C
        // netutil.cc::icmp_get_data fatal is a separate function.
        for t in [99u8, 200, 255, 42] {
            let b = [t, 0, 0, 0, 0, 0, 0, 0];
            let h = Icmpv4Header::parse(&b).unwrap();
            assert_eq!(h.icmp_type, t);
            assert_eq!(h.header_len(), 8);
        }
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(
            Icmpv4Header::parse(&[0u8; 7]),
            Err(ParseError::Truncated {
                needed: 8,
                available: 7
            })
        );
    }

    #[test]
    fn truncation_sweep_never_panics() {
        let full = [
            ICMP_TSTAMP,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        for n in 0..=full.len() {
            let _ = Icmpv4Header::parse(&full[..n]);
        }
    }
}
