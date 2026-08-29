//! ICMPv6 header parse. Ports nmap's `ICMPv6Header` (`ICMPv6Header.{cc,h}`).
//!
//! Like ICMPv4, an ICMPv6 header's length is **type-dependent**: `validate()` asks
//! `getHeaderLengthFromType(type)` how many bytes this type implies and requires at
//! least that many. Unknown or non-RFC types fall back to the 8-byte minimum rather
//! than aborting, so the class parser is total.
//!
//! The C stores `MIN(sizeof(nping_icmpv6_hdr_t), len)` bytes into a packed struct
//! whose body array is sized to the largest message it knows (Redirect, 36 body
//! bytes → a 40-byte struct). Because that cap is exactly the largest type-derived
//! length, `length < should_have` and `available < should_have` are the same test —
//! this port makes that explicit rather than reproducing the intermediate clamp.
//!
//! Only the fixed part is decoded. The message body is kept as bytes: the
//! IPv6 fingerprint engine wants the type and code, and the neighbour-discovery
//! option TLVs inside an advertisement are a separate parser the C keeps in
//! `ICMPv6Option`.

use crate::bytes::Cursor;
use core::fmt;

/// Type + code + checksum — the part every ICMPv6 message shares.
pub const ICMPV6_COMMON_HEADER_LEN: usize = 4;
/// Smallest ICMPv6 header the C will even store (`ICMPv6_MIN_HEADER_LEN`).
pub const ICMPV6_MIN_HEADER_LEN: usize = 8;
/// IP protocol number for ICMPv6.
pub const IP_PROTO_ICMPV6: u8 = 58;

// ICMPv6 type numbers (the subset nmap gives a length to).
pub const ICMPV6_UNREACH: u8 = 1;
pub const ICMPV6_PKTTOOBIG: u8 = 2;
pub const ICMPV6_TIMXCEED: u8 = 3;
pub const ICMPV6_PARAMPROB: u8 = 4;
pub const ICMPV6_ECHO: u8 = 128;
pub const ICMPV6_ECHOREPLY: u8 = 129;
pub const ICMPV6_GRPMEMBQUERY: u8 = 130;
pub const ICMPV6_GRPMEMBREP: u8 = 131;
pub const ICMPV6_GRPMEMBRED: u8 = 132;
pub const ICMPV6_ROUTERSOLICIT: u8 = 133;
pub const ICMPV6_ROUTERADVERT: u8 = 134;
pub const ICMPV6_NGHBRSOLICIT: u8 = 135;
pub const ICMPV6_NGHBRADVERT: u8 = 136;
pub const ICMPV6_REDIRECT: u8 = 137;
pub const ICMPV6_RTRRENUM: u8 = 138;
pub const ICMPV6_NODEINFOQUERY: u8 = 139;
pub const ICMPV6_NODEINFORESP: u8 = 140;

/// The header length ICMPv6 type `t` implies, per nmap's `getHeaderLengthFromType`.
///
/// Unknown types map to [`ICMPV6_MIN_HEADER_LEN`] — the C's `default:` arm, which
/// treats a non-RFC type as a plain 8-byte header rather than rejecting it.
#[must_use]
pub fn header_len_for_type(t: u8) -> usize {
    match t {
        ICMPV6_REDIRECT => ICMPV6_COMMON_HEADER_LEN.saturating_add(36),
        ICMPV6_NGHBRSOLICIT | ICMPV6_NGHBRADVERT | ICMPV6_GRPMEMBQUERY | ICMPV6_GRPMEMBREP
        | ICMPV6_GRPMEMBRED => ICMPV6_COMMON_HEADER_LEN.saturating_add(20),
        ICMPV6_ROUTERADVERT | ICMPV6_RTRRENUM | ICMPV6_NODEINFOQUERY | ICMPV6_NODEINFORESP => {
            ICMPV6_COMMON_HEADER_LEN.saturating_add(12)
        }
        // UNREACH, PKTTOOBIG, TIMXCEED, PARAMPROB, ECHO, ECHOREPLY, ROUTERSOLICIT
        // all declare COMMON+4, which is the same as the 8-byte default.
        _ => ICMPV6_MIN_HEADER_LEN,
    }
}

/// Why an ICMPv6 header failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than [`ICMPV6_MIN_HEADER_LEN`] bytes were available (C: `storeRecvData`).
    Truncated { needed: usize, available: usize },
    /// The type's required header length exceeded the bytes available
    /// (C: `length < getHeaderLengthFromType(type)`).
    TypeLenExceedsBuffer { header_len: usize, available: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { needed, available } => {
                write!(f, "icmpv6: truncated (need {needed}, have {available})")
            }
            ParseError::TypeLenExceedsBuffer {
                header_len,
                available,
            } => {
                write!(f, "icmpv6: type needs {header_len} bytes, have {available}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed ICMPv6 header — the common 4 bytes plus the type-implied message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmpv6Header {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    /// Message body: `header_len_for_type(icmp_type) - 4` bytes, exactly the span
    /// the C's `validate()` accounts for.
    pub body: Vec<u8>,
}

impl Icmpv6Header {
    /// Bytes this header occupies — the type-derived length the C walk advances by.
    #[must_use]
    pub fn header_len(&self) -> usize {
        header_len_for_type(self.icmp_type)
    }

    /// Parse an ICMPv6 header from the front of `buf`, applying nmap's accept rules.
    pub fn parse(buf: &[u8]) -> Result<Icmpv6Header, ParseError> {
        if buf.len() < ICMPV6_MIN_HEADER_LEN {
            return Err(ParseError::Truncated {
                needed: ICMPV6_MIN_HEADER_LEN,
                available: buf.len(),
            });
        }
        let trunc = || ParseError::Truncated {
            needed: ICMPV6_MIN_HEADER_LEN,
            available: buf.len(),
        };
        let mut c = Cursor::new(buf);
        let icmp_type = c.read_u8().map_err(|_| trunc())?;
        let code = c.read_u8().map_err(|_| trunc())?;
        let checksum = c.read_be_u16().map_err(|_| trunc())?;

        let header_len = header_len_for_type(icmp_type);
        if header_len > buf.len() {
            return Err(ParseError::TypeLenExceedsBuffer {
                header_len,
                available: buf.len(),
            });
        }
        let body = c
            .take(header_len.saturating_sub(ICMPV6_COMMON_HEADER_LEN))
            .map_err(|_| trunc())?
            .to_vec();

        Ok(Icmpv6Header {
            icmp_type,
            code,
            checksum,
            body,
        })
    }

    /// Serialize the header (common fields + body), writing `checksum` as stored.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_len());
        out.push(self.icmp_type);
        out.push(self.code);
        out.extend_from_slice(&self.checksum.to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// Whether this type carries the offending IPv6 packet as its payload — the
    /// four error reports the C descends into (`UNREACH`, `PKTTOOBIG`, `TIMXCEED`,
    /// `PARAMPROB`).
    #[must_use]
    pub fn quotes_packet(&self) -> bool {
        matches!(
            self.icmp_type,
            ICMPV6_UNREACH | ICMPV6_PKTTOOBIG | ICMPV6_TIMXCEED | ICMPV6_PARAMPROB
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(t: u8, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        if !v.is_empty() {
            v[0] = t;
        }
        if v.len() > 1 {
            v[1] = 7; // code
        }
        v
    }

    #[test]
    fn echo_reply_is_eight_bytes() {
        let h = Icmpv6Header::parse(&msg(ICMPV6_ECHOREPLY, 8)).expect("parse");
        assert_eq!(h.icmp_type, ICMPV6_ECHOREPLY);
        assert_eq!(h.code, 7);
        assert_eq!(h.header_len(), 8);
        assert_eq!(h.body.len(), 4);
    }

    #[test]
    fn neighbour_solicit_needs_twenty_four() {
        assert_eq!(header_len_for_type(ICMPV6_NGHBRSOLICIT), 24);
        assert!(matches!(
            Icmpv6Header::parse(&msg(ICMPV6_NGHBRSOLICIT, 23)),
            Err(ParseError::TypeLenExceedsBuffer { .. })
        ));
        let h = Icmpv6Header::parse(&msg(ICMPV6_NGHBRSOLICIT, 24)).expect("parse");
        assert_eq!(h.header_len(), 24);
    }

    #[test]
    fn redirect_is_the_longest_type() {
        assert_eq!(header_len_for_type(ICMPV6_REDIRECT), 40);
        // The C's storage cap is exactly this, so nothing longer is representable.
        for t in 0u8..=255 {
            assert!(header_len_for_type(t) <= 40, "type {t} claims > 40 bytes");
            assert!(header_len_for_type(t) >= ICMPV6_MIN_HEADER_LEN);
        }
    }

    #[test]
    fn unknown_types_are_eight_bytes_not_a_rejection() {
        // 200 is unassigned; the C's default arm gives it the 8-byte minimum.
        let h = Icmpv6Header::parse(&msg(200, 8)).expect("unknown type must still parse");
        assert_eq!(h.header_len(), ICMPV6_MIN_HEADER_LEN);
    }

    #[test]
    fn short_input_is_an_error_not_a_panic() {
        for n in 0..ICMPV6_MIN_HEADER_LEN {
            assert!(matches!(
                Icmpv6Header::parse(&vec![0xffu8; n]),
                Err(ParseError::Truncated { .. })
            ));
        }
    }

    #[test]
    fn round_trips_through_serialize() {
        let raw = msg(ICMPV6_REDIRECT, 40);
        let h = Icmpv6Header::parse(&raw).expect("parse");
        assert_eq!(h.serialize(), raw);
    }

    #[test]
    fn only_the_four_error_reports_quote_a_packet() {
        for t in 0u8..=255 {
            let quotes = Icmpv6Header::parse(&msg(t, 40))
                .expect("40 bytes is enough for every type")
                .quotes_packet();
            assert_eq!(quotes, (1..=4).contains(&t), "type {t}");
        }
    }
}
