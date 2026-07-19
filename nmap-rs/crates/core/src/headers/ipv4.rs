//! IPv4 header parse + serialize. Ports nmap's `IPv4Header` (`IPv4Header.{cc,h}`).
//!
//! The C overlays a `__packed__ nping_ipv4_hdr` struct on a fixed buffer, `memcpy`s
//! `MIN(60, len)` wire bytes in (`storeRecvData`), then `validate()`s: version==4,
//! `ip_hl >= 5`, and `ip_hl*4 <= length` — advancing the parser by `ip_hl*4`. This
//! port reproduces exactly those accept/reject rules over a [`Cursor`], with the
//! header fields read as explicit big-endian slices instead of a packed-struct
//! overlay, so there is no alignment assumption and no path to an out-of-bounds read.

use crate::bytes::Cursor;
use crate::checksum::in_cksum;
use core::fmt;

/// Minimum IPv4 header length (no options), in bytes.
pub const IP_HEADER_LEN: usize = 20;
/// Don't-Fragment flag within the flags/fragment-offset word.
pub const IP_DF: u16 = 0x4000;
/// More-Fragments flag within the flags/fragment-offset word.
pub const IP_MF: u16 = 0x2000;
/// Mask selecting the 13-bit fragment offset.
pub const IP_OFFMASK: u16 = 0x1FFF;

/// Why an IPv4 header failed to parse. Mirrors the three C reject points plus the
/// length precondition; every case is a clean error, never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than [`IP_HEADER_LEN`] bytes were available.
    Truncated { needed: usize, available: usize },
    /// Version nibble was not 4 (C: `getVersion()!=4`).
    BadVersion(u8),
    /// Header-length field was < 5 words (C: `getHeaderLength()<5`).
    HeaderLenTooSmall(u8),
    /// `ihl*4` exceeded the bytes available (C: `getHeaderLength()*4 > length`).
    HeaderLenExceedsBuffer { header_len: usize, available: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { needed, available } => {
                write!(f, "ipv4: truncated (need {needed}, have {available})")
            }
            ParseError::BadVersion(v) => write!(f, "ipv4: version {v} != 4"),
            ParseError::HeaderLenTooSmall(ihl) => write!(f, "ipv4: ihl {ihl} < 5"),
            ParseError::HeaderLenExceedsBuffer {
                header_len,
                available,
            } => {
                write!(f, "ipv4: header len {header_len} > available {available}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed IPv4 header. Field values are host-order integers decoded from the
/// wire's big-endian layout; addresses stay as raw 4-byte arrays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    /// IP version — always 4 for a successfully parsed header.
    pub version: u8,
    /// Header length in 32-bit words (>= 5).
    pub ihl: u8,
    /// Type of service / DSCP+ECN byte.
    pub tos: u8,
    /// Total datagram length field (header + payload), as stated on the wire.
    pub total_length: u16,
    /// Identification field.
    pub id: u16,
    /// Raw flags + fragment-offset word (use [`Ipv4Header::df`] etc. to decode).
    pub flags_frag: u16,
    /// Time to live.
    pub ttl: u8,
    /// Upper-layer protocol number.
    pub protocol: u8,
    /// Header checksum as carried on the wire.
    pub checksum: u16,
    /// Source address (raw 4 bytes).
    pub src: [u8; 4],
    /// Destination address (raw 4 bytes).
    pub dst: [u8; 4],
    /// IP options bytes (`ihl*4 - 20`); empty when `ihl == 5`.
    pub options: Vec<u8>,
}

impl Ipv4Header {
    /// Bytes this header occupies (`ihl*4`) — the offset at which the payload
    /// begins, i.e. what the C `validate()` returns and the parser advances by.
    #[must_use]
    pub fn header_len(&self) -> usize {
        // ihl <= 15 so ihl*4 <= 60; widen to usize before the multiply.
        usize::from(self.ihl).saturating_mul(4)
    }

    /// Don't-Fragment flag set?
    #[must_use]
    pub fn df(&self) -> bool {
        self.flags_frag & IP_DF != 0
    }

    /// More-Fragments flag set?
    #[must_use]
    pub fn mf(&self) -> bool {
        self.flags_frag & IP_MF != 0
    }

    /// The 13-bit fragment offset (in 8-byte units, as on the wire).
    #[must_use]
    pub fn frag_offset(&self) -> u16 {
        self.flags_frag & IP_OFFMASK
    }

    /// Parse an IPv4 header from the front of `buf`, applying nmap's exact
    /// accept/reject rules. On success the payload starts at [`Ipv4Header::header_len`].
    pub fn parse(buf: &[u8]) -> Result<Ipv4Header, ParseError> {
        if buf.len() < IP_HEADER_LEN {
            return Err(ParseError::Truncated {
                needed: IP_HEADER_LEN,
                available: buf.len(),
            });
        }
        let mut c = Cursor::new(buf);

        // Byte 0: version (high nibble) + IHL (low nibble). Reads are infallible
        // here because we checked len >= 20, but we still use the checked cursor.
        let vhl = c.read_u8().map_err(|_| ParseError::Truncated {
            needed: IP_HEADER_LEN,
            available: buf.len(),
        })?;
        let version = vhl >> 4;
        let ihl = vhl & 0x0F;
        if version != 4 {
            return Err(ParseError::BadVersion(version));
        }
        if ihl < 5 {
            return Err(ParseError::HeaderLenTooSmall(ihl));
        }
        let header_len = usize::from(ihl).saturating_mul(4);
        if header_len > buf.len() {
            return Err(ParseError::HeaderLenExceedsBuffer {
                header_len,
                available: buf.len(),
            });
        }

        // Fixed fields (offsets 1..20). Every read is bounds-checked; the map_err
        // is defensive — none can fail given the length checks above.
        let trunc = || ParseError::Truncated {
            needed: IP_HEADER_LEN,
            available: buf.len(),
        };
        let tos = c.read_u8().map_err(|_| trunc())?;
        let total_length = c.read_be_u16().map_err(|_| trunc())?;
        let id = c.read_be_u16().map_err(|_| trunc())?;
        let flags_frag = c.read_be_u16().map_err(|_| trunc())?;
        let ttl = c.read_u8().map_err(|_| trunc())?;
        let protocol = c.read_u8().map_err(|_| trunc())?;
        let checksum = c.read_be_u16().map_err(|_| trunc())?;
        let src = c.read_array::<4>().map_err(|_| trunc())?;
        let dst = c.read_array::<4>().map_err(|_| trunc())?;

        // Options: the bytes between the fixed header and header_len. header_len is
        // >= 20 and <= buf.len() (checked), so this slice is always in range.
        let opt_len = header_len.saturating_sub(IP_HEADER_LEN);
        let options = c.take(opt_len).map_err(|_| trunc())?.to_vec();

        Ok(Ipv4Header {
            version,
            ihl,
            tos,
            total_length,
            id,
            flags_frag,
            ttl,
            protocol,
            checksum,
            src,
            dst,
            options,
        })
    }

    /// Serialize the header back to bytes (fixed fields + options). The `checksum`
    /// field is written as stored; use [`Ipv4Header::with_computed_checksum`] to set
    /// a correct one first.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_len());
        out.push((self.version << 4) | (self.ihl & 0x0F));
        out.push(self.tos);
        out.extend_from_slice(&self.total_length.to_be_bytes());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags_frag.to_be_bytes());
        out.push(self.ttl);
        out.push(self.protocol);
        out.extend_from_slice(&self.checksum.to_be_bytes());
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(&self.options);
        out
    }

    /// The RFC 791 header checksum computed over this header with the checksum field
    /// treated as zero — what belongs in `checksum` on the wire.
    #[must_use]
    pub fn computed_checksum(&self) -> u16 {
        let mut bytes = self.serialize();
        // Zero the checksum field (offsets 10..12) before summing.
        if bytes.len() >= 12 {
            bytes[10] = 0;
            bytes[11] = 0;
        }
        in_cksum(&bytes)
    }

    /// A clone with `checksum` set to the correct computed value.
    #[must_use]
    pub fn with_computed_checksum(&self) -> Ipv4Header {
        let mut h = self.clone();
        h.checksum = self.computed_checksum();
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid 20-byte header (the Wikipedia RFC-1071 example, UDP, no
    /// options). Its stored checksum 0xB861 is correct.
    fn sample() -> [u8; 20] {
        [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xB8, 0x61, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7,
        ]
    }

    #[test]
    fn parses_all_fixed_fields() {
        let h = Ipv4Header::parse(&sample()).unwrap();
        assert_eq!(h.version, 4);
        assert_eq!(h.ihl, 5);
        assert_eq!(h.header_len(), 20);
        assert_eq!(h.tos, 0);
        assert_eq!(h.total_length, 0x0073);
        assert_eq!(h.id, 0x0000);
        assert_eq!(h.flags_frag, 0x4000);
        assert!(h.df());
        assert!(!h.mf());
        assert_eq!(h.frag_offset(), 0);
        assert_eq!(h.ttl, 0x40);
        assert_eq!(h.protocol, 17);
        assert_eq!(h.checksum, 0xB861);
        assert_eq!(h.src, [192, 168, 0, 1]);
        assert_eq!(h.dst, [192, 168, 0, 199]);
        assert!(h.options.is_empty());
    }

    #[test]
    fn stored_checksum_matches_recomputation() {
        let h = Ipv4Header::parse(&sample()).unwrap();
        assert_eq!(h.checksum, h.computed_checksum());
        assert_eq!(h.with_computed_checksum().checksum, 0xB861);
    }

    #[test]
    fn serialize_roundtrips_the_bytes() {
        let bytes = sample();
        let h = Ipv4Header::parse(&bytes).unwrap();
        assert_eq!(h.serialize(), bytes.to_vec());
    }

    #[test]
    fn parses_options_when_ihl_gt_5() {
        // ihl=6 -> 24-byte header with 4 option bytes.
        let mut b = sample().to_vec();
        b[0] = 0x46; // version 4, ihl 6
        b.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // 4 option bytes
        let h = Ipv4Header::parse(&b).unwrap();
        assert_eq!(h.ihl, 6);
        assert_eq!(h.header_len(), 24);
        assert_eq!(h.options, vec![0x01, 0x02, 0x03, 0x04]);
    }

    // --- the reject rules (must match the C validate() exactly) ---

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(
            Ipv4Header::parse(&[0x45; 19]),
            Err(ParseError::Truncated {
                needed: 20,
                available: 19
            })
        );
        assert!(matches!(
            Ipv4Header::parse(&[]),
            Err(ParseError::Truncated { available: 0, .. })
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut b = sample();
        b[0] = 0x65; // version 6, ihl 5
        assert_eq!(Ipv4Header::parse(&b), Err(ParseError::BadVersion(6)));
    }

    #[test]
    fn rejects_ihl_below_5() {
        let mut b = sample();
        b[0] = 0x44; // version 4, ihl 4
        assert_eq!(Ipv4Header::parse(&b), Err(ParseError::HeaderLenTooSmall(4)));
    }

    #[test]
    fn rejects_ihl_exceeding_buffer() {
        // ihl=15 -> claims a 60-byte header, but only 20 bytes are present.
        let mut b = sample();
        b[0] = 0x4F; // version 4, ihl 15
        assert_eq!(
            Ipv4Header::parse(&b),
            Err(ParseError::HeaderLenExceedsBuffer {
                header_len: 60,
                available: 20
            })
        );
    }

    #[test]
    fn ihl_exactly_fills_buffer_is_accepted() {
        // ihl=6 (24 bytes) with exactly 24 bytes present — boundary accept.
        let mut b = sample().to_vec();
        b[0] = 0x46;
        b.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(b.len(), 24);
        let h = Ipv4Header::parse(&b).unwrap();
        assert_eq!(h.header_len(), 24);
        assert_eq!(h.options, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn never_panics_on_arbitrary_prefixes_of_the_sample() {
        // Truncation sweep: every prefix parses to Ok or a clean Err, never panics.
        let full = sample();
        for n in 0..=full.len() {
            let _ = Ipv4Header::parse(&full[..n]);
        }
    }
}
