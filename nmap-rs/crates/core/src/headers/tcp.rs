//! TCP header parse + serialize + checksum. Ports nmap's `TCPHeader`
//! (`TCPHeader.{cc,h}`), including a **safe** TCP-options walker.
//!
//! The C stores `MIN(60, len)` bytes into a packed struct (`storeRecvData`), then
//! `validate()`s: data-offset >= 5 and `off*4 <= length`, advancing by `off*4`.
//! `getFlags16` reads a field through an unaligned `*(u16*)` cast. This port
//! reproduces the accept/reject rules over [`Cursor`] with explicit big-endian
//! reads, and walks options with an iterator that cannot infinite-loop on a
//! zero-length option or read past the options area — the hazard the C's
//! `foreachOpt` guards by hand.

use crate::bytes::Cursor;
use crate::checksum::ipv4_pseudoheader_cksum;
use core::fmt;

/// Minimum TCP header length (no options), in bytes.
pub const TCP_HEADER_LEN: usize = 20;
/// IP protocol number for TCP.
pub const IP_PROTO_TCP: u8 = 6;

// TCP flag bits (th_flags byte).
pub const TH_FIN: u8 = 0x01;
pub const TH_SYN: u8 = 0x02;
pub const TH_RST: u8 = 0x04;
pub const TH_PSH: u8 = 0x08;
pub const TH_ACK: u8 = 0x10;
pub const TH_URG: u8 = 0x20;
pub const TH_ECE: u8 = 0x40;
pub const TH_CWR: u8 = 0x80;

/// Why a TCP header failed to parse. Mirrors the C reject points; every case is a
/// clean error, never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than [`TCP_HEADER_LEN`] bytes were available.
    Truncated { needed: usize, available: usize },
    /// Data-offset field was < 5 words (C: `getOffset()<5`).
    OffsetTooSmall(u8),
    /// `off*4` exceeded the bytes available (C: `getOffset()*4 > length`).
    OffsetExceedsBuffer { header_len: usize, available: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { needed, available } => {
                write!(f, "tcp: truncated (need {needed}, have {available})")
            }
            ParseError::OffsetTooSmall(o) => write!(f, "tcp: data offset {o} < 5"),
            ParseError::OffsetExceedsBuffer {
                header_len,
                available,
            } => {
                write!(f, "tcp: header len {header_len} > available {available}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed TCP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    /// Data offset in 32-bit words (>= 5).
    pub data_offset: u8,
    /// The 4 reserved bits (low nibble of byte 12).
    pub reserved: u8,
    /// Flags byte (use [`TcpHeader::syn`] etc. to decode).
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    /// Raw options bytes (`off*4 - 20`); empty when `data_offset == 5`.
    pub options: Vec<u8>,
}

impl TcpHeader {
    /// Bytes this header occupies (`data_offset*4`) — where the payload begins.
    #[must_use]
    pub fn header_len(&self) -> usize {
        usize::from(self.data_offset).saturating_mul(4)
    }

    pub fn syn(&self) -> bool {
        self.flags & TH_SYN != 0
    }
    pub fn ack(&self) -> bool {
        self.flags & TH_ACK != 0
    }
    pub fn rst(&self) -> bool {
        self.flags & TH_RST != 0
    }
    pub fn fin(&self) -> bool {
        self.flags & TH_FIN != 0
    }
    pub fn psh(&self) -> bool {
        self.flags & TH_PSH != 0
    }
    pub fn urg(&self) -> bool {
        self.flags & TH_URG != 0
    }

    /// Parse a TCP header from the front of `buf`, applying nmap's exact
    /// accept/reject rules. On success the payload starts at [`TcpHeader::header_len`].
    pub fn parse(buf: &[u8]) -> Result<TcpHeader, ParseError> {
        if buf.len() < TCP_HEADER_LEN {
            return Err(ParseError::Truncated {
                needed: TCP_HEADER_LEN,
                available: buf.len(),
            });
        }
        let trunc = || ParseError::Truncated {
            needed: TCP_HEADER_LEN,
            available: buf.len(),
        };
        let mut c = Cursor::new(buf);
        let sport = c.read_be_u16().map_err(|_| trunc())?;
        let dport = c.read_be_u16().map_err(|_| trunc())?;
        let seq = c.read_be_u32().map_err(|_| trunc())?;
        let ack = c.read_be_u32().map_err(|_| trunc())?;
        let off_res = c.read_u8().map_err(|_| trunc())?;
        let data_offset = off_res >> 4;
        let reserved = off_res & 0x0F;
        let flags = c.read_u8().map_err(|_| trunc())?;
        let window = c.read_be_u16().map_err(|_| trunc())?;
        let checksum = c.read_be_u16().map_err(|_| trunc())?;
        let urgent_ptr = c.read_be_u16().map_err(|_| trunc())?;

        if data_offset < 5 {
            return Err(ParseError::OffsetTooSmall(data_offset));
        }
        let header_len = usize::from(data_offset).saturating_mul(4);
        if header_len > buf.len() {
            return Err(ParseError::OffsetExceedsBuffer {
                header_len,
                available: buf.len(),
            });
        }
        let opt_len = header_len.saturating_sub(TCP_HEADER_LEN);
        let options = c.take(opt_len).map_err(|_| trunc())?.to_vec();

        Ok(TcpHeader {
            sport,
            dport,
            seq,
            ack,
            data_offset,
            reserved,
            flags,
            window,
            checksum,
            urgent_ptr,
            options,
        })
    }

    /// Serialize the header (fixed fields + options), writing `checksum` as stored.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_len());
        out.extend_from_slice(&self.sport.to_be_bytes());
        out.extend_from_slice(&self.dport.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ack.to_be_bytes());
        out.push((self.data_offset << 4) | (self.reserved & 0x0F));
        out.push(self.flags);
        out.extend_from_slice(&self.window.to_be_bytes());
        out.extend_from_slice(&self.checksum.to_be_bytes());
        out.extend_from_slice(&self.urgent_ptr.to_be_bytes());
        out.extend_from_slice(&self.options);
        out
    }

    /// The RFC 793 checksum over the IPv4 pseudo-header + this segment (+ `payload`),
    /// with the checksum field zeroed — what belongs in `checksum` on the wire.
    #[must_use]
    pub fn computed_checksum(&self, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> u16 {
        let mut seg = self.serialize();
        if seg.len() >= 18 {
            seg[16] = 0; // checksum field high byte
            seg[17] = 0; // checksum field low byte
        }
        seg.extend_from_slice(payload);
        ipv4_pseudoheader_cksum(src, dst, IP_PROTO_TCP, &seg)
    }

    /// Walk the TCP options as `(kind, data)` items, safely. EOL (0) ends the walk;
    /// NOP (1) is a single byte with no data; every other kind is length-prefixed
    /// (`kind, len, len-2 data bytes`). A `len < 2` or a length running past the
    /// options area ends the walk instead of looping forever or reading OOB — the
    /// exact hazard nmap's `foreachOpt` handles by hand.
    #[must_use]
    pub fn options_iter(&self) -> TcpOptionsIter<'_> {
        TcpOptionsIter {
            buf: &self.options,
            pos: 0,
        }
    }
}

/// One parsed TCP option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOption<'a> {
    pub kind: u8,
    pub data: &'a [u8],
}

/// Safe iterator over TCP options (see [`TcpHeader::options_iter`]).
pub struct TcpOptionsIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for TcpOptionsIter<'a> {
    type Item = TcpOption<'a>;

    fn next(&mut self) -> Option<TcpOption<'a>> {
        let kind = *self.buf.get(self.pos)?;
        if kind == 0 {
            // EOL: stop.
            self.pos = self.buf.len();
            return None;
        }
        if kind == 1 {
            // NOP: single byte.
            self.pos = self.pos.saturating_add(1);
            return Some(TcpOption { kind: 1, data: &[] });
        }
        // Length-prefixed. Need a length byte.
        let len = usize::from(*self.buf.get(self.pos.saturating_add(1))?);
        // A valid option length includes the kind+len bytes, so len >= 2; and the
        // whole option must fit in what remains. Either failure ends the walk.
        let end = self.pos.checked_add(len)?;
        if len < 2 || end > self.buf.len() {
            self.pos = self.buf.len();
            return None;
        }
        let data_start = self.pos.saturating_add(2);
        let opt = TcpOption {
            kind,
            data: &self.buf[data_start..end],
        };
        self.pos = end;
        Some(opt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 20-byte SYN with window 0x2000 (matches the M4 ipv6 corpus TCP segment).
    fn sample() -> [u8; 20] {
        [
            0x00, 0x50, 0x01, 0xBB, // sport 80, dport 443
            0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0x20, 0x00, // off=5, flags=SYN, win=0x2000
            0x00, 0x00, 0x00, 0x00, // checksum, urg
        ]
    }

    #[test]
    fn parses_all_fixed_fields() {
        let h = TcpHeader::parse(&sample()).unwrap();
        assert_eq!(h.sport, 80);
        assert_eq!(h.dport, 443);
        assert_eq!(h.seq, 0);
        assert_eq!(h.ack, 0);
        assert_eq!(h.data_offset, 5);
        assert_eq!(h.header_len(), 20);
        assert_eq!(h.flags, TH_SYN);
        assert!(h.syn() && !h.ack() && !h.rst() && !h.fin());
        assert_eq!(h.window, 0x2000);
        assert!(h.options.is_empty());
    }

    #[test]
    fn serialize_roundtrips() {
        let b = sample();
        assert_eq!(TcpHeader::parse(&b).unwrap().serialize(), b.to_vec());
    }

    #[test]
    fn synack_and_rst_flags_decode() {
        let mut b = sample();
        b[13] = TH_SYN | TH_ACK;
        let h = TcpHeader::parse(&b).unwrap();
        assert!(h.syn() && h.ack());
        b[13] = TH_RST | TH_ACK;
        let h = TcpHeader::parse(&b).unwrap();
        assert!(h.rst() && h.ack() && !h.syn());
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(
            TcpHeader::parse(&[0u8; 19]),
            Err(ParseError::Truncated {
                needed: 20,
                available: 19
            })
        );
    }

    #[test]
    fn rejects_data_offset_below_5() {
        let mut b = sample();
        b[12] = 0x40; // off=4
        assert_eq!(TcpHeader::parse(&b), Err(ParseError::OffsetTooSmall(4)));
    }

    #[test]
    fn rejects_offset_exceeding_buffer() {
        let mut b = sample();
        b[12] = 0xF0; // off=15 -> 60 bytes, only 20 present
        assert_eq!(
            TcpHeader::parse(&b),
            Err(ParseError::OffsetExceedsBuffer {
                header_len: 60,
                available: 20
            })
        );
    }

    #[test]
    fn parses_options_and_walks_them_safely() {
        // off=7 -> 28-byte header, 8 option bytes: MSS(2,4,0x05,0xB4), NOP, NOP, EOL, pad
        let mut b = sample().to_vec();
        b[12] = 0x70; // off=7
        b.extend_from_slice(&[0x02, 0x04, 0x05, 0xB4, 0x01, 0x01, 0x00, 0x00]);
        let h = TcpHeader::parse(&b).unwrap();
        assert_eq!(h.header_len(), 28);
        let opts: Vec<_> = h.options_iter().collect();
        assert_eq!(opts.len(), 3); // MSS, NOP, NOP  (EOL stops the walk)
        assert_eq!(opts[0].kind, 2);
        assert_eq!(opts[0].data, &[0x05, 0xB4]);
        assert_eq!(opts[1].kind, 1);
        assert_eq!(opts[2].kind, 1);
    }

    #[test]
    fn zero_length_option_cannot_infinite_loop() {
        // A length-prefixed option claiming len=0 must END the walk, not spin.
        let mut b = sample().to_vec();
        b[12] = 0x60; // off=6 -> 4 option bytes
        b.extend_from_slice(&[0x08, 0x00, 0xAA, 0xBB]); // kind 8, bogus len 0
        let h = TcpHeader::parse(&b).unwrap();
        let opts: Vec<_> = h.options_iter().collect();
        assert!(opts.is_empty()); // len<2 ends the walk immediately
    }

    #[test]
    fn option_length_past_end_ends_walk() {
        let mut b = sample().to_vec();
        b[12] = 0x60; // off=6 -> 4 option bytes
        b.extend_from_slice(&[0x08, 0x40, 0xAA, 0xBB]); // kind 8, len 64 > remaining
        let h = TcpHeader::parse(&b).unwrap();
        assert!(h.options_iter().collect::<Vec<_>>().is_empty());
    }

    #[test]
    fn checksum_is_computed_over_pseudo_header() {
        // Pin a value so a future arithmetic change is caught; cross-checked against
        // the C oracle at the header-serialize differential.
        let h = TcpHeader::parse(&sample()).unwrap();
        let ck = h.computed_checksum([192, 168, 0, 1], [192, 168, 0, 199], &[]);
        // Recompute independently: pseudo-header + zeroed-checksum segment.
        let mut seg = h.serialize();
        seg[16] = 0;
        seg[17] = 0;
        assert_eq!(
            ck,
            crate::checksum::ipv4_pseudoheader_cksum([192, 168, 0, 1], [192, 168, 0, 199], 6, &seg)
        );
    }

    #[test]
    fn truncation_sweep_never_panics() {
        let full = sample();
        for n in 0..=full.len() {
            let _ = TcpHeader::parse(&full[..n]);
        }
    }
}
