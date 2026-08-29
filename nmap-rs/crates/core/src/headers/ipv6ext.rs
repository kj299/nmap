//! IPv6 extension headers. Ports nmap's `HopByHopHeader`, `DestOptsHeader`,
//! `RoutingHeader` and `FragmentHeader` (`libnetutil/*.cc`).
//!
//! These sit between the IPv6 base header and the transport layer, each declaring
//! the protocol that follows it. Only their **length and acceptance rules** matter
//! to a scanner: they decide where the TCP or ICMPv6 header actually starts, and
//! whether nmap's walk reaches it at all. The C's `storeRecvData` + `validate` pair
//! is ported exactly, because a header nmap rejects truncates the whole chain — the
//! transport layer then goes unseen, which for OS detection is the difference
//! between a response that contributes evidence and one that does not.
//!
//! ## The unknown-routing-type rule
//!
//! `RoutingHeader::storeRecvData`'s unknown-type arm reads its own length field
//! *after* clearing the struct it lives in:
//!
//! ```text
//! this->reset();                          // memset(&h, 0, sizeof h)
//! this->length = (this->h.len + 1) * 8;   // h.len is now 0, so length == 8
//! memcpy(&(this->h), buf, this->length);  // h.len is real again
//! ```
//!
//! so the stored length is always 8, and `validate()`'s `length != (h.len+1)*8`
//! then rejects the header unless the real `Hdr Ext Len` is 0. (The type-0 arm gets
//! this right — it computes the length into a local *before* `reset()`.) The net
//! rule is that nmap accepts an unrecognised routing type only as a minimal 8-byte
//! header; anything longer truncates the walk and the rest of the packet is raw.
//!
//! That decision is reproduced, because it is the conservative one — a hostile
//! sender cannot get a deeper parse out of us than out of nmap by hiding a
//! transport header behind an invented routing type — but it is written here as an
//! explicit rule instead of as an accident of statement order. Ledgered as
//! `ipv6ext-unknown-routing-type-is-minimal-only`.
//!
//! ## What this fixes about the C
//!
//! `HopByHopHeader::validate()` walks the option TLVs with a raw
//! `nping_ipv6_ext_hopbyhop_opt_t *` overlay and reads `curr_opt->len` *before*
//! establishing that a length byte exists. With one option byte left, that read
//! lands one past the copied data, inside the 2050-byte packed struct — a read of
//! **uninitialised memory**. Every arm that can be reached in that state rejects
//! the header regardless of the byte's value (`bytes_left < 2 + len` is
//! unconditionally true when `bytes_left == 1`, and the fixed-length arms all fail
//! their second check), so the C's *decision* is deterministic even though the read
//! is not. This port makes the missing length byte an explicit rejection, which
//! reproduces the decision with nothing uninitialised read. Ledgered as
//! `ipv6ext-option-length-byte-must-exist`.

use core::fmt;

/// Every extension header is a multiple of 8 bytes and at least this long.
pub const EXT_HEADER_MIN_LEN: usize = 8;
/// The fragment header is exactly 8 bytes (`FRAGMENT_HEADER_LEN`).
pub const FRAGMENT_HEADER_LEN: usize = 8;
/// A type-2 routing header is exactly 24 bytes (`ROUTING_TYPE_2_HEADER_LEN`).
pub const ROUTING_TYPE_2_HEADER_LEN: usize = 24;

// IP protocol numbers that select an extension header (PacketElement.h).
pub const IP_PROTO_HOPOPT: u8 = 0;
pub const IP_PROTO_ROUTING: u8 = 43;
pub const IP_PROTO_FRAGMENT: u8 = 44;
pub const IP_PROTO_DSTOPTS: u8 = 60;

// Hop-by-Hop / Destination option types (IPv6ExtensionHeader.h).
const EXTOPT_PAD1: u8 = 0x00;
/// PadN is length-driven like an unrecognised option, so it needs no arm of its own;
/// named here because the tests build one and the C lists it explicitly.
#[cfg(test)]
const EXTOPT_PADN: u8 = 0x01;
const EXTOPT_JUMBO: u8 = 0xC2;
const EXTOPT_TUNENCAPLIM: u8 = 0x04;
const EXTOPT_ROUTERALERT: u8 = 0x05;
const EXTOPT_QUICKSTART: u8 = 0x26;
const EXTOPT_CALIPSO: u8 = 0x07;
const EXTOPT_HOMEADDR: u8 = 0xC9;

/// Which extension header this is — selected by the *preceding* header's next-header
/// field, not by anything inside the header itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtKind {
    /// Hop-by-Hop Options (protocol 0).
    HopByHop,
    /// Destination Options (protocol 60). Same wire format and same validation as
    /// hop-by-hop; the C implements it by inheriting `HopByHopHeader`.
    DestOpts,
    /// Routing Header (protocol 43).
    Routing,
    /// Fragment Header (protocol 44).
    Fragment,
}

impl ExtKind {
    /// The extension header a next-header value selects, if any.
    #[must_use]
    pub fn from_protocol(proto: u8) -> Option<ExtKind> {
        match proto {
            IP_PROTO_HOPOPT => Some(ExtKind::HopByHop),
            IP_PROTO_ROUTING => Some(ExtKind::Routing),
            IP_PROTO_FRAGMENT => Some(ExtKind::Fragment),
            IP_PROTO_DSTOPTS => Some(ExtKind::DestOpts),
            _ => None,
        }
    }

    /// Canonical short token — the projection alphabet shared with the C oracle.
    #[must_use]
    pub fn kind_str(self) -> &'static str {
        match self {
            ExtKind::HopByHop => "hopopt",
            ExtKind::DestOpts => "dopts",
            ExtKind::Routing => "route",
            ExtKind::Fragment => "frag",
        }
    }
}

/// Why an extension header failed to parse. Each variant is one of the C's reject
/// points; every case is a clean error, never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than the minimum bytes were available (C: `storeRecvData`).
    Truncated { needed: usize, available: usize },
    /// The `Hdr Ext Len` field claimed more bytes than were present
    /// (C: `(h.len+1)*8 > len`).
    LengthExceedsBuffer { claimed: usize, available: usize },
    /// A routing type 0 header declared an odd `Hdr Ext Len`; it counts 16-byte
    /// addresses, so the field must be even (C: `h.len%2==1`).
    RoutingType0OddLength(u8),
    /// A routing type 0 header claimed more segments left than it carries addresses
    /// (C: `segleft > h.len/2`).
    RoutingSegmentsLeft { segleft: u8, addresses: u8 },
    /// A type-2 routing header did not carry RFC 6275's mandated field values
    /// (C: `segleft!=1 || h.len!=2`).
    RoutingType2Malformed { segleft: u8, hdr_ext_len: u8 },
    /// An unrecognised routing type declared more than the minimum 8 bytes. nmap
    /// accepts an unknown routing type only at that length; see the module docs.
    RoutingUnknownTypeNotMinimal(u8),
    /// An option TLV ran past the end of the options area (C: `bytes_left<2+len`).
    OptionOverruns { option_type: u8, bytes_left: usize },
    /// A fixed-length option declared the wrong length (C: `curr_opt->len!=N`).
    OptionWrongLength {
        option_type: u8,
        expected: u8,
        found: u8,
    },
    /// One byte of options remained, so the TLV length byte does not exist. The C
    /// reads it anyway (uninitialised) and then rejects; this rejects directly.
    OptionLengthByteMissing { option_type: u8 },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated { needed, available } => {
                write!(f, "ipv6ext: truncated (need {needed}, have {available})")
            }
            ParseError::LengthExceedsBuffer { claimed, available } => {
                write!(f, "ipv6ext: claims {claimed} bytes, have {available}")
            }
            ParseError::RoutingType0OddLength(n) => {
                write!(f, "ipv6ext: routing type 0 has odd hdr ext len {n}")
            }
            ParseError::RoutingSegmentsLeft { segleft, addresses } => write!(
                f,
                "ipv6ext: routing segments left {segleft} > {addresses} addresses"
            ),
            ParseError::RoutingType2Malformed {
                segleft,
                hdr_ext_len,
            } => write!(
                f,
                "ipv6ext: routing type 2 needs segleft=1 len=2, got {segleft}/{hdr_ext_len}"
            ),
            ParseError::RoutingUnknownTypeNotMinimal(n) => write!(
                f,
                "ipv6ext: unknown routing type with hdr ext len {n} (only 0 is accepted)"
            ),
            ParseError::OptionOverruns {
                option_type,
                bytes_left,
            } => write!(
                f,
                "ipv6ext: option 0x{option_type:02x} overruns ({bytes_left} bytes left)"
            ),
            ParseError::OptionWrongLength {
                option_type,
                expected,
                found,
            } => write!(
                f,
                "ipv6ext: option 0x{option_type:02x} needs length {expected}, got {found}"
            ),
            ParseError::OptionLengthByteMissing { option_type } => {
                write!(f, "ipv6ext: option 0x{option_type:02x} has no length byte")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed IPv6 extension header.
///
/// The payload is not retained: nothing downstream of the scanner reads a hop-by-hop
/// option or a routing segment, and the fields that matter — how far to advance and
/// what comes next — are here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6ExtHeader {
    /// Which extension header this is.
    pub kind: ExtKind,
    /// Protocol number of the header that follows.
    pub next_header: u8,
    /// The raw `Hdr Ext Len` byte, as it appeared. For a fragment header this field
    /// is reserved and the C ignores it, so it is recorded but not load-bearing.
    pub hdr_ext_len: u8,
    /// Routing type, for [`ExtKind::Routing`] only.
    pub routing_type: Option<u8>,
    /// Bytes this header occupies — what the C's `validate()` returned.
    len: usize,
}

impl Ipv6ExtHeader {
    /// Bytes this header occupies on the wire.
    #[must_use]
    pub fn header_len(&self) -> usize {
        self.len
    }

    /// Parse the extension header `kind` from the front of `buf`.
    pub fn parse(kind: ExtKind, buf: &[u8]) -> Result<Ipv6ExtHeader, ParseError> {
        match kind {
            ExtKind::HopByHop | ExtKind::DestOpts => Ipv6ExtHeader::parse_options(kind, buf),
            ExtKind::Routing => Ipv6ExtHeader::parse_routing(buf),
            ExtKind::Fragment => Ipv6ExtHeader::parse_fragment(buf),
        }
    }

    /// Hop-by-Hop and Destination Options: `nh`, `len`, then `(len+1)*8 - 2` bytes
    /// of TLV-encoded options that must tile the header exactly.
    fn parse_options(kind: ExtKind, buf: &[u8]) -> Result<Ipv6ExtHeader, ParseError> {
        let (next_header, hdr_ext_len) = fixed_two(buf)?;
        let total = declared_len(hdr_ext_len, buf.len())?;
        // The C's own `length%8`, `length<8`, `length>MAX` and `(h.len+1)*8!=length`
        // checks in validate() cannot fail after storeRecvData succeeded — `total` is
        // (hdr_ext_len+1)*8 by construction, so they are omitted rather than
        // reproduced as dead code.
        validate_options(buf.get(2..total).unwrap_or_default())?;
        Ok(Ipv6ExtHeader {
            kind,
            next_header,
            hdr_ext_len,
            routing_type: None,
            len: total,
        })
    }

    /// Routing header: `nh`, `len`, `type`, `segleft`, then type-specific data.
    fn parse_routing(buf: &[u8]) -> Result<Ipv6ExtHeader, ParseError> {
        let (next_header, hdr_ext_len) = fixed_two(buf)?;
        // Safe: fixed_two established at least EXT_HEADER_MIN_LEN (8) bytes.
        let routing_type = buf.get(2).copied().unwrap_or(0);
        let segleft = buf.get(3).copied().unwrap_or(0);

        let total = match routing_type {
            // Type 0 (deprecated by RFC 5095) carries whole 16-byte addresses, so
            // `Hdr Ext Len` counts 8-byte units two at a time and must be even.
            0 => {
                if hdr_ext_len % 2 == 1 {
                    return Err(ParseError::RoutingType0OddLength(hdr_ext_len));
                }
                let total = declared_len(hdr_ext_len, buf.len())?;
                // segleft may be less than the address count (RFC 2460 only forbids
                // more), so this is `>` and not `!=`.
                if segleft > hdr_ext_len / 2 {
                    return Err(ParseError::RoutingSegmentsLeft {
                        segleft,
                        addresses: hdr_ext_len / 2,
                    });
                }
                total
            }
            // Type 2 (RFC 6275 mobility) is fixed at 24 bytes and its two length
            // fields are mandated constants; the C never cross-checks them against
            // `Hdr Ext Len * 8`, because `len == 2` already implies 24.
            2 => {
                if buf.len() < ROUTING_TYPE_2_HEADER_LEN {
                    return Err(ParseError::Truncated {
                        needed: ROUTING_TYPE_2_HEADER_LEN,
                        available: buf.len(),
                    });
                }
                if segleft != 1 || hdr_ext_len != 2 {
                    return Err(ParseError::RoutingType2Malformed {
                        segleft,
                        hdr_ext_len,
                    });
                }
                ROUTING_TYPE_2_HEADER_LEN
            }
            // An unknown routing type says nothing about its own semantics, so nmap
            // only length-checks it — and, through the read-after-reset described in
            // the module docs, accepts it only at the 8-byte minimum.
            _ => {
                let declared = declared_len(hdr_ext_len, buf.len())?;
                if hdr_ext_len != 0 {
                    return Err(ParseError::RoutingUnknownTypeNotMinimal(hdr_ext_len));
                }
                declared
            }
        };

        Ok(Ipv6ExtHeader {
            kind: ExtKind::Routing,
            next_header,
            hdr_ext_len,
            routing_type: Some(routing_type),
            len: total,
        })
    }

    /// Fragment header: a fixed 8 bytes with no field the C validates.
    fn parse_fragment(buf: &[u8]) -> Result<Ipv6ExtHeader, ParseError> {
        let (next_header, hdr_ext_len) = fixed_two(buf)?;
        Ok(Ipv6ExtHeader {
            kind: ExtKind::Fragment,
            next_header,
            hdr_ext_len,
            routing_type: None,
            len: FRAGMENT_HEADER_LEN,
        })
    }
}

/// The `Next Header` and `Hdr Ext Len` bytes, after establishing the 8-byte minimum
/// every extension header's `storeRecvData` requires.
fn fixed_two(buf: &[u8]) -> Result<(u8, u8), ParseError> {
    if buf.len() < EXT_HEADER_MIN_LEN {
        return Err(ParseError::Truncated {
            needed: EXT_HEADER_MIN_LEN,
            available: buf.len(),
        });
    }
    Ok((
        buf.first().copied().unwrap_or(0),
        buf.get(1).copied().unwrap_or(0),
    ))
}

/// `(Hdr Ext Len + 1) * 8`, rejected if it claims more than is present.
///
/// The C computes this in `unsigned int` and compares against `len`; a `u8` field
/// caps it at 2048, so the arithmetic cannot overflow on either side.
fn declared_len(hdr_ext_len: u8, available: usize) -> Result<usize, ParseError> {
    let claimed = usize::from(hdr_ext_len).saturating_add(1).saturating_mul(8);
    if claimed > available {
        return Err(ParseError::LengthExceedsBuffer { claimed, available });
    }
    Ok(claimed)
}

/// Walk the TLV options of a hop-by-hop / destination-options header, applying the
/// C `HopByHopHeader::validate()` rules. `options` is the header minus its first two
/// bytes; the walk must consume it exactly.
fn validate_options(options: &[u8]) -> Result<(), ParseError> {
    // Each fixed-length option is (declared data length, total bytes consumed).
    const FIXED: &[(u8, u8, usize)] = &[
        (EXTOPT_JUMBO, 4, 6),
        (EXTOPT_TUNENCAPLIM, 1, 3),
        (EXTOPT_ROUTERALERT, 2, 4),
        (EXTOPT_QUICKSTART, 6, 8),
        (EXTOPT_HOMEADDR, 16, 18),
    ];

    let mut pos = 0usize;
    while pos < options.len() {
        let bytes_left = options.len().saturating_sub(pos);
        let option_type = options.get(pos).copied().unwrap_or(0);

        // Pad1 is a lone zero byte with no length field.
        if option_type == EXTOPT_PAD1 {
            pos = pos.saturating_add(1);
            continue;
        }

        // Every other option is TLV, so it needs a length byte. The C reads it out
        // of the uninitialised tail of its struct when only one byte remains and
        // then rejects on the following bounds test; rejecting here reaches the same
        // decision without the read (see the module docs).
        let Some(data_len) = options.get(pos.saturating_add(1)).copied() else {
            return Err(ParseError::OptionLengthByteMissing { option_type });
        };

        if let Some(&(_, expected, consumed)) = FIXED.iter().find(|f| f.0 == option_type) {
            if data_len != expected {
                return Err(ParseError::OptionWrongLength {
                    option_type,
                    expected,
                    found: data_len,
                });
            }
            if bytes_left < consumed {
                return Err(ParseError::OptionOverruns {
                    option_type,
                    bytes_left,
                });
            }
            pos = pos.saturating_add(consumed);
            continue;
        }

        // CALIPSO's compartment bitmap is optional, so its length is variable but
        // must cover the fixed part.
        if option_type == EXTOPT_CALIPSO && data_len < 8 {
            return Err(ParseError::OptionWrongLength {
                option_type,
                expected: 8,
                found: data_len,
            });
        }

        // PadN, CALIPSO and every unrecognised option are length-driven: the C
        // trusts `Opt Data Len` as long as the bytes are actually there.
        let consumed = usize::from(data_len).saturating_add(2);
        if bytes_left < consumed {
            return Err(ParseError::OptionOverruns {
                option_type,
                bytes_left,
            });
        }
        pos = pos.saturating_add(consumed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hop-by-hop header carrying `options`, padded with Pad1 to the next 8-byte
    /// boundary so the declared length is consistent.
    fn hopopt(next: u8, options: &[u8]) -> Vec<u8> {
        let mut v = vec![next, 0];
        v.extend_from_slice(options);
        while v.len() % 8 != 0 {
            v.push(EXTOPT_PAD1);
        }
        let units = v.len() / 8;
        v[1] = u8::try_from(units.saturating_sub(1)).unwrap_or(0);
        v
    }

    #[test]
    fn all_pad1_hop_by_hop_is_accepted() {
        let h = Ipv6ExtHeader::parse(ExtKind::HopByHop, &hopopt(6, &[])).expect("parse");
        assert_eq!(h.header_len(), 8);
        assert_eq!(h.next_header, 6);
    }

    #[test]
    fn padn_tiling_the_header_is_accepted() {
        // PadN with 4 data bytes = 6 bytes, exactly filling an 8-byte header.
        let raw = hopopt(58, &[EXTOPT_PADN, 4, 0, 0, 0, 0]);
        assert_eq!(raw.len(), 8);
        let h = Ipv6ExtHeader::parse(ExtKind::HopByHop, &raw).expect("parse");
        assert_eq!(h.header_len(), 8);
        assert_eq!(h.next_header, 58);
    }

    #[test]
    fn an_option_running_past_the_header_is_rejected() {
        // PadN claiming 40 data bytes inside an 8-byte header.
        let raw = hopopt(6, &[EXTOPT_PADN, 40]);
        assert!(matches!(
            Ipv6ExtHeader::parse(ExtKind::HopByHop, &raw),
            Err(ParseError::OptionOverruns { .. })
        ));
    }

    #[test]
    fn a_fixed_length_option_with_the_wrong_length_is_rejected() {
        let raw = hopopt(6, &[EXTOPT_ROUTERALERT, 3, 0, 0]);
        assert!(matches!(
            Ipv6ExtHeader::parse(ExtKind::HopByHop, &raw),
            Err(ParseError::OptionWrongLength { expected: 2, .. })
        ));
    }

    /// The state where the C reads an uninitialised length byte: five Pad1s leave
    /// exactly one option byte, whose type then decides.
    #[test]
    fn a_single_trailing_option_byte_decides_by_type_alone() {
        // Sixth byte is Pad1 → the walk finishes cleanly.
        let mut ok = vec![6u8, 0, 0, 0, 0, 0, 0, 0];
        ok[1] = 0;
        assert!(Ipv6ExtHeader::parse(ExtKind::HopByHop, &ok).is_ok());

        // Sixth byte is a TLV type → no length byte exists, so it is rejected. The C
        // reaches the same verdict via an uninitialised read.
        for t in [EXTOPT_PADN, EXTOPT_JUMBO, EXTOPT_CALIPSO, 0x99] {
            let mut bad = vec![6u8, 0, 0, 0, 0, 0, 0, 0];
            bad[7] = t;
            assert!(
                matches!(
                    Ipv6ExtHeader::parse(ExtKind::HopByHop, &bad),
                    Err(ParseError::OptionLengthByteMissing { .. })
                ),
                "type 0x{t:02x} should be rejected for want of a length byte"
            );
        }
    }

    #[test]
    fn dest_opts_shares_hop_by_hop_validation() {
        let raw = hopopt(6, &[EXTOPT_PADN, 40]);
        assert_eq!(
            Ipv6ExtHeader::parse(ExtKind::DestOpts, &raw).unwrap_err(),
            Ipv6ExtHeader::parse(ExtKind::HopByHop, &raw).unwrap_err()
        );
    }

    #[test]
    fn declared_length_beyond_the_buffer_is_rejected() {
        let mut raw = vec![6u8; 8];
        raw[1] = 4; // claims (4+1)*8 = 40 bytes
        assert!(matches!(
            Ipv6ExtHeader::parse(ExtKind::HopByHop, &raw),
            Err(ParseError::LengthExceedsBuffer {
                claimed: 40,
                available: 8
            })
        ));
    }

    #[test]
    fn routing_type_zero_needs_an_even_length_and_sane_segments_left() {
        // len=2 → 24 bytes, one address; segleft may be 0 or 1.
        let mut raw = vec![0u8; 24];
        raw[0] = 6;
        raw[1] = 2;
        raw[2] = 0; // type 0
        raw[3] = 1; // segleft
        let h = Ipv6ExtHeader::parse(ExtKind::Routing, &raw).expect("parse");
        assert_eq!(h.header_len(), 24);
        assert_eq!(h.routing_type, Some(0));

        raw[3] = 2; // more segments than addresses
        assert!(matches!(
            Ipv6ExtHeader::parse(ExtKind::Routing, &raw),
            Err(ParseError::RoutingSegmentsLeft { .. })
        ));

        raw[1] = 1; // odd hdr ext len
        raw[3] = 0;
        assert!(matches!(
            Ipv6ExtHeader::parse(ExtKind::Routing, &raw),
            Err(ParseError::RoutingType0OddLength(1))
        ));
    }

    #[test]
    fn routing_type_two_is_a_fixed_shape() {
        let mut raw = vec![0u8; 24];
        raw[0] = 58;
        raw[1] = 2;
        raw[2] = 2; // type 2
        raw[3] = 1; // segleft
        let h = Ipv6ExtHeader::parse(ExtKind::Routing, &raw).expect("parse");
        assert_eq!(h.header_len(), ROUTING_TYPE_2_HEADER_LEN);

        raw[3] = 0;
        assert!(matches!(
            Ipv6ExtHeader::parse(ExtKind::Routing, &raw),
            Err(ParseError::RoutingType2Malformed { .. })
        ));

        // Short buffer: the C's storeRecvData refuses before looking at any field.
        assert!(matches!(
            Ipv6ExtHeader::parse(ExtKind::Routing, &raw[..16]),
            Err(ParseError::Truncated { needed: 24, .. })
        ));
    }

    #[test]
    fn an_unknown_routing_type_is_accepted_only_at_the_minimum_length() {
        let mut raw = vec![0u8; 16];
        raw[0] = 6;
        raw[1] = 0; // (0+1)*8 = 8 — the only length nmap accepts here
        raw[2] = 99; // unknown type
        raw[3] = 200; // segleft is not checked for unknown types
        let h = Ipv6ExtHeader::parse(ExtKind::Routing, &raw).expect("parse");
        assert_eq!(h.header_len(), 8);

        raw[1] = 1; // claims 16 bytes; nmap's read-after-reset stores 8 and rejects
        assert!(matches!(
            Ipv6ExtHeader::parse(ExtKind::Routing, &raw),
            Err(ParseError::RoutingUnknownTypeNotMinimal(1))
        ));
    }

    #[test]
    fn fragment_is_always_eight_bytes() {
        let raw = [6u8, 0, 0, 1, 0, 0, 0, 9];
        let h = Ipv6ExtHeader::parse(ExtKind::Fragment, &raw).expect("parse");
        assert_eq!(h.header_len(), FRAGMENT_HEADER_LEN);
        assert_eq!(h.next_header, 6);
        // A longer buffer still yields exactly 8 bytes.
        let long = [6u8; 64];
        assert_eq!(
            Ipv6ExtHeader::parse(ExtKind::Fragment, &long)
                .expect("parse")
                .header_len(),
            FRAGMENT_HEADER_LEN
        );
    }

    #[test]
    fn short_input_is_an_error_for_every_kind() {
        for kind in [
            ExtKind::HopByHop,
            ExtKind::DestOpts,
            ExtKind::Routing,
            ExtKind::Fragment,
        ] {
            for n in 0..EXT_HEADER_MIN_LEN {
                assert!(
                    matches!(
                        Ipv6ExtHeader::parse(kind, &vec![0xffu8; n]),
                        Err(ParseError::Truncated { .. })
                    ),
                    "{kind:?} with {n} bytes"
                );
            }
        }
    }

    #[test]
    // 196k parses: instructive natively, far too slow under Miri's interpreter.
    #[cfg_attr(miri, ignore)]
    fn parse_never_reports_a_length_beyond_the_buffer() {
        // Exhaustive over the first four bytes of an 8-byte header: whatever the
        // header claims, an accepted parse never advances past what we were given.
        let mut raw = [0u8; 8];
        for kind in [ExtKind::HopByHop, ExtKind::Routing, ExtKind::Fragment] {
            for a in 0u8..=255 {
                for b in 0u8..=255 {
                    raw[1] = a;
                    raw[2] = b;
                    if let Ok(h) = Ipv6ExtHeader::parse(kind, &raw) {
                        assert!(h.header_len() <= raw.len(), "{kind:?} {a} {b}");
                        assert!(h.header_len() >= EXT_HEADER_MIN_LEN);
                    }
                }
            }
        }
    }
}
