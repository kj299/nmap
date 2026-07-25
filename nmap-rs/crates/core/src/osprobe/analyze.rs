//! Response analysis — turning probe replies into fingerprint attribute values.
//!
//! This slice ports `get_tcpopt_string` and its `tcpopt_tostring` callback from
//! `osscan2.cc`, together with the `TCPOptions` walk in `libnetutil/TCPHeader.cc` that
//! drives them. The result is the `OPS` test's `O1`–`O6` values and the `O` attribute of
//! `ECN` and `T1`–`T7` — the compact option summary that a database entry matches with
//! [`crate::osdb::expr`].
//!
//! The encoding keeps *which* options appeared, *in what order*, and a little of their
//! content, because option order is one of the most discriminating things about a TCP
//! stack:
//!
//! | Option | Emitted | Content |
//! |--------|---------|---------|
//! | End of List | `L` | — |
//! | No-op | `N` | — |
//! | MSS | `M` | value in uppercase hex, no leading zeros |
//! | Window scale | `W` | shift count in uppercase hex |
//! | SACK permitted | `S` | — |
//! | Timestamp | `T` | two digits: is TSval non-zero, is TSecr non-zero |
//!
//! So a Linux SYN/ACK typically reads `M5B4ST11NW7`: MSS 1460, SACK permitted, a
//! timestamp with both halves set, a no-op, window scale 7. Any other option kind is
//! skipped silently — it is consumed, but contributes nothing.

/// Options are at most 40 bytes, and the densest encoding (MSS: 4 bytes in, 5 chars out)
/// bounds the result well under this. Used only as a sanity assertion.
const MAX_OPTION_BYTES: usize = 40;

/// Why an option block could not be summarised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionError {
    /// The segment is shorter than a TCP header, or its data offset is below the
    /// 5-word minimum.
    Truncated,
    /// A type-length-value option ran off the end of the block, or declared a length
    /// below the 2-byte minimum (which the C rejects explicitly to avoid an infinite
    /// loop).
    MalformedLength,
    /// A known option appeared with too few bytes to hold its payload — an MSS in 3
    /// bytes, a timestamp in 6. The C sets `valid = false` for exactly these.
    ShortOption,
}

/// Summarise a TCP segment's options as the fingerprint's `O` attribute value.
///
/// `segment` is the TCP header and everything after it, as received. Returns `None`-ish
/// errors where the C returns `-1`; a segment with no options yields an empty string,
/// which is what the C's empty buffer means and what the database records as `O=`.
///
/// # Divergence from the C's buffer handling
///
/// The C writes into a caller-supplied fixed buffer and checks for room before each
/// write. When the room runs out its callback returns `false`, which stops the option
/// walk — but `foreachOpt` reports that as **success** and `valid` is never cleared, so
/// `get_tcpopt_string` returns a **silently truncated** string rather than the `-1` its
/// own comment claims. A truncated option summary is not a parse failure that gets
/// noticed; it is a different fingerprint. Building a `String` removes the failure mode
/// entirely: there is no buffer to overrun, and the output is bounded by construction
/// because options are capped at 40 bytes.
pub fn tcp_option_string(segment: &[u8]) -> Result<String, OptionError> {
    let options = tcp_options(segment)?;
    let mut out = String::new();

    let mut i = 0usize;
    while i < options.len() {
        let op = options[i];
        // End-of-list and no-op are single bytes with no length field. Note the C does
        // **not** stop at an end-of-list option, contrary to the RFC — it emits `L` and
        // keeps walking, so trailing padding after an EOL still contributes. Stacks do
        // emit options after EOL padding, and the database entries were generated with
        // this behaviour, so it is reproduced rather than corrected.
        let oplen = if matches!(op, 0 | 1) {
            1usize
        } else {
            let len = usize::from(
                *options
                    .get(i.saturating_add(1))
                    .ok_or(OptionError::MalformedLength)?,
            );
            // Below 2 would not advance the cursor — the C rejects it with the comment
            // "No infinite loops, please".
            if len < 2 || len > options.len().saturating_sub(i) {
                return Err(OptionError::MalformedLength);
            }
            len
        };

        // Option payload starts after the kind and length bytes.
        let payload = options.get(i.saturating_add(2)..).unwrap_or_default();

        match op {
            0 => out.push('L'),
            1 => out.push('N'),
            2 => {
                if oplen < 4 {
                    return Err(OptionError::ShortOption);
                }
                out.push('M');
                let mss = u16::from_be_bytes([
                    payload.first().copied().unwrap_or(0),
                    payload.get(1).copied().unwrap_or(0),
                ]);
                out.push_str(&format!("{mss:X}"));
            }
            3 => {
                if oplen < 3 {
                    return Err(OptionError::ShortOption);
                }
                out.push('W');
                let shift = payload.first().copied().unwrap_or(0);
                out.push_str(&format!("{shift:X}"));
            }
            4 => {
                if oplen < 2 {
                    return Err(OptionError::ShortOption);
                }
                out.push('S');
            }
            8 => {
                if oplen < 10 {
                    return Err(OptionError::ShortOption);
                }
                out.push('T');
                // Only whether each half is non-zero is recorded — the values themselves
                // are per-connection noise, but whether a stack echoes them is not.
                let tsval = payload.get(..4).unwrap_or_default();
                let tsecr = payload.get(4..8).unwrap_or_default();
                out.push(if tsval.iter().any(|&b| b != 0) {
                    '1'
                } else {
                    '0'
                });
                out.push(if tsecr.iter().any(|&b| b != 0) {
                    '1'
                } else {
                    '0'
                });
            }
            // Any other option kind is consumed but contributes nothing, as in the C.
            _ => {}
        }

        i = i.saturating_add(oplen);
    }

    debug_assert!(out.len() <= MAX_OPTION_BYTES.saturating_mul(2));
    Ok(out)
}

/// The option bytes of a TCP segment, following `TCPOptions::fromTCPPacket`.
///
/// The C computes `MIN(4 * data_offset, tcplen) - TCP_HEADER_LEN`, so a data offset
/// claiming more options than the captured segment holds is clamped to what is actually
/// present rather than read past.
fn tcp_options(segment: &[u8]) -> Result<&[u8], OptionError> {
    const TCP_HEADER_LEN: usize = 20;
    if segment.len() < TCP_HEADER_LEN {
        return Err(OptionError::Truncated);
    }
    let data_offset = usize::from(segment[12] >> 4);
    if data_offset < 5 {
        return Err(OptionError::Truncated);
    }
    let end = data_offset.saturating_mul(4).min(segment.len());
    Ok(segment.get(TCP_HEADER_LEN..end).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a minimal TCP segment carrying exactly `options`.
    ///
    /// The data offset is rounded up to the next word, and the C's
    /// `MIN(4 * data_offset, tcplen)` clamp then trims it back to the bytes actually
    /// present — so the option block is `options` and nothing more. Padding with real
    /// NOP or end-of-list bytes would encode as `N`/`L` and muddy every expectation.
    fn segment(options: &[u8]) -> Vec<u8> {
        let words = 20usize.saturating_add(options.len()).div_ceil(4);
        let mut s = vec![0u8; 20];
        s[12] = u8::try_from(words << 4).unwrap_or(0xf0);
        s.extend_from_slice(options);
        s
    }

    /// Same, but without padding, so the data offset can be set independently.
    fn segment_raw(options: &[u8], data_offset: u8) -> Vec<u8> {
        let mut s = vec![0u8; 20];
        s[12] = data_offset << 4;
        s.extend_from_slice(options);
        s
    }

    #[test]
    fn the_documented_example_round_trips() {
        // MSS 1460, SACK permitted, timestamp with both halves set, NOP, window scale 7.
        let opts = [
            2, 4, 0x05, 0xb4, // MSS 1460
            4, 2, // SACK permitted
            8, 10, 1, 2, 3, 4, 5, 6, 7, 8, // timestamp, both non-zero
            1, // NOP
            3, 3, 7, // window scale 7
        ];
        assert_eq!(tcp_option_string(&segment(&opts)).unwrap(), "M5B4ST11NW7");
    }

    #[test]
    fn hex_is_uppercase_without_leading_zeros() {
        // The C formats with "%X", so 1460 is 5B4 and a window scale of 10 is A.
        assert_eq!(
            tcp_option_string(&segment(&[2, 4, 0x05, 0xb4])).unwrap(),
            "M5B4"
        );
        assert_eq!(tcp_option_string(&segment(&[3, 3, 10])).unwrap(), "WA");
        assert_eq!(tcp_option_string(&segment(&[3, 3, 0])).unwrap(), "W0");
        assert_eq!(tcp_option_string(&segment(&[2, 4, 0, 1])).unwrap(), "M1");
        assert_eq!(
            tcp_option_string(&segment(&[2, 4, 0xff, 0xff])).unwrap(),
            "MFFFF"
        );
    }

    #[test]
    fn the_timestamp_records_only_whether_each_half_is_set() {
        let ts = |val: [u8; 4], ecr: [u8; 4]| {
            let mut o = vec![8, 10];
            o.extend_from_slice(&val);
            o.extend_from_slice(&ecr);
            tcp_option_string(&segment(&o)).unwrap()
        };
        assert_eq!(ts([0, 0, 0, 0], [0, 0, 0, 0]), "T00");
        assert_eq!(ts([0, 0, 0, 1], [0, 0, 0, 0]), "T10");
        assert_eq!(ts([0, 0, 0, 0], [1, 0, 0, 0]), "T01");
        assert_eq!(ts([9, 9, 9, 9], [9, 9, 9, 9]), "T11");
    }

    #[test]
    fn no_options_is_an_empty_string_not_an_error() {
        let s = segment_raw(&[], 5);
        assert_eq!(tcp_option_string(&s).unwrap(), "");
    }

    #[test]
    fn end_of_list_does_not_stop_the_walk() {
        // Contrary to the RFC, the C emits `L` and keeps going, so options after an EOL
        // still contribute. The shipped database was generated with this behaviour.
        assert_eq!(
            tcp_option_string(&segment(&[0, 1, 4, 2])).unwrap(),
            "LNS",
            "options after an end-of-list must still be summarised"
        );
    }

    #[test]
    fn unknown_options_are_consumed_but_contribute_nothing() {
        // Option kind 5 (SACK) has no encoding, but its length must still be honoured or
        // the walk would desynchronise and misread its payload as further options.
        let opts = [
            1, // NOP
            5, 6, 0xde, 0xad, 0xbe, 0xef, // unknown 6-byte option
            4, 2, // SACK permitted
        ];
        assert_eq!(tcp_option_string(&segment(&opts)).unwrap(), "NS");
    }

    #[test]
    fn options_beyond_the_data_offset_are_ignored() {
        // The data offset, not the buffer length, bounds the option block.
        let s = segment_raw(&[4, 2, 1, 1, 3, 3, 7, 0], 6);
        assert_eq!(
            tcp_option_string(&s).unwrap(),
            "SNN",
            "only the first 4 option bytes are inside the header"
        );
    }

    #[test]
    fn a_data_offset_larger_than_the_capture_is_clamped() {
        // The C takes MIN(4 * data_offset, tcplen), so an over-large offset reads only
        // what is actually present instead of running off the end.
        let s = segment_raw(&[4, 2], 15);
        assert_eq!(tcp_option_string(&s).unwrap(), "S");
    }

    #[test]
    fn a_short_segment_or_data_offset_is_rejected() {
        assert_eq!(tcp_option_string(&[]), Err(OptionError::Truncated));
        assert_eq!(tcp_option_string(&[0u8; 19]), Err(OptionError::Truncated));
        // Data offset below the 5-word minimum.
        assert_eq!(
            tcp_option_string(&segment_raw(&[], 4)),
            Err(OptionError::Truncated)
        );
        assert_eq!(
            tcp_option_string(&segment_raw(&[], 0)),
            Err(OptionError::Truncated)
        );
    }

    #[test]
    fn a_malformed_length_is_rejected_rather_than_looped_on() {
        // Length 0 or 1 would not advance the cursor: the C rejects it with the comment
        // "No infinite loops, please".
        for bad in [0u8, 1] {
            assert_eq!(
                tcp_option_string(&segment_raw(&[2, bad, 0, 0], 6)),
                Err(OptionError::MalformedLength),
                "option length {bad}"
            );
        }
        // A length running past the end of the option block.
        assert_eq!(
            tcp_option_string(&segment_raw(&[2, 40, 0, 0], 6)),
            Err(OptionError::MalformedLength)
        );
        // A TLV kind with no room for its length byte at all.
        assert_eq!(
            tcp_option_string(&segment_raw(&[1, 1, 1, 2], 6)),
            Err(OptionError::MalformedLength)
        );
    }

    #[test]
    fn a_known_option_that_is_too_short_is_rejected() {
        // The C sets `valid = false` for each of these, which becomes a -1 return.
        assert_eq!(
            tcp_option_string(&segment_raw(&[2, 3, 0, 1], 6)),
            Err(OptionError::ShortOption),
            "MSS needs 4 bytes"
        );
        assert_eq!(
            tcp_option_string(&segment_raw(&[3, 2, 0, 1], 6)),
            Err(OptionError::ShortOption),
            "window scale needs 3 bytes"
        );
        assert_eq!(
            tcp_option_string(&segment_raw(&[8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1], 8)),
            Err(OptionError::ShortOption),
            "timestamp needs 10 bytes"
        );
    }

    #[test]
    fn option_order_is_preserved() {
        // Order is a large part of the identifying signal, so two stacks emitting the
        // same options differently must not summarise alike.
        let a = tcp_option_string(&segment(&[2, 4, 0x05, 0xb4, 4, 2])).unwrap();
        let b = tcp_option_string(&segment(&[4, 2, 2, 4, 0x05, 0xb4])).unwrap();
        assert_eq!(a, "M5B4S");
        assert_eq!(b, "SM5B4");
        assert_ne!(a, b);
    }

    #[test]
    fn a_full_forty_byte_option_block_is_handled() {
        // The largest block a TCP header can carry — the C's fixed output buffer is the
        // constraint there, and we have none.
        let opts = vec![1u8; MAX_OPTION_BYTES];
        let s = segment(&opts);
        assert_eq!(tcp_option_string(&s).unwrap(), "N".repeat(MAX_OPTION_BYTES));
    }
}
