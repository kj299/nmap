//! Receive-side packet validation. Ports nmap's `validatepkt()` + `validateTCPhdr()`
//! (`tcpip.cc`), the gate `readip_pcap()` runs on every captured frame before it is
//! handed to the scan engine.
//!
//! This is a pure predicate over **untrusted network input** (a captured packet an
//! attacker fully controls), so it is the highest-value fuzz/differential target of
//! the receive path. It answers: is this a well-formed, non-fragmented IPv4 packet
//! whose L4 header (and, for TCP, its option list) is structurally sound — and if so,
//! how many bytes are really packet (capping the link-layer CRC trailer that pcap
//! also captures)?
//!
//! ## Scope / divergence
//!
//! `validate-ipv4-only-for-now` — the C `validatepkt` also validates IPv6 (walking the
//! extension-header chain via `ipv6_get_data`). This port handles IPv4 and rejects
//! IPv6 with [`Reject::Ipv6Unsupported`], deferring IPv6 receive-validation to the
//! same milestone that lands the IPv6 extension-header parser (M5+), consistent with
//! `packet-parser-ported-subset-degrades-to-raw`. Ledgered in `DIVERGENCES.md`.
//!
//! Total on all input: every path returns; no panic, no unchecked index, no unsigned
//! underflow (the exact class the C `OPTLEN_IS` macro guards against by hand).

/// IPv4 fixed header length.
const IP_HEADER_LEN: usize = 20;
/// TCP fixed header length.
const TCP_HEADER_LEN: usize = 20;
/// UDP fixed header length.
const UDP_HEADER_LEN: usize = 8;
/// IPv4 fragment-offset mask (low 13 bits of the flags/frag word).
const IP_OFFMASK: u16 = 0x1FFF;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Why a captured packet was rejected. Mirrors the `validatepkt`/`validateTCPhdr`
/// rejection points (the C only distinguishes them in `--debug` logging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Fewer than 20 bytes — not even a full IPv4 header.
    TooShort,
    /// IP version was neither 4 nor 6.
    BadVersion(u8),
    /// IPv6 receive-validation is not yet ported (see the module scope note).
    Ipv6Unsupported,
    /// The IHL field is < 5 words or runs past the captured bytes.
    BadIpHeaderLen,
    /// A non-initial fragment (fragment offset != 0) — the C drops these.
    Fragment,
    /// A TCP packet whose payload is shorter than the fixed TCP header.
    IncompleteTcpHeader,
    /// A TCP option list that is malformed (bad length, overrun, wrong fixed size).
    BadTcpOptions,
    /// A UDP packet whose payload is shorter than the fixed UDP header.
    IncompleteUdpHeader,
}

/// A captured packet that passed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validated {
    /// IP version (always 4 in this port).
    pub version: u8,
    /// Upper-layer protocol number (`ip_p`).
    pub proto: u8,
    /// IP header length in bytes (`ihl * 4`), i.e. where the L4 header begins.
    pub data_offset: usize,
    /// The real packet length: `min(captured, ip_total_length)`. The C caps the
    /// caller's length here so a link-layer CRC trailer counted by pcap is not
    /// mistaken for packet data.
    pub captured_len: usize,
}

/// Validate a captured IPv4 packet. Ports `validatepkt()` for the IPv4 path.
pub fn validate_packet(buf: &[u8]) -> Result<Validated, Reject> {
    if buf.len() < IP_HEADER_LEN {
        return Err(Reject::TooShort);
    }
    let version = buf[0] >> 4;
    if version == 6 {
        return Err(Reject::Ipv6Unsupported);
    }
    if version != 4 {
        return Err(Reject::BadVersion(version));
    }

    // ipv4_get_data: IHL bounds, then the L4 data length.
    let ihl = buf[0] & 0x0F;
    let header_len = usize::from(ihl).saturating_mul(4);
    if header_len < IP_HEADER_LEN || header_len > buf.len() {
        return Err(Reject::BadIpHeaderLen);
    }
    let datalen = buf.len().saturating_sub(header_len);

    // Reject non-initial fragments.
    let ip_off = u16::from_be_bytes([buf[6], buf[7]]);
    if (ip_off & IP_OFFMASK) != 0 {
        return Err(Reject::Fragment);
    }

    // Cap the reported length to the IP total-length field (drop CRC trailers).
    let iplen = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    let captured_len = buf.len().min(iplen);

    let proto = buf[9];
    let data = &buf[header_len..];
    match proto {
        IPPROTO_TCP => {
            if datalen < TCP_HEADER_LEN {
                return Err(Reject::IncompleteTcpHeader);
            }
            if !validate_tcp_header(data) {
                return Err(Reject::BadTcpOptions);
            }
        }
        IPPROTO_UDP => {
            if datalen < UDP_HEADER_LEN {
                return Err(Reject::IncompleteUdpHeader);
            }
        }
        _ => {}
    }

    Ok(Validated {
        version: 4,
        proto,
        data_offset: header_len,
        captured_len,
    })
}

/// Validate a TCP header including its option list. Ports `validateTCPhdr()`.
///
/// `tcp` is the TCP header + options + payload (length already checked >= 20 by the
/// caller for the receive path, but this is total for any slice). Returns `true` iff
/// the data-offset and every option length are internally consistent — the safe
/// re-implementation of the C `OPTLEN_IS` underflow-guard dance.
#[must_use]
pub fn validate_tcp_header(tcp: &[u8]) -> bool {
    if tcp.len() < TCP_HEADER_LEN {
        return false;
    }
    // Data offset (high nibble of byte 12) in bytes.
    let hdrlen = usize::from(tcp[12] >> 4).saturating_mul(4);
    if hdrlen > tcp.len() || hdrlen < TCP_HEADER_LEN {
        return false;
    }
    // Walk the options region [20, hdrlen).
    let opts = &tcp[TCP_HEADER_LEN..hdrlen];
    let mut pos = 0usize;
    while opts.len().saturating_sub(pos) > 1 {
        let kind = opts[pos];
        // The declared length byte for this option (safe: pos+1 < len by the guard).
        let optlen_byte = usize::from(opts[pos.saturating_add(1)]);
        let remaining = opts.len().saturating_sub(pos);

        // Each arm computes the next position or rejects. `consume_fixed` requires the
        // declared length byte to equal `expected` (the C `OPTLEN_IS(expected)`).
        let next = match kind {
            0 => return true,                 // EOL: options end.
            1 => Some(pos.saturating_add(1)), // NOP: single byte.
            2 => consume_fixed(4, remaining, optlen_byte, pos),
            3 => consume_fixed(3, remaining, optlen_byte, pos),
            4 => consume_fixed(2, remaining, optlen_byte, pos),
            5 => {
                // SACK: length byte must be 2 + a positive multiple of 8.
                let blocks = optlen_byte.saturating_sub(2);
                if optlen_byte < 2 || blocks == 0 || blocks % 8 != 0 {
                    return false;
                }
                consume_variable(optlen_byte, remaining, pos)
            }
            8 => consume_fixed(10, remaining, optlen_byte, pos),
            14 => consume_fixed(3, remaining, optlen_byte, pos),
            _ => consume_variable(optlen_byte, remaining, pos),
        };
        match next {
            Some(p) => pos = p,
            None => return false,
        }
    }

    // One byte left: must be NOP or EOL. Zero bytes left: valid.
    if opts.len().saturating_sub(pos) == 1 {
        return opts[pos] == 0 || opts[pos] == 1;
    }
    true
}

/// The fixed-length `OPTLEN_IS(expected)` case: consume exactly `expected` bytes,
/// requiring the option's declared length byte to equal `expected`.
fn consume_fixed(
    expected: usize,
    remaining: usize,
    optlen_byte: usize,
    pos: usize,
) -> Option<usize> {
    if expected == 0 || remaining < expected || optlen_byte != expected {
        None
    } else {
        pos.checked_add(expected)
    }
}

/// The variable-length `OPTLEN_IS(optlen_byte)` case: consume the option's own
/// declared length, requiring it to be non-zero and to fit the remaining bytes.
fn consume_variable(optlen_byte: usize, remaining: usize, pos: usize) -> Option<usize> {
    if optlen_byte == 0 || remaining < optlen_byte {
        None
    } else {
        pos.checked_add(optlen_byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid IPv4+TCP packet (ihl 5, proto TCP, no options), total_length
    /// set to the full length.
    fn ipv4_tcp(total_len: u16, tcp: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x45,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            0x00,
            0x40,
            IPPROTO_TCP,
            0x00,
            0x00,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
        ];
        let [hi, lo] = total_len.to_be_bytes();
        p[2] = hi;
        p[3] = lo;
        p.extend_from_slice(tcp);
        p
    }

    fn tcp_hdr(data_offset_words: u8, options: &[u8]) -> Vec<u8> {
        let mut t = vec![
            0x00,
            0x50,
            0x01,
            0xbb,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            data_offset_words << 4,
            0x10,
            0x20,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        t.extend_from_slice(options);
        t
    }

    #[test]
    fn accepts_plain_tcp() {
        let tcp = tcp_hdr(5, &[]);
        let pkt = ipv4_tcp(40, &tcp);
        let v = validate_packet(&pkt).unwrap();
        assert_eq!(v.proto, IPPROTO_TCP);
        assert_eq!(v.data_offset, 20);
        assert_eq!(v.captured_len, 40);
    }

    #[test]
    fn caps_captured_len_to_total_length() {
        // total_length says 40 but we captured 44 (a 4-byte Ethernet CRC trailer).
        let tcp = tcp_hdr(5, &[]);
        let mut pkt = ipv4_tcp(40, &tcp);
        pkt.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let v = validate_packet(&pkt).unwrap();
        assert_eq!(v.captured_len, 40, "trailer must be trimmed");
    }

    #[test]
    fn rejects_fragment() {
        let tcp = tcp_hdr(5, &[]);
        let mut pkt = ipv4_tcp(40, &tcp);
        pkt[6] = 0x00;
        pkt[7] = 0x10; // fragment offset = 16 (nonzero)
        assert_eq!(validate_packet(&pkt), Err(Reject::Fragment));
    }

    #[test]
    fn rejects_short_and_bad_version() {
        assert_eq!(validate_packet(&[0u8; 10]), Err(Reject::TooShort));
        let mut pkt = ipv4_tcp(40, &tcp_hdr(5, &[]));
        pkt[0] = 0x75; // version 7
        assert_eq!(validate_packet(&pkt), Err(Reject::BadVersion(7)));
    }

    #[test]
    fn rejects_ipv6() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        assert_eq!(validate_packet(&pkt), Err(Reject::Ipv6Unsupported));
    }

    #[test]
    fn valid_tcp_options_accepted() {
        // MSS(4) + SACK-permitted(2) + NOP + WScale(3) = 10 bytes -> offset 30/4=... 30 not /4.
        // Pad to 12 bytes with EOL so hdrlen = 32 (offset 8 words).
        let opts = [
            0x02, 0x04, 0x05, 0xb4, // MSS 1460
            0x04, 0x02, // SACK permitted
            0x01, // NOP
            0x03, 0x03, 0x07, // WScale 7
            0x00, 0x00, // EOL pad
        ];
        let tcp = tcp_hdr(8, &opts); // 20 + 12 = 32 = 8 words
        let pkt = ipv4_tcp(52, &tcp);
        assert!(validate_packet(&pkt).is_ok());
        assert!(validate_tcp_header(&tcp));
    }

    #[test]
    fn rejects_mss_with_wrong_length_byte() {
        // MSS option claiming length 3 (must be 4). hdrlen 24 (6 words).
        let opts = [0x02, 0x03, 0x05, 0xb4];
        let tcp = tcp_hdr(6, &opts);
        assert!(!validate_tcp_header(&tcp));
        let pkt = ipv4_tcp(44, &tcp);
        assert_eq!(validate_packet(&pkt), Err(Reject::BadTcpOptions));
    }

    #[test]
    fn rejects_option_overrunning_header() {
        // An option (kind 8, timestamp) claiming length 10 but only 4 option bytes.
        let opts = [0x08, 0x0a, 0x00, 0x00];
        let tcp = tcp_hdr(6, &opts);
        assert!(!validate_tcp_header(&tcp));
    }

    #[test]
    fn rejects_sack_with_bad_block_length() {
        // SACK (kind 5) length 6 -> (6-2)=4, 4%8 != 0 -> reject. hdrlen 28 (7 words).
        let opts = [0x05, 0x06, 0, 0, 0, 0, 0, 0];
        let tcp = tcp_hdr(7, &opts);
        assert!(!validate_tcp_header(&tcp));
    }

    #[test]
    fn zero_length_option_does_not_loop() {
        // A bogus option with declared length 0 must be rejected, not spin forever.
        let opts = [0x09, 0x00, 0x00, 0x00];
        let tcp = tcp_hdr(6, &opts);
        assert!(!validate_tcp_header(&tcp));
    }

    #[test]
    fn incomplete_l4_headers_rejected() {
        // proto TCP but only 10 bytes after IP header.
        let mut pkt = ipv4_tcp(30, &[0u8; 10]);
        pkt[9] = IPPROTO_TCP;
        assert_eq!(validate_packet(&pkt), Err(Reject::IncompleteTcpHeader));
        // proto UDP but only 4 bytes.
        let mut pkt = ipv4_tcp(24, &[0u8; 4]);
        pkt[9] = IPPROTO_UDP;
        assert_eq!(validate_packet(&pkt), Err(Reject::IncompleteUdpHeader));
    }

    #[test]
    fn total_validation_never_panics() {
        let base = ipv4_tcp(60, &tcp_hdr(10, &[0xff; 20]));
        for n in 0..=base.len() {
            let _ = validate_packet(&base[..n]);
        }
        for b in 0u16..=511 {
            let opts: Vec<u8> = (0..16)
                .map(|i| u8::try_from(b.wrapping_add(i) & 0xFF).unwrap_or(0))
                .collect();
            let _ = validate_tcp_header(&opts);
        }
    }
}
