//! OpenSSL 3.0.13's BER reader, as its template decoder reads (`crypto/asn1/
//! tasn_dec.c`, `asn1_lib.c`), and the encoder half it re-encodes with
//! (`tasn_enc.c`): what decides whether `parse_ssl_certificate` returns a
//! certificate, and the bytes its `pem` and `digest` are computed over
//! (E5, `spikes/m65-x509/RESULT.md` §10). Pure and total: every input
//! gives a value or [`Bad`], within bounded depth and linear time.
//!
//! The reader follows the C's control flow rather than a schema of its own,
//! because the C's leniencies are the behaviour: lengths in any long form up
//! to `LONG_MAX`, indefinite lengths on constructed elements, constructed
//! strings concatenated, trailing bytes after the outer element ignored, the
//! last field of a SEQUENCE never skipped as absent while data remains.
//! Function names say which C function each one is.
//!
//! **Arithmetic** is on offsets and lengths inside the input slice: a
//! header is only used after [`check_tlen`] has refused one whose length
//! runs past the bytes left, so `off + len` never passes `p.len()`, and a
//! counter decremented is first checked non-zero, as the C checks it.
#![allow(clippy::arithmetic_side_effects)]

/// A decode failure. The C raises one of a few dozen reasons; nmap discards
/// them all (`d2i_X509` returns NULL and `parse_ssl_certificate` nil).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bad;

pub type Res<T> = Result<T, Bad>;

/// What a field's reader returns: the value and the bytes it used, or
/// `None` for an OPTIONAL field that is absent.
pub type Field<T> = Res<Option<(T, usize)>>;

/// The class bits of an identifier octet (`V_ASN1_UNIVERSAL` ...).
pub const UNIVERSAL: u8 = 0x00;
pub const APPLICATION: u8 = 0x40;
pub const CONTEXT: u8 = 0x80;
pub const PRIVATE: u8 = 0xc0;

/// Universal tags (`V_ASN1_*`).
pub mod tag {
    pub const EOC: u32 = 0;
    pub const BOOLEAN: u32 = 1;
    pub const INTEGER: u32 = 2;
    pub const BIT_STRING: u32 = 3;
    pub const OCTET_STRING: u32 = 4;
    pub const NULL: u32 = 5;
    pub const OBJECT: u32 = 6;
    pub const ENUMERATED: u32 = 10;
    pub const UTF8STRING: u32 = 12;
    pub const SEQUENCE: u32 = 16;
    pub const SET: u32 = 17;
    pub const NUMERICSTRING: u32 = 18;
    pub const PRINTABLESTRING: u32 = 19;
    pub const T61STRING: u32 = 20;
    pub const VIDEOTEXSTRING: u32 = 21;
    pub const IA5STRING: u32 = 22;
    pub const UTCTIME: u32 = 23;
    pub const GENERALIZEDTIME: u32 = 24;
    pub const GRAPHICSTRING: u32 = 25;
    pub const VISIBLESTRING: u32 = 26;
    pub const GENERALSTRING: u32 = 27;
    pub const UNIVERSALSTRING: u32 = 28;
    pub const BMPSTRING: u32 = 30;
}

/// `ASN1_tag2bit`'s bits (`B_ASN1_*`), for the multi-string masks.
pub mod bit {
    pub const NUMERICSTRING: u32 = 0x0001;
    pub const PRINTABLESTRING: u32 = 0x0002;
    pub const T61STRING: u32 = 0x0004;
    pub const VIDEOTEXSTRING: u32 = 0x0008;
    pub const IA5STRING: u32 = 0x0010;
    pub const GRAPHICSTRING: u32 = 0x0020;
    pub const ISO64STRING: u32 = 0x0040;
    pub const GENERALSTRING: u32 = 0x0080;
    pub const UNIVERSALSTRING: u32 = 0x0100;
    pub const OCTET_STRING: u32 = 0x0200;
    pub const BIT_STRING: u32 = 0x0400;
    pub const BMPSTRING: u32 = 0x0800;
    pub const UNKNOWN: u32 = 0x1000;
    pub const UTF8STRING: u32 = 0x2000;
    pub const UTCTIME: u32 = 0x4000;
    pub const GENERALIZEDTIME: u32 = 0x8000;
    pub const SEQUENCE: u32 = 0x10000;
    /// `B_ASN1_PRINTABLE`: what a Name's attribute value may be.
    pub const PRINTABLE: u32 = NUMERICSTRING
        | PRINTABLESTRING
        | T61STRING
        | IA5STRING
        | BIT_STRING
        | UNIVERSALSTRING
        | BMPSTRING
        | UTF8STRING
        | SEQUENCE
        | UNKNOWN;
    /// `B_ASN1_TIME`.
    pub const TIME: u32 = UTCTIME | GENERALIZEDTIME;
    /// `B_ASN1_DIRECTORYSTRING`.
    pub const DIRECTORYSTRING: u32 =
        PRINTABLESTRING | TELETEXSTRING | BMPSTRING | UNIVERSALSTRING | UTF8STRING;
    /// `B_ASN1_DISPLAYTEXT`.
    pub const DISPLAYTEXT: u32 = IA5STRING | VISIBLESTRING | BMPSTRING | UTF8STRING;
    pub const TELETEXSTRING: u32 = T61STRING;
    pub const VISIBLESTRING: u32 = ISO64STRING;
}

/// `ASN1_tag2bit` (`tasn_dec.c`).
pub fn tag2bit(tag: u32) -> u32 {
    const T: [u32; 31] = [
        0,
        0,
        0,
        bit::BIT_STRING,
        bit::OCTET_STRING,
        0,
        0,
        bit::UNKNOWN,
        bit::UNKNOWN,
        bit::UNKNOWN,
        0,
        bit::UNKNOWN,
        bit::UTF8STRING,
        bit::UNKNOWN,
        bit::UNKNOWN,
        bit::UNKNOWN,
        bit::SEQUENCE,
        0,
        bit::NUMERICSTRING,
        bit::PRINTABLESTRING,
        bit::T61STRING,
        bit::VIDEOTEXSTRING,
        bit::IA5STRING,
        bit::UTCTIME,
        bit::GENERALIZEDTIME,
        bit::GRAPHICSTRING,
        bit::ISO64STRING,
        bit::GENERALSTRING,
        bit::UNIVERSALSTRING,
        bit::UNKNOWN,
        bit::BMPSTRING,
    ];
    T.get(tag as usize).copied().unwrap_or(0)
}

/// `ASN1_MAX_CONSTRUCTED_NEST`: `asn1_item_embed_d2i`'s depth bound.
pub const MAX_CONSTRUCTED_NEST: u32 = 30;
/// `ASN1_MAX_STRING_NEST`: `asn1_collect`'s.
pub const MAX_STRING_NEST: u32 = 5;
/// `LONG_MAX` on the LP64 targets the oracle runs on.
const LONG_MAX: u64 = i64::MAX as u64;

/// A header as `asn1_check_tlen` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hdr {
    pub tag: u32,
    pub class: u8,
    pub cons: bool,
    pub inf: bool,
    /// The identifier and length octets.
    pub hdr_len: usize,
    /// The content length; for an indefinite length, the bytes left after
    /// the header (`asn1_check_tlen`'s upper bound).
    pub len: usize,
}

/// `ASN1_get_object` over `p` (at most `p.len()` bytes): the header, and
/// whether the definite length runs past the end (the `0x80` "too long"
/// bit, which `asn1_check_tlen` treats as an error). `Err` where it returns
/// `0x80` without a header: a header that does not fit, a high tag past
/// `INT_MAX`, a length of more than 8 significant octets or past `LONG_MAX`,
/// an indefinite length on a primitive.
pub fn get_object(p: &[u8]) -> Res<(Hdr, bool)> {
    let omax = p.len();
    if omax == 0 {
        return Err(Bad);
    }
    let first = p[0];
    let cons = first & 0x20 != 0;
    let class = first & 0xc0;
    let mut i = 1usize;
    let mut max = omax - 1;
    let tag: u32;
    if first & 0x1f == 0x1f {
        if max == 0 {
            return Err(Bad);
        }
        let mut l: u64 = 0;
        while p[i] & 0x80 != 0 {
            l = (l << 7) | u64::from(p[i] & 0x7f);
            i += 1;
            max -= 1;
            if max == 0 {
                return Err(Bad);
            }
            if l > (i32::MAX as u64 >> 7) {
                return Err(Bad);
            }
        }
        l = (l << 7) | u64::from(p[i] & 0x7f);
        i += 1;
        max -= 1;
        if max == 0 {
            return Err(Bad);
        }
        tag = u32::try_from(l).map_err(|_| Bad)?;
    } else {
        tag = u32::from(first & 0x1f);
        if max == 0 {
            return Err(Bad);
        }
    }
    // asn1_get_length, with `max` the bytes after the identifier.
    let (len, inf, used) = get_length(&p[i..], max)?;
    i += used;
    if inf && !cons {
        return Err(Bad);
    }
    let too_long = len > (omax - i) as u64;
    let hdr = Hdr {
        tag,
        class,
        cons,
        inf,
        hdr_len: i,
        len: usize::try_from(len).unwrap_or(usize::MAX),
    };
    Ok((hdr, too_long))
}

/// `asn1_get_length`: (length, indefinite, octets used).
fn get_length(p: &[u8], max: usize) -> Res<(u64, bool, usize)> {
    if max < 1 {
        return Err(Bad);
    }
    let mut max = max - 1;
    let b = p[0];
    if b == 0x80 {
        return Ok((0, true, 1));
    }
    if b & 0x80 == 0 {
        return Ok((u64::from(b), false, 1));
    }
    let mut n = usize::from(b & 0x7f);
    // `if (max < i + 1) return 0`: one octet more than the length octets.
    if max < n + 1 {
        return Err(Bad);
    }
    let mut k = 1usize;
    while n > 0 && p[k] == 0 {
        k += 1;
        n -= 1;
    }
    if n > 8 {
        return Err(Bad);
    }
    let mut ret: u64 = 0;
    while n > 0 {
        ret = (ret << 8) | u64::from(p[k]);
        k += 1;
        n -= 1;
    }
    max = max.saturating_sub(0);
    let _ = max;
    if ret > LONG_MAX {
        return Err(Bad);
    }
    Ok((ret, false, k))
}

/// `asn1_check_tlen` without the context cache (equivalent: the cache only
/// replays a header read at the same place with the same bound). `want` is
/// the expected tag and class; `Ok(None)` is the `-1` of a mismatch on an
/// OPTIONAL field.
pub fn check_tlen(p: &[u8], want: Option<(u32, u8)>, opt: bool) -> Res<Option<Hdr>> {
    if p.is_empty() {
        return Err(Bad);
    }
    let (mut h, too_long) = get_object(p)?;
    if too_long {
        return Err(Bad);
    }
    if let Some((t, c)) = want {
        if t != h.tag || c != h.class {
            if opt {
                return Ok(None);
            }
            return Err(Bad);
        }
    }
    if h.inf {
        h.len = p.len() - h.hdr_len;
    }
    Ok(Some(h))
}

/// `asn1_check_eoc`: two zero octets, swallowed.
pub fn check_eoc(p: &[u8]) -> bool {
    p.len() >= 2 && p[0] == 0 && p[1] == 0
}

/// `asn1_find_end` for the content of an element whose header said `inf`:
/// the bytes from the content's start through its EOC.
pub fn find_end(p: &[u8], len: usize, inf: bool) -> Res<usize> {
    if !inf {
        return Ok(len);
    }
    let mut expected: u64 = 1;
    let mut off = 0usize;
    let mut len = len;
    while len > 0 {
        if check_eoc(&p[off..off + len]) {
            off += 2;
            expected -= 1;
            if expected == 0 {
                break;
            }
            len -= 2;
            continue;
        }
        let h = check_tlen(&p[off..off + len], None, false)?.ok_or(Bad)?;
        let q = off;
        off += h.hdr_len;
        if h.inf {
            if expected == u64::from(u32::MAX) {
                return Err(Bad);
            }
            expected += 1;
        } else {
            off += h.len;
        }
        len -= off - q;
    }
    if expected != 0 {
        return Err(Bad);
    }
    Ok(off)
}

/// `asn1_collect`: the content of a constructed string, its segments'
/// contents concatenated (any universal tag inside, nested at most
/// [`MAX_STRING_NEST`] deep). Returns the bytes consumed.
pub fn collect(out: &mut Vec<u8>, p: &[u8], len: usize, inf: bool, depth: u32) -> Res<usize> {
    let mut inf = inf;
    let mut off = 0usize;
    let mut len = len;
    while len > 0 {
        let q = off;
        if check_eoc(&p[off..off + len]) {
            if !inf {
                return Err(Bad);
            }
            off += 2;
            inf = false;
            break;
        }
        // asn1_check_tlen(..., tag -1, V_ASN1_UNIVERSAL, ...): the tag is
        // not checked (exptag < 0), the class neither.
        let h = check_tlen(&p[off..off + len], None, false)?.ok_or(Bad)?;
        off += h.hdr_len;
        if h.cons {
            if depth >= MAX_STRING_NEST {
                return Err(Bad);
            }
            off += collect(out, &p[off..], h.len, h.inf, depth + 1)?;
        } else if h.len > 0 {
            out.extend_from_slice(&p[off..off + h.len]);
            off += h.len;
        }
        len -= off - q;
    }
    if inf {
        return Err(Bad);
    }
    Ok(off)
}

/// A decoded primitive, as `asn1_ex_c2i` stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prim {
    /// Any string type, and the types stored as strings (`default`).
    Str {
        utype: u32,
        data: Vec<u8>,
    },
    /// SEQUENCE, SET and "other" (a non-universal tag under ANY): the whole
    /// element as received, header included (`cont = *in`).
    Encoded {
        utype: Utype,
        raw: Vec<u8>,
    },
    /// The unused-bits octet and the data, its padding bits masked.
    Bits {
        unused: u8,
        data: Vec<u8>,
    },
    /// An INTEGER or ENUMERATED: its content octets (canonical, checked) and
    /// sign; `ASN1_INTEGER`'s magnitude is [`int_magnitude`] of them.
    Int {
        utype: u32,
        content: Vec<u8>,
        neg: bool,
    },
    Oid(Vec<u8>),
    Null,
    /// The content octet as received (`*tbool = *cont`).
    Bool(u8),
}

/// The type of an element kept in its encoded form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Utype {
    Sequence,
    Set,
    Other,
}

/// `asn1_d2i_ex_primitive` for a fixed type `utype` (not ANY), under an
/// IMPLICIT tag `imp` if any: the value and the bytes consumed, or `None`
/// for an absent OPTIONAL.
pub fn primitive(
    p: &[u8],
    utype: u32,
    imp: Option<(u32, u8)>,
    opt: bool,
) -> Res<Option<(Prim, usize)>> {
    let want = imp.unwrap_or((utype, UNIVERSAL));
    let Some(h) = check_tlen(p, Some(want), opt)? else {
        return Ok(None);
    };
    decode_body(p, h, utype as i64).map(Some)
}

/// `asn1_d2i_ex_primitive` for ASN1_ANY: the type from the header, "other"
/// for a class that is not universal. ANY is never OPTIONAL in the C
/// (`ASN1_R_ILLEGAL_OPTIONAL_ANY`).
pub fn any(p: &[u8]) -> Res<(Prim, usize)> {
    let h = check_tlen(p, None, false)?.ok_or(Bad)?;
    let utype: i64 = if h.class != UNIVERSAL {
        V_ASN1_OTHER
    } else {
        i64::from(h.tag)
    };
    decode_body(p, h, utype)
}

/// `V_ASN1_OTHER`.
const V_ASN1_OTHER: i64 = -3;

/// The rest of `asn1_d2i_ex_primitive` once the header is read, then
/// `asn1_ex_c2i`.
fn decode_body(p: &[u8], h: Hdr, utype: i64) -> Res<(Prim, usize)> {
    let content_start = h.hdr_len;
    let is_seq = utype == i64::from(tag::SEQUENCE);
    let is_set = utype == i64::from(tag::SET);
    if is_seq || is_set || utype == V_ASN1_OTHER {
        if utype != V_ASN1_OTHER && !h.cons {
            return Err(Bad);
        }
        let end = content_start + find_end(&p[content_start..], h.len, h.inf)?;
        let kind = if is_seq {
            Utype::Sequence
        } else if is_set {
            Utype::Set
        } else {
            Utype::Other
        };
        return Ok((
            Prim::Encoded {
                utype: kind,
                raw: p[..end].to_vec(),
            },
            end,
        ));
    }
    let utype = u32::try_from(utype).map_err(|_| Bad)?;
    let (content, end): (std::borrow::Cow<'_, [u8]>, usize) = if h.cons {
        if matches!(
            utype,
            tag::NULL | tag::BOOLEAN | tag::OBJECT | tag::INTEGER | tag::ENUMERATED
        ) {
            return Err(Bad);
        }
        let mut buf = Vec::new();
        let used = collect(&mut buf, &p[content_start..], h.len, h.inf, 0)?;
        (buf.into(), content_start + used)
    } else {
        let end = content_start + h.len;
        (p[content_start..end].into(), end)
    };
    Ok((c2i(&content, utype)?, end))
}

/// `asn1_ex_c2i` for a universal type.
pub fn c2i(cont: &[u8], utype: u32) -> Res<Prim> {
    Ok(match utype {
        tag::OBJECT => {
            check_oid(cont)?;
            Prim::Oid(cont.to_vec())
        }
        tag::NULL => {
            if !cont.is_empty() {
                return Err(Bad);
            }
            Prim::Null
        }
        tag::BOOLEAN => {
            if cont.len() != 1 {
                return Err(Bad);
            }
            Prim::Bool(cont[0])
        }
        tag::BIT_STRING => {
            let (unused, data) = c2i_bit_string(cont)?;
            Prim::Bits { unused, data }
        }
        tag::INTEGER | tag::ENUMERATED => {
            let neg = c2i_ibuf_check(cont)?;
            Prim::Int {
                utype,
                content: cont.to_vec(),
                neg,
            }
        }
        _ => {
            if utype == tag::BMPSTRING && cont.len() & 1 != 0 {
                return Err(Bad);
            }
            if utype == tag::UNIVERSALSTRING && cont.len() & 3 != 0 {
                return Err(Bad);
            }
            Prim::Str {
                utype,
                data: cont.to_vec(),
            }
        }
    })
}

/// `ossl_c2i_ASN1_OBJECT`'s checks: at least one octet, the last without the
/// continuation bit, no sub-identifier starting `0x80`. (An OID OpenSSL
/// knows is valid by construction and skips the scan; its encodings never
/// start a sub-identifier with `0x80`, so the result is the same.)
pub fn check_oid(cont: &[u8]) -> Res<()> {
    if cont.is_empty() || cont.len() > i32::MAX as usize || cont[cont.len() - 1] & 0x80 != 0 {
        return Err(Bad);
    }
    for (i, &b) in cont.iter().enumerate() {
        if b == 0x80 && (i == 0 || cont[i - 1] & 0x80 == 0) {
            return Err(Bad);
        }
    }
    Ok(())
}

/// `ossl_c2i_ASN1_BIT_STRING`: the unused-bits octet (at most 7) and the
/// data, its last octet masked by `0xff << unused`.
pub fn c2i_bit_string(cont: &[u8]) -> Res<(u8, Vec<u8>)> {
    let (&unused, rest) = cont.split_first().ok_or(Bad)?;
    if unused > 7 {
        return Err(Bad);
    }
    let mut data = rest.to_vec();
    if let Some(last) = data.last_mut() {
        *last &= 0xffu8 << unused;
    }
    Ok((unused, data))
}

/// `c2i_ibuf`'s checks: content present, not padded. Returns the sign.
pub fn c2i_ibuf_check(p: &[u8]) -> Res<bool> {
    let (&first, rest) = p.split_first().ok_or(Bad)?;
    let neg = first & 0x80 != 0;
    if rest.is_empty() {
        return Ok(neg);
    }
    let pad = if first == 0 {
        true
    } else if first == 0xff {
        rest.iter().any(|&b| b != 0)
    } else {
        false
    };
    if pad && neg == (rest[0] & 0x80 != 0) {
        return Err(Bad);
    }
    Ok(neg)
}

/// `c2i_ibuf`'s value: the magnitude, big-endian, as `ASN1_INTEGER` holds it
/// (the pad octet dropped, a negative number's two's complement undone).
pub fn int_magnitude(p: &[u8]) -> Vec<u8> {
    let Some(&first) = p.first() else {
        return Vec::new();
    };
    let neg = first & 0x80 != 0;
    if p.len() == 1 {
        return vec![if neg {
            (first ^ 0xff).wrapping_add(1)
        } else {
            first
        }];
    }
    let pad = first == 0 || (first == 0xff && p[1..].iter().any(|&b| b != 0));
    let src = if pad { &p[1..] } else { p };
    if !neg {
        return src.to_vec();
    }
    // twos_complement(dst, src, len, 0xff): invert and add one, from the
    // least significant end.
    let mut out = vec![0u8; src.len()];
    let mut carry = 1u16;
    for i in (0..src.len()).rev() {
        let v = u16::from(src[i] ^ 0xff) + carry;
        out[i] = v.to_le_bytes()[0];
        carry = v >> 8;
    }
    out
}

// ---- encoding (`tasn_enc.c`, `ASN1_put_object`) -------------------------------

/// `ASN1_put_object` with `ASN1_object_size`'s length: a definite header,
/// minimal.
pub fn put_header(out: &mut Vec<u8>, cons: bool, len: usize, tag: u32, class: u8) {
    let id = if cons { 0x20 } else { 0 } | (class & 0xc0);
    if tag < 31 {
        out.push(id | u8::try_from(tag).unwrap_or(0x1f));
    } else {
        out.push(id | 0x1f);
        let mut groups = Vec::new();
        let mut t = tag;
        while t > 0 {
            groups.push((t & 0x7f) as u8);
            t >>= 7;
        }
        for (i, g) in groups.iter().enumerate().rev() {
            out.push(if i == 0 { *g } else { *g | 0x80 });
        }
    }
    if len <= 127 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | u8::try_from(bytes.len() - skip).unwrap_or(8));
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// A TLV with a minimal definite header.
pub fn tlv(tag: u32, class: u8, cons: bool, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 8);
    put_header(&mut out, cons, content.len(), tag, class);
    out.extend_from_slice(content);
    out
}

/// `i2d` of a value decoded as ANY (`asn1_i2d_ex_primitive`, `asn1_ex_i2c`):
/// SEQUENCE, SET and "other" as received; the rest re-encoded primitive and
/// definite under their universal tag, a BIT STRING with its unused-bits
/// octet and masked data.
pub fn i2d_any(v: &Prim) -> Vec<u8> {
    match v {
        Prim::Encoded { raw, .. } => raw.clone(),
        Prim::Str { utype, data } => tlv(*utype, UNIVERSAL, false, data),
        Prim::Bits { unused, data } => tlv(
            tag::BIT_STRING,
            UNIVERSAL,
            false,
            &bit_content(*unused, data),
        ),
        Prim::Int { utype, content, .. } => tlv(*utype, UNIVERSAL, false, content),
        Prim::Oid(c) => tlv(tag::OBJECT, UNIVERSAL, false, c),
        Prim::Null => tlv(tag::NULL, UNIVERSAL, false, &[]),
        Prim::Bool(b) => tlv(tag::BOOLEAN, UNIVERSAL, false, &[*b]),
    }
}

/// `ossl_i2c_ASN1_BIT_STRING` for a string decoded with its unused-bits
/// octet (`ASN1_STRING_FLAG_BITS_LEFT`): that octet, then the data with
/// the last octet masked; an empty string is the octet alone.
pub fn bit_content(unused: u8, data: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(data.len() + 1);
    c.push(if data.is_empty() { 0 } else { unused });
    c.extend_from_slice(data);
    if let Some(last) = c.last_mut().filter(|_| !data.is_empty()) {
        *last &= 0xffu8 << unused;
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_are_asn1_get_length() {
        // Long form with leading zeros, up to 8 significant octets.
        let (h, tl) = get_object(&[0x30, 0x84, 0, 0, 0, 2, 5, 0]).unwrap();
        assert_eq!((h.len, h.hdr_len, tl), (2, 6, false));
        // One octet more than the length octets must be there.
        assert!(get_object(&[0x30, 0x81, 0x00]).is_err());
        assert!(get_object(&[0x30, 0x81, 0x00, 0x00]).is_ok());
        // Nine significant octets.
        assert!(get_object(&[0x30, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // Past LONG_MAX.
        assert!(get_object(&[0x30, 0x88, 0x80, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // Indefinite only when constructed.
        assert!(get_object(&[0x04, 0x80, 0, 0]).is_err());
        let (h, _) = get_object(&[0x30, 0x80, 0, 0]).unwrap();
        assert!(h.inf);
        // A tag octet alone is "header too long".
        assert!(get_object(&[0x30]).is_err());
        // Too long is reported, not an error, here.
        assert!(get_object(&[0x04, 0x05, 1]).unwrap().1);
        // High tags.
        let (h, _) = get_object(&[0x9f, 0x81, 0x00, 0x00]).unwrap();
        assert_eq!((h.tag, h.class), (128, CONTEXT));
    }

    #[test]
    fn find_end_and_collect() {
        // 30 80 (04 01 aa) (30 80 00 00) 00 00
        let p = [0x04, 0x01, 0xaa, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(find_end(&p, p.len(), true), Ok(9));
        assert!(find_end(&p[..7], 7, true).is_err());
        let mut buf = Vec::new();
        // 24 80 (04 01 aa) (04 02 bb cc) 00 00: content of a constructed OCTET STRING
        let q = [0x04, 0x01, 0xaa, 0x04, 0x02, 0xbb, 0xcc, 0x00, 0x00];
        assert_eq!(collect(&mut buf, &q, q.len(), true, 0), Ok(9));
        assert_eq!(buf, [0xaa, 0xbb, 0xcc]);
        // An EOC in definite form is "unexpected EOC".
        assert!(collect(&mut Vec::new(), &q, q.len(), false, 0).is_err());
    }

    #[test]
    fn integers_are_c2i_ibuf() {
        assert!(c2i_ibuf_check(&[]).is_err());
        assert!(c2i_ibuf_check(&[0x00, 0x7f]).is_err());
        assert!(c2i_ibuf_check(&[0xff, 0x80]).is_err());
        assert_eq!(c2i_ibuf_check(&[0x00, 0x80]), Ok(false));
        assert_eq!(c2i_ibuf_check(&[0xff, 0x00]), Ok(true));
        assert_eq!(int_magnitude(&[0xff, 0x00]), [0x01, 0x00]);
        assert_eq!(int_magnitude(&[0xff, 0x7f]), [0x81]);
        assert_eq!(int_magnitude(&[0x80]), [0x80]);
        assert_eq!(int_magnitude(&[0xff]), [0x01]);
        assert_eq!(int_magnitude(&[0x00, 0x80]), [0x80]);
    }

    #[test]
    fn bit_strings_are_masked() {
        assert_eq!(c2i_bit_string(&[3, 0xff]), Ok((3, vec![0xf8])));
        assert!(c2i_bit_string(&[8, 0]).is_err());
        assert!(c2i_bit_string(&[]).is_err());
        assert_eq!(c2i_bit_string(&[5]), Ok((5, vec![])));
        assert_eq!(bit_content(5, &[]), [0]);
        assert_eq!(bit_content(1, &[0xff]), [1, 0xfe]);
    }

    #[test]
    fn oids_are_checked() {
        assert!(check_oid(&[]).is_err());
        assert!(check_oid(&[0x2a, 0x86]).is_err());
        assert!(check_oid(&[0x2a, 0x80, 0x01]).is_err());
        assert!(check_oid(&[0x80, 0x01]).is_err());
        assert!(check_oid(&[0x2a, 0x86, 0x80, 0x01]).is_ok());
    }

    #[test]
    fn headers_are_minimal() {
        assert_eq!(tlv(16, UNIVERSAL, true, &[0; 200])[..3], [0x30, 0x81, 200]);
        assert_eq!(tlv(128, CONTEXT, false, &[])[..], [0x9f, 0x81, 0x00, 0x00]);
    }
}
