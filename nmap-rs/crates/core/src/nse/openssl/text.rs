//! How OpenSSL 3.0.13 renders ASN.1 values as text, as the extension
//! printers (`ext`) call it: times (`ASN1_TIME_print`), names
//! (`X509_NAME_oneline`, `X509_NAME_print_ex` one-line), strings
//! (`ASN1_STRING_print`), integers (`i2s_ASN1_INTEGER`, `i2a_ASN1_INTEGER`,
//! `ASN1_INTEGER_get`), objects (`OBJ_obj2txt` into a buffer,
//! `i2a_ASN1_OBJECT`) and the hex forms (`OPENSSL_buf2hexstr`,
//! `BIO_hex_string`, `BIO_dump`). Each function names the C function it is;
//! each output is byte for byte the C's.
//!
//! **Arithmetic** is on lengths of slices in hand and on calendar fields
//! bounded by the parser (two digits each, a year below 10000), so it does
//! not overflow; the Julian-day sums are `i64`, as the C's `long`.
#![allow(clippy::arithmetic_side_effects)]

use std::fmt::Write as _;

use super::asn1::{self, tag, Prim, Utype};
use super::err::{self, *};
use super::ext::Errs;
use super::objects::{self, nid_of, NID_UNDEF};
use super::x509::NameEntry;

// ---- C string conventions ------------------------------------------------

/// What `%s` of a buffer prints: up to its first NUL.
pub fn cstr(s: &[u8]) -> &[u8] {
    s.iter().position(|&b| b == 0).map_or(s, |i| &s[..i])
}

/// `OBJ_obj2txt(buf, buf_len, obj, no_name)` and what the buffer holds after:
/// the text's first `buf_len - 1` bytes, or nothing where it fails (content
/// past 586 bytes: the buffer's first byte is cleared before anything else).
pub fn obj2txt_buf(oid: &[u8], buf_len: usize, no_name: bool) -> Vec<u8> {
    let mut t = objects::obj2txt(oid, no_name)
        .unwrap_or_default()
        .into_bytes();
    t.truncate(buf_len.saturating_sub(1));
    t
}

/// `i2t_ASN1_OBJECT(buf, buf_len, obj)`.
pub fn i2t(oid: &[u8], buf_len: usize) -> Vec<u8> {
    obj2txt_buf(oid, buf_len, false)
}

/// `i2a_ASN1_OBJECT`: the whole text, or `<INVALID>` and a dump of the
/// content where `OBJ_obj2txt` fails.
pub fn i2a_object(out: &mut Vec<u8>, oid: &[u8]) {
    match objects::obj2txt(oid, false) {
        Some(t) => out.extend_from_slice(t.as_bytes()),
        None => {
            out.extend_from_slice(b"<INVALID>");
            bio_dump(out, oid);
        }
    }
}

/// `OBJ_nid2ln(OBJ_obj2nid(obj))`: `undefined` for an OID OpenSSL does not
/// know.
pub fn nid2ln(oid: &[u8]) -> &'static str {
    objects::long_name(nid_of(oid)).unwrap_or("undefined")
}

// ---- strings -------------------------------------------------------------------

/// `ASN1_STRING_print`: printable ASCII, `\n` and `\r` as they are, every
/// other byte `.`.
pub fn string_print(out: &mut Vec<u8>, data: &[u8]) {
    out.extend(data.iter().map(|&b| {
        if b > b'~' || (b < b' ' && b != b'\n' && b != b'\r') {
            b'.'
        } else {
            b
        }
    }));
}

/// `OPENSSL_buf2hexstr`: `AB:CD:...`, empty for no bytes.
pub fn buf2hexstr(data: &[u8]) -> Vec<u8> {
    let mut s = String::with_capacity(data.len() * 3);
    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        let _ = write!(s, "{b:02X}");
    }
    s.into_bytes()
}

/// `BIO_hex_string(out, indent, width, data, len)`.
pub fn hex_string(out: &mut Vec<u8>, indent: usize, width: usize, data: &[u8]) {
    let Some((&last, rest)) = data.split_last() else {
        return;
    };
    let mut j = 0;
    for (i, b) in rest.iter().enumerate() {
        if i > 0 && j == 0 {
            out.resize(out.len() + indent, b' ');
        }
        out.extend_from_slice(format!("{b:02X}:").as_bytes());
        j = (j + 1) % width;
        if j == 0 {
            out.push(b'\n');
        }
    }
    if !rest.is_empty() && j == 0 {
        out.resize(out.len() + indent, b' ');
    }
    out.extend_from_slice(format!("{last:02X}").as_bytes());
}

/// `BIO_dump` (indent 0): rows of sixteen bytes, `%04x - ` and the hex with
/// a `-` after the eighth, two spaces, the printable ASCII.
pub fn bio_dump(out: &mut Vec<u8>, data: &[u8]) {
    for (row, chunk) in data.chunks(16).enumerate() {
        out.extend_from_slice(format!("{:04x} - ", row * 16).as_bytes());
        for j in 0..16 {
            match chunk.get(j) {
                Some(b) => {
                    let sep = if j == 7 { '-' } else { ' ' };
                    out.extend_from_slice(format!("{b:02x}{sep}").as_bytes());
                }
                None => out.extend_from_slice(b"   "),
            }
        }
        out.extend_from_slice(b"  ");
        out.extend(
            chunk
                .iter()
                .map(|&b| if (b' '..=b'~').contains(&b) { b } else { b'.' }),
        );
        out.push(b'\n');
    }
}

// ---- integers ------------------------------------------------------------------

/// An `ASN1_INTEGER` or `ASN1_ENUMERATED` as `c2i_ASN1_INTEGER` stores it:
/// the sign and the magnitude (at least one octet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Int {
    pub neg: bool,
    pub mag: Vec<u8>,
}

impl Int {
    /// From a decoded INTEGER or ENUMERATED.
    pub fn from_prim(v: &Prim) -> Option<Int> {
        match v {
            Prim::Int { content, neg, .. } => Some(Int {
                neg: *neg,
                mag: asn1::int_magnitude(content),
            }),
            _ => None,
        }
    }
}

/// `i2s_ASN1_INTEGER` (`bignum_to_string`): decimal below 128 bits, else
/// `0x` and `BN_bn2hex`'s whole octets, the sign first.
pub fn i2s_integer(v: &Int) -> Vec<u8> {
    let skip = v.mag.iter().take_while(|&&b| b == 0).count();
    let mag = &v.mag[skip..];
    let bits = mag.first().map_or(0, |&b| {
        (mag.len() - 1) * 8 + (8 - b.leading_zeros() as usize)
    });
    let sign = if v.neg && !mag.is_empty() { "-" } else { "" };
    if bits < 128 {
        let n = mag.iter().fold(0u128, |n, &b| (n << 8) | u128::from(b));
        return format!("{sign}{n}").into_bytes();
    }
    let mut s = format!("{sign}0x");
    for b in mag {
        let _ = write!(s, "{b:02X}");
    }
    s.into_bytes()
}

/// `i2a_ASN1_INTEGER`: the sign, then the magnitude's octets in hex, a
/// backslash-newline before every 35th.
pub fn i2a_integer(out: &mut Vec<u8>, v: &Int) {
    if v.neg {
        out.push(b'-');
    }
    for (i, b) in v.mag.iter().enumerate() {
        if i != 0 && i % 35 == 0 {
            out.extend_from_slice(b"\\\n");
        }
        out.extend_from_slice(format!("{b:02X}").as_bytes());
    }
}

/// `ASN1_INTEGER_get_int64` (`asn1_get_int64`): the value, or `None` with
/// "too large" or "too small" raised.
pub fn get_int64(v: &Int, e: &mut Errs) -> Option<i64> {
    if v.mag.len() > 8 {
        e.raise(err::asn1(ASN1_R_TOO_LARGE));
        return None;
    }
    let r = v.mag.iter().fold(0u64, |n, &b| (n << 8) | u64::from(b));
    if v.neg {
        if let Ok(n) = i64::try_from(r) {
            Some(-n)
        } else if r == 1 << 63 {
            Some(i64::MIN)
        } else {
            e.raise(err::asn1(ASN1_R_TOO_SMALL));
            None
        }
    } else if let Ok(n) = i64::try_from(r) {
        Some(n)
    } else {
        e.raise(err::asn1(ASN1_R_TOO_LARGE));
        None
    }
}

/// `ASN1_INTEGER_get`: -1 where the value does not fit.
pub fn integer_get(v: &Int, e: &mut Errs) -> i64 {
    get_int64(v, e).unwrap_or(-1)
}

/// `ASN1_ENUMERATED_get`: `0xffffffff` for more than eight octets (no error
/// raised), else as [`integer_get`].
pub fn enumerated_get(v: &Int, e: &mut Errs) -> i64 {
    if v.mag.len() > 8 {
        return 0xffff_ffff;
    }
    integer_get(v, e)
}

// ---- times ---------------------------------------------------------------------

/// A `struct tm`'s fields as the printers read them: the full year, the
/// month from 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tm {
    year: i64,
    mon: i64,
    mday: i64,
    hour: i64,
    min: i64,
    sec: i64,
}

fn leap_year(y: i64) -> bool {
    y % 400 == 0 || (y % 100 != 0 && y % 4 == 0)
}

/// `date_to_julian` (Fliegel & Van Flandern; C's truncating division).
fn date_to_julian(y: i64, m: i64, d: i64) -> i64 {
    (1461 * (y + 4800 + (m - 14) / 12)) / 4 + (367 * (m - 2 - 12 * ((m - 14) / 12))) / 12
        - (3 * ((y + 4900 + (m - 14) / 12) / 100)) / 4
        + d
        - 32075
}

/// `julian_to_date`.
fn julian_to_date(jd: i64) -> (i64, i64, i64) {
    let mut l = jd + 68569;
    let n = (4 * l) / 146_097;
    l -= (146_097 * n + 3) / 4;
    let i = (4000 * (l + 1)) / 1_461_001;
    l = l - (1461 * i) / 4 + 31;
    let j = (80 * l) / 2447;
    let d = l - (2447 * j) / 80;
    l = j / 11;
    let m = j + 2 - (12 * l);
    let y = 100 * (n - 49) + i + l;
    (y, m, d)
}

/// `OPENSSL_gmtime_adj(tm, off_day, offset_sec)`: `None` where the result
/// falls outside years 1900 to 9999 or before Julian day 0.
fn gmtime_adj(tm: Tm, off_day: i64, offset_sec: i64) -> Option<Tm> {
    const DAY: i64 = 86_400;
    let mut offset_day = offset_sec / DAY;
    let mut hms = offset_sec - offset_day * DAY;
    offset_day += off_day;
    hms += tm.hour * 3600 + tm.min * 60 + tm.sec;
    if hms >= DAY {
        offset_day += 1;
        hms -= DAY;
    } else if hms < 0 {
        offset_day -= 1;
        hms += DAY;
    }
    let jd = date_to_julian(tm.year, tm.mon + 1, tm.mday) + offset_day;
    if jd < 0 {
        return None;
    }
    let (y, m, d) = julian_to_date(jd);
    if !(1900..=9999).contains(&y) {
        return None;
    }
    Some(Tm {
        year: y,
        mon: m - 1,
        mday: d,
        hour: hms / 3600,
        min: (hms / 60) % 60,
        sec: hms % 60,
    })
}

/// `ossl_asn1_time_to_tm` for a decoded (not RFC 5280-flagged) UTCTime or
/// GeneralizedTime: two-digit fields in range, the day within its month,
/// seconds optional, a fraction after GeneralizedTime's seconds, then `Z` or
/// a `+hhmm`/`-hhmm` offset the time is moved by.
fn time_to_tm(utype: u32, a: &[u8]) -> Option<Tm> {
    const MIN: [i64; 9] = [0, 0, 1, 1, 0, 0, 0, 0, 0];
    const MAX: [i64; 9] = [99, 99, 12, 31, 23, 59, 59, 12, 59];
    const MDAYS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let utc = utype == tag::UTCTIME;
    let (min_l, end, btz) = match utype {
        tag::UTCTIME => (11, 6, 5),
        tag::GENERALIZEDTIME => (13, 7, 6),
        _ => return None,
    };
    let l = a.len();
    if l < min_l {
        return None;
    }
    let digit = |c: u8| c.is_ascii_digit().then(|| i64::from(c - b'0'));
    let mut tm = Tm {
        year: 1900,
        ..Tm::default()
    };
    let mut o = 0;
    for i in 0..end {
        if i == btz && matches!(a[o], b'Z' | b'+' | b'-') {
            break;
        }
        let mut n = digit(a[o])?;
        o += 1;
        if o == l {
            return None;
        }
        n = n * 10 + digit(a[o])?;
        o += 1;
        if o == l {
            return None;
        }
        let i2 = if utc { i + 1 } else { i };
        if n < MIN[i2] || n > MAX[i2] {
            return None;
        }
        match i2 {
            0 => tm.year = n * 100,
            1 => {
                if utc {
                    tm.year = 1900 + if n < 50 { n + 100 } else { n };
                } else {
                    tm.year += n;
                }
            }
            2 => tm.mon = n - 1,
            3 => {
                let md = if tm.mon == 1 {
                    MDAYS[1] + i64::from(leap_year(tm.year))
                } else {
                    MDAYS[usize::try_from(tm.mon).unwrap_or(0)]
                };
                if n > md {
                    return None;
                }
                tm.mday = n;
            }
            4 => tm.hour = n,
            5 => tm.min = n,
            _ => tm.sec = n,
        }
    }
    if !utc && a[o] == b'.' {
        o += 1;
        if o == l {
            return None;
        }
        let start = o;
        while o < l && a[o].is_ascii_digit() {
            o += 1;
        }
        if start == o || o == l {
            return None;
        }
    }
    if a[o] == b'Z' {
        o += 1;
    } else if matches!(a[o], b'+' | b'-') {
        let sign = if a[o] == b'-' { 1 } else { -1 };
        o += 1;
        if o + 4 != l {
            return None;
        }
        let mut offset = 0;
        for i in end..end + 2 {
            let n = digit(a[o])? * 10 + digit(a[o + 1])?;
            o += 2;
            let i2 = if utc { i + 1 } else { i };
            if n < MIN[i2] || n > MAX[i2] {
                return None;
            }
            offset += if i == end { n * 3600 } else { n * 60 };
        }
        if offset != 0 {
            tm = gmtime_adj(tm, 0, offset * sign)?;
        }
    } else {
        return None;
    }
    (o == l).then_some(tm)
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `ASN1_TIME_print` (`ASN1_DTFLGS_RFC822`) of a time of type `utype`:
/// `Mon DD HH:MM:SS[.fff] YYYY[ GMT]`, or `Bad time value`.
pub fn time_print(out: &mut Vec<u8>, utype: u32, v: &[u8]) {
    let Some(tm) = time_to_tm(utype, v) else {
        out.extend_from_slice(b"Bad time value");
        return;
    };
    let gmt = if v.last() == Some(&b'Z') { " GMT" } else { "" };
    let mut frac: &[u8] = b"";
    if utype == tag::GENERALIZEDTIME && v.len() > 15 && v[14] == b'.' {
        let mut n = 1;
        while 14 + n < v.len() && v[14 + n].is_ascii_digit() {
            n += 1;
        }
        frac = &v[14..14 + n];
    }
    let mon = MONTHS[usize::try_from(tm.mon).unwrap_or(0)];
    out.extend_from_slice(
        format!(
            "{mon} {:2} {:02}:{:02}:{:02}",
            tm.mday, tm.hour, tm.min, tm.sec
        )
        .as_bytes(),
    );
    out.extend_from_slice(frac);
    out.extend_from_slice(format!(" {}{gmt}", tm.year).as_bytes());
}

/// The CT printer's `timestamp_print`: milliseconds since 1970 as a
/// GeneralizedTime with milliseconds, through `ASN1_GENERALIZEDTIME_adj`
/// (whose day count is the C's `(int)` of the quotient); nothing where that
/// date is not in years 1900 to 9999.
pub fn ct_timestamp_print(out: &mut Vec<u8>, ts: u64) {
    #[allow(clippy::cast_possible_truncation)] // the C's `(int)` cast
    let days = i64::from((ts / 86_400_000) as i32);
    let secs = i64::try_from((ts % 86_400_000) / 1000).unwrap_or(0);
    let epoch = Tm {
        year: 1970,
        mday: 1,
        ..Tm::default()
    };
    let tm = if days != 0 || secs != 0 {
        match gmtime_adj(epoch, days, secs) {
            Some(tm) => tm,
            None => return,
        }
    } else {
        epoch
    };
    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}.{:03}Z",
        tm.year,
        tm.mon + 1,
        tm.mday,
        tm.hour,
        tm.min,
        tm.sec,
        ts % 1000
    );
    time_print(out, tag::GENERALIZEDTIME, s.as_bytes());
}

// ---- names ---------------------------------------------------------------------

/// The `ASN1_STRING` type of a Name entry's value.
fn value_type(v: &Prim) -> i64 {
    match v {
        Prim::Str { utype, .. } | Prim::Int { utype, .. } => i64::from(*utype),
        Prim::Bits { .. } => i64::from(tag::BIT_STRING),
        Prim::Encoded { utype, .. } => match utype {
            Utype::Sequence => i64::from(tag::SEQUENCE),
            Utype::Set => i64::from(tag::SET),
            Utype::Other => -3,
        },
        Prim::Oid(_) => i64::from(tag::OBJECT),
        Prim::Null => i64::from(tag::NULL),
        Prim::Bool(_) => i64::from(tag::BOOLEAN),
    }
}

/// `NAME_ONELINE_MAX`.
const NAME_ONELINE_MAX: usize = 1024 * 1024;

/// `X509_NAME_oneline(name, buf, len)`: `/SN=value` per entry (`+` for an
/// entry of the same RDN), `/` and `+` escaped, bytes outside printable
/// ASCII as `\xHH`, a GeneralString of four-octet characters by its non-zero
/// octets; entries stop at the first that does not fit in `len - 1` bytes.
/// `None` with "name too long" raised where an entry's value or the text so
/// far passes [`NAME_ONELINE_MAX`].
pub fn name_oneline(entries: &[NameEntry], len: usize, e: &mut Errs) -> Option<Vec<u8>> {
    let len = len - 1;
    let mut buf = Vec::new();
    let mut l = 0usize;
    let mut prev_set = None;
    for ne in entries {
        let nid = nid_of(&ne.oid);
        let s: Vec<u8> = match objects::short_name(nid).filter(|_| nid != NID_UNDEF) {
            Some(sn) => sn.as_bytes().to_vec(),
            None => i2t(&ne.oid, 80),
        };
        let q = super::x509::string_data(&ne.value);
        if q.len() > NAME_ONELINE_MAX {
            e.raise(err::pack(LIB_X509, X509_R_NAME_TOO_LONG));
            return None;
        }
        let mut doit = [true; 4];
        if value_type(&ne.value) == i64::from(tag::GENERALSTRING) && q.len().is_multiple_of(4) {
            let mut nz = [false; 4];
            for (j, &b) in q.iter().enumerate() {
                if b != 0 {
                    nz[j & 3] = true;
                }
            }
            if !(nz[0] || nz[1] || nz[2]) {
                doit = [false, false, false, true];
            }
        }
        let mut l2 = 0usize;
        for (j, &b) in q.iter().enumerate() {
            if !doit[j & 3] {
                continue;
            }
            l2 += 1;
            if b == b'/' || b == b'+' {
                l2 += 1;
            } else if !(b' '..=b'~').contains(&b) {
                l2 += 3;
            }
        }
        l += 1 + s.len() + 1 + l2;
        if l > NAME_ONELINE_MAX {
            e.raise(err::pack(LIB_X509, X509_R_NAME_TOO_LONG));
            return None;
        }
        if l > len {
            break;
        }
        buf.push(if prev_set == Some(ne.set) { b'+' } else { b'/' });
        buf.extend_from_slice(&s);
        buf.push(b'=');
        for (j, &b) in q.iter().enumerate() {
            if !doit[j & 3] {
                continue;
            }
            if !(b' '..=b'~').contains(&b) {
                buf.extend_from_slice(format!("\\x{b:02X}").as_bytes());
            } else {
                if b == b'/' || b == b'+' {
                    buf.push(b'\\');
                }
                buf.push(b);
            }
        }
        prev_set = Some(ne.set);
    }
    Some(buf)
}

/// `char_type` (`crypto/asn1/charmap.h`): each ASCII character's escaping
/// classes.
const CHAR_TYPE: [u16; 128] = [
    1026, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 120, 0, 1, 40, 0, 0, 0, 16, 1040, 1040, 33792, 25, 25, 16400, 8208, 16, 4112, 4112, 4112,
    4112, 4112, 4112, 4112, 4112, 4112, 4112, 16, 9, 9, 16, 9, 16, 0, 4112, 4112, 4112, 4112, 4112,
    4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112,
    4112, 4112, 4112, 4112, 4112, 0, 1025, 0, 0, 0, 0, 4112, 4112, 4112, 4112, 4112, 4112, 4112,
    4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112, 4112,
    4112, 4112, 4112, 0, 0, 0, 0, 2,
];

/// `ASN1_STRFLGS_ESC_2253 | ESC_CTRL | ESC_MSB | ESC_QUOTE`, the escaping
/// `XN_FLAG_ONELINE` asks for.
const ESC: u16 = 1 | 2 | 4 | 8;
const ESC_2253: u16 = 1;
const ESC_QUOTE: u16 = 8;
const FIRST_ESC_2253: u16 = 0x20;
const LAST_ESC_2253: u16 = 0x40;
const BS_ESC: u16 = ESC_2253 | FIRST_ESC_2253 | LAST_ESC_2253;

/// `do_esc_char` for one octet: the bytes it writes, and whether it asks
/// for quotes.
fn esc_char(out: &mut Vec<u8>, c: u8, flags: u16, quotes: &mut bool) {
    let chflgs = if c > 0x7f {
        flags & 4
    } else {
        CHAR_TYPE[usize::from(c)] & flags
    };
    if chflgs & BS_ESC != 0 {
        if chflgs & ESC_QUOTE != 0 {
            *quotes = true;
            out.push(c);
        } else {
            out.push(b'\\');
            out.push(c);
        }
    } else if chflgs & (2 | 4 | 0x400) != 0 {
        out.extend_from_slice(format!("\\{c:02X}").as_bytes());
    } else if c == b'\\' {
        out.extend_from_slice(b"\\\\");
    } else {
        out.push(c);
    }
}

/// `UTF8_putc`: nothing for a surrogate or a value past U+10FFFF.
fn utf8_putc(c: u32) -> Vec<u8> {
    char::from_u32(c).map_or_else(Vec::new, |ch| {
        let mut b = [0u8; 4];
        ch.encode_utf8(&mut b).as_bytes().to_vec()
    })
}

/// `tag2nbyte`: a string type's character width, 0 for UTF-8, `None` for a
/// type dumped instead.
fn tag2nbyte(t: i64) -> Option<usize> {
    match t {
        12 => Some(0),
        18 | 19 | 20 | 22 | 23 | 24 | 26 => Some(1),
        28 => Some(4),
        30 => Some(2),
        _ => None,
    }
}

/// `do_print_ex` with `XN_FLAG_ONELINE`'s string flags: a type with no
/// character width as `#` and its DER in hex; else each character (UTF-8
/// strings octet by octet, the others converted to UTF-8) escaped per RFC
/// 2253, in quotes where a character asked for them.
fn print_ex(out: &mut Vec<u8>, v: &Prim) {
    let t = value_type(v);
    let Some(width) = tag2nbyte(t) else {
        out.push(b'#');
        for b in asn1::i2d_any(v) {
            out.extend_from_slice(format!("{b:02X}").as_bytes());
        }
        return;
    };
    let data = super::x509::string_data(v);
    let (width, conv) = if width == 0 {
        (1, false)
    } else {
        (width, true)
    };
    let mut body = Vec::new();
    let mut quotes = false;
    let chars: Vec<u32> = data
        .chunks(width)
        .map(|c| c.iter().fold(0u32, |n, &b| (n << 8) | u32::from(b)))
        .collect();
    for (i, &c) in chars.iter().enumerate() {
        let mut or = if i == 0 { FIRST_ESC_2253 } else { 0 };
        if i + 1 == chars.len() {
            or = LAST_ESC_2253;
        }
        if conv {
            for b in utf8_putc(c) {
                esc_char(&mut body, b, ESC | or, &mut quotes);
            }
        } else {
            esc_char(&mut body, c.to_be_bytes()[3], ESC | or, &mut quotes);
        }
    }
    if quotes {
        out.push(b'"');
    }
    out.extend_from_slice(&body);
    if quotes {
        out.push(b'"');
    }
}

/// `X509_NAME_print_ex(out, name, 0, XN_FLAG_ONELINE)`: `SN = value`
/// entries, `, ` between RDNs and ` + ` within one, an OID OpenSSL does not
/// know in numbers (79 characters at most). Returns the bytes written.
pub fn name_print_ex(out: &mut Vec<u8>, entries: &[NameEntry]) -> usize {
    let start = out.len();
    let mut prev = None;
    for ne in entries {
        if let Some(p) = prev {
            out.extend_from_slice(if p == ne.set { &b" + "[..] } else { b", " });
        }
        prev = Some(ne.set);
        let nid = nid_of(&ne.oid);
        if nid == NID_UNDEF {
            out.extend(obj2txt_buf(&ne.oid, 80, true));
        } else {
            out.extend_from_slice(objects::short_name(nid).unwrap_or("").as_bytes());
        }
        out.extend_from_slice(b" = ");
        print_ex(out, &ne.value);
    }
    out.len() - start
}

/// `ossl_ipaddr_to_asc`: dotted IPv4, eight `%X` groups for IPv6, else
/// `<invalid length=N>`.
pub fn ipaddr_to_asc(p: &[u8]) -> Vec<u8> {
    match p.len() {
        4 => format!("{}.{}.{}.{}", p[0], p[1], p[2], p[3]).into_bytes(),
        16 => p
            .chunks(2)
            .map(|c| format!("{:X}", u16::from_be_bytes([c[0], c[1]])))
            .collect::<Vec<_>>()
            .join(":")
            .into_bytes(),
        n => format!("<invalid length={n}>").into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tp(utype: u32, s: &str) -> String {
        let mut out = Vec::new();
        time_print(&mut out, utype, s.as_bytes());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn times_print_as_asn1_time_print() {
        let g = tag::GENERALIZEDTIME;
        let u = tag::UTCTIME;
        assert_eq!(tp(g, "20200101000000Z"), "Jan  1 00:00:00 2020 GMT");
        assert_eq!(tp(g, "20200229123456.789Z"), "Feb 29 12:34:56.789 2020 GMT");
        assert_eq!(tp(g, "20190229000000Z"), "Bad time value");
        assert_eq!(tp(g, "202001011200Z"), "Jan  1 12:00:00 2020 GMT");
        assert_eq!(tp(g, "20200101000000+0100"), "Dec 31 23:00:00 2019");
        assert_eq!(tp(g, "20200101230000-0130"), "Jan  2 00:30:00 2020");
        assert_eq!(tp(g, "18991231230000-0100"), "Jan  1 00:00:00 1900");
        assert_eq!(tp(g, "19000101000000+0100"), "Bad time value");
        assert_eq!(tp(u, "491231235959Z"), "Dec 31 23:59:59 2049 GMT");
        assert_eq!(tp(u, "500101000000Z"), "Jan  1 00:00:00 1950 GMT");
        assert_eq!(tp(g, "20200101000000"), "Bad time value");
        assert_eq!(tp(g, "20200101000000.Z"), "Bad time value");
    }

    #[test]
    fn ct_timestamps_carry_milliseconds() {
        let mut out = Vec::new();
        ct_timestamp_print(&mut out, 1_577_836_800_123);
        assert_eq!(out, b"Jan  1 00:00:00.123 2020 GMT");
        let mut out = Vec::new();
        ct_timestamp_print(&mut out, 0);
        assert_eq!(out, b"Jan  1 00:00:00.000 1970 GMT");
        let mut out = Vec::new();
        ct_timestamp_print(&mut out, u64::MAX);
        assert_eq!(out, b"");
    }

    #[test]
    fn integers_print_as_bignum_to_string() {
        let i = |neg, mag: &[u8]| Int {
            neg,
            mag: mag.to_vec(),
        };
        assert_eq!(i2s_integer(&i(false, &[0])), b"0");
        assert_eq!(i2s_integer(&i(true, &[1, 0])), b"-256");
        assert_eq!(
            i2s_integer(&i(false, &[0x7f; 16])),
            b"169473963133173273960190490760135540607"
        );
        assert_eq!(
            i2s_integer(&i(true, &[0x80; 16])),
            b"-0x80808080808080808080808080808080"
        );
        assert_eq!(
            i2s_integer(&i(false, &[0x0a; 17]))[..6].to_vec(),
            b"0x0A0A".to_vec()
        );
    }

    #[test]
    fn hex_forms() {
        assert_eq!(buf2hexstr(&[0xab, 0x01]), b"AB:01");
        assert_eq!(buf2hexstr(&[]), b"");
        let mut out = Vec::new();
        hex_string(&mut out, 4, 2, &[1, 2, 3, 4, 5]);
        assert_eq!(out, b"01:02:\n    03:04:\n    05");
        let mut out = Vec::new();
        bio_dump(&mut out, b"ABCDEFGHIJKLMNOPQ");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "0000 - 41 42 43 44 45 46 47 48-49 4a 4b 4c 4d 4e 4f 50   ABCDEFGHIJKLMNOP\n\
             0010 - 51                                                Q\n"
        );
        assert_eq!(ipaddr_to_asc(&[10, 0, 0, 1]), b"10.0.0.1");
        assert_eq!(
            ipaddr_to_asc(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            b"2001:DB8:0:0:0:0:0:1"
        );
        assert_eq!(ipaddr_to_asc(&[1, 2]), b"<invalid length=2>");
    }

    #[test]
    fn names_escape_as_rfc2253_oneline() {
        let cn = objects::der_of(13).to_vec();
        let ent = |v: &[u8], set| NameEntry {
            oid: cn.clone(),
            value: Prim::Str {
                utype: tag::UTF8STRING,
                data: v.to_vec(),
            },
            set,
        };
        let mut out = Vec::new();
        name_print_ex(
            &mut out,
            &[ent(b" a,b", 0), ent(b"x\"\\\x01", 1), ent(b"#", 1)],
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "CN = \" a,b\", CN = x\\\"\\\\\\01 + CN = #"
        );
        let mut e = Errs::default();
        let one = name_oneline(&[ent(b"a/b\x7f", 0), ent(b"c", 0)], 256, &mut e).unwrap();
        assert_eq!(one, b"/CN=a\\/b\\x7F+CN=c");
    }
}
