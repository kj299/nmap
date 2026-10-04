// cargo-fuzz target for `nmap_core::nse::stdlib::utf8lib` and
// `nmap_core::nse::stdlib::osdate`.
//
// Both take remote data: scripts hand `utf8` functions strings a server sent,
// and hand `os.date` and `os.time` times and date fields parsed out of
// certificates, HTTP headers and SMB replies. The port reimplements the C
// library half of `os.date` (`gmtime`, `mktime`, `strftime`), so this target
// checks it against the real thing in-process, as `nse_format` does
// `snprintf`. The properties checked:
//
//   * `decode` agrees with a transliteration of `utf8_decode` (lutf8lib.c)
//     at every position of any input, strict and lax, reading the C string's
//     terminating NUL past the end;
//   * `encode` of any value up to `MAXUTF` decodes back to it (lax), and of
//     any Unicode scalar value is exactly Rust's own UTF-8;
//   * `gmtime` of any time gives glibc's `gmtime_r` fields, or fails exactly
//     where it does;
//   * `mktime` of any fields (with no DST asked for) gives glibc's `timegm`:
//     the same time and the same normalised fields, or failure;
//   * every conversion `check_option` accepts formats as glibc's `strftime`
//     formats it in the C locale.
//
// Input layout: bytes 0..8 a time, 8..32 six `int` date fields, the rest a
// string to decode and a run of conversions.
#![no_main]

use std::ffi::{c_char, c_int, c_long};

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::stdlib::osdate::{check_option, gmtime, mktime, strftime, Tm, TmInput};
use nmap_core::nse::stdlib::utf8lib::{decode, encode};

/// glibc's `struct tm`.
#[repr(C)]
#[derive(Clone, Copy)]
struct CTm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: *const c_char,
}

extern "C" {
    fn gmtime_r(t: *const i64, out: *mut CTm) -> *mut CTm;
    fn timegm(tm: *mut CTm) -> i64;
    #[link_name = "strftime"]
    fn c_strftime(s: *mut c_char, max: usize, format: *const c_char, tm: *const CTm) -> usize;
}

fn zeroed() -> CTm {
    CTm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    }
}

fn glibc_gmtime(t: i64) -> Option<CTm> {
    let mut out = zeroed();
    // SAFETY: `t` and `out` are valid for the call; `gmtime_r` writes only `out`.
    let r = unsafe { gmtime_r(&t, &mut out) };
    (!r.is_null()).then_some(out)
}

fn fields(c: &CTm) -> [i64; 8] {
    [
        c.tm_sec, c.tm_min, c.tm_hour, c.tm_mday, c.tm_mon, c.tm_year, c.tm_wday, c.tm_yday,
    ]
    .map(i64::from)
}

fn tm_fields(t: &Tm) -> [i64; 8] {
    [t.sec, t.min, t.hour, t.mday, t.mon, t.year, t.wday, t.yday]
}

fn glibc_strftime(conv: &[u8], tm: &CTm) -> Vec<u8> {
    let mut fmt = b"%".to_vec();
    fmt.extend_from_slice(conv);
    fmt.push(0);
    let mut buf = [0u8; 256];
    // SAFETY: `fmt` is NUL-terminated, `buf` is writable for its length and
    // `tm` is a valid `struct tm` whose zone is a static string from glibc.
    let n = unsafe { c_strftime(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr().cast(), tm) };
    buf[..n].to_vec()
}

/// `utf8_decode` (lutf8lib.c), over a C string.
fn reference_decode(s: &[u8], pos: usize, strict: bool) -> Option<(u32, usize)> {
    const LIMITS: [u32; 6] = [!0, 0x80, 0x800, 0x1_0000, 0x20_0000, 0x400_0000];
    let byte = |i: usize| u32::from(s.get(i).copied().unwrap_or(0));
    let mut c = byte(pos);
    let mut res: u32 = 0;
    let mut count: u32 = 0;
    if c < 0x80 {
        res = c;
    } else {
        while c & 0x40 != 0 {
            count += 1;
            let cc = byte(pos + count as usize);
            if cc & 0xC0 != 0x80 {
                return None;
            }
            res = (res << 6) | (cc & 0x3F);
            c <<= 1;
        }
        res |= (c & 0x7F).checked_shl(count * 5).unwrap_or(0);
        if count > 5 || res > 0x7FFF_FFFF || res < LIMITS[count as usize] {
            return None;
        }
    }
    if strict && (res > 0x10_FFFF || (0xD800..=0xDFFF).contains(&res)) {
        return None;
    }
    Some((res, pos + count as usize + 1))
}

fn le_i32(b: &[u8]) -> i32 {
    i32::from_le_bytes(b.try_into().unwrap())
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let rest = &data[32..];

    // utf8.
    for pos in 0..=rest.len() {
        for strict in [false, true] {
            assert_eq!(
                decode(rest, pos, strict),
                reference_decode(rest, pos, strict),
                "decode({rest:?}, {pos}, {strict})"
            );
        }
    }
    let x = u32::from_le_bytes(data[0..4].try_into().unwrap()) & 0x7FFF_FFFF;
    let e = encode(x);
    assert!(e.len() <= 6);
    assert_eq!(decode(&e, 0, false), Some((x, e.len())));
    if let Some(ch) = char::from_u32(x) {
        assert_eq!(e, ch.to_string().into_bytes());
    }

    // gmtime.
    let raw = i64::from_le_bytes(data[0..8].try_into().unwrap());
    // Mostly times a C `int` year can hold, sometimes anything.
    let t = if data[8] & 1 == 0 {
        raw % (1 << 46)
    } else {
        raw
    };
    let ours = gmtime(t);
    let theirs = glibc_gmtime(t);
    assert_eq!(ours.is_some(), theirs.is_some(), "gmtime({t})");
    if let (Some(o), Some(c)) = (ours, theirs) {
        assert_eq!(tm_fields(&o), fields(&c), "gmtime({t})");
        // strftime, on the same broken-down time.
        let mut convs = rest;
        while let Some(i) = convs.iter().position(|&b| b == b'%') {
            convs = &convs[i + 1..];
            if let Some(conv) = check_option(convs) {
                let mut out = Vec::new();
                strftime(&mut out, conv, &o);
                assert_eq!(out, glibc_strftime(conv, &c), "strftime(%{conv:?}) at {t}");
                convs = &convs[conv.len()..];
            }
        }
    }

    // mktime, against timegm (no DST asked for).
    let f: Vec<i32> = data[8..32].chunks(4).map(le_i32).collect();
    // Mostly small fields, which carry into one another; sometimes anything.
    let shape = |v: i32, m: i32| if data[9] & 1 == 0 { v % m } else { v };
    let input = TmInput {
        year: shape(f[0], 1 << 20),
        mon: shape(f[1], 40),
        mday: shape(f[2], 400),
        hour: shape(f[3], 100),
        min: shape(f[4], 5000),
        sec: shape(f[5], 1 << 20),
        isdst: if data[9] & 2 == 0 { -1 } else { 0 },
    };
    let mut c = zeroed();
    c.tm_year = input.year;
    c.tm_mon = input.mon;
    c.tm_mday = input.mday;
    c.tm_hour = input.hour;
    c.tm_min = input.min;
    c.tm_sec = input.sec;
    c.tm_isdst = input.isdst;
    // SAFETY: `c` is a valid, exclusively borrowed `struct tm`.
    let theirs = unsafe { timegm(&mut c) };
    match mktime(input) {
        Some((t, tm)) => {
            assert_eq!(t, theirs, "mktime({input:?})");
            assert_eq!(tm_fields(&tm), fields(&c), "mktime({input:?})");
        }
        None => assert_eq!(theirs, -1, "mktime({input:?}) failed; timegm did not"),
    }
    // A time's own fields come back to it.
    if let Some(o) = ours {
        if let (Ok(year), Ok(mday)) = (i32::try_from(o.year), i32::try_from(o.mday)) {
            let back = mktime(TmInput {
                year,
                mon: o.mon as i32,
                mday,
                hour: o.hour as i32,
                min: o.min as i32,
                sec: o.sec as i32,
                isdst: 0,
            });
            assert_eq!(back.map(|b| b.0), Some(t), "round trip of {t}");
        }
    }
});
