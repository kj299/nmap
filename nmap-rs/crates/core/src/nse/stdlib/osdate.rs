//! The arithmetic behind `os.date` and `os.time` (`loslib.c`): breaking a
//! time into calendar fields (`gmtime`), putting fields back together with
//! C's normalisation of out-of-range values (`mktime`), and formatting
//! (`strftime` in the C locale). Pure: no clock, no time zone database.
//!
//! The time zone is UTC. PUC-Lua asks the C library for local time, which
//! reads `TZ` and the system's zone files; this port reads neither, so local
//! time and UTC are the same here (`os-local-time-is-utc`, DIVERGENCES.md).
//! Run under `TZ=UTC`, nmap's own Lua agrees with this module exactly, and
//! that is how the differential corpus runs it.
//!
//! Arithmetic: every quantity here is bounded. `mktime` takes C `int`s and
//! widens them to `i64`; `gmtime` refuses days beyond ±2^40, so every year a
//! [`Tm`] holds fits an `i32` and every day count fits well inside `i64`. No
//! sum or product below comes near overflowing, which the `os_date` fuzz
//! target checks with overflow checks on.
#![allow(clippy::arithmetic_side_effects)]

/// `struct tm`, with the fields `os.date("*t")` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tm {
    /// Seconds, 0-60.
    pub sec: i64,
    pub min: i64,
    pub hour: i64,
    /// Day of the month, 1-31.
    pub mday: i64,
    /// Month, 0-11.
    pub mon: i64,
    /// Years since 1900.
    pub year: i64,
    /// Days since Sunday, 0-6.
    pub wday: i64,
    /// Days since January 1st, 0-365.
    pub yday: i64,
    /// Daylight saving time: never, in UTC.
    pub isdst: bool,
    /// `tm_zone`: `gmtime` calls the zone "GMT", `localtime` under `TZ=UTC`
    /// calls it "UTC".
    pub zone: &'static str,
}

const SECS_PER_DAY: i64 = 86_400;

/// Whether `year` (the full year) is a leap year.
fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Days from 1970-01-01 to `year`-`month`-`day` (proleptic Gregorian;
/// `month` 1-12). Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01: `(year, month 1-12, day 1-31)`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The smallest and largest `days` [`civil_from_days`] is used on: well past
/// any year a C `int` holds, and far from overflowing its arithmetic.
const DAY_RANGE: i64 = 1 << 40;

/// `gmtime`: `t` seconds after the epoch, broken down; `None` where glibc
/// fails, when the year does not fit a C `int`.
pub fn gmtime(t: i64) -> Option<Tm> {
    let days = t.div_euclid(SECS_PER_DAY);
    let secs = t.rem_euclid(SECS_PER_DAY);
    if !(-DAY_RANGE..=DAY_RANGE).contains(&days) {
        return None;
    }
    let (year, month, day) = civil_from_days(days);
    let tm_year = year - 1900;
    if i32::try_from(tm_year).is_err() {
        return None;
    }
    Some(Tm {
        sec: secs % 60,
        min: secs / 60 % 60,
        hour: secs / 3600,
        mday: day,
        mon: month - 1,
        year: tm_year,
        wday: (days + 4).rem_euclid(7),
        yday: days - days_from_civil(year, 1, 1),
        isdst: false,
        zone: "GMT",
    })
}

/// `localtime`: [`gmtime`], local time being UTC here.
pub fn localtime(t: i64) -> Option<Tm> {
    gmtime(t).map(|tm| Tm { zone: "UTC", ..tm })
}

/// The fields `os.time` reads, as C `int`s after `getfield`'s adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TmInput {
    pub year: i32,
    pub mon: i32,
    pub mday: i32,
    pub hour: i32,
    pub min: i32,
    pub sec: i32,
    /// `getboolfield`: absent (-1), false (0) or true (1).
    pub isdst: i32,
}

/// `mktime` in UTC: the time the fields name, with out-of-range fields
/// carried into the next larger one, and the normalised fields; `None` when
/// the result is not a representable `struct tm`. A result of -1 — one second
/// before the epoch — comes back like any other: glibc normalises the fields
/// and returns -1, which `os.time` then reports as an error.
///
/// A daylight-saving flag that is set asks for a time an hour earlier than
/// the fields say, as glibc's `mktime` treats a request for DST in a zone
/// that has none; the normalised fields then report no DST.
pub fn mktime(input: TmInput) -> Option<(i64, Tm)> {
    // glibc carries seconds into minutes and so on with wide arithmetic, so
    // any `int` fields have a sum; only its breakdown can fail.
    let mon = i64::from(input.mon);
    let year = i64::from(input.year) + 1900 + mon.div_euclid(12);
    let month = mon.rem_euclid(12) + 1;
    let days = days_from_civil(year, month, 1) + i64::from(input.mday) - 1;
    let mut t = days
        .checked_mul(SECS_PER_DAY)?
        .checked_add(i64::from(input.hour) * 3600)?
        .checked_add(i64::from(input.min) * 60)?
        .checked_add(i64::from(input.sec))?;
    if input.isdst > 0 {
        t = t.checked_sub(3600)?;
    }
    let tm = localtime(t)?;
    Some((t, tm))
}

/// `LUA_STRFTIMEOPTIONS` for C99: the conversions `os.date` accepts.
const ONE_CHAR: &[u8] = b"aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%";
const TWO_CHAR: &[&[u8]] = &[
    b"Ec", b"EC", b"Ex", b"EX", b"Ey", b"EY", b"Od", b"Oe", b"OH", b"OI", b"Om", b"OM", b"OS",
    b"Ou", b"OU", b"OV", b"Ow", b"OW", b"Oy",
];

/// `checkoption`: the conversion at the start of `conv` (after its `%`), if
/// `os.date` accepts it.
pub fn check_option(conv: &[u8]) -> Option<&[u8]> {
    match conv.first() {
        Some(c) if ONE_CHAR.contains(c) => Some(&conv[..1]),
        _ => TWO_CHAR
            .iter()
            .find(|o| conv.starts_with(o))
            .map(|o| &conv[..o.len()]),
    }
}

/// `os.date`'s error for a conversion it does not accept: what `checkoption`
/// passes to `luaL_argerror`, which `lua_pushfstring` reads as a C string.
pub fn invalid_conversion(conv: &[u8]) -> Vec<u8> {
    let mut msg = b"invalid conversion specifier '%".to_vec();
    let end = conv.iter().position(|&b| b == 0).unwrap_or(conv.len());
    msg.extend_from_slice(&conv[..end]);
    msg.push(b'\'');
    msg
}

const DAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// `v` mod `n` as an index: a day or month number, always in range.
fn index(v: i64, n: i64) -> usize {
    usize::try_from(v.rem_euclid(n)).unwrap_or(0)
}

/// The full year of `tm`.
fn full_year(tm: &Tm) -> i64 {
    tm.year + 1900
}

/// `%U` (`sunday_first`) or `%W`: the week of the year, weeks starting on
/// Sunday or Monday, days before the first such day in week 0.
fn week_number(tm: &Tm, sunday_first: bool) -> i64 {
    let wday = if sunday_first {
        tm.wday
    } else {
        (tm.wday + 6) % 7
    };
    (tm.yday + 7 - wday) / 7
}

/// glibc's `iso_week_days`: days since the first day of the ISO week-based
/// year's first week, which may be negative.
fn iso_week_days(yday: i64, wday: i64) -> i64 {
    const BIG_ENOUGH_MULTIPLE_OF_7: i64 = (366 / 7 + 2) * 7;
    yday - (yday - wday + 4 + BIG_ENOUGH_MULTIPLE_OF_7) % 7 + 3
}

/// The ISO 8601 week-based year and week number of `tm` (`%G`, `%V`).
fn iso_week(tm: &Tm) -> (i64, i64) {
    let mut year = full_year(tm);
    let mut days = iso_week_days(tm.yday, tm.wday);
    if days < 0 {
        // This ISO week belongs to the previous year.
        year -= 1;
        let len = if is_leap(year) { 366 } else { 365 };
        days = iso_week_days(tm.yday + len, tm.wday);
    } else {
        let len = if is_leap(year) { 366 } else { 365 };
        let d = iso_week_days(tm.yday - len, tm.wday);
        if d >= 0 {
            // This ISO week belongs to the next year.
            year += 1;
            days = d;
        }
    }
    (year, days / 7 + 1)
}

/// glibc's `%C`/`%y` arithmetic on a year that may be negative: the century
/// rounds toward negative infinity and the two digits are taken from what is
/// left, as `strftime_l.c` computes them from `tm_year`.
fn century_and_yy(year: i64) -> (i64, i64) {
    let century = year.div_euclid(100);
    (century, year.rem_euclid(100))
}

/// `strftime` in the C locale for one conversion `conv` (as [`check_option`]
/// returned it), appended to `out`. The `E` and `O` modifiers change nothing
/// in the C locale.
pub fn strftime(out: &mut Vec<u8>, conv: &[u8], tm: &Tm) {
    let c = match conv {
        [b'E' | b'O', c] => *c,
        [c] => *c,
        _ => return,
    };
    let mut put = |s: &str| out.extend_from_slice(s.as_bytes());
    let year = full_year(tm);
    match c {
        b'a' => put(&DAYS[index(tm.wday, 7)][..3]),
        b'A' => put(DAYS[index(tm.wday, 7)]),
        b'b' | b'h' => put(&MONTHS[index(tm.mon, 12)][..3]),
        b'B' => put(MONTHS[index(tm.mon, 12)]),
        b'c' => {
            for (i, sub) in [&b"a"[..], b"b", b"e", b"H", b"M", b"S", b"Y"]
                .iter()
                .enumerate()
            {
                strftime(out, sub, tm);
                out.extend_from_slice(match i {
                    0..=2 => b" ",
                    3 | 4 => b":",
                    5 => b" ",
                    _ => b"",
                });
            }
        }
        // glibc prints the century and `%F`'s year as plain numbers, with no
        // padding: year 1 is century "0" and "1-01-01".
        b'C' => put(&century_and_yy(year).0.to_string()),
        b'd' => put(&format!("{:02}", tm.mday)),
        b'D' | b'x' => {
            strftime(out, b"m", tm);
            out.push(b'/');
            strftime(out, b"d", tm);
            out.push(b'/');
            strftime(out, b"y", tm);
        }
        b'e' => put(&format!("{:2}", tm.mday)),
        b'F' => {
            out.extend_from_slice(year.to_string().as_bytes());
            out.push(b'-');
            strftime(out, b"m", tm);
            out.push(b'-');
            strftime(out, b"d", tm);
        }
        b'g' => put(&format!("{:02}", iso_week(tm).0.rem_euclid(100))),
        b'G' => put(&iso_week(tm).0.to_string()),
        b'H' => put(&format!("{:02}", tm.hour)),
        b'I' => put(&format!("{:02}", (tm.hour + 11) % 12 + 1)),
        b'j' => put(&format!("{:03}", tm.yday + 1)),
        b'm' => put(&format!("{:02}", tm.mon + 1)),
        b'M' => put(&format!("{:02}", tm.min)),
        b'n' => put("\n"),
        b'p' => put(if tm.hour < 12 { "AM" } else { "PM" }),
        b'r' => {
            strftime(out, b"I", tm);
            out.push(b':');
            strftime(out, b"M", tm);
            out.push(b':');
            strftime(out, b"S", tm);
            out.push(b' ');
            strftime(out, b"p", tm);
        }
        b'R' => {
            strftime(out, b"H", tm);
            out.push(b':');
            strftime(out, b"M", tm);
        }
        b'S' => put(&format!("{:02}", tm.sec)),
        b't' => put("\t"),
        b'T' | b'X' => {
            strftime(out, b"H", tm);
            out.push(b':');
            strftime(out, b"M", tm);
            out.push(b':');
            strftime(out, b"S", tm);
        }
        b'u' => put(&((tm.wday + 6) % 7 + 1).to_string()),
        b'U' => put(&format!("{:02}", week_number(tm, true))),
        b'V' => put(&format!("{:02}", iso_week(tm).1)),
        b'w' => put(&tm.wday.to_string()),
        b'W' => put(&format!("{:02}", week_number(tm, false))),
        b'y' => put(&format!("{:02}", century_and_yy(year).1)),
        b'Y' => put(&year.to_string()),
        b'z' => put("+0000"),
        b'Z' => put(tm.zone),
        b'%' => put("%"),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trips() {
        for d in [
            -1_000_000, -719_468, -1, 0, 1, 59, 11_016, 2_932_896, 1_000_000,
        ] {
            let (y, m, day) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, day), d);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    }

    #[test]
    fn epoch_breaks_down() {
        let tm = gmtime(0).unwrap();
        assert_eq!(
            (tm.year, tm.mon, tm.mday, tm.wday, tm.yday),
            (70, 0, 1, 4, 0)
        );
        let tm = gmtime(-1).unwrap();
        assert_eq!((tm.year, tm.hour, tm.min, tm.sec), (69, 23, 59, 59));
        assert!(gmtime(i64::MAX).is_none());
    }

    #[test]
    fn mktime_normalises() {
        let input = TmInput {
            year: 100,
            mon: 13,
            mday: 0,
            hour: 25,
            min: -1,
            sec: 61,
            isdst: -1,
        };
        let (t, tm) = mktime(input).unwrap();
        assert_eq!(
            (tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec),
            (101, 1, 1, 1, 0, 1)
        );
        assert_eq!(localtime(t).unwrap(), tm);
    }
}
