//! Output filenames — nmap's `logfilename` and `test_file_name`.
//!
//! Every `-oN` / `-oX` / `-oG` / `-oA` argument passes through both: the first
//! expands strftime-style escapes, the second refuses names that would be a
//! footgun. This port did neither until M7.9, which meant
//!
//! ```console
//! $ nmap-rs -sL -n -oN 'scan-%Y%m%d.txt' 127.0.0.1
//! $ ls
//! scan-%Y%m%d.txt          # C writes scan-20260920.txt
//! ```
//!
//! — an operator running that from cron got one file silently overwritten
//! every day where they had asked for a dated series.
//!
//! # The escape rules are not the obvious ones
//!
//! Eleven conversions are recognised, and several are nmap's own compressed
//! spellings rather than the C library's:
//!
//! | escape | expands to | |
//! |---|---|---|
//! | `%H` `%M` `%S` | hour, minute, second | |
//! | `%T` | `%H%M%S` | nmap's own |
//! | `%R` | `%H%M` | nmap's own |
//! | `%m` `%d` `%y` `%Y` | month, day, 2- and 4-digit year | |
//! | `%D` | `%m%d%y` | nmap's own |
//! | `%F` | `%Y-%m-%d` | |
//!
//! Anything else after a `%` has the **`%` dropped and the character kept**, so
//! `%Z` is `Z` and `%%` is `%`; and a trailing `%` is dropped entirely. Those
//! three rules are what a reimplementation from memory gets wrong, which is why
//! this is ported against a verbatim oracle
//! (`tests/differential/m7/oracle/logfile_oracle.c`).
//!
//! # UTC, not local time
//!
//! C's callers pass `localtime()`. Reproducing that needs a timezone database,
//! a dependency this crate does not carry for a handful of output fields. The
//! same choice was made for `-O`'s boot time and for the scan-start banner; see
//! `DIVERGENCES.md`. The consequence is real but narrow: an operator west of
//! Greenwich running `-oA scan-%F` late in the evening gets tomorrow's date in
//! the filename.

use crate::osscan::civil_from_epoch;

/// Why an output filename was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileNameError {
    /// The name begins with `-`, which later shell commands would read as a
    /// flag. C's message names the way out, so this carries the option letter
    /// to reproduce it.
    LeadingDash { option: String, filename: String },
    /// `-oA -`: the three formats cannot all go to stdout.
    MultipleToStdout,
    /// The deprecated bare `-o` followed by what looks like a format letter —
    /// `-oN foo` written as `-o Nfoo`.
    DeprecatedFormatLetter { letter: char, rest: String },
}

impl FileNameError {
    /// C's wording, which is what an operator will search for.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            FileNameError::LeadingDash { option, filename } => format!(
                "Output filename begins with '-'. Try '-{option} ./{filename}' if you really want it to be named as such."
            ),
            FileNameError::MultipleToStdout => {
                "Cannot display multiple output types to stdout.".to_string()
            }
            FileNameError::DeprecatedFormatLetter { letter, rest } => format!(
                "You are using a deprecated option in a dangerous way. Did you mean: -o{letter} {rest}"
            ),
        }
    }
}

/// C's `test_file_name`, in C's order — which matters, because the leading-dash
/// check comes first and so catches `-oA -foo` before the `-oA`-specific one.
/// Only a bare `-` reaches [`FileNameError::MultipleToStdout`].
///
/// # Errors
/// Returns the refusal C would `fatal()` with.
pub fn validate(filename: &str, option: &str) -> Result<(), FileNameError> {
    let mut chars = filename.chars();
    let first = chars.next();
    let rest: String = chars.collect();

    if first == Some('-') && !rest.is_empty() {
        return Err(FileNameError::LeadingDash {
            option: option.to_string(),
            filename: filename.to_string(),
        });
    }
    if option == "o" {
        if let Some(c) = first {
            if "NAXGS".contains(c) {
                return Err(FileNameError::DeprecatedFormatLetter { letter: c, rest });
            }
        }
    }
    if first == Some('-') && option == "oA" {
        return Err(FileNameError::MultipleToStdout);
    }
    Ok(())
}

/// C's `logfilename`: expand the strftime-style escapes in an output filename.
///
/// `epoch` is seconds since the Unix epoch, interpreted as **UTC** (see the
/// module docs). An epoch outside the range [`civil_from_epoch`] accepts leaves
/// every time-based escape empty rather than panicking — a filename is not
/// worth aborting a finished scan over.
#[must_use]
pub fn expand(spec: &str, epoch: i64) -> String {
    let t = civil_from_epoch(epoch);
    let two = |v: i64| format!("{:02}", v.clamp(0, 99));
    let (year, month, day, hour, min, sec) = match t {
        Some((y, mo, d, h, mi, s, _)) => (y, mo, d, h, mi, s),
        None => (0, 0, 0, 0, 0, 0),
    };

    let mut out = String::with_capacity(spec.len());
    let mut it = spec.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        // A trailing '%' is dropped: C breaks out of the loop on `if (!*str)`.
        let Some(esc) = it.next() else {
            break;
        };
        match esc {
            'H' => out.push_str(&two(hour)),
            'M' => out.push_str(&two(min)),
            'S' => out.push_str(&two(sec)),
            'T' => {
                out.push_str(&two(hour));
                out.push_str(&two(min));
                out.push_str(&two(sec));
            }
            'R' => {
                out.push_str(&two(hour));
                out.push_str(&two(min));
            }
            'm' => out.push_str(&two(month)),
            'd' => out.push_str(&two(day)),
            'y' => out.push_str(&two(year.rem_euclid(100))),
            'Y' => out.push_str(&format!("{year:04}")),
            'D' => {
                out.push_str(&two(month));
                out.push_str(&two(day));
                out.push_str(&two(year.rem_euclid(100)));
            }
            'F' => {
                out.push_str(&format!("{year:04}"));
                out.push('-');
                out.push_str(&two(month));
                out.push('-');
                out.push_str(&two(day));
            }
            // Unrecognised: the '%' is dropped and the character kept.
            other => out.push(other),
        }
    }
    out
}

/// The three files `-oA <base>` writes, in C's order (`nmap.cc:907-915`).
///
/// The suffixes are not the option letters: normal is `.nmap`, grepable is
/// `.gnmap`, XML is `.xml`. There is no `-oS` file — `--oA` does not imply it.
#[must_use]
pub fn all_formats(base: &str) -> (String, String, String) {
    (
        format!("{base}.nmap"),
        format!("{base}.gnmap"),
        format!("{base}.xml"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-09-10T00:26:40Z — two-digit month, day, hour and minute, nonzero
    /// second, so a swapped field shows up instead of cancelling out.
    const EPOCH: i64 = 1_789_000_000;

    #[test]
    fn the_eleven_recognised_conversions() {
        for (spec, want) in [
            ("%H", "00"),
            ("%M", "26"),
            ("%S", "40"),
            ("%T", "002640"),
            ("%R", "0026"),
            ("%m", "09"),
            ("%d", "10"),
            ("%y", "26"),
            ("%Y", "2026"),
            ("%D", "091026"),
            ("%F", "2026-09-10"),
        ] {
            assert_eq!(expand(spec, EPOCH), want, "{spec}");
        }
    }

    /// The three rules a reimplementation gets wrong.
    #[test]
    fn the_unusual_rules() {
        // An unrecognised escape drops the '%' and keeps the character.
        assert_eq!(expand("%Z", EPOCH), "Z");
        assert_eq!(expand("u%Zx", EPOCH), "uZx");
        // Which makes "%%" a literal '%'.
        assert_eq!(expand("p%%l", EPOCH), "p%l");
        // And a trailing '%' vanishes entirely.
        assert_eq!(expand("t%", EPOCH), "t");
        assert_eq!(expand("%", EPOCH), "");
    }

    #[test]
    fn text_without_escapes_is_untouched() {
        for s in ["base", "/tmp/scan.txt", "dir/sub/name", ""] {
            assert_eq!(expand(s, EPOCH), s);
        }
    }

    /// An epoch outside the supported range must not panic — a filename is not
    /// worth aborting a finished scan over.
    #[test]
    fn an_impossible_clock_still_produces_a_name() {
        for bad in [-1, i64::MIN, i64::MAX] {
            let out = expand("s-%F", bad);
            assert!(out.starts_with("s-"), "{bad}: {out}");
        }
    }

    /// C's order: the leading-dash check runs first, so only a BARE `-`
    /// reaches the `-oA`-specific refusal.
    #[test]
    fn validation_follows_cs_order() {
        assert_eq!(
            validate("-foo", "oA"),
            Err(FileNameError::LeadingDash {
                option: "oA".to_string(),
                filename: "-foo".to_string()
            })
        );
        assert_eq!(validate("-", "oA"), Err(FileNameError::MultipleToStdout));
        // A bare `-` is fine for a single format: it means stdout.
        assert_eq!(validate("-", "oN"), Ok(()));
        assert_eq!(validate("./-foo", "oA"), Ok(()));
        assert_eq!(validate("base", "oA"), Ok(()));
    }

    /// The deprecated bare `-o`, where `-o Nfoo` is almost certainly a typo for
    /// `-oN foo` and C says so rather than writing a file called `Nfoo`.
    #[test]
    fn the_deprecated_bare_o_catches_a_format_letter() {
        assert_eq!(
            validate("Nfoo", "o"),
            Err(FileNameError::DeprecatedFormatLetter {
                letter: 'N',
                rest: "foo".to_string()
            })
        );
        // Only for the bare `-o`; `-oN Nfoo` is a legitimate filename.
        assert_eq!(validate("Nfoo", "oN"), Ok(()));
    }

    /// The suffixes are not the option letters.
    #[test]
    fn the_three_suffixes() {
        assert_eq!(
            all_formats("s"),
            ("s.nmap".into(), "s.gnmap".into(), "s.xml".into())
        );
    }
}
