//! The `nmap-protocols` table — the port of `protocols.cc`.
//!
//! `nmap-protocols` names the IP protocol numbers, one `name number` pair per
//! line, with `#` comments. nmap reads it lazily, the first time something asks
//! (`nmap_protocols_init`), and answers two questions from it: the name of a
//! number (`nmap_getprotbynum`) and the number of a name (`nmap_getprotbyname`).
//! Scripts ask both through `nmapdb` ([`crate::nse::nmapdb`]).
//!
//! The two lookups are two tables, filled in file order, and their first-wins
//! rules differ in a way that is visible (`protocols.cc:131-148`):
//!
//! - **By name**, the first line naming a protocol wins. A later line with the
//!   same name is dropped whole: its number is not claimed either.
//! - **By number**, the first line *whose name was new* wins. A later line with
//!   a new name but a taken number is still kept by name, so
//!
//!   ```text
//!   a 1        by name: a -> 1, b -> 1
//!   b 1        by number: 1 -> a
//!   ```
//!
//!   and `b`'s number does not name `b`.
//!
//! C reads each line with `fgets` into 1,024 bytes and `sscanf(line, "%127s
//! %hu")`. Lines it cannot read are skipped with an error, as here
//! (`protocols.cc:121-124`). What C also does is *misread* some lines rather
//! than skip them, and those are skipped here instead
//! (`protocols-hu-wrap-rejected`):
//!
//! | line | C reads | here |
//! |------|---------|------|
//! | `x 65542` | `%hu` wraps it: protocol 6 | skipped |
//! | `x -65530` | `strtoul` negates, `%hu` wraps: 6 | skipped |
//! | `x 8abc` | the digits before the junk: 8 | skipped |
//! | `x 0x9` | the `0` before the `x`: 0 | skipped |
//! | a name over 127 bytes, `aaa…a6 7` | `%127s` stops mid-name and `%hu` reads the rest: 6 | skipped |
//! | a line over 1,023 bytes | `fgets` splits it, and the tail is read as a line of its own | read whole |
//!
//! What C reads correctly is read the same: `+6` and `006` are 6, `-0` is 0, a
//! comment may follow the number with or without a space, a name may hold any
//! byte but whitespace, and a NUL byte ends the line, as it ends C's string.
//! Whitespace is C's `isspace` in the C locale, which includes `\v` and `\f`.

use std::collections::BTreeMap;

/// `MAX_IPPROTONUM`: the largest protocol number (`protocols.h`).
pub const MAX_IPPROTONUM: u8 = 255;

/// The longest name `%127s` reads whole.
const MAX_NAME: usize = 127;

/// A line that could not be read, with its 1-based number. C prints `Parse
/// error in protocols file FILE line N` for each, and goes on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolWarning {
    /// 1-based line number.
    pub line: usize,
    /// What was wrong with it.
    pub message: &'static str,
}

/// How many warnings a parse keeps; the rest are only counted
/// ([`ProtocolTable::warning_count`]), so a malformed file of any size costs no
/// memory for its warnings beyond these (`protocols-parse-warning-cap`).
pub const KEPT_WARNINGS: usize = 10;

/// The parsed `nmap-protocols` table.
#[derive(Debug, Clone, Default)]
pub struct ProtocolTable {
    /// `proto_map`: name to number, the first line for a name winning.
    by_name: BTreeMap<Vec<u8>, u8>,
    /// `protocol_table`: number to name, the first new name for a number
    /// winning.
    by_number: BTreeMap<u8, Vec<u8>>,
    /// The first [`KEPT_WARNINGS`] lines that could not be read.
    pub warnings: Vec<ProtocolWarning>,
    /// How many lines could not be read, kept or not.
    pub warning_count: usize,
}

/// C's `isspace` in the C locale. Not `u8::is_ascii_whitespace`, which leaves
/// out `\v`.
fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// The bytes of `s` before its first NUL: what C's string functions see.
fn c_str(s: &[u8]) -> &[u8] {
    s.iter().position(|&b| b == 0).map_or(s, |i| &s[..i])
}

/// The protocol number field: an optional sign, decimal digits, and then the
/// end of the line, whitespace or a comment. `None` for anything `%hu` would
/// reject or misread; `-0` is 0, as C reads it.
fn parse_number(field: &[u8]) -> Option<u8> {
    let (negative, rest) = match field.first() {
        Some(b'+') => (false, &field[1..]),
        Some(b'-') => (true, &field[1..]),
        _ => (false, field),
    };
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    // Junk glued to the number is read by C as far as the digits go.
    if let Some(&next) = rest.get(digits) {
        if !is_c_space(next) && next != b'#' {
            return None;
        }
    }
    let mut value: u16 = 0;
    for &d in &rest[..digits] {
        value = value
            .checked_mul(10)?
            .checked_add(u16::from(d.wrapping_sub(b'0')))?;
        if value > u16::from(MAX_IPPROTONUM) {
            return None;
        }
    }
    // A negative number other than zero only reaches 0..=255 by wrapping.
    if negative && value != 0 {
        return None;
    }
    u8::try_from(value).ok()
}

/// One line: `Ok(None)` for a comment or a blank line, `Ok(Some(entry))` for
/// an entry, `Err` for a line that cannot be read.
fn parse_line(raw: &[u8]) -> Result<Option<(&[u8], u8)>, &'static str> {
    let line = c_str(raw);
    let start = line
        .iter()
        .position(|&b| !is_c_space(b))
        .unwrap_or(line.len());
    let line = &line[start..];
    if line.is_empty() || line[0] == b'#' {
        return Ok(None);
    }
    let name_len = line
        .iter()
        .position(|&b| is_c_space(b))
        .unwrap_or(line.len());
    if name_len > MAX_NAME {
        return Err("protocol name longer than 127 bytes");
    }
    let (name, rest) = line.split_at(name_len);
    let field_start = rest
        .iter()
        .position(|&b| !is_c_space(b))
        .unwrap_or(rest.len());
    let number = parse_number(&rest[field_start..]).ok_or("no protocol number from 0 to 255")?;
    Ok(Some((name, number)))
}

impl ProtocolTable {
    /// Parse the contents of an `nmap-protocols` file.
    ///
    /// Never fails: a line that cannot be read becomes a [`ProtocolWarning`]
    /// and is skipped, and the rest of the file is still read.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Self {
        let mut table = ProtocolTable::default();
        for (i, raw) in bytes.split(|&b| b == b'\n').enumerate() {
            match parse_line(raw) {
                Ok(None) => {}
                Ok(Some((name, number))) => table.insert(name, number),
                Err(message) => {
                    table.warning_count = table.warning_count.saturating_add(1);
                    if table.warnings.len() < KEPT_WARNINGS {
                        table.warnings.push(ProtocolWarning {
                            line: i.saturating_add(1),
                            message,
                        });
                    }
                }
            }
        }
        table
    }

    /// `proto_map.insert`, then `protocol_table[protno]` if it is free.
    fn insert(&mut self, name: &[u8], number: u8) {
        if self.by_name.contains_key(name) {
            return;
        }
        self.by_name.insert(name.to_vec(), number);
        self.by_number
            .entry(number)
            .or_insert_with(|| name.to_vec());
    }

    /// `nmap_getprotbynum`: the name of protocol `number`, if one is known.
    #[must_use]
    pub fn by_number(&self, number: u8) -> Option<&[u8]> {
        self.by_number.get(&number).map(Vec::as_slice)
    }

    /// `nmap_getprotbyname`: the number of protocol `name`, compared byte for
    /// byte (case matters).
    #[must_use]
    pub fn by_name(&self, name: &[u8]) -> Option<u8> {
        self.by_name.get(name).copied()
    }

    /// Every name and its number, in byte order of the names.
    pub fn names(&self) -> impl Iterator<Item = (&[u8], u8)> {
        self.by_name.iter().map(|(k, &v)| (k.as_slice(), v))
    }

    /// The number of names known.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the table knows no protocol.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Option<u8> {
        let t = ProtocolTable::parse(line.as_bytes());
        let numbers: Vec<u8> = t.names().map(|(_, n)| n).collect();
        numbers.first().copied()
    }

    #[test]
    fn reads_names_and_numbers_both_ways() {
        let t = ProtocolTable::parse(
            b"# comment\nhopopt\t0\tHOPOPT\t# IPv6 Hop-by-Hop Option\n\
              icmp\t1\tICMP\ntcp 6 TCP\n\n   \nudp 17\n",
        );
        assert!(t.warnings.is_empty(), "{:?}", t.warnings);
        assert_eq!(t.len(), 4);
        assert_eq!(t.by_number(6), Some(&b"tcp"[..]));
        assert_eq!(t.by_name(b"udp"), Some(17));
        assert_eq!(t.by_name(b"hopopt"), Some(0));
        assert_eq!(t.by_number(2), None);
        assert_eq!(t.by_name(b"TCP"), None, "names are case-sensitive");
    }

    /// The quirks table of the module documentation, row by row: what C
    /// misreads is skipped, what C reads right is read the same.
    #[test]
    fn the_quirks_table() {
        // Misread by C, skipped here (`protocols-hu-wrap-rejected`).
        for line in [
            "x 65542",
            "x 65536",
            "x -65530",
            "x -1",
            "x 8abc",
            "x 0x9",
            "x 6.5",
            "x 256",
            "x 99999999999999999999999",
            "x",
            "x  ",
            "x #6",
        ] {
            let t = ProtocolTable::parse(line.as_bytes());
            assert!(t.is_empty(), "{line:?} was read");
            assert_eq!(t.warnings.len(), 1, "{line:?}");
            assert_eq!(t.warnings[0].line, 1);
        }
        // A name over 127 bytes, whatever follows it.
        let long = format!("{}6 7", "a".repeat(127));
        assert!(ProtocolTable::parse(long.as_bytes()).is_empty());
        let long = format!("{} 7", "a".repeat(128));
        assert!(ProtocolTable::parse(long.as_bytes()).is_empty());
        let edge = format!("{} 7", "a".repeat(127));
        assert_eq!(one(&edge), Some(7), "127 bytes is a whole name");

        // Read by C correctly, read the same here.
        assert_eq!(one("x +6"), Some(6));
        assert_eq!(one("x 006"), Some(6));
        assert_eq!(one("x -0"), Some(0));
        assert_eq!(one("x 255"), Some(255));
        assert_eq!(one("x 6#comment"), Some(6));
        assert_eq!(one("x 6 trailing words"), Some(6));
        assert_eq!(one("x\x0b6"), Some(6), "\\v is C whitespace");
        assert_eq!(one("x\x0c6\r"), Some(6), "\\f and \\r are C whitespace");
        assert_eq!(one("  \tx 6"), Some(6), "leading whitespace");
        assert_eq!(one("x 6\0junk"), Some(6), "a NUL ends the line");
        assert_eq!(one("x 6"), Some(6));
    }

    #[test]
    fn a_nul_ends_the_line_as_it_ends_cs_string() {
        // The name stops at the NUL, and with it the line, so no number.
        let t = ProtocolTable::parse(b"tc\0p 6\n");
        assert!(t.is_empty());
        assert_eq!(t.warnings.len(), 1);
        // A line that starts with NUL is empty to C: skipped, no error.
        let t = ProtocolTable::parse(b"\0tcp 6\n");
        assert!(t.is_empty());
        assert!(t.warnings.is_empty());
    }

    #[test]
    fn names_hold_any_byte_but_whitespace() {
        let t = ProtocolTable::parse(b"tcp# 6\na/n 107\nlat\xe9 9\n");
        assert!(t.warnings.is_empty());
        assert_eq!(t.by_name(b"tcp#"), Some(6));
        assert_eq!(t.by_name(b"a/n"), Some(107));
        assert_eq!(t.by_name(b"lat\xe9"), Some(9));
    }

    #[test]
    fn the_first_line_for_a_name_wins_and_takes_its_number_with_it() {
        // `a 2` is dropped whole: 2 is left for `b`.
        let t = ProtocolTable::parse(b"a 1\na 2\nb 2\n");
        assert_eq!(t.by_name(b"a"), Some(1));
        assert_eq!(t.by_name(b"b"), Some(2));
        assert_eq!(t.by_number(1), Some(&b"a"[..]));
        assert_eq!(t.by_number(2), Some(&b"b"[..]));
    }

    #[test]
    fn the_first_new_name_for_a_number_wins_but_the_others_keep_their_names() {
        let t = ProtocolTable::parse(b"a 1\nb 1\n");
        assert_eq!(t.by_number(1), Some(&b"a"[..]));
        assert_eq!(t.by_name(b"a"), Some(1));
        assert_eq!(t.by_name(b"b"), Some(1), "b stays known by name");
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn a_bad_line_costs_only_that_line() {
        let t = ProtocolTable::parse(b"a 1\nb 70000\nc\nd 4\n");
        assert_eq!(
            t.warnings.iter().map(|w| w.line).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(t.by_name(b"d"), Some(4));
    }

    #[test]
    fn a_long_line_is_read_whole() {
        // C's `fgets(line, 1024)` would read the tail, `y 7`, as a line.
        let mut line = b"x 6".to_vec();
        line.extend(std::iter::repeat_n(b' ', 1100));
        line.extend_from_slice(b"y 7\n");
        let t = ProtocolTable::parse(&line);
        assert_eq!(t.by_name(b"x"), Some(6));
        assert_eq!(t.by_name(b"y"), None);
        assert!(t.warnings.is_empty());
    }

    /// `protocols-parse-warning-cap`: every bad line is counted, the first
    /// [`KEPT_WARNINGS`] are kept, and the good lines among them still load.
    #[test]
    fn warnings_past_the_cap_are_counted_not_kept() {
        let mut file = Vec::new();
        for i in 0..25 {
            file.extend_from_slice(b"bad\n");
            if i == 20 {
                file.extend_from_slice(b"tcp 6\n");
            }
        }
        let t = ProtocolTable::parse(&file);
        assert_eq!(t.warning_count, 25);
        assert_eq!(t.warnings.len(), KEPT_WARNINGS);
        assert_eq!(
            t.warnings.iter().map(|w| w.line).collect::<Vec<_>>(),
            (1..=KEPT_WARNINGS).collect::<Vec<_>>()
        );
        assert_eq!(t.by_name(b"tcp"), Some(6));
    }

    #[test]
    fn empty_input_is_an_empty_table() {
        let t = ProtocolTable::parse(b"");
        assert!(t.is_empty());
        assert!(t.warnings.is_empty());
        assert_eq!(t.by_number(0), None);
    }
}
