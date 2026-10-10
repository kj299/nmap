//! MAC-address vendor lookup — the port of `MACLookup.cc`.
//!
//! `nmap-mac-prefixes` maps an IEEE Organizationally Unique Identifier to the
//! organisation that registered it, so a scan can report "Apple" beside a host's MAC
//! address. The IEEE issues three assignment sizes and the file mixes all three:
//!
//! | Block | Prefix bits | Hex digits |
//! |-------|-------------|------------|
//! | MA-L  | 24          | 6          |
//! | MA-M  | 28          | 7          |
//! | MA-S  | 36          | 9          |
//!
//! Because a short prefix is a prefix of a long one, lookup must try the **most specific
//! block first**: a MAC under an MA-S assignment also sits inside some MA-L range, and
//! reporting the MA-L holder would name the wrong organisation. Keys are tagged with
//! their digit count so the three address spaces cannot collide.

use std::collections::BTreeMap;

/// Hex digits in an MA-L (24-bit) prefix.
const MAL_DIGITS: u32 = 6;
/// Hex digits in an MA-M (28-bit) prefix.
const MAM_DIGITS: u32 = 7;
/// Hex digits in an MA-S (36-bit) prefix.
const MAS_DIGITS: u32 = 9;

/// Where the digit count is packed into a table key, matching the C's `(len << 36)`.
const TAG_SHIFT: u32 = 36;

/// What was wrong with a line of `nmap-mac-prefixes`. A value, not a string:
/// a malformed file of millions of lines costs no allocation per line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacDbProblem {
    /// The line does not start with 6, 7 or 9 hex digits; how many it has.
    PrefixLength {
        /// The number of hex digits the line starts with.
        digits: usize,
    },
    /// The prefix runs straight into something other than whitespace.
    NoWhitespace,
    /// The prefix is followed by no vendor name.
    NoVendor,
}

impl std::fmt::Display for MacDbProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MacDbProblem::PrefixLength { digits } => write!(
                f,
                "expected a {MAL_DIGITS}, {MAM_DIGITS} or {MAS_DIGITS} digit prefix, \
                 found {digits} hex digits"
            ),
            MacDbProblem::NoWhitespace => f.write_str("prefix is not followed by whitespace"),
            MacDbProblem::NoVendor => f.write_str("prefix has no vendor name"),
        }
    }
}

/// A non-fatal problem encountered while parsing, with the line it occurred on. The C
/// prints these and then **abandons the rest of the file**; we collect them and keep
/// going (`macvendor-parse-degrade`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacDbWarning {
    /// 1-based line number.
    pub line: usize,
    /// What went wrong.
    pub problem: MacDbProblem,
}

/// How many warnings a parse keeps; the rest are only counted
/// ([`MacPrefixDb::warning_count`]), so a malformed file of any size costs no
/// memory for its warnings beyond these (`macvendor-parse-degrade`).
pub const KEPT_WARNINGS: usize = 10;

/// A registered prefix, as returned by [`MacPrefixDb::find_prefix`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacPrefix {
    /// Number of hex digits the assignment covers: 6, 7 or 9.
    pub digits: u32,
    /// The prefix bytes, `(digits + 1) / 2` of them. When `digits` is odd the final
    /// byte's low nibble is zero padding and is not part of the assignment.
    pub bytes: Vec<u8>,
}

/// The parsed `nmap-mac-prefixes` table.
///
/// Keys are `(digit_count << 36) | value`, so the three assignment sizes occupy disjoint
/// ranges and iterate MA-L, then MA-M, then MA-S — the same order the C's `std::map`
/// yields, which [`Self::find_prefix`] depends on. Vendor names are bytes, as the C
/// stores them: a file an operator supplies need not be UTF-8.
#[derive(Debug, Clone, Default)]
pub struct MacPrefixDb {
    entries: BTreeMap<u64, Vec<u8>>,
    /// The first [`KEPT_WARNINGS`] lines that could not be parsed.
    pub warnings: Vec<MacDbWarning>,
    /// How many lines could not be parsed, kept or not.
    pub warning_count: usize,
}

/// Value of a hex digit. The C's `nibble()` does this with bit tricks that quietly accept
/// non-hex bytes; callers here have already checked `is_ascii_hexdigit`.
fn hex_value(c: u8) -> Option<u64> {
    (c as char).to_digit(16).map(u64::from)
}

/// C's `isspace` in the C locale. Not `u8::is_ascii_whitespace`, which leaves out
/// `\v`.
fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

impl MacPrefixDb {
    /// Parse the contents of an `nmap-mac-prefixes` file.
    ///
    /// Never fails: unparseable lines become [`MacDbWarning`]s and are skipped. Where a
    /// prefix appears more than once the **first** entry wins, as the C's
    /// `std::map::insert` does.
    ///
    /// A line is read as `mac_prefix_init` reads it (`MACLookup.cc:109-165`), but whole
    /// (`macvendor-no-fgets-truncation`):
    /// - it ends at its first NUL byte, as C's string does;
    /// - the prefix must be followed by C whitespace, `\v` and `\f` included;
    /// - the whitespace after the prefix is skipped, `\r` included, and the vendor
    ///   runs from there to the first `\r` or the end of the line, keeping any
    ///   trailing spaces.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Self {
        let mut db = MacPrefixDb::default();

        for (i, raw) in bytes.split(|&b| b == b'\n').enumerate() {
            let lineno = i.saturating_add(1);
            if raw.iter().all(|&b| is_c_space(b)) {
                // The C treats a blank line as "not a hex digit" and gives up on the
                // whole file. Skipping it costs nothing.
                continue;
            }
            // What the C's string functions see of the line.
            let line = raw
                .iter()
                .position(|&b| b == 0)
                .map_or(raw, |end| &raw[..end]);
            if line.first() == Some(&b'#') {
                continue;
            }

            let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
            if !matches!(
                u32::try_from(digits),
                Ok(MAL_DIGITS | MAM_DIGITS | MAS_DIGITS)
            ) {
                db.warn(lineno, MacDbProblem::PrefixLength { digits });
                continue;
            }
            let (prefix, rest) = line.split_at(digits);
            // The C requires whitespace immediately after the prefix, so `0000001 Foo`
            // is rejected rather than silently read as a 6-digit prefix.
            if !rest.first().is_some_and(|&b| is_c_space(b)) {
                db.warn(lineno, MacDbProblem::NoWhitespace);
                continue;
            }

            let mut value: u64 = 0;
            for &c in prefix {
                // `digits` is at most 9, so this shifts by at most 32 bits.
                value = (value << 4) | hex_value(c).unwrap_or(0);
            }

            let start = rest
                .iter()
                .position(|&b| !is_c_space(b))
                .unwrap_or(rest.len());
            let vendor = &rest[start..];
            let vendor = vendor
                .iter()
                .position(|&b| b == b'\r')
                .map_or(vendor, |end| &vendor[..end]);
            if vendor.is_empty() {
                // The C `assert()`s here, and nmap's build keeps its asserts: 7.94 aborts
                // (`macvendor-empty-vendor-skipped`).
                db.warn(lineno, MacDbProblem::NoVendor);
                continue;
            }

            let digits = u64::try_from(digits).unwrap_or(0);
            db.entries
                .entry((digits << TAG_SHIFT) | value)
                .or_insert_with(|| vendor.to_vec());
        }

        db
    }

    fn warn(&mut self, line: usize, problem: MacDbProblem) {
        self.warning_count = self.warning_count.saturating_add(1);
        if self.warnings.len() < KEPT_WARNINGS {
            self.warnings.push(MacDbWarning { line, problem });
        }
    }

    /// Number of registered prefixes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The organisation that registered `mac`'s prefix, or `None` if unregistered.
    ///
    /// Tries the most specific assignment first (MA-S, then MA-M, then MA-L) so a host
    /// inside a 36-bit assignment is attributed to that registrant rather than to the
    /// holder of the enclosing 24-bit block.
    #[must_use]
    pub fn lookup(&self, mac: [u8; 6]) -> Option<&[u8]> {
        // The top 36 bits of the address: nine hex digits.
        let mas = (u64::from(mac[0]) << 28)
            | (u64::from(mac[1]) << 20)
            | (u64::from(mac[2]) << 12)
            | (u64::from(mac[3]) << 4)
            | u64::from(mac[4] >> 4);

        for (digits, value) in [
            (MAS_DIGITS, mas),
            (MAM_DIGITS, mas >> 8),
            (MAL_DIGITS, mas >> 12),
        ] {
            if let Some(vendor) = self
                .entries
                .get(&((u64::from(digits) << TAG_SHIFT) | value))
            {
                return Some(vendor.as_slice());
            }
        }
        None
    }

    /// The first registered prefix whose organisation name contains `needle`, compared
    /// case-insensitively.
    ///
    /// "First" is by prefix key, so MA-L assignments are considered before MA-M and
    /// MA-S, each in ascending prefix order — the C's `std::map` iteration order, which
    /// decides which of several matching vendors is chosen. Used by `--spoof-mac` to
    /// turn a vendor name into an address to masquerade as.
    #[must_use]
    pub fn find_prefix(&self, needle: impl AsRef<[u8]>) -> Option<MacPrefix> {
        let needle = needle.as_ref().to_ascii_lowercase();
        let (key, _) = self.entries.iter().find(|(_, vendor)| {
            needle.is_empty()
                || vendor
                    .to_ascii_lowercase()
                    .windows(needle.len())
                    .any(|w| w == needle.as_slice())
        })?;

        let digits = u32::try_from(key >> TAG_SHIFT).unwrap_or(0);
        let value = key & ((1u64 << TAG_SHIFT).wrapping_sub(1));
        // Left-align the value in a whole number of bytes: an odd digit count leaves the
        // final low nibble as zero padding.
        let byte_len = digits.saturating_add(1) / 2;
        let padding_nibbles = byte_len.saturating_mul(2).saturating_sub(digits);
        let aligned = value << (padding_nibbles.saturating_mul(4));

        let mut bytes = Vec::with_capacity(byte_len as usize);
        for i in (0..byte_len).rev() {
            let shift = i.saturating_mul(8);
            // Truncation to the low 8 bits is the intent, so mask rather than cast.
            bytes.push(u8::try_from((aligned >> shift) & 0xff).unwrap_or(0));
        }

        Some(MacPrefix { digits, bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# a comment
000000 Xerox
080027 PCS Systemtechnik GmbH
0055DA0 IEEE Registration Authority
70B3D5EEF Sunlite Technology
";

    fn db() -> MacPrefixDb {
        let db = MacPrefixDb::parse(SAMPLE.as_bytes());
        assert!(db.warnings.is_empty(), "{:?}", db.warnings);
        db
    }

    #[test]
    fn parses_all_three_assignment_sizes() {
        let db = db();
        assert_eq!(db.len(), 4);
        assert_eq!(
            db.lookup([0x08, 0x00, 0x27, 0x12, 0x34, 0x56]),
            Some(&b"PCS Systemtechnik GmbH"[..])
        );
        assert_eq!(
            db.lookup([0x00, 0x00, 0x00, 0xAB, 0xCD, 0xEF]),
            Some(&b"Xerox"[..])
        );
    }

    #[test]
    fn vendor_names_keep_their_internal_spacing() {
        let db = db();
        assert_eq!(
            db.lookup([0x00, 0x55, 0xDA, 0x0F, 0x00, 0x01]),
            Some(&b"IEEE Registration Authority"[..])
        );
    }

    #[test]
    fn the_most_specific_assignment_wins() {
        // 0055DA is not itself registered here, but 0055DA0 is: a 28-bit lookup must not
        // be answered by a 24-bit entry, nor the reverse.
        let db = MacPrefixDb::parse(b"0055DA Wrong Answer\n0055DA0 Right Answer\n");
        assert!(db.warnings.is_empty());
        assert_eq!(
            db.lookup([0x00, 0x55, 0xDA, 0x01, 0x02, 0x03]),
            Some(&b"Right Answer"[..]),
            "the 28-bit assignment covers 0055DA0*"
        );
        assert_eq!(
            db.lookup([0x00, 0x55, 0xDA, 0x11, 0x02, 0x03]),
            Some(&b"Wrong Answer"[..]),
            "0055DA1* falls outside the 28-bit assignment, so the 24-bit one applies"
        );
    }

    #[test]
    fn a_36_bit_assignment_beats_the_blocks_containing_it() {
        let db = MacPrefixDb::parse(b"70B3D5 Registry\n70B3D5E Middle\n70B3D5EEF Specific\n");
        assert!(db.warnings.is_empty());
        assert_eq!(
            db.lookup([0x70, 0xB3, 0xD5, 0xEE, 0xF0, 0x00]),
            Some(&b"Specific"[..])
        );
        assert_eq!(
            db.lookup([0x70, 0xB3, 0xD5, 0xEE, 0x00, 0x00]),
            Some(&b"Middle"[..])
        );
        assert_eq!(
            db.lookup([0x70, 0xB3, 0xD5, 0x00, 0x00, 0x00]),
            Some(&b"Registry"[..])
        );
    }

    #[test]
    fn an_unregistered_prefix_has_no_vendor() {
        assert_eq!(db().lookup([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]), None);
        assert_eq!(MacPrefixDb::default().lookup([0; 6]), None);
    }

    #[test]
    fn lookup_is_case_insensitive_in_the_file() {
        let db = MacPrefixDb::parse(b"00aAbB Lowercase Prefix\n");
        assert!(db.warnings.is_empty());
        assert_eq!(
            db.lookup([0x00, 0xAA, 0xBB, 0x00, 0x00, 0x00]),
            Some(&b"Lowercase Prefix"[..])
        );
    }

    #[test]
    fn a_bad_line_costs_only_that_line() {
        // The C stops parsing the whole file at the first bad line, silently discarding
        // every vendor after it.
        let db = MacPrefixDb::parse(
            b"000000 First\nZZZZZZ junk\n00000 too short\n0000001x no space\n080027 Last\n",
        );
        assert_eq!(db.warnings.len(), 3, "{:?}", db.warnings);
        assert_eq!(db.warnings[0].line, 2);
        assert_eq!(db.warnings[1].line, 3);
        assert_eq!(db.warnings[2].line, 4);
        assert_eq!(db.lookup([0; 6]), Some(&b"First"[..]));
        assert_eq!(
            db.lookup([0x08, 0x00, 0x27, 0, 0, 0]),
            Some(&b"Last"[..]),
            "entries after the bad lines must survive"
        );
    }

    #[test]
    fn a_prefix_with_no_vendor_is_skipped_rather_than_stored_empty() {
        let db = MacPrefixDb::parse(b"000000\n000001   \n080027 Fine\n");
        assert_eq!(db.warnings.len(), 2);
        assert_eq!(db.lookup([0; 6]), None);
        assert_eq!(db.lookup([0x08, 0x00, 0x27, 0, 0, 0]), Some(&b"Fine"[..]));
    }

    #[test]
    fn the_first_entry_for_a_prefix_wins() {
        let db = MacPrefixDb::parse(b"000000 First\n000000 Second\n");
        assert!(db.warnings.is_empty());
        assert_eq!(db.len(), 1);
        assert_eq!(db.lookup([0; 6]), Some(&b"First"[..]));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let db = MacPrefixDb::parse(b"# header\n\n000000 Xerox\n\n# trailer\n");
        assert!(db.warnings.is_empty(), "{:?}", db.warnings);
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn carriage_returns_do_not_end_up_in_vendor_names() {
        let db = MacPrefixDb::parse(b"000000 Xerox\r\n");
        assert!(db.warnings.is_empty());
        assert_eq!(db.lookup([0; 6]), Some(&b"Xerox"[..]));
    }

    #[test]
    fn find_prefix_returns_the_bytes_of_the_assignment() {
        let db = db();
        let p = db.find_prefix("systemtechnik").expect("vendor found");
        assert_eq!(p.digits, 6);
        assert_eq!(p.bytes, vec![0x08, 0x00, 0x27]);

        // An odd digit count pads the final low nibble with zero.
        let p = db.find_prefix("Sunlite").expect("vendor found");
        assert_eq!(p.digits, 9);
        assert_eq!(p.bytes, vec![0x70, 0xB3, 0xD5, 0xEE, 0xF0]);

        let p = db.find_prefix("IEEE").expect("vendor found");
        assert_eq!(p.digits, 7);
        assert_eq!(p.bytes, vec![0x00, 0x55, 0xDA, 0x00]);
    }

    #[test]
    fn find_prefix_is_case_insensitive_and_matches_substrings() {
        let db = db();
        assert!(db.find_prefix("XEROX").is_some());
        assert!(db.find_prefix("xerox").is_some());
        assert!(db.find_prefix("ero").is_some());
        assert!(db.find_prefix("not a vendor").is_none());
        // An empty needle matches everything, so it returns the lowest-keyed entry.
        assert_eq!(db.find_prefix("").map(|p| p.bytes), Some(vec![0, 0, 0]));
    }

    #[test]
    fn find_prefix_prefers_the_lowest_key_which_orders_by_block_size() {
        // Both entries mention "Acme"; MA-L sorts before MA-S because the digit count is
        // packed above the value, so the 24-bit assignment is returned.
        let db = MacPrefixDb::parse(b"FFFFFF Acme Small Block\n000000A Acme Large Block\n");
        assert!(db.warnings.is_empty());
        let p = db.find_prefix("Acme").expect("vendor found");
        assert_eq!(p.digits, 6);
        assert_eq!(p.bytes, vec![0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn round_trips_every_assignment_size_through_lookup() {
        let db = db();
        for needle in ["Xerox", "Systemtechnik", "IEEE", "Sunlite"] {
            let p = db.find_prefix(needle).expect("vendor found");
            let mut mac = [0u8; 6];
            for (slot, b) in mac.iter_mut().zip(p.bytes.iter()) {
                *slot = *b;
            }
            assert!(
                db.lookup(mac).is_some_and(|v| String::from_utf8_lossy(v)
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())),
                "{needle}: prefix bytes {:02X?} did not look up to it",
                p.bytes
            );
        }
    }

    #[test]
    fn a_vendor_ends_at_its_first_carriage_return_as_in_the_c() {
        // `MACLookup.cc:157`: the vendor runs to the first `\r` or `\n`.
        let db = MacPrefixDb::parse(b"000000 Xerox\rCorp\n080027 Spaced  \n");
        assert!(db.warnings.is_empty(), "{:?}", db.warnings);
        assert_eq!(db.lookup([0; 6]), Some(&b"Xerox"[..]));
        assert_eq!(
            db.lookup([0x08, 0x00, 0x27, 0, 0, 0]),
            Some(&b"Spaced  "[..]),
            "trailing spaces are the vendor's, as in the C"
        );
    }

    #[test]
    fn whitespace_after_the_prefix_is_cs_isspace() {
        // `\v` and `\f` are whitespace to `isspace`; so is a `\r` before the vendor,
        // which the C skips with the rest.
        let db = MacPrefixDb::parse(b"000000\x0bXerox\n000001\x0cOne\n000002 \r Two\n");
        assert!(db.warnings.is_empty(), "{:?}", db.warnings);
        assert_eq!(db.lookup([0; 6]), Some(&b"Xerox"[..]));
        assert_eq!(db.lookup([0, 0, 1, 0, 0, 0]), Some(&b"One"[..]));
        assert_eq!(db.lookup([0, 0, 2, 0, 0, 0]), Some(&b"Two"[..]));
    }

    #[test]
    fn a_nul_ends_the_line_as_it_ends_the_cs_string() {
        let db = MacPrefixDb::parse(b"000000 Xer\0ox\n000001\0 One\n\0\n");
        assert_eq!(db.lookup([0; 6]), Some(&b"Xer"[..]));
        // The prefix is followed by the end of the C string, not whitespace.
        assert_eq!(db.lookup([0, 0, 1, 0, 0, 0]), None);
        // A line that is a NUL is not a hex digit to the C.
        assert_eq!(
            db.warnings.iter().map(|w| w.line).collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn a_prefix_only_line_is_skipped_where_7_94_aborts() {
        // `macvendor-empty-vendor-skipped`: 7.94 dies on `assert(*endptr)` for each of
        // these lines; here each costs only itself.
        for line in [&b"000000\n"[..], b"000000 \r\n", b"000000\t \x0b\n"] {
            let mut file = line.to_vec();
            file.extend_from_slice(b"080027 Fine\n");
            let db = MacPrefixDb::parse(&file);
            assert_eq!(db.warnings.len(), 1, "{line:?}");
            assert_eq!(db.lookup([0; 6]), None, "{line:?}");
            assert_eq!(db.lookup([0x08, 0x00, 0x27, 0, 0, 0]), Some(&b"Fine"[..]));
        }
    }

    #[test]
    fn vendors_are_bytes_as_the_c_stores_them() {
        let db = MacPrefixDb::parse(b"000000 Latin\xe9 Corp\n");
        assert!(db.warnings.is_empty());
        assert_eq!(db.lookup([0; 6]), Some(&b"Latin\xe9 Corp"[..]));
        assert!(db.find_prefix(b"latin\xe9").is_some());
    }

    /// `macvendor-parse-degrade`: every bad line is counted, the first
    /// [`KEPT_WARNINGS`] are kept, as values, and the good lines still load.
    #[test]
    fn warnings_past_the_cap_are_counted_not_kept() {
        let mut file = b"x\n".repeat(30);
        file.extend_from_slice(b"0000001Glued\n000001   \n080027 Fine\n");
        let db = MacPrefixDb::parse(&file);
        assert_eq!(db.warning_count, 32);
        assert_eq!(db.warnings.len(), KEPT_WARNINGS);
        assert_eq!(
            db.warnings[0],
            MacDbWarning {
                line: 1,
                problem: MacDbProblem::PrefixLength { digits: 0 }
            }
        );
        assert_eq!(
            db.warnings[0].problem.to_string(),
            "expected a 6, 7 or 9 digit prefix, found 0 hex digits"
        );
        assert_eq!(db.lookup([8, 0, 0x27, 0, 0, 0]), Some(&b"Fine"[..]));
        let db = MacPrefixDb::parse(b"0000001Glued\n000001   \n");
        assert_eq!(
            db.warnings.iter().map(|w| w.problem).collect::<Vec<_>>(),
            [MacDbProblem::NoWhitespace, MacDbProblem::NoVendor]
        );
        assert_eq!(db.warning_count, 2);
    }
}
