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

/// A non-fatal problem encountered while parsing, with the line it occurred on. The C
/// prints these and then **abandons the rest of the file**; we collect them and keep
/// going.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacDbWarning {
    /// 1-based line number.
    pub line: usize,
    /// What went wrong.
    pub message: String,
}

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
/// yields, which [`Self::find_prefix`] depends on.
#[derive(Debug, Clone, Default)]
pub struct MacPrefixDb {
    entries: BTreeMap<u64, String>,
    /// Lines that could not be parsed.
    pub warnings: Vec<MacDbWarning>,
}

/// Value of a hex digit. The C's `nibble()` does this with bit tricks that quietly accept
/// non-hex bytes; callers here have already checked `is_ascii_hexdigit`.
fn hex_value(c: u8) -> Option<u64> {
    (c as char).to_digit(16).map(u64::from)
}

impl MacPrefixDb {
    /// Parse the contents of an `nmap-mac-prefixes` file.
    ///
    /// Never fails: unparseable lines become [`MacDbWarning`]s and are skipped. Where a
    /// prefix appears more than once the **first** entry wins, as the C's
    /// `std::map::insert` does.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut db = MacPrefixDb::default();

        for (i, raw) in text.lines().enumerate() {
            let lineno = i.saturating_add(1);
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            if line.starts_with('#') {
                continue;
            }
            if line.trim().is_empty() {
                // The C treats a blank line as "not a hex digit" and gives up on the
                // whole file. Skipping it costs nothing.
                continue;
            }

            let digits = line
                .bytes()
                .take_while(u8::is_ascii_hexdigit)
                .count()
                .try_into()
                .unwrap_or(u32::MAX);
            let Some(rest) = line.get(digits as usize..) else {
                db.warn(lineno, "prefix is not valid UTF-8 at its boundary");
                continue;
            };

            if !matches!(digits, MAL_DIGITS | MAM_DIGITS | MAS_DIGITS) {
                db.warn(
                    lineno,
                    &format!(
                        "expected a {MAL_DIGITS}, {MAM_DIGITS} or {MAS_DIGITS} digit prefix, \
                         found {digits} hex digits"
                    ),
                );
                continue;
            }
            // The C requires whitespace immediately after the prefix, so `0000001 Foo`
            // is rejected rather than silently read as a 6-digit prefix.
            if !rest.starts_with([' ', '\t']) {
                db.warn(lineno, "prefix is not followed by whitespace");
                continue;
            }

            let mut value: u64 = 0;
            let mut ok = true;
            for c in line.bytes().take(digits as usize) {
                match hex_value(c) {
                    // `digits` is at most 9, so this shifts by at most 32 bits.
                    Some(v) => value = (value << 4) | v,
                    None => ok = false,
                }
            }
            if !ok {
                db.warn(lineno, "prefix contains a non-hex digit");
                continue;
            }

            let vendor = rest.trim_start_matches([' ', '\t']);
            if vendor.is_empty() {
                // The C `assert()`s here, aborting a debug build; with `NDEBUG` it stores
                // an empty vendor name that would later be reported as the organisation.
                db.warn(lineno, "prefix has no vendor name");
                continue;
            }

            db.entries
                .entry((u64::from(digits) << TAG_SHIFT) | value)
                .or_insert_with(|| vendor.to_owned());
        }

        db
    }

    fn warn(&mut self, line: usize, message: &str) {
        self.warnings.push(MacDbWarning {
            line,
            message: message.to_owned(),
        });
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
    pub fn lookup(&self, mac: [u8; 6]) -> Option<&str> {
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
                return Some(vendor.as_str());
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
    pub fn find_prefix(&self, needle: &str) -> Option<MacPrefix> {
        let needle = needle.to_ascii_lowercase();
        let (key, _) = self
            .entries
            .iter()
            .find(|(_, vendor)| vendor.to_ascii_lowercase().contains(&needle))?;

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
        let db = MacPrefixDb::parse(SAMPLE);
        assert!(db.warnings.is_empty(), "{:?}", db.warnings);
        db
    }

    #[test]
    fn parses_all_three_assignment_sizes() {
        let db = db();
        assert_eq!(db.len(), 4);
        assert_eq!(
            db.lookup([0x08, 0x00, 0x27, 0x12, 0x34, 0x56]),
            Some("PCS Systemtechnik GmbH")
        );
        assert_eq!(
            db.lookup([0x00, 0x00, 0x00, 0xAB, 0xCD, 0xEF]),
            Some("Xerox")
        );
    }

    #[test]
    fn vendor_names_keep_their_internal_spacing() {
        let db = db();
        assert_eq!(
            db.lookup([0x00, 0x55, 0xDA, 0x0F, 0x00, 0x01]),
            Some("IEEE Registration Authority")
        );
    }

    #[test]
    fn the_most_specific_assignment_wins() {
        // 0055DA is not itself registered here, but 0055DA0 is: a 28-bit lookup must not
        // be answered by a 24-bit entry, nor the reverse.
        let db = MacPrefixDb::parse("0055DA Wrong Answer\n0055DA0 Right Answer\n");
        assert!(db.warnings.is_empty());
        assert_eq!(
            db.lookup([0x00, 0x55, 0xDA, 0x01, 0x02, 0x03]),
            Some("Right Answer"),
            "the 28-bit assignment covers 0055DA0*"
        );
        assert_eq!(
            db.lookup([0x00, 0x55, 0xDA, 0x11, 0x02, 0x03]),
            Some("Wrong Answer"),
            "0055DA1* falls outside the 28-bit assignment, so the 24-bit one applies"
        );
    }

    #[test]
    fn a_36_bit_assignment_beats_the_blocks_containing_it() {
        let db = MacPrefixDb::parse("70B3D5 Registry\n70B3D5E Middle\n70B3D5EEF Specific\n");
        assert!(db.warnings.is_empty());
        assert_eq!(
            db.lookup([0x70, 0xB3, 0xD5, 0xEE, 0xF0, 0x00]),
            Some("Specific")
        );
        assert_eq!(
            db.lookup([0x70, 0xB3, 0xD5, 0xEE, 0x00, 0x00]),
            Some("Middle")
        );
        assert_eq!(
            db.lookup([0x70, 0xB3, 0xD5, 0x00, 0x00, 0x00]),
            Some("Registry")
        );
    }

    #[test]
    fn an_unregistered_prefix_has_no_vendor() {
        assert_eq!(db().lookup([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]), None);
        assert_eq!(MacPrefixDb::default().lookup([0; 6]), None);
    }

    #[test]
    fn lookup_is_case_insensitive_in_the_file() {
        let db = MacPrefixDb::parse("00aAbB Lowercase Prefix\n");
        assert!(db.warnings.is_empty());
        assert_eq!(
            db.lookup([0x00, 0xAA, 0xBB, 0x00, 0x00, 0x00]),
            Some("Lowercase Prefix")
        );
    }

    #[test]
    fn a_bad_line_costs_only_that_line() {
        // The C stops parsing the whole file at the first bad line, silently discarding
        // every vendor after it.
        let db = MacPrefixDb::parse(
            "000000 First\nZZZZZZ junk\n00000 too short\n0000001x no space\n080027 Last\n",
        );
        assert_eq!(db.warnings.len(), 3, "{:?}", db.warnings);
        assert_eq!(db.warnings[0].line, 2);
        assert_eq!(db.warnings[1].line, 3);
        assert_eq!(db.warnings[2].line, 4);
        assert_eq!(db.lookup([0; 6]), Some("First"));
        assert_eq!(
            db.lookup([0x08, 0x00, 0x27, 0, 0, 0]),
            Some("Last"),
            "entries after the bad lines must survive"
        );
    }

    #[test]
    fn a_prefix_with_no_vendor_is_skipped_rather_than_stored_empty() {
        let db = MacPrefixDb::parse("000000\n000001   \n080027 Fine\n");
        assert_eq!(db.warnings.len(), 2);
        assert_eq!(db.lookup([0; 6]), None);
        assert_eq!(db.lookup([0x08, 0x00, 0x27, 0, 0, 0]), Some("Fine"));
    }

    #[test]
    fn the_first_entry_for_a_prefix_wins() {
        let db = MacPrefixDb::parse("000000 First\n000000 Second\n");
        assert!(db.warnings.is_empty());
        assert_eq!(db.len(), 1);
        assert_eq!(db.lookup([0; 6]), Some("First"));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let db = MacPrefixDb::parse("# header\n\n000000 Xerox\n\n# trailer\n");
        assert!(db.warnings.is_empty(), "{:?}", db.warnings);
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn carriage_returns_do_not_end_up_in_vendor_names() {
        let db = MacPrefixDb::parse("000000 Xerox\r\n");
        assert!(db.warnings.is_empty());
        assert_eq!(db.lookup([0; 6]), Some("Xerox"));
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
        let db = MacPrefixDb::parse("FFFFFF Acme Small Block\n000000A Acme Large Block\n");
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
                db.lookup(mac).is_some_and(|v| v
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())),
                "{needle}: prefix bytes {:02X?} did not look up to it",
                p.bytes
            );
        }
    }
}
