//! Corpus gate for `core::macvendor` against the **real** `nmap-mac-prefixes`.
//!
//! The oracle is built here from the raw file text using plain string operations — a
//! `HashMap` keyed by the uppercase hex prefix, and "most specific wins" resolved by
//! trying the 9-, 7- and 6-digit slices of the address in that order. That deliberately
//! shares no code with the module under test: `macvendor` packs prefixes into tagged
//! 64-bit integers and resolves them with shifts, so agreement across all 52,085 entries
//! cross-checks the bit packing rather than restating it.
//!
//! Skipped under Miri (reads a real file; Miri's filesystem isolation aborts rather than
//! returning `Err`). The unit suite in `macvendor` is what Miri interrogates.
#![cfg(not(miri))]

use std::collections::HashMap;

use nmap_core::macvendor::MacPrefixDb;

/// Entries in the shipped file: 38,930 MA-L + 6,262 MA-M + 6,893 MA-S.
const ENTRIES: usize = 52_085;
const MAL: usize = 38_930;
const MAM: usize = 6_262;
const MAS: usize = 6_893;

fn load_corpus() -> Option<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../nmap-mac-prefixes");
    std::fs::read_to_string(path).ok()
}

/// The independent oracle: uppercase hex prefix -> vendor, first entry winning.
fn oracle(text: &str) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let Some((prefix, vendor)) = line.split_once([' ', '\t']) else {
            continue;
        };
        let vendor = vendor.trim_start_matches([' ', '\t']);
        if vendor.is_empty() {
            continue;
        }
        map.entry(prefix.to_ascii_uppercase())
            .or_insert_with(|| vendor.to_owned());
    }
    map
}

/// Hex string -> the 6 address bytes, zero-padded on the right.
fn mac_bytes(hex12: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    let digits: Vec<u8> = hex12
        .chars()
        .map(|c| u8::try_from(c.to_digit(16).unwrap_or(0)).unwrap_or(0))
        .collect();
    for (slot, pair) in out.iter_mut().zip(digits.chunks(2)) {
        let hi = pair.first().copied().unwrap_or(0);
        let lo = pair.get(1).copied().unwrap_or(0);
        *slot = (hi << 4) | lo;
    }
    out
}

/// What the file says a given address resolves to: longest registered prefix wins.
fn expected<'a>(map: &'a HashMap<String, String>, hex12: &str) -> Option<&'a String> {
    for len in [9usize, 7, 6] {
        if let Some(v) = hex12.get(..len).and_then(|p| map.get(p)) {
            return Some(v);
        }
    }
    None
}

#[test]
fn parses_the_shipped_file_with_no_warnings() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-mac-prefixes not found; skipping macvendor corpus");
        return;
    };
    let db = MacPrefixDb::parse(&text);

    for w in db.warnings.iter().take(5) {
        eprintln!("unexpected warning at line {}: {}", w.line, w.message);
    }
    assert!(
        db.warnings.is_empty(),
        "the shipped file must parse cleanly, got {} warnings",
        db.warnings.len()
    );
    assert_eq!(db.len(), ENTRIES, "registered prefix count");
    assert_eq!(db.len(), oracle(&text).len(), "agrees with the text oracle");
    assert_eq!(
        MAL + MAM + MAS,
        ENTRIES,
        "block counts account for every entry"
    );
}

#[test]
fn every_registered_prefix_resolves_the_way_the_file_says() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-mac-prefixes not found; skipping macvendor corpus");
        return;
    };
    let db = MacPrefixDb::parse(&text);
    let map = oracle(&text);
    if map.is_empty() {
        return;
    }

    // For each registered prefix, form the canonical address (prefix then zeros) and
    // check the module resolves it exactly as the file text does — including the cases
    // where a longer assignment shadows the entry we started from.
    let mut checked = 0usize;
    let mut shadowed = 0usize;
    for (prefix, vendor) in &map {
        let mut hex12 = prefix.clone();
        while hex12.len() < 12 {
            hex12.push('0');
        }
        let want = expected(&map, &hex12).expect("the prefix itself is registered");
        let got = db.lookup(mac_bytes(&hex12));
        assert_eq!(
            got,
            Some(want.as_str()),
            "{prefix}: expected {want:?}, got {got:?}"
        );
        if want != vendor {
            shadowed += 1;
        }
        checked += 1;
    }
    assert_eq!(checked, ENTRIES);
    // Overlapping assignments are what make lookup order load-bearing; if the file ever
    // stopped containing any, this gate would quietly stop testing that.
    assert!(
        shadowed > 0,
        "no assignment is shadowed by a longer one, so specificity was never exercised"
    );
    eprintln!("{checked} prefixes checked, {shadowed} shadowed by a longer assignment");
}

#[test]
fn block_sizes_are_distributed_as_the_file_records_them() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-mac-prefixes not found; skipping macvendor corpus");
        return;
    };
    let map = oracle(&text);
    if map.is_empty() {
        return;
    }
    let count = |n: usize| map.keys().filter(|k| k.len() == n).count();
    assert_eq!(count(6), MAL, "MA-L (24-bit) entries");
    assert_eq!(count(7), MAM, "MA-M (28-bit) entries");
    assert_eq!(count(9), MAS, "MA-S (36-bit) entries");
    assert_eq!(
        map.keys().filter(|k| !matches!(k.len(), 6 | 7 | 9)).count(),
        0,
        "the file holds only the three IEEE assignment sizes"
    );
}

#[test]
fn well_known_prefixes_resolve_to_their_registrants() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-mac-prefixes not found; skipping macvendor corpus");
        return;
    };
    let db = MacPrefixDb::parse(&text);
    if db.is_empty() {
        return;
    }

    // 080027 is VirtualBox's, and the file's own header calls it out as an nmap addition.
    let vbox = db
        .lookup([0x08, 0x00, 0x27, 0xAB, 0xCD, 0xEF])
        .expect("080027 is registered");
    assert!(
        vbox.to_ascii_lowercase().contains("virtualbox"),
        "080027 resolved to {vbox:?}"
    );
    // 000000 is the first line of the file.
    assert_eq!(db.lookup([0, 0, 0, 0, 0, 0]), Some("Xerox"));

    // An address in no registered block has no vendor. FFFFFF is the broadcast prefix.
    assert_eq!(db.lookup([0xFF; 6]), None);
}

#[test]
fn find_prefix_round_trips_through_lookup_over_the_real_file() {
    let Some(text) = load_corpus() else {
        eprintln!("nmap-mac-prefixes not found; skipping macvendor corpus");
        return;
    };
    let db = MacPrefixDb::parse(&text);
    if db.is_empty() {
        return;
    }

    // What `--spoof-mac <vendor>` does: name a vendor, get a prefix to masquerade as.
    for needle in ["Xerox", "apple", "Cisco", "Intel", "SYSTEMTECHNIK"] {
        let p = db
            .find_prefix(needle)
            .unwrap_or_else(|| panic!("{needle} should appear in the file"));
        assert!(matches!(p.digits, 6 | 7 | 9), "{needle}: odd digit count");
        assert_eq!(
            p.bytes.len(),
            (p.digits as usize).div_ceil(2),
            "{needle}: wrong byte count"
        );
        if p.digits % 2 == 1 {
            assert_eq!(
                p.bytes.last().copied().unwrap_or(0) & 0x0f,
                0,
                "{needle}: odd-length prefix must zero-pad the final nibble"
            );
        }

        // The returned prefix must actually resolve to a vendor matching the needle.
        let mut mac = [0u8; 6];
        for (slot, b) in mac.iter_mut().zip(p.bytes.iter()) {
            *slot = *b;
        }
        let resolved = db
            .lookup(mac)
            .unwrap_or_else(|| panic!("{needle}: prefix {:02X?} resolves to nothing", p.bytes));
        assert!(
            resolved
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()),
            "{needle}: prefix {:02X?} resolved to {resolved:?}",
            p.bytes
        );
    }

    assert!(db.find_prefix("no such vendor exists here").is_none());
}
