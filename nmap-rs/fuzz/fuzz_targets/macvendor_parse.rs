// cargo-fuzz target for `nmap_core::macvendor::MacPrefixDb`.
//
// `nmap-mac-prefixes` is loaded from the data-file search path, so like nmap-os-db and
// nmap-service-probes it is untrusted-input-shaped: whoever can place a file on that
// path chooses every byte the parser sees.
//
// The C reacts to a single malformed line by printing an error and `break`ing out of the
// read loop, abandoning every remaining line — one stray byte near the top of the file
// silently costs ~52,000 vendor entries. It also `assert()`s on a prefix with no vendor,
// aborting a debug build outright.
//
// The contract enforced here: parsing is TOTAL, lookup is TOTAL, and the table's own
// invariants hold for any input. Since M6.6 the parser reads bytes, and `nmapdb.mac2corp`
// hands what it finds to scripts.
//
// And it is READ RIGHT (M6.6 review, security D4): a valid line generated from the input
// — a 6, 7 or 9 digit prefix in either case, C whitespace (`\v` and `\f` included), a
// vendor that keeps its inner and trailing spaces and ends at the first `\r` or NUL — is
// found, with exactly that vendor, both alone and put in front of the input as a 9-digit
// prefix (the most specific, so first-wins decides it). A parser that returns an empty
// table, drops the `\r` or NUL rule, or trims the vendor fails here.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::macvendor::MacPrefixDb;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// A valid line made from `seed`: its prefix's hex digits, the address under it, and
/// the vendor the parser must store.
fn valid_line(seed: &[u8], digits: usize) -> (Vec<u8>, [u8; 6], Vec<u8>) {
    let byte = |i: usize| seed.get(i).copied().unwrap_or(0x5a);
    // The prefix: nibbles from the seed, upper- or lower-case by another bit.
    let mut nibbles = [0u8; 12];
    let mut line = Vec::new();
    for (i, n) in nibbles.iter_mut().enumerate().take(digits) {
        *n = byte(i) & 0x0f;
        let c = HEX[usize::from(*n)];
        line.push(if byte(i) & 0x10 != 0 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    // The address: the prefix, then the seed's bits.
    for (i, n) in nibbles.iter_mut().enumerate().skip(digits) {
        *n = byte(i) & 0x0f;
    }
    let mut mac = [0u8; 6];
    for (i, m) in mac.iter_mut().enumerate() {
        *m = (nibbles[2 * i] << 4) | nibbles[2 * i + 1];
    }
    // One or more C-space bytes, then the vendor.
    let spaces = [b' ', b'\t', 0x0b, 0x0c];
    for k in 0..=(byte(12) % 3) {
        line.push(spaces[usize::from(byte(13).wrapping_add(k) % 4)]);
    }
    let mut vendor: Vec<u8> = seed
        .iter()
        .skip(14)
        .copied()
        .filter(|&b| b != 0 && b != b'\n' && b != b'\r')
        .take(24)
        .collect();
    while vendor
        .first()
        .is_some_and(|&b| matches!(b, b' ' | b'\t' | 0x0b | 0x0c))
    {
        vendor.remove(0);
    }
    if vendor.is_empty() {
        vendor = b"Vendor  Inc ".to_vec();
    }
    line.extend_from_slice(&vendor);
    // What follows a `\r` or a NUL is not the vendor's.
    match byte(12) % 3 {
        0 => line.extend_from_slice(b"\rtail"),
        1 => line.extend_from_slice(b"\0tail"),
        _ => {}
    }
    (line, mac, vendor)
}

fuzz_target!(|data: &[u8]| {
    // The file is read as bytes, as the C reads it: no UTF-8 gate in front of the parser.
    let db = MacPrefixDb::parse(data);

    // Every warning must name a real 1-based line: one per `\n`, plus the last.
    let lines = data.iter().filter(|&&b| b == b'\n').count() + 1;
    for w in &db.warnings {
        assert!(w.line >= 1 && w.line <= lines, "warning line out of range");
    }
    assert!(db.warnings.len() <= db.warning_count);
    assert!(db.warning_count <= lines);

    // A valid line is found, with its vendor: alone, at each size.
    for digits in [6, 7, 9] {
        let (line, mac, vendor) = valid_line(data, digits);
        let one = MacPrefixDb::parse(&line);
        assert_eq!(one.len(), 1, "{line:?} was not read");
        assert_eq!(one.warning_count, 0, "{line:?} was warned of");
        assert_eq!(one.lookup(mac), Some(&vendor[..]), "{line:?}");
    }
    // And in front of the input, as the most specific prefix: first wins.
    let (mut front, mac, vendor) = valid_line(data, 9);
    front.push(b'\n');
    front.extend_from_slice(data);
    assert_eq!(
        MacPrefixDb::parse(&front).lookup(mac),
        Some(&vendor[..]),
        "{front:?}"
    );
    assert_eq!(db.is_empty(), db.len() == 0);

    // Lookup must be total over arbitrary addresses, including ones assembled from the
    // input itself so the fuzzer can steer toward addresses the table knows about.
    let bytes = data;
    let mut mac = [0u8; 6];
    for (i, slot) in mac.iter_mut().enumerate() {
        *slot = bytes.get(i).copied().unwrap_or(0);
    }
    for probe in [mac, [0u8; 6], [0xffu8; 6]] {
        let _ = db.lookup(probe);
    }

    // Anything the table holds must be reachable: search for a vendor name, then confirm
    // the prefix it hands back is well formed and resolves to a matching vendor. This is
    // the `--spoof-mac <vendor>` path.
    for needle in [&b""[..], b"a", data] {
        let Some(p) = db.find_prefix(needle) else {
            continue;
        };
        assert!(matches!(p.digits, 6 | 7 | 9), "invalid digit count");
        assert_eq!(
            p.bytes.len(),
            (p.digits as usize + 1) / 2,
            "byte count disagrees with digit count"
        );
        if p.digits % 2 == 1 {
            assert_eq!(
                p.bytes.last().copied().unwrap_or(0) & 0x0f,
                0,
                "odd-length prefix must zero-pad its final nibble"
            );
        }

        let mut mac = [0u8; 6];
        for (slot, b) in mac.iter_mut().zip(p.bytes.iter()) {
            *slot = *b;
        }
        let resolved = db.lookup(mac).expect("a returned prefix must resolve");
        let (resolved, needle) = (resolved.to_ascii_lowercase(), needle.to_ascii_lowercase());
        assert!(
            needle.is_empty()
                || resolved.windows(needle.len()).any(|w| w == needle.as_slice())
                // A longer assignment may shadow the prefix we were handed, in which case
                // the resolved vendor is a different (more specific) registrant.
                || db.len() > 1,
            "prefix resolved to an unrelated vendor in a single-entry table"
        );
    }
});
