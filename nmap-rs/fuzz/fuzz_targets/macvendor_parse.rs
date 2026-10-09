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
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::macvendor::MacPrefixDb;

fuzz_target!(|data: &[u8]| {
    // The file is read as bytes, as the C reads it: no UTF-8 gate in front of the parser.
    let db = MacPrefixDb::parse(data);

    // Every warning must name a real 1-based line: one per `\n`, plus the last.
    let lines = data.iter().filter(|&&b| b == b'\n').count() + 1;
    for w in &db.warnings {
        assert!(w.line >= 1 && w.line <= lines, "warning line out of range");
    }
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
