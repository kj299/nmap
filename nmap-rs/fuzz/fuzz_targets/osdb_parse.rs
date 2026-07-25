// cargo-fuzz target for `nmap_core::osdb::model::FingerPrintDb::parse`.
//
// `--osscandb <file>` points this parser at an arbitrary file, so nmap-os-db is
// untrusted-shaped input parsed before any scanning happens — the same threat-model
// boundary nmap-service-probes has. The C reacts to malformed input with a mix of
// error() (warn and continue) and fatal() (abort the scan outright): a duplicate
// MatchPoints block, an unparseable point value, a Fingerprint line with no terminator
// or an empty OS name, a short Class line, or a CPE line with no preceding Class all
// kill the process.
//
// The contract enforced here: parsing is TOTAL. Any byte sequence yields a database
// (possibly empty, possibly all warnings) and never panics — the deliberate
// safer-than-C divergence `osdb-parse-degrade`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::osdb::model::FingerPrintDb;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let db = FingerPrintDb::parse(text);

    // Drive the query paths too, so a malformed record cannot produce a structure that
    // blows up on access.
    for fp in &db.prints {
        for t in &fp.tests {
            // Slot count must always agree with the test's attribute table, otherwise
            // the scorer would index out of range.
            assert_eq!(t.values.len(), t.id.attrs().len());
            for attr in t.id.attrs() {
                let _ = t.get(attr);
            }
            let _ = t.get("");
            let _ = t.get("NOPE");
        }
        let _ = fp.classes.len();
    }
    if let Some(mp) = db.match_points.as_ref() {
        for t in nmap_core::osdb::model::TestId::ALL {
            for i in 0..t.attrs().len() {
                let _ = mp.get(t, i);
            }
            // Out-of-range lookups must be defined, not panic.
            let _ = mp.get(t, usize::MAX);
        }
    }
    let _ = db.warnings.len();
});
