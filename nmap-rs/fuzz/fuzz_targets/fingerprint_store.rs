// cargo-fuzz target for `nmap_core::fingerprint_store`.
//
// The stored text is built from bytes a scanned host chose, and the target label can
// come from DNS, so both are attacker-influenced. The export is then read by an
// operator's terminal and by whatever tooling consumes it.
//
// The contract enforced here:
//   * recording and exporting are TOTAL for any input;
//   * a DISABLED store keeps nothing, ever -- the property the default configuration
//     rests on;
//   * no fingerprint or target can forge a record boundary in the export, however it
//     is spelled;
//   * a Submission export never carries a target or a timestamp;
//   * every declared bound holds on the resulting store.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::fingerprint_store::{
    ExportScope, FingerprintKind, FingerprintStore, RecordOutcome, MAX_ENTRIES,
    MAX_FINGERPRINT_LEN, MAX_LABEL_LEN,
};

/// Split the input into (kind, target, fingerprint) triples on a byte the fuzzer can
/// find easily, so it spends its budget on content rather than on framing.
fn triples(data: &[u8]) -> Vec<(FingerprintKind, String, String)> {
    data.split(|&b| b == 0x1e)
        .filter(|c| !c.is_empty())
        .map(|chunk| {
            let kind = if chunk[0] % 2 == 0 {
                FingerprintKind::Os
            } else {
                FingerprintKind::Service
            };
            let rest = &chunk[1..];
            let mid = rest.iter().position(|&b| b == 0x1f).unwrap_or(0);
            let (t, f) = rest.split_at(mid);
            (
                kind,
                String::from_utf8_lossy(t).into_owned(),
                String::from_utf8_lossy(f).into_owned(),
            )
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let items = triples(data);

    // --- a disabled store keeps nothing, whatever it is offered -------------------
    let mut off = FingerprintStore::disabled();
    for (kind, target, fp) in &items {
        assert_eq!(
            off.record(*kind, target, fp, Some(1)),
            RecordOutcome::NoConsent
        );
    }
    assert!(off.is_empty(), "disabled store kept {} entries", off.len());
    assert_eq!(off.export(ExportScope::Local), "");
    assert_eq!(off.export(ExportScope::Submission), "");

    // --- an enabled store holds to its bounds -------------------------------------
    let mut on = FingerprintStore::enabled();
    for (kind, target, fp) in &items {
        let outcome = on.record(*kind, target, fp, Some(7));
        // An empty fingerprint is the one input that must always be refused.
        if fp.is_empty() {
            assert_eq!(outcome, RecordOutcome::Rejected);
        }
    }

    assert!(on.len() <= MAX_ENTRIES, "entry cap broken: {}", on.len());
    for e in on.entries() {
        assert!(!e.fingerprint.is_empty(), "empty fingerprint stored");
        assert!(e.fingerprint.len() <= MAX_FINGERPRINT_LEN);
        assert!(e.target.len() <= MAX_LABEL_LEN, "label cap broken");
        // Truncation must not have split a character: a String that survived a
        // mid-codepoint cut could not exist, so this checks the cut was on a
        // boundary by construction as well as by round trip.
        assert!(std::str::from_utf8(e.target.as_bytes()).is_ok());
    }

    // Entries are unique on (kind, target, fingerprint).
    for (i, e) in on.entries().iter().enumerate() {
        assert!(
            !on.entries()
                .iter()
                .skip(i.saturating_add(1))
                .any(|g| g.kind == e.kind && g.target == e.target && g.fingerprint == e.fingerprint),
            "duplicate survived"
        );
    }

    // --- no input can forge a record boundary -------------------------------------
    for scope in [ExportScope::Local, ExportScope::Submission] {
        let out = on.export(scope);
        let begins = out
            .lines()
            .filter(|l| *l == "begin os" || *l == "begin service")
            .count();
        let ends = out.lines().filter(|l| *l == "end").count();
        assert_eq!(begins, on.len(), "record count desynchronised in {scope:?}");
        assert_eq!(ends, on.len(), "end count desynchronised in {scope:?}");

        // Control bytes never reach the reader as themselves.
        assert!(
            !out.chars().any(|c| (c as u32) < 0x20 && c != '\n'),
            "raw control byte in export"
        );
        assert!(!out.contains('\x7f'), "raw DEL in export");
    }

    // --- a submission export carries no host identity ------------------------------
    let sub = on.export(ExportScope::Submission);
    assert!(
        !sub.lines().any(|l| l.starts_with("target ") || l.starts_with("recorded ")),
        "submission export leaked host identity"
    );

    // Exporting is pure: same store, same bytes.
    assert_eq!(on.export(ExportScope::Submission), sub);
});
