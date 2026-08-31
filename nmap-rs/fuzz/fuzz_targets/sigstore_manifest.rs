// cargo-fuzz target for `nmap_core::sigstore::manifest::Manifest`.
//
// The manifest is the document that decides whether other bytes are trustworthy, and
// it is reached from two untrusted sources: a bundle fetched over the network, and an
// operator-supplied file passed to `--import-signatures` (which may have come off an
// untrusted medium). Signature verification runs over the raw bytes BEFORE this parser,
// so in the happy path it sees verified input — but a parser that only holds up on
// verified input is one control deep, and `--import-signatures` of an unverified file
// is a real path. It has to be total on arbitrary bytes.
//
// The contract enforced here:
//   * parsing is TOTAL — no panic, no overflow, no unbounded allocation, for any input;
//   * every name that survives parsing is safe to join onto a directory (this is the
//     control that kills path traversal for every downstream consumer, present and
//     future, rather than resting on each of them remembering to check);
//   * all declared bounds actually hold on the returned value;
//   * the downgrade comparison is a total order, so a rollback can never read as an
//     upgrade.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::sigstore::manifest::{
    Manifest, VersionVerdict, MAX_FILES, MAX_FILE_SIZE, MAX_NAME_LEN, SCHEMA_VERSION,
};

fuzz_target!(|data: &[u8]| {
    let Ok(m) = Manifest::parse(data) else {
        // Every rejection path must also be panic-free, which reaching here proves.
        return;
    };

    // --- bounds the type promises ------------------------------------------------
    assert!(m.schema <= SCHEMA_VERSION, "schema {} accepted", m.schema);
    assert!(!m.files.is_empty(), "empty file list accepted");
    assert!(m.files.len() <= MAX_FILES, "{} files accepted", m.files.len());

    for f in &m.files {
        // --- the traversal guarantee ---------------------------------------------
        assert!(!f.name.is_empty(), "empty name accepted");
        assert!(f.name.len() <= MAX_NAME_LEN, "long name accepted: {:?}", f.name);
        assert!(!f.name.starts_with('.'), "dot-leading name accepted: {:?}", f.name);
        assert!(!f.name.contains('/'), "slash in name: {:?}", f.name);
        assert!(!f.name.contains('\\'), "backslash in name: {:?}", f.name);
        assert!(!f.name.contains(".."), "parent ref in name: {:?}", f.name);
        assert!(
            f.name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'),
            "name outside the allowlist: {:?}",
            f.name
        );
        // A name that passes the above is a single normal path component. Assert the
        // property a consumer actually relies on, not just the bytes it is made of.
        let joined = std::path::Path::new("/data").join(&f.name);
        assert_eq!(
            joined.parent(),
            Some(std::path::Path::new("/data")),
            "name escaped its directory: {:?}",
            f.name
        );

        // --- the installer's pre-write ceiling -----------------------------------
        assert!(f.size <= MAX_FILE_SIZE, "oversize file accepted: {}", f.size);
    }

    // Names are unique, so a second record can never shadow an earlier hash.
    for (i, f) in m.files.iter().enumerate() {
        assert!(
            !m.files.iter().skip(i.saturating_add(1)).any(|g| g.name == f.name),
            "duplicate file name survived: {:?}",
            f.name
        );
        // Lookup agrees with the vector it was built from.
        assert_eq!(m.file(&f.name).map(|e| &e.name), Some(&f.name));
    }

    // --- the downgrade decision is a total order ---------------------------------
    // Checked against the serial's own ordering at the boundaries an off-by-one would
    // hit, since "accepts a rollback" is the failure that matters.
    for probe in [0, 1, m.serial, u64::MAX] {
        let verdict = m.compare_to_installed(probe);
        let expected = if m.serial > probe {
            VersionVerdict::Newer
        } else if m.serial == probe {
            VersionVerdict::Same
        } else {
            VersionVerdict::Older
        };
        assert_eq!(verdict, expected, "serial {} vs installed {}", m.serial, probe);
    }
    assert_eq!(m.compare_to_installed(m.serial), VersionVerdict::Same);

    // Re-parsing must be deterministic: the same bytes always give the same document.
    assert_eq!(Manifest::parse(data).ok(), Some(m));
});
