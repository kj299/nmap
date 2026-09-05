//! Signature-database maintenance — the manifest, verification and version model
//! behind `--update-signatures` (Workstream S; see `docs/S-ANALYSIS.md`).
//!
//! Unlike every other module in this crate, this one has **no C counterpart**.
//! nmap ships `nmap-os-db`, `nmap-service-probes` and `nmap-mac-prefixes` but has
//! no in-tool way to update them, no version metadata to report (all three files
//! carry an unexpanded SVN `$Id$` where a version should be), and no way to
//! collect the unmatched fingerprints it computes and prints. So there is nothing
//! to differential against here: correctness rests on golden and negative tests,
//! and every behaviour is ledgered in `DIVERGENCES.md` as intentional additive
//! behaviour rather than silently appearing.
//!
//! The security argument for the whole workstream is in `docs/S-ANALYSIS.md`, but
//! the short version: `nmap_fetchfile_sub` resolves database paths through
//! `$NMAPDIR` ahead of the user and system directories, takes the first readable
//! hit, and then trusts its contents completely. nmap's own mitigation is to warn
//! the operator off running setuid (`nmap.cc:319`), because there is nothing in
//! the file format to verify against. Verifying content against a pinned key is
//! what makes the search order stop being security-relevant.

pub mod digest;
pub mod manifest;
pub mod verify;

pub use digest::{to_hex, Sha256, DIGEST_LEN};
pub use manifest::{FileEntry, Manifest, ManifestError, VersionVerdict, SCHEMA_VERSION};
pub use verify::{
    verify_manifest, KeyRing, SignedEnvelope, TrustedKey, VerifiedManifest, VerifyError,
    ENVELOPE_VERSION,
};
