//! The opt-in store for unmatched fingerprints (Workstream S, slice S3a).
//!
//! nmap computes an unmatched OS fingerprint, prints it, tells the operator to
//! paste it into a web form (`output.cc:1901/1925/1938`), and then throws it away.
//! The data exists in-process and nothing captures it. This module is the missing
//! half: a local, **opt-in**, consent-gated store, plus an export the operator can
//! actually do something with.
//!
//! There is no C counterpart, so every behaviour here is ledgered in
//! `DIVERGENCES.md` as intentional additive behaviour rather than left to look
//! like drift.
//!
//! # Consent is structural, not a flag someone remembers to check
//!
//! [`FingerprintStore`] cannot be constructed without saying which it is:
//! [`FingerprintStore::enabled`] or [`FingerprintStore::disabled`]. A disabled
//! store still accepts [`record`](FingerprintStore::record) calls and still
//! answers questions — it simply keeps nothing, and says so by returning
//! [`RecordOutcome::NoConsent`]. That shape means a caller cannot *forget* to
//! check consent: there is no way to reach the storage without having chosen, and
//! the default in the CLI is disabled.
//!
//! # What is stored, and what leaves
//!
//! A fingerprint describes a host the operator scanned, so the store holds
//! reconnaissance data about a third party. The local record keeps the target
//! label because an operator reviewing their own file needs to know which host a
//! fingerprint came from. **Export makes that a decision, not a default:**
//! [`ExportScope::Submission`] omits the target entirely, because a fingerprint
//! submitted to improve a shared database does not need to carry who was scanned.
//! The caller must name a scope; there is no default that quietly picks one.
//!
//! # The stored text is attacker-controlled
//!
//! A fingerprint is built from bytes a scanned host chose. Two consequences the
//! implementation takes seriously: nothing here interpolates a fingerprint into a
//! path, command, or URL, and the export format escapes control bytes so a
//! fingerprint cannot forge a record boundary in its own export, inject ANSI
//! sequences into a terminal, or smuggle a newline past a line-oriented reader.

use core::fmt::Write as _;

/// Largest number of fingerprints kept. A scan of a large network can produce one
/// per host; the store is a convenience, not an archive, and an unbounded one is a
/// memory-exhaustion path driven by how many hosts the operator scanned.
pub const MAX_ENTRIES: usize = 1024;

/// Longest fingerprint text kept, in bytes. `fp2ascii` output for a full 13-test
/// fingerprint is well under this; the cap bounds a hostile or degenerate one.
pub const MAX_FINGERPRINT_LEN: usize = 8 * 1024;

/// Longest target label kept, in bytes. An address or hostname, not a URL.
pub const MAX_LABEL_LEN: usize = 256;

/// Which detection produced the fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FingerprintKind {
    /// An OS fingerprint, from `-O`.
    Os,
    /// A service fingerprint, from `-sV`. **Not produced yet** — the builder in
    /// `service_scan.cc` was never ported (M3 gap, tracked as slice S3b). The
    /// variant exists so the store's format does not have to change when it lands.
    Service,
}

impl FingerprintKind {
    /// The tag used in the export format.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Os => "os",
            Self::Service => "service",
        }
    }
}

/// What happened to a [`record`](FingerprintStore::record) call.
///
/// Every outcome is explicit: a caller that ignores this cannot tell "stored" from
/// "silently dropped", and silently dropping an operator's data is the failure mode
/// this whole module exists to fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// Stored.
    Stored,
    /// Consent is off, so nothing was kept. Not an error — the expected result of
    /// the default configuration.
    NoConsent,
    /// An identical fingerprint for this host and kind is already held.
    Duplicate,
    /// The store is at [`MAX_ENTRIES`].
    Full,
    /// The fingerprint was empty, or longer than [`MAX_FINGERPRINT_LEN`].
    Rejected,
}

/// One stored fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFingerprint {
    /// Which detection produced it.
    pub kind: FingerprintKind,
    /// The target it came from, as the operator addressed it. Kept for the local
    /// record; omitted by [`ExportScope::Submission`].
    pub target: String,
    /// The rendered fingerprint text.
    pub fingerprint: String,
    /// When it was recorded, as epoch seconds — **passed in by the caller**, never
    /// read here. `core` takes no clock: a module that reads the time is a module
    /// Miri cannot run and a test cannot pin (the lesson from `osprobe::seq`, whose
    /// `SystemTime::now()` turned the Miri job red in #81).
    pub recorded_at: Option<u64>,
}

/// How much of a record to include when exporting.
///
/// There is deliberately no `Default`. Choosing whether a host's identity leaves
/// the machine is not a decision to make by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportScope {
    /// The operator's own copy: includes the target and timestamp.
    Local,
    /// For submission to a shared database: **omits the target and the timestamp**.
    /// A fingerprint improves the database on its own; who was scanned, and when,
    /// is the operator's business and nobody else's.
    Submission,
}

/// The store.
#[derive(Debug, Clone)]
pub struct FingerprintStore {
    consent: bool,
    entries: Vec<StoredFingerprint>,
}

/// Escape a value for the export format.
///
/// The text is attacker-controlled, so this is a security control, not
/// prettification: `\n` would forge a record boundary in a line-oriented format,
/// `\x1b` would inject an escape sequence into whatever terminal reads the export,
/// and `\\` has to be escaped for the mapping to be reversible at all.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                // Control bytes never reach the reader as themselves.
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

impl FingerprintStore {
    /// A store that will keep what it is given. The operator has opted in.
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            consent: true,
            entries: Vec::new(),
        }
    }

    /// A store that keeps nothing. **This is the default configuration** — nothing
    /// is collected unless the operator asks for it.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            consent: false,
            entries: Vec::new(),
        }
    }

    /// Whether collection is on.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.consent
    }

    /// How many fingerprints are held. Always 0 for a disabled store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The stored fingerprints, in the order they were recorded.
    #[must_use]
    pub fn entries(&self) -> &[StoredFingerprint] {
        &self.entries
    }

    /// Offer a fingerprint to the store.
    ///
    /// Returns what actually happened — see [`RecordOutcome`]. A disabled store
    /// returns [`RecordOutcome::NoConsent`] and keeps nothing, which is the whole
    /// point: consent is checked here, once, rather than at every call site.
    ///
    /// `recorded_at` is supplied by the caller; this module never reads a clock.
    pub fn record(
        &mut self,
        kind: FingerprintKind,
        target: &str,
        fingerprint: &str,
        recorded_at: Option<u64>,
    ) -> RecordOutcome {
        if !self.consent {
            return RecordOutcome::NoConsent;
        }
        if fingerprint.is_empty() || fingerprint.len() > MAX_FINGERPRINT_LEN {
            return RecordOutcome::Rejected;
        }
        // Truncation is on a char boundary: `target` is a `&str`, and slicing one
        // mid-codepoint panics. Take whole characters up to the cap instead.
        let target: String = target
            .chars()
            .scan(0usize, |used, c| {
                let next = used.saturating_add(c.len_utf8());
                if next > MAX_LABEL_LEN {
                    None
                } else {
                    *used = next;
                    Some(c)
                }
            })
            .collect();

        if self
            .entries
            .iter()
            .any(|e| e.kind == kind && e.target == target && e.fingerprint == fingerprint)
        {
            return RecordOutcome::Duplicate;
        }
        if self.entries.len() >= MAX_ENTRIES {
            return RecordOutcome::Full;
        }
        self.entries.push(StoredFingerprint {
            kind,
            target,
            fingerprint: fingerprint.to_owned(),
            recorded_at,
        });
        RecordOutcome::Stored
    }

    /// Render the store for `--export-fingerprints`.
    ///
    /// The scope decides whether host identity leaves the machine; see
    /// [`ExportScope`]. An empty store exports an empty string, not a header, so
    /// concatenating exports stays meaningful.
    #[must_use]
    pub fn export(&self, scope: ExportScope) -> String {
        let mut out = String::new();
        for e in &self.entries {
            out.push_str("begin ");
            out.push_str(e.kind.tag());
            out.push('\n');
            if scope == ExportScope::Local {
                let _ = writeln!(out, "target {}", escape(&e.target));
                if let Some(t) = e.recorded_at {
                    let _ = writeln!(out, "recorded {t}");
                }
            }
            let _ = writeln!(out, "fingerprint {}", escape(&e.fingerprint));
            out.push_str("end\n");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "SEQ(SP=104%GCD=1%ISR=10D%TI=Z%CI=Z%II=I)\nOPS(O1=M5B4ST11NW7)";

    // --- consent ---------------------------------------------------------------

    #[test]
    fn a_disabled_store_keeps_nothing_no_matter_how_often_it_is_offered() {
        // The default configuration. This is the test the whole module exists for.
        let mut s = FingerprintStore::disabled();
        for i in 0..10 {
            assert_eq!(
                s.record(FingerprintKind::Os, &format!("10.0.0.{i}"), FP, Some(1)),
                RecordOutcome::NoConsent
            );
        }
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(!s.is_enabled());
        assert_eq!(s.export(ExportScope::Local), "");
        assert_eq!(s.export(ExportScope::Submission), "");
    }

    #[test]
    fn an_enabled_store_keeps_what_it_is_given() {
        let mut s = FingerprintStore::enabled();
        assert!(s.is_enabled());
        assert_eq!(
            s.record(FingerprintKind::Os, "10.0.0.1", FP, Some(1_700_000_000)),
            RecordOutcome::Stored
        );
        assert_eq!(s.len(), 1);
        let e = &s.entries()[0];
        assert_eq!(e.kind, FingerprintKind::Os);
        assert_eq!(e.target, "10.0.0.1");
        assert_eq!(e.fingerprint, FP);
        assert_eq!(e.recorded_at, Some(1_700_000_000));
    }

    #[test]
    fn consent_cannot_be_reached_around_by_a_caller_that_forgets_to_check() {
        // There is no constructor that leaves consent unspecified, and `record` is
        // the only way in. A caller that never asks about consent still cannot
        // store anything through a disabled store.
        let mut disabled = FingerprintStore::disabled();
        let _ = disabled.record(FingerprintKind::Os, "h", FP, None);
        let _ = disabled.record(FingerprintKind::Service, "h", "x", None);
        assert_eq!(disabled.entries(), &[]);
    }

    // --- what leaves the machine ------------------------------------------------

    #[test]
    fn submission_export_omits_the_target_and_the_timestamp() {
        // A fingerprint improves a shared database on its own. Who was scanned, and
        // when, is the operator's business.
        let mut s = FingerprintStore::enabled();
        s.record(
            FingerprintKind::Os,
            "192.168.7.42",
            "SEQ(SP=1)",
            Some(1_700_000_000),
        );

        let sub = s.export(ExportScope::Submission);
        assert!(
            sub.contains("SEQ(SP=1)"),
            "fingerprint must survive: {sub:?}"
        );
        assert!(!sub.contains("192.168.7.42"), "target leaked: {sub:?}");
        assert!(!sub.contains("1700000000"), "timestamp leaked: {sub:?}");
        assert!(!sub.contains("target"), "target field present: {sub:?}");

        let local = s.export(ExportScope::Local);
        assert!(local.contains("192.168.7.42"), "local export must keep it");
        assert!(local.contains("1700000000"));
    }

    #[test]
    fn no_target_survives_a_submission_export_of_many_hosts() {
        let mut s = FingerprintStore::enabled();
        let hosts = ["10.0.0.1", "scanner.internal.example", "2001:db8::1"];
        for h in hosts {
            s.record(FingerprintKind::Os, h, &format!("FP-for-{h}"), Some(5));
        }
        let sub = s.export(ExportScope::Submission);
        for h in hosts {
            // The host name appears inside the fake fingerprint text, so check the
            // `target` field specifically rather than raw containment.
            assert!(
                !sub.lines().any(|l| l == format!("target {h}")),
                "target line for {h} leaked"
            );
        }
        assert_eq!(sub.matches("begin os").count(), 3);
    }

    // --- the stored text is attacker-controlled ---------------------------------

    #[test]
    fn a_fingerprint_cannot_forge_a_record_boundary_in_its_own_export() {
        // The bytes come from a scanned host. If a newline survived unescaped, a
        // fingerprint could write its own `end` / `begin` lines and desynchronise
        // any reader of the export.
        let hostile = "real\nend\nbegin os\nfingerprint injected";
        let mut s = FingerprintStore::enabled();
        s.record(FingerprintKind::Os, "h", hostile, None);

        let out = s.export(ExportScope::Local);
        // The format is line-oriented, so the property that matters is that no LINE
        // reads as a delimiter. The literal text "begin os" may well appear inside
        // the escaped fingerprint -- harmlessly, because it cannot start a line.
        assert_eq!(
            out.lines().filter(|l| *l == "begin os").count(),
            1,
            "forged record boundary: {out:?}"
        );
        assert_eq!(out.lines().filter(|l| *l == "end").count(), 1);
        assert_eq!(out.lines().count(), 4, "extra lines appeared: {out:?}");
        assert!(out.contains("\\n"), "newline was not escaped: {out:?}");
        assert!(!out.contains("\nend\nbegin"), "raw injection survived");
    }

    #[test]
    fn a_target_cannot_forge_a_record_boundary_either() {
        let mut s = FingerprintStore::enabled();
        s.record(FingerprintKind::Os, "h\nend\nbegin os", FP, None);
        let out = s.export(ExportScope::Local);
        assert_eq!(
            out.lines().filter(|l| *l == "begin os").count(),
            1,
            "forged record boundary: {out:?}"
        );
        assert_eq!(out.lines().filter(|l| *l == "end").count(), 1);
    }

    #[test]
    fn control_bytes_are_escaped_rather_than_emitted() {
        // An export is read in a terminal. A fingerprint should not be able to move
        // the cursor or set colours there.
        let mut s = FingerprintStore::enabled();
        s.record(FingerprintKind::Os, "h", "a\x1b[31mb\x00c\x7fd\te", None);
        let out = s.export(ExportScope::Local);
        assert!(!out.contains('\x1b'), "escape byte leaked: {out:?}");
        assert!(!out.contains('\x00'), "nul leaked");
        assert!(!out.contains('\x7f'), "del leaked");
        assert!(out.contains("\\x1b") && out.contains("\\x00") && out.contains("\\x7f"));
        assert!(out.contains("\\t"));
    }

    #[test]
    fn a_backslash_is_escaped_so_the_mapping_is_reversible() {
        let mut s = FingerprintStore::enabled();
        s.record(FingerprintKind::Os, "h", r"a\nb", None);
        let out = s.export(ExportScope::Local);
        // The literal backslash-n in the input must not be confused with a newline.
        assert!(out.contains(r"a\\nb"), "ambiguous escaping: {out:?}");
    }

    // --- bounds ------------------------------------------------------------------

    /// How many entries the cap test writes.
    ///
    /// Natively this fills all [`MAX_ENTRIES`] slots and then checks the refusal.
    /// Under Miri that single test cost **320 seconds** measured -- `record`'s dedup
    /// is a linear scan, so filling the store is O(n^2) in string comparisons, about
    /// 524,000 of them. That is fine natively (the whole suite runs in ~10 ms) and it
    /// buys Miri nothing: `core` is `#![forbid(unsafe_code)]`, and every line this
    /// test executes is already executed under Miri by the other tests in this
    /// module -- it differs only in how many times it loops.
    ///
    /// So under Miri it fills a prefix instead: same code path, 1/256th the work. The
    /// cap refusal itself is asserted in the native run, which is where the bound
    /// actually matters.
    #[cfg(miri)]
    const CAP_TEST_FILL: usize = 64;
    /// See [`CAP_TEST_FILL`] under `cfg(miri)`.
    #[cfg(not(miri))]
    const CAP_TEST_FILL: usize = MAX_ENTRIES;

    #[test]
    fn the_store_stops_at_its_entry_cap() {
        let mut s = FingerprintStore::enabled();
        for i in 0..CAP_TEST_FILL {
            assert_eq!(
                s.record(
                    FingerprintKind::Os,
                    &format!("h{i}"),
                    &format!("fp{i}"),
                    None
                ),
                RecordOutcome::Stored
            );
        }
        assert_eq!(s.len(), CAP_TEST_FILL);
        if CAP_TEST_FILL == MAX_ENTRIES {
            assert_eq!(
                s.record(FingerprintKind::Os, "one-too-many", "fp", None),
                RecordOutcome::Full
            );
            assert_eq!(s.len(), MAX_ENTRIES);
        }
    }

    #[test]
    fn an_empty_or_oversized_fingerprint_is_refused() {
        let mut s = FingerprintStore::enabled();
        assert_eq!(
            s.record(FingerprintKind::Os, "h", "", None),
            RecordOutcome::Rejected
        );
        let huge = "x".repeat(MAX_FINGERPRINT_LEN.saturating_add(1));
        assert_eq!(
            s.record(FingerprintKind::Os, "h", &huge, None),
            RecordOutcome::Rejected
        );
        // Exactly at the cap is accepted, so the bound is off-by-one-proof.
        let at = "x".repeat(MAX_FINGERPRINT_LEN);
        assert_eq!(
            s.record(FingerprintKind::Os, "h", &at, None),
            RecordOutcome::Stored
        );
    }

    #[test]
    fn an_over_long_target_is_truncated_on_a_character_boundary() {
        // Slicing a &str mid-codepoint panics. The label is operator- or
        // DNS-supplied, so it can be long and it can be multi-byte.
        let mut s = FingerprintStore::enabled();
        let long: String = "é".repeat(MAX_LABEL_LEN);
        assert_eq!(
            s.record(FingerprintKind::Os, &long, FP, None),
            RecordOutcome::Stored
        );
        let kept = &s.entries()[0].target;
        assert!(kept.len() <= MAX_LABEL_LEN);
        assert!(
            kept.chars().all(|c| c == 'é'),
            "boundary was split: {kept:?}"
        );
        // And the whole thing is still valid UTF-8, which it would not be if the
        // truncation had cut a two-byte character in half.
        assert!(std::str::from_utf8(kept.as_bytes()).is_ok());
    }

    // --- deduplication -----------------------------------------------------------

    #[test]
    fn the_same_fingerprint_from_the_same_host_is_kept_once() {
        // -O retries the battery over several rounds; without this the store would
        // fill with copies of one host's result.
        let mut s = FingerprintStore::enabled();
        assert_eq!(
            s.record(FingerprintKind::Os, "10.0.0.1", FP, Some(1)),
            RecordOutcome::Stored
        );
        assert_eq!(
            s.record(FingerprintKind::Os, "10.0.0.1", FP, Some(2)),
            RecordOutcome::Duplicate
        );
        assert_eq!(s.len(), 1);
        // The timestamp of the FIRST sighting is the one kept.
        assert_eq!(s.entries()[0].recorded_at, Some(1));
    }

    #[test]
    fn the_same_fingerprint_from_a_different_host_is_a_separate_record() {
        let mut s = FingerprintStore::enabled();
        s.record(FingerprintKind::Os, "10.0.0.1", FP, None);
        assert_eq!(
            s.record(FingerprintKind::Os, "10.0.0.2", FP, None),
            RecordOutcome::Stored
        );
        // As is the same host under a different detection kind.
        assert_eq!(
            s.record(FingerprintKind::Service, "10.0.0.1", FP, None),
            RecordOutcome::Stored
        );
        assert_eq!(s.len(), 3);
    }

    // --- format ------------------------------------------------------------------

    #[test]
    fn an_empty_store_exports_nothing_at_all() {
        // Not a header with no body: concatenating exports has to stay meaningful.
        let s = FingerprintStore::enabled();
        assert_eq!(s.export(ExportScope::Local), "");
        assert_eq!(s.export(ExportScope::Submission), "");
    }

    #[test]
    fn the_export_is_the_documented_shape() {
        let mut s = FingerprintStore::enabled();
        s.record(FingerprintKind::Os, "10.0.0.1", "SEQ(SP=1)", Some(42));
        assert_eq!(
            s.export(ExportScope::Local),
            "begin os\ntarget 10.0.0.1\nrecorded 42\nfingerprint SEQ(SP=1)\nend\n"
        );
        assert_eq!(
            s.export(ExportScope::Submission),
            "begin os\nfingerprint SEQ(SP=1)\nend\n"
        );
    }

    #[test]
    fn a_record_with_no_timestamp_omits_the_line_rather_than_writing_a_placeholder() {
        let mut s = FingerprintStore::enabled();
        s.record(FingerprintKind::Os, "h", "fp", None);
        let out = s.export(ExportScope::Local);
        assert!(!out.contains("recorded"), "placeholder written: {out:?}");
        assert_eq!(out, "begin os\ntarget h\nfingerprint fp\nend\n");
    }

    #[test]
    fn entries_keep_the_order_they_were_recorded_in() {
        let mut s = FingerprintStore::enabled();
        for i in 0..5 {
            s.record(
                FingerprintKind::Os,
                &format!("h{i}"),
                &format!("fp{i}"),
                None,
            );
        }
        let out = s.export(ExportScope::Submission);
        let positions: Vec<_> = (0..5)
            .map(|i| out.find(&format!("fp{i}")).expect("present"))
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "order lost");
    }

    #[test]
    fn the_kind_tag_distinguishes_the_two_detections() {
        assert_eq!(FingerprintKind::Os.tag(), "os");
        assert_eq!(FingerprintKind::Service.tag(), "service");
        let mut s = FingerprintStore::enabled();
        s.record(FingerprintKind::Service, "h", "fp", None);
        assert!(s
            .export(ExportScope::Submission)
            .starts_with("begin service\n"));
    }

    #[test]
    fn recording_never_reads_a_clock() {
        // `recorded_at` is whatever the caller passed, verbatim -- including a value
        // no clock would produce. A module that reads the time is one Miri cannot
        // run and a test cannot pin (the lesson that turned #81's Miri job red).
        let mut s = FingerprintStore::enabled();
        s.record(FingerprintKind::Os, "h", "fp", Some(u64::MAX));
        assert_eq!(s.entries()[0].recorded_at, Some(u64::MAX));
        assert!(s.export(ExportScope::Local).contains(&u64::MAX.to_string()));
    }
}
