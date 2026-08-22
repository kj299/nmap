//! The `nmap-os-db` data model — the types `osscan.cc` builds while parsing the
//! fingerprint database, and that the match scorer consumes.
//!
//! A database is one optional `MatchPoints` block (how many points each attribute is
//! worth when scoring) plus a list of fingerprints. Each fingerprint is an OS name, zero
//! or more `Class`/`CPE` classifications, and up to 13 *tests* — `SEQ`, `OPS`, `WIN`,
//! `ECN`, `T1`–`T7`, `U1`, `IE` — each holding a fixed set of named attributes whose
//! values are [`crate::osdb::expr`] expressions.

/// Number of fingerprint tests, matching the C's `NUM_FPTESTS`.
pub const NUM_FPTESTS: usize = 13;
/// Widest attribute list of any test, matching the C's `FP_MAX_TEST_ATTRS`.
pub const FP_MAX_TEST_ATTRS: usize = 11;

/// One of the 13 fingerprint tests. Ordering matches the C's `TestID` enum, which the
/// scorer relies on to index the match-points table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TestId {
    Seq,
    Ops,
    Win,
    Ecn,
    T1,
    T2,
    T3,
    T4,
    T5,
    T6,
    T7,
    U1,
    Ie,
}

/// Per-test attribute names, a direct transcription of the C's
/// `FingerPrintDef::test_attrs`. Order is significant: it is the index space for both
/// a test's values and the match-points table.
const TEST_ATTRS: [&[&str]; NUM_FPTESTS] = [
    /* SEQ */ &["SP", "GCD", "ISR", "TI", "CI", "II", "SS", "TS"],
    /* OPS */ &["O1", "O2", "O3", "O4", "O5", "O6"],
    /* WIN */ &["W1", "W2", "W3", "W4", "W5", "W6"],
    /* ECN */ &["R", "DF", "T", "TG", "W", "O", "CC", "Q"],
    /* T1  */ &["R", "DF", "T", "TG", "S", "A", "F", "RD", "Q"],
    /* T2  */ &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    /* T3  */ &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    /* T4  */ &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    /* T5  */ &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    /* T6  */ &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    /* T7  */ &["R", "DF", "T", "TG", "W", "S", "A", "F", "O", "RD", "Q"],
    /* U1  */
    &[
        "R", "DF", "T", "TG", "IPL", "UN", "RIPL", "RID", "RIPCK", "RUCK", "RUD",
    ],
    /* IE  */ &["R", "DFI", "T", "TG", "CD"],
];

const TEST_NAMES: [&str; NUM_FPTESTS] = [
    "SEQ", "OPS", "WIN", "ECN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE",
];

impl TestId {
    /// Every test, in the C's declaration order.
    pub const ALL: [TestId; NUM_FPTESTS] = [
        TestId::Seq,
        TestId::Ops,
        TestId::Win,
        TestId::Ecn,
        TestId::T1,
        TestId::T2,
        TestId::T3,
        TestId::T4,
        TestId::T5,
        TestId::T6,
        TestId::T7,
        TestId::U1,
        TestId::Ie,
    ];

    /// Position in the C's `TestID` enum / match-points table.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            TestId::Seq => 0,
            TestId::Ops => 1,
            TestId::Win => 2,
            TestId::Ecn => 3,
            TestId::T1 => 4,
            TestId::T2 => 5,
            TestId::T3 => 6,
            TestId::T4 => 7,
            TestId::T5 => 8,
            TestId::T6 => 9,
            TestId::T7 => 10,
            TestId::U1 => 11,
            TestId::Ie => 12,
        }
    }

    /// The test's name as it appears in the database (`"SEQ"`, `"T1"`, …).
    #[must_use]
    pub fn name(self) -> &'static str {
        TEST_NAMES[self.index()]
    }

    /// Parse a test name; `None` for anything not one of the 13.
    #[must_use]
    pub fn from_name(name: &str) -> Option<TestId> {
        TEST_NAMES
            .iter()
            .position(|&n| n == name)
            .map(|i| TestId::ALL[i])
    }

    /// The test's attribute names, in index order.
    #[must_use]
    pub fn attrs(self) -> &'static [&'static str] {
        TEST_ATTRS[self.index()]
    }

    /// Index of a named attribute within this test.
    #[must_use]
    pub fn attr_index(self, attr: &str) -> Option<usize> {
        self.attrs().iter().position(|&a| a == attr)
    }

    /// Whether the test carries the `R` (responded) attribute — true for every test
    /// whose attribute list starts with `R`. The C tracks this as `FingerTestDef::hasR`
    /// and uses it to default `R=Y`/`R=N`.
    #[must_use]
    pub fn has_r(self) -> bool {
        self.attrs().first() == Some(&"R")
    }
}

/// One test's attribute values, indexed in step with [`TestId::attrs`]. `None` means the
/// database did not specify that attribute, which the scorer skips rather than treats as
/// a mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerTest {
    /// Which test this is.
    pub id: TestId,
    /// Values by attribute index; `None` where unspecified.
    pub values: Vec<Option<String>>,
}

impl FingerTest {
    /// An empty test with every attribute unset.
    #[must_use]
    pub fn new(id: TestId) -> Self {
        Self {
            id,
            values: vec![None; id.attrs().len()],
        }
    }

    /// The expression recorded for a named attribute, if any.
    #[must_use]
    pub fn get(&self, attr: &str) -> Option<&str> {
        let i = self.id.attr_index(attr)?;
        self.values.get(i)?.as_deref()
    }

    /// Record a value for a named attribute. An attribute this test does not define is
    /// ignored rather than panicking — the C's `setAVal` looks the name up in the same
    /// table and would run off the end.
    pub fn set(&mut self, attr: &str, value: impl Into<String>) {
        if let Some(i) = self.id.attr_index(attr) {
            if let Some(slot) = self.values.get_mut(i) {
                *slot = Some(value.into());
            }
        }
    }

    /// Remove a named attribute, returning it to the "not specified" state the scorer
    /// skips.
    pub fn clear(&mut self, attr: &str) {
        if let Some(i) = self.id.attr_index(attr) {
            if let Some(slot) = self.values.get_mut(i) {
                *slot = None;
            }
        }
    }

    /// Render as `NAME(A=v%B=v)` — the C's `test2str`, and the exact syntax
    /// [`super::parse`] reads back.
    ///
    /// A test with no attribute set renders as `NAME()`. Unset attributes are skipped, so
    /// the result names only what was actually observed.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(self.id.name());
        out.push('(');
        let mut first = true;
        for (i, attr) in self.id.attrs().iter().enumerate() {
            let Some(Some(value)) = self.values.get(i) else {
                continue;
            };
            if !first {
                out.push('%');
            }
            first = false;
            out.push_str(attr);
            out.push('=');
            out.push_str(value);
        }
        out.push(')');
        out
    }
}

/// An `Class vendor | family | generation | device type` line, plus any `CPE` lines that
/// followed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsClass {
    /// e.g. `Linux`.
    pub vendor: String,
    /// e.g. `Linux`.
    pub family: String,
    /// e.g. `5.X`. Genuinely absent rather than empty when the field is blank — the C
    /// stores `NULL` here specifically.
    pub generation: Option<String>,
    /// e.g. `general purpose`.
    pub device_type: String,
    /// CPE identifiers attached to this classification.
    pub cpe: Vec<String>,
}

/// One `Fingerprint` record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FingerPrint {
    /// The human-readable OS name from the `Fingerprint` line.
    pub os_name: String,
    /// 1-based line the record started on, for diagnostics.
    pub line: usize,
    /// `Class`/`CPE` classifications.
    pub classes: Vec<OsClass>,
    /// The tests this fingerprint specifies.
    pub tests: Vec<FingerTest>,
    /// Total points available, summed over the attributes present in each test — the
    /// denominator the scorer divides by (the C's `match.numprints`).
    pub num_points: u32,
}

impl FingerPrint {
    /// The named test, if this fingerprint specifies it.
    #[must_use]
    pub fn test(&self, id: TestId) -> Option<&FingerTest> {
        self.tests.iter().find(|t| t.id == id)
    }

    /// Mutable access to the named test, if present.
    pub fn test_mut(&mut self, id: TestId) -> Option<&mut FingerTest> {
        self.tests.iter_mut().find(|t| t.id == id)
    }

    /// Render the tests as the newline-separated block nmap prints for an unrecognised
    /// host and asks the user to submit — the C's `fp2ascii`.
    ///
    /// Tests are emitted in [`TestId::ALL`] order regardless of insertion order, so the
    /// output is canonical: two runs that observed the same things render identically.
    ///
    /// ## Divergence — `fp-render-no-truncation`
    ///
    /// The C renders into a **2048-byte `static` buffer** and silently `break`s out of the
    /// loop when it fills, so a long fingerprint is truncated with no indication. That
    /// output is precisely what users are asked to paste into a submission, and a
    /// truncated one is a corrupt submission. `static` also makes it non-reentrant. This
    /// returns an owned `String` that always holds the whole fingerprint.
    #[must_use]
    pub fn render_tests(&self) -> String {
        let mut out = String::new();
        for id in TestId::ALL {
            if let Some(test) = self.test(id) {
                out.push_str(&test.render());
                out.push('\n');
            }
        }
        out
    }
}

/// The `MatchPoints` block: how much each attribute of each test is worth when scoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchPoints {
    points: Vec<Vec<u32>>,
}

impl Default for MatchPoints {
    fn default() -> Self {
        Self {
            points: TestId::ALL
                .iter()
                .map(|t| vec![0u32; t.attrs().len()])
                .collect(),
        }
    }
}

impl MatchPoints {
    /// Points for one attribute of one test; `0` when unspecified.
    #[must_use]
    pub fn get(&self, id: TestId, attr_index: usize) -> u32 {
        self.points
            .get(id.index())
            .and_then(|row| row.get(attr_index))
            .copied()
            .unwrap_or(0)
    }

    /// Record a point value. Returns `false` if the indices are out of range.
    pub fn set(&mut self, id: TestId, attr_index: usize, points: u32) -> bool {
        match self
            .points
            .get_mut(id.index())
            .and_then(|row| row.get_mut(attr_index))
        {
            Some(slot) => {
                *slot = points;
                true
            }
            None => false,
        }
    }
}

/// A non-fatal problem encountered while parsing, with the line it occurred on. The C
/// `fatal()`s or `error()`s on these; we collect them so a corrupt database degrades
/// instead of aborting the scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbWarning {
    /// 1-based line number.
    pub line: usize,
    /// What went wrong.
    pub message: String,
}

/// A parsed `nmap-os-db`.
#[derive(Debug, Clone, Default)]
pub struct FingerPrintDb {
    /// The scoring weights, if the file carried a `MatchPoints` block.
    pub match_points: Option<MatchPoints>,
    /// Every fingerprint, in file order.
    pub prints: Vec<FingerPrint>,
    /// Lines that could not be parsed (see [`DbWarning`]).
    pub warnings: Vec<DbWarning>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ids_round_trip_through_their_names() {
        for t in TestId::ALL {
            assert_eq!(TestId::from_name(t.name()), Some(t), "{}", t.name());
        }
        assert_eq!(TestId::from_name("NOPE"), None);
        assert_eq!(TestId::from_name(""), None);
        assert_eq!(TestId::from_name("seq"), None, "names are case-sensitive");
    }

    #[test]
    fn indices_are_dense_and_ordered() {
        for (i, t) in TestId::ALL.iter().enumerate() {
            assert_eq!(t.index(), i);
        }
    }

    #[test]
    fn attribute_tables_match_the_c() {
        assert_eq!(TestId::Seq.attrs().len(), 8);
        assert_eq!(TestId::Ops.attrs(), &["O1", "O2", "O3", "O4", "O5", "O6"]);
        assert_eq!(TestId::U1.attrs().len(), FP_MAX_TEST_ATTRS);
        assert_eq!(TestId::Ie.attrs(), &["R", "DFI", "T", "TG", "CD"]);
        for t in TestId::ALL {
            assert!(t.attrs().len() <= FP_MAX_TEST_ATTRS, "{}", t.name());
        }
    }

    #[test]
    fn has_r_is_exactly_the_tests_whose_first_attr_is_r() {
        // SEQ/OPS/WIN describe sampled values, so they carry no "responded" flag.
        for t in [TestId::Seq, TestId::Ops, TestId::Win] {
            assert!(!t.has_r(), "{}", t.name());
        }
        for t in [TestId::Ecn, TestId::T1, TestId::U1, TestId::Ie] {
            assert!(t.has_r(), "{}", t.name());
        }
    }

    #[test]
    fn attr_lookup_by_name() {
        assert_eq!(TestId::Seq.attr_index("SP"), Some(0));
        assert_eq!(TestId::Seq.attr_index("TS"), Some(7));
        assert_eq!(TestId::Seq.attr_index("W1"), None);
        let mut t = FingerTest::new(TestId::Seq);
        assert_eq!(t.get("SP"), None);
        t.values[0] = Some("0-5".into());
        assert_eq!(t.get("SP"), Some("0-5"));
        assert_eq!(t.get("NOPE"), None);
    }

    #[test]
    fn match_points_default_to_zero_and_round_trip() {
        let mut mp = MatchPoints::default();
        assert_eq!(mp.get(TestId::Seq, 0), 0);
        assert!(mp.set(TestId::Seq, 0, 25));
        assert_eq!(mp.get(TestId::Seq, 0), 25);
        // Out-of-range indices are rejected, never panic.
        assert!(!mp.set(TestId::Ie, 99, 1));
        assert_eq!(mp.get(TestId::Ie, 99), 0);
    }
}
