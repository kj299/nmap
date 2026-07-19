//! The service-detection match engine — the Rust analog of
//! `ServiceProbeMatch::testMatch` / `ServiceProbe::testMatch` (`service_scan.cc`).
//!
//! Given a probe's `match`/`softmatch` rules ([`crate::probedb`]) and a banner
//! returned by a target, decide which service it is. This is **Milestone 3's
//! highest-risk module**: every byte matched is chosen by whoever runs on the
//! target port, so the banner is the #1 fuzz target.
//!
//! ## The hybrid engine (the M3-1 spike's decision, now built)
//!
//! nmap runs PCRE2 for *all* patterns and has to leash it with a `match_limit`
//! against catastrophic backtracking. This port splits the corpus:
//!
//! * **Linear default — `regex::bytes` (Unicode off).** ~93.6% of the shipped
//!   patterns compile here (after [`crate::pcre_translate`]). This engine is a
//!   finite automaton with a **linear-time guarantee** — ReDoS is *unexpressible*,
//!   strictly safer than the C. It runs directly on the raw banner bytes.
//! * **Bounded-backtracking fallback — `fancy-regex`.** The ~6% needing
//!   lookaround / backreferences / atomic groups compile here, with an explicit
//!   **backtrack-step limit** (the direct analog of nmap's `match_limit`): if a
//!   banner would blow the limit, the match is abandoned as "no match", never a
//!   hang. `fancy-regex` is `&str`-only, so a binary banner is mapped to a string
//!   through a **latin-1 bijection** (`byte b` ⇄ `char U+00b`); every
//!   backtracking pattern in the corpus is ASCII, so this mapping is exact, and
//!   captured groups are mapped back to the original bytes.
//!
//! A rule that compiles in **neither** engine is *dropped with a warning* (the
//! `probedb-parse-degrade` philosophy) rather than aborting — its service simply
//! can't be detected until the break-glass path lands. A rule whose regex can
//! match the **empty string** is also dropped (nmap `fatal()`s on this via
//! `PCRE2_INFO_MATCHEMPTY`; a match-everything rule would mislabel every port).
//!
//! ## Contract
//!
//! Compilation is fallible and localized; matching ([`CompiledProbe::test`]) is
//! **total and bounded** — any banner in, an `Option` out, never a panic, never
//! unbounded work. Version-string substitution (`$1`, `$P()`, …) is the *next*
//! module (`core::versioninfo`); the matcher returns the raw capture groups it
//! will consume.

use crate::pcre_translate::translate;
use crate::probedb::{MatchRule, Probe, ProbeDb};

/// Cap on the compiled size of a single linear pattern (bounds compile-time
/// memory on a hostile `--versiondb`). 10 MiB is far above any real probe.
const LINEAR_SIZE_LIMIT: usize = 10 * 1024 * 1024;

/// Backtrack-step limit for the `fancy-regex` fallback — the analog of nmap's
/// `pcre2_set_match_limit(50000)`, generous but finite so a hostile banner can't
/// hang the scan.
const BACKTRACK_LIMIT: usize = 1_000_000;

/// A compiled regex behind one of the two engines.
enum Engine {
    /// Linear-time finite automaton over raw bytes (the common, safe case).
    Linear(regex::bytes::Regex),
    /// Bounded-backtracking engine over a latin-1 view of the banner.
    Backtrack(fancy_regex::Regex),
}

/// Why a single rule could not be compiled. The rule is skipped, never fatal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileWarning {
    /// The service the dropped rule would have detected.
    pub service: String,
    /// Human-readable reason (both engines rejected it, or it matched empty).
    pub reason: String,
}

/// A successfully compiled `match`/`softmatch` rule: the engine plus the rule's
/// metadata and version templates (carried through for `core::versioninfo`).
pub struct CompiledRule {
    /// The originating rule — service name, `soft` flag, version templates.
    pub rule: MatchRule,
    engine: Engine,
}

impl CompiledRule {
    /// Compile one rule. `Ok` on success; `Err` if neither engine accepts it or
    /// it can match the empty string.
    pub fn compile(rule: &MatchRule) -> Result<CompiledRule, CompileWarning> {
        let translated = translate(&rule.pattern);
        let warn = |reason: String| CompileWarning {
            service: rule.service.clone(),
            reason,
        };

        // 1) Linear engine on raw bytes (Unicode off — banners are bytes).
        let linear = regex::bytes::RegexBuilder::new(&translated)
            .unicode(false)
            .case_insensitive(rule.ignorecase)
            .dot_matches_new_line(rule.dotall)
            .size_limit(LINEAR_SIZE_LIMIT)
            .build();
        if let Ok(re) = linear {
            // Reject empty-matching patterns (nmap's PCRE2_INFO_MATCHEMPTY guard).
            if re.is_match(b"") {
                return Err(warn("pattern matches the empty string".into()));
            }
            return Ok(CompiledRule {
                rule: rule.clone(),
                engine: Engine::Linear(re),
            });
        }

        // 2) Backtracking fallback. Flags are expressed inline (fancy-regex has
        //    no builder flags for these). It is `&str`-only, so the pattern must
        //    be valid as text — which it is (a `&str` already).
        let mut pat = String::new();
        if rule.ignorecase {
            pat.push_str("(?i)");
        }
        if rule.dotall {
            pat.push_str("(?s)");
        }
        pat.push_str(&translated);
        let built = fancy_regex::RegexBuilder::new(&pat)
            .backtrack_limit(BACKTRACK_LIMIT)
            .build();
        match built {
            Ok(re) => {
                // Empty-match guard for the fancy engine too.
                if matches!(re.is_match(""), Ok(true)) {
                    return Err(warn("pattern matches the empty string".into()));
                }
                Ok(CompiledRule {
                    rule: rule.clone(),
                    engine: Engine::Backtrack(re),
                })
            }
            Err(e) => Err(warn(format!("no engine accepts the pattern: {e}"))),
        }
    }

    /// Run this rule against `banner`. Returns the capture groups (group 0 is the
    /// whole match) as raw bytes on a match, else `None`. Bounded: the backtrack
    /// limit turns a pathological banner into `None`, never a hang or panic.
    pub fn captures(&self, banner: &[u8]) -> Option<Vec<Option<Vec<u8>>>> {
        self.captures_with(banner, &mut None)
    }

    /// As [`Self::captures`], but sharing a lazily-built latin-1 view of `banner`
    /// across the rules of one probe. `latin1` is populated on first backtrack
    /// use and reused, so a probe with many backtracking rules decodes the banner
    /// once per match call instead of once per rule.
    fn captures_with(
        &self,
        banner: &[u8],
        latin1: &mut Option<String>,
    ) -> Option<Vec<Option<Vec<u8>>>> {
        match &self.engine {
            Engine::Linear(re) => {
                let caps = re.captures(banner)?;
                Some(
                    (0..caps.len())
                        .map(|i| caps.get(i).map(|m| m.as_bytes().to_vec()))
                        .collect(),
                )
            }
            Engine::Backtrack(re) => {
                let hay = latin1.get_or_insert_with(|| latin1_decode(banner));
                // A backtrack-limit overflow surfaces as Err → treat as no match.
                let caps = match re.captures(hay) {
                    Ok(Some(c)) => c,
                    _ => return None,
                };
                Some(
                    (0..caps.len())
                        .map(|i| {
                            caps.get(i)
                                // Re-encode chars back to their originating bytes.
                                .map(|m| m.as_str().chars().map(|c| c as u8).collect())
                        })
                        .collect(),
                )
            }
        }
    }

    /// Whether this rule matched, ignoring captures (cheaper for `test`). Shares
    /// the same lazily-built latin-1 view as [`Self::captures_with`].
    fn is_match_with(&self, banner: &[u8], latin1: &mut Option<String>) -> bool {
        match &self.engine {
            Engine::Linear(re) => re.is_match(banner),
            Engine::Backtrack(re) => {
                let hay = latin1.get_or_insert_with(|| latin1_decode(banner));
                matches!(re.is_match(hay), Ok(true))
            }
        }
    }
}

/// Latin-1 decode: each banner byte becomes one `char` in `U+0000..=U+00FF`. The
/// inverse (`char as u8`) recovers the original byte, so captures round-trip
/// exactly. Used only for the `&str`-only backtracking engine.
fn latin1_decode(banner: &[u8]) -> String {
    banner.iter().map(|&b| b as char).collect()
}

/// A compiled probe: its rules in file order. Mirrors `ServiceProbe` (match half).
pub struct CompiledProbe {
    /// Probe name (for scheduling / diagnostics).
    pub name: String,
    rules: Vec<CompiledRule>,
}

/// The outcome of matching a banner against a probe: which rule fired.
pub struct MatchOutcome<'a> {
    /// The rule that matched (service name, `soft` flag, version templates).
    pub rule: &'a MatchRule,
    /// The capture groups (group 0 = whole match) as raw bytes.
    pub captures: Vec<Option<Vec<u8>>>,
}

impl<'a> MatchOutcome<'a> {
    /// The detected service name.
    pub fn service(&self) -> &str {
        &self.rule.service
    }
    /// Whether this was a `softmatch` (keep probing) vs a hard `match` (final).
    pub fn is_soft(&self) -> bool {
        self.rule.soft
    }
}

impl CompiledProbe {
    /// Compile a probe's rules, skipping (and reporting) any that neither engine
    /// accepts. Never fails as a whole.
    pub fn compile(probe: &Probe) -> (CompiledProbe, Vec<CompileWarning>) {
        let mut rules = Vec::with_capacity(probe.matches.len());
        let mut warnings = Vec::new();
        for m in &probe.matches {
            match CompiledRule::compile(m) {
                Ok(c) => rules.push(c),
                Err(w) => warnings.push(w),
            }
        }
        (
            CompiledProbe {
                name: probe.name.clone(),
                rules,
            },
            warnings,
        )
    }

    /// Match `banner` against this probe's rules, **first match wins in file
    /// order** (`ServiceProbe::testMatch`). Returns the firing rule + its
    /// captures, or `None` if nothing matched.
    pub fn test(&self, banner: &[u8]) -> Option<MatchOutcome<'_>> {
        // Decode the banner to latin-1 at most once, shared across all
        // backtracking rules of this probe (linear rules never touch it).
        let mut latin1: Option<String> = None;
        for rule in &self.rules {
            if let Some(captures) = rule.captures_with(banner, &mut latin1) {
                return Some(MatchOutcome {
                    rule: &rule.rule,
                    captures,
                });
            }
        }
        None
    }

    /// Whether any rule matches (cheaper than [`Self::test`] — no capture alloc).
    pub fn matches(&self, banner: &[u8]) -> bool {
        let mut latin1: Option<String> = None;
        self.rules
            .iter()
            .any(|r| r.is_match_with(banner, &mut latin1))
    }

    /// Number of rules that compiled.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// A fully compiled probe database: the NULL probe plus all others.
pub struct CompiledDb {
    /// The NULL probe (banner-only detection), if the DB had one.
    pub null_probe: Option<CompiledProbe>,
    /// All non-NULL probes, in file order.
    pub probes: Vec<CompiledProbe>,
    /// Every rule dropped during compilation (both engines rejected / empty).
    pub warnings: Vec<CompileWarning>,
}

impl CompiledDb {
    /// Compile an entire [`ProbeDb`]. Total: rules that don't compile are
    /// collected into [`CompiledDb::warnings`], never fatal.
    pub fn compile(db: &ProbeDb) -> CompiledDb {
        let mut warnings = Vec::new();
        let null_probe = db.null_probe.as_ref().map(|p| {
            let (c, w) = CompiledProbe::compile(p);
            warnings.extend(w);
            c
        });
        let probes = db
            .probes
            .iter()
            .map(|p| {
                let (c, w) = CompiledProbe::compile(p);
                warnings.extend(w);
                c
            })
            .collect();
        CompiledDb {
            null_probe,
            probes,
            warnings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probedb::ProbeProtocol;

    fn rule(pattern: &str, soft: bool) -> MatchRule {
        MatchRule {
            soft,
            service: "svc".into(),
            pattern: pattern.into(),
            ..MatchRule::default()
        }
    }

    #[test]
    fn linear_match_and_captures() {
        let c = CompiledRule::compile(&rule(r"^SSH-([\d.]+)-", false)).unwrap();
        let caps = c.captures(b"SSH-2.0-OpenSSH_9.0").unwrap();
        assert_eq!(caps[0].as_deref(), Some(&b"SSH-2.0-"[..]));
        assert_eq!(caps[1].as_deref(), Some(&b"2.0"[..]));
        assert!(c.captures(b"HTTP/1.1 200 OK").is_none());
    }

    #[test]
    fn binary_banner_bytes() {
        // A NUL-containing pattern against a NUL-containing banner (linear).
        let c = CompiledRule::compile(&rule(r"^\x04\0\xfbLAPK", false)).unwrap();
        assert!(c.captures(b"\x04\x00\xfbLAPK...").is_some());
        assert!(c.captures(b"\x04\x00\xfeLAPK").is_none());
    }

    #[test]
    fn case_insensitive_flag() {
        let mut r = rule(r"^http", false);
        r.ignorecase = true;
        let c = CompiledRule::compile(&r).unwrap();
        assert!(c.captures(b"HTTP/1.1").is_some());
    }

    #[test]
    fn dotall_flag() {
        let mut r = rule(r"^a.b", false);
        r.dotall = true;
        let c = CompiledRule::compile(&r).unwrap();
        assert!(c.captures(b"a\nb").is_some());
    }

    #[test]
    fn backtracking_pattern_uses_fancy_engine() {
        // Backreference forces the fancy engine; verify it matches on bytes.
        let c = CompiledRule::compile(&rule(r"^(.)\1", false)).unwrap();
        assert!(matches!(c.engine, Engine::Backtrack(_)));
        assert!(c.captures(b"aabc").is_some());
        assert!(c.captures(b"abc").is_none());
    }

    #[test]
    fn fancy_engine_binary_capture_roundtrip() {
        // A lookahead (fancy) with a high-byte capture — verify bytes survive the
        // latin-1 round-trip.
        let c = CompiledRule::compile(&rule(r"^(?=\xff)(\xff\xfe)", false)).unwrap();
        assert!(matches!(c.engine, Engine::Backtrack(_)));
        let caps = c.captures(b"\xff\xferest").unwrap();
        assert_eq!(caps[1].as_deref(), Some(&b"\xff\xfe"[..]));
    }

    #[test]
    fn empty_matching_pattern_rejected() {
        // `a*` matches "" → dropped (would mislabel every port).
        let e = match CompiledRule::compile(&rule(r"a*", false)) {
            Err(e) => e,
            Ok(_) => panic!("expected empty-match rejection"),
        };
        assert!(e.reason.contains("empty"));
    }

    #[test]
    fn probe_first_match_wins() {
        let probe = Probe {
            protocol: ProbeProtocol::Tcp,
            name: "P".into(),
            probestring: b"x".to_vec(),
            no_payload: false,
            ports: vec![],
            sslports: vec![],
            rarity: 5,
            totalwaitms: 5000,
            tcpwrappedms: 2000,
            fallback: vec![],
            matches: vec![
                {
                    let mut m = rule(r"^HTTP", false);
                    m.service = "http".into();
                    m
                },
                {
                    let mut m = rule(r"^HTTP/1", false);
                    m.service = "http1".into();
                    m
                },
            ],
        };
        let (c, w) = CompiledProbe::compile(&probe);
        assert!(w.is_empty());
        let out = c.test(b"HTTP/1.1 200 OK").unwrap();
        // First rule in file order wins, even though both match.
        assert_eq!(out.service(), "http");
        assert!(!out.is_soft());
    }

    #[test]
    fn soft_flag_surfaced() {
        let probe = Probe {
            protocol: ProbeProtocol::Tcp,
            name: "P".into(),
            probestring: b"x".to_vec(),
            no_payload: false,
            ports: vec![],
            sslports: vec![],
            rarity: 5,
            totalwaitms: 5000,
            tcpwrappedms: 2000,
            fallback: vec![],
            matches: vec![{
                let mut m = rule(r"^220 ", true);
                m.service = "ftp".into();
                m
            }],
        };
        let (c, _) = CompiledProbe::compile(&probe);
        let out = c.test(b"220 Welcome").unwrap();
        assert!(out.is_soft());
        assert_eq!(out.service(), "ftp");
    }

    #[test]
    fn no_match_returns_none() {
        let probe = Probe {
            protocol: ProbeProtocol::Tcp,
            name: "P".into(),
            probestring: b"x".to_vec(),
            no_payload: false,
            ports: vec![],
            sslports: vec![],
            rarity: 5,
            totalwaitms: 5000,
            tcpwrappedms: 2000,
            fallback: vec![],
            matches: vec![rule(r"^SSH-", false)],
        };
        let (c, _) = CompiledProbe::compile(&probe);
        assert!(c.test(b"nope").is_none());
    }

    #[test]
    fn matcher_is_total_on_arbitrary_banners() {
        let c = CompiledRule::compile(&rule(r"^A.*Z", false)).unwrap();
        for banner in [
            &b""[..],
            &b"\x00\x00\x00"[..],
            &b"\xff\xfe\xfd"[..],
            &[0u8; 4096][..],
        ] {
            let _ = c.captures(banner); // never panics
        }
    }
}
