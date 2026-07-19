//! Service-scan **scheduler** — the pure decision half of `service_scan.cc`'s
//! `ServiceNFO` probe state machine (`currentProbe`/`nextProbe`, the
//! `PROBESTATE_*` walk). Given a probe database, a port, and the
//! `--version-intensity`, it decides *which probe to send next*, consumes the
//! match result of each, and produces the final version verdict — all as a pure,
//! Miri-checkable state machine with **no I/O**. The tokio driver in
//! `nmap-sys::servicescan` performs the connects/sends/reads those decisions call
//! for and feeds the outcomes back (the same pure-core / thin-driver split M2 used
//! for the connect engine).
//!
//! ## The state walk (`nextProbe`)
//!
//! 1. **NULL probe** — for TCP, first grab whatever banner the port volunteers
//!    (the `NULL` probe sends nothing).
//! 2. **Matching-port probes** — probes whose `ports` list includes this port
//!    (`portIsProbable`), in file order. After a soft match, only probes that can
//!    detect the soft-matched service are tried (unless intensity 9 / `--version-all`).
//! 3. **Non-matching-port probes** — the rest, gated by `rarity <= intensity`
//!    (or, after a soft match, by "can detect the soft service").
//! 4. **Finished** — a hard match ends it immediately with full version info; else
//!    the soft-matched service (if any) stands, otherwise "no match".
//!
//! Scope (this slice): the **connect** path — TCP probes only. SSL/STARTTLS
//! tunnels, UDP probes, and the RPC grinder are deferred (see `DIVERGENCES.md`
//! `servicescan-connect-only`); the state machine is structured so they slot in
//! as additional phases without disturbing this core.

use crate::probedb::{MatchRule, Probe, ProbeDb, ProbeProtocol};
use crate::versioninfo::{self, VersionInfo};

/// Default `--version-intensity` (`o.version_intensity`, nmap default 7).
pub const DEFAULT_INTENSITY: u8 = 7;
/// Intensity at which the soft-match service filter is bypassed (`--version-all`).
const INTENSITY_ALL: u8 = 9;

/// Which probe the scheduler wants the driver to send next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeRef {
    /// The NULL probe (send nothing, read the volunteered banner).
    Null,
    /// `ProbeDb::probes[index]`.
    Indexed(usize),
}

/// What the driver's matcher made of the last probe's banner. The driver computes
/// this via `nmap-core::matcher`; the scheduler only needs the *kind*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchKind {
    /// No rule matched the banner.
    NoMatch,
    /// A `softmatch` fired — narrows subsequent probes, but keeps scanning.
    Soft { service: String },
    /// A hard `match` fired — detection is complete.
    Hard,
}

/// Internal phase, mirroring `PROBESTATE_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Initial,
    NullProbe,
    Matching,
    NonMatching,
    Finished,
}

/// How a finished scan resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Resolution {
    /// A hard `match` fired — full version info is available.
    HardMatched,
    /// Only a `softmatch` fired — the service name stands, no version.
    SoftMatched,
    /// Nothing matched.
    #[default]
    NoMatch,
}

/// The per-port probe scheduler.
pub struct Scheduler {
    intensity: u8,
    proto: ProbeProtocol,
    port: u16,
    phase: Phase,
    /// Cursor into `ProbeDb::probes` while in Matching/NonMatching.
    idx: usize,
    /// Service name of the soft match, once one is seen (`softMatchFound`).
    soft_service: Option<String>,
    /// Set once a hard match ends the scan.
    hard: bool,
}

impl Scheduler {
    /// New scheduler for a TCP `port` at `intensity` (`0..=9`; values above 9 are
    /// treated as 9). The NULL probe runs first.
    pub fn new(port: u16, intensity: u8) -> Scheduler {
        Scheduler {
            intensity: intensity.min(INTENSITY_ALL),
            proto: ProbeProtocol::Tcp,
            port,
            phase: Phase::Initial,
            idx: 0,
            soft_service: None,
            hard: false,
        }
    }

    /// The next probe to send, or `None` when the scan is finished. Advances the
    /// state exactly like `ServiceNFO::nextProbe` (dropping down through the phases
    /// in a single call until it finds an applicable probe or finishes).
    pub fn next_probe(&mut self, db: &ProbeDb) -> Option<ProbeRef> {
        if self.hard {
            self.phase = Phase::Finished;
        }
        // `dropdown` = we just entered this phase, so don't pre-increment the cursor.
        let mut dropdown = false;

        if self.phase == Phase::Initial {
            self.phase = Phase::NullProbe;
            // The NULL probe is TCP-only and optional.
            if self.proto == ProbeProtocol::Tcp && db.null_probe.is_some() {
                return Some(ProbeRef::Null);
            }
        }

        if self.phase == Phase::NullProbe {
            self.phase = Phase::Matching;
            dropdown = true;
            self.idx = 0;
        }

        if self.phase == Phase::Matching {
            if !dropdown {
                self.idx = self.idx.saturating_add(1);
            }
            while let Some(probe) = db.probes.get(self.idx) {
                if self.proto == probe.protocol
                    && probe.ports.contains(&self.port)
                    && self.soft_allows(probe)
                {
                    return Some(ProbeRef::Indexed(self.idx));
                }
                self.idx = self.idx.saturating_add(1);
            }
            self.phase = Phase::NonMatching;
            dropdown = true;
            self.idx = 0;
        }

        if self.phase == Phase::NonMatching {
            if !dropdown {
                self.idx = self.idx.saturating_add(1);
            }
            while let Some(probe) = db.probes.get(self.idx) {
                if self.proto == probe.protocol
                    && !probe.ports.contains(&self.port)
                    && self.nonmatch_allows(probe)
                {
                    return Some(ProbeRef::Indexed(self.idx));
                }
                self.idx = self.idx.saturating_add(1);
            }
            self.phase = Phase::Finished;
        }

        None
    }

    /// Feed the match result of the probe just sent. A hard match finishes the
    /// scan; a soft match records the service (narrowing later probes).
    pub fn record(&mut self, kind: MatchKind) {
        match kind {
            MatchKind::Hard => self.hard = true,
            MatchKind::Soft { service } => {
                // C keeps the first soft match's service as `probe_matched`.
                if self.soft_service.is_none() {
                    self.soft_service = Some(service);
                }
            }
            MatchKind::NoMatch => {}
        }
    }

    /// Whether the scan has finished (a hard match, or all probes exhausted).
    pub fn is_finished(&self) -> bool {
        self.phase == Phase::Finished || self.hard
    }

    /// How the scan resolved (only meaningful once [`Self::is_finished`]).
    pub fn resolution(&self) -> Resolution {
        if self.hard {
            Resolution::HardMatched
        } else if self.soft_service.is_some() {
            Resolution::SoftMatched
        } else {
            Resolution::NoMatch
        }
    }

    /// The soft-matched service name, if any.
    pub fn soft_service(&self) -> Option<&str> {
        self.soft_service.as_deref()
    }

    /// MATCHING-phase soft filter: no soft match yet, or intensity 9, or this probe
    /// can detect the soft-matched service.
    fn soft_allows(&self, probe: &Probe) -> bool {
        match &self.soft_service {
            None => true,
            Some(svc) => self.intensity >= INTENSITY_ALL || probe_detects(probe, svc),
        }
    }

    /// NONMATCHING-phase filter: no soft match and `rarity <= intensity`, or a soft
    /// match and (intensity 9 or this probe can detect the soft service).
    fn nonmatch_allows(&self, probe: &Probe) -> bool {
        match &self.soft_service {
            None => probe.rarity <= self.intensity,
            Some(svc) => self.intensity >= INTENSITY_ALL || probe_detects(probe, svc),
        }
    }
}

/// Whether `probe` has a `match`/`softmatch` rule for `service` (`serviceIsPossible`).
fn probe_detects(probe: &Probe, service: &str) -> bool {
    probe.matches.iter().any(|m| m.service == service)
}

/// The final `-sV` verdict for one port — the service name plus, on a hard match,
/// the substituted version fields (byte-faithful, as `versioninfo` produces them).
/// Assembled by the driver from the fired rule and its captures.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionResult {
    /// Detected service name (`http`, `ssh`, …), if any.
    pub service: Option<String>,
    /// How detection resolved.
    pub resolution: Resolution,
    /// The connection closed with no data before `tcpwrappedms` — likely a
    /// tcpwrapper / firewall, not the real service.
    pub tcpwrapped: bool,
    pub product: Option<Vec<u8>>,
    pub version: Option<Vec<u8>>,
    pub info: Option<Vec<u8>>,
    pub hostname: Option<Vec<u8>>,
    pub ostype: Option<Vec<u8>>,
    pub devicetype: Option<Vec<u8>>,
    /// CPE identifiers (`cpe:/a:…`), verbatim.
    pub cpe: Vec<Vec<u8>>,
}

impl VersionResult {
    /// A hard match: pull the version fields from the fired `rule`'s templates via
    /// [`versioninfo::build`] with the match's capture groups.
    pub fn hard(rule: &MatchRule, captures: &[Option<Vec<u8>>]) -> VersionResult {
        let vi: VersionInfo = versioninfo::build(rule, captures);
        let mut cpe = Vec::new();
        cpe.extend(vi.cpe_a);
        cpe.extend(vi.cpe_h);
        cpe.extend(vi.cpe_o);
        VersionResult {
            service: Some(rule.service.clone()),
            resolution: Resolution::HardMatched,
            tcpwrapped: false,
            product: vi.product,
            version: vi.version,
            info: vi.info,
            hostname: vi.hostname,
            ostype: vi.ostype,
            devicetype: vi.devicetype,
            cpe,
        }
    }

    /// A soft match: only the service name is known.
    pub fn soft(service: &str) -> VersionResult {
        VersionResult {
            service: Some(service.to_string()),
            resolution: Resolution::SoftMatched,
            ..VersionResult::default()
        }
    }

    /// A `tcpwrapped` verdict (connection closed with no data quickly).
    pub fn tcpwrapped() -> VersionResult {
        VersionResult {
            service: Some("tcpwrapped".to_string()),
            resolution: Resolution::NoMatch,
            tcpwrapped: true,
            ..VersionResult::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probedb::{MatchRule, Probe};

    fn probe(name: &str, ports: &[u16], rarity: u8, services: &[&str], null: bool) -> Probe {
        Probe {
            protocol: ProbeProtocol::Tcp,
            name: name.into(),
            probestring: if null { vec![] } else { b"x".to_vec() },
            no_payload: false,
            ports: ports.to_vec(),
            sslports: vec![],
            rarity,
            totalwaitms: 5000,
            tcpwrappedms: 2000,
            fallback: vec![],
            matches: services
                .iter()
                .map(|s| MatchRule {
                    service: (*s).into(),
                    pattern: "^x".into(),
                    ..MatchRule::default()
                })
                .collect(),
        }
    }

    fn db_with(null: bool, probes: Vec<Probe>) -> ProbeDb {
        ProbeDb {
            null_probe: null.then(|| probe("NULL", &[], 5, &[], true)),
            probes,
            ..ProbeDb::default()
        }
    }

    #[test]
    fn null_probe_first_then_matching_then_nonmatching() {
        let db = db_with(
            true,
            vec![
                probe("OnPort", &[80], 5, &["http"], false), // matches port 80
                probe("OffPort", &[21], 5, &["ftp"], false), // not port 80, rarity 5<=7
            ],
        );
        let mut s = Scheduler::new(80, DEFAULT_INTENSITY);
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Null));
        s.record(MatchKind::NoMatch);
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Indexed(0))); // matching-port
        s.record(MatchKind::NoMatch);
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Indexed(1))); // non-matching
        s.record(MatchKind::NoMatch);
        assert_eq!(s.next_probe(&db), None);
        assert!(s.is_finished());
        assert_eq!(s.resolution(), Resolution::NoMatch);
    }

    #[test]
    fn hard_match_ends_immediately() {
        let db = db_with(true, vec![probe("P", &[80], 5, &["http"], false)]);
        let mut s = Scheduler::new(80, DEFAULT_INTENSITY);
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Null));
        s.record(MatchKind::Hard); // NULL probe banner hard-matched
        assert_eq!(s.next_probe(&db), None);
        assert!(s.is_finished());
        assert_eq!(s.resolution(), Resolution::HardMatched);
    }

    #[test]
    fn rarity_above_intensity_is_skipped() {
        let db = db_with(
            false,
            vec![
                probe("Rare", &[21], 8, &["ftp"], false), // rarity 8 > intensity 7, off-port
                probe("Common", &[21], 3, &["ftp"], false), // rarity 3 <= 7, off-port
            ],
        );
        let mut s = Scheduler::new(80, DEFAULT_INTENSITY);
        // No NULL probe → straight to matching (none match port 80) → non-matching.
        // Rare (rarity 8) skipped; Common (rarity 3) selected.
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Indexed(1)));
        s.record(MatchKind::NoMatch);
        assert_eq!(s.next_probe(&db), None);
    }

    #[test]
    fn intensity_zero_still_runs_matching_port_probes() {
        // A probe whose ports include this port is tried regardless of rarity in
        // the MATCHING phase (only NONMATCHING obeys rarity<=intensity).
        let db = db_with(false, vec![probe("OnPort", &[80], 9, &["http"], false)]);
        let mut s = Scheduler::new(80, 0);
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Indexed(0)));
    }

    #[test]
    fn soft_match_narrows_nonmatching_to_that_service() {
        let db = db_with(
            true,
            vec![
                probe("A", &[21], 3, &["ftp"], false),  // off-port, detects ftp
                probe("B", &[21], 3, &["smtp"], false), // off-port, detects smtp only
            ],
        );
        let mut s = Scheduler::new(80, DEFAULT_INTENSITY);
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Null));
        s.record(MatchKind::Soft {
            service: "ftp".into(),
        });
        // After a soft match on ftp, only probes that can detect ftp are tried.
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Indexed(0))); // A detects ftp
        s.record(MatchKind::NoMatch);
        assert_eq!(s.next_probe(&db), None); // B (smtp) filtered out
        assert_eq!(s.resolution(), Resolution::SoftMatched);
        assert_eq!(s.soft_service(), Some("ftp"));
    }

    #[test]
    fn intensity_nine_bypasses_soft_filter() {
        let db = db_with(
            true,
            vec![probe("B", &[21], 3, &["smtp"], false)], // off-port, smtp only
        );
        let mut s = Scheduler::new(80, 9);
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Null));
        s.record(MatchKind::Soft {
            service: "ftp".into(),
        });
        // Intensity 9 (--version-all) ignores the soft-service filter.
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Indexed(0)));
    }

    #[test]
    fn no_null_probe_starts_at_matching() {
        let db = db_with(false, vec![probe("P", &[80], 5, &["http"], false)]);
        let mut s = Scheduler::new(80, DEFAULT_INTENSITY);
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Indexed(0)));
    }

    #[test]
    fn empty_db_finishes_at_once() {
        let db = db_with(false, vec![]);
        let mut s = Scheduler::new(80, DEFAULT_INTENSITY);
        assert_eq!(s.next_probe(&db), None);
        assert!(s.is_finished());
        assert_eq!(s.resolution(), Resolution::NoMatch);
    }

    #[test]
    fn matching_port_probe_preferred_over_offport_even_if_later() {
        // File order: off-port first, on-port second. MATCHING must pick the
        // on-port one first (index 1), then NONMATCHING the off-port (index 0).
        let db = db_with(
            false,
            vec![
                probe("Off", &[21], 3, &["ftp"], false),
                probe("On", &[80], 3, &["http"], false),
            ],
        );
        let mut s = Scheduler::new(80, DEFAULT_INTENSITY);
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Indexed(1)));
        s.record(MatchKind::NoMatch);
        assert_eq!(s.next_probe(&db), Some(ProbeRef::Indexed(0)));
    }
}
