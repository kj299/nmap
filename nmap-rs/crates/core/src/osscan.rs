//! OS-detection scan policy and reporting — the pure half of `os_scan_ipv4` plus
//! `printosscanoutput`.
//!
//! [`crate::osprobe`] turns replies into a fingerprint and [`crate::osdb::score`] matches
//! it against the database. What is left is the *policy* wrapped around those two, and it
//! is entirely a function of its inputs — no socket touches any of it:
//!
//! * **when a host is done** — a round that produced a perfect match completes the host;
//!   otherwise nmap retries, and the best fingerprint *across all rounds* is reported
//!   ([`best_round`], porting `findBestFPs`);
//! * **how far away the host is** — [`attribute_distance`], porting the priority ladder in
//!   `endRound`, which prefers facts we already know over anything the target told us;
//! * **whether the fingerprint is fit to submit** — [`submission_reason`], porting
//!   `OmitSubmissionFP`;
//! * **what gets printed** — [`render`], porting `printosscanoutput`'s plain-text output.

use crate::ipid::IpidSequence;
use crate::model::{Port, PortState, Protocol};
use crate::osdb::model::FingerPrint;
use crate::osdb::score::{MatchResults, ScanOutcome};

/// Perfect matches above this count are too many to name individually; the C prints a
/// "too many fingerprints match" line instead (unless debugging).
pub const MAX_NAMED_PERFECT_MATCHES: usize = 8;
/// Guesses are listed only while they stay within this much of the best accuracy.
pub const GUESS_ACCURACY_WINDOW: f64 = 0.10;
/// At most this many matches are listed when there is no perfect one.
pub const MAX_LISTED_GUESSES: usize = 10;
/// Beyond this many hops the fingerprint is not worth submitting.
pub const MAX_SUBMITTABLE_DISTANCE: u8 = 5;

/// The ports the probe battery needs, and how each was chosen.
///
/// Ports the selection at the top of `HostOsScan::initScanStats`. `ECN`/`T1`–`T4` need an
/// open TCP port, `T5`–`T7` a closed one, and `U1` a closed UDP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProbePorts {
    /// A port found open. Without one the `SEQ`/`OPS`/`WIN`/`ECN`/`T1`–`T4` probes cannot
    /// be sent at all.
    pub open_tcp: Option<u16>,
    /// A port believed closed, for `T5`–`T7`.
    pub closed_tcp: Option<u16>,
    /// A UDP port believed closed, for `U1`.
    pub closed_udp: Option<u16>,
    /// Whether `closed_tcp` was guessed rather than observed.
    pub closed_tcp_guessed: bool,
    /// Whether `closed_udp` was guessed rather than observed.
    pub closed_udp_guessed: bool,
}

/// The C's last-resort closed-port guess: `(get_random_uint() % 14781) + 30000`.
/// Taken as a parameter so selection stays a pure function of its inputs.
#[must_use]
pub fn guessed_closed_port(random: u32) -> u16 {
    // 30000..=44780. `%` and `+` cannot overflow a u16 for this range.
    let offset = random % 14781;
    u16::try_from(offset.saturating_add(30000)).unwrap_or(30000)
}

/// Choose the probe ports from a completed scan's results.
///
/// Follows the C's preference order exactly, including two quirks worth naming:
///
/// * **Port 0 is avoided when an alternative exists.** The C explicitly retries when its
///   first pick is port 0, because a probe to port 0 is not a normal conversation and
///   several stacks answer it differently — which would be recorded as the *stack's*
///   behaviour rather than an artefact of our choice.
/// * **A closed port is invented if none was seen.** With no closed port observed the C
///   picks a random high one and assumes it is closed. That assumption can be wrong, and
///   the resulting `T5`–`T7`/`U1` evidence is then meaningless — so the choice is recorded
///   in `closed_tcp_guessed`/`closed_udp_guessed` rather than being silently indistinguishable
///   from an observed one. The C keeps no such flag.
#[must_use]
pub fn select_probe_ports(ports: &[Port], random: u32) -> ProbePorts {
    // First matching port, preferring a non-zero one — the C's "if it is zero, try another".
    let pick = |proto: Protocol, state: PortState| -> Option<u16> {
        let mut first = None;
        for p in ports
            .iter()
            .filter(|p| p.protocol == proto && p.state == state)
        {
            if p.number != 0 {
                return Some(p.number);
            }
            first.get_or_insert(p.number);
        }
        first
    };

    let open_tcp = pick(Protocol::Tcp, PortState::Open);

    let (closed_tcp, closed_tcp_guessed) = match pick(Protocol::Tcp, PortState::Closed)
        .or_else(|| pick(Protocol::Tcp, PortState::Unfiltered))
    {
        Some(p) => (Some(p), false),
        None => (Some(guessed_closed_port(random)), true),
    };

    let (closed_udp, closed_udp_guessed) = match pick(Protocol::Udp, PortState::Closed)
        .or_else(|| pick(Protocol::Udp, PortState::Unfiltered))
    {
        Some(p) => (Some(p), false),
        None => (Some(guessed_closed_port(random)), true),
    };

    ProbePorts {
        open_tcp,
        closed_tcp,
        closed_udp,
        closed_tcp_guessed,
        closed_udp_guessed,
    }
}

/// How the hop count to a host was arrived at. Ports the C's `dist_calc_method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistanceMethod {
    /// The host is this machine: zero hops, by definition.
    Localhost,
    /// We have the host's MAC address, so it is on our own segment: one hop.
    Direct,
    /// Derived from the TTL the target quoted back in the `U1` ICMP error.
    IcmpQuote,
    /// Nothing established it.
    None,
}

/// Facts about a host that the distance ladder consults before trusting the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostFacts {
    /// Whether the target address is this machine.
    pub is_localhost: bool,
    /// Whether we learned the host's MAC address (same broadcast domain).
    pub has_mac_address: bool,
}

/// Hop count plus how it was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Distance {
    /// Hops, or `None` when unknown.
    pub hops: Option<u8>,
    /// Which rule produced it.
    pub method: DistanceMethod,
}

/// Decide how far away a host is, porting the ladder at the end of `endRound`.
///
/// The order matters and is not arbitrary: `measured` comes from the TTL a **hostile
/// target chose to quote back**, so it is consulted only after the two facts we
/// established ourselves. A directly-connected host therefore reports one hop no matter
/// what the target claims in its `U1` quote.
#[must_use]
pub fn attribute_distance(facts: HostFacts, measured: Option<u8>) -> Distance {
    if facts.is_localhost {
        Distance {
            hops: Some(0),
            method: DistanceMethod::Localhost,
        }
    } else if facts.has_mac_address {
        Distance {
            hops: Some(1),
            method: DistanceMethod::Direct,
        }
    } else if let Some(hops) = measured {
        Distance {
            hops: Some(hops),
            method: DistanceMethod::IcmpQuote,
        }
    } else {
        Distance {
            hops: None,
            method: DistanceMethod::None,
        }
    }
}

/// One retry round's result: the fingerprint observed and how it scored.
#[derive(Debug, Clone)]
pub struct Round {
    /// The fingerprint assembled from this round's replies.
    pub fingerprint: FingerPrint,
    /// How it scored against the reference database.
    pub matches: MatchResults,
}

impl Round {
    /// Whether this round identified the host outright, which ends the retry loop.
    #[must_use]
    pub fn is_conclusive(&self) -> bool {
        self.matches.outcome == Some(ScanOutcome::Success) && self.matches.num_perfect_matches > 0
    }
}

/// Pick the round whose fingerprint to report, porting `findBestFPs`.
///
/// nmap retries OS detection several times; each round produces its own fingerprint,
/// because replies that were dropped in one round may arrive in the next. The round with
/// the highest top accuracy wins, and the search stops early at the first round that
/// matched perfectly.
///
/// Returns `None` only when there were no rounds at all — a run where every round scored
/// nothing still reports its first round, which is what carries the fingerprint the user
/// is asked to submit.
#[must_use]
pub fn best_round(rounds: &[Round]) -> Option<usize> {
    if rounds.is_empty() {
        return None;
    }
    let mut best_index = 0;
    let mut best_accuracy = 0.0f64;
    for (i, round) in rounds.iter().enumerate() {
        let usable = round.matches.outcome == Some(ScanOutcome::Success)
            && !round.matches.matches.is_empty();
        if !usable {
            continue;
        }
        let accuracy = round.matches.matches.first().map_or(0.0, |m| m.accuracy);
        if accuracy > best_accuracy {
            best_accuracy = accuracy;
            best_index = i;
            if round.matches.num_perfect_matches > 0 {
                break;
            }
        }
    }
    Some(best_index)
}

/// Conditions under which the observed fingerprint is not worth submitting.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct SubmissionInputs {
    /// `--scan-delay` in milliseconds; large delays distort the `SEQ` timing analysis.
    pub scan_delay_ms: u64,
    /// `-T` level; 5 (Insane) is too aggressive for a trustworthy fingerprint.
    pub timing_level: u8,
    /// Whether an open TCP port was found.
    pub have_open_tcp_port: bool,
    /// Whether a closed TCP port was found.
    pub have_closed_tcp_port: bool,
    /// Whether a closed UDP port was found (the `U1` probe's target).
    pub have_closed_udp_port: bool,
    /// Whether a UDP scan was requested at all.
    pub udp_scan_requested: bool,
    /// Hop count, if known.
    pub distance: Option<u8>,
    /// Worst observed ratio of actual to expected probe timing.
    pub max_timing_ratio: f64,
    /// Whether any probe failed to send.
    pub incomplete: bool,
}

/// Why this fingerprint should not be submitted, or `None` if it is fit to submit.
///
/// Ports `OmitSubmissionFP`. Every condition is a reason the *observation* is untrustworthy
/// rather than a reason the host is uninteresting: submitting a fingerprint taken under
/// bad conditions would poison the shared database for everyone.
///
/// The C's `distance < -1` branch ("host distance appears to be negative") has no
/// counterpart here: our hop count is an unsigned `Option<u8>`, so the state that branch
/// detects — a target quoting back a TTL higher than the one we sent — is unrepresentable.
/// It is rejected at the source in `osprobe::icmpreply` instead (`u1-distance-never-negative`).
#[must_use]
pub fn submission_reason(i: &SubmissionInputs) -> Option<String> {
    if i.scan_delay_ms > 500 {
        return Some(format!(
            "Scan delay ({}) is greater than 500",
            i.scan_delay_ms
        ));
    }
    if i.timing_level > 4 {
        return Some("Timing level 5 (Insane) used".to_owned());
    }
    if !i.have_open_tcp_port {
        return Some("Missing an open TCP port so results incomplete".to_owned());
    }
    if !i.have_closed_tcp_port {
        return Some("Missing a closed TCP port so results incomplete".to_owned());
    }
    if let Some(d) = i.distance {
        if d > MAX_SUBMITTABLE_DISTANCE {
            return Some(format!(
                "Host distance ({d} network hops) is greater than five"
            ));
        }
    }
    if i.max_timing_ratio > 1.4 {
        return Some(format!(
            "maxTimingRatio ({:e}) is greater than 1.4",
            i.max_timing_ratio
        ));
    }
    // A missing `U1` response only counts against us if we actually looked for a closed
    // UDP port; otherwise the silence says nothing about the stack.
    if !i.have_closed_udp_port && !i.udp_scan_requested {
        return Some("Didn't receive UDP response. Please try again with -sSU".to_owned());
    }
    if i.incomplete {
        return Some("Some probes failed to send so results incomplete".to_owned());
    }
    None
}

/// How hard the host's ISN sequence is to predict, porting `seqidx2difficultystr`.
#[must_use]
pub fn difficulty_str(index: u32) -> &'static str {
    match index {
        0..=2 => "Trivial joke",
        3..=5 => "Easy",
        6..=10 => "Medium",
        11 => "Formidable",
        12..=15 => "Worthy challenge",
        _ => "Good luck!",
    }
}

/// Human-readable IP-ID sequence class, porting `ipidclass2ascii`.
#[must_use]
pub fn ipid_class_str(class: IpidSequence) -> &'static str {
    match class {
        IpidSequence::Constant => "Duplicated ipid (!)",
        IpidSequence::Incr => "Incremental",
        IpidSequence::IncrBy2 => "Incrementing by 2",
        IpidSequence::BrokenIncr => "Broken little-endian incremental",
        IpidSequence::Rd => "Randomized",
        IpidSequence::Rpi => "Random positive increments",
        IpidSequence::Zero => "All zeros",
        IpidSequence::Unknown => "Busy server or unknown class",
    }
}

/// A comma-separated list of uppercase hex values.
///
/// ## Divergence — `osscan-output-no-fatal-on-long-list`
///
/// The C formats these into a fixed 512-byte buffer and calls
/// **`fatal("STRANGE ERROR #3877")`** — aborting the entire scan, losing every result for
/// every host — if the list would overflow. Three separate call sites do this (sequence
/// numbers, IP IDs, timestamps). Growing a `String` cannot overflow, so the abort has no
/// counterpart here.
fn hex_list<T: std::fmt::UpperHex>(values: &[T]) -> String {
    values
        .iter()
        .map(|v| format!("{v:X}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// The sequence-prediction facts `-O` reports alongside the OS guess.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeqReport {
    /// ISNs observed, in probe order.
    pub seqs: Vec<u32>,
    /// IP IDs observed.
    pub ipids: Vec<u16>,
    /// TCP timestamps observed.
    pub timestamps: Vec<u32>,
    /// ISN predictability index.
    pub index: u32,
    /// How the IP-ID counter behaves.
    pub ipid_class: IpidSequence,
}

/// Everything [`render`] needs to produce the `-O` block.
#[derive(Debug, Clone)]
pub struct Report<'a> {
    /// The chosen round's match results.
    pub matches: &'a MatchResults,
    /// The chosen round's fingerprint, printed when it is fit to submit.
    pub fingerprint: &'a FingerPrint,
    /// Why the fingerprint should not be submitted, if so.
    pub submission_reason: Option<&'a str>,
    /// Hop count and how it was found.
    pub distance: Distance,
    /// Sequence-prediction facts.
    pub seq: &'a SeqReport,
    /// Open TCP port used, if any.
    pub open_tcp_port: Option<u16>,
    /// Closed TCP port used, if any.
    pub closed_tcp_port: Option<u16>,
    /// Whether `--osscan-guess` was given.
    pub osscan_guess: bool,
    /// Whether we had both an open and a closed port (results are unreliable without).
    pub reliable: bool,
    /// Whether verbose output was requested.
    pub verbose: bool,
    /// Whether to print the raw observed fingerprint regardless of the verdict (`-d`, or
    /// `-vv`). The C gates every `write_merged_fpr` call on
    /// `suggest_submission || o.debugging || o.verbose > 1`, **including the perfect-match
    /// branch** — an operator asking to see the observation is making a different request
    /// from being invited to submit it, and that holds whether or not the host was
    /// identified.
    pub always_show_fingerprint: bool,
}

/// Render the plain-text `-O` block, porting `printosscanoutput`.
///
/// Only the human-readable stream is produced here; XML and grepable output are rendered
/// by [`crate::output`] from the same data.
#[must_use]
pub fn render(r: &Report) -> String {
    let mut out = String::new();

    if !r.reliable {
        out.push_str(
            "Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port\n",
        );
    }

    let perfect = r.matches.num_perfect_matches;
    let too_many = r.matches.outcome == Some(ScanOutcome::TooManyMatches)
        || perfect > MAX_NAMED_PERFECT_MATCHES;

    if too_many {
        out.push_str("Too many fingerprints match this host to give specific OS details\n");
        if r.always_show_fingerprint {
            out.push_str(&r.fingerprint.render_tests());
        }
    } else if r.matches.outcome == Some(ScanOutcome::Success) && perfect > 0 {
        // Perfect matches: name them all on one line.
        let names: Vec<&str> = r
            .matches
            .matches
            .iter()
            .take(perfect)
            .map(|m| m.os_name.as_str())
            .collect();
        out.push_str("OS details: ");
        out.push_str(&names.join(", "));
        out.push('\n');
        // A perfect match is not a submission request, but `-d`/`-vv` still shows the
        // observation the match was made from.
        if r.always_show_fingerprint {
            out.push_str(&r.fingerprint.render_tests());
        }
    } else if r.matches.outcome == Some(ScanOutcome::Success) {
        // Matches, but none perfect. Guesses are printed only when asked for, or when the
        // fingerprint is not submittable anyway — in which case a guess is more useful to
        // the user than a submission request.
        let listed = listed_guesses(r.matches);
        if (r.osscan_guess || r.submission_reason.is_some()) && !listed.is_empty() {
            let rendered: Vec<String> = listed
                .iter()
                .map(|m| format!("{} ({:.0}%)", m.os_name, (m.accuracy * 100.0).floor()))
                .collect();
            out.push_str("Aggressive OS guesses: ");
            out.push_str(&rendered.join(", "));
            out.push('\n');
        }
        match r.submission_reason {
            None => {
                out.push_str("No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).\n");
                out.push_str(&r.fingerprint.render_tests());
            }
            Some(reason) => {
                if r.verbose {
                    out.push_str(&format!("OS fingerprint not ideal because: {reason}\n"));
                }
                out.push_str("No exact OS matches for host (test conditions non-ideal).\n");
                if r.always_show_fingerprint {
                    out.push_str(&r.fingerprint.render_tests());
                }
            }
        }
    } else {
        match r.submission_reason {
            None => {
                out.push_str("No OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).\n");
                out.push_str(&r.fingerprint.render_tests());
            }
            Some(reason) => {
                out.push_str(&format!("OS fingerprint not ideal because: {reason}\n"));
                out.push_str("No OS matches for host\n");
                if r.always_show_fingerprint {
                    out.push_str(&r.fingerprint.render_tests());
                }
            }
        }
    }

    if let Some(hops) = r.distance.hops {
        let plural = if hops == 1 { "" } else { "s" };
        out.push_str(&format!("Network Distance: {hops} hop{plural}\n"));
    }

    if r.verbose && r.seq.seqs.len() > 3 {
        out.push_str(&format!(
            "TCP Sequence Prediction: Difficulty={} ({})\n",
            r.seq.index,
            difficulty_str(r.seq.index)
        ));
    }
    if r.verbose && r.seq.ipids.len() > 2 {
        out.push_str(&format!(
            "IP ID Sequence Generation: {}\n",
            ipid_class_str(r.seq.ipid_class)
        ));
    }

    out
}

/// The matches worth listing as guesses: capped, and only those close enough to the best.
#[must_use]
pub fn listed_guesses(matches: &MatchResults) -> Vec<&crate::osdb::score::OsMatch> {
    let Some(best) = matches.matches.first() else {
        return Vec::new();
    };
    let floor = best.accuracy - GUESS_ACCURACY_WINDOW;
    matches
        .matches
        .iter()
        .take(MAX_LISTED_GUESSES)
        .take_while(|m| m.accuracy > floor)
        .collect()
}

/// The comma-separated hex lists `-O` reports for the sequence samples.
#[must_use]
pub fn seq_value_lists(seq: &SeqReport) -> (String, String, String) {
    (
        hex_list(&seq.seqs),
        hex_list(&seq.ipids),
        hex_list(&seq.timestamps),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osdb::score::OsMatch;

    fn os_match(name: &str, accuracy: f64) -> OsMatch {
        OsMatch {
            os_name: name.to_owned(),
            accuracy,
            index: 0,
        }
    }

    fn results(outcome: ScanOutcome, perfect: usize, matches: Vec<OsMatch>) -> MatchResults {
        MatchResults {
            matches,
            num_perfect_matches: perfect,
            outcome: Some(outcome),
        }
    }

    fn port(number: u16, protocol: Protocol, state: PortState) -> Port {
        Port::new(number, protocol, state, crate::model::Reason::Reset)
    }

    #[test]
    fn probe_ports_follow_the_c_preference_order() {
        let ports = vec![
            port(1, Protocol::Tcp, PortState::Closed),
            port(22, Protocol::Tcp, PortState::Open),
            port(80, Protocol::Tcp, PortState::Open),
            port(53, Protocol::Udp, PortState::Closed),
        ];
        let p = select_probe_ports(&ports, 0);
        assert_eq!(p.open_tcp, Some(22), "the first open port wins");
        assert_eq!(p.closed_tcp, Some(1));
        assert_eq!(p.closed_udp, Some(53));
        assert!(!p.closed_tcp_guessed && !p.closed_udp_guessed);
    }

    #[test]
    fn port_zero_is_avoided_when_an_alternative_exists() {
        // Port 0 is not a normal conversation and stacks answer it inconsistently, so
        // choosing it would record our own artefact as the target's behaviour.
        let ports = vec![
            port(0, Protocol::Tcp, PortState::Open),
            port(443, Protocol::Tcp, PortState::Open),
            port(0, Protocol::Tcp, PortState::Closed),
            port(1, Protocol::Tcp, PortState::Closed),
        ];
        let p = select_probe_ports(&ports, 0);
        assert_eq!(p.open_tcp, Some(443));
        assert_eq!(p.closed_tcp, Some(1));

        // But if port 0 is genuinely the only one, it is still used rather than guessing.
        let only_zero = vec![port(0, Protocol::Tcp, PortState::Open)];
        assert_eq!(select_probe_ports(&only_zero, 0).open_tcp, Some(0));
    }

    #[test]
    fn unfiltered_is_accepted_before_guessing() {
        let ports = vec![port(4444, Protocol::Tcp, PortState::Unfiltered)];
        let p = select_probe_ports(&ports, 0);
        assert_eq!(p.closed_tcp, Some(4444));
        assert!(!p.closed_tcp_guessed, "an observed port is not a guess");
    }

    #[test]
    fn a_guessed_closed_port_is_flagged_as_such() {
        // With nothing observed the C invents a port and assumes it closed. That
        // assumption can be wrong, making the T5-T7/U1 evidence meaningless — so it is
        // recorded rather than left indistinguishable from an observed port.
        let p = select_probe_ports(&[], 0);
        assert!(p.closed_tcp_guessed && p.closed_udp_guessed);
        assert!(p.open_tcp.is_none(), "an open port is never invented");
        // The guess stays inside the C's range for every input.
        for r in [0u32, 1, 14780, 14781, u32::MAX] {
            let g = guessed_closed_port(r);
            assert!((30000..=44780).contains(&g), "{r} produced {g}");
        }
    }

    #[test]
    fn distance_prefers_what_we_know_over_what_the_target_claims() {
        // A hostile target quoting an absurd TTL cannot override either local fact.
        let lying = Some(200);
        assert_eq!(
            attribute_distance(
                HostFacts {
                    is_localhost: true,
                    has_mac_address: false
                },
                lying
            ),
            Distance {
                hops: Some(0),
                method: DistanceMethod::Localhost
            }
        );
        assert_eq!(
            attribute_distance(
                HostFacts {
                    is_localhost: false,
                    has_mac_address: true
                },
                lying
            ),
            Distance {
                hops: Some(1),
                method: DistanceMethod::Direct
            }
        );
        // With no local fact, the measured value is used.
        assert_eq!(
            attribute_distance(HostFacts::default(), Some(4)),
            Distance {
                hops: Some(4),
                method: DistanceMethod::IcmpQuote
            }
        );
        // And nothing at all stays unknown rather than defaulting to a number.
        assert_eq!(
            attribute_distance(HostFacts::default(), None),
            Distance {
                hops: None,
                method: DistanceMethod::None
            }
        );
    }

    #[test]
    fn best_round_takes_the_highest_and_stops_at_a_perfect_match() {
        let round = |outcome, perfect, acc: f64| Round {
            fingerprint: FingerPrint::default(),
            matches: results(outcome, perfect, vec![os_match("x", acc)]),
        };

        // Highest accuracy wins.
        let rounds = vec![
            round(ScanOutcome::Success, 0, 0.70),
            round(ScanOutcome::Success, 0, 0.92),
            round(ScanOutcome::Success, 0, 0.81),
        ];
        assert_eq!(best_round(&rounds), Some(1));

        // A perfect match short-circuits: later rounds are not consulted.
        let rounds = vec![
            round(ScanOutcome::Success, 0, 0.70),
            round(ScanOutcome::Success, 1, 0.95),
            round(ScanOutcome::Success, 0, 0.99),
        ];
        assert_eq!(best_round(&rounds), Some(1));

        // Rounds that did not succeed are skipped, but a run where nothing scored still
        // reports its first round — that is the fingerprint the user is asked to submit.
        let rounds = vec![
            round(ScanOutcome::NoMatches, 0, 0.0),
            round(ScanOutcome::NoMatches, 0, 0.0),
        ];
        assert_eq!(best_round(&rounds), Some(0));
        assert_eq!(best_round(&[]), None);
    }

    #[test]
    fn a_conclusive_round_needs_both_success_and_a_perfect_match() {
        let make = |outcome, perfect| Round {
            fingerprint: FingerPrint::default(),
            matches: results(outcome, perfect, vec![os_match("x", 1.0)]),
        };
        assert!(make(ScanOutcome::Success, 1).is_conclusive());
        assert!(!make(ScanOutcome::Success, 0).is_conclusive());
        assert!(!make(ScanOutcome::TooManyMatches, 5).is_conclusive());
        assert!(!make(ScanOutcome::NoMatches, 0).is_conclusive());
    }

    #[test]
    fn submission_is_refused_for_each_untrustworthy_condition() {
        // A fingerprint taken under good conditions is submittable.
        let good = SubmissionInputs {
            scan_delay_ms: 0,
            timing_level: 3,
            have_open_tcp_port: true,
            have_closed_tcp_port: true,
            have_closed_udp_port: true,
            udp_scan_requested: false,
            distance: Some(3),
            max_timing_ratio: 1.0,
            incomplete: false,
        };
        assert_eq!(submission_reason(&good), None);

        let refused = |f: fn(&mut SubmissionInputs)| {
            let mut i = good;
            f(&mut i);
            submission_reason(&i).expect("should have been refused")
        };
        assert!(refused(|i| i.scan_delay_ms = 501).contains("Scan delay"));
        assert!(refused(|i| i.timing_level = 5).contains("Insane"));
        assert!(refused(|i| i.have_open_tcp_port = false).contains("open TCP port"));
        assert!(refused(|i| i.have_closed_tcp_port = false).contains("closed TCP port"));
        assert!(refused(|i| i.distance = Some(6)).contains("greater than five"));
        assert!(refused(|i| i.max_timing_ratio = 1.5).contains("maxTimingRatio"));
        assert!(refused(|i| i.incomplete = true).contains("failed to send"));

        // A missing U1 response only counts against us when we actually looked.
        let mut i = good;
        i.have_closed_udp_port = false;
        assert!(submission_reason(&i)
            .expect("refused")
            .contains("Didn't receive UDP response"));
        i.udp_scan_requested = true;
        assert_eq!(submission_reason(&i), None);

        // Exactly five hops is still submittable; the C's bound is `> 5`.
        let mut i = good;
        i.distance = Some(MAX_SUBMITTABLE_DISTANCE);
        assert_eq!(submission_reason(&i), None);
    }

    #[test]
    fn difficulty_and_ipid_strings_match_the_c_boundaries() {
        assert_eq!(difficulty_str(0), "Trivial joke");
        assert_eq!(difficulty_str(2), "Trivial joke");
        assert_eq!(difficulty_str(3), "Easy");
        assert_eq!(difficulty_str(5), "Easy");
        assert_eq!(difficulty_str(6), "Medium");
        assert_eq!(difficulty_str(10), "Medium");
        assert_eq!(difficulty_str(11), "Formidable");
        assert_eq!(difficulty_str(12), "Worthy challenge");
        assert_eq!(difficulty_str(15), "Worthy challenge");
        assert_eq!(difficulty_str(16), "Good luck!");
        assert_eq!(difficulty_str(u32::MAX), "Good luck!");

        assert_eq!(ipid_class_str(IpidSequence::Incr), "Incremental");
        assert_eq!(ipid_class_str(IpidSequence::Zero), "All zeros");
        assert_eq!(
            ipid_class_str(IpidSequence::Constant),
            "Duplicated ipid (!)"
        );
    }

    #[test]
    fn hex_lists_grow_instead_of_aborting_the_scan() {
        assert_eq!(hex_list::<u32>(&[]), "");
        assert_eq!(hex_list(&[0x1au32, 0xff, 0]), "1A,FF,0");
        // The C aborts the entire scan past 512 bytes; this simply produces a long string.
        let many: Vec<u32> = (0..500).map(|i| 0xdead_0000 + i).collect();
        let rendered = hex_list(&many);
        assert!(rendered.len() > 512);
        assert_eq!(rendered.matches(',').count(), 499);
    }

    #[test]
    fn guesses_are_capped_and_windowed() {
        let matches = results(
            ScanOutcome::Success,
            0,
            vec![
                os_match("a", 0.95),
                os_match("b", 0.90),
                os_match("c", 0.86),
                os_match("d", 0.84), // outside the 0.10 window
                os_match("e", 0.80),
            ],
        );
        let listed = listed_guesses(&matches);
        assert_eq!(
            listed
                .iter()
                .map(|m| m.os_name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b", "c"],
            "the window must cut off at best - 0.10"
        );

        // The cap applies even when every entry is within the window.
        let many = results(
            ScanOutcome::Success,
            0,
            (0..20).map(|i| os_match(&format!("os{i}"), 0.99)).collect(),
        );
        assert_eq!(listed_guesses(&many).len(), MAX_LISTED_GUESSES);
        assert!(listed_guesses(&results(ScanOutcome::NoMatches, 0, vec![])).is_empty());
    }

    fn report_for<'a>(
        matches: &'a MatchResults,
        fp: &'a FingerPrint,
        seq: &'a SeqReport,
        reason: Option<&'a str>,
    ) -> Report<'a> {
        Report {
            matches,
            fingerprint: fp,
            submission_reason: reason,
            distance: Distance {
                hops: Some(3),
                method: DistanceMethod::IcmpQuote,
            },
            seq,
            open_tcp_port: Some(22),
            closed_tcp_port: Some(1),
            osscan_guess: false,
            reliable: true,
            verbose: false,
            always_show_fingerprint: false,
        }
    }

    #[test]
    fn perfect_matches_are_named_on_one_line() {
        let m = results(
            ScanOutcome::Success,
            2,
            vec![os_match("Linux 5.4", 1.0), os_match("Linux 5.5", 1.0)],
        );
        let (fp, seq) = (FingerPrint::default(), SeqReport::default());
        let out = render(&report_for(&m, &fp, &seq, None));
        assert!(out.contains("OS details: Linux 5.4, Linux 5.5\n"), "{out}");
        assert!(out.contains("Network Distance: 3 hops\n"), "{out}");
        // A perfect match is not a submission request.
        assert!(!out.contains("nmap.org/submit"), "{out}");
    }

    #[test]
    fn debug_shows_the_fingerprint_in_every_branch() {
        // The C gates every `write_merged_fpr` on `debugging || verbose > 1`, including
        // the perfect-match branch. Missing that branch made our `-d` output silently
        // differ from nmap's whenever the host was actually identified — which is exactly
        // when the on-wire differential has the most to compare.
        let mut fp = FingerPrint::default();
        let mut t1 = crate::osdb::model::FingerTest::new(crate::osdb::model::TestId::T1);
        t1.set("R", "Y");
        fp.tests.push(t1);
        let seq = SeqReport::default();

        let cases = [
            (
                "perfect match",
                results(ScanOutcome::Success, 1, vec![os_match("Linux", 1.0)]),
                None,
            ),
            (
                "no perfect match",
                results(ScanOutcome::Success, 0, vec![os_match("Linux", 0.9)]),
                Some("Timing level 5 (Insane) used"),
            ),
            (
                "no matches",
                results(ScanOutcome::NoMatches, 0, vec![]),
                Some("Timing level 5 (Insane) used"),
            ),
            (
                "too many",
                results(ScanOutcome::TooManyMatches, 0, vec![]),
                None,
            ),
        ];
        for (name, m, reason) in cases {
            let mut r = report_for(&m, &fp, &seq, reason);
            r.always_show_fingerprint = true;
            assert!(
                render(&r).contains("T1(R=Y)"),
                "{name}: -d must show the fingerprint\n{}",
                render(&r)
            );
            // And without the flag it stays out of the branches that withhold it.
            r.always_show_fingerprint = false;
            if reason.is_some() {
                assert!(
                    !render(&r).contains("T1(R=Y)"),
                    "{name}: leaked an unfit fingerprint"
                );
            }
        }
    }

    #[test]
    fn too_many_matches_suppresses_the_details_line() {
        let m = results(
            ScanOutcome::Success,
            MAX_NAMED_PERFECT_MATCHES + 1,
            (0..9).map(|i| os_match(&format!("os{i}"), 1.0)).collect(),
        );
        let (fp, seq) = (FingerPrint::default(), SeqReport::default());
        let out = render(&report_for(&m, &fp, &seq, None));
        assert!(
            out.contains("Too many fingerprints match this host"),
            "{out}"
        );
        assert!(!out.contains("OS details:"), "{out}");

        // The explicit outcome does the same regardless of count.
        let m = results(ScanOutcome::TooManyMatches, 0, vec![]);
        let out = render(&report_for(&m, &fp, &seq, None));
        assert!(
            out.contains("Too many fingerprints match this host"),
            "{out}"
        );
    }

    #[test]
    fn an_unsubmittable_fingerprint_is_never_printed_for_submission() {
        // A submittable no-match prints the fingerprint and asks for it.
        let m = results(ScanOutcome::NoMatches, 0, vec![]);
        let mut fp = FingerPrint::default();
        fp.tests.push(crate::osdb::model::FingerTest::new(
            crate::osdb::model::TestId::T1,
        ));
        let seq = SeqReport::default();
        let out = render(&report_for(&m, &fp, &seq, None));
        assert!(out.contains("No OS matches for host (If you know"), "{out}");
        assert!(
            out.contains("T1("),
            "the fingerprint itself must be printed: {out}"
        );

        // An unsubmittable one says why and prints nothing to submit — pasting a
        // fingerprint taken under bad conditions would poison the shared database.
        let out = render(&report_for(
            &m,
            &fp,
            &seq,
            Some("Timing level 5 (Insane) used"),
        ));
        assert!(out.contains("not ideal because: Timing level 5"), "{out}");
        assert!(out.contains("No OS matches for host\n"), "{out}");
        assert!(
            !out.contains("T1("),
            "must not offer an unfit fingerprint: {out}"
        );
        assert!(!out.contains("nmap.org/submit"), "{out}");
    }

    #[test]
    fn guesses_appear_only_when_asked_for_or_when_submission_is_refused() {
        let m = results(
            ScanOutcome::Success,
            0,
            vec![os_match("Linux 4.x", 0.91), os_match("Linux 5.x", 0.88)],
        );
        let (fp, seq) = (FingerPrint::default(), SeqReport::default());

        // Neither flag: no guess line, and the fingerprint is offered for submission.
        let out = render(&report_for(&m, &fp, &seq, None));
        assert!(!out.contains("Aggressive OS guesses"), "{out}");
        assert!(
            out.contains("No exact OS matches for host (If you know"),
            "{out}"
        );

        // --osscan-guess turns them on.
        let mut r = report_for(&m, &fp, &seq, None);
        r.osscan_guess = true;
        let out = render(&r);
        assert!(
            out.contains("Aggressive OS guesses: Linux 4.x (91%), Linux 5.x (88%)"),
            "{out}"
        );

        // So does an unsubmittable fingerprint: a guess beats a request we cannot honour.
        let out = render(&report_for(
            &m,
            &fp,
            &seq,
            Some("Timing level 5 (Insane) used"),
        ));
        assert!(out.contains("Aggressive OS guesses:"), "{out}");
        assert!(out.contains("test conditions non-ideal"), "{out}");
    }

    #[test]
    fn accuracy_percentages_round_down_like_the_c() {
        let m = results(ScanOutcome::Success, 0, vec![os_match("X", 0.9689)]);
        let (fp, seq) = (FingerPrint::default(), SeqReport::default());
        let mut r = report_for(&m, &fp, &seq, None);
        r.osscan_guess = true;
        // The C uses floor(), so 96.89% prints as 96%, never 97%.
        assert!(render(&r).contains("X (96%)"), "{}", render(&r));
    }

    #[test]
    fn one_hop_is_singular() {
        let m = results(ScanOutcome::Success, 1, vec![os_match("X", 1.0)]);
        let (fp, seq) = (FingerPrint::default(), SeqReport::default());
        let mut r = report_for(&m, &fp, &seq, None);
        r.distance = Distance {
            hops: Some(1),
            method: DistanceMethod::Direct,
        };
        assert!(render(&r).contains("Network Distance: 1 hop\n"));
        // Unknown distance prints no line at all.
        r.distance = Distance {
            hops: None,
            method: DistanceMethod::None,
        };
        assert!(!render(&r).contains("Network Distance"));
    }

    #[test]
    fn unreliable_scans_are_flagged() {
        let m = results(ScanOutcome::Success, 1, vec![os_match("X", 1.0)]);
        let (fp, seq) = (FingerPrint::default(), SeqReport::default());
        let mut r = report_for(&m, &fp, &seq, None);
        r.reliable = false;
        assert!(render(&r).contains("results may be unreliable"));
        r.reliable = true;
        assert!(!render(&r).contains("results may be unreliable"));
    }

    #[test]
    fn sequence_lines_need_enough_samples_and_verbosity() {
        let m = results(ScanOutcome::Success, 1, vec![os_match("X", 1.0)]);
        let fp = FingerPrint::default();
        let seq = SeqReport {
            seqs: vec![1, 2, 3, 4],
            ipids: vec![1, 2, 3],
            timestamps: vec![9, 8, 7],
            index: 7,
            ipid_class: IpidSequence::Incr,
        };
        let mut r = report_for(&m, &fp, &seq, None);
        // Quiet by default.
        assert!(!render(&r).contains("TCP Sequence Prediction"));
        r.verbose = true;
        let out = render(&r);
        assert!(
            out.contains("TCP Sequence Prediction: Difficulty=7 (Medium)"),
            "{out}"
        );
        assert!(
            out.contains("IP ID Sequence Generation: Incremental"),
            "{out}"
        );

        // Too few samples: the C requires > 3 sequence and > 2 IP-ID samples.
        let thin = SeqReport {
            seqs: vec![1, 2, 3],
            ipids: vec![1, 2],
            ..Default::default()
        };
        let mut r = report_for(&m, &fp, &thin, None);
        r.verbose = true;
        let out = render(&r);
        assert!(!out.contains("TCP Sequence Prediction"), "{out}");
        assert!(!out.contains("IP ID Sequence Generation"), "{out}");
    }
}
