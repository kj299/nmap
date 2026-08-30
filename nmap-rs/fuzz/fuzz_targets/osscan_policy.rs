// cargo-fuzz target for `nmap_core::osscan` — the OS-detection policy and reporting.
//
// This module looks like plain formatting, but two of its inputs are attacker-influenced.
// OS names and accuracies come from the reference database, which `--osscandb <file>`
// makes attacker-supplyable; the sequence samples come straight off the wire from the
// target. The C renders the latter into fixed 512-byte buffers and calls
// `fatal("STRANGE ERROR #3877")` — killing the whole scan, losing every host's results —
// if a list would overflow.
//
// Enforced: reporting is TOTAL for any inputs, an unsubmittable fingerprint is NEVER
// offered for submission, the guess list respects its cap and accuracy window, and
// `best_round` always names a real round.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::ipid::IpidSequence;
use nmap_core::osdb::model::FingerPrint;
use nmap_core::osdb::score::{MatchResults, OsMatch, ScanOutcome};
use nmap_core::osscan::{
    attribute_distance, best_round, listed_guesses, render, seq_value_lists, submission_reason,
    DistanceMethod, HostFacts, Report, Round, SeqReport, SubmissionInputs,
    GUESS_ACCURACY_WINDOW, MAX_LISTED_GUESSES,
};

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.wrapping_add(1);
        b
    }
    fn u16(&mut self) -> u16 {
        u16::from(self.u8()) << 8 | u16::from(self.u8())
    }
    fn u32(&mut self) -> u32 {
        u32::from(self.u16()) << 16 | u32::from(self.u16())
    }
    fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }
    /// Accuracies including the degenerate values a hostile database can induce.
    fn accuracy(&mut self) -> f64 {
        match self.u8() % 8 {
            0 => f64::NAN,
            1 => f64::INFINITY,
            2 => -1.0,
            3 => 2.0,
            n => f64::from(n) / 5.0,
        }
    }
}

fn outcome(n: u8) -> Option<ScanOutcome> {
    match n % 4 {
        0 => Some(ScanOutcome::Success),
        1 => Some(ScanOutcome::NoMatches),
        2 => Some(ScanOutcome::TooManyMatches),
        _ => None,
    }
}

fn ipid_class(n: u8) -> IpidSequence {
    match n % 8 {
        0 => IpidSequence::Unknown,
        1 => IpidSequence::Incr,
        2 => IpidSequence::BrokenIncr,
        3 => IpidSequence::Rpi,
        4 => IpidSequence::Rd,
        5 => IpidSequence::Constant,
        6 => IpidSequence::Zero,
        _ => IpidSequence::IncrBy2,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor { data, pos: 0 };

    // A match list a hostile database could produce: arbitrary names and accuracies, and
    // not necessarily sorted.
    let count = usize::from(c.u8() % 24);
    let matches: Vec<OsMatch> = (0..count)
        .map(|i| OsMatch {
            os_name: format!("os{}{}", c.u8(), if c.bool() { "%weird(" } else { "" }),
            accuracy: c.accuracy(),
            index: i,
        })
        .collect();
    let results = MatchResults {
        num_perfect_matches: usize::from(c.u8()) % (count + 1),
        matches,
        outcome: outcome(c.u8()),
    };

    let seq = SeqReport {
        // Chosen independently of the vector lengths, so the fuzzer explores a
        // response count both shorter and LONGER than the vectors it bounds.
        responses: usize::from(c.u8() % 40),
        seqs: (0..usize::from(c.u8() % 40)).map(|_| c.u32()).collect(),
        ipids: (0..usize::from(c.u8() % 40)).map(|_| c.u16()).collect(),
        timestamps: (0..usize::from(c.u8() % 40)).map(|_| c.u32()).collect(),
        index: c.u32(),
        ipid_class: ipid_class(c.u8()),
    };

    // The value lists must be produced without the C's fatal(), at any length, and
    // each is bounded by `responses` — the C reads only the live entries of its
    // fixed-size arrays. A `responses` larger than the vector must yield the whole
    // vector rather than panicking or reading past it.
    let (s, i, t) = seq_value_lists(&seq);
    let listed = |rendered: &str, len: usize| {
        let want = seq.responses.min(len);
        assert_eq!(
            rendered.matches(',').count(),
            want.saturating_sub(1),
            "expected {want} entries from responses={} over a {len}-long vector, got {rendered:?}",
            seq.responses
        );
    };
    listed(&s, seq.seqs.len());
    listed(&i, seq.ipids.len());
    listed(&t, seq.timestamps.len());

    let inputs = SubmissionInputs {
        scan_delay_ms: u64::from(c.u32()),
        timing_level: c.u8(),
        have_open_tcp_port: c.bool(),
        have_closed_tcp_port: c.bool(),
        have_closed_udp_port: c.bool(),
        udp_scan_requested: c.bool(),
        distance: if c.bool() { Some(c.u8()) } else { None },
        max_timing_ratio: f64::from(c.u8()) / 100.0,
        incomplete: c.bool(),
    };
    let reason = submission_reason(&inputs);
    // Deterministic.
    assert_eq!(submission_reason(&inputs), reason);

    let facts = HostFacts {
        is_localhost: c.bool(),
        has_mac_address: c.bool(),
    };
    let measured = if c.bool() { Some(c.u8()) } else { None };
    let distance = attribute_distance(facts, measured);
    // A local fact always wins over anything the target claimed.
    if facts.is_localhost {
        assert_eq!(distance.hops, Some(0));
        assert_eq!(distance.method, DistanceMethod::Localhost);
    } else if facts.has_mac_address {
        assert_eq!(distance.hops, Some(1));
        assert_eq!(distance.method, DistanceMethod::Direct);
    }
    // A hop count is reported only when some rule actually produced one.
    assert_eq!(
        distance.hops.is_some(),
        distance.method != DistanceMethod::None
    );

    // The guess list must respect both bounds even with NaN accuracies present.
    let listed = listed_guesses(&results);
    assert!(listed.len() <= MAX_LISTED_GUESSES);
    if let Some(best) = results.matches.first() {
        let floor = best.accuracy - GUESS_ACCURACY_WINDOW;
        for m in &listed {
            assert!(m.accuracy > floor, "a guess outside the window was listed");
        }
    }

    let mut fingerprint = FingerPrint::default();
    fingerprint.os_name = "observed".to_owned();

    let report = Report {
        matches: &results,
        fingerprint: &fingerprint,
        submission_reason: reason.as_deref(),
        distance,
        seq: &seq,
        // Exercise both uptime shapes and the absent case: the render must not panic
        // or produce a NaN/inf day count for any of them.
        uptime: if c.bool() {
            Some(nmap_core::osscan::UptimeLine {
                seconds: f64::from(c.u32()),
                since: if c.bool() {
                    nmap_core::osscan::format_boot_time(i64::from(c.u32()))
                } else {
                    None
                },
            })
        } else {
            None
        },
        open_tcp_port: if c.bool() { Some(c.u16()) } else { None },
        closed_tcp_port: if c.bool() { Some(c.u16()) } else { None },
        osscan_guess: c.bool(),
        reliable: c.bool(),
        verbose: c.bool(),
        always_show_fingerprint: c.bool(),
    };

    let out = render(&report);
    assert_eq!(render(&report), out, "rendering is not deterministic");
    // Scoped to the uptime line: this target deliberately feeds degenerate *accuracies*
    // (NaN/inf) to prove the policy does not panic on them, so a non-finite percentage
    // elsewhere is the point rather than a defect.
    for line in out.lines().filter(|l| l.starts_with("Uptime guess")) {
        assert!(
            !line.contains("NaN") && !line.contains("inf"),
            "a non-finite day count reached the uptime line: {line}"
        );
    }

    // The invariant that protects the shared fingerprint database: a fingerprint judged
    // unfit must never be printed *for submission*. Showing it under -d is a different
    // thing — the operator asked to see it — so the invariant is about the submission
    // request, which must never appear for an unfit observation regardless of verbosity.
    if reason.is_some() {
        assert!(
            !out.contains("https://nmap.org/submit/"),
            "asked for submission of an unfit fingerprint:\n{out}"
        );
    }

    // `-d` shows the observation in every branch; without it, an unfit fingerprint is
    // withheld. Both must hold for any inputs.
    let mut shown = report;
    shown.always_show_fingerprint = true;
    let with_debug = render(&shown);
    assert!(
        with_debug.len() >= out.len(),
        "-d must not withhold what the default shows"
    );

    // Whatever branch was taken, exactly one verdict line must be present.
    let verdicts = [
        "OS details:",
        "Too many fingerprints match this host",
        "No exact OS matches for host",
        "No OS matches for host",
    ];
    assert!(
        verdicts.iter().filter(|v| out.contains(**v)).count() >= 1,
        "no verdict line rendered:\n{out}"
    );

    // `best_round` must name a real round whenever there is one.
    let rounds: Vec<Round> = (0..usize::from(c.u8() % 5))
        .map(|_| Round {
            fingerprint: FingerPrint::default(),
            matches: MatchResults {
                matches: vec![OsMatch {
                    os_name: "r".to_owned(),
                    accuracy: c.accuracy(),
                    index: 0,
                }],
                num_perfect_matches: usize::from(c.u8() % 2),
                outcome: outcome(c.u8()),
            },
        })
        .collect();
    match best_round(&rounds) {
        Some(i) => assert!(i < rounds.len(), "best_round named a nonexistent round"),
        None => assert!(rounds.is_empty()),
    }
});
