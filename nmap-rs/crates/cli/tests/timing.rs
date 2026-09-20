//! The `-T` group end to end — twelve options that between them decide how hard
//! this scanner leans on a network.
//!
//! Three properties, and every test here serves one:
//!
//!   1. **A refusal looks like C's refusal.** An operator who hits one of these
//!      messages will search for C nmap's wording, so the wording is C's — down
//!      to the numbers, which differ per option ("3.3 minutes" for
//!      `--scan-delay`, "11.1 hours" for `--host-timeout`).
//!   2. **An explicit knob beats `-T`, whichever came first.** C applies them
//!      after the whole argument loop, so argv order does not decide.
//!   3. **Nothing is accepted that does not take effect.** `--host-timeout` and
//!      the hostgroup pair are parsed and then *refused*, because this engine
//!      has no per-host deadline and no hostgroup batching. Accepting them
//!      would repeat the M7.0 mistake: an option that silently does nothing is
//!      an option that silently scans past the limit you set.
//!
//! Every message below was compared against the installed C nmap, not against a
//! reading of `nmap.cc`.
//!
//! Skipped under Miri (spawns a process).
#![cfg(not(miri))]

use std::process::Command;
use std::time::Instant;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_nmap-rs")
}

fn run(args: &[&str]) -> (String, String, bool) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("nmap-rs runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

// ---- 1. refusals carry C's wording ----------------------------------------

/// The "since April 2010" guard. Each option converts to a different unit and
/// suggests a different fix, so a single generic message would be wrong for
/// three of the four. These strings are C's, verbatim.
#[test]
fn the_bare_seconds_guard_matches_c_for_every_option() {
    for (args, expect) in [
        (
            ["--scan-delay", "200"],
            "so your time of \"200\" is 3.3 minutes. Use \"200ms\" for 200 milliseconds.",
        ),
        (
            ["--max-scan-delay", "150"],
            "so your time of \"150\" is 2.5 minutes. If this is what you want, use \"150s\".",
        ),
        (
            ["--host-timeout", "40000"],
            "so your time of \"40000\" is 11.1 hours. If this is what you want, use \"40000s\".",
        ),
        (
            ["--max-rtt-timeout", "60"],
            "so your time of \"60\" is 60 seconds. Use \"60ms\" for 60 milliseconds.",
        ),
    ] {
        let (_, stderr, ok) = run(&[args[0], args[1], "-sL", "-n", "127.0.0.1"]);
        assert!(!ok, "{} {} must be refused", args[0], args[1]);
        assert!(
            stderr.contains(expect),
            "{} {}:\n  want …{expect}\n  got  {stderr}",
            args[0],
            args[1]
        );
    }
}

/// The same value *with a unit* is honoured — that is the whole point of the
/// guard, and of `tval_unit` existing.
#[test]
fn an_explicit_unit_clears_the_guard() {
    let (_, _, ok) = run(&["--scan-delay", "200ms", "-sL", "-n", "127.0.0.1"]);
    assert!(ok, "--scan-delay 200ms is a legitimate 200 milliseconds");
}

/// An unparseable value trips the option's *floor* check, because that is the
/// order C runs them in: `tval2msecs` returns -1 and -1 fails `l < 5`. So the
/// message is the floor's, not a separate "cannot parse" one.
#[test]
fn an_unparseable_value_reports_the_floor_message() {
    let (_, stderr, ok) = run(&["--max-rtt-timeout", "zzz", "-sL", "-n", "127.0.0.1"]);
    assert!(!ok);
    assert!(
        stderr.contains("Bogus --max-rtt-timeout argument specified, must be at least 5ms"),
        "got: {stderr}"
    );
}

/// `-T` accepts the six names case-insensitively and the digits 0-5.
#[test]
fn timing_templates_parse_by_name_and_number() {
    for spec in [
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "Paranoid",
        "sneaky",
        "POLITE",
        "Normal",
        "aGGressive",
        "Insane",
    ] {
        let (_, stderr, ok) = run(&[&format!("-T{spec}"), "-sL", "-n", "127.0.0.1"]);
        assert!(ok, "-T{spec} should parse: {stderr}");
    }
}

/// C reads only the FIRST character of a numeric `-T`, so `-T4abc` is
/// Aggressive there, and `-T11` hits an easter egg that silently means `-T5` —
/// turning a typo of the second most cautious template into the most aggressive
/// one. Reaching it in C also reads past the end of a stack array. This port
/// refuses anything that is not exactly a digit 0-5 or one of the six names.
/// See DIVERGENCES.md.
#[test]
fn a_malformed_timing_template_is_refused_rather_than_guessed() {
    for spec in ["11", "4abc", "44", "6", "-1", "Paranoidish", ""] {
        let (_, stderr, ok) = run(&[&format!("-T{spec}"), "-sL", "-n", "127.0.0.1"]);
        assert!(!ok, "-T{spec} must be refused, not guessed at");
        assert!(stderr.contains("Unknown timing mode"), "-T{spec}: {stderr}");
    }
}

// ---- 2. an explicit knob beats -T, whichever came first --------------------

/// C applies the explicit knobs *after* the whole argument loop
/// (`nmap.cc:1472`), so `-T0 --scan-delay X` and `--scan-delay X -T0` are the
/// same scan. Applying in argv order instead would make one of the two forms
/// silently discard the operator's value.
///
/// Measured rather than asserted on a field: `-T0` is a five-minute delay, so
/// if the explicit 50ms did not win, this test would not finish.
#[test]
fn an_explicit_scan_delay_overrides_the_template_in_either_order() {
    for args in [
        vec!["-T0", "--scan-delay", "50ms"],
        vec!["--scan-delay", "50ms", "-T0"],
    ] {
        let mut full = args.clone();
        full.extend_from_slice(&["-sT", "-Pn", "-n", "-p", "1-3", "127.0.0.1"]);
        let start = Instant::now();
        let (_, stderr, ok) = run(&full);
        let elapsed = start.elapsed();
        assert!(ok, "{args:?}: {stderr}");
        assert!(
            elapsed.as_secs() < 30,
            "{args:?} took {elapsed:?} — the template's 5-minute delay won over the explicit 50ms"
        );
    }
}

/// `--scan-delay` is real, not just parsed. Three ports at 150ms apart cannot
/// finish in under 300ms however fast the connects are.
#[test]
fn a_scan_delay_actually_paces_the_scan() {
    let start = Instant::now();
    let (_, stderr, ok) = run(&[
        "-sT",
        "-Pn",
        "-n",
        "--scan-delay",
        "150ms",
        "-p",
        "1-3",
        "127.0.0.1",
    ]);
    assert!(ok, "{stderr}");
    assert!(
        start.elapsed().as_millis() >= 300,
        "3 ports at 150ms apart finished in {:?} — the delay is not being applied",
        start.elapsed()
    );
}

/// The templates that exist *because* they are slow must be slow. `-T2` is a
/// 400ms inter-probe delay; without it "Polite" is just a serialised scan at
/// full speed, which is not what an operator choosing it asked for.
#[test]
fn the_polite_template_carries_its_delay() {
    let start = Instant::now();
    let (_, stderr, ok) = run(&["-sT", "-Pn", "-n", "-T2", "-p", "1-3", "127.0.0.1"]);
    assert!(ok, "{stderr}");
    assert!(
        start.elapsed().as_millis() >= 800,
        "-T2 over 3 ports finished in {:?}; its 400ms scan delay is not being applied",
        start.elapsed()
    );
}

// ---- 3. nothing is accepted that does not take effect ----------------------

#[test]
fn options_the_engine_cannot_honour_are_refused_not_ignored() {
    for (args, expect) in [
        (vec!["--host-timeout", "30s"], "per-host deadline"),
        (vec!["--max-hostgroup", "5"], "hostgroup ceiling"),
        (vec!["--min-hostgroup", "2"], "hostgroup ceiling"),
    ] {
        let mut full = args.clone();
        full.extend_from_slice(&["-sL", "-n", "127.0.0.1"]);
        let (stdout, stderr, ok) = run(&full);
        assert!(!ok, "{args:?} must be refused while it does nothing");
        assert!(stderr.contains(expect), "{args:?}: {stderr}");
        assert!(
            !stdout.contains("Nmap scan report"),
            "{args:?} scanned anyway:\n{stdout}"
        );
    }
}

// ---- warnings (C's error(), which prints and carries on) -------------------

#[test]
fn warnings_match_c_and_do_not_stop_the_scan() {
    for (args, expect) in [
        (
            vec!["--max-rtt-timeout", "10ms"],
            "WARNING: You specified a round-trip time timeout (10 ms) that is EXTRAORDINARILY SMALL.  Accuracy may suffer.",
        ),
        (
            vec!["--min-parallelism", "200"],
            "Warning: Your --min-parallelism option is pretty high!  This can hurt reliability.",
        ),
        (
            vec!["-M", "950"],
            "Warning: Your max-parallelism (-M) option is extraordinarily high, which can hurt reliability",
        ),
        (
            vec!["--scan-delay", "5ms", "--max-parallelism", "10"],
            "Warning: --min-parallelism and --max-parallelism are ignored with --scan-delay.",
        ),
    ] {
        let mut full = args.clone();
        full.extend_from_slice(&["-sL", "-n", "127.0.0.1"]);
        let (stdout, stderr, ok) = run(&full);
        assert!(ok, "{args:?} warns, it does not refuse: {stderr}");
        assert!(stderr.contains(expect), "{args:?}:\n  want {expect}\n  got  {stderr}");
        assert!(
            stdout.contains("Nmap scan report"),
            "{args:?} must still scan"
        );
    }
}

/// Both spellings `getopt_long_only` accepts, and both ways of attaching a
/// value. A value-taking option that failed to consume its argument would leave
/// it in argv for the positional handler to read as a target — the M7.0 bug.
#[test]
fn every_spelling_consumes_its_argument() {
    for args in [
        vec!["--max-retries", "2"],
        vec!["--max-retries=2"],
        vec!["-max-retries", "2"],
        vec!["-max-retries=2"],
    ] {
        let mut full = args.clone();
        full.extend_from_slice(&["-sL", "-n", "127.0.0.1"]);
        let (stdout, stderr, ok) = run(&full);
        assert!(ok, "{args:?}: {stderr}");
        let hosts: Vec<&str> = stdout
            .lines()
            .filter(|l| l.starts_with("Nmap scan report for "))
            .collect();
        assert_eq!(
            hosts,
            ["Nmap scan report for 127.0.0.1"],
            "{args:?} leaked its argument into the target list:\n{stdout}"
        );
    }
}
