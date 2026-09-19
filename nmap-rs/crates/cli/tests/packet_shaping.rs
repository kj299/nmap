//! `--ttl`, `--badsum` and `-S` end to end — the three evasion options M7.5
//! ported.
//!
//! The scope decision behind them is `THREAT-MODEL.md` §7. The short version:
//! these three were not "declined for three milestones", they were *already
//! built* — `Ipv4Spec` carried `ttl`, `bad_sum` and `src` with tests, because
//! the raw scan paths needed those fields regardless. Withholding them would
//! have meant leaving working, gated capability deliberately unreachable.
//!
//! What these tests hold down is the wiring, and one property in particular:
//! **a scan that names none of them behaves exactly as before.** The override
//! is applied at a single site (`group.rs`, per-probe `Ipv4Spec`) and its
//! default is a no-op, so the blast radius of this change is meant to be zero
//! for every existing invocation.
//!
//! Skipped under Miri (spawns a process).
#![cfg(not(miri))]

use std::process::Command;

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

/// The options parse, are accepted, and do not disturb an ordinary connect scan.
///
/// They cannot *take effect* here — a connect scan builds no IP header — which
/// is exactly why the warning below exists. What this asserts is that accepting
/// them did not break the scan.
#[test]
fn the_three_options_are_accepted_and_the_scan_still_runs() {
    for args in [
        &["--ttl", "7", "-sT", "-p", "80", "127.0.0.1"][..],
        &["--badsum", "-sT", "-p", "80", "127.0.0.1"][..],
        &["-S", "192.0.2.9", "-sT", "-p", "80", "127.0.0.1"][..],
        &[
            "--ttl",
            "7",
            "--badsum",
            "-S",
            "192.0.2.9",
            "-sT",
            "-p",
            "80",
            "127.0.0.1",
        ][..],
    ] {
        let (stdout, stderr, ok) = run(args);
        assert!(ok, "{args:?} should still scan: {stderr}");
        assert!(
            stdout.contains("Nmap scan report for 127.0.0.1"),
            "{args:?} did not scan: {stdout}"
        );
    }
}

/// C warns and continues when raw-only options meet a scan that cannot honour
/// them (`nmap.cc:1817`), and so do we. These options shape packets rather than
/// constrain scope, so ignoring one does not scan more hosts or faster — the
/// M7.0 fail-closed rule is not engaged and matching C is the right default.
///
/// Our message improves on C's in one way: it names which options were dropped.
#[test]
fn raw_only_options_warn_by_name_on_a_connect_scan() {
    let (_, stderr, ok) = run(&["--ttl", "7", "-sT", "-p", "80", "127.0.0.1"]);
    assert!(ok, "a warning, not a refusal");
    assert!(stderr.contains("--ttl"), "should name the option: {stderr}");
    assert!(
        stderr.contains("will not be honored"),
        "should say it was dropped: {stderr}"
    );

    let (_, stderr, _) = run(&[
        "--ttl",
        "7",
        "--badsum",
        "-S",
        "192.0.2.9",
        "-sT",
        "-p",
        "80",
        "127.0.0.1",
    ]);
    for opt in ["--ttl", "--badsum", "-S"] {
        assert!(stderr.contains(opt), "{opt} should be named: {stderr}");
    }
}

/// An ordinary scan must not draw the warning, or it becomes noise nobody reads.
#[test]
fn an_ordinary_scan_draws_no_warning() {
    let (_, stderr, ok) = run(&["-sT", "-p", "80", "127.0.0.1"]);
    assert!(ok);
    assert!(
        !stderr.contains("will not be honored"),
        "unexpected warning: {stderr}"
    );
}

/// C: `fatal("You can only use the source option once!")`. Two source addresses
/// is an ambiguous command, not a preference to resolve.
#[test]
fn a_second_source_address_is_refused() {
    let (stdout, stderr, ok) = run(&[
        "-S",
        "1.1.1.1",
        "-S",
        "2.2.2.2",
        "-sT",
        "-p",
        "80",
        "127.0.0.1",
    ]);
    assert!(!ok);
    assert!(
        !stdout.contains("Nmap scan report"),
        "must not scan: {stdout}"
    );
    assert!(
        stderr.contains("only use the source option"),
        "got: {stderr}"
    );
}

/// A `-S` that is not an address refuses rather than falling back to the routed
/// source. An operator who asked to send from a particular address and silently
/// got a different one has been told something untrue about their own traffic.
#[test]
fn a_non_address_source_refuses_rather_than_falling_back() {
    let (stdout, stderr, ok) = run(&["-S", "not-an-address", "-sT", "-p", "80", "127.0.0.1"]);
    assert!(!ok);
    assert!(
        !stdout.contains("Nmap scan report"),
        "must not scan: {stdout}"
    );
    assert!(stderr.contains("expects an IPv4 address"), "got: {stderr}");
}

/// An out-of-range TTL is refused, matching C's
/// `fatal("ttl option must be a number between 0 and 255")`. Notably `atoi`
/// would turn "abc" into a valid TTL of 0; we refuse instead.
#[test]
fn an_out_of_range_ttl_refuses_to_scan() {
    for bad in ["256", "999", "-1", "abc"] {
        let (stdout, stderr, ok) = run(&["--ttl", bad, "-sT", "-p", "80", "127.0.0.1"]);
        assert!(!ok, "--ttl {bad} should refuse");
        assert!(
            !stdout.contains("Nmap scan report"),
            "--ttl {bad} scanned: {stdout}"
        );
        assert!(
            stderr.contains("--ttl"),
            "--ttl {bad} should be named: {stderr}"
        );
    }
    // The boundaries still work.
    for good in ["0", "255"] {
        let (_, stderr, ok) = run(&["--ttl", good, "-sT", "-p", "80", "127.0.0.1"]);
        assert!(ok, "--ttl {good} should be accepted: {stderr}");
    }
}
