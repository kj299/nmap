//! The CLI must refuse to scan when handed an option it does not implement.
//!
//! This pins a bug found during the M7 cutover audit. `nmap-rs` used to print a
//! warning for an unimplemented option and scan anyway, which went wrong twice
//! over:
//!
//!   * Most unimplemented options *constrain* a scan — `--exclude`,
//!     `--scan-delay`, `-T`, `--max-retries`, `--top-ports`. Ignoring a
//!     constraint scans more hosts, or faster, than the operator asked for.
//!   * An unimplemented option that takes a value left that value in argv,
//!     where the positional handler collected it as a target. So
//!     `--exclude 127.0.0.2` did not merely fail to exclude that address — it
//!     *added* it to the scan. Naming a host in order to protect it was the
//!     thing that got it scanned.
//!
//! C nmap exits without scanning on an unrecognised option (`nmap.cc:653`,
//! `case '?'` → `error()` then `exit(-1)`), so the old behaviour was also an
//! unledgered divergence, in the dangerous direction.
//!
//! Skipped under Miri (spawns a process).
#![cfg(not(miri))]

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_nmap-rs")
}

/// `(stdout, stderr, exit_ok)` from one invocation.
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

/// This used to be written with `--exclude`, which M7.4 implements. The example
/// moved to a still-unimplemented value-taking option rather than being deleted:
/// the property under test is not about any one flag, it is that an option we
/// cannot honour stops the scan instead of leaking its argument into the target
/// list.
#[test]
fn an_unimplemented_option_refuses_to_scan() {
    let (stdout, stderr, ok) = run(&["--scan-delay", "5s", "-sT", "-p", "80", "127.0.0.1"]);
    assert!(!ok, "must exit non-zero, like C nmap's `case '?'`");
    assert!(
        stderr.contains("--scan-delay"),
        "the offending option should be named: {stderr}"
    );
    assert!(
        !stdout.contains("Nmap scan report"),
        "nothing may be scanned: {stdout}"
    );
}

/// The sharp version of the bug: the excluded address must not be scanned.
///
/// Without `--exclude` this command scans exactly one host. The original bug
/// scanned two — 127.0.0.1 *and* the address named in `--exclude` — because the
/// unimplemented option left its value in argv for the positional handler.
///
/// This assertion has now held for three different reasons in three milestones,
/// which is why it is worth keeping exactly as written: before M7.0 it FAILED
/// (the address was scanned); from M7.0 it passed because the whole scan was
/// refused; from M7.4 it passes because `--exclude` is implemented and actually
/// excludes. The behaviour the operator cares about never changed.
#[test]
fn the_excluded_address_is_never_scanned() {
    let (stdout, _, ok) = run(&["--exclude", "127.0.0.2", "-sT", "-p", "80", "127.0.0.1"]);
    assert!(ok, "--exclude is implemented now; this must scan");
    assert!(
        !stdout.contains("127.0.0.2"),
        "the address named in --exclude was scanned: {stdout}"
    );
    assert!(
        stdout.contains("Nmap scan report for 127.0.0.1"),
        "the un-excluded target must still be scanned: {stdout}"
    );
}

/// Rate limits are constraints too: ignoring `-T2` or `--scan-delay` scans
/// harder than asked, which can take a fragile target down.
#[test]
fn ignoring_a_rate_limit_is_also_refused() {
    for args in [
        &["-T2", "-sT", "-p", "80", "127.0.0.1"][..],
        &["--scan-delay", "5s", "-sT", "-p", "80", "127.0.0.1"][..],
        &["--max-retries", "1", "-sT", "-p", "80", "127.0.0.1"][..],
        &["--top-ports", "5", "-sT", "127.0.0.1"][..],
    ] {
        let (stdout, _, ok) = run(args);
        assert!(!ok, "{args:?} should be refused");
        assert!(
            !stdout.contains("Nmap scan report"),
            "{args:?} scanned anyway"
        );
    }
}

/// The gate must not fire on a supported invocation.
#[test]
fn a_supported_invocation_still_scans() {
    let (stdout, stderr, ok) = run(&["-sT", "-p", "80", "127.0.0.1"]);
    assert!(ok, "supported flags must still work: {stderr}");
    assert!(
        stdout.contains("Nmap scan report for 127.0.0.1"),
        "expected a scan: {stdout}"
    );
}

/// `-h` and `--version` short-circuit before the gate, so they keep working
/// even though plenty of options remain unimplemented.
#[test]
fn help_and_version_are_unaffected() {
    for flag in ["-h", "--help", "--version"] {
        let (stdout, _, ok) = run(&[flag]);
        assert!(ok, "{flag} should succeed");
        assert!(!stdout.is_empty(), "{flag} should print something");
    }
}
