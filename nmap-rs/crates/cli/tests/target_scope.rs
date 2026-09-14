//! `--exclude`, `--excludefile` and `-iL` end to end.
//!
//! These are the first three options of M7.3's MUST tier, and they are first
//! because they are the ones the M7.0 audit found a hole in. Two properties are
//! worth stating before the tests, because every assertion below serves one of
//! them:
//!
//!   1. **An exclusion removes hosts.** Not "is accepted", not "is parsed" —
//!      the address named must not appear in the scan. The original bug parsed
//!      `--exclude` fine in the sense that it did not crash; it just scanned the
//!      host anyway.
//!   2. **An exclusion that cannot be applied stops the scan.** A missing file,
//!      an unparseable spec, an unresolvable name — none of these may degrade
//!      into "carry on without that exclusion", because the result is scanning
//!      exactly the host the operator took an explicit step to protect.
//!
//! Skipped under Miri (spawns a process, reads files).
#![cfg(not(miri))]

use std::io::Write;
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

/// A temp file holding `body`, removed when the returned guard drops.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn new(name: &str, body: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("nmap-rs-scope-{}-{}", std::process::id(), name));
        let mut f = std::fs::File::create(&p).expect("create temp file");
        f.write_all(body.as_bytes()).expect("write temp file");
        Self(p)
    }
    fn path(&self) -> &str {
        self.0.to_str().expect("utf-8 temp path")
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn hosts_in(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| l.strip_prefix("Nmap scan report for "))
        .map(str::to_string)
        .collect()
}

// ---- property 1: an exclusion actually removes hosts ----------------------

#[test]
fn exclude_removes_an_address_from_an_expanded_range() {
    let (stdout, _, ok) = run(&["--exclude", "127.0.0.2", "-sT", "-p", "80", "127.0.0.1-3"]);
    assert!(ok, "should scan");
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.3"]);
}

#[test]
fn exclude_accepts_a_comma_separated_list() {
    let (stdout, _, ok) = run(&[
        "--exclude",
        "127.0.0.2,127.0.0.3",
        "-sT",
        "-p",
        "80",
        "127.0.0.1-4",
    ]);
    assert!(ok);
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.4"]);
}

#[test]
fn exclude_accepts_cidr_and_ranges() {
    let (stdout, _, ok) = run(&[
        "--exclude",
        "127.0.0.0/30",
        "-sT",
        "-p",
        "80",
        "127.0.0.1-5",
    ]);
    assert!(ok);
    // /30 covers .0-.3, so only .4 and .5 survive.
    assert_eq!(hosts_in(&stdout), ["127.0.0.4", "127.0.0.5"]);
}

#[test]
fn excludefile_removes_the_addresses_it_lists() {
    let ex = TempFile::new("ex.txt", "# hosts to leave alone\n127.0.0.2\n127.0.0.4\n");
    let (stdout, _, ok) = run(&["--excludefile", ex.path(), "-sT", "-p", "80", "127.0.0.1-4"]);
    assert!(ok);
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.3"]);
}

/// C loads `--exclude` and `--excludefile` into the SAME `exclude_group`
/// (`nmap.cc:2070-2074`), so giving both must union them, not let one win.
#[test]
fn exclude_and_excludefile_combine_rather_than_override() {
    let ex = TempFile::new("both.txt", "127.0.0.2\n");
    let (stdout, _, ok) = run(&[
        "--exclude",
        "127.0.0.4",
        "--excludefile",
        ex.path(),
        "-sT",
        "-p",
        "80",
        "127.0.0.1-4",
    ]);
    assert!(ok);
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.3"]);
}

#[test]
fn excluding_every_target_says_so_rather_than_blaming_resolution() {
    let (stdout, stderr, ok) = run(&["--exclude", "127.0.0.1", "-sT", "-p", "80", "127.0.0.1"]);
    assert!(!ok, "nothing to scan is a failure exit");
    assert!(hosts_in(&stdout).is_empty());
    // The operator needs to know the exclusion worked, not go hunting for a
    // resolution bug that does not exist.
    assert!(
        stderr.contains("matched an exclusion"),
        "expected an exclusion-specific message, got: {stderr}"
    );
}

// ---- -iL ------------------------------------------------------------------

#[test]
fn input_file_supplies_targets() {
    let list = TempFile::new("hosts.txt", "127.0.0.1\n127.0.0.3\n");
    let (stdout, _, ok) = run(&["-iL", list.path(), "-sT", "-p", "80"]);
    assert!(ok);
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.3"]);
}

/// The tokenizer is nmap's `read_host_from_file`, not "one host per line":
/// several specs may share a line, and `#` comments to end of line.
#[test]
fn input_file_takes_several_specs_per_line_and_comments() {
    let list = TempFile::new(
        "multi.txt",
        "# leading comment\n127.0.0.1 127.0.0.3\t127.0.0.4 # trailing\n",
    );
    let (stdout, _, ok) = run(&["-iL", list.path(), "-sT", "-p", "80"]);
    assert!(ok);
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.3", "127.0.0.4"]);
}

/// C's `grab_next_host_spec` returns argv entries while `optind < argc` and only
/// then reads the input file, so positional targets come first.
#[test]
fn positional_targets_come_before_the_input_file() {
    let list = TempFile::new("order.txt", "127.0.0.3\n");
    let (stdout, _, ok) = run(&["-iL", list.path(), "-sT", "-p", "80", "127.0.0.1"]);
    assert!(ok);
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.3"]);
}

#[test]
fn input_file_and_exclusions_compose() {
    let list = TempFile::new("compose.txt", "127.0.0.1\n127.0.0.2\n127.0.0.3\n");
    let (stdout, _, ok) = run(&[
        "-iL",
        list.path(),
        "--exclude",
        "127.0.0.2",
        "-sT",
        "-p",
        "80",
    ]);
    assert!(ok);
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.3"]);
}

// ---- property 2: an exclusion that cannot be applied stops the scan --------

/// Every one of these would, if it degraded to a warning, scan a host the
/// operator named in order to protect it. The target on the command line is one
/// that WOULD scan successfully, so a passing test means the refusal is doing
/// the work — not that the scan failed for some unrelated reason.
#[test]
fn an_exclusion_that_cannot_be_applied_refuses_to_scan() {
    let cases: [(&[&str], &str); 3] = [
        (
            &["--excludefile", "/nonexistent/nmap-rs/exclude.txt"],
            "failed to read exclude file",
        ),
        (&["--exclude", "10.0.0.0/x"], "bad exclusion"),
        (
            &["--exclude", "no-such-host.invalid"],
            "could not resolve excluded name",
        ),
    ];
    for (flag, expect) in cases {
        let mut args = flag.to_vec();
        args.extend_from_slice(&["-sT", "-p", "80", "127.0.0.1"]);
        let (stdout, stderr, ok) = run(&args);
        assert!(!ok, "{flag:?} must refuse, got success");
        assert!(
            hosts_in(&stdout).is_empty(),
            "{flag:?} scanned anyway: {stdout}"
        );
        assert!(
            stderr.contains(expect),
            "{flag:?} should say why; got: {stderr}"
        );
        assert!(
            stderr.contains("refusing to scan"),
            "{flag:?} should name the refusal: {stderr}"
        );
    }
}

/// An unreadable `-iL` list is not an empty list. C `pfatal`s; so do we.
#[test]
fn an_unreadable_input_file_refuses_to_scan() {
    let (stdout, stderr, ok) = run(&["-iL", "/nonexistent/nmap-rs/hosts.txt", "-sT", "-p", "80"]);
    assert!(!ok);
    assert!(hosts_in(&stdout).is_empty());
    assert!(
        stderr.contains("failed to read input file"),
        "got: {stderr}"
    );
}

/// C: `fatal("Only one input filename allowed")`. Silently keeping one of the
/// two would scan a different set than the operator asked for.
#[test]
fn two_input_files_are_refused() {
    let a = TempFile::new("a.txt", "127.0.0.1\n");
    let b = TempFile::new("b.txt", "127.0.0.3\n");
    let (stdout, stderr, ok) = run(&["-iL", a.path(), "-iL", b.path(), "-sT", "-p", "80"]);
    assert!(!ok);
    assert!(hosts_in(&stdout).is_empty());
    assert!(
        stderr.contains("only one input filename allowed"),
        "got: {stderr}"
    );
}

/// A spec longer than the C's 1024-byte buffer is `fatal` there. Truncating it
/// would scan an address nobody wrote.
#[test]
fn an_over_long_spec_in_a_list_refuses_to_scan() {
    let list = TempFile::new("long.txt", &format!("{}\n", "a".repeat(1024)));
    let (stdout, stderr, ok) = run(&["-iL", list.path(), "-sT", "-p", "80"]);
    assert!(!ok);
    assert!(hosts_in(&stdout).is_empty());
    assert!(stderr.contains("SpecTooLong"), "got: {stderr}");
}
