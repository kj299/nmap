//! `-sL` list scan end to end — the dry run.
//!
//! M7.3 put `-sL` in the MUST tier on a safety argument rather than a
//! convenience one: it is how an operator checks what a target expression
//! expands to *before* scanning it, and a scanner that cannot be asked "what
//! would you scan?" is harder to use safely.
//!
//! C sets `listscan` + `noportscan` + `PINGTYPE_NONE` (`nmap.cc:1307`), so it is
//! the one scan type that puts no packet on the wire. Two properties follow, and
//! every test here serves one:
//!
//!   1. **It previews the real scan.** Whatever `--exclude` and `-iL` would do
//!      to a real scan, they do here — otherwise the preview lies about the
//!      thing it previews, which is worse than having no preview.
//!   2. **It claims nothing it did not learn.** No liveness, no port state. C's
//!      grepable says `Status: Unknown`, not `Down`, and so must this.
//!
//! The output is also compared against C nmap itself by three cases in
//! `tests/differential/mvp-matrix.toml`; these tests cover the behaviours that
//! matrix cannot express (refusals, exit codes).
//!
//! Skipped under Miri (spawns a process).
#![cfg(not(miri))]

use std::io::Write;
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

fn hosts_in(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| l.strip_prefix("Nmap scan report for "))
        .map(str::to_string)
        .collect()
}

#[test]
fn a_list_scan_expands_targets_and_reports_them() {
    let (stdout, _, ok) = run(&["-sL", "127.0.0.1-3"]);
    assert!(ok, "a list scan exits 0");
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.2", "127.0.0.3"]);
}

/// It claims nothing it did not learn. Nothing was probed, so there is no
/// liveness and no port state to report — and "Host seems down" would be an
/// invented result, not a cautious one.
#[test]
fn a_list_scan_claims_no_liveness_and_no_ports() {
    let (stdout, _, ok) = run(&["-sL", "127.0.0.1-2"]);
    assert!(ok);
    assert!(!stdout.contains("Host is up"), "claimed liveness: {stdout}");
    assert!(
        !stdout.contains("Host seems down"),
        "guessed down: {stdout}"
    );
    assert!(!stdout.contains("PORT"), "rendered a port table: {stdout}");
    assert!(
        stdout.contains("(0 hosts up)"),
        "must report 0 up: {stdout}"
    );
}

/// C's grepable output for a list scan is `Status: Unknown`.
#[test]
fn grepable_output_says_unknown_not_down() {
    let (stdout, _, ok) = run(&["-sL", "-oG", "-", "127.0.0.1-2"]);
    assert!(ok);
    assert!(
        stdout.contains("Host: 127.0.0.1 ()\tStatus: Unknown"),
        "got: {stdout}"
    );
    assert!(!stdout.contains("Status: Down"), "claimed down: {stdout}");
}

#[test]
fn xml_output_says_unknown() {
    let (stdout, _, ok) = run(&["-sL", "-oX", "-", "127.0.0.1"]);
    assert!(ok);
    assert!(
        stdout.contains(r#"<status state="unknown"/>"#),
        "got: {stdout}"
    );
}

/// Property 1: the preview must reflect what a real scan would do. An exclusion
/// that applied to the scan but not to its preview would make the preview lie.
#[test]
fn exclusions_apply_to_the_preview() {
    let (stdout, _, ok) = run(&["-sL", "--exclude", "127.0.0.2", "127.0.0.1-3"]);
    assert!(ok);
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.3"]);
}

#[test]
fn an_input_file_feeds_the_preview() {
    let mut p = std::env::temp_dir();
    p.push(format!("nmap-rs-list-{}.txt", std::process::id()));
    std::fs::File::create(&p)
        .and_then(|mut f| f.write_all(b"127.0.0.1\n# a comment\n127.0.0.3\n"))
        .expect("write list");
    let (stdout, _, ok) = run(&["-sL", "-iL", p.to_str().expect("utf-8")]);
    let _ = std::fs::remove_file(&p);
    assert!(ok);
    assert_eq!(hosts_in(&stdout), ["127.0.0.1", "127.0.0.3"]);
}

/// C: `fatal("You cannot use -F (fast scan) or -p (explicit port selection)
/// when not doing a port scan")` — `nmap.cc:1584`. An operator who wrote
/// `-sL -p 80` asked for two incompatible things, and silently honouring one is
/// a guess about which they meant.
#[test]
fn ports_with_a_list_scan_are_refused() {
    let (stdout, stderr, ok) = run(&["-sL", "-p", "80", "127.0.0.1"]);
    assert!(!ok, "must exit non-zero");
    assert!(hosts_in(&stdout).is_empty(), "must not list: {stdout}");
    assert!(
        stderr.contains("not doing a port scan"),
        "should explain: {stderr}"
    );
}

/// A list scan sends nothing, so it must work without raw-socket privilege and
/// without falling back to anything.
#[test]
fn a_list_scan_needs_no_privilege_and_no_fallback() {
    let (stdout, stderr, ok) = run(&["-sL", "127.0.0.1"]);
    assert!(ok, "{stderr}");
    assert_eq!(hosts_in(&stdout), ["127.0.0.1"]);
    assert!(
        !stderr.contains("falling back"),
        "should not mention a fallback: {stderr}"
    );
}
