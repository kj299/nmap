//! `-oA`, and the filename handling all four output options share.
//!
//! Three properties:
//!
//!   1. **`-oA <base>` writes exactly three files**, `.nmap`, `.gnmap`, `.xml`
//!      — suffixes that are not the option letters, and no `-oS` file.
//!   2. **Every output filename has its strftime escapes expanded**, which this
//!      port did not do before M7.9. `-oN scan-%Y%m%d.txt` from cron wrote one
//!      file called `scan-%Y%m%d.txt` and silently overwrote it every night
//!      where the operator had asked for a dated series.
//!   3. **A name that would be a footgun is refused**, with C's wording. A file
//!      whose name starts with `-` is read as a flag by the next shell command
//!      that touches it, which is why C refuses it and names the `./` escape.
//!
//! Filenames and messages here were compared against the installed C nmap.
//!
//! Skipped under Miri (spawns a process, and reads and writes files).
#![cfg(not(miri))]

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_nmap-rs")
}

fn datadir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// A scratch directory of our own, so the assertions can be about *exactly*
/// which files exist rather than about a needle in the repo tree.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("nmap-rs-oa-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn run_in(dir: &std::path::Path, args: &[&str]) -> (String, bool) {
    let out = Command::new(bin())
        .current_dir(dir)
        .env("NMAP_RS_DATADIR", datadir())
        .args(args)
        .output()
        .expect("nmap-rs runs");
    (
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

fn listing(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("read scratch")
        .filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned()))
        .collect();
    v.sort();
    v
}

#[test]
fn oa_writes_exactly_the_three_formats() {
    let dir = scratch("three");
    let (stderr, ok) = run_in(&dir, &["-sL", "-n", "-oA", "base", "127.0.0.1"]);
    assert!(ok, "{stderr}");
    assert_eq!(listing(&dir), ["base.gnmap", "base.nmap", "base.xml"]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Each file must actually carry its own format, not three copies of one.
#[test]
fn each_of_the_three_carries_its_own_format() {
    let dir = scratch("formats");
    let (stderr, ok) = run_in(&dir, &["-sL", "-n", "-oA", "f", "127.0.0.1"]);
    assert!(ok, "{stderr}");
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).expect(n);
    assert!(read("f.nmap").contains("Nmap scan report for 127.0.0.1"));
    assert!(read("f.xml").starts_with("<?xml"));
    assert!(read("f.gnmap").contains("Host: 127.0.0.1"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Property 2, and the regression this milestone exists for. Compared against
/// C nmap, which produces the same names from the same specs.
#[test]
fn strftime_escapes_are_expanded_in_every_output_option() {
    let dir = scratch("escapes");
    // %Y%m%d is a date; asserting the literal spec is absent is the point.
    let (stderr, ok) = run_in(
        &dir,
        &[
            "-sL",
            "-n",
            "-oA",
            "s-%Y%m%d",
            "-oN",
            "n-%F.txt",
            "127.0.0.1",
        ],
    );
    assert!(ok, "{stderr}");
    let files = listing(&dir);
    assert!(
        !files.iter().any(|f| f.contains('%')),
        "an escape survived unexpanded: {files:?}"
    );
    assert!(
        files
            .iter()
            .any(|f| f.starts_with("s-20") && f.ends_with(".xml")),
        "expected s-<date>.xml, got {files:?}"
    );
    assert!(
        files
            .iter()
            .any(|f| f.starts_with("n-20") && f.ends_with(".txt")),
        "expected n-<date>.txt, got {files:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `%%` is a literal `%`, and an unrecognised escape drops the `%` and keeps
/// the letter. Both verified against C.
#[test]
fn the_unusual_escape_rules_match_c() {
    let dir = scratch("odd");
    for (spec, want) in [("p%%l", "p%l"), ("u%Zx", "uZx"), ("t%", "t")] {
        let (stderr, ok) = run_in(&dir, &["-sL", "-n", "-oA", spec, "127.0.0.1"]);
        assert!(ok, "{spec}: {stderr}");
        assert!(
            dir.join(format!("{want}.nmap")).exists(),
            "{spec:?} should have produced {want}.nmap, got {:?}",
            listing(&dir)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Property 3, for all four options. C's wording, including the `./` hint.
#[test]
fn a_leading_dash_is_refused_for_every_output_option() {
    let dir = scratch("dash");
    for opt in ["-oA", "-oN", "-oX", "-oG"] {
        let (stderr, ok) = run_in(&dir, &["-sL", "-n", opt, "-foo", "127.0.0.1"]);
        assert!(!ok, "{opt} -foo must be refused");
        assert!(
            stderr.contains(&format!(
                "Output filename begins with '-'. Try '{opt} ./-foo' if you really want it to be named as such."
            )),
            "{opt}: {stderr}"
        );
    }
    assert!(listing(&dir).is_empty(), "a refusal must write nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `-oA -` is its own refusal: three formats cannot share one stdout. Note the
/// leading-dash check runs first in C, so only a BARE `-` reaches this one.
#[test]
fn oa_to_stdout_is_refused() {
    let dir = scratch("stdout");
    let (stderr, ok) = run_in(&dir, &["-sL", "-n", "-oA", "-", "127.0.0.1"]);
    assert!(!ok);
    assert!(
        stderr.contains("Cannot display multiple output types to stdout."),
        "got: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The escape hatch C's own message recommends has to work.
#[test]
fn the_dot_slash_escape_hatch_works() {
    let dir = scratch("hatch");
    let (stderr, ok) = run_in(&dir, &["-sL", "-n", "-oA", "./-foo", "127.0.0.1"]);
    assert!(ok, "{stderr}");
    assert_eq!(listing(&dir), ["-foo.gnmap", "-foo.nmap", "-foo.xml"]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `-` still means stdout for the single-format options, and must never be
/// expanded into a file named after the clock.
#[test]
fn a_single_format_can_still_go_to_stdout() {
    let dir = scratch("dash-ok");
    let (stderr, ok) = run_in(&dir, &["-sL", "-n", "-oX", "-", "127.0.0.1"]);
    assert!(ok, "{stderr}");
    assert!(listing(&dir).is_empty(), "stdout must not become a file");
    let _ = std::fs::remove_dir_all(&dir);
}

/// All four options share one timestamp, so a `-oA` and a `-oN` in the same
/// command cannot disagree about the date — even if the run straddles midnight.
#[test]
fn every_output_option_shares_one_timestamp() {
    let dir = scratch("stamp");
    let (stderr, ok) = run_in(
        &dir,
        &["-sL", "-n", "-oA", "a-%F", "-oN", "b-%F.txt", "127.0.0.1"],
    );
    assert!(ok, "{stderr}");
    let files = listing(&dir);
    let date_of = |prefix: &str| -> String {
        files
            .iter()
            .find(|f| f.starts_with(prefix))
            .map(|f| f[prefix.len()..prefix.len() + 10].to_string())
            .unwrap_or_default()
    };
    assert_eq!(date_of("a-"), date_of("b-"), "files: {files:?}");
    assert!(!date_of("a-").is_empty(), "files: {files:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
