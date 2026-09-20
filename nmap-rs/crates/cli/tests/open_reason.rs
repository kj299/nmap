//! `--open` and `--reason`, and the port-listing threshold they exposed.
//!
//! The headline is not either flag. It is that **this port always behaved as
//! though `--open` had been given**: every non-open port was summarized into
//! "Not shown" however few there were, where C lists them until a state exceeds
//! 25. That was ledgered in M1 as an "intentional MVP renderer abbreviation"
//! and survived nine milestones, because the differential's projection
//! canonicalized both representations to a count and so could not see it.
//! Implementing the flag that is *supposed* to produce that behaviour is what
//! forced the question.
//!
//! Every expectation here was compared against the installed C nmap.
//!
//! Skipped under Miri (spawns a process).
#![cfg(not(miri))]

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_nmap-rs")
}

fn datadir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn run(args: &[&str]) -> (String, String, bool) {
    let out = Command::new(bin())
        .env("NMAP_RS_DATADIR", datadir())
        .args(args)
        .output()
        .expect("nmap-rs runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

/// Bind a port and keep accepting until the handle is dropped, so `--open` has
/// something to preserve.
///
/// The ports used here (20101+) are deliberately OUTSIDE the 20001-20040 range
/// the threshold tests scan: cargo runs these concurrently, and a listener
/// inside that range turns a "closed" port open under another test's feet. Returns None if the port is already in use, in which
/// case the caller skips rather than asserting on a scan of nothing.
fn listener(port: u16) -> Option<std::net::TcpListener> {
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).ok()?;
    let accept = l.try_clone().ok()?;
    std::thread::spawn(move || {
        for s in accept.incoming().take(256).flatten() {
            drop(s);
        }
    });
    Some(l)
}

/// The table's header line, whitespace-collapsed, so assertions are about
/// column ORDER rather than about padding that varies with the widest cell.
fn header(stdout: &str) -> String {
    stdout
        .lines()
        .find(|l| l.starts_with("PORT"))
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Ports listed individually in the table (not the "Not shown" summary).
fn listed(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|l| {
            l.split('/')
                .next()
                .is_some_and(|p| p.parse::<u16>().is_ok())
                && l.contains("/tcp")
        })
        .map(|l| l.split_whitespace().next().unwrap_or("").to_string())
        .collect()
}

/// A closed port below the threshold is LISTED, and therefore must not also be
/// claimed as hidden. This is the assertion that would have failed for every
/// milestone before M7.10.
#[test]
fn a_few_closed_ports_are_listed_not_summarized() {
    let (stdout, stderr, ok) = run(&["-sT", "-Pn", "-n", "-p", "20001-20004", "127.0.0.1"]);
    assert!(ok, "{stderr}");
    assert_eq!(
        listed(&stdout).len(),
        4,
        "all four should be listed:\n{stdout}"
    );
    assert!(
        !stdout.contains("Not shown:"),
        "listed ports must not also be summarized:\n{stdout}"
    );
}

/// Past the threshold, C summarizes — and so must this. 25 listed, 26 not:
/// verified against the reference at exactly that boundary.
#[test]
fn the_listing_threshold_is_twenty_five() {
    let (a, _, ok) = run(&["-sT", "-Pn", "-n", "-p", "20001-20025", "127.0.0.1"]);
    assert!(ok);
    assert_eq!(listed(&a).len(), 25, "25 closed ports are listed:\n{a}");

    let (b, _, ok) = run(&["-sT", "-Pn", "-n", "-p", "20001-20026", "127.0.0.1"]);
    assert!(ok);
    assert_eq!(listed(&b).len(), 0, "26 are summarized:\n{b}");
    assert!(b.contains("Not shown: 26 closed tcp ports"), "{b}");
}

/// `-v` raises the threshold, exactly as C scales it.
#[test]
fn verbosity_raises_the_threshold() {
    let (quiet, _, _) = run(&["-sT", "-Pn", "-n", "-p", "20001-20040", "127.0.0.1"]);
    assert_eq!(listed(&quiet).len(), 0, "40 > 25, so summarized:\n{quiet}");

    let (loud, _, _) = run(&["-sT", "-Pn", "-n", "-v", "-p", "20001-20040", "127.0.0.1"]);
    assert_eq!(listed(&loud).len(), 40, "-v raises it past 40:\n{loud}");
}

/// `--open` forces the summary however few ports there are — the flag's job,
/// and what this port used to do unconditionally.
#[test]
fn open_only_summarizes_regardless_of_count() {
    // One open port, so the host is reported at all — with none, `--open`
    // suppresses the whole host and there is no table to inspect.
    let Some(_l) = listener(20101) else {
        return;
    };
    let (stdout, stderr, ok) = run(&[
        "-sT",
        "-Pn",
        "-n",
        "--open",
        "-p",
        "20001-20004,20101",
        "127.0.0.1",
    ]);
    assert!(ok, "{stderr}");
    assert_eq!(listed(&stdout), ["20101/tcp"], "{stdout}");
    assert!(stdout.contains("Not shown: 4 closed tcp ports"), "{stdout}");
}

/// `--open` drops a host with no open ports from the report entirely, while
/// still counting it as up. C: "--open means don't show any hosts without open
/// ports" (`nmap.cc:2312`), which skips only the printing.
#[test]
fn open_only_hides_a_host_with_nothing_open() {
    let (stdout, stderr, ok) = run(&["-sT", "-Pn", "-n", "--open", "-p", "20001", "127.0.0.1"]);
    assert!(ok, "{stderr}");
    assert!(
        !stdout.contains("Nmap scan report"),
        "the host should be hidden:\n{stdout}"
    );
    assert!(
        stdout.contains("(1 host up)"),
        "hidden is not un-found:\n{stdout}"
    );
}

/// `--reason` adds the REASON column between SERVICE and VERSION, and names
/// what established the host's liveness. `-Pn` means the operator asserted it,
/// so C reports `user-set` rather than inventing a packet reason.
#[test]
fn reason_adds_the_column_and_the_host_reason() {
    let (stdout, stderr, ok) = run(&[
        "-sT",
        "-Pn",
        "-n",
        "--reason",
        "-p",
        "20001-20002",
        "127.0.0.1",
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("Host is up, received user-set."),
        "{stdout}"
    );
    // REASON sits between SERVICE and VERSION, not appended. Compared by
    // column order rather than by padding, which varies with the widest cell.
    assert_eq!(header(&stdout), "PORT STATE SERVICE REASON", "{stdout}");
    assert!(stdout.contains("conn-refused"), "{stdout}");
}

/// Without the flag, nothing changes — `--reason` controls the rendering, not
/// the collection. The reason is already in the XML either way.
#[test]
fn without_reason_the_column_is_absent_but_the_xml_still_carries_it() {
    let (stdout, _, ok) = run(&["-sT", "-Pn", "-n", "-p", "20001", "127.0.0.1"]);
    assert!(ok);
    assert!(!stdout.contains("REASON"), "{stdout}");
    assert!(stdout.contains("Host is up."), "{stdout}");

    let (xml, _, ok) = run(&["-sT", "-Pn", "-n", "-oX", "-", "-p", "20001", "127.0.0.1"]);
    assert!(ok);
    assert!(
        xml.contains("reason=\"conn-refused\""),
        "XML carries the reason regardless of the flag:\n{xml}"
    );
}

/// The two flags compose: only open ports, with reasons.
#[test]
fn open_and_reason_compose() {
    let Some(_l) = listener(20102) else {
        return;
    };
    let (stdout, _, ok) = run(&[
        "-sT",
        "-Pn",
        "-n",
        "--open",
        "--reason",
        "-p",
        "20001-20004,20102",
        "127.0.0.1",
    ]);
    assert!(ok);
    assert!(stdout.contains("Not shown: 4 closed tcp ports"), "{stdout}");
    assert!(
        stdout.contains("Host is up, received user-set."),
        "{stdout}"
    );
    assert_eq!(header(&stdout), "PORT STATE SERVICE REASON", "{stdout}");
    assert_eq!(listed(&stdout), ["20102/tcp"], "{stdout}");
}
