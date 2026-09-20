//! `--top-ports`, `--port-ratio`, `-F`, `--exclude-ports`, `--allports` end to
//! end, plus the `nmap-service-probes` `Exclude` directive they sit alongside.
//!
//! The identity of the selected port sets is checked against C nmap's own
//! `--packet-trace` output by the unit tests in `main.rs`; these cover what
//! that cannot — refusals, exit codes, and the `-sV` exclusion.
//!
//! Every message asserted here was compared against the installed C nmap.
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

/// Every refusal in this group, with C's exact wording. The two `gettoppts`
/// ones are deferred past the parse in C — `--port-ratio 0` passes the
/// parse-time range test and dies later — and are deferred here too, so the
/// message an operator sees is the one they would search for.
#[test]
fn refusals_match_c_word_for_word() {
    for (args, expect) in [
        (vec!["--top-ports", "5.5"], "--top-ports should be an integer 1 or greater"),
        (vec!["--top-ports", "abc"], "--top-ports should be an integer 1 or greater"),
        (vec!["--top-ports", "0"], "--top-ports should be an integer 1 or greater"),
        (vec!["--port-ratio", "1"], "--port-ratio should be between [0 and 1)"),
        (vec!["--port-ratio", "-0.1"], "--port-ratio should be between [0 and 1)"),
        (
            vec!["--port-ratio", "0"],
            "Argument to gettoppts (0) should be a positive ratio below 1 or an integer of 1 or higher",
        ),
        (
            vec!["--top-ports", "65537"],
            "Level argument to gettoppts (65537) is too large",
        ),
        (
            vec!["-F", "-p", "80"],
            "You cannot use -F (fast scan) with -p (explicit port selection) but see --top-ports and --port-ratio to fast scan a range of ports",
        ),
        (
            vec!["--exclude-ports", "1", "--exclude-ports", "2"],
            "Only 1 --exclude-ports option allowed, separate multiple ranges with commas.",
        ),
    ] {
        let mut full = args.clone();
        full.extend_from_slice(&["-sT", "-Pn", "-n", "127.0.0.1"]);
        let (stdout, stderr, ok) = run(&full);
        assert!(!ok, "{args:?} must be refused");
        assert!(stderr.contains(expect), "{args:?}:\n  want {expect}\n  got  {stderr}");
        assert!(!stdout.contains("Nmap scan report"), "{args:?} scanned anyway");
    }
}

/// `-F` and `-p` both mean "not a port scan" when combined with `-sL`.
#[test]
fn fast_scan_with_a_list_scan_is_refused() {
    let (_, stderr, ok) = run(&["-sL", "-F", "-n", "127.0.0.1"]);
    assert!(!ok);
    assert!(
        stderr.contains(
            "You cannot use -F (fast scan) or -p (explicit port selection) when not doing a port scan"
        ),
        "got: {stderr}"
    );
}

/// Because `strtod` parses the number, a trailing tail is ignored and a hex
/// literal works. Both confirmed against the reference; both are consequences
/// of C using `strtod` rather than a stricter reader, and neither is something
/// a hand-written parser would have produced.
#[test]
fn strtod_shaped_arguments_are_accepted_as_c_accepts_them() {
    for args in [
        vec!["--top-ports", "5abc"],
        vec!["--top-ports", "0x10"],
        vec!["--port-ratio", "0.5abc"],
    ] {
        let mut full = args.clone();
        full.extend_from_slice(&["-sT", "-Pn", "-n", "127.0.0.1"]);
        let (_, stderr, ok) = run(&full);
        assert!(ok, "{args:?} is accepted by C nmap: {stderr}");
    }
}

/// The count of ports actually scanned, read back out of the report. This is
/// the end-to-end check that the selection reaches the scan rather than being
/// computed and dropped.
fn scanned_count(args: &[&str]) -> usize {
    let mut full = args.to_vec();
    full.extend_from_slice(&["-sT", "-Pn", "-n", "127.0.0.1"]);
    let (stdout, stderr, ok) = run(&full);
    assert!(ok, "{args:?}: {stderr}");
    let not_shown = stdout
        .lines()
        .find_map(|l| {
            l.strip_prefix("Not shown: ")
                .and_then(|r| r.split_whitespace().next())
                .and_then(|n| n.parse::<usize>().ok())
        })
        .unwrap_or(0);
    let listed = stdout
        .lines()
        .filter(|l| l.contains("/tcp") && l.contains("open"))
        .count();
    not_shown.saturating_add(listed)
}

#[test]
fn the_selection_reaches_the_scan() {
    assert_eq!(scanned_count(&["--top-ports", "10"]), 10);
    assert_eq!(scanned_count(&["-F"]), 100);
    assert_eq!(scanned_count(&["--port-ratio", "0.01"]), 36);
    // Excluded first, then cut: still 20, backfilled.
    assert_eq!(
        scanned_count(&["--top-ports", "20", "--exclude-ports", "80,443"]),
        20
    );
    assert_eq!(
        scanned_count(&["-p", "20-30", "--exclude-ports", "22-25"]),
        7
    );
}

// ---- the nmap-service-probes Exclude directive -----------------------------

/// `nmap-service-probes` opens with `Exclude T:9100-9107`. Those are JetDirect
/// printer ports, where a version probe is not a read but a *print job* — which
/// is why nmap refuses to probe them by default and why `--allports` exists.
///
/// This port parsed the directive from M3 on and unit-tested it
/// (`probedb::is_excluded(9100, Tcp)` passes), and then called it from nowhere.
/// So `-sV` here behaved exactly like C's `-sV --allports`:
///
/// ```text
///     C: 9100/tcp open  jetdirect?     <- no probes sent
///  ours: 9100/tcp open  tcpwrapped     <- a probe RESULT
/// ```
///
/// A parser test that never checks the behaviour is the shape of LESSONS #027,
/// and this was the sharpest instance of it in the port. These tests assert the
/// behaviour.
///
/// Each spawns a listener on 9100 so there is something to report at all.
mod service_probe_exclusions {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// Serve 9100 until the returned handle is dropped.
    fn listener_9100() -> Option<TcpListener> {
        let l = TcpListener::bind("127.0.0.1:9100").ok()?;
        let accept = l.try_clone().ok()?;
        std::thread::spawn(move || {
            for mut s in accept.incoming().take(64).flatten() {
                let _ = s.write_all(b"");
            }
        });
        Some(l)
    }

    fn port_line(stdout: &str) -> String {
        stdout
            .lines()
            .find(|l| l.starts_with("9100/tcp"))
            .unwrap_or("<no 9100 line>")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn version_detection_skips_an_excluded_port() {
        let Some(_l) = listener_9100() else {
            return; // port in use on this machine; nothing to assert
        };
        let (stdout, stderr, ok) = run(&["-sV", "-Pn", "-n", "-p", "9100", "127.0.0.1"]);
        assert!(ok, "{stderr}");
        let line = port_line(&stdout);
        // The name comes from nmap-services, and the `?` says so: nothing was
        // confirmed, because nothing was probed. C prints exactly this.
        assert!(
            line.contains("jetdirect?"),
            "expected the unconfirmed table name, got: {line}"
        );
        assert!(
            !line.contains("tcpwrapped"),
            "tcpwrapped is a PROBE RESULT — the exclusion was not honoured: {line}"
        );
    }

    /// `--allports` is the override, and it must actually override — otherwise
    /// the flag is decoration.
    #[test]
    fn allports_overrides_the_exclusion() {
        let Some(_l) = listener_9100() else {
            return;
        };
        let (stdout, stderr, ok) =
            run(&["-sV", "--allports", "-Pn", "-n", "-p", "9100", "127.0.0.1"]);
        assert!(ok, "{stderr}");
        let line = port_line(&stdout);
        assert!(
            !line.contains("jetdirect?"),
            "--allports should have probed it: {line}"
        );
    }

    /// Without `-sV` there is no probe to skip, so no `?` — the name is just
    /// the table lookup it has always been, and the exclusion is irrelevant.
    #[test]
    fn without_version_detection_the_name_is_unmarked() {
        let Some(_l) = listener_9100() else {
            return;
        };
        let (stdout, stderr, ok) = run(&["-Pn", "-n", "-p", "9100", "127.0.0.1"]);
        assert!(ok, "{stderr}");
        let line = port_line(&stdout);
        assert!(line.contains("jetdirect"), "got: {line}");
        assert!(!line.contains('?'), "no -sV was requested: {line}");
    }
}
