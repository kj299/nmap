//! Raw port scans over IPv6 are not ported (`ipv6-raw-port-scans-unported`):
//! every raw driver sends IPv4. Until FreeBSD step e, `-6 -sS` sent nothing and
//! reported the host with no ports and no word of why. Every raw scan type now
//! says so and connect-scans, as a raw scan without privilege does.
//!
//! Skipped under Miri (spawns a process).
#![cfg(not(miri))]

use std::process::Command;

/// `(stdout, stderr)` from one invocation.
fn run(args: &[&str]) -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
        .args(args)
        .output()
        .expect("nmap-rs runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const WARNING: &str = "raw IPv6 port scans are not ported yet; running a connect scan (-sT)";

#[test]
fn a_raw_ipv6_port_scan_says_so_and_connect_scans() {
    for scan in ["-sS", "-sU", "-sA", "-sW", "-sM", "-sF", "-sN", "-sX"] {
        let (stdout, stderr) = run(&["-6", scan, "-Pn", "-n", "-p", "1", "::1"]);
        assert!(stderr.contains(WARNING), "{scan}: {stderr}");
        // The connect scan ran: port 1 is reported, in whatever state this
        // host gives it (closed, or filtered where there is no IPv6).
        assert!(stdout.contains("1/tcp"), "{scan}: {stdout}");
    }
}

#[test]
fn a_connect_scan_and_ipv4_raw_scans_do_not_warn() {
    let (_, stderr) = run(&["-6", "-sT", "-Pn", "-n", "-p", "1", "::1"]);
    assert!(!stderr.contains(WARNING), "{stderr}");
    // IPv4 raw scans keep their own paths (and their own fallbacks).
    let (_, stderr) = run(&["-sS", "-Pn", "-n", "-p", "1", "127.0.0.1"]);
    assert!(!stderr.contains(WARNING), "{stderr}");
}
