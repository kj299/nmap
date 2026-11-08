//! Raw IPv6 port scans reach this host's own addresses so far (IPv6 scans step d):
//! `::1` and an address of its own go over a loopback, where no neighbor has to be
//! discovered. Any other IPv6 target needs Ethernet framing and neighbor discovery,
//! not ported yet (`ipv6-raw-port-scans-unported`, step e). Until FreeBSD step e,
//! `-6 -sS` sent nothing and reported the host with no ports and no word of why;
//! from then until step d every raw scan type said so and connect-scanned. Now only
//! a target beyond this host does.
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

const WARNING: &str =
    "raw IPv6 port scans reach only this host's own addresses so far; running a connect scan (-sT)";

const RAW_SCANS: [&str; 8] = ["-sS", "-sU", "-sA", "-sW", "-sM", "-sF", "-sN", "-sX"];

/// 2001:db8::/32 is for documentation (RFC 3849): never this host, never a loopback.
#[test]
fn a_raw_ipv6_port_scan_beyond_this_host_says_so_and_connect_scans() {
    for scan in RAW_SCANS {
        let (stdout, stderr) = run(&["-6", scan, "-Pn", "-n", "-T5", "-p", "1", "2001:db8::1"]);
        assert!(stderr.contains(WARNING), "{scan}: {stderr}");
        // The connect scan ran: port 1 is reported, in whatever state this
        // host's network gives it.
        assert!(stdout.contains("1/tcp"), "{scan}: {stdout}");
    }
}

/// `::1` goes over the loopback: the raw scan runs (as root), or falls back for
/// want of privilege (or of a pcap build) with that reason, never this warning.
#[test]
fn a_raw_ipv6_port_scan_of_this_host_does_not_fall_back_for_ipv6() {
    for scan in RAW_SCANS {
        let (stdout, stderr) = run(&[
            "-6",
            scan,
            "-Pn",
            "-n",
            "-T5",
            "--max-retries",
            "0",
            "-p",
            "1",
            "::1",
        ]);
        assert!(!stderr.contains(WARNING), "{scan}: {stderr}");
        // Port 1 is reported, by the raw scan or its fallback.
        assert!(
            stdout.contains("1/tcp") || stdout.contains("1/udp"),
            "{scan}: {stdout}"
        );
    }
}

#[test]
fn a_connect_scan_and_ipv4_raw_scans_do_not_warn() {
    let (_, stderr) = run(&["-6", "-sT", "-Pn", "-n", "-p", "1", "2001:db8::1"]);
    assert!(!stderr.contains(WARNING), "{stderr}");
    // IPv4 raw scans keep their own paths (and their own fallbacks).
    let (_, stderr) = run(&["-sS", "-Pn", "-n", "-p", "1", "127.0.0.1"]);
    assert!(!stderr.contains(WARNING), "{stderr}");
}

/// With `-6`, `-S` names an IPv6 source, as nmap resolves it in the scan's
/// family (`nmap.cc:1463`); an IPv4 one is refused rather than ignored.
#[test]
fn ipv6_spoof_source_is_read_in_the_scans_family() {
    let (_, stderr) = run(&[
        "-6",
        "-sS",
        "-S",
        "192.0.2.9",
        "-Pn",
        "-n",
        "-p",
        "1",
        "::1",
    ]);
    assert!(stderr.contains("-S expects an IPv6 address"), "{stderr}");
    let (_, stderr) = run(&[
        "-sS",
        "-S",
        "2001:db8::9",
        "-Pn",
        "-n",
        "-p",
        "1",
        "127.0.0.1",
    ]);
    assert!(stderr.contains("-S expects an IPv4 address"), "{stderr}");
}
