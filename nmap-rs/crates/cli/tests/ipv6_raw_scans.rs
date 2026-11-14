//! Raw IPv6 port scans run for every IPv6 target (IPv6 scans step e). Until FreeBSD
//! step e, `-6 -sS` sent nothing and reported the host with no ports and no word of
//! why; from then until IPv6 scans step d every raw scan type connect-scanned instead
//! and said so, and until step e every target beyond this host still did
//! (`ipv6-raw-port-scans-unported`, resolved). No raw scan falls back for being IPv6
//! now: it runs, or falls back for want of privilege (or of a pcap build), with that
//! reason.
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

const RAW_SCANS: [&str; 8] = ["-sS", "-sU", "-sA", "-sW", "-sM", "-sF", "-sN", "-sX"];

/// `::1` goes over the loopback; 2001:db8::/32 is for documentation (RFC 3849), never
/// this host, and routed (or not) like any other host.
#[test]
fn no_raw_ipv6_scan_falls_back_for_being_ipv6() {
    for target in ["::1", "2001:db8::1"] {
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
                target,
            ]);
            assert!(
                !stderr.contains("raw IPv6 port scans"),
                "{scan} {target}: {stderr}"
            );
            assert!(stdout.contains("Nmap done"), "{scan} {target}: {stdout}");
            if target == "::1" {
                // Port 1 is reported, by the raw scan or its privilege fallback.
                assert!(
                    stdout.contains("1/tcp") || stdout.contains("1/udp"),
                    "{scan}: {stdout}"
                );
            }
        }
    }
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
