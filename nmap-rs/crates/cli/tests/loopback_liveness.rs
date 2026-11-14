//! A raw scan's loopback target is up before any probe is sent. 7.94 marks every
//! target on a loopback route up (`targets.cc:588`), as `localhost-response`, or
//! `user-set` under `-Pn`, so its ports cannot make it down
//! (`loopback-target-localhost-response`).
//!
//! Needs root, for the raw scan: `#[ignore]` + self-skip without it. With
//! `REQUIRE_RAW=1` (as CI runs it) a fallback fails instead. The `::1` half skips
//! on a host without IPv6, unless `REQUIRE_IPV6=1`. Run as root:
//! `sudo -E cargo test -p nmap-cli --all-features --test loopback_liveness -- --ignored`.
//!
//! Skipped under Miri (spawns a process).
#![cfg(not(miri))]

use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
use std::process::Command;

/// stdout, or `None` (a skip) when the scan could not run raw.
fn run_raw(args: &[&str]) -> Option<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
        .args(args)
        .output()
        .expect("nmap-rs runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("falling back to a") || stderr.contains("lacks raw-scan support") {
        assert!(
            std::env::var_os("REQUIRE_RAW").is_none(),
            "REQUIRE_RAW is set, but the scan did not run raw: {stderr}"
        );
        eprintln!("skipping the loopback liveness check: {stderr}");
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A FIN probe to a listener draws no reply, so `open|filtered` is the port's only
/// state. Before, that made the host down: hidden without `-v`, with "Host seems down".
#[test]
#[ignore = "needs root"]
fn a_loopback_target_is_up_whatever_its_ports_say() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let scan = |pn: bool| {
        let mut args = vec!["-sF", "-n", "--reason", "-T4", "-p", &port, "127.0.0.1"];
        if pn {
            args.insert(1, "-Pn");
        }
        run_raw(&args)
    };

    let Some(out) = scan(false) else { return };
    assert!(
        out.contains("Host is up, received localhost-response."),
        "{out}"
    );
    assert!(out.contains(&format!("{port}/tcp open|filtered")), "{out}");
    assert!(out.contains("(1 host up)"), "{out}");
    assert!(!out.contains("Host seems down"), "{out}");

    let Some(out) = scan(true) else { return };
    assert!(out.contains("Host is up, received user-set."), "{out}");
    drop(listener);
}

/// The same over IPv6, on `::1`, which step d brought onto the engine: its own
/// route-groups take the same verdict.
#[test]
#[ignore = "needs root"]
fn an_ipv6_loopback_target_is_up_whatever_its_ports_say() {
    let listener = match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
        Ok(l) => l,
        Err(e) => {
            assert!(
                std::env::var_os("REQUIRE_IPV6").is_none(),
                "REQUIRE_IPV6 is set, but ::1 is unusable: {e}"
            );
            eprintln!("skipping the ::1 liveness check: {e}");
            return;
        }
    };
    let port = listener.local_addr().unwrap().port().to_string();
    let scan = |pn: bool| {
        let mut args = vec!["-6", "-sF", "-n", "--reason", "-T4", "-p", &port, "::1"];
        if pn {
            args.insert(1, "-Pn");
        }
        run_raw(&args)
    };

    let Some(out) = scan(false) else { return };
    assert!(
        out.contains("Host is up, received localhost-response."),
        "{out}"
    );
    assert!(out.contains(&format!("{port}/tcp open|filtered")), "{out}");
    assert!(out.contains("(1 host up)"), "{out}");

    let Some(out) = scan(true) else { return };
    assert!(out.contains("Host is up, received user-set."), "{out}");
    drop(listener);
}
