//! The run is scanned and reported host group by host group (M7 cutover step b).
//!
//! 7.94 scans a run's targets in host groups (`core::hostgroup`), writes each
//! group's hosts when the group is done, and its totals at the end. These tests
//! run the binary and check that it does the same: the sizes the groups take,
//! that the three formats stay whole across groups, and that a group's hosts are
//! in the output files before the next group is scanned. Group sizes are read
//! from `-d`'s "host group k: n host(s)" line.
//!
//! The routed half needs root (`#[ignore]` + self-skip without it; `REQUIRE_RAW=1`
//! makes a fallback fail) and an IPv4 address of this host's own:
//! `sudo -E cargo test -p nmap-cli --all-features --test hostgroups -- --ignored`.
//!
//! Skipped under Miri (spawns a process).
#![cfg(not(miri))]

use std::net::{Ipv4Addr, TcpListener};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_nmap-rs")
}

/// (stdout, stderr, success).
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

/// The sizes of the groups the run formed, from `-d`.
fn sizes(stderr: &str) -> Vec<usize> {
    stderr
        .lines()
        .filter_map(|l| l.split_once("] host group ").map(|(_, r)| r))
        .filter_map(|r| r.split_once(": ")?.1.split(' ').next()?.parse().ok())
        .collect()
}

/// The addresses in report order.
fn reports(normal: &str) -> Vec<String> {
    normal
        .lines()
        .filter_map(|l| l.strip_prefix("Nmap scan report for "))
        .map(|r| r.split(' ').next().unwrap_or(r).to_string())
        .collect()
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("nmap-rs-hostgroups-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// `--max-hostgroup` bounds every group; the default for a one-port connect
/// scan is one group of up to 1,024 (`max(1024 / ports, 64)`).
#[test]
fn the_groups_take_the_sizes_7_94_gives_them() {
    let (out, err, ok) = run(&[
        "-d",
        "-sT",
        "-Pn",
        "-n",
        "-p",
        "1",
        "--max-hostgroup",
        "2",
        "127.0.0.1-5",
    ]);
    assert!(ok, "{err}");
    assert_eq!(sizes(&err), [2, 2, 1], "{err}");
    assert_eq!(
        reports(&out),
        [
            "127.0.0.1",
            "127.0.0.2",
            "127.0.0.3",
            "127.0.0.4",
            "127.0.0.5"
        ]
    );
    assert!(
        out.contains("Nmap done: 5 IP addresses (5 hosts up) scanned in "),
        "{out}"
    );

    let (_, err, ok) = run(&["-d", "-sT", "-Pn", "-n", "-p", "1", "127.0.0.1-5"]);
    assert!(ok, "{err}");
    assert_eq!(sizes(&err), [5], "{err}");

    // --min-hostgroup raises a group past the size rule: a list scan is
    // neither TCP nor UDP, so 16, boxed up to 100. (7.94 reports a list
    // scan's hosts as it draws them; the groups here change nothing visible.)
    let (_, err, ok) = run(&["-d", "-sL", "-n", "--min-hostgroup", "100", "10.0.0.1-130"]);
    assert!(ok, "{err}");
    assert_eq!(sizes(&err), [100, 30], "{err}");
}

/// Written group by group, every format is still one report: one header, one
/// footer, every host once, in order, with totals over every group.
#[test]
fn every_format_is_whole_across_groups() {
    let (n, x, g) = (scratch("w.nmap"), scratch("w.xml"), scratch("w.gnmap"));
    let (out, err, ok) = run(&[
        "-sT",
        "-Pn",
        "-n",
        "-p",
        "1",
        "--max-hostgroup",
        "2",
        "-oN",
        n.to_str().unwrap(),
        "-oX",
        x.to_str().unwrap(),
        "-oG",
        g.to_str().unwrap(),
        "127.0.0.1-5",
    ]);
    assert!(ok, "{err}");
    let normal = std::fs::read_to_string(&n).unwrap();
    let xml = std::fs::read_to_string(&x).unwrap();
    let grep = std::fs::read_to_string(&g).unwrap();
    let five = [
        "127.0.0.1",
        "127.0.0.2",
        "127.0.0.3",
        "127.0.0.4",
        "127.0.0.5",
    ];

    assert_eq!(reports(&out), five);
    assert_eq!(reports(&normal), five);
    assert_eq!(normal.matches("Starting nmap-rs").count(), 1, "{normal}");
    assert_eq!(normal.matches("Nmap done:").count(), 1, "{normal}");
    assert!(
        normal.contains("Nmap done: 5 IP addresses (5 hosts up)"),
        "{normal}"
    );

    assert_eq!(xml.matches("<?xml").count(), 1, "{xml}");
    assert_eq!(xml.matches("<nmaprun ").count(), 1, "{xml}");
    assert_eq!(xml.matches("<host>").count(), 5, "{xml}");
    assert_eq!(xml.matches("</host>").count(), 5, "{xml}");
    assert!(
        xml.contains("<hosts up=\"5\" down=\"0\" total=\"5\"/>"),
        "{xml}"
    );
    assert!(xml.ends_with("</nmaprun>\n"), "{xml}");
    let order: Vec<&str> = xml
        .match_indices("<address addr=\"")
        .map(|(i, m)| {
            let rest = &xml[i + m.len()..];
            &rest[..rest.find('"').unwrap()]
        })
        .collect();
    assert_eq!(order, five);

    assert!(grep.starts_with("# nmap-rs"), "{grep}");
    assert_eq!(grep.matches("Status: Up").count(), 5, "{grep}");
    assert!(
        grep.trim_end().ends_with("-- 5 IP address scanned"),
        "{grep}"
    );
}

/// A group's hosts are on disk before the next group is scanned: the
/// `-oN` file holds the first report while the run is still going.
#[test]
fn a_group_is_written_before_the_next_is_scanned() {
    // Two ports, so --scan-delay paces each one-host group: three groups of
    // at least one delay each.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let ports = format!("{port},1");
    let n = scratch("stream.nmap");
    let mut child = Command::new(bin())
        .args([
            "-sT",
            "-Pn",
            "-n",
            "-p",
            &ports,
            "--scan-delay",
            "1500ms",
            "--max-hostgroup",
            "1",
            "-oN",
            n.to_str().unwrap(),
            "127.0.0.1",
            "127.0.0.2",
            "127.0.0.3",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("nmap-rs runs");
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut seen_while_running = false;
    while Instant::now() < deadline {
        let text = std::fs::read_to_string(&n).unwrap_or_default();
        let running = child.try_wait().expect("child state").is_none();
        if text.contains("Nmap scan report for 127.0.0.1") {
            seen_while_running = running && !text.contains("Nmap done");
            break;
        }
        if !running {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let status = child.wait().expect("child exits");
    assert!(status.success());
    assert!(
        seen_while_running,
        "the first group's report was not in the file before the run ended"
    );
    let text = std::fs::read_to_string(&n).unwrap();
    assert_eq!(reports(&text), ["127.0.0.1", "127.0.0.2", "127.0.0.3"]);
}

/// An output path that cannot be written ends the run before anything runs,
/// as 7.94 fails at once: the pre-scan script here sleeps three seconds, and
/// the run must end well before it would wake.
#[test]
fn an_unwritable_output_fails_before_anything_runs() {
    let script = scratch("slowpre.nse");
    std::fs::write(
        &script,
        "description = 'x'\ncategories = {'safe'}\nlocal stdnse = require 'stdnse'\nprerule = function() return true end\naction = function() stdnse.sleep(3) return 'slept' end\n",
    )
    .unwrap();
    let started = Instant::now();
    let (out, err, ok) = run(&[
        "-sT",
        "-Pn",
        "-n",
        "-p",
        "1",
        "--script",
        script.to_str().unwrap(),
        "-oX",
        "/nonexistent-dir/x.xml",
        "127.0.0.1",
    ]);
    // And ahead of the engine itself: with a script that cannot load, the
    // output path is still what fails.
    let (_, err2, ok2) = run(&[
        "-sT",
        "-Pn",
        "-n",
        "-p",
        "1",
        "--script",
        "no-such-script-anywhere",
        "-oX",
        "/nonexistent-dir/x.xml",
        "127.0.0.1",
    ]);
    assert!(
        !ok2 && err2.contains("failed to open output") && !err2.contains("NSE"),
        "{err2}"
    );
    let took = started.elapsed();
    assert!(!ok, "{err}");
    assert!(err.contains("failed to open output"), "{err}");
    assert!(
        !err.contains("NSE"),
        "the script engine started first: {err}"
    );
    assert!(
        took < Duration::from_millis(2500),
        "the pre-scan script ran first: {took:?}"
    );
    assert!(!out.contains("Nmap scan report"), "{out}");
}

/// This host's own non-loopback IPv4 address, if it has one.
fn own_address() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    // No packet is sent: connecting a UDP socket only picks a route.
    s.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(a) if !a.is_loopback() => Some(a),
        _ => None,
    }
}

/// A routed run's groups share a source and hold no address twice: 7.94 gives
/// `-sS` over `127.0.0.1 <own> 127.0.0.2` groups of 2 and 1, and reports the
/// third target before the second (`hostgroup_golden.txt`).
#[test]
#[ignore = "needs root"]
fn a_routed_run_groups_by_route() {
    let Some(own) = own_address() else {
        eprintln!("skipping: no non-loopback IPv4 address here");
        return;
    };
    let own = own.to_string();
    let (out, err, ok) = run(&[
        "-d",
        "-sS",
        "-Pn",
        "-n",
        "-p",
        "1",
        "127.0.0.1",
        &own,
        "127.0.0.2",
    ]);
    if err.contains("falling back to a") || err.contains("lacks raw-scan support") {
        assert!(
            std::env::var_os("REQUIRE_RAW").is_none(),
            "REQUIRE_RAW is set, but the scan did not run raw: {err}"
        );
        eprintln!("skipping the routed grouping check: {err}");
        return;
    }
    assert!(ok, "{err}");
    assert_eq!(sizes(&err), [2, 1], "{err}");
    assert_eq!(reports(&out), ["127.0.0.1", "127.0.0.2", own.as_str()]);

    // A connect scan without `-Pn` is routed too, its pings being raw
    // (`RawScan()`, `NmapOps.cc:354-358`): 7.94 scans the loopback pair, then
    // 192.0.2.2 alone (*measured*).
    let (out, err, ok) = run(&["-d", "-sT", "-n", "-p", "1", "127.0.0.1", &own, "127.0.0.2"]);
    assert!(ok, "{err}");
    assert_eq!(sizes(&err), [2, 1], "{err}");
    assert_eq!(reports(&out), ["127.0.0.1", "127.0.0.2", own.as_str()]);

    // A connect scan does not honour `-S`, so `-S` does not key its groups:
    // the same two as without it. 7.94 here forces `-S`'s device, whose
    // routes split the same way (`spoof-source-groups-by-route`).
    let (_, err, ok) = run(&[
        "-d",
        "-sT",
        "-n",
        "-S",
        &own,
        "-p",
        "1",
        "127.0.0.1",
        &own,
        "127.0.0.2",
    ]);
    assert!(ok, "{err}");
    assert_eq!(sizes(&err), [2, 1], "{err}");

    // A list scan routes nothing (its ping type is none, `nmap.cc:1307`, so
    // `RawScan()` is false): input order, as 7.94 lists them (*measured*).
    let (out, err, ok) = run(&["-sL", "-n", "127.0.0.1", &own, "127.0.0.2"]);
    assert!(ok, "{err}");
    assert_eq!(reports(&out), ["127.0.0.1", own.as_str(), "127.0.0.2"]);

    // A repeated address waits for a later group.
    let (out, err, ok) = run(&[
        "-d",
        "-sS",
        "-Pn",
        "-n",
        "-p",
        "1",
        "127.0.0.1",
        "127.0.0.1",
        "127.0.0.2",
    ]);
    assert!(ok, "{err}");
    assert_eq!(sizes(&err), [2, 1], "{err}");
    assert_eq!(reports(&out), ["127.0.0.1", "127.0.0.2", "127.0.0.1"]);

    // A connect scan under -Pn is not routed: one group, in input order.
    let (out, err, ok) = run(&[
        "-d",
        "-sT",
        "-Pn",
        "-n",
        "-p",
        "1",
        "127.0.0.1",
        &own,
        "127.0.0.2",
    ]);
    assert!(ok, "{err}");
    assert_eq!(sizes(&err), [3], "{err}");
    assert_eq!(reports(&out), ["127.0.0.1", own.as_str(), "127.0.0.2"]);
}

/// "scanned in" counts from before the pre-scan scripts, as 7.94's `o.start`
/// (`NmapOps.cc:291`) does: a prerule that sleeps a second is in it.
#[test]
fn scanned_in_counts_the_pre_scan_scripts() {
    let script = scratch("sleep1pre.nse");
    std::fs::write(
        &script,
        "description = 'x'\ncategories = {'safe'}\nlocal stdnse = require 'stdnse'\nprerule = function() return true end\naction = function() stdnse.sleep(1) return 'slept' end\n",
    )
    .unwrap();
    let (out, err, ok) = run(&[
        "-sT",
        "-Pn",
        "-n",
        "-p",
        "1",
        "--script",
        script.to_str().unwrap(),
        "127.0.0.1",
    ]);
    assert!(ok, "{err}");
    let secs: f64 = out
        .lines()
        .find_map(|l| {
            l.split_once(" scanned in ")?
                .1
                .split(' ')
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no \"scanned in\": {out}"));
    assert!(
        secs >= 1.0,
        "scanned in {secs} s, under the prerule's 1 s: {out}"
    );
}

/// `-sV`'s count of ports left alone under the probe file's Exclude is one
/// line for the run, the count of every group, not a line per group.
#[test]
fn the_version_exclude_note_is_once_for_the_run() {
    // Any free port of the Exclude range (`nmap-service-probes`: T:9100-9107).
    let Some((port, _l)) =
        (9100..=9107).find_map(|p| TcpListener::bind(("0.0.0.0", p)).ok().map(|l| (p, l)))
    else {
        eprintln!("skipped: every port of 9100-9107 is taken");
        return;
    };
    let port = port.to_string();
    let (_, err, ok) = run(&[
        "-sV",
        "-sT",
        "-Pn",
        "-n",
        "-v",
        "-p",
        &port,
        "--max-hostgroup",
        "1",
        "127.0.0.1-3",
    ]);
    assert!(ok, "{err}");
    let notes: Vec<&str> = err
        .lines()
        .filter(|l| l.contains("not version-scanned"))
        .collect();
    assert_eq!(notes.len(), 1, "{err}");
    assert!(notes[0].starts_with("3 port(s)"), "{err}");
}

/// A raw scan that falls back to a connect scan says so once for the run, not
/// once per group. Run without privilege: as root, through `setpriv`.
#[test]
fn the_connect_fallback_is_announced_once() {
    let args = [
        "-sS",
        "-Pn",
        "-n",
        "-p",
        "1",
        "--max-hostgroup",
        "1",
        "127.0.0.1-3",
    ];
    // Root or not, by `id -u`, so the test needs no unsafe.
    let root = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false);
    let out = if root {
        let Ok(out) = Command::new("setpriv")
            .args(["--reuid=65534", "--regid=65534", "--clear-groups", "--"])
            .arg(bin())
            .args(args)
            .output()
        else {
            eprintln!("skipped: root without setpriv");
            return;
        };
        out
    } else {
        Command::new(bin()).args(args).output().unwrap()
    };
    let err = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && err.contains("Permission denied") {
        eprintln!("skipped: the binary is not executable unprivileged: {err}");
        return;
    }
    assert!(out.status.success(), "{err}");
    assert_eq!(
        err.matches("falling back to a connect scan").count(),
        1,
        "{err}"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout)
            .matches("Nmap scan report for ")
            .count(),
        3
    );
}

/// Whether this host has an IPv6 default route, by `/proc/net/ipv6_route`;
/// with `/proc/net` but no such file, IPv6 is off and there is none. `None`
/// when it cannot tell (not Linux).
fn has_ipv6_default_route() -> Option<bool> {
    let Ok(table) = std::fs::read_to_string("/proc/net/ipv6_route") else {
        return std::path::Path::new("/proc/net/route")
            .exists()
            .then_some(false);
    };
    Some(table.lines().any(|l| {
        let mut f = l.split_whitespace();
        f.next() == Some("00000000000000000000000000000000") && f.next() == Some("00")
    }))
}

/// In a routed run, a target with no route groups with the other unroutable
/// ones alone, and the routed target is not drawn into their group: 7.94
/// drops unroutable targets before grouping (`targets.cc:409-413`). Over IPv6,
/// where, with no IPv6 default route, `::2` and `::3` route nowhere and the
/// port routes `::1` by loopback; 7.94 on such a host routes `::1` nowhere
/// too (`ipv6-loopback-routed-without-stack`). Needs root, for a routed run.
#[test]
#[ignore = "needs root"]
fn an_unroutable_target_groups_apart_from_routed_ones() {
    if has_ipv6_default_route() != Some(false) {
        eprintln!("skipping: this host may route ::2 (an IPv6 default route, or none known)");
        return;
    }
    let (out, err, _) = run(&[
        "-6", "-d", "-sS", "-Pn", "-n", "-p", "80", "::2", "::1", "::3",
    ]);
    if err.contains("falling back to a") || err.contains("lacks raw-scan support") {
        assert!(
            std::env::var_os("REQUIRE_RAW").is_none(),
            "REQUIRE_RAW is set, but the scan did not run raw: {err}"
        );
        eprintln!("skipping the routed grouping check: {err}");
        return;
    }
    assert_eq!(sizes(&err), [2, 1], "{err}");
    assert_eq!(reports(&out), ["::2", "::3", "::1"], "{out}");
}
