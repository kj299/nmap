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

    // --min-hostgroup raises a group past the size rule (here 1,024 / 20 = 51,
    // floored at 64).
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
