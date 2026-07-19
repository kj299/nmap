//! End-to-end `-sV` test driving the real `nmap-rs` binary against a loopback
//! service that emits a known banner. Proves the whole Milestone-3 pipeline
//! through the actual CLI: connect scan → probe DB load → matcher → versioninfo →
//! rendered output, across the normal and XML formats.
//!
//! Skipped under Miri (spawns a process + real sockets).
#![cfg(not(miri))]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::process::Command;
use std::thread;
use std::time::Duration;

/// Spawn a loopback listener that answers each connection with `banner`, for a
/// bounded number of accepts. Returns the bound port.
fn spawn_banner_server(banner: &'static [u8], accepts: usize) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        listener.set_nonblocking(false).expect("blocking listener");
        for _ in 0..accepts {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    let _ = sock.write_all(banner);
                    let _ = sock.flush();
                    // Give the scanner a moment to read before we close.
                    thread::sleep(Duration::from_millis(100));
                    // Drain anything the probe sent so the close is clean.
                    let mut buf = [0u8; 256];
                    let _ = sock.read(&mut buf);
                }
                Err(_) => break,
            }
        }
    });
    // Let the listener thread reach accept().
    thread::sleep(Duration::from_millis(50));
    port
}

/// Run the `nmap-rs` binary with `args`, returning stdout. `NMAP_RS_DATADIR`
/// points at the C repo root so it finds `nmap-service-probes`.
fn run_nmap_rs(args: &[&str]) -> String {
    let datadir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
    let out = Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
        .args(args)
        .env("NMAP_RS_DATADIR", datadir)
        .output()
        .expect("run nmap-rs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn sv_detects_ssh_openssh_in_normal_output() {
    let port = spawn_banner_server(b"SSH-2.0-OpenSSH_9.6\r\n", 6);
    let p = port.to_string();
    let out = run_nmap_rs(&["-sV", "-Pn", "-p", &p, "127.0.0.1"]);

    // The whole pipeline: service name, product, version, and the VERSION column.
    assert!(out.contains("VERSION"), "no VERSION column:\n{out}");
    assert!(
        out.contains(&format!("{port}/tcp open  ssh")),
        "ssh not detected:\n{out}"
    );
    assert!(
        out.contains("OpenSSH 9.6 (protocol 2.0)"),
        "version string missing:\n{out}"
    );
}

#[test]
fn sv_xml_carries_product_version_and_cpe() {
    let port = spawn_banner_server(b"SSH-2.0-OpenSSH_9.6\r\n", 6);
    let p = port.to_string();
    let xml = run_nmap_rs(&["-sV", "-Pn", "-p", &p, "-oX", "-", "127.0.0.1"]);

    assert!(xml.contains("name=\"ssh\""), "xml service name:\n{xml}");
    assert!(xml.contains("product=\"OpenSSH\""), "xml product:\n{xml}");
    assert!(xml.contains("version=\"9.6\""), "xml version:\n{xml}");
    assert!(
        xml.contains("method=\"probed\""),
        "xml method not probed:\n{xml}"
    );
    assert!(
        xml.contains("<cpe>cpe:/a:openbsd:openssh:9.6</cpe>"),
        "xml cpe:\n{xml}"
    );
}

#[test]
fn without_sv_no_version_column() {
    // A plain connect scan of the same fixture shows the table name, no VERSION.
    let port = spawn_banner_server(b"SSH-2.0-OpenSSH_9.6\r\n", 4);
    let p = port.to_string();
    let out = run_nmap_rs(&["-Pn", "-p", &p, "127.0.0.1"]);
    assert!(
        !out.contains("VERSION"),
        "unexpected VERSION column:\n{out}"
    );
    assert!(
        out.contains(&format!("{port}/tcp open")),
        "port not open:\n{out}"
    );
}
