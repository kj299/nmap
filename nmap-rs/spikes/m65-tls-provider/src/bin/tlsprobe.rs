//! The spike's client: connect to 127.0.0.1:PORT (after an SMTP STARTTLS
//! exchange if asked), handshake under nmap's rules, and report one line:
//!   OK <version> <suite> leaf=<sha256 of the leaf DER> certs=<n> ms=<handshake>
//!   FAIL <error> ms=<elapsed>
//! Arguments: PORT [--name NAME | --ip] [--starttls smtp] [--tls12 | --tls13]
//! [--group x25519|p256|p384|p521] [--timeout SECS]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use m65_tls_provider_spike::client::client_config;
use m65_tls_provider_spike::provider;
use rustls::crypto::SupportedKxGroup;
use rustls::pki_types::ServerName;
use sha2::Digest;

fn smtp_starttls(sock: &mut TcpStream) -> Result<(), String> {
    let mut reader = BufReader::new(sock.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    let expect =
        |reader: &mut BufReader<TcpStream>, code: &str, line: &mut String| -> Result<(), String> {
            loop {
                line.clear();
                let n = reader.read_line(line).map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("smtp: closed".into());
                }
                if line.starts_with(code) && line.as_bytes().get(3) == Some(&b' ') {
                    return Ok(());
                }
                if !line.starts_with(&code[..1]) {
                    return Err(format!("smtp: unexpected {}", line.trim_end()));
                }
            }
        };
    expect(&mut reader, "220", &mut line)?;
    sock.write_all(b"EHLO probe\r\n")
        .map_err(|e| e.to_string())?;
    expect(&mut reader, "250", &mut line)?;
    sock.write_all(b"STARTTLS\r\n").map_err(|e| e.to_string())?;
    expect(&mut reader, "220", &mut line)?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1).and_then(|p| p.parse().ok()).expect("PORT");
    let mut name: Option<String> = None;
    let mut starttls = false;
    let mut versions: Vec<&'static rustls::SupportedProtocolVersion> =
        vec![&rustls::version::TLS13, &rustls::version::TLS12];
    let mut groups: Option<Vec<&'static dyn SupportedKxGroup>> = None;
    let mut timeout = Duration::from_secs(5);
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                name = Some(args[i + 1].clone());
                i += 1;
            }
            "--ip" => name = None,
            "--starttls" => {
                starttls = true;
                i += 1;
            }
            "--tls12" => versions = vec![&rustls::version::TLS12],
            "--tls13" => versions = vec![&rustls::version::TLS13],
            "--group" => {
                let g: &'static dyn SupportedKxGroup = match args[i + 1].as_str() {
                    "x25519" => &provider::X25519,
                    "p256" => &provider::SECP256R1,
                    "p384" => &provider::SECP384R1,
                    "p521" => &provider::SECP521R1,
                    other => panic!("unknown group {other}"),
                };
                groups = Some(vec![g]);
                i += 1;
            }
            "--timeout" => {
                timeout = Duration::from_secs(args[i + 1].parse().expect("seconds"));
                i += 1;
            }
            other => panic!("unknown argument {other}"),
        }
        i += 1;
    }
    let started = Instant::now();
    let report_fail = |e: String| {
        println!(
            "FAIL {} ms={}",
            e.replace('\n', " "),
            started.elapsed().as_millis()
        );
    };
    let mut sock = match TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), timeout) {
        Ok(s) => s,
        Err(e) => return report_fail(format!("connect: {e}")),
    };
    sock.set_read_timeout(Some(timeout)).expect("timeout");
    sock.set_write_timeout(Some(timeout)).expect("timeout");
    if starttls {
        if let Err(e) = smtp_starttls(&mut sock) {
            return report_fail(e);
        }
    }
    let cfg = Arc::new(client_config(&versions, groups));
    let server_name = match &name {
        Some(n) => match ServerName::try_from(n.clone()) {
            Ok(sn) => sn,
            Err(e) => return report_fail(format!("server name {n:?} rejected by rustls: {e}")),
        },
        None => ServerName::IpAddress(rustls::pki_types::IpAddr::from(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        ))),
    };
    let mut conn = match rustls::ClientConnection::new(cfg, server_name) {
        Ok(c) => c,
        Err(e) => return report_fail(format!("config: {e}")),
    };
    // Drive the handshake to completion within the deadline.
    let deadline = started + timeout;
    while conn.is_handshaking() {
        if Instant::now() > deadline {
            return report_fail("handshake: timed out".into());
        }
        if let Err(e) = conn.complete_io(&mut sock) {
            return report_fail(format!("handshake: {e}"));
        }
    }
    let ms = started.elapsed().as_millis();
    let certs = conn
        .peer_certificates()
        .map(|c| c.to_vec())
        .unwrap_or_default();
    let leaf = certs
        .first()
        .map(|c| format!("{:x}", sha2::Sha256::digest(c.as_ref())))
        .unwrap_or_else(|| "none".into());
    println!(
        "OK {:?} {:?} leaf={} certs={} ms={}",
        conn.protocol_version().expect("negotiated"),
        conn.negotiated_cipher_suite()
            .map(|s| s.suite())
            .expect("negotiated"),
        leaf,
        certs.len(),
        ms
    );
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    let _ = sock.shutdown(Shutdown::Both);
    let mut sink = [0u8; 16];
    let _ = sock.read(&mut sink);
}
