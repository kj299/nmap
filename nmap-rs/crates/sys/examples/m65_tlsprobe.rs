//! The port's leaf for the M6.5 TLS fixture gate (step f1,
//! `tests/differential/m6/oracle/gen_m65_tls.py --check`): what
//! `m65_tls/s0probe.nse` prints of the certificate under nmap 7.94,
//! `R: ok leaf=<sha256 of the leaf DER> len=<bytes> cn=<commonName>`, from
//! the port's own socket host ([`nmap_sys::nsenet::TokioNet`]) driven as
//! `core::nse::net` drives it. Until step f2 gives `get_ssl_certificate` its
//! table, a script cannot see the leaf, so the gate runs the probe script
//! through the port and this beside it, and compares the leaf from here.
//!
//! usage: m65_tlsprobe PORT [SCRIPT-ARGS], where SCRIPT-ARGS is the probe's
//! `--script-args` (`mode=host|ipstr|name|table|starttls|udpssl`, `name=`,
//! `tn=`, `timeout=`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use nmap_core::nse::net::{
    sni_name, Completion, Family, NetProto, OpId, ReadMode, ScriptNet, SockId,
};
use nmap_core::nse::openssl::x509;
use nmap_sys::nsenet::TokioNet;
use sha2::Digest;

const SOCK: SockId = 1;

fn wait(net: &mut TokioNet, op: OpId) -> Completion {
    loop {
        for (done, c) in net.poll(Duration::from_millis(100)) {
            if done == op {
                return c;
            }
        }
    }
}

fn status(c: &Completion) -> String {
    match c {
        Completion::Failed(st) => st.as_str().to_string(),
        other => format!("{other:?}"),
    }
}

/// `smtp_expect`: lines until one with `code` and a space.
fn smtp_expect(net: &mut TokioNet, op: &mut OpId, t: Option<Duration>, code: &str) -> Result<(), String> {
    loop {
        *op += 1;
        net.read(*op, SOCK, ReadMode::Lines(1), t);
        let data = match wait(net, *op) {
            Completion::Data(d) => d,
            c => return Err(format!("smtp: {}", status(&c))),
        };
        for l in data.split(|&b| b == b'\r' || b == b'\n').filter(|l| !l.is_empty()) {
            if l.starts_with(code.as_bytes()) && l.get(3) == Some(&b' ') {
                return Ok(());
            }
            if l.first() != code.as_bytes().first() {
                return Err(format!("smtp: {}", String::from_utf8_lossy(l)));
            }
        }
    }
}

fn send(net: &mut TokioNet, op: &mut OpId, t: Option<Duration>, data: &[u8]) {
    *op += 1;
    net.write(*op, SOCK, data.to_vec(), t);
    wait(net, *op);
}

fn common_name(der: &[u8]) -> String {
    let Some(cert) = x509::d2i_x509(der) else {
        return "nil".into();
    };
    // `name_to_table` keeps the last value of a repeated attribute.
    cert.subject
        .iter()
        .rev()
        .find(|e| e.oid == [0x55, 0x04, 0x03])
        .map_or_else(
            || "nil".into(),
            |e| String::from_utf8_lossy(x509::string_data(&e.value)).into_owned(),
        )
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let port: u16 = argv.get(1).and_then(|p| p.parse().ok()).expect("PORT");
    let args: HashMap<String, String> = argv
        .get(2)
        .map(|s| {
            s.split(',')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let mode = args.get("mode").map_or("host", String::as_str);
    let t = Some(Duration::from_millis(
        args.get("timeout").and_then(|v| v.parse().ok()).unwrap_or(5000),
    ));
    let mut net = TokioNet::new().expect("tokio");
    let localhost = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut remote = SocketAddr::new(localhost, port);
    // The server name, as `nseU_checktarget` gives it: none for a host
    // table without a target name, the string itself otherwise.
    let hostname: Option<Vec<u8>> = match mode {
        "ipstr" => Some(b"127.0.0.1".to_vec()),
        "name" => {
            let n = args.get("name").cloned().unwrap_or_else(|| "localhost".into());
            let ip = net
                .resolve(&n, Family::Inet)
                .ok()
                .and_then(|l| l.into_iter().next())
                .expect("the name resolves");
            remote = SocketAddr::new(ip, port);
            Some(n.into_bytes())
        }
        "table" => args.get("tn").map(|tn| match tn.as_str() {
            "EMPTY" => Vec::new(),
            "LONG255" => vec![b'a'; 255],
            "LONG256" => vec![b'a'; 256],
            other => other.as_bytes().to_vec(),
        }),
        _ => None,
    };
    let sni = match sni_name(hostname.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            println!("R: fail lua-error {e}");
            return;
        }
    };
    let mut op: OpId = 1;
    let done = if mode == "starttls" {
        net.connect(op, SOCK, NetProto::Tcp, None, remote, t);
        if let c @ Completion::Failed(_) = wait(&mut net, op) {
            println!("R: fail connect {}", status(&c));
            return;
        }
        for (send_first, code) in [(None, "220"), (Some(&b"EHLO probe\r\n"[..]), "250"), (Some(b"STARTTLS\r\n"), "220")] {
            if let Some(d) = send_first {
                send(&mut net, &mut op, t, d);
            }
            if let Err(e) = smtp_expect(&mut net, &mut op, t, code) {
                println!("R: fail {e}");
                return;
            }
        }
        op += 1;
        net.reconnect_ssl(op, SOCK, t, sni);
        wait(&mut net, op)
    } else {
        net.connect_ssl(op, SOCK, None, remote, t, sni);
        wait(&mut net, op)
    };
    if let c @ Completion::Failed(_) = done {
        println!("R: fail {}", status(&c));
        return;
    }
    match net.peer_certificate(SOCK) {
        Some(der) => println!(
            "R: ok leaf={} len={} cn={}",
            sha2::Sha256::digest(&der)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            der.len(),
            common_name(&der)
        ),
        None => println!("R: ok leaf=none err=nil"),
    }
    net.close(SOCK);
}
