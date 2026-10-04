//! M6.4d gate: scripts' sockets, timers, mutexes and condition variables, and
//! `nmap.resolve`, behave as under nmap 7.94.
//!
//! `oracle/gen_m64_net.py` ran nmap over the fixture scripts in
//! `tests/differential/m6/nse_net/`, which talk to loopback services the
//! generator ran: an echo server, a banner that closes, a silent server, a
//! closed port, a server that sends in pieces, a UDP echo and a silent UDP
//! port. This test runs the same services and the same scripts through the
//! port's engine over [`nmap_sys::nsenet::TokioNet`], and every result must
//! match byte for byte. `M64_NET_GOLDEN` names a golden to use instead of the
//! committed one; CI's differential job regenerates it live.
#![cfg(all(unix, not(miri)))] // real sockets, and data directories of symlinks

#[path = "../../core/tests/nse_host/mod.rs"]
mod nse_host;

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use nse_host::scenarios::{check, m6, Fixtures};

fn tcp(port: u16, handler: fn(TcpStream)) {
    let l = TcpListener::bind(("127.0.0.1", port)).expect("fixture port free");
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            thread::spawn(move || handler(c));
        }
    });
}

fn echo(mut c: TcpStream) {
    let mut buf = [0u8; 4096];
    while let Ok(n) = c.read(&mut buf) {
        if n == 0 || c.write_all(&buf[..n]).is_err() {
            break;
        }
    }
}

fn banner(mut c: TcpStream) {
    let _ = c.write_all(b"line1\nline2\r\nline3");
    thread::sleep(Duration::from_millis(100));
}

fn silent(c: TcpStream) {
    thread::sleep(Duration::from_secs(10));
    drop(c);
}

fn drip(mut c: TcpStream) {
    for piece in [&b"ab"[..], b"c\nd", b"e\n", b"fgh"] {
        let _ = c.write_all(piece);
        thread::sleep(Duration::from_millis(200));
    }
}

/// The generator's services (`gen_m64_net.py`).
fn serve() {
    tcp(46030, echo);
    tcp(46031, banner);
    tcp(46032, silent);
    tcp(46035, drip);
    let u = UdpSocket::bind(("127.0.0.1", 46034)).expect("fixture port free");
    thread::spawn(move || {
        let mut buf = [0u8; 65536];
        while let Ok((n, from)) = u.recv_from(&mut buf) {
            let _ = u.send_to(&buf[..n], from);
        }
    });
}

#[test]
fn sockets_behave_as_under_nmap() {
    serve();
    let golden = std::env::var_os("M64_NET_GOLDEN")
        .map_or_else(|| m6().join("m64_net_golden.txt"), PathBuf::from);
    let fx = Fixtures {
        dir: "nse_net",
        shipped: &[],
    };
    let (n, failures) = check(&golden, &fx, || {
        Rc::new(RefCell::new(nmap_sys::nsenet::TokioNet::new().expect("tokio")))
    });
    assert!(n >= 2, "only {n} scenarios");
    assert!(
        failures.is_empty(),
        "{} of {n} scenarios differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
