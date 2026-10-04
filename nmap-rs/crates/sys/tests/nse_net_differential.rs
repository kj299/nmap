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

const HTTP_BODY: &[u8] =
    b"<html><head><title>Fixture &amp; Title</title></head><body>hi</body></html>";

fn http(mut c: TcpStream) {
    let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while !data.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    }
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nServer: fixture/1.0\r\nContent-Type: text/html\r\nX-Fixture: yes\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        HTTP_BODY.len()
    )
    .into_bytes();
    resp.extend_from_slice(HTTP_BODY);
    let _ = c.write_all(&resp);
}

/// The generator's services (`gen_m64_net.py`).
fn serve() {
    tcp(8080, http);
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
        shipped: &["http-title.nse", "http-headers.nse"],
    };
    let (n, failures) = check(&golden, &fx, || {
        Rc::new(RefCell::new(
            nmap_sys::nsenet::TokioNet::new().expect("tokio"),
        ))
    });
    assert!(n >= 2, "only {n} scenarios");
    assert!(
        failures.is_empty(),
        "{} of {n} scenarios differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// `receive_buf` with a delimiter function whose indices fall before the
/// buffer. nmap copies `l-1` (or `r`) bytes as a `size_t` and keeps `buf+r`,
/// reading out of bounds, so this has no oracle. Here an index before the
/// buffer is its start (`nse-receive-buf-negative-index`).
#[test]
fn receive_buf_clamps_indices_before_the_buffer() {
    use nmap_core::nse::engine::ChosenScript;
    use nmap_core::nse::nmaplib::{NmapLib, Phase};
    use nmap_core::nse::runtime::{new_state, StateConfig};
    let l = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            thread::spawn(move || echo(c));
        }
    });
    let tmp = std::env::temp_dir().join(format!("m64d-rbuf-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("tmp");
    let script = tmp.join("rbuf.nse");
    std::fs::write(
        &script,
        format!(
            "local nmap = require 'nmap'\n\
             categories = {{}}\n\
             prerule = function() return true end\n\
             action = function()\n\
               local s = nmap.new_socket()\n\
               s:connect('127.0.0.1', {port})\n\
               s:send('abcdef')\n\
               local out = {{}}\n\
               local function rb(need, l, r, keep)\n\
                 local ok, v = s:receive_buf(function(b) if #b >= need then return l, r end end, keep)\n\
                 out[#out+1] = tostring(ok) .. ':' .. v\n\
               end\n\
               rb(6, -3, -1, false)\n\
               rb(6, 1, 2, true)\n\
               rb(4, -2, -1, true)\n\
               rb(4, 4, 4, false)\n\
               return table.concat(out, ',')\n\
             end\n"
        ),
    )
    .expect("script");
    let dir = nse_host::repo_root();
    let mut st = new_state(&StateConfig {
        lib: NmapLib::new(nse_host::env(dir.clone())),
        args: Default::default(),
        source: Rc::new(nse_host::Dir(dir)),
        fs: Rc::new(nse_host::ReadOnlyFs),
        os: Rc::new(nse_host::os_env()),
        memory_limit: Some(256 << 20),
        engine: Default::default(),
        net: Rc::new(RefCell::new(
            nmap_sys::nsenet::TokioNet::new().expect("tokio"),
        )),
    })
    .expect("state");
    st.load_scripts(
        &[ChosenScript {
            path: script.display().to_string().into_bytes(),
            selection: "file path",
            verbosity: true,
            forced: false,
        }],
        None,
    )
    .expect("load");
    let r = st.run_phase(Phase::PreScan, vec![], None);
    let _ = std::fs::remove_dir_all(&tmp);
    assert_eq!(r.aborted, None);
    let got: Vec<_> = r.run.iter().map(|o| o.output.clone()).collect();
    assert_eq!(got, [Some(b"true:,true:ab,true:,true:cde".to_vec())]);
}
