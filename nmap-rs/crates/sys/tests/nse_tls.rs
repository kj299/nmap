//! M6.5 step f1: TLS sockets through the whole NSE path (the glue, the
//! scheduler, `core::nse::net`, `sys::nsenet` and `sys::tls`) against
//! in-process TLS servers over the same provider, which record what a
//! client did: the server name it sent, how it ended the connection.
//!
//! The fixture gate (`tests/differential/m6/oracle/gen_m65_tls.py --check`,
//! CI's differential job) holds the same paths to nmap 7.94 on loopback
//! servers; these run in every `cargo test` and pin the rules one by one:
//! the server name a connection sends, the refusals that are Lua errors
//! here and fatal in 7.94, `get_ssl_certificate`'s raise/nil contract (and
//! `ftp.auth`, which relies on it), UDP sockets, the end-of-stream model,
//! the `close_notify` on close, and teardown within the time-out.
#![cfg(all(unix, not(miri)))] // real sockets, real handshakes

#[path = "../../core/tests/nse_host/mod.rs"]
mod nse_host;

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nmap_core::nse::engine::ChosenScript;
use nmap_core::nse::nmaplib::{NmapLib, Phase};
use nmap_core::nse::runtime::{new_state, StateConfig};
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{ServerConfig, ServerConnection, SignatureAlgorithm, SignatureScheme};

const CERTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/differential/m6/m65_tls/certs"
);

// ---- a TLS server over the client's own provider ----------------------------

/// A P-256 key; `corrupt` spoils every signature it makes.
#[derive(Debug, Clone)]
struct P256(p256::ecdsa::SigningKey, bool);

impl SigningKey for P256 {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for P256 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.0.sign(message);
        let mut der = sig.to_der().as_bytes().to_vec();
        if self.1 {
            if let Some(b) = der.last_mut() {
                *b ^= 1;
            }
        }
        Ok(der)
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn server_config() -> Arc<ServerConfig> {
    server_config_with(false, &[])
}

/// The server's configuration, its signatures spoiled if `corrupt`, the
/// certificates of `chain` sent after its own.
fn server_config_with(corrupt: bool, chain: &[&str]) -> Arc<ServerConfig> {
    let hex = std::fs::read_to_string(format!("{CERTS}/ecp256.scalar")).expect("scalar");
    let hex = hex.trim();
    let scalar: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).expect("hex"), 16).expect("hex"))
        .collect();
    let key = P256(
        p256::ecdsa::SigningKey::from_slice(&scalar).expect("P-256 scalar"),
        corrupt,
    );
    let mut certs = vec![CertificateDer::from(
        std::fs::read(format!("{CERTS}/ecp256.der")).expect("certificate"),
    )];
    for c in chain {
        certs.push(CertificateDer::from(
            std::fs::read(format!("{CERTS}/{c}")).expect("certificate"),
        ));
    }
    let ck = Arc::new(CertifiedKey::new(certs, Arc::new(key)));
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(nmap_sys::tls::provider::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(ck))),
    )
}

/// What a server saw of each connection, in order.
type Log = Arc<Mutex<Vec<String>>>;

fn note(log: &Log, s: impl Into<String>) {
    log.lock().expect("log").push(s.into());
}

/// The handshake, as a server; the name the client sent, `-` for none.
fn accept_tls(
    tcp: TcpStream,
    cfg: &Arc<ServerConfig>,
) -> Option<(rustls::StreamOwned<ServerConnection, TcpStream>, String)> {
    let mut conn = ServerConnection::new(cfg.clone()).ok()?;
    let mut tcp = tcp;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).ok()?;
    }
    let sni = conn.server_name().unwrap_or("-").to_string();
    Some((rustls::StreamOwned::new(conn, tcp), sni))
}

/// How the client ended the connection: `close_notify`, `eof` (TCP closed
/// with no close_notify), or `error`.
fn drain(s: &mut rustls::StreamOwned<ServerConnection, TcpStream>) -> &'static str {
    let mut buf = [0u8; 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return "close_notify",
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return "eof",
            Err(_) => return "error",
        }
    }
}

/// A TLS server: per connection, the server name, then `hello\n`, then how
/// the client ended it.
fn tls_hello_server() -> (u16, Log) {
    let l = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = l.local_addr().expect("addr").port();
    let log: Log = Arc::default();
    let cfg = server_config();
    let lg = log.clone();
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            let (cfg, lg) = (cfg.clone(), lg.clone());
            thread::spawn(move || match accept_tls(c, &cfg) {
                Some((mut s, sni)) => {
                    note(&lg, format!("sni={sni}"));
                    let _ = s.write_all(b"hello\n");
                    let how = drain(&mut s);
                    note(&lg, how);
                }
                None => note(&lg, "no handshake"),
            });
        }
    });
    (port, log)
}

/// A TCP server that never speaks: notes `closed` when the client ends a
/// connection (FIN or RST).
fn silent_server() -> (u16, Log) {
    let l = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = l.local_addr().expect("addr").port();
    let log: Log = Arc::default();
    let lg = log.clone();
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let lg = lg.clone();
            thread::spawn(move || {
                let _ = c.set_read_timeout(Some(Duration::from_secs(20)));
                let mut b = [0u8; 4096];
                // A ClientHello is read and ignored; the end is noted.
                loop {
                    match c.read(&mut b) {
                        Ok(0) => break note(&lg, "closed"),
                        Ok(_) => continue,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                        Err(_) => break note(&lg, "closed"),
                    }
                }
            });
        }
    });
    (port, log)
}

/// A TCP server that closes each connection at once: a handshake on it
/// fails.
fn closer_server() -> u16 {
    let l = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            drop(c);
        }
    });
    port
}

// ---- running a script --------------------------------------------------------

/// Run `body` as a prerule script's action over the tokio host; its result.
fn run(body: &str) -> String {
    let tmp = std::env::temp_dir().join(format!(
        "m65f1-{}-{}",
        std::process::id(),
        body.len()
            ^ (body
                .as_bytes()
                .iter()
                .map(|&b| usize::from(b))
                .sum::<usize>()
                << 8)
    ));
    std::fs::create_dir_all(&tmp).expect("tmp");
    let script = tmp.join("t.nse");
    std::fs::write(
        &script,
        format!(
            "local nmap = require 'nmap'\n\
             local stdnse = require 'stdnse'\n\
             categories = {{}}\n\
             prerule = function() return true end\n\
             action = function()\n\
               local ok, v = pcall(function()\n{body}\nend)\n\
               if not ok then return 'ERROR: ' .. tostring(v) end\n\
               return v\n\
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
    // `parse_ssl_certificate` itself, which the `nmap` module holds only
    // from step g: the scripts compare the socket's table with it.
    st.lua.enter(|ctx| {
        ctx.set_global(
            "test_parse",
            nmap_core::nse::openssl::cert::parse_ssl_certificate(ctx),
        );
    });
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
    let out = r.run.first().expect("the script ran");
    out.output
        .as_deref()
        .map_or_else(|| "nil".into(), |o| String::from_utf8_lossy(o).into_owned())
}

fn wait_for(log: &Log, n: usize) -> Vec<String> {
    let end = Instant::now()
        .checked_add(Duration::from_secs(5))
        .expect("a deadline");
    loop {
        let l = log.lock().expect("log").clone();
        if l.len() >= n || Instant::now() > end {
            return l;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

// ---- the server name -----------------------------------------------------------

#[test]
fn the_server_name_is_the_targetname_where_rustls_can_send_it() {
    let (port, log) = tls_hello_server();
    let out = run(&format!(
        "local r = {{}}\n\
         for _, t in ipairs({{ {{ip='127.0.0.1'}}, {{ip='127.0.0.1', targetname='example.test'}},\n\
                              'localhost', '127.0.0.1', {{ip='127.0.0.1', targetname='a.test\\0b'}} }}) do\n\
           local s = nmap.new_socket()\n\
           local ok, e = s:connect(t, {port}, 'ssl')\n\
           r[#r+1] = tostring(ok)\n\
           s:close()\n\
         end\n\
         -- A plain connection keeps its target name for reconnect_ssl.\n\
         local s = nmap.new_socket()\n\
         s:connect({{ip='127.0.0.1', targetname='later.test'}}, {port}, 'tcp')\n\
         r[#r+1] = tostring(s:reconnect_ssl())\n\
         s:close()\n\
         return table.concat(r, ',')"
    ));
    assert_eq!(out, "true,true,true,true,true,true");
    let seen: Vec<String> = wait_for(&log, 12)
        .into_iter()
        .filter(|l| l.starts_with("sni="))
        .collect();
    // A host table without a target name sends none; an IP literal is not
    // sent (nse-tls-sni-rustls-names); a name is cut at its NUL (strdup).
    assert_eq!(
        seen,
        [
            "sni=-",
            "sni=example.test",
            "sni=localhost",
            "sni=-",
            "sni=a.test",
            "sni=later.test"
        ]
    );
}

#[test]
fn a_name_openssl_refuses_is_a_lua_error_not_a_fatal_one() {
    let (port, log) = tls_hello_server();
    for tn in ["''", "string.rep('a', 256)"] {
        let out = run(&format!(
            "local s = nmap.new_socket()\n\
             return s:connect({{ip='127.0.0.1', targetname={tn}}}, {port}, 'ssl')"
        ));
        assert!(
            out.contains(nmap_core::nse::net::SNI_REFUSED),
            "{tn}: {out}"
        );
    }
    // reconnect_ssl too, with the name of the plain connect; 255 bytes is
    // a name OpenSSL takes.
    let out = run(&format!(
        "local s = nmap.new_socket()\n\
         s:connect({{ip='127.0.0.1', targetname=''}}, {port}, 'tcp')\n\
         return s:reconnect_ssl()"
    ));
    assert!(out.contains(nmap_core::nse::net::SNI_REFUSED), "{out}");
    let out = run(&format!(
        "local s = nmap.new_socket()\n\
         return tostring(s:connect({{ip='127.0.0.1', targetname=string.rep('a', 255)}}, {port}, 'ssl'))"
    ));
    assert_eq!(out, "true");
    // The refused connects never reached the server; the plain connect
    // did, and never handshook. The 255-byte name is not one rustls can
    // send (nse-tls-sni-rustls-names).
    let seen = wait_for(&log, 3);
    assert_eq!(
        seen.iter()
            .filter(|l| l.starts_with("sni="))
            .collect::<Vec<_>>(),
        ["sni=-"],
        "{seen:?}"
    );
    assert!(seen.iter().any(|l| l == "no handshake"), "{seen:?}");
}

// ---- get_ssl_certificate and UDP sockets ------------------------------------------

#[test]
fn get_ssl_certificate_raises_on_a_socket_that_is_not_ssl() {
    let (port, _log) = tls_hello_server();
    let closer = closer_server();
    let out = run(&format!(
        "local r = {{}}\n\
         local function try(label, f, ...)\n\
           local ok, v = pcall(f, ...)\n\
           r[#r+1] = label .. ':' .. tostring(ok) .. ',' .. (type(v) == 'string' and v or type(v))\n\
         end\n\
         local s = nmap.new_socket()\n\
         try('new', s.get_ssl_certificate, s)\n\
         s:connect('127.0.0.1', {port}, 'tcp')\n\
         try('tcp', s.get_ssl_certificate, s)\n\
         s:close()\n\
         local t = nmap.new_socket()\n\
         t:connect('127.0.0.1', {port}, 'ssl')\n\
         try('ssl', t.get_ssl_certificate, t)\n\
         t:close()\n\
         try('closed', t.get_ssl_certificate, t)\n\
         try('arg', t.get_ssl_certificate, 5)\n\
         local u = nmap.new_socket()\n\
         u:set_timeout(300)\n\
         local fok, ferr = u:connect('127.0.0.1', {closer}, 'ssl')\n\
         r[#r+1] = 'failed:' .. tostring(fok) .. ',' .. tostring(ferr)\n\
         try('failedcert', u.get_ssl_certificate, u)\n\
         return table.concat(r, ' | ')"
    ));
    assert_eq!(
        out,
        "new:false,bad argument #1 to '?' (not a SSL socket) | \
         tcp:false,bad argument #1 to '?' (not a SSL socket) | \
         ssl:true,userdata | \
         closed:false,bad argument #1 to '?' (not a SSL socket) | \
         arg:false,bad argument #1 to '?' (nsock expected, got number) | \
         failed:nil,ERROR | \
         failedcert:true,nil"
    );
}

/// Renders a value as `oracle/m65_core.lua` does a parsed certificate: every
/// field, then `digest` over several names; tables with their keys sorted,
/// bignums through their methods.
const RENDER: &str = "\
local render
local FIELDS = {'subject', 'issuer', 'version', 'serial', 'sig_algorithm',
  'validity', 'pubkey', 'extensions', 'pem', 'nosuchfield'}
render = function(v)
  local t = type(v)
  if t == 'string' then return string.format('%q', v) end
  if t ~= 'table' and t ~= 'userdata' then return t .. ':' .. tostring(v) end
  local mt = getmetatable(v)
  local name = type(mt) == 'table' and mt.__name or nil
  if name == 'BIGNUM' then return 'bn<' .. v:tohex() .. '>' end
  if name == 'SSL_CERT' then
    local parts = {}
    for _, f in ipairs(FIELDS) do parts[#parts + 1] = f .. '=' .. render(v[f]) end
    for _, d in ipairs({'md5', 'sha1', 'sha256', 'bogus'}) do
      parts[#parts + 1] = d .. '=' .. render(v:digest(d))
    end
    return 'cert<' .. table.concat(parts, ' ') .. '>'
  end
  local parts = {}
  for k, x in pairs(v) do parts[#parts + 1] = render(k) .. '=' .. render(x) end
  table.sort(parts)
  return '{' .. table.concat(parts, ',') .. '}'
end
";

/// The leaf's DER, from a table's `pem`.
const DER_OF: &str = "\
local base64 = require 'base64'
local function der_of(c)
  return base64.dec((c.pem:gsub('%-%-%-%-%-[^\\n]*%-%-%-%-%-', ''):gsub('%s', '')))
end
";

fn sha256_hex(der: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Step f2: the table is `parse_ssl_certificate`'s of the leaf the server
/// sent, and `parse_ssl_certificate` takes the trailing bytes the handshake
/// refuses (`a_certificate_entry_must_be_exactly_a_certificate`).
#[test]
fn get_ssl_certificate_is_the_parsed_table_of_the_leaf() {
    let (port, _log) = tls_hello_server();
    let out = run(&format!(
        "{RENDER}{DER_OF}\
         local s = nmap.new_socket()\n\
         assert(s:connect('127.0.0.1', {port}, 'ssl'))\n\
         local c = s:get_ssl_certificate()\n\
         s:close()\n\
         local der = der_of(c)\n\
         local mine = render(c)\n\
         return table.concat({{\n\
           stdnse.tohex(c:digest('sha256')),\n\
           tostring(mine == render(test_parse(der))),\n\
           tostring(mine == render(test_parse(der .. '\\0trailing'))),\n\
           c.subject.commonName, c.pubkey.type, tostring(c.pubkey.bits),\n\
         }}, ' ')"
    ));
    let der = std::fs::read(format!("{CERTS}/ecp256.der")).expect("certificate");
    assert_eq!(
        out,
        format!("{} true true m65-ecp256 ec 256", sha256_hex(&der))
    );
}

/// The table is the leaf's, the first certificate of the chain.
#[test]
fn the_table_is_the_leafs_not_the_chains() {
    let l = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = l.local_addr().expect("addr").port();
    let cfg = server_config_with(false, &["rsa2048.der", "ed25519.der"]);
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            let cfg = cfg.clone();
            thread::spawn(move || {
                if let Some((mut s, _)) = accept_tls(c, &cfg) {
                    drain(&mut s);
                }
            });
        }
    });
    let out = run(&format!(
        "local s = nmap.new_socket()\n\
         assert(s:connect('127.0.0.1', {port}, 'ssl'))\n\
         local c = s:get_ssl_certificate()\n\
         s:close()\n\
         return c.subject.commonName .. ' ' .. stdnse.tohex(c:digest('sha256'))"
    ));
    let der = std::fs::read(format!("{CERTS}/ecp256.der")).expect("certificate");
    assert_eq!(out, format!("m65-ecp256 {}", sha256_hex(&der)));
}

/// OpenSSL keeps the leaf once its checks pass, and the handshake failing
/// later on a bad signature leaves it to `get_ssl_certificate` (7.94:
/// `cert-fake-badsig`, `cert-bad13-corrupt`).
#[test]
fn a_handshake_that_fails_after_the_certificate_keeps_the_leaf() {
    let l = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = l.local_addr().expect("addr").port();
    let cfg = server_config_with(true, &[]);
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            let cfg = cfg.clone();
            thread::spawn(move || drop(accept_tls(c, &cfg)));
        }
    });
    let der = std::fs::read(format!("{CERTS}/ecp256.der")).expect("certificate");
    let out = run(&format!(
        "local s = nmap.new_socket()\n\
         s:set_timeout(3000)\n\
         local st, e = s:connect('127.0.0.1', {port}, 'ssl')\n\
         local c = s:get_ssl_certificate()\n\
         return tostring(st) .. ',' .. tostring(e) .. ' ' .. stdnse.tohex(c:digest('sha256'))"
    ));
    assert_eq!(out, format!("nil,ERROR {}", sha256_hex(&der)));
}

#[test]
fn ssl_from_a_udp_socket_is_tls_over_tcp_and_reconnect_ssl_raises() {
    let (port, log) = tls_hello_server();
    let out = run(&format!(
        "local s = nmap.new_socket('udp')\n\
         local ok = s:connect('127.0.0.1', {port}, 'ssl')\n\
         local line = select(2, s:receive_lines(1))\n\
         s:close()\n\
         local u = nmap.new_socket('udp')\n\
         local rok, e = pcall(u.reconnect_ssl, u)\n\
         return tostring(ok) .. ',' .. tostring(line) .. ',' .. tostring(rok) .. ',' .. tostring(e)"
    ));
    assert_eq!(
        out,
        format!("true,hello\n,false,{}", nmap_core::nse::net::RECONNECT_UDP)
    );
    assert_eq!(wait_for(&log, 2), ["sni=-", "close_notify"]);
}

// ---- the end of a connection ----------------------------------------------------

#[test]
fn closing_an_ssl_socket_sends_close_notify() {
    let (port, log) = tls_hello_server();
    let out = run(&format!(
        "local s = nmap.new_socket()\n\
         s:connect('127.0.0.1', {port}, 'ssl')\n\
         local ok, d = s:receive_lines(1)\n\
         s:close()\n\
         return d"
    ));
    assert_eq!(out, "hello\n");
    assert_eq!(wait_for(&log, 2), ["sni=-", "close_notify"]);
}

/// A TLS server that sends `hello\n`, waits for one byte, then ends the
/// connection as `how` says.
fn ending_server(how: &'static str) -> u16 {
    let l = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = l.local_addr().expect("addr").port();
    let cfg = server_config();
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            let cfg = cfg.clone();
            thread::spawn(move || {
                let Some((mut s, _)) = accept_tls(c, &cfg) else {
                    return;
                };
                let _ = s.write_all(b"hello\n");
                let mut b = [0u8; 1];
                let _ = s.read(&mut b);
                if how.ends_with("+data") {
                    let _ = s.write_all(b"tail\n");
                    thread::sleep(Duration::from_millis(200));
                }
                if how.starts_with("notify") {
                    s.conn.send_close_notify();
                    let _ = s.flush();
                    let _ = s.conn.complete_io(&mut s.sock);
                    thread::sleep(Duration::from_secs(5));
                }
                // Dropping the stream closes TCP; for `abrupt` with nothing
                // before it.
            });
        }
    });
    port
}

fn reads(port: u16, how: &str) -> String {
    run(&format!(
        "local s = nmap.new_socket()\n\
         s:set_timeout(1000)\n\
         s:connect('127.0.0.1', {port}, 'ssl')\n\
         s:receive_bytes(6)\n\
         s:send('x')\n\
         local out = {{}}\n\
         for _ = 1, 3 do\n\
           local t0 = nmap.clock_ms()\n\
           local ok, d\n\
           if '{how}' == 'recv' then ok, d = s:receive() else ok, d = s:receive_bytes(100) end\n\
           local slow = (nmap.clock_ms() - t0) > 800 and 'slow' or 'fast'\n\
           out[#out+1] = (ok and ('ok(' .. d:gsub('\\n', '|') .. ')') or ('nil(' .. tostring(d) .. ')')) .. slow\n\
         end\n\
         return table.concat(out, ' ')"
    ))
}

#[test]
fn the_end_of_a_connection_reads_as_7_94_reads_it() {
    // The m65_tls golden's io-* rows, measured on nmap 7.94.
    for (how, recv, bytes) in [
        (
            "abrupt",
            "nil(EOF)fast nil(ERROR)fast nil(ERROR)fast",
            "nil(EOF)fast nil(ERROR)fast nil(ERROR)fast",
        ),
        (
            "abrupt+data",
            "ok(tail|)fast nil(EOF)fast nil(ERROR)fast",
            "ok(tail|)fast nil(ERROR)fast nil(ERROR)fast",
        ),
        (
            "notify",
            "nil(EOF)fast nil(TIMEOUT)slow nil(TIMEOUT)slow",
            "nil(EOF)fast nil(TIMEOUT)slow nil(TIMEOUT)slow",
        ),
        (
            "notify+data",
            "ok(tail|)fast nil(EOF)fast nil(TIMEOUT)slow",
            "ok(tail|)fast nil(TIMEOUT)slow nil(TIMEOUT)slow",
        ),
    ] {
        let port = ending_server(how);
        assert_eq!(reads(port, "recv"), recv, "{how}, receive");
        assert_eq!(reads(port, "bytes"), bytes, "{how}, receive_bytes");
    }
}

// ---- time-outs and teardown -------------------------------------------------------

#[test]
fn one_time_out_covers_the_connect_and_the_handshake() {
    let (port, log) = silent_server();
    let t0 = Instant::now();
    let out = run(&format!(
        "local s = nmap.new_socket()\n\
         s:set_timeout(500)\n\
         local ok, e = s:connect('127.0.0.1', {port}, 'ssl')\n\
         return tostring(ok) .. ',' .. tostring(e)"
    ));
    let took = t0.elapsed();
    assert_eq!(out, "nil,TIMEOUT");
    assert!(took < Duration::from_millis(1500), "{took:?}");
    // And the connection is gone once the handshake gave up (LESSONS #017).
    assert_eq!(wait_for(&log, 1), ["closed"]);
}

#[test]
fn closing_a_socket_mid_handshake_drops_the_connection() {
    let (port, log) = silent_server();
    let out = run(&format!(
        "local s = nmap.new_socket()\n\
         s:set_timeout(60000)\n\
         stdnse.new_thread(function () s:connect('127.0.0.1', {port}, 'ssl') end)\n\
         stdnse.sleep(0.5)\n\
         s:close()\n\
         return 'closed'"
    ));
    assert_eq!(out, "closed");
    assert_eq!(wait_for(&log, 1), ["closed"]);
}

// ---- comm.tryssl, which falls back to plain text -----------------------------------

#[test]
fn tryssl_falls_back_to_plain_text_when_the_handshake_fails() {
    let l = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    // `https` makes shortport.ssl true, so SSL is tried first; the echo
    // server answers the ClientHello with the ClientHello, which fails it.
    let out = run(&format!(
        "local comm = require 'comm'\n\
         local sd, resp, best = comm.tryssl({{ip='127.0.0.1'}}, {{number={port}, protocol='tcp', service='https'}}, 'hi\\n', {{timeout=2000}})\n\
         if sd then sd:close() end\n\
         return tostring(sd ~= nil) .. ',' .. tostring(resp) .. ',' .. tostring(best)"
    ));
    assert_eq!(out, "true,hi\n,tcp");
}

// ---- ftp.auth, which asks get_ssl_certificate whether a socket is TLS ------------

#[test]
fn ftp_auth_upgrades_with_auth_tls() {
    let l = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = l.local_addr().expect("addr").port();
    let cfg = server_config();
    thread::spawn(move || {
        let Some(Ok(mut c)) = l.incoming().next() else {
            return;
        };
        let _ = c.write_all(b"220 fixture FTP\r\n");
        let mut r = BufReader::new(c.try_clone().expect("clone"));
        let mut line = String::new();
        loop {
            line.clear();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if line.starts_with("USER") {
                let _ = c.write_all(b"530 Use AUTH TLS first\r\n");
            } else if line.starts_with("AUTH TLS") {
                let _ = c.write_all(b"234 go ahead\r\n");
                break;
            }
        }
        let Some((s, _)) = accept_tls(c, &cfg) else {
            return;
        };
        let mut r = BufReader::new(s);
        loop {
            line.clear();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let reply: &[u8] = if line.starts_with("USER") {
                b"331 password please\r\n"
            } else if line.starts_with("PASS") {
                b"230 logged in over TLS\r\n"
            } else {
                b"500 ?\r\n"
            };
            let _ = r.get_mut().write_all(reply);
        }
    });
    let out = run(&format!(
        "local ftp = require 'ftp'\n\
         local s, code, msg, buf = ftp.connect({{ip='127.0.0.1'}}, {{number={port}, protocol='tcp'}}, {{request_timeout=3000}})\n\
         if not s then return 'connect: ' .. tostring(code) end\n\
         local ok, c, m = ftp.auth(s, buf, 'u', 'p')\n\
         return tostring(ok) .. ',' .. tostring(c) .. ',' .. tostring(m)"
    ));
    assert_eq!(out, "true,230,logged in over TLS");
}
