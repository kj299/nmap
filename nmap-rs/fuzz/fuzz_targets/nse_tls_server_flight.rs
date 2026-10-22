// cargo-fuzz target for `nmap_sys::tls`, the TLS client behind NSE's
// `connect(..., "ssl")` and `reconnect_ssl` (M6.5 step f1). Its input is a
// peer's: whatever a server sends after the client's ClientHello.
//
// The client is the shipped one (`client_config()`: the first-party
// provider and the nmap-rules verifier). What a server's flight reaches in
// plaintext is all first-party or the provider's: the ServerHello's key
// share (X25519 and NIST point checks), a TLS 1.2 Certificate (each entry
// through `core`'s `d2i_X509`, its key through the key decoder) and
// ServerKeyExchange (RSA PKCS#1 and PSS over num-bigint, ECDSA, Ed25519),
// the HelloRetryRequest, alerts. Checked: nothing panics, and the
// connection ends in an error or waits for more, within the input.
//
// The client random and key shares are fresh each run (the randomness seam
// is the OS's), so a ServerKeyExchange signature never verifies; the seeds
// (`gen_tls_seeds.py`: the step-f1 fixture servers' flights) carry real
// certificates and signatures, which drive the verifier to the end.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_sys::tls::client_config;
use rustls::pki_types::ServerName;
use rustls::ClientConnection;
use std::io::Read;

fuzz_target!(|data: &[u8]| {
    let Ok(name) = ServerName::try_from("fuzz.test") else {
        return;
    };
    let Ok(mut c) = ClientConnection::new(client_config(), name) else {
        return;
    };
    let mut sink = Vec::new();
    while c.wants_write() {
        if c.write_tls(&mut sink).is_err() {
            break;
        }
    }
    let mut rd = data;
    let mut plain = [0u8; 4096];
    // Each round consumes input or ends: a bound of one round per byte.
    for _ in 0..=data.len() {
        match c.read_tls(&mut rd) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if c.process_new_packets().is_err() {
            break;
        }
        while let Ok(n) = c.reader().read(&mut plain) {
            if n == 0 {
                break;
            }
        }
        sink.clear();
        while c.wants_write() {
            if c.write_tls(&mut sink).is_err() {
                break;
            }
        }
        if rd.is_empty() {
            break;
        }
    }
});
