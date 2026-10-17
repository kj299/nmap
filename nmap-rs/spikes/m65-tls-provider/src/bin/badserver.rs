//! A TLS 1.3-only fixture server over the same provider, whose P-256
//! CertificateVerify signature is corrupted when `--corrupt` is given. It
//! serves one connection after another until killed, printing per connection
//! what the client did (handshake completed, or the alert it sent).
//! Arguments: PORT CERT.der SCALAR.hex [--corrupt]

use std::net::TcpListener;
use std::sync::Arc;

use m65_tls_provider_spike::provider::provider;
use m65_tls_provider_spike::sign::P256Signer;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args[1].parse().expect("PORT");
    let cert = std::fs::read(&args[2]).expect("certificate DER");
    let scalar = unhex(
        std::fs::read_to_string(&args[3])
            .expect("scalar file")
            .trim(),
    );
    let corrupt = args.iter().any(|a| a == "--corrupt");
    let signer = P256Signer::from_scalar(&scalar, corrupt).expect("scalar");
    let key = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(cert)],
        Arc::new(signer),
    ));
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(key))),
    );
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    println!("listening corrupt={corrupt}");
    for stream in listener.incoming() {
        let mut sock = match stream {
            Ok(s) => s,
            Err(e) => {
                println!("accept: {e}");
                continue;
            }
        };
        let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let mut conn = rustls::ServerConnection::new(cfg.clone()).expect("connection");
        let mut outcome = String::from("handshake completed");
        while conn.is_handshaking() {
            match conn.complete_io(&mut sock) {
                Ok(_) => {}
                Err(e) => {
                    outcome = format!("client: {e}");
                    break;
                }
            }
        }
        if !conn.is_handshaking() {
            // Let the client's close_notify or alert arrive.
            let _ = conn.complete_io(&mut sock);
            if let Err(e) = conn.complete_io(&mut sock) {
                outcome = format!("after handshake: {e}");
            }
        }
        println!("{outcome}");
    }
}
