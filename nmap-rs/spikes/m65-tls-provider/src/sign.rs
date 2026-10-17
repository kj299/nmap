//! A P-256 signer for the fixture server only (the client never signs). It can
//! corrupt its output, which is how the "bad TLS 1.3 CertificateVerify"
//! fixture is produced: a server that otherwise handshakes correctly.

use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};

#[derive(Debug, Clone)]
pub struct P256Signer {
    key: p256::ecdsa::SigningKey,
    corrupt: bool,
}

impl P256Signer {
    pub fn from_scalar(scalar: &[u8], corrupt: bool) -> Result<Self, &'static str> {
        let key = p256::ecdsa::SigningKey::from_slice(scalar).map_err(|_| "not a P-256 scalar")?;
        Ok(Self { key, corrupt })
    }
}

impl SigningKey for P256Signer {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for P256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.key.sign(message);
        let (r, s) = sig.split_bytes();
        let mut der = der_sequence(&[der_integer(&r), der_integer(&s)].concat());
        if self.corrupt {
            // Flip the low bit of the last byte of `s`: still a well-formed
            // signature, no longer a valid one.
            let n = der.len();
            der[n - 1] ^= 1;
        }
        Ok(der)
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        vec![0x81, n as u8]
    }
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = {
        let mut b = bytes;
        while b.len() > 1 && b[0] == 0 {
            b = &b[1..];
        }
        let mut v = Vec::new();
        if b[0] & 0x80 != 0 {
            v.push(0);
        }
        v.extend_from_slice(b);
        v
    };
    let mut out = vec![0x02];
    out.extend(der_len(trimmed.len()));
    out.extend(trimmed);
    out
}

fn der_sequence(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend(der_len(body.len()));
    out.extend_from_slice(body);
    out
}
