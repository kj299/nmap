//! Key exchange: X25519 over `x25519-dalek`; P-256, P-384 and P-521 over the
//! RustCrypto curve crates. No FFDHE: that would need secret-dependent bignum
//! arithmetic, which the threat model (§6) forbids outside constant-time code.
//! Each exchange draws a fresh ephemeral secret from the randomness seam, and
//! refuses to start when the seam gives nothing.

use rustls::crypto::{ActiveKeyExchange, GetRandomFailed, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

fn source() -> Result<(), Error> {
    if crate::tls::rand::available() {
        Ok(())
    } else {
        Err(Error::from(GetRandomFailed))
    }
}

#[derive(Debug)]
pub(crate) struct X25519;

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        source()?;
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(crate::tls::rand::Rng);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Ok(Box::new(X25519Active { secret, public }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Active {
    secret: x25519_dalek::EphemeralSecret,
    public: [u8; 32],
}

impl ActiveKeyExchange for X25519Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // RFC 7748 §6.1: an all-zero result means a low-order peer point.
        if !shared.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

macro_rules! nist_group {
    ($modname:ident, $name:ident, $curve:ident, $group:expr) => {
        pub(crate) use $modname::$name;
        mod $modname {
            use super::*;
            use $curve::elliptic_curve::sec1::ToEncodedPoint;

            #[derive(Debug)]
            pub(crate) struct $name;

            impl SupportedKxGroup for $name {
                fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                    source()?;
                    let secret = $curve::ecdh::EphemeralSecret::random(&mut crate::tls::rand::Rng);
                    let public = secret
                        .public_key()
                        .to_encoded_point(false)
                        .as_bytes()
                        .to_vec();
                    Ok(Box::new(Active { secret, public }))
                }
                fn name(&self) -> NamedGroup {
                    $group
                }
            }

            struct Active {
                secret: $curve::ecdh::EphemeralSecret,
                public: Vec<u8>,
            }

            impl ActiveKeyExchange for Active {
                fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
                    // The peer's point must be uncompressed and on the curve.
                    if peer.first() != Some(&0x04) {
                        return Err(PeerMisbehaved::InvalidKeyShare.into());
                    }
                    let peer = $curve::PublicKey::from_sec1_bytes(peer)
                        .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
                    let shared = self.secret.diffie_hellman(&peer);
                    Ok(SharedSecret::from(shared.raw_secret_bytes().as_slice()))
                }
                fn pub_key(&self) -> &[u8] {
                    &self.public
                }
                fn group(&self) -> NamedGroup {
                    $group
                }
            }
        }
    };
}

nist_group!(p256_group, Secp256r1, p256, NamedGroup::secp256r1);
nist_group!(p384_group, Secp384r1, p384, NamedGroup::secp384r1);
nist_group!(p521_group, Secp521r1, p521, NamedGroup::secp521r1);
