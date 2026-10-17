//! Handshake signature verification: ECDSA over the RustCrypto curves, Ed25519
//! over `ed25519-dalek` (`verify_strict` only, LESSONS #037), RSA first-party
//! (`rsa.rs`). Offered both as rustls-pki-types algorithms, for the provider's
//! table, and as one dispatcher the nmap-rules verifier calls with the key type
//! it read itself (`spki.rs`), which is where OpenSSL's "key type matches the
//! scheme" check lives (`statem_clnt.c:1918-1922`).

use rustls::SignatureScheme;
use rustls_pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};

use crate::rsa::HashAlg;
use crate::spki::{ecdsa_sig_to_fixed, KeyType};

/// The hash a scheme names; for ECDSA in TLS 1.2 that is all it names: OpenSSL
/// signs with `ecdsa_secp256r1_sha256` under a P-384 key (the curve is bound
/// only in TLS 1.3), so the curve comes from the key and the hash from the
/// scheme, and the hash is verified as a prehash.
pub fn hash_for(scheme: SignatureScheme) -> Option<HashAlg> {
    Some(match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
        | SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PSS_SHA256 => HashAlg::Sha256,
        SignatureScheme::ECDSA_NISTP384_SHA384
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PSS_SHA384 => HashAlg::Sha384,
        SignatureScheme::ECDSA_NISTP521_SHA512
        | SignatureScheme::RSA_PKCS1_SHA512
        | SignatureScheme::RSA_PSS_SHA512 => HashAlg::Sha512,
        _ => return None,
    })
}

fn ecdsa(curve: &KeyType, hash: HashAlg, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ()> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    // FIPS 186-4 §6.4: e is the leftmost min(N, hashlen) bits of the hash, as
    // an integer. The `ecdsa` crate refuses a prehash shorter than half the
    // field (SHA-256 under P-521), so a short one is left-padded to the field
    // size here, which is the same integer.
    let field = match curve {
        KeyType::EcP256 => 32,
        KeyType::EcP384 => 48,
        KeyType::EcP521 => 66,
        _ => return Err(()),
    };
    let mut prehash = hash.digest_of(msg);
    if prehash.len() < field {
        let mut padded = vec![0u8; field - prehash.len()];
        padded.extend_from_slice(&prehash);
        prehash = padded;
    }
    match curve {
        KeyType::EcP256 => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| ())?;
            let sig =
                p256::ecdsa::Signature::from_slice(&ecdsa_sig_to_fixed(sig, 32).map_err(|_| ())?)
                    .map_err(|_| ())?;
            vk.verify_prehash(&prehash, &sig).map_err(|_| ())
        }
        KeyType::EcP384 => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| ())?;
            let sig =
                p384::ecdsa::Signature::from_slice(&ecdsa_sig_to_fixed(sig, 48).map_err(|_| ())?)
                    .map_err(|_| ())?;
            vk.verify_prehash(&prehash, &sig).map_err(|_| ())
        }
        KeyType::EcP521 => {
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| ())?;
            let sig =
                p521::ecdsa::Signature::from_slice(&ecdsa_sig_to_fixed(sig, 66).map_err(|_| ())?)
                    .map_err(|_| ())?;
            vk.verify_prehash(&prehash, &sig).map_err(|_| ())
        }
        _ => Err(()),
    }
}

fn ed25519(key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ()> {
    let key: &[u8; 32] = key.try_into().map_err(|_| ())?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| ())?;
    let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|_| ())?;
    vk.verify_strict(msg, &sig).map_err(|_| ())
}

fn rsa(hash: HashAlg, pss: bool, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ()> {
    let key = crate::rsa::parse_rsa_public_key(key).map_err(|_| ())?;
    let ok = if pss {
        key.verify_pss(hash, msg, sig)
    } else {
        key.verify_pkcs1(hash, msg, sig)
    };
    ok.then_some(()).ok_or(())
}

/// The key type each scheme needs.
pub fn key_type_for(scheme: SignatureScheme) -> Option<KeyType> {
    Some(match scheme {
        SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512
        | SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => KeyType::Rsa,
        SignatureScheme::ECDSA_NISTP256_SHA256 => KeyType::EcP256,
        SignatureScheme::ECDSA_NISTP384_SHA384 => KeyType::EcP384,
        SignatureScheme::ECDSA_NISTP521_SHA512 => KeyType::EcP521,
        SignatureScheme::ED25519 => KeyType::Ed25519,
        _ => return None,
    })
}

/// Verify `sig` over `msg` under `scheme` with the raw subject public key of
/// type `key_type`, which the caller has already matched to the scheme as the
/// protocol version requires.
pub fn verify_with_key(
    scheme: SignatureScheme,
    key_type: &KeyType,
    key: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), ()> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 => rsa(HashAlg::Sha256, false, key, msg, sig),
        SignatureScheme::RSA_PKCS1_SHA384 => rsa(HashAlg::Sha384, false, key, msg, sig),
        SignatureScheme::RSA_PKCS1_SHA512 => rsa(HashAlg::Sha512, false, key, msg, sig),
        SignatureScheme::RSA_PSS_SHA256 => rsa(HashAlg::Sha256, true, key, msg, sig),
        SignatureScheme::RSA_PSS_SHA384 => rsa(HashAlg::Sha384, true, key, msg, sig),
        SignatureScheme::RSA_PSS_SHA512 => rsa(HashAlg::Sha512, true, key, msg, sig),
        SignatureScheme::ECDSA_NISTP256_SHA256
        | SignatureScheme::ECDSA_NISTP384_SHA384
        | SignatureScheme::ECDSA_NISTP521_SHA512 => {
            ecdsa(key_type, hash_for(scheme).ok_or(())?, key, msg, sig)
        }
        SignatureScheme::ED25519 => ed25519(key, msg, sig),
        _ => Err(()),
    }
}

/// Verify with the key type the scheme itself implies (TLS 1.3's binding).
pub fn verify_raw(scheme: SignatureScheme, key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ()> {
    let kt = key_type_for(scheme).ok_or(())?;
    verify_with_key(scheme, &kt, key, msg, sig)
}

/// A rustls-pki-types algorithm, for the provider's table.
#[derive(Debug)]
pub struct Alg {
    scheme: SignatureScheme,
    pk: AlgorithmIdentifier,
    sig: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for Alg {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_raw(self.scheme, public_key, message, signature).map_err(|()| InvalidSignature)
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.pk
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.sig
    }
}

pub static ECDSA_P256_SHA256: Alg = Alg {
    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
    pk: alg_id::ECDSA_P256,
    sig: alg_id::ECDSA_SHA256,
};
pub static ECDSA_P384_SHA384: Alg = Alg {
    scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
    pk: alg_id::ECDSA_P384,
    sig: alg_id::ECDSA_SHA384,
};
pub static ECDSA_P521_SHA512: Alg = Alg {
    scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
    pk: alg_id::ECDSA_P521,
    sig: alg_id::ECDSA_SHA512,
};
pub static ED25519: Alg = Alg {
    scheme: SignatureScheme::ED25519,
    pk: alg_id::ED25519,
    sig: alg_id::ED25519,
};
pub static RSA_PSS_SHA256: Alg = Alg {
    scheme: SignatureScheme::RSA_PSS_SHA256,
    pk: alg_id::RSA_ENCRYPTION,
    sig: alg_id::RSA_PSS_SHA256,
};
pub static RSA_PSS_SHA384: Alg = Alg {
    scheme: SignatureScheme::RSA_PSS_SHA384,
    pk: alg_id::RSA_ENCRYPTION,
    sig: alg_id::RSA_PSS_SHA384,
};
pub static RSA_PSS_SHA512: Alg = Alg {
    scheme: SignatureScheme::RSA_PSS_SHA512,
    pk: alg_id::RSA_ENCRYPTION,
    sig: alg_id::RSA_PSS_SHA512,
};
pub static RSA_PKCS1_SHA256: Alg = Alg {
    scheme: SignatureScheme::RSA_PKCS1_SHA256,
    pk: alg_id::RSA_ENCRYPTION,
    sig: alg_id::RSA_PKCS1_SHA256,
};
pub static RSA_PKCS1_SHA384: Alg = Alg {
    scheme: SignatureScheme::RSA_PKCS1_SHA384,
    pk: alg_id::RSA_ENCRYPTION,
    sig: alg_id::RSA_PKCS1_SHA384,
};
pub static RSA_PKCS1_SHA512: Alg = Alg {
    scheme: SignatureScheme::RSA_PKCS1_SHA512,
    pk: alg_id::RSA_ENCRYPTION,
    sig: alg_id::RSA_PKCS1_SHA512,
};
