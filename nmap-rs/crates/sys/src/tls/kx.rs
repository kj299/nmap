//! Key exchange: X25519 over `x25519-dalek`; P-256, P-384 and P-521 over the
//! RustCrypto curve crates; X448 first-party ([`super::x448`]); and the RFC
//! 7919 FFDHE groups, for TLS 1.2 DHE and TLS 1.3 key shares, over
//! `crypto-bigint`'s constant-time Montgomery exponentiation (M6.7 step a).
//! The threat model's rule holds (docs/M6.5-ANALYSIS.md: no secret-dependent
//! work over `num-bigint`): every operation on a secret here is constant time
//! in it. Each exchange draws a fresh ephemeral secret from the randomness
//! seam, and refuses to start when the seam gives nothing.

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use rustls::crypto::{ActiveKeyExchange, GetRandomFailed, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion, SupportedProtocolVersion};

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
            use $curve::elliptic_curve::sec1::ToSec1Point;
            use $curve::elliptic_curve::Generate;

            #[derive(Debug)]
            pub(crate) struct $name;

            impl SupportedKxGroup for $name {
                fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
                    source()?;
                    let secret = $curve::ecdh::EphemeralSecret::try_generate_from_rng(
                        &mut crate::tls::rand::Rng,
                    )
                    .map_err(|_| Error::from(GetRandomFailed))?;
                    let public = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
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

// ---- X448 ---------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct X448;

impl SupportedKxGroup for X448 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut secret = [0u8; 56];
        if !nmap_core::nse::openssl::rand::fill(&mut secret) {
            return Err(GetRandomFailed.into());
        }
        let public = super::x448::public(&secret);
        Ok(Box::new(X448Active { secret, public }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X448
    }
}

struct X448Active {
    secret: [u8; 56],
    public: [u8; 56],
}

impl Drop for X448Active {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

impl ActiveKeyExchange for X448Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 56] = peer
            .try_into()
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = super::x448::x448(&self.secret, &peer);
        // RFC 7748 §6.2: an all-zero result means a low-order peer point.
        if shared.iter().fold(0u8, |acc, b| acc | b) == 0 {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared[..]))
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X448
    }
}

// ---- FFDHE (RFC 7919) ------------------------------------------------------------

/// One RFC 7919 group, with the private-exponent length OpenSSL uses for it
/// (`ossl_ffc_named_group_get_keylength`: twice the group's security
/// strength, 225 to 400 bits). The length is public, and the exponentiation
/// is constant time for a given length.
#[derive(Debug)]
pub(crate) struct Ffdhe {
    pub(crate) name: NamedGroup,
    pub(crate) group: FfdheGroup<'static>,
    pub(crate) exp_bits: u32,
}

impl Ffdhe {
    fn params(&self) -> BoxedMontyParams {
        let p = BoxedUint::from_be_slice_vartime(self.group.p);
        // The modulus is public: its parameters may be computed in
        // variable time.
        BoxedMontyParams::new_vartime(Odd::new(p).expect("an RFC 7919 prime is odd"))
    }
}

impl Ffdhe {
    /// The exchange with private exponent `x` (big-endian, kept to
    /// `exp_bits` bits): g^x mod p, constant time in x.
    fn active(&self, mut x: Vec<u8>) -> Result<FfdheActive, Error> {
        let len = self.group.p.len();
        let bits_precision =
            u32::try_from(len.saturating_mul(8)).map_err(|_| Error::from(GetRandomFailed))?;
        let x_bits = u32::try_from(x.len().saturating_mul(8)).unwrap_or(u32::MAX);
        let extra = x_bits.saturating_sub(self.exp_bits);
        if let Some(first) = x.first_mut() {
            *first &= 0xffu8.checked_shr(extra).unwrap_or(0);
        }
        let xb = BoxedUint::from_be_slice(&x, bits_precision)
            .map_err(|_| Error::from(GetRandomFailed))?;
        zeroize::Zeroize::zeroize(&mut x);
        let params = self.params();
        let g = BoxedUint::from_be_slice(self.group.g, bits_precision)
            .map_err(|_| Error::from(GetRandomFailed))?;
        let y = BoxedMontyForm::new(g, &params)
            .pow_bounded_exp(&xb, self.exp_bits)
            .retrieve();
        Ok(FfdheActive {
            name: self.name,
            group: self.group,
            params,
            x: xb,
            exp_bits: self.exp_bits,
            public: pad(&y.to_be_bytes(), len),
        })
    }
}

impl SupportedKxGroup for Ffdhe {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // x in [0, 2^exp_bits), as OpenSSL draws it.
        let mut x = vec![0u8; (self.exp_bits as usize).div_ceil(8)];
        if !nmap_core::nse::openssl::rand::fill(&mut x) {
            return Err(GetRandomFailed.into());
        }
        Ok(Box::new(self.active(x)?))
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        Some(self.group)
    }
    fn name(&self) -> NamedGroup {
        self.name
    }
}

/// `bytes` (big-endian) as exactly `len` bytes: leading zeros added or
/// removed. The value is below p, so only zeros are removed.
fn pad(bytes: &[u8], len: usize) -> Vec<u8> {
    match bytes.len().checked_sub(len) {
        Some(cut) => bytes.get(cut..).unwrap_or_default().to_vec(),
        None => {
            let mut v = vec![0u8; len.saturating_sub(bytes.len())];
            v.extend_from_slice(bytes);
            v
        }
    }
}

struct FfdheActive {
    name: NamedGroup,
    group: FfdheGroup<'static>,
    params: BoxedMontyParams,
    x: BoxedUint,
    exp_bits: u32,
    public: Vec<u8>,
}

impl Drop for FfdheActive {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.x);
    }
}

impl FfdheActive {
    /// y^x mod p for the peer's y, which must satisfy 1 < y < p - 1 (RFC
    /// 7919 §5.1, OpenSSL's `DH_check_pub_key`). The check is on public data.
    fn agree(&self, peer: &[u8]) -> Result<SharedSecret, Error> {
        let len = self.group.p.len();
        let bad = || Error::from(PeerMisbehaved::InvalidKeyShare);
        if peer.len() > len {
            return Err(bad());
        }
        let bits = self.params.bits_precision();
        let p = BoxedUint::from_be_slice(self.group.p, bits).map_err(|_| bad())?;
        let y = BoxedUint::from_be_slice(&pad(peer, len), bits).map_err(|_| bad())?;
        let one = BoxedUint::one_with_precision(bits);
        let p_minus_1 = p.wrapping_sub(&one);
        if y <= one || y >= p_minus_1 {
            return Err(bad());
        }
        let z = BoxedMontyForm::new(y, &self.params)
            .pow_bounded_exp(&self.x, self.exp_bits)
            .retrieve();
        Ok(SharedSecret::from(pad(&z.to_be_bytes(), len).as_slice()))
    }

    /// The TLS 1.2 form of the secret: without its leading zeros (RFC 5246
    /// §8.1.2). How many there are is public once the secret is used.
    fn agree_tls12(&self, peer: &[u8]) -> Result<SharedSecret, Error> {
        let secret = self.agree(peer)?;
        let b = secret.secret_bytes();
        let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        Ok(SharedSecret::from(&b[start..]))
    }
}

impl ActiveKeyExchange for FfdheActive {
    /// TLS 1.3 (RFC 8446 §4.2.8.1): the share is exactly as long as p, and
    /// so is the secret.
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if peer.len() != self.group.p.len() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        self.agree(peer)
    }
    /// TLS 1.2 (RFC 5246 §8.1.2): `dh_Ys` may be shorter than p, and the
    /// secret loses its leading zeros.
    fn complete_for_tls_version(
        self: Box<Self>,
        peer: &[u8],
        version: &SupportedProtocolVersion,
    ) -> Result<SharedSecret, Error> {
        if version.version != ProtocolVersion::TLSv1_2 {
            return self.complete(peer);
        }
        self.agree_tls12(peer)
    }
    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        Some(self.group)
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        self.name
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test vectors: fixed small ranges"
)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    static G2048: Ffdhe = Ffdhe {
        name: NamedGroup::FFDHE2048,
        group: rustls::ffdhe_groups::FFDHE2048,
        exp_bits: 225,
    };
    static G3072: Ffdhe = Ffdhe {
        name: NamedGroup::FFDHE3072,
        group: rustls::ffdhe_groups::FFDHE3072,
        exp_bits: 275,
    };

    /// The public value and the agreed secret, against `num-bigint`'s
    /// modpow (an independent implementation; public test values only).
    #[test]
    #[cfg_attr(
        miri,
        ignore = "2,048-bit exponentiations and X448 ladders take minutes under Miri"
    )]
    fn ffdhe_agrees_with_an_independent_modpow() {
        for g in [&G2048, &G3072] {
            let p = BigUint::from_bytes_be(g.group.p);
            let n = (g.exp_bits as usize).div_ceil(8) as u8;
            let xa: Vec<u8> = (1..=n).collect();
            let xb: Vec<u8> = (100..100 + n).rev().collect();
            let a = g.active(xa.clone()).expect("a");
            let b = g.active(xb.clone()).expect("b");
            let mask = |x: &[u8], bits: u32| {
                let mut x = x.to_vec();
                x[0] &= 0xff >> (x.len() as u32 * 8 - bits);
                BigUint::from_bytes_be(&x)
            };
            let ya = BigUint::from(2u8).modpow(&mask(&xa, g.exp_bits), &p);
            assert_eq!(a.pub_key(), pad(&ya.to_bytes_be(), g.group.p.len()));
            assert_eq!(a.pub_key().len(), g.group.p.len());
            let want = ya.modpow(&mask(&xb, g.exp_bits), &p);
            let ab = Box::new(a)
                .complete(&pad(
                    &BigUint::from_bytes_be(b.pub_key()).to_bytes_be(),
                    g.group.p.len(),
                ))
                .expect("ab");
            let ba = Box::new(b)
                .complete(&pad(&ya.to_bytes_be(), g.group.p.len()))
                .expect("ba");
            assert_eq!(ab.secret_bytes(), ba.secret_bytes());
            assert_eq!(ab.secret_bytes(), pad(&want.to_bytes_be(), g.group.p.len()));
        }
    }

    /// The peer's value must satisfy 1 < y < p - 1 and fit in p's length;
    /// TLS 1.3 wants exactly p's length.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "2,048-bit exponentiations and X448 ladders take minutes under Miri"
    )]
    fn ffdhe_refuses_out_of_range_shares() {
        let len = G2048.group.p.len();
        let p = BigUint::from_bytes_be(G2048.group.p);
        let one = BigUint::from(1u8);
        for y in [
            BigUint::from(0u8),
            one.clone(),
            &p - &one,
            p.clone(),
            &p + &one,
        ] {
            let a = G2048.active(vec![5; 29]).expect("a");
            let share = pad(&y.to_bytes_be(), len);
            assert!(Box::new(a).complete(&share).is_err(), "y = {y}");
        }
        let a = G2048.active(vec![5; 29]).expect("a");
        assert!(
            Box::new(a).complete(&[2u8; 255]).is_err(),
            "short TLS 1.3 share"
        );
        let a = G2048.active(vec![5; 29]).expect("a");
        assert!(
            Box::new(a).complete(&vec![2u8; len + 1]).is_err(),
            "long share"
        );
    }

    /// TLS 1.2: `dh_Ys` may come without its leading zeros, and the secret
    /// drops its own (RFC 5246 §8.1.2). The exponent is searched for until
    /// the secret starts with a zero byte (about one in 256), so the
    /// stripping is seen to happen; OpenSSL's server strips it too, and
    /// keeping it would fail one DHE handshake in 256.
    #[test]
    #[cfg_attr(miri, ignore = "hundreds of 2,048-bit exponentiations")]
    fn ffdhe_tls12_takes_short_shares_and_strips_the_secret() {
        let len = G2048.group.p.len();
        let mut found = false;
        for n in 0u16..4096 {
            let mut x = vec![7u8; 29];
            x[27..].copy_from_slice(&n.to_be_bytes());
            let full = Box::new(G2048.active(x.clone()).expect("a"))
                .complete(&pad(&[2u8], len))
                .expect("y = 2, padded");
            if full.secret_bytes()[0] != 0 {
                continue;
            }
            let s12 = Box::new(G2048.active(x).expect("a"))
                .complete_for_tls_version(&[2u8], &rustls::version::TLS12)
                .expect("y = 2, one byte");
            let b = full.secret_bytes();
            let start = b.iter().position(|&v| v != 0).expect("nonzero");
            assert!(start >= 1);
            assert_eq!(s12.secret_bytes(), &b[start..]);
            assert!(s12.secret_bytes().len() < len);
            found = true;
            break;
        }
        assert!(found, "no secret with a leading zero in 4,096 exponents");
    }

    /// X448 refuses a low-order share (the all-zero result) and a share of
    /// the wrong length.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "2,048-bit exponentiations and X448 ladders take minutes under Miri"
    )]
    fn x448_refuses_low_order_and_misshapen_shares() {
        let a = X448.start().expect("x448");
        assert!(a.complete(&[0u8; 56]).is_err());
        let a = X448.start().expect("x448");
        assert!(a.complete(&[5u8; 55]).is_err());
    }
}
