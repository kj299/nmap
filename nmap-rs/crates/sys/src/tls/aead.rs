//! AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 for TLS 1.3 and TLS 1.2,
//! over `aes-gcm` (AES-NI or the fixsliced software AES; POLYVAL/GHASH
//! constant-time) and `chacha20poly1305`; and for TLS 1.2 (M6.7 step a)
//! AES-CCM and AES-CCM-8 (RFC 6655, 7251) over `ccm`, and ARIA-GCM (RFC
//! 6209) under `aes-gcm`'s generic GCM. All TLS 1.2 AEADs but ChaCha20 frame
//! records alike: a 4-byte salt from the key block and an 8-byte explicit
//! nonce, only the tag length differing (8 for CCM-8, 16 otherwise). The record-layer framing follows
//! rustls's own ring-backed implementation (`crypto/ring/tls12.rs`, `tls13.rs`
//! at 0.23.46). A record shorter than its tag (and explicit nonce) is a
//! decrypt error, never an underflow.

use std::marker::PhantomData;

use aes_gcm::aead::generic_array::typenum::{Unsigned, U12, U16, U8};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit};
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};

/// The three AEADs share this shape: a 12-byte nonce and a 16-byte tag.
pub(crate) trait Cipher:
    AeadInPlace + AeadCore<NonceSize = U12, TagSize = U16> + KeyInit + Send + Sync + 'static
{
}
impl<T> Cipher for T where
    T: AeadInPlace + AeadCore<NonceSize = U12, TagSize = U16> + KeyInit + Send + Sync + 'static
{
}

const TAG_LEN: usize = 16;

/// A TLS 1.2 AEAD with an explicit nonce: a 12-byte nonce, any tag length.
pub(crate) trait Cipher12:
    AeadInPlace + AeadCore<NonceSize = U12> + KeyInit + Send + Sync + 'static
{
}
impl<T> Cipher12 for T where
    T: AeadInPlace + AeadCore<NonceSize = U12> + KeyInit + Send + Sync + 'static
{
}

fn tag_len<A: Cipher12>() -> usize {
    <A as AeadCore>::TagSize::USIZE
}

/// The explicit nonce and the tag: what a TLS 1.2 record adds.
fn overhead<A: Cipher12>() -> usize {
    GCM_EXPLICIT.saturating_add(tag_len::<A>())
}

pub(crate) type Aria128Gcm = aes_gcm::AesGcm<aria::Aria128, U12>;
pub(crate) type Aria256Gcm = aes_gcm::AesGcm<aria::Aria256, U12>;
pub(crate) type Aes128Ccm = ccm::Ccm<aes::Aes128, U16, U12>;
pub(crate) type Aes256Ccm = ccm::Ccm<aes::Aes256, U16, U12>;
pub(crate) type Aes128Ccm8 = ccm::Ccm<aes::Aes128, U8, U12>;
pub(crate) type Aes256Ccm8 = ccm::Ccm<aes::Aes256, U8, U12>;

// ---- TLS 1.3 -----------------------------------------------------------------

pub struct Aead13<A>(PhantomData<fn() -> A>);

impl<A> Aead13<A> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<A: Cipher> Tls13AeadAlgorithm for Aead13<A> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Enc13 {
            aead: A::new_from_slice(key.as_ref()).expect("rustls derives a key of key_len()"),
            iv,
        })
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Dec13 {
            aead: A::new_from_slice(key.as_ref()).expect("rustls derives a key of key_len()"),
            iv,
        })
    }
    fn key_len(&self) -> usize {
        A::key_size()
    }
    fn extract_keys(
        &self,
        _: AeadKey,
        _: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

struct Enc13<A> {
    aead: A,
    iv: Iv,
}

impl<A: Cipher> MessageEncrypter for Enc13<A> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&[u8::from(msg.typ)]);
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(total_len);
        let tag = self
            .aead
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, payload.as_mut())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len.saturating_add(1 + TAG_LEN)
    }
}

struct Dec13<A> {
    aead: A,
    iv: Iv,
}

impl<A: Cipher> MessageDecrypter for Dec13<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let len = payload.len();
        let body_len = len.checked_sub(TAG_LEN).ok_or(Error::DecryptError)?;
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(len);
        let (body, tag) = payload.split_at_mut(body_len);
        self.aead
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                &aad,
                body,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(body_len);
        msg.into_tls13_unpadded_message()
    }
}

// ---- TLS 1.2, GCM and CCM: a 4-byte salt and an 8-byte explicit nonce --------

pub struct Aead12<A>(PhantomData<fn() -> A>);

impl<A> Aead12<A> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

const GCM_EXPLICIT: usize = 8;

fn gcm_iv(write_iv: &[u8], explicit: &[u8]) -> Iv {
    let mut iv = [0u8; 12];
    iv[..4].copy_from_slice(write_iv);
    iv[4..].copy_from_slice(explicit);
    Iv::new(iv)
}

impl<A: Cipher12> Tls12AeadAlgorithm for Aead12<A> {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(Enc12 {
            aead: A::new_from_slice(key.as_ref()).expect("key length from key_block_shape"),
            iv: gcm_iv(write_iv, explicit),
        })
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut salt = [0u8; 4];
        salt.copy_from_slice(iv);
        Box::new(Dec12 {
            aead: A::new_from_slice(key.as_ref()).expect("key length from key_block_shape"),
            salt,
        })
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: A::key_size(),
            fixed_iv_len: 4,
            explicit_nonce_len: GCM_EXPLICIT,
        }
    }
    fn extract_keys(
        &self,
        _: AeadKey,
        _: &[u8],
        _: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

struct Enc12<A> {
    aead: A,
    iv: Iv,
}

impl<A: Cipher12> MessageEncrypter for Enc12<A> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        payload.extend_from_slice(&nonce[4..]);
        payload.extend_from_chunks(&msg.payload);
        let tag = self
            .aead
            .encrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                &aad,
                &mut payload.as_mut()[GCM_EXPLICIT..],
            )
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len.saturating_add(overhead::<A>())
    }
}

struct Dec12<A> {
    aead: A,
    salt: [u8; 4],
}

impl<A: Cipher12> MessageDecrypter for Dec12<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let len = payload.len();
        let body_len = len
            .checked_sub(overhead::<A>())
            .ok_or(Error::DecryptError)?;
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&payload[..GCM_EXPLICIT]);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, body_len);
        let (body, tag) = payload[GCM_EXPLICIT..].split_at_mut(body_len);
        self.aead
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                &aad,
                body,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| Error::DecryptError)?;
        Ok(msg.into_plain_message_range(GCM_EXPLICIT..GCM_EXPLICIT.saturating_add(body_len)))
    }
}

/// A TLS 1.2 decrypter for `A` keyed with `key` directly, for the fuzz
/// target (`tls::fuzzing::open_tls12`): rustls's public `AeadKey` holds only
/// 32-byte keys.
pub(crate) fn decrypter12<A: Cipher12>(
    key: &[u8],
    salt: [u8; 4],
) -> Option<Box<dyn MessageDecrypter>> {
    Some(Box::new(Dec12 {
        aead: A::new_from_slice(key).ok()?,
        salt,
    }))
}

// ---- TLS 1.2, ChaCha20-Poly1305: a 12-byte IV, no explicit nonce -------------

pub struct Chacha12;

impl Tls12AeadAlgorithm for Chacha12 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(ChachaEnc12 {
            aead: chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("32-byte key"),
            iv: Iv::copy(iv),
        })
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(ChachaDec12 {
            aead: chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("32-byte key"),
            iv: Iv::copy(iv),
        })
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }
    fn extract_keys(
        &self,
        _: AeadKey,
        _: &[u8],
        _: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

struct ChachaEnc12 {
    aead: chacha20poly1305::ChaCha20Poly1305,
    iv: Iv,
}

impl MessageEncrypter for ChachaEnc12 {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let tag = self
            .aead
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, payload.as_mut())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len.saturating_add(TAG_LEN)
    }
}

struct ChachaDec12 {
    aead: chacha20poly1305::ChaCha20Poly1305,
    iv: Iv,
}

impl MessageDecrypter for ChachaDec12 {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let len = payload.len();
        let body_len = len.checked_sub(TAG_LEN).ok_or(Error::DecryptError)?;
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, body_len);
        let (body, tag) = payload.split_at_mut(body_len);
        self.aead
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                &aad,
                body,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| Error::DecryptError)?;
        payload.truncate(body_len);
        Ok(msg.into_plain_message())
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
    use rustls::crypto::cipher::{InboundOpaqueMessage, OutboundPlainMessage};

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    const NONCE: [u8; 12] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ];

    /// Known answers computed by OpenSSL 3.0.13's libcrypto (EVP, the
    /// ciphers 7.94 negotiates with): key 0x40.., the nonce above, AAD
    /// 0x00..0x0c, plaintext 0x20..0x44; ciphertext then tag. The AES-128-CCM
    /// ciphertext's first 24 bytes are also NIST SP 800-38C example 3's.
    fn known<A: Cipher12>(key_len: usize, want: &str) {
        let key: Vec<u8> = (0x40..0x40 + key_len as u8).collect();
        let aad: Vec<u8> = (0..13).collect();
        let pt: Vec<u8> = (0x20..0x45).collect();
        let aead = A::new_from_slice(&key).expect("key");
        let mut buf = pt.clone();
        let tag = aead
            .encrypt_in_place_detached(GenericArray::from_slice(&NONCE), &aad, &mut buf)
            .expect("seal");
        let mut got = buf.clone();
        got.extend_from_slice(&tag);
        assert_eq!(got, h(want));
        aead.decrypt_in_place_detached(GenericArray::from_slice(&NONCE), &aad, &mut buf, &tag)
            .expect("open");
        assert_eq!(buf, pt);
        // Any bit of the tag flipped: refused.
        let mut bad = tag.clone();
        bad[0] ^= 1;
        let mut buf = got[..pt.len()].to_vec();
        assert!(aead
            .decrypt_in_place_detached(GenericArray::from_slice(&NONCE), &aad, &mut buf, &bad)
            .is_err());
    }

    #[test]
    fn aes_128_ccm_known_answer() {
        known::<Aes128Ccm>(16, "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5541bd1d416fa0ce3ec37af206eb79e569d79164f9f8aad7cfd72784374");
    }
    #[test]
    fn aes_256_ccm_known_answer() {
        known::<Aes256Ccm>(32, "04f883aeb3bd0730eaf50bb6de4fa2212034e4e41b0e75e577f6bf2422c0f6d266a55d0cddabd3c84a24e37e3188556904f9c5c2ed");
    }
    #[test]
    fn aes_128_ccm_8_known_answer() {
        known::<Aes128Ccm8>(16, "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5541bd1d416fa0ce3ec37af206e39b37da9ee6bcf6d");
    }
    #[test]
    fn aes_256_ccm_8_known_answer() {
        known::<Aes256Ccm8>(32, "04f883aeb3bd0730eaf50bb6de4fa2212034e4e41b0e75e577f6bf2422c0f6d266a55d0cddc3dbd54ee4bd9f59");
    }
    #[test]
    fn aria_128_gcm_known_answer() {
        known::<Aria128Gcm>(16, "05f443cfd40b2822bbc567ab855508f6f40fbdf962a796deb0680765169e7a9d5c58ae4d776df4a93efe0b9f166c58aa5cac87075f");
    }
    #[test]
    fn aria_256_gcm_known_answer() {
        known::<Aria256Gcm>(32, "413b8d583ca3e1002c5bf27ef11691fb2d57eb7225a01eb7a9a4890aba9e8c49f2a7bac245f0ee8a9301e19c073f61e754ce7f098b");
    }

    /// The TLS 1.2 framing with an 8-byte tag (CCM-8): a record round-trips,
    /// is 8 + payload + 8 bytes long, and a record shorter than the explicit
    /// nonce and the tag is a decrypt error, never an underflow.
    #[test]
    fn ccm_8_records_frame_and_refuse_short_ones() {
        // AES-256 (rustls's public AeadKey constructor takes 32 bytes).
        let alg: Aead12<Aes256Ccm8> = Aead12::new();
        let shape = alg.key_block_shape();
        assert_eq!(
            (
                shape.enc_key_len,
                shape.fixed_iv_len,
                shape.explicit_nonce_len
            ),
            (32, 4, 8)
        );
        let mut enc = alg.encrypter(
            AeadKey::from([7u8; 32]),
            &[1, 2, 3, 4],
            &[9, 9, 9, 9, 9, 9, 9, 9],
        );
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: rustls::crypto::cipher::OutboundChunks::Single(b"hello, ccm-8"),
        };
        let sealed = enc.encrypt(msg, 5).expect("seal");
        let mut raw = sealed.encode();
        assert_eq!(raw.len(), 5 + 8 + 12 + 8);
        let mut dec = alg.decrypter(AeadKey::from([7u8; 32]), &[1, 2, 3, 4]);
        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut raw[5..],
        );
        let plain = dec.decrypt(inbound, 5).expect("open");
        assert_eq!(plain.payload, b"hello, ccm-8");
        for len in 0..16 {
            let mut short = vec![0u8; len];
            let inbound = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut short,
            );
            assert!(
                matches!(dec.decrypt(inbound, 0), Err(Error::DecryptError)),
                "{len}"
            );
        }
    }
}
