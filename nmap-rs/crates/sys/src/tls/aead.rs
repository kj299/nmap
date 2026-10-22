//! AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 for TLS 1.3 and TLS 1.2,
//! over `aes-gcm` (AES-NI or the fixsliced software AES; POLYVAL/GHASH
//! constant-time) and `chacha20poly1305`. The record-layer framing follows
//! rustls's own ring-backed implementation (`crypto/ring/tls12.rs`, `tls13.rs`
//! at 0.23.46). A record shorter than its tag (and explicit nonce) is a
//! decrypt error, never an underflow.

use std::marker::PhantomData;

use aes_gcm::aead::generic_array::typenum::{U12, U16};
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

// ---- TLS 1.2, GCM: a 4-byte salt and an 8-byte explicit nonce ----------------

pub struct Gcm12<A>(PhantomData<fn() -> A>);

impl<A> Gcm12<A> {
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

impl<A: Cipher> Tls12AeadAlgorithm for Gcm12<A> {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(GcmEnc12 {
            aead: A::new_from_slice(key.as_ref()).expect("key length from key_block_shape"),
            iv: gcm_iv(write_iv, explicit),
        })
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let mut salt = [0u8; 4];
        salt.copy_from_slice(iv);
        Box::new(GcmDec12 {
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

struct GcmEnc12<A> {
    aead: A,
    iv: Iv,
}

impl<A: Cipher> MessageEncrypter for GcmEnc12<A> {
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
        payload_len.saturating_add(GCM_EXPLICIT + TAG_LEN)
    }
}

struct GcmDec12<A> {
    aead: A,
    salt: [u8; 4],
}

impl<A: Cipher> MessageDecrypter for GcmDec12<A> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let len = payload.len();
        let body_len = len
            .checked_sub(GCM_EXPLICIT + TAG_LEN)
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
