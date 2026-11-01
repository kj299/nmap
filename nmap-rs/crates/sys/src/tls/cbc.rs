//! TLS 1.2 CBC record protection (M6.7 step d): the suites 7.94 offers with
//! AES, Camellia or SEED in CBC mode and HMAC-SHA-1, -SHA-256 or -SHA-384,
//! through the vendored rustls's patch 0003 (`mac_key_len`,
//! `encrypter_with_mac`, `decrypter_with_mac`).
//!
//! The record (RFC 5246 §6.2.3.2): a fresh random IV, then
//! - **MAC-then-encrypt** (the default): `CBC(IV, P || MAC(P) || padding)`,
//!   the MAC over `seq || type || version || length(P) || P`;
//! - **encrypt-then-MAC** (RFC 7366, when the server acknowledged it):
//!   `CBC(IV, P || padding) || MAC`, the MAC over
//!   `seq || type || version || length(IV || C) || IV || C`.
//!
//! The padding is the minimum, `p + 1` bytes of value `p`, as OpenSSL sends
//! it. On receipt the padding and the MAC are checked without a branch on
//! secret data, and the two are compared with `subtle`. With
//! MAC-then-encrypt the time to compute the MAC still depends on the
//! padding's length (Lucky 13, CVE-2013-0169); here the peer that could
//! measure it is the server, which holds the keys, so that is recorded
//! (docs/M6.7-ANALYSIS.md §6, §18) rather than countered with OpenSSL's
//! constant-time digest. Encrypt-then-MAC has no such leak: the MAC is
//! checked before anything is decrypted.

use std::marker::PhantomData;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::Mac;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, Error};
use subtle::ConstantTimeEq;

const BLOCK: usize = 16;

/// A 16-byte block cipher.
pub(crate) trait Block: Send + Sync + 'static + Sized {
    const KEY_LEN: usize;
    fn new(key: &[u8]) -> Option<Self>;
    fn encrypt(&self, b: &mut [u8; BLOCK]);
    fn decrypt(&self, b: &mut [u8; BLOCK]);
}

macro_rules! rustcrypto_block {
    ($t:ty, $len:expr) => {
        impl Block for $t {
            const KEY_LEN: usize = $len;
            fn new(key: &[u8]) -> Option<Self> {
                <$t as KeyInit>::new_from_slice(key).ok()
            }
            fn encrypt(&self, b: &mut [u8; BLOCK]) {
                BlockEncrypt::encrypt_block(self, GenericArray::from_mut_slice(b));
            }
            fn decrypt(&self, b: &mut [u8; BLOCK]) {
                BlockDecrypt::decrypt_block(self, GenericArray::from_mut_slice(b));
            }
        }
    };
}
rustcrypto_block!(aes::Aes128, 16);
rustcrypto_block!(aes::Aes256, 32);
rustcrypto_block!(camellia::Camellia128, 16);
rustcrypto_block!(camellia::Camellia256, 32);

impl Block for super::seed::Seed {
    const KEY_LEN: usize = 16;
    fn new(key: &[u8]) -> Option<Self> {
        super::seed::Seed::new(key)
    }
    fn encrypt(&self, b: &mut [u8; BLOCK]) {
        self.encrypt_block(b);
    }
    fn decrypt(&self, b: &mut [u8; BLOCK]) {
        self.decrypt_block(b);
    }
}

/// The record MAC: an HMAC, its key and tag `LEN` bytes.
pub(crate) trait MacAlg: Send + Sync + 'static {
    const LEN: usize;
    fn mac(key: &[u8], parts: &[&[u8]]) -> Vec<u8>;
}

macro_rules! hmac_alg {
    ($name:ident, $d:ty, $len:expr) => {
        pub(crate) struct $name;
        impl MacAlg for $name {
            const LEN: usize = $len;
            fn mac(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
                let mut m = <hmac::Hmac<$d> as Mac>::new_from_slice(key)
                    .expect("HMAC takes any key length");
                for p in parts {
                    m.update(p);
                }
                m.finalize().into_bytes().to_vec()
            }
        }
    };
}
hmac_alg!(Sha1, sha1::Sha1, 20);
hmac_alg!(Sha256, sha2::Sha256, 32);
hmac_alg!(Sha384, sha2::Sha384, 48);

/// A CBC suite's record protection: block cipher `B`, MAC `M`.
pub struct Cbc12<B, M>(PhantomData<fn() -> (B, M)>);

impl<B, M> Cbc12<B, M> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<B: Block, M: MacAlg> Tls12AeadAlgorithm for Cbc12<B, M> {
    /// Unreachable: rustls builds a suite with a MAC key through
    /// `encrypter_with_mac`. A refusing encrypter all the same.
    fn encrypter(&self, _: AeadKey, _: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Refuse)
    }
    fn decrypter(&self, _: AeadKey, _: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Refuse)
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        // TLS 1.2's IV is explicit, per record: none from the key block.
        KeyBlockShape {
            enc_key_len: B::KEY_LEN,
            fixed_iv_len: 0,
            explicit_nonce_len: 0,
        }
    }
    fn mac_key_len(&self) -> usize {
        M::LEN
    }
    fn encrypter_with_mac(
        &self,
        mac_key: &[u8],
        key: &[u8],
        _: &[u8],
        _: &[u8],
        encrypt_then_mac: bool,
    ) -> Box<dyn MessageEncrypter> {
        match B::new(key) {
            Some(cipher) => Box::new(CbcEnc::<B, M> {
                cipher,
                mac_key: mac_key.to_vec(),
                etm: encrypt_then_mac,
                _m: PhantomData,
            }),
            None => Box::new(Refuse),
        }
    }
    fn decrypter_with_mac(
        &self,
        mac_key: &[u8],
        key: &[u8],
        _: &[u8],
        encrypt_then_mac: bool,
    ) -> Box<dyn MessageDecrypter> {
        match B::new(key) {
            Some(cipher) => Box::new(CbcDec::<B, M> {
                cipher,
                mac_key: mac_key.to_vec(),
                etm: encrypt_then_mac,
                _m: PhantomData,
            }),
            None => Box::new(Refuse),
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

struct Refuse;

impl MessageEncrypter for Refuse {
    fn encrypt(
        &mut self,
        _: OutboundPlainMessage<'_>,
        _: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

impl MessageDecrypter for Refuse {
    fn decrypt<'a>(
        &mut self,
        _: InboundOpaqueMessage<'a>,
        _: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}

/// `n` rounded up past the next multiple of the block: the length once the
/// minimal padding (1 to 16 bytes) is added.
fn padded(n: usize) -> usize {
    n.saturating_add(BLOCK).saturating_sub(n % BLOCK)
}

/// The MAC header, `seq || type || version || length`.
fn header(
    seq: u64,
    typ: rustls::ContentType,
    version: rustls::ProtocolVersion,
    len: usize,
) -> [u8; 13] {
    let mut h = [0u8; 13];
    h[..8].copy_from_slice(&seq.to_be_bytes());
    h[8] = u8::from(typ);
    h[9..11].copy_from_slice(&u16::from(version).to_be_bytes());
    // A record is at most 2^14 + 2048 bytes: the length fits.
    h[11..].copy_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    h
}

fn cbc_encrypt<B: Block>(cipher: &B, iv: &[u8; BLOCK], data: &mut [u8]) {
    let mut prev = *iv;
    for chunk in data.chunks_exact_mut(BLOCK) {
        let mut b = [0u8; BLOCK];
        for ((o, c), p) in b.iter_mut().zip(chunk.iter()).zip(prev.iter()) {
            *o = c ^ p;
        }
        cipher.encrypt(&mut b);
        chunk.copy_from_slice(&b);
        prev = b;
    }
}

fn cbc_decrypt<B: Block>(cipher: &B, iv: &[u8], data: &mut [u8]) {
    let mut prev = [0u8; BLOCK];
    prev.copy_from_slice(iv);
    for chunk in data.chunks_exact_mut(BLOCK) {
        let mut b = [0u8; BLOCK];
        b.copy_from_slice(chunk);
        let next = b;
        cipher.decrypt(&mut b);
        for ((o, d), p) in chunk.iter_mut().zip(b.iter()).zip(prev.iter()) {
            *o = d ^ p;
        }
        prev = next;
    }
}

struct CbcEnc<B, M> {
    cipher: B,
    mac_key: Vec<u8>,
    etm: bool,
    _m: PhantomData<fn() -> M>,
}

impl<B, M> Drop for CbcEnc<B, M> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.mac_key);
    }
}

impl<B: Block, M: MacAlg> MessageEncrypter for CbcEnc<B, M> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let n = msg.payload.len();
        let mut body = Vec::with_capacity(self.encrypted_payload_len(n));
        let mut iv = [0u8; BLOCK];
        if !nmap_core::nse::openssl::rand::fill(&mut iv) {
            return Err(Error::EncryptError);
        }
        body.extend_from_slice(&iv);
        let mut content = msg.payload.to_vec();
        if !self.etm {
            let tag = M::mac(
                &self.mac_key,
                &[&header(seq, msg.typ, msg.version, n), &content],
            );
            content.extend_from_slice(&tag);
        }
        // p + 1 bytes of value p, to the next block.
        let pad = padded(content.len()).saturating_sub(content.len());
        let p = u8::try_from(pad.saturating_sub(1)).map_err(|_| Error::EncryptError)?;
        content.resize(content.len().saturating_add(pad), p);
        cbc_encrypt(&self.cipher, &iv, &mut content);
        body.extend_from_slice(&content);
        if self.etm {
            let tag = M::mac(
                &self.mac_key,
                &[&header(seq, msg.typ, msg.version, body.len()), &body],
            );
            body.extend_from_slice(&tag);
        }
        let mut payload = PrefixedPayload::with_capacity(body.len());
        payload.extend_from_slice(&body);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        if self.etm {
            BLOCK
                .saturating_add(padded(payload_len))
                .saturating_add(M::LEN)
        } else {
            BLOCK.saturating_add(padded(payload_len.saturating_add(M::LEN)))
        }
    }
}

struct CbcDec<B, M> {
    cipher: B,
    mac_key: Vec<u8>,
    etm: bool,
    _m: PhantomData<fn() -> M>,
}

impl<B, M> Drop for CbcDec<B, M> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.mac_key);
    }
}

/// Whether the last `p + 1` bytes of `data` all equal `p` (the last byte),
/// with `p + 1 <= data.len() - reserve`: checked over the last
/// `min(256, data.len())` bytes without a branch on their values.
fn padding_ok(data: &[u8], reserve: usize) -> (subtle::Choice, usize) {
    let Some(&p) = data.last() else {
        return (subtle::Choice::from(0), 0);
    };
    let pad = usize::from(p).saturating_add(1);
    let fits = subtle::Choice::from(u8::from(pad.saturating_add(reserve) <= data.len()));
    let mut good = fits;
    let span = data.len().min(256);
    for (i, &b) in data.iter().rev().take(span).enumerate() {
        let inside = subtle::Choice::from(u8::from(i < pad));
        good &= !inside | b.ct_eq(&p);
    }
    (good, pad)
}

impl<B: Block, M: MacAlg> MessageDecrypter for CbcDec<B, M> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let (typ, version) = (msg.typ, msg.version);
        let payload = &mut msg.payload;
        let len = payload.len();
        if self.etm {
            // IV, at least one block, the MAC.
            let ct_end = len.checked_sub(M::LEN).ok_or(Error::DecryptError)?;
            let ct_len = ct_end.checked_sub(BLOCK).ok_or(Error::DecryptError)?;
            if ct_len == 0 || ct_len % BLOCK != 0 {
                return Err(Error::DecryptError);
            }
            let (ivct, tag) = payload.split_at_mut(ct_end);
            let want = M::mac(&self.mac_key, &[&header(seq, typ, version, ct_end), ivct]);
            if !bool::from(want.as_slice().ct_eq(tag)) {
                return Err(Error::DecryptError);
            }
            let (iv, ct) = ivct.split_at_mut(BLOCK);
            cbc_decrypt(&self.cipher, iv, ct);
            let (good, pad) = padding_ok(ct, 0);
            if !bool::from(good) {
                return Err(Error::DecryptError);
            }
            let n = ct_len.checked_sub(pad).ok_or(Error::DecryptError)?;
            return Ok(msg.into_plain_message_range(BLOCK..BLOCK.saturating_add(n)));
        }
        // MAC-then-encrypt: IV, then whole blocks holding P, the MAC and at
        // least one padding byte.
        let ct_len = len.checked_sub(BLOCK).ok_or(Error::DecryptError)?;
        if ct_len % BLOCK != 0 || ct_len < padded(M::LEN) {
            return Err(Error::DecryptError);
        }
        let (iv, ct) = payload.split_at_mut(BLOCK);
        cbc_decrypt(&self.cipher, iv, ct);
        let (good, pad) = padding_ok(ct, M::LEN);
        // With bad padding, go on as if there were none (one byte), so a
        // MAC is computed either way (RFC 5246 §6.2.3.2).
        let pad_eff = if bool::from(good) { pad } else { 1 };
        let n = ct_len
            .checked_sub(pad_eff)
            .and_then(|v| v.checked_sub(M::LEN))
            .ok_or(Error::DecryptError)?;
        let (plain, rest) = ct.split_at(n);
        let tag = rest.get(..M::LEN).ok_or(Error::DecryptError)?;
        let want = M::mac(&self.mac_key, &[&header(seq, typ, version, n), plain]);
        let mac_ok = want.as_slice().ct_eq(tag);
        if !bool::from(good & mac_ok) {
            return Err(Error::DecryptError);
        }
        Ok(msg.into_plain_message_range(BLOCK..BLOCK.saturating_add(n)))
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test lengths and indices: fixed small ranges"
)]
mod tests {
    use super::*;
    use rustls::crypto::cipher::OutboundChunks;
    use rustls::{ContentType, ProtocolVersion};

    fn pair<B: Block, M: MacAlg>(
        etm: bool,
    ) -> (Box<dyn MessageEncrypter>, Box<dyn MessageDecrypter>) {
        let alg = Cbc12::<B, M>::new();
        let mac = vec![0x5a; M::LEN];
        let key = vec![0x3c; B::KEY_LEN];
        (
            alg.encrypter_with_mac(&mac, &key, &[], &[], etm),
            alg.decrypter_with_mac(&mac, &key, &[], etm),
        )
    }

    fn seal(enc: &mut dyn MessageEncrypter, data: &[u8], seq: u64) -> Vec<u8> {
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(data),
        };
        let out = enc.encrypt(msg, seq).expect("seal").encode();
        assert_eq!(out.len() - 5, enc.encrypted_payload_len(data.len()));
        out[5..].to_vec()
    }

    fn open(dec: &mut dyn MessageDecrypter, body: &mut [u8], seq: u64) -> Result<Vec<u8>, Error> {
        let msg =
            InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, body);
        dec.decrypt(msg, seq).map(|m| m.payload.to_vec())
    }

    fn round_trips<B: Block, M: MacAlg>() {
        for etm in [false, true] {
            let (mut enc, mut dec) = pair::<B, M>(etm);
            for n in [0usize, 1, 15, 16, 17, 31, 32, 100, 1000] {
                let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
                let mut body = seal(enc.as_mut(), &data, n as u64);
                assert_eq!((body.len() - if etm { M::LEN } else { 0 }) % BLOCK, 0);
                assert_eq!(
                    open(dec.as_mut(), &mut body, n as u64).expect("open"),
                    data,
                    "{etm} {n}"
                );
                // The sequence number is under the MAC.
                let mut body = seal(enc.as_mut(), &data, 7);
                assert!(open(dec.as_mut(), &mut body, 8).is_err(), "{etm} {n}: seq");
            }
        }
    }

    #[test]
    fn records_round_trip() {
        round_trips::<aes::Aes128, Sha1>();
        round_trips::<aes::Aes256, Sha256>();
        round_trips::<aes::Aes256, Sha384>();
        round_trips::<camellia::Camellia128, Sha256>();
        round_trips::<super::super::seed::Seed, Sha1>();
    }

    /// Any bit flipped in the IV, the ciphertext or the MAC is refused, in
    /// both modes.
    #[test]
    fn a_flipped_bit_is_refused() {
        for etm in [false, true] {
            let (mut enc, mut dec) = pair::<aes::Aes128, Sha1>(etm);
            let good = seal(
                enc.as_mut(),
                b"forty-two bytes of application data here!",
                3,
            );
            for i in 0..good.len() {
                let mut body = good.clone();
                body[i] ^= 0x01;
                assert!(open(dec.as_mut(), &mut body, 3).is_err(), "{etm} byte {i}");
            }
        }
    }

    /// Padding: a record whose padding bytes do not all equal the last one,
    /// or that claims more padding than there is room for, is refused even
    /// with a correct MAC under encrypt-then-MAC (where the MAC is checked
    /// first and passes).
    #[test]
    fn bad_padding_is_refused() {
        let alg = Cbc12::<aes::Aes128, Sha256>::new();
        let mac_key = [0x5a; 32];
        let key = [0x3c; 16];
        let cipher = <aes::Aes128 as Block>::new(&key).expect("key");
        let mut dec = alg.decrypter_with_mac(&mac_key, &key, &[], true);
        for content in [
            // "data" then padding 03 03 02 03: one byte wrong.
            [b'd', b'a', b't', b'a', 9, 9, 9, 9, 9, 9, 9, 9, 3, 3, 2, 3],
            // padding length 0x30: more than the record holds.
            [
                b'd', b'a', b't', b'a', 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0x30,
            ],
        ] {
            let iv = [7u8; BLOCK];
            let mut ct = content.to_vec();
            cbc_encrypt(&cipher, &iv, &mut ct);
            let mut body = iv.to_vec();
            body.extend_from_slice(&ct);
            let tag = Sha256::mac(
                &mac_key,
                &[
                    &header(
                        0,
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        body.len(),
                    ),
                    &body,
                ],
            );
            body.extend_from_slice(&tag);
            assert!(open(dec.as_mut(), &mut body, 0).is_err());
        }
    }

    /// Records of every length up to four blocks past the minimum, of any
    /// content: a decrypt error or a plaintext, never a panic.
    #[test]
    fn short_and_odd_records_are_errors() {
        for etm in [false, true] {
            let (_, mut dec) = pair::<aes::Aes256, Sha384>(etm);
            for len in 0..(BLOCK * 4 + 48 * 2) {
                let mut body = vec![0xa5u8; len];
                assert!(open(dec.as_mut(), &mut body, 0).is_err(), "{etm} {len}");
            }
        }
    }
}
