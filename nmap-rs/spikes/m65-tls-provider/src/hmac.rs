//! HMAC-SHA-256 and HMAC-SHA-384 for rustls, over `hmac`. The TLS 1.2 PRF and
//! the TLS 1.3 HKDF are rustls's own `PrfUsingHmac` and `HkdfUsingHmac` over
//! these.

use hmac::Mac;
use rustls::crypto::hmac::{Hmac, Key, Tag};

pub struct HmacSha256;
pub struct HmacSha384;

impl Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(K256(
            hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC takes any key length"),
        ))
    }
    fn hash_output_len(&self) -> usize {
        32
    }
}

impl Hmac for HmacSha384 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(K384(
            hmac::Hmac::<sha2::Sha384>::new_from_slice(key).expect("HMAC takes any key length"),
        ))
    }
    fn hash_output_len(&self) -> usize {
        48
    }
}

struct K256(hmac::Hmac<sha2::Sha256>);
struct K384(hmac::Hmac<sha2::Sha384>);

impl Key for K256 {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut m = self.0.clone();
        m.update(first);
        for p in middle {
            m.update(p);
        }
        m.update(last);
        Tag::new(&m.finalize().into_bytes()[..])
    }
    fn tag_len(&self) -> usize {
        32
    }
}

impl Key for K384 {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut m = self.0.clone();
        m.update(first);
        for p in middle {
            m.update(p);
        }
        m.update(last);
        Tag::new(&m.finalize().into_bytes()[..])
    }
    fn tag_len(&self) -> usize {
        48
    }
}
