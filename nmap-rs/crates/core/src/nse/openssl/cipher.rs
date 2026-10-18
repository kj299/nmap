//! The `openssl` module's ciphers (M6.5 step d), pure: no Lua.
//!
//! `l_encrypt` and `l_decrypt` (`nse_openssl.cc:405-535`) drive OpenSSL's
//! EVP layer; this is that layer's observable behaviour for D4(b)'s ten
//! ciphers, over RustCrypto's block primitives (E1):
//!
//! - **Names** ([`resolve`]): `EVP_get_cipherbyname`, ASCII
//!   case-insensitive and up to the first NUL. [`NAMES`] holds every
//!   spelling OpenSSL 3.0.13 gives these ten; the oracle's record of 643
//!   spellings (`tests/differential/m6/m65_cipher_names.txt`) must resolve
//!   exactly as recorded. Every other cipher is unknown here
//!   (`openssl-algorithm-subset`).
//! - **Keys:** DES and AES take exactly their length, and any other is
//!   `invalid key length` (`EVP_CIPHER_CTX_set_key_length`). CAST5 takes
//!   any: OpenSSL's `CAST_set_key` uses the first 16 bytes, pads a shorter
//!   key with zeros, and runs 12 rounds for a key of 10 bytes or fewer.
//! - **IVs:** none (`nil` or empty) is a zero IV; any other IV must be the
//!   mode's length, 0 for ECB, or it is `Length of iv is N; should be M`
//!   (checked after the key).
//! - **Padding** is PKCS#7 when asked for and off by default. Off, a partial
//!   final block is `wrong final block length`, either way. On, decryption
//!   of no whole block is `wrong final block length`, and a bad pad is
//!   `bad decrypt`.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

/// The ciphers D4(b) offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cipher {
    DesEcb,
    DesCbc,
    Aes128Ecb,
    Aes128Cbc,
    Aes192Ecb,
    Aes192Cbc,
    Aes256Ecb,
    Aes256Cbc,
    Cast5Ecb,
    Cast5Cbc,
}

/// Every spelling OpenSSL 3.0.13 resolves to one of [`Cipher`], lowercase
/// ASCII: a name matches when it equals one of these ignoring ASCII case.
pub const NAMES: &[(&str, Cipher)] = &[
    ("des-ecb", Cipher::DesEcb),
    ("1.3.14.3.2.6", Cipher::DesEcb),
    ("des-cbc", Cipher::DesCbc),
    ("des", Cipher::DesCbc),
    ("1.3.14.3.2.7", Cipher::DesCbc),
    ("aes-128-ecb", Cipher::Aes128Ecb),
    ("2.16.840.1.101.3.4.1.1", Cipher::Aes128Ecb),
    ("aes-128-cbc", Cipher::Aes128Cbc),
    ("aes128", Cipher::Aes128Cbc),
    ("2.16.840.1.101.3.4.1.2", Cipher::Aes128Cbc),
    ("aes-192-ecb", Cipher::Aes192Ecb),
    ("2.16.840.1.101.3.4.1.21", Cipher::Aes192Ecb),
    ("aes-192-cbc", Cipher::Aes192Cbc),
    ("aes192", Cipher::Aes192Cbc),
    ("2.16.840.1.101.3.4.1.22", Cipher::Aes192Cbc),
    ("aes-256-ecb", Cipher::Aes256Ecb),
    ("2.16.840.1.101.3.4.1.41", Cipher::Aes256Ecb),
    ("aes-256-cbc", Cipher::Aes256Cbc),
    ("aes256", Cipher::Aes256Cbc),
    ("2.16.840.1.101.3.4.1.42", Cipher::Aes256Cbc),
    ("cast5-ecb", Cipher::Cast5Ecb),
    ("cast5-cbc", Cipher::Cast5Cbc),
    ("cast", Cipher::Cast5Cbc),
    ("cast-cbc", Cipher::Cast5Cbc),
    ("1.2.840.113533.7.66.10", Cipher::Cast5Cbc),
];

/// `EVP_get_cipherbyname(name)` over [`NAMES`]: the name up to its first
/// NUL, compared ignoring ASCII case.
#[must_use]
pub fn resolve(name: &[u8]) -> Option<Cipher> {
    let name = name.split(|&b| b == 0).next().unwrap_or_default();
    NAMES
        .iter()
        .find(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
        .map(|&(_, c)| c)
}

/// Why a call failed, in OpenSSL's words (the binding prefixes the EVP ones
/// with `OpenSSL error: `).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherError {
    /// `EVP_CIPHER_CTX_set_key_length` refused the key.
    InvalidKeyLength,
    /// An IV of `got` bytes where the mode takes `want`.
    IvLength { got: usize, want: usize },
    /// A partial final block: without padding, or a decryption with it.
    WrongFinalBlockLength,
    /// A decryption whose PKCS#7 pad does not check out.
    BadDecrypt,
}

impl CipherError {
    /// The text after `OpenSSL error: `, as `ERR_error_string` prints the
    /// error OpenSSL 3.0.13 queues; `None` for the IV check, which is the
    /// C's own message.
    #[must_use]
    pub fn openssl_text(self) -> Option<&'static str> {
        Some(match self {
            CipherError::InvalidKeyLength => {
                "error:03000082:digital envelope routines::invalid key length"
            }
            CipherError::WrongFinalBlockLength => {
                "error:1C80006B:Provider routines::wrong final block length"
            }
            CipherError::BadDecrypt => "error:1C800064:Provider routines::bad decrypt",
            CipherError::IvLength { .. } => return None,
        })
    }
}

impl Cipher {
    /// The key length OpenSSL reports, which DES and AES require.
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Cipher::DesEcb | Cipher::DesCbc => 8,
            Cipher::Aes128Ecb | Cipher::Aes128Cbc | Cipher::Cast5Ecb | Cipher::Cast5Cbc => 16,
            Cipher::Aes192Ecb | Cipher::Aes192Cbc => 24,
            Cipher::Aes256Ecb | Cipher::Aes256Cbc => 32,
        }
    }

    /// `EVP_CIPHER_CTX_iv_length`: the block for CBC, 0 for ECB.
    #[must_use]
    pub fn iv_len(self) -> usize {
        if self.is_cbc() {
            self.block_size()
        } else {
            0
        }
    }

    /// The block size.
    #[must_use]
    pub fn block_size(self) -> usize {
        match self {
            Cipher::DesEcb | Cipher::DesCbc | Cipher::Cast5Ecb | Cipher::Cast5Cbc => 8,
            _ => 16,
        }
    }

    fn is_cbc(self) -> bool {
        matches!(
            self,
            Cipher::DesCbc
                | Cipher::Aes128Cbc
                | Cipher::Aes192Cbc
                | Cipher::Aes256Cbc
                | Cipher::Cast5Cbc
        )
    }

    /// The keyed block primitive, or `invalid key length`.
    fn keyed(self, key: &[u8]) -> Result<Prim, CipherError> {
        let fixed = |n: usize| {
            if key.len() == n {
                Ok(())
            } else {
                Err(CipherError::InvalidKeyLength)
            }
        };
        let bad = |_| CipherError::InvalidKeyLength;
        Ok(match self {
            Cipher::DesEcb | Cipher::DesCbc => {
                fixed(8)?;
                Prim::Des(des::Des::new_from_slice(key).map_err(bad)?)
            }
            Cipher::Aes128Ecb | Cipher::Aes128Cbc => {
                fixed(16)?;
                Prim::Aes128(aes::Aes128::new_from_slice(key).map_err(bad)?)
            }
            Cipher::Aes192Ecb | Cipher::Aes192Cbc => {
                fixed(24)?;
                Prim::Aes192(aes::Aes192::new_from_slice(key).map_err(bad)?)
            }
            Cipher::Aes256Ecb | Cipher::Aes256Cbc => {
                fixed(32)?;
                Prim::Aes256(aes::Aes256::new_from_slice(key).map_err(bad)?)
            }
            Cipher::Cast5Ecb | Cipher::Cast5Cbc => {
                // `CAST_set_key`: the first 16 bytes; a shorter key is padded
                // with zeros, and one of 10 bytes or fewer runs 12 rounds.
                // The crate takes 5 to 16 bytes with the same two rules, so a
                // key under 5 bytes goes in zero-padded to 5.
                let mut k = key[..key.len().min(16)].to_vec();
                if k.len() < 5 {
                    k.resize(5, 0);
                }
                Prim::Cast5(cast5::Cast5::new_from_slice(&k).map_err(bad)?)
            }
        })
    }
}

/// A keyed block primitive.
enum Prim {
    Des(des::Des),
    Aes128(aes::Aes128),
    Aes192(aes::Aes192),
    Aes256(aes::Aes256),
    Cast5(cast5::Cast5),
}

impl Prim {
    fn encrypt(&self, block: &mut [u8]) {
        match self {
            Prim::Des(c) => c.encrypt_block(GenericArray::from_mut_slice(block)),
            Prim::Aes128(c) => c.encrypt_block(GenericArray::from_mut_slice(block)),
            Prim::Aes192(c) => c.encrypt_block(GenericArray::from_mut_slice(block)),
            Prim::Aes256(c) => c.encrypt_block(GenericArray::from_mut_slice(block)),
            Prim::Cast5(c) => c.encrypt_block(GenericArray::from_mut_slice(block)),
        }
    }

    fn decrypt(&self, block: &mut [u8]) {
        match self {
            Prim::Des(c) => c.decrypt_block(GenericArray::from_mut_slice(block)),
            Prim::Aes128(c) => c.decrypt_block(GenericArray::from_mut_slice(block)),
            Prim::Aes192(c) => c.decrypt_block(GenericArray::from_mut_slice(block)),
            Prim::Aes256(c) => c.decrypt_block(GenericArray::from_mut_slice(block)),
            Prim::Cast5(c) => c.decrypt_block(GenericArray::from_mut_slice(block)),
        }
    }
}

/// What `encrypt` or `decrypt` gives: the key checked, then the IV
/// (`None` for none: a zero IV), then the data run through the mode, with
/// PKCS#7 padding if `padding`. `out` receives the result; the caller has
/// reserved [`out_capacity`] bytes for it.
///
/// # Errors
/// [`CipherError`], in the order the C meets them.
pub fn crypt(
    cipher: Cipher,
    encrypt: bool,
    key: &[u8],
    iv: Option<&[u8]>,
    data: &[u8],
    padding: bool,
    out: &mut Vec<u8>,
) -> Result<(), CipherError> {
    let prim = cipher.keyed(key)?;
    let bs = cipher.block_size();
    if let Some(iv) = iv {
        if iv.len() != cipher.iv_len() {
            return Err(CipherError::IvLength {
                got: iv.len(),
                want: cipher.iv_len(),
            });
        }
    }
    let partial = !data.len().is_multiple_of(bs);
    if partial && !(encrypt && padding) || !encrypt && padding && data.is_empty() {
        return Err(CipherError::WrongFinalBlockLength);
    }
    out.clear();
    out.extend_from_slice(data);
    if encrypt && padding {
        // A whole block of padding when the data fills its last block.
        let pad = bs.saturating_sub(data.len().checked_rem(bs).unwrap_or(0));
        out.resize(
            data.len().saturating_add(pad),
            u8::try_from(pad).unwrap_or(0),
        );
    }
    let mut chain = vec![0u8; bs];
    if let Some(iv) = iv.filter(|_| cipher.is_cbc()) {
        chain.copy_from_slice(iv);
    }
    for block in out.chunks_exact_mut(bs) {
        if !cipher.is_cbc() {
            if encrypt {
                prim.encrypt(block);
            } else {
                prim.decrypt(block);
            }
        } else if encrypt {
            block.iter_mut().zip(&chain).for_each(|(b, c)| *b ^= c);
            prim.encrypt(block);
            chain.copy_from_slice(block);
        } else {
            let saved = block.to_vec();
            prim.decrypt(block);
            block.iter_mut().zip(&chain).for_each(|(b, c)| *b ^= c);
            chain = saved;
        }
    }
    if !encrypt && padding {
        // `ossl_cipher_unpadblock`: the last byte is the pad's length, 1 to
        // the block, and every pad byte is that length.
        let pad = usize::from(*out.last().unwrap_or(&0));
        let tail = out.len().saturating_sub(pad);
        if pad == 0 || pad > bs || out[tail..].iter().any(|&b| usize::from(b) != pad) {
            out.clear();
            return Err(CipherError::BadDecrypt);
        }
        out.truncate(tail);
    }
    Ok(())
}

/// The most bytes [`crypt`] writes for `data_len` bytes of input: a block
/// more than the input (`EVP_MAX_BLOCK_LENGTH`, as `l_encrypt` allocates).
#[must_use]
pub fn out_capacity(data_len: usize) -> usize {
    data_len.saturating_add(32)
}

/// `l_DES_string_to_key`: seven bytes spread over eight, seven bits each,
/// the low bit of every byte clear (`nse_openssl.cc:537-555`). The C reads a
/// `data[7]` that a 7-byte Lua string has only as its terminating NUL; it is
/// 0 here.
#[must_use]
pub fn des_string_to_key(data: &[u8; 7]) -> [u8; 8] {
    let at = |i: usize| data.get(i).copied().unwrap_or(0);
    let mut key = [0u8; 8];
    key[0] = data[0] & !1;
    for (i, k) in (1u32..).zip(key.iter_mut().skip(1)) {
        let prev = at(usize::try_from(i.saturating_sub(1)).unwrap_or(0));
        let hi = prev.checked_shl(8u32.saturating_sub(i)).unwrap_or(0);
        let lo = at(usize::try_from(i).unwrap_or(0))
            .checked_shr(i)
            .unwrap_or(0);
        *k = (hi | lo) & !1;
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).expect("ascii"), 16).expect("hex"))
            .collect()
    }

    fn run(c: Cipher, enc: bool, key: &str, iv: Option<&str>, data: &str, pad: bool) -> String {
        let iv = iv.map(unhex);
        let mut out = Vec::new();
        match crypt(
            c,
            enc,
            &unhex(key),
            iv.as_deref(),
            &unhex(data),
            pad,
            &mut out,
        ) {
            Ok(()) => hex(&out),
            Err(e) => format!("{e:?}"),
        }
    }

    /// Published known answers: FIPS-197 Appendix C (AES-128/192/256), NIST
    /// SP 800-38A F.2.1 (AES-128-CBC), FIPS 81's DES example and NBS SP
    /// 500-20's, RFC 2144 B.1 (CAST5 at 128, 80 and 40 bits).
    #[test]
    fn published_cipher_vectors() {
        let pt = "00112233445566778899aabbccddeeff";
        assert_eq!(
            run(
                Cipher::Aes128Ecb,
                true,
                "000102030405060708090a0b0c0d0e0f",
                None,
                pt,
                false
            ),
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        );
        assert_eq!(
            run(
                Cipher::Aes192Ecb,
                true,
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                None,
                pt,
                false
            ),
            "dda97ca4864cdfe06eaf70a0ec0d7191"
        );
        assert_eq!(
            run(
                Cipher::Aes256Ecb,
                true,
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                None,
                pt,
                false
            ),
            "8ea2b7ca516745bfeafc49904b496089"
        );
        assert_eq!(
            run(
                Cipher::Aes128Cbc,
                true,
                "2b7e151628aed2a6abf7158809cf4f3c",
                Some("000102030405060708090a0b0c0d0e0f"),
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
                false
            ),
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
        );
        assert_eq!(
            run(
                Cipher::Aes128Cbc,
                false,
                "2b7e151628aed2a6abf7158809cf4f3c",
                Some("000102030405060708090a0b0c0d0e0f"),
                "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2",
                false
            ),
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        );
        // FIPS 81 Appendix B: "Now is the time for all " under 0123456789abcdef.
        assert_eq!(
            run(
                Cipher::DesEcb,
                true,
                "0123456789abcdef",
                None,
                "4e6f772069732074",
                false
            ),
            "3fa40e8a984d4815"
        );
        assert_eq!(
            run(
                Cipher::DesCbc,
                true,
                "0123456789abcdef",
                Some("1234567890abcdef"),
                "4e6f77206973207468652074696d6520666f7220616c6c20",
                false
            ),
            "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6"
        );
        // NBS SP 500-20's variable-plaintext test: key 0101..01, 8000..00.
        assert_eq!(
            run(
                Cipher::DesEcb,
                true,
                "0101010101010101",
                None,
                "8000000000000000",
                false
            ),
            "95f8a5e5dd31d900"
        );
        let cast_key = "0123456712345678234567893456789a";
        let cast_pt = "0123456789abcdef";
        assert_eq!(
            run(Cipher::Cast5Ecb, true, cast_key, None, cast_pt, false),
            "238b4fe5847e44b2"
        );
        assert_eq!(
            run(
                Cipher::Cast5Ecb,
                true,
                &cast_key[..20],
                None,
                cast_pt,
                false
            ),
            "eb6a711a2c02271b"
        );
        assert_eq!(
            run(
                Cipher::Cast5Ecb,
                true,
                &cast_key[..10],
                None,
                cast_pt,
                false
            ),
            "7ac816d16e9b302e"
        );
    }

    #[test]
    fn key_and_iv_rules_are_evps() {
        let k16 = "00".repeat(16);
        assert_eq!(
            run(Cipher::Aes128Cbc, true, &"00".repeat(15), None, "", false),
            "InvalidKeyLength"
        );
        // The key is checked before the IV.
        assert_eq!(
            run(
                Cipher::Aes128Cbc,
                true,
                &"00".repeat(15),
                Some("00"),
                "",
                false
            ),
            "InvalidKeyLength"
        );
        assert_eq!(
            run(
                Cipher::Aes128Cbc,
                true,
                &k16,
                Some(&"00".repeat(15)),
                "",
                false
            ),
            "IvLength { got: 15, want: 16 }"
        );
        assert_eq!(
            run(
                Cipher::Aes128Ecb,
                true,
                &k16,
                Some(&"00".repeat(16)),
                "",
                false
            ),
            "IvLength { got: 16, want: 0 }"
        );
        // No IV is a zero IV.
        let zero = Some("00".repeat(16));
        assert_eq!(
            run(Cipher::Aes128Cbc, true, &k16, None, &"ab".repeat(32), false),
            run(
                Cipher::Aes128Cbc,
                true,
                &k16,
                zero.as_deref(),
                &"ab".repeat(32),
                false
            )
        );
        // CAST5 takes any key: 0 to 4 bytes are the zero-padded 5, past 16 the first 16.
        assert_eq!(
            run(Cipher::Cast5Ecb, true, "", None, &"00".repeat(8), false),
            run(
                Cipher::Cast5Ecb,
                true,
                "0000000000",
                None,
                &"00".repeat(8),
                false
            )
        );
        let k20 = "0123456712345678234567893456789aabcdef01";
        assert_eq!(
            run(Cipher::Cast5Ecb, true, k20, None, &"00".repeat(8), false),
            run(
                Cipher::Cast5Ecb,
                true,
                &k20[..32],
                None,
                &"00".repeat(8),
                false
            )
        );
    }

    #[test]
    fn padding_is_pkcs7_and_off_by_default() {
        let k = "00".repeat(8);
        assert_eq!(
            run(Cipher::DesEcb, true, &k, None, "01", false),
            "WrongFinalBlockLength"
        );
        assert_eq!(
            run(Cipher::DesEcb, false, &k, None, "01", false),
            "WrongFinalBlockLength"
        );
        assert_eq!(run(Cipher::DesEcb, true, &k, None, "", false), "");
        assert_eq!(run(Cipher::DesEcb, false, &k, None, "", false), "");
        assert_eq!(
            run(Cipher::DesEcb, false, &k, None, "", true),
            "WrongFinalBlockLength"
        );
        // An empty input pads to a whole block; a whole block to two.
        let one = run(Cipher::DesEcb, true, &k, None, "", true);
        assert_eq!(one.len(), 16);
        assert_eq!(run(Cipher::DesEcb, false, &k, None, &one, true), "");
        assert_eq!(
            run(Cipher::DesEcb, true, &k, None, &"11".repeat(8), true).len(),
            32
        );
        // A block that does not unpad is a bad decrypt.
        let raw = run(Cipher::DesEcb, true, &k, None, "0102030405060708", false);
        assert_eq!(
            run(Cipher::DesEcb, false, &k, None, &raw, true),
            "BadDecrypt"
        );
        let zero_pad = run(Cipher::DesEcb, true, &k, None, "0102030405060700", false);
        assert_eq!(
            run(Cipher::DesEcb, false, &k, None, &zero_pad, true),
            "BadDecrypt"
        );
        let ok = run(Cipher::DesEcb, true, &k, None, "0102030405060701", false);
        assert_eq!(
            run(Cipher::DesEcb, false, &k, None, &ok, true),
            "01020304050607"
        );
    }

    #[test]
    fn des_string_to_key_spreads_seven_bytes() {
        assert_eq!(des_string_to_key(&[0xff; 7]), [0xfe; 8]);
        assert_eq!(des_string_to_key(&[0; 7]), [0; 8]);
        // The last byte is data[6]'s low seven bits, shifted up: what the C
        // computes with the NUL after the string as data[7]. data[6]'s top
        // two bits end key[6].
        let k = des_string_to_key(&[0, 0, 0, 0, 0, 0, 0x7f]);
        assert_eq!(k, [0, 0, 0, 0, 0, 0, 0, 0xfe]);
        let k = des_string_to_key(&[0, 0, 0, 0, 0, 0, 0x80]);
        assert_eq!(k, [0, 0, 0, 0, 0, 0, 0x02, 0]);
        let k = des_string_to_key(&[0, 0, 0, 0, 0, 0x01, 0x80]);
        assert_eq!(k, [0, 0, 0, 0, 0, 0, 0x06, 0]);
    }

    #[test]
    fn names_resolve_case_insensitively_up_to_a_nul() {
        assert_eq!(resolve(b"des"), Some(Cipher::DesCbc));
        assert_eq!(resolve(b"DES-ECB"), Some(Cipher::DesEcb));
        assert_eq!(resolve(b"aes-128-cbc\0x"), Some(Cipher::Aes128Cbc));
        assert_eq!(resolve(b"AeS256"), Some(Cipher::Aes256Cbc));
        assert_eq!(resolve(b"des-ede3-cbc"), None);
        assert_eq!(resolve(b"rc4"), None);
        assert_eq!(resolve(b" des"), None);
        assert_eq!(resolve(b""), None);
    }

    /// The oracle's spellings (oracle/gen_m65_cipher_names.py): each D4 one
    /// resolves to the cipher the oracle's encryptions named, and every
    /// `other` or `unknown` one to nothing.
    #[test]
    #[cfg_attr(miri, ignore = "reads the corpus from disk")]
    fn every_recorded_cipher_spelling_resolves_as_the_oracle_does() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/differential/m6/m65_cipher_names.txt"
        );
        let text = std::fs::read_to_string(path).expect("m65_cipher_names.txt");
        let canon = |c: Cipher| match c {
            Cipher::DesEcb => "des-ecb",
            Cipher::DesCbc => "des-cbc",
            Cipher::Aes128Ecb => "aes-128-ecb",
            Cipher::Aes128Cbc => "aes-128-cbc",
            Cipher::Aes192Ecb => "aes-192-ecb",
            Cipher::Aes192Cbc => "aes-192-cbc",
            Cipher::Aes256Ecb => "aes-256-ecb",
            Cipher::Aes256Cbc => "aes-256-cbc",
            Cipher::Cast5Ecb => "cast5-ecb",
            Cipher::Cast5Cbc => "cast5-cbc",
        };
        let (mut n, mut d4) = (0usize, 0usize);
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (h, want) = line.split_once('\t').expect("HEX<TAB>CLASS");
            let name = unhex(h);
            let got = resolve(&name).map_or("refused", canon);
            let want_port = if want == "other" || want == "unknown" {
                "refused"
            } else {
                d4 = d4.saturating_add(1);
                want
            };
            assert_eq!(got, want_port, "{:?}", String::from_utf8_lossy(&name));
            n = n.saturating_add(1);
        }
        assert!(n > 600 && d4 >= NAMES.len(), "{n} spellings, {d4} D4");
        for &(name, _) in NAMES {
            assert!(
                text.contains(&hex(name.as_bytes())),
                "{name} is not in the oracle's record"
            );
        }
    }
}
