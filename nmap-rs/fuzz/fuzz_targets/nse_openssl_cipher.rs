// cargo-fuzz target for `nmap_core::nse::openssl::cipher`, the `openssl`
// module's ciphers (M6.5 step d). Its inputs are script- and
// peer-controlled: keys derived from passwords and challenges, IVs and
// ciphertext off the wire (smbauth, mssql, tns, vnc, afp;
// `docs/M6.5-ANALYSIS.md` §3).
//
// Checked, on arbitrary bytes:
//   * `resolve` never panics, ignores ASCII case, and reads only up to the
//     first NUL;
//   * `crypt` fails exactly where EVP's rules say, in their order: a DES or
//     AES key of the wrong length, then an IV of the wrong length, then a
//     partial block without padding (or no block to unpad);
//   * whatever encrypts decrypts back, with padding or without, and the
//     output's length is the input's, padded up to the block when asked;
//   * the first block of ECB is the crate's own block call on the data, and
//     CBC's is ECB's of the data XOR the IV (the zero IV when none), so the
//     mode code is checked against the primitive, not against itself;
//   * `des_string_to_key` is the 56 bits of its input in seven-bit groups,
//     each shifted up over a clear low bit, computed here a second way.
//
// Input layout: byte 0 picks the cipher, byte 1 the key length, byte 2 the
// IV shape and padding; the rest is the key, then the IV, then the data.
#![no_main]

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use libfuzzer_sys::fuzz_target;
use nmap_core::nse::openssl::cipher::{self, Cipher, CipherError};

const CIPHERS: [Cipher; 10] = [
    Cipher::DesEcb,
    Cipher::DesCbc,
    Cipher::Aes128Ecb,
    Cipher::Aes128Cbc,
    Cipher::Aes192Ecb,
    Cipher::Aes192Cbc,
    Cipher::Aes256Ecb,
    Cipher::Aes256Cbc,
    Cipher::Cast5Ecb,
    Cipher::Cast5Cbc,
];

/// The crate's block encryption of `block` under `key` (the port's key
/// rules applied: CAST5's first 16 bytes, padded to 5).
fn primitive(c: Cipher, key: &[u8], block: &[u8]) -> Vec<u8> {
    let mut b = block.to_vec();
    let ga = &mut b[..];
    match c {
        Cipher::DesEcb | Cipher::DesCbc => des::Des::new_from_slice(key)
            .unwrap()
            .encrypt_block(GenericArray::from_mut_slice(ga)),
        Cipher::Aes128Ecb | Cipher::Aes128Cbc => aes::Aes128::new_from_slice(key)
            .unwrap()
            .encrypt_block(GenericArray::from_mut_slice(ga)),
        Cipher::Aes192Ecb | Cipher::Aes192Cbc => aes::Aes192::new_from_slice(key)
            .unwrap()
            .encrypt_block(GenericArray::from_mut_slice(ga)),
        Cipher::Aes256Ecb | Cipher::Aes256Cbc => aes::Aes256::new_from_slice(key)
            .unwrap()
            .encrypt_block(GenericArray::from_mut_slice(ga)),
        Cipher::Cast5Ecb | Cipher::Cast5Cbc => {
            let mut k = key[..key.len().min(16)].to_vec();
            k.resize(k.len().max(5), 0);
            cast5::Cast5::new_from_slice(&k)
                .unwrap()
                .encrypt_block(GenericArray::from_mut_slice(ga))
        }
    }
    b
}

fn is_cast(c: Cipher) -> bool {
    matches!(c, Cipher::Cast5Ecb | Cipher::Cast5Cbc)
}

fn des_key_by_bits(d: &[u8; 7]) -> [u8; 8] {
    let bits: Vec<u8> = d.iter().flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1)).collect();
    let mut key = [0u8; 8];
    for (k, group) in key.iter_mut().zip(bits.chunks(7)) {
        *k = group.iter().fold(0u8, |acc, &b| acc << 1 | b) << 1;
    }
    key
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let c = CIPHERS[usize::from(data[0]) % CIPHERS.len()];
    let shape = data[2];
    let rest = &data[3..];
    // Mostly the right key length, sometimes any.
    let klen = if data[1] & 0x80 == 0 {
        c.key_len()
    } else {
        usize::from(data[1] & 0x3f)
    }
    .min(rest.len());
    let (key, rest) = rest.split_at(klen);
    let ivlen = match shape & 3 {
        0 => 0,
        1 => c.iv_len(),
        2 => c.block_size(),
        _ => usize::from(shape >> 4),
    }
    .min(rest.len());
    let (iv, msg) = rest.split_at(ivlen);
    let iv = (!iv.is_empty()).then_some(iv);
    let padding = shape & 4 != 0;
    let bs = c.block_size();

    // Names.
    let r = cipher::resolve(key);
    assert_eq!(r, cipher::resolve(&key.to_ascii_uppercase()));
    let mut junk = key.split(|&b| b == 0).next().unwrap_or_default().to_vec();
    junk.push(0);
    junk.extend_from_slice(msg);
    assert_eq!(r, cipher::resolve(&junk));

    // The rules, in order.
    let mut ct = Vec::new();
    let res = cipher::crypt(c, true, key, iv, msg, padding, &mut ct);
    let want_err = if !is_cast(c) && key.len() != c.key_len() {
        Some(CipherError::InvalidKeyLength)
    } else if iv.is_some_and(|iv| iv.len() != c.iv_len()) {
        Some(CipherError::IvLength { got: iv.map_or(0, <[u8]>::len), want: c.iv_len() })
    } else if !padding && msg.len() % bs != 0 {
        Some(CipherError::WrongFinalBlockLength)
    } else {
        None
    };
    assert_eq!(res.err(), want_err, "{c:?}");
    if want_err.is_some() {
        return;
    }
    let want_len = if padding { (msg.len() / bs + 1) * bs } else { msg.len() };
    assert_eq!(ct.len(), want_len, "{c:?}");
    assert!(ct.len() <= cipher::out_capacity(msg.len()));

    // The first block against the primitive.
    if !ct.is_empty() {
        let mut first = msg[..msg.len().min(bs)].to_vec();
        if first.len() < bs {
            let pad = bs - first.len();
            first.resize(bs, u8::try_from(pad).unwrap());
        }
        if c.iv_len() > 0 {
            let chain = iv.map_or_else(|| vec![0; bs], <[u8]>::to_vec);
            first.iter_mut().zip(&chain).for_each(|(b, v)| *b ^= v);
        }
        assert_eq!(&ct[..bs], &primitive(c, key, &first)[..], "{c:?}");
    }

    // And back.
    let mut pt = Vec::new();
    let back = cipher::crypt(c, false, key, iv, &ct, padding, &mut pt);
    if padding && ct.is_empty() {
        assert_eq!(back, Err(CipherError::WrongFinalBlockLength));
    } else {
        assert_eq!(back, Ok(()), "{c:?}");
        assert_eq!(pt, msg, "{c:?}");
    }

    // DES_string_to_key.
    if let Ok(seven) = <&[u8; 7]>::try_from(&data[data.len() - 7.min(data.len())..]) {
        let k = cipher::des_string_to_key(seven);
        assert_eq!(k, des_key_by_bits(seven));
        assert!(k.iter().all(|b| b & 1 == 0));
    }
});
