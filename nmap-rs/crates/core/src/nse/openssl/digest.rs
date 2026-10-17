//! The `openssl` module's digests and HMAC (M6.5 step c), pure: no Lua.
//!
//! - **Names** ([`resolve`]): `EVP_get_digestbyname` as `l_digest` and
//!   `l_hmac` call it (`nse_openssl.cc:315,358`), over D4(b)'s ten
//!   algorithms. OpenSSL looks a name up in its object-name table and its
//!   provider namemap, ASCII case-insensitively, and only up to the first
//!   NUL, since the name comes from `luaL_checkstring`. Every spelling of
//!   these ten that OpenSSL 3.0.13 accepts is in [`NAMES`]: the short and
//!   long names, the `RSA-` and `WithRSAEncryption` signature names, the
//!   provider names (`SHA2-256`, `SHA-512/224`), `SSL3-` names and the
//!   dotted OID. `tests/differential/m6/m65_digest_names.txt` records how
//!   the oracle resolves 398 spellings; the port must agree on every one
//!   (`every_recorded_spelling_resolves_as_the_oracle_does`). The names
//!   OpenSSL accepts for other digests (SHA-3, SHAKE, BLAKE2, SM3,
//!   whirlpool, `MD5-SHA1`) are unknown here (`openssl-algorithm-subset`).
//! - **Digests**: RustCrypto's (E1), one call each.
//! - **HMAC**: RFC 2104 over them ([`hmac`]), first-party.

use sha2::Digest; // the digest 0.10 trait, which all five crates implement

/// The digests D4(b) offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alg {
    Md4,
    Md5,
    Sha1,
    Ripemd160,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
}

/// Every spelling OpenSSL 3.0.13 resolves to one of [`Alg`], lowercase
/// ASCII: a name matches when it equals one of these ignoring ASCII case.
pub const NAMES: &[(&str, Alg)] = &[
    ("md4", Alg::Md4),
    ("rsa-md4", Alg::Md4),
    ("md4withrsaencryption", Alg::Md4),
    ("1.2.840.113549.2.4", Alg::Md4),
    ("md5", Alg::Md5),
    ("rsa-md5", Alg::Md5),
    ("md5withrsaencryption", Alg::Md5),
    ("ssl3-md5", Alg::Md5),
    ("1.2.840.113549.2.5", Alg::Md5),
    ("sha1", Alg::Sha1),
    ("sha-1", Alg::Sha1),
    ("rsa-sha1", Alg::Sha1),
    ("rsa-sha1-2", Alg::Sha1),
    ("sha1withrsaencryption", Alg::Sha1),
    ("ssl3-sha1", Alg::Sha1),
    ("1.3.14.3.2.26", Alg::Sha1),
    ("ripemd160", Alg::Ripemd160),
    ("ripemd", Alg::Ripemd160),
    ("ripemd-160", Alg::Ripemd160),
    ("rmd160", Alg::Ripemd160),
    ("rsa-ripemd160", Alg::Ripemd160),
    ("ripemd160withrsa", Alg::Ripemd160),
    ("1.3.36.3.2.1", Alg::Ripemd160),
    ("sha224", Alg::Sha224),
    ("sha-224", Alg::Sha224),
    ("sha2-224", Alg::Sha224),
    ("rsa-sha224", Alg::Sha224),
    ("sha224withrsaencryption", Alg::Sha224),
    ("2.16.840.1.101.3.4.2.4", Alg::Sha224),
    ("sha256", Alg::Sha256),
    ("sha-256", Alg::Sha256),
    ("sha2-256", Alg::Sha256),
    ("rsa-sha256", Alg::Sha256),
    ("sha256withrsaencryption", Alg::Sha256),
    ("2.16.840.1.101.3.4.2.1", Alg::Sha256),
    ("sha384", Alg::Sha384),
    ("sha-384", Alg::Sha384),
    ("sha2-384", Alg::Sha384),
    ("rsa-sha384", Alg::Sha384),
    ("sha384withrsaencryption", Alg::Sha384),
    ("2.16.840.1.101.3.4.2.2", Alg::Sha384),
    ("sha512", Alg::Sha512),
    ("sha-512", Alg::Sha512),
    ("sha2-512", Alg::Sha512),
    ("rsa-sha512", Alg::Sha512),
    ("sha512withrsaencryption", Alg::Sha512),
    ("2.16.840.1.101.3.4.2.3", Alg::Sha512),
    ("sha512-224", Alg::Sha512_224),
    ("sha-512/224", Alg::Sha512_224),
    ("sha2-512/224", Alg::Sha512_224),
    ("rsa-sha512/224", Alg::Sha512_224),
    ("sha512-224withrsaencryption", Alg::Sha512_224),
    ("2.16.840.1.101.3.4.2.5", Alg::Sha512_224),
    ("sha512-256", Alg::Sha512_256),
    ("sha-512/256", Alg::Sha512_256),
    ("sha2-512/256", Alg::Sha512_256),
    ("rsa-sha512/256", Alg::Sha512_256),
    ("sha512-256withrsaencryption", Alg::Sha512_256),
    ("2.16.840.1.101.3.4.2.6", Alg::Sha512_256),
];

/// `EVP_get_digestbyname(name)` over [`NAMES`]: the name up to its first
/// NUL, compared ignoring ASCII case.
#[must_use]
pub fn resolve(name: &[u8]) -> Option<Alg> {
    let name = name.split(|&b| b == 0).next().unwrap_or_default();
    NAMES
        .iter()
        .find(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
        .map(|&(_, a)| a)
}

fn hash<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
    let mut d = D::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().to_vec()
}

impl Alg {
    /// The digest of the concatenation of `parts`.
    fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        match self {
            Alg::Md4 => hash::<md4::Md4>(parts),
            Alg::Md5 => hash::<md5::Md5>(parts),
            Alg::Sha1 => hash::<sha1::Sha1>(parts),
            Alg::Ripemd160 => hash::<ripemd::Ripemd160>(parts),
            Alg::Sha224 => hash::<sha2::Sha224>(parts),
            Alg::Sha256 => hash::<sha2::Sha256>(parts),
            Alg::Sha384 => hash::<sha2::Sha384>(parts),
            Alg::Sha512 => hash::<sha2::Sha512>(parts),
            Alg::Sha512_224 => hash::<sha2::Sha512_224>(parts),
            Alg::Sha512_256 => hash::<sha2::Sha512_256>(parts),
        }
    }

    /// The input block size, which HMAC pads the key to (`EVP_MD_block_size`).
    #[must_use]
    pub fn block_size(self) -> usize {
        match self {
            Alg::Md4 | Alg::Md5 | Alg::Sha1 | Alg::Ripemd160 | Alg::Sha224 | Alg::Sha256 => 64,
            Alg::Sha384 | Alg::Sha512 | Alg::Sha512_224 | Alg::Sha512_256 => 128,
        }
    }
}

/// `l_digest`: the digest of `msg`.
#[must_use]
pub fn digest(alg: Alg, msg: &[u8]) -> Vec<u8> {
    alg.hash(&[msg])
}

/// `l_hmac`'s `HMAC(evp_md, key, key_len, msg, msg_len, ...)`: RFC 2104.
/// A key longer than the block is hashed first; the key is then padded
/// with zeros to the block.
#[must_use]
pub fn hmac(alg: Alg, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let block = alg.block_size();
    let mut k = if key.len() > block {
        alg.hash(&[key])
    } else {
        key.to_vec()
    };
    k.resize(block, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let inner = alg.hash(&[&ipad, msg]);
    alg.hash(&[&opad, &inner])
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

    /// The published vectors: RFC 1320 A.5 (MD4), RFC 1321 A.5 (MD5),
    /// FIPS 180-4's examples (SHA-1, SHA-2), and the RIPEMD-160 page.
    #[test]
    fn published_digest_vectors() {
        let million_a = vec![b'a'; 1_000_000];
        let cases: &[(Alg, &[u8], &str)] = &[
            (Alg::Md4, b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            (Alg::Md4, b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
            (
                Alg::Md4,
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
            (Alg::Md5, b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (Alg::Md5, b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                Alg::Md5,
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
            (Alg::Sha1, b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                Alg::Sha1,
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            ),
            (Alg::Ripemd160, b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            (Alg::Ripemd160, b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            (
                Alg::Sha224,
                b"abc",
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            ),
            (
                Alg::Sha256,
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                Alg::Sha384,
                b"abc",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                Alg::Sha512,
                b"abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                Alg::Sha512_224,
                b"abc",
                "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
            ),
            (
                Alg::Sha512_256,
                b"abc",
                "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
            ),
        ];
        for &(alg, msg, want) in cases {
            assert_eq!(hex(&digest(alg, msg)), want, "{alg:?} {msg:?}");
        }
        if !cfg!(miri) {
            assert_eq!(
                hex(&digest(Alg::Sha1, &million_a)),
                "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
            );
            assert_eq!(
                hex(&digest(Alg::Ripemd160, &million_a)),
                "52783243c1697bdbe16d37f97f68f08325dc1528"
            );
        }
    }

    /// RFC 2202 (HMAC-MD5, HMAC-SHA-1) and RFC 4231 (HMAC-SHA-2), including
    /// their keys longer than a block, which are hashed first.
    #[test]
    fn rfc_hmac_vectors() {
        let k20 = vec![0x0b; 20];
        let k16 = vec![0x0b; 16];
        let aa80 = vec![0xaa; 80];
        let aa131 = vec![0xaa; 131];
        let cases: &[(Alg, &[u8], &[u8], &str)] = &[
            (Alg::Md5, &k16, b"Hi There", "9294727a3638bb1c13f48ef8158bfc9d"),
            (
                Alg::Md5,
                b"Jefe",
                b"what do ya want for nothing?",
                "750c783e6ab0b503eaa86e310a5db738",
            ),
            (
                Alg::Md5,
                &aa80,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
            ),
            (
                Alg::Sha1,
                &k20,
                b"Hi There",
                "b617318655057264e28bc0b6fb378c8ef146be00",
            ),
            (
                Alg::Sha1,
                &aa80,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "aa4ae5e15272d00e95705637ce8a3b55ed402112",
            ),
            (
                Alg::Sha224,
                &k20,
                b"Hi There",
                "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
            ),
            (
                Alg::Sha256,
                &k20,
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                Alg::Sha256,
                &aa131,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                Alg::Sha384,
                &k20,
                b"Hi There",
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            ),
            (
                Alg::Sha512,
                &k20,
                b"Hi There",
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
            (
                Alg::Sha512,
                &aa131,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            ),
        ];
        for &(alg, key, msg, want) in cases {
            assert_eq!(hex(&hmac(alg, key, msg)), want, "{alg:?}");
        }
        // A key of exactly a block is used as it is; one byte more is hashed.
        for alg in [Alg::Md5, Alg::Sha512] {
            let b = alg.block_size();
            assert_ne!(
                hmac(alg, &vec![1; b], b"m"),
                hmac(alg, &digest(alg, &vec![1; b]), b"m")
            );
            assert_eq!(
                hmac(alg, &vec![1; b + 1], b"m"),
                hmac(alg, &digest(alg, &vec![1; b + 1]), b"m")
            );
        }
        let _ = unhex;
    }

    #[test]
    fn names_resolve_case_insensitively_up_to_a_nul() {
        assert_eq!(resolve(b"md5"), Some(Alg::Md5));
        assert_eq!(resolve(b"mD5"), Some(Alg::Md5));
        assert_eq!(resolve(b"md5\0junk"), Some(Alg::Md5));
        assert_eq!(resolve(b"SHA-512/224"), Some(Alg::Sha512_224));
        assert_eq!(resolve(b"sha512/224"), None);
        assert_eq!(resolve(b" md5"), None);
        assert_eq!(resolve(b"md5 "), None);
        assert_eq!(resolve(b""), None);
        assert_eq!(resolve(b"\0md5"), None);
        assert_eq!(resolve(b"sha3-256"), None);
        assert_eq!(resolve(b"MD5-SHA1"), None);
        // ASCII only: a non-ASCII byte matches only itself.
        assert_eq!(resolve("m\u{e4}5".as_bytes()), None);
    }

    /// The oracle's 398 spellings (oracle/gen_m65_digest_names.py): each
    /// D4 one resolves to the algorithm the oracle's digest of "abc" named,
    /// and every `other` or `unknown` one resolves to nothing.
    #[test]
    #[cfg_attr(miri, ignore = "reads the corpus from disk")]
    fn every_recorded_spelling_resolves_as_the_oracle_does() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/differential/m6/m65_digest_names.txt"
        );
        let text = std::fs::read_to_string(path).expect("m65_digest_names.txt");
        let class = |a: Alg| match a {
            Alg::Md4 => "md4",
            Alg::Md5 => "md5",
            Alg::Sha1 => "sha1",
            Alg::Ripemd160 => "ripemd160",
            Alg::Sha224 => "sha224",
            Alg::Sha256 => "sha256",
            Alg::Sha384 => "sha384",
            Alg::Sha512 => "sha512",
            Alg::Sha512_224 => "sha512-224",
            Alg::Sha512_256 => "sha512-256",
        };
        let (mut n, mut d4) = (0, 0);
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (h, want) = line.split_once('\t').expect("HEX<TAB>CLASS");
            let name = unhex(h);
            let got = resolve(&name).map_or("refused", class);
            let want_port = if want == "other" || want == "unknown" {
                "refused"
            } else {
                d4 += 1;
                want
            };
            assert_eq!(got, want_port, "{:?}", String::from_utf8_lossy(&name));
            n += 1;
        }
        assert!(n > 150 && d4 >= NAMES.len(), "{n} spellings, {d4} D4");
        // Every entry of the table is exercised by some recorded spelling.
        for &(name, _) in NAMES {
            assert!(
                text.contains(&hex(name.as_bytes())),
                "{name} is not in the oracle's record"
            );
        }
    }
}
