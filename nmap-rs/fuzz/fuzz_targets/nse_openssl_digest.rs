// cargo-fuzz target for `nmap_core::nse::openssl::digest`, the `openssl`
// module's digests and HMAC (M6.5 step c). Its inputs are script- and
// peer-controlled: the algorithm name a script passes, and the key and
// message, which are challenges, nonces and passwords off the wire (sasl,
// pop3 APOP, mysql, ipmi, smbauth; `docs/M6.5-ANALYSIS.md` §3).
//
// Checked, on arbitrary bytes:
//   * `resolve` never panics, ignores ASCII case, and reads only up to the
//     first NUL: the name, its upper-case form, and the name with a NUL and
//     junk appended resolve alike;
//   * `digest` equals the crate's hash fed in two pieces split at a
//     fuzzer-chosen point (its buffering at every block edge), and has the
//     crate's output size;
//   * `hmac` equals a reference HMAC (RFC 2104) that takes the block size
//     from the crate's own `BlockSizeUser`, not the port's table, and feeds
//     the inner hash in pieces.
//
// Input layout: byte 0 picks the algorithm, byte 1 the split point; the
// rest is split at its first 0xFF into the key (or name) and the message.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::openssl::digest::{self, Alg};
use sha2::digest::core_api::BlockSizeUser;
use sha2::Digest;

const ALGS: [Alg; 10] = [
    Alg::Md4,
    Alg::Md5,
    Alg::Sha1,
    Alg::Ripemd160,
    Alg::Sha224,
    Alg::Sha256,
    Alg::Sha384,
    Alg::Sha512,
    Alg::Sha512_224,
    Alg::Sha512_256,
];

fn split_hash<D: Digest>(msg: &[u8], at: usize) -> Vec<u8> {
    let at = at.min(msg.len());
    let mut d = D::new();
    d.update(&msg[..at]);
    d.update(&msg[at..]);
    d.finalize().to_vec()
}

fn ref_hmac<D: Digest + BlockSizeUser>(key: &[u8], msg: &[u8], at: usize) -> Vec<u8> {
    let block = <D as BlockSizeUser>::block_size();
    let mut k = if key.len() > block {
        D::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(block, 0);
    let mut inner = D::new();
    inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    let at = at.min(msg.len());
    inner.update(&msg[..at]);
    inner.update(&msg[at..]);
    let mut outer = D::new();
    outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(inner.finalize());
    outer.finalize().to_vec()
}

fn check<D: Digest + BlockSizeUser>(alg: Alg, key: &[u8], msg: &[u8], at: usize) {
    let d = digest::digest(alg, msg);
    assert_eq!(d.len(), <D as Digest>::output_size(), "{alg:?}");
    assert_eq!(d, split_hash::<D>(msg, at), "{alg:?} digest");
    assert_eq!(<D as BlockSizeUser>::block_size(), alg.block_size(), "{alg:?}");
    assert_eq!(
        digest::hmac(alg, key, msg),
        ref_hmac::<D>(key, msg, at),
        "{alg:?} hmac"
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (pick, at) = (data[0], usize::from(data[1]) * 7);
    let rest = &data[2..];
    let (key, msg) = match rest.iter().position(|&b| b == 0xff) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &rest[..0]),
    };

    // Names: the key bytes as a name.
    let r = digest::resolve(key);
    assert_eq!(r, digest::resolve(&key.to_ascii_uppercase()));
    assert_eq!(r, digest::resolve(&key.to_ascii_lowercase()));
    let mut junk = key.split(|&b| b == 0).next().unwrap_or_default().to_vec();
    junk.push(0);
    junk.extend_from_slice(msg);
    assert_eq!(r, digest::resolve(&junk));

    let alg = ALGS[usize::from(pick) % ALGS.len()];
    match alg {
        Alg::Md4 => check::<md4::Md4>(alg, key, msg, at),
        Alg::Md5 => check::<md5::Md5>(alg, key, msg, at),
        Alg::Sha1 => check::<sha1::Sha1>(alg, key, msg, at),
        Alg::Ripemd160 => check::<ripemd::Ripemd160>(alg, key, msg, at),
        Alg::Sha224 => check::<sha2::Sha224>(alg, key, msg, at),
        Alg::Sha256 => check::<sha2::Sha256>(alg, key, msg, at),
        Alg::Sha384 => check::<sha2::Sha384>(alg, key, msg, at),
        Alg::Sha512 => check::<sha2::Sha512>(alg, key, msg, at),
        Alg::Sha512_224 => check::<sha2::Sha512_224>(alg, key, msg, at),
        Alg::Sha512_256 => check::<sha2::Sha512_256>(alg, key, msg, at),
    }
});
