//! X448 (RFC 7748 §5), first-party over `num-bigint` (D4 (b)): the scalar
//! clamped, the u-coordinate read little-endian, the Montgomery ladder of
//! §5's pseudocode, and the result written back in 56 bytes.
//!
//! **Not constant-time.** `BigUint` arithmetic takes time that depends on its
//! operands. The scalar is a fresh ephemeral key per handshake, and the only
//! party that receives a value derived from it is the server, which learns
//! the shared secret anyway; step a weighs this before it ships (a
//! fixed-limb field would remove it).

use num_bigint::BigUint;
use num_traits::{One, Zero};

/// p = 2^448 - 2^224 - 1.
fn p() -> BigUint {
    (BigUint::one() << 448u32) - (BigUint::one() << 224u32) - BigUint::one()
}

/// (A - 2) / 4 for A = 156326.
const A24: u32 = 39081;

/// `decodeScalar448`: clear the two low bits, set the top one.
fn clamp(k: &[u8; 56]) -> BigUint {
    let mut k = *k;
    k[0] &= 252;
    k[55] |= 128;
    BigUint::from_bytes_le(&k)
}

fn encode(u: &BigUint) -> [u8; 56] {
    let mut out = [0u8; 56];
    let b = u.to_bytes_le();
    out[..b.len()].copy_from_slice(&b);
    out
}

/// `X448(k, u)`.
#[must_use]
pub fn x448(k: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
    let p = p();
    let k = clamp(k);
    // `decodeUCoordinate`: all 448 bits, reduced mod p.
    let x1 = BigUint::from_bytes_le(u) % &p;
    let (mut x2, mut z2) = (BigUint::one(), BigUint::zero());
    let (mut x3, mut z3) = (x1.clone(), BigUint::one());
    let mut swap = false;
    let sub = |a: &BigUint, b: &BigUint| (a + &p - b) % &p;
    for t in (0..448u64).rev() {
        let k_t = k.bit(t);
        if swap ^ k_t {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = k_t;
        let a = (&x2 + &z2) % &p;
        let aa = (&a * &a) % &p;
        let b = sub(&x2, &z2);
        let bb = (&b * &b) % &p;
        let e = sub(&aa, &bb);
        let c = (&x3 + &z3) % &p;
        let d = sub(&x3, &z3);
        let da = (&d * &a) % &p;
        let cb = (&c * &b) % &p;
        let s = (&da + &cb) % &p;
        x3 = (&s * &s) % &p;
        let dif = sub(&da, &cb);
        z3 = (&x1 * ((&dif * &dif) % &p)) % &p;
        x2 = (&aa * &bb) % &p;
        z2 = (&e * ((&aa + (&e * A24) % &p) % &p)) % &p;
    }
    if swap {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }
    // z2^(p-2): the inverse; 0 for z2 = 0, as RFC 7748 specifies.
    let inv = z2.modpow(&(&p - 2u32), &p);
    encode(&((x2 * inv) % &p))
}

/// The public key for `k`: X448 of the base point u = 5.
#[must_use]
pub fn public(k: &[u8; 56]) -> [u8; 56] {
    let mut five = [0u8; 56];
    five[0] = 5;
    x448(k, &five)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 56] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect();
        v.try_into().expect("56 bytes")
    }

    /// RFC 7748 §5.2, the two single-call vectors.
    #[test]
    fn rfc7748_vectors() {
        assert_eq!(
            x448(
                &h("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"),
                &h("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"),
            ),
            h("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f")
        );
        assert_eq!(
            x448(
                &h("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"),
                &h("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"),
            ),
            h("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d")
        );
    }

    /// RFC 7748 §5.2, the iterated vector: k = u = 5, then
    /// (k, u) = (X448(k, u), k), after 1 and 1,000 iterations.
    #[test]
    fn rfc7748_iterated() {
        let mut k = [0u8; 56];
        k[0] = 5;
        let mut u = k;
        for i in 1..=1000 {
            let r = x448(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(k, h("3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"));
            }
        }
        assert_eq!(k, h("aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"));
    }

    /// RFC 7748 §6.2, Alice and Bob.
    #[test]
    fn rfc7748_diffie_hellman() {
        let a = h("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
        let b = h("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
        let pa = public(&a);
        let pb = public(&b);
        assert_eq!(pa, h("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"));
        assert_eq!(pb, h("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"));
        let shared = h("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
        assert_eq!(x448(&a, &pb), shared);
        assert_eq!(x448(&b, &pa), shared);
    }
}
