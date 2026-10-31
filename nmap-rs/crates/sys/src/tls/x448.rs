//! X448 (RFC 7748 §5): the Montgomery ladder of §5's pseudocode over
//! `crypto-bigint`'s fixed-size Montgomery form, with the conditional swap
//! done by `ct_assign` (M6.7 D4 (b), step a). Every operation is constant
//! time in the scalar: the ladder runs all 448 steps, the swap is a mask, and
//! the final inversion is `crypto-bigint`'s constant-time `invert`. That is
//! the rule of docs/M6.5-ANALYSIS.md (the provider never does secret-dependent
//! work over `num-bigint`); step 0's spike over `num-bigint` was not.

use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Choice, CtAssign, Odd, U448};

type Fe = FixedMontyForm<{ U448::LIMBS }>;

/// p = 2^448 - 2^224 - 1.
const P: U448 = U448::from_be_hex(concat!(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
));

fn params() -> FixedMontyParams<{ U448::LIMBS }> {
    // The modulus is public: computing its parameters in variable time
    // leaks nothing.
    FixedMontyParams::new_vartime(Odd::new(P).expect("p is odd"))
}

/// (A - 2) / 4 for A = 156326.
const A24: u64 = 39081;

/// Swap `a` and `b` when `swap` is set, in constant time.
fn cswap(swap: Choice, a: &mut Fe, b: &mut Fe) {
    let old_a = *a;
    a.ct_assign(b, swap);
    b.ct_assign(&old_a, swap);
}

/// `X448(k, u)`.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "field arithmetic mod p (+, -, * of FixedMontyForm) cannot overflow; t / 8 and t % 8 index 56 bytes for t < 448"
)]
pub(crate) fn x448(k: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
    let params = params();
    // `decodeScalar448`: clear the two low bits, set the top one.
    let mut k = *k;
    k[0] &= 252;
    k[55] |= 128;
    // `decodeUCoordinate`: all 448 bits; the Montgomery form reduces mod p.
    let x1 = Fe::new(&U448::from_le_slice(u), &params);
    let a24 = Fe::new(&U448::from_u64(A24), &params);
    let mut x2 = Fe::one(&params);
    let mut z2 = Fe::zero(&params);
    let mut x3 = x1;
    let mut z3 = Fe::one(&params);
    let mut swap = Choice::FALSE;
    for t in (0..448usize).rev() {
        let k_t = Choice::from_u8_lsb(k[t / 8] >> (t % 8));
        swap ^= k_t;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = k_t;
        let a = x2 + z2;
        let aa = a.square();
        let b = x2 - z2;
        let bb = b.square();
        let e = aa - bb;
        let c = x3 + z3;
        let d = x3 - z3;
        let da = d * a;
        let cb = c * b;
        x3 = (da + cb).square();
        z3 = x1 * (da - cb).square();
        x2 = aa * bb;
        z2 = e * (aa + a24 * e);
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    // z2 is 0 for a low-order u; RFC 7748 then gives 0, which the caller
    // refuses. `invert` of 0 is none: take 0 in its place.
    let inv = z2.invert().unwrap_or(Fe::zero(&params));
    let out = (x2 * inv).retrieve().to_le_bytes();
    let mut r = [0u8; 56];
    r.copy_from_slice(out.as_ref());
    r
}

/// The public key for `k`: X448 of the base point u = 5.
#[must_use]
pub(crate) fn public(k: &[u8; 56]) -> [u8; 56] {
    let mut five = [0u8; 56];
    five[0] = 5;
    x448(k, &five)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "hex decoding of fixed test vectors"
)]
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
    #[cfg_attr(miri, ignore = "a 448-step ladder takes minutes under Miri")]
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
    #[cfg_attr(miri, ignore = "1,000 ladders are too slow under Miri")]
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
    #[cfg_attr(miri, ignore = "a 448-step ladder takes minutes under Miri")]
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

    /// A low-order u (0 and 1 are two of them) gives the all-zero output,
    /// which the key exchange refuses.
    #[test]
    #[cfg_attr(miri, ignore = "a 448-step ladder takes minutes under Miri")]
    fn low_order_points_give_zero() {
        let k = [0x42u8; 56];
        assert_eq!(x448(&k, &[0u8; 56]), [0u8; 56]);
        let mut one = [0u8; 56];
        one[0] = 1;
        assert_eq!(x448(&k, &one), [0u8; 56]);
    }
}
