//! Ed448 signature verification (RFC 8032 §5.2.7), for the `ed448`
//! signature scheme 7.94 offers (M6.7 step f). As OpenSSL verifies
//! (`ossl_c448_ed448_verify`, crypto/ec/curve448/eddsa.c at 3.0.13): the
//! public key must decode, S must be below the group's order, and
//! `[S]B - [k]A` must encode to exactly the signature's R, so a
//! non-canonical R is refused. No cofactor is applied, as OpenSSL applies
//! none.
//!
//! Everything here is public (the key, the message, the signature), so the
//! arithmetic is `num-bigint`'s, in projective coordinates (RFC 8032
//! §5.2.4); M6.5's rule against secret-dependent `num-bigint` work does not
//! reach it.

use num_bigint::BigUint;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// p = 2^448 - 2^224 - 1.
fn p() -> BigUint {
    BigUint::parse_bytes(
        concat!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        .as_bytes(),
        16,
    )
    .unwrap_or_default()
}

/// The group's order, L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885.
fn order() -> BigUint {
    BigUint::parse_bytes(
        b"3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
        16,
    )
    .unwrap_or_default()
}

/// The base point's coordinates (RFC 8032 §5.2).
const BX: &[u8] = b"4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e";
const BY: &[u8] = b"693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14";

/// A point in projective coordinates (X : Y : Z), x = X/Z, y = Y/Z.
#[derive(Clone, Debug)]
struct Point {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

/// The field, with d = -39081.
struct Field {
    p: BigUint,
    d: BigUint,
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "num-bigint arithmetic on unbounded integers, reduced mod p; a subtraction adds p first"
)]
impl Field {
    fn new() -> Self {
        let p = p();
        let d = &p - BigUint::from(39081u32);
        Self { p, d }
    }

    fn add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a + b) % &self.p
    }

    fn sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a + &self.p - (b % &self.p)) % &self.p
    }

    fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.p
    }

    /// a^(p-2): the inverse of a non-zero a.
    fn inv(&self, a: &BigUint) -> BigUint {
        a.modpow(&(&self.p - BigUint::from(2u8)), &self.p)
    }

    fn identity() -> Point {
        Point {
            x: BigUint::from(0u8),
            y: BigUint::from(1u8),
            z: BigUint::from(1u8),
        }
    }

    /// RFC 8032 §5.2.4, addition (a = 1).
    fn padd(&self, a: &Point, b: &Point) -> Point {
        let aa = self.mul(&a.z, &b.z);
        let bb = self.mul(&aa, &aa);
        let c = self.mul(&a.x, &b.x);
        let d = self.mul(&a.y, &b.y);
        let e = self.mul(&self.mul(&self.d, &c), &d);
        let f = self.sub(&bb, &e);
        let g = self.add(&bb, &e);
        let h = self.mul(&self.add(&a.x, &a.y), &self.add(&b.x, &b.y));
        Point {
            x: self.mul(&self.mul(&aa, &f), &self.sub(&self.sub(&h, &c), &d)),
            y: self.mul(&self.mul(&aa, &g), &self.sub(&d, &c)),
            z: self.mul(&f, &g),
        }
    }

    /// `[k]P`, by double-and-add (k is public).
    fn scalar_mul(&self, k: &BigUint, pt: &Point) -> Point {
        let mut acc = Self::identity();
        for i in (0..k.bits()).rev() {
            acc = self.padd(&acc, &acc);
            if k.bit(i) {
                acc = self.padd(&acc, pt);
            }
        }
        acc
    }

    fn neg(&self, pt: &Point) -> Point {
        Point {
            x: self.sub(&BigUint::from(0u8), &pt.x),
            y: pt.y.clone(),
            z: pt.z.clone(),
        }
    }

    /// RFC 8032 §5.2.2: 57 bytes, y little-endian with x's low bit on top.
    fn encode(&self, pt: &Point) -> [u8; 57] {
        let zi = self.inv(&pt.z);
        let x = self.mul(&pt.x, &zi);
        let y = self.mul(&pt.y, &zi);
        let mut out = [0u8; 57];
        let yb = y.to_bytes_le();
        out[..yb.len()].copy_from_slice(&yb);
        if x.bit(0) {
            out[56] |= 0x80;
        }
        out
    }

    /// RFC 8032 §5.2.3; `None` where the encoding is refused.
    fn decode(&self, enc: &[u8; 57]) -> Option<Point> {
        // Bits 448 to 454 must be zero; bit 455 is x's sign.
        if enc[56] & 0x7f != 0 {
            return None;
        }
        let sign = enc[56] >> 7 == 1;
        let y = BigUint::from_bytes_le(&enc[..56]);
        if y >= self.p {
            return None;
        }
        // x^2 = (y^2 - 1) / (d y^2 - 1)
        let y2 = self.mul(&y, &y);
        let u = self.sub(&y2, &BigUint::from(1u8));
        let v = self.sub(&self.mul(&self.d, &y2), &BigUint::from(1u8));
        // x = u^3 v (u^5 v^3)^((p-3)/4)
        let u3 = self.mul(&self.mul(&u, &u), &u);
        let u5v3 = self.mul(
            &self.mul(&u3, &self.mul(&u, &u)),
            &self.mul(&self.mul(&v, &v), &v),
        );
        let e = (&self.p - BigUint::from(3u8)) >> 2u32;
        let mut x = self.mul(&self.mul(&u3, &v), &u5v3.modpow(&e, &self.p));
        if self.mul(&v, &self.mul(&x, &x)) != u {
            return None;
        }
        if x.bits() == 0 && sign {
            return None;
        }
        if x.bit(0) != sign {
            x = self.sub(&BigUint::from(0u8), &x);
        }
        Some(Point {
            x,
            y,
            z: BigUint::from(1u8),
        })
    }
}

/// SHAKE256(dom4(0, "") || R || A || M, 114), as an integer mod L.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "num-bigint reduction of an unbounded integer"
)]
fn challenge(r: &[u8], a: &[u8], msg: &[u8], l: &BigUint) -> BigUint {
    let mut h = sha3::Shake256::default();
    h.update(b"SigEd448\x00\x00");
    h.update(r);
    h.update(a);
    h.update(msg);
    let mut out = [0u8; 114];
    h.finalize_xof().read(&mut out);
    BigUint::from_bytes_le(&out) % l
}

/// Whether `sig` is an Ed448 signature (pure, no context) of `msg` under
/// the 57-byte public key `key`.
#[must_use]
pub(crate) fn verify(key: &[u8; 57], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = <&[u8; 114]>::try_from(sig) else {
        return false;
    };
    let (r, s) = sig.split_at(57);
    let f = Field::new();
    let l = order();
    let s = BigUint::from_bytes_le(s);
    if s >= l {
        return false;
    }
    let Some(a) = f.decode(key) else {
        return false;
    };
    let (Some(bx), Some(by)) = (BigUint::parse_bytes(BX, 16), BigUint::parse_bytes(BY, 16)) else {
        return false;
    };
    let base = Point {
        x: bx,
        y: by,
        z: BigUint::from(1u8),
    };
    let k = challenge(r, key, msg, &l);
    let sb = f.scalar_mul(&s, &base);
    let ka = f.scalar_mul(&k, &a);
    f.encode(&f.padd(&sb, &f.neg(&ka))).as_slice() == r
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic on unbounded integers"
)]
mod tests {
    use super::*;

    #[test]
    fn the_base_point_is_on_the_curve_and_of_order_l() {
        let f = Field::new();
        let b = Point {
            x: BigUint::parse_bytes(BX, 16).expect("x"),
            y: BigUint::parse_bytes(BY, 16).expect("y"),
            z: BigUint::from(1u8),
        };
        let (x2, y2) = (f.mul(&b.x, &b.x), f.mul(&b.y, &b.y));
        assert_eq!(
            f.add(&x2, &y2),
            f.add(&BigUint::from(1u8), &f.mul(&f.d, &f.mul(&x2, &y2)))
        );
        // [L]B is the identity, which encodes as y = 1, x = 0.
        let mut id = [0u8; 57];
        id[0] = 1;
        assert_eq!(f.encode(&f.scalar_mul(&order(), &b)), id);
        // And B round-trips through its encoding.
        let enc = f.encode(&b);
        assert_eq!(f.encode(&f.decode(&enc).expect("decodes")), enc);
    }
}
