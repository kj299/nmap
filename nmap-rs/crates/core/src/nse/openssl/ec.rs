//! OpenSSL's built-in elliptic curves and its point decoder (`crypto/ec/
//! ec_curve.c`, `ecp_oct.c`, `ec2_oct.c`, `ec2_smpl.c`), as much as decides
//! whether a certificate's EC public key decodes and what nmap reports for
//! it: the curve's name (`OSSL_EC_curve_nid2name`), its order's size in bits
//! (`EVP_PKEY_bits`), and whether the point is valid: the encoding's form and
//! length, coordinates inside the field, a compressed point that has a
//! solution, a point on the curve. Pure; nothing here is secret, so nothing
//! needs to be constant-time.
//!
//! **Arithmetic** is on `BigUint`s, which do not overflow, and on bit
//! counts and indices below a field's degree (at most a few thousand for
//! explicit parameters, which are capped at 661 bits).
#![allow(clippy::arithmetic_side_effects)]

use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::curves_table::{CURVES, CURVE_NAMES};

/// One built-in curve, its data as `ec_curve.c` holds it.
pub struct Curve {
    pub nid: u16,
    /// A binary field (`NID_X9_62_characteristic_two_field`): `p` is the
    /// reduction polynomial's bits.
    pub char2: bool,
    pub seed: &'static [u8],
    pub p: &'static [u8],
    pub a: &'static [u8],
    pub b: &'static [u8],
    pub x: &'static [u8],
    pub y: &'static [u8],
    pub order: &'static [u8],
    pub cofactor: u32,
}

/// `EC_GROUP_new_by_curve_name`'s lookup.
#[must_use]
pub fn curve(nid: u16) -> Option<&'static Curve> {
    CURVES.iter().find(|c| c.nid == nid)
}

/// The built-in curves, in `curve_list`'s order.
#[must_use]
pub fn curves() -> &'static [Curve] {
    &CURVES
}

/// `OSSL_EC_curve_nid2name`: the first name `ec_support.c` lists for it.
#[must_use]
pub fn curve_name(nid: u16) -> Option<&'static str> {
    CURVE_NAMES
        .iter()
        .find(|&&(_, n)| n == nid)
        .map(|&(name, _)| name)
}

/// A group to decode a point on: the built-in curve's numbers, or explicit
/// parameters' (`EC_GROUP_new_from_ecparameters`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub char2: bool,
    /// The prime, or the reduction polynomial.
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub order: BigUint,
}

impl Group {
    #[must_use]
    pub fn builtin(c: &Curve) -> Group {
        Group {
            char2: c.char2,
            p: BigUint::from_bytes_be(c.p),
            a: BigUint::from_bytes_be(c.a),
            b: BigUint::from_bytes_be(c.b),
            order: BigUint::from_bytes_be(c.order),
        }
    }

    /// `EC_GROUP_order_bits`.
    #[must_use]
    pub fn order_bits(&self) -> u64 {
        self.order.bits()
    }

    /// `EC_GROUP_get_degree` for a binary field (the polynomial's degree);
    /// for a prime field, the prime's size in bits.
    #[must_use]
    pub fn degree(&self) -> u64 {
        if self.char2 {
            self.p.bits().saturating_sub(1)
        } else {
            self.p.bits()
        }
    }

    /// `EC_POINT_oct2point` (`ossl_ec_GFp_simple_oct2point`,
    /// `ossl_ec_GF2m_simple_oct2point`): whether `buf` is a valid encoding of
    /// a point of this group. The point at infinity (`00`) is.
    #[must_use]
    pub fn point_ok(&self, buf: &[u8]) -> bool {
        self.decode_point(buf).is_some()
    }

    /// [`Group::point_ok`], and the point: its affine coordinates, or
    /// `(None, None)` for the point at infinity.
    #[must_use]
    pub fn decode_point(&self, buf: &[u8]) -> Option<(Option<BigUint>, Option<BigUint>)> {
        let &first = buf.first()?;
        let y_bit = first & 1 != 0;
        let form = first & !1;
        if !matches!(form, 0 | 2 | 4 | 6) {
            return None;
        }
        if (form == 0 || form == 4) && y_bit {
            return None;
        }
        if form == 0 {
            return (buf.len() == 1).then_some((None, None));
        }
        let field_len = if self.char2 {
            usize::try_from(self.degree().div_ceil(8)).unwrap_or(usize::MAX)
        } else {
            usize::try_from(self.p.bits().div_ceil(8)).unwrap_or(usize::MAX)
        };
        let enc_len = if form == 2 {
            field_len.saturating_add(1)
        } else {
            field_len.saturating_mul(2).saturating_add(1)
        };
        if buf.len() != enc_len {
            return None;
        }
        let x = BigUint::from_bytes_be(&buf[1..=field_len]);
        let rest = &buf[1 + field_len..];
        let (x, y) = if self.char2 {
            self.char2_point(form, y_bit, x, rest)?
        } else {
            self.prime_point(form, y_bit, x, rest)?
        };
        Some((Some(x), Some(y)))
    }

    fn prime_point(
        &self,
        form: u8,
        y_bit: bool,
        x: BigUint,
        rest: &[u8],
    ) -> Option<(BigUint, BigUint)> {
        let p = &self.p;
        if &x >= p {
            return None;
        }
        let rhs = |x: &BigUint| (x * x * x + &self.a * x + &self.b) % p;
        if form == 2 {
            // ossl_ec_GFp_simple_set_compressed_coordinates: a square root of
            // the right-hand side, or the point is invalid; the root of the
            // parity y_bit asks for (p - y for the other), and the root zero
            // cannot carry y_bit.
            let y = sqrt_mod_prime(&rhs(&x), p)?;
            if y_bit == y.bit(0) {
                return Some((x, y));
            }
            if y.is_zero() {
                return None;
            }
            return Some((x, p - y));
        }
        let y = BigUint::from_bytes_be(rest);
        if &y >= p {
            return None;
        }
        if form == 6 && y_bit != y.bit(0) {
            return None;
        }
        ((&y * &y) % p == rhs(&x)).then_some((x, y))
    }

    fn char2_point(
        &self,
        form: u8,
        y_bit: bool,
        x: BigUint,
        rest: &[u8],
    ) -> Option<(BigUint, BigUint)> {
        let m = self.degree();
        if x.bits() > m {
            return None;
        }
        let f = Gf2m::new(&self.p);
        let x = f.elem(&x);
        let a = f.elem(&self.a);
        let b = f.elem(&self.b);
        let on_curve = |x: &BigUint, y: &BigUint| {
            // y^2 + x*y = x^3 + a*x^2 + b  <=>  ((x + a)*x + y)*x + b + y^2 = 0
            f.add(
                &f.add(&f.mul(&f.add(&f.mul(&f.add(x, &a), x), y), x), &b),
                &f.sqr(y),
            )
            .is_zero()
        };
        if form == 2 {
            // ossl_ec_GF2m_simple_set_compressed_coordinates: x = 0 has
            // y = sqrt(b); otherwise y = x*z for z with z^2 + z = x + a +
            // b/x^2, which must exist, z's low bit chosen by y_bit.
            let y = if x.is_zero() {
                f.sqrt(&b)
            } else {
                let inv = f.inv(&f.sqr(&x))?;
                let c = f.add(&f.add(&f.mul(&b, &inv), &a), &x);
                let z = f.solve_quad(&c)?;
                let y = f.mul(&x, &z);
                if z.bit(0) == y_bit {
                    y
                } else {
                    f.add(&y, &x)
                }
            };
            return on_curve(&x, &y).then_some((x, y));
        }
        let yv = BigUint::from_bytes_be(rest);
        if yv.bits() > m {
            return None;
        }
        let y = f.elem(&yv);
        if form == 6 {
            if x.is_zero() {
                if y_bit {
                    return None;
                }
            } else {
                let xi = f.inv(&x)?;
                if y_bit != f.mul(&y, &xi).bit(0) {
                    return None;
                }
            }
        }
        on_curve(&x, &y).then_some((x, y))
    }
}

/// A square root of `a` modulo the odd prime `p` (`BN_mod_sqrt`): either
/// root, or `None` if `a` is not a square. Tonelli-Shanks.
#[must_use]
pub fn sqrt_mod_prime(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    let a = a % p;
    if a.is_zero() {
        return Some(BigUint::zero());
    }
    let one = BigUint::one();
    let two = BigUint::from(2u8);
    if p == &two {
        return Some(a);
    }
    let pm1 = p - &one;
    // Euler's criterion.
    if a.modpow(&(&pm1 >> 1u8), p) != one {
        return None;
    }
    let s = pm1.trailing_zeros().unwrap_or(0);
    let q = &pm1 >> s;
    let mut z = two.clone();
    while z.modpow(&(&pm1 >> 1u8), p) != pm1 {
        z += 1u8;
        if &z >= p {
            return None;
        }
    }
    let mut m = s;
    let mut c = z.modpow(&q, p);
    let mut t = a.modpow(&q, p);
    let mut r = a.modpow(&((&q + &one) >> 1u8), p);
    while t != one {
        let mut i = 0u64;
        let mut tt = t.clone();
        while tt != one {
            tt = &tt * &tt % p;
            i += 1;
            if i == m {
                return None;
            }
        }
        let mut b = c.clone();
        for _ in 0..(m - i - 1) {
            b = &b * &b % p;
        }
        m = i;
        c = &b * &b % p;
        t = t * &c % p;
        r = r * &b % p;
    }
    Some(r)
}

/// Arithmetic in GF(2^m) modulo a reduction polynomial, elements as bit
/// polynomials in a `BigUint`.
pub struct Gf2m {
    poly: BigUint,
    m: u64,
}

impl Gf2m {
    #[must_use]
    pub fn new(poly: &BigUint) -> Gf2m {
        Gf2m {
            poly: poly.clone(),
            m: poly.bits().saturating_sub(1),
        }
    }

    /// `BN_GF2m_mod_arr`: reduce.
    #[must_use]
    pub fn elem(&self, v: &BigUint) -> BigUint {
        let mut r = v.clone();
        while r.bits() > self.m && self.m > 0 {
            let shift = r.bits() - 1 - self.m;
            r ^= &self.poly << shift;
        }
        if self.m == 0 {
            return BigUint::zero();
        }
        r
    }

    #[must_use]
    pub fn add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a ^ b
    }

    #[must_use]
    pub fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        let mut acc = BigUint::zero();
        for i in 0..a.bits() {
            if a.bit(i) {
                acc ^= b << i;
            }
        }
        self.elem(&acc)
    }

    #[must_use]
    pub fn sqr(&self, a: &BigUint) -> BigUint {
        self.mul(a, a)
    }

    /// The inverse, by `a^(2^m - 2)`; `None` for zero.
    /// The square root, `a^(2^(m-1))` (`BN_GF2m_mod_sqrt_arr`).
    #[must_use]
    pub fn sqrt(&self, a: &BigUint) -> BigUint {
        let mut r = self.elem(a);
        for _ in 1..self.m {
            r = self.sqr(&r);
        }
        r
    }

    #[must_use]
    pub fn inv(&self, a: &BigUint) -> Option<BigUint> {
        if a.is_zero() {
            return None;
        }
        // a^(2^m - 2) = (a^(2^(m-1) - 1))^2, by square-and-multiply.
        let mut r = BigUint::one();
        let mut base = a.clone();
        // exponent 2^m - 2 has bits 1..m-1 set.
        for i in 0..self.m {
            if i >= 1 {
                r = self.mul(&r, &base);
            }
            base = self.sqr(&base);
        }
        Some(r)
    }

    /// A solution of `z^2 + z = c` (`BN_GF2m_mod_solve_quad_arr`), or `None`
    /// if there is none. Gaussian elimination over GF(2) on the linear map
    /// `z -> z^2 + z`, for any `m`.
    #[must_use]
    pub fn solve_quad(&self, c: &BigUint) -> Option<BigUint> {
        let m = usize::try_from(self.m).ok()?;
        if c.is_zero() {
            return Some(BigUint::zero());
        }
        // Column j is the image of the basis vector x^j.
        let cols: Vec<BigUint> = (0..m)
            .map(|j| {
                let e = BigUint::one() << j;
                self.add(&self.sqr(&e), &e)
            })
            .collect();
        // Rows of the augmented matrix [A | c]: row i has bit j for A[i][j]
        // and bit m for c's bit i.
        let mut rows: Vec<BigUint> = (0..m)
            .map(|i| {
                let mut r = BigUint::zero();
                for (j, col) in cols.iter().enumerate() {
                    if col.bit(i as u64) {
                        r.set_bit(j as u64, true);
                    }
                }
                if c.bit(i as u64) {
                    r.set_bit(m as u64, true);
                }
                r
            })
            .collect();
        let mut pivots = Vec::new();
        let mut row = 0usize;
        for col in 0..m {
            let Some(pr) = (row..m).find(|&r| rows[r].bit(col as u64)) else {
                continue;
            };
            rows.swap(row, pr);
            let pivot = rows[row].clone();
            for (r, v) in rows.iter_mut().enumerate() {
                if r != row && v.bit(col as u64) {
                    *v ^= &pivot;
                }
            }
            pivots.push((row, col));
            row += 1;
        }
        // A row with no pivot and the right-hand side set has no solution.
        if rows[row..].iter().any(|r| r.bit(m as u64)) {
            return None;
        }
        let mut z = BigUint::zero();
        for (r, col) in pivots {
            if rows[r].bit(m as u64) {
                z.set_bit(col as u64, true);
            }
        }
        Some(z)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn names_and_sizes_are_openssls() {
        let p256 = curve(415).unwrap();
        assert_eq!(curve_name(415), Some("prime256v1"));
        assert_eq!(Group::builtin(p256).order_bits(), 256);
        let k283 = curve(729).unwrap();
        assert_eq!(curve_name(729), Some("sect283k1"));
        assert_eq!(Group::builtin(k283).order_bits(), 281);
        assert_eq!(Group::builtin(k283).degree(), 283);
        assert_eq!(curves().len(), 82);
    }

    #[test]
    fn generators_decode_in_every_form() {
        // Every curve natively; under Miri, the two smallest of each field
        // type (the arithmetic is the same code, and all 82 take hours there).
        let mut picked: Vec<_> = curves().iter().collect();
        if cfg!(miri) {
            picked.sort_by_key(|c| (c.char2, c.p.len()));
            let prime: Vec<_> = picked
                .iter()
                .filter(|c| !c.char2)
                .take(2)
                .copied()
                .collect();
            let binary: Vec<_> = picked.iter().filter(|c| c.char2).take(2).copied().collect();
            picked = prime.into_iter().chain(binary).collect();
        }
        for c in picked {
            let g = Group::builtin(c);
            let len = if c.char2 {
                usize::try_from(g.degree().div_ceil(8)).unwrap()
            } else {
                usize::try_from(g.p.bits().div_ceil(8)).unwrap()
            };
            let pad = |v: &[u8]| {
                let n = BigUint::from_bytes_be(v).to_bytes_be();
                let mut out = vec![0u8; len - n.len().min(len)];
                out.extend_from_slice(&n);
                out
            };
            let (x, y) = (pad(c.x), pad(c.y));
            let mut un = vec![4];
            un.extend_from_slice(&x);
            un.extend_from_slice(&y);
            assert!(g.point_ok(&un), "uncompressed generator of {}", c.nid);
            let mut bad = un.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(!g.point_ok(&bad), "off-curve point accepted on {}", c.nid);
            let mut comp = vec![2];
            comp.extend_from_slice(&x);
            assert!(g.point_ok(&comp), "compressed generator of {}", c.nid);
            assert!(g.point_ok(&[0]));
            assert!(!g.point_ok(&[1]));
        }
    }

    #[test]
    fn a_compressed_prime_point_needs_a_root() {
        // secp256r1: x = 0 gives rhs = b, which has no square root.
        let g = Group::builtin(curve(415).unwrap());
        let mut enc = vec![2];
        enc.extend_from_slice(&[0; 32]);
        assert_eq!(sqrt_mod_prime(&g.b, &g.p).is_some(), g.point_ok(&enc));
        assert!(!g.point_ok(&hex("05")));
    }
}
