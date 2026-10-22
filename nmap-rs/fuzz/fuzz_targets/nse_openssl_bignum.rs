// cargo-fuzz target for `nmap_core::nse::openssl::bn`, the `openssl`
// module's BIGNUM layer (M6.5 step b). Its inputs are script- and
// peer-controlled: `bignum_bin2bn` of a DH `p` or an ssh2 group, `dec2bn` of
// what `todec` printed, `mod_exp` and `is_prime` on them
// (`docs/M6.5-ANALYSIS.md` §6).
//
// Checked, on arbitrary bytes:
//   * nothing panics, and no value passes the construction cap;
//   * the text forms round-trip: hex, decimal, binary (the magnitude) and
//     MPI (decoded here by its own grammar) give the value back;
//   * against a model written with machine integers, where the operands fit
//     in 64 bits: `dec2bn`/`hex2bn`'s prefix parse, `add`, `div`
//     (truncating, zeros for a zero divisor), `mod_exp` (`a^|p| mod |m|` in
//     `[0, |m|)`, 0 modulo 0), the bit functions on the magnitude with the
//     sign kept, and primality against a deterministic Miller-Rabin for
//     64-bit numbers (`BN_check_prime` is random, but with 64 rounds its
//     error is under 2^-128).
//
// Input layout: byte 0 picks the operation, byte 1 a position, the rest is
// split at its first 0xFF into two operands.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::openssl::bn::{self, Bn, Random, CONSTRUCT_BITS};

/// Witnesses from the input's own bytes, cycled.
struct Bytes(Vec<u8>, usize);

impl Random for Bytes {
    fn fill(&mut self, buf: &mut [u8]) -> bool {
        for b in buf {
            *b = self.0.get(self.1 % self.0.len().max(1)).copied().unwrap_or(7) ^ (self.1 as u8);
            self.1 = self.1.wrapping_add(1);
        }
        true
    }
}

fn small(b: &Bn) -> Option<i128> {
    if b.num_bits() > 64 {
        return None;
    }
    let s = String::from_utf8(b.to_dec()).ok()?;
    s.parse().ok()
}

/// The prefix parse, written out.
fn model_parse(s: &[u8], radix: u32) -> Option<i128> {
    let s = s.split(|&b| b == 0).next().unwrap_or(&[]);
    let (neg, rest) = match s.split_first() {
        Some((b'-', r)) => (true, r),
        _ => (false, s),
    };
    let mut v: i128 = 0;
    for &b in rest {
        let d = match radix {
            10 if b.is_ascii_digit() => u32::from(b - b'0'),
            16 if b.is_ascii_hexdigit() => char::from(b).to_digit(16)?,
            _ => break,
        };
        v = v.checked_mul(i128::from(radix))?.checked_add(i128::from(d))?;
        if v > i128::from(u64::MAX) {
            return None;
        }
    }
    Some(if neg { -v } else { v })
}

fn mulmod(a: u128, b: u128, m: u128) -> u128 {
    // a, b < m <= 2^64: the product fits in 128 bits.
    a * b % m
}

fn powmod(mut b: u128, mut e: u128, m: u128) -> u128 {
    let mut r = 1 % m;
    b %= m;
    while e > 0 {
        if e & 1 == 1 {
            r = mulmod(r, b, m);
        }
        b = mulmod(b, b, m);
        e >>= 1;
    }
    r
}

fn model_prime(n: i128) -> bool {
    if n < 2 {
        return false;
    }
    let n = n as u128;
    for p in [2u128, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n.is_multiple_of(p) {
            return n == p;
        }
    }
    let (mut d, mut s) = (n - 1, 0);
    while d % 2 == 0 {
        d /= 2;
        s += 1;
    }
    'bases: for a in [2u128, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = powmod(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 1..s {
            x = mulmod(x, x, n);
            if x == n - 1 {
                continue 'bases;
            }
        }
        return false;
    }
    true
}

/// `BN_bn2mpi`'s grammar, read back.
fn from_mpi(m: &[u8]) -> Option<(bool, Vec<u8>)> {
    let (len, body) = m.split_at_checked(4)?;
    let len = u32::from_be_bytes(len.try_into().ok()?) as usize;
    if body.len() != len {
        return None;
    }
    let Some((&first, rest)) = body.split_first() else {
        return Some((false, Vec::new()));
    };
    let neg = first & 0x80 != 0;
    let mut mag = vec![first & 0x7f];
    mag.extend_from_slice(rest);
    let start = mag.iter().position(|&b| b != 0).unwrap_or(mag.len());
    Some((neg, mag[start..].to_vec()))
}

fn check_forms(b: &Bn) {
    assert!(b.num_bits() <= CONSTRUCT_BITS);
    assert_eq!(Bn::from_hex(&b.to_hex()).as_ref(), Ok(b));
    assert_eq!(Bn::from_dec(&b.to_dec()).as_ref(), Ok(b));
    let hex = b.to_hex();
    let digits = hex.strip_prefix(b"-").unwrap_or(&hex);
    assert!(b.is_zero() || digits.len().is_multiple_of(2), "{hex:?}");
    assert!(!hex.iter().any(u8::is_ascii_lowercase));
    let bin = b.to_bin();
    assert_eq!(bin.len() as u64, b.num_bytes());
    let (neg, mag) = from_mpi(&b.to_mpi()).expect("well-formed MPI");
    assert_eq!(mag, bin);
    assert_eq!(neg, b.to_dec().first() == Some(&b'-'));
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (op, pos) = (data[0], i32::from(data[1] as i8));
    let body = &data[2..];
    let cut = body.iter().position(|&b| b == 0xff).unwrap_or(body.len());
    let (x, y) = (&body[..cut], body.get(cut + 1..).unwrap_or(&[]));
    let a = match op % 3 {
        0 => Bn::from_bin(x),
        1 => Bn::from_dec(x),
        _ => Bn::from_hex(x),
    };
    let Ok(a) = a else { return };
    let b = Bn::from_dec(y).unwrap_or_default();
    check_forms(&a);
    if op % 3 != 0 {
        if let Some(m) = model_parse(x, if op % 3 == 1 { 10 } else { 16 }) {
            assert_eq!(small(&a), Some(m), "{x:?}");
        }
    }
    let (sa, sb) = (small(&a), small(&b));
    match (op / 3) % 6 {
        0 => {
            let s = a.add(&b).expect("under the cap");
            check_forms(&s);
            if let (Some(p), Some(q)) = (sa, sb) {
                // Two 64-bit magnitudes can sum to 65 bits, which `small`
                // does not model (a CI run found 2^64 - 1 + 12).
                let sum = p + q;
                let want = (sum.unsigned_abs() >> 64 == 0).then_some(sum);
                assert_eq!(small(&s), want);
            }
        }
        1 => {
            let (q, r) = a.div(&b);
            check_forms(&q);
            check_forms(&r);
            if let (Some(p), Some(d)) = (sa, sb) {
                let want = if d == 0 { (0, 0) } else { (p / d, p % d) };
                assert_eq!((small(&q), small(&r)), (Some(want.0), Some(want.1)));
            }
        }
        2 => {
            let m = Bn::from_bin(y.get(..8).unwrap_or(y)).expect("small");
            if let Ok(r) = Bn::mod_exp(&a, &b, &m) {
                check_forms(&r);
                if let (Some(p), Some(e), Some(mm)) = (sa, sb, small(&m)) {
                    let want = if mm == 0 {
                        0
                    } else {
                        let mm = mm.unsigned_abs();
                        let base = p.rem_euclid(mm as i128) as u128;
                        powmod(base, e.unsigned_abs(), mm) as i128
                    };
                    assert_eq!(small(&r), Some(want));
                }
            } else {
                assert!([&a, &b, &m].iter().any(|v| v.num_bits() > bn::MOD_EXP_BITS));
            }
        }
        3 => {
            let mut s = a.clone();
            let mut c = a.clone();
            assert!(s.set_bit(pos).is_ok());
            c.clear_bit(pos);
            check_forms(&s);
            check_forms(&c);
            assert_eq!(s.is_bit_set(pos), pos >= 0);
            assert!(!c.is_bit_set(pos));
            if let Some(v) = sa {
                if (0..60).contains(&pos) {
                    let mag = v.unsigned_abs();
                    let sign = |m: u128| if v < 0 { -(m as i128) } else { m as i128 };
                    assert_eq!(small(&s), Some(sign(mag | 1 << pos)));
                    assert_eq!(small(&c), Some(sign(mag & !(1 << pos))));
                }
            }
        }
        4 => {
            let mut rng = Bytes(body.to_vec(), 0);
            if let Ok(Ok(prime)) = bn::is_prime(&a, &mut rng) {
                if let Some(v) = sa {
                    assert_eq!(prime, model_prime(v), "{v}");
                }
            }
        }
        _ => {
            let mut rng = Bytes(body.to_vec(), 0);
            let r = Bn::rand(pos.wrapping_mul(97), &mut rng).expect("under the cap");
            check_forms(&r);
            assert!(r.num_bits() <= u64::try_from(pos.wrapping_mul(97).max(0)).unwrap_or(0));
        }
    }
});
