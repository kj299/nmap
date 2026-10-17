//! `BIGNUM` as the `openssl` module shows it (`nse_openssl.cc:40-277`), over
//! `num-bigint`, with no interpreter in sight: the binding
//! ([`super`]) turns Lua values into these calls, and the fuzz target and
//! Miri reach this file alone.
//!
//! `num-bigint` does the arithmetic; this layer owns everything OpenSSL makes
//! observable (`docs/M6.5-ANALYSIS.md` §4, E2):
//!
//! - **Values.** A sign and a magnitude, never a negative zero: OpenSSL's
//!   `neg` flag is cleared whenever `top` reaches 0 (`bn_correct_top`), and
//!   `BigInt` has no negative zero to begin with.
//! - **Text.** `bn2hex` is uppercase, two digits per byte of the magnitude,
//!   `0` for zero (`BN_bn2hex`); `bn2dec` is decimal; both put `-` first.
//!   `bn2bin` is the magnitude, big-endian, empty for zero; `bn2mpi` is a
//!   4-byte length and the magnitude with a leading zero byte where its top
//!   bit is set, the sign in that top bit. `dec2bn` and `hex2bn` read an
//!   optional `-` and then the longest run of digits, and anything after it
//!   is ignored; no digits at all leave the number 0 (`BN_dec2bn`,
//!   `BN_hex2bn`).
//! - **The silent zeros.** `div` by zero and `mod_exp` modulo zero fail in
//!   OpenSSL, the C ignores the failure, and the results are the zeros
//!   `BN_new` made (`nse_openssl.cc:105,127`). `num-bigint` would panic on
//!   both; they are checked first, as are its other two panics (a remainder
//!   by zero, and a negative exponent, which `mod_exp`'s use of the
//!   magnitude rules out).
//! - **Signs.** `div` truncates: the quotient's sign is the product's and the
//!   remainder's is the dividend's. `mod_exp` reduces the base into
//!   `[0, |m|)` and ignores the signs of `p` and `m`, and gives 0 modulo ±1.
//!   The bit functions act on the magnitude and keep the sign.
//! - **`BN_check_prime`** (`bn_prime.c` at `openssl-3.0.13`): 1 and below
//!   are composite, 2 and 3 prime, other even numbers composite; then trial
//!   division by the first 64 to 2,048 odd primes by size, a hit being prime
//!   only when it is that prime; then Miller-Rabin with random witnesses in
//!   `[2, w-2]`, 64 rounds up to 2,048 bits and 128 above. Fixed witnesses
//!   would be measurably wrong (the oracle calls `318665857834031151167461`
//!   composite). [`Primality`] runs the rounds one at a time, so the binding
//!   can yield between them.
//!
//! **The caps** (`nse-bignum-operand-cap`, §14.3). No value is ever larger
//! than [`CONSTRUCT_BITS`]; `mod_exp` takes no operand over
//! [`MOD_EXP_BITS`], and the primality tests none over [`PRIME_BITS`]. Over a
//! cap, or where the memory budget refuses the bytes, the call is
//! [`Refused`], which the binding raises as the budget's "not enough memory".
//! The C computes up to OpenSSL's own cap of 536,870,848 bits, for minutes
//! to days, and returns 0 above it.

use std::sync::OnceLock;

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};

/// The largest value, in bits, any operation builds or returns: twice the
/// largest DH `p` a TLS peer can send (§14.3).
pub const CONSTRUCT_BITS: u64 = 1_048_576;

/// The largest operand of `mod_exp`, in bits: one call is one native
/// computation that nothing can interrupt, about 2 s at this size (§14.3).
pub const MOD_EXP_BITS: u64 = 16_384;

/// The largest operand of `is_prime` and `is_safe_prime`, in bits: RFC
/// 7919's ffdhe8192, ssh2's group-exchange maximum (§14.3).
pub const PRIME_BITS: u64 = 8_192;

/// Refused: an operand over its cap, or bytes the memory budget will not
/// grant. The binding raises "not enough memory", as the C's allocator does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

/// A source of random bytes ([`super::rand`] in the module; a model in tests
/// and the fuzz target).
pub trait Random {
    /// Fill `buf`, or say that the source failed.
    fn fill(&mut self, buf: &mut [u8]) -> bool;
}

/// The random source failed: the binding raises it, where `BN_check_prime`
/// would return -1 and the C push that as `true` (`nse_openssl.cc:189-199`,
/// `openssl-random-failure-raises`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomFailed;

/// An OpenSSL `BIGNUM`'s value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bn(BigInt);

/// Whether a value of `bits` bits may be built: under [`CONSTRUCT_BITS`],
/// and its bytes granted by the memory budget.
fn fits(bits: u64) -> Result<(), Refused> {
    if bits > CONSTRUCT_BITS {
        return Err(Refused);
    }
    let bytes = usize::try_from(bits.div_ceil(8)).map_err(|_| Refused)?;
    if piccolo::budget::allows(bytes) {
        Ok(())
    } else {
        Err(Refused)
    }
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// The most decimal digits a value under [`CONSTRUCT_BITS`] has: 315,653
/// (`log10 2` = 0.30103).
const MAX_DIGITS: u64 = 315_653;

/// The mask that keeps the low `bits` bits of a number's first byte, where
/// its byte count is `ceil(bits / 8)`: `0xff` for a whole byte.
fn top_mask(bits: u64) -> u8 {
    const MASK: [u8; 8] = [0xff, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f];
    MASK[usize::try_from(bits % 8).unwrap_or(0)]
}

/// The bits of `v`'s magnitude (`BN_num_bits`).
fn bits_of(v: &BigInt) -> u64 {
    v.magnitude().bits()
}

impl Bn {
    /// 0, as `BN_new` makes it.
    #[must_use]
    pub fn zero() -> Bn {
        Bn(BigInt::zero())
    }

    /// `v`, if it fits ([`fits`]).
    ///
    /// # Errors
    /// [`Refused`] over [`CONSTRUCT_BITS`] or the memory budget.
    pub fn new(v: BigInt) -> Result<Bn, Refused> {
        fits(bits_of(&v))?;
        Ok(Bn(v))
    }

    /// The value.
    #[must_use]
    pub fn value(&self) -> &BigInt {
        &self.0
    }

    /// `BN_is_zero`.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// `BN_num_bits`: the bits of the magnitude.
    #[must_use]
    pub fn num_bits(&self) -> u64 {
        bits_of(&self.0)
    }

    /// `BN_num_bytes`.
    #[must_use]
    pub fn num_bytes(&self) -> u64 {
        self.num_bits().div_ceil(8)
    }

    /// What the value holds on the heap, for the memory accounting: its
    /// 64-bit digits.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        usize::try_from(self.num_bits().div_ceil(64).saturating_mul(8)).unwrap_or(usize::MAX)
    }

    // ---- construction ------------------------------------------------------

    /// `BN_bin2bn`: `s` as a big-endian magnitude.
    ///
    /// # Errors
    /// [`Refused`] past the cap.
    pub fn from_bin(s: &[u8]) -> Result<Bn, Refused> {
        let start = s.iter().position(|&b| b != 0).unwrap_or(s.len());
        let sig = &s[start..];
        let bits = match sig.first() {
            None => 0,
            Some(&top) => {
                let len = u64::try_from(sig.len()).map_err(|_| Refused)?;
                len.saturating_sub(1)
                    .saturating_mul(8)
                    .saturating_add(u64::from(u8::BITS.saturating_sub(top.leading_zeros())))
            }
        };
        fits(bits)?;
        Ok(Bn(BigInt::from_bytes_be(Sign::Plus, sig)))
    }

    /// `BN_dec2bn`: an optional `-`, then the longest run of decimal digits
    /// of `s` up to its first NUL (the C reads `luaL_checkstring`).
    ///
    /// # Errors
    /// [`Refused`] past the cap.
    pub fn from_dec(s: &[u8]) -> Result<Bn, Refused> {
        parse_prefix(s, 10)
    }

    /// `BN_hex2bn`: as [`Bn::from_dec`], with hex digits of either case.
    ///
    /// # Errors
    /// [`Refused`] past the cap.
    pub fn from_hex(s: &[u8]) -> Result<Bn, Refused> {
        parse_prefix(s, 16)
    }

    /// `BN_rand(num, bits, -1, 0)` (`nse_openssl.cc:86-89`): uniform in
    /// `[0, 2^bits)`, the top bit free and the bottom bit too. `bits` is the
    /// C's `int`; 0 or less leaves the number 0 (a negative count is an
    /// error the C ignores), as does a failed source.
    ///
    /// # Errors
    /// [`Refused`] past the cap.
    pub fn rand(bits: i32, rng: &mut dyn Random) -> Result<Bn, Refused> {
        let Ok(bits) = u64::try_from(bits) else {
            return Ok(Bn::zero());
        };
        if bits == 0 {
            return Ok(Bn::zero());
        }
        fits(bits)?;
        let len = usize::try_from(bits.div_ceil(8)).map_err(|_| Refused)?;
        let mut buf = Vec::new();
        if !crate::nse::stdlib::reserve(&mut buf, len) {
            return Err(Refused);
        }
        buf.resize(len, 0);
        if !rng.fill(&mut buf) {
            return Ok(Bn::zero());
        }
        buf[0] &= top_mask(bits);
        Ok(Bn(BigInt::from_bytes_be(Sign::Plus, &buf)))
    }

    // ---- text ---------------------------------------------------------------

    /// `BN_bn2bin`: the magnitude, big-endian; empty for 0.
    #[must_use]
    pub fn to_bin(&self) -> Vec<u8> {
        if self.is_zero() {
            Vec::new()
        } else {
            self.0.magnitude().to_bytes_be()
        }
    }

    /// `BN_bn2mpi`: the length in four big-endian bytes, then the magnitude
    /// with a zero byte before it where its top bit is set, and the sign in
    /// the first byte's top bit. 0 is four zero bytes.
    #[must_use]
    pub fn to_mpi(&self) -> Vec<u8> {
        let mut mag = self.to_bin();
        if mag.first().is_some_and(|&b| b & 0x80 != 0) {
            mag.insert(0, 0);
        }
        if self.0.sign() == Sign::Minus {
            if let Some(b) = mag.first_mut() {
                *b |= 0x80;
            }
        }
        let len = u32::try_from(mag.len()).unwrap_or(u32::MAX);
        let mut out = len.to_be_bytes().to_vec();
        out.extend_from_slice(&mag);
        out
    }

    /// `BN_bn2dec`.
    #[must_use]
    pub fn to_dec(&self) -> Vec<u8> {
        self.0.to_str_radix(10).into_bytes()
    }

    /// `BN_bn2hex`: `0` for zero; otherwise `-` if negative, then two
    /// uppercase digits for each byte of the magnitude.
    #[must_use]
    pub fn to_hex(&self) -> Vec<u8> {
        if self.is_zero() {
            return b"0".to_vec();
        }
        let mag = self.0.magnitude().to_bytes_be();
        let mut out = Vec::with_capacity(mag.len().saturating_mul(2).saturating_add(1));
        if self.0.sign() == Sign::Minus {
            out.push(b'-');
        }
        for b in mag {
            out.push(HEX[usize::from(b >> 4)]);
            out.push(HEX[usize::from(b & 0x0f)]);
        }
        out
    }

    // ---- bits ---------------------------------------------------------------

    /// `BN_set_bit(a, pos)`: the bit of the magnitude set, the sign kept. A
    /// negative position changes nothing. `pos` is the C's `int`.
    ///
    /// # Errors
    /// [`Refused`] where the value would pass the cap.
    pub fn set_bit(&mut self, pos: i32) -> Result<(), Refused> {
        let Ok(pos) = u64::try_from(pos) else {
            return Ok(());
        };
        if pos >= self.num_bits() {
            fits(pos.saturating_add(1))?;
        }
        let (sign, mut mag) = std::mem::take(&mut self.0).into_parts();
        mag.set_bit(pos, true);
        let sign = if sign == Sign::Minus {
            Sign::Minus
        } else {
            Sign::Plus
        };
        self.0 = BigInt::from_biguint(sign, mag);
        Ok(())
    }

    /// `BN_clear_bit(a, pos)`: the bit of the magnitude cleared; a negative
    /// position, or one past the value's last word, changes nothing. A value
    /// cleared to 0 loses its sign.
    pub fn clear_bit(&mut self, pos: i32) {
        let Ok(pos) = u64::try_from(pos) else {
            return;
        };
        if pos >= self.num_bits() {
            return;
        }
        let (sign, mut mag) = std::mem::take(&mut self.0).into_parts();
        mag.set_bit(pos, false);
        self.0 = BigInt::from_biguint(sign, mag);
    }

    /// `BN_is_bit_set(a, pos)`: the bit of the magnitude; false for a
    /// negative position.
    #[must_use]
    pub fn is_bit_set(&self, pos: i32) -> bool {
        u64::try_from(pos).is_ok_and(|p| self.0.magnitude().bit(p))
    }

    // ---- arithmetic ---------------------------------------------------------

    /// `BN_add`.
    ///
    /// # Errors
    /// [`Refused`] where the sum passes the cap.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "arbitrary precision: allocates, never overflows"
    )]
    pub fn add(&self, b: &Bn) -> Result<Bn, Refused> {
        Bn::new(&self.0 + &b.0)
    }

    /// `BN_div(dv, rem, a, d)`: truncated division, the remainder taking the
    /// dividend's sign. Division by 0 fails in OpenSSL and the C ignores it:
    /// both results are 0.
    #[must_use]
    pub fn div(&self, d: &Bn) -> (Bn, Bn) {
        if d.is_zero() {
            return (Bn::zero(), Bn::zero());
        }
        let (q, r) = self.0.div_rem(&d.0);
        (Bn(q), Bn(r))
    }

    /// `BN_mod_exp(r, a, p, m)`: `a^|p|` reduced into `[0, |m|)`. Modulo 0
    /// fails in OpenSSL and the C ignores it: the result is 0.
    ///
    /// # Errors
    /// [`Refused`] for any operand over [`MOD_EXP_BITS`].
    pub fn mod_exp(a: &Bn, p: &Bn, m: &Bn) -> Result<Bn, Refused> {
        if [a, p, m].iter().any(|x| x.num_bits() > MOD_EXP_BITS) {
            return Err(Refused);
        }
        if m.is_zero() {
            return Ok(Bn::zero());
        }
        let modulus = m.0.magnitude();
        let base = a.0.mod_floor(&BigInt::from(modulus.clone()));
        let r = base.magnitude().modpow(p.0.magnitude(), modulus);
        Ok(Bn(BigInt::from(r)))
    }

    /// `(p - 1) / 2` as `l_bignum_is_safe_prime` makes it from a prime `p`
    /// (`BN_sub_word`, `BN_div_word`).
    #[must_use]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "arbitrary precision: allocates, never overflows"
    )]
    pub fn sophie_germain(&self) -> Bn {
        Bn((&self.0 - BigInt::one()) / BigInt::from(2u8))
    }
}

/// `BN_dec2bn` and `BN_hex2bn` (`radix` 10 or 16).
fn parse_prefix(s: &[u8], radix: u32) -> Result<Bn, Refused> {
    let s = s.iter().position(|&b| b == 0).map_or(s, |i| &s[..i]);
    let (neg, rest) = match s.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, s),
    };
    let is_digit = |b: &u8| {
        if radix == 10 {
            b.is_ascii_digit()
        } else {
            b.is_ascii_hexdigit()
        }
    };
    let n = rest.iter().take_while(|b| is_digit(b)).count();
    let digits = &rest[..n];
    let sig = &digits[digits.iter().position(|&b| b != b'0').unwrap_or(n)..];
    let Some(&top) = sig.first() else {
        return Ok(Bn::zero());
    };
    let len = u64::try_from(sig.len()).map_err(|_| Refused)?;
    if radix == 16 {
        let top = char::from(top).to_digit(16).unwrap_or(0);
        fits(
            len.saturating_sub(1)
                .saturating_mul(4)
                .saturating_add(u64::from(u32::BITS.saturating_sub(top.leading_zeros()))),
        )?;
    } else if len > MAX_DIGITS {
        // More digits than any value under the cap has (log10 2 = 0.30103).
        return Err(Refused);
    }
    let mag = BigUint::parse_bytes(sig, radix).ok_or(Refused)?;
    let v = BigInt::from_biguint(if neg { Sign::Minus } else { Sign::Plus }, mag);
    Bn::new(v)
}

// ---- primality ----------------------------------------------------------------

/// `NUMPRIMES`: the size of OpenSSL's table of small primes
/// (`bn_prime.h`), 2 to 17,863.
const NUMPRIMES: usize = 2048;

/// The first [`NUMPRIMES`] primes.
fn primes() -> &'static [u32] {
    static PRIMES: OnceLock<Vec<u32>> = OnceLock::new();
    PRIMES.get_or_init(|| {
        let limit = 17_864usize;
        let mut composite = vec![false; limit];
        let mut out = Vec::with_capacity(NUMPRIMES);
        for n in 2..limit {
            if !composite[n] {
                out.push(u32::try_from(n).unwrap_or(u32::MAX));
                let mut m = n.saturating_mul(n);
                while m < limit {
                    composite[m] = true;
                    m = m.saturating_add(n);
                }
            }
        }
        out.truncate(NUMPRIMES);
        out
    })
}

/// `calc_trial_divisions` (`bn_prime.c`): how many of the small primes
/// trial division tries, by size.
fn trial_divisions(bits: u64) -> usize {
    match bits {
        0..=512 => 64,
        513..=1024 => 128,
        1025..=2048 => 384,
        2049..=4096 => 1024,
        _ => NUMPRIMES,
    }
}

/// `bn_mr_min_checks`: Miller-Rabin rounds, by size.
fn rounds(bits: u64) -> u32 {
    if bits > 2048 {
        128
    } else {
        64
    }
}

/// A primality test under way: `BN_check_prime` after trial division, one
/// Miller-Rabin round at a time (`ossl_bn_miller_rabin_is_prime`).
#[derive(Debug, Clone)]
pub struct MillerRabin {
    w: BigUint,
    /// `w - 1`.
    w1: BigUint,
    /// `w - 3`: witnesses are `2 + [0, w - 3)`.
    w3: BigUint,
    /// `w - 1 = 2^a * m`, `m` odd.
    m: BigUint,
    a: u64,
    left: u32,
    done: u32,
}

/// What a primality test knows.
#[derive(Debug, Clone)]
pub enum Primality {
    /// Decided without Miller-Rabin.
    Known(bool),
    /// Miller-Rabin has rounds to run.
    Testing(MillerRabin),
}

/// `BN_check_prime(w)` up to its Miller-Rabin rounds.
///
/// # Errors
/// [`Refused`] over [`PRIME_BITS`].
#[allow(
    clippy::arithmetic_side_effects,
    reason = "arbitrary precision on w >= 5: allocates, never overflows or underflows"
)]
pub fn check_prime(w: &Bn) -> Result<Primality, Refused> {
    let bits = w.num_bits();
    if bits > PRIME_BITS {
        return Err(Refused);
    }
    if w.0 <= BigInt::one() {
        return Ok(Primality::Known(false));
    }
    let mag = w.0.magnitude();
    if mag.is_even() {
        return Ok(Primality::Known(*mag == BigUint::from(2u8)));
    }
    if *mag == BigUint::from(3u8) {
        return Ok(Primality::Known(true));
    }
    // Trial division, from the second prime: 2 is the parity test above.
    for &p in primes().iter().take(trial_divisions(bits)).skip(1) {
        if (mag % p).is_zero() {
            return Ok(Primality::Known(*mag == BigUint::from(p)));
        }
    }
    let w1 = mag - 1u8;
    let a = w1.trailing_zeros().unwrap_or(0);
    Ok(Primality::Testing(MillerRabin {
        m: &w1 >> a,
        w3: mag - 3u8,
        w: mag.clone(),
        w1,
        a,
        left: rounds(bits),
        done: 0,
    }))
}

/// A uniform value in `[0, n)` (`BN_priv_rand_range`), `n > 0`, by
/// rejection over the bits of `n`.
fn below(n: &BigUint, rng: &mut dyn Random) -> Result<BigUint, RandomFailed> {
    let bits = n.bits();
    let len = usize::try_from(bits.div_ceil(8)).map_err(|_| RandomFailed)?;
    let mut buf = vec![0u8; len];
    // Each draw is below n with probability over 1/2.
    for _ in 0..1000 {
        if !rng.fill(&mut buf) {
            return Err(RandomFailed);
        }
        buf[0] &= top_mask(bits);
        let v = BigUint::from_bytes_be(&buf);
        if &v < n {
            return Ok(v);
        }
    }
    Err(RandomFailed)
}

impl MillerRabin {
    /// The size of the number under test, in 64-bit words.
    #[must_use]
    pub fn words(&self) -> u64 {
        self.w.bits().div_ceil(64)
    }

    /// Rounds run so far.
    #[must_use]
    pub fn rounds_done(&self) -> u32 {
        self.done
    }

    /// One round with a random witness: `Some(false)` when it proves `w`
    /// composite, `Some(true)` after the last round, `None` while rounds
    /// remain.
    ///
    /// # Errors
    /// [`RandomFailed`] when no witness could be drawn.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "arbitrary precision modulo w > 0: allocates, never overflows"
    )]
    pub fn round(&mut self, rng: &mut dyn Random) -> Result<Option<bool>, RandomFailed> {
        let b = below(&self.w3, rng)? + 2u8;
        self.done = self.done.saturating_add(1);
        let mut z = b.modpow(&self.m, &self.w);
        let one = BigUint::one();
        if z != one && z != self.w1 {
            let mut passed = false;
            for _ in 1..self.a {
                z = (&z * &z) % &self.w;
                if z == self.w1 {
                    passed = true;
                    break;
                }
                if z == one {
                    return Ok(Some(false));
                }
            }
            if !passed {
                return Ok(Some(false));
            }
        }
        self.left = self.left.saturating_sub(1);
        Ok((self.left == 0).then_some(true))
    }

    /// Every remaining round, at once.
    ///
    /// # Errors
    /// [`RandomFailed`] when no witness could be drawn.
    pub fn finish(&mut self, rng: &mut dyn Random) -> Result<bool, RandomFailed> {
        loop {
            if let Some(v) = self.round(rng)? {
                return Ok(v);
            }
        }
    }
}

/// `BN_check_prime(w)`, every round at once (tests, and the fuzz target).
///
/// # Errors
/// [`Refused`] over [`PRIME_BITS`]; a failed random source is `Ok(Err(_))`.
pub fn is_prime(w: &Bn, rng: &mut dyn Random) -> Result<Result<bool, RandomFailed>, Refused> {
    Ok(match check_prime(w)? {
        Primality::Known(v) => Ok(v),
        Primality::Testing(mut mr) => mr.finish(rng),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic source for the pure tests.
    struct Counter(u64);

    impl Random for Counter {
        fn fill(&mut self, buf: &mut [u8]) -> bool {
            for b in buf {
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *b = self.0.to_be_bytes()[0];
            }
            true
        }
    }

    struct Broken;

    impl Random for Broken {
        fn fill(&mut self, _: &mut [u8]) -> bool {
            false
        }
    }

    fn dec(s: &str) -> Bn {
        Bn::from_dec(s.as_bytes()).unwrap()
    }

    fn s(v: &[u8]) -> String {
        String::from_utf8(v.to_vec()).unwrap()
    }

    #[test]
    fn text_forms_are_openssls() {
        for (v, hex, mpi) in [
            ("0", "0", &b"\0\0\0\0"[..]),
            ("4", "04", b"\0\0\0\x01\x04"),
            ("-31", "-1F", b"\0\0\0\x01\x9f"),
            ("128", "80", b"\0\0\0\x02\0\x80"),
            ("-128", "-80", b"\0\0\0\x02\x80\x80"),
            ("65536", "010000", b"\0\0\0\x03\x01\0\0"),
        ] {
            let b = dec(v);
            assert_eq!(s(&b.to_hex()), hex, "{v}");
            assert_eq!(s(&b.to_dec()), v, "{v}");
            assert_eq!(b.to_mpi(), mpi, "{v}");
        }
        assert!(dec("0").to_bin().is_empty());
        assert_eq!(dec("-258").to_bin(), b"\x01\x02");
        assert_eq!(dec("-258").num_bits(), 9);
        assert_eq!(dec("-258").num_bytes(), 2);
    }

    #[test]
    fn dec2bn_and_hex2bn_read_a_prefix() {
        for (input, want) in [
            ("", "0"),
            ("-", "0"),
            ("+5", "0"),
            (" 5", "0"),
            ("5 ", "5"),
            ("--5", "0"),
            ("00012", "12"),
            ("-0", "0"),
            ("-00", "0"),
            ("12abc", "12"),
            ("1e3", "1"),
            ("1\x002", "1"),
            ("-17", "-17"),
        ] {
            assert_eq!(
                s(&Bn::from_dec(input.as_bytes()).unwrap().to_dec()),
                want,
                "{input:?}"
            );
        }
        for (input, want) in [
            ("ff", "255"),
            ("FF", "255"),
            ("-ff", "-255"),
            ("0x10", "0"),
            ("fG", "15"),
            ("1 2", "1"),
            ("-0", "0"),
        ] {
            assert_eq!(
                s(&Bn::from_hex(input.as_bytes()).unwrap().to_dec()),
                want,
                "{input:?}"
            );
        }
        assert_eq!(s(&Bn::from_bin(b"\0\0\x01\x00").unwrap().to_dec()), "256");
        assert!(Bn::from_bin(b"").unwrap().is_zero());
    }

    #[test]
    fn division_truncates_and_zero_divisors_give_zeros() {
        for (a, d, q, r) in [
            ("7", "2", "3", "1"),
            ("-7", "2", "-3", "-1"),
            ("7", "-2", "-3", "1"),
            ("-7", "-2", "3", "-1"),
            ("-7", "100", "0", "-7"),
            ("5", "0", "0", "0"),
            ("0", "0", "0", "0"),
        ] {
            let (qq, rr) = dec(a).div(&dec(d));
            assert_eq!(
                (s(&qq.to_dec()), s(&rr.to_dec())),
                (q.into(), r.into()),
                "{a}/{d}"
            );
        }
    }

    #[test]
    fn mod_exp_ignores_the_signs_of_p_and_m() {
        for (a, p, m, want) in [
            ("2", "10", "1000", "24"),
            ("2", "-10", "1000", "24"),
            ("2", "10", "-1000", "24"),
            ("-2", "3", "7", "6"),
            ("5", "0", "7", "1"),
            ("5", "0", "1", "0"),
            ("5", "3", "-1", "0"),
            ("5", "3", "0", "0"),
            ("-4", "0", "0", "0"),
        ] {
            let r = Bn::mod_exp(&dec(a), &dec(p), &dec(m)).unwrap();
            assert_eq!(s(&r.to_dec()), want, "{a}^{p} mod {m}");
        }
    }

    #[test]
    fn bits_act_on_the_magnitude() {
        let mut v = dec("-5");
        v.set_bit(1).unwrap();
        assert_eq!(s(&v.to_dec()), "-7");
        v.clear_bit(0);
        v.clear_bit(2);
        assert_eq!(s(&v.to_dec()), "-2");
        v.clear_bit(1);
        assert_eq!(s(&v.to_hex()), "0");
        assert_eq!(v.to_mpi(), b"\0\0\0\0");
        v.set_bit(-1).unwrap();
        v.clear_bit(64);
        assert!(v.is_zero());
        v.set_bit(70).unwrap();
        assert!(v.is_bit_set(70) && !v.is_bit_set(-1) && !v.is_bit_set(69));
        assert_eq!(v.num_bits(), 71);
    }

    #[test]
    fn rand_is_bounded_and_its_top_bit_is_free() {
        let mut rng = Counter(1);
        assert!(Bn::rand(0, &mut rng).unwrap().is_zero());
        assert!(Bn::rand(-1, &mut rng).unwrap().is_zero());
        assert!(Bn::rand(9, &mut Broken).unwrap().is_zero());
        let (mut shorter, mut full) = (false, false);
        for _ in 0..64 {
            let b = Bn::rand(9, &mut rng).unwrap();
            assert!(b.num_bits() <= 9 && b.0.sign() != Sign::Minus);
            shorter |= b.num_bits() < 9;
            full |= b.num_bits() == 9;
        }
        assert!(shorter && full);
    }

    /// `nse-bignum-operand-cap`: every cap, at and one past it.
    #[test]
    fn the_caps_hold_at_their_edges() {
        let at = |bits: u64| {
            let mut v = Bn::zero();
            v.set_bit(i32::try_from(bits - 1).unwrap()).unwrap();
            v
        };
        let big = at(CONSTRUCT_BITS);
        assert_eq!(big.num_bits(), CONSTRUCT_BITS);
        let mut over = big.clone();
        assert_eq!(
            over.set_bit(i32::try_from(CONSTRUCT_BITS).unwrap()),
            Err(Refused)
        );
        assert_eq!(big.add(&big), Err(Refused));
        let bytes = vec![0xffu8; usize::try_from(CONSTRUCT_BITS / 8).unwrap()];
        assert!(Bn::from_bin(&bytes).is_ok());
        let mut more = vec![0u8; 3];
        more.extend_from_slice(&bytes);
        assert!(
            Bn::from_bin(&more).is_ok(),
            "leading zero bytes are not counted"
        );
        more.push(1);
        assert_eq!(Bn::from_bin(&more), Err(Refused));
        let hex = vec![b'f'; usize::try_from(CONSTRUCT_BITS / 4).unwrap()];
        assert!(Bn::from_hex(&hex).is_ok());
        let mut hex1 = b"1".to_vec();
        hex1.extend_from_slice(&hex);
        assert_eq!(Bn::from_hex(&hex1), Err(Refused));
        assert_eq!(
            Bn::rand(i32::try_from(CONSTRUCT_BITS + 1).unwrap(), &mut Counter(3)),
            Err(Refused)
        );
        let m = at(MOD_EXP_BITS);
        assert!(Bn::mod_exp(&m, &m, &m).is_ok());
        let m1 = at(MOD_EXP_BITS + 1);
        let two = dec("2");
        assert_eq!(Bn::mod_exp(&m1, &two, &two), Err(Refused));
        assert_eq!(Bn::mod_exp(&two, &m1, &two), Err(Refused));
        assert_eq!(Bn::mod_exp(&two, &two, &m1), Err(Refused));
        assert!(check_prime(&at(PRIME_BITS)).is_ok());
        assert!(check_prime(&at(PRIME_BITS + 1)).is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // tens of seconds of modpow under Miri
    fn the_decimal_cap_is_exact() {
        // 2^CONSTRUCT_BITS - 1 has 315,653 digits and fits; ten times it does
        // not.
        let v = Bn::new((BigInt::one() << CONSTRUCT_BITS) - 1u8).unwrap();
        let digits = v.to_dec();
        assert_eq!(digits.len(), 315_653);
        assert_eq!(Bn::from_dec(&digits).unwrap(), v);
        let mut ten = digits.clone();
        ten.push(b'0');
        assert_eq!(Bn::from_dec(&ten), Err(Refused));
    }

    /// `BN_check_prime` on the small numbers and the classic liars: a
    /// Carmichael number, strong pseudoprimes to many fixed bases, and the
    /// value fixed witnesses get wrong.
    #[test]
    fn primality_agrees_with_trial_division_and_beats_the_liars() {
        let mut rng = Counter(9);
        let small = |n: u64| {
            n >= 2
                && (2..n)
                    .take_while(|d| d.saturating_mul(*d) <= n)
                    .all(|d| !n.is_multiple_of(d))
        };
        for n in -10i64..400 {
            let got = is_prime(&dec(&n.to_string()), &mut rng).unwrap().unwrap();
            assert_eq!(got, u64::try_from(n).is_ok_and(small), "{n}");
        }
        for liar in [
            "561",
            "3215031751",
            "3825123056546413051",
            "318665857834031151167461",
            "3317044064679887385961981",
        ] {
            assert!(!is_prime(&dec(liar), &mut rng).unwrap().unwrap(), "{liar}");
        }
        for p in [
            "2305843009213693951",
            "170141183460469231731687303715884105727",
        ] {
            assert!(is_prime(&dec(p), &mut rng).unwrap().unwrap(), "{p}");
        }
    }

    /// The seeded unit test of §11 row b: a prime runs every round, 64 up to
    /// 2,048 bits and 128 above, each with its own witness; a composite that
    /// survives trial division stops at its first failing round; and a
    /// failed source is reported, never answered.
    #[test]
    fn miller_rabin_runs_the_rounds_openssl_runs() {
        let mut rng = Counter(42);
        let count = |v: &Bn, rng: &mut Counter| match check_prime(v).unwrap() {
            Primality::Known(_) => panic!("decided by trial division"),
            Primality::Testing(mut mr) => {
                let verdict = mr.finish(rng).unwrap();
                (verdict, mr.rounds_done())
            }
        };
        // 2^127 - 1: 127 bits.
        let m127 = dec("170141183460469231731687303715884105727");
        assert_eq!(count(&m127, &mut rng), (true, 64));
        // A strong pseudoprime to every base up to 37 still falls at once to
        // a random witness, nearly always.
        let spsp = dec("318665857834031151167461");
        let (v, n) = count(&spsp, &mut rng);
        assert!(!v && n <= 2, "{n}");
        // Over 2,048 bits: 128 rounds (2^2203 - 1, a Mersenne prime).
        if !cfg!(miri) {
            let mut m2203 = Bn::zero();
            for i in 0..2203 {
                m2203.set_bit(i).unwrap();
            }
            assert_eq!(count(&m2203, &mut rng), (true, 128));
        }
        let Primality::Testing(mut mr) = check_prime(&m127).unwrap() else {
            panic!("trial division")
        };
        assert_eq!(mr.round(&mut Broken), Err(RandomFailed));
    }

    #[test]
    fn trial_division_counts_follow_the_size() {
        assert_eq!(primes().len(), NUMPRIMES);
        assert_eq!(primes()[NUMPRIMES - 1], 17_863);
        assert_eq!(trial_divisions(512), 64);
        assert_eq!(trial_divisions(513), 128);
        assert_eq!(trial_divisions(2048), 384);
        assert_eq!(trial_divisions(4096), 1024);
        assert_eq!(trial_divisions(4097), NUMPRIMES);
        // A prime among the divisors tried is found by trial division: up
        // to 512 bits, the 64th prime, 311.
        assert!(matches!(
            check_prime(&dec("311")).unwrap(),
            Primality::Known(true)
        ));
        assert!(matches!(
            check_prime(&dec("933")).unwrap(),
            Primality::Known(false)
        ));
        // The next primes go to Miller-Rabin, as does 17,863 at 15 bits.
        assert!(matches!(
            check_prime(&dec("313")).unwrap(),
            Primality::Testing(_)
        ));
        assert!(matches!(
            check_prime(&dec("17863")).unwrap(),
            Primality::Testing(_)
        ));
    }
}
