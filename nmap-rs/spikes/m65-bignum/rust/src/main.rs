// nmap bignum measurement spike - Rust side (num-bigint 0.4)
// Usage: bnbench <op> <bits> [reps]
// ops: modpow_full modpow_dh modpow_e17 to_dec from_dec trialdiv miller_rabin
// Random operands from an xorshift64 PRNG (no extra crates).
// Prints: op bits rep_ms... median median_ms
use num_bigint::{BigUint, BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use std::time::Instant;

struct Xorshift(u64);
impl Xorshift {
    fn new(seed: u64) -> Self { Xorshift(seed | 1) }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        self.0 = x; x
    }
    fn next_u32(&mut self) -> u32 { (self.next_u64() >> 11) as u32 }
}

// Random BigUint of exactly `bits` bits (top bit set). `odd` forces bit 0.
fn rand_biguint(rng: &mut Xorshift, bits: usize, odd: bool) -> BigUint {
    let ndig = (bits + 31) / 32;
    let mut digits = vec![0u32; ndig];
    for d in digits.iter_mut() { *d = rng.next_u32(); }
    // set top bit within the requested width
    let top_word = (bits - 1) / 32;
    let top_bit = (bits - 1) % 32;
    // mask off any bits above `bits`
    let hi_mask = if top_bit == 31 { 0xffff_ffffu32 } else { (1u32 << (top_bit + 1)) - 1 };
    digits[top_word] &= hi_mask;
    digits[top_word] |= 1u32 << top_bit;
    for d in digits.iter_mut().skip(top_word + 1) { *d = 0; }
    if odd { digits[0] |= 1; }
    BigUint::new(digits)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

// first n primes via simple sieve
fn first_primes(n: usize) -> Vec<u64> {
    let mut primes = Vec::with_capacity(n);
    let mut cand = 2u64;
    while primes.len() < n {
        let mut is_p = true;
        for &p in &primes {
            if p * p > cand { break; }
            if cand % p == 0 { is_p = false; break; }
        }
        if is_p { primes.push(cand); }
        cand += 1;
    }
    primes
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 { eprintln!("usage: bnbench op bits [reps]"); std::process::exit(2); }
    let op = args[1].as_str();
    let bits: usize = args[2].parse().unwrap();
    let reps: usize = if args.len() > 3 { args[3].parse().unwrap() } else { 3 };
    let mut rng = Xorshift::new(0x9e3779b97f4a7c15 ^ bits as u64);

    let mut times = Vec::new();
    for _ in 0..reps {
        let ms = match op {
            "modpow_full" => {
                let a = rand_biguint(&mut rng, bits, false);
                let e = rand_biguint(&mut rng, bits, false);
                let m = rand_biguint(&mut rng, bits, true);
                let t = Instant::now();
                let _ = a.modpow(&e, &m);
                t.elapsed().as_secs_f64() * 1000.0
            }
            "modpow_dh" => {
                let a = rand_biguint(&mut rng, bits, false);
                let e = rand_biguint(&mut rng, 2048, false);
                let m = rand_biguint(&mut rng, bits, true);
                let t = Instant::now();
                let _ = a.modpow(&e, &m);
                t.elapsed().as_secs_f64() * 1000.0
            }
            "modpow_e17" => {
                let a = rand_biguint(&mut rng, bits, false);
                let e = BigUint::from(65537u32);
                let m = rand_biguint(&mut rng, bits, true);
                let t = Instant::now();
                let _ = a.modpow(&e, &m);
                t.elapsed().as_secs_f64() * 1000.0
            }
            "to_dec" => {
                let a = rand_biguint(&mut rng, bits, false);
                let t = Instant::now();
                let _ = a.to_str_radix(10);
                t.elapsed().as_secs_f64() * 1000.0
            }
            "from_dec" => {
                let a = rand_biguint(&mut rng, bits, false);
                let s = a.to_str_radix(10);
                let bytes = s.as_bytes();
                let t = Instant::now();
                let _ = BigUint::parse_bytes(bytes, 10).unwrap();
                t.elapsed().as_secs_f64() * 1000.0
            }
            "trialdiv" => {
                let primes = first_primes(2048);
                let w = rand_biguint(&mut rng, bits, true);
                let t = Instant::now();
                let mut acc = 0u64;
                for &p in primes.iter().skip(1) {
                    let r = (&w % BigUint::from(p)).to_u64_digits();
                    acc ^= *r.get(0).unwrap_or(&0);
                }
                std::hint::black_box(acc);
                t.elapsed().as_secs_f64() * 1000.0
            }
            // Full BN_check_prime-shaped test: trial division by first 2048
            // primes, then `rounds` Miller-Rabin rounds. Timed end to end on
            // the number provided via env BN_HEX (hex) or a random odd number.
            "miller_rabin" => {
                let w = match std::env::var("BN_HEX") {
                    Ok(h) => BigUint::parse_bytes(h.trim().as_bytes(), 16).unwrap(),
                    Err(_) => rand_biguint(&mut rng, bits, true),
                };
                let rounds = if bits > 2048 { 128usize } else { 64 };
                let t = Instant::now();
                let r = is_probable_prime(&w, rounds, &mut rng);
                let ms = t.elapsed().as_secs_f64() * 1000.0;
                eprintln!("miller_rabin bits={} rounds={} result={}", bits, rounds, r);
                ms
            }
            _ => { eprintln!("unknown op {}", op); std::process::exit(2); }
        };
        times.push(ms);
    }
    let med = median(times.clone());
    print!("{} {}", op, bits);
    for t in &times { print!(" {:.3}", t); }
    print!(" median {:.3}", med);
    let hwm = std::fs::read_to_string("/proc/self/status").ok()
        .and_then(|st| st.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.trim().to_string()))
        .unwrap_or_default();
    println!(" {}", hwm);
}

fn is_probable_prime(w: &BigUint, rounds: usize, rng: &mut Xorshift) -> bool {
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    if *w <= one { return false; }
    if w.is_even() { return *w == two; }
    // trial division by first 2048 primes
    for &p in first_primes(2048).iter().skip(1) {
        let bp = BigUint::from(p);
        if *w == bp { return true; }
        if (w % &bp).is_zero() { return false; }
    }
    // write w-1 = 2^s * d
    let w_minus_1 = w - &one;
    let mut d = w_minus_1.clone();
    let mut s = 0u32;
    while d.is_even() { d >>= 1; s += 1; }
    let bits = w.bits() as usize;
    'outer: for _ in 0..rounds {
        // random witness a in [2, w-2]
        let a = {
            let mut cand = rand_biguint(rng, bits, false) % (w - &two);
            if cand < two { cand = two.clone(); }
            cand
        };
        let mut x = a.modpow(&d, w);
        if x == one || x == w_minus_1 { continue; }
        for _ in 0..(s - 1) {
            x = x.modpow(&two, w);
            if x == w_minus_1 { continue 'outer; }
        }
        return false;
    }
    true
}

// keep BigInt/Sign imported for the panic companion binary; silence warnings here
#[allow(dead_code)]
fn _unused() { let _ = BigInt::from_biguint(Sign::Plus, BigUint::zero()); }
