// Confirm num-bigint 0.4 panic behaviour with catch_unwind.
use num_bigint::{BigUint, BigInt};
use std::panic;

fn probe(name: &str, f: impl FnOnce() + panic::UnwindSafe) {
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {})); // silence the default panic message
    let r = panic::catch_unwind(f);
    panic::set_hook(prev);
    match r {
        Ok(()) => println!("{}: NO PANIC (returned normally)", name),
        Err(_) => println!("{}: PANIC", name),
    }
}

fn main() {
    // 1. division by zero
    probe("BigUint / 0", || {
        let a = BigUint::from(123456789u64);
        let z = BigUint::from(0u32);
        let _ = a / z;
    });
    probe("BigUint % 0", || {
        let a = BigUint::from(123456789u64);
        let z = BigUint::from(0u32);
        let _ = a % z;
    });
    // 2. modpow with modulus 0
    probe("BigUint::modpow(.., modulus=0)", || {
        let a = BigUint::from(7u32);
        let e = BigUint::from(13u32);
        let m = BigUint::from(0u32);
        let _ = a.modpow(&e, &m);
    });
    // 3. negative exponent via BigInt::modpow
    probe("BigInt::modpow(negative exponent, odd modulus)", || {
        let a = BigInt::from(7);
        let e = BigInt::from(-5);         // negative exponent
        let m = BigInt::from(13);
        let r = a.modpow(&e, &m);
        // print so the compiler cannot elide; shows it if it returns
        println!("    -> returned {}", r);
    });
    probe("BigInt::modpow(negative exponent, non-invertible modulus)", || {
        let a = BigInt::from(6);          // gcd(6,9)=3, no inverse
        let e = BigInt::from(-1);
        let m = BigInt::from(9);
        let r = a.modpow(&e, &m);
        println!("    -> returned {}", r);
    });
}
