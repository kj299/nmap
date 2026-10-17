# NSE `openssl` bignum operand-size spike: OpenSSL 3.0.13 (C) vs num-bigint 0.4.8 (Rust)

All sources, binaries and raw outputs live under
`$SCRATCH/` (called `$SCRATCH` below).
Nothing under `/home/user/nmap` was touched. `$SCRATCH/target` (cargo build dir) was deleted after the runs; sources kept.

## (a) Environment

| item | value |
|---|---|
| CPU | Intel(R) Xeon(R) Processor @ 2.10GHz, 4 logical CPUs (avx2, avx512f, bmi2, adx), 16 GB RAM, no swap |
| gcc | 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), `-O2`, linked `-lcrypto` |
| OpenSSL | 3.0.13 30 Jan 2024 (library and headers; same build nmap 7.94SVN links) |
| rustc / cargo | 1.88.0 (6b00bc388 2025-06-23) via `cargo +1.88`, `--release` (opt-level 3), `--offline` |
| num-bigint | 0.4.8 (num-integer 0.1.47, num-traits 0.2.19) from the local registry cache; no `rand` feature |
| nmap | 7.94SVN at /usr/bin/nmap, "Compiled with: liblua-5.4.6 openssl-3.0.13" |
| timing | C: `clock_gettime(CLOCK_MONOTONIC)`; Rust: `std::time::Instant`. 3 repetitions, median reported, except where marked "1 rep". Peak RSS: C `getrusage(RUSAGE_SELF).ru_maxrss`, Rust `/proc/self/status VmHWM` (`/usr/bin/time` is not installed on this machine). |
| PRNG | C: `BN_rand` (top bit set, modulus forced odd). Rust: xorshift64 seeded from the bit size, top bit set, modulus forced odd. |

Caveat on contention: the machine has 4 cores and, to fit the time budget, up to 4-5 single-threaded runs were in flight at once during the large-size runs. Where a result looked contention-inflated it was re-run alone and the solo figure is the one reported (noted inline). Small-size medians (<= 65,536 bits) were stable to within a few percent across runs.

Per-measurement wall-clock cap: 120 s (`timeout 120`), per the coordinator's instruction; the first C `modexp_e17 8388608` ran under an earlier 300 s cap and is reported as ">300 s". Anything over the cap is reported as such and extrapolated with the power-law exponent fitted from the two largest measured sizes (exponent stated).

## Reference facts from source (cited)

* OpenSSL cap: `crypto/bn/bn_lib.c:270` (openssl-3.0.13), `bn_expand_internal`: `if (words > (INT_MAX / (4 * BN_BITS2))) { ERR_raise(ERR_LIB_BN, BN_R_BIGNUM_TOO_LONG); return NULL; }`. With `BN_BITS2 = 64`: max 8,388,607 words = 536,870,848 bits = 67,108,856 bytes.
* `BN_check_prime` (`bn_prime.c:255-258`) calls `ossl_bn_check_prime(p, 0, ctx, 1, cb)` (checks=0 -> minimum rounds, trial division on). `bn_is_prime_int` (`bn_prime.c:266-337`): trial division over the first `calc_trial_divisions(bits)` primes (`bn_prime.c:74-85`: 64 for <=512 bits, 128 <=1024, 384 <=2048, 1024 <=4096, else `NUMPRIMES` = 2048), then `ossl_bn_miller_rabin_is_prime` with random witnesses. Rounds: `bn_mr_min_checks` (`bn_prime.c:94-99`): **64 rounds if bits <= 2048, 128 rounds if bits > 2048**.
* nmap `l_bignum_bin2bn` (`nse_openssl.cc:55-62`): `BN_new()` then `BN_bin2bn(s, len, num)` with the return value ignored, so an over-cap input leaves the zero bignum.
* `l_bignum_mod_exp` (`:88-98`): plain `BN_mod_exp` (no `BN_FLG_CONSTTIME`). `l_bignum_is_safe_prime` (`:176-200`): `BN_check_prime(p)` then, if prime, `BN_check_prime((p-1)/2)`.

## (b) Timing tables (ms, median of 3 unless noted)

Sizes are bits of every N-bit operand. "ratio" = Rust / C.

### 1. `mod_exp(a, e, m)`, a, e, m all N bits, m odd (= one Miller-Rabin round)

| N bits | C `BN_mod_exp` | Rust `BigUint::modpow` | ratio |
|---|---|---|---|
| 4,096 | 15.85 | (not run; derived from 4096-bit prime check: 6973/128 = 54.5) | 3.4 |
| 8,192 | 119.4 | 333.6 | 2.8 |
| 16,384 | 965.6 | 2,152.7 | 2.2 |
| 65,536 | 96,448 (1 rep) | >120 s; extrapolated ~91 s (exp 2.69) | ~0.9 (unverified) |
| 524,280 | >120 s; extrapolated 4.9e4-9.2e4 s = 14-26 h (exp 3.0-3.3) | >120 s; extrapolated ~2.5e4 s = 6.9 h (exp 2.69) | - |
| 1,048,576 | >120 s; extrapolated 30-250 h | >120 s; extrapolated ~45 h | - |
| 8,388,608 | >120 s; extrapolated 1.6e4-2.7e4 h | >120 s; extrapolated ~1.2e4 h | - |

Fitted exponents. C: 4096->8192 2.91, 8192->16384 3.02, 16384->65536 3.32 (steepening: OpenSSL's Karatsuba only, no Toom). Rust: 8192->16384 2.69 (num-bigint 0.4 has Karatsuba+Toom-3 so its exponent is lower; the projected crossover near 65 k bits was not verified because the Rust run exceeded 120 s).

### 2. DH shape: 2,048-bit exponent, N-bit base and modulus; and e = 65537

| N bits | C 2048-bit e | Rust 2048-bit e | ratio | C e=65537 | Rust e=65537 | ratio |
|---|---|---|---|---|---|---|
| 8,192 | 30.19 | 69.35 | 2.3 | 0.365 | 2.656 | 7.3 |
| 16,384 | 120.7 | 264.1 | 2.2 | 1.170 | 11.58 | 9.9 |
| 65,536 | 3,069.5 | 4,287.7 | 1.4 | 26.86 | 192.4 | 7.2 |
| 524,280 | >120 s; extrap. 200-390 s (exp 2.0-2.33) | >120 s; extrap. ~274 s (exp 2.0) | - | 1,777 | 12,270 | 6.9 |
| 1,048,576 | >120 s; extrap. 400-2,000 s | >120 s; extrap. ~1,100 s | - | 6,637 | 42,706 (1 rep, solo re-run; first attempt under contention hit 120 s) | 6.4 |
| 8,388,608 | >120 s; extrap. 7-70 h | >120 s; extrap. ~19 h | - | >300 s (killed at 300 s); extrap. 350-430 s (exp 1.9-2.0) | >120 s; extrap. ~3,100 s = 52 min (exp 2.0) | - |

Exponents: C 2048-bit-e 2.0 (8k->16k), 2.33 (16k->64k); Rust 1.93, 2.01. C e=65537: 1.68, 2.26, 2.02, 1.90; Rust: 2.12, 2.03, 2.0, 1.8.

### 3. `is_prime`

Typical case (random odd N-bit input). Trial division cost is the floor; by Mertens' theorem ~11.5 % of random odd numbers have no factor <= 17,863 (the 2,048th prime) and then pay one Miller-Rabin round = table 1.

| N bits | C trial division (2,047 `BN_mod_word`) | Rust trial division (2,047 `%` by small BigUint) | ratio |
|---|---|---|---|
| 8,192 | 3.20 | 1.38 | 0.43 |
| 16,384 | 6.55 | 2.82 | 0.43 |
| 65,536 | 27.15 | 11.74 | 0.43 |
| 524,280 | 216.3 | 94.3 | 0.44 |
| 1,048,576 | 433.3 | 188.7 | 0.44 |
| 8,388,608 | 3,503.6 | 1,535.5 | 0.44 |

(Linear in N. Rust's MR loop on random odd 8,192- and 16,384-bit inputs: 0.30 ms, i.e. trial division rejected both samples before any modpow.)

Worst case (input is prime: trial division survives, all rounds run) = rounds x table 1; rounds = 64 for <= 2,048 bits, 128 above.

| N bits | C derived (128 x modexp) | C measured `BN_check_prime` on a real prime | Rust derived (128 x modpow) | Rust measured MR loop on a real prime |
|---|---|---|---|---|
| 4,096 | 2,029 | **1,965.7** (prime from `BN_generate_prime_ex`, gen 4.9 s) | 6,976 | **6,973** (prime from `openssl prime -generate -bits 4096`) |
| 8,192 | 15,280 (15.3 s) | not measured: `BN_generate_prime_ex(8192)` did not finish inside the 120 s cap | 42,700 (42.7 s) | not measured (no cheap 8192-bit prime) |
| 16,384 | 123,600 (124 s) | - | 275,500 (276 s) | - |
| 65,536 | 1.23e7 (3.4 h) | - | ~1.2e7 (3.2 h, extrapolated) | - |
| 524,280 | 14-26 h x 128 = 75-140 days | - | ~37 days | - |

The 4,096-bit direct measurement agrees with the derivation within 3 % (C) and 0.1 % (Rust), so the derived rows are trustworthy.

### 4. `is_safe_prime` (derived)

= `is_prime(p)` + `is_prime((p-1)/2)`. For a composite p: same as the typical `is_prime` row (3). For a prime p (whether or not (p-1)/2 is prime, since (p-1)/2 usually fails on its first MR round): worst case 2 x the worst-case row, best case 1 x worst + 1 round. Worst-case values: C 4,096: ~3.9 s; 8,192: ~31 s; 16,384: ~247 s; 65,536: ~6.9 h. Rust 4,096: ~14 s; 8,192: ~85 s; 16,384: ~551 s; 65,536: ~6.5 h.

### 5. `bn2dec` / `dec2bn`

| N bits (decimal digits) | C `BN_bn2dec` | Rust `to_str_radix(10)` | ratio | C `BN_dec2bn` | Rust `parse_bytes(..,10)` | ratio |
|---|---|---|---|---|---|---|
| 8,192 (2,466) | 0.079 | 0.044 | 0.56 | 0.017 | 0.010 | 0.6 |
| 16,384 (4,933) | 0.274 | 0.114 | 0.42 | 0.043 | 0.031 | 0.7 |
| 65,536 (19,729) | 3.79 | 0.756 | 0.20 | 0.466 | 0.391 | 0.84 |
| 524,280 (157,824) | 232.3 | 19.03 | 0.082 | 26.26 | 24.81 | 0.94 |
| 1,048,576 (315,653) | 944.3 | 48.87 | 0.052 | 102.8 | 98.82 | 0.96 |
| 8,388,608 (2,525,223) | **60,009** (1 rep, solo; first attempt under contention exceeded 120 s) | 1,146 (1 rep) | 0.019 | 6,705 | 6,563 (1 rep) | 0.98 |

C `BN_bn2dec` is quadratic (exponent 2.02 between the three largest sizes); the Rust radix conversion is sub-quadratic (exponent 1.5). Both `dec2bn`s are quadratic (exponent 2.0).

## (c) Memory (peak RSS of the whole process; baseline C ~5.6 MB with libcrypto, Rust ~2.4 MB)

| case | C maxrss | Rust VmHWM |
|---|---|---|
| bn2dec 524,280 bits | 5,872 kB | 3,952 kB |
| bn2dec 8,388,608 bits | 11,876 kB | 19,644 kB |
| dec2bn 524,280 bits | 6,000 kB | 4,156 kB |
| dec2bn 8,388,608 bits | 12,008 kB | 19,840 kB |
| modexp e=65537 1,048,576 bits | - | 6,436 kB |

Memory is not the limiting resource at any size tested: an 8.4 M-bit number is 1 MiB, its decimal string 2.4 MiB. At the OpenSSL cap (67 MB operand) the nmap 7.94 run below completed two bin2bn + bn2hex round trips in 1.96 s total.

## (d) The cap

C probe (`$SCRATCH/c/cap.c`, zero-filled buffer with a 0xff first byte, `BN_new()` then `BN_bin2bn` exactly like nmap):

```
len=67108856  bin2bn_ret=non-NULL  bits_in_num=536870848  is_zero=no  err=(none)
len=67108857  bin2bn_ret=NULL      bits_in_num=0          is_zero=yes err=error:01800072:bignum routines::bignum too long
```

nmap 7.94SVN, prerule script `$SCRATCH/nse/bncap.nse` run as `nmap --datadir /home/user/nmap --script $SCRATCH/nse/bncap.nse -sn -n -Pn` (rc 0, 1.96 s wall):

```
| len=67108856  bn2hex[1..16]="FFFFFFFFFFFFFFFF"  #hex=134217712  -> nonzero
|_len=67108857  bn2hex[1..16]="0"                 #hex=1          -> ZERO
```

So 7.94's visible behaviour is exactly as read from source: 67,108,856 bytes is accepted (536,870,848 bits); one byte more silently yields the bignum 0 (no Lua error, no log line).

## (e) num-bigint 0.4.8 panics (`$SCRATCH/rust/src/bin/panics.rs`, each under `catch_unwind`)

```
BigUint / 0: PANIC
BigUint % 0: PANIC
BigUint::modpow(.., modulus=0): PANIC
BigInt::modpow(negative exponent, odd modulus): PANIC
BigInt::modpow(negative exponent, non-invertible modulus): PANIC
```

`BigInt::modpow` does not accept a negative exponent at all (panics before considering invertibility). OpenSSL by contrast returns 0/error for `BN_mod_exp` with m = 0 and `BN_div` by zero; the port's wrappers must pre-check `m == 0`, divisor `== 0` and exponent sign before calling into num-bigint.

## (f) Recommendation

### Where each operation crosses 1 s / 10 s / 60 s / 600 s (bits; interpolated/extrapolated on the fitted exponents above; values beyond the largest measured size are projections)

| operation | impl | 1 s | 10 s | 60 s | 600 s |
|---|---|---|---|---|---|
| mod_exp, N-bit exponent (= 1 MR round) | C | ~16.6 k | ~33 k | ~57 k | ~114 k |
| | Rust | ~12.3 k | ~29 k | ~57 k | ~133 k |
| is_prime worst case (prime input, 128 rounds) | C | ~3.2 k | ~7.1 k | ~12.9 k | ~26 k |
| | Rust | ~2.05 k (the 64->128-round step at 2,048 bits) | ~4.7 k | ~9.3 k | ~22 k |
| is_safe_prime worst case (2 x above) | C | ~2.6 k | ~5.9 k | ~10.7 k | ~21 k |
| | Rust | ~2.05 k | ~4.0 k | ~7.6 k | ~17 k |
| mod_exp, 2048-bit exponent (DH) | C | ~41 k | ~109 k | ~235 k | ~630 k |
| | Rust | ~32 k | ~100 k | ~245 k | ~775 k |
| mod_exp, e = 65537 | C | ~390 k | ~1.3 M | ~3.2 M | ~10 M |
| | Rust | ~150 k | ~470 k | ~1.2 M | ~3.7 M |
| bn2dec | C | ~1.08 M | ~3.4 M | ~8.2 M | ~26 M |
| | Rust | ~7.5 M | ~35 M | >100 M | - |
| dec2bn | C / Rust | ~3.3 M | ~10 M | ~25 M | ~79 M |
| trial division (is_prime floor) | C / Rust | ~2.4 M / ~5.5 M | ~24 M / ~55 M | ~144 M / ~330 M | ~860 M / >cap |

At OpenSSL's own cap (536,870,848 bits) every arithmetic operation is far past the watchdog in both implementations: `mod_exp` with e = 65537 is ~19 days in C (quadratic from the measured 6.6 s at 1 M bits), bn2dec ~3 days in C, dec2bn ~7.6 h, and a single Miller-Rabin round (hence `is_prime` on anything that survives trial division, ~11 % of random odd inputs) is on the order of years. Only `bin2bn`/`bn2bin`/`bn2hex`/`hex2bn`/`add`/`num_bits` stay in seconds at the cap.

### Mirroring OpenSSL's cap and relying on pre-emption

Not viable as the only defence. A `BigUint::modpow` (or `BN_mod_exp`) call is one native call with no cancellation point; the 10-minute stall watchdog can at best notice the stall after 600 s and cannot unwind the computation, so the thread keeps burning CPU for hours-to-days (the same exposure nmap 7.94 has today, which is "one `BN_mod_exp` in C" with no watchdog at all). Mirroring the cap only makes sense for the cheap, linear functions.

### Caps that keep every single operation under 600 s with margin

Per-operation caps, chosen from the Rust column (the slower one for arithmetic) and the C column (the slower one for bn2dec), each with roughly 5x headroom under the watchdog:

| function(s) | cap (bits) | worst single call at the cap, Rust / C |
|---|---|---|
| `is_prime`, `is_safe_prime` | **8,192** | ~85 s / ~31 s (safe-prime on a 8,192-bit safe prime; is_prime alone 43 s / 15 s). This is the largest standardised DH/RSA group size (RFC 7919 ffdhe8192, ssh2 group-exchange max 8,192), so nothing legitimate is lost. 16,384 would give ~551 s / ~247 s - too close to the watchdog. |
| `mod_exp` (all three operands) | **16,384** | ~2.2 s / ~1.0 s with a full-size exponent. Covers every real DH/RSA size with 2x headroom; with the TLS wire maximum (524,280 bits) a 2,048-bit-exponent call would already be ~274 s / 200-390 s and a full-exponent call ~7 h / 14-26 h. |
| `bn2dec`, `dec2bn`, `bn2hex`, `hex2bn`, `bin2bn`, `bn2bin`, `add`, `div`, `num_bits`, bit ops | **1,048,576** (128 KiB) | bn2dec ~0.05 s / ~0.94 s; dec2bn ~0.1 s / ~0.1 s; peak RSS < 20 MB. This is 2x the TLS 2-byte-length maximum (524,280 bits), so `ssl-dh-params`-style scripts can still convert whatever a TLS peer sends; an ssh2 group-exchange `p` larger than 128 KiB (which the C code would accept up to 64 MiB) gets rejected instead of silently zeroed. If the port prefers one number, 1,048,576 bits as the construction cap plus the two arithmetic caps above is the minimal set. |

Behaviour at the cap: the port should raise a Lua error (or return nil + message) rather than copy 7.94's silent zero, since a zero `p` then flows into `mod_exp`/`div` and in num-bigint a zero modulus/divisor is a panic (section e). Document the divergence from 7.94 in the ledger: 7.94 accepts up to 67,108,856 bytes and returns 0 above that.

What was not measured and why: `mod_exp` with full-size exponent above 65,536 bits, with 2,048-bit exponent at >= 524,280 bits, and with e = 65537 at 8,388,608 bits (Rust) all exceed the 120 s per-measurement cap in both implementations; they are extrapolated with the stated exponents. `BN_check_prime` on a real 8,192-bit prime was not timed because generating the prime did not finish inside 120 s; the derived figure is backed by the 4,096-bit direct check matching its derivation to 3 %. Rust `modpow` at 65,536 bits (full exponent) also exceeded the cap, so the projected Rust/C crossover there is unverified.

## Reproduce

```
SCRATCH=$(pwd)   # this directory, spikes/m65-bignum
export CARGO_TARGET_DIR=/somewhere/outside/the/tree
# C
cd $SCRATCH/c && gcc -O2 bench.c -lcrypto -o bench && gcc -O2 cap.c -lcrypto -o cap && gcc -O2 checkprime.c -lcrypto -o checkprime
./bench <modexp_full|modexp_dh|modexp_e17|trialdiv|bn2dec|dec2bn> <bits> [reps]     # prints reps, median ms, maxrss_kb
./cap                                                   # BN_bin2bn at 67108856 / 67108857 bytes
timeout 120 ./checkprime 4096 3                         # generate prime, time BN_check_prime
# Rust
cd $SCRATCH/rust && cargo +1.88 build --release --offline
$CARGO_TARGET_DIR/release/bnbench <modpow_full|modpow_dh|modpow_e17|trialdiv|to_dec|from_dec|miller_rabin> <bits> [reps]
BN_HEX=$(cat $SCRATCH/raw/prime4096.hex) $CARGO_TARGET_DIR/release/bnbench miller_rabin 4096 3
$CARGO_TARGET_DIR/release/panics
# nmap 7.94
nmap --datadir /home/user/nmap --script $SCRATCH/nse/bncap.nse -sn -n -Pn
```

Raw outputs: `$SCRATCH/raw/` - `modexp_full_65536.txt`, `modexp_e17.txt`, `trialdiv.txt`, `dec2bn.txt`, `bn2dec.txt`, `bn2dec_8M_solo.txt`, `modexp_dh_big.txt`, `rss_c.txt`, `cap_c.txt`, `c_4096_prime.txt`, `checkprime_8192.txt`, `rust_sweep.txt` (first, contended, killed run), `rust_sweep2.txt` (the run reported above), `rust_e17_1M_rerun.txt`, `rust_mr_panics.txt`, `nmap794_cap.txt`, `prime4096.hex`. The small-size C medians quoted for `modexp_full` 8192/16384, `modexp_dh` 8192-65536 and the calibration `bn2dec`/`dec2bn`/`trialdiv` runs come from the calibration pass whose output is in this document's tables and in `$SCRATCH/raw/calibration.txt`.
