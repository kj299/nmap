#!/usr/bin/env python3
"""Generate SEQ-analysis differential cases for `core::osprobe::seq`.

One case per line: <scan_delay_ms> <n> <isn>:<usec>:<ts> ...

Covers the shapes that drive each branch of makeTSeqFP's numeric core — constant
ISNs, perfectly linear counters, jittered counters at small and large GCDs (the
divide-only-when-large-than-9 compromise), counter wraparound, degenerate timings,
and every TS frequency bucket — plus seeded random samples.
"""
import random

cases = []

def case(samples, scan_delay=0):
    parts = " ".join(f"{isn}:{usec}:{ts}" for isn, usec, ts in samples)
    cases.append(f"{scan_delay} {len(samples)} {parts}")

def linear(step, n=6, ts_step=0, usec_step=100_000, base=0x10000000, delay=0):
    case([((base + step * i) & 0xFFFFFFFF, usec_step * i, ts_step * i) for i in range(n)], delay)

# 1. Constant ISN — gcd 0, the "maximally predictable" branch.
linear(0)
# 2. Perfectly linear at a range of steps, including the >9 GCD boundary.
for step in [1, 2, 8, 9, 10, 11, 64, 1000, 64000, 1 << 20, 0x7FFFFFFF]:
    linear(step)
# 3. Response counts either side of the >= 4 threshold.
for n in range(0, 7):
    linear(1000, n=n)
# 4. scan_delay either side of the 1000 ms cutoff.
for d in [0, 999, 1000, 1001, 5000]:
    linear(1000, delay=d)
# 5. Jitter at small and large GCDs — the div_gcd compromise.
for base_step, jitter in [(2, 2), (10, 5), (64000, 32000), (100, 1), (1 << 16, 1 << 15)]:
    isn, samples = 0x10000000, []
    for i in range(6):
        samples.append((isn & 0xFFFFFFFF, 100_000 * i, 0))
        isn += base_step + (jitter if i % 2 else 0)
    case(samples)
# 6. Counter wraparound — MOD_DIFF must take the short way round.
case([(0xFFFFFC18, 0, 0), (1000, 100_000, 0), (3001, 200_000, 0),
      (5002, 300_000, 0), (7003, 400_000, 0), (9004, 500_000, 0)])
# 7. Degenerate timings: identical send times, and very long gaps.
case([(0x10000000 + 1000 * i, 0, 0) for i in range(6)])
case([(0x10000000 + i, 3_600_000_000 * i, 0) for i in range(6)])
case([(0x10000000 + 1, 0, 0), (0x10000000 + 2, 1, 0), (0x10000000 + 3, 2, 0),
      (0x10000000 + 4, 3, 0), (0x10000000 + 5, 4, 0), (0x10000000 + 6, 5, 0)])
# 8. TS frequency buckets, including the boundaries the C deliberately widened.
for hz in [0, 1, 2, 5, 5.66, 6, 10, 70, 71, 100, 150, 151, 200, 350, 351,
           512, 724, 1000, 1448, 2000, 100000]:
    per = int(round(hz / 10.0))
    linear(1000, ts_step=per)
# 9. Seeded random samples.
rng = random.Random(0x5EED)
for _ in range(300):
    n = rng.randrange(0, 7)
    isn = rng.randrange(0, 1 << 32)
    ts = rng.randrange(0, 1 << 32)
    t = 0
    samples = []
    for _ in range(n):
        samples.append((isn & 0xFFFFFFFF, t, ts & 0xFFFFFFFF))
        isn += rng.choice([0, 1, 2, 64, 1000, 64000, rng.randrange(0, 1 << 24)])
        ts += rng.choice([0, 1, 10, 100, 1000, rng.randrange(0, 100000)])
        t += rng.choice([1, 1000, 100_000, 1_000_000])
    case(samples, rng.choice([0, 500, 1000, 2000]))

with open("seq_cases.txt", "w") as f:
    for c in cases:
        f.write(c + "\n")
print(f"{len(cases)} cases")
