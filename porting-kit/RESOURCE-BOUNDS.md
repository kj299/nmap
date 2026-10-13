# RESOURCE-BOUNDS: gating time and memory on untrusted input

PLAYBOOK Phase 4 step 4b links here. The rule: **pre-emptible is not bounded.**
For every input edge in the threat model, gate how much work one slice does and
how total work and peak memory grow with input size. Measure the port, in a
release build, by wall clock and RSS, and compare the result with C
(LESSONS #040).

## Why the kit has this gate

nmap's M6.6 ported LPeg 0.12 into a pre-emptible VM. Every safety gate was green
at every step, and the step reviews still found nine resource defects. These were
9 of about 15 substantive findings, and they included the milestone's only High:

| step | what the review measured | port | C |
|---|---|---|---|
| b | one grammar build ran as a single slice | 13.66 s, 4.3 GB | — |
| c | `/string` re-copied its format on every step (2 MB format) | ≈140 s | 0.033 s |
| c | one slice's memory against the budget | 344 MB (5.4×) | — |
| c | the per-slice heap walk at `Ct(Ct(C(1))^0)`, 999k (missed by step c's own review) | 34.6 s | 0.36 s |
| d | `json.parse` of a 1.8 MB network body (the per-poll heap walk) | 270 s | 0.17 s |
| d | strings retained after the parse | 525 MB | ~4 MB |

The plan had gated the mechanism: "the match returns `Pending` on schedule." It
did, and that is the trap. A computation that yields every 10 ms can still do
1,600 times C's work in total. The meters were blind too. Step 0b's linearity
search counted the instrumented C's steps, and step e's ceiling counted the
port's VM steps. One VM step scanned a whole run of bytes, so a quadratic pattern
read as a flat 6 steps per byte while CPU time grew 30×. A meter counts only what
it is instrumented to count. Wall clock and RSS count everything.

## The procedure

1. **Declare the bound at Phase 0.** The threat model's trust-boundary table has
   an availability column (`skeleton/THREAT-MODEL.md`). For each untrusted edge,
   record the expected time and memory exponents (1 = linear) and any absolute
   budget, such as a per-script memory cap. A bound that is never written down
   cannot be gated. Classify path inputs as well: a data file can be a FIFO or
   `/dev/zero` (LESSONS #001). M6.6's FIFO blocked forever and `/dev/zero` looped
   to 2.07 GB, and both were found only at step a's review.

2. **Scale the port against C.** Use a release build and the threat model's
   worst-case shapes, not its typical ones. Good shapes are deep nesting, long
   runs of one byte, many small items as well as one large one, repeated
   formats, captures inside loops, and the slowest inputs the fuzz corpus has
   found.

   ```
   python3 porting-kit/harnesses/scaling/scale_check.py \
       --gen  'python3 gen_nested_json.py {n} > {input}' \
       --cmd  './target/release/port --script json-parse {input}' \
       --oracle-cmd './c-oracle --script json-parse {input}' \
       --n 100000 --steps 3 --time-exp 1 --mem-exp 1 --max-time-ratio 10
   ```

   The harness fits each exponent on successive differences, which cancels
   start-up time and the start-up RSS high-water mark. It fails when an exponent
   exceeds the declared bound or C's own exponent by more than the tolerance, or
   when the port/C ratio at the largest size exceeds `--max-time-ratio` or
   `--max-mem-ratio`. Commit each check as a test or a CI step. A scale check
   that only ever ran once is a measurement, not a gate.

3. **Self-metering code gates work, not yielding.** Some code charges fuel,
   counts steps, or pre-empts itself. For that code, assert that the work done
   per slice is at most c × the fuel paid. Count the work independently of the
   charge: bytes touched, allocations, and bookkeeping walks such as heap
   accounting. Add a wall-clock check on the longest slice. **Calibrate every step
   counter against wall clock once.** Run one pattern at n and 4n. If steps per
   byte stay flat while time grows, the meter is blind to something.

4. **Memory: test peak and retention at two sizes.** Peak RSS must stay within
   the budget plus one growth step of any buffer. The memory still held after
   the operation completes must not grow with input that has already been
   consumed.

5. **A pre-emption spike gates total work and the slice bound**, not only "can
   yield". It sits next to LESSONS #017's teardown criterion in the
   spike-and-gate ritual. Step 0b's spike passed 8 requirements and none of
   them was about total work. Step d's defects were in the part the spike did
   not cover (capture evaluation).

6. **A finding of this class becomes a standing gate for every later step**
   (LESSONS #041, `REVIEW-GATE.md`). Step b's review already said "fuel is
   charged per call, not per unit of work". Each fix gated only its own step's
   code, so the class recurred at c and d.

## What this gate still cannot see

A scale check scales only the shapes someone lists. Step c's security review
measured its own F2 and F3 and still missed the per-slice walk, which was already
visible at `Ct(Ct(C(1))^0)`. That walk surfaced only when step d made it run on
every poll. The missing tool is a **differential performance search**: a
hill-climb over inputs, seeded from the fuzz corpus, that maximises port time ÷
oracle time and port peak memory ÷ oracle peak memory on the port's own code
paths. The kit does not have it yet. It is recorded as the next port's target in
LESSONS #040 and in OPERATING-GUIDE §5.
