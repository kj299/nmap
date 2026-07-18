# Spikes — timeboxed experiments recorded before committing to a design

The kit's Phase-4 rule: **spike the scary module before you schedule it.** Each
entry records what was unknown, what the spike found, and the design decision it
unblocked — so the risk is retired on paper, not mid-port.

---

## M2-1 — `ultra_scan` congestion-control timing math

- **Date:** 2026-07-10
- **Milestone:** 2 (async engine + full `ultra_scan`)
- **Hazard (why spiked):** the plan flags the congestion-control + retransmission
  timing as "the subtle part — spike it against the C before committing." It is
  the piece whose arithmetic, if ported wrong, silently mis-paces every scan and
  is invisible to the safety gates (not UB, not a panic — just wrong numbers).
- **What was unknown going in:** the exact AIMD algorithm nmap uses (slow-start
  vs congestion-avoidance split, the increment scaling, the drop divisors), which
  constants are `-T`-level-dependent, and where the C has divide-by-zero /
  overflow footguns a Rust port must close rather than reproduce.
- **What the spike found (read from `timing.cc` / `timing.h`):**
  - It is textbook TCP AIMD over a `cwnd` measured **in probes** (`f64`), with a
    slow-start threshold `ssthresh`. `ack`: slow-start adds
    `slow_incr * cc_scale` (capped at `ssthresh`), congestion-avoidance adds
    `ca_incr / cwnd * cc_scale`; `cwnd` is capped at `max_cwnd`. `drop` (host)
    resets `cwnd` to the loss window `low_cwnd` and sets
    `ssthresh = max(in_flight / host_divisor, 2)`; `drop_group` is gentler
    (`cwnd /= 2`, not reset). `cc_scale = min(expected/received, 50)`.
  - `-T`-dependent constants: `ca_incr` is 1 for T0–T3, 2 for T4/T5; the ssthresh
    drop divisor is 3/2 (≤T3), 4/3 (T4), 5/4 (T5). Everything else is fixed
    (`cc_scale_max=50`, `initial_ssthresh=75`, `group_drop_cwnd_divisor=2`).
  - **Two latent-footgun sites the C guards with an `assert`/invariant, that Rust
    can close structurally:** (1) `cc_scale` divides by `num_replies_received`,
    which C asserts is `> 0`; (2) congestion-avoidance divides by `cwnd`. Both are
    safe **because** `cwnd >= low_cwnd >= 1` always and `ack` increments
    `num_replies_received` *before* calling `cc_scale`.
- **Design decision unblocked:** the controller is **pure** (no clock, no I/O), so
  it ports as a standalone `core::congestion` module — `PerfVars` +
  `TimingVals::{ack,drop,drop_group}` — with the two divide invariants encoded by
  construction (window held `>= 1`; `received` floored to `1`), replacing C's
  `assert`-and-hope with a value that cannot reach the bad state. Confidence:
  **High** — the math is small, deterministic, and now pinned by 12 unit tests
  transcribing the exact C arithmetic (defaults, level scaling, slow-start cap,
  cc_scale cap, CA increment, both drop paths, the ssthresh floor of 2, and a
  1000-step ack/drop fuzz-of-sequences asserting `cwnd` stays finite and `>= 1`).
- **Outcome:** the spike graduated directly into the shipped `core::congestion`
  module (the algorithm was small enough that the experiment *is* the port). The
  async driver (next M2 module) will call `ack`/`drop` on these values; no engine
  code reaches a socket through this type. **No design pivot needed.**

---

## M3-1 — service-detection regex-engine corpus validation

- **Date:** 2026-07-18
- **Milestone:** 3 (`-sV` service/version detection)
- **Hazard (why spiked):** the whole M3 plan rests on one assumption — that Rust's
  linear-time `regex` crate can carry the bulk of `nmap-service-probes`, confining
  the ReDoS-capable backtracking engine to a small minority. A paper feature-grep
  estimated ~7% need backtracking. Before scheduling the milestone, that had to be
  proven by *actually compiling every pattern*, not grepped.
- **What was unknown going in:** the real fraction that compiles in `regex`; what
  *else* (beyond lookaround/backrefs) Rust rejects that PCRE accepts; and whether
  any patterns are simply un-portable.
- **What the spike found** (`spikes/regex-census/`, compiling all 12,171
  `match`/`softmatch` patterns through `regex::bytes` then `fancy-regex`):
  - **Naively, only 77.5% compile in `regex`** — far below the 7%-fail estimate.
    The gap is **PCRE-vs-Rust *syntax*, not semantics**: nmap writes `\0` for the
    null byte (Rust needs `\x00`), bare `{`/`}` as literals (Rust requires them
    escaped), and leading-bracket character classes `[]abc]` / `[^]]` (Rust
    requires escaping). 421 patterns compiled in **neither** engine.
  - **Service banners are binary, so the engine must be `regex::bytes` with Unicode
    off** — not the `&str` API. (Also relevant: `fancy-regex` is `&str`-only, so a
    pattern that needs *both* backtracking *and* binary bytes is a genuine hard
    case.)
  - **A ~20-line PCRE→Rust translation pass** (`\0`→`\x00`, escape bare braces)
    moves the linear fit **77.5% → 93.5%** (11,380 patterns), drops the
    backtracking set to **6.4%** (782), and collapses the un-portable set from
    **421 → 9**. Extending the translator to the leading-bracket class forms would
    absorb most of the final 9, leaving a single-digit set of genuine
    atomic-group-on-binary patterns for `DIVERGENCES.md` / the break-glass PCRE2
    path.
- **Design decision unblocked / changed:** the port order gains a module the paper
  analysis could not see — **`core::pcre_translate`**, a bounded, pure, heavily
  tested PCRE-syntax→Rust-`regex`-syntax preprocessor — inserted **before**
  `core::matcher`. The hybrid engine choice (`regex::bytes` default →
  `fancy-regex` fallback, step-limited) stands, and is now *empirically* backed:
  the dangerous engine runs on ~6.4% of patterns, and only after translation.
  Confidence: **High**; **the plan changed** (a new module), which is exactly what a
  spike is for — this would otherwise have surfaced as a wall at 77.5% mid-port.
- **Outcome:** finding recorded; `docs/M3-ANALYSIS.md` port order updated. The spike
  crate is retained (detached, not in the workspace build) as the reproducible
  measurement and the seed corpus for `core::pcre_translate`'s test suite.
- **Productionized (M3 module 2/6):** `core::pcre_translate` shipped through the six
  gates. Its class-context state machine (which the spike's flat prototype lacked)
  adds the "escape a literal `[` inside a class" rewrite, so the corpus regression
  measures **77.50% → 93.57%** — marginally above the spike's 93.50%. The spike's
  `translate_pcre_to_rust` prototype is thus fully superseded by the tested module;
  the spike crate remains only as the standalone census.
