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

---

## M4-1 — pcap capture into an async runtime with no selectable fd

- **Date:** 2026-07-19
- **Milestone:** 4 (raw-packet infrastructure + all raw scans)
- **Hazard (why spiked):** the top M4 hazard (`docs/M4-ANALYSIS.md` §S1). On Windows
  nmap's pcap handle exposes **no selectable file descriptor** — `PCAP_CAN_DO_SELECT`
  is undefined on WIN32 (`nsock_pcap.h:85`), so `pcap_get_selectable_fd` is never
  called (`pcap_desc = -1`); nmap sets the handle non-blocking and **polls
  `pcap_next_ex` at a forced 2 ms cap** inside the IOCP loop
  (`engine_iocp.c:328-346`). A Rust port that assumes "register the pcap fd with
  tokio/mio and await readiness" **cannot work on Windows** — there is no readiness
  fd to register. The entire `sys::npcap` capture design hinges on how we bridge a
  no-readiness-fd source into the tokio driver, so it had to be settled before
  scheduling any scan-type work that consumes captured packets.
- **What was unknown going in:** whether an event-driven bridge (no polling) is even
  possible without a readiness fd, and what latency / idle-CPU penalty nmap's actual
  Windows mechanism (the 2 ms poll) imposes versus the alternative.
- **Decision gate (written before the code):** the chosen design must (a) deliver a
  loopback packet into the async runtime with **median added latency well under the
  2 ms poll floor**, (b) **not busy-spin** the CPU while the network is idle, and
  (c) **require no selectable/readiness fd** so it ports to Npcap on Windows. On
  failing, document the capture design as a platform constraint before proceeding.
- **What the spike found** (`spikes/pcap-async/`, real loopback UDP, `std` sockets
  only so the tokio reactor is never registered — faithfully modeling "no readiness
  fd"; 2000 packets @ 200 µs spacing, two runs):
  - **BlockingThread → `tokio::mpsc`** (a dedicated OS thread does a *blocking* recv —
    models Npcap blocking mode / a capture thread — and forwards frames into a channel
    the async driver awaits): **median ~60–64 µs** send→delivery latency, **p99
    ~120 µs–1 ms**, and **0 idle wakeups** (the thread parks in `recv`). **PASS.**
  - **PollTask (2 ms)** (a tokio task polls a *non-blocking* socket, sleeping 2 ms
    between empty reads — a faithful analogue of nmap's Windows IOCP path): **median
    ~1.6 ms** (≈25× worse, exactly the expected half-of-2 ms poll floor) and
    **~125 idle wakeups per 300 ms** of quiet network (busy-spin). Reproduces nmap's
    Windows behavior and quantifies its cost.
  - Neither design needs a readiness fd, so both are Windows-portable — but only the
    blocking-thread bridge is event-driven.
- **Design decision unblocked:** **commit `sys::npcap` capture to the
  BlockingThread → channel design** — a dedicated blocking capture thread (Npcap in
  blocking mode on Windows, libpcap on Linux) feeding a `tokio::mpsc` the async raw
  driver awaits. It is event-driven (~0 idle CPU), ~25× lower latency than nmap's own
  Windows poll, needs no selectable fd, and is identical on both platforms — so the
  differential oracle runs the same capture path on Linux CI that ships on Windows.
  The RAII `OwnedPcapHandle` lives on the capture thread; the async side only ever
  touches the safe channel. Keep the 2 ms PollTask **only** as a documented fallback
  if a platform's blocking capture misbehaves (e.g. an Npcap immediate-mode quirk).
  Confidence: **High**; the plan did not change (the port order already isolated
  `sys::npcap` behind the seam), but the internal design is now empirically fixed
  rather than an open question mid-port.
- **Outcome:** finding recorded; `docs/M4-ANALYSIS.md` §S1's decision gate is
  discharged. The spike crate is retained (detached, not in the workspace build) as
  the reproducible measurement. **Still to gate before `sys::npcap` ships: S2** —
  confirming the design links against the real Npcap SDK (`wpcap.dll` + `Packet.dll`)
  on `x86_64-pc-windows-msvc` and round-trips on the Npcap loopback adapter — which
  needs a Windows host and is deferred to the `sys::npcap` slice.
