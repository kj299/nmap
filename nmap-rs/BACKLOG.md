# nmap-rs backlog

Deferred work, in priority order. Items move out of here into their own branch +
draft PR when picked up. Kept in-repo so it survives across sessions.

## Deferred by the user (2026-07-24)

### 2. Depth on the existing raw scans
- ~~**Multi-host group loop**~~ — **done**. `sys::group` scans a whole host group over
  one shared capture demultiplexed by source address (nmap's `ultra_scan` model), and
  **every** raw scan now runs on it via `RawScanKind`: `SynKind` (`-sS`), `UdpKind`
  (`-sU`), `FlagKind` (the six flag scans). The three single-host drivers it replaced
  are deleted. Ledgered: `group-scan-one-engine-for-every-raw-scan`.
- ~~**UDP protocol payloads** (`payload.cc`)~~ — **done**. `core::payload` derives the
  payload table from `nmap-service-probes` (nmap has no separate payload DB), and
  `sys::group::UdpKind` sends one datagram per registered payload. Ledgered:
  `payload-cap-warns-not-fatal`, `payload-missing-db-degrades`,
  `payload-one-datagram-per-payload`.
- ~~**Back-fill the SYN/flag scans' ICMP path**~~ — **done**. `core::icmp_quote` is the
  shared quote parser for all three raw scans; `-sS` and the six flag scans now report
  *filtered* (with the specific ICMP reason) instead of falling back to the no-response
  default. Also closed a gap in our own UDP path: the quoted packet's source is now
  checked against our address, as the C does. Ledgered:
  `icmp-quote-requires-our-source`, `icmp-quote-verifies-our-sequence`,
  `icmp-reason-fidelity`, `icmp-bpf-widened-for-tcp-scans`.

### 3. M5 — OS detection  ⟵ **IN PROGRESS**
Phase 0 done (inventory + cflaw-scan + threat model + FPModel spike); both the IPv4
and IPv6 tracks are approved. Port order, leaf-first:
1. ~~`core::osdb::expr`~~ — **done**, C-oracle differential over 23.8k cases.
2. ~~`core::osdb::model` / `parse`~~ — **done**, corpus gate over the real 5.1 MB file
   (6,108 fingerprints, zero warnings) + fuzz.
3. ~~`core::osdb::score`~~ — **done**, corpus gate over the real database (perfect match
   on a concrete Linux observation) + the early-exit invariant over all 6,108 records.
4. ~~`core::macvendor`~~ — **done**, corpus gate over the real file (52,085 prefixes,
   zero warnings) cross-checked against a text-derived oracle.
5. ~~`core::osprobe`~~ — **done**. Modules: `osprobe::build` (the probe battery, C-oracle
   differential over all 23 packets), `osprobe::analyze::tcp_option_string` (the
   `O`/`O1`-`O6` encoder, C-oracle differential over 428 cases), and `osprobe::seq`
   (`makeTSeqFP` — SP/GCD/ISR/TI/CI/II/SS/TS, C-oracle differential over 354 cases).
   `osprobe::tcpreply` (`processT1_7Resp` / `processTEcnResp` / `processTOpsResp` /
   `processTWinResp` plus the `T`/`TG` post-pass from `makeFP`), and `osprobe::icmpreply`
   (`processTUdpResp` — the `U1` test + hop distance — and `processTIcmpResp` — the `IE`
   test). **`core::osprobe` is now complete: all 13 fingerprint tests can be built.**
6. ~~`core::osprobe::assemble`~~ — **done**. Ports `makeFP`: aggregates + per-reply tests
   into one observed `FingerPrint`, the `R=N` silence defaults (gated on actually having
   had a port to probe), and the `T`/`TG` resolution once `U1` yields the hop count. Also
   `FingerPrint::render_tests` (`fp2ascii`), gated by a render/parse round trip over
   **every** shipped fingerprint plus an end-to-end "synthesised Linux host is identified
   as Linux" test against the real database.
7. ~~`core::osscan`~~ — **done**. The pure half of the driver: `endRound`'s completion
   test and distance ladder, `findBestFPs`, `OmitSubmissionFP`, and `printosscanoutput`'s
   plain-text rendering. No sockets, so it is fully unit/Miri/fuzz testable.
8. ~~`core::osprobe::demux` + `sys::osscan` + `cli -O`~~ — **done. `-O` works end to end.**
   `demux` attributes a frame to its probe by identity (TCP source port, ICMP id/seq, the
   UDP port quoted inside the error); `sys::osscan` sends the battery, paces the `SEQ`
   probes, and drives the retry rounds through `core::osscan`'s policy; port selection
   comes from the scan's own results; and the CLI renders the result after the port table.
   **Design note so it is not relitigated:** this deliberately does *not* implement
   `group::RawScanKind` — that engine is port-keyed (scheduler walks a port list, yields
   `(port, tryno)`, produces per-port states) while `-O` sends 23 heterogeneous probes
   feeding 13 extractors, and its congestion window wants to send as fast as possible
   whereas the six `SEQ` probes must be paced at 100 ms or the ISN/timestamp analysis is
   wrong. It reuses the layer below — `AsyncCapture`, `RawSender`, the timeout math.
   **Gated by the first on-wire differential in M5**
   (`tests/differential/m5/run_os_differential.sh`, in CI): C nmap and nmap-rs fingerprint
   the same loopback host and all 13 tests must agree.
   Remaining polish (not blocking): XML/grepable `<os>` output, the `Uptime guess` and
   `TCP Sequence Prediction` lines (the renderer supports them; the driver does not yet
   collect `SeqReport`), and `--max-os-tries`.
   **Harness note:** the differential compares the *final* round's fingerprint from each
   tool's `-d` output and strips the fields that are measurements rather than properties
   (the `SCAN` metadata line, `SEQ`'s `SP`/`GCD`/`ISR`, a numeric `SEQ.TS`, and `T`/`TG`).
   It verifies its own loopback fixture is listening before comparing — without that a
   failed bind leaves no open TCP port, and two fingerprints of a host with no open port
   agree trivially, turning the gate into a no-op that reports success.
9. IPv6: `core::fpmodel` (embed weights, port `predict_values`/`novelty_of` — pure
   f64, no liblinear FFI), `core::fp6::vectorize`, then `sys::fpengine` + CLI.

## Smaller follow-ups (opportunistic)
- **Pin `rust-toolchain.toml`** — done (M4 retrospective, LESSONS #16).
- **Full routing-table LPM** in `sys::route` (today: on-link match → default gateway).
  Ledgered: `route-minimal-onlink-then-gateway`.
- **Non-Ethernet datalinks** (Linux SLL, BSD NULL) in the capture path; today
  `eth_included` is assumed true (correct for `lo`/Ethernet).
- ~~**DRY the scan matchers**~~ — **done**. The three drivers collapsed into one
  (`sys::group`), and the duplicated `ipv4_offset` plus the ICMP-quote decode now live
  once in `core::icmp_quote`.
- **New-fuzz-target checklist**: every new `fuzz_targets/<t>.rs` needs a committed
  `fuzz/seeds/<t>/` dir, or CI's `cargo fuzz run <t> fuzz/seeds/<t>` errors. Capture
  in the next scan-driver retrospective (cousin of LESSONS #15).
- **The fuzz crate is not in the workspace lint sweep.** `cargo clippy --workspace
  --all-targets` does **not** build `fuzz/`, which is a separate crate compiled only by
  `cargo +nightly fuzz build`. So adding a public field to a struct a fuzz target
  constructs (here `osscan::Report`) passes every local check and then fails CI's fuzz
  job on a plain compile error. Before pushing a change to any type a fuzz target names,
  run `for t in $(cargo +nightly fuzz list); do cargo +nightly fuzz build $t; done`.
  Same shape as the "lint both feature configurations" lesson: the local convenience
  invocation is not the CI invocation. (Cost a red fuzz job on #69.)
- **Lint both feature configurations before pushing**: `--all-features` turns `pcap`
  on, so it never sees an import that is only used by a `#[cfg(feature = "pcap")]`
  item. CI runs clippy with **and** without the feature under `-D warnings`; a
  local `--all-features`-only check passes code CI rejects. (Cost a red run on #55.)
  Same shape as the fuzz `+nightly` note in LESSONS #16: the local convenience
  invocation is not the CI invocation. For the next retrospective.
