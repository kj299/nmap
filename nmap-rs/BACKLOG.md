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
5. `core::osprobe` — **in progress**. Done: `osprobe::build` (the probe battery, C-oracle
   differential over all 23 packets), `osprobe::analyze::tcp_option_string` (the
   `O`/`O1`-`O6` encoder, C-oracle differential over 428 cases), and `osprobe::seq`
   (`makeTSeqFP` — SP/GCD/ISR/TI/CI/II/SS/TS, C-oracle differential over 354 cases).
   Remaining: the per-reply attribute extraction in `processT1_7Resp` /
   `processTEcnResp` / `processTUdpResp` / `processTIcmpResp` / `makeTWinFP`, which is
   mechanical field-reading by comparison.
6. `sys::osscan` + `cli -O` — privileged driver on the M4 group engine.
7. IPv6: `core::fpmodel` (embed weights, port `predict_values`/`novelty_of` — pure
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
- **Lint both feature configurations before pushing**: `--all-features` turns `pcap`
  on, so it never sees an import that is only used by a `#[cfg(feature = "pcap")]`
  item. CI runs clippy with **and** without the feature under `-D warnings`; a
  local `--all-features`-only check passes code CI rejects. (Cost a red run on #55.)
  Same shape as the fuzz `+nightly` note in LESSONS #16: the local convenience
  invocation is not the CI invocation. For the next retrospective.
