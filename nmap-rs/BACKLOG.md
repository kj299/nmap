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

### 3. M5 — OS detection
The next milestone in the plan of record. Consumes this raw send/capture layer:
IPv4 `osscan2` probe engine + `nmap-os-db` fingerprint match; IPv6 `FPEngine`
inference. See the milestone plan for the full breakdown.

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
