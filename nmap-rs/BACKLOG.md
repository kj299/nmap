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
- **UDP protocol payloads** (`payload.cc`): protocol-specific probe payloads that
  elicit replies from more services, shrinking the `open|filtered` bucket. Ledgered:
  `udpscan-empty-payload`.
- **Back-fill the SYN/flag scans' ICMP path** with the embedded-probe match machinery
  the UDP scan introduced (`core::udpscan::embedded_probe` generalizes — it already
  returns the quoted destination, which is what attributes an error to the right host
  in a group scan). Ledgered: `synscan-icmp-match-deferred`,
  `flagscan-icmp-match-deferred`.

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
- **DRY the scan matchers** — partly done: the three *drivers* collapsed into one
  (`sys::group`). Still outstanding on the `core` side: `synscan`/`udpscan`/`flagscan`
  each carry their own copy of `ipv4_offset` and a similar frame-decode preamble;
  extract a shared helper.
- **New-fuzz-target checklist**: every new `fuzz_targets/<t>.rs` needs a committed
  `fuzz/seeds/<t>/` dir, or CI's `cargo fuzz run <t> fuzz/seeds/<t>` errors. Capture
  in the next scan-driver retrospective (cousin of LESSONS #15).
