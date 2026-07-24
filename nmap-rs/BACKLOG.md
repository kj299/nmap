# nmap-rs backlog

Deferred work, in priority order. Items move out of here into their own branch +
draft PR when picked up. Kept in-repo so it survives across sessions.

## Deferred by the user (2026-07-24)

### 2. Depth on the existing raw scans
- **Multi-host group loop** for `-sS`/`-sU` (one shared capture demultiplexed by
  source address, as nmap's `ultra_scan` does). Today each scans a single host per
  call. Ledgered: `synscan-single-host-first-slice`, `udpscan-single-host-first-slice`.
- **UDP protocol payloads** (`payload.cc`): protocol-specific probe payloads that
  elicit replies from more services, shrinking the `open|filtered` bucket. Ledgered:
  `udpscan-empty-payload`.
- **Back-fill the SYN scan's ICMP path** with the embedded-probe match machinery the
  UDP scan introduced (`core::udpscan::embedded_udp_ports` generalizes). Ledgered:
  `synscan-icmp-match-deferred`.

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
- **DRY the scan matchers** — `synscan`/`udpscan`/`flagscan` each carry their own
  `ipv4_offset` + a similar match skeleton; extract a shared helper once the third
  lands.
- **New-fuzz-target checklist**: every new `fuzz_targets/<t>.rs` needs a committed
  `fuzz/seeds/<t>/` dir, or CI's `cargo fuzz run <t> fuzz/seeds/<t>` errors. Capture
  in the next scan-driver retrospective (cousin of LESSONS #15).
