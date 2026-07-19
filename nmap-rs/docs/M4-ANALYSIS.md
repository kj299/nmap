# Milestone 4 — raw-packet infrastructure: Phase-0 analysis

Fresh kit cycle (PLAYBOOK Phases 0–1). Inventory + C-flaw scan + threat model +
dependency-ordered port plan. **No Rust is written until the port order is
approved** (kit requirement). This document is the durable record of the Phase-0
findings; the differential oracle (Phase 2) and the per-module six-gate loop
(Phase 4) follow on approval.

## Scope

The full privileged scanning suite: raw packet build/parse, the raw send/capture
chokepoint, every raw scan type (`-sS/-sA/-sW/-sM/-sN/-sF/-sX/-sU/-sO/-sY/-sZ`),
idle scan (`-sI`), traceroute, raw host discovery, and the Windows OS-acquisition
layer (Npcap + IP Helper). FFI is reserved for Npcap; interface/route/ARP
enumeration moves to the pure-Rust `windows` crate. Target `x86_64-pc-windows-msvc`.

## The C surface (~30k LOC, three strata)

| Stratum | Files | LOC | Destination |
|---|---|---|---|
| Packet build/parse (pure) | `libnetutil/` headers, `PacketParser.cc` (1801), `netutil.cc` checksums | ~8k | `core` (`#![forbid(unsafe_code)]`), fuzz-first |
| Send/recv chokepoint + scan types (mixed) | `tcpip.cc` (1685), `scan_engine_raw.cc` (2201), `idle_scan.cc` (1354), `traceroute.cc` (1558), `payload.cc` (181) | ~7k | split `core` (build + classify) / `sys` (I/O) |
| OS acquisition (unsafe) | `libdnet *-win32` (intf 608, route 275, arp 158, eth 152, ip 75), `nsock_pcap.c` (525), `engine_iocp.c` (861) | ~2.7k | `sys` — the only `unsafe`; Npcap FFI + IP Helper |

## Latent C bugs found — fix, do NOT re-port (→ DIVERGENCES.md on porting)

These are the Phase-0 flaw inventory. The heuristic `scan_c_flaws.py` grep produced
36 hits that were almost all low-signal (`strcpy` of a constant string into a sized
local in the `--packet-trace` decorator, `packettrace.cc`); the real M4 hazard class
is **parse-side bounds on attacker-controlled captured packets**, which the grep
cannot see. The agents found those by reading the code:

1. **1-byte stack-buffer overflow, `UDPHeader::setSum` (CWE-121, real & reachable).**
   Buffer `u8 aux[65535-8]` = 65527 bytes (`UDPHeader.cc:197`), but
   `dumpToBinaryBuffer(aux, 65536-8)` passes `maxlen = 65528` (`:209`).
   `dumpToBinaryBuffer` (`PacketElement.h:171`) only aborts when a *single* element
   exceeds the remaining `maxlen`, so a UDP+payload chain whose total `getLen()` is
   65528 `memcpy`s 65528 bytes into a 65527-byte stack array. The parallel TCP path
   uses one constant for both and is correct; UDP's two constants disagree. The Rust
   core sizes buffer and length from a single source → class removed.
2. **Remote DoS: `netutil_fatal()` process-abort on an attacker-chosen ICMP type**
   (`netutil.cc:848-878`, `icmp_get_data`/`icmpv6_get_data` for any type other than
   TIMEXCEED/UNREACH). In a `forbid(unsafe)` core these return `Result::Err`.
3. **Attacker-influenced `assert(newipid < 0xffff)`** in idle scan
   (`idle_scan.cc:698`): a crafted zombie/injected IP-ID aborts nmap → recoverable
   error, never a panic.
4. **Silent send failure: `eth_send` ignores `PacketSendPacket`'s BOOL** and always
   returns `len` (`eth-win32.c:104`); the sync flag is `TRUE` so the call can wait on
   the driver. The port surfaces the real result.
5. **Signed/unsigned truncation, `RawData::store`** (`RawData.cc:147-163`): `int
   length` vs `size_t len`; `len > INT_MAX` casts negative and can drive a full-size
   `memcpy`. Bounded in practice by `pktlen`; removed by construction in Rust.
6. **Non-reentrant shared state:** `static pkt_type_t this_packet[]` returned by
   pointer (`PacketParser.cc:126`) and `static int myttl` inside the "pure"
   `build_ip_raw` (`tcpip.cc:524`) → owned returns / explicit params.
7. **Silent truncation (behavioral divergence, ledger only):** fixed
   `pingpkt.data[1500]`/`igmp.data[1500]` send buffers (`tcpip.cc:940,1054`) copy
   `MIN(dlen,datalen)` — no overflow, but oversized payloads are silently truncated.
   Recorded, not "fixed" (it is not a memory bug).
8. **ICMPv4 union-overlay getters read the zero-filled tail** of a fixed buffer on a
   truncated inner ICMP (`ICMPv4Header.cc` getters; `is_response` reads them) — not
   OOB, but reads bytes that were never on the wire. Encoded explicitly.

## Spike-and-gate hazards (research-grade — gate before committing)

Per LESSONS #1 the spike-and-gate ritual runs on each hard piece **before** it is
scheduled: rate effort + confidence, write the decision gate first, pivot-check on
hitting it.

- **S1 — pcap capture in an async runtime on Windows (TOP hazard).** Windows nmap
  uses **no selectable pcap FD**: `PCAP_CAN_DO_SELECT` is undefined on WIN32
  (`nsock_pcap.h:85`), so `pcap_get_selectable_fd` is never called
  (`pcap_desc = -1`); the handle is set non-blocking (`pcap_setnonblock`,
  `nsock_pcap.c:340`) and the IOCP loop **polls `pcap_next_ex` at a forced 2 ms cap**
  (`PCAP_POLL_INTERVAL`, `engine_iocp.c:328-346`). A Rust port that assumes "wrap the
  pcap fd in mio/tokio and await readiness" **cannot work on Windows** — there is no
  readiness fd. The single load-bearing anti-hang invariant is the successful
  `pcap_setnonblock` (fatal if it fails with no selectable fd, `nsock_pcap.c:345-352`).
  **Decision gate:** prove one of { timer-driven non-blocking `pcap_next_ex` poll
  task; Npcap `pcap_getevent` + `WaitForSingleObject`; dedicated blocking capture
  thread → channel } delivers a loopback packet into the async driver within a fixed
  latency. On hitting the gate, document the chosen capture design as a platform
  constraint before any scan-type work depends on it.
- **S2 — Npcap SDK linkage on `-msvc`.** The only mandatory C FFI is `wpcap.dll`
  (capture) + `Packet.dll` (raw-eth send, `eth-win32.c`). **Gate:** a round-trip
  send+capture on the Npcap loopback adapter links and runs, or stop and report the
  SDK/linkage limit. RAII `OwnedPcapHandle`; every FFI call in a small audited safe fn.
- **S3 — idle-scan IP-ID kernel.** `ipid_distance` (`idle_scan.cc:313`) relies on
  *deliberate* `u16`/`u32` wraparound per sequence class (plain subtract; byteswap
  then subtract for BROKEN_INCR; /2 for INCR_BY_2) plus a probabilistic binary-split
  open-port inference with adaptive retry. **Gate:** isolate the pure delta +
  classification kernel (`core::ipid`) and match the C on captured traces before
  porting the adaptive I/O loop.

The Windows OS-integration layer is otherwise **mechanical** (no FFI): intf/route/arp
enumeration (`GetAdaptersAddresses`, `GetIpForwardTable(2)`, `GetIpNetTable2`,
`GetBestRoute`, `GetBestInterfaceEx`, `FreeMibTable`, the Npcap loopback registry
probe) maps 1:1 to the `windows` crate `Win32::NetworkManagement::IpHelper`; none
block, none need admin for read enumeration. `ip-win32.c` raw sockets are effectively
dead on the target (SOCK_RAW/IP_HDRINCL disabled since XP SP2 — the very reason the
Npcap eth path exists) and can be a thin `sendto` shim or omitted.

## Proposed dependency-ordered port plan (leaf-first)

**Core (pure, each fuzzed + differential'd):**
1. `core::bytes` — checked `&[u8]` cursor (read_u8/be_u16/be_u32, split_at, take);
   replaces every pointer-add + `memcpy` + `(struct ip*)buf` overlay.
2. `core::checksum` — `in_cksum` (safe `chunks(2)` `u32` fold + carry), v4/v6
   pseudo-header. Depends: bytes. `[netutil.cc:633-955]`
3. `core::consts` — HEADER_TYPE_*/ETHTYPE_*/proto numbers/ICMP type-code enums.
4. `core::headers::*` — ethernet, arp, ipv4, ipv6(+ext), tcp (+options iterator),
   udp, icmpv4, icmpv6, raw. Each = `parse(&[u8]) -> Result` + `serialize` +
   `checksum`; each independently fuzzed against its C `storeRecvData`+`validate`.
   `TCPOptions::foreachOpt` (already careful about `oplen<2` infinite-loop) is a good
   standalone early fuzz target.
5. `core::packet_parser` — `parse_packet`/`split`/`is_response` as a cursor state
   machine returning `Vec<Header>` (kills the `static this_packet[]`). Bounded by
   `MAX_HEADERS_IN_PACKET`=32.
6. `core::build` — the `build_*` constructors + `fill_ip_raw` from `tcpip.cc`;
   `o.*`/`static myttl` refactored to explicit params. Owns the 1500-byte-truncation
   divergence.
7. `core::recv_validate` — `validatepkt`/`validateTCPhdr`/`accept_ip`/`accept_any` +
   MAC-from-link-header (`setTargetMACIfAvailable`). Primary fuzz target.
8. `core::classify` — the pure `(scantype, headers, from_target) -> PortState` tables
   (`scan_engine_raw.cc` recv-loop transitions + `set_default_port_state`
   `scan_engine.cc:803`). **The differential-oracle centerpiece** — extract it from
   the giant recv `do/while` into a table-driven pure fn. `from_target` (source ==
   scanned host) gates CLOSED/OPEN vs FILTERED and is load-bearing.
9. `core::ipid` — idle-scan delta + sequence classification kernel (spike S3 first).

**Sys (unsafe seam, only crate with `unsafe`):**
10. `sys::netif` — intf/route/arp enumeration via the `windows` crate IP Helper
    (mechanical, no FFI).
11. `sys::npcap` — **spike S1 + S2 first** — Npcap FFI capture + raw-eth send; RAII
    `OwnedPcapHandle`; capture integrated into the async runtime per S1's outcome.
12. `sys::rawio` — the `send_ip_packet` (`tcpip.cc:411`) / `readip_pcap`
    (`tcpip.cc:1410`) seam functions + fragmentation + decoy loop I/O.

**Scan drivers (core+sys):**
13. `scan_engine_raw` — probe-send dispatch + recv loop feeding `core::classify`;
    wires `-sS/-sA/-sW/-sM/-sN/-sF/-sX/-sU/-sO/-sY/-sZ`.
14. raw host discovery — ARP / ICMP echo·timestamp·netmask / TCP·UDP ping.
15. `idle` (`-sI`) — adaptive loop around `core::ipid`.
16. `traceroute` — last (depends on all lower layers; `hop_cache` + ICMP dissection).
17. `cli` — flags + `PrivilegeGuard` (Administrator + Npcap capability check) +
    **graceful degrade to connect scan** when privilege/Npcap unavailable (never
    hard-fail).

**Build/test order within core:** `bytes → checksum → consts → headers/* → parser`,
differential-testing each leaf header first (the true untrusted-parse units), the
parser last since it only orchestrates.

## Threat model (draft)

- **Untrusted boundaries:** every captured packet is attacker-controlled network
  input. Fuzz-first list: `core::packet_parser` + every `core::headers::*` leaf,
  `core::recv_validate`, `core::classify`, `core::ipid`, and the traceroute ICMP
  dissection. No parser may panic/abort on hostile input (the `netutil_fatal` and
  idle-scan `assert` bugs are the anti-patterns).
- **Privilege:** raw send/capture require Administrator + the Npcap driver. Gate
  behind an explicit capability check; RAII `PrivilegeGuard`; degrade gracefully to
  the unprivileged connect scan when unavailable — never hard-fail.
- **Unsafe containment:** all `unsafe` lives in `sys::npcap` (Npcap FFI). `sys::netif`
  and the IOCP primitives are safe `windows`-crate calls. Every FFI call sits in a
  small audited safe fn with a `// SAFETY:` proof; every OS resource is an RAII type.

## Oracle plan (Phase 2, recommended)

Differential the pure core (parsers / `classify` / `ipid`) against captured &
synthetic packet-trace corpora on the unprivileged Linux CI runner; run the
privileged live send/capture differential only in the Windows+Npcap real-run gate.
Keeps CI unprivileged, fast, and portable while still pinning the load-bearing
semantic result (response → port-state). Seed `DIVERGENCES.md` from the eight flaw
findings above.

## Status

Phase 0 complete (this document). **Awaiting approval of the port order before any
Rust.** Recommended first step on approval: run the **S1 spike** (pcap-in-async on
Windows) with its written decision gate — its outcome shapes the entire `sys` capture
design — then stand up the Phase-2 oracle and begin the core leaf modules
(`bytes → checksum → headers`), which need neither Npcap nor privilege.
