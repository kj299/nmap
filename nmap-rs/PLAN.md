# Plan — Rewrite nmap from C to Rust on Windows (full multi-milestone port)

Driven by the **c2rust-port Porting Kit** (`kj299/c2rust-port`). This is a long,
multi-milestone project; **"go big or go home"** — the full nmap core engine
including raw scanning, OS detection, and NSE. This file is the durable plan of
record; edit it as milestones complete.

---

## ⚑ STATUS TRACKER — where we are (keep current every session)

| # | Milestone | Kit cycle | State |
|---|---|---|---|
| — | **Planning** | — | ✅ **DONE** (this document) |
| 0 | Kit vendored + workspace skeleton + CI | Phase 3 | ✅ **MERGED** — squashed to `master` `16f8ea1` (PR #1) |
| 1 | **MVP: unprivileged TCP connect scan → output** | full cycle | 🔶 **CURRENT** — merged: …`timing`, `sys::net`; `connect_scan` done (end-to-end scan works: open/closed detected); next: `output` then `cli` |
| 2 | Full async engine (`nsock`→tokio) + full `ultra_scan` | full cycle | ⬜ |
| 3 | Service / version detection (`-sV`) | full cycle | ⬜ |
| 4 | **Raw-packet infrastructure + all raw scans** (privileged) | full cycle | ⬜ |
| 5 | OS detection (IPv4 `osscan2` + IPv6 `FPEngine`) | full cycle | ⬜ |
| S | **Signature DB maintenance mechanism** (OS/service/MAC) | cross-cutting | ⬜ |
| 6 | NSE — Lua engine + bridges + scripts | full cycle | ⬜ |
| 7 | Cutover + subprojects (`ncat`/`nping`) | Phase 5 | ⬜ |

> **We are here:** Milestone 0 is complete and pushed (kit vendored at `porting-kit/`,
> `nmap-rs/` workspace up, six skill symlinks in `.claude/skills/`, path-scoped CI
> wired with differential/fuzz gates stubbed to skip "until targets exist", PR #1
> Rust jobs green). **The immediate next action is Milestone 1 Phase 0** — invoke
> `porting-kit-kickoff` (inventory + `cflaw-scan` + `THREAT-MODEL.md`) and
> `porting-kit-oracle` in parallel, present the Phase-0 report + confirmed port
> order, and **stop for approval before writing any Rust** (kit requirement).
> Each milestone is its own kit cycle: `kickoff → (cflaw-scan ∥ oracle) → per-module
> six-gate loop → audit → retrospective-that-patches-the-kit`. **Never skip the
> retrospective** — it is the one rule that makes the kit worth having.

**Sequencing rationale (why this order, and where raw lands).** Order follows the
kit's "roots-before-dependents, cheapest-and-safest-first, spike-the-scary-module-
before-scheduling-it." The connect scan (M1) is unprivileged and needs no Npcap —
the safe way to prove the whole pipeline. Raw scanning (M4) is the scariest,
highest-privilege, most Windows-specific phase, so it is deliberately deferred to
**after** the engine, async layer, and service detection are battle-tested and the
kit has been hardened by three retrospectives. OS detection (M5) **consumes** the
raw infrastructure, so it must follow M4. NSE (M6) needs everything, so it is
genuinely last. Raw scanning is thus the final *infrastructure* phase — promoted
from a footnote to a first-class milestone, as requested.

---

## Context & prime directive

nmap: ~55k LOC of core C++ at repo root + 10 bundled C libraries + an async socket
layer (`nsock`) + a raw-packet layer (`libdnet`+Npcap) + an ML OS-detector + a
612-script Lua engine (NSE). The kit's **prime directive**: the Rust must be
**safer and more secure than the C, not merely equivalent**. The C is a
specification that *may itself be buggy* — never faithfully re-implement a
vulnerability; every behavioral divergence is triaged (Rust bug vs. intentional
fix of a C defect) and the intentional ones are logged in `DIVERGENCES.md`, never
silently matched. Maximize safety controls; all are cheap relative to a CVE.

**Two standing decisions (agreed with user):**
- **Dependencies = pure-Rust crates** wherever mature; **FFI reserved for Npcap**
  (no pure-Rust Windows raw-packet driver exists) and PCRE2 if regex fidelity to
  `nmap-service-probes` demands it.
- **Full scope**, delivered as the milestone ladder above.

**Port classification (kit Phase 0 step 5) — hybrid, matching `core`/`sys`/`cli`:**
- **Translate → `core`** (`#![forbid(unsafe_code)]`): all portable logic — target
  expansion, port/service parsing, scan-result model, timing/congestion math,
  packet *building/parsing*, fingerprint matching, output rendering.
- **Reimplement behind a seam → `sys`** (only crate allowed `unsafe`): the
  OS-acquisition layer — async sockets (`nsock`→tokio), raw send/capture (Npcap
  FFI), interface/route enumeration (`windows` crate / IP Helper, replacing
  `libdnet .*-win32.c`). Every FFI call in a small audited safe fn; every OS
  resource an RAII type.

---

## Target architecture (kit `skeleton/`, refocused on unsafe isolation)

Rust workspace lives **beside** the untouched C tree; the C stays runnable as the
differential oracle through cutover (kit Phase 5 discipline). Unlike lsof, **C nmap
runs on both Windows and Linux**, giving us the kit's *easy* same-binary
differential mode throughout.

```
nmap/                      # existing C tree — untouched → the oracle
├─ porting-kit/            # vendored kj299/c2rust-port (docs + harnesses + skills)
├─ .claude/skills/         # symlinks → porting-kit/skills/porting-kit-*
└─ nmap-rs/                # NEW Rust workspace (from porting-kit/skeleton/)
   ├─ Cargo.toml           # overflow-checks=true, lto, workspace safety lints
   ├─ crates/
   │  ├─ core/  #![forbid(unsafe_code)]   ← MOST logic; testable on Linux CI, fuzzed
   │  ├─ sys/   the ONLY unsafe crate     ← tokio sockets; later Npcap FFI + windows
   │  └─ cli/   thin: argv → Scan request → core+sys → render
   ├─ DIVERGENCES.md   ├─ THREAT-MODEL.md   └─ deny.toml
```

**Workspace-wide safety controls (from skeleton, non-negotiable):**
`#![forbid(unsafe_code)]` on `core`; `unsafe_op_in_unsafe_fn=deny`;
clippy `undocumented_unsafe_blocks` + `missing_safety_doc` + `cast_possible_truncation`
+ `arithmetic_side_effects` (all `-D` in CI); `overflow-checks=true` even in release.

**The six gates every module clears before merge** (kit Phase 4, CI-enforced):
`ported → differential → fuzzed → sanitized → unsafe-audited → pinned+merged`.
Harnesses: `unsafe-audit/audit_unsafe.py` (hard-fail on undocumented `unsafe`),
`differential/diff_run.py` (stdout **and** exit code; ledger-aware; per-case timeout
= liveness backstop), `fuzz/gen_fuzz_target.sh` (cargo-fuzz), `sanitizers/run_sanitizers.sh`
(Miri/ASan/UBSan/TSan), `supply-chain/run_supply_chain.sh` (`cargo audit`+`cargo deny`),
`progress/progress.py` (status), `c-flaw-scan/scan_c_flaws.py` (Phase 0).

---

## Milestone 0 — Foundation (kit Phase 3 + preflight)

- Vendor `kj299/c2rust-port` → `nmap/porting-kit/`; symlink `porting-kit/skills/
  porting-kit-*` → `.claude/skills/`; run `make -C porting-kit check-kit` (python3+
  bash only) to confirm harnesses work here.
- Copy `porting-kit/skeleton/` → `nmap-rs/`; keep `#![forbid(unsafe_code)]` on `core`.
- Wire `harnesses/ci/porting-ci.template.yml` into GitHub Actions, **path-scoped to
  `nmap-rs/**`** so it never triggers the heavy C autotools build (LESSONS #5).
- Scaffold a `TRACE` env-gated phase logger **on day one** (retrospective habit #5 —
  it was added reactively at hang-fix step 4/5 in winlsof).
- **Windows preflight** (LESSONS #1): target **`x86_64-pc-windows-msvc`** (matches
  nmap's own MSVC Windows build + the Npcap SDK needed in M4; avoids the winlsof
  MSVC-vs-GNU linker time-sink); verify `target/` isn't a synced/locked folder.
- **Exit:** workspace builds; `core` is `forbid(unsafe)`; unsafe-audit gate wired;
  trace logger present; preflight clean.

---

## Milestone 1 — MVP: unprivileged TCP connect scan  ⬅ NEXT

**Goal:** the smallest end-to-end vertical slice that proves the kit on nmap:
`-sT` connect scan + host discovery + normal/grepable/XML output. Needs **no
Npcap, no Administrator, no raw packets** — it sidesteps every hazard the winlsof
retrospective bled over and should ship at **~0 `unsafe`** (a headline result).

**Kit cycle:**
- **Phase 0** (`porting-kit-kickoff` + `porting-kit-cflaw-scan`): seed
  `progress.py` over the MVP modules; run `scan_c_flaws.py` on the MVP C sources
  and triage hits into `DIVERGENCES.md` — **tune the scanner for signal-to-noise
  first** (LESSONS #2: 828 false positives once buried the real ones). Classify the
  FFI surface: only `connect()`/DNS via tokio — bounded by timeout, unprivileged,
  not version-variant → **no spike needed**. Fill `THREAT-MODEL.md`: untrusted
  boundaries = CLI target/port-spec parser, `nmap-services` file parser, DNS
  responses (the fuzz-first list); privilege = none (state it).
- **Phase 2** (`porting-kit-oracle`, ∥ with cflaw-scan): lock C nmap at a commit;
  **same-binary differential** — capture golden `nmap -sT -oX -`/`-oN`/`-oG` over a
  documented matrix against **local-listener fixtures** (loopback listeners on known
  open ports + closed/filtered ports, reproducible). `golden.py` detects
  nondeterminism (scan duration, timestamps, `<runstats>` elapsed, host order,
  latency) → `normalize.py` masks it symmetrically. Verdict = stdout **and** exit
  code (LESSONS #4). Seed `DIVERGENCES.md` from the flaw scan.
- **Phase 4 module loop (leaf-first):**
  1. `core::model` — `Target`, `Port`, `PortState`, `ScanResult` (`Target.h`, `portlist.h`)
  2. `core::targets` — CIDR/range/hostname expansion (`TargetGroup.cc`, `targets.cc`) — **fuzz**
  3. `core::options` + `core::log` — **verbosity/debug pulled forward**: `-v`/`-vv`/`-vN`,
     `-d`/`-dN` (nmap `o.verbose`/`o.debugging`, `box(0,10,·)`) + a leveled `verbose!`/`debug!`
     logger to **stderr** (keeps stdout differential-clean). Done early so every module below
     is diagnosable during development (kit habit #5). Starts the `NmapOps` analog.
  4. `core::ports` — port-spec + `nmap-services` parse (`scan_lists.cc`, `services.cc`) — **fuzz**
  5. `core::timing` — minimal timeout/parallelism math (`timing.cc` subset)
  6. `sys::net` — async TCP connect-with-timeout + DNS (`tokio`, `hickory-resolver`)
  7. `core+sys::connect_scan` — bounded-concurrency connect driver (`scan_engine_connect.cc`)
  8. `core::output` — normal / grepable / XML renderers (`output.cc`, `xml.cc`) — **golden**
  9. `cli` — argv → `Scan` request → run → render (`nmap.cc` getopt subset, growing `NmapOps`)

**Crates:** `tokio`, `hickory-resolver`, `ipnet`/std, `clap` (or hand-rolled to
match nmap's exact flags), `quick-xml`/hand-rolled (nmap XML DTD), `arbitrary`+`cargo-fuzz`.
**Windows:** default output ASCII with UTF-8 opt-in (winlsof CP-1252 saga).
**Exit:** all 8 modules through six gates; differential corpus green; `-sT` on
Windows cross-checked vs `Get-NetTCPConnection` (native oracle) and vs C nmap `-oX`.
**Retrospective** → patch kit + `LESSONS.md`.

---

## Milestone 2 — Full async engine + complete `ultra_scan`

**Goal:** replace nmap's async core (`nsock`) with `tokio` and port the full
`ultra_scan` state machine (`scan_engine.cc`, 2844 LOC) — host groups, congestion
control, retransmission, RTT-adaptive timing — still exercised over the connect
path so it's testable without privilege. This is the scan-engine backbone all later
scan types plug into.

- **C→Rust:** `scan_engine.{cc,h}` (state machine → `core` logic + `sys` I/O
  driver), full `timing.cc` (congestion window, ramp/backoff, `--min-rate`/`--max-rate`),
  `nsock/` connect+event-loop semantics → tokio tasks/`select!`.
- **Hazard/spike:** the congestion-control + retransmission timing is subtle;
  **spike** a faithful port of the timing math against captured C traces before
  committing. TSan over the concurrent driver (the winlsof hang-class).
- **Oracle:** differential `nmap -sT` with varied `--min-rate`/`-T<0-5>`/large host
  groups vs Rust; timing normalized, port-state results exact.
- **Exit:** engine handles multi-host groups at parity; TSan clean. Retrospective.

---

## Milestone 3 — Service / version detection (`-sV`)

**Goal:** port `service_scan.cc` (2896 LOC) — probe scheduling + matching responses
against `nmap-service-probes` (2.5 MB). Runs over the M2 async engine (socket I/O,
no raw needed).

- **C→Rust:** `service_scan.{cc,h}`, probe-DB parser, the soft/hard-match state
  machine, `nmap_ftp.cc` (FTP bounce). Version-info substitution + CPE.
- **Regex fidelity (decision point):** `nmap-service-probes` uses PCRE syntax. Try
  the pure-Rust `regex` crate first; where a probe uses backreferences/lookaround,
  fall back to `fancy-regex` or **FFI to PCRE2** (the one sanctioned non-Npcap FFI).
  Validate by running every probe pattern against a corpus first (C-baseline-validate).
- **Threat model:** service banners are **untrusted network input** → fuzz the
  match engine hard (no panic/OOM on hostile banners; cap length-derived allocs).
- **Oracle:** differential `nmap -sV` against local fixture services (http, ssh
  banner, ftp, etc.); the divergence ledger absorbs any deliberately-safer parsing.
- **Exit:** `-sV` at parity on the fixture matrix; fuzz clean. Retrospective.

---

## Milestone 4 — Raw-packet infrastructure + all raw scans (the big privileged phase)

**Goal:** the full privileged scanning suite. This is the scariest, most
Windows-specific milestone — run the kit's **spike-and-gate ritual** on each hard
piece before committing (effort/confidence rating + written decision gate + pivot
check, per LESSONS #1 / retrospective §6.3).

- **`sys` raw layer (unsafe lives here, all audited):**
  - **Npcap FFI** for raw send + capture — no pure-Rust equivalent; wrap in RAII
    (`OwnedPcapHandle`) + small audited safe fns. **Spike first:** confirm Npcap SDK
    linkage on `-msvc`, packet inject + capture on loopback/Npcap "Adapter for
    loopback traffic."
  - **Interface/route/ARP enumeration** via the `windows` crate (IP Helper API) —
    replaces `libdnet .*-win32.c` (`intf-win32.c`, `route-win32.c`, `arp-win32.c`).
  - Integrate capture into the tokio loop (replaces `nsock/src/nsock_pcap.c` +
    `engine_iocp.c`) — **spike** the "pcap fd in an async runtime on Windows"
    question (Npcap handle → mio/`AsyncFd` vs. a dedicated blocking capture thread
    feeding a channel). Treat any hang as a design smell to design out.
- **`core` packet build/parse:** port `libnetutil/` (`IPv4Header`, `IPv6Header`,
  `TCPHeader`, `UDPHeader`, `EthernetHeader`, `ICMPv4/6`, `SCTP`, `PacketParser`) —
  prefer hand-port into `core` with `pnet_packet`/`etherparse` as reference; all
  checksum/bit math `checked_*`, bounds by construction.
- **Raw send/recv chokepoint:** port `tcpip.cc` (`send_ip_packet`, `send_tcp_raw`,
  `send_udp_raw`, decoys, `readip_pcap`, `nmap_route_dst`, `setTargetMACIfAvailable`).
- **Scan types → `scan_engine_raw.cc` (2201 LOC):** `-sS` SYN, `-sA` ACK, `-sW`
  Window, `-sM` Maimon, `-sN/-sF/-sX` null/FIN/Xmas, `-sU` UDP (+ `payload.cc`),
  `-sO` IP-proto, `-sY/-sZ` SCTP. Plus **`idle_scan.cc`** (`-sI` zombie),
  **`traceroute.cc`**, and **raw host discovery** (ARP, ICMP echo/timestamp/netmask,
  TCP/UDP ping).
- **Privilege:** gate raw ops behind an explicit capability check (`o.isr00t` analog
  = Administrator + Npcap access); RAII `PrivilegeGuard`; degrade gracefully to
  connect scan when unavailable (never hard-fail).
- **Threat model:** captured packets are **untrusted network input** → fuzz every
  packet parser (`arbitrary`-typed); ASan/UBSan/TSan over the whole `sys` raw layer.
- **Oracle:** differential vs C nmap for each scan type against local fixtures +
  a controlled test network; normalize source-port/IP-ID/timing; verify on real
  Windows with Npcap installed.
- **Exit:** every raw scan type at parity; unsafe-audit reports 0 undocumented;
  sanitizers clean; no hangs under the timeout backstop. Retrospective (expect the
  richest lessons here — feed them back into the kit's hazardous-API notes).

---

## Milestone 5 — OS detection (depends on M4 raw layer)

**Goal:** active OS fingerprinting. Consumes the raw send/capture from M4.

- **IPv4:** `osscan2.cc` (3552 LOC) probe engine + `osscan.cc` fingerprint DB
  parse/match against `nmap-os-db` (5.3 MB); `FingerPrintResults.cc`, `MACLookup.cc`
  (`nmap-mac-prefixes`).
- **IPv6:** `FPEngine.cc` (2730 LOC) + `FPModel.cc` (2.8 MB generated ML weights =
  data) — a logistic-regression classifier backed by `liblinear`. **Port only the
  inference path** (prediction, not training) — reimplement in `core` (pure math) or
  via `linfa-logistic`; the weights are data to load.
- **Threat model:** fingerprint responses are untrusted → fuzz the parser/classifier.
- **Oracle:** differential `nmap -O` vs Rust against fixtures with known OS
  signatures; fingerprint-match output exact, classifier scores within tolerance
  (normalize float formatting).
- **Exit:** `-O` at parity on the fixture set; inference numerically matches C
  within documented tolerance. Retrospective.

---

## Workstream S — Signature database maintenance mechanism (cross-cutting; **new**)

**Why:** nmap's detection depends on shipped signature databases — `nmap-os-db`
(OS), `nmap-service-probes` (service/version), and `nmap-mac-prefixes` (MAC vendor
→ network-node/device identity) — but **nmap has no in-tool mechanism to update
them or to collect unmatched fingerprints**. Today it only *prints* unmatched
fingerprints and asks the user to paste them into a web form
(`output.cc:834` service, `output.cc:1901/1925/1938` OS); `--script-updatedb`
rebuilds only the local **NSE script index**, not these DBs. The DBs otherwise
change solely by shipping a new nmap release. This workstream builds the missing
maintenance loop as a first-class, security-reviewed feature of the Rust port.

**Design (four parts):**
1. **Versioned, signed bundles.** Each DB gets a manifest (schema version, content
   version/date, SHA-256, source). Bundles are **cryptographically signed**
   (minisign/cosign) and the loader records the loaded version (surfaced in
   `--version`/verbose). A `SignatureStore` type in `core` owns load + version query.
2. **Update channel** (`sys::update`, unprivileged): `nmap-rs --update-signatures`
   fetches the latest signed bundle from a **pinned HTTPS source**, verifies
   signature **and** checksum, and **atomically** swaps it into the per-user data
   dir (never silently overwrites a system copy). `--check-signatures` reports
   current-vs-available; `--import-signatures <file>` supports **offline/air-gapped**
   manual import; verify-fail ⇒ keep the old DB (rollback), never run on unverified data.
3. **Local collection + submission pipeline** (`core::fingerprint_store`): nmap
   already *computes* the unmatched OS/service fingerprints — capture them into a
   local, **opt-in, consent-gated** store (privacy-reviewed: no payloads, secrets,
   or PII beyond the fingerprint itself), with `--export-fingerprints` and an
   optional structured submit to a configured endpoint. Replaces copy-paste-to-web
   with a reviewable pipeline that feeds the update loop (and mirrors nmap's intent).
4. **Integrity as a threat-model item.** Signature DBs are **trusted inputs whose
   poisoning misleads detection** → updates MUST be signed+verified (ties into the
   kit's supply-chain gate + `SECURITY-CHECKLIST` per-release). DB **parsing** is
   untrusted-input-shaped regardless → the M3/M5 fuzz targets cover the parsers;
   the update path adds its own fuzz/negative tests (malformed/renamed/downgraded
   bundle, bad signature, truncated download).

**Build order:** the DB **parsers + version metadata** land naturally with **M3**
(`nmap-service-probes`) and **M5** (`nmap-os-db`, `nmap-mac-prefixes`). The
**update channel + collection/submission pipeline** is its own deliverable,
implemented **alongside M5** and hardened at **M7** (it's a signing/supply-chain
concern). Track as workstream **S** in the status table.
**Gates:** same six, plus the per-release supply-chain + signing controls. **Oracle:**
the loaders differential-match C nmap's DB parsing (same matches on the same DB);
the update/submission paths are new behavior → golden + negative tests, ledgered in
`DIVERGENCES.md` as an intentional additive feature.

---

## Milestone 6 — NSE (Nmap Scripting Engine) — last, largest

**Goal:** the Lua scripting engine — a major fraction of nmap's real-world value.

- **Embed Lua** via `mlua` (Lua 5.4, matching bundled `liblua` 5.4.8); keep the 147
  `nselib/` libraries + 612 `scripts/*.nse` **as-is** (they define the API surface
  to preserve — treat as data + conformance oracle).
- **Reimplement the C↔Lua bridges** (`sys`/`core` as appropriate):
  `nse_main.{cc,lua}` (scheduler), `nse_nmaplib.cc` (exposes targets/ports/host
  state), `nse_nsock.cc` (async sockets → tokio), `nse_dnet.cc` (raw send → M4
  layer), plus binding shims `nse_ssl_cert.cc`/`nse_openssl.cc` (→ `rustls`),
  `nse_libssh2.cc` (→ `russh` or `ssh2`), `nse_zlib.cc` (→ `flate2`),
  `nse_lpeg.cc`/`lpeg.c` (→ `rust-lpeg` or FFI), `nse_utility/db/fs/debug`.
- **Hazard:** the async coroutine scheduler bridging Lua coroutines to tokio is the
  hard part — **spike** the `mlua` + async integration before committing.
- **Threat model:** scripts + all their network I/O are untrusted; sandbox
  considerations; fuzz the bridge marshalling.
- **Oracle:** run representative `.nse` scripts (e.g. `http-title`, `ssl-cert`,
  `banner`) under Rust-NSE vs C-nmap-NSE against fixtures; compare script output.
- **Exit:** a documented, growing subset of scripts run at parity (full 612-script
  parity is an ongoing tail). Retrospective.

---

## Milestone 7 — Cutover, subprojects, release

- **Cutover** (kit Phase 5) per phase: gate on all target modules through six
  gates; differential green (modulo ledgered divergences); fuzz seeded+clean;
  supply-chain clean; least-privilege verified; ASCII-default output. Keep C nmap
  as oracle through one overlap release, then archive (don't delete).
- Ship `DIVERGENCES.md` as **release notes** — the security fixes over C are a
  feature. SBOM (`cargo cyclonedx`), auditable build (`cargo auditable`), signed
  releases (cosign/minisign), reproducible+checksummed. Code-sign the Windows
  binary (unsigned → SmartScreen/AV friction).
- **Subprojects (separable, optional):** `ncat` (C, own binary) and `nping` (C++,
  uses libnetutil/nsock — reuses M4 layer) can each be their own kit cycle.
  **Out of scope:** `ndiff` (Python), `zenmap` (GTK Python GUI).

---

## Critical files
- **Kit (read; do not restate divergently):** `porting-kit/PLAYBOOK.md`, `CLAUDE.md`,
  `RETROSPECTIVE-lsof.md` §6/§9, `C-to-Rust-Playbook-Best-of-Both.md`,
  `SECURITY-CHECKLIST.md`, `skeleton/`, `harnesses/*`, `skills/porting-kit-*`.
- **nmap C by milestone:** M1 `Target/TargetGroup/targets/portlist/scan_lists/
  services/timing/scan_engine_connect/output/xml/nmap(argparse)`; M2 `scan_engine/
  timing/nsock`; M3 `service_scan/nmap_ftp` + `nmap-service-probes`; M4 `tcpip/
  libnetutil/*/libdnet-*-win32/scan_engine_raw/idle_scan/traceroute/payload` +
  Npcap; M5 `osscan2/osscan/FPEngine/FPModel/liblinear/MACLookup` + `nmap-os-db`;
  M6 `nse_*` + `nselib/` + `scripts/`.
- **New Rust:** `nmap-rs/crates/{core,sys,cli}/…`, `nmap-rs/{DIVERGENCES,THREAT-MODEL}.md`.

## Verification (per milestone, escalating)
1. **core on Linux CI** — unit + golden tests on the cheap runner every push.
2. **Differential** — `diff_run.py --oracle <C nmap> --rust <nmap-rs> --matrix
   <milestone>.toml --ledger DIVERGENCES.md`; MATCH on stdout+exit or a ledgered divergence.
3. **Fuzz** — `cargo fuzz run <target> -- -max_total_time=60`; zero panics/crashes
   on every untrusted-input parser (grows each milestone).
4. **Sanitize + audit** — Miri on `core`; ASan/UBSan/TSan on `sys`; `audit_unsafe.py`
   0 undocumented; `cargo audit`/`cargo deny` clean.
5. **Windows real run** — build `-msvc`, run against localhost/known hosts, cross-check
   with native oracles (`Get-NetTCPConnection`, `netstat`, packet captures) and diff
   `-oX` vs C nmap on Windows. M4+ requires Npcap installed + Administrator.

## Next concrete steps
1. ✅ **M0 (done):** kit vendored → `porting-kit/`, skills symlinked, `make check-kit`
   green; `skeleton/` → `nmap-rs/`; path-scoped CI wired; Windows-msvc preflight.
   Committed (`278f403`, `6108be3`), PR #1 open with Rust jobs green.
2. 🔶 **M1 Phase 0 (next):** invoke `porting-kit-kickoff` — inventory + `cflaw-scan`
   (tune for signal-to-noise first) + `THREAT-MODEL.md`; in parallel invoke
   `porting-kit-oracle` to lock C nmap + build the connect-scan differential matrix
   against local-listener fixtures. Present the Phase-0 report + confirmed leaf-first
   port order, then **stop for approval before any Rust** (kit requirement).
3. On approval, begin the M1 six-gate loop at `core::model`; **update the STATUS
   TRACKER** above as each module/milestone advances (the "don't lose the phase" rule).
