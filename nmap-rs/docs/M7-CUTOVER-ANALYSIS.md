# M7 cutover gate: host groups and the host timeout — Phase 0

Status: **Phase 0 written; D1–D7 await a decision (§8). No port code until they
are decided.** C line numbers are this tree's at `b5bebc249`. Everything marked
*measured* was run here against the installed oracle, Nmap 7.94SVN, on loopback.

## 0. Value

Three options in the MUST tier of [`M7.3-CLI-PARITY.md`](M7.3-CLI-PARITY.md) are
still refused: `--host-timeout`, `--min-hostgroup` and `--max-hostgroup`
(`timing-knobs-not-yet-enforced`). They are the last items of the cutover gate.
Each is refused for a reason that is still true: the engine has no per-host
deadline, and it scans every target of a run as one group.

They are worth more than three flags:

- **A bound the operator can set.** `--host-timeout` is nmap's only way to stop
  one slow host from holding a scan. `-T5` implies 15 minutes, which the port
  records and ignores.
- **Memory.** The port resolves every target, scans them all, then renders
  everything at the end. A `/16` holds 65,536 hosts' results before one line is
  printed. Host groups bound that to one group.
- **Results as they come.** 7.94 prints each group's hosts when the group
  finishes. The port prints nothing until the whole run ends.
- **Two ledgered divergences close.** `output-down-hosts-first` and
  `scan-repeated-target-deferred` both say "the port has one group".

## 1. What 7.94 does: host groups

### 1.1 Forming a group (`nmap.cc:2107-2200`)

The main loop asks for an ideal size, then pulls hosts until the group has that
many **up** hosts:

- **Size** (`determineScanGroupSize`, `scan_engine.cc:1218-1249`):
  - 16 by default;
  - 128 for a UDP or SCTP scan;
  - for a TCP scan, `max(1024 / tcp_ports, 64)`;
  - above 1,000 TCP ports at `-T4` or slower, the first group is 4 (8 at `-T4`),
    and the next is shortened by that much, to stay on network boundaries;
  - then boxed into `[--min-hostgroup, --max-hostgroup]` (defaults 1 and
    100,000, `NmapOps.cc:256-257`).

  UDP is tested first, so `-sS -sU` takes 128.
- **Down hosts do not count.** A host found down is reported and dropped as it is
  pulled (`nmap.cc:2151-2164`), and the loop continues.
- **A group is homogeneous** (`target_needs_new_hostgroup`, `targets.cc:276-314`).
  For a raw scan as root, a host that differs from the group's first in address
  family, interface, source address or direct-connectedness, or that repeats an
  address already in the group, is handed back and starts the next group
  (`nmap.cc:2192-2196`). `--min-hostgroup` does not override this.
- **The batch behind it.** Hosts come from a ping batch of up to 4,096
  (`PING_GROUP_SZ`, `nmap.h:206`; raised to `--min-hostgroup` if that is larger,
  `nmap.cc:2102`). The batch applies the same homogeneity test and **defers** a
  mismatching host to the next batch (`targets.cc:533-535`). So a mismatching
  host is overtaken by later hosts that match.

*Measured:*

| Command (all `-sT -Pn -n -v`, or `-sS` where said) | "Scanning N hosts" |
|---|---|
| `-p 1`, 70 hosts | 70 |
| `-p 1-20`, 70 hosts | 64, then 6 |
| `-p 1-2000`, 12 hosts | 4, then 8 |
| `-p 1 --max-hostgroup 2`, 5 hosts | 2, 2, 1 |
| `-sS -p 1 --min-hostgroup 3`, `127.0.0.1 <own address> 127.0.0.2` | 2 (the two 127 hosts), then the own address alone |

The last row shows both the split that `--min-hostgroup` cannot override and the
reordering: the third target is scanned and reported before the second.

### 1.2 What a group is the unit of

Every phase runs over the group, in order: port scans, `-sV`, `-O`, traceroute,
scripts, then output for each host (`nmap.cc:2200-2335`). Then the group is
freed and the next one formed. So results appear per group, and a host's whole
pipeline finishes before the next group's first probe.

### 1.3 Validation (`NmapOps.cc:578-590`, `nmap.cc:710-715`)

- Both values go through `atoi`.
- `--min-hostgroup` above the current maximum is fatal, and above 100 warns.
- `--max-hostgroup` below the current minimum is fatal. That check comes first, so
  `--max-hostgroup 0` says "may not be set to less than the minimum size
  (currently 1)" (*measured*); "Max host size must be at least 1" is unreachable.

The port already parses and validates these (M7.7, `options::hostgroup_error`).

## 2. What 7.94 does: the host timeout

### 2.1 The clock (`Target.cc:420-453`, `Target.h:96-101`)

Each target has a stopwatch: `msecs_used`, plus a running flag and start time.

- `startTimeOutClock` and `stopTimeOutClock` bracket work on the host.
  `msecs_used` accumulates across phases.
- `timedOut()` is `msecs_used + (running time) > o.host_timeout`. Strictly
  greater. With `host_timeout == 0` it is always false.
- `--host-timeout 0` means none, and overrides a template (`nmap.cc:738-746`,
  `:1499`). Only `-T5` sets one: 900,000 ms (`nmap.cc:1392`). *Measured* in `-d`:
  `host-timeout: 900000` under `-T5`, `0` otherwise.

### 2.2 Who starts, stops and checks it

| Phase | Starts | Checks | Stops |
|---|---|---|---|
| Host discovery | never (`scan_engine.cc:2011-2021`: discovery time is not charged) | never | — |
| Port scan (`ultra_scan`) | at the host's first probe (`:2247`) | at start, skipping a host already out (`:927`); before each send (`:546`); each pass over incomplete hosts (`:1151`) | when the host completes or times out (`:1202`) |
| `-sV` | when a service's first probe launches (`service_scan.cc:2331`) | at start (`:1974`); before launching each service (`:2327`); in the event handlers (`:2370`, `:2446`, `:2538`) | when the host's last service ends (`:2269`) |
| `-O` | `osscan2.cc:1691` | `:1538`, `:1608`, `:3259`, `:3343` | `:933`, `:3366` |
| Scripts | per host or port thread (`nse_main.lua:412`) | every thread, each scheduler pass (`nse_main.lua:405`) | `nse_main.lua:418` |
| Output | — | `nmap.cc:2296` | — |

The clock does not run between phases, nor while other groups are scanned.

### 2.3 What a timed-out host looks like

*Measured*, `-sT -Pn -n -p 1-3000 --scan-delay 20ms --host-timeout 1s 127.0.0.1`:

```
Nmap scan report for 127.0.0.1
Host is up (0.00014s latency).
Skipping host 127.0.0.1 due to host timeout
Nmap done: 1 IP address (1 host up) scanned in 1.06 seconds
```

- **Normal:** the report line, "Host is up", then "Skipping host X due to host
  timeout". No port table, and no blank line after it.
- **Grepable:** two records, `Status: Up` then `Status: Timeout`.
- **XML:** `<host starttime=… endtime=… timedout="true">` with status, address,
  hostnames and `<times>`. No `<ports>`.
- **The host still counts as up**, and the exit status is 0.
- Under `-v`: "127.0.0.1 timed out during Connect Scan (1 host left)", and
  "Completed Connect Scan …(2 hosts timed out)".

### 2.4 Quirks

- **Q1. Everything is discarded.** The check at output (`nmap.cc:2296`) is on the
  total. *Measured:* a port scan that finished in 0.00 s and found a port open,
  followed by a `-sV` probe that overran, prints only "Skipping host". The open
  port is not reported.
- **Q2. `-sV` does not enforce it.** *Measured:* under `--host-timeout 2s`, the
  service scan ran 6.01 s, the NULL probe's full wait. The checks sit before a
  launch and in handlers, and none cancels a probe in flight.
- **Q3. Scripts do enforce it.** *Measured:* a host script sleeping 5 s under
  `--host-timeout 2s` ended at 2.09 s.
- **Q4. A host that finishes inside its budget is kept, however small the
  budget.** *Measured:* `--host-timeout 1ms` with one port that answers at once
  reports the port.
- **Q5. A timed-out host is skipped by every later phase**, including a second
  port-scan type (`scan_engine.cc:927`).
- **Q6. The group clock.** A host's stopwatch starts at *its* first probe, not
  the group's. In a large group a host late in the send order has used none of
  its budget while earlier hosts were probed.

## 3. What the port has

- **Parsing and validation** of all three, with C's messages
  (`core::options`, M7.7), then a refusal in `cli::main` (`:88-103`).
  `TimingParams` carries `host_timeout_ms`, `min_hostgroup`, `max_hostgroup`, and
  nothing reads them.
- **One pass over all targets** (`cli::main`): resolve everything, `run_scan`
  over every address, then `-sV`, `-O` and scripts over the whole result, then
  render once (`emit_outputs`).
- **Engines:**
  - the connect scan (`sys::scan::connect_scan`), with a per-host scheduler and
    no notion of a deadline;
  - the raw engine (`sys::group`), which already groups by route and by repeat
    (`bucket_targets`), inside one call.
- **Later phases:** `sys::servicescan`, `sys::osscan` and `sys::fpengine`, and
  NSE, where `cnse.timedOut` is always false and the clock calls are no-ops
  (`nse-no-host-timeout`).
- **Output:** `core::output` renders a whole `ScanResults` at once, down hosts
  first (`report_order`). `Host` has no "timed out" state.
- **Not ported, and out of scope here:** host discovery (so no ping batch and no
  discovery time to exclude), `--randomize-hosts`, `-iR`, traceroute, idle and
  FTP-bounce scans, and the `-v` progress lines ("Initiating…", "Completed…").

## 4. Threat model delta

- **No new untrusted input.** Neither feature parses anything from the network.
  There is no new message a receiver must validate (the kit's §2a table is
  empty for this milestone).
- **Availability is the point.** Both options are bounds the operator sets, and a
  bound that is accepted and not kept is worse than one refused (M7.0). The
  milestone's security property: **a host's work stops by its timeout, and a
  run's memory is bounded by its group**. Each gets a scale check
  (`RESOURCE-BOUNDS.md`): peak memory at n and 4n hosts with a fixed group size
  must not grow with n.
- **`--min-hostgroup` is an amplifier.** A large value raises parallel load on the
  network and memory here. C warns above 100 and caps nothing. The port keeps
  the warning. Its memory per group is bounded by the group size the operator
  chose.
- **A hostile target can stall a phase** (a service that never answers, a tarpit).
  That is what the timeout is for. D4 decides whether the port stops at the
  deadline or, like 7.94's `-sV`, at the next convenient point.

## 5. Oracles

Everything here runs locally: IPv4 loopback, root, and 7.94 installed. No gate of
this milestone is CI-only except the FreeBSD copies.

1. **Group formation** — 7.94 itself, under `-v`. A generator runs a matrix and
   records the "Scanning N hosts" sequence and the order of reports:
   - scan type (`-sT`, `-sS`, `-sU`, `-sS -sU`, a flag scan);
   - port count (1, 16, 17, 64, 1000, 1001, 2000);
   - host count around each boundary;
   - `-T3`, `-T4`, `-T5`;
   - `--min-hostgroup` and `--max-hostgroup`, each alone and together, and each
     omitted (LESSONS #047, #057);
   - mixed routes and repeated targets, as root.

   The port's pure function is compared with the recorded sequences.
2. **Host timeout** — CLI differential with slow fixtures. Verdicts only, since
   times vary: which hosts are "Skipping", in normal, grepable and XML, per
   phase. Fixtures are built with wide margins:
   - a port scan slowed by `--scan-delay` against a short timeout;
   - a listener that accepts and never speaks (`-sV`);
   - a script that sleeps;
   - a host that finishes at once under a 1 ms timeout (Q4).
3. **The clock** — a pure stopwatch, unit-tested and Miri-checked with an
   injected time source.
4. **C sabotage of the corpus** (LESSONS #044) for the group function: variants
   of `determineScanGroupSize` and `target_needs_new_hostgroup` built from the
   tree, each of which the matrix must tell apart.

## 6. Claims not measured here

Per LESSONS #056, each is traced from the option's default and names where it
will be measured.

| Claim | Read from | Why unmeasured | Measured at |
|---|---|---|---|
| `-O` charges and checks the clock as §2.2 says | `osscan2.cc:933-3366` | not run yet; needs a slow OS-scan fixture | step d |
| Group sizes for UDP and SCTP scans (128) | `scan_engine.cc:1222-1225` | only TCP rows run so far | step a's matrix |
| The first-group rule at `-T4` (8) and `-T5` (none) | `scan_engine.cc:1228-1238` | only `-T3` run so far | step a's matrix |
| A repeated target starts a new group as root | `targets.cc:306-313` | read at IPv6 step e, never run | step a's matrix |
| FreeBSD forms the same groups | — | no FreeBSD here | CI's VM job, when CI runs |
| IPv6 targets group the same way | `targets.cc:287` | no IPv6 here | CI, when CI runs |

## 7. Proposed build order

| Step | Delivers | Gates |
|---|---|---|
| **a — group formation** | `core::hostgroup`: the size rule and the homogeneity and deferral rules, pure | the `-v` matrix against 7.94; C sabotage; fuzz not applicable (no untrusted input; exemption with reason) |
| **b — the group loop** | the CLI runs its pipeline per group and writes each group's hosts as it finishes; renderers split into header, host and footer; `--min/--max-hostgroup` accepted | output byte-identical to today's for one group; order and separators against 7.94 for several; memory flat at n and 4n hosts |
| **c — the clock in port scans** | `core::hosttimeout`; the connect and raw engines honour it; `Host` gains a timed-out state; the three output formats | fixture differential, port-scan phase; unit tests and Miri |
| **d — `-sV` and `-O`** | both phases charge and check the clock; a timed-out host is skipped by later phases | fixture differential per phase; the `-O` row of §6 measured first |
| **e — scripts** | `cnse.timedOut` and the clock calls are real (`nse-no-host-timeout` resolved) | fixture differential with a sleeping script |
| **f — close** | `-T5`'s 15 minutes enforced; the refusals removed; `timing-knobs-not-yet-enforced` resolved; MUST tier complete | the M7.3 table re-run; full matrix |

`--host-timeout` stays refused until step f. Accepting it after step c would
keep the bound for port scans and drop it for `-sV`.

Each step ends as the kit now requires (LESSONS #052–#055): an independent
review, repeated on its fix round until a round confirms nothing, then
`stamp … reviewed`; sabotage through `harnesses/sabotage/sabotage.py`, with a
mutation naming the pin of every ledgered fix; and a `ci-local` record on the
tree that is pushed.

## 8. Decisions

- **D1 — How faithful is group formation?**
  - (a) 7.94's whole rule: sizes by scan type and port count, the first-group
    rule, homogeneity, deferral and its reordering.
  - (b) Only the operator's bounds: one group unless `--max-hostgroup` is given.

  *Recommended: (a).* The default sizes decide the order of reports and when
  results appear, and (b) leaves both ledger entries open.
- **D2 — Does output stream per group?**
  - (a) Yes, to the terminal and to `-oN`, `-oX` and `-oG`, as 7.94 does.
  - (b) No: groups bound the scanning, and the report is still written once.

  *Recommended: (a).* It is what bounds memory, and a long scan that prints
  nothing until it ends is a regression users will meet first. It costs a
  renderer split, and an interrupted run leaves an unfinished XML file, as
  7.94's does.
- **D3 — Is a timed-out host's partial work discarded (Q1)?**
  - (a) Yes, as 7.94: "Skipping host", no ports.
  - (b) Report what was found, marked incomplete.

  *Recommended: (a).* (b) is friendlier and is not what any tool reading nmap's
  output expects. Ledger it as a C behaviour reproduced.
- **D4 — Is the timeout enforced where 7.94 only checks it (Q2)?**
  - (a) Enforce: work on the host is cancelled at the deadline in every phase.
  - (b) Reproduce: `-sV` finishes the probe in flight.

  *Recommended: (a).* The verdict is the same either way, since a host over its
  budget is skipped at output in both. Only the elapsed time differs, and the
  option exists to bound it. Ledger it as a deliberate fix.
- **D5 — `-T5`'s implied 15 minutes.** *Recommended: enforce it at step f*, as
  7.94 does. Today it is recorded and ignored.
- **D6 — The `-v` progress lines** ("X timed out during Connect Scan (1 host
  left)", "Completed … (2 hosts timed out)"). The port prints none of the
  "Initiating"/"Completed" family.
  - (a) Out of scope; ledger the two timeout lines with the family.
  - (b) Port the family here.

  *Recommended: (a).*
- **D7 — Where this lands.** *Recommended: its own PRs, one per step*, after
  #160 (the retrospective) merges, so each step's review and `ci-local` record
  are on a small diff.

## 9. Not verified

- Nothing in §1 or §2 was run as root over a real interface, on FreeBSD, or over
  IPv6. §6 lists what follows from that.
- The `-v` matrix of §5.1 is designed, not built. The five rows of §1.1 are the
  only group sizes measured so far.
- CI has not run since 3 November. This document changes no code, so nothing
  here depends on it; step a's PR will carry a `ci-local` record.
