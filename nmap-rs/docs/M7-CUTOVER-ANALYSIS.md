# M7 cutover gate: host groups and the host timeout — Phase 0

Status: **Phase 0 written; D1–D7 decided 2026-11-21, all as recommended (§8).
Step a (group formation) is done: §10. Step b (the group loop) is done: §11.** C line numbers are this tree's at `b5bebc249`. Everything marked
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
- **Down hosts take no place.** A host found down is reported and dropped as it is
  pulled (`nmap.cc:2151-2164`), and the loop continues. It is still added to
  `o.numhosts_scanned`, which the size rule reads for its quick group
  (*corrected at step a's review; this said they "do not count"*).
- **A group is homogeneous** (`target_needs_new_hostgroup`, `targets.cc:276-314`).
  As root with `RawScan()` true (every raw port scan, and a connect scan with
  `-O` or `--traceroute`, or without `-Pn`), a host that differs from the group's first in address
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
- **Not ported, and out of scope here:** host discovery other than the IPv6 ND
  ping, which the raw engine runs per route-group after grouping (so no ping
  batch; *corrected at step a's fourth review, this said there was no discovery
  time to exclude*: whether the ND ping's time is charged to the host clock is
  step c's to settle, and 7.94 charges none, §2.2), `--randomize-hosts`, `-iR`, traceroute, idle and
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
| Group sizes for UDP scans (128) | `scan_engine.cc:1222-1225` | — | **measured at step a** (§10) |
| Group sizes for SCTP scans (128) | `scan_engine.cc:1222-1225` | the port has no SCTP scan to compare | when SCTP scans are ported |
| The first-group rule at `-T4` (8) and `-T5` (none) | `scan_engine.cc:1228-1238` | — | **measured at step a** (§10) |
| A repeated target starts a new group as root | `targets.cc:306-313` | — | **measured at step a** (§10) |
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

**Decided 2026-11-21: all seven as recommended.** D1 (a) 7.94's whole rule; D2
(a) output streams per group; D3 (a) a timed-out host's partial work is
discarded; D4 (a) the timeout is enforced at the deadline in every phase; D5
`-T5`'s 15 minutes at step f; D6 (a) the `-v` progress lines stay out of scope;
D7 one PR per step.

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
- The `-v` matrix of §5.1 is built (§10). It runs on loopback with one address
  of the host's own as the second route, so the interface and
  direct-connectedness rules and the address-family rule are unit-tested and
  not compared with 7.94.
- CI has not run since 3 November. Each step's PR carries a `ci-local` record
  and names what that record leaves unrun.

## 10. Step a: group formation

`core::hostgroup` ports `determineScanGroupSize`, `target_needs_new_hostgroup`
and the batch behind them (`refresh_hostbatch`, `nexthost`, `returnhost`) as a
pure iterator: targets in, groups out. Nothing calls it yet; step b does.

**What Phase 0 had not read.** §1.1 says a mismatching host is deferred to the
next batch. The rest of that mechanism decides the order of reports, and the
matrix measured each part:

- The defer buffer holds 64 (`DEFER_LIMIT`, `targets.h`). The target that fills
  it ends the batch, so targets after it are not drawn into that batch even if
  they fit.
- Deferred targets are drawn before the source when the next batch is filled.
- A full batch does not look at the next target. So `l1-l4096,own,l4097` puts
  `own` at the head of the second batch and `l4097` waits behind it, while under
  `--min-hostgroup 5000` (a batch of 5,000) `own` is deferred and `l4097`
  overtakes it.
- The quick-group rule reads the hosts of every group so far
  (`o.numhosts_scanned`), so only the run's second group is shortened.

**The gate.** `tests/differential/m7/gen_hostgroup_golden.py` runs 7.94 under
`-Pn -n -v` over 65 cases and reads each group's size and the order of reports
from nmap's own output. The cases cover:

- eight scan kinds: `-sT`, `-sS`, `-sA`, `-sU`, `-sS -sU`, `-sU -sS`, `-sO`
  (neither TCP nor UDP) and `-sT -O` (a routed connect scan);
- port counts 1, 2, 15, 16, 17, 20, 64, 1000, 1001 and 2000;
- `-T0` to `-T5`;
- `--min-hostgroup` and `--max-hostgroup`, each alone, together, and absent;
- a second source, repeated addresses (the group's first and a later one), the
  defer buffer at 63, 64 and 65, and the batch at 4,095, 4,096, 4,097 and at
  `--min-hostgroup 5000` exactly.

`crates/core/tests/hostgroup_differential.rs` requires the port to give the same
sizes and the same order on every case. It does. The golden was generated from
the installed 7.94SVN and matches a build of this repository's 7.94 commit
(`3be01efb1`). The first 55 cases also matched a build of the tree's current C.

**The golden can tell broken C apart, as far as it has been tried.**
`sabotage_c_hostgroup.py` builds 29 variants of the C, one changed rule each, and
requires the generator's `--check` to fail on each. All 29 are caught. That
number was reached in rounds, and each found the golden or its harness short:

- my own first 23 variants found one gap (every later group shortened, not only
  the second), closed by `-p 1-1001` over 130 hosts;
- one variant as first written produced an nmap that scanned nothing, and was
  rewritten to one that runs;
- the independent review then built four broken variants that passed all 55
  cases, and named two more; they are the last six of the 29, and ten cases
  were added for them;
- two variants that let an address into a group twice then hung the broken nmap
  on a new case (it waits out every probe of the copy). A hang is not a catch
  (LESSONS #044), so the generator now passes over a case that does not finish
  and goes on comparing; both variants are caught by a case that ran to its end.

So "all caught" is a statement about these 29, not about every wrong C.

**The tests can tell a broken port apart.** 41 mutations of `hostgroup.rs`
through the kit's `sabotage.py` (`tests/differential/m7/sabotage_hostgroup.json`),
41 caught, 37 of them by the differential by name. The other four are pinned by
unit tests only. Three are rules loopback cannot show 7.94 exercising: a
different interface, a different direct-connectedness and a different address
family. The fourth is that the source is asked again after it has ended, which
the generator has no case for (it would take a script that adds targets).

**The review.** Independent reviews, repeated on each fix round. The first was
of the step as first written. It could
not make the port's sizes or order differ from 7.94 on any input in which every
target is up: it read the C line by line, ran 362 random cases against the 7.94
build with no difference, and replayed the mutations. What it found, all
confirmed here and fixed in the follow-up to #161:

1. The ledger said the port and 7.94 agree under `-Pn`. They do not where 7.94
   pings anyway: an on-link Ethernet target is put to the ARP or ND ping under
   `-Pn`, and a silent one takes no place in a group. Measured, 4/64/2 against
   the module's 4/60/10 (`hostgroup-every-target-counts`, rewritten).
2. Four broken variants of the C and four of the port passed every test. See
   above.
3. The claim that `numhosts_scanned` accumulating could not be shown on loopback
   was false: repeats on one route end a batch on a group of four. It is now a
   golden case and its mutation is caught by the differential.
4. "A connect scan routes nothing" is true only under `-Pn` without `-O` or
   `--traceroute`: 7.94 routes whenever `RawScan()` holds. The docs say so now
   and the golden holds a `-sT -O` case.
5. Smaller: a stale case count in two comments; the generator would have read
   an ARP ping's "Scanning N hosts" as groups, and now refuses a run in which
   nmap pings; the source iterator was asked again after its end (see the
   second round).

**The second round**, on that fix round, confirmed four more. None is in the
grouping logic: 119 further random cases against 7.94 showed no difference.

1. **The fix for "asked again after its end" was the wrong way round.** The fix
   round fused the source. 7.94's source resumes on purpose: when the command
   line's targets are spent it reads the targets scripts have added, and draws
   them after those (*measured*: a hostrule script adding two hosts to a run of
   one gives "Scanning 127.0.0.1" and then "Scanning 2 hosts"). The fuse is undone,
   the module says why it asks again, and `nse-new-targets-not-scanned` names
   this as the way in.
2. **The fuse's unit test could not fail.** Without the fuse it never returned,
   and a hang is not a catch. Its replacement adds targets between two groups,
   as a script would, and a mutation that fuses the source fails it by name.
3. **`--check` had stopped comparing the golden as a file.** Rewritten to
   compare case by case, it accepted a stale line ahead of the right one for a
   case, a duplicate line, and any order. It compares the whole file again, and refuses an `--only` that
   matches no case.
4. Two sentences were contradicted by the same commit: "the port sends no
   host-discovery probes" (it sends the IPv6 ND ping, after grouping), and
   "`box` asserts what validation guarantees" (7.94 lets a value past
   `i32::MAX` wrap and trip it).

**For step b**, from the review:

- **A down verdict has no way into `HostGroups`.** 7.94 gives a down host no
  place and adds it to `numhosts_scanned`. The port has such verdicts for IPv6
  on-link neighbors (its ND ping), and reaches them after grouping, for a whole
  route-group at once. Step b decides whether the ND ping moves ahead of group
  formation, per batch, as in 7.94, or the difference is ledgered.
- **The caller decides `route`.** `Some` when root and `RawScan()` holds, so
  `-sT -O` is routed; and `RouteKey::source` is `-S`'s address when given
  (measured: `-sS -S 127.0.0.1 -e lo` over `l1, own, l2` is one group of 3).
- **Bounds that read negative as a 32-bit `int`.** 7.94 aborts on
  `--max-hostgroup 2147483648`, and on `-1` (an assertion in `box`;
  *measured*). The CLI should refuse such a value with a message.
- **Script-added targets.** The module asks its source again whenever a group
  wants a target and the batch is spent. Whether step b feeds it the
  new-targets queue, or leaves `nse-new-targets-not-scanned` open, is decided
  there. If it does: 7.94 runs its pre-scan scripts before the first group is
  formed, so a prerule's additions can be in the first group, and a run may
  have no command-line target at all (*measured in the third round*: a prerule
  adding two loopback hosts gave one group of three with a command-line target
  and one group of two without).

**The third round**, on the second fix round, confirmed six, all low: five
sentences that were not quite true and one hole in the generator. Nothing in
the grouping logic, on 500 further random cases with script-added targets
against 7.94, traced poll for poll against an instrumented build.

1. "Script-added targets are scanned in later groups" is false for a prerule's
   additions, which can be in the first group. Reworded.
2. "Asked again once for every group" was not the rule: the source is asked
   whenever a group wants a target and the batch is spent. Reworded.
3. `--check` skipped its whole-file comparison when any case timed out, and
   said "the rest match". It now compares the cases that finished with the
   golden's lines for them.
4. The sentence the second round corrected ("no host discovery") survived in
   the generator's header and in one older ledger entry. Both corrected. (A
   third copy, in §3 of this document, was found in the fourth round.)
5. The note on `box` named one of the inputs that trip 7.94's assertion; a
   negative maximum does too.
6. The second round's item 3 above had the stale line's position backwards.

**The fourth round**, on the third fix round, confirmed two, both sentences. It
could not make the generator's `--check` give a wrong answer in 504
combinations of doctored goldens, modes and timed-out cases.

1. "Script-added targets are scanned after the command line's targets" is
   false when a command-line target is deferred (*measured*: a prerule adding
   two loopback hosts to `127.0.0.1 192.0.2.2 127.0.0.2` under `-sS` gives a
   group of four and then 192.0.2.2). The port does the same. The three
   sentences now say "drawn after".
2. §3's "host discovery ... no discovery time to exclude" was the third copy
   of the sentence above. Corrected there.

**The fifth round**, on the fourth fix round, confirmed one, again a sentence.
The reworded text still stated consequences that do not always hold: that a
prerule's additions share the first group "if it has room", and that a
deferred command-line target comes "behind them". *Measured*: with
`192.0.2.2 127.0.0.1` under `-sS`, the additions do not join the first group,
which holds 192.0.2.2 alone, and the deferred 127.0.0.1 is ahead of them in
the next. The port does the same. The module and the ledger now state only
the mechanism (the additions are drawn after the command line's targets and
are then batched, deferred and grouped like any other target), and give
measured cases as examples.

**The sixth round**, on the fifth fix round, confirmed nothing. Six rounds
confirmed 10, 4, 6, 2, 1 and 0 findings. No round found the grouping rules as
first written to differ from 7.94. The one defect in the module's code was the
fuse, which the first fix round introduced and the second removed; the rest
were sentences, test gaps and the test tools.

**Divergences.** Every target takes a place in a group here, and in 7.94 a down
host takes none (`hostgroup-every-target-counts`). `--randomize-hosts`, `-iR`
and SCTP scans are not ported.

**Gates.** Fuzzing is exempt with a reason: the module reads sizes from the
command line and route keys from this host's routing table, and no bytes from
the network. Miri passes on its unit tests. It has no `unsafe`. In CI the
differential job runs the generator's `--check` as root against the distro's
nmap; that step has not run in CI, which has not run since 3 November, and has
run here. #161 was merged before the review and before any local CI record;
both are on the follow-up.

## 11. Step b: the group loop

The CLI now runs its pipeline per host group, as 7.94's main loop does
(`nmap.cc:2080-2330`): it draws a group from the lazy target source through
`core::hostgroup`, port-scans it, runs `-sV`, `-O` and the scripts' host phase
over it, writes its hosts to the terminal and every `-o` file, flushes, and
drops it. The pre-scan phase runs before the first group, the post-scan phase
and the totals after the last. `--min-hostgroup` and `--max-hostgroup` are
accepted and bind; `--host-timeout` stays refused until step f.

**Commits.** b.1 checks the hostgroup bounds as 7.94's setters do, in argv order
(`hostgroup-bound-past-int-refused`). b.2 splits each renderer into header,
group and footer, with `RunTotals` summed across groups. b.3 adds
`sys::route::GroupRouter`, which gives each target its `RouteKey` before the
scan (with `-S` as the source, and IPv4 direct-connectedness). b.4 holds what a
run loads or decides once (`RunOnce`: the probe and OS databases, the UDP
payloads, the connect fallback). b.5 makes the targets a lazy source. b.6 is the
loop. b.7 is the gates below.

**How §10's open items were settled.**

- *Who decides `route`:* the CLI, as 7.94's `RawScan()` does as root: every raw
  scan, and a connect scan with `-O` or without `-Pn`. "Root" is "a raw socket
  opens". A build without `pcap` routes nothing.
- *`-S`:* the group key's source is `-S`'s address.
- *Bounds that read negative as an `int`:* refused (b.1).
- *A down verdict entering `HostGroups`:* not done. The port's one verdict, the
  IPv6 ND ping's, still arrives after grouping
  (`hostgroup-every-target-counts`).
- *Script-added targets:* not done (`nse-new-targets-not-scanned`); the lazy
  source is where they would join.

**Gates.**

- *End to end against 7.94.* `gen_hostgroup_golden.py --check --port`, as root,
  runs the port's own binary over the matrix and reads its groups from `-d`'s
  "host group k: n host(s)". All 61 cases of a kind the port has (`-sT`, `-sS`,
  `-sA`, `-sU`, `-sT -O`) give 7.94's sizes and report order; the other four
  are `-sO` and two scan types at once, which the port does not have. In CI's
  differential job.
- *Report text across groups.* With and without `-v`, over three groups and
  over a routed run with a repeat, the report lines and their order match
  7.94's. One difference predates the step: no blank line between "Host is up"
  and the port table (`report-no-blank-line-before-port-table`).
- *Memory.* `scale_check.py` at 4k, 16k and 64k targets: peak RSS 14.6 MiB at
  every size (7.94: 20.9), time linear. The build before b.6 measured 19, 42
  and 133 MiB and 0.13, 8.4 and 131 s. In CI, against the port's own bounds; the
  harness's fit of a flat cost was fixed on the way (LESSONS #059).
- *The quadratic was bounded, not removed.* One group of n hosts still costs
  O(n²) in the connect engine (`connect-scan-quadratic-in-group-size`):
  `--min-hostgroup 65536` gives 135 s at 64k hosts. Default groups keep a run
  linear. Not fixed in this step.
- *CLI tests.* `cli/tests/hostgroups.rs`: sizes under `--max-hostgroup`, the
  default and `--min-hostgroup`; every format whole across groups; a group's
  report on disk while the run goes on; and, as root, routed grouping by source
  and repeat. In CI's privileged steps on Linux and FreeBSD.
- *Sabotage (before the review).* 18 mutations across the six commits through `sabotage.py`
  (`tests/differential/m7/sabotage_stepb.json`), each naming the test that must
  catch it. The first run caught 17: dropping the service fingerprints from the
  totals passed, because the test that compares a run written by group with
  one written whole builds both through the same totals. It now asserts the
  fingerprint block itself, and all 18 are caught.

**What changed for an operator** (`output-streamed-per-group`): output files are
opened before anything runs; "Starting" follows the pre-scan scripts; "scanned
in" counts from before them; two formats on stdout interleave by group (7.94's
at each write); a
script's stdout lines can fall between groups; the unmatched service
fingerprints follow each host's table, at most nine, as in 7.94. Otherwise a run
that forms one group writes each format's bytes as before.

**The first review** confirmed eight findings, and the fix round answers each:

1. `-iL` memory grew a kilobyte per line, since every line was parsed before
   the first target was drawn: 1.2 GiB for a million lines, against 102 MiB
   before the step. Lines are kept as text and parsed when reached: 87 MiB
   (`target-list-file-read-whole`; 7.94 holds 16 MiB).
2. The unmatched service fingerprints stayed one run-wide, uncapped block,
   where 7.94 prints at most nine per host after its table. Moved, and the
   mutation that pinned the old placement replaced.
3. Output files were opened after the pre-scan scripts, so an unwritable path
   failed only after them. Opened first now.
4. "scanned in" did not count the pre-scan phase. It does now.
5. "Each format's bytes are as before" was false for two formats on stdout,
   which now interleave, as in 7.94. The claim is corrected.
6. `-sV`'s Exclude note printed once per group. Once per run now.
7. The truncation message came when the source ran dry. It comes before the
   scan now. The `-v` "excluded N host(s)" line comes when the source runs
   dry, which grouping can reach before the first group is written (the
   fourth review corrected "at the end"); 7.94 prints no such line.
8. Comments: the capture-failure function's doc, the blank-line ledger entry
   (7.94 prints none after "Not shown:"), and a test's sizing comment.

A ninth, noted: the mutation of `routes_targets` is caught only by a root test,
so the sabotage set needs root to report it.

**The second review** confirmed five, all low:

1. The `-iL` fix still held every line: the file was read whole before
   `prepare` ran, so memory grew with the list past the cap (351 MiB at 4M
   lines), and the ledger said otherwise. The file is now read a
   specification at a time, no further than the cap: 17 MiB at every size.
2. Opening the output files before the script engine left them empty when the
   engine could not start. A run that ended before writing removed them; the
   third review found that wrong, below.
3. "scanned in" and the start time still left out name resolution. Both are
   taken before it now, and the files are opened before it.
4. The truncation message printed when only an unparsable specification lay
   past the cap, and that specification's error went unreported. Now a name
   past the cap counts, unresolved; a specification that does not parse is
   reported, and does not.
5. Two tests could not fail for part of what they claimed. `prepare`'s test
   uses a name that resolves; the message, at and past the cap, and the files
   left by an early failure have CLI tests; the unwritable-output test also
   runs with a script that cannot load.

**The third review** confirmed six, one serious:

1. Serious: removing the files of a run that ended early deleted whatever the
   path named, `/dev/null` or a file that was there before. 7.94 deletes no
   output path, and now neither does the port: the files are left, empty.
   A test checks that a file that was there survives.
2. `-iL -` with `--excludefile -` read stdin for one of them and found it
   empty for the other. Refused then; the fourth review found the premise
   wrong, below.
3. A list that could not be read printed the error's debug form. It prints
   a sentence now (the C's for a specification too long), for `-iL` and
   `--excludefile` alike, with tests.
4. The reader's equivalence check (unit test and fuzz target) compared the
   error but not how many specifications came before it. It does now.
5. The ledger said an early failure with no target removed files; a run with
   no target opens none. The entry now says what each side does, measured.
6. The sabotage entry for the removal went with it.

**The fourth review** confirmed six, all low:

1. The exclusions were read and their names resolved before the output files
   were opened, so an unresolvable exclusion was reported ahead of an
   unwritable path, where 7.94 opens its logs first (`nmap.cc:1534-1546`,
   `:1752`). The files and the clock now come first, with a test.
2. A run left with no target after the files were opened (an empty `-iL`,
   every target excluded, every name unresolved) left them empty and exited
   1, unrecorded; 7.94 writes a zero-host report and exits 0. Ledgered,
   measured, in `output-streamed-per-group`.
3. `--excludefile -` read stdin; 7.94 `fopen`s a file named `-`. It does now
   (`exclude-file-dash-is-a-file`), so the both-on-stdin refusal goes, its
   test replaced by one for the file named `-`.
4. Text: the "excluded N host(s)" timing (above), the stdout interleaving
   (7.94 mixes at each write, not by group), and five C line numbers.
5. With `-O`, the OS block is held for the run, so memory grows with the
   hosts it covers: ledgered (`os-block-held-for-the-run`).
6. The test comparing a run written by group with one written whole could
   fail only through the totals, since the whole-run renderers are that
   composition. It now asserts one header and footer per format, every host
   once and in order, and the fingerprint between its table and the next
   host; two test docs sat on the wrong tests.

**The fifth review** confirmed six, all low; none needed a code change:

1. The 65,536-target cap had no ledger entry, and excluded targets count
   toward it. Ledgered, measured (`target-cap-65536`).
2. Start-up errors are reported by kind, not in command-line order, and a
   failing host-group bound drops the "highly aggressive" warning before it.
   Ledgered (`startup-errors-not-in-argv-order`); the host-group entry's
   "command-line order" now says it holds between the two options.
3. `TargetSource::finish`'s comment still said the "excluded" line comes at
   the end. Corrected.
4. `-iL` given a directory is refused, where 7.94 warns and scans nothing;
   older than the step, and pinned by its new test. Ledgered
   (`input-list-unreadable-refused`).
5. A failed output write exits 1 where 7.94 exits 0, and since this step it
   comes before the scan. Ledgered (`output-write-failure-fatal`).
6. The kit's flat rule hides growth under 5% of the baseline. The harness
   now names a flat fit and how far the cost moved (a kit commit; LESSONS
   #059 addendum).

