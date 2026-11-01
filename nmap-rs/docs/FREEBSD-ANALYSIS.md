# FreeBSD backend — Phase 0

The port runs on Linux and targets Windows. This document is Phase 0 for a
third platform, FreeBSD. It records what was measured, where FreeBSD differs,
how the result will be proven against C nmap, and the decisions that need you
(§6) before any step starts.

## 0. Value

FreeBSD is nmap's best-supported BSD. The repository's own CI builds C nmap
on FreeBSD 15.0 (`.github/workflows/build.yml`, `freebsd-15-gcc`/`-clang`).
A port that cannot run where the C runs is not yet a replacement.

## 1. Measured

| check | result |
|---|---|
| `cargo check --target x86_64-unknown-freebsd --workspace --all-targets` | clean |
| the same with `--all-features` (`pcap`, `raw-ffi`) | clean |
| `cargo clippy` for that target, CI's flags (`-D warnings`, unsafe docs) | clean |

The workspace already compiles and lints for FreeBSD, with no change. It is
mostly portable by construction:
- `netdev` handles interfaces and routes, with a BSD routing-socket backend.
- `tokio` uses kqueue.
- `socket2` opens the raw IPv4 socket.
- `pcap` wraps the libpcap in FreeBSD's base system.
- Everything else is `cfg(unix)`, not `cfg(target_os = "linux")`.

What compiling cannot show is behaviour. This container has no KVM, so
nothing below has run on FreeBSD yet. §2 is from reading the port against
the C and FreeBSD's documented behaviour; §4 is how each item gets proven.

## 2. Where FreeBSD differs

| # | difference | the C | the port today | effect on FreeBSD |
|---|---|---|---|---|
| F1 | **The loopback's link layer is `DLT_NULL`**: a 4-byte address family in host byte order, not Linux's 14-byte zeroed Ethernet header | `datalink_offset` skips 4 bytes for `DLT_NULL`/`DLT_LOOP` (`netutil.cc:3215`); `send_ip_packet_eth` writes the family, 28 for IPv6 on FreeBSD (`netutil.cc:2627`) | `Route::eth_included` is `true` for every interface (`route.rs:67`), and `EthFramingSender` always frames Ethernet | **every raw scan of localhost finds nothing** (`-sS`, `-sU`, `-sF`/`-sN`/`-sX`, `-O`), and IPv6 L2 sends on `lo0` are malformed |
| F2 | Other datalinks: `DLT_RAW` (tun, WireGuard) on both OSes | supported (offset 0) | parsed as Ethernet | raw scans over a tunnel fail; **Linux has this gap too** |
| F3 | `open(O_NOFOLLOW)` on a symlink fails with **`EMLINK`**, not POSIX's `ELOOP` (FreeBSD `open(2)`) | n/a (the C has no `O_NOFOLLOW`) | `nsefs` maps only `ELOOP` to "denied"/"no such file" (`nsefs.rs:540`) | a symlink swapped in during an NSE file open is still refused, but with a different error message than on Linux |
| F4 | `NMAPDATADIR` is `/usr/local/share/nmap` (ports and pkg; configure's default prefix) | compiled in from `--prefix` | `/usr/share/nmap` on every Unix (`datadir.rs:24`) | **an installed port finds no data files**; scans fail at load |
| F5 | Gateway and MAC come from routing sockets and `AF_LINK` | libdnet `route_get`, `intf_get` | `netdev`'s BSD code (feature `gateway`) | unverified: an off-link raw scan needs the gateway, and the L2 path needs both MACs |
| F6 | `IP_HDRINCL` wants `ip_len`/`ip_off` in network byte order since FreeBSD 11 | swaps only before `__FreeBSD_version` 1100030 (`netutil.cc:2692`) | network order everywhere | **no change needed**; the kernel refuses a wrong `ip_len` (`EINVAL`), which the port never sends |
| F7 | The loopback is `lo0` | n/a | the privileged e2e tests open `"lo"` (`sys/tests/*_e2e.rs`) | those tests cannot run on FreeBSD as written |
| F8 | `raw-ffi`'s `getifaddrs` cross-check reads MACs from `AF_PACKET` (Linux only) | n/a | FreeBSD's `AF_LINK`/`sockaddr_dl` is not read | with `raw-ffi`, the cross-check reports no MACs and disagrees with `netdev` |
| F9 | ICMP replies are rate-limited (`net.inet.icmp.icmplim`, 200/s) | same kernel, same limit | same | UDP-scan results depend on timing; the differential must run both programs on one host, as on Linux |
| F10 | Raw sockets and `/dev/bpf*` need root; FreeBSD has no capabilities | same | same | raw-scan tests run as root in the VM |

F1, F4 and F5 decide whether the FreeBSD build is usable at all. F1 and F2
are one change: the capture carries its datalink to the parsers, as the C
does (§5).

## 3. Threat model delta (extends THREAT-MODEL.md)

- **No new input surface.** BPF delivers the same packets libpcap does on
  Linux. The new code is the datalink dispatch, which reads at most 4 bytes
  before the network header, plus a 4-byte header the sender writes. The
  existing parser fuzz targets gain the `DLT_NULL` and `DLT_RAW` framings.
- **Privilege.** `/dev/bpf*` is root-only by default, as `AF_PACKET` is on
  Linux. Nothing changes.
- **Symlinks (F3).** The `O_NOFOLLOW` guard holds on FreeBSD; only the error
  it reports differs. Mapping `EMLINK` as well keeps both messages equal.
- **`unsafe`.** The default build adds none. F8's `AF_LINK` arm adds one
  audited block to `raw-ffi` (off by default), beside the `AF_PACKET` one.

## 4. The oracle and CI

**Oracle:** C nmap 7.94 built in the same FreeBSD VM from commit
`3be01efb1`, with the recipe `build.yml` already uses (`./configure &&
gmake`). That is the source of Debian's `7.94+git20230807.3be01efb1`, the
oracle every golden comes from (docs/M6.5-ANALYSIS.md §1.1), so the gates
carry over unchanged. (*Corrected in step a:* this section first said "built
from this repository". This repository's own C is 7.99SVN, not the goldens'
source.)
- the M1 connect-scan differential;
- the NSE corpus;
- the CLI scenarios;
- as root, the raw scans of localhost and of the VM's own address.

**CI job** (`nmap-rs-ci.yml`, new):
- `vmactions/freebsd-vm`, pinned by commit SHA, not `@v1`.
- Rust 1.97.0 from rustup inside the VM, the pinned toolchain. FreeBSD's pkg
  Rust is older.
- libpcap from base; pcre2, libnet and gmake from pkg for the oracle.
- Runs, as root:
  - `cargo test --workspace --all-features`;
  - the privileged e2e tests (`--ignored`), on `lo0`;
  - the M1 differential against the VM-built C nmap.
- Expected 25–40 minutes. Rust and C build from source in an emulated
  runner; the miri job already takes about 25.

**Local proof is compile-only.** No KVM here, and a FreeBSD guest under
software emulation would take hours per run. Every runtime claim in §2 is
proven first in the VM job. Because the work waits for #152 to merge (your
choice), the first FreeBSD run happens on the PR that follows it.

## 4a. Step a: what the first runs found

The job's first run booted FreeBSD 15.0-RELEASE-p13 as root, then failed
building the oracle: configure missed pkg's pcre2 under `/usr/local` and fell
back to the bundled copy, which FreeBSD's lld refuses to link. The fix is to
pass `--with-libpcre=/usr/local`.

The second run built the port with every feature and ran the whole suite on
FreeBSD for the first time. Everything passed (rustls's 147 included) except
three tests. Each is a FreeBSD difference in a test's expectation, not in the
port:

| test | on FreeBSD | cause | fix |
|---|---|---|---|
| `nsefs::paths_resolve_as_the_system_calls_resolve_them` | `ELOOP` is 62, not 40; `ENAMETOOLONG` 63, not 36 | the test wrote Linux's numbers; the port passes the OS's errno through | `libc::ELOOP`, `libc::ENAMETOOLONG` |
| `cli data_file_tests::a_socket_is_unreadable_with_the_cs_reason` | `open(2)` on a socket gives `EOPNOTSUPP` ("Operation not supported (45)"), not Linux's `ENXIO` | 7.94's `fopen` gets the same there; the port reports what the OS says | the expectation by OS |
| `nse_exit_differential` | no `unshare` | isolation by Linux user namespace | a VNET jail holding only `lo0` on FreeBSD; the golden regenerated on the VM from the 7.94 oracle |

The third run built the oracle from `3be01efb1` (`Nmap version 7.94SVN`),
regenerated the exit differential's golden in a VNET jail, and passed it:
**the port's 18 exit scenarios match 7.94's on FreeBSD.** The three fixes
above held. One more test failed:

| test | on FreeBSD | cause | fix |
|---|---|---|---|
| `net::an_open_port_probe_ends_in_a_reset` | the listener's `accept` fails with `ECONNABORTED` | the connect probe resets (linger 0), as nmap's does. FreeBSD drops a connection reset in the accept queue; Linux keeps it, and the read gets `ECONNRESET` | either form of reset passes; a graceful close still fails |

The fourth run passed the whole suite on FreeBSD. The M1 differential then
matched 7.94 on 19 of its 20 cases. `sv-ssh-banner` (`-sV -Pn -n -p 18022
127.0.0.1`) timed out in the port (the harness gives a case 15 s). This
document first put that down to F1, reasoning that as root both programs
SYN-scan through pcap. **That was wrong** (§4b): with no scan type, nmap-rs
connect-scans even as root (`ScanKind`'s default), so the case never took
the raw path. Its cause is still open.

The privileged e2e tests stay `#[ignore]`d, as on Linux; step d runs them in
the VM (§4c).

## 4b. Step c: datalinks (capture)

- **`PcapSource` reads `pcap_datalink` at open** and handles each link as
  `datalink_offset` does:
  - Ethernet (`DLT_EN10MB`) is kept whole for the parsers;
  - `DLT_NULL` and `DLT_LOOP` lose their 4-byte family;
  - `DLT_RAW` (12, 14 on OpenBSD, or 101) passes as it is;
  - any other datalink is refused at open, not misparsed.
- **The scans take `eth_included` from the capture**
  (`PacketSource::eth_included`, `true` unless a source says otherwise):
  the SYN, UDP and flag scans (`group`), the IPv4 OS scan (`osscan`) and
  the IPv6 one (`fpengine`). `Route` and `Route6` lose their `eth_included`
  field, which was always `true`.
- **Tests.** The datalink table, and a SYN-ACK and an ICMP error matching
  the same with their Ethernet header stripped. The parsers' no-Ethernet
  path had no test before. The fuzz targets need nothing new: `match_syn`,
  `match_udp`, `match_flag`, `parse_packet` and `osprobe_demux` already run
  both framings. The strip itself is one bounds-checked slice.
- Sending on `DLT_NULL` (the IPv6 L2 path on `lo0`) is step e.
- **The fifth and sixth runs.** With the capture change, `sv-ssh-banner`
  still timed out. The sixth run kept a failed capture's error and ran the
  port's root scans of `lo0`'s sshd for 40 s each: `-sS` finished in
  0.01 s, port 22 open on a SYN-ACK, so the raw path on `lo0` works. Its
  `-sV` runs connect-scanned and skipped version detection, for want of the
  probe database the matrix loads. So the timeout is in version detection
  with the database loaded, not in capture.
- **The cause** (step d's first run, which timed the case for both programs):
  not the port at all, but the M1 fixture. As root, 7.94 SYN-scans by default
  and nmap-rs connect-scans (`default-scan-connect-even-privileged`, newly
  ledgered); the port's connect probe closes with linger 0, as nmap's does.
  FreeBSD fails `accept()` for a connection reset while queued
  (`ECONNABORTED`, as in step a's `net` test), and the fixture's banner
  thread took any `accept()` error as the end: every later `-sV` connection
  queued with no banner until the case's 15 s ran out. In the diagnostic the
  fixture, which caught nothing, died outright, and the port's `-sV` found
  the port closed. The fixtures now take `ECONNABORTED` as one lost client
  (the M1 banner and drain threads, the raw differential's listener).

## 4c. Step d: routes and MACs

- **The host's own address goes over the loopback.** `route_dst` checks
  the interface addresses before the routing table: a target that is one of
  them goes out of a loopback device, with the target itself as the source
  ("we need to use a localhost device for these"). The port went to the
  address's own interface instead, and captured there. The kernel delivers
  such a probe, and the reply, over the loopback, so the capture saw
  nothing. **A raw scan of the host's own address reported every port
  filtered, on Linux as well**: on the Linux host this step was developed
  on, `-sS` of its own `192.0.2.2` gave `filtered` where 7.94 gives
  `closed`. The route
  is now a pure function of the interface table (`route::choose_route`,
  tested on synthetic topologies), with `route_dst`'s rule second, after the
  loopback range. `-O` takes its distance from `route::is_localhost`, a port
  of `islocalhost` (127/8, 0.0.0.0, or an interface address), and reports 0
  hops there as the C does; it said 1. IPv6's own-address rule waits for
  step e, which can test it.
- **F8.** `raw-ffi`'s `getifaddrs` walk reads MACs from `AF_LINK` on the
  BSDs. The `sockaddr_dl` is read through its own `sa_len`, not the struct's
  nominal `sdl_data` (12 bytes on macOS, shorter than some names plus an
  address), and parsed by a safe function (`link_mac`: a 6-byte address
  after `sdl_nlen` bytes of name, inside the sockaddr, non-zero), unit-tested
  on every OS. One new `unsafe` block, documented. The cross-check against
  `netdev` now compares each interface's IPv4 addresses with prefixes and
  its MAC, not just the names, and fails if no interface has a MAC at all.
- **F7.** The five privileged e2e files ask the route for the loopback's name
  (`tests/common`) and take the framing from the capture. CI never ran them;
  now the Linux job runs them under `sudo` (cargo's runner, so nothing is
  rebuilt as root) and the VM job runs them, with `127.0.0.2` aliased on
  `lo0`, which FreeBSD does not route by default.
- **F5.** An ignored test reads the OS's default route (`/proc/net/route`,
  or `route -n get default`) and requires `netdev` to report that gateway on
  that interface, and an off-link target to route out of it. Both CI jobs
  run it.
- **Gates.** `tests/differential/raw/run_raw_differential.sh` runs `-sS`,
  `-sF`, `-sN`, `-sX`, `-sA`, `-sW`, `-sM` and `-sU` with both programs as
  root against one target, by default the host's own address
  (`own_address.py`), and compares each port's state and reason. The OS
  differential takes a target too, and now compares the distance line. Both
  CI jobs run the raw differential on the own address and on 127.0.0.1, and
  the OS differential on the own address. On the development host (Linux):
  8 of 8 scans match on both targets, and `-O` matches (13 tests, 0 hops).
- **The first VM run of step d.** The raw differential matched 7.94 on
  all 8 scans, on the VM's own `192.168.122.10` and on `127.0.0.1`; F5
  passed (`vtnet0`, gateway `192.168.122.2` with its MAC). Three things
  failed, none in the port:
  - `flagscan_e2e`'s on-the-wire test found the IP checksum invalid. On
    `lo0` it is 0: FreeBSD's `ip_output` zeroes `ip_sum` and computes it only
    for an interface without `CSUM_IP` in `if_hwassist`, and `lo0` claims it.
    The port builds a valid checksum, as nmap does; the kernel discards it.
    The three on-the-wire tests now accept a valid checksum, or 0 on FreeBSD
    (`tests/common`). cargo stopped at that binary, so the other four e2e
    files had not run; both jobs now pass `--no-fail-fast`.
  - The OS differential: nmap-rs found no `nmap-os-db`. The VM's oracle is
    not installed, so its data files sit beside its binary. nmap-rs now
    reads the directory 7.94 reports reading (`-d`'s "Read from"); this
    tree's own `nmap-os-db` is newer than 7.94, which aborts on it.
  - `sv-ssh-banner`: the fixture (§4b).
- **Sabotage**, 7 variants, each caught: the own-address rule removed (two
  unit tests), and again against the raw differential alone (every scan
  diverges, each port `filtered`); `is_localhost` back to the loopback range
  (the OS differential on the own address); the `AF_PACKET` MAC read one
  byte late (the cross-check); `sdl_data` at offset 7, and the name length
  ignored (`link_mac`'s tests); `is_local` ignoring the interfaces (its
  test).

## 5. Engineering choices (recorded; you may veto)

- **The datalink travels with the capture.** `PcapSource` reports
  `pcap_datalink`. The parsers take a link type (`Ethernet`, `Null`, `Raw`)
  instead of `eth_included: bool`, and skip 14, 4 or 0 bytes, as
  `datalink_offset` does. The alternative, rewriting `DLT_NULL` frames into
  fake Ethernet in `sys`, would invent MAC addresses and leave F2 unsolved.
- **The L2 sender frames by link type.** On `DLT_NULL` it writes the 4-byte
  family in host order: `AF_INET` (2), or `AF_INET6` as libpcap defines it
  per OS (28 on FreeBSD, 24 elsewhere, 30 on Darwin), as `netutil.cc:2627`
  does.
- **`NMAPDATADIR` by target:** `/usr/local/share/nmap` on FreeBSD (ports and
  pkg), `/usr/share/nmap` on other Unixes as today.
- **`EMLINK` is treated as `ELOOP`** after an `O_NOFOLLOW` open on FreeBSD
  (F3).
- **The privileged e2e tests ask the route** for the loopback interface name
  instead of hard-coding `"lo"`.

## 6. Decisions for you

### D1 — Scope

- (a) Unprivileged only: connect scan, NSE, data files and `-sV` on FreeBSD.
  Raw scans are ledgered as unsupported there.
- (b) **Everything the Linux build does:** (a), plus raw IPv4 scans and `-O`
  over BPF (localhost included, F1), plus raw IPv6 (`-6 -sS`, `-6 -O`) over
  the L2 path. IPv6 comes last, so (a) and IPv4 are not held up by it.
- (c) (b) without raw IPv6, ledgered.

**Decided (2026-11-01): (b)**, as recommended. F1's fix serves IPv4 and IPv6 alike. The IPv6 send
path is already layer 2 on Linux for the same reason (no `IPV6_HDRINCL`),
and FreeBSD has none either.

### D2 — Oracle

- (a) **C nmap built in the VM from the goldens' source.** That is commit
  `3be01efb1` (Debian's 7.94 is built from it), not this repository's head,
  which is 7.99SVN. *Corrected in step a; the premise as first written said
  "this repository".*
- (b) FreeBSD's packaged nmap: a different version, so a differential
  against it would mix version drift with port bugs.

**Decided: (a)**, as recommended.

### D3 — FreeBSD release

- (a) **15.0**, as the repository's C FreeBSD job.
- (b) 14.3, the older supported branch.
- (c) Both: twice the CI time.

**Decided: (a)**, as recommended. The C job already proves the oracle builds there.

### D4 — When the VM job runs

- (a) **Every push and pull request,** like the other jobs. About 30
  minutes, in parallel with them.
- (b) Only when `crates/sys`, `crates/cli`, `Cargo.lock` or the workflow
  change. Faster, but a path-filtered job cannot be a required check.
- (c) Nightly only.

**Decided: (a)**, as recommended.

## 7. Proposed build order

| step | delivers | gates |
|---|---|---|
| **a — the CI job** (in progress, §4a) | the VM job: build, `cargo test --workspace`, the C oracle built beside it | the existing suite green on FreeBSD; failures recorded, not fixed, in this step |
| **b — data and files** | F4 (`NMAPDATADIR`), F3 (`EMLINK`) | the NSE corpus and CLI scenarios in the VM against the VM's C nmap |
| **c — datalinks** (capture done, §4b) | F1 and F2 for capture: a link type from `pcap_datalink`, parsers by offset; fuzz targets over `DLT_NULL`/`DLT_RAW` | raw IPv4 scans and `-O` of `lo0` as root, against the C; unit tests for each framing (on Linux too) |
| **d — routes and MACs** (in progress, §4c) | F5 checked in the VM, fixed if `netdev` falls short; F7 (the e2e tests by route); F8 (`AF_LINK` in `raw-ffi`) | raw scans of the VM's own non-loopback address; the `raw-ffi` cross-check agreeing with `netdev` |
| **e — IPv6** (D1 (b)) | F1 for sending: the L2 sender framing `DLT_NULL` | `-6 -sS` and `-6 -O` of `::1` and the VM's IPv6 address against the C |

Each step comes with its own sabotage list, as in M6.5–M6.7.
