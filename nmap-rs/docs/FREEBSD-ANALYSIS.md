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

The privileged e2e tests stay `#[ignore]`d, as on Linux. They run in steps
c and d, after F1 and F7.

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
| **c — datalinks** | F1 and F2 for capture: a link type from `pcap_datalink`, parsers by offset; fuzz targets over `DLT_NULL`/`DLT_RAW` | raw IPv4 scans and `-O` of `lo0` as root, against the C; unit tests for each framing (on Linux too) |
| **d — routes and MACs** | F5 checked in the VM, fixed if `netdev` falls short; F7 (the e2e tests by route); F8 (`AF_LINK` in `raw-ffi`) | raw scans of the VM's own non-loopback address; the `raw-ffi` cross-check agreeing with `netdev` |
| **e — IPv6** (D1 (b)) | F1 for sending: the L2 sender framing `DLT_NULL` | `-6 -sS` and `-6 -O` of `::1` and the VM's IPv6 address against the C |

Each step comes with its own sabotage list, as in M6.5–M6.7.
