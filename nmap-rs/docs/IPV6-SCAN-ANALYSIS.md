# IPv6 raw port scans — Phase 0

Status: **Phase 0 done; D1–D5 decided 2026-11-02 as recommended (§7).
Step a (receive) done (§11).** Step b is next. Per D5 this milestone lands in
its own PRs, after #153 (FreeBSD).

## 0. Value

nmap scans IPv6 with every raw technique it has. nmap-rs has none: with `-6`,
`-sS`, `-sU`, `-sA`, `-sW`, `-sM`, `-sF`, `-sN` and `-sX` all fall back to a
connect scan and say so (FreeBSD step e, `ipv6-raw-port-scans-unported`). Until
step e they sent nothing at all and reported no ports. A UDP scan of an IPv6
host is therefore impossible today, and every TCP technique degrades to a full
connect. This milestone brings the eight raw scan types the IPv4 build has to
IPv6, on Linux and FreeBSD, against nmap 7.94 on the wire.

## 1. Measured

- **The IPv4 raw path is complete and gated.** `sys::group` drives SYN, UDP and
  the six flag scans through one engine (`RawScanKind`), over an `IP_HDRINCL`
  raw socket, with pcap capture; `core::{synscan,udpscan,flagscan}` build and
  match; `core::recv_validate` validates replies; `core::classify` decides
  states. Each has a C oracle (`tests/differential/m4`): `validatepkt` 18/18
  plus a 6,000-packet randomized cross-check, classification over 12,504 cases,
  the builders byte for byte. The raw differential matches 7.94 on all 8 scans
  on Linux and FreeBSD (FreeBSD step d).
- **IPv6 pieces exist, built for OS detection:** `core::build6` (the battery's
  IPv6 header and pseudo-header checksums), `core::headers::{ipv6ext,icmpv6}`
  (nping's `PacketParser` rules), `core::ndp` + `sys::ndp` (neighbor discovery
  for the next hop), `route::choose_route6` (scope-aware source selection, the
  own-address rule), and `rawio::FramingSender` (layer-2 send framed for its
  link: Ethernet, `DLT_NULL`, `DLT_RAW`; FreeBSD step e).
- **What is IPv4-only:** `RawScanKind` (`build_probes` takes an `Ipv4Spec`,
  `bpf` an `Ipv4Addr`), `MatchParams` (`our_ip: [u8; 4]`), every matcher (they
  locate an IPv4 header and call `validate_packet`), `validate_packet` (rejects
  IPv6 with `Reject::Ipv6Unsupported`, ledgered `recv-validate-ipv4-only-for-now`),
  `classify_icmp` (ICMPv4 only, `classify-ipv4-icmp-only-for-now`), the probe
  builders (`Ipv4Spec`), and `group_scan_targets` (IPv6 targets never reach the
  engine).
- **Not measurable here.** This container has no IPv6 (the kernel refuses
  `AF_INET6`), so 7.94's IPv6 scans cannot be run locally; every wire gate below
  runs in CI, as FreeBSD step e's do.

## 2. What the C does

**Building** (`scan_engine_raw.cc:1235`, `:1278`; `tcpip.cc:549-800`). Each probe
is `build_tcp_raw_ipv6` / `build_udp_raw_ipv6`: the same TCP or UDP header the
IPv4 path builds (`build_tcp`: window 1024, the SYN options, the encoded source
port and sequence; UDP payloads from `nmap-payloads`, one probe per payload),
the checksum over the IPv6 pseudo-header (`ipv6_cksum`, which applies
`--badsum`), and an IPv6 header from `build_ipv6_raw`: traffic class 0, flow
label 0, hop limit `o.ttl`, no extension headers. Decoys are sent as for IPv4.

**Sending** (`send_ipv6_packet_eth_or_sd`, `raw_socket_or_eth`). On Ethernet,
layer 2 by default, to the next hop's MAC (`setTargetNextHopMAC`, ND); a target
whose MAC cannot be found is marked down with reason `no-route` and an error
(`targets.cc:575`). On a loopback, a raw socket: `IPPROTO_RAW` with the whole
header on Linux; on the BSDs `sendmsg` on a protocol socket, the kernel writing
the header (FreeBSD step e).

**Receiving** (`readip_pcap` → `validatepkt`, `tcpip.cc:1274`). The IPv6 path
walks the extension headers with `ipv6_get_data` (`netutil.cc:689`): while the
next header is hop-by-hop, destination options, routing or **fragment**, skip
`(p[1] + 1) * 8` bytes; the last header must be TCP, UDP, ICMP, ICMPv6, SCTP or
none. TCP then goes through `validateTCPhdr` (as for IPv4), UDP needs 8 bytes.

**Matching and classifying** (`get_pcap_result`, `scan_engine_raw.cc:1602`).
TCP and UDP replies match as for IPv4 (addresses, ports, the encoded sequence).
ICMPv6 (`:1933`): only Destination Unreachable (1) and Parameter Problem (4)
count; the quoted packet is walked with `ip_get_data_any`, must hold 8 bytes of
transport header, must be from our source address to a scanned host, and must
match a probe's ports (and TCP sequence). Then, with the reason always
`icmp_to_reason`'s for the type and code (the branch sets its own and then
overwrites it):

| ICMPv6 type/code | state |
|---|---|
| 1/0 no route, 1/1 prohibited, 1/2 beyond scope, 1/3 address, 1/5 filter-prohibited, 1/6 reject route | filtered |
| 1/4 port unreachable | closed for `-sU` from the target, else filtered |
| 4/0 erroneous header field | **open, for every scan type** |
| 4/1 unrecognized next header | filtered (closed for `-sO` from the target) |
| any other code | unchanged; error and hexdump on stderr |

## 3. Where the C is wrong, or odd

- **Q1 — hop limit 255.** `build_ipv6_raw` means a random 37–59 when the hop
  limit is -1, as IPv4 does for TTL. But `build_tcp_raw_ipv6` takes it as a
  `u8`, so `o.ttl`'s default -1 arrives as 255 and the random branch never runs.
  7.94's IPv6 scan probes carry hop limit 255.
- **Q2 — Parameter Problem code 0 means open.** The branch was written for
  `-sO`, where "erroneous header field" means the protocol was understood. For a
  TCP or UDP probe it means some node found a field in our packet erroneous,
  which says nothing about the port. It is also spoofable: any host on the path
  that can quote our probe can mark a port open.
- **Q3 — fragments are parsed as if they began with a transport header.** The
  IPv4 path rejects any fragment with a nonzero offset; the IPv6 walk treats the
  fragment header as one more extension, so a later fragment's payload,
  mid-segment bytes, is read as a TCP or UDP header and matched. The fragment
  header's length also comes from its reserved byte (`(p[1] + 1) * 8`), not its
  fixed 8 bytes.
- **Q4 — the trailer trim counts the wrong thing.** `validatepkt` compares the
  upper-layer length with `ip6_plen`, which includes the extension headers, so
  with extension headers present a link-layer trailer is trimmed short or not
  at all.
- **Q5 — Time Exceeded and Packet Too Big are ignored** for port scans, where
  the IPv4 path takes ICMP Time Exceeded (`:1927`). An asymmetry, not a defect;
  reproducing it is the faithful choice.
- **Q6 — an unknown unreachable code hexdumps to stderr** at any verbosity.

## 4. Threat model delta (extends THREAT-MODEL.md)

- **New untrusted input: IPv6 replies.** Every captured IPv6 packet is walked
  (extension headers whose lengths the sender chooses), validated and matched.
  The walk is bounded by the packet (each step at least 8 bytes), and runs on
  bounds-checked slices; it gets a fuzz target, as do the three IPv6 matchers.
- **ICMPv6 errors quote an arbitrary packet.** As for ICMPv4, a forged error
  that guesses the encoded ports and sequence can set a port's state; Q2 makes
  one forgery set **open**, which ICMPv4 never can (§7 D2).
- **Fragments** (Q3, §7 D3).
- **Neighbor discovery.** An on-link host can answer our solicitation for
  another and draw our probes to itself, against the C as against the port
  (`core::ndp`, M5). Unchanged here.
- **`unsafe`.** None expected: sending is `pcap::sendpacket` (step e's
  `FramingSender`), capture exists.

## 5. The oracle and the gates

Unchanged in kind from M4 and M5: the tree's C, compiled into small oracles
that link real `libnetutil` code where it is not `static`, transcribing (with
line references) where it is.

- **Receive:** `validatepkt`'s IPv6 path transcribed, calling the real
  `ipv6_get_data`/`ip_get_data_any` from `netutil.cc`; hand-written vectors for
  every extension and fragment shape, plus a randomized cross-check as for IPv4.
- **Classify:** `classify_oracle.cc` extended with §2's ICMPv6 branch,
  exhaustively over scan × type × code × from-target.
- **Build:** `build_tcp_raw_ipv6` / `build_udp_raw_ipv6` (with `build_tcp`,
  `build_udp`, `ipv6_cksum`) byte for byte, over `--ttl`, `--badsum`, `--data`
  and the payload table.
- **On the wire:** `run_raw_differential.sh` already takes IPv6 targets
  (FreeBSD step e) and runs `-6 -sT`; it runs all eight scans as each lands, on
  `::1` and on the host's own address, on Linux and in the FreeBSD VM.
- **Fuzz:** the IPv6 walk and validator, and each IPv6 matcher.

## 6. What carries over, and what is new

| piece | IPv4 today | IPv6 |
|---|---|---|
| encoding (source port, sequence) | `synscan::{sport,seq32}_encode` | the same |
| TCP/UDP headers, payloads | `core::build` | the same headers, an IPv6 header and pseudo-header around them (new builder) |
| validation | `recv_validate::validate_packet` | an IPv6 path: `ipv6_get_data`'s walk (new; not `PacketParser`'s rules, which OS detection keeps) |
| TCP/UDP reply matching | `match_*_response` | the same transport checks behind an IPv6 header (new matchers sharing them) |
| ICMP errors | `classify_icmp` + `match_*_icmp_error` | ICMPv6 classification and quote matching (new, §2's table) |
| engine | `group_scan` over `Ipv4Addr` | the same engine over either family |
| send | `IP_HDRINCL` raw socket | `FramingSender` per link, ND per next hop |
| route | `route_for` | `route_for6` (exists) |

## 7. Decisions for you

### D1 — Scope
- (a) **The eight scan types the IPv4 build has** (SYN, UDP, ACK, Window,
  Maimon, FIN, NULL, Xmas) over IPv6, on Linux and FreeBSD, with the IPv4
  build's host handling (no separate host discovery; `-Pn` as today).
- (b) (a) plus IPv6 host discovery (ICMPv6 echo, ND ping). The port has no raw
  host discovery for IPv4 either, so this would be a new subsystem for both
  families, better as its own milestone.
- (c) SYN and UDP only, the rest later.

**Recommended: (a). Decided (2026-11-02): (a).**

### D2 — ICMPv6 Parameter Problem, code 0, on a TCP or UDP probe (Q2)
- (a) Reproduce: the port is open.
- (b) **Filtered, as the other ICMPv6 errors from the path are**, keeping the
  C's `open` for an IP-protocol scan should one ever be ported. Ledgered as a
  fix of a C defect.
- (c) Ignore the error; the port takes its no-response default.

**Recommended: (b).** An error about our packet is evidence that something on
the path stopped it, which is what filtered means elsewhere; and it removes the
only forged ICMP that can claim open. **Decided (2026-11-02): (b).**

### D3 — Fragments (Q3)
- (a) Reproduce: walk the fragment header by its reserved byte, read a later
  fragment's payload as a transport header.
- (b) **Reject fragments with a nonzero offset, as the IPv4 path does, and take
  the fragment header as its fixed 8 bytes.** Ledgered.

**Recommended: (b). Decided (2026-11-02): (b).**

### D4 — Ethernet on the wire
Loopback alone never exercises neighbor discovery or Ethernet framing, and CI
has no second IPv6 host.
- (a) Loopback only (`::1`, the host's own address).
- (b) **(a), plus an on-link neighbor: a veth pair into a Linux network
  namespace, and an epair into a FreeBSD VNET jail**, with the fixture listening
  inside, so ND, Ethernet framing and an ND failure (a silent neighbor: down,
  `no-route`) all face 7.94.

**Recommended: (b). Decided (2026-11-02): (b).**

### D5 — Landing
PR #153 (FreeBSD) is open, and this branch is the only one I may push to.
- (a) **Write the steps here, push nothing for this milestone until #153 has
  merged**, then open its own PR on the same branch.
- (b) Push to #153 now, making it FreeBSD plus IPv6 scans.

**Recommended: (a)**, as with #152 before FreeBSD. **Decided (2026-11-02):
(a).**

## 8. Engineering choices (recorded; you may veto)

- **Q1 is reproduced:** hop limit 255 unless `--ttl` sets it, traffic class 0,
  flow label 0, no extension headers. Ledgered as a faithfully reproduced quirk.
- **Q4 is fixed:** trailers are trimmed to the IPv6 header plus `ip6_plen`.
- **Q5 is reproduced:** Time Exceeded and Packet Too Big leave a port as it is.
- **Q6:** an unknown code changes nothing and is logged at `-d`, not hexdumped
  at every verbosity. Ledgered.
- **One engine, both families.** `RawScanKind` and `group_scan` become generic
  over the address family; the transport logic of each matcher is shared, so
  IPv4 and IPv6 cannot drift apart.
- **The next hop is resolved once per next hop per scan,** for on-link targets
  each target and for off-link ones the gateway, with step e's framing per link.
  A next hop that never answers marks its hosts down, reason `no-route`, with
  the C's message.
- **Step e's fallback goes away per scan type** as each lands.

## 9. Proposed build order

| step | delivers | gates |
|---|---|---|
| **a — receive** ✅ (§11) | the IPv6 walk (`ipv6_get_data`), `validate_packet`'s IPv6 path (D3, Q4) | the validate oracle extended (vectors per header and fragment shape; randomized cross-check); fuzz target; Miri |
| **b — match and classify** | ICMPv6 classification (§2's table, D2, Q5, Q6); IPv6 matchers for SYN, UDP and the flag scans, sharing the IPv4 transport checks | the classify oracle extended, exhaustively; matcher unit tests over crafted replies (including quotes behind extension headers); fuzz targets |
| **c — build** | IPv6 scan probes (Q1), `--ttl`, `--badsum`, `--data`, the UDP payloads | byte-identical to `build_tcp_raw_ipv6` / `build_udp_raw_ipv6` |
| **d — the engine on loopback** | `group_scan` over both families; `FramingSender` per link; step e's fallback removed | privileged e2e tests on `::1`; `run_raw_differential.sh` with all 8 scans on `::1` and the host's own address, Linux and FreeBSD, against 7.94 |
| **e — Ethernet** (D4) | ND per next hop; down/`no-route` when it fails | the same differential across a veth pair (Linux) and an epair (FreeBSD), plus a silent neighbor |

Each step comes with its own sabotage list, as in M6.5–M6.7 and the FreeBSD
steps.

## 10. Not verified

- 7.94's IPv6 scans have not been run: no IPv6 here. §2 is read from the
  source; the first CI runs of step d are its first measurement.
- FreeBSD's `lo0` does accept the port's `DLT_NULL` IPv6 frames: FreeBSD step
  e's `-6 -O` of `::1` matched 7.94 there (#153).
- Whether GitHub's Linux runners allow a network namespace with IPv6 on a veth
  pair (D4 (b)) is untested; the exit differential already uses unprivileged
  namespaces there, so it is likely.

## 11. Step a — results

`validate_packet` validates IPv6 (`core::recv_validate`): the header, the
extension-header walk (`ipv6_payload`, a port of `ipv6_get_data`), then the
IPv4 path's TCP and UDP checks, shared (`validate_l4`). D3 and Q4 are fixed as
decided: a fragment header is its fixed 8 bytes and a nonzero offset is
refused (`recv-validate6-non-initial-fragment`); the packet ends at
40 + `ip6_plen` (`recv-validate6-trailer-trim`). `recv-validate-ipv4-only-for-now`
is resolved. The matchers still hand it only IPv4 replies; step b changes that.

- **Oracle.** `validate_oracle` now has validatepkt's IPv6 branch
  (`tcpip.cc:1310`), and the walk inside it is not a transcription: the build
  copies `ipv6_is_extension_header`, `ipv6_is_upperlayer`,
  `ipv6_get_data_primitive` and both `ipv6_get_data` overloads out of
  `netutil.cc` by name and compiles them against libdnet's headers. If one is
  missing the build fails.
- **Hand corpus.** 36 IPv6 vectors, one per extension header, fragment shape
  (first, atomic, later, behind another header, nonzero reserved byte),
  way a chain runs out (under 40 bytes, header only, under 8 bytes left, a
  length past the end, ending at the end, ending in an extension header),
  unknown last protocol, and transport failure. With the IPv4 ones, 50 of 55
  match the C. The other 5 are pinned in `validate_differential.rs` with the
  C's answer next to the port's.
- **Random corpus.** 4,000 IPv6 packets (`gen_validate_random.py`, fixed
  seed): chains of up to five headers in any order, lying lengths, every
  ending, payload lengths short, exact and long, truncation. 2,903 match the
  C exactly. 489 are Q4's class: the same protocol and offset, a different
  length, and the C's length is checked against the C's rule. 608 cross a later
  fragment (tagged by a mirror of the C walk) and the port refuses each as a
  fragment. The C accepted 331 of those, so D3 changes real behavior.
- **CI.** `regen_validate_golden.sh --check` rebuilds the oracle and both
  corpora in the differential job and fails on drift, so a change to
  netutil.cc's walk shows up there.
- **Fuzz.** The `validate_packet` target checks, for an IPv6 accept, that the
  offset falls inside the buffer past 40, that the protocol is upper-layer and
  that the walk agrees with it. It also runs the walk alone and checks that it
  can only refuse in the walk's own ways. Five IPv6 seeds; 79M runs here, no
  failure.
- **Miri.** The 19 unit tests, 8 of them IPv6, pass.
- **Sabotage, 16, all caught.** In the port: the offset check removed; the
  fragment length taken from the reserved byte; the offset read from the
  flag bits; the C's trim; the trim without the fixed header; an extension
  length one unit long; SCTP or ICMP missing from the upper-layer set; the
  `p >= end` check dropped; routing headers not walked; the first next header
  read from the hop limit; the transport checks skipped; an unknown ending
  accepted (each caught by the unit tests and the differential). In the C,
  through `--check`: the walk's step changed, SCTP removed from the
  upper-layer set, the walk function renamed.

