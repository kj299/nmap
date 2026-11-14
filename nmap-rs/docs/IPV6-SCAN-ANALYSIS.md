# IPv6 raw port scans — Phase 0

Status: **Phase 0 done; D1–D5 decided 2026-11-02 as recommended (§7).
Steps a (receive, §11), b (match and classify, §12) and c (build, §13) done.
Steps d (the engine on loopback, §14) and e (Ethernet, §15) written, and their
review's findings fixed (§15); their wire gates run in CI only.** §2's account of
sending on Ethernet was wrong, and was corrected at step e (§15). Per D5 this
milestone lands in its own PRs.

## 0. Value

nmap scans IPv6 with every raw technique it has. At Phase 0 nmap-rs had none:
with `-6`, `-sS`, `-sU`, `-sA`, `-sW`, `-sM`, `-sF`, `-sN` and `-sX` all fell
back to a connect scan and said so (FreeBSD step e, `ipv6-raw-port-scans-unported`).
Until FreeBSD step e they sent nothing at all and reported no ports. A UDP scan of
an IPv6 host was therefore impossible, and every TCP technique degraded to a full
connect. (Step e of this milestone resolved the entry, §15.) This milestone brings the eight raw scan types the IPv4 build has to
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

**Sending** (`send_ipv6_packet_eth_or_sd`, `raw_socket_or_eth`). *Corrected at
step e; this paragraph first said that Ethernet was sent at layer 2 by default.*
On Unix the default send preference is `PACKET_SEND_IP_WEAK` (`NmapOps.cc:437`),
so on every link a probe leaves through a raw socket: `IPPROTO_RAW` with the
whole header on Linux (`acinclude.m4:90`); on the BSDs `sendmsg` on a protocol
socket, the kernel writing the header (FreeBSD step e). The kernel resolves the
next hop. Layer 2, to the next hop's MAC (`setTargetNextHopMAC`), is the
`--send-eth` path (forced by `--spoof-mac` too, `nmap.cc:1685`). Only there is a
target whose MAC cannot be found marked down with reason `no-route`
(`targets.cc:579`), and only one the ND ping left up: an off-link target behind a
silent gateway, or any under `--disable-arp-ping`. What does decide an on-link target is
the **implicit ND ping**. For a directly connected target on Ethernet, nmap
solicits it before the scan, even under `-Pn` (`targets.cc:560`, `arpping`,
`PING_SCAN_ND`), whenever `RawScan()` holds. `--disable-arp-ping` and `--send-ip`
skip it, as does a link that is not `DLT_EN10MB` (`targets.cc:559-565`). An
advertisement makes it up, `nd-response`, with its MAC. Silence makes it down,
`no-response`, and it is not scanned, under `--send-eth` too: `setTargetNextHopMAC`
passes over a host the ND ping found down.

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
  `no-route`) all face 7.94. *(Step e: down, but `no-response`, from 7.94's
  implicit ND ping; §2, §15.)*

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
  *(As built at step e, following §2's correction: a silent on-link target is
  down, `no-response`, as 7.94's ND ping finds it; a target behind a silent
  gateway is scanned, and its probes go nowhere, as 7.94's kernel drops them.)*
- **Step e's fallback goes away per scan type** as each lands. (Step d removes it
  for this host's own addresses, all eight scan types at once; the connect fallback
  stays for every other IPv6 target until step e.)
- **The IPv6 capture filter admits replies behind extension headers** (step d,
  `scan6-filter-admits-extension-headers`): 7.94's `tcp`/`udp`/`icmp6` primitives drop
  them before its own walk runs. Recorded 2026-11-08.
- **Attempts keep the port's numbering** (base+N, `scan-attempt-encoding-step-one`),
  for both families. Decided 2026-11-08.

## 9. Proposed build order

| step | delivers | gates |
|---|---|---|
| **a — receive** ✅ (§11) | the IPv6 walk (`ipv6_get_data`), `validate_packet`'s IPv6 path (D3, Q4) | the validate oracle extended (vectors per header and fragment shape; randomized cross-check); fuzz target; Miri |
| **b — match and classify** ✅ (§12) | ICMPv6 classification (§2's table, D2, Q5, Q6); IPv6 matchers for SYN, UDP and the flag scans, sharing the IPv4 transport checks | the classify oracle extended, exhaustively; matcher unit tests over crafted replies (including quotes behind extension headers); fuzz targets |
| **c — build** ✅ (§13) | IPv6 scan probes (Q1), `--ttl`, `--badsum`, `--data`, the UDP payloads | byte-identical to `build_tcp_raw_ipv6` / `build_udp_raw_ipv6` |
| **d — the engine on loopback** (§14; wire gates in CI) | `group_scan` over both families; `FramingSender` per link; step e's fallback removed | privileged e2e tests on `::1`; `run_raw_differential.sh` with all 8 scans on `::1` and the host's own address, Linux and FreeBSD, against 7.94 |
| **e — Ethernet** (D4; §15; wire gates in CI) | ND per next hop; the ND ping's verdicts (`nd-response` up, `no-response` down) | the same differential across a veth pair (Linux) and an epair (FreeBSD), plus a silent neighbor |

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

## 12. Step b — results

- **Classification.** `classify_icmpv6` ports the ICMPv6 branch
  (`scan_engine_raw.cc:1933`): unreachable codes 0–3, 5 and 6 are filtered;
  port unreachable is closed for `-sU` from the target, open for `-sO` from the
  target, otherwise filtered; next-header parameter problem is closed for `-sO`
  from the target, otherwise filtered. D2 is applied: parameter problem 0 is
  filtered, except for `-sO` where it stays open
  (`classify6-param-problem-field-filtered`). Q5 is reproduced: Time Exceeded and
  Packet Too Big give no verdict. Q6: an unexpected code gives no verdict and
  prints nothing (`classify6-unexpected-code-silent`; the `-d` line comes with
  the engine). The reasons are `icmpv6_to_reason`'s (`no-route`, `beyond-scope`,
  `reject-route`, `param-problem`, new in `model::Reason`).
  `classify-ipv4-icmp-only-for-now` is resolved.
- **Matching.** The SYN, UDP and flag-scan matchers are generic over the address
  family (`core::ipfamily::IpFamily`, implemented by `[u8; 4]` and `[u8; 16]`).
  The TCP and UDP checks exist once, and the IPv4 path behaves as before. The
  context, reply and quote types default to IPv4, so `sys::group` is unchanged
  until step d. IPv6 replies are taken only when IPv6 is the frame's first
  network header (never tunnelled). An ICMPv6 error is read up to the packet's own
  end, and its quote is walked like a received packet
  (`icmp_quote::parse_icmpv6_error`), so a quoted later fragment matches nothing.
- **Classify oracle.** `classify_oracle.cc` gains the ICMPv6 branch, transcribed
  with line references. The matrix now covers every code of unreachable and
  parameter problem, plus 15 other types over a spread of codes, for every scan
  and both senders: 28,032 cases (15,528 of them new). All match the C except the
  22 parameter-problem-0 cases (11 scans × 2 senders), which are pinned with the
  C's `open` beside the port's `filtered`. `regen_classify_golden.sh --check` now
  runs in CI. The classify golden had not been re-derived in CI before.
- **Matcher tests.** 18 new unit tests over crafted IPv6 replies, bare and
  Ethernet-framed (and 3 for the classifier):
  - SYN/ACK, RST, a datagram back, and each flag scan's RST.
  - Every ICMPv6 code with its reason, from the target and from a router.
  - Quotes behind destination options, under an error behind hop-by-hop
    options.
  - Refused: a later fragment, a quote not from us, a foreign sequence, a
    7-byte quote, an IPv4 quote inside ICMPv6, and each family's packets offered
    to the other's context.
  - Every truncation of an error and of a reply.
- **Fuzz.** `match_syn`, `match_udp` and `match_flag` run every input through
  both families and assert that only a direct reply can say open; no ICMP error
  can. `classify` asserts that no ICMPv6 error says open except to `-sO`. There
  are 7 new IPv6 seeds, each checked to reach a match. About 71M runs here, no
  failure.
- **Miri.** The unit tests of all six touched modules pass.
- **Sabotage, 15, all caught.** Five in the classifier, each caught by the unit
  tests and the differential:
  - D2 undone;
  - Time Exceeded read as in ICMPv4;
  - port unreachable closed from anyone;
  - unexpected unreachable codes filtered;
  - next-header problem closed from anyone.

  Ten in the matchers, each caught by the unit tests:
  - no-route reported as `net-unreach`;
  - the quote read past the packet's end;
  - quoted extension headers not walked;
  - the quote's source not checked;
  - the Ethernet type not checked;
  - the source read from the destination field;
  - ICMPv6 classified by the ICMPv4 table;
  - ICMPv6 taken as protocol 1;
  - `from_target` against the quoted source;
  - the quoted sequence dropped.
- **For step d.** The engine's capture filter has to admit IPv6 TCP and UDP
  behind extension headers. libpcap's `tcp` primitive only checks the first next
  header, so a filter written as for IPv4 would drop what the matchers accept.

## 13. Step c — results

- **Builders.** `core::build` gains `Ipv6Spec`, `build_ipv6_raw`,
  `build_tcp_raw_ipv6` and `build_udp_raw_ipv6`, ports of the C functions of those
  names (`tcpip.cc:549`, `:657`, `:786`) with `ipv6_cksum`'s checksum and
  `--badsum`. `Ipv6Spec::new` is what the scan engine sends: traffic class 0, flow
  label 0, no extension headers, hop limit 255. Q1 is reproduced
  (`build6-scan-hop-limit-255`): `--ttl` sets the hop limit, and `-S` (an IPv4
  address in `PacketOverrides`) does not apply.
- **Probes.** A `ProbeSpec` trait, implemented by `Ipv4Spec` and `Ipv6Spec`, makes
  `build_syn_probe`, `build_flag_probe` and `build_udp_probe` generic. What goes in
  the TCP or UDP header is one piece of code for both families, as it is in
  `sendIPScanProbe`. `*_with` variants carry `--data`'s payload on TCP probes. The
  UDP payloads already rode `build_udp_probe_with`. The CLI still refuses `--data`,
  `--data-string` and `--data-length` for both families; wiring them is a separate
  change.
- **The oracle.** `scanprobe6_oracle` compiles nmap's own code, copied out by name
  at build time:
  - from `tcpip.cc`: `ipv6_cksum`, `build_ipv6_raw`, `build_tcp`,
    `build_tcp_raw_ipv6`, `build_udp`, `build_udp_raw_ipv6`;
  - from `netutil.cc`: `ipv6_pseudoheader_cksum`;
  - from libdnet: `ip_cksum_add`;
  - from `scan_engine_raw.cc`: `seq32_encode`, `sport_encode`.

  It transcribes only how `sendIPScanProbe` chooses their arguments, with line
  references. That includes passing `o.ttl = -1` through the C's own `u8` parameter,
  so the hop limit of 255 comes from the C itself. The corpus has 2,140 cases:
  - 1,232 probes covering every scan type the port has, the hop limit,
    attempts, masks, `--data`, UDP payloads and `--badsum`;
  - 908 runs of the builders over random fields;
  - the `--badsum` UDP zero cases.

  All 2,140 are **byte-identical**. `regen_scanprobe6_golden.sh --check` runs in CI.
- **Found by byte identity**, all ledgered, the first two fixed for IPv4 as well:
  - **`flagscan-ack-probe-attempt-in-sequence` (fixed).** The C puts the attempt in
    the ack of an ACK-flagged probe (`-sA`, `-sW`, `-sM`) and sends sequence 0; the
    port's IPv4 flag probes had carried it in the sequence. `probe_seq_ack` now
    follows the C, and so does the quote check.
  - **`build-badsum-host-order-decrement` (reproduced).** The C's `--badsum`
    decrements a host-order `u16`. On the little-endian hosts 7.94 runs on, that
    takes one from the checksum's first wire byte, and a UDP zero goes out as
    0xFFFF. The port's IPv4 `--badsum` had subtracted one in network order, and had
    no UDP zero rule. A side effect carried over from the C: a TCP checksum of
    0x0000 becomes 0xFFFF and still verifies, which the fuzz target found.
  - **`scan-attempt-encoding-step-one` (recorded, not changed).** The C's `tryno_t`
    `opaque` byte is `seqnum << 1`, so 7.94 sends retransmission N from base+2N; the
    port uses base+N. No port state differs. Aligning it belongs with the engine
    (step d) if wanted.
- **Tests.** 13 new unit tests:
  - the header fields and the checksum over the IPv6 pseudo-header;
  - `--ttl` and `--badsum`, including the host-order rule and both zero cases;
  - the refusals: misaligned or overlong options, payloads past the length field;
  - the seq/ack rule;
  - probes for each family, built by step c and matched by step b's own quote
    parser.
- **Fuzz.** `build_packet` now drives both IPv6 builders. A built packet must
  validate as IPv6 with its whole length counted, and its checksum must verify,
  except that `--badsum` must break it apart from the zero-checksum case above.
  3 seeds; 15.9M runs, no failure after the zero-checksum case was understood.
- **Miri.** Passes on `build`, `synscan`, `udpscan` and `flagscan`. The two tests
  that search 65,536 checksums are kept out of Miri, as M6.7's slow tests are.
- **Sabotage, 12, all caught**, by the unit tests and the differential unless
  noted:
  - hop limit 64 instead of 255;
  - the traffic class in the wrong bits;
  - the flow label unmasked (differential only);
  - `--badsum` in network order;
  - the UDP zero sent as zero;
  - the attempt always in the sequence;
  - no MSS option on a SYN;
  - TCP summed with the UDP pseudo-header;
  - the payload length counting the header;
  - `--ttl` ignored;
  - the UDP length short by its header;
  - TCP `--data` dropped.

  A thirteenth, unmasked reserved bits, was equivalent: `TcpHeader::serialize`
  masks them. Four more in the C, each caught by `--check` against the committed
  golden:
  - `build_tcp`'s window default changed;
  - `ipv6_cksum`'s `--badsum` changed;
  - `sport_encode` changed;
  - `build_udp_raw_ipv6` renamed, which stops the oracle's build.

  The control run passes.

## 14. Step d — results

Decided for this step (2026-11-08): the code lands now, gated locally by unit and
mock-capture tests, with the wire gates wired into CI. Its PR stays a draft until CI
has run them and they pass, since this container cannot (the kernel boots with
`ipv6.disable=1`). The attempt numbering stays base+N.

- **One engine, both families.** `sys::group` is generic over a `ScanFamily`,
  implemented by `Ipv4Addr` and `Ipv6Addr`. A family supplies only:
  - its probe spec, from the scan's defaults and then the operator's options. IPv4 is
    unchanged; IPv6 is step c's `Ipv6Spec::new` with `--ttl`, `--badsum` and `-S`;
  - its capture filter;
  - its octets, which select step b's `IpFamily` to read replies.

  `RawScanKind`'s `build_probes` and `match_reply` are generic, so `SynKind`,
  `UdpKind` and `FlagKind` are written once for both families, and so is the loop
  (scheduling, demux by source address, timeouts, results). The per-kind `bpf` methods
  are gone: the filter is the family's, given the scan's transport.
- **Sending.** An IPv6 probe goes out at layer 2 on the loopback through
  `FramingSender` over a capture handle, as `-6 -O` already sends. That is a
  choice, one path for Linux and the BSDs (`ipv6-send-is-layer-2-only`). Linux
  could take a caller-built IPv6 header, through an `IPPROTO_RAW` socket or
  `IPV6_HDRINCL` (since 4.5); this paragraph said otherwise until step e. The
  framing comes from `LinkFraming::for_loopback`, now shared with
  OS detection: Linux's `lo` is Ethernet with zero MACs, FreeBSD's `lo0` is
  `DLT_NULL`. The C sends through a raw socket there; what reaches the loopback is
  the same packet.
- **Routing.** `group_scan_targets` buckets targets by family and route
  (`bucket_targets`, pure and unit-tested). An IPv6 target routed over a loopback
  (`::1`, or one of this host's own addresses, which `choose_route6` sends over the
  loopback from itself) joins a route-group. One routed anywhere else makes the call
  `Unsupported` before anything is sent, since Ethernet and neighbor discovery are
  step e's. A target with no route is down, as for IPv4.
- **The CLI.** The `-6` fallback now applies only to a raw scan of a target beyond this
  host (`route::routes_over_loopback6`). It says "raw IPv6 port scans reach only this
  host's own addresses so far; running a connect scan (-sT)"
  (`ipv6-raw-port-scans-unported`, narrowed). With `-6`, `-S` takes an IPv6 literal and
  refuses an IPv4 one, as nmap resolves it in the scan's family (`nmap.cc:1463`). It
  used to take only IPv4, which an IPv6 scan ignored (`cli-spoof-source-literal-only`,
  `PacketOverrides::spoof_src6`).
- **The capture filter** (`scan6-filter-admits-extension-headers`):

  ```
  dst host <us> and ((ip6[6:1] = <proto> and ip6[42:2] >= <base> and ip6[42:2] <= <base+span>)
                     or (ip6[6:1] != 6 and ip6[6:1] != 17))
  ```

  Our transport straight after the fixed header must be to one of our source ports,
  as the IPv4 filter's `portrange` requires. ICMPv6, and any reply behind extension
  headers, passes to the walk and the matchers. libpcap's `tcp` and `portrange` would
  read the first next header and offset 40 only, so with them a reply step b's
  matchers accept would never reach them. 7.94's own filter drops such replies; the
  port does not.
- **Mock-capture tests** (`sys::group`, 9 new for IPv6):
  - demux of two hosts by source address;
  - the probes on the wire are step c's for every attempt, with hop limit 255, and
    with `--ttl 9 --badsum`;
  - `-sU` closed from the target, filtered from a router (attributed to the probed
    host), and open on a datagram;
  - D2's parameter problem filtered, with no-route and admin-prohibited reasons;
  - a reply behind destination options matched;
  - an IPv4 reply from the mapped address answering nothing in an IPv6 scan;
  - replies without a link header, as `lo0` gives them;
  - two routing tests (`bucket_targets`).
- **The filters, run by libpcap.** Both families' filters are compiled by libpcap for
  Ethernet and `DLT_NULL` and run over packets built for each case: each end of the
  port range and one past it, the other transport, our own probe, ICMPv6, the
  extension headers and a fragment header, and the other family. The IPv4 filter is
  pinned to the string it always was.
- **Live, without an IPv6 stack.** This VM has no IPv6, but its `lo` still carries
  frames. With a userspace responder answering the probes on `lo` the way Linux
  would, all eight scan types of `::1` resolve as Linux's stack implies:
  - `-sS`: open `syn-ack`, closed `reset`;
  - `-sA`: unfiltered, both;
  - `-sW` and `-sM`: closed, both;
  - `-sF`, `-sN` and `-sX`: open|filtered and closed;
  - `-sU`: open|filtered, and closed `port-unreach`.

  They resolve the same with a destination-options header in front of every reply.
  This runs the real path from kernel BPF on a live capture to the engine, but it is
  not a gate, and it is not 7.94.
- **IPv4 is unchanged on the wire.** Here, against 7.94: all eight scans of 127.0.0.1
  and of this host's own address match, port by port (16/16), as do the IPv4 e2e
  tests.
- **Wire gates, in CI only.**
  - `scan6_e2e`: every raw scan type on `::1` through the CLI's entry points, and the
    SYN probe on the wire byte-identical to `core::build`'s. It runs in the Linux test
    job and the FreeBSD VM with `REQUIRE_IPV6=1`, so a loopback without IPv6 fails
    instead of skipping.
  - `run_raw_differential.sh` now runs `-sT` and all eight raw scans for an IPv6
    target, and fails a raw scan that fell back to a connect scan. CI already runs it
    on `::1` and on `fd00:5ca1::10`, on Linux and in the FreeBSD VM. These are the
    first runs of 7.94's IPv6 scans anywhere in this project (§10).

- **Miri.** The new pure tests (routing, loopback framing) and `core::build` pass. The
  engine tests are kept out of Miri as before, since they spawn a capture thread; the
  filter tests are kept out because they call into libpcap.
- **Fuzz.** No new parser: replies of both families still go through step b's
  matchers, whose targets cover both. `build_packet` was re-run on the changed
  `core::build` (24.5M runs, no failure).
- **Sabotage, 16, all caught.** Six in the filters and the engine's families:
  - the extension-header clause dropped;
  - ports read at offset 40;
  - the other transport admitted;
  - `src host` for `dst host`;
  - the IPv4 filter's `icmp` changed;
  - the IPv6 spec ignoring the options, or swapping source and destination.

  Four in the engine:
  - replies demuxed to the last host;
  - hosts reported at our own address;
  - the matchers told that the first target is us;
  - a broadcast destination in the loopback framing.

  Two in routing:
  - IPv6 taken over any route;
  - route-groups keyed by interface alone.

  Three in the CLI and `core::build`:
  - the fallback test inverted;
  - `-S` read as IPv4 under `-6`;
  - `spoof_src6` not applied.

  Each is caught by the unit, filter or CLI tests.
- **Lint and audits.** clippy with CI's flags is clean on Linux and FreeBSD, and fmt is
  clean. The unsafe audit finds 42 blocks, all documented, none new. The progress
  stamps for `core::build` and `cli` were re-run and re-stamped, and drift and audit
  pass. The full suite passes: 1,793 tests.

## 15. Step e — results

The same terms as step d: the code lands now, gated locally, with the wire gates in CI
and the PR a draft until CI has run them. This container still boots with
`ipv6.disable=1`.

- **§2 was wrong about Ethernet.** Phase 0 read `setTargetNextHopMAC` and the
  `no-route` verdict as 7.94's default, but they belong to its `--send-eth` path. On
  Unix 7.94 sends IPv6 probes through a raw socket and lets the kernel resolve the
  next hop (§2, corrected). Up or down on a link is decided by the implicit ND ping,
  which `-Pn` does not skip. The comments in `rawio`, `ndp`, `fpengine`, `route` and
  `core::ndp`, and the ledger's `ipv6-send-is-layer-2-only`, had said Linux could
  not take a caller-built IPv6 header. Its `IPPROTO_RAW` socket can, and they are
  corrected.
- **What the port does.** Every IPv6 target now goes through the engine. The connect
  fallback is gone (`ipv6-raw-port-scans-unported`, resolved). On Ethernet:
  - each route-group's next hops (the target when it is on-link, the gateway
    otherwise) are solicited at once, on `doND`'s schedule (`ndp::resolve_many`);
  - each probe is framed to its own destination's next-hop MAC
    (`rawio::NeighborSender`);
  - `plan_neighbors` takes 7.94's verdicts
    (`scan6-nd-ping-decides-on-link-hosts`). An on-link target that answers is up,
    `nd-response`. One that is silent is down, `no-response`, and not scanned, under
    `-Pn` too. An off-link target behind a silent gateway is scanned, and its probes
    go nowhere.

  A link with no link-layer addresses (`DLT_RAW`, a BSD tunnel's `DLT_NULL`) is
  framed as it is, with nothing to resolve. Sending stays at layer 2 on every link:
  a recorded choice, one path for Linux and the BSDs.
- **Host verdicts and output.**
  - The CLI keeps a verdict the scan reached rather than overriding it with `-Pn`,
    and `Reason::NdResponse` is new.
  - A down host is now reported as the C reports it: only under `-v`, as "Nmap scan
    report for X [host down]". The closing "Host seems down" note appears for a lone
    host without `-Pn` (`output-down-host-verbose-only`). This is fixed for every
    scan type, since the silent neighbor is the first differential case to find a
    host down.
- **Found and ledgered, not fixed here:**
  - `ipv4-implicit-arp-ping-unported`, measured locally against 7.94 on an unused
    address of this VM's own /24;
  - `on-link-mac-address-line-unported`, for both families;
  - `raw-scan-unroutable-target-reported`, for both families.
- **Live, on a TAP interface** (`scan6_tap_e2e`, Linux, root). A scripted IPv6 link
  behind a TAP device (`tap_neighbor.py`) needs no kernel IPv6. It holds:
  - a host answering like Linux;
  - a silent address;
  - a gateway with a host behind it;
  - a gateway that never answers.

  The engine runs over it with real ND, framing, capture and matching
  (`group_scan_targets_routed` takes the routes the kernel would give). It runs
  `-sS`, `-sA`, `-sF` and `-sU`, bare and with destination options on every reply.
  Every verdict is checked, and the link counts any probe framed to the wrong MAC:
  none. The test runs in CI's Linux e2e step with `REQUIRE_TAP=1`, so a missing TAP
  device fails the step instead of skipping.
- **Wire gates, in CI only (D4).**
  - **Linux:** a network namespace behind a veth pair holds fd00:6e7::2, with the
    fixture inside (`FIXTURE_IN="ip netns exec nrs6"`).
  - **FreeBSD:** a VNET jail behind an epair holds the same address
    (`FIXTURE_IN="jexec nrs6"`).
  - Both run `-sT` and every raw scan type against 7.94. Then the silent neighbor,
    fd00:6e7::3 (`SILENT=1`): every raw scan, and both tools must find the host down.
    `-sT` is left out there: 7.94's ND ping runs only when `RawScan()` holds, which a
    connect scan with `-Pn` does not.
  - The raw projection now ends with the run's count of hosts up and down, which is
    all a down host leaves in the XML.
- **IPv4 unchanged on the wire.** Here, against 7.94: 127.0.0.1, eight scans, 8/8. The
  silent-neighbor mechanics were tried on IPv4 too, and showed the ARP-ping gap
  above.

- **Unit tests.** New or extended:
  - three for the batch resolver;
  - the per-destination sender;
  - routing a group, including on-link and off-link next hops;
  - `plan_neighbors`, every verdict;
  - liveness settling (`Host::settle_liveness`, which the CLI now calls);
  - the down-host rendering.
- **Miri** passes on the new pure tests (routing, `plan_neighbors`, the senders,
  liveness, the down-host rendering).
- **Sabotage, 16, all caught.** Six in the neighbor logic and the senders:
  - frames sent from our MAC to our MAC;
  - a destination with no MAC sent to broadcast;
  - a silent on-link target scanned and left up;
  - an advertised one not marked `nd-response`;
  - a target behind a silent gateway marked down;
  - a known gateway MAC ignored.

  Four in routing and the resolver:
  - the next hop taken as the target;
  - a resolved address solicited again;
  - an advertisement without an address resolving;
  - one round only.

  Two caught by the TAP link only:
  - targets solicited instead of their next hops, so no gateway is resolved;
  - silent hosts left as the scan left them.

  Four in liveness and output:
  - `-Pn` overriding the scan's verdict;
  - down hosts reported without `-v`;
  - the note under `-Pn`;
  - `nd-response` misspelled.

  The last one was missed at first, because every test compared the enum and none
  the string. A test now pins both reason strings to the C's table.
- **Lint and audits.** clippy with CI's flags is clean on Linux and FreeBSD, and fmt is
  clean. The unsafe audit finds 42 blocks, all documented, none new. The `cli` stamp
  was re-run, and drift and audit pass. The full suite passes: 1,798 tests.

### The review

An adversarial review of steps d and e left 22 findings after verification. All are
fixed here, or corrected in the docs. Five matter on the wire:

- **Loopback targets** were judged by their ports, so a FIN scan of a listener on
  127.0.0.1 or `::1` found the host down. They are now up, `localhost-response`, as
  7.94 marks them before any probe (`loopback-target-localhost-response`).
- **Off-link IPv6 frames** went to the interface's one gateway MAC, which can be the
  IPv4 router's. The IPv6 gateway is now always solicited
  (`route6-gateway-mac-not-borrowed`).
- **`-S`** changed only the probes. The capture, the matching and the solicitations
  kept the routed address, so no reply to the spoofed one was taken. The spoofed
  address is now the source of all of them, with a promiscuous capture, as in C
  (`spoof-source-receives-too`).
- **A repeated target** shared a route-group with itself and lost every reply to its
  twin. Each repeat now gets a group of its own, as 7.94 defers it to a later host
  group (`scan-repeated-target-deferred`).
- **Neighbor discovery.** A stream of advertisement-shaped frames could hold the
  exchange open without bound; a failed capture read as silence; and any advertisement
  could choose where the probes went. Now:
  - the exchange ends by its last deadline plus 25 ms;
  - a failed capture is an error;
  - an advertisement must have hop limit 255 and a unicast MAC.

  See `ndp-exchange-bounded-and-fails-loudly` and `ndp-advert-hop-limit-255`. The ND
  ping's verdict now accepts what 7.94's accepts: any Ethernet destination, and no
  link-layer address needed.

The output now follows 7.94 too:
- in XML and grepable output a down host is its status alone;
- down hosts come first, with no blank line after them (`output-down-hosts-first`);
- the "Host seems down" note goes to the terminal only;
- a down host's reason is `no-response`, whatever found it down;
- `-sL -Pn` claims no host up.

The docs and the ledger were wrong in places, and are corrected:
- when the ND ping runs and what skips it, and `no-route` under `--send-eth`;
- the `IPV6_HDRINCL` rationale, here (§14) and in PLAN, BACKLOG and the FreeBSD
  analysis;
- the C's message for an unroutable target;
- stale text in the raw harness, §9 and three module docs.

New gates:
- **The TAP link** counts anything sent to an address no host answers for (none). A
  second test runs a `-S` scan there: the link answers only what comes from the
  spoofed address.
- **The loopback verdict**, `cli/tests/loopback_liveness.rs`, runs as root in both
  CI jobs, with `REQUIRE_RAW=1`.
- **The note.** `output_all` produces a lone down host in an empty network namespace
  and checks the note's three destinations.
- **Unit tests** for:
  - down-host order and rendering;
  - `-sL -Pn`;
  - the ND hop limit, group MACs, the flood and the failed capture;
  - the spoofed source;
  - repeated-target grouping.
- **CI fixes.** The raw harness now catches every fallback message; its old pattern
  matched none. The FreeBSD job's link setup is one gate, so a failure is reported
  and the gates after it still run.
- **Sabotage of the fixes: 20, all caught.**
  - Engine, six:
    - a loopback group not marked up;
    - `localhost-response` kept under `-Pn`;
    - the shared gateway MAC used again;
    - a repeat in the same group;
    - `-S` dropped from the capture and matching, and from the solicitations (two,
      caught by the TAP link's `-S` test).
  - Neighbor discovery, six:
    - any hop limit;
    - a group MAC;
    - an ND ping that needs a link-layer address;
    - a filter on our MAC;
    - a fresh window per frame;
    - a failed capture read as silence.
  - Liveness and output, eight:
    - a down host with no reason;
    - `-sL -Pn` up;
    - a down host's ports in XML, and its `Ports:` record in grepable;
    - the note in `-oN`;
    - hosts in target order;
    - a blank line after a down host;
    - the terminal given the file's text.

  The fresh-window mutation at first hung its test rather than failing it. The test
  now has a timeout of its own.

A second review, of these fixes, confirmed eight findings after verification. Fixed:
- **A failed capture ends the run.** Both the scan's capture and ND's now return a
  `CaptureFailed`, and the CLI exits 1 with it rather than fall back to a connect
  scan, as 7.94's `netutil_fatal` does. Before, ND's failure became a connect scan
  that exited 0. Since M4 the scan's own failure had let every pending port expire
  into "filtered".
- **Gateways need an advertised MAC.** A gateway is held to `doND`'s rule; only an
  on-link target takes the ND ping's, which reads the frame's Ethernet source when no
  link-layer address is given.
- **`-S`'s source choice is one function, tested** (`scan_source`). The ND capture
  is promiscuous under `-S` too, as C's is.
- **Output and liveness:**
  - the last scanned host's block ends with its blank line, before "Nmap done";
  - an up host whose only answer is `unfiltered` takes that port's reason.
- **`::1`** has its own loopback test, run with `REQUIRE_IPV6=1` in CI. This container
  has no IPv6, so it skips here.
- **The ledger:**
  - the order entry gives 7.94's real host-group conditions;
  - the `-S` entry names its real pins, and says what has no end-to-end test;
  - root `-sT` without `-Pn` is ledgered open
    (`privileged-connect-scan-no-implicit-verdicts`);
  - `--spoof-mac` also forces layer 2;
  - `sys::ndp`'s module doc says which byte decisions live there.

The TAP link gains a gateway that answers without its link-layer address: nothing may
be sent behind it. Sabotage of these fixes: 7, all caught.

After both passes, all of these hold:
- the full suite passes: 1,809 tests;
- IPv4 against 7.94 on 127.0.0.1 is still 8/8;
- clippy with CI's flags is clean on Linux and FreeBSD;
- Miri passes on the new pure tests;
- the unsafe audit finds 42 blocks, none new;
- the three scan modules' match targets fuzz clean for a minute each, after their doc
  edits;
- the stale progress ticks are re-stamped, and drift and audit pass.
