# M4 packet-parse differential oracle

Milestone 4's load-bearing `core` is **library-shaped** — packet parse (`PacketParser`
+ the per-protocol header classes) and response→port-state classification are
*functions*, not a CLI. So the M4 oracle is a **`cando`-style function-level
differential** (PLAYBOOK Phase 2 / synthesis Step 0.5), not the binary-stdout diff the
M1–M3 connect/`-sV` oracles used: feed the *same* packet bytes to a thin C harness that
links nmap's real `libnetutil` and to the Rust parser, and compare their **canonical
projections**.

This is the **unprivileged** half of the M4 oracle (the approved plan): it runs on the
Linux CI runner with no raw sockets, no Npcap, no Administrator — it exercises pure
parse/classify logic over a fixed byte corpus. The **privileged** half (live raw
send/capture vs C nmap) runs only in the Windows+Npcap real-run gate and is out of
scope here.

## Status

- ✅ **Corpus generator** (`gen_corpus.py`) — 18 vectors, dependency-free, weighted to
  the untrusted-input hazards (truncation, integer boundaries) plus the two Phase-0
  latent-bug triggers. Regenerate with `python3 gen_corpus.py`.
- ✅ **Oracle build de-risked** (see recipe below) — the parse path is nearly
  self-contained; it compiles with `nbase` configured + a minimal `pcap.h` stub.
- ✅ **C oracle harness built** (`oracle/`, `oracle/build.sh`) — links nmap's real
  `IPv4Header` and emits the projection; unused-method symbols inert-stubbed
  (`oracle/stubs.cc`) to avoid a libpcap/dnet link. Build needs `-DHAVE_CONFIG_H`
  (the one flag that makes `nbase.h` include its generated config), `nbase`
  configured, and the `pcap.h` stub.
- ✅ **IPv4 differential wired** — `ipv4_vectors/` (18 IPv4-layer inputs) run through
  the C oracle produce `ipv4_golden/`; the Rust parser's projection is asserted equal
  to that golden by `crates/core/tests/ipv4_differential.rs` (runs in normal
  `cargo test`, no C toolchain needed at test time — the C was run once to produce the
  golden, satisfying "validate every vector against the C first"). Regenerate the
  golden with `oracle/build.sh` when the format or reference changes.
- ⏳ Later header modules (`tcp`, `udp`, `icmp`, …) extend the harness the same way.
  The leaf modules `core::bytes` / `core::checksum` needed no packet oracle (pure
  logic / RFC 1071 vectors).

## Projection format (the canonical shape both sides emit)

One line per parsed header, in layer order, then a trailer. Only the *load-bearing*
semantic fields are projected — the same philosophy as the M1 `project.py`: enough to
catch a real regression (a mis-parsed field, a wrong length, a header the C accepted
that the port dropped or vice-versa), nothing so incidental that it manufactures
divergence.

```
hdr <index> <type> len=<header_bytes>
  ip4 src=<a.b.c.d> dst=<a.b.c.d> proto=<n> ihl=<n> totlen=<n>
  tcp sport=<n> dport=<n> flags=<hex> win=<n>
  udp sport=<n> dport=<n> ulen=<n>
  icmp type=<n> code=<n>
  ...
result <ok|err:<reason>>          # err = a parse that terminated early / rejected
```

A malformed/truncated input projects the headers parsed *up to* the failure plus
`result err:<reason>` — so "the C aborts here but the port degrades" shows up as a
difference in the trailer, not a crash. `result ok` means the whole packet parsed.
Product-of-DB-version fields do not exist at this layer, so (unlike `-sV`) the full
projection is compared.

## C oracle harness — build recipe (de-risked at Phase 0)

The parse path (`PacketParser.cc` + the header `.cc` files) is almost dependency-free.
What Phase-0 probing established it needs:

1. **`nbase` configured** — `nbase.h` includes the autotools-generated
   `nbase_config.h`. Generate it once: `( cd ../../../.. /nbase && ./configure )`
   (runs in <60 s on the CI image; no extra packages).
2. **Include paths:** `-I../../../../libnetutil -I../../../../nbase
   -I../../../../libdnet-stripped/include` plus a **stub `pcap.h`** on the path *before*
   the system/bundled one. `libnetutil/netutil.h` `#include <pcap.h>` only for the
   opaque `pcap_t` and `struct pcap_pkthdr` *declarations* — the parse path never
   *calls* libpcap — so `oracle/pcap_stub.h` (a ~10-line forward-decl shim) satisfies it
   without dragging in the real capture library and its header conflicts. The two
   residual declaration clashes Phase-0 hit (nbase's `gettimeofday` decl vs glibc; a
   `unistd` getopt path via `dnet/os.h`) are resolved with the stub + a
   `-D_GNU_SOURCE`/order fix, documented in `oracle/build.sh` when it lands.
3. **Link** `PacketParser.o` + the header-class `.o`s into `oracle/parse_oracle`; it
   reads a hex packet on stdin and writes the projection above on stdout.

`oracle/` is intentionally empty until the `core::headers::ipv4` slice — the recipe is
recorded here so that slice starts from a known-good path, not a blank page.

## Wiring the differential (per module, once the harness exists)

For each `core::headers::*` / `core::packet_parser` slice, the Rust side grows a tiny
`--project-packet` mode (or a test binary) emitting the same projection, and:

```
for v in corpus/*.hex; do
  diff <(./oracle/parse_oracle < "$v") <(nmap-rs --project-packet < "$v") \
    || echo "DIVERGENCE: $v"   # triage: Rust bug -> fix, or C bug -> DIVERGENCES.md
done
```

Per the kit, **validate every vector against the C first** (a wrong vector that
"passes" teaches nothing): the C harness's projection is the golden output, captured +
versioned under `corpus/golden/` when the harness lands; a **hidden acceptance set**
(vectors not in this committed corpus) guards against overfitting. The two bug-trigger
vectors are the exception that proves the rule — there the C and Rust projections
*must diverge* (the C overflows / aborts; the port degrades safely), and that divergence
is asserted, ledgered in `DIVERGENCES.md` (`udp-checksum-no-fixed-buffer`,
`parse-no-fatal-on-hostile`), not matched.
