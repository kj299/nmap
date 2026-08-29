# Intentional divergences from the C original

Every place the Rust port **deliberately** behaves differently from the C. The
differential harness (`diff_run.py --ledger DIVERGENCES.md`) reads this file:
a case listed here as `- [x]` is a *known-intentional* divergence and is
suppressed (reported as `DIVERGE(ledgered)`, not a failure). Everything else that
diverges is an unexplained regression and fails CI.

**This file is a feature, not an apology.** The prime directive is that the C may
be buggy; where you fixed a C defect, the Rust *should* diverge — record it here
and ship it as a release note. Seed this from the Phase-0 C-flaw scan.

Format — one bullet per case name, ticked when reviewed and accepted:

```
- [x] <matrix-case-name>: <why the Rust intentionally differs; CWE if a security fix>
```

## Security fixes (C defect closed by the port)

### Milestone 1 (planned — from the Phase-0 `scan_c_flaws.py` triage; `nmap-rs/m1_cflaw.json`)
Unchecked `[ ]` = planned (Rust not yet written); ticked `[x]` when the owning
module lands and the fix is in the tree. These are *internal* hardenings — most
produce no observable output divergence (so no differential case), but each is a
C sink the port must not re-implement. Case names prefixed `sec-` for the ones
that could surface in a differential.

- [x] `sec-services-path` (`services.cc:134/140`, owner `core::ports`): C builds
      the fallback services-file path with `GetSystemDirectory(buf,480)` then
      `strcpy(buf+len, "\\drivers\\etc\\services")` — a latent CWE-120 overflow
      resting on a hardcoded `480` "be safe" assumption. Rust uses
      `PathBuf::join`, so the bound is structural and the overflow class is gone.
- [x] `sec-proto-name` (`output.cc:719`, owner `core::output`):
      `strcpy(protocol, IPPROTO2STR(...))` into a fixed buffer (CWE-120). Rust
      renders protocol names as `String`/`&str` with no fixed-size destination.
- [x] `sec-log-format` (`output.cc:923/928`, owner `core::output`):
      `vfprintf(fmt, …)` with a non-literal `fmt` (CWE-134 format-string). Rust's
      compile-time-checked `format!`/`write!` makes the whole class unexpressible.

> **Deferred (not M1):** `output.cc:1564/2003/2027/2048`
> (`strcat`/`sprintf` of OS-detect sequence/IP-ID/timestamp values, CWE-120) live
> on the osscan output path — logged here for **Milestone 5**, not ported in M1.

## Behavioral improvements (not security, but deliberate)

- [x] `services-parse-degrade` (`services.cc` `nmap_services_init`, owner
      `core::ports`): the C `fatal()`s and aborts the whole scan on a malformed
      `nmap-services` line (bad ratio, `/0` denominator, unknown protocol). The
      Rust `ServiceTable::parse` **skips** the offending line and keeps going, so
      a corrupt or partially-edited data file degrades gracefully instead of
      taking the tool down (availability hardening). Verified: real 3.9 MB
      `nmap-services` parses to 27,461 entries; `top_ports(tcp,8)` matches nmap's
      canonical `[80,23,443,21,22,25,3389,110]`.

## Deferred `-p` syntax (rejected explicitly, never silently ignored)

`core::ports::parse_port_spec` returns `PortSpecError::Unsupported` for syntax
accepted by nmap but not yet ported — `[...]` top-ports brackets, `*`/`?`
wildcard service masks, and `P:` protocol scan. Numeric ranges/lists,
`T:`/`U:`/`S:` prefixes, open ranges, and exact service names are supported.
These land in a later slice; until then they error rather than mis-scan.

## M1 output-format abbreviation (confirmed by the differential oracle)

The M1 differential (`tests/differential/`) compares the **semantic** scan result
— host status + open-port state/reason + closed/filtered counts — via
`project.py`, and all matrix cases MATCH C nmap 7.94. The comparison deliberately
projects away the following **intentional MVP renderer abbreviations**, documented
here so the format-level differential planned for M2/M3 treats them as known and
not as regressions. None is a fidelity bug in *what was scanned*; each is a
narrower *rendering* of the same result.

- **Collapsed non-open ports.** C nmap lists every scanned port individually (incl.
  `closed`/`filtered`) until a per-state count crosses its "Not shown" threshold;
  the MVP always collapses non-open ports into a single `<extraports>` / `Not shown`
  summary. `project.py` canonicalizes both to a per-(state,proto) count, so the
  *set* is verified even though per-closed-port identity is not rendered.
- **No decorative XML preamble.** The MVP omits `<!DOCTYPE nmaprun>`,
  `<?xml-stylesheet?>`, `<scaninfo>`, `<verbose>`, `<debugging>`, `<hostnames>`,
  `<times>`, `reason_ttl`, and `startstr`/`xmloutputversion` attributes. These are
  non-load-bearing for the connect scan and land with the output-fidelity pass.
- **Unknown-service labelling.** In `-oN` the MVP prints `unknown` in the SERVICE
  column (matching nmap); in `-oX`/`-oG` nmap emits an *empty* service field / no
  `<service>` element for an unknown port, whereas the MVP currently emits
  `name="unknown"`. Excluded from the projection (M1 does no `-sV`); flagged to
  reconcile in the output-fidelity pass so `-oX` consumers aren't misled.
- **`# Nmap ...` file banners / done-line.** nmap's `-oN`/`-oX`/`-oG` file format
  wraps output in `# Nmap <ver> scan initiated ... as: ...` / `# Nmap done at ...`
  comments and omits the interactive `Starting Nmap` line; the MVP uses its own
  banner/`Nmap done:` line. `project.py` and the format's comment convention make
  this invisible to the semantic diff.

- [x] `no-op-dns-flag` (`cli`, owner `core::options`): nmap-rs accepts `-n`
      (never-do-DNS) but prints a `warning: ignoring unrecognized option '-n'` to
      stderr because forward resolution is only performed for hostname targets
      under `-Pn` anyway — so `-n` is a semantic no-op in M1, not silently honored.
      Stderr-only; does not affect scan output or the differential projection.

## Milestone 3 — service/version detection (`-sV`)

- [x] `probedb-parse-degrade` (`core::probedb`, ports the parse half of
      `service_scan.cc`): the C parser `fatal()`s (aborts the whole process) on the
      first malformed byte of `nmap-service-probes` — a bad protocol, a missing
      delimiter, an unsupported probe-string escape, an out-of-range
      `rarity`/`totalwaitms`/`tcpwrappedms`, an unknown directive, a second NULL
      probe (`assert`), a second `Exclude`, or an `Exclude` after a Probe. Because
      `--versiondb <file>` makes this file **untrusted-shaped input**, the port
      instead *localizes* every failure: the offending line (or probe) is skipped,
      a `ProbeWarning{line, message}` is recorded, and parsing continues. A hostile
      or corrupt database degrades to "fewer probes" rather than aborting the scan,
      and never panics (proved by the `services_probes_parse` fuzz target). This is
      the same deliberate, safer-than-C divergence M1 made for `nmap-services`
      (`services-parse-degrade`). On the *shipped, well-formed* file the behavior is
      identical to C — the corpus differential parses it with **zero warnings** and
      the exact C structural counts (186 non-NULL probes + 1 NULL, 12,171 match
      rules), so the divergence is observable only on malformed input.
- [x] `probedb-waitms-rarity-keep-default` (`core::probedb`): where the C aborts on
      an out-of-range `rarity` (not `1..=9`) or `totalwaitms`/`tcpwrappedms` (not
      `[100, 300000]`), the port keeps the field's **default** value and warns,
      rather than clamping (which would silently alter timing) or aborting. A
      sub-case of `probedb-parse-degrade`, called out because it changes a value
      rather than dropping a whole line.
- [x] `probedb-fallback-unresolved` (`core::probedb`): the C `compileFallbacks()`
      resolves each `fallback` name to a probe pointer at load time and `fatal()`s
      on an unknown name. The port stores fallback **names** (comma/space-split,
      capped at `MAXFALLBACKS`=20) and defers resolution to the probe scheduler
      (a later M3 module), so a probe DB naming a not-yet-defined fallback loads
      instead of aborting. Not a behavior change for the shipped file; a robustness
      improvement for hand-edited databases. Resolution + its own divergence entry
      land with the scheduling slice.
- [x] `pcre-syntax-translate` (`core::pcre_translate`): nmap compiles each pattern
      with PCRE2; the port compiles with Rust's `regex`/`fancy-regex`, whose syntax
      differs in a few spellings. Rather than reject those patterns, a pure,
      semantics-preserving preprocessor rewrites exactly three PCRE spellings into
      their Rust equivalents — `\0`→`\x00`, a bare literal `{`/`}`→`\{`/`\}`, and a
      literal `[` inside a character class→`\[` (Rust reads an unescaped `[` there
      as a nested-class opener). Verified against `regex::bytes`: over the 12,171
      shipped patterns this lifts linear-engine acceptance from 77.50% to **93.57%**
      with no pattern made worse. This changes *how a pattern is spelled to the
      engine*, never *what it matches* — so it is not a behavioral divergence in the
      scan result, but it is recorded here because the on-the-wire regex text sent to
      the engine differs from the C's. The un-rewritable remainder is handled by the
      backtracking fallback (`core::matcher`, ~6.4%) or ledgered per pattern below.
- [x] `pcre-unportable-residual` (`core::matcher`): **resolved to zero on the
      shipped file.** The spike (with its prototype translator) projected ~9
      patterns compiling in neither engine; the production `core::pcre_translate`
      adds the literal-`[`-in-class rewrite the prototype lacked, which fixes the
      leading-bracket-class patterns that made up most of that residual. With the
      bounded-backtracking fallback, `core::matcher` compiles **all 12,171** shipped
      rules (100% coverage, 0 dropped — pinned by `tests/matcher_corpus.rs`). The
      degrade path (drop-with-warning for a rule neither engine accepts) remains for
      hostile/custom `--versiondb` input; it just never fires on the shipped DB.
- [x] `matcher-empty-match-drop` (`core::matcher`): nmap `fatal()`s if a pattern can
      match the empty string (`PCRE2_INFO_MATCHEMPTY`, `service_scan.cc:440`) — such
      a rule would label every port. The port instead **drops** that rule with a
      warning and keeps the rest of the DB usable (degrade, not abort). No shipped
      rule matches empty, so this only fires on a malformed custom DB.
- [x] `matcher-backtrack-bound` (`core::matcher`): nmap bounds PCRE2 with
      `match_limit=50000`/`depth=1000` because a backtracking engine's cost can't be
      *proven*. The port runs ~93.6% of patterns on a **linear-time** engine
      (`regex::bytes`) where the hazard is *unexpressible*, and confines
      backtracking to `fancy-regex` with an explicit `backtrack_limit`; exceeding it
      yields "no match", never a hang. A banner that would ReDoS the C is safe here.
- [x] `matcher-fancy-latin1` (`core::matcher`): `fancy-regex` is `&str`-only, so a
      binary banner is matched through a latin-1 bijection (`byte b` ⇄ `char U+00b`)
      and captures are mapped back to bytes. Exact for the corpus (every
      backtracking pattern is ASCII); the only theoretical difference is that a
      Unicode class (`\w`/`\d`) in a *backtracking* pattern would range over
      U+0080–U+00FF letters rather than bytes — no such pattern exists in the shipped
      DB. Recorded for completeness.
- [x] `versioninfo-no-fixed-buffer` (`core::versioninfo`, ports `getVersionStr` /
      `dotmplsubst` / `substvar`): the C assembles each `-sV` field (`product`,
      `version`, CPE, …) into a **fixed stack buffer** (`SERVICE_FIELD_LEN`) with
      `memcpy`/`Snprintf`, and drops the whole field with a warning if the
      substitution overflows it — the same fixed-destination family behind the
      `strcat`/`sprintf` CWE-120 findings in `output.cc`. The port substitutes into
      a growing `Vec<u8>`, so **there is no fixed destination and no overflow
      class**, and an unusually long value is kept rather than silently truncated
      away. Both the banner (capture bytes) and the templates (a custom `--versiondb`)
      are untrusted, so substitution is fuzzed to be total (never panics). A template
      that references an absent capture group (`$5` with 3 groups) drops **that field**
      (`None`), matching the C's per-field failure — the service name still stands.
- [ ] `servicescan-connect-only` (`core::servicescan` + `sys::servicescan`, scope):
      this slice ports the **connect** `-sV` path — the NULL-probe banner grab and
      TCP probes in the C's exact rarity / intensity / soft-match order
      (`ServiceNFO::nextProbe`). Three C features are **deferred** to a follow-up and
      are *not yet* attempted (so no wrong result is produced — the affected service
      simply reports `unknown`/soft rather than a fabricated version): **SSL/STARTTLS
      tunnels** (probing through TLS; needs `rustls`), **UDP probes** (needs the M4
      raw/UDP path), and the **RPC grinder** (`nmap_ftp.cc` bounce is also out of
      scope). The state machine is structured so each slots in as an added phase
      without disturbing the connect core. Tracked, never silently dropped.
- [x] `servicescan-bounded-banner` (`sys::servicescan`): each probe's banner read is
      capped (`max_banner_bytes`, default 64 KiB) and time-bounded by the probe's
      `totalwaitms`. A chatty or hostile port can neither exhaust memory nor stall the
      scan — a bound the C's `nsock` read loop imposes only via the overall timeout.
- [x] `cli-sv-service-name-differential` (`cli` + `tests/differential`): the `-sV`
      differential vs C nmap projects the detected **service name** per open port
      (`service <port> <proto> <name>`, only for `method="probed"` findings), **not**
      the product/version strings. Those vary with each tool's `nmap-service-probes`
      version — comparing them would make the gate a data-file-version check, not a
      port-fidelity check. Verified: nmap-rs `-sV` and C nmap 7.94 both detect `ssh`
      on the loopback SSH-banner fixture (case `sv-ssh-banner`, MATCH). Product/
      version fidelity is unit-pinned in `versioninfo`/`output`, not the differential.
- [x] `cli-version-display-escape` (`cli`): `-sV` version fields are byte-faithful
      through `core` (`Vec<u8>`); the CLI escapes them for display as `\xNN` for
      non-printables (nmap's `nmap_printable`) and caps each field at 256 bytes, so a
      hostile banner cannot corrupt or flood the terminal. Display-only; the XML
      carries the same escaped text under `xml_escape`.

## Milestone 4 — raw-packet infrastructure (planned; from the Phase-0 read in `docs/M4-ANALYSIS.md`)

These are seeded from the Phase-0 flaw inventory (the heuristic `scan_c_flaws.py` was
low-signal for this layer; the real hazards are parse-side bounds on attacker-
controlled captured packets, found by reading the code). Each is a C defect the port
**fixes rather than re-implements**; `[ ]` = to be discharged when the owning module
lands, `[x]` = confirmed by that module's gates.

### Security fixes (C defect closed by the port)

- [x] `udp-checksum-no-fixed-buffer` (`core::headers::udp`, ports `UDPHeader::setSum`;
      **realized** — `UdpHeader::computed_checksum` sums a growing `Vec` whose length
      is its capacity, so the fixed-`aux[65527]`/`maxlen 65528` overflow class is gone;
      pinned by `max_size_datagram_checksum_does_not_overflow`, which exercises the
      exact 65528-byte datagram that overflows the C):
      the C sizes the checksum scratch buffer `u8 aux[65535-8]` = **65527 bytes**
      (`UDPHeader.cc:197`) but then calls `dumpToBinaryBuffer(aux, 65536-8)` passing
      **maxlen 65528** (`:209`); `dumpToBinaryBuffer` only aborts when a *single*
      element exceeds the remaining budget (`PacketElement.h:171`), so a UDP+payload
      chain whose total `getLen()` is 65528 writes one byte past the stack buffer — a
      real, reachable **1-byte stack overflow (CWE-121)**. (The TCP path uses the same
      constant for both and is correct; only UDP's two constants disagree.) The port
      computes the checksum over a `&[u8]`/growing `Vec` sized from a single source, so
      the overflow class does not exist. Fix, not re-port.
- [ ] `parse-no-fatal-on-hostile` (`core::headers::*`, `core::packet_parser`, ports
      `netutil.cc` `icmp_get_data`/`icmpv6_get_data` and the header `validate()`s): the
      C `netutil_fatal()`s (process abort) on an attacker-chosen inner ICMP type
      (`netutil.cc:848-878`) — a **remote DoS**: a single crafted ICMP error aborts the
      scan. In a `#![forbid(unsafe_code)]` core every parse path returns
      `Result::Err`/`None` and the scan continues (degrade, not abort). Proved by the
      packet-parser fuzz target (no panic/abort on any input).
- [ ] `idle-ipid-no-assert` (`core::ipid`, ports `idle_scan.cc`): the C
      `assert(newipid < 0xffff)` (`idle_scan.cc:698`) is reachable with an
      attacker-influenced IP-ID (a crafted or noisy zombie reply) → **panic-on-input**.
      The port returns a recoverable "zombie unusable" error. Fix, not re-port.
- [ ] `ethsend-surface-errors` (`sys::npcap`, reimplements `eth-win32.c` `eth_send`):
      the C ignores `PacketSendPacket`'s BOOL and unconditionally returns `len`
      (`eth-win32.c:104`), so a failed raw send looks successful. The port returns the
      real send result. Additive robustness (Windows-only path).
- [ ] `rawdata-no-signed-truncation` (`core::headers::raw`, ports `RawData::store`):
      the C compares `int length >= (int)len` with `len` a `size_t` (`RawData.cc:147`);
      `len > INT_MAX` casts negative and defeats the guard. The port carries lengths as
      `usize` with checked slicing; the truncation/underflow class is removed by
      construction. Bounded in practice today; hardened regardless.

### Behavioral / structural (not security, ledgered)

- [x] `parser-owned-return` (`core::packet_parser`): the C returns a **`static`
      `this_packet[MAX_HEADERS_IN_PACKET+1]`** array by pointer (`PacketParser.cc:126`) —
      non-reentrant, not thread-safe; a second call clobbers a live result. The port
      returns an owned `Vec<Header>` by value (reentrant, `Send`), and each element
      carries the fully-parsed typed header rather than the C's bare `(type, length)`
      pair, so callers read TCP flags / ICMP type / addresses without re-parsing. The
      differential compares the `(type, length, offset)` projection, which is identical.
      *(Realized at M4 `core::packet_parser`.)*
- [x] `packet-parser-ported-subset-degrades-to-raw` (`core::packet_parser`): where the C
      walk would descend into a header this milestone has **not** ported — ICMPv6
      (IPv6 `next_header == 58`), the IPv6 extension-header chain (`0`/`43`/`44`/`60`),
      SCTP, etc. — the port stops sub-parsing and records the remainder as a single
      `Header::Raw` instead. This is strictly *safer* (it never parses un-audited
      bytes) and conservative (no field is fabricated). The differential corpus is
      restricted to chains within the ported set so C and Rust agree byte-for-byte; the
      degrade behavior is pinned by `core::packet_parser` unit tests
      (`ipv6_icmpv6_degrades_to_raw_not_subparsed`). To be tightened as those parsers
      land (M5+). *(Introduced at M4 `core::packet_parser`.)*
- [x] `build-no-static-myttl` (`core::build`): the C's "pure" `build_ip_raw` holds a
      function-local `static int myttl` (`tcpip.cc:524`) — a reentrancy landmine. The
      port threads TTL as an explicit parameter (as it does all `NmapOps o.*` reads the
      builders touch: `o.badsum` → `Ipv4Spec::bad_sum`, `o.ttl`, decoys). No retained
      state between calls. *(Realized at M4 `core::build`.)*
- [x] `build-explicit-fields-no-magic` (`core::build`): the C builders inject hidden
      randomness and silent defaults — `ttl == -1` → random TTL (`build_ip_raw`),
      `seq == 0 && SYN` → random ISN and `window == 0` → 1024 (`build_tcp`). Randomness
      at the construction layer is untestable and non-reproducible. The port takes
      concrete values only; the scan driver at the edge supplies any randomness. This
      matches nmap's own `libnetutil` header-class setters (the build differential's
      C oracle), so the ported builders agree with the class-level C byte-for-byte.
      *(Introduced at M4 `core::build`.)*
- [x] `build-unknown-icmp-no-fatal` (`core::build`, ports `build_icmp_raw`): the C
      `fatal()`s (aborts the whole process) on an ICMP type/code it does not construct
      (`tcpip.cc`). The port returns `BuildError::UnknownIcmpType` — a library never
      aborts. *(Introduced at M4 `core::build`.)*
- [x] `classify-ipv4-icmp-only-for-now` (`core::classify`): the port classifies
      TCP/UDP/ICMPv4/SCTP responses; the C's ICMPv6 response branch
      (`scan_engine_raw.cc:1933`) is deferred with the rest of the IPv6 raw path (M5+),
      consistent with the other IPv4-only-for-now scoping. The IPv4 decision logic is
      exhaustively differential-checked (12504 cases — every scan × all 256 TCP flag
      bytes × ICMP type/code/from-target × SCTP chunk — 0 mismatches). This is also a
      *structural* safety win over the C: nmap's nested `switch`es with fall-through and
      an unset `newstate` become total functions returning `Option<PortState>`, so an
      unhandled response is an explicit `None`, never an accidental stale state.
      *(Introduced at M4 `core::classify`.)*
- [x] `recv-validate-ipv4-only-for-now` (`core::recv_validate`, ports `validatepkt`):
      the C `validatepkt` validates both IPv4 and IPv6 (the latter walking the
      extension-header chain via `ipv6_get_data`). This port validates the IPv4 path
      and rejects IPv6 with `Reject::Ipv6Unsupported`, deferring IPv6
      receive-validation to the milestone that lands the IPv6 extension-header parser
      (M5+), consistent with `packet-parser-ported-subset-degrades-to-raw`. The
      IPv4 accept/reject decision — including the security-critical `validateTCPhdr`
      option walk — matches nmap byte-for-byte (differential 18/18 + a 6000-packet
      randomized C-vs-Rust cross-check, 0 mismatches). *(Introduced at M4
      `core::recv_validate`.)*
- [x] `send-payload-no-silent-truncation` (`core::build`, ports `build_icmp_raw`/
      `build_igmp_raw`): the C copies an oversized data payload into fixed
      `pingpkt.data[1500]`/`igmp.data[1500]` buffers via `MIN(dlen,datalen)`
      (`tcpip.cc:940,1054`) — no overflow, but oversized payloads are **silently
      truncated**; separately `build_ip_raw` narrows `int packetlen` into the `u16` IP
      length, silently wrapping past 65535. The port sizes output to the payload (a
      growing `Vec`) and returns `BuildError::PayloadTooLarge` past 65535 rather than
      truncate or wrap; pinned by `oversized_payload_rejected_not_truncated`.
      *(Realized at M4 `core::build`. IGMP builder deferred with the SCTP/IGMP scans.)*
- [ ] `icmpv4-no-uninit-tail-read` (`core::headers::icmpv4`): the C's union-overlay
      getters read the zero-filled tail of a fixed buffer on a truncated inner ICMP
      (`ICMPv4Header.cc` getters via `is_response`) — not OOB, but returns bytes never
      on the wire. The port's parser only exposes fields actually present (length-
      checked), returning `None` otherwise. Observable only on truncated/hostile input.

## Milestone 4 — SYN scan driver (`-sS`)

The first raw scan type, wiring `core::build` (probe) + `sys::rawio` (send) +
`sys::capture` (receive) + `core::recv_validate` + `core::classify` into a
bounded-concurrency scan over the pure `core::engine::HostScheduler`. The port-state
*decisions* are the already-ledgered `core::classify` behavior; these entries cover
the driver-specific choices.

- [x] ~~`synscan-icmp-match-deferred`~~ — **resolved**: `match_syn_response` now matches
      an ICMP unreachable/time-exceeded quoting one of our SYNs and reports *filtered*
      with the specific ICMP reason. See the ICMP back-fill section below.
- [x] `synscan-late-reply-no-grace-window` (`sys::synscan`): nmap keeps a probe
      matchable for `10*min(1s,RTO)` past its timeout (`probeExpireTime`,
      `scan_engine.cc:525`), so a very late reply can still resolve a port. This driver
      resolves a probe when its timeout elapses (retransmit or, at the retry cap,
      `Filtered`) and drops a reply arriving after that. A safe, simpler policy — it can
      only mislabel a genuinely-open port that answered *after* every retransmission
      expired as `filtered`, the same conservative direction nmap's own timeout takes.
- [x] `synscan-bpf-self-probe-filter` (`sys::synscan` + `core::synscan`): on loopback
      the scanner sees its **own** outgoing SYNs. nmap drops them with an ipid
      self-probe guard (`scan_engine_raw.cc:1675`); this port instead scopes the pcap
      BPF filter to `tcp and dst portrange base..base+max_tryno` — a reply's destination
      is our encoded source port (in range), our own probe's destination is the scanned
      service port (out of range) — so self-probes never reach the matcher. Behavioral
      shape, not output: replies delivered are identical.
- [x] ~~`synscan-single-host-first-slice`~~ — **resolved**: `-sS` runs on the shared
      multi-host group engine (`sys::group::SynKind`), driving a whole host group through
      one capture demultiplexed by source address, as nmap's `ultra_scan` does.

  Inherits `build-explicit-fields-no-magic` (the driver passes `window=1024` and the
  encoded `seq` explicitly, since `build_tcp_raw` carries no magic defaults) and
  `validate-ipv4-only-for-now` (IPv6 SYN scan awaits the IPv6 receive path).

- [x] `route-minimal-onlink-then-gateway` (`sys::route`, minimal port of
      `nmap_route_dst`): source/interface selection tries loopback → an interface whose
      subnet contains the target → the first up interface with a default gateway, rather
      than a full longest-prefix routing-table lookup. Correct for the common
      single-subnet / default-route host; a full route table read is a later
      refinement. The capture is assumed to carry a link header (`eth_included = true`),
      correct for Linux `lo` and Ethernet — the datalinks the parser handles.
- [x] `raw-scan-pcap-feature-gated-fallback` (`cli`): `-sS` needs the `pcap` capture
      backend (a build-time libpcap/Npcap dependency) and `CAP_NET_RAW`. When the build
      lacks `pcap`, or the process lacks privilege, the CLI **prints a notice and falls
      back to the connect scan** rather than failing — the "degrade gracefully, never
      hard-fail" posture from the plan. nmap similarly needs libpcap and root for `-sS`.

## Milestone 4 — UDP scan driver (`-sU`)

- [x] ~~`udpscan-empty-payload`~~ — **resolved**: `core::payload` supplies nmap's
      protocol-specific UDP payloads (see the payload section below), so an open UDP port
      running a real service now resolves to `open` rather than `open|filtered`. Ports
      with no registered payload still get a bare datagram, as in the C.
- [x] `udpscan-icmp-embedded-match` (`core::udpscan`): the UDP matcher parses the
      **IPv4/UDP packet quoted inside an ICMP error** to tie a port-unreachable (→
      closed) or other unreachable/time-exceeded (→ filtered) back to the probe it
      answers — the embedded-probe match `synscan` deferred (`synscan-icmp-match-deferred`).
      Bounds-checked and fuzzed (the nested parse is a second untrusted-input surface).
      Generalized to TCP and shared with the SYN and flag scans in the ICMP back-fill
      section below (`core::icmp_quote`).
- [x] ~~`udpscan-single-host-first-slice`~~ — **resolved**: `-sU` now runs on the shared
      multi-host group engine (`sys::group::UdpKind`), so the single-host limit is gone.
- [x] `udpscan-icmp-attributed-to-quoted-destination` (`core::udpscan`): an ICMP error is
      attributed to the **destination of the probe it quotes** — the host we scanned —
      rather than to whichever address sent the ICMP, which is legitimately an
      intermediate router. `from_target` (the test that promotes a port-unreachable from
      *filtered* to *closed*) is correspondingly "the sender is the host the quoted probe
      was addressed to", computed from the packet alone. This makes the matcher a pure
      function of the frame — no ambient target to pass in, which is what lets one matcher
      serve a whole host group.

      **Structural only — this matches the C.** An earlier revision of this entry claimed
      the rule was *stricter* than the C; that was wrong, and is corrected here.
      `scan_engine_raw.cc` looks the host up by `encaps_hdr.dst` (the quoted destination)
      and then computes `from_target` against the outer ICMP source, which is exactly the
      rule above. No behavioral divergence.

## Milestone 4 — TCP flag scans (`-sA`/`-sW`/`-sM`/`-sF`/`-sN`/`-sX`)

One generalized `core::flagscan` + `sys::flagscan`, parametrized by
`classify::ScanType`, covers all six stateless flag scans (the C spreads them across
`scan_engine_raw.cc`). The port-state decisions are the already-ledgered
`core::classify` behavior; these entries cover the shared driver's choices.

- [x] `flagscan-match-on-port-not-sequence` (`core::flagscan`): a flag-scan reply is an
      RST that (per RFC 793) takes its sequence from our *ack* field and carries no ack
      of its own, so — unlike a SYN/ACK — it cannot reflect our sequence. The matcher
      keys purely on the reply's destination port (= our per-attempt encoded source
      port); the pcap BPF filter scopes capture to that range, excluding our own
      outgoing probes. No behavioral divergence; a structural note on how matching
      differs from the SYN scan.
- [x] ~~`flagscan-icmp-match-deferred`~~ — **resolved**: all six flag scans match ICMP
      errors through the shared `match_tcp_icmp_error`. This matters most for
      `-sF`/`-sN`/`-sX`/`-sM`, whose no-response default is `open|filtered`: only the ICMP
      error can tell those apart from *filtered*. See the ICMP back-fill section below.
- [x] ~~`flagscan-single-host-first-slice`~~ — **resolved**: all six flag scans now run on
      the shared multi-host group engine (`sys::group::FlagKind`).

## Milestone 4 — multi-host group scan engine

- [x] `group-scan-shared-capture-demux-by-src` (`sys::group`): a whole host group is
      scanned through **one** raw sender + **one** pcap capture (nmap's `ultra_scan`
      host-group model), with a per-host `HostScheduler` and a `GroupScheduler` bounding
      total probes in flight. A captured reply is routed to the host that sent it by its
      **source IP**, so every host shares one encoded source-port range — the source
      address disambiguates them (`SynReply` now carries `src_ip`). Structural, not an
      output divergence; the per-host verdicts are identical to the single-host path.
- [x] `group-scan-per-route-bucketing` (`sys::group`): the CLI entry point buckets
      targets by egress route (interface + source) and runs one shared-capture group per
      bucket; targets reachable through different interfaces scan as separate groups
      rather than one. Matches nmap's per-interface capture; no output divergence.
- [x] `group-scan-one-engine-for-every-raw-scan` (`sys::group`): every raw scan — `-sS`,
      `-sU`, and the six flag scans — runs on **one** driver loop, with the scan-specific
      parts (probe build, reply match, no-response default, BPF filter) behind the
      `RawScanKind` trait. The three near-identical single-host drivers this replaces are
      deleted rather than left beside it; a single host is simply a group of one. The C
      spreads the equivalent logic across `scan_engine_raw.cc` per technique. Structural:
      one loop to audit, fuzz, and keep correct instead of four that can drift apart.
      Per-scan verdicts are unchanged (the retired drivers' unit tests were ported onto
      the engine, and the privileged on-the-wire differential + loopback e2e gates for
      each scan now exercise it directly).

## Milestone 4 — UDP probe payloads (`payload.cc`)

`payload.cc` has no data file of its own: `init_payloads()` **derives** the payload table
from `nmap-service-probes` — every `Probe UDP` line not flagged `no-payload` contributes
its probe string to each port in its `ports` directive (`probablePorts`, *not*
`sslports`). Our `core::payload` is the same derivation over the already-ported
`core::probedb`, so it introduces no new file format and no new untrusted-input parser.
Over the shipped file both implementations agree on all **33 205** (port, payload) pairs
across **33 110** ports (`payload_corpus.rs`, ground truth from an independent
derivation).

- [x] `payload-cap-warns-not-fatal` (`core::payload`): the C `fatal()`s — killing the
      whole scan — if one port accumulates more than `MAX_PAYLOADS_PER_PORT` (0xff)
      payloads, a limit that exists only because its count/index are `u8`. We keep the
      same ceiling so the payload *sequence* matches, but **truncate and report** the
      port via `capped_ports()` instead of aborting: an over-generous data file should
      cost a little detection depth, not the run. Unreachable with the shipped file
      (max observed is 4); asserted in the corpus gate and exercised by a unit test.
- [x] `payload-missing-db-degrades` (`cli`): C nmap `fatal()`s when it cannot load
      `nmap-service-probes`, so a `-sU` scan fails outright on a stripped install. We
      warn and scan with bare datagrams — more ports read `open|filtered`, but the scan
      still runs. Same posture as `-sV` (`probedb-parse-degrade`): an absent *optional*
      data file must not be fatal.
- [x] `payload-one-datagram-per-payload` (`sys::group`): a port with N registered
      payloads sends N datagrams per attempt, all from the same encoded source port —
      matching the C's `for (i < MAX(udp_payload_count(dport), 1))` loop. Because they
      share a source port, a reply cannot be attributed to a particular payload (the C
      notes this too), so the engine keeps **one** outstanding entry per `(port, tryno)`
      and matches replies by port. Consequence, ledgered: the group congestion window
      counts *logical probes*, not datagrams, so a port with several payloads puts more
      bytes on the wire per admitted probe than a SYN scan does. Not an output
      divergence; it makes `-sU` pacing slightly more permissive than the C's
      per-datagram accounting.

## Milestone 4 — ICMP back-fill for the TCP scans (`core::icmp_quote`)

An ICMP destination-unreachable (type 3) or time-exceeded (type 11) quotes the packet
that provoked it, so it can be matched back to the probe it answers. The UDP scan used
this from the start; `core::icmp_quote` generalizes the quote parser to TCP and shares it
with `-sS` and all six flag scans, closing `synscan-icmp-match-deferred` and
`flagscan-icmp-match-deferred`.

It matters most for `-sF`/`-sN`/`-sX`/`-sM`, whose no-response default is `open|filtered`:
without ICMP matching there is no way for those scans to report a port as *filtered* at
all. The three matchers also now carry the **reason** they matched on, so a filtered port
reports the specific code (`host-unreach`, `admin-prohibited`, `time-exceeded`, …) instead
of a generic `no-response`.

- [x] `icmp-quote-requires-our-source` (`core::icmp_quote`, **fixes a gap in our own
      earlier slice**): an ICMP error is only considered when the packet it quotes has
      **our** source address — the C's `if (sockaddr_storage_cmp(USI->SourceSockAddr(),
      &encaps_hdr.src) != 0) continue;`, *"If it didn't come from us, we don't care."* The
      UDP matcher shipped without this check (its port/attempt encoding limited the
      impact, but a crafted error quoting a third party's packet could be accepted). All
      three scans now enforce it, which is why every match context carries `our_ip`.
      Matches the C; no divergence in behavior, a hardening relative to what we shipped.
- [x] `icmp-quote-verifies-our-sequence` (`core::synscan`): for a TCP scan the quote
      contains our original packet, so — unlike a RST, which reflects no sequence of ours
      (`flagscan-match-on-port-not-sequence`) — the encoded sequence *is* present and is
      verified against `seq32_encode(seqmask, tryno)`. Ports the C's
      `ntohl(tcp.th_seq) != probe->tcpseq()` check. This makes a flag scan's ICMP path
      strictly better authenticated than its RST path.
- [x] `icmp-reason-fidelity` (`core::icmp_quote`, `core::model`): ports
      `portreasons.cc: icmp_to_reason`, adding the reasons nmap distinguishes —
      `proto-unreach`, `dest-unreach`, `net-prohibited`, `host-prohibited`,
      `admin-prohibited`, `time-exceeded`. Note codes 9/10/13 are **three different**
      reasons in nmap, not one "admin-prohibited". Previously an ICMP-derived *filtered*
      reported `no-response`, which was inaccurate; UDP's ICMP-filtered ports change
      reason string accordingly (the *state* is unchanged).
- [x] `icmp-bpf-widened-for-tcp-scans` (`sys::group`): the SYN and flag BPF filters now
      also admit `icmp and dst host <us>`. An ICMP error is addressed to our *address* and
      carries no port of ours in its own header, so a purely port-scoped filter dropped it
      at the kernel and the port fell back to the no-response default. Matches the UDP
      filter's existing shape.

## Milestone 5 — OS detection: the `nmap-os-db` expression matcher

`core::osdb::expr` ports `expr_match()` from `osscan.cc` — the matcher every OS
fingerprint attribute goes through. Both of its inputs are attacker-influenced: the
*expression* comes from `nmap-os-db`, which `--osscandb` lets a user point at any file,
and the *value* is derived from packets the scanned host sent back. It is verified
against a verbatim transcription of the C over **23,812** cases (23,200 comparable,
2,047 of them matches) drawn from the grammar's shapes, the shipped 5 MB database, and a
deterministic random cross-product.

### Security fix (C defect closed by the port)

- [x] `osdb-expr-unterminated-nest-no-abort` (`core::osdb::expr`): an expression
      containing `[` with no closing `]` makes the C's `assert(q1)` fire. Measured, not
      inferred — **612 of the 23,812 corpus cases abort the C outright**, which is a
      denial of service reachable from a malformed or hostile `nmap-os-db`. Release
      builds define `NDEBUG`, which compiles the assert out and instead evaluates
      `q1 - nest` and `q1 + 1` with `q1 == NULL` — undefined behavior. In practice the
      resulting `explen` is huge, so `p_end` wraps below `p` and the scan loops run zero
      times; five hand-built variants under ASan returned "no match" without an
      out-of-bounds read, so the observable release-build symptom is a wrong-ish answer
      rather than a crash. The port treats an unterminated `[` as **no match** and
      continues with the remaining alternatives — total on all input, proven by the
      `osdb_expr` fuzz target (3.0M runs) and asserted case-by-case in
      `expr_differential.rs`.

### Faithfully reproduced C quirks (deliberately *not* fixed)

Both look like bugs, but the shipped database was authored against them, so "fixing"
them would mis-match real fingerprints. Reproduced deliberately and pinned by the
differential:

- [x] `osdb-expr-vlen-persists-across-alternatives` (`core::osdb::expr`): the C declares
      `subval` inside the alternation loop (reset per alternative) but `vlen` is the
      function parameter, so stripping leading zeros while testing one alternative
      permanently shortens the value every later alternative sees. Our port keeps `vlen`
      outside the loop for exactly this reason.
- [x] `osdb-expr-nested-run-is-greedy` (`core::osdb::expr`): a `[...]` group is tested
      against the *entire* following hex run, not the minimum needed. Since `B` is a hex
      digit, `M[1-6]ST11` does **not** match `M5B4ST11` — the run is `5B4`.

## Milestone 5 — the `nmap-os-db` parser

`core::osdb::{model,parse}` port `parse_fingerprint_file()` and its helpers from
`osscan.cc`. `--osscandb <file>` makes the 5.1 MB database **attacker-supplyable**, and
it is parsed before any scanning happens — the same threat-model boundary
`nmap-service-probes` has. Verified against the shipped file: **6,108 fingerprints,
7,100 `Class` lines, 6,968 `CPE` lines, 79,404 record test lines, zero warnings**
(`osdb_corpus.rs`), and fuzzed (`osdb_parse`, 2.0M runs).

- [x] `osdb-parse-degrade` (`core::osdb::parse`): **no input aborts the parse.** The C
      `fatal()`s — killing the whole scan — on a second `MatchPoints` block, a
      `MatchPoints` attribute that is not a positive integer, a `Fingerprint` line with
      no terminator or an empty OS name, a `Class` line with fewer than four `|` fields,
      and a `CPE` line with no preceding `Class`. Each becomes a `DbWarning` here and
      parsing continues, so a corrupt or hostile database costs fingerprints rather than
      the run. The same deliberate divergence M1 made for `nmap-services`
      (`services-parse-degrade`) and M3 for `nmap-service-probes`
      (`probedb-parse-degrade`). On the shipped, well-formed file the behavior is
      identical to the C — the corpus gate parses it with zero warnings and the exact
      structural counts — so this is observable only on malformed input.
- [x] `osdb-parse-skips-only-the-bad-line` (`core::osdb::parse`): on a malformed test
      line the C executes `goto top`, abandoning the **rest of the current record** (its
      remaining lines are then reported as stray top-level parse errors, and the partial
      record stays in the database). This port drops just the offending line and keeps
      the record's other tests, which loses less detection capability for the same input.
      Unreachable on the shipped file.

## Milestone 5 — the fingerprint match scorer

`core::osdb::score` ports `AVal_match`, `compare_fingerprints` and `match_fingerprint`
from `osscan.cc`. Both inputs are attacker-influenced: the reference database comes from
`--osscandb`, and the observed fingerprint is assembled from probe responses the target
host chooses freely. Verified against the shipped database with a concrete Linux
observation — a perfect 1.0 on `Linux 3.2 - 4.14` with a coherent ranking behind it —
plus the early-exit invariant checked over all 6,108 records (`osdb_score_corpus.rs`),
and fuzzed (`osdb_score`, 3.5M runs).

- [x] `osdb-score-admits-zero-without-aborting` (`core::osdb::score`): the C inserts a
      new match by scanning its fixed 36-slot array for a slot whose accuracy is
      *strictly less* than the new score, and `fatal()`s — killing the process — if it
      finds none. A record scoring exactly `0.0` finds none, and is admitted whenever the
      threshold is `0.0` (since `0.0 >= 0.0` passes the entrance test). nmap's own callers
      all pass `OSSCAN_GUESS_THRESHOLD` (0.85), so this is not reachable from the C CLI
      today, but it is reachable through the function's own documented interface. This
      port appends instead, which is the same placement without the abort — exercised
      against the real database by `a_zero_threshold_admits_everything_without_aborting`.
- [x] `osdb-score-missing-matchpoints-degrades` (`core::osdb::score`): the C reaches
      `DB->MatchPoints->getTestDef()` with no null check, so scoring against a database
      whose `MatchPoints` block is missing or was rejected is a null-pointer dereference.
      Here an absent block scores as an all-zero weight table: every attribute is worth
      nothing, nothing clears the threshold, and the answer is `NoMatches`. Losing OS
      detection on a broken database is the right failure; crashing mid-scan is not.
- [x] `osdb-score-out-of-range-threshold-clamped` (`core::osdb::score`): the C asserts
      `0 <= threshold <= 1` in `match_fingerprint` but not in `compare_fingerprints`,
      which computes `unsigned long max_mismatch = (1.0 - threshold) * numprints`. A
      threshold above 1 makes that product negative, and converting a negative double to
      an unsigned integer type is undefined behaviour. Both entry points clamp here (and
      map `NaN` to `0.0`), so an out-of-range threshold is merely useless.
- [x] `osdb-score-negative-weights-unrepresentable` (`core::osdb::score`): `AVal_match`
      `fatal()`s on a negative point value. Our match-point weights are `u32`, so a
      negative weight cannot be represented and the check has nothing to catch — the
      parser rejects non-positive-integer point values at the source
      (`osdb-parse-degrade`).
- [x] `osdb-score-early-exit-is-not-a-lower-bound` (`core::osdb::score`): **not a
      divergence — a documented C property this port reproduces exactly**, recorded
      because it is easy to get wrong. `compare_fingerprints` stops once the lost weight
      exceeds `(1 - threshold) * num_points` and returns the partial ratio. That value is
      guaranteed strictly below `threshold`, but it is *not* the record's true accuracy
      and *not* a lower bound on it — abandoning the remaining tests discards their
      mismatches as well as their matches, so the partial ratio can land above the exact
      one (observed on the shipped database: 0.80530 returned where the exact score is
      0.80527). It is therefore only meaningful as "did not clear the bar", and two
      rejected records must never be ranked against each other by it. `match_fingerprint`
      is unaffected: every record it *keeps* was scored without the early exit firing, so
      the reported list is exact. The corpus gate asserts this over all 6,108 records.

## Milestone 5 — MAC vendor lookup

`core::macvendor` ports `MACLookup.cc`. `nmap-mac-prefixes` is loaded from the data-file
search path, so like the other databases it is untrusted-input-shaped. Verified against
the shipped file: **52,085 prefixes (38,930 MA-L + 6,262 MA-M + 6,893 MA-S), zero
warnings**, with every prefix's resolution cross-checked against an oracle built from the
raw text by string operations — including the **410 assignments shadowed by a longer
one** (`macvendor_corpus.rs`) — and fuzzed (`macvendor_parse`, 5.5M runs).

- [x] `macvendor-parse-degrade` (`core::macvendor`): **one bad line no longer discards the
      rest of the file.** The C prints an error and then `break`s out of its read loop on
      any unparseable line — a wrong digit count, a prefix not followed by whitespace, a
      leading byte that is not a hex digit. Since the loop is abandoned rather than
      continued, a single stray byte near the top of the file silently costs *all*
      remaining vendor entries, degrading MAC attribution across the whole scan with only
      one line of warning. A blank line does it too, since a blank line is "not a hex
      digit". Here each bad line becomes a `MacDbWarning` and parsing continues; blank
      lines are skipped silently, as they carry no information. Same shape as
      `services-parse-degrade`, `probedb-parse-degrade` and `osdb-parse-degrade`. On the
      shipped file the behaviour is identical — it parses with zero warnings.
- [x] `macvendor-empty-vendor-skipped` (`core::macvendor`): a line holding a valid prefix
      and no vendor name reaches an `assert(*endptr)` in the C, aborting a debug build. In
      a release build (`NDEBUG`) the assert vanishes and the entry is stored with an
      **empty** organisation name, which would later be reported as the host's vendor.
      Here the line is warned about and skipped, so no address can resolve to a blank
      registrant.
- [x] `macvendor-no-fgets-truncation` (`core::macvendor`): the C reads lines into a
      128-byte `fgets` buffer, so a longer line is split and its tail is parsed as if it
      were a new line — which fails the hex-digit check and (per
      `macvendor-parse-degrade`) abandons the file. This port reads whole lines. The
      shipped file's longest line is 105 bytes, so the two agree on it today; the
      divergence only shows on a file with a long vendor name.
- [x] `macvendor-lookup-order-preserved` (`core::macvendor`): **not a divergence** —
      recorded because it is load-bearing and easy to lose. Prefix keys are tagged with
      their digit count in the high bits exactly as the C's `(len << 36)` does, so the
      three IEEE assignment sizes occupy disjoint key ranges and iterate MA-L, then MA-M,
      then MA-S. `find_prefix` (the `--spoof-mac <vendor>` path) returns the *first*
      match in that order, so the tagging decides which of several matching registrants is
      chosen. Lookup independently tries the most specific block first, so a host inside a
      36-bit assignment is attributed to that registrant rather than to the holder of the
      enclosing 24-bit block.

## Milestone 5 — the IPv4 OS-detection probes

`core::osprobe::build` ports the probe-construction half of `osscan2.cc`. Verified by a
**C-oracle differential**: all 23 packets are decoded by nmap's own
`IPv4Header`/`TCPHeader`/`UDPHeader`/`ICMPv4Header` classes and must project identically
under the Rust parsers, over a projection that includes every field the battery is
defined by — TOS, DF, IP ID, TTL, the exact TCP option bytes, the urgent pointer and the
reserved bits (`osprobe_differential.rs`, oracle mode `osprobe`). Fuzzed
(`osprobe_build`, 2.7M runs).

- [x] `osprobe-missing-port-is-an-error` (`core::osprobe::build`): each of the C's senders
      begins `if (hss->openTCPPort == -1) return;` (or the closed-port equivalent) and
      returns *success*, so the driver cannot distinguish "probe skipped, no suitable
      port" from "probe sent, no reply". Those mean different things to the fingerprint —
      an unanswered probe is evidence about the stack, an unsent one is evidence about
      nothing — and the C's `FingerPrint` records them identically. Here the missing port
      is a typed error (`NoOpenTcpPort`/`NoClosedTcpPort`/`NoClosedUdpPort`) and the
      caller decides.
- [x] `osprobe-index-out-of-range-is-an-error` (`core::osprobe::build`): `sendTSeqProbe`,
      `sendTOpsProbe`, `sendT1_7Probe` and `sendTIcmpProbe` each open with an `assert()`
      on the probe index, aborting the process in a debug build and running off the ends
      of `prbOpts[]`/`prbWindowSz[]` in a release build where the assert is compiled out.
      Every table lookup here is bounds-checked and an out-of-range index returns
      `UnknownProbe`.
- [x] `osprobe-params-are-explicit` (`core::osprobe::build`): the C reads the random
      bases, the target ports and `o.ttl` from global and per-host mutable state at send
      time, so a probe's bytes depend on when it is built. Everything is an input here,
      making construction a pure function — which is what allows the differential above
      to pin every byte, and the fuzz target to assert determinism. A continuation of the
      M4 entry `build-explicit-fields-no-magic`.
- [x] `osprobe-default-ttl-is-255` (`core::osprobe::build`): **not a divergence** —
      recorded because it is surprising and easy to "fix" by mistake. nmap's `o.ttl`
      defaults to `-1`, and `fill_ip_raw` assigns it straight into the 8-bit `ip_ttl`
      field with no translation, so the TCP and ICMP OS-detection probes go out with
      **TTL 255** unless `--ttl` says otherwise. `ProbeParams::ttl` is a `u8` with no
      sentinel, so the driver must pass 255 to match the C default; a "sensible" 64 would
      silently change what the probes measure, since the reply's TTL is part of the
      fingerprint.

### Response analysis — the TCP option summary

`core::osprobe::analyze::tcp_option_string` ports `get_tcpopt_string` and its
`tcpopt_tostring` callback, plus the `TCPOptions` walk that drives them. The value it
produces is the `OPS` test's `O1`–`O6` and the `O` attribute of `ECN` and `T1`–`T7`, so it
is matched against every database entry — getting it subtly wrong would not fail loudly,
it would identify the wrong operating system. Verified by a **C-oracle differential** over
**428 cases** (nmap's own `prbOpts[]` blocks, every option kind at valid and short
lengths, the malformed-length rejections, the data-offset clamp, and seeded
randomly-assembled well-formed sequences): **236 summaries and 192 rejections, all
matching**, against `tcpopt_string_ctx`/`tcpopt_tostring` copied verbatim into the oracle.
Fuzzed (`osprobe_tcpopt`, 87.8M runs).

- [x] `tcpopt-no-silent-truncation` (`core::osprobe::analyze`): the C writes the summary
      into a caller-supplied fixed buffer, checking for room before each write. When the
      room runs out its callback returns `false`, which **stops the option walk** — but
      `TCPOptions::foreachOpt` treats a `false` callback return as normal termination and
      returns `true`, and `valid` is never cleared, so `get_tcpopt_string` returns a
      **silently truncated** summary instead of the `-1` its own comment claims ("2. The
      option string is too long"). Worse, the truncation can land mid-option: the MSS case
      emits `'M'` *before* checking room for its four hex digits, so the result can end in
      a bare `M`. A truncated summary is not a noticed parse failure — it is a different
      fingerprint, matched against the database as if it were real. Building a `String`
      removes the failure mode by construction: there is no buffer to overrun, and the
      output is bounded anyway because options are capped at 40 bytes.
- [x] `tcpopt-eol-does-not-terminate` (`core::osprobe::analyze`): **not a divergence** —
      recorded because it looks like a bug and must not be "fixed". RFC 793 makes the
      end-of-list option terminate the option block, but the C emits `L` and **keeps
      walking**, so padding and any options after an EOL still contribute to the summary.
      Every fingerprint in the shipped `nmap-os-db` was generated with this behaviour, so
      correcting it would silently invalidate the database. Pinned by
      `end_of_list_does_not_stop_the_walk` and by the corpus cases in section 6 of
      `gen_tcpopt_cases.py`.

### Response analysis — the `SEQ` test

`core::osprobe::seq` ports `makeTSeqFP`: the ISN-predictability analysis (`SP`, `GCD`,
`ISR`), the three IP-ID classifications plus the shared-counter test (`TI`, `CI`, `II`,
`SS`), and the TCP-timestamp frequency buckets (`TS`). Verified by a **C-oracle
differential over 354 cases** whose oracle carries `gcd_n_uint`, the ISN rate/standard-
deviation block and the `TS` bucketing copied **verbatim** from `osscan2.cc` — 143 ISN
analyses and 215 timestamp analyses, all matching. IP-ID classification is covered by
`core::ipid`'s own M4 differential. Fuzzed (`osprobe_seq`, 10.4M runs).

- [x] `seq-isr-no-negative-cast` (`core::osprobe::seq`): the C computes the ISN rate as
      `seq_rate = log(rate)/log(2.0); (unsigned int)(seq_rate * 8 + 0.5)`. When the
      counter advances slower than once per second the logarithm is **negative**, and
      converting a negative `double` to an unsigned integer type is **undefined
      behaviour**; a zero rate makes it `-inf`, which is worse. In practice it wraps: the
      committed golden records `ISR=FFFFFFA2` for probes an hour apart with a one-step
      advance, i.e. a nonsense "4.29 billion" rate fed straight into fingerprint
      matching. This port saturates to `0`. **Reachable, not theoretical** — the
      differential corpus hits it, and the test asserts both that our value is `0` and
      that every other attribute on those lines still agrees exactly, so the divergence
      stays exactly this wide.
- [x] `seq-ss-divisor-guarded` (`core::osprobe::seq`): the shared-counter test divides by
      `good_tcp_ipid_num - 1`. That is only safe because the enclosing branch requires an
      incremental classification, which requires three samples — a coupling across ~60
      lines and two functions. The divisor is checked directly here instead of resting on
      it.
- [x] `seq-isn-zero-is-a-real-sample` (`core::osprobe::seq`): the C stores replies in an
      array where `seqs[i] == 0` means "no reply", so a host whose ISN is genuinely zero
      has that sample silently dropped from the ISN analysis — changing `GCD`, `SP` and
      `ISR`, and the response count with them. Replies are `Option`-shaped here, so
      absence and a zero ISN are distinct. Observable only against a host that returns
      ISN 0, which is a 1-in-2^32 accident per probe.
- [x] `seq-gcd-divide-only-when-large` (`core::osprobe::seq`): **not a divergence** —
      recorded because it looks like a bug and is easy to "simplify" away. The rate
      standard deviation is divided by the GCD **only when the GCD exceeds 9**. The C's
      own comment explains why: dividing always would produce an artificially low value
      "about 1/32 of the time if the responses all happen to be even", while never
      dividing would make a stack that deliberately steps by 64,000 look wildly
      unpredictable. `SP` is therefore not a pure function of the rate ratios, and the
      unit test `the_gcd_is_divided_out_only_when_it_is_large` pins both sides.

### Response analysis — per-reply TCP attributes

`core::osprobe::tcpreply` ports `processT1_7Resp`, `processTEcnResp`, `processTOpsResp`,
`processTWinResp` and the `T`/`TG` post-pass from `makeFP`. Fuzzed
(`osprobe_tcpreply`, 2.6M runs).

- [x] `tcpreply-t-and-tg-are-exclusive` (`core::osprobe::tcpreply`): **not a divergence** —
      recorded because the two-stage handling is easy to miss and silently wrong if you
      do. Per-reply extraction stores the **observed** TTL in `T`, which is *not* what the
      database holds. A post-pass then resolves it exactly one of two ways: with a known
      hop distance (from the `U1` probe's ICMP quote) `T` becomes
      `observed + distance - 1`, the reconstructed initial TTL; without one, `TG` gets the
      rounded guess (32/64/128/255) and **`T` is deleted**, because an uncorrected
      observed TTL would match entries for a completely different initial value. Porting
      only the extraction would leave every test carrying a raw observed TTL that
      essentially never matches. The fuzz target asserts the two stay mutually exclusive
      for every distance.
- [x] `tcpreply-empty-option-value-is-not-absent` (`core::osprobe::tcpreply`): where the
      option block cannot be summarised, the C sets the `O` attribute to the **empty
      string** rather than leaving it unset. The distinction is load-bearing for the
      scorer: an unset attribute is skipped (neither match nor mismatch), while an empty
      one is matched against the database's `O=` and can agree with it. Reproduced.
- [x] `tcpreply-flag-order-is-a-wire-contract` (`core::osprobe::tcpreply`): the `F`
      attribute lists flags in the fixed order `E U A P R S F`, which is not bit order.
      A different order would never match any database entry. Pinned by
      `flags_are_listed_in_the_c_order_not_bit_order`.
- [x] `tcpreply-zero-distance-does-not-underflow` (`core::osprobe::tcpreply`): the C
      computes `ttl + hss->distance - 1` where `distance` is an `int` the caller is
      trusted to have set above zero. The subtraction saturates here rather than resting
      on that.

### Response analysis — the `U1` and `IE` ICMP replies

`core::osprobe::icmpreply` ports `processTUdpResp` (the `U1` test) and `processTIcmpResp`
(the `IE` test). The `U1` quote is our own packet echoed back by the target, so it is
fully attacker-shaped; the C walks it with `memcpy` after two length checks, while this
port slices it defensively and returns `None` on any malformed quote. Fuzzed
(`osprobe_icmpreply`, 12M runs).

- [x] `u1-quote-parsed-defensively` (`core::osprobe::icmpreply`): the C dispatches into
      `processTUdpResp` after `assert`ing the ICMP type/code, then reads the quoted IP and
      UDP headers with `memcpy` guarded only by `icmplen < 8 + 20 + 8` and
      `ip2hlen < 20 || icmplen < 8 + ip2hlen + 8`. Those cover the fixed-size reads, but
      the port additionally bounds every field access, so a quote that passes the length
      gates but is internally inconsistent still cannot read out of range — it yields
      `None`. On a well-formed quote the two agree.
- [x] `u1-distance-never-negative` (`core::osprobe::icmpreply`): the hop count is
      `udpttl - quoted_ttl + 1`, computed as a C `int`. The quoted TTL is attacker-chosen,
      so a value above the TTL we sent drives the count negative — and that number then
      flows into **every** test through `finalize_ttl` (`T = observed + distance - 1`),
      corrupting the whole fingerprint from one hostile byte. Here an out-of-range count
      yields `None` (distance unknown), so the affected tests fall back to the `TG` guess
      rather than to a garbage reconstructed TTL. Reachable and covered by
      `a_lying_ttl_yields_no_distance_rather_than_a_negative_one`.
- [x] `u1-ruck-compares-the-sent-checksum` (`core::osprobe::icmpreply`): **not a
      divergence — a faithfulness note.** `RUCK` compares the quoted UDP checksum against
      the exact value the sender placed on the probe (threaded through `U1Sent`), as the C
      does (`udp.uh_sum == hss->upi.udpck`). Recomputing the "expected" checksum from the
      quote instead — an easy shortcut — would wrongly report `G` for a target that
      altered the datagram *and* recomputed a fresh valid checksum; comparing against the
      original value catches it, matching the C exactly.

### Assembling the observed fingerprint (`makeFP`) and rendering it

`core::osprobe::assemble` ports `makeFP`: it runs the three aggregate analyses, collects
the per-reply tests, defaults unanswered probes to `R=N`, and resolves every test's
`T`/`TG` once the `U1` quote has yielded the hop count. `FingerPrint::render_tests` ports
`fp2ascii`/`test2str`, the text nmap prints for an unrecognised host and asks users to
submit. Gated by a corpus test that renders **every one of the ~6,100 shipped
fingerprints** and parses the result back for an exact match, an end-to-end test that
assembles a synthesised Linux host and confirms it is identified as Linux against the real
database at nmap's own guess threshold, and fuzzing (`osprobe_assemble`).

- [x] `fp-render-no-truncation` (`core::osdb::model`): `fp2ascii` renders into a
      **2048-byte `static` buffer** and silently `break`s out of its loop when the buffer
      fills, returning a truncated fingerprint with no indication that anything was lost.
      That output is exactly what users are asked to paste into a submission, so a
      truncated one is a corrupt submission — and `static` also makes the function
      non-reentrant. This port returns an owned `String` that always contains the whole
      fingerprint. Round-tripped against every shipped record.
- [x] `fp-render-is-canonical` (`core::osdb::model`): tests are emitted in `TestID` order
      regardless of the order they were collected in, so two runs that observed the same
      things render byte-identical text. The C relies on `FP->tests[]` being index-ordered
      by construction; making the order explicit here means a future caller that appends
      tests out of order cannot silently change what gets submitted.
- [x] `fp-silence-only-for-probes-we-sent` (`core::osprobe::assemble`): **faithfulness
      note, and the subtlest part of `makeFP`.** An unanswered probe is recorded as `R=N`
      — silence is evidence — but only when the probe was actually sendable: `ECN`/`T1`–
      `T4` need an open TCP port and `T5`–`T7` a closed one (the C's index-range guards).
      With no such port the test is left **absent** instead. Recording `R=N` for a probe
      that was never sent would tell the database the host declined to answer something we
      never asked, shifting the match away from the correct OS. Covered by
      `silence_is_recorded_only_for_probes_we_could_send` and asserted over all inputs by
      the fuzz target.
- [x] `fp-ttl-resolved-once-per-test` (`core::osprobe::assemble`): the `T`/`TG` post-pass
      runs exactly once per test, after `U1` has been extracted, and the two attributes
      remain mutually exclusive — a test carrying both would be scored twice for one
      observation. The C achieves this ordering implicitly (reply processing sets
      `hss->distance` before `makeFP` runs); here `U1` is extracted in the first pass and
      applied in a second, so the dependency is explicit rather than incidental.

### Scan policy and `-O` reporting

`core::osscan` ports the pure half of `os_scan_ipv4` (`endRound`'s completion test and
distance ladder, `findBestFPs`), `OmitSubmissionFP`, and `printosscanoutput`'s plain-text
output. None of it touches a socket, so all of it is unit- and Miri-testable and directly
fuzzable — which matters because two of its inputs are attacker-influenced: OS names and
accuracies come from the reference database (`--osscandb` makes that attacker-supplyable),
and the sequence samples come off the wire from the target. Fuzzed (`osscan_policy`).

- [x] `osscan-output-no-fatal-on-long-list` (`core::osscan`): `printosscanoutput` formats
      the observed sequence numbers, IP IDs and timestamps into a fixed **512-byte** buffer
      and calls **`fatal("STRANGE ERROR #3877")`** — aborting the entire scan and losing
      every result for every host — if a list would overflow. Three call sites do this
      (`#3876`, `#3877`, `#3878`). The sample counts come from the target, so this is a
      remote input deciding whether the scan survives. Here the lists are grown `String`s,
      which cannot overflow, so the abort has no counterpart.
- [x] `osscan-negative-distance-unrepresentable` (`core::osscan`): `OmitSubmissionFP`
      carries a `distance < -1` branch whose comment reads "This can happen if the TTL in
      the response to the UDP probe is somehow greater than the TTL in the probe itself" —
      the C detecting, after the fact, exactly the hostile-quote case that
      `u1-distance-never-negative` rejects at the source. Our hop count is an unsigned
      `Option<u8>`, so that state is unrepresentable and the branch has no counterpart: the
      bug is excluded by the type rather than screened for downstream.
- [x] `osscan-unfit-fingerprint-is-never-offered` (`core::osscan`): **faithfulness note,
      and the invariant the fuzz target exists to protect.** When `submission_reason`
      judges the observation untrustworthy — bad timing, missing ports, too many hops —
      the fingerprint is never printed with a submission request. Submitting a fingerprint
      taken under bad conditions would poison the shared database for every nmap user, so
      "we could not measure this properly" must never render as "please send this in".
- [x] `osscan-no-static-reason-buffer` (`core::osscan`): `OmitSubmissionFP` returns a
      pointer into a `static char reason[128]`, so the string is overwritten by the next
      call and the function is not reentrant — the same shape as `fp2ascii`'s static
      buffer. This returns an owned `Option<String>`.

### The privileged OS-detection driver (`sys::osscan`) and reply demultiplexing

`core::osprobe::demux` attributes a captured frame to the probe that provoked it, and
`sys::osscan` sends the battery and collects the replies. The driver contains **no
`unsafe`** — the raw socket and capture handles are already safe abstractions from M4 —
so the whole path is testable with a mock sender and a scripted packet source, no
privilege required.

- [x] `osscan-demux-identity-not-proximity` (`core::osprobe::demux`): every probe is
      identified by something it actually put on the wire — TCP probes by the distinct
      **source** port each used (so a reply's destination port names the probe), the two
      `IE` probes by their ICMP identifier and sequence, and `U1` by the UDP source port
      **quoted back inside** the ICMP error. Nothing is matched by arrival order or
      proximity. This matters more than dropping a reply would: an attribute recorded
      against the wrong test yields a well-formed fingerprint that matches the wrong OS.
      Frames whose source address is not the host we probed are rejected outright.
- [x] `osscan-seq-pacing-is-a-correctness-constraint` (`sys::osscan`): the six `SEQ`
      probes are sent no faster than one per 100 ms (`OS_SEQ_PROBE_DELAY`), because
      `makeTSeqFP` derives the ISN rate and timestamp frequency from the **actual** send
      times. This is why the M4 group engine's `RawScanKind` is not used: that engine is
      port-keyed (its scheduler walks a port list and yields `(port, tryno)` pairs
      resolving to per-port states) and its congestion window exists to send as fast as
      the network allows — which here would corrupt the fingerprint rather than merely
      finish sooner. The driver reuses the layer below it (`AsyncCapture`, `RawSender`,
      the timeout math) with its own schedule. Covered by
      `the_seq_probes_are_paced_not_blasted`.
- [x] `osscan-first-reply-wins` (`sys::osscan`): a duplicate or retransmitted reply never
      replaces the first one recorded for a probe. The timing analysis was measured
      against the first sample, so letting a later copy overwrite it would silently
      decouple the recorded attributes from the send times they are divided by.
- [x] `osscan-unsent-is-not-unanswered` (`sys::osscan`): probes that could not be built
      (no open TCP port, no closed port) are recorded as **unsent** rather than being
      allowed to look like silence. The C's senders `return` early in that case, so its
      driver cannot tell the two apart — and they mean different things to the
      fingerprint, which is exactly what `fp-silence-only-for-probes-we-sent` turns on.
- [x] `osscan-cli-says-why-it-cannot-run` (`cli`): `-O` without a `--features pcap` build
      and raw-socket privilege reports that plainly, and flags a host lacking an open or
      closed TCP port, instead of printing nothing. Silence would leave the user unable to
      distinguish "unidentifiable host" from "this build cannot do OS detection".

### Completing `-O`: rounds, port selection, and the on-wire differential

`core::osscan::select_probe_ports` picks the ports the battery needs,
`sys::osscan::scan_host_rounds` drives the retry loop through the already-ported policy,
and `cli` renders the result. Gated by **the first on-wire differential in M5**
(`tests/differential/m5/run_os_differential.sh`): C nmap and nmap-rs fingerprint the same
loopback host and all thirteen tests must agree, after stripping only the fields that are
legitimately run-to-run variable.

- [x] `osscan-guessed-closed-port-is-recorded` (`core::osscan`): with no closed port
      observed, the C invents one — `(get_random_uint() % 14781) + 30000` — and assumes it
      is closed. If that assumption is wrong the resulting `T5`–`T7`/`U1` evidence is
      meaningless, but the C keeps no record that it guessed, so nothing downstream can
      weigh it. This port returns `closed_tcp_guessed`/`closed_udp_guessed` alongside the
      choice, and the CLI feeds them into `submission_reason`.
- [x] `osscan-u1-reply-proves-the-port-closed` (`cli`): **faithfulness note.** A guessed
      UDP port that answers with an ICMP port-unreachable is thereby *proven* closed, so
      it stops counting against submission. This is what the C does in `processTUdpResp`
      (`if (osscan_closedudpport == -1) osscan_closedudpport = upi.dport`). An earlier
      draft of this port treated any guessed port as permanently unproven, which wrongly
      suppressed submission for exactly the runs that worked; the C's behaviour is the
      correct one and is reproduced.
- [x] `osscan-port-zero-avoided` (`core::osscan`): **faithfulness note.** Port 0 is skipped
      when any alternative exists, as the C does. A probe to port 0 is not a normal
      conversation and stacks answer it inconsistently — choosing it would record an
      artefact of our own selection as the target's behaviour. When port 0 is genuinely
      the only candidate it is still used rather than guessing.
- [x] `osscan-debug-always-shows-the-fingerprint` (`core::osscan`, `cli`): `-d`/`-vv`
      prints the raw observed fingerprint in **every** branch, as the C does — it gates
      each `write_merged_fpr` call on `suggest_submission || o.debugging || o.verbose > 1`,
      *including* the perfect-match branch. Asking to see the observation is a different
      request from being invited to submit it, and that holds whether or not the host was
      identified. This is also what makes the on-wire differential meaningful: without it,
      either tool may withhold its fingerprint and two withheld fingerprints would "agree"
      vacuously. A first draft covered only the branches that judge the run *unfit*, so
      `-d` silently printed nothing whenever the host was actually identified — the case
      the differential has the most to compare. Caught by that gate in CI.
- [x] `osscan-seq-pacing-measured-from-the-last-send` (`sys::osscan`): the wait before each
      `SEQ` probe runs until `last_sent + 100 ms`, not for a flat 100 ms after the
      preceding work. The C gates on exactly this (`hostSeqSendOK` compares
      `now - lastProbeSent` against the delay). Sleeping a flat interval and *then*
      draining the capture makes every gap overshoot, inflating `timingRatio` — and a
      ratio above 1.4 makes the scan reject its own fingerprint as untrustworthy. The
      first draft of this port had that bug and rejected its own results intermittently.
- [x] `osscan-ipid-sample-presence-is-not-comparable` (differential harness): the
      *values* of `SEQ`'s `TI`/`CI`/`II` are properties of the target's IP-ID counters and
      are compared strictly. Their *presence* is not comparable between the two tools.
      Each needs at least two usable samples, and C nmap discards the sample from any
      probe it retransmitted (`osscan2.cc`: "Retransmitted ipid is useless"), so under
      packet loss it emits fewer of these than a clean run. This port re-sends the whole
      battery per round rather than retransmitting individual probes, so its samples always
      come from first transmissions. Comparing presence would diff the two tools' luck
      rather than their fidelity — the CI runner produced exactly that, with C nmap
      omitting `II` after an `IE` retransmission while this port emitted `II=I`. The
      harness therefore skips an attribute only one side sampled, and still fails on any
      value both sides have and disagree on.
- [x] `osscan-output-follows-the-port-table` (`cli`): the OS block is rendered into a
      string and printed after the scan report rather than as it is computed, matching
      nmap's ordering. Printing during detection put the OS lines *before* the port table
      they describe.

## Milestone 5 — IPv6 OS detection: the classifier model

IPv6 detection does not match expressions against a database. nmap ships a **trained
logistic-regression model** — 101 OS classes over a 695-element feature vector — and
classifies observations against it. `core::fpmodel` ports that.

Gated by a differential that links **liblinear's own `predict_values`, verbatim, against
nmap's real model tables** and requires **bit-exact** agreement across 124 feature vectors
(695 scaled values + 101 decision values + 101 novelty distances each — ~111,000 `f64`
comparisons at zero tolerance). Exactness is the point: the accept rule downstream turns
on whether one class scores within 90% of the best, so an error in the last few bits can
change which OS is reported. Verified to catch a transposed weight layout, a wrong default
variance, and a wrong scaling formula.

- [x] `fp6-no-liblinear` (`core::fpmodel`): the C delegates prediction to **liblinear**, a
      bundled third-party C++ library, and compiles in a 2.8 MB generated model file. The
      only prediction entry point nmap uses is `predict_values`, and for this model — 
      linear, negative `bias` so no bias column, solver type 0 — that reduces to a dot
      product. Porting it directly removes the entire library from the trust boundary. The
      model *data* is copied verbatim into a little-endian `f64` blob
      (`tools/extract_fpmodel.py`), so predictions are bit-identical.
- [x] `fp6-scale-preserves-the-absent-sentinel` (`core::fpmodel`): **faithfulness fix, and
      a lesson about oracles.** nmap's `apply_scale` skips any negative value
      (`if (val < 0) continue;`), because `-1` is the "attribute absent" sentinel that
      `vectorize` initialises every feature to and leaves wherever a probe went unanswered
      or an option was missing. Scaling it would map "no data" onto an arbitrary in-range
      number the model reads as evidence — and since most real scans leave some probes
      unanswered, that corrupts nearly every classification rather than an edge case.
      The first version of this port scaled negatives, **and the differential did not
      catch it**: the oracle's copy of `apply_scale` was hand-written without the guard
      while its comment claimed to be verbatim, so the gate compared the port against a
      restatement of the C rather than against the C. Both are now fixed, and the corrected
      oracle rejects the old behaviour on the first case. The lesson generalises: a
      function an oracle claims to copy verbatim must actually be copied, not retyped.
- [x] `fp6-nan-score-is-no-evidence` (`core::fpmodel`): **found by fuzzing.** A NaN or
      infinite feature makes a decision value non-finite. The C feeds that into
      `1.0/(1.0+exp(-v))` and then into two places that cannot cope: `label_prob_cmp`
      orders with `>` and `<`, both false for NaN, so it reports "equal" for a NaN against
      everything while other elements keep a strict order — **not a strict weak ordering,
      making the `qsort` call undefined behaviour** — and the value then reaches the user
      as a printed accuracy percentage. Here a non-finite score is treated as *no
      evidence* (probability 0), the sort uses a total order, and a class the model gave
      no answer for can never be promoted. The first draft of this port propagated the NaN
      exactly as the C does; the fuzz target caught it.
- [x] `fp6-novelty-label-bound` (`core::fpmodel`): `novelty_of` guards its label with
      `assert(label < nr_feature)` — the wrong dimension. It then indexes `FPmean[label]`
      and `FPvariance[label]`, which have `nr_class` rows: **695 vs 101**, so labels
      101–694 pass the check and read out of bounds. Under `NDEBUG` the assert is gone
      altogether. Here the label indexes a bounds-checked slice and an out-of-range one
      returns `None`. Not reachable from the C's own call sites today, which pass labels
      below `nr_class` — a latent defect rather than a live one.
- [x] `fp6-model-blob-is-validated` (`core::fpmodel`): the embedded model carries a magic
      and version, and a truncated or degenerate blob is rejected at load. The C's tables
      are plain global arrays whose consistency with `nr_class`/`nr_feature` is assumed;
      a mismatch would read past them silently. Also: `FpModel`'s `Debug` is hand-written
      to print only the shape, because a derived one would dump ~210,000 floats into any
      log line that happened to include the model.

## Milestone 4 — CLI scan-technique selection

- [x] `cli-scan-reason-from-port-not-hardcoded` (`core::output`): the "Not shown"
      ignored-state summary now takes its reason token from a real port of that state
      (a connect scan's closed ports carry `conn-refused`, a SYN scan's carry `reset`)
      instead of the M1 hardcoded `closed → conn-refused`. A fidelity fix — nmap prints
      the actual reason — observable as `Not shown: N closed tcp ports (reset)` under `-sS`.

## Platform / environment differences

- [x] `rawio-safe-socket2-l3-plus-pcap-l2` (`sys::rawio`, ports the `send_ip_packet*` /
      `send_eth_packet` chokepoint): the send half of the raw path mirrors nmap's
      L3-vs-L2 choice (`send_ip_packet_eth_or_sd`) behind a `RawSender` seam. The
      **default L3 sender** is an `IP_HDRINCL` raw IPv4 socket via the safe `socket2`
      crate (**0 first-party `unsafe`**; the packet's own IPv4 dst field drives kernel
      routing); the **L2 sender** (feature `pcap`) injects via libpcap/Npcap
      `sendpacket` (audited-upstream FFI, still no first-party `unsafe`). Same
      safe-crate-first Option-C shape as `netif`/`capture`. Privileged runtime paths
      self-skip when unprivileged (CI), and are validated as root here — including a
      real loopback send and (feature-gated, `#[ignore]`) an end-to-end
      build→send→capture→parse round trip. *(Introduced at M4 `sys::rawio`.)*
- [x] `capture-blocking-thread-not-poll` (`sys::capture`, realizes spike S1): nmap runs
      its pcap handle **non-blocking and polls** it from the nsock event loop (Windows
      Npcap exposes no selectable fd, so `pcap_get_selectable_fd` is never used). This
      port uses a **dedicated blocking capture thread forwarding frames into a
      `tokio::mpsc` channel** the async driver awaits — the spike-measured design
      (~60 µs latency, 0 idle CPU, no readiness fd required, so it ports unchanged to
      Npcap). A behavioral-shape divergence, not an output one: the frames delivered are
      identical, only the delivery mechanism differs. The OS-agnostic plumbing holds
      **0 `unsafe`** and is tested on CI against a mock source (ordered delivery,
      backpressure, clean shutdown); the live libpcap/Npcap source is behind the
      off-by-default `pcap` feature (the `pcap` crate's FFI is audited upstream, so it
      too adds no first-party `unsafe`), validated on a privileged host.
      *(Introduced at M4 `sys::capture`.)*


- [x] `sys-osquery-safe-crate-default` (`sys::netif`, and the route/MTU needs it fills):
      the OS-query layer (interfaces, addresses+prefixes, MTU, MAC, default gateway) uses
      the vetted cross-platform `netdev` crate as its **default backend** rather than
      hand-rolled `getifaddrs`/`GetAdaptersAddresses`. This keeps the first-party
      OS-query code at **0 `unsafe`** on *both* Windows and Linux (netdev's own OS
      `unsafe` is audited upstream) and is more complete than a hand port — a *safer*
      choice than faithfully re-implementing libdnet's `intf-*.c`/`route-*.c`. `unsafe`
      is thereby reserved for Npcap, where no safe equivalent exists. An off-by-default
      `raw-ffi` feature keeps a direct `getifaddrs` backend (`interfaces_ffi`) as an
      audited escape hatch — cross-checked in CI to agree with `netdev` on the interface
      set — for any field `netdev` does not expose. Accepted supply-chain cost: netdev
      pulls the unmaintained-but-not-vulnerable `paste` proc-macro (RUSTSEC-2024-0436,
      ignored in `deny.toml` with justification). *(Introduced at M4 `sys::netif`;
      supersedes the hand-FFI-per-OS approach.)*


- [x] `version`: `nmap-rs --version` carries Rust build metadata and notes it is the
      port; the differential compares the semantic projection, which excludes the
      version banner entirely. (Confirmed at M1 CLI.)
