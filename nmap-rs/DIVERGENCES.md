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

## Platform / environment differences

- [x] `sys-windows-backend-validated-on-windows` (`sys::netif`, and the raw-I/O modules
      to come): the `sys` OS-acquisition layer has per-target backends. CI is Linux, so
      the **Unix backend** (`getifaddrs`) is the one that clears build/test/miri/
      unsafe-audit here; the **Windows backend** (IP Helper `GetAdaptersAddresses`, later
      Npcap) is written against the same seam, unsafe-audited by review (the audit
      harness scans all `cfg` branches), but compiled and run only on a Windows target
      (this host lacks the msvc std). Not a behavioral divergence — a gate-coverage note:
      the Windows path's *runtime* validation defers to a real Windows run. Both backends
      populate the identical `Interface` shape. *(Introduced at M4 `sys::netif`.)*


- [x] `version`: `nmap-rs --version` carries Rust build metadata and notes it is the
      port; the differential compares the semantic projection, which excludes the
      version banner entirely. (Confirmed at M1 CLI.)
