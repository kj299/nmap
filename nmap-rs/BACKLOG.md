# nmap-rs backlog

Deferred work, in priority order. Items move out of here into their own branch +
draft PR when picked up. Kept in-repo so it survives across sessions.

## Deferred by the user (2026-07-24)

### 2. Depth on the existing raw scans
- ~~**Multi-host group loop**~~ — **done**. `sys::group` scans a whole host group over
  one shared capture demultiplexed by source address (nmap's `ultra_scan` model), and
  **every** raw scan now runs on it via `RawScanKind`: `SynKind` (`-sS`), `UdpKind`
  (`-sU`), `FlagKind` (the six flag scans). The three single-host drivers it replaced
  are deleted. Ledgered: `group-scan-one-engine-for-every-raw-scan`.
- ~~**UDP protocol payloads** (`payload.cc`)~~ — **done**. `core::payload` derives the
  payload table from `nmap-service-probes` (nmap has no separate payload DB), and
  `sys::group::UdpKind` sends one datagram per registered payload. Ledgered:
  `payload-cap-warns-not-fatal`, `payload-missing-db-degrades`,
  `payload-one-datagram-per-payload`.
- ~~**Back-fill the SYN/flag scans' ICMP path**~~ — **done**. `core::icmp_quote` is the
  shared quote parser for all three raw scans; `-sS` and the six flag scans now report
  *filtered* (with the specific ICMP reason) instead of falling back to the no-response
  default. Also closed a gap in our own UDP path: the quoted packet's source is now
  checked against our address, as the C does. Ledgered:
  `icmp-quote-requires-our-source`, `icmp-quote-verifies-our-sequence`,
  `icmp-reason-fidelity`, `icmp-bpf-widened-for-tcp-scans`.

### 3. M5 — OS detection  ⟵ **IN PROGRESS**
Phase 0 done (inventory + cflaw-scan + threat model + FPModel spike); both the IPv4
and IPv6 tracks are approved. Port order, leaf-first:
1. ~~`core::osdb::expr`~~ — **done**, C-oracle differential over 23.8k cases.
2. ~~`core::osdb::model` / `parse`~~ — **done**, corpus gate over the real 5.1 MB file
   (6,108 fingerprints, zero warnings) + fuzz.
3. ~~`core::osdb::score`~~ — **done**, corpus gate over the real database (perfect match
   on a concrete Linux observation) + the early-exit invariant over all 6,108 records.
4. ~~`core::macvendor`~~ — **done**, corpus gate over the real file (52,085 prefixes,
   zero warnings) cross-checked against a text-derived oracle.
5. ~~`core::osprobe`~~ — **done**. Modules: `osprobe::build` (the probe battery, C-oracle
   differential over all 23 packets), `osprobe::analyze::tcp_option_string` (the
   `O`/`O1`-`O6` encoder, C-oracle differential over 428 cases), and `osprobe::seq`
   (`makeTSeqFP` — SP/GCD/ISR/TI/CI/II/SS/TS, C-oracle differential over 354 cases).
   `osprobe::tcpreply` (`processT1_7Resp` / `processTEcnResp` / `processTOpsResp` /
   `processTWinResp` plus the `T`/`TG` post-pass from `makeFP`), and `osprobe::icmpreply`
   (`processTUdpResp` — the `U1` test + hop distance — and `processTIcmpResp` — the `IE`
   test). **`core::osprobe` is now complete: all 13 fingerprint tests can be built.**
6. ~~`core::osprobe::assemble`~~ — **done**. Ports `makeFP`: aggregates + per-reply tests
   into one observed `FingerPrint`, the `R=N` silence defaults (gated on actually having
   had a port to probe), and the `T`/`TG` resolution once `U1` yields the hop count. Also
   `FingerPrint::render_tests` (`fp2ascii`), gated by a render/parse round trip over
   **every** shipped fingerprint plus an end-to-end "synthesised Linux host is identified
   as Linux" test against the real database.
7. ~~`core::osscan`~~ — **done**. The pure half of the driver: `endRound`'s completion
   test and distance ladder, `findBestFPs`, `OmitSubmissionFP`, and `printosscanoutput`'s
   plain-text rendering. No sockets, so it is fully unit/Miri/fuzz testable.
8. ~~`core::osprobe::demux` + `sys::osscan` + `cli -O`~~ — **done. `-O` works end to end.**
   `demux` attributes a frame to its probe by identity (TCP source port, ICMP id/seq, the
   UDP port quoted inside the error); `sys::osscan` sends the battery, paces the `SEQ`
   probes, and drives the retry rounds through `core::osscan`'s policy; port selection
   comes from the scan's own results; and the CLI renders the result after the port table.
   **Design note so it is not relitigated:** this deliberately does *not* implement
   `group::RawScanKind` — that engine is port-keyed (scheduler walks a port list, yields
   `(port, tryno)`, produces per-port states) while `-O` sends 23 heterogeneous probes
   feeding 13 extractors, and its congestion window wants to send as fast as possible
   whereas the six `SEQ` probes must be paced at 100 ms or the ISN/timestamp analysis is
   wrong. It reuses the layer below — `AsyncCapture`, `RawSender`, the timeout math.
   **Gated by the first on-wire differential in M5**
   (`tests/differential/m5/run_os_differential.sh`, in CI): C nmap and nmap-rs fingerprint
   the same loopback host and all 13 tests must agree.
   Remaining polish: ~~the `Uptime guess` and `TCP Sequence Prediction` lines~~ and
   ~~`--max-os-tries`~~ — **done**. The driver now collects a per-round `SeqReport`
   (`sys::osscan::seq_report`) and the uptime inferred from the target's timestamp clock
   (`core::osprobe::seq::estimate_uptime`, porting the `si.lastboot` derivation), so
   `-v -O` reports uptime, sequence-prediction difficulty and IP-ID generation.
   `--max-os-tries N` overrides the retry count. Ledgered
   `uptime-implausible-claim-still-dates-a-boot`,
   `uptime-ladder-differs-from-the-ts-attribute-ladder`, `uptime-boot-time-in-utc`.
   ~~Still outstanding: **XML/grepable `<os>` output**~~ — **done**. The `<os>` block
   (`<portused>`, `<osmatch>` with nested `<osclass>`/`<cpe>`, `<osfingerprint>`) plus
   `<uptime>`, `<distance>`, `<tcpsequence>`, `<ipidsequence>` and `<tcptssequence>`,
   and the grepable `OS:`/`Seq Index:`/`IP ID Seq:` fields. The report is carried on
   `model::Host.os` as a rendered-form snapshot, so the normal, XML and grepable
   outputs are built from the same values and cannot disagree. **`-O` is now
   feature-complete against the C's user-visible output.**
   **Harness note:** the differential compares the *final* round's fingerprint from each
   tool's `-d` output and strips the fields that are measurements rather than properties
   (the `SCAN` metadata line, `SEQ`'s `SP`/`GCD`/`ISR`, a numeric `SEQ.TS`, and `T`/`TG`).
   It verifies its own loopback fixture is listening before comparing — without that a
   failed bind leaves no open TCP port, and two fingerprints of a host with no open port
   agree trivially, turning the gate into a no-op that reports success.
9. ~~`core::fpmodel`~~ — **done**. nmap's trained IPv6 classifier (101 classes x 695
   features): `apply_scale`, `predict_values`, `novelty_of`, and the accept policy.
   **liblinear is gone** — the one entry point nmap used reduces to a dot product for this
   model. Model data extracted verbatim by `tools/extract_fpmodel.py` into a 1.7 MB
   little-endian blob (vs 2.8 MB of generated C). Gated by a bit-exact differential
   against liblinear's own `predict_values` over the real tables.
10. ~~`core::headers::icmpv6` + `core::headers::ipv6ext`~~ — **done**. The layers an
   IPv6 response is made of, which `fp6::vectorize` has to walk before it can extract a
   single feature: ICMPv6 (type-derived header length) and the four extension headers
   (hop-by-hop, destination options, routing, fragment), wired into
   `core::packet_parser`. This **closes** the M4 divergence
   `packet-parser-ported-subset-degrades-to-raw`: the walk now follows every chain the C
   walk can follow. Gated by the packet differential extended from 17 to 45 hand-written
   vectors **plus 4,000 generated IPv6 chains**, all bit-exact against nmap's real
   `PacketParser::parse_packet`, with the committed golden re-derived from the C on
   every CI run (`tests/differential/m4/regen_pkt_golden.sh --check`) so it cannot drift
   into agreeing with a paraphrase. Two C defects ledgered:
   `ipv6ext-option-length-byte-must-exist` (an uninitialised read in the option walk) and
   `ipv6ext-unknown-routing-type-is-minimal-only` (a length field read after the struct
   holding it was cleared).
11. ~~`core::fp6::vectorize`~~ — **done**. Builds the 695-element feature vector from
   IPv6 probe responses (17 IPv6 probes × plen/tc/hlim = 51, + ISR = 1, + 13 TCP probes ×
   49 = 637, + 3 ICMPv6 probes × type/code = 6). Every feature defaults to the `-1`
   sentinel `apply_scale` leaves alone. The 17th-TCP-option overwrite and `foreachOpt`'s
   walk-past-EOL are reproduced deliberately (ledgered `fp6-vectorize-preserves-the-absent-
   sentinel`); the C's zero-length-response `assert`/abort is dropped for a safe degrade
   (`fp6-empty-response-no-abort`). Gated by a **bit-exact differential over 1,500 generated
   observations** against nmap's real `vectorize()` (pasted verbatim, linked to the real
   libnetutil parser), re-derived from the C on every CI run
   (`tests/differential/m5/regen_fp6_vectorize.sh --check`); 12 unit tests; a fuzz target
   (491k runs clean). Eight mutations of the port were each caught by the gate.
12. **The IPv6 driver, in two slices** (there is no IPv6 support below this yet —
   `sys::rawio`, `sys::route` and `core::build` are all IPv4-only):
   - ~~**12a. `core::build6`**~~ — **done**. The 17 IPv6 probes as a pure, deterministic
     function of [`Build6Params`] (ports `FPHost6::build_probe_list` + `make_tcp`): six
     timed SEQ SYNs, IE1/IE2 (echo behind hop-by-hop / a mis-ordered extension chain), NS
     (on-link only), U1, TECN, and T2–T7 — emitted only when the scan has the port state
     each targets, in nmap's send order. Gated by a **byte-exact** differential against
     nmap's real builder linked to libnetutil (400 cases / 5,919 probes, re-derived from
     the C on every CI run), 9 unit tests, a fuzz target (1.3M runs), 8 mutations caught.
     Ledgered `build6-no-random-inside-the-builder`, `build6-oracle-needs-real-checksums`.
   - ~~**12b-i. `core::fp6_match`**~~ — **done**. Ports the IPv6 path of
     `PacketParser::is_response` — the pure decision that attributes a captured packet to
     the probe it answers (address mirror, TCP/UDP port mirror, ICMPv6 echo id/seq,
     Neighbor Advertisement solicited-flag + target). Gated by a verdict-exact differential
     against nmap's real `is_response` (246 pairs, 51 matches, re-derived from the C on
     every CI run), 8 unit tests, a fuzz target (2.3M runs). The differential surfaced a
     genuine nmap bug — a `dynamic_cast<NetworkLayerElement *>` that makes an ICMPv6 error
     **never** match any probe — which the port reproduces deliberately (faithful to the
     trained model *and* safer against forged errors). Ledgered
     `fp6-match-icmp-error-never-matches`, `fp6-match-only-battery-sent-types`.
   - ~~**12b-ii-a. `sys::fpengine` (the driver core)**~~ — **done**. The probe scheduler
     (six SEQ probes paced at 100 ms, then the rest back to back), response attribution via
     `fp6_match::is_response` into an `Fp6Observation`, the locality→distance resolution,
     and `fp6::vectorize` → `fpmodel::classify`. Generic over `RawSender`/`PacketSource`
     like the IPv4 driver, so the whole round is mock-tested (7 tests: a SYN/ACK attributed
     to S1, an echo reply to IE1, an ICMPv6 error attributed to *nothing*, a wrong-host
     frame ignored, the capture filter, the observation assembly). Also the pure
     `bpf_filter` for IPv6. Ledgered `fp6-distance-hoplimit-path-is-dead` (the C's IE2/U1
     hop-limit distance never fires because `is_response` never matches the error responses
     it reads, so distance is localhost/direct/none only).
   - **12b-ii-b. Privileged IPv6 wire path + CLI `-6 -O`** — the remaining integration.
     Linux has **no `IPV6_HDRINCL`**, so a full-packet IPv6 send must go L2 (Ethernet) with
     NDP next-hop resolution — a real subsystem, deliberately *not* stubbed with untested
     socket code. Decomposed leaf-first so that everything decidable from bytes is gated in
     CI and only the socket plumbing rests on a privileged host:
     - ~~**12b-ii-b-1. `core::ndp` (neighbor discovery, pure)**~~ — **done**. The
       solicited-node multicast address and MAC, the Neighbor Solicitation frame builder,
       and the advertisement reader that decides whether a captured frame resolves the next
       hop. Byte-exact + verdict-exact differential against nmap's real `doND` /
       `accept_ns` / `read_ns_reply_pcap` (81 cases, re-derived from the C each CI run, six
       mutations each caught), 11 unit tests, `ndp_advert` fuzz target (26.9M runs clean).
       Found, proved under ASAN, and fixed **two** nmap defects reachable by any on-link
       host: `ndp-advert-target-read-past-capture` (a 16-byte read past the captured
       packet) and `ndp-advert-accepted-without-link-layer-address` (an uninitialised MAC
       cached as the next hop).
     - ~~**12b-ii-b-2. IPv6 route lookup in `sys::route`**~~ — **done**. `route_for6`:
       on-link prefix match over `netif`'s IPv6 addresses, else the interface holding a
       default IPv6 gateway; yields the egress interface, source address, next hop and
       `directly_connected`. Source selection matches **scope** explicitly (a link-local
       destination gets a link-local source), and a link-local target off every prefix
       yields no route rather than falling through to a gateway. The decision is a pure
       function of the interface table (`choose_route6`), tested against synthetic
       topologies. Ledgered `route6-explicit-source-scope-selection`.
     - ~~**12b-ii-b-3. L2 sender + resolver + CLI `-6 -O`**~~ — **done**, with the caveat
       below. `sys::ndp` runs the C's 100/400/800 ms solicitation schedule (deadlines from
       the start of the exchange, as `doND` computes them) generically over
       `RawSender`/`PacketSource`, so the loop is mock-tested in CI; `rawio::EthFramingSender`
       wraps any L2 backend to frame IPv6 packets, also mock-tested;
       `fpengine::os_scan_host6` is the privileged entry point, and the CLI `-6 -O` branch
       reports the model's ranked guesses. Ledgered `ipv6-send-is-layer-2-only` and
       `ipv6-os-detection-is-a-classifier-not-a-database`.
       **Still unvalidated on real hardware**: everything below the seams is tested, but
       the wiring in `os_scan_host6` — opening the pcap handles, the live solicitation
       exchange, and a real battery on a real IPv6 link — has no CI-differential and needs
       a privileged host with real IPv6 to exercise. Treat it as untested-in-anger until
       someone runs it there.

## Workstream S — signature-database maintenance  ⟵ **IN PROGRESS**

Phase 0 done (`docs/S-ANALYSIS.md`): the C has no update mechanism, no version
metadata to read, and resolves DB paths through `$NMAPDIR` with no way to verify
what it loaded. Build order S1-S5, security core first, only the networked slice
last.

1. ~~**S1. `core::sigstore::manifest`**~~ - **done**. The manifest format (schema,
   bundle serial, per-file version/sha256/size), the downgrade comparison, and the
   file-name allowlist that kills path traversal *at parse time* so every consumer
   inherits the guarantee. Fail-closed where its sibling DB parsers are lenient,
   because a signed document with a defect is never a line to skip. 33 unit tests,
   11 mutations each caught, `sigstore_manifest` fuzz target with 20 committed
   seeds. Fuzzing found a real gap in the first draft: `nmap-os-..` passed the
   leading-dot rule, and Win32 silently strips trailing dots, so `db`/`db.`/`db..`
   would collide *after* the duplicate-name check passed. Ledgered under
   `sigstore-manifest-*`.
2. **S2. `core::sigstore::verify`** - signature over the manifest, then per-file
   hash. Pure over `&[u8]` with an injected key. **Blocked on the signing-scheme
   decision** (minisign-style Ed25519 recommended vs cosign/sigstore).
3. ~~**S3a. `core::fingerprint_store`**~~ - **done**. The opt-in, consent-gated
   store for unmatched OS fingerprints, with a `Local`/`Submission` export split so
   host identity leaving the machine is a decision rather than a default. Consent is
   structural (no constructor leaves it unspecified), the export escapes
   attacker-controlled text so a fingerprint cannot forge its own record boundary,
   and the module reads no clock. 20 unit tests, 12 mutations each caught, fuzz
   target with 13 committed seeds. Ledgered under `fpstore-*`.
4. ~~**S3b. `core::servicefp`**~~ - **done**. Ports `service_scan.cc`'s
   `addServiceChar`/`addServiceString`/`addToServiceFingerprint`/
   `getServiceFingerprint` (`:1663-1795`), the M3 gap that left the port unable to
   produce a service fingerprint at all. **The one slice in this workstream with a
   real C oracle**, gated by a byte-exact differential over 861 cases whose corpus
   AND golden are both re-derived from the C on every CI run. Header inputs
   (version, platform, intensity, localtime) are parameters rather than globals,
   which is what makes the comparison byte-exact instead of "equal after stripping
   the fields that move". 14 unit tests, 18 mutations caught, 798,428 fuzz runs
   clean with 12 committed seeds. Ledgered under `servicefp-*`.

   Two things worth carrying forward: the C `fatal()`s and asserts three separate
   ways on lengths a scanned host controls, none of which the port reproduces; and
   the first corpus missed the `>` vs `>=` total-cap boundary entirely, so a
   mutation survived a differential that was otherwise catching everything. **A
   differential is only as good as whether its corpus reaches the boundary** - the
   fix was to sweep response sizes rather than to compute where the boundary falls,
   since computing it would have meant deriving the corpus from the port under test.

   ~~**Still outstanding for S3b:** nothing wires this into `-sV`.~~ - **done**
   (S3c). `sys::servicescan` accumulates every probe response that returned data and
   matched nothing, `should_print_fingerprint` (porting `shouldWePrintFingerprint`)
   gates it on the hard match and the intensity floor, and `core::output` renders the
   "N services unrecognized despite returning data" block from `output.cc:830-843`.
   The header's version/platform/date come from the CLI so `core` stays clock-free.
   `osscan::civil_from_epoch` was extracted from `format_boot_time` rather than
   duplicated. Ledgered under `servicefp-print-policy`,
   `servicefp-single-accumulation-point`, `servicefp-header-*`.

   **Still outstanding:** `core::fingerprint_store` is not fed a `Service` record,
   because nothing yet exposes the opt-in or `--export-fingerprints` on the command
   line. Storing into an always-disabled store would be dead code, so that waits for
   the slice that adds the CLI surface — naturally S5, which also adds
   `--update-signatures` and friends.
5. **S4. `sys::sigstore`** - atomic install (temp + fsync + rename), per-user data
   dir, archive unpack with the traversal/bomb/size limits.
6. **S5. `sys::update` + CLI** - `--update-signatures`, `--check-signatures`,
   `--import-signatures <file>`. **Blocked on the bundle-source decision.**

**Run Miri the way CI runs it: `cargo +nightly miri test` over the WHOLE
workspace.** Twice now a local sweep has run Miri only on selected `-p nmap-core`
modules and reported "Miri clean", and twice CI has disagreed. #81: `SystemTime::now()`
in the SEQ send loop hit Miri isolation in `nmap-sys`, which the core-only run never
touched. #88 (S3c): four new `#[tokio::test]` driver tests bound real loopback
sockets, and `socket` is not available under Miri isolation -- `crates/sys/src/
servicescan.rs` already carried
`#[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]` on its two
pre-existing socket tests, and the new ones simply lacked it. Both failures were a
one-line fix; both cost a red CI cycle purely because the local command was narrower
than the gate. Same shape as the fuzz-build blind spot (LESSONS #023) and the
"lint both feature configurations" note: **the local convenience invocation is not
the CI invocation**, and the gap is invisible until the gate disagrees. Per-module
Miri is fine while iterating; the pre-push sweep must be the workspace-wide command.
Promote to the kit at the Workstream S retrospective.

**Miri is now the CI critical path and grows with every pure-`core` module.**
Measured on three consecutive PRs: #84 (docs only) 11m36s, #85 (S1, 33 tests)
12m26s, #86 (S3a, 20 tests) 12m57s. Both code PRs were measured *after* catching a
pathological case in their own tests (S1's exhaustive byte sweeps at 858s, S3a's
O(n^2) cap fill at 320s), so ~80s of growth across two slices is the *healthy*
rate, not the worst case. The direction is one-way, and #83's sharding bought ~28
minutes, so at roughly a minute per slice that win erodes over ~25 more modules.
Nothing to act on yet; options when it matters are sharding Miri the way fuzz was
sharded, or running it only over crates the diff touches. Decide it in the
Workstream S retrospective rather than when the job hits 20 minutes.

**Kit gap found in S1, for the Workstream S retrospective.** The six-gate ladder
(`ported -> differential -> fuzzed -> sanitized -> unsafe_audited`) is linear and
assumes a C counterpart exists. An *additive* module can never clear
`differential`, so `progress.py` cannot represent "done" for it without either
overclaiming (marking a gate that was never run) or understating it forever. S1 is
recorded as `fuzzed` and is in fact also sanitized and unsafe-audited. The kit
needs either an explicit `n/a` for a gate or an `additive` track; decide it in the
retrospective rather than quietly picking a convention per module.

## Smaller follow-ups (opportunistic)
- **Pin `rust-toolchain.toml`** — done (M4 retrospective, LESSONS #16).
- **Full routing-table LPM** in `sys::route` (today: on-link match → default gateway).
  Ledgered: `route-minimal-onlink-then-gateway`.
- **Non-Ethernet datalinks** (Linux SLL, BSD NULL) in the capture path; today
  `eth_included` is assumed true (correct for `lo`/Ethernet).
- ~~**DRY the scan matchers**~~ — **done**. The three drivers collapsed into one
  (`sys::group`), and the duplicated `ipv4_offset` plus the ICMP-quote decode now live
  once in `core::icmp_quote`.
- ~~**Shard the fuzz smoke across a matrix.**~~ — **done**. The 60s smoke is *per
  target* and targets accumulate one per ported module, so the job had grown to ~38
  minutes of pure fuzzing (38 targets). Now six shards, split round-robin with the
  divisor taken from `strategy.job-total` so it follows the matrix automatically, and
  `fail-fast: false` so one shard's crash does not hide the others. Promoted to the kit
  as LESSONS #024.
- ~~**CI runs the whole suite twice per PR.**~~ — **done**. The workflow triggered on
  `push` (branches included `claude/**`) *and* on `pull_request`, so every PR ran the
  whole pipeline twice — that is why there were 12 checks rather than 6, which was
  repeatedly mis-read as six jobs across two feature configurations. `push` is now
  scoped to `master` only, and a `concurrency` group supersedes a PR's in-flight run on
  force-push (never on master, where an intermediate merge commit's run is the only
  evidence it was green). Accepted trade-off: a `claude/**` branch pushed with no open
  PR is not built until a PR is opened. Promoted to the kit as LESSONS #025 — its
  template had the same bug with no branch filter at all.
- **CI never runs `--features pcap` or `--all-features`** — only the default config, so
  the local three-config clippy/test sweep is stricter than the gate. An import used
  only under `#[cfg(feature = "pcap")]`, or a lint that only fires with the feature on,
  would pass CI and fail a contributor's local check. Closing this means a small feature
  matrix on the build-test job (and, for the `pcap` config, libpcap installed on the
  runner).
- ~~**Fail the fuzz *build* fast, in its own CI step.**~~ — **done**. The "fuzz crate is
  not in the workspace lint sweep" lesson had bitten **three times** (#69, and twice
  while completing `-O` — both a field added to `SeqReport`). The fuzz job now runs a
  `fuzz targets compile` step (`cargo +nightly fuzz build`, no target name, so all of
  them build in one invocation) before any target is fuzzed, so a compile break fails
  in about a minute rather than tens. Promoted to the kit as LESSONS #023 and added to
  `harnesses/ci/porting-ci.template.yml`, since the note living only here is what let
  it recur twice more.
- **`cargo fuzz run <t> fuzz/seeds/<t>` writes into the committed seed dir.** libFuzzer
  treats the corpus argument as read-*write*, so a local smoke run leaves hundreds of
  machine-generated inputs in the working tree (one 60 s run on `osscan_policy` added
  483 files / 2.1 MB against 40 curated seeds). Discard them with
  `git clean -fd fuzz/seeds/<t>` unless a specific find is worth seeding; CI does the
  same thing but never commits. Consider pointing runs at a scratch corpus dir with the
  seeds as a read-only `-seed_inputs` set instead.
- **New-fuzz-target checklist**: every new `fuzz_targets/<t>.rs` needs a committed
  `fuzz/seeds/<t>/` dir, or CI's `cargo fuzz run <t> fuzz/seeds/<t>` errors. Capture
  in the next scan-driver retrospective (cousin of LESSONS #15).
- **An oracle must copy the C, not restate it.** The fp6 differential passed bit-exact
  while both sides were wrong: the oracle's `apply_scale` had been retyped without nmap's
  `if (val < 0) continue;` guard, under a comment claiming it was verbatim. A gate that
  compares a port against a paraphrase of the C proves only self-consistency. When an
  oracle copies a C function, paste it and diff it against the source; when that is
  impractical (headers, globals), say in the comment exactly what was changed and why.
  (Shipped a real fidelity bug in #70; caught while porting `fp6::vectorize`, which is
  what surfaced the sentinel's meaning.)
- **The fuzz crate is not in the workspace lint sweep.** `cargo clippy --workspace
  --all-targets` does **not** build `fuzz/`, which is a separate crate compiled only by
  `cargo +nightly fuzz build`. So adding a public field to a struct a fuzz target
  constructs (here `osscan::Report`) passes every local check and then fails CI's fuzz
  job on a plain compile error. Before pushing a change to any type a fuzz target names,
  run `for t in $(cargo +nightly fuzz list); do cargo +nightly fuzz build $t; done`.
  Same shape as the "lint both feature configurations" lesson: the local convenience
  invocation is not the CI invocation. (Cost a red fuzz job on #69.)
- **Lint both feature configurations before pushing**: `--all-features` turns `pcap`
  on, so it never sees an import that is only used by a `#[cfg(feature = "pcap")]`
  item. CI runs clippy with **and** without the feature under `-D warnings`; a
  local `--all-features`-only check passes code CI rejects. (Cost a red run on #55.)
  Same shape as the fuzz `+nightly` note in LESSONS #16: the local convenience
  invocation is not the CI invocation. For the next retrospective.
