# Workstream S — signature-database maintenance: Phase-0 analysis

Fresh kit cycle (PLAYBOOK Phases 0–1). Inventory + C-flaw scan + threat model +
dependency-ordered build order. **No Rust is written until the build order is
approved** (kit requirement). This document is the durable record of the Phase-0
findings; the golden/negative test harness (Phase 2) and the per-module six-gate
loop (Phase 4) follow on approval.

## Scope

The maintenance loop around the three detection databases: **versioned signed
bundles**, an **update channel**, an **offline import path**, and an **opt-in
store for the unmatched fingerprints nmap already computes**. The *parsers* are
already ported and gated (M3 for `nmap-service-probes`, M5 for `nmap-os-db` and
`nmap-mac-prefixes`) and are **out of scope** here except where they must surface
version metadata.

| Database | Size | Records | Parser | Landed |
|---|---|---|---|---|
| `nmap-os-db` | 5.4 MB / 116,271 lines | 6,108 fingerprints | `core::osdb::{expr,model,parse,score}` | M5 |
| `nmap-service-probes` | 2.6 MB / 17,154 lines | 12,171 match rules | `core::probedb` + `core::matcher` | M3 |
| `nmap-mac-prefixes` | 1.4 MB / 52,091 lines | 52,085 OUI prefixes | `core::macvendor` | M5 |

## What the C actually does — verified, not assumed

This workstream is unusual: it is **additive**. Almost none of it exists in the C,
so the inventory is mostly a record of *absence*. Every claim below was checked
against the tree rather than carried over from the earlier plan sketch.

**1. There is no update mechanism. At all.**
`--script-updatedb` (`nmap.cc:247/615/666/2081`) rebuilds only the local **NSE
script index** — it does not touch these three databases. No other flag fetches,
verifies, or refreshes them. They change solely by shipping a new nmap release.

**2. There is no version metadata to read.**
All three files carry an **unexpanded SVN keyword** where a version should be:
`nmap-os-db:2` and `nmap-service-probes:2` are literally `# $Id$`, and
`nmap-mac-prefixes:1` is `# $Id: $`. A running nmap therefore *cannot* report
which vintage of `nmap-os-db` it loaded, because the file does not say. This is
the concrete gap behind part 1 of the design: the version field has to be added,
not merely surfaced.

**3. Collection is a copy-paste-to-web-form request.**
nmap computes the unmatched fingerprint and then prints a URL:
`output.cc:836` (`submit.cgi?new-service`), `:840`
(`NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)`), and `:1901/:1925/:1938`
(`https://nmap.org/submit/`) for OS. `:2506–2510` repeats the ask at scan end.
The data exists in-process; nothing captures it.

> **Correction (found while starting S3).** The paragraph above was originally
> written to say the *port* already computes both the OS and the service
> fingerprint, so collection would be pure capture. That is true for OS —
> `core::osscan::submission_reason` (porting `OmitSubmissionFP`) and
> `FingerPrint::render_tests` (porting `fp2ascii`) both landed in M5. It is
> **false for service**: `service_scan.cc`'s `addServiceChar` /
> `addServiceString` / `addToServiceFingerprint` (`:1663–1720`) were never
> ported in M3, and a search of `crates/` finds no service-fingerprint builder
> at all. The service half of collection therefore needs a *port*, not a
> capture — and unlike the rest of this workstream it has a real C oracle,
> because the C emits a specific format (74-column wrap with `\nSF:`
> continuations, `\xHH` escaping, a 900/1300-byte per-response truncation and a
> 2200/10000-byte total cap, `%r(probe,len,"...")` records under an
> `SF-PortNNNN-TCP` header). That is a different kind of work from the additive
> store, so the slice is split: **S3a** captures what exists, **S3b** ports the
> builder. Splitting it also keeps a differential-gated port out of a PR whose
> other half can only be golden-gated.

**4. Database path resolution is a trust boundary the C handles by warning.**
`nmap_fetchfile_sub` (`nmap.cc:2677`) searches, in order: `--datadir` → **the
`$NMAPDIR` environment variable** → the user's home directory (`~/.nmap`, or
`%APPDATA%\nmap`) → the executable's directory → `../share/nmap` → `NMAPDATADIR`.
The first readable hit wins, and the content is then trusted completely.

Two properties matter for the port:

- On non-Windows, `nmap_fetchfile_userdir` (`:2660`) tries `getuid()`'s home
  **first** and only then `geteuid()`'s. Under a setuid-root nmap that means the
  *unprivileged* invoking user's `~/.nmap/nmap-os-db` is preferred over root's.
- nmap knows this. `nmap.cc:319–323` prints
  `"WARNING: Running Nmap setuid, as you are doing, is a major security risk."`
  The mitigation for data-file substitution is **telling the operator not to do
  that**, because there is nothing in the format to verify against.

There is also a partial anti-confusion check: if a same-named file exists in the
CWD and differs from the chosen one, nmap warns (`:2744`) — but on Windows only
when `-d` is on, and it is a warning, not a refusal.

**This is the strongest argument for the design.** Signed bundles do not merely
add a feature; they replace "trust whichever path won the search" with "trust
content that verifies against a pinned key," which makes the whole search-order
question stop being security-relevant.

## C-flaw scan

`scan_c_flaws.py nmap.cc` → **2 hits, both `toctou` (CWE-367)**, at `nmap.cc:2581`
and `:2583` — the two `stat()` calls in `same_file()`, reached from the `./`
confusion check above.

The scanner's own "what this cannot find" section applies with unusual force here,
and the honest summary is that **a flaw scan has almost nothing to bite on in this
workstream**, because the code being written does not exist in the C yet. Reading
the surrounding code found more than the grep did:

1. **TOCTOU on every database path (CWE-367).** `file_is_readable()`
   (`nbase/nbase_misc.c:707`) is a `stat()`; the file is opened later, by a
   different call, with no handle carried between them. All six
   `file_is_readable` call sites inside `nmap_fetchfile_sub` (`:2687`, `:2694`,
   `:2712`, `:2719`, `:2730`, `:2738`) have this shape, as does the
   `--servicedb`-style early return at `:2623`. The window is small and local,
   but it is structural.
   **The port closes this by construction:** a bundle is verified by *content
   hash and signature over the bytes actually read*, so what the path pointed at
   between the check and the open cannot matter.

2. **1-byte out-of-bounds read on an empty data-file path (Windows-only,
   operator-triggered).** `file_is_readable()` does
   `char last_char = pathname_buf[pathname_len - 1];` (`nbase_misc.c:715`) with no
   guard for `pathname_len == 0`. `--servicedb ""` / `--versiondb ""` take
   `required_argument` and store `optarg` verbatim into `o.requested_data_files`
   (`nmap.cc:755–759`), which `nmap_fetchfile` passes straight to
   `file_is_readable` (`:2623`) — so an empty string reaches it and indexes
   `strdup("")[-1]`.
   **Severity: low, and stated as such.** It is Windows-only, requires the
   operator to pass an empty value on their own command line, and reads one byte
   before a heap allocation rather than writing. It is not remotely reachable. It
   is recorded because we target `x86_64-pc-windows-msvc` and the port must not
   reproduce the class: in Rust the path is a `Path`, and "last character of a
   possibly-empty string" is `.chars().last()` returning `Option`.

Both go to `DIVERGENCES.md` when the owning module lands.

## Threat model (additions for Workstream S)

This workstream introduces the port's **first outbound network fetch** and its
**first signature verification**. That is a materially larger attack surface than
anything M0–M5 added, and it is the part of Phase 0 that matters most.

### New assets
- **The pinned verification key.** Compromise of it forfeits every other control.
- **The installed database bundles.** Poisoning them silently misleads detection —
  the interesting attack is not a crash, it is an OS/service *misidentification*
  that the operator acts on.
- **The local unmatched-fingerprint store.** It describes hosts the operator
  scanned. It is reconnaissance data about third parties.

### Trust boundaries crossed
| Boundary | Untrusted input | Control |
|---|---|---|
| Update channel → loader | The fetched bundle (a remote server, or anyone who can MITM or compromise it) | Signature over the manifest, then content hash per file; **verify before parse**, never parse to decide whether to verify |
| Offline import → loader | An operator-supplied file, possibly from an untrusted medium | Identical verification path — no "it's local, so it's fine" shortcut |
| Fingerprint store → disk | Scan responses, i.e. attacker-controlled bytes | The fingerprint is already a normalized, bounded projection; store it as data, never interpolate it into a path or command |
| Fingerprint store → network (submit) | The operator's own scan history | **Opt-in, consent-gated, off by default**; nothing leaves the host without an explicit act |

### Attacker capabilities defended against
- **Network attacker on the update path** — passive read, active MITM, or full
  control of the source. Signature verification, not TLS alone, is the control;
  TLS is defense in depth. A verify failure **keeps the existing database** and
  exits non-zero; the port never runs on unverified data.
- **Rollback / freeze.** A signed-but-old bundle is a valid signature over stale
  content. The manifest carries a monotonic content version and the loader
  **refuses a downgrade** unless the operator passes an explicit override flag.
- **Malicious bundle content.** A bundle that verifies can still contain a hostile
  *database*. The parsers are already fuzzed, and the archive layer gets its own
  negative tests: path traversal (`../`), absolute paths, symlinks, duplicate
  entries, decompression bombs, truncation, and size caps enforced before write.
- **Local attacker racing the swap.** The install is **atomic** (write to a
  temporary file in the destination directory, fsync, rename) and never overwrites
  a system copy — updates land in the per-user data directory.

### Explicit non-goals for this workstream
- **Running the signing infrastructure.** The port verifies; it does not become a
  key-management or distribution service. Key rotation policy is an M7 release
  concern, flagged here so it is not silently assumed solved.
- **Automatic background updates.** Every fetch is an explicit operator action.
  No timer, no update-on-scan, no phone-home.
- **Submitting anything by default.** Part 3 ships collection and export first;
  network submission is a separate, later, opt-in switch.

## Proposed build order (leaf-first) — **approval gate**

Five slices, each a PR, each clearing all six gates. Ordered so that everything
decidable from bytes is gated in CI before any network code exists.

| # | Module | Crate | What it is | Gate |
|---|---|---|---|---|
| S1 | `core::sigstore::manifest` | `core` | The manifest format: schema version, per-file content version + SHA-256 + source, and the **downgrade comparison**. Pure, no I/O. | Golden + negative tests; fuzz the manifest parser (untrusted input); property-test the version ordering |
| S2 | `core::sigstore::verify` | `core` | Signature verification over the manifest, then per-file hash. Pure over `&[u8]` with an injected key — no filesystem, no clock. | Known-answer tests against fixed vectors; negative tests (wrong key, truncated sig, hash mismatch, swapped files); fuzz |
| S3a | `core::fingerprint_store` | `core` | The opt-in store for the **OS** fingerprints the port already computes, plus `--export-fingerprints`. Pure model + serializer. | Round-trip golden; fuzz; an explicit test that consent-off stores nothing |
| S3b | `core::servicefp` | `core` | **Port** of `service_scan.cc`'s service-fingerprint builder (wrap, escape, truncate, cap), which M3 left out. Feeds the same store. | C-oracle differential — the one slice in this workstream that has one |
| S4 | `sys::sigstore` | `sys` | Atomic install (temp + fsync + rename), per-user data dir resolution, and the archive unpack with the traversal/bomb/size limits from the threat model. | Negative tests per attack in the table; no network yet |
| S5 | `sys::update` + CLI | `sys`/`cli` | `--update-signatures`, `--check-signatures`, `--import-signatures <file>`, and the version surfaced in `--version`/verbose. HTTPS fetch behind the same verify path. | Mock-transport tests for the fetch loop; end-to-end against a locally served fixture bundle |

**Why this order.** S1 and S2 are pure and fully CI-gated, so the security core is
proved before anything can download a byte. S3 is independent of S1/S2 and could
move earlier if you want the collection half first. S4 is where the first `unsafe`-
adjacent surface (filesystem, atomicity) appears, and S5 — the only slice with
network access — is deliberately last and thinnest, because by then it is a
transport feeding an already-verified pipeline.

**S2, as built (resolved).** The signing scheme question below was answered
*minisign-style Ed25519*, implemented with the vetted `ed25519-dalek` crate rather
than hand-rolled — the opposite of the call made for SHA-256 one slice earlier, and
argued in `DIVERGENCES.md` under `sigstore-ed25519-dependency`. Two scope
corrections to the row above:

- **Verification only.** The row says "signature verification over the manifest,
  *then per-file hash*". The per-file hash half already shipped in S4:
  `sys::sigstore::Installer::install` checks declared size, then SHA-256, before it
  writes a byte. S2 is therefore purely the signature layer, and the two meet at
  `VerifiedManifest`, which is the only thing the install path accepts.
- **There *is* an oracle after all.** The note below says S1–S5 have nothing to
  differential against. That is true of the C nmap tree, but not of the primitive:
  S2 verifies signatures produced by the OpenSSL CLI, over a 39-case corpus
  re-derived on every CI run, with the generator refusing to emit anything unless
  OpenSSL first reproduces the RFC 8032 §7.1 vectors byte for byte. The container
  was additionally cross-checked against the real `minisign` 0.11 binary, which
  accepts our fixtures (with `-l`, since we sign in pure mode). So this slice is
  gated by an independent implementation, not only by golden and negative tests.

**Oracle note, stated plainly.** There is no C to differential against for S1–S5;
the C has none of this. Per the kit that means golden + negative tests carry the
weight here, and **every slice is ledgered in `DIVERGENCES.md` as intentional
additive behavior** rather than silently appearing. The one exception is that the
loaders must keep matching C nmap on the same database — that differential already
exists from M3/M5 and must stay green as version metadata is threaded through.

## Open questions for the approval gate

1. ✅ **Signing scheme — DECIDED and shipped in S2.** minisign (small, Ed25519, one dependency, no X.509) vs
   cosign/sigstore (transparency log, heavier, more infrastructure). Recommend
   **minisign-style Ed25519** for S2 — it keeps `core` pure and the verify path
   auditable in a page of code — with the format versioned so a transparency log
   can be added later without a breaking change.
2. **Bundle source.** There is no official nmap signature-bundle endpoint to point
   at, because this mechanism does not exist upstream. S5 needs a decision: a
   configurable source with no default (safest, least useful), or a documented
   default the operator can override.
3. **S3 ordering.** Collection is independent of the update path. If the
   fingerprint store is the more useful half to you, S3 can lead.
4. **S3b scope.** Porting the service-fingerprint builder is a real C port with a
   real oracle, discovered only when S3 started (see the correction above). It is
   worth doing for its own sake — it closes an M3 gap, not just an S one — but it
   is not on the critical path for the update channel.
