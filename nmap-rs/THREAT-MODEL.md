# Threat model — nmap-rs

> Sections 1–6 are the Milestone 1 model, kept as written; later sections extend
> it per milestone: §7 traffic obfuscation (M7.5), §8 NSE (M6). Per-milestone
> Phase-0 analyses in `docs/` carry their own threat notes; this file collects
> the decisions.

Scopes what "secure" means for the M1 MVP (unprivileged `-sT` connect scan + host
discovery + normal/grepable/XML output) and tells the port loop which modules
touch untrusted input (fuzz those first) and which cross a privilege boundary
(audit those hardest). Extended per milestone as the surface grows.

## 1. Assets — what are we protecting?
- **The host we run on** from being subverted by hostile input we parse.
- **Our own process** from crash/hang/UB triggered by malformed data files,
  crafted CLI input, or hostile network responses.
- **Correctness of the scan report** — a scanner that mis-reports port state (or
  crashes mid-scan) is a safety failure for the operator who acts on it.

## 2. Trust boundaries — where untrusted / lower-trust data crosses in
Fuzz + validation priorities for M1, in order:

| Entry point | Source | Trust | Ported module | Fuzz? |
|---|---|---|---|---|
| **Target spec** (`scanme.nmap.org`, `10.0.0.0/24`, `1-100.*`) | CLI / `-iL` file | **untrusted** | `core::targets` | **yes (P0)** |
| **Port spec** (`-p 1-65535,U:53,T:80`) | CLI | **untrusted** | `core::ports` | **yes (P0)** |
| **`nmap-services`** data file (~1 MB) | filesystem / `--datadir` | **semi-trusted** | `core::ports` | **yes (P1)** |
| **DNS responses** (fwd/rev resolution of targets) | remote resolver | **untrusted** | the OS resolver (`getaddrinfo`, via `tokio::net::lookup_host` in `sys::net`) | no — no DNS bytes reach our code |
| Connect-scan results (RST/SYN-ACK/timeout) | remote host | untrusted-but-shallow | `sys::net` + `sys::scan::connect_scan` | indirect |
| Other CLI args / flags | operator | trusted-ish | `cli` | negative tests |
| `NMAP_RS_TRACE`, env, `--datadir` | operator | trusted-ish | `cli`, `sys` | — |

The M1 differential/fuzz gates cover exactly the **yes** rows. Network *content*
parsing (banners, packet dissection) is minimal in M1 (connect scan only observes
connect success/refusal/timeout) — it grows in M3 (`-sV`) and M4 (raw), which add
their own fuzz targets.

## 3. Privilege transitions
**M1 requires no elevation** — connect scan uses ordinary OS sockets (Winsock via
`tokio`), no raw packets, no Npcap, no Administrator. This is a deliberate M1
property: it sidesteps the whole privileged/`unsafe` surface. State it plainly so
reviewers don't assume raw-scan protections that arrive only in M4. When the
privileged path lands (M4), privilege is acquired just-in-time behind a
`PrivilegeGuard` RAII type and dropped on scope exit; M1 introduces no such
transition. `sys::net` is the only crate touching the OS; it is expected to carry
**~0 `unsafe`** for M1 (tokio's safe socket API), which the unsafe-audit gate
enforces.

## 4. Attacker capabilities we defend against
- Supplies **arbitrary bytes** on any untrusted boundary (target/port spec,
  `nmap-services`, DNS answers) → no panic / no UB: the fuzz gate proves it; no
  `unwrap()`/`expect()`/unchecked indexing on attacker-controlled data.
- Supplies **pathological sizes** (a `/0` CIDR = 2³² hosts; `-p 1-65535` ×
  protocols; a 10 M-line `-iL`; a length field in `nmap-services`) → no integer
  overflow, no unbounded allocation: `overflow-checks` on; size math is
  `checked_*`/`saturating_*`; iterate targets lazily rather than materializing.
- Returns **hostile DNS answers** (oversized names, compression loops, non-UTF-8)
  → the port parses no DNS: resolution is the OS's `getaddrinfo` (through
  `tokio::net::lookup_host`), which hands back addresses only; a failure is
  "unresolved," never a crash. If the port ever parses DNS itself, that parser
  is a new untrusted boundary and needs a fuzz target before it ships.
- **Races the filesystem** on the data-file path (`--datadir`, services file) →
  prefer open-then-use over check-then-open (no TOCTOU).

## 5. Explicit non-goals (M1)
- **No raw-packet scans, OS detection, service/version detection, or NSE** — those
  are M3/M4/M5/M6; their protections are out of scope here.
- We do **not** defend against a malicious *operator* who already has our
  privileges (they can pass any target/flags — that is the tool's purpose).
- Not resistant to a hostile *local filesystem* that replaces `nmap-services` with
  a well-formed-but-wrong file (that is a supply-chain/integrity concern handled by
  Workstream S signing, not M1 parsing).
- Timing/side-channel resistance is out of scope.

## 6. C-defect inventory (from `scan_c_flaws.py`)
Phase-0 scan of the M1 C sources (`Target/TargetGroup/targets/portlist/scan_lists/
services/timing/scan_engine_connect/output/xml/NmapOps`): **9 hits** — 7
unbounded-copy (CWE-120), 2 non-literal format-string (CWE-134). Raw output:
`nmap-rs/m1_cflaw.json`. Triage (each confirmed hit → a planned `DIVERGENCES.md`
entry the port closes, not re-ports):

| Site | Class | In M1? | Disposition |
|---|---|---|---|
| `services.cc:134/140` path build (`strcpy(filename+len, "\\drivers\\etc\\services")`) | CWE-120 | **yes** | Rust `PathBuf::join` — overflow-by-assumption eliminated |
| `output.cc:719` `strcpy(protocol, IPPROTO2STR(...))` | CWE-120 | **yes** | Rust `String`/`&str` — no fixed buffer |
| `output.cc:923/928` `vfprintf(fmt, …)` non-literal format | CWE-134 | **yes** | Rust type-safe `format!`/`write!` — format-string class gone |
| `output.cc:1564/2003/2027/2048` (`strcat`/`sprintf` of OS-detect seq/ipid/ts) | CWE-120 | **no (M5)** | osscan output path; logged for M5, not ported in M1 |

## 7. Traffic obfuscation and attribution — scope decision (M7.5)

C nmap ships an evasion suite: decoys (`-D`), source-address spoofing (`-S`),
MAC spoofing (`--spoof-mac`), fragmentation (`-f`/`--ff`/`--mtu`), bogus
checksums (`--badsum`), custom payloads (`--data*`), IP options
(`--ip-options`) and TTL control (`--ttl`). Nothing in this document previously
said whether the port should carry them, so this section is the precedent
rather than an application of one.

**The decision is not "evasion yes/no".** Framing it that way was the mistake
that kept it open through three milestones. These options differ enormously in
what they cost us and in what they let an operator do, and the useful split is
by *machinery*, not by intent.

**Ported (M7.5).** `--ttl`, `--badsum`, and `-S`. The packet builder already
carried `Ipv4Spec { ttl, bad_sum, src }` with tests
(`bad_sum_corrupts_the_l4_checksum`), because the raw scan paths needed those
fields to exist regardless. Declining these would not have meant *not building*
something — it would have meant deliberately leaving working, gated capability
unreachable, which is a much stronger claim than "we did not do that work" and
one nobody had actually made.

The operative argument for porting rather than withholding: this port's users
are people doing authorised testing. Withholding `-S` does not stop a scan from
being spoofed; it sends that operator back to C nmap, which is worse for
everyone including us — they lose the memory-safety properties this project
exists to provide, and we lose a user whose bug reports we would want.

**Deferred on cost, not on principle.**

| option | why not yet |
|---|---|
| `--ip-options` | the *transport* exists (`Ipv4Spec.options`, tested), but the spec string is a ~150-line state machine in C (`parse_ip_options`, `libnetutil/netutil.cc:207`) with `\x` escapes, `R`/`T`/`S`/`L` route and timestamp forms, `*` repetition and address lists. By this project's standards a new parser over operator-supplied text needs a differential oracle and a fuzz target. That is a piece of work, not a wiring job. |
| `-f` / `--ff` / `--mtu` | real IP fragmentation, which the builder does not do at all |
| `--data` / `--data-string` / `--data-length` | small, genuinely unstarted |
| `-D` (decoys) | needs a new sending model — N copies with varied sources, interleaved — and it *multiplies* generated traffic, so it interacts directly with the rate-limiting work in M7.3's MUST tier. Landing it before `-T`, `--scan-delay` and `--max-rate` exist would add a traffic multiplier to a scanner that cannot yet be told to slow down. |
| `--spoof-mac` | needs the L2 send path |

**What this section commits to.** Nothing here is "not ever". The boundary is
cost and ordering, and it is written down so that a future milestone picking
one of these up is continuing a plan rather than reopening a question. The one
ordering constraint that is a *safety* constraint, not a preference: **`-D`
does not land before the rate-limit options do.**

**What this section does not change.** The operator remains trusted (§5): they
can already pass any target and any flag, and that is the tool's purpose. These
options do not widen what a *remote* attacker can do to us, which is what the
rest of this document is about.

## 8. NSE — scripts, their arguments, and what they parse (M6)

NSE is the first part of nmap that **executes code by design**. Phase-0's
threat notes are in [`docs/M6-ANALYSIS.md`](docs/M6-ANALYSIS.md) ("Threat
model", Decision 2); this section records what the port does about each.

| boundary | trust | what the port does | where |
|---|---|---|---|
| A script's code (`--script FILE`, `scripts/`) | **untrusted-ish** (shipped scripts are trusted; a path the operator names may not be) | runs in a VM with no process, environment or unrestricted file access (below) | `core::nse::runtime`, `stdlib::{iolib,oslib}` |
| `script.db` and `.nse` metadata | semi-trusted (decides what runs) | parsed as bytes, never executed; fuzzed | `core::nse::script` (`nse_scriptdb`, `nse_metadata`) |
| `--script` selection rules | operator | total, fuzzed; rules over 64 KiB refused | `core::nse::selection` (`nse_selection`) |
| `--script-args` | operator, but often pasted | parsed by a port of nse_main.lua's grammar; fuzzed. Since the lfs step its values also designate output directories, by documented key only: pinned by unit and CLI tests; the fuzz target checks it is total and that making a directory is never allowed where writing is not | `core::nse::scriptargs`, `core::nse::fspolicy` (`nse_scriptargs`) |
| Network responses handed to scripts | **untrusted** | parsed in Lua, through first-party stdlib functions that are each fuzzed and differentially tested; since M6.6 step e also through LPeg (`json.parse`, coap's link format, lpeg-utility's fingerprint parsers, ntp-info, fingerprint-strings, http-affiliate-id's `re` grammars): a first-party engine, total, fuzzed, with nmap's backtrack ceiling (D2), wide indices where C's are 16 bits (D4), and every stage pre-emptible (D3) | `core::nse::stdlib` (`nse_pattern`, `nse_format`, `nse_strpack`, `nse_tail`, `nse_utf8_date`), `core::nse::lpeg` (`nse_lpeg_build`, `nse_lpeg_match`) |
| `nmapdb` arguments (M6.6 step a) | script | total parsers; the protocol option list is terminated, and a byte ≥ 0x80 is never a hex digit; fuzzed | `core::nse::nmapdb` (`nse_mac2corp`) |
| `nmap-mac-prefixes`, `nmap-protocols` (M6.6 step a) | semi-trusted (installer, `--datadir`) | read once, as bytes; no assert: a prefix-only line is skipped, and so is a protocol line C misreads; fuzzed | `core::macvendor` (`macvendor_parse`), `core::protocols` (`nse_protocols`) |

**The sandbox (Decision 2, M6.4c1).** In C nmap, `luaL_openlibs` gives every
script `os.execute`, `io.popen` and the whole file system, usually as root.
Here:

- **No process or environment surface.** There is no `os.execute`, `exit`,
  `remove`, `rename` or `tmpname`, no `io.popen`, `tmpfile` or stdin, and no
  `loadfile`, `dofile`, `package.loadlib` or C searchers. `os.getenv`
  answers `HOME` alone (`os-getenv-home-only`, M6.4e). `debug` is `getinfo`
  and `traceback` only.
- **Files through a policy.** Scripts may read beneath nmap's data
  directories and operator-named files. They may write operator-named files,
  or beneath an operator-designated output directory, and may create
  directories (`lfs.mkdir`) beneath such a directory only. A directory is
  designated by the arguments the shipped scripts document as their output
  directory, `http-fetch.destination` and three more
  (`fspolicy::OUTPUT_DIR_ARGS`, `docs/LFS-ANALYSIS.md` D1); a value
  elsewhere that names a directory (`url=/`) designates nothing. Paths are
  compared and opened canonical, so `..` and symbolic links do not escape
  (`core::nse::fspolicy`, `sys::nsefs`). A name that is a link leading
  nowhere is not written through, which `fopen` would do, creating the
  link's target wherever it is (`nse-write-through-dangling-link`, found by
  the lfs step's review); and the final name is opened with `O_NOFOLLOW`. A
  refusal looks like `EACCES`.
  - Residual risk: a link swapped in at an *intermediate* component between
    the check and the open, by an actor *outside* nmap who can write the
    directory (`openat2`'s `RESOLVE_BENEATH` would close it on Linux).
    Scripts cannot create links: `lfs.link` is not ported (`lfs-minimal`).
  - On Windows, unvalidated: a UNC path is canonicalised, which opens an SMB
    session, before the policy refuses it
    (`nse-fs-windows-unc-canonicalize`).
  - **Open** (`nse-named-values-grant-files`, next): any argument value
    that names a local file is readable and writable by every script, even
    one that names a path on the target.

**Resource bounds.** A runaway script must not take the scanner down:

- **Memory.** A budget fails with a catchable "not enough memory" instead of
  aborting the process (`Lua::set_memory_limit`, patch `0009`).
  - The command line sets **no** budget today (`nse-cli-no-memory-budget`);
    only the gates do.
  - So outside `stdlib::reserve`'s `try_reserve` paths, an allocation the
    system refuses still aborts the process.
- **Depth.** C-call depth (200), Lua stack (1,000,000 slots) and
  `__index`/`__newindex` chains (2,000) are bounded as in PUC-Lua.
- **Runaway matching.** The pattern matcher's worst case is bounded
  (`pattern-worst-case-time-is-bounded`). LPeg's is not bounded, as in C:
  building, compiling, matching and evaluating captures can each take time
  exponential in a pattern a script writes. Instead every stage burns fuel
  and returns to the VM between slices, so the watchdog below ends it
  (`lpeg-stall-limit-ends-finite-work`; C hangs), and the 11 patterns that
  read network data are linear in their subject, held to 1.25 times the
  steps per byte of their adversarial inputs (`lpeg_slowness_regression`).
  Size-chosen buffers (`string.rep`, `format`, `pack`) are checked against
  the budget before they are built.
- **CPU.** The engine steps the VM in slices and checks a watchdog between
  them. On the command line, a phase whose scheduler makes no pass for ten
  minutes, or for `--script-timeout` when set, ends as aborted. The results
  stored so far are kept and the scan carries on (`nse-stall-limit`). In
  nmap a script in `while true do end` hangs the scan. `--script-timeout`
  also runs through nmap's own `Thread:timed_out`, which, as in nmap,
  reaches threads waiting on I/O.
- **Code from the working directory.** nmap never looks for data files in
  the working directory, and neither does the port now. Before M6.4e its
  command line searched `.`, `..` and `../..` for data files. For NSE that
  would have meant running Lua from wherever the operator stands
  (`datadir-no-working-directory`).
- **Network data.** Whatever a peer sends reaches a script as an opaque Lua
  string. One read returns at most 4 MiB (`nse-read-size-cap`); nsock
  buffers without bound, so a peer that never sends the newline a
  `receive_lines` waits for can grow nmap's memory for as long as it keeps
  sending. Every socket a script opens counts against the parallelism limit, as
  in nmap (`nse-socket-limit`). Scripts reach the network only through
  `sys::nsenet`, which has no `unsafe`.

**Memory-safety bugs nmap has.** None of them is reproduced:

- `port_set_output` dereferences a port lookup it never checks. A script
  that edits the port table `stdnse.gethostport()` gives it crashes nmap.
  The port raises an error instead (`nse-port-output-on-unknown-port`).
- `receive_buf` trusts a delimiter function's indices down to `size_t`, so
  indices before the buffer read out of bounds
  (`nse-receive-buf-negative-index`).
- `condvar`'s option list is not `NULL`-terminated, so an unknown option
  reads past it (`nse-condvar-option-overread`).
- `set_timeout` formats an `int` with `%f` (`nse-negative-timeout-message`).
- `nmapdb.getservbyport`'s protocol list is not `NULL`-terminated, so an
  unknown protocol name reads past it
  (`nmapdb-getservbyport-option-overread`).
- 7.94's `nmapdb.getprotbynum` admits 255 and then asserts `num <
  UCHAR_MAX`, and its 255-slot protocol table takes a write one past its
  end from a data line for 255 (`nmapdb-getprotbynum-255-oracle-abort`).
- `nmapdb.mac2corp` passes a `char` to `isxdigit`, which is undefined for
  bytes ≥ 0x80 (`nmapdb-mac2corp-isxdigit-signed-char`).
- LPeg (`lpeg.c`, M6.6), seven, each reachable from patterns and calls a
  script makes:
  - a `Cmt` can call `__gc` on the pattern it runs in, which frees the code
    the machine is reading (use-after-free, `lpeg-code-freed-during-match`);
  - `doublecap` copies one entry more than the 32-entry capture array on
    the C stack holds (stack over-read, `lpeg-doublecap-stack-overread`);
  - `Cc(nil)` with no other constant reads a constant table that does not
    exist (null dereference, `lpeg-cc-nil-without-ktable`);
  - the peephole resumes one slot early after rewriting a jump, so it reads
    operands as instructions and follows jumps out of the code
    (`lpeg-codegen-jump-out-of-code`);
  - nested captures push past the Lua stack space LPeg checked for
    (`lpeg-nested-capture-lua-stack-overflow`);
  - tree sizes computed in `int` (`lpeg-tree-size-int-overflow`) and a
    string pattern's size truncated to `int`
    (`lpeg-pattern-string-size-overflow`) wrap short, and the C writes past
    the allocation (heap overflow).

**Not defended.** The operator can name any script, and a script can scan,
brute-force or exploit whatever its arguments point at. That is the tool's
purpose, as in §5. What the port removes is the step from "a script ran" to
"the host running nmap is compromised".
