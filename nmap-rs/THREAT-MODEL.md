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
| Connect-scan results (RST/SYN-ACK/timeout) | remote host | untrusted-but-shallow | `sys::net` + `core::connect_scan` | indirect |
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
| `--script-args` | operator, but often pasted | parsed by a port of nse_main.lua's grammar; fuzzed | `core::nse::scriptargs` (`nse_scriptargs`) |
| Network responses handed to scripts | **untrusted** | parsed in Lua, through first-party stdlib functions that are each fuzzed and differentially tested | `core::nse::stdlib` (`nse_pattern`, `nse_format`, `nse_strpack`, `nse_tail`, `nse_utf8_date`) |

**The sandbox (Decision 2, M6.4c1).** In C nmap, `luaL_openlibs` gives every
script `os.execute`, `io.popen` and the whole file system, usually as root.
Here:

- **No process or environment surface.** There is no `os.execute`, `exit`,
  `getenv`, `remove`, `rename` or `tmpname`, no `io.popen`, `tmpfile` or stdin,
  and no `loadfile`, `dofile`, `package.loadlib` or C searchers. `debug` is
  `getinfo` and `traceback` only.
- **Files through a policy.** Scripts may read beneath nmap's data
  directories and operator-named files. They may write operator-named files,
  or beneath an operator-designated output directory. Paths are compared and
  opened canonical, so `..` and symbolic links do not escape
  (`core::nse::fspolicy`, `sys::nsefs`). A refusal looks like `EACCES`.
  - Residual risk: a link swapped between the check and the open by an
    actor *outside* nmap. Scripts cannot create links.

**Resource bounds.** A runaway script must not take the scanner down:

- **Memory.** A budget fails with a catchable "not enough memory" instead of
  aborting the process (`Lua::set_memory_limit`, patch `0009`).
- **Depth.** C-call depth (200), Lua stack (1,000,000 slots) and
  `__index`/`__newindex` chains (2,000) are bounded as in PUC-Lua.
- **Runaway matching.** The pattern matcher's worst case is bounded
  (`pattern-worst-case-time-is-bounded`). Size-chosen buffers (`string.rep`,
  `format`, `pack`) are checked against the budget before they are built.
- **CPU.** Bounded by fuel today only for the engine's own prelude. Per-script
  time limits (`--script-timeout`) arrive with the scheduler (M6.4c2). Until
  then no script runs outside tests.

**Not defended.** The operator can name any script, and a script can scan,
brute-force or exploit whatever its arguments point at. That is the tool's
purpose, as in §5. What the port removes is the step from "a script ran" to
"the host running nmap is compromised".
