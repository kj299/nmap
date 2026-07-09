# Threat model — nmap-rs (Milestone 1: unprivileged TCP connect scan)

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
| **DNS responses** (fwd/rev resolution of targets) | remote resolver | **untrusted** | `sys::net` | **yes (P1)** |
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
  → the resolver crate is fuzzed at the boundary; malformed answers degrade to
  "unresolved," never crash.
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
