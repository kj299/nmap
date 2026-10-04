# Differential tests — nmap-rs against the C

Gate 2 of the kit's six (`ported → differential → …`): every module is compared
with the C it replaces, run as an oracle. Each directory holds a milestone's
corpora, the oracles that produced them, and the scripts that regenerate them.
The Rust side of each is a test in `crates/core/tests/` (or a CI job, where
the comparison needs the whole binary).

| directory | what it gates | oracle |
|---|---|---|
| this one | M1: `-sT` end to end (`run_differential.sh`, below) | installed nmap, on a loopback fixture |
| [`m4/`](m4/README.md) | M4: packet headers, builder, parser, validation, classification | C harnesses compiled from this tree's sources |
| `m5/` | M5: OS-detection expressions, probes and IPv6 fingerprinting; `run_os_differential.sh` runs `-O` on the wire | C harnesses from this tree, and installed nmap |
| [`m6/`](m6/README.md) | M6: NSE — script metadata, selection, the Lua VM and stdlib, `--script-args`, the `nmap` module, the NSE state | `liblua/` and `lpeg.c` from this tree; installed nmap 7.94 |
| `m7/` | M7: log-file output, time-value parsing, and the `--top-ports`/`-F`/`--port-ratio` port sets | C harnesses from this tree; installed nmap (`--packet-trace`, `--datadir` this tree) |
| `s/` | Workstream S: SHA-256, minisign verification, service fingerprints | OpenSSL CLI; a C++ harness over this tree's service-fingerprint code |

Each corpus with a `regen_*.sh` is re-derived from its oracle in CI with
`--check`, and fails on any difference. Live runs against installed nmap are
in CI's `differential` job.

---

## M1 differential oracle — nmap-rs vs C nmap

Proves the Milestone-1 connect scan reports the **same scan result** as C nmap,
over a reproducible loopback fixture. This is gate 2 of the kit's six
(`ported → differential → …`) for the M1 modules, wired into CI as the
`differential` job.

### Run it

```sh
cargo build --release                       # produce target/release/nmap-rs
sudo apt-get install -y nmap                 # the C oracle
bash tests/differential/run_differential.sh  # fixture + both tools + diff
```

Point at specific binaries with `NMAP=/path/to/nmap NMAP_RS=/path/to/nmap-rs`.
Harness sanity without a fixture: `run_differential.sh --self-test`.

### How it works

- **Fixture** — `run_differential.sh` binds loopback listeners on the fixed
  "open" ports (18080, 18443); every other port is closed and returns an immediate
  RST. Loopback makes `open`/`closed` deterministic without depending on timing.
- **Matrix** — `mvp-matrix.toml` lists the scan cases (flags + target); the
  wrappers append `-oX -`.
- **Projection** — `project.py` reduces each tool's XML to the canonical semantic
  result: `host <addr> <status>`, `open <port> <proto> <reason>`, and per-state
  `closed-count`/`filtered-count`. This is the content M1 commits to.
- **Diff** — the kit's `harnesses/differential/diff_run.py` compares the two
  projections per case. `MATCH` = identical result; an unledgered `DIVERGE` fails.

### Why a projection, not a raw diff

C nmap and the MVP legitimately differ in ways that are **out of M1 scope**, not
fidelity bugs (see `../../DIVERGENCES.md` → "M1 output-format abbreviation"): the
MVP collapses non-open ports into an `<extraports>` summary, omits nmap's
decorative XML preamble, and does no service/version guessing. Diffing raw XML
would bury the load-bearing question — *did we get every port's state and reason
right?* — under that intentional noise. The projection canonicalizes both
representations so a genuine regression (an open port reported closed, a wrong
reason, a miscounted closed set) breaks the match while the ledgered abbreviations
stay invisible. Full output-format parity is a later-milestone differential.

### Grow it

Every time a bug escapes, add the case that would have caught it to
`mvp-matrix.toml`. When the output-fidelity pass lands (M2/M3), extend the
projection or add a second, format-level matrix.
