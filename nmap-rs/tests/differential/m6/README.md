# M6 differentials — NSE, against nmap's own Lua and nmap itself

Every M6 gate is here. The oracle is one of three things:

- `liblua/` (and, where needed, `lpeg.c`) compiled **out of this repository**
  by `oracle/build_lua_oracle.sh`;
- `nse_main.lua` logic sliced verbatim by `oracle/extract_nse_main.py`;
- the installed nmap 7.94, pointed at this tree with `--datadir`.

Each `regen_*.sh` re-derives its files, and `--check` (what CI runs) fails on
any difference.

| corpus | gates | regenerate | Rust test | cases |
|---|---|---|---|---|
| `m6_scriptdb_*`, `m6_nse_*` | `.nse` metadata, `script.db` (M6.1) | `regen_m6.sh` | `nse_differential`, `nse_corpus` | 58 + 31 |
| `m62_*` | `--script` selection (M6.2) | `regen_m62.sh` | `selection_differential`, `selection_corpus` | 98 + 15, 27,495-verdict sweep |
| `m60_semantics_*` | VM semantics (M6.0) | `regen_m60.sh` | `lua_semantics_differential` | 99 (1 pinned) |
| `m60_arith_*`, `m60_coerce_*` | modulo and shifts; string-to-number coercion | `regen_m60.sh` | `lua_semantics_differential` | 2,955; 1,975 |
| `m60_floatfmt_*` | float formatting | `regen_m60.sh` | `lua_float_format_differential` | 7,917 |
| `m6_strpack_*` | `string.pack` / `unpack` / `packsize` | `regen_m6_strpack.sh` | `strpack_differential` | 4,804 |
| `m6_pattern_*` | `string.find` / `match` / `gmatch` / `gsub` | `regen_m6_pattern.sh` | `pattern_differential` | 11,408 |
| `m6_format_*` | `string.format` | `regen_m6_format.sh` | `format_differential` | 6,037 |
| `m6_tail_*` | `_G`, `rawequal`, `xpcall`, `load`, `coroutine.wrap`, `string.rep` | `regen_m6_tail.sh` | `tail_differential` | 1,019 |
| `m63_args_*` | `--script-args` (M6.3) | `regen_m63.sh` | `scriptargs_differential` | 20,517 |
| `m63_nmap_golden.txt` | the `nmap` module's non-I/O half, vs nmap 7.94 | `oracle/gen_m63_nmap.py` (live in CI) | `nmaplib_differential` | 10 scenarios (9 without IPv6 loopback, as in the committed golden) |
| `m64_errors_*` | VM runtime errors, numeric `for` (M6.4a) | `regen_m64_errors.sh` | `errors_differential` | 12,438 |
| `m64_limits_*` | C-call depth, stack, `MAXTAGLOOP` (M6.4b) | `regen_m64_limits.sh` | `limits_differential` | 335 |
| `m64_memory_*` | the memory budget, vs `ulimit -v` (M6.4b) | `regen_m64_memory.sh` | `memory_differential` | 41 |
| `m64_stdlib_*` | `utf8`, `os`, `io`, `debug` (M6.4c1) | `regen_m64_stdlib.sh` | `stdlib_differential` | 2,012 |
| `m64_nselib_golden.txt` | every `nselib/` library loads; unit-test suites pass, vs nmap 7.94 | `oracle/gen_m64_nselib.py` (live in CI) | `nselib_differential` | 133 + 26 |
| `m64_scripts_golden.txt` | running scripts: rules, threads, runlevels, selection, output (M6.4c2), vs nmap 7.94 | `oracle/gen_m64_scripts.py` (live in CI) | `scripts_differential` | 37 scenarios |
| `m64_net_golden.txt` | sockets, timers, `resolve`, `mutex`, `condvar`, socket limits, shipped `http-*` scripts (M6.4d), vs nmap 7.94 | `oracle/gen_m64_net.py` (live in CI) | `nse_net_differential` (in `nmap-sys`) | 3 scenarios, 17 scripts |
| `m64_cli_golden.txt` | `nmap-rs --script` as a whole program: every phase's results and port states in normal and XML output, script arguments, timeouts, start-up errors (M6.4e), vs nmap 7.94 | `oracle/gen_m64_cli.py` (live in CI) | `nse_cli_differential` (in `nmap-cli`) | 15 scenarios |
| `m66_nmapdb_golden.txt`, `m66_nmapdb_quarantine.txt` | the C module `nmapdb` over this tree's data files (M6.6), vs nmap 7.94 | `regen_m66_nmapdb.sh`, `oracle/gen_m66_nmapdb.py` (live in CI) | `nmapdb_differential` | 115,064 lines; 36 calls quarantined, each pinned |
| `m66_scriptload_golden.txt` | how each shipped script loads, alone, without the C modules the port lacks (M6.6), vs nmap 7.94 | `regen_m66_scriptload.sh`, `oracle/gen_m66_scriptload.py` (live in CI) | `scriptload_differential` | 611 scripts: 531 OK, 33 LOUD, 47 QUIET |
| `m66_lpeg_*` | the C module `lpeg` (LPeg 0.12) with `re` and `lpeg-utility` (M6.6 step 0b), vs this tree's Lua + LPeg, and nmap 7.94 | `regen_m66_lpeg.sh` (`--check`; `--check-794` live in CI) | none yet (steps b–e) | 62,599 rows; 164 quarantined |

Pinned exceptions are named in each Rust test and ledgered in `DIVERGENCES.md`.
The sections below explain the corpora that need it.

## M6.1 differential — the NSE script index and `.nse` metadata

Gate 2 for `core::nse::script`. Two oracles run here, and they answer different
questions.

### Oracle 1 — nmap's own Lua, on a corpus of edge cases

`regen_m6.sh` compiles `liblua/` **out of this repository** into a Lua 5.4.8
interpreter and drives it with loading logic sliced verbatim out of
`nse_main.lua`. Nothing about how nmap reads these two formats is restated in the
harness; `oracle/extract_nse_main.py` lifts six blocks by anchor line and
`gen_m6_cases.py` pastes them into the generated driver, with a digest over all
six in its header. If upstream moves an anchor, generation fails loudly — a
silently-diverged oracle is worse than no oracle.

```sh
bash regen_m6.sh            # rebuild the corpus, golden and fixtures
bash regen_m6.sh --check    # FAIL if any of the five files differs (what CI runs)
```

Five files are derived and all five are checked:

| file | what it holds |
|---|---|
| `m6_scriptdb_cases.txt` | 58 `script.db` inputs, hex-encoded |
| `m6_scriptdb_golden.txt` | Lua's verdict, and the verdict this port must reach |
| `m6_nse_cases.txt` | 31 `.nse` sources |
| `m6_nse_golden.txt` | the same two columns |
| `m6_fixtures.rs` | the same inputs as Rust consts, `include!`d by the unit tests |

The fixtures exist because the unit tests in `core::nse::script` run under Miri,
where there is no filesystem. Checking them here is what stops the Miri-visible
tests from drifting away from the corpus.

A golden row whose two columns disagree is a deliberate divergence, ledgered in
`DIVERGENCES.md` and pinned by name in `crates/core/tests/nse_differential.rs`,
so a new one cannot appear without editing that test. There are seven, and every
one is nmap's Lua accepting something that requires *evaluation*.

### Oracle 2 — nmap's own output, over the whole shipped corpus

The stronger check needs no Lua at all, and it is in
`crates/core/tests/nse_corpus.rs`.

`scripts/script.db` was generated by upstream nmap: `--script-updatedb` loads
every `scripts/*.nse` through `Script.new`, which *executes* each script's top
level with the full standard library, and writes out the categories it found.
That committed file is therefore a golden record of exactly the extraction this
module ports — produced by the reference implementation, over all 611 shipped
scripts.

So the test re-derives it: read every script with `core::nse::script`, re-emit
the index in nmap's exact output format (`nse_main.lua:1336-1343`), and require
the result to equal the committed file **byte for byte**. It does, all 52,755 of
them.

### Why the oracle cannot simply be run over the real scripts

Feeding a real `.nse` to oracle 1 fails: 610 of 611 shipped scripts
`require "nmap"`, a module that only exists inside the nmap process, so
`Script.new` raises before it reaches the metadata. That is not a defect in the
harness — it is the measurement that motivates the port. The C's metadata
extraction is coupled to the whole runtime *because it works by execution*;
this port's is a function of the bytes, and reads all 611 outside any process.

---

## M6.2 differential — the `--script` selection grammar

Gate 2 for `core::nse::selection`. Regenerate with `regen_m62.sh`; CI runs
`regen_m62.sh --check`, which re-derives all six generated files and fails on
any difference.

### Why the oracle needs LPeg, not just Lua

M6.1 needed nmap's Lua. M6.2 needs nmap's **LPeg** as well, so
`build_lua_oracle.sh` now compiles `lpeg.c` (through `nse_lpeg.cc`, the same
wrapper nmap itself builds it with) into the oracle interpreter.

That is not fastidiousness. Everything surprising about this grammar is a
property of that engine:

- **Ordered choice commits.** PEG backtracking is local: once an alternative
  succeeds, a later failure in the enclosing sequence does not reconsider it.
  With `x` as one of the script's categories, `x,y` therefore fails to parse —
  `category` consumes `x` and the leftover `,y` is fatal — while the same rule
  against a script *without* that category parses as the single glob `x,y`.
- **Repetition is possessive.** `path` is `R(...)^1` and never gives characters
  back to help a later part of the pattern.
- **Capture functions run after the match, over the surviving tree only.**
  `match_script` sets `selected_by_name` as a side effect, so a glob that is
  evaluated but contributes nothing still sets it — `safe and not http-*`
  reports "selected by name" while returning false.

A hand-written oracle would encode what a PEG *ought* to do and bless the same
wrong answers as the port. Compiling the real engine costs about twenty lines of
build script.

### The two oracles

**1. Edge cases** — 98 `(rule, filename, categories)` triples plus 15
rule-normalisation cases, chosen to sit on the corners: keyword follow-sets,
glob metacharacters, the path class's byte-range edges, grouping, and the
nesting ceilings.

**2. The shipped index** — `m62_sweep_golden.txt` runs 45 realistic rules
against all 611 entries of `scripts/script.db`: **27,495 verdicts**, none chosen
to be interesting. Per rule it records how many scripts matched, how many were
selected by name, and a SHA-256 over the matching filenames in index order. The
digest is what makes it exact rather than statistical — two different selections
of the same size cannot agree.

### Three things the corpus establishes

**Grouping is right-greedy, not conventional.** `a and b or c` means
`a and (b or c)`. On the shipped index, `safe and not intrusive or vuln` selects
**350** scripts while `(safe and not intrusive) or vuln` selects **421** — so the
trap is worth 71 scripts on real data. The port reproduces it rather than
"fixing" it, because fixing it would silently change which scripts run.

**Keywords fold case; globs do not.** `--script SAFE` selects the same 352
scripts as `safe`. `--script Http-*` selects **none**, where `http-*` selects
134.

**`*` is the only wildcard.** `?`, `.`, `[`, `]`, `+`, `-`, `^`, `$` and `%` are
all escaped into literals before matching, so `http-titl?` does not match
`http-title`.

### Divergences

One, ledgered as `nse-selection-depth-ceiling` and pinned by name in
`selection_differential.rs`: the C refuses deeply nested rules because LPeg's
100-slot backtrack stack runs out — at 15 nested parentheses, 19 chained `and`s
or 31 chained `or`s, three different numbers from one shared budget — and this
port evaluates them instead. Plus `nse-selection-rule-length`, the one place the
port is stricter: rules over 64 KiB are refused.

### Running the fuzzer without trashing the seeds

libFuzzer treats the **first** corpus directory on the command line as writable
output and any further ones as read-only input. So this grows the curated seed
corpus by thousands of files:

```sh
cargo +nightly fuzz run nse_selection fuzz/seeds/nse_selection   # DON'T
```

Pass a scratch corpus first instead — `fuzz/corpus/` is gitignored:

```sh
mkdir -p fuzz/corpus/nse_selection
cargo +nightly fuzz run nse_selection fuzz/corpus/nse_selection fuzz/seeds/nse_selection \
  -- -max_total_time=300 -print_final_stats=1
```

CI does the same. The seeds directory is meant to stay small and hand-read:
20 shapes chosen by hand, plus three inputs the fuzzer found that are kept
because they are regression tests for specific performance bugs.

## M6 stdlib differentials — the Lua standard library NSE needs

The vendored VM ships seven string functions; the rest are written first-party
in `core::nse::stdlib`. Each is gated against `liblua/` (the table above). Every
case is a Lua chunk that the oracle's `lua` evaluates, and that the Rust harness
(`crates/core/tests/m6_eval/`) evaluates through the VM with the port
installed. None of these corpora has an exemption list.

The pattern corpus was the first to compare error **messages**
(`oracle/m6_pattern_driver.lua` hex-encodes them), because the matcher's errors
are lazy, and "which message, or none" is the behaviour under test. Every later
corpus uses the same driver. Section J of the pattern corpus reads every
pattern literal in `nselib/` and `scripts/`, so a change to those trees changes
the corpus, and `--check` says so.

To check a candidate case before adding it, run the same cases file through
both sides and diff:

```sh
./oracle/lua oracle/m6_pattern_driver.lua my_cases.txt > lua.txt
cargo run -p nmap-core --example m6_eval -- my_cases.txt > port.txt
diff lua.txt port.txt
```

The VM positions its own errors as PUC-Lua does (M6.4a). An error raised by a
first-party stdlib function and escaping the chunk, however, lacks the
`chunk:N: ` prefix that `luaL_error` gives it in nmap's Lua
(`stdlib-errors-have-no-position`, DIVERGENCES.md). The gates discount exactly
that prefix, and a plain `diff` does not. `M6_MEMORY_LIMIT=<bytes>` runs the
example under a memory budget, as `memory_differential` does.

## M6.4c1 — the NSE state

`m64_stdlib_*` runs from this directory under `TZ=UTC`: the port's local time
is UTC (`os-local-time-is-utc`). The `io` cases read the files in
`fixtures/io/` and write in `/tmp/m64io/`, which `regen_m64_stdlib.sh`
recreates. The Rust harness serves the same paths from memory
(`crates/core/tests/m6_eval/memfs.rs`), so the gate never touches the disk the
oracle wrote.

`m64_nselib_golden.txt` comes from nmap itself. `oracle/gen_m64_nselib.py` runs
two probe scripts (`oracle/m64_probe_require.nse`, `m64_probe_unittest.nse`)
as prerules, with `-sn` against 127.0.0.1, so nothing leaves the host. They
`require` every library in this tree's `nselib/` and run every `test_suite`.
The port must end each one the same way, except for the libraries pinned in
`nselib_differential.rs` to C modules not yet ported. To see one library under
the port:

```sh
cargo run -p nmap-core --example nse_require -- [--unittest] /path/to/nmap LIB...
```

## M6.4c2 — running scripts

`m64_scripts_golden.txt` comes from nmap itself, running the fixture scripts in
`nse_scripts/`. Each one exercises one thing:

- an output shape: string, number, table, `__tostring`, `output_table`,
  bytes that need escaping;
- a rule;
- an error path;
- a selection case.

They come with their own `script.db`. `oracle/gen_m64_scripts.py` builds a
scratch data directory from this tree's data files and `nselib/`, with a
`scripts/` holding the fixtures and the shipped `unittest.nse`. It then runs
each scenario as a connect scan of two loopback listeners and one closed
port. It records the scan's port facts, then each result's normal-output
lines and its `<script>` element, or the init error's message.
`scripts_differential` builds the same directory, chooses the same scripts with
`core::nse::choose`, runs the three phases through the engine, and compares
byte for byte.

The fixtures keep at most one string key per table level. Lua orders string
keys by hash, which varies run to run under nmap. Results are compared in
script-id order, which is the port's order; nmap's own order is allocation
order (`nse-results-sorted-by-id`).

To see what the port prints for some scripts:

```sh
cargo run -p nmap-core --example nse_run -- /path/to/nmap SCRIPT.nse...
```

## M6.4d — sockets

`m64_net_golden.txt` comes from nmap running the fixture scripts in
`nse_net/`, with their own `script.db`, against loopback services that
`oracle/gen_m64_net.py` runs while it scans:

| port | service |
|---|---|
| 46030 | TCP echo |
| 46031 | TCP banner (`line1\nline2\r\nline3`), then close |
| 46032 | TCP, accepts and stays silent |
| 46033 | closed |
| 46034 | UDP echo |
| 46035 | TCP, sends `ab`, `c\nd`, `e\n`, `fgh` 200 ms apart |
| 46036 | UDP, nothing listens: a connected receive times out |
| 8080 | HTTP, one fixed response |

There are three scenarios:

- `net` runs every script in the `net` category;
- `shipped` runs this tree's `http-title` and `http-headers` against port
  8080;
- `script-timeout` runs `n-slow`, which waits on the silent port, under
  `--script-timeout 1`.

The generator symlinks the shipped scripts into the scratch data
directory's `scripts/`. Without that, nmap would take them from its
installed data directory.

`nse_net_differential` (in `nmap-sys`, since it needs the tokio host) runs
the same services and scripts through the port's engine over
`sys::nsenet::TokioNet`, and compares byte for byte.

The fixtures print only what is the same on every run:

- elapsed times as a comparison against a bound;
- `n-timeout` prints only the prefix of the negative-timeout message, whose
  value nmap prints through undefined behaviour;
- `n-refused` strips the function's name from one argument error, since
  `nmap.new_socket` and `nmap.socket.new` are one function and the C reports
  whichever name it finds first;
- `n-resolve` reports whether every address of `localhost` is `127.0.0.1`,
  not the list, whose length depends on the machine's `/etc/hosts`;
- `n-sleep` reports the type of `connect_waiting`, not its value, which
  depends on `n-many` running at the same time.

## M6.4e — `--script` on the command line

`oracle/gen_m64_cli.py` compares two whole programs: nmap, which writes the
golden, and `nmap-rs`, in `--check` mode. Each runs with `--datadir` set to
one scratch data directory, holding:
- this tree's data files and `nselib/`;
- in `scripts/`, the fixtures of `nse_scripts/`, `nse_net/` and `nse_cli/`,
  and the shipped `http-title` and `http-headers`;
- a `script.db` listing them all.

The services are those of the other two generators. Each scenario is one
command line with `-oN` and `-oX`, and the same Python parses both programs'
files, so the comparison cannot disagree with itself:
- **Normal output:** each script result's lines go into their block: `pre`,
  `host`, `post`, `port:PROTO/NUMBER`, or `port-table` for a `Bug in` line
  written before the table.
- **XML:** each `<script>` element, re-serialised, and each port's state.
- **Errors:** the message after `NSE: failed to initialize the script
  engine:`.

Within a block, results are sorted by id (`nse-results-sorted-by-id`).
`crates/cli/tests/nse_cli_differential.rs` runs the check against the
built binary. It also has two tests with no oracle:
- the stall limit;
- that a `scripts/` in the working directory is never used.

## M6.6 — `nmapdb`, and how each shipped script loads

Two oracles, both nmap 7.94 with `--datadir` set to this repository
(`docs/M6.6-ANALYSIS.md` §3, step 0a).

**`nmapdb`.** `oracle/gen_m66_nmapdb.py` runs `oracle/m66_probe_nmapdb.nse`
as a prerule, `-sn` against 127.0.0.1. The probe calls the module's four
functions and writes one line per call:
- `mac2corp` on every prefix in `nmap-mac-prefixes` (52,085), at both ends
  of its range, and on 50,000 addresses from a fixed LCG, each as raw bytes
  and as hex in two spellings;
- `getservbyport` on every port of tcp, udp and sctp;
- 834 more: the module's shape, the counts, argument shapes and edges, and
  calls through `datafiles`.

Edge cases call through `pcall` directly, so 7.94's errors carry no position
and name the function `'nmapdb.getservbyport'`. The generator fails unless
the probe read this tree's data files, which differ from the installed ones:
the paths, the prefix and protocol counts, and the services per protocol.
`regen_m66_nmapdb.sh` runs it twice and requires byte-identical output.

Calls that abort or are undefined in 7.94 are never made (LESSONS #033):
- `getprotbynum(255)` (an assert);
- `getservbyport` with a protocol not in its unterminated option list;
- `mac2corp` reading a byte ≥ 0x80 as a hex digit (`isxdigit` of a
  negative `char`).

`m66_nmapdb_quarantine.txt` lists them with their ledger ids.

`nmapdb_differential` (step a) runs the same probe as a prerule through the
port's engine, with the same script arguments, over the same data files, its
output file kept in memory, and requires every line of the golden, line for
line; the two data files' paths are written as their names, as the generator
writes them. No line is excused: the port names the function as
`luaL_argerror` does for the call's shape, and raises with `luaL_where`'s
position, so the `pcall` rows and the `datafiles.lua:127:` rows match as they
stand. A second test runs every quarantined call and requires the answer its
ledger id pins: a constant for `getprotbynum(255)` (nil, and a third test
checks, without the port's parser, that the shipped `nmap-protocols` has no
line for 255), a clean `invalid option` error for an unknown protocol, and
`Expected a 6-byte MAC address` for a high byte. The probe is shared by
oracle and port, so the golden must also hold a floor of rows of each kind
(`MIN_ROWS`): a probe weakened and regenerated in place fails there.
`M66_NMAPDB_GOLDEN` names a live golden.

The engine-level tests hand the engine a data-file reader of their own; the
CLI's (`data_file_at`, which also refuses FIFOs, devices and files over
64 MiB) is gated end to end by `crates/cli/tests/nmapdb_cli.rs`, which runs
`nmap-rs --datadir` over this repository with a prerule that calls all four
functions.

**Script loads.** nmap cannot load a script without its C modules, so
`oracle/gen_m66_scriptload.py` emulates it. The scratch data directory
links this tree's data files, `nselib/` and `scripts/`, and holds a copy of
`nse_main.lua` with one line added before `local REQUIRE_ERROR = {};`. That
line removes the missing modules from `package.loaded` and `_G`, and
`lpeg-utility` with `lpeg`, since `nse_main.lua:150-151` preloads both.
Each script is then loaded alone, with `-v --script-help`, and ends one of
three ways:
- `OK`;
- `LOUD`: a hard `require` failed and nmap quit. The detail is the first
  `file:line: module 'X' not found`, the path cut to the file's name;
- `QUIET`: a `silent_require` failed and the script was dropped.

The header's `missing:` line is the set removed. It is the generator's
`PORT_MISSING` unless `--missing` says otherwise, and that is the port's set:
`openssl`, `lpeg`, `lfs`, `libssh2` and `zlib` (`nmapdb` left it in step a).

`scriptload_differential` loads each script the way the command line does:
chosen by its path, in a fresh state at `-v`, through
`NseState::load_chosen`. It requires the same outcome and detail for every
script, with no pins. It also checks that the port lacks exactly the
golden's missing set. So porting a module fails the gate until the module
leaves `PORT_MISSING` and the golden is regenerated:

```sh
./regen_m66_scriptload.sh            # regenerate in place
./regen_m66_scriptload.sh --check    # what CI runs: the committed golden is the live one
```

`--check` compares the whole file, the `# missing:` header included, so a
golden regenerated with another missing set fails CI even when the test job,
which reads the committed copy, would pass. A unit test in `nse/runtime.rs`
(`the_registered_c_modules_are_exactly_the_ported_ones`) lists the C modules
the port registers, exactly, so porting or stubbing one means editing that
list as well as `PORT_MISSING`.

Measured with this generator: with every module missing, 7.94 gives
514 / 51 / 46; once `nmapdb` leaves the set, 531 / 33 / 47 (the committed
golden since step a, which the port matches with no pins); and once `lpeg`
leaves it too, 560 / 2 / 49, as `docs/M6.6-ANALYSIS.md` §0 predicts.

**The `unknown` service name** (step a) is gated with the M6.4c2 scripts:
the `service-names` scenario of `m64_scripts_golden.txt` runs the fixture
`s-service.nse` over 1/tcp, 4/tcp (which `nmap-services` names `unknown`)
and an open port, and 7.94 and the port both see no name for 4/tcp
(`nmaplib-unknown-service-name`). Since the M6.6 review the fixture then calls
`nmap.set_port_version(host, port, "incomplete")` on 1/tcp and 4/tcp, and both
see the table's fallback: `tcpmux`, and no name for 4/tcp, `dtype=table`,
conf 3.

**Sabotage checks.** To show a gate catches a defect, break the code, run the
gate, and restore the file from a byte copy, never with `git checkout` (which
discards uncommitted work, `porting-kit/LESSONS.md` #038). The restore must
also change the file's mtime — `cp` without `-p`, `shutil.copy` rather than
`copy2`, or a `touch` afterwards — because cargo decides what to rebuild by
mtime: a restore that brings back the file's original, older timestamp leaves
the build made from the sabotaged file looking up to date, and the next run
tests that stale, still-sabotaged binary (the M6.6 review's first S25 run did
exactly that).

## M6.6 step 0b — the LPeg oracle

The corpus every LPeg step (b to e) is gated on (`docs/M6.6-ANALYSIS.md` §3,
§11 row 0b). It holds 62,599 rows of LPeg 0.12 (`lpeg.c`), `nselib/re.lua` and
`nselib/lpeg-utility.lua`, from one seeded generator, and two oracles run the
same case runner over them:

- **the spec:** this tree's `liblua/` plus `lpeg.c` (`oracle/build_lua_oracle.sh`,
  M6.5 D1(c)), through `oracle/m66_lpeg_driver.lua`;
- **nmap 7.94:** a prerule probe, `oracle/m66_lpeg_probe.nse`, with
  `--datadir` set to this tree, so `re` and `lpeg-utility` are this tree's.

```sh
./regen_m66_lpeg.sh               # regenerate cases, golden and step map; check 7.94 (needs nmap)
./regen_m66_lpeg.sh --check       # CI, beside regen_m62.sh: two runs agree, files are current
./regen_m66_lpeg.sh --check-794   # CI, differential job: 7.94 drifts only in named classes
python3 oracle/gen_m66_lpeg_cases.py --self-test
```

| file | what it is |
|---|---|
| `oracle/gen_m66_lpeg_cases.py` | the generator: seed 1, families A–K, Q, R and X; `--self-test` checks its infix translator, its determinism and its lint |
| `oracle/m66_lpeg_core.lua` | the case runner both oracles load, under one chunk name: the wrappers, the rendering, and the census mode |
| `oracle/m66_lpeg_driver.lua`, `oracle/m66_lpeg_probe.nse` | the standalone driver and the 7.94 probe |
| `oracle/classify_m66_lpeg.py` | reads, canonicalises and compares outputs; names each difference's class; maps rows to steps |
| `oracle/gen_m66_lpeg.py` | what `regen_m66_lpeg.sh` runs |
| `oracle/screen_m66_lpeg.py` | the sanitizer screen, **local only** |
| `m66_lpeg_cases.txt` | `id<TAB>tags<TAB>chunk`, 8.1 MB |
| `m66_lpeg_golden.txt` | `id<TAB>status<TAB>values<TAB>log`, 1.8 MB |
| `m66_lpeg_steps.txt` | `id<TAB>step<TAB>census flags`, 1.2 MB |
| `m66_lpeg_quarantine.txt` | `id<TAB>reason<TAB>chunk`, 164 rows, input to the regeneration |

**Every LPeg call is a direct `pcall` (E6).** In a case's environment `P`, `S`,
`R`, `V`, `B`, `C`, `Cc`, `Cmt`, `Cb`, `Carg`, `Cp`, `Cs`, `Ct`, `Cf`, `Cg`,
`locale`, `match`, `setmaxstack`, `version`, `ptree`, `pcode` and `ltype` are
wrappers that call the C function as `pcall(lpeg.f, ...)`. The operators are
the metatable's own functions, the same way: `mul`, `add`, `sub`, `div`,
`pow`, `unm`, `len`, and `mcall(p, "match", ...)` for a method. `re.*` and
`U.*` (lpeg-utility) are wrapped too. So `luaL_where(L, 1)` names `pcall`,
a C function, and no message carries `chunk:N:`. `luaL_argerror` names the
function as the C finds it: `lpeg.P` through `package.loaded`, `?` for a
metamethod. A failure is re-raised as a marker object and reported as `err`.
`xerr` would mean an error that passed through no wrapper; the corpus has
none. The generator writes the operator rows in ordinary infix Lua and
translates them (`T()`), and its lint refuses a chunk that calls the raw
`lpeg` module.

**Rendering.** Values are typed: `i3`, `f2.5`, `s"..."`, `true`, `nil`, and
tables with their keys sorted. A pattern renders as `<pattern>`. No table,
userdata or function is ever passed to `tostring`, because addresses differ
from run to run. Bytes outside printable ASCII, and `"` and `\`, are written
`\xHH`. A string over 512 bytes, or a table over 4 KiB rendered, becomes its
length and an FNV-1a digest. The fourth column logs the deterministic
callbacks (`Fcat`, `Mkeep`, `K`, `IDXF`, ...) in the order LPeg called them.
Paths are cut to the file name: `.../nselib/re.lua:270:` becomes
`re.lua:270:`, and a position inside the runner loses its line.

**Families** (rows in the golden; quarantined rows excluded):

| family | what | rows | `ok` | `err` | quarantined | step b | step c | step d |
|---|---|---|---|---|---|---|---|---|
| A | constructors | 595 | 402 | 193 | 4 | 213 | 380 | 2 |
| B | operators | 2,264 | 1,236 | 1,028 | 0 | 1,031 | 1,071 | 162 |
| C | captures, every kind | 764 | 631 | 133 | 12 | 44 | 336 | 384 |
| D | grammars and their errors | 700 | 195 | 505 | 0 | 523 | 165 | 12 |
| E | `match` arguments | 74 | 57 | 17 | 2 | 0 | 72 | 2 |
| F | `p / string`, `/ number`, `/ table`, `/ function` | 501 | 384 | 117 | 4 | 30 | 340 | 131 |
| G | `setmaxstack` | 269 | 127 | 142 | 0 | 40 | 229 | 0 |
| H | Lua-stack and C-stack limits | 33 | 33 | 0 | 8 | 0 | 16 | 17 |
| I | `locale` | 18 | 16 | 2 | 0 | 7 | 11 | 0 |
| J | `re`: corpus grammars, features, errors | 980 | 859 | 121 | 0 | 0 | 0 | 980 |
| K | lpeg-utility | 33 | 29 | 4 | 0 | 0 | 0 | 33 |
| Q | random `re` strings | 6,000 | 5,166 | 834 | 0 | 0 | 0 | 6,000 |
| R | random pattern trees | 49,880 | 37,321 | 12,559 | 120 | 10,657 | 21,839 | 17,384 |
| X | fixed rows | 488 | 282 | 206 | 14 | 96 | 267 | 125 |
| all | | 62,599 | 46,738 | 15,861 | 164 | 12,641 | 24,726 | 25,232 |

No row is `xerr` or `loaderr`. The generator writes 62,763 rows; 164 are
quarantined.

Family X holds the fixed rows the plan asks for (§11 row 0b, §5):
- `Cb` with two differently named groups (S14);
- `Cc('k') * Carg(2)` after a ktable join (S16). `correctkeys` runs only when
  both sides have a ktable, so the right side carries a constant of its own:
  `Cc("k") * (Carg(2) * Cc("j"))`;
- dynamic captures discarded on backtrack at n = 10^6, in a table and in a
  substitution (S08);
- `Cmt` returning integers, integral and non-integral floats, numeric strings,
  `"0x3"`, `"3e0"`, tables, `true` with values, nothing, backward and
  past-the-end positions, and error values (S06, S07);
- `MAXSTRCAPS` at 8–12 nested captures (S10);
- the backtrack ceiling at the boundary depth for 19 `setmaxstack` values
  plus the floor (S04, S05, S12);
- the §5 edges: a trailing `%`, `%N` in pre-order, group names as strings,
  grammar keys `'1'` and `'1.0'`, table queries giving `false`, nil and NaN,
  `/table` through `__index` (S09), `initposition` 0 and `-0.0`, 32-bit
  narrowing, the identity constructors through `rawequal`, `ptree`/`pcode`
  argument processing, `setmaxstack` details, `locale(t)` writing through
  `__newindex` in class order, `Cf`, and error objects;
- a grammar table's `__index`, which `getfirstrule` reads the initial rule
  through (`lpeg.c:2932`), the one place construction calls Lua;
- each message LPeg raises;
- `__name` in type errors;
- the 16-bit truncations on both sides of their thresholds. The row below the
  runtime-capture threshold first fills and drops 4n ordinary captures, so
  the C never grows its capture list from the runtime-capture path, where
  `doublecap` over-reads (`lpeg-doublecap-stack-overread`).

**Classes** (`oracle/classify_m66_lpeg.py`). A row that differs between two
outputs gets the smallest set of normalisations under which it agrees:
- **`hashorder`:** the rule name in LPeg's four grammar errors follows table
  iteration order, which Lua salts per process. It is masked to `'?'`, and the
  golden is stored masked. `initial rule 'X' is not a pattern` is not masked:
  that name is the grammar's first field, so it is deterministic.
- **`path`:** an nselib path.
- **`position`:** a `name:N:` prefix (`stdlib-errors-have-no-position`).
- **`argname`:** the name in `bad argument #N to 'NAME'`
  (`stdlib-bad-argument-naming`).

Three classes come from the row, not its text:
- **`cdepth`:** rows tagged `cdepth` in the cases file. Their answer is the
  embedding's depth: the C-call depth of re-entry, or the Lua-stack ceiling
  on captures. Only rows near a ceiling are tagged.
- **`drift794`:** rows where 7.94 answers differently from every standalone
  Lua measured. Only the 7.94 agreement check accepts the class; a port gate
  holds these rows to the golden.
- **`quarantine`:** rows in the quarantine list.

Anything else is `other`, and nothing accepts it. Each regeneration runs the
standalone oracle twice. A row that differs between the runs outside
`hashorder` fails the regeneration, and so does a row 7.94 gives differently
outside the named classes.

**What the classes cover, measured.** The C-call ceiling on re-entry is 195 in
the standalone oracle and 194 in 7.94. Rows below 190 give the same answer
under standalone Lua 5.4.4, 5.4.6 and 5.4.8 and under 7.94, so only
`H.reenter.190` and deeper are `cdepth`. 7.94's `gsub` re-enters 195 deep in
the same probe, so the pin relative to `gsub` (`H.reenter.rel`) is 0 under
every standalone Lua and -1 under 7.94. It is `drift794`: the port is held to
0. Why 7.94's LPeg re-entry costs one C level more than its `gsub` is
**unverified**; it is not the Lua version. The Lua-stack ceiling on captures is 999,934 standalone and
999,945 under 7.94, so the probe has 11 more free slots (measured; that
fewer frames lie below its call is [INFERRED]).
Relative to `table.unpack`'s ceiling in the same frame, it is -5 in both, so
`H.stackcaps.rel` is an untagged pin. The ceiling for dynamic captures (two
slots each) is not relative-pinned, because the 11-slot difference is odd.

**Steps** (`m66_lpeg_steps.txt`). The map is measured, not guessed from the
row's text. A census run (`oracle/m66_lpeg_core.lua`, census mode) puts a
debug hook on every call and return, and records four things per row:
- whether `lpeg.match` ran, directly, as a method, or from `re` or
  lpeg-utility;
- whether any pattern given to `match` contains a capture that calls Lua.
  Taint flows from every constructor's and operator's arguments to its
  result. `Cmt`, `P(function)`, `p / function`, `Cf` and `p / table` taint;
  a grammar is tainted by its rules; `Cc`'s constants never taint;
- whether `lpeg.locale` got a table;
- whether code from `re.lua` or `lpeg-utility.lua` ran.

It also records which LPeg function, if any, called a Lua function: `match`
(a capture), or another (`locale`'s `__newindex`, a grammar's `__index`).

From these:
- **b:** the row never calls `match` and runs no `re`/lpeg-utility code (the
  plan runs those libraries from step d). A constructor may call Lua, through
  a grammar's `__index` or `locale(t)`'s `__newindex`: step b implements both;
- **c:** every pattern it matches is free of Lua-calling captures, `match`
  itself calls no Lua, and it runs no `re`/lpeg-utility code;
- **d:** everything else.

Steps d and e run every row. A row mapped to c in which `match` did call Lua
fails the regeneration, which keeps the taint tracking honest.

So step b can run 12,641 rows, step c 37,367 (step b's and its own 24,726),
and steps d and e all 62,599.

**The quarantine.** `oracle/screen_m66_lpeg.py` runs every generated row
through four harnesses, resuming after each row that kills one:
- the standalone oracle;
- the same in census mode (its hook moves the heap);
- an ASan/UBSan build with `-fno-sanitize-recover` and `LUA_USE_APICHECK`,
  so the first report, or a push past the stack space a C function was given
  or checked for, ends the process;
- 7.94.

It then repeats uninterrupted passes, as CI runs them, until one is clean. A
row that crashes, trips a sanitizer or hangs anywhere is quarantined. So is a
row the generator tags `q=LEDGERID`, without being run: the C is undefined or
knowingly wrong there (the 16-bit truncations, D4), or the row would allocate
gigabytes. The reason names each harness, and the ledger id where the
report's first `lpeg.c` frame falls in a §7 defect.

The screen needs an ASan build and about six minutes, so CI does not
run it. The list's header records the SHA-256 of the corpus it screened, and
`gen_m66_lpeg.py` refuses any other corpus. Changing the generator therefore
means re-running the screen locally. Quarantined rows never reach an oracle
in CI or a golden, and each needs a port pin with the semantic answer by step
e (§11).

| ledger id (§7) | rows |
|---|---|
| `lpeg-cc-nil-without-ktable` | 105 |
| `lpeg-codegen-jump-out-of-code` | 33 |
| `lpeg-doublecap-stack-overread` | 6 |
| `lpeg-tree-size-int-overflow` | 5 |
| `lpeg-nested-capture-lua-stack-overflow` | 5 |
| `lpeg-initposition-negation-overflow` | 4 |
| `lpeg-ktable-key-16bit` | 2 |
| `lpeg-runtime-capture-index-16bit` | 1 |
| `lpeg-getfirst-unbounded-recursion` | 1 |
| `lpeg-pattern-string-size-overflow` | 1 |
| `lpeg-code-freed-during-match` | 1 |

18 rows are tagged by the generator. Of the 146 found, the standalone oracle
crashes on 115, the census run on 114, 7.94 on 114, and the sanitizer build
flags all 146. Every crash in the other three harnesses is also a sanitizer
report. Every report's first `lpeg.c` frame falls in a §7 defect, so every
quarantined row carries a ledger id.

Two of the defects shaped the corpus:
- **`lpeg-nested-capture-lua-stack-overflow`.** Nested captures 40 to 299
  deep push past the stack space LPeg checked for, but still inside the Lua
  stack's allocation, so ASan alone stays silent. A screen without
  `LUA_USE_APICHECK` let `H.nestC.299` through, and the uninterrupted census
  pass then crashed on it. `H.nestC.10` and `H.nestC.16` stay in the golden.
- **`lpeg-doublecap-stack-overread`.** `Cmt(1, f)^0` with one value per call
  steps the capture count by three past the 32-entry stack array, so the C
  grows the array from the runtime-capture path and over-reads it. That is
  why `X.rtcap.30000` fills the capture list with ordinary captures first.

**For the port's gates (steps b–e).** Run `oracle/m66_lpeg_core.lua`
unchanged in the port's VM, with the port's `lpeg` and this tree's `re.lua`
and `lpeg-utility.lua`, over the rows the step can run
(`m66_lpeg_steps.txt`). Then compare the output with the golden:

```sh
python3 oracle/classify_m66_lpeg.py compare m66_lpeg_golden.txt PORT_OUTPUT \
  --cases m66_lpeg_cases.txt --quarantine m66_lpeg_quarantine.txt --allow CLASSES
```

A Rust harness can parse the same four-column format. Each class a step
accepts must be ledgered (`position` and `argname` already are). Each
quarantined row needs a unit-test pin by step e.

**Agreement with 7.94** (`--check-794`): the committed golden is what 7.94
gives on 62,591 of 62,599 rows (99.987%) once the rule names are masked. Of the 8 drift rows, 7 are
`cdepth` (`H.reenter.195` to `.200` and `H.reenter.250`) and 1 is `drift794` (`H.reenter.rel`).

Raw against a standalone run (`./regen_m66_lpeg.sh`), 62,584 rows agree
(99.976%), with `cdepth` 7, `drift794` 1 and `hashorder` 7. The `hashorder` count moves
from run to run: two standalone runs differed on 0 to 27 rows in this step's
measurements. 2,504 rows of 7.94's output carry a masked rule name. No row drifts
by `path`, `position` or `argname`.

**What the corpus catches.** The 16 sabotaged `lpeg.c` builds of the M6.6
sequencing review were rebuilt from patched copies of `lpeg.c` (the tree's
file is never edited); `lpeg_sabotage/run_sabotage.sh` rebuilds and re-runs
them (local only, see its README). Each ran the committed cases,
resuming after crashes, against the committed golden:

| variant | rows differing | of them, fixed rows (not R or Q) | crashed or hung | fixed rows that catch it (family X first) |
|---|---|---|---|---|
| S00 unpatched | 0 | 0 | 0 | — |
| S01 `C` pushes the whole match last | 126 | 12 | 0 | `X.group.15` |
| S02 `Ct` multi-value order reversed | 38 | 17 | 0 | `X.dyncap.bt.small`, `X.group.24` |
| S03 `Cf` arguments swapped | 3,385 | 475 | 0 | `X.fold.3`, `X.fold.5`, `X.fold.6`, `X.fold.7` |
| S04 backtrack limit removed | 215 | 215 | 0 | 66 X rows, e.g. `X.limit.100.50`, `X.narrow.sms.1.500` |
| S05 backtrack limit + 1 | 11 | 11 | 0 | 10 X rows: `X.limit.101.50`, `.103.51`, `.151.75`, `.199.99`, `.201.100`, ... |
| S06 `Cmt` accepts backward positions | 156 | 45 | 1 (a hang) | 30 X rows, e.g. `X.cmt.res.back.0` |
| S07 `Cmt` accepts 3.5 | 15 | 15 | 0 | 10 X rows: `X.cmt.res.h0.*`, `.h1.*`, `.str25.*`, `.f35.*`, `.f45.*` |
| S08 dynamic captures kept on backtrack | 2 | 2 | 0 | `X.dyncap.bt.1000000`, `X.dyncap.bt.cs.1000000` |
| S09 `/table` through `rawget` | 19 | 19 | 0 | 7 X rows: `X.query.4` to `.8`, `.10`, `.11` |
| S10 `MAXSTRCAPS` 9 | 22 | 22 | 0 | 21 X rows, e.g. `X.maxstrcaps.9.0`, `X.maxstrcaps.nested.9` |
| S11 `codechoice` off | 19 | 8 | 10 | `G.none`, `G.choice.101`, `J.nest.paren.16`, ... (the crashing rows, such as `B.bin.343`, move with the memory layout) |
| S12 `INITBACK` 32 | 25 | 25 | 0 | 6 X rows: `X.limit.5.49`, `.50.49`, `.99.49`, `.nil.49`, `X.narrow.sms.1.49`, `.2.49` |
| S13 `init` past the end cropped to len−1 | 245 | 28 | 0 | `X.init.8.0`, `.9.0`, `.10.0`, `.14.0` |
| S14 `Cb` ignores the group name | 24 | 17 | 0 | 9 X rows: `X.cb.names.0` to `.6`, `.8`, `X.group.7` |
| S15 a named group keeps its last value | 17 | 14 | 0 | `X.group.21`, `X.query.6`, `X.query.12` |
| S16 `correctkeys` shifts `Carg` | 3,358 | 211 | 0 | 6 X rows: `X.carg.join.8`, `.10`–`.13`, `.15` |

The 22 rows then tagged `cdepth` are left out of the count, because another
build of the same sources may answer differently there (step 0b's review
narrowed the tag: 17 rows are `cdepth` now and 1 is `drift794`). The unpatched build does differ on
one of them, `H.stackcaps.999925`. A row that killed or hung a variant counts
as caught; S06 loops forever on `R.6687`, which was stopped after 90 s.

Every variant differs on at least one row. The six the plan singles out are
each caught by a fixed row of family X, not only by random rows: S05, S07,
S08, S09, S10 and S14.

**Adversarial time.** `lpeg_search/run_search.sh` (local only, see its
README) searches for subjects that make each of the 11 network-facing
patterns do the most LPeg work per byte: `json.parse`, the coap link format,
lpeg-utility's `get_response`, `parse_fp` and `escaped_quote`, ntp-info's
`kvmatch`, fingerprint-strings, and http-affiliate-id's four `re` grammars.
Every one is linear in subject size up to 64 KiB. Step e sets each pattern's
regression ceiling from it. Its step counter cannot see work inside a span
instruction; the README says what that misses.

## M6.6 step c — matching, against the corpus and the C

Step c ports `lpeg.match` with every capture that calls no Lua. Its gates
read the step 0b files above and three more of their own.

**The corpus at step c.** `crates/core/tests/lpeg_corpus_differential.rs`
takes its step from one constant, now `'c'`: it runs the 37,367 rows
`m66_lpeg_steps.txt` gives steps b and c through `oracle/m66_lpeg_core.lua`
in the port's VM and compares them with the golden. A row that differs passes
only under a named class, each ledgered: `argname` (2 rows), `vmbase` (2) and
`cdepth` (1, `H.stackcaps.999950`: the absolute capture ceiling is the
embedding's, `lpeg-capture-ceiling-is-the-embeddings`). `cdepth` accepts only
rows the cases file tags `cdepth`, and only when their status and log are the
golden's. `H.stackcaps.rel`, the ceiling relative to `table.unpack`'s, is
held to the golden's -5.

**The quarantine's pins.** No golden records a quarantined row (LESSONS
#033), so each gets a pin of its own in `m66c_quarantine_pins.txt`
(`id<TAB>step<TAB>source<TAB>status<TAB>values<TAB>log`), which
`every_quarantined_step_row_matches_its_pin` runs at or below its step:

```sh
python3 oracle/gen_m66c_quarantine_pins.py          # rewrite the pins (local only)
python3 oracle/gen_m66c_quarantine_pins.py --check  # FAIL if stale
```

- `fixed-c`: the answer of this tree's `lpeg.c` with the two defects fixed
  that the port fixes, built from a patched copy (`lpeg_search/
  build_patched_lua.sh`; the tree's file is never edited): the peephole keeps
  its rewrite of a jump and goes on after it, without the `i--` re-scan
  (`lpeg-codegen-jump-out-of-code`), and `Cconst` pushes nil for key 0
  (`lpeg-cc-nil-without-ktable`). Rows of those ids and of
  `lpeg-initposition-negation-overflow` take this source, each run alone, its
  step from the same census rule `classify_m66_lpeg.py` applies;
- `semantic`: a correct LPeg's answer where that build still fails, written in
  the generator with its reason (16-bit constant keys; nested captures past
  the stack space LPeg checked for).

149 rows: 112 `fixed-c` and 7 `semantic` at step c, 30 `fixed-c` at step d.
The other quarantined rows (`lpeg-doublecap-stack-overread`,
`lpeg-code-freed-during-match`, `lpeg-runtime-capture-index-16bit`, and
construction rows step b's tests pin) are step d's or not `match` rows.

**Left calls through `B`.** `oracle/m66c_behind.lua` holds the step b
review's 334 grammars in six uses each (`P(g)`, `"q" + P(g)`, `P(g) * "z"`,
`P(g) + "q"`, `-P(g)`, `P(g)^-1`), matched on four subjects.
`oracle/gen_m66c_behind.py` (local only, the same patched build) runs each
case in its own process and writes `m66c_behind_golden.txt`: the answer, or
`CRASH` where the C's `getfirst` recursed until the process died, or `HANG`
where it ran on for 3 s. Of 2,004 cases: 537 answers, 1,451 crashes, 16
hangs. `left_calls_through_behind_compile_where_the_c_does` holds the port to
every answer, to "rule '…' may be left recursive" at every crash, and to
running on (pre-emptibly) where the C ran on; a grammar step b's second
verifier pass refuses at construction counts only where the C crashed or ran
on (60 cases).

```sh
python3 oracle/gen_m66c_behind.py           # rewrite the golden (local only)
python3 oracle/gen_m66c_behind.py --check   # FAIL if stale
```

**Quirks.** `crates/core/tests/lpeg_match_quirks.rs` holds 174 chunks, each
with the tree's oracle's answer through the same serialiser: the compiler's,
the machine's and the captures' observable quirks (the step's brief §5), and
four out-of-order substitutions (`lpeg-subst-negative-length`). `Q01a` and
`Q01b` (H07, H06) carry the patched build's answer.

**Fuzzing.** `fuzz/fuzz_targets/nse_lpeg_match.rs` builds a pattern from the
input, compiles, matches and evaluates it in one slice and in slices of 1 to
64 units, and checks both against a direct PEG interpreter of the tree with
LPeg's capture placement, evaluated by a transliteration of `lpcap.c`.
Seeds: `fuzz/seeds/nse_lpeg_match/`, one per capture kind and error.
