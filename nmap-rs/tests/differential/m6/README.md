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
