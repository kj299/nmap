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
| `m60_semantics_*` | VM semantics (M6.0), table borders (patch 0013) | `regen_m60.sh` | `lua_semantics_differential` | 133 (17 pinned) |
| `m60_arith_*`, `m60_coerce_*` | modulo and shifts; string-to-number coercion | `regen_m60.sh` | `lua_semantics_differential` | 2,955; 1,975 |
| `m60_floatfmt_*` | float formatting | `regen_m60.sh` | `lua_float_format_differential` | 7,917 |
| `m6_strpack_*` | `string.pack` / `unpack` / `packsize` | `regen_m6_strpack.sh` | `strpack_differential` | 4,804 |
| `m6_pattern_*` | `string.find` / `match` / `gmatch` / `gsub` | `regen_m6_pattern.sh` | `pattern_differential` | 11,408 |
| `m6_format_*` | `string.format` | `regen_m6_format.sh` | `format_differential` | 6,037 |
| `m6_tail_*` | the base library (`pcall`, `xpcall`, `rawequal`/`rawlen`/`rawget`/`rawset`, `next`/`pairs`/`ipairs`, `select`, `type`, `tostring`, `tonumber`, `getmetatable`/`setmetatable`, `collectgarbage`, `assert`, `error`, `warn`, `load`, `_G`), the coroutine library, `string.rep`, `string.char`, the string metatable's arithmetic, `table.insert`/`remove`/`concat`'s checks | `regen_m6_tail.sh` | `tail_differential` | 2,742 |
| `m63_args_*` | `--script-args` (M6.3) | `regen_m63.sh` | `scriptargs_differential` | 20,517 |
| `m63_nmap_golden.txt` | the `nmap` module's non-I/O half, vs nmap 7.94 | `oracle/gen_m63_nmap.py` (live in CI) | `nmaplib_differential` | 10 scenarios (9 without IPv6 loopback, as in the committed golden) |
| `m64_errors_*` | VM runtime errors, numeric `for` (M6.4a) | `regen_m64_errors.sh` | `errors_differential` | 12,438 |
| `m64_limits_*` | C-call depth, stack, `MAXTAGLOOP` (M6.4b) | `regen_m64_limits.sh` | `limits_differential` | 335 |
| `m64_memory_*` | the memory budget, vs `ulimit -v` (M6.4b) | `regen_m64_memory.sh` | `memory_differential` | 41 |
| `m64_stdlib_*` | `utf8`, `os`, `io`, `debug` (M6.4c1) | `regen_m64_stdlib.sh` | `stdlib_differential` | 2,012 |
| `m64_nselib_golden.txt` | every `nselib/` library loads; unit-test suites pass, by their test counts (since M6.6 step e); `unittest.run_tests()` over every library fails as without the port's missing C modules, vs nmap 7.94 | `oracle/gen_m64_nselib.py` (live in CI) | `nselib_differential` | 133 + 26 (+ 26 counted without the missing modules) + 16 |
| `m64_scripts_golden.txt` | running scripts: rules, threads, runlevels, selection, output (M6.4c2), vs nmap 7.94 | `oracle/gen_m64_scripts.py` (live in CI) | `scripts_differential` | 37 scenarios |
| `m64_net_golden.txt` | sockets, timers, `resolve`, `mutex`, `condvar`, socket limits, shipped `http-*` scripts (M6.4d), vs nmap 7.94 | `oracle/gen_m64_net.py` (live in CI) | `nse_net_differential` (in `nmap-sys`) | 3 scenarios, 17 scripts |
| `m64_cli_golden.txt` | `nmap-rs --script` as a whole program: every phase's results and port states in normal and XML output, script arguments, timeouts, start-up errors (M6.4e), vs nmap 7.94 | `oracle/gen_m64_cli.py` (live in CI) | `nse_cli_differential` (in `nmap-cli`) | 15 scenarios |
| `m66_nmapdb_golden.txt`, `m66_nmapdb_quarantine.txt` | the C module `nmapdb` over this tree's data files (M6.6), vs nmap 7.94 | `regen_m66_nmapdb.sh`, `oracle/gen_m66_nmapdb.py` (live in CI) | `nmapdb_differential` | 115,064 lines; 36 calls quarantined, each pinned |
| `m66_scriptload_golden.txt` | how each shipped script loads, alone, without the C modules the port lacks (M6.6), vs nmap 7.94 | `regen_m66_scriptload.sh`, `oracle/gen_m66_scriptload.py` (live in CI) | `scriptload_differential` | 611 scripts: 560 OK, 2 LOUD, 49 QUIET (531 / 33 / 47 before step e) |
| `m66_lpeg_*`, `m66{c,d,e}_quarantine_pins.txt` | the C module `lpeg` (LPeg 0.12) with `re` and `lpeg-utility` (M6.6 step 0b), vs this tree's Lua + LPeg, and nmap 7.94 | `regen_m66_lpeg.sh` (`--check`; `--check-794` live in CI) | `lpeg_corpus_differential`: through the test-only registration, and since step e through the registered module, run by the port's engine under `oracle/m66_lpeg_probe.nse` | 62,599 rows; 164 quarantined, every one pinned |
| `m66b_tree_*` | LPeg pattern construction (M6.6 step b): every constructor and operator, the grammar builder and verifier, the metatable, vs this tree's Lua + LPeg built with `-fwrapv`, and a UBSan screen of every row | `regen_m66b_trees.sh` | `lpeg_tree_differential` | 5,710 rows (14 `[wrapv]`) |
| `m6_base_golden.txt` | the base and coroutine libraries as an NSE script meets them (`oracle/m6_base_probe.nse`): argument checks and results, coroutines inside a script's own, the collector as nmap starts it, `warn`'s output, vs nmap 7.94 | `regen_m6_base.sh`, `oracle/gen_m6_base.py` (live in CI) | `base_differential` | 67 rows + 5 warning lines; 7 pinned |
| `m66_exit_golden.txt` | M6.6's exit criterion (step e): what `-sC`, `--script default`, `--script version` and `-A` select, load and drop on `--datadir REPO`; the categories that still stop at start-up; address-info, riak-http-info, bitcoinrpc-info and http-affiliate-id run, vs nmap 7.94 | `regen_m66_exit.sh`, `oracle/gen_m66_exit.py` (live in CI) | `nse_exit_differential` (in `nmap-cli`) | 18 scenarios |
| `m65_cases.txt`, `m65_golden.txt`, `m65_drift.txt`, `m65_screen.txt`, `m65_census.txt`, `m65_sabotage.txt` (with `m65_algs.txt`, `m65_certs.txt`) | the C module `openssl` and `parse_ssl_certificate` (M6.5 step a): digests, HMAC, ciphers, bignums, randomness, argument checks and 3,638 certificates, vs nmap 7.94; this tree's C, built standalone, differs only in pinned drift rows | `regen_m65.sh` (`--check`; `--check-794` live in CI) | `openssl_bn_differential` (step b: the 11,170 `b` rows and `bnmeta`, all agreeing); `openssl_digest_differential` (step c: the 2,322 `c` rows, all agreeing, 740 pinned to `openssl-algorithm-subset`); `openssl_cipher_differential` (step d: the 12,949 `d` rows, all agreeing, 11,749 pinned, the `ivnul` drift rows held to `m65_drift_tree.txt`); `openssl_cert_differential` (step e: the 3,648 `e` rows, all agreeing, no exemption) | 30,094 rows; 1,690 `ub:` (no C run), 447 `nondet:`, 3,686 drift |
| `m65_tls_golden.txt` | nmap 7.94's TLS client on 61 fixture servers (M6.5 step a; the oracle side of step f1) | `regen_m65_tls.sh` (`--check` live in CI) | none yet: step f1 | 61 fixtures |

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

The vendored VM ships seven string functions, of which six are still its own
(`string.char` is first-party since the base-library port); the rest are
written first-party in `core::nse::stdlib`. Each is gated against `liblua/` (the table above). Every
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
three probe scripts (`oracle/m64_probe_require.nse`, `m64_probe_unittest.nse`,
and since M6.6 step e `m64_probe_unittest_all.nse`, also under an emulated
data directory, `unittest-emu`) as prerules, with `-sn` against 127.0.0.1, so nothing leaves the host. They
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
`openssl`, `lfs`, `libssh2` and `zlib` (`nmapdb` left it in step a, `lpeg` in
step e).

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
514 / 51 / 46; once `nmapdb` leaves the set, 531 / 33 / 47 (the golden from
step a); and once `lpeg` leaves it too, 560 / 2 / 49, as
`docs/M6.6-ANALYSIS.md` §0 predicts: the committed golden since step e, which
the port matches with no pins. The 2 are http-fetch (`lfs`) and
http-vuln-cve2014-3704 (`openssl`).

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
outside the named classes. Since the M6.6 retrospective the 7.94 check lists
its drift per row (`gen_m66_lpeg.py`'s `DRIFT_794`: the 7 `cdepth` rows and
the 1 `drift794` row, each with its class): a row not listed that drifts
fails, and so does a listed row that no longer drifts. `path`, `position`
and `argname` are listed for no row there; `hashorder`, the golden's own
mask, is the only class any row may take.

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
`screened-sources-sha256`, one digest over what the verdict rests on besides
the corpus (`classify_m66_lpeg.SCREENED_SOURCES`: `lpeg.c`, `nse_lpeg.cc`
and `.h`, `nse_lua.h`, `liblua/*.[ch]`, the screen with its build flags,
`oracle/build_lua_oracle.sh`, the driver, the case runner and the 7.94
probe; since the M6.6 retrospective). `gen_m66_lpeg.py` refuses any other
corpus or sources. Changing the generator, the C or a recipe therefore means
re-running the screen locally (5 min 48 s at the retrospective). Quarantined rows never reach an oracle
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
crashes on 117, the census run on 112, 7.94 on 114, and the sanitizer build
flags all 146 (the retrospective's re-screen; the census and 7.94 counts move
by one or two between screens, as a crash depends on the binary's layout,
§1.2, while the quarantined set does not). Every crash in the other three harnesses is also a sanitizer
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
accepts must be ledgered, and scoped to the rows it was ledgered for
(`lpeg_corpus_differential`'s `SCOPED`, since the M6.6 retrospective). Each
quarantined row has a pin in a pin file (`m66{c,d,e}_quarantine_pins.txt`).

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
regression ceiling from it. Its step counter could not see work inside a span
instruction until step e, which counts each byte a span examines; the README
says what it still misses.

## M6.6 step c — matching, against the corpus and the C

Step c ports `lpeg.match` with every capture that calls no Lua. Its gates
read the step 0b files above and three more of their own.

**The corpus at step c.** `crates/core/tests/lpeg_corpus_differential.rs`
takes its step from one constant, `'c'` at step c and `'d'` since step d: it
runs the rows `m66_lpeg_steps.txt` gives that step and the earlier ones
(37,367 at step c; all 62,599 now) through `oracle/m66_lpeg_core.lua` in the
port's VM and compares them with the golden. A row that differs passes only
under a named class, each ledgered: at step c `argname` (2 rows), `vmbase`
(2, retired by the base-library port, #136) and `cdepth` (1,
`H.stackcaps.999950`: the absolute capture ceiling is the embedding's,
`lpeg-capture-ceiling-is-the-embeddings`). Since the M6.6 retrospective each
class is listed per row (`SCOPED`: `argname` 2, `method` 1, `cdepth` 7), a
differing row passes only under its own, and a listed row that stops
needing it fails too. `cdepth` accepts only
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

**Quirks.** `crates/core/tests/lpeg_match_quirks.rs` holds 188 chunks, each
with the tree's oracle's answer through the same serialiser: the compiler's,
the machine's and the captures' observable quirks (the step's brief §5), and
four out-of-order substitutions (`lpeg-subst-negative-length`). `Q01a` and
`Q01b` (H07, H06) carry the patched build's answer.

**Fuzzing.** `fuzz/fuzz_targets/nse_lpeg_match.rs` builds a pattern from the
input, compiles, matches and evaluates it in one slice and in slices of 1 to
64 units, and checks both against a direct PEG interpreter of the tree with
LPeg's capture placement, evaluated by a transliteration of `lpcap.c`.
Seeds: `fuzz/seeds/nse_lpeg_match/`, one per capture kind and error.

## M6.6 step e — `lpeg` registered, and the exit criterion

**The corpus through the registered module.** `lpeg_corpus_differential`'s
`every_row_through_the_registered_module_matches_the_trees_own_lpeg` runs
`oracle/m66_lpeg_probe.nse` — the prerule nmap 7.94 runs for
`regen_m66_lpeg.sh --check-794` — through the port's own engine, over
`m66_lpeg_cases.txt` and then `m66_lpeg_quarantine.txt`: every row compared
with the golden under the named classes only, every quarantined row with its
pin. `m66e_quarantine_pins.txt` pins the last 7 quarantined rows (written by
hand; its header says where each answer comes from), so every one of the 164
has a pin, which `every_quarantined_step_row_matches_its_pin` now requires.

**The exit criterion.** `oracle/gen_m66_exit.py` (docstring) runs nmap 7.94
and, with `--check`, `nmap-rs` over the same scenarios on this repository's
own data directory, parsed by one parser: the `-d2` selection and load lines
of `-sC`, `--script default`, `--script version` and `-A` (7.94's oracle for
`-A` is `-sC -sV`); the categories that stop at start-up without `lfs` or
`openssl`; and four scripts run against loopback listeners (8098, 8332,
8180). Its two tolerances, `OPENSSL_QUIET` and `SV_VERSION_ONLY`, are the
ledger entries `nse-sc-openssl-quiet-drops` and
`nse-sv-version-scripts-pending`, and generation fails if 7.94 disagrees with
either.

```sh
./regen_m66_exit.sh            # regenerate in place (needs nmap)
./regen_m66_exit.sh --check    # what CI runs: the committed golden is the live one
```

**Denial of service.** `nse_lpeg_dos/` holds the fixtures
`nse_exit_differential` runs at `--script-timeout 2`: an exponential grammar
built at load (`m66-expo-load.nse`, K = 36) and, in a prerule after
`m66-quick.nse` stored a result, one row per stage (`m66-expo-run.nse`,
`m66dos.stage=build|compile|match|capture`). nmap 7.94 hangs in each, in the
stage named; to see it:

```sh
timeout 60 nmap --datadir REPO -d -Pn -n -sT -p 1 --script-timeout 2 \
  --script nse_lpeg_dos/m66-quick.nse,nse_lpeg_dos/m66-expo-run.nse \
  --script-args m66dos.stage=match 127.0.0.1        # rc 124
```

**Adversarial slowness.** `lpeg_search/adversarial/` and
`crates/core/tests/lpeg_slowness_regression.rs`: see `lpeg_search/README.md`,
"The regression gate".

## M6.5 step a — the `openssl` corpus

The oracle for steps b–e (`docs/M6.5-ANALYSIS.md` §11 row a, D1): nmap 7.94's
`openssl` module and `parse_ssl_certificate`, over a seeded case matrix, with
this tree's C as the spec.

```sh
./regen_m65.sh               # regenerate everything in place (needs nmap; about a minute)
./regen_m65.sh --check       # CI build job: no nmap
./regen_m65.sh --check-794   # CI differential job: nmap 7.94 against the golden
python3 oracle/sabotage_m65.py   # local: the 34 C sabotage variants (about five minutes)
```

| file | what it is |
|---|---|
| `oracle/gen_m65_cases.py` | the case generator (seed `0x6D65`), a pure function of itself, `m65_algs.txt` and `m65_certs.txt`; its docstring lists the families and the tags |
| `m65_algs.txt` | the algorithm table, captured once (`--capture-algs`) from the oracle and libcrypto: 56 digests and 170 ciphers as `supported_*` list them, OpenSSL's aliases, and the key, IV and block length of every cipher name a case uses |
| `m65_certs.txt` | the certificate corpus, committed as data (its keys are random): Phase 0's 2,876 `x` rows (`oracle/gen_m65_certs.py`) and 144 BER rows (`b`) (`oracle/mkber_m65.py`, which reproduces them byte for byte); step e's 365 `k` rows (key types, curves, explicit parameters, Name values, extension framing, a tag-0 signature parameter, string nesting) and 253 `p` rows (every extension printer), written by `oracle/gen_m65_x509.py`, each row's note ending with its expected outcome |
| `oracle/gen_m65_x509.py` | step e's generator: deterministic DER built byte by byte; `--check` requires the `k` and `p` rows to be what it writes, `--check-golden` requires the golden to show every row as its note expects (for a printer row, the exact text, written from OpenSSL 3.0.13's printers by hand) |
| `m65_cases.txt` | 30,094 rows, `ID TAGS OP SUB ARG...` |
| `oracle/m65_core.lua` | the one case runner: 7.94 loads it through `oracle/m65_probe.nse`, the tree's C through `oracle/m65_driver.lua`, and the port through `runner{…, drain = false}` one row at a time (the shared harness `crates/core/tests/m65/`, which the `openssl_*_differential` gates use). Renders every value greppably (LESSONS #049) and drains the OpenSSL error queue after each case (the port has none: `q=-`) |
| `oracle/build_openssl_oracle.sh` | builds `oracle/lua-openssl`: this tree's `liblua/` with `nse_openssl.cc` and `nse_ssl_cert.cc` linked in, nmap's headers swapped for `oracle/openssl_oracle_shim.h` by anchored edits, nsock's SSL initialisation replayed (without it `supported_ciphers` is empty), and one named repair (below); `--variant asan` and `--sabotage NAME` build the variants |
| `m65_golden.txt` | 7.94's answer for every row, run twice, under a header pinning nmap, OpenSSL, `OPENSSL_CONF`, the legacy provider and the digests of the cases and certificates |
| `m65_drift.txt` | the 3,686 rows where this tree's C differs from 7.94, each with its §2 family: `year` 3,024 (validity years are `year - 1900` in the tree), `ivnul` 648 (an IV whose first byte is NUL is no IV to 7.94), `asn1time` 13, `state` 1 |
| `m65_screen.txt` | the sanitizer screen's record: every row under the tree's C built with `-fsanitize=address,undefined -fno-sanitize-recover=all -DLUA_USE_APICHECK`, no report, with the digests of what decided it |
| `m65_census.txt` | rows per exposed function and method; none is zero |
| `m65_sabotage.txt` | what each of the 34 C sabotage variants changed, and how many rows caught it |
| `oracle/xref_m65.py` | the independent references (below) |
| `m65_drift_tree.txt` | this tree's C's answer on each of the 3,686 drift rows (`gen_m65.py drift`, checked by `--check-tree`): what the port is held to where 7.94 differs by a §2 family (D1 (c)) |
| `m65_cipher_names.txt`, `oracle/gen_m65_cipher_names.py` | step d's cipher name table: 643 spellings (every cipher name, alias and lookup of `m65_algs.txt`, every name the corpus passes, case variants, OIDs, NULs, separators, near misses), each classified by what the tree's C encrypts under it as one of D4(b)'s ten ciphers, `other` or `unknown` |
| `m65_digest_names.txt`, `oracle/gen_m65_digest_names.py` | step c's digest name table: 399 spellings (every `supported_digests` name and alias, every name the corpus passes, case variants, OIDs padded and prefixed, NULs, separators changed), each classified by the tree's C's digest of "abc" against published vectors as one of D4(b)'s ten algorithms, `other` (accepted, outside D4: `openssl-algorithm-subset`) or `unknown`; `regen_m65.sh --check` regenerates it, and the port must resolve every row as recorded |

**Tags.** A row's tags name the step that gates it (`b` bignums, `c` digests,
HMAC and randomness, `d` ciphers, `e` certificates, `g` the module's shape),
then:
- `nondet:random` (70): the random functions, compared on shape (type,
  length, a bignum's sign). The bignum rows draw 64 times and report whether
  every draw fits in N bits and whether one is shorter, which pins
  `BN_rand`'s free top bit.
- `nondet:random-iv` (357): GCM and 3DES key wrap with no IV, or, to 7.94,
  an IV whose first byte is NUL. libcrypto draws the IV itself.
- `nondet:alias-name` (20): an argument error of `bignum_rand` or
  `bignum_pseudo_rand`. They are one C function under two names, and
  `luaL_argerror` names whichever its walk of `package.loaded` meets first.
  That order follows Lua's per-state hash seed (`lstate.c:71`), so it
  changes from run to run. The two names compare equal on these rows only.
- `ub:iv-length-uaf` (1,688): a non-empty IV of the wrong length. The C frees
  the cipher context and then reads it for the error message
  (`nse-openssl-iv-length-uaf`). It crashed 7.94 more than 1,000 times before
  the first run was stopped. No C runs these rows as written. The golden records status `ub` and
  the message the C means, `Length of iv is N; should be M`, from the
  oracle's one named repair: build_openssl_oracle.sh reads the length before
  the free. `gen_m65.py golden` refuses a golden unless the repaired C
  raises "Length of iv" on exactly the tagged rows.
- `ub:rc4-empty-key` (2): RC4 with a zero-length key. libcrypto's
  `RC4_set_key` reads 256 bytes past the key (`nse-openssl-rc4-empty-key`),
  so the output changes from run to run. The golden records `ub` with no
  value (ORACLE-CHECKS 5c); the Rust side covers the row.

**What each mode checks.** `golden` runs the tree's C first and checks the
`ub:` tags. It then runs 7.94 twice over every other row and refuses the
golden if an untagged row differs between the runs. `drift` refuses any
difference between the tree and 7.94 that no §2 family explains. `--check`
needs no nmap. It regenerates the cases and requires them byte for byte. It
checks the golden's digests and statuses, the drift and census files, and
the screen record against its inputs. It rebuilds the tree's C and requires
it to differ from the golden in exactly the pinned rows (`--check-tree`). It
runs the cross-check, and requires the sabotage record to name these cases.
`--check-794` refuses to compare on an environment other than the header's,
then requires 7.94 to agree with the golden on all 28,404 rows it runs.
It also checks the OpenSSL tables (`crates/vendor/openssl-data/gen.py
--check`) and step e's generated rows (`gen_m65_x509.py --check` and
`--check-golden`).

**Independent references** (`oracle/xref_m65.py`, part of `--check`). These
share no code with OpenSSL:
- Python ints, for add, div, mod_exp, the bit functions, primality and every
  bignum's five renderings;
- CPython's own hash modules (`_md5`, `_sha1`, `_sha256`, `_sha512`,
  `_sha3`, `_blake2`, not `hashlib`), with HMAC computed from them;
- nettle, through ctypes, for md4, ripemd160, sha512-224/256 and sm3.

They agree on every check they can compute: 16,376 bignum renderings, and
1,678 digest, 466 HMAC, 2,841 add, 2,502 div, 1,999 mod_exp, 1,767 bit and
1,092 primality rows. Only whirlpool has no reference. The C's deliberate behaviours are written in as the
expectation: `div` by 0 is (0, 0); `mod_exp` ignores the signs of p and m
and gives 0 for m = 0; positions are int32.

**What the screen cannot see.** ASan instruments the C that is built here,
not the system libcrypto it calls. The RC4 over-read happens inside
libcrypto, so the screen passed it. It surfaced as an untagged row whose
output changed between two 7.94 runs, which is what the two-run rule exists
to catch. The screen runs with `allocator_may_return_null=1`, so that
`rand_bytes(-1)`'s `malloc(SIZE_MAX)` returns NULL as glibc's does. The C
checks for NULL ("Couldn't allocate memory."); without the option, ASan
aborts on a request whose behaviour is defined.

**Sabotage** (ORACLE-CHECKS §4). The corpus catches all 34 variants:
`bn-div-swap` to `cert-bad-der-false`, with what each changes in
`oracle/sabotage_m65.py`. The first pass missed four:
- `bn-rand-top`: random rows were compared only by shape. This added the
  64-draw bound.
- `digest-short-msg`: no message was over 1,000 bytes. This added 4,099.
- `cert-utctime-pivot` and `cert-month`: these changed `time_to_tm`'s own
  parser, which is dead with OpenSSL 3 (`HAVE_OPAQUE_STRUCTS` uses
  `ASN1_TIME_to_tm`). They were replaced by mutations of the live path.

A variant that changed nothing observable on 3.0.13 (HMAC's unchecked length)
was replaced by one that does (`hmac-result-checked`). The plan's trimming
rule applies to every later change of the cases. The cipher grid was trimmed
(57,885 rows in all before, 29,476 now), and the trimmed corpus is what these
34 variants measured. The port
sabotage lists of steps b–e and f1–f2 run against this corpus as each step
lands.

## M6.5 step a — the TLS fixtures

The oracle side of step f1's gate (`docs/M6.5-ANALYSIS.md` §11 rows a and f1,
§14.1, §14.5). Step 0's spike ran 61 TLS fixtures against nmap 7.94 and
against its rustls client; step a commits the fixtures in `m65_tls/` and
records 7.94's result on each in `m65_tls_golden.txt`. Step f1 supplies the
other side: the port's client over the same servers, compared row by row,
with each divergence pinned and ledgered (the five step-0 entries of §14.1).

```sh
./regen_m65_tls.sh                  # regenerate in place (needs nmap, openssl; about a minute)
./regen_m65_tls.sh --check          # regenerate and FAIL if the committed golden differs
./regen_m65_tls.sh --check-header   # FAIL if this machine is not the pinned environment
python3 oracle/gen_m65_tls.py --check m65_tls_golden.txt --client CMD   # step f1: exits 2 today
```

| file | what it is |
|---|---|
| `oracle/gen_m65_tls.py` | the generator: the fixture table (`FIXTURES`, the rows and names of the spike's `run.py`), the servers, the parsing of what each saw, the header |
| `m65_tls/s0probe.nse` | the probe 7.94 runs: `connect(...,"ssl")` with a host table, an IP string or a name, or SMTP then `reconnect_ssl`; prints the leaf's SHA-256, length and CN, or the error |
| `m65_tls/fakesrv.py` | a TLS 1.2 server flight (ServerHello, Certificate, ServerKeyExchange, ServerHelloDone, suite `0xc02f`) with one thing mutated per mode, recording the client's next record |
| `m65_tls/starttls_smtp.py` | SMTP with STARTTLS, then TLS over Python's `ssl` (OpenSSL 3's `s_server` has no `-starttls`) |
| `m65_tls/silent.py` | accepts and never speaks |
| `m65_tls/certs/` | the certificates and keys, all throwaway and self-signed (`CN=m65-*`, `O=nmap-rs`, or `*.example.test`); two chains of 86 and 127 copies of `rsa2048.crt` (70,606 and 104,267 bytes of DER) |
| `m65_tls/clienthello_suites_794.txt` | the suites 7.94 offers, in its order (§5's `s_server -trace`), for f1's ClientHello |
| `m65_tls_golden.txt` | the golden: a header, then `FIXTURE<TAB>TAGS<TAB>RESULT<TAB>SERVER`, 61 rows |

The servers were copied from `spikes/m65-tls-provider/fixtures/`. The only
changes are in what they print:
- a connection that never reaches TLS prints a line starting `noise:`;
- `silent.py` holds each connection on its own thread.

**The fixtures.** Each server listens on 127.0.0.1, on port 47300 plus its row
number (47301–47361; no other M6 generator uses a 47xxx port). nmap 7.94 runs
`-Pn -sT -n -p PORT --datadir REPO --script m65_tls/s0probe.nse` once against
each:

| rows | what they test |
|---|---|
| `tls12-ecdhe-{rsa,ecdsa}-{aes128gcm,aes256gcm,chacha}`, `tls12-ecdsa-p{384,521}-cert`, `tls12-group-p{256,384,521}` | TLS 1.2 ECDHE with each AEAD suite rustls carries, RSA and ECDSA certificates, each curve forced |
| `tls12-sig-{pss-sha256,pss-sha512,pkcs1-sha256,pkcs1-sha384,pkcs1-sha1}` | each ServerKeyExchange signature scheme forced; SHA-1 is refused at 7.94's level |
| `tls13-{aes128-x25519,aes256-p256,chacha-p384,aes128-p521,x448,ffdhe2048}` | TLS 1.3 with each suite and group forced (a HelloRetryRequest where 7.94's first key share is not the group) |
| `tls13-ecdsa-p{256,384,521}`, `tls13-ed25519`, `tls13-sig-pss-sha384` | TLS 1.3 certificate types and a forced CertificateVerify scheme |
| `dual-tls12-clientpref`, `dual-tls12-serverpref`, `dual-tls13` | RSA and ECDSA certificates on one server: which leaf 7.94 gets |
| `starttls-legacy`, `starttls-modern` | SMTP STARTTLS then `reconnect_ssl`, with `AES128-SHA` and with ECDHE-RSA-AES128-GCM |
| `rsa512`, `rsa2048-md5cert`, `rsa-sha1-signed-cert`, `secp256k1-cert`, `dsa-dhe` | weak and odd certificates. `rsa2048-md5cert` was `rsa1024-md5cert` in Phase 0: the key is 2048-bit |
| `chain-over64k`, `chain-over100k`, `chain13-over64k` | chains past rustls's 65,535-byte handshake limit and past OpenSSL's 102,400-byte certificate list |
| `sni-ip-string`, `sni-name` | the server_name 7.94 sends for an IP string and for a name |
| `tls10-only`, `tls11-only`, `tls12-rsa-kx-gcm`, `tls12-ecdhe-cbc`, `tls12-dhe2048` | legacy reach, the `nse-tls-modern-only` pins |
| `fake-ok`, `fake-badsig`, `fake-trail`, `fake-garbage`, `fake-noreneg`, `fake-{ecdsa,ed25519}-cert-rsa-suite`, `fake-{x25519,dh,unknownoid}-cert` | the negative fixtures, TLS 1.2: in order, nothing mutated, one ServerKeyExchange signature bit flipped, a byte after the certificate inside its entry, an undecodable certificate, no `renegotiation_info`, and a certificate whose key does not match the suite or is a type TLS refuses |
| `bad13-control`, `bad13-corrupt-certverify` | TLS 1.3 with a valid and with a corrupt P-256 CertificateVerify |
| `silent-server`, `connection-refused` | a server that never speaks (7.94 at a 3 s timeout), and a closed port |

**The golden.** `RESULT` is the probe's line. It has three forms:
- `ok leaf=<sha256> len=<n> cn=<cn>`;
- `fail <socket error>`;
- `fail closed`, when the scan found nothing listening. The spike's
  `results.tsv` spells this `fail (no script result; port closed)`.

`SERVER` is what the fixture server saw of 7.94's connection, and only what is
the same on every run:
- **`s_server` rows:** parsed from `-trace` and stderr, keeping only the
  connections that sent a ClientHello (the connect scan sends none). The
  fields are:
  - `hello=` the number of ClientHellos;
  - `sni=` each one's server_name (`-` for none);
  - from the last ServerHello and the server's ServerKeyExchange or
    CertificateVerify: `version=`, `suite=`, `group=` and `sigalg=`;
  - `alerts=` the fatal alerts, sent or received;
  - `error=` the server's OpenSSL reason, without the thread id or the
    source line.
- **fake rows:** `client alert N` or `client ClientKeyExchange`.
- **STARTTLS rows:** `tls VERSION CIPHER`.
- **bad13 rows:** `handshake completed` or the alert the server received.

That gives f1 the version and suite to compare, not only reach, and the SNI
rows' `sni=127.0.0.1` and `sni=localhost`.

The generator does not connect to check that a server is up. It reads
`/proc/net/tcp`, because a probe connection is one more connection the
server would log.

What 7.94 does, against the spike's record:
- **43 `ok`, 16 `fail ERROR`, 1 `fail TIMEOUT`, 1 `fail closed`.** Every row
  equals `spikes/m65-tls-provider/fixtures/results/results.tsv`'s 7.94 column,
  except for the spelling of the closed port.
- **The fake server saw** ClientKeyExchange for `fake-ok`, then alerts 51, 50,
  42 and 40 (`noreneg`), 47 for each of the four key-type rows, and 80 for
  the unknown OID.
- **`bad13-corrupt-certverify`:** the server received `DecryptError`.

**The header** pins the environment, as §2 "Pinning the CI environment" asks.
Each `# env` line is one field:
- `nmap --version`'s first line, and the OpenSSL nmap was compiled with;
- `openssl version` and `openssl version -d`;
- `OPENSSL_CONF`, or `unset`;
- `seclevel`, the effective default security level, **measured**. The
  generator creates `SSL_CTX_new(TLS_client_method())` through `ctypes`, in
  the libssl that `ldd` says nmap links, and applies nsock's
  `CIPHERS_SECURE` (7.94's `nsock_ssl.c`). The configuration file is loaded
  as libssl loads it for nmap. Measured: 2. A config with
  `CipherString = DEFAULT:@SECLEVEL=1` makes it 1. A Python `ssl` context or
  `s_client` would not do: each sets its own cipher string;
- `seclevel-compiled`, the `-DOPENSSL_TLS_SECURITY_LEVEL` in
  `openssl version -a` (Ubuntu builds with 2; upstream's default is 1);
- `legacy-provider`: whether `openssl list -providers -provider legacy`
  succeeds;
- `python-ssl`: the OpenSSL behind the STARTTLS fixture server.

`--check-header` compares these fields and exits 1 on any difference.
`--check` runs the same comparison before anything else.

**Nondeterminism.** None was found, measured as follows:
- the generator runs the matrix twice by default, about 30 s each, and
  refuses to write a golden if an untagged row differs;
- seven full runs with the badserver, in four generator invocations, gave
  identical rows, and two invocations into separate directories gave
  byte-identical goldens.

A row that later proves nondeterministic goes into `NONDET` with a reason. It
is then written with the tag `nondet:<reason>` and never compared. Fields
that vary by nature are never recorded: timings, random values, the server's
thread ids and source lines, and the connect scan's own connection.

**The corrupt CertificateVerify: `needs-badserver`.** The spike's TLS 1.3
server is a Rust binary (`spikes/m65-tls-provider/src/bin/badserver.rs`), and
nothing in Python or the `openssl` CLI can stand in for it:
- Python's `ssl` cannot corrupt a CertificateVerify;
- `s_server` refuses a key that does not match its certificate;
- corrupting the encrypted record in a proxy draws `bad_record_mac`, not
  `decrypt_error`.

So the two `bad13-*` rows are tagged `needs-badserver` and recorded from the
binary when it is there. The generator looks in `$BADSERVER`, then
`$CARGO_TARGET_DIR/release/badserver`, then
`spikes/m65-tls-provider/target/release/badserver`. The committed rows were
recorded from a build of the spike (`cargo build --release --bin badserver`).

Without the binary, the generator prints which rows it could not run and
why. Then:
- with `--carry GOLDEN`, it copies those rows from the golden;
  `regen_m65_tls.sh` passes the committed golden this way, so a
  regeneration or a `--check` on a machine without Rust keeps them;
- without `--carry`, it writes them as `skipped`. A `skipped` row is never
  compared.

The oracle never builds the spike.
