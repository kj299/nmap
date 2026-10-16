# The minimal `lfs` step — Phase 0 and decisions

M6.6 D1 (c) (`docs/M6.6-ANALYSIS.md` §9): a minimal `lfs` follows M6.6, as a
small step with its own short Phase 0, because `mkdir` changes the sandbox.
This is that Phase 0. Measured on master `34ed0fb08`, against the installed
nmap 7.94 with `--datadir` set to this tree. C and script citations are
against `bc4346dd8`, the last commit to change the files cited.

## 1. What the C is

`nse_fs.cc` (300 lines) is nmap's cut-down LuaFileSystem 1.5.0. It registers
`lfs` with `luaL_requiref(L, "lfs", luaopen_lfs, 1)` (`nse_main.cc:566`): a
global and in `package.loaded`, between `nmapdb` and `lpeg`.

| field | C | used by the shipped tree |
|---|---|---|
| `get_path_separator()` | `"\\"` under `WIN32`, else `"/"` | `http-fetch.nse:69` |
| `mkdir(path)` | `mkdir(path, 0775)`; `true`, or `nil, strerror(errno)`: two values, no path, no errno | `http-fetch.nse:77,87` |
| `dir(path)` | an iterator over a directory | none |
| `link(old, new[, sym])` | `link`/`symlink` | none |
| `rmdir(path)` | `rmdir` | none |
| `_COPYRIGHT`, `_DESCRIPTION`, `_VERSION` | `set_info` | none |

`nselib/unittest.lua:79` lists `lfs` among the libraries to test; it has no
test suite. Nothing else in `nselib/` or `scripts/` touches the module.

## 2. Who needs it

`http-fetch` alone, which hard-requires it (`http-fetch.nse:4`), so `--script
safe` and `--script all` stop at start-up without it
(`nse-categories-abort-on-unported-modules`). Measured on 7.94 with only the
port's other missing modules (`openssl`, `libssh2`, `zlib`) removed:

| | before | with `lfs` |
|---|---|---|
| per-script loads (`gen_m66_scriptload.py`) | 560 OK / 2 LOUD / 49 QUIET | **561 / 1 / 49** (http-fetch) |
| `--script safe` | stops on `http-fetch.nse:4` | **352 selected, 334 loaded, 18 quiet**, rc 0 |
| `--script all` | stops on `lfs` | stops on `http-vuln-cve2014-3704.nse:8` (`openssl`) |
| `vuln`, `intrusive`, `exploit` | stop on `openssl` | unchanged |

All 18 of `safe`'s quiet drops are `openssl`'s: removing each module alone,
`openssl` drops all 18 and `libssh2` and `zlib` none. Real 7.94 loads all 352.

## 3. The sandbox finding

`mkdir` is to go "through the existing write policy" (D1 (c)). That policy
(Decision 2, `core::nse::fspolicy`) allows writing to a file the operator
named, or beneath a directory "the operator designated for script output".
**Nothing designated one.** The command line built the policy with no output
directories (`PolicyFs::new(.., &[], ..)` in `cli/src/nse.rs`), and a named
value that is a directory is dropped. So no script could write beneath a
directory, and the ledger entry `io-files-through-policy` described a
designation that did not exist.

Nine shipped scripts save beneath a directory the operator names (four
found here, five more by the review, §7):

| script | argument | reads it at |
|---|---|---|
| http-fetch | `http-fetch.destination` (also `destination`) | `http-fetch.nse:200` |
| http-config-backup | `http-config-backup.save` | `http-config-backup.nse:183` |
| ms-sql-dump-hashes | `ms-sql-dump-hashes.dir` | `ms-sql-dump-hashes.nse:98` |
| snmp-ios-config | `snmp-ios-config.tftproot` (also `tftproot`) | `snmp-ios-config.nse:55` |
| cics-enum | `cics-enum.path` | `cics-enum.nse:378` |
| lu-enum | `lu-enum.path` | `lu-enum.nse:178` |
| vtam-enum | `vtam-enum.path` | `vtam-enum.nse:249` |
| domino-enum-users | `domino-enum-users.path` | `domino-enum-users.nse:74` |
| http-domino-enum-passwords | `http-domino-enum-passwords.idpath` (also `idpath`) | `http-domino-enum-passwords.nse:217` |

`stdnse.get_script_args` also accepts the key without the script's name
(`stdnse.lua:616-628`). Three short keys collide with arguments that are not
local directories: `dir` is also `http-phpmyadmin-dir-traversal.dir` and
`http-vlcstreamer-ls.dir`, both paths **on the target**; `save` is also
`stuxnet-detect.save`, a file-name template; and 34 keys end in `.path`, most
of them URL paths on the target. Treating any value that names a
directory as designated would be worse still: `url=/` is a common argument,
and would make this host's root writable.

A second weakness surfaced on the way (D2): every argument value that names a
local file becomes readable and writable by every script, including values
that name a path on the target, such as
`http-phpmyadmin-dir-traversal.file=/etc/passwd`.

## 4. Threat model

- A script, or a server steering one, must not create a directory anywhere it
  could not already write. `mkdir` goes through the canonical-path policy as
  `open` does: the directory's canonical parent joined with its name, beneath
  a designated directory, or `EACCES`.
- Nor write through a link someone left in a designated directory. A name
  that is a link leading nowhere is not written through (`fopen` would create
  its target, wherever it is), and every file is opened with `O_NOFOLLOW`
  (`nse-write-through-dangling-link`, the review's B1).
- `link` is not ported. The sandbox's TOCTOU argument rests on scripts being
  unable to create links (`THREAT-MODEL.md`). `rmdir` and `dir` are not
  ported: nothing calls them.
- **Traversal from the server**, measured on 7.94: links through `..`,
  `%2e%2e` and `..%2f` do not lead http-fetch outside its destination. The
  URL library resolves dot segments, and `stringaux.filename_escape` escapes
  what is left (`..%2F` is saved as `..%252F`). The port runs the same Lua, so
  it writes the same tree, and its policy would refuse an escape anyway.
- `mkdir`'s mode is the C's, 0775 before the umask.

## 5. Decisions (answered 2026-10-16)

### D1 — How does an operator designate a directory?

- **(a) The documented output-directory arguments.** The values of those four
  scripts' arguments designate the directory when it exists. The full key
  always counts; a short key only where no other shipped script reads it:
  `destination` and `tftproot` do, `dir` and `save` do not.
  nmap command lines work unchanged.
- (b) A port-only `--script-output-dir DIR`, which nmap does not have.
- (c) No writable directories: `lfs` loads, but the four save nothing.

**Decided: (a).** The table is `fspolicy::OUTPUT_DIR_ARGS`, with the five
folder arguments the review found added under the same rule (`idpath` by its
short key too; `path` never). Designation is per run, not per script, as
named files are. A directory that does not exist was
not designated at first: http-fetch in 7.94 creates a missing destination, and
the port refused (`nse-output-dir-must-exist`, closed by D2's step, §8).

### D2 — Argument values that grant files

- **(a) Ledger it now, fix it in its own step next:** grant a file only from
  an argument the scripts document as a local file, the same mechanism as D1.
- (b) Fix it in this step.
- (c) Accept it as a residual risk.

**Decided: (a)** (`nse-named-values-grant-files`), and done in its own step
(§8).

## 6. The step

- **Built:**
  - `core::nse::lfs`: `get_path_separator`, `mkdir` and the info fields,
    registered as `nse_main.cc` registers it;
  - `ScriptFs::mkdir`, which refuses by default;
  - `FsPolicy::allows_mkdir` (beneath an output directory only; a named
    *file* is not a directory);
  - `fspolicy::OUTPUT_DIR_ARGS` and `output_dir_values`;
  - `sys::nsefs::PolicyFs::mkdir`;
  - the command line designating output directories.
- **Oracle:** nmap 7.94, through `gen_m64_cli.py`:
  - the fixture `l-lfs.nse`: 30 rows of results and argument errors (20 at first; the review added 10);
  - http-fetch mirroring a fixture site three ways;
  - each compared on script output and on the tree it leaves: path, type,
    mode, size, SHA-256.
  - Plus the per-script load golden (`PORT_MISSING` without `lfs`), the
    nselib golden, and the exit scenarios: `safe` is a load block, run in a
    loopback-only network namespace because it runs broadcast scripts; `all`
    now stops on `openssl`.
- **One harness tolerance:** http-fetch's XML lists its downloads in the order
  its parallel crawl finishes, which varies from run to run under 7.94 itself
  (5 runs, 4 orders). In those two scenarios, and only in that table, the
  elements are compared sorted.
- **Exit:** `--script safe` loads as under 7.94 without `openssl` (352 / 334 /
  18 quiet, rc 0); `all` stops on `openssl`; http-fetch's mirror matches 7.94
  byte for byte.

## 7. The review (LESSONS #041)

An independent fidelity and security review of the step, before merge, ran
its own 18 sabotages (14 caught) and found:

- **B1, blocking: writes followed a dangling link out of a designated
  directory.** `canonical_target` fell back to "the canonical parent and the
  name" for a link that leads nowhere, and `OpenOptions::create` followed
  it. Designation made that reachable with no race. Through the shipped
  http-fetch, one planted link wrote the server's page into another
  directory's `authorized_keys`. **Fixed:** such a name is refused for
  writing, and files are opened with `O_NOFOLLOW`
  (`nse-write-through-dangling-link`).
- **S7: path shapes.** `Path` drops a trailing `.` and separators, and every
  lookup error became "the parent and the name". `io.open("f/.", "w")`
  truncated `f`, `mkdir("nx/.")` made `nx`, and a loop or an over-long path
  read as `ENOENT`. **Fixed:** paths resolve as `open(2)` and `mkdir(2)`
  resolve them (`nse-open-path-shapes-as-the-kernel`), each row measured
  against the kernel and 7.94 and pinned in `l-lfs.nse`.
- **Gates that could not fail.**
  - S1, S2: the mode compared after a 022 umask. Every run is now under
    umask 0, so 0775 vs 0777 vs 0755 shows.
  - S3: an encoded-`..` link the fixture site keyed in lower case. The
    crawler asks in upper case, so it now runs.
  - S4: the CLI designating every directory argument passed everything. A
    port-only test now fails it.
  - S11: `mkdir` of the destination itself: a row now.
  - S8: only `safe` ran in the namespace. Every load and abort block does
    now, and the namespace is checked to hold only `lo`.
- **S5:** the census was short by five scripts, now designated (§3).
- **Ledgered rather than fixed here:**
  - `lfs-bad-argument-naming` (S6);
  - `nse-fs-windows-errno-text` and `nse-fs-windows-unc-canonicalize` (S10);
  - `nse-templated-output-paths` and `nse-whois-ip-cache-in-datadir`;
  - `cli-debug-equals-refused`;
  - the hardening notes (refuse designating a directory that holds a data
    directory), under D2's step, which did it (§8).

After the fixes, the review's four surviving sabotages, and both
dangling-link defences removed together, each fail a named gate.

## 8. The named-files step (D2)

D2 (a): a value grants a file only from an argument the shipped scripts open
as a local file, by the same mechanism as D1. Done on the lfs step's branch,
with the two changes the step's ledger left to it: a destination that does not
exist yet, and the review's hardening.

### The census

Every argument read in the 744 shipped Lua files (945 reads of 792 keys:
797 through `stdnse.get_script_args`, 148 through `nmap.registry.args`), and
every `io.open` and `io.lines` (86 sites in 68 files), each
traced from the open back to where its path comes from. A path comes from:

| source | examples | grant |
|---|---|---|
| a data file, by `nmap.fetchfile` alone | `datafiles`, `jdwp-inject.filename`, `nselib/data/...` | none needed: `fetchfile` searches the data directories only, and an absolute path is not found there |
| an argument, opened as a local file to read (often after `fetchfile` fails) | `userdb`, `brute.credfile`, `dns-brute.hostlist`, `targets-xml.iX` | **`READ_FILE_ARGS`**, 52 keys |
| an argument, opened to write or append | `*.outfile`, `ajp-request.filename`, `*.map_path`, `oracle-brute-stealth.johnfile` | **`WRITE_FILE_ARGS`**, 20 keys |
| a directory argument, the file beneath it | http-fetch, the 3270 scripts | `OUTPUT_DIR_ARGS` (D1) |
| an argument, with more appended | `ldap.savesearch`, `ldap.saveprefix`, `hostmap.prefix`, `stuxnet-detect.save` | none (`nse-templated-output-paths`) |
| the environment | `ssh1.lua`'s `~/.ssh/config` and `~/.ssh/known_hosts` | read-only, by the host (`os-getenv-home-only`) |
| the script's own state | whois-ip's cache beside `nmap-services` | none (`nse-whois-ip-cache-in-datadir`) |

Each table entry cites the line that reads it (`fspolicy.rs`).

### The short-key rule

`stdnse.get_script_args` accepts a key without the script's name
(`stdnse.lua:616-628`); `nmap.registry.args[k]` takes the key as written. A
short key is listed only where **every** shipped reader of it, by its full key
or its short one, opens a local file the same way:

- `file` is never: `http-axis2-dir-traversal.file`,
  `http-phpmyadmin-dir-traversal.file` and `http-vuln-cve2006-3392.file` name
  a file on the target. `http-put.file` counts by its full key only.
- `filename` is read-only: `http-virustotal.filename` and
  `smb-print-text.filename` read it, `ajp-request.filename` writes, so only
  that full key writes.
- `hostlist` (dns-brute, nje-node-brute), `idlist` (cics-enum, vtam-enum) and
  `outfile` (seven scripts) are read or written by every reader alike.
- `path`, `dir` and `save` stay out, as in D1.

So `filename=/x` lets scripts read `/x`, and `ajp-request.filename=/x` lets
them write it; under nmap, `filename=/x` also makes ajp-request write `/x`.
That and the closed list itself are the divergence
(`nse-file-args-documented`): a script given a local path under an argument
the census missed cannot open it.

The values are those of top-level string fields, as in D1:
`nested={userdb=/x}` and `{/x}` grant nothing, where before any value at any
depth did. `smb-psexec`'s `config` is not listed: it is a Lua file run with
`loadfile`, which scripts do not have here (`require-searches-only-nselib`).

### A destination that does not exist yet

The C's http-fetch makes a missing destination, parents and all
(`create_directory`, `http-fetch.nse:76-89`). An output directory named before
it exists is now designated as its nearest existing ancestor, canonical,
joined with the rest of the path, which must be plain names: a `.` or `..`
there means what it means only once the directories exist, so it refuses the
designation. The missing directories above it may be made, each itself and
nothing beside it (`FsPolicy::creatable`). Compared canonical, as everything
is, so a link planted in their place later leads nowhere writable.

Measured through the shipped http-fetch against 7.94, with
`http-fetch.destination=DEST/new/deeper/dest` (the `fetch-new` scenario): the
same 16-entry tree, path, type, mode, size and SHA-256, and the same output
(`nse-output-dir-must-exist`, closed).

### Hardening: nothing writable overlaps a data directory

From the lfs review: an output directory or a named file that is in a data
directory, or holds one, is refused, and so is one that overlaps what a data
directory's entries lead to (`nselib`, `scripts`, the data files), which a
link can put anywhere. Scripts could otherwise write what this run and later
runs load. nmap has no such rule (`nse-write-overlapping-data-dirs`). Each
refusal, and each output directory that cannot be designated, is reported on
standard error, before the scan:

```
NSE: Warning: scripts may not write to /usr/share/nmap/nselib: it overlaps the data directory /usr/share/nmap.
```

Binding a key to the scripts that read it, the review's last note, is not
done: a grant holds for every script in the run, as nmap's arguments are
every script's (left in `nse-file-args-documented`).

### Gates

- `fspolicy::tests::only_local_file_arguments_name_files`,
  `the_tables_are_disjoint`,
  `the_missing_way_to_an_output_dir_is_creatable_and_no_more`;
- `nsefs::tests::an_output_dir_that_does_not_exist_yet_can_be_made`,
  `nothing_writable_overlaps_a_data_directory`,
  `output_dirs_must_be_directories_or_plain_names_beneath_one`;
- `only_local_file_arguments_open_their_files` (the CLI, port only): a path on
  the target opens nothing, a read argument reads and does not write, a write
  argument writes, a destination in a data directory is refused with the
  warning;
- the `fetch-new` scenario against 7.94 (20 scenarios, 0 differ);
- the `nse_scriptargs` fuzz target: each table's values are exactly the
  top-level string fields it lists.

Four sabotages, each caught: `file` added to `READ_FILE_ARGS` (two fspolicy
tests and the CLI test), the overlap check removed (nsefs and the CLI),
read files made writable (the CLI), and `..` accepted in a destination that
does not exist (nsefs).
