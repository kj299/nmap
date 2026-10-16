# The minimal `lfs` step — Phase 0 and decisions

M6.6 D1 (c) (`docs/M6.6-ANALYSIS.md` §9): a minimal `lfs` follows M6.6, as a
small step with its own short Phase 0, because `mkdir` changes the sandbox.
This is that Phase 0. Measured on master `34ed0fb08`, against the installed
nmap 7.94 with `--datadir` set to this tree.

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

Four shipped scripts save beneath a directory the operator names:

| script | argument | reads it at |
|---|---|---|
| http-fetch | `http-fetch.destination` (also `destination`) | `http-fetch.nse:200` |
| http-config-backup | `http-config-backup.save` | `http-config-backup.nse:183` |
| ms-sql-dump-hashes | `ms-sql-dump-hashes.dir` | `ms-sql-dump-hashes.nse:98` |
| snmp-ios-config | `snmp-ios-config.tftproot` (also `tftproot`) | `snmp-ios-config.nse:55` |

`stdnse.get_script_args` also accepts the key without the script's name
(`stdnse.lua:616-628`). Two short keys collide with arguments that are not
local directories: `dir` is also `http-phpmyadmin-dir-traversal.dir` and
`http-vlcstreamer-ls.dir`, both paths **on the target**, and `save` is also
`stuxnet-detect.save`, a file-name template. Treating any value that names a
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

**Decided: (a).** The table is `fspolicy::OUTPUT_DIR_ARGS`. Designation is per
run, not per script, as named files are. A directory that does not exist is
not designated: http-fetch in 7.94 creates a missing destination, and the port
refuses (`nse-output-dir-must-exist`).

### D2 — Argument values that grant files

- **(a) Ledger it now, fix it in its own step next:** grant a file only from
  an argument the scripts document as a local file, the same mechanism as D1.
- (b) Fix it in this step.
- (c) Accept it as a residual risk.

**Decided: (a)** (`nse-named-values-grant-files`, open).

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
  - the fixture `l-lfs.nse`: 20 rows of results and argument errors;
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
