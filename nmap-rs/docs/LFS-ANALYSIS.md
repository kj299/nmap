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
  scripts' arguments designate the directory (when it exists, at first; since
  D2's step, also before, §8). The full key
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
as a local file, by the same mechanism as D1. Done in its own PR after the lfs
step merged, with the two changes the step's ledger left to it: a destination
that does not exist yet, and the review's hardening. Its own review is §9.

### The census

Every argument read in the 744 shipped Lua files (`stdnse.get_script_args`
and `nmap.registry.args`), and every `io.open` and `io.lines` (86 sites in 68
files), each traced from the open back to where its path comes from. A path
comes from:

| source | examples | grant |
|---|---|---|
| a data file, looked up by `nmap.fetchfile` alone | `datafiles`, `tftp-enum.filelist`, `nselib/data/...` | none needed: found beneath the data directories, which are readable already |
| an argument, opened as a local file to read (often after `fetchfile` fails) | `userdb`, `brute.credfile`, `jdwp-inject.filename`, `targets-xml.iX` | **`READ_FILE_ARGS`**, 53 keys |
| an argument, opened to write or append | `*.outfile`, `ajp-request.filename`, `*.map_path`, `oracle-brute-stealth.johnfile` | **`WRITE_FILE_ARGS`**, 20 keys |
| a directory argument, the file beneath it | http-fetch, the 3270 scripts | `OUTPUT_DIR_ARGS` (D1) |
| an argument, with more appended | `ldap.savesearch`, `ldap.saveprefix`, `hostmap.prefix`, `stuxnet-detect.save` | none (`nse-templated-output-paths`) |
| an argument run with `loadfile` | `mysql-audit.filename`, `http-devframework.fingerprintfile`, smb-psexec's `config` | none: scripts have no `loadfile` here (`nse-loadfile-file-args`) |
| the environment | `ssh1.lua`'s `~/.ssh/config` and `~/.ssh/known_hosts` | read-only, by the host (`os-getenv-home-only`) |
| the script's own state | whois-ip's cache beside `nmap-services` | none (`nse-whois-ip-cache-in-datadir`) |

The census is in the code, as `CENSUS` in `fspolicy`'s tests: each key a
table lists by its own name, the file and line that reads it, and how it is
opened. Three tests hold it to the tree and the tables:

- `the_census_cites_the_lines_that_read_each_key`: each cited line, read from
  the shipped file, reads that key (as a string, a field such as
  `args.userdb`, or `SCRIPT_NAME .. ".key"`);
- `the_tables_are_the_census`: each table lists exactly the census keys of its
  kind, plus short keys derived from them, and none of a pinned list of keys
  that name something on the target or a template;
- `every_reader_of_a_short_key_opens_a_local_file`: below.

### The short-key rule

`stdnse.get_script_args` accepts a key without the script's name
(`stdnse.lua:616-628`); `nmap.registry.args[k]` takes the key as written. A
short key is listed only where every shipped reader of it, by its full key or
its short one, is in the census as the table grants. A read short key may
also have readers that write (`filename`: `ajp-request.filename` writes), and
readers that look it up in the data directories alone or run it with
`loadfile` (`OTHER_READERS`: the `fingerprintfile` of http-default-accounts,
http-enum and http-devframework; `targets-ipv6-wordlist.wordlist`;
`tftp-enum.filelist`; `mysql-audit.filename`). A write or directory short key
may have no other reader. The test scans every line of the tree that reads an
argument for keys ending in each short key.

- `file` is never listed: `http-axis2-dir-traversal.file`,
  `http-phpmyadmin-dir-traversal.file` and `http-vuln-cve2006-3392.file` name
  a file on the target. `http-put.file` counts by its full key only.
- `filename` is read-only, so only `ajp-request.filename` writes.
- `path`, `dir` and `save` stay out, as in D1.

So `filename=/x` lets scripts read `/x`, and `ajp-request.filename=/x` lets
them write it; under nmap, `filename=/x` also makes ajp-request write `/x`.
That and the closed list itself are the divergence
(`nse-file-args-documented`): a script given a local path under an argument
the census missed cannot open it.

The values are those of top-level string fields, as in D1:
`nested={userdb=/x}` and `{/x}` grant nothing, where before any value at any
depth did. A read value may name any file that is not a directory: nmap reads
`userdb=/dev/null`.

### A destination that does not exist yet

The C's http-fetch makes a missing destination, parents and all
(`create_directory`, `http-fetch.nse:76-89`). An output directory named before
it exists is now designated as its nearest existing ancestor, canonical,
joined with the rest of the path. The missing directories above it may be
made, each itself and nothing beside it (`FsPolicy::creatable`), compared
canonical, as everything is, so a link planted in their place later leads
nowhere writable.

Only a path that is *missing* climbs to its parent. Any other failure to look
it up refuses it: `ENOTDIR` for `file/`, `file/.` or `file/x`, a loop, a
permission error. So does a missing part that is a link leading nowhere, and a
`..` in the missing part, which means what it means only once the directories
exist (`nse-output-dir-dotdot-refused`: 7.94 makes the tree). A `.` there is
dropped, as the kernel drops it once the directories exist, and matches 7.94.

Measured through the shipped http-fetch against 7.94, with
`http-fetch.destination=DEST/new/deeper/dest` (the `fetch-new` scenario): the
same 16-entry tree, path, type, mode, size and SHA-256, and the same output
(`nse-output-dir-must-exist`, closed).

### Hardening: nothing writable overlaps what nmap loads

From the lfs review, and widened by D2's own review (§9). An output
directory or a file named for writing is refused when it overlaps:

- a data directory in the search, **whether or not it exists**: an absent
  `~/.nmap` or `$NMAPDIR` is protected where it would be, since the next run
  without `--datadir` loads it. So `destination=$HOME` is refused, and so is
  `destination=~/.nmap/nselib`;
- what a link leads to, at a data directory's top or anywhere beneath its
  `nselib/` and `scripts/` (`scripts/mine.nse -> ~/dev/mine.nse`, the usual
  way to add a script), followed out, up to 65,536 entries in all;
- a script this run loads (`--script ~/dev/mine.nse`);
- on Unix, a file among those by device and inode: a hard link to one, by any
  name.

Scripts could otherwise write what this run and later runs load. nmap has no
such rule (`nse-write-overlapping-data-dirs`). This is worked out only when
something writable was named. Each refusal, and each output directory that
cannot be designated, is reported on standard error, before the scan:

```
NSE: Warning: scripts may not write to /usr/share/nmap/nselib: it overlaps the data directory /usr/share/nmap.
NSE: Warning: scripts may not write to /home/op/dev: it overlaps /home/op/dev/mine.nse, which /usr/share/nmap/scripts/mine.nse leads to.
```

Left as residual risk, in the ledger entry: a hard link to a data file
planted *beneath* an output directory (only someone who can already write the
data file can make one where the kernel protects hard links); an absent data
directory named with `..` in its missing part; and on Windows, hard links.
Binding a key to the scripts that read it, the lfs review's last note, is not
done: a grant holds for every script in the run, as nmap's arguments are
every script's.

### Gates

- `fspolicy::tests`: `only_local_file_arguments_name_files`,
  `the_tables_are_disjoint`,
  `the_missing_way_to_an_output_dir_is_creatable_and_no_more`, and the three
  census tests above;
- `nsefs::tests`: `an_output_dir_that_does_not_exist_yet_can_be_made`,
  `nothing_writable_overlaps_a_data_directory`,
  `output_dirs_must_be_directories_or_plain_names_beneath_one` (each refusal
  with its own reason), `a_data_directory_that_does_not_exist_yet_is_protected`,
  `nested_links_hard_links_and_chosen_scripts_are_protected`,
  `read_files_may_be_devices_not_directories`;
- `only_local_file_arguments_open_their_files` (the CLI, port only): a path on
  the target opens nothing; `userdb`, `jdwp-inject.filename` and `filename`
  read and do not write; `/dev/null` reads; `outfile` writes; a destination
  in a data directory is refused with one warning naming the link; `$HOME`
  and `~/.nmap/nselib` are refused with `HOME` pointed at a scratch
  directory and no `~/.nmap`; a script chosen by path and named in `outfile`
  is refused;
- the `fetch-new` scenario against 7.94 (20 scenarios, 0 differ). http-fetch's
  `ERROR` table is compared sorted by URL too, as its downloads are (N4);
- the `nse_scriptargs` fuzz target: each table's values are exactly the
  top-level string fields it lists.

## 9. D2's review (LESSONS #041)

An independent review of the step, before merge, ran 17 sabotages of its own
(13 caught, one an equivalent mutant) and found:

- **H1: a file named as a directory became an output root.** `designate`
  climbed to the parent on any lookup error, not only "missing", so
  `destination=F/` (or `F/.`, `F//`) for an existing file `F` designated `F`
  itself, writable, with no warning. **Fixed** (§8), with each refusal's
  reason pinned per row.
- **H2: absent data directories were unprotected.** `~/.nmap` is usually
  absent; `destination=$HOME`, or D2's new route `destination=~/.nmap/nselib`,
  let a script plant a library the next run loads. **Fixed:** every data
  directory in the search is protected, existing or not.
- **M1: `jdwp-inject.filename` was missed.** `io.open(nmap.fetchfile(filename)
  or filename, "rb")` reads it locally. **Fixed:** listed (53 read keys), and
  the census is now a test.
- **M2: protection went one level deep.** A link nested in `scripts/`, a hard
  link to a data file, and a chosen script were writable. **Fixed** (§8).
- **L1:** a read value naming a device was refused; nmap reads
  `userdb=/dev/null`. **Fixed.**
- **L2:** the tables' contents were not pinned: adding a target path, dropping
  a key or moving one between tables survived. **Fixed:** the census tests.
- **L3:** the `..` refusal was described only in a closed entry, and `.` was
  said to refuse when it does not. **Fixed:** `nse-output-dir-dotdot-refused`.
- **L4:** the protected set was built on every run. **Fixed:** only when
  something writable was named.
- **L5:** the `..` refusal had two layers, either alone redundant. **Fixed:**
  one layer (a `..` has no name to climb by).
- **N1–N4:** the warning named a link's target as "the data directory";
  stale docs; inexact claims (`fetchfile` "never leaves" the data
  directories, which 7.94's does with `..`; census counts no script
  reproduced, now replaced by the census test); and the `ERROR` table's
  order. **Fixed.**
- **Ledgered:** `nse-fetchfile-dotdot-refused`, `nse-libssh2-key-file-args`,
  `nse-loadfile-file-args`, `nse-supermicro-default-out-cwd`.

After the fixes, 14 sabotages of the fix round, each caught by a named test:
the review's three survivors (a target path added to the read table, a write
key dropped, a read key moved to the write table), an unlisted other reader,
a wrong citation, a short key with a target-path reader, and one per fix
(climbing on any error, no check for a link leading nowhere, absent data
directories unprotected, no nested walk, no inode check, chosen scripts not
passed by the CLI, read files regular only, the CLI protecting existing
directories only).
