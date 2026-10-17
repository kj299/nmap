//! The Lua state NSE runs in, assembled as `nse_main.cc`'s `init_main` and
//! `nse_main.lua`'s preamble assemble it.
//!
//! Every script and library shares one state. It holds the standard library
//! the scripts are allowed (the VM's own, and the first-party half in
//! [`super::stdlib`]), `package` and `require` ([`super::package`]), and the
//! modules the engine provides — `nmap` ([`super::nmaplib`]), `nmapdb`
//! ([`super::nmapdb`]), `lfs` ([`super::lfs`]) and `lpeg`
//! ([`super::lpeg`]) — each both in
//! `package.loaded` and as a global, as `luaL_requiref(L, name, open, 1)`
//! leaves them.

use std::cell::RefCell;
use std::rc::Rc;

use piccolo::{Closure, Executor, Fuel, Lua, StashedExecutor, StashedTable, Value, Variadic};

use super::engine::{load_cnse, EngineOptions, Store};

use super::lfs::load_lfs;
use super::lpeg::load_lpeg;
use super::nmapdb::load_nmapdb;
use super::nmaplib::{load_nmap, Shared};
use super::package::{load_package, preload_module, LibrarySource};
use super::scriptargs::ArgTable;
use super::stdlib::debuglib::load_debug;
use super::stdlib::iolib::{load_io, ScriptFs};
use super::stdlib::oslib::{load_os, OsEnv};
use super::stdlib::utf8lib::load_utf8;
use super::stdlib::{load_format, load_patterns, load_strpack, load_tail};

/// What the state is built from.
pub struct StateConfig {
    /// The `nmap` module's state: the run's options and hosts.
    pub lib: Shared,
    /// `--script-args` and `--script-args-file`, parsed.
    pub args: ArgTable,
    /// Where `require` finds `nselib/`.
    pub source: Rc<dyn LibrarySource>,
    /// The files `io` may open, and its standard output.
    pub fs: Rc<dyn ScriptFs>,
    /// The clocks `os` reads.
    pub os: Rc<OsEnv>,
    /// The VM's memory budget, in bytes ([`Lua::set_memory_limit`]).
    pub memory_limit: Option<usize>,
    /// What the engine reads of the run's options.
    pub engine: EngineOptions,
    /// The network scripts' sockets use ([`super::net::NoNet`] for none).
    pub net: super::net::SharedNet,
}

/// The engine's Lua, from `nse_main.lua` (see the file).
pub const PRELUDE: &str = include_str!("prelude.lua");

/// The fuel the prelude may use: it loads `stdnse`, `strict` and
/// `tableaux`, and defines the engine; a few thousand instructions.
const PRELUDE_FUEL: u64 = 50_000_000;

/// A built NSE state.
pub struct NseState {
    pub lua: Lua,
    /// What the prelude returned: the engine's own values (`NSE_YIELD_VALUE`,
    /// `REQUIRE_ERROR`, `print_debug`, ...) and its entry points (`main`,
    /// `load_script`, `scripts_loaded`, `render`).
    pub engine: StashedTable,
    /// The `nmap` module's state, which the engine shares.
    pub(crate) lib: super::nmaplib::Shared,
    /// Results the scripts stored, until a phase renders them.
    pub(crate) store: Rc<RefCell<Store>>,
    /// Run between slices of every call into the engine, and told of
    /// progress by `cnse.progress`.
    pub(crate) watchdog: super::engine::SharedWatchdog,
}

impl NseState {
    /// Set the check run between slices of VM work ([`super::engine::Watchdog`]).
    pub fn set_watchdog(&mut self, watchdog: Option<Box<dyn super::engine::Watchdog>>) {
        *self.watchdog.borrow_mut() = watchdog;
    }
}

/// Build NSE's Lua state and run the prelude in it; the prelude's error if it
/// fails, which means `nselib/` is missing or broken.
pub fn new_state(config: &StateConfig) -> Result<NseState, String> {
    let mut lua = build(config);
    let store = Rc::new(RefCell::new(Store::default()));
    let watchdog: super::engine::SharedWatchdog = Rc::new(RefCell::new(None));
    let ipv6 = config.lib.borrow().env.ipv6;
    let cnse = lua.enter(|ctx| {
        let cnse = load_cnse(ctx, &config.lib, &store, &watchdog, config.engine);
        let nmap: piccolo::Table = ctx.get_global("nmap").expect("build installs nmap");
        let net = super::net::load_net(
            ctx,
            config.net.clone(),
            ipv6,
            config.engine.max_parallelism,
            nmap,
        );
        cnse.set_field(ctx, "net", net);
        ctx.stash(cnse)
    });
    let engine = run_with(
        &mut lua,
        "=nse_main",
        PRELUDE.as_bytes(),
        PRELUDE_FUEL,
        Some(&cnse),
    )
    .and_then(|ex| {
        lua.try_enter(|ctx| {
            let t: piccolo::Table = ctx.fetch(&ex).take_result::<piccolo::Table>(ctx)??;
            Ok(ctx.stash(t))
        })
        .map_err(|e| format!("{e:#}"))
    })?;
    Ok(NseState {
        lua,
        engine,
        lib: config.lib.clone(),
        store,
        watchdog,
    })
}

/// The state, before the prelude has run.
fn build(config: &StateConfig) -> Lua {
    let mut lua = Lua::core();
    if let Some(limit) = config.memory_limit {
        lua.set_memory_limit(limit);
    }
    lua.enter(|ctx| {
        load_patterns(ctx).expect("Lua::core() has a string table");
        load_strpack(ctx).expect("Lua::core() has a string table");
        load_format(ctx).expect("Lua::core() has a string table");
        load_tail(ctx).expect("Lua::core() has string and coroutine tables");
        // The VM's own `coroutine.continue` and `yieldto`, which Lua 5.4 does
        // not have: `continue` resumes a coroutine without returning to its
        // resumer, which would suspend the scheduler that drives every script
        // (`vm-nonstandard-coroutine-functions`).
        if let Ok(Value::Table(co)) = ctx.get_global::<Value>("coroutine") {
            co.set_field(ctx, "continue", Value::Nil);
            co.set_field(ctx, "yieldto", Value::Nil);
        }
        // `LUA_VERSION`, which `nse_main.lua` checks before anything else.
        ctx.set_global("_VERSION", "Lua 5.4");
        load_io(ctx, config.fs.clone());
        load_os(ctx, config.os.clone());
        load_utf8(ctx);
        // `debug` needs `package.loaded`, which `load_package` then records
        // it in: the library table is put in place first and filled after.
        let debug = piccolo::Table::new(&ctx);
        ctx.set_global("debug", debug);
        let loaded = load_package(ctx, config.source.clone());
        let filled = load_debug(ctx, loaded);
        for (k, v) in filled {
            debug.set(ctx, k, v).expect("string keys");
        }
        ctx.set_global("debug", debug);
        let nmap = load_nmap(ctx, &config.lib, &config.args);
        preload_module(ctx, loaded, "nmap", Value::Table(nmap), true);
        // `luaL_requiref(L, "nmap.socket", ..., 0)`: in `package.loaded`
        // only, as is `nmap.dnet`.
        for sub in ["socket", "dnet"] {
            let module = nmap.get_value(ctx, sub);
            let name = if sub == "socket" {
                "nmap.socket"
            } else {
                "nmap.dnet"
            };
            preload_module(ctx, loaded, name, module, false);
        }
        // `set_nmap_libraries` registers `nmapdb` next (`nse_main.cc:564`).
        let nmapdb = load_nmapdb(ctx, &config.lib);
        preload_module(ctx, loaded, "nmapdb", Value::Table(nmapdb), true);
        // Then `lfs` and `lpeg` (`nse_main.cc:566-567`), each a global and
        // in `package.loaded`; `lfs` in its minimal form (`lfs-minimal`),
        // creating directories through the same policy as `io`.
        let lfs = load_lfs(ctx, config.fs.clone());
        preload_module(ctx, loaded, "lfs", Value::Table(lfs), true);
        // nmap's engine also requires `lpeg-utility` before any script loads
        // (`nse_main.lua:151`); the port's engine needs none of it
        // (`nse-lpeg-utility-not-preloaded`).
        let lpeg = load_lpeg(ctx);
        preload_module(ctx, loaded, "lpeg", Value::Table(lpeg), true);
    });
    lua
}

/// The outcome of [`run_chunk`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkOutcome {
    /// What the chunk returned, each value as `tostring` shows it.
    Returned(Vec<String>),
    /// The error that escaped it.
    Raised(String),
    /// It was still running when the fuel ran out.
    OutOfFuel,
}

/// Compile `src` as a chunk named `name` and step it until it finishes; the
/// executor, holding its result, or why it did not finish.
fn run_to_completion(
    lua: &mut Lua,
    name: &str,
    src: &[u8],
    fuel: u64,
) -> Result<StashedExecutor, String> {
    run_with(lua, name, src, fuel, None)
}

/// [`run_to_completion`], the chunk called with `arg` when there is one.
fn run_with(
    lua: &mut Lua,
    name: &str,
    src: &[u8],
    fuel: u64,
    arg: Option<&StashedTable>,
) -> Result<StashedExecutor, String> {
    let ex: StashedExecutor = lua
        .try_enter(|ctx| {
            let f = Closure::load(ctx, Some(name), src)?;
            let ex = match arg {
                Some(a) => Executor::start(ctx, f.into(), ctx.fetch(a)),
                None => Executor::start(ctx, f.into(), ()),
            };
            Ok(ctx.stash(ex))
        })
        .map_err(|e| format!("{e:#}"))?;
    const SLICE: i32 = 4096;
    let mut spent: u64 = 0;
    loop {
        let mut f = Fuel::with(SLICE);
        match lua.enter(|ctx| ctx.fetch(&ex).step(ctx, &mut f)) {
            Ok(true) => return Ok(ex),
            Ok(false) => {}
            Err(e) => return Err(e.to_string()),
        }
        spent = spent.saturating_add(u64::from(SLICE.unsigned_abs()));
        if spent > fuel {
            return Err(format!("{name}: out of fuel"));
        }
    }
}

/// Run `src` as a chunk named `name` in `lua` to completion, or until `fuel`
/// is spent.
pub fn run_chunk(lua: &mut Lua, name: &str, src: &[u8], fuel: u64) -> ChunkOutcome {
    let ex = match run_to_completion(lua, name, src, fuel) {
        Ok(ex) => ex,
        Err(e) if e.ends_with("out of fuel") => return ChunkOutcome::OutOfFuel,
        Err(e) => return ChunkOutcome::Raised(e),
    };
    lua.enter(
        |ctx| match ctx.fetch(&ex).take_result::<Variadic<Vec<Value>>>(ctx) {
            Ok(Ok(vs)) => {
                ChunkOutcome::Returned(vs.0.into_iter().map(|v| v.display().to_string()).collect())
            }
            Ok(Err(e)) => ChunkOutcome::Raised(match e {
                piccolo::Error::Lua(v) => v.0.display().to_string(),
                piccolo::Error::Runtime(r) => format!("{r:#}"),
            }),
            Err(e) => ChunkOutcome::Raised(e.to_string()),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::PRELUDE;

    /// Every `-- >>> nse_main.lua` block of the prelude, verbatim in
    /// `nse_main.lua`: the engine's Lua is copied from nmap's, not restated.
    #[test]
    #[cfg(not(miri))] // reads nse_main.lua from disk
    fn prelude_blocks_are_nse_main_verbatim() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../nse_main.lua");
        let nse_main = std::fs::read_to_string(&path).expect("nse_main.lua at the repository root");
        let mut blocks = 0;
        let mut rest = PRELUDE;
        while let Some(start) = rest.find("-- >>> nse_main.lua\n") {
            let body = &rest[start + "-- >>> nse_main.lua\n".len()..];
            let end = body.find("-- <<<\n").expect("every block is closed");
            let block = &body[..end];
            assert!(
                nse_main.contains(block),
                "prelude block not found verbatim in nse_main.lua:\n{block}"
            );
            blocks += 1;
            rest = &body[end..];
        }
        assert_eq!(blocks, 14, "the prelude's blocks");
    }

    /// The C modules this port registers, exactly: nmap's are registered by
    /// `set_nmap_libraries` (`nse_main.cc:556-579`) — `nmap`, `nmapdb`,
    /// `lfs`, `lpeg`, `libssh2`, `openssl`, `zlib` — with `nmap.socket` and
    /// `nmap.dnet` from `luaopen_nmap`. This port has `nmap`, `nmapdb`,
    /// `lpeg` (M6.6 step e), `lfs` (the lfs step) and the sub-modules, and
    /// the scriptload golden is generated with the rest removed
    /// (`oracle/gen_m66_scriptload.py`, `PORT_MISSING`). Porting a
    /// module, or stubbing one, means changing this list as well as that one
    /// (M6.6 review, sabotages S24 and S27).
    /// The state `new_state` builds, before the prelude, with no libraries,
    /// files or data.
    fn bare_state() -> piccolo::Lua {
        use super::*;
        use crate::nse::nmaplib::{NmapEnv, NmapLib, Phase};
        use crate::nse::stdlib::iolib::{FsError, OpenMode, ScriptFile, Whence};

        struct NoLibs;
        impl LibrarySource for NoLibs {
            fn find(&self, _: &[u8]) -> Option<Vec<u8>> {
                None
            }
            fn read(&self, _: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
                Err(b"none".to_vec())
            }
        }
        struct Sink;
        impl ScriptFile for Sink {
            fn read(&mut self, _: &mut [u8]) -> Result<usize, FsError> {
                Ok(0)
            }
            fn write(&mut self, _: &[u8]) -> Result<(), FsError> {
                Ok(())
            }
            fn seek(&mut self, _: Whence, _: i64) -> Result<u64, FsError> {
                Ok(0)
            }
            fn flush(&mut self) -> Result<(), FsError> {
                Ok(())
            }
        }
        struct NoFs;
        impl ScriptFs for NoFs {
            fn open(&self, _: &[u8], _: OpenMode) -> Result<Box<dyn ScriptFile>, FsError> {
                Err(FsError {
                    message: "no".into(),
                    errno: 2,
                })
            }
            fn stdout(&self) -> Box<dyn ScriptFile> {
                Box::new(Sink)
            }
        }
        let lib = NmapLib::new(NmapEnv {
            verbose: 0,
            debugging: 0,
            timing_level: 3,
            version_intensity: 7,
            ttl: -1,
            data_length: -1,
            have_ssl: false,
            privileged: false,
            ipv6: false,
            interface: None,
            dns_servers: vec![],
            excluded_ports: None,
            services: None,
            phase: Phase::PreScan,
            interfaces: Ok(Vec::new()),
            fetchfile: Box::new(|_| None),
            read_data_file: Box::new(|_| crate::nse::nmapdb::DataFile::NotFound),
            clock: Box::new(|| (0, 0)),
            random: Box::new(|_| false),
            log: Box::new(|_, _| {}),
        });
        let config = StateConfig {
            lib,
            args: ArgTable::default(),
            source: Rc::new(NoLibs),
            fs: Rc::new(NoFs),
            os: Rc::new(OsEnv {
                now: Box::new(|| 0),
                cpu_seconds: Box::new(|| 0.0),
                home: None,
            }),
            memory_limit: None,
            engine: EngineOptions::default(),
            net: Rc::new(RefCell::new(crate::nse::net::NoNet)),
        };
        build(&config)
    }

    #[test]
    fn the_registered_c_modules_are_exactly_the_ported_ones() {
        use super::*;
        let mut lua = bare_state();
        // Every `package.loaded` entry that is not one of Lua's own libraries,
        // and which of them are globals too.
        let out = run_chunk(
            &mut lua,
            "=t",
            b"local std = {_G = 1, package = 1, coroutine = 1, table = 1, io = 1, os = 1, \
               string = 1, math = 1, utf8 = 1, debug = 1} \
              local k = {} \
              for name, v in pairs(package.loaded) do \
                if not std[name] then \
                  k[#k + 1] = name .. (rawget(_G, name) == v and '=global' or '') \
                end \
              end \
              table.sort(k) \
              return table.concat(k, ',')",
            1_000_000,
        );
        assert_eq!(
            out,
            ChunkOutcome::Returned(vec![
                "lfs=global,lpeg=global,nmap.dnet,nmap.socket,nmap=global,nmapdb=global"
                    .to_string()
            ])
        );
        for missing in ["libssh2", "openssl", "zlib"] {
            let out = run_chunk(
                &mut lua,
                "=t",
                format!("return tostring(rawget(_G, '{missing}'))").as_bytes(),
                1_000_000,
            );
            assert_eq!(out, ChunkOutcome::Returned(vec!["nil".to_string()]));
        }
    }

    /// `lpeg` is registered as `luaL_requiref(L, "lpeg", luaopen_lpeg, 1)`
    /// leaves it (`nse_main.cc:567,581`; M6.6 step e): one table, in
    /// `package.loaded` and the global `lpeg`, which `require` returns; the
    /// pattern metatable reachable through `getmetatable` (no `__metatable`
    /// field: `re.lua` reads it and calls its fields), its `__index` that
    /// table; and matching works through it. The runtime opens it through
    /// `lpeg::load_lpeg`, never the test-only `register_for_tests`.
    #[test]
    fn lpeg_is_registered_as_nmap_registers_it() {
        use super::*;
        let mut lua = bare_state();
        let out = run_chunk(
            &mut lua,
            "=t",
            b"local ok, l = pcall(require, 'lpeg') \
              local mt = getmetatable(l.P(1)) \
              return ok, rawequal(l, rawget(_G, 'lpeg')), rawequal(l, package.loaded.lpeg), \
                     l.version(), type(mt), rawequal(mt.__index, l), \
                     rawget(mt, '__metatable') == nil, mt.__name, type(mt.__add), \
                     l.match(l.C(l.P'a'^1) * l.Cp(), 'aab')",
            10_000_000,
        );
        assert_eq!(
            out,
            ChunkOutcome::Returned(
                [
                    "true",
                    "true",
                    "true",
                    "0.12",
                    "table",
                    "true",
                    "true",
                    "lpeg-pattern",
                    "function",
                    "aa",
                    "3"
                ]
                .map(str::to_string)
                .to_vec()
            )
        );
        let src = include_str!("runtime.rs");
        let call = ["register", "_for_tests"].concat();
        assert!(
            !src.contains(&format!("{call}(")),
            "the runtime registers lpeg through the test-only path"
        );
    }

    /// Nothing calls `lpeg::register_for_tests` or
    /// `openssl::register_for_tests` but the modules' own tests, the
    /// integration tests and the fuzz targets: a search of every crate's
    /// sources, so a caller anywhere else — the engine, the command line —
    /// fails here, not only one in this file. The runtime registers `lpeg`
    /// through `lpeg::load_lpeg` alone, and `openssl` not at all before step
    /// g ([`openssl_is_not_registered`]).
    #[test]
    #[cfg_attr(miri, ignore = "reads the source tree")]
    fn only_tests_register_lpeg_and_openssl() {
        let call = format!("{}(", ["register", "_for_tests"].concat());
        let mut dirs = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..")];
        let (mut files, mut callers) = (0usize, Vec::new());
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("a crate directory") {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    let skip = path.ends_with("tests")
                        || path.ends_with("target")
                        || path.ends_with("nse/lpeg")
                        || path.ends_with("nse/openssl");
                    if !skip {
                        dirs.push(path);
                    }
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files = files.saturating_add(1);
                    let src = std::fs::read_to_string(&path).expect("a source file");
                    if src.contains(&call) {
                        callers.push(path);
                    }
                }
            }
        }
        assert!(files > 100, "searched only {files} files");
        assert!(
            callers.is_empty(),
            "lpeg or openssl is registered by {callers:?}"
        );
    }

    /// `openssl` is not registered (`docs/M6.5-ANALYSIS.md` D2(D), E7): its
    /// parts land step by step and the module only at step g, once TLS
    /// works. Until then `require "openssl"` fails in the NSE state, as it
    /// does in an nmap built without OpenSSL, and nothing names it in
    /// `package.loaded` or the globals. Step g turns this into the
    /// registration test.
    #[test]
    fn openssl_is_not_registered() {
        use super::*;
        let mut lua = bare_state();
        let out = run_chunk(
            &mut lua,
            "=t",
            b"local ok = pcall(require, 'openssl') \
              return ok, rawget(_G, 'openssl'), package.loaded.openssl, \
                     package.preload and package.preload.openssl",
            1_000_000,
        );
        assert_eq!(
            out,
            ChunkOutcome::Returned(["false", "nil", "nil", "nil"].map(str::to_string).to_vec())
        );
        let src = include_str!("runtime.rs");
        assert!(!src.contains(&["openssl", "::load"].concat()));
    }
}
