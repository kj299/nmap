//! The `lfs` module (`nse_fs.cc`, nmap's cut-down LuaFileSystem), in the
//! minimal form M6.6 decided (`docs/M6.6-ANALYSIS.md` D1 (c),
//! `docs/LFS-ANALYSIS.md`): the two functions the shipped tree calls, and the
//! three fields `set_info` sets.
//!
//! | field | C | here |
//! |---|---|---|
//! | `get_path_separator()` | `get_path_separator`: `"\\"` under `WIN32`, else `"/"` | the same, by target |
//! | `mkdir(path)` | `make_dir`: `mkdir(path, 0775)`; `true`, or `nil, strerror(errno)` | the same, through the host's file policy ([`ScriptFs::mkdir`]) |
//! | `_COPYRIGHT`, `_DESCRIPTION`, `_VERSION` | `set_info` | the same strings |
//! | `dir`, `link`, `rmdir` | `dir_iter_factory`, `make_link`, `remove_dir` | absent (`lfs-minimal`) |
//!
//! Only `http-fetch.nse` uses the module (`http-fetch.nse:69,77,87`), and
//! only these two functions. `link` is left out because the sandbox rests on
//! scripts being unable to make links (`THREAT-MODEL.md`), `rmdir` and `dir`
//! because nothing calls them.
//!
//! The module is registered as `nse_main.cc:566` registers it, with
//! `luaL_requiref(L, "lfs", luaopen_lfs, 1)`: a global, and in
//! `package.loaded`, between `nmapdb` and `lpeg` ([`super::runtime`]).
//!
//! **Errors** are raised as `luaL_checkstring` raises them, after
//! `luaL_where(L, 1)`, naming the function as [`super::nmapdb`] does:
//! `'mkdir'` when Lua code called it, `'lfs.mkdir'` (the name
//! `pushglobalfuncname` finds in `package.loaded`) when a C function such as
//! `pcall` did.

use std::rc::Rc;

use gc_arena::Collect;
use piccolo::{Callback, CallbackReturn, Context, Error, Execution, Stack, Table, Value};

use super::nmaplib::Fail;
use super::stdlib::iolib::ScriptFs;
use super::stdlib::{lua_error_bytes, LuaArgs};

/// What `get_path_separator` returns: `nse_fs.cc` tests `WIN32`.
pub const PATH_SEPARATOR: &str = if cfg!(windows) { "\\" } else { "/" };

/// `set_info`'s three fields.
const INFO: [(&str, &str); 3] = [
    ("_COPYRIGHT", "Copyright (C) 2003-2009 Kepler Project"),
    (
        "_DESCRIPTION",
        "LuaFileSystem is a Lua library developed to complement the set of functions \
         related to file systems offered by the standard Lua distribution",
    ),
    ("_VERSION", "LuaFileSystem 1.5.0"),
];

/// The file system `mkdir` asks.
#[derive(Collect)]
#[collect(require_static)]
struct Fs(Rc<dyn ScriptFs>);

/// `luaopen_lfs`: the module's table.
pub fn load_lfs<'gc>(ctx: Context<'gc>, fs: Rc<dyn ScriptFs>) -> Table<'gc> {
    let t = Table::new(&ctx);
    t.set_field(
        ctx,
        "mkdir",
        Callback::from_fn_with(&ctx, Fs(fs), |fs, ctx, exec, mut stack| {
            match make_dir(&*fs.0, ctx, &mut stack) {
                Ok(()) => Ok(CallbackReturn::Return),
                Err(e) => Err(raise(ctx, &exec, &e, "mkdir")),
            }
        }),
    );
    t.set_field(
        ctx,
        "get_path_separator",
        Callback::from_fn(&ctx, |ctx, _, mut stack| {
            stack.clear();
            stack.push_back(Value::String(ctx.intern(PATH_SEPARATOR.as_bytes())));
            Ok(CallbackReturn::Return)
        }),
    );
    for (k, v) in INFO {
        t.set_field(ctx, k, v);
    }
    t
}

/// `make_dir`: `luaL_checkstring(L, 1)`, then `true`, or `nil` and the
/// system's words for why not — two values, without the path or `errno`
/// `io.open` adds.
fn make_dir<'gc>(fs: &dyn ScriptFs, ctx: Context<'gc>, s: &mut Stack<'gc, '_>) -> Result<(), Fail> {
    let path = LuaArgs { ctx, stack: s }.string(1)?.into_owned();
    let result = fs.mkdir(&path);
    s.clear();
    match result {
        Ok(()) => s.push_back(Value::Boolean(true)),
        Err(e) => {
            s.push_back(Value::Nil);
            s.push_back(Value::String(ctx.intern(e.message.as_bytes())));
        }
    }
    Ok(())
}

/// The name `luaL_argerror` gives the function (see the module docs).
fn function_name(exec: &Execution<'_, '_>, name: &'static str) -> String {
    if exec.frame_info(1).is_some_and(|f| f.lua.is_some()) {
        name.to_string()
    } else {
        format!("lfs.{name}")
    }
}

/// `luaL_argerror`: the message, after `luaL_where(L, 1)`.
fn raise<'gc>(
    ctx: Context<'gc>,
    exec: &Execution<'gc, '_>,
    e: &Fail,
    name: &'static str,
) -> Error<'gc> {
    let mut msg = exec.where_at(1);
    msg.extend_from_slice(&e.message(&function_name(exec, name)));
    lua_error_bytes(ctx, &msg)
}

#[cfg(test)]
mod tests {
    //! The module through the VM, over a file system that records what it is
    //! asked. In-module so that Miri runs them.
    use super::*;
    use crate::nse::stdlib::iolib::{FsError, OpenMode, ScriptFile};
    use piccolo::{Closure, Executor, Lua, Variadic};
    use std::cell::RefCell;

    /// Records each `mkdir` path; answers from `answer`.
    struct Recorder {
        asked: RefCell<Vec<Vec<u8>>>,
        answer: fn(&[u8]) -> Result<(), FsError>,
    }

    impl ScriptFs for Recorder {
        fn open(&self, _: &[u8], _: OpenMode) -> Result<Box<dyn ScriptFile>, FsError> {
            Err(FsError::denied())
        }
        fn stdout(&self) -> Box<dyn ScriptFile> {
            unreachable!("lfs never writes to the standard output")
        }
        fn mkdir(&self, path: &[u8]) -> Result<(), FsError> {
            self.asked.borrow_mut().push(path.to_vec());
            (self.answer)(path)
        }
    }

    fn exists(path: &[u8]) -> Result<(), FsError> {
        if path == b"/d/old" {
            Err(FsError {
                message: "File exists".into(),
                errno: 17,
            })
        } else {
            Ok(())
        }
    }

    /// Run `src` with `lfs` as a global; what it returns, through
    /// `tostring`, joined with `,`.
    fn run(fs: Rc<Recorder>, src: &str) -> String {
        let mut lua = Lua::core();
        let ex = lua.enter(|ctx| {
            let t = load_lfs(ctx, fs);
            ctx.set_global("lfs", t);
            let f = Closure::load(ctx, Some("=probe"), src.as_bytes()).expect("compiles");
            ctx.stash(Executor::start(ctx, f.into(), ()))
        });
        lua.finish(&ex).expect("runs");
        lua.enter(|ctx| {
            let vs: Vec<Value> = ctx
                .fetch(&ex)
                .take_result::<Variadic<Vec<Value>>>(ctx)
                .expect("finished")
                .expect("returns")
                .0;
            vs.iter()
                .map(|v| match v {
                    Value::String(s) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
                    Value::Nil => "nil".into(),
                    Value::Boolean(b) => b.to_string(),
                    Value::Integer(i) => i.to_string(),
                    other => other.type_name().to_string(),
                })
                .collect::<Vec<_>>()
                .join(",")
        })
    }

    fn recorder() -> Rc<Recorder> {
        Rc::new(Recorder {
            asked: RefCell::new(Vec::new()),
            answer: exists,
        })
    }

    #[test]
    fn mkdir_returns_true_or_nil_and_the_reason() {
        let fs = recorder();
        assert_eq!(
            run(
                fs.clone(),
                "local a = {lfs.mkdir('/d/new')} local b = {lfs.mkdir('/d/old')} \
                             return #a, a[1], #b, b[1], b[2]"
            ),
            "1,true,2,nil,File exists"
        );
        assert_eq!(
            *fs.asked.borrow(),
            vec![b"/d/new".to_vec(), b"/d/old".to_vec()]
        );
    }

    #[test]
    fn a_host_without_directories_refuses_as_the_system_would() {
        struct Plain;
        impl ScriptFs for Plain {
            fn open(&self, _: &[u8], _: OpenMode) -> Result<Box<dyn ScriptFile>, FsError> {
                Err(FsError::denied())
            }
            fn stdout(&self) -> Box<dyn ScriptFile> {
                unreachable!()
            }
        }
        let mut lua = Lua::core();
        let ex = lua.enter(|ctx| {
            ctx.set_global("lfs", load_lfs(ctx, Rc::new(Plain)));
            let f = Closure::load(ctx, Some("probe"), &b"return lfs.mkdir('/x')"[..])
                .expect("compiles");
            ctx.stash(Executor::start(ctx, f.into(), ()))
        });
        lua.finish(&ex).expect("runs");
        let got = lua.enter(|ctx| {
            let vs: Vec<Value> = ctx
                .fetch(&ex)
                .take_result::<Variadic<Vec<Value>>>(ctx)
                .expect("finished")
                .expect("returns")
                .0;
            (
                vs[0].is_nil(),
                vs[1].into_string(ctx).map(|s| s.as_bytes().to_vec()),
            )
        });
        assert_eq!(got, (true, Some(b"Permission denied".to_vec())));
    }

    #[test]
    fn the_path_is_checkstring_s_number_conversion_and_bytes_pass_through() {
        let fs = recorder();
        run(
            fs.clone(),
            "lfs.mkdir(12) lfs.mkdir(1.5) lfs.mkdir('a\\0b') return 0",
        );
        assert_eq!(
            *fs.asked.borrow(),
            vec![b"12".to_vec(), b"1.5".to_vec(), b"a\0b".to_vec()]
        );
    }

    #[test]
    fn a_bad_argument_names_the_function_as_its_caller_found_it() {
        let fs = recorder();
        assert_eq!(
            run(
                fs.clone(),
                "return select(2, pcall(lfs.mkdir)), select(2, pcall(lfs.mkdir, {}))"
            ),
            "bad argument #1 to 'lfs.mkdir' (string expected, got no value),\
             bad argument #1 to 'lfs.mkdir' (string expected, got table)"
        );
        assert_eq!(
            run(
                fs.clone(),
                "return select(2, pcall(function() lfs.mkdir(nil) end))"
            ),
            "probe:1: bad argument #1 to 'mkdir' (string expected, got nil)"
        );
        assert!(
            fs.asked.borrow().is_empty(),
            "a bad argument reached the host"
        );
    }

    #[test]
    fn the_separator_and_info_fields() {
        let fs = recorder();
        assert_eq!(
            run(
                fs,
                "return lfs.get_path_separator(), lfs.get_path_separator(1, 2), lfs._VERSION, \
                     lfs._COPYRIGHT, lfs.dir, lfs.link, lfs.rmdir"
            ),
            format!(
                "{PATH_SEPARATOR},{PATH_SEPARATOR},LuaFileSystem 1.5.0,\
                 Copyright (C) 2003-2009 Kepler Project,nil,nil,nil"
            )
        );
    }
}
