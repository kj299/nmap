//! `require` and the `package` table, as NSE sets them up.
//!
//! PUC-Lua's `require` (`loadlib.c`'s `ll_require`) is ported as it is: a
//! module already in `package.loaded` is returned; otherwise each function in
//! `package.searchers` is asked in turn for a loader, the loader is called with
//! the module name and whatever the searcher returned beside it, and its
//! result — or `true` — is recorded in `package.loaded` and returned with that
//! loader data.
//!
//! The searchers are NSE's. `nse_main.lua` inserts its own loader first, which
//! looks for `nselib/NAME.lua` along nmap's data-file search path
//! (`cnse.fetchfile_absolute`) and compiles it with `loadfile`; then comes
//! `package.preload`. PUC-Lua's own path searchers — `package.path` and
//! `package.cpath`, which load Lua and **C** code from directories outside
//! nmap's — are not installed: a script loads nselib libraries, the modules
//! the engine itself provides, and whatever it puts in `package.preload`,
//! and nothing else (`require-searches-only-nselib`, DIVERGENCES.md).
//!
//! What a library's source is, and where it lives, is asked of a
//! [`LibrarySource`] the engine is given, so that this module reads no files.

use std::pin::Pin;
use std::rc::Rc;

use gc_arena::Collect;
use piccolo::{
    BoxSequence, Callback, CallbackReturn, Closure, CompilerError, Context, Error, Execution,
    Function, Sequence, SequencePoll, Stack, String as LuaString, Table, Value,
};

use super::stdlib::lua_error_bytes;

/// Where `require` finds NSE's Lua libraries.
pub trait LibrarySource {
    /// `cnse.fetchfile_absolute(file)` for a path relative to the data
    /// directories (`nselib/NAME.lua`): the absolute path, if a regular file
    /// is there.
    fn find(&self, file: &[u8]) -> Option<Vec<u8>>;

    /// The bytes of the file at `path`, as `loadfile` reads them, or why not.
    fn read(&self, path: &[u8]) -> Result<Vec<u8>, Vec<u8>>;
}

/// Installs `package` and `require` into `ctx`'s globals, with NSE's searchers
/// in NSE's order, and returns `package.loaded`.
///
/// `package.loaded` starts with what `luaL_openlibs` puts there — `_G` and the
/// standard library tables present in the globals — and `package` itself.
/// Modules the engine provides (`nmap`, ...) are added with [`preload_module`].
pub fn load_package<'gc>(ctx: Context<'gc>, source: Rc<dyn LibrarySource>) -> Table<'gc> {
    let globals = ctx.globals();
    let package = Table::new(&ctx);
    let loaded = Table::new(&ctx);
    let preload = Table::new(&ctx);
    let searchers = Table::new(&ctx);

    // `luaL_openlibs` records each library it opens in `package.loaded`.
    loaded.set_field(ctx, "_G", globals);
    for lib in [
        "coroutine",
        "table",
        "io",
        "os",
        "string",
        "math",
        "utf8",
        "debug",
    ] {
        let v = globals.get_value(ctx, lib);
        if !v.is_nil() {
            loaded.set_field(ctx, lib, v);
        }
    }
    loaded.set_field(ctx, "package", package);

    // `nse_main.lua`: `insert(package.searchers, 1, loader)`, ahead of
    // `searcher_preload`.
    let nse = Callback::from_fn_with(&ctx, Holder(source), |source, ctx, _, mut stack| {
        nse_searcher(ctx, &*source.0, &mut stack)
    });
    searchers
        .set(ctx, 1, nse)
        .expect("an integer key is always valid");
    let preload_searcher = Callback::from_fn_with(&ctx, package, |&package, ctx, _, mut stack| {
        preload_search(ctx, package, &mut stack)
    });
    searchers
        .set(ctx, 2, preload_searcher)
        .expect("an integer key is always valid");

    package.set_field(ctx, "loaded", loaded);
    package.set_field(ctx, "preload", preload);
    package.set_field(ctx, "searchers", searchers);
    // `LUA_DIRSEP`, `LUA_PATH_SEP`, `LUA_PATH_MARK`, `LUA_EXEC_DIR`,
    // `LUA_IGMARK`, as `luaopen_package` writes them on POSIX.
    package.set_field(ctx, "config", "/\n;\n?\n!\n-\n");

    globals.set_field(ctx, "package", package);
    globals.set_field(
        ctx,
        "require",
        Callback::from_fn_with(
            &ctx,
            (package, loaded),
            |&(package, loaded), ctx, exec, stack| require(ctx, exec, stack, package, loaded),
        ),
    );
    loaded
}

/// `luaL_requiref(L, name, open, 1)` for a module the engine has already
/// built: `package.loaded[name] = module`, and the global of that name too
/// when `global` is set, as `nse_main.cc` registers its C modules.
pub fn preload_module<'gc>(
    ctx: Context<'gc>,
    loaded: Table<'gc>,
    name: &'static str,
    module: Value<'gc>,
    global: bool,
) {
    loaded.set_field(ctx, name, module);
    if global {
        ctx.globals().set_field(ctx, name, module);
    }
}

/// Holds the library source in a callback; it owns no GC pointers.
#[derive(Collect)]
#[collect(require_static)]
struct Holder(Rc<dyn LibrarySource>);

/// `ll_require` (`loadlib.c`).
fn require<'gc>(
    ctx: Context<'gc>,
    exec: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
    package: Table<'gc>,
    loaded: Table<'gc>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let name = match stack.get(0) {
        Value::String(s) => s,
        v @ (Value::Integer(_) | Value::Number(_)) => {
            v.into_string(ctx).expect("a number converts to a string")
        }
        v => {
            let got = if stack.is_empty() {
                "no value"
            } else {
                v.type_name()
            };
            let msg = format!("bad argument #1 to 'require' (string expected, got {got})");
            return Err(positioned(ctx, &exec, msg.as_bytes()));
        }
    };
    stack.clear();
    let existing = loaded.get_value(ctx, name);
    if existing.to_bool() {
        stack.push_back(existing);
        return Ok(CallbackReturn::Return);
    }
    let Value::Table(searchers) = package.get_value(ctx, "searchers") else {
        return Err(positioned(
            ctx,
            &exec,
            b"'package.searchers' must be a table",
        ));
    };
    let where_ = exec.where_at(1);
    Ok(CallbackReturn::Sequence(BoxSequence::new(
        &ctx,
        Require {
            name,
            loaded,
            searchers,
            next: 1,
            msg: Vec::new(),
            stage: Stage::Searching,
            data: Value::Nil,
            where_,
        },
    )))
}

/// A `luaL_error` raised by `require` itself: `luaL_where(L, 1)`, the position
/// of the Lua code that called it, then the message.
fn positioned<'gc>(ctx: Context<'gc>, exec: &Execution<'gc, '_>, msg: &[u8]) -> Error<'gc> {
    let mut out = exec.where_at(1);
    out.extend_from_slice(msg);
    lua_error_bytes(ctx, &out)
}

#[derive(Collect)]
#[collect(require_static)]
enum Stage {
    /// A searcher has been called, or is about to be.
    Searching,
    /// The loader has been called.
    Loading,
}

/// `findloader`, then the rest of `ll_require`, as a sequence: each searcher
/// and the loader are Lua-callable functions, called in turn.
#[derive(Collect)]
#[collect(no_drop)]
struct Require<'gc> {
    name: LuaString<'gc>,
    loaded: Table<'gc>,
    searchers: Table<'gc>,
    /// The index of the searcher to ask next.
    #[collect(require_static)]
    next: i64,
    /// `findloader`'s message buffer.
    #[collect(require_static)]
    msg: Vec<u8>,
    stage: Stage,
    /// The loader data the searcher returned beside the loader.
    data: Value<'gc>,
    /// `luaL_where(L, 1)` when `require` was called, for its own errors.
    #[collect(require_static)]
    where_: Vec<u8>,
}

impl<'gc> Require<'gc> {
    /// Ask the next searcher, or fail when there is none.
    fn ask_next(
        &mut self,
        ctx: Context<'gc>,
        stack: &mut Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        stack.clear();
        // `lua_rawgeti(L, 3, i)`.
        let searcher = self.searchers.get_value(ctx, self.next);
        if searcher.is_nil() {
            let mut msg = self.where_.clone();
            msg.extend_from_slice(b"module '");
            msg.extend_from_slice(self.name.as_bytes());
            msg.extend_from_slice(b"' not found:");
            msg.extend_from_slice(&self.msg);
            return Err(lua_error_bytes(ctx, &msg));
        }
        self.next = self.next.saturating_add(1);
        let function = piccolo::meta_ops::call(ctx, searcher).map_err(|_| {
            let msg = format!("attempt to call a {} value", searcher.type_name());
            lua_error_bytes(ctx, msg.as_bytes())
        })?;
        stack.push_back(Value::String(self.name));
        Ok(SequencePoll::Call {
            bottom: 0,
            function,
        })
    }
}

impl<'gc> Sequence<'gc> for Require<'gc> {
    fn poll(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let this = self.get_mut();
        match this.stage {
            Stage::Searching => {
                if stack.is_empty() && this.next == 1 {
                    // First poll: nothing asked yet.
                    return this.ask_next(ctx, &mut stack);
                }
                // `lua_call(L, 1, 2)`: two results, padded with nil.
                let found = stack.get(0);
                let extra = stack.get(1);
                if let Value::Function(loader) = found {
                    this.data = extra;
                    this.stage = Stage::Loading;
                    stack.clear();
                    stack.push_back(Value::String(this.name));
                    stack.push_back(extra);
                    return Ok(SequencePoll::Call {
                        bottom: 0,
                        function: loader,
                    });
                }
                match found {
                    // `lua_isstring`: a string, or a number as one.
                    Value::String(_) | Value::Integer(_) | Value::Number(_) => {
                        this.msg.extend_from_slice(b"\n\t");
                        let s = found.into_string(ctx).expect("a string or number converts");
                        this.msg.extend_from_slice(s.as_bytes());
                    }
                    _ => {}
                }
                this.ask_next(ctx, &mut stack)
            }
            Stage::Loading => {
                // `lua_call(L, 2, 1)`: one result.
                let result = stack.get(0);
                stack.clear();
                if !result.is_nil() {
                    this.loaded.set(ctx, this.name, result)?;
                }
                let mut module = this.loaded.get_value(ctx, this.name);
                if module.is_nil() {
                    module = Value::Boolean(true);
                    this.loaded.set(ctx, this.name, module)?;
                }
                stack.push_back(module);
                stack.push_back(this.data);
                Ok(SequencePoll::Return)
            }
        }
    }
}

/// The searcher `nse_main.lua` installs first: `nselib/NAME.lua`, with dots
/// in the name as directory separators, compiled by `loadfile` and asserted.
fn nse_searcher<'gc>(
    ctx: Context<'gc>,
    source: &dyn LibrarySource,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    // `lib:gsub("%.", "/")` on the name, which `require` passed as a string.
    let lib: Vec<u8> = match stack.get(0) {
        Value::String(s) => s.as_bytes().to_vec(),
        v @ (Value::Integer(_) | Value::Number(_)) => v
            .into_string(ctx)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default(),
        v => {
            let msg = format!("attempt to index a {} value", v.type_name());
            return Err(lua_error_bytes(ctx, msg.as_bytes()));
        }
    };
    let lib: Vec<u8> = lib
        .into_iter()
        .map(|b| if b == b'.' { b'/' } else { b })
        .collect();
    let mut file = b"nselib/".to_vec();
    file.extend_from_slice(&lib);
    file.extend_from_slice(b".lua");
    stack.clear();
    let Some(path) = source.find(&file) else {
        let mut msg = b"\n\tNSE failed to find ".to_vec();
        msg.extend_from_slice(&file);
        msg.extend_from_slice(b" in search paths.");
        stack.push_back(Value::String(ctx.intern(&msg)));
        return Ok(CallbackReturn::Return);
    };
    // `assert(loadfile(path))`: the chunk, or its error raised as it is.
    let mut chunk_name = b"@".to_vec();
    chunk_name.extend_from_slice(&path);
    let text = match source.read(&path) {
        Ok(text) => text,
        Err(why) => {
            let mut msg = b"cannot open ".to_vec();
            msg.extend_from_slice(&path);
            if !why.is_empty() {
                msg.extend_from_slice(b": ");
                msg.extend_from_slice(&why);
            }
            return Err(lua_error_bytes(ctx, &msg));
        }
    };
    let chunk = compile_file(ctx, &chunk_name, &text)?;
    stack.push_back(Value::Function(chunk));
    Ok(CallbackReturn::Return)
}

/// `luaL_loadfilex` on text already read: a leading `#` line is skipped, as
/// `skipcomment` skips it, and the chunk compiles in the global environment.
fn compile_file<'gc>(
    ctx: Context<'gc>,
    chunk_name: &[u8],
    text: &[u8],
) -> Result<Function<'gc>, Error<'gc>> {
    let body: std::borrow::Cow<'_, [u8]> = match text.first() {
        // The `#!` line is dropped but its newline kept, so line numbers hold.
        Some(b'#') => {
            let end = text.iter().position(|&b| b == b'\n').unwrap_or(text.len());
            std::borrow::Cow::Owned(text[end..].to_vec())
        }
        _ => std::borrow::Cow::Borrowed(text),
    };
    let name = String::from_utf8_lossy(chunk_name);
    match Closure::load_with_env(ctx, Some(&name), &body, ctx.globals()) {
        Ok(closure) => Ok(Function::Closure(closure)),
        Err(e) => {
            let (line, what) = match &e {
                CompilerError::Parsing(p) => (p.line_number, p.kind.to_string()),
                CompilerError::Compilation(c) => (c.line_number, c.kind.to_string()),
            };
            let mut msg = piccolo::chunk_id::chunk_id(chunk_name);
            msg.extend_from_slice(format!(":{line}: {what}").as_bytes());
            Err(lua_error_bytes(ctx, &msg))
        }
    }
}

/// `searcher_preload` (`loadlib.c`).
fn preload_search<'gc>(
    ctx: Context<'gc>,
    package: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let name = stack.get(0);
    stack.clear();
    let Value::Table(preload) = package.get_value(ctx, "preload") else {
        return Err(lua_error_bytes(ctx, b"'package.preload' must be a table"));
    };
    let loader = preload.get_value(ctx, name);
    if loader.is_nil() {
        let mut msg = b"no field package.preload['".to_vec();
        if let Some(s) = name.into_string(ctx) {
            msg.extend_from_slice(s.as_bytes());
        }
        msg.extend_from_slice(b"']");
        stack.push_back(Value::String(ctx.intern(&msg)));
    } else {
        stack.push_back(loader);
        stack.push_back(Value::String(ctx.intern(b":preload:")));
    }
    Ok(CallbackReturn::Return)
}
