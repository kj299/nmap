//! The `io` library NSE scripts get, ported from `liolib.c` over files the
//! host opens.
//!
//! The library itself — read formats, line iteration, `seek`, how failures
//! are reported — is PUC-Lua's. What differs is who opens a file: not
//! `fopen`, but a [`ScriptFs`] the engine is given, which decides what a
//! script may touch (Decision 2, `docs/M6-ANALYSIS.md`). A file it refuses
//! fails to open as a file the system refuses does: `nil`, then
//! `"NAME: Permission denied"`, then `13`.
//!
//! Not provided: `io.popen` (it runs a command), `io.tmpfile`, `io.read`,
//! `io.input` and reading standard input (NSE runs unattended; no shipped
//! file reads it). `io.write` writes to the host's standard output, as it
//! does in nmap; `io.output(name)` redirects it to a file the host allows.

use std::cell::RefCell;
use std::rc::Rc;

use std::pin::Pin;

use gc_arena::Collect;
use piccolo::meta_ops::{self, MetaResult};
use piccolo::{
    BoxSequence, Callback, CallbackReturn, Context, Error, Execution, Function, IntoValue,
    Sequence, SequencePoll, Stack, Table, UserData, Value,
};

use super::strpack::PackError;
use super::{lua_error, lua_error_bytes, reserve, LuaArgs};

/// How a file is opened: `fopen`'s mode, already checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenMode {
    /// `r`, `w` or `a`.
    pub base: u8,
    /// `+`: both reading and writing.
    pub update: bool,
}

impl OpenMode {
    /// `l_checkmode`: `[rwa]`, an optional `+`, then only `b`s.
    pub fn parse(mode: &[u8]) -> Option<OpenMode> {
        let (&base, rest) = mode.split_first()?;
        if !b"rwa".contains(&base) {
            return None;
        }
        let (update, rest) = match rest.split_first() {
            Some((b'+', rest)) => (true, rest),
            _ => (false, rest),
        };
        // `strspn(mode, "b") == strlen(mode)`: the rest, as a C string.
        let rest = rest
            .iter()
            .position(|&b| b == 0)
            .map_or(rest, |i| &rest[..i]);
        rest.iter()
            .all(|&b| b == b'b')
            .then_some(OpenMode { base, update })
    }

    /// Whether the file is written to.
    pub fn writes(self) -> bool {
        self.base != b'r' || self.update
    }
}

/// Why a file operation failed: `strerror(errno)` and `errno`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsError {
    pub message: String,
    pub errno: i64,
}

impl FsError {
    /// `EACCES`: what a file the host refuses fails with.
    pub fn denied() -> FsError {
        FsError {
            message: "Permission denied".into(),
            errno: 13,
        }
    }
}

/// Where to seek from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whence {
    Set,
    Cur,
    End,
}

/// An open file.
pub trait ScriptFile {
    /// Read up to `buf.len()` bytes; 0 at end of file.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, FsError>;
    fn write(&mut self, data: &[u8]) -> Result<(), FsError>;
    /// The new position.
    fn seek(&mut self, whence: Whence, offset: i64) -> Result<u64, FsError>;
    fn flush(&mut self) -> Result<(), FsError>;
}

/// The files a script may open, and its standard output.
pub trait ScriptFs {
    /// `fopen(path, mode)`, if the host allows the script this file.
    fn open(&self, path: &[u8], mode: OpenMode) -> Result<Box<dyn ScriptFile>, FsError>;
    /// The default output, which `io.write` writes to.
    fn stdout(&self) -> Box<dyn ScriptFile>;
}

/// `LUAL_BUFFERSIZE`.
const BUFFER_SIZE: usize = 16 * 8 * 8;

/// `L_MAXLENNUM`: the longest numeral `read("n")` reads.
const MAX_LEN_NUM: usize = 200;

/// A `FILE *` and its stdio buffer: what `LStream` holds.
struct Stream {
    file: Option<Box<dyn ScriptFile>>,
    /// Read but not yet consumed.
    buf: Vec<u8>,
    pos: usize,
    /// Whether this is the standard output, which `close` does not close.
    std: bool,
}

impl Stream {
    fn new(file: Box<dyn ScriptFile>, std: bool) -> Self {
        Stream {
            file: Some(file),
            buf: Vec::new(),
            pos: 0,
            std,
        }
    }

    fn file(&mut self) -> &mut Box<dyn ScriptFile> {
        self.file.as_mut().expect("callers check isclosed first")
    }

    /// `getc`: the next byte, or `None` at end of file.
    #[allow(clippy::arithmetic_side_effects)] // `pos` indexes `buf`, so `pos + 1` is at most its length
    fn getc(&mut self) -> Result<Option<u8>, FsError> {
        if self.pos == self.buf.len() {
            self.buf.resize(BUFFER_SIZE, 0);
            let n = {
                let Stream { file, buf, .. } = self;
                file.as_mut().expect("open").read(buf)?
            };
            self.buf.truncate(n);
            self.pos = 0;
            if n == 0 {
                return Ok(None);
            }
        }
        let c = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(c))
    }

    /// `ungetc` of the byte just read.
    fn ungetc(&mut self) {
        self.pos = self.pos.saturating_sub(1);
    }

    /// Drop what has been read ahead, moving the file back to the position
    /// the script has reached, before a write or a seek: stdio's rule for a
    /// stream switched between reading and writing.
    #[allow(clippy::arithmetic_side_effects)] // `pos` never passes `buf.len()`
    fn sync(&mut self) -> Result<(), FsError> {
        let unread = self.buf.len() - self.pos;
        self.buf.clear();
        self.pos = 0;
        if unread > 0 {
            let back = i64::try_from(unread).unwrap_or(i64::MAX);
            self.file().seek(Whence::Cur, -back)?;
        }
        Ok(())
    }

    /// `fread` of up to `n` bytes into `out`.
    #[allow(clippy::arithmetic_side_effects)] // `take` is at most `n` and what `buf` holds past `pos`
    fn read_into(&mut self, out: &mut Vec<u8>, mut n: usize) -> Result<usize, FsError> {
        let mut got = 0;
        while n > 0 {
            if self.pos == self.buf.len() && self.getc()?.map(|_| self.ungetc()).is_none() {
                break;
            }
            let take = n.min(self.buf.len() - self.pos);
            out.extend_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            got += take;
            n -= take;
        }
        Ok(got)
    }
}

/// The userdata a file handle is.
struct Handle(RefCell<Stream>);

/// The `io` library's state: its file metatable, and the default output.
#[derive(Collect)]
#[collect(require_static)]
struct Io {
    fs: Rc<dyn ScriptFs>,
}

/// Installs `io` into `ctx`'s globals and returns it.
pub fn load_io<'gc>(ctx: Context<'gc>, fs: Rc<dyn ScriptFs>) -> Table<'gc> {
    let io = Table::new(&ctx);
    let meta = Table::new(&ctx);
    let methods = Table::new(&ctx);
    meta.set_field(ctx, "__index", methods);
    meta.set_field(ctx, "__name", "FILE*");
    meta.set_field(ctx, "__tostring", Callback::from_fn(&ctx, f_tostring));
    macro_rules! method {
        ($name:literal, $f:ident) => {
            methods.set_field(
                ctx,
                $name,
                Callback::from_fn_with(&ctx, meta, |&meta, ctx, _, mut stack| {
                    $f(ctx, meta, &mut stack)
                }),
            );
        };
    }
    method!("read", f_read);
    method!("write", f_write);
    method!("lines", f_lines);
    method!("close", f_close);
    method!("flush", f_flush);
    method!("seek", f_seek);
    method!("setvbuf", f_setvbuf);
    meta.set_field(ctx, "__close", methods.get_value(ctx, "close"));

    let stdout = new_handle(ctx, meta, fs.stdout(), true);
    // `IO_OUTPUT` in the registry: here, a field of a private table.
    let state = Table::new(&ctx);
    state.set_field(ctx, "output", stdout);
    io.set_field(ctx, "stdout", stdout);

    let fs = Io { fs };
    let shared = Rc::new(fs);
    io.set_field(
        ctx,
        "open",
        Callback::from_fn_with(
            &ctx,
            (
                Io {
                    fs: shared.fs.clone(),
                },
                meta,
            ),
            |(io, meta), ctx, _, mut stack| io_open(ctx, &*io.fs, *meta, &mut stack),
        ),
    );
    io.set_field(
        ctx,
        "lines",
        Callback::from_fn_with(
            &ctx,
            (
                Io {
                    fs: shared.fs.clone(),
                },
                meta,
            ),
            |(io, meta), ctx, _, mut stack| io_lines(ctx, &*io.fs, *meta, &mut stack),
        ),
    );
    io.set_field(
        ctx,
        "output",
        Callback::from_fn_with(
            &ctx,
            (
                Io {
                    fs: shared.fs.clone(),
                },
                meta,
                state,
            ),
            |(io, meta, state), ctx, _, mut stack| {
                io_output(ctx, &*io.fs, *meta, *state, &mut stack)
            },
        ),
    );
    io.set_field(
        ctx,
        "write",
        Callback::from_fn_with(&ctx, (meta, state), |&(meta, state), ctx, _, mut stack| {
            let out = state.get_value(ctx, "output");
            stack.push_front(out);
            f_write(ctx, meta, &mut stack)
        }),
    );
    io.set_field(
        ctx,
        "close",
        Callback::from_fn_with(&ctx, (meta, state), |&(meta, state), ctx, _, mut stack| {
            if stack.get(0).is_nil() {
                stack.clear();
                stack.push_back(state.get_value(ctx, "output"));
            }
            f_close(ctx, meta, &mut stack)
        }),
    );
    io.set_field(
        ctx,
        "flush",
        Callback::from_fn_with(&ctx, (meta, state), |&(meta, state), ctx, _, mut stack| {
            stack.clear();
            stack.push_back(state.get_value(ctx, "output"));
            f_flush(ctx, meta, &mut stack)
        }),
    );
    io.set_field(
        ctx,
        "type",
        Callback::from_fn_with(&ctx, meta, |&meta, ctx, _, mut stack| {
            let v = match handle_of(meta, stack.get(0)) {
                None => Value::Nil,
                Some(h) if h.0.borrow().file.is_none() => "closed file".into_value(ctx),
                Some(_) => "file".into_value(ctx),
            };
            stack.replace(ctx, v);
            Ok(CallbackReturn::Return)
        }),
    );
    ctx.set_global("io", io);
    // `luaB_print` writes to the C library's `stdout`, not to `io.output()`.
    let out = Rc::new(RefCell::new(shared.fs.stdout()));
    ctx.set_global(
        "print",
        Callback::from_fn_with(&ctx, Out(out), |out, ctx, _, mut stack| {
            let args: Vec<Value<'gc>> = stack.drain(..).collect();
            Ok(CallbackReturn::Sequence(BoxSequence::new(
                &ctx,
                Print {
                    out: Out(out.0.clone()),
                    args,
                    next: 0,
                    line: Vec::new(),
                    waiting: false,
                },
            )))
        }),
    );
    io
}

/// The output `print` writes to.
#[derive(Collect)]
#[collect(require_static)]
struct Out(Rc<RefCell<Box<dyn ScriptFile>>>);

/// `luaB_print`: each argument through `luaL_tolstring` — a `__tostring`
/// metamethod is called — separated by tabs, then a newline.
#[derive(Collect)]
#[collect(no_drop)]
struct Print<'gc> {
    out: Out,
    args: Vec<Value<'gc>>,
    #[collect(require_static)]
    next: usize,
    #[collect(require_static)]
    line: Vec<u8>,
    /// A `__tostring` call has been made for argument `next - 1`.
    #[collect(require_static)]
    waiting: bool,
}

impl<'gc> Print<'gc> {
    fn add(&mut self, ctx: Context<'gc>, v: Value<'gc>) -> Result<(), Error<'gc>> {
        let Some(s) = v.into_string(ctx) else {
            return Err(lua_error(ctx, "'__tostring' must return a string"));
        };
        if self.next > 1 {
            self.line.push(b'\t');
        }
        self.line.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

impl<'gc> Sequence<'gc> for Print<'gc> {
    #[allow(clippy::arithmetic_side_effects)] // `next` is below `args.len()`
    fn poll(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let this = self.get_mut();
        if this.waiting {
            // The `__tostring` result for the previous argument.
            this.waiting = false;
            let v = stack.get(0);
            stack.clear();
            this.add(ctx, v)?;
        }
        while this.next < this.args.len() {
            let v = this.args[this.next];
            this.next += 1;
            match meta_ops::tostring(ctx, v)? {
                MetaResult::Value(v) => this.add(ctx, v)?,
                MetaResult::Call(call) => {
                    this.waiting = true;
                    stack.clear();
                    stack.extend(call.args);
                    return Ok(SequencePoll::Call {
                        bottom: 0,
                        function: call.function,
                    });
                }
            }
        }
        this.line.push(b'\n');
        let mut out = this.out.0.borrow_mut();
        let _ = out.write(&this.line);
        let _ = out.flush();
        stack.clear();
        Ok(SequencePoll::Return)
    }
}

fn new_handle<'gc>(
    ctx: Context<'gc>,
    meta: Table<'gc>,
    file: Box<dyn ScriptFile>,
    std: bool,
) -> Value<'gc> {
    let ud = UserData::new_static(&ctx, Handle(RefCell::new(Stream::new(file, std))));
    ud.set_metatable(&ctx, Some(meta));
    Value::UserData(ud)
}

/// The handle `v` is, if it is one of this library's.
fn handle_of<'gc>(meta: Table<'gc>, v: Value<'gc>) -> Option<&'gc Handle> {
    let Value::UserData(ud) = v else { return None };
    if ud.metatable() != Some(meta) {
        return None;
    }
    ud.downcast_static::<Handle>().ok()
}

fn raise<'gc>(ctx: Context<'gc>, name: &str, e: PackError) -> Error<'gc> {
    lua_error(ctx, &e.lua_message(name))
}

/// `tolstream` then `tofile`: argument 1 as an open file.
fn to_file<'gc>(
    ctx: Context<'gc>,
    meta: Table<'gc>,
    stack: &Stack<'gc, '_>,
    fname: &str,
) -> Result<&'gc Handle, Error<'gc>> {
    let v = stack.get(0);
    let Some(h) = handle_of(meta, v) else {
        let got = if stack.is_empty() {
            "no value"
        } else {
            v.type_name()
        };
        return Err(raise(
            ctx,
            fname,
            PackError::bad_argument(1, format!("FILE* expected, got {got}")),
        ));
    };
    if h.0.borrow().file.is_none() {
        return Err(lua_error(ctx, "attempt to use a closed file"));
    }
    Ok(h)
}

/// `luaL_fileresult(L, 0, fname)`: `nil`, the message, `errno`.
fn file_failure<'gc>(
    ctx: Context<'gc>,
    stack: &mut Stack<'gc, '_>,
    e: &FsError,
    fname: Option<&[u8]>,
) {
    let mut msg = Vec::new();
    if let Some(f) = fname {
        msg.extend_from_slice(f);
        msg.extend_from_slice(b": ");
    }
    msg.extend_from_slice(e.message.as_bytes());
    stack.replace(ctx, (Value::Nil, ctx.intern(&msg), e.errno));
}

/// `io.open(filename [, mode])`.
fn io_open<'gc>(
    ctx: Context<'gc>,
    fs: &dyn ScriptFs,
    meta: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let (name, mode) = {
        let args = LuaArgs { ctx, stack };
        let name = args
            .string(1)
            .map_err(|e| raise(ctx, "open", e))?
            .into_owned();
        let mode = match args.get(2) {
            None | Some(Value::Nil) => b"r".to_vec(),
            Some(_) => args
                .string(2)
                .map_err(|e| raise(ctx, "open", e))?
                .into_owned(),
        };
        (name, mode)
    };
    let Some(mode) = OpenMode::parse(&mode) else {
        return Err(raise(
            ctx,
            "open",
            PackError::bad_argument(2, "invalid mode"),
        ));
    };
    let path = until_nul(&name);
    match fs.open(path, mode) {
        Ok(file) => {
            let h = new_handle(ctx, meta, file, false);
            stack.replace(ctx, h);
        }
        Err(e) => file_failure(ctx, stack, &e, Some(path)),
    }
    Ok(CallbackReturn::Return)
}

/// The bytes of a Lua string up to its first NUL: what `fopen` sees.
fn until_nul(s: &[u8]) -> &[u8] {
    s.iter().position(|&b| b == 0).map_or(s, |i| &s[..i])
}

/// `opencheckfile`: open, or raise `"NAME: message"`.
fn open_check<'gc>(
    ctx: Context<'gc>,
    fs: &dyn ScriptFs,
    meta: Table<'gc>,
    name: &[u8],
    mode: OpenMode,
) -> Result<Value<'gc>, Error<'gc>> {
    let path = until_nul(name);
    match fs.open(path, mode) {
        Ok(file) => Ok(new_handle(ctx, meta, file, false)),
        Err(e) => {
            let mut msg = b"cannot open file '".to_vec();
            msg.extend_from_slice(path);
            msg.extend_from_slice(b"' (");
            msg.extend_from_slice(e.message.as_bytes());
            msg.push(b')');
            Err(lua_error_bytes(ctx, &msg))
        }
    }
}

/// `io.lines(filename, ...)`.
fn io_lines<'gc>(
    ctx: Context<'gc>,
    fs: &dyn ScriptFs,
    meta: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    if stack.get(0).is_nil() {
        // The default input is standard input, which scripts do not get.
        return Err(lua_error(ctx, "standard input is not available to scripts"));
    }
    let name = {
        let args = LuaArgs { ctx, stack };
        args.string(1)
            .map_err(|e| raise(ctx, "lines", e))?
            .into_owned()
    };
    let file = open_check(
        ctx,
        fs,
        meta,
        &name,
        OpenMode {
            base: b'r',
            update: false,
        },
    )?;
    let formats: Vec<Value<'gc>> = (1..stack.len()).map(|i| stack.get(i)).collect();
    let iter = lines_iterator(ctx, meta, file, formats, true)?;
    stack.replace(ctx, (iter, Value::Nil, Value::Nil, file));
    Ok(CallbackReturn::Return)
}

/// `MAXARGLINE`.
const MAX_ARG_LINE: usize = 250;

/// `aux_lines`: the iterator `io_readline` is.
#[allow(clippy::arithmetic_side_effects)] // at most `MAX_ARG_LINE` formats, checked first
fn lines_iterator<'gc>(
    ctx: Context<'gc>,
    meta: Table<'gc>,
    file: Value<'gc>,
    formats: Vec<Value<'gc>>,
    to_close: bool,
) -> Result<Function<'gc>, Error<'gc>> {
    if formats.len() > MAX_ARG_LINE {
        return Err(raise(
            ctx,
            "lines",
            PackError::bad_argument(MAX_ARG_LINE + 2, "too many arguments"),
        ));
    }
    let formats_t = Table::new(&ctx);
    for (i, f) in formats.iter().enumerate() {
        formats_t.set(ctx, i64::try_from(i + 1).unwrap_or(i64::MAX), *f)?;
    }
    let n = formats.len();
    Ok(Callback::from_fn_with(
        &ctx,
        (meta, file, formats_t, n, to_close),
        |&(meta, file, formats_t, n, to_close), ctx, _, mut stack| {
            let Some(h) = handle_of(meta, file) else {
                return Err(lua_error(ctx, "file is already closed"));
            };
            if h.0.borrow().file.is_none() {
                return Err(lua_error(ctx, "file is already closed"));
            }
            stack.clear();
            stack.push_back(file);
            for i in 1..=n {
                stack.push_back(formats_t.get_value(ctx, i64::try_from(i).unwrap_or(i64::MAX)));
            }
            g_read(ctx, h, &mut stack, 2)?;
            if stack.get(0).to_bool() {
                return Ok(CallbackReturn::Return);
            }
            if stack.len() > 1 {
                // `g_read`'s failure: nil, message, errno.
                let msg = stack.get(1).into_string(ctx).map(|s| s.as_bytes().to_vec());
                return Err(lua_error_bytes(ctx, &msg.unwrap_or_default()));
            }
            if to_close {
                close_stream(&mut h.0.borrow_mut());
            }
            stack.clear();
            Ok(CallbackReturn::Return)
        },
    )
    .into())
}

/// `file:read(...)`.
fn f_read<'gc>(
    ctx: Context<'gc>,
    meta: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let h = to_file(ctx, meta, stack, "read")?;
    g_read(ctx, h, stack, 2)?;
    Ok(CallbackReturn::Return)
}

/// One result of a read: a value, and whether it succeeded.
enum Got {
    Bytes(Vec<u8>, bool),
    Number(Option<Value<'static>>),
}

/// `g_read`: the formats from argument `first` on, read in turn until one
/// fails, which yields `nil` in its place.
#[allow(clippy::arithmetic_side_effects)] // `first` is 1 or 2 and `nargs` at most the stack's length
fn g_read<'gc>(
    ctx: Context<'gc>,
    h: &Handle,
    stack: &mut Stack<'gc, '_>,
    first: usize,
) -> Result<(), Error<'gc>> {
    let nargs = stack.len().saturating_sub(first - 1);
    let mut results: Vec<Value<'gc>> = Vec::new();
    let mut stream = h.0.borrow_mut();
    let mut failure: Option<FsError> = None;
    let mut push = |got: Result<Got, FsError>, results: &mut Vec<Value<'gc>>| -> bool {
        match got {
            Ok(Got::Bytes(b, ok)) => {
                results.push(if ok {
                    Value::String(ctx.intern(&b))
                } else {
                    Value::Nil
                });
                ok
            }
            Ok(Got::Number(Some(v))) => {
                results.push(match v {
                    Value::Integer(i) => Value::Integer(i),
                    Value::Number(n) => Value::Number(n),
                    _ => Value::Nil,
                });
                true
            }
            Ok(Got::Number(None)) => {
                results.push(Value::Nil);
                false
            }
            Err(e) => {
                failure = Some(e);
                false
            }
        }
    };
    if nargs == 0 {
        push(read_line(&mut stream, true), &mut results);
    } else {
        for n in first..first + nargs {
            let arg = stack.get(n - 1);
            let got = match arg {
                Value::Integer(_) | Value::Number(_) => {
                    let l = {
                        let args = LuaArgs { ctx, stack };
                        args.check_integer(n).map_err(|e| raise(ctx, "read", e))?
                    };
                    // `(size_t)l`: a negative count is a buffer no allocator
                    // grants, and `luaL_prepbuffsize` fails with the memory
                    // error.
                    let Ok(l) = usize::try_from(l) else {
                        return Err(ctx.not_enough_memory());
                    };
                    if l == 0 {
                        test_eof(&mut stream)
                    } else {
                        read_chars(&mut stream, l)
                    }
                }
                _ => {
                    let p = {
                        let args = LuaArgs { ctx, stack };
                        args.string(n)
                            .map_err(|e| raise(ctx, "read", e))?
                            .into_owned()
                    };
                    let p = p.strip_prefix(b"*").unwrap_or(&p);
                    match p.first() {
                        Some(b'n') => read_number(&mut stream),
                        Some(b'l') => read_line(&mut stream, true),
                        Some(b'L') => read_line(&mut stream, false),
                        Some(b'a') => read_all(&mut stream),
                        _ => {
                            return Err(raise(
                                ctx,
                                "read",
                                PackError::bad_argument(n, "invalid format"),
                            ))
                        }
                    }
                }
            };
            if !push(got, &mut results) {
                break;
            }
        }
    }
    drop(stream);
    stack.clear();
    if let Some(e) = failure {
        file_failure(ctx, stack, &e, None);
        return Ok(());
    }
    stack.extend(results);
    Ok(())
}

/// `test_eof`: `""` unless at end of file.
fn test_eof(s: &mut Stream) -> Result<Got, FsError> {
    let c = s.getc()?;
    if c.is_some() {
        s.ungetc();
    }
    Ok(Got::Bytes(Vec::new(), c.is_some()))
}

/// `read_chars`.
fn read_chars(s: &mut Stream, n: usize) -> Result<Got, FsError> {
    let mut out = Vec::new();
    if !reserve(&mut out, n.min(BUFFER_SIZE * 64)) {
        return Err(FsError {
            message: "not enough memory".into(),
            errno: 12,
        });
    }
    let got = s.read_into(&mut out, n)?;
    Ok(Got::Bytes(out, got > 0))
}

/// `read_all`.
fn read_all(s: &mut Stream) -> Result<Got, FsError> {
    let mut out = Vec::new();
    loop {
        if !reserve(&mut out, BUFFER_SIZE) {
            return Err(FsError {
                message: "not enough memory".into(),
                errno: 12,
            });
        }
        if s.read_into(&mut out, BUFFER_SIZE)? < BUFFER_SIZE {
            break;
        }
    }
    Ok(Got::Bytes(out, true))
}

/// `read_line`: up to a newline, which `chop` leaves off.
fn read_line(s: &mut Stream, chop: bool) -> Result<Got, FsError> {
    let mut out = Vec::new();
    let mut newline = false;
    while let Some(c) = s.getc()? {
        if c == b'\n' {
            newline = true;
            break;
        }
        if !reserve(&mut out, 1) {
            return Err(FsError {
                message: "not enough memory".into(),
                errno: 12,
            });
        }
        out.push(c);
    }
    if newline && !chop {
        out.push(b'\n');
    }
    let ok = newline || !out.is_empty();
    Ok(Got::Bytes(out, ok))
}

/// `read_number`: the longest prefix of a numeral, then
/// `lua_stringtonumber` on it.
#[allow(clippy::arithmetic_side_effects)] // counts of bytes read, at most `L_MAXLENNUM` + 1
fn read_number(s: &mut Stream) -> Result<Got, FsError> {
    struct Rn<'a> {
        s: &'a mut Stream,
        c: Option<u8>,
        buf: Vec<u8>,
        overflow: bool,
    }
    impl Rn<'_> {
        fn nextc(&mut self) -> Result<bool, FsError> {
            if self.buf.len() >= MAX_LEN_NUM {
                self.overflow = true;
                return Ok(false);
            }
            if let Some(c) = self.c {
                self.buf.push(c);
            }
            self.c = self.s.getc()?;
            Ok(true)
        }
        fn test2(&mut self, set: &[u8; 2]) -> Result<bool, FsError> {
            match self.c {
                Some(c) if c == set[0] || c == set[1] => self.nextc(),
                _ => Ok(false),
            }
        }
        fn digits(&mut self, hex: bool) -> Result<usize, FsError> {
            let mut count = 0;
            while let Some(c) = self.c {
                let ok = if hex {
                    c.is_ascii_hexdigit()
                } else {
                    c.is_ascii_digit()
                };
                if !ok || !self.nextc()? {
                    break;
                }
                count += 1;
            }
            Ok(count)
        }
    }
    let mut c = s.getc()?;
    // `isspace` in the C locale.
    while matches!(c, Some(b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')) {
        c = s.getc()?;
    }
    let mut rn = Rn {
        s,
        c,
        buf: Vec::new(),
        overflow: false,
    };
    let mut count = 0;
    let mut hex = false;
    rn.test2(b"-+")?;
    if rn.test2(b"00")? {
        if rn.test2(b"xX")? {
            hex = true;
        } else {
            count = 1;
        }
    }
    count += rn.digits(hex)?;
    if rn.test2(b"..")? {
        count += rn.digits(hex)?;
    }
    if count > 0 && rn.test2(if hex { b"pP" } else { b"eE" })? {
        rn.test2(b"-+")?;
        rn.digits(false)?;
    }
    if rn.c.is_some() {
        rn.s.ungetc();
    }
    if rn.overflow {
        return Ok(Got::Number(None));
    }
    let text = String::from_utf8_lossy(&rn.buf).into_owned();
    Ok(Got::Number(string_to_number(&text)))
}

/// `lua_stringtonumber` on a numeral `read_number` collected: the VM's own
/// conversion (`luaO_str2num`), an integer when the numeral is one.
fn string_to_number(text: &str) -> Option<Value<'static>> {
    match piccolo::Constant::<&[u8]>::String(text.as_bytes()).to_numeric()? {
        piccolo::Constant::Integer(i) => Some(Value::Integer(i)),
        piccolo::Constant::Number(n) => Some(Value::Number(n)),
        _ => None,
    }
}

/// `file:write(...)`: the file, or `nil`, message, `errno`.
#[allow(clippy::arithmetic_side_effects)] // `arg` is at least 2
fn f_write<'gc>(
    ctx: Context<'gc>,
    meta: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let h = to_file(ctx, meta, stack, "write")?;
    let file = stack.get(0);
    let mut pieces: Vec<Vec<u8>> = Vec::new();
    {
        let args = LuaArgs { ctx, stack };
        for arg in 2..=stack.len() {
            let v = stack.get(arg - 1);
            pieces.push(match v {
                // `LUA_INTEGER_FMT` and `LUA_NUMBER_FMT` ("%.14g").
                Value::Integer(i) => i.to_string().into_bytes(),
                Value::Number(n) => super::strformat::lua_number_fmt(n),
                _ => args
                    .string(arg)
                    .map_err(|e| raise(ctx, "write", e))?
                    .into_owned(),
            });
        }
    }
    let mut stream = h.0.borrow_mut();
    let result = stream.sync().and_then(|()| {
        for p in &pieces {
            stream.file().write(p)?;
        }
        Ok(())
    });
    drop(stream);
    match result {
        Ok(()) => stack.replace(ctx, file),
        Err(e) => file_failure(ctx, stack, &e, None),
    }
    Ok(CallbackReturn::Return)
}

/// `file:lines(...)`.
fn f_lines<'gc>(
    ctx: Context<'gc>,
    meta: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    to_file(ctx, meta, stack, "lines")?;
    let file = stack.get(0);
    let formats: Vec<Value<'gc>> = (1..stack.len()).map(|i| stack.get(i)).collect();
    let iter = lines_iterator(ctx, meta, file, formats, false)?;
    stack.replace(ctx, iter);
    Ok(CallbackReturn::Return)
}

fn close_stream(s: &mut Stream) {
    let _ = s.sync();
    if let Some(mut f) = s.file.take() {
        let _ = f.flush();
    }
}

/// `file:close()`. The standard output cannot be closed, as `io_noclose`
/// refuses: `nil`, "cannot close standard file".
fn f_close<'gc>(
    ctx: Context<'gc>,
    meta: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let h = to_file(ctx, meta, stack, "close")?;
    let mut s = h.0.borrow_mut();
    if s.std {
        drop(s);
        stack.replace(ctx, (Value::Nil, "cannot close standard file"));
        return Ok(CallbackReturn::Return);
    }
    close_stream(&mut s);
    drop(s);
    stack.replace(ctx, true);
    Ok(CallbackReturn::Return)
}

/// `file:flush()`: `true`, or `nil`, message, `errno`.
fn f_flush<'gc>(
    ctx: Context<'gc>,
    meta: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let h = to_file(ctx, meta, stack, "flush")?;
    let r = {
        let mut s = h.0.borrow_mut();
        s.sync().and_then(|()| s.file().flush())
    };
    match r {
        Ok(()) => stack.replace(ctx, true),
        Err(e) => file_failure(ctx, stack, &e, None),
    }
    Ok(CallbackReturn::Return)
}

/// `file:seek([whence [, offset]])`.
fn f_seek<'gc>(
    ctx: Context<'gc>,
    meta: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let h = to_file(ctx, meta, stack, "seek")?;
    let (whence, offset) = {
        let args = LuaArgs { ctx, stack };
        let whence = match args.get(2) {
            None | Some(Value::Nil) => Whence::Cur,
            Some(_) => match &*args.string(2).map_err(|e| raise(ctx, "seek", e))? {
                b"set" => Whence::Set,
                b"cur" => Whence::Cur,
                b"end" => Whence::End,
                other => {
                    let msg = format!("invalid option '{}'", String::from_utf8_lossy(other));
                    return Err(raise(ctx, "seek", PackError::bad_argument(2, msg)));
                }
            },
        };
        let offset = match args.get(3) {
            None | Some(Value::Nil) => 0,
            Some(_) => args.check_integer(3).map_err(|e| raise(ctx, "seek", e))?,
        };
        (whence, offset)
    };
    let r = {
        let mut s = h.0.borrow_mut();
        s.sync().and_then(|()| s.file().seek(whence, offset))
    };
    match r {
        Ok(p) => stack.replace(ctx, i64::try_from(p).unwrap_or(i64::MAX)),
        Err(e) => file_failure(ctx, stack, &e, None),
    }
    Ok(CallbackReturn::Return)
}

/// `file:setvbuf(mode [, size])`: the mode is checked, and buffering left as
/// it is.
fn f_setvbuf<'gc>(
    ctx: Context<'gc>,
    meta: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    to_file(ctx, meta, stack, "setvbuf")?;
    {
        let args = LuaArgs { ctx, stack };
        let mode = args.string(2).map_err(|e| raise(ctx, "setvbuf", e))?;
        if !matches!(&*mode, b"no" | b"full" | b"line") {
            let msg = format!("invalid option '{}'", String::from_utf8_lossy(&mode));
            return Err(raise(ctx, "setvbuf", PackError::bad_argument(2, msg)));
        }
    }
    stack.replace(ctx, true);
    Ok(CallbackReturn::Return)
}

/// `__tostring`.
fn f_tostring<'gc>(
    ctx: Context<'gc>,
    _: piccolo::Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let v = stack.get(0);
    let s = match v {
        Value::UserData(ud) => match ud.downcast_static::<Handle>() {
            Ok(h) if h.0.borrow().file.is_none() => "file (closed)".to_string(),
            Ok(h) => format!("file ({:p})", h as *const Handle),
            Err(_) => "file".to_string(),
        },
        _ => "file".to_string(),
    };
    stack.replace(ctx, ctx.intern(s.as_bytes()));
    Ok(CallbackReturn::Return)
}

/// `io.output([file])`.
fn io_output<'gc>(
    ctx: Context<'gc>,
    fs: &dyn ScriptFs,
    meta: Table<'gc>,
    state: Table<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let arg = stack.get(0);
    match arg {
        Value::Nil => {}
        Value::String(_) | Value::Integer(_) | Value::Number(_) => {
            let name = arg
                .into_string(ctx)
                .expect("a string or number")
                .as_bytes()
                .to_vec();
            let file = open_check(
                ctx,
                fs,
                meta,
                &name,
                OpenMode {
                    base: b'w',
                    update: false,
                },
            )?;
            state.set(ctx, "output", file)?;
        }
        _ => {
            to_file(ctx, meta, stack, "output")?;
            state.set(ctx, "output", arg)?;
        }
    }
    stack.replace(ctx, state.get_value(ctx, "output"));
    Ok(CallbackReturn::Return)
}
