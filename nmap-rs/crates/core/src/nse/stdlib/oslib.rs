//! The `os` library NSE scripts get: the clock, and nothing else.
//!
//! PUC-Lua's `os` also runs commands (`execute`), removes and renames files,
//! makes temporary names, reads the environment and exits the process. A
//! script selected with `--script` runs as whoever runs nmap — often root —
//! so those would make every script a full shell. Decision 2
//! (`docs/M6-ANALYSIS.md`) measured what the 744 shipped Lua files use: none
//! of them, outside two unit-test self-checks. They are not provided
//! (`os-is-the-clock`, DIVERGENCES.md); what is, is ported from `loslib.c`.

use gc_arena::Collect;
use piccolo::{Callback, CallbackReturn, Context, Error, Stack, Table, Value};
use std::rc::Rc;

use super::osdate::{
    check_option, gmtime, invalid_conversion, localtime, mktime, strftime, Tm, TmInput,
};
use super::strpack::PackError;
use super::{lua_error, lua_error_bytes, LuaArgs};

/// What the `os` library reads from the system.
pub struct OsEnv {
    /// `time(NULL)`: seconds since the epoch.
    pub now: Box<dyn Fn() -> i64>,
    /// `clock() / CLOCKS_PER_SEC`: processor time used, in seconds.
    pub cpu_seconds: Box<dyn Fn() -> f64>,
    /// The home directory `os.getenv("HOME")` reports, if any.
    pub home: Option<Vec<u8>>,
}

#[derive(Collect)]
#[collect(require_static)]
struct Env(Rc<OsEnv>);

/// Installs `os` — `clock`, `date`, `difftime`, `time` — into `ctx`'s
/// globals, and returns it.
pub fn load_os<'gc>(ctx: Context<'gc>, env: Rc<OsEnv>) -> Table<'gc> {
    let os = Table::new(&ctx);
    let e = Env(env);
    os.set_field(
        ctx,
        "clock",
        Callback::from_fn_with(&ctx, Env(e.0.clone()), |env, ctx, _, mut stack| {
            stack.replace(ctx, (env.0.cpu_seconds)());
            Ok(CallbackReturn::Return)
        }),
    );
    os.set_field(
        ctx,
        "date",
        Callback::from_fn_with(&ctx, Env(e.0.clone()), |env, ctx, _, mut stack| {
            os_date(ctx, &env.0, &mut stack)
        }),
    );
    os.set_field(
        ctx,
        "time",
        Callback::from_fn_with(&ctx, Env(e.0.clone()), |env, ctx, _, mut stack| {
            os_time(ctx, &env.0, &mut stack)
        }),
    );
    os.set_field(
        ctx,
        "difftime",
        Callback::from_fn(&ctx, |ctx, _, mut stack| {
            let (t1, t2) = {
                let args = LuaArgs { ctx, stack: &stack };
                let t1 = args
                    .check_integer(1)
                    .map_err(|e| raise(ctx, "difftime", e))?;
                let t2 = args
                    .check_integer(2)
                    .map_err(|e| raise(ctx, "difftime", e))?;
                (t1, t2)
            };
            // `difftime` on two `time_t`s, as a double.
            stack.replace(ctx, (t1 as f64) - (t2 as f64));
            Ok(CallbackReturn::Return)
        }),
    );
    // `getenv`, for `HOME` alone: the one variable a shipped Lua file reads
    // (`ssh1.lua:244`). Every other name is unset (`os-getenv-home-only`).
    os.set_field(
        ctx,
        "getenv",
        Callback::from_fn_with(&ctx, Env(e.0.clone()), |env, ctx, _, mut stack| {
            let is_home = {
                let args = LuaArgs { ctx, stack: &stack };
                args.string(1)
                    .map_err(|e| raise(ctx, "getenv", e))?
                    .as_ref()
                    == b"HOME"
            };
            let value = match (&env.0.home, is_home) {
                (Some(home), true) => Value::String(ctx.intern(home)),
                _ => Value::Nil,
            };
            stack.replace(ctx, value);
            Ok(CallbackReturn::Return)
        }),
    );
    ctx.set_global("os", os);
    os
}

fn raise<'gc>(ctx: Context<'gc>, name: &str, e: PackError) -> Error<'gc> {
    lua_error_bytes(ctx, &e.lua_message(name))
}

/// `os_date`.
fn os_date<'gc>(
    ctx: Context<'gc>,
    env: &OsEnv,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let (format, t) = {
        let args = LuaArgs { ctx, stack };
        let format = match args.get(1) {
            None | Some(Value::Nil) => b"%c".to_vec(),
            Some(_) => args
                .string(1)
                .map_err(|e| raise(ctx, "date", e))?
                .into_owned(),
        };
        let t = match args.get(2) {
            None | Some(Value::Nil) => (env.now)(),
            Some(_) => args.check_integer(2).map_err(|e| raise(ctx, "date", e))?,
        };
        (format, t)
    };
    let (utc, mut s) = match format.split_first() {
        Some((b'!', rest)) => (true, rest),
        _ => (false, &format[..]),
    };
    let tm = if utc { gmtime(t) } else { localtime(t) };
    let Some(tm) = tm else {
        return Err(lua_error(
            ctx,
            "date result cannot be represented in this installation",
        ));
    };
    // `strcmp(s, "*t")`: the format read as a C string.
    let c_str = s.iter().position(|&b| b == 0).map_or(s, |i| &s[..i]);
    if c_str == b"*t" {
        let t = Table::new(&ctx);
        set_all_fields(ctx, t, &tm)?;
        stack.replace(ctx, t);
        return Ok(CallbackReturn::Return);
    }
    let mut out = Vec::new();
    while let Some((&c, rest)) = s.split_first() {
        if c != b'%' {
            out.push(c);
            s = rest;
            continue;
        }
        let Some(conv) = check_option(rest) else {
            let msg = String::from_utf8_lossy(&invalid_conversion(rest)).into_owned();
            return Err(raise(ctx, "date", PackError::bad_argument(1, msg)));
        };
        strftime(&mut out, conv, &tm);
        s = &rest[conv.len()..];
    }
    let s = ctx.intern(&out);
    stack.replace(ctx, s);
    Ok(CallbackReturn::Return)
}

/// `setallfields`.
#[allow(clippy::arithmetic_side_effects)] // a `Tm`'s year fits an `i32`; the other fields are small
fn set_all_fields<'gc>(ctx: Context<'gc>, t: Table<'gc>, tm: &Tm) -> Result<(), Error<'gc>> {
    for (k, v) in [
        ("year", tm.year + 1900),
        ("month", tm.mon + 1),
        ("day", tm.mday),
        ("hour", tm.hour),
        ("min", tm.min),
        ("sec", tm.sec),
        ("yday", tm.yday + 1),
        ("wday", tm.wday + 1),
    ] {
        t.set(ctx, k, v)?;
    }
    t.set(ctx, "isdst", tm.isdst)?;
    Ok(())
}

/// `getfield`: the field as a C `int` after subtracting `delta`, `default`
/// when absent (none if negative), or `os.time`'s error.
#[allow(clippy::arithmetic_side_effects)] // `delta` is 0, 1 or 1900, so neither bound check nor result overflows
fn get_field<'gc>(
    ctx: Context<'gc>,
    t: Table<'gc>,
    key: &'static str,
    default: i32,
    delta: i64,
) -> Result<i32, Error<'gc>> {
    let v = t.get_value(ctx, key);
    match v.to_integer() {
        Some(res) => {
            let fits = if res >= 0 {
                res - delta <= i64::from(i32::MAX)
            } else {
                i64::from(i32::MIN) + delta <= res
            };
            if !fits {
                return Err(lua_error(ctx, &format!("field '{key}' is out-of-bound")));
            }
            Ok(i32::try_from(res - delta).expect("checked against INT_MAX/INT_MIN"))
        }
        None if !v.is_nil() => Err(lua_error(ctx, &format!("field '{key}' is not an integer"))),
        None if default < 0 => Err(lua_error(
            ctx,
            &format!("field '{key}' missing in date table"),
        )),
        None => Ok(default),
    }
}

/// `os_time`.
fn os_time<'gc>(
    ctx: Context<'gc>,
    env: &OsEnv,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    let t = match stack.get(0) {
        Value::Nil => (env.now)(),
        Value::Table(table) => {
            let input = TmInput {
                year: get_field(ctx, table, "year", -1, 1900)?,
                mon: get_field(ctx, table, "month", -1, 1)?,
                mday: get_field(ctx, table, "day", -1, 0)?,
                hour: get_field(ctx, table, "hour", 12, 0)?,
                min: get_field(ctx, table, "min", 0, 0)?,
                sec: get_field(ctx, table, "sec", 0, 0)?,
                isdst: match table.get_value(ctx, "isdst") {
                    Value::Nil => -1,
                    v => i32::from(v.to_bool()),
                },
            };
            let cannot = "time result cannot be represented in this installation";
            let Some((t, tm)) = mktime(input) else {
                return Err(lua_error(ctx, cannot));
            };
            // `setallfields` runs before the check for `(time_t)-1`, glibc's
            // error value, so the table is normalised even then.
            set_all_fields(ctx, table, &tm)?;
            if t == -1 {
                return Err(lua_error(ctx, cannot));
            }
            t
        }
        other => {
            let got = if stack.is_empty() {
                "no value"
            } else {
                other.type_name()
            };
            return Err(raise(
                ctx,
                "time",
                PackError::bad_argument(1, format!("table expected, got {got}")),
            ));
        }
    };
    stack.replace(ctx, t);
    Ok(CallbackReturn::Return)
}
