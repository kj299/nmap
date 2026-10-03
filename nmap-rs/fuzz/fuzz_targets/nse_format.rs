// cargo-fuzz target for `nmap_core::nse::stdlib::strformat`.
//
// `string.format` is Lua's validation of each conversion specification in
// front of the C library's `printf`. The port reimplements the `printf` half,
// so this target checks it against the real thing: for every specification
// Lua's rules accept, it builds the specification `str_format` would hand to
// `snprintf` — the same flags, width and precision, `ll` for integers, an
// `int` for `%c`, a `double` for floats — calls glibc's `snprintf` in-process,
// and requires the same bytes. That makes every fuzz input a differential
// against the oracle's own `printf`, at fuzzing speed, for exactly the
// conversions NSE scripts use (`%d %x %s %f`) and the ones they do not.
//
// The properties checked:
//
//   * `format` is TOTAL: any format and arguments give a string or a Lua
//     error, never a panic;
//   * a single conversion that Lua accepts produces exactly what glibc's
//     `snprintf` produces for the same specification and argument.
//
// Input layout: byte 0 picks the conversion, byte 1 the specification length,
// then the flag/width/precision bytes, then 8 bytes of argument. The rest is
// also run as a whole format string with mixed arguments, for totality.
#![no_main]

use std::borrow::Cow;
use std::ffi::{c_char, c_int, c_longlong, CString};

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::stdlib::strformat::{format, FormatArgs, Literal};
use nmap_core::nse::stdlib::strpack::PackError;

extern "C" {
    fn snprintf(buf: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
}

#[derive(Clone, Copy)]
enum Arg<'a> {
    I(i64),
    F(f64),
    S(&'a [u8]),
}

struct Args<'a>(Vec<Arg<'a>>);

impl FormatArgs for Args<'_> {
    fn count(&self) -> usize {
        self.0.len() + 1
    }
    fn integer(&mut self, arg: usize) -> Result<i64, PackError> {
        match self.0.get(arg - 2) {
            Some(Arg::I(n)) => Ok(*n),
            _ => Err(PackError::bad_argument(arg, "number expected")),
        }
    }
    fn number(&mut self, arg: usize) -> Result<f64, PackError> {
        match self.0.get(arg - 2) {
            Some(Arg::I(n)) => Ok(*n as f64),
            Some(Arg::F(x)) => Ok(*x),
            _ => Err(PackError::bad_argument(arg, "number expected")),
        }
    }
    fn tostring(&mut self, arg: usize) -> Result<Option<Cow<'_, [u8]>>, PackError> {
        Ok(Some(match self.0.get(arg - 2) {
            Some(Arg::S(s)) => Cow::Borrowed(*s),
            Some(Arg::I(n)) => Cow::Owned(n.to_string().into_bytes()),
            Some(Arg::F(x)) => Cow::Owned(format!("{x:?}").into_bytes()),
            None => Cow::Borrowed(b"nil"),
        }))
    }
    fn literal(&mut self, arg: usize) -> Result<Literal<'_>, PackError> {
        Ok(match self.0.get(arg - 2) {
            Some(Arg::S(s)) => Literal::Str(Cow::Borrowed(*s)),
            Some(Arg::I(n)) => Literal::Integer(*n),
            Some(Arg::F(x)) => Literal::Float(*x),
            None => Literal::Text("nil"),
        })
    }
    fn pointer(&mut self, _arg: usize) -> Option<usize> {
        None
    }
}

/// glibc's answer for one specification and argument.
fn glibc(spec: &[u8], arg: Arg<'_>) -> Vec<u8> {
    let fmt = CString::new(spec).expect("specifications contain no NUL");
    let mut buf = vec![0u8; 1024];
    // SAFETY: `fmt` is a NUL-terminated specification this target built from
    // one conversion Lua accepted, so it consumes exactly one argument, and the
    // argument passed has the C type that conversion reads: `long long` for
    // `d i u o x X` (the `ll` added below), `int` for `c`, `double` for
    // `a A e E f g G`, and a NUL-terminated `char *` for `s`. The buffer's
    // length is passed, so `snprintf` writes at most that many bytes; the
    // longest item a two-digit width and precision allow is 99 digits plus a
    // 309-digit integer part, well inside 1,024.
    let n = unsafe {
        match arg {
            Arg::I(v) if spec.ends_with(b"c") => {
                snprintf(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), v as c_int)
            }
            Arg::I(v) => snprintf(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), v as c_longlong),
            Arg::F(x) => snprintf(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), x),
            Arg::S(s) => {
                let c = CString::new(s).expect("callers pass no NUL");
                snprintf(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), c.as_ptr())
            }
        }
    };
    buf.truncate(usize::try_from(n).expect("snprintf succeeded"));
    buf
}

const CONVS: &[u8] = b"diuoxXcaAeEfgGs";

fuzz_target!(|input: &[u8]| {
    let [sel, len, rest @ ..] = input else {
        return;
    };
    let conv = CONVS[usize::from(*sel) % CONVS.len()];
    let (body, rest) = rest.split_at(usize::from(*len % 24).min(rest.len()));
    // Only the bytes Lua's `getformat` spans can be in a specification body.
    if !body.iter().all(|b| b"-+ #0123456789.".contains(b)) {
        return;
    }
    let mut word = [0u8; 8];
    let take = rest.len().min(8);
    word[..take].copy_from_slice(&rest[..take]);
    let tail = &rest[take..];
    let bits = u64::from_le_bytes(word);

    let arg = match conv {
        b'a' | b'A' | b'e' | b'E' | b'f' | b'g' | b'G' => Arg::F(f64::from_bits(bits)),
        b's' => {
            // A NUL-free string, so that glibc's `%s` sees all of it.
            let s = &tail[..tail.iter().position(|&b| b == 0).unwrap_or(tail.len())];
            Arg::S(&s[..s.len().min(200)])
        }
        _ => Arg::I(bits as i64),
    };
    let mut spec = vec![b'%'];
    spec.extend_from_slice(body);
    spec.push(conv);

    if let Ok(ours) = format(&spec, &mut Args(vec![arg])) {
        // `%s` without a precision and 100 bytes or more is kept whole by Lua
        // itself, before `printf` is reached.
        let lua_bypass = conv == b's'
            && !body.contains(&b'.')
            && matches!(arg, Arg::S(s) if s.len() >= 100 || body.is_empty());
        if !lua_bypass {
            let mut c_spec = spec.clone();
            if matches!(conv, b'd' | b'i' | b'u' | b'o' | b'x' | b'X') {
                c_spec.splice(c_spec.len() - 1..c_spec.len() - 1, *b"ll");
            }
            let theirs = glibc(&c_spec, arg);
            assert_eq!(
                ours,
                theirs,
                "{:?} on {:?}: ours {:?}, glibc {:?}",
                String::from_utf8_lossy(&spec),
                match arg {
                    Arg::I(v) => format!("{v}"),
                    Arg::F(x) => format!("{x:?} ({:#x})", x.to_bits()),
                    Arg::S(s) => format!("{s:?}"),
                },
                String::from_utf8_lossy(&ours),
                String::from_utf8_lossy(&theirs),
            );
        }
    }

    // Totality over a whole format string with mixed arguments.
    let args = vec![Arg::I(bits as i64), Arg::F(f64::from_bits(bits.rotate_left(17))), Arg::S(b"abc"), Arg::I(-1)];
    let _ = format(tail, &mut Args(args));
});
