//! The `openssl` module (`nse_openssl.cc`), built step by step as
//! `docs/M6.5-ANALYSIS.md` §11 orders it. Step b: the `BIGNUM` half — the
//! 19 `bignum_*` functions, the 11 methods, and the shared userdata other
//! modules hand scripts (`SSL_CERT`'s RSA `exponent` and `modulus`, step e).
//! Step c: `md4`, `md5`, `sha1`, `ripemd160`, `digest`, `hmac`, `rand_bytes`
//! and `rand_pseudo_bytes`. Step d: `encrypt`, `decrypt` and
//! `DES_string_to_key`.
//!
//! - [`bn`], pure: the values and OpenSSL's semantics over `num-bigint`,
//!   with the operand caps. Fuzzed and run under Miri on its own.
//! - [`digest`], pure: D4(b)'s digests, OpenSSL's names for them, and HMAC.
//! - [`cipher`], pure: D4(b)'s ciphers, their names, and the EVP rules.
//! - [`rand`]: the one randomness seam (E3), for `rand_*` as for the rest.
//! - this file, the binding.
//!
//! **Not registered.** Under D2(D) the module is registered last, at step g,
//! once TLS works and every part is in; until then nothing gives scripts
//! `require "openssl"`, and [`register_for_tests`] opens what exists in the
//! bare states of the module's own tests, the integration tests and the fuzz
//! targets (`runtime::tests::openssl_is_not_registered`, E7).
//!
//! **The userdata** is `luaopen_openssl`'s: a metatable named `BIGNUM`
//! (`__name`), its own `__index`, `__tostring` = `bignum_bn2hex`, the methods,
//! and `__gc`, present and inert (`nse-openssl-bignum-gc-callable`: the C's
//! frees the number, so calling it, which `__index` allows, is a
//! use-after-free; here it checks its argument and does nothing). Every
//! script shares the one metatable, as every script shares the C's. A
//! number's digits are accounted to the VM's heap while it lives, so the
//! memory budget and the collector see them (§1.4).
//!
//! **Errors** are raised as `luaL_error` and `luaL_argerror` raise them: the
//! C's words, after the position of the Lua code that made the call
//! (`luaL_where(L, 1)`). A bad argument names the function as `nmapdb` names
//! its own (`nmapdb-bad-argument-naming`, here
//! `openssl-bad-argument-naming`): from Lua code, by the name it is
//! registered under (`'bignum_add'`, `'tohex'`); otherwise as
//! `pushglobalfuncname` finds the C function in `package.loaded`, which for a
//! method is the library function sharing its C function
//! (`'openssl.bignum_bn2hex'` for `tohex` and `__tostring`) and for `__gc`,
//! which is in no table it searches, `'?'`. `bignum_rand` and
//! `bignum_pseudo_rand` share one C function, which 7.94 names by whichever
//! its search meets first, an order Lua's hash seed decides; the port names
//! the one called (`nse-openssl-rand-alias-name`). A value over a cap
//! ([`bn`], `nse-bignum-operand-cap`) raises "not enough memory", without a
//! position, as an allocation failure does; so do random bytes the memory
//! budget will not hold (`openssl-random-bytes-budget`).
//!
//! **Time.** `is_prime` and `is_safe_prime` run their Miller-Rabin rounds as
//! a [`Sequence`], paying fuel for each, so the VM — and the stall watchdog
//! above it — sees every round (§6); one round of the largest operand takes
//! about a third of a second. `mod_exp` is one native computation and pays
//! its fuel when it returns, as hashing and drawing random bytes do (`fuel_units`
//! for each 64-byte block).

pub mod bn;
pub mod cipher;
pub mod digest;
pub mod rand;

use std::cell::{Ref, RefCell};
use std::pin::Pin;

use gc_arena::metrics::Metrics;
use gc_arena::{Collect, Rootable};
use piccolo::{
    BoxSequence, Callback, CallbackReturn, Context, Error, Execution, Sequence, SequencePoll,
    Singleton, Stack, Table, UserData, Value,
};

use self::bn::{Bn, MillerRabin, Primality, RandomFailed, Refused};
use super::lpeg::narrow;
use super::nmaplib::{c_str, Fail};
use super::stdlib::strpack::PackError;
use super::stdlib::{lua_error, lua_error_bytes, type_error, LuaArgs};

/// The metatable's name (`luaL_newmetatable(L, "BIGNUM")`), and the type
/// name in argument errors.
pub const BIGNUM_T: &str = "BIGNUM";

/// `l_rand_bytes`' and `l_rand_pseudo_bytes`' message when `malloc` fails
/// (`nse_openssl.cc:283,297`): a negative length, which `size_t` makes
/// enormous, or one the allocator refuses. A length the memory budget
/// refuses is the budget's "not enough memory", as for a bignum.
const NO_MEMORY: &str = "Couldn't allocate memory.";

/// The message of a value over a cap, or of bytes the budget refused.
const REFUSED: &str = "not enough memory";

/// What a failed random source raises: `rand_bytes`'s words for the same
/// failure (`nse_openssl.cc:286`; `openssl-random-failure-raises`).
const RANDOM_FAILED: &str = "Failure in RAND_bytes.";

/// A `BIGNUM` userdata: the number, mutable in place (`set_bit` and
/// `clear_bit` change the value every holder of the userdata sees), and its
/// digits accounted to the VM's heap.
pub struct Bignum {
    bn: RefCell<Bn>,
    held: std::cell::Cell<usize>,
    metrics: Metrics,
}

impl Bignum {
    /// The number.
    #[must_use]
    pub fn get(&self) -> Ref<'_, Bn> {
        self.bn.borrow()
    }

    /// Account the number's current size.
    fn account(&self) {
        let now = self.bn.borrow().heap_bytes();
        let was = self.held.replace(now);
        if now > was {
            self.metrics
                .mark_external_allocation(now.saturating_sub(was));
        } else {
            self.metrics
                .mark_external_deallocation(was.saturating_sub(now));
        }
    }
}

impl Drop for Bignum {
    fn drop(&mut self) {
        self.metrics.mark_external_deallocation(self.held.get());
    }
}

/// What `luaopen_openssl` keeps in the registry: the `BIGNUM` metatable.
#[derive(Collect, Clone, Copy)]
#[collect(no_drop)]
struct Registry<'gc> {
    metatable: Table<'gc>,
}

impl<'gc> Singleton<'gc> for Registry<'gc> {
    fn create(ctx: Context<'gc>) -> Self {
        let metatable = Table::new(&ctx);
        metatable.set_field(ctx, "__name", BIGNUM_T);
        metatable.set_field(ctx, "__index", metatable);
        metatable.set_field(ctx, "__tostring", callback(ctx, F::Bn2Hex, "__tostring"));
        for (name, f) in METHODS {
            metatable.set_field(ctx, name, callback(ctx, f, name));
        }
        Registry { metatable }
    }
}

fn registry<'gc>(ctx: Context<'gc>) -> Registry<'gc> {
    *ctx.singleton::<Rootable![Registry<'_>]>()
}

/// A new `BIGNUM` userdata holding `bn` (`nse_pushbn`).
pub fn push_bignum<'gc>(ctx: Context<'gc>, bn: Bn) -> Value<'gc> {
    let b = Bignum {
        bn: RefCell::new(bn),
        held: std::cell::Cell::new(0),
        metrics: ctx.metrics().clone(),
    };
    b.account();
    let u = UserData::new_static(&ctx, b);
    u.set_metatable(&ctx, Some(registry(ctx).metatable));
    Value::UserData(u)
}

/// The `BIGNUM` `v` is, if it is one: a userdata with the `BIGNUM`
/// metatable (`luaL_testudata`).
#[must_use]
pub fn bignum<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Option<&'gc Bignum> {
    let Value::UserData(u) = v else {
        return None;
    };
    if u.metatable() != Some(registry(ctx).metatable) {
        return None;
    }
    u.downcast_static::<Bignum>().ok()
}

/// The functions, each a C function of `nse_openssl.cc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Collect)]
#[collect(require_static)]
enum F {
    NumBits,
    NumBytes,
    SetBit,
    ClearBit,
    IsBitSet,
    IsPrime,
    IsSafePrime,
    Bin2Bn,
    Dec2Bn,
    Hex2Bn,
    Rand,
    Bn2Bin,
    Bn2Mpi,
    Bn2Dec,
    Bn2Hex,
    Add,
    ModExp,
    Div,
    Free,
    Digest,
    Md4,
    Md5,
    Sha1,
    Ripemd160,
    Hmac,
    RandBytes,
    RandPseudoBytes,
    Encrypt,
    Decrypt,
    DesStringToKey,
}

impl F {
    /// The name `pushglobalfuncname` finds for the C function: its entry in
    /// the library table, or none (`l_bignum_free`).
    fn global_name(self) -> Option<&'static str> {
        Some(match self {
            F::NumBits => "openssl.bignum_num_bits",
            F::NumBytes => "openssl.bignum_num_bytes",
            F::SetBit => "openssl.bignum_set_bit",
            F::ClearBit => "openssl.bignum_clear_bit",
            F::IsBitSet => "openssl.bignum_is_bit_set",
            F::IsPrime => "openssl.bignum_is_prime",
            F::IsSafePrime => "openssl.bignum_is_safe_prime",
            F::Bin2Bn => "openssl.bignum_bin2bn",
            F::Dec2Bn => "openssl.bignum_dec2bn",
            F::Hex2Bn => "openssl.bignum_hex2bn",
            F::Rand => return None, // two names: the one called (below)
            F::Bn2Bin => "openssl.bignum_bn2bin",
            F::Bn2Mpi => "openssl.bignum_bn2mpi",
            F::Bn2Dec => "openssl.bignum_bn2dec",
            F::Bn2Hex => "openssl.bignum_bn2hex",
            F::Add => "openssl.bignum_add",
            F::ModExp => "openssl.bignum_mod_exp",
            F::Div => "openssl.bignum_div",
            F::Free => return None,
            F::Digest => "openssl.digest",
            F::Md4 => "openssl.md4",
            F::Md5 => "openssl.md5",
            F::Sha1 => "openssl.sha1",
            F::Ripemd160 => "openssl.ripemd160",
            F::Hmac => "openssl.hmac",
            F::RandBytes => "openssl.rand_bytes",
            F::RandPseudoBytes => "openssl.rand_pseudo_bytes",
            F::Encrypt => "openssl.encrypt",
            F::Decrypt => "openssl.decrypt",
            F::DesStringToKey => "openssl.DES_string_to_key",
        })
    }
}

/// `openssllib`'s entries (`nse_openssl.cc:568-600`): the `BIGNUM` ones
/// (step b), the digests, HMAC and randomness (step c), and the ciphers
/// (step d).
const LIBRARY: [(&str, F); 30] = [
    ("bignum_num_bits", F::NumBits),
    ("bignum_num_bytes", F::NumBytes),
    ("bignum_set_bit", F::SetBit),
    ("bignum_clear_bit", F::ClearBit),
    ("bignum_is_bit_set", F::IsBitSet),
    ("bignum_is_prime", F::IsPrime),
    ("bignum_is_safe_prime", F::IsSafePrime),
    ("bignum_bin2bn", F::Bin2Bn),
    ("bignum_dec2bn", F::Dec2Bn),
    ("bignum_hex2bn", F::Hex2Bn),
    ("bignum_rand", F::Rand),
    ("bignum_pseudo_rand", F::Rand),
    ("bignum_bn2bin", F::Bn2Bin),
    ("bignum_bn2mpi", F::Bn2Mpi),
    ("bignum_bn2dec", F::Bn2Dec),
    ("bignum_bn2hex", F::Bn2Hex),
    ("bignum_add", F::Add),
    ("bignum_mod_exp", F::ModExp),
    ("bignum_div", F::Div),
    ("rand_bytes", F::RandBytes),
    ("rand_pseudo_bytes", F::RandPseudoBytes),
    ("md4", F::Md4),
    ("md5", F::Md5),
    ("sha1", F::Sha1),
    ("ripemd160", F::Ripemd160),
    ("digest", F::Digest),
    ("hmac", F::Hmac),
    ("encrypt", F::Encrypt),
    ("decrypt", F::Decrypt),
    ("DES_string_to_key", F::DesStringToKey),
];

/// `bignum_methods` (`nse_openssl.cc:551-566`; `is_bit_set` is listed twice
/// there, once here).
const METHODS: [(&str, F); 12] = [
    ("num_bits", F::NumBits),
    ("num_bytes", F::NumBytes),
    ("tobin", F::Bn2Bin),
    ("tompi", F::Bn2Mpi),
    ("todec", F::Bn2Dec),
    ("tohex", F::Bn2Hex),
    ("is_bit_set", F::IsBitSet),
    ("set_bit", F::SetBit),
    ("clear_bit", F::ClearBit),
    ("is_prime", F::IsPrime),
    ("is_safe_prime", F::IsSafePrime),
    ("__gc", F::Free),
];

/// One registered entry: the C function and the name it is registered under.
#[derive(Clone, Copy, Collect)]
#[collect(require_static)]
struct Entry {
    f: F,
    name: &'static str,
}

impl Entry {
    /// The name `luaL_argerror` gives the function (see the module's
    /// "Errors").
    fn function_name(self, exec: &Execution<'_, '_>) -> String {
        if exec.frame_info(1).is_some_and(|f| f.lua.is_some()) {
            return self.name.to_string();
        }
        match (self.f, self.f.global_name()) {
            (_, Some(g)) => g.to_string(),
            (F::Rand, None) => format!("openssl.{}", self.name),
            _ => "?".to_string(),
        }
    }
}

/// Why a call failed.
enum Failure {
    /// `luaL_error` or `luaL_argerror`.
    Lua(Fail),
    /// Over a cap or the budget: "not enough memory", unpositioned.
    Refused,
    /// The random source failed.
    Random,
}

impl From<Fail> for Failure {
    fn from(f: Fail) -> Self {
        Failure::Lua(f)
    }
}

impl From<PackError> for Failure {
    fn from(e: PackError) -> Self {
        Failure::Lua(e.into())
    }
}

impl From<Refused> for Failure {
    fn from(_: Refused) -> Self {
        Failure::Refused
    }
}

impl From<RandomFailed> for Failure {
    fn from(_: RandomFailed) -> Self {
        Failure::Random
    }
}

fn raise<'gc>(
    ctx: Context<'gc>,
    exec: &Execution<'gc, '_>,
    e: &Failure,
    entry: Entry,
) -> Error<'gc> {
    match e {
        Failure::Lua(f) => {
            let mut msg = exec.where_at(1);
            msg.extend_from_slice(&f.message(&entry.function_name(exec)));
            lua_error_bytes(ctx, &msg)
        }
        Failure::Refused => lua_error(ctx, REFUSED),
        Failure::Random => {
            let mut msg = exec.where_at(1);
            msg.extend_from_slice(RANDOM_FAILED.as_bytes());
            lua_error_bytes(ctx, &msg)
        }
    }
}

/// `luaL_checkudata(L, arg, "BIGNUM")`.
fn check<'gc>(args: &LuaArgs<'_, 'gc, '_>, arg: usize) -> Result<&'gc Bignum, Fail> {
    let v = args.get(arg);
    v.and_then(|v| bignum(args.ctx, v))
        .ok_or_else(|| type_error(args.ctx, v, arg, BIGNUM_T).into())
}

/// Fuel for `n` word operations of a modular exponentiation (`words^3` for
/// a Miller-Rabin round on numbers of `words` 64-bit words): ten units each,
/// a unit for roughly the 20 ns a VM instruction takes.
fn fuel_units(n: u64) -> i32 {
    i32::try_from(n.saturating_mul(10)).unwrap_or(i32::MAX)
}

/// [`fuel_units`] for one Miller-Rabin round.
fn cubic_fuel(words: u64) -> i32 {
    let w = words.max(1);
    fuel_units(w.saturating_mul(w).saturating_mul(w))
}

/// `EVP_get_digestbyname(name)`, or `l_digest`'s and `l_hmac`'s error: the
/// name up to its first NUL, as `%s` prints it (`nse_openssl.cc:317,360`).
fn algorithm(name: &[u8]) -> Result<digest::Alg, Fail> {
    digest::resolve(name).ok_or_else(|| {
        let mut msg = b"Unknown digest algorithm: ".to_vec();
        msg.extend_from_slice(c_str(name));
        Fail::err(msg)
    })
}

/// A cipher failure as the C raises it: `NSE_SSL_LUA_ERR`'s `OpenSSL error:`
/// and the error OpenSSL queued, or the IV check's own words with the
/// lengths as `int`s (`nse_openssl.cc:37-38,431-433`).
fn cipher_error(e: cipher::CipherError) -> Fail {
    match (e, e.openssl_text()) {
        (_, Some(text)) => Fail::err(format!("OpenSSL error: {text}")),
        (cipher::CipherError::IvLength { got, want }, None) => {
            let int = |n: usize| narrow(i64::try_from(n).unwrap_or(i64::MAX));
            Fail::err(format!(
                "Length of iv is {}; should be {}",
                int(got),
                int(want)
            ))
        }
        (_, None) => Fail::err("OpenSSL error: error:00000000:lib(0)::reason(0)"),
    }
}

/// Fuel for hashing or drawing `bytes` bytes: [`fuel_units`] of the number
/// of 64-byte blocks.
fn hash_fuel(bytes: usize) -> i32 {
    fuel_units(u64::try_from(bytes.div_ceil(64)).unwrap_or(u64::MAX))
}

/// What a call returns now, or the primality test still to run.
enum Done {
    Now,
    Prime(PrimeSeq),
}

fn string<'gc>(ctx: Context<'gc>, bytes: &[u8]) -> Value<'gc> {
    Value::String(ctx.intern(bytes))
}

/// The C function `f`, on the call's arguments.
fn call<'gc>(
    ctx: Context<'gc>,
    exec: &mut Execution<'gc, '_>,
    stack: &mut Stack<'gc, '_>,
    f: F,
) -> Result<Done, Failure> {
    // `NSE_DECLARE_DIGEST`: `md5(s)` is `digest("md5", s)`, with the name
    // inserted below the arguments, so the message is argument #2
    // (`nse_openssl.cc:336-347`).
    if let Some(name) = match f {
        F::Md4 => Some("md4"),
        F::Md5 => Some("md5"),
        F::Sha1 => Some("sha1"),
        F::Ripemd160 => Some("ripemd160"),
        _ => None,
    } {
        stack.push_front(string(ctx, name.as_bytes()));
    }
    let args = LuaArgs { ctx, stack };
    let out: Vec<Value<'gc>> = match f {
        F::NumBits => {
            let n = check(&args, 1)?.get().num_bits();
            vec![Value::Integer(i64::try_from(n).unwrap_or(i64::MAX))]
        }
        F::NumBytes => {
            let n = check(&args, 1)?.get().num_bytes();
            vec![Value::Integer(i64::try_from(n).unwrap_or(i64::MAX))]
        }
        F::SetBit | F::ClearBit => {
            let b = check(&args, 1)?;
            let pos = narrow(args.check_integer(2)?);
            if f == F::SetBit {
                b.bn.borrow_mut().set_bit(pos)?;
            } else {
                b.bn.borrow_mut().clear_bit(pos);
            }
            b.account();
            vec![]
        }
        F::IsBitSet => {
            let b = check(&args, 1)?;
            let pos = narrow(args.check_integer(2)?);
            vec![Value::Boolean(b.get().is_bit_set(pos))]
        }
        F::IsPrime | F::IsSafePrime => {
            let p = check(&args, 1)?.get().clone();
            let seq = PrimeSeq::new(&p, f == F::IsSafePrime)?;
            stack.clear();
            return Ok(Done::Prime(seq));
        }
        F::Bin2Bn => {
            let s = args.string(1)?;
            vec![push_bignum(ctx, Bn::from_bin(&s)?)]
        }
        F::Dec2Bn | F::Hex2Bn => {
            let s = args.string(1)?;
            let s = c_str(&s);
            let v = if f == F::Dec2Bn {
                Bn::from_dec(s)?
            } else {
                Bn::from_hex(s)?
            };
            vec![push_bignum(ctx, v)]
        }
        F::Rand => {
            // `size_t bits = luaL_checkinteger(L, 1)`, passed as `int`.
            let bits = narrow(args.check_integer(1)?);
            vec![push_bignum(ctx, Bn::rand(bits, &mut rand::Os)?)]
        }
        F::Bn2Bin => vec![string(ctx, &check(&args, 1)?.get().to_bin())],
        F::Bn2Mpi => vec![string(ctx, &check(&args, 1)?.get().to_mpi())],
        F::Bn2Dec => vec![string(ctx, &check(&args, 1)?.get().to_dec())],
        F::Bn2Hex => vec![string(ctx, &check(&args, 1)?.get().to_hex())],
        F::Add => {
            let a = check(&args, 1)?;
            let b = check(&args, 2)?;
            let r = a.get().add(&b.get())?;
            vec![push_bignum(ctx, r)]
        }
        F::ModExp => {
            let a = check(&args, 1)?;
            let p = check(&args, 2)?;
            let m = check(&args, 3)?;
            let r = Bn::mod_exp(&a.get(), &p.get(), &m.get())?;
            // A multiplication modulo m per bit of p: words(m)^2 each.
            let words = m.get().num_bits().div_ceil(64).max(1);
            let exp_words = p.get().num_bits().div_ceil(64).max(1);
            exec.fuel().consume(fuel_units(
                words.saturating_mul(words).saturating_mul(exp_words),
            ));
            vec![push_bignum(ctx, r)]
        }
        F::Div => {
            let a = check(&args, 1)?;
            let d = check(&args, 2)?;
            let (q, r) = a.get().div(&d.get());
            vec![push_bignum(ctx, q), push_bignum(ctx, r)]
        }
        F::Free => {
            check(&args, 1)?;
            vec![]
        }
        F::Digest | F::Md4 | F::Md5 | F::Sha1 | F::Ripemd160 => {
            let name = args.string(1)?;
            let msg = args.string(2)?;
            let alg = algorithm(&name)?;
            exec.fuel().consume(hash_fuel(msg.len()));
            vec![string(ctx, &digest::digest(alg, &msg))]
        }
        F::Hmac => {
            let name = args.string(1)?;
            let key = args.string(2)?;
            let msg = args.string(3)?;
            let alg = algorithm(&name)?;
            exec.fuel()
                .consume(hash_fuel(key.len().saturating_add(msg.len())));
            vec![string(ctx, &digest::hmac(alg, &key, &msg))]
        }
        F::RandBytes | F::RandPseudoBytes => {
            // `size_t len = luaL_checkinteger(L, 1)`: a negative length is
            // enormous, and `malloc` refuses it.
            let len = usize::try_from(args.check_integer(1)?).map_err(|_| Fail::err(NO_MEMORY))?;
            // The bytes come out of the memory budget first, which refuses
            // with its "not enough memory" (7.94 has none); then `malloc`'s
            // own failure is the C's.
            if !piccolo::budget::allows(len) {
                return Err(Failure::Refused);
            }
            let mut buf = Vec::new();
            if buf.try_reserve_exact(len).is_err() {
                return Err(Fail::err(NO_MEMORY).into());
            }
            // `RAND_bytes` takes the length as an `int` and fails on a
            // negative one (`nse_openssl.cc:285`).
            if f == F::RandBytes && narrow(i64::try_from(len).unwrap_or(i64::MAX)) < 0 {
                return Err(Failure::Random);
            }
            buf.resize(len, 0);
            if !rand::fill(&mut buf) {
                return Err(Failure::Random);
            }
            exec.fuel().consume(hash_fuel(len));
            vec![string(ctx, &buf)]
        }
        F::Encrypt | F::Decrypt => {
            // The name is looked up before any other argument is read
            // (`nse_openssl.cc:407-409`).
            let name = args.string(1)?;
            let c = cipher::resolve(&name).ok_or_else(|| {
                let mut msg = b"Unknown cipher algorithm: ".to_vec();
                msg.extend_from_slice(c_str(&name));
                Fail::err(msg)
            })?;
            let key = args.string(2)?;
            // `luaL_optlstring(L, 3, NULL, ...)`, and an empty IV is none.
            let iv = match args.get(3) {
                None | Some(Value::Nil) => None,
                Some(_) => Some(args.string(3)?),
            };
            let data = args.string(4)?;
            let padding = args.get(5).is_some_and(|v| v.to_bool());
            let iv = iv.as_deref().filter(|iv| !iv.is_empty());
            // The output comes out of the memory budget first, as random
            // bytes do; then `malloc`'s failure is the C's.
            let cap = cipher::out_capacity(data.len());
            if !piccolo::budget::allows(cap) {
                return Err(Failure::Refused);
            }
            let mut out = Vec::new();
            if out.try_reserve_exact(cap).is_err() {
                return Err(Fail::err(NO_MEMORY).into());
            }
            exec.fuel().consume(hash_fuel(data.len()));
            cipher::crypt(c, f == F::Encrypt, &key, iv, &data, padding, &mut out)
                .map_err(cipher_error)?;
            vec![string(ctx, &out)]
        }
        F::DesStringToKey => {
            let s = args.string(1)?;
            let Ok(seven) = <&[u8; 7]>::try_from(&s[..]) else {
                return Err(Fail::err("String must have length of 7 bytes.").into());
            };
            vec![string(ctx, &cipher::des_string_to_key(seven))]
        }
    };
    stack.clear();
    stack.extend(out);
    Ok(Done::Now)
}

/// `l_bignum_is_prime` and `l_bignum_is_safe_prime`: `BN_check_prime` on
/// `p` and, for `is_safe_prime` when `p` is prime, on `(p - 1) / 2`; the
/// Miller-Rabin rounds one at a time, as many per poll as the fuel allows and
/// at least one. Returns `is_prime`, or `is_safe, is_prime`.
#[derive(Collect)]
#[collect(require_static)]
struct PrimeSeq {
    entry: Option<Entry>,
    safe: bool,
    /// The verdict on `p`, once known.
    prime: Option<bool>,
    /// `(p - 1) / 2`, for `is_safe_prime`, until its test starts.
    half: Option<Bn>,
    /// The verdict on `(p - 1) / 2`.
    half_prime: Option<bool>,
    /// The test under way: `p`'s, then `(p - 1) / 2`'s.
    testing: Option<MillerRabin>,
}

impl PrimeSeq {
    fn new(p: &Bn, safe: bool) -> Result<PrimeSeq, Failure> {
        let mut seq = PrimeSeq {
            entry: None,
            safe,
            prime: None,
            half: safe.then(|| p.sophie_germain()),
            half_prime: None,
            testing: None,
        };
        seq.start(bn::check_prime(p)?)?;
        Ok(seq)
    }

    fn start(&mut self, p: Primality) -> Result<(), Failure> {
        match p {
            Primality::Testing(mr) => self.testing = Some(mr),
            Primality::Known(v) => self.known(v)?,
        }
        Ok(())
    }

    /// A verdict: on `p` first, then on `(p - 1) / 2`, which is tested only
    /// when `p` is prime.
    fn known(&mut self, v: bool) -> Result<(), Failure> {
        if self.prime.is_some() {
            self.half_prime = Some(v);
        } else {
            self.prime = Some(v);
            if let Some(half) = self.half.take().filter(|_| v) {
                self.start(bn::check_prime(&half)?)?;
            }
        }
        Ok(())
    }

    /// Run rounds while the fuel lasts; the results once both tests are done.
    fn run(&mut self, exec: &mut Execution<'_, '_>) -> Result<Option<Vec<bool>>, Failure> {
        while let Some(mr) = self.testing.as_mut() {
            let fuel = cubic_fuel(mr.words());
            let verdict = mr.round(&mut rand::Os)?;
            exec.fuel().consume(fuel);
            if let Some(v) = verdict {
                self.testing = None;
                self.known(v)?;
            }
            if self.testing.is_some() && !exec.fuel().should_continue() {
                return Ok(None);
            }
        }
        let prime = self.prime.unwrap_or(false);
        Ok(Some(if self.safe {
            vec![prime && self.half_prime.unwrap_or(false), prime]
        } else {
            vec![prime]
        }))
    }
}

impl<'gc> Sequence<'gc> for PrimeSeq {
    fn poll(
        mut self: Pin<&mut Self>,
        ctx: Context<'gc>,
        mut exec: Execution<'gc, '_>,
        mut stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        let entry = self.entry.unwrap_or(Entry {
            f: F::IsPrime,
            name: "is_prime",
        });
        match self.run(&mut exec) {
            Ok(Some(vs)) => {
                stack.clear();
                stack.extend(vs.into_iter().map(Value::Boolean));
                Ok(SequencePoll::Return)
            }
            Ok(None) => Ok(SequencePoll::Pending),
            Err(e) => Err(raise(ctx, &exec, &e, entry)),
        }
    }
}

/// The callback for `f`, registered as `name`.
fn callback<'gc>(ctx: Context<'gc>, f: F, name: &'static str) -> Callback<'gc> {
    Callback::from_fn_with(
        &ctx,
        Entry { f, name },
        |&entry, ctx, mut exec, mut stack| {
            match call(ctx, &mut exec, &mut stack, entry.f) {
                Ok(Done::Now) => Ok(CallbackReturn::Return),
                Ok(Done::Prime(mut seq)) => {
                    seq.entry = Some(entry);
                    // Decided without a round: return at once.
                    match seq.run(&mut exec) {
                        Ok(Some(vs)) => {
                            stack.extend(vs.into_iter().map(Value::Boolean));
                            Ok(CallbackReturn::Return)
                        }
                        Ok(None) => Ok(CallbackReturn::Sequence(BoxSequence::new(&ctx, seq))),
                        Err(e) => Err(raise(ctx, &exec, &e, entry)),
                    }
                }
                Err(e) => Err(raise(ctx, &exec, &e, entry)),
            }
        },
    )
}

/// `luaopen_openssl`'s library table, as far as the port has come: the
/// `BIGNUM` functions (step b).
fn open<'gc>(ctx: Context<'gc>) -> Table<'gc> {
    let lib = Table::new(&ctx);
    for (name, f) in LIBRARY {
        lib.set_field(ctx, name, callback(ctx, f, name));
    }
    lib
}

/// **For tests only.** Open `openssl` in a bare state (no NSE runtime), put
/// it in `loaded` (the state's `package.loaded`) when given, and return it.
///
/// The NSE runtime does not register the module before step g (D2(D)); this
/// is for the states the module's own tests, the integration tests and the
/// fuzz targets build (`runtime::tests::openssl_is_not_registered`).
pub fn register_for_tests<'gc>(ctx: Context<'gc>, loaded: Option<Table<'gc>>) -> Table<'gc> {
    let lib = open(ctx);
    if let Some(loaded) = loaded {
        loaded.set_field(ctx, "openssl", lib);
    }
    lib
}

#[cfg(test)]
mod tests;
