//! The binding through the VM, in-module so that Miri runs it. The
//! differential corpus (`tests/openssl_bn_differential.rs`, 11,171 rows
//! against nmap 7.94) holds the oracle's answers; these pin what the corpus
//! does not reach: argument errors from Lua code, the metamethods, the caps,
//! shared mutation, the memory accounting, and the rounds a primality test
//! yields between.

use super::*;
use crate::nse::stdlib::{load_format, load_patterns, load_tail};
use piccolo::{Closure, Executor, Fuel, Lua, StashedExecutor};

fn state() -> Lua {
    let mut lua = Lua::core();
    lua.enter(|ctx| {
        load_patterns(ctx).expect("string table");
        load_format(ctx).expect("string table");
        load_tail(ctx).expect("string and coroutine tables");
        ctx.set_global("openssl", register_for_tests(ctx, None));
    });
    lua
}

fn start(lua: &mut Lua, src: &str) -> StashedExecutor {
    lua.enter(|ctx| {
        let render = "local function r(...) \
            local t = table.pack(...) \
            local out = {} \
            for i = 1, t.n do \
              local v = t[i] \
              out[i] = type(v) == 'string' and ('s:' .. v) or tostring(v) \
            end \
            return table.concat(out, '|') end ";
        let f = Closure::load(ctx, Some("=t"), format!("{render}{src}").as_bytes()).unwrap();
        ctx.stash(Executor::start(ctx, f.into(), ()))
    })
}

/// Run `src` to its end in slices of `slice` fuel; what it returned, as a
/// string, and the slices it took.
fn run_sliced(lua: &mut Lua, src: &str, slice: i32) -> (String, u32) {
    let ex = start(lua, src);
    let mut slices = 0u32;
    loop {
        let mut fuel = Fuel::with(slice);
        slices = slices.saturating_add(1);
        if lua
            .enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel))
            .unwrap()
        {
            break;
        }
        assert!(slices < 100_000, "never finished");
    }
    let out = lua.enter(
        |ctx| match ctx.fetch(&ex).take_result::<Value>(ctx).unwrap() {
            Ok(v) => v.display().to_string(),
            Err(e) => format!("raised: {e:#}"),
        },
    );
    (out, slices)
}

fn run(src: &str) -> String {
    run_sliced(&mut state(), src, i32::MAX).0
}

#[test]
fn the_metatable_is_luaopen_openssls() {
    let out = run("local mt = getmetatable(openssl.bignum_dec2bn('1')) \
         local k = {} for name, v in pairs(mt) do k[#k + 1] = name .. '=' .. type(v) end \
         table.sort(k) \
         return r(table.concat(k, ','), mt.__index == mt, mt.__name, \
                  tostring(openssl.bignum_hex2bn('-1f')), \
                  getmetatable(openssl.bignum_bin2bn('\\1')) == mt)");
    assert_eq!(
        out,
        "s:__gc=function,__index=table,__name=string,__tostring=function,clear_bit=function,\
         is_bit_set=function,is_prime=function,is_safe_prime=function,num_bits=function,\
         num_bytes=function,set_bit=function,tobin=function,todec=function,tohex=function,\
         tompi=function|true|s:BIGNUM|s:-1F|true"
    );
}

#[test]
fn the_library_has_the_bignum_functions_and_nothing_else_yet() {
    let out = run(
        "local k = {} for name, v in pairs(openssl) do k[#k + 1] = name .. ':' .. type(v) end \
         table.sort(k) return #k .. ' ' .. table.concat(k, ',')",
    );
    assert!(
        out.starts_with("19 bignum_add:function,bignum_bin2bn:function"),
        "{out}"
    );
    assert!(out.ends_with("bignum_set_bit:function"), "{out}");
}

/// `openssl-bad-argument-naming`: from Lua code, the name a function is
/// registered under, after the caller's position; otherwise the library
/// name of its C function, `?` for `__gc`, and for the two names of
/// `l_bignum_rand`, the one called (`nse-openssl-rand-alias-name`).
#[test]
fn bad_arguments_are_named_as_the_port_names_them() {
    let out = run("local bn = openssl.bignum_dec2bn('5') \
         local mt = getmetatable(bn) \
         return r(select(2, pcall(function() return openssl.bignum_add(bn, 1) end)), \
                  select(2, pcall(function() return bn.tohex(nil) end)), \
                  select(2, pcall(bn.tohex, {})), \
                  select(2, pcall(mt.__tostring, 1)), \
                  select(2, pcall(mt.__gc, 'x')), \
                  select(2, pcall(openssl.bignum_rand)), \
                  select(2, pcall(openssl.bignum_pseudo_rand, 'x')), \
                  select(2, pcall(openssl.bignum_set_bit, bn, 1.5)), \
                  select(2, pcall(openssl.bignum_add, setmetatable({}, mt), bn)))");
    assert_eq!(
        out,
        "s:t:1: bad argument #2 to 'bignum_add' (BIGNUM expected, got number)|\
         s:t:1: bad argument #1 to 'tohex' (BIGNUM expected, got nil)|\
         s:bad argument #1 to 'openssl.bignum_bn2hex' (BIGNUM expected, got table)|\
         s:bad argument #1 to 'openssl.bignum_bn2hex' (BIGNUM expected, got number)|\
         s:bad argument #1 to '?' (BIGNUM expected, got string)|\
         s:bad argument #1 to 'openssl.bignum_rand' (number expected, got no value)|\
         s:bad argument #1 to 'openssl.bignum_pseudo_rand' (number expected, got string)|\
         s:bad argument #2 to 'openssl.bignum_set_bit' (number has no integer representation)|\
         s:bad argument #1 to 'openssl.bignum_add' (BIGNUM expected, got BIGNUM)"
    );
}

/// `nse-openssl-bignum-gc-callable`: the C's `__gc` frees the number, and
/// `__index` hands it to any script; here it does nothing, and the number
/// lives on.
#[test]
fn gc_is_present_and_inert() {
    let out = run("local bn = openssl.bignum_dec2bn('12345') \
         local n = select('#', bn:__gc()) \
         getmetatable(bn).__gc(bn) \
         return r(n, bn:todec(), openssl.bignum_add(bn, bn):todec())");
    assert_eq!(out, "0|s:12345|s:24690");
}

/// `set_bit` and `clear_bit` change the number in place: every reference to
/// the userdata sees it, as every pointer to the C's `BIGNUM` does.
#[test]
fn the_bit_functions_mutate_the_shared_number() {
    let out = run("local a = openssl.bignum_dec2bn('-4') local b = a \
         local n = select('#', openssl.bignum_set_bit(a, 0)) \
         b:set_bit(2^32 + 1) \
         a:clear_bit(2) \
         return r(n, b:todec(), a:is_bit_set(1), a:is_bit_set(-1), a:num_bits(), a:num_bytes())");
    // -4 | 1 = -5; bit 2^32+1 is bit 1 as an `int`: -7; then bit 2 cleared: -3.
    assert_eq!(out, "0|s:-3|true|false|2|1");
}

/// `nse-bignum-operand-cap`: over a cap, "not enough memory", unpositioned,
/// where 7.94 computes for minutes to days or returns 0. Under Miri, the
/// small caps only.
#[test]
fn over_a_cap_is_not_enough_memory() {
    let out = run(
        "local big = openssl.bignum_bin2bn(string.rep('\\255', 2049)) \
         local two = openssl.bignum_dec2bn('2') \
         return r(select(2, pcall(openssl.bignum_mod_exp, big, two, two)), \
                  select(2, pcall(function() return big:is_prime() end)), \
                  select(2, pcall(openssl.bignum_is_safe_prime, big)), \
                  big:num_bits(), \
                  openssl.bignum_mod_exp(two, two, openssl.bignum_dec2bn('5')):todec())",
    );
    assert_eq!(
        out,
        "s:not enough memory|s:not enough memory|s:not enough memory|16392|s:4"
    );
    if !cfg!(miri) {
        let out = run(
            "local ok, e = pcall(openssl.bignum_bin2bn, '\\1' .. string.rep('\\0', 131072)) \
             local ok2, e2 = pcall(openssl.bignum_rand, 1048577) \
             local x = openssl.bignum_rand(1048576) \
             return r(ok, e, ok2, e2, x:num_bits() <= 1048576)",
        );
        assert_eq!(
            out,
            "false|s:not enough memory|false|s:not enough memory|true"
        );
    }
}

/// A number's digits are on the VM's books while it lives (§1.4): setting
/// bit 524,287 of a zero grows the state's memory by its 64 KiB.
#[test]
fn numbers_are_accounted_to_the_heap() {
    let mut lua = state();
    let before = lua.total_memory();
    let ex = start(
        &mut lua,
        "big = openssl.bignum_dec2bn('0') big:set_bit(524287) return 1",
    );
    lua.enter(|ctx| {
        let mut fuel = Fuel::with(i32::MAX);
        assert!(ctx.fetch(&ex).step(ctx, &mut fuel).unwrap());
    });
    let after = lua.total_memory();
    assert!(after - before >= 65536, "{before} -> {after}");
}

/// The Miller-Rabin rounds yield to the VM: with little fuel per slice, a
/// primality test of a 2,203-bit Mersenne prime takes a slice per round or
/// so, and still answers. (Miri: a 127-bit prime.)
#[test]
fn a_primality_test_yields_between_rounds() {
    super::rand::seed_for_tests(Some(5));
    // Fuel per slice under one round's price: 80 at 127 bits, 428,750 at
    // 2,203.
    let (src, rounds, slice) = if cfg!(miri) {
        (
            "local p = openssl.bignum_dec2bn('170141183460469231731687303715884105727')",
            64,
            50,
        )
    } else {
        (
            "local p = openssl.bignum_dec2bn('0') for i = 0, 2202 do p:set_bit(i) end",
            128,
            1000,
        )
    };
    let mut lua = state();
    let (out, slices) = run_sliced(
        &mut lua,
        &format!("{src} return r(p:is_prime(), openssl.bignum_is_safe_prime(p))"),
        slice,
    );
    super::rand::seed_for_tests(None);
    assert_eq!(out, "true|false|true");
    // is_prime, then is_safe_prime's test of p: two full runs, and the
    // second half (2^2202 - 1, or 2^126 - 1) is divisible by 3.
    assert!(slices >= 2 * rounds, "{slices} slices for {rounds} rounds");
}

#[test]
fn is_safe_prime_tests_p_then_its_half() {
    let out = run("local t = {} \
         for _, n in ipairs({'2', '3', '5', '7', '11', '13', '23', '47', '-7', '0', '4'}) do \
           local s, p = openssl.bignum_is_safe_prime(openssl.bignum_dec2bn(n)) \
           t[#t + 1] = n .. '=' .. tostring(s) .. ',' .. tostring(p) \
         end return table.concat(t, ' ')");
    assert_eq!(
        out,
        "2=false,true 3=false,true 5=true,true 7=true,true 11=true,true 13=false,true \
         23=true,true 47=true,true -7=false,false 0=false,false 4=false,false"
    );
}

/// Under a memory budget, a number the budget cannot hold is refused before
/// it is built, with the budget's "not enough memory" (`stdlib::reserve`'s
/// rule, §6): a 4 MiB `bignum_rand` in an 8 MiB state works; a 8 MiB
/// `bignum_bin2bn` and a `set_bit` far out do not, and nothing aborts.
#[test]
#[cfg_attr(miri, ignore)] // megabytes of digits
fn the_memory_budget_refuses_a_number() {
    let mut lua = state();
    lua.set_memory_limit(lua.total_memory() + (8 << 20));
    let (out, _) = run_sliced(
        &mut lua,
        "local x = openssl.bignum_rand(1 << 20) \
         local ok1, e1 = pcall(openssl.bignum_bin2bn, string.rep('\\255', 131072)) \
         local z = openssl.bignum_dec2bn('1') \
         local ok2, e2 = pcall(z.set_bit, z, (1 << 20) - 1) \
         return r(x:num_bits() <= 1 << 20, ok1, type(e1), ok2, e2)",
        i32::MAX,
    );
    assert_eq!(out, "true|true|s:userdata|true|nil");
    lua.set_memory_limit(lua.total_memory() + (64 << 10));
    let (out, _) = run_sliced(
        &mut lua,
        "local ok1, e1 = pcall(openssl.bignum_rand, 1 << 20) \
         local z = openssl.bignum_dec2bn('1') \
         local ok2, e2 = pcall(z.set_bit, z, (1 << 20) - 1) \
         return r(ok1, e1, ok2, e2, z:num_bits())",
        i32::MAX,
    );
    // Refused before the number changes: it is still 1.
    assert_eq!(out, "false|s:not enough memory|false|s:not enough memory|1");
}

/// `bignum_rand`'s count is the C's `int` (`size_t bits = luaL_checkinteger`,
/// passed to `BN_rand`'s `int`): 2^32 + 8 is 8 bits, and 2^32 - 1 is -1, 0.
#[test]
fn rand_bits_are_narrowed_to_int() {
    let out = run("local big, max, nonzero = 0, 0, false \
         for _ = 1, 64 do \
           local x = openssl.bignum_rand((1 << 32) + 8) \
           max = math.max(max, x:num_bits()) nonzero = nonzero or x:num_bits() > 0 \
         end \
         return r(max <= 8, nonzero, openssl.bignum_rand((1 << 32) - 1):num_bits())");
    assert_eq!(out, "true|true|0");
}
