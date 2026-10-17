//! The binding through the VM, in-module so that Miri runs it. The
//! differential corpora (`tests/openssl_bn_differential.rs`, 11,171 rows,
//! and `tests/openssl_digest_differential.rs`, 2,322, against nmap 7.94)
//! hold the oracle's answers; these pin what the corpus does not reach:
//! argument errors from Lua code, the metamethods, the caps, shared
//! mutation, the memory accounting, the rounds a primality test yields
//! between, and the random functions' lengths and budget.

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
fn the_library_has_steps_b_and_c_and_nothing_else_yet() {
    let out = run(
        "local k = {} for name, v in pairs(openssl) do k[#k + 1] = name .. ':' .. type(v) end \
         table.sort(k) return #k .. ' ' .. table.concat(k, ',')",
    );
    assert_eq!(
        out,
        "27 bignum_add:function,bignum_bin2bn:function,bignum_bn2bin:function,\
         bignum_bn2dec:function,bignum_bn2hex:function,bignum_bn2mpi:function,\
         bignum_clear_bit:function,bignum_dec2bn:function,bignum_div:function,\
         bignum_hex2bn:function,bignum_is_bit_set:function,bignum_is_prime:function,\
         bignum_is_safe_prime:function,bignum_mod_exp:function,bignum_num_bits:function,\
         bignum_num_bytes:function,bignum_pseudo_rand:function,bignum_rand:function,\
         bignum_set_bit:function,digest:function,hmac:function,md4:function,md5:function,\
         rand_bytes:function,rand_pseudo_bytes:function,ripemd160:function,sha1:function"
    );
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
         b:set_bit((1 << 32) + 1) \
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

/// `NSE_DECLARE_DIGEST` inserts the algorithm's name below the arguments
/// (`nse_openssl.cc:336-347`), so `md5`'s message is argument #2, from Lua
/// code as from C; an unknown name is printed up to its NUL; a number is a
/// string to `luaL_checkstring`, for the name and the message alike.
#[test]
fn digest_errors_are_the_cs() {
    let out = run(
        "local function e(f, ...) return select(2, pcall(f, ...)) end \
         return r(select(2, pcall(function() return openssl.md5() end)), \
                  select(2, pcall(function() return openssl.sha1({}) end)), \
                  e(openssl.ripemd160, nil), \
                  e(openssl.digest, 'nope\\0md5', ''), \
                  e(openssl.hmac, 'sha3-256', 'k', 'm'), \
                  e(openssl.digest, 42, 'x'), \
                  openssl.md5(42) == openssl.md5('42'), \
                  openssl.digest('MD5\\0junk', 1.5) == openssl.md5('1.5'), \
                  openssl.hmac('SHA-256', 7, 8) == openssl.hmac('sha256', '7', '8'))",
    );
    assert_eq!(
        out,
        "s:t:1: bad argument #2 to 'md5' (string expected, got no value)|\
         s:t:1: bad argument #2 to 'sha1' (string expected, got table)|\
         s:bad argument #2 to 'openssl.ripemd160' (string expected, got nil)|\
         s:Unknown digest algorithm: nope|\
         s:Unknown digest algorithm: sha3-256|\
         s:Unknown digest algorithm: 42|true|true|true"
    );
}

/// The digests and HMAC through the binding, against published vectors
/// (the full sets are `digest::tests`).
#[test]
fn digests_and_hmac_through_the_binding() {
    let out = run("local function hex(s) return (s:gsub('.', function(c) \
           return ('%02x'):format(c:byte()) end)) end \
         return r(hex(openssl.md4('abc')), hex(openssl.md5('')), hex(openssl.sha1('abc')), \
                  hex(openssl.ripemd160('abc')), hex(openssl.digest('sha512-224', 'abc')), \
                  hex(openssl.hmac('md5', 'Jefe', 'what do ya want for nothing?')))");
    assert_eq!(
        out,
        "s:a448017aaf21d8525fc10ae87aa6729d|s:d41d8cd98f00b204e9800998ecf8427e|\
         s:a9993e364706816aba3e25717850c26c9cd0d89d|\
         s:8eb208f7e05d987a9b044a8e98c6b087f15a0bfc|\
         s:4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa|\
         s:750c783e6ab0b503eaa86e310a5db738"
    );
}

/// `rand_bytes` and `rand_pseudo_bytes`: the length asked for; a negative
/// one is `size_t`-enormous and `malloc` refuses it, as the allocator
/// refuses 2^62 bytes (no abort); draws differ (E3).
#[test]
fn random_bytes_have_the_length_asked_for() {
    let out = run(
        "local function e(f, ...) return select(2, pcall(f, ...)) end \
         local a, b = openssl.rand_bytes(32), openssl.rand_bytes(32) \
         local c, d = openssl.rand_pseudo_bytes(32), openssl.rand_pseudo_bytes(32) \
         return r(#openssl.rand_bytes(0), #openssl.rand_pseudo_bytes(1), \
                  #openssl.rand_bytes(1000), a ~= b, c ~= d, a ~= c, \
                  select(2, pcall(function() return openssl.rand_bytes(-1) end)), \
                  e(openssl.rand_pseudo_bytes, math.mininteger), \
                  e(openssl.rand_bytes, 1 << 62), \
                  e(openssl.rand_bytes, 1.5))",
    );
    assert_eq!(
        out,
        "0|1|1000|true|true|true|s:t:1: Couldn't allocate memory.|\
         s:Couldn't allocate memory.|s:Couldn't allocate memory.|\
         s:bad argument #1 to 'openssl.rand_bytes' (number has no integer representation)"
    );
}

/// The bytes come out of the memory budget: a draw the budget cannot hold is
/// refused with its "not enough memory" before anything is drawn, as a
/// bignum is (7.94 has no budget; its `malloc` would grant it).
#[test]
#[cfg_attr(miri, ignore)] // megabytes of random bytes
fn the_memory_budget_refuses_random_bytes() {
    let mut lua = state();
    lua.set_memory_limit(lua.total_memory() + (8 << 20));
    let (out, _) = run_sliced(
        &mut lua,
        "return r(#openssl.rand_bytes(1 << 20), \
                  select(2, pcall(openssl.rand_bytes, 16 << 20)), \
                  select(2, pcall(openssl.rand_pseudo_bytes, 16 << 20)))",
        i32::MAX,
    );
    assert_eq!(out, "1048576|s:not enough memory|s:not enough memory");
}

/// A draw the budget refuses takes nothing from the source: with the test
/// generator seeded, the draw after a refused one is the seed's first.
#[test]
#[cfg_attr(miri, ignore)] // megabytes of budget
fn a_refused_draw_takes_no_randomness() {
    let mut lua = state();
    lua.set_memory_limit(lua.total_memory() + (8 << 20));
    rand::seed_for_tests(Some(11));
    let (refused, _) = run_sliced(
        &mut lua,
        "return r(select(2, pcall(openssl.rand_bytes, 16 << 20)), openssl.rand_bytes(16))",
        i32::MAX,
    );
    rand::seed_for_tests(Some(11));
    let (fresh, _) = run_sliced(&mut lua, "return r(openssl.rand_bytes(16))", i32::MAX);
    rand::seed_for_tests(None);
    assert_eq!(refused, format!("s:not enough memory|{fresh}"));
}

/// E3's release check: the seam is the operating system's CSPRNG, not a
/// generator seeded the same way in every process. Two child processes of
/// this test binary each draw 32 bytes through `rand_bytes`; a fixed seed
/// would give both the same bytes (in-process checks cannot see it).
#[test]
#[cfg_attr(miri, ignore)] // spawns processes
fn draws_differ_across_processes() {
    const CHILD: &str = "NMAP_RS_OPENSSL_RAND_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let out = run("return (openssl.rand_bytes(32):gsub('.', function(c) \
             return ('%02x'):format(c:byte()) end))");
        println!("draw={out}");
        return;
    }
    let draw = || {
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "nse::openssl::tests::draws_differ_across_processes",
            ])
            .args(["--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .expect("spawn");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.lines()
            // libtest prints the test's name on the same line first.
            .find_map(|l| l.split_once("draw=").map(|(_, d)| d.trim().to_string()))
            .unwrap_or_else(|| panic!("no draw in {text}"))
    };
    let (a, b) = (draw(), draw());
    assert_eq!(a.len(), 64);
    assert_ne!(a, b, "two processes drew the same bytes");
}
