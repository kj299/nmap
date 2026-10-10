//! `lpeg.match` against the C, case by case: the observable quirks of LPeg
//! 0.12's compiler, matching machine and non-calling captures that a naive
//! implementation gets wrong (M6.6 step c's brief, §5: C-Q1 to C-Q13, K-Q1
//! to K-Q21, and the `R`/`T` rows).
//!
//! Each case is a chunk, named `=c`, run with LPeg's functions as globals
//! and its results serialised by the oracle's `run.lua`; the answers are
//! the tree's standalone oracle's (`oracle/build_lua_oracle.sh`), measured
//! for this table, except:
//! - `Q01a` and `Q01b` (H07 and H06), which crash the C in some harnesses
//!   (`lpeg-codegen-jump-out-of-code`): the answer of the C with its
//!   peephole fixed;
//! - `Q06a`'s second half, `match(Cc(nil), "")`, which crashes the C
//!   (`lpeg-cc-nil-without-ktable`): pinned in `lpeg_match_limits`.
//!
//! Calls are direct, not through `pcall`, so errors carry the caller's
//! position (`c:1:`) as `luaL_where` gives it.
#![cfg(not(miri))] // the VM over 170 cases; the module's own tests run under Miri

mod lpeg_eval;

use piccolo::{Closure, Executor, Function, Value, Variadic};

/// (id, chunk, ok, number of results, results serialised).
const CASES: &[(&str, &str, bool, usize, &str)] = &[
    (
        "Q01a",
        r##"return match(-(S""*"a")+"c", "x")"##,
        true,
        1,
        r##"1"##,
    ),
    (
        "Q01b",
        r##"return match(P{P""}^-1, "x")"##,
        true,
        1,
        r##"1"##,
    ),
    (
        "Q02",
        r##"return match(P{"A", A=Ct(V"B"), B=C"x"}, "x")"##,
        true,
        2,
        r##""x", {}"##,
    ),
    (
        "Q02b",
        r##"return match(Ct(C"x"), "x")"##,
        true,
        1,
        r##"{[1]="x"}"##,
    ),
    (
        "Q02c",
        r##"return match(P{"A", A=Ct(V"B"*"y"), B=C"x"}, "xy")"##,
        true,
        2,
        r##""x", {}"##,
    ),
    (
        "Q03",
        r##"return match(P{"A", A=#V"B"*1, B=C"x"}, "x")"##,
        true,
        1,
        r##""x""##,
    ),
    ("Q03b", r##"return match(#C"x"*1, "x")"##, true, 1, r##"2"##),
    (
        "Q04a",
        r##"return match(Cp(), "abc", 0)"##,
        true,
        1,
        r##"4"##,
    ),
    (
        "Q04b",
        r##"return match(Cp(), "abc", -0.0)"##,
        true,
        1,
        r##"4"##,
    ),
    (
        "Q04c",
        r##"return match(Cp(), "abc", 10)"##,
        true,
        1,
        r##"4"##,
    ),
    (
        "Q04d",
        r##"return match(Cp(), "abc", -10)"##,
        true,
        1,
        r##"1"##,
    ),
    (
        "Q04e",
        r##"return match(Cp(), "abc", math.mininteger)"##,
        true,
        1,
        r##"1"##,
    ),
    (
        "Q04f",
        r##"return match(Cp(), "abc", math.maxinteger)"##,
        true,
        1,
        r##"4"##,
    ),
    (
        "Q04g",
        r##"return match(Cp(), "abc", -1)"##,
        true,
        1,
        r##"3"##,
    ),
    (
        "Q04h",
        r##"return match(Cp(), "abc", 1.5)"##,
        false,
        1,
        r##""c:1: bad argument #3 to 'match' (number has no integer representation)""##,
    ),
    (
        "Q04i",
        r##"return match(Cp(), "abc", "2")"##,
        true,
        1,
        r##"2"##,
    ),
    (
        "Q04j",
        r##"return match(Cp(), "abc", nil)"##,
        true,
        1,
        r##"1"##,
    ),
    (
        "Q04k",
        r##"return match(Cp(), "abc", 2.0)"##,
        true,
        1,
        r##"2"##,
    ),
    ("Q05", r##"return match(B"a", "ab", 2)"##, true, 1, r##"2"##),
    (
        "Q05b",
        r##"return match(B"a", "ab", 1)"##,
        true,
        1,
        r##"nil"##,
    ),
    (
        "Q06a",
        r##"return match(Cc(nil)*Cc(1), "")"##,
        true,
        2,
        r##"nil, 1"##,
    ),
    (
        "Q06b",
        r##"return match(Cc(1,nil,3), "")"##,
        true,
        3,
        r##"1, nil, 3"##,
    ),
    (
        "Q06c",
        r##"return match(Ct(Cc(1,nil,3)), "")"##,
        true,
        1,
        r##"{[1]=1,[3]=3}"##,
    ),
    (
        "Q06d",
        r##"return match(Cc(false), "")"##,
        true,
        1,
        r##"false"##,
    ),
    ("Q06e", r##"return match(Cc(), "x")"##, true, 1, r##"1"##),
    (
        "Q07a",
        r##"return match(Carg(1), "x", 1, nil)"##,
        true,
        1,
        r##"nil"##,
    ),
    (
        "Q07b",
        r##"return match(Carg(1), "x")"##,
        false,
        1,
        r##""c:1: reference to absent argument #1""##,
    ),
    (
        "Q07c",
        r##"return match(Carg(2), "x", 1, "a")"##,
        false,
        1,
        r##""c:1: reference to absent argument #2""##,
    ),
    (
        "Q07d",
        r##"return match(Carg(1)*"y", "x")"##,
        true,
        1,
        r##"nil"##,
    ),
    (
        "Q07e",
        r##"return match(Carg(1), "x", nil, "A")"##,
        true,
        1,
        r##""A""##,
    ),
    (
        "Q07f",
        r##"return select("#", match(Carg(1), "x", 1, nil))"##,
        true,
        1,
        r##"1"##,
    ),
    (
        "Q08a",
        r##"return match(P"a"/1, "a")"##,
        true,
        1,
        r##""a""##,
    ),
    (
        "Q08b",
        r##"return match(P"a"/2, "a")"##,
        false,
        1,
        r##""c:1: no capture '2'""##,
    ),
    (
        "Q08c",
        r##"return match((C"a"*C"b")/2, "ab")"##,
        true,
        1,
        r##""b""##,
    ),
    ("Q08d", r##"return match(P"a"/0, "a")"##, true, 1, r##"2"##),
    (
        "Q08e",
        r##"return match((P"a"/0)/1, "a")"##,
        true,
        1,
        r##""a""##,
    ),
    (
        "Q09a",
        r##"return match((C(C"a"*C"b")*C"c")/"%1|%2|%3|%4", "abc")"##,
        true,
        1,
        r##""ab|a|b|c""##,
    ),
    (
        "Q09b",
        r##"return match(C"a"/"%10", "a")"##,
        true,
        1,
        r##""a0""##,
    ),
    (
        "Q09c",
        r##"return match(P"a"/"x%", "a")"##,
        true,
        1,
        r##""x\0""##,
    ),
    (
        "Q09d",
        r##"return match(P"ab"/"%1", "ab")"##,
        false,
        1,
        r##""c:1: invalid capture index (1)""##,
    ),
    (
        "Q09e",
        r##"return match(P"ab"/"%0-%%-%a", "ab")"##,
        true,
        1,
        r##""ab-%-a""##,
    ),
    (
        "Q09f",
        r##"return match(C(1)^11/"%9", "abcdefghijk")"##,
        true,
        1,
        r##""i""##,
    ),
    (
        "Q09g",
        r##"return match((C(1)^8*Cb"nope")/"%9", "abcdefgh")"##,
        false,
        1,
        r##""c:1: back reference 'nope' not found""##,
    ),
    (
        "Q09h",
        r##"return match((C(1)^9*Cb"nope")/"%9", "abcdefghi")"##,
        true,
        1,
        r##""i""##,
    ),
    (
        "Q09i",
        r##"return match((C(1)^8*Cb"nope")/"%8", "abcdefgh")"##,
        true,
        1,
        r##""h""##,
    ),
    (
        "Q09j",
        r##"return match(C(1)^2/"%3", "ab")"##,
        false,
        1,
        r##""c:1: invalid capture index (3)""##,
    ),
    (
        "Q09k",
        r##"return match((P(1)*Cc(true))/"%1", "a")"##,
        false,
        1,
        r##""c:1: invalid capture value (a boolean)""##,
    ),
    (
        "Q09l",
        r##"return match((Cp()*1)/"%1", "a")"##,
        true,
        1,
        r##""1""##,
    ),
    (
        "Q09m",
        r##"return match(Cg(C"a","k")/"%1", "a")"##,
        false,
        1,
        r##""c:1: no values in capture index 1""##,
    ),
    (
        "Q09n",
        r##"return match((C(C(C"a")))/"%1%2%3", "a")"##,
        true,
        1,
        r##""aaa""##,
    ),
    (
        "Q09o",
        r##"return match((C"a"*Ct(C"b"))/"%2", "ab")"##,
        false,
        1,
        r##""c:1: invalid capture value (a table)""##,
    ),
    (
        "Q10a",
        r##"return match(Cs((P"a"/0)*"b"), "ab")"##,
        true,
        1,
        r##""ab""##,
    ),
    (
        "Q10b",
        r##"return match(Cs(P"a"/"x"*P"b"), "ab")"##,
        true,
        1,
        r##""xb""##,
    ),
    (
        "Q10c",
        r##"return match(Cs(Cg(P"a"/"x","k")), "a")"##,
        true,
        1,
        r##""a""##,
    ),
    (
        "Q10d",
        r##"return match(Cs(Cc(true)), "a")"##,
        false,
        1,
        r##""c:1: invalid replacement value (a boolean)""##,
    ),
    (
        "Q10e",
        r##"return match(Cs(P"a"*Cp()), "a")"##,
        true,
        1,
        r##""a2""##,
    ),
    (
        "Q10f",
        r##"return match(Cs(Carg(1)*"a"), "a", 1, "X")"##,
        true,
        1,
        r##""Xa""##,
    ),
    (
        "Q10g",
        r##"return match(Cs(C"a"/"%0%0"*C"b"), "ab")"##,
        true,
        1,
        r##""aab""##,
    ),
    (
        "Q11a",
        r##"return match(Cg(C"a","k"), "a")"##,
        true,
        1,
        r##"2"##,
    ),
    (
        "Q11b",
        r##"return match(Cg(C"a"*C"b"), "ab")"##,
        true,
        2,
        r##""a", "b""##,
    ),
    (
        "Q11c",
        r##"return match(Ct(Cg(C"a", 1)), "a")"##,
        true,
        1,
        r##"{["1"]="a"}"##,
    ),
    (
        "Q11d",
        r##"return match(Cg(C"a",1)*Cb"1", "a")"##,
        true,
        1,
        r##""a""##,
    ),
    (
        "Q11e",
        r##"return match(Cg(C"a",1)*Cb(1), "a")"##,
        true,
        1,
        r##""a""##,
    ),
    (
        "Q12a",
        r##"return match(Ct(C"a"*Cg(C"b","k")*C"c"), "abc")"##,
        true,
        1,
        r##"{[1]="a",[2]="c",["k"]="b"}"##,
    ),
    (
        "Q12b",
        r##"return match(Ct(Cg(C"a","k")*Cg(C"b","k")), "ab")"##,
        true,
        1,
        r##"{["k"]="b"}"##,
    ),
    (
        "Q12c",
        r##"return match(Ct(Cg(P"ab","k")), "ab")"##,
        true,
        1,
        r##"{["k"]="ab"}"##,
    ),
    (
        "Q12d",
        r##"return match(Ct(Cg(Cc(nil),"k")*Cc(1)), "")"##,
        true,
        1,
        r##"{[1]=1}"##,
    ),
    (
        "Q12e",
        r##"return match(Ct(Cg(P"a"/0)), "a")"##,
        true,
        1,
        r##"{[1]="a"}"##,
    ),
    (
        "Q12f",
        r##"return match(Cg(P"a"/0), "a")"##,
        true,
        1,
        r##""a""##,
    ),
    (
        "Q12g",
        r##"return match(Ct(Carg(1)*Carg(2)), "", 1, nil, 2)"##,
        true,
        1,
        r##"{[2]=2}"##,
    ),
    (
        "Q12h",
        r##"return match(Ct(Cp()*1*Cp()), "a")"##,
        true,
        1,
        r##"{[1]=1,[2]=2}"##,
    ),
    (
        "Q12i",
        r##"return match(Ct(P"a"), "a")"##,
        true,
        1,
        r##"{}"##,
    ),
    (
        "Q12j",
        r##"return match(Ct(Cg(C"a"*C"b","k")), "ab")"##,
        true,
        1,
        r##"{["k"]="a"}"##,
    ),
    (
        "Q13a",
        r##"return match(Cg(Cb"k","k"), "")"##,
        true,
        1,
        r##"1"##,
    ),
    (
        "Q13b",
        r##"return match(Cg(C"a","k")*Cg(C"b","k")*Cb"k", "ab")"##,
        true,
        1,
        r##""b""##,
    ),
    (
        "Q13c",
        r##"return match(C(Cg(C"a","k"))*Cb"k", "a")"##,
        false,
        1,
        r##""c:1: back reference 'k' not found""##,
    ),
    (
        "Q13d",
        r##"return match(Cg(C"a","k")*C(Cb"k"), "a")"##,
        true,
        2,
        r##""", "a""##,
    ),
    (
        "Q13e",
        r##"return match(Cg(P"ab","k")*Cb"k", "ab")"##,
        true,
        1,
        r##""ab""##,
    ),
    (
        "Q13f",
        r##"return match(Cg(C"a","k")*Ct(Cb"k"), "a")"##,
        true,
        1,
        r##"{[1]="a"}"##,
    ),
    (
        "Q13g",
        r##"return match(Cg(C"a"*C"b","k")*Cb"k", "ab")"##,
        true,
        2,
        r##""a", "b""##,
    ),
    (
        "Q13h",
        r##"return match(Cg(Cg(C"a","k")*C"b","j")*Cb"k", "ab")"##,
        false,
        1,
        r##""c:1: back reference 'k' not found""##,
    ),
    (
        "Q13i",
        r##"return match(Cg(C"a","k")*Cg(Cb"k","j")*Cb"j", "a")"##,
        true,
        1,
        r##""a""##,
    ),
    (
        "Q13j",
        r##"return match(Cg(C"a")*Cb"k", "a")"##,
        false,
        1,
        r##""c:1: back reference 'k' not found""##,
    ),
    ("Q14a", r##"return match(Cp(), "")"##, true, 1, r##"1"##),
    ("Q14b", r##"return match(P"a", "b")"##, true, 1, r##"nil"##),
    ("Q14c", r##"return match(P"a"/0, "a")"##, true, 1, r##"2"##),
    ("Q14d", r##"return match(P(1), 42)"##, true, 1, r##"2"##),
    (
        "Q14e",
        r##"return match(V"a", nil)"##,
        false,
        1,
        r##""c:1: rule 'a' used outside a grammar""##,
    ),
    (
        "Q14f",
        r##"return match(V"a"*1, "x")"##,
        false,
        1,
        r##""c:1: rule 'a' used outside a grammar""##,
    ),
    ("Q14g", r##"return match(P(-1), "")"##, true, 1, r##"1"##),
    (
        "Q14h",
        r##"return match(P"", "abc", 10)"##,
        true,
        1,
        r##"4"##,
    ),
    (
        "Q15a",
        r##"return match(P{"S", S="a"*V"S"+""}, ("a"):rep(100000))"##,
        true,
        1,
        r##"100001"##,
    ),
    (
        "Q15b",
        r##"return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(49)..("b"):rep(49))"##,
        true,
        1,
        r##"99"##,
    ),
    (
        "Q15c",
        r##"return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(50)..("b"):rep(50))"##,
        false,
        1,
        r##""c:1: too many pending calls/choices""##,
    ),
    (
        "Q15d",
        r##"return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(50))"##,
        false,
        1,
        r##""c:1: too many pending calls/choices""##,
    ),
    (
        "Q15e",
        r##"return match(P{"S", S="("*V"S"*")"+"x"}, ("("):rep(98).."x"..(")"):rep(98))"##,
        true,
        1,
        r##"198"##,
    ),
    (
        "Q15f",
        r##"return match(P{"S", S="("*V"S"*")"+"x"}, ("("):rep(99).."x"..(")"):rep(99))"##,
        false,
        1,
        r##""c:1: too many pending calls/choices""##,
    ),
    (
        "Q15g",
        r##"setmaxstack(1000); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(499)..("b"):rep(499))"##,
        true,
        1,
        r##"999"##,
    ),
    (
        "Q15h",
        r##"setmaxstack(1000); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(500)..("b"):rep(500))"##,
        false,
        1,
        r##""c:1: too many pending calls/choices""##,
    ),
    (
        "Q15i",
        r##"setmaxstack(2^32+1000); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(499)..("b"):rep(499))"##,
        true,
        1,
        r##"999"##,
    ),
    (
        "Q15j",
        r##"setmaxstack(2^31); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(49)..("b"):rep(49))"##,
        true,
        1,
        r##"99"##,
    ),
    (
        "Q15k",
        r##"setmaxstack(2^31); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(50)..("b"):rep(50))"##,
        false,
        1,
        r##""c:1: too many pending calls/choices""##,
    ),
    (
        "Q15l",
        r##"setmaxstack("1000"); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(499)..("b"):rep(499))"##,
        true,
        1,
        r##"999"##,
    ),
    (
        "Q15m",
        r##"return setmaxstack(1000.5)"##,
        false,
        1,
        r##""c:1: bad argument #1 to 'setmaxstack' (number has no integer representation)""##,
    ),
    (
        "Q15n",
        r##"setmaxstack(); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(49)..("b"):rep(49))"##,
        true,
        1,
        r##"99"##,
    ),
    (
        "Q15o",
        r##"setmaxstack(); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(50)..("b"):rep(50))"##,
        false,
        1,
        r##""c:1: too many pending calls/choices""##,
    ),
    (
        "Q15p",
        r##"setmaxstack(5); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(50)..("b"):rep(50))"##,
        false,
        1,
        r##""c:1: too many pending calls/choices""##,
    ),
    (
        "Q15q",
        r##"setmaxstack(150); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(74)..("b"):rep(74))"##,
        true,
        1,
        r##"149"##,
    ),
    (
        "Q15r",
        r##"setmaxstack(150); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(75)..("b"):rep(75))"##,
        false,
        1,
        r##""c:1: too many pending calls/choices""##,
    ),
    (
        "Q15s",
        r##"return setmaxstack("abc")"##,
        false,
        1,
        r##""c:1: bad argument #1 to 'setmaxstack' (number expected, got string)""##,
    ),
    (
        "Q15t",
        r##"setmaxstack("0x3e8"); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(499)..("b"):rep(499))"##,
        true,
        1,
        r##"999"##,
    ),
    (
        "Q15u",
        r##"setmaxstack(1000.0); return match(P{"S", S="a"*V"S"*"b"+""}, ("a"):rep(499)..("b"):rep(499))"##,
        true,
        1,
        r##"999"##,
    ),
    (
        "Q16a",
        r##"return match((P"a"+P"ab")*-1, "ab")"##,
        true,
        1,
        r##"nil"##,
    ),
    (
        "Q16b",
        r##"return match(C(P"a"^0), ("a"):rep(300))"##,
        true,
        1,
        r##""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""##,
    ),
    (
        "Q16c",
        r##"return #match(C(C(C(C(C(C(C(C(P"a")))))))), "a")"##,
        true,
        1,
        r##"1"##,
    ),
    (
        "Q17a",
        r##"return match(lpeg.P{"A", A=lpeg.C(lpeg.V"B")*lpeg.V"B", B=lpeg.Cc(1)}, "")"##,
        true,
        3,
        r##"1, "", 1"##,
    ),
    (
        "Q18a",
        r##"return match(Cg(Cc(1,2)), "")"##,
        true,
        2,
        r##"1, 2"##,
    ),
    (
        "Q18b",
        r##"return match(Ct(Cg(Cc(1,2),"k")), "")"##,
        true,
        1,
        r##"{["k"]=1}"##,
    ),
    (
        "Q19a",
        r##"return match(Ct(Cg(C"a","k"))*Cb"k", "a")"##,
        false,
        1,
        r##""c:1: back reference 'k' not found""##,
    ),
    (
        "Q20a",
        r##"return match(C(Cp()), "")"##,
        true,
        2,
        r##""", 1"##,
    ),
    (
        "R01",
        r##"return match(nil, "x")"##,
        false,
        1,
        r##""c:1: bad argument #1 to 'match' (lpeg-pattern expected, got nil)""##,
    ),
    (
        "R02",
        r##"return match(P(1), nil)"##,
        false,
        1,
        r##""c:1: bad argument #2 to 'match' (string expected, got nil)""##,
    ),
    (
        "R03",
        r##"return match(P(1), {})"##,
        false,
        1,
        r##""c:1: bad argument #2 to 'match' (string expected, got table)""##,
    ),
    (
        "R04",
        r##"return match(V"a", {}, "z")"##,
        false,
        1,
        r##""c:1: rule 'a' used outside a grammar""##,
    ),
    (
        "R05",
        r##"return match(P(1), "x", "z")"##,
        false,
        1,
        r##""c:1: bad argument #3 to 'match' (number expected, got string)""##,
    ),
    (
        "R06",
        r##"return match(Ct(Cg(Cb"k","k")), "")"##,
        false,
        1,
        r##""c:1: back reference 'k' not found""##,
    ),
    (
        "R07",
        r##"return match((Cb"nope")/0, "")"##,
        true,
        1,
        r##"1"##,
    ),
    (
        "R08",
        r##"return match(Cg(Cb"nope","k"), "")"##,
        true,
        1,
        r##"1"##,
    ),
    (
        "R09",
        r##"return match(Cs(Cg(Cb"nope","k")), "")"##,
        true,
        1,
        r##""""##,
    ),
    (
        "R10",
        r##"return match(C(Cb"nope")/0, "")"##,
        true,
        1,
        r##"1"##,
    ),
    ("R11", r##"return match("abc", "abcd")"##, true, 1, r##"4"##),
    (
        "R12",
        r##"return match({"a"}, "abc")"##,
        false,
        1,
        r##""c:1: grammar has no initial rule""##,
    ),
    ("R13", r##"return match(3, "abcd")"##, true, 1, r##"4"##),
    ("R14", r##"return match(true, "")"##, true, 1, r##"1"##),
    (
        "R16",
        r##"local p = V"a"*1; local ok, e = pcall(match, p, "x"); local ok2, e2 = pcall(match, p, "x"); return e, e2"##,
        true,
        2,
        r##""rule 'a' used outside a grammar", "rule 'a' used outside a grammar""##,
    ),
    (
        "R17",
        r##"return match(Cp()*Cb"x", "")"##,
        false,
        1,
        r##""c:1: back reference 'x' not found""##,
    ),
    (
        "R18",
        r##"return match(Cc(1)/"%1", "")"##,
        true,
        1,
        r##""1""##,
    ),
    (
        "R19",
        r##"return match(C"a"/"%1%1", "a")"##,
        true,
        1,
        r##""aa""##,
    ),
    (
        "R20",
        r##"return match(Ct(Cg(C"a"*C"b")), "ab")"##,
        true,
        1,
        r##"{[1]="a",[2]="b"}"##,
    ),
    (
        "R21",
        r##"return match(Ct(C"a"*Ct(C"b")), "ab")"##,
        true,
        1,
        r##"{[1]="a",[2]={[1]="b"}}"##,
    ),
    (
        "R22",
        r##"return match(Cg(C"a","k")*Ct(Cb"k"*Cb"k"), "a")"##,
        true,
        1,
        r##"{[1]="a",[2]="a"}"##,
    ),
    (
        "R23",
        r##"return match(Ct(Cg(Cb"k","j")), "")"##,
        false,
        1,
        r##""c:1: back reference 'k' not found""##,
    ),
    (
        "R24",
        r##"return match(Cg(C"x","k")*Ct(Cg(Cb"k","j")), "x")"##,
        true,
        1,
        r##"{["j"]="x"}"##,
    ),
    (
        "R25",
        r##"return match(Cs(Cg(C"a"))*Cs(Cc("Q")*"b"), "ab")"##,
        true,
        2,
        r##""a", "Qb""##,
    ),
    (
        "R26",
        r##"return match(C(1)^0/2, "abc")"##,
        true,
        1,
        r##""b""##,
    ),
    (
        "R27",
        r##"return match((C(1)*C(1))/0*C(1), "abc")"##,
        true,
        1,
        r##""c""##,
    ),
    (
        "R28",
        r##"return match(Carg(1)/"%0", "x", 1, 7)"##,
        true,
        1,
        r##""""##,
    ),
    (
        "R29",
        r##"return match(Carg(1)/"%0", "x", 1, {})"##,
        true,
        1,
        r##""""##,
    ),
    (
        "R30",
        r##"return match(Cs(Carg(1)), "", 1, {})"##,
        false,
        1,
        r##""c:1: invalid replacement value (a table)""##,
    ),
    (
        "R31",
        r##"return match(Cs(Carg(1)), "", 1, 2.5)"##,
        true,
        1,
        r##""2.5""##,
    ),
    (
        "R32",
        r##"return match(Cs(Cp()), "")"##,
        true,
        1,
        r##""1""##,
    ),
    (
        "R33",
        r##"return match((Cp()*Cp())/"%2", "")"##,
        true,
        1,
        r##""1""##,
    ),
    (
        "R34",
        r##"return match(C(P"a"^0)*Cp(), ("a"):rep(300))"##,
        true,
        2,
        r##""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 301"##,
    ),
    (
        "T01",
        r##"return match(Ct(Cg(C"a","k")*Cg(Cc(nil),"k")), "a")"##,
        true,
        1,
        r##"{}"##,
    ),
    (
        "T02",
        r##"return match(((P"a"/"x")*C"b")/"%1%2", "ab")"##,
        true,
        1,
        r##""xb""##,
    ),
    (
        "T03",
        r##"return match(Cs(Cs(P"a"/"x")*"b"), "ab")"##,
        true,
        1,
        r##""xb""##,
    ),
    (
        "T04",
        r##"return match(Cg(P"ab"), "ab")"##,
        true,
        1,
        r##""ab""##,
    ),
    (
        "T05",
        r##"return match(Ct(Cg(P"ab")), "ab")"##,
        true,
        1,
        r##"{[1]="ab"}"##,
    ),
    (
        "T06",
        r##"return match(Cs((C"a"/"%1%1")*(P"b"/"")), "ab")"##,
        true,
        1,
        r##""aa""##,
    ),
    (
        "T07",
        r##"return match(Ct((C(1)/"%0%0")^0), "ab")"##,
        true,
        1,
        r##"{[1]="aa",[2]="bb"}"##,
    ),
    (
        "T08",
        r##"return match(Cs((C(1)*Cc(3.0))/2), "a")"##,
        true,
        1,
        r##""3.0""##,
    ),
    (
        "T09",
        r##"return match(Cs(Cc(2^63)), "")"##,
        true,
        1,
        r##""9.2233720368548e+18""##,
    ),
    (
        "T10",
        r##"return match(Cs(Cc(-0.0)), "")"##,
        true,
        1,
        r##""-0.0""##,
    ),
    (
        "T11",
        r##"return match((C"a"*C"b")/"%2%1%0", "ab")"##,
        true,
        1,
        r##""baab""##,
    ),
    (
        "T12",
        r##"return match(Cg(C"a","k")*Cg(C"b","k")*Ct(Cb"k"), "ab")"##,
        true,
        1,
        r##"{[1]="b"}"##,
    ),
    (
        "T13",
        r##"return match(Cg(C"a"*Cg(C"b","k"),"k")*Cb"k", "ab")"##,
        true,
        1,
        r##""a""##,
    ),
    (
        "T14",
        r##"return match(Ct(C"a"*Cg(C"b"*C"c","k")), "abc")"##,
        true,
        1,
        r##"{[1]="a",["k"]="b"}"##,
    ),
    (
        "T15",
        r##"return match(Cs(C"a"*Ct(C"b")), "ab")"##,
        false,
        1,
        r##""c:1: invalid replacement value (a table)""##,
    ),
    (
        "T16",
        r##"return match(C"a"*Cg(C"b","k")*Cb"k"*Cb"k", "ab")"##,
        true,
        3,
        r##""a", "b", "b""##,
    ),
    (
        "T17",
        r##"return match(P"a"/"%", "a")"##,
        true,
        1,
        r##""\0""##,
    ),
    // `Cs` adds the subject between captures with a length that a capture
    // kept by `#V"B"` (`hascaptures` does not follow the call) makes
    // negative: `luaL_addlstring`'s `size_t` is "buffer too large" when the
    // buffer holds at least its magnitude, else "not enough memory".
    (
        "Qbuf1",
        r##"return match(P{"A", A = Cs(#V"B" * (P(1)/"y")), B = P(1)/"x"}, "ab")"##,
        false,
        1,
        r##""c:1: buffer too large""##,
    ),
    (
        "Qbuf2",
        r##"return match(P{"A", A = Cs(#V"B" * (P(1)/"y")), B = P(1)/""}, "ab")"##,
        false,
        1,
        r##""not enough memory""##,
    ),
    (
        "Qbuf3",
        r##"return match(P{"A", A = Cs(#V"B" * P(1) * (P(1)/"y")), B = P(2)/"x"}, "abc")"##,
        false,
        1,
        r##""c:1: buffer too large""##,
    ),
    (
        "Qbuf4",
        r##"return match(P{"A", A = Cs(#V"B" * C(1)), B = C(1)}, "ab")"##,
        false,
        1,
        r##""c:1: buffer too large""##,
    ),
];

/// `run.lua`'s runner, as a function of a case.
const RUNNER: &str = r#"
local lpeg = lpeg
local function ser(v, d)
  d = d or 0
  local t = type(v)
  if t == "string" then return (string.format("%q", v):gsub("\\\n", "\\n"))
  elseif t == "number" then return (math.type(v) == "integer" and "%d" or "%.17g"):format(v)
  elseif t == "table" then
    if d > 5 then return "{...}" end
    local ks = {}
    for k in pairs(v) do ks[#ks+1] = k end
    table.sort(ks, function(a, b) if type(a) == type(b) then return a < b end return type(a) < type(b) end)
    local p = {}
    for _, k in ipairs(ks) do p[#p+1] = "[" .. ser(k, d+1) .. "]=" .. ser(v[k], d+1) end
    return "{" .. table.concat(p, ",") .. "}"
  elseif t == "userdata" then return lpeg.type(v) and "<pattern>" or "<ud>"
  else return tostring(v) end
end
local env = setmetatable({}, {__index = function(_, k) return lpeg[k] or _G[k] end})
return function(chunk)
  local f = assert(load(chunk, "=c", "t", env))
  local r = table.pack(pcall(f))
  local out = {}
  for i = 2, r.n do out[#out+1] = ser(r[i]) end
  lpeg.setmaxstack(100)
  return r[1], r.n - 1, table.concat(out, ", ")
end
"#;

#[test]
fn match_quirks_are_the_cs() {
    let mut lua = lpeg_eval::new_lua();
    let ex = lua
        .try_enter(|ctx| {
            let c = Closure::load(ctx, Some("=runner"), RUNNER.as_bytes())?;
            Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
        })
        .expect("the runner compiles");
    assert!(lpeg_eval::step_only(&mut lua, &ex, 1_000_000, 100).0);
    lua.enter(|ctx| {
        let f: Function = ctx
            .fetch(&ex)
            .take_result::<Function>(ctx)
            .unwrap()
            .unwrap();
        ctx.set_global("run_case", f);
    });
    let mut bad = Vec::new();
    for &(id, chunk, ok, n, vals) in CASES {
        let ex = lua.enter(|ctx| {
            let f: Function = ctx.get_global("run_case").expect("run_case");
            ctx.stash(Executor::start(ctx, f, ctx.intern(chunk.as_bytes())))
        });
        let (done, _) = lpeg_eval::step_only(&mut lua, &ex, 1_000_000, 100_000);
        assert!(done, "{id}: unfinished");
        let got = lua.enter(|ctx| {
            let vs: Variadic<Vec<Value>> = ctx.fetch(&ex).take_result(ctx).unwrap().unwrap();
            let s = |v: Value| match v {
                Value::String(s) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
                v => v.display().to_string(),
            };
            (
                vs.0[0].to_bool(),
                usize::try_from(vs.0[1].to_integer().unwrap()).unwrap(),
                s(vs.0[2]),
            )
        });
        if got != (ok, n, vals.to_string()) {
            bad.push(format!(
                "  {id}: {chunk}\n    C    = {ok} {n} {vals}\n    port = {} {} {}",
                got.0, got.1, got.2
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} of {} cases differ:\n{}",
        bad.len(),
        CASES.len(),
        bad.join("\n")
    );
}
