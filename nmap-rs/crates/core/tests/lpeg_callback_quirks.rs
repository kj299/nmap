//! `lpeg.match`'s captures that call Lua, against the C, case by case: the
//! 207 pins of M6.6 step d's brief (`probe/quirks.lua`, run with its
//! `harness.lua`), each the answer of the tree's standalone oracle
//! (`oracle/build_lua_oracle.sh`) and of the C as M6.6's Phase 0 measured it
//! (the brief: "0 mismatches on both oracles") — `Cmt`'s arguments and the
//! decoding of its results, dynamic captures through backtracking and
//! `#p`, when a `/f` runs and how often, `Cf`, `/table` and `__index`,
//! error objects, re-entry and C levels, `locale(t)`, a grammar's `__index`,
//! and the corpus's `json.lua`, `lpeg-utility.lua` and `re.lua` over them.
//!
//! Each case is a chunk, named `=case`, run in an environment over the
//! globals, with `lpeg`, `re`, `json` and `U` (lpeg-utility) loaded as the
//! harness loads them (`stdnse`, `unittest` and `unicode` stubbed), its
//! results serialised by the harness's `ser` as `n=COUNT:VALUES` and an
//! error as `ERR:OBJECT`. LPeg is called through a direct `pcall`, so its
//! own errors carry no position.
//!
//! **No exemption list.** A case answers as the C does, or the port's
//! answer is pinned beside the C's under a named class, each a ledger entry
//! ([`CLASSED`]): the port's deliberate departures (wide indices, the
//! callbacks' yields), the ceilings that are the embedding's (the Lua
//! stack's slots, C levels), and the tree's own file paths.
#![cfg(not(miri))] // the VM over 207 cases, a million-step few among them

mod lpeg_eval;

use piccolo::{Closure, Executor, Function, Value, Variadic};

/// `harness.lua`, less its loading of the libraries
/// (`lpeg_eval::new_lua_with_nselib`) and its loop: `run(code)` serialises
/// what a case returns.
const HARNESS: &str = r#"

local function ser(v, depth)
  depth = depth or 0
  local t = type(v)
  if t == "string" then return string.format("%q", v):gsub("\\\n", "\\n")
  elseif t == "number" then
    if math.type(v) == "integer" then return tostring(v) else
      if v ~= v then return "nan" end
      return string.format("%.17g", v) .. "f" end
  elseif t == "table" then
    if depth > 2 then return "{...}" end
    local ks = {}
    for k in pairs(v) do ks[#ks + 1] = k end
    table.sort(ks, function(a, b)
      local ta, tb = type(a), type(b)
      if ta ~= tb then return ta < tb end
      if ta == "number" or ta == "string" then return a < b end
      return tostring(a) < tostring(b)
    end)
    local parts = {}
    for _, k in ipairs(ks) do
      parts[#parts + 1] = "[" .. ser(k, depth + 1) .. "]=" .. ser(v[k], depth + 1)
    end
    return "{" .. table.concat(parts, ",") .. "}"
  elseif t == "userdata" then
    return lpeg.type(v) == "pattern" and "<pattern>" or "<userdata>"
  elseif t == "function" then return "<function>"
  else return tostring(v) end
end

return function(code)
  local f, err = load(code, "=case", "t", setmetatable({}, {__index = _G}))
  if not f then return "LOADERR:" .. err end
  local r = table.pack(pcall(f))
  lpeg.setmaxstack(100)
  if not r[1] then return "ERR:" .. ser(r[2]) end
  local parts = {}
  for i = 2, r.n do parts[#parts + 1] = ser(r[i]) end
  return "n=" .. (r.n - 1) .. ":" .. table.concat(parts, ",")
end
"#;

/// (id, chunk, the C's answer), `quirks.lua`'s cases in its order.
const CASES: &[(&str, &str, &str)] = &[
    (
        "M01",
        r###"return lpeg.match(lpeg.Cmt(lpeg.P"ab", function(s,i,...) return true, select('#',...), ... end), "abc")"###,
        r###"n=2:1,"ab""###,
    ),
    (
        "M02",
        r###"return lpeg.match(lpeg.P"x" * lpeg.Cmt(lpeg.C"a"*lpeg.C"b", function(s,i,a,b) return true, s, i, a, b end), "xabc")"###,
        r###"n=4:"xabc",4,"a","b""###,
    ),
    (
        "M03",
        r###"return lpeg.match(lpeg.Cmt(1, function(s) return true, type(s), s end), 123)"###,
        r###"n=2:"string","123""###,
    ),
    (
        "M04",
        r###"return lpeg.match(lpeg.Cmt(1, function(s,i) return true, i end), "abc", 2)"###,
        r###"n=1:3"###,
    ),
    (
        "M05",
        r###"return lpeg.match(lpeg.P(function(...) return true, select('#', ...), (select(3, ...)) end), "ab")"###,
        r###"n=2:3,"""###,
    ),
    (
        "M06",
        r###"return lpeg.match(lpeg.P"a" * function(s,i) return i end, "ab")"###,
        r###"n=1:2"###,
    ),
    (
        "M07",
        r###"return lpeg.match(lpeg.Cmt(lpeg.Carg(1), function(s,i,a) return true, a end), "x", 1, "A")"###,
        r###"n=1:"A""###,
    ),
    (
        "M08",
        r###"return pcall(lpeg.match, lpeg.Cmt(lpeg.Carg(2), function() return true end), "x")"###,
        r###"n=2:false,"reference to absent argument #2""###,
    ),
    (
        "M09",
        r###"return lpeg.match(lpeg.Cg(lpeg.C"a","n") * lpeg.Cmt(lpeg.Cb"n", function(s,i,v) return true, v.."!" end), "a")"###,
        r###"n=1:"a!""###,
    ),
    (
        "M10",
        r###"return lpeg.match(lpeg.Cmt(lpeg.Cg(lpeg.C"a","k"), function(s,i,...) return true, ... end), "a")"###,
        r###"n=1:"a""###,
    ),
    (
        "M11",
        r###"return pcall(lpeg.match, lpeg.Cmt(lpeg.Cg(lpeg.C"a","k"), function() return true end) * lpeg.Cb"k", "a")"###,
        r###"n=2:false,"back reference 'k' not found""###,
    ),
    (
        "M12",
        r###"return lpeg.match(lpeg.Cmt(0, function(s,i) return true, i end), "abc", 10)"###,
        r###"n=1:4"###,
    ),
    (
        "M13",
        r###"return lpeg.match(lpeg.Cmt(lpeg.C(1) * lpeg.Cc(nil) * lpeg.C(1), function(s, i, ...) return true, select('#', ...), ... end), "ab")"###,
        r###"n=4:3,"a",nil,"b""###,
    ),
    (
        "M14",
        r###"return lpeg.match(lpeg.Cmt(lpeg.Cc(1, 2, 3), function(s, i, ...) return true, select('#', ...) end), "")"###,
        r###"n=1:3"###,
    ),
    (
        "M15",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, error), "abc")"###,
        r###"n=2:false,"abc""###,
    ),
    (
        "R01",
        r###"return lpeg.match(lpeg.Cmt(1, function() return 3 end)*lpeg.Cp(), "abcd")"###,
        r###"n=1:3"###,
    ),
    (
        "R02",
        r###"return lpeg.match(lpeg.Cmt(1, function() return "3" end)*lpeg.Cp(), "abcd")"###,
        r###"n=1:3"###,
    ),
    (
        "R03",
        r###"return lpeg.match(lpeg.Cmt(1, function() return " 2 " end)*lpeg.Cp(), "abcd")"###,
        r###"n=1:2"###,
    ),
    (
        "R04",
        r###"return lpeg.match(lpeg.Cmt(1, function() return "0x3" end)*lpeg.Cp(), "abcd")"###,
        r###"n=1:3"###,
    ),
    (
        "R05",
        r###"return lpeg.match(lpeg.Cmt(1, function() return "3e0" end)*lpeg.Cp(), "abcd")"###,
        r###"n=1:3"###,
    ),
    (
        "R06",
        r###"return lpeg.match(lpeg.Cmt(1, function() return 3.0 end)*lpeg.Cp(), "abcd")"###,
        r###"n=1:3"###,
    ),
    (
        "R07",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function() return 3.5 end), "abcd")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R08",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function() return 0 end), "abcd")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R09",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function() return {} end), "abcd")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R10",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function() return "x" end), "abcd")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R11",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function() return 2^63 end), "abcd")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R12",
        r###"return pcall(lpeg.match, lpeg.P"ab" * lpeg.Cmt(1, function() return 3 end), "abcd")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R13",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function() return math.mininteger end), "abcd")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R14",
        r###"return lpeg.match(lpeg.Cmt(1, function(s) return #s+1 end), "ab")"###,
        r###"n=1:3"###,
    ),
    (
        "R15",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function(s) return #s+2 end), "ab")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R16",
        r###"return lpeg.match(lpeg.Cmt(1, function() return false end), "a")"###,
        r###"n=1:nil"###,
    ),
    (
        "R17",
        r###"return lpeg.match(lpeg.Cmt(1, function() return nil end), "a")"###,
        r###"n=1:nil"###,
    ),
    (
        "R18",
        r###"return lpeg.match(lpeg.Cmt(1, function() end), "a")"###,
        r###"n=1:nil"###,
    ),
    (
        "R19",
        r###"return lpeg.match(lpeg.Cmt(1, function() return true, nil end), "a")"###,
        r###"n=1:nil"###,
    ),
    (
        "R20",
        r###"return lpeg.match(lpeg.Cmt(1, function() return true, nil, 3 end), "a")"###,
        r###"n=2:nil,3"###,
    ),
    (
        "R21",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function() return 1, "v" end) * lpeg.Cp(), "ab")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R22",
        r###"return lpeg.match(lpeg.Cmt(1, function(s,i) return i, "v" end) * lpeg.Cp(), "ab")"###,
        r###"n=2:"v",2"###,
    ),
    (
        "R23",
        r###"return lpeg.match(lpeg.Cmt(1, function() return true end), "a")"###,
        r###"n=1:2"###,
    ),
    (
        "R24",
        r###"return lpeg.match(lpeg.Ct(lpeg.Cmt(1, function() return true, 1, 2 end)), "a")"###,
        r###"n=1:{[1]=1,[2]=2}"###,
    ),
    (
        "R25",
        r###"local t={}; return rawequal(lpeg.match(lpeg.Cmt(1, function() return true, t end), "a"), t)"###,
        r###"n=1:true"###,
    ),
    (
        "R26",
        r###"local t={}; for i=1,100 do t[i]=i end; return select('#', lpeg.match(lpeg.Cmt(1, function() return true, table.unpack(t) end), "a"))"###,
        r###"n=1:100"###,
    ),
    (
        "R27",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function() return 0/0 end), "a")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R28",
        r###"return lpeg.match(lpeg.Cmt(1, function() return "2.0" end) * lpeg.Cp(), "ab")"###,
        r###"n=1:2"###,
    ),
    (
        "R29",
        r###"return pcall(lpeg.match, lpeg.Cmt(lpeg.P"abc", function(s, i) return i - 1 end), "abcd")"###,
        r###"n=2:false,"invalid position returned by match-time capture""###,
    ),
    (
        "R30",
        r###"return lpeg.match(lpeg.C(lpeg.Cmt(1, function(s) return 4 end)), "abcd")"###,
        r###"n=1:"abc""###,
    ),
    (
        "R31",
        r###"return lpeg.match(#lpeg.Cmt(1, function(s) return #s+1 end) * lpeg.C(1), "abc")"###,
        r###"n=1:"a""###,
    ),
    (
        "N01",
        r###"return lpeg.match(lpeg.Cmt(lpeg.Cmt(1, function() return true, "x", "y" end) * lpeg.Cmt(1, function() return true, "z" end), function(s,i,...) return true, table.concat({...}, ",") end), "ab")"###,
        r###"n=1:"x,y,z""###,
    ),
    (
        "N02",
        r###"return lpeg.match(lpeg.Cmt(lpeg.Cmt(1, function() return true, "x" end), function() return true end), "a")"###,
        r###"n=1:2"###,
    ),
    (
        "N03",
        r###"return lpeg.match(lpeg.Cmt(lpeg.Cmt(lpeg.P"ab", function() return true end), function(s,i,...) return true, ... end), "ab")"###,
        r###"n=1:"ab""###,
    ),
    (
        "N04",
        r###"return lpeg.match(lpeg.Cmt(1, function() return true, "x" end) * "b" + lpeg.C(1), "ac")"###,
        r###"n=1:"a""###,
    ),
    (
        "N05",
        r###"local n=0; lpeg.match(lpeg.Cmt(1, function() n=n+1 return true end)^0, "abc"); return n"###,
        r###"n=1:3"###,
    ),
    (
        "N06",
        r###"return lpeg.match(-lpeg.Cmt(1, function() return false end) * lpeg.C(1), "a")"###,
        r###"n=1:"a""###,
    ),
    (
        "N07",
        r###"return lpeg.match(#lpeg.Cmt(1, function() return true, "x" end) * lpeg.C(1), "a")"###,
        r###"n=1:"a""###,
    ),
    (
        "N08",
        r###"return lpeg.match(lpeg.Cg(lpeg.Cmt(1, function() return true, "v" end), "k") * lpeg.Cb"k", "a")"###,
        r###"n=1:"v""###,
    ),
    (
        "N09",
        r###"return lpeg.match(lpeg.Ct(lpeg.Cg(lpeg.Cmt(1, function() return true, "v", "w" end), "k")), "a")"###,
        r###"n=1:{["k"]="v"}"###,
    ),
    (
        "N10",
        r###"return lpeg.match(lpeg.Cf(lpeg.Cmt(1, function() return true, 1, 2 end) * lpeg.Cc(10), function(a, b) return a + b end), "a")"###,
        r###"n=1:11"###,
    ),
    (
        "N11",
        r###"return lpeg.match(lpeg.Cs(lpeg.Cmt(1, function(s,i,c) return true, c:upper() end)), "a")"###,
        r###"n=1:"A""###,
    ),
    (
        "N12",
        r###"return lpeg.match(lpeg.Cs(lpeg.Cmt(lpeg.P"a", function() return true end) * "b"), "ab")"###,
        r###"n=1:"ab""###,
    ),
    (
        "N13",
        r###"return pcall(lpeg.match, lpeg.Cs(lpeg.Cmt(1, function() return true, {} end)), "a")"###,
        r###"n=2:false,"invalid replacement value (a table)""###,
    ),
    (
        "N14",
        r###"local p = lpeg.Ct(((lpeg.Cmt(1, function(s, i) return i, 'v' end) * 'z') + lpeg.C(1))^0); local r = lpeg.match(p, ('a'):rep(1000000)); return #r, r[1] "###,
        r###"n=2:1000000,"a""###,
    ),
    (
        "N15",
        r###"local n=0; local ok, e = pcall(lpeg.match, (#lpeg.Cmt(1, function() n=n+1 return true, 1 end) * 1)^0, string.rep("a", 1100000)); return n, ok, e"###,
        r###"n=3:999957,false,"stack overflow""###,
    ),
    (
        "N16",
        r###"local n=0; local ok, e = pcall(lpeg.match, (#lpeg.Cmt(1, function() n=n+1 return true end) * 1)^0, string.rep("a", 1100000)); return n, ok, e"###,
        r###"n=3:1100000,true,1100001"###,
    ),
    (
        "N17",
        r###"local n=0; local ok, e = pcall(lpeg.match, lpeg.Cmt(1, function() n=n+1 return true, 1 end)^0, string.rep("a", 1100000)); return n, ok, e"###,
        r###"n=3:999957,false,"stack overflow""###,
    ),
    (
        "N18",
        r###"local n=0; local ok, e = pcall(function() return select('#', lpeg.match(lpeg.Cmt(1, function() n=n+1 return true, 1 end)^0, string.rep("a", 999900))) end); return n, ok, (e:gsub("^case:1: ", ""))"###,
        r###"n=3:999900,false,"stack overflow (too many captures)""###,
    ),
    (
        "N19",
        r###"local t = lpeg.match(lpeg.Ct(lpeg.Cmt(1, function(s,i) return true, i end)^0), string.rep("a", 33000)); local bad; for k=1,#t do if t[k] ~= k+1 then bad=k break end end; return #t, bad"###,
        r###"n=2:33000,32762"###,
    ),
    (
        "N20",
        r###"local p = (lpeg.Cmt(1, function() return true, "a" end) * lpeg.Cmt(1, function() return true, "b" end) * "z" + lpeg.Cmt(1, function() return true, "c" end))^0; return lpeg.match(p, "xyzw")"###,
        r###"n=3:"a","b","c""###,
    ),
    (
        "N21",
        r###"local n = 0; local p = lpeg.Cmt(lpeg.Cmt(1, function() return true, 1, 2, 3 end)^0, function(s, i, ...) n = select('#', ...); return true end); local r = lpeg.match(p, string.rep("a", 1000)); return n, r"###,
        r###"n=2:3000,1001"###,
    ),
    (
        "N22",
        r###"return lpeg.match(lpeg.Ct(lpeg.C(1) * lpeg.Cmt(1, function() return true, "x", "y" end) * lpeg.C(1)), "abc")"###,
        r###"n=1:{[1]="a",[2]="x",[3]="y",[4]="c"}"###,
    ),
    (
        "N23",
        r###"return pcall(lpeg.match, lpeg.Cf(lpeg.Cmt(1, function() return true end) * lpeg.Cc(1), print), "x")"###,
        r###"n=2:true,1"###,
    ),
    (
        "N24",
        r###"local log = {}; local p = lpeg.Cmt(lpeg.P(1), function(s, i) log[#log+1] = i; return true end); lpeg.match((p * p * "x" + p)^0, "abc"); return table.concat(log, ",")"###,
        r###"n=1:"2,3,2,3,4,3,4,4""###,
    ),
    (
        "N25",
        r###"local p = lpeg.Cmt(1, function(s, i) return i end) / function(...) return select('#', ...), ... end; return lpeg.match(p, "x")"###,
        r###"n=2:1,"x""###,
    ),
    (
        "F01",
        r###"local log={}; local p = lpeg.Cmt(lpeg.P(1)/function(c) log[#log+1]="f"..c; return c end, function(s,i,c) log[#log+1]="cmt"..c; return true end) * (lpeg.P(1)/function(c) log[#log+1]="g"..c end); log[#log+1]="ret"; lpeg.match(p, "ab"); return table.concat(log, " ")"###,
        r###"n=1:"ret fa cmta gb""###,
    ),
    (
        "F02",
        r###"local n=0; local r = lpeg.match(lpeg.Cmt(lpeg.P(1)/function() n=n+1 end, function() return true end) * "z", "ab"); return n, r"###,
        r###"n=2:1,nil"###,
    ),
    (
        "F03",
        r###"local n=0; local r = lpeg.match((lpeg.P(1)/function() n=n+1 end) * "z", "ab"); return n, r"###,
        r###"n=2:0,nil"###,
    ),
    (
        "F04",
        r###"local n=0; lpeg.match(lpeg.Cmt(lpeg.P(1)/function() n=n+1 return "v" end, function(s,i,v) return true, v end), "a"); return n"###,
        r###"n=1:1"###,
    ),
    (
        "F05",
        r###"local n=0; lpeg.match((lpeg.P(1)/function() n=n+1 end) * "z" + 1, "ab"); return n"###,
        r###"n=1:0"###,
    ),
    (
        "F06",
        r###"local n=0; lpeg.match(lpeg.Cmt(lpeg.P(1)/function() n=n+1 end, function() return true end) * "z" + lpeg.Cmt(lpeg.P(1)/function() n=n+10 end, function() return true end), "ab"); return n"###,
        r###"n=1:11"###,
    ),
    (
        "F07",
        r###"return lpeg.match(lpeg.P"ab"/function(...) return select('#',...), ... end, "ab")"###,
        r###"n=2:1,"ab""###,
    ),
    (
        "F08",
        r###"return lpeg.match(lpeg.P(1)/function() return 1,2,3 end, "a")"###,
        r###"n=3:1,2,3"###,
    ),
    (
        "F09",
        r###"return lpeg.match(lpeg.P(1)/function() end, "a")"###,
        r###"n=1:2"###,
    ),
    (
        "F10",
        r###"return lpeg.match(lpeg.Cg(lpeg.C"a","k")/function(...) return select('#', ...), ... end, "a")"###,
        r###"n=2:1,"a""###,
    ),
    (
        "F11",
        r###"return lpeg.match(lpeg.C(1)/string.upper, "a")"###,
        r###"n=1:"A""###,
    ),
    (
        "F12",
        r###"local log={}; lpeg.match(((lpeg.C(1)/function(c) log[#log+1]=c end) * (lpeg.C(1)/function(c) log[#log+1]=c end))/function() log[#log+1]="outer" end, "ab"); return table.concat(log, " ")"###,
        r###"n=1:"a b outer""###,
    ),
    (
        "F13",
        r###"local n=0; lpeg.match(lpeg.Cg(lpeg.P(1)/function() n=n+1 end, "k") * lpeg.Cb"k" * lpeg.Cb"k", "a"); return n"###,
        r###"n=1:2"###,
    ),
    (
        "F14",
        r###"local n=0; local r = lpeg.match(((lpeg.C(1)/function() n=n+1 return "w" end) * (lpeg.C(1)/function() n=n+1 return "x" end))/2, "ab"); return n, r"###,
        r###"n=2:2,"x""###,
    ),
    (
        "F15",
        r###"local n=0; local r = lpeg.match(((lpeg.C(1)/function() n=n+1 end) * (lpeg.C(1)/function() n=n+1 return "x" end))/0, "ab"); return n, r"###,
        r###"n=2:0,3"###,
    ),
    (
        "F16",
        r###"local n=0; local r = lpeg.match(((lpeg.P(1)/function() n=n+1 return "x" end) * (lpeg.P(1)/function() n=n+1 return "y" end))/"%2%2", "ab"); return n, r"###,
        r###"n=2:2,"yy""###,
    ),
    (
        "F17",
        r###"return pcall(lpeg.match, lpeg.Cs(lpeg.P(1)/function() return nil end), "a")"###,
        r###"n=2:false,"invalid replacement value (a nil)""###,
    ),
    (
        "F18",
        r###"return lpeg.match(lpeg.Cs(lpeg.P(1)/function() end), "a")"###,
        r###"n=1:"a""###,
    ),
    (
        "F19",
        r###"return pcall(lpeg.match, (lpeg.P(1)/function() return {} end)/"%1", "a")"###,
        r###"n=2:false,"invalid capture value (a table)""###,
    ),
    (
        "F20",
        r###"return lpeg.match(lpeg.Cs(lpeg.P(1)/function() return 7 end), "a")"###,
        r###"n=1:"7""###,
    ),
    (
        "F21",
        r###"return lpeg.match(lpeg.P(1)/setmetatable({}, {__call=function() return "called" end, __index=function() return "indexed" end}), "a")"###,
        r###"n=1:"indexed""###,
    ),
    (
        "F22",
        r###"local log={}; lpeg.match(lpeg.Cf(lpeg.C(1)/function(c) log[#log+1]="v"..c return c end * (lpeg.C(1)/function(c) log[#log+1]="v"..c return c end)^0, function(a,b) log[#log+1]="f" return a..b end), "abc"); return table.concat(log," ")"###,
        r###"n=1:"va vb f vc f""###,
    ),
    (
        "F23",
        r###"local log={}; lpeg.match(lpeg.Ct((lpeg.C(1)/function(c) log[#log+1]=c end) * lpeg.Cg(lpeg.C(1)/function(c) log[#log+1]=c end, "k") * (lpeg.C(1)/function(c) log[#log+1]=c end)), "abc"); return table.concat(log," ")"###,
        r###"n=1:"a b c""###,
    ),
    (
        "F24",
        r###"local n=0; local r = {lpeg.match(lpeg.Cg(lpeg.C(1)/function() n=n+1 end, "k") * lpeg.C(1), "ab")}; return n, r[1] "###,
        r###"n=2:0,"b""###,
    ),
    (
        "F25",
        r###"return pcall(lpeg.match, lpeg.Cmt(lpeg.P(1)/function() error("in", 0) end, function() return true end) + 1, "a")"###,
        r###"n=2:false,"in""###,
    ),
    (
        "F26",
        r###"return pcall(lpeg.match, (lpeg.P(1)/function() error("in",0) end) * "z" + 1, "a")"###,
        r###"n=2:true,2"###,
    ),
    (
        "F27",
        r###"local n=0; local r = lpeg.match(lpeg.Cmt(lpeg.Cf(lpeg.Cc(1)*lpeg.Cc(2), function(a,b) n=n+1 return a+b end), function(s,i,v) return true, v end) * "z", "a"); return n, r"###,
        r###"n=2:1,nil"###,
    ),
    (
        "F28",
        r###"local log = {}; local f = function(tag) return function(...) log[#log+1] = tag; return ... end end; local p = lpeg.Cmt((lpeg.C(1)/f"a") * lpeg.Cmt((lpeg.C(1)/f"b"), function(s,i,v) log[#log+1]="cmt-in"; return true, v end), function(s,i,...) log[#log+1]="cmt-out"; return true, ... end) / f"post"; lpeg.match(p, "xy"); return table.concat(log, " ")"###,
        r###"n=1:"b cmt-in a cmt-out post""###,
    ),
    (
        "F29",
        r###"return pcall(lpeg.match, (lpeg.P(1)/function() end)/"%1", "a")"###,
        r###"n=2:false,"no values in capture index 1""###,
    ),
    (
        "F30",
        r###"return lpeg.match(lpeg.Cs(lpeg.P(1)/function() return 0.1 end), "a")"###,
        r###"n=1:"0.1""###,
    ),
    (
        "C01",
        r###"return lpeg.match(lpeg.Cf(lpeg.C(1)^1, function(a,b) return a..b end), "abc")"###,
        r###"n=1:"abc""###,
    ),
    (
        "C02",
        r###"return pcall(lpeg.match, lpeg.Cf(lpeg.P"a", print), "a")"###,
        r###"n=2:false,"no initial value for fold capture""###,
    ),
    (
        "C03",
        r###"return pcall(lpeg.match, lpeg.Cf(lpeg.P"a"^0, print), string.rep("a", 300))"###,
        r###"n=2:false,"no initial value for fold capture""###,
    ),
    (
        "C04",
        r###"return pcall(lpeg.match, lpeg.Cf(lpeg.Cg(lpeg.C"a","x")*lpeg.C"b", print), "ab")"###,
        r###"n=2:false,"no initial value for fold capture""###,
    ),
    (
        "C05",
        r###"return lpeg.match(lpeg.Cf(lpeg.Cc(1,2) * lpeg.Cc(3), function(a,b) return a+b end), "")"###,
        r###"n=1:4"###,
    ),
    (
        "C06",
        r###"return lpeg.match(lpeg.Cf(lpeg.Cc(0) * lpeg.Cc(1,2), function(a,...) return select('#',...) end), "")"###,
        r###"n=1:2"###,
    ),
    (
        "C07",
        r###"return lpeg.match(lpeg.Cf(lpeg.Cc(0) * lpeg.Cg(lpeg.Cc(5),"k"), function(a, ...) return a + select('#', ...) + 10 end), "")"###,
        r###"n=1:10"###,
    ),
    (
        "C08",
        r###"return select('#', lpeg.match(lpeg.Cf(lpeg.Cc(0)*lpeg.Cc(1), function() end), ""))"###,
        r###"n=1:1"###,
    ),
    (
        "C09",
        r###"return lpeg.match(lpeg.Cf(lpeg.Cc("a") * lpeg.Cc("b"), function(a,b) return a..b, "extra" end), "")"###,
        r###"n=1:"ab""###,
    ),
    (
        "C10",
        r###"return pcall(lpeg.Cf, 1, 2)"###,
        r###"n=2:false,"bad argument #2 to 'lpeg.Cf' (function expected, got number)""###,
    ),
    (
        "C11",
        r###"return lpeg.match(lpeg.Cf(lpeg.Cc(1), error), "")"###,
        r###"n=1:1"###,
    ),
    (
        "C12",
        r###"return pcall(lpeg.match, lpeg.Cf(lpeg.P"a"/function() end * lpeg.Cc(1), print), "a")"###,
        r###"n=2:false,"no initial value for fold capture""###,
    ),
    (
        "C13",
        r###"return lpeg.match(lpeg.Cf(lpeg.Ct"" * lpeg.Cg(lpeg.C"a" * lpeg.C"b")^0, rawset), "abab")"###,
        r###"n=1:{["a"]="b"}"###,
    ),
    (
        "C14",
        r###"return lpeg.match(lpeg.Cf(lpeg.Cmt(1, function() return true, nil end) * lpeg.Cc(1), function(a, b) return tostring(a) .. b end), "x")"###,
        r###"n=1:"nil1""###,
    ),
    (
        "Q01",
        r###"return lpeg.match(lpeg.C(1)/{a=false}, "a")"###,
        r###"n=1:false"###,
    ),
    (
        "Q02",
        r###"return lpeg.match(lpeg.C(1)/{}, "a")"###,
        r###"n=1:2"###,
    ),
    (
        "Q03",
        r###"return lpeg.match(lpeg.Ct((lpeg.C(1)/{a=1})^0), "aba")"###,
        r###"n=1:{[1]=1,[2]=1}"###,
    ),
    (
        "Q04",
        r###"return lpeg.match(lpeg.C(1)/setmetatable({}, {__index=function(t,k) return k:upper() end}), "a")"###,
        r###"n=1:"A""###,
    ),
    (
        "Q05",
        r###"return lpeg.match((lpeg.P(1)/function() return nil end)/setmetatable({}, {__index=function(t,k) return tostring(k) end}), "a")"###,
        r###"n=1:"nil""###,
    ),
    (
        "Q06",
        r###"return lpeg.match((lpeg.P(1)/function() return 0/0 end)/{}, "a")"###,
        r###"n=1:2"###,
    ),
    (
        "Q07",
        r###"return lpeg.match((lpeg.P(1)/function() return 0/0 end)/setmetatable({}, {__index=function(t,k) return tostring(k ~= k) end}), "a")"###,
        r###"n=1:"true""###,
    ),
    (
        "Q08",
        r###"return lpeg.match((lpeg.C"a"*lpeg.C"b")/{a="x", b="y"}, "ab")"###,
        r###"n=1:"x""###,
    ),
    (
        "Q09",
        r###"return lpeg.match(lpeg.P"ab"/{ab=1}, "ab")"###,
        r###"n=1:1"###,
    ),
    (
        "Q10",
        r###"return lpeg.match(lpeg.Cp()/{"one"}, "")"###,
        r###"n=1:"one""###,
    ),
    (
        "Q11",
        r###"return lpeg.match((lpeg.P(1)/function() return 1.0 end)/{"one"}, "a")"###,
        r###"n=1:"one""###,
    ),
    (
        "Q12",
        r###"return lpeg.match(lpeg.C(1)/setmetatable({}, {__index={a=7}}), "a")"###,
        r###"n=1:7"###,
    ),
    (
        "Q13",
        r###"return lpeg.match(lpeg.C(1)/setmetatable({}, {__index=function() return nil end}), "a")"###,
        r###"n=1:2"###,
    ),
    (
        "Q14",
        r###"local t = {q=1}; local ok, e = pcall(lpeg.match, lpeg.C(1)/setmetatable({}, {__index=function() error(t) end}), "a"); return ok, rawequal(e, t)"###,
        r###"n=2:false,true"###,
    ),
    (
        "Q15",
        r###"local n=0; local p = lpeg.Cmt(lpeg.C(1)/setmetatable({}, {__index=function(t,k) n=n+1 return k end}), function(s,i,v) return true, v end) * "z"; local r = lpeg.match(p, "ab"); return n, r"###,
        r###"n=2:1,nil"###,
    ),
    (
        "Q16",
        r###"local ok, e = pcall(function() return lpeg.P(1)/io.stdout end); return ok, (e:gsub("^case:1: ", ""))"###,
        r###"n=2:false,"bad argument #2 to 'div' (invalid replacement value)""###,
    ),
    (
        "Q17",
        r###"return lpeg.match(lpeg.Cg(lpeg.C"a","k")/{a=1}, "a")"###,
        r###"n=1:1"###,
    ),
    (
        "E01",
        r###"local t = {code=1}; local ok, e = pcall(lpeg.match, lpeg.Cmt(1, function() error(t) end), "a"); return ok, rawequal(e, t)"###,
        r###"n=2:false,true"###,
    ),
    (
        "E02",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function() error("x") end), "a")"###,
        r###"n=2:false,"case:1: x""###,
    ),
    (
        "E03",
        r###"return pcall(lpeg.match, lpeg.Cmt(1, function() error() end), "a")"###,
        r###"n=2:false,nil"###,
    ),
    (
        "E04",
        r###"return pcall(lpeg.match, lpeg.P(function() error("boom", 2) end), "a")"###,
        r###"n=2:false,"boom""###,
    ),
    (
        "E05",
        r###"return pcall(lpeg.match, lpeg.P(1)/function() error("boom", 2) end, "a")"###,
        r###"n=2:false,"boom""###,
    ),
    (
        "E06",
        r###"local t = {}; local ok, e = pcall(lpeg.match, lpeg.P(1)/function() error(t) end, "a"); return ok, rawequal(e, t)"###,
        r###"n=2:false,true"###,
    ),
    (
        "E07",
        r###"local t = {}; local ok, e = pcall(lpeg.match, lpeg.Cf(lpeg.Cc(1)*lpeg.Cc(2), function() error(t) end), ""); return ok, rawequal(e, t)"###,
        r###"n=2:false,true"###,
    ),
    (
        "E08",
        r###"local p = lpeg.Cmt(1, function(s,i) if s == "e" then error("E", 0) end return true end) * lpeg.C(1); local a = {pcall(p.match, p, "e")}; return a[2], p:match("ab")"###,
        r###"n=2:"E","b""###,
    ),
    (
        "E09",
        r###"local mt = {__tostring=function() return "TS" end}; local t = setmetatable({}, mt); local ok, e = pcall(lpeg.match, lpeg.Cmt(1, function() error(t) end), "a"); return ok, rawequal(e, t)"###,
        r###"n=2:false,true"###,
    ),
    (
        "X01",
        r###"return lpeg.match(lpeg.Cmt(1, function(s,i) return true, lpeg.match(lpeg.C(1), s, i) end), "ab")"###,
        r###"n=1:"b""###,
    ),
    (
        "X02",
        r###"local p; p = lpeg.Cmt(1, function(s,i) if i <= #s then return true, (p:match(s, i)) else return true, "end" end end); return p:match("abc")"###,
        r###"n=1:"end""###,
    ),
    (
        "X03",
        r###"local d=0; local p; p = lpeg.Cmt(lpeg.P(true), function(s,i) d = d + 1; return lpeg.match(p, s) end); local ok, e = pcall(lpeg.match, p, "a"); return d, e"###,
        r###"n=2:195,"C stack overflow""###,
    ),
    (
        "X04",
        r###"local d=0; local p; p = lpeg.P(1)/function(c) d=d+1; return lpeg.match(p, c) end; local ok, e = pcall(lpeg.match, p, "a"); return d, e"###,
        r###"n=2:195,"C stack overflow""###,
    ),
    (
        "X05",
        r###"local d=0; local t = setmetatable({}, {}); getmetatable(t).__index = function(t,k) d=d+1; return lpeg.match(lpeg.C(1)/t, k) end; local ok, e = pcall(lpeg.match, lpeg.C(1)/t, "a"); return d, e"###,
        r###"n=2:195,"case:1: C stack overflow""###,
    ),
    (
        "X06",
        r###"local d=0; local f; f = function(a,b) d=d+1; return lpeg.match(lpeg.Cf(lpeg.Cc(1)*lpeg.Cc(2), f), "") end; local ok, e = pcall(lpeg.match, lpeg.Cf(lpeg.Cc(1)*lpeg.Cc(2), f), ""); return d, e"###,
        r###"n=2:195,"case:1: C stack overflow""###,
    ),
    (
        "X07",
        r###"local d=0; local function f(s) d=d+1; return (string.gsub(s, ".", f)) end; local ok, e = pcall(f, "a"); return d, e"###,
        r###"n=2:196,"C stack overflow""###,
    ),
    (
        "X08",
        r###"local co = coroutine.wrap(function() return pcall(lpeg.match, lpeg.Cmt(lpeg.P"a", function() coroutine.yield("Y") return true end), "a") end); return co()"###,
        r###"n=2:false,"attempt to yield across a C-call boundary""###,
    ),
    (
        "X09",
        r###"local co = coroutine.wrap(function() return pcall(lpeg.match, lpeg.C"a" / function() coroutine.yield("Y") return 1 end, "a") end); return co()"###,
        r###"n=2:false,"attempt to yield across a C-call boundary""###,
    ),
    (
        "X10",
        r###"local g = lpeg.P{ "S", S = lpeg.P"a" * lpeg.V"S" * "b" + "" }; local p = lpeg.Cmt(lpeg.P(true), function() lpeg.setmaxstack(1000) return true end) * g; lpeg.setmaxstack(100); local s = string.rep("a",200)..string.rep("b",200); local ok1, r1 = pcall(lpeg.match, g, s); lpeg.setmaxstack(100); local ok2, r2 = pcall(lpeg.match, p, s); lpeg.setmaxstack(100); return ok1, r1, ok2, r2"###,
        r###"n=4:false,"too many pending calls/choices",true,401"###,
    ),
    (
        "X11",
        r###"local p = lpeg.Cmt(1, function() collectgarbage(); collectgarbage(); return true, {} end) * lpeg.C(1); local a, b = p:match("ab"); return type(a), b"###,
        r###"n=2:"table","b""###,
    ),
    (
        "X12",
        r###"local p = lpeg.P(1)/function(c) return lpeg.match(lpeg.Cf(lpeg.C(1) * lpeg.C(1), function(a,b) return a..b end), c..c) end; return p:match("x")"###,
        r###"n=1:"xx""###,
    ),
    (
        "X13",
        r###"return pcall(getmetatable(lpeg.P(1)).__gc, {})"###,
        r###"n=2:false,"bad argument #1 to '?' (lpeg-pattern expected, got table)""###,
    ),
    (
        "X14",
        r###"local p = lpeg.P"a"; getmetatable(p).__gc(p); getmetatable(p).__gc(p); return p:match("a")"###,
        r###"n=1:2"###,
    ),
    (
        "L01",
        r###"local log={}; local t=setmetatable({}, {__newindex=function(t,k,v) log[#log+1]=k end}); local r = lpeg.locale(t); return rawequal(r,t), table.concat(log, ",")"###,
        r###"n=2:true,"alnum,alpha,cntrl,digit,graph,lower,print,punct,space,upper,xdigit""###,
    ),
    (
        "L02",
        r###"local log={}; local t=setmetatable({alpha=1}, {__newindex=function(t,k,v) log[#log+1]=k; rawset(t,k,v) end}); lpeg.locale(t); return table.concat(log, ","), lpeg.type(t.alpha)"###,
        r###"n=2:"alnum,cntrl,digit,graph,lower,print,punct,space,upper,xdigit","pattern""###,
    ),
    (
        "L03",
        r###"local t=setmetatable({}, {__newindex=function(t,k,v) if k=="digit" then error("stop", 0) end rawset(t,k,v) end}); local ok, e = pcall(lpeg.locale, t); local ks={} for k in pairs(t) do ks[#ks+1]=k end table.sort(ks); return ok, e, table.concat(ks, ",")"###,
        r###"n=3:false,"stop","alnum,alpha,cntrl""###,
    ),
    (
        "L04",
        r###"return pcall(lpeg.locale, 1)"###,
        r###"n=2:false,"bad argument #1 to 'lpeg.locale' (table expected, got number)""###,
    ),
    (
        "L05",
        r###"local sink = {}; local t = setmetatable({}, {__newindex=sink}); lpeg.locale(t); return rawget(t, "alpha"), lpeg.type(sink.alpha)"###,
        r###"n=2:nil,"pattern""###,
    ),
    (
        "L06",
        r###"local n=0 for k in pairs(lpeg.locale()) do n=n+1 end; local m=0 for k in pairs(lpeg.locale(nil)) do m=m+1 end; return n, m"###,
        r###"n=2:11,11"###,
    ),
    (
        "L07",
        r###"local co = coroutine.wrap(function() return pcall(lpeg.locale, setmetatable({}, {__newindex=function() coroutine.yield() end})) end); return co()"###,
        r###"n=2:false,"attempt to yield across a C-call boundary""###,
    ),
    (
        "L08",
        r###"return pcall(lpeg.locale, setmetatable({}, {__newindex="x"}))"###,
        r###"n=2:false,"attempt to index a string value""###,
    ),
    (
        "B01",
        r###"local n = 0; local g = setmetatable({"S"}, {__index = function(t, k) n = n + 1; return lpeg.P"a" end}); local p = lpeg.P(g); return n, p:match("a")"###,
        r###"n=2:1,2"###,
    ),
    (
        "B02",
        r###"local g = setmetatable({"S"}, {__index = {S = lpeg.C"a"}}); return lpeg.match(lpeg.P(g), "a")"###,
        r###"n=1:"a""###,
    ),
    (
        "B03",
        r###"local co = coroutine.wrap(function() return pcall(lpeg.P, setmetatable({"S"}, {__index = function() coroutine.yield() end})) end); return co()"###,
        r###"n=2:false,"attempt to yield across a C-call boundary""###,
    ),
    (
        "B04",
        r###"local t = {}; local g = setmetatable({"S"}, {__index = function() error(t) end}); local ok, e = pcall(lpeg.P, g); return ok, rawequal(e, t)"###,
        r###"n=2:false,true"###,
    ),
    (
        "J01",
        r###"return json.parse('"\\u00e9"')"###,
        r###"n=2:true,"é""###,
    ),
    (
        "J02",
        r###"return json.parse('"\\ud83d\\ude00"')"###,
        r###"n=2:true,"😀""###,
    ),
    (
        "J03",
        r###"local ok, e = json.parse('"\\udc00"'); return ok, (e:gsub("^.-:%d+: ", ""))"###,
        r###"n=2:false,"Not a Unicode character: U+DC00""###,
    ),
    (
        "J04",
        r###"local ok, e = json.parse('"\\ud83dx"'); return ok, (e:gsub("^.-:%d+: ", ""))"###,
        r###"n=2:false,"Bad unicode escape \\ud83d (missing low surrogate)""###,
    ),
    (
        "J05",
        r###"local ok, e = json.parse('"\\ud83d\\u0041"'); return ok, (e:gsub("^.-:%d+: ", ""))"###,
        r###"n=2:false,"Bad unicode escape \\ud83d\\u0041 (bad low surrogate)""###,
    ),
    (
        "J06",
        r###"local ok, t = json.parse('{"a":1,"b":[true,false,null],"c":{"d":"e"}}'); return ok, t.a, #t.b, t.b[3] == json.NULL, t.c.d, getmetatable(t).json, getmetatable(t.b).json"###,
        r###"n=7:true,1,3,true,"e","object","array""###,
    ),
    (
        "J07",
        r###"return json.parse('[1] x')"###,
        r###"n=2:false,"syntax error""###,
    ),
    (
        "J08",
        r###"local ok, t = json.parse('{"a":1,"a":2}'); return ok, t.a"###,
        r###"n=2:true,2"###,
    ),
    (
        "J09",
        r###"local d = string.rep("[", 34)..string.rep("]", 34); return json.parse(d)"###,
        r###"n=2:false,"too many pending calls/choices""###,
    ),
    (
        "J10",
        r###"return json.parse('"\\uzzzz"')"###,
        r###"n=2:true,"uzzzz""###,
    ),
    (
        "J11",
        r###"local parts, exp = {}, {} for i=0,32999 do parts[#parts+1] = string.format("\\u%04X", 0x41 + (i % 26)); exp[#exp+1] = string.char(0x41 + (i % 26)) end; exp = table.concat(exp); local ok, s = json.parse('["'..table.concat(parts)..'"]'); local got = s[1]; local first; for i=1,#exp do if got:sub(i,i) ~= exp:sub(i,i) then first=i break end end; return ok, #got, got == exp, first"###,
        r###"n=4:true,33000,false,32762"###,
    ),
    (
        "J12",
        r###"local parts, exp = {}, {} for i=0,32761 do parts[#parts+1] = string.format("\\u%04X", 0x41 + (i % 26)); exp[#exp+1] = string.char(0x41 + (i % 26)) end; exp = table.concat(exp); local ok, s = json.parse('["'..table.concat(parts)..'"]'); return ok, type(s) == "table" and (s[1] == exp) or s"###,
        r###"n=2:false,"invalid value (table) at index 32762 in table for 'concat'""###,
    ),
    (
        "J13",
        r###"local parts, exp = {}, {} for i=0,32760 do parts[#parts+1] = string.format("\\u%04X", 0x41 + (i % 26)); exp[#exp+1] = string.char(0x41 + (i % 26)) end; exp = table.concat(exp); local ok, s = json.parse('["'..table.concat(parts)..'"]'); return ok, type(s) == "table" and (s[1] == exp) or s"###,
        r###"n=2:true,true"###,
    ),
    (
        "U01",
        r###"return pcall(U.get_response, 'SF:GetRequest,5,"\\xzz"', "GetRequest")"###,
        r###"n=2:false,"/home/user/nmap/nselib/lpeg-utility.lua:144: bad argument #1 to 'char' (number expected, got nil)""###,
    ),
    (
        "U02",
        r###"return U.get_response('SF:GetRequest,5,"a\\x41\\tb\\0\\n\\r\\q"', "GetRequest")"###,
        r###"n=1:"aA\9b\0\n\13q""###,
    ),
    (
        "U03",
        r###"return U.parse_fp('SF-Port80-TCP:V=7%r(NULL,5,"a\\x41b")%r(GetRequest,3,"\\r\\n")')"###,
        r###"n=1:{["GetRequest"]="\13\n",["NULL"]="aAb"}"###,
    ),
    (
        "U04",
        r###"local p = U.caseless("aB"); return p:match("Ab"), p:match("AB"), p:match("ac")"###,
        r###"n=3:3,3,nil"###,
    ),
    (
        "U05",
        r###"return lpeg.match(U.escaped_quote(), '"a\\"b"')"###,
        r###"n=1:"a\"b""###,
    ),
    (
        "U06",
        r###"return pcall(U.split, "a,b,,c", ",")"###,
        r###"n=2:false,"/home/user/nmap/nselib/lpeg-utility.lua:58: rule 'sep' is not a pattern""###,
    ),
    (
        "E-re01",
        r###"return re.match("hello", "{%a+}")"###,
        r###"n=1:"hello""###,
    ),
    (
        "E-re02",
        r###"return re.match("ab", "{| {.} {.} |}")"###,
        r###"n=1:{[1]="a",[2]="b"}"###,
    ),
    (
        "E-re03",
        r###"return re.match("a", "'a' -> {}")"###,
        r###"n=1:{}"###,
    ),
    (
        "E-re04",
        r###"return re.compile("{'a'} -> upper", {upper=string.upper}):match("a")"###,
        r###"n=1:"A""###,
    ),
    (
        "E-re05",
        r###"return re.compile("'a' => f", {f=function(s,i) return i end}):match("ab")"###,
        r###"n=1:2"###,
    ),
    (
        "E-re06",
        r###"return re.compile("{.} -> '%1%1'"):match("ab")"###,
        r###"n=1:"aa""###,
    ),
    (
        "E-re07",
        r###"return re.compile("{.} -> 1"):match("ab")"###,
        r###"n=1:"a""###,
    ),
    (
        "E-re08",
        r###"return re.compile("{:x: [a-z]+ :} ' ' =x"):match("foo foo"), re.compile("{:x: [a-z]+ :} ' ' =x"):match("foo bar")"###,
        r###"n=2:8,nil"###,
    ),
    (
        "E-re09",
        r###"return pcall(re.compile, "a ]")"###,
        r###"n=2:false,"pattern error near ']'""###,
    ),
    (
        "E-re10",
        r###"local ok, e = pcall(re.compile, "x <- 'a' x <- 'b'"); return ok, (e:gsub("^.-:%d+: ", ""))"###,
        r###"n=2:false,"'x' already defined as a rule""###,
    ),
    (
        "E-re11",
        r###"local ok, e = pcall(re.compile, "%foo"); return ok, (e:gsub("^.-:%d+: ", ""))"###,
        r###"n=2:false,"name 'foo' undefined""###,
    ),
    (
        "E-re12",
        r###"return re.find("abc", "'c'")"###,
        r###"n=2:3,3"###,
    ),
    (
        "E-re13",
        r###"return re.gsub("abc", "'b'", "x"), re.gsub("abc", "{'b'}", string.upper)"###,
        r###"n=2:"axc","aBc""###,
    ),
    (
        "E-re14",
        r###"return re.match("a", "{: 'a' :}")"###,
        r###"n=1:"a""###,
    ),
    (
        "E-re15",
        r###"return re.match("abab", "{:x: 'ab' :} =x")"###,
        r###"n=1:5"###,
    ),
    (
        "E-re16",
        r###"return re.compile("{~ ('a' -> 'b' / .)* ~}"):match("xaya")"###,
        r###"n=1:"xbyb""###,
    ),
    (
        "E-re17",
        r###"local ok, e = pcall(re.compile, "x"); return ok, (tostring(e):gsub("^.-:%d+: ", ""))"###,
        r###"n=2:false,"rule 'x' used outside a grammar""###,
    ),
    (
        "E-re18",
        r###"local ok, e = pcall(re.compile, "'a' -> nope", {}); return ok, (tostring(e):gsub("^.-:%d+: ", ""))"###,
        r###"n=2:false,"undefined name: nope""###,
    ),
    (
        "E-re19",
        r###"return pcall(re.compile, "(")"###,
        r###"n=2:false,"pattern error near '('""###,
    ),
    (
        "A01",
        r###"return re.compile [[{| ({'UA-' [%d]^6 [%d]^-3 '-' [%d][%d]?} / .)* |}]]:match("x UA-1234567-12 y UA-123456-1")"###,
        r###"n=1:{[1]="UA-1234567-12",[2]="UA-123456-1"}"###,
    ),
    (
        "A02",
        r###"return re.compile [[{| ({'pub-' [%d]^16} / .)* |}]]:match("pub-1234567890123456 pub-12")"###,
        r###"n=1:{[1]="pub-1234567890123456"}"###,
    ),
];

/// The cases the port answers otherwise, deliberately, and why: (id, the
/// named class — a ledger entry — and the port's own answer, pinned).
const CLASSED: &[(&str, &str, &str)] = &[
    // The Lua stack's ceiling on live dynamic values (orphans of `#p`
    // included, N15) is where the embedding's frames leave it: 999,957
    // calls in the C's standalone harness, 999,986 here, then Lua's bare
    // "stack overflow" as the next callback's frame is pushed.
    (
        "N15",
        "lpeg-capture-ceiling-is-the-embeddings",
        r#"n=3:999986,false,"stack overflow""#,
    ),
    (
        "N17",
        "lpeg-capture-ceiling-is-the-embeddings",
        r#"n=3:999986,false,"stack overflow""#,
    ),
    // Wide runtime-capture indices (D4): every value is the one returned,
    // where the C's `short` wraps from the 32,762nd.
    (
        "N19",
        "lpeg-runtime-capture-index-16bit",
        r#"n=2:33000,nil"#,
    ),
    (
        "J11",
        "lpeg-runtime-capture-index-16bit",
        r#"n=4:true,33000,true,nil"#,
    ),
    (
        "J12",
        "lpeg-runtime-capture-index-16bit",
        r#"n=2:true,true"#,
    ),
    // C levels: the embedding's own calls below the chunk (the standalone
    // `lua.c` makes two, an `Executor` none). Relative to `gsub` in the
    // same harness each path is the C's, one level less, which
    // `reentry_is_one_c_level_below_gsub` checks.
    (
        "X03",
        "lpeg-capture-ceiling-is-the-embeddings",
        r#"n=2:197,"C stack overflow""#,
    ),
    (
        "X04",
        "lpeg-capture-ceiling-is-the-embeddings",
        r#"n=2:197,"C stack overflow""#,
    ),
    (
        "X05",
        "lpeg-capture-ceiling-is-the-embeddings",
        r#"n=2:197,"case:1: C stack overflow""#,
    ),
    (
        "X06",
        "lpeg-capture-ceiling-is-the-embeddings",
        r#"n=2:197,"case:1: C stack overflow""#,
    ),
    (
        "X07",
        "lpeg-capture-ceiling-is-the-embeddings",
        r#"n=2:198,"C stack overflow""#,
    ),
    // A callback may yield (the C refuses: "attempt to yield across a
    // C-call boundary"): the coroutine yields what it yields.
    ("X08", "lpeg-callback-may-yield", r#"n=1:"Y""#),
    ("X09", "lpeg-callback-may-yield", r#"n=1:"Y""#),
    ("L07", "lpeg-callback-may-yield", r#"n=0:"#),
    ("B03", "lpeg-callback-may-yield", r#"n=0:"#),
    // `string.char` is the VM's, its argument error in its own words (and,
    // a Rust function's, with no position).
    (
        "U01",
        "vm-base-library-argument-errors",
        r#"n=2:false,"type error, expected u8, found nil""#,
    ),
];

/// A path into the tree's `nselib/`, as an error position carries it, made
/// the oracle's (`/home/user/nmap/nselib/`): the `path` class of
/// `classify_m66_lpeg.py`, for a checkout elsewhere.
fn unpath(s: &str) -> String {
    let here = format!("{}/", lpeg_eval::nselib().display());
    s.replace(&here, "/home/user/nmap/nselib/")
}

#[test]
fn callback_quirks_are_the_cs() {
    let mut lua = lpeg_eval::new_lua_with_nselib();
    let ex = lua
        .try_enter(|ctx| {
            let c = Closure::load(ctx, Some("=harness"), HARNESS.as_bytes())?;
            Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
        })
        .expect("the harness compiles");
    assert!(
        lpeg_eval::step_only(&mut lua, &ex, 1_000_000, 1_000).0,
        "the harness loads"
    );
    lua.enter(|ctx| {
        let f: Function = ctx
            .fetch(&ex)
            .take_result::<Function>(ctx)
            .expect("finished")
            .expect("the harness loads");
        ctx.set_global("run_case", f);
    });
    let mut bad = Vec::new();
    let mut classed = std::collections::BTreeMap::<&str, Vec<&str>>::new();
    for &(id, chunk, c) in CASES {
        let ex = lua.enter(|ctx| {
            let f: Function = ctx.get_global("run_case").expect("run_case");
            ctx.stash(Executor::start(ctx, f, ctx.intern(chunk.as_bytes())))
        });
        let (done, _) = lpeg_eval::step_only(&mut lua, &ex, 1_000_000, 1_000_000);
        let got = if done {
            lua.enter(
                |ctx| match ctx.fetch(&ex).take_result::<Variadic<Vec<Value>>>(ctx) {
                    Ok(Ok(vs)) => match vs.0.first() {
                        Some(Value::String(s)) => unpath(&String::from_utf8_lossy(s.as_bytes())),
                        v => format!("NOT A STRING: {v:?}"),
                    },
                    Ok(Err(e)) => format!("RAISED: {e:#}"),
                    Err(e) => format!("NO RESULT: {e}"),
                },
            )
        } else {
            "UNFINISHED".to_string()
        };
        let want = match CLASSED.iter().find(|(i, _, _)| *i == id) {
            Some(&(_, class, port)) => {
                classed.entry(class).or_default().push(id);
                port
            }
            None => c,
        };
        if got != want {
            bad.push(format!(
                "  {id}: {chunk}\n    C    = {c}\n    want = {want}\n    port = {got}"
            ));
        }
    }
    eprintln!(
        "{} cases; the port's own answer under a named class: {classed:?}",
        CASES.len()
    );
    // Each LPeg path re-enters one C level less deep than `gsub`, as in
    // the C (X03-X06 against X07).
    let depth = |id: &str| -> u32 {
        let (_, _, a) = CLASSED
            .iter()
            .find(|c| c.1 == "lpeg-capture-ceiling-is-the-embeddings" && c.0 == id)
            .expect("pinned");
        a.trim_start_matches("n=2:")
            .split(',')
            .next()
            .and_then(|d| d.parse().ok())
            .expect("a depth")
    };
    for id in ["X03", "X04", "X05", "X06"] {
        assert_eq!(
            depth(id) + 1,
            depth("X07"),
            "{id}: one C level per call, as gsub's"
        );
    }
    assert_eq!(CASES.len(), 207, "quirks.lua has 207 pins");
    assert!(
        bad.is_empty(),
        "{} of {} cases differ:\n{}",
        bad.len(),
        CASES.len(),
        bad.join("\n")
    );
}
