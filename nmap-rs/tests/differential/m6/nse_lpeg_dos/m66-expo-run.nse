-- M6.6 step e DoS fixture: LPeg work exponential in one stage, run in a
-- prerule after m66-quick has stored its result (runlevel 2, by dependency).
--
-- m66dos.stage picks the stage (docs/M6.6-ANALYSIS.md §1.1); m66dos.n sets
-- its size. Before each piece of work the action logs `m66dos: STAGE` (at -d)
-- and sleeps, which yields to the scheduler: the next resume is progress for
-- the port's stall limit (nse-stall-limit), so each piece starts a window of
-- its own, and the last marker logged names the stage the limit cut.
--
--   build    the choice chain R_i <- R_{i+1} / R_{i+1}: lpeg.P walks 2^(n-1)
--            paths in the verifier (verifyrule, lpeg.c:3047), in C and in the
--            port alike. n = 36 (at 32, C finishes the build in under a
--            minute and hangs in the compile that follows).
--   compile  first a balanced pattern of 2^n leaves (p = p * p, n = 21),
--            whose compile is linear in its 6 million nodes in both, about
--            8 s in the port's debug build and 0.3 s in C; then the chain
--            R_i <- R_{i-1}'x' / R_{i-1}'y' (n = 28), whose first match C
--            compiles in time exponential in n (getfirst, lpeg.c:1175, and
--            codegen) and the port in linear time (E10). So the port is cut in
--            the first compile, and C hangs in the second; the port never
--            reaches the chain, whose build is 2^n in both.
--   match    S <- 'a' S 'b' / 'a' S 'c' / '' on a^n d: 2^n attempts, no
--            memo (lpvm). n = 34, under the backtrack ceiling of 50.
--   capture  nested Cg((Cb"a" * Cb"a") / 1, "a"): each back-reference
--            evaluates the group before it again, 2^n values, no Lua call
--            (backrefcap, lpeg.c:527). n = 32.
--
-- C can be interrupted in none of them, so nmap 7.94's --script-timeout never
-- fires and the scan hangs (measured under a hard timeout). In the port each
-- stage burns fuel (D3): the stall limit ends the phase, the stored result is
-- kept, and the scan goes on (lpeg-stall-limit-ends-finite-work).
local lpeg = require "lpeg"
local stdnse = require "stdnse"

description = [[M6.6 step e DoS fixture: exponential LPeg work in its action.]]
categories = {"m66dos"}
author = "nmap-rs differential"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
dependencies = {"m66-quick"}

local P, V, Cg, Cb, Cc = lpeg.P, lpeg.V, lpeg.Cg, lpeg.Cb, lpeg.Cc

-- Log the stage about to run, after a yield to the scheduler.
local function stage(name)
  stdnse.sleep(0.01)
  stdnse.debug1("m66dos: %s", name)
end

local function chain_choice(n)
  local g = { "R1" }
  for i = 1, n - 1 do g["R" .. i] = V("R" .. (i + 1)) + V("R" .. (i + 1)) end
  g["R" .. n] = P "a"
  return g
end

local stages = {
  build = { 36, function(n)
    stage("build")
    local p = P(chain_choice(n))
    stage("match")
    return lpeg.match(p, "a")
  end },
  compile = { 21, function(n)
    stage("build")
    local p = P "a" + "b"
    for _ = 1, n do p = p * p end
    stage("compile")
    lpeg.match(p, "x")
    stage("build")
    local g = { "R28", R0 = P "a" }
    for i = 1, 28 do g["R" .. i] = V("R" .. (i - 1)) * "x" + V("R" .. (i - 1)) * "y" end
    local q = P(g)
    stage("compile")
    return lpeg.match(q, "a" .. ("y"):rep(28))
  end },
  match = { 34, function(n)
    stage("build")
    local S = P { "S", S = P "a" * V "S" * "b" + P "a" * V "S" * "c" + P "" }
    lpeg.match(S, "")
    stage("match")
    return lpeg.match(S, ("a"):rep(n) .. "d")
  end },
  capture = { 32, function(n)
    stage("build")
    local p = Cg(Cc "x", "a")
    for _ = 1, n do p = p * Cg((Cb "a" * Cb "a") / 1, "a") end
    p = p * Cb "a"
    stage("capture")
    return lpeg.match(p, "")
  end },
}

prerule = function() return true end
action = function()
  local name = stdnse.get_script_args("m66dos.stage") or "build"
  local entry = assert(stages[name], "m66dos.stage")
  local def, f = entry[1], entry[2]
  local n = tonumber(stdnse.get_script_args("m66dos.n")) or def
  local r = f(n)
  stdnse.debug1("m66dos: done")
  return ("%s n=%d -> %s"):format(name, n, tostring(r))
end
