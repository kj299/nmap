-- M6.6 step e DoS fixture: an exponential LPeg grammar built at LOAD time.
--
-- The choice chain R_i <- R_{i+1} / R_{i+1} (docs/M6.6-ANALYSIS.md §1.1)
-- makes lpeg.P(grammar) walk 2^(K-1) paths in the verifier (verifyrule,
-- lpeg.c:3047, :3071-3073). C cannot be interrupted there, so nmap 7.94 hangs
-- before any phase (K = 36; measured: nothing after `selected by file path`
-- under a 60 s timeout, where K = 32 loads in under a minute and then hangs
-- in the action's first match, which compiles the grammar). The port's
-- construction burns fuel (D3), and each script's load counts as progress
-- for the stall limit (nse-stall-limit), so start-up fails at the limit with
-- rc 1: no phase has run, and nothing exists to keep. m66dos.k sets K
-- (default 36).
local lpeg = require "lpeg"
local stdnse = require "stdnse"

description = [[M6.6 step e DoS fixture: builds an exponential LPeg grammar at load time.]]
categories = {"m66dos"}
author = "nmap-rs differential"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local K = tonumber(stdnse.get_script_args("m66dos.k")) or 36
local g = { "R1" }
for i = 1, K - 1 do
  g["R" .. i] = lpeg.V("R" .. (i + 1)) + lpeg.V("R" .. (i + 1))
end
g["R" .. K] = lpeg.P "a"
local patt = lpeg.P(g)

prerule = function() return true end
action = function() return ("built K=%d, match=%s"):format(K, tostring(patt:match("a"))) end
