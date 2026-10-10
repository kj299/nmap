-- M6.6 step c: left calls through lpeg.B, compiled and matched
-- (lpeg-getfirst-unbounded-recursion).
--
-- The verifier does not follow a call under a predicate in B's pattern, so
-- these grammars build, in the C and in the port (step b's review: 334
-- shapes, 322 build). The C's getfirst does descend into B's pattern, and
-- recurses for ever -- a crash -- in the uses whose code generation asks for
-- the first set of the cycle; the other uses compile and match. The port's
-- getfirst raises "rule '...' may be left recursive" exactly where the C's
-- recursion would not end.
--
-- Loaded by gen_m66c_behind.py under a fixed build of the tree's lpeg.c (one
-- process per case: a crash ends only its case), and by the port's test
-- (crates/core/tests/lpeg_match_limits.rs) with the test-only lpeg. Returns
-- { count = n, run = function(i) -> outcome }: the outcome of case i is
--   build:MSG                 lpeg.P refused the grammar
--   r1|r2|r3|r4               the use's results on the four subjects, each the
--                             first result's tostring or err:MSG
local lpeg = lpeg or require "lpeg"
local P, V, B, C = lpeg.P, lpeg.V, lpeg.B, lpeg.C

local function preds(R)
  return { "#" .. R, "-" .. R, "#(" .. R .. ' * "b")', "-(" .. R .. ' * "b")',
           "#(" .. R .. ' + "b")', '#(P"b" + ' .. R .. ")", "-(-" .. R .. ")" }
end
local function bodies(p)
  return { "B(" .. p .. ' * "a")', "B(" .. p .. ' * P"ab")', "B(" .. p .. " * " .. p .. ' * "a")',
           "B(B(" .. p .. ' * "a") * "c")' }
end
local WRAP = { "{X}", 'P"x" + {X}', '{X} + "x"', 'P"x" * {X}', '{X} * "x"', '#P"x" * {X}',
               '-P"x" * {X}', '({X})^-1 * "y"', "C({X})", '{X} * V"Z"' }
local gs = {}
for _, p in ipairs(preds('V"A"')) do
  for _, b in ipairs(bodies(p)) do
    for _, w in ipairs(WRAP) do
      local body = w:gsub("{X}", function() return b end)
      local extra = body:find('V"Z"', 1, true) and ', Z = P"z"' or ""
      gs[#gs + 1] = '{ "A", A = ' .. body .. extra .. " }"
    end
  end
end
for _, p in ipairs(preds('V"A"')) do
  for _, w in ipairs { 'V"C"', 'P"x" + V"C"', 'V"C" + "x"', 'V"C" * "x"' } do
    gs[#gs + 1] = '{ "A", A = ' .. w .. ", C = B(" .. p .. ' * "c") }'
  end
end
for _, p in ipairs(preds('V"A"')) do
  gs[#gs + 1] = '{ "A", A = B(P"a" * ' .. p .. ") }"
  gs[#gs + 1] = '{ "A", A = P"x" + B(P"a" * ' .. p .. ") }"
end
for _, c in ipairs { '-P{P"x"}', '#P{P"x"}', 'P{P"x"}^0', '(#P"a" + P{P"x"})', '-(-P{P"x"})',
                     'P{P"x"}^-1' } do
  gs[#gs + 1] = '{ "A", A = ' .. c .. ' * V"A" + "y" }'
  gs[#gs + 1] = '{ "A", A = P"q" + ' .. c .. ' * V"A" }'
end

local USES = {
  function(g) return g end,
  function(g) return "q" + g end,
  function(g) return g * "z" end,
  function(g) return g + "q" end,
  function(g) return -g end,
  function(g) return g ^ -1 end,
}
local SUBJECTS = { { "ab", 2 }, { "aab", 3 }, { "b", 1 }, { "xa", 1 } }

local function run(i)
  local gi, ui = (i - 1) // #USES + 1, (i - 1) % #USES + 1
  local t = assert(load("local P, V, B, C = ... return " .. gs[gi]))(P, V, B, C)
  local ok, g = pcall(P, t)
  if not ok then return "build:" .. tostring(g) end
  local p = USES[ui](g)
  local out = {}
  for k, s in ipairs(SUBJECTS) do
    local r = table.pack(pcall(lpeg.match, p, s[1], s[2]))
    out[k] = r[1] and tostring(r[2]) or ("err:" .. tostring(r[2]))
  end
  return table.concat(out, "|")
end

return { count = #gs * #USES, run = run }
