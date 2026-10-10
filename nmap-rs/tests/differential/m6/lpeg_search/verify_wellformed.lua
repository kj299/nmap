-- Fixed well-formed families for the patterns whose search maximum came from
-- large subjects (get_response, parse_fp, ntp). Each family always closes its
-- quote or paren, so both LPeg passes (getquote, then unescape) run on every
-- size: no one-pass/two-pass discontinuity in the fit.
--
--   lua-instr verify_wellformed.lua
local HERE = arg[0]:match("^(.*)/[^/]*$") or "."
local REPO = HERE .. "/../../../../.."
local M, lpeg = assert(loadfile(HERE .. "/matchers.lua"))(REPO, HERE)
local U = require "lpeg-utility"
local STEPS = assert(lpeg.__steps, "not the instrumented interpreter: lpeg.__steps is missing")
local rep = string.rep
local function measure(fn, s) STEPS(); pcall(fn, s); local vm, cap = STEPS(); return vm + cap end
local function fit(xs, ys)
  local n = #xs; local sx, sy, sxx, sxy = 0, 0, 0, 0
  for i = 1, n do
    local lx, ly = math.log(xs[i]), math.log(ys[i])
    sx = sx + lx; sy = sy + ly; sxx = sxx + lx * lx; sxy = sxy + lx * ly
  end
  return (n * sxy - sx * sy) / (n * sxx - sx * sx)
end
local ntp = M._ntp_kvmatch ^ 0
local fams = {
  {"get_response \\x-tiled", function(n) return 'NULL,4,"' .. rep("\\x", n) .. '"' end,
     function(s) U.get_response(s, "NULL") end},
  {"get_response \\\\-tiled", function(n) return 'NULL,4,"' .. rep("\\\\", n) .. '"' end,
     function(s) U.get_response(s, "NULL") end},
  {"parse_fp \\x-tiled", function(n) return '%r(NULL,4,"' .. rep("\\x", n) .. '")' end,
     function(s) U.parse_fp(s) end},
  {"parse_fp manyprobes", function(n) return rep('%r(P,1,"\\x")', n) end,
     function(s) U.parse_fp(s) end},
  {"ntp unterminated-quote", function(n) return 'k="' .. rep("x", n) end,
     function(s) ntp:match(s) end},
}
for _, fam in ipairs(fams) do
  local name, grow, fn = fam[1], fam[2], fam[3]
  local xs, ys = {}, {}
  io.write("== " .. name .. " ==\n")
  for _, n in ipairs({256, 512, 1024, 2048, 4096, 8192, 16000}) do
    local s = grow(n)
    if #s <= 65536 then
      local st = measure(fn, s)
      xs[#xs + 1] = #s; ys[#ys + 1] = math.max(st, 1)
      io.write(string.format("   n=%6d size=%6d steps=%9d perbyte=%.3f\n", n, #s, st, st / #s))
    end
  end
  io.write(string.format("   EXP=%.3f\n", fit(xs, ys)))
end
