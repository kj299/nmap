-- Wall time of the SCRIPT-SIDE Lua around two of the patterns, which the step
-- counters do not see: ntp-info's accumulate_output (a recursive
-- select(3, ...) over every capture, quadratic in the pair count) and the
-- tables json.parse builds. Informational: CPU-dependent, not a gate input.
--
--   lua-instr scriptside.lua
local HERE = arg[0]:match("^(.*)/[^/]*$") or "."
local REPO = HERE .. "/../../../../.."
local M = assert(loadfile(HERE .. "/matchers.lua"))(REPO, HERE)
local json = require "json"
local rep = string.rep
local kvmatch = M._ntp_kvmatch

io.write("== ntp accumulate_output (script-side Lua, NOT LPeg) ==\n")
for _, np in ipairs({1024, 2048, 4096, 8192}) do
  local data = rep("k=v,", np)
  local output = {}
  -- the shape of scripts/ntp-info.nse's accumulate_output
  local function accumulate_output(...)
    local k, v = ...
    if k == nil then return end
    output[k] = v
    return accumulate_output(select(3, ...))
  end
  local list = kvmatch^0 / accumulate_output
  local t = os.clock(); list:match(data); local dt = os.clock() - t
  io.write(string.format("   pairs=%5d bytes=%6d cpu=%.3fs\n", np, #data, dt))
end
io.write("== json.parse at large valid sizes (the table build is script-side) ==\n")
for _, np in ipairs({2000, 4000, 8000, 16000, 32000}) do
  local doc = "[" .. rep("1,", np) .. "1]"
  local t = os.clock(); json.parse(doc); local dt = os.clock() - t
  io.write(string.format("   elems=%5d bytes=%6d cpu=%.3fs\n", np, #doc, dt))
end
io.write("== json.parse object (Cf/rawset build) ==\n")
for _, np in ipairs({2000, 4000, 8000, 16000}) do
  local parts = {}; for i = 1, np do parts[i] = '"k' .. i .. '":' .. i end
  local doc = "{" .. table.concat(parts, ",") .. "}"
  local t = os.clock(); json.parse(doc); local dt = os.clock() - t
  io.write(string.format("   keys=%5d bytes=%6d cpu=%.3fs\n", np, #doc, dt))
end
