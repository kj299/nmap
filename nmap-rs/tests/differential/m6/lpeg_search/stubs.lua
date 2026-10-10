-- Minimal stubs so the tree's real nselib libraries load under the standalone
-- instrumented Lua. Nothing in the repository is modified; these only satisfy
-- `require`. Called as loadfile(...)(REPO).
local REPO = assert(..., "stubs.lua: pass the repository root")
package.path = REPO .. "/nselib/?.lua;" .. package.path
local function reg(name, mod)
  package.loaded[name] = mod
  package.preload[name] = function() return mod end
end
-- stdnse: json, lpeg-utility and the scripts need module(), seeall, the debug
-- printers, output_table and get_script_args
local stdnse = {}
stdnse.debug1 = function() end
stdnse.debug2 = function() end
stdnse.debug = function() end
function stdnse.module(name, ...)
  local m = {}
  m._NAME = name; m._M = m; m._PACKAGE = (name:gsub("[^.]*$", ""))
  return setmetatable(m, {__index = _G})
end
stdnse.seeall = 0
function stdnse.get_script_args() return nil end
function stdnse.output_table() return setmetatable({}, {}) end
function stdnse.format_output(ok, t) return t end
reg("stdnse", stdnse)
-- unicode: json's \u escapes need utf8_enc (a function capture: Lua time, not
-- LPeg steps, so a faithful-enough encoder does not move the counts)
local unicode = {}
function unicode.utf8_enc(cp)
  if cp < 0x80 then return string.char(cp)
  elseif cp < 0x800 then return string.char(0xC0 | (cp >> 6), 0x80 | (cp & 0x3F))
  elseif cp < 0x10000 then
    return string.char(0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F))
  else
    return string.char(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3F), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F))
  end
end
reg("unicode", unicode)
-- unittest: json requires it and calls unittest.testing() at load
reg("unittest", setmetatable({}, {__index = function() return function() end end}))
-- tableaux (fingerprint-strings): keys()
local tableaux = {}
function tableaux.keys(t) local k = {} for key in pairs(t) do k[#k + 1] = key end return k end
reg("tableaux", tableaux)
return true
