description = [[
The lfs module as a script meets it (nse_fs.cc): get_path_separator, mkdir's
results and errors, its argument checks and the info fields, beneath the
directory named by http-fetch.destination, which must exist and be empty. The
same command line runs under nmap 7.94 and nmap-rs (oracle/gen_m64_cli.py), so
this also passes through the port's designation of that argument as an output
directory (fspolicy::OUTPUT_DIR_ARGS). What only the port does (refusing a
directory elsewhere, having no dir, link or rmdir) is pinned in its own tests.
]]
categories = {"cli"}

local lfs = require "lfs"
local nmap = require "nmap"
local stdnse = require "stdnse"

prerule = function() return true end

local function show(...)
  local p = table.pack(...)
  local s = {}
  for i = 1, p.n do
    local v = p[i]
    s[i] = type(v) == "string" and string.format("%q", v) or tostring(v)
  end
  return p.n .. ": " .. table.concat(s, ", ")
end

action = function()
  local base = assert(stdnse.get_script_args("http-fetch.destination"))
  local out = stdnse.output_table()
  out.global = show(type(lfs), lfs == package.loaded.lfs, lfs == _ENV.lfs)
  out.separator = show(lfs.get_path_separator(), lfs.get_path_separator(1, 2))
  out.version = show(lfs._VERSION, lfs._COPYRIGHT)
  out.description = show(lfs._DESCRIPTION)
  out.new = show(lfs.mkdir(base .. "/a"))
  out.again = show(lfs.mkdir(base .. "/a"))
  out.trailing_existing = show(lfs.mkdir(base .. "/a/"))
  out.trailing_new = show(lfs.mkdir(base .. "/a/b/"))
  out.no_parent = show(lfs.mkdir(base .. "/n/o"))
  local f = assert(io.open(base .. "/f", "w"))
  f:close()
  out.on_a_file = show(lfs.mkdir(base .. "/f"))
  out.under_a_file = show(lfs.mkdir(base .. "/f/g"))
  out.nul = show(lfs.mkdir(base .. "/a\0zz"))
  out.empty = show(lfs.mkdir(""))
  out.dotdot_inside = show(lfs.mkdir(base .. "/a/../c"))
  out.dot = show(lfs.mkdir(base .. "/a/."))
  out.none = show(pcall(lfs.mkdir))
  out.table = show(pcall(lfs.mkdir, {}))
  out.boolean = show(pcall(lfs.mkdir, true))
  out.from_lua = show(pcall(function() return lfs.mkdir(nil) end))
  out.extra_args = show(lfs.mkdir(base .. "/d", "ignored", 3))
  return out
end
