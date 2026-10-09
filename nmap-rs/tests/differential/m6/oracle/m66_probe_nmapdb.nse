-- The M6.6 probe for the C module `nmapdb` (nse_db.cc): run as a prerule by
-- nmap 7.94 with --datadir set to this repository, it writes one line per
-- call to the file named by --script-args out=PATH, `tag|call|outcome`.
--
-- What it covers:
-- - the module's shape: its four functions, global and in package.loaded,
--   one result each;
-- - `getservbyport` over every port of tcp, udp and sctp (the non-nil ones,
--   and a count per protocol);
-- - `mac2corp` over every prefix in nmap-mac-prefixes, at the low and high
--   end of its range, and over 50,000 addresses from a fixed LCG, each as
--   raw bytes, lower-case hex and upper-case hex with colons, which must
--   agree;
-- - argument shapes and edges for all four functions, and the two
--   functions scripts reach through `datafiles`.
--
-- Every call is deterministic, and every value is rendered with its type.
-- Argument and edge cases call the function through `pcall` directly, so an
-- error has no position prefix (`luaL_where(L, 1)` finds no Lua caller) and
-- its function is named as PUC-Lua names a function called that way, from
-- package.loaded: 'nmapdb.getservbyport'.
--
-- Some calls are not made, because they abort or are undefined in 7.94
-- (LESSONS #033). `mode=quarantine` lists them, one line each with the
-- defect's ledger id, without calling anything; the port pins its answer to
-- each with a unit test.

description = "M6.6 nmapdb probe"
categories = {"m66probe"}
author = "nmap-rs"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local nmap = require "nmap"
local nmapdb = require "nmapdb"

prerule = function() return true end

local out
local function w(s) out:write(s, "\n") end

local function esc(s)
  return (s:gsub("[^\32-\126]", function(c) return string.format("\\x%02x", c:byte()) end)
           :gsub("|", "\\x7c"))
end

local function render(v)
  local t = type(v)
  if t == "nil" then return "nil"
  elseif t == "string" then return "s:" .. esc(v)
  elseif t == "number" then
    if math.type(v) == "integer" then return "i:" .. tostring(v) end
    return "f:" .. string.format("%.17g", v)
  elseif t == "boolean" then return "b:" .. tostring(v)
  else return t end
end

local function rargs(n, a1, a2)
  if n == 0 then return "" end
  if n == 1 then return render(a1) end
  return render(a1) .. "," .. render(a2)
end

-- `fn` called through pcall with exactly `n` arguments: an absent argument
-- ("got no value") and a nil one ("got nil") are different cases.
local function call(fn, n, a1, a2)
  local f = nmapdb[fn]
  local r
  if n == 0 then r = table.pack(pcall(f))
  elseif n == 1 then r = table.pack(pcall(f, a1))
  else r = table.pack(pcall(f, a1, a2)) end
  if not r[1] then return "E:" .. esc(tostring(r[2])) end
  return render(r[2])
end

local function rec(tag, fn, n, a1, a2)
  w(tag .. "|" .. fn .. "(" .. rargs(n, a1, a2) .. ")|" .. call(fn, n, a1, a2))
end

-- How many values a call returns.
local function nret(fn, ...)
  local r = table.pack(pcall(nmapdb[fn], ...))
  return r.n - 1
end

local function hex2raw(h)
  return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end))
end

-- An error raised from Lua code carries its file's path; only the file's
-- name is kept, which holds wherever the repository is checked out.
local function basename_errors(e)
  return (tostring(e):gsub("[^%s]*/([^/%s]+:%d+:)", "%1"))
end

local function main()
  -- 0. The module's shape.
  local keys = {}
  for k, v in pairs(nmapdb) do keys[#keys + 1] = k .. ":" .. type(v) end
  table.sort(keys)
  w("shape|" .. table.concat(keys, ","))
  w("global|" .. tostring(rawget(_G, "nmapdb") == nmapdb) .. "|loaded=" .. tostring(package.loaded.nmapdb == nmapdb))
  w("nret|mac2corp=" .. nret("mac2corp", "000000000000") .. ",gsp=" .. nret("getservbyport", 80, "tcp")
    .. ",gsp_nil=" .. nret("getservbyport", 1, "tcp") .. ",gpn=" .. nret("getprotbynum", 6)
    .. ",gpn_nil=" .. nret("getprotbynum", 200) .. ",gpna=" .. nret("getprotbyname", "tcp")
    .. ",gpna_nil=" .. nret("getprotbyname", "nope"))
  w("types|gpna=" .. math.type(nmapdb.getprotbyname("tcp")) .. ",gpn=" .. type(nmapdb.getprotbynum(6)))

  -- 1. getservbyport over every port: the non-nil results, and a count.
  for _, proto in ipairs({"tcp", "udp", "sctp"}) do
    local nn = 0
    for p = 0, 65535 do
      local r = nmapdb.getservbyport(p, proto)
      if r ~= nil then
        nn = nn + 1
        w("gsp_sweep|" .. proto .. "|" .. p .. "|" .. render(r))
      end
    end
    w("gsp_count|" .. proto .. "|" .. nn)
  end

  -- 2. getservbyport's arguments. The protocol is always one the list holds:
  --    any other name is quarantined.
  local ports = { -1, 0, 1, 7, 80, 65535, 65536, -65536, 131152, math.maxinteger, math.mininteger,
    80.0, -0.0, 80.5, 1e300, -1e300, 2^53, 2^63, -(2^63), 0/0, 1/0, -1/0,
    "80", " 80 ", "0x50", "8e1", "80.0", "80.5", "1e2", "", "abc", "-1", "65536", "0x7fffffffffffffff",
    "9223372036854775808", true, false, {}, print }
  for _, p in ipairs(ports) do
    for _, proto in ipairs({"tcp", "udp", "sctp"}) do
      rec("gsp_arg", "getservbyport", 2, p, proto)
    end
  end
  rec("gsp_arg", "getservbyport", 0)
  rec("gsp_arg", "getservbyport", 1, 80)
  rec("gsp_arg", "getservbyport", 2, 80, nil)
  rec("gsp_arg", "getservbyport", 2, nil, "tcp")
  rec("gsp_arg", "getservbyport", 2, 80, true)
  rec("gsp_arg", "getservbyport", 2, 80, {})
  -- The order of the checks: a bad port and a protocol that is not a string.
  rec("gsp_arg", "getservbyport", 2, "x", nil)
  rec("gsp_arg", "getservbyport", 2, 70000, nil)
  rec("gsp_arg", "getservbyport", 2, -1, true)
  -- A protocol with an embedded NUL still matches its list entry.
  rec("gsp_arg", "getservbyport", 2, 80, "tcp\0junk")
  rec("gsp_arg", "getservbyport", 2, 53, "udp\0")
  -- Extra arguments are ignored.
  local r3 = table.pack(pcall(nmapdb.getservbyport, 80, "tcp", "extra"))
  w("gsp_extra|" .. render(r3[2]) .. "|n=" .. (r3.n - 1))
  -- A port given as a string, as datafiles' __index passes a string key.
  rec("gsp_arg", "getservbyport", 2, "22", "tcp")

  -- 3. getprotbynum over -2..254, and 256 up. 255 is quarantined.
  for n = -2, 254 do rec("gpn", "getprotbynum", 1, n) end
  for _, n in ipairs({256, 257, 65535, 65536, math.maxinteger, math.mininteger, 6.0, -0.0, 6.5, 0/0, 1/0,
      "6", "0x6", " 6 ", "6.0", "6.5", "", "tcp", true, {}}) do
    rec("gpn_arg", "getprotbynum", 1, n)
  end
  rec("gpn_arg", "getprotbynum", 0)
  rec("gpn_arg", "getprotbynum", 1, nil)
  rec("gpn_arg", "getprotbynum", 2, 6, "extra")

  -- 4. getprotbyname over every name in nmap-protocols, as written and in
  --    upper case, and some variants.
  local fn = nmap.fetchfile("nmap-protocols")
  w("protofile|" .. tostring(fn))
  local names = {}
  for line in io.lines(fn) do
    local name = line:match("^%s*([^%s#]+)%s+%d+")
    if name then names[#names + 1] = name end
  end
  for _, nm in ipairs(names) do
    rec("gpna", "getprotbyname", 1, nm)
    rec("gpna_uc", "getprotbyname", 1, nm:upper())
  end
  for _, nm in ipairs({"", " tcp", "tcp ", "Tcp", "TCP", "ip", "IP", "ICMP", "IPv6", "ipv6-icmp", "icmp6",
      "tcp\0", "tcp\0udp", "udp\0x", "\0", "6", 6, 6.0, 6.5, true, {}, ("a"):rep(200), "tp++", "a/n", "ax.25",
      "experimental1", "reserved", "any", "nsh", "homa", "bit-emu"}) do
    rec("gpna_arg", "getprotbyname", 1, nm)
  end
  rec("gpna_arg", "getprotbyname", 0)
  rec("gpna_arg", "getprotbyname", 1, nil)

  -- 5. mac2corp's argument shapes. A hex string with a byte >= 0x80 where a
  --    hex digit is read is quarantined.
  local macs = {
    "", "0", "00", "000000", "\0\0\0\0\0\0", "\0\0\0\0\0", "\0\0\0\0\0\0\0",
    "00000000000", "000000000000", "0000000000000", "00000000000000",
    "001122334455", "00:11:22:33:44:55", "00-11-22-33-44-55", "0011.2233.4455",
    "00:11:22:33:44:5", "00:11:22:33:44:55:", ":00:11:22:33:44:55", ":001122334455",
    "0011:2233:4455", "00::11:22:33:44:55", "0:11:22:33:44:55", "00:11:22:33:44:555",
    "00:11:22:33:44:55:66", "0011223344556", "001122334455 ", " 001122334455",
    "00:00:0c:12:34:56", "00:00:0C:12:34:56", "00000C123456", "00000c123456", "00:00:0c:12:34:5g",
    "AABBCCDDEEFF", "aabbccddeeff", "aa:bb:cc:dd:ee:ff", "gg:hh:ii:jj:kk:ll", "0x0000000c12",
    "\128\128\128\128\128\128", "\255\255\255\255\255\255", "\0\0\12\1\2\3",
    "00\0" .. "000000000", "00:00:0c:12:34:56\0",
    "00:00:0C:12:34", "00:00:0C", "0000", "00000", "1234567", "12345678901",
    "08:00:27:00:00:00", "080027000000", "08:00:27", "\8\0\39\0\0\0",
    "70:b3:d5:ee:f0:00", "70B3D5EEF000", "70B3D5EEFFFF", "70B3D5000000",
    "00:55:DA:00:00:00", "0055DA000000", "0055DAFFFFFF",
    123456, 100000000000, 1.5, 0x123456, true, {}, ("0"):rep(1000), ("0:"):rep(5) .. "0",
  }
  for _, m in ipairs(macs) do rec("mac_arg", "mac2corp", 1, m) end
  rec("mac_arg", "mac2corp", 0)
  rec("mac_arg", "mac2corp", 1, nil)
  rec("mac_arg", "mac2corp", 2, "000000000000", "extra")

  -- 6. mac2corp over every prefix in nmap-mac-prefixes, at the low and high
  --    end of its range. Raw bytes, lower-case hex and upper-case hex with
  --    colons must agree; a disagreement is a line of its own.
  local mfn = nmap.fetchfile("nmap-mac-prefixes")
  w("macfile|" .. tostring(mfn))
  local nprefix, nmismatch, nnil = 0, 0, 0
  local function look(h12)
    local a = nmapdb.mac2corp(hex2raw(h12))
    local b = nmapdb.mac2corp(h12:lower())
    local c = nmapdb.mac2corp((h12:upper():gsub("(..)", "%1:"):sub(1, 17)))
    if a ~= b or a ~= c then
      nmismatch = nmismatch + 1
      w("mac_mismatch|" .. h12 .. "|" .. render(a) .. "|" .. render(b) .. "|" .. render(c))
    end
    if a == nil then nnil = nnil + 1 end
    return a
  end
  for line in io.lines(mfn) do
    local pfx = line:match("^(%x+)%s")
    if pfx and (#pfx == 6 or #pfx == 7 or #pfx == 9) then
      nprefix = nprefix + 1
      local lo = pfx .. ("0"):rep(12 - #pfx)
      local hi = pfx .. ("F"):rep(12 - #pfx)
      w("mac_pfx|" .. pfx .. "|" .. render(look(lo)) .. "|" .. render(look(hi)))
    end
  end
  w("mac_pfx_count|" .. nprefix .. "|mismatch=" .. nmismatch .. "|nil=" .. nnil)

  -- 7. mac2corp over 50,000 addresses from a fixed LCG.
  local x = 12345
  local nn, hits = 0, 0
  for _ = 1, 50000 do
    local b = {}
    for j = 1, 6 do
      x = (x * 1103515245 + 12345) % 2147483648
      b[j] = (x >> 16) & 0xff
    end
    local h = string.format("%02X%02X%02X%02X%02X%02X", table.unpack(b))
    local r = look(h)
    nn = nn + 1
    if r then hits = hits + 1 end
    w("mac_rand|" .. h .. "|" .. render(r))
  end
  w("mac_rand_count|" .. nn .. "|hits=" .. hits .. "|mismatch_total=" .. nmismatch)

  -- 8. Through datafiles, which is how scripts reach the module.
  local datafiles = require "datafiles"
  local ok, t = datafiles.parse_services("tcp")
  w("df|parse_services(tcp)|" .. tostring(ok) .. "|" .. render(t[22]) .. "|" .. render(t[1]) .. "|" .. render(t["80"]))
  local ok2, all = datafiles.parse_services()
  w("df|parse_services()|" .. tostring(ok2) .. "|" .. render(all.udp[53]) .. "|" .. render(all.sctp[80]))
  w("df|parse_services(bad)|" .. render(select(2, datafiles.parse_services("bad"))))
  local _, mt = datafiles.parse_mac_prefixes()
  for _, m in ipairs({"000000", "00000C", "\0\0\12", "00:00:0C", "0800270102", "08002701020304", "08:00:27:01:02:03"}) do
    local s, r = pcall(function() local v = mt[m] return v end)
    w("df|mac[" .. esc(m) .. "]|" .. tostring(s) .. "|" .. (s and render(r) or esc(basename_errors(r))))
  end
end

-- The calls the probe does not make, with the defect each would reach.
local QUARANTINE = {}
local function q(id, fn, n, a1, a2)
  QUARANTINE[#QUARANTINE + 1] = {id, fn, n, a1, a2}
end
-- 7.94 asserts `num < UCHAR_MAX` (3be01efb1:protocols.cc:193) and aborts;
-- this tree admits 255 (efa0dc36f).
for _, n in ipairs({255, 255.0, "255", "0xff"}) do
  q("nmapdb-getprotbynum-255-oracle-abort", "getprotbynum", 1, n)
end
-- luaL_checkoption scans past the unterminated {"tcp","udp","sctp"}
-- (nse_db.cc:49-52) for any name the list does not hold, before the port's
-- range is checked.
for _, proto in ipairs({"foo", "TCP", "Tcp", "", "ip", "icmp", "6", 6, "tcp ", " tcp", "sctp\1",
    "mac2corp", "getservbyport", "nmapdb", "udplite"}) do
  q("nmapdb-getservbyport-option-overread", "getservbyport", 2, 80, proto)
  q("nmapdb-getservbyport-option-overread", "getservbyport", 2, -1, proto)
end
-- isxdigit() of a negative `char` other than EOF (nse_db.cc:31): undefined
-- in ISO C, tolerated by glibc. (0xff is EOF, which isxdigit accepts.)
q("nmapdb-mac2corp-isxdigit-signed-char", "mac2corp", 1, "00\128" .. "000000000")
q("nmapdb-mac2corp-isxdigit-signed-char", "mac2corp", 1, "\200\200\200\200\200\200\200\200\200\200\200\200")

local function quarantine()
  for _, c in ipairs(QUARANTINE) do
    w("quarantine|" .. c[2] .. "(" .. rargs(c[3], c[4], c[5]) .. ")|" .. c[1])
  end
end

action = function()
  local args = nmap.registry.args
  out = assert(io.open(args.out, "w"))
  if (args.mode or "main") == "quarantine" then
    quarantine()
  else
    main()
  end
  w("done")
  out:close()
  return nil
end
