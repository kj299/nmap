-- The 11 network-facing LPeg patterns of M6.6 step 0b, built from this tree's
-- real nselib/ and scripts/. Called as loadfile(...)(REPO, HERE); returns
-- M, lpeg, ORDER. Each M[id] has:
--   match(subject)  runs the LPeg work the script or library runs on that
--                   network subject (nested matches included)
--   seeds           realistic fixtures (the search starts from them)
--   alpha           structural tokens for mutation
--   grow(n)         a scalable adversarial family for the growth test
--   site            where the pattern lives (line numbers computed, not typed)
--
-- json, lpeg-utility and re are `require`d from nselib/ through package.path.
-- The grammars that live inside a script or inside a library function
-- (coap's link format, ntp-info's kvmatch, fingerprint-strings' strings(),
-- http-affiliate-id's four `re` grammars) are not copied here: their source
-- lines are sliced out of the real file by exact-line anchors and loaded, so
-- an edit to those files either reaches the search or stops it with an error.
-- Nothing in the repository is modified.
local REPO, HERE = ...
assert(REPO and HERE, "matchers.lua: pass the repository root and lpeg_search/")
assert(loadfile(HERE .. "/stubs.lua"))(REPO)
local lpeg = require "lpeg"
local json = require "json"
local U    = require "lpeg-utility"
local re   = require "re"
local rep  = string.rep

local function lines_of(rel)
  local t = {}
  for l in io.lines(REPO .. "/" .. rel) do t[#t + 1] = l end
  return t
end

-- The one line of `rel` equal to `text` (a missing or repeated line is an error).
local function line_of(rel, text, L)
  L = L or lines_of(rel)
  local at
  for i, l in ipairs(L) do
    if l == text then
      assert(not at, rel .. ": anchor occurs twice: " .. text)
      at = i
    end
  end
  return assert(at, rel .. ": anchor not found: " .. text)
end

-- Lines `from`..`to` of `rel`, searched forward from the one line equal to
-- `outer`. If `after` is given, the next non-blank line must equal it (the
-- line that uses the grammar); its number is returned as the match site.
local function slice(rel, outer, from, to, after)
  local L = lines_of(rel)
  local o = line_of(rel, outer, L)
  local s, e, m
  for i = o, #L do if L[i] == from then s = i; break end end
  assert(s, rel .. ": anchor not found after line " .. o .. ": " .. from)
  for i = s, #L do if L[i] == to then e = i; break end end
  assert(e, rel .. ": anchor not found after line " .. s .. ": " .. to)
  if after then
    m = e + 1
    while L[m] and L[m]:match("^%s*$") do m = m + 1 end
    assert(L[m] == after, rel .. ":" .. tostring(m) .. ": expected " .. after)
  end
  return table.concat(L, "\n", s, e), s, e, m, L
end

-- Load a slice so that its line numbers are the file's. `prelude` (one line)
-- is placed on the line before the slice.
local function build(rel, code, first, env, prelude)
  local pad
  if prelude then
    assert(first >= 2)
    pad = rep("\n", first - 2) .. prelude .. "\n"
  else
    pad = rep("\n", first - 1)
  end
  return assert(load(pad .. code, "@" .. rel, "t", env))
end

local M = {}
local ORDER = {"json", "coap", "get_response", "parse_fp", "ntp", "fpstrings",
               "aff_ga", "aff_ad", "aff_amz", "aff_short", "escaped_quote"}

-- P1: json.lua's grammar (compiled at load), through json.parse
M.json = {
  site = "nselib/json.lua json.parse",
  match = function(s) json.parse(s) end,
  seeds = {
    '{"name":"scanme","ports":[22,80,443],"up":true,"meta":{"os":"linux","v":null}}',
    '[1,2,3,4,5,6,7,8,9,10]',
    '{"a":"\\u0041\\u00e9\\uD83D\\uDE00","b":false}',
    '{"items":[{"id":1,"t":"x"},{"id":2,"t":"yy"}],"n":3.14e2}',
    '"a plain string with \\t tab and \\\\ backslash"',
  },
  alpha = {"[","]","{","}",'"',"\\",",",":","0","1","9",".","-","e","t","r","u","a",
           "true","false","null",'\\u0041','\\uD83D','\\uDE00','0x','\\n'," "},
  -- flat wide array of numbers: exercises value/number/elements repetition
  grow = function(n) return "[" .. rep("1,", n) .. "1]" end,
}

-- P2: coap's link-format grammar, built inside
-- COAP.payload.application_link_format.parse (coap.lua pulls in comm, nmap
-- and more, so the grammar's own lines are loaded instead of the module)
do
  local rel = "nselib/coap.lua"
  local code, s, e, m = slice(rel,
    "COAP.payload.application_link_format.parse = function(hdr, buf)",
    "  local P  = lpeg.P",
    "  local patt = Ct(link * (P',' * link)^0)",
    "  local matches = lpeg.match(patt, buf)")
  local patt = build(rel, code .. "\nreturn patt", s, {lpeg = lpeg})()
  M.coap = {
    site = ("%s:%d-%d (application_link_format grammar); matched :%d"):format(rel, s, e, m),
    match = function(subj) lpeg.match(patt, subj) end,
    seeds = {
      "</sensors/temp>;rt=\"temperature\";if=\"sensor\",</sensors/light>;rt=\"light\"",
      "</.well-known/core>,</time>;ct=0,</dev>;title=\"Device\"",
      "</a>;b=c,</d>;e=\"f,g;h\"",
    },
    alpha = {"<",">",";","=",'"',",","a","b","x","/",".","\\"},
    grow = function(n) return rep("<u>;k=v,", n - 1) .. "<u>;k=v" end,
  }
end

-- P3: lpeg-utility get_response: getquote (escaped_quote) then unescape.
-- Subject = the network service fingerprint; probe fixed "NULL".
local FPQ = function(payload) return 'NULL,4,"' .. payload .. '"' end
M.get_response = {
  site = "nselib/lpeg-utility.lua get_response (escaped_quote + unescape)",
  match = function(s) U.get_response(s, "NULL") end,
  seeds = {
    FPQ("HTTP/1.0 200 OK\\r\\nServer: foo\\r\\n\\r\\n"),
    FPQ("\\x01\\x02\\x03abc\\ndef"),
    FPQ(rep("A", 64)),
    "NULL,4,\"short\"%r(GetRequest,5,\"other\")",
  },
  alpha = {'"',"\\",",","N","U","L","0","4",'\\x','\\n','\\r','\\t','\\0',"A","a","%r(",")"},
  -- a long quoted blob full of hex escapes: unescape must process each
  grow = function(n) return 'NULL,4,"' .. rep("\\x41", n) .. '"' end,
}

-- P4: lpeg-utility parse_fp (anywhere, Cf, Cg, getquote/unescape).
-- Subject = the service fingerprint.
M.parse_fp = {
  site = "nselib/lpeg-utility.lua parse_fp (anywhere + svfp_parser)",
  match = function(s) U.parse_fp(s) end,
  seeds = {
    '%r(NULL,4,"abc")%r(GetRequest,5,"HTTP/1.0")',
    'Prefix junk %r(NULL,2,"xy")',
    '%r(A,1,"\\x41\\x42")%r(B,2,"ok")',
    rep("x", 200) .. "%r(NULL,4,\"y\")",
  },
  alpha = {"%r(",")",'"',"\\",",","A","B","N","U","0","1","4","x",'\\x',"a"," "},
  grow = function(n) return rep('%r(P,1,"x")', n) end,
}

-- P5: ntp-info's kvmatch (U.localize + U.escaped_quote), applied as
-- kvmatch^0. The script appends `/ accumulate_output`, a function capture
-- whose Lua cost is script-side and quadratic in the pair count
-- (scriptside.lua measures it); the search measures the LPeg work.
do
  local rel = "scripts/ntp-info.nse"
  local code, s, e = slice(rel, "local kvmatch = U.localize( {", "local kvmatch = U.localize( {", "  } )")
  local kvmatch = build(rel, code .. "\nreturn kvmatch", s, {lpeg = lpeg, U = U})()
  local m = line_of(rel, "    local list = kvmatch^0 / accumulate_output")
  local list = kvmatch^0
  M.ntp = {
    site = ("%s:%d-%d (kvmatch); matched :%d-%d"):format(rel, s, e, m, m + 1),
    match = function(subj) list:match(subj) end,
    seeds = {
      "version=\"ntpd 4.2.8p15\", processor=\"x86_64\", system=\"Linux\", stratum=3",
      "refid=0x7f000001, rootdelay=0.000, leap=0, precision=-24",
      "a=\"quoted, with commas\", b=bare, c=",
    },
    alpha = {"=",",",'"',"\\","k","v","a","_","-",".","0","1"," ","\\n"},
    grow = function(n) return rep("k=v,", n) end,
  }
  M._ntp_kvmatch = kvmatch   -- for scriptside.lua and verify_wellformed.lua
end

-- P6: fingerprint-strings' strings() grammar at the script's default n.
do
  local rel = "scripts/fingerprint-strings.nse"
  local code, s, e, m, L = slice(rel, "local function strings (blob, n)",
    "  local pat = lpeg.P {", "  }", "  return lpeg.match(lpeg.Cs(pat), blob)")
  local n, nline
  for i, l in ipairs(L) do
    local d = l:match('^%s*local min = stdnse%.get_script_args%(SCRIPT_NAME %.%. "%.n"%) or (%d+)$')
    if d then assert(not n, rel .. ": default n found twice"); n = tonumber(d); nline = i end
  end
  assert(n, rel .. ": the default of fingerprint-strings.n was not found")
  local mk = build(rel, code .. "\nreturn lpeg.Cs(pat)", s, {lpeg = lpeg}, "local n = ...")
  local pat = mk(n)
  M.fpstrings = {
    site = ("%s:%d-%d (strings(), n=%d, the default at :%d); matched :%d"):format(rel, s, e, n, nline, m),
    match = function(subj) lpeg.match(pat, subj) end,
    seeds = {
      "Server: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html>",
      "\x00\x01\x02GET / HTTP/1.1\r\n\x7f\x80\x90normalchars",
      rep("A", 80) .. "\x00" .. rep("B", 80),
    },
    alpha = {"A","a"," ","\t","\r","\n","\x00","\x7f","\x80","\xff","\x20","\x21","!","Z","z","\x01"},
    grow = function(k) return rep("ab \x00", k) end,  -- alternate plain/skip
  }
end

-- P7a-d: http-affiliate-id's four `re` grammars. Subject = the HTTP body.
do
  local rel = "scripts/http-affiliate-id.nse"
  local c1, s1, e1, _, L = slice(rel, "local AFFILIATE_PATTERNS = {", "local AFFILIATE_PATTERNS = {", "}")
  local c2, s2, e2 = slice(rel, "local URL_SHORTENERS = {", "local URL_SHORTENERS = {", "}")
  local AP = build(rel, c1 .. "\nreturn AFFILIATE_PATTERNS", s1, {re = re})()
  local US = build(rel, c2 .. "\nreturn URL_SHORTENERS", s2, {re = re})()
  local function keyline(key, s, e)
    for i = s, e do if L[i]:find('["' .. key .. '"]', 1, true) then return i end end
    error(rel .. ": no line for " .. key)
  end
  local want = {
    {"aff_ga", AP, "Google Analytics ID", s1, e1},
    {"aff_ad", AP, "Google Adsense ID", s1, e1},
    {"aff_amz", AP, "Amazon Associates ID", s1, e1},
    {"aff_short", US, "amzn.to", s2, e2},
  }
  -- the search covers exactly these: a pattern added to the script must be
  -- added here too, so count them
  local na, ns = 0, 0
  for _ in pairs(AP) do na = na + 1 end
  for _ in pairs(US) do ns = ns + 1 end
  assert(na == 3 and ns == 1, ("%s: expected 3 affiliate and 1 shortener patterns, found %d and %d"):format(rel, na, ns))
  local body_seeds = {
    "<html><body><script>UA-123456-1</script><a href='http://amzn.to/abc'>x</a></body></html>",
    "pub-1234567890123456 and some text http://www.amazon.com/?tag=foo-12 more",
    rep("x", 500) .. "UA-654321" .. rep("y", 500),
    "no ids here, just plain text " .. rep("lorem ipsum ", 40),
  }
  local body_alpha = {"U","A","-","p","u","b","h","t","p",":","/",".","w","a","m","z","o","n","c",
                      "?","&",";","=","'","\"","0","1","9"," ","x","<",">","g"}
  local grows = {
    -- near-miss: 'UA-' + 5 digits fails the ^6, and retries through `/ .`
    aff_ga = function(n) return rep("UA-12345", n) end,
    -- 'pub-' + 15 digits, one short of the 16
    aff_ad = function(n) return rep("pub-123456789012345", n) end,
    aff_amz = function(n) return rep("http://www.amazon.com/?tag=a-1&", n) end,
    aff_short = function(n) return rep("http://amzn.to/a", n) end,
  }
  for _, w in ipairs(want) do
    local id, tbl, key, s, e = w[1], w[2], w[3], w[4], w[5]
    local p = assert(tbl[key], rel .. ": pattern " .. key .. " missing")
    M[id] = {
      site = ("%s:%d (%s)"):format(rel, keyline(key, s, e), key),
      match = function(subj) p:match(subj) end,
      seeds = body_seeds, alpha = body_alpha, grow = grows[id],
    }
  end
end

-- P8: escaped_quote() on its own, the sub-pattern shared by P3, P4 and P5
do
  local eq = U.escaped_quote()
  M.escaped_quote = {
    site = "nselib/lpeg-utility.lua escaped_quote() (sub-pattern of get_response, parse_fp, ntp)",
    match = function(s) eq:match(s) end,
    seeds = { '"abc\\"def"', '"' .. rep("x", 64) .. '"', '"\\\\\\""' },
    alpha = {'"',"\\","a","x"},
    grow = function(n) return '"' .. rep("x\\\"", n) .. '"' end,
  }
end

for _, id in ipairs(ORDER) do assert(M[id], "matchers.lua: no pattern " .. id) end
return M, lpeg, ORDER
