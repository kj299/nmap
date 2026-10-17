-- The M6.5 case runner (docs/M6.5-ANALYSIS.md §11 row a). nmap 7.94 loads it
-- through oracle/m65_probe.nse, the tree's C through oracle/m65_driver.lua run
-- by oracle/lua-openssl, and the port will load it the same way: one runner,
-- one rendering, whatever executes it.
--
--   run{ openssl = <module>, parse = <parse_ssl_certificate>,
--        cases = PATH, certs = PATH, out = PATH, start = N }
--   runner{ openssl = <module>, parse = <...>, certs = PATH, drain = false }
--        -> a function from one case row to its result row (the port's
--           gates call it row by row; `drain = false` skips the error-queue
--           drain, which needs `openssl.decrypt`, and writes q=-)
--
-- Case row (oracle/gen_m65_cases.py):  ID TAGS OP SUB ARG...
-- Result row:                          ID <TAB> STATUS <TAB> VALUES <TAB> q=N
-- STATUS is `ok` or `err`. VALUES are the call's results, rendered by
-- `render` and separated by spaces. q=N is how many stale entries the OpenSSL
-- error queue held after the case: it is drained before the next one, so every
-- case starts with it empty (§2, "Error strings depend on history").
--
-- Rendering is greppable (LESSONS #049): a string is "..." with \xHH for any
-- byte outside printable ASCII and for `"` and `\`; one over 256 bytes is
-- #LEN:FNV1A64. A number is i3 or f2.5. A table renders with its keys sorted
-- by their rendering, to depth 6. A BIGNUM renders through its own methods,
-- bn<hex|dec|mpi|bits|bytes>; an SSL_CERT through its fields (`cert_render`).
-- No address ever appears: nothing but these is passed to tostring.

local M = {}

local function fnv64(s)
  local h = -3750763034362895579 -- 0xcbf29ce484222325
  for i = 1, #s do
    h = h ~ s:byte(i)
    h = h * 1099511628211
  end
  return string.format("%016x", h)
end

local function str(s)
  if #s > 256 then return "#" .. #s .. ":" .. fnv64(s) end
  return '"' .. s:gsub('[%c"\\\128-\255]', function(c)
    return string.format("\\x%02x", c:byte())
  end) .. '"'
end
M.str = str

local function unhex(h)
  return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end))
end

function M.runner(env)
  local openssl, parse = env.openssl, env.parse
  local BNMT = getmetatable(openssl.bignum_dec2bn("1"))
  local function is_bn(v) return type(v) == "userdata" and getmetatable(v) == BNMT end

  local render

  local function bn_render(v)
    return "bn<" .. v:tohex() .. "|" .. v:todec() .. "|" .. str(v:tompi()) .. "|"
      .. v:num_bits() .. "|" .. v:num_bytes() .. ">"
  end

  local function table_render(t, depth)
    if depth > 6 then return "{...}" end
    local parts = {}
    for k, v in pairs(t) do
      parts[#parts + 1] = render(k, depth + 1) .. "=" .. render(v, depth + 1)
    end
    table.sort(parts)
    return "{" .. table.concat(parts, ",") .. "}"
  end

  -- An SSL_CERT: what parse_ssl_cert sets (nse_ssl_cert.cc:560-680), the
  -- methods table it inherits, and `digest` over several algorithms.
  local FIELDS = { "subject", "issuer", "version", "serial", "sig_algorithm",
    "validity", "pubkey", "extensions", "pem", "nosuchfield" }
  local DIGESTS = { "md5", "sha1", "sha256", "SHA512", "bogus" }
  local function cert_render(c, depth)
    local parts = {}
    for _, f in ipairs(FIELDS) do
      local ok, v = pcall(function() return c[f] end)
      parts[#parts + 1] = f .. "=" .. (ok and render(v, depth + 1) or ("raise:" .. str(tostring(v))))
    end
    for _, d in ipairs(DIGESTS) do
      local r = table.pack(pcall(function() return c:digest(d) end))
      local rs = {}
      for i = 2, r.n do rs[#rs + 1] = render(r[i], depth + 1) end
      parts[#parts + 1] = "digest(" .. d .. ")=" .. (r[1] and "" or "raise:") .. table.concat(rs, ",")
    end
    return "cert<" .. table.concat(parts, " ") .. ">"
  end

  render = function(v, depth)
    depth = depth or 0
    local t = type(v)
    if t == "string" then return str(v) end
    if t == "number" then
      return (math.type(v) == "integer" and "i" or "f") .. tostring(v)
    end
    if t == "boolean" or t == "nil" then return tostring(v) end
    if is_bn(v) then return bn_render(v) end
    if t == "table" then return table_render(v, depth) end
    if t == "userdata" then
      local ok, sub = pcall(function() return v.subject end)
      if ok and sub ~= nil then return cert_render(v, depth) end
      local mt = getmetatable(v)
      return "userdata<" .. (type(mt) == "table" and tostring(mt.__name) or "?") .. ">"
    end
    return t
  end

  -- An error: positions are discounted (`stdlib-errors-have-no-position`);
  -- the rest is compared exactly.
  local function render_err(e)
    if type(e) ~= "string" then return "e" .. render(e) end
    return "e" .. str((e:gsub("^[^\n]-:%d+: ", "")))
  end

  local CERTS = {}
  if env.certs then
    for line in io.lines(env.certs) do
      if line ~= "" and line:sub(1, 1) ~= "#" then
        local id, _, der = line:match("^([^\t]+)\t([^\t]*)\t(%x*)$")
        CERTS[id] = unhex(der)
      end
    end
  end

  local function decode(tok)
    if tok == "nil" then return nil end
    if tok == "T" then return true end
    if tok == "F" then return false end
    if tok == "tbl" then return {} end
    if tok == "fn" then return print end
    local tag, body = tok:match("^(%w+):(.*)$")
    if tag == "s" then return unhex(body) end
    if tag == "i" then return math.tointeger(tonumber(body)) end
    if tag == "f" then return tonumber(body) + 0.0 end
    if tag == "bnd" then return openssl.bignum_dec2bn(unhex(body)) end
    if tag == "bnh" then return openssl.bignum_hex2bn(unhex(body)) end
    if tag == "bnb" then return openssl.bignum_bin2bn(unhex(body)) end
    if tag == "der" then return assert(CERTS[body], "no certificate " .. body) end
    error("bad token " .. tok)
  end

  -- A failing call that queues nothing: GCM decryption with no tag. Each one
  -- pops one stale entry; an empty queue reads as error:00000000.
  local DK, DIV = string.rep("\1", 16), string.rep("\1", 12)
  local function drain()
    for n = 0, 40 do
      local ok, e = pcall(openssl.decrypt, "aes-128-gcm", DK, DIV, "x")
      if ok then return "?" end
      if e:find("error:00000000:", 1, true) then return n end
    end
    return "40+"
  end

  local OPS = {}

  -- call FN ARGS...: every result.
  OPS.call = function(fn, args)
    return pcall(openssl[fn], table.unpack(args, 1, args.n))
  end

  -- mut FN BN ARGS...: a mutator's results, then the mutated bignum.
  OPS.mut = function(fn, args)
    local r = table.pack(pcall(openssl[fn], table.unpack(args, 1, args.n)))
    if r[1] then r.n = r.n + 1; r[r.n] = args[1] end
    return table.unpack(r, 1, r.n)
  end

  -- meth NAME BN ARGS...: the same function reached as a method, then the
  -- receiver (which set_bit and clear_bit change).
  OPS.meth = function(name, args)
    local v = args[1]
    local r = table.pack(pcall(function() return v[name](table.unpack(args, 1, args.n)) end))
    if r[1] then r.n = r.n + 1; r[r.n] = v end
    return table.unpack(r, 1, r.n)
  end

  -- rt CIPHER KEY IV DATA PAD: encrypt, then decrypt what came out.
  OPS.rt = function(cipher, args)
    local key, iv, data, pad = args[1], args[2], args[3], args[4]
    local ok, ct = pcall(openssl.encrypt, cipher, key, iv, data, pad)
    if not ok then return false, ct end
    local ok2, pt = pcall(openssl.decrypt, cipher, key, iv, ct, pad)
    if not ok2 then return true, ct, "dec-err", pt end
    return true, ct, pt == data
  end

  -- rlen FN N: a random function; its shape, not its bytes. For a random
  -- bignum, over 64 draws: every one within N bits, some one shorter (BN_rand's
  -- top bit is free, `nse_openssl.cc:89`: a 2^-64 chance of a false "no"),
  -- and none negative.
  OPS.rlen = function(fn, args)
    local ok, r = pcall(openssl[fn], table.unpack(args, 1, args.n))
    if not ok then return false, r end
    if is_bn(r) then
      local n = math.max(args[1], 0)
      local within, shorter, neg = true, false, false
      for _ = 1, 64 do
        local b = openssl[fn](args[1])
        within = within and b:num_bits() <= n
        shorter = shorter or b:num_bits() < n
        neg = neg or b:tohex():sub(1, 1) == "-"
      end
      return true, "bits", within, shorter, neg
    end
    return true, type(r), #r
  end

  -- cert parse_ssl_certificate ARG...: parse, render what comes back.
  OPS.cert = function(_, args)
    return pcall(parse, table.unpack(args, 1, args.n))
  end

  -- meta: the module's shape.
  OPS.meta = function(what)
    if what == "keys" then
      local ks = {}
      for k, v in pairs(openssl) do
        if k ~= "nse_openssl_state" then ks[#ks + 1] = k .. "=" .. type(v) end
      end
      table.sort(ks)
      return true, table.concat(ks, ",")
    elseif what == "state" then
      return true, type(openssl.nse_openssl_state)
    elseif what == "bnmeta" then
      local ks = {}
      for k, v in pairs(BNMT) do ks[#ks + 1] = tostring(k) .. "=" .. type(v) end
      table.sort(ks)
      return true, table.concat(ks, ","), BNMT.__index == BNMT,
        tostring(openssl.bignum_hex2bn("-1f"))
    elseif what == "digests" then
      return true, table.concat(openssl.supported_digests(), ",")
    elseif what == "ciphers" then
      return true, table.concat(openssl.supported_ciphers(), ",")
    end
  end

  local do_drain = env.drain ~= false
  return function(line)
    local f = {}
    for tok in line:gmatch("[^\t]+") do f[#f + 1] = tok end
    local id, op, sub = f[1], f[3], f[4]
    local args = { n = #f - 4 }
    local okdec, derr = pcall(function()
      for i = 5, #f do args[i - 4] = decode(f[i]) end
    end)
    local r
    if not okdec then
      r = table.pack(false, "decode: " .. tostring(derr))
    else
      r = table.pack(OPS[op](sub, args))
    end
    local parts = {}
    if r[1] then
      for i = 2, r.n do parts[#parts + 1] = render(r[i]) end
    else
      parts[1] = render_err(r[2])
    end
    return id .. "\t" .. (r[1] and "ok" or "err") .. "\t" .. table.concat(parts, " ")
      .. "\tq=" .. (do_drain and tostring(drain()) or "-")
  end
end

function M.run(env)
  local row = M.runner(env)
  local start = tonumber(env.start or 1)
  local out = assert(io.open(env.out, "a"))
  local idx = 0
  for line in io.lines(env.cases) do
    if line ~= "" and line:sub(1, 1) ~= "#" then
      idx = idx + 1
      if idx >= start then
        out:write(row(line), "\n")
        out:flush()
      end
    end
  end
  out:close()
  return idx
end

return M
