-- The M6.3 probe: run by nmap 7.94 (the oracle) and by the port, against the
-- same host, it prints what the `nmap` module's non-I/O half says.
--
-- It uses nothing but the `nmap` module and the base library -- no `require`,
-- no stdnse -- so the port can run it before NSE's loader exists. Every value
-- is rendered with its type, strings in hex; anything that differs from run to
-- run (clocks, random bytes, interface lists) is reduced to its type or length.
-- Argument errors name the function as the C does for a call made by pcall,
-- 'nmap.get_ports'; the port names it 'get_ports', and `fix` rewrites the one
-- into the other (DIVERGENCES.md, `nmaplib-bad-argument-naming`).

description = "M6.3 differential probe"
categories = {"m63probe"}
author = "nmap-rs"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

hostrule = function(host)
  return host.ip == "127.0.0.1" or host.ip == "::1"
end

local out = {}
local function w(...)
  out[#out + 1] = table.concat({...}, " ")
end

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local render
local function key_order(a, b)
  local ta, tb = type(a), type(b)
  if ta ~= tb then return ta < tb end
  if ta == "number" or ta == "string" then return a < b end
  return false
end
render = function(v, depth)
  depth = depth or 0
  local t = type(v)
  if t == "string" then return "s:" .. hex(v) end
  if t == "number" then return math.type(v) .. ":" .. tostring(v) end
  if t == "boolean" or t == "nil" then return tostring(v) end
  if t ~= "table" then return t end
  if depth > 6 then return "{...}" end
  local keys = {}
  for k in pairs(v) do keys[#keys + 1] = k end
  table.sort(keys, key_order)
  local parts = {}
  for _, k in ipairs(keys) do
    parts[#parts + 1] = render(k, depth + 1) .. "=" .. render(v[k], depth + 1)
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local function fix(e)
  if type(e) == "string" then
    return "s:" .. hex((e:gsub("'nmap%.([%w_]+)'", "'%1'")))
  end
  return render(e)
end

-- pcall f with the arguments and render every result.
local function try(label, f, ...)
  local r = table.pack(pcall(f, ...))
  local parts = {}
  if r[1] then
    for i = 2, r.n do parts[#parts + 1] = render(r[i]) end
    w(label, "ok", tostring(r.n - 1), table.concat(parts, " "))
  else
    w(label, "err", fix(r[2]))
  end
end

local function port_key(p)
  return p and (p.number .. "/" .. p.protocol) or "nil"
end

action = function(host)
  -- Everything this probe logs comes after this line.
  nmap.log_write("stdout", "m63-log begin")
  -- The host table as NSE built it.
  local h = {}
  for k, v in pairs(host) do h[k] = v end
  w("HOST", render(h))
  w("ARGS", render(nmap.registry.args))
  w("REGISTRY_TYPE", type(nmap.registry), type(host.registry))

  -- Options and facts.
  try("verbosity", nmap.verbosity)
  try("debugging", nmap.debugging)
  try("timing_level", nmap.timing_level)
  try("version_intensity", nmap.version_intensity)
  try("version_intensity_again", nmap.version_intensity)
  try("have_ssl", nmap.have_ssl)
  try("is_privileged", nmap.is_privileged)
  try("address_family", nmap.address_family)
  try("get_interface", nmap.get_interface)
  try("get_ttl", nmap.get_ttl)
  try("get_payload_length", nmap.get_payload_length)
  w("dns_type", type(nmap.get_dns_servers()))
  w("fetchfile_found", type(nmap.fetchfile("nmap-services")))
  try("fetchfile_missing", nmap.fetchfile, "no-such-file-m63")
  try("fetchfile_none", nmap.fetchfile)
  w("clock_type", math.type(nmap.clock()), math.type(nmap.clock_ms()))
  w("interfaces_type", type((nmap.list_interfaces())))

  -- Random bytes: lengths and the errors.
  for _, n in ipairs({0, 1, 5}) do
    local ok, r = pcall(nmap.get_random_bytes, n)
    w("random", tostring(n), tostring(ok), ok and tostring(#r) or fix(r))
  end
  for i, n in ipairs({-1, "x", 1.5, (1 << 32) + 3, "7"}) do
    local ok, r = pcall(nmap.get_random_bytes, n)
    w("random_odd", tostring(i), tostring(ok), ok and tostring(#r) or fix(r))
  end
  try("random_none", nmap.get_random_bytes)

  -- Exclusions.
  for _, c in ipairs({{9100, "tcp"}, {9100, "udp"}, {9107, "tcp"}, {9108, "tcp"},
                      {80, "tcp"}, {65536 + 9100, "tcp"}, {-56436, "tcp"}}) do
    try("excluded_" .. c[1] .. "_" .. c[2], nmap.port_is_excluded, c[1], c[2])
  end
  try("excluded_badproto", nmap.port_is_excluded, 9100, "icmp")
  try("excluded_noproto", nmap.port_is_excluded, 9100)
  try("excluded_str", nmap.port_is_excluded, "9100", "tcp")
  try("excluded_float", nmap.port_is_excluded, 9100.5, "tcp")

  -- Every port, by every protocol and state, following get_ports' chain.
  local seen, scanned = {}, {}
  for _, proto in ipairs({"tcp", "udp", "sctp"}) do
    for _, state in ipairs({"open", "filtered", "unfiltered", "closed",
                            "open|filtered", "closed|filtered"}) do
      local chain = {}
      local p = nmap.get_ports(host, nil, proto, state)
      local n = 0
      while p and n < 80 do
        chain[#chain + 1] = port_key(p)
        if not seen[port_key(p)] then
          seen[port_key(p)] = true
          scanned[#scanned + 1] = p
        end
        p = nmap.get_ports(host, p, proto, state)
        n = n + 1
      end
      w("CHAIN", proto, state, table.concat(chain, ","))
    end
  end
  table.sort(scanned, function(a, b)
    if a.protocol ~= b.protocol then return a.protocol < b.protocol end
    return a.number < b.number
  end)
  for _, p in ipairs(scanned) do
    w("PORT", port_key(p), render(nmap.get_port_state(host, p)))
  end

  -- Port and host lookups, and their errors.
  local first = scanned[1]
  local num = first and first.number or 1
  local proto = first and first.protocol or "tcp"
  local function q(t) return render((select(2, pcall(nmap.get_port_state, host, t)))) end
  try("lookup_plain", function() return port_key(nmap.get_port_state(host, {number = num, protocol = proto})) end)
  try("lookup_wrap", function() return port_key(nmap.get_port_state(host, {number = num + (1 << 32), protocol = proto})) end)
  try("lookup_unscanned", nmap.get_port_state, host, {number = 59999, protocol = "tcp"})
  try("lookup_other_proto_tcp", function() return port_key(nmap.get_port_state(host, {number = num, protocol = "tcp"})) end)
  try("lookup_other_proto_udp", function() return port_key(nmap.get_port_state(host, {number = num, protocol = "udp"})) end)
  try("lookup_other_proto_sctp", function() return port_key(nmap.get_port_state(host, {number = num, protocol = "sctp"})) end)
  try("lookup_float", nmap.get_port_state, host, {number = num + 0.0, protocol = proto})
  try("lookup_strnum", nmap.get_port_state, host, {number = tostring(num), protocol = proto})
  try("lookup_noproto", nmap.get_port_state, host, {number = num})
  try("lookup_numproto", nmap.get_port_state, host, {number = num, protocol = 6})
  try("lookup_upper", nmap.get_port_state, host, {number = num, protocol = "TCP"})
  try("lookup_proto_nul", function() return port_key(nmap.get_port_state(host, {number = num, protocol = proto .. "\0x"})) end)
  try("lookup_port_str", nmap.get_port_state, host, "80")
  try("lookup_port_none", nmap.get_port_state, host)
  try("host_empty", nmap.get_port_state, {}, {number = num, protocol = proto})
  try("host_unknown", nmap.get_port_state, {ip = "192.0.2.77"}, {number = num, protocol = proto})
  try("host_numip", nmap.get_port_state, {ip = 5}, {number = num, protocol = proto})
  try("host_copy", function() return port_key(nmap.get_port_state({ip = host.ip}, {number = num, protocol = proto})) end)
  try("host_target", function() return port_key(nmap.get_port_state({targetname = host.targetname or host.ip}, {number = num, protocol = proto})) end)
  try("host_badip_goodname", function() return port_key(nmap.get_port_state({ip = "192.0.2.1", targetname = host.ip}, {number = num, protocol = proto})) end)
  try("host_string", nmap.get_port_state, "127.0.0.1", {number = num, protocol = proto})
  try("ports_missing_port", nmap.get_ports, host)
  try("ports_none_port", nmap.get_ports, host, nil)
  try("ports_bad_proto", nmap.get_ports, host, nil, "icmp", "open")
  try("ports_bad_state", nmap.get_ports, host, nil, "tcp", "OPEN")
  try("ports_unknown_cur", function() return port_key(nmap.get_ports(host, {number = 59999, protocol = "tcp"}, "tcp", "closed")) end)
  for _, pr in ipairs({"tcp", "udp", "sctp"}) do
    try("ports_cross_" .. pr, function()
      local r = {}
      local p = nmap.get_ports(host, nil, pr, "closed")
      while p and #r < 80 do r[#r + 1] = port_key(p); p = nmap.get_ports(host, p, pr, "open") end
      return table.concat(r, ",")
    end)
  end

  -- new_try.
  local calls = 0
  local t = nmap.new_try()
  local th = nmap.new_try(function() calls = calls + 1 end)
  try("try_true", t, true, 1, nil, "x")
  try("try_true_only", t, true)
  try("try_false", t, false, "boom")
  try("try_false_nomsg", t, false)
  try("try_nil", t, nil, "m")
  try("try_none", t)
  try("try_nonconforming", t, 1, 2)
  try("try_handler", th, false, "h")
  w("try_handler_calls", tostring(calls))
  try("try_handler_true", th, true, "v")
  w("try_handler_calls", tostring(calls))
  try("try_handler_errors", nmap.new_try(function() error("in handler", 0) end), false, "m")
  try("try_handler_number", nmap.new_try(5), false, "m")
  try("try_extra_args", nmap.new_try(nil, "ignored"), false, "m")

  -- Changing ports.
  local open = nmap.get_ports(host, nil, "tcp", "open")
  local closed = nmap.get_ports(host, nil, "tcp", "closed")
  if open then
    try("set_closed", nmap.set_port_state, host, open, "closed")
    w("after_set_closed", render(nmap.get_port_state(host, open)))
    try("set_open", nmap.set_port_state, host, open, "open")
    w("after_set_open", render(nmap.get_port_state(host, open)))
    try("set_same", nmap.set_port_state, host, open, "open")
    w("after_set_same", render(nmap.get_port_state(host, open)))
  end
  if closed then
    try("set_closed_open", nmap.set_port_state, host, closed, "open")
    w("after_set_closed_open", render(nmap.get_port_state(host, closed)))
    try("set_bad_option", nmap.set_port_state, host, closed, "filtered")
  end
  try("set_unknown_bad_option", nmap.set_port_state, host, {number = 59999, protocol = "tcp"}, "bogus")

  local long = string.rep("p", 100)
  local versions = {
    {"hard", {name = "m63svc", product = long, version = "1.0\1\127\200", extrainfo = string.rep("e", 300),
              hostname = "h\0tail", ostype = string.rep("o", 40), devicetype = "router",
              service_tunnel = "ssl", service_fp = "SF:fp", cpe = {"cpe:/a:x:y", 7, true, "cpe:/o:" .. long}}, nil},
    {"soft", {name = "m63soft", product = 42, service_fp = "SF:soft\0x"}, "softmatched"},
    {"nomatch_named", {name = "m63named"}, "nomatch"},
    {"nomatch_unnamed", {}, "nomatch"},
    {"wrapped_unnamed", {}, "tcpwrapped"},
    {"wrapped_named", {name = "w"}, "tcpwrapped"},
    {"incomplete", {product = "inc"}, "incomplete"},
    {"tunnel_none", {name = "n", service_tunnel = "none"}, "hardmatched"},
    {"tunnel_bad", {name = "n", service_tunnel = "tls"}, "hardmatched"},
    {"cpe_bad", {name = "n", cpe = "cpe:/a"}, "hardmatched"},
    {"fields_odd", {name = {}, product = true, version = 1.5}, "hardmatched"},
  }
  for _, target in ipairs({open, closed}) do
    for _, case in ipairs(versions) do
      local p = {number = target.number, protocol = target.protocol, version = case[2]}
      local label = "version_" .. case[1] .. "_" .. target.state
      try(label, nmap.set_port_version, host, p, case[3])
      w("after_" .. label, render(nmap.get_port_state(host, target)))
    end
  end
  -- No unknown probe state: l_set_port_version's option list has no
  -- terminating NULL, so nmap reads past it, which is undefined behaviour and
  -- recorded in no golden (nmaplib-set-port-version-option-overread). A unit
  -- test in core::nse::nmaplib pins the port's error instead.
  try("version_no_table", nmap.set_port_version, host, {number = open.number, protocol = "tcp"}, "hardmatched")
  try("version_unknown_port", nmap.set_port_version, host, {number = 59999, protocol = "tcp"})
  try("version_bad_host", nmap.set_port_version, {}, open)

  -- New targets.
  try("targets_queue_empty", nmap.add_targets)
  try("targets_num_start", nmap.new_targets_num)
  try("targets_empty_string", nmap.add_targets, "")
  try("targets_one", nmap.add_targets, "127.0.0.2")
  try("targets_again", nmap.add_targets, "127.0.0.2")
  try("targets_empty_now", nmap.add_targets, "")
  try("targets_many", nmap.add_targets, "127.0.0.3", "", "127.0.0.4")
  try("targets_too_long", nmap.add_targets, string.rep("a", 1024))
  try("targets_long_ok", nmap.add_targets, string.rep("a", 1023) .. "\0tail")
  try("targets_stop_early", nmap.add_targets, "127.0.0.5", string.rep("b", 2000), {})
  try("targets_bad_type", nmap.add_targets, {})
  try("targets_number", nmap.add_targets, 7)
  try("targets_queue", nmap.add_targets)
  try("targets_num", nmap.new_targets_num)

  -- Logging (the lines themselves are compared separately).
  try("log_stdout", nmap.log_write, "stdout", "m63-log one")
  try("log_nul", nmap.log_write, "stdout", "m63-log two\0hidden")
  try("log_number", nmap.log_write, "stdout", 63)
  try("log_stderr", nmap.log_write, "stderr", "m63-log err")
  try("log_bad", nmap.log_write, "both", "x")
  try("log_nomsg", nmap.log_write, "stdout")

  -- I/O functions are M6.4's: only their presence is compared.
  for _, n in ipairs({"new_socket", "new_dnet", "get_interface_info", "mutex", "condvar", "resolve"}) do
    w("present", n, type(nmap[n]))
  end

  return table.concat(out, "\n")
end
