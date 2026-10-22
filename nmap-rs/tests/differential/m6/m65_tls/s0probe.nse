-- The oracle's side of the M6.5 TLS fixtures (step 0's spike, committed by
-- step a; oracle/gen_m65_tls.py runs it): nmap 7.94 connects with "ssl"
-- (or STARTTLS then reconnect_ssl) and reports one line:
--   R: ok leaf=<sha256 of the leaf DER> len=<bytes> cn=<commonName>
--   R: fail <error>
-- --script-args mode=host|ipstr|name|table|starttls [name=...] [tn=...]
-- [timeout=ms]
--
-- Step f1 added modes that read and probe rather than fetch the
-- certificate, and need no `openssl` (the port runs them before step g
-- registers it; `openssl` is loaded only by `leaf`):
--   table     connect with {ip=..., targetname=tn}: the server name sent
--             (tn=EMPTY is "", tn=LONG255 and LONG256 are that many "a")
--   io        how=recv|bytes: read 6 bytes, send "x" (the server then ends
--             the connection as its mode says), then three reads, each
--             `ok(<data>)`, or `nil(<status>)`, and `fast` or `slow`
--             (over 800 ms of the 1000 ms time-out)
--   contract  get_ssl_certificate on a new, a TCP, a failed-TLS and a
--             closed socket, and reconnect_ssl on a closed one
--   udpssl    connect with "ssl" from a UDP socket
--   udprecon  reconnect_ssl on a UDP socket
--   closemid  a worker thread connects with "ssl" (60 s time-out) to a
--             server that never answers; the script closes the socket under
--             it after a second, waits another, and reports `closed`
local nmap = require "nmap"
local stdnse = require "stdnse"
local base64 = require "base64"

description = "M6.5 TLS fixture oracle probe"
categories = {"safe"}
author = "nmap-rs"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

portrule = function(host, port) return port.protocol == "tcp" end

local function leaf(cert)
  local openssl = require "openssl"
  local b64 = cert.pem:gsub("%-%-%-%-%-[^\n]*%-%-%-%-%-", ""):gsub("%s", "")
  local der = base64.dec(b64)
  return stdnse.tohex(openssl.digest("sha256", der)), #der
end

local function smtp_expect(s, code)
  while true do
    local ok, data = s:receive_lines(1)
    if not ok then return nil, "smtp: " .. tostring(data) end
    for l in data:gmatch("[^\r\n]+") do
      if l:sub(1, 3) == code and l:sub(4, 4) == " " then return true end
      if l:sub(1, 1) ~= code:sub(1, 1) then return nil, "smtp: " .. l end
    end
  end
end

local function shown(d)
  return (d:gsub("[^%w%.%-_ ]", function(c) return ("\\x%02x"):format(c:byte()) end))
end

local function io(host, port)
  local how = stdnse.get_script_args("how") or "recv"
  local s = nmap.new_socket()
  s:set_timeout(1000)
  local st, err = s:connect(host, port, "ssl")
  if not st then return "R: fail " .. tostring(err) end
  local ok = s:receive_bytes(6)
  local out = {"io first=" .. tostring(ok)}
  s:send("x")
  for _ = 1, 3 do
    local t0 = nmap.clock_ms()
    local ok, d
    if how == "recv" then ok, d = s:receive() else ok, d = s:receive_bytes(100) end
    local tag = (nmap.clock_ms() - t0) > 800 and "slow" or "fast"
    if ok then
      out[#out + 1] = ("ok(%s)%s"):format(shown(d), tag)
    else
      out[#out + 1] = ("%s(%s)%s"):format(tostring(ok), tostring(d), tag)
    end
  end
  s:close()
  return "R: " .. table.concat(out, " ")
end

local function contract(host, port)
  local out = {}
  local function try(label, f, ...)
    local ok, v = pcall(f, ...)
    out[#out + 1] = ("%s:%s,%s"):format(label, tostring(ok), type(v) == "string" and v or type(v))
  end
  local s = nmap.new_socket()
  try("new", s.get_ssl_certificate, s)
  s:connect(host, port, "tcp")
  try("tcp", s.get_ssl_certificate, s)
  try("arg", s.get_ssl_certificate, 5)
  s:close()
  local c = nmap.new_socket()
  try("closedrecon", c.reconnect_ssl, c)
  local t = nmap.new_socket()
  local st, e = t:connect(host, port, "ssl")
  out[#out + 1] = ("ssl:%s,%s"):format(tostring(st), tostring(e))
  try("sslcert", t.get_ssl_certificate, t)
  t:close()
  try("closedcert", t.get_ssl_certificate, t)
  return "R: contract " .. table.concat(out, " | ")
end

local function closemid(host, port)
  local s = nmap.new_socket()
  s:set_timeout(60000)
  stdnse.new_thread(function () s:connect(host, port, "ssl") end)
  stdnse.sleep(1)
  s:close()
  stdnse.sleep(1)
  return "R: closed"
end

action = function(host, port)
  local mode = stdnse.get_script_args("mode") or "host"
  if mode == "io" then return io(host, port) end
  if mode == "closemid" then return closemid(host, port) end
  if mode == "contract" then return contract(host, port) end
  local s = nmap.new_socket(mode:match("^udp") and "udp" or "tcp")
  s:set_timeout(tonumber(stdnse.get_script_args("timeout")) or 5000)
  local st, err
  if mode == "starttls" then
    st, err = s:connect(host, port, "tcp")
    if not st then return "R: fail connect " .. tostring(err) end
    local ok, e = smtp_expect(s, "220")
    if not ok then return "R: fail " .. e end
    s:send("EHLO probe\r\n")
    ok, e = smtp_expect(s, "250")
    if not ok then return "R: fail " .. e end
    s:send("STARTTLS\r\n")
    ok, e = smtp_expect(s, "220")
    if not ok then return "R: fail " .. e end
    st, err = s:reconnect_ssl()
  elseif mode == "udprecon" then
    st, err = s:reconnect_ssl()
  elseif mode == "udpssl" then
    st, err = s:connect(host.ip, port.number, "ssl")
  elseif mode == "table" then
    local tn = stdnse.get_script_args("tn")
    if tn == "EMPTY" then tn = ""
    elseif tn == "LONG255" then tn = ("a"):rep(255)
    elseif tn == "LONG256" then tn = ("a"):rep(256)
    end
    st, err = s:connect({ip = host.ip, targetname = tn}, port, "ssl")
  elseif mode == "ipstr" then
    st, err = s:connect(host.ip, port.number, "ssl")
  elseif mode == "name" then
    st, err = s:connect(stdnse.get_script_args("name") or "localhost", port.number, "ssl")
  else
    st, err = s:connect(host, port, "ssl")
  end
  if not st then return "R: fail " .. tostring(err) end
  local ok, cert = pcall(s.get_ssl_certificate, s)
  s:close()
  if not ok or not cert then return "R: ok leaf=none err=" .. tostring(cert) end
  local h, n = leaf(cert)
  return ("R: ok leaf=%s len=%d cn=%s"):format(h, n, tostring(cert.subject and cert.subject.commonName))
end
