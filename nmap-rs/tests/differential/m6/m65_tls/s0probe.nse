-- The oracle's side of the M6.5 TLS fixtures (step 0's spike, committed by
-- step a; oracle/gen_m65_tls.py runs it): nmap 7.94 connects with "ssl"
-- (or STARTTLS then reconnect_ssl) and reports one line:
--   R: ok leaf=<sha256 of the leaf DER> len=<bytes> cn=<commonName>
--   R: fail <error>
-- --script-args mode=host|ipstr|name|starttls [name=...] [timeout=ms]
local nmap = require "nmap"
local stdnse = require "stdnse"
local base64 = require "base64"
local openssl = require "openssl"

description = "M6.5 TLS fixture oracle probe"
categories = {"safe"}
author = "nmap-rs"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

portrule = function(host, port) return port.protocol == "tcp" end

local function leaf(cert)
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

action = function(host, port)
  local mode = stdnse.get_script_args("mode") or "host"
  local s = nmap.new_socket()
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
