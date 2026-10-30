description = [[
The libraries that authenticate through `openssl` (M6.5 step g), each against
gen_m64_cli.py's fixture server for it, with the right password and a wrong
one: http.lua's digest authentication (http.lua:1416-1440, MD5 through
`openssl.md5`) on 46040, pop3.lua's APOP (`login_apop`, `openssl.md5`) on
46041, and mysql.lua's `loginRequest` (`createLoginHash`, SHA-1 through
`openssl.sha1`) on 46042. Each result is printed as the library returns it.
The shipped scripts that reach these paths (http-brute, pop3-brute,
mysql-brute) also print timing statistics, which no two runs share.
]]
categories = {"cli"}

local http = require "http"
local mysql = require "mysql"
local nmap = require "nmap"
local pop3 = require "pop3"

portrule = function(host, port)
  return port.number == 46040 or port.number == 46041 or port.number == 46042
end

local function digest(host, port)
  -- nmap.have_ssl, which no shipped script reads: true in an nmap built with
  -- OpenSSL, as the port is since step g.
  local out = {"have_ssl: " .. tostring(nmap.have_ssl())}
  for _, pw in ipairs({"wonderland", "wrong"}) do
    local r = http.get(host, port, "/secret", {no_cache = true, auth = {username = "alice", password = pw, digest = true}})
    out[#out + 1] = ("%s: %s %s"):format(pw, tostring(r.status), tostring(r.body))
  end
  return out
end

local function apop(host, port)
  local out = {}
  for _, pw in ipairs({"wonderland", "wrong"}) do
    local s = nmap.new_socket()
    s:set_timeout(5000)
    s:connect(host, port)
    local _, line = s:receive_lines(1)
    local challenge = line:match("<[%p%w]+>")
    out[#out + 1] = ("%s: %s"):format(pw, tostring((pop3.login_apop(s, "alice", pw, challenge))))
    s:close()
  end
  return out
end

local function login(host, port)
  local out = {}
  for _, pw in ipairs({"wonderland", "wrong", ""}) do
    local s = nmap.new_socket()
    s:set_timeout(5000)
    s:connect(host, port)
    local ok, greeting = mysql.receiveGreeting(s)
    if not ok then return {"greeting: " .. tostring(greeting)} end
    local st, r = mysql.loginRequest(s, {authversion = "post41", charset = greeting.charset},
                                     "alice", pw, greeting.salt)
    out[#out + 1] = ("%q: %s %s"):format(pw, tostring(st), type(r) == "table" and r.errorcode or tostring(r))
    s:close()
  end
  return out
end

action = function(host, port)
  if port.number == 46040 then return digest(host, port) end
  if port.number == 46041 then return apop(host, port) end
  return login(host, port)
end
