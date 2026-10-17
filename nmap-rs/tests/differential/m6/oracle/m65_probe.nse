-- The M6.5 corpus under nmap itself (7.94): a prerule that runs
-- oracle/m65_core.lua over a cases file and writes one result row per case to
-- a file (never to script output, so no output limit applies).
--
--   nmap -n --script m65_probe.nse --script-args \
--     core=CORE,cases=CASES,certs=CERTS,out=OUT[,start=N]
--
-- `start=N` skips the first N-1 cases: oracle/gen_m65.py restarts the run
-- after a case that kills the process.

description = "M6.5 openssl differential probe"
categories = {"m65probe"}
author = "nmap-rs"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

prerule = function() return true end

local openssl = require "openssl"

action = function()
  local a = nmap.registry.args
  local core = dofile(a.core)
  local n = core.run{
    openssl = openssl, parse = nmap.socket.parse_ssl_certificate,
    cases = a.cases, certs = a.certs, out = a.out, start = a.start,
  }
  return "done " .. n
end
