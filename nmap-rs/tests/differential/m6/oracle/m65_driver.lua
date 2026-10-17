-- The M6.5 corpus under this tree's C: oracle/lua-openssl (build_openssl_oracle.sh)
-- runs oracle/m65_core.lua over a cases file.
--
--   oracle/lua-openssl oracle/m65_driver.lua CORE CASES CERTS OUT [START]

local core = dofile(arg[1])
local n = core.run{
  openssl = require "openssl", parse = require "nmap.socket".parse_ssl_certificate,
  cases = arg[2], certs = arg[3], out = arg[4], start = arg[5],
}
io.stderr:write("done ", n, "\n")
