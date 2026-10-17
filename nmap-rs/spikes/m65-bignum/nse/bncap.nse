local openssl = require "openssl"
local stdnse = require "stdnse"

description = [[measurement spike: observe nmap's openssl.bignum_bin2bn at the OpenSSL cap boundary]]
author = "spike"
license = "measurement only"
categories = {"safe"}

prerule = function() return true end

action = function()
  local out = {}
  for _, n in ipairs({67108856, 67108857}) do
    local s = string.rep("\xff", n)
    local x = openssl.bignum_bin2bn(s)
    local hex = openssl.bignum_bn2hex(x)
    local prefix = (hex and hex:sub(1,16)) or "(nil)"
    local hexlen = (hex and #hex) or -1
    local iszero = (hex == "0" or hex == "00" or hexlen == 0) and "ZERO" or "nonzero"
    out[#out+1] = string.format("len=%d  bn2hex[1..16]=%q  #hex=%d  -> %s",
                                n, prefix, hexlen, iszero)
  end
  return "\n" .. table.concat(out, "\n")
end
