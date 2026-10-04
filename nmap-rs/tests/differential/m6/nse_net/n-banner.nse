description = "TCP: a server that writes and closes."
categories = {"net"}
local nmap = require "nmap"
prerule = function() return true end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = tostring(t[i]) end return table.concat(t, ",") end
action = function()
  local out = {}
  local s = nmap.new_socket()
  s:set_timeout(2000)
  out[#out+1] = "connect " .. show(s:connect("127.0.0.1", 46031, "tcp"))
  out[#out+1] = "buf1 " .. show(s:receive_buf("\n", false))
  out[#out+1] = "buf2 " .. show(s:receive_buf("\r?\n", true))
  out[#out+1] = "buf3 " .. show(s:receive_buf(function(b) return b:find("ne") end, true))
  out[#out+1] = "buf4 " .. show(s:receive_buf("\n", false))
  out[#out+1] = "receive " .. show(s:receive())
  out[#out+1] = "receive " .. show(s:receive())
  s:close()
  return table.concat(out, "\n")
end
