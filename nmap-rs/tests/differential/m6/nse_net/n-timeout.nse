description = "TCP: timeouts on a silent server; set_timeout's checks."
categories = {"net"}
local nmap = require "nmap"
prerule = function() return true end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = tostring(t[i]) end return table.concat(t, ",") end
action = function()
  local out = {}
  local s = nmap.new_socket()
  out[#out+1] = "set " .. show(s:set_timeout(300))
  out[#out+1] = "connect " .. show(s:connect("127.0.0.1", 46032))
  out[#out+1] = "receive " .. show(s:receive())
  out[#out+1] = "lines " .. show(s:receive_lines(1))
  out[#out+1] = "bytes " .. show(s:receive_bytes(1))
  out[#out+1] = "buf " .. show(s:receive_buf("\n", true))
  -- nmap formats this int with %f (undefined behaviour): only the start of
  -- the message is stable.
  local ok, e = pcall(s.set_timeout, s, -2)
  out[#out+1] = "negative " .. show(ok, (e:match("^Negative timeout: ")))
  out[#out+1] = "fraction " .. show(s:set_timeout(250.9))
  out[#out+1] = "none " .. show(s:set_timeout(-1))
  s:close()
  return table.concat(out, "\n")
end
