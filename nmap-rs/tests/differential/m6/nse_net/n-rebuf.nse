description = "close forgets what receive_buf had buffered."
categories = {"net"}
local nmap = require "nmap"
prerule = function() return true end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = tostring(t[i]) end return table.concat(t, ",") end
action = function()
  local out = {}
  local s = nmap.new_socket()
  s:connect("127.0.0.1", 46030)
  s:send("a|b|c")
  out[#out+1] = "first " .. show(s:receive_buf("|", false))
  out[#out+1] = "close " .. show(s:close())
  s:connect("127.0.0.1", 46030)
  s:send("x|")
  out[#out+1] = "after " .. show(s:receive_buf("|", false))
  s:close()
  return table.concat(out, "\n")
end
