description = "More threads hold sockets than the parallelism limit; those over it wait to connect."
categories = {"net"}
local nmap = require "nmap"
local stdnse = require "stdnse"
prerule = function() return true end
action = function()
  local ok, done = 0, 0
  local cv = nmap.condvar(stdnse)
  for i = 1, 25 do
    stdnse.new_thread(function()
      local s = nmap.new_socket()
      if s:connect("127.0.0.1", 46030) and s:send("x\n") and s:receive() then ok = ok + 1 end
      stdnse.sleep(0.05)
      -- Half the workers leave their socket open; it is closed when they end.
      if i % 2 == 0 then s:close() end
      done = done + 1
      cv "signal"
    end)
  end
  while done < 25 do cv "wait" end
  return "ok " .. ok
end
