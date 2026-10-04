description = "signal wakes one waiter at a time, the last to wait first."
categories = {"net"}
local nmap = require "nmap"
local stdnse = require "stdnse"
prerule = function() return true end
action = function()
  local woke = {}
  local key = {}
  local cv = nmap.condvar(key)
  for i = 1, 3 do
    stdnse.new_thread(function()
      stdnse.sleep(0.1 * i)
      cv "wait"
      woke[#woke+1] = i
    end)
  end
  stdnse.sleep(0.5)
  for _ = 1, 3 do
    cv "signal"
    stdnse.sleep(0.1)
  end
  cv "broadcast"
  return "woke " .. table.concat(woke, " ")
end
