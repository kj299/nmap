description = "Workers that sleep and append; the script waits on a condition variable."
categories = {"net"}
local nmap = require "nmap"
local stdnse = require "stdnse"
prerule = function() return true end
action = function()
  local order = {}
  local done = 0
  local cv = nmap.condvar(order)
  for i, delay in ipairs({0.3, 0.1, 0.2}) do
    stdnse.new_thread(function()
      stdnse.sleep(delay)
      order[#order+1] = i
      done = done + 1
      cv "signal"
    end)
  end
  while done < 3 do cv "wait" end
  return "order " .. table.concat(order, " ")
end
