description = "Spawns worker threads; they run after the script's own thread."
categories = {"workers"}
local nmap = require "nmap"
local stdnse = require "stdnse"
prerule = function() return true end
action = function()
  local _, info = stdnse.new_thread(function(x)
    nmap.registry.worker_ran = (nmap.registry.worker_ran or "") .. x
  end, "1")
  stdnse.new_thread(function() error("a worker's error is not output") end)
  stdnse.new_thread(function(a, b)
    nmap.registry.worker_ran = (nmap.registry.worker_ran or "") .. a .. b
  end, "2", "3")
  return "spawned, first is " .. info() .. ", isworker " .. tostring(stdnse.isworker())
end
