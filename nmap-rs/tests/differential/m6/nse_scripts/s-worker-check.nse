description = "Reads what s-worker's threads left, after the pre-scan."
categories = {"workers"}
local nmap = require "nmap"
postrule = function() return true end
action = function() return "workers left " .. tostring(nmap.registry.worker_ran) end
