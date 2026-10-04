description = "Runlevel 2: runs after s-dep-a."
categories = {"deps"}
dependencies = {"s-dep-a", "not-loaded"}
local nmap = require "nmap"
prerule = function() return true end
action = function()
  nmap.registry.dep_order = (nmap.registry.dep_order or "") .. "b"
  return "order " .. nmap.registry.dep_order
end
