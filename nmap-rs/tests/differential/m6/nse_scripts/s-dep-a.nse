description = "Runlevel 1: leaves a value for s-dep-b."
categories = {"deps"}
local nmap = require "nmap"
prerule = function() return true end
action = function()
  nmap.registry.dep_order = (nmap.registry.dep_order or "") .. "a"
  return "a ran"
end
