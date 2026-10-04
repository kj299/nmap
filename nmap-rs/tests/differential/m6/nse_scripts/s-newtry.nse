description = "nmap.new_try's exception ends the script quietly."
categories = {"errors"}
local nmap = require "nmap"
hostrule = function(host) return true end
action = function(host)
  local try = nmap.new_try()
  try(nil, "TIMEOUT")
  return "never"
end
