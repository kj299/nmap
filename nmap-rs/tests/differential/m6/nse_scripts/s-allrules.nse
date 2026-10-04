description = "All four rules: one thread per rule and target."
categories = {"rules"}
prerule = function() return true end
hostrule = function(host) return true end
portrule = function(host, port) return port.state == "open" end
postrule = function() return true end
action = function(host, port)
  return SCRIPT_TYPE .. " " .. SCRIPT_NAME .. (port and (" " .. port.number) or "")
end
