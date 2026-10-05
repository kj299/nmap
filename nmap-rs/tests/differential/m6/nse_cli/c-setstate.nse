description = "Marks an open port closed with nmap.set_port_state: the scan's report shows the new state."
categories = {"cli"}
local nmap = require "nmap"
portrule = function(host, port) return port.number == 46021 and port.state == "open" end
action = function(host, port)
  nmap.set_port_state(host, port, "closed")
  return "marked " .. port.number .. " closed"
end
