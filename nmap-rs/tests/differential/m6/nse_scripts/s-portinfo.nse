description = "What a portrule sees of its port."
categories = {"rules"}
portrule = function(host, port) return true end
action = function(host, port)
  return ("%d/%s %s %s"):format(port.number, port.protocol, port.state, port.reason)
end
