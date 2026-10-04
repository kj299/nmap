description = "A number and a float, as structured output."
categories = {"shapes"}
portrule = function(host, port) return port.number == 46020 end
action = function(host, port) return 42 end
hostrule = function(host) return true end
