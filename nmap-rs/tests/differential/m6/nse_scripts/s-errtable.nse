description = "An action that raises a table."
categories = {"errors"}
hostrule = function(host) return true end
action = function(host) error({code = 1}) end
