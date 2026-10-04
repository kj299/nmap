description = "An action that raises."
categories = {"errors"}
hostrule = function(host) return true end
action = function(host) error("action failed") end
