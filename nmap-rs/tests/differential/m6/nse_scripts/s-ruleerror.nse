description = "A rule that raises."
categories = {"errors"}
hostrule = function(host) error("rule failed") end
action = function(host) return "never" end
