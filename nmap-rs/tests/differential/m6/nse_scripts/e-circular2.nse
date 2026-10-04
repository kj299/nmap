description = "Circular dependency, other side."
categories = {"circular"}
dependencies = {"e-circular1"}
prerule = function() return true end
action = function() return "x" end
