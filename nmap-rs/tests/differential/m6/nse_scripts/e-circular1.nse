description = "Circular dependency, one side."
categories = {"circular"}
dependencies = {"e-circular2"}
prerule = function() return true end
action = function() return "x" end
