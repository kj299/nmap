description = "Reading an undeclared global is an error (strict.lua)."
categories = {"errors"}
hostrule = function(host) return true end
action = function(host) return undeclared_global_variable end
