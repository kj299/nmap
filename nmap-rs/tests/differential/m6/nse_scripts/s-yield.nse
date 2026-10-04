description = "A script that yields on its own cannot be resumed."
categories = {"errors"}
hostrule = function(host) return true end
action = function(host) coroutine.yield(1) return "never" end
