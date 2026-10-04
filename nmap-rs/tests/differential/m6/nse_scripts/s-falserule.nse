description = "A rule that declines; runs only when forced."
categories = {"forceme"}
hostrule = function(host) return false end
action = function(host) return "ran anyway" end
