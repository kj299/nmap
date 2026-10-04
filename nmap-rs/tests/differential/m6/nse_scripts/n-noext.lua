description = "A script without the .nse extension: a warning, then it runs."
categories = {"named"}
prerule = function() return true end
action = function() return "no extension" end
