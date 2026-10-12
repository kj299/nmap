-- M6.6 step e DoS fixture: a result stored before the pathological LPeg work
-- of m66-expo-run.nse, which depends on this script, so it runs first
-- (runlevel 1). nse_exit_differential.rs requires it kept after the stall.
description = [[M6.6 step e DoS fixture: stores one result at once.]]
categories = {"m66dos"}
author = "nmap-rs differential"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
prerule = function() return true end
action = function() return "stored before the stall" end
