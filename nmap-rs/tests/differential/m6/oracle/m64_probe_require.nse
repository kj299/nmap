description = "Probe: require every nselib library and record the outcome."
categories = {"safe"}
author = "probe"
prerule = function() return true end
action = function()
  local out = assert(io.open(nmap.registry.args.out, "w"))
  for name in io.lines(nmap.registry.args.libs) do
    local ok, err = pcall(require, name)
    if ok then
      out:write(name, "\tok\n")
    else
      out:write(name, "\terror\t", (tostring(err):gsub("\n", "\\n")), "\n")
    end
  end
  out:close()
  return "done"
end
