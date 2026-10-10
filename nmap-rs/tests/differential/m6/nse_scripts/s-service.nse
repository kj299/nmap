description = [[
What a script sees of a port's service name when no probe set one: the
nmap-services lookup, for each port the scenario scans, closed ones included.
C stores the entries the file names `unknown` with no name
(services.cc:228-232), so for 4/tcp a script sees nil, as nmapdb.getservbyport
gives, while nmap's own output prints `unknown`.

Then nmap.set_port_version with no name and a state that is not a match
("incomplete"): C falls back to the table (portlist.cc:337-341), which is
again `s_name`, so 4/tcp still has no name, with dtype "table" and conf 3.
]]
categories = {"service"}
local nmap = require "nmap"
hostrule = function(host) return true end
action = function(host)
  local out = {}
  for _, n in ipairs({1, 4, 46020}) do
    local p = nmap.get_port_state(host, {number = n, protocol = "tcp"})
    local v = p.version
    out[#out + 1] = ("%d/%s %s service=%s/%s name=%s/%s conf=%s dtype=%s nmapdb=%s"):format(
      p.number, p.protocol, p.state, tostring(p.service), type(p.service),
      tostring(v.name), type(v.name), tostring(v.name_confidence), tostring(v.service_dtype),
      tostring(nmapdb.getservbyport(p.number, p.protocol)))
  end
  for _, n in ipairs({1, 4}) do
    nmap.set_port_version(host, {number = n, protocol = "tcp", version = {}}, "incomplete")
    local v = nmap.get_port_state(host, {number = n, protocol = "tcp"}).version
    out[#out + 1] = ("set %d/tcp name=%s/%s conf=%s dtype=%s"):format(
      n, tostring(v.name), type(v.name), tostring(v.name_confidence), tostring(v.service_dtype))
  end
  return table.concat(out, "\n")
end
