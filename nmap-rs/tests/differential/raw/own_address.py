#!/usr/bin/env python3
"""Print this host's own non-loopback IPv4 address: the source of a route to
TEST-NET-2 (198.51.100.0/24), which is where an outbound packet leaves from.
connect() on a datagram socket only consults the routing table; nothing is
sent."""
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("198.51.100.1", 9))
print(s.getsockname()[0])
