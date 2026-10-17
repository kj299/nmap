#!/usr/bin/env python3
"""A server that accepts and never speaks: the client must give up within its
own timeout (LESSONS #017's teardown criterion). usage: silent.py PORT"""
import socket
import sys
import time

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(5)
print("listening", flush=True)
while True:
    c, _ = srv.accept()
    time.sleep(30)
    c.close()
