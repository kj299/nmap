#!/usr/bin/env python3
"""A server that accepts and never speaks: the client must give up within its
own timeout (LESSONS #017's teardown criterion). Each connection is held 30 s
on a thread of its own, so a readiness check or a connect scan in front of the
client under test does not delay its accept. usage: silent.py PORT

Each connection the client ends within the 30 s (a FIN or a RST) prints
"client closed" (step f1: the teardown rows hold the port to closing what
7.94 closes, a connect scan's probe included).

Copied from spikes/m65-tls-provider/fixtures/silent.py (M6.5 step 0) for the
oracle of step a; the thread per connection is new."""
import socket
import sys
import threading


def hold(c):
    c.settimeout(30)
    try:
        while True:
            d = c.recv(4096)
            if not d:
                print("client closed", flush=True)
                break
    except ConnectionResetError:
        print("client closed", flush=True)
    except OSError:
        pass
    c.close()


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(5)
print("listening", flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=hold, args=(c,), daemon=True).start()
