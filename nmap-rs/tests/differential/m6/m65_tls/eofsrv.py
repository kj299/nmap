#!/usr/bin/env python3
"""How a TLS server ends a connection, for the end-of-stream rows of M6.5
step f1 (`io-*`). usage: eofsrv.py PORT CERT KEY MODE

Each connection: the handshake (Python's `ssl`, OpenSSL 3.0.13), then
"hello\\n"; then the server waits for one byte from the client, the trigger,
so that what follows reaches a client already waiting to read (7.94's
results depend on that order, and are deterministic with it). Then, by
MODE:

    abrupt[+data]      close TCP without a close_notify
    notify[+data]      send close_notify (`unwrap`), then close TCP
    notifyopen[+data]  send close_notify, keep TCP open for 20 s
    closer             (no handshake) accept and close at once; prints
                       nothing

`+data` sends "tail\\n" first, 200 ms before the end. Each connection prints one line: "done MODE",
or a line starting "noise:" for one that never reached TLS (a connect
scan)."""
import socket
import ssl
import sys
import threading
import time

port, crt, key, mode = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(crt, key)


def serve(c):
    if mode == "closer":
        c.close()
        return
    c.settimeout(10)
    try:
        s = ctx.wrap_socket(c, server_side=True)
    except Exception as e:  # noqa: BLE001 - a fixture reports
        print("noise:", e.__class__.__name__, flush=True)
        c.close()
        return
    try:
        s.sendall(b"hello\n")
        if s.recv(10) == b"":
            print("noise: closed before the trigger", flush=True)
            return
        how, _, data = mode.partition("+")
        if data:
            s.sendall(b"tail\n")
            # Apart from what follows: 7.94's result depends on whether the
            # data and the end arrive in one read event (two runs gave two
            # results for `abrupt+data`), so they never do here.
            time.sleep(0.2)
        if how == "abrupt":
            s.close()
        elif how == "notify":
            s.unwrap().close()
        elif how == "notifyopen":
            raw = s.unwrap()
            time.sleep(20)
            raw.close()
        print("done", mode, flush=True)
    except Exception as e:  # noqa: BLE001
        print("noise:", e.__class__.__name__, flush=True)


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(5)
print("listening", flush=True)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
