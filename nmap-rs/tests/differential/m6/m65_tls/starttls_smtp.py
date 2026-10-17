#!/usr/bin/env python3
"""An SMTP server that offers STARTTLS and upgrades through Python's `ssl`
(the system OpenSSL 3.0.13, as `s_server` would be; OpenSSL 3's `s_server`
has no `-starttls`), with the cipher list and version given; logs what each
client negotiated. usage: starttls_smtp.py PORT CERT KEY CIPHERS [tls12]

One line per connection. A connection that closes or resets before asking for
STARTTLS (a readiness check, a connect scan) prints a line starting "noise:";
one that asks prints "tls VERSION CIPHER" or "tls failed: REASON", which is
what the generator records.

Copied from spikes/m65-tls-provider/fixtures/starttls_smtp.py (M6.5 step 0)
for the oracle of step a; only the reporting changed."""
import socket
import ssl
import sys

port = int(sys.argv[1])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
ctx.set_ciphers(sys.argv[4])
if len(sys.argv) > 5 and sys.argv[5] == "tls12":
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(5)
print("listening", flush=True)


class Done(Exception):
    pass


while True:
    c, _ = srv.accept()
    c.settimeout(5)
    try:
        c.sendall(b"220 fixture ESMTP\r\n")
        buf = b""
        while True:
            d = c.recv(1024)
            if not d:
                print("noise: closed before STARTTLS", flush=True)
                break
            buf += d
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                u = line.upper()
                if u.startswith(b"EHLO") or u.startswith(b"HELO"):
                    c.sendall(b"250-fixture\r\n250 STARTTLS\r\n")
                elif u.startswith(b"STARTTLS"):
                    c.sendall(b"220 go ahead\r\n")
                    try:
                        t = ctx.wrap_socket(c, server_side=True)
                        print("tls", t.version(), t.cipher()[0], flush=True)
                        t.close()
                    except Exception as e:  # noqa: BLE001 - a fixture reports
                        print("tls failed:", getattr(e, "reason", None) or e.__class__.__name__, flush=True)
                    raise Done
                elif u.startswith(b"QUIT"):
                    c.sendall(b"221 bye\r\n")
                    raise Done
                else:
                    c.sendall(b"250 ok\r\n")
    except Done:
        pass
    except Exception as e:  # noqa: BLE001
        print("noise: error before STARTTLS:", e.__class__.__name__, flush=True)
    finally:
        c.close()
