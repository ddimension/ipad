#!/usr/bin/env python3
"""A plain-HTTP server for test_http that answers and then keeps the
connection open for 10 s, as a load balancer that ignores `Connection:
close` would: /cl answers with Content-Length, /chunked in chunks, /close
without either (read to close, then it does close). Prints its port."""
import socket, sys, threading, time

def serve(c):
    data = b''
    while b'\r\n\r\n' not in data:
        d = c.recv(4096)
        if not d:
            return
        data += d
    head, _, body = data.partition(b'\r\n\r\n')
    clen = [int(l.split(b':')[1]) for l in head.split(b'\r\n') if l.lower().startswith(b'content-length:')]
    while clen and len(body) < clen[0]:
        body += c.recv(4096)
    path = head.split(b' ')[1]
    if path.endswith(b'/chunked'):
        c.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n')
    elif path.endswith(b'/close'):
        c.sendall(b'HTTP/1.1 200 OK\r\n\r\nok')
        c.close()
        return
    else:
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
    time.sleep(10)
    c.close()

s = socket.socket()
s.bind(('127.0.0.1', 0))
s.listen(4)
print(s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
