#!/usr/bin/env python3
"""A stand-in eIM endpoint for test_http: HTTPS on 127.0.0.1:<port> (or the
address given after the key), answers a
POST with its own body behind a marker, and reports the two ESipa headers it
saw. Chunked when the path asks for it; /host answers with the Host field."""
import http.server, socket, ssl, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        out = b'echo:' + self.headers.get('Content-Type', '').encode() + b'|' + \
              self.headers.get('X-Admin-Protocol', '').encode() + b'|' + body
        if self.path.endswith('host'):
            out = self.headers.get('Host', '').encode()
        self.send_response(200)
        if self.path.endswith('chunked'):
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            for i in range(0, len(out), 7):
                c = out[i:i + 7]
                self.wfile.write(b'%x\r\n%s\r\n' % (len(c), c))
            self.wfile.write(b'0\r\n\r\n')
        else:
            self.send_header('Content-Length', str(len(out)))
            self.end_headers()
            self.wfile.write(out)
    def log_message(self, *a):
        pass

class H6(http.server.HTTPServer):
    address_family = socket.AF_INET6

port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
host = sys.argv[4] if len(sys.argv) > 4 else '127.0.0.1'
srv = (H6 if ':' in host else http.server.HTTPServer)((host, port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print('ready', flush=True)
srv.serve_forever()
