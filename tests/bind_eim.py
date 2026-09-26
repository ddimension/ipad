#!/usr/bin/env python3
"""A stand-in eIM for test_cli's bundle flow, plain HTTP on 127.0.0.1:
POST /ipad/v1/bind answers the next status from argv (the last one repeats;
429:<n> adds Retry-After: <n>) and stores each body as <dir>/bind.<n>; ESipa (/gsma/rsp2/asn1) answers
GetEimPackage with noEimPackageAvailable and anything else with 204.
Prints the port it listens on."""
import http.server, sys

out, statuses = sys.argv[1], sys.argv[2].split(',')
n = 0

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def reply(self, st, body=b'', ctype=None, retry=None):
        self.send_response(st)
        if retry:
            self.send_header('Retry-After', retry)
        if ctype:
            self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        global n
        body = self.rfile.read(int(self.headers['Content-Length']))
        if self.path == '/ipad/v1/bind':
            st, _, retry = statuses[min(n, len(statuses) - 1)].partition(':')
            n += 1
            with open('%s/bind.%d' % (out, n), 'wb') as f:
                f.write(body)
            self.reply(int(st), retry=retry or None)
        elif body[:2] == b'\xbf\x4f':
            self.reply(200, b'\xbf\x4f\x03\x02\x01\x01', 'application/x-gsma-rsp-asn1')
        else:
            self.reply(204)
    def log_message(self, *a):
        pass

srv = http.server.HTTPServer(('127.0.0.1', 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
