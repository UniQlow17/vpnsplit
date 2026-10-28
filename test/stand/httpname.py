#!/usr/bin/env python3
"""Answers every HTTP GET with its own name: which network a request came through.
Listens on IPv4 and, where the namespace has IPv6, on IPv6 too (one dual-stack socket)."""
import socket
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

NAME = sys.argv[1]


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = NAME.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Dual(HTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


try:
    srv = Dual(("::", 80), H)
except OSError:
    srv = HTTPServer(("0.0.0.0", 80), H)
srv.serve_forever()
