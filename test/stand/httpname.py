#!/usr/bin/env python3
"""Answers every HTTP GET with its own name: which network a request came through."""
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


HTTPServer(("0.0.0.0", 80), H).serve_forever()
