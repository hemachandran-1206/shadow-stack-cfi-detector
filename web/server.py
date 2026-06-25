#!/usr/bin/env python3
"""
server.py — Shadow CFI Dashboard Server
Serves dashboard.html and cfi_report.json on localhost:9090
Usage: python3 server.py
"""

import http.server
import socketserver
import os
import sys

PORT = 9090
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, fmt, *args):
        print(f"  [{self.log_date_time_string()}] {fmt % args}")

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

print(f"""
╔══════════════════════════════════════════╗
║       Shadow CFI Dashboard Server       ║
╠══════════════════════════════════════════╣
║  http://localhost:{PORT}                    ║
║  Serving from: {os.path.basename(DIRECTORY):<26}║
║  Press Ctrl+C to stop                   ║
╚══════════════════════════════════════════╝
""")

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
        sys.exit(0)
