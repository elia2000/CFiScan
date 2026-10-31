#!/usr/bin/env python3
"""
Tiny speed-test server for CF-SCAN. Run it on YOUR VPS - the server behind your VLESS config.

CF-SCAN then measures download and upload through your tunnel against THIS server instead of a
third-party one (speed.cloudflare.com, Hetzner, ... may refuse or ignore requests from a VPS).
The only thing measured is then "your PC -> Cloudflare IP -> your VPS", which is exactly the part
that differs between Cloudflare IPs.

  python3 speedtest_server.py                       # 127.0.0.1:8080
  python3 speedtest_server.py --port 9000 --bind 0.0.0.0

Then, on your PC:
  python3 cf_ping.py subnets.txt -c "vless://..." --speed-test \\
      --down-url "http://127.0.0.1:8080/down?bytes={bytes}" --up-url "http://127.0.0.1:8080/up"

(127.0.0.1 is the VPS itself, because the VPS opens the connection. If your Xray config blocks
private addresses, bind to 0.0.0.0 and use the VPS's public IP in the URLs instead - and block
that port from outside in your firewall: the server answers anybody.)

Endpoints:  GET /down?bytes=N  -> N bytes (default 100 MB, at most 4 GB)
            POST /up           -> reads the body, answers "ok"
Standard library only, Python 3.8+, Windows and Linux.
"""
import argparse
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

MAX_BYTES = 4 * 1024 ** 3
CHUNK     = os.urandom(65536)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"          # keep-alive: CF-SCAN sends several requests per connection
    server_version   = "cf-scan-speedtest"

    def log_message(self, *args):          # quiet
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass                           # the scanner cuts downloads off at the end of its time window

    def _reply(self, code, body=b"ok\n"):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/down":
            try:
                n = int(parse_qs(url.query).get("bytes", ["100000000"])[0])
            except ValueError:
                return self._reply(400, b"bad bytes\n")
            n = max(0, min(n, MAX_BYTES))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(n))
            self.end_headers()
            while n > 0:
                part = min(n, len(CHUNK))
                self.wfile.write(CHUNK[:part])
                n -= part
        elif url.path == "/":
            self._reply(200, b"cf-scan speedtest server: GET /down?bytes=N, POST /up\n")
        else:
            self._reply(404, b"not found\n")

    def do_POST(self):
        if urlsplit(self.path).path != "/up":
            return self._reply(404, b"not found\n")
        left = int(self.headers.get("Content-Length") or 0)
        while left > 0:                    # answer only after the WHOLE body arrived: that is what is timed
            data = self.rfile.read(min(left, 65536))
            if not data:
                return
            left -= len(data)
        self._reply(200)


def main():
    ap = argparse.ArgumentParser(description="Speed-test server for CF-SCAN (run it on your VPS)")
    ap.add_argument("--bind", default="127.0.0.1", help="address to listen on (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080, help="port (default: 8080)")
    args = ap.parse_args()
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"speed-test server on http://{args.bind}:{args.port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
