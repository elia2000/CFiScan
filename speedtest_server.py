#!/usr/bin/env python3
"""
Tiny speed-test server for CF-SCAN. Run it on YOUR VPS - the server behind your VLESS config.

CF-SCAN then measures download and upload through your tunnel against THIS server instead of a
third-party one (speed.cloudflare.com, Hetzner, ... may refuse or ignore requests from a VPS).
The only thing measured is then "your PC -> Cloudflare IP -> your VPS", which is exactly the part
that differs between Cloudflare IPs.

  python3 speedtest_server.py

It needs no root and does NOT touch your panel / Xray: it is a separate little program that only
needs a free port. It tries 8080 and, if something (x-ui, ...) already uses it, picks a free port
itself - then prints the exact scanner options to use. Leave it running while the scanner runs.

Use your VPS's PUBLIC IP in the scanner's URLs, not 127.0.0.1: the VPS opens the connection, and
many Xray servers (3x-ui by default) BLOCK private/loopback destinations, so 127.0.0.1 gets "closed
the connection without answering". Listening on all addresses is safe because the server answers
ONLY connections made from the VPS itself (that is where Xray connects from); everybody else gets
"403 local clients only". Use --allow-any if Xray runs somewhere else (e.g. in Docker with its own
network) and the connections seem to come from another address.

Endpoints:  GET /down?bytes=N  -> N bytes (default 100 MB, at most 4 GB)
            POST /up           -> reads the body, answers "ok"
Standard library only, Python 3.8+, Windows and Linux.
"""
import argparse
import errno
import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

DEFAULT_PORT = 8080
MAX_BYTES    = 4 * 1024 ** 3
CHUNK        = os.urandom(65536)
OPTS         = {"allow_any": False, "quiet": False, "connections": 0}


def log(msg):
    if not OPTS["quiet"]:
        print(time.strftime("%H:%M:%S ") + msg, flush=True)


def plain(addr):
    return addr[7:] if addr.startswith("::ffff:") else addr       # IPv4-mapped IPv6 -> IPv4


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"          # keep-alive: CF-SCAN sends several requests per connection
    server_version   = "cf-scan-speedtest"

    def log_message(self, *args):          # the default per-request log line is too noisy; see setup()
        pass

    def setup(self):
        super().setup()
        OPTS["connections"] += 1
        n = OPTS["connections"]
        if n <= 10 or n % 50 == 0:         # the first few prove "the tunnel reaches me"; then only a heartbeat
            log(f"connection #{n} from {self.client_address[0]}")

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass                           # the scanner cuts downloads off at the end of its time window

    def _local(self):
        """Only the VPS itself (where Xray connects from) may use this server."""
        if OPTS["allow_any"]:
            return True
        peer, here = plain(self.client_address[0]), plain(self.connection.getsockname()[0])
        try:
            return peer == here or ipaddress.ip_address(peer).is_loopback
        except ValueError:
            return False

    def _reply(self, code, body=b"ok\n"):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _allowed(self):
        if self._local():
            return True
        log(f"refused {self.client_address[0]}: not a local client (use --allow-any if this is your Xray)")
        self._reply(403, b"local clients only\n")
        return False

    def do_GET(self):
        if not self._allowed():
            return
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
        if not self._allowed():
            return
        if urlsplit(self.path).path != "/up":
            return self._reply(404, b"not found\n")
        left = int(self.headers.get("Content-Length") or 0)
        while left > 0:                    # answer only after the WHOLE body arrived: that is what is timed
            data = self.rfile.read(min(left, 65536))
            if not data:
                return
            left -= len(data)
        self._reply(200)


class Server(ThreadingHTTPServer):
    daemon_threads = True


def make_server(bind, port):
    Server.address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    return Server((bind, port), Handler)


def port_owner(port):
    """Who listens on this port? (best effort: Linux `ss`; needs root to see other users' programs)"""
    try:
        out = subprocess.run(["ss", "-H", "-ltnp", f"sport = :{port}"], capture_output=True, text=True,
                             timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', out)
    return f"{m.group(1)} (pid {m.group(2)})" if m else None


def free_port(bind):
    """A port that is free right now (the OS picks it)."""
    with socket.socket(socket.AF_INET6 if ":" in bind else socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((bind, 0))
        return s.getsockname()[1]


def local_ip():
    """This machine's main IPv4 address (a UDP 'connect' sends nothing; it only picks the route)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Speed-test server for CF-SCAN (run it on your VPS)")
    ap.add_argument("--bind", default="0.0.0.0", help="address to listen on (default: 0.0.0.0 = all; '::' for IPv6)")
    ap.add_argument("--port", type=int, default=None,
                    help=f"port (default: {DEFAULT_PORT}, or a free one if that is taken; below 1024 needs root)")
    ap.add_argument("--allow-any", action="store_true", help="also answer connections that do not come from this machine")
    ap.add_argument("--quiet", action="store_true", help="no log lines")
    args = ap.parse_args()
    OPTS["allow_any"], OPTS["quiet"] = args.allow_any, args.quiet

    explicit = args.port is not None
    port     = args.port if explicit else DEFAULT_PORT
    try:
        srv = make_server(args.bind, port)
    except PermissionError:
        sys.exit(f"cannot listen on port {port}: ports below 1024 need root. Leave --port out (a free port is chosen).")
    except OSError as e:
        if e.errno not in (errno.EADDRINUSE, 10048):                 # 10048 = WSAEADDRINUSE on Windows
            sys.exit(f"cannot listen on {args.bind}:{port}: {e}")
        owner = port_owner(port)
        used  = f"port {port} is already used by {owner}" if owner else f"port {port} is already in use"
        if explicit:
            sys.exit(f"{used}.\nNo need to stop it: any other free port works - e.g. --port {free_port(args.bind)} "
                     f"(free right now) - or leave --port out and a free one is chosen for you.")
        print(f"{used} (your panel / Xray?) - leaving it alone and choosing a free port instead", flush=True)
        srv = make_server(args.bind, 0)
    port = srv.server_address[1]

    who = "any client" if args.allow_any else "connections made from this machine only"
    ip  = local_ip()
    shown = ip or "VPS_IP"
    print(f"speed-test server listening on {args.bind}:{port} - answers {who}", flush=True)
    print(f'scanner:  --down-url "http://{shown}:{port}/down?bytes={{bytes}}" --up-url "http://{shown}:{port}/up"', flush=True)
    if not ip:
        print("          (replace VPS_IP with this server's public IP)", flush=True)
    elif ipaddress.ip_address(ip).is_private:
        print(f"          ({ip} is a private address - this machine is behind NAT: use its PUBLIC IP instead)", flush=True)
    else:
        print("          (if that IP is not your VPS's public IP, use the public one)", flush=True)
    print("waiting for the scanner... (Ctrl+C to stop)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
