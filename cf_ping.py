#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   CF-SCAN  ·  Cloudflare IP Scanner  ·  Config Edition       ║
║   Tests your actual VLESS/WS config against each IP          ║
╚══════════════════════════════════════════════════════════════╝

Windows + Linux (+ macOS), Python 3.8+, standard library only.

Every "good" IP is verified by opening a REAL VLESS-over-WebSocket tunnel with
your config (same SNI / Host / path as V2rayN) and fetching data through it.
Speed tests (download AND upload) run inside that same tunnel, so the numbers
are what V2rayN will actually give you - not the raw speed of the Cloudflare
edge, which is what made the old versions report "10 Mbps" for IPs that
delivered 0.0 MB/s in V2rayN.

Usage:
  python3 cf_ping.py subnets.txt [OPTIONS]          (Windows: python cf_ping.py ...)

Scan options:
  -c, --config    vless:// URI  -> real tunnel test (BEST, needed for speed tests)
  -s, --sni       Domain for TLS-only test (no config needed)
  -t, --threads   Parallel threads          (default: 50)
  -w, --wait      Timeout in seconds        (default: 3.0)
  -p, --port      Port override             (default: from config or 443)
  -o, --output    Results JSON file         (default: cf_results.json)
  -r, --resume    Resume/progress file      (default: cf_progress.json)
  --ping-only     ICMP ping only
  --tls13-only    Save only TLS 1.3 IPs (needs --sni)
  --no-verify     Only check the WebSocket 101 handshake (fast, but many of
                   those IPs do NOT carry traffic - not recommended)
  --verify-url    URL fetched THROUGH the tunnel to verify every hit
                   (default: https://cp.cloudflare.com/generate_204)

Speed-test options (need -c):
  --speed-test    Every --speed-limit tunnel-verified hits, PAUSE the scan, measure
                   real download + upload through the tunnel, then RESUME
  --speed-limit   Hits per speed-test batch                   (default: 20)
  --speed-time    Seconds per download / upload measurement   (default: 5)
  --min-download  Reject IPs below this download Mbps         (default: 2)
  --min-upload    Reject IPs below this upload Mbps           (default: 1)
  --no-upload     Skip the upload test
  --speed-threads Parallel speed tests. Keep 1 for honest numbers - parallel
                   tests share your bandwidth                 (default: 1)
  --want N        Stop everything as soon as N IPs passed (default: 0 = scan all)
  --sort          download | upload | delay                   (default: download)
  --loss-count    ICMP pings per IP for packet loss, 0 = off  (default: 0)
  --down-url      Force ONE download URL ({bytes} = request size the script picks).
                   Default: automatic - the first of Cloudflare's speed server and a few
                   public test files that your server can really reach
  --up-url        Force ONE upload URL (must accept POST bodies). Default: automatic

A quick parallel screen drops dead/throttled IPs first, hopeless IPs are dropped early
(a few seconds), only IPs that pass the download
test get the upload test, and rejected IPs never reach the result list.

Examples:
  # Scan with your real config, verified through the tunnel:
  python3 cf_ping.py subnets.txt -c "vless://UUID@your.domain.com:443?type=ws&security=tls&path=%2Fxyz&host=your.domain.com&sni=your.domain.com" -t 100

  # + real download/upload test, stop after 10 good IPs:
  python3 cf_ping.py subnets.txt -c "vless://..." -t 100 --speed-test --want 10

  # TLS only:
  python3 cf_ping.py subnets.txt -s yourdomain.com
"""

import sys, os, json, time, random, signal, argparse, re
import ipaddress, shutil, subprocess, threading, ssl, socket
import urllib.parse, base64, hashlib, struct, uuid
from datetime import datetime, timedelta
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

VERSION = "4.0"
IS_WIN  = os.name == "nt"
now     = time.perf_counter

# ─── ANSI Colors ─────────────────────────────────────────────────────────────
R   = "\033[0m";  B   = "\033[1m";  DIM = "\033[2m"
CW  = "\033[97m"; CY  = "\033[93m"; CG  = "\033[92m"
CR  = "\033[91m"; CC  = "\033[96m"; CM  = "\033[95m"
CB  = "\033[94m"; CGR = "\033[90m"
HIDE_CURSOR = "\033[?25l"; SHOW_CURSOR = "\033[?25h"
CLEAR = "\033[2J\033[H"

def clr(text, *codes): return "".join(codes) + str(text) + R

def setup_console():
    """UTF-8 output + ANSI escape support, so the same UI works on Windows and Linux."""
    for s in (sys.stdout, sys.stderr):
        try: s.reconfigure(encoding="utf-8", errors="replace")
        except Exception: pass
    if IS_WIN:
        try:
            import ctypes
            k32  = ctypes.windll.kernel32
            h    = k32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(h, ctypes.byref(mode)):
                k32.SetConsoleMode(h, mode.value | 0x0004)   # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            os.system("")   # older trick that also switches the console to VT mode

def clear_screen():
    sys.stdout.write(CLEAR); sys.stdout.flush()

BANNER = (
    f"\n{CY}{B}╔══════════════════════════════════════════════════════════════╗{R}\n"
    f"{CY}{B}║  {CC}⚡ CF-SCAN  {CGR}·  {CW}Cloudflare IP Scanner  {CGR}·  {CM}Config Edition{CY}{B}     ║{R}\n"
    f"{CY}{B}╚══════════════════════════════════════════════════════════════╝{R}\n"
)

# ─── Constants ────────────────────────────────────────────────────────────────
VERIFY_URL   = "https://cp.cloudflare.com/generate_204"           # scan-stage check, light enough for thousands of hits
# Speed-test servers, tried in this order (once per run, through the tunnel) until one answers.
# {bytes} in a URL = request size chosen by the script; other URLs are plain files.
DOWN_URLS    = ["https://speed.cloudflare.com/__down?bytes={bytes}",
                "https://speed.hetzner.de/100MB.bin",
                "https://cachefly.cachefly.net/100mb.test",
                "http://speedtest.tele2.net/100MB.zip",
                "https://proof.ovh.net/files/100Mb.dat"]
UP_URLS      = ["https://speed.cloudflare.com/__up",
                "http://speedtest.tele2.net/upload.php"]
UA           = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
WS_GUID      = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_FRAME     = 16384                    # max WebSocket payload per frame we send
DOWN_FIRST, DOWN_FLOOR, DOWN_MAX, DOWN_TARGET = 2_000_000, 1_000_000, 100_000_000, 1.5   # download request size / target secs
PROBE_SECS   = 2.5                      # after this long, speeds below half the minimum are aborted
STALL_SECS   = 4.0                      # no data for this long during a transfer = dead
UP_MIN, UP_MAX, UP_TARGET = 64 * 1024, 4 * 1024 * 1024, 1.5   # upload request size / target secs
PRESCREEN_THREADS, PRESCREEN_BYTES, PRESCREEN_SECS, PRESCREEN_MIN = 8, 64 * 1024, 4.0, 3   # quick screen before the speed test
UPLOAD_GIVEUP = 3                       # IPs in a row whose upload stalled everywhere -> upload switched off
SAVE_EVERY_S = 15                       # progress/result autosave interval
_UP_BODY     = os.urandom(UP_MAX)

# ─── Global State ─────────────────────────────────────────────────────────────
stats = {
    "total": 0, "processed": 0, "base": 0,
    "ws_ok": 0, "tls13": 0, "tls12": 0, "tcp_only": 0, "dead": 0, "tunnel_dead": 0,
    "untested": 0, "passed": 0, "slow": 0, "failed": 0,
    "start_time": None, "paused": 0.0, "lock": threading.Lock(),
}
alive_ips    = []
alive_lock   = threading.Lock()
log_buffer   = []
LOG_MAXLEN   = 14
log_lock     = threading.Lock()
shutdown     = threading.Event()      # Ctrl+C
want_reached = threading.Event()      # --want N satisfied
host_refuses = threading.Event()      # no download test server answers
refusal_lock = threading.Lock()       # guards host_refuses / stop_notes
stop_notes   = []                     # why the run stopped early; printed again in the final summary
upload_lock  = threading.Lock()
upload_state = {"streak": [], "worked": False, "rej": 0, "hinted": False}
done_ips_set = set()
done_lock    = threading.Lock()
last_save    = 0.0
print_lock   = threading.Lock()

# ─── VLESS URI Parser ─────────────────────────────────────────────────────────
def parse_vless(uri):
    """
    Parse vless://uuid@host:port?params#name
    Returns dict with all fields needed for the tunnel test, or None.
    """
    uri = uri.strip()
    if not uri.startswith("vless://"):
        print(f"{CR}  Config must start with vless://{R}")
        return None
    try:
        rest     = uri[8:]
        fragment = ""
        if "#" in rest:
            rest, fragment = rest.rsplit("#", 1)
        query = ""
        if "?" in rest:
            rest, query = rest.split("?", 1)
        user, hostport = rest.rsplit("@", 1)
        if hostport.startswith("["):                       # [ipv6]:port
            host, _, tail = hostport[1:].partition("]")
            port = int(tail[1:]) if tail.startswith(":") else 443
        elif ":" in hostport:
            host, port = hostport.rsplit(":", 1)
            port = int(port)
        else:
            host, port = hostport, 443
        params = dict(urllib.parse.parse_qsl(query))      # values are already percent-decoded
        cfg = {
            "uuid":       user,
            "uuid_bytes": uuid.UUID(user).bytes,
            "host":       host,
            "port":       port,
            "type":       params.get("type", "tcp"),
            "path":       params.get("path", "/") or "/",
            "ws_host":    params.get("host") or host,       # Host header
            "sni":        params.get("sni") or params.get("host") or host,
            "security":   params.get("security", "none"),
            "alpn":       params.get("alpn", ""),
            "fp":         params.get("fp", ""),
            "name":       urllib.parse.unquote(fragment),
        }
    except Exception as e:
        print(f"{CR}  Failed to parse vless URI: {e}{R}")
        return None
    if cfg["type"] != "ws":
        print(f"{CR}  Only WebSocket configs are supported (type=ws), got type={cfg['type']}{R}")
        return None
    if cfg["security"] not in ("tls", "none"):
        print(f"{CR}  Only security=tls or security=none can be tested, got {cfg['security']}{R}")
        return None
    return cfg

# ─── Real tunnel: VLESS over WebSocket (what V2rayN / Xray open for your config) ─
class TunnelError(Exception):
    """A step of the real tunnel failed; the message is shown in the log."""

class TooSlow(TunnelError):
    def __init__(self, mbps):
        super().__init__(f"too slow ({mbps:.2f} Mbps)")
        self.mbps = mbps

class Refused(TunnelError):
    """The test server itself answered with an error (HTTP status) - the same for every edge IP."""

def _note(e):
    if isinstance(e, TunnelError):         return str(e)
    if isinstance(e, socket.timeout):      return "timeout"
    if isinstance(e, ConnectionRefusedError): return "refused"
    if isinstance(e, ssl.SSLError):        return f"TLS: {getattr(e, 'reason', None) or e}"[:40]
    return (str(e) or type(e).__name__)[:40]

def mbps(nbytes, secs):
    return nbytes * 8 / max(secs, 1e-6) / 1_000_000

class VlessWS:
    """
    One connection to <ip>:<port> carrying VLESS inside a WebSocket (inside TLS when
    security=tls), using the SNI / Host / path / UUID of the user's config.
    connect() performs TCP + TLS + WebSocket upgrade; set_dest() + send()/recv() then
    carry a byte stream to dest_host:dest_port through the proxy server.
    """
    def __init__(self, ip, cfg, timeout):
        self.ip, self.cfg, self.timeout = ip, cfg, timeout
        self.sock    = None
        self.tls     = None          # "1.3" / "1.2" of the TLS session to the edge
        self.ws_ms   = None          # TCP + TLS + WS upgrade time
        self._rbuf   = bytearray()   # raw bytes read from the socket
        self._hdr    = None          # VLESS request header, prepended to the first send()
        self._resp   = bytearray()   # VLESS response header being collected
        self._resp_done = False

    # -- setup -----------------------------------------------------------------
    def connect(self):
        cfg = self.cfg
        t0  = now()
        raw = socket.create_connection((self.ip, cfg["port"]), timeout=self.timeout)
        raw.settimeout(self.timeout)
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if cfg["security"] == "tls":
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname  = False
                ctx.verify_mode     = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                try: ctx.set_alpn_protocols(["http/1.1"])   # WebSocket upgrade is HTTP/1.1
                except NotImplementedError: pass
                self.sock = ctx.wrap_socket(raw, server_hostname=cfg["sni"] or None)
                v = self.sock.version() or ""
                self.tls = {"TLSv1.3": "1.3", "TLSv1.2": "1.2"}.get(v, v)
            else:
                self.sock = raw

            key = base64.b64encode(os.urandom(16)).decode()
            self.sock.sendall((
                f"GET {cfg['path']} HTTP/1.1\r\n"
                f"Host: {cfg['ws_host']}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"User-Agent: {UA}\r\n\r\n").encode())

            lines = self._read_head().split("\r\n")
            parts = lines[0].split(" ", 2)
            code  = parts[1] if len(parts) > 1 and parts[1].isdigit() else "???"
            if code != "101":                      # 200 etc. is NOT a working WebSocket
                hint = {"400": " (wrong path/config?)", "404": " (wrong path/config?)",
                        "403": " (CF blocking)"}.get(code, "")
                raise TunnelError(f"HTTP {code}{hint}")
            hdrs   = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
            expect = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            if hdrs.get("sec-websocket-accept") != expect:
                raise TunnelError("fake WS 101 (bad accept key)")
        except BaseException:
            self.close(); raw.close(); raise
        self.ws_ms = round((now() - t0) * 1000, 1)

    def _read_head(self):
        buf = self._rbuf
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise TunnelError("closed during WS handshake")
            buf += chunk
            if len(buf) > 16384:
                raise TunnelError("bad HTTP reply")
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        self._rbuf = bytearray(rest)
        return head.decode("latin-1")

    def set_dest(self, host, port):
        """Destination the proxy server should connect to (sent with the first payload)."""
        h = host.encode("ascii")
        self._hdr = (b"\x00" + self.cfg["uuid_bytes"] + b"\x00"      # version, UUID, no addons
                     + b"\x01" + struct.pack(">H", port)             # command TCP, port
                     + b"\x02" + bytes([len(h)]) + h)                # address type domain

    # -- WebSocket framing -----------------------------------------------------
    @staticmethod
    def _frame(payload, opcode=0x2):
        n, key = len(payload), os.urandom(4)
        if   n < 126:   head = struct.pack(">BB",  0x80 | opcode, 0x80 | n)
        elif n < 65536: head = struct.pack(">BBH", 0x80 | opcode, 0x80 | 126, n)
        else:           head = struct.pack(">BBQ", 0x80 | opcode, 0x80 | 127, n)
        mask   = (key * (n // 4 + 1))[:n]
        masked = (int.from_bytes(payload, "little") ^ int.from_bytes(mask, "little")).to_bytes(n, "little")
        return head + key + masked

    def _need(self, n):
        buf = self._rbuf
        while len(buf) < n:
            chunk = self.sock.recv(max(65536, n - len(buf)))
            if not chunk:
                raise EOFError
            buf += chunk
        out = bytes(buf[:n]); del buf[:n]
        return out

    def _read_ws(self):
        """Next data-frame payload from the server, None when it closed."""
        try:
            while True:
                b0, b1 = self._need(2)
                op, n  = b0 & 0x0F, b1 & 0x7F
                if   n == 126: n = struct.unpack(">H", self._need(2))[0]
                elif n == 127: n = struct.unpack(">Q", self._need(8))[0]
                key     = self._need(4) if b1 & 0x80 else None     # servers normally don't mask
                payload = self._need(n)
                if key:
                    mask    = (key * (n // 4 + 1))[:n]
                    payload = (int.from_bytes(payload, "little") ^ int.from_bytes(mask, "little")).to_bytes(n, "little")
                if op in (0x0, 0x1, 0x2): return payload
                if op == 0x8:             return None
                if op == 0x9:             self.sock.sendall(self._frame(payload, 0xA))
        except EOFError:
            return None

    # -- byte stream through the tunnel ----------------------------------------
    def send(self, data):
        if self._hdr:
            data, self._hdr = self._hdr + data, None
        for i in range(0, len(data), WS_FRAME):
            self.sock.sendall(self._frame(data[i:i + WS_FRAME]))

    def recv(self):
        """Next chunk of tunnel data (b'' when closed); strips the VLESS response header."""
        while True:
            data = self._read_ws()
            if data is None:
                return b""
            if not data:
                continue
            if not self._resp_done:
                self._resp += data
                if len(self._resp) < 2:
                    continue
                need = 2 + self._resp[1]
                if len(self._resp) < need:
                    continue
                if self._resp[0] != 0:
                    raise TunnelError("bad VLESS reply")
                data, self._resp, self._resp_done = bytes(self._resp[need:]), None, True
                if not data:
                    continue
            return data

    def close(self):
        try:
            if self.sock: self.sock.close()
        except Exception:
            pass

class TunnelTLS:
    """TLS to the real destination (e.g. speed.cloudflare.com) carried INSIDE the tunnel."""
    def __init__(self, tunnel, hostname):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        try: ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError: pass
        self.t    = tunnel
        self._in  = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._ssl = ctx.wrap_bio(self._in, self._out, server_hostname=hostname)
        self._eof = False

    def _run(self, fn, *a):
        while True:
            try:
                res = fn(*a)
            except ssl.SSLWantReadError:
                self._flush()
                if self._eof:
                    raise ssl.SSLEOFError("tunnel closed")
                data = self.t.recv()
                if data: self._in.write(data)
                else:    self._eof = True; self._in.write_eof()
                continue
            self._flush()
            return res

    def _flush(self):
        data = self._out.read()
        if data: self.t.send(data)

    def handshake(self):
        self._run(self._ssl.do_handshake)

    def write(self, data):
        mv = memoryview(data)
        while len(mv):
            n  = self._run(self._ssl.write, mv[:65536])
            mv = mv[n:]

    def read(self, n=65536):
        try:
            return self._run(self._ssl.read, n)
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            return b""
        except ssl.SSLError:
            if self._eof: return b""
            raise

def parse_url(u):
    """Split an http(s) URL into what is needed to reach it through the tunnel."""
    p = urllib.parse.urlsplit(u)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError(f"not an http(s) URL: {u}")
    tls = p.scheme == "https"
    return {"url": u, "tls": tls, "host": p.hostname, "port": p.port or (443 if tls else 80),
            "hostport": p.netloc.rpartition("@")[2],
            "path": (p.path or "/") + ("?" + p.query if p.query else "")}

class PlainStream:
    """Unencrypted (http://) destination carried inside the tunnel; same interface as TunnelTLS."""
    def __init__(self, tunnel):
        self.t = tunnel
    def write(self, data):
        self.t.send(data)
    def read(self, n=65536):
        return self.t.recv()

def open_stream(tun, target):
    """Ask the proxy server for target host:port and, for https, do TLS to it - all through the tunnel."""
    tun.set_dest(target["host"], target["port"])
    if not target["tls"]:
        return PlainStream(tun)
    st = TunnelTLS(tun, target["host"])
    st.handshake()
    return st

def _http_head(st):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = st.read()
        if not chunk:
            raise TunnelError("closed before HTTP reply")
        buf += chunk
        if len(buf) > 65536:
            raise TunnelError("bad HTTP reply")
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise TunnelError("not an HTTP reply")
    hdrs = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
    return int(parts[1]), hdrs, rest

def _read_body(st, hdrs, rest, keep=0):
    """Consume the rest of a reply body (so the connection can be reused); returns its first `keep` bytes."""
    body = bytearray(rest[:keep])
    if "content-length" in hdrs:
        left = int(hdrs["content-length"]) - len(rest)
        while left > 0:
            chunk = st.read(min(left, 65536))
            if not chunk: raise TunnelError("closed during reply")
            left -= len(chunk)
            body += chunk[:max(0, keep - len(body))]
    elif "chunked" in hdrs.get("transfer-encoding", "").lower():
        tail = rest[-8:]
        while not tail.endswith(b"0\r\n\r\n"):
            chunk = st.read()
            if not chunk: raise TunnelError("closed during reply")
            body += chunk[:max(0, keep - len(body))]
            tail = (tail + chunk)[-8:]
    return bytes(body)

def _refused(st, status, hdrs, rest):
    """
    A reply that is not what we asked for -> (error saying WHY, connection still usable?).
    Shows server / cf-mitigated headers and the start of the body, e.g.
    HTTP 403 [server: cloudflare] "error code: 1020"
    """
    try:    body, reusable = _read_body(st, hdrs, rest, 400), hdrs.get("connection", "").lower() != "close"
    except Exception: body, reusable = rest[:400], False
    bits = [f"{k}: {hdrs[k]}" for k in ("server", "cf-mitigated", "retry-after", "location") if k in hdrs]
    text = body.decode("latin-1")
    if "chunked" in hdrs.get("transfer-encoding", "").lower():
        text = re.sub(r"^[0-9a-fA-F]+\r\n", "", text)                     # chunk-size line
    title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    text  = " ".join((title.group(1) if title else text).split())[:80]
    note = f"HTTP {status}" + (f" [{'; '.join(bits)}]" if bits else "") + (f' "{text}"' if text else "")
    return Refused(note), reusable

def _request(method, target, path, extra=""):
    if target["host"] == "speed.cloudflare.com":      # what the official speed-test page sends
        extra += "Referer: https://speed.cloudflare.com/\r\nOrigin: https://speed.cloudflare.com\r\n"
    return (f"{method} {path} HTTP/1.1\r\nHost: {target['hostport']}\r\nUser-Agent: {UA}\r\n"
            f"Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\n{extra}\r\n").encode()

def verify_tunnel(tun, target):
    """Real-delay check (like V2rayN's): a request to `target` through the tunnel must be answered."""
    st = open_stream(tun, target)
    st.write(_request("GET", target, target["path"], "Connection: close\r\n"))
    status, hdrs, rest = _http_head(st)
    if status not in (200, 204):
        raise _refused(st, status, hdrs, rest)[0]

def tunnel_download(st, target, window, min_mbps, until_bytes=None):
    """
    Download through the tunnel for at most `window` seconds in keep-alive requests.
    Speed = bytes actually received / time since the first request (gaps between requests,
    stalls and slow start all count against it). With a {bytes} placeholder in the URL the
    request size starts at 2 MB, follows the speed, and shrinks when the server refuses a
    big size, so a size limit on the test server never kills a test.
    `until_bytes` ends the test as soon as that much arrived (used by the quick screen).
    """
    t0, got = now(), 0
    sized = "{bytes}" in target["path"]
    size, cap, refusals = DOWN_FIRST, DOWN_MAX, 0
    try:
        while True:
            if now() - t0 >= window: break
            t1 = now()
            try:
                st.write(_request("GET", target, target["path"].replace("{bytes}", str(size)),
                                  "Connection: keep-alive\r\n"))
                status, hdrs, rest = _http_head(st)
            except (TunnelError, OSError):
                if got: break                  # server closed after the first request: use what we have
                raise
            if status != 200:
                err, reusable = _refused(st, status, hdrs, rest)
                refusals += 1
                if not (sized and reusable) or size <= DOWN_FLOOR or refusals > 3:
                    raise err
                cap = size = max(DOWN_FLOOR, size // 4)       # too big for this server: back off
                continue
            total = int(hdrs["content-length"]) if hdrs.get("content-length", "").isdigit() else None
            if total is not None and total < DOWN_FLOOR:      # e.g. an HTML error page sent with 200
                raise Refused(f"HTTP 200 but only {total} bytes ({hdrs.get('content-type', 'unknown type')})"
                              f" - not a speed-test file")
            left  = None if total is None else total - len(rest)
            got  += len(rest)
            done  = False
            while left is None or left > 0:
                if shutdown.is_set(): raise TunnelError("aborted")
                if until_bytes and got >= until_bytes:
                    return mbps(got, now() - t0)
                el = now() - t0
                if el >= window:
                    done = True; break
                if el >= PROBE_SECS and mbps(got, el) < min_mbps / 2:
                    raise TooSlow(mbps(got, el))
                chunk = st.read(65536)
                if not chunk:
                    if left is not None: raise TunnelError("download cut off")
                    done = True; break         # body without length ended with the connection
                got += len(chunk)
                if left is not None: left -= len(chunk)
            if done: break
            size = int(min(cap, max(DOWN_FIRST, (total or size) / max(now() - t1, 1e-3) * DOWN_TARGET)))
    except socket.timeout:
        raise TunnelError(f"no data for {STALL_SECS:g}s ({got // 1000} KB had arrived)" if got
                          else f"no reply from {target['host']} within {STALL_SECS:g}s")
    if got == 0:
        raise TunnelError("no data received")
    return mbps(got, now() - t0)

def tunnel_upload(st, target, window, min_mbps):
    """
    Upload through the tunnel in acknowledged POSTs. A chunk only counts once the server
    has answered it, so data still sitting in socket buffers is never counted as speed.
    """
    sock  = st.t.sock
    t0    = now()
    sent, t_ack, size = 0, t0, UP_MIN
    # the first 64 KB must be answered within a time that still allows the minimum speed
    first_wait = max(STALL_SECS, UP_MIN * 8 / (max(min_mbps, 0.05) * 1_000_000) * 1.5 + 1)
    while True:
        if shutdown.is_set(): raise TunnelError("aborted")
        el = now() - t0
        if el >= window: break
        if el >= PROBE_SECS and sent and mbps(sent, t_ack - t0) < min_mbps / 2:
            raise TooSlow(mbps(sent, t_ack - t0))
        wait_s = first_wait if not sent else max(1.0, window + STALL_SECS - el)
        sock.settimeout(wait_s)
        t1 = now()
        try:
            st.write(_request("POST", target, target["path"],
                              f"Content-Type: application/octet-stream\r\nContent-Length: {size}\r\n"
                              f"Connection: keep-alive\r\n") + _UP_BODY[:size])
            status, hdrs, rest = _http_head(st)
            if status not in (200, 201, 202, 204):
                raise _refused(st, status, hdrs, rest)[0]
            _read_body(st, hdrs, rest)
        except socket.timeout:
            if sent: break                       # keep what was acknowledged so far
            raise TunnelError(f"stalled: no reply to the first {size // 1024} KB within {wait_s:.0f}s")
        t_ack  = now()
        sent  += size
        rate   = size / max(t_ack - t1, 1e-3)    # bytes/s of this request
        size   = int(min(UP_MAX, max(UP_MIN, rate * UP_TARGET)))
    if not sent:
        raise TunnelError("no upload acknowledged")
    return mbps(sent, t_ack - t0)

def test_config(ip, cfg, args):
    """
    Scan-stage test: TCP + TLS + WS upgrade with the config's SNI/Host/path (must be a
    real 101), then - unless --no-verify - a request to --verify-url THROUGH the VLESS
    tunnel. Only IPs that pass both are reported as good.
    """
    res   = {"ip": ip, "method": None, "port": cfg["port"]}
    stage = "ws"
    tun   = VlessWS(ip, cfg, args.wait)
    try:
        t0 = now()
        tun.connect()
        res.update(latency_ms=tun.ws_ms, tls=tun.tls)
        if args.no_verify:
            res.update(method="ws", note="WS 101 ✔ (tunnel not verified)")
            return res
        stage = "tunnel"
        verify_tunnel(tun, args.verify_target)
        res.update(method="ws", tunnel_ms=round((now() - t0) * 1000, 1), note="tunnel ✔")
    except Exception as e:
        res["note"] = _note(e)
        if stage == "tunnel":
            res["tunnel_fail"] = True
            res["note"] = "WS ok, tunnel dead: " + res["note"]
    finally:
        tun.close()
    return res

def run_in_tunnel(ip, cfg, args, target, fn, *a, **kw):
    """A fresh VLESS tunnel over `ip` to `target`, then fn(stream, target, ...). A timeout says which step it hit."""
    tun   = VlessWS(ip, cfg, max(args.wait, 5.0))
    stage = f"connecting to {ip}"
    try:
        tun.connect()
        stage = f"reaching {target['host']} through the tunnel"
        st = open_stream(tun, target)
        stage = "transferring"
        tun.sock.settimeout(STALL_SECS)
        return fn(st, target, *a, **kw)
    except socket.timeout:
        raise TunnelError(f"timeout while {stage}")
    finally:
        tun.close()

class NoServer(Exception):
    """Every test server of one kind refused us."""

class TestServers:
    """
    Speed-test URLs in priority order, shared by every test of the run. The server BEHIND the
    tunnel is what talks to them, so a server that refuses us (HTTP error) refuses all edge IPs
    alike: it is dropped for everybody and the next one is used. Timeouts are blamed on the IP -
    unless no server has worked yet, then the next server is tried for that IP as well.
    """
    LABEL = {"down": "download", "up": "upload"}

    def __init__(self, down, up):
        self.lock    = threading.Lock()
        self.cands   = {"down": list(down), "up": list(up)}
        self.pos     = {"down": 0, "up": 0}
        self.shown   = {"down": set(), "up": set()}
        self.proven  = {"down": False, "up": False}
        self.skipped = {"down": [], "up": []}               # "host: why" lines

    def remaining(self, kind):
        with self.lock:
            return self.cands[kind][self.pos[kind]:]

    def is_proven(self, kind):
        return self.proven[kind]

    def skipped_lines(self, kind):
        with self.lock:
            return list(self.skipped[kind])

    def announce(self, kind, target):
        with self.lock:
            if id(target) in self.shown[kind]: return
            self.shown[kind].add(id(target))
        url = target["url"]
        if "{bytes}" in url:
            url = url.replace("{bytes}", str(DOWN_FIRST)) + \
                  f"   (request size starts at {DOWN_FIRST // 1_000_000} MB and adapts to your speed)"
        with print_lock:
            print(f"  {CG}▸ {self.LABEL[kind]} test server:{R} {CW}{url}{R}")

    def _skip(self, kind, target, why):                      # caller holds self.lock
        self.skipped[kind].append(f"{target['host']}: {why}")
        return f"    {CGR}skipped {target['host']}: {why}{R}"

    def drop(self, kind, target, why):
        with self.lock:
            lst = self.cands[kind]
            if self.pos[kind] >= len(lst) or lst[self.pos[kind]] is not target:
                return                                       # someone else already dropped it
            self.pos[kind] += 1
            line = self._skip(kind, target, why)
        with print_lock:
            print(line)

    def prove(self, kind, target):
        """`target` really carried data: keep it, and drop earlier servers that only timed out."""
        lines = []
        with self.lock:
            self.proven[kind] = True
            lst = self.cands[kind]
            i = next((j for j, t in enumerate(lst) if t is target), None)
            while i is not None and self.pos[kind] < i:
                lines.append(self._skip(kind, lst[self.pos[kind]], f"no reply while {target['host']} worked"))
                self.pos[kind] += 1
        with print_lock:
            for l in lines: print(l)

def with_failover(kind, servers, attempt):
    """
    attempt(target) -> value. Walks the servers in order: a refusal (HTTP error) drops the
    server for everybody and moves on; a timeout/stall moves on to the next server for THIS IP
    only while no server has worked yet (afterwards it is the IP's fault). NoServer when every
    server refused.
    """
    last, all_refused = None, True
    for target in servers.remaining(kind):
        servers.announce(kind, target)
        try:
            value = attempt(target)
        except Refused as e:
            servers.drop(kind, target, str(e)); last = e
            continue
        except TooSlow:
            servers.prove(kind, target)                      # it took our data, the IP is just slow
            raise
        except (TunnelError, OSError) as e:                  # timeout / stall / reset
            if shutdown.is_set() or servers.is_proven(kind):
                raise
            all_refused, last = False, e
            continue
        servers.prove(kind, target)
        return value
    if all_refused:
        raise NoServer(kind)
    raise last

def disable_upload(args, why):
    """Judge IPs by download only from now on (once, loudly)."""
    with upload_lock:
        if args.no_upload: return False
        args.no_upload = True
    with print_lock:
        print(f"\n  {CY}{B}⚠ Upload tests switched OFF:{R} {CY}{why}{R}\n"
              f"    {CW}IPs are judged by download speed only from now on (their upload_mbps stays empty).\n"
              f"    This usually means your own uplink or the test servers are the limit, not the IPs.{R}\n")
    return True

def measure_ip(ip, cfg, args):
    """
    Real speed of one IP: a fresh VLESS tunnel to the download server for the download, and
    another to the upload server for the upload (only if the download was good enough).
    Returns the fields to merge into the result entry; verdict "unjudged" = no test server
    answers at all, which says nothing about the IP.
    """
    sv  = args.servers
    out = {"verdict": "pass", "reason": ""}
    try:
        dl = with_failover("down", sv, lambda t: run_in_tunnel(ip, cfg, args, t, tunnel_download,
                                                               args.speed_time, args.min_download))
        out["download_mbps"] = round(dl, 2)
    except NoServer:
        return {"verdict": "unjudged", "reason": "no download test server answers"}
    except TooSlow as e:
        return {"download_mbps": round(e.mbps, 2), "verdict": "slow", "reason": f"download {e}"}
    except Exception as e:
        return {"verdict": "fail", "reason": "download: " + _note(e)}
    if out["download_mbps"] < args.min_download:
        out.update(verdict="slow", reason=f"download {out['download_mbps']} Mbps < {args.min_download}")
        return out
    if args.no_upload:
        return out
    try:
        ul = with_failover("up", sv, lambda t: run_in_tunnel(ip, cfg, args, t, tunnel_upload,
                                                             args.speed_time, args.min_upload))
        out["upload_mbps"] = round(ul, 2)
    except NoServer:
        disable_upload(args, "every upload test server refused us")
        return out
    except TooSlow as e:
        out.update(upload_mbps=round(e.mbps, 2), verdict="slow", reason=f"upload {e}")
        return out
    except Exception as e:
        out.update(verdict="fail", reason="upload: " + _note(e))
        return out
    if out["upload_mbps"] < args.min_upload:
        out.update(verdict="slow", reason=f"upload {out['upload_mbps']} Mbps < {args.min_upload}")
    return out

def prescreen_ip(ip, cfg, args):
    """
    Quick check run many-at-once before the accurate (one-at-a-time) speed test: can this IP's
    tunnel pull even 64 KB from the download server? Returns None if so, else the reason.
    Dead and throttled IPs are common, and this finds them in seconds instead of minutes.
    """
    try:
        with_failover("down", args.servers, lambda t: run_in_tunnel(ip, cfg, args, t, tunnel_download,
                                                                    PRESCREEN_SECS, 0, until_bytes=PRESCREEN_BYTES))
    except NoServer:
        raise
    except Exception as e:
        return _note(e)
    return None

# ─── TLS-only check ───────────────────────────────────────────────────────────
def _try_tls(ip, sni, port, timeout, ver):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        if ver == "1.3":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        t0 = now()
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni): pass
        return round((now() - t0) * 1000, 1)
    except Exception:
        return None

def check_tls_only(ip, sni, port, timeout, tls13_only=False):
    ms = _try_tls(ip, sni, port, timeout, "1.3")
    if ms: return {"tls": "1.3", "latency_ms": ms}
    if not tls13_only:
        ms = _try_tls(ip, sni, port, timeout, "1.2")
        if ms: return {"tls": "1.2", "latency_ms": ms}
    return {"tls": None, "latency_ms": None}

# ─── TLS version ranking (for descending sort: 1.3 → 1.2 → 1.1 → 1.0) ────────
TLS_RANK = {"1.3": 3, "1.2": 2, "1.1": 1, "1.0": 0}

def tls_rank(v):
    return TLS_RANK.get(v, -1)

# ─── ICMP (ping / packet loss) - Windows, Linux and macOS flavours ────────────
_TIME_RE = re.compile(r"[=<]\s*(\d+(?:\.\d+)?)\s*ms", re.I)
_PCT_RE  = re.compile(r"(\d+(?:\.\d+)?)%")

def _ping_cmd(ip, count, wait):
    if IS_WIN:                                     # -n count, -w timeout in ms
        return ["ping", "-n", str(count), "-w", str(int(wait * 1000)), ip]
    if sys.platform == "darwin":                   # -W timeout in ms
        return ["ping", "-c", str(count), "-W", str(int(wait * 1000)), ip]
    return ["ping", "-c", str(count), "-W", str(max(1, int(round(wait)))), ip]   # seconds

def ping_ip(ip, timeout=2.0):
    try:
        r = subprocess.run(_ping_cmd(ip, 1, timeout), capture_output=True, text=True,
                           errors="replace", timeout=timeout + 3)
        out = r.stdout
        if r.returncode == 0 and re.search(r"ttl", out, re.I):   # Windows exits 0 on "unreachable"
            m = _TIME_RE.search(out)
            return True, float(m.group(1)) if m else None
        return False, None
    except Exception:
        return False, None

def measure_packet_loss(ip, count, wait=1.0):
    """Loss percentage (0-100) from `count` ICMP pings, or None if ping couldn't run."""
    try:
        r = subprocess.run(_ping_cmd(ip, count, wait), capture_output=True, text=True,
                           errors="replace", timeout=count * (wait + 1) + 5)
        m = _PCT_RE.search(r.stdout)
        return float(m.group(1)) if m else None
    except Exception:
        return None

# ─── Args ─────────────────────────────────────────────────────────────────────
def parse_args():
    ap = argparse.ArgumentParser(
        description="Cloudflare IP scanner — tests your real VLESS/WS config",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    ap.add_argument("subnets_file")
    ap.add_argument("-c","--config",   default=None,               help="vless:// URI to test")
    ap.add_argument("-s","--sni",      default=None,               help="Domain for TLS-only test")
    ap.add_argument("-t","--threads",  type=int,   default=50,     help="Parallel threads (default:50)")
    ap.add_argument("-w","--wait",     type=float, default=3.0,    help="Timeout seconds (default:3.0)")
    ap.add_argument("-p","--port",     type=int,   default=None,   help="Port override")
    ap.add_argument("-o","--output",   default="cf_results.json",  help="Output JSON")
    ap.add_argument("-r","--resume",   default="cf_progress.json", help="Resume file")
    ap.add_argument("--ping-only",     action="store_true",        help="ICMP ping only mode")
    ap.add_argument("--tls13-only",    action="store_true",        help="TLS 1.3 only filter")
    ap.add_argument("--no-ping",       action="store_true",        help=argparse.SUPPRESS)  # old flag, ICMP pre-check is gone
    ap.add_argument("--no-verify",     action="store_true",        help="Only check the WS 101 handshake, skip the real tunnel check")
    ap.add_argument("--verify-url",    default=VERIFY_URL,         help=f"URL fetched through the tunnel to verify each hit (default:{VERIFY_URL})")
    ap.add_argument("--down-url",      default=None,               help="Download URL for speed tests, {bytes} = request size (default: automatic - first working of Cloudflare's speed server and public test files)")
    ap.add_argument("--up-url",        default=None,               help="Upload URL for speed tests, must accept POST bodies (default: automatic)")
    ap.add_argument("--speed-test",    action="store_true",        help="Every --speed-limit verified hits, pause the scan and measure real download/upload through the tunnel")
    ap.add_argument("--speed-limit",   type=int,   default=20,     help="Verified hits per speed-test batch (default:20)")
    ap.add_argument("--speed-time",    type=float, default=5.0,    help="Seconds per download / upload measurement (default:5)")
    ap.add_argument("--min-download",  type=float, default=2.0,    help="Reject IPs below this download Mbps (default:2)")
    ap.add_argument("--min-upload",    type=float, default=1.0,    help="Reject IPs below this upload Mbps (default:1)")
    ap.add_argument("--no-upload",     action="store_true",        help="Skip the upload test")
    ap.add_argument("--speed-threads", type=int,   default=1,      help="Parallel speed tests; >1 is faster but they share your bandwidth (default:1)")
    ap.add_argument("--want",          type=int,   default=0,      help="Stop once N good IPs were found (default:0 = scan all)")
    ap.add_argument("--sort",          choices=["download", "upload", "delay"], default="download", help="Result order (default:download)")
    ap.add_argument("--loss-count",    type=int,   default=0,      help="ICMP pings per IP for packet loss, 0 = off (default:0)")
    return ap.parse_args()

# ─── Subnet Expansion ─────────────────────────────────────────────────────────
def expand_subnets(filepath):
    if not os.path.exists(filepath):
        try:                                           # a single IP / CIDR instead of a file: handy to re-test one IP
            ipaddress.ip_network(filepath, strict=False)
            lines = [filepath]
        except ValueError:
            print(f"{CR}  Error: File not found: {filepath}{R}"); sys.exit(1)
    else:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            lines = [l.split("#", 1)[0].strip() for l in f]
    lines = [l for l in lines if l]

    print(f"\n{CC}  ▸ Reading {len(lines)} subnet entries …{R}")
    all_ips = []
    for line in lines:
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            all_ips.append(line)                     # plain hostname
            continue
        n = net.num_addresses
        if n <= 2:
            all_ips.extend(str(a) for a in net)
        elif net.version == 6 and n > 65536:         # can't enumerate IPv6 blocks, sample them
            base = int(net.network_address)
            all_ips.extend(str(ipaddress.ip_address(base + random.randrange(1, n - 1)))
                           for _ in range(4096))
        else:
            all_ips.extend(str(a) for a in net.hosts())
    return list(set(all_ips))

# ─── Resume / Save ────────────────────────────────────────────────────────────
def make_scan_id(args, cfg):
    """Progress is only reusable for the same config/mode, otherwise results would lie."""
    key = {
        "cfg":    [cfg[k] for k in ("uuid", "port", "ws_host", "path", "sni", "security")] if cfg else None,
        "mode":   "ping" if args.ping_only else "cfg" if cfg else "tls" if args.sni else "tcp",
        "sni":    args.sni, "port": args.port, "t13": args.tls13_only,
        "verify": not args.no_verify, "host": args.verify_url,
    }
    return hashlib.sha1(json.dumps(key, sort_keys=True).encode()).hexdigest()[:12]

def load_progress(resume_file, all_ips, scan_id):
    done_set, resumed = set(), False
    if os.path.exists(resume_file):
        try:
            with open(resume_file, encoding="utf-8") as f: data = json.load(f)
            if data.get("scan_id") == scan_id:
                done_set, resumed = set(data.get("processed_ips", [])), True
                print(f"  {CG}▸ Resuming: {len(done_set):,} IPs already processed{R}")
            else:
                print(f"  {CY}▸ Progress file is from another config/mode — starting fresh{R}")
        except Exception:
            print(f"  {CY}▸ Could not read resume file — starting fresh{R}")
    return [ip for ip in all_ips if ip not in done_set], done_set, resumed

def load_results(path):
    try:
        with open(path, encoding="utf-8") as f: data = json.load(f)
        items = list(data.get("results", [])) + list(data.get("rejected", []))
        return [e for e in items if isinstance(e, dict) and e.get("ip")]
    except Exception:
        return []

def _atomic_write(path, data):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception: pass

def save_progress(resume_file, done_ips, scan_id):
    _atomic_write(resume_file, {"scan_id": scan_id, "processed_ips": list(done_ips),
                                "saved_at": datetime.now().isoformat()})

def sort_key(x, mode="download"):
    dl    = x.get("download_mbps") or 0.0
    ul    = x.get("upload_mbps") or 0.0
    delay = x.get("tunnel_ms") or x.get("latency_ms") or 9999
    loss  = x.get("packet_loss_pct")
    loss  = 100.0 if loss is None else loss
    if mode == "upload": return (-ul, -dl, -tls_rank(x.get("tls")), delay, loss)
    if mode == "delay":  return (delay, -dl, -ul, -tls_rank(x.get("tls")), loss)
    return (-dl, -ul, -tls_rank(x.get("tls")), delay, loss)

def build_uri(cfg, e):
    ip     = e["ip"]
    host   = f"[{ip}]" if ":" in ip else ip
    remark = f"{cfg['name']}-{ip}" if cfg["name"] else ip
    if e.get("download_mbps") is not None: remark += f"-D{e['download_mbps']:.1f}"
    if e.get("upload_mbps")   is not None: remark += f"-U{e['upload_mbps']:.1f}"
    params = [("type", cfg["type"]), ("encryption", "none"), ("path", cfg["path"]),
              ("host", cfg["ws_host"]), ("security", cfg["security"]), ("sni", cfg["sni"]),
              ("fp", cfg["fp"]), ("alpn", cfg["alpn"])]
    query  = "&".join(f"{k}={urllib.parse.quote(v, safe='/' if k == 'path' else '')}"
                      for k, v in params if v)
    return f"vless://{cfg['uuid']}@{host}:{cfg['port']}?{query}#{urllib.parse.quote(remark)}"

def save_results(output_file, cfg, sort_mode="download"):
    """
    Good IPs first-class in "results" (best first); IPs that failed or were too slow in
    the real speed test go to "rejected" so they never waste your time.
    """
    with alive_lock:
        items = [dict(e) for e in alive_ips]
    good = sorted((e for e in items if e.get("verdict") in (None, "pass")),
                  key=lambda e: sort_key(e, sort_mode))
    bad  = [e for e in items if e.get("verdict") in ("slow", "fail")]
    if cfg:
        for e in good:
            e["vless_uri"] = build_uri(cfg, e)
    _atomic_write(output_file, {
        "generated_at": datetime.now().isoformat(),
        "count":        len(good),
        "speed_tested": sum(1 for x in good if x.get("verdict") == "pass"),
        "ws_ok":        sum(1 for x in good if x.get("method") == "ws"),
        "tls13":        sum(1 for x in good if x.get("method") == "1.3"),
        "tls12":        sum(1 for x in good if x.get("method") == "1.2"),
        "results":      good,
        "rejected":     bad,
    })

def autosave(args, cfg, scan_id, force=False):
    global last_save
    if not force and now() - last_save < SAVE_EVERY_S:
        return
    last_save = now()
    with done_lock: snap = set(done_ips_set)
    save_progress(args.resume, snap, scan_id)
    save_results(args.output, cfg, args.sort)

# ─── Worker ───────────────────────────────────────────────────────────────────
def worker(ip, args, cfg, result_q):
    if shutdown.is_set(): return
    try:
        result_q.put(scan_one(ip, args, cfg))
    except Exception as e:
        result_q.put({"ip": ip, "method": None, "note": _note(e)})

def scan_one(ip, args, cfg):
    port = args.port or (cfg["port"] if cfg else 443)

    # ── Mode 1: ping only ──
    if args.ping_only:
        alive, ms = ping_ip(ip, args.wait)
        return {"ip": ip, "method": "ping" if alive else None,
                "latency_ms": ms, "note": "icmp"}

    # ── Mode 2: real config test ──
    if cfg:
        return test_config(ip, cfg, args)

    # ── Mode 3: TLS only ──
    if args.sni:
        res = check_tls_only(ip, args.sni, port, args.wait, args.tls13_only)
        res["ip"]     = ip
        res["method"] = res["tls"]
        res["port"]   = port
        return res

    # ── Mode 4: plain TCP ──
    try:
        t0 = now()
        with socket.create_connection((ip, port), timeout=args.wait): pass
        ms = round((now() - t0) * 1000, 1)
        return {"ip": ip, "method": "tcp", "latency_ms": ms, "port": port}
    except Exception:
        return {"ip": ip, "method": None, "latency_ms": None}

def handle_result(res, args, cfg, scan_id, pause_evt):
    ip     = res["ip"]
    method = res.get("method")
    ms     = res.get("tunnel_ms") or res.get("latency_ms")
    note   = res.get("note", "")
    tls    = res.get("tls", "")

    with done_lock:
        done_ips_set.add(ip)

    with stats["lock"]:
        stats["processed"] += 1
        if method == "ws":
            stats["ws_ok"] += 1
            tls_tag = f" {CG}[TLS {tls}]{R}" if tls else ""
            label   = f"{CG}{B}WS ✔{R}{tls_tag}"
            icon    = f"{CG}✔{R}"
        elif method == "1.3":
            stats["tls13"] += 1
            label = f"{CG}{B}TLS 1.3{R}"; icon = f"{CG}✔{R}"
        elif method == "1.2":
            stats["tls12"] += 1
            label = f"{CY}{B}TLS 1.2{R}"; icon = f"{CY}✔{R}"
        elif method in ("tcp", "ping"):
            stats["tcp_only"] += 1
            label = f"{CC}TCP/PING{R}"; icon = f"{CC}~{R}"
        else:
            key = "tunnel_dead" if res.get("tunnel_fail") else "dead"
            stats[key] += 1
            color = CY if key == "tunnel_dead" else CR
            add_log(f"{color}✘ {CGR}{ip:<18}{R}{color} {(note or 'no response')[:40]}{R}")
            label = None

        if label is not None:
            ms_str = f"{ms:.1f}ms" if ms else "??ms"
            note_s = f" {CGR}{note[:28]}{R}" if note and note not in ("icmp", "") else ""
            add_log(f"{icon} {B}{ip:<18}{R} {label}  {CC}{ms_str}{R}{note_s}")

            entry = dict(res)
            entry["method"] = method
            with alive_lock:
                alive_ips.append(entry)

            if method == "ws" and args.speed_test:
                stats["untested"] += 1
                if (pause_evt is not None and not pause_evt.is_set()
                        and stats["untested"] >= args.speed_limit):
                    add_log(f"{CM}{B}▸ {stats['untested']} verified hits — "
                            f"pausing scan for a real speed-test batch{R}")
                    pause_evt.set()
            if (args.want and not args.speed_test and
                    stats["ws_ok"] + stats["tls13"] + stats["tls12"] >= args.want):
                want_reached.set()

    autosave(args, cfg, scan_id)

def result_processor(result_q, args, cfg, scan_id, stop_evt, pause_evt):
    while not stop_evt.is_set() or not result_q.empty():
        try:
            res = result_q.get(timeout=0.3)
        except Empty:
            continue
        try:
            handle_result(res, args, cfg, scan_id, pause_evt)
        except Exception as e:
            add_log(f"{CR}internal error: {e}{R}")
        finally:
            result_q.task_done()

# ─── Speed-test phase ─────────────────────────────────────────────────────────
def fmt_speed(v):
    return "    -" if v is None else f"{v:6.2f} Mbps ({v/8:5.2f} MB/s)"

def _run_pool(fn, items, workers):
    """fn(item) for every item on a small pool; short waits keep Ctrl+C responsive on Windows."""
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        not_done = {ex.submit(fn, it) for it in items}
        while not_done:
            _, not_done = wait(not_done, timeout=0.3)

def run_speed_test_phase(candidates, args, cfg):
    """
    Real speed of the given entries (best tunnel delay first), stamping each with its numbers
    and a verdict. 1) a quick many-at-once screen drops IPs whose tunnel cannot even carry
    64 KB; 2) the survivors are measured one at a time (parallel tests would share your
    bandwidth). Stops early when --want is satisfied, on Ctrl+C or when no test server
    answers; skipped entries stay untested for the next run.
    """
    if not candidates:
        return
    sv    = args.servers
    delay = lambda e: e.get("tunnel_ms") or e.get("latency_ms") or 9999
    candidates = sorted(candidates, key=delay)

    def stopped():
        return shutdown.is_set() or want_reached.is_set() or host_refuses.is_set()

    def no_download_server():
        """Nothing answers: that says nothing about the IPs - stop the run and keep them untested."""
        with refusal_lock:
            if host_refuses.is_set(): return
            host_refuses.set()
            lines = [f"{CR}{B}✘ No download test server answers your server:{R}"]
            lines += [f"  {CY}{n}{R}" for n in sv.skipped_lines("down")]
            lines.append(f"{CW}These IPs were NOT judged. Run again with --down-url <a large file your server can fetch>.{R}")
            stop_notes.extend(lines)
        with print_lock:
            print("\n" + "\n".join("  " + l for l in lines) + "\n")

    def record(entry, res):
        """Store a verdict, update the counters and print the line. False = nothing was recorded."""
        v = res["verdict"]
        if v == "unjudged":
            no_download_server(); return False
        if shutdown.is_set() and v == "fail":
            return False                                # cut short by Ctrl+C: not the IP's fault, stays untested
        with alive_lock:
            entry.update(res)
        with stats["lock"]:
            stats["untested"] -= 1
            stats[{"pass": "passed", "slow": "slow", "fail": "failed"}[v]] += 1
            if v == "pass" and args.want and stats["passed"] >= args.want:
                want_reached.set()
        with print_lock:
            tls = entry.get("tls") or "-"
            if v == "pass":
                ul = "" if args.no_upload else f"  ↑{fmt_speed(res.get('upload_mbps'))}"
                print(f"  {CG}✔ {entry['ip']:<18}{R} TLS {tls:<4} {CG}↓{fmt_speed(res['download_mbps'])}{R}"
                      f"{CG}{ul}{R}  {CGR}{entry.get('tunnel_ms') or '?'}ms{R}")
            else:
                print(f"  {CR}✘ {entry['ip']:<18}{R} TLS {tls:<4} {CR}rejected: {res.get('reason', '')}{R}")
        return True

    def after_upload(entry, res):
        """Upload safeguards: give up on upload when it never works, hint when it rejects everything."""
        v, reason = res["verdict"], res.get("reason", "")
        stalled = (v == "fail" and reason.startswith("upload:")
                   and any(k in reason for k in ("stalled", "timeout", "no reply", "no data")))
        revert = None
        with upload_lock:
            s = upload_state
            if res.get("upload_mbps") is not None:
                s["worked"] = True; s["streak"].clear()
            elif stalled:
                s["streak"].append(entry)
            if v in ("slow", "fail") and reason.startswith("upload"): s["rej"] += 1
            elif v == "pass": s["rej"] = 0
            hint = s["rej"] >= 5 and not s["hinted"]
            if hint: s["hinted"] = True
            if not s["worked"] and len(s["streak"]) >= UPLOAD_GIVEUP and not args.no_upload:
                revert = list(s["streak"]); s["streak"].clear()
        if revert and disable_upload(args, f"no reply to the upload test on {len(revert)} IPs in a row, "
                                           f"on every upload server, and it never worked in this run"):
            with alive_lock:                            # those IPs passed the download test: count them as passed
                for e in revert:
                    e.update(verdict="pass", reason="", upload_note="not measured: upload stalled everywhere")
                    e.pop("upload_mbps", None)
            with stats["lock"]:
                stats["failed"] -= len(revert); stats["passed"] += len(revert)
                if args.want and stats["passed"] >= args.want: want_reached.set()
        if hint:
            with print_lock:
                print(f"\n  {CY}{B}⚠ 5 IPs in a row passed the download test but were rejected by the UPLOAD test.{R}\n"
                      f"    {CW}If your own uplink is the limit, lower --min-upload (now {args.min_upload:g} Mbps) "
                      f"or use --no-upload.{R}\n")

    # ── 1. quick screen (many at once): can the tunnel carry data at all? ──
    survivors = candidates
    if len(candidates) > PRESCREEN_MIN:
        print(f"\n  {CM}{B}▸ Quick screen of {len(candidates)} IPs, {PRESCREEN_THREADS} at a time: "
              f"can their tunnel carry data at all?{R}\n")
        ok, ok_lock = [], threading.Lock()

        def screen(entry):
            if stopped(): return
            try:
                reason = prescreen_ip(entry["ip"], cfg, args)
            except NoServer:
                record(entry, {"verdict": "unjudged"}); return
            except Exception as e:
                reason = _note(e)
            if reason is None:
                with ok_lock: ok.append(entry)
            else:
                record(entry, {"verdict": "fail", "reason": "download: " + reason})

        _run_pool(screen, candidates, PRESCREEN_THREADS)
        survivors = sorted(ok, key=delay)
        if shutdown.is_set() or host_refuses.is_set():
            return
        print(f"\n  {CG}▸ {len(survivors)} of {len(candidates)} IPs can carry data{R}")
        if not survivors:
            print()
            return

    # ── 2. accurate speed test, one at a time ──
    ul_txt = "" if args.no_upload else " + upload"
    print(f"\n  {CM}{B}▸ Real speed test of {len(survivors)} IPs through your VLESS tunnel "
          f"(download{ul_txt}, {args.speed_time:g}s each, min {args.min_download:g}"
          f"{'' if args.no_upload else '/' + format(args.min_upload, 'g')} Mbps, "
          f"{args.speed_threads} at a time)…{R}\n")

    def job(entry):
        if stopped(): return
        try:
            res = measure_ip(entry["ip"], cfg, args)
            if args.loss_count > 0 and res["verdict"] == "pass":
                res["packet_loss_pct"] = measure_packet_loss(entry["ip"], args.loss_count, 1.0)
        except Exception as e:
            res = {"verdict": "fail", "reason": _note(e)}
        if record(entry, res):
            after_upload(entry, res)

    _run_pool(job, survivors, args.speed_threads)

    if host_refuses.is_set():
        return                                          # the explanation was printed (and is repeated at the end)
    with stats["lock"]:
        passed, slow, failed = stats["passed"], stats["slow"], stats["failed"]
    print(f"\n  {CG}{B}✔ Batch done — {passed} passed in total, "
          f"{slow} too slow, {failed} failed so far{R}\n")

# ─── Display ─────────────────────────────────────────────────────────────────
def add_log(line):
    with log_lock:
        log_buffer.append(line)
        if len(log_buffer) > LOG_MAXLEN: log_buffer.pop(0)

def progress_bar(f, w=42):
    n = int(f * w)
    return clr("█"*n, CG, B) + clr("░"*(w-n), CGR)

def ratio_bar(ws, t13, t12, tcp, proc, w=58):
    if proc == 0: return clr("░"*w, CGR)
    a = int((ws  / proc) * w); b = int((t13 / proc) * w)
    c = int((t12 / proc) * w); d = int((tcp / proc) * w)
    e = w - a - b - c - d
    return (clr("█"*a, CG, B) + clr("█"*b, CM, B) +
            clr("█"*c, CY, B) + clr("█"*d, CC) +
            clr("░"*max(0,e), CR))

def fmt_eta(el, done, remaining):
    if done == 0 or el < 0.5: return "calculating…"
    return str(timedelta(seconds=int(remaining / (done / el))))

def fmt_rate(el, done):
    return "–" if el < 0.1 else f"{done/el:.1f}/s"

def best_line():
    with alive_lock:
        tested = [e for e in alive_ips if e.get("verdict") == "pass"]
    if not tested: return None
    e = max(tested, key=lambda x: x.get("download_mbps") or 0)
    ul = f"  ↑ {e['upload_mbps']:.2f} Mbps" if e.get("upload_mbps") is not None else ""
    return f"{e['ip']}  ↓ {e['download_mbps']:.2f} Mbps ({e['download_mbps']/8:.2f} MB/s){ul}"

def render(args, cfg):
    with stats["lock"]:
        s = dict(stats)
    total, proc = s["total"], s["processed"]
    done_now    = proc - s["base"]
    elapsed     = max(0.0, time.time() - (s["start_time"] or time.time()) - s["paused"])
    remaining   = total - proc
    frac        = proc / total if total > 0 else 0
    L = [BANNER]

    if cfg:
        mode_str = (f"{CM}Config:{R} {CW}{B}{cfg['ws_host']}{R}  "
                    f"{CGR}path:{R}{CW}{cfg['path']}{R}  "
                    f"{CGR}port:{R}{CW}{cfg['port']}{R}")
    elif args.sni:
        mode_str = f"{CM}TLS SNI:{R} {CW}{B}{args.sni}{R}"
    elif args.ping_only:
        mode_str = f"{CY}ICMP PING-ONLY{R}"
    else:
        mode_str = f"{CC}TCP-only{R}"
    L.append(f"  {mode_str}   {CGR}Threads:{R}{CW}{args.threads}{R}  "
             f"{CGR}Timeout:{R}{CW}{args.wait}s{R}")
    if cfg:
        how = (f"{CY}WS handshake only (--no-verify){R}" if args.no_verify
               else f"{CG}real VLESS tunnel via {args.verify_target['host']}{R}")
        L.append(f"  {CGR}Verify:{R} {how}")
    L.append("")
    L.append(f"  {B}{CW}Progress{R}  {progress_bar(frac)}  {CY}{B}{frac*100:6.2f}%{R}\n")

    col = 26
    L.append(f"  {CC}{'Total IPs':<{col}}{R}{CW}{B}{total:>10,}{R}   "
             f"{CGR}{'Elapsed':<{col}}{R}{CW}{str(timedelta(seconds=int(elapsed))):>10}{R}")
    if cfg:
        okname = "✔ WS 101 OK" if args.no_verify else "✔ Tunnel OK"
        L.append(f"  {CG}{okname:<{col}}{R}{CG}{B}{s['ws_ok']:>10,}{R}   "
                 f"{CB}{'ETA':<{col}}{R}{CW}{fmt_eta(elapsed, done_now, remaining):>10}{R}")
        L.append(f"  {CY}{'✘ WS ok, tunnel dead':<{col}}{R}{CY}{s['tunnel_dead']:>10,}{R}   "
                 f"{CM}{'Scan rate':<{col}}{R}{CW}{fmt_rate(elapsed, done_now):>10}{R}")
    else:
        L.append(f"  {CM}{'✔ TLS 1.3':<{col}}{R}{CM}{B}{s['tls13']:>10,}{R}   "
                 f"{CB}{'ETA':<{col}}{R}{CW}{fmt_eta(elapsed, done_now, remaining):>10}{R}")
        L.append(f"  {CY}{'✔ TLS 1.2':<{col}}{R}{CY}{s['tls12']:>10,}{R}   "
                 f"{CM}{'Scan rate':<{col}}{R}{CW}{fmt_rate(elapsed, done_now):>10}{R}")
    L.append(f"  {CC}{'✔ TCP/Ping':<{col}}{R}{CC}{s['tcp_only']:>10,}{R}   "
             f"{CGR}{'Timeout/IP':<{col}}{R}{CW}{args.wait:>9}s{R}")
    L.append(f"  {CR}{'✘ Dead':<{col}}{R}{CR}{s['dead']:>10,}{R}   "
             f"{CY}{'⏳ Remaining':<{col}}{R}{CW}{B}{remaining:>10,}{R}")
    if args.speed_test:
        L.append(f"  {CG}{'⚡ Speed passed':<{col}}{R}{CG}{B}{s['passed']:>10,}{R}   "
                 f"{CR}{'Rejected (slow/failed)':<{col}}{R}{CR}{s['slow'] + s['failed']:>10,}{R}")
        L.append(f"  {CM}{'Waiting for speed test':<{col}}{R}{CW}{s['untested']:>10,}{R}")

    L.append(f"\n  {ratio_bar(s['ws_ok'], s['tls13'], s['tls12'], s['tcp_only'], proc)}")
    if proc > 0:
        L.append(f"  {CG}WS:{s['ws_ok']/proc*100:.1f}%{R}  "
                 f"{CM}1.3:{s['tls13']/proc*100:.1f}%{R}  "
                 f"{CY}1.2:{s['tls12']/proc*100:.1f}%{R}  "
                 f"{CC}TCP:{s['tcp_only']/proc*100:.1f}%{R}  "
                 f"{CR}Dead:{(s['dead'] + s['tunnel_dead'])/proc*100:.1f}%{R}")

    L.append(f"\n  {DIM}{'─'*62}{R}  {B}{CGR}Recent Activity{R}")
    with log_lock:
        L.extend(f"  {line}" for line in log_buffer)

    L.append(f"\n  {DIM}{'─'*62}{R}")
    best = best_line()
    if best:
        L.append(f"  {CG}{B}★ Best so far:{R} {CW}{best}{R}")
    L.append(f"  {CGR}Output → {CW}{args.output}{R}   "
             f"{CGR}Resume → {CW}{args.resume}{R}   "
             f"{CGR}[Ctrl+C to stop & save]{R}\n")
    if cfg and s["ws_ok"] > 0:
        L.append(f"  {CG}{B}✔ {s['ws_ok']} working IPs found! Ready-to-use vless:// URIs saved in output.{R}\n")

    sys.stdout.write("\033[H" + "\n".join(l + "\033[K" for l in "\n".join(L).split("\n")) + "\033[J")
    sys.stdout.flush()

def display_thread_fn(args, cfg, stop_evt, render_pause_evt):
    while not stop_evt.is_set():
        if render_pause_evt.is_set():
            time.sleep(0.2)
            continue
        try: render(args, cfg)
        except Exception: pass
        time.sleep(0.5)

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    setup_console()
    args = parse_args()
    print(BANNER)
    print(HIDE_CURSOR, end="", flush=True)
    try:
        run(args)
    finally:
        print(SHOW_CURSOR, end="", flush=True)

def run(args):
    # Parse config
    cfg = None
    if args.config:
        cfg = parse_vless(args.config)
        if not cfg:
            sys.exit(1)
        if args.port:
            cfg["port"] = args.port
        print(f"  {CG}▸ Config parsed:{R} {CW}{cfg['ws_host']}{R} "
              f"path={CW}{cfg['path']}{R} port={CW}{cfg['port']}{R} "
              f"tls={CW}{cfg['security']}{R}")
        if args.no_verify:
            print(f"  {CY}⚠  --no-verify: IPs are only checked for a WS 101 reply and may not carry traffic{R}")
    elif not args.sni and not args.ping_only:
        print(f"  {CY}⚠  No config (-c) or SNI (-s) given → TCP-only mode{R}\n")

    try:
        args.verify_target = parse_url(args.verify_url)
        args.servers = TestServers([parse_url(u) for u in ([args.down_url] if args.down_url else DOWN_URLS)],
                                   [parse_url(u) for u in ([args.up_url] if args.up_url else UP_URLS)])
    except ValueError as e:
        print(f"  {CR}  {e}{R}"); sys.exit(1)

    for opt, url in (("--verify-url", args.verify_url), ("--down-url", args.down_url), ("--up-url", args.up_url)):
        host = urllib.parse.urlsplit(url or "").hostname or ""
        if (host in ("example.com", "example.org", "example.net")
                or host.endswith((".example.com", ".example.org", ".example.net", ".invalid", ".example", ".test"))):
            print(f"  {CR}  {opt} {url}\n  {host} is a placeholder from the README, not a real server - "
                  f"use a URL of a large file that really exists.{R}")
            sys.exit(1)

    if args.tls13_only and not args.sni:
        print(f"  {CR}  --tls13-only requires -s/--sni{R}"); sys.exit(1)
    if args.speed_test and (not cfg or args.ping_only):
        print(f"  {CR}  --speed-test needs -c/--config: speed is measured through your real VLESS "
              f"tunnel.\n  A direct download from Cloudflare says nothing about what V2rayN will get.{R}")
        sys.exit(1)

    if (args.ping_only or args.loss_count) and not shutil.which("ping"):
        print(f"  {CR}  The 'ping' command was not found - install it "
              f"(Debian/Ubuntu: sudo apt install iputils-ping){R}")
        sys.exit(1)

    scan_id = make_scan_id(args, cfg)
    all_ips = expand_subnets(args.subnets_file)
    print(f"  {CG}▸ Unique IPs after expansion: {B}{len(all_ips):,}{R}")

    remaining_ips, done_set, resumed = load_progress(args.resume, all_ips, scan_id)
    with done_lock: done_ips_set.update(done_set)
    random.shuffle(remaining_ips)
    if resumed:
        old = load_results(args.output)
        with alive_lock: alive_ips.extend(old)
        for e in old:
            m = e.get("method")
            if   m == "ws":  stats["ws_ok"]    += 1
            elif m == "1.3": stats["tls13"]    += 1
            elif m == "1.2": stats["tls12"]    += 1
            elif m in ("tcp", "ping"): stats["tcp_only"] += 1
            v = e.get("verdict")
            if   v == "pass": stats["passed"]  += 1
            elif v == "slow": stats["slow"]    += 1
            elif v == "fail": stats["failed"]  += 1
            elif m == "ws":   stats["untested"] += 1
        if old:
            print(f"  {CG}▸ Loaded {len(old):,} earlier results from {args.output}{R}")
    print(f"  {CC}▸ IPs to scan this session:   {B}{len(remaining_ips):,}{R}")
    if args.want and args.speed_test and stats["passed"] >= args.want:
        print(f"  {CG}▸ {stats['passed']} IPs already passed the speed test (--want {args.want}) — "
              f"nothing to do, raise --want to look for more{R}")
        want_reached.set()
    time.sleep(1.5)

    with stats["lock"]:
        stats["total"]      = len(all_ips)
        stats["processed"]  = len(done_set)
        stats["base"]       = len(done_set)
        stats["start_time"] = time.time()

    result_q     = Queue()
    stop_disp    = threading.Event()
    stop_proc    = threading.Event()
    render_pause = threading.Event()
    pause_evt    = threading.Event() if args.speed_test else None

    dt = threading.Thread(target=display_thread_fn, args=(args, cfg, stop_disp, render_pause), daemon=True)
    dt.start()
    pt = threading.Thread(target=result_processor, args=(result_q, args, cfg, scan_id, stop_proc, pause_evt), daemon=True)
    pt.start()

    def handle_exit(sig, frame):
        if shutdown.is_set():            # second Ctrl+C: leave right now
            print(SHOW_CURSOR, end="", flush=True)
            os._exit(130)
        shutdown.set()
    signal.signal(signal.SIGINT, handle_exit)
    try: signal.signal(signal.SIGTERM, handle_exit)
    except (ValueError, OSError, AttributeError): pass

    def untested():
        with alive_lock:
            return [e for e in alive_ips if e.get("method") == "ws" and not e.get("verdict")]

    def run_batch():
        """Pause rendering, drain in-flight results, speed-test the verified hits
        collected so far, then let scanning resume."""
        t_pause = time.time()
        render_pause.set()
        time.sleep(0.6)  # let any in-progress render() finish before we print
        clear_screen(); print(BANNER)
        result_q.join()
        run_speed_test_phase(untested(), args, cfg)
        autosave(args, cfg, scan_id, force=True)
        with stats["lock"]:
            stats["paused"] += time.time() - t_pause
        render_pause.clear()
        pause_evt.clear()

    MAX_INFLIGHT = args.threads * 2
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            ip_iter   = iter(remaining_ips)
            pending   = set()
            exhausted = False

            while not (shutdown.is_set() or want_reached.is_set() or host_refuses.is_set()):
                if pause_evt is not None and pause_evt.is_set():
                    if pending:
                        done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                        for f in done:
                            try: f.result()
                            except Exception: pass
                        continue
                    run_batch()
                    continue

                while not exhausted and len(pending) < MAX_INFLIGHT:
                    try:
                        ip = next(ip_iter)
                    except StopIteration:
                        exhausted = True
                        break
                    pending.add(executor.submit(worker, ip, args, cfg, result_q))

                if not pending:
                    break  # nothing left to submit, nothing in flight

                done, pending = wait(pending, timeout=0.3, return_when=FIRST_COMPLETED)
                for f in done:
                    try: f.result()
                    except Exception: pass
            # leaving the with-block waits for the (at most --wait seconds long) in-flight probes
    except Exception:
        pass

    result_q.join()
    stop_proc.set(); pt.join(timeout=3)

    if args.speed_test and not (shutdown.is_set() or want_reached.is_set() or host_refuses.is_set()):
        render_pause.set()
        time.sleep(0.6)
        clear_screen(); print(BANNER)
        run_speed_test_phase(untested(), args, cfg)
    stop_disp.set(); dt.join(timeout=2)

    autosave(args, cfg, scan_id, force=True)

    clear_screen()
    print(BANNER)
    with stats["lock"]:
        s = dict(stats)

    verb = ("Stopped by Ctrl+C" if shutdown.is_set()
            else "Stopped: no usable speed-test server" if host_refuses.is_set()
            else f"Stopped: found the {args.want} IPs you wanted" if want_reached.is_set()
            else "Scan complete")
    if host_refuses.is_set():
        print(f"\n  {CR}{B}✘ {verb}{R}\n")
        for l in stop_notes:
            print(f"  {l}")
        print()
    else:
        print(f"\n  {CG}{B}✔ {verb}!{R}\n")
    print(f"  {CW}{'Total IPs':<26}{R}{CY}{B}{s['total']:>10,}{R}")
    print(f"  {CW}{'Processed':<26}{R}{CC}{B}{s['processed']:>10,}{R}")
    if cfg:
        print(f"  {CG}{('✔ WS 101 OK' if args.no_verify else '✔ Tunnel OK'):<26}{R}{CG}{B}{s['ws_ok']:>10,}{R}")
        print(f"  {CY}{'✘ WS ok, tunnel dead':<26}{R}{CY}{s['tunnel_dead']:>10,}{R}")
    print(f"  {CM}{'✔ TLS 1.3':<26}{R}{CM}{B}{s['tls13']:>10,}{R}")
    print(f"  {CY}{'✔ TLS 1.2':<26}{R}{CY}{s['tls12']:>10,}{R}")
    print(f"  {CC}{'✔ TCP/Ping':<26}{R}{CC}{s['tcp_only']:>10,}{R}")
    print(f"  {CR}{'✘ Dead':<26}{R}{CR}{s['dead']:>10,}{R}")
    if args.speed_test:
        print(f"  {CG}{'⚡ Passed speed test':<26}{R}{CG}{B}{s['passed']:>10,}{R}")
        print(f"  {CR}{'Rejected (slow/failed)':<26}{R}{CR}{s['slow'] + s['failed']:>10,}{R}")
        print(f"  {CM}{'Not speed-tested yet':<26}{R}{CW}{s['untested']:>10,}{R}")

    with alive_lock:
        top = sorted((e for e in alive_ips if e.get("verdict") == "pass"),
                     key=lambda e: sort_key(e, args.sort))[:10]
    if top:
        print(f"\n  {CY}{B}Top {len(top)} (real speed through your tunnel):{R}")
        for e in top:
            ul = "" if e.get("upload_mbps") is None else f"  ↑{fmt_speed(e['upload_mbps'])}"
            print(f"  {CG}{e['ip']:<18}{R} {CG}↓{fmt_speed(e['download_mbps'])}{R}{CG}{ul}{R}"
                  f"  {CGR}{e.get('tunnel_ms') or '?'}ms{R}")

    print(f"\n  {CG}Results → {B}{args.output}{R}")
    print(f"  {CC}Resume  → {B}{args.resume}{R}")
    with alive_lock:
        usable = sum(1 for e in alive_ips if e.get("method") == "ws"
                     and (e.get("verdict") == "pass" if args.speed_test else e.get("verdict") in (None, "pass")))
    if cfg and usable > 0:
        kind = "speed-tested " if args.speed_test else ""
        print(f"\n  {CG}{B}✔ {usable} {kind}vless:// URIs are inside {args.output} → 'vless_uri' field{R}")
    order = {"download": "download speed", "upload": "upload speed", "delay": "tunnel delay"}[args.sort]
    print(f"\n  {CGR}Sorted best first by {order} (rejected IPs are listed separately){R}")
    with alive_lock:
        up_rejected = sum(1 for e in alive_ips if e.get("verdict") in ("slow", "fail")
                          and str(e.get("reason", "")).startswith("upload"))
    if args.speed_test and up_rejected >= 3 and s["passed"] == 0:
        print(f"\n  {CY}{B}⚠ {up_rejected} IPs passed the download test and were rejected ONLY by the upload test.{R}\n"
              f"    {CW}If your own uplink is the limit, run again with a lower --min-upload "
              f"(now {args.min_upload:g} Mbps) or with --no-upload.{R}")
    print()

if __name__ == "__main__":
    main()
