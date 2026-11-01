#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   CF-SCAN  ·  SNI search  ·  which SNI is fastest on which IP ║
╚══════════════════════════════════════════════════════════════╝

The SNI a DPI sees decides whether a connection is blocked, throttled or left alone, and a
Cloudflare IP may treat SNIs differently from another one. This tool takes the best IPs found by
cf_ping.py and a long list of candidate SNIs (sni_list.txt) and tells you which (IP, SNI) pairs
give the best REAL speed through YOUR VLESS config.

Stages (each one only looks at what the previous one let through):
  1. REACH   every SNI on every IP: a ClientHello with that SNI is sent (byte for byte the packet
             sni-spoof-rs injects / its `scan` sends); a ServerHello back = the DPI let it pass.
             No admin rights, no config needed.
  2. PROBE   the surviving SNIs get a short real speed test (download) through your tunnel.
  3. MATRIX  the best SNIs x the IPs they passed on: full download + upload, one at a time.
             Your own SNI is measured too, as the baseline to beat.

Two ways to carry the SNI (--mode):
  direct   the SNI is the REAL SNI of the connection (Host header stays yours). Works only if
           Cloudflare serves your domain under a different SNI (domain fronting).
  spoof    sni-spoof-rs (https://github.com/therealaleph/sni-spoofing-rust) runs with one listener
           per pair: the DPI sees the fake SNI, Cloudflare sees your real one. Needs that tool and
           Administrator/root. THIS is what to use if you use SNI-spoofing.

Usage (IPs come from ./cf_results.json, the output of cf_ping.py, unless you give --ips):
  python3 sni_scan.py --mode reach                                       # which SNIs pass at all? (no admin, no config)
  sudo python3 sni_scan.py -c "vless://..." --spoof-bin ./sni-spoof-rs-linux-amd64   # real ranking via sni-spoof-rs
  python3 sni_scan.py -c "vless://..."                                   # direct mode (SNI = the real SNI)
  python3 sni_scan.py --ips 104.18.4.130,172.67.139.236                  # reach only, for these IPs
"""
import argparse
import atexit
import collections
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime
from types import SimpleNamespace

import cf_ping as C

HERE         = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LIST = os.path.join(HERE, "sni_list.txt")
RELEASES_URL = "https://github.com/therealaleph/sni-spoofing-rust/releases/latest"


# ─── The ClientHello sni-spoof-rs injects (ported from its src/packet/tls.rs, MIT) ────────────────
# A fixed 517-byte TLS 1.3 ClientHello; only the SNI and three random fields change and the padding
# extension keeps the size constant. Probing with these exact bytes tells how the DPI treats the packet
# the spoof tool would send.
_TPL = bytes.fromhex(
    "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a2300948"
    "15ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b00"
    "6700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104"
    "002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b08040805"
    "0806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44a"
    "b3ad55616c36e0613473e2338770efdaa98693d217001500d5")
_TPL_SNI       = b"mci.ir"
CLIENT_HELLO_SIZE = 517


def build_client_hello(sni):
    name = sni.encode("idna") if not sni.isascii() else sni.encode("ascii")
    if len(name) > 219:
        raise ValueError("SNI too long (max 219 bytes)")
    n = len(_TPL_SNI)
    out = bytearray(_TPL[:11])
    out += os.urandom(32)                                   # client random
    out.append(0x20)
    out += os.urandom(32)                                   # session id
    out += _TPL[76:120]                                     # cipher suites ... up to the SNI extension type
    out += struct.pack(">H", len(name) + 5)                 # extension length
    out += struct.pack(">H", len(name) + 3)                 # server_name list length
    out += b"\x00" + struct.pack(">H", len(name)) + name    # host_name entry
    out += _TPL[127 + n:262 + n]                            # the extensions after the SNI
    out += os.urandom(32)                                   # x25519 key share
    pad = 219 - len(name)
    out += b"\x00\x15" + struct.pack(">H", pad) + b"\x00" * pad
    assert len(out) == CLIENT_HELLO_SIZE
    return bytes(out)


def parse_sni(hello):
    """The SNI inside a hello built by build_client_hello (None if it is not one)."""
    if len(hello) < CLIENT_HELLO_SIZE:
        return None
    n = struct.unpack(">H", hello[125:127])[0]
    return hello[127:127 + n].decode("ascii", "replace")


# ─── Stage 1: does a ClientHello with this SNI get an answer? ──────────────────────────────────
def probe_sni(ip, port, sni, timeout):
    """
    One probe, like `sni-spoof-rs scan`: connect, send the ClientHello, read the first reply byte.
    outcome: ok (0x16 ServerHello) | alert (0x15, the server itself refused that SNI - the DPI did not
    block it) | reset | timeout | closed | connect failed/timeout | bad response
    """
    t0 = C.now()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except socket.timeout:
        return {"outcome": "connect timeout"}
    except OSError as e:
        return {"outcome": "connect failed", "note": (e.strerror or str(e))[:40]}
    try:
        t1 = C.now()
        s.settimeout(timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(build_client_hello(sni))
        first = s.recv(5)
        t2 = C.now()
    except socket.timeout:
        return {"outcome": "timeout"}
    except ConnectionResetError:
        return {"outcome": "reset"}
    except OSError as e:
        return {"outcome": "error", "note": (e.strerror or str(e))[:40]}
    finally:
        s.close()
    if not first:
        return {"outcome": "closed"}
    kind = {0x16: "ok", 0x15: "alert"}.get(first[0], f"bad response 0x{first[0]:02x}")
    return {"outcome": kind, "connect_ms": round((t1 - t0) * 1000, 1), "reply_ms": round((t2 - t1) * 1000, 1)}


def reach_stage(ips, snis, port, timeout, threads):
    pairs = [(ip, sni) for sni in snis for ip in ips]
    random.shuffle(pairs)                                   # don't hit one IP with a burst
    res, cnt, lock = {}, collections.Counter(), threading.Lock()
    t0 = time.time()

    def work(p):
        if C.shutdown.is_set():
            return
        r = probe_sni(p[0], port, p[1], timeout)
        with lock:
            res[p] = r
            cnt[r["outcome"] if r["outcome"] in ("ok", "alert") else "fail"] += 1

    with ThreadPoolExecutor(max_workers=threads) as ex:
        pending = {ex.submit(work, p) for p in pairs}
        while pending:
            _, pending = wait(pending, timeout=0.5)
            with lock:
                line = (f"\r  {len(res)}/{len(pairs)}   ok {cnt['ok']}   alert {cnt['alert']}   "
                        f"blocked/failed {cnt['fail']}   {time.time() - t0:.0f}s   ")
            sys.stdout.write(line)
            sys.stdout.flush()
    sys.stdout.write("\n")
    return res


def passing(reach, accept):
    """{sni: [(ip, reply_ms), ...]} for the probes whose outcome is in `accept`, best SNI first."""
    by = collections.defaultdict(list)
    for (ip, sni), r in reach.items():
        if r["outcome"] in accept:
            by[sni].append((ip, r.get("reply_ms", 9999)))
    return sorted(by.items(), key=lambda kv: (-len(kv[1]), min(x[1] for x in kv[1]), kv[0]))


# ─── Carrying the SNI: directly, or through sni-spoof-rs ───────────────────────────────────────
def fmt_addr(ip):
    return f"[{ip}]" if ":" in ip else ip


def is_admin():
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


class Direct:
    """The candidate SNI is the real SNI of the connection (Host / path / UUID stay yours)."""
    name = "direct"
    max_batch = None

    def __init__(self, cfg):
        self.cfg = cfg

    def prepare(self, pairs):
        pass

    def route(self, ip, sni):
        return ip, dict(self.cfg, sni=sni)

    def close(self):
        pass


class SpoofError(Exception):
    pass


class Done(Exception):
    """Nothing more to measure (not an error)."""


def batches(items, n):
    n = n or len(items) or 1
    for i in range(0, len(items), n):
        yield items[i:i + n]


def free_port(start):
    for p in range(start, start + 2000):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise SpoofError("no free local port found")


class Spoof:
    """
    Runs ONE sni-spoof-rs process with a listener per (IP, fake SNI) pair: connecting to the listener's
    local port reaches that IP with that fake SNI injected, while the TLS inside is still your real one.
    """
    name = "spoof"
    max_batch = 64                                          # listeners per sni-spoof-rs process

    def __init__(self, cfg, binary, base_port):
        self.cfg, self.binary, self.base_port = cfg, binary, base_port
        self.ports, self.proc, self.tmp, self.log, self.log_path = {}, None, None, None, None
        atexit.register(self.close)

    def prepare(self, pairs):
        self.close()
        self.ports, listeners, port = {}, [], self.base_port
        for ip, sni in pairs:
            port = free_port(port)
            self.ports[(ip, sni)] = port
            listeners.append({"listen": f"127.0.0.1:{port}", "connect": f"{fmt_addr(ip)}:{self.cfg['port']}",
                              "fake_sni": sni, "conn_timeout_sec": 5, "handshake_timeout_sec": 3})
            port += 1
        self.tmp = tempfile.mkdtemp(prefix="sni_scan_")
        conf = os.path.join(self.tmp, "config.json")
        with open(conf, "w", encoding="utf-8") as f:
            json.dump({"graceful_shutdown_sec": 0, "listeners": listeners}, f, indent=1)
        self.log_path = os.path.join(self.tmp, "spoof.log")
        self.log = open(self.log_path, "a", encoding="utf-8", errors="replace")      # append: the child's writes never overlap
        env = dict(os.environ)
        env.setdefault("RUST_LOG", "info")                  # so each listener announces itself
        try:
            self.proc = subprocess.Popen([self.binary, conf], stdout=self.log, stderr=subprocess.STDOUT, env=env,
                                         cwd=os.path.dirname(os.path.abspath(self.binary)) or None)
        except OSError as e:
            hint = " - on Linux/macOS make it executable first: chmod +x " + self.binary if isinstance(e, PermissionError) else ""
            raise SpoofError(f"cannot run {self.binary}: {e}{hint}")
        self._wait_ready(len(listeners))

    def _log_text(self):
        try:
            with open(self.log_path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def _wait_ready(self, n):
        t0, deadline = time.time(), time.time() + 10 + 0.05 * n
        last = max(self.ports.values())
        while time.time() < deadline:
            if self.proc.poll() is not None:
                tail = "\n".join(self._log_text().strip().splitlines()[-12:])
                raise SpoofError(f"sni-spoof-rs stopped right away (exit {self.proc.returncode}). It needs "
                                 f"Administrator/root (raw packets).\n--- its output:\n{tail}")
            if len(re.findall(r"listener started", self._log_text())) >= n:
                return
            if time.time() - t0 > 3:                        # older builds don't log: look at the last port instead
                with socket.socket() as s:
                    s.settimeout(0.3)
                    if s.connect_ex(("127.0.0.1", last)) == 0:
                        return
            time.sleep(0.2)
        raise SpoofError("sni-spoof-rs did not start listening in time")

    def warnings(self):
        text = self._log_text() if self.tmp else ""
        return len(re.findall(r"timeout waiting for fake ACK", text))

    def route(self, ip, sni):
        return "127.0.0.1", dict(self.cfg, port=self.ports[(ip, sni)])

    def close(self):
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try: self.proc.kill()
                except Exception: pass
            self.proc = None
        if self.log is not None:
            try: self.log.close()
            except Exception: pass
            self.log = None
        if self.tmp:
            shutil.rmtree(self.tmp, ignore_errors=True)
            self.tmp = None


def find_spoof_bin(explicit):
    """
    The sni-spoof-rs executable: --spoof-bin, else next to this script, in the current folder or on PATH.
    Release files are called sni-spoof-rs-linux-amd64, sni-spoof-rs-macos-arm64 ..., and sni-spoof-rs.exe
    inside the Windows zip (the *-ui* files are the desktop app, not this).
    """
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    plat = "linux" if sys.platform.startswith("linux") else "macos" if sys.platform == "darwin" else "windows"
    arch = "arm64" if platform.machine().lower() in ("aarch64", "arm64") else "amd64"

    def fits(name):
        n = name.lower()
        if not n.startswith("sni-spoof-rs") or "-ui" in n or n.endswith((".zip", ".gz", ".tar", ".md", ".json", ".txt", ".log")):
            return False
        if n.endswith(".exe") != (os.name == "nt"):
            return False
        for marker, mine in (("linux", plat), ("macos", plat), ("windows", plat), ("arm64", arch), ("amd64", arch)):
            if marker in n and marker != mine:
                return False
        return True

    for d in dict.fromkeys((HERE, os.getcwd())):
        try:
            names = sorted(os.listdir(d), key=lambda x: (x.lower() not in ("sni-spoof-rs", "sni-spoof-rs.exe"),
                                                         "musl" in x.lower(), x))
        except OSError:
            continue
        for n in names:
            if fits(n) and os.path.isfile(os.path.join(d, n)):
                return os.path.join(d, n)
    for n in (("sni-spoof-rs.exe",) if os.name == "nt" else ("sni-spoof-rs",)):
        p = shutil.which(n)
        if p:
            return p
    return None


# ─── Loading IPs and SNIs ──────────────────────────────────────────────────────────────────────
_NAME_RE = re.compile(r"^(?=.{1,219}$)([a-z0-9_]([a-z0-9_-]*[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")


def load_snis(path, limit):
    seen, out, bad = set(), [], 0
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            s = line.split("#", 1)[0].strip().lower().rstrip(".")
            if not s:
                continue
            try:
                s = s.encode("idna").decode("ascii")
            except UnicodeError:
                bad += 1; continue
            if not _NAME_RE.match(s):
                bad += 1; continue
            if s not in seen:
                seen.add(s); out.append(s)
    return (out[:limit] if limit else out), bad


def ips_from_results(path, top):
    """The best IPs of a cf_ping.py run: speed-tested winners first, then the untested ones by delay."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    items = data.get("results", [])
    good  = [e for e in items if e.get("verdict") == "pass"]
    rest  = sorted((e for e in items if not e.get("verdict")),
                   key=lambda e: e.get("tunnel_ms") or e.get("latency_ms") or 9999)
    return [e["ip"] for e in (good + rest)[:top]]


def load_ips(args):
    ips = []
    if args.ips:
        ips += [x.strip() for x in args.ips.split(",") if x.strip()]
    if args.ips_file:
        with open(args.ips_file, encoding="utf-8-sig") as f:
            ips += [l.split("#", 1)[0].strip() for l in f if l.split("#", 1)[0].strip()]
    if not ips:
        path = args.ips_from or ("cf_results.json" if os.path.exists("cf_results.json") else None)
        if path:
            ips = ips_from_results(path, args.top)
    out = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"  {C.CR}skipping '{ip}': not an IP address{C.R}")
            continue
        if ip not in out:
            out.append(ip)
    return out


# ─── Tunnel checks and speed tests (the engine of cf_ping.py) ──────────────────────────────────
def tunnel_check(pairs, ev, targs, threads=8):
    """WS upgrade + a request through the VLESS tunnel for each pair, many at once -> {pair: result}."""
    out, lock = {}, threading.Lock()

    def work(p):
        if C.shutdown.is_set():
            return
        dial, cfg2 = ev.route(*p)
        r = C.test_config(dial, cfg2, targs)
        with lock:
            out[p] = r

    C._run_pool(work, pairs, threads)
    return out


def quick_speed(ip, cfg, args, nbytes=1_000_000, secs=4.0):
    """Rough speed of one pair: how fast ~1 MB comes through the tunnel (or what arrives in `secs`). Raises on failure."""
    return C.with_failover("down", args.servers, lambda t: C.run_in_tunnel(
        ip, cfg, args, t, C.tunnel_download, secs, 0, until_bytes=nbytes))


def rough_screen(pairs, ev, qargs, threads=8):
    """Quick speed of many pairs at once (coarse on purpose: it only has to tell 0.5 Mbps from 20 Mbps)."""
    rough, errors, lock = {}, {}, threading.Lock()
    state = {"no_server": False}

    def work(p):
        if C.shutdown.is_set():
            return
        dial, cfg2 = ev.route(*p)
        try:
            v = quick_speed(dial, cfg2, qargs)
        except C.NoServer:
            state["no_server"] = True
            return
        except Exception as e:
            with lock: errors[p] = C._note(e)
            return
        with lock: rough[p] = v

    done = 0
    for chunk in batches(pairs, ev.max_batch):
        ev.prepare(chunk)
        C._run_pool(work, chunk, threads)
        done += len(chunk)
        sys.stdout.write(f"\r  {done}/{len(pairs)} pairs   measured {len(rough)}   failed {len(errors)}   ")
        sys.stdout.flush()
        if C.shutdown.is_set() or state["no_server"]:
            break
    sys.stdout.write("\n")
    return rough, errors, state["no_server"]


def speed_pairs(pairs, ev, margs, store, label):
    """Real speed of each pair, strictly one at a time (tests running together would share your bandwidth)."""
    for p in pairs:
        if C.shutdown.is_set():
            break
        dial, cfg2 = ev.route(*p)
        r = C.measure_ip(dial, cfg2, margs)
        if C.shutdown.is_set():                             # Ctrl+C: what was cut off half-way is not a result
            break
        store[p] = r
        v = r["verdict"]
        if v == "unjudged":
            print(f"\n  {C.CR}{C.B}No download test server answers your server - see the list above. "
                  f"Give --down-url a server your VPS can reach (README: Test against your own server).{C.R}")
            raise Done()
        ul = "" if r.get("upload_mbps") is None else f"  ↑{C.fmt_speed(r['upload_mbps'])}"
        if r.get("download_mbps") is not None and v in ("pass", "slow"):
            print(f"  {C.CG if v == 'pass' else C.CY}{'✔' if v == 'pass' else '~'} {p[0]:<18}{C.R} {p[1]:<34}"
                  f" ↓{C.fmt_speed(r['download_mbps'])}{ul}  {C.CGR}{label}{C.R}")
        else:
            print(f"  {C.CR}✘ {p[0]:<18}{C.R} {p[1]:<34} {C.CR}{r.get('reason', '')[:70]}{C.R}")


def report_tunnel_failures(chk, mode):
    """Why do whole groups of pairs fail the tunnel check? (fronting refused, spoof tool trouble ...)"""
    notes = collections.Counter(r.get("note", "?").replace("WS ok, tunnel dead: ", "") for r in chk.values()
                                if r.get("method") != "ws")
    if not notes:
        return
    print(f"  {C.CGR}tunnel check failures:{C.R} " + "; ".join(f"{n}× {k[:60]}" for k, n in notes.most_common(3)))
    http4 = sum(n for k, n in notes.items() if k.startswith("HTTP 4"))
    if mode == "direct" and http4 >= max(3, 0.5 * len(chk)):
        print(f"  {C.CY}{C.B}⚠ Cloudflare answers HTTP 4xx when the SNI differs from your domain (it does not accept "
              f"fronting for it).{C.R}\n    {C.CW}Direct mode cannot measure this. Use --mode spoof with sni-spoof-rs: "
              f"there the real SNI stays yours.{C.R}")


# ─── Report ────────────────────────────────────────────────────────────────────────────────────
def median(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.median(xs), 2) if xs else None


def summarize_snis(full):
    """Per SNI over the IPs it was measured on."""
    by = collections.defaultdict(list)
    for (ip, sni), r in full.items():
        by[sni].append((ip, r))
    rows = []
    for sni, items in by.items():
        ok = [r for _, r in items if r.get("verdict") == "pass"]
        rows.append({"sni": sni, "measured_on": len(items), "passed_on": len(ok),
                     "download_best": max((r["download_mbps"] for r in ok), default=None),
                     "download_median": median([r["download_mbps"] for r in ok]),
                     "upload_best": max((r["upload_mbps"] for r in ok if r.get("upload_mbps") is not None), default=None),
                     "upload_median": median([r.get("upload_mbps") for r in ok])})
    return rows


def entry(ip, sni, reach, chk, r):
    return {"ip": ip, "sni": sni, "reach_ms": (reach.get((ip, sni)) or {}).get("reply_ms"),
            "tunnel_ms": (chk.get((ip, sni)) or {}).get("tunnel_ms"), "verdict": r.get("verdict"),
            "download_mbps": r.get("download_mbps"), "upload_mbps": r.get("upload_mbps"),
            "reason": r.get("reason", ""), "tls": (chk.get((ip, sni)) or {}).get("tls")}


def write_exports(args, cfg, mode, reach, accept, ranked, outdir):
    paths = {}
    base = os.path.join(outdir, "sni_working.txt")
    with open(base, "w", encoding="utf-8") as f:
        f.write("# SNIs that passed on at least one IP, best first (same format as `sni-spoof-rs scan -o`)\n")
        for sni, rows in passing(reach, accept):
            f.write(sni + "\n")
    paths["working"] = base
    if not ranked:
        return paths
    top = ranked[:3]
    listeners, links = [], []
    for i, e in enumerate(top):
        port = 40443 + i
        listeners.append({"listen": f"127.0.0.1:{port}", "connect": f"{fmt_addr(e['ip'])}:{cfg['port']}",
                          "fake_sni": e["sni"], "conn_timeout_sec": 5, "handshake_timeout_sec": 2,
                          "keepalive_time_sec": 11, "keepalive_interval_sec": 2})
        if mode == "spoof":
            links.append(C.build_uri(dict(cfg, port=port), dict(e, ip="127.0.0.1")))
        else:
            links.append(C.build_uri(dict(cfg, sni=e["sni"]), e))
    conf = os.path.join(outdir, "sni_spoof_config.json")
    with open(conf, "w", encoding="utf-8") as f:
        json.dump({"graceful_shutdown_sec": 0, "listeners": listeners}, f, indent=2)
    lk = os.path.join(outdir, "sni_best_links.txt")
    with open(lk, "w", encoding="utf-8") as f:
        f.write(("# via sni-spoof-rs: start it with sni_spoof_config.json, then import ONE of these (they point at "
                 "127.0.0.1)\n") if mode == "spoof" else
                "# direct: the SNI is part of the link\n")
        f.write("\n".join(links) + "\n")
    paths.update(spoof_config=conf, links=lk)
    return paths


# ─── Main flow ─────────────────────────────────────────────────────────────────────────────────
def parse_args():
    ap = argparse.ArgumentParser(description="CF-SCAN SNI search: which SNI is fastest on which Cloudflare IP",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("-c", "--config", default=None, help="your vless:// link (needed for tunnel checks and speed tests)")
    ap.add_argument("--ips", default=None, help="comma-separated Cloudflare IPs to test")
    ap.add_argument("--ips-file", default=None, help="file with one IP per line")
    ap.add_argument("--ips-from", default=None, help="cf_results.json of cf_ping.py (default: ./cf_results.json)")
    ap.add_argument("--top", type=int, default=5, help="IPs taken from the results file, best first (default:5)")
    ap.add_argument("--snis", default=DEFAULT_LIST, help="candidate SNI list, one per line (default: sni_list.txt)")
    ap.add_argument("--max-snis", type=int, default=0, help="only the first N SNIs of the list (default: all)")
    ap.add_argument("-p", "--port", type=int, default=None, help="port (default: from the config, else 443)")
    ap.add_argument("--mode", choices=["reach", "direct", "spoof"], default=None,
                    help="reach = stage 1 only; direct = SNI is the real SNI; spoof = through sni-spoof-rs "
                         "(default: spoof if --spoof-bin is given, else direct if -c is given, else reach)")
    ap.add_argument("--spoof-bin", default=None, help="path of sni-spoof-rs(.exe); needs Administrator/root")
    ap.add_argument("--spoof-base-port", type=int, default=41000, help="first local port for the spoof listeners (default:41000)")
    ap.add_argument("-t", "--threads", type=int, default=100, help="parallel probes in stage 1 (default:100)")
    ap.add_argument("-w", "--wait", type=float, default=4.0, help="timeout per probe / step in seconds (default:4)")
    ap.add_argument("--max-probe", type=int, default=300, help="SNIs that get the rough 1 MB screen, 0 = all that passed (default:300)")
    ap.add_argument("--probe-snis", type=int, default=30, help="best SNIs of the rough screen that get the accurate probe, 0 = all (default:30)")
    ap.add_argument("--probe-time", type=float, default=3.0, help="seconds of the quick speed probe (default:3)")
    ap.add_argument("--top-snis", type=int, default=6, help="best SNIs that go to the full IP x SNI stage (default:6)")
    ap.add_argument("--speed-time", type=float, default=5.0, help="seconds per full download / upload measurement (default:5)")
    ap.add_argument("--min-download", type=float, default=1.0, help="abort pairs slower than this (Mbps, default:1)")
    ap.add_argument("--min-upload", type=float, default=0.5, help="abort pairs slower than this (Mbps, default:0.5)")
    ap.add_argument("--no-upload", action="store_true", help="skip the upload test")
    ap.add_argument("--no-baseline", action="store_true", help="don't measure your own SNI as the reference")
    ap.add_argument("--down-url", default=None, help="download URL, {bytes} = request size (default: automatic)")
    ap.add_argument("--up-url", default=None, help="upload URL (default: automatic)")
    ap.add_argument("--sort", choices=["download", "upload", "delay"], default="download", help="ranking (default:download)")
    ap.add_argument("-o", "--output", default="sni_results.json", help="results JSON (default:sni_results.json)")
    return ap.parse_args()


def run(args):
    print(f"\n{C.CY}{C.B}  CF-SCAN · SNI search{C.R}\n")
    cfg = None
    if args.config:
        cfg = C.parse_vless(args.config)
        if not cfg:
            sys.exit(1)
        if args.port:
            cfg["port"] = args.port
    port = args.port or (cfg["port"] if cfg else 443)

    mode = args.mode or ("spoof" if args.spoof_bin else "direct" if cfg else "reach")
    if mode in ("direct", "spoof") and not cfg:
        sys.exit(f"  {C.CR}--mode {mode} needs -c/--config (the speed is measured through your tunnel).{C.R}")
    binary = None
    if mode == "spoof":
        binary = find_spoof_bin(args.spoof_bin)
        if not binary:
            sys.exit(f"  {C.CR}sni-spoof-rs not found. Download it from {RELEASES_URL} and pass --spoof-bin PATH "
                     f"(or put it next to this script).{C.R}")
        if not is_admin():
            print(f"  {C.CY}⚠ Not running as {'Administrator' if os.name == 'nt' else 'root'}: sni-spoof-rs captures raw "
                  f"packets and will most likely refuse to start.{C.R}")

    ips = load_ips(args)
    if not ips:
        sys.exit(f"  {C.CR}No IPs. Give --ips, --ips-file or --ips-from (cf_results.json from cf_ping.py).{C.R}")
    try:
        snis, bad = load_snis(args.snis, args.max_snis)
    except OSError as e:
        sys.exit(f"  {C.CR}Cannot read the SNI list: {e}{C.R}")
    if not snis:
        sys.exit(f"  {C.CR}The SNI list is empty.{C.R}")
    print(f"  {C.CW}Mode:{C.R} {mode}   {C.CW}IPs:{C.R} {len(ips)}   {C.CW}SNIs:{C.R} {len(snis)}"
          + (f" ({bad} invalid lines skipped)" if bad else "") + f"   {C.CW}port:{C.R} {port}")
    print("  " + "  ".join(ips[:8]) + (" …" if len(ips) > 8 else "") + "\n")

    def on_sigint(sig, frm):
        if C.shutdown.is_set():
            os._exit(130)
        C.shutdown.set()
        print(f"\n  {C.CY}stopping … (Ctrl+C again to quit at once){C.R}")
    signal.signal(signal.SIGINT, on_sigint)

    accept = {"ok", "alert"} if mode == "spoof" else {"ok"}
    out = {"generated_at": datetime.now().isoformat(), "mode": mode, "ips": ips, "port": port, "snis_tested": len(snis)}

    # ── Stage 1 ────────────────────────────────────────────────────────────────────────────────
    print(f"{C.CM}{C.B}▸ Stage 1 — reach: does a ClientHello with each SNI get an answer?{C.R}")
    print(f"  {len(ips)} IPs × {len(snis)} SNIs = {len(ips) * len(snis)} probes, {args.threads} at a time, "
          f"{args.wait:g}s timeout (the same packet sni-spoof-rs sends)")
    reach = reach_stage(ips, snis, port, args.wait, args.threads)

    # an IP that nobody can connect to would only waste time later
    tried, no_conn = collections.Counter(), collections.Counter()
    for (i, _), r in reach.items():
        tried[i] += 1
        no_conn[i] += r["outcome"].startswith("connect")
    dead = [ip for ip in ips if tried[ip] and no_conn[ip] >= 0.9 * tried[ip]]
    for ip in dead:
        print(f"  {C.CY}⚠ {ip}: {len(snis)} probes could not connect to port {port} - the IP is down, blocked or "
              f"does not listen there; dropped{C.R}")
    ips = [ip for ip in ips if ip not in dead]
    ranked_reach = passing(reach, accept)
    on_all  = sum(1 for _, rows in ranked_reach if len(rows) == len(ips))
    on_some = len(ranked_reach) - on_all
    kinds = collections.Counter(r["outcome"] for r in reach.values())
    print(f"  {C.CG}{C.B}{len(ranked_reach)} of {len(snis)} SNIs pass{C.R}  (on all {len(ips)} IPs: {on_all} · only on some IPs: {on_some})")
    print(f"  {C.CGR}outcomes: " + ", ".join(f"{k} {v}" for k, v in kinds.most_common(6)) + C.R)
    some = [(s, rows) for s, rows in ranked_reach if len(rows) < len(ips)][:3]
    for sni, rows in some:
        print(f"    {C.CGR}only on some IPs:{C.R} {sni} → {', '.join(ip for ip, _ in rows)}")
    stage1 = collections.defaultdict(dict)
    for (ip, sni), r in reach.items():
        stage1[sni][ip] = [r["outcome"], r.get("reply_ms")]
    out["stage1"] = stage1
    paths = {}
    if mode == "reach" or not ranked_reach or C.shutdown.is_set():
        if not ranked_reach:
            print(f"\n  {C.CR}{C.B}No SNI passed on any IP.{C.R} Check the IPs (cf_ping.py), the timeout (-w), or your network.")
        paths = write_exports(args, cfg or {"port": port}, mode, reach, accept, [], os.path.dirname(os.path.abspath(args.output)) or ".")
        C._atomic_write(args.output, out)
        print(f"\n  {C.CG}Working SNIs → {paths['working']}{C.R}\n  {C.CG}Details      → {args.output}{C.R}\n")
        return

    # ── common setup for the speed stages ────────────────────────────────────────────────────────
    servers = C.TestServers([C.parse_url(u) for u in ([args.down_url] if args.down_url else C.DOWN_URLS)],
                            [C.parse_url(u) for u in ([args.up_url] if args.up_url else C.UP_URLS)])
    targs = SimpleNamespace(wait=args.wait, no_verify=False, verify_target=C.parse_url(C.VERIFY_URL))
    qargs = SimpleNamespace(servers=servers, wait=args.wait)
    pargs = SimpleNamespace(servers=servers, wait=args.wait, speed_time=args.probe_time, min_download=0.0,
                            min_upload=0.0, no_upload=True)
    margs = SimpleNamespace(servers=servers, wait=args.wait, speed_time=args.speed_time, min_download=args.min_download,
                            min_upload=args.min_upload, no_upload=args.no_upload)
    ev = Spoof(cfg, binary, args.spoof_base_port) if mode == "spoof" else Direct(cfg)
    direct = Direct(cfg)
    order = {ip: i for i, ip in enumerate(ips)}             # the order you gave / cf_results.json had: best IP first
    chk_all, rough, probe, full, base = {}, {}, {}, {}, {}
    try:
        # ── Stage 2 ──────────────────────────────────────────────────────────────────────────────
        # too many to speed-test them all: take the ones that passed on the most IPs, then the list's own order
        # (it starts with the best-known names); a probe's reply time says nothing about throughput
        place = {sni: i for i, sni in enumerate(snis)}
        cand = sorted(ranked_reach, key=lambda kv: (-len(kv[1]), place[kv[0]]))
        cand = cand[:args.max_probe] if args.max_probe else cand
        # every SNI is probed on the SAME IP (the best one it passed on) so the numbers compare SNIs, not IPs
        pairs2 = [(min(rows, key=lambda r: order[r[0]])[0], sni) for sni, rows in cand]
        on_first = sum(1 for ip, _ in pairs2 if ip == ips[0])
        print(f"\n{C.CM}{C.B}▸ Stage 2 — speed probe of {len(pairs2)} SNIs, {on_first} of them on {ips[0]}{C.R}")
        if len(cand) < len(ranked_reach):
            print(f"  {C.CGR}{len(ranked_reach) - len(cand)} more SNIs passed stage 1 but get no speed test "
                  f"(--max-probe {args.max_probe}, taken in list order; --max-probe 0 tests all of them){C.R}")
        if not args.no_baseline and cfg["sni"] not in snis:
            print(f"\n  {C.CW}Reference: your own SNI ({cfg['sni']}), no spoofing{C.R}")
            bp = [(ips[0], cfg["sni"])]
            if tunnel_check(bp, direct, targs).get(bp[0], {}).get("method") == "ws":
                speed_pairs(bp, direct, margs, base, "your SNI")
            else:
                print(f"  {C.CY}your own SNI does not even carry the tunnel on {ips[0]} - nothing to compare with{C.R}")
        print(f"\n  {C.CW}2a. rough screen: ~1 MB per pair, 8 at a time{C.R}")
        rough, errors, no_server = rough_screen(pairs2, ev, qargs)
        if no_server:
            raise Done()
        notes = collections.Counter(errors.values())
        if notes and not C.shutdown.is_set():
            print(f"  {C.CGR}failures:{C.R} " + "; ".join(f"{n}× {k[:60]}" for k, n in notes.most_common(3)))
            http4 = sum(n for k, n in notes.items() if k.startswith("HTTP 4"))
            if mode == "direct" and http4 >= max(3, 0.5 * len(pairs2)):
                print(f"  {C.CY}{C.B}⚠ Cloudflare answers HTTP 4xx when the SNI differs from your domain (no fronting for it).{C.R}\n"
                      f"    {C.CW}Direct mode cannot measure this. Use --mode spoof with sni-spoof-rs: there the real SNI stays yours.{C.R}")
        if mode == "spoof" and ev.warnings():
            print(f"  {C.CY}⚠ sni-spoof-rs logged {ev.warnings()}× 'timeout waiting for fake ACK': it could not confirm its "
                  f"injected packet (admin rights? WinDivert files? another VPN capturing packets?){C.R}")
        ranked2 = sorted(rough, key=lambda p: -rough[p])
        if C.shutdown.is_set():
            raise Done()
        if not ranked2:
            print(f"\n  {C.CR}{C.B}No pair carries the tunnel, so there is nothing to measure.{C.R}")
            raise Done()
        print(f"  best rough speeds: " + ", ".join(f"{p[1]} {rough[p]:.1f}" for p in ranked2[:4]) + " Mbps")

        finalists = ranked2[:args.probe_snis] if args.probe_snis else ranked2
        print(f"\n  {C.CW}2b. accurate probe: the best {len(finalists)}, {args.probe_time:g}s each, one at a time{C.R}\n")
        for chunk in batches(finalists, ev.max_batch):
            ev.prepare(chunk)
            speed_pairs(chunk, ev, pargs, probe, f"probe {args.probe_time:g}s")
            if C.shutdown.is_set():
                break
        by_probe = sorted((p for p in probe if probe[p].get("download_mbps") is not None),
                          key=lambda p: -probe[p]["download_mbps"])
        top = []
        for p in by_probe:
            if p[1] not in top:
                top.append(p[1])
        top = top[:args.top_snis]
        if not top or C.shutdown.is_set():
            raise Done()

        # ── Stage 3 ──────────────────────────────────────────────────────────────────────────────
        reach_ips = {sni: [ip for ip, _ in rows] for sni, rows in ranked_reach}
        matrix = [(ip, sni) for sni in top for ip in sorted(reach_ips[sni], key=order.get)]
        print(f"\n{C.CM}{C.B}▸ Stage 3 — matrix: the best {len(top)} SNIs on every IP they passed ({len(matrix)} pairs): "
              f"download{'' if args.no_upload else ' + upload'}, {args.speed_time:g}s each, one at a time{C.R}")
        if not args.no_baseline and cfg["sni"] not in snis:
            bpairs = [(ip, cfg["sni"]) for ip in ips if (ip, cfg["sni"]) not in base]
            if bpairs:
                print(f"\n  {C.CW}Reference: your own SNI on the other IPs{C.R}")
                bchk = tunnel_check(bpairs, direct, targs)
                speed_pairs([p for p in bpairs if bchk.get(p, {}).get("method") == "ws"], direct, margs, base, "your SNI")
        print()
        for chunk in batches(matrix, ev.max_batch):
            ev.prepare(chunk)
            chk = tunnel_check(chunk, ev, targs)
            chk_all.update(chk)
            report_tunnel_failures(chk, mode)
            speed_pairs([p for p in chunk if chk.get(p, {}).get("method") == "ws"], ev, margs, full, "full")
            if C.shutdown.is_set():
                break
    except Done:
        pass
    except SpoofError as e:
        print(f"\n  {C.CR}{C.B}✘ {e}{C.R}")
    finally:
        ev.close()

    # ── Report ───────────────────────────────────────────────────────────────────────────────────
    good = [entry(ip, sni, reach, chk_all, r) for (ip, sni), r in full.items()
            if r.get("verdict") == "pass" and r.get("download_mbps") is not None]
    good.sort(key=lambda e: C.sort_key(e, args.sort))
    probes_ok = [entry(ip, sni, reach, chk_all, r) for (ip, sni), r in probe.items() if r.get("download_mbps") is not None]
    out["rough_screen"] = {f"{ip} {sni}": round(v, 2) for (ip, sni), v in rough.items()}
    probes_ok.sort(key=lambda e: -(e["download_mbps"] or 0))
    shown = good or probes_ok
    out["baseline"] = [entry(ip, sni, reach, {}, r) for (ip, sni), r in base.items()]
    out["probe"], out["matrix"] = probes_ok, [entry(ip, sni, reach, chk_all, r) for (ip, sni), r in full.items()]
    out["ranking"] = good
    out["per_sni"] = sorted(summarize_snis(full), key=lambda r: -(r["download_median"] or 0))
    paths = write_exports(args, cfg, mode, reach, accept, shown, os.path.dirname(os.path.abspath(args.output)) or ".")
    C._atomic_write(args.output, out)

    print(f"\n{C.CY}{C.B}══ Result ══{C.R}")
    if C.shutdown.is_set():
        print(f"  {C.CY}Stopped early - what follows is only what was measured until then.{C.R}")
    if base:
        for (ip, sni), r in sorted(base.items()):
            if r.get("download_mbps") is not None:
                ul = "" if r.get("upload_mbps") is None else f"  ↑{C.fmt_speed(r['upload_mbps'])}"
                print(f"  {C.CGR}reference {ip:<18} your SNI {sni}  ↓{C.fmt_speed(r['download_mbps'])}{ul}{C.R}")
    if not shown:
        print(f"  {C.CR}Nothing could be measured{'' if C.shutdown.is_set() else ' - see the messages above'}.{C.R}")
    else:
        what = "full download/upload" if good else "quick download probe only"
        print(f"  {C.CW}Best (IP, SNI) pairs ({what}):{C.R}")
        for i, e in enumerate(shown[:10], 1):
            ul = "" if e["upload_mbps"] is None else f"  ↑{C.fmt_speed(e['upload_mbps'])}"
            print(f"  {i:>2}. {C.CG}{e['ip']:<18}{C.R} {e['sni']:<34} ↓{C.fmt_speed(e['download_mbps'])}{ul}"
                  f"  {C.CGR}reach {e['reach_ms']} ms · tunnel {e['tunnel_ms']} ms{C.R}")
        sn = [r for r in out["per_sni"] if r["passed_on"]]
        if len(sn) > 1:
            print(f"\n  {C.CW}Best SNIs overall (median over the IPs they were measured on):{C.R}")
            for r in sn[:6]:
                ub = "" if r["upload_median"] is None else f"  ↑ {r['upload_median']} Mbps"
                print(f"      {r['sni']:<34} ↓ {r['download_median']} Mbps{ub}   ({r['passed_on']}/{r['measured_on']} IPs)")
        if base and good:
            bests = max((r["download_mbps"] for r in base.values() if r.get("download_mbps") is not None), default=None)
            if bests and good[0]["download_mbps"]:
                print(f"\n  {C.CW}Best pair vs. your own SNI:{C.R} ↓ {good[0]['download_mbps']} vs {bests} Mbps "
                      f"({good[0]['download_mbps'] / bests:.1f}×)")
        print(f"\n  {C.CGR}Each number is one measurement: repeat for the finalists before trusting a small difference.{C.R}")
    print()
    for label, p in [("Results", args.output)] + [(label, paths[k]) for k, label in (
            ("working", "Working SNIs"), ("spoof_config", "sni-spoof-rs"), ("links", "Links")) if k in paths]:
        print(f"  {C.CG}{label:<13}→ {p}{C.R}")
    if "spoof_config" in paths:
        how = ("sudo ./sni-spoof-rs sni_spoof_config.json   (Windows: as Administrator), then import a link from sni_best_links.txt"
               if mode == "spoof" else
               "import a link from sni_best_links.txt; to try them with sni-spoof-rs use sni_spoof_config.json")
        print(f"  {C.CGR}{how}{C.R}")
    print()


def main():
    C.setup_console()
    args = parse_args()
    try:
        run(args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
