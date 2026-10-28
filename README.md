# CF-SCAN — Cloudflare clean-IP scanner for VLESS + WebSocket

**English** · [فارسی](README.fa.md)

Finds Cloudflare IPs that really work **with your own VLESS + WebSocket (+TLS) config**, and measures the
**real download and upload speed through your tunnel** — the same path V2rayN / Xray use.

* Single file (`cf_ping.py`), **no dependencies** — Python 3.8+ standard library only
* Works on **Windows** and **Linux** (macOS should work too)
* Resume support, live dashboard, ready-to-import `vless://` links in the results

---

## Why v4 exists (the "10 Mbps here, 0.0 MB/s in V2rayN" bug)

Older versions listed an IP as good when a bare WebSocket handshake answered, and then "speed-tested" it by
downloading **directly from `speed.cloudflare.com`** through that IP. That only measures *your PC ↔ Cloudflare
edge*. Your real traffic is different:

```
V2rayN ──TLS(SNI = your domain)──▶ Cloudflare IP ──WebSocket──▶ your server ──▶ internet
```

SNI-based throttling/blocking by your ISP, the Cloudflare → origin leg and a broken VLESS path were invisible,
so an IP could show 10 Mbps and still load nothing (not even speedtest.net) in V2rayN. Smaller flaws added to
the confusion: a plain `HTTP 200` counted as a working WebSocket, the HTTP status of the speed test was never
checked, and 8 tests ran in parallel and shared the same bandwidth.

**v4 contains its own VLESS-over-WebSocket client.** Every candidate IP is tested with your exact
SNI / Host / path / UUID:

| Stage | What is checked | Cost |
|---|---|---|
| 1. Scan | TCP + TLS + WebSocket upgrade must return a real `101` (valid `Sec-WebSocket-Accept`) | cheap, high parallelism |
| 2. Tunnel check | An HTTPS request to `cp.cloudflare.com/generate_204` **through the tunnel** must succeed — like V2rayN's "real delay" | a few round trips, only for stage-1 hits |
| 3. Download | Download through the tunnel for `--speed-time` seconds. Slow IPs are dropped after ~2.5 s | one IP at a time |
| 4. Upload | Only for IPs that passed 3. Chunks are POSTed through the tunnel and **only counted once the server acknowledged them** | one IP at a time |

IPs that fail any stage are never put in the result list, so you only look at IPs that carry real traffic.

---

## Quick start

1. Install Python 3.8 or newer (`python3 --version` on Linux, `python --version` on Windows).
2. Put the IP ranges to scan in a text file — copy `subnets.example.txt` to `subnets.txt`.
3. Run it with your own `vless://` link (it must be `type=ws`; `security=tls` or `none`).

**Linux**

```bash
python3 cf_ping.py subnets.txt -c "vless://UUID@your.domain.com:443?type=ws&security=tls&path=%2Fxyz&host=your.domain.com&sni=your.domain.com#name" -t 100 --speed-test --want 10
```

**Windows** (PowerShell or cmd — keep the link in double quotes)

```bat
python cf_ping.py subnets.txt -c "vless://UUID@your.domain.com:443?type=ws&security=tls&path=%2Fxyz&host=your.domain.com&sni=your.domain.com#name" -t 100 --speed-test --want 10
```

> In a `.bat` file write `%%2F` instead of `%2F`. Use Windows Terminal, PowerShell or Windows 10+ `cmd` for colours.

This scans with 100 threads, speed-tests every 20 verified hits and **stops as soon as 10 IPs passed**.
Open `cf_results.json` — `results` is sorted best first and each entry has a ready `vless_uri`; paste it into
V2rayN (*Servers → Import from clipboard*).

Press **Ctrl+C** once to stop and save (progress and results are kept); a second press quits immediately
without saving.

### Reading the speeds

The script prints **Mbps** (megabits/s) and, next to it, **MB/s** (megabytes/s, Mbps ÷ 8) — V2rayN shows MB/s.
`7.25 Mbps (0.91 MB/s)` is the same number twice.

---

## Options

| Option | Default | Meaning |
|---|---|---|
| `subnets_file` | – | File with IPs / CIDR ranges, one per line (`#` = comment) |
| `-c, --config` | – | Your `vless://` link. Needed for tunnel checks and speed tests |
| `-s, --sni` | – | TLS-only scan for a domain (no config) |
| `-t, --threads` | 50 | Parallel scan threads |
| `-w, --wait` | 3.0 | Timeout per network step (seconds) |
| `-p, --port` | from config / 443 | Port override |
| `-o, --output` | `cf_results.json` | Results file |
| `-r, --resume` | `cf_progress.json` | Progress file (see *Resume*) |
| `--no-verify` | off | Only check the WebSocket `101` (fast, but many such IPs carry no traffic) |
| `--verify-url` | `https://cp.cloudflare.com/generate_204` | URL fetched *through the tunnel* to verify every hit (a `200`/`204` answer is expected) |
| `--down-url` | automatic | Force **one** download URL for speed tests (`http://` or `https://`). `{bytes}` is the request size the script picks; a plain file URL works too. Default: automatic, see below |
| `--up-url` | automatic | Force **one** upload URL for speed tests; must accept `POST` bodies |
| `--speed-test` | off | Real download/upload test of the verified hits (needs `-c`) |
| `--speed-limit` | 20 | Verified hits that trigger a speed-test batch (the scan pauses meanwhile) |
| `--speed-time` | 5 | Seconds per download and per upload measurement |
| `--min-download` | 2 | Reject IPs slower than this download speed (Mbps) |
| `--min-upload` | 1 | Reject IPs slower than this upload speed (Mbps) |
| `--no-upload` | off | Skip the upload test |
| `--speed-threads` | 1 | Parallel speed tests. Keep **1** for honest numbers — parallel tests share your bandwidth |
| `--want N` | 0 (off) | Stop everything once N IPs passed (N verified IPs without `--speed-test`) |
| `--sort` | `download` | Result order: `download`, `upload` or `delay` |
| `--loss-count` | 0 (off) | ICMP pings per IP for packet loss (needs `ping`; many networks block ICMP) |
| `--ping-only`, `--tls13-only` | off | ICMP-only scan / keep only TLS 1.3 (`-s` mode) |

Tips:

* **Save time:** `--want 10` (or any N) — you rarely need more than a handful of good IPs.
* Raise `--min-download` / `--min-upload` (for example `--min-download 8`) to reject mediocre IPs even faster.
* Slow link or far-away server? Raise `-w` (e.g. `-w 5`) and `--speed-time` (e.g. `8`).
* Close other downloads while testing; they eat the bandwidth that is being measured.

---

## Output

```jsonc
{
  "count": 2,
  "speed_tested": 2,
  "results": [                       // verified, best first
    {
      "ip": "104.16.12.34", "tls": "1.3",
      "latency_ms": 55.5,            // TCP + TLS + WebSocket upgrade
      "tunnel_ms": 103.7,            // full request through the tunnel (like V2rayN real delay)
      "download_mbps": 23.4, "upload_mbps": 8.1, "verdict": "pass",
      "vless_uri": "vless://UUID@104.16.12.34:443?type=ws&...#name-104.16.12.34-D23.4-U8.1"
    }
  ],
  "rejected": [                      // too slow / failed the real test
    { "ip": "104.16.99.1", "verdict": "slow", "reason": "download too slow (0.94 Mbps)" }
  ]
}
```

IPs found but not speed-tested yet (e.g. after Ctrl+C) stay in `results` without a `verdict`; they are tested
automatically the next time you resume.

### Resume

`cf_progress.json` stores which IPs were already scanned, `cf_results.json` what was found. Run the same command
again to continue. Both files belong to **one config + mode**: change the config (UUID, host, path, SNI, port,
`--no-verify`, `--verify-url`) and the old progress is ignored and the scan starts fresh. Use `-o` / `-r` to keep
several scans side by side.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Every IP: `HTTP 400/404 (wrong path/config?)` | Wrong `path`, `host` or `sni` in the link |
| `WS ok, tunnel dead: …` for everything | Wrong UUID, your server is down, or your server cannot reach the `--verify-url` host. `--no-verify` shows whether the edge answers at all (those IPs are *not* proven to work) |
| `No download test server answers your server` | Every speed-test server refused or was unreachable from your server. The text after each host is what it answered. Give `--down-url` a large file your server can fetch. The IPs stay **untested** |
| `fake WS 101` | Something in the network is faking WebSocket replies |
| Speeds still higher than V2rayN | V2rayN measures another URL and duration; other traffic on your line; try `--speed-time 10`. Compare IPs against each other, not the absolute value |
| `ping` not found | Linux minimal images: `sudo apt install iputils-ping` (only needed for `--ping-only` / `--loss-count`) |

### Which server is used for the speed test?

The traffic of a speed test goes **from your server** (the one behind the tunnel) to a test server, so what matters
is what *your server* can reach. Cloudflare's own `speed.cloudflare.com` sometimes refuses such requests
(`HTTP 403` or an HTML `404` page for datacenter IPs). That is why, before the first batch, the script tries these
servers **once per run, through your tunnel**, and uses the first one that answers — the same server for every IP, so
the numbers stay comparable:

| | Download | Upload |
|---|---|---|
| 1 | `speed.cloudflare.com/__down` | `speed.cloudflare.com/__up` |
| 2 | `speed.hetzner.de/100MB.bin` | `speedtest.tele2.net/upload.php` |
| 3 | `cachefly.cachefly.net/100mb.test` | |
| 4 | `speedtest.tele2.net/100MB.zip` | |
| 5 | `proof.ovh.net/files/100Mb.dat` | |

The skipped servers and the reason (status, `server:` header and page title) are printed, e.g.
`skipped speed.cloudflare.com: HTTP 404 [server: cloudflare] "404 Not Found"`. If no upload server works the script
continues **without** the upload test and says so. Public test files can move or disappear; to use your own
(a big file on your server or CDN is best):

```bash
python3 cf_ping.py subnets.txt -c "vless://..." --speed-test --down-url "https://your-server.invalid/100mb.bin" --no-upload
```

`--down-url` / `--up-url` force a single URL — no fallback. `--up-url` needs a server that accepts `POST` bodies.
`your-server.invalid` above is a **placeholder** — replace it with a real file URL (the script refuses placeholder
hosts such as `example.com`).

## Limitations

* Tests **VLESS over WebSocket** only (`type=ws`, `security=tls` or `none`). gRPC, Reality, VMess, Trojan are not supported.
* The TLS ClientHello comes from Python, not uTLS — `fp=` in your link is ignored while scanning. If your ISP
  treats TLS fingerprints differently, results can differ from the real client.
* Certificates are not verified (it is a scanner). IPv6 blocks are sampled (4096 addresses), IPv4 ranges are fully enumerated.
