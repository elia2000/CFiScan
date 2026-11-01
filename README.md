# CF-SCAN — Cloudflare clean-IP scanner for VLESS + WebSocket

**English** · [فارسی](README.fa.md)

Finds Cloudflare IPs that really work **with your own VLESS + WebSocket (+TLS) config**, and measures the
**real download and upload speed through your tunnel** — the same path V2rayN / Xray use.

* Single file (`cf_ping.py`), **no dependencies** — Python 3.8+ standard library only
* Works on **Windows** and **Linux** (macOS should work too)
* Resume support, live dashboard, ready-to-import `vless://` links in the results
* A second tool, **`sni_scan.py`**, finds the fastest **SNI** (for SNI spoofing) on your best IPs — see [SNI search](#sni-search-sni_scanpy--which-sni-is-fastest-and-on-which-ip)

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
| 3. Quick screen | Before each speed-test batch: can the IP's tunnel pull even 64 KB within 4 s? Dead or throttled IPs are common and are dropped here, **8 at a time** | seconds, in parallel |
| 4. Download | Download through the tunnel for `--speed-time` seconds. Slow IPs are dropped after ~2.5 s | one IP at a time |
| 5. Upload | Only for IPs that passed 4. Chunks are POSTed through the tunnel and **only counted once the server acknowledged them** | one IP at a time |

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
| `subnets_file` | – | File with IPs / CIDR ranges, one per line (`#` = comment) — or just one IP / CIDR, handy to re-test a single IP |
| `-c, --config` | – | Your `vless://` link. Needed for tunnel checks and speed tests |
| `-s, --sni` | – | TLS-only scan for a domain (no config) |
| `-t, --threads` | 50 | Parallel scan threads |
| `-w, --wait` | 3.0 | Timeout per network step (seconds) |
| `-p, --port` | from config / 443 | Port override |
| `-o, --output` | `cf_results.json` | Results file |
| `-r, --resume` | `cf_progress.json` | Progress file (see *Resume*) |
| `--no-verify` | off | Only check the WebSocket `101` (fast, but many such IPs carry no traffic) |
| `--verify-url` | `https://cp.cloudflare.com/generate_204` | URL fetched *through the tunnel* to verify every hit (a `200`/`204` answer is expected) |
| `--down-url` | automatic | Force **one** download URL for speed tests (`http://` or `https://`). `{bytes}` in it is replaced by the request size the script picks (it starts at 2,000,000 bytes and adapts to your speed); a plain file URL works too. Default: automatic, see below |
| `--up-url` | automatic | Force **one** upload URL for speed tests; must accept `POST` bodies |
| `--speed-test` | off | Real download/upload test of the verified hits (needs `-c`) |
| `--speed-limit` | 20 | Verified hits that trigger a speed-test batch (the scan pauses meanwhile) |
| `--speed-time` | 5 | Seconds per download and per upload measurement |
| `--min-download` | 2 | Reject IPs slower than this download speed (Mbps) |
| `--min-upload` | 1 | Reject IPs slower than this upload speed (Mbps) |
| `--no-upload` | off | Skip the upload test |
| `--speed-threads` | – | **Ignored.** Speed tests always run one IP at a time: tests running together share your bandwidth, so every number reads too low (with `--speed-threads 10` fast IPs looked slow and almost nothing passed `--min-download`). The quick screen is the only parallel step |
| `--want N` | 0 (off) | Stop everything once N IPs passed (N verified IPs without `--speed-test`) |
| `--sort` | `download` | Result order: `download`, `upload` or `delay` |
| `--loss-count` | 0 (off) | ICMP pings per IP for packet loss (needs `ping`; many networks block ICMP) |
| `--ping-only`, `--tls13-only` | off | ICMP-only scan / keep only TLS 1.3 (`-s` mode) |

Tips:

* **Save time:** `--want 10` (or any N) — you rarely need more than a handful of good IPs.
* Raise `--min-download` / `--min-upload` (for example `--min-download 8`) to reject mediocre IPs even faster — but keep them realistic: **upload is only tested for IPs that already passed the download test**, so a `--min-download` above what your path can do means no IP ever reaches the upload test. If nothing passes, the summary lists the closest IPs with their numbers.
* The speed is the average over `--speed-time` seconds, TCP slow start included (like most download tests). Limits close to your line speed need a longer window, e.g. `--speed-time 10`.
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

**Changing the speed settings between runs is safe.** Every verdict is stamped with the limits it was judged against. When you run again with other `--min-download` / `--min-upload` / `--no-upload`, the script checks the earlier verdicts against the new limits first and prints e.g. `2 still valid, 2 re-judged from their stored numbers, 7 will be measured again`: complete measurements are simply re-judged, cut-off ones stay rejected if they would be rejected anyway, and an IP is measured again when the new settings need something that was never measured (for example upload after a `--no-upload` run). Without this, old download-only results would sit in the list next to the new ones and `--sort upload` would have nothing to sort.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Every IP: `HTTP 400/404 (wrong path/config?)` | Wrong `path`, `host` or `sni` in the link |
| `WS ok, tunnel dead: …` for everything | Wrong UUID, your server is down, or your server cannot reach the `--verify-url` host. `--no-verify` shows whether the edge answers at all (those IPs are *not* proven to work) |
| `download: no reply from … within 4s` / `no data for 4s (N KB had arrived)` / `timeout while connecting to …` | The IP's tunnel stalls or is too slow to even start; the text says at which step. These IPs are useless for you |
| `32 KB went out but <host> sent no reply in 5s` | The data left your PC but that upload server never answered — public servers often ignore datacenter IPs. Use your own server, see above |
| `uplink stuck: only 16 of 32 KB went out in 5s` | The data does not even leave your PC through this IP: your uplink, or the path through this IP, is blocked or extremely slow |
| `⚠ Upload tests switched OFF` | The upload test failed on 3 IPs in a row and never worked in this run; the warning lists what the IPs said — see above |
| `N of N IPs failed the same way` | Nearly every IP fails identically: the test server (or your VPS) is the problem, not the IPs. The run stops, the IPs stay untested, and the scanner adds what it found out about your server |
| `127.0.0.1:8080 closed the connection without answering` | The tunnel works, but the VPS did not (or could not) connect to that address: Xray blocks private addresses, nothing listens there, or the port is taken. Use the VPS's public IP (the scanner prints it), the default all-address server and a free port |
| `No download test server answers your server` | Every speed-test server refused or was unreachable from your server. The text after each host is what it answered. Give `--down-url` a large file your server can fetch. The IPs stay **untested** |
| `fake WS 101` | Something in the network is faking WebSocket replies |
| Speeds still higher than V2rayN | V2rayN measures another URL and duration; other traffic on your line; try `--speed-time 10`. Compare IPs against each other, not the absolute value |
| `ping` not found | Linux minimal images: `sudo apt install iputils-ping` (only needed for `--ping-only` / `--loss-count`) |

### Which server is used for the speed test?

The traffic of a speed test goes **from your server** (the one behind the tunnel) to a test server, so what matters
is what *your server* can reach. Cloudflare's own `speed.cloudflare.com` sometimes refuses such requests
(`HTTP 403` or an HTML `404` page for datacenter IPs). So the script tries these servers in order, **through your
tunnel**, and uses the first one that answers — the same server for every IP, so the numbers stay comparable:

| | Download | Upload |
|---|---|---|
| 1 | `speed.cloudflare.com/__down` | `speed.cloudflare.com/__up` |
| 2 | `speed.hetzner.de/100MB.bin` | `speedtest.tele2.net/upload.php` |
| 3 | `cachefly.cachefly.net/100mb.test` | `httpbin.org/post` (echoes the body: measures up + down) |
| 4 | `speedtest.tele2.net/100MB.zip` | `postman-echo.com/post` (same) |
| 5 | `proof.ovh.net/files/100Mb.dat` | |

How a server gets dropped:

* **It refuses us** (an HTTP error such as `403`/`404`): it refuses every IP alike, so it is dropped for the whole run
  and the next one is used. The reason is printed (status, `server:` header, page title), e.g.
  `skipped speed.cloudflare.com: HTTP 404 [server: cloudflare] "404 Not Found"`.
* **It times out:** that is blamed on the IP — unless no server has worked yet, then the next server is tried for that
  IP too. As soon as one server worked, the earlier silent ones are dropped.
* **No download server answers at all:** the run stops and the IPs stay **untested** (they are not judged).
* **Upload never works** (the first 3 IPs that passed download all failed on every upload server): upload tests are
  switched **off** with a warning that lists **what the IPs said**, those IPs count as passed by download, and the run
  goes on. If instead every IP is rejected for a *slow* upload, you get a hint to lower `--min-upload` or use
  `--no-upload`.
* **Every IP fails the quick screen the same way:** that points at the test server or your VPS, not the IPs — the run
  stops and the IPs stay untested.

How the upload is measured: a tiny first POST measures the round-trip time, then requests grow quickly (starting at
32 KB, so a poor uplink can finish them). A chunk counts only once the server **answered** it, and the bandwidth is
estimated from the transfer part of each request, so a long round trip does not make a fast uplink look slow. A stall
tells you where it happened: `uplink stuck: only 16 of 32 KB went out` (the data did not leave your PC) or
`32 KB went out but <host> sent no reply` (the server did not answer).

### Test against your own server (most accurate)

Public test servers are third parties: they may refuse, throttle or simply ignore a VPS (`HTTP 403/404`, or *"32 KB
went out but speed.cloudflare.com sent no reply"*). The most reliable alternative is a tiny test server on **your own
VPS** — the server behind your VLESS config. It then measures exactly what differs between Cloudflare IPs: *your PC →
Cloudflare IP → your VPS*.

1. Copy `speedtest_server.py` to the VPS and start it (Python 3.8+, no packages). Keep it running (`tmux`,
   `nohup python3 speedtest_server.py &`, or a systemd service):

   ```bash
   python3 speedtest_server.py
   ```

   It does **not** touch your panel or Xray — you never have to stop x-ui; it is a separate little program that only
   needs a free port. It tries 8080 and, if something else already holds it (x-ui, another inbound, ...), picks a free
   port by itself and says so. It then prints the exact options to use. It also logs the first connections — if none
   arrive once the scanner runs, the tunnel cannot reach it (see below).

2. On your PC, point the speed test at it, with **your VPS's public IP** and the port it printed:

   ```bash
   python3 cf_ping.py subnets.txt -c "vless://..." --speed-test \
       --down-url "http://VPS_IP:PORT/down?bytes={bytes}" --up-url "http://VPS_IP:PORT/up"
   ```

**Why the public IP and not `127.0.0.1`:** the VPS opens that connection, and many Xray servers (3x-ui by default)
block private and loopback destinations with a routing rule (`geoip:private` → `block`). Then every IP fails with
`127.0.0.1:8080 closed the connection without answering`. The scanner notices this: it asks the tunnel for your VPS's
public IP, probes it, and prints either the exact `--down-url` / `--up-url` to use or what to change on the server.

**Is it safe to listen on all addresses?** Yes: the server answers **only connections made from the VPS itself** (that
is where Xray connects from); everybody else gets `403 local clients only`. If your Xray runs in Docker with its own
network and the connections appear to come from another address, start the server with `--allow-any` and restrict the
port in your firewall instead. It does not measure the VPS → internet leg, which is the same for every Cloudflare IP.

### Your own file or another server

Public test files can move or disappear; to use a file on your own server or CDN:

```bash
python3 cf_ping.py subnets.txt -c "vless://..." --speed-test --down-url "https://your-server.invalid/100mb.bin" --no-upload
```

`--down-url` / `--up-url` force a single URL — no fallback. `--up-url` needs a server that accepts `POST` bodies.
`your-server.invalid` above is a **placeholder** — replace it with a real file URL (the script refuses placeholder
hosts such as `example.com`).

---

## SNI search (`sni_scan.py`) — which SNI is fastest, and on which IP?

If your ISP uses DPI, the **SNI** (the server name sent in clear text at the start of every TLS connection) decides
whether a connection is blocked, throttled or left alone — and the same SNI can behave differently on two Cloudflare
IPs. [SNI spoofing](https://github.com/patterniha/SNI-Spoofing) (here through its Rust port
[sni-spoof-rs](https://github.com/therealaleph/sni-spoofing-rust)) runs a small local forwarder that shows the DPI a
**fake SNI** while your real TLS handshake (real SNI, Host, UUID) passes through unchanged. Which fake SNI you pick
has a direct effect on your speed.

`sni_scan.py` finds out **which fake SNI to use, and on which IP**. It takes the best IPs of `cf_ping.py`
(`cf_results.json`) and a list of candidate SNIs (`sni_list.txt`, about 2 350 names, [credits](THIRD_PARTY.md)) and
ranks every (IP, SNI) pair by the **real download and upload speed through your own VLESS tunnel** — the same
measurement as above, not just "the handshake answered".

```bash
# 1. find good IPs first (see above) -> cf_results.json
# 2. which SNIs get through at all?  No admin rights, no config needed; reads ./cf_results.json
python3 sni_scan.py --mode reach
# 3. the real ranking, through sni-spoof-rs (it needs root / Administrator for raw packets)
sudo python3 sni_scan.py -c "vless://..." --spoof-bin ./sni-spoof-rs-linux-amd64
```

Windows (PowerShell **as Administrator**): `python sni_scan.py -c "vless://..." --spoof-bin .\sni-spoof-rs.exe`

Download sni-spoof-rs from its [releases page](https://github.com/therealaleph/sni-spoofing-rust/releases/latest)
(Windows: unzip it and keep the WinDivert files next to the `.exe`; Linux/macOS: `chmod +x` it). If it lies next to
`sni_scan.py` the `--spoof-bin` option can be left out. `sni_scan.py` never downloads anything and only starts the
program you point it to.

### What it does

| Stage | What happens | Cost |
|---|---|---|
| 1. Reach | Every SNI on every IP: a ClientHello with that SNI — byte for byte the packet sni-spoof-rs injects, like its own `scan` — is sent and the first reply byte is checked. `0x16` (ServerHello) = passed; `0x15` (alert) = the server refused that name but the DPI did not block it, which is enough for a *fake* SNI; reset / timeout = blocked | 2 000+ names × 5 IPs: minutes, 100 at a time |
| 2. Probe | The SNIs that passed get a real download through your tunnel: a rough screen (~1 MB, 8 at a time), then an accurate probe of the best ones, one at a time. All SNIs are measured on the **same IP**, so the numbers compare SNIs, not IPs | seconds per SNI |
| 3. Matrix | The best SNIs × **every IP they passed on**: full download and upload, one at a time. Your own SNI is measured on the same IPs as the baseline to beat | `--speed-time` per pair |

This is what shows when an SNI works only on some IPs or is fast on one IP and slow on another: stage 1 prints
`only on some IPs: … → 104.18.x.x`, and stage 3 measures each SNI on each IP it passed on.

| `--mode` | What it does | Needs |
|---|---|---|
| `reach` | Stage 1 only: which SNIs pass on which IPs | nothing (default when `-c` is missing) |
| `spoof` | Stages 1–3 **through sni-spoof-rs**: one listener per (IP, SNI) pair — the DPI sees the fake SNI, Cloudflare sees yours | `-c`, sni-spoof-rs, root / Administrator (default when `--spoof-bin` is given) |
| `direct` | Stages 1–3 with the candidate as the **real** SNI. Cloudflare normally refuses a request whose SNI and Host differ (`HTTP 403`) — then the tool tells you to use `spoof` instead | `-c` (default when `-c` is given without `--spoof-bin`) |

### Output

* The console: best (IP, SNI) pairs, best SNIs overall (median over the IPs), and the best pair against your own SNI.
* `sni_results.json` — everything: stage-1 outcome of every pair, rough screen, probes, matrix, ranking.
* `sni_working.txt` — SNIs that passed, best first (same format as `sni-spoof-rs scan -o`).
* `sni_spoof_config.json` — a ready config for sni-spoof-rs with the three best pairs (local ports 40443, 40444, 40445).
* `sni_best_links.txt` — the matching `vless://` links.

To use the result:

```bash
sudo ./sni-spoof-rs-linux-amd64 sni_spoof_config.json     # Windows: as Administrator; leave it running
# then import one link from sni_best_links.txt (V2rayN: Servers -> Import from clipboard)
```

The links point to `127.0.0.1:40443…` (sni-spoof-rs) and keep your real SNI, Host, path and UUID.

### Options

| Option | Default | Meaning |
|---|---|---|
| `-c`, `--config` | – | your `vless://` link (needed for every speed measurement) |
| `--ips`, `--ips-file`, `--ips-from` | `./cf_results.json` | IPs to test: comma list, file with one IP per line, or the `cf_results.json` of `cf_ping.py` (verified IPs first) |
| `--top` | `5` | how many IPs are taken from the results file |
| `--snis` | `sni_list.txt` | candidate names, one per line (`#` = comment) |
| `--max-snis` | all | only the first N names (the list starts with the best-known ones) |
| `--mode` | automatic | `reach`, `direct` or `spoof` (see above) |
| `--spoof-bin` | automatic | path of sni-spoof-rs (found by itself when it lies next to the script, in the current folder or on `PATH`) |
| `-t`, `--threads` / `-w`, `--wait` | `100` / `4` | stage-1 parallelism / timeout per probe and step (seconds) |
| `--max-probe` | `300` | how many of the SNIs that passed get the rough 1 MB screen (`0` = all of them) |
| `--probe-snis` / `--probe-time` | `30` / `3` | how many go on to the accurate probe / its length in seconds |
| `--top-snis` | `6` | best SNIs that go to the IP × SNI matrix |
| `--speed-time` | `5` | seconds per full download / upload measurement |
| `--min-download`, `--min-upload` | `1` / `0.5` | Mbps; slower pairs are dropped early |
| `--no-upload`, `--no-baseline` | off | skip the upload test / don't measure your own SNI as the reference |
| `--down-url`, `--up-url` | automatic | same as in `cf_ping.py` — see *Test against your own server* |
| `--sort` | `download` | `download`, `upload` or `delay` |
| `-o` | `sni_results.json` | results file (the other files are written next to it) |

### Good to know

* **The list** (`sni_list.txt`) holds candidates only: part 1 is the best-known names (tried first with
  `--max-snis`), part 2 sites that are on Cloudflare (they work in both modes), part 3 names that are **not** on
  Cloudflare — Iranian sites, big tech — which only make sense as a fake SNI in `spoof` mode (in `direct` mode stage 1
  drops them). Add your own names anywhere; duplicates are ignored.
* **Time:** the full list on 5 IPs takes minutes in stage 1. Use `--max-snis 300` for a first look, `-w 6` on a slow
  line, `--max-probe 0` when you want every passing name speed-tested.
* **Each number is one measurement.** Pairs within about 20 % of each other are a tie; repeat the finalists
  (`--top-snis 3`), also at another time of the day, before trusting a small difference.
* Passing stage 1 only means the DPI did not block the name. Whether it is also **fast** is what stages 2 and 3 measure.
* **Results belong to your ISP and the time of day.** A list that works on one network may not work on another.
* If stage 1 looks fine but every pair fails afterwards, run sni-spoof-rs by hand first (see its README): missing
  root / Administrator, WinDivert files, an antivirus or another VPN capturing packets. The tool prints the log line
  `timeout waiting for fake ACK` when it sees it.
* The packet injection is sni-spoof-rs's job; `sni_scan.py` writes its config, starts it, measures through its
  listeners and stops it again when it ends or on Ctrl+C. If the scan is killed hard, a leftover `sni-spoof-rs` may
  keep running — end it in Task Manager (Windows) or with `pkill sni-spoof-rs`.
* Like the scanner, it measures **VLESS over WebSocket** only.

## Limitations

* Tests **VLESS over WebSocket** only (`type=ws`, `security=tls` or `none`). gRPC, Reality, VMess, Trojan are not supported.
* The TLS ClientHello comes from Python, not uTLS — `fp=` in your link is ignored while scanning. If your ISP
  treats TLS fingerprints differently, results can differ from the real client.
* Certificates are not verified (it is a scanner). IPv6 blocks are sampled (4096 addresses), IPv4 ranges are fully enumerated.
