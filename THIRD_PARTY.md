# Third-party material

CF-SCAN is original work, except for the items below.

## sni-spoofing-rust

- Project: https://github.com/therealaleph/sni-spoofing-rust (a Rust implementation of the SNI-spoofing technique)
- License: MIT, reproduced below. Its LICENSE file names no author, only "Copyright (c) 2025".
- What was taken from it:
  - `sni_list.txt` contains the domain names of its `data/scan-snis.txt` (merged with many additions of ours).
  - `sni_scan.py`: the layout of the fixed 517-byte TLS ClientHello that `build_client_hello()` produces is
    ported from `src/packet/tls.rs`, and the stage-1 probe follows what its `scan` command does
    (`src/scan.rs`: send that ClientHello, treat a first reply byte of `0x16` as "passed").
  - `sni_scan.py` writes a config file in the format that tool reads (`sni_spoof_config.json`) and can start it.
  - Nothing of it is bundled: its binary is not part of this repository and is never downloaded
    automatically; you get it from its own releases page.

```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## SNI-Spoofing (the technique)

- Original idea and first implementation: patterniha, https://github.com/patterniha/SNI-Spoofing
- No code from that project is included here; it is credited because the technique that `--mode spoof`
  builds on is theirs.
