---
title: "L3akCTF 2026 Reverse Engineering Writeup: All 6 Challenges"
slug: "l3akctf-2026-reverse-engineering-writeup"
description: "Full L3akCTF 2026 reverse engineering writeup covering all six rev challenges: reversing a subleq VM memory dump that runs Langton's Ant to un-scramble an ASCII-art bitmap (Subleq Scramble); running a UPX-scrubbed chat server in Wine and replaying pcap ciphertext so the binary decrypts a custom 8-byte ECB cipher for you (Yet Another Chat); defeating an MBA-obfuscated neural-net checker with a Kannan lattice embedding and BKZ instead of reading the code (Buzzword); solving a custom .wwc VM's six questions including a Feistel inversion bound to a hidden rolling state (What-Who); extracting a flag hidden as 3D Unity cube geometry across serialized scenes with UnityPy (Drippy Adventures); and forging a PRX job with a SHA-256 length-extension attack plus an unauthenticated entry-point patch to run MIPS-like VM shellcode (Omega)."
date: 2026-08-06T17:00:00Z
lastmod: 2026-08-06T17:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["L3akCTF 2026"]
tags:
  - "l3akctf"
  - "l3akctf 2026"
  - "ctf writeup"
  - "reverse engineering"
  - "rev"
  - "custom vm"
  - "subleq"
  - "langtons ant"
  - "self-modifying code"
  - "mba obfuscation"
  - "lattice reduction"
  - "bkz"
  - "kannan embedding"
  - "gfni"
  - "feistel network"
  - "sha-256 length extension"
  - "unity"
  - "unitypy"
  - "upx"
  - "packed binary"
  - "ecb"
  - "wine"
  - "ghidra"
  - "ctf 2026"
keywords:
  - "l3akctf 2026 reverse engineering writeup"
  - "l3akctf 2026 rev writeup"
  - "subleq scramble ctf writeup"
  - "yet another chat ctf writeup"
  - "buzzword ctf writeup"
  - "what-who ctf writeup"
  - "drippy adventures ctf writeup"
  - "omega ctf writeup"
  - "langtons ant reverse ctf"
  - "mba obfuscation lattice bkz ctf"
  - "sha256 length extension prx ctf"
  - "unity cube geometry flag ctf"
  - "custom vm reverse engineering ctf"
  - "reverse engineering ctf 2026"
toc: true
cover:
  image: "/images/articles/l3akctf-2026-reverse-engineering-writeup.png"
  alt: "L3akCTF 2026 reverse engineering writeup covering all six rev challenges — Subleq Scramble reverses a subleq VM memory dump running Langton's Ant to un-scramble an ASCII-art bitmap, Yet Another Chat runs a UPX-scrubbed chat server in Wine and replays pcap ciphertext so the binary decrypts a custom 8-byte ECB cipher, Buzzword defeats an MBA-obfuscated neural-net checker with a Kannan lattice embedding and BKZ instead of reading the code, What-Who solves a custom wwc VM's six questions including a seed-bound Feistel inversion, Drippy Adventures extracts a flag hidden as 3D Unity cube geometry across serialized scenes with UnityPy, and Omega forges a PRX job with a SHA-256 length-extension attack plus an unauthenticated entry-point patch to run MIPS-like VM shellcode reading the flag"
---

Reverse engineering at L3akCTF 2026 was six challenges with one loud message: **you're not always meant to fully reverse the thing in front of you.** Three of the six are bespoke virtual machines, two more bury their logic under industrial-strength obfuscation, and one hides the flag as literal 3D geometry. The winning move, over and over, isn't to grind through every instruction — it's to spot the *structural property* that makes the whole obfuscation irrelevant: a reversible cellular automaton, a decrypt oracle you can just run, a lattice that recovers a small secret, a crypto construction with a known break, or data hidden outside the code entirely.

This **CyberSecurity Elite** L3akCTF 2026 reverse engineering writeup walks all six challenges end to end, focused on the shortcut that cracks each one. Handouts, custom disassemblers, and solvers are at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026). For the rest of the event, see the [pwn](/ctf-writeups/l3akctf-2026-pwn-writeup/), [crypto](/ctf-writeups/l3akctf-2026-crypto-writeup/), [misc](/ctf-writeups/l3akctf-2026-misc-writeup/), [web](/ctf-writeups/l3akctf-2026-web-writeup/), [OSINT](/ctf-writeups/l3akctf-2026-osint-writeup/), and [forensics](/ctf-writeups/l3akctf-2026-forensics-writeup/) writeups.

## All six challenges at a glance

| Challenge | Points | Solves | Core idea |
|---|---:|---:|---|
| [Subleq Scramble](#subleq-scramble--un-walking-langtons-ant) | 99 | 69 | Reverse a subleq VM's Langton's Ant scrambler |
| [Yet Another Chat](#yet-another-chat--let-the-binary-decrypt-it) | 141 | 38 | Run the packed server as a decrypt oracle; replay the pcap |
| [Buzzword](#buzzword--a-neural-net-that-is-really-an-svp) | 244 | 16 | Kannan embedding + BKZ on an MBA-obfuscated checker |
| [What-Who](#what-who--six-questions-for-a-custom-vm) | 286 | 12 | Solve a `.wwc` VM's six questions; invert a seed-bound Feistel |
| [Drippy Adventures](#drippy-adventures--the-flag-is-the-level-geometry) | 383 | 6 | Extract a flag hidden as 3D Unity cube geometry |
| [Omega](#omega--length-extension-against-a-prx-loader) | 453 | 3 | SHA-256 length extension + unauthenticated entry-point patch |

---

## Subleq Scramble — un-walking Langton's Ant

> *Flag:* `L3AK{L4NGT?N'S4NT_SCR4MBL3RRR_10,000}`

`data.subleq` is a 6912-byte memory dump of a [subleq](https://en.wikipedia.org/wiki/One-instruction_set_computer) one-instruction VM that ran an "image scrambler" to completion. Decoding the dump, two negated strings (subleq's classic `subleq src -1 next` stdout idiom) give a decoy flag and — crucially — `Ant out of bounds:`. That's a neon sign: the scrambler is **Langton's Ant**.

Disassembling the loop confirms it. Constants at the code's tail spell out an 84×38 monochrome bitmap at address 264, a `-9999` loop bound, and an ant position/direction. The step logic uses **self-modifying code** — three instruction slots (`[90]`, `[97]`, `[136]`) are rewritten each iteration to read/write the current pixel — and implements Langton's rule exactly: white cell → turn one way, flip, step; black cell → turn the other way, flip, step, for 9999 steps.

Langton's Ant is **fully reversible**, so from the halt state (position `(80,32)`, direction `(-1,0)`) you un-walk it:

```python
x, y, dx, dy = 80, 32, -1, 0
for _ in range(9999):
    x -= dx; y -= dy
    c = grid[y][x]; grid[y][x] = 1 - c
    if c == 1: dx, dy = dy, -dx      # inverse of forward CCW turn
    else:      dx, dy = -dy, dx      # inverse of forward CW turn
```

The recovered bitmap is 3×5 pixel-font ASCII art spelling the flag; a round-trip (reverse → forward → identity) confirms the turn directions before OCR'ing the glyphs. **Takeaway:** identify the algorithm from a single leaked string, then exploit its reversibility — you never have to run the scrambler forward or guess the plaintext.

---

## Yet Another Chat — let the binary decrypt it

> *Flag:* `L3AK{1t_is_@ll_jU5t_4n0th3r_d30bf_uZzZc4t!0n_game_hopeyouenjoy:)_asengishere}`

Two 32-bit PEs (`server.exe`, `client.exe`) and a pcap. The binaries are UPX-family packed with the `UPX!` marker scrubbed (so `upx -d` refuses), and the real chat/crypto code is buried behind self-modifying `xchg`-based trampolines — Ghidra sees ~1400 functions bouncing through opaque stubs. From the pcap, each frame is `[len:4][iv:16][ciphertext]`, every ciphertext is a multiple of **8** bytes, and sending `AAAAAAAABBBBBBBBAAAAAAAABBBBBBBB` produces repeating ciphertext blocks — a custom **8-byte-block ECB** cipher with a per-message key derived from the IV. No standard cipher's constants appear; reversing it would take hours.

The shortcut is to not reverse it at all. The protocol is **stateless per message** — the IV rides on every frame and the server decrypts each frame in isolation with no session key exchange. So *any* server instance can decrypt *any* client frame, and it rebroadcasts every decrypted message as `Client N: <plaintext>`. Run the server under Wine, connect an observer client, and replay the pcap's client-side byte stream verbatim:

```console
$ wine ./server.exe &     # owns the decrypt routine
$ wine ./client.exe &     # observer terminal
$ python3 solve.py        # replays [len][iv][ct] frames from the pcap
```

The observer's terminal fills with the plaintext conversation — and Client 3's message hands over the flag. **Takeaway:** when a binary *contains* the routine you'd otherwise reverse and there's no session state to defeat, recruit it as an oracle. The lack of any handshake (the key comes straight from the wire IV) is exactly what makes replay work.

---

## Buzzword — a neural net that is really an SVP

> *Flag:* `L3AK{it's_a_svp_challenge?_everything_is.}`

A stripped, statically linked ELF whose "state-of-the-art AI flag checker" is three 42×42 matrix layers (two over `GF(127)`, one mod `65537`). The binary is deliberately unreadable: 16 KiB NOP walls and every multiply-accumulate blown up into tens of thousands of bytes of **mixed Boolean-arithmetic (MBA)** identities. The model weights in `model.bin` are hidden behind a byte-wise `GF(2^8)` inverse (GFNI `GF2P8AFFINEINVQB`) and `PEXT` nibble-packing. Emulating one MBA block while varying its inputs collapses each layer back to `acc' = (acc + weight·input) mod m`, giving the clean network:

```text
h1 = A0·x mod 127 ;  h2 = A1·h1 mod 127 ;  z = h2 - 64 ;  y = A2·z mod 65537
```

The trap is the tolerance: the checker accepts when `sum(error_i²) ≤ 127`, so the supplied target is `A2·z - error (mod 65537)` with `z ∈ [-64,62]` and tiny `error`. Exact inversion of `A2` smears the small error across every coordinate and yields nonsense — this is bounded-distance decoding, not a linear solve. Build an 85-dimensional **Kannan embedding** and let BKZ-20 recover the planted short vector `(error, z, -1)`:

```text
    [ q·I_n    0     0 ]
B = [  A2^T   I_n    0 ]      →  short vector = (e, z, -1),  ||e||² = 23 ≤ 127
    [ target^T  0    1 ]
```

With `z` recovered, `h2 = z + 64`, and the two `GF(127)` layers invert with ordinary Gaussian elimination back to the ASCII flag. **Takeaway:** the MBA and GFNI theater only obscures a plain linear model; recognizing "noisy linear system with a small secret" turns a nightmare disassembly into a textbook lattice problem — as the flag itself admits, *it's a SVP challenge.*

---

## What-Who — six questions for a custom VM

> *Flag:* `L3AK{wh4t_4sks_wh0_4nsw3rs}`

A stripped PIE plus a custom `vault.wwc` container (magic `WWHO`) holding 262 fixed-width instructions and a data section. The VM has *both* a register and a stack instruction set and asks six questions, and every accepted answer folds into a hidden **rolling state** that the final question depends on. The six stages:

1. **Password mixer** — four bytes through an xor/rotate/multiply/xorshift/add chain; every op is invertible (odd multiplier ⇒ modular inverse), reversing to `slop`.
2. **Stateful byte check** — 16 bytes verified against four tables with a running key; invert the rotate/sub/xor per byte to get `slop_slop_slop!!`.
3. **Embedded maze** — a 17×17 grid where `N/E/S/W` moves must stay on open cells; BFS finds the unique 102-step route.
4. **& 5. Seed-derived values** — decimal and 64-bit hex outputs computed by hundreds of rounds of a mixing function over the per-connection instance seed.
6. **Feistel inversion** — 128 bits decoded as two halves; the VM derives a target pair from `seed` and the rolling `state`, runs ten Feistel rounds, and a Feistel is invertible regardless of its round function, so processing rounds 9→0 recovers the preimage.

Because the seed is fresh per connection and each accepted answer mutates the rolling state, the solver keeps one TLS session open, reads the seed, and reproduces every operation (hashing the *rendered* answer strings, not their numeric values) in order. **Takeaway:** custom-VM challenges reward mapping the interpreter once, then attacking each stage with the right primitive — invert what's invertible, BFS the maze, and never fight a Feistel head-on.

---

## Drippy Adventures — the flag *is* the level geometry

> *Flag:* `L3AK{TH3_B35T_0f_G4M35_M45T3R_0F_UNITY!!}`

A Windows Unity Mono game with 200 serialized scenes. Decompiling `Assembly-CSharp.dll` shows only routine movement logic — no flag string, no checker. That's the tell: **the flag lives in the assets, not the code.** Every letter is built from thin Unity cubes, each cube one stroke of a block-font glyph, hidden in the scene hierarchies. Parsing scenes with **UnityPy**, applying each cube's `Transform` (scale → quaternion → translation, composing parent transforms), and projecting the cuboids onto a plane renders the glyphs.

In-game signs (also cube text) give a coordinate trail and a hint — *"File size and scripting exist!"* — so sorting scenes by size makes the outlier `level176` obvious rather than brute-forcing 198 files. The five fragments come from: an opening marker (`L3AK{`), a detached 37-stroke cluster in `level0` (`TH3_B35T`), a 50-stroke group in `level1` (`_0f_G4M35`), a 44-cuboid **underwater chamber** in `level176` whose walls must be clustered and read in reverse angular order (`_M45T3R_0F_`), and 27 tiny cubes attached to the `Player` object itself (`UNITY!!}`). Concatenated, they form the flag. **Takeaway:** when the code is clean, geolocate the flag in the data — Unity scenes are just serialized transforms, and treating hidden objects as geometry (rather than playing the game) is the whole solve.

---

## Omega — length extension against a PRX loader

> *Flag:* `L3AK{M45k3d_1n$truct!on5_P3rmu+ed_5u8s+1tut3d_954247ee}`

The single-hardest rev challenge: a native executor runs programs in a custom **PRX** container on a MIPS-like VM, but first forks an embedded verifier that authenticates the job. Diffing the two example PRX files shows only the 32-byte digest at `0x10` changes, and reversing the extracted verifier reveals the fatal construction — the accepted tag is `SHA256(secret || body)`, a raw secret-prefix MAC over the body starting at offset `0x30`. The magic, flags, initial register, and **VM entry point at `0x08` are all outside the authenticated body.**

That's a classic **SHA-256 length-extension** setup. SHA-256 is Merkle–Damgård, so from a known digest `D = SHA256(S‖M)` and a guessed prefix length you can resume hashing and compute `D' = SHA256(S‖M‖P‖X)` for attacker glue-padding `P` and payload `X` — without knowing the secret. Two more design flaws complete the chain: the second PRX segment has size `0xffffffff`, which the loader replaces with "file size − offset," so **appended bytes get mapped into VM memory**; and the unauthenticated entry point lets you redirect execution to them. So forge `body' = M‖P‖X` with `X` a MIPS-like payload that `open`/`read`/`write`s `/app/flag.txt`, patch entry `0x08` to point at the appended code, and brute the secret length 1–256 (the remote is 15):

```console
$ python3 exploit.py --secret-length 15 --remote
[+] Verified
L3AK{M45k3d_1n$truct!on5_P3rmu+ed_5u8s+1tut3d_954247ee}
```

**Takeaway:** `SHA256(secret‖message)` is not a MAC — use HMAC over the *entire* canonical structure. Here three small decisions (secret-prefix hash, unauthenticated header fields, a load-to-end segment) compose into full VM code execution.

---

## Cross-cutting lessons from the L3akCTF 2026 rev set

Six challenges, one repeated instinct — **find the property that makes the obfuscation irrelevant:**

- **Custom VMs are a genre, not a wall.** Subleq, the `.wwc` register/stack machine, and the PRX MIPS-like VM all yield to the same routine: map the interpreter and instruction encoding once, then attack the *logic* with the right tool (reverse a reversible automaton, BFS a maze, invert a Feistel).
- **Don't reverse what you can sidestep.** Yet Another Chat runs the binary as a decrypt oracle; Buzzword replaces a hopeless MBA disassembly with a lattice; Omega breaks the crypto instead of finding the secret. Recognizing the exploitable *structure* beats grinding the code.
- **Invertibility is the recurring key.** Langton's Ant, the What-Who mixer and Feistel, and the Buzzword layers are all solved by running the transform *backwards* — spotting reversibility early saves the most time.
- **Sometimes the flag isn't in the code at all.** Drippy Adventures hides it as 3D geometry; the clean C# assembly is the hint to look at the assets.
- **Obfuscation is theater over simple cores.** NOP walls, MBA identities, `xchg` trampolines, and scrubbed packers all dress up ordinary linear algebra, a standard cipher, or a plain VM. Follow data flow, not every temporary.

## Reproduce it yourself

Every challenge ships a standalone solver at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026) under `rev/<challenge>/`. Most are standard-library-only Python (Subleq Scramble, What-Who, Omega, plus Omega's `disasm_prx.py`); Buzzword needs the `fplll` CLI for BKZ; Drippy Adventures uses UnityPy to render the hidden geometry; and Yet Another Chat drives the packed server under Wine and replays the pcap. Each per-challenge `README.md` records the VM encodings, offsets, and exact reproduction commands.

Pair this with the [L3akCTF 2026 pwn](/ctf-writeups/l3akctf-2026-pwn-writeup/), [crypto](/ctf-writeups/l3akctf-2026-crypto-writeup/), [misc](/ctf-writeups/l3akctf-2026-misc-writeup/), [web](/ctf-writeups/l3akctf-2026-web-writeup/), [OSINT](/ctf-writeups/l3akctf-2026-osint-writeup/), and [forensics](/ctf-writeups/l3akctf-2026-forensics-writeup/) writeups, or browse the full [CTF writeups](/ctf-writeups/) archive for more reverse-engineering deep-dives.

---

*This writeup is part of the CyberSecurity Elite [L3akCTF 2026](/series/l3akctf-2026/) series. Handouts, disassemblers, and solver scripts for all six reverse engineering challenges are published at [github.com/Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026).*
