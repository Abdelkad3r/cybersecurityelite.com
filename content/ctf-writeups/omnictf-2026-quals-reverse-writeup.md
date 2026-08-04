---
title: "OmniCTF 2026 Quals Reverse Writeup: 4 Challenges Solved"
slug: "omnictf-2026-quals-reverse-writeup"
description: "OmniCTF 2026 Quals reverse step-by-step: CredVault Parcel migration mismatch, Gatekeep FPGA byte-circuit SAT, Kant multi-round Rust pipeline inversion, Pusher signal-VM."
date: 2026-07-19T18:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["OmniCTF 2026 Quals"]
tags:
  - "omnictf"
  - "omnictf 2026"
  - "omnictf quals"
  - "ctf writeup"
  - "reverse"
  - "reverse engineering"
  - "binary protocol reversing"
  - "parcel migration mismatch"
  - "fpga byte circuit"
  - "constraint solving"
  - "rust binary reversing"
  - "splitmix64 keystream"
  - "aes s-box variants"
  - "feistel inversion"
  - "signal-driven vm"
  - "sigsegv sigill as control flow"
  - "scanf format string trap"
keywords:
  - "omnictf 2026 quals reverse writeup"
  - "omnictf credvault writeup"
  - "omnictf gatekeep writeup"
  - "omnictf kant writeup"
  - "omnictf pusher writeup"
  - "strict vs forwarding parser mismatch"
  - "fpga schematic byte constraint solver"
  - "rust checker pipeline inversion"
  - "power map (b+1)^17 mod 257 inverse"
  - "sigsegv sigill vm branches obfuscation"
  - "scanf %d vs %c input trap"
  - "reversible transforms invert from target"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/omnictf-2026-quals-reverse-writeup.png"
  alt: "OmniCTF 2026 Quals reverse writeup — four challenges solved covering CredVault Parcel migration mismatch where the forwarding validator only checks a legacy dword the strict validator's checksum can't authenticate, Gatekeep FPGA-style combinational byte circuit solved as a constraint satisfaction problem, Kant stripped Rust binary whose check pipeline stacks XOR, AES-style S-boxes, MixColumns, power maps mod 257, two 16-round Feistel transforms, byte permutations and a bit permutation all inverted from the embedded compare target, and Pusher 32-bit i386 signal-driven VM with SIGSEGV/SIGILL as branch instructions and a scanf %d vs %c input-format trap solved by 50 laps of the slot state machine to build the target string byte by byte"
---

OmniCTF 2026 Quals shipped a reverse-engineering track that runs the full spectrum from beginner constraint-solving to a signal-driven VM that uses `SIGSEGV` and `SIGILL` as branch instructions; in this **CyberSecurity Elite** **OmniCTF 2026 Quals reverse** writeup we walk all four. Four challenges: **CredVault** (medium, 85 solves) is a Parcel-format migration mismatch between two validators over a binary TCP protocol; **Gatekeep** (medium, 62 solves) is a PNG-only FPGA schematic solved as a byte-level constraint satisfaction problem; **Kant** (medium, 92 solves) is a stripped Rust binary whose hidden `check <hex>` mode stacks XOR / S-boxes / MixColumns / power-maps mod 257 / two 16-round Feistels / byte and bit permutations, all reversible from the embedded compare target; **Pusher** (hard, 500 points, 0 solves at release) is a 32-bit i386 ELF whose control flow is smuggled through installed signal handlers and whose `%d` vs ` %c` format-string trap costs an entire remote instance to figure out from the wrong side.

Handouts, per-challenge READMEs, and solver scripts live at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). This writeup covers the four reverse challenges I solved. The paired writeups on the same event are the [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/) (Ganzir SSTI via reset-token debug leak into Jinja2 `read_file`; StayWild GNU tar `--checkpoint-action` option injection through unfiltered filenames) and the [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/) (nullshui glibc 2.39 tcache poison over `_IO_2_1_stdout_`; WinCapture Windows kernel-driver `COPY` double-read race).

## The four OmniCTF 2026 Quals reverse challenges

| Challenge | Difficulty | Bug class / primitive | Flag |
|---|---|---|---|
| CredVault | Medium (85 solves) | Small stripped Linux ELF over a binary TCP protocol. Five commands (load, strict-validate, forward-validate, flag, cookie). Strict Parcel validator checks structure + reversible checksum `p[5] == p[1] ^ 0xca110000` but never restricts `p[1]`. Forwarding validator only checks `p[1] == 0xca110042`. Migration bug: one field authenticates the strict path via the checksum while unlocking the legacy forwarding path directly. Single Parcel satisfies both: `p = {0xca110001, 0xca110042, 1, 0, 0, 0x42}`. Chain: load → strict-validate → forward-validate → flag. | `OmniCTF{d1_532d0a87aa120465_7da960a4f955190182f4f760115accb6_1c52be88d2cf76a2f23f8b80cb756e3b}` |
| Gatekeep | Medium (62 solves) | Handout is a PNG-only schematic of a combinational byte circuit. Nine byte inputs `c1..c9`, mixed arithmetic (add/sub mod 256), bitwise (AND/OR/XOR/NOT), and equality comparators against nine constants ANDed into a final `valid`. Solve as constraint satisfaction: start with `c9+c5==0xa5` and `c9^c5==0x41` pinning `(c9,c5)` to a small set, then derive `c1` from `(c1+c5)-c9==0x87`, and propagate through the rest. Verify the byte string matches the published `md5 = 47797f54...`; the flag body is `sha256(password)`. Wire-crossing trap on the `0x45` branch (visual crossings without connection dots are not connections). | `omniCTF{286fc732ff998a04c5660b517df3404b4de58292ae0b3002fd107ecb484f8d70}` |
| Kant | Medium (92 solves) | Stripped Rust ELF with a visible shifting-maze game as distraction and a fake `.rodata` flag. Hidden `check <hex>` mode expects 36 hex-decoded bytes; forward pipeline stacks: XOR key0 → S-box(0x63 affine) → AES MixColumns-style diffusion → power map `(b+1)^17 mod 257` minus 1 → 16-round Feistel A → 36-byte Fisher-Yates shuffle A → bit permutation by 13 → S-box(0x8f) → 16-round Feistel B → power map `(b+1)^11 mod 257` minus 1 → XOR key1 → shuffle B → memcmp target. Every stage reversible: `pow(17,-1,256)` and `pow(11,-1,256)` invert the power maps, Feistel rounds reverse without inverting F, SplitMix64 keystream is deterministic. Invert from the embedded target. | `OMNICTF{t1m3_x0r_1s_r3v3rs1bl3_cr4p}` |
| Pusher | Hard (0 solves at release) | 32-bit i386 ELF that installs `SIGSEGV` (0x11) and `SIGILL` (0x4) handlers and uses bad memory accesses / illegal instructions as VM branches. Win condition: `hz_sp == strlen(hz_target)` and `hz_stk[1:1+hz_sp] == hz_target`, then menu option 4. Menu reads decimal via `%d`, but push data reads via ` %c`: sending `65\n` writes `'6'`, not `'A'`. Slot state machine transitions (slots 0-8) let one lap stabilise exactly one new byte. 50 full laps build the first 50 target bytes, one partial lap leaves the last 4 live, option 4 runs the checker and copies the real remote `flag.txt`. | `OmniCTF{H3ap_1T_a11_L3ave_N0n3}` |

The four challenges share a discipline worth stating up front: **read past the visible surface**. CredVault's second validator does not enforce what the first does. Gatekeep's wire crossings without connection dots aren't wires. Kant has a large fake `.rodata` flag pinned next to the real embedded compare target, and the whole maze game is a decoy for a hidden CLI mode. Pusher has a placeholder local `flag.txt` output that will never match remote, and its scanf format string quietly switches between `%d` and ` %c` between menu and payload. In every case the trained-triage move is to enumerate the whole binary or schematic before committing to what a single visible pointer *seems* to say.

## Methodology — every stage is reversible, so invert from the target

A pattern that worked across every challenge in this set: **when the target of the final comparison is a fixed value in the binary, work backwards from that target instead of trying to guess the input**. Kant is the cleanest example. The `check` branch does a `memcmp` against a specific 36-byte blob in `.rodata`; every transform between the user input and that memcmp is deterministic and reversible; so the input that passes is `inverse_pipeline(target)`. No brute force, no SMT, no dynamic instrumentation past confirming the pipeline order. CredVault is the same shape at a smaller scale: the flag path checks two flags that get set by two validators. The validators check *properties*, so working out which single Parcel satisfies both properties is the whole exploit. Gatekeep is the constraint-satisfaction cousin: the target is a conjunction of nine byte equalities, and the input `(c1..c9)` that satisfies all nine is recoverable in a few seconds of Python without any solver library.

Pusher is the outlier because it doesn't expose a target you can invert from. The compare is a `strcmp` against a fake local target in the binary; the *remote* replaces the flag file, and the fake target's role is to make the local exploit lightning-quick to develop. The signal-driven VM is designed to make static disassembly look chaotic, so the trained move is to run the binary and *name globals as you go*: pick a global that changes every prompt, tag it (`hz_sp`, `hz_stk`, `hz_slot`), and infer the transitions dynamically. The `scanf` format switch between `%d` and ` %c` between menu and payload is the one trap that will burn a remote instance if you don't observe it locally first; it's why setting up the 32-bit loader before spending a remote attempt pays for itself many times over.

Per-challenge walkthroughs follow.

## 1. CredVault

Binary TCP protocol reversing. Two validators disagree on which Parcel field authenticates the payload. One Parcel satisfies both.

### Step 1 — Triage

```
$ file credvault
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Full RELRO + canary + NX + PIE. Points away from memory corruption; the challenge is about the state machine.

Strings are sparse:

```
CREDVAULT_FLAG
CTF{local_test_only_not_a_real_flag}
```

The service reads `CREDVAULT_FLAG` from the environment, unsets it, and accepts one TCP connection. The local placeholder isn't the real flag; the remote runner injects the real one.

### Step 2 — Wire format

The handler reads 8 bytes for `{u32 command, u32 body_len}`, optionally reads `body_len` bytes, and writes a response `{u32 status, u32 output_length, optional output}`. Small Python helper:

```python
def request(sock, cmd, body=b""):
    sock.sendall(struct.pack("<II", cmd, len(body)) + body)
    status, length = struct.unpack("<II", recvn(sock, 8))
    data = recvn(sock, length) if length else b""
    return status, data
```

### Step 3 — Command surface

The dispatch subtracts `0xca000001` and accepts five commands:

| Command | Body | Behaviour |
|---|---|---|
| `0xca000001` | 0 | Returns a 4-byte cookie |
| `0xca000002` | 24 | Stores Parcel, marks loaded |
| `0xca000003` | 0 or body | Strict validator; sets `strict_authorized` |
| `0xca000004` | 0 or body | Forwarding validator; requires strict auth |
| `0xca000005` | 0 or body | Returns flag if `forwarded != 0` |

### Step 4 — The two validators disagree

Strict validator:

```c
bool strict(uint32_t *p, uint32_t len) {
    if (len <= 0x17) return false;
    if (p[0] != 0xca110001) return false;
    if (p[2] != 1) return false;
    if (p[3] != 0) return false;
    if (p[4] != 0) return false;
    return (p[1] ^ 0xca110000) == p[5];   // reversible checksum
}
```

Forwarding validator:

```c
bool forwarding(uint32_t *p, uint32_t len) {
    return len > 0x0f && p[1] == 0xca110042;   // literal check
}
```

The strict path never restricts `p[1]` beyond the checksum, and the checksum is trivially satisfiable because we choose both `p[1]` and `p[5]`. The forwarding path checks a specific magic value in the same field.

### Step 5 — One Parcel to satisfy both

```python
parcel = struct.pack("<6I",
    0xca110001,   # strict magic (p[0])
    0xca110042,   # forwarding magic (p[1])
    1,            # p[2]
    0,            # p[3]
    0,            # p[4]
    0xca110042 ^ 0xca110000,   # 0x42 (p[5], checksum)
)
```

### Step 6 — Fire the chain

```python
request(sock, 0xca000002, parcel)   # load
request(sock, 0xca000003)           # strict authorize
request(sock, 0xca000004)           # forward validate
status, flag = request(sock, 0xca000005)
```

Live output:

```
OmniCTF{d1_532d0a87aa120465_7da960a4f955190182f4f760115accb6_1c52be88d2cf76a2f23f8b80cb756e3b}
```

Per-challenge README + solver: [rev/credvault](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/rev/credvault).

The bug class is a migration mismatch. When a binary format changes shape (new fields, new checksum), the old fields sometimes stay live in secondary paths ("forwarding", "backward-compat mode", "legacy client support") that were signed off before the migration. When strict and legacy validators disagree on which fields authenticate what, the attacker is free to satisfy both with a single artefact. Real-world analogues: JWT header/payload mismatches (`typ: JWT+CWT` styled bypasses), Kubernetes `apiextensions.k8s.io/v1beta1` versus `v1` validation windows, PDF signed-content-vs-visible-content mismatches, X.509 SAN vs CN mismatches, HTTP request smuggling primitive as a whole. Any legacy validator that survives a migration deserves an audit against every field the new one checks.

## 2. Gatekeep

PNG-only FPGA schematic. Nine byte inputs, nine equality comparators ANDed to `valid`. Solve as a constraint satisfaction problem.

### Step 1 — Read the schematic

```
$ file checker.png
checker.png: PNG image data, 10000 x 13506, 8-bit/color RGBA, non-interlaced
```

Ten-thousand-pixel-wide image, no embedded SVG source, no vector metadata. The useful artefact is what's rendered. Zoom out to catalogue the primitives:

- Nine byte inputs named `c1` through `c9`.
- Arithmetic gates: `+` (add mod 256), `-` (sub mod 256).
- Bitwise gates: AND, OR, XOR, NOT (masked to one byte).
- Equality comparators against byte constants.
- Final AND chain producing `valid`.

Constants at the comparator chain, read left to right:

```
0x60, 0x45, 0xaf, 0xbb, 0xa5, 0x41, 0xb2, 0x87, 0xfd
```

### Step 2 — Watch for the wire-crossing trap

The `0x45` branch has several long wires crossing near the top-left. Following the visually nearest line makes the branch look like it uses `(c1 + c4)`. Connection dots are the ground truth: the actual expression is `((c1 + c3) + c2) | (c1 & c2)`. Getting this branch wrong produces a plausible-looking but wrong candidate set. Trust dots, not proximity.

### Step 3 — Traced constraint system

```
((c1 - c4) ^ (c1 + c4)) == 0x60
(((c1 + c3) + c2) | (c1 & c2)) == 0x45
((c9 ^ c6) - (c8 & c6)) + (c9 - ~(c1 & c2)) == 0xaf
((c7 & ~c4) ^ (c1 + c5)) == 0xbb
(c9 + c5) == 0xa5
(c9 ^ c5) == 0x41
((c6 & c5) ^ (c9 | c5) ^ (~c5 & ~c6)) == 0xb2
((c1 + c5) - c9) == 0x87
((c4 & c5 & c9) | (((c1 & c8) & c2) ^ (c2 + c8))) == 0xfd
```

### Step 4 — Solve in dependency order

The two comparators against `(c9, c5)` collapse first. `c9 + c5 == 0xa5` and `c9 ^ c5 == 0x41` pin the pair to a small set. Then `(c1 + c5) - c9 == 0x87` gives `c1` immediately for each candidate. Propagate through `c6`, `c4`, `(c2, c8)`, `c3`, `c7` in order and enumerate the survivors.

```python
for c9 in range(256):
    for c5 in range(256):
        if add8(c9, c5) != 0xa5: continue
        if c9 ^ c5 != 0x41: continue
        c1 = add8(0x87 + c9 - c5, 0)
        ...  # propagate
```

Verify each surviving `(c1..c9)` byte string against the published `md5 = 47797f54b0f9f4b5b46463e7f86655d5`. Exactly one matches:

```
c1..c9 = 0x48 0x57 0x66 0x30 0x72 0x4c 0x31 0x66 0x33
       = H    W    f    0    r    L    1    f    3
       = "HWf0rL1f3"
```

### Step 5 — Build the flag

```python
>>> hashlib.sha256(b"HWf0rL1f3").hexdigest()
'286fc732ff998a04c5660b517df3404b4de58292ae0b3002fd107ecb484f8d70'
```

Flag: `omniCTF{286fc732ff998a04c5660b517df3404b4de58292ae0b3002fd107ecb484f8d70}`.

Per-challenge README + solver: [rev/gatekeep](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/rev/gatekeep).

The generalisable pattern: byte-level combinational circuits map cleanly to Python constraint systems. Nine 8-bit unknowns is `2^72` combined, well past brute force, but solving in the right order reduces to enumerating one or two bytes at a time. Same shape applies to any small circuit reversing exercise, including bitcoin-style hashcash puzzles, small hash preimages with heavy internal structure, and hand-written obfuscated password checkers with `if (input[i] * K + M == target[i])`-style constraints. Trust the constants, solve in the order that pins the smallest search space first, verify with any secondary oracle (here, the published MD5).

## 3. Kant

Stripped Rust ELF. Visible shifting-maze game as decoy. Hidden `check <hex>` mode with a fully deterministic reversible pipeline against an embedded compare target.

### Step 1 — Triage

```
$ file kant
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

$ rabin2 -I kant | grep compiler
compiler: rustc version 1.89.0
```

Full RELRO + NX + PIE. Rust binary, so no memory corruption path.

Strings expose the hidden modes:

```
usage: kant check <hex>
THE SHIFTING MAZE
OMNICTF{n0t_th3_r34l_0n3_keep_d1gg1ng}   <-- decoy
correct, that is the flag.
```

The visible flag in `.rodata` is the fake. The `check <hex>` mode is the real challenge surface.

### Step 2 — Locate the compare target

The `check` branch decodes hex, requires exactly 36 decoded bytes, and eventually `memcmp`s against:

```
155df956979abc1b2cc950fc301c3fa7
a424feb1b7ece49e4c6ea8e9630c2e3e
9eebb3de
```

That's the target we invert from.

### Step 3 — SplitMix64 keystream

The checker allocates `0x2a0` bytes and fills `0x298` bytes with:

```python
state = 0x9EF879A83A2689F7
x = state
x ^= x >> 30; x *= 0xBF58476D1CE4E5B9
x ^= x >> 27; x *= 0x94D049BB133111EB
x ^= x >> 31
state += 1
```

Slices are used as:

| Range | Purpose |
|---|---|
| `[0x000:0x024]` | First 36-byte XOR key |
| `[0x024:0x144]` | 16 Feistel-A round keys × 18 bytes |
| `[0x144:0x14c]` | Seed for Fisher-Yates shuffle A |
| `[0x14c:0x170]` | Second 36-byte XOR key |
| `[0x170:0x290]` | Feistel-B round keys |
| `[0x290:0x298]` | Seed for Fisher-Yates shuffle B |

Fisher-Yates seed advances via:

```python
seed = seed * 0x5851F42D4C957F2D + 0x14057B7EF767814F
idx  = (seed >> 33) % remaining
```

### Step 4 — Two AES-style S-boxes

The helper generates a 512-byte table: 256-byte S-box + inverse. With affine constant `0x63` the first 16 bytes are the standard AES S-box (`63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76`). The helper is called twice: `make_sbox(0x63)` and `make_sbox(0x8f)`. So the checker has two AES-style S-box families.

### Step 5 — The full forward pipeline

```
input (36 bytes)
  XOR key0
  S-box(0x63)
  MixColumns-style over each 4-byte block
  power map (b+1)^17 mod 257, minus 1
  16-round Feistel A
  36-byte shuffle A
  bit permutation by 13
  S-box(0x8f)
  16-round Feistel B
  power map (b+1)^11 mod 257, minus 1
  XOR key1
  36-byte shuffle B
  memcmp against embedded target
```

Every stage is reversible.

### Step 6 — Inverses

**Power maps.** For each byte `b`, treat `b+1` as an element of `(Z/257Z)*`. The group has order 256. The inverse of `x → x^k mod 257` is `x → x^(k^-1 mod 256)`:

```python
INV_17 = pow(17, -1, 256)   # 241
INV_11 = pow(11, -1, 256)   # 163
```

**Feistel.** For `L, R = R, L ^ F(R, key)`, the inverse round is `L, R = R ^ F(L, key), L`. So both 16-round transforms invert by applying the same F with keys in reverse order (no need to invert the round function).

**Shuffles.** Fisher-Yates over indices `0..35` with the fixed seed sequence. Compute the permutation and undo with `perm^-1`.

**Bit permutation by 13.** Undo by rotating in the opposite direction.

**S-boxes and XORs.** Trivially reversible.

**MixColumns.** Standard AES-style invertible over GF(2^8); apply the inverse matrix per 4-byte block.

### Step 7 — Invert from the target

```python
data = target
data = undo_shuffle(data, perm_b)
data = xor_bytes(data, key1)
data = undo_power_map(data, INV_11)
data = undo_feistel(data, feistel_keys_b, sbox_b)
data = inverse_sbox(data, sbox_b)
data = undo_bit_permute(data, 13)
data = undo_shuffle(data, perm_a)
data = undo_feistel(data, feistel_keys_a, sbox_a)
data = undo_power_map(data, INV_17)
data = undo_mix_columns(data)
data = inverse_sbox(data, sbox_a)
flag = xor_bytes(data, key0)
# b'OMNICTF{t1m3_x0r_1s_r3v3rs1bl3_cr4p}'
```

Then run the reconstructed forward transform against `flag` and confirm the result equals the embedded target. That catches any mistake in S-boxes, shuffles, bit order, or Feistel inversion before you go to the binary.

### Step 8 — Verify with the hidden mode

```
$ ./kant check 4f4d4e494354467b74316d335f7830725f31735f72337633727331626c335f637234707d
correct, that is the flag.
```

Flag: `OMNICTF{t1m3_x0r_1s_r3v3rs1bl3_cr4p}`. The body reads as "time-XOR is reversible crap", which is exactly what the whole pipeline demonstrates.

Per-challenge README + solver: [rev/kant](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/rev/kant).

Two portable lessons. **Long deterministic pipelines against fixed embedded targets are always inversion, never brute force.** When every step is reversible and the compare target lives in `.rodata`, walking the pipeline backwards is strictly cheaper than any forward-search attempt. **Rebuild the forward pipeline as a sanity check.** After computing `flag = inverse_pipeline(target)`, running `forward_pipeline(flag)` and comparing to `target` catches every mistake in a controllable environment (no binary needed). If the two don't match, one specific stage is wrong; bisect.

## 4. Pusher

32-bit i386 ELF that installs `SIGSEGV`/`SIGILL` handlers and uses bad memory accesses / illegal instructions as VM branches. Hard, 500 points, 0 solves at release. The gotcha isn't the VM; it's a `scanf` format-string switch between menu and payload that costs a remote instance to discover from the wrong side.

### Step 1 — Triage

```
$ file challenge
ELF 32-bit LSB executable, Intel 80386, dynamically linked, not stripped
```

Unusually old shape for a modern challenge: 32-bit i386, no PIE, no canary, NX disabled, partial RELRO. Looks pwn-friendly but isn't; it's a reversing puzzle built around a custom execution model.

Exported symbols are helpfully named:

```
dispatch, master_loop, applyMove, isWin, loadFlag, win, main
```

Menu strings + fake target string:

```
1.Good stuff.  2.Tango down.  3.We're on.  4.Dropped 'em.
It's dark and I'm wearing sunglasses.
Pressure and time.
OMNICTF{G3T_R3A1_0N_R3M0TE_B0z0_TH1S_1S_NOT_A_HAND0UT}
Congrats!!!The flag is : %s
flag.txt
```

The hardcoded `OMNICTF{...}` string is the compare target for `isWin`, not the actual flag; the real flag lives in `flag.txt` on the remote and is copied by `loadFlag()` on success.

### Step 2 — The signal-driven VM

The binary registers handlers at startup:

```
sigaction(SIGSEGV=0xb, handler=0x860d2f4)
sigaction(SIGILL=0x4,  handler=0x860d380)
```

`dispatch` restores the VM stack pointer from a global and jumps through an indirect target:

```
080490c0 <dispatch>:
  mov esp, [0x840d240]
  jmp [0x860d2e4]
```

Static disassembly looks chaotic because the program uses invalid memory accesses and illegal instructions as VM branches: the signal handlers catch them, look up the intended target, and jump. Trying to trace the binary purely statically is a waste of time.

The productive move is dynamic: run it, name globals as their values change, ignore the dispatcher noise.

### Step 3 — Name the globals

Watching the globals at each prompt gives:

```
0x0880d420  hz_sp        logical stack depth
0x0880d454  hz_r1First   first-push latch
0x0880d458  hz_slot      current slot/state
0x0880d45c  hz_lastPush  previous operation
0x0880d460  hz_sub       substate inside a slot
0x0880d570  hz_stk       logical byte stack (data)
0x0880dd70  hz_target    fake target string
```

### Step 4 — Win condition

`isWin` reduces to:

```
hz_sp == strlen(hz_target)
hz_stk[1 : 1 + hz_sp] == hz_target
then menu option 4
```

For the fake local target, on success:

```
Congrats!!!The flag is : OMNICTF{no_flag_file_here}
```

Remote replaces the flag file, so reaching `win()` remotely prints the real flag.

### Step 5 — The scanf format trap

At the top-level menu:

```
SCANF fmt=%d dst=0x860d258
```

After option 1, the byte read uses a different format:

```
SCANF fmt=' %c' dst=0x860d254
```

This is the trap. Sending `65\n` after option 1 writes `0x36` (`'6'`), not `0x41` (`'A'`), because `%c` takes the first character of the input line, not an integer value. Sending `O\n` writes `0x4f` (`'O'`).

Any solver that treats push data as decimal integers works locally under a hand-rolled emulator but breaks against the real binary. Testing against the real 32-bit binary before spending a remote attempt is essential.

### Step 6 — Fix the local runtime

Running on an amd64-only VM fails with `./challenge: not found` (missing 32-bit loader, not missing file). Extract Ubuntu's `libc6:i386` into a user-writable dir and invoke the loader directly:

```
$ ./root_host/usr/lib/i386-linux-gnu/ld-linux.so.2 \
    --library-path ./root_host/usr/lib/i386-linux-gnu \
    ./challenge
```

Reliable local oracle with real Linux signal handling.

### Step 7 — Map the slot machine

The menu operations aren't an unbounded stack. State transitions across slots 0..8, one full lap stabilises exactly one target byte. Observed lap:

```
slot 0: push filler, pop
slot 1: push filler, pop
slot 2: push filler, pop
slot 3: first push -> next stable byte
slot 3: second push advances to slot 4
slot 4: pop, push filler
slot 5: pop, push filler
slot 6: pop, push filler
slot 7: push filler, push filler
slot 8: pop, pop, pop  -> reset to slot 0
```

The three pops at slot 8 rewind state while preserving the deep byte. Repeating the lap builds a long string even though `hz_sp` rises and falls constantly.

### Step 8 — Build the target string

Fake target length is 54 bytes:

```python
TARGET = "OMNICTF{G3T_R3A1_0N_R3M0TE_B0z0_TH1S_1S_NOT_A_HAND0UT}"
```

50 laps stabilise bytes `[0:50]`. One partial lap leaves bytes `[50:54]` = `"0UT}"` live at slot 8. Then:

```
hz_sp == 54
hz_stk[1:55] == TARGET
hz_slot == 8
```

Menu option 4 fires `isWin()`. The check passes, `loadFlag()` copies `/flag.txt`, and:

```
Congrats!!!The flag is : OmniCTF{H3ap_1T_a11_L3ave_N0n3}
```

### Step 9 — Run remotely

```
$ python3 solve.py | ncat --ssl \
    --ssl-servername pusher-<id>.inst.omnictf.com \
    --no-shutdown -q 30 \
    pusher-<id>.inst.omnictf.com 1337
...
Congrats!!!The flag is : OmniCTF{H3ap_1T_a11_L3ave_N0n3}
```

The `--no-shutdown -q 30` flags matter: `ncat` needs to keep reading after stdin EOF so the final print lines aren't dropped.

Per-challenge README + solver: [rev/pusher](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/rev/pusher).

The lesson worth carrying is that signal handlers as control flow are a legitimate anti-static-analysis technique in real malware and packers (VMProtect / Themida / SafenSoft SoftGuard families all use variants), and the intended reversing move is always dynamic. Name globals as they change, treat the VM's own state machine as the object you're mapping, and let the binary tell you the transitions instead of trying to reconstruct them from a broken static disassembly. The `%d` vs ` %c` scanf switch is a small but expensive trap: solver-development discipline is to always confirm one full round-trip against the real target binary before firing at the remote, and to log the exact bytes going in at each prompt.

## Cross-cutting defender notes

Five patterns recur across the OmniCTF 2026 Quals reverse track and translate directly into review or triage heuristics.

**Migration mismatches are a bug class.** CredVault has two validators over the same Parcel: one strict (new format), one forwarding (legacy). The strict validator wins the checksum but doesn't restrict the legacy field; the forwarding validator wins the legacy field but doesn't check the checksum. When a binary format migrates, every legacy code path that still reads any migrated field is a candidate for the same shape of bug. Real-world analogues: HTTP/1.1 → HTTP/2 upgrade paths that keep header parsing loose, protobuf v2 → v3 wire compatibility with `required` field semantics, ONNX opset version handoffs, JWT libraries that accept both HS256 and RS256 for the same key, gRPC-web fallback paths. Audit legacy parsers against every field the new one validates.

**Byte-level constraint systems reduce to small Python solvers.** Gatekeep's 9-input, 9-comparator circuit has `2^72` raw combinations but solves in a few seconds when the equations are applied in dependency order. Same shape applies to hand-written obfuscated password checkers, small AES-lookalike toy cyphers, per-character CTF flag validators (`if (input[i] * K + M == target[i])`), and even license-key checks in small commercial software. When the constant table is visible in the binary and each constraint is byte-level, brute force is usually one Python script away.

**Reversible pipelines against fixed compare targets are always inversion.** Kant's checker stacks 12 stages: XOR keys, two S-box families, MixColumns, two power maps mod 257, two 16-round Feistel transforms, byte permutations, a bit permutation. Every stage is reversible, and the compare target lives in `.rodata`. Walking the pipeline backwards is strictly cheaper than any forward attack. Same class: any custom cipher whose S-boxes / round functions are visible and whose target is embedded (obfuscated crackmes, in-app-purchase key validators, DRM tokens with local verification), any hash-of-transform-of-input check where the transform is deterministic.

**Non-cryptographic reversibility is a design property, not an accident.** Kant's power map `(b+1)^17 mod 257` looks non-invertible if you don't recognise 257 as prime and the exponent as a unit in `(Z/256Z)*`. Once you see that, the inverse is `pow(17, -1, 256) = 241`. Any transform that composes standard reversible primitives (XOR, S-box, byte permutation, Feistel round with any F, modular exponentiation with unit exponent mod prime, MixColumns) is reversible end-to-end without inverting the individual round function. The design lesson: if you want a one-way check, use a modern cryptographic hash (HMAC-SHA256, Argon2id), not a chain of reversible primitives.

**Signal handlers as control flow are a static-analysis defeat, not a security control.** Pusher's `SIGSEGV`/`SIGILL` handler dispatch is a legitimate obfuscation technique (real packers use it), but the intended reversing move is dynamic: run the binary, name globals, observe transitions. Any code base that treats "static analysers can't follow the control flow" as a security property is confusing obfuscation for authentication. The same pattern shows up in commercial packers, malware VMs, and some anti-cheat runtimes. Defence-in-depth needs a real trust boundary (signature, HMAC, remote attestation), not a control-flow smokescreen.

## Frequently asked questions

### What is OmniCTF 2026 Quals?

OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition, with challenges spanning web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces (`CTF{...}`, `OMNICTF{...}`, `OmniCTF{...}`, `omniCTF{...}`) depending on the challenge author's choice. This writeup covers the four reverse challenges I solved (CredVault, Gatekeep, Kant, Pusher). The paired [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/) and [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/) cover the other tracks. Per-challenge READMEs and solvers at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals).

### How does the CredVault two-validator mismatch work?

The service exposes strict-validate (`0xca000003`) and forward-validate (`0xca000004`) commands. Strict checks structure (`p[0]=0xca110001, p[2]=1, p[3]=0, p[4]=0`) plus reversible checksum `p[5] == p[1] ^ 0xca110000`. Forward only checks `p[1] == 0xca110042`. The strict validator never restricts `p[1]` beyond the checksum, and the checksum is trivially satisfiable because the attacker chooses both `p[1]` and `p[5]`. One Parcel `{0xca110001, 0xca110042, 1, 0, 0, 0x42}` satisfies both validators, unlocking the flag path.

### How is Gatekeep's byte-circuit solvable in a few seconds of Python?

Nine byte inputs is `256^9 ≈ 4.7 × 10^21` combined, past brute force. But the nine comparator constants and the traced equations pin the search space in dependency order: `(c9+c5==0xa5, c9^c5==0x41)` collapses `(c9, c5)` to a small set; `(c1+c5)-c9==0x87` derives `c1` immediately; propagate through the rest. Total search is a handful of nested 256-loops, seconds in straight-line Python. Verify each surviving byte string against the published `md5 = 47797f54b0f9f4b5b46463e7f86655d5`. Watch the `0x45` branch wire-crossing trap: connection dots (not visual proximity) determine which wires actually connect.

### What is the Kant check pipeline and how is it inverted?

Twelve stages against 36 bytes: XOR key0, S-box(0x63), AES MixColumns-style, power map `(b+1)^17 mod 257`, 16-round Feistel A, 36-byte Fisher-Yates shuffle A, bit permutation by 13, S-box(0x8f), 16-round Feistel B, power map `(b+1)^11 mod 257`, XOR key1, shuffle B, memcmp against embedded target. Every stage is reversible: power maps invert via `pow(17,-1,256) = 241` and `pow(11,-1,256) = 163`; Feistel inverts without inverting F (`L,R = R^F(L,key), L`); S-boxes have inverses; MixColumns is standard AES-invertible over GF(2^8); shuffles/permutations undo trivially. Inverting the whole pipeline from the target yields `OMNICTF{t1m3_x0r_1s_r3v3rs1bl3_cr4p}`. Rebuild the forward transform against the recovered flag as a sanity check.

### Why can Feistel rounds be inverted without knowing F?

A Feistel round is `L_{i+1} = R_i, R_{i+1} = L_i ^ F(R_i, key_i)`. The inverse is `L_i = R_{i+1} ^ F(L_{i+1}, key_i), R_i = L_{i+1}`. So you compute F with the same key on the *new* left half (which equals the *old* right half), XOR into the new right half to recover the old left, and swap. F never has to be inverted; you just apply it a second time with the same inputs. Kant's 16-round Feistel transforms apply this trick with per-round keys in reverse order for the inverse.

### What's the trap in Kant's `.rodata` "flag"?

Kant embeds a visible string `OMNICTF{n0t_th3_r34l_0n3_keep_d1gg1ng}` in `.rodata` as a decoy. Any reversing tool that greps for `OMNICTF{` will surface it. The actual compare target is a different 36-byte blob elsewhere in `.rodata` (`155df956979abc1b2cc950fc301c3fa7...`), which is the value the checker's memcmp compares against. Recognising this needs a full pass over the checker function, not a strings-based first look. The decoy is deliberately placed near the fake to make grep-first tooling misidentify it as the answer.

### How does Pusher's signal-driven VM work?

The binary installs `sigaction` handlers for `SIGSEGV` (signal 11) and `SIGILL` (signal 4) at startup. Throughout the code, deliberate bad memory accesses (`mov [invalid], reg`) or illegal instructions serve as VM branch instructions: the handler catches the signal, looks up the intended target from a jump table indexed by the trapping PC, restores the VM stack pointer, and jumps to the resolved target. Static disassembly looks chaotic because the "instructions" that cause the branches are not real jumps or calls. Dynamic analysis is required: run the binary, name globals as they change (`hz_sp`, `hz_slot`, `hz_stk`), infer the state machine from observed transitions.

### What is the Pusher `%d` vs `%c` scanf trap?

The top-level menu reads choices with `scanf("%d", ...)` (integer parsing, whitespace-tolerant). After picking option 1 (push), the byte to push is read with `scanf(" %c", ...)` (single-character read after skipping whitespace). Sending `65\n` after option 1 does *not* write `0x41` (`'A'`); it writes `0x36` (`'6'`), the first character of the input line. Any solver that treats push data as decimal integers works locally under a hand-rolled emulator but breaks against the real binary. Testing against the real binary before spending a remote attempt is essential; this trap alone accounts for the 0-solves-at-release stat.

### How does Pusher's slot state machine build the target string?

The state cycles through slots 0..8 with specific push/pop transitions per slot. Empirically, one full lap through 0..8 (with the specific push-filler / pop / push-real-byte / pop-reset pattern documented in the writeup) stabilises exactly one new byte at the correct position in `hz_stk`. 50 laps build the first 50 bytes of the 54-byte target. One final partial lap that stops at slot 8 leaves the last 4 bytes live. At that point `hz_sp == 54`, `hz_stk[1:55]` matches the target, and menu option 4 fires `isWin()`, which passes and calls `loadFlag()` to copy the real remote `/flag.txt`.

### What's the broader lesson from the OmniCTF 2026 Quals reverse track?

*Read past the visible surface, invert from the target when the pipeline is deterministic, and use dynamic analysis when static is deliberately broken.* CredVault's second validator doesn't enforce what the first does. Gatekeep's wire crossings aren't wires without dots. Kant has a decoy `.rodata` flag next to the real compare target. Pusher's local `flag.txt` output is a placeholder for the remote. In every case the trained-triage move is to catalogue the entire challenge surface (all strings, all handlers, all validators, all embedded blobs, all CLI modes) before committing to a hypothesis about which visible pointer matters. The plumbing between the visible surface and the actual weak point is where the exploit work lives.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and solver scripts at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). CredVault, Gatekeep, and Kant ship pure-stdlib Python solvers. Pusher ships a Python payload generator that pipes through `ncat --ssl` (with `--no-shutdown -q 30` for correct output draining). All solvers reproducible against fresh remote instances. Python 3.8+ is sufficient for all four.

## Closing notes

Four rev challenges pulled together by one discipline: **when every stage of the target's derivation is visible in the binary, walk it backwards from the compare target instead of trying to guess the input**. CredVault's checksum is reversible, so the strict validator authenticates nothing about `p[1]`. Gatekeep's byte comparators are a small constraint system, solvable in dependency order. Kant's twelve-stage pipeline is fully invertible from an embedded 36-byte target. Pusher is the outlier because its target is a stack state, not a bytestring, but the same discipline applies: name the globals, observe the state machine, walk the transitions backward from `isWin`.

For the same event's other tracks, the [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/) covers Ganzir (SSTI via reset-token debug leak into a Jinja2 `read_file` helper) and StayWild (GNU tar `--checkpoint-action` option injection through unfiltered filenames); the [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/) covers nullshui (glibc 2.39 heap null-write to tcache poison over `_IO_2_1_stdout_`) and WinCapture (Windows kernel-driver `COPY` IOCTL TOCTOU race); the [OmniCTF 2026 Quals crypto writeup](/ctf-writeups/omnictf-2026-quals-crypto-writeup/) covers dual_linera (two-modulus LWE + LLL), Whiskerfield-Meowtin (DH mod `65537^16` one-byte patch), and Orbital-Strike-Cannon (non-associative octonion state, per-satellite RREF); the [OmniCTF 2026 Quals game writeup](/ctf-writeups/omnictf-2026-quals-game-writeup/) covers permissiondenied and Shibiu; and the [OmniCTF 2026 Quals misc writeup](/ctf-writeups/omnictf-2026-quals-misc-writeup/) covers baccarat, Node (Node-RED unauth RCE + `DT_RUNPATH` SUID privesc), nostalgia (Scratch `.sb3` embedding a RISC-V Linux ROM), and Sanity P0zzl3 (jigsaw CP-SAT + QR repair). Adjacent reverse writeups on the site: the [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) covers Cat Simulator, C++ Unplugged, Dog Simulator (ARM64 FNV-1a Z3 preimage), and Mirror Mirror (self-referential SHA-256 XOR loop). The [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/) covers a modified TCC compiler with a 512-byte VM blob decrypted by an ELF-relocation-derived key. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is OmniCTF 2026 Quals?","acceptedAnswer": {"@type": "Answer","text": "OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition, with challenges spanning web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces (CTF{...}, OMNICTF{...}, OmniCTF{...}, omniCTF{...}) depending on the challenge. This writeup covers the four reverse challenges I solved (CredVault, Gatekeep, Kant, Pusher). The paired web and pwn writeups on the same site cover the other tracks. Per-challenge READMEs and solvers at github.com/Abdelkad3r/OmniCTF-2026-Quals."}},
    {"@type": "Question","name": "How does the CredVault two-validator mismatch work?","acceptedAnswer": {"@type": "Answer","text": "Strict-validate checks structure (p[0]=0xca110001, p[2]=1, p[3]=0, p[4]=0) plus reversible checksum p[5] == p[1] XOR 0xca110000. Forward-validate only checks p[1] == 0xca110042. The strict validator never restricts p[1] beyond the checksum, and the checksum is trivially satisfiable because the attacker chooses both p[1] and p[5]. One Parcel {0xca110001, 0xca110042, 1, 0, 0, 0x42} satisfies both, unlocking the flag path."}},
    {"@type": "Question","name": "How is Gatekeep's byte-circuit solvable in a few seconds of Python?","acceptedAnswer": {"@type": "Answer","text": "Nine byte inputs is 256^9 combined, past brute force. But nine comparator constants + traced equations pin the search space in dependency order: (c9+c5==0xa5, c9^c5==0x41) collapses (c9, c5) to a small set; (c1+c5)-c9==0x87 derives c1; propagate through the rest. Total search is a handful of nested 256-loops, seconds in straight-line Python. Verify against the published MD5. Watch the 0x45 branch wire-crossing trap: dots not proximity determine connectivity."}},
    {"@type": "Question","name": "What is the Kant check pipeline and how is it inverted?","acceptedAnswer": {"@type": "Answer","text": "Twelve stages against 36 bytes: XOR key0, S-box(0x63), MixColumns, power map (b+1)^17 mod 257, 16-round Feistel A, shuffle A, bit permute by 13, S-box(0x8f), 16-round Feistel B, power map (b+1)^11 mod 257, XOR key1, shuffle B, memcmp target. Every stage reversible: power maps invert via pow(17,-1,256)=241 and pow(11,-1,256)=163; Feistel inverts without inverting F; MixColumns invertible over GF(2^8); permutations undo trivially. Inversion yields OMNICTF{t1m3_x0r_1s_r3v3rs1bl3_cr4p}."}},
    {"@type": "Question","name": "Why can Feistel rounds be inverted without knowing F?","acceptedAnswer": {"@type": "Answer","text": "A Feistel round is L_{i+1}=R_i, R_{i+1}=L_i XOR F(R_i, key_i). The inverse is L_i = R_{i+1} XOR F(L_{i+1}, key_i), R_i = L_{i+1}. Compute F with the same key on the new left half (which equals the old right half), XOR into new right to recover old left, swap. F never has to be inverted; apply it a second time with the same inputs. Kant's 16-round transforms use this with per-round keys in reverse order for the inverse."}},
    {"@type": "Question","name": "What's the trap in Kant's .rodata flag?","acceptedAnswer": {"@type": "Answer","text": "Kant embeds a visible OMNICTF{n0t_th3_r34l_0n3_keep_d1gg1ng} in .rodata as a decoy. Any grep-based tooling surfaces it. The actual compare target is a different 36-byte blob elsewhere (155df956979abc1b2cc950fc301c3fa7...), which is the memcmp target. The decoy is placed near the real target to make grep-first tooling misidentify it. Requires a full pass over the checker function, not just strings."}},
    {"@type": "Question","name": "How does Pusher's signal-driven VM work?","acceptedAnswer": {"@type": "Answer","text": "The binary installs sigaction handlers for SIGSEGV (11) and SIGILL (4). Deliberate bad memory accesses / illegal instructions serve as VM branches: the handler catches the signal, looks up the intended target from a table indexed by trapping PC, restores VM stack pointer, jumps. Static disassembly looks chaotic because the branch 'instructions' aren't real jumps. Dynamic analysis is required: run the binary, name globals as they change (hz_sp, hz_slot, hz_stk), infer the state machine from observed transitions."}},
    {"@type": "Question","name": "What is the Pusher %d vs %c scanf trap?","acceptedAnswer": {"@type": "Answer","text": "Menu uses scanf('%d') for choices (integer parsing). After option 1, push data uses scanf(' %c') (single-character read after whitespace). Sending 65\\n writes 0x36 ('6'), not 0x41 ('A'), because %c takes the first character of the input line. Any solver treating push data as decimal integers works locally under a hand-rolled emulator but breaks against the real binary. Testing against the real binary before spending a remote attempt is essential."}},
    {"@type": "Question","name": "How does Pusher's slot state machine build the target string?","acceptedAnswer": {"@type": "Answer","text": "The state cycles slots 0..8 with specific push/pop transitions per slot. One full lap stabilises exactly one new byte at the correct position in hz_stk. 50 laps build the first 50 bytes of the 54-byte target; one partial lap leaves the last 4 bytes live at slot 8. At that point hz_sp==54, hz_stk[1:55] matches the target, menu option 4 fires isWin() which passes and calls loadFlag() to copy the real remote /flag.txt."}},
    {"@type": "Question","name": "What's the broader lesson from the OmniCTF 2026 Quals reverse track?","acceptedAnswer": {"@type": "Answer","text": "Read past the visible surface, invert from the target when the pipeline is deterministic, use dynamic analysis when static is deliberately broken. CredVault's second validator doesn't enforce what the first does. Gatekeep's wire crossings aren't wires without dots. Kant has a decoy .rodata flag next to the real compare target. Pusher's local flag.txt output is a placeholder for the remote. Catalogue the entire challenge surface before committing to a hypothesis about which visible pointer matters."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and solver scripts at github.com/Abdelkad3r/OmniCTF-2026-Quals. CredVault, Gatekeep, and Kant ship pure-stdlib Python solvers. Pusher ships a Python payload generator that pipes through ncat --ssl (with --no-shutdown -q 30 for correct output draining). All reproducible against fresh remote instances. Python 3.8+ is sufficient for all four."}}
  ]
}
</script>
