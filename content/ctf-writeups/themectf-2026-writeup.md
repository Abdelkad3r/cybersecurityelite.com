---
title: "THEM?! CTF 2026 Writeup: 7 Solved Challenges"
slug: "themectf-2026-writeup"
description: "THEM?! CTF 2026 writeup — the 7 reverse and crypto challenges I solved from an 85-challenge event, with exploit code and lessons learned."
date: 2026-06-01T02:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "themectf"
  - "them ctf"
  - "ctf 2026"
  - "reverse engineering"
  - "cryptography"
  - "chip-8"
  - "des weak key"
  - "xor cryptanalysis"
  - "unicorn engine"
  - "vm emulation"
  - "control flow flattening"
  - "modular arithmetic"
series: ["THEM?! CTF 2026"]
keywords:
  - "themectf 2026 writeup"
  - "themectf writeup"
  - "them ctf 2026"
  - "them?! ctf"
  - "themectf challenges"
  - "themectf solutions"
  - "themectf old cassette chip-8"
  - "themectf ancient signals fnv-1a"
  - "themectf entropy core vm"
  - "themectf eyes chico unicorn"
  - "themectf cascadino chain xor"
  - "themectf despacito des weak key"
  - "themectf no 7race modular"
  - "des weak key e1e1e1e1f0f0f0f0"
  - "chip-8 reverse engineering ctf"
toc: true
cover:
  image: "/images/articles/themectf-2026-writeup.png"
  alt: "THEM?! CTF 2026 writeup — all 7 challenges across reverse engineering and cryptography"
---

{{< ctf-meta platform="THEM?! CTF 2026" difficulty="Mixed (Easy → Hard)" os="Jeopardy (Reverse, Crypto)" skills="CHIP-8 emulation, x86-64 PE reverse engineering, Unicorn dynamic emulation, FNV-1a hash recovery, custom bytecode VMs, control-flow flattening, DES weak-key parity, XOR-chain cryptanalysis, modular arithmetic over 10^155" >}}

**THEM?! CTF 2026** is a large jeopardy event covered here by **CyberSecurity Elite**, with **85 total challenges** across the usual categories. This writeup covers the **seven challenges I personally solved**, all from the reverse-engineering and cryptography tracks — every one demanded a real RE or cryptanalytic technique end-to-end. The reverse picks range from a CHIP-8 ROM that paints its flag onto a 64×32 screen across ~2⁴⁰ encoder steps per round, to a Windows binary whose VM mutates its own register state *during dispatch*. The crypto picks are the same shape — three challenges that look obscure on the surface and reduce to a clean number-theory or XOR-algebra invariant once you read carefully.

This is the per-challenge writeup for the seven I solved. Each section below covers the bug, the exploit chain, and the recovered flag. Full per-challenge reproductions — solver scripts, Unicorn hooks, and the bytecode disassemblies — live in the source repository: [Abdelkad3r/themectf-2026](https://github.com/Abdelkad3r/themectf-2026).

## The event at a glance

| Category    | Challenge          | Core technique                                                                              |
|-------------|--------------------|---------------------------------------------------------------------------------------------|
| Reverse     | Old Cassette       | CHIP-8 ROM, 16-bit state-machine cycle (tail 329, cycle 34), 32 rounds paint the flag       |
| Reverse     | Ancient Signals    | 8-bit PCM XOR-leak from silence + FNV-1a-hashed `.text` slice as XOR key for the real flag  |
| Reverse     | Entropy Core       | 16-register 64-bit bytecode VM, 30 opcodes, DFS backtracking over printable ASCII           |
| Reverse     | Eyes Chico         | CFG-flattened VM with mutating dispatch state; Unicorn dynamic emulation walks past it      |
| Crypto      | Cascadino Chain    | 4-stage closed XOR cycle; flag-format crib (`THEM` ⊕ `c1[0:4]`) breaks the chain            |
| Crypto      | Despacito          | DES weak key disguised by parity bits (`E1…F0…` ↔ `E0…F1…`); encrypt == decrypt             |
| Crypto      | No 7race           | `a << 77777` ends with 155-digit suffix → CRT mod `10^155 = 2^155 · 5^155`, invert mod 5^155 |

## Methodology — the reusable framework

Jeopardy CTFs don't have an OS-user privilege boundary to cross, so the *"recon → enumeration → exploitation → flag"* shape carries the whole engagement. THEM?! CTF 2026 rewards two specific reading habits over and above the framework itself:

1. **Read the flag.** All seven flags are *descriptive* — they spell out the technique you were supposed to use. `0LD_T4P3_N3V3R_D1E5K7` ("old tape never dies, K7" — *K7* is French slang for cassette). `D3S_4774K_W3S_AW3S0M3` ("DES attack was awesome"). `R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL`. When you're stuck, look at what other solvers found and you'll see the next step described in plain English.
2. **Trust the prompt, then check it for misdirection.** Ancient Signals tells you to fix the player and listen to the tape — the *tape* is a Rick Astley rickroll and the *flag* is in the player's own `.data` section behind a static self-check. The brief is half-true and that's enough to get you started.

{{< callout type="info" title="Static vs dynamic" >}}
Four of the seven challenges are *easier* with dynamic instrumentation than with pure static analysis. Entropy Core and Eyes Chico both ship hand-rolled VMs where the dispatcher's side effects depend on prior state — symbolic execution stalls and Ghidra's decompiler renders something close to noise. Unicorn or QEMU-user gets you past both in a few hundred lines.
{{< /callout >}}

---

## Reverse Engineering

### Old Cassette — CHIP-8 ROM, state-machine cycle, 32 screen-paint rounds

The handout is a 3 282-byte CHIP-8 ROM (`main.bin`). The first opcodes are `00E0 1280` — `CLS; JP 0x280` — and the ROM never prompts for input. Instead, it paints the flag onto a 64×32 monochrome display, using a state machine that's iterated for absurd counts: up to ~10¹³ encoder steps per character.

Naïve emulation would take hours. The escape hatch is that the state machine at `0x2C0` is a pure function on 16 bits of state `(VA, VB)` seeded at `(0xA7, 0xC3)`:

- **Trajectory enters a short cycle almost immediately.** Tail length **329**, cycle length **34**.
- Once you have the cycle, `state_at(N)` is constant-time: `if N < 329: states[N] else: states[329 + ((N − 329) mod 34)]`.

The main routine at `0x900` runs **32 rounds**. Each round iterates the encoder a hard-coded number of times (rounds 0–15 use explicit `4^k` counters; rounds 16–31 invoke a wrapper firing `255 × (2³² − 1) ≈ 2⁴⁰` encoder steps per round), then computes:

```text
chr = mem[TBL[VA & 7] + off] ^ VA ^ VB
```

where `TBL` is a 9-byte dispatch table at `0x322`. Replay all 32 rounds with the cycle shortcut, sort the emitted characters by `(yp, xp)` to read the screen left-to-right, top-to-bottom:

```text
THEM?!CTF{
0LD_T4P3_N
3V3R_D1E5K
7}
```

**Flag:** `THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}`

**Defender takeaway:** state-machine obfuscators that look exponentially expensive are usually polynomially cheap once you spot the cycle. The trajectory of *any* pure function over a small state space `S` always enters a cycle within `|S|` steps — that's a one-line Floyd's tortoise-and-hare argument, not an exploit.

### Ancient Signals — two solves, one real flag

A Windows 64-bit GUI player (`player.exe`, miniaudio + WinMM) and a binary payload (`transmission.dat`). The brief says the *software* is corrupted and the flag is on the *tape*. Both halves are misdirection.

**Track 1 — the tape (the rickroll).** `transmission.dat` is 8-bit unsigned PCM XOR-encrypted with a 128-byte repeating key. Silence in 8-bit PCM is `0x80` (mid-range), so any silent region of the original audio leaks the key:

```python
key[p % 128] = data[p] ^ 0x80   # for any p in a silent region
```

The block `0x50..0xCF` is silent (it repeats byte-for-byte at `0xD0..0x14F`, which can only happen if both regions decode to all-zero samples). Recover the key, XOR the file → `RIFF…WAVE`. The audio is **Rick Astley** *Never Gonna Give You Up*. It is part of the joke; it is **not** the flag.

**Track 2 — the player (the real flag).** A 55-byte XOR-encrypted blob sits in `player.exe`'s `.data` section at VA `0x140080000`. The XOR key is the **FNV-1a hash** of an 80-byte slice of `.text` — the body of a tiny anti-tamper helper at `0x1400032d0` that checks the first 4 bytes of its input are `"RIFF"`. Compute the hash, XOR the blob:

**Flag:** `THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}`

If you tried the brief literally — fix the player, listen to the tape — you'd emulate Windows with audio output just to confirm the rickroll. The flag-printing code path inside `player.exe` is gated by `is_RIFF()` on the raw input bytes, and the raw `.dat` starts with `08 CE 08 25` not `RIFF`, so the player always short-circuits to "Frequencies misaligned" regardless of whether you "fix" anything.

**Defender takeaway:** anti-tamper helpers whose *bytes* are used as a key are simultaneously self-protecting and self-incriminating. If a single instruction is rewritten by a debugger or hot-patched at load time, the hash changes, the XOR key changes, and the decoded payload is garbage. Worth knowing for both sides.

### Entropy Core — 16-register 64-bit bytecode VM

`entropy_core.exe` is a 134 KB MinGW C wrapper around a hand-rolled VM:

- 16 registers, 64-bit.
- 30 reachable opcodes through a `cmpb $0x61` jump table at `0x1400050c0`.
- A 284-byte bytecode program embedded in `.rdata` at `0x140005260`.
- Reads 36 input bytes, runs each through a per-byte hash that mixes the input into `R10`, compares low byte against a 36-byte ciphertext stored at the tail of the program.

Two static-analysis traps make the reverse harder than it looks:

1. **The fake-out RC4 key.** A 232-byte structure looks like an RC4 KSA setup; the real key is 16 bytes (`EntropyCoreV1!\x00\x00`).
2. **The shift operand isn't a register.** `ROL`/`SHL`/`SHR`/`ROR` opcodes take the shift amount as *the literal third operand byte* in the bytecode, not the value of a register pointed to by it. Misreading this puts every shift off by the byte's interpretation, and the solver finds no satisfying inputs.

Position 0 has many input bytes that all hit the target cipher byte; a greedy first-match search gets stuck after ~9 iterations. A **depth-first backtracking search that prefers printable ASCII** walks straight to the unique flag:

**Flag:** `THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}`

**Defender takeaway:** custom bytecode VMs are reverse-engineerable, but they're *time-expensive* to reverse engineer. The defensive cost is one developer-day. The offensive cost is several. Where the asymmetry is worth it (DRM, anti-cheat, license verification), VMs remain a viable layer; where it isn't (offline crackmes), they're decorative.

### Eyes Chico — control-flow-flattened VM with mutating dispatch state

`1983.exe` is a 22.5 KB console crackme — prompt `flag> `, compare 113 bytes of input against a value the program computes for itself. The interesting part is *how* it computes:

- 491-byte instruction tape at `.rdata+0x580`.
- 36-entry jump table at `.rdata+0x18`.
- 113-byte stack buffer at `[rsp+0xbf]` written one byte at a time as the VM executes.
- Check is a SIMD `pxor` of 16-byte input chunks vs the buffer, `por` into `xmm1`, horizontal-reduce, branch on zero.

The VM's prologue **mutates state during dispatch**:

```text
k = ((ecx*2) XOR r11 XOR state[state[8]] XOR opcode) & 3
state[esi]          ^= ...
state[state[14]]    ^= ...
state[state[15]]    ^= ...
```

Same opcode value at two different points has different side effects, because the indices used to mutate the state vector depend on prior state. CFG flattening on top + a *"WRONG-EXIT"* sink as the default jump-table target makes static reconstruction a slog.

The escape hatch is **dynamic emulation via Unicorn**:

1. Map every PE section at its preferred VA.
2. Replicate `main`'s exact prologue — state seed, register values, stack layout.
3. Jump to the VM dispatcher entry.
4. Hook every write into `[rsp+0xbf … +0x130)`.
5. When RIP reaches the `leaq "flag> ", %rcx` instruction, the VM has terminated and the stack buffer is fully populated. Read 113 bytes.

```bash
$ ./solve.py
[+] loaded .text  at 0x140001000 size 0x2400
[+] loaded .data  at 0x140004000 size 0x200
[+] loaded .rdata at 0x140005000 size 0x1400
[+] emulating 0x140002ac0 -> 0x140002b80
THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}
```

The flag spells out the entire defensive technique.

**Defender takeaway:** anti-static-analysis combinations (CFG flattening + state-mutating dispatch + decoy strings) raise the static cost dramatically, but emulation-with-hooks is a constant-cost answer. If your binary's job is to *eventually* write the right bytes into a buffer somewhere, an attacker who can run it on a controlled CPU will eventually read those bytes back.

---

## Cryptography

### Cascadino Chain — closed 4-cycle of XOR keys

Four hex ciphertexts of equal length (42 bytes each):

```text
c1 = 36273f225d4e393b2414025f1030025f1030025f10301907035e145e0c082508520a0930001d081d1012
c2 = 0e021b000e021b00…  ← period 4
c3 = 180504021805040218…← period 4
c4 = 2020202020 + apparent random
```

The structure is a closed XOR loop:

```text
c1 = flag ⊕ k1
c2 = k1   ⊕ k2
c3 = k2   ⊕ k3
c4 = k3   ⊕ flag
```

so `c1 ⊕ c2 ⊕ c3 ⊕ c4 == 0` and the riddle's *"there's no way in"* boast is information-theoretically honest: with only `c1..c4`, you cannot recover the flag without one external constraint.

The external constraint is the **flag format**:

```python
k1 = bytes(a ^ b for a, b in zip(c1[:4], b"THEM")) = b"bozo"
flag = bytes(a ^ b for a, b in zip(c1, b"bozo" * 11)) = "THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}"
```

The other keys collapse for the joke:

```text
k2 = "lmao"
k3 = "them"
```

**Flag:** `THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}`

**Defender takeaway:** XOR is its own inverse, so any *cycle* of XOR encryptions sums to zero in the same way `a − b + b − a == 0`. Multiple-layer XOR doesn't add security against an attacker who has a known-plaintext crib of the same length as a single key — even if the key chain is much longer.

### Despacito — DES weak key disguised by parity bits

`ques.py` does DES-ECB with key `E1E1E1E1F0F0F0F0`, pads with `*` to a multiple of 8, base64-encodes the result.

DES has exactly four **weak keys** for which encryption equals decryption (`E_k(E_k(P)) == P`):

```text
01 01 01 01 01 01 01 01
FE FE FE FE FE FE FE FE
1F 1F 1F 1F 0E 0E 0E 0E
E0 E0 E0 E0 F1 F1 F1 F1   ← this one
```

Compare the supplied key against the third weak key, byte by byte:

```text
E1 vs E0  →  differ in bit 0 (LSB)
F0 vs F1  →  differ in bit 0 (LSB)
```

Every byte's LSB is a **parity bit**. DES's Permuted Choice 1 keeps only the 56 high bits of the 64-bit key, so `E1E1E1E1F0F0F0F0` schedules to *exactly the same 56-bit key* as the weak key `E0E0E0E0F1F1F1F1`. The supplied key is the weak key in parity-bit disguise.

With a weak key, encryption equals decryption. Calling `cipher.decrypt` (or `cipher.encrypt` — same thing here) on the base64-decoded ciphertext yields the plaintext directly:

```bash
$ ./solve.py
[+] key e1e1e1e1f0f0f0f0 -> weak after parity-strip? True
[+] decrypt == encrypt (weak-key cross-check passes)
THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
```

**Flag:** `THEM?!CTF{D3S_4774K_W3S_AW3S0M3}`

**Defender takeaway:** the four DES weak keys are taught in every introductory cryptography course and still ship in production code in 2026, usually disguised behind their parity-bit twins. If you're auditing a system that uses DES at all (you shouldn't be), check key derivation for the eight parity-bit twins of each weak key, not just the canonical form.

### No 7race — invert a left-shift mod `10^155`

`challenge.py` reads `flag.txt` as a big-endian integer `a`, computes `b = a << 77777`, converts to a decimal string, and gates execution on a fixed 155-digit decimal suffix. Nothing is printed; the constraint *is* the challenge.

`b.endswith(target_decimal_155)` rewrites as:

```text
a · 2^77777 ≡ target  (mod 10^155)
```

Factoring `10^155 = 2^155 · 5^155` and applying CRT:

- **mod 2^155.** `2^77777 ≡ 0 (mod 2^155)` because `77777 ≫ 155`. The constraint forces `target ≡ 0 (mod 2^155)` (which the handout's suffix satisfies) but tells you *nothing* about `a` — every value of `a` works modulo `2^155`.
- **mod 5^155.** `gcd(2, 5) = 1`, so `2^77777` is invertible. Compute `inv = pow(2, -77777, 5**155)`, then `a ≡ target · inv (mod 5^155)`.

`5^155 ≈ 2^359.7`, while the flag is ≤ 50 bytes = `2^400`. The residue class mod `5^155` contains exactly one *small* representative; convert it to bytes:

```bash
$ ./solve.py
[+] target has 155 decimal digits
[+] working modulus is 10^155 = 2^155 · 5^155
[+] recovered a mod 5^155: 32 bytes
THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}
```

**Flag:** `THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}` *("number theorem is fun.")*

**Defender takeaway:** any constraint of the form *"this big integer multiplied by `2^k` ends in these digits"* is a modular equation over `10^N`. The factorisation `10^N = 2^N · 5^N` plus CRT plus the multiplicative invertibility of `2` modulo `5^N` is a standard recipe. Recognising the recipe is the whole challenge.

---

## Lessons learned — what THEM?! CTF 2026 rewarded

Four patterns recur across these seven challenges; they're worth lifting out:

1. **Cycles collapse exponential-looking iteration counts.** Old Cassette's 10¹³ encoder steps reduce to ~330 state-machine steps once you find the cycle. Any pure-function iteration on a small state space is doing this whether you notice or not.
2. **Two-phase static + dynamic is the default reverse-engineering posture.** Entropy Core and Eyes Chico both fight static analysis with VM dispatch and mutating state. Both fall to ~200 lines of Unicorn that re-creates the prologue and hooks the buffer. Don't burn a week in Ghidra when an emulator is one pip install away.
3. **Flag formats are cribs.** Cascadino Chain's whole "unbreakable" boast is honest until you XOR `c1[:4]` against `"THEM"`. Any closed XOR cycle of ciphertexts loses to a four-byte known-plaintext crib at one position. Always try the format first.
4. **Read the bytes you're being given.** Despacito's key isn't *near* a weak key — it *is* the weak key, hidden behind parity bits. Ancient Signals' real flag isn't on the tape — it's in the player's own bytes. The handout doesn't tell you anything that isn't in the handout.

## Source repository

Every per-challenge writeup includes solver scripts, Unicorn emulation harnesses, and the bytecode disassemblies:

**Repo:** [github.com/Abdelkad3r/themectf-2026](https://github.com/Abdelkad3r/themectf-2026)

If you're building detections from this writeup, the *Defender takeaway* lines translate cleanly to rules — particularly the DES weak-key parity-bit detection (audit any DES key for the parity-bit twins of `0101…`, `FEFE…`, `1F1F…0E0E…`, `E0E0…F1F1…`), and the FNV-1a-of-`.text` anti-tamper pattern from Ancient Signals (a yara rule on the slice + the XOR'd blob is two strings and a constraint).

{{< faq >}}
[
  {
    "q": "What is THEM?! CTF 2026?",
    "a": "THEM?! CTF 2026 is a large jeopardy-style capture-the-flag competition that released 85 challenges in total across multiple categories. This writeup covers the seven challenges I personally solved, all from the Reverse Engineering and Cryptography tracks. The techniques covered include CHIP-8 emulation, hand-rolled bytecode VMs, Unicorn dynamic emulation, DES weak-key analysis, and modular arithmetic over a 155-digit modulus."
  },
  {
    "q": "How many challenges does THEM?! CTF 2026 have?",
    "a": "THEM?! CTF 2026 released 85 challenges in total across the event. This writeup documents only the seven I personally solved: four Reverse Engineering (Old Cassette, Ancient Signals, Entropy Core, Eyes Chico) and three Cryptography (Cascadino Chain, Despacito, No 7race). The flag prefix is THEM?!CTF{...} for every challenge in the event."
  },
  {
    "q": "Where can I find the THEM?! CTF 2026 solver scripts?",
    "a": "The full per-challenge writeups, solver scripts, and Unicorn emulation harnesses live in the source repository at github.com/Abdelkad3r/themectf-2026. Each challenge has its own directory with a README and standalone solver."
  },
  {
    "q": "How is the Old Cassette CHIP-8 challenge solved?",
    "a": "The ROM paints the flag onto a 64x32 monochrome screen using a state machine iterated up to 2^40 times per round. The state machine on (VA, VB) seeded at (0xA7, 0xC3) enters a short cycle with tail 329 and cycle length 34, so state_at(N) becomes constant-time. Replay all 32 painting rounds with the cycle shortcut, sort emitted characters by screen position, read THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}."
  },
  {
    "q": "What is the FNV-1a trick in Ancient Signals?",
    "a": "The flag is XOR-encrypted in player.exe's .data section. The XOR key is the FNV-1a hash of an 80-byte slice of the binary's own .text — the body of a small anti-tamper helper that checks input bytes start with RIFF. Hash the slice, XOR the blob, read the flag. The transmission.dat tape is a separate rickroll joke that does not contain the real flag."
  },
  {
    "q": "How does the Despacito DES weak-key attack work?",
    "a": "DES has four weak keys for which encryption equals decryption. The handout key E1E1E1E1F0F0F0F0 differs from the weak key E0E0E0E0F1F1F1F1 only in the LSB of each byte. Those LSBs are parity bits — DES's Permuted Choice 1 strips them, so both keys schedule to the same 56-bit key. With encrypt == decrypt, call decrypt on the ciphertext to recover the plaintext."
  },
  {
    "q": "What is the No 7race modular-arithmetic trick?",
    "a": "The constraint a << 77777 ends with a fixed 155-digit decimal suffix means a * 2^77777 equals target mod 10^155. Factor 10^155 = 2^155 * 5^155 and apply CRT. Mod 2^155 the shift erases all information. Mod 5^155 the value 2^77777 is invertible: compute pow(2, -77777, 5**155) and multiply. The single small representative of the residue class is the 32-byte ASCII flag."
  },
  {
    "q": "Should I use Unicorn for THEM?! CTF reverse challenges?",
    "a": "Yes for Eyes Chico and helpful for Entropy Core. Eyes Chico has CFG flattening plus a VM dispatcher whose state vector mutates during dispatch — static recovery is slow and Unicorn emulation finishes in a couple of seconds. Entropy Core's VM is statically tractable but the two operand-decoding traps (fake RC4 key, literal-byte shift operand) eat hours; instrumenting the run with breakpoints catches both."
  },
  {
    "q": "Is THEM?! CTF 2026 beginner-friendly?",
    "a": "Mixed. Cascadino Chain, Despacito, and No 7race are approachable with introductory crypto background — the techniques are textbook (XOR-cycle algebra, DES weak keys, CRT). The reverse track is more advanced: Old Cassette needs CHIP-8 familiarity, Ancient Signals assumes comfort with Windows PE internals and FNV-1a, Entropy Core and Eyes Chico require custom-VM reverse-engineering practice. Start with the three crypto challenges."
  },
  {
    "q": "What does the K7 in the Old Cassette flag mean?",
    "a": "K7 is French slang for cassette — pronounced ka-sept, where sept means seven in French. The compound k-sept sounds like cassette. The flag THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7} reads as 'old tape never dies, K7' — a self-referential joke matching the challenge title."
  }
]
{{< /faq >}}
