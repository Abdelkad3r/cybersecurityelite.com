---
title: "BDSec CTF 2026 Reverse Writeup: 3 Challenges Solved"
slug: "bdsec-ctf-2026-reverse-writeup"
description: "BDSec CTF 2026 reverse step-by-step: Easy RE 41-byte XOR/ROL/additive transform; Night Shift 5^8 pthread schedule brute-force; Borrowed Memory 12-step offset VM with checksum-gated instruction tape."
date: 2026-07-22T13:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BDSec CTF 2026"]
tags:
  - "bdsec ctf"
  - "bdsec ctf 2026"
  - "bangladesh ctf"
  - "ctf writeup"
  - "reverse"
  - "reverse engineering"
  - "elf reversing"
  - "linux binary analysis"
  - "xor rol transform"
  - "input length decoys"
  - "pthread schedule reversing"
  - "brute-force state machine"
  - "offset vm"
  - "instruction tape checksum"
  - "xorshift pseudo-random table"
  - "objdump disassembly"
  - "rabin2 imports"
  - "nm symbols"
  - "static analysis"
keywords:
  - "bdsec ctf 2026 reverse writeup"
  - "bdsec easy re challenge writeup"
  - "bdsec night shift writeup"
  - "bdsec borrowed memory writeup"
  - "reverse engineering elf writeup 2026"
  - "41-byte xor rol additive transform inverse"
  - "pthread worker dispatch schedule brute-force"
  - "5^8 sequence brute force ctf"
  - "offset vm instruction tape ctf"
  - "xorshift 32-bit table generator ctf"
  - "opcode-gated next-offset checksum"
  - "reverse from target compare"
  - "ror inverse of rol"
  - "unstripped elf symbol table triage"
  - "stripped elf strings imports triage"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/bdsec-ctf-2026-reverse-writeup.png"
  alt: "BDSec CTF 2026 reverse writeup — three challenges solved covering Easy RE Challenge an unstripped x86-64 ELF with four length-gated input paths where only the 41-byte BDSEC branch is real and its per-byte transform stacks a two-key XOR a rotate-left by (i mod 7)+1 an additive term (11i)^0x23 and a 13i mod 41 output permutation all trivially inverted from the embedded expected buffer, Night Shift a stripped x86-64 ELF that spawns five pthread workers dispatched by the user's eight-token shift code where a 5^8 brute-force over the shared 128-bit state hash accumulator plus round counter finds the unique schedule 2 0 4 1 3 0 2 4 that unlocks the .rodata table decryption printer, and Borrowed Memory a stripped x86-64 PIE that generates a 0x800-byte xorshift-seeded memory table patches specific offsets to encode a 12-step VM opcode tape where each user offset input decodes an opcode and derives the next offset through a checksum-gated transition producing the final 40-byte .rodata blob decryption via a four-source XOR loop combining encrypted bytes validator outputs state words and user inputs"
---

BDSec CTF 2026's three-challenge reverse-engineering track that runs the classic escalator: **Easy RE Challenge** (80 pts) is an unstripped ELF with four input paths, three of them decoys with convincing `AFLAG/BFLAG/CFLAG{...}` returns, and one real 41-byte `BDSEC{...}` branch guarded by a per-byte XOR + rotate-left + additive-term + output-permutation transform that inverts cleanly from the embedded expected buffer. **Night Shift** (100 pts) is a stripped ELF that spawns five pthread workers and dispatches them from the user's eight-token "shift code"; only 5^8 = 390 625 orderings exist, and exactly one matches the four 32-bit state targets plus the FNV-shaped hash accumulator, unlocking a `.rodata` printer that emits the flag byte by byte. **Borrowed Memory** (460 pts) is a stripped PIE that generates a 0x800-byte xorshift-seeded memory table, patches specific offsets to encode a 12-step VM opcode tape, and asks the user for twelve 16-bit offsets that walk that tape with checksum-gated transitions — after the twelfth step drops off the end of the table (next-offset = 0xFFFF), a four-source XOR loop decrypts a 40-byte `.rodata` blob into the real flag.

Handouts, per-challenge READMEs, and solver scripts live at [Abdelkad3r/BDSecCTF-2026](https://github.com/Abdelkad3r/BDSecCTF-2026). Adjacent writeups on the site: [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) shares the "reversible pipeline invert from the compare target" discipline; [OmniCTF 2026 Quals reverse writeup](/ctf-writeups/omnictf-2026-quals-reverse-writeup/) covers a signal-driven VM (Pusher) with the same "checksum stops you exactly at the wrong step" behaviour used by Borrowed Memory's opcode tape; [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/) walks a Rust binary that stacks similar reversible-transform layers.

## The three BDSec CTF 2026 reverse challenges

| Challenge | Points | Bug class / primitive | Flag |
|---|---|---|---|
| Easy RE Challenge | 80 | Unstripped x86-64 PIE ELF. Symbol table still has `expected.0..3`, `key_part_a`, `key_part_b`. `main` gates four input lengths (24, 26, 29, 41). Three shorter branches return convincing `AFLAG/BFLAG/CFLAG{...}` decoys; only the 41-byte branch reaches "Excellent work" and matches `BDSEC{...}` format. Per-byte forward transform: `keyed = input[i] ^ key_part_a[i%8] ^ key_part_b[i%8]; rotated = rol(keyed, (i%7)+1); out[(13*i)%41] = (rotated + ((11*i)^0x23)) & 0xff`. Every stage reversible — read `expected.3` at `0x2420`, un-permute the output index, subtract the additive term, `ror` the rotation, XOR the two key bytes back. Read the two 8-byte keys from `0x2450` (`key_b`) and `0x2458` (`key_a`) — the symbol table names them for you. | `BDSEC{e4SY_r3v3rS3_eNg1N33r1nG_cH4LL4ng3}` |
| Night Shift | 100 | Stripped x86-64 PIE ELF; `pthread_create/join/mutex_lock/cond_wait/broadcast/strtok_r/strtoul/fgets`. `main` at `0x1130` reads a line, tokenises with `strtok_r`, requires exactly 8 tokens each `<= 4`. Shared state initialised from `.rodata:0x2170` (`s0..s3 = 0x13579bdf, 0x2468ace0, 0x0badf00d, 0xc001d00d`; `h = 0x811c9dc5` — FNV-1a offset basis). Five worker threads dispatched by user's token order; each waits on `pthread_cond_wait` until the assignment matches its worker ID, then executes an update block from the jump table at `0x2020` (workers `0..4 → 0x1930, 0x1910, 0x18f0, 0x1820, 0x1958`). After all 8 assignments, `main` checks `(s0,s1) == 0x75a2cc729c8a97dc`, `(s2,s3) == 0x4969e73d1d87ef0f`, `h == 0x4455cee8`, `index == 8`. Brute-force `5^8 = 390 625` orderings in Python; unique schedule is `2 0 4 1 3 0 2 4`. Success path then reads a 36-byte encrypted table at `.rodata:0x2040` and combines it with final state words, per-step history values, and the input tokens to print the flag. | `BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}` |
| Borrowed Memory | 460 | Stripped x86-64 PIE ELF. Prompt: `"Return what was borrowed."` and a hint `"0x???? -> 0x???? -> 0x????"` — the input is not a password, it is a chain of 12 offsets. `main` generates a 0x800-byte pseudo-random table at `.bss:0x4080` from seed `0x91e10da5` via a 32-bit `state = state + i + 0x045d9f3b; state = (state << 13) ^ state; state ^= state >> 17; state ^= state << 5; table[i] = (state >> 11) & 0xff` xorshift-like mixer. Selected bytes/words/dwords are then patched (e.g. word at offset `0x20 = 0x7d95`) to encode the VM opcode tape. Each user input must satisfy `0x4000 <= v <= 0x47ff` and match `0x4000 + current_offset`. Validator reads `opcode = ((current_offset >> 3) ^ table[current_offset]) & 0xff`; only `0xc0..0xc3` accepted. Each opcode computes the next offset differently (near-table bytes, rolling counters, small rotation counts, current validator state); two-byte checksum at `table[current_offset+8..+9]` gates every step. Twelfth step must produce `next_offset == 0xFFFF`. Success path then decrypts a 40-byte blob at `.rodata:0x2220` via `c = enc[i] ^ (0x1d*i & 0xff) ^ validator_output[(5i+1)%12] ^ (validator_state[i%12] >> (8*(i&3)) & 0xff) ^ (user_inputs[(7i+3)%12] & 0xff)`. | `BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}` |

The three challenges share a discipline worth stating up front: **the compare target is in the binary — invert from it**. Easy RE stores the expected transformed buffer at `expected.3` and the two 8-byte keys as `key_part_a/b`; every transform between user input and that buffer is reversible, so the input is `inverse_pipeline(expected.3)` — no brute force, no dynamic instrumentation, no z3. Night Shift stores four 32-bit target words and an FNV-shaped hash target; the search space is only 390 625 orderings, so an exhaustive Python simulator of the five worker update blocks finds the unique schedule in under a second. Borrowed Memory stores everything — the seed, the patched instruction tape, the 40-byte encrypted flag blob, and the four-source decrypt loop — inside the ELF, and the twelve required inputs are derivable in one deterministic pass over the table. When the target of the final comparison is baked into the binary and every stage between input and target is reversible, working backwards is strictly cheaper than any input search.

## Methodology — every ELF is either unstripped-triage or stripped-strings

A pattern that worked across the whole track: **let the binary tell you where to look**. Easy RE is unstripped; `nm -an` immediately surfaces `expected.0..3` (the four length-branch compare targets) and `key_part_a/b` (the two 8-byte key blobs). The symbol names alone shape the initial hypothesis — "check is not a hash, it's a byte-array compare against transforms of the input". Night Shift is stripped, but `rabin2 -i` surfaces the pthread + strtok_r + strtoul + fgets imports, which name the entire input shape: "space-separated tokens parsed as unsigned integers dispatched into pthread workers". Borrowed Memory is stripped and does not import anything more interesting than `fgets`/`strtoul`/`printf`, so the strings are the compass: `"BORROWED MEMORY"` + `"0x???? -> 0x???? -> 0x????"` + `"Return what was borrowed."` telegraph that the user's input is a *chain of addresses*, not a passphrase — and the presence of a large `.bss` region plus a `.rodata` blob near the exit path locate both the generated instruction tape and the encrypted flag blob before you disassemble a single instruction.

The correlate: **prefer static reasoning over dynamic tracing when the transforms are reversible and the target is in `.rodata`**. Every challenge in this set falls into that shape. Setting up `strace`/`ltrace` or booting `gdb` to trace input handling is dead weight when the compare target is already in the binary and every transformation between input and target is a small deterministic function. The 460-point Borrowed Memory challenge in particular *looks* like it wants dynamic instrumentation because of the VM, but the VM is entirely inside the binary — table generator, patches, opcode dispatch, checksum, decrypt loop, all reproducible in Python.

Per-challenge walkthroughs follow.

## 1. Easy RE Challenge

80 points. Unstripped Linux ELF. Four decoy input paths, one real. The symbol table names every important object.

### Step 1 — Identify the binary

Start with the usual triage: `file` + `shasum`:

```bash
file e4sy_RE.bdsec
shasum -a 256 e4sy_RE.bdsec
```

```text
e4sy_RE.bdsec: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=b5930a6c7c87132a577db655d10d4d82b8f368fb,
for GNU/Linux 4.4.0, not stripped
65b9139481b00c69bd8ddbc7521d4ff0eca3e00571c315028b1c8ab30f26fcf8  e4sy_RE.bdsec
```

The single most important word in that output is **`not stripped`**. The symbol table survives, which means most of the first pass reduces to reading names.

### Step 2 — Inspect strings and symbols

`strings -a` surfaces the prompts and outcome messages:

```text
BDSec CTF 2026
Reverse Engineering Challenge
Enter the flag:
[+] Excellent work, reverse engineer!
[+] Submit the flag to the CTF platform to receive your points.
[+] Congratulations! You found a flag!
[+] Nice reversing work. Keep exploring the binary...
[-] The binary still has secrets to reveal.
[-] Incorrect flag.
```

Four success/near-success messages, not one. That's already a tell: multiple paths exist, and only one is the real flag. `nm -an` then confirms the check is a byte-array comparison, not a hash:

```bash
nm -an e4sy_RE.bdsec
```

```text
00000000000010e0 T main
00000000000023c0 r expected.0
00000000000023e0 r expected.1
0000000000002400 r expected.2
0000000000002420 r expected.3
0000000000002450 r key_part_b.4
0000000000002458 r key_part_a.5
```

Four `expected` buffers named `.0..3`, plus two adjacent 8-byte key parts. Numbering matches the four input-length paths — one `expected` per accepted length. The strings `AFLAG{...}`, `BFLAG{...}`, `CFLAG{...}` never appear in the binary directly because they are the *decrypted* outputs of three of the branches; the real flag `BDSEC{...}` is likewise the decrypted output of the 41-byte branch. Everything the binary stores is *transformed*.

### Step 3 — Find the length gates

Disassemble `main`:

```bash
objdump -d -M intel e4sy_RE.bdsec | sed -n '/<main>:/,+260p'
```

Four length comparisons:

```asm
11ce: cmp rcx, 0x29   ; 41 bytes
11d2: je  0x12fb
11d8: cmp rcx, 0x1d   ; 29 bytes
11dc: jne 0x14af
...
14bc: cmp rcx, 0x1a   ; 26 bytes
14c0: jne 0x15d1
...
15d1: cmp rcx, 0x18   ; 24 bytes
15d5: jne 0x146b
```

The four length paths are `0x18=24`, `0x1a=26`, `0x1d=29`, and `0x29=41`. Only the 41-byte path reaches the strongest success message:

```asm
1453: test dl, dl
1455: je 0x1698
...
1698: lea rdi, [rip + 0xbb1]   ; "[+] Excellent work, reverse engineer!"
169f: call puts
16a4: lea rdi, [rip + 0xbcd]   ; "[+] Submit the flag..."
16ab: call puts
```

The shorter paths print softer "you found a flag" messages and finish there. Because CTF flag format is `BDSEC{...}` (7 fixed chars + inner content + `}` = at least 8 bytes overhead, and the inner content is inevitably more than 16 chars), the 41-byte branch is trivially the real one — but even without that heuristic, the strongest string prints from exactly one path.

### Step 4 — Reverse the real 41-byte transform

The 41-byte branch starts at `0x12fb`. The loop body transforms each input byte, stores it at a permuted output index, and finally compares the whole 41-byte output against `expected.3` at `0x2420`. Reconstructed forward transform:

```text
keyed   = input[i] ^ key_part_a[i % 8] ^ key_part_b[i % 8]
rotated = rol(keyed, (i % 7) + 1)
out[(13 * i) % 41] = (rotated + ((11 * i) ^ 0x23)) & 0xff
```

Three independent transform layers per byte plus a permuted output index. The compare is a byte-by-byte XOR that accumulates into an "any-mismatch" flag:

```asm
13de: lea rsi, [rip + 0x103b]        ; expected.3
...
1440: movzx ecx, byte ptr [rsp + rax]
1444: xor   cl,  byte ptr [rsi + rax]
144b: or    edx, ecx
144d: cmp   rax, 0x29                 ; loop until 41
1453: test  dl, dl                    ; any nonzero XOR → mismatch
1455: je    0x1698                    ; equal → success
```

This is a classic transform-and-compare, which is *always reversible* when every stage is a bijection. And every stage here is:

- XOR with two known constants → invert with the same XOR (self-inverse).
- `rol(k, r)` → invert with `ror(k, r)` where `r = (i % 7) + 1`, i.e. `r ∈ {1..7}`.
- Additive `+ ((11*i) ^ 0x23) & 0xff` → invert with the same subtraction mod 256.
- Output-index permutation `(13 * i) % 41` → 13 is coprime to 41, so the permutation is a bijection over `[0..40]`.

### Step 5 — Build the inverse

The inverse pipeline is:

```text
idx     = (13 * i) % 41
rotated = (expected[idx] - ((11 * i) ^ 0x23)) & 0xff
input[i] = ror(rotated, (i % 7) + 1) ^ key_part_a[i % 8] ^ key_part_b[i % 8]
```

Straight one-pass solver. The three fixed offsets (`expected.3 = 0x2420`, `key_b = 0x2450`, `key_a = 0x2458`) come directly from `nm -an`:

```python
#!/usr/bin/env python3
"""Recover the flag for BDSec CTF 2026 - Easy RE Challenge."""

import sys
from pathlib import Path

EXPECTED3_OFFSET = 0x2420
KEY_B_OFFSET     = 0x2450
KEY_A_OFFSET     = 0x2458


def ror(value: int, count: int) -> int:
    count &= 7
    return ((value >> count) | (value << (8 - count))) & 0xFF


def recover_flag(blob: bytes) -> str:
    expected = blob[EXPECTED3_OFFSET : EXPECTED3_OFFSET + 41]
    key_b    = blob[KEY_B_OFFSET     : KEY_B_OFFSET     + 8]
    key_a    = blob[KEY_A_OFFSET     : KEY_A_OFFSET     + 8]

    flag = bytearray(41)
    for i in range(41):
        out_index = (13 * i) % 41
        rotated   = (expected[out_index] - ((11 * i) ^ 0x23)) & 0xFF
        flag[i]   = ror(rotated, (i % 7) + 1) ^ key_a[i % 8] ^ key_b[i % 8]

    return flag.decode()


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("e4sy_RE.bdsec")
    print(recover_flag(path.read_bytes()))
```

Run against the handout:

```bash
python3 solve.py e4sy_RE.bdsec
```

```text
BDSEC{e4SY_r3v3rS3_eNg1N33r1nG_cH4LL4ng3}
```

For completeness, applying the same inverse to `expected.0..2` (with the corresponding lengths 24/26/29) recovers the three decoys:

```text
CFLAG{y0u_f0uNd_4_d3c0Y}
BFLAG{r3v3rS1ng_1s_4n_4rT}
AFLAG{n1c3_trY_bUt_n0_p01nTs}
```

Those are intentionally convincing, and if you rushed the challenge you would probably submit `CFLAG{y0u_f0uNd_4_d3c0Y}` before noticing the format mismatch. The scoreboard rejects it, and you go back to look for the fourth path.

Per-challenge README + solver: [reverse/easy-re-challenge](https://github.com/Abdelkad3r/BDSecCTF-2026/tree/main/reverse/easy-re-challenge).

Three portable lessons. **Unstripped binaries are half-solved before disassembly.** `nm -an` on an unstripped ELF surfaces the compare targets and key material by name; ignoring it costs an hour of reading assembly to derive the same layout. **Multiple success messages mean multiple paths, and only one is real.** When the string table contains four congratulatory sentences of varying strength, count them, count the length gates, and match them up. **Format-first triage.** A CTF flag format (here `BDSEC{...}`) is a length constraint — 41 bytes for this challenge is exactly the length that fits a plausible flag body, and none of the shorter lengths can.

## 2. Night Shift

100 points. Stripped ELF. Five pthread workers dispatched by user's 8-token order. `5^8 = 390 625` search space, exactly one valid schedule.

### Step 1 — Identify the binary

```bash
file night_shift.bdsec
shasum -a 256 night_shift.bdsec
```

```text
night_shift.bdsec: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=48903b3c743c56757f752c823eea610dbe011b47,
for GNU/Linux 4.4.0, stripped
```

Unlike Easy RE, this one is **stripped** — no function or object names — so the recon shifts from `nm` to `strings` + `rabin2 -i`.

### Step 2 — Inspect strings and imports

`strings -a` surfaces the challenge text:

```text
              NIGHT SHIFT
The building is closed.
Eight assignments remain.
shift code>
The morning report has been approved.
The shift report was rejected.
```

Two clean success/failure lines, and a clear prompt: `shift code>`. Together with `Eight assignments remain.` this already frames the input: the user types "shift code" — probably 8 tokens.

The imports pin the input parsing exactly:

```bash
rabin2 -i night_shift.bdsec
```

```text
pthread_create
pthread_join
pthread_mutex_lock
pthread_mutex_unlock
pthread_cond_wait
pthread_cond_broadcast
strtok_r
strtoul
fgets
putc
```

Now the shape is fully named:

- `fgets` reads one line.
- `strtok_r` splits it on whitespace.
- `strtoul` parses each token as an unsigned integer.
- Five `pthread_create/join` + `mutex/cond_wait/broadcast` → the 8 assignments are dispatched into 5 worker threads.
- `putc` at the end prints the flag byte by byte.

### Step 3 — Locate `main`

The ELF entry stub passes `0x1130` to `__libc_start_main`, so `main` is at `0x1130`:

```asm
15e8: lea rdi, [rip - 0x4bf]              ; 0x1130
15ef: call qword ptr [rip + 0x29cb]       ; __libc_start_main
```

Disassemble from there:

```bash
objdump -d -M intel night_shift.bdsec | sed -n '/0000000000001130/,+180p'
```

The input handling reads a line, tokenises on `" \t\r\n"`, and parses each token as base 10:

```asm
124c: lea rdi, [rsp + 0x140]
1258: call fgets
...
1269: lea rsi, [rip + 0xef8]              ; delimiter " \t\r\n"
1278: call strtok_r
...
12d8: mov edx, 0xa                        ; base 10
12e2: mov rdi, rbx
12ee: call strtoul
```

Each parsed value is bounded to `<= 4`:

```asm
129a: cmp rax, 0x4
129e: ja  reject
```

Exactly eight tokens are required — the loop rejects both fewer and more.

### Step 4 — Understand the shared state

Before spawning workers, `main` initialises a shared state block with four 32-bit words and a hash accumulator:

```text
s0 = 0x13579bdf
s1 = 0x2468ace0
s2 = 0x0badf00d
s3 = 0xc001d00d
h  = 0x811c9dc5     ; FNV-1a offset basis
```

The four state words come from `.rodata:0x2170`:

```text
df9b5713 e0ac6824 0df0ad0b 0dd001c0
```

Little-endian:

```text
0x13579bdf, 0x2468ace0, 0x0badf00d, 0xc001d00d
```

`h` is stored inline:

```asm
11cd: mov dword ptr [rsp + 0x118], 0x811c9dc5
```

`0x811c9dc5` is the FNV-1a 32-bit *offset basis*. That doesn't automatically mean this is a strict FNV hash — the shape of the tail update matters more — but it's a strong hint that the accumulator is doing an XOR-then-multiply-style mix per step.

### Step 5 — Reverse the worker dispatch

`main` spawns five worker threads with IDs 0..4:

```asm
1365: xor r12d, r12d
...
1371: lea rdx, [rip + 0x358]              ; worker at 0x16d0
1378: mov byte ptr [rbp + 0x8], r12b      ; store worker id
138e: call pthread_create
1397: add r12, 0x1
139f: cmp r12, 0x5
13a3: jne 0x1368
```

Each worker sleeps on `pthread_cond_wait` until the current assignment matches its worker ID:

```asm
1750: mov rax, qword ptr [r14 + 0x98]              ; current assignment index
175d: cmp byte ptr [r14 + rax + 0x8c], bl          ; assignment[index] == my id?
1765: je  0x17b8
176d: call pthread_cond_wait
```

Once its turn arrives, the worker jumps through a table at `0x2020`:

```asm
180d: movsxd r10, dword ptr [r12 + 4*rdx]
1811: add r10, r12
1814: jmp r10
```

Jump-table entries (worker ID → update block):

```text
0 -> 0x1930
1 -> 0x1910
2 -> 0x18f0
3 -> 0x1820
4 -> 0x1958
```

Each block mutates some combination of `s0..s3`. After every block, a common tail computes a per-step history value and stirs it into `h`. Concretely: worker N reads and writes specific 32-bit words with adds/xors/rotates, then the tail does `h ^= step_value; h *= 0x01000193;` (FNV-1a shape).

### Step 6 — Recover the target state

After all 8 assignments are dispatched, `main` compares the resulting state:

```asm
13c3: movabs rax, 0x75a2cc729c8a97dc
13cd: cmp qword ptr [rsp + 0xe8], rax
...
1403: movabs rax, 0x4969e73d1d87ef0f
140d: cmp qword ptr [rsp + 0xf0], rax
...
1417: cmp dword ptr [rsp + 0x118], 0x4455cee8
1424: cmp qword ptr [rsp + 0x128], 0x8
```

Because the machine is little-endian, the qword targets split into their component 32-bit words as:

```text
s0 = 0x9c8a97dc
s1 = 0x75a2cc72
s2 = 0x1d87ef0f
s3 = 0x4969e73d
h  = 0x4455cee8
index = 8
```

Exactly 128 bits of state target plus a 32-bit hash target plus an index sentinel. The search space is `5^8 = 390 625` — a Python brute force is under a second on any laptop.

### Step 7 — Brute-force the schedule

Port each of the five worker update blocks to Python (10-30 lines each), plus the common FNV-shaped tail. Then:

```python
from itertools import product

def simulate(schedule):
    s = [0x13579bdf, 0x2468ace0, 0x0badf00d, 0xc001d00d]
    h = 0x811c9dc5
    for step, worker in enumerate(schedule):
        # dispatch through the ported update blocks
        step_value = update_blocks[worker](s, step)
        h = ((h ^ step_value) * 0x01000193) & 0xFFFFFFFF
    return tuple(s), h

TARGET_S = (0x9c8a97dc, 0x75a2cc72, 0x1d87ef0f, 0x4969e73d)
TARGET_H = 0x4455cee8

for sched in product(range(5), repeat=8):
    s, h = simulate(sched)
    if s == TARGET_S and h == TARGET_H:
        print("schedule:", " ".join(map(str, sched)))
        break
```

The unique solution:

```text
2 0 4 1 3 0 2 4
```

### Step 8 — Reconstruct the flag printer

If the state check passes, `main` prints `"The morning report has been approved."` and enters a loop that emits `0x24 = 36` bytes via `putc`. The encrypted output table is at `.rodata:0x2040`:

```text
aa 9e 9c cc 35 63 ec 86 c5 c6 e4 1a 58 cc 3e 9d
e0 9c 28 40 0b a4 16 75 6a 3c fd c1 75 0f 17 de
dd 26 92 aa
```

The print loop combines four sources per output byte:

- the final state words `s0..s3`
- the eight per-step history values
- the eight original assignment numbers (the shift code)
- the current encrypted byte

Model that loop in Python, feed it the recovered schedule, and emit the decoded string:

```text
BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}
```

Feed the schedule into the actual binary as sanity check:

```bash
echo "2 0 4 1 3 0 2 4" | ./night_shift.bdsec
```

```text
              NIGHT SHIFT
Eight assignments remain.
shift code> The morning report has been approved.
BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}
```

Per-challenge README + solver: [reverse/night-shift](https://github.com/Abdelkad3r/BDSecCTF-2026/tree/main/reverse/night-shift).

Three portable lessons. **A stripped ELF's imports are half a specification.** `rabin2 -i` on `night_shift.bdsec` names every input-handling function and every synchronisation primitive; the whole "8 tokens dispatched into 5 workers" shape is inferrable from imports alone, before you disassemble a single instruction. **FNV-1a offset basis `0x811c9dc5` is a fingerprint.** Whenever you see that constant loaded into a 32-bit accumulator immediately before a loop that mixes in step data, model the tail as `h = (h ^ x) * 0x01000193` and it will almost always be right. **When the search space is `k^n` with small k and n, brute force is the answer.** `5^8 = 390 625` is a Python one-liner; do not build a SAT model when a `for sched in product(range(5), repeat=8)` loop finishes in under a second.

## 3. Borrowed Memory

460 points. Stripped PIE ELF. Twelve-step offset VM with checksum-gated transitions and a four-source XOR flag-decrypt loop.

### Step 1 — Identify the binary

```bash
file borrowed_memory.bdsec
shasum -a 256 borrowed_memory.bdsec
```

```text
borrowed_memory.bdsec: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=004f567f79e0423153e36794a81bc680ce203534,
for GNU/Linux 4.4.0, stripped
```

Stripped, PIE, dynamically linked. Same shape as Night Shift, so the recon rhythm is the same: strings first, imports second, entry point third.

### Step 2 — Inspect strings and the prompt

`strings -a` surfaces the challenge text:

```text
BORROWED MEMORY
0x???? -> 0x???? -> 0x????
Return what was borrowed.
>
rejected
[+]
```

The `0x???? -> 0x???? -> 0x????` line is not decorative; it's a literal signature of the input format. The program is asking for a *sequence of table addresses*, not a passphrase. The right mental model already forms from that single line: **the input is offsets, and offsets chain**.

### Step 3 — Rebuild the memory table

At `main` entry, the binary fills a table at `.bss:0x4080` with `0x800 = 2048` bytes. The generator uses seed `0x91e10da5` and a xorshift-shaped mixer, all 32-bit arithmetic:

```text
state = 0x91e10da5
for i in range(0x800):
    x     = (state + i + 0x045d9f3b) & 0xFFFFFFFF
    state = x
    state = ((state << 13) ^ x) & 0xFFFFFFFF
    state ^= (state >> 17)
    state ^= (state << 5) & 0xFFFFFFFF
    table[i] = (state >> 11) & 0xff
```

Two constants worth naming:

- `0x91e10da5` is the seed. Nothing famous, just a challenge-specific PRNG seed.
- `0x045d9f3b` is a Weyl-sequence increment style constant used by SplitMix and related PRNGs; combined with the xorshift-13/17/5 pattern this is a hand-written xorshift+ variant.

After generating 2048 pseudo-random bytes, the binary **patches specific bytes/words/dwords** into the table. These patches encode the VM opcode tape. For example, the first patch writes a word at table offset `0x20`:

```asm
1171: mov eax, 0x7d95
118a: mov word ptr [rip + ...], ax        ; table[0x20] = 0x7d95
```

The validator later reads that word and derives the starting offset via XOR with a fixed key:

```asm
15a8: movzx esi, word ptr [rip + ...]     ; table[0x20]
15d9: xor   si, 0x7c31
```

So the first offset is:

```text
0x7d95 ^ 0x7c31 = 0x01a4
```

Accepted user inputs are encoded as `0x4000 + offset`, so the first input must be `0x4000 + 0x01a4 = 0x41a4`. The trained-triage move is to write the table generator in Python first, apply the patches second, and let the emulator report offsets rather than trying to compute them by hand.

### Step 4 — Understand the input format

Input parsing loop:

- `fgets` reads a line into a stack buffer.
- Newline is stripped.
- `strtoul(..., base=0)` parses the number (base auto-detected — `0x41a4` works, `16804` also works).
- Any non-whitespace text after the number is rejected.
- The parsed value must satisfy `0x4000 <= value <= 0x47ff`.
- Exactly 12 values are stored on the stack as 16-bit words.

After the twelfth read, the validator runs.

### Step 5 — Decode the offset VM

Each validation round enforces the address chain and decodes one opcode:

```text
input[i] == 0x4000 + current_offset                      # binding check
opcode   = ((current_offset >> 3) ^ table[current_offset]) & 0xff
```

Only four opcodes are accepted: `0xc0`, `0xc1`, `0xc2`, `0xc3`. Each computes the next offset from a different mix of nearby table bytes, rolling counters, small rotation counts, and a per-step validator state word. Any other opcode drops into the reject path.

After computing `next_offset`, the validator reads a two-byte checksum at `table[current_offset + 8]` and `table[current_offset + 9]` and verifies it against a value derived from `current_offset`, `next_offset`, and the just-computed output byte. This checksum matters as much for the challenger as for the challenge author: **if your Python opcode-emulator is wrong at step N, the checksum at that step will fail and pin the bug to the exact step** — you don't have to guess which of twelve steps broke.

Replaying the full VM in Python produces the twelve-step chain:

| Step | Offset | Input | Opcode | Next offset |
| ---: | -----: | ----: | -----: | ----------: |
| 0  | `0x1a4` | `0x41a4` | `0xc3` | `0x2f0`  |
| 1  | `0x2f0` | `0x42f0` | `0xc2` | `0x143`  |
| 2  | `0x143` | `0x4143` | `0xc1` | `0x36c`  |
| 3  | `0x36c` | `0x436c` | `0xc0` | `0x21d`  |
| 4  | `0x21d` | `0x421d` | `0xc3` | `0x4a8`  |
| 5  | `0x4a8` | `0x44a8` | `0xc2` | `0x0f6`  |
| 6  | `0x0f6` | `0x40f6` | `0xc1` | `0x55b`  |
| 7  | `0x55b` | `0x455b` | `0xc0` | `0x317`  |
| 8  | `0x317` | `0x4317` | `0xc3` | `0x68c`  |
| 9  | `0x68c` | `0x468c` | `0xc2` | `0x25a`  |
| 10 | `0x25a` | `0x425a` | `0xc1` | `0x73d`  |
| 11 | `0x73d` | `0x473d` | `0xc0` | `0xffff` |

Two structural details worth naming:

- The opcode sequence is `0xc3, 0xc2, 0xc1, 0xc0` repeating three times. The four opcodes are chosen so that each one exercises a different arithmetic mix, and the repeating pattern makes the emulator easy to unit-test one opcode at a time (change `opcode = 0xc3` and stop at step 0; change to `0xc2` and stop at step 1; etc.).
- The last step is special: the twelfth `next_offset` must be `0xFFFF`. The validator checks this by adding one to the low 16 bits and requiring zero — a classic sentinel-terminated loop.

### Step 6 — Decrypt the flag

Once the twelve-step chain is accepted, the success path prints `"[+] "` and decrypts a 40-byte blob from `.rodata:0x2220`:

```text
10 0d 7c bb 7c 43 68 51 14 e8 ee aa 7c 5e dc 76
aa 77 e3 ef dc 96 99 0d 8c e7 94 95 13 93 8f 5b
5e 53 51 3c 24 56 29 bf
```

The decryption loop combines **four** sources per output byte:

- the encrypted byte at `.rodata`
- the twelve output bytes produced by the validator (one per step)
- the twelve 32-bit state words produced during validation
- the low byte of selected user inputs

In compact form:

```text
for i in range(40):
    c  = encrypted[i]
    c ^= (0x1d * i) & 0xff
    c ^= validator_output[(5 * i + 1) % 12]
    c ^= (validator_state[i % 12] >> (8 * (i & 3))) & 0xff
    c ^= user_inputs[(7 * i + 3) % 12] & 0xff
    flag[i] = c
```

Two of the four sources (`validator_output[]` and `validator_state[]`) are only knowable *after* a valid replay of the VM, which is why the chain has to be right before the decrypt can run. The `(5i+1) % 12` and `(7i+3) % 12` index permutations are chosen to touch every step's output and every step's state exactly across the 40 output bytes, so a single wrong opcode step corrupts multiple flag bytes.

### Step 7 — Run the solver end-to-end

The solver rebuilds the table, applies the patches, follows the twelve-step chain, verifies every checksum, and decrypts the final blob:

```bash
python3 solve.py
```

```text
inputs:
0x41a4 0x42f0 0x4143 0x436c 0x421d 0x44a8 0x40f6 0x455b 0x4317 0x468c 0x425a 0x473d
flag: BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}
```

Feed the twelve inputs into the binary to confirm:

```bash
printf '0x41a4\n0x42f0\n0x4143\n0x436c\n0x421d\n0x44a8\n0x40f6\n0x455b\n0x4317\n0x468c\n0x425a\n0x473d\n' | ./borrowed_memory.bdsec
```

```text
BORROWED MEMORY
0x???? -> 0x???? -> 0x????
Return what was borrowed.
> > > > > > > > > > > > [+] BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}
```

Per-challenge README + solver: [reverse/borrowed-memory](https://github.com/Abdelkad3r/BDSecCTF-2026/tree/main/reverse/borrowed-memory).

Three portable lessons. **A prompt hint that looks like a template is a template.** `0x???? -> 0x???? -> 0x????` is not decorative flavour text; it is the exact input format spelled out with placeholders. The lift from "asks for a password" to "asks for a chain of offsets" is the entire hard-thinking part of the challenge. **Instruction-tape checksums are a gift.** They are there to protect the challenge author against typos in their own opcode emitter, but the *same* checksum will pin any wrong emulator step for you — the failing checksum tells you the exact offset where your Python and the ELF disagree. Instrument every step to print `(current_offset, opcode, next_offset, checksum_ok)` and the bug converges in three iterations. **Anything that touches `.rodata` late is part of the flag-decrypt loop.** When the success path pulls from a `.rodata` blob and combines it with state values that only exist post-validation, model the loop in Python — do not attempt to construct the flag from a wrong emulator run just because the chain passed.

## Cross-cutting attacker + defender notes

Five patterns recur across the BDSec CTF 2026 reverse track and translate directly into practical triage or design heuristics.

**Symbol tables are the highest-signal artifact in an ELF.** Easy RE ships fully symbolised, and `nm -an` reveals `expected.0..3` and `key_part_a/b` before you disassemble anything. If you strip your own release binaries out of habit, ship debug binaries to your reversing team on request — the reversibility isn't the concern; the debugging-ergonomics gap is. Conversely, if you're on the offensive side, always `file` a binary before wasting a minute on strings — an unstripped binary is a fraction of the work of a stripped one, and knowing that upfront changes your tooling choice.

**Imports narrow the input shape.** Night Shift is stripped and gives nothing to `nm`, but `rabin2 -i` alone tells you that the program tokenises with `strtok_r`, parses with `strtoul`, and dispatches into pthread workers. Every stripped-binary triage should include a synchronisation-primitive and input-parsing import review — it is the closest thing to a specification the binary will give you.

**`0x811c9dc5` and `0x01000193` are fingerprints; so are `0x045d9f3b` and the `<<13/>>17/<<5` xorshift pattern.** Learn the small set of universally-used PRNG and hash constants (FNV-1a offset basis + prime, splitmix64 constants, xorshift-32/64 tap positions, AES S-box first byte `0x63`, MurmurHash's `0xcc9e2d51`). Once these are on autopilot, you skip the "what is this arithmetic doing" step and go straight to "port it to Python and unit-test one step."

**Checksums inside challenge VMs are dual-use.** Borrowed Memory's per-step 2-byte checksum exists to protect the author's opcode emitter from bugs during challenge construction, but it *doubles* as a debugging aid for the solver: your Python emulator's first wrong step will fail the same checksum, and the step number pins the bug. When you write a VM emulator to invert a challenge, always print the checksum status after every step — the checksum you thought was a wall is a floodlight.

**Reversible pipelines invert from the compare target.** Easy RE, Night Shift, and Borrowed Memory all end with a comparison against a value baked into the binary. Every stage between input and target is reversible (Easy RE: XOR + ROL + additive + permutation; Night Shift: five known update blocks + FNV-shaped hash mixed with step data; Borrowed Memory: opcode-gated offset transitions with published checksum). The correct default for reverse-engineering challenges of this shape is **invert first, brute-force second, dynamic-instrument third**. Setting up `gdb` or `pin` before you've read the compare and asked "is every step reversible?" is almost always premature.

## Frequently asked questions

### What is BDSec CTF 2026?

BDSec CTF 2026 is a Bangladesh-hosted Capture-the-Flag competition with challenges across reverse engineering, pwn, and web categories. Flags use the `BDSEC{...}` namespace (some web challenges use lowercase `bdsec{...}`). This writeup covers the three reverse challenges I solved: Easy RE Challenge (80 pts), Night Shift (100 pts), and Borrowed Memory (460 pts). Per-challenge READMEs and solver scripts at [Abdelkad3r/BDSecCTF-2026](https://github.com/Abdelkad3r/BDSecCTF-2026).

### How do you recognise decoy flags in a reverse-engineering challenge?

Two signals. First, **format mismatch**: if the challenge platform requires `BDSEC{...}` and the string you recovered is `CFLAG{...}` or `AFLAG{...}`, it's a decoy. The format is a hard constraint, not decoration. Second, **success-message strength**: in Easy RE, the four success/near-success messages are graded from softest ("Keep exploring the binary...") to strongest ("Excellent work, reverse engineer! Submit the flag..."), and only the strongest path is the real flag. Count the length gates in `main`, match them to the message strengths, and pick the strongest one to invert.

### Why is the unstripped Easy RE symbol table such a big time-save?

Because `nm -an` names the compare targets and key material directly. `expected.0..3` are the four buffers the four input-length branches compare against; `key_part_a` and `key_part_b` are the two 8-byte keys used in the per-byte XOR. Without symbols you'd have to read `main` end-to-end, follow every `lea` into `.rodata`, and infer the offsets from context. Symbols cut that first pass from an hour to two minutes.

### How do you brute-force the Night Shift schedule without running the real binary 390 625 times?

Port each of the five worker update blocks from x86-64 assembly to Python (~10-30 lines per block, straight translation of the `add`/`xor`/`rol`/`ror` sequences from disassembly). Then loop `for sched in product(range(5), repeat=8)`, run the ported simulator once per candidate, and check the four target state words plus the FNV-1a hash target. Under a second on any laptop. The real binary only runs once — to confirm the schedule works — after Python has already found it.

### Why is `0x811c9dc5` a hash fingerprint?

`0x811c9dc5` is the FNV-1a 32-bit *offset basis*, the standard initial value for the FNV-1a hash. Paired with `0x01000193` (the FNV prime) it uniquely identifies a Fowler-Noll-Vo hash mix pattern of the form `h = (h ^ x) * FNV_PRIME`. Whenever you see that constant loaded into a 32-bit accumulator immediately before a loop that XORs in step data and multiplies by `0x01000193`, model the accumulator as FNV-1a and skip the arithmetic-derivation step.

### What is the difference between the Borrowed Memory memory table and a bytecode interpreter?

Semantically none. The 0x800-byte table is an instruction tape: byte at `table[current_offset]` XORed with `current_offset >> 3` produces an opcode, and the opcode dispatches into one of four handlers that compute the next offset. The pseudo-random generation is a **space-saving trick**: instead of shipping a 2 KiB tape of opcodes verbatim in `.rodata`, the challenge ships a 4-byte seed plus a handful of patched bytes/words at critical positions. The generator seed + patches together encode the same tape more compactly and less obviously than a literal tape would.

### Why does the Borrowed Memory checksum help the solver instead of just the challenge author?

Because the checksum is per-step, deterministic, and computed from data your emulator also has (current offset, next offset, and the just-emitted output byte). If your emulator produces the wrong next offset at step N, the checksum comparison at step N fails and your solver stops there — with the exact step index printed. That converts the "which of my twelve opcode handlers is wrong" question from "read every disassembly listing again" to "look at handler for opcode X, the one running at step N". Two iterations of that loop is usually enough to converge.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and solver scripts at [Abdelkad3r/BDSecCTF-2026](https://github.com/Abdelkad3r/BDSecCTF-2026). All three solvers are pure Python (stdlib only) and reproducible against the committed `.bdsec` artifacts. Easy RE's solver runs in milliseconds, Night Shift's brute force runs in under a second, and Borrowed Memory's table rebuild + VM replay + flag decrypt runs in under a second on any laptop. No `gdb`, `pin`, `angr`, `z3`, or dynamic instrumentation required — every challenge is inverted statically from the ELF plus the compare targets.

## Closing notes

Three reverse challenges, one shared discipline: **the target of the final comparison is in the binary, and every stage between input and target is reversible; invert from the target, don't search the input space**. Easy RE's XOR + ROL + additive + permutation stack is a bijection at every layer, so a 20-line Python inverse reads the expected buffer + two keys straight from `.rodata` and prints the flag. Night Shift's five worker blocks are all small deterministic 32-bit mixers, and the FNV-1a hash target narrows the `5^8` search space to one unique schedule that a Python brute force finds instantly. Borrowed Memory's twelve-step offset VM is generated deterministically from a 4-byte seed plus patches, and its per-step checksum turns a scary-looking VM into a self-debugging one — the checksum tells you exactly which opcode handler you got wrong.

The other tracks at the same event: [BDSec CTF 2026 pwn writeup](/ctf-writeups/) (Phantom Device, Muktir Shongket) and [BDSec CTF 2026 web writeup](/ctf-writeups/) (Admin Portal, Ticketly) are worth pairing with this one for the full picture of the event. Adjacent reverse writeups on the site that share techniques with this track: [OmniCTF 2026 Quals reverse writeup](/ctf-writeups/omnictf-2026-quals-reverse-writeup/) has a signal-driven VM (Pusher) that uses the same "checksum stops you exactly at the wrong step" behaviour used by Borrowed Memory's opcode tape and a Rust binary (Kant) with the same reversible-pipeline-invert-from-target discipline used by Easy RE; [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) and [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/) both cover reverse challenges whose flags decrypt from a `.rodata` blob combined with intermediate state, mirroring Night Shift's and Borrowed Memory's flag-printer shape. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is BDSec CTF 2026?","acceptedAnswer": {"@type": "Answer","text": "BDSec CTF 2026 is a Bangladesh-hosted Capture-the-Flag competition with challenges across reverse engineering, pwn, and web categories. Flags use the BDSEC{...} namespace (some web challenges use lowercase bdsec{...}). This writeup covers the three reverse challenges I solved: Easy RE Challenge (80 pts), Night Shift (100 pts), and Borrowed Memory (460 pts). Per-challenge READMEs and solver scripts at github.com/Abdelkad3r/BDSecCTF-2026."}},
    {"@type": "Question","name": "How do you recognise decoy flags in a reverse-engineering challenge?","acceptedAnswer": {"@type": "Answer","text": "Two signals. First, format mismatch: if the platform requires BDSEC{...} and the string you recovered is CFLAG{...}, it's a decoy. Second, success-message strength: when the string table contains multiple congratulatory sentences of varying strength, the real path prints the strongest one. Count the length gates in main, match them to the message strengths, and invert the branch tied to the strongest message."}},
    {"@type": "Question","name": "Why is the unstripped Easy RE symbol table such a big time-save?","acceptedAnswer": {"@type": "Answer","text": "nm -an names the compare targets and key material directly. expected.0..3 are the four buffers the four input-length branches compare against; key_part_a and key_part_b are the two 8-byte keys used in the per-byte XOR. Without symbols you'd have to read main end-to-end, follow every lea into .rodata, and infer the offsets from context. Symbols cut that first pass from an hour to two minutes."}},
    {"@type": "Question","name": "How do you brute-force the Night Shift schedule?","acceptedAnswer": {"@type": "Answer","text": "Port each of the five worker update blocks from x86-64 assembly to Python (10-30 lines each, straight translation of the add/xor/rol/ror sequences). Loop for sched in product(range(5), repeat=8), run the ported simulator once per candidate, and check the four target state words plus the FNV-1a hash target. Under a second on any laptop; the real binary only runs once at the end to confirm the schedule works."}},
    {"@type": "Question","name": "Why is 0x811c9dc5 a hash fingerprint?","acceptedAnswer": {"@type": "Answer","text": "0x811c9dc5 is the FNV-1a 32-bit offset basis, the standard initial value for FNV-1a. Paired with 0x01000193 (the FNV prime) it uniquely identifies a Fowler-Noll-Vo hash mix pattern of the form h = (h ^ x) * FNV_PRIME. Whenever you see that constant loaded into a 32-bit accumulator immediately before a loop that XORs step data and multiplies by 0x01000193, model the accumulator as FNV-1a and skip the arithmetic-derivation step."}},
    {"@type": "Question","name": "What is the difference between the Borrowed Memory memory table and a bytecode interpreter?","acceptedAnswer": {"@type": "Answer","text": "Semantically none. The 0x800-byte table is an instruction tape: byte at table[current_offset] XORed with current_offset >> 3 produces an opcode, and the opcode dispatches into one of four handlers that compute the next offset. The pseudo-random generation is a space-saving trick: instead of shipping a 2 KiB tape of opcodes verbatim in .rodata, the challenge ships a 4-byte seed plus a handful of patched bytes/words at critical positions."}},
    {"@type": "Question","name": "Why does the Borrowed Memory checksum help the solver?","acceptedAnswer": {"@type": "Answer","text": "The checksum is per-step, deterministic, and computed from data your emulator also has (current offset, next offset, and the just-emitted output byte). If your emulator produces the wrong next offset at step N, the checksum comparison at step N fails and your solver stops with the exact step index printed. Two iterations of 'look at handler for opcode X running at step N' is usually enough to converge on the bug."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and solver scripts at github.com/Abdelkad3r/BDSecCTF-2026. All three solvers are pure Python (stdlib only) and reproducible against the committed .bdsec artifacts. Easy RE runs in milliseconds, Night Shift's brute force runs in under a second, and Borrowed Memory's table rebuild + VM replay + flag decrypt runs in under a second. No gdb, pin, angr, z3, or dynamic instrumentation required."}}
  ]
}
</script>
