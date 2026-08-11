---
title: "UIUCTF 2026 Reverse Engineering Writeup: vector-cache, GODMODE//999, Veil of Evernight & glyphs"
slug: "uiuctf-2026-reverse-engineering-writeup"
description: "Complete UIUCTF 2026 Reverse Engineering writeup covering all four RE challenges. vector-cache — x86-64 ELF whose token verifier lives inside a SIGILL handler dispatched by an intentional ud2 instruction; each of three modes runs 96 virtual instructions over a 7-opcode ARX+S-box VM, solved by GDB-tracing the parent and forked child (handle SIGILL nostop noprint pass), extracting the S-boxes, and running a compact CSP with MRV backtracking to recover a 24-byte token that also passes a downstream vector-cache/v3/seal SHA-256-IV mixer. GODMODE//999 — AArch64 firmware + 16 MiB RankedFS disk with 7-op journaled filesystem (transactions, snapshot, rollback, commit) and a bait transaction 404 after the type-7 checkpoint; a custom SHA-256 variant (hashlib silently returns the wrong root); a 13-op RAID//9 ARX replay VM with speculative snapshots inverted mod 2^32 by backtracking over commit/rollback choices; solved by emulating the real firmware routines under Unicorn to recover the 48-byte player code r0llb4ck_th3_un1v3rs3_4nd_qu3u3_f0r_LV999!!!n0w!. Veil of Evernight — 195,816 bytes reconstructed by a small embedded VM (opcodes 0xa7 0xd2 0x19 0x43 0x75 0x8e 0x2d 0x9a 0x62 0xcd) that XORs two 198,486-byte reflection buffers under 765 fragment records into a 466x341 PNG containing handwritten flag text with an ambiguous +3 tail that resolves to t}; deobfuscated ARX permutation with hidden 0xd6e8feb86659fd93 multiplication; solved by patching two ELF code-cave hooks into the untouched binary and brute-forcing 95x95 printable tails. glyphs — 23 MB PIE whose interpreter walks a 13,915 x 13,843 bitmap and builds a lambda-calculus term graph (constant / variable / lambda / application tags) that returns nope or good, solved by dumping the final GLYPHTRM graph, running an offline call-by-need Thunk-based evaluator, decoding Scott-encoded Tree = Empty | Node Glyph Tree Tree structures, identifying length=146 by tree topology, and inverting body pairs with 7 bit-coded probes plus batches of 57 candidates per run."
date: 2026-08-12T10:00:00Z
lastmod: 2026-08-12T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["UIUCTF 2026"]
tags:
  - "uiuctf"
  - "uiuctf 2026"
  - "uiuc ctf"
  - "ctf writeup"
  - "reverse engineering"
  - "reverse"
  - "vector-cache"
  - "godmode-999"
  - "veil of evernight"
  - "glyphs"
  - "sigill handler vm"
  - "ud2 dispatch"
  - "custom vm"
  - "constraint satisfaction"
  - "gdb tracing"
  - "arm64"
  - "aarch64 firmware"
  - "unicorn engine"
  - "custom sha-256"
  - "journaled filesystem"
  - "arx cipher"
  - "chacha20-poly1305"
  - "elf code cave"
  - "binary patching"
  - "mixed boolean arithmetic deobfuscation"
  - "lambda calculus"
  - "scott encoding"
  - "call by need"
  - "bitmap interpreter"
  - "lazy evaluation"
  - "ctf 2026"
keywords:
  - "uiuctf 2026 reverse engineering writeup"
  - "uiuctf 2026 reverse writeup"
  - "uiuctf 2026 re writeup"
  - "uiuctf vector-cache writeup"
  - "uiuctf godmode 999 writeup"
  - "uiuctf veil of evernight writeup"
  - "uiuctf glyphs writeup"
  - "sigill handler vm dispatch ctf"
  - "ud2 signal-driven verifier reverse engineering"
  - "gdb handle sigill nostop noprint pass"
  - "aarch64 firmware reversing unicorn"
  - "custom sha-256 compression function ctf"
  - "rankedfs journaled filesystem reversing"
  - "raid9 replay vm arx inversion snapshot commit rollback"
  - "elf code cave patching syscall hook"
  - "embedded vm png reassembly ctf"
  - "mixed boolean arithmetic ctf deobfuscation"
  - "lambda calculus term graph reverse engineering"
  - "scott encoding tree decoder ctf"
  - "call by need thunk evaluator lambda calculus"
  - "bitmap interpreter reverse engineering ctf"
  - "uiuctf 2026 solutions"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/uiuctf-2026-reverse-engineering-writeup.png"
  alt: "UIUCTF 2026 Reverse Engineering writeup cover — all four RE challenges solved. vector-cache is an x86-64 ELF whose token verifier lives inside a SIGILL signal handler dispatched by a deliberate ud2 instruction; each of three modes (parent, forked child, parent again after receiving a pipe from the child) runs 96 virtual instructions over a 7-opcode ARX plus S-box VM, solved by GDB tracing with handle SIGILL nostop noprint pass and constraint satisfaction with minimum-remaining-values backtracking against a downstream vector-cache slash v3 slash seal SHA-256-IV mixer. GODMODE//999 is an AArch64 firmware image plus 16 MiB RankedFS disk with a 7-op journaled filesystem including a bait transaction 404 after the type-7 checkpoint, a custom SHA-256 variant that hashlib silently gets wrong, and a 13-op RAID//9 ARX replay VM whose speculative snapshots are inverted modulo 2 to the 32 by backtracking commit/rollback choices, solved by emulating the real firmware routines under Unicorn to recover the 48-byte player code r0llb4ck_th3_un1v3rs3_4nd_qu3u3_f0r_LV999. Veil of Evernight rebuilds 195,816 bytes with an embedded VM that XORs two 198,486-byte reflection buffers under 765 fragment records into a 466 by 341 PNG containing handwritten flag text with an ambiguous plus-three tail that resolves to t close-brace, solved by patching two ELF code-cave hooks into the untouched binary and brute-forcing 95 by 95 printable pairs. glyphs is a 23 MB PIE whose interpreter walks a 13,915 by 13,843 bitmap and builds a lambda-calculus term graph with constant, variable, lambda, and application tags that returns nope or good, solved by dumping the final GLYPHTRM graph, running an offline call-by-need Thunk-based evaluator, decoding Scott-encoded Tree = Empty or Node Glyph Tree Tree structures, identifying length=146 by tree topology, and inverting body pairs with 7 bit-coded probes plus batches of 57 candidates per run"
---

**UIUCTF 2026**'s Reverse Engineering track is four Hard challenges built on one repeated architectural insight: **the verifier your disassembler shows you is not the verifier the program runs.** vector-cache dispatches its byte checks through a `SIGILL` handler installed on `SA_SIGINFO` — every `ud2` instruction is a virtual opcode. GODMODE//999 ships an AArch64 firmware whose journaled filesystem uses a *custom* SHA-256 with a modified compression function (using `hashlib.sha256` silently produces the wrong root and the wrong keys). Veil of Evernight buries its real check inside a small embedded VM that outputs 195,816 bytes which, sorted by rank, are a PNG of the flag. glyphs implements the entire check as a lambda-calculus term graph built by an interpreter walking a 13,915 × 13,843 bitmap. Every static-analysis pass shows the shell of the interpreter; the actual logic lives one indirection deeper.

Every intended solve reads the same way: **find the real machine, instrument the original binary in place of reimplementing it, and let the challenge do the heavy computation for you.** vector-cache is traced with two GDB scripts (one attached to the parent, one following the fork) and `handle SIGILL nostop noprint pass` to keep the VM alive. GODMODE//999 is loaded into Unicorn at physical address zero so the exact firmware routines — custom hash, keystream, replay VM, ChaCha20-Poly1305-like AEAD — run against synthetic RankedFS state without a byte of reimplementation. Veil of Evernight is patched in place: a zero-filled ELF segment is turned into a code cave, and two hooks emit VM register bytes via `syscall` so the untouched binary itself produces the 195,816-byte payload. glyphs is dumped with `dumpterm.gdb` into a portable `GLYPHTRM` graph format, then evaluated offline by a call-by-need Thunk-based lambda-calculus reducer that decodes the challenge's Scott-encoded trees and glyphs. In every case the reimplementation trap is explicit: custom crypto, custom VM, obfuscated permutations. Instrumentation wins.

Handouts, per-challenge READMEs, and dependency-conscious solvers live at [Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026). This **CyberSecurity Elite** UIUCTF 2026 Reverse Engineering writeup covers all four challenges end to end, with an emphasis on the *runtime instrumentation techniques* that turn each apparently unreadable artifact into a tractable dataset. Read alongside the paired [UIUCTF 2026 Cryptography writeup](/ctf-writeups/uiuctf-2026-crypto-writeup/), the [UIUCTF 2026 Miscellaneous writeup](/ctf-writeups/uiuctf-2026-misc-writeup/), and the [UIUCTF 2026 Nabi AI web writeup](/ctf-writeups/uiuctf-2026-web-nabi-ai-writeup/).

## All four Reverse Engineering challenges at a glance

| Challenge | Author | Runtime substrate | Instrumentation strategy | Flag |
|---|---|---|---|---|
| [vector-cache](#vector-cachesigill-dispatched-vm-inside-an-elf) | DJ Wang | x86-64 Linux ELF; `SIGILL` handler as VM dispatch | GDB scripts on parent + fork with `handle SIGILL pass`; extract 3 S-boxes + 288 equations; CSP-solve 24 bytes | `uiuctf{8655505e3fea99f9cb2f10aa25aa8d66a301473757aba051}` |
| [GODMODE//999](#godmode999aarch64-firmware-rankedfs-and-a-raid9-arx-vm) | Mewski | AArch64 firmware + 16 MiB RankedFS disk; custom SHA-256; 13-op replay VM with snapshot/commit/rollback | Unicorn-emulate the real firmware routines; replay journal through record 28 (skip bait); backtrack commit/rollback choices | `uiuctf{r0llb4ck_th3_un1v3rs3_4nd_qu3u3_4g41n}` |
| [Veil of Evernight](#veil-of-evernightreassembling-a-png-inside-a-static-elf) | Mewski | Static x86-64 ELF; 213-byte VM; 765 fragment records over two 198 KB reflection buffers | ELF code-cave patching; two `syscall` write hooks; brute-force 95×95 printable tails against the untouched checker | `uiuctf{wh3r3_i5_my_c4m3r4_4t}` |
| [glyphs](#glyphslambdacalculus-verifier-inside-a-bitmap-interpreter) | 32121 | 23 MB x86-64 PIE; interpreter walks a 13,915 × 13,843 bitmap; builds a lambda-calculus term graph | Dump term with GDB → `GLYPHTRM` file; offline call-by-need Thunk evaluator; Scott decoder; 7 bit-coded probes; 57-candidate batches | `uiuctf{oRig1naLLy_7Hi5_W4s_gonna_be_moR3_FoCU53d_0N_the_GLyPh_p4rt_BU7_1_f3LL_d0WN_7h3_L4mbD4_c4lc_R4bb17_H0Le_uH_H3R3_w3_4r3_noW_4iN7_7H47_gR3at}` |

Four different runtime substrates. Four different instrumentation choices — GDB, Unicorn, ELF patching, and GDB-again-plus-offline-lambda-calculus. One consistent lesson: **the fastest path to a Hard RE flag is teaching your tools to run the program's own real verifier under your microscope, not writing your own imitation of it.**

---

## vector-cache — SIGILL-dispatched VM inside an ELF

> *Flag:* `uiuctf{8655505e3fea99f9cb2f10aa25aa8d66a301473757aba051}`
>
> *Author's hint:* "The verifier looks ordinary until the illegal instructions start firing."

vector-cache is a small stripped x86-64 Linux ELF that reads one line from stdin, prints `accepted` or `rejected`, and exits. Static disassembly reveals a tight `main` that parses the input, then jumps into a routine that appears to crash. That "crash" is the entire verifier.

### Initial triage

```console
$ ./vector-cache
vector-cache recovery console
token> test
rejected

$ strings -a -t x vector-cache | grep -E 'accepted|rejected|vector-cache'
   7b40 vector-cache/v3/seal
   7ee0 accepted
   7ee9 rejected
   7f10 vector-cache recovery console
```

The strict input filter in `main` requires:

1. exactly 56 characters,
2. `uiuctf{...}` wrapper,
3. body is 48 lowercase hex characters,
4. decoded to 24 raw bytes.

So the real secret is 24 bytes; the flag is its hex encoding.

### The SIGILL handler is the VM

At startup, the program installs an `SA_SIGINFO` handler for signal 4 (`SIGILL`), rooted at ELF offset `0x2080`. The verifier setup routine at `0x2620` builds a context and reaches a `ud2` instruction. Linux transfers control into the handler, which interprets one virtual instruction and advances the saved instruction pointer so execution continues after `ud2`. That is why standard decompilation makes the verifier look fragmented — the *crash* is the dispatch primitive.

The handler's context layout:

| Offset | Purpose |
| --- | --- |
| `+0x00` | encoded VM instruction stream |
| `+0x08` | opcode translation table |
| `+0x10` | pointer to the decoded token-byte table |
| `+0x18` | start of the mode-specific 256-byte S-box |
| `+0x120` | rolling 64-bit VM state |
| `+0x128` | accumulated mismatch bits |
| `+0x140` | current step |
| `+0x148` | completion / failure status |

Each mode executes 96 virtual instructions. At `0x23ad`, the handler has just decoded opcode + three table indices + operation constants. At `0x23ea`, both the computed byte (`r8b`) and the expected byte (`dil`) are simultaneously live, and their XOR is ORed into the mismatch accumulator. **A mode passes only when every one of its 96 equations is satisfied**.

### Tracing the VM without killing it

Two runtime addresses matter under GDB with disabled randomization:

```text
0x5555555563ad  decoded operation, immediately before table loads
0x5555555563ea  computed and expected bytes are both available
```

The critical detail is passing `SIGILL` through to the inferior — stopping or swallowing it prevents the VM from running:

```gdb
set disable-randomization on
handle SIGILL nostop noprint pass
break *0x5555555563ad
break *0x5555555563ea
```

The verifier calls a fork. Modes 0 and 2 run in the parent; mode 1 runs in the forked child and returns its result through a pipe. Two GDB batch scripts capture both sides:

```console
$ gdb -q -batch -x trace-parent.gdb handout/vector-cache > parent.log
$ gdb -q -batch -x trace-child.gdb  handout/vector-cache > child.log
```

Each script also dumps its mode's 256-byte S-box.

### Seven byte operations

Naming the selected token-table bytes `d = table[idx8]`, `a = table[idx9]`, `c = table[idx11]`; the current S-box as `S`; the low bytes of `rbp`, `rbx`, `r14` as `P`, `B`, `Q`; rotate-left as `R(x, n)`; and constants `r = r13`, `k = k14`, `m = k15` (all arithmetic mod 256):

```text
op 0: R(P xor c, r) xor Q xor S[R(d, k) + B + a]
op 1: R(P + c,   r) +   Q +   S[R(B + d, k) xor a]
op 2: Q xor S[c + P] xor S[a + B - d]
op 3: R(S[a xor B], k) xor (m*d + P) xor R(c, r) xor Q
op 4: (c + P) * m xor Q xor S[a + B + S[d]]
op 5: S[R(d, k) + (B xor a)] + Q - R(c xor P, r)
op 6: S[a + B] xor P
```

The jump table at `0x3020` maps opcodes 0–6 to these formulas. `solve.py`'s `vm_operation()` implements them directly.

### Three-stage token recovery

The VM controls the permitted token-table range via `limit = 8 * (base + 1)`:

- **Mode 0** (`base = 0`, parent): equations touch table indices 0–7 → recovers `8655505e3fea99f9`.
- **Mode 1** (`base = 1`, forked child): equations touch indices 0–15; fix mode-0 output → recovers `cb2f10aa25aa8d66`.
- **Mode 2** (`base = 2`, parent after pipe): equations touch indices 0–23; fix modes 0 and 1 → recovers `a301473757aba051`.

Because each VM equation touches at most three token bytes, the search is tractable without symbolic execution. The compact CSP in `solve.py`:

1. Fix all bytes recovered by earlier modes.
2. Evaluate unary equations over all 256 possible values to shrink individual byte domains.
3. Group equations that reference the same pair of unknown bytes and enumerate their allowed pairs.
4. MRV backtracking with pairwise forward checking.
5. Validate the full candidate against all 96 equations before advancing.

```console
$ python3 solve.py
mode 0: 8655505e3fea99f9
mode 1: cb2f10aa25aa8d66
mode 2: a301473757aba051
flag: uiuctf{8655505e3fea99f9cb2f10aa25aa8d66a301473757aba051}
```

### The final seal check

Passing all three VM modes is *not* sufficient. Back in `main`, a 256-bit state initialised from the SHA-256 IV is updated by a nonlinear mixer at `0x1ce0` that consumes:

1. the 24 decoded token bytes,
2. the three 64-bit VM outputs,
3. the literal suffix `vector-cache/v3/seal`,
4. a final sequence of ARX rounds.

The resulting 256 bits are compared to constants embedded in the binary. This defeats attacks that satisfy an isolated VM stage without producing the correct token bytes.

```console
$ printf '%s\n' 'uiuctf{8655505e3fea99f9cb2f10aa25aa8d66a301473757aba051}' | ./handout/vector-cache
vector-cache recovery console
token> accepted
```

### Takeaway

**A signal handler is a control-flow construct in disguise.** vector-cache turns `ud2` into a VM dispatch instruction and hides an entire byte-level verifier inside `SA_SIGINFO`. Once the pattern is recognised — `SIGILL` handler registered, `ud2` executed, saved RIP updated by the handler — the "fragmented decompilation" story dissolves. The only tooling adaptation required is `handle SIGILL nostop noprint pass` to prevent GDB from short-circuiting the trap. The rest is disciplined CSP on a small VM.

---

## GODMODE//999 — AArch64 firmware, RankedFS, and a RAID//9 ARX VM

> *Flag:* `uiuctf{r0llb4ck_th3_un1v3rs3_4nd_qu3u3_4g41n}`
>
> *Author's hint:* "Restore the committed timeline and claim the achievement she left behind."

GODMODE//999 hands over an AArch64 firmware image (`godmode.rom`) and a 16 MiB virtual disk (`ranked.img`). The disk hosts a small journaled filesystem called RankedFS with transactions, snapshots, and commit points. The firmware decrypts committed files, validates a chain of replay records, and finally opens an authenticated-encryption "achievement" seal. Nothing in the chain uses standard crypto primitives, and every reimplementation shortcut is a trap.

### Triage

Recommended boot:

```console
$ qemu-system-aarch64 -M virt -cpu cortex-a72 -m 128M \
    -global virtio-mmio.force-legacy=false \
    -bios handout/godmode.rom \
    -drive file=handout/ranked.img,format=raw,if=none,id=ranked \
    -device virtio-blk-device,drive=ranked -nographic
```

`godmode.rom` is a raw AArch64 image at physical zero (not an ELF). Strings expose the flow:

```text
GODMODE//999 RANKED CONSOLE
PLAYER CODE (48 bytes):
RANK DOWN // malformed replay
RANK DOWN // timeline rejected
RANK DOWN // achievement seal invalid
ONE-BUTTON CLEAR // HIDDEN MMR 999
RANKEDFS-COMMITTED / RANKEDFS-ROOT / RANKEDFS-BLOCK
RAID9-MAP / RAID9-TARGET / RAID9-DROP
```

The disk begins with two `RNK9` superblocks:

| Offset | Generation | Journal block | Records | Checkpoint |
| --- | ---: | ---: | ---: | ---: |
| `0x0000` | 8 | 2 | 19 | 0 |
| `0x1000` | 9 | 2 | 31 | 28 |

Generation 9 is newer and has a valid checksum; its journal is the one to replay.

### The bait transaction

The journal has 31 records of `0x80` bytes each with 7 operation types (create, allocate, rename, delete, begin-transaction, roll-back, publish-checkpoint):

```text
records  5-10: transaction 101, rolled back
records 15-19: transaction 202, rolled back
records 24-27: transaction 303, rolled back
record      28: publish committed checkpoint
records 29-31: transaction 404, still speculative
```

Transaction 404 deletes the achievement and creates `/replays/one_button_clear.raid`. **It is deliberate bait.** There is no type-7 record after it, so its state is speculative and must be ignored. Replaying only through record 28 yields the intended committed directory:

```text
/profile/player.dat       id=1  block=64  length=0x0050
/replays/tutorial.raid    id=2  block=66  length=0x05e8
/replays/placement.raid   id=3  block=68  length=0x1498
/replays/promotion.raid   id=4  block=71  length=0x2390
/replays/godmode.raid     id=5  block=75  length=0x5a28
/cache/achievement.bin    id=6  block=82  length=0x006d
```

### Two custom checksums, neither is what it claims

The `crc` fields are not CRC32. The superblock uses an FNV-1a variant:

```python
h = 0x811C9DC5
for byte in data_with_crc_field_zeroed:
    h = ((h ^ byte) * 0x01000193) & 0xFFFFFFFF
    h ^= h >> 13
```

Files use a *different* primitive. The firmware routines at ROM offsets `0x2534`, `0x2590`, `0x2654`, and `0x26f0` initialise SHA-256's IV but implement a **custom compression function**. A one-line sanity test:

```text
firmware_hash("abc") =
508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982
```

That is not `sha256("abc")`. Using `hashlib.sha256` silently produces the wrong filesystem root, wrong keystreams, wrong everything downstream. The solver's foundational decision is to **stop reimplementing and start emulating**.

### File encryption

Each file is encrypted in 32-byte chunks with the keystream:

```text
firmware_hash(
    committed_root ||
    little_endian_u32(file_id) ||
    little_endian_u32(off / 32) ||
    "RANKEDFS-BLOCK"
)
```

XOR the disk bytes and recover `data/`. The profile confirms scenario and starting MMR:

```text
PLAYER=SILVER WOLF
MODE=FINAL LV.999
HIDDEN_MMR=998
POLICY=COMMITTED_TICKS_ONLY
```

### RAID//9 replay format

Each `.raid` file has a `0x100` header:

| Offset | Field |
| ---: | --- |
| `0x00` | Magic `RAID//9\0` |
| `0x0c` | Stage number |
| `0x10` | Node count |
| `0x12` | Edge count |
| `0x14` | Lane count |
| `0x16` | Player-code slice start |
| `0x18` | Player-code slice length |

The four stages check overlapping slices of one 48-byte player code:

| Replay | Stage | Slice | Nodes | Edges | Lanes |
| --- | ---: | --- | ---: | ---: | ---: |
| tutorial | 0 | `[0:16]` | 30 | 35 | 4 |
| placement | 1 | `[8:32]` | 109 | 188 | 6 |
| promotion | 2 | `[24:48]` | 180 | 383 | 6 |
| godmode | 3 | `[0:48]` | 464 | 991 | 12 |

Stages 0–2 together cover every byte; stage 3 validates the assembled 48 bytes and the final MMR state.

### Emulate the verifier under Unicorn

`emulate_verifier.py` maps the raw ROM at address zero, constructs the RankedFS state structure the firmware expects, and intercepts the file-read routine at `0x10a0` to return the recovered committed files. Running the *actual firmware* against synthetic state has three advantages:

1. custom hash and key derivations are exact by construction;
2. every candidate is judged by the real verifier;
3. final AEAD requires no guessed implementation.

At `0x18a8`, the harness records each replay node after its label is translated through the 16-byte `RAID9-MAP` table, revealing 13 VM operations (0–12).

### Reverse the ARX replay VM

Every arithmetic op is invertible mod `2^32`:

- rotations undone by opposite rotation;
- additions by subtraction;
- XOR is self-inverse;
- odd multiplications inverted via modular inverse;
- xorshift steps reconstructed iteratively.

Ops 8 / 9 / 11 handle snapshot / commit-or-rollback / commit-and-swap. `solve_code.py` runs a bad placeholder first to collect the full node trace and encrypted target, then walks the trace backward from the target, enumerating commit/rollback choices at every op 9. A rollback removes operations performed since the latest op 8. Candidates are retained only when they are printable, agree with already-recovered overlap bytes, and advance the genuine firmware verifier to the next stage.

Unique stage results:

```text
stage 0: decisions=(True,)                code[0:16]  = r0llb4ck_th3_un1        MMR=996
stage 1: decisions=(False, True)          code[8:32]  = _th3_un1v3rs3_4nd_qu3u3_ MMR=997
stage 2: decisions=(False, False, True)   code[24:48] = d_qu3u3_f0r_LV999!!!n0w! MMR=999
```

Merging overlaps:

```text
r0llb4ck_th3_un1v3rs3_4nd_qu3u3_f0r_LV999!!!n0w!
```

Simply "selecting" the `one_button_clear` bait fails because the verifier only counts *committed* ticks, and the correct rollback history is part of the answer.

### Achievement seal

`achievement.bin` starts with:

```text
magic           ACHV999\0
version         1
header size     0x40
timestamp       0x20260999
ciphertext size 45
```

After all four replay stages pass with MMR 999, the routine at `0x1e70` derives an AEAD key from the player code, the verifier output, and the achievement timestamp, then calls the firmware's ChaCha20-Poly1305-like routine at `0x2dd0`. Tag validates, 45-byte plaintext is the flag.

### Run

```console
$ .venv/bin/python solve_code.py
stage 0: decisions=(True,) slice=b'r0llb4ck_th3_un1' mmr=996
stage 1: decisions=(False, True) slice=b'_th3_un1v3rs3_4nd_qu3u3_' mmr=997
stage 2: decisions=(False, False, True) slice=b'd_qu3u3_f0r_LV999!!!n0w!' mmr=999
player code: b'r0llb4ck_th3_un1v3rs3_4nd_qu3u3_f0r_LV999!!!n0w!'
verifier result=1 mmr=999
achievement result=1
flag: uiuctf{r0llb4ck_th3_un1v3rs3_4nd_qu3u3_4g41n}
```

### Takeaway

**When the firmware ships its own SHA-256, do not ship your own.** GODMODE//999 punishes every reimplementation shortcut — the checksum fields are named `crc` but are FNV-1a variants, the hash starts with the SHA-256 IV but uses a modified compression function, the AEAD is "ChaCha20-Poly1305-like" but has custom key schedule. Emulating the original firmware under Unicorn skips every one of those subtle deviations at the cost of a couple hundred lines of harness. The intended narrative — "restore the committed timeline" — reads as a design brief: the whole solve is a sequence of "run the real thing under a microscope" moves, from the journal (replay through record 28) to the replay VM (backtrack over commit/rollback) to the AEAD (let the firmware do it).

---

## Veil of Evernight — reassembling a PNG inside a static ELF

> *Flag:* `uiuctf{wh3r3_i5_my_c4m3r4_4t}`
>
> *Author's hint:* "No single reflection shows the whole truth. Return every fragment to the place where it belongs."

Veil of Evernight is a statically linked stripped x86-64 ELF that reads a single input line and prints `The mirrored soul remembers.` or `Oblivion claims this memory.` It contains a small encrypted VM, two large "reflection" buffers, 765 shuffled fragment records, and an obfuscated verifier. The exploit lets the challenge's own VM decrypt the reflections and reassembles the emitted bytes into a **466×341 PNG** — which is the flag, handwritten.

### Triage

```console
$ file handout/evernight
handout/evernight: ELF 64-bit LSB executable, x86-64, statically linked, stripped

$ ./handout/evernight
Veil of Evernight
Memory to preserve: test
Oblivion claims this memory.
```

`main` at `0x28cc70` reads input, strips CR/LF, initialises a 32-byte memory state, transforms the input with that state, and compares four 64-bit output words. The comparator at `0x297c60` XORs the input length into the mismatch accumulator:

```asm
mov    rax, input_length
xor    rax, 0x1d
```

So the input is exactly 29 bytes. The four target words at `0x367c80`:

```text
a1b4e784a656a0e7
9ce17d05d484b23c
861cd6412636b540
fb52abc0f2c34a9a
```

Brute-forcing 29 preimage bytes against a 13-round ARX permutation is not tractable. The *initialisation* is the intended source of information.

### The fragment VM

The wrapper at `0x28cda0` calls `0x297cd0`, which runs a custom bytecode interpreter, then mixes eight encrypted textual fragments into the state. The VM's byte decoder is `0x2ab540`; the current bytecode position lives at context offset `0xb0`.

The initial decoded program is 213 bytes. Relevant instructions:

| Opcode | Operation |
| ---: | --- |
| `0xa7` | Load 64-bit immediate into VM register |
| `0xd2` | Load one field from a 16-byte fragment record |
| `0x19` | Copy register |
| `0x43` | XOR two registers |
| `0x75` | Load one byte from reflection 0 or reflection 1 |
| `0x8e` | Add two registers |
| `0x2d` | Multiply two registers |
| `0x9a` | Increment register |
| `0x62` | Compare + conditional PC change |
| `0xcd` | Halt |

The decoder is context-dependent — decoding every position with a zeroed context reveals the first pass, but execution unlocks a hidden loop. Runtime tracing shows the loop:

```text
load reflection_0[offset_a + index]
load reflection_1[offset_b + index]
xor the two bytes
derive a per-fragment mask
xor the mask into the byte
update the memory-state hash
advance to the next byte
```

The VM uses 16 general-purpose 64-bit registers stored from `[rbp-0xe8]`. After the second XOR, the reconstructed byte is in virtual register 10.

### Embedded data layout

The first read-only ELF segment contains all fragment material:

| VA | Size | Purpose |
| ---: | ---: | --- |
| `0x2004c0` | `765 × 16` | Fragment record table |
| `0x203490` | `198,486` | Reflection 0 |
| `0x233be6` | `198,477` | Reflection 1 |
| `0x264333` | encoded | VM bytecode |

Field layout:

```c
struct fragment_record {
    uint32_t encoded_offset_a;
    uint32_t encoded_offset_b;
    uint16_t encoded_length;
    uint16_t encoded_rank;
    uint32_t encoded_seed;
};
```

The values are not directly usable because the VM decodes them with a record-specific state. It is safer to capture the registers *after* the VM has decoded them: at bytecode PC `0x9c`, virtual registers 4–7 contain source offsets, length, and destination rank. Length is 256 for 764 records and 232 for one, summing to 195,816. Ranks are a complete permutation of `0..764`.

### Instrument the VM instead of reimplementing it

The ELF has a large zero-filled region at VA `0x27e362`. The solver marks the first load segment executable and uses that region as a **code cave**. The original handout is never modified — patches are applied only to temporary copies.

**Hook 1 — capture recovered bytes.** After the second XOR (bytecode position `0xba`), write the low byte of virtual register 10 to stdout:

```asm
cmp    qword [rbp-0x38], 0xba
jne    resume
mov    eax, 1                  ; SYS_write
mov    edi, 1                  ; stdout
lea    rsi, [rbp-0x98]         ; virtual register 10
mov    edx, 1
syscall
resume:
jmp    0x2a8954
```

Produces exactly 195,816 bytes in fragment-table order.

**Hook 2 — capture decoded metadata.** After the load-immediate handler (bytecode position `0x9c`), write registers 4–7 (32 bytes) to stdout:

```asm
cmp    qword [rbp-0x38], 0x9c
jne    resume
mov    eax, 1
mov    edi, 1
lea    rsi, [rbp-0xc8]
mov    edx, 32
syscall
resume:
jmp    0x2a895a
```

Emits `765 × 32 = 24,480` metadata bytes.

### Reassemble the memory image

Split the recovered stream by each record's decoded length and sort pieces by rank:

```python
fragments = []
offset = 0

for source_a, source_b, length, rank in records:
    fragment = recovered[offset:offset + length]
    fragments.append((rank, fragment))
    offset += length

image = b"".join(fragment for rank, fragment in sorted(fragments))
```

The result begins with a PNG signature, ends with `IEND`, and is:

```console
$ file data/evernight-memory.png
data/evernight-memory.png: PNG image data, 466 x 341, 8-bit/color RGB
```

The image contains March 7th/Evernight and the handwritten text:

```text
uiuctf{wh3r3_
i5_my_c4m3
r4_4+3
```

Literal concatenation gives 29 chars but no closing brace; adding a brace gives 30 chars, which fails the strict length check. The last two handwritten characters must be resolved by the binary.

### Deobfuscate the verifier

The input transform uses a 512-bit state, a four-word key, and 13 permutation rounds per input byte. Two helpers are inflated with mixed-boolean arithmetic (MBA).

Helper at `0x2bbad0` simplifies to:

```c
x ^= x >> 29;
x *= 0x9e6c63d0676a9a99;
x ^= x >> 32;
x *= 0x9e6d62d06f6a9a9b;
x ^= x >> 28;
```

The large permutation at `0x2c1190` looks worse because a **single constant multiplication is hidden behind thousands of reversible operations**. Tracing `rax` at `0x2c3e7d`, immediately before that multiplication, yields:

```text
0xd6e8feb86659fd93
```

Cancelling the arithmetic noise gives a compact ARX round in `fast_permute.c`. Validated against the original by comparing all four output words for identical state / key / seed / input.

Memory state after the fragment VM and the eight textual fragments:

```text
5c58f5c8064a7119
bb999f382bd98b97
b68ab5b85a6a2965
4bc992da3b55da0f
```

The solver caches this state, installs the optimised permutation in the code cave, and converts `main` into a **streaming checker** so candidates avoid rerunning the expensive fragment VM.

### Resolve the last two characters

The first 27 image characters are unambiguous:

```text
uiuctf{wh3r3_i5_my_c4m3r4_4
```

Trying every printable ASCII pair against the streaming checker (`95 × 95 = 9025` attempts) yields exactly one accept:

```text
t}
```

Full input:

```text
uiuctf{wh3r3_i5_my_c4m3r4_4t}
```

The visible `+3` in the image is the final misdirection; the verifier resolves it as `t}`.

### Run

```console
$ python3 solve.py
memory: data/evernight-memory.png (195816 bytes)
memory sha256: 90a48b7c4c7f3e122a8f8a38ee2a621adf4e516b3fdce0d6007bf925049f42df
flag: uiuctf{wh3r3_i5_my_c4m3r4_4t}
verification: The mirrored soul remembers.
```

### Takeaway

**A zero-filled ELF segment is a code cave.** Two three-line `syscall` hooks turn Veil of Evernight from a 195,816-byte VM-decode-and-reassemble problem into a single `write(1, ...)` sink. The MBA-obfuscated permutation is real; the solver finds the one hidden multiplication constant by tracing rax at the pre-multiplication site rather than by symbolic simplification of the enclosing noise. The final resolution — that the image says `+3` but the verifier means `t}` — is a rare CTF pun where the *artwork* is a lie and the *binary* is the source of truth. Trust the binary.

---

## glyphs — lambda-calculus verifier inside a bitmap interpreter

> *Flag:* `uiuctf{oRig1naLLy_7Hi5_W4s_gonna_be_moR3_FoCU53d_0N_the_GLyPh_p4rt_BU7_1_f3LL_d0WN_7h3_L4mbD4_c4lc_R4bb17_H0Le_uH_H3R3_w3_4r3_noW_4iN7_7H47_gR3at}`
>
> *Author's hint:* "Strange glyphs inscribed on the wall rearrange themselves chaotically. Will they respond if you call out to them?"

glyphs ships a 23 MB stripped x86-64 PIE whose small native interpreter walks a 13,915 × 13,843 bitmap; shapes in that bitmap are instructions. The program eventually builds and evaluates a graph of lambda-calculus terms, so ordinary decompilation shows the interpreter rather than the real verifier. The fix is to dump the final term graph, evaluate it offline, decode its Scott-encoded data, and invert the input-to-glyph mapping in batches.

### Triage

```console
$ file handout/glyphs
handout/glyphs: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

$ ./handout/glyphs test
nope
```

Small `.text`, enormous initialised data, only libc imports (`malloc`, `free`, `printf`, `puts`) — no crypto, no obvious verifier strings. The bulk of the file is a packed bitmap sized `0x365b × 0x3613 = 13,915 × 13,843`.

Global VM state:

| Offset | Purpose |
| ---: | --- |
| `0x847acc8` | current X |
| `0x847acd0` | current Y |
| `0x847acd8` | selected register |
| `0x17017d0` | direction |
| `0x17017f0` | eleven 24-byte VM registers |
| `0x1701970` | VM memory array |

The native function at offset `0x1290` recognises geometric patterns around the current bitmap position and dispatches arithmetic, copies, memory access, branches, and heap operations.

### The heap holds a lambda-calculus term graph

Near native offset `0x419e`, VM registers hold 24-byte tagged records. Four tags dominate the reachable graph:

| Tag | Meaning | Payload |
| ---: | --- | --- |
| `0` | raw constant | 64-bit value |
| `2` | variable | binder id |
| `3` | lambda | binder id + body pointer |
| `4` | application | function + argument pointers |

Application and lambda records point to separate 16-byte payloads. The last reduction is around `0x436a`; the result is written to VM memory and printed via `puts` at `0x79fb`. Tracing a rejected input reveals both output constants:

```text
0x65706f6e -> "nope"
0x646f6f67 -> "good"
```

The problem stops being "reverse a huge bitmap" and becomes "recover and interpret the lambda term the bitmap builds."

### Dump the final term graph

Under GDB with ASLR disabled, the PIE loads at `0x555555554000`. Immediately before the final reducer call, the root term is in `rdi`. The instruction is at base + `0x4375`; the same native site is shared, so the useful call is selected by the bitmap coordinate `(11256, 2700)`.

`dumpterm.gdb` follows every reachable record and emits a portable format:

```text
header:  <8sQQ>   magic="GLYPHTRM", root_index, node_count
record:  <B7xQQ>  tag, first, second
```

Pointers are replaced with node indexes. For tag 4 (application), `first`/`second` are function/argument. For tag 3 (lambda), they are binder/body.

```console
$ TERM_OUT=/tmp/term.bin TERM_QUIET=1 \
    gdb -q -batch -x dumpterm.gdb --args ./handout/glyphs \
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

For a 40-byte `A` input, about 67,000 nodes are reachable. Unrolling the root's application spine:

```text
Y equality embedded_target encoded_input "nope" "good"
```

Sizes:

| Component | Nodes |
| --- | ---: |
| fixed-point combinator `Y` | 14 |
| generic equality routine | 396 |
| embedded target | 61,307 |
| encoded 40-byte candidate | 5,696 |

The huge target and compressed candidate are values passed to a generic recursive equality routine.

### Offline call-by-need evaluator

A naive normaliser expands `Y` forever. Only weak head normal form is required, and pure lambda calculus permits call-by-need sharing. `lambda_reduce.py` uses a mutable `Thunk`; the first variable lookup evaluates it and caches the closure:

```python
if value.result is None:
    value.result = self.whnf(value.value)
value = value.result
```

Beta reduction extends the function closure's lexical environment:

```python
environment = Environment(
    function.binder,
    Thunk(Closure(argument, caller_environment)),
    function.environment,
)
value = Closure(function.body, environment)
```

Rejected roots evaluate in milliseconds; more importantly, marker values can be applied to individual encoded objects to expose their shape.

### Decode Scott-encoded structures

Applying a unique marker to the target or candidate exposes products encoded as:

```text
lambda handler. handler field0 field1 ... fieldN
```

Selectors are the Church form:

```text
lambda x0. lambda x1. ... lambda xN. xi
```

The two recursive types:

```text
Tree  = Product4(Present2, Glyph, Tree, Tree)
Glyph = Product3(Present2, Trit3, Glyph)
```

In conventional notation:

```text
Tree  = Empty | Node Glyph Tree Tree
Glyph = [] | Trit : Glyph
Trit  = 0 | 1 | 2
```

The presence selector must be checked *before* touching remaining fields — the empty-constructor fields are deliberately lazy and can contain fixed-point computations that never terminate under eager decoding:

```python
def tree(self, value):
    present, glyph, left, right = self.product(value, 4)
    if self.selector(present, 2) == 0:
        return None
    return self.glyph(glyph), self.tree(left), self.tree(right)
```

Decoding the embedded target:

```text
tree nodes:       141
unique glyphs:    53
glyph lengths:    24 through 27 trits
```

### Recover the required input length

Changing characters at a fixed length changes glyph payloads but not tree topology. Length changes topology *chaotically* — the author's hint made literal. The binary accepts at most 200 bytes, so every length can be tested:

1. Run under `dumpterm.gdb` with `"A" * length`.
2. Decode argument 2 as a tree.
3. Discard glyph payloads; keep `(left_shape, right_shape)`.
4. Compare with the target shape.

Exactly one length matches:

```text
length = 146
```

The matching baseline is `data/baseline-146A.term`: a 141-node tree with 140 copies of the ordinary `A` glyph and one sentinel.

### Attribute tree slots with 7 bit-coded probes

At length 146, the meaningful body starts at byte 7. Bytes 7–144 are 69 adjacent two-byte units:

```text
pair j = input[7 + 2*j : 9 + 2*j],  0 <= j < 69
```

A single changed pair may appear in multiple tree nodes. Instead of 69 one-at-a-time probes, **seven bit-coded probes** identify all pairs simultaneously. For probe bit `b`, the first byte of pair `j` is flipped `A → B` when:

```text
(j >> b) & 1 == 1
```

An eighth probe changes every pair, distinguishing active slots from slots that never depend on a body pair. For each changed tree slot, its seven-bit change pattern is exactly the source pair index.

`data/slot-map.json` shows:

- 56 body pairs affect at least one tree slot;
- 13 body pairs are completely unchecked;
- slot 134 checks wrapper bytes 3 and 4 (recovering `ct`);
- slot 135 checks byte 145 (the closing `}`).

Unchecked body-pair indexes:

```text
7, 25, 26, 32, 34, 40, 47, 48, 52, 54, 57, 62, 67
```

### Invert glyphs in batches of 57

The ternary glyph for a two-byte unit is position-independent — a candidate pair placed at any active body position yields the same glyph. So 57 pair candidates are testable per run:

1. Place one candidate at bytes 3, 4 and read slot 134.
2. Place 56 more in the active body positions.
3. Dump and decode the candidate tree once.
4. Read one representative slot per pair.
5. Store `glyph -> pair` in a dictionary.

Enumerating pairs over ASCII letters, digits, `_`, `-` resolves every glyph the target requires. The compact lookup lands in `data/pair-map.json`. Reading representative target slots reconstructs this already-accepted candidate (`AA` marks unchecked pairs):

```text
uiuctf{oRig1naLLy_7HiAAW4s_gonna_be_moR3_FoCU53d_0N_the_GAAAA_p4rt_BU7_AAf3AA_d0WN_7h3_AAmbD4_c4lc_R4AAAA_H0Le_AA_HAA3_w3AAr3_noW_4AA7_7H47_gAAat}
```

The missing text is unambiguous once the checked characters are read as a sentence:

```text
oRig1naLLy_7Hi5_W4s_gonna_be_moR3_FoCU53d_0N_the_GLyPh_p4rt_
BU7_1_f3LL_d0WN_7h3_L4mbD4_c4lc_R4bb17_H0Le_uH_H3R3_w3_4r3_
noW_4iN7_7H47_gR3at
```

Because those 13 pairs are unchecked, the `AA`-filled version also passes. The text above restores the author's intended flag.

### Validate

```console
$ ./handout/glyphs \
  'uiuctf{oRig1naLLy_7Hi5_W4s_gonna_be_moR3_FoCU53d_0N_the_GLyPh_p4rt_BU7_1_f3LL_d0WN_7h3_L4mbD4_c4lc_R4bb17_H0Le_uH_H3R3_w3_4r3_noW_4iN7_7H47_gR3at}'
good
```

### Takeaway

**When the interpreter is a decoy, dump the semantics.** Decompiling glyphs' bitmap walker is a dead end — it *is* the interpreter, but the checker's meaning lives in the term graph the interpreter constructs. The right move is to extract the term graph itself (one GDB script), evaluate it with a fifty-line call-by-need lambda reducer, and decode the Scott-encoded structures the challenge chose to model the check. The seven-bit probe attribution is a genuinely elegant trick that turns 69 sequential experiments into 8 parallel ones. The unchecked-pairs observation — that 13 body positions never affect the tree — means the challenge's authoritative flag is not unique; the intended English-sentence variant is a courtesy from the author.

---

## Cross-cutting lessons from the UIUCTF 2026 Reverse Engineering set

Four Hard challenges, four different runtime substrates, one repeated pattern — **the verifier your disassembler shows you is not the verifier the program runs**:

- **vector-cache**: the verifier is a `SIGILL` handler dispatched by `ud2`; ordinary control flow reads as intentional garbage.
- **GODMODE//999**: the verifier is a set of firmware routines using a custom SHA-256 variant that `hashlib` silently gets wrong.
- **Veil of Evernight**: the verifier's *input* is the output of a 213-byte VM that decrypts 195,816 bytes into a PNG containing handwritten flag text.
- **glyphs**: the verifier is a lambda-calculus term graph built by a bitmap-walking interpreter; the interpreter is legible but hollow.

Portable techniques from the set:

- **Instrument the original binary in place of reimplementing it.** Every solve in this set uses the challenge's own primitives via GDB scripts, Unicorn emulation, or ELF code-cave patches. Reimplementations of custom crypto (GODMODE's custom SHA-256) or obfuscated permutations (Veil's MBA-wrapped ARX) are punished silently.
- **Pass signals through, do not swallow them.** `handle SIGILL nostop noprint pass` is the entire difference between a debuggable vector-cache and a stubborn crash. Any time a challenge behaves differently under GDB than in the wild, check whether a signal handler is doing dispatch.
- **Code caves are attack surface.** Zero-filled ELF regions marked writable can be turned executable, and a two-instruction `syscall` hook is enough to exfiltrate any register state the challenge computes for you. That is exactly how Veil of Evernight's 195,816-byte reconstructed PNG gets to stdout.
- **Emulate the boundary you cannot cross.** GODMODE//999 hides four distinct primitives behind a single firmware image; Unicorn lets you *use* all four without reimplementing any of them. The harness cost — mapping the ROM, faking the RankedFS state, intercepting `file_read` — is small compared to the cost of correctly cloning a modified SHA-256, a bespoke replay VM, and a ChaCha20-like AEAD.
- **When the artifact is a data structure, dump it in a portable format.** glyphs' `GLYPHTRM` header (`magic`, `root_index`, `node_count` + `tag/first/second` records) turns "reverse a bitmap interpreter" into "evaluate a lambda-calculus term graph in Python." The one-time GDB export decouples the runtime from the semantics.
- **Parallelise your probes.** glyphs' seven bit-coded probes plus one all-changed probe attribute 69 body positions to their tree slots in *eight runs* instead of 69. Any time an unknown-to-output mapping is linear (or near-linear) in the changes, a bit-coded probe schedule collapses the query count.
- **The image is not the answer.** Veil of Evernight's PNG says `+3` and means `t}`. The check runs against the *bytes*, not the pixels. Always cross-check any "we recovered a picture" moment against the actual verifier — the artwork may be the last piece of misdirection.

## Reproduce it yourself

Each challenge ships a standalone solver in the [UIUCTF 2026 repository](https://github.com/Abdelkad3r/UIUCTF-2026) under its own directory, with the original handout, any offline analysis tooling, and (where cross-platform reproducibility matters) an emulator harness or GDB script:

- [`vector-cache/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/vector-cache) — `trace-parent.gdb`, `trace-child.gdb`, `data/vm-traces.json`, and a pure-Python CSP solver.
- [`godmode-999/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/godmode-999) — Unicorn harness (`emulate_verifier.py`), decrypted `data/` snapshot, and `solve_code.py` that walks the replay VM in reverse.
- [`veil-of-evernight/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/veil-of-evernight) — `fast_permute.c` (deobfuscated ARX round), `solve.py` (ELF code-cave patcher + streaming checker), and the reassembled `data/evernight-memory.png`.
- [`glyphs/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/glyphs) — `dumpterm.gdb` (GLYPHTRM extractor), `lambda_reduce.py` (offline call-by-need evaluator), `decode_glyphs.py` (Scott decoder), `term_diff.py`, and `solve.py` (final flag reconstruction).

Browse the full [CTF writeups](/ctf-writeups/) archive for more reverse engineering and firmware-emulation walkthroughs, or read the companion [UIUCTF 2026 Cryptography writeup](/ctf-writeups/uiuctf-2026-crypto-writeup/) (plactic monoid + CKKS + Elder Futhark), [UIUCTF 2026 Miscellaneous writeup](/ctf-writeups/uiuctf-2026-misc-writeup/) (three jail escapes), and [UIUCTF 2026 Nabi AI web writeup](/ctf-writeups/uiuctf-2026-web-nabi-ai-writeup/) (Next.js Server Action SSRF + OpenBao ACL wildcard).

---

*This writeup is part of the CyberSecurity Elite [UIUCTF 2026](/series/uiuctf-2026/) series. Handouts, per-challenge READMEs, and dependency-conscious solvers for all four Reverse Engineering challenges are published at [github.com/Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026).*
