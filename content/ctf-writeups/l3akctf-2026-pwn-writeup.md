---
title: "L3akCTF 2026 Pwn Writeup: All 7 Binary Exploitation Challenges"
slug: "l3akctf-2026-pwn-writeup"
description: "Full L3akCTF 2026 pwn writeup covering all seven binary exploitation challenges: a scanf %s NUL-byte overflow that turns a bignum printer into a stack leak for ret2win (Rudimentary Calculator); a custom stack-VM whose DUP instruction corrupts its own stack pointer into a native-frame read/write primitive with leak-free ASLR-relative ROP (LattiaVM 1 & 2); an RWX-module CTF shell defeated with /proc/self/exe recovery, behavioral oracles, a self-disable bypass, an opcode-widening byte→dword trick, and an atomic stdout->write hook (Bosh); a Piet interpreter whose up/down opcodes alias stack_depth into an exact set_depth primitive and whose roll ignores its depth bound (Piet 1 & 2); and a seccomp user-notification supervisor broken by two unsigned-arithmetic offset+count wraparounds into arbitrary parent read/write, GOT overwrite, and system(\"/readflag\")."
date: 2026-08-06T23:00:00Z
lastmod: 2026-08-06T23:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["L3akCTF 2026"]
tags:
  - "l3akctf"
  - "l3akctf 2026"
  - "ctf writeup"
  - "pwn"
  - "binary exploitation"
  - "stack overflow"
  - "ret2win"
  - "stack canary bypass"
  - "custom vm exploitation"
  - "stack pivot"
  - "rop chain"
  - "aslr bypass"
  - "leakless exploitation"
  - "libc offset arithmetic"
  - "rwx memory"
  - "got overwrite"
  - "seccomp user notification"
  - "process_vm_readv"
  - "integer overflow"
  - "piet"
  - "musl"
  - "glibc 2.42"
  - "ctf 2026"
keywords:
  - "l3akctf 2026 pwn writeup"
  - "l3akctf 2026 binary exploitation writeup"
  - "rudimentary calculator ctf writeup"
  - "lattiavm ctf writeup"
  - "bosh ctf writeup"
  - "piet ctf pwn writeup"
  - "supervisor seccomp ctf writeup"
  - "scanf %s nul byte overflow exploit"
  - "custom vm stack pointer corruption ctf"
  - "leakless rop aslr relative offset ctf"
  - "stack depth alias set_depth primitive"
  - "roll out of bounds piet exploit"
  - "seccomp user notification offset count wrap exploit"
  - "strlen got overwrite system readflag"
  - "binary exploitation ctf 2026"
toc: true
cover:
  image: "/images/articles/l3akctf-2026-pwn-writeup.png"
  alt: "L3akCTF 2026 binary exploitation writeup covering seven pwn challenges — Rudimentary Calculator turns a scanf %s NUL-byte stack overflow into a bignum-printer stack leak that defeats PIE and the canary before a ret2win, LattiaVM 1 and 2 abuse a custom stack VM whose DUP instruction overwrites its own stack pointer to become a native-frame read/write that builds a leak-free ASLR-relative system(pr f*) ROP chain, Bosh recovers a hidden musl binary through /proc/self/exe and uses behavioral oracles plus an opcode-widening byte-to-dword patch to atomically hook stdout->write into a chmod-and-forward stub, Piet 1 aliases stack_depth via up and down opcodes into an exact set_depth primitive while Piet 2 abuses an unbounded roll to overwrite saved rbp and pivot into a forged frame, and Supervisor breaks a seccomp user-notification sandbox with two offset-plus-count unsigned wraparounds into arbitrary parent read and write, a strlen GOT overwrite, and system(/readflag)"
---

L3akCTF 2026's binary exploitation track was one of the strongest of the season: seven challenges that walked from a beginner-friendly stack overflow all the way to a zero-solve Piet interpreter and a seccomp-user-notification sandbox escape. What ties the set together is a single recurring theme — **metadata you are allowed to touch is more dangerous than the memory you are trying to reach.** Almost every challenge here is won not by smashing a return address directly, but by corrupting a length field, a stack-pointer field, a self-disable byte, an opcode byte, or a saved frame pointer, and letting the program's own trusted code do the dangerous write for you.

This **CyberSecurity Elite** L3akCTF 2026 pwn writeup covers all seven challenges end to end, focusing on **methodology** — the reasoning behind each primitive — rather than just dropping the final payloads. Challenge sources, per-challenge READMEs, recovered binaries, and standalone solver scripts are available at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026).

## All seven challenges at a glance

| Challenge | Points | Solves | Core bug | Primitive |
|---|---:|---:|---|---|
| [Rudimentary Calculator](#rudimentary-calculator--nul-bytes-turn-a-bignum-printer-into-a-stack-leak) | 86 | 91 | `scanf("%s")` overflow past a length field | Bignum printer → stack leak → ret2win |
| [LattiaVM](#lattiavm--a-dup-instruction-that-overwrites-its-own-stack-pointer) | 181 | 26 | Unbounded `push` + `DUP` aliasing the SP | VM value → native-frame read/write → leakless ROP |
| [LattiaVM 2](#lattiavm-2--same-bug-bigger-budget) | 190 | 24 | Same VM bug; heap-backed program | Identical ROP within a larger input limit |
| [Bosh](#bosh-the-536f4u1t-oracle--a-cosmic-ray-in-rwx-memory) | 220 | 19 | One-shot RWX module + writable musl `FILE` | Byte oracle → dword store → atomic `stdout->write` hook |
| [Piet](#piet--aliasing-stack_depth-into-an-exact-set_depth-primitive) | 253 | 15 | `up`/`down` opcodes write `stack_depth` | `set_depth(N)` → leakless libc ROP |
| [Piet 2](#piet-2--when-roll-forgets-its-own-depth-bound) | 500 | 0 (at release) | `roll` ignores `d <= stack_depth` | Saved-`rbp` overwrite → forged-frame pivot |
| [Supervisor](#supervisor--breaking-a-seccomp-user-notification-sandbox) | 405 | 5 | `offset + count` unsigned wrap in emulated I/O | Arbitrary parent R/W → GOT overwrite → `system("/readflag")` |

If you only read one section, make it Piet 2 (a zero-solve, saved-`rbp` pivot built entirely from uninitialized stack values) or Supervisor (a seccomp-notifier compromise that is more valuable than escaping the sandboxed child directly).

---

## Rudimentary Calculator — NUL bytes turn a bignum printer into a stack leak

> *Flag:* `L3AK{s3Arch_f0r_Sm0otH}`

The friendliest challenge in the set, and a clean lesson in reading the *whole* stack frame rather than the one obvious bug.

### The layout

The calculator's state object lives in the `run()` frame:

```c
struct {
    char buf[0x1000];
    int product_bignum_len;
    uint32_t product_bignum[0x60];
} s;

scanf("%s", s.buf);
```

The unbounded `scanf("%s")` is the obvious overflow, but a plain return-address smash dies on the stack canary. The *useful* bug is that `product_bignum_len` sits immediately after `buf`, and both `multiply_digit()` and `to_base_10()` trust that length completely even though the array only has `0x60` limbs.

### Why embedded NUL bytes matter

The trick that makes the exploit clean: `scanf("%s")` does **not** stop at `\x00`. Over a socket, NUL is just another non-whitespace byte, so a single payload can carry two meanings at once. `1\x00AAAA...<new length>` overflows `buf` and rewrites the length field for `scanf`, while every C string function — including the expression parser — sees only `1`.

### Two stages

1. **Leak.** Overwrite `product_bignum_len` with `103`. The parser performs one harmless multiplication by `1`, then `to_base_10()` prints 103 little-endian base-2³² limbs as one giant decimal integer — reaching past the 96 real limbs into the canary, saved `rbp`, and saved return address. Reconstructing them is arithmetic:

   ```python
   words = [(leaked_integer >> (32 * i)) & 0xFFFFFFFF for i in range(103)]
   canary       = words[97]  + (words[98]  << 32)
   saved_return = words[101] + (words[102] << 32)
   pie_base     = saved_return - 0x1a9b
   win          = pie_base + 0x1289
   ```

2. **Control.** A second payload begins with `quit\x00`: `strcmp(s.buf, "quit")` cleanly breaks the loop while the overflow rewrites the saved return address to `win()`. The leaked canary is restored in place, so the stack check passes and `run()` returns into the flag-printing function.

The [full solver](https://github.com/Abdelkad3r/L3akCTF-2026/tree/main/pwn/rudimentary-calculator) needs no pwntools. **Takeaway:** an unbounded read is bad, but turning an output routine into a *disclosure primitive* by corrupting the metadata it trusts is what actually defeats PIE and the canary.

---

## LattiaVM — a `DUP` instruction that overwrites its own stack pointer

> *Flag:* `L3AK{h3ll000_c4ll1ng_fr0m_50-47714-5-1000_4ny0n3_7h3r3}`

A 14-instruction stack VM (`PUSH/POP/ADD/.../DUP/SWAP/HALT`) whose state object lives on `main()`'s native stack:

```c
typedef struct { int32_t stack[256]; int32_t sp; } vm_t;
```

`pop()` checks underflow; `push()` does **not** check overflow. That single omission, combined with `DUP`, is the whole challenge.

### The DUP stack-pointer corruption

`DUP` is `value = pop(); push(value); push(value);`. Run it at `sp == 256`:

1. `pop()` sets `sp = 255`, returns `x = stack[255]`.
2. First `push(x)` writes `stack[255]`, `sp` back to `256`.
3. Second `push(x)` evaluates `stack[256]` — which **aliases the `sp` field itself** — so `sp` becomes `x`.
4. The helper then increments it: `sp = x + 1`.

One instruction converts a controlled VM value into an arbitrary logical index into `main()`'s frame. Mapping four-byte VM entries onto the frame, index 256 is the SP, 258/259 the canary, 262/263 the saved return address, and 264+ the caller stack usable for a ROP chain. `SWAP imm8` then becomes a constrained native-stack read/write.

### Leak-free, reconnect-free ROP

The environment is unforgiving: a network `wrapper.c` limits input to **128 decoded bytes**, redirects the child's stdin to `/dev/null` (so an interactive shell is useless), and the VM caps execution at **512 instructions**. Full RELRO, NX, PIE, and glibc 2.42 rule out the easy routes.

The elegant part is that **nothing is ever printed to leak ASLR.** The saved return address (`libc + 0x29f75`) is already sitting at index 262. Since every ROP target lives in the same libc mapping, only the *low* dword differs, and the VM computes each target's low dword by adding a fixed offset using only 8-bit immediates factored into small products:

```text
0x44386 - 0x29f75 = 0x1a411 = 53 * (8 * 253 + 5)   ; pop rax ; ret
0x54790 - 0x44386 = 0x1040a = 210 * (62 + 255)      ; system
0x14eae3 - 0x54790 = 0xfa353                         ; mov rdi, rsp ; call rax
```

A seven-`DUP` loop builds depth to 256 within the instruction budget, the `DUP` bug sets `sp = 270`, and `SWAP`/`DUP` sequences splice three ASLR-correct 64-bit pointers plus the command string `"pr f*"` into the caller frame. Because stdin is dead, the payload runs `system("pr f*")` — `pr` prints `flag.txt` (glob-expanded) non-interactively. Final chain: `pop rax; ret` → `rax = system` → `mov rdi, rsp; call rax`. Total: 128 bytes, 489 VM instructions — right at both limits.

**Fix:** an upper-bound check in `push()`, and never store VM state adjacent to native return metadata.

## LattiaVM 2 — same bug, bigger budget

> *Flag:* `L3AK{ty_f0r_50-47714-5-1000_2_m4ll0ctr1c_str1ng1f4l00}`

The "update" advertised *longer programs*: `MAX_HEX` grows from 257 to 513 (256 decoded bytes), and the decoded program now lives in a `malloc()` allocation instead of a global. Neither change matters — **the VM state is still a stack local**, so the exact same `DUP` corruption and the identical 128-byte / 489-instruction chain from LattiaVM 1 solve it, using only half the new input allowance. The supplied libc and loader are byte-identical, so every offset carries over.

One deployment nuance: v2 doesn't explicitly initialize `sp`, but on the challenge image the slot begins at zero and an immediate `POP` reports underflow, so the exploit starts consistently from depth zero both locally and remotely. The v2 lesson is a good one for defenders: doubling a buffer and moving a *different* buffer to the heap does nothing when the bug is in code that indexes native-stack-backed state.

---

## Bosh: the 536F4U1t oracle — a cosmic ray in RWX memory

> *Flag:* `L3AK{eVer_h34rd_of_7He_536F4U1t_0R4Cle}`

Bosh is a fake shell whose handout ships **only** `chal.c` — no executable, no libc, and five deliberately withheld "proprietary" command modules. The visible bug (a 786-byte global overflow via `memcpy(previousCommand, cmdBuf, cmdLen)`) is a trap: the shipped binary is fortified, and an inline `cmp rbx, 0x200 / ja ud2` object-size check aborts any oversized copy. Real exploitation runs through the modules.

### Step 1 — recover the missing binary

The `cat` module reads ordinary files, and Linux exposes the running executable at `/proc/self/exe`:

```text
cat /proc/self/exe
```

That returns the complete ELF — a **statically linked musl 1.2.5, non-PIE** binary (base `0x400000`) with symbols intact, giving fixed addresses for `chmod`, `__stdio_write`, `"flag.txt"`, and the `stdout` `FILE` object (whose `write` field is at `+0x48` → `0x40a268`). Each module is `mmap`'d at a fixed RWX address (`ray` at `0x0133b000`).

### Step 2 — treat the withheld module as an oracle

`ray` performs exactly one arbitrary byte write, then overwrites its own entry byte with `RET` (`0xc3`) to disable itself. Since the module bytes can't be read (mode `000` files, EOF-positioned fds), two black-box scans recover the needed offsets purely from behavior:

- **Unlimited writes.** Brute-forcing (offset, entry-byte) pairs and checking whether a *second* `ray` call succeeds finds that writing `0x41` to `ray+0xe2` makes `ray` restore its original entry byte instead of writing `RET`. From then on, every call is a fresh arbitrary byte write.
- **Byte → dword store.** The instruction encodings `0x88 mov r/m8,r8` and `0x89 mov r/m32,r32` differ by one opcode byte. A `prev`-command oracle (does overwriting `"ray "` produce `"cay"` — one byte changed — or `"cat"` — four bytes changed?) pinpoints the store opcode at `ray+0x4b`. Writing `0x89` there widens the primitive to an **atomic 32-bit write**.

### Step 3 — atomic stdout hook

Why atomic matters: the shell calls `printf("boosh>")` after every command, so patching `stdout->write` one byte at a time would crash on the next prompt. Instead, a 30-byte stub is written into unused RWX space at `ray+0xf00` that calls `chmod("flag.txt", 0600)` and tail-jumps to the real `__stdio_write` (preserving all output):

```asm
push rdi ; push rsi ; push rdx
mov edi, 0x4070bc      ; "flag.txt"
mov esi, 0x180         ; 0600
mov eax, 0x403600      ; chmod
call rax
pop rdx ; pop rsi ; pop rdi
mov eax, 0x406291      ; __stdio_write
jmp rax
```

A single widened `ray` swaps `stdout->write` (`0x00406291 → 0x0133bf00`) in one store; that same call's own success `printf` immediately fires the hook, re-enables `flag.txt`, and the final `cat flag.txt\n` returns the flag. Non-PIE + fixed module maps means zero heap/stack leaks are needed and there's no race.

**Six reusable techniques:** recover an omitted binary via `/proc/self/exe`; treat inaccessible code as an oracle; neutralize a self-disabling primitive by changing what it writes back; upgrade write width with a one-byte opcode patch; prefer atomic pointer replacement when the target is exercised between commands; and always preserve the original callback contract so you don't destroy your own output channel.

---

## Piet — aliasing `stack_depth` into an exact `set_depth` primitive

> *Flag lives inside a Base64 PNG:* `L3AK{iVBORw0KGgo...ErkJggg}`

The frontend is exotic — a **Piet interpreter** that runs programs encoded as PNG images — but the bug is textbook. The 256-entry VM stack is indexed by `stack_depth`, which `stack_push`/`stack_pop` trust with no bounds check, and two custom opcodes (`up`, `down`) modify that field *directly* without touching the stack:

```c
static void op_up(ProgramState *s, int sz)   { s->stack_depth++; }
static void op_down(ProgramState *s, int sz) { s->stack_depth--; }
```

### The set_depth(N) primitive

`stack_depth` sits six dwords before `stack[0]`, i.e. at VM index `-6`. So six `down` operations followed by `push N` do this: `stack_push` reads old depth `-6`, stores `-5` into the field, then writes `N` into `stack[-6]` — **which is the field itself.** The net result is an exact `set_depth(N)`:

```python
def set_depth(self, target):
    for _ in range(self.depth + 6): self.emit("down")
    self.emit("push", target)   # width of the color block = N
    self.depth = target
```

That is arbitrary out-of-bounds positioning into `interpret_program()`'s frame. Index 270/271 holds `main()`'s saved libc return address (`libc + 0x2a601`).

### Leakless ROP + a shaped halt

As with LattiaVM, no leak is printed: the exploit duplicates that saved pointer four times and adjusts each copy's low dword by `target_offset - 0x2a601`, building `pop rdi; ret` / `"/bin/sh"` / `ret` / `system` on the native stack. Piet's signed 32-bit arithmetic wraps naturally, and `roll(2,1)` swaps low/high dwords so only the low half is edited.

The subtle finishing move is halting *cleanly* without executing junk after the corruption. The exploit shapes a 3×3 terminal color block entered through the center of its top edge; Piet's exit rules only test the block's corners (all black/out-of-bounds), so all eight moves fail, `next_codel()` returns 0, the interpreter prints `halted`, and `main()`'s epilogue runs the ROP chain — canary untouched. The malicious image compresses to ~501 bytes despite 1286 Piet operations.

## Piet 2 — when `roll` forgets its own depth bound

> *Flag lives inside a Base64 PNG:* `L3AK{iVBORw0KGgo...ErkJggg}` — **0 solves at release.**

Piet 2 patches the original: `stack_push`/`stack_pop` are now bounds-checked and the `up`/`down` opcodes are gone. But the standard `roll` operation checks `d <= 0` and never `d > stack_depth`:

```c
static void op_roll(ProgramState *s, int sz) {
    if (!stack_pop(s, &n) || !stack_pop(s, &d)) return;
    if (d <= 0) return;                 // no d <= stack_depth check
    int count = ((n % d) + d) % d;
    for (int i = 0; i < count; i++) {
        int32_t top = s->stack[s->stack_depth - 1];
        for (int j = s->stack_depth - 1; j > s->stack_depth - d; j--)
            s->stack[j] = s->stack[j - 1];
        s->stack[s->stack_depth - d] = top;
    }
}
```

If `d` exceeds the live depth, the copy loop and final store use *negative* VM indices that overlap `ProgramState` and the native frame. Worse, the loop re-reads `stack_depth` each iteration, so an out-of-bounds copy that changes that field alters the roll mid-flight.

### Two rolls, a forged frame, and a saved-rbp pivot

1. **Depth bootstrap.** With depth 1, `push 80; push 7; push 1; roll` stores `80` into `stack[1-7] = stack[-6] = stack_depth`, jumping the logical depth to 80 without ever pushing beyond index 255.

2. **Leakless pointers from uninitialized stack.** The `int32_t stack[256]` is never zeroed and reliably retains three stale values from earlier PNG parsing: a live `Image *` (indices 16/17), a pointer to `stack[84]` (76/77), and a libc pointer `libc + 0x128e6e` (78/79). Legal `roll`/`dup` sequences copy these while preserving the originals, and each ROP entry is derived by adding a 32-bit delta to the stale libc low dword — no leak, no fixed ASLR address.

3. **The distant write.** A forged frame is laid out around `stack[84]` (fake `rbp = 0`, then `pop rdi; ret` / `"/bin/sh"` / `ret` / `system`, with the genuine `Image *` at `stack[82]`). A final malformed `roll` with `d = H - 260` (where `H` is the native stack's high 16 bits) first sets `stack_depth = H` via `stack[-6] = stack[-7]`, then computes its store target as `stack[H - (H-260)] = stack[260]` — the **low dword of the saved frame pointer**. The high dword already carries the right stack prefix, so saved `rbp` now points at the forged frame.

4. **Pivot through cleanup.** Because the real `Image *` sits at `[fake_rbp - 8]`, `main()`'s `free_image()` still frees a valid object, then `leave; ret` pivots into the chain: `pop rdi; ret` → `"/bin/sh"` → `ret` (alignment) → `system`. The return address and canary are never touched.

Two operational details make it work remotely: `H` is only known to be in `0x7ffc`–`0x7fff`, so the solver cycles the four candidates across fresh connections; and because the program calls `png_read_image()` but not `png_read_end()`, the 12-byte `IEND` chunk must be *withheld* from the socket so the spawned `/bin/sh` doesn't swallow binary trailer bytes before `cat flag.txt`.

**Why it's a great challenge:** bounding `push`/`pop` is not enough when another instruction (`roll`) independently performs indexed memory access and needs its *own* `d <= stack_depth` validation. Corrupting a saved frame pointer rather than a return address is what lets normal cleanup finish before the controlled pivot.

---

## Supervisor — breaking a seccomp user-notification sandbox

> *Flag:* `L3AK{w0w_7his_5UP3RVis0r_is_R3411Y_terriB1e}`

The hardest "systems" challenge of the set. The service accepts an ELF, forks, applies a seccomp **user-notification** filter to the child, and **emulates the child's syscalls in the parent**. Uploaded programs never touch host files; instead the parent keeps virtual files as anonymous mappings and copies data with `process_vm_readv/writev`. The privilege boundary: the network process runs as `ubuntu`, and only a setuid-root `/readflag` helper can read `/flag.txt`.

### Two unsigned-arithmetic bugs

Both emulated I/O paths do pointer arithmetic on attacker-controlled `offset`/`count` before proving the range is in-bounds.

- **Arbitrary parent read.** `read_fd()` computes `files[id].data + offset` and, if `offset + count > size`, "clamps" via `count = size - offset` — which *underflows*. `lseek` accepts a negative `off_t` into the unsigned `offset` field, so `offset = target - data_base (mod 2⁶⁴)` makes the source resolve to any parent address. Reading into a single scratch page at `0x100000000` yields a page-oriented disclosure that stops safely at the first unmapped child page.

- **Arbitrary 8-byte parent write.** `write_fd()` checks `offset + count > cap` before growing the mapping. Choosing `offset = target - data_base` and `count = 0 - offset` makes `offset + count == 0 (mod 2⁶⁴)`, skipping the capacity check while `data_base + offset` still points at the target. Placing the source value in the last 8 bytes of the child's scratch page (next page unmapped) makes `process_vm_readv` copy exactly 8 bytes and fault — a clean arbitrary qword write.

### Defeating ASLR entirely from the target's own memory

No `/proc`, no output leak. Scan backward in page steps from the virtual mapping to find the first ELF header (libc). Leak `_IO_2_1_stdout_ + 0xd8` (the vtable → `_IO_file_jumps`) for an exact `libc_base = stdout_vtable - 0x202030`, hence `data_base`. Leak `environ` to reach the parent stack, "write it back to itself" to abuse the `size = offset + res` update and inflate the virtual file's logical size (so higher addresses read cleanly), then scan below `environ` for a supervisor PIE pointer (`0x5000_0000_0000`–`0x6000_0000_0000`) and walk back to its `\x7fELF` to recover the PIE base. All three bases come from the supervisor's own memory.

### The finish: strlen@GOT → system

Partial RELRO leaves the GOT writable. Overwrite `strlen@GOT` (`PIE + 0x8038`) with `system` (`libc + 0x58750`), then have the child `openat("/readflag")`. The parent's `resolve_path()` runs `strlen(path)` on the absolute path — now `system("/readflag")`. The decisive asymmetry: `PR_SET_NO_NEW_PRIVS` was applied only in the *child*. The **parent** is unconfined and may still exec a setuid binary, so `/readflag` runs as root and prints the flag.

The solver is a freestanding, statically linked raw-syscall ELF (`gcc -nostdlib -static -no-pie ...`), uploaded and run over TLS.

**Defensive lesson:** a seccomp notifier is a parser for attacker-controlled process state, and every emulated offset/length is a kernel-grade trust boundary. The safe checks are subtraction-based (`offset <= size && count <= size - offset`) with negative offsets rejected outright. And note the strategic point: compromising the *notifier* was worth more than escaping the child, because the notifier kept the privilege needed to invoke the setuid helper.

---

## Cross-cutting lessons from the L3akCTF 2026 pwn set

Seven very different frontends — a calculator, two custom bytecode VMs, a fake shell, two Piet image interpreters, and a syscall supervisor — converge on the same handful of ideas worth internalizing:

- **Corrupt the metadata, not the target.** A length field (Rudimentary Calculator), a VM stack pointer (LattiaVM), a `stack_depth` field (Piet 1), a saved `rbp` (Piet 2), a self-disable byte and store opcode (Bosh), and an emulated `offset` (Supervisor) were each the real primitive. Return addresses were almost an afterthought.
- **You rarely need to print a leak.** Four of the seven build ASLR-correct pointers by adding fixed offsets to an existing in-memory pointer (the saved libc return, a stale stack value, or a scanned ELF header). Practice thinking in *offsets from a base you already have* rather than reaching for a `puts`-style disclosure.
- **Respect the harness constraints as part of the puzzle.** `/dev/null` stdin forces non-interactive commands (`pr f*`); a 128-byte / 512-instruction VM budget forces byte-immediate arithmetic and tight loops; an unread PNG `IEND` chunk must be withheld from a spawned shell. The transport is part of the exploit.
- **Bounds checks must cover every indexed access.** Piet 2 is the canonical example: bounding `push`/`pop` while leaving `roll` unchecked left a wide-open door.
- **Pin the runtime bit-exact.** The LattiaVM, Piet, and Supervisor solvers all depend on specific glibc/musl builds; extract the handout's `libc.so.6`/`ld` (or recover the binary via `/proc/self/exe`) and develop against it.

## Reproduce it yourself

Every challenge in this writeup ships a standalone solver at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026) under `pwn/<challenge>/`. The LattiaVM, Piet, Rudimentary Calculator, and Bosh solvers use only the Python standard library (no pwntools dependency); Supervisor's solver is a freestanding C payload. Each per-challenge `README.md` includes the exact offsets, SHA-256 hashes, remediation notes, and local-reproduction commands.

If you're building a study path around these techniques, pair this with our other [CTF writeups](/ctf-writeups/) — the D3CTF kernel page-cache challenge and the OmniCTF glibc heap challenges make good next steps once the stack-metadata patterns here feel routine.

---

*This writeup is part of the CyberSecurity Elite [L3akCTF 2026](/series/l3akctf-2026/) series. Challenge files, recovered binaries, and complete solver scripts for all seven binary exploitation challenges are published at [github.com/Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026).*
