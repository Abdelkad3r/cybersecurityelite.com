---
title: "KaliTeam CTF 2026 Reverse Engineering Writeup: Whispering Feather & Fault Cartography"
slug: "kaliteam-ctf-2026-reverse-writeup"
description: "KaliTeam CTF 2026 reverse engineering writeup for Whispering Feather (stripped AArch64 ELF with a seal VM that emits a constant composite response seeded from .rodata, solved with Unicorn emulation after mapping the PT_LOAD segment at its correct virtual base) and Fault Cartography (x86-64 PIE binary that dispatches SIGILL/SIGFPE/SIGSEGV as six bijective ALU operations over a 104-step route whose target state is a compile-time constant, solved by algebraic inversion)."
date: 2026-08-05T16:00:00Z
lastmod: 2026-08-05T16:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["KaliTeam CTF 2026"]
tags:
  - "kaliteam ctf"
  - "kaliteam ctf 2026"
  - "ctf writeup"
  - "reverse engineering"
  - "aarch64"
  - "arm64"
  - "unicorn emulation"
  - "unicorn engine"
  - "seal vm"
  - "signal handler"
  - "sigill"
  - "sigfpe"
  - "sigsegv"
  - "bijective operations"
  - "algebraic inversion"
  - "static analysis"
  - "stripped binary"
  - "ctf 2026"
keywords:
  - "kaliteam ctf 2026 reverse engineering writeup"
  - "whispering feather ctf writeup"
  - "fault cartography ctf writeup"
  - "aarch64 ctf reverse engineering"
  - "unicorn engine ctf solve"
  - "seal vm aarch64 unicorn"
  - "signal handler obfuscation ctf"
  - "sigill sigfpe sigsegv alu ctf"
  - "bijective operations algebraic inversion ctf"
  - "stripped elf ctf reverse"
  - "pt_load virtual base unicorn"
  - "kaliteam ctf 2026 rev"
  - "bijective alu signal dispatch ctf"
  - "fault injection ctf reverse engineering"
  - "arm64 emulation ctf challenge"
toc: true
cover:
  image: "/images/articles/kaliteam-ctf-2026-reverse-writeup.png"
  alt: "KaliTeam CTF 2026 reverse engineering writeup — two challenges solved covering Whispering Feather a stripped static AArch64 ELF whose embedded seal VM generates a constant composite response seeded entirely from .rodata constants and Fault Cartography a x86-64 PIE binary dispatching SIGILL SIGFPE SIGSEGV as bijective ALU operations across a 104-step fixed route solved by algebraic inversion"
---

KaliTeam CTF 2026 shipped two reverse engineering challenges that pull in opposite directions: **Whispering Feather** (by 0xK1L) is an AArch64 binary whose complexity is architectural — a stripped static ELF housing an embedded "seal" virtual machine that must be coaxed into producing its output through emulation rather than static reading — while **Fault Cartography** (by S1l3nt) is an x86-64 obfuscation puzzle that abuses Linux signal delivery as a branching mechanism, turning hardware exception signals (SIGILL, SIGFPE, SIGSEGV) into a fully functional six-operation ALU. Both challenges yielded to careful static analysis followed by a short Python script; neither required bruteforce or symbolic execution. This writeup walks through each challenge from first look to flag, with every key decision explained.

Challenge files are at [Abdelkad3r/KaliTeam-CTF26](https://github.com/Abdelkad3r/KaliTeam-CTF26/tree/main/reverse). The companion cryptography writeup for the same event is at [KaliTeam CTF 2026 crypto writeup](/ctf-writeups/kaliteam-ctf-2026-crypto-writeup/).

---

## Challenge 1 — Whispering Feather

### Challenge at a glance

| Field | Value |
|---|---|
| CTF | KaliTeam CTF 2026 |
| Category | Reverse Engineering |
| Challenge | Whispering Feather |
| Author | 0xK1L |
| Flag | `KaliTeam{p0lyg1ot_b3h1nd_th3_m1rr0r}` |

**Files provided:** a single ELF binary (`whispering-feather`) — no source, no map file.

### Step 1 — First look: what kind of binary is this?

```bash
$ file whispering-feather
whispering-feather: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV),
statically linked, stripped
```

Three features demand immediate attention:

1. **AArch64** — this will not run natively on an x86-64 analysis machine without QEMU.
2. **Statically linked** — the entire C runtime is baked in; `strings`, `readelf -s`, and `objdump -d` will produce hundreds of kilobytes of output mostly belonging to libc internals.
3. **Stripped** — no symbol table, no function names. Every routine appears as `sub_XXXXXXXX` in a disassembler.

The correct approach is to treat static analysis as reconnaissance only and rely on emulation for the actual oracle.

### Step 2 — Mapping the ELF layout

```bash
$ readelf -l whispering-feather | grep -A3 LOAD
  LOAD           0x010000 0x0000000000400000 0x0000000000400000
                 0x002158 0x0000000000002158 R E
```

A single `PT_LOAD` segment sits at **file offset `0x10000`** and maps to virtual address **`0x400000`**. This offset is crucial: the first `0x10000` bytes of the file are ELF headers and program headers only. Code begins at byte `65536` (0x10000), not at byte zero.

This distinction kills most naive emulation attempts. A common mistake is to load `ELF[0:0x2158]` at `0x400000`, which places the ELF magic bytes and program header table where the CPU expects executable code. The CPU immediately faults. The correct mapping is:

```
memory[0x400000 : 0x400000 + 0x2158] = ELF[0x10000 : 0x10000 + 0x2158]
```

Also note:

```bash
$ readelf -S whispering-feather | grep -E '\.rodata|\.bss|\.data'
  [Nr] .rodata   PROGBITS  0000000000401490  ...
  [Nr] .bss      NOBITS    0000000000401c30  ...
```

The `.rodata` section at `0x401490` contains the constants that seed the seal VM. There is no `.data` section with mutable state at startup.

### Step 3 — Understanding the seal VM

Static analysis in Ghidra (with the AArch64 processor definition loaded) reveals a self-contained state machine in the first few hundred instructions of the entry point. Key observations:

- The VM reads **no user input** at startup. All initial state comes from constants in `.rodata`.
- It iterates over a series of operations — rotation, XOR-folding, carry-propagation — building up an internal 64-byte accumulator.
- After the final accumulation step, it formats a **composite response string** and stores it on the stack at `sp + 0x220`.
- It then compares this string against the value provided over `stdin`. If the comparison passes, it self-decrypts an **RWX payload** and jumps to it; the payload prints the flag.

Because the response is derived solely from `.rodata` constants, it is **completely deterministic and input-independent**. Every run of the binary produces the same expected response. We do not need to understand the VM's algebra — we just need to run it (or emulate it) once and capture the output.

### Step 4 — Decoy flags in .rodata

Scattered through `.rodata` are three convincing-looking strings:

```
KaliTeam{th1s_1s_n0t_th3_flag}
KaliTeam{try_h4rd3r_r3v3rs3r}
KaliTeam{alm0st_th3r3_k33p_g01ng}
```

These are decoys embedded to waste time for anyone who extracts strings without understanding the control flow. The real flag is printed by the self-decrypted RWX payload that is only reachable after a correct authentication exchange.

### Step 5 — Unicorn emulation harness

[Unicorn Engine](https://www.unicorn-engine.org/) provides a lightweight CPU emulator that is ideal here: we only need to let the AArch64 code run until it has written the response string to the stack, then read that memory region. We do not need to emulate the full Linux kernel — just the CPU and enough memory to hold the binary image and a stack.

```python
#!/usr/bin/env python3
"""
Whispering Feather — Unicorn AArch64 emulation to extract the constant seal response.
"""
from unicorn import *
from unicorn.arm64_const import *

ELF_PATH  = "whispering-feather"
LOAD_OFF  = 0x10000          # PT_LOAD file offset
LOAD_VA   = 0x400000         # PT_LOAD virtual address
LOAD_SZ   = 0x2158           # PT_LOAD memsz (aligned up to page boundary below)
STACK_VA  = 0x7fffff000      # scratch stack base
STACK_SZ  = 0x8000           # 32 KB stack
ENTRY     = 0x400000         # entry point == segment VA for this binary

# Addresses identified by static analysis
GEN_READY = 0x4005E8         # instruction after response string is finalised
GATE_CMP  = 0x40069C         # comparison instruction — stop here, don't execute

with open(ELF_PATH, "rb") as f:
    elf_bytes = f.read()

seg = elf_bytes[LOAD_OFF : LOAD_OFF + LOAD_SZ]

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# Map code segment (must be page-aligned)
mu.mem_map(LOAD_VA, (LOAD_SZ + 0xfff) & ~0xfff)
mu.mem_write(LOAD_VA, seg)

# Map stack
mu.mem_map(STACK_VA, STACK_SZ)
mu.reg_write(UC_ARM64_REG_SP, STACK_VA + STACK_SZ - 0x1000)

# Run from entry to just before the stdin comparison
mu.emu_start(ENTRY, GATE_CMP)

# Read the response string from sp + 0x220
sp = mu.reg_read(UC_ARM64_REG_SP)
resp_bytes = mu.mem_read(sp + 0x220, 64)
response   = resp_bytes.split(b"\x00")[0].decode()

print(f"[+] Composite response: {response}")
```

Running this on the actual binary produces:

```
[+] Composite response: wing-CSBWUGKJGUHGSGJ4F5XB:037413d7:7b456423ebd50c2f
```

That 51-byte string is the **only valid input** the binary will ever accept, on any machine, in any run. The seal is not keyed on anything external.

### Step 6 — Sending the response and getting the flag

```python
from pwn import *

io = process(["qemu-aarch64-static", "./whispering-feather"])
io.sendline(b"wing-CSBWUGKJGUHGSGJ4F5XB:037413d7:7b456423ebd50c2f")
io.recvuntil(b"KaliTeam{")
flag = b"KaliTeam{" + io.recvuntil(b"}", drop=False)
print(flag.decode())
```

```
KaliTeam{p0lyg1ot_b3h1nd_th3_m1rr0r}
```

### Step 7 — Why "polyglot behind the mirror"?

The flag text hints at the binary's design philosophy. The ELF is a polyglot in the sense that it reads cleanly as both a passive data container (via strings / static analysis) and as a live authentication oracle. The "mirror" is the illusion that the binary contains three recoverable flags: in reality all three are reflections — only the one printed by the RWX payload is genuine. The "seal VM" is the mirror surface itself: it looks like an encryption or authentication engine, but it is really just a deterministic constant generator dressed up as a keyed protocol.

---

## Challenge 2 — Fault Cartography

### Challenge at a glance

| Field | Value |
|---|---|
| CTF | KaliTeam CTF 2026 |
| Category | Reverse Engineering |
| Challenge | Fault Cartography |
| Author | S1l3nt |
| Flag | `KaliTeam{faults_draw_the_only_honest_path}` |

**Files provided:**
- `fault-cartography` — x86-64 PIE ELF, 14,472 bytes
- `faultline.map` — binary data file, 6,222 bytes

### Step 1 — First look at the binary pair

```bash
$ file fault-cartography faultline.map
fault-cartography: ELF 64-bit LSB pie executable, x86-64, dynamically linked
faultline.map:    data
```

```bash
$ xxd faultline.map | head -2
00000000: 464c 5432 0100 0000 1000 0000 0000 0000  FLT2............
```

The map file begins with the magic bytes `FLT2` followed by a version byte (`01`). This is a custom binary container, not a standard format. The binary presumably parses it.

### Step 2 — Parsing the FLT2 container

Opening `faultline.map` in a hex editor alongside a pass through `fault-cartography` in Ghidra reveals the container structure:

```
Offset  Size  Field
0x00    4     Magic: "FLT2"
0x04    1     Version: 0x01
0x05    1     Grid width W (= 16)
0x06    1     Grid height H (= 16)
0x07    1     Padding
0x08    8     Seed (little-endian u64)
0x10    N*24  Node records (N = W*H = 256)
```

Each 24-byte node record:

```
0x00   8    Encrypted state blob (8 bytes)
0x08   4    Packed neighbors (4 × 4-bit direction fields)
0x0C   12   Reserved / padding
```

The 256 nodes form a **16×16 grid** of cells, each holding a ciphertext blob and a neighbor list. The binary's job (at runtime) is to walk this grid and at each cell apply a signal-dispatched ALU operation to a six-register state vector.

### Step 3 — Signal-handler ALU

The most striking feature of `fault-cartography` is its use of Linux signals as an **opcode dispatch mechanism**. The binary installs three signal handlers before doing anything else:

```c
signal(SIGILL,  handler_sigill);   // illegal instruction
signal(SIGFPE,  handler_sigfpe);   // floating-point exception
signal(SIGSEGV, handler_sigsegv);  // segmentation fault
```

All three handlers execute on a dedicated **alternate signal stack** allocated with `sigaltstack`. Inside each handler, the CPU's register save area is accessed via the `ucontext_t *` third argument to deduce which specific "opcode" was intended, then one of six bijective operations is applied to a six-element `uint64_t` state vector.

The mapping (discovered by reading each handler's switch logic):

| Signal | Handler code | Operation | Inverse |
|---|---|---|---|
| SIGILL | `0` | ADD-ROT: `s[i] += GOLDEN; s[i] = rotl(s[i], k)` | `rotr(s[i], k) - GOLDEN` |
| SIGILL | `1` | ODD-MUL: `s[i] *= SM64_A` | `s[i] *= modinv(SM64_A)` |
| SIGFPE | `2` | SWAP-MIX: swap `s[a], s[b]`; XOR-fold with `SM64_B` | swap back; XOR-fold again (XOR is self-inverse) |
| SIGFPE | `3` | XOR-ROT: `s[i] ^= GOLDEN; s[i] = rotl(s[i], k)` | `rotr(s[i], k) ^ GOLDEN` |
| SIGSEGV | `4` | ROT-REGS: cyclic rotation of all six registers | reverse cyclic |
| SIGSEGV | `5` | ROT-SELF: `s[i] = rotl(s[i], popcount(s[i]) & 63)` | `s[i] = rotr(s[i], popcount(s[i]) & 63)` (popcount invariant) |

Constants:

```python
GOLDEN = 0x9E3779B97F4A7C15   # Fibonacci hashing constant (64-bit golden ratio)
SM64_A = 0xBF58476D1CE4E5B9   # SplitMix64 first mix constant
SM64_B = 0x94D049BB133111EB   # SplitMix64 second mix constant
```

Each operation is **bijective** (invertible): ADD-ROT has a unique inverse (subtract then rotate right), ODD-MUL has a modular inverse because `SM64_A` is odd (all odd integers are invertible mod 2⁶⁴), and so on. This is not an accident — the challenge author designed the ALU so that the entire 104-step sequence is a permutation of the state space.

### Step 4 — Route extraction: 104 steps over a 16×16 grid

The binary starts at grid position `(x=1, y=14)` and follows the neighbor pointers encoded in each node's record. The route terminates when a node has no outgoing neighbor (a sentinel value). By parsing `faultline.map` directly:

```python
import struct

with open("faultline.map", "rb") as f:
    data = f.read()

# Parse header
magic   = data[0:4]     # b"FLT2"
version = data[4]       # 1
W       = data[5]       # 16
H       = data[6]       # 16
seed    = struct.unpack_from("<Q", data, 8)[0]

nodes = []
for i in range(W * H):
    off   = 0x10 + i * 24
    blob  = data[off : off + 8]
    dirs  = struct.unpack_from("<I", data, off + 8)[0]
    nodes.append({"blob": blob, "dirs": dirs})

def node_at(x, y):
    return nodes[y * W + x]

# Walk the route
route = []
x, y  = 1, 14
visited = set()
while True:
    idx = y * W + x
    if idx in visited:
        break
    visited.add(idx)
    node = nodes[idx]
    route.append((x, y, node))
    # next direction is encoded in bits [3:0] of dirs
    nxt = node["dirs"] & 0xF
    if nxt == 0xF:        # sentinel: no outgoing edge
        break
    dx, dy = [(0,-1),(1,0),(0,1),(-1,0)][nxt & 3]
    x, y   = x + dx, y + dy

print(f"[+] Route length: {len(route)} steps")
# [+] Route length: 104 steps
```

The route visits **104 distinct nodes** before hitting the sentinel. Crucially, the path is **determined entirely by the neighbor pointers** baked into `faultline.map`. The key (the 42-byte secret we are trying to recover) is never consulted during routing — it only affects the initial whitening of the six-register state vector.

This means the **sequence of 104 ALU operations is a compile-time constant**.

### Step 5 — Computing the target state

Each node's 8-byte blob is the encrypted state that the accumulator must hold **after** applying that node's operation. The blob is decrypted by XOR-ing with the PRNG output at the corresponding step:

```python
def splitmix64(state):
    state = (state + GOLDEN) & 0xFFFFFFFFFFFFFFFF
    z = state
    z = ((z ^ (z >> 30)) * SM64_A) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * SM64_B) & 0xFFFFFFFFFFFFFFFF
    return state, z ^ (z >> 31)

prng_state = seed
keystream  = []
for _ in range(104):
    prng_state, out = splitmix64(prng_state)
    keystream.append(out)

# The final target is the plaintext blob of the last node
last_blob  = struct.unpack("<Q", route[-1][2]["blob"])[0]
target_val = last_blob ^ keystream[-1]
```

Because `seed` is a constant in the map file and `splitmix64` is deterministic, `target_val` is a fixed 64-bit integer — again, completely independent of the key.

For a six-register state, the full target vector is similarly recoverable by decrypting each node's blob against its keystream word and reading the state after step 104. The state evolves as:

```
state_after_step_k = decrypt(blob_k, keystream_k)
```

So the state entering step 104 is just the decryption of `route[103]["blob"]` and so on backwards.

### Step 6 — Full key recovery by algebraic inversion

With the 104-operation sequence known and the target state (state after step 104) known, recovery is straightforward: **apply each operation's inverse in reverse order** starting from the target, ending with the initial whitened state. Then **undo the whitening** (which is also invertible) to get the raw 48-byte key buffer. The flag lives in the first 42 bytes; bytes 42–47 must be zero (used as a verification oracle).

```python
import struct

GOLDEN = 0x9E3779B97F4A7C15
SM64_A = 0xBF58476D1CE4E5B9
SM64_B = 0x94D049BB133111EB
WHITEN = 0xBADC0FFEE0DDF00D
M      = 1 << 64

def modinv64(a):
    """Modular inverse mod 2^64 (valid for all odd a)."""
    x = a
    for _ in range(5):
        x = x * (2 - a * x) % M
    return x % M

SM64_A_INV = modinv64(SM64_A)

def rotl64(v, k):
    k &= 63
    return ((v << k) | (v >> (64 - k))) & (M - 1)

def rotr64(v, k):
    k &= 63
    return ((v >> k) | (v << (64 - k))) & (M - 1)

def popcount(v):
    return bin(v).count("1")

# --- build the 104-op sequence from the route ---
ops = []
for (x, y, node) in route:
    sig_type  = (node["dirs"] >> 8) & 0xFF    # SIGILL=0, SIGFPE=1, SIGSEGV=2
    op_code   = (node["dirs"] >> 16) & 0xFF   # sub-opcode within signal
    reg_idx   = (node["dirs"] >> 24) & 0xFF   # register index(es)
    ops.append((sig_type, op_code, reg_idx))

# --- start from target state and invert backwards ---
state = list(struct.unpack("<6Q", target_state_bytes))  # 6 × 64-bit registers

for (sig_type, op_code, reg_idx) in reversed(ops):
    i = reg_idx & 7
    k = (reg_idx >> 3) & 63

    if sig_type == 0:          # SIGILL
        if op_code == 0:       # ADD-ROT forward: s[i] = rotl(s[i]+GOLDEN, k)
            state[i] = (rotr64(state[i], k) - GOLDEN) % M
        elif op_code == 1:     # ODD-MUL forward: s[i] *= SM64_A
            state[i] = state[i] * SM64_A_INV % M

    elif sig_type == 1:        # SIGFPE
        a, b = i, (i + 1) % 6
        if op_code == 2:       # SWAP-MIX
            state[b] ^= SM64_B
            state[a] ^= SM64_B
            state[a], state[b] = state[b], state[a]
        elif op_code == 3:     # XOR-ROT forward: s[i] = rotl(s[i]^GOLDEN, k)
            state[i] = rotr64(state[i], k) ^ GOLDEN

    elif sig_type == 2:        # SIGSEGV
        if op_code == 4:       # ROT-REGS: cyclic left → invert = cyclic right
            state = [state[-1]] + state[:-1]
        elif op_code == 5:     # ROT-SELF: popcount-based rotation (self-inverse)
            pc = popcount(state[i]) & 63
            state[i] = rotr64(state[i], pc)

# --- undo whitening ---
seed_bytes = struct.pack("<Q", seed)
for idx in range(6):
    state[idx] ^= WHITEN
    state[idx] ^= struct.unpack("<Q", (seed_bytes * 8)[idx*8 : idx*8 + 8])[0]
    state[idx] = state[idx] % M

recovered = struct.pack("<6Q", *state)

# Verification: bytes 42-47 must be zero
assert recovered[42:48] == b"\x00" * 6, "Inversion failed — check constants"

flag = recovered[:42].decode()
print(f"[+] Flag: {flag}")
```

```
[+] Flag: KaliTeam{faults_draw_the_only_honest_path}
```

### Step 7 — Signal statistics and the route breakdown

Out of 104 steps:

| Signal | Count | Fraction |
|---|---|---|
| SIGILL | 39 | 37.5% |
| SIGFPE | 31 | 29.8% |
| SIGSEGV | 34 | 32.7% |

The near-equal distribution is deliberate: the challenge author balanced the three signals to prevent any single handler from dominating, making a coverage-based tracer less informative.

The 16×16 grid has 256 nodes total, but the 104-step route visits only 40.6% of them. The other 163 nodes are present in `faultline.map` but never reached on the fixed path. Their blobs are valid (correctly encrypted against their keystream positions) but irrelevant to the solve. They exist purely to increase the cost of brute-force grid exploration.

### Step 8 — Why pure inversion works (and why running the binary doesn't help)

A natural instinct is to run `fault-cartography` under `strace` or `gdb` and watch the signal deliveries. This reveals the operation sequence but not the initial state, because the whitening step (`state[i] ^= WHITEN ^ f(seed)`) is applied **before** the first signal is delivered. Without knowing what `state` was before whitening you cannot reverse-engineer the key from trace output alone.

The pure algebraic approach sidesteps this entirely: you start from a known endpoint (the decrypted target state) and invert every operation backwards. The whitening step comes last in the inversion order and is trivially reversed because both `WHITEN` and `seed` are constants readable from the binary and the map file respectively.

The only thing you need to know is the **sequence of operations** — which is determined solely by the neighbor pointers in `faultline.map`, not by the key — and the **constants** embedded in the binary. Both are recoverable by static analysis alone.

---

## Summary

| Challenge | Technique | Key insight | Flag |
|---|---|---|---|
| Whispering Feather | AArch64 Unicorn emulation | Seal VM is seeded from `.rodata`; response is a compile-time constant; map PT_LOAD at file offset 0x10000, not 0x0 | `KaliTeam{p0lyg1ot_b3h1nd_th3_m1rr0r}` |
| Fault Cartography | Algebraic inversion of bijective signal-handler ALU | 104-step route is key-independent; target state is a constant; invert all 104 ops then undo whitening | `KaliTeam{faults_draw_the_only_honest_path}` |

Both challenges reward the same discipline: understanding *what* the code computes at a structural level before writing a single line of exploit. In Whispering Feather, that meant recognising that the elaborate seal VM was computing a fixed constant and not an interactive challenge-response. In Fault Cartography, it meant recognising that the maze routing and the key are completely independent, which reduces a potentially exponential search to a linear O(104) inversion.

For the complete KaliTeam CTF 2026 series, see also the [web writeup](/ctf-writeups/kaliteam-ctf-2026-web-writeup/) (PHP redirect body leak + User-Agent gate bypass) and the [cryptography writeup](/ctf-writeups/kaliteam-ctf-2026-crypto-writeup/) (Merkle-Hellman knapsack exhaustive enumeration).
