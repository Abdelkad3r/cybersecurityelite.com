---
title: "ASIS CTF Quals 2026 Reverse Engineering Writeup: ASIS Arch & LeakMeAk"
slug: "asis-ctf-quals-2026-reverse-engineering-writeup"
description: "Complete ASIS CTF Quals 2026 Reverse Engineering writeup covering both RE challenges. ASIS Arch is a 2.5 KB custom 16-bit VM disguised as QEMU with an 8-register 26-opcode ISA whose four-byte instructions are encrypted with a keystream derived from the address they sit at — the same bytes decode differently at every PC and the immediate field carries the second register operand plus a 13-bit displacement through the same middle-endian nibble scramble that decodes the entry point. Recovering the ISA statically from the R_X86_64_RELATIVE relocations in the dispatch table gives the 26 live opcodes without executing a byte; a recursive-descent disassembler starting at the header's entry PC reaches 7960 instructions and finds a single unrolled basic block from 0x0024 to 0x7873 that runs ten rounds of substitute plus diffuse-forward plus diffuse-backward across 22 16-bit words. Because the transform is branch-free the operation sequence is input-independent, so lifting each store to a symbolic step 'buf[i] = f(buf[i], other words, constants)' and inverting the 660 steps in reverse recovers the flag directly with no brute force and no SMT solver. LeakMeAk is a stripped PIE flag checker that consumes the 28 inner bytes of ASIS{...} four at a time as big-endian words folded through H[i] = word * 0x9e3779b9 XOR mix_i where mix_i comes from a per-byte state machine with character-class counters. The hash is deliberately lossy so many inputs collide to the same H, but seven cyclic equations against two rodata tables, a poly-33 hash target of 0xddaacf25, its 64-round remix, and two low-bit s30 state checks tighten it back to a single printable answer. z3 recovers the seven H dwords uniquely from the cyclic equations; a Unicorn emulation hooked at the dword store acts as an exact oracle for mix; each (H, mix) pair inverts to word = (H XOR mix) times inv(0x9e3779b9); a DFS across the small candidate tree keeps the one string the checker actually grants — ASIS{haaducrcplmekhylrozcxyxzuizs}."
date: 2026-09-02T09:00:00Z
lastmod: 2026-09-02T09:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["ASIS CTF Quals 2026"]
tags:
  - "asis ctf"
  - "asis ctf quals 2026"
  - "asis ctf 2026"
  - "ctf writeup"
  - "reverse engineering"
  - "reverse challenge"
  - "asis arch"
  - "leakmeak"
  - "custom vm"
  - "virtual machine reversing"
  - "isa recovery"
  - "self encrypting instructions"
  - "middle endian nibbles"
  - "elf relocations"
  - "dispatch table"
  - "recursive descent disassembler"
  - "branch free obfuscation"
  - "symbolic lifting"
  - "z3 solver"
  - "unicorn emulator"
  - "non injective hash"
  - "golden ratio constant"
  - "flag checker"
  - "cyclic hash equations"
  - "state machine reversing"
  - "dfs candidate search"
  - "ctf 2026"
keywords:
  - "asis ctf quals 2026 writeup"
  - "asis ctf 2026 reverse writeup"
  - "asis ctf reverse engineering writeup"
  - "asis arch writeup"
  - "asis arch qemu ctf"
  - "asis arch custom vm ctf"
  - "leakmeak writeup"
  - "leakmeak elf ctf"
  - "self encrypting instruction vm ctf"
  - "middle endian nibble encoding ctf"
  - "elf relocation opcode table ctf"
  - "branch free transform inversion ctf"
  - "z3 cyclic equation solver ctf"
  - "unicorn oracle mix inversion ctf"
  - "non injective hash ctf"
  - "asis ctf 2026 solutions"
  - "ctf reverse step by step 2026"
toc: true
cover:
  image: "/images/articles/asis-ctf-quals-2026-reverse-engineering-writeup.png"
  alt: "ASIS CTF Quals 2026 Reverse Engineering writeup cover — both RE challenges solved. ASIS Arch is a 2.5 KB custom 16-bit VM disguised as QEMU with an 8-register 26-opcode ISA whose four-byte instructions are encrypted with a keystream derived from the address they sit at so the same bytes decode differently at every PC. The immediate field carries the second register operand plus a 13-bit displacement through the same middle-endian nibble scramble that decodes the entry point. Recovering the ISA statically from the R_X86_64_RELATIVE relocations in the dispatch table gives all 26 live opcodes without executing a byte, a recursive-descent disassembler reaches 7960 instructions from the header entry PC and finds a single unrolled basic block that runs ten rounds of substitute plus diffuse-forward plus diffuse-backward across 22 16-bit words. Because the transform is branch-free the operation sequence is input-independent so lifting each store to a symbolic step buf i equals f of buf i and inverting the 660 steps in reverse recovers the flag directly with no brute force and no SMT solver. LeakMeAk is a stripped PIE flag checker that consumes 28 inner bytes four at a time as big-endian words folded through H equals word times 0x9e3779b9 XOR mix where mix is a per-byte state machine; the hash is lossy so many inputs collide but seven cyclic equations against two rodata tables plus a poly-33 hash target and its remix plus two low-bit s30 state checks tighten it to a single printable answer. z3 recovers the seven H dwords uniquely, a Unicorn emulation hooked at the dword store acts as an exact oracle for mix, each pair inverts to word equals H XOR mix times inv 0x9e3779b9, and a DFS across the small candidate tree keeps the one string the checker actually grants."
---

**ASIS CTF Quals 2026**'s Reverse Engineering track is a two-challenge lesson in one shared discipline: **build a faithful model of the target, then let the model do the reversing rather than doing it by hand**. `ASIS Arch` ships a 2.5 KB binary that presents itself as a QEMU-like emulator with a custom architecture, and the only way through is to statically recover a 26-opcode ISA (from ELF relocations, not from a debugger), reimplement the machine cycle-accurately, and lift a branch-free 660-store transform into a symbolic representation you can invert in closed form. `LeakMeAk` is a stripped Linux flag-checker whose acceptance predicate mixes a lossy `H = word * 0x9e3779b9 XOR mix` hash with a state machine, seven cyclic equations, a poly-33 target, and a couple of low-bit checks — the shape of a problem that resists hand-reversing but yields to z3 for the cyclic equations and Unicorn as an exact oracle for the mix state machine.

Both challenges reward the same discipline: **do not paraphrase the target — reimplement it, then diff it against ground truth**. ASIS Arch's cycle count on both accepting and rejecting paths is the pass/fail; LeakMeAk's `puts` verdict from the real ELF (via Unicorn) is what confirms each candidate string. Neither challenge has a timing oracle, an early exit, or an addressable per-byte fault; both must be solved by modelling the whole check at once.

Handouts, per-challenge READMEs, solver scripts, and formatted writeups live at [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026). This **CyberSecurity Elite** ASIS CTF Quals 2026 Reverse Engineering writeup covers both challenges end to end, with an emphasis on the *static* path (relocations, symbolic lifting, cyclic constraint solving) over the *dynamic* one (fuzzing, single-stepping, per-byte grep). See also the companion posts for the [Misc](/ctf-writeups/asis-ctf-quals-2026-misc-writeup/) and [Crypto](/ctf-writeups/asis-ctf-quals-2026-crypto-writeup/) tracks.

## Both Reverse Engineering challenges at a glance

| Challenge | Difficulty | Sub-genre | Key insight | Flag |
|---|---|---|---|---|
| [ASIS Arch](#asis-arch--custom-16-bit-vm-with-address-keyed-instruction-encryption) | Medium | Custom 16-bit VM + branch-free block cipher | ISA lives in relocations; branch-free transform lifts symbolically and inverts step-for-step | `ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}` |
| [LeakMeAk](#leakmeak--z3-plus-unicorn-against-a-non-injective-hash) | Medium | Non-injective hash + state-machine flag checker | z3 pins the 7 internal dwords; Unicorn oracle inverts `word = (H XOR mix) * inv(const)` | `ASIS{haaducrcplmekhylrozcxyxzuizs}` |

Two categories dressed as one: a hand-rolled architecture and a hand-rolled cipher. Same discipline — model, do not paraphrase.

---

## ASIS Arch — custom 16-bit VM with address-keyed instruction encryption

> *Flag:* `ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}`
>
> *Prompt:* "We recovered a custom CPU emulator binary and a secure ROM image. The architecture does not appear in any public manual. Recover the ISA, reverse the verification logic, and find the correct flag from new ASIS Arch."

The handout is a 14 KB Linux ELF (`qemu-asisarch`) plus a 32 KB ROM (`challenge.rom`). Real QEMU is measured in megabytes; this binary is measured in kilobytes.

### 1. First-tell recon

```
$ file qemu-asisarch
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

$ ls -l qemu-asisarch challenge.rom
-rwxr-xr-x  14656 qemu-asisarch
-rw-r--r--  32171 challenge.rom
```

The section sizes say what the binary really is:

| Section | Size | What it is |
|---|---|---|
| `.text` | 0x9f5 (2549 B) | the entire CPU |
| `.rodata` | 0x260 | decode tables + strings |
| `.data.rel.ro` | 0x800 | **256 × 8** — an opcode dispatch table |

A 2 KB table of function pointers indexed by a byte is the shape of an interpreter dispatch. Strings confirm the model — `illegal instruction`, `PC out of bounds`, `guest cycle limit exceeded`, `ROM checksum mismatch`. Imports agree: no threading, no JIT, just `fopen`/`fread`/`getc`/`putc`.

Run it and it prompts for a flag:

```
$ echo 'ASIS{aaaa}' | ./qemu-asisarch -M asisboard -kernel challenge.rom -nographic
=== ASISARCH Secure Enclave v2.0 ===
Enter flag:
[-] Access Denied. Invalid flag.
```

An interactive flag checker. Everything interesting is in the ROM.

### 2. The ROM container

A 32-byte header validates before the body is copied to guest address 0:

```
+0x00  "AARQ"            magic
+0x04  02                version, must be 2
+0x08  byte lo           entry PC, low  half (scrambled)
+0x09  byte hi           entry PC, high half (scrambled)
+0x0c  uint32            checksum over the body
+0x20  image             body, at most 0x10000 bytes
```

The checksum is a 16-bit rolling XOR seeded with `0x31415926`:

```python
d = 0x31415926
for c in image:
    d = rol16(d & 0xffff, 3) ^ c ^ (d >> 16) ^ 0x9e37
```

The entry PC is not stored directly. It is built by swapping the nibbles of each header byte and rotating the assembled word:

```python
entry = rol16((rol8(hdr[9], 4) << 8) | rol8(hdr[8], 4), 5)   # = 0x0000
```

This same nibble scramble decodes every instruction immediate — the *middle-endian nibbles* the flag names.

### 3. Machine state

The whole machine is one flat allocation:

```
0x00000 .. 0x0ffff   RAM, 64 KiB
0x10000 .. 0x1000f   r0 .. r7, 16-bit each
0x10010              SP, initialised to 0xfff0
0x10012              PC
0x10018              cycle counter, aborts above 10_000_000
```

Registers are 16-bit, memory is byte-addressed and little-endian, and there are no flags — conditional control flow tests a register directly.

### 4. The fetch stage — instructions are encrypted with their own address

This is the core of the challenge. Every instruction is four bytes, but before decoding, the fetch stage derives a per-address keystream:

```python
raw = ((PC ^ 0x9e37) * 0x1039 + 0x79b9) & 0xffff
sel = (raw >> 14) & 3          # picks one of four byte permutations
k   = rol16(raw, 5)            # keystream word
```

`sel` indexes a `4x4` permutation table in `.rodata`:

```
sel 0: [0, 1, 2, 3]      sel 2: [3, 2, 1, 0]
sel 1: [2, 0, 3, 1]      sel 3: [1, 3, 0, 2]
```

The permuted bytes `b0..b3` are then unmasked with the keystream:

```python
op  = rol8((0x5d * PC ^ k ^ b2) & 0xff, (k >> 5) & 7) ^ 0x6d

x   = (7 * PC ^ (k >> 2) ^ b0) & 0xff
rd  = ((5 * (((5 * x) ^ 3) & 7)) ^ 3) & 7          # destination register

imm = rol16((rol8((b3 ^ (k >> 8)) & 0xff, 4) << 8)
            | rol8((b1 ^ k) & 0xff, 4), 5)          # 16-bit immediate
```

Three consequences, all deliberate:

- **The same bytes decode differently at different addresses.** A linear sweep from any offset produces plausible-looking but wrong instructions, and never resynchronises.
- **The ROM cannot be relocated.** Code is welded to the address it was assembled for.
- **Register numbers are permuted twice** by `x -> ((5x) ^ 3) & 7`, so the register field is not readable even after the keystream is removed.

The second register operand of ALU and memory instructions is not in the instruction byte at all — it is packed into the low three bits of the immediate, through the same permutation, with the remaining 13 bits used as an address displacement:

```python
rs   = ((5 * (imm & 7)) ^ 3) & 7
disp = imm >> 3
```

### 5. Recovering the opcode map without guessing

`.data.rel.ro` holds the 256-entry dispatch table, but in a PIE it is zero-filled on disk and populated at load time by `R_X86_64_RELATIVE` relocations. Reading the relocation table gives the mapping directly — 26 live opcodes, 230 null entries that trap as *illegal instruction*. `isa.py` does this, along with pulling the S-box and permutation tables out of `.rodata`, so nothing about the ISA is hardcoded except the names given to the 26 handler addresses.

The instruction set, read off the handlers:

| Op | Mnemonic | Semantics |
|---|---|---|
| `0x10` | `nop` | — |
| `0x15` | `li rd, imm` | `rd = imm` |
| `0x21` | `addi rd, imm` | `rd += imm` |
| `0x27` | `subi rd, imm` | `rd -= imm` |
| `0x32` | `xori rd, imm` | `rd ^= imm` |
| `0x38` | `andi rd, imm` | `rd &= imm` |
| `0x44` | `roli rd, imm` | `rd = rol16(rd, imm & 15)` |
| `0x4b` | `mov rd, rs` | `rd = rs` |
| `0x50` | `add rd, rs` | `rd += rs` |
| `0x56` | `sub rd, rs` | `rd -= rs` |
| `0x5c` | `xor rd, rs` | `rd ^= rs` |
| `0x63` | `ldb rd, [rs+disp]` | zero-extending byte load |
| `0x69` | `stb [rs+disp], rd` | byte store |
| `0x71` | `ldw rd, [rs+disp]` | 16-bit little-endian load |
| `0x77` | `stw [rs+disp], rd` | 16-bit little-endian store |
| `0x80` | `jmp imm` | `PC = imm` |
| `0x86` | `jz rd, imm` | jump if `rd == 0` |
| `0x8c` | `jnz rd, imm` | jump if `rd != 0` |
| `0x92` | `push rd` | `SP -= 2`, store word |
| `0x98` | `pop rd` | load word, `SP += 2` |
| `0xa1` | `call imm` | push `PC+4`, `PC = imm` |
| `0xa7` | `ret` | pop into `PC` |
| `0xb3` | `in rd` | `rd = getc(stdin)`, EOF reads as 0 |
| `0xb9` | `out rd` | `putc(rd & 0xff)` |
| `0xc2` | `sbox rd` | `rd = (S[rd >> 8] << 8) | S[rd & 0xff]` |
| `0xfe` | `halt` | stop |

Two are worth flagging. Arithmetic is written with the carry-free identity `x + y == (x ^ y) + 2*(x & y)`, so `add` compiles to that form and `sub` to `(a ^ ~b) + 2*(a & ~b) + 1` — neither looks like an addition at a glance. And `sbox` is a substitution instruction with no equivalent on any real CPU — the first hint that the ROM is doing block-cipher work.

### 6. Reimplementing the machine — validate on cycle counts

`asisarch.py` reimplements the machine in ~200 lines. The validation that matters is not "it produces output" but that it agrees with the original on both paths, **including the cycle count**:

```
$ echo 'ASIS{aaaaaaaa}' | python3 solution/asisarch.py
=== ASISARCH Secure Enclave v2.0 ===
Enter flag:
[-] Access Denied. Invalid flag.
[614 cycles]
```

Byte-identical to the reference binary. Matching text only proves the I/O path; matching the cycle count on both the accepting and rejecting paths exercises every instruction the ROM uses.

### 7. Disassembling the ROM (recursive descent)

Linear sweep is useless — the fetch stage rekeys per PC. `disasm.py` is a recursive-descent disassembler: start at the header's entry PC, follow `jmp`/`jz`/`jnz`/`call`, stop at `ret`/`halt`.

```
$ python3 solution/disasm.py > rom.asm
; entry 0x0000, image 0x7d8b bytes
; 7960 instructions reached
```

7960 instructions covering essentially the whole image — nothing is hidden behind computed jumps. The entry point reads clearly:

```
0000:  li r6, 0x7c60      ; banner
0004:  call 0x7c04        ; puts
0008:  li r6, 0x7c86      ; "Enter flag: "
000c:  call 0x7c04
0010:  li r6, 0xc000      ; input buffer
0014:  call 0x7c1c        ; readline -> length in r3
0018:  li r1, 0x002c
001c:  sub r1, r3
0020:  jnz r1, 0x7bf8     ; length != 44 -> reject
```

**The flag is exactly 44 bytes**, buffered at `0xc000` — 22 16-bit words.

### 8. The verification routine

Between the length check and the comparison sits one enormous basic block — `0x0024` to `0x7873`, **fully unrolled, no branches**. The instruction histogram is entirely data movement and arithmetic. Lifting it shows exactly **660 stores to the buffer, in three repeating shapes, 220 each — ten rounds of three passes over 22 words**:

| Pass | Operation |
|---|---|
| **Substitute** | `w[i] = S16(w[i]) XOR K[round][i]`, with 220 distinct constants |
| **Diffuse forward** | `w[i] = w[i] + w[i-1 mod 22] + 0x5a5a`, chained low to high |
| **Diffuse backward** | `w[i] ^= sigma(w[i+1]) XOR rol(sigma(w[i+2]), r)`, `sigma(x) = x XOR rol(x, 5) XOR rol(x, 11)` |

The forward pass propagates changes upward through the buffer, the backward pass propagates them downward, and the rotation amount `r` in the third pass increases each round. After two rounds every output word depends on every input byte, so guessing the flag piecewise is hopeless.

The comparison at `0x7874`-`0x7be7` is repeated 22 times:

```
li r6, 0xc022        ; a transformed word
ldw r3, [r6+0x0]
li r1, 0x7cdb        ; constant table
addi r1, 0x0058      ; ... at a shuffled offset
ldw r4, [r1+0x0]
addi r1, 0x0002
ldw r7, [r1+0x0]
xor r4, r7           ; expected = tbl[off] ^ tbl[off+2]
xor r3, r4
add r5, r3           ; accumulate the difference
...
jnz r5, 0x7bf8       ; any mismatch -> reject
```

The expected words are never stored in the clear: each is the XOR of two entries of a 176-byte table at `0x7cdb`, read at offsets that hop around the table. Differences are accumulated into `r5` rather than compared individually, so there is no early exit to time and no per-word oracle to attack.

### 9. Inverting the transform

The winning observation is that **the transform contains no branches**, so the sequence of buffer updates is identical no matter what the input is. That makes it possible to lift it once, symbolically, into a list of elementary steps.

`solve.py` walks the block a single time, tracking a symbolic expression per register instead of a value. Buffer loads produce the symbol `B[i]`, and each `stw` emits a step and resets that symbol — so every step is expressed against the *current* buffer contents rather than the original input:

```python
elif name == "ldw":
    sym[rd] = ("B", (a - BUF) // 2) if in_buffer(a) else ("C", word_at(a))
elif name == "stw":
    steps.append(((a - BUF) // 2, sym[rd]))
```

The result is 660 steps of the form `buf[i] <- f(buf[i], other words, constants)` with `f` built only from `xor`, `add`, `rol`, and `sbox`. Two properties make them trivially invertible:

- every step mentions its own target **exactly once** (asserted by the solver), so the occurrence can be isolated by peeling operations from the outside in;
- the other words a step reads are not modified by *that* step, so when replaying backwards their post-values are also their pre-values.

Inverting is then mechanical — undo `xor` with `xor`, `add` with subtraction, `rol` with `ror`, `sbox` with the inverse permutation:

```python
for i, e in reversed(steps):
    state[i] = invert(e, i, state[i], state)
```

Starting from the 22 expected words and running the steps backwards recovers the input directly. No brute force, no SMT solver, and the search space never enters into it.

```
$ python3 solution/solve.py
[+] lifted 660 elementary buffer updates
[+] expected words: 544c 15a0 eb44 09d6 b6ab 496e fd0a 3806 f1df 0913 ffd8 8549 debb 5400 261a 5185 a205 a0b8 be18 efff b9b9 e889
[+] flag: ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
[+] emulator says: ACCEPTED (8906 cycles)
```

### 10. Flag

Confirmed against the original binary, not just the reimplementation:

```
$ echo 'ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}' | ./qemu-asisarch -M asisboard -kernel challenge.rom -nographic
=== ASISARCH Secure Enclave v2.0 ===
Enter flag:
[+] Access Granted! Flag verified.
```

```
ASIS{M1ddL3_3nd14n_N1bbL35_M4k3_Q3MU_D122y!}
```

The flag describes its own encoding: the middle-endian nibble scramble on every immediate is exactly what makes the ROM undisassemblable until the fetch stage is understood.

### 11. Takeaway

- **Size is the first tell.** A 2.5 KB `.text` with a 2 KB pointer table in `.data.rel.ro` is an interpreter, and the dispatch table is the ISA. Do not start by reading the handlers — start by counting them.
- **Recover tables from relocations, not from a debugger.** In a PIE, a table of function pointers lives in `.rela.dyn`. Parsing it gives the opcode map statically, with no execution and no guessing about which entries are live.
- **Validate a reimplemented VM on cycle counts, not on output.** Matching text only proves the I/O path. Matching the cycle count on both the accepting and rejecting paths exercises every instruction the ROM uses.
- **Branch-free obfuscation defeats itself.** Unrolling the transform hides its structure from a reader, but it also removes every input-dependent decision — which is precisely what allows the operation sequence to be lifted once and inverted in closed form. A single data-dependent branch in that block would have forced a solver.

---

## LeakMeAk — z3 plus Unicorn against a non-injective hash

> *Flag:* `ASIS{haaducrcplmekhylrozcxyxzuizs}`
>
> *Prompt:* "In LeakMeAk, even the flag has trust issues."

### 1. Recon

```
$ file leakmeak.elf
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

$ strings leakmeak.elf | grep -Ei 'flag|access|asis|%127'
Enter Flag:
Access Denied!
ASIS{
Access Granted! Correct Flag.
%127s
ZZZZ<<<<
```

`main` reads `%127s` into a stack buffer, then verifies. Three cheap gates come first:

```asm
call strlen ; cmp rax, 0x22 ; jne DENIED     ; length must be 34
lea rsi,[ASIS{] ; mov edx,5 ; call strncmp   ; prefix "ASIS{"
cmp byte [rsp+0x81], 0x7d ; jne DENIED        ; suffix '}'
```

So the flag is `ASIS{` + **28 inner bytes** + `}`. Those 28 bytes are gathered onto the stack and fed to the real check.

### 2. The internal hash

The core is one heavily obfuscated function. Working through it, the 28 bytes are consumed **four at a time** as a big-endian word and folded into seven 32-bit dwords:

```
H[i] = (word_i * 0x9e3779b9) XOR mix_i          word_i = big-endian bytes[4i..4i+3]
```

`0x9e3779b9` is the golden-ratio constant, and `mix_i` is produced by a per-byte **state machine** — character-class counters, `> 'Y'` comparisons (`cmp r10b, 0x59`), and two small stack arrays. Empirically `H = word * const XOR mix` holds exactly; for a fixed prefix, `mix_i` depends only on the current four bytes (through low-bit masks and those comparisons), so it is low-entropy.

### 3. The acceptance conditions

The function never early-exits; it accumulates an error mask in `ecx` and, at the end, checks everything together:

- **`ecx == 0`** — the byte-processing state machine must never `or` an error bit (`0x1 / 0x2 / 0x4 / 0x10`) during the loop.
- **Seven cyclic equations** on the dwords, against two rodata tables (`tableA @0x204c`, `tableB @0x206c`):

    ```
    (ror(H[i % 7], 13) + H[i-1]) XOR tableB[i] == tableA[i]        for i = 1..7
    ```

- **A poly-33 hash** of the seven dwords equals `0xddaacf25`:

    ```
    edx = 0
    for h in H: edx = edx * 33 XOR h
    ```

- **Its 64-round remix** equals `0x376a3d36` — deterministic in the poly result, hence a redundant check.
- **Two low-bit checks** on an internal state array `s30`: `s30[0] & 3 == 1` and `s30[1] & 3 == 2`.

Only when all of these pass does it print `Access Granted! Correct Flag.`

### 4. "Trust issues" — the hash is not injective

`H[i] = word_i * const XOR mix_i` maps four bytes to a dword, but different `(word, mix)` pairs collide to the same `H`. Given a target `H[i]`, each candidate value of `mix_i` yields one `word_i = (H[i] XOR mix_i) * inv(const)`, so a single dword has several printable preimages — this is the leak the title winks at. What restores uniqueness is the rest: the `ecx` state machine and the `s30` checks couple the four-byte groups together, so only one full 28-byte string satisfies *everything*.

### 5. Stage 1 — the internal dwords, with z3

The seven cyclic equations are seven constraints on seven 32-bit unknowns. Feeding them to z3 (with `C[i] = tableA[i] XOR tableB[i]`), plus the poly-33 target as a consistency check, gives a **unique** solution:

```python
for i in range(1, 8):
    solver.add(RotateRight(H[i % 7], 13) + H[i - 1] == C[i])
edx = BitVecVal(0, 32)
for h in H:
    edx = edx * 33 ^ h
solver.add(edx == 0xddaacf25)
```

```
H = [0x0cf6a545, 0x89397a88, 0x54c2caf9, 0xab02cb0c,
     0xcda7368c, 0xb2fab02b, 0xf6c4d21a]
```

### 6. Stage 2 — a Unicorn oracle for the mix

Rather than fully reverse the tangled `mix` state machine by hand, `solve.py` emulates the check function with **Unicorn**. Entering just past the length/prefix checks (`0x115e`) with the flag written to the stack buffer, it hooks the dword store (`mov [rsp+4*rbp+0x10], edx` at `0x13c2`) to read `(H_i, mix_i, ecx_i)` on every iteration, and hooks the two `puts` sites (`0x147e` granted / `0x14bb` denied) for the verdict. The emulation is cycle-accurate against the real binary (~0.16 ms per run) and confirms `H = word * const XOR mix`.

### 7. Stage 3 — invert and DFS

For each 4-byte group `i`, given the target `H[i]`:

- the oracle samples the small set of `mix_i` values reachable for the current prefix;
- each `mix` inverts to `word_i = (H[i] XOR mix) * inv(0x9e3779b9)`, and the printable ones whose emulated `H` matches with a clean `ecx` are the candidates.

A DFS over these (typically one or two per position) keeps only the completed string the checker **grants**. The cross-position `ecx`/`s30` constraints eliminate every collision but one:

```
$ python3 solution/solve.py
[+] internal dwords H = ['0xcf6a545', '0x89397a88', ...]
[i=0]                           '' + 'haad'
[i=1]                       'haad' + 'ucrc'
 ...
[+] 1 string(s) accepted by the checker
[+] flag: ASIS{haaducrcplmekhylrozcxyxzuizs}
```

### 8. Flag

```
ASIS{haaducrcplmekhylrozcxyxzuizs}
```

Confirmed against the live service — `Access Granted! Correct Flag.`, and any single-byte change gives `Access Denied!`. The flag reads as random rather than as leetspeak; that is a property of the challenge (a lossy checker with exactly one printable fixed point), not a missed decode — the exhaustive search finds this and only this.

### 9. Takeaway

- **A checker that accumulates errors and compares once has no timing oracle** — you cannot peel it character by character. The way in is to model the whole predicate, and z3 plus an emulator do that without hand-reversing every branch.
- **Emulate the parts that resist static reading.** The `mix` state machine is genuinely awkward; instead of transcribing it, Unicorn *is* the ground truth, and one hook on the dword store turns it into an exact oracle.
- **A lossy hash plus side constraints can still be unique.** Non-injectivity gives collisions per dword, but the state-machine and low-bit checks couple the groups; enumerating the small candidate tree and asking the checker for the verdict collapses it to one answer.
- **Trust the search, then trust the target.** The flag looks like noise, which invites second-guessing — but the enumeration is exhaustive and the live remote confirms it, so the odd-looking string is the intended one.

---

## Cross-cutting notes

Both challenges reward the same discipline in two very different flavours:

- **Recover before you read.** ASIS Arch's ISA lives in the ELF's relocation table, not in the handlers. LeakMeAk's `H = word * const XOR mix` relation is a static observation you can make from a couple of Unicorn traces, without transcribing the `mix` state machine at all. The static recovery step is what makes the subsequent work small.
- **Reimplement and diff.** ASIS Arch's cycle-count check catches every instruction the ROM uses; LeakMeAk's Unicorn oracle confirms `H = word * const XOR mix` on real inputs. In both cases the reimplementation is *the* validator — matching output alone is not evidence.
- **Prefer static structural reasoning to symbolic execution.** ASIS Arch's transform is 660 branch-free stores; symbolic lifting collapses a would-be SMT problem to a linear list of trivially invertible operations. LeakMeAk's 7 cyclic equations pin the internal dwords in one z3 call. Neither challenge needed a solver that ran for more than seconds.
- **Trust the AEAD-style pass/fail, not intermediate values.** LeakMeAk's `puts` verdict is the check; ASIS Arch's `Access Granted!` is the check. Both give a free proof of correctness that closes out any lingering ambiguity from the reversing.

## Frequently asked questions

### What is ASIS CTF Quals 2026?

ASIS CTF Quals 2026 is the qualifier round for the ASIS CTF Finals, run annually by the ASIS team. The event is Jeopardy-style with the traditional five tracks. Flags use the `ASIS{...}` prefix. The consolidated writeup repository lives at [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026).

### Why does ASIS Arch call itself qemu-asisarch when it isn't QEMU?

The binary name and `-M asisboard -kernel challenge.rom -nographic` command-line are QEMU-shaped by design — they steer readers toward reading a real emulator (large `.text`, JIT, thread pool) rather than a 2.5 KB interpreter dispatched through a 2 KB function-pointer table. The very first tell that it is not QEMU is `-rwxr-xr-x 14656 qemu-asisarch` — QEMU is measured in megabytes.

### Why can't you just linearly disassemble the ROM?

Because every four-byte instruction is decoded through a keystream `k = rol16(((PC XOR 0x9e37) * 0x1039 + 0x79b9), 5)` derived from the PC. The same bytes at PC `0x0000` and PC `0x0004` produce different opcodes, register fields, and immediates. A linear sweep from any offset resynchronises to plausible-looking but wrong instructions, and never recovers. A recursive-descent disassembler starting at the header's entry PC (itself scrambled through the same nibble-swap) is the only way to reach the 7960 live instructions.

### How do you recover the opcode table without executing the binary?

The dispatch table is in `.data.rel.ro`, which is zero-filled on disk in a PIE. The values are supplied at load time by `R_X86_64_RELATIVE` relocations in `.rela.dyn`. Parsing `.rela.dyn` gives you the mapping `opcode -> handler_offset` directly, statically, and marks the 26 live opcodes vs. the 230 illegal ones. `isa.py` does this in about 40 lines.

### Why does the ROM's transform have 660 stores exactly?

Ten rounds of three passes over 22 16-bit words = `10 * 3 * 22 = 660`. The three passes per round are Substitute (`w[i] = S16(w[i]) XOR K[round][i]`), Diffuse forward (`w[i] = w[i] + w[i-1 mod 22] + 0x5a5a`), and Diffuse backward (`w[i] ^= sigma(w[i+1]) XOR rol(sigma(w[i+2]), r)` with `sigma(x) = x XOR rol(x, 5) XOR rol(x, 11)`). The whole basic block is fully unrolled and branch-free, which is what allows a single symbolic lift plus reverse replay to invert it in closed form.

### Why is LeakMeAk's flag random-looking?

Because the acceptance predicate is a lossy hash plus a set of side-constraints, and the *only* 28-byte string of printable characters that satisfies all of them together is `haaducrcplmekhylrozcxyxzuizs`. The challenge was written to demonstrate that a non-injective hash with tight side constraints still has a unique preimage even when the preimage is not leetspeak. The exhaustive DFS across `(mix, word)` candidates confirms it, and the live remote confirms it again with `Access Granted!`.

### Why use both z3 and Unicorn on LeakMeAk?

They solve different sub-problems. **z3** pins the seven internal dwords `H[0..6]` uniquely from the seven cyclic equations `(ror(H[i%7], 13) + H[i-1]) XOR tableB[i] == tableA[i]` plus the poly-33 hash target — that is a self-contained arithmetic-over-BitVec problem, ideal for z3. **Unicorn** is the ground-truth oracle for the `mix` state machine, which involves stack arrays, character-class counters, and comparisons that are genuinely awkward to transcribe. One hook on the dword store gives you `(H, mix, ecx)` on every iteration in ~0.16 ms per full run. Using each tool for the sub-problem it fits keeps the solver short.

### Could you solve ASIS Arch with symbolic execution instead of lifting?

You could, but you would not need to — the branch-free transform makes lifting a strictly better fit. Symbolic execution treats every buffer update as a new constraint over the input bytes, and after ten rounds the constraint expression per word is a large tree. Lifting emits a *list* of trivially invertible steps, and the invert-and-replay is just 660 arithmetic operations. When the target is branch-free, "lift + reverse" beats "SMT" in both wall clock and clarity.

### Could you solve LeakMeAk with just angr or KLEE?

Probably yes — the whole predicate is symbolic-executable — but the running time is much worse. The `mix` state machine involves many `> 'Y'` comparisons and low-bit masks, each of which forks the symbolic state. The z3-plus-Unicorn hybrid keeps everything concrete except the seven internal dwords, which are the only genuinely symbolic quantities in the problem.

### Where can I find the source and solvers?

Full challenge binaries, ROM, solvers, and per-challenge notes are at [Abdelkad3r/ASIS-CTF-Quals-2026/Rev](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Rev). Each challenge has its own `challenge/`, `solution/`, `writeup.html`, and per-challenge `README.md`.

### What broader lesson does the ASIS 2026 Reverse track teach?

**Reverse engineering is model-building.** Neither challenge yields to reading assembly top-to-bottom; both yield to reimplementing the target and diffing the reimplementation against ground truth. ASIS Arch teaches recovering an ISA from ELF metadata and lifting a branch-free transform symbolically; LeakMeAk teaches wiring an SMT solver together with an emulator to attack a mixed arithmetic-plus-state-machine predicate. In both cases the reversing that mattered was the reversing you didn't have to do — the parts you could recover statically or emulate directly.

## Closing notes

The ASIS 2026 Reverse track is compact — two challenges — but broad in surface. ASIS Arch covers custom instruction-set design, ELF-metadata-driven recovery, cycle-accurate reimplementation, symbolic lifting of branch-free code, and closed-form inversion. LeakMeAk covers non-injective hash design, cyclic constraint systems, static-vs-dynamic partitioning of a reversing problem, and DFS across a constrained candidate space.

Full source, solvers, and per-challenge notes are in the [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026) repository. The [Misc writeup](/ctf-writeups/asis-ctf-quals-2026-misc-writeup/) and [Crypto writeup](/ctf-writeups/asis-ctf-quals-2026-crypto-writeup/) cover the other tracks solved in this event.
