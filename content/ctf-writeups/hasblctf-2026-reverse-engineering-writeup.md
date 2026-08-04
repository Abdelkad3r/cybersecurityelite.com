---
title: "HASBLCTF 2026 Reverse Engineering: All 4 Challenges Solved"
slug: "hasblctf-2026-reverse-engineering-writeup"
description: "HASBLCTF 2026 reverse engineering writeup — all 4 rev challenges solved: Go binary triage, anti-debug bypass, custom protocol, game-logic RE."
date: 2026-06-01T03:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "hasblctf"
  - "hasbl ctf"
  - "ctf 2026"
  - "reverse engineering"
  - "golang reverse engineering"
  - "anti-debug"
  - "windows reverse engineering"
  - "binary protocol"
  - "game reverse engineering"
  - "static analysis"
  - "elf reverse engineering"
  - "pe reverse engineering"
series: ["HASBL CTF 2026"]
keywords:
  - "hasblctf 2026 writeup"
  - "hasblctf writeup"
  - "hasbl ctf 2026"
  - "hasbl ctf reverse engineering"
  - "hasblctf rev challenges"
  - "hasblctf baby-go writeup"
  - "hasblctf debugme writeup"
  - "hasblctf pr0t0c0l1337 writeup"
  - "hasblctf pamukthecat writeup"
  - "golang reverse engineering ctf"
  - "go binary debug info ctf"
  - "windows anti-debug ctf"
  - "peb beingdebugged"
  - "ntcreatethreadex anti-debug"
  - "custom binary protocol reverse engineering"
  - "game logic reverse engineering ctf"
toc: true
cover:
  image: "/images/articles/hasblctf-2026-reverse-engineering-writeup.png"
  alt: "HASBLCTF 2026 reverse engineering writeup — all 4 rev challenges (baby-go, DebugMe, Pr0t0c0l1337, PamukTheCat)"
---

{{< ctf-meta platform="HASBL CTF 2026" difficulty="Mixed (Easy → Medium)" os="Jeopardy — Reverse Engineering" skills="Go binary triage, static-only flag recovery, PE anti-debug bypass (PEB.BeingDebugged, x64dbg process scan, NtCreateThreadEx), custom binary protocol parsing, game-logic reverse engineering" >}}

This **CyberSecurity Elite** reverse engineering writeup covers **HASBL CTF 2026**, a multi-category jeopardy event spanning Reverse Engineering, Pwn, Web, and Forensics. It is dedicated to the **Reverse Engineering track** — the four rev challenges (`baby-go`, `DebugMe`, `Pr0t0c0l1337`, `PamukTheCat`) were all solved, and each one teaches a different reverse-engineering skill: static-only recognition on a Go binary with debug symbols, anti-debug bypass on a Windows PE, custom binary-protocol parsing on a Linux PIE, and game-logic reverse engineering on a JRPG-shaped crackme.

This is the master writeup for the rev track. Each challenge below covers the binary's structure, the bug or hidden constant, and the recovered flag. Full per-challenge reproductions — solver scripts, disassembly listings, and PEB/anti-debug primitive notes — live in the source repository: [Abdelkad3r/hasblctf-2026](https://github.com/Abdelkad3r/hasblctf-2026).

## The reverse track at a glance

| Challenge       | Target                                          | Core technique                                                                          |
|-----------------|-------------------------------------------------|-----------------------------------------------------------------------------------------|
| baby-go         | 2.1 MB Linux x86-64 Go ELF, **not stripped**    | Recognise a hard-coded base64 constant as the encoded flag; no actual reversing needed |
| DebugMe         | 67 KB Win64 PE32+ MSVC Debug build              | Three anti-debug primitives are decorative — the cipher bytes + XOR key 0x4A are literals |
| Pr0t0c0l1337    | Linux x86-64 PIE, stripped, ~14 KB, remote nc   | Reverse a 5-field custom binary protocol; magic 0x2752 + 144 × 0x84 + "root" + cmd 0x03 |
| PamukTheCat     | Linux x86-64 PIE, stripped, ~14 KB, remote nc   | Hidden menu choice `10` sets `Player.Damage = 99999`; gated on XP ≥ 18 and Coins > 599   |

## Methodology — a reverse-engineering checklist

The classic *recon → enumeration → exploitation → flag* framework still applies, but for reverse-engineering challenges specifically there's a more useful four-step shape:

1. **Triage.** `file`, `strings`, `nm`, `readelf` / `dumpbin`. Is it stripped? What toolchain built it? Are there embedded resources or PDBs? `baby-go` is a 30-second triage win because the Go binary ships with full debug info — `main.main` is right there.
2. **Static analysis.** Find `main`, follow control flow, identify the **check routine** — the function that decides whether the input is correct. In `DebugMe` the check routine is also the *constant table*, which is why static recovery beats running the binary.
3. **Dynamic analysis.** Run it under a debugger or emulator when statics fall short. Hook syscalls, set breakpoints on `strcmp`/`memcmp`, watch memory writes. `PamukTheCat` actively benefits from dynamic exploration of the menu — you discover choice `10` by *trying* it.
4. **Inversion or extraction.** Once you understand the check, either invert it algebraically (XOR with the key in `DebugMe`), forge the input it accepts (the binary protocol in `Pr0t0c0l1337`), or read the flag straight out of the constants (`baby-go`).

{{< callout type="info" title="When statics beat dynamics" >}}
Three of the four HASBL CTF rev challenges fall to **pure static analysis**. The exception is `PamukTheCat`, where the hidden menu choice is discoverable statically (it's a first-class case in the switch) but the XP/Coin gates are easier to reach by playing the game than by simulating the RNG. Whenever a challenge ships with debug info or unstripped symbols (`baby-go`, `DebugMe`), assume static will be the fastest path.
{{< /callout >}}

---

## baby-go — the flag is the constant

```bash
$ file main
ELF 64-bit LSB executable, x86-64, statically linked,
with debug_info, not stripped
```

A Go binary with **full debug info preserved**. `main.main` is right there with its real symbol name. No anti-debug, no packing, no runtime key derivation.

`sym.main.main` is a 32-iteration loop that, for each byte of a hard-coded constant at `.rodata:0x004baf62`, calls:

```go
fmt.Fprintf(os.Stdout, "Did you do your homework?!?!?%x!?!\n", byte)
```

The constant is **`SEFTQkx7QjRCWV9HMEw0TkdfMTExMX0=`** — 32 chars, ends in `=`, only alphanumerics. Classic base64. Decode:

```bash
$ python3 -c "import base64; print(base64.b64decode('SEFTQkx7QjRCWV9HMEw0TkdfMTExMX0='))"
b'HASBL{B4BY_G0L4NG_1111}'
```

The challenge title is *baby-go* and the leet decode of the flag reads **"BABY GOLANG 1111"** — self-referential.

**Flag:** `HASBL{B4BY_G0L4NG_1111}`

**Reverse-engineering takeaway:** any binary that *prints* a constant byte-by-byte without comparing it to input has already given up the secret. The "challenge" is recognising that no comparison instruction exists — the constant is the answer, not the question. Always check whether the suspicious data is *used as a key* or just *displayed*.

**Defender takeaway:** Go binaries ship with full debug info by default (`-ldflags="-s -w"` strips it). Any production binary that wants to resist reverse-engineering should strip at link time and consider building with `goreleaser`'s default `--trimpath` flags so file-system paths don't leak.

---

## DebugMe — three real anti-debug primitives, fully decorative

```bash
$ file DebugMe.exe
PE32+ executable (console) x86-64, for MS Windows
```

The binary's startup message reads:

```text
checking if there's any debuggers...
[-] Attach a debugger! Your goal is debugging me!
```

The story is that the flag is only revealed after defeating three anti-debug checks. All three are real and would trap a dynamic-only reverser — but the encrypted flag bytes and the single-byte XOR key are both static literals visible in the disassembly. The binary never has to run.

### Anti-debug primitive #1 — `PEB.BeingDebugged`

A hand-rolled `IsDebuggerPresent` that reads the PEB directly so an API hook on `kernel32!IsDebuggerPresent` won't catch it:

```nasm
xor   rcx, rcx
mov   rax, qword [gs:rcx + 0x60]   ; PEB
movzx eax, byte [rax + 2]          ; PEB.BeingDebugged
ret
```

### Anti-debug primitive #2 — scan for `x64dbg.exe`

`Process32First` / `Process32Next` via Toolhelp32 snapshot, walking the process list to look for `x64dbg.exe`. Bypassing this dynamically requires renaming the debugger; bypassing it statically is free.

### Anti-debug primitive #3 — `NtCreateThreadEx` with `HideFromDebugger`

A worker thread is spawned via `ntdll!NtCreateThreadEx` with the `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER` flag. Debuggers attached via `DebugActiveProcess` never see this thread's exceptions or DLL events.

### Why all three fall to one `python` line

The flag-printing thread starts by initialising a 34-byte stack buffer with **thirty-four `mov byte [rbp+disp8], imm8` instructions** at consecutive displacements `rbp+0x08..rbp+0x29`, then runs:

```nasm
xor eax, 0x4A
```

over each byte before `puts`-ing it. Both the cipher bytes and the key are visible in `objdump -d`. XOR them:

```python
cipher = bytes.fromhex("02 0b 19 08 06 31 33 7a 3f 15 2e 79 28 3f 2d 2d "
                       "79 2e 15 27 79 3a 38 79 71 53 7d 7d 33 15 2d 7a 7a 2e".replace(" ", ""))
flag = bytes(b ^ 0x4A for b in cipher)
# → HASBL{y0u_d3bugg3d_m3_pr377y_g00d}
```

**Flag:** `HASBL{y0u_d3bugg3d_m3_pr377y_g00d}`

**Reverse-engineering takeaway:** anti-debug primitives only protect *runtime* state. If the secret material is statically embedded as instruction immediates, the binary is just an obfuscated wrapper around a constant table. The MSVC Debug build of `DebugMe` is recognisable by the `_RTC_*` runtime checks, the `0xCCCCCCCC` stack-frame fills, and the embedded PDB path (`C:\Users\Terry\Desktop\yks_soru_yazm\rev\DebugMe\x64\Debug\DebugMe.pdb`).

**Defender takeaway:** anti-debug should not be the *only* layer. Pair it with at minimum a runtime decrypt step that depends on a value not present in the binary — a server-issued token, a hardware fingerprint, anything. Three anti-debug techniques and a 34-byte XOR table is a 5-minute defeat.

---

## Pr0t0c0l1337 — custom binary protocol with one wrong assumption

Remote service at `nc 34.77.68.154 10102`. The binary prompts "Say the magic words:" and reads up to 256 bytes. Whatever you send has to satisfy a hand-rolled binary protocol.

The parser at `.text:0x11e5` accepts a packet with this structure:

```text
offset  length  value          meaning
------  ------  -------------  ---------------------------------------
0       2       52 27          magic header (uint16 LE == 0x2752)
2       144     84 × 144       padding — exactly 0x90 (=144) bytes of \x84
146     4       72 6F 6F 74    keyword "root"     ← NOT "rot"
150     1       cmd            00=pong, 01=msg, 02=exit, 03=flag
```

The challenge title is the giveaway — *"activate the **root** protocol"*. The four-byte keyword is `root` (4 bytes), not `rot` (3 bytes), because the parser reads exactly 4 bytes at offset 146 and `memcmp`s them against the literal `"root"`.

### Strings recon

```bash
$ strings -n 6 main
Say the magic words:
Invalid Magic Header: 0x%04x
Invalid payload! j = %d
pong
You're the only person that can help yourself.
./flag.txt
Couldn't open up the flag.txt file. Contact to an administrator!
Congratulations! Here's your flag: %s
Invalid command!
```

Five response paths but only three are reachable through the protocol: `Invalid Magic Header`, `Invalid payload`, and the success branch. Both `Invalid command!` and the puts-only handlers (`pong`, `You're the only person...`) are wired in but require a valid magic + padding + keyword first.

### The exploit payload

```python
import socket
p  = b"\x52\x27"          # magic 0x2752 LE
p += b"\x84" * 144        # padding
p += b"root"              # keyword
p += b"\x03"              # cmd = flag

s = socket.create_connection(("34.77.68.154", 10102))
s.recv(64)                # banner
s.sendall(p + b"\n")
print(s.recv(256).decode())
# Congratulations! Here's your flag: HASBL{TH3_PR0T0C0L_1337_IS_ACTIVATED}
```

**Flag:** `HASBL{TH3_PR0T0C0L_1337_IS_ACTIVATED}`

**Reverse-engineering takeaway:** when a binary's `strings` output contains *more response messages than the protocol seems to support*, the unreachable strings are usually the success path — and the parser between them is the reversing target. The trap here is the keyword length — `rot` is a famous protocol fragment from `rot13`, easy to type by reflex, and it produces *exactly the same error message* as any other wrong payload (`Invalid payload! j = %d`). Read four bytes, not three.

**Defender takeaway:** custom binary protocols are no harder to reverse than well-known ones; if anything, they're *easier* because the parser is in front of you and `strings` enumerates every error branch. If your service needs an authentication challenge, sign tokens, don't invent a packet shape and call it a secret.

---

## PamukTheCat — hidden menu choice on a JRPG crackme

Remote service at `nc 34.77.68.154 10103`. The story is a JRPG about a cat (Pamuk) who puts on a magical red hoodie and faces the boss "Homework" while her hacker brother sleeps. Menu:

```text
1  Fight Homework
2  Market
3  Random enemy
4  (Exit / give up)
```

Homework's HP is 9337 and the only visible weapon (Wooden sword, 100 coins, Damage = 20) requires 467 perfect hits to kill it, which the fight loop doesn't allow.

### The hidden cheat

```nasm
scanf("%u", &choice)
cmp eax, 0xA            ; 10
je  .cheat              ; hidden menu choice
ja  .unknown
cmp eax, 3
je  .random_enemy
ja  .unknown
cmp eax, 1
je  .fight_homework
cmp eax, 2
je  .market
jmp .unknown
```

Choice `10` is not on the printed menu but it's a first-class case in the switch. The handler:

```nasm
.cheat:
  movss   xmm0, [Player+4]              ; XP
  cvtss2sd xmm1, xmm0
  movsd   xmm0, qword [.rodata + 18.0]
  comisd  xmm0, xmm1                    ; if 18.0 < XP
  jbe     .gate_xp_ok
  jmp     .denied
.gate_xp_ok:
  cmp     dword [Player+8], 599         ; Coins > 599
  jbe     .denied
  mov     dword [Player+0xC], 99999     ; Player.Damage = 99999
  jmp     .menu
```

So the path is:

1. **Market** → buy Wooden sword (100c → Damage = 20).
2. **Grind** ~7–10 random fights, pacing one per ~1.1 s so `srand(time(NULL))` reseeds and you don't keep drawing the same enemy.
3. Once `XP ≥ 18.0` and `Coins > 599`, send `10`. The hidden case sets `Player.Damage = 99999`.
4. Send `1`. Pamuk attacks first; 99999 ≥ 9337 (Homework's HP); the boss dies before retaliating; the server prints the flag.

**Flag:** `HASBL{P4MUK_TH3_M4ST3R_H4CK3R}`

**Reverse-engineering takeaway:** when a menu's printed options don't satisfy the visible win condition, **the dispatcher's switch contains the missing option**. A JRPG that hands you a 20-damage sword and a 9337-HP boss is mathematically telling you a hidden option exists. Read every case in the switch, not just the ones on the screen.

**Defender takeaway:** "hidden menu" is the cheat-code design pattern from 30 years of console games — and it survives in modern crackme challenges precisely because most reversers stop at the visible UI. If you ship a binary that has unprinted menu options, assume players will find them; if those options are gated by trivial state checks (`XP >= 18.0`), assume they'll satisfy the gates.

---

## Lessons learned — what HASBLCTF 2026 rev rewarded

Four patterns recur across these four reverse-engineering solves; they generalise to most RE-track CTF work:

1. **Strip your symbols.** `baby-go` and `DebugMe` both ship with full symbol information — Go's `main.main` and MSVC's embedded PDB path turn 15-minute reverse jobs into 30-second triage wins. The fix is one linker flag.
2. **Anti-debug is theatre when constants are static.** `DebugMe` stacks PEB.BeingDebugged + process-scan + NtCreateThreadEx, then keeps the cipher bytes and XOR key as `mov` immediates in the worker thread's prologue. Three runtime defences cannot protect a value that exists at compile time.
3. **Read every code path your `strings` output names.** `Pr0t0c0l1337` exposes five response strings, but only three are reachable through obvious paths; the missing two are the success branches. `PamukTheCat`'s switch handles a tenth case the menu never prints. The disassembler always knows more than the user-facing UI.
4. **The flag is often the punchline.** *BABY GOLANG 1111*. *you debugged me pretty good*. *THE PROTOCOL 1337 IS ACTIVATED*. *PAMUK THE MASTER HACKER*. When you decode something that reads as English commentary on what you just did, you've solved it.

## Source repository

Every per-challenge writeup includes solver scripts, full disassembly listings, and (for `DebugMe`) the PEB / anti-debug primitive notes:

**Repo:** [github.com/Abdelkad3r/hasblctf-2026](https://github.com/Abdelkad3r/hasblctf-2026)

The repo also contains the pwn (`baby-bufferoverflow`, `candy-store`, `baby-shellcoder`), forensics (`Quick Response`, `Logo`, `Digits`, `pamuk`, `magic-numbers`), and web (`T/I Forum`, `Anatolian Atlas`) writeups from the same event. This article is scoped to the rev category only.

If you're building reverse-engineering practice plans from this writeup, the four challenges form a clean progression: **baby-go (recognition) → Pr0t0c0l1337 (protocol parsing) → DebugMe (anti-debug bypass) → PamukTheCat (dynamic state + hidden control flow)**. That order maps to the standard *static → dynamic* reversing curriculum.

{{< faq >}}
[
  {
    "q": "What is HASBL CTF 2026?",
    "a": "HASBL CTF 2026 is a multi-category jeopardy-style capture-the-flag competition covering Reverse Engineering, Pwn, Web, and Forensics. The flag prefix is HASBL{...} for every challenge. This writeup is dedicated to the Reverse Engineering track only."
  },
  {
    "q": "How many reverse engineering challenges does HASBL CTF 2026 have?",
    "a": "Four reverse engineering challenges: baby-go, DebugMe, Pr0t0c0l1337, and PamukTheCat. All four were solved and are documented in this writeup. The full event also includes pwn, web, and forensics tracks covered separately in the source repository."
  },
  {
    "q": "Where can I find the HASBL CTF 2026 reverse engineering solver scripts?",
    "a": "All four per-challenge writeups, solver scripts, and disassembly listings live in the source repository at github.com/Abdelkad3r/hasblctf-2026 under the rev/ directory. Each challenge has its own README and standalone solver."
  },
  {
    "q": "How is the HASBL CTF baby-go challenge solved?",
    "a": "The binary is a Go ELF with full debug info preserved. main.main contains a 32-iteration loop that prints each byte of a hard-coded constant at .rodata:0x004baf62. The constant SEFTQkx7QjRCWV9HMEw0TkdfMTExMX0= is base64 — decode it to get HASBL{B4BY_G0L4NG_1111}. No actual reverse engineering required, just recognition that the program never compares input to anything."
  },
  {
    "q": "How does the DebugMe anti-debug bypass work?",
    "a": "The binary uses three anti-debug primitives: PEB.BeingDebugged read via gs:[0x60], a process-list scan for x64dbg.exe via Toolhelp32 snapshot, and NtCreateThreadEx with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER. All three are runtime defences and don't protect static constants. The 34-byte cipher and the XOR key 0x4A are both mov-immediate instructions in the worker thread. Recover statically by XOR-ing the 34 bytes with 0x4A — flag is HASBL{y0u_d3bugg3d_m3_pr377y_g00d}."
  },
  {
    "q": "What is the Pr0t0c0l1337 packet format?",
    "a": "A 151-byte custom binary protocol: 2-byte magic header 0x2752 little-endian (bytes 52 27), 144 bytes of padding all 0x84, 4-byte keyword 'root' (not 'rot'), and a 1-byte command. Command 0x03 returns the flag. Concatenating \\x52\\x27 + \\x84*144 + 'root' + \\x03 over the netcat connection yields HASBL{TH3_PR0T0C0L_1337_IS_ACTIVATED}."
  },
  {
    "q": "How is the PamukTheCat boss defeated?",
    "a": "The menu shows choices 1-4 but the switch handler accepts choice 10 as well — a hidden cheat that sets Player.Damage to 99999 if Player.XP is at least 18.0 and Player.Coins is greater than 599. Buy a Wooden sword from the market, grind random encounters to satisfy both gates, send choice 10, then fight Homework. With 99999 damage Pamuk one-shots the 9337-HP boss before it retaliates. Flag is HASBL{P4MUK_TH3_M4ST3R_H4CK3R}."
  },
  {
    "q": "Are HASBL CTF reverse challenges beginner-friendly?",
    "a": "Yes. baby-go is recognisable in under a minute (the flag is a base64 string in the data section). Pr0t0c0l1337 requires reading one parser function. DebugMe needs comfort with Windows PE format and PEB internals but the actual flag-recovery is a one-liner XOR. PamukTheCat is the most advanced — it teaches dynamic state exploration — but is still approachable. The four challenges form a clean static-to-dynamic learning progression."
  },
  {
    "q": "What tools should I use for HASBL CTF reverse engineering?",
    "a": "For static analysis: file, strings, nm, objdump, radare2 or Ghidra. For Go binaries specifically: go-symbol-recovery or built-in nm output. For PE inspection: PE-bear or rabin2. For dynamic analysis on Linux remotes: a netcat client is sufficient for Pr0t0c0l1337 and PamukTheCat. None of the four reverse challenges require commercial tooling — radare2 + Python handles every step."
  },
  {
    "q": "What is the key reverse-engineering lesson from HASBLCTF 2026?",
    "a": "Anti-debug is theatre when constants are static. DebugMe demonstrates this perfectly — three independent runtime defences cannot protect cipher bytes that exist as mov-immediate instructions in the disassembly. Always check whether the secret material is computed at runtime or just decorated by runtime checks. If it's static, statics win."
  }
]
{{< /faq >}}
