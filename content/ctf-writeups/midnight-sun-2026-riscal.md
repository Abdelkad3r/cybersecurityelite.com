---
title: "Midnight Sun CTF 2026: riscal Writeup — A RISC-V Binary That Stores Its Flag in .rodata"
slug: "midnight-sun-2026-riscal"
description: "Midnight Sun CTF 2026 riscal walkthrough — RISC-V 64-bit ELF that validates input against a hardcoded string. The string is sitting in .rodata in plaintext, so `strings | grep midnight` solves the challenge without ever opening a disassembler."
date: 2026-05-16T12:45:00Z
lastmod: 2026-05-16T12:45:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["midnight-sun", "midnight-sun-ctf", "reverse engineering", "risc-v", "strings", "low-hanging fruit"]
series: ["Midnight Sun CTF 2026 Quals"]
keywords: ["midnight sun ctf 2026 riscal writeup", "risc-v ctf reverse engineering", "strings ctf flag", "rodata flag plaintext"]
toc: true
cover:
  image: "/images/midnight.png"
  alt: "Midnight Sun CTF 2026 riscal writeup"
---

{{< ctf-meta platform="Midnight Sun CTF 2026 Quals" difficulty="Trivial" os="RISC-V 64-bit Linux" skills="strings(1), reading the rules" >}}

`riscal` is the kind of challenge that gets harder the more you respect the category label. *"Reverse engineering"* + *"RISC-V"* primes you to spin up a cross-disassembler, set up a `qemu-user` static binary, learn the RV64 calling convention, and start manually annotating decompilation. The intended solve is `strings`.

Source: [Abdelkad3r/midnight-sun-ctf-2026-quals · riscal/](https://github.com/Abdelkad3r/midnight-sun-ctf-2026-quals/tree/main/riscal).

## The Challenge

> The name "riscal" is a play on RISC-V + "rascal."

A single RISC-V 64-bit ELF that takes user input and validates it as a flag.

## Solution — Check `strings` Before Anything Else

The very first recon command on any reverse-engineering challenge is `strings | grep` for the flag format. It costs 50 milliseconds and rules out the "flag is literally sitting in .rodata" case before any time is invested in proper analysis.

{{< terminal title="kali ~/ctf/midnight-sun/riscal" >}}
$ file riscal
riscal: ELF 64-bit LSB executable, UCB RISC-V, version 1 (SYSV), dynamically linked, ...

$ strings riscal | grep midnight
midnight{RISCV_1S_4_34zy_1S4_70_unDeRst4Nd!!}
{{< /terminal >}}

That's the flag. Submitting it solves the challenge.

A quick `objdump -d` confirms why this works: the binary simply does a `strcmp` against the hardcoded `.rodata` string. No XOR, no packing, no obfuscation, no runtime decryption. The flag is the literal target of the comparison.

## Flag

```
midnight{RISCV_1S_4_34zy_1S4_70_unDeRst4Nd!!}
```

The flag content — *"RISC-V is a easy ISA to understand"* — is itself a hint that the challenge is meant to be approachable. The category framing was the misdirection.

## Lessons learned

1. **`strings | grep <flag_format>` is the literal first recon step on every RE challenge.** This is the *first* command, not the last. Most "easy" rev challenges are solved by it, and even the genuinely hard ones often have a partial hint in plaintext.

2. **Don't let the architecture label dictate your effort.** "RISC-V" sounds intimidating, but unfamiliar instruction sets only matter when you have to *understand* the code path. If the flag is a static string, the architecture is irrelevant — the ELF parser still finds it.

3. **The CTF category label is a frame, not a contract.** A challenge filed under "reverse engineering" can be solved with `strings`. A challenge filed under "stego" can be solved with a hex editor. Spending too much time matching the technique to the category's expectation gets in the way of just reading the input.

4. **Tools work cross-architecture more often than you'd think.** `strings`, `file`, `readelf`, `objdump -d`, and `binwalk` all handle RISC-V (and ARM, MIPS, PowerPC) just fine. Don't reach for a special toolchain until the basic toolchain returns nothing useful.

## References

- [RISC-V Instruction Set Manual](https://riscv.org/technical/specifications/)
- [`strings(1)`](https://man7.org/linux/man-pages/man1/strings.1.html) — the most underrated CTF tool
- Source writeup: [midnight-sun-ctf-2026-quals/riscal/README.md](https://github.com/Abdelkad3r/midnight-sun-ctf-2026-quals/blob/main/riscal/README.md)
