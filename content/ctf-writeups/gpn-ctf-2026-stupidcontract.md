---
title: "GPN CTF 2026 — Stupidcontract: Patched eBPF Verifier + Signed-Cmp OOB"
slug: "gpn-ctf-2026-stupidcontract"
description: "GPN CTF 2026 Reverse: a custom kernel strips BPF verifier bounds checks. A signed-comparison eBPF program writes outside the map, clobbers SUCCESS[0], and lights the flag path."
date: 2026-06-07T18:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "stupidcontract"
  - "reverse engineering"
  - "ebpf verifier"
  - "bpf adjust_end"
  - "kernel patch"
  - "signed comparison bypass"
  - "rust aya"
  - "bzimage diff"
  - "kernel forensics"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf stupidcontract writeup"
  - "ebpf verifier bypass ctf"
  - "bpf adjust_end_from_imm patch"
  - "signed compare ebpf oob"
  - "rust aya ebpf ctf"
  - "bzimage diff vmlinux unpack"
  - "ebpf map oob write"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-stupidcontract.png"
  alt: "GPN CTF 2026 Stupidcontract writeup — patched kernel strips BPF verifier bounds checks, signed-comparison OOB write clobbers SUCCESS"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Hard" os="Reverse — Linux kernel forensics, eBPF, Rust aya" skills="unpacking bzImage to vmlinux ELF, string-diffing two kernels with shifted section layout to find removed verifier messages, reading eBPF disassembly to spot signed-compare bypass, exploiting unchecked map-value pointer arithmetic with a negative index, beating a 20%-RNG bit-flip gate by detecting the win and switching to a neutral index" >}}

This **CyberSecurity Elite** writeup breaks down **Stupidcontract**, the GPN CTF 2026 reverse challenge that lives at the intersection of kernel forensics and eBPF. The handout ships two kernel images — `patched.bzImage` and `unpatched.bzImage` — plus a Rust/aya userspace runner that loads an eBPF program against a 101-byte `.bss` map. The challenge is to figure out *what was patched* and exploit it.

The diff turns out to be **five string deletions from the BPF verifier** — exactly the error messages that block unbounded pointer arithmetic against map-value pointers. With those checks gone, an eBPF program using a signed-comparison bounds check and a negative index can write to `bss[idx + 1]` where `idx + 1` lands outside the map. Targeting `idx = -1` writes the RNG bit directly into `bss[0]` = `SUCCESS[0]`, the flag gate. Flag:

```
GPNCTF{W417, n0! WHo STo1e mY S3CurITy???}
```

This is the standalone deep-dive on `reverse/stupidcontract` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full source at [`reverse/stupidcontract`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/reverse/stupidcontract).

## What's "patched"?

The bzImage payload is a gzip stream starting at offset `0x42c4`:

```python
data = open('patched.bzImage','rb').read()
i = data.find(b'\x1f\x8b\x08')   # 0x42c4
open('comp.gz','wb').write(data[i:])
```

After `gunzip`, both vmlinux ELFs are ~23 MB and **99% of bytes differ** because of a section-layout shift introduced by the patch. Naive `diff -q` is uninformative. String-diffing strips the noise:

```
$ strings vmlinux-patched | sort -u > p.s
$ strings vmlinux-unpatched | sort -u > u.s
$ diff p.s u.s | awk 'length > 30'
< 6.19.5-patched SMP preempt mod_unload
> 6.19.5 SMP preempt mod_unload
> R%d max value is outside of the allowed memory range
> R%d min value is outside of the allowed memory range
> R%d unbounded memory access, make sure to bounds check any such access
> math between %s pointer and register with unbounded min value is not allowed
> value %lld makes %s pointer be out of bounds
```

The unpatched kernel *has* the verifier's bounds-check error messages; the patched one does **not**. So the patch is "delete the OOB-pointer error paths in `check_reg_arithmetic` / `check_helper_mem_access`" — the verifier still loads programs but no longer rejects unbounded pointer arithmetic against map-value pointers.

Conclusion: any eBPF code with deliberately unverifiable pointer math is now loadable, and its runtime accesses are unchecked. We need to find a program that takes advantage of that.

## The userspace binary

`rootfs.ext2` mounts cleanly as ext2. The Rust/aya binary `/usr/bin/stupidcontract` exposes two BPF programs:

- `try_get_reservation(idx: i64)` — runs a 20% RNG check, writes the resulting `0`/`1` byte into a 101-byte `.bss` map at offset `idx + 1`.
- `validate_reservations()` — walks `bss[1..100]`; if every byte's low bit is set, writes `bss[0] = 1`.

The userspace loop runs `try_get_reservation` 300 times with user-supplied indices, then runs `validate_reservations`, then checks `SUCCESS[0]` and prints the flag if it's `1`.

The embedded BPF ELF (machine = `EM_BPF` = `0xf7`) is at file offset `0x2aa20` (three identical copies are baked in for relocation purposes); extract it by walking the ELF header.

## `try_get_reservation` in eBPF

```
0000000000000000 <try_get_reservation>:
   0:  r0 = 0xffffffff ll                      ; default retval = -1
   2:  if r1 == 0x0  goto +0x16c               ; null ctx → return -1
   3:  r7 = *(u64 *)(r1 + 0x0)                 ; r7 = user-supplied i64 index
   4:  if r7 s> 0x63 goto +0xd                 ; SIGNED check: idx > 99 → log path
   5:  call 0x7                                ; bpf_get_prandom_u32
   6:  r1 = r0
   7:  r1 <<= 0x20
   8:  r1 >>= 0x20                             ; r1 = random_u32
   9:  r0 = 0x1                                ; tentative win
  10:  r2 = 0x33333333
  11:  if r2 > r1  goto +0x1                   ; random < 0x33333333 → keep r0 = 1
  12:  r0 = 0x0                                ; else r0 = 0
  13:  r1 = .bss                               ; map_value pointer (relocation)
  15:  r1 += r7                                ; r1 += idx       ← UNBOUNDED ADD
  16:  *(u8 *)(r1 + 0x1) = w0                  ; bss[idx + 1] = r0
  17:  goto +0x15d                             ; → exit
```

Two cooperating mistakes:

1. **Signed compare on an unsigned offset.** `r7 s> 0x63` returns false for any value with bit 63 set — any negative `i64`. A user input of `-1` skips the "index too large" branch.
2. **Unbounded map-value arithmetic.** `r1 += r7` after `r1 = .bss` is exactly the pattern the deleted verifier messages warn about. On stock 6.19.5 the program would be rejected at load time. On the patched kernel it loads, and at runtime the kernel just does the addition.

Passing `r7 = -1` makes the store target `bss + (-1) + 1 = bss[0]` — the `SUCCESS[0]` flag gate.

## Exploiting the 20% gate

`try_get_reservation` always **writes** `r0` to the target byte, win or lose. So consecutive `-1` calls keep overwriting `SUCCESS[0]` with fresh RNG bits. The final state is the *last call's* result — a 20%/80% coinflip even if we made 300 attempts.

What we actually want:

1. Send `-1` until `SUCCESS[0]` becomes `1`. The server prints *Your reservation succeeded* on the same iteration, so we know when this happens.
2. Immediately switch to a "neutral" index whose write target is outside `bss[0..100]`. `-200` writes `bss[-199]` and changes nothing the binary cares about. `validate_reservations` still fails (`bss[1..100]` were never set), but it doesn't *clear* `bss[0]` either.
3. Burn the remaining iterations on `-200`. The 300-round loop ends, `validate_reservations` runs, `bss[0]` is still `1` from our earlier successful `-1` call, the binary's `SUCCESS[0]` lookup returns `1`, and the flag-printing branch fires.

The "we won" detection is straightforward: each round the server prints `Your reservation succeeded` or `Well, better luck next time` between prompts.

## Solver

`solve.py` is stdlib-only:

```python
PROMPT = b"index ("
ssock.sendall(b"-1\n" if not won else b"-200\n")
read_until(PROMPT)
if b"reservation succeeded" in buf and not won:
    won = True
```

End-to-end run (excerpt):

```
266/300 …  -1
[INFO  stupidcontract::interaction] Your reservation succeeded, …

*** [iter 266] SUCCESS — switching to neutral index ***

267/300 …  -200
[INFO  stupidcontract::interaction] Well, better luck next time...
…
300/300 …  -200
[INFO  stupidcontract] As a thank you, here's your flag: GPNCTF{W417, n0! WHo STo1e mY S3CurITy???}
```

## Defender takeaway

- **An eBPF verifier is a compiler in your TCB.** Custom-kernel patches to the verifier should get the same review rigor as the verifier's original code. The five-string deletion patch in this challenge would be a single-PR change in a real codebase, and it carries the security implication of "every BPF program that runs is now untrusted."
- **Differential analysis on bzImage is a real engineering skill.** Bzipped kernel images differ in 99% of bytes due to layout shifts even when the source diff is tiny. The reliable forensic path is unpack → ELF symbol diff → string diff for content changes → manual review of the related code.
- **Signed vs unsigned comparisons on attacker-controlled offsets** are the most common eBPF map-OOB primitive. The verifier's bounds tracking specifically handles this — removing it lets a `r7 s> 0x63` check pass for `r7 = -1` and any other negative value.
- **Rust/aya doesn't help.** The Rust BPF source code that compiled to the offending bytecode is just as patched-kernel-dependent as a C version. Memory safety in userspace doesn't translate to BPF program safety.

## Frequently asked questions

### What was patched in the kernel?

Five strings were removed from the BPF verifier — specifically the error messages from `check_reg_arithmetic` / `check_helper_mem_access` that reject unbounded pointer arithmetic against map-value pointers. Removing the strings is a proxy for removing the corresponding error paths. eBPF programs with deliberately unverifiable pointer math now load and run with their pointer arithmetic unchecked.

### Why is the diff on bzImage so noisy?

Adding code to the kernel shifts every following section's load address, which cascades through `e_shoff`/`e_shnum` and the gzip-compressed payload's layout. The result: 99% of bytes differ between two kernels that share 99% of their source. Reliable diff: unpack to vmlinux, sort `strings` output, diff at line granularity, then grep for missing content patterns.

### What's the signed-comparison bug in `try_get_reservation`?

The check `if r7 s> 0x63 goto error` returns false for any `r7` with bit 63 set — i.e. any negative `i64`. Sending `-1` as the user index passes the "too large" check and enters the RNG/write branch with `r7 = -1`. The subsequent `r1 += r7` against the map base pointer produces an out-of-bounds write at runtime.

### Why does `-1` write to `bss[0]`?

The store instruction is `*(u8 *)(r1 + 0x1) = w0` where `r1 = bss + r7`. With `r7 = -1`, the effective address is `bss + (-1) + 1 = bss[0]`. That's the `SUCCESS[0]` flag gate the userspace binary reads after the 300-iteration loop.

### How do you beat the 20% RNG gate?

Each `try_get_reservation` call *writes* the RNG result, win or lose. So consecutive `-1` calls overwrite `SUCCESS[0]` each time, and the final state is the last call's value — still a 20% probability. The trick is to detect the "Your reservation succeeded" message (server prints it on the same iteration as the win), then switch to a neutral index (`-200` writes to `bss[-199]`, well outside the map) for the remaining iterations. The successful `-1` write persists; `validate_reservations` doesn't clear `bss[0]` on failure.

### Why doesn't the kernel SIGSEGV on the OOB write?

eBPF map values are kernel-heap allocations. Writing into adjacent pages within the kernel heap doesn't fault as long as the page is mapped and writable. `-199` reaches the adjacent page in this layout, which is mapped (allocator slab) and writable. No SIGSEGV, no kernel oops; the BPF program returns normally.

### Where can I find the solver?

Full source at [`reverse/stupidcontract`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/reverse/stupidcontract) including the extracted `contract.bpf.o`. Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What was patched in the kernel?","acceptedAnswer": {"@type": "Answer","text": "Five strings were removed from the BPF verifier — specifically error messages from check_reg_arithmetic and check_helper_mem_access that reject unbounded pointer arithmetic against map-value pointers. Removing the strings is a proxy for removing the corresponding error paths. eBPF programs with deliberately unverifiable pointer math now load and run with unchecked pointer arithmetic."}},
    {"@type": "Question","name": "Why is the diff on bzImage so noisy?","acceptedAnswer": {"@type": "Answer","text": "Adding code to the kernel shifts every following section's load address, cascading through e_shoff/e_shnum and the gzip-compressed payload's layout. 99% of bytes differ between two kernels that share 99% of source. Reliable diff: unpack to vmlinux, sort strings output, diff at line granularity, grep for missing content patterns."}},
    {"@type": "Question","name": "What's the signed-comparison bug in try_get_reservation?","acceptedAnswer": {"@type": "Answer","text": "The check if r7 s> 0x63 returns false for any r7 with bit 63 set — any negative i64. Sending -1 passes the too-large check and enters the RNG/write branch with r7 = -1. The subsequent r1 += r7 against the map base pointer produces an out-of-bounds write at runtime."}},
    {"@type": "Question","name": "Why does -1 write to bss[0]?","acceptedAnswer": {"@type": "Answer","text": "The store is *(u8 *)(r1 + 0x1) = w0 where r1 = bss + r7. With r7 = -1, the effective address is bss + (-1) + 1 = bss[0]. That's the SUCCESS[0] flag gate the userspace binary reads after the 300-iteration loop."}},
    {"@type": "Question","name": "How do you beat the 20% RNG gate?","acceptedAnswer": {"@type": "Answer","text": "Each try_get_reservation writes the RNG result win or lose, so consecutive -1 calls overwrite SUCCESS[0]. Detect the Your reservation succeeded message and switch to a neutral index (-200 writes to bss[-199], outside the map). The successful -1 write persists; validate_reservations doesn't clear bss[0] on failure."}},
    {"@type": "Question","name": "Why doesn't the kernel SIGSEGV on the OOB write?","acceptedAnswer": {"@type": "Answer","text": "eBPF map values are kernel-heap allocations. Writing into adjacent pages within the kernel heap doesn't fault as long as the page is mapped and writable. -199 reaches an adjacent page that is mapped (allocator slab) and writable. No SIGSEGV, no kernel oops; the BPF program returns normally."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full source at reverse/stupidcontract in github.com/Abdelkad3r/gpn-ctf-2026 including the extracted contract.bpf.o. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
