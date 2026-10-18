---
title: "GPN CTF 2026 — Stupidcontract: Patched eBPF Verifier + Signed-Cmp OOB"
slug: "gpn-ctf-2026-stupidcontract"
description: "GPN CTF Stupidcontract analysis separates the signed-index behavior visible in the eBPF object from the README’s unverified patched-verifier claim."
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
  alt: "Dark grid cover card for GPN CTF 2026 — Stupidcontract, with large high-contrast title lettering."
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Hard" os="Reverse — Linux kernel forensics, eBPF, Rust aya" skills="reviewing a supplied eBPF object, tracing signed comparisons and map-value pointer arithmetic, assessing a challenge-reported verifier patch, following the solver's RNG-gate strategy" >}}

This **CyberSecurity Elite** writeup examines **Stupidcontract**, the GPN CTF 2026 reverse challenge involving a Rust/aya runner and an eBPF object. The public challenge repository includes a README, `contract.bpf.o`, and a solver. Its README says the full handout contains patched and unpatched kernel images plus a root filesystem, but those images and the root filesystem are not present in the public repository snapshot. This distinction matters: the object lets us inspect the program's index check and pointer arithmetic, while the exact kernel patch can only be attributed to the README's account unless the images or a source diff are available.

The challenge README reports that comparing the supplied kernel images reveals five verifier-related strings present in the reference image but absent from the patched image. It interprets those differences as removal of verifier rejection paths for out-of-bounds pointer arithmetic. The public repository does not include either image, the extracted `vmlinux` files, or a source diff, so that patch-level conclusion cannot be independently confirmed here. A missing diagnostic string alone does not establish which code paths changed or whether all bounds checks were removed.

The included BPF object does independently show the relevant program pattern: a signed comparison against `99`, a map-value pointer relocation, a register-based pointer addition, and a byte store at offset `1`. With an index of `-1`, the computed store address is the map-value base. The README and supplied solver report that this works in the challenge environment and changes `SUCCESS[0]`; that runtime result is documented by the challenge author, not reproduced from the missing kernel image in this review. Flag:

```
GPNCTF{W417, n0! WHo STo1e mY S3CurITy???}
```

This is the standalone deep-dive on `reverse/stupidcontract` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full source at [`reverse/stupidcontract`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/reverse/stupidcontract).

## What's "patched"?

The challenge README gives a procedure for extracting a gzip stream from the supplied `patched.bzImage`, at offset `0x42c4` in that handout:

```python
data = open('patched.bzImage','rb').read()
i = data.find(b'\x1f\x8b\x08')   # 0x42c4
open('comp.gz','wb').write(data[i:])
```

The challenge README says the unpacked `vmlinux` files are about 23 MB and that most bytes differ because of a section-layout shift. It also reports the following string comparison. Since the images and extracted ELFs are absent from the public repository, these sizes, byte-difference percentage, and string results are not independently reproducible from the published files:

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

The README attributes the missing strings to changes in verifier checks such as `check_reg_arithmetic` and `check_helper_mem_access`. That is a plausible interpretation of the reported diff, but the string comparison alone cannot prove that those particular paths were deleted. It also does not support the broader claim that *any* program with unverifiable pointer arithmetic is accepted. The narrower challenge-specific claim is that the supplied object and solver are reported to run on the challenge kernel.

## The userspace binary

According to the challenge README, `rootfs.ext2` contains a Rust/aya binary at `/usr/bin/stupidcontract` with two BPF programs. The root filesystem and executable are not present in the public repository snapshot, so the following userspace behavior is the challenge-provided description rather than an independent inspection:

- `try_get_reservation(idx: i64)` — runs a 20% RNG check, writes the resulting `0`/`1` byte into a 101-byte `.bss` map at offset `idx + 1`.
- `validate_reservations()` — walks `bss[1..100]`; if every byte's low bit is set, writes `bss[0] = 1`.

The README describes a userspace loop that runs `try_get_reservation` 300 times with supplied indices, then calls `validate_reservations` and checks `SUCCESS[0]` before printing the flag.

The README places the embedded BPF ELF at offset `0x2aa20` and reports three identical copies. The published `contract.bpf.o` is independently identifiable as a 64-bit ELF for the eBPF machine; the rootfs binary needed to verify its embedding offset and copies is not included.

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
2. **Map-value pointer arithmetic from an attacker-controlled register.** `r1 += r7` after `r1 = .bss` makes the store address depend on the supplied index. The challenge README says the patched kernel accepts this program and that the unpatched image rejects it. The exact verifier behavior is kernel-version and program-context dependent; without those images or a matching source diff, this writeup cannot independently verify the claimed stock-kernel rejection or identify the patch that changed it.

Passing `r7 = -1` makes the store target `bss + (-1) + 1`, the map-value base. The challenge README identifies that byte as `SUCCESS[0]`, the flag gate.

## Exploiting the 20% gate

`try_get_reservation` always **writes** `r0` to the target byte, win or lose. So consecutive `-1` calls keep overwriting `SUCCESS[0]` with fresh RNG bits. The final state is the *last call's* result — a 20%/80% coinflip even if we made 300 attempts.

What we actually want:

1. Send `-1` until `SUCCESS[0]` becomes `1`. The server prints *Your reservation succeeded* on the same iteration, so we know when this happens.
2. The supplied solver switches to `-200` after observing a successful `-1` attempt. That index computes a store before the map-value base (`bss - 199`); it is still an out-of-bounds write. The README reports that this write completes in the challenge's kernel. Its safety depends on that environment's memory layout: a similar write could corrupt unrelated kernel memory or fault on another build. Do not treat a negative index as a generally safe or neutral destination. `validate_reservations` still fails (`bss[1..100]` were never set), but it does not clear `bss[0]` according to the challenge's documented behavior.
3. The supplied solver burns the remaining iterations on `-200`. According to the README's description, after the 300-round loop `validate_reservations` runs without clearing `bss[0]`; the userspace check then sees the earlier `1` and prints the flag. The rootfs executable needed to independently confirm that sequence is not present in the public snapshot.

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

The repository's README includes an end-to-end run (excerpt); this review did not reproduce it because the kernel image and root filesystem are missing from the published snapshot:

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

- **Treat verifier changes as security-sensitive kernel changes.** The challenge README attributes the demonstrated acceptance to a custom verifier patch. Because its images and source diff are unavailable here, this writeup cannot establish the patch's exact scope or generalize its impact to other programs.
- **Use binary differences as leads, not proof of a code change.** The README recommends comparing unpacked kernels and strings, but matching source or disassembly is needed to establish which verifier logic changed. The reported byte-difference percentage and string removals could not be checked from the public artifacts reviewed here.
- **Inspect signed comparisons and pointer arithmetic together.** In the included object, the signed `r7 > 99` branch and later map-value pointer addition are visible. The object alone does not prove that a given kernel verifier accepts the program or that an out-of-bounds access will be safe.
- **Userspace language safety does not establish BPF safety.** The public snapshot reviewed here contains the compiled object, not the Rust BPF source. Whatever language produced it, verifier acceptance and runtime pointer behavior depend on the kernel and program context.

## Frequently asked questions

### What was patched in the kernel?

The challenge README reports five verifier-related strings missing from the patched image and attributes them to changes involving `check_reg_arithmetic` and `check_helper_mem_access`. The images and a source diff are not in the public repository snapshot, so this writeup cannot confirm the code changes from those strings. It also cannot conclude that arbitrary unverifiable eBPF programs load. The supplied object and solver are reported by the README to work in the challenge environment.

### Why is the diff on bzImage so noisy?

The challenge README says a section-layout shift explains the large byte-level difference and reports that about 99% of bytes differ. The underlying images are unavailable in the public snapshot, so that percentage and explanation are not independently verified here. Unpacked ELF and string comparisons can help locate differences, but code or disassembly review is needed to determine their meaning.

### What's the signed-comparison bug in `try_get_reservation`?

In the included object, the signed check `if r7 s> 0x63 goto error` returns false for a negative `i64`, including `-1`. The object then adds `r7` to the map-value pointer and stores at offset `1`, which computes the map-value base for `-1`. The README identifies this as an out-of-bounds verifier bypass targeting `SUCCESS[0]` and reports it works on the challenge kernel; the missing kernel image prevents independent confirmation of verifier acceptance and runtime behavior.

### Why does `-1` write to `bss[0]`?

The store instruction is `*(u8 *)(r1 + 0x1) = w0` where `r1` is relocated to a map value and then adjusted by `r7`. With `r7 = -1`, the arithmetic reaches the map-value base. The challenge README identifies that byte as `SUCCESS[0]` and describes it as the flag gate; the userspace binary needed to confirm this mapping is absent from the public snapshot.

### How do you beat the 20% RNG gate?

Each `try_get_reservation` call *writes* the RNG result, win or lose. So consecutive `-1` calls overwrite `SUCCESS[0]` each time, and the final state is the last call's value — still a 20% probability. The supplied solver detects the "Your reservation succeeded" message and then switches to `-200`. From the shown arithmetic, that index targets `bss - 199`, still outside the map; the README reports this works in the challenge environment. This is not a neutral or generally safe address. The persistence of `bss[0]` after failed validation is also described by the README and depends on the challenge program's behavior.

### Why doesn't the kernel SIGSEGV on the OOB write?

The public artifacts reviewed here do not establish the address reached by `-200`, adjacent allocator state, or why the challenge run completes without faulting. The README and solver report a successful run in the challenge environment; the precise memory-layout explanation is unverified. An out-of-bounds kernel write may corrupt data or fault and must not be assumed safe.

### Where can I find the solver?

Full source at [`reverse/stupidcontract`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/reverse/stupidcontract) including the extracted `contract.bpf.o`. Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What was patched in the kernel?","acceptedAnswer": {"@type": "Answer","text": "The challenge README reports five verifier-related strings missing from the patched image and attributes them to changes involving check_reg_arithmetic and check_helper_mem_access. The images and source diff are absent from the public repository snapshot, so this writeup cannot verify the code changes or conclude that arbitrary unverifiable eBPF programs load. The README reports that the supplied object and solver work in the challenge environment."}},
    {"@type": "Question","name": "Why is the diff on bzImage so noisy?","acceptedAnswer": {"@type": "Answer","text": "The challenge README attributes a large byte-level difference to a section-layout shift and reports about 99 percent of bytes differ. The images are unavailable in the public snapshot, so the percentage and explanation are not independently verified here. ELF and string comparisons can locate leads; code or disassembly review is needed to establish their meaning."}},
    {"@type": "Question","name": "What's the signed-comparison issue in try_get_reservation?","acceptedAnswer": {"@type": "Answer","text": "In the included object, the signed check r7 s> 0x63 is followed by map-value pointer arithmetic using r7 and a byte store at offset 1. For r7 = -1, that arithmetic targets the map-value base. The challenge README identifies this as SUCCESS[0] and reports the program works on its patched kernel; the public snapshot lacks the kernel image needed to verify verifier acceptance and runtime behavior independently."}},
    {"@type": "Question","name": "Why does -1 target bss[0]?","acceptedAnswer": {"@type": "Answer","text": "In the included object, the pointer is adjusted by r7 and then the byte store uses offset 1. With r7 = -1, the computed address is the map-value base. The challenge README identifies that byte as SUCCESS[0]; the rootfs binary needed to independently confirm that mapping is absent from the public snapshot."}},
    {"@type": "Question","name": "How does the solver handle the RNG gate?","acceptedAnswer": {"@type": "Answer","text": "The included solver watches for the success message after sending -1 and then switches to -200. That index is still out of bounds according to the object's pointer arithmetic. The README reports it works in the challenge environment; it is not a generally safe or neutral address, and the README's description of state persistence depends on the challenge program."}},
    {"@type": "Question","name": "Why doesn't the kernel fault on the out-of-bounds write?","acceptedAnswer": {"@type": "Answer","text": "The public artifacts do not establish the address reached by -200 or the adjacent allocator state. The README and solver report a successful run in the challenge environment, but the precise memory-layout explanation is unverified. An out-of-bounds kernel write may corrupt data or fault and should not be assumed safe."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full source at reverse/stupidcontract in github.com/Abdelkad3r/gpn-ctf-2026 including the extracted contract.bpf.o. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
