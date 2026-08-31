---
title: "z0d1akCTF 2026 Qualifiers Reverse Engineering Writeup: All 3 RE Challenges Solved"
slug: "z0d1akctf-2026-qualifiers-reverse-engineering-writeup"
description: "Complete z0d1akCTF 2026 Qualifiers Reverse Engineering writeup covering all three RE challenges. stars-below — stripped x86-64 ELF with an SDL observatory front-end and a headless verifier that takes ROUTE plus CALLSIGN plus TICKET; brute force 8-factorial route permutations yields 16403752 which indexes the fragment string AP9GLSEO into PELAGOS9; the ticket is a custom Base32 of a 32-byte payload plus a 4-byte BLAKE2s checksum, and the payload is recovered by inverting 24 reversible ARX rounds of VM A plus a callsign-derived permutation plus 19 reversible stack-VM rounds of VM B starting from the BLAKE2s-derived target. Black Tide Survey — undocumented BTS2 side-scan sonar container plus a stripped diagnostic program that decodes but never reorders; reversing reveals a tagged CRC-protected format where each ping has two 384-sample banks packed as 12-bit words then ZigZag delta encoded modulo 4096, with even sequence numbers before odd sequence numbers; two decode paths reveal S4Ble_54_T3L0 as the raw-frame 5-by-7 marker and SABLE-7319 as the georeferenced vessel hull identifier. husk — 14 KB stripped x86-64 PIE that validates a 41-byte input by XORing four anti-debug results into a 16-byte key; in a clean run every check (ptrace TRACEME, TracerPid in proc-self-status, rdtsc timing loop, getenv LD_PRELOAD) returns zero so the stored key is de c0 37 13 b5 00 6b b1 ce fa ed fe be ba fe ca; the check is F of input XOR LCG equals RC4-keystream of key XOR CONST_B where F is a 6-round byte-oriented chained cipher, LCG seed 0x1234abcd, CONST_B derived from two rodata tables — every layer bijective so inverting the pipeline recovers the flag."
date: 2026-08-30T22:00:00Z
lastmod: 2026-08-30T22:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["z0d1akCTF 2026 Qualifiers"]
tags:
  - "z0d1akctf"
  - "z0d1akctf 2026"
  - "z0d1ak ctf"
  - "z0d1akctf qualifiers"
  - "ctf writeup"
  - "reverse engineering"
  - "reverse"
  - "stripped elf"
  - "custom vm"
  - "arx cipher"
  - "stack vm"
  - "blake2s target"
  - "invert the pipeline"
  - "bijective codec"
  - "route brute force"
  - "base32 custom alphabet"
  - "side scan sonar"
  - "bts2 container"
  - "12-bit packing"
  - "zigzag delta coding"
  - "sequence reordering"
  - "crc container"
  - "georeferenced image"
  - "ptrace anti-debug"
  - "tracerpid check"
  - "rdtsc timing"
  - "ld_preload check"
  - "rc4 keystream"
  - "lcg mask"
  - "anti-debug as key"
  - "stars-below"
  - "black tide survey"
  - "husk"
  - "ctf 2026"
keywords:
  - "z0d1akctf 2026 qualifiers reverse engineering writeup"
  - "z0d1akctf 2026 reverse writeup"
  - "z0d1akctf stars-below writeup"
  - "z0d1akctf black tide survey writeup"
  - "z0d1akctf husk writeup"
  - "stripped elf route callsign ticket verifier ctf"
  - "custom vm arx rounds invert pipeline blake2s target"
  - "bts2 side scan sonar 12-bit zigzag delta decode"
  - "even odd sequence reorder side-scan ping ctf"
  - "ptrace tracerpid rdtsc ld_preload anti-debug key material"
  - "rc4 keystream mask lcg inverse f cipher chained"
  - "z0d1akctf 2026 solutions"
  - "ctf reverse engineering step by step 2026"
toc: true
cover:
  image: "/images/articles/z0d1akctf-2026-qualifiers-reverse-engineering-writeup.png"
  alt: "z0d1akCTF 2026 Qualifiers Reverse Engineering writeup cover — all three RE challenges solved. stars-below is a stripped x86-64 ELF with an SDL observatory front-end and a headless verifier that takes route plus callsign plus ticket; brute-force 8-factorial route permutations yield 16403752 which indexes fragment string AP9GLSEO into PELAGOS9; the ticket is a custom Base32 of a 32-byte payload plus 4-byte BLAKE2s checksum recovered by inverting 24 reversible ARX rounds of VM A plus a callsign-derived permutation plus 19 reversible stack-VM rounds of VM B starting from the BLAKE2s-derived target. Black Tide Survey ships an undocumented BTS2 side-scan sonar container plus a stripped diagnostic program that decodes but never reorders; reversing reveals a tagged CRC-protected format where each ping has two 384-sample banks packed as 12-bit words then ZigZag delta encoded modulo 4096 with all even sequence numbers stored before all odd sequence numbers; two decode paths reveal a 5 by 7 flag marker in the raw diagnostic frame and the georeferenced vessel hull identifier SABLE-7319. husk is a 14 KB stripped x86-64 PIE that validates a 41-byte input by XORing four anti-debug results (ptrace TRACEME, TracerPid in proc-self-status, rdtsc timing loop, getenv LD_PRELOAD) into a 16-byte RC4 key; in a clean run every check returns zero so the stored key is a fixed constant, and the check is F of input XOR LCG equals RC4 keystream of key XOR CONST_B with every layer bijective so inverting the pipeline recovers the flag"
---

**z0d1akCTF 2026 Qualifiers**'s Reverse Engineering track is a three-challenge lesson in one discipline: **peel every shell.** In every one of these challenges the flag is buried under a stack of bijective codecs — a Base32 alphabet plus a custom-VM cipher plus a permutation plus a second custom-VM cipher plus a BLAKE2s target (stars-below); a CRC-protected container plus 12-bit packing plus ZigZag delta encoding plus even/odd sequence reordering plus optional georeferencing (Black Tide Survey); a linear-congruential mask plus a six-round chained cipher plus an RC4 keystream plus a constant derived from two rodata tables plus a 128-bit key that is itself the XOR of four anti-debug probe results (husk). The husk flag says the whole discipline out loud — *`7h3_An7LdEbu6_Was_Th3_decryP7LON_key`* — and its prompt reads *"Every shell you peel off is just another shell."* Both apply verbatim to the other two challenges.

The unifying pattern is that every layer in every one of these pipelines is a bijection you can either compute forward from the input or run backward from the target. stars-below inverts a 19-round stack VM and a 24-round ARX VM from a BLAKE2s-derived target that the binary computes for us. husk inverts an F cipher and an LCG keystream from an `EXPECTED` value the binary constructs from constants that are readable in `.rodata`. Black Tide Survey is one long forward pipeline — CRC-validate every record, dezigzag the deltas, depack the 12-bit samples, sort by sequence number, render — and the flag falls out of the raw diagnostic image without any inversion at all, but the same layered discipline applies. In every case the reversing effort is proportional to the number of layers, not to the difficulty of any single layer.

Handouts, per-challenge READMEs, and dependency-conscious solvers live at [Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers). This **CyberSecurity Elite** z0d1akCTF 2026 Qualifiers Reverse Engineering writeup covers all three RE challenges end to end. Read alongside the paired [z0d1akCTF 2026 Qualifiers Miscellaneous writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-misc-writeup/), the [z0d1akCTF 2026 Qualifiers Forensics writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-forensics-writeup/), the [z0d1akCTF 2026 Qualifiers Cryptography writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-crypto-writeup/), and the [z0d1akCTF 2026 Qualifiers Binary Exploitation writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-pwn-writeup/) for twenty-seven more challenges from the same event.

## All three Reverse Engineering challenges at a glance

| Challenge | Points | Sub-genre | Layer stack | Flag |
|---|---:|---|---|---|
| [stars-below](#stars-below--invert-two-custom-vms-from-a-blake2s-target) | 209 | Custom VM inversion | Base32 → payload → VM A 24 ARX rounds → callsign permutation → VM B 19 stack rounds → BLAKE2s target | `zdk{The_1OAd3r_DREaMS_IN_PAgE_boUNDArIE5}` |
| [Black Tide Survey](#black-tide-survey--bts2-container-plus-12-bit-zigzag-plus-even-odd-reorder) | 179 | Undocumented binary format | BTS2 CRC container → 12-bit packing → ZigZag delta mod 4096 → even/odd seq reorder → render | `zdk{S4Ble_54_T3L0}` |
| [husk](#husk--the-anti-debug-results-are-the-key) | 132 | Anti-debug + chained cipher | LCG mask → F 6-round chained cipher → RC4 keystream → key = XOR of 4 anti-debug probes | `zdk{7h3_An7LdEbu6_Was_Th3_decryP7LON_key}` |

Three challenges, three completely different pipelines, one repeated discipline: **document every codec, invert every codec, and the flag is at the bottom of the stack.**

---

## stars-below — invert two custom VMs from a BLAKE2s target

> *Flag:* `zdk{The_1OAd3r_DREaMS_IN_PAgE_boUNDArIE5}`
>
> *Prompt:* "The drowned observatory still charts a sky."

A stripped x86-64 ELF with two interfaces: an SDL observatory where eight labelled beacons can be visited in a chosen order, and a headless verifier that accepts `ROUTE`, `CALLSIGN`, and `TICKET`. The route brute forces over `8! = 40320` permutations; only one solution is accepted, `16403752`, which indexes the fragment string `AP9GLSEO` into `PELAGOS9`. The ticket is a custom Base32 encoding of a 32-byte payload plus a 4-byte BLAKE2s checksum. Recovering the payload is the main reversing task.

### Adversarial reversing environment

The binary rejects instrumentation-related environment variables (`LD_BIND_NOW`, `LD_AUDIT`, `LD_PRELOAD`) and its PLT relocations are deliberately awkward so decompilers attach misleading import names. Calls labelled `strstr` by Ghidra/IDA behave as fixed-length memory copies; the call's machine-level argument flow is more reliable than any imported label. Domain-separated hashes carry their terminating NUL byte — omitting it produces plausible-looking but incorrect values. The useful string dump exposes eight domain tags:

```text
stars-below/name/v1
stars-below/name-guard/v1
stars-below/invariant-mask/v1
stars-below/permutation/v1
stars-below/target/v1
stars-below/ticket/v1
stars-below/vm-a-key/v1
stars-below/vm-b-key/v1
```

Plus the ticket alphabet `87RJF2ACZLVUMXB3D6GH9WNSYP5QK4ET` and the fragment string `AP9GLSEO`.

### Two encrypted VM programs

The program decrypts two custom-VM programs at runtime and expands two round schedules:

- **VM A** — 24 reversible ARX rounds followed by a callsign-derived permutation over the 32-byte payload. Each round records four constants and touches every state word.
- **VM B** — 19 reversible stack-VM rounds; every opcode is invertible under its own recorded round record.

The verifier compares VM B's final state with a target derived from `BLAKE2s("stars-below/target/v1\x00" || callsign)`. Because every round in both VMs is a bijection, the inverse of the entire pipeline is:

```text
target ← BLAKE2s of "stars-below/target/v1\0" || CALLSIGN
state  ← invert VM B (19 rounds) starting from target
state  ← invert callsign-derived permutation
state  ← invert VM A (24 ARX rounds)
payload ← state
ticket  ← custom-Base32(payload || BLAKE2s-checksum(payload))
```

### Inverting the pipeline in practice

Both VM programs are decrypted lazily in memory; the solver dumps the decrypted `vma.bin` (1,417 instructions), `vmb.bin` (1,084 instructions), and the two round-schedule tables (`vma-table.bin`, `vmb-table.bin`) before touching a single input. With those tables in hand:

1. Compute the target for the recovered callsign `PELAGOS9`.
2. Start from the target and apply VM B's inverse opcode for each round record, in reverse order.
3. Undo the callsign-derived permutation (a table lookup that the binary computes from `BLAKE2s("stars-below/permutation/v1\x00" || callsign)`).
4. Apply VM A's inverse ARX round for each of the 24 records, in reverse order.
5. Encode the resulting 32-byte payload plus a 4-byte BLAKE2s-derived checksum through the custom Base32 alphabet.

### Route recovery is the entry point

At file offset `0x77e0`, the binary stores eight 32-bit constants that seed the route validator. Brute-forcing all `8!` permutations under the exact routine (a small chained accumulator with a fixed target constant) finds one accepted permutation:

```text
route = 16403752
```

Reading each digit as an index into the fragment string `AP9GLSEO` (index 1 = A, 6 = O, 4 = L, 0 = A → offsets that spell `PELAGOS9`) produces the callsign. **The route is not the flag** — it is the *seed* the whole downstream pipeline needs.

### Run it

The [solver](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/blob/master/Reverse/stars-below/solve.py) performs every stage end to end and checks each intermediate layer before producing the ticket. Submitting `route callsign ticket` returns the flag.

**Takeaway:** when a binary computes a BLAKE2s target from constants you can see, the shape of the exploit is fixed — invert everything between the input and the target. Every ARX round with a recorded schedule is trivially invertible (opposite rotate + subtract instead of add + rotate); every stack VM opcode paired with a recorded round record is invertible by construction. The reversing effort is dominated by *reading the schedule* and *labelling every opcode*, not by inverting any single round.

---

## Black Tide Survey — BTS2 container plus 12-bit ZigZag plus even/odd reorder

> *Flag:* `zdk{S4Ble_54_T3L0}`
>
> *Prompt:* "Survey unit BT-04 was recovered twelve nautical miles east of its assigned transect. Recover the final surveyed image and identify the marked vessel."

Two side-scan sonar recordings in an undocumented `BTS2` format, a reference image for calibration, and a stripped diagnostic program that decodes but *does not reorder or project* the samples. The diagnostic emits `768 × N` grayscale PGMs (two 384-sample banks per ping) but leaves acquisition-order and coordinate reconstruction to the reverse engineer.

### The container is tagged and CRC-protected

Reversing `sonar_diag` reveals a straightforward binary format:

- File header contains a `BTS2` magic plus per-file metadata (sample count, ping count, calibration constants) protected by a CRC32.
- Each ping is a `PING` tagged record with two 384-sample banks (port + starboard), a 16-bit sequence number, and its own CRC32.

Every CRC must validate before the record is trusted; the solver refuses to emit any artifact if a single record fails.

### 12-bit packing + ZigZag delta

Each 384-sample bank is not raw 12-bit samples but **delta-encoded** ones. Two 12-bit words pack into three bytes (`3 × 8 = 2 × 12 = 24 bits`), and each 12-bit value is a ZigZag-encoded delta modulo 4096 against the previous sample in the same bank.

```python
def dezigzag(z):
    return (z >> 1) ^ -(z & 1)

def depack_bank(three_byte_stride_bytes):
    words = []
    for i in range(0, len(three_byte_stride_bytes), 3):
        b0, b1, b2 = three_byte_stride_bytes[i:i+3]
        words.append(b0 | ((b1 & 0x0F) << 8))
        words.append((b1 >> 4) | (b2 << 4))
    prev = 0
    samples = []
    for z in words:
        delta = dezigzag(z)
        prev = (prev + delta) & 0xFFF
        samples.append(prev)
    return samples
```

### Even sequence numbers are stored before odd ones

The physical record layout in the file is not chronological — **all pings with even sequence numbers are stored first, then all pings with odd sequence numbers**. The diagnostic tool emits records in file order, which is why its output image looks scrambled. Sorting by the embedded sequence number restores acquisition order:

```python
pings.sort(key=lambda p: p.sequence_number)
```

### Two decode paths, two answers

The challenge accepts either of two artifacts:

**Path 1 — reproduce the raw diagnostic frame.** Concatenate `reverse(port_bank) || starboard_bank` per ping, sort by sequence, render as an 8-bit grayscale image. A clear **5×7 pixel marker** in this raw frame reads:

```text
S4Ble_54_T3L0
```

**Path 2 — full georeferenced survey.** Apply the calibration gains and offsets from the header, correct slant-to-ground for each sample using the platform altitude, apply side-specific range ordering (port samples increase towards the outer edge, starboard towards the inner edge), and project into world coordinates using the per-ping navigation and heading. The resulting georeferenced image shows the surveyed vessel and its hull identifier `SABLE-7319`.

Both paths corroborate the flag: `zdk{S4Ble_54_T3L0}`.

### Run it

The [dependency-free solver](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/blob/master/Reverse/black-tide-survey/solve.py) validates every header and record CRC before emitting anything. It writes the raw diagnostic reproduction (byte-for-byte match against `sonar_diag`'s output on the reordered stream), the georeferenced survey, and enlarged crops of both the flag marker and the vessel identifier.

**Takeaway:** any undocumented binary format that decodes cleanly under one interpretation still deserves the "does the file order match the semantic order?" check. Even/odd or bank-interleaved storage is a common efficient-write pattern in embedded acquisition systems and produces exactly this kind of scrambled diagnostic view. When the challenge ships a *diagnostic* rather than a *decoder*, the missing step is usually a reordering, a projection, or both.

---

## husk — the anti-debug results are the key

> *Flag:* `zdk{7h3_An7LdEbu6_Was_Th3_decryP7LON_key}`
>
> *Prompt:* "Every shell you peel off is just another shell."

A 14 KB stripped x86-64 PIE that validates a single 41-byte argument. The imports give the game away:

```text
$ strings husk | grep -Ei 'ptrace|status|preload|correct|nope'
/proc/self/status   TracerPid:   LD_PRELOAD   Nope   Correct!
```

Four anti-debug checks, each of which XORs a 32-bit value into a 16-byte buffer that becomes the RC4 key. And the *twist* — which the flag states outright — is that **the anti-debug results are the decryption key**, not just gates on execution.

### The four probes

| Check | Instruction | Clean result | Stored value |
|---|---|---|---|
| `ptrace(PTRACE_TRACEME)` | `xor eax, 0x1337c0de` | `0` | `0x1337c0de` |
| `TracerPid:` in `/proc/self/status` | `xor eax, 0xb16b00b5` | `0` | `0xb16b00b5` |
| `rdtsc` timing of a 200-iter loop | `xor eax, 0xfeedface` | `0` | `0xfeedface` |
| `getenv("LD_PRELOAD")` | `xor eax, 0xcafebabe` | `0` | `0xcafebabe` |

In a **clean run** every check returns `0`, so the stored constants are just the four literals. Under a debugger `ptrace` returns `-1`, `TracerPid` is non-zero, single-stepping blows the `rdtsc` budget, and an `LD_PRELOAD` shim flips the last check — each would change the key and silently corrupt decryption. That is the whole trick: **the checks are the key material, not gates.**

The little-endian dword sequence assembles into the 16-byte RC4 key:

```text
de c0 37 13  b5 00 6b b1  ce fa ed fe  be ba fe ca
```

### The full check

```text
accept  iff  F( input ⊕ LCG )  ==  RC4_keystream(key) ⊕ CONST_B
```

Four ingredients:

- **`key`** — the 16 bytes assembled from the four anti-debug XORs above.
- **`CONST_B`** — 41 bytes derived from two `.rodata` tables: `CONST_B[i] = table1[(0x11 * i) mod 41] ⊕ table2[i mod 16]`.
- **`LCG`** — a fixed linear-congruential keystream seeded with `0x1234abcd` (readable in `.rodata` as constants).
- **`F`** — a 6-round byte-oriented chained cipher (two rotate/add/XOR passes plus a mod-41 permutation per round) that operates on the 41-byte block.

Every layer is a bijection.

### Invert the pipeline

Because every layer is bijective, the entire pipeline inverts cleanly from `Correct!`:

```text
target       ← RC4_keystream(key)[0:41] ⊕ CONST_B
intermediate ← F⁻¹(target)          # invert 6 rounds
flag         ← intermediate ⊕ LCG   # remove the LCG mask
             = zdk{7h3_An7LdEbu6_Was_Th3_decryP7LON_key}
```

The `F` inverse is straightforward round-by-round: reverse the mod-41 permutation, then undo each of the two rotate/add/XOR passes with the opposite rotate + subtract instead of add. Every constant used in `F` is stored in `.rodata` under a fixed pointer, so no dynamic tracing is needed once the routine is labelled.

### Verify forward

The solver reads every constant out of the binary at rest (never running it), computes `EXPECTED` = `RC4_keystream(key) ⊕ CONST_B`, applies `F⁻¹` to recover the pre-permutation state, XORs against the LCG keystream to remove the mask, and — as a sanity check — runs the forward pipeline on the recovered flag to confirm the check would say `Correct!`.

**Takeaway:** when a binary uses anti-debug results as *data* rather than as *control flow*, running it under a debugger is actively harmful — the wrong key gets built and the answer is silently wrong. Read the disassembly instead. All the constants are in `.rodata` and every operation is a bijection. The flag `7h3_An7LdEbu6_Was_Th3_decryP7LON_key` names the entire class of exploit outright.

---

## Cross-cutting lessons from the z0d1akCTF 2026 Qualifiers Reverse Engineering set

Three challenges, three completely different substrates, one repeated discipline — **peel every shell**:

- **Every layer is a bijective codec.** stars-below's ARX and stack VMs, husk's F cipher and RC4-mask and LCG, Black Tide Survey's 12-bit packing and ZigZag delta. Every one of them can be run forward from an input or backward from a target. The reversing effort is dominated by *documenting every layer*, not by inverting any single one.
- **When the binary computes the target, invert the pipeline from the target.** stars-below's BLAKE2s target is derived from constants and the callsign, both of which are visible; husk's `EXPECTED` is derived from RC4 over a key and a rodata `CONST_B`. In both cases the pipeline runs `input → ... → target` forward, so `target → ... → input` runs backward once every intermediate operation is labelled.
- **When file order and semantic order disagree, the sort is the exploit.** Black Tide Survey stores all even sequence numbers before all odd ones, and the diagnostic tool that emits records in file order looks scrambled by design. Any container with sequence numbers deserves the sort-and-compare check before rendering.
- **Anti-debug results can be key material.** husk's four fixed 32-bit XORs XORed with anti-debug outputs assemble the RC4 key. Running under a debugger silently corrupts the key. Read the disassembly and compute the clean-run values from the operations, not from a dynamic trace.
- **Domain-separated hashes include their terminating NUL.** stars-below's eight `stars-below/foo/v1` domains all end with a NUL byte in the hashed material. Omitting the NUL produces plausible-looking but wrong hashes — a silent bug that costs an hour if it's not the first thing you check.
- **Decompilers mislabel PLT calls on purpose.** stars-below's `strstr` calls behave as memcpy. Trust the machine-level argument flow (register saves, argument counts, return-value use), not the imported symbol names. Awkward PLT relocations are a deliberate reversing-difficulty knob.
- **`LD_PRELOAD` / `LD_AUDIT` / `LD_BIND_NOW` rejection is a hint, not a wall.** stars-below refuses to run with any of those set — which tells you exactly what the intended reverser was going to try. Instrument via GDB scripts, `ptrace` wrappers, or by dumping the decrypted VM programs from memory rather than by preloading a shim.
- **A `strings` grep for well-known probe strings is a five-second first pass.** `TracerPid:`, `/proc/self/status`, `LD_PRELOAD` all appear in husk's `.rodata` and immediately name the four anti-debug checks. Any RE challenge with those strings has anti-debug — the only question is whether it's a gate (skip and continue) or a key (must produce the clean-run values).
- **When a challenge ships a diagnostic and a reference, the reference is the calibration.** Black Tide Survey supplies a `dock_reference.png` alongside a `dock_calibration.bts` recording. The reference names exactly what a *correct* decode looks like, which is what lets you validate every decoding decision (even/odd reorder? projection? gain?) against a known-good target before touching the final transect.

## Reproduce it yourself

Each challenge ships a standalone solver in the [z0d1akCTF 2026 Qualifiers repository](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers) under `Reverse/<challenge>/`:

- [`Reverse/stars-below/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Reverse/stars-below) — end-to-end solver that dumps decrypted VM programs and round tables from the ELF, brute-forces the 8-permutation route, computes the callsign from the fragment string, inverts both VMs from the BLAKE2s target, and encodes the ticket through the custom Base32 alphabet.
- [`Reverse/black-tide-survey/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Reverse/black-tide-survey) — dependency-free stdlib solver validating every header and per-record CRC, depacking 12-bit ZigZag delta samples, sorting by embedded sequence number, and emitting both the raw-diagnostic reproduction (with the 5×7 flag marker) and the georeferenced survey (with the vessel hull identifier).
- [`Reverse/husk/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Reverse/husk) — pure-Python solver that reimplements the LCG keystream, the 6-round F cipher (and its inverse), the RC4 keystream, and the two-table `CONST_B` derivation; recomputes `EXPECTED`, inverts F, XORs the LCG mask, and re-verifies forward — all without executing the binary.

All three solvers are Python standard library only.

Browse the full [CTF writeups](/ctf-writeups/) archive for more reverse engineering walkthroughs, or continue the z0d1akCTF 2026 Qualifiers series with the [Miscellaneous writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-misc-writeup/), the [Forensics writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-forensics-writeup/), the [Cryptography writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-crypto-writeup/), and the [Binary Exploitation writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-pwn-writeup/) — twenty-seven more challenges under the same substrate-first discipline.

---

*This writeup is part of the CyberSecurity Elite [z0d1akCTF 2026 Qualifiers](/series/z0d1akctf-2026-qualifiers/) series. Handouts, per-challenge READMEs, and dependency-conscious solvers for all three Reverse Engineering challenges are published at [github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers).*
