---
title: "V1t CTF 2026 Writeup: 8 Challenges Solved (Crypto, Reverse, Web, Misc)"
slug: "v1t-ctf-2026-writeup"
description: "Step-by-step V1t CTF 2026 writeup — eight challenges covered across crypto (ZUC keystream recovery, RSA sextic-twist ECM), reverse (tiny ELF RLE bitmap, TCC stack-VM, KMDF driver), web (Emoji-To-AZ font stego, shell glob bypass), and misc."
date: 2026-06-28T16:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["V1t CTF 2026"]
tags:
  - "v1t ctf"
  - "v1t ctf 2026"
  - "ctf writeup"
  - "zuc stream cipher"
  - "rsa ecm sextic twist"
  - "tcc stack vm"
  - "kmdf driver reverse engineering"
  - "shell glob bypass"
  - "font stego"
  - "ctf cryptography"
  - "ctf reverse engineering"
  - "ctf web"
keywords:
  - "v1t ctf 2026 writeup"
  - "v1t ctf writeup"
  - "v1t ctf 2026 solutions"
  - "china crack 202 writeup"
  - "hextrap writeup"
  - "ducks ping pong writeup"
  - "sealed input verifier writeup"
  - "tini rev writeup"
  - "duck nettool revenge writeup"
  - "hvl mckeyyyyyy writeup"
  - "duck v1t writeup"
  - "zuc keystream leak recovery ctf"
  - "rsa sextic twist ecm j=0 curve"
  - "kmdf ioctl fnv1a hash binding"
  - "shell glob ? filter bypass"
  - "emoji to az font cmap stego"
toc: true
cover:
  image: "/images/articles/v1t-ctf-2026-writeup.png"
  alt: "V1t CTF 2026 writeup — eight challenges solved across crypto, reverse, web, and misc tracks"
---

Welcome to a **CyberSecurity Elite** writeup on V1t CTF 2026, which shipped a small but unusually well-curated set of challenges. Every one of the eight problems covered here teaches a specific primitive: a structured-prime RSA factored by stage-1 ECM on a `j = 0` curve, a ZUC stream cipher recovered from three leak functions without the key, a 904-byte ELF whose only validation is the byte-sum of the input, a TCC binary dressed up in packer-section costume but driven by a tiny 365-byte stack VM, a KMDF driver that binds to its userland by FNV-1a of `.text`, a font file aliased back to `Noto Sans` that quietly rewrites emoji into letters, and a 16-character allowlist regex on a `shell=True` command that still leaks the flag via `python3 dis.py` and globs.

This is the master writeup for the whole track. The original handouts, per-challenge READMEs, and solver scripts live in [Abdelkad3r/V1t-CTF-2026](https://github.com/Abdelkad3r/V1t-CTF-2026). I solved everything statically where possible (Ducks Ping-Pong, Sealed Input Verifier, Tiny, both crypto challenges) and reached for headless Chrome only where Cloudflare's managed challenge forced it (Duck Nettool Revenge).

## The eight V1t CTF 2026 challenges

| Challenge | Category | Bug class / primitive | Flag |
|---|---|---|---|
| China Crack? - 202 | Crypto | ZUC stream cipher with three keystream leak functions. `leak2 = ((w * 0x45d9f3b) ^ (w >> 16)) & 0xffff` collapses each 32-bit word to a 16-bit candidate space, `leak3` (popcount) prunes, ciphertext + CRC32 of first 16 bytes pin the chain uniquely. | `V1T{7fK9xL2mQp8ZrT5uWc3Yd6Hs0AaBbCcDdEeFf}` |
| Hextrap | Crypto | 1280-bit RSA with one structured prime built as `p = Norm(z - 1)` for a 2^15-smooth Eisenstein integer `z`. One sextic twist of a `j = 0` curve has smooth order modulo `p`, so a targeted ECM stage-1 with scalar `M = prod prime_power <= 2^15` yields `gcd(Z, n) = p`. | `v1t{six_twists_one_smooth_order}` |
| Duck | Misc | `https://v1t.site/duck` is an ANSI-coloured menu page. `/flag` returns FIGlet block art rendered in the `dos_rebel` font. Strip the ANSI sequences, OCR via `pyfiglet`. | `v1t{ducky_quacky}` |
| Tiny | Reverse | 904-byte statically-linked x86-64 ELF with corrupted section headers. Sums all non-newline input bytes into `ebp`, subtracts that sum from each of `0xe3` 16-bit words to decode an RLE bitmap. Only one key (`625`) makes the bitmap internally consistent. The flag's own byte sum is the key. | `v1t{^}` |
| Sealed Input Verifier | Reverse | TCC binary in fake-packer costume (`.enigma1`, `.vmp0`, `UPX0`, `.petite`, `.aspack`, `__wibu00` sections all 1-byte padding). Underneath is a 365-byte stack VM with eight opcodes; the live chain per byte is `LOAD_INPUT → XOR_LIT → ADD_LIT → ROTL → XOR_LIT → ASSERT_EQ`, which inverts directly. | `v1t{n0_dump_just_pain}` |
| Ducks Ping-Pong | Reverse | KMDF driver `DucksKD.sys` + userland `Ducks_Ping-Pong.exe`. Driver gates first IOCTL on FNV-1a of caller's `.text` section. Three IOCTLs hand back per-stage rewards; the 32-byte flag is a static XOR fold of three known FNV/reward pairs, a 16-byte `.rdata` blob XORed with `0x55`, and a 16-byte kernel blob returned on stage 1. | `v1t{kn0w_h0w_to_p1ngp0ng_ducks!}` |
| HVL (MCKeyyyyyy) | Web | Variation Selectors Supplement stego (`U+E0100-U+E01EF` after `🔥`) decodes to `hello sir` and is a deliberate red herring. The real flag is rendered by an "Emoji To AZ" font aliased back to `"Noto Sans"` via `@font-face`. The `cmap` rewrites each emoji code point to a single letter. | `v1t{g04t_mck_hvl}` |
| Duck Nettool Revenge | Web | Flask `ping -c 1 <target>` with `shell=True` behind an 11-character allowlist regex (`[i0-9.;?/ ]`). `;` chains, `?` is a shell glob. The `Dockerfile` prunes `/bin`, `/usr/bin`, `/usr/local/bin` down to `sh`, `ping`, `python*`, `gunicorn`. `python3 dis.py /app/app.py` prints the module docstring, which the deployer rewrites to embed the real flag. | `v1t{br0_th15_15_duck}` |

The pattern that connects everything: each challenge has a single load-bearing primitive and a pile of decoration around it. The skill is identifying which one piece of code is doing the real work and ignoring the rest. The fake packer sections, the `MIX_HASH` decoy opcodes, the duck phrases the user actually types, the Variation Selectors stego, the `BLOCKED_TOKENS` base64 list: all decoration. The real work is one regex, one byte sum, one structured prime, one font cmap, one XOR fold.

## Methodology — find the one primitive, ignore the rest

A pattern that worked across every challenge: write a one-line description of the primitive that actually constrains the flag before touching any code. For China Crack? - 202 the line is "leak2 reduces each keystream word to a 16-bit search." For Hextrap it is "smooth Eisenstein norm makes one sextic twist of `y^2 = x^3 + b` smooth." For Tiny it is "byte sum of input is the only key, RLE consistency picks it uniquely." For Sealed Input Verifier it is "stack VM with `LOAD/XOR/ADD/ROTL/XOR/ASSERT` per byte, no state crossing chains." For Ducks Ping-Pong it is "32 bytes are a static fold of FNV/reward constants both binaries contain." For HVL it is "the `cmap` of the font aliased as Noto Sans rewrites the visible emojis to letters." For Duck Nettool Revenge it is "`?` is a glob, `dis.py` prints the docstring, the deployer puts the real flag in the docstring."

Once those one-liners are written, every challenge becomes a matter of expressing the primitive in code. The hours go into discarding the decoration: figuring out that the packer section names are 1-byte padding, that the `MIX_HASH` and decoy `0x5D` opcodes never feed back into `flags`, that `BLOCKED_TOKENS` base64 contains characters the regex would reject anyway, that `WhatSoundDoesACowMake` is dead code. None of those wastes a primitive; they only waste an analyst's time.

I solved seven of the eight without touching the live target. Duck Nettool Revenge needed the live endpoint only because Cloudflare's managed challenge required a real browser session to clear once before the HTTP API would accept the payload.

Per-challenge walkthroughs follow.

## Crypto

### China Crack? - 202

A small handout: a working ZUC stream-cipher implementation in `zuc.py`, a `challenge.py` whose key/IV definitions deliberately call `bytes.fromhex(...)` on non-hex strings (so the script does not execute), and a bottom-of-file comment block holding the ciphertext, three leak arrays, and one CRC32. The ZUC implementation is sound; the key is never recoverable; the point is the leaks.

#### Step 1 — Read the leak shapes

The script encrypts the flag with the keystream and prints four side channels:

```python
words = keystream_words(len(flag))
keystream = words_to_bytes(words, len(flag))
cipher_flag = xor(flag, keystream)

leak1 = [((words[i] ^ words[i+1]) * 0x9e3779b1 >> 24) & 0xFF
         for i in range(len(words)-1)]
leak2 = [((words[i] * 0x45d9f3b) ^ (words[i] >> 16)) & 0xFFFF
         for i in range(len(words))]
leak3 = [bin(words[i]).count("1") for i in range(len(words))]
partial_crc = zlib.crc32(flag[:16])
```

Each keystream word is 32 bits. Naive brute force over all words would be `2^32` per word, which is unworkable. `leak2` is the lever that makes the recovery affordable.

#### Step 2 — Reduce `leak2` to a 16-bit search

Write each word as `w = (high << 16) | low`. Because `leak2` keeps only the low 16 bits and multiplication distributes naturally over the bottom of the word:

```
(w * 0x45d9f3b) mod 2^16  ==  (low * 0x45d9f3b) mod 2^16
```

So for any candidate `low` (16 bits), the corresponding `high` is forced by `leak2`:

```
high  =  leak2[i] ^ ((low * 0x45d9f3b) & 0xffff)
```

That collapses the per-word search from `2^32` to `2^16`. For an 11-word flag plaintext that is `11 * 65536` candidate words to score, which finishes in tenths of a second.

#### Step 3 — Filter by popcount and ciphertext

`leak3[i]` is the Hamming weight of `words[i]`, an 8-bit number. After enumerating the `2^16` `(low, high)` pairs for each `i`, keep only those whose popcount matches `leak3[i]`. That typically cuts the candidate list per word to a few hundred.

The ciphertext gives a stronger filter for word 0: if a candidate word XORed with the first four ciphertext bytes is `V1T{` (uppercase, the published flag prefix), that word is almost certainly correct. The lowercase variant `v1t{` does not satisfy the published leaks, which is a small forensic detail that tells you the flag's case matters.

#### Step 4 — Link adjacent words with `leak1`

`leak1[i]` constrains the pair `(words[i], words[i+1])`. After the per-word filters, walk the candidate list pairwise and keep only candidate pairs whose `leak1` matches. For most positions this collapses each side to a single candidate.

#### Step 5 — Pin the first four words with CRC32

`partial_crc = zlib.crc32(flag[:16])` is a 32-bit constraint over the first 16 plaintext bytes, which correspond to the first four keystream words. Any remaining ambiguity from `leak1/2/3` over those four words is removed by requiring `zlib.crc32(plaintext_first_16) == 0x32c29a97`. After that, the chain locks down: every subsequent word is uniquely determined by `leak1` from its predecessor.

#### Step 6 — Run the solver and verify

```bash
python3 solve.py
```

```
flag=V1T{7fK9xL2mQp8ZrT5uWc3Yd6Hs0AaBbCcDdEeFf}
words=0x24a14039,0x9acba2fc,0x433081eb,0xbfc88e2c,0x2f16eeb0,0xd9a5e71b,
      0x83461fc4,0xe5931308,0x9e6c2d67,0x49b54ad9,0x962ddc14
verified=true
```

The recovered keystream is verified against ciphertext, `leak1`, `leak2`, `leak3`, and the CRC. Per-challenge README and solver: [crypto/china-crack-202](https://github.com/Abdelkad3r/V1t-CTF-2026/tree/master/crypto/china-crack-202).

### Hextrap

The headline crypto challenge. 1280-bit RSA-OAEP with one structured prime. The `chall.py` source ships with the keygen function, which is where the bug lives.

#### Step 1 — Read the prime generator

The script works in the Eisenstein integers, whose norm form is:

```python
def hnorm(z):
    x, y = z
    return x*x - x*y + y*y
```

A helper `smooth_hex` multiplies many small Eisenstein factors until `Norm(z)` reaches 640 bits. The largest rational prime used in the construction is below `2^15`, so `Norm(z)` is `2^15`-smooth. The script then accepts primes of the form:

```python
p = hnorm((x - 1, y))   # i.e. Norm(z - 1)
```

The published modulus `n` is a 1280-bit product of one such `p` and a random 640-bit `q`. The encrypted flag is OAEP ciphertext under this `n`.

#### Step 2 — Recognise the trapdoor

For Eisenstein primes generated this way, one of the sextic twists of the `j = 0` family

```
E_b: y^2 = x^3 + b   (over F_p)
```

has order related directly to `Norm(z)`, which is `2^15`-smooth. That makes the entire group order of this twist a product of small primes, and ECM stage-1 with bound `B1 = 2^15` will (in expectation, over the choice of `b`) compute the identity element of the smooth twist modulo `p` while not doing so modulo `q`. In projective coordinates the identity sends `Z` to a multiple of `p`, so `gcd(Z, n) = p`.

The attack does not need to know which twist is the smooth one. Sampling random `b` values cycles through the six twists; one of them will work.

#### Step 3 — Stage-1 ECM on a `j = 0` curve

Concretely:

1. Compute the stage-1 scalar `M = product(prime_power) for prime_power <= 2^15`.
2. Sample a random `x, y` modulo `n`, define `b = (y^2 - x^3) mod n`. This places the point `(x, y)` on `E_b: y^2 = x^3 + b` modulo `n`.
3. Multiply the point by `M` in projective coordinates on `E_b` modulo `n`.
4. Take `g = gcd(final_Z, n)`.
5. If `1 < g < n`, you have `p`. Otherwise resample `b` and retry.

In practice this hits in a handful of samples because the smooth twist has roughly 1-in-6 probability under random `b`. The included solver replays one successful sample so the result is deterministic.

#### Step 4 — Decrypt OAEP

After factoring:

```python
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
key = RSA.construct((n, e, d, p, q))
flag = PKCS1_OAEP.new(key).decrypt(c)
```

```
factor=3971164587634789113399026192514096315991628797934773099935584394633035439388594766334258365776620150043505274728443195855341627841973958963995826770119296074037237592729321872073402425949370737
other_factor=3748220483810589669566755882957060576744772379472871070171392916477678542421486526677373954661404221027616486603318970391886391444386888979538324563143039101271482850421776119711933444343051867
flag=v1t{six_twists_one_smooth_order}
```

The flag text itself spells out the design (`six_twists_one_smooth_order`). Per-challenge README and solver: [crypto/hextrap](https://github.com/Abdelkad3r/V1t-CTF-2026/tree/master/crypto/hextrap).

The deeper lesson is structural: RSA primes generated from algebraically structured constructions (Eisenstein norms, Galois closures, CM curves) often inherit smoothness in some hidden algebraic group order. Pollard p-1, Williams p+1, and ECM each exploit a different one. If a CTF (or a production keygen) builds a prime through anything other than "sample uniform, test primality," the structure is the bug.

## Misc

### Duck

A small terminal-style page hosted at `v1t.site` whose `/duck` endpoint returns ANSI-coloured ASCII art and a command list, and whose `/flag` endpoint returns more ANSI-coloured ASCII art that, once decoded, is the flag rendered in a known FIGlet font.

#### Step 1 — Strip the ANSI escapes from `/duck`

The downloaded `artifacts/duck` is UTF-8 text with escape sequences. A one-line Perl filter exposes the menu:

```bash
perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' artifacts/duck
```

The decoded menu lists the live endpoints, including `/flag`. That endpoint is the only one whose name promises the flag, so it is the first target.

#### Step 2 — Fetch `/flag` through a browser

The CTF infrastructure is fronted by Cloudflare, which bounces direct `curl` requests with the managed challenge. Pulling `/flag` through a normal browser session and saving the response works. The downloaded payload is, again, UTF-8 with escape sequences.

#### Step 3 — Recognise the FIGlet block art

After stripping the ANSI codes, the remaining output is a large block-art banner. The banner is not random ASCII art; it is a known FIGlet rendering of the flag. The shape of the glyphs (`dos_rebel` has a very recognisable thick-edged style) and the spacing pattern are the giveaway.

The solver iterates `pyfiglet` over likely candidate strings and FIGlet fonts, normalising both rendered and downloaded banners by collapsing whitespace and mapping non-space characters to a single token. The pair with the smallest "occupancy diff" wins:

```bash
python3 solve.py artifacts/flag
```

```
best_font=dos_rebel
best_candidate=v1t{ducky_quacky}
occupancy_diff=0
flag=v1t{ducky_quacky}
```

An occupancy diff of `0` means the rendered candidate matches the downloaded banner exactly (after the normalisation). Per-challenge README: [misc/duck](https://github.com/Abdelkad3r/V1t-CTF-2026/tree/master/misc/duck).

## Reverse engineering

### Tiny

A 904-byte statically-linked x86-64 ELF whose section headers are deliberately corrupted ("corrupted section header size", per `file`). Normal symbol-based analysis is useless; the program is small enough that the entry point is the whole story.

#### Step 1 — Disassemble from the entry point

Entry is `0x400070`. The body is three things: a 256-byte `read` from stdin into `r8`, an accumulator loop over the input that adds every non-CR/LF byte to `ebp`, and a decoder loop that walks `0xe3` 16-bit words at virtual address `0x4001b8`, subtracting `ebp` from each:

```asm
mov    rsi, 0x4001b8
mov    ecx, 0xe3
decode:
    movzx  eax, word ptr [rsi]
    add    rsi, 2
    sub    eax, ebp
    stosw
    loop   decode
```

There is no string comparison, no `strcmp`, no flag literal anywhere. The "verification" is purely structural: the decoded words must be a valid run-length encoded 10-row, 140-column bitmap.

#### Step 2 — Pin the key by RLE consistency

The 10 row descriptor bytes are stored at the end of the file: `10 14 18 15 17 16 1a 12 12 1a`. A valid decoded stream must satisfy:

- header words decode to `[10, 1, 1]`;
- each row contains exactly the count given by its row descriptor;
- each row's start bit is `0` or `1`;
- each row's run lengths sum to 140 (the row width);
- all `0xe3` decoded words are consumed exactly.

A short brute force over the key (16-bit, the input sum) finds exactly one value that satisfies every condition:

```
key = 625
```

#### Step 3 — Read the rendered bitmap

With key 625, the first decoded words are `[10, 1, 1, 16, 0, 1, 4, 12, 4, 12, ...]`. The `16` is the first row descriptor; the `0` is the first row's start bit; the rest are run lengths summing to 140. The decoded bitmap, when rendered as `0`/`1` characters and rotated correctly, is a `^` glyph.

#### Step 4 — Match the key to the flag

The flag wrapper `v1t{}` sums to 531. The total key is 625. The remaining single payload byte is:

```
625 - 531 = 94 = ord("^")
```

So the flag is `v1t{^}`. The flag's own byte sum is exactly the key, which means the flag passes its own check when fed back as the program's input. Running the binary with the flag as stdin renders the bitmap on stdout:

```bash
printf 'v1t{^}\n' | ./tini_rev
```

That self-referential property is the puzzle's punchline. Per-challenge README: [reverse/tiny](https://github.com/Abdelkad3r/V1t-CTF-2026/tree/master/reverse/tiny).

### Sealed Input Verifier

A 38 KB stripped TCC binary dressed up as something far more intimidating. The section table reads like a CTF parody of itself:

```
.enigma1   .enigma2   .vmp0   .vmp1   .vmp2
UPX0       .winlice   .petite .aspack ... __wibu01
```

Every one of those sections is one byte of padding. The string table contains `Enigma protector v`, `denuvo_atd`, `NUITKA_ONEFILE_PARENT`, and a `chall_tcc_obfus.exe` filename leak that gives away the actual build. None of those packers is present. Underneath the costume is a 365-byte stack VM with eight opcodes.

#### Step 1 — Identify the verifier

The entry point at `0x4030e0` does the standard TCC/MSVCRT setup and tail-calls `main` at `0x402962`. `main` reads a line with `fgets`, calls a `strip_nl` chop, calls `anti_debug`, and then calls `verifier(buf, anti_debug_result)`. The interesting calls are `anti_debug` at `0x4024d9` and `verifier` at `0x402618`.

The verifier copies up to 22 bytes into a scratch buffer and runs three checks in order: `vm_check(scratch, key)`, `original_len == 0x16`, and an `input_hash == exp(key)` that turns out to be tautological. So the only real constraint is the VM, plus length.

#### Step 2 — Resolve the key

`anti_debug` returns one of four bytes: `0x13` if `IsDebuggerPresent`, `0x29` if `CheckRemoteDebuggerPresent`, `0x4e` if a `QueryPerformanceCounter`-bracketed `Sleep(12)` exceeded 600 ms, otherwise `0xa7`. On any clean run the answer is `0xa7`. The same constant is recoverable statically from a small arithmetic on bytes at `0x4040fb..0x404104` (the published bytes evaluate to zero, which drops through into the `0xa7` return).

`key = 0xa7` propagates into every VM fetch as part of the keystream.

#### Step 3 — Decode the bytecode

The VM lives in `vm_check` at `0x401fb8`. Each fetch reads one encrypted byte, mixes it with a per-PC keystream byte derived from the Murmur3 byte-folding tail (`* 0x45d9f3b ^ 0x6d2b79f5 * ... fold to 8 bits`), XORs, then `rotr`s by `(pc ^ key) & 7`:

```python
def fetch_byte(bc, pc):
    enc = bc[pc]
    plain = rotr_byte(enc ^ murmur_mix(pc, KEY), (pc ^ KEY) & 7)
    return plain, pc + 1
```

With `key = 0xa7` and `pc` walking from 0, the keystream is fully determined and the 365-byte program decodes to 165 opcodes plainly.

#### Step 4 — Identify the live opcodes

Eight opcodes total. The dispatch table at `0x402470` shows which ones actually feed into the success condition:

| Opcode | Operands | Effect |
|---|---|---|
| `0x4B` | `idx` | `cur = input[idx % 22]`; sets a fail-bit if `idx >= 22` |
| `0x71` | `lit` | `cur = cur ^ lit` |
| `0x32` | `lit` | `cur = (cur + lit) & 0xff` |
| `0x18` | `lit` | `cur = rotl_byte(cur, lit)` |
| `0xD4` | `exp` | `flags |= cur ^ exp`; `counter++` |
| `0xA9` | `i1, i2, k, exp` | `flags |= pair_hash(input[i1], input[i2], i1, i2, k) ^ exp`; `counter++` |
| `0x5D` | `lit` | Updates an independent hash accumulator. **Decoy.** |
| `0xEE` | `exp` | `flags |= counter ^ exp`; success iff `flags == 0` |

`MIX_HASH` (the `0x5D` family) updates a byte at `[rbp-0xa]` that no later opcode ever reads. The state that matters at `ASSERT_EQ` is `[rbp-0x9]`, the value most recently produced by the `LOAD/XOR/ADD/ROTL/XOR` chain.

#### Step 5 — Invert the per-byte chains

The program runs 22 fixed-pattern blocks (one per input index, in a shuffled order), followed by 11 `PAIR_ASSERT`s and one `EXIT 33`. Each per-index block is:

```
LOAD_INPUT idx        ; cur = input[idx]
XOR_LIT    a          ; cur ^= a
ADD_LIT    b          ; cur = (cur + b) & 0xff
ROTL       r          ; cur = rotl(cur, r)
XOR_LIT    c          ; cur ^= c
ASSERT_EQ  e          ; require cur == e
```

Solving for `input[idx]` is one line:

```python
input[idx] = (rotr_byte(e ^ c, r) - b) & 0xff ^ a
```

Running that across all 22 blocks recovers the 22-byte flag directly. No emulator, no dump, no debugging.

#### Step 6 — Cross-check the `PAIR_ASSERT`s

The solver replays every `PAIR_ASSERT` against the recovered bytes:

```python
def pair_hash(x, y, i1, i2, k):
    t1 = ((x ^ ((k + i1) & 0xff)) + (y ^ ((k + i2) & 0xff))) & 0xff
    res1 = rotl_byte(t1, (k ^ i1 ^ i2) & 7)
    r1 = (x * ((k & 7) | 1)) & 0xff
    r2 = (y * (((k >> 3) & 7) | 1)) & 0xff
    res2 = rotl_byte((r1 + r2) & 0xff, (i1 + i2 + k) & 7)
    return (res1 ^ res2) & 0xff
```

All eleven `pair_hash` values match their stored `exp` bytes; the total assert count is `22 + 11 = 33`, matching `EXIT 33`. The accept path is fully accounted for, and the flag is `v1t{n0_dump_just_pain}`. Per-challenge README and solver: [reverse/sealed-input-verifier](https://github.com/Abdelkad3r/V1t-CTF-2026/tree/master/reverse/sealed-input-verifier).

### Ducks Ping-Pong

A two-binary Windows kernel-RE warmup: 17 KB userland EXE `Ducks_Ping-Pong.exe`, 13 KB KMDF driver `DucksKD.sys`. The userland asks three duck-themed prompts (`HOOOONK-honk-quack?`, `Squeak-squeak-quack?`, `Qwack-quackity-quack?`), reads one token per prompt with `scanf("%63s")`, ships each through the driver, and on success prints "The ducks ponder your words and offer this in return:" followed by a 32-character payload. The userland never holds the flag bytes anywhere; they are synthesised from constants in both binaries.

#### Step 1 — Confirm the binding

The driver's first IOCTL (`0x222004`, the register call) opens the calling process, queries `ProcessImageFileName`, reads the EXE off disk, finds the section named `.text\0`, and FNV-1a hashes its raw bytes. The expected hash is `0x6598ae16e4af8e05`. Any patch to the userland changes the hash and the driver returns `STATUS_ACCESS_DENIED`.

That binding is the static-solver's friend, not its enemy. The userland is unmodifiable, which means the synthesis logic and inputs are exactly what the disassembly says they are.

#### Step 2 — Read the driver's three IOCTLs

The dispatch lives in `EvtIoDeviceControl` at `0x1400011d0`. Each branch validates a 4-byte magic `0xe7de0322` and locks a global 32-slot PID table at `0x1400040f0`.

`0x222000` is the per-stage check. It reads `{stage, magic, session, random, fnv_hash}` from the user, finds the matching slot, compares `fnv_hash` against the stage's expected FNV-1a:

| Stage | Expected FNV-1a       | Reward                 |
|-------|-----------------------|------------------------|
| 0     | `0x41f59f05e7b2ab5d`  | `0x4d3a1f7b9e52c806`   |
| 1     | `0xf9ac95fed5fbf6a9`  | `0x71f4820d3cb96a15`   |
| 2     | `0xa4c25ee6cd04dc19`  | `0x0000000000000000`   |

On match, it folds `random XOR reward[stage]` into the output buffer. On stage 1 it also copies 16 fixed bytes from `0x1400032a0` (`effd350f14edd6913077a49a9a205409`) into `[buf+0x28]` regardless of FNV match. That is the only kernel-side data leak past the FNV gate.

`0x222008` is the final, which just echoes the slot's stage counter. The userland refuses to proceed unless it is 3.

#### Step 3 — Spot the VEH-driven IOCTL plumbing

The userland hides the three round-trips behind a vectored exception handler at `0x140001230` registered via `AddVectoredExceptionHandler`. At startup the program allocates `0x3000` bytes of heap and saves three pointers (`heap+0x10`, `heap+0x1010`, `heap+0x2010`) to globals at `0x1400056d0/d8/e0`. Reading any of them later triggers an access violation. The VEH inspects the exception address, decides which stage it is, FNV-1a hashes the matching `%63s` input, sends `IOCTL_0x222000`, and folds the response.

The trick is purely an obfuscation: the IOCTLs happen at confusing places in the trace, and the import-table view shows only the direct `DeviceIoControl(0x222004)` from main. The VEH structure does not affect the cryptographic shape.

#### Step 4 — Compute the per-stage slot constants

For each stage the userland sends `fnv_user` (FNV-1a of the user's typed answer) and an unrelated random `r14`, and receives `r14 XOR reward_returned`. It XORs the response with `r14` (cancelling the randomness) and then XORs with `fnv_user`. So the bytes that land at `0x1400056f0`, `0x1400056f8`, `0x140005700` are:

```
slot_i = fnv_user[i]  XOR  reward_returned[i]
```

When the user types the right answer, `fnv_user[i] == EXPECTED_FNV[i]` and `reward_returned[i] == reward[i]`. So each slot ends up holding the constant `EXPECTED_FNV[i] XOR reward[i]`. Both halves of that XOR are baked into the binaries; the user does not need to guess the duck phrases at all.

#### Step 5 — Build `secret1` correctly

The synthesis at `0x140001687..0x140001ade` works on four blobs:

- `secret1` (16 bytes from `.rdata` at `0x1400034e0`), but the copy at `0x140001e00` does `xor al, 0x55` on every byte, and the parallel SIMD path at `0x140001e16` is `xorps xmm1, xmm0` against 16 adjacent `0x55` bytes at `0x1400034f0`. The bytes that arrive at the synthesis are `secret1 XOR 0x55_pad`.
- `kernel_extra` (16 bytes the driver wrote on stage 1).
- The three 8-byte slot values `A`, `B`, `C` from step 4.

Skipping the `0x55` XOR leaves positions 0 and 18 of the flag off by exactly `0x55` (which gives `#1t{...%1ngp0ng...}`, close enough to look right, easy enough to miss in a first pass).

#### Step 6 — Replay the XOR fold

A dense block of `mov byte [rsp/rbp+off], reg` writes tiles `A`, `B`, `C` four times each across three 32-byte stack buffers. A SIMD round computes:

```
xmm1 = data_C[1:17] XOR secret1 XOR (secret1[1:16] || kernel_extra[0])
```

written to `[rbp-0x2f..-0x1f]`. A 15-byte XOR loop fills `[rbp-0x1f..-0x11]` with:

```
data_C[17..31] XOR kernel_extra[1..15] XOR kernel_extra[0..14]
```

Two more XMM XORs fold `[rsp+0x40..0x60]` into `[rbp-0x70..-0x50]` against the intermediate buffer at `[rbp-0x30..-0x10]`. Finally the print loop emits 32 putchars:

```
flag[i] = [rbp-0x70+i] XOR [rsp+0x60+i]
```

#### Step 7 — Watch the stray `mov`

The dense byte-by-byte interleave fills 31 of the 32 rbp slots. The 32nd is filled by a single `mov [rbp-0x51], al` at `0x140001a75`, after the slow XMM phase has loaded the `[rbp-0x6f]` window into `xmm1`. Forget that write and the 15-byte XOR loop reads zero on the last iteration, which propagates into the final XMM round and corrupts the trailing `}` to `0xd9`.

#### Step 8 — Run the solver and read the flag

The solver pulls every constant directly from the two PE images, verifies the FNV-1a-of-`.text` binding, and replays the synthesis without ever running either binary:

```bash
/tmp/v1t-ducks-venv/bin/python solve.py
```

```
[+] FNV-1a(.text) = 0x6598ae16e4af8e05  (matches driver expectation)
[+] stage rewards = 0x4d3a1f7b9e52c806, 0x71f4820d3cb96a15, 0x0000000000000000
[+] 32-byte flag:
    v1t{kn0w_h0w_to_p1ngp0ng_ducks!}
```

Per-challenge README and solver: [reverse/ducks-ping-pong](https://github.com/Abdelkad3r/V1t-CTF-2026/tree/master/reverse/ducks-ping-pong).

## Web

### HVL (MCKeyyyyyy)

A tribute site to the Hmong rapper MCK, fronted by Cloudflare. The page is a YouTube-style player with an embedded SRT subtitle block. The description literally says "Note this is a troll challenge" and there are two distinct stego layers in the page; only one of them is the flag.

#### Step 1 — Get past Cloudflare to identify the origin

Direct curl requests to `https://hvl.v1t.site/` are blocked by Cloudflare's managed challenge. Static asset paths slip through: `/favicon.ico` returns 404 with GitHub Pages headers (`x-github-request-id`, `x-served-by`, the `varnish` chain). That is enough to confirm the origin is GitHub Pages.

A GitHub search for `hvl v1t` points at the source repo, which contains the page, the font, and the background MP3.

#### Step 2 — Spot the Variation Selectors stego (and dismiss it)

The page embeds the subtitle file inline as `embeddedSrt`. Scanning that string for code points in the Variation Selectors Supplement block (`U+E0100-U+E01EF`) yields nine invisible characters tacked onto SRT line 33, right after the 🔥 emoji:

```
U+E0158 U+E0155 U+E015C U+E015C U+E015F U+E0110 U+E0163 U+E0159 U+E0162
```

Subtracting offset `0xE00F0` gives printable ASCII:

```
h e l l o   s i r
```

Submitting `v1t{hello_sir}` and neighbours is wrong on purpose. This is the troll layer.

#### Step 3 — Inspect the font

The page declares the font with:

```html
<style>
  @font-face {
    font-family: "Noto Sans";
    src: url("./NotoSans-Regular.ttf") format("truetype");
  }
</style>
```

The file name lies. The font's internal `name` table reads:

```
nameID 1 -> Emoji To AZ
nameID 4 -> Emoji To AZ Regular
nameID 6 -> Emoji-To-AZ-Regular
```

This is Google's "Emoji To AZ" demo font, a TrueType file whose `cmap` rewrites a handful of emoji code points to ASCII glyph names. The `@font-face` rule re-labels it as `"Noto Sans"` so the browser applies it to every text element, including the emoji block in the SRT.

#### Step 4 — Decode through the cmap

The relevant `cmap` entries are:

```
U+1F600 -> v   U+1F601 -> {   U+1F602 -> 4   U+1F603 -> 1
U+1F604 -> t   U+1F605 -> 0   U+1F606 -> g   U+1F607 -> c
U+1F609 -> v   U+1F60A -> m   U+1F60C -> l   U+1F60D -> }
U+1F642 -> k   U+1F643 -> h   U+1F923 -> t   U+1F972 -> _
```

The five emoji lines in the SRT (😀😃😄😁😆 / 😅😂🤣 / 🥲😊😇 / 🙂🥲🙃 / 😉😌😍) substitute through that table to:

```
v 1 t { 4   0 4 t   _ m c   k _ k   v m }
```

Collapsing inter-emoji whitespace and reading left-to-right gives `v1t{g04t_mck_hvl}`. Visiting the page in any browser that respects the `@font-face` rule shows the flag directly under the lyrics. The troll is that you only see it if you ignore the file name and trust the rendering.

#### Step 5 — Automate the substitution

The solver wires both decodings together so the result is reproducible without a browser:

```bash
/tmp/v1t-hvl-venv/bin/python solve.py
```

```
[*] Red herring (Variation Selectors Supplement):
     'hello sir'
[*] Real flag (Emoji-To-AZ font cmap on SRT emojis):
     v1t{g04t_mck_hvl}
```

Per-challenge README and solver: [web/hvl](https://github.com/Abdelkad3r/V1t-CTF-2026/tree/master/web/hvl).

### Duck Nettool Revenge

A small Flask "NetTool" wrapping `ping -c 1 <target>`. The "revenge" framing matters: an earlier version of the challenge had an unintended solve, and this iteration tightens the filter. The author's hint "Flag on the source code" reads like a giveaway right up until the only place the literal flag appears in the source is inside the module docstring of `app.py`, which the deployer rewrites at build time.

#### Step 1 — Read the filter

The only check the user-controlled `target` has to pass is:

```python
ALLOWED_TARGET_RE = re.compile(r"^(?!.* \.)(?!.*\. )[i0-9.;?/ ]+$")
```

The character class is eleven characters: `i 0 1 2 3 4 5 6 7 8 9 . ; ? /` and space. The two lookaheads forbid `<space><dot>` and `<dot><space>` anywhere. There is no length cap; there is no separate blocklist that matters here (the two base64 strings in `BLOCKED_TOKENS` are unreachable by anything the regex allows, so they are decoration).

The two characters that actually matter to the shell are `;` (command chain) and `?` (single-character wildcard in glob expansion). The challenge stops being "can I inject a command" (that part is free) and becomes "what absolute path can I express using only `i`, digits, `.`, `/`, `?`, and space, and what useful output does it print?"

#### Step 2 — Inventory what survived the Dockerfile prune

The `Dockerfile` deletes almost everything in `/bin`, `/usr/bin`, `/usr/local/bin`, leaving only:

```
/bin/sh, /bin/ping
/usr/bin/sh, /usr/bin/ping
/usr/local/bin/python, /usr/local/bin/python3, /usr/local/bin/python3.11, /usr/local/bin/gunicorn
```

No `cat`, no `head`, no `xxd`, no `cp`, no `awk`, no `grep`. And `PATH` is forced to `/bin:/usr/bin` so the surviving `python*` binaries must be addressed by absolute path.

`flag.txt` is `chmod 0000` and `flag.py` is `print('FLAG')`, both owned by root. Reading `flag.txt` is not the path. The actual readable target, as the `ctf` user, is `/app/app.py`. The build-time deployer rewrites every `v1t{fake_flag}` token in the source tree to the real flag, and the module docstring at the top of `app.py` contains exactly that token.

#### Step 3 — Pick the tool that prints a docstring

Of the surviving binaries, only the `python*` family will read a file and emit its contents to stdout without help. `-c` and `-m` are out (`-` is not in the alphabet), so we have to invoke a stdlib module by its file path.

`dis.py` is the cleanest pick. Running `python3 dis.py /path/to/script.py` shows the module's first `LOAD_CONST`, which is the docstring, verbatim, repr'd inline. `tokenize.py` and `tabnanny.py` also work but their filenames do not glob uniquely in a pruned `python:3.11-slim` image (`?????i??.py` matches `tokenize.py`, `datetime.py`, and `tempfile.py`).

So the operational plan is:

```
/usr/local/bin/python3   /usr/local/lib/python3.11/dis.py   /app/app.py
```

#### Step 4 — Spell the three paths in only `?`, `/`, `i`, digits, `.`

Each `?` matches exactly one filename character (not `/`). The shell expands each `?`-only template into every existing path that fits. The challenge is keeping each expansion unique.

- `/usr/local/bin/python3` is `3 / 5 / 3 / 7`. The naive `/???/?????/???/???????` matches it, and one other path on the box (see step 5).
- `/usr/local/lib/python3.11/dis.py` is `3 / 5 / 3 / 10 / 6`, with `python3.11` as `7+.+2` and `dis.py` as `3+.+2`. The free `i` in the alphabet plus `dis.py`'s `i` at position 1 makes `/???/?????/???/???????.??/?i?.??` unique.
- `/app/app.py` is `3 / 6`. `/???/???.??` matches it.

Composed payload:

```
8.8.8.8;/???/?????/???/??????? /???/?????/???/???????.??/?i?.?? /???/???.??
```

`8.8.8.8` keeps the original `ping -c 1` valid; `;` ends it; the three globs become the next command. That string passes `ALLOWED_TARGET_RE.fullmatch`.

#### Step 5 — Fix the `diskseq` glob collision

The first try against the live target returned:

```
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
...
/bin/sh: 1: /sys/block/vda/diskseq: Permission denied
```

`ping` ran fine. The next command was `/sys/block/vda/diskseq`, not python3. The shell sorts glob expansions alphabetically, and on the container's filesystem two paths match `/???/?????/???/???????`:

```
/sys/block/vda/diskseq      (3 / 5 / 3 / 7)
/usr/local/bin/python3      (3 / 5 / 3 / 7)
```

`s` sorts before `u`, so `diskseq` wins. The shell tries to execute the sysfs file, which is non-executable, and the rest of the line gets fed to it as arguments. The python3 binary never runs.

Anchoring the python3 glob with the trailing literal `3` removes the collision (`/usr/local/bin/python3` ends in `3`; `diskseq` ends in `q`):

```
8.8.8.8;/???/?????/???/??????3 /???/?????/???/???????.??/?i?.?? /???/???.??
```

#### Step 6 — Clear Cloudflare and read the docstring

`api.v1t.site` is fronted by a Cloudflare managed challenge (the JavaScript proof-of-work variant). `curl`, `curl_cffi --impersonate chrome131`, and `cloudscraper` all bounce off with "Just a moment..." Even headless Chrome via Playwright never cleared from a flagged IP. What worked was the same Chrome binary run visibly, with a fresh user-data-dir, with remote debugging on:

```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --user-data-dir=/tmp/chrome-cdp \
  https://api.v1t.site/
```

Once Cloudflare cleared and the title flipped from `Just a moment...` to `NetTool v1`, Playwright connected over CDP, filled the form, submitted, and read the `<pre>` back. The dis.py output included the docstring with the real flag:

```
LOAD_CONST  0  ("\nTODO / Deployment fixes\n\n
        - The challenge is currently not solvable because:\n
        ...
        - The SHA-256 hash of v1t{br0_th15_15_duck} is not realistically
          brute-forceable,\n  so the init Bash script also needs to be
          fixed.\n")
```

Flag: `v1t{br0_th15_15_duck}`. Per-challenge README and solver: [web/duck-nettool-revenge](https://github.com/Abdelkad3r/V1t-CTF-2026/tree/master/web/duck-nettool-revenge).

The deeper lesson is that allowlist filters that admit `;` and `?` are not filters at all. The shell metacharacter set is large and well-known, and a regex that allows `?` plus `/` plus digits is a glob primitive. Any filter that wants to be meaningful has to either tokenise (split, escape, reassemble) or use `subprocess` with a list and no shell.

## Cross-cutting defender notes

Four patterns recur across the V1t track and translate directly into production-code review heuristics.

**One load-bearing primitive, lots of decoration.** Every challenge in the track has one piece of code that actually constrains the flag and a pile of distractions around it. The `MIX_HASH` opcodes in Sealed Input Verifier, the duck phrases in Ducks Ping-Pong, the Variation Selectors stego in HVL, the `BLOCKED_TOKENS` base64 in Duck Nettool Revenge, the packer section names in Sealed Input Verifier: none of them is the bug. Mapping the actual primitive first and then walking the trace is faster than reverse-engineering every decoy. In production code review the same heuristic applies: when an auditor finds three encryption helpers, two validation layers, and a token denylist, the bug is almost always in the one piece that touches user input directly, not in the layered defences around it.

**Algebraic structure in RSA primes is the bug.** Hextrap is a textbook case of generating a prime through "interesting" algebra (Eisenstein norms in this build, but any CM-style or `j = 0`-related construction has the same shape), and the moment a prime carries hidden algebraic structure, some group order (Pollard p-1, Williams p+1, ECM on a twist) becomes smooth and the modulus factors in seconds rather than years. The defence is mechanical: generate primes by uniformly sampling and Miller-Rabin testing. Any other generator is an opportunity for a stealthy backdoor or a CTF-style trapdoor. A production check that would have caught this: the modulus' size in bits looks fine, but ECM stage-1 with `B1 = 2^15` finishes in under a minute and yields a factor.

**Shell allowlists with `?`, `;`, or `*` are not allowlists.** Duck Nettool Revenge's regex permits only 11 characters but two of them are `;` and `?`. `;` chains a shell command, `?` is a single-character glob, and the combination is a path-construction primitive. Any filter that wants to actually constrain shell input either has to tokenise (split on whitespace, validate each token against an absolute-path allowlist, reassemble) or has to abandon `shell=True` entirely and call `subprocess.run([...], shell=False)`. A regex that accepts `?` is allowing path globbing the same way a regex that accepts `'` and `;` would be allowing SQL injection.

**Font files and Unicode private-use blocks are stego primitives.** HVL is two stego layers stacked: a private-use Unicode block (Variation Selectors Supplement) as the red herring, and a custom font `cmap` aliased to a trusted name as the real channel. Both are common patterns in real-world phishing kits (private-use code points hide commands inside chat messages; custom fonts remap deceptive text to plausible glyphs). The defensive review for either is the same: render the document in two engines and diff the resulting glyphs; flag any custom `@font-face` that aliases to a name that does not match the file's internal `name` table.

## Frequently asked questions

### What is V1t CTF 2026?

V1t CTF 2026 is a Jeopardy-style CTF whose challenges span cryptography, reverse engineering, web, misc, and (in the wider event) other categories. The flag prefix is `v1t{...}` (sometimes uppercase `V1T{...}`, as in China Crack? - 202). The eight challenges covered in this writeup are mirrored with per-challenge READMEs, artifacts, and solver scripts at [Abdelkad3r/V1t-CTF-2026](https://github.com/Abdelkad3r/V1t-CTF-2026).

### How do you recover the ZUC keystream in China Crack? - 202 without the key?

Three published leaks make the key unnecessary. `leak2 = ((w * 0x45d9f3b) ^ (w >> 16)) & 0xffff` keeps only the low 16 bits of the product, which means the multiplication only depends on the low 16 bits of the word. For each candidate `low` (16-bit), the matching `high` is forced by `leak2[i] ^ ((low * 0x45d9f3b) & 0xffff)`. That collapses each word's search space from `2^32` to `2^16`. `leak3` (popcount) filters those candidates by bit count; the ciphertext filters word 0 by demanding the plaintext start with `V1T{`; `leak1` links adjacent words; and `crc32(flag[:16])` pins down any remaining ambiguity in the first four words. The chain is then unique.

### Why does ECM factor the Hextrap modulus so quickly?

The prime `p` is generated as `p = Norm(z - 1)` for a 2^15-smooth Eisenstein integer `z`. That construction creates a prime for which one sextic twist of a `j = 0` elliptic curve (`y^2 = x^3 + b`) has order related to `Norm(z)`, which is itself 2^15-smooth. Stage-1 ECM with scalar `M = product(prime_power) for prime_power <= 2^15` computes the identity element on the smooth twist modulo `p` while not doing so modulo `q`. In projective coordinates the identity sends the final `Z` to a multiple of `p`, so `gcd(Z, n) = p`. Sampling random `b` values cycles through the six twists; one of them is the smooth one.

### What is the FNV-1a binding in Ducks Ping-Pong?

The KMDF driver's first IOCTL opens the calling process, queries `ProcessImageFileName`, reads the userland EXE off disk, locates the section whose name is `.text\0`, and FNV-1a hashes its raw bytes (64-bit basis `0xcbf29ce484222325`, prime `0x100000001b3`). The expected hash is `0x6598ae16e4af8e05`. Any patch to the userland changes the hash and the driver returns `STATUS_ACCESS_DENIED`. The static solver does not have to defeat this binding; it confirms the hash from the unmodified EXE on disk and replays the synthesis from constants in both binaries.

### What does the Sealed Input Verifier 365-byte program actually do?

The 365 bytes decode (with `key = 0xa7` and the per-PC Murmur3 keystream) to 165 opcodes across eight live opcodes. Twenty-two `LOAD_INPUT / XOR_LIT / ADD_LIT / ROTL / XOR_LIT / ASSERT_EQ` blocks, one per input index in shuffled order, are followed by eleven `PAIR_ASSERT`s and one `EXIT 33`. Each per-index block inverts to `input[idx] = (rotr(e ^ c, r) - b) & 0xff ^ a`. The `MIX_HASH` (`0x5D`) opcodes update an independent byte at `[rbp-0xa]` that no later opcode reads, so they are dead state.

### Why is the flag in Tiny just `v1t{^}`?

Tiny has no string comparison anywhere in the binary. The only "check" is that the input's non-CR/LF byte sum, used as a 16-bit key, must decode the embedded 226-word RLE bitmap into a valid 10-row, 140-column image. Only `key = 625` satisfies every structural condition (header `[10, 1, 1]`, row counts matching descriptor bytes, run lengths summing to 140, all words consumed). The flag wrapper `v1t{}` sums to 531; the remaining single payload byte is `625 - 531 = 94 = ord("^")`. The flag's own byte sum is the key, so the flag passes its own check.

### What is the Emoji To AZ font used for in HVL?

It is Google's demo font whose `cmap` rewrites a handful of emoji code points to single ASCII letters. The page declares `@font-face { font-family: "Noto Sans"; src: url("./NotoSans-Regular.ttf") }`, but the file's internal `name` table identifies it as "Emoji To AZ Regular". Any browser that respects the `@font-face` rule renders the SRT emoji block as the actual letters `v 1 t { 4 0 4 t _ m c k _ k v m }`, which collapses to `v1t{g04t_mck_hvl}`. The Variation Selectors Supplement stego that decodes to `hello sir` is a deliberate distraction.

### Why does `?` defeat the 11-character allowlist in Duck Nettool Revenge?

The regex `^(?!.* \.)(?!.*\. )[i0-9.;?/ ]+$` permits `;` (shell command chain) and `?` (single-character glob in shell expansion). The combination is a path-construction primitive: `?` matches any single non-`/` filename character, and chained `?`s can spell out absolute paths from purely "neutral" characters. The Dockerfile prune leaves `python3`, `dis.py`, and `app.py` reachable by globs, so the payload `8.8.8.8;/???/?????/???/??????3 /???/?????/???/???????.??/?i?.?? /???/???.??` runs `python3 dis.py /app/app.py` and prints the module docstring. The deployer has rewritten `v1t{fake_flag}` to the real flag in that docstring.

### What is the `diskseq` collision and how do you avoid it?

On the live container, `/sys/block/vda/diskseq` and `/usr/local/bin/python3` both match the glob `/???/?????/???/???????` (both are 3/5/3/7 characters). The shell sorts glob expansions alphabetically; `s` sorts before `u`, so `diskseq` wins. The first attempt ran `/sys/block/vda/diskseq` instead of `python3`. Anchoring the python3 glob with a literal trailing `3` (turning it into `/???/?????/???/??????3`) removes `diskseq` from the match set (it ends in `q`, not `3`) while keeping `python3`.

### How did you solve these without the live target?

Seven of eight (both crypto, both reverse with binaries, Tiny, Ducks Ping-Pong, Sealed Input Verifier, HVL) were solved entirely statically from the handouts. Duck Nettool Revenge required the live API because the docstring lives in the deployed image and is only readable from the running container. Cloudflare's managed challenge forced a real visible-browser session before the API would accept the payload; Playwright over CDP handled the form submission once Cloudflare cleared.

### What's the broader lesson from the V1t track?

Every challenge isolates one load-bearing primitive (an algebraic trapdoor, a byte-sum key, a stack-VM chain, a font cmap, a shell glob) and dresses it in decoration (decoy opcodes, fake packer sections, stego red herrings, blocked-token denylists). The skill is identifying which one piece of code constrains the flag and ignoring everything else. The same skill is exactly what production code review wants: do not get lost in the layered defences around user input. Find the one place that touches the input directly and audit it carefully.

### Where can I find the solver scripts?

Per-challenge READMEs and complete solver scripts are at [Abdelkad3r/V1t-CTF-2026](https://github.com/Abdelkad3r/V1t-CTF-2026). Each challenge's `solve.py` is standalone (only `pyfiglet`, `pefile`, `fonttools`, `pycryptodome`, or stdlib depending on the challenge) and replays the recovery from the published artifacts.

## Closing notes

Eight challenges, eight distinct primitives, all of them mechanical once the load-bearing one is identified. The crypto track teaches "structure in a prime is the bug" and "leak functions can encode their own decryption procedure." The reverse track teaches "tiny ELFs whose only validation is a byte-sum self-reference are common puzzle shapes," "TCC binaries in packer-section costume hide stack VMs that invert in a one-liner," and "kernel-driver flag synthesis works on constants both binaries already contain." The web track teaches "font cmap aliasing is the modern visible-stego primitive" and "any allowlist regex that accepts `;` and `?` is a path-construction primitive."

For more crypto writeups on this site, the [TraceBash CTF 2026 crypto writeup](/ctf-writeups/tracebash-ctf-2026-crypto-writeup/) covers a small-subgroup Diffie-Hellman, a shared 512-bit RSA prime recovered by `gcd(n1, n2)`, and a harmonic-XOR keystream recovered from audio. The [Anti-Slop CTF 2026 crypto writeup](/ctf-writeups/anti-slopctf-2026-crypto-writeup/) covers a Bellcore CRT fault and a few other lattice-leaning constructions.

For reverse engineering, the [Anti-Slop CTF 2026 reverse writeup](/ctf-writeups/anti-slopctf-2026-reverse-writeup/) and the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) walk similar VM-recovery and binary-RE patterns. For web, the [Anti-Slop CTF 2026 web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/) covers a related set of source-recovery and shell-injection chains. The full [CTF writeups index](/ctf-writeups/) is the home for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is V1t CTF 2026?","acceptedAnswer": {"@type": "Answer","text": "V1t CTF 2026 is a Jeopardy-style CTF whose challenges span cryptography, reverse engineering, web, misc, and other categories. The flag prefix is v1t{...} (sometimes uppercase V1T{...}, as in China Crack? - 202). The eight challenges covered in this writeup are mirrored with per-challenge READMEs, artifacts, and solver scripts at github.com/Abdelkad3r/V1t-CTF-2026."}},
    {"@type": "Question","name": "How do you recover the ZUC keystream in China Crack? - 202 without the key?","acceptedAnswer": {"@type": "Answer","text": "Three published leaks make the key unnecessary. leak2 = ((w * 0x45d9f3b) ^ (w >> 16)) & 0xffff keeps only the low 16 bits, so the multiplication only depends on the low 16 bits of the word. For each candidate low, the matching high is forced. That collapses each word's search from 2^32 to 2^16. leak3 (popcount) filters, ciphertext demands V1T{ in word 0, leak1 links adjacent words, crc32(flag[:16]) pins the first four words. The chain is then unique."}},
    {"@type": "Question","name": "Why does ECM factor the Hextrap modulus so quickly?","acceptedAnswer": {"@type": "Answer","text": "The prime p is generated as p = Norm(z - 1) for a 2^15-smooth Eisenstein integer z. That construction makes one sextic twist of a j = 0 elliptic curve y^2 = x^3 + b have order related to Norm(z), which is itself 2^15-smooth. Stage-1 ECM with scalar M = product(prime_power) for prime_power <= 2^15 sends a point to infinity modulo p but not modulo q, so gcd(Z, n) = p. Random b values cycle through the six twists; one is smooth."}},
    {"@type": "Question","name": "What is the FNV-1a binding in Ducks Ping-Pong?","acceptedAnswer": {"@type": "Answer","text": "The KMDF driver's first IOCTL opens the calling process, queries ProcessImageFileName, reads the userland EXE off disk, locates the .text section, and FNV-1a hashes its raw bytes (basis 0xcbf29ce484222325, prime 0x100000001b3). Expected hash 0x6598ae16e4af8e05. Any patch to the EXE changes the hash and the driver returns STATUS_ACCESS_DENIED. The static solver confirms the hash from the unmodified EXE on disk and replays the synthesis from constants in both binaries."}},
    {"@type": "Question","name": "What does the Sealed Input Verifier 365-byte program actually do?","acceptedAnswer": {"@type": "Answer","text": "The 365 bytes decode (key = 0xa7, per-PC Murmur3 keystream) to 165 opcodes across eight live opcodes. Twenty-two LOAD_INPUT/XOR_LIT/ADD_LIT/ROTL/XOR_LIT/ASSERT_EQ blocks, one per input index in shuffled order, then eleven PAIR_ASSERTs and one EXIT 33. Each per-index block inverts to input[idx] = (rotr(e ^ c, r) - b) & 0xff ^ a. MIX_HASH (0x5D) updates a byte no later opcode reads, so it is dead state."}},
    {"@type": "Question","name": "Why is the flag in Tiny just v1t{^}?","acceptedAnswer": {"@type": "Answer","text": "Tiny has no string comparison. The only check is that the input's non-CR/LF byte sum, used as a 16-bit key, must decode the embedded 226-word RLE bitmap into a valid 10-row, 140-column image. Only key 625 satisfies every condition. v1t{} sums to 531; the remaining payload byte is 625 - 531 = 94 = ord('^'). The flag's own byte sum is the key, so the flag passes its own check."}},
    {"@type": "Question","name": "What is the Emoji To AZ font used for in HVL?","acceptedAnswer": {"@type": "Answer","text": "Google's demo font whose cmap rewrites a handful of emoji code points to single ASCII letters. The page declares @font-face with src NotoSans-Regular.ttf, but the file's internal name table identifies it as Emoji To AZ Regular. Browsers render the SRT emoji block as v 1 t { 4 0 4 t _ m c k _ k v m }, which collapses to v1t{g04t_mck_hvl}. The Variation Selectors stego that decodes to hello sir is a deliberate red herring."}},
    {"@type": "Question","name": "Why does ? defeat the 11-character allowlist in Duck Nettool Revenge?","acceptedAnswer": {"@type": "Answer","text": "The regex permits ; (command chain) and ? (single-character shell glob). Combined, they are a path-construction primitive. The Dockerfile prune leaves python3, dis.py, and app.py reachable by globs, so the payload 8.8.8.8;/???/?????/???/??????3 /???/?????/???/???????.??/?i?.?? /???/???.?? runs python3 dis.py /app/app.py and prints the module docstring. The deployer has rewritten v1t{fake_flag} to the real flag v1t{br0_th15_15_duck} in that docstring."}},
    {"@type": "Question","name": "What is the diskseq collision and how do you avoid it?","acceptedAnswer": {"@type": "Answer","text": "On the live container, /sys/block/vda/diskseq and /usr/local/bin/python3 both match /???/?????/???/??????? (both are 3/5/3/7 characters). The shell sorts glob expansions alphabetically; s sorts before u, so diskseq wins. The first attempt ran /sys/block/vda/diskseq instead of python3. Anchoring the glob with a literal trailing 3 (/???/?????/???/??????3) removes diskseq (ends in q) but keeps python3."}},
    {"@type": "Question","name": "How did you solve these without the live target?","acceptedAnswer": {"@type": "Answer","text": "Seven of eight were solved entirely statically from the handouts. Duck Nettool Revenge required the live API because the docstring lives in the deployed image. Cloudflare's managed challenge forced a real visible-browser session; Playwright over CDP handled the form submission once Cloudflare cleared."}},
    {"@type": "Question","name": "What's the broader lesson from the V1t track?","acceptedAnswer": {"@type": "Answer","text": "Every challenge isolates one load-bearing primitive (an algebraic trapdoor, a byte-sum key, a stack-VM chain, a font cmap, a shell glob) and dresses it in decoration (decoy opcodes, fake packer sections, stego red herrings, blocked-token denylists). The skill is identifying which one piece of code constrains the flag and ignoring everything else."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs and complete solver scripts at github.com/Abdelkad3r/V1t-CTF-2026. Each challenge's solve.py is standalone (only pyfiglet, pefile, fonttools, pycryptodome, or stdlib depending on the challenge) and replays the recovery from the published artifacts."}}
  ]
}
</script>
