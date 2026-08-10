---
title: "scriptCTF 2026 Writeup: Misdirection & F\\*\\*K — Bacon Cipher Trap + Brainfuck Timing"
slug: "scriptctf-2026-writeup"
description: "Full scriptCTF 2026 writeup covering both released challenges: Misdirection (Cryptography, 160 pts) where a 115-bit blob rules out byte-decoding, splits cleanly into 23 five-bit groups, and only produces meaningful text under Bacon's original 24-letter alphabet (I/J and U/V shared) — the modern 26-letter mapping is the trap; and F\\*\\*K (Reverse Engineering, 454 pts) where a 28,786-byte Brainfuck program disguises 31 algebraic byte checks as noise, each shaped like `input += C; temp = A*K + B; input -= temp`, encoding the flag entirely in `[-]` clear-loop iteration count with no printable success output — the flag lives in the program's timing."
date: 2026-08-11T10:00:00Z
lastmod: 2026-08-11T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["scriptCTF 2026"]
tags:
  - "scriptctf"
  - "scriptctf 2026"
  - "script ctf"
  - "ctf writeup"
  - "cryptography"
  - "crypto"
  - "reverse engineering"
  - "reverse"
  - "bacon cipher"
  - "bacons cipher"
  - "classical cipher"
  - "historical alphabet"
  - "24 letter alphabet"
  - "5-bit encoding"
  - "brainfuck"
  - "brainfuck ctf"
  - "esoteric language"
  - "timing side channel"
  - "algebraic solver"
  - "brainfuck vm"
  - "ast folding"
  - "clear loop"
  - "modular arithmetic"
  - "ctf 2026"
  - "step by step writeup"
keywords:
  - "scriptctf 2026 writeup"
  - "scriptctf 2026 crypto writeup"
  - "scriptctf 2026 reverse writeup"
  - "scriptctf misdirection writeup"
  - "scriptctf funk writeup"
  - "bacon cipher 24 letter alphabet ctf"
  - "bacons original alphabet i j u v shared"
  - "5-bit binary bacon cipher writeup"
  - "115 bit blob divisible by 5"
  - "brainfuck timing side channel ctf"
  - "brainfuck algebraic reverse engineering"
  - "brainfuck clear loop iteration count flag"
  - "brainfuck ast folding solver"
  - "brainfuck comparison template ctf"
  - "brainfuck +[] infinite loop sentinel"
  - "scriptctf 2026 solutions"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/scriptctf-2026-writeup.png"
  alt: "scriptCTF 2026 writeup covering both released challenges — Misdirection is a 115-bit blob that rules out byte decoding by length, splits cleanly into 23 five-bit groups, but only produces meaningful text under Bacon's original 24-letter alphabet where I and J share a symbol and U and V share a symbol, revealing SCRIPTCTFNOTWHATITSEEMS which restores to scriptCTF{notwhatitseems}; and F**K is a 28,786-byte Brainfuck program that hides 31 algebraic byte checks of the form input += C then temp = A times K plus B then input -= temp inside deliberate visual noise, encodes the entire flag in the iteration count of the [-] clear loops with no printable success message, ends in a +[] infinite loop sentinel, and reveals scriptCTF{t1mm1ng_s1d$_ch@nn31} once the comparison template is recognized and folded"
---

**scriptCTF 2026** is a two-challenge micro-set that manages to teach the same lesson twice in radically different domains: **the first plausible interpretation of the data is the trap, and the challenge itself tells you so.** Misdirection is 115 bits of ASCII binary — a length that is not divisible by 8 but is divisible by 5, a shape that rules out byte-decoding before you write any code. Fold it into 23 five-bit groups and the "obvious" modern 26-letter Bacon mapping produces plausible-looking gibberish (`RCQIOSCSFMNSUHASISREELR`). Only Bacon's *original* 24-letter alphabet — the one where `I/J` and `U/V` share a symbol — collapses those groups into `SCRIPTCTFNOTWHATITSEEMS`. The flag name (*Misdirection*), the hint (*"It is not what it is"*), and the recovered plaintext (`NOT WHAT IT SEEMS`) all point at the same lesson.

F\*\*K, the reverse challenge, does the same thing at 28 kilobytes. The handout is 28,786 bytes of Brainfuck weaponized as visual intimidation — 8,376 `+` instructions, 5,273 `-` instructions, more than seven thousand pointer moves — but the brackets nest only two levels deep, and 395 of the operations survive after algebraic folding. Every check is one shape: `input += C; temp = A * K + B; input -= temp`, exactly zero net residual only when `expected = (A*K + B - C) mod 256`. There is no success message and the program ends on `+[]`, an infinite loop sentinel that hangs on any candidate. The flag is not printed by the program — it is encoded in **how quickly the program reaches that hang**, because `[-]` clears a nonzero cell one decrement at a time. The censored title itself hints at both the language and the "no swearing, so nothing printable" trick.

Handouts, per-challenge READMEs, and pure-stdlib solvers live at [Abdelkad3r/scriptCTF-2026](https://github.com/Abdelkad3r/scriptCTF-2026). This **CyberSecurity Elite** scriptCTF 2026 writeup walks both challenges end to end, emphasising the shape-first reasoning that turns each intimidating artifact into an ordinary parsing problem.

## Both challenges at a glance

| Challenge | Category | Points | Author | Flag |
|---|---|---:|---|---|
| [Misdirection](#misdirectionbacons-original-24letter-alphabet) | Cryptography | 160 | NoobMaster | `scriptCTF{notwhatitseems}` |
| [F\*\*K](#fkbrainfuck-as-a-timing-encoded-comparator) | Reverse Engineering | 454 | Connor Chang | `scriptCTF{t1mm1ng_s1d$_ch@nn31}` |

Two challenges, two categories, and one repeated pattern: the intended solve is always one deliberate step *below* the obvious first attempt. Reading the *shape* of the data before decoding it wins both.

---

## Misdirection — Bacon's original 24-letter alphabet

> *Flag:* `scriptCTF{notwhatitseems}`
>
> *Hint:* "It is not what it is."

The handout is a single line of 115 ASCII binary digits followed by a newline — the smallest possible cryptography artifact, which itself is a signal to read every byte of it carefully.

### Read the shape before the bytes

Basic triage of `enc.txt`:

```text
$ file challenge/enc.txt
challenge/enc.txt: ASCII text

$ wc -c -l challenge/enc.txt
       1     116 challenge/enc.txt

$ shasum -a 256 challenge/enc.txt
2f85d02b187ca89b88b826babbc68c76faf5cfcd080692fed47676d4fb4716ba  challenge/enc.txt
```

Stripping the newline leaves exactly 115 characters, each `0` or `1`:

```text
1000100010100000100001110100100001010010001010110001101100101010000111000001001001000100101000100100001000101110001
```

The instinctive first move on 115 bits is to slice them into bytes. Don't. Do the modular arithmetic first:

```text
115 mod 8 = 3     ← rules out a byte stream
115 mod 5 = 0     ← 5-bit groups fit exactly
115 / 5   = 23    ← 23 symbols
```

The choice of exactly 115 bits, not 112 or 120, is deliberate. Five-bit groups are the characteristic shape of two classical ciphers: telegraph Baudot codes and **Bacon's cipher**. The 23-symbol length is a reasonable phrase length for a CTF flag body plus wrapper — Baudot's shift-in / shift-out semantics would need extra symbols for figures. Bacon fits.

### Split into five-bit groups

Reading left to right:

```text
10001 00010 10000 01000 01110 10010 00010 10010
00101 01100 01101 10010 10100 00111 00000 10010
01000 10010 10001 00100 00100 01011 10001
```

Interpret each as a big-endian integer:

```text
17, 2, 16, 8, 14, 18, 2, 18, 5, 12, 13, 18,
20, 7, 0, 18, 8, 18, 17, 4, 4, 11, 17
```

Every value falls in `[0, 20]`, which is the second confirmation of the shape: a 26-letter alphabet would use indices up to 25, and none appear. The maximum index of 20 is exactly the range of Bacon's 24-letter table (`0..23`).

### The misdirection

The natural first attempt is to map `00000..11001` onto `A..Z` with `A = 0`. That produces:

```text
RCQIOSCSFMNSUHASISREELR
```

The result is *all letters, no obvious digrams, no obvious flag prefix*. It is exactly close enough to keep you trying — reverse the string, invert the bits, reverse each group, XOR with a constant. Every variation is more of the same. The problem is not the bit stream or the grouping; it is the alphabet.

### Bacon's original alphabet

Francis Bacon's biliteral cipher, published in *De Augmentis Scientiarum* (1623), predates the modern 26-letter English alphabet. Bacon used only **24 symbols** because two pairs of letters share a code:

```text
I / J  share one symbol
U / V  share one symbol
```

The lookup table becomes:

```text
index:     0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23
alphabet:  A B C D E F G H I K L  M  N  O  P  Q  R  S  T  U  W  X  Y  Z
```

Applying it to the 23 indices:

| # | Bits | Value | Letter |
|---:|:---:|---:|:---:|
| 0 | `10001` | 17 | `S` |
| 1 | `00010` | 2 | `C` |
| 2 | `10000` | 16 | `R` |
| 3 | `01000` | 8 | `I` |
| 4 | `01110` | 14 | `P` |
| 5 | `10010` | 18 | `T` |
| 6 | `00010` | 2 | `C` |
| 7 | `10010` | 18 | `T` |
| 8 | `00101` | 5 | `F` |
| 9 | `01100` | 12 | `N` |
| 10 | `01101` | 13 | `O` |
| 11 | `10010` | 18 | `T` |
| 12 | `10100` | 20 | `W` |
| 13 | `00111` | 7 | `H` |
| 14 | `00000` | 0 | `A` |
| 15 | `10010` | 18 | `T` |
| 16 | `01000` | 8 | `I` |
| 17 | `10010` | 18 | `T` |
| 18 | `10001` | 17 | `S` |
| 19 | `00100` | 4 | `E` |
| 20 | `00100` | 4 | `E` |
| 21 | `01011` | 11 | `M` |
| 22 | `10001` | 17 | `S` |

Concatenated:

```text
SCRIPTCTFNOTWHATITSEEMS
```

Split at the natural boundary and the plaintext resolves the title, the hint, and the flag body all at once:

```text
SCRIPTCTF | NOT WHAT IT SEEMS
```

### Restore the flag format

Bacon's alphabet cannot express braces, case, spaces, or underscores — it is a 24-symbol letter substitution and nothing else. The `SCRIPTCTF` prefix marks where the event wrapper ends; the remaining body is a continuous 14-letter phrase:

```text
NOTWHATITSEEMS
```

Applying scriptCTF's flag format without inventing separators:

```text
scriptCTF{notwhatitseems}
```

### Reproduce the solve

The [Python solver](https://github.com/Abdelkad3r/scriptCTF-2026/tree/main/crypto/misdirection/scripts) validates the input length, groups into five-bit symbols, applies the original 24-letter alphabet, and prints the flag using only the standard library:

```bash
python3 crypto/misdirection/scripts/solve.py
```

Output:

```text
Bacon plaintext: SCRIPTCTFNOTWHATITSEEMS
Flag: scriptCTF{notwhatitseems}
```

Passing `--show-groups` prints the full per-group derivation table above.

### Takeaway

**Read the length first, and read the historical alphabet before the modern one.** Both are the difference between a decoder that produces nonsense and a decoder that produces the flag. The modular arithmetic (`115 mod 8 = 3`, `115 mod 5 = 0`) forces the grouping without touching the bits. The Bacon vs. modern-alphabet distinction is the entire challenge — and both are documented in every reference on the cipher. The 160 points reward remembering that classical ciphers pre-date the modern English alphabet, not writing new code.

---

## F\*\*K — Brainfuck as a timing-encoded comparator

> *Flag:* `scriptCTF{t1mm1ng_s1d$_ch@nn31}`
>
> *Hint:* "ABSOLUTELY NO SWEARING IS PERMITTED"

The handout is a single file named `funk` — no ELF header, no shebang. It weighs 28,786 bytes. The censored title and the "no swearing" rule are the first two hints: the language uses only eight ASCII punctuation characters, and the phonetic joke lands only if the file *is* Brainfuck.

### Identify the language

```text
$ file challenge/funk
challenge/funk: ASCII text, with very long lines (28785)

$ sha256sum challenge/funk
c9aec8dacfeba0aa825b70fac870799ef22ef8190d5e9a4a7f2fc081e68f979c
```

Every non-whitespace byte belongs to `< > + - . , [ ]`, the complete Brainfuck instruction set. The raw counts are deliberately intimidating:

```text
+ : 8376       - : 5273
> : 7461       < : 7376
[ :  126       ] : 126
, :   38       . :    9
```

Two structural properties dispel the intimidation immediately. The brackets balance perfectly (126/126) and nest only **two levels deep** — no arbitrary control flow. And only 9 output instructions exist against 38 input instructions — the program reads far more than it writes.

### Establish the input length

A small instrumented Brainfuck VM confirms that only 31 of the 38 `,` instructions actually execute; the remaining 7 sit inside dead decoy loops whose control cells are already zero when the loop is reached.

The 31 live reads write sequentially to cells `0..30`:

```text
input[0]  -> cell 0
input[1]  -> cell 1
...
input[30] -> cell 30
```

That matches the scriptCTF flag format exactly: `scriptCTF{` is 10 bytes, `}` is one, leaving a 20-byte body — 31 bytes total.

### Fold the visual noise

Most of the 28 KB is algebraically redundant. Consecutive arithmetic collapses modulo 256:

```text
+++-+---++-   →   one net ADD (or SUB) of the summed constant
```

Pointer motion collapses the same way:

```text
>>>>><<<<<   →   no movement
```

Post-fold, only **395 top-level operations remain**. Every meaningful byte-check uses the same two-idiom template.

**Idiom 1 — multiply-and-transfer** (a temporary constant times a multiplier, deposited into the neighbouring cell):

```brainfuck
A [ - < K > ]
```

If the current cell starts at `A`, the loop decrements it to zero, adding `K` to the left neighbour each iteration. Net effect: left cell gains `A * K`.

**Idiom 2 — subtract-into-input** (drain the temporary into a distant input cell as subtraction):

```brainfuck
[ - <<...< - >...>> ]
```

Both the temporary and the far cell are decremented until the temporary reaches zero.

### Recover one target byte

Each byte check reduces to four constants — `C`, `A`, `K`, and `B` — with the shape:

```text
input += C                          ← additive offset
temporary = A * K + B               ← constructed constant
input -= temporary
residual = (input + C - (A*K + B)) mod 256
```

The residual is zero exactly when:

```text
expected = (A*K + B - C) mod 256
```

For input index 1, the constants come out to `C = 39, A = 8, K = 17, B = 2`, giving:

```text
expected = 8*17 + 2 - 39 = 99 = 'c'
```

That is the second byte of `scriptCTF`. Index 0 similarly:

```text
12*12 + 0 - 29 = 115 = 's'
```

The known `s` and `c` from the flag prefix confirm the formula and the byte-order convention before any unknown byte is decoded.

### Decode all 31 shuffled checks

The comparisons are not laid out in input order. Scanning the folded program for the comparison template, recording the current input-cell pointer, and sorting by that pointer produces the full table:

| Index | C | A | K | B | Target | Character |
|---:|---:|---:|---:|---:|---:|:---:|
| 0 | 29 | 12 | 12 | 0 | 115 | `s` |
| 1 | 39 | 8 | 17 | 2 | 99 | `c` |
| 2 | 73 | 2 | 93 | 1 | 114 | `r` |
| 3 | 17 | 4 | 30 | 2 | 105 | `i` |
| 4 | 75 | 6 | 31 | 1 | 112 | `p` |
| 5 | 83 | 7 | 28 | 3 | 116 | `t` |
| 6 | 33 | 10 | 10 | 0 | 67 | `C` |
| 7 | 84 | 2 | 84 | 0 | 84 | `T` |
| 8 | 61 | 2 | 65 | 1 | 70 | `F` |
| 9 | 22 | 6 | 24 | 1 | 123 | `{` |
| 10 | 76 | 9 | 21 | 3 | 116 | `t` |
| 11 | 22 | 7 | 10 | 1 | 49 | `1` |
| 12 | 43 | 4 | 38 | 0 | 109 | `m` |
| 13 | 29 | 10 | 13 | 8 | 109 | `m` |
| 14 | 82 | 5 | 26 | 1 | 49 | `1` |
| 15 | 43 | 5 | 30 | 3 | 110 | `n` |
| 16 | 54 | 10 | 15 | 7 | 103 | `g` |
| 17 | 65 | 6 | 26 | 4 | 95 | `_` |
| 18 | 27 | 5 | 28 | 2 | 115 | `s` |
| 19 | 61 | 10 | 11 | 0 | 49 | `1` |
| 20 | 32 | 12 | 11 | 0 | 100 | `d` |
| 21 | 49 | 2 | 42 | 1 | 36 | `$` |
| 22 | 77 | 8 | 21 | 4 | 95 | `_` |
| 23 | 29 | 9 | 14 | 2 | 99 | `c` |
| 24 | 22 | 6 | 21 | 0 | 104 | `h` |
| 25 | 45 | 2 | 54 | 1 | 64 | `@` |
| 26 | 71 | 6 | 30 | 1 | 110 | `n` |
| 27 | 73 | 11 | 16 | 7 | 110 | `n` |
| 28 | 74 | 8 | 15 | 5 | 51 | `3` |
| 29 | 87 | 7 | 19 | 3 | 49 | `1` |
| 30 | 23 | 9 | 16 | 4 | 125 | `}` |

Concatenating the target bytes:

```text
scriptCTF{t1mm1ng_s1d$_ch@nn31}
```

The `$` at index 21 and `@` at index 25 look like glyph-recognition guesses but are exact byte values derived from the arithmetic:

```text
index 21:  2*42 + 1 - 49 = 36  = '$'
index 25:  2*54 + 1 - 45 = 64  = '@'
```

No ambiguity, no hand-tuning.

### The timing channel — where the flag actually lives

Every comparison finishes with `[-]`, the standard Brainfuck idiom to clear the current cell by decrementing until zero. With wrapping 8-bit cells:

```text
input == target      residual 0x00 → 0 clear iterations
input == target + 1  residual 0x01 → 1 clear iteration
input == target − 1  residual 0xff → 255 clear iterations   ← wraparound
```

The program prints nothing on success. It ends with:

```brainfuck
+[]
```

`+` makes the current cell nonzero, `[]` loops forever on it without changing it. **Every candidate input hangs.** What differs is the *number of Brainfuck instruction steps* required to reach that sentinel — the flag is encoded entirely in that count.

Instrumented VM run on the recovered flag:

```text
steps to final +[] sentinel: 462101
program output before sentinel: b''
+1 mutation timing delta: min=2 max=2
−1 mutation timing delta: min=510 max=510
```

Mutate any single byte up by one → 2 extra steps. Down by one → 510 extra steps (255 iterations × 2 instructions per iteration). The recovered candidate is the **unique global minimum** across all 31 independent residual loops. The hint `t1mm1ng_s1d$_ch@nn31` — deliberately spelled *"timing side channel"* in leet — advertises the design in the flag itself.

### Reproduce the solve

The [Python solver](https://github.com/Abdelkad3r/scriptCTF-2026/tree/main/reverse/funk/scripts) parses the Brainfuck source into a folded AST, walks the tree to detect the four-constant comparison template, reconstructs every target byte, and validates the result with an instrumented 8-bit VM:

```bash
python3 reverse/funk/scripts/solve.py challenge/funk
```

Relevant output:

```text
flag: scriptCTF{t1mm1ng_s1d$_ch@nn31}
length: 31 bytes; input operations executed: 31
steps to final +[] sentinel: 462101
program output before sentinel: b''
+1 mutation timing delta: min=2 max=2
```

Only the standard library — no `pip install brainfuck`.

### Takeaway

**28 KB of Brainfuck is not 28 KB of logic** — it is a few hundred logic ops after algebraic folding, and every one of them fits the same four-constant template. The real hint is that the program has *no output*: a checker that never prints "correct" is never comparing against a stored string; it must be comparing structurally. Once the comparison template is recognised, decoding the flag is a one-loop scan over the AST. The 454 points reward two moves — recognising the language, and recognising that the difficulty is *bulk*, not *complexity*. The timing channel is the elegant flourish, not the attack: knowing the flag is the design goal is what tells you the algebra you're looking at is a comparator rather than a computation.

---

## Cross-cutting lessons from scriptCTF 2026

Two challenges, two categories, one repeated pattern:

- **The first plausible interpretation is the trap, and the challenge title tells you so.** *Misdirection*'s modern Bacon mapping produces letters that look almost meaningful. F\*\*K's raw instruction counts (8,376 `+`, 7,461 `>`) look like a lot of logic. Both are engineered to consume time from anyone who does not verify their assumptions first.
- **Read the shape before the content.** 115 bits is not 14 bytes — it is 23 five-bit groups. 28 KB of Brainfuck is not 28 KB of logic — it is 395 folded ops. In both cases the *modular arithmetic on the artifact size* rules out a whole class of decode strategies before any code is written.
- **Prefer the historical / structural reading over the modern / convenient one.** Bacon's cipher is 24 letters, not 26. Brainfuck arithmetic is `mod 256`, not two's-complement. When the "obvious" mapping produces near-nonsense, question the mapping, not the input.
- **Use known plaintext to validate the decoder before decoding the unknown.** The `scriptCTF` prefix confirms both the Bacon 24-letter table (`S=17, C=2, R=16, I=8...`) and the F\*\*K four-constant formula (`12*12 - 29 = 115 = 's'`) with zero ambiguity. A decoder that reproduces known plaintext is a decoder you can trust on the unknown body.
- **Silence is a signal.** F\*\*K prints nothing on success and hangs on every input. That is not a bug; it is the design. Whenever a program's success path is silent and its failure path is indistinguishable from its success path, look for the difference in **time**, **memory**, or **side effect** — not output.

## Reproduce it yourself

Both challenges ship a reproducible solver in the [scriptCTF 2026 repository](https://github.com/Abdelkad3r/scriptCTF-2026) under `<category>/<challenge>/`, each with a `challenge/` directory containing the original handout, a `scripts/` directory containing the pure-stdlib Python solver, and a detailed `README.md`.

- [`crypto/misdirection/`](https://github.com/Abdelkad3r/scriptCTF-2026/tree/main/crypto/misdirection) — 115-bit Bacon decoder using the original 24-letter alphabet, with an optional `--show-groups` derivation table.
- [`reverse/funk/`](https://github.com/Abdelkad3r/scriptCTF-2026/tree/main/reverse/funk) — Brainfuck AST folder, comparison-template extractor, and instrumented 8-bit VM that reports the step count to the `+[]` sentinel.

Browse the full [CTF writeups](/ctf-writeups/) archive for more cryptography and reverse engineering walkthroughs, or read the companion [STARPWN CTF 2026 writeup series](/ctf-writeups/starpwn-ctf-2026-writeup-part-1/) for a much larger set of space-comms and orbital-mechanics challenges from the same season.

---

*This writeup is part of the CyberSecurity Elite [scriptCTF 2026](/series/scriptctf-2026/) series. Challenge files, solver scripts, and step-by-step READMEs for both challenges are published at [github.com/Abdelkad3r/scriptCTF-2026](https://github.com/Abdelkad3r/scriptCTF-2026).*
