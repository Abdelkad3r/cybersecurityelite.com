---
title: "VuwCTF 2026 Reverse Engineering Writeup: Kaprekar's Constant XOR & a Rotated Morse Cipher"
slug: "vuwctf-2026-reverse-writeup"
description: "VuwCTF 2026 reverse engineering writeup covering both challenges: ilikewords (a stripped libcurl ELF whose 'random' XOR key is always 6174 — Kaprekar's constant — used to decode an obfuscated NYT Wordle URL, where the flag's %s is a fixed 'wordle' slice of the URL and the network key check is only a gate) and dotsbedashing (a stripped ELF that packs a rol8-obfuscated Morse alphabet table and a ror32 rolling-XOR encrypted target stream that decodes to the0world0says0hii)."
date: 2026-08-03T15:30:00Z
lastmod: 2026-08-03T15:30:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["VuwCTF 2026"]
tags:
  - "vuwctf"
  - "vuwctf 2026"
  - "ctf writeup"
  - "reverse engineering"
  - "reversing"
  - "stripped elf"
  - "kaprekar's constant"
  - "6174"
  - "xor obfuscation"
  - "libcurl"
  - "anti-debug"
  - "morse code"
  - "bit rotation"
  - "rol"
  - "ror"
  - "rolling xor"
  - "ghidra"
  - "static analysis"
  - "ctf 2026"
keywords:
  - "vuwctf 2026 reverse writeup"
  - "ilikewords vuwctf writeup"
  - "dotsbedashing vuwctf writeup"
  - "kaprekar constant 6174 xor key ctf"
  - "kaprekar routine reverse engineering"
  - "obfuscated url xor decode ctf"
  - "nyt wordle url reverse ctf"
  - "morse code table reverse engineering ctf"
  - "rol8 rotate encoded character ctf"
  - "ror32 rolling xor key stream ctf"
  - "stripped elf static analysis ctf"
  - "anti-debug time check ctf"
  - "network gate not source ctf flag"
  - "vuwctf reverse challenge"
  - "packed morse entry decode ctf"
toc: true
cover:
  image: "/images/articles/vuwctf-2026-reverse-writeup.png"
  alt: "VuwCTF 2026 reverse engineering writeup — two challenges covering ilikewords a stripped PIE ELF that links libcurl and prompts for a key where the key generator looks random using time srand and rand but always converges to 6174 Kaprekar's constant via the Kaprekar routine of max permutation minus min permutation and that constant 6174 is the seed of a walking XOR stream that decodes a 45-byte blob into the NYT Wordle URL template so the flag's percent-s slot is a fixed six-byte wordle slice of the URL at offset 28 and the network strncmp check is only a gate not the source of the flag; and dotsbedashing a stripped ELF that stores a Morse alphabet table whose character bytes are obfuscated with an 8-bit left rotate and an encrypted target stream at 0x40c0 decrypted with an initial key 0xb1e1e1f1 rotated right by one bit before each XOR yielding packed Morse entries that map back through the table to the inner text the0world0says0hii"
---

VuwCTF 2026's reverse engineering track was two stripped ELFs that both hide a
short answer behind a wall of *theatrical* computation. **ilikewords** (100 pts,
Easy) wraps its XOR key in `time()`/`srand()`/`rand()` to look random — but the
Kaprekar routine it runs always converges to the same integer, `6174`, and that
key decodes an obfuscated URL whose path segment *is* the flag's variable slot.
**dotsbedashing** (100 pts, Medium) packs a rotated Morse alphabet and a rolling
`ror32`-XOR target stream that decodes to the inner flag text. This writeup solves
both statically, step by step — no runtime, no network, no debugger.

Both binaries and the Python solvers are at
[Abdelkad3r/VuwCTF-2026](https://github.com/Abdelkad3r/VuwCTF-2026/tree/master/Reverse).
Companion posts from the same event:
[Cryptography](/ctf-writeups/vuwctf-2026-crypto-writeup/) and
[Forensics](/ctf-writeups/vuwctf-2026-forensics-writeup/).

## Challenges at a glance

| Challenge | Difficulty | Points | Core trick | Flag |
|---|---|---|---|---|
| ilikewords | Easy | 100 | Kaprekar's constant `6174` as XOR key → decode NYT Wordle URL | `VuwCTF{do_you_like_wordle_as_much_as_i?}` |
| dotsbedashing | Medium | 100 | `rol8` Morse table + `ror32` rolling-XOR stream | `VuwCTF{the0world0says0hii}` |

---

## Challenge 1 — ilikewords (Easy, 100 pts)

> "Every day is a new challenge. Embrace it."

A stripped, PIE `libcurl` binary that prompts for a key, checks it against
something fetched over the network, and prints the flag on success:

```console
$ file ilikewords
ilikewords: ELF 64-bit LSB pie executable, x86-64, ..., stripped
$ ./ilikewords
Please enter a key: guess
 > That is the incorrect key! Please try again.
```

The title screams Wordle — but we never need today's Wordle answer. The flag is
recoverable from the binary alone.

### Step 1 — Read the static landmarks

`strings` points straight at the interesting data:

```text
Please enter a key:
 > Well done! You have found the key!
VuwCTF{do_you_like_%s_as_much_as_i?}
":"
vkjmo!54kji1pdhrw~o3}ps2omy4krl{rx3m(49n0umrr      # 45-byte high-entropy blob
%d-%02d-%02d                                        # a YYYY-MM-DD format
```

Three things stand out: a **flag template with one `%s` slot**, a 45-byte
obfuscated blob (the URL the program will `curl`), and a date format used to
build the request.

### Step 2 — See that the flag `%s` is not the key

The `main` flow (at `0x1515`), condensed:

```c
key = gen_key();                            // 0x1b4c
decode_url(url_buf, key);                   // 0x187a -> writes URL into .bss
if (fetch_daily(response)) {                // libcurl
    if (compare_input(input)) {             // strncmp gate vs response
        strncpy(local, url_buf + 0x1c, 6);  // <-- 6 bytes at offset 28
        printf("VuwCTF{do_you_like_%s_as_much_as_i?}", local);
    }
}
```

The critical observation: the `%s` argument is **neither the user's key nor the
Wordle answer**. It's a fixed 6-byte slice of the URL buffer at offset `+0x1c`
(28–33). Whatever URL is built, bytes 28–33 are printed. Since the URL is a
`.../svc/wordle/v2/...` path, that slice is guaranteed to spell `wordle`. **The
key check is a gate, not a source.** Deriving the URL just confirms the offset —
and it's the fun part.

### Step 3 — The "random" XOR key is always 6174 (Kaprekar)

`gen_key` looks random but isn't:

```c
srand(time(NULL));
int k = 1000 + rand() % 9000;      // random 4-digit int
k = fix_repdigit(k);               // nudge 1111/2222/... off a repdigit
int prev = -1, curr = k;
while (prev != curr) {             // Kaprekar's routine
    prev = curr;
    curr = max_perm(digits(curr)) - min_perm(digits(curr));
}
return curr;
```

This is **Kaprekar's routine**: repeatedly replace `k` with
`max(perm) − min(perm)` of its digits. Every 4-digit non-repdigit converges — in
≤7 steps — to **6174, Kaprekar's constant**. The binary explicitly pushes
repdigits off first so the loop always terminates at 6174. The seed is pure
theatre; the XOR key is constant.

### Step 4 — Decode the URL with the walking key

`decode_url` XORs the 45-byte blob with a key that *walks* ±1 around the seed
`6174` on a mod-5 phase toggle (only the low byte of the key is ever used):

```python
# key seeded at 6174 (low byte 0x1E); ±1 with a mod-5 phase flip per byte
```

Applying it:

```text
vkjmo!54kji1pdhrw~o3}ps2omy4krl{rx3m(49n0umrr
        │  xor(walking key seeded at 6174)
        ▼
https://www.nytimes.com/svc/wordle/v2/%s.json
```

### Step 5 — Confirm the "wordle" offset

`main` fills the `%s` with a `YYYY-MM-DD` date and then copies 6 bytes from
`url_buf + 0x1c`:

```text
https://www.nytimes.com/svc/wordle/v2/2026-08-02.json
0         1         2         3
0123456789012345678901234567890123456789
                            ^^^^^^
                            offset 28..33 == "wordle"
```

So the flag template's `%s` resolves to `wordle`, independent of the date or the
network. The `strncmp` gate (5 bytes after the first `":"` in the response — the
`printDate`/solution field) is only what blocks the print path at runtime;
statically we skip it entirely:

```console
$ python3 solve.py
[+] key from Kaprekar: 6174
[+] decoded URL template: https://www.nytimes.com/svc/wordle/v2/%s.json
[+] URL[28:34] = 'wordle'
[+] FLAG = VuwCTF{do_you_like_wordle_as_much_as_i?}
```

### Flag

```text
VuwCTF{do_you_like_wordle_as_much_as_i?}
```

**Two nice tells.** The XOR loop contains two `time(NULL)` checks that `exit(1)`
if more than a second elapses between iterations — crude anti-single-step that
static analysis sidesteps. And the runtime gate compares **5** bytes (Wordle
answers are 5 letters) while the flag `strncpy` copies **6** — that mismatch is
the giveaway that the printed substring is a hard-coded window into the URL
buffer, not the user's key. Every day is a new challenge *for the gate*; the flag
is the same every day.

---

## Challenge 2 — dotsbedashing (Medium, 100 pts)

> A top secret encoded transmission has been captured! I bet it says something
> supeerrr dupeerrr important, if only we knew how to decode it :)

A stripped ELF that reads an inner value, validates it, and prints `VuwCTF{%s}`
around the accepted input:

```text
Please enter a flag below!
Well done! You found the flag :) Please submit the following:
VuwCTF{%s}
Incorrect flag, please try again!
```

Since the flag isn't fully static, we have to recover the inner value the
validator expects. The real work is in `check()` at `0x1352`.

### Step 1 — Decode the Morse table (an 8-bit rotate)

The title — *dots and dashes* — is the hint. A Morse alphabet table sits at
`.data:0x4020`, one 32-bit little-endian word per entry:

```text
bits 31..24  rotate amount
bits 23..16  encoded character byte
bits 15..8   Morse length
bits 7..0    Morse bits (0 = dot, 1 = dash)
```

The character byte is not stored plainly — it's recovered with an **8-bit left
rotate** using the top byte as the amount:

```python
char = rol8((entry >> 16) & 0xff, (entry >> 24) & 0xff)
```

Decoding all 36 entries reproduces the standard Morse layout for `a–z0–9`:

| Entry | Char | Morse bits | Morse |
|---|---|---|---|
| `0x01b00201` | `a` | `01` | `.-` |
| `0x034c0408` | `b` | `1000` | `-...` |
| `0x02590100` | `e` | `0` | `.` |
| `0x04470101` | `t` | `1` | `-` |
| `0x0118051f` | `0` | `11111` | `-----` |

This table maps each input character to its packed Morse entry; a character
missing from the table fails the check.

### Step 2 — Decrypt the target stream (ror32 rolling XOR)

The expected answer is stored encrypted. The initial key is the dword at
`.data:0x40b0`:

```text
key = 0xb1e1e1f1
```

The encrypted target begins at `.data:0x40c0`. For each dword, **rotate the key
right by one bit first, then XOR**:

```python
key = ror32(key, 1)
decrypted_entry = encrypted_entry ^ key
```

The decrypted dwords are packed Morse entries again. Mapping them back through
the table recovers the inner text:

```text
the0world0says0hii
```

(The `0`s are literal Morse digits — `VuwCTF{the0world0says0hii}` uses them as
word separators.)

### Step 3 — The verifier quirk (compare lengths, not patterns)

There's a bug in the comparison helper at `0x1637`. It tests a Morse bit and
compares the result against `0xffffffd3`:

```asm
shl esi, cl
and eax, edx
cmp eax, 0xffffffd3
setne cl
```

Because `eax` is always `0` or a power of two, it never equals `0xffffffd3`, so
the rendered temporary becomes all-`1` bytes of the same length. The runtime
check therefore effectively compares **Morse lengths**, not exact dot/dash
patterns — which admits alternate accepted strings with matching lengths.
Regardless, the intended decrypted target is unambiguous from the full
`(length, bits)` values.

### Step 4 — Solve and verify

```console
$ python3 solve.py
[+] binary: artifacts/dotsbedashing
[+] Morse table entries: 36
[+] initial XOR key: 0xb1e1e1f1
[+] decoded inner flag text: the0world0says0hii
[+] flag: VuwCTF{the0world0says0hii}
```

Confirmed against the original binary:

```console
$ printf '%s\n' 'the0world0says0hii' | ./dotsbedashing
 > Well done! You found the flag :) Please submit the following:
VuwCTF{the0world0says0hii}
```

### Flag

```text
VuwCTF{the0world0says0hii}
```

---

## Cross-cutting notes

**"Random" that always lands on the same value isn't random.** ilikewords seeds
with `time()` and calls `rand()`, then runs Kaprekar's routine — which collapses
every 4-digit non-repdigit to `6174`. Whenever a key derivation *looks* random
but feeds into a convergent numeric process (Kaprekar, digit sums to a fixed
point, repeated hashing to a cycle), compute the fixed point and treat the RNG as
decoration.

**Follow the flag's format-string argument, not the validation.** Both challenges
print `VuwCTF{...}` — but what fills the `%s` is the real question. In ilikewords
the `%s` is a hard-coded slice of the URL buffer, so the elaborate network gate
never touches the printed flag. Trace the exact pointer passed to `printf`; a
"gate" that blocks the print path is not necessarily the source of the printed
bytes.

**Obfuscated tables usually hide behind a rotate or a rolling key.** dotsbedashing
uses both: an `rol8` per-entry rotate to hide the character byte, and a `ror32`
rolling-XOR to hide the target stream. Bit-rotation of a byte/word by a
per-element amount, and a key that transforms (`ror`, `+=`, `^= prev`) between
elements, are the two most common homemade obfuscations — recognizing them turns
"encrypted blob" into a dozen lines of Python.

**Anti-debug timing checks only bite dynamic analysis.** ilikewords' two
`time(NULL)` guards `exit(1)` if you single-step slowly, but a static solver that
reimplements the loop in Python never runs them. When you see `time()` sprinkled
inside a transform loop, that's an anti-debug crumb, not part of the math.

**Read comparison constants carefully — bugs change the semantics.**
dotsbedashing's `cmp eax, 0xffffffd3` can never be true given the operands, which
silently downgrades an exact-pattern check to a length-only check. A verifier bug
can widen the accepted set; recover the intended answer from the full data, not
from what the buggy check happens to accept.

---

## Frequently Asked Questions

**Q: What is Kaprekar's constant and why is the ilikewords XOR key always 6174?**

Kaprekar's routine takes a 4-digit number, forms the largest and smallest numbers
from its digits, and subtracts them, repeating on the result. Every 4-digit
number that isn't a repdigit (1111, 2222, …) converges to **6174** in at most 7
iterations — that's Kaprekar's constant. ilikewords seeds a random 4-digit value,
nudges it off any repdigit, and runs the routine, so the result is always 6174.
The `time()`/`srand()`/`rand()` scaffolding is theatre; the XOR key is a constant.

**Q: Do I need today's Wordle answer to solve ilikewords?**

No. The flag's `%s` slot is filled by `strncpy(local, url_buf + 0x1c, 6)` — six
bytes at offset 28 of the decoded URL — which always spells `wordle` because the
URL path is `.../svc/wordle/v2/...`. The network `strncmp` against the Wordle
`printDate`/solution field is only a runtime gate that blocks the print path; it
does not supply the printed flag. Statically decoding the URL gives the flag
`VuwCTF{do_you_like_wordle_as_much_as_i?}` directly.

**Q: How is the character byte hidden in the dotsbedashing Morse table?**

Each 32-bit table entry stores a rotate amount (bits 31–24), an encoded character
byte (bits 23–16), a Morse length (bits 15–8), and Morse bits (bits 7–0). The
real character is recovered by an 8-bit left rotate of the encoded byte by the
rotate amount: `char = rol8((entry >> 16) & 0xff, (entry >> 24) & 0xff)`. Decoding
all 36 entries reproduces the standard `a–z0–9` Morse alphabet.

**Q: How do you decrypt the dotsbedashing target stream?**

The initial 32-bit key is `0xb1e1e1f1` at `.data:0x40b0`. For each encrypted dword
starting at `.data:0x40c0`, first rotate the key right by one bit and then XOR it
with the ciphertext dword: `key = ror32(key, 1); plain = enc ^ key`. The decrypted
dwords are packed Morse entries, which map back through the table to the inner
text `the0world0says0hii`.

**Q: What is the verifier bug in dotsbedashing?**

The comparison helper at `0x1637` executes `cmp eax, 0xffffffd3` where `eax` is
always 0 or a power of two, so the comparison is never equal. This makes the
rendered temporary all-ones of a fixed length, so the runtime check compares Morse
*lengths* rather than exact dot/dash patterns — meaning strings with the same
per-character Morse lengths are also accepted. The intended flag is still clear
from the full `(length, bits)` data: `the0world0says0hii`.

**Q: What are the flags for the VuwCTF 2026 reverse challenges?**

ilikewords: `VuwCTF{do_you_like_wordle_as_much_as_i?}`. dotsbedashing:
`VuwCTF{the0world0says0hii}`.

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is Kaprekar's constant and why is the ilikewords XOR key always 6174?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Kaprekar's routine takes a 4-digit number, forms the largest and smallest numbers from its digits, and subtracts them, repeating on the result. Every 4-digit number that is not a repdigit converges to 6174 in at most 7 iterations, which is Kaprekar's constant. ilikewords seeds a random 4-digit value, nudges it off any repdigit, and runs the routine, so the result is always 6174. The time, srand, and rand scaffolding is theatre; the XOR key is a constant."
      }
    },
    {
      "@type": "Question",
      "name": "Do I need today's Wordle answer to solve ilikewords?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "No. The flag's %s slot is filled by copying six bytes at offset 28 of the decoded URL, which always spells wordle because the URL path is /svc/wordle/v2/. The network strncmp against the Wordle printDate or solution field is only a runtime gate that blocks the print path; it does not supply the printed flag. Statically decoding the URL gives the flag VuwCTF{do_you_like_wordle_as_much_as_i?} directly."
      }
    },
    {
      "@type": "Question",
      "name": "How is the character byte hidden in the dotsbedashing Morse table?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Each 32-bit table entry stores a rotate amount in bits 31-24, an encoded character byte in bits 23-16, a Morse length in bits 15-8, and Morse bits in bits 7-0. The real character is recovered by an 8-bit left rotate of the encoded byte by the rotate amount: char = rol8((entry >> 16) & 0xff, (entry >> 24) & 0xff). Decoding all 36 entries reproduces the standard a-z0-9 Morse alphabet."
      }
    },
    {
      "@type": "Question",
      "name": "How do you decrypt the dotsbedashing target stream?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The initial 32-bit key is 0xb1e1e1f1. For each encrypted dword, first rotate the key right by one bit and then XOR it with the ciphertext dword: key = ror32(key, 1); plain = enc ^ key. The decrypted dwords are packed Morse entries, which map back through the table to the inner text the0world0says0hii."
      }
    },
    {
      "@type": "Question",
      "name": "What is the verifier bug in dotsbedashing?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The comparison helper executes cmp eax, 0xffffffd3 where eax is always 0 or a power of two, so the comparison is never equal. This makes the rendered temporary all-ones of a fixed length, so the runtime check compares Morse lengths rather than exact dot-dash patterns, meaning strings with the same per-character Morse lengths are also accepted. The intended flag is still clear from the full length and bits data: the0world0says0hii."
      }
    },
    {
      "@type": "Question",
      "name": "What are the flags for the VuwCTF 2026 reverse engineering challenges?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "ilikewords: VuwCTF{do_you_like_wordle_as_much_as_i?}. dotsbedashing: VuwCTF{the0world0says0hii}."
      }
    }
  ]
}
```
