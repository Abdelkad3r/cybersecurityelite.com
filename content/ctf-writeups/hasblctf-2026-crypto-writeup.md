---
title: "HASBLCTF 2026 Crypto Writeup: All 6 Challenges Solved"
slug: "hasblctf-2026-crypto-writeup"
description: "HASBLCTF 2026 crypto writeup — all 6 challenges solved: modular bijections, permutation undo, debug-leak shortcut, LFSR endianness, classic VIC cipher."
date: 2026-06-01T06:00:00Z
lastmod: 2026-06-01T06:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "hasblctf"
  - "hasbl ctf"
  - "ctf 2026"
  - "cryptography"
  - "ctf crypto"
  - "modular arithmetic"
  - "modular inverse"
  - "multiplicative cipher"
  - "bijection"
  - "lfsr"
  - "stream cipher"
  - "endianness"
  - "htonl"
  - "vic cipher"
  - "soviet cipher"
  - "straddling checkerboard"
  - "chain addition"
  - "matrix cipher"
series: ["HASBL CTF 2026"]
keywords:
  - "hasblctf 2026 crypto writeup"
  - "hasblctf crypto writeup"
  - "hasbl ctf crypto challenges"
  - "hasblctf baby-counting-fingers writeup"
  - "hasblctf baby-learns-obfuscation writeup"
  - "hasblctf baby-learns-walking writeup"
  - "hasblctf script-kiddie writeup"
  - "hasblctf head-team writeup"
  - "hasblctf vic cipher writeup"
  - "multiplicative cipher modular inverse"
  - "bijection brute force ctf"
  - "htonl endianness bug ctf"
  - "lfsr taps 0x80200003"
  - "vic straddling checkerboard"
  - "chain addition keystream"
  - "soviet vic cipher writeup"
  - "matrix cipher debug leak"
toc: true
cover:
  image: "/images/articles/hasblctf-2026-crypto-writeup.png"
  alt: "HASBLCTF 2026 crypto writeup — all 6 challenges (baby-counting-fingers, baby-learns-obfuscation, baby-learns-walking, script-kiddie, head-team, VIC)"
---

{{< ctf-meta platform="HASBL CTF 2026" difficulty="Mixed (Easy → Medium)" os="Jeopardy — Crypto (Python + C)" skills="Modular multiplicative bijections, modular-inverse tables, permutation reversal, debug-print leakage exploitation, Galois LFSR + htonl endianness pitfalls, classic VIC cipher (straddling checkerboard + chain-addition keystream + special-character word substitution)" >}}

**HASBL CTF 2026** is a multi-category jeopardy event with Reverse Engineering, Pwn, Web, and Forensics tracks. This writeup is dedicated to the **Crypto track** — the six crypto challenges (`baby-counting-fingers`, `baby-learns-obfuscation`, `baby-learns-walking`, `script-kiddie`, `head-team`, `VIC`) were all solved, and each one teaches a different applied-cryptography primitive: modular multiplicative bijections on `Z_n`, two-layer permutation-plus-multiplication ciphers, position-salted chained byte operations, debug-print leakage of an otherwise elaborate matrix cipher, dual Galois LFSRs ruined by an `htonl` endianness asymmetry, and a faithful textbook implementation of the Soviet **VIC hand-cipher** with straddling checkerboard and chain-addition keystream.

This is the master writeup for the crypto track. Each challenge below covers the cipher primitives, the inversion path, and the recovered flag. Full per-challenge reproductions — solver scripts and handout files — live in the source repository: [Abdelkad3r/hasblctf-2026](https://github.com/Abdelkad3r/hasblctf-2026).

## The crypto track at a glance

| Challenge                 | Cipher primitive(s)                                                          | Core technique                                                                              |
|---------------------------|------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| baby-counting-fingers     | 5-cycle `(q_i, n_i)` per-byte multiplicative cipher on `Z_{n_i}`             | `n_i` all prime, all `> 95` → bijection on printable ASCII → 95-char brute per position    |
| baby-learns-obfuscation   | Permutation prefix + per-byte `* 0xDEADBEEF mod 0x1337` (4919, prime)        | Precompute inversion table `Z_4919 → ASCII`; strip 56-byte prefix; unscramble 28-byte suffix |
| baby-learns-walking       | Per-byte chained: `(ord(c) * 1337 + i) ^ 0x42`, hex-encoded with stripped `0x` | Position-by-position invert: `((v ^ 0x42) - i) // 1337` — no key material, all in the source |
| script-kiddie             | 20×20 matrix cipher with 3 rounds + final 4-byte XOR keystream               | The handout's `[debug]` print leaks `(155 * ord(pt[j])) mod 256` for every j; `155⁻¹ = 147` |
| head-team                 | Dual 32-bit Galois LFSR stream cipher (taps `0x80200003`) keyed by 64-bit int | `htonl` byte-swaps only the high half of the key on little-endian hosts — model the asymmetry |
| VIC                       | Soviet hand-cipher: special-word substitution + straddling checkerboard + chain-addition keystream mod 10 | Recognise VIC primitives in the source, invert each layer with longest-prefix matching     |

## Methodology — a crypto checklist

Crypto challenges are unusual in CTFs: they ship with the source code. The whole engagement is *reading and inverting*, not exploit discovery. The four-step framework:

1. **Read.** The handout's `chall.py` / `chall.c` is the complete specification. There are no opaque blobs — every transformation, every constant, every modular operation is in plain sight. Read it line by line before reaching for a decoder.
2. **Classify the primitives.** Each non-trivial line is one of: a modular multiplication, a XOR keystream, an LFSR step, a matrix operation, a permutation, or a classical cipher. Each primitive has a textbook inversion. *"What cipher is this?"* is the entire diagnostic question.
3. **Invert in reverse order.** If the encryptor does `permute → multiply → XOR`, the decryptor does `XOR → multiply⁻¹ → unpermute`. Each layer is undone independently. The "complexity" of a stacked cipher is rarely deeper than the sum of its layers.
4. **Verify against the format.** Every HASBL CTF challenge flag matches `[Hh][Aa][Ss][Bb][Ll]\{...\}` (note: two of the six crypto flags use lowercase `hasbl{`). Decoded output that doesn't start with `HASBL{` or `hasbl{` means you got a layer wrong.

{{< callout type="info" title="The recurring pattern: read the source" >}}
Five of the six HASBL CTF 2026 crypto challenges fall to "the modular operation is a bijection — invert it directly." The sixth (`script-kiddie`) has the *plaintext leaked in a debug print* before the encryption begins. Across all six, the answer is in the source code; the only puzzle is recognising which line gives it to you. This is the structural lesson of intro-crypto challenges — *the cipher's complexity is independent of its breakability*.
{{< /callout >}}

---

## baby-counting-fingers — five fingers, five bijections

```python
q_list = [31, 71, 19, 97, 47]
n_list = [127, 131, 137, 139, 149]

def encrypt(pt):
    ct = []
    for i, ch in enumerate(pt):
        finger = i % 5
        c = (ord(ch) * q_list[finger]) % n_list[finger]
        ct.append(c)
    return ct
```

### Why it's a bijection

For the map `f_{q,n}(x) = (x · q) mod n` to be a bijection on `Z_n`, the condition is `gcd(q, n) = 1`. Inspect each pair:

| pair | q  | n   | gcd | n > 95 (printable ASCII)? |
|:---:|:--:|:---:|:---:|:--------------------------|
| 0   | 31 | 127 | 1   | yes (n prime)             |
| 1   | 71 | 131 | 1   | yes                       |
| 2   | 19 | 137 | 1   | yes                       |
| 3   | 97 | 139 | 1   | yes                       |
| 4   | 47 | 149 | 1   | yes                       |

Every `n_i` is prime, every `q_i` is coprime, so each position's map is a permutation of `Z_{n_i}`. And every `n_i > 95` (the printable-ASCII range), so two distinct printable characters can never collide on the same ciphertext value at the same position.

### Invert without computing the inverse

The textbook move is to compute `q_i⁻¹ mod n_i` and decrypt with `ord = c · q⁻¹ mod n`. Faster intellectually, but the brute-force lookup is more obviously correct and runs in milliseconds:

```python
flag = []
for i, c in enumerate(ct):
    q, n = q_list[i % 5], n_list[i % 5]
    flag.append(next(chr(o) for o in range(32, 127) if (o*q) % n == c))
print("".join(flag))     # hasbl{F1NG3R_C0UN7IN6_15_1N5I6H7FUL}
```

95 candidates × 36 positions = 3 420 trial multiplications. Done in milliseconds.

**Flag:** `hasbl{F1NG3R_C0UN7IN6_15_1N5I6H7FUL}` *("finger counting is insightful")*

**Crypto takeaway:** modular multiplicative ciphers `c = (m · q) mod n` are broken the moment `gcd(q, n) = 1` *and* `n` exceeds the plaintext alphabet — the second condition is what makes the bijection inject into your search space. The author named the challenge "counting fingers" because there are five (q, n) pairs; the cipher's joke is that knowing *which* finger doesn't matter, because brute-force handles all five at once.

---

## baby-learns-obfuscation — permutation plus multiplication

```python
def obf(pt):
    obf_text = "aaaaaaaaaaaabbbbbbbbbbbJohnDoeaaaaaaaaaaaaabbbbbbbbbbbbb"  # 56 bytes
    if len(pt) % 2 == 0:
        i = len(pt) - len(pt) // 2
        j = len(pt) - 1
        while j != (i - 1):  obf_text += pt[j]; j -= 1   # reversed second half
        j = 0
        while j != i:        obf_text += pt[j]; j += 1   # first half, in order
    return obf_text

def encrypt(ptt):
    obf_t = obf(ptt)
    return [str((ord(ch) * 0xDEADBEEF) % 0x1337) for ch in obf_t]
```

Two layers: a permutation (`obf` prefix + halving reorder) followed by a per-byte modular multiplication. Output is base-10 stringified — 84 entries total.

### Step 1 — invert the per-byte multiplication

`0x1337 = 4919` is prime, `gcd(0xDEADBEEF, 4919) = 1`, and `4919 > 95` (printable ASCII). The map is a bijection. Precompute the inversion table once:

```python
TABLE = {(o * 0xDEADBEEF) % 0x1337: chr(o) for o in range(32, 127)}
recovered_obf = "".join(TABLE[int(v)] for v in ct_tokens)
# "aaaaaaaaaaaabbbbbbbbbbbJohnDoeaaaaaaaaaaaaabbbbbbbbbbbbb<permuted suffix>"
```

### Step 2 — strip the fixed prefix

The `obf()` function prepends a 56-character literal: `12 × 'a'` + `11 × 'b'` + `"JohnDoe"` + `13 × 'a'` + `13 × 'b'`. Strip those 56 bytes. The remaining 28 bytes are the permuted plaintext.

### Step 3 — reverse the permutation

For even-length input (28 → even, even branch fires), the layout is:

```text
obf_suffix = reversed(pt[mid:]) || pt[:mid]    where mid = N // 2 = 14
```

Inverting:

```python
suffix    = recovered_obf[56:]       # 28 bytes
mid       = len(suffix) // 2          # 14
pt_first  = suffix[mid:]              # first half = unrotated tail
pt_second = suffix[:mid][::-1]        # second half = reversed front
plaintext = pt_first + pt_second
# HASBL{0BFU5C473D_3NCRYP710N}
```

**Flag:** `HASBL{0BFU5C473D_3NCRYP710N}`

**Crypto takeaway:** stacking a permutation on top of a per-byte bijection adds zero security — the permutation is data-independent (it depends only on `len(pt)`), so the attacker just runs the same fixed inverse. The 56-byte `"JohnDoe"`-style filler is decoration. Real obfuscation needs an attacker-unknown key, not an attacker-readable layout.

---

## baby-learns-walking — `(ord(c) * 1337 + i) ^ 0x42`

```python
def encrypt(pt):
    ct = []
    for i, ch in enumerate(pt):
        res = (ord(ch) * 1337 + i) ^ 0x42
        ct.append(hex(res))
    return "".join(ct).replace("0x", " ")
```

The output is a single string of space-separated hex tokens (the leading space comes from the first `0x` being replaced).

### Invert each operation

Three operations applied per character:

1. `* 1337` — multiply by a small odd constant
2. `+ i` — add the position index (`enumerate` → 0, 1, 2, …)
3. `^ 0x42` — XOR with a fixed mask

None is secret; all are in the source. The inversion runs right-to-left:

```python
tokens = output.split()                # 37 hex strings
nums   = [int(t, 16) for t in tokens]
flag   = "".join(
    chr(((v ^ 0x42) - i) // 1337) for i, v in enumerate(nums)
)
# HASBL{1_F33L_D1ZZY_WH3N_1_S33_4_L00P}
```

Sanity check: printable ASCII × 1337 ≤ 126 × 1337 = 168 462 ≈ 2¹⁷·⁴, and `i < 50` for any sensible flag length. So `(v XOR 0x42) - i` is always a clean multiple of 1337 — `divmod` returns remainder 0 at every position.

**Flag:** `HASBL{1_F33L_D1ZZY_WH3N_1_S33_4_L00P}` *("I feel dizzy when I see a loop")*

**Crypto takeaway:** chained per-byte operations don't compound security; they compound *transparency*. If every operation is a public function of the plaintext byte and the position index, the cipher is an encoding, not an encryption. The position-dependent `+ i` term defeats a naïve "same byte at two positions → same ciphertext" attack but does nothing to prevent per-byte inversion.

---

## script-kiddie — the matrix cipher leaks its own plaintext

```python
def encrypt(data):
    initial_mtx = fill_matrix(data)
    _, (r0, r1, r2) = key_creation(initial_mtx)
    factor = 31 * (r0 + 1)
    debug_row = [(factor * ord(data[j])) % 256 for j in range(len(data))]
    print(f"[debug] Round 1 selected row index: {r0}")
    print(f"[debug] Initial matrix row {r0} (extended): {debug_row}")
    mtx = matrix_rounds(initial_mtx)
    return final_xor(mtx, data)
```

The cipher looks heavy: a 20×20 matrix, three rounds of mod-256 matrix multiplication, derived round keys, and a final 4-byte plaintext XOR keystream. The flattened output is 400 bytes of hex.

### The debug-print leak

Look at what `encrypt()` does **before** the rounds run. It computes a `debug_row` that's a *per-position transform of the plaintext* using `factor = 31 × (r0 + 1)`, then prints it. The handout's `output.txt` includes:

```text
[debug] Round 1 selected row index: 4
[debug] Initial matrix row 4 (extended): [152, 91, 65, 246, 4, 121, ...]
```

`r0 = 4` gives `factor = 31 × 5 = 155`. So:

```text
debug_row[j] = (155 × ord(data[j])) % 256
```

`155` is odd, so `gcd(155, 256) = 1`. The modular inverse: `155 × 147 ≡ 1 (mod 256)` (since `155 × 147 = 22 785 = 89 × 256 + 1`). The plaintext recovers in one line:

```python
flag = "".join(chr((v * 147) % 256) for v in debug_row)
# HASBL{3V3RY_SCR1P73R_C4N_40LV3_17}
```

The three rounds of matrix multiplication, the round-key extraction ritual, the final XOR keystream — none of it ever needs to run. The debug print sits at *round 1, before encryption begins*, and leaks the entire plaintext in plain modular arithmetic.

**Flag:** `HASBL{3V3RY_SCR1P73R_C4N_40LV3_17}` *("every scripter can solve it")*

**Crypto takeaway:** debug instrumentation is part of the cipher's attack surface. Anything that the encryption process emits to `stdout`, to a log, or to a side channel is reachable by the adversary. The matrix cipher in `script-kiddie` may be cryptographically interesting; the debug print is not interesting and breaks it completely. **Strip all `printf`/`print` calls before shipping.** This applies in production code as much as in CTF challenge design.

---

## head-team — two LFSRs ruined by one `htonl`

```c
#define TAPS 0x80200003UL
static uint32_t g_state[2];

static inline uint32_t lfsr_step(uint32_t s) {
    return (s & 1u) ? ((s >> 1) ^ TAPS) : (s >> 1);
}

static uint8_t ks_byte(void) {
    uint8_t out = 0;
    for (int i = 0; i < 8; i++) {
        g_state[0] = lfsr_step(g_state[0]);
        g_state[1] = lfsr_step(g_state[1]);
        out = (uint8_t)((out << 1) | ((g_state[0] ^ g_state[1]) & 1u));
    }
    return out;
}

static void init_cipher(uint64_t key) {
    uint32_t hi = (uint32_t)(key >> 32);
    uint32_t lo = (uint32_t)(key & 0xFFFFFFFFULL);
    g_state[0] = htonl(hi);    // <-- htonl on the HIGH half only
    g_state[1] = lo;           // <-- no htonl on the LOW half
}
```

Build: `gcc -O2 -o streamlock chall.c`. Key: `0xDEADBEEFCAFEBABE`. Ciphertext: 33 bytes (66 hex chars + newline) in `flag.enc`.

### Recognising the structure

Two 32-bit LFSRs in **Galois form** (taps `0x80200003`), running in lockstep. Each step emits one bit — the LSB of `(g_state[0] XOR g_state[1])` after both step. Eight steps make one keystream byte, packed **MSB-first**. The XOR encryption is symmetric — `process()` just XORs each input byte against one keystream byte.

### The `htonl` asymmetry

`htonl` is "host-to-network long" — it byte-swaps on little-endian hosts (x86_64 Linux is the intended target), or is a no-op on big-endian. The init does:

```c
g_state[0] = htonl(hi);    // hi = 0xDEADBEEF
g_state[1] = lo;           // lo = 0xCAFEBABE
```

Only the **high** half is byte-swapped. On little-endian:

```text
key       = 0xDEADBEEFCAFEBABE
state[0]  = htonl(0xDEADBEEF) = 0xEFBEADDE
state[1]  = 0xCAFEBABE   (unchanged)
```

That's both the title's *"head-team"* hint (head = upper half) and the entire challenge — a Python re-implementation of the LFSR has to match the C byte-swap to produce the right keystream:

```python
import struct
TAPS = 0x80200003

def lfsr_step(s):
    return ((s >> 1) ^ TAPS) if (s & 1) else (s >> 1)

def ks_byte(state):
    out = 0
    for _ in range(8):
        state[0] = lfsr_step(state[0])
        state[1] = lfsr_step(state[1])
        out = ((out << 1) | ((state[0] ^ state[1]) & 1)) & 0xff
    return out

key  = 0xDEADBEEFCAFEBABE
hi   = (key >> 32) & 0xFFFFFFFF
lo   = key & 0xFFFFFFFF
state = [struct.unpack(">I", struct.pack("<I", hi))[0], lo]   # htonl on hi only

ct = bytes.fromhex(open("flag.enc").read().strip())
flag = bytes(b ^ ks_byte(state) for b in ct)
# hasbl{H70NL_15_N07_4LW4Y5_53CUR3}
```

Alternatively, since the XOR stream is symmetric, just feed `flag.enc` back into the compiled binary with the same key and read the decrypted output.

**Flag:** `hasbl{H70NL_15_N07_4LW4Y5_53CUR3}` *("htonl is not always secure")*

**Crypto takeaway:** `htonl`/`ntohl` are network-byte-order helpers that *byte-swap on little-endian systems and do nothing on big-endian*. Using them on cipher state means your cipher's behaviour depends on the build host's endianness — a portability bug that doubles as a key-derivation asymmetry. The flag spells it out: htonl is not always secure. The right move in real code is `__builtin_bswap32` (explicit) or `htobe32` (named for the actual target order), never `htonl` on cipher state.

---

## VIC — the Soviet hand-cipher, faithfully

```python
CHECKERBOARD_SINGLE       = list("ETAOINSH")
CHECKERBOARD_SINGLE_CODES = ["0","1","2","4","5","7","8","9"]
CHECKERBOARD_ROW3         = list("RDBCFGJKLM")   # codes 30..39
CHECKERBOARD_ROW6         = list("PQUVWXYZ")     # codes 60..67

SPECIAL_TO_WORD = {
    "{": "LCURL", "}": "RCURL", "_": "SCORE",
    "0": "ZERO",  "1": "ONE",   ..., "9": "NINE",
}

KEY = "PHANTOM"

def encrypt(plaintext, key):
    preprocessed = preprocess(plaintext)              # specials -> words
    encoded      = checkerboard_encode(preprocessed)  # letters -> digits
    return add_keystream(encoded, key)                 # + keystream mod 10
```

The challenge name is an acrostic — **V**-ery **I**-nteresting En**C**-ryption = **VIC**, the Soviet hand-cipher used by KGB illegal Reino Häyhänen (named after his handler, "Victor"). This is a faithful textbook variant.

### Three layers, each invertible

1. **Special-character → word substitution.** `{` → `LCURL`, `}` → `RCURL`, `_` → `SCORE`, `0`–`9` → `ZERO`–`NINE`. Spelling out the specials so the next layer (digit-only) doesn't choke on them.
2. **Straddling-checkerboard digit encoding.** The 8 highest-frequency English letters (`E T A O I N S H`) get *one-digit* codes (`0 1 2 4 5 7 8 9`). The remaining letters get *two-digit* codes prefixed by either `3` (`RDBCFGJKLM` → `30..39`) or `6` (`PQUVWXYZ` → `60..67`). The `3` and `6` prefixes are the only codes that *don't* exist as singletons, so the decoder knows that when it sees a `3` or `6` it has to read two digits, not one. That's the "straddling" trick.
3. **Chain-addition keystream.** Take the key `"PHANTOM"`, convert letters to indices (`P=15, H=7, A=0, N=13, T=19, O=14, M=12`), then extend forever: each new digit is `(prev_digit + current_digit) mod 10`. Add the keystream to the encoded digit string, mod 10.

### Inversion

```python
# Step 1 — recover the keystream
seed = [letter_to_index(c) for c in "PHANTOM"]
keystream = list(seed)
while len(keystream) < CIPHERTEXT_LEN:
    keystream.append((keystream[-2] + keystream[-1]) % 10)
keystream = keystream[:CIPHERTEXT_LEN]

# Step 2 — subtract the keystream mod 10
digits = [(int(c) - k) % 10 for c, k in zip(CIPHERTEXT, keystream)]

# Step 3 — parse straddling checkerboard, longest-match first
letters = []
i = 0
while i < len(digits):
    d = digits[i]
    if d in (3, 6):                           # two-digit code
        letters.append(LOOKUP[(d, digits[i+1])])
        i += 2
    else:
        letters.append(LOOKUP_SINGLE[d])
        i += 1
letters_str = "".join(letters)
# "HASBLLCURLVONECSCOREONEFIVESCORENZEROSEVENSCOREJUSTSCOREFOURSCORECONEPHTHREERRCURL"

# Step 4 — walk left-to-right with longest-prefix SPECIAL_TO_WORD match
WORDS_DESC = sorted(SPECIAL_TO_WORD.items(), key=lambda kv: -len(kv[1]))
output = ""
i = 0
while i < len(letters_str):
    matched = False
    for special, word in WORDS_DESC:
        if letters_str.startswith(word, i):
            output += special
            i += len(word)
            matched = True
            break
    if not matched:
        output += letters_str[i]
        i += 1
# HASBL{V1C_15_N07_JUST_4_C1PH3R}
```

The trick in step 4 is **longest-prefix-first** matching: `SCORE` (5 chars) before any 4-letter word, `LCURL`/`RCURL` (5 chars) before `LC`/`RC`/`UR` letter pairs, `SEVEN`/`THREE` before `S`/`T`. Without the length-descending order, `ONE` would falsely match inside `LCURLVONEC` at the `ONEC` boundary.

**Flag:** `HASBL{V1C_15_N07_JUST_4_C1PH3R}` *("VIC is not just a cipher")*

**Crypto takeaway:** the VIC cipher is famous for being broken not by mathematics but by *operational error* — Häyhänen's defection in 1957 surrendered the keying procedure to the FBI, which then read messages dating back to 1953. The mathematics of VIC's three layers is mechanically invertible if you know the key (`PHANTOM` here); the historical security came from key secrecy plus rapid key rotation, both of which are operational disciplines, not cryptographic ones. As a CTF challenge, VIC is recognition-bound: spot the straddling-checkerboard prefixes (`3` and `6`) and the spelled-out specials, and the rest follows.

---

## Lessons learned — what HASBLCTF 2026 crypto rewarded

Five patterns recur across these six solves; they're the meat of intro-cryptanalysis:

1. **Bijectivity is breakability.** `(x · q) mod n` is a bijection whenever `gcd(q, n) = 1`. If the plaintext alphabet is smaller than `n`, the bijection injects — and a 95-character brute force per position recovers the message. `baby-counting-fingers` and `baby-learns-obfuscation` are both built on this primitive.
2. **The source is the spec.** Five of the six challenges expose every operation in `chall.py` or `chall.c`. Read every line before reaching for a decoder; the "cipher" is rarely more than a composition of three or four named primitives. `baby-learns-walking` is the canonical example — the entire algorithm is `(ord(c) * 1337 + i) ^ 0x42`, invertible right-to-left in one line.
3. **Debug instrumentation is part of the attack surface.** `script-kiddie`'s 20×20 matrix cipher with three rounds and a derived-key XOR is irrelevant — a `print` statement at round 1 leaks the plaintext. Strip every `print` / `printf` / log line before shipping. This applies in production code too.
4. **Endianness is a security boundary.** `head-team`'s `htonl(hi)` + `lo` (without `htonl`) byte-swaps half the key on little-endian systems and does nothing on big-endian. Cipher state should never go through `htonl`/`ntohl` — use explicit `bswap` intrinsics or named byte-order helpers (`htobe32`, `htole32`) so the behaviour is target-independent.
5. **Classical ciphers reward recognition over arithmetic.** VIC isn't broken by lattice reduction or differential cryptanalysis — it's broken by *spotting the straddling checkerboard's `3` and `6` two-digit prefixes*, the spelled-out specials, and the chain-addition keystream. The math is mechanically invertible once you know what cipher you're looking at. Read the source for the recognisable fingerprints.

## Source repository

Every per-challenge writeup includes solver scripts, the modular-inverse calculations, and the VIC-decryption trace:

**Repo:** [github.com/Abdelkad3r/hasblctf-2026](https://github.com/Abdelkad3r/hasblctf-2026)

The repo also contains the [reverse engineering](/ctf-writeups/hasblctf-2026-reverse-engineering-writeup/), [pwn](/ctf-writeups/hasblctf-2026-pwn-writeup/), and [forensics](/ctf-writeups/hasblctf-2026-forensics-writeup/) writeups from the same event, plus the web track. This article is scoped to the crypto category only.

If you're building an intro-crypto learning progression from this writeup, the six challenges form a clean order: **baby-learns-walking (chained byte ops, all visible) → baby-counting-fingers (modular bijection on Z_n) → baby-learns-obfuscation (bijection + permutation) → script-kiddie (debug-print leak through a heavy facade) → head-team (LFSR + endianness pitfall) → VIC (classical cipher recognition)**. That order maps to *"invert one byte"* → *"invert one modular primitive"* → *"invert a stack of primitives"* → *"read the source for a shortcut"* → *"watch for build-host pitfalls"* → *"recognise the cipher by its fingerprint"*.

{{< faq >}}
[
  {
    "q": "What is HASBL CTF 2026?",
    "a": "HASBL CTF 2026 is a multi-category jeopardy-style capture-the-flag competition covering Reverse Engineering, Pwn, Web, and Forensics, plus Crypto. The flag prefix is HASBL{...} for most challenges (two of the six crypto challenges use lowercase hasbl{...}). This writeup is dedicated to the Crypto track only."
  },
  {
    "q": "How many crypto challenges does HASBL CTF 2026 have?",
    "a": "Six crypto challenges, all solved in this writeup: baby-counting-fingers, baby-learns-obfuscation, baby-learns-walking, script-kiddie, head-team, and VIC. The full event also includes reverse engineering, pwn, web, and forensics tracks covered separately."
  },
  {
    "q": "Where can I find the HASBL CTF 2026 crypto solver scripts?",
    "a": "All six per-challenge writeups and solver scripts live in the source repository at github.com/Abdelkad3r/hasblctf-2026 under the crypto/ directory. Each challenge has its own README and standalone solver."
  },
  {
    "q": "How is the baby-counting-fingers challenge solved?",
    "a": "The cipher cycles through five (q, n) pairs by position: q_list=[31,71,19,97,47], n_list=[127,131,137,139,149]. Every n_i is prime, every q_i is coprime, and every n_i exceeds 95 (the printable-ASCII range), so each per-position map (x*q)%n is a bijection that injects into printable ASCII. Brute-force 95 candidates per position and pick the one that matches the ciphertext value. The flag is hasbl{F1NG3R_C0UN7IN6_15_1N5I6H7FUL}."
  },
  {
    "q": "What is the bijectivity argument in HASBL CTF crypto challenges?",
    "a": "A modular multiplication f(x) = (x * q) mod n is a bijection on Z_n if and only if gcd(q, n) = 1. When the plaintext alphabet (printable ASCII, 95 characters) is smaller than n, the bijection injects — no two printable characters can produce the same ciphertext value. A 95-character brute force per position then recovers each plaintext character in O(95) operations, which beats computing modular inverses in code-reading time and runs in milliseconds total. This argument underpins both baby-counting-fingers and the per-byte layer of baby-learns-obfuscation."
  },
  {
    "q": "How is the baby-learns-obfuscation challenge solved?",
    "a": "Two layers: per-byte (ord(ch) * 0xDEADBEEF) % 0x1337 (4919, prime) followed by a permutation that prepends a 56-byte fixed prefix and then appends reversed(pt[mid:]) || pt[:mid] for even-length input. Precompute the inversion table {(o * 0xDEADBEEF) % 0x1337: chr(o)} for printable ASCII, decode all 84 ciphertext entries, strip the 56-byte prefix, and unscramble the 28-byte suffix by pt[:mid] = suffix[mid:] and pt[mid:] = reversed(suffix[:mid]). Flag: HASBL{0BFU5C473D_3NCRYP710N}."
  },
  {
    "q": "How is the baby-learns-walking challenge solved?",
    "a": "The encryption per byte is res = (ord(ch) * 1337 + i) ^ 0x42 with i = position index. Invert right-to-left: ord(ch) = ((v ^ 0x42) - i) // 1337. The output is hex-encoded with 0x replaced by spaces — split on whitespace, int(t, 16) each token, then apply the inverse for each position. Flag: HASBL{1_F33L_D1ZZY_WH3N_1_S33_4_L00P}."
  },
  {
    "q": "How is the script-kiddie matrix cipher broken?",
    "a": "The encryption process prints a debug line before the matrix rounds run. The debug_row variable equals [(155 * ord(data[j])) % 256 for j in range(len(data))] where 155 = 31 * (r0 + 1) with r0 = 4. 155 is odd so gcd(155, 256) = 1, and the modular inverse is 147 (155 * 147 = 22785 = 89*256 + 1). The plaintext recovers in one line: chr((v * 147) % 256) for each v in debug_row. The 20x20 matrix cipher, three rounds, and final XOR keystream are entirely irrelevant. Flag: HASBL{3V3RY_SCR1P73R_C4N_40LV3_17}."
  },
  {
    "q": "What is the htonl bug in the head-team challenge?",
    "a": "The C source initialises two LFSR states from a 64-bit key: g_state[0] = htonl(hi) but g_state[1] = lo (no htonl on the low half). htonl byte-swaps on little-endian hosts and is a no-op on big-endian. On x86_64 Linux, htonl(0xDEADBEEF) = 0xEFBEADDE while 0xCAFEBABE stays put. Re-implementing the LFSR in Python requires matching this asymmetry — only the high half of the key gets byte-swapped before going into state[0]. Alternatively, since the XOR stream is symmetric, feeding flag.enc back into the compiled binary with the same key decrypts it directly. Flag: hasbl{H70NL_15_N07_4LW4Y5_53CUR3}."
  },
  {
    "q": "What is the VIC cipher in the HASBL CTF challenge?",
    "a": "VIC is a Soviet hand-cipher used by KGB illegal Reino Häyhänen, named after his handler 'Victor.' The challenge implements three layers: (1) special-character substitution where { becomes LCURL, } becomes RCURL, _ becomes SCORE, and digits 0-9 become ZERO-NINE; (2) a straddling checkerboard where the eight highest-frequency English letters (E T A O I N S H) get single-digit codes 0,1,2,4,5,7,8,9 and the remaining letters get two-digit codes prefixed by 3 or 6; (3) a chain-addition keystream from the key PHANTOM extended via prev_digit + current_digit mod 10. All three layers are mechanically invertible. Flag: HASBL{V1C_15_N07_JUST_4_C1PH3R}."
  },
  {
    "q": "Are HASBL CTF crypto challenges beginner-friendly?",
    "a": "Yes — the six form a clean intro-cryptanalysis curriculum. baby-learns-walking is the simplest (read the loop, invert each operation). baby-counting-fingers teaches the bijection argument on Z_n. baby-learns-obfuscation stacks a permutation on top. script-kiddie introduces the read-the-source-for-shortcuts principle. head-team teaches LFSRs and endianness pitfalls. VIC is the recognition-bound classical cipher. All six are solvable with Python's stdlib plus basic number theory; no Sage or expensive tooling required."
  },
  {
    "q": "What tools are needed for HASBL CTF crypto challenges?",
    "a": "Python's standard library is enough for all six: integer modular arithmetic for the multiplicative bijections, struct module for the htonl asymmetry in head-team, and hand-rolled lookup tables for the VIC straddling checkerboard. The GCC toolchain (gcc -O2 -o streamlock chall.c) is needed only to run the C binary in head-team as an alternative to the Python re-implementation. No Sage, no PARI/GP, no commercial cryptography suite — the cipher primitives in this CTF are simple enough that the stdlib carries the whole engagement."
  }
]
{{< /faq >}}
