---
title: "DalCTF 2026 Writeup: All 9 Challenges Solved"
slug: "dalctf-2026-writeup"
description: "DalCTF 2026 full writeup — 9 challenges across Crypto, Reverse, Web, and Android. RSA small factors, Bellcore fault attack, Playfair, Huffman tiebreak, IEEE-754 type punning, UPX-packed checker."
date: 2026-06-08T19:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "dalctf"
  - "dalctf 2026"
  - "ctf 2026"
  - "crypto ctf"
  - "rsa ctf"
  - "reverse engineering"
  - "android reverse engineering"
  - "web exploitation"
  - "playfair cipher"
  - "huffman coding"
  - "bellcore fault attack"
  - "rsa small factor"
  - "lcg known plaintext"
  - "ieee 754 type punning"
  - "upx packed binary"
  - "apk decompile"
  - "html hidden attribute"
series: ["DalCTF 2026"]
keywords:
  - "dalctf 2026 writeup"
  - "dalctf writeup"
  - "dalctf 2026"
  - "dalctf2026.com challenges"
  - "playfair cipher ctf writeup"
  - "rsa small prime factor ctf"
  - "bellcore fault attack rsa ctf"
  - "huffman tiebreak inverted ctf"
  - "lcg known plaintext attack ctf"
  - "quake fast inverse sqrt ctf"
  - "ieee 754 float pointer cast"
  - "upx packed elf checker"
  - "android apk hardcoded flag ctf"
  - "html hidden attribute flag"
  - "baby web ctf writeup"
  - "baby android ctf writeup"
  - "do you know the way ctf"
  - "lcg seed squared ctf"
  - "alls fair in love and ctfs"
  - "angry shamir rsa ctf"
  - "compression isnt encryption ctf"
  - "playing with pointers ctf"
  - "fun with rsa ctf"
toc: true
cover:
  image: "/images/articles/dalctf-2026-writeup.png"
  alt: "DalCTF 2026 writeup — 9 challenges solved across Crypto, Reverse, Web, and Android"
---

{{< ctf-meta platform="DalCTF 2026 (dalctf2026.com)" difficulty="Mixed (Easy → Medium)" os="Jeopardy — Crypto, Reverse Engineering, Web, Android" skills="RSA modulus with small prime factor recovered by trial division, Bellcore CRT fault attack as the verification path, Playfair decryption against an un-keyed alphabet square, Huffman tree decode with inverted tiebreaker convention, LCG state recovery from one known plaintext byte, IEEE-754 bit-pattern reinterpretation via Quake-style float pointer cast, UPX-packed ELF unpacked into 44 per-byte check functions, Android APK static-string mining across MainActivity + strings.xml + ColorKt, HTML hidden attribute as a flag-hiding sink" >}}

**DalCTF 2026**'s crypto-heavy board is the subject of this **CyberSecurity Elite** writeup: the [DalCTF](https://dalctf2026.com/) Jeopardy event with challenges spread across Crypto, Reverse Engineering, Web, and Android. The 2026 edition leans heavily into *classical cryptography mistakes wrapped in misdirection* — six of the nine challenges are crypto, and almost every one of them tries to push you toward a harder attack than the one that actually works. The flag format is `dalctf{...}` (occasionally `DalCTF{...}`), and the challenge names are explicit hints once you've solved them.

This is the master writeup. All nine challenges (`Baby Android`, `Do you know the way?`, `Baby Web`, `LCG Seed Squared`, `All's Fair in Love and CTFs`, `Angry Shamir`, `Compression isn't encryption`, `Playing with Pointers`, `Fun with RSA`) were solved end-to-end. Each section below covers the surface, the bug class, the exploitation chain, and the recovered flag. Full per-challenge reproductions — Python solvers, r2 sessions, Huffman tree builders, RSA scripts — live in the source repository: [Abdelkad3r/dalctf-2026](https://github.com/Abdelkad3r/dalctf-2026).

The two writeups worth flagging for any reader skimming this for technique: [`crypto/fun-with-rsa`](https://github.com/Abdelkad3r/dalctf-2026/blob/main/crypto/fun-with-rsa.md) (the entire intended Bellcore fault attack is decorative — `pow(s, e, n)` recovers the message in two lines because the script publishes the signature) and [`crypto/compression-isnt-encryption`](https://github.com/Abdelkad3r/dalctf-2026/blob/main/crypto/compression-isnt-encryption.md) (a Huffman decode whose first attempt garbles only the middle of the message — the diagnostic that the tree topology is right but the *tiebreaker convention* is inverted). Both are the kind of CTF lesson that travels straight to production code review.

## The event at a glance

| Category | Challenge                          | Core technique                                                                                       |
|----------|------------------------------------|------------------------------------------------------------------------------------------------------|
| Android  | Baby Android                       | Three hardcoded flag pieces across `MainActivity.java`, `strings.xml`, and `ColorKt.java`            |
| Reverse  | Do you know the way?               | UPX-packed x86-64 ELF; symbols expose 44 per-byte `f_i` check functions, brute-force each byte       |
| Web      | Baby Web                           | `<p hidden="true">` in a 52 KB static HTML page; flag bytes are in source, suppressed in render      |
| Crypto   | LCG Seed Squared                   | `t_i = ord(flag[i]) * x_i`; flag[0] = 'D' = 68 recovers `x_1` directly, no LCG inversion needed      |
| Crypto   | All's Fair in Love and CTFs        | Playfair with the **plain** alphabet square (no keyword scramble); 18-char ciphertext decodes        |
| Crypto   | Angry Shamir                       | 2054-bit RSA modulus with a tiny factor (67); `n % 67 == 0`, decrypt with `phi = 66 * (q-1)`         |
| Crypto   | Compression isn't encryption       | Huffman coding masquerading as a cipher; first decode garbles the middle → invert tiebreaker         |
| Crypto   | Playing with Pointers              | C source casts `float*` to `long*` Quake-style; output is IEEE-754 bit pattern of `(float)(c)^2`     |
| Crypto   | Fun with RSA                       | Script publishes `s = m^d mod n` — the RSA signature; `m = pow(s, e, n)` recovers the message        |

Nine flags. Per-challenge reproductions in the source repository linked above.

## Methodology — read the name, then read the artefact

DalCTF 2026's crypto track rewards exactly one habit: **the challenge name is the hint, and the artefact tells you whether the obvious-from-the-name attack is also the obvious-from-the-source attack.** Six of the nine challenges this engagement turned on a single sentence of the source/PDF text or filename: "All's Fair" = Playfair, "Angry Shamir" = something wrong with the RSA modulus, "Compression isn't encryption" = Huffman, "Playing with Pointers" = type punning, "Fun with RSA" = something published that shouldn't be. Reading the name correctly cut hours off most of these.

The four-step framework that carried the engagement:

1. **Read the title as a hint, not a category.** "Angry Shamir" doesn't mean Shamir's secret sharing — it means *something is wrong with the **S** in RSA*. "Playing with Pointers" doesn't mean pointer arithmetic — it means *something is being reinterpreted via a pointer cast*. Each title is engineered to point at the specific bug; treat it as one of the inputs to the puzzle.
2. **Match the source/output to the simplest decode.** `LCG Seed Squared` publishes `t_i = ord(flag[i]) * x_i`. If `flag[0]` is known (`D`), `x_1` falls out from one division. Skip the seed recovery the title nudges toward.
3. **Don't auto-normalize the recovered plaintext.** `All's Fair in Love and CTFs` decrypts to `ANYTHINGFORTHEFLAG`, and the natural reflex is to submit `dalctf{anything_for_the_flag}`. **The accepted flag is `dalctf{ANYTHINGFORTHEFLAG}` — raw uppercase, no underscores.** DalCTF's house formatting style is not universal; check the literal plaintext first.
4. **For RSA challenges with multiple published values, try each one against `pow(?, e, n)` before anything else.** Half the layering in DalCTF's RSA challenges is decoration designed to point you at fault analysis, common-factor, or Wiener. The simplest attack uses the value the script accidentally published as a signature.

The detailed per-challenge writeups follow. Throughout, the **bug class** is called out in the section heading so security engineers reading this for code-review patterns can scan straight to the relevant entry.

## Android — Baby Android

The entry-level Android challenge. The handout is `BabyAndroid.apk` with package `com.example.babyandroid`. The flag is **statically embedded** in three pieces across the APK — no runtime check, no obfuscation, no anti-debug.

Decompile both the resources and the Java side:

```
apktool d BabyAndroid.apk -o apk_res    # resources + manifest
jadx -d apk_src BabyAndroid.apk         # Java decompilation
```

The three pieces:

- **`flag1`** — hardcoded field in `MainActivity.java`: `dalctf{4ndr0id`
- **`flag2`** — `res/values/strings.xml`, also referenced as `android:description` on `MainActivity` in `AndroidManifest.xml`: `_d3bugg1ng_`
- **`flag3`** — hardcoded field in `ui/theme/ColorKt.java`: `_1s_e4sy}`

Concatenate:

```
dalctf{4ndr0id_d3bugg1ng_1s_e4sy}
```

**The teaching point** — and the reason this challenge is worth running for a junior Android reviewer — is that flag fragments love to hide in resources. `strings.xml`, `colors.xml`, theme files, and the manifest's `android:description` / `android:label` attributes are all single-step "grep here too" sinks. A thorough APK review pipeline runs `grep -rE 'dalctf\{|flag' apk_res apk_src` over the entire decompilation output, not just the `.java` files.

**Bug class:** static strings in shipped artefacts; resource attributes as flag-hiding sinks.

## Reverse — Do you know the way?

A UPX-packed x86-64 ELF with one entirely-decorative runtime gate. The binary prints:

> Do you know the way? Are there any symbols around to help you?

That second sentence is the *entire* hint — the binary is not stripped. After `upx -d`, the symbol table exposes:

- `f_0 … f_43` — 44 small functions, one per flag byte
- `rol8`, `ror8` — 8-bit rotate helpers
- `expected` — 44-byte array at `.data:0x3020`

### The red herring in `main`

`main` does roughly:

```c
fgets(input, 44, stdin);
for (int i = 0; i < 44; i++) {
    idx = rand() % 44;
    if (i == idx) return;          // silently bail
    if (!f_i(input[i])) return;    // wrong byte
}
puts("Good job!");
```

The random `idx` check means at runtime the chain *never* completes — even with the correct flag you usually get nothing. **Don't try to solve this dynamically.** The check chain itself is the puzzle; the runtime gate is just decoration designed to make naive `pwntools` fuzzing time out.

### The solve — emulate each `f_i`

Each `f_i` is a short transformation of `input[i]`: `xor`, `add`, `sub`, `mul` (via shift+add), `rol8`, `ror8`, bitwise `not`. Then it compares the result against `expected[i]`. Pull each function with radare2:

```
r2 -A checker
[0x...]> pdf @ sym.f_38
```

Implement a small Python emulator that brute-forces the single input byte for each `i`:

```python
for b in range(256):
    if f_i(b) == expected[i]:
        flag += chr(b); break
```

A subtle gotcha: `f_38` contains a `not eax` that's easy to drop while parsing — the first pass produced `dalctf{symb0ls_4r3_4lw4ys_3xtr3m3ly_h3.pfu1}` instead of `…h3lpfu1}`. Re-reading the disassembly more carefully puts the `not` back in place.

### Final flag

```
dalctf{symb0ls_4r3_4lw4ys_3xtr3m3ly_h3lpfu1}
```

**Bug class:** symbol-bearing binary with decorative runtime gate; static per-byte check functions trivially brute-forced.

## Web — Baby Web

A single ~52 KB static HTML page styled as a *Boss Baby* movie summary and transcript. No scripts, no forms, no other endpoints — nothing to fuzz, no attack surface.

A near-bottom `<h2>` hints:

> the flag is somewhere in the transcript

The flag is wrapped in a `<p hidden="true">…dalctf{…}…</p>` tag. The HTML `hidden` attribute suppresses *rendering* in the browser, but the bytes are sitting right there in the source.

### The solve

Either *View Source* in the browser, or:

```
curl -s https://<instance>.instancer.dalctf2026.com/ | grep -E 'hidden=|dalctf\{'
```

Out comes:

```
dalctf{n0w_y0u_ar3_th3_b0ss_b4by}
```

**The teaching point** is broader than the cheap `hidden`-attribute hide: when a page renders nothing useful, the source isn't the page. The single-step "is it really not there?" checklist for any web challenge:

- `<element hidden>` and `<element hidden="true">` (HTML attribute)
- CSS `display: none`, `visibility: hidden`, `opacity: 0`
- White-on-white text (`color: white` over `background: white`)
- HTML comments `<!-- … -->`
- Tags with `aria-hidden="true"` (accessibility-hidden, content-present)
- Off-screen positioning (`position: absolute; left: -9999px`)
- Hidden form inputs (`<input type="hidden">`)

`View Source` (or `curl | grep`) hits every one of these in one step.

**Bug class:** content-vs-render boundary; `hidden`-attribute as a flag-hiding sink.

## Crypto — six challenges, six classical mistakes

The crypto track is where DalCTF 2026 spent its design budget. Every challenge layers a name-hint over an artefact with a simple correct attack and a decorative complex attack. Read the name, match it to the artefact, take the simple path.

### LCG Seed Squared — known-plaintext leak of the LCG state

The script:

```python
def rng(y):
    return pow(int((175*y + 17) / 14 + 45), 15, 4294967295)

# x_0 = sum(ord(c) for c in seed)  # unknown seed string
for i in range(len(flag)):
    x = rng(x)
    print(ord(flag[i]) * x)
```

So output `t_i = ord(flag[i]) * x_{i+1}`, where `x_{i+1} = rng(x_i)` and `x_0` is the seed-derived initial state.

The "Seed Squared" framing in the name suggests you should attack the seed (square it, factor it, reconstruct the initial sum from the LCG state). **Don't.** The flag format is known: `DalCTF{…`, so `flag[0] = 'D'` and `ord('D') = 68`.

```
t_0 = 71303168 = 68 * 1048576
```

so `x_1 = 1048576` falls out directly. No seed recovery, no inversion of the LCG — just one known plaintext byte.

```python
import re

with open("output (9).txt") as f:
    ts = [int(x) for x in re.findall(r"\d+", f.read())]

def rng(y):
    return pow(int((175*y + 17) / 14 + 45), 15, 4294967295)

x = ts[0] // ord('D')      # x_1
flag = ['D']
for t in ts[1:]:
    x = rng(x)
    assert t % x == 0
    flag.append(chr(t // x))

print(''.join(flag))
```

Every division lands cleanly in printable ASCII.

```
DalCTF{533m1ng1y_r4nd0m1y_g3n3r473d_num63rs}
```

**Defender takeaway:** any stream cipher whose output is `f(plaintext) * internal_state` is broken the moment one plaintext byte is known. The flag-format prefix is essentially always known in CTFs; in production, file format magic, message envelopes, and protocol framing serve the same role.

**Bug class:** known-plaintext attack via multiplicative output; flag-format-as-known-prefix.

### All's Fair in Love and CTFs — Playfair against the plain alphabet square

The handout is a 5×3 grid image showing only the odd-numbered columns of a standard 5×5 Polybius / Playfair square (I/J merged):

```
A _ C _ E
F _ H _ K
L _ N _ P
Q _ S _ U
V _ W _ X
```

Fill the blanks back in. It's the plain A–Z order with I=J, **no keyword scramble at all**:

```
A B C D E
F G H I K
L M N O P
Q R S T U
V W X Y Z
```

The ciphertext is `CLDYIKMHILSUKCLQBF` — 18 characters, 9 digraphs. Apply standard Playfair decryption:

- Same row → shift each letter left
- Same column → shift each letter up
- Rectangle → swap columns

```
CL → AN     DY → YT     IK → HI     MH → NG
IL → FO     SU → RT     KC → HE     LQ → FL
BF → AG
```

→ `ANYTHINGFORTHEFLAG`.

### The flag-formatting gotcha

DalCTF's house style is `dalctf{lowercase_with_underscores}`, so the natural first guess is `dalctf{anything_for_the_flag}`. **That's wrong.** The accepted flag preserves the raw uppercase plaintext exactly:

```
dalctf{ANYTHINGFORTHEFLAG}
```

For DalCTF crypto challenges, don't auto-normalize the decrypted plaintext to lowercase/underscored before submitting — try the raw plaintext as-is first.

**Bug class:** classical cipher without keyed alphabet; flag-format normalization trap.

### Angry Shamir — RSA modulus with a tiny prime factor

The handout publishes `n` (2054 bits), `e = 65537`, and `c`. The challenge name is the entire hint: "Shamir" is the **S** in RSA, "Angry" = something is wrong with the modulus.

`n` looks like a real 2054-bit RSA modulus, but trial division by the first few small primes immediately gives:

```python
>>> n % 67
0
```

The prime generator failed to reject small factors. `n = 67 · q` where `q` passes Miller-Rabin. Decrypt with the correct `phi`:

```python
from Crypto.Util.number import long_to_bytes

p = 67
q = n // 67
phi = (p - 1) * (q - 1)        # 66 * (q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

→ `dalctf{sm4ll_f4ct0rs_4r3_d4ng3r0us_1n_rs4}`

**Defender takeaway:** any RSA prime-generator should reject candidates with small factors at sample time. The simple check `for small_p in PRIMES[:1000]: if cand % small_p == 0: continue` runs in microseconds and catches this bug. Production RSA libraries (OpenSSL's `BN_generate_prime_ex`, libsodium's `crypto_sign_keypair`) do exactly this; rolling your own RNG-driven prime sampler without the small-factor reject is the bug class.

For any CTF RSA challenge whose title hints at "small", "tiny", "weak", "broken", or "angry", **trial-divide first** before reaching for Fermat, Wiener, common-factor, or Coppersmith. A two-line check rules out the laziest mistake.

**Bug class:** broken prime generator; small-factor RSA modulus.

### Compression isn't encryption — Huffman with inverted tiebreaker

The handout gives an alphabet of 41 symbols (`a-z`, `0-9`, `_{}!$`) with frequencies, plus a 192-bit string. Notable ties in the frequency table: `{` and `}` both at `0.001`; `6`, `8`, `9` all at `0.02`.

The name is the entire diagnosis: **Huffman coding**, not a cipher. The frequencies are exactly what you'd feed a Huffman encoder.

### First attempt — wrong tiebreak

Standard `heapq` Huffman with an ascending counter for tie-breaking ("older item wins") decodes most of the string correctly:

```
y311e8wi11_4m4eypt_32tni274
       ^^^^^^^^^^^^^^^^^^^^      garbled middle
dalctf{                          good prefix
                          ...    good suffix
```

Prefix and suffix look right (the wrapping characters are unambiguous because of their distinctive code lengths), but the middle is scrambled. **That's the diagnostic**: when prefix+suffix decode cleanly but the middle doesn't, the tree topology is correct and only the tiebreak convention is inverted.

### Fix — flip the tiebreaker direction

The encoder pops **newly-merged subtrees before older equal-probability leaves** — the tiebreaker counter is *decreasing*, not increasing. Flip the counter sign in the heap tuple and the same Huffman decoder produces:

```
dalctf{y0u_wi11_3ncrypt_4lw4y$}
```

Solve sketch:

```python
import heapq

freqs = parse_alphabet("alphabet.txt")
bits  = open("output (10).txt").read().strip()

heap = []
counter = 0
for ch, p in freqs.items():
    heapq.heappush(heap, (p, -counter, ch))      # negative = newer wins ties
    counter += 1

while len(heap) > 1:
    p1, _, n1 = heapq.heappop(heap)
    p2, _, n2 = heapq.heappop(heap)
    heapq.heappush(heap, (p1 + p2, -counter, (n1, n2)))
    counter += 1

root = heap[0][2]

# walk bits → tree
out = []
node = root
for b in bits:
    node = node[0] if b == '0' else node[1]
    if isinstance(node, str):
        out.append(node)
        node = root
print(''.join(out))
```

**Defender takeaway:** Huffman coding is not specified by the standard library to use one tiebreaker convention. Two implementations that both produce minimum-redundancy codes for the same alphabet can disagree byte-for-byte if they break ties differently. Anywhere you interoperate Huffman streams across implementations, the tree-construction tiebreak must be part of the interop spec. RFC 1951 (DEFLATE) sidesteps this entirely by transmitting the code lengths, not the tree.

**Bug class:** unspecified tiebreaker in serialized tree-construction; interop fragility.

### Playing with Pointers — IEEE-754 bit pattern via type pun

The C source:

```c
for (int i = 0; i < N; i++) {
    fflag[i]  = (float)FLAG[i];
    fflag[i] *= fflag[i];           // square the float
    // TODO: copy fflag[i] into lflag[i] — but I was playing Quake
    printf("%ld\n", lflag[i]);
}
```

The "copy" line is *missing* and the comment mentions Quake. Quake III's famous trick is **fast inverse square root**, which works by reinterpreting a float's bit pattern as an integer:

```c
i = *(long *)&y;        // type-pun float → int
```

So the missing line is:

```c
lflag[i] = *(long *)&fflag[i];
```

Each printed `long` is the **IEEE-754 bit pattern** of `(float)(char)²`.

### Reverse

For each output value:

1. Pack as little-endian 4 bytes.
2. Unpack as a float (`<f`).
3. Take `sqrt`, round, `chr`.

```python
import struct, math

vals = [int(x) for x in open("output (11).txt").read().split()]
flag = ''
for v in vals:
    f = struct.unpack('<f', struct.pack('<I', v & 0xFFFFFFFF))[0]
    flag += chr(round(math.sqrt(f)))
print(flag)
```

→ `DalCTF{s0m3_fUn_w17h_P01n73r5}`

**The diagnostic phrase:** `*(long *)&float` (or `*(int *)&float`, `*(uint32_t *)&float`). The moment a C source casts a float pointer to an integer pointer (or vice versa), the integer you read is the IEEE-754 bit pattern, not a numeric conversion. This pattern is a CTF crypto staple and a real-world undefined-behavior anti-pattern — C standardises type punning via `union` or `memcpy`, never via pointer cast.

**Bug class:** IEEE-754 bit-pattern leak; type-punning via undefined-behavior pointer cast.

### Fun with RSA — published signature recovers the message

The script publishes 512-bit RSA values with multiple layered distractions:

- `ct = c XOR p XOR q` — the "ciphertext" is XOR-blinded with both primes, so `ct` alone is useless.
- `s = pow(m, d, n)` — the **RSA signature** of the plaintext message. Published.
- `spz` — CRT-style half-signature with a deliberate fault on the `p` side: `sp ⊕ 1` injected before `crt_combine(sp_faulty, sq)`.

The challenge name hints at *all three* tricks (`segfault` = the fault, `RSA mixed with XOR` = the `ct` blinding). The intended path is the **Bellcore attack**.

### Trivial path — `pow(s, e, n)`

`s = m^d mod n` is *the message's RSA signature*, and the public exponent `e` is given. So:

```python
m = pow(s, e, n)
print(long_to_bytes(m))
```

No factoring, no XOR, no fault analysis. The script handed us the message directly.

→ `dalctf{s3gf4u17_r54_m1x3d_w17h_x0r}`

### Bellcore fault path — also works

For completeness — and because the challenge clearly wants you to do this — the faulted CRT signature gives a textbook **Bellcore attack**:

`spz ≡ sp_faulty (mod p)` but `≡ sq (mod q)`. So:

- `s ≡ spz (mod q)` (q-half unaffected by the p-side fault)
- `s ≢ spz (mod p)`

Therefore `s − spz` is a multiple of `q` but not of `p`:

```python
from math import gcd
q = gcd(s - spz, n)
p = n // q
phi = (p - 1) * (q - 1)
d   = pow(e, -1, phi)
c   = ct ^ p ^ q                # undo the XOR blinding
m   = pow(c, d, n)
print(long_to_bytes(m))
```

Both paths recover the same flag.

**Defender takeaway:** if a CTF RSA challenge publishes `s = m^d mod n`, **try `pow(s, e, n)` before anything else**. In production, the equivalent bug is publishing a signature alongside the public key and treating the pair as "the message is hidden because it was encrypted." A signature *is* a permutation of the message under the private key; the public key inverts it.

The Bellcore fault path is the famous 1997 attack on CRT-based RSA (Boneh, DeMillo, Lipton): a single computational fault in the p-half of CRT signing reveals `gcd(s - s_faulty, n) = q`. Production CRT-RSA implementations defend against it by **verifying every signature against the public key before returning it** — if `pow(sig, e, n) != message`, abort the signing operation. This is one of the cheapest fault-attack defences and is mandatory in PKCS#1 v2.2.

**Bug class:** RSA signature published as if it were ciphertext; CRT fault attack as the canonical fallback.

## Defender takeaways — patterns to look for in your codebase

Every challenge in this writeup maps to a class of bug that exists in production code. The defender-side takeaways, grouped by domain:

**RSA implementation.** Reject candidate primes with small factors before passing them to Miller-Rabin. `for small_p in PRIMES[:1000]: if cand % small_p == 0: continue` is microseconds of cost. Production libraries do this; rolling your own RNG-driven prime sampler without the small-factor reject is the bug class. Also: **never publish a signature alongside a "ciphertext"** without explicit threat modelling — the signature recovers the message under the public key. PKCS#1 v2.2 mandates sign-then-verify against the public key before returning the signature; CRT-RSA implementations that skip this step are vulnerable to the Bellcore fault attack.

**Classical / stream ciphers.** Any cipher whose output is `f(plaintext) * internal_state` or `f(plaintext) XOR internal_state` is broken the moment one plaintext byte is known. In production, the equivalent of "flag-format-as-known-prefix" is **file format magic, protocol framing, message envelopes** — all of which are essentially always known. A stream-cipher implementation that mixes plaintext into internal state via multiplication is broken even before nonce-reuse considerations.

**Type punning in C.** The pattern `*(long *)&float` (and friends) is **undefined behavior** under strict-aliasing rules in C99+ and C++. The standardised punning paths are `union` (C only, C++ implementation-defined) or `memcpy(&dst, &src, sizeof(dst))`. Production code should treat any pointer cast between unrelated types as a finding; `-Wstrict-aliasing` catches most of these at compile time.

**Compression / encoding interop.** Huffman coding is not specified by a single tree-construction convention. RFC 1951 (DEFLATE) sidesteps this by transmitting code lengths; bespoke Huffman implementations that transmit a tree shape must specify the tiebreak. Anywhere you interoperate compressed streams across implementations, the tree-construction tiebreak must be in the interop spec or you'll see "decodes correctly except in the middle" bug reports.

**APK distribution.** Static strings shipped in an APK are **public**. The defender story for any genuinely-sensitive secret is "don't ship it in the APK at all" — retrieve it at runtime over an attested channel. If you must ship a secret in the APK (e.g. an obfuscated short-lived token), grep `strings.xml`, the manifest's `android:description`/`android:label`, theme files, and the entire `res/` tree as part of release engineering. Single-source the secret if you can.

**Web rendering vs source.** The `hidden` HTML attribute, CSS `display: none`, white-on-white text, and HTML comments all hide content from rendering but ship it in the source. Anywhere your server emits user-data into HTML, check whether the data is also accessible via `View Source` or `curl`. The classical defence is "don't put sensitive data in HTML at all" — render server-side and emit only the rendered fragment.

**Reverse engineering.** If you ship a stripped binary, strip it *completely* — symbol-bearing checker programs (the `Do you know the way?` pattern) are routinely brute-forced via per-byte emulation. Production code obfuscation should remove function symbols at link time; otherwise the static names give the attacker the entire structure of the check.

## Frequently asked questions

### What is DalCTF?

DalCTF is a Jeopardy-style Capture the Flag event hosted at [dalctf2026.com](https://dalctf2026.com/). The 2026 edition spans Crypto, Reverse Engineering, Web, and Android categories, with infrastructure under `*.instancer.dalctf2026.com` for per-team instanced challenges.

### How many challenges did you solve at DalCTF 2026?

Nine flags across one Android, one reverse-engineering, one web, and six crypto challenges. The full reproduction repository at [Abdelkad3r/dalctf-2026](https://github.com/Abdelkad3r/dalctf-2026) contains a standalone writeup with solver code for each.

### What was the trickiest challenge?

`Compression isn't encryption`. The Huffman decode first produced a string with correct prefix and suffix but a garbled middle. That asymmetric failure mode is the entire diagnostic: the tree topology is right, but the tiebreaker convention for equal-probability nodes is inverted. Flipping the counter sign in the heap tuple (`(p, -counter, ch)` instead of `(p, counter, ch)`) makes the same decoder produce the correct flag.

### How does the Angry Shamir RSA attack work?

The 2054-bit modulus `n` has a tiny prime factor (67) because the prime generator forgot to reject candidates with small factors. `n % 67 == 0` is a single line of Python. Compute `q = n // 67`, verify `q` is prime via Miller-Rabin, decrypt with `phi = 66 * (q - 1)` and `d = pow(e, -1, phi)`. No Fermat, no Wiener, no Coppersmith — trial division is the right first attack whenever the title hints at "small", "weak", "broken", or "angry".

### Why does `pow(s, e, n)` recover the message in Fun with RSA?

The script publishes `s = pow(m, d, n)`, which is the RSA signature of the plaintext `m`. The public exponent `e` is also given. By definition of RSA, `pow(s, e, n) == m mod n` — the signature *is* the message under a permutation that the public key inverts. The intended attack is the Bellcore CRT-fault path using the published `spz` half-signature, but the two-line `pow(s, e, n)` shortcut also works because the script accidentally published the signature alongside the public key.

### What is the Bellcore fault attack on CRT-RSA?

The 1997 Boneh-DeMillo-Lipton attack: if a CRT-based RSA signature computation has a fault in the p-half (e.g. `sp` flipped one bit), then `spz ≡ sp_faulty (mod p)` but `≡ sq (mod q)`. The correct signature `s` is congruent to `spz` mod `q` but not mod `p`. Therefore `gcd(s - spz, n) = q`, recovering one prime factor of `n`. Defended in production by sign-then-verify: compute the signature, then verify against the public key before returning; abort if verification fails.

### Why is the All's Fair flag in raw uppercase?

DalCTF 2026's flag format is mostly `dalctf{lowercase_with_underscores}`, but for the Playfair challenge the accepted flag is `dalctf{ANYTHINGFORTHEFLAG}` — raw uppercase, no underscores. The teaching point is to not auto-normalize the decrypted plaintext before submitting. Always try the literal plaintext as-is first.

### How does the LCG Seed Squared attack avoid recovering the seed?

The script publishes `t_i = ord(flag[i]) * x_{i+1}`. The flag's first byte is `D` (because the format is `DalCTF{...`), so `ord('D') = 68`, and `x_1 = t_0 / 68 = 1048576`. From `x_1` the LCG can run forward indefinitely, and each `t_i / x_{i+1}` lands cleanly in printable ASCII. No seed inversion needed — the known plaintext byte is the entire vulnerability.

### What's the Quake trick referenced in Playing with Pointers?

Quake III's `Q_rsqrt` function computes a fast approximation of `1/sqrt(x)` by reinterpreting a `float`'s IEEE-754 bit pattern as a 32-bit integer, subtracting it from the magic number `0x5f3759df`, and re-interpreting back. The reinterpretation is the `i = *(long *)&y` step. In DalCTF's challenge the same `*(long *)&fflag[i]` pattern is used to leak the squared-character bit pattern — reverse by packing as little-endian 4 bytes, unpacking as a float, taking `sqrt`, and rounding.

### How was the Baby Android flag fragmented?

Three pieces across three different artefacts in the APK: `MainActivity.java` (literal string field), `res/values/strings.xml` (string resource also referenced as `android:description` on `MainActivity` in the manifest), and `ui/theme/ColorKt.java` (literal string field in a theme file). The teaching point is that flag fragments love non-Java sinks — `strings.xml`, the manifest's accessibility attributes, and theme files are routinely overlooked by `jadx`-only review pipelines.

### Where can I find the solver code?

The full source repository is at [github.com/Abdelkad3r/dalctf-2026](https://github.com/Abdelkad3r/dalctf-2026). Each challenge writeup contains the solver script inline; for compact reproductions, copy the Python blocks directly into a venv with `pycryptodome` and `heapq` from the stdlib.

### What's the broader lesson from DalCTF 2026?

**Read the challenge name as a hint.** Six of nine challenges this engagement turned on a single-word title clue: "All's Fair" = Playfair, "Angry Shamir" = broken RSA modulus, "Compression isn't encryption" = Huffman, "Playing with Pointers" = type punning, "Fun with RSA" = published signature, "Seed Squared" = misdirection toward the seed. Match the name to the artefact before reaching for the heaviest attack the artefact superficially supports.

## Closing notes and links

The full per-challenge writeups, with solver scripts, RSA values, Huffman tree builders, and the radare2 disassembly for `Do you know the way?`, live in the source repository:

- **Main repo:** [github.com/Abdelkad3r/dalctf-2026](https://github.com/Abdelkad3r/dalctf-2026)
- **Crypto track:** [`crypto/`](https://github.com/Abdelkad3r/dalctf-2026/tree/main/crypto)
- **Reverse track:** [`rev/`](https://github.com/Abdelkad3r/dalctf-2026/tree/main/rev)
- **Web track:** [`web/`](https://github.com/Abdelkad3r/dalctf-2026/tree/main/web)
- **Android track:** [`android/`](https://github.com/Abdelkad3r/dalctf-2026/tree/main/android)

For more CTF coverage — including the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) (19 challenges across reverse, crypto, web, pwn, and misc), the [BhAcKAri CTF 2026 multi-category writeup](/ctf-writeups/bhackari-ctf-2026-writeup/), and the [SAS CTF 2026 Quals Incident 67 BGP hijack writeup](/ctf-writeups/incident-67-bgp-hijack-crypto-wallet/) — see the full [CTF writeups index](/ctf-writeups/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is DalCTF?","acceptedAnswer": {"@type": "Answer","text": "DalCTF is a Jeopardy-style Capture the Flag event hosted at dalctf2026.com. The 2026 edition spans Crypto, Reverse Engineering, Web, and Android categories, with infrastructure under *.instancer.dalctf2026.com for per-team instanced challenges."}},
    {"@type": "Question","name": "How many challenges did you solve at DalCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "Nine flags across one Android, one reverse-engineering, one web, and six crypto challenges. The full reproduction repository at github.com/Abdelkad3r/dalctf-2026 contains a standalone writeup with solver code for each."}},
    {"@type": "Question","name": "What was the trickiest challenge at DalCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "Compression isn't encryption. The Huffman decode first produced a string with correct prefix and suffix but a garbled middle. That asymmetric failure is the diagnostic: the tree topology is right but the tiebreaker convention for equal-probability nodes is inverted. Flipping the counter sign in the heap tuple makes the same decoder produce the correct flag."}},
    {"@type": "Question","name": "How does the Angry Shamir RSA attack work?","acceptedAnswer": {"@type": "Answer","text": "The 2054-bit modulus n has a tiny prime factor (67) because the prime generator forgot to reject candidates with small factors. n % 67 == 0 is a single line of Python. Compute q = n // 67, verify q is prime, decrypt with phi = 66 * (q - 1) and d = pow(e, -1, phi). Trial division is the right first attack whenever the title hints at small, weak, broken, or angry."}},
    {"@type": "Question","name": "Why does pow(s, e, n) recover the message in Fun with RSA?","acceptedAnswer": {"@type": "Answer","text": "The script publishes s = pow(m, d, n), which is the RSA signature of plaintext m. The public exponent e is also given. By definition of RSA, pow(s, e, n) == m mod n — the signature is the message under a permutation that the public key inverts. The intended attack is the Bellcore CRT-fault path using spz, but the two-line pow(s, e, n) shortcut also works because the script accidentally published the signature alongside the public key."}},
    {"@type": "Question","name": "What is the Bellcore fault attack on CRT-RSA?","acceptedAnswer": {"@type": "Answer","text": "The 1997 Boneh-DeMillo-Lipton attack: if a CRT-based RSA signature computation has a fault in the p-half, then spz ≡ sp_faulty (mod p) but ≡ sq (mod q). The correct signature s is congruent to spz mod q but not mod p. Therefore gcd(s - spz, n) = q, recovering one prime factor of n. Defended by sign-then-verify before returning the signature."}},
    {"@type": "Question","name": "Why is the All's Fair flag in raw uppercase?","acceptedAnswer": {"@type": "Answer","text": "DalCTF 2026's flag format is mostly dalctf{lowercase_with_underscores}, but for the Playfair challenge the accepted flag is dalctf{ANYTHINGFORTHEFLAG} — raw uppercase, no underscores. Don't auto-normalize the decrypted plaintext before submitting; always try the literal plaintext as-is first."}},
    {"@type": "Question","name": "How does the LCG Seed Squared attack avoid recovering the seed?","acceptedAnswer": {"@type": "Answer","text": "The script publishes t_i = ord(flag[i]) * x_{i+1}. The flag's first byte is D (format is DalCTF{...), so ord('D') = 68, and x_1 = t_0 / 68 = 1048576. From x_1 the LCG can run forward indefinitely, and each t_i / x_{i+1} lands cleanly in printable ASCII. No seed inversion needed."}},
    {"@type": "Question","name": "What's the Quake trick in Playing with Pointers?","acceptedAnswer": {"@type": "Answer","text": "Quake III's Q_rsqrt computes a fast approximation of 1/sqrt(x) by reinterpreting a float's IEEE-754 bit pattern as a 32-bit integer. The reinterpretation step is i = *(long *)&y. In DalCTF's challenge the same pattern is used to leak the squared-character bit pattern. Reverse by packing as little-endian 4 bytes, unpacking as a float, taking sqrt, and rounding."}},
    {"@type": "Question","name": "How was the Baby Android flag fragmented?","acceptedAnswer": {"@type": "Answer","text": "Three pieces across three different artefacts in the APK: MainActivity.java (literal string field), res/values/strings.xml (string resource also referenced as android:description on MainActivity in the manifest), and ui/theme/ColorKt.java (literal string field in a theme file). Flag fragments love non-Java sinks — strings.xml, manifest accessibility attributes, and theme files are routinely overlooked."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "The full source repository is at github.com/Abdelkad3r/dalctf-2026. Each challenge writeup contains the solver script inline; for compact reproductions, copy the Python blocks into a venv with pycryptodome and heapq from the stdlib."}},
    {"@type": "Question","name": "What's the broader lesson from DalCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "Read the challenge name as a hint. Six of nine challenges turned on a single-word title clue: All's Fair = Playfair, Angry Shamir = broken RSA modulus, Compression isn't encryption = Huffman, Playing with Pointers = type punning, Fun with RSA = published signature, Seed Squared = misdirection toward the seed. Match the name to the artefact before reaching for the heaviest attack."}}
  ]
}
</script>
