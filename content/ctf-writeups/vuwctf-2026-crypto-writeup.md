---
title: "VuwCTF 2026 Cryptography Writeup: Franklin–Reiter RSA, a GF(257) Key-Gen Collapse & Dickson Permutation Polynomials"
slug: "vuwctf-2026-crypto-writeup"
description: "VuwCTF 2026 cryptography writeup covering all three challenges: nom-nom (RSA with e=3 and two related messages under one modulus, broken with the Franklin–Reiter related-message attack via a polynomial gcd over Z/nZ), concord (a 3.5e13-operation AES key schedule that collapses to 256 candidates once you see op() is multiplication in GF(257) and Fermat's little theorem kills the 1 GB inner sweep), and D (a 16-round GF(2^128) block cipher whose nonlinear layer is the Dickson polynomial D_13(x,19), inverted with the composition identity D_m(D_n(x,a),a^n)=D_mn(x,a) and m = 13^-1 mod 2^256-1)."
date: 2026-08-03T14:00:00Z
lastmod: 2026-08-03T14:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["VuwCTF 2026"]
tags:
  - "vuwctf"
  - "vuwctf 2026"
  - "ctf writeup"
  - "crypto"
  - "cryptography"
  - "rsa"
  - "franklin-reiter"
  - "related message attack"
  - "coppersmith"
  - "polynomial gcd"
  - "small public exponent"
  - "finite fields"
  - "gf(257)"
  - "fermat's little theorem"
  - "dickson polynomials"
  - "permutation polynomials"
  - "block cipher"
  - "gf(2^128)"
  - "sagemath"
  - "ctf 2026"
keywords:
  - "vuwctf 2026 crypto writeup"
  - "nom-nom vuwctf writeup"
  - "concord vuwctf writeup"
  - "d vuwctf dickson polynomial writeup"
  - "franklin reiter related message attack ctf"
  - "rsa e=3 related message polynomial gcd"
  - "polynomial gcd over z/nz ctf"
  - "gf(257) multiplication op ctf"
  - "fermat little theorem key schedule collapse"
  - "dickson permutation polynomial inverse ctf"
  - "d_13 x 19 block cipher invert sage"
  - "gf(2^128) cbc cipher ctf 2026"
  - "13 inverse mod 2^256-1 dickson"
  - "vuwctf cryptography challenge"
  - "permuting permutation polynomials flag"
toc: true
cover:
  image: "/images/articles/vuwctf-2026-crypto-writeup.png"
  alt: "VuwCTF 2026 cryptography writeup — three challenges covering nom-nom an RSA scheme with public exponent 3 that gives two ciphertexts of related plaintexts under a single modulus where the flag envelope VuwCTF brace makes the flag plaintext a known linear function A times m_inner plus B of the inner message so the Franklin-Reiter related-message attack recovers the message as the constant term of the monic gcd of x cubed minus c_inner and A x plus B cubed minus c_flag over the ring Z mod n; concord an AES-CBC challenge whose key schedule runs 32 times 1023 iterations each sweeping a billion pseudorandom bytes but where op a b equals a plus one times b plus one mod 257 minus one is multiplication in the field GF(257) so Fermat's little theorem collapses the 2 to the 30 inner product to a single constant P leaving only 256 candidate keys to brute force; and D a 16-round CBC block cipher over GF(2 to the 128) whose nonlinear round function is the Dickson polynomial D_13 of x with parameter 19 inverted using the composition identity D_m of D_n equals D_mn and the inverse exponent m equal to 13 inverse mod 2 to the 256 minus 1 to decrypt the flag PNG"
---

VuwCTF 2026's cryptography track was three lessons in the same idea: **the expensive-looking thing is a thin disguise over one clean algebraic fact.** `nom-nom` (100 pts, Easy) dresses an RSA flag as a template around an inner message — which is exactly the linear relation the Franklin–Reiter attack needs. `concord` (100 pts, Medium) flexes a key schedule that costs 35 trillion operations, all of which evaporate once you notice its core operation is multiplication in `GF(257)` and Fermat's little theorem zeroes the exponent. `D` (316 pts, Hard) builds a 16-round `GF(2^128)` block cipher whose only nonlinear layer is a Dickson polynomial — a *permutation* polynomial with a closed-form inverse. This writeup solves all three step by step, with the algebra spelled out.

All challenge files and solvers are at [Abdelkad3r/VuwCTF-2026](https://github.com/Abdelkad3r/VuwCTF-2026/tree/master/Crypto). Every flag is verified by re-encrypting the recovered plaintext against the given parameters — not guessed.

## Challenges at a glance

| Challenge | Difficulty | Points | Core primitive | Attack |
|---|---|---|---|---|
| nom-nom | Easy | 100 | RSA, `e = 3`, shared `n` | Franklin–Reiter related-message (poly gcd over `Z/nZ`) |
| concord | Medium | 100 | AES-CBC key schedule over `GF(257)` | Fermat collapse → 256-candidate brute force |
| D | Hard | 316 | `GF(2^128)` cipher, Dickson `D_13(x,19)` | Permutation-polynomial inverse via composition |

---

## Challenge 1 — nom-nom (Easy, 100 pts)

We get an RSA modulus `n` (2048-bit), `e = 3`, and **two** ciphertexts:

```text
e = 3
n = 2370719799...45971
c_flag_inner = 1133267644...89781     # RSA(inner message)
c_flag       = 9527654200...50991973  # RSA(VuwCTF{ inner })
```

The flag is `VuwCTF{<inner>}` with `<inner>` exactly 16 ASCII bytes → 24-byte
plaintext.

### Step 1 — Write the relation between the two plaintexts

The two plaintexts aren't independent; the second is the first wrapped in a
fixed 8-byte envelope. As big-endian integers:

```text
m_flag = P·256^17 + m_inner·256 + S
       = A·m_inner + B
  where  A = 256
         B = P·256^17 + S
         P = int.from_bytes(b"VuwCTF{")   (7 bytes)
         S = int.from_bytes(b"}")         (1 byte)
```

`A` and `B` are fully known constants. The only unknown is `m_inner`.

### Step 2 — Recognize Franklin–Reiter

Two ciphertexts of *related* messages — `m_2 = f(m_1)` for a known low-degree
`f` — under a **shared modulus** and **small `e`** are exactly the setup for the
**Franklin–Reiter related-message attack** (CRYPTO '96). With `e = 3` and
`f(x) = A·x + B`, both of these polynomials in `(Z/nZ)[x]` vanish at
`x = m_inner`:

```text
g_1(x) = x^3 − c_flag_inner
g_2(x) = (A·x + B)^3 − c_flag
```

So `(x − m_inner)` divides both, and with overwhelming probability their gcd is
exactly that linear factor:

```text
h(x) = gcd(g_1, g_2)  =  x − m_inner       (monic, degree 1)
```

Reading `m_inner` off the constant term recovers the message.

### Step 3 — gcd over a ring that isn't a field

`Z/nZ` is not a field (`n = p·q`), so the Euclidean algorithm needs a guard:
each reduction inverts the divisor's leading coefficient with `pow(lc, -1, n)`.
If that inverse fails, `gcd(lc, n) > 1` — which means we just **factored `n`**,
an even better outcome. In practice it never triggers here; the reduction
returns a degree-1 polynomial on the first pass. The solver implements
`poly_mod`/`poly_gcd` over `Z/nZ` in pure Python `int`s — no SymPy, no Sage.

### Step 4 — Solve and verify

```console
$ python3 solve.py
gcd deg = 1
m_inner       = 104258345777904576648690201020578295661
m_inner bytes = b'NomPolynomialNom'
FLAG          = VuwCTF{NomPolynomialNom}
[+] both ciphertexts verified
```

The two `assert`s re-encrypt the recovered plaintexts under `(n, e)` and confirm
they reproduce both original ciphertexts — the flag is proven, not guessed.

### Flag

```text
VuwCTF{NomPolynomialNom}
```

**Why not Håstad?** Håstad's broadcast attack wants `e` ciphertexts of the
*same* plaintext under `e` *distinct* moduli. Here we have two ciphertexts of
*different* plaintexts under *one* modulus — Franklin–Reiter is the tool that
matches the givens. `e = 3` is the sweet spot: `(A·x + B)^e − c_2` has degree
`e`, so the Euclidean reduction is `O(e^2)` polynomial operations.

---

## Challenge 2 — concord (Medium, 100 pts)

> I encrypted the flag on a powerful HPC cluster and my poor laptop can't decrypt
> it no matter how hard it tries.

Two files: `concord.py` (encryptor) and `concord.ciphertext` (hex AES-CBC). The
encryptor:

```python
from random import seed, randbytes
from functools import reduce
seed("concord")

def op(a, b):
    return (a+1)*(b+1) % 257 - 1

rand_input = randbytes(2**30)          # 1 GB of deterministic PRNG bytes
state = 0
key = []
for j in range(32):
    for i in range(1023):
        state = op(reduce(op, (op(rand_input[j+i], b) for b in rand_input)), state)
    key.append(state)

cipher = AES.new(bytes(key), AES.MODE_CBC, iv=bytes.fromhex("243f57341528c28727458b8cc5f52786"))
print(cipher.encrypt(flag).hex())
```

The key schedule is `32 × 1023 = 32,736` outer steps, each sweeping all `2^30`
bytes of `rand_input` → `≈ 3.5 × 10^13` operations. That's the "HPC" flavor. The
whole challenge is realizing you never have to run it.

### Step 1 — `op` is multiplication in GF(257)

257 is prime, so `GF(257)` exists. Define φ(x) = x + 1. Then:

```text
φ(op(a,b)) = (a+1)(b+1) mod 257 = φ(a)·φ(b)
```

`op` is field multiplication shifted down by 1. Consequently
`reduce(op, [v_0,…,v_{n-1}]) + 1 = ∏ (v_i + 1) mod 257`.

### Step 2 — The billion-byte inner sweep is constant

The inner generator is `op(rand_input[j+i], b) for b in rand_input`. Let
`c = rand_input[j+i] + 1`. In the field, each term is `c·(b+1)`, so the whole
reduce is:

```text
reduce(...) + 1 = ∏_b [ c·(b+1) ] = c^n · P      where n = 2^30,  P = ∏(b+1) mod 257
```

Now apply Fermat: `GF(257)*` is cyclic of order 256, and **256 | 2^30**, so
`c^(2^30) = (c^256)^(2^22) = 1`. The `c^n` factor vanishes:

```text
inner reduce ≡ P − 1     for every j, i, regardless of rand_input[j+i]
```

The 1 GB sweep is a red herring — it always produces the same constant `P − 1`.

### Step 3 — The key is a geometric sequence in P

Each outer step becomes `state = op(P−1, state)`, i.e. φ(state_new) = P·φ(state_old).
From `state = 0` (φ = 1), after `k` steps φ(state) = P^k. Key byte `j` is stored
after `(j+1)·1023` steps:

```text
key[j] = P^(1023·(j+1)) − 1  mod 257 = P^(255·(j+1) mod 256) − 1     (since 1023 ≡ 255 mod 256)
```

### Step 4 — Only 256 possible P → brute force

`P ∈ GF(257)*` has just 256 possible values. Try each, rebuild the 32-byte key,
AES-CBC-decrypt, and check for the `VuwCTF{` prefix:

```python
for log_p in range(256):
    P = pow(3, log_p, 257)                              # 3 is a primitive root mod 257
    key = bytes(pow(P, 1023*(j+1) % 256, 257) - 1 for j in range(32))
    pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
    if pt[:7] == b"VuwCTF{":
        print(pt.rstrip(pt[-1:].ljust(1, pt[-1:])).decode()); break
```

```text
P = 239  (log_3 239 = 178)
Key: 9ce9f30e29a83de073dd9e21c5f547fc8e5b33c4585e087f318b8678eb2be10f
Flag: VuwCTF{crypto_loves_mathematics}
```

Runs in under a millisecond. The `\x10`×16 PKCS#7 padding confirms a 32-byte
plaintext padded to 48 bytes.

### Flag

```text
VuwCTF{crypto_loves_mathematics}
```

**The three-line collapse:** (1) `op` is `GF(257)` multiplication; (2) Fermat
kills the `2^30`-fold inner product to a single constant `P`; (3) only 256 values
of `P` exist. `O(3.5×10^13)` → `O(256)` AES decryptions.

---

## Challenge 3 — D (Hard, 316 pts)

> Not the programming language, sadly.

Handout: `D.sage` (encryptor) and `flag.png.encrypted`. The cipher operates over
`GF(2^128)` (block size = one field element):

```python
key = random.Random(b"p-box").randbytes(128)         # deterministic — no secret
F.<x> = GF(340282366920938463463374607431768211456)  # 2^128
R.<y> = PolynomialRing(F)

def D(n, a):                                          # Dickson recurrence
    if n == 0: return 0
    if n == 1: return y
    return y*D(n-1, a) - a*D(n-2, a)

p = D(13, F.from_integer(19))                         # nonlinear round function
```

### Step 1 — Read the structure

The key stream is derived from a fixed seed `b"p-box"` — there is **no unknown
secret**. This is not key recovery; it's inverting a transformation. The mode is
CBC-like (each block XORed with the previous ciphertext), and `encrypt_block`
runs 16 rounds of:

1. XOR the next deterministic round key,
2. apply the field polynomial `p = D_13(x, 19)`,
3. a 4×4 ShiftRows-style byte permutation.

The permutation is trivially invertible. The only real question is inverting the
polynomial.

### Step 2 — A Dickson polynomial is a permutation polynomial

Dickson polynomials satisfy the composition identity:

```text
D_m(D_n(x, a), a^n) = D_{mn}(x, a)
```

Over `GF(q)`, `D_n(x, a)` permutes the field iff `gcd(n, q^2 − 1) = 1`. Here
`q = 2^128`, `n = 13`, and `gcd(13, 2^256 − 1) = 1` — so `D_13` is a bijection
with a clean inverse. Pick

```text
m = 13^{-1} mod (2^256 − 1)
```

Then `D_m(·, 19^13)` inverts `D_13(·, 19)`, because
`D_m(D_13(x, 19), 19^13) = D_{13m}(x, 19) = D_1(x, 19) = x` (the exponent
`13m ≡ 1`). Verified in Sage on random elements:

```python
m = inverse_mod(13, 2^256 - 1)
z = F.random_element()
assert D(m, F(19)^13)(D(13, F(19))(z)) == z
```

### Step 3 — Invert one round, then the chain

Encryption of one round is `state = ShiftRows(D_13(state ⊕ round_key, 19))`, so
decryption reverses it:

```text
state = D_m( UnshiftRows(state), 19^13 ) ⊕ round_key
```

Apply the 16 rounds in reverse order to turn each ciphertext block back into its
CBC-mixed block, then XOR off the previous ciphertext block to recover the true
PNG block.

### Step 4 — Run the Sage solver

```console
$ sage solve.sage
[+] ciphertext blocks: 725
[+] inverse exponent m: 53442502724915167118571223850163649778432300614911029556672731080575290603047
[+] wrote: artifacts/flag.png
[+] sha256(flag.png): 6b244e866a232b4941dc19db8590972eb51af7e745e81c9bb6d0fbbdab1d1f12
[+] elapsed: 32.812s
[+] flag: VuwCTF{permuting_permutation_polynomials}
```

The recovered `flag.png` renders the flag.

### Flag

```text
VuwCTF{permuting_permutation_polynomials}
```

**The whole trick** is recognizing `D_13(x, 19)` as a Dickson polynomial and
knowing its permutation condition. Once `gcd(13, 2^256 − 1) = 1` holds, the
"custom block cipher" is a stack of individually reversible layers, and the flag
name — *permuting permutation polynomials* — is the hint stated outright.

---

## Cross-cutting notes

**The costly surface is the disguise; find the algebraic identity underneath.**
All three challenges advertise difficulty they don't actually have. nom-nom's
"two RSA ciphertexts" is a linear relation; concord's 35-trillion-operation key
schedule is one `GF(257)` constant; D's "custom cipher" is a permutation
polynomial with a closed-form inverse. Reversing crypto is mostly identifying
which known structure the author dressed up.

**Small `e` + a known relation between plaintexts = Franklin–Reiter.** Whenever
you see two RSA ciphertexts under one modulus where one plaintext is a known
low-degree function of the other (a fixed prefix/suffix, a counter, a linear
tweak), compute the polynomial gcd of `x^e − c_1` and `f(x)^e − c_2` over
`Z/nZ`. The message falls out as the linear factor.

**Fermat's little theorem is the great collapser.** In `GF(p)*` any exponent that
is a multiple of `p − 1` is the identity. concord's billion-byte inner loop
raises a field element to the `2^30`, and `256 | 2^30`, so it's just `1`. When a
challenge makes you exponentiate by a suspiciously round number, check it mod the
group order first.

**Permutation polynomials are invertible by design.** Dickson polynomials
`D_n(x, a)` permute `GF(q)` exactly when `gcd(n, q^2 − 1) = 1`, and the inverse is
`D_m(x, a^n)` with `m = n^{-1} mod (q^2 − 1)`, thanks to the composition identity
`D_m(D_n(x,a),a^n) = D_{mn}(x,a)`. A "nonlinear round function" built from one is
not a one-way function.

**Deterministic "keys" mean it's not key recovery.** Both concord and D derive
their key material from a fixed, public seed. When the RNG is seeded with a
constant, there is no secret to recover — the challenge is always about inverting
a transformation you can fully reconstruct.

---

## Frequently Asked Questions

**Q: What is the Franklin–Reiter related-message attack?**

It recovers RSA plaintexts when two messages `m_1` and `m_2 = f(m_1)` (for a
known low-degree polynomial `f`) are encrypted under the *same* modulus with a
*small* public exponent `e`. Both `g_1(x) = x^e − c_1` and `g_2(x) = f(x)^e − c_2`
have `m_1` as a root, so `(x − m_1)` divides their gcd over `(Z/nZ)[x]`. With
overwhelming probability that gcd is exactly `x − m_1`, revealing the message. In
nom-nom, `f(x) = 256·x + B` because the flag is the inner message wrapped in the
fixed `VuwCTF{…}` envelope.

**Q: How do you compute a polynomial gcd over Z/nZ when n isn't prime?**

Run the Euclidean algorithm as usual, but to make each divisor monic you must
invert its leading coefficient modulo `n` with `pow(lc, -1, n)`. If that inverse
doesn't exist, then `gcd(lc, n)` is a nontrivial factor of `n` — you've factored
the modulus, which breaks RSA outright. For nom-nom this never triggers and the
gcd reduces to a linear polynomial on the first attempt.

**Q: Why does concord's billion-byte key schedule collapse to 256 possibilities?**

The operation `op(a,b) = (a+1)(b+1) mod 257 − 1` is multiplication in `GF(257)`
under the map φ(x) = x+1. The inner loop multiplies `2^30` field elements, which
factors as `c^(2^30) · P`. Since `GF(257)*` has order 256 and `256` divides
`2^30`, Fermat's little theorem makes `c^(2^30) = 1`, so every inner reduce equals
the single constant `P − 1`. The key becomes a geometric sequence in `P`, and `P`
has only 256 possible values in `GF(257)*` — trivially brute-forced.

**Q: What is a Dickson polynomial and when is it invertible?**

A Dickson polynomial `D_n(x, a)` is defined by the recurrence
`D_n = x·D_{n-1} − a·D_{n-2}` with `D_0 = 2`… (here `D_0 = 0`, `D_1 = x` per the
challenge's variant). Over `GF(q)` it is a permutation polynomial — a bijection —
exactly when `gcd(n, q^2 − 1) = 1`. Its inverse is `D_m(x, a^n)` where
`m = n^{-1} mod (q^2 − 1)`, which follows from the composition identity
`D_m(D_n(x, a), a^n) = D_{mn}(x, a)`.

**Q: How is the D challenge inverted if it's a custom block cipher?**

Because there is no secret key (it's seeded from a constant) and every layer is
reversible. Each of the 16 rounds is XOR-key → `D_13(x, 19)` → ShiftRows. The
ShiftRows permutation is directly invertible, and `D_13` is inverted by
`D_m(x, 19^13)` with `m = 13^{-1} mod (2^256 − 1)` since `q = 2^128`. Undo the
rounds in reverse, then undo the CBC chaining with the previous ciphertext block
to recover the flag PNG.

**Q: What are the flags for the VuwCTF 2026 crypto challenges?**

nom-nom: `VuwCTF{NomPolynomialNom}`. concord: `VuwCTF{crypto_loves_mathematics}`.
D: `VuwCTF{permuting_permutation_polynomials}`.

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is the Franklin–Reiter related-message attack?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "It recovers RSA plaintexts when two messages m1 and m2 = f(m1), for a known low-degree polynomial f, are encrypted under the same modulus with a small public exponent e. Both g1(x) = x^e − c1 and g2(x) = f(x)^e − c2 have m1 as a root, so (x − m1) divides their gcd over the ring Z/nZ. With overwhelming probability that gcd is exactly x − m1, revealing the message. In nom-nom, f(x) = 256*x + B because the flag is the inner message wrapped in the fixed VuwCTF envelope."
      }
    },
    {
      "@type": "Question",
      "name": "How do you compute a polynomial gcd over Z/nZ when n is not prime?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Run the Euclidean algorithm as usual, but to make each divisor monic you must invert its leading coefficient modulo n with pow(lc, -1, n). If that inverse does not exist, then gcd(lc, n) is a nontrivial factor of n, which means you have factored the modulus and broken RSA outright. For nom-nom this never triggers and the gcd reduces to a linear polynomial on the first attempt, whose constant term is the recovered inner message."
      }
    },
    {
      "@type": "Question",
      "name": "Why does concord's billion-byte key schedule collapse to 256 possibilities?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The operation op(a,b) = (a+1)(b+1) mod 257 − 1 is multiplication in GF(257) under the map phi(x) = x+1. The inner loop multiplies 2^30 field elements, which factors as c^(2^30) times P. Since GF(257)* has order 256 and 256 divides 2^30, Fermat's little theorem makes c^(2^30) = 1, so every inner reduce equals the single constant P − 1. The key becomes a geometric sequence in P, and P has only 256 possible values in GF(257)*, which is trivially brute-forced against the VuwCTF prefix."
      }
    },
    {
      "@type": "Question",
      "name": "What is a Dickson polynomial and when is it invertible?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "A Dickson polynomial D_n(x, a) is defined by the recurrence D_n = x*D_{n-1} − a*D_{n-2}. Over GF(q) it is a permutation polynomial, a bijection, exactly when gcd(n, q^2 − 1) = 1. Its inverse is D_m(x, a^n) where m = n^{-1} mod (q^2 − 1), which follows from the composition identity D_m(D_n(x, a), a^n) = D_{mn}(x, a). In the D challenge n = 13 and q = 2^128, and gcd(13, 2^256 − 1) = 1, so the round function is invertible."
      }
    },
    {
      "@type": "Question",
      "name": "How is the D challenge inverted if it is a custom block cipher?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Because there is no secret key — it is seeded from the constant b'p-box' — and every layer is reversible. Each of the 16 rounds is XOR-key, then D_13(x, 19), then a ShiftRows byte permutation. The permutation is directly invertible and D_13 is inverted by D_m(x, 19^13) with m = 13^{-1} mod (2^256 − 1). Undo the rounds in reverse order, then undo the CBC chaining by XORing the previous ciphertext block, to recover the flag PNG."
      }
    },
    {
      "@type": "Question",
      "name": "What are the flags for the VuwCTF 2026 cryptography challenges?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "nom-nom: VuwCTF{NomPolynomialNom}. concord: VuwCTF{crypto_loves_mathematics}. D: VuwCTF{permuting_permutation_polynomials}."
      }
    }
  ]
}
```
