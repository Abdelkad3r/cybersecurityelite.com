---
title: "OmniCTF 2026 Quals Crypto Writeup: 3 Challenges Solved"
slug: "omnictf-2026-quals-crypto-writeup"
description: "OmniCTF 2026 Quals crypto step-by-step: dual_linera CRT-collapse LWE + LLL, Whiskerfield DH mod 65537^16 one-byte patch to shared=0, Orbital octonion state rank test."
date: 2026-07-19T20:00:00Z
lastmod: 2026-07-19T20:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["OmniCTF 2026 Quals"]
tags:
  - "omnictf"
  - "omnictf 2026"
  - "omnictf quals"
  - "ctf writeup"
  - "crypto"
  - "cryptography"
  - "lwe"
  - "lll lattice reduction"
  - "crt shared error"
  - "diffie-hellman prime power"
  - "fermat prime dh"
  - "octonion cryptanalysis"
  - "non-associative algebra"
  - "broken rng lcg"
  - "shared secret zero attack"
  - "hidden number problem"
keywords:
  - "omnictf 2026 quals crypto writeup"
  - "omnictf dual_linera writeup"
  - "omnictf whiskerfield meowtin writeup"
  - "omnictf orbital strike cannon writeup"
  - "two-modulus lwe crt attack"
  - "shared error e lwe cryptanalysis"
  - "lll lattice attack 20-dimensional"
  - "dh mod p^k prime power collapse"
  - "65537^16 fermat prime dh"
  - "shared secret 0 one-byte patch"
  - "octonion mat_left mat_right matrix"
  - "cayley-dickson f_p linear collapse"
  - "broken lcg rng u v recovery"
  - "per-satellite rref real vs fake"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/omnictf-2026-quals-crypto-writeup.png"
  alt: "OmniCTF 2026 Quals crypto writeup — three challenges solved covering dual_linera two-modulus LWE where the same small e is used across both moduli so CRT collapse to a single equation Y equals A s plus e mod q1 q2 followed by LLL on a 20-dimensional lattice recovers the 96-bit secret, Whiskerfield-Meowtin CuteSecure DH whose modulus is 65537 raised to the 16th power and whose public value is hand-crafted as one byte flip away from a multiple of 65537 so a single-byte patch drives the shared secret to zero and the flag decrypts under a glibc-rand LCG stream cipher, and Orbital-Strike-Cannon octonion state with a broken LCG whose output stream is published and 7 satellites 5 real 2 fake where non-associative Cayley-Dickson multiplication collapses to 8x8 matrix multiplication once association order is fixed leaving 9 unknowns against 75 linear equations per real satellite solved by per-satellite RREF"
---

OmniCTF 2026 Quals shipped a crypto track built around one recurring lesson: **the algebra is scarier than the actual attack surface**. Three challenges, all rated medium, and every one dresses a mundane linear-algebra collapse in a costume the reader is expected to spend hours investigating. **dual_linera** uses two-modulus LWE where the error `e` is shared across both moduli. CRT is a linear map, so `e` survives the reconstruction and 18 samples plus LLL on a 20x20 lattice recover the 96-bit secret. **Whiskerfield-Meowtin** offers a "CuteSecure-DH" whose modulus is `65537^16` (Fermat prime to the 16th power) and whose public value is hand-crafted as one byte-flip away from a multiple of 65537. Patch the byte, drive the shared secret to zero, decrypt under the LCG stream cipher. **Orbital-Strike-Cannon** wraps a 9-unknown affine state in non-associative octonion multiplication, a published-stream "broken RNG", and 7 satellites (5 real, 2 fake), but once you fix the association order it becomes 8x8 matrix multiplication, and once you write the samples as linear equations a per-satellite RREF sorts real from fake without needing the private `real_ids`.

Handouts, per-challenge READMEs, and pure-stdlib Python solvers live at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). This writeup covers the three crypto challenges I solved. Adjacent writeups on the same event: the [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/) (Ganzir SSTI via reset-token debug leak; StayWild GNU tar `--checkpoint-action` option injection), the [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/) (nullshui glibc 2.39 tcache poison over `_IO_2_1_stdout_`; WinCapture Windows kernel-driver TOCTOU race), and the [OmniCTF 2026 Quals reverse writeup](/ctf-writeups/omnictf-2026-quals-reverse-writeup/) (CredVault Parcel migration mismatch; Gatekeep FPGA byte-circuit SAT; Kant multi-round Rust pipeline inversion; Pusher signal-driven i386 VM).

## The three OmniCTF 2026 Quals crypto challenges

| Challenge | Difficulty | Bug class / primitive | Flag |
|---|---|---|---|
| dual_linera | Medium | Sage generator produces two coprime primes `q1 ~ 2^180`, `q2 ~ 2^181`, a 96-bit secret `s`, and 18 samples `(a1, a2, y1, y2)` where `y1 = a1*s + e mod q1` and `y2 = a2*s + e mod q2` share **the same** 176-bit `e`. CRT collapses each pair into `Y ≡ A*s + e (mod Q)` with `Q = q1*q2 ~ 2^361`, same `s`, same `e`. `log Q / log e ~ 2.05` per sample, 18 samples plenty for LLL. Build a 20x20 lattice with weights `W_S = 2^80` on the secret column and `W_K = 2^176` on the shift row, LLL-reduce, read `s` off the row whose last coordinate is `±W_K`. Flag XOR'd against SHAKE256(SHA256(str(s))). | `OmniCTF{crt_makes_a_tiny_nonce_without_leaking_it}` |
| Whiskerfield-Meowtin | Medium (76 solves) | Stripped Linux `.so` implementing CuteSecure-DH. Modulus in `.rodata` is 64 hex chars; constructor pokes a `'1'` byte at offset 64, making the full string `65` hex chars = `65537^16`. Fermat prime raised to the 16th power. Wrapper's `generate_public_key_near_multiple` starts with a multiple of 65537 and XORs one byte with a small mask so it's no longer a multiple, telling you to XOR the byte back. Patch one byte so `A' ≡ 0 (mod 65537)`; since `b ≥ 2^127 >> 16`, `A'^b ≡ 0 (mod 65537^16)`. Shared secret is 0. Decrypt payload with the reverse-engineered LCG stream (glibc `rand()` multiplier + drifting increment). | `OmniCTF{I_just_LOVE_the_sm3ll_0f_f34r_1ab27f8d}` |
| Orbital-Strike-Cannon | Medium (115 solves) | Octonion state over `F_{2^127 - 1}` via Cayley-Dickson. Public: `alpha`, `beta`, `outer_a`, `rng_beacons` (full published LCG stream), 7 satellites each with `{arange, mask_offset, basis, bias, coords}`. Secret: `moon0` (8 F_P values) + `x0` (scalar) + `rng_u`, `rng_v` (LCG params). Non-associative `((R_i * M_i) * alpha)` collapses to `mat_right(alpha) * mat_left(R_i)` = one 8x8 matrix. State becomes affine map `[M_i, X_i, 1] = states[i] * [M_0, X_0, 1]`. 5 real satellites × 15 exact linear equations = 75 equations in 9 unknowns. Per-satellite RREF `[coefs | rhs]`: fake satellites produce `[0..0 \| nonzero]` inconsistency rows. RNG params recovered from two consecutive beacon differences: `u = (b_2 - b_1) / (b_1 - b_0)`, `v = b_1 - u*b_0`. | `OmniCTF{Wemmbu_h4s_destroy3d_th3_law_hell_nawhh_where-is_you_eggcha~}` |

The three challenges share a discipline worth stating up front: **the exotic algebra is a costume**. Every one of these primitives has a scary name (LWE, non-associative Cayley-Dickson, DH over `Z/p^k`), but the actual attack surface reduces to 20th-century linear algebra plus one specific structural mistake per challenge. dual_linera's mistake is sharing `e` across two moduli through a linear (CRT) map. Whiskerfield's is using a modulus whose group `(Z/p^k)^*` has an obvious filtration by powers of `p`, plus a wrapper that hand-delivers the near-multiple. Orbital's is fixing the association order and publishing the RNG state, which turns the non-associativity into a `mat_left`/`mat_right` bookkeeping distinction rather than a security feature. Once you name the mistake, the exploit is Python plus (in one case) LLL.

## Methodology — write everything linearly first

A pattern that worked on every challenge in this set: **before touching the scary primitive, write out every quantity you know as a linear function of the unknowns**. dual_linera's `y1, y2` are linear in `(s, e)` per row; CRT is linear; the composite `Y ≡ A*s + e (mod Q)` is linear. Whiskerfield's DH is exponential, but the specific exploit (`A'^b ≡ 0 (mod p^k)`) turns on divisibility, which is a purely arithmetic property. Orbital's octonion multiplication is non-associative, but the `((R_i * M_i) * alpha)` expression is `mat_right(alpha) * mat_left(R_i) * M_i` which is one 8x8 matrix in `F_P^8`. Once every quantity is linear (or reducible to divisibility), the exploit is a rank test, a lattice reduction, or a byte patch. No number theory, no algebraic geometry, no cryptographic infrastructure. Just linear algebra and one specific structural observation per challenge.

The correlate is: **don't try to invert the scary primitive**. dual_linera does not require inverting the LWE-per-modulus rows on their own (each has ratio `log q / log e ~ 1.02`, hopeless); it requires *combining* them into one row with a better ratio. Whiskerfield does not require solving discrete log mod `65537^16` (nobody knows how to do that efficiently); it requires forcing the shared-secret computation into a divisibility corner where the value is 0. Orbital does not require inverting octonion multiplication (there's no invertible-octonion trick that helps here); it requires recognising that non-associativity only affects the order-of-composition bookkeeping, and once fixed the whole system is linear.

Per-challenge walkthroughs follow.

## 1. dual_linera

Two-modulus LWE with a shared 176-bit error `e`. CRT collapses each sample pair into one equation with the same `e`; 18 samples plus LLL on a 20-dimensional lattice recover the 96-bit secret.

### Step 1 — Spot the shared invariant

Generator (Sage):

```python
q1 = random_prime(2^180, ...)
q2 = random_prime(2^181, ...)   # coprime to q1
s  = randrange(0, 2^96)         # 96-bit secret
for _ in range(18):
    a1 = randrange(1, q1)
    a2 = randrange(1, q2)
    e  = randrange(0, 2**176)   # <-- one draw per sample
    y1 = (a1 * s + e) % q1
    y2 = (a2 * s + e) % q2
```

`a1` and `a2` are independent, but the same `e` is used on both sides. Without that sharing, each row on its own is bounded-error LWE with `|e|/q ~ 2^{-4}`; the noise floor is basically the modulus, no lattice will save you. The shared `e` turns two seemingly-independent weak rows into one strong small-error row.

### Step 2 — CRT collapse

Let `Q = q1 * q2 ~ 2^361` and pick CRT coefficients:

```
u = q2 * pow(q2, -1, q1) % Q     # ≡ 1 mod q1, ≡ 0 mod q2
v = q1 * pow(q1, -1, q2) % Q     # ≡ 0 mod q1, ≡ 1 mod q2
```

Note `u + v ≡ 1 (mod Q)`. For each sample:

```
A_i = (a1_i * u + a2_i * v) % Q
Y_i = (y1_i * u + y2_i * v) % Q
```

Then:

```
Y_i ≡ a1_i*s*u + e*u + a2_i*s*v + e*v
    ≡ s*(a1_i*u + a2_i*v) + e*(u + v)
    ≡ A_i * s + e     (mod Q)
```

18 equations, same `s`, same `e`. `|s| < 2^96`, `|e| < 2^176`, `Q ~ 2^361`. `log Q / log e ~ 2.05` per sample. Well inside LLL's reach.

### Step 3 — Build the 20x20 lattice

Standard LWE construction with weights so every coordinate lands at the same scale:

```
W_S = 2^(E_BITS - SECRET_BITS) = 2^80    # weight on secret
W_K = 2^E_BITS                 = 2^176   # weight on shift
```

For `n = 18`, build the `(n+2) x (n+2) = 20 x 20` matrix:

```
row 0     : [ W_S | A_1  A_2 ...  A_n | 0   ]     <- s row
row i>=1  : [ 0   | 0    ... Q ... 0  | 0   ]     <- Q on column i
row n+1   : [ 0   | Y_1  Y_2 ...  Y_n | W_K ]     <- shift row
```

Coefficients `(s, k_1, ..., k_n, -1)` on the rows produce the target short vector:

```
target = (s * W_S, -e, -e, ..., -e, -W_K)
```

Every coordinate has magnitude ~2^176, so total L2 norm is `sqrt(20) * 2^176`. Way shorter than the generic Minkowski bound for a 20-dimensional lattice with determinant `W_S * W_K * Q^n`. LLL finds it (or a small integer multiple of it).

### Step 4 — Read `s` from the reduced basis

After LLL, scan for a row whose last coordinate is `±W_K`. That row is (up to sign) the target. Column 0 divided by `W_S` gives `±s`; take the positive representative. Sanity check on sample 0:

```python
e0  = (y1_0 - a1_0 * s) % q1
e0p = (y2_0 - a2_0 * s) % q2
assert e0 == e0p < 2**180
```

Then derive the stream key and decrypt:

```python
key    = hashlib.sha256(str(s).encode()).digest()
stream = hashlib.shake_256(key).digest(len(ct))
flag   = xor_bytes(ct, stream)
# b'OmniCTF{crt_makes_a_tiny_nonce_without_leaking_it}'
```

Recovered secret: `67133769516566898715085291836` (exactly 96 bits). Flag body reads *"CRT makes a tiny nonce without leaking it"*: the flag literally names the vulnerability class.

Per-challenge README + solver: [crypto/dual_linera](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/crypto/dual_linera).

Two portable lessons. **A "small" quantity shared linearly across two coprime moduli is a single leak, not two.** After CRT the effective modulus is `prod q_i` and the error is still whatever it was on one side. Design your ratios against `Q`, not against each `q_i` individually. Same failure applies to hidden-number problem instances sharing a nonce across two moduli, biased-nonce ECDSA collated across two curves, small-CRT-exponent RSA where a bounded quantity leaks on both mod-p and mod-q sides. **You don't need Sage to solve LLL-sized CTF crypto.** A 20x20 pure-Python LLL is silly slow (~90 minutes on an M-series laptop) but correct; drop-in Sage or fpylll for a much faster reduction if you want to reproduce fast. But the algorithm is the same either way.

## 2. Whiskerfield-Meowtin

CuteSecure-DH over `65537^16`. The wrapper hands you `A` one byte-flip away from a multiple of 65537. Patch the byte, shared secret is 0, decrypt with the LCG stream cipher.

### Step 1 — Read the wrapper's public-key construction

`wrapper.py` (250 lines of Python, no cryptography of its own) has one function that gives the whole game away:

```python
def generate_public_key_near_multiple(length: int) -> bytes:
    while True:
        seed = bytearray(secrets.token_bytes(length))
        seed[0] |= 0x40
        target = int.from_bytes(seed, "big")
        target -= target % 65537              # target is a MULTIPLE of 65537
        if target <= 1:
            continue
        target_bytes = bytearray(target.to_bytes(length, "big"))
        for _ in range(length * 8):
            byte_index = secrets.randbelow(length)
            mask = secrets.choice((0x01, 0x02, 0x04, 0x08, 0x11, 0x55, 0x80))
            candidate = bytearray(target_bytes)
            candidate[byte_index] ^= mask
            if int.from_bytes(candidate, "big") % 65537 != 0:
                return bytes(candidate)      # !=0 by design, but 1 XOR away
```

Reading this out loud: *start with a multiple of 65537, XOR one byte with a small mask so it's no longer a multiple, return that*. The message is unsubtle. The challenge wants you to XOR that byte back, which is exactly what "one byte to patch, one shot" from the prompt buys.

Also relevant: the private exponent has its top bit forced:

```python
def generate_private_exponent_hex(length=16):
    random_bytes = bytearray(secrets.token_bytes(length))
    random_bytes[0] |= 0x80        # b >= 2^127
    random_bytes[-1] |= 0x11
    return random_bytes.hex()
```

So `b >= 2^127`. Hold on to that.

### Step 2 — Find the modulus in the stripped `.so`

```
$ nm -D libcutecrypto.so | grep -E 'SecureChannel|CuteBigInt::FromHex'
0000000000083190 T SecureChannel::SecureChannel()
0000000000083490 T SecureChannel::ModPow(...)
0000000000083b80 T SecureChannel::ProcessMitm(...)
00000000000860f0 T CuteBigInt::FromHex(std::string)
```

`.rodata` at `0x1341b0` has 64 ASCII hex chars:

```
1001000780230071c11101f482cb032462cb01f481110071c023000780010000
```

Factoring the resulting integer gives small primes and one random 108-bit prime. Not obviously a DH modulus.

The tell is a few instructions into the constructor at `0x83190`:

```
movdqa xmm0, [0x1341b0]         ; bytes 0-15
movups [rax], xmm0
mov   byte [rax + 0x40], 0x31   ; poke '1' at byte 64  <-- !!
movups [rax + 0x10], xmm0       ; bytes 16-31
movdqa xmm0, [0x1341d0]
movups [rax + 0x20], xmm0       ; bytes 32-47
movdqa xmm0, [0x1341e0]
movups [rax + 0x30], xmm0       ; bytes 48-63
```

The four `movdqa/movups` writes lay down the 64 `.rodata` bytes, then `mov byte [rax + 0x40], 0x31` writes `'1'` at byte 64. The `CuteBigInt::FromHex` input is 65 hex chars:

```
"1001000780230071c11101f482cb032462cb01f481110071c023000780010000" + "1"
= 0x1001000780230071c11101f482cb032462cb01f481110071c0230007800100001
```

Sanity check:

```python
>>> R = int("1001000780230071c11101f482cb032462cb01f481110071c023000780010000", 16)
>>> R * 16 + 1 == 65537 ** 16
True
```

The modulus is `65537^16`: Fermat prime raised to the 16th power.

### Step 3 — Why "multiple of 65537" is the whole game

The peer performs `shared = A'^b mod 65537^16`. Suppose we patch `A` so `A' = 65537 * m` for some integer `m`. Then:

```
A'^b = (65537 * m)^b = 65537^b * m^b
```

`65537^16` divides `65537^b` whenever `b >= 16`. And the wrapper guarantees `b >= 2^127 >> 16`. So:

```
65537^b ≡ 0 (mod 65537^16)  for all b >= 16
```

which forces:

```
shared = A'^b ≡ 0 (mod 65537^16)   always.
```

This is the classical "prime power is a bad DH modulus" trap. The group `(Z/p^k)^*` has an obvious filtration by powers of `p`, and any input divisible by `p` collapses to 0 after `k` levels of exponentiation.

### Step 4 — Enumerate valid one-byte patches

For byte position `i` (0-indexed from the left) and candidate value `v`:

```
int(A_new) = int(A) + (v - A[i]) * 256^(23 - i)
```

We want that `≡ 0 (mod 65537)`. Since `gcd(256, 65537) = 1`, `256^(23-i)` is invertible mod 65537, so exactly one `v` in `[0, 65537)` works per position. It's a candidate iff that `v` fits in `[0, 256)`.

Useful observation: `256^2 = 65536 ≡ -1 (mod 65537)`, so powers of 256 mod 65537 cycle through `{1, 256, -1, -256}`. For a 24-byte `A`, only positions where `256^(23-i)` is `±1` can produce a valid `v < 256`. In practice ~12 valid positions per instance; the wrapper guarantees at least one exists (it's the byte it XOR'd during setup).

```python
def find_zero_mod_patches(A: bytes):
    n = len(A)
    A_int = int.from_bytes(A, "big")
    for i in range(n):
        weight = pow(256, n - 1 - i, 65537)
        winv   = pow(weight, -1, 65537)
        target = (A[i] - A_int * winv) % 65537
        if 0 <= target <= 255:
            yield i, target
```

For `A = 5fa9e673f2e450da6c32a46e06864926883b81ed3744dd77`, the first candidate is `1:29` (change byte 1 from `0xa9` to `0x29`, XOR `0x80`, one of the wrapper's allowed masks).

### Step 5 — Reverse the KDF from `ProcessMitm`

`ProcessMitm` (`0x83b80`) is ~22 KB of unrolled bignum plumbing, but the payload construction at the tail is short.

Shared-secret hash at `0x84410`:

```c
h = 0xc0dec0de
for b in shared_bytes:
    h = ((b ^ h) * 0x19660d + 0x3c6ef35f) & 0xffffffff
```

Stream cipher over the flag at `0x84470`:

```c
state = h
for i in range(len(flag)):
    state = (state * 0x41c64e6d + i * 0x21 + 0x3039) & 0xffffffff
    out[i] = (state >> 16) ^ (i * 0xd) ^ flag[i]
```

`0x41c64e6d` is glibc's `rand()` multiplier; `0x3039 = 12345` is its increment. The homebrewed part is that the increment drifts by `0x21` per iteration and output is XOR'd with a byte counter stepping by 13. Both deterministic, both irrelevant to the attack.

### Step 6 — Serialise `shared = 0`

One empirical question: how does the bignum library encode 0 as bytes before feeding it to the hash? Three natural candidates:

- Empty byte string.
- Single `0x00` byte.
- Fixed 32-byte zero-padded encoding.

The solver enumerates all three. For this build the answer is **a single `0x00` byte**, giving:

```
seed = ((0 ^ 0xc0dec0de) * 0x19660d + 0x3c6ef35f) mod 2^32 = 0x9e4532a5
```

Keystream bytes: `83 12 59 36 c8 93 ...`. XOR with observed payload `cc 7f 37 5f 8b c7 ...`: `4f 6d 6e 69 43 54 = "OmniCT"`.

### Step 7 — Fire

```
$ python3 solve.py whiskerfield-<id>.inst.omnictf.com
[*] A = 5fa9e673f2e450da6c32a46e06864926883b81ed3744dd77
[*] A mod 65537 = 65409
[*] candidate patches: [('0x1','0x29'), ('0x3','0xcb'), ...]
[*] sending: 1:29
[shared=\x00 * 1] printable=100.0%  b'OmniCTF{I_just_LOVE_the_sm3ll_0f_f34r_1ab27f8d}'
OmniCTF{I_just_LOVE_the_sm3ll_0f_f34r_1ab27f8d}
```

Per-challenge README + solver: [crypto/whiskerfield_meowtin](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/crypto/whiskerfield_meowtin).

Three questionable choices compound in Whiskerfield, each embarrassing on its own. **DH mod `p^k` is a footgun.** The group `(Z/p^k)^*` is not the one you want DH in; its filtration by powers of `p` makes inputs divisible by `p` collapse to 0 after enough exponentiation. Use safe-prime moduli (`p = 2q + 1` with `q` prime) or work over `Z/p` with a large-order subgroup. **Trust nothing about `A`.** If the peer will trustingly compute `A^b`, at minimum check `gcd(A, p) = 1`; better, check that `A` has the right order in the target subgroup. **The construction of `A` is documentation for the attacker.** Anything shaped like *"start with X, perturb it a little, return that"* is a written invitation to reverse the perturbation. Attackers read code; helpful comments and helpful constructions help them first.

## 3. Orbital-Strike-Cannon

Three costumes stacked on one problem: non-associative octonions, a "broken RNG" with published stream, and 7 satellites (5 real, 2 fake). All three go away as soon as you write things linearly.

### Step 1 — Read the constants

```python
P               = (1 << 127) - 1     # Mersenne prime
N_STATES        = 34
N_SATELLITES    = 7
REAL_SATELLITES = 5
COORDS_PER_SAMPLE     = 3
SAMPLES_PER_SATELLITE = 5
```

State evolution:

```python
moon_{i+1}  = add(o_mul(o_mul(R_i, M_i), ALPHA), BETA)
orbit_{i+1} = (outer_a * orbit_i + sum(M_i) + rng_i) % P
```

`o_mul` is octonion multiplication over `F_P` via Cayley-Dickson. Note `((R_i * M_i) * ALPHA)`: the parenthesisation is fixed, `alpha` and `beta` are public.

Encryption:

```python
secret_material = vec_to_bytes(moon0 + [x0, rng_u, rng_v])
key             = sha256(b"OSC-KEY|" + secret_material).digest()
ciphertext      = shake_xor(key, flag)
firing_code     = sha256(key + b"|fire").hexdigest()[:32]
```

Public in `public_json`: `alpha`, `beta`, `outer_a`, `rng_beacons` (the whole LCG stream), `satellites` (7 records with `{arange, mask_offset, basis, bias, coords}`), `ciphertext`. Secret: `moon0` (8 F_P values), `x0` (scalar), `rng_u`, `rng_v`.

### Step 2 — The "broken" RNG hands you `u`, `v`

```python
class BrokenRNG:
    def next(self):
        out = self.state
        self.state = (self.u * self.state + self.v) % P
        return out
```

`rng_beacons[i+1] = u * rng_beacons[i] + v (mod P)`. Two consecutive differences:

```
u = (b_2 - b_1) * (b_1 - b_0)^{-1} mod P
v =  b_1 - u * b_0                 mod P
```

That leaves `moon0` (8) and `x0` (1). Nine unknowns.

### Step 3 — Non-associativity, meet linear algebra

`build_state_expressions` already spells the trick out:

```python
transition = mat_mul(mat_right(alpha), mat_left(r_oct))
```

- `mat_left(o)`  is the 8x8 matrix representing `x → o_mul(o, x)`.
- `mat_right(o)` is the 8x8 matrix representing `x → o_mul(x, o)`.

So:

```
o_mul(o_mul(R_i, M_i), ALPHA)
    = mat_right(ALPHA) * (R_i * M_i)
    = mat_right(ALPHA) * mat_left(R_i) * M_i
```

One 8x8 matrix. Even though the underlying algebra is non-associative, the `(A B) C ≠ A (B C)` failure lives inside the `mat_left`/`mat_right` distinction. Once you pick a side, matrices compose associatively as usual.

Extend the 8-dim moon to a 10-dim affine state `[M, X, 1]`:

- 8 rows for moon: `transition[8x8] * M + BETA * 1`.
- 1 row for orbit: `outer_a * X + <1,1,...,1> * M + rng_i * 1`.
- 1 row for the constant slot: identity.

Stacking `N_STATES + 3` step matrices gives, for each `i`, a 10x10 matrix `states[i]` such that:

```
[M_i, X_i, 1] = states[i] * [M_0, X_0, 1]
```

The 11-dim feature vector `feature[idx] = M_idx || [X_idx, X_{idx+1}, X_{idx+2}]` is then an `11 x 10` known matrix `A_idx` times the 10-dim unknown `[M_0, X_0, 1]`.

### Step 4 — Each real sample is one linear equation

For a real satellite at time index `idx = start + step * t`:

```python
mask   = rng_beacons[idx + mask_offset]        # public
y_j    = mask * <basis_row_j, feature[idx]> + bias_j
```

`basis_row_j`, `bias_j`, `mask` are all in the JSON. Rearrange:

```
<basis_row_j, feature[idx]> = (coord_j - bias_j) * mask^{-1} mod P
```

Substitute `feature[idx] = A_idx * [M_0, X_0, 1]`:

```
(basis_row_j^T * A_idx) . [M_0, X_0, 1] = (coord_j - bias_j) * mask^{-1} mod P
```

The dot with `basis_row_j` collapses the 11 rows of `A_idx` into a single 10-dim coefficient vector. The last entry multiplies the constant slot `1`; move it to the RHS. **One linear equation in 9 unknowns per coordinate.**

Per satellite: 5 sample times × 3 coords = **15 equations**. Real: all 15 fit the true `(M_0, X_0)`. Fake: coords are `rnd_vec(...)`, so 15 random RHS values; augmented rank vs coefficient rank differ almost surely (`Pr[accidental consistency] ~ 1/P^6`).

### Step 5 — Sort real from fake with per-satellite RREF

For each satellite, build augmented matrix `[coefs | rhs]`, Gauss-eliminate mod `P`. If any row is `[0, 0, ..., 0 | non-zero]`, the satellite is fake. Otherwise real.

On the live instance: `{sat-01, sat-02, sat-03, sat-04, sat-06}` real, `{sat-00, sat-05}` fake. Matches `REAL_SATELLITES = 5`.

### Step 6 — Solve, decrypt, submit

Stack the ~75 real equations, RREF, read `(M_0, X_0)` off the reduced matrix. Recover `u, v` from `rng_beacons`. Rebuild the key, print the firing code, decrypt locally.

```
$ python3 solve.py orbital-<id>.inst.omnictf.com
[*] sat-00: fake
[*] sat-01: REAL
[*] sat-02: REAL
[*] sat-03: REAL
[*] sat-04: REAL
[*] sat-05: fake
[*] sat-06: REAL
[*] moon0[0..1] = 14598914431436..., 11953631947875...
[*] x0    = 46185392415993808500431983316962390203
[*] u,v   = 12979879898..., 53901520642...
[+] firing_code = 75af1bd515c8d3ec26f7a0e6ab9fc8f4
[+] flag (local decrypt) = b'OmniCTF{Wemmbu_h4s_destroy3d_th3_law_hell_nawhh_where-is_you_eggcha~}'
```

Per-challenge README + solver: [crypto/orbital_strike_cannon](https://github.com/Abdelkad3r/OmniCTF-2026-Quals/tree/main/crypto/orbital_strike_cannon).

Three portable lessons. **If you can write it as a matrix, do.** Non-associative algebras scare cryptographers when the operation is being composed *many* times with variables in the middle. As soon as the association order is fixed and one of the operands is public, the operation becomes an 8x8 matrix mod `P` and the algebra ends. **A "broken" RNG whose state you transmit is just a KDF input.** Public RNG state is not a secret you can rekey around; it's a public parameter. If you want key material out of an LCG, keep the state private. **In mixed real/fake channels with an exact linear model, rank tests are all you need.** No priors, no ground truth, no majority vote: RREF per channel and be done.

## Cross-cutting defender notes

Five patterns recur across the OmniCTF 2026 Quals crypto track and translate directly into review or triage heuristics.

**Any small quantity shared linearly across two moduli is one leak, not two.** dual_linera's error `e` looks safe when you're computing modulo `q1` alone (`|e|/q1 ~ 2^{-4}`, hopeless for lattice), but the CRT reconstruction is a linear map over the integers, so the shared `e` survives. Same failure applies to hidden-number problem instances that share a nonce across two moduli, biased-nonce ECDSA collated across two curves, or small-CRT-exponent RSA where a bounded quantity leaks on both mod-p and mod-q sides. Design your ratios against the composite modulus, not against each factor.

**DH modulus choice matters at least as much as key length.** Whiskerfield's `65537^16` is 256 bits (bigger than a lot of production DH moduli), but the group `(Z/p^k)^*` has a filtration by powers of `p`. Inputs divisible by `p` collapse to 0 after `k` levels of exponentiation. Safe-prime moduli (`p = 2q + 1` with `q` prime) or working over `Z/p` with a large-order subgroup are the standard defences. Same class: DH over composite `n = p*q` (nobody does this, but people have done it in coursework and shipped it), DH over elliptic curves with small embedding degree, DH over `Z/2^n` (also bad).

**Validate every peer-supplied group element.** Whiskerfield's peer will trustingly compute `A^b` for any 24-byte `A` the wrapper hands out. `gcd(A, p) = 1` would have caught this specific bug at essentially zero cost. Better: verify that `A` has the correct order in the target subgroup (check `A^(order) == 1` and `A^(order/prime) != 1` for each prime dividing the order). Same class: ECDH curve validation (Bleichenbacher-style attacks on invalid curve points), Schnorr signature validation of public keys, any protocol where the peer contributes a group element and you exponentiate it.

**Non-associativity is not a security property when association order is fixed.** Orbital's octonion multiplication is genuinely non-associative, but every `((R_i * M_i) * alpha)` in the state evolution has the parenthesisation baked in. `mat_right(alpha) * mat_left(R_i)` is one 8x8 matrix; the non-associativity lives inside the `mat_left`/`mat_right` bookkeeping and does not survive matrix composition. If you want to use a non-associative algebra as a security primitive, the operation has to be applied *variably* (attacker chooses the parenthesisation) and one of the operands has to be secret. Otherwise it's just linear algebra with two flavours of "multiply by X" matrices.

**Publishing the RNG stream doesn't hide anything.** Orbital's "broken RNG" has its whole output stream printed as `rng_beacons`. Two consecutive differences give up the LCG parameters `(u, v)`. Any protocol whose security depends on a pseudorandom stream but publishes the stream itself is a plain-text protocol with theatrical framing. If the RNG state is meant to be secret, keep it secret; if it's public parameters, treat it that way in the security model.

## Frequently asked questions

### What is OmniCTF 2026 Quals?

OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition, with challenges spanning web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces (`CTF{...}`, `OMNICTF{...}`, `OmniCTF{...}`, `omniCTF{...}`) depending on the challenge author. This writeup covers the three crypto challenges I solved (dual_linera, Whiskerfield-Meowtin, Orbital-Strike-Cannon). The paired [web](/ctf-writeups/omnictf-2026-quals-web-writeup/), [pwn](/ctf-writeups/omnictf-2026-quals-pwn-writeup/), and [reverse](/ctf-writeups/omnictf-2026-quals-reverse-writeup/) writeups on the same site cover the other tracks. Per-challenge READMEs and solvers at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals).

### How does dual_linera's CRT collapse turn two-modulus LWE into one small-error equation?

The generator produces `y1 = a1*s + e mod q1` and `y2 = a2*s + e mod q2` with the same `e` on both sides. On its own, each row has ratio `|e|/q ~ 2^{-4}`: hopeless for lattice reduction. Take CRT coefficients `u ≡ 1 mod q1, u ≡ 0 mod q2` and `v ≡ 0 mod q1, v ≡ 1 mod q2` with `u+v ≡ 1 mod Q` where `Q = q1*q2`. Then `Y_i = y1_i*u + y2_i*v ≡ (a1_i*u + a2_i*v)*s + e*(u+v) ≡ A_i * s + e (mod Q)`. Same `s`, same `e` across all 18 samples. `log Q / log e ~ 2.05` per sample makes LLL on a 20-dimensional lattice tractable.

### Why does the 20x20 lattice work for dual_linera?

Weights `W_S = 2^80` and `W_K = 2^176` scale the secret column and shift row so the target short vector `(s*W_S, -e, -e, ..., -e, -W_K)` has every coordinate around `2^176`. Total L2 norm is `sqrt(20) * 2^176`, far shorter than the generic Minkowski bound for a 20-dim lattice with determinant `W_S * W_K * Q^n`. LLL reliably finds it. Read `s` off the row whose last coordinate is `±W_K`.

### Why is CuteSecure-DH's `65537^16` modulus catastrophic?

The group `(Z/p^k)^*` has structure `(Z/p^{k-1}) x (Z/(p-1))^*` and a filtration by powers of `p`. Any input divisible by `p` sits in the "kernel" of the reduction mod `p^{k-1}`, and `k` levels of exponentiation collapse it to 0. Since the private exponent `b >= 2^127 >> 16`, `A'^b ≡ 0 (mod 65537^16)` for any `A'` divisible by 65537. The wrapper hands you an `A` one byte-flip away from a multiple of 65537. Patch the byte, `A' = 65537 * m`, `shared = 0`.

### How do you find the one-byte patch for Whiskerfield?

For 24-byte `A` and byte position `i`, we want a candidate value `v` such that `int(A_new) ≡ 0 mod 65537`. `256^2 ≡ -1 mod 65537`, so powers of 256 cycle through `{1, 256, -1, -256}`. Only positions where `256^(23-i)` is `±1` can produce a valid `v` in `[0, 256)`. Compute `weight = pow(256, 23-i, 65537)`, `winv = pow(weight, -1, 65537)`, `target = (A[i] - A_int * winv) % 65537`. If `0 <= target <= 255`, position `i` with value `target` is a valid patch. ~12 candidates per instance; the wrapper guarantees at least one exists.

### How is Whiskerfield's shared secret serialised to bytes for the KDF?

The `.so`'s bignum library encodes 0 as a single `0x00` byte (rather than empty string or fixed-32-byte padding). Feeding that through the shared-secret hash yields `h = ((0 ^ 0xc0dec0de) * 0x19660d + 0x3c6ef35f) mod 2^32 = 0x9e4532a5`. That seed drives the LCG stream cipher (glibc `rand()` multiplier `0x41c64e6d`, increment `0x3039 + i*0x21`, output XOR'd with `i*0xd` per byte). Solver enumerates the three natural encodings; single `0x00` matches on this build.

### Why does Orbital-Strike-Cannon's non-associative octonion multiplication reduce to 8x8 matrix multiplication?

The state evolution fixes `((R_i * M_i) * alpha)` as the parenthesisation. Define `mat_left(o)` = 8x8 matrix representing `x -> o_mul(o, x)` and `mat_right(o)` = matrix representing `x -> o_mul(x, o)`. Then `o_mul(o_mul(R_i, M_i), alpha) = mat_right(alpha) * mat_left(R_i) * M_i`, a single 8x8 matrix in `F_P^8`. Non-associativity `(A B) C ≠ A (B C)` lives inside the `mat_left` vs `mat_right` distinction, but once each `(o, side)` maps to a matrix, matrices compose associatively as usual. Extend to a 10-dim affine state `[M, X, 1]` and stack step matrices.

### How does per-satellite RREF sort real from fake in Orbital-Strike-Cannon?

For each satellite, build the augmented matrix `[coefs | rhs]` from its 15 samples (5 time steps × 3 coords). Real satellites' `coords` are exact affine measurements of the true `[M_0, X_0, 1]`, so the augmented matrix is consistent: RREF finishes with no all-zero coefficient rows against nonzero RHS. Fake satellites' `coords` are random `rnd_vec(...)` values from `F_P^15`, so the augmented rank exceeds the coefficient rank almost surely; RREF produces at least one row `[0, 0, ..., 0 | nonzero]`, marking the satellite as fake. Probability of accidental consistency is `~1/P^6` per fake satellite, negligible for `P = 2^127 - 1`.

### How do you recover the LCG parameters `u, v` from Orbital's beacon stream?

`rng_beacons[i+1] = u * rng_beacons[i] + v (mod P)`. Two consecutive differences: `b_2 - b_1 = u * (b_1 - b_0) mod P`, so `u = (b_2 - b_1) * (b_1 - b_0)^{-1} mod P`. Then `v = b_1 - u * b_0 mod P`. Requires `b_1 - b_0` invertible mod P, which is essentially always true for `P = 2^127 - 1`. Once `u, v` are recovered, the RNG contributes no secret material; the only remaining unknowns are `moon0` (8) and `x0` (1), which the per-satellite equations solve.

### What's the broader lesson from the OmniCTF 2026 Quals crypto track?

*The exotic algebra is a costume.* Every one of these primitives has a scary name (two-modulus LWE, DH over `Z/p^k` with Fermat prime base, non-associative Cayley-Dickson octonions), but the actual attack surface reduces to 20th-century linear algebra plus one specific structural mistake. dual_linera's mistake is sharing `e` across two moduli through the linear CRT map. Whiskerfield's is using a prime-power modulus whose group has an obvious filtration plus a wrapper that hand-delivers the near-multiple. Orbital's is fixing the association order and publishing the RNG state. Name the mistake first, invert the algebra second (or don't, when a rank test suffices).

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and pure-stdlib Python solvers at [Abdelkad3r/OmniCTF-2026-Quals](https://github.com/Abdelkad3r/OmniCTF-2026-Quals). All three solvers use only the Python standard library (no `pycryptodome`, no `pwntools`). dual_linera's solver ships its own pure-Python integer LLL (slow but correct: ~90 minutes on a 20x20 lattice; use Sage or fpylll for a millisecond-scale reduction). Whiskerfield and Orbital solvers finish in seconds. All three reproducible against fresh remote instances.

## Closing notes

Three crypto challenges pulled together by one discipline: **write everything linearly first, and if you can't, ask why not**. dual_linera's `y1, y2` become one linear equation after CRT. Whiskerfield's DH exponentiation becomes divisibility once you notice `65537^16` is a prime power. Orbital's octonion state becomes 8x8 matrix multiplication once the association order is fixed. Every one of these is a structural mistake dressed as exotic algebra, and every one has a real-world analogue in production systems that have shipped essentially the same bug.

For the same event's other tracks, the [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/), [OmniCTF 2026 Quals pwn writeup](/ctf-writeups/omnictf-2026-quals-pwn-writeup/), and [OmniCTF 2026 Quals reverse writeup](/ctf-writeups/omnictf-2026-quals-reverse-writeup/) each cover their own set. Adjacent crypto writeups on the site: the [Junior.Crypt 2026 web + crypto writeup](/ctf-writeups/junior-crypt-2026-web-crypto-writeup/) walks Franklin-Reiter e=3, Vaudenay CBC via timing trace, LCG seed truncation, and many-time pad via multiset match. The [R3CTF 2026 master writeup](/ctf-writeups/r3ctf-2026-writeup/) covers Microsoft SEAL CKKS delta recovery via 95 approximate modular equations plus a baseline-noise filter. The [BroncoCTF 2026 web + crypto writeup](/ctf-writeups/broncoctf-2026-web-crypto-writeup/) covers a Blorg Multiplier MD5 collision dispatcher and a Probably Unbreakable OTP whose 64-character keystring turns each ciphertext byte into a per-position membership test. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is OmniCTF 2026 Quals?","acceptedAnswer": {"@type": "Answer","text": "OmniCTF 2026 Quals is the qualifier round of the OmniCTF 2026 competition, with challenges spanning web, pwn, reverse, crypto, game, misc, and forensics. Flags use event-specific namespaces (CTF{...}, OMNICTF{...}, OmniCTF{...}, omniCTF{...}). This writeup covers the three crypto challenges I solved (dual_linera, Whiskerfield-Meowtin, Orbital-Strike-Cannon). Paired web/pwn/reverse writeups on the same site. Per-challenge READMEs and solvers at github.com/Abdelkad3r/OmniCTF-2026-Quals."}},
    {"@type": "Question","name": "How does dual_linera's CRT collapse turn two-modulus LWE into one small-error equation?","acceptedAnswer": {"@type": "Answer","text": "Generator produces y1 = a1*s + e mod q1 and y2 = a2*s + e mod q2 with the same e on both sides. Take CRT coefficients u ≡ 1 mod q1, ≡ 0 mod q2 and v ≡ 0 mod q1, ≡ 1 mod q2. Then Y_i = y1_i*u + y2_i*v ≡ (a1_i*u + a2_i*v)*s + e*(u+v) ≡ A_i * s + e mod Q where Q = q1*q2. Same s, same e across all 18 samples. log Q / log e ~ 2.05 per sample makes LLL on a 20-dim lattice tractable."}},
    {"@type": "Question","name": "Why does the 20x20 lattice work for dual_linera?","acceptedAnswer": {"@type": "Answer","text": "Weights W_S = 2^80 and W_K = 2^176 scale the secret column and shift row so the target short vector (s*W_S, -e, ..., -e, -W_K) has every coordinate around 2^176. Total L2 norm sqrt(20)*2^176, far shorter than the generic Minkowski bound for a 20-dim lattice with determinant W_S * W_K * Q^n. LLL reliably finds it. Read s off the row whose last coordinate is ±W_K."}},
    {"@type": "Question","name": "Why is CuteSecure-DH's 65537^16 modulus catastrophic?","acceptedAnswer": {"@type": "Answer","text": "The group (Z/p^k)* has a filtration by powers of p. Any input divisible by p collapses to 0 after k levels of exponentiation. Since private b >= 2^127 >> 16, A'^b ≡ 0 mod 65537^16 for any A' divisible by 65537. The wrapper hands you A one byte-flip away from a multiple of 65537. Patch the byte, A' = 65537*m, shared = 0."}},
    {"@type": "Question","name": "How do you find the one-byte patch for Whiskerfield?","acceptedAnswer": {"@type": "Answer","text": "256^2 ≡ -1 mod 65537, so powers of 256 cycle through {1, 256, -1, -256}. Only positions where 256^(23-i) is ±1 can produce a valid v in [0, 256). Compute weight = pow(256, 23-i, 65537), winv = pow(weight, -1, 65537), target = (A[i] - A_int * winv) % 65537. If 0 <= target <= 255, position i with value target is a valid patch. ~12 candidates per instance."}},
    {"@type": "Question","name": "How is Whiskerfield's shared secret serialised to bytes for the KDF?","acceptedAnswer": {"@type": "Answer","text": "The .so's bignum library encodes 0 as a single 0x00 byte (rather than empty string or fixed-32-byte padding). Feeding that through the shared-secret hash yields h = ((0 ^ 0xc0dec0de) * 0x19660d + 0x3c6ef35f) mod 2^32 = 0x9e4532a5. That seed drives the LCG stream cipher (glibc rand() multiplier 0x41c64e6d, increment 0x3039 + i*0x21, output XOR'd with i*0xd per byte)."}},
    {"@type": "Question","name": "Why does Orbital-Strike-Cannon's non-associative octonion multiplication reduce to 8x8 matrix multiplication?","acceptedAnswer": {"@type": "Answer","text": "State evolution fixes ((R_i * M_i) * alpha) as parenthesisation. mat_left(o) is the 8x8 matrix for x -> o_mul(o, x); mat_right(o) is for x -> o_mul(x, o). Then o_mul(o_mul(R_i, M_i), alpha) = mat_right(alpha) * mat_left(R_i) * M_i, a single 8x8 matrix. Non-associativity lives inside the mat_left/mat_right distinction; matrices compose associatively as usual once each (o, side) maps to a matrix."}},
    {"@type": "Question","name": "How does per-satellite RREF sort real from fake in Orbital-Strike-Cannon?","acceptedAnswer": {"@type": "Answer","text": "For each satellite, build augmented [coefs | rhs] from its 15 samples. Real satellites' coords are exact affine measurements: RREF finishes with no all-zero coefficient rows against nonzero RHS. Fake satellites' coords are random F_P^15: RREF produces at least one row [0, 0, ..., 0 | nonzero], marking as fake. Probability of accidental consistency is ~1/P^6 per fake satellite for P = 2^127 - 1."}},
    {"@type": "Question","name": "How do you recover the LCG parameters u, v from Orbital's beacon stream?","acceptedAnswer": {"@type": "Answer","text": "rng_beacons[i+1] = u * rng_beacons[i] + v mod P. Two consecutive differences: b_2 - b_1 = u * (b_1 - b_0) mod P, so u = (b_2 - b_1) * (b_1 - b_0)^{-1} mod P. Then v = b_1 - u * b_0 mod P. Once u, v recovered, RNG contributes no secret material; only unknowns are moon0 (8) and x0 (1)."}},
    {"@type": "Question","name": "What's the broader lesson from the OmniCTF 2026 Quals crypto track?","acceptedAnswer": {"@type": "Answer","text": "The exotic algebra is a costume. Every primitive has a scary name (two-modulus LWE, DH over Z/p^k, non-associative Cayley-Dickson octonions), but the actual attack surface reduces to 20th-century linear algebra plus one structural mistake. dual_linera's mistake is sharing e across two moduli through the linear CRT map. Whiskerfield's is prime-power modulus + wrapper hand-delivers the near-multiple. Orbital's is fixing the association order and publishing the RNG state."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and pure-stdlib Python solvers at github.com/Abdelkad3r/OmniCTF-2026-Quals. dual_linera's solver ships its own pure-Python integer LLL (slow but correct: ~90 minutes on 20x20 lattice; use Sage or fpylll for millisecond reduction). Whiskerfield and Orbital solvers finish in seconds. All three reproducible against fresh remote instances."}}
  ]
}
</script>
