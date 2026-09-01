---
title: "ASIS CTF Quals 2026 Crypto Writeup: Hackel, Headache, Linchan, Mario, Less is More, Pancake Stack & Sultan"
slug: "asis-ctf-quals-2026-crypto-writeup"
description: "Complete ASIS CTF Quals 2026 Crypto writeup covering all seven challenges. Hackel dresses a plaintext bit encoding in the language of combinatorial group theory: the ciphertext words are printed as strings so bit equals 1 iff the word contains the letter b, and the equivalent-key verifier never touches the secret conjugator so a diagonal embedding of a 10-cycle plus 11-cycle passes every gate including AGL(1,11) at order 110. Headache is a Non-Linear Hamiltonian Authenticator that unwinds to a three-head softmax attention PRF with 60 secret parameters regenerated per round; a noise-free float64 oracle turns key recovery into Levenberg-Marquardt curve fitting with an exact analytic Jacobian, and pipelined queries plus parallel restarts fit all seven rounds inside the 120s connection window. Linchan hides five secret matrices as conjugate pairs of GF(2) subspaces among 102 decoys, but plants two rank-25 matrices in every real subspace where a uniform 32-by-32 matrix hits rank 25 with probability 2^-47, so a Gray-code MinRank scan of all 16.9M subspace elements identifies real boxes in 14 seconds, powers-fingerprint pairs them, and X-H = G-X becomes a linear system over GF(2) with 1-dimensional solution space equal to S. Mario is a UOV instance at n=96 m=72 d=24 over GF(16) whose 64 published reports all share the same masking vector g drawn once outside the loop, so every report lies in W = O oplus span(g); a quadratic form vanishing on a hyperplane factors as l times L and its polar form drops to rank 2 with 23-dimensional kernel inside O, so two polar kernels intersect to the full oil space. Less is More is a code-equivalence signature over GF(827) with an iteration-skip bug that overwrites f[target] with the previous round's indicator 72 percent of the time, letting a leaf be simultaneously revealed by the cover and challenged by the response so its column-permutation constraint leaks; voting over 830 hits across 5963 records pins all seven permutations and a linear solve recovers the diagonals from the public keys. Pancake Stack is AES-GCM keystream reuse: a 32-bit seed drives the AES-256 master key and the challenge publishes SHA256 of the seed as a hint, and a truncated-collision KDF searches for alt with the same upper 96 bits so the flag and a known-all-zero sample share one keystream — flag equals sample ciphertext XOR flag ciphertext. Sultan is module-LWE with a hint leak that publishes both v = u + c-s and floor of inner product A,u over 65000; substituting u = v - c-s turns every hint into a 7-bit linear constraint on s, and Bai-Galbraith primal embedding plus BKZ-30 recovers s in 5 seconds so SHAKE256 SULTAN/key of s decrypts the flag."
date: 2026-09-01T20:00:00Z
lastmod: 2026-09-01T20:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["ASIS CTF Quals 2026"]
tags:
  - "asis ctf"
  - "asis ctf quals 2026"
  - "asis ctf 2026"
  - "ctf writeup"
  - "cryptography"
  - "crypto challenge"
  - "hackel"
  - "headache"
  - "linchan"
  - "mario"
  - "less is more"
  - "pancake stack"
  - "sultan"
  - "combinatorial group theory"
  - "group presentation attack"
  - "equivalent key recovery"
  - "softmax attention prf"
  - "levenberg marquardt fit"
  - "analytic jacobian"
  - "minrank attack"
  - "matrix subspace"
  - "gf 2 linear algebra"
  - "uov cryptanalysis"
  - "unbalanced oil vinegar"
  - "polar form rank 2"
  - "hyperplane factorization"
  - "code equivalence signature"
  - "iteration skip bug"
  - "cut and choose zero knowledge"
  - "aes gcm keystream reuse"
  - "truncated aes collision"
  - "seed brute force"
  - "module lwe"
  - "bai galbraith embedding"
  - "bkz lattice reduction"
  - "small secret lwe"
  - "aead tag verification"
  - "ctf 2026"
keywords:
  - "asis ctf quals 2026 writeup"
  - "asis ctf 2026 crypto writeup"
  - "asis ctf hackel writeup"
  - "asis ctf headache writeup"
  - "asis ctf linchan writeup"
  - "asis ctf mario writeup"
  - "asis ctf less is more writeup"
  - "asis ctf pancake stack writeup"
  - "asis ctf sultan writeup"
  - "hackel group presentation ctf"
  - "headache softmax attention prf ctf"
  - "linchan minrank matrix subspace ctf"
  - "mario uov oil hyperplane leak ctf"
  - "less is more iteration skip cut and choose"
  - "pancake stack aes gcm keystream reuse"
  - "sultan module lwe hint leak bkz"
  - "asis ctf 2026 solutions"
  - "ctf crypto step by step 2026"
toc: true
cover:
  image: "/images/articles/asis-ctf-quals-2026-crypto-writeup.png"
  alt: "ASIS CTF Quals 2026 Crypto writeup cover — all seven crypto challenges solved. Hackel dresses a plaintext bit encoding in combinatorial group theory so bit equals 1 iff the word contains letter b and the equivalent-key verifier never touches the secret conjugator. Headache unwinds a Non-Linear Hamiltonian Authenticator into a three-head softmax attention PRF whose 60 parameters per round fall to Levenberg-Marquardt with an analytic Jacobian in a pipelined connection. Linchan plants rank-25 matrices in every real GF(2) matrix subspace so a Gray-code MinRank scan finds real boxes in 14 seconds and X-H = G-X becomes a 1-dimensional GF(2) linear system. Mario ships 64 UOV reports all masked by the same g vector so they span W = O oplus span g in 25 dimensions and quadratic forms restricted to W factor as l times L with polar-form rank 2 kernel inside the oil space. Less is More has a 72-percent iteration-skip bug that lets a leaf be simultaneously revealed and challenged so voting over 830 hits recovers all seven code-equivalence permutations. Pancake Stack chains a 32-bit seed brute-force against a published hint with a truncated-collision KDF that forces the flag and an all-zero sample to share one AES-GCM keystream so flag equals sample ciphertext XOR flag ciphertext. Sultan publishes both v = u + c-s and floor of inner product A,u over 65000 which converts every committee hint into a 7-bit linear constraint on a tiny secret s and Bai-Galbraith primal embedding with BKZ-30 recovers s in 5 seconds."
---

**ASIS CTF Quals 2026**'s Cryptography track is a seven-challenge tour through the modern crypto attack surface: a group-theoretic warm-up (`Hackel`), a softmax-attention PRF disguised as a Hamiltonian (`Headache`), matrix-subspace obfuscation (`Linchan`), a UOV multivariate signature (`Mario`), a code-equivalence zero-knowledge scheme (`Less is More`), AES-GCM keystream reuse via truncated collisions (`Pancake Stack`), and module-LWE with hint leakage (`Sultan`). Every challenge in the set is solvable in under a few hundred lines of Python and, in almost every case, without touching the advertised hard problem — the schemes look like their inspiration but ship with a load-bearing structural leak that reduces recovery to enumeration, curve fitting, voting, or lattice reduction against a target sized comfortably below any real-world parameterisation.

The unifying thread across the track is a single discipline: **before attacking the maths, list what actually reaches the wire**. `Hackel` never evaluates its permutation words into permutations. `Headache`'s oracle is noise-free `float64`, so a functional twin replaces the secret. `Linchan` re-bases every matrix subspace, but every subspace element (including planted rank-25 markers) is invariant under that change of basis. `Mario` publishes 64 reports masked by the same `g` — the linear span of the reports is a public 25-dimensional space that contains the entire secret oil space as a hyperplane. `Less is More` strips a `_hit` marker before shipping but every hit is reconstructible from public data (`serial`, `cmt`, `salt`, the cover tree). `Pancake Stack` publishes `SHA256("K1-SEED-HINT" || seed)` alongside a 32-bit seed. `Sultan` publishes `floor(inner(A,u)/65000)` alongside `v = u + c·s`. In every case the exploitable substrate is one indirection below the surface the scheme presents, and the scheme's own outputs name it.

Handouts, per-challenge READMEs, solver scripts, and formatted writeups live at [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026). This **CyberSecurity Elite** ASIS CTF Quals 2026 Crypto writeup covers all seven challenges end to end, with an emphasis on the *substrate* each one operates on and the disciplined tooling — coset membership tests, analytic Jacobians, Gray-code MinRank, Bai-Galbraith embeddings, GCM tag-as-proof — that turns the theory into a solve. See also the companion posts for the [Misc](/ctf-writeups/asis-ctf-quals-2026-misc-writeup/) track.

## All seven Cryptography challenges at a glance

| Challenge | Difficulty | Sub-genre | Substrate the exploit reads | Flag |
|---|---|---|---|---|
| [Hackel](#hackel--the-ciphertext-is-plaintext-and-the-verifier-never-sees-the-secret) | Baby | Group presentation | Ciphertext words printed as strings + verifier reads only the public presentation | `ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK!!}` |
| [Headache](#headache--softmax-attention-prf-recovered-by-analytic-least-squares) | Medium | Softmax-attention PRF | Noise-free `float64` oracle over a 60-parameter functional form | `ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}` |
| [Mario](#mario--the-uov-reports-share-one-masking-direction) | Medium | UOV multivariate signature | 64 reports all masked by a single `g` — spans `W = O oplus span(g)` | `ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}` |
| [Pancake Stack](#pancake-stack--gcm-keystream-reuse-via-a-truncated-permutation-collision) | Medium | AES-GCM keystream reuse | 32-bit seed hint + truncated `AES_k1(y || 0)` collision | `ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}` |
| [Sultan](#sultan--module-lwe-with-a-quotient-hint) | Medium-Hard | Module-LWE with hint leak | `hint = floor(inner(A,u)/65000)` alongside `v = u + c·s` | `ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}` |
| [Linchan](#linchan--rank-25-plants-turn-minrank-into-a-14-second-scan) | Hard | GF(2) matrix subspaces | Rank-25 planted markers survive re-basing, conjugation, and transposition | `ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}` |
| [Less is More](#less-is-more--an-iteration-skip-collapses-a-cut-and-choose) | Hard | Code-equivalence signature | `f[target] = self.state[target]` — a leaf revealed *and* challenged | `ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}` |

Seven categories, one repeated pattern: read the substrate the system operates on, not the one it advertises.

---

## Hackel — the ciphertext is plaintext, and the verifier never sees the secret

> *Flag:* `ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK!!}`
>
> *Prompt:* "Our lead cryptographer hackel proudly announced a revolutionary post-quantum vault guarded by intricate algebraic group presentations. With a search space boasting over 1.6 quadrillion states, they confidently declared: No supercomputer on Earth could brute-force our permutations before the heat death of the universe."

The handout is a single Python file, `hackel.py`. The service exposes five menu actions over TCP; `[4]` (`Submit Recovered Equivalent Key`) and `[5]` (`Interactive Speed Challenge`) both print the flag on success. The advertised keyspace of `(11!)^2 = 1,593,350,922,240,000` is the two independent conjugator choices used to build the uppercase and lowercase alphabets.

### The scheme

Permutations act on `n = 11` points and compose left-to-right (`compose(a, b)[i] = b[a[i]]`, i.e. "apply `a` then `b`"). Each alphabet is generated from a random conjugator:

```python
a_l = conj(cyc_perm(n, [tuple(range(10))]), l_rand)             # a 10-cycle
b_l = conj(cyc_perm(n, [tuple(rng.sample(range(n), n))]), l_rand)  # an 11-cycle
c_l = compose(a_l, b_l)
d_l = compose(invert(a_l), compose(b_l, c_l))                   # d = a^-1 b c
e_l = compose(c_l, d_l)                                         # e = cd
```

`c`, `d`, `e` are derived — only `a` (order 10) and `b` (order 11) are independent. The uppercase alphabet mirrors the construction with its own conjugator. Flag bits are encoded as **words over the lowercase alphabet**:

```python
flag_words = [(t0,) * rng.randint(1, 9) if bit == "0"
              else (t0,) * rng.randint(0, 9) + (t1,)
              for bit in flag_bits]
```

with `t0 = 'a'`, `t1 = 'b'`. Bit `0` is `a^k` (`k >= 1`); bit `1` is `a^k b`.

### Break 1 — the ciphertext is never encrypted

Menu option `[2]` prints the words **as strings**, not as evaluated permutations:

```
[+] Encrypted Flag Words (496):
    aaa, ab, aaaaa, aaa, aaaaaaaa, a, aaa, aaaaaab, ...
```

The two branches differ by a single visible character, so **bit = 1 iff the word contains `b`**. 496 words = 496 bits = 62 bytes = the flag length:

```python
bits = "".join("1" if "b" in w else "0" for w in words)
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode()
```

Even if the server had evaluated the words into permutations, the bit is still determined by the **coset of `<a>`**: `a^k` lies in `<a>` (bit 0), and `a^k * b` does not, because `|b| = 11` does not divide `|<a>| = 10`. Coset membership is basis-independent and needs no key.

### Break 2 — the verifier never touches the secret

Menu option `[4]` (`submit_key`) is the intended path. Critically, it validates the submission only against the *public* presentation — every check is on the submitted permutations, none is on the server's secret. Substituting `C = AB`, `D = A^-1 B A B`, `E = CD` collapses eight of the ten upper relations to tautologies, leaving just:

```
< A, B | A^10 = 1, B^11 = 1 >
```

The mixed relations `Aa = aA`, `Ab = ab a^9 A`, `Bb = bB`, `Ba = ba b^10 B` are satisfied by setting `lower := upper` (`a = A`, `b = B`, …) — the RHS of `Ab` becomes `A B A^9 A = A B A^10 = A B`, using `A^10 = 1`. `is_symmetric_gen` is not the check its name suggests; it verifies only that the generators act transitively on the 11 points and at least one is odd (a 10-cycle has sign `(-1)^9 = -1`).

The obvious diagonal choice satisfies every gate:

```python
A = tuple((i + 1) % 10 if i < 10 else 10 for i in range(11))  # 10-cycle fixing 10
B = tuple((i + 1) % 11 for i in range(11))                    # 11-cycle
```

Even the Frobenius group `AGL(1, 11)` at order 110 passes every gate — 362,880 times smaller than `S_11` — which is the sharpest statement of how little the verifier constrains. `submit_key` then prints the flag.

### Break 3 — the speed challenge

Menu option `[5]` generates 16 fresh words with the same encoding and demands classification within 5 seconds. The same `"b" in word` test answers it instantly.

### Flag

```
ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK!!}
```

The name says it: **semidirect group presentation key recovery attack**.

### Takeaway

**Encoding is not encryption.** The words were never evaluated into the permutation group; the group was decoration around a plaintext channel. And **a verifier that never touches the secret is not verifying the key** — `submit_key` accepts any representation that satisfies the published equations, so key recovery collapsed to "solve the published equations," which took eight relations away with algebra and two more with a 10-plus-11 cycle pair.

---

## Headache — softmax-attention PRF recovered by analytic least-squares

> *Flag:* `ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}`
>
> *Prompt:* "Headache is a haunted math blender. Crack its secret matrices, forge tags, get flag."

The Non-Linear Hamiltonian Authenticator is dressed in physics vocabulary — `coupling_tensors`, `partition_fn`, `boltzmann_weights`, `gauge_shift` — but the core einsum unwinds to a three-head softmax-attention layer.

### The scheme

Each of 7 rounds regenerates secret matrices `A[c]` (4-by-4) and `B[c]` (length-4) for `c in 0..2`, entries drawn `U(0.5, 2.0)`. For a sequence `X` of shape `(L, 4)` with `x_tail = X[-1]`, the tag is:

```
T(X) = sum_c softmax_i( X[i] . (A[c] . x_tail) ) . ( X[i] . B[c] )
```

Per-round budget is 1200 `eval` queries (each incurring a 0.03s server-side delay), then a `challenge` command emits 6 random sequences of lengths `[3, 5, 7, 9, 13, 17]` and demands their tags to `1e-6` tolerance. Total connection window is roughly 120 seconds.

### The recovery

The oracle is **exact**: `float64`, noise-free, deterministic. A candidate `(A', B')` that reproduces the tag on `~150` generic sequences reproduces `T` everywhere. So the goal shifts from *find the secret* to *find any functional twin*, which sidesteps the internal channel permutations that would otherwise confuse a fit.

Two structural observations make the fit trivial to condition:

1. **`B` is linear given `A`.** Softmax weights `w_c = softmax(X . (A[c] . x_tail))` depend only on `A`, and `T = sum_c (w_c . X) . B[c]`. The Jacobian block for `B[c]` is just `w_c . X`.
2. **Analytic Jacobian.** With `o_c = X . B[c]` and `val_c = w_c . o_c`:

    ```
    d T / d B[c] = w_c . X
    d T / d A[c] = outer( X^T . (w_c * (o_c - val_c)), x_tail )
    ```

    The softmax derivative `d w_m / d e_n = w_m (delta_{mn} - w_n)` collapses cleanly.

Levenberg-Marquardt over all 60 parameters (`3 * 16 + 3 * 4`) with the analytic Jacobian, vectorised across queries (sequences padded to a common length with a `-inf` energy mask), lands at `rmse ~ 1e-15` on the true basin and `> 1e-3` on any other. Restart from the known `U(0.5, 2)` prior until `rmse < 1e-7`.

### Making it fit inside the connection

Two engineering fixes turn a plausible offline attack into a live solve:

- **Pipeline the eval queries.** Synchronous round-trips at ~0.18 s each burn ~30 s/round. Writing all `eval` lines, flushing, then reading all responses collapses the query phase to roughly the server-side delay (`150 * 0.03 = 4.5 s`) plus one RTT.
- **Parallel LM restarts.** Some rounds land in the wrong basin repeatedly. Running restarts in parallel across CPU cores (`multiprocessing`), stopping at the first `rmse < 1e-7`, bounds the worst-case fit at ~10 s.

Total wall time across 7 rounds: about 70 seconds, comfortably inside the connection budget. Each round's `max_err` on the challenge sequences is `~1e-15`, nine orders of magnitude below the `1e-6` tolerance.

### Flag

```
ASIS{c0uPleD_n0nL1n3Ar_Dynam!c5_R3c0vEry_v1A_p0l3s_&_l34st_squ4r3s!!}
```

### Takeaway

**Vocabulary is not security.** "Hamiltonian coupling tensors" and "partition function" are attention scores and a softmax normaliser. **A deterministic noise-free oracle is a gift** — it turns key recovery into curve fitting and reduces the goal from "find the secret" to "find any functional twin". And **interactive constraints are part of the crypto**: the real difficulty here is budget management (pipelining + parallel restarts) to fit seven independent 60-parameter systems inside one time-limited connection.

---

## Mario — the UOV reports share one masking direction

> *Flag:* `ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}`
>
> *Prompt:* "Something is wrong beneath the Mushroom Kingdom Mario. Find the flag!"

The public key is a textbook Unbalanced Oil and Vinegar instance: 72 quadratic forms in 96 variables over `GF(16)`, all vanishing on a secret 24-dimensional *oil* subspace `O`. The flag key is derived from `O`, so recovering that subspace is the whole challenge.

### The scheme

Parameters `n = 96, m = 72, d = 24, s = 64`, with `v = n - d = 72` vinegar variables. `oil_embed` maps `x ∈ GF(16)^24` to `(K.x, x) ∈ GF(16)^96` for a secret 72-by-24 matrix `K`. The image is `O = { (K.x, x) : x ∈ GF(16)^24 }`.

`build_public_map` fills each quadratic form's non-oil-oil block with random coefficients, then patches the oil-oil block so the form vanishes on `O`. In characteristic 2, using the polar form `B(a, b) = P(a+b) - P(a) - P(b)`, `poly[v+i][v+i] = P(basis[i])` cancels `P` on each basis vector and a similar patch on `poly[v+i][v+j]` cancels each `P(basis[i] + basis[j])`, forcing `B(basis_i, basis_j) = 0`.

`monomial_scramble` picks a permutation + per-coordinate nonzero scalars and applies the matching change of variables. This is a **linear change of coordinates and nothing more** — the whole attack runs in public coordinates without undoing it.

The flag key is `HKDF(row_reduce(oil_basis), 32, salt, SHA256, context="MARIO")`, so any basis of `T(O)` yields the same key.

### The leak

```python
while True:
    g = r(n)
    if any(eval_quad(poly, g) for poly in polys):
        break                                          # <-- one g, chosen once

reports = []
for _ in range(s):
    oil_vec = oil_embed(k_mat, r(d))
    mask    = secrets.randbelow(15) + 1
    reports.append(vec_add(oil_vec, vec_scale(g, mask)))
```

Each report is `r_i = o_i + lambda_i . g` with `o_i ∈ O`, `lambda_i != 0` — and **the same `g` is reused across all 64 reports**. So every report lies in

```
W = O oplus span(g),     dim W = 24 + 1 = 25
```

(`g not-in O` because it makes some form nonzero, and every form vanishes on `O`.) 25 independent reports span `W`; the generator hands over 64.

### Inside `W`, the forms factor

`O` is a hyperplane of `W`, so `O = ker(l)` for some linear form `l` on `W`. In coordinates where `l` is the last coordinate `c_25`, every quadratic form vanishing on `O` has no term without `c_25`:

```
Q(c) = c_25 . ( sum_{i<25} q_{i,25} c_i + q_{25,25} c_25 ) = l(c) . L(c)
```

**Every one of the 72 forms, restricted to `W`, factors as a product of two linear forms sharing the factor `l`.**

The polar form of `Q = l . L` is:

```
B(u, v) = l(u) L(v) + l(v) L(u)
```

whose matrix is `l . L^T + L . l^T` — symmetric with zero diagonal (alternating), and of **rank exactly 2** whenever `L` is not a multiple of `l`. Its kernel is:

```
ker(B) = ker(l) intersect ker(L) subset ker(l) = O          dim 23
```

Each restricted polar form hands over a 23-dimensional slice of the 24-dimensional secret. Two different forms give two different 23-dim subspaces of a 24-dim space, and their intersection spans the entire oil space:

```
[+] poly 0: polar rank 2, kernel dim 23, oil span now 23
[+] poly 1: polar rank 2, kernel dim 23, oil span now 24
```

Computationally this is one matrix triple product per form (`W . S . W^T` at 25-by-25).

### Verification and decryption

Lift the 24 recovered coordinate vectors through the basis of `W`, evaluate every public form on every basis vector — 1728 evaluations, all zero. `row_reduce` the recovered basis, flatten to 2304 bytes, run the generator's HKDF, and decrypt AES-256-GCM. The **GCM tag validating** is the cryptographic proof that the recovered subspace is exactly the generator's.

### Flag

```
ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}
```

### Takeaway

**Count dimensions before doing algebra.** 64 vectors in a 96-dimensional space span only 25 — a public 25-dim envelope that contains the entire 24-dim secret as a hyperplane. **A quadratic form vanishing on a hyperplane factors** as `l . L`, its polar form drops to rank 2, and its kernel is a near-complete slice of the secret. And **auxiliary data is part of the attack surface**: the public key was sound; the extra reports leaked. `g` drawn once outside the loop instead of once per report is the one-line bug that collapses the whole scheme.

---

## Pancake Stack — GCM keystream reuse via a truncated permutation collision

> *Flag:* `ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}`
>
> *Prompt:* "Chef Crypto served a batch of extra-fluffy key derivation layers, claiming they are mathematically unbreakable. But rumors say something went wrong during the baking process."

The "fluffy KDF" boils down to AES-GCM keystream reuse, opened with two composable bugs.

### The construction

`challenge.json` publishes `d = 32` (drop bits), `a` (a hint), `n = [n1, n2]`, `h` (associated data), `m` (128 zero bytes of known plaintext), `y` (the flag AEAD blob), and `z` (a sealed ticket). The derivation:

```python
def seed_to_k1(seed):   return sha256(b"K1-SEED"      + seed.to_bytes(4, "big")).digest()
def seed_to_hint(seed): return sha256(b"K1-SEED-HINT" + seed.to_bytes(4, "big")).hexdigest()

def diffuse_state(k, n1, n2):
    e  = AES.new(k, AES.MODE_ECB)
    j  = extract_upper(e.encrypt(format_block(n2, 0)))     # top 96 bits of AES_k(n2 || 0)
    w1 = n1 ^ j
    w2 = n1 ^ gf_double(j)
    r1 = extract_upper(e.encrypt(format_block(w1, 0x18)))
    r2 = extract_upper(e.encrypt(format_block(w2, 0x28)))
    return j, w1, w2, r1, r2
```

`derive_keys(k2, n1, state)` then SHAKE-256s the state to `(ek, iv, ck)`.

### Bug 1 — the 32-bit seed hint

`k1` is a full AES-256 key generated from only a 32-bit `seed`, and `hint = SHA256("K1-SEED-HINT" || be32(seed))` is a direct oracle for it. Iterate `seed ∈ [0, 2^32)`, hash, compare. A threaded C brute-forcer finds `seed = 0x22c4d3ef` in seconds, giving `k1`.

### Bug 2 — the truncated collision forces one keystream

`find_collision(k1, n2)` searches for `alt != n2` with the same top-96 bits of `AES_k1(alt || 0)`:

```python
base_int = target << 32
for sep in range(1 << 32):
    x = AES_k1.decrypt((base_int | sep))
    if (x & DROP_MASK) == 0:
        y = x >> 32
        if y != n2: return y
```

Once `alt` is found, generation produces:

```python
sample = encrypt_authenticated(k1, k2, n1, alt, ad, KNOWN_PLAINTEXT)   # (n1, alt), zeros
y      = encrypt_authenticated(k1, k2, n1, n2,  ad, flag)               # (n1, n2), flag
z      = seal_sample(k1, n1, alt, {"n": [n1, alt], "x": sample})
```

Trace `diffuse_state` for both:

| Quantity | flag `(n1, n2)` | sample `(n1, alt)` |
|---|---|---|
| `j` | `upper96(AES_k1(n2 || 0))` | `upper96(AES_k1(alt || 0))` **= same** (by construction) |
| `w1 = n1 ^ j` | same | same |
| `w2 = n1 ^ gf_double(j)` | same | same |
| `r1, r2` | same (depend on `w1, w2`) | same |

The **entire diffused state is identical**, `n1` is identical, so `derive_keys(k2, n1, state)` returns the **same `(ek, iv, ck)`** for both — regardless of the secret `k2`. AES-GCM is CTR mode, so identical `(key, nonce)` implies identical keystream. The sample's plaintext is zeros, so `sample.ciphertext = keystream`, and:

```
flag = y.ciphertext XOR sample.ciphertext[:len(flag)]
```

### Recovering the sample ciphertext

The sample ciphertext lives only inside the sealed ticket `z`, encrypted under:

```python
key   = sha256(b"SEALED-TICKET-KEY" + k1 + n1 + alt).digest()[:16]
nonce = sha256(b"SEALED-TICKET-IV"  + key).digest()[:12]
```

Recompute `alt` with the same `2^32` scan (extended to enumerate every collision), try each, and let the GCM tag select the right one. The ticket then decrypts to yield the reused keystream.

### Flag

```
ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}
```

### Takeaway

**A 256-bit key seeded from 32 bits has 32 bits of security** — and publishing *any* deterministic function of the seed (the "hint") gives it up outright. **Truncating a PRP creates collisions by design**: dropping 32 bits turns AES into a 96-to-96 map with frequent collisions; here one collision forces two distinct nonces to derive the same `(ek, iv)`. **Nonce/keystream reuse is fatal for GCM (and any CTR-mode)** — one of the two colliding messages was known all-zero, so its ciphertext is the raw keystream, and XOR reveals the other.

---

## Sultan — module-LWE with a quotient hint

> *Flag:* `ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}`
>
> *Prompt:* "An encrypted archive from the sultan's laboratory has resurfaced. It is said to contain a message meant for the court alone."

The service mints a per-session `secret_string` and lets the client download `encrypt_sultan(secret_string)` as `secret.enc` up to 500 times, then verify a guess at `/api/verify`. The whole task is recovering the session's secret from one `secret.enc`.

### The cipher

Parameters `q = 8380417, n = 64, ell = 1, m = 70, t = 16, b = 65000, secret_bound = 3`. The secret is a single polynomial `s ∈ R_q = Z_q[X] / (X^64 + 1)` with coefficients in `[-3, 3]`:

```python
s     = [_g(-secret_bound, secret_bound) for _ in range(ell)]
w     = _secret_bytes(s)
k     = shake_256(b"SULTAN/key" + w).digest(32)
nonce = token_bytes(24)
p     = shake_256(b"SULTAN/stream" + k + nonce).digest(len(secret_data))
e     = bytes(u ^ v for u, v in zip(secret_data, p))
d     = blake2s(b"SULTAN/tag" + nonce + e, key=k).digest()
```

**The key is a pure function of `s`.** Recovering `s` gives `k`, hence the keystream, hence `secret_string = e XOR p`. The BLAKE2s tag lets us confirm a candidate `s` offline.

### The leak

For each of 70 sessions the record publishes:

```python
x = token_bytes(32)
y = bytes(sorted(random.sample(range(63), 32)))
seed = x + y
u = [_g(0, q-1) for _ in range(ell)]
c = _b(seed)                                 # sparse +-1 challenge, 16 nonzeros
v = [_a(up, _p(c, sp)) for up, sp in zip(u, s)]
R.append(x + y + struct.pack("<I", _i(_r(seed), u) // b) + _z(v))
```

Each record therefore ships `c = _b(seed)`, `A = _r(seed)` (both derivable from public `seed`), the full `v = u + c . s`, and `hint = floor(inner(A, u) / b)`. `v` alone is uniform (masked by `u`); the hint is the whole game.

Since `u = v - c . s`:

```
inner(A, u) ≡ inner(A, v) - inner(A, c . s)   (mod q)
```

Both `inner(A, v)` and the map `s -> inner(A, c . s)` are public. Writing `M_j . s = inner(A_j, c_j . s)` and `a_j = inner(A_j, v_j)`, the hint reads:

```
M_j . s + r_j ≡ a_j - hint_j . b   (mod q),     r_j ∈ [0, b)
```

Setting `T_j = (a_j - hint_j . b) mod q`, that is a **textbook LWE sample** with tiny secret `s ∈ [-3, 3]^64` and error `r_j < 65000 << q`.

### Making the linear form explicit

`inner(A, c . s)` is linear in the 64 coefficients of `s`. Column `k` is `M_{j,k} = inner(A_j, c_j . e_k)` where in `R_q`:

```
(c . e_k)[i] =  c[i-k]        if i >= k
             = -c[i-k+n]      otherwise    (negacyclic wrap, X^n = -1)
```

### The lattice

70 samples constrain 64 unknowns; each hint carries `log2(q/b) ≈ 7` bits, so about 490 bits pin a secret with only about 180 bits of entropy — wildly over-determined; `s` is unique. Bai-Galbraith primal (Kannan) embedding in dimension `n + m + 1 = 135`, with secret coordinates scaled by `Ws ≈ b / 6` and the error centered at `b/2`:

```
rows i<n :   [ Ws . e_i | M[:, i]      | 0 ]
rows n+j :   [    0     | q . e_j      | 0 ]
last row :   [    0     | (T_j - b/2)  | 1 ]
```

The unique short vector encodes `(-s, r - b/2, 1)`. Target norm ~ `2.4e5` vs Gaussian heuristic ~ `9e5` — a uSVP gap of ~3.7 in dimension 135. Plain LLL is not enough (reaches ~ `4e6`, ~14x GH), so run **progressive BKZ**; BKZ-30 recovers `s` in about 2 seconds.

### Flag

```
ASIS{cORrup7_qu0ruM_rEu5e_!n_l4sT_ASIS_CTF!!}
```

### Takeaway

**Don't leak high bits of a mask that also carries the secret.** Publishing `floor(inner(A, u) / b)` alongside `v = u + c . s` converts every "committee hint" into a linear equation on `s` with `b`-bounded error. **Toy parameters are toy security**: `n = 64, ell = 1`, secret width 3 — far below any real Dilithium-style level and collapses under BKZ-30 in seconds. And **a key that is a pure function of a recoverable value is only as strong as that value** — `k = SHAKE(s)` means one lattice solve unlocks the entire authenticated cipher.

---

## Linchan — rank-25 plants turn MinRank into a 14-second scan

> *Flag:* `ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}`

`linchan.py` uses single-letter names throughout and encodes each 32-by-32 matrix over GF(2) as 32 row-integers. `_h()` returns a `32 x 25` times `25 x 32` product — a matrix of **rank exactly 25**. `_o(B)` re-expresses a basis through a random invertible change of basis and transposes each element with probability 1/2.

### The scheme

```python
_l = ((16, 2), (17, 2), (18, 1))     # (dimension, number of real pairs)
_d = 34                              # decoys per dimension

for m, c in _l:
    for _ in range(c):
        C, S = _b(m, True), _g()
        T = _i(S)
        D = [_m(_m(S, A), T) for A in C]     # D = S . C . S^-1
        B += [(m, _o(C)), (m, _o(D))]
        K.append(S)
    for _ in range(_d):
        B.append((m, _o(_b(m))))             # decoy
shuffle(B)
```

The output is **112 boxes**, each an m-dim subspace of `M_32(GF(2))`, presented in a random basis and possibly transposed. Ten boxes form five conjugate pairs `span(D) = S . span(C) . S^-1`. The flag is encrypted under `ChaCha20Poly1305` keyed on SHAKE of the sorted canonical forms of the five `S`.

### The plant

`_b(m, True)` seeds real subspaces with two elements drawn from `_h()` (rank exactly 25), while decoys are uniform. The rank distribution of a uniform 32-by-32 matrix over GF(2) is:

| rank | probability |
|---|---|
| 32 | 0.2888 |
| 31 | 0.5776 |
| 30 | 0.1284 |
| 25 | 6.06 x 10^-15 |

`P(rank <= 25) ≈ 6.1 x 10^-15 ≈ 2^-47.2`. A dimension-18 decoy subspace contains `2^18` elements; its expected number of rank-<= 25 matrices is `1.6 x 10^-9`, and across all 102 decoys about `10^-7`. Two facts make this fatal rather than merely interesting:

- **Rank is a property of the subspace, not the basis.** `_o()` re-expresses the basis through a random change of basis, leaving the set of subspace elements unchanged.
- **Rank is invariant under conjugation and transposition.** `rank(S . H . S^-1) = rank(H)` and `rank(H^T) = rank(H)`, so the marker survives into the partner box and survives the transposition coin flip.

### MinRank by exhaustion

Every element of every subspace can simply be enumerated: `38 * (2^16 - 1) + 38 * (2^17 - 1) + 36 * (2^18 - 1) = 16,908,176` matrices. A C solver walks each subspace in Gray-code order (one XOR of 32 words per step) and ranks each element with a 32-step elimination. Threshold 26 keeps false positives negligible while catching everything planted.

```
[+] 112 boxes, 16,908,176 subspace elements to scan
[+] MinRank: 20 matrices of rank <= 26 in 10 boxes
[+] real boxes by dimension: {16: [49, 60, 82, 86], 17: [1, 47, 92, 106], 18: [32, 44]}
```

14 seconds. 20 hits, all rank exactly 25, exactly two per box, in exactly 10 boxes, splitting 4/4/2 across the three dimensions — precisely the shape of `_l`.

### Pairing

Conjugate matrices are similar, so any similarity invariant works, provided it also survives transposition. The rank sequence of the powers does both:

```python
fingerprint(H) = tuple(rank(H ** k) for k in range(1, 13))
```

12 32-by-32 multiplications per matrix, and the correct pairing is immediate.

### Linearising `S`

The plants are canonically identifiable inside their subspace (only elements of rank 25), which removes the unknown change of basis entirely. If box A contains `H_1, H_2` and box B contains `G_1, G_2`, then up to swapping the two, `G_i = S . H_i . S^-1`. The unknown is now only `S`:

```
X . H_1 = G_1 . X
X . H_2 = G_2 . X
```

2 x 1024 = **2048 equations in 1024 unknowns** over GF(2) — one Gaussian elimination. The solution space is `S . Centralizer(H_1, H_2)`. Two random rank-25 matrices generate the whole matrix algebra `M_32(GF(2))` with overwhelming probability, whose centralizer is `{0, I}`, so the space is one-dimensional and its single nonzero element is `S`.

### The transposition ambiguity is free

`_o()` transposes each box independently. There are four combinations, but only two matter: one of the two boxes needs to be flipped (or neither). The `_f` canonical form quotients over `{S, S^-1, S^T, S^-T}`, so landing on `S^-T` instead of `S` produces the same key.

### Decryption

SHAKE the sorted canonical forms of the five `S`, take 32 bytes, run ChaCha20-Poly1305 with the leading 12 bytes of the ciphertext as nonce. The Poly1305 tag validating is the cryptographic proof that all five recovered matrices are correct.

### Flag

```
ASIS{Mr.__L1nChaN_h3aViEr__GFq2__ma7ch!nG_9aUntl3t!!?}
```

### Takeaway

**Ask what survives the obfuscation.** `_o()` looks like it hides the subspace, but a change of basis preserves every element of it. **A distinguisher and a key-recovery are often the same observation** — the low-rank plants identified the real boxes, paired them, and pinned the basis correspondence. **MinRank is only hard when the space is big**; at `m <= 18` the entire subspace fits in a Gray-code loop and the security argument evaporates.

---

## Less is More — an iteration skip collapses a cut-and-choose

> *Flag:* `ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}`
>
> *Prompt:* "We captured traffic from a prototype signing device. The implementation is small, but some records in the capture do not match a normal run. Note the less is more."

### The scheme

Parameters `P = 827, N = 548, K = 274, T = 345, W = 75`, with `REAL = 7` real keys hidden among `SLOTS = 17` public slots (10 decoys).

`base()` builds a `K x N` Cauchy matrix `g[i][j] = 1 / ((i - (K + j)) mod P)` and reduces it to RREF. A secret key is `(p, d)` where `p` permutes the `N` columns and `d` is a vector of nonzero scalars. Its public key is:

```
public(g, (p, d)) = RREF([[ g[i][p[j]] . inv(d[j]) for j in range(N) ] for i in range(K)])
```

The flag is sealed under `SHAKE-256("o" + pack_key(real 7 keys))`, where `pack_key` serialises each real key as its permutation followed by its diagonal **normalised by `d[0]`**. Recovering all seven `(p, d)` pairs is the whole game (each `d` only needed up to a global scalar).

### One signature

`box.one(msg, serial)` is MPC-in-the-head cut-and-choose over a Merkle tree of `T = 345` leaves. A per-message `root` seeds the tree; `cmt` commits to all leaves; `b = chal(cmt, salt, msg)` is a length-`T` challenge with 75 nonzero entries, each a class label in `1..7`. The reveal indicator `f = [int(b[i] != 0)]` decides whether each leaf is hidden or revealed by `cover()`. For every challenged leaf `i`:

```python
v = take(leaf[i], 'n', N, K)               # secret K-subset of columns
rsp += [ label(cmt, leaf[i]), bits({ p_x^-1[j] : j in v }) ]
```

So the response reveals the **set** `S = { i : p_x[i] in v }` — but `v` is derived from the hidden leaf seed, so honestly it is zero-knowledge.

### The bug

```python
target = (37 * serial + 11) % T
if int.from_bytes(sha256(b'v' + root)[:2], 'big') % 100 < 72:
    f[target] = self.state[target]         # <-- previous round's indicator
self.state = f
hit = [i for i in range(T) if b[i] and not f[i]]
```

72 % of the time the signer overwrites `f[target]` with the **previous** signature's value at that position. When the previous value was `0` while this round's challenge has `b[target] != 0`, we get a **hit**: a leaf genuinely challenged (has a response) but marked `f = 0` (its seed is revealed by the cover). Revealed and challenged were supposed to be disjoint.

### Detecting hits from the capture

`_hit` is stripped before saving, but every hit is reconstructible:

1. `serial = int(msg[1:])`, so `target = (37 * serial + 11) mod T`.
2. Recompute `b = chal(cmt, salt, msg)` (only public inputs). Skip records where `b[target] = 0`.
3. Recover `leaf[target]`. The cover path stores `[token(cmt, u), seed]` with `token(cmt, u) = u XOR (sha256('m' + cmt)[:2] & 1023)`; invert to get the node `u`, then descend to `leaf[target]` if `u` covers `target`.
4. Confirm by matching `label(cmt, leaf[target])` against the record's responses.

Across the 5963 records this finds **830 hits, every one label-matched**, **105–128 per class**.

### Recovering the permutations

For a hit of class `x` we now know both `v = take(leaf[target], 'n', N, K)` and the response set `S`. Since `|v| = |S| = K = N / 2` with `p_x` a bijection, the response says exactly `p_x[i] ∈ v iff i ∈ S`. Each hit restricts every position `i` to one side (`v` or its complement) of a random balanced split.

**Vote**: for each `(x, i)` tally how often each column is on the allowed side. The true `p_x[i]` is allowed in every honest hit (~110 votes); any other column is allowed about half the time (~55); the rare 14 % fault records are outvoted. `argmax` gives `p_x[i]`, and every recovered `p_x` is a valid permutation (minimum vote margin 21).

### Recovering the diagonals

With `p_x` fixed, `M = RREF(g[:, p_x] . diag(1 / d))`. Column scaling does not change which columns are pivots, so:

- **Match** each `p_x` to its public key by comparing the pivot set of `RREF(g[:, p_x])` against the pivot set of each `M`.
- **Solve** `d`. Let `piv` be the pivots and `Ginv = (g[:, p][:, piv])^-1`. Then `(Ginv . g[:, p]) . diag(1 / d)` has the same row space as `M`, giving `d[j] / d[piv[t]] = W[t, j] / M[t, j]` with `W = Ginv . g[:, p]`. Fixing the global scale and propagating recovers every `d[j]`.

The `/ d[0]` normalisation in `pack_key` removes the global scalar, so the recovered diagonals reproduce the sealed key bytes regardless of scale.

### Flag

```
ASIS{iZ_1tEr4t10n_5k1p_m4ke5_n0_1nn0c3nT_r3sPonse!!!?}
```

The name says it: **an iteration skip makes no innocent response.**

### Takeaway

**A cut-and-choose is only zero-knowledge if the two cases stay disjoint.** The whole scheme rests on "challenged implies hidden" and "revealed implies unchallenged". The iteration skip lets a single leaf be both revealed **and** challenged, and one coincidence collapses the ZK property into a plaintext leak. **Reused state across signatures is the vulnerability, not the maths** — the Cauchy code and monomial masking are sound; `f[target] = self.state[target]` is what leaks. **Set-membership leaks compose**: 110 balanced random halves per class pin the permutation with no cryptanalysis beyond counting.

---

## Cross-cutting notes

Seven challenges, one repeated pattern: **the substrate the exploit reads is one level below the substrate the scheme presents, and the scheme's own outputs name it**. Hackel prints ciphertext as strings. Headache's oracle is exact. Mario reuses one masking direction. Pancake Stack publishes a hint for its 32-bit seed. Sultan publishes a hint for its LWE mask. Linchan plants a rank marker canonical enough to find. Less is More reuses one bit of state across signatures. In every case the fix is one line — draw `g` inside the loop, do not print the hint, do not drop 32 bits, do not carry `self.state`, do not seed with `_h()` — and in every case the surrounding maths is decoration for a leak two lines away.

**Recurring defender lessons across the seven:**

- **A verifier that never touches the secret is not verifying the secret.** (Hackel, Sultan's `/api/verify` route accepts any string it derives to the right bytes.)
- **A noise-free oracle is a gift.** Turns key recovery into curve fitting. (Headache.)
- **Auxiliary data is part of the attack surface.** The public key can be sound while the extras leak. (Mario, Sultan, Less is More.)
- **Truncated PRPs collide by design; nonce-key reuse is fatal for CTR/GCM.** (Pancake Stack.)
- **Obfuscation that commutes with your attack is not a defence.** Change-of-basis, monomial scrambles, transposition — none of them touched a rank, a dimension, or a coset. (Linchan, Mario.)
- **Verify with the AEAD tag, not the plaintext.** GCM, Poly1305, and BLAKE2s tags give free proofs of correctness. (Mario, Linchan, Sultan.)

## Frequently asked questions

### What is ASIS CTF Quals 2026?

ASIS CTF Quals 2026 is the qualifier round for the ASIS CTF Finals, run annually by the ASIS team. The event is Jeopardy-style with the traditional five tracks and a heavy tilt toward Crypto — this year's Crypto set had seven challenges spanning Baby through Hard. Flags use the `ASIS{...}` prefix. The consolidated writeup repository lives at [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026).

### What was the theme across the Crypto track?

Every challenge in the set had a structural leak that reduced the advertised hard problem to something enumerable, fittable, or linearly solvable. The lesson repeated in seven variations: **read the substrate the scheme actually operates on, not the substrate it advertises**.

### Which challenges required lattice reduction?

Only Sultan. Its 135-dimensional Bai-Galbraith primal embedding of `(-s, r - b/2, 1)` fell to BKZ-30 in about 2 seconds; plain LLL was ~14x above the target norm. The `fpylll` implementation is what the solver ships with; SageMath or `flatter` would also work.

### Which challenges required a C solver?

Linchan (Gray-code MinRank over 16.9 M subspace elements, ~14 s in threaded C, minutes in pure Python) and Pancake Stack (two independent `2^32` scans: seed brute-force and truncated-collision search, both threaded with CommonCrypto or OpenSSL). Everything else runs in pure Python plus `numpy` or `scipy`.

### Was `Headache`'s attack really just curve fitting?

Yes. The einsum unwinds to a three-head softmax-attention layer with 60 secret parameters per round; the oracle is noise-free `float64`; a candidate that matches ~150 generic queries matches the tag everywhere. Levenberg-Marquardt with an analytic Jacobian lands at `rmse ~ 1e-15` on the true basin. The interactive difficulty (fitting 7 independent rounds inside a 120 s connection) was solved by pipelining `eval` queries and running LM restarts across CPU cores in parallel.

### What is the intended difficulty of Mario without the leak?

At `n = 96, m = 72, d = 24` over GF(16), UOV key recovery is the classic hard problem — you would attempt it through algebraic Gröbner-basis techniques (the flag text `grOe8n3r`, `8aSi5` gestures at that path) and it is not something you do by hand in a CTF. The 64 reports collapsed it to a 25-dimensional envelope containing the entire 24-dim oil space as a hyperplane, and the polar form of any restricted quadratic form dropped to rank 2 with a 23-dim kernel inside `O`. Two forms sufficed.

### What is the intended difficulty of Linchan without the plants?

Without the rank-25 seeds every subspace is uniform, the boxes become indistinguishable, and matching a conjugate pair means solving the bilinear subspace-conjugacy problem across ~700 candidate pairs per dimension. The plants were load-bearing — the author needed a canonical hook so the puzzle had a solution at all. The mistake was choosing a hook (low rank) that is visible from *outside* the pairing, so it separated real from decoy, paired the real ones, and pinned the basis correspondence all at once.

### What is the intended difficulty of Sultan without the hint?

Without `floor(inner(A, u) / 65000)`, each record is `v = u + c . s` with `u` uniform in `[0, q)^n` — pure noise. Recovering `s` would require classical module-LWE cryptanalysis at Dilithium-like parameters, which is genuinely hard even at `n = 64`. The hint carries about 7 bits per record; 70 records is 490 bits, over-determining a 180-bit secret by more than 2x, so the lattice gap is comfortable in dimension 135.

### What is the intended difficulty of Less is More without the iteration skip?

The Merkle cut-and-choose is intended to be zero-knowledge: challenged leaves are hidden, revealed leaves are unchallenged, and each response leaks only a set-membership condition against a hidden random subset. Without the iteration skip you never learn `v`, so `S = { i : p_x[i] in v }` is a partition of `[N]` against an unknown random half — no exploitable structure. The skip is what breaks disjointness by forcing 830 leaves across 5963 signatures to be simultaneously revealed and challenged.

### Which challenges had solutions that verify cryptographically?

Mario (GCM tag), Linchan (Poly1305 tag), Sultan (BLAKE2s tag), and Pancake Stack (GCM tag on the sealed ticket) all give a free proof-of-correctness at the end: if the tag validates, the recovered key/subspace/secret is exactly right, no eyeballing of ASCII required. Hackel (option `[4]` on the server), Headache (the `challenge`/`verify` round-trip), and Less is More (the sealed vault XOR) rely on the server's or the vault's response as the confirmation.

### Where can I find the source and solvers?

Full challenge source, solver scripts, self-test harnesses, and formatted writeups for all seven crypto challenges are at [Abdelkad3r/ASIS-CTF-Quals-2026/Crypto](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Crypto). Each challenge has its own `challenge/`, `solution/`, `writeup.html`, and per-challenge `README.md`.

### What broader lesson does the ASIS 2026 Crypto track teach?

**Structural leaks are the modern crypto attack surface**. In every one of the seven challenges the advertised hard problem was replaced by something two lines less careful — a reused mask, a printed intermediate, a truncated PRP, a hint, a shared state, an over-detailed distinguisher. Defensively, treat every value that reaches the wire as a potential leak, treat every noise-free oracle as an invitation to system identification, and prefer keys derived from values that cannot be individually recovered.

## Closing notes

The ASIS CTF Quals 2026 Crypto track packs a lot of modern cryptographic surface into seven challenges — combinatorial group theory, attention-style PRFs, multivariate signatures, code-equivalence signatures, AEAD-with-collision, and module-LWE with hints — and each one distills to the same discipline: **read the substrate the exploit actually operates on**. The maths in every challenge is sound in isolation; the wire format is what leaks.

Full source, solvers, and per-challenge notes are in the [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026) repository. The [Misc writeup](/ctf-writeups/asis-ctf-quals-2026-misc-writeup/) covers the (single) warm-up challenge in the Miscellaneous track; the Reverse and Web tracks are covered by their own separate posts.
