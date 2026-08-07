---
title: "L3akCTF 2026 Cryptography Writeup: BabyLCG, RSA Eclipse, Immiscible, po1337nomial-revenge, CSC265, Isaac's Kaleidoscope, A Fine Product, and 1+1=3"
slug: "l3akctf-2026-crypto-writeup"
description: "Full L3akCTF 2026 cryptography writeup covering all eight crypto challenges: recovering LCG parameters from three leaked states to predict an XOR key (BabyLCG); factoring an RSA modulus whose primes sit just below 2^607 and 2^521 (RSA Eclipse); an Oil-and-Vinegar system that becomes linear once the vinegar variables are fixed (Immiscible); reordering shuffled MT19937 outputs via untempering plus graph color refinement to clone the generator (po1337nomial-revenge); a garbled Bloom filter broken with identity-point oblivious transfer, Shamir interpolation, and a hybrid-filter reconstruction (CSC265); a Newton-fractal ECB byte-at-a-time oracle defeated by palette normalization (Isaac's Kaleidoscope); forcing a Sophie Germain / safe-prime relation to factor with Fermat and a GCD, synthesized through lattice reduction (A Fine Product); and a Groth16 proof forgery against a weakened CRS where delta = lambda * gamma (1+1=3)."
date: 2026-08-06T22:00:00Z
lastmod: 2026-08-06T22:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["L3akCTF 2026"]
tags:
  - "l3akctf"
  - "l3akctf 2026"
  - "ctf writeup"
  - "cryptography"
  - "crypto"
  - "lcg"
  - "rsa"
  - "rsa factoring"
  - "oil and vinegar"
  - "multivariate cryptography"
  - "mt19937"
  - "mersenne twister"
  - "prng prediction"
  - "graph isomorphism"
  - "color refinement"
  - "oblivious transfer"
  - "shamir secret sharing"
  - "bloom filter"
  - "ecb oracle"
  - "byte at a time"
  - "newton fractal"
  - "lattice reduction"
  - "lll"
  - "discrete log"
  - "safe prime"
  - "sophie germain prime"
  - "groth16"
  - "zk-snark"
  - "bn254"
  - "ctf 2026"
keywords:
  - "l3akctf 2026 crypto writeup"
  - "l3akctf 2026 cryptography writeup"
  - "babylcg ctf writeup"
  - "rsa eclipse ctf writeup"
  - "immiscible oil and vinegar ctf writeup"
  - "po1337nomial revenge ctf writeup"
  - "csc265 garbled bloom filter ctf writeup"
  - "isaacs kaleidoscope newton fractal oracle ctf"
  - "a fine product safe prime ctf writeup"
  - "1+1=3 groth16 forgery ctf writeup"
  - "lcg parameter recovery xor key ctf"
  - "rsa primes near power of two factoring"
  - "mt19937 shuffled output recover order color refinement"
  - "identity point oblivious transfer ctf"
  - "groth16 weak crs delta lambda gamma forgery"
  - "cryptography ctf 2026"
toc: true
cover:
  image: "/images/articles/l3akctf-2026-crypto-writeup.png"
  alt: "L3akCTF 2026 cryptography writeup covering all eight crypto challenges — BabyLCG recovers LCG multiplier and increment from three leaked states to predict the fourth state used as an XOR key, RSA Eclipse factors a modulus whose primes sit just below 2^607 and 2^521 by reading small offsets out of A times B minus N, Immiscible turns an Oil-and-Vinegar public key linear by fixing the four vinegar variables and brute forcing 79^4 assignments, po1337nomial-revenge untempers shuffled MT19937 outputs and reorders them via graph color refinement on the twist recurrence to clone the generator and predict randbytes, CSC265 breaks a garbled Bloom filter with identity-point oblivious transfer and Shamir interpolation then reconstructs a hybrid filter from public and corrected rows, Isaac's Kaleidoscope defeats a Newton-fractal ECB byte-at-a-time oracle by normalizing away the random palette, A Fine Product forces a Sophie Germain safe-prime relation via lattice-synthesized affine composition and factors with Fermat and a GCD, and 1+1=3 forges a Groth16 proof against a weakened common reference string where delta equals lambda times gamma using baby-step giant-step and a zero-randomness Krs correction"
---

L3akCTF 2026's cryptography track was a full tour of the discipline: two beginner warm-ups, a multivariate-crypto puzzle, a Mersenne-Twister reconstruction, a protocol challenge that stitched together oblivious transfer and Shamir secret sharing, an image-oracle side channel, a lattice-plus-number-theory monster, and a zero-knowledge proof forgery. Eight challenges, and every one of them rewards the same instinct — **find the structure the designer left in the "random," then let algebra do the rest.**

This **CyberSecurity Elite** L3akCTF 2026 crypto writeup walks all eight challenges end to end, prioritizing the *reasoning* — why each leak is fatal — over just dropping the final scripts. Challenge sources, per-challenge READMEs, and standalone solvers are published at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026). If you're after the binary side, see the companion [L3akCTF 2026 binary exploitation writeup](/ctf-writeups/l3akctf-2026-pwn-writeup/).

## All eight challenges at a glance

| Challenge | Difficulty | Points | Solves | Core idea |
|---|---|---:|---:|---|
| [BabyLCG](#babylcg--three-states-are-enough-to-predict-an-lcg) | Beginner | 64 | 206 | Recover LCG `a`, `c` from 3 states → predict XOR key |
| [RSA Eclipse](#rsa-eclipse--primes-hiding-just-below-a-power-of-two) | Beginner | 84 | 95 | Primes near `2^607` / `2^521`; read offsets from `A·B − N` |
| [Immiscible](#immiscible--oil-and-vinegar-that-refuses-to-mix) | Medium | 102 | 65 | Fix vinegar vars → system is linear in oil vars |
| [po1337nomial-revenge](#po1337nomial-revenge--reordering-a-shuffled-mersenne-twister) | Hard | 195 | 23 | Untemper + graph color refinement → clone MT19937 |
| [CSC265](#csc265--a-garbled-bloom-filter-meets-oblivious-transfer) | Hard | 274 | 13 | Identity-point OT + Shamir + hybrid-filter reconstruction |
| [Isaac's Kaleidoscope](#isaacs-kaleidoscope--a-newton-fractal-ecb-oracle) | Insane | 405 | 5 | Palette-normalized fractal = byte-at-a-time ECB oracle |
| [A Fine Product](#a-fine-product--manufacturing-a-safe-prime-to-factor) | Insane | 405 | 5 | Force safe-prime relation → Fermat + GCD factor |
| [1+1=3](#113--forging-a-groth16-proof-against-a-broken-crs) | Insane | 405 | 5 | Weak CRS (`δ = λ·γ`) → forge Groth16 proof for a false statement |

---

## BabyLCG — three states are enough to predict an LCG

> *Flag:* `L3AK{n3v3r_trU5t_b4s1c_LCG5_frfr}`

A textbook opener. A linear congruential generator produces a one-time XOR key, but `output.txt` leaks the modulus `m` and the first three states `s0, s1, s2`, while the key is the *fourth* state.

An LCG obeys `s_{i+1} = a·s_i + c (mod m)`. Subtracting consecutive recurrences eliminates the unknown increment:

```text
s2 - s1 = a·(s1 - s0) (mod m)
```

Since `gcd(s1 - s0, m) = 1`, the multiplier inverts out directly, then the increment falls out of the first recurrence:

```text
a = (s2 - s1)·(s1 - s0)^-1  (mod m)
c = s1 - a·s0               (mod m)
key = a·s2 + c              (mod m)
flag_int = ciphertext XOR key
```

Recovering `a`, `c`, and the predicted `key` immediately decrypts the flag. **Takeaway:** an LCG is a linear recurrence, not a cipher — a handful of consecutive outputs fully determine every future output.

---

## RSA Eclipse — primes hiding just below a power of two

> *Flag:* `L3AK{Th3_P3numbr4_H1d35_Th3_Fl4w_In_Th3_Mers3nne_V01d}`

The handout looks like ordinary 1128-bit RSA, but two tells give it away: the prime sizes are the suspiciously specific `607` and `521` bits, and printing `N` in hex shows a long run of `f`s followed by a long run of `0`s — both factors sit just below a power of two.

Write `p = 2^607 - a`, `q = 2^521 - b` for small offsets. With `A = 2^607`, `B = 2^521`, and `D = A·B - N`, expanding the product gives:

```text
D = a·B + b·A - a·b = (a + b·2^86)·B - a·b     (since A = 2^86 · B)
```

Because `a·b` is tiny relative to `B`, the offsets pop straight out of the high part:

```text
a = (D // B + 1) mod 2^86 = 2799
b = (D // B + 1) >> 86    = 1749
```

That yields `p = 2^607 - 2799`, `q = 2^521 - 1749`, `p·q == N`, and the rest is standard RSA decryption. **Takeaway:** structured primes (near powers of two, or with a known relationship) collapse factoring into simple algebra — always eyeball the modulus in hex before assuming it's random.

---

## Immiscible — Oil-and-Vinegar that refuses to mix

> *Flag:* `L3AK{Oil_4ND_v1N3g4r_WitH0ut_Mix1nG_Sp1LL5_eV3rYth1ng}`

The flavor text about two liquids that shake together but separate again *is* the hint. The public key is a multivariate quadratic system over `GF(79)` with 8 variables and 9 polynomials, and the goal is to recover the secret 8-element signature (which keys the AES-encrypted flag).

Reading `make_poly()` reveals the structural weakness: there are quadratic terms among the first four variables, and cross terms between the first four and the last four, but **never** a product of two of the last four variables. That is the classic Oil-and-Vinegar shape — the last four are "oil" variables that never multiply each other.

The consequence: **fix the four vinegar variables to concrete values, and every equation becomes linear in the four oil variables.** So instead of solving an intractable 8-variable quadratic system, you:

1. Iterate all `79^4 = 38,950,081` vinegar assignments.
2. For each, build a 9×4 linear system over `GF(79)`: `A_k(v)·o = target_k - known_k(v)`.
3. Gaussian-eliminate; if consistent, you have the full signature.

`79^4` is heavy for pure Python but trivial in a small generated C loop. The recovered signature `[23, 7, 73, 60, 34, 54, 53, 7]` hashes to the AES key and decrypts the flag. **Takeaway:** in multivariate crypto, the *absence* of certain cross-terms is the whole ballgame — it linearizes the system after guessing the vinegar block.

---

## po1337nomial-revenge — reordering a shuffled Mersenne Twister

> *Flag:* `L3AK{19937_bottles_of_beer_on_the_wall}`

The "revenge" of a Crew CTF 2025 challenge. The server generates 1,337 consecutive 32-bit MT19937 outputs, `shuffle()`s them (with the *same* generator), leaks the shuffled list, and later asks you to predict a future `randbytes(1337)`. The predecessor's polynomial-evaluation leak is now `REDACTED`, so you only get the shuffled coefficients — order destroyed, values intact.

### Untemper, then rebuild the order from structure

MT19937's tempering is a sequence of XOR/shift operations and therefore invertible. Untempering the 1,337 leaked values gives the *set* of raw state words `{x[0], …, x[1336]}` — but cloning needs 624 *consecutive, ordered* words. Recovering the order is the real puzzle.

The twist recurrence `x[i+624] = x[i+397] XOR twist(x[i], x[i+1])` uses only the top bit of the left word and the low 31 bits of the right word. Rewriting with `t = i+1` gives, for each `0 ≤ t ≤ 713`, a relation:

```text
x[t+623] XOR x[t+396] = twist(x[t-1], x[t])   →   x[t] -> {x[t+396], x[t+623]}
```

Searching the leaked set for each relation (only `right = left XOR target` needs testing, ~`2N²` lookups) yields **714 unordered relations**. These form a directed hypergraph. Build two graphs — a *template* over known positions `0..1336`, and an *observed* graph over shuffled indices — and run **iterative color refinement** on both. The unusual offsets 396 and 623 (difference 227) inject enough asymmetry that all 1,337 nodes get a unique color after 287 rounds, and matching equal colors recovers the chronological order.

### Clone, re-shuffle, predict

The first 624 ordered words are a full MT state block; `setstate` with index 624 clones the generator, and the remaining 713 outputs verify it. The subtle final step: replay the *high-level* `shuffle()` on a copy (rather than counting PRNG calls) so the clone consumes exactly the server's rejection-sampled randomness — then `clone.randbytes(1337).hex()` is the answer. Accidental XOR collisions are filtered by consistency checks (unique values, exactly 714 relations, matching color-class distributions), and a fresh connection is tried if anything is off. **Takeaway:** shuffling MT19937 output removes chronology, not structure; the fixed recurrence turns the leak into a graph-isomorphism problem with no seed brute force required.

---

## CSC265 — a garbled Bloom filter meets oblivious transfer

> *Flag:* `L3AK{why_d1d_th15_B3come_4_ppC_ch4ll3nge???}`

The most protocol-heavy challenge, and the one whose flag ("why did this become a ppc challenge???") is earned. The server encodes a 32-character secret in a **garbled Bloom filter** (GBF) of `M = 384` rows with `k = 8` indices per element. It publishes one AES-encrypted version of the filter and runs **384 elliptic-curve oblivious transfers**, each offering either a Shamir share of a temporary AES key, or an AES-encrypted row of a second, *corrected* (cleartext-queryable) filter.

### The identity-point OT trick

Each OT sends a random P-256 point `c`; the receiver submits `pk0 + pk1 = c` and can only unmask the branch it "chose." Submitting the **point at infinity** `O = (0:1:0)` for the unwanted branch makes `r_b·O = O`, so that branch's mask is a *known constant* `H("(0 : 1 : 0)")`. This is legitimate OT usage — no curve arithmetic needed, since one submitted key is always `c` and the other is the identity — but it lets the solver deterministically pick each branch.

### The real weakness: two filters that barely differ

The Shamir polynomial has degree 95, so exactly 96 shares reconstruct the temporary key. Choose **96 branch-zero shares** (the threshold) and **288 branch-one rows**. Interpolating at zero recovers the key and decrypts all 288 corrected rows.

The crucial observation: the public filter `gbf` and the corrected filter `D` differ at **only 32 rows** — one reserved insertion slot per secret character. So for the 96 rows you *didn't* get, substituting their public values is wrong only when a row happens to be a reserved insertion slot: expected `32 · 96/384 = 8` errors. In the winning run only 5 corrected insertion rows landed in the unavailable set.

Once the server reveals its nonce, each of `32 × 36 = 1152` candidate characters can be tested against `XOR(rows[j] for j in indices(candidate)) = hash_element(candidate)` — a 128-bit check. Most positions become fixed **anchors** immediately; the rest fall out of replaying the GBF insertion order, reconstructing the one unknown insertion row per branch when needed, and verifying against the final SHA-256 hint. Because the 96 unavailable rows are chosen before the nonce reveal, the solver simply retries fresh sessions when a run draws too many missing insertion rows. **Takeaway:** the OT wasn't broken — the fatal interaction was a low threshold, a sparse-difference corrected filter, and publication of the encrypted original, which together turn recovery into a sparse-error problem.

---

## Isaac's Kaleidoscope — a Newton-fractal ECB oracle

> *Flag:* `L3AK{N3wT0N_fR4cT@Ls_Ar3_m4STerP1eC3s_0F_Ma7H_&_ArT}`

A black-box web service: submit a message, receive a gallery of colorful **Newton fractals**. No source. The insight is that the service appends the flag to your input, splits the result into independent 16-byte blocks, and renders each block as a fractal — an ECB structure in disguise.

### Prove the ECB shape, then normalize the palette

An empty message returns four blocks; 16 `A`s returns five, and the *second* image of the `A` request matches the *first* image of the empty request. That confirms two things: your input is prepended to the flag, and each 16-byte block is transformed independently — a byte-at-a-time ECB oracle where the "ciphertext" is a PNG.

The obstacle is that colors are randomized per render, so PNGs can't be hashed directly. But the *basin geometry* is deterministic. The fractal has eight attraction basins (degree-8 polynomial) with hues ~45° apart. The solver estimates the palette phase using the eighth circular harmonic:

```text
z = Σ saturation · exp(i · 8 · hue)   →   phase = arg(z)/8  (mod 45°)
```

Multiplying every hue by eight collapses colors separated by 45° onto one direction. Each saturated pixel is assigned to its nearest palette slot `round((hue - phase)/45) mod 8`, basins are relabeled by first-appearance order to kill the remaining permutation, and the canonical label array is SHA-256'd. Independently recolored renders of the same block now collapse to an identical fingerprint.

### Batch the oracle

With PNGs parsed using only the standard library (`zlib` + manual filter reversal), the classic byte-at-a-time attack proceeds — but the service accepts up to 200 chosen bytes, so 11–12 candidate blocks are packed *before* the alignment padding to test a whole batch per request. Starting from `L3AK{`, every character (including `@`, `&`, and `}`) is confirmed by an exact canonical-image match. **Takeaway:** a randomized presentation layer over deterministic structure is still an oracle — normalize away the randomness and a "fractal art generator" becomes a standard ECB byte-at-a-time break.

---

## A Fine Product — manufacturing a safe prime to factor

> *Flag:* `L3AK{9nineNINE99_nInE9999NineNINe}`

An "insane" that fuses number theory with lattice reduction. The service offers 99 random affine functions over `Z / 9^99 Z`, lets you compose them, then generates primes `start` and `end = start·A + B (mod N)` and — *only if `end` is prime* — publishes `P = secret · start · end`. The goal is `secret`.

### The number-theory core

Target the composed map `F(s) = 2s + 1`. Then `end = 2·start + 1`, so whenever the reduction doesn't wrap and `end` is prime, `start` is a **Sophie Germain prime** and `end` its **safe prime**, with `q - 1 = 2p`. Since `p | P`, we have `q-1 | 2P`, and Fermat gives `g^{2P} ≡ 1 (mod q)` for small `g`. Therefore:

```text
q = gcd(pow(2, 2P, P) - 1, P)
p = (q - 1) // 2
secret = P // (p · q)
```

One GCD isolates the safe prime; the two unrelated random factors almost never satisfy the same exponent relation.

### The hard part: building `F(s) = 2s + 1`

You must construct that exact affine map from 99 random functions using only nonnegative repetition counts. Because `N = 3^198` and `2` is a primitive root mod `N`, each multiplier is `a_i = 2^{ℓ_i}`, and composing needs `Σ c_i·ℓ_i ≡ 1 (mod 2·3^197)`. The solver:

1. Recovers all 99 discrete logs one ternary digit at a time (the group order is smooth).
2. Feeds a scaled lattice to `fplll` to get short homogeneous relations `Σ c_i·ℓ_i ≡ 0`, then Babai nearest-plane to push a trivial inhomogeneous solution into a small nonnegative vector — giving `F_0(s) = 2s + B_0`.
3. Builds 99 pure translations (multiplier 1) and solves a second modular subset-sum for `Σ d_j·t_j ≡ 1 - B_0 (mod N)` to correct the constant term to exactly `+1`.

The synthesized word held **4,081,392 indices** across 409 composition rounds (respecting the 999-operation / 9,999-index-per-request budget), leaving 590 product attempts; the secret was recovered on attempt 256. **Takeaway:** when a service will only hand you a product under a primality condition, you can *engineer* an exploitable relationship (safe prime) into the output, then let Fermat + GCD finish — the lattice work is just the machinery to hit an exact affine target with nonnegative moves.

---

## 1+1=3 — forging a Groth16 proof against a broken CRS

> *Flag:* `L3AK{1_Plus_1_EquAls_3_gaMMa4637_Linear663_delTA6926_113377}`

"Hacking ZK is just finding Delta, Lambda, Gamma." The service asks for a Groth16 proof over BN254 that `X + Y = Z`, but every instance sets `Z = X + Y + 1` — an impossible statement. The attack isn't against the constraint; it's against a deliberately weakened common reference string.

### Find the trapdoor

Deserializing and diffing the proving key against the verifying key (`inspect.go`) shows everything matches **except the G2 `delta` point**:

```text
shared alpha=true beta1=true beta2=true delta1=true delta2=false
```

The verifier uses a replacement `delta`, and the title hints its relation to `gamma` is small. Baby-step giant-step over a `2^40` interval (`dlog.go`) recovers `delta = λ·gamma` with `λ = 46376636926` — a trapdoor that would be infeasible to find in a correctly generated setup.

### Forge

Because the public-input basis has a term `K[3]` for `Z`, bumping `Z` by one shifts the verifier's public combination by exactly `K[3]·gamma`. The forgery:

1. Reproduce the server's `X`, `Y`, and prove the *valid* statement `Z_valid = X + Y`, but replace `crypto/rand` with a **zero reader** so the prover randomizers `r = s = 0`. For this all-public one-constraint circuit, the Groth16 `C` point (`Krs`) becomes the identity, so the proof no longer depends on the mismatched proving-key delta.
2. Cancel the extra `+1` by correcting `C`:

   ```text
   C' = C - λ^{-1}·K[3]      (inverse mod the BN254 scalar field)
   ```

   In the pairing equation `-C'·delta = -C·delta + K[3]·gamma`, and that `+K[3]·gamma` exactly cancels the unwanted contribution from the server's extra one. The forged 164-byte proof then verifies for the false statement `X + Y + 1 = Z`.

**Takeaway:** Groth16's soundness rests entirely on the CRS trapdoors being unknown. A single small `delta`/`gamma` relation lets an attacker re-target the `C` point and prove anything — the constraint system was never the weak link.

---

## Cross-cutting lessons from the L3akCTF 2026 crypto set

Eight very different challenges, one recurring discipline: **hunt for the structure hidden inside something advertised as random or secure.**

- **Leaked outputs of a linear/reversible generator are the generator.** BabyLCG (3 LCG states → all future outputs) and po1337nomial-revenge (untempered MT19937 → cloned generator) are the same lesson at different scales. Never use `random` for secrets, and never reuse a public PRNG for secret generation.
- **Eyeball the modulus / key material before assuming randomness.** RSA Eclipse falls the moment you notice the hex pattern; structured primes turn factoring into arithmetic.
- **Absence of terms linearizes systems.** Immiscible's missing oil×oil products and A Fine Product's engineered safe-prime relation both reduce a "hard" problem to linear algebra or a single GCD.
- **A randomized or exotic presentation layer is still an oracle.** Isaac's Kaleidoscope (fractal PNGs) and CSC265 (encrypted GBF rows) both reduce to classic building blocks — ECB byte-at-a-time and sparse-error reconstruction — once you normalize away the noise.
- **Zero-knowledge and MPC soundness live in their setup, not their math.** 1+1=3's weak-CRS trapdoor and CSC265's low OT threshold show that protocol parameters are as much an attack surface as the primitives themselves.

## Reproduce it yourself

Every challenge above ships a standalone solver at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026) under `crypto/<challenge>/`. Most use only the Python standard library (BabyLCG, RSA Eclipse, po1337nomial-revenge, Isaac's Kaleidoscope, plus CSC265 with the `openssl` CLI); Immiscible generates a small C search program; A Fine Product needs the `fplll` executable; and 1+1=3 is Go with gnark (runnable in the official Go container). Each per-challenge `README.md` carries the exact parameters, SHA-256 hashes, and reproduction commands.

Pair this with the companion [L3akCTF 2026 binary exploitation writeup](/ctf-writeups/l3akctf-2026-pwn-writeup/), and browse our full [CTF writeups](/ctf-writeups/) archive for more crypto, pwn, and reversing deep-dives.

---

*This writeup is part of the CyberSecurity Elite [L3akCTF 2026](/series/l3akctf-2026/) series. Challenge files and complete solver scripts for all eight cryptography challenges are published at [github.com/Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026).*
