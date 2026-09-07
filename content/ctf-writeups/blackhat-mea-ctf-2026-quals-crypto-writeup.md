---
title: "Black Hat MEA CTF Qualification 2026 — Crypto Writeup (Hokan & Popcnt Oracle)"
date: 2026-09-05T10:00:00Z
lastmod: 2026-09-07T00:00:00Z
description: "Full step-by-step crypto writeup for Black Hat MEA CTF Qualification 2026. Covers Hokan (sparse multivariate interpolation over unknown F_p, weighted-degree substitution, LLL knapsack) and Popcnt Oracle (RSA-2048 Hamming-weight oracle, modular-doubling bit extraction, adaptive collision resolution)."
summary: "Two advanced crypto challenges from BlackHat MEA CTF Quals 2026: Hokan asks you to interpolate a 5-term 11-variable polynomial over a secret 256-bit prime using only 8 evaluations — two fewer than Ben-Or/Tiwari and without knowing p; Popcnt Oracle leaks only the Hamming weight of RSA decryptions, and you must recover a full 2048-bit plaintext from that single bit of information per query."
tags:
  - ctf
  - crypto
  - cryptography
  - lattice
  - rsa
  - interpolation
  - lll
  - blackhat-mea
  - 2026
keywords:
  - "black hat mea ctf 2026 crypto"
  - "blackhat mea ctf qualification 2026 writeup"
  - "hokan ctf writeup"
  - "popcnt oracle ctf writeup"
  - "sparse polynomial interpolation ctf"
  - "lll lattice ctf"
  - "rsa hamming weight oracle"
  - "multivariate polynomial interpolation unknown prime"
  - "ben-or tiwari sparse interpolation"
  - "ctf crypto 2026"
categories:
  - CTF Writeups
author: "CyberSecurity Elite"
cover:
  image: "/images/articles/blackhat-mea-ctf-2026-quals-crypto-writeup.png"
  alt: "Black Hat MEA CTF Qualification 2026 Crypto writeup cover — Hokan sparse polynomial interpolation and Popcnt Oracle RSA Hamming-weight attack"
  relative: false
showToc: true
TocOpen: false
draft: false
---

## Overview

Black Hat MEA CTF Qualification 2026 fielded two Crypto challenges. Both sit at the intersection of number theory and algorithmic cleverness — neither is a standard textbook attack, and both require building non-trivial machinery from scratch. No third-party libraries are needed: LLL, Babai's nearest-plane, Miller-Rabin, and Sage's exact polynomial string format are all implemented in the solve directories.

| Challenge | Difficulty | Core idea | Flag |
|---|---|---|---|
| **Hokan** | ★★★★★ | Sparse multivariate interpolation over unknown F_p, weighted-degree substitution + LLL knapsack | `BHFlagY{b76085b3a7563a438da13397e0a8da14}` |
| **Popcnt Oracle** | ★★★★☆ | RSA-2048 Hamming-weight oracle, modular-doubling binary extraction, adaptive collision resolution | `BHFlagY{f2bfc77b60aa990dc06ef4e1830c578e}` |

---

## Hokan

### Challenge

```python
import os
flag = os.environ.get("DYN_FLAG", "BHFlagY{dummy}")
R = PolynomialRing(Zmod(random_prime(2^256)), 11, "x")
f = R.random_element(degree=11)

for _ in range(8):
    v = list(map(int, input("> ").split(",")))
    print(f(*v))
if str(f) == input("> "):
    print(flag)
```

*Hokan* (補間) is Japanese for **interpolation** — the title is the hint.

Eleven variables. Degree ≤ 11. A secret 256-bit prime modulus. **Eight** evaluations. At the end, reproduce `str(f)` character for character and get the flag.

### Why Eight Queries is the Whole Puzzle

Sage's `MPolynomialRing_base.random_element` defaults to `terms=5`, so `f` is a **5-term** polynomial whose monomials are drawn uniformly from `binomial(22,11) = 705,432` monomials of degree ≤ 11 in 11 variables.

Ben-Or/Tiwari sparse interpolation needs `2t = 10` evaluations for a 5-sparse polynomial. We have 8. And we don't know `p`, which every step of the arithmetic requires.

Two obstacles, one budget. Counting the information content:

| Unknown | Bits |
|---|---|
| `p` | 256 |
| 5 coefficients in `[0, p)` | 1,280 |
| 5 monomials from 705,432 | 97 |
| **Total needed** | **1,633** |
| Available: 8 × log₂(p) | **2,048** |

A solution exists — it just cannot be a generic sparse-interpolation algorithm. It has to exploit the fact that the exponents live in a *small, known* set.

### Preliminary Recon

Two facts established before writing any maths:

**The service takes ~28 seconds to answer.** Sage's startup. A 6-second timeout makes the service look dead. Set it to 60.

**`p` and `f` are freshly random on every connection.** Sending the same query set down two connections gives two unrelated answer sets — everything must come out of one session's eight evaluations.

```
conn A   [1]*11 -> 5226873945499952041655581879930230104947917304629601989945508053246873836890
conn B   [1]*11 -> 4503185451316233031895676066163918853382130671604280503563490454449330237958
```

The attack is **fully non-adaptive**: all eight points are fixed in advance. Send them all, compute off-line, and send the answer. No round-trip pressure.

---

### The Idea — Weighted-Degree Substitution

Evaluate along a geometric family built from a **weight vector** `w = (0, 3, 1, 2, 3, 0, 2, 1, 3, 2, 1)`:

```
v⁽ⁱ⁾ = ( z^(i·w₀), z^(i·w₁), …, z^(i·w₁₀) )   where z = 2
```

A monomial `x^e` collapses to a single power of `z`:

```
∏ₖ (z^(i·wₖ))^eₖ  =  z^(i·⟨w,e⟩)
```

So the evaluations form a Ben-Or/Tiwari sequence:

```
aᵢ = f(v⁽ⁱ⁾) = Σⱼ cⱼ · (z^Kⱼ)ⁱ ,      Kⱼ = ⟨w, eⱼ⟩
```

The roots `z^Kⱼ` depend only on the **weighted degrees** `{Kⱼ}`. This converts "which 5 of 705,432 monomials?" into "which 5 values of `⟨w,e⟩`?" — and the latter is a much smaller set.

### Choosing `w` — the Critical Parameter

The weighted degrees range over `[0, 11·max(w)]`, so the support search costs `C(11·max(w)+1, 5)`. Bigger weights spread the `Kⱼ` apart (needed for distinctness) but blow up the enumeration. The table below was measured over 4,000 random 5-monomial samples:

| Weight vector | K range | Supports to search | 5 distinct Kⱼ |
|---|---:|---:|---:|
| All ones (total degree) | 11 | 792 | **0.8 %** |
| max 2 | 22 | 33,649 | 42.1 % |
| max 3, sequential | 33 | 278,256 | 52.9 % |
| **max 3, spread `(0,3,1,2,3,0,2,1,3,2,1)`** | **33** | **278,256** | **56.0 %** |
| max 4 | 44 | 1,221,759 | 64.7 % |
| max 7 | 77 | 21,111,090 | 75.4 % |

**Plain total degree is useless — 0.8 %.** Half of all monomials of degree ≤ 11 have degree exactly 11, and another 26 % have degree 10. Five random monomials essentially always collide on total degree, so their coefficients merge into indistinguishable buckets.

`max 3, spread` is the sweet spot: 278 k supports search in ~4 seconds of pure Python, and 56 % of instances are solvable. The rest fail cleanly — detected and the driver reconnects.

---

### Phase 1 — Queries 1–7: Recover `p` and the Coefficients

Send `v⁽ⁱ⁾` for `i = 0..6`, collecting `a₀ … a₆`.

For a **guessed** support `{K₁ … K₅}`, the roots `z^Kⱼ` are known exactly, so we can build the annihilating polynomial over the *integers*:

```
Λ(Z) = ∏ⱼ (Z − z^Kⱼ)  =  Σₖ Eₖ Z^(5−k)     (E₀ = 1, all Eₖ ∈ ℤ)
```

Because `Λ` kills every root of the sequence, each shifted relation

```
Rᵢ = Σₖ Eₖ · a_{i+5−k}       i = 0, 1
```

is an exact **multiple of `p`** — computed entirely in ℤ from public numbers. Two of them give:

```
gcd(R₀, R₁) = p · gcd(κ₀, κ₁)
```

`gcd(κ₀, κ₁)` is small, so stripping small factors and testing primality (plus `p > max(aᵢ)`) recovers `p` outright. A wrong support gives two essentially random ~2⁴²⁴ integers whose gcd is also small — so the true support announces itself. In practice exactly one candidate survives.

The search is a DFS extending `Λ` one root at a time, reusing prefixes — each of the 278,256 leaves costs 12 big-int multiplications and one gcd. About 4 seconds in pure Python.

With `p` and the `Kⱼ` known, the coefficients fall out of a Vandermonde solve on `a₀…a₄`:

```python
def solve_coeffs(a, Ks, p):
    r = [pow(Z, k, p) for k in Ks]
    M = [[pow(r[j], i, p) for j in range(5)] + [a[i] % p] for i in range(5)]
    # ... Gaussian elimination ...
    return cs   # or None if any amplitude is zero (degenerate instance)
```

The deliberate holdouts `a₅` and `a₆` **verify** the result — a wrong candidate fails here.

```
phase1: 1 candidate (p,K) pairs
p = 22506639698101281076962449818093261022858920674767227711431485102684443458397
K = (9, 14, 18, 19, 21)
```

> **Degenerate-instance detection.** If the true `{Kⱼ}` has a collision (only 4 distinct values), many size-5 supersets annihilate the sequence and phase 1 returns ~30 candidates, each with a zero amplitude. Zero amplitude is the signal: reject and reconnect. The fix is to check `if any(c % p == 0 for c in cs): return None` and reconnect rather than crashing on `pow(cs[0], -1, p)`.

---

### Phase 2 — Query 8: A Low-Density Modular Knapsack

One query left, five monomials still to pin down. Evaluate at the **first eleven primes**:

```
v = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31)
y = Σⱼ cⱼ · mⱼ  (mod p),      mⱼ = ∏ᵢ primeᵢ^(eⱼᵢ)
```

The prime basis makes `e ↦ m` injective: different exponent vectors give different monomial values. A degree-≤11 monomial over these primes averages about 2³⁷ (worst case `31¹¹ ≈ 2⁵⁴·⁵`), so the five unknowns total ~190 bits against a 256-bit modulus. That is a *low-density* knapsack — lattice territory.

Consider the lattice of solutions to the congruence:

```
L = { x ∈ ℤ⁵ : Σⱼ cⱼxⱼ ≡ 0 (mod p) }
```

`L` has determinant `p`, so by the Gaussian heuristic `λ₁(L) ≈ p^(1/5) ≈ 2⁵¹`. The target solution has norm ≈ 2⁴⁰ — well inside `λ₁/2`, so the closest vector is unique and Babai's nearest-plane on an LLL-reduced basis finds it.

```python
def solve_knapsack(cs, y, p):
    n = len(cs)
    # Build the constraint lattice
    piv = next(i for i in range(n) if cs[i] % p)
    ipv = pow(cs[piv], -1, p)
    basis = [[0]*n for _ in range(n)]
    basis[piv][piv] = p
    for j in range(n):
        if j == piv: continue
        basis[j][piv] = (-ipv * cs[j]) % p
        basis[j][j] = 1
    t = [0]*n
    t[piv] = (ipv * y) % p
    red = lll(basis)        # pure-Python LLL
    u = babai(red, t)       # Babai nearest-plane
    return [t[i] - u[i] for i in range(n)]   # the short vector
```

> **The one real trap.** The first attempt scaled each coordinate by its per-K worst case (`31¹¹` for some classes). That skews the basis badly — the reduction misses the target and every instance fails with "density 1.06". **Uniform scaling** is correct: the bounds are unknown anyway, and the true solution is short enough that the unweighted lattice already isolates it.

Finally, trial-divide each `mⱼ` by the eleven primes to read off the exponent vector `eⱼ`, and verify `Σeⱼ ≤ 11` and `⟨w, eⱼ⟩ = Kⱼ`. A wrong lattice point differs by ≈ 2⁵¹ and fails both checks instantly.

---

### Reproducing `str(f)` Exactly

Getting the polynomial right is not the end. The submitted string must match **byte for byte**. Sage's `MPolynomial_polydict.__repr__` delegates to `PolyDict.poly_repr`, which:

- Joins variables with `*`, writing `^k` only when `k ≠ 1` → `x0*x1^2*x10^4`
- Omits a unit coefficient entirely; renders `p−1` as a leading `−`
- Joins terms with `" + "`, then applies `.replace(" + -", " - ")`
- Sorts by the **degrevlex** term order's sortkey with `reverse=True`

Sage's degrevlex sortkey:

```python
def sortkey_degrevlex(f):
    return (sum(f.nonzero_values(sort=False)), tuple(reversed([-v for v in f])))
```

That is `(total_degree, (−e₁₀, −e₉, …, −e₀))`, descending. Ties at equal degree go to the **smaller trailing exponent** first.

This detail caused a debugging round: a sloppier ordering produced a syntactically correct but lexicographically different string that the server rejected. The lesson is that the reference implementation has to be exactly what the service uses.

```python
def sage_str(pairs, p):
    def key(ce):
        e = ce[1]
        return (sum(e), tuple(-e[i] for i in reversed(range(NV))))
    out = []
    for c, e in sorted(pairs, key=key, reverse=True):
        multi = "*".join(f"x{i}" + (f"^{ei}" if ei != 1 else "")
                         for i, ei in enumerate(e) if ei)
        if not multi:        out.append(str(c % p))
        elif c % p == 1:     out.append(multi)
        elif c % p == p - 1: out.append("-" + multi)
        else:                out.append(f"{c % p}*{multi}")
    return " + ".join(out).replace(" + -", " - ")
```

---

### End-to-End Results

Development used a local model (`solve/sim.py`) — random 256-bit prime, five uniformly-chosen monomials, Sage-accurate `str()`:

```bash
$ python3 solve/bigtest.py
25 instances in 65s: solved=14  K-collision=11  other-fail=0
=> per-connection success ~56%
```

Zero failures whenever the five weighted degrees are distinct. The 44 % loss is entirely K-collisions, which are detected cleanly and never return a wrong answer (`solve/collision_test.py` asserts this).

Live session, attempt 4:

```
=== attempt 4 ===
  [+] booted in 28s
  [+] 8 queries done (29s), solving...
  phase1: 1 candidate (p,K) pairs
  p=22506639698101281076962449818093261022858920674767227711431485102684443458397
  K=(9, 14, 18, 19, 21)
  [+] f = 11009932442512469248347420817634832509228818476313118764625225966755293183552*x1^2*x2^2*x4*x5^2*x8^3*x10 + …

*** BHFlagY{b76085b3a7563a438da13397e0a8da14} ***
```

**Flag: `BHFlagY{b76085b3a7563a438da13397e0a8da14}`**

### Reproducing

```bash
cd solve
python3 pick_w.py           # weight-vector trade-off table
python3 bigtest.py          # end-to-end success rate on the local model
python3 collision_test.py   # collisions fail cleanly, never wrongly
python3 exploit.py          # live: retries until an instance is solvable
```

Pure Python 3, no third-party packages — LLL, Babai, Miller-Rabin, and the Sage-accurate `str()` are all in `solve/`.

---

## Popcnt Oracle

### Challenge

```python
import os
from Crypto.Util.number import getPrime
from math import gcd
import secrets

flag = os.environ.get("DYN_FLAG", "BHFlagY{dummy}")

e = 65537
while True:
    p = getPrime(1024)
    q = getPrime(1024)
    if gcd((p-1)*(q-1), e) == 1:
        break
n = p * q
d = pow(e, -1, (p-1)*(q-1))
m = secrets.randbelow(n)
c = pow(m, e, n)

print(f"{e = }")
print(f"{n = }")
print(f"{c = }")
while True:
    x = int(input("x> "))
    if x == m:
        print(flag)
        break
    print(pow(x, d, n).bit_count())
```

The server prints an RSA-2048 public key and `c = m^e mod n`. We win only by submitting the exact 2048-bit plaintext `m`. Every wrong guess is decrypted and the server returns its **population count** — the number of one-bits — of that decryption.

At first glance, one Hamming weight per query seems hopelessly weak for recovering a 2048-bit integer. The missing insight is textbook RSA's multiplicative structure.

---

### Step 1 — Turning RSA into a Chosen-Multiple Oracle

For any chosen multiplier `r`, send:

```
x = c · r^e  mod n
```

RSA decryption gives:

```
x^d = (m^e · r^e)^d = m · r  mod n
```

The returned value is therefore `HW(m · r mod n)`. Choosing `r = 2^i` exposes the orbit:

```
aᵢ = m · 2^i  mod n
```

These consecutive values satisfy:

```
a_{i+1} = 2·aᵢ          if aᵢ < n/2    (no reduction)
a_{i+1} = 2·aᵢ − n      if aᵢ ≥ n/2    (modular reduction)
```

When no reduction occurs, doubling is a left shift — the Hamming weight is preserved exactly:

```
aᵢ < n/2  ⟹  HW(a_{i+1}) = HW(aᵢ)
```

A **changed** Hamming weight proves `aᵢ` was in the upper half. The converse is not always true: subtracting `n` can occasionally produce a result with the same Hamming weight. Those collisions are the main technical problem.

---

### Step 2 — How Upper-Half Decisions Recover `m`

Write the binary expansion of `m/n`:

```
m/n = 0.b₀ b₁ b₂ …  (base 2)
```

The modular-doubling map is the binary shift map. Its upper-half decision at step `i` is exactly the next binary digit:

```
bᵢ = ⌊2·aᵢ / n⌋
```

After `L = bit_length(n)` decisions, the prefix `P` bounds the secret to:

```
⌈n·P / 2^L⌉ ≤ m ≤ ⌈n·(P+1) / 2^L⌉ − 1
```

Because `n < 2^L`, this interval has width below one. Once all decisions are correct, it contains at most one integer — the exact `m`.

---

### Step 3 — Detecting Both Halves with the Negative Orbit

To make the upper-half test reliable without being misled by Hamming-weight-preserving reductions, query both a value and its modular negative. If `zᵢ = n − aᵢ`, then `zᵢ` occupies the opposite half:

| Positive stream | Negative stream | Decision |
|---|---|---|
| Hamming weight changes | Unchanged | `aᵢ ≥ n/2` → bit = 1 |
| Unchanged | Hamming weight changes | `aᵢ < n/2` → bit = 0 |
| Unchanged | Unchanged | Popcount collision → **erasure** |

Both streams cannot change simultaneously — the stream that does not reduce is a plain left shift, whose Hamming weight is guaranteed to stay equal. The pair gives a **provably correct** bit when either stream changes, and an erasure otherwise.

In the winning instance, this classified all but 18 of the 2048 decisions.

---

### Step 4 — Reducing Oracle Calls with Adaptive Querying

A naïve implementation queries every positive and every negative value — about 4,098 RSA private operations. The remote service is CPU-bound, so the exploit uses an adaptive strategy:

1. Collect the complete positive stream (2,049 observations).
2. Query `HW(n − m)` once for the initial negative value.
3. Walk forward:
   - If the **positive** weight changes → decision is 1; the negative side did not reduce, so its next weight equals its current, and no query is needed.
   - If the positive weight stays equal → query only the next negative weight; a change gives 0, equality gives a collision.

Live result:

```
2049 positive observations
1030 adaptive negative observations
```

**~3,079 oracle calls** instead of ~4,098 — a 25 % reduction while keeping all guarantees.

---

### Step 5 — Resolving Collisions with a Sparse Secondary Orbit

The 18 erased decisions represent up to `2¹⁸` prefix branches. A secondary orbit with multiplier `r = 3` resolves them without a full additional stream:

```
aᵢ⁽³⁾ = 3·m·2^i  mod n
```

Only the samples **adjacent to the erased primary positions** are queried. The solver then performs a depth-first reconstruction of the binary prefix of `m/n`. At depth `k`, a prefix `P` fixes:

```
m/n ∈ [P/2^k, (P+1)/2^k)
```

For the secondary constraint at shift `i`, the fractional value `frac(3 · 2^i · m/n)` lies in a correspondingly small interval. As soon as that interval lies entirely below or above `1/2`, its upper-half bit is determined. Any branch that disagrees with the observed r=3 label is discarded immediately.

One r=3 position also collided in the winning run, so a single sparse `r = 5` check was added. The search then explored only **2,067 prefix nodes** — essentially one path through the 2,048 decisions — and recovered a unique integer.

```python
def classify(positive: list[int], negative: list[int]) -> list[int | None]:
    result: list[int | None] = []
    for before, after, opp_before, opp_after in zip(
        positive, positive[1:], negative, negative[1:]
    ):
        if before != after:
            result.append(1)
        elif opp_before != opp_after:
            result.append(0)
        else:
            result.append(None)   # erasure
    return result
```

---

### Step 6 — Crafting RSA Queries Without Knowing `d`

The exploit never encrypts a plaintext directly. Starting from `c`, it updates ciphertexts using only public operations:

```python
double_cipher = pow(2, e, n)    # encrypts r = 2
value = c                        # encrypts m

for _ in range(n.bit_length() + 1):
    positive_query = value
    negative_query = (-value) % n    # encrypts -m·2^i ≡ n-m·2^i
    value = (value * double_cipher) % n    # encrypts m·2^{i+1}
```

Decrypting `positive_query` yields `m·2^i mod n`; decrypting `negative_query` yields its modular negative. The same construction with `c · 3^e mod n` and `c · 5^e mod n` creates the sparse secondary streams. All arithmetic is in the public group — `d` is never needed.

---

### Step 7 — Recovering and Submitting the Plaintext

For every surviving `L`-bit prefix, the solver computes the exact integer interval:

```python
from math import ceil

low  = ceil(n * prefix / 2**L)
high = ceil(n * (prefix + 1) / 2**L) - 1
```

A candidate is accepted only when `low == high` and its entire positive doubling orbit reproduces the recorded Hamming weights. The resulting integer is sent to the socket as a decimal value. Because `x == m`, the service prints the flag instead of decrypting.

---

### Winning Run

```
[*] Connected: n is 2048 bits, e = 65537
[*] Collecting 2049 positive observations
[*] Collecting 1030 adaptive negative observations
[*] Primary stream has 18 collisions; resolving only those
[*] 1 secondary collisions remain; adding r = 5
[*] primary erasures: 18; multipliers: [1, 3, 5]
[*] explored 2067 prefix nodes
[*] Plaintext recovered; submitting it
BHFlagY{f2bfc77b60aa990dc06ef4e1830c578e}
```

**Flag: `BHFlagY{f2bfc77b60aa990dc06ef4e1830c578e}`**

### Reproducing

```bash
cd crypto/Popcnt-Oracle
python3 solve/exploit.py tcp.flagyard.com PORT --timeout 90
```

The live service needs several minutes to answer all queries. Keep one connection open — each new connection generates a different RSA key and plaintext. No third-party Python packages needed.

---

## Key Takeaways

**Pick the substitution so the unknowns land in a set you can enumerate.** Ben-Or/Tiwari treats monomial values as arbitrary field elements and pays `2t` evaluations for the privilege. The weight vector converts the 705,432-element monomial search into a 34-element support search — that is what buys the two missing evaluations. Measuring distinctness rates across 4,000 random samples before committing to a weight vector is the move; gut feel for a 0.8 % vs 56 % difference doesn't work.

**An unknown modulus is recoverable whenever you can build an exact integer annihilator.** Any relation among the outputs that must vanish mod `p`, but is computable over ℤ, is a multiple of `p`. Two of them and a gcd is all it takes. The cost of guessing a cheap structural property (the support) to manufacture that relation is the 278 k-leaf DFS — a few seconds in Python.

**Uniform lattice scaling beats "informed" bounds.** The Hokan knapsack first failed because scaling coordinates by their per-K worst case (`31¹¹`) skewed the basis and sent the CVP off target. The target was already short enough for the unweighted lattice to isolate it. Respect the Gaussian heuristic before adding weights.

**RSA's multiplicative structure is a multiplier oracle.** Sending `c · r^e` and receiving `HW(m · r)` is the entire foundation of the Popcnt attack. Once that framing is clear, the rest — modular-doubling binary extraction, dual negative stream, adaptive queries, sparse secondary streams — follows directly from the modular arithmetic.

**Hamming weight alone is not weak when the observation is coherent across a long orbit.** 2,049 Hamming weights of `{m·2^i mod n}` carry enough information to pin a 2,048-bit integer to a unique value. The key is that successive observations are *not independent* — they are linked by the modular-doubling recurrence, and that structure collapses 2^2048 possibilities to one in ~2,067 recursive steps.

---

## FAQ

**Q: Why does Sage generate a 5-term polynomial specifically?**  
A: `MPolynomialRing_base.random_element` has a `terms` parameter that defaults to `5` when `total >= 5`. It samples 5 monomials uniformly from all monomials of degree ≤ the given degree, assigns each a random coefficient in `[1, p-1]`, and sums them. The challenge source passes `degree=11` and no explicit `terms`, so you always get exactly five terms.

**Q: What is the weight vector doing, mathematically?**  
A: It maps each monomial `x^e` (a vector of 11 non-negative integer exponents summing to ≤ 11) to a scalar `K = ⟨w, e⟩`. The geometric substitution then makes `f(v⁽ⁱ⁾)` a linear combination of geometric sequences `{(z^Kⱼ)^i}` — exactly the Ben-Or/Tiwari structure, but with roots drawn from the small set `{z⁰, z¹, …, z³³}` instead of an arbitrary field. The roots are "tiny" in the sense that we can enumerate all `C(34, 5)` = 278,256 possible 5-subsets.

**Q: Why does the GCD of two shifted relations give `p · gcd(κ₀, κ₁)` instead of just `p`?**  
A: The annihilating polynomial `Λ` kills the sequence *modulo p*, so `Σ Eₖ · a_{i+k} = p · κᵢ` for some integer `κᵢ`. The two residuals `R₀, R₁` are `p·κ₀` and `p·κ₁`, so their gcd is `p · gcd(κ₀, κ₁)`. In practice `gcd(κ₀, κ₁)` is a small number (often 1), and stripping all prime factors below 100,000 while checking that the result remains above 200 bits and is prime suffices to isolate `p`.

**Q: Why does uniform lattice scaling work when per-bound scaling fails?**  
A: Per-bound scaling sets the column scale to the *worst-case* monomial value for each K-class, which can reach `31¹¹ ≈ 2⁵⁵`. Those extreme cases are exponentially rare, but the scaling applies to every sample. The resulting basis is so skewed that the first LLL short vector isn't anywhere near the target direction. The target's true norm (~2⁴⁰) is well below the unweighted Gaussian heuristic (~2⁵¹), so unweighted LLL + Babai is provably sufficient — no column scaling needed.

**Q: How does the modular-doubling orbit encode bits of m?**  
A: `m/n` has a binary expansion `0.b₀b₁b₂…`. Doubling mod `n` is equivalent to shifting that expansion left: the digit that "falls out" is `bᵢ = ⌊2·aᵢ/n⌋`, which is 1 if and only if `aᵢ ≥ n/2`. So each upper-half/lower-half decision directly reads off one binary digit of `m/n`, and 2,048 such decisions determine `m/n` to within one unit in the last place — which, combined with `m < n < 2^{2048}`, isolates `m` exactly.

**Q: Why query the negative orbit at all? Can't you just use the positive stream?**  
A: The positive stream alone is ambiguous: a Hamming weight that stays constant between steps could mean either that `aᵢ < n/2` (no reduction, shift preserves weight) or that `aᵢ ≥ n/2` but the modular subtraction coincidentally leaves weight unchanged. The negative stream removes this ambiguity: if `zᵢ = n − aᵢ`, exactly one of `aᵢ` and `zᵢ` is in the upper half, so exactly one doubling step reduces. The stream that does not reduce is a guaranteed left shift with preserved weight, which is the error-free signal.

**Q: How many collisions should we expect in a 2048-bit run?**  
A: A Hamming-weight-preserving reduction (positive stream changes, HW stays equal) happens when `popcount(2a − n) = popcount(a)` for `a ≥ n/2`. This is a rare alignment — roughly `O(1/√L)` of steps in theory, consistent with 18 collisions in 2,048 steps in the winning run. A second multiplier (`r = 3`) resolves almost all of them because collisions in independent streams are independent, so the probability of a joint collision at the same position is `O(1/L)`.

---

*Full source — solve scripts, local model, and winning session transcript — available at [github.com/Abdelkad3r/BlackHat-MEA-CTF-Qualification-2026](https://github.com/Abdelkad3r/BlackHat-MEA-CTF-Qualification-2026).*
