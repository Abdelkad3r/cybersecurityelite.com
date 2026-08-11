---
title: "UIUCTF 2026 Cryptography Writeup: Young Cryptography, positive-thinking & Rune Decryptor"
slug: "uiuctf-2026-crypto-writeup"
description: "Complete UIUCTF 2026 Cryptography writeup covering all three crypto challenges: Young Cryptography (a Diffie–Hellman-style key exchange over 64×64 symmetric integer matrices whose custom my_prod is actually the Robinson–Schensted–Knuth correspondence with Schensted insertion in the plactic monoid — broken by Monico's plactic-division algorithm: find any quotient q such that q·G = AG, then compute q·GB = AGB by associativity, hash the reconstructed matrix, AES-CBC decrypt); positive-thinking (a CKKS FHE oracle that publishes an encrypted 50-bit secret and reveals only the sign of a degree-8 Chebyshev polynomial evaluated on x/2^49 — broken with a chosen-ciphertext adaptive-oracle attack using only additions and repeated doublings so no modulus level is consumed, coarse-splitting the candidate set with translated roots then amplifying with additive 2^d doubling to place the first positive root at a half-integer boundary and recover all 50 bits in 50 queries); and Rune Decryptor (20 rounds of Elder Futhark monoalphabetic substitution across 10 languages with per-key scoring — the redacted bibliographic citation leaks the word-length and punctuation skeleton of Title -- Author, resolving one Project Gutenberg entry among 79,000, plus classical corpora for Latin and Ancient Greek, then gap-tolerant word alignment with majority-vote key recovery — 18 of 20 rounds solved for uiuctf{Po1ygl0t_Pr4ctIC3})."
date: 2026-08-11T18:00:00Z
lastmod: 2026-08-11T18:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["UIUCTF 2026"]
tags:
  - "uiuctf"
  - "uiuctf 2026"
  - "uiuc ctf"
  - "ctf writeup"
  - "cryptography"
  - "crypto"
  - "young cryptography"
  - "positive-thinking"
  - "rune decryptor"
  - "plactic monoid"
  - "robinson schensted knuth"
  - "rsk correspondence"
  - "schensted insertion"
  - "monico plactic division"
  - "ckks"
  - "tenseal"
  - "microsoft seal"
  - "fully homomorphic encryption"
  - "fhe"
  - "chebyshev polynomial"
  - "sign oracle"
  - "adaptive oracle"
  - "chosen ciphertext"
  - "monoalphabetic substitution"
  - "elder futhark"
  - "project gutenberg"
  - "corpus alignment"
  - "aes-cbc"
  - "sha-256"
  - "ctf 2026"
keywords:
  - "uiuctf 2026 crypto writeup"
  - "uiuctf 2026 cryptography writeup"
  - "uiuctf young cryptography writeup"
  - "uiuctf positive-thinking writeup"
  - "uiuctf rune decryptor writeup"
  - "plactic monoid key exchange break ctf"
  - "monico plactic division algorithm ctf"
  - "robinson schensted knuth correspondence ctf"
  - "schensted row insertion plactic ctf"
  - "ckks sign oracle attack ctf"
  - "tenseal chebyshev polynomial oracle ctf"
  - "chosen ciphertext fhe adaptive search ctf"
  - "ciphertext doubling no level consumption ckks"
  - "monoalphabetic substitution 10 language ctf"
  - "elder futhark cipher plaintext recovery"
  - "project gutenberg catalog word-length mask ctf"
  - "corpus alignment majority vote key recovery"
  - "uiuctf 2026 solutions"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/uiuctf-2026-crypto-writeup.png"
  alt: "UIUCTF 2026 Cryptography writeup cover — all three crypto challenges solved: Young Cryptography implements a Diffie-Hellman-style key exchange over 64 by 64 symmetric integer matrices whose custom my_prod turns out to be the Robinson-Schensted-Knuth correspondence with Schensted insertion in the plactic monoid, broken by Monico's plactic-division algorithm that finds any quotient q with q times G equals AG then computes q times GB equals AGB by associativity, hashes the reconstructed matrix and AES-CBC decrypts; positive-thinking exposes a CKKS FHE oracle that publishes an encrypted 50-bit secret and reveals only the sign of a degree-8 Chebyshev polynomial evaluated on x divided by 2 to the 49, broken with a chosen-ciphertext adaptive-oracle attack using only additions and repeated doublings so no CKKS modulus level is consumed, coarse-splitting the candidate set with translated roots then amplifying with additive 2 to the d doubling to place the first positive root at a half-integer boundary and recovering all 50 bits in 50 queries; and Rune Decryptor runs 20 rounds of Elder Futhark monoalphabetic substitution across 10 languages with per-key scoring where the redacted bibliographic citation leaks the word-length and punctuation skeleton of Title dash dash Author which resolves one Project Gutenberg entry among 79 thousand plus classical corpora for Latin and Ancient Greek then gap-tolerant word alignment with majority-vote key recovery solves 18 of 20 rounds for uiuctf{Po1ygl0t_Pr4ctIC3}"
---

**UIUCTF 2026**'s Cryptography track is a three-challenge object lesson in one principle: **attack the wrapper, not the primitive.** Every challenge in the set ships with a serious-looking cryptographic core — a Diffie–Hellman-style key exchange, a CKKS fully-homomorphic ciphertext, an Elder Futhark monoalphabetic substitution — and every intended solve leaves that core completely unbroken. The break is in the surrounding structure: the *monoid* the exchange lives in has division, the *oracle* on the FHE ciphertext leaks a sign under a malleable scheme, and the *metadata line* under the ciphertext identifies the source book to within one row of a 79,000-entry catalogue.

`Young Cryptography` cosplays a matrix-based DH but its custom `my_prod` operator is the Robinson–Schensted–Knuth correspondence in disguise, so multiplication of symmetric matrices is really multiplication of Young tableaux in the plactic monoid — a structure with a documented division algorithm (Monico 2022). `positive-thinking` gives an unauthenticated CKKS oracle: publish an encrypted 50-bit secret, evaluate a degree-eight Chebyshev polynomial on `x/2^49`, print only whether the decrypted result is positive. That sign is enough for an adaptive search that uses only additions and repeated ciphertext doublings, preserving the modulus chain the server needs to finish the polynomial. `Rune Decryptor` looks like a per-key-scored polyglot substitution cipher; the actual vulnerability is that the redacted citation printed beneath the ciphertext preserves word-length and punctuation, turning the challenge into a Project Gutenberg lookup.

Handouts, per-challenge READMEs, dependency-conscious Python solvers, and captured transcripts live at [Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026). This **CyberSecurity Elite** UIUCTF 2026 Cryptography writeup walks all three end to end with an emphasis on *what the actual primitive is*, why the intended attack sidesteps it, and how to reproduce every step with pure Python (plus one optional C reference for the plactic-division heavy path). Read alongside the paired [UIUCTF 2026 Miscellaneous writeup](/ctf-writeups/uiuctf-2026-misc-writeup/) (three jail escapes) and the [UIUCTF 2026 Nabi AI web writeup](/ctf-writeups/uiuctf-2026-web-nabi-ai-writeup/) (Next.js Server Action SSRF).

## All three Cryptography challenges at a glance

| Challenge | Category | Bug class / primitive | Flag |
|---|---|---|---|
| [Young Cryptography](#young-cryptographyplactic-division-breaks-a-fake-matrix-diffiehellman) | Crypto | Diffie–Hellman-style key exchange over 64×64 symmetric matrices with custom `my_prod` that is the RSK correspondence + Schensted insertion (plactic monoid). Broken by Monico's plactic-division algorithm: find any `q` with `q·G = AG`, compute `q·GB = AGB`. | `uiuctf{r081n50n_sch3n573d_knu7h_f9a29620}` |
| [positive-thinking](#positive-thinkingsign-oracle-adaptive-search-over-ckks) | Crypto | Malleable CKKS ciphertext + sign-of-`T8(x/2^49)` oracle. Broken with additions and repeated doublings only (no modulus-level consumption), coarse-splitting via translated Chebyshev roots then amplifying to a half-integer boundary. 50 queries recover 50 bits. | `uiuctf{s34rch1ng_th3_sp4c3_667f4c3d}` |
| [Rune Decryptor](#rune-decryptor20-language-substitution-solved-by-corpus-lookup) | Crypto | 20 rounds Elder Futhark monoalphabetic substitution × 10 languages, per-key scoring. Redacted citation preserves word-length + punctuation skeleton → Project Gutenberg lookup + Latin / Ancient Greek corpora + gap-tolerant word alignment + majority-vote key recovery. | `uiuctf{Po1ygl0t_Pr4ctIC3}` |

Three challenges, three completely different cores, and one repeated principle — **the flag is downstream of the primitive, and the wrapper is always closer to the flag**.

---

## Young Cryptography — plactic division breaks a fake matrix Diffie–Hellman

> *Flag:* `uiuctf{r081n50n_sch3n573d_knu7h_f9a29620}`

Young Cryptography presents itself as a straightforward three-message key exchange over sparse symmetric integer matrices. The public transcript is exactly five Python literals — one per `print` call:

```text
G
AG = A * G
GB = G * B
ciphertext
IV
```

`A` and `B` are private random `64 × 64` symmetric matrices. The shared value is computed on either side using the challenge's custom `my_prod`:

```python
AGB = my_prod(A, GB)
shared_secret = SHA256.new(str(AGB).encode()).digest()[:128]
```

Since `SHA256.digest()` returns exactly 32 bytes, slicing to 128 is a no-op — the AES-256 key is the full SHA-256 of the exact repr of the reconstructed shared matrix. Recovering it requires reproducing `AGB` byte-for-byte in Python list form; a coarse invariant of the matrix will not do.

### Parse and inspect

```python
lines = Path("out").read_text().splitlines()
G, AG, GB, ct, iv = [ast.literal_eval(line) for line in lines]
```

```text
G:   64 x 64, total weight 256
AG:  64 x 64, total weight 512
GB:  64 x 64, total weight 512
ct:  48 bytes
iv:  16 bytes
```

Every call to `random_matrix()` performs 128 edge insertions with symmetric mirroring (a diagonal pick doubles the same entry), producing total weight 256 per matrix.

### Recognise the custom product

`my_prod` is not ordinary matrix multiplication. Its inner rule reads:

```python
def f(a, b, c, x):
    return (max(b[0], c[0]) + x,) + tuple(
        min(b[k - 1], c[k - 1])
        + max(b[k], c[k])
        - a[k - 1]
        for k in range(1, n)
    )
```

That is the **tropical growth rule** for the Robinson–Schensted–Knuth correspondence. The forward loop propagates a boundary of partitions; the final inverse loop turns the boundary back into a symmetric matrix.

Under RSK, a matrix corresponds to a pair of semistandard Young tableaux `(P, Q)`. Transposing the matrix swaps the tableaux, so a symmetric matrix has `P = Q` and is represented by a single tableau. `my_prod` therefore:

1. Converts each symmetric input matrix into its tableau.
2. Multiplies the tableaux with Schensted row insertion.
3. Converts the product tableau back into its unique symmetric matrix.

This is exactly multiplication in the **plactic monoid**. A one-line sanity check confirms the zero matrix is the identity:

```python
Z = [[0] * 64 for _ in range(64)]
assert my_prod(G, Z) == G
assert my_prod(Z, G) == G
```

The construction `a·g / g·b / a·g·b` is the same as the plactic Diffie–Hellman studied in [Division in the Plactic Monoid (Monico, ePrint 2022/1684)](https://eprint.iacr.org/2022/1684). The relevant contribution of that paper is: **the plactic monoid supports a probabilistic left-division algorithm.**

### Reduce to left-division

Let lowercase letters be the plactic elements represented by the public matrices. We know `g`, `ag`, `gb`. It is enough to solve:

```text
find q such that q·g = ag
```

The monoid is not cancellative, so `q` is not guaranteed to equal the original private `a`. That does not matter — associativity gives the intended shared value regardless:

```text
q·(gb) = (q·g)·b = (ag)·b = agb
```

A candidate quotient can be verified using public data alone:

```python
assert insert_word(q + matrix_to_word(G)) == insert_word(matrix_to_word(AG))
```

### Leak the quotient's content

Plactic multiplication preserves content — the multiset of symbols in `q · g` equals the multiset union of the multisets in `q` and `g`. Since both `g` and `ag` are public, so is the content of `q`:

```python
q_count[s] = count_AG[s] - count_G[s]
```

The counts sum to 256 (the weight of a single private matrix). The search space is no longer all words over a 64-symbol alphabet — it is *permutations of a known 256-element multiset*.

### Divide with a tableau metric

For two equal-length words `u` and `v`, define a distance on their tableaux:

```text
d(u, v) = 1/2 · Σ_{r,s} |P_r(u)[s] − P_r(v)[s]|
```

where `P_r(w)[s]` is the count of symbol `s` in row `r` of the tableau. Distance is zero exactly when the two words are plactically equal.

The division algorithm:

1. Start with any word matching the known content of `q`.
2. Randomly remove one symbol and reinsert it at another position.
3. Compute the tableau of the candidate followed by the divisor word.
4. Accept moves that do not increase the distance to the target `ag` tableau.
5. Track the best word; after a plateau, take a short random jump from that best.

The search is accelerated by **lifting over increasing alphabets**. First solve using only symbol `1`, then introduce all copies of symbol `2` and solve over `{1, 2}`, then `{1, 2, 3}`, and so on to all 64 symbols. Projection onto each prefix alphabet respects plactic equivalence, so every solved prefix is a useful seed for the next lift.

This is Algorithms 1 and 2 from Monico's paper. The author's [C reference implementation](https://www.math.ttu.edu/~cmonico/placdiv.c) recovers a quotient in roughly 100 seconds on a single CPU core with seed 1 for this instance, without needing a random jump. [`solve.py --recover`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/young-cryptography/solve.py) contains a readable Python implementation; the successful quotient is preserved in [`quotient.txt`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/young-cryptography/quotient.txt) for immediate, deterministic verification without waiting on the probabilistic search.

### Reconstruct, hash, decrypt

Given the recovered quotient:

```python
shared_rows = insert_word(q + matrix_to_word(GB))
shared_matrix = rows_to_matrix(shared_rows, 64)
```

The shared matrix has total weight 768 (three factors of 256). The AES-256 key is the SHA-256 of the exact Python list repr:

```python
key = hashlib.sha256(str(shared_matrix).encode()).digest()[:128]
```

For this transcript:

```text
key: 611c8c07414307e4caeee73b28111c9c43adcf18cc219e54e8a128f0f243fede
iv : 3b7460aa3a1a776115ed0479fe755cdf
```

AES-CBC decryption with PKCS#7 unpadding yields the flag. `solve.py` uses PyCryptodome when available and falls back to shelling out to `openssl` with local PKCS#7 validation.

### Run the solver

Deterministic (loads the saved quotient):

```bash
python3 solve.py
```

```text
[+] Saved plactic quotient verified
[+] Plaintext: uiuctf{r081n50n_sch3n573d_knu7h_f9a29620}
```

Probabilistic re-derivation:

```bash
python3 solve.py --recover --seed 0
```

### Takeaway

**The primitive was not broken; the monoid was.** Diffie–Hellman is safe in a cyclic group because groups are cancellative and cyclic-group discrete log is hard. The plactic monoid is neither cancellative nor a group, and its multiplication is polynomial-time invertible up to plactic equivalence. Reading `my_prod` carefully — recognising that RSK boundary rule for what it is — is the entire crypto content of the solve. Once the primitive is named (plactic multiplication of Young tableaux), a 2022 paper hands over the algorithm. The flag body — `r081n50n_sch3n573d_knu7h` — is the challenge tipping its hat.

---

## positive-thinking — sign oracle adaptive search over CKKS

> *Flag:* `uiuctf{s34rch1ng_th3_sp4c3_667f4c3d}`

positive-thinking is a live TLS service. It publishes a public [TenSEAL](https://github.com/OpenMined/TenSEAL) CKKS context (Microsoft SEAL 4.3 under the hood), publishes a ciphertext encrypting a uniformly random 50-bit integer, and offers up to 100 oracle queries. For each submitted ciphertext `x`, it computes a degree-eight Chebyshev polynomial on `x / 2^49` and reveals only the sign of the result. Then it asks you to name the secret.

The intended attack turns that sign into an adaptive predicate oracle over the secret, split into two phases: a coarse range reducer that uses the eight roots of `T8`, and a fine binary comparator that amplifies with additive doublings so no CKKS modulus level is spent on the client side.

### Audit the service

Secret generation:

```python
SECRET_BITS = 50
secret = secrets.randbelow(2**SECRET_BITS)
encrypted_secret = ts.ckks_vector(context, [secret])
```

The server publishes a public copy of the context (private key stripped):

```python
public_context = context.copy()
public_context.make_context_public()
```

The client can therefore deserialize `encrypted_secret`, encrypt known values, and apply supported homomorphic operations. CKKS is intentionally malleable; a stripped context is enough to *transform* a ciphertext, just not decrypt one.

For every submitted ciphertext `x`, the service computes:

```python
normalized = x * (1.0 / 2**24) * (1.0 / 2**25)
result = chebyshev8(normalized).decrypt()[0]
print("Positive" if result > 0 else "Not positive")
```

The value fed to `T8` is `x / 2^49`. The submitted ciphertext does not have to be a fresh encryption — it can be a translation or additively amplified version of the published `encrypted_secret`.

### Recognise the polynomial

The service evaluates:

```text
T8(x) = 128·x^8 − 256·x^6 + 160·x^4 − 32·x^2 + 1
```

This is the Chebyshev polynomial of the first kind, satisfying `T8(cos θ) = cos(8θ)`. Its eight simple roots are:

```text
ρ_k = cos((2k − 1)·π/16),  k = 1, …, 8
```

In the unnormalised ciphertext domain with `N = 2^49`, the roots sit at `R_k = N · ρ_k`. Sorted:

```text
−0.980785 N, −0.831470 N, −0.555570 N, −0.195090 N,
 0.195090 N,  0.555570 N,  0.831470 N,  0.980785 N
```

Because `T8(0) = 1` and every root is simple, the sign alternates at every root. A single response therefore reports membership in a known union of intervals.

### Why straight binary search fails

The tempting probe is:

```text
c = a · (Enc(secret) − midpoint)
```

with a scalar `a` chosen to place the sign transition exactly where we want. In TenSEAL, multiplication by a plaintext scalar is followed by a rescale and **consumes one CKKS modulus level**. The server already needs its level chain for:

1. multiplication by `1 / 2^24`;
2. multiplication by `1 / 2^25`;
3. degree-eight polynomial evaluation.

Any client-side level consumption causes the server evaluation to error out with a scale or chain-exhaustion failure. The exploit must preserve the ciphertext's original level.

Ciphertext addition and plaintext addition both preserve level. The entire attack is consequently built from **translations, subtractions, and repeated doublings only**.

### Phase 1 — coarse search with translated roots

Start with:

```text
S = {0, 1, …, 2^50 − 1}
```

For a translation `Enc(secret) + offset`, the eight root boundaries become `secret = R_k − offset`. Any offset partitions `S` into nine alternating positive / negative regions.

The solver represents the current candidate set as a sorted list of inclusive integer intervals. A `partition(offset)` helper intersects each candidate interval with the nine sign regions, returning two new lists: candidates that would answer `Positive` and candidates that would answer `Not positive`.

To extract maximum information per response, `balanced_offset()` searches for a translation that splits the candidate cardinality exactly in half. The count can change only when a translated root crosses a candidate interval endpoint, so the relevant breakpoints are `offset = R_k − endpoint`. Scanning between breakpoints yields exact half-splits on the power-of-two domain.

Representative run — first five queries:

```text
Query 1: 2^50 → 2^49, four intervals
Query 2: 2^49 → 2^48, two intervals
Query 3: 2^48 → 2^47, two intervals
Query 4: 2^47 → 2^46, two intervals
Query 5: 2^46 → 2^45, one interval
```

Once one sufficiently narrow interval remains, a simpler numerically-stable comparator becomes possible.

### Phase 2 — exact search with additive amplification

Given the remaining candidates as one interval `[L, H]`:

```text
M = ⌊(L + H + 1) / 2⌋
B = M − 1/2
```

`B` lies exactly between the greatest integer in the lower half and the least integer in the upper half. Let the first two positive roots in the ciphertext domain be:

```text
A = 2^49 · cos(7π/16)
C = 2^49 · cos(5π/16)
```

Construct this affine function of the encrypted secret:

```text
q(secret) = 2^d · (secret − L) + A − 2^d · (B − L)
```

By construction `q(B) = A`. The first positive root sits at the half-integer boundary between the two halves. The power `2^d` is chosen so the complete lower half remains in `(−A, A)` (where `T8` is positive) and the complete upper half in `(A, C)` (where `T8` is negative):

```text
2^d · (B − L) < 2·A
2^d · (H − B) < C − A
```

The implementation uses 80% of the maximum to stay away from neighbouring roots. The oracle interpretation is now a conventional binary compare:

```text
Positive     ⇒ secret <  M
Not positive ⇒ secret >= M
```

Crucially, multiplication by `2^d` is not CKKS multiplication — it is `d` ciphertext doublings:

```python
probe = encrypted_secret - float(low)
for _ in range(doublings):
    probe = probe + probe
```

Addition does not consume a level. As the candidate interval shrinks, `d` grows and the distance between adjacent integer candidates at the root is amplified, counteracting CKKS approximation error during the low-bit recovery.

### Recover and submit

Every well-chosen query halves the candidate count. After 50 responses starting from `2^50`, one integer remains. Successful live run ended with:

```text
[47] amplified 2^44, positive: 8/16 candidates in 1 interval(s)
[48] amplified 2^45, positive: 4/8 candidates in 1 interval(s)
[49] amplified 2^46, positive: 2/4 candidates in 1 interval(s)
[50] amplified 2^48, positive: 1/2 candidates in 1 interval(s)
recovered secret: 973748065867721
uiuctf{s34rch1ng_th3_sp4c3_667f4c3d}
```

50 queries against a 100-query budget — half the budget unused. No brute force.

### Reproduce

TenSEAL 0.3.17 tags upstream but is not currently on PyPI; the [`requirements.txt`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/positive-thinking/requirements.txt) pins the exact upstream commit that builds against Microsoft SEAL 4.3.3.

```bash
python3 -m pip install -r requirements.txt
python3 solve.py
```

Wire compatibility matters — TenSEAL 0.3.16 macOS wheels use SEAL 4.1 and cannot load the live service's context.

### Takeaway

**FHE protects plaintext during computation; it does not make arbitrary derived output safe to expose.** The oracle accepts arbitrary ciphertexts under the same public context as the encrypted secret. Because the scheme is malleable, the client can construct chosen affine functions of that ciphertext. Revealing the sign of a polynomial on those chosen ciphertexts is an adaptive predicate oracle over the secret, and the polynomial's root structure hands out the discretisation for free. A real deployment must strictly bind allowed computations to an authenticated protocol and analyse every revealed predicate for cumulative leakage. The `s34rch1ng_th3_sp4c3` in the flag calls it: the attack is search, dressed in CKKS clothes.

---

## Rune Decryptor — 20-language substitution solved by corpus lookup

> *Flag:* `uiuctf{Po1ygl0t_Pr4ctIC3}`

Rune Decryptor is 20 rounds of the same setup: one paragraph of natural language drawn from one of ten languages (`de en es fr grc it la nl ru sv`), monoalphabetically substituted onto the Elder Futhark rune block. Below the ciphertext, a dim redacted bibliographic citation is printed. Five attempts per round. More than 70% of 20 rounds earns the flag — 15 rounds.

Two properties reshape the challenge relative to a textbook cryptogram. **Scoring is per key, not per character** — a wrong guess reports `1/20 symbols mapped correctly`, and a round only counts when *every* symbol of a 20–29 letter alphabet is right. Statistical quadgram hill-climbers routinely reach 95% of a paragraph while misassigning a once-occurring letter, which here scores zero. That is the harder half. The easier half is that the redacted citation preserves word-length and punctuation and therefore leaks the *source text*, turning the challenge into a lookup problem.

### Getting past the proof-of-work

Every connection opens with a kCTF proof-of-work:

```text
== proof-of-work: enabled ==
please solve a pow first
You can run the solver with:
    python3 <(curl -sSL https://goo.gle/kctf-pow) solve s.ABod.AACXB+lMsiIf075N4d/Pk5zU
```

The challenge string decodes to a difficulty and a seed. `ABod` is `00 1a 1d` — 6685 sequential square roots modulo `2^1279 − 1`. Serial by design, but `gmpy2` finishes in about 3.5 seconds.

A parser trap worth calling out: the naïve `re.search(rb'solve (\S+)', banner)` matches the "please **solve a** pow" line above it and returns `a`. Anchor on the version prefix:

```python
m = re.search(rb'solve (s\.\S+)', d)
```

### Harvest ground truth before writing any solver

Rather than guess at the format, one connection deliberately fails every round. Submitting a wrong answer of the correct length burns an attempt; after five, the server reveals the source:

```text
[1 attempt(s) left] >
Incorrect.
Out of attempts.   [German]
        Kleine Lebensgemälde in Erzählungen -- Voss, Julius von, 1768-1…
```

That single session produces a labelled corpus of twenty rounds — ciphertext, hint line, revealed language and title — which becomes the offline regression set in [`samples/rounds.json`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/rune-decryptor/samples/rounds.json). Everything else is then developed offline, honouring the "do not hammer the server" request.

Established rules:

| Property | Observation |
| --- | --- |
| Language distribution | exactly two rounds per language (10 × 2 = 20) |
| Text length | 300–450 letters |
| Alphabet size | 20–24 symbols (Latin), 21–24 (Greek), 27–29 (Cyrillic) |
| Character set | letters, spaces and periods only — no commas, no apostrophes |
| Submission check | `Submission has 3 letters, expected 362.` — length-compared |
| Scoring | `1/20 symbols mapped correctly` — whole key must be right |

The 27–29 distinct symbols in Russian rounds rule out Latin transliteration and confirm the substitution alphabet is per-script.

### The hint line is a fingerprint

The masked citation replaces word characters only, preserving every space and every punctuation mark:

```text
mask: ██████ █████████████ ██ ███████████ -- ████, ██████ ███, ████-█…
real: Kleine Lebensgemälde in Erzählungen -- Voss, Julius von, 1768-1…
```

That mask encodes the word-length sequence *and* the punctuation skeleton of `"{Title} -- {Author}"`. Project Gutenberg publishes its full catalogue as CSV:

```bash
curl -sSL https://www.gutenberg.org/cache/epub/feeds/pg_catalog.csv.gz | gunzip > pg_catalog.csv
```

Masking each of the ~79,000 catalogue entries the same way and comparing turns book identification into exact string matching. Two implementation details make it land in practice:

- **Truncation.** Long citations are cut and ellipsised. The observed rule is `s[:63].rstrip() + '…'` when `len(s) > 64`, right-aligned in 72 columns. Comparing prefixes handles it.
- **Authors.** The catalogue joins contributors with `; ` and tags their roles, but the server prints only the first one. Both the full and first-only rendering must be tried.

Running [`matcher.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/rune-decryptor/matcher.py) over the captured rounds resolves **12 of 14 Gutenberg rounds to a single catalogue entry**. The exceptions are volume series — *Histoire du Consulat et de l'Empire* matches all 16 volumes because only the volume number differs and it is masked — which is harmless because content-based disambiguation happens in the next stage.

### Recover the exact normalisation

Knowing the book is not enough; the plaintext must be reproduced character-for-character. The challenge lowercases and strips punctuation, but the treatment of diacritics is a real question — and testable. Take a round with a now-known source, normalise the book several ways, and slide the ciphertext's word-length sequence across it looking for agreement:

```text
acc_strip_sp   nwords= 34335 bestmatch=51/60 at 10015
expand_sp      nwords= 34036 bestmatch=60/60 at 9909   ← exact
umlaut_sp      nwords= 34036 bestmatch=51/60 at 9909
```

For German, the winner *expands* umlauts (`ließ → liess`, `Thür → thuer`). Repeating the experiment for every language shows the normalisation is **language-aware**, not one transliteration pass:

| Language | Rule | Evidence |
| --- | --- | --- |
| German | `ä→ae ö→oe ü→ue ß→ss` | `ließ→liess`, `Thür→thuer` |
| Swedish | strip diacritics (`ä→a ö→o å→a`) | `ifrån→ifran`, `Fjällbyfolk→fjallbyfolk` |
| Spanish / French / Italian / Dutch | strip diacritics | `sueño→sueno`, `armée→armee` |
| Ancient Greek | strip polytonic accents, `ς→σ` | verified by consistent key recovery |
| Russian | Cyrillic preserved | 29 distinct symbols > 26 |

Everything not a letter becomes a space — `l'armée` yields two words `l armee` — while periods survive as their own layout symbol. Rules live in [`norm.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/rune-decryptor/norm.py). German and Swedish disagree, so this is not `unidecode` and not any single locale-independent library.

### Latin, Greek, and Russian are not on Gutenberg

Six rounds return zero catalogue candidates:

```text
[Latin]          In C. Verrem -- M. Tullius Cicero
[Latin]          Ad Lucilium Epistulae Morales -- Seneca, Lucius Annaeus
[Ancient Greek]  Dialexeis -- Maximus of Tyre
[Ancient Greek]  Historia Ecclesiastica -- Eusebius
[Russian]        Война и мир. Том 2 -- Tolstoy
[Russian]        С того берега -- Herzen
```

Gutenberg holds 103 Latin texts, 9 Russian, and no Ancient Greek at all; author strings like `M. Tullius Cicero` are Perseus house style, not Gutenberg's.

The important realisation: **identifying the title is not required**. The word-length search only needs the passage to exist *somewhere* in a corpus. Skip the catalogue entirely and search bulk corpora:

- Latin: the Latin Library (CLTK mirror) + Perseus `canonical-latinLit` → **21.3 M words**
- Ancient Greek: Perseus `canonical-greekLit` + `First1KGreek` → **36.4 M words**

Each corpus is flattened to one space-separated stream of normalised words and indexed as one byte per word length ([`corpus_index.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/rune-decryptor/corpus_index.py)). Searching for a passage is a plain `bytes.find` over a 36 MB byte-length index. A hit returns a word index; a streaming pass recovers the text — the corpora never have to live in memory.

Russian remains unsolved (no assembled corpus contains the editions used), capping the approach at 18 of 20 rounds. That is comfortably above the 15 required.

### Verse and drama break exact matching

Version 1 of the solver demanded the entire word-length sequence match verbatim. Prose worked; poetry and drama did not:

```text
=== R16 Ancient Greek (Ἠλέκτρα -- Sophocles) 79 words ===
best contiguous word-run: 12/79
corpus: … πολλα τοι σμικροι λογοι εσφηλαν ηδη και κατωρθωσαν βροτουσ χρυσοθεμισ λογοσ τισ …
```

That stray `χρυσοθεμισ` in mid-sentence is a **speaker label** (ΧΡΥΣΟΘΕΜΙΣ) that the TEI-to-text conversion kept inline. Ovid's *Tristia* fails for the analogous reason — textual variants between Latin Library and Perseus editions.

The fix: the answer is not the passage, it is the 20-to-29 entry key. A *partial* alignment covering 60% of the words still contains every symbol. [`align.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/rune-decryptor/align.py) anchors on any 8-word run and walks outward, resynchronising across small insertions or deletions on either side:

```python
for d in range(1, MAX_SKIP + 1):
    if _run(ctw, lens, i, j + step * d, step):      # corpus has extra words
        j += step * d; break
    if _run(ctw, lens, i + step * d, j, step):      # ciphertext has extra words
        i += step * d; break
else:
    break
```

With gap tolerance, all four classical rounds that had failed — *Tristia*, *Institutio Oratoria*, *Thesmophoriazusae*, *Electra* — recover complete keys with zero conflicts.

### Majority-vote key recovery

Aligned word pairs are zipped character-by-character into per-rune vote counters; each rune takes its most-voted letter, highest-confidence first, so bijectivity is preserved:

```python
for r in sorted(votes, key=lambda x: -votes[x].most_common(1)[0][1]):
    for letter, _ in votes[r].most_common():
        if letter not in used:
            key[r] = letter; used[letter] = r
            break
```

Voting is not just defensive bookkeeping — it repairs the source. One Seneca round aligned with three character conflicts because the Latin Library reads `trementis et attonitos` where the challenge's edition reads `trementes et adtonitos`. Every other occurrence of those runes agreed, so the majority carried, and applying the recovered key back to the *ciphertext* reproduced the challenge's reading rather than the corpus's. **Answer submissions are always the ciphertext-with-key substitution**, never a corpus paste — the ciphertext carries the authoritative spacing, periods, and word forms.

### Results

Replaying both captured sessions offline ([`replay.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/rune-decryptor/replay.py)) recovers **36 of 40 complete keys**; the four misses are precisely the four Russian rounds:

```text
capture-1 R9  Latin          In C. Verrem -- M. Tullius Cicer  17.1s (21, 21, 0)  FULL KEY
capture-1 R16 Russian        Война и мир. Том 2 -- Tolstoy    228.8s (19, 27, 15) incomplete
capture-2 R4  Latin          Tristia -- P. Ovidius Naso        14.5s (21, 21, 0)  FULL KEY
capture-2 R16 Ancient Greek  Ἠλέκτρα -- Sophocles              62.0s (23, 23, 0)  FULL KEY

recovered 36/40 complete keys
```

Live session end:

```text
========================================================================
Solved 18/20 (90%).
uiuctf{Po1ygl0t_Pr4ctIC3}
========================================================================
```

### Reproduce

```bash
pip install gmpy2                 # optional; ~10x faster proof-of-work
python3 build_corpora.py          # Latin + Ancient Greek corpora (~1.5 GB download)
python3 replay.py                 # offline regression over samples/rounds.json
python3 play.py                   # live session against the challenge server
```

`matcher.py` fetches `pg_catalog.csv` on first use; `pgtext.py` caches every downloaded book under `pgcache/` for lightweight repeat runs.

### Takeaway

**The metadata was the vulnerability, not the ciphertext.** Publishing a redacted citation that preserves word lengths and punctuation leaks enough to identify one book among 79,000, and from there the plaintext is public data. Two additional notes worth internalising:

- **Deterministic beats statistical when the scoring is per key.** A quadgram hill-climb that recovers 95% of a 350-character paragraph scores zero. An alignment that covers 60% of the words scores 100% because it still pins the whole key. Match the algorithm to the scoring function.
- **A `>70%` threshold is a `>=71%` threshold when the denominator is 20.** An earlier session scored 14/20 (70%) and was refused — because the parser was scraping the *previous round's title* into the ciphertext slot due to the `…` truncation character clearing the `U+16A0` rune-block threshold. Read the parsing rules the same way you read the cryptographic ones.

---

## Cross-cutting lessons from the UIUCTF 2026 Cryptography set

Three challenges, three different-looking primitives, one repeated pattern — **attack the wrapper, not the primitive**:

- **Young Cryptography** advertises a matrix-based DH. The actual object is a monoid, and monoids have quotients that groups do not. Reading `my_prod` for what it computes (RSK + Schensted) points at a paper (Monico 2022) that hands over the algorithm.
- **positive-thinking** advertises a CKKS-protected secret. FHE is not broken; the *sign oracle* on a *malleable ciphertext* under a *public context* is broken. The homomorphic algebra the primitive supports (addition without level consumption) is exactly what the exploit needs.
- **Rune Decryptor** advertises a per-key-scored polyglot substitution. The cipher is fine. The *metadata line* under the ciphertext identifies one book in a 79,000-entry catalogue, and Project Gutenberg publishes the plaintext.

Portable techniques used across the set:

- **Name the primitive first.** Custom operators in a CTF are almost never new mathematics; they are named things with search terms attached. Recognising `my_prod` as RSK, or Chebyshev's `T8` by its coefficients, or Elder Futhark by its Unicode block turned each challenge into "apply the standard result."
- **Public data + malleability = adaptive oracle.** Every time a scheme lets an attacker transform an existing ciphertext (RSA blinding, ElGamal multiplicativity, CKKS addition/doubling), a bit-leaking output turns into a full-secret adaptive search. Estimate the leakage-per-query and multiply.
- **Preserve the invariants the server needs.** positive-thinking's server needs three unspent modulus levels for its own computation; the exploit uses only additions and doublings for that reason. Any exploit whose plumbing steals resources the server needs to finish its side of the protocol looks like a "flaky service" failure, not an exploit.
- **Redacted output is not opaque output.** Rune Decryptor's citation was redacted, but the mask preserved word lengths and punctuation. Anywhere a redaction preserves structure, the structure is the leak.
- **Match your algorithm to the scoring function.** Per-key scoring kills statistical solvers that reach 95% of a paragraph. Alignment-and-vote scores 100% at 60% word coverage. Design the algorithm around the metric the server actually evaluates.

## Reproduce it yourself

Each challenge ships a standalone solver in the [UIUCTF 2026 repository](https://github.com/Abdelkad3r/UIUCTF-2026) under its own directory, with the original handout, a Python solver, and any offline analysis tooling. Where a heavy pass benefits from a compiled implementation, an alternative is documented (the plactic-division reference C code for Young Cryptography); where a live TLS service is involved, the solver uses only the Python standard library.

- [`young-cryptography/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/young-cryptography) — plactic monoid division, RSK conversion, Schensted insertion, AES-CBC decrypt; ships `quotient.txt` for deterministic verification.
- [`positive-thinking/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/positive-thinking) — TenSEAL 0.3.17 pinned to the exact upstream commit compatible with SEAL 4.3; live-tested adaptive oracle solver.
- [`rune-decryptor/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/rune-decryptor) — Project Gutenberg catalogue matcher, language-aware normalisation, Latin + Ancient Greek corpus indices, gap-tolerant alignment, majority-vote key recovery, kCTF proof-of-work driver.

Browse the full [CTF writeups](/ctf-writeups/) archive for more cryptography and adversarial-search walkthroughs, or read the companion [UIUCTF 2026 Miscellaneous writeup](/ctf-writeups/uiuctf-2026-misc-writeup/) covering all three jail escapes and the [UIUCTF 2026 Nabi AI web writeup](/ctf-writeups/uiuctf-2026-web-nabi-ai-writeup/) covering the Next.js Server Action SSRF + OpenBao ACL wildcard chain.

---

*This writeup is part of the CyberSecurity Elite [UIUCTF 2026](/series/uiuctf-2026/) series. Handouts, per-challenge READMEs, and dependency-conscious solvers for all three Cryptography challenges are published at [github.com/Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026).*
