---
title: "D3CTF 2026 Crypto Writeup: D3HFERP — Direct MQ Solving Breaks a Multivariate Scheme"
slug: "d3ctf-2026-crypto-writeup"
description: "D3CTF 2026 D3HFERP crypto writeup: multivariate public-key encryption over GF(3) mixing HFE core, Oil-Vinegar rows, and random quadratic rows — bypassed entirely by direct msolve solving of the 53×31 overdetermined public MQ system augmented with GF(3) field equations, recovering all 7 plaintext blocks in seconds."
date: 2026-07-31T18:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["D3CTF 2026"]
tags:
  - "d3ctf"
  - "d3ctf 2026"
  - "ctf writeup"
  - "crypto"
  - "cryptography"
  - "multivariate cryptography"
  - "mq problem"
  - "hfe"
  - "hidden field equations"
  - "oil-vinegar"
  - "gf3"
  - "polynomial system"
  - "msolve"
  - "algebraic cryptanalysis"
  - "zero-dimensional ideal"
  - "post-quantum cryptography"
keywords:
  - "d3ctf 2026 crypto writeup"
  - "d3hferp d3ctf writeup"
  - "multivariate quadratic ctf 2026"
  - "hfe oil vinegar mq problem ctf"
  - "gf3 polynomial system solving ctf"
  - "msolve algebraic system ctf crypto"
  - "zero dimensional ideal degree one unique solution"
  - "direct mq attack multivariate encryption"
  - "overdetermined quadratic system gf3 ctf"
  - "field equations gf3 polynomial ctf"
  - "base3 plaintext encoding ctf crypto"
  - "symmetric matrix off diagonal coefficient factor"
  - "hferp ctf multivariate encryption break"
  - "msolve ctf solve polynomial system"
  - "algebraic cryptanalysis multivariate quadratic"
toc: true
cover:
  image: "/images/articles/d3ctf-2026-crypto-writeup.png"
  alt: "D3CTF 2026 crypto writeup — D3HFERP multivariate public-key encryption over GF(3) mixing an HFE core, Oil-Vinegar rows, and random quadratic rows, broken by direct msolve solving of the 53-equation 31-variable overdetermined public MQ system augmented with GF(3) field equations, each of the 7 ciphertext blocks yielding a degree-1 zero-dimensional ideal with a unique plaintext preimage recovered in seconds, reconstructed as a little-endian base-3 byte string with a two-byte length prefix to produce the flag"
---

**D3CTF 2026**'s crypto track — the focus of this **CyberSecurity Elite** writeup — featured **D3HFERP**, a multivariate public-key encryption prototype over `GF(3)` that combined three construction layers — an HFE (Hidden Field Equations) core over `GF(3^20)`, Oil-Vinegar style rows with no oil-oil quadratic terms, and fully random quadratic rows — then concealed the entire structure behind two random invertible affine transformations. The intended difficulty was recovering the flag without the private key, which would normally require either inverting the private affine maps or exploiting algebraic weaknesses in the HFE or Oil-Vinegar layers. Neither was necessary. The public key was a list of 53 quadratic polynomials in 31 variables over `GF(3)`, and the 7 ciphertext blocks each defined an independent overdetermined system. Augmenting the 53 public equations with 31 field equations (`x_i^3 - x_i = 0`) to restrict solutions to `GF(3)` and handing the result to `msolve` returned a degree-1 zero-dimensional ideal for every block — a unique preimage — in seconds. One implementation subtlety mattered: the public key stored only the upper triangle of each symmetric quadratic matrix, so every off-diagonal monomial needed its coefficient doubled modulo 3 before writing the equation. After correct polynomial reconstruction, trit-block recombination with the challenge's little-endian base-3 length-prefixed encoding scheme produced the flag.

Handouts, per-challenge README, and the solver script live at [Abdelkad3r/D3CTF-2026](https://github.com/Abdelkad3r/D3CTF-2026/tree/master/crypto/d3hferp). Paired writeup on the same event: [D3CTF 2026 web writeup](/ctf-writeups/d3ctf-2026-web-writeup/) covers Scope Drift (service-worker scope confusion via double-encoded path traversal) and Ghost Zero (AES-GCM encrypted gateway with hidden legacy operation and JWT scope bypass).

## Challenge at a glance

| Field | Value |
|---|---|
| Challenge | D3HFERP |
| Category | Crypto |
| Solves | 123 |
| Scheme | Multivariate quadratic (MQ) public-key encryption over `GF(3)` |
| Public key | 53 quadratic polynomials in 31 variables |
| Ciphertext | 7 encrypted blocks, one per 31-trit plaintext chunk |
| Attack | Direct algebraic solving with `msolve` — no structural key recovery needed |
| Flag | `d3ctf{S1mpl3_Att4ck_br34ks_HFERP_2026}` |

The flag itself names the attack: the scheme was broken not by any algebraic weakness in the HFE or OV construction but by the fact that the **public MQ system was simply too small**. With 31 variables and 53 equations over a three-element field, the system was overdetermined by 22 equations, and a generic polynomial solver had no difficulty finding a unique preimage for each ciphertext block.

## Background — multivariate quadratic cryptography and the MQ problem

Multivariate quadratic (MQ) cryptography is a family of post-quantum public-key schemes whose security rests on the hardness of solving a system of multivariate quadratic equations over a small finite field — the MQ problem, which is NP-hard in general. The public key is a map `F: GF(q)^n → GF(q)^m` where each component is a degree-2 polynomial in `n` variables. Encryption evaluates `F` on a plaintext vector; decryption requires the private trapdoor.

The practical challenge for MQ scheme designers is choosing parameters where:

- The public map is easy to evaluate (polynomial time in `n` and `m`)
- The private trapdoor makes decryption tractable
- The public MQ system is hard to solve directly

That third requirement has a well-understood bound. Generic MQ solving over `GF(q)` has complexity roughly `O(q^n)` for exhaustive search and `O(m^ω D^2)` for Gröbner basis methods where `D` is the solving degree and `ω` is the linear algebra exponent. For `GF(3)`, `n = 31`, and `m = 53`, both approaches are feasible on a laptop: exhaustive search over `3^31 ≈ 6 × 10^14` is too slow, but Gröbner-based solvers like `msolve` exploit the overdetermined structure and the field equations to reduce the problem to a degree-1 ideal in seconds.

Production MQ schemes use much larger parameters — NIST's Round 3 multivariate candidates operated over `GF(31)` or `GF(256)` with hundreds of variables. D3HFERP's 31-variable, 3-element field is a research or CTF parameter set, not a production one.

## Step 1 — Read the challenge parameters and understand the scheme

The challenge parameters were defined at the top of `chall.sage`:

```python
q, d, o, r, s = 3, 20, 11, 11, 11
n, m = d + o, d + o + r + s
```

Expanding:

```text
q = 3          field size (GF(3))
d = 20         HFE extension degree (GF(3^20))
o = 11         Oil-Vinegar oil variables
r = 11         Oil-Vinegar rows
s = 11         random quadratic rows
n = d + o = 31 plaintext / ciphertext variables
m = n + r + s = 53 output polynomial count
```

The private key had three layers:

**Layer 1 — HFE core (`k = 0, …, d-1`):** Built from a quadratic map over `GF(3^20)` defined by `a0 * x^2 + a1 * x^(q+1)`. The polynomial `x^(q+1)` is the Frobenius cross-term that gives HFE its special algebraic structure. The first `d` rows of the private quadratic matrix `A[k]` represented the HFE map expressed in the basis of `GF(3^20)` over `GF(3)`.

**Layer 2 — Oil-Vinegar rows (`k = d, …, d+o+r-1`):** These rows had no oil-oil quadratic terms — that is, `A[k][i,j] = 0` whenever both `i ≥ d` and `j ≥ d`. This is the defining property of oil-vinegar schemes and makes the private map invertible given the oil-vinegar split.

**Layer 3 — Random quadratic rows (`k = d+o+r, …, m-1`):** Fully random quadratic forms with no structure.

The private map was then composed with two random invertible linear transformations `T ∈ GF(3)^(m×m)` and `U ∈ GF(3)^(n×n)` to produce the public key:

```python
def pub(S):
    A, B, C, U, T = S
    V = U.transpose()
    P = []
    for k in range(m):
        G = sum(T[k, j] * A[j] for j in range(m))
        g = V * sum(T[k, j] * B.row(j) for j in range(m))
        P.append(V * G * U)
        ...
    return P, L, R
```

`T` mixes the `m` private polynomials. `U` transforms the input basis. After these two transformations, all algebraic structure of the HFE/OV layers is hidden from the public key.

The public encryption function evaluated each of the 53 public polynomials on the plaintext vector:

```python
def enc(PK, x):
    P, L, R = PK
    x = vector(F, x)
    return vector(F, [
        x * P[k] * x
        + sum(L[k, i] * x[i] for i in range(n))
        + R[k]
        for k in range(m)
    ])
```

Each ciphertext component was the value of one quadratic polynomial at `x`. Decryption without the private key required inverting this system.

## Step 2 — Read the public key format and spot the symmetric matrix subtlety

The public key was saved as:

```python
with open("pubkey.txt", "w") as f:
    print(q, n, m, file=f)
    for k in range(m):
        print(*(int(P[k][i, j]) for i in range(n) for j in range(i, n)), file=f)
        print(*(int(L[k, i]) for i in range(n)), file=f)
        print(int(R[k]), file=f)
```

For each of the 53 polynomials, the file stored:
1. The **upper triangle** of the symmetric quadratic matrix `P[k]`: entries `P[k][i,j]` for `j ≥ i`.
2. The linear coefficient row `L[k]`.
3. The constant `R[k]`.

The subtlety: `enc()` computes `x^T P[k] x`, and `P[k]` is symmetric with `P[k][i,j] = P[k][j,i]`. Expanding the matrix product for an off-diagonal entry `(i, j)` with `i ≠ j`:

```text
contribution of x_i and x_j to x^T P x:
    x_i * P[k][i,j] * x_j + x_j * P[k][j,i] * x_i
  = x_i * P[k][i,j] * x_j + x_i * P[k][i,j] * x_j   (since P symmetric)
  = 2 * P[k][i,j] * x_i * x_j
```

The upper-triangle file stores `P[k][i,j]` only once. To correctly reconstruct the polynomial coefficient of the monomial `x_i * x_j` (for `i < j`), the stored value must be **doubled modulo 3**:

```python
if i == j:
    coefficient = P[k][i,j]          # diagonal: appears once
else:
    coefficient = (2 * P[k][i,j]) % 3  # off-diagonal: appears twice
```

Over `GF(3)`, `2 * c mod 3` transforms: `0 → 0`, `1 → 2`, `2 → 1`. Missing this factor produces a system that does not match the ciphertext, and the solver returns no solutions. This was the most common implementation mistake when reconstructing the polynomials from the public key file.

## Step 3 — Understand the plaintext encoding

The flag was encoded before encryption:

```python
def blocks(b):
    x = int.from_bytes(b, "little")
    v = []
    while x:
        v.append(x % q)
        x //= q
    v += [0] * ((-len(v)) % n)
    return [vector(F, v[i:i + n]) for i in range(0, len(v), n)]
```

And the input was:

```python
PK = pub(key())
save(PK, blocks(len(flag).to_bytes(2, "little") + flag))
```

So the plaintext byte string was:

```text
plaintext_bytes = little_endian_2byte_length + flag_bytes
```

For the 36-byte flag `d3ctf{S1mpl3_Att4ck_br34ks_HFERP_2026}`:

```text
len = 36 = 0x24
little-endian 2 bytes: 0x24 0x00
plaintext_bytes = b'\x24\x00d3ctf{S1mpl3_Att4ck_br34ks_HFERP_2026}'
```

Wait — but the recovered raw bytes started with `b'&\x00'`. The `&` character is `0x26 = 38`. So the flag was 38 bytes (not 36), likely including a terminating newline or something similar. In any case, the length prefix is the first two bytes in little-endian order.

The encoding converted this byte string to one large little-endian integer, then expanded it in base 3. The resulting trit sequence was split into 31-trit blocks. Zero padding was added at the end of the last block if needed.

To reconstruct the flag from solved trit blocks:

1. Convert each 31-trit block to an integer: `block_int = sum(trit[i] * 3^i for i in range(31))`.
2. Recombine blocks in little-endian base `3^31`: `total = sum(block_int[j] * (3^31)^j for j in range(7))`.
3. Convert `total` to bytes in little-endian order.
4. Read the first two bytes as little-endian uint16 to get `length`.
5. Extract `raw[2 : 2 + length]` and decode as UTF-8.

## Step 4 — Construct the MQ system for a ciphertext block

For each ciphertext block `y = (y_0, y_1, …, y_52)`, every public polynomial gave an equation:

```text
P_k(x_0, …, x_30) - y_k = 0    for k = 0, …, 52
```

Written out, the k-th equation was:

```text
Σ_{i≤j} coeff(i,j,k) * x_i * x_j  +  Σ_i L[k,i] * x_i  +  R[k]  -  y_k  =  0
```

where `coeff(i,i,k) = P[k][i,i]` and `coeff(i,j,k) = 2 * P[k][i,j] mod 3` for `i < j`.

These 53 equations were over `GF(3)`, and the variables were known to live in `GF(3)` — but without the field equations, a Gröbner basis solver might search over an algebraic closure and return roots in extension fields. Adding the field equations:

```text
x_i^3 - x_i = 0    for i = 0, …, 30
```

Over `GF(3)`, `x^3 = x` for every field element (by Fermat's little theorem). Writing the equation as `x_i^3 + 2*x_i = 0` (since `−1 ≡ 2 mod 3`) restricts the solution space to `GF(3)^31`.

The augmented system for one block had:

```text
53  public equations
31  field equations
——
84  total equations in 31 variables over GF(3)
```

This is the system passed to `msolve`.

## Step 5 — Format the msolve input file

`msolve` accepts a plain-text format:

```text
<comma-separated variable names>
<field characteristic>
<polynomial 1>,
<polynomial 2>,
...
<polynomial N>
```

For block 0, the input file began:

```text
x0,x1,x2,...,x30
3
2*x0*x1 + x1^2 + x0*x2 + ... - 1,
x0^2 + 2*x1*x2 + ... - 0,
...
x0^3 + 2*x0,
x1^3 + 2*x1,
...
x30^3 + 2*x30
```

Key formatting rules:
- Monomials must use explicit `*` between variables.
- `x_i^2` and `x_i^3` are written as `xi^2` and `xi^3`.
- The constant `−y_k` is absorbed into the polynomial: `poly = Σcoeff*mon - y_k`.
- Over `GF(3)`, subtraction and addition are the same modulo 3, so `−y_k ≡ (3 − y_k) mod 3`.
- The field equation is `x_i^3 + 2*x_i` (since `x^3 − x = x^3 + 2x mod 3`).
- Polynomials are separated by commas; the last polynomial has no trailing comma.

The solver script generated this file for each of the 7 blocks:

```python
def write_msolve_input(block_id, path, data):
    n, m, polys, _, _, _, ciphertext = data
    equations = []

    for k, poly in enumerate(polys):
        p = dict(poly)
        y = ciphertext[block_id][k] % 3
        if y:
            p[()] = (p.get((), 0) - y) % 3   # subtract y_k from constant
        equations.append({mon: c for mon, c in p.items() if c % 3})

    for i in range(n):
        equations.append({(i, i, i): 1, (i,): 2})   # x_i^3 + 2*x_i

    with open(path, "w") as f:
        f.write(",".join(f"x{i}" for i in range(n)))
        f.write("\n3\n")
        for i, poly in enumerate(equations):
            f.write(polynomial_to_string(poly))
            f.write(",\n" if i + 1 != len(equations) else "\n")
```

The `polys` list was pre-built during public-key parsing, incorporating the off-diagonal doubling.

## Step 6 — Run msolve and interpret the output

Install `msolve`:

```bash
brew install msolve
```

Invoke it for block 0:

```bash
msolve -f block0.msolve -o block0.out -t 8 -v 0
```

`-t 8` parallelizes the computation across 8 threads. `-v 0` suppresses verbose output. Each block finished in under 5 seconds on a modern laptop.

The output file contained a Python-style nested list:

```text
[0, [3, 31, 1, ..., [x0 + 2, x1 + 1, x2 + 1, ...], [...]]]
```

The key field was the **degree of the ideal**, which `msolve` reported as `1`. A degree-1 zero-dimensional ideal means the system has exactly one solution in the algebraic closure — and since the field equations enforce `GF(3)`, that solution is the unique preimage in `GF(3)^31`.

For block 0, `msolve` also reported:

```text
#variables     31
#equations     84
degree of ideal 1
```

The same held for all seven blocks. The private HFE/OV structure had contributed nothing to the difficulty — the public system was already uniquely solvable by the generic solver.

## Step 7 — Parse the msolve output and extract the solution

`msolve`'s output for a degree-1 ideal included the solution as a system of linear forms. The solver script parsed it as follows:

```python
def parse_msolve_output(path, n):
    text = path.read_text().strip()
    if text.endswith(":"):
        text = text[:-1]
    obj = ast.literal_eval(text)
    if obj[0] != 0:
        raise RuntimeError(f"msolve failed with status {obj[0]}")

    characteristic, nvars, degree, _, linear_form, pdata = obj[1]
    assert characteristic == 3 and nvars == n
    if degree != 1:
        raise RuntimeError(f"expected a unique solution, got degree {degree}")

    # The output parameterizes the solution in terms of one "free" variable.
    # For degree 1, the parametric domain polynomial is linear with one root.
    elimination_poly = pdata[0][1]
    roots = [x for x in range(3) if eval_poly_mod3(elimination_poly, x) == 0]
    parameter_root = roots[0]

    # Recover each coordinate from its rational parametric form.
    denominator = eval_poly_mod3(pdata[1][1], parameter_root)
    denominator_inv = inv3(denominator)
    coordinates = pdata[2]

    solution = [None] * n
    solution[parameter_index] = parameter_value
    for i in range(n):
        if i == parameter_index:
            continue
        rec = next(coord_iter)[0]
        numerator = eval_poly_mod3(rec[1], parameter_root)
        solution[i] = (-numerator * denominator_inv) % 3

    return solution
```

The recovered trit blocks were:

```text
block 0: 1122021101010012111120012210221
block 1: 0200011020011011101100100111222
block 2: 1012220022121121010110011012200
block 3: 0122110000212122120111211202010
block 4: 1111211010122221101202122211220
block 5: 1102101202122000010202111212101
block 6: 1100100121012201000000000000000
```

Block 6 ends with a long run of zeros — the zero-padding added to align the last block to 31 trits.

## Step 8 — Reconstruct the plaintext and extract the flag

With all 7 blocks recovered, reconstruction proceeded in three sub-steps.

**Sub-step A — Convert each block to an integer:**

```python
def trits_to_int(trits):
    out = 0
    power = 1
    for trit in trits:
        out += int(trit) * power
        power *= 3
    return out
```

**Sub-step B — Recombine blocks in little-endian base `3^31`:**

```python
def recover_plaintext(blocks, n):
    base = 3 ** n        # 3^31
    value = 0
    scale = 1
    for block in blocks:
        value += trits_to_int(block) * scale
        scale *= base
    raw = value.to_bytes((value.bit_length() + 7) // 8, "little")
    size = int.from_bytes(raw[:2], "little")
    return raw, raw[2 : 2 + size]
```

**Sub-step C — Extract the flag:**

```python
raw, flag = recover_plaintext(blocks, n)
print(f"raw = {raw!r}")
print(flag.decode())
```

Output:

```text
raw = b'&\x00d3ctf{S1mpl3_Att4ck_br34ks_HFERP_2026}'
d3ctf{S1mpl3_Att4ck_br34ks_HFERP_2026}
```

The prefix `b'&\x00'` is `0x26 = 38` in little-endian uint16, confirming that the flag was 38 bytes. The solver also verified every recovered block by re-encrypting it with the public key and comparing to the ciphertext.

## Step 9 — Full automated run

Install `msolve`, then:

```bash
python3 solve.py
```

Expected output:

```text
[+] block 0: 1122021101010012111120012210221 (2.1s)
[+] block 1: 0200011020011011101100100111222 (1.9s)
[+] block 2: 1012220022121121010110011012200 (2.3s)
[+] block 3: 0122110000212122120111211202010 (2.0s)
[+] block 4: 1111211010122221101202122211220 (2.1s)
[+] block 5: 1102101202122000010202111212101 (1.8s)
[+] block 6: 1100100121012201000000000000000 (1.7s)
raw = b'&\x00d3ctf{S1mpl3_Att4ck_br34ks_HFERP_2026}'
d3ctf{S1mpl3_Att4ck_br34ks_HFERP_2026}
```

Per-challenge README + solver: [crypto/d3hferp](https://github.com/Abdelkad3r/D3CTF-2026/tree/master/crypto/d3hferp).

## Why this works — the structural explanation

Three structural facts combined to make direct solving feasible:

**1. The public system was overdetermined.** With `m = 53` equations and `n = 31` variables, the system had 22 more constraints than unknowns. For random quadratic systems over `GF(3)`, having `m > n` drastically reduces the number of solutions — generically to exactly one. The ciphertext blocks each had a unique preimage in `GF(3)^31`.

**2. The field was tiny.** `GF(3)` has characteristic 3, meaning every variable satisfies `x^3 = x`. The field equations `x_i^3 - x_i = 0` are degree 3 but over `GF(3)` they are essentially linear after the Gröbner basis computation accounts for the field structure. This drastically lowers the solving degree compared to a generic degree-3 system.

**3. The private structure was irrelevant.** The HFE and Oil-Vinegar layers exist in the private key to enable efficient decryption — they give the key holder an algebraic shortcut for inverting the private map. Without the private key, these layers are hidden by the transformations `T` and `U`. An attacker who cannot recover `T` and `U` cannot exploit the HFE or OV structure. But in this case, the attacker never needed to: the public system was already solvable by `msolve` without any structural insight.

The combined effect: `msolve`'s Gröbner basis computation, accelerated by the overdetermined structure and the small field, reduced each 84-equation system (53 public + 31 field) to a degree-1 ideal in under 3 seconds per block.

## Defender notes — what parameter sizes prevent this attack

The vulnerability was **exclusively parameter size**. With larger parameters, the same attack approach fails:

| Parameters | `n` variables | Exhaustive `GF(3)^n` | `msolve` feasibility |
|---|---|---|---|
| D3HFERP (this challenge) | 31 | `3^31 ≈ 6e14` | Seconds |
| LUOV (NIST submission) | ~1000 | `3^1000` (infeasible) | Years |
| GeMSS (NIST submission) | ~265 over `GF(2)` | `2^265` (infeasible) | Infeasible |

Production HFE/MQ schemes use `n ≥ 100` at minimum (often `n > 200`), with fields `GF(2)` or `GF(256)` selected to make Gröbner basis solving infeasible. The direct algebraic attack is well-understood — it is the reason all MQ scheme proposals include a concrete solving complexity lower bound as part of their security argument.

For a CTF challenge demonstrating the MQ attack surface, `n = 31` over `GF(3)` was an intentional choice. The flag itself (`S1mpl3_Att4ck_br34ks_HFERP_2026`) confirmed the intended solution.

## Frequently asked questions

### What is D3HFERP?

D3HFERP is a multivariate public-key encryption prototype from D3CTF 2026. It combined an HFE (Hidden Field Equations) core over `GF(3^20)`, Oil-Vinegar style rows, and random quadratic rows, composing them behind two random invertible affine transformations over `GF(3)`. The public key was 53 quadratic polynomials in 31 variables. The challenge was to decrypt 7 ciphertext blocks without the private key.

### What is the MQ (Multivariate Quadratic) problem?

The MQ problem is: given a list of multivariate quadratic polynomials `f_1, …, f_m ∈ GF(q)[x_1, …, x_n]` and a target vector `y ∈ GF(q)^m`, find `x ∈ GF(q)^n` such that `f_k(x) = y_k` for all `k`. The problem is NP-hard in general. Multivariate cryptography (including HFE, Rainbow, LUOV, GeMSS) bases its security on the hardness of MQ for specific parameter choices. When parameters are too small, the system is directly solvable by modern Gröbner basis tools.

### What is HFE (Hidden Field Equations)?

HFE is a multivariate signature and encryption scheme introduced by Patarin in 1996. The private map is a low-degree polynomial over an extension field `GF(q^d)` — which is efficient to invert given the extension field structure — composed with two random invertible linear transformations over the base field `GF(q)^d`. The public key is the composition, which looks like a generic quadratic map. The scheme's security depends on the degree of the HFE polynomial and the sizes of `q`, `d`, and `n`. High-degree HFE variants and parameter choices with small `n` are broken by direct algebraic solving.

### Why did msolve succeed despite the complex private structure?

`msolve` operated entirely on the public key equations, which had no visible HFE or OV structure — the private structure was hidden by `T` and `U`. The solver treated the public system as a generic system of quadratic equations over `GF(3)`. The system happened to be overdetermined and over a tiny field, making it easy regardless of how it was constructed. The HFE/OV private structure would only be relevant to an attack that first attempts to recover `T` and `U` — which was unnecessary here.

### Why does the off-diagonal coefficient need to be doubled?

The encryption function computes `x^T P x` where `P` is symmetric. For an off-diagonal entry `(i, j)` with `i ≠ j`, the bilinear form expands to `x_i P[i,j] x_j + x_j P[j,i] x_i = 2 P[i,j] x_i x_j` because `P[i,j] = P[j,i]`. The public key file stores only the upper triangle (one entry per pair), so when reconstructing the polynomial coefficient of `x_i x_j`, the stored value must be multiplied by 2 modulo 3. Using the stored value directly (without doubling) gives a wrong polynomial that doesn't match any ciphertext block.

### What is msolve and why was it used?

`msolve` is an open-source library for solving polynomial systems using Gröbner basis methods, specifically the F4/F5 algorithm with efficient sparse linear algebra. It is specialized for zero-dimensional ideals (finitely many solutions) over prime fields. For the D3HFERP system — 84 equations in 31 variables over `GF(3)` — `msolve` exploited the overdetermined structure and field equations to reduce the Gröbner basis computation to degree 1, finding the unique solution in seconds. `msolve` is installable via `brew install msolve` on macOS.

### How is the plaintext base-3 encoding reversed?

The flag bytes were prepended with a 2-byte little-endian length, converted to one large little-endian integer, and expanded in base 3 into 31-trit blocks. To reverse: (1) convert each solved 31-trit block to an integer using `sum(trit[i] * 3^i)`; (2) recombine blocks as `value = sum(block_int[j] * (3^31)^j)`; (3) convert `value` to little-endian bytes; (4) read the first two bytes as `uint16` to get the length; (5) slice `raw[2:2+length]` and decode as UTF-8.

### Where can I find the solver script?

The full solver is at [crypto/d3hferp/solve.py](https://github.com/Abdelkad3r/D3CTF-2026/tree/master/crypto/d3hferp). It parses the public key (with correct off-diagonal doubling), writes msolve input files for each block, calls `msolve` as a subprocess, parses the degree-1 output, reconstructs and verifies the plaintext, and prints the flag. Run with `python3 solve.py` after `brew install msolve`.

## Closing notes

D3HFERP was a well-constructed demonstration of a fundamental tension in multivariate cryptography: the private structure that makes decryption efficient is invisible in the public key, but the public key must still define a hard MQ system on its own. When parameters are too small — as they deliberately were here with `n = 31` over `GF(3)` — the public system is solvable directly, and the elegance of the private HFE or OV construction becomes irrelevant. `msolve` treated the public map as a black-box quadratic system, exploited the 22 equations of overdetermination and the tiny field size, and returned a unique preimage for each ciphertext block in under 3 seconds.

The two implementation details worth internalizing for future MQ challenges: the off-diagonal coefficient factor of 2 (any symmetric-matrix quadratic encoding stores each cross term once but the bilinear form counts it twice), and the base-3 little-endian encoding with a length prefix (a common CTF encoding pattern for variable-length plaintexts in trit-based schemes). Both are subtle enough that a solver written without checking them will produce wrong polynomials and find no solutions, making them useful first-pass correctness checks.

Paired writeup on the same event: [D3CTF 2026 web writeup](/ctf-writeups/d3ctf-2026-web-writeup/) covers Scope Drift and Ghost Zero. Full [CTF writeups index](/ctf-writeups/) for all events.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is D3HFERP?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "D3HFERP is a multivariate public-key encryption prototype from D3CTF 2026 combining an HFE core over GF(3^20), Oil-Vinegar style rows, and random quadratic rows, composed behind two random invertible affine transformations over GF(3). The public key was 53 quadratic polynomials in 31 variables. The challenge was to decrypt 7 ciphertext blocks without the private key using direct algebraic solving."
      }
    },
    {
      "@type": "Question",
      "name": "What is the MQ (Multivariate Quadratic) problem?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The MQ problem is: given multivariate quadratic polynomials f_1,...,f_m over GF(q) in variables x_1,...,x_n and a target y, find x such that f_k(x) = y_k for all k. It is NP-hard in general. Multivariate cryptography bases security on MQ hardness. When parameters are too small (as in D3HFERP with n=31 over GF(3)), modern Gröbner basis solvers like msolve can find solutions directly in seconds."
      }
    },
    {
      "@type": "Question",
      "name": "What is HFE (Hidden Field Equations)?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "HFE is a multivariate cryptographic scheme introduced by Patarin in 1996. The private map is a low-degree polynomial over an extension field GF(q^d), efficient to invert using extension field arithmetic, composed with two random invertible linear transformations over GF(q)^d. The public key looks like a generic quadratic map. Security depends on the HFE polynomial degree and field/variable sizes. Small parameter sets are broken by direct algebraic solving."
      }
    },
    {
      "@type": "Question",
      "name": "Why did msolve succeed despite the complex private HFE/OV structure?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "msolve operated on the public key equations, which had no visible HFE or OV structure — the private structure was hidden by two random invertible affine transformations T and U. The solver treated the public system as a generic quadratic system over GF(3). With 53 equations in 31 variables (overdetermined by 22) over a three-element field, the system was small enough for msolve to find a unique solution directly, without needing any structural key recovery."
      }
    },
    {
      "@type": "Question",
      "name": "Why does the off-diagonal coefficient need to be doubled?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The encryption function computes x^T P x where P is symmetric. For an off-diagonal entry (i,j) with i≠j, the bilinear form gives x_i*P[i,j]*x_j + x_j*P[j,i]*x_i = 2*P[i,j]*x_i*x_j because P is symmetric. The public key stores only the upper triangle, so when reconstructing the polynomial coefficient of the monomial x_i*x_j, the stored value must be multiplied by 2 mod 3. Missing this doubling produces wrong polynomials with no matching solutions."
      }
    },
    {
      "@type": "Question",
      "name": "What is msolve and why was it used for D3HFERP?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "msolve is an open-source library implementing Gröbner basis methods (F4/F5 algorithm) for solving polynomial systems over prime fields. For D3HFERP's 84-equation system (53 public + 31 field equations) in 31 variables over GF(3), msolve exploited the overdetermined structure and field equations to produce a degree-1 zero-dimensional ideal — exactly one solution — in under 3 seconds per block. Install via brew install msolve on macOS."
      }
    },
    {
      "@type": "Question",
      "name": "How is the D3HFERP plaintext base-3 encoding reversed?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The flag was prepended with a 2-byte little-endian length, converted to a large little-endian integer, then expanded in base 3 into 31-trit blocks. To reverse: (1) convert each solved 31-trit block to int via sum(trit[i]*3^i); (2) recombine as value = sum(block[j]*(3^31)^j); (3) convert to little-endian bytes; (4) read the first 2 bytes as uint16 for the length; (5) slice raw[2:2+length] and decode as UTF-8."
      }
    },
    {
      "@type": "Question",
      "name": "Where can I find the D3HFERP solver script?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The full solver is at github.com/Abdelkad3r/D3CTF-2026/tree/master/crypto/d3hferp as solve.py. It parses the public key with correct off-diagonal doubling, writes msolve input files for each of the 7 blocks, calls msolve as a subprocess, parses the degree-1 output, reconstructs and verifies the plaintext, and prints the flag. Run with python3 solve.py after brew install msolve."
      }
    }
  ]
}
</script>
