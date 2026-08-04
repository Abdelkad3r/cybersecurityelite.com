---
title: "GPN CTF 2026 — Justfollowtherecipe: AVX2 Miscompile + SIS Lattice"
slug: "gpn-ctf-2026-justfollowtherecipe"
description: "GPN CTF 2026 Crypto: gcc -O3 -mavx2 swaps lanes 1↔2 in mat_mul. Repair the leak, run Kannan-embedding BKZ-58 against a 165-dim SIS lattice — flag in 45 seconds."
date: 2026-06-07T17:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "justfollowtherecipe"
  - "crypto ctf"
  - "compiler miscompilation"
  - "gcc avx2"
  - "vpermd lane swap"
  - "sis lattice"
  - "kannan embedding"
  - "fpylll bkz"
  - "usvp"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf 2026 justfollowtherecipe"
  - "justfollowtherecipe writeup"
  - "gcc -O3 -mavx2 miscompile mat_mul"
  - "vpermd lane swap ctf"
  - "sis lattice ctf writeup"
  - "kannan embedding lattice attack"
  - "fpylll bkz default.json strategies"
  - "ntru sis kannan ctf"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-justfollowtherecipe.png"
  alt: "GPN CTF 2026 Justfollowtherecipe writeup — gcc -O3 -mavx2 lane swap and Kannan-embedding BKZ-58 SIS lattice attack"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Hard" os="Crypto — SIS hash, Kannan embedding, BKZ lattice reduction" skills="reading AVX2 disassembly to identify vpermd lane interchange, repairing the per-batch lane swap in oracle output, building a q-ary kernel lattice with Kannan embedding, fpylll BKZ-58 with default.json preprocessing+pruning strategies, fpylll heartbeat to keep the SSL proxy alive" >}}

In this **CyberSecurity Elite** crypto writeup, we solve **Justfollowtherecipe**, the GPN CTF 2026 challenge that asks a textbook **SIS** (Short Integer Solution) hash recovery question — except the Linux binary's `mat_mul` is **miscompiled**. `gcc -O3 -funroll-loops -mavx2` swaps AVX2 lanes 1 and 2 in every 4-wide block of the inner-product loop, so every column of the public matrix the oracle hands back is permuted. Repair the swap, run a Kannan embedding against the q-ary kernel lattice, finish with **BKZ-58** under fplll's `default.json` strategies in 45 seconds. The flag — `GPNCTF{coMP1L3rS_aRe_Y0UR_fr1End_7HEY_w0ULd_never}` — names the lesson.

This writeup is the standalone deep-dive on `crypto/justfollowtherecipe` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full solver code lives at [`crypto/justfollowtherecipe`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/crypto/justfollowtherecipe) in the source repository.

## Parameters and protocol

The challenge spec is a small SIS instance:

| Parameter   | Value     |
|-------------|-----------|
| `N` (rows)  | 64        |
| `M` (cols)  | 164       |
| `q`         | 12289     |
| Secret      | `{0..9}^M` |

The server stores `flag_hash = A · secret mod q` for a random `A ∈ Z_q^{N×M}` and a uniformly chosen `secret ∈ {0,…,9}^M`. The protocol exposes three operations:

```
0) Check your work       — submit a guess of secret, win if exact
1) Hash a single vector  — read v, print A·v mod q
2) Hash multiple vectors — same, up to 100 vectors per call
3) Exit
```

Submitting the wrong secret prints the real `secret_vec` and exits — useless across connections (each session re-randomises everything), but priceless for ground-truth verification against a locally-rebuilt binary.

The intended path is mathematically standard: leak `A` column-by-column via the oracle, then solve `A · x = flag_hash mod q` for short `x` using a uSVP lattice attack. The challenge's trick is in the *leaking* half.

## The compiler bug

`mat_mul` is a textbook 4-wide unrolled inner-product loop:

```c
for (blk = 0; blk < (int)MM - 4; blk += 4) {
    for (int i = 0; i < NN; i++) {
        result[blk + 0] += src[i] * (uint64_t)BB[i*MM + blk + 0];
        result[blk + 1] += src[i] * (uint64_t)BB[i*MM + blk + 1];
        result[blk + 2] += src[i] * (uint64_t)BB[i*MM + blk + 2];
        result[blk + 3] += src[i] * (uint64_t)BB[i*MM + blk + 3];
    }
}
for (; blk < MM; blk++) for (int i = 0; i < NN; i++)
    result[blk] += src[i] * BB[i*MM + blk];
```

Under `gcc -O3 -funroll-loops -mavx2 -flra-remat -fsched-spec …` (the Dockerfile's exact flag set), the outer loop vectorises with `vpmuludq` over four 64-bit lanes packed into `ymm0..15`, then stores four 64-bit results per outer iteration. Reading the disassembly at `mat_mul @ 0x404830`:

- The 64-bit accumulator `ymm8` is laid out with lane `i` corresponding to result position `blk + i`.
- In the broadcast/permute step `vpermd ymm6, ymm13, ymm7` plus the high/low load pattern via `vinserti128`, the compiler ends up reading `BB[blk+0], BB[blk+2], BB[blk+1], BB[blk+3]` into lanes 0..3. **Lanes 1 and 2 are interchanged.**
- The `vmovdqu ymmword ptr [r8 - 0x20], ymm8` store dumps the lanes back into `result[blk+0..3]` in lane order — so `result[blk+1]` is written with what should have been `result[blk+2]` and vice versa.

The scalar tail loop (the `for (; blk < MM; blk++)` portion) is left untouched, so positions `blk = MM - (MM mod 4)` through `MM - 1` are correct. For `MM = 64` the bug swaps result indices `(1, 2), (5, 6), …, (57, 58)` and leaves `(60, 61, 62, 63)` alone — **15 swaps per result vector**, with the last 4 positions correct.

`mat_mul_naive` is a straight scalar loop and is **not** miscompiled, so the `flag_hash = A · secret_vec` line in `setup_challenge` is correct. The server has the real `A` and the real `flag_hash`. Only what we *read back* from `hash_single` / `multi_hash` is permuted.

## Two query paths, two different corruptions

| call                            | mat_mul result axis                          | what the bug does to us                                                  |
|---------------------------------|----------------------------------------------|--------------------------------------------------------------------------|
| `hash_single`: `mat_mul(res, A, v)` | result is the **rows** of `A` (length 64) | each returned 64-vector has its entries `(1,2),(5,6),…,(57,58)` swapped |
| `multi_hash`: `mat_mul(acc, B_t, a_col)` | result is the **batch index** (length `n`) | for `n = 64` the returned `hashes[1]` and `hashes[2]` are swapped — we get `A · msgs[2]` where we asked for `A · msgs[1]` |

We attack `multi_hash` because the corruption is in the **batch** index, not the entry index. So each returned 64-vector is still a full untouched column of `A` — we just need to relabel which column it is.

The corrective swap is:

1. Use `multi_hash` with **n = 64 exactly** (pad the last partial batch with zero vectors). For `n < 64` `results[i]` is truncated; for `n > 64` it wraps into `msgs[i+1]`. `n = 64` is the only clean value.
2. After each batch, swap back the AVX2 lane interchange: swap `hashes[4k+1]` ↔ `hashes[4k+2]` for `k = 0 .. (n-1)//4 - 1` (all blocks **except** the tail block).
3. With `n = 64`, that's swaps `(1,2), (5,6), …, (57,58)` — 15 pairs per batch — and three batches reconstruct `A` exactly.

`mat_mul_naive` was never used for queries (only at startup), so once `A` is correct the lattice attack proceeds against the real `flag_hash`.

## Lattice setup — q-ary kernel + Kannan embedding

Standard primal uSVP on the q-ary kernel lattice plus a Kannan embedding:

1. Split `A = [A1 | A2]` where `A1 ∈ Z_q^{N×N}` is invertible w.o.p.
2. Particular solution `s0 = [A1^{-1} t' | 0]` where `t' = flag_hash − 5·A·1`.
3. Kernel basis (M × M) rows: `(−A1^{-1}·A2_j, e_j)` and `(q·e_j, 0)`.
4. Centre to `t = secret − 5·1` so `t ∈ [−5, 4]^M` with `‖t‖² ≈ M · 8.5`.
5. Kannan: extend to `(M+1) × (M+1)` with last row `(s0_centered, K=1)`.

The resulting parameters:

| quantity                | value             |
|-------------------------|-------------------|
| dimension `d`           | 165               |
| determinant             | `q^N = 12289^64`  |
| `det^{1/d}`             | `≈ 38.7`          |
| `GH(L')`                | `≈ 120`           |
| target `‖(t, K)‖`       | `≈ 37`            |
| target / GH             | `≈ 0.31`          |

Textbook uSVP. But stock fpylll BKZ-40 *without* strategies grinds for minutes and lands at norm ~310 — *above* the GH bound, no flag. Loading fplll's `default.json` preprocessing+pruning strategies is the difference between "infeasible" and "45 seconds." Homebrew installs them at `/usr/local/Cellar/fplll/<ver>/share/fplll/strategies/default.json`.

A 20-second heartbeat thread keeps the kitctf SSL proxy from idling out during BKZ — without it the proxy hangs up around minute 3 of the BKZ-55 stage.

## Solver run

```
$ python3 solve.py braised-crab-marinated-in-braised-noodles-kwb4.gpn24.ctf.kitctf.de 443
[ 17.4s] flag_hash[:5] = [504, 10242, 12264, 8305, 8985]
[ 17.4s] Querying A...
[ 17.8s]   batch 0..63: got 64 hashes (real=64)
[ 18.1s]   batch 64..127: got 64 hashes (real=64)
[ 18.4s]   batch 128..163: got 64 hashes (real=36)
[ 18.4s] A recovered shape=(64, 164)
[ 22.4s] LLL done; Budget remaining: 172.6s
[ 22.4s] BKZ-30 ml=2 …  0.9s
[ 23.3s] BKZ-40 ml=2 …  1.5s
[ 24.8s] BKZ-50 ml=2 …  8.7s
[ 33.5s] BKZ-55 ml=2 …  22.2s
[ 55.7s] BKZ-58 ml=2 …  35.4s
[ 91.1s] BKZ-58 found!
[ 91.1s] verify: True; s[:10]=[0, 5, 1, 8, 8, 4, 7, 2, 0, 0]
Impossible the recipe was a lie.
GPNCTF{coMP1L3rS_aRe_Y0UR_fr1End_7HEY_w0ULd_never}
```

## Why this is the prize-overall writeup

The combination of bugs is what makes this challenge a top submission:

- The **AVX2 lane swap** is the kind of compiler miscompilation that production crypto libraries (libsodium, BoringSSL) defend against by maintaining a scalar reference implementation that can be differentially tested. The challenge built exactly that defensive structure into the source — `mat_mul_naive` is the unaffected reference, and it was used (at startup, for `flag_hash`) precisely to anchor the protocol's ground truth.
- The **SIS / Kannan-embedding** lattice attack is canonical uSVP, but tuning fpylll to actually find the short vector at `target/GH ≈ 0.31` is the unsung half. The default strategies file is what makes BKZ-58 land — without it BKZ-40 gets stuck at norm ~310 and never breaks through.

Two stacked bugs, one in the compiler and one in the math, both load-bearing. The reader-facing takeaway is: **assume your stack contains a compiler-shaped bug and structure code so you can find it.**

## Defender takeaway

- **Any SIMD / auto-vectorised cryptographic-shape code needs a scalar reference implementation it can be differentially tested against.** That's exactly the structure the challenge baked in (`mat_mul_naive` next to `mat_mul`) — and exactly the structure production crypto libraries already follow. If you're writing or reviewing AVX2/NEON intrinsic code, write the scalar version too and assert byte-for-byte equivalence in CI.
- **Read the disassembly when the source looks innocent.** The C source for `mat_mul` is correct. The bug is exclusively in `vpermd` lane assignment under specific gcc flag combinations. The only way to catch it from source is to know about it; the way to catch it from disassembly is to read the disassembly.
- **fpylll BKZ tuning is a real engineering surface.** The default block-size choice, pruning strategy, and preprocessing parameters can move a problem between "instantly solvable" and "infeasible" — for the same lattice. Bring `default.json` (or your tuned equivalent) on every BKZ engagement.

## Frequently asked questions

### What is the AVX2 lane swap in justfollowtherecipe?

`gcc -O3 -funroll-loops -mavx2` vectorises the 4-wide inner-product loop in `mat_mul` with `vpmuludq` and a `vpermd` broadcast/permute step that ends up loading `BB[blk+0], BB[blk+2], BB[blk+1], BB[blk+3]` into AVX2 lanes 0..3. The store writes lanes in order, so `result[blk+1]` and `result[blk+2]` are interchanged for every full block of 4 — for `MM = 64`, swaps are `(1,2), (5,6), …, (57,58)` and positions 60–63 are correct (scalar tail loop).

### Why does `mat_mul_naive` matter for the solve?

`mat_mul_naive` is a straight scalar loop and not miscompiled. It's called once at startup to compute `flag_hash = A · secret_vec`, so the server's stored hash is correct. The vectorised `mat_mul` is only used inside the oracle — meaning what we leak through `multi_hash` is permuted, but the target `flag_hash` we're trying to match is true. Repairing the per-batch lane swap recovers `A` exactly.

### Why attack `multi_hash` instead of `hash_single`?

For `hash_single`, the bug corrupts the *entry* index of each returned 64-vector. For `multi_hash` with `n = 64`, the bug corrupts the *batch* index — meaning each returned vector is still an untouched column of `A`, just mislabelled. Relabelling is a simple per-batch swap; entry-level corruption inside each column would need 15 corrections per column instead of one global pairing.

### How is the SIS lattice constructed for the Kannan embedding?

Split `A = [A1 | A2]` with `A1` invertible. Build the kernel basis with `(−A1^{-1}·A2_j, e_j)` and `(q·e_j, 0)` rows. Centre the secret to `t = secret − 5·1` so `t ∈ [−5, 4]^M`. Kannan-embed by appending a last row `(s0_centered, K=1)` where `K=1`. The resulting 165-dimensional lattice has `det^{1/d} ≈ 38.7`, `GH(L') ≈ 120`, target norm ≈ 37 — a target/GH ratio of ~0.31, well inside uSVP.

### Why does BKZ-58 work but BKZ-40 fail?

Stock fpylll BKZ-40 without the default strategies file lands at vector norm ~310 — above the GH bound. The default `default.json` strategies (preprocessing + extreme pruning radii) shift the effective root-Hermite factor enough that BKZ-55 to BKZ-58 reach a short enough vector. The cost is wall-clock: ~45 seconds total with strategies versus "stuck at norm 310 indefinitely" without.

### Why the heartbeat thread?

The kitctf challenge instance terminates idle SSL connections after ~60 seconds. BKZ-55 and BKZ-58 stages can take 20–40 seconds each, during which the solver isn't sending traffic. A 20-second heartbeat thread that writes a benign byte over the SSL channel keeps the proxy from dropping the connection mid-reduction.

### Where can I find the solver?

Full source code is at [`crypto/justfollowtherecipe/solve.py`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/crypto/justfollowtherecipe) in the GPN CTF 2026 repo. The master writeup with all 19 challenges is at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is the AVX2 lane swap in justfollowtherecipe?","acceptedAnswer": {"@type": "Answer","text": "gcc -O3 -funroll-loops -mavx2 vectorises the 4-wide inner-product loop in mat_mul with vpmuludq and a vpermd permute that loads BB[blk+0], BB[blk+2], BB[blk+1], BB[blk+3] into AVX2 lanes 0..3. The store writes lanes in order, so result[blk+1] and result[blk+2] are interchanged for every full block of 4. For MM = 64, swaps are (1,2), (5,6), …, (57,58); positions 60-63 are correct (scalar tail loop)."}},
    {"@type": "Question","name": "Why does mat_mul_naive matter for the solve?","acceptedAnswer": {"@type": "Answer","text": "mat_mul_naive is scalar and not miscompiled. It is called once at startup to compute flag_hash = A · secret_vec, so the server's stored hash is correct. The vectorised mat_mul is only used inside the oracle, so what we leak through multi_hash is permuted but the target flag_hash is true. Repairing the per-batch lane swap recovers A exactly."}},
    {"@type": "Question","name": "Why attack multi_hash instead of hash_single?","acceptedAnswer": {"@type": "Answer","text": "For hash_single the bug corrupts the entry index of each returned 64-vector. For multi_hash with n = 64 the bug corrupts the batch index, so each returned vector is still an untouched column of A — just mislabelled. Relabelling is one swap per batch, simpler than per-column entry fixes."}},
    {"@type": "Question","name": "How is the SIS lattice constructed for the Kannan embedding?","acceptedAnswer": {"@type": "Answer","text": "Split A = [A1 | A2] with A1 invertible. Build kernel basis rows (−A1^{-1}·A2_j, e_j) and (q·e_j, 0). Centre secret to t = secret − 5·1 so t ∈ [−5, 4]^M. Kannan-embed with a last row (s0_centered, K=1). The 165-dimensional lattice has det^{1/d} ≈ 38.7, GH(L') ≈ 120, target norm ≈ 37 — target/GH ratio of ~0.31."}},
    {"@type": "Question","name": "Why does BKZ-58 work but BKZ-40 fail?","acceptedAnswer": {"@type": "Answer","text": "Stock fpylll BKZ-40 without strategies lands at vector norm ~310, above the GH bound. fplll's default.json preprocessing+pruning strategies shift the effective root-Hermite factor enough for BKZ-55 to BKZ-58 to reach a short enough vector. Wall-clock ~45 seconds with strategies vs. stuck indefinitely without."}},
    {"@type": "Question","name": "Why the heartbeat thread?","acceptedAnswer": {"@type": "Answer","text": "The kitctf SSL proxy terminates idle connections after ~60s. BKZ stages take 20–40 seconds during which the solver is silent. A 20-second heartbeat writing a benign byte over SSL keeps the proxy from dropping the connection mid-reduction."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full source is at crypto/justfollowtherecipe/solve.py in github.com/Abdelkad3r/gpn-ctf-2026. The master writeup with all 19 challenges is at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
