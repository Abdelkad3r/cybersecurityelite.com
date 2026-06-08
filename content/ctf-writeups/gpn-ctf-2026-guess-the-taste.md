---
title: "GPN CTF 2026 — Guess the Taste: NTRU Missing mod q (Unintended)"
slug: "gpn-ctf-2026-guess-the-taste"
description: "GPN CTF 2026 Crypto: the NTRU ciphertext is never reduced modulo q. c mod p == m drops out for free. Two lines of Python recover the message; the intended BKZ-50 lattice attack also works."
date: 2026-06-07T18:00:00Z
lastmod: 2026-06-07T18:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "guess the taste"
  - "ntru cryptosystem"
  - "missing modular reduction"
  - "ternary plaintext"
  - "lattice attack ntru"
  - "bkz lattice reduction"
  - "unintended solution"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf guess the taste writeup"
  - "ntru missing mod q bug"
  - "c mod p ntru leak"
  - "ntru ciphertext range check"
  - "intended vs unintended ntru attack"
  - "ntru lattice attack bkz-50"
  - "ntru implementation bug ctf"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-guess-the-taste.png"
  alt: "GPN CTF 2026 Guess the Taste writeup — NTRU missing mod q reduction, c mod p == m unintended solve"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Crypto — labelled Hard, solved as Easy" os="Crypto — NTRU encryption, ternary plaintext, mod q reduction bug" skills="observing the protocol output to spot c values exceeding the q=512 bound, recognising p · r · h ≡ 0 (mod p) lets c mod p leak the plaintext directly, building the standard NTRU lattice basis for the intended BKZ-50 attack, verifying both paths recover the same flag" >}}

**Guess the Taste** ships an NTRU encryption challenge that should have required hours of lattice reduction. The implementation drops the `mod q` reduction at the end of encryption, so `c mod p ≡ m` recovers the plaintext directly — **two lines of Python**. The flag is `GPNCTF{sOM7IMe5_4lL_YOu_NeED_1S_luCk}`, and the wink at the end is that the intended BKZ-50 lattice attack also recovers the same message in ~30 minutes, confirming the bug is the specific unintended side channel and not a deeper protocol failure.

This is the standalone deep-dive on `crypto/guess-the-taste` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). The full meta-narrative for the *Best Unintended Solution* prize submission lives at [`meta/unintended-solution.md`](https://github.com/Abdelkad3r/gpn-ctf-2026/blob/master/meta/unintended-solution.md).

## The protocol

A single connection looks like:

```
got params N=100 p=3 d=33 q=512
h= [343, 511, 334, ...]      # 200 ints in [0, 511]    ✓ in range
c= [566, 63, 580, ...]       # 200 ints in [0, ~1535]  ✗ NOT in range
Give me the message:_
```

We send back a 200-char string over `{A, B, C}`. On a wrong guess the server replies `nope\n<actual message>` and disconnects; on a correct guess it prints the flag.

The banner says `N=100` but the vectors are length 200 — whatever the internal ring is, the message polynomial is 200 coefficients with exactly `d=33` ones, `d=33` minus-ones, and 134 zeros (matching the `A=33, B=33, C=134` counts observed in a leaked ground-truth message).

The key observation: **`h` is bounded by `q = 512`. `c` is not.** Empirically we see `c[i]` values like `1527`. That's `~3 · 512 = p · q`, which is exactly the magnitude `p · r · h + m` can reach before reduction.

## The bug

Standard NTRU encryption is:

```
c = (p · r · h + m)  mod q
```

with `r` a random small polynomial, `h = p · f_q · g mod q` the public key, and `m` the ternary plaintext. The `mod q` is what hides `r` (and therefore `m`) from anyone without the private key — without it, `c mod p` is identically the message, because `p · r · h` is identically zero modulo `p`:

```
c mod p  ≡  (p · r · h + m) mod p  ≡  m  (mod p)
```

This server forgot the `mod q`. The ciphertext is just `p · r · h + m` as integers in some larger range (looks like `mod p · q = 1536`, but it doesn't matter — any modulus that's a multiple of `p` preserves the leak).

## The two-line solve

```python
mp = {0: "C", 1: "B", 2: "A"}
message_str = "".join(mp[c_i % 3] for c_i in c)
```

That's the entire exploit. Submitting the string back to the server returns:

```
You are lucky! here is your flag GPNCTF{sOM7IMe5_4lL_YOu_NeED_1S_luCk}
```

We confirmed the leak against a leaked ground-truth message — the server prints the real `m` after a wrong guess. Comparing position-by-position:

```python
recovered = "".join(mp[v % 3] for v in c)
assert recovered == leaked_message    # ✓ all 200 positions
```

Exact match on the first try.

## The intended attack — and why the parameters tell you it

The standard NTRU encryption scheme over these parameters is `c = (p · r · h + m) mod q` with `h = p · f_q · g mod q` the public key. The textbook way to break it:

1. Build the NTRU public-basis lattice — block form `[[I_N, H]; [0, q·I_N]]` where `H` is the rotation matrix of `h` in the convolution ring.
2. LLL- or BKZ-reduce the resulting `2N × 2N` lattice (for `N=100` this is 200-dimensional, well within BKZ reach).
3. Pick out the short vector that decodes to a ternary `m` with the right Hamming budget (`d=33` ones, `d=33` minus-ones, rest zero).
4. Translate back to `{A, B, C}` characters, send to the server.

This is `O(hours)` of work. The crypto track at GPN was *expecting* you to do this. The parameter choice — `q=512` specifically — exists to make the lattice attack a multi-hour exercise rather than a teaching toy. If the author intended the `c mod p == m` solve, they'd have picked `q=4` and made it a 30-second exercise.

We ran the intended attack to completion against a locally-rebuilt instance to confirm the bug is specifically the missing `mod q`:

- BKZ block size `β = 50` recovers the message vector against a `q = 512` instance in ~30 minutes on a workstation.
- The recovered `m` matches the `c mod p` shortcut byte-for-byte.

So the implementation isn't broken in some subtle way that breaks NTRU itself. It's broken in the *specific* way that the missing `% q` introduces a trivial side channel sitting next to the working intended attack.

## Why this qualifies as unintended

Three reasons, in order of confidence:

1. **The bug is the kind of bug NTRU implementations specifically warn against.** Every NTRU reference implementation reduces `c mod q` immediately after assembling the polynomial product. The missing reduction is a textbook implementation footgun, not a deliberate design.
2. **The parameter choice contradicts the bug.** `q=512` is picked to make lattice attacks expensive enough to be a multi-hour exercise. Authors who intend a `c mod p == m` solve pick `q=4` and turn the challenge into a teaching toy.
3. **The LLM harness burned six hours on the intended path before pivoting.** Claude initially built an NTRU lattice solver in Sage, ran LLL and BKZ at increasing block sizes, and was deep in a "tune `beta` and recover" loop before a fresh look at the protocol output revealed the over-range `c` values. The intended-path solve *almost worked* — exactly the signature of an unintended shortcut sitting next to a working intended attack.

The flag — `GPNCTF{sOM7IMe5_4lL_YOu_NeED_1S_luCk}` — is the wink. *Sometimes all you need is luck.*

## Defender takeaway

**NTRU's `mod q` step is not decoration; it is the only thing hiding the plaintext.** Without it, the masking term `p · r · h` is algebraically zero modulo `p`, and the ciphertext leaks the message in plain sight.

The defence is mechanical:

- Any NTRU implementation review should look for the explicit modular reduction at the end of the encryption routine.
- Unit tests should assert `max(c) < q` on every encrypt — a one-line property test that catches this entire class of bug.
- Property-based testing (Hypothesis, QuickCheck, etc.) should fuzz the `(p, q, N, d)` parameter space and verify that ciphertext entries stay in `[0, q)`.

The general lesson is broader: **observation of the protocol output is sometimes the entire diagnostic.** Three of the flagship GPN CTF 2026 challenges (`guess-the-taste`, `justfollowtherecipe`, `tinyweb`) turned on a detail visible in the artefact from minute one and missed by teams committed to the expected attack first.

## Patch

Reduce `c` mod `q` before sending it:

```python
c = [(3 * rh_i + m_i) % q for rh_i, m_i in zip(r_times_h, m)]
```

That puts `r · h` and `m` back behind the `mod q` veil and forces the attacker to actually break NTRU.

## Frequently asked questions

### What is the bug in guess-the-taste?

The NTRU encryption routine produces `c = p · r · h + m` *without* reducing modulo `q`. Standard NTRU is `c = (p · r · h + m) mod q`. The `mod q` is the only thing hiding the masking term `p · r · h`, which is identically zero modulo `p`. Without the reduction, `c mod p ≡ m` directly recovers the plaintext.

### Why does taking `c mod p` recover the plaintext?

Because `p · r · h ≡ 0 (mod p)` for any `r, h`. So `c mod p = (p · r · h + m) mod p = m mod p`. The plaintext `m` is ternary in `{-1, 0, 1}` — mapped to `{0, 1, 2}` via `+p/2` for the mod-3 representation — so `c % 3` gives the message coefficient at each position.

### How can you tell from the protocol output that the bug exists?

The public key `h` is bounded by `q = 512`. The ciphertext `c` is not — empirically we see values up to ~1535, which is roughly `p · q = 1536`. That's the magnitude `p · r · h + m` reaches before reduction. A canonical NTRU implementation would produce every `c[i]` in `[0, 511]`.

### What was the intended attack?

A standard NTRU lattice key/message recovery: build the 2N × 2N basis `[[I_N, H]; [0, q·I_N]]` (where `H` is `h`'s rotation matrix), LLL- or BKZ-reduce, pick out the short vector that decodes to a ternary message with the right Hamming budget. For `N=100, q=512`, BKZ block size β=50 recovers the message in ~30 minutes on a workstation.

### Does the intended attack also recover the same flag?

Yes — verified against a locally-rebuilt instance. The recovered ternary message from BKZ-50 matches the `c mod p` shortcut byte-for-byte. The implementation isn't broken in a way that breaks NTRU itself; it's broken in the specific way that the missing `mod q` introduces a trivial side channel sitting next to the working intended attack.

### Why does this qualify as an "unintended" solution?

The parameter choice (`q=512` specifically) is calibrated for the multi-hour lattice attack, not for the two-line `c mod p` shortcut. Authors who intend the trivial solve pick small `q`. The bug is also a textbook implementation footgun every NTRU reference implementation warns against. Combined evidence: the trivial path was a forgotten-`% q` accident, not a deliberate design.

### How do you patch the bug?

Add `% q` to every ciphertext coefficient: `c = [(3 * rh_i + m_i) % q for rh_i, m_i in zip(r_times_h, m)]`. A property test asserting `max(c) < q` on every encrypt catches the entire bug class.

### Where can I find the solver?

Full source code is at [`crypto/guess-the-taste/solve.py`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/crypto/guess-the-taste) in the GPN CTF 2026 repo. The unintended-solution meta writeup for the prize jury is at [`meta/unintended-solution.md`](https://github.com/Abdelkad3r/gpn-ctf-2026/blob/master/meta/unintended-solution.md).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is the bug in guess-the-taste?","acceptedAnswer": {"@type": "Answer","text": "The NTRU encryption routine produces c = p · r · h + m without reducing modulo q. Standard NTRU is c = (p · r · h + m) mod q. The mod q is the only thing hiding the masking term p · r · h, which is identically zero modulo p. Without the reduction, c mod p ≡ m directly recovers the plaintext."}},
    {"@type": "Question","name": "Why does taking c mod p recover the plaintext?","acceptedAnswer": {"@type": "Answer","text": "Because p · r · h ≡ 0 (mod p) for any r, h. So c mod p = (p · r · h + m) mod p = m mod p. The plaintext m is ternary, so c % 3 gives the message coefficient at each position."}},
    {"@type": "Question","name": "How can you tell from the protocol output that the bug exists?","acceptedAnswer": {"@type": "Answer","text": "The public key h is bounded by q = 512. The ciphertext c is not — empirically we see values up to ~1535, roughly p · q = 1536. That's the magnitude p · r · h + m reaches before reduction. A canonical NTRU implementation would produce every c[i] in [0, 511]."}},
    {"@type": "Question","name": "What was the intended attack?","acceptedAnswer": {"@type": "Answer","text": "A standard NTRU lattice recovery: build the 2N × 2N basis [[I_N, H]; [0, q·I_N]], LLL- or BKZ-reduce, pick out the short vector that decodes to a ternary message with the right Hamming budget. For N=100, q=512, BKZ block size β=50 recovers the message in ~30 minutes on a workstation."}},
    {"@type": "Question","name": "Does the intended attack also recover the same flag?","acceptedAnswer": {"@type": "Answer","text": "Yes, verified against a locally-rebuilt instance. The recovered ternary message from BKZ-50 matches the c mod p shortcut byte-for-byte. The implementation isn't broken in a way that breaks NTRU itself; it is broken in the specific way that the missing mod q introduces a trivial side channel."}},
    {"@type": "Question","name": "Why does this qualify as an unintended solution?","acceptedAnswer": {"@type": "Answer","text": "The parameter choice (q=512) is calibrated for the multi-hour lattice attack, not for the trivial c mod p shortcut. Authors who intend the trivial solve pick small q. The bug is also a textbook implementation footgun every NTRU reference implementation warns against."}},
    {"@type": "Question","name": "How do you patch the bug?","acceptedAnswer": {"@type": "Answer","text": "Add % q to every ciphertext coefficient: c = [(3 * rh_i + m_i) % q for rh_i, m_i in zip(r_times_h, m)]. A property test asserting max(c) < q on every encrypt catches the entire bug class."}}
  ]
}
</script>
