---
title: "GPN CTF 2026 — Easy-DSA: UUID3 MD5 Collision → ECDSA Nonce Reuse"
slug: "gpn-ctf-2026-easy-dsa"
description: "GPN CTF 2026 Crypto: uuid3 is MD5 with a constant prefix. Fastcoll generates colliding messages, ECDSA reuses the same nonce on P-521, key recovery and forge in one round."
date: 2026-06-07T18:15:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "easy-dsa"
  - "ecdsa nonce reuse"
  - "p-521 curve"
  - "fastcoll md5 collision"
  - "uuid3 md5"
  - "rfc 6979"
  - "marc stevens fastcoll"
  - "sha256 nonce derivation"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf easy-dsa writeup"
  - "ecdsa nonce reuse ctf"
  - "fastcoll md5 identical prefix collision"
  - "uuid3 md5 ctf"
  - "p-521 nonce reuse key recovery"
  - "rfc 6979 deterministic ecdsa"
  - "ecdsa sign ambiguity flip"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-easy-dsa.png"
  alt: "GPN CTF 2026 Easy-DSA writeup — UUID3 MD5 collision to force ECDSA nonce reuse on P-521 and recover the private key"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Medium" os="Crypto — ECDSA on P-521, deterministic nonce, MD5 collision" skills="recognising uuid3 as MD5(ns || name), generating identical-prefix MD5 collisions with Marc Stevens' fastcoll, recovering the nonce from two signatures with the same r, sign-flip check against the published public key, forging fresh signatures with the recovered private key" >}}

Welcome to a **CyberSecurity Elite** crypto writeup on **GPN CTF 2026 — Easy-DSA**, a classic cryptographic-engineering blunder dressed up in a Mongolian-barbecue narrative. The server signs arbitrary recipes with ECDSA on P-521. The "secure" nonce is derived through `uuid3`, which is **MD5** under the hood. Marc Stevens' `fastcoll` generates two messages that MD5-collide under the namespace prefix, forcing the ECDSA nonce to repeat. Standard nonce-reuse algebra recovers the private key in one round. Forge a fresh signature, claim the flag:

```
GPNCTF{m4yb3_w3_sh0uld_us3_RFC_6979_n3xt_t1m3}
```

The flag spells the lesson. This is the standalone deep-dive on `crypto/easy-dsa` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full source at [`crypto/easy-dsa`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/crypto/easy-dsa).

## Where the security falls over

The server's nonce derivation:

```python
secure_namespace = UUID(bytes=b"kitchenexplosion")

def secure_random(sk, message):
    key_id = uuid3(secure_namespace, sk.export_key(format="PEM")).bytes
    msg_id = uuid3(secure_namespace, message).bytes
    return sha256(key_id + msg_id).digest()[...] % (n - 1) + 1
```

`uuid3(ns, name)` is just `MD5(ns.bytes ‖ name.encode())`, lightly tagged for RFC 4122. So `msg_id = MD5("kitchenexplosion" ‖ message)` (modulo a few fixed bits). If we find `M1 ≠ M2` with `MD5("kitchenexplosion" ‖ M1) == MD5("kitchenexplosion" ‖ M2)`, then `msg_id` matches for both, the SHA-256 input matches, and the ECDSA nonce `k` is reused across the two signatures.

The chain of trust collapses at the first hash. MD5 collisions have been efficiently generatable since Wang et al. (2004). Marc Stevens' `fastcoll` produces identical-prefix collisions in seconds on a laptop. None of the SHA-256 wrapping, namespace tagging, or modular reduction past that point matters — the SHA-256 input is determined entirely by the MD5 output.

## Building the collision

```
$ fastcoll -p prefix.bin -o m1.bin m2.bin       # prefix = "kitchenexplosion"
$ tail -c +17 m1.bin > msg1.bin                 # strip prefix
$ tail -c +17 m2.bin > msg2.bin
$ python -c "from hashlib import md5; \
    a=open('msg1.bin','rb').read(); b=open('msg2.bin','rb').read(); \
    print(md5(b'kitchenexplosion'+a).hexdigest() == md5(b'kitchenexplosion'+b).hexdigest())"
True
```

`msg1.bin` and `msg2.bin` differ in their interior bytes — fastcoll picks two near-collision blocks — but both produce the same `MD5("kitchenexplosion" ‖ ·)` digest, the same `uuid3.bytes`, the same SHA-256 input, the same ECDSA nonce `k`.

## Recovering the private key

ECDSA with reused nonce `k`:

```
s1 = k^-1 · (z1 + r·d)   mod n
s2 = k^-1 · (z2 + r·d)   mod n
```

Subtract:

```
s1 - s2 = k^-1 · (z1 - z2)   mod n
```

So:

```
k = (z1 - z2) · (s1 - s2)^-1 mod n
d = (s1·k - z1) · r^-1 mod n
```

`z_i` is `sha256(M_i)` (since `n` has 521 bits the masking `& ~(1 << 521)` is a no-op here). The arithmetic is standard 64-bit-ish modular inversion modulo the P-521 order.

After computing `d`, check it against the published public key by multiplying with the generator and comparing `Q.x`. If it doesn't match, flip the sign — the symmetric solution `(-k, -d)` corresponds to the negated nonce. This sign ambiguity is a well-known footgun in ECDSA nonce-reuse exploitation; the canonical writeups document it in the third sentence, and forgetting to check it costs you a wasted exploitation attempt before the second-pass verification.

## Forging

Pick any recipe the server hasn't already signed (e.g. `b"forged-recipe"`), choose a fresh random `kk`, compute the standard ECDSA signature with the recovered `d`, and hand `(rr, ss)` to the `flag please` flow.

## Run

```
$ python3 solve.py <host> <port>
> sign 1755...
s1: 0x...
s2: 0x...
> sign 2cd9...
s1: 0x...                 ← same r as previous: nonce reuse confirmed
s2: 0x...
*** nonce reuse confirmed: r matches ***
d matches the published public key ✓
Congratulations. Here is your flag: GPNCTF{m4yb3_w3_sh0uld_us3_RFC_6979_n3xt_t1m3}
```

The flag says it explicitly: **"maybe we should use RFC 6979 next time."** RFC 6979 specifies deterministic ECDSA, where the nonce is derived from `HMAC-DRBG(private_key ‖ message_hash)` — no random source, no hash-collision attack surface, no nonce-reuse possibility. It exists precisely so this bug stops being possible.

## Defender takeaway

- **Any nonce derivation that round-trips through MD5 is broken.** Fastcoll-style identical-prefix collisions are seconds of compute on commodity hardware. The 1996-era MD5 collision attacks are 30 years old. If you see `uuid3` (or any other MD5 wrapper) in a cryptographic context, treat it as a vulnerability finding.
- **Use RFC 6979 for ECDSA**, full stop. Modern crypto libraries (cryptography.io, BoringSSL, libsodium) ship deterministic ECDSA by default. If your code calls `secrets.randbits()` or similar for the nonce, audit it before shipping.
- **Sign-flip check is mandatory in nonce-reuse exploits.** The symmetric `(-k, -d)` solution is not a bug; it's a feature of the modular arithmetic. Multiply the recovered `d` by the generator and compare with the published public key before forging.
- **Function-typed "hash with namespace" wrappers (`uuid3`, `uuid5`) are not cryptographic primitives.** `uuid3` is MD5, `uuid5` is SHA-1. Neither is collision-resistant. Use them for ID generation; never for security-relevant binding.

## Frequently asked questions

### What is the bug in easy-dsa?

The ECDSA nonce derivation passes the message through `uuid3`, which is MD5 under the hood. Two messages that MD5-collide under the namespace prefix produce the same `uuid3.bytes`, the same SHA-256 input, and the same ECDSA nonce `k`. With `k` reused across two signatures, standard nonce-reuse algebra recovers the private key.

### How does fastcoll generate the colliding messages?

Marc Stevens' `fastcoll` is an implementation of Wang's identical-prefix MD5 collision attack. Given a chosen prefix, it generates two near-collision blocks that, when appended to the prefix, produce the same MD5 digest. The collision search takes a few seconds on a laptop. The two output messages differ in their interior bytes (fastcoll's two near-collision blocks) but produce identical MD5 hashes.

### How is the private key recovered from nonce reuse?

From `s1 = k^{-1}(z1 + rd) mod n` and `s2 = k^{-1}(z2 + rd) mod n`, subtracting gives `s1 - s2 = k^{-1}(z1 - z2)`. So `k = (z1 - z2)(s1 - s2)^{-1} mod n`. Then `d = (s1k - z1) r^{-1} mod n`. The arithmetic is modular inversion against the P-521 group order `n`.

### Why do you need to check sign ambiguity?

ECDSA has a symmetric solution: `(k, d)` and `(-k, -d)` produce the same `r` and the same set of valid signatures. The nonce-reuse recovery doesn't distinguish between them. After computing the recovered `d`, multiply with the generator `Q = d · G` and compare `Q.x` with the published public key. If it doesn't match, negate `d`; the symmetric solution corresponds to the negated nonce.

### Why does the flag mention RFC 6979?

RFC 6979 specifies deterministic ECDSA, deriving the nonce from `HMAC-DRBG(private_key, message_hash)`. There is no random source and no hash-collision attack surface. Modern crypto libraries ship deterministic ECDSA by default. The flag — *"maybe we should use RFC 6979 next time"* — names the exact mitigation.

### Could you use a non-MD5 collision?

The bug is specifically that `uuid3` is MD5. If the server used `uuid5` (SHA-1) you would need an SHA-1 collision (Stevens et al.'s `SHAttered`, 2017, takes ~110 GPU-years — feasible for nation-states, infeasible in a CTF time budget). If the server used a SHA-256 derivation, the attack would not work at all in any realistic compute budget.

### Where can I find the solver?

Full source code at [`crypto/easy-dsa/solve.py`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/crypto/easy-dsa). Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is the bug in easy-dsa?","acceptedAnswer": {"@type": "Answer","text": "The ECDSA nonce derivation passes the message through uuid3, which is MD5 under the hood. Two messages that MD5-collide under the namespace prefix produce the same uuid3.bytes, the same SHA-256 input, and the same ECDSA nonce k. With k reused across two signatures, standard nonce-reuse algebra recovers the private key."}},
    {"@type": "Question","name": "How does fastcoll generate the colliding messages?","acceptedAnswer": {"@type": "Answer","text": "Marc Stevens' fastcoll is an implementation of Wang's identical-prefix MD5 collision attack. Given a chosen prefix, it generates two near-collision blocks that produce the same MD5 digest. The search takes seconds on a laptop."}},
    {"@type": "Question","name": "How is the private key recovered from nonce reuse?","acceptedAnswer": {"@type": "Answer","text": "From s1 = k^-1(z1 + rd) and s2 = k^-1(z2 + rd) modulo n, subtracting gives s1 - s2 = k^-1(z1 - z2). So k = (z1 - z2)(s1 - s2)^-1 mod n. Then d = (s1·k - z1) · r^-1 mod n. Standard modular inversion against the P-521 group order."}},
    {"@type": "Question","name": "Why do you need to check sign ambiguity?","acceptedAnswer": {"@type": "Answer","text": "ECDSA has a symmetric solution: (k, d) and (-k, -d) produce the same r. The nonce-reuse recovery doesn't distinguish between them. Multiply recovered d with the generator and compare Q.x with the published public key. If it doesn't match, negate d."}},
    {"@type": "Question","name": "Why does the flag mention RFC 6979?","acceptedAnswer": {"@type": "Answer","text": "RFC 6979 specifies deterministic ECDSA, deriving the nonce from HMAC-DRBG(private_key, message_hash). There is no random source and no hash-collision attack surface. The flag — maybe we should use RFC 6979 next time — names the exact mitigation."}},
    {"@type": "Question","name": "Could you use a non-MD5 collision?","acceptedAnswer": {"@type": "Answer","text": "The bug is specifically that uuid3 is MD5. uuid5 is SHA-1; an SHA-1 collision (SHAttered, 2017) takes ~110 GPU-years — feasible for nation-states, infeasible in a CTF budget. A SHA-256 derivation would not be attackable in any realistic compute budget."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full source code at crypto/easy-dsa/solve.py in github.com/Abdelkad3r/gpn-ctf-2026. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
