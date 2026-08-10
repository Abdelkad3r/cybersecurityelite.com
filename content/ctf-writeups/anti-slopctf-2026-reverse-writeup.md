---
title: "Anti-Slop CTF 2026 Reverse Writeup: Audit Spiral + Parallax Cartridge"
slug: "anti-slopctf-2026-reverse-writeup"
description: "Step-by-step reverse writeups for Anti-Slop CTF 2026. Audit Spiral: quadratic ECDSA nonce. Parallax Cartridge: audit/runner split + SHA-256 length extension on the resume token."
date: 2026-06-22T18:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["Anti-Slop CTF 2026"]
tags:
  - "anti-slop ctf"
  - "anti-slopctf 2026"
  - "reverse engineering"
  - "ecdsa nonce attack"
  - "secp256k1"
  - "sha-256 length extension"
  - "merkle damgard"
  - "qar cartridge format"
  - "audit vs runtime split"
  - "linear system over group order"
keywords:
  - "anti-slop ctf 2026 reverse writeup"
  - "audit spiral writeup"
  - "parallax cartridge writeup"
  - "ecdsa quadratic nonce recovery"
  - "ecdsa polynomial nonce attack"
  - "secp256k1 private key from biased nonces"
  - "sha-256 length extension attack ctf"
  - "prefix mac length extension"
  - "qar5 cartridge format reverse"
  - "audit runtime parser split ctf"
  - "stripped go binary reverse ctf"
  - "ctf reverse step by step"
toc: true
cover:
  image: "/images/articles/anti-slopctf-2026-reverse-writeup.png"
  alt: "Anti-Slop CTF 2026 reverse writeup — Audit Spiral quadratic ECDSA nonce and Parallax Cartridge length-extension exploit"
---

**Anti-Slop CTF 2026**'s reverse engineering track featured two challenges: **Audit Spiral**, where a secp256k1 signing VM generates ECDSA nonces as a quadratic polynomial in the signing index (`k_i = c0 + c1·i + c2·i²`), recovered by solving a 4×4 linear system mod the group order with four signatures; and **Parallax Cartridge**, where a `quiet` record byte shifts the cartridge runner's final program index into a hidden dictionary bank the audit step never checks, combined with a `SHA256(secret || body)` prefix MAC on the resume token that is vulnerable to SHA-256 length extension. This is the second post in the Anti-Slop CTF 2026 series; the [web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/) covered the two challenges that lived in HTTP parsers.

Both challenges reward reading the bytes. Neither falls to a tool. Source artefacts, the stripped ELF, the Go binary, the starter cartridge, and full Python solvers all live at [Abdelkad3r/Anti-SlopCTF-2026/reverse](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/reverse).

## The two reverse challenges

| Challenge | Bug class | Points | Flag |
|---|---|---|---|
| Audit Spiral | ECDSA nonce is `c0 + c1·i + c2·i²` — quadratic in the signing index, solvable as a linear system over `n` | 500 | `slopped{quadratic_capsules_unlock_the_attestor}` |
| Parallax Cartridge | Cartridge runner shifts the final opcode into a hidden dictionary bank that audit doesn't see; resume-token MAC is a prefix MAC vulnerable to length extension | 355 | `slopped{quiet_tracks_hide_in_hash_padded_resume_tapes}` |

If you only have time for one, Audit Spiral teaches the more useful underlying lesson: biased ECDSA nonces are not a single class of bug. The textbook attacks (`k` reused, `k` with a fixed prefix or suffix, `k` linear in `i`) are well-known. Polynomial bias is the same shape one degree up. Anywhere you control the index and the message digest, you can lift the polynomial structure into a linear system.

## Methodology — read the wire, then read the bytes

Two principles carried both solves.

For Audit Spiral, the wire interface looked tiny and the obvious moves (load capsule, sign, read signature) gave nothing useful from a single observation. The breakthrough was repeating the same signing operation many times and looking at the *sequence* of signatures, not any individual one. ECDSA hides the nonce inside the signature; the only way to see nonce structure is to compare across signatures.

For Parallax Cartridge, the BOOT/STEP protocol was a bait. The intended split between "audit" and "execute", with one lane certified and another lane running, is exactly the kind of design that invites parser-differential bugs. Anywhere a single byte buffer is parsed twice by two different consumers, the two consumers will eventually disagree about what it means. The cartridge format gave you the differential; the resume token gave you the authenticator to forge once you knew what you wanted to swap.

Detailed walkthroughs below.

## Audit Spiral

### The handout

A 27 KiB Linux x86-64 PIE ELF named `auditvm`. Stripped. Build-ID `2a77f8573617426c5a53ba63e20db266322f7b34`. The binary is a VM runner; the remote service wraps the same VM with a secp256k1 signing interface, so the wire protocol carries everything the solve needs and the local binary mostly serves to confirm the VM's behaviour.

### The wire interface

A clean `nc` session shows four commands:

```
load <capsulehex>
sign
target
admin <r> <s>
```

`load` accepts a hex blob of bytecode for the inner VM. `sign` runs the loaded capsule, takes its 16-byte output, hashes it, and returns an ECDSA signature over the digest using a fixed service private key on secp256k1. `target` returns a fresh challenge digest the server wants signed. `admin <r> <s>` accepts a signature over that target digest and, if valid, returns the flag.

The legitimate flow has no admin signing oracle exposed. The server signs whatever the capsule outputs, not the target digest itself. The intended attack therefore has to recover the service private key from signatures over attacker-controlled but harmless data, then sign the target digest locally.

### Step 1 — Get a stable input to sign

If the capsule's output varies between calls (and small VMs love to mix in cycle counters, timestamps, or RNG), the digest changes every signature and you can't isolate nonce structure from message structure. The first task is therefore to write a capsule that emits exactly the same 16 bytes on every run.

The simplest version is a capsule that emits sixteen zero bytes. The exact opcodes depend on the VM (the README and the inner ELF give the encoding; I won't reproduce it byte-for-byte here, but the practical recipe is "any constant-output capsule of length 16"). The capsule has to be *at least* 16 bytes of output; shorter capsules trip a Python `ValueError` in the wrapper and the signing command fails with a stack trace. That's actually useful. The error is the server telling you exactly which length boundary matters.

With a constant-output capsule loaded, repeated `sign` commands return signatures over the same digest `z`. Now every variation between signatures is variation in `(k, r, s)`. Collect a few hundred of them.

### Step 2 — Spot that the nonce isn't random

Each signature gives you `(r_i, s_i)` for the same `z`. With ECDSA, the relation is:

```
s = k^{-1} · (z + r · d) mod n
```

If `k` were truly random and `d` were fixed, `r` would be a uniformly-distributed integer modulo `n`. With dozens of signatures over the same `z`, you can plot or histogram `r` and look for bias. There's a faster check. Pick any pair of signatures and compute the would-be nonce as if it were reused:

```
k_candidate = (z + r_1 · d) · s_1^{-1}
```

Even though you don't know `d`, the relation between `k_i` and `k_j` across pairs is structured if the nonces share a polynomial generator. Concretely: if `k_i = c0 + c1·i + c2·i²` for some unknown coefficients, then for any fixed unknown `d`,

```
s_i · (c0 + c1·i + c2·i²) ≡ z + r_i · d (mod n)
```

That is **linear in the four unknowns** `(d, c0, c1, c2)`.

### Step 3 — Build the linear system

Take four signatures. Rewrite each ECDSA equation as

```
s_i · c0 + (i · s_i) · c1 + (i² · s_i) · c2 − r_i · d ≡ z (mod n)
```

Stack the four equations into a 4×4 matrix `A` with columns `(s_i, i·s_i, i²·s_i, −r_i)` and right-hand side `(z, z, z, z)`. Invert mod `n` (the secp256k1 group order), multiply, and you get the four unknowns.

I take five signatures rather than four and check that the fifth equation is consistent with the recovered unknowns. That extra equation kills the entire class of "I picked four samples whose matrix happened to be singular mod `n`" failures, and it acts as a sanity check that the polynomial degree was actually two and not three.

A minimal solver in Python:

```python
from sage.all import Matrix, GF, vector  # or use a pure-Python fallback

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Collected per-index: r_i, s_i, plus the constant digest z.
signatures = [...]  # list of (i, r_i, s_i) tuples
z = ...

F = GF(N)
rows = []
rhs = []
for i, r, s in signatures[:4]:
    rows.append([F(s), F(i * s), F((i*i) * s), F(-r)])
    rhs.append(F(z))
A = Matrix(F, rows)
b = vector(F, rhs)
c0, c1, c2, d = A.solve_right(b)
print("private d =", hex(int(d)))
```

### Step 4 — Verify the key against the service public point

The recovered `d` should match the service's published public key. Multiply `d` by the secp256k1 generator and compare:

```python
Q = scalar_mult(int(d), G)
print(f"Qx={Q[0]:064x} Qy={Q[1]:064x}")
```

The compressed/uncompressed point should match whatever the service banners or whatever you can extract via a static read of the ELF. For this challenge, the recovered key was:

```
d = 0xa8118ccf6054821700c20bf08bd0b4cbe9bc4e4c140a619d86c0536692f417f
```

producing the public point:

```
04
  beca28a00a6eaac538fc75af63b68e07aa530f7fe93d534eb15d1a5a4a38e638
  0ba57795d2dfe2f7c86ec2b2ecd5e3a09e69db0b5f8bfdc26d331331f3f4e251
```

That matched the service's advertised public key, confirming the recovery was correct.

### Step 5 — Sign the target digest and submit

The rest is mechanical. Issue `target`, capture the 64-character hex digest from the response, sign locally using any deterministic ECDSA implementation (RFC 6979 is fine; nothing here requires a particular `k` since you're now the legitimate signer), then send `admin <r> <s>`.

```python
def sign_digest(digest):
    z = int.from_bytes(digest, "big") % N
    k = rfc6979_k(PRIVATE_KEY, digest, N)
    r = scalar_mult(k, G)[0] % N
    s = (pow(k, -1, N) * (z + r * PRIVATE_KEY)) % N
    return r, s
```

The server responds:

```
slopped{quadratic_capsules_unlock_the_attestor}
```

The full client at `reverse/audit-spiral/solve.py` in the repo automates target retrieval, signing, and submission.

### Why Audit Spiral works

The fix for Audit Spiral is the same fix every modern ECDSA implementation already ships: derive `k` deterministically from `(private_key, message)` via HMAC-DRBG, per RFC 6979. The challenge's nonce was deterministic in a different way, deterministic in the signing index, which leaks every coefficient of the generating polynomial as soon as the attacker controls enough samples.

The underlying lesson is broader than CTFs. Anywhere ECDSA nonces are derived from a counter, a timestamp, a per-session RNG seed, or anything that's a polynomial in observable state, the linear-system attack collapses the private key. The bug surface is much wider than "reused `k`": linear, quadratic, or higher-order polynomial bias all reduce to a linear system as long as the polynomial degree fits inside the sample budget.

For defenders, the practical check on any ECDSA implementation is: "where does `k` come from, and can an attacker influence its derivation?" If the answer involves a counter, an index, or any per-call state that's not strictly secret, the implementation is suspect. RFC 6979 closes the entire family.

## Parallax Cartridge

### The handout

Three artefacts. A stripped static Go service binary named `parallax-cartridge` (4.6 MB or so, stripped, BuildID inferable from `.note.go.buildid`), a `starter.qar` cartridge file the protocol expects, and the original zip the organisers shipped. The Go binary is the actual server; the protocol it speaks accepts two commands:

```
BOOT <base64-qar>
STEP <base64-qar> <base64-token>
```

`BOOT` audits a cartridge and, if the audit passes, returns a base64-encoded resume token. `STEP` accepts a cartridge plus that token and continues execution. The intended split is what the README spells out: audit certifies one view of the cartridge, the runner uses another. Find the gap.

### Step 1 — Reverse the cartridge format

The starter cartridge begins with `QAR5`. The next bytes are TLV-shaped records, each tagged `LREC` with a one-byte name length, a two-byte little-endian data length, the name, and the data. The starter's record layout:

```
0x004 LREC dict  len=256 data=0x00f
0x10f LREC prog  len=5   data=0x11a
0x11f LREC mesh  len=32  data=0x12a
0x14a LREC quiet len=8   data=0x156
0x15e LREC note  len=20  data=0x169
0x17d QDIR ...
```

`dict` is a 256-byte table of 64 four-byte VM cells. `prog` is a 5-byte packed-index record listing the VM's program. `quiet` is an 8-byte side-channel record. `mesh` and `note` are dressing.

The `prog` record uses a custom Gray-coded packed-index encoding. The first byte is the count of indices. The remaining bytes are 5 bits per index packed little-endian, with each 5-bit field interpreted through an `ungray()` step. Decoding the starter `prog`:

```python
def ungray(value):
    out = value
    while value:
        value >>= 1
        out ^= value
    return out

def unpack_indices(blob):
    count = blob[0]
    packed = int.from_bytes(blob[1:], "little")
    return [ungray((packed >> (5 * i)) & 0x1F) for i in range(count)]
```

The starter program is `[0, 1, 2, 3, 4]`. Cell `4` of the dictionary is the visible final opcode that audit checks.

### Step 2 — Find the quiet-bank shift

A 64-cell dictionary with a program that only references the first 5 cells leaves 59 cells unused. That's a lot of dead state for an audit format. Reversing the Go binary's runner reveals that the runner doesn't read the program indices directly; it reads them through a translation step that consults the `quiet` record. If bit 0 of `quiet[1]` is set, the runner adds 32 (`QUIET_BANK_DELTA`) to the last visible index before looking it up in the dictionary.

Audit doesn't perform that step. Audit reads the visible indices directly and certifies them. So with `quiet[1] |= 1`, the audit sees `[0, 1, 2, 3, 4]` and certifies the program, while the runner executes `[0, 1, 2, 3, 36]`. Cell 36 of the dictionary holds whatever the cartridge author put there. In the live challenge, that's the hidden answer opcode that triggers the flag-emitting code path.

The mutation is a single byte:

```python
mutated = bytearray(original)
mutated[quiet_off + 1] |= 1
```

That gets you a cartridge whose audit signature would match the original but whose runner program is the hidden one. The next problem: the server doesn't just sign cartridges. It signs a *runner cookie* over the runner program inside the resume token. So mutating the cartridge alone gets you nothing unless you can also forge a resume token that contains the hidden runner cookie.

### Step 3 — Reverse the resume token

`BOOT` returns a base64-encoded resume token. Decoded, the last 32 bytes look like a SHA-256 digest. Everything before that is the token body, a small TLV blob containing fields like the runner program hash, a debug flag, a sequence number, and the runner cookie expected by `STEP`.

Reversing the Go binary's MAC construction reveals the digest is computed as:

```
digest = SHA256(secret || token_body)
```

where `secret` is a 32-byte server-side key. That's not HMAC. That's a prefix MAC, and prefix MACs over Merkle-Damgård hash functions are vulnerable to length-extension attacks.

### Step 4 — Build the length-extension extension

The classic SHA-256 length-extension primitive: given `H = SHA256(secret || M)` and the length `|secret| + |M|`, you can compute `SHA256(secret || M || glue || X)` for any chosen `X`, where `glue` is the canonical Merkle-Damgård padding for the original message length.

The chosen extension here is a small chunk of decoded TLV fields:

```
f0 01 01                # set field 1 (debug/answer path) = true
f0 06 <runner_cookie>   # set field 6 (runner cookie) = our forged cookie
```

The token's state decoder accepts duplicate fields and **the later value wins** (a frequently-occurring weakness in resumable-state designs; Go's `gob`-style and most TLV decoders do this without explicit dedup). So appending these fields after the legitimate token body overrides whatever values the original token carried.

The runner cookie itself is computed by the server as:

```python
runner_cookie = SHA256(b"parallax/runner-cookie/v5" + runner_program)[:4]
```

So we compute the same SHA-256 prefix over `b"parallax/runner-cookie/v5"` concatenated with the *mutated* runner program bytes (`dict[0] || dict[1] || dict[2] || dict[3] || dict[36]`), take the first four bytes, and use that as the cookie to install.

### Step 5 — Implement the SHA-256 length extension

There's no standard Python module that exposes SHA-256's internal state, so the solver re-implements the compression function. The state of the digest at the moment it was finalized is exactly the eight 32-bit big-endian words of the final digest. To extend:

1. Recover the eight `(a, b, c, d, e, f, g, h)` state words by unpacking the original digest as `>8I`.
2. Compute the `glue` padding for the original `|secret| + |body|` message length: a `0x80` byte, zero padding to bring the total to a multiple of 64 minus 8, then the original message bit-length as a big-endian 64-bit integer.
3. Construct the extension: `suffix + SHA256_padding(original_length + |glue| + |suffix|)`.
4. Apply the SHA-256 compression function over each 64-byte block of the extension, starting from the recovered state.

The forged token is:

```
body || glue || suffix || new_digest
```

A clean Python implementation, factored out of the repo's `solve.py`:

```python
def sha256_length_extend(digest, original_len, suffix):
    state = list(struct.unpack(">8I", digest))
    glue = sha256_padding(original_len)
    total_len = original_len + len(glue) + len(suffix)
    extension = suffix + sha256_padding(total_len)
    for offset in range(0, len(extension), 64):
        state = sha256_compress(extension[offset:offset + 64], state)
    return struct.pack(">8I", *state), glue
```

`sha256_padding` and `sha256_compress` are the textbook FIPS 180-4 routines. Roughly forty lines of Python total. The repo's solver includes both verbatim.

### Step 6 — Stitch BOOT and STEP together

The full exploit flow:

1. Parse `starter.qar`, locate `dict`, `prog`, `quiet`.
2. Mutate `quiet[1] |= 1` to flip the runner into the hidden bank.
3. Decode the visible program indices.
4. Replace the last visible index `4` with the hidden index `4 + 32 = 36`.
5. Build the hidden runner program bytes by concatenating `dict[i*4:(i+1)*4]` for each `i` in `[0, 1, 2, 3, 36]`.
6. Compute the 4-byte runner cookie as `SHA256("parallax/runner-cookie/v5" || runner_program)[:4]`.
7. Send `BOOT <base64(original_cartridge)>` and capture the returned token.
8. Length-extend the token's SHA-256 digest, appending `\xf0\x01\x01\xf0\x06<cookie>` after the original body, prefixed by the canonical Merkle-Damgård glue padding.
9. Send `STEP <base64(mutated_cartridge)> <base64(forged_token)>`.

The server's response:

```
OK FLAG slopped{quiet_tracks_hide_in_hash_padded_resume_tapes}
```

### Why Parallax Cartridge works

Two failures composed.

The audit/runtime parser split is the same shape as the [Slipstream Cache](/ctf-writeups/anti-slopctf-2026-web-writeup/) bug from the web track. Anywhere two consumers walk the same buffer with different decoder logic, you get a differential. Cartridge formats are particularly prone to this because the audit step is usually meant to be *fast* and read a subset of fields, while the runner has to read everything. Defenders fix this by serialising the same canonicalisation function from both consumers, so that audit and runner walk identical decoding logic and disagree only at the "is this safe?" gate.

The prefix-MAC weakness is older and sharper. `SHA256(secret || message)` has been a known anti-pattern since the early 2000s when length-extension attacks against MD5 and SHA-1 hit the literature. HMAC was standardised in 1997 specifically to defeat this attack. Any modern protocol that uses a raw-prefix MAC is shipping a 25-year-old bug. The fix is one line in most languages: `hmac.new(secret, message, sha256).digest()` in Python, `crypto/hmac` in Go.

For defenders reviewing any custom protocol with resumable state: audit every byte sequence that crosses the trust boundary. Token format? HMAC, not raw hash. State decoder? Reject duplicate fields by default, not silently overwrite. Audit pass vs runtime pass? Single canonicalisation function shared between them, not two parallel decoders.

## Cross-cutting defender notes

Both challenges sit inside the same broader story as the web track: bugs that live in the gap between components.

**ECDSA nonce derivation belongs in the standard library, not in your code.** Audit Spiral's quadratic nonce is exactly the bug that RFC 6979 was written to make impossible. Any ECDSA implementation that calls `random()` or derives `k` from `(counter, message)` instead of `HMAC_DRBG(private_key, message)` is at risk of the same family of attacks. Concrete review checklist: grep for `ecdsa.sign`, `secp256k1.sign`, or `Signature::sign` and trace the `k` parameter back to its source. If the source is anything other than RFC 6979 or `crypto/rand` mixed into HMAC-DRBG, that's a finding.

**Parsers that walk the same buffer twice need to walk it identically.** The Parallax cartridge's audit-vs-runtime split is the same bug class as PHP's PHAR auto-deserialize on path operations, JWT `alg=none` confusion, OAuth scope handling between authorization-time and resource-server checks, and a dozen other production incidents. The defender pattern is to share a single canonicalisation step between every consumer of the byte sequence, even at the cost of a slower audit. Don't optimise the audit by parsing a subset of fields. That's exactly the optimisation that opens the differential.

**Prefix MACs are not MACs.** Any `Hash(secret || message)` construction over SHA-1, SHA-256, or any Merkle-Damgård hash leaks the ability to forge extensions of authenticated messages. HMAC has existed for 25 years. The replacement is a one-line change in any modern crypto library. There is no excuse for shipping a prefix MAC in 2026.

## Frequently asked questions

### What is Anti-Slop CTF?

Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source or reverse-engineering a custom format. The flag prefix is `slopped{...}` and the writeup compilation is at [Abdelkad3r/Anti-SlopCTF-2026](https://github.com/Abdelkad3r/Anti-SlopCTF-2026).

### What's the bug in Audit Spiral?

The service's ECDSA nonce `k` is not random and not deterministic-per-message. It follows a polynomial in the signing index: `k_i = c0 + c1·i + c2·i²` for unknown `c0, c1, c2`. With four or more signatures over the same digest, the ECDSA relation `s_i · k_i ≡ z + r_i · d (mod n)` becomes a linear system in the unknowns `(d, c0, c1, c2)` over the secp256k1 group order. Solving the system recovers the static private key.

### Why does the linear system trick work for quadratic nonces?

The ECDSA relation is linear in `(k, d)` per signature. If `k_i` is itself a linear combination of unknown coefficients `(c0, c1, c2)` with *known* per-sample weights `(1, i, i²)`, then the whole equation `s_i · (c0 + c1·i + c2·i²) ≡ z + r_i · d (mod n)` is linear in `(d, c0, c1, c2)`. Four samples give a 4×4 system over the secp256k1 group order, solvable by Gaussian elimination. The same trick extends to any polynomial nonce of degree `k` with `k + 2` samples.

### How do you get a stable digest to sign in Audit Spiral?

The signing command hashes whatever the loaded capsule emits and signs that hash. If the capsule's output varies between calls, the digest varies and you can't isolate the nonce structure. Load a capsule that emits exactly the same 16 bytes every time (sixteen zero bytes is the simplest version) and now `z` is constant across signatures. Anything that varies between signatures is nonce structure.

### What's the bug in Parallax Cartridge?

Two bugs composed. First, the cartridge runner reads a `quiet` record that can shift the final program index into a hidden dictionary bank (`+32`) while the audit step doesn't perform that shift. The same cartridge audits clean and runs the hidden opcode. Second, the BOOT-step resume token is authenticated with a raw `SHA256(secret || body)` prefix MAC, which is vulnerable to length extension. Length-extending the token lets you append duplicate fields that install the runner cookie for the hidden program.

### How does the SHA-256 length-extension attack work here?

SHA-256 is a Merkle-Damgård hash, meaning its final digest is the internal state at the end of the last compression block. Given `digest = SHA256(secret || body)` and the length `|secret| + |body|`, you can reconstruct the internal state, append the canonical Merkle-Damgård padding for the original message length (the "glue"), then continue compressing your chosen extension. The resulting digest is a valid `SHA256(secret || body || glue || extension)` even though you never knew `secret`.

### Why does the duplicate-field win matter in Parallax?

The token body is TLV-encoded with field-tagged records. The Go state decoder reads fields in order and stores each into a map keyed by field tag. When it encounters a duplicate tag, the later value silently overwrites the earlier one. That means the length-extension suffix can re-set fields the original body already set, including the runner cookie for the program to be executed. A defensive decoder would reject duplicate fields with an explicit error.

### Can you recover the secret in Parallax instead of length-extending?

You don't need to. The whole point of a length-extension attack is that the secret stays secret and you still forge a valid MAC. The 32-byte server secret is unrecoverable from a single legitimate digest; what you can do, given a legitimate digest, is *extend* the message it authenticates. The forged token never reveals or requires the secret.

### Where can I find the full solver scripts?

Source artefacts and solvers for both reverse challenges are at [Abdelkad3r/Anti-SlopCTF-2026/reverse](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/reverse). Audit Spiral's solver is in `audit-spiral/solve.py` and includes a small pure-Python secp256k1 implementation. Parallax Cartridge's solver is in `parallax-cartridge/solve.py` and includes a hand-rolled SHA-256 compression function for the length-extension step.

### What's the broader lesson from the Anti-Slop CTF reverse track?

Both bugs are in primitives that have well-known correct replacements. ECDSA's correct nonce derivation has been RFC 6979 since 2013. Prefix MACs have had a correct replacement (HMAC) since 1997. The challenges aren't about discovering new attack classes; they're about noticing that the implementation in front of you uses a primitive in a way the literature flagged decades ago. The Anti-Slop framing rewards exactly that posture: read the code, recognise the antique, exploit it.

## Closing notes

Both flags landed in roughly the same shape: an hour or two of reversing to map the relevant data structures, then a few minutes of cryptographic algebra or SHA-256 plumbing. Neither challenge had a clever undocumented opcode. Both punished any solver that tried to skip the reversing step and went straight for "what tool gives me the answer".

The repository at [Abdelkad3r/Anti-SlopCTF-2026](https://github.com/Abdelkad3r/Anti-SlopCTF-2026) contains writeups for all 14 challenges across the event. The companion [web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/) covers Slipstream Cache and SloppedRider. For more reverse-engineering content on this site, see the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) (six reverse challenges including a 250-state FSM Hamiltonian path and a custom-kernel eBPF verifier patch) or the [SCTF 2026 writeup](/ctf-writeups/sctf-2026-writeup/) (a Groth16 Poseidon-Merkle witness gated by Fermat-factorable RSA). Full [CTF writeups index](/ctf-writeups/) is also available.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is Anti-Slop CTF?","acceptedAnswer": {"@type": "Answer","text": "Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source or reverse-engineering a custom format. The flag prefix is slopped{...} and the writeup compilation is at github.com/Abdelkad3r/Anti-SlopCTF-2026."}},
    {"@type": "Question","name": "What's the bug in Audit Spiral?","acceptedAnswer": {"@type": "Answer","text": "The service's ECDSA nonce k follows a polynomial in the signing index: k_i = c0 + c1·i + c2·i² for unknown coefficients. With four or more signatures over the same digest, the ECDSA relation s_i · k_i ≡ z + r_i · d (mod n) becomes a linear system in (d, c0, c1, c2) over the secp256k1 group order. Solving the system recovers the private key."}},
    {"@type": "Question","name": "Why does the linear system trick work for quadratic nonces?","acceptedAnswer": {"@type": "Answer","text": "The ECDSA relation is linear in (k, d) per signature. If k_i is itself a linear combination of unknown coefficients (c0, c1, c2) with known per-sample weights (1, i, i²), then s_i · (c0 + c1·i + c2·i²) ≡ z + r_i · d (mod n) is linear in (d, c0, c1, c2). Four samples give a 4×4 system over the secp256k1 group order, solvable by Gaussian elimination. The same trick extends to any polynomial nonce of degree k with k + 2 samples."}},
    {"@type": "Question","name": "How do you get a stable digest to sign in Audit Spiral?","acceptedAnswer": {"@type": "Answer","text": "The signing command hashes whatever the loaded capsule emits and signs that hash. If the output varies between calls, the digest varies and you can't isolate the nonce structure. Load a capsule that emits exactly the same 16 bytes every time, like sixteen zero bytes, and now z is constant across signatures. Anything that varies between signatures is nonce structure."}},
    {"@type": "Question","name": "What's the bug in Parallax Cartridge?","acceptedAnswer": {"@type": "Answer","text": "Two bugs composed. First, the cartridge runner reads a quiet record that can shift the final program index into a hidden dictionary bank (+32) while the audit step doesn't perform that shift. The same cartridge audits clean and runs the hidden opcode. Second, the BOOT-step resume token is authenticated with a raw SHA256(secret || body) prefix MAC, which is vulnerable to length extension."}},
    {"@type": "Question","name": "How does the SHA-256 length-extension attack work here?","acceptedAnswer": {"@type": "Answer","text": "SHA-256 is Merkle-Damgård, so the final digest is the internal state at the end of the last compression block. Given digest = SHA256(secret || body) and the length |secret| + |body|, you reconstruct the internal state, append the canonical Merkle-Damgård padding (the glue), then continue compressing your chosen extension. The result is a valid SHA256(secret || body || glue || extension) even though you never knew secret."}},
    {"@type": "Question","name": "Why does the duplicate-field win matter in Parallax?","acceptedAnswer": {"@type": "Answer","text": "The token body is TLV-encoded. The Go state decoder reads fields in order and stores each into a map by tag. When it encounters a duplicate tag, the later value silently overwrites the earlier one. That means the length-extension suffix can re-set fields the original body already set, including the runner cookie for the program to be executed."}},
    {"@type": "Question","name": "Can you recover the secret in Parallax instead of length-extending?","acceptedAnswer": {"@type": "Answer","text": "You don't need to. The whole point of a length-extension attack is that the secret stays secret and you still forge a valid MAC. The 32-byte server secret is unrecoverable from a single legitimate digest; what you can do, given a legitimate digest, is extend the message it authenticates. The forged token never reveals or requires the secret."}},
    {"@type": "Question","name": "Where can I find the full solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Source artefacts and solvers for both reverse challenges are at github.com/Abdelkad3r/Anti-SlopCTF-2026/reverse. Audit Spiral's solver is in audit-spiral/solve.py and includes a small pure-Python secp256k1 implementation. Parallax Cartridge's solver is in parallax-cartridge/solve.py and includes a hand-rolled SHA-256 compression function for the length-extension step."}},
    {"@type": "Question","name": "What is the broader lesson from the Anti-Slop CTF reverse track?","acceptedAnswer": {"@type": "Answer","text": "Both bugs are in primitives that have well-known correct replacements. ECDSA's correct nonce derivation has been RFC 6979 since 2013. Prefix MACs have had a correct replacement (HMAC) since 1997. The challenges aren't about discovering new attack classes; they're about noticing that the implementation in front of you uses a primitive in a way the literature flagged decades ago."}}
  ]
}
</script>
