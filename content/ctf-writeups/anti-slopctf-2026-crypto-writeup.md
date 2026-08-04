---
title: "Anti-Slop CTF 2026 Crypto Writeup: Polynomial Drift + Sealed Signal"
slug: "anti-slopctf-2026-crypto-writeup"
description: "Step-by-step crypto writeups for Anti-Slop CTF 2026. Polynomial Drift: 24-bit ECDSA nonce leak solved as a CVP lattice. Sealed Signal: CBC-MAC splice past a domain header."
date: 2026-06-22T21:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["Anti-Slop CTF 2026"]
tags:
  - "anti-slop ctf"
  - "anti-slopctf 2026"
  - "cryptography"
  - "ecdsa hidden number problem"
  - "lattice cvp"
  - "fpylll"
  - "cbc-mac forgery"
  - "chosen message oracle"
  - "secp256k1"
  - "domain separation"
keywords:
  - "anti-slop ctf 2026 crypto writeup"
  - "polynomial drift writeup"
  - "sealed signal writeup"
  - "ecdsa hidden number problem ctf"
  - "ecdsa low bit nonce leak cvp"
  - "fpylll cvp recover private key"
  - "cbc-mac splice attack ctf"
  - "chosen message cbc-mac oracle"
  - "domain header cancel xor"
  - "secp256k1 24 bit nonce leak"
  - "ctf crypto step by step"
toc: true
cover:
  image: "/images/articles/anti-slopctf-2026-crypto-writeup.png"
  alt: "Anti-Slop CTF 2026 crypto writeup — Polynomial Drift CVP-based ECDSA recovery and Sealed Signal CBC-MAC splice"
---

Fourth post in the **CyberSecurity Elite** Anti-Slop CTF 2026 crypto series. The [web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/) covered HTTP parsers. The [reverse writeup](/ctf-writeups/anti-slopctf-2026-reverse-writeup/) covered a quadratic ECDSA nonce and a SHA-256 length extension. The [pwn writeup](/ctf-writeups/anti-slopctf-2026-pwn-writeup/) covered a Bellcore CRT fault, a leak-then-overwrite, and a five-stage GCM forge chain. This one walks the two crypto challenges in the same step-by-step format.

**Polynomial Drift** is the more mathematical of the two: a Rust TCP service signs capsule commits with ECDSA over secp256k1, but the VM that runs each capsule leaks the low 24 bits of the signing nonce. Eleven signatures plus an `fpylll` CVP solve recovers the private key. **Sealed Signal** is the more protocol-level of the two: a WebSocket relay uses CBC-MAC over two compatible capsule families, the cache-signing oracle accepts attacker-chosen blobs, and an XOR-cancellation against the fixed 16-byte cache header splices a valid MAC onto a forbidden resume capsule.

Both are clean textbook attacks once the leak surface is identified. The work is in spotting the leak. Artefacts, the stripped Rust binary, the captured WebSocket session, and the full Python solvers live at [Abdelkad3r/Anti-SlopCTF-2026/crypto](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/crypto).

## The two crypto challenges

| Challenge | Bug class | Points | Flag |
|---|---|---|---|
| Polynomial Drift | ECDSA nonce low 24 bits leak through the VM preview byte; 11+ signatures give a Hidden Number Problem instance solvable as a CVP on a small lattice with `fpylll` | 443 | `slopped{polyphase_masks_force_a_hidden_number_pivot}` |
| Sealed Signal | Cache-signing oracle is a chosen-message CBC-MAC oracle; a `B0 = P0 xor H` block cancels the fixed cache-header state, splicing a valid MAC onto a forbidden `role=root` resume capsule | 459 | `slopped{cbc_mac_capsule_splice_last_claim_wins}` |

The shape that connects both: **a primitive that looks domain-separated isn't, and the gap is the bug**. Polynomial Drift's signing service looks like it signs the commit blob through a clean ECDSA layer; the VM running underneath it leaks four nonce bytes per signature into the response. Sealed Signal's cache signer looks like it operates on cache blobs only; the CBC-MAC state it computes is interoperable with the resume-capsule MAC after a one-block XOR cancel. Both bugs hide in the seam between an apparently-isolated layer and the layer underneath.

## Methodology — find the leak, then build the attack the literature already wrote

A pattern that worked for both challenges: don't reach for cryptanalysis. Reach for *leak identification*. ECDSA and CBC-MAC are well-studied; neither falls to a generic break. They fall to specific weaknesses (partial nonce disclosure, oracle interoperability, key reuse across domains) that are catalogued in two-decade-old papers. Once you know which weakness applies, the attack is mechanical and the literature has the math.

For Polynomial Drift, the leak surface is the four bytes of preview that come back with every commit signature. Most of the work is identifying that bytes `3:6` of the preview happen to be exactly the low 24 bits of `k`. After that, Boneh and Venkatesan (1996) wrote the lattice. Nguyen and Shparlinski (2002) wrote the specific construction we use. `fpylll` solves it in seconds.

For Sealed Signal, the leak surface is the cache-signing oracle that returns the CBC-MAC state of an attacker-chosen blob with a fixed 16-byte prefix. Most of the work is realising that the resume capsule and the cache capsule both use the same underlying CBC-MAC, and that one XOR-cancellation against the fixed prefix lets a chosen-message oracle in the cache domain forge a tag in the resume domain. Bellare, Kilian, Rogaway (1994) wrote the threat model. The textbook splice attack against CBC-MAC under chosen messages has been the same shape for thirty years.

Per-challenge walkthroughs follow.

## Polynomial Drift

### The setup

A Rust TCP service called `polydrift` (Linux x86-64 PIE, ~473 KiB, stripped). The wire protocol exposes a small VM that loads capsules, commits them, and signs commits with ECDSA over secp256k1. Two keys exist on the server side: a "diag" key that signs status payloads, and a "main" key that signs capsule commits and gates the `auth` command. The flag flow:

```
load <capsule>     # load a capsule into the VM
commit             # run the capsule, return preview + signature
...repeat...
auth <signature>   # submit a signature over SHA256("POLYPHASE|grant|" + sid); win
```

The `auth` command verifies the signature against the **main** public key. The diag key is decorative.

### Step 1 — Pick the right key to attack

A first-pass read of the service surfaces two interesting code paths. The diag endpoint returns status payloads signed with a key whose nonces are demonstrably random (no per-payload bias I could find). The commit signer uses a second key, the main one, whose nonces look the same on first inspection. I wasted forty minutes trying to find a leak in the diag signatures before switching focus. **The diag key is a decoy.** Every interesting structural property in the service binary is in the commit-signing path.

That's the methodology lesson worth pulling out of this challenge: if a service exposes two cryptographic surfaces and one of them is labelled "diagnostic" or "debug" or "telemetry", attack the other one first. Production paths get more attention than instrumentation paths; if there's a bug in either, it's usually in the production path because that's where the protocol designer was actually doing creative work.

### Step 2 — Find the leak

A minimal valid capsule that runs cleanly through the VM looks like:

```
504446540209008a0000000010163e474c709aa5f8
```

The `PDFT` magic prefix, a tiny header, then bytecode pushing `(1, 2, 3, 4)` onto the VM stack. Commit it and the response carries a preview byte plus the ECDSA signature. After committing the same capsule many times and comparing the preview byte across signatures, the relationship surfaces:

```
k & 0xffffff == (4 << 16) | (3 << 8) | preview
```

Bytes 1 and 2 of the low 24 bits of `k` are the constants 4 and 3 (the top two values the capsule pushed). Byte 0 is the preview byte the server returns. For every signature, **the low 24 bits of `k` are known**.

That's a tight leak. ECDSA recovery on `n`-bit curves is feasible when the leaked-nonce-bits per signature multiplied by the signature count exceeds roughly `2n`. For secp256k1 (`n = 256`), 24 bits per signature times 11 signatures gives 264 bits of total leak, comfortably above the threshold. The Hidden Number Problem instance is solvable.

### Step 3 — Build the Hidden Number Problem

ECDSA, for signature `i`:

```
s_i = k_i^{-1} · (z_i + r_i · d) mod n
```

Rearrange to isolate `k_i`:

```
k_i = z_i / s_i + (r_i / s_i) · d mod n
```

Split `k_i` into its known low-24-bit portion `K_i` and an unknown 232-bit high portion `t_i`:

```
k_i = K_i + 2^24 · t_i
```

Substitute and rearrange:

```
2^24 · t_i ≡ (r_i / s_i) · d + (z_i / s_i − K_i) mod n
```

Let `a_i = (r_i / s_i) mod n` and `b_i = (z_i / s_i − K_i) mod n`. Then for each signature:

```
2^24 · t_i ≡ a_i · d + b_i mod n
```

The unknowns are `d` (one shared variable) and `t_1, t_2, ..., t_m` (one per signature). The constraint per signature is that `t_i` is roughly 232 bits, much smaller than `n`. That's a textbook Closest Vector Problem on a `(m+1)`-dimensional lattice.

### Step 4 — Set up the CVP lattice

The standard Nguyen–Shparlinski construction for `m` signatures uses an `(m+1) × (m+1)` lattice basis. With `B = 2^24` for clarity:

```
       d-col   t_1     t_2    ...  t_m
row d:   n     0       0      ...  0
row 1:  -a_1   B·n     0      ...  0
row 2:  -a_2   0       B·n    ...  0
...
row m:  -a_m   0       0      ...  B·n
target: 0      b_1     b_2    ...  b_m
```

(Each non-trivial column scaled so all entries have comparable magnitude. Exact normalisation depends on how you weight `d` vs `t_i`.)

The closest lattice vector to the target reveals `d` and the `t_i` values via the recovered linear combination. `fpylll`'s BKZ + Babai-CVP gets there in seconds for `m = 11`.

A minimal solver sketch (the actual repo solver includes the normalisation, the embedding tricks, and the post-solve verification):

```python
from fpylll import IntegerMatrix, LLL, BKZ, CVP

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B = 1 << 24
m = 11  # number of signatures

# Compute a_i and b_i from collected (z_i, r_i, s_i, K_i) tuples.
a = [...]   # length m
b = [...]   # length m

M = IntegerMatrix(m + 1, m + 1)
M[0, 0] = N
for i in range(m):
    M[i + 1, 0] = -a[i] % N
    M[i + 1, i + 1] = B * N

M = BKZ.reduction(M, BKZ.Param(block_size=20))

target = [0] + b
close = CVP.closest_vector(M, target)

# Recover d from the close vector (sign and modular reduction)
d_candidate = close[0] % N
```

In practice the solver computes `d` modulo `n` and then verifies `d · G == public_key`. If verification fails on the first candidate, flip the sign or shift the embedding constant and retry. The lattice has a discrete symmetry that occasionally lands on the negative solution.

### Step 5 — Recover the main private key

For the live challenge, the recovered main private key was:

```
d = 0xb94052b8ca127bc32e757e49dc37abcc55d0333186ef7e4dd96973439e8da570
```

Compressed public point matched the value the service advertised at connection:

```
02cc74bc2c7013648ff52090c12ed29cf95ce79ab49506d6c16957cc04e660e488
```

That's the recovery sanity check. If `d · G` doesn't match the published key, the CVP solution landed on the wrong basis vector and you re-run with a different normalisation or with one extra signature added to the lattice.

### Step 6 — Sign the auth challenge

The auth gate signs:

```python
msg = hashlib.sha256(b"POLYPHASE|grant|" + sid.to_bytes(8, "big")).digest()
```

where `sid` is a per-session integer the server advertises. Sign locally with the recovered key using any deterministic ECDSA implementation (RFC 6979 is fine; the server only checks the signature verifies):

```python
r, s = ecdsa_sign(d, msg)
sig_hex = r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()
```

Send `auth <sig_hex>` and the server returns:

```
slopped{polyphase_masks_force_a_hidden_number_pivot}
```

The full client at [`crypto/polynomial-drift/solve.py`](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/crypto/polynomial-drift) automates capsule loading, signature collection, the CVP solve, and the auth submission.

### Why Polynomial Drift works

Two design decisions compose into the win.

The first is that the VM previews its top-of-stack into the same response that carries the signature, without thinking about what's in the nonce derivation. The author likely treated "preview byte" as a UX touch, useful for clients to know whether their capsule actually ran. They didn't notice that the preview byte was derived from internal VM state that the nonce derivation also touched.

The second is that the nonce derivation pulls bytes from VM state at all. RFC 6979 derives `k` purely from `(private_key, message_hash)` via HMAC-DRBG. There's no VM state, no per-call entropy, no preview byte. Any service that derives `k` from anything an attacker can influence is at risk. Polynomial Drift's specific bug is "the preview byte equals the low byte of `k`", which is the worst-case version of this class.

The defender fix is RFC 6979, full stop. Anywhere ECDSA's `k` is anything other than `HMAC_DRBG(private_key, message_hash)`, the implementation is suspect. The cost of switching is zero in any modern crypto library.

## Sealed Signal

### The setup

A WebSocket relay service whose UI offers six user actions:

```
HELLO     — connect with a nickname
OPEN      — open a draft for an 8-byte room
SEAL      — seal the latest draft, return a resume token + capsule
RESUME    — resume from token + capsule
FLAGREQ   — ask for the flag (role/scope gated)
CAPSULE   — ask the cache signer to sign a cache blob
```

The flag is gated by a resume state with `role=root scope=flag room=flagroom`. The legitimate UI never produces a capsule with those values. Sealing as a normal user produces `role=user scope=chat`, and there's no UI control to escalate. The path to the flag has to forge a resume capsule whose MAC the server will accept.

### Step 1 — Read the wire protocol

The relay's `/app.js` is the client and gives away the wire format. Each frame:

```
"R1" || nibble_swap(op || xid_le16 || varint(payload_len) || payload || crc16_le)
```

Payloads are TLV:

```
tag || varint(length) || value
```

Notable tags and opcodes (full table in the source README):

```
ROOM    = 0x04    HELLO    = 0x10
ROLE    = 0x07    OPEN     = 0x20
SCOPE   = 0x08    SEAL     = 0x30
BLOB    = 0x0d    RESUME   = 0x40
CAPSULE = 0x0e    FLAGREQ  = 0x50
                  CAPSULE  = 0x60
```

After `HELLO_ACK` the server returns a one-byte "dialect" that XORs every subsequent opcode on the wire. CRC is CRC16-CCITT over the unswapped body. None of this is the bug; it's just framing the solver has to get right before any cryptographic exploration starts. Get the nibble-swap and dialect XOR wrong and every frame returns "bad frame" with no useful information.

### Step 2 — Observe a normal resume capsule

Open a draft for `flagroom`, seal it, and the server returns a token plus a capsule. The capsule plaintext is visible (it's not encrypted, only MAC'd). The format:

```
kind=resume&role=user&scope=chat&room=flagroom&cache=flagroom&pad=...
<16-byte MAC>
```

The MAC is exactly 16 bytes, AES-block-sized, and resuming this capsule works. `FLAGREQ` against it returns "permission denied" because role and scope aren't privileged. Tampering with the plaintext (changing `role=user` to `role=admin`) and resending invalidates the MAC, so the server rejects the resume.

### Step 3 — Probe the cache signer

The CAPSULE opcode signs an arbitrary `BLOB` and returns a capsule containing:

```
"CACHE::SIGNME::!" || blob || mac
```

`CACHE::SIGNME::!` is exactly 16 bytes, one AES block. Asking the signer to MAC an empty blob returns the CBC-MAC state after this fixed header alone. Call that state `H`:

```python
H = sign_cache_blob(b"")  # this is AES_K("CACHE::SIGNME::!")
```

That `H` is the key to the splice. It's the value at the chaining position right after the cache header, computable any time, and it's the same value the resume MAC would have at the *start* of its message if we could prefix it with that block.

We can't prefix the resume MAC with the cache header. But we can cancel the cache header out.

### Step 4 — Try the cheap filter bypass first

The cache signer rejects any blob containing the literal substring `scope=flag`. Sending `blob = "kind=resume&role=root&scope=flag&..."` directly returns an error. That filter is the only defence on this path; if you're going to construct the splice, you have to construct it without ever asking the signer to sign anything containing `scope=flag` literally.

This is the part of the challenge where you stop fighting the filter at the request layer and start fighting it at the cryptographic layer.

### Step 5 — The splice math

Let `E` be the AES block cipher under the relay's secret key. CBC-MAC is:

```
state_0 = 0^128
state_i = E(state_{i-1} XOR P_i)
mac     = state_n
```

For the cache signer, the first block is always `H1 = "CACHE::SIGNME::!"`, so the state after the first block is:

```
H = E(H1)      (we measured this with the empty-blob query)
```

For a cache blob `B0 || B1 || ...`, the state after `B0` is:

```
state_after_B0 = E(H XOR B0)
```

Now consider the target resume message we want a MAC for:

```
P0 = b"kind=resume&role"
P1 = b"=root&scope=fla"
P2 = b"g&room=flagroom&"
P3 = b"cache=flagroom&p"
P4 = b"ad=AAAAAAAAAAAAA"
```

A legitimate resume MAC computes `state_1 = E(P0)` from a zero IV. We want a cache-oracle query whose state at the same chaining position is `E(P0)`. Choose:

```
B0 = P0 XOR H
```

Then `state_after_B0 = E(H XOR (P0 XOR H)) = E(P0)`. **The cache header has been algebraically cancelled.** The cache signer's chaining state after processing `(P0 XOR H) || P1` matches the resume MAC's chaining state after processing `P0 || P1`. Call that resulting tag `T1` (it's the MAC the cache signer returns).

Now for the next chunk: we want the resume MAC's state after `P0 || P1 || P2`. That state is `E(T1 XOR P2)`. The cache signer, starting fresh, produces `state_after_X = E(H XOR X)` for whatever block `X` we put first. Choose:

```
X = T1 XOR P2 XOR H
```

Then `E(H XOR X) = E(H XOR T1 XOR P2 XOR H) = E(T1 XOR P2)`, which is the resume MAC's `state_3`. So a cache query for `X || P3 || P4` returns the resume MAC tag for `P0 || P1 || P2 || P3 || P4`.

Two cache queries, two splices, one forged MAC. Neither query ever contains the literal `scope=flag` substring, because `B0 = P0 XOR H` is a pseudorandom block (`H` is `AES_K("CACHE::SIGNME::!")`, attacker-unpredictable in plaintext but a known value because we measured it). Same for `X`. The filter sees gibberish; the cryptographic chaining state matches the forbidden plaintext.

### Step 6 — The "admin isn't enough" gotcha

The target plaintext I tried first was:

```
kind=resume&role=admin&scope=flag&room=flagroom&cache=flagroom&pad=...
```

The splice produced a valid MAC, the server accepted the resume (`resumed: admin flag flagroom`), and `FLAGREQ` returned:

```
admins only
```

Confusing first read. The role `admin` was clearly accepted; the resumed-state line said so. The flag endpoint just refused it. After a closer read of the `FLAGREQ` handler in `/app.js`, the check is for `role=root` specifically, not for any "privileged" role. The string `admin` happens to be one of the roles the resume state machine knows about (and prints in the resumed line), but it's not what the flag gate requires.

This is the trap the challenge is named after: *last claim wins* in the CBC-MAC splice means you can forge any plaintext that fits the block alignment, including ones that *look* like they should work but don't. The forge is correct; the role string is wrong. Switching to `role=root` and rebuilding the splice from scratch passes.

### Step 7 — Build the winning capsule and pull the flag

Final target plaintext:

```
P = b"kind=resume&role=root&scope=flag&room=flagroom&cache=flagroom&pad=AAAAAAAAAAAAA"
```

Length 80 bytes, exactly five AES blocks. Build the splice over two cache-signing queries as described, get the forged MAC, assemble the capsule as `P || forged_mac`, and submit:

```
RESUME(token=legit_token, capsule=forged_capsule)
FLAGREQ()
```

The legitimate token from earlier sealing is reused; only the capsule changes. The server accepts the resume:

```
resumed: root flag flagroom
```

Then `FLAGREQ` returns:

```
slopped{cbc_mac_capsule_splice_last_claim_wins}
```

### Why Sealed Signal works

The bug is the absence of real domain separation between cache capsules and resume capsules. Both use the same AES key under the same CBC-MAC construction. The fixed 16-byte cache header is the only thing the designer thought separated the two domains. It doesn't, because:

- The header is exactly one AES block, so its contribution is a single chaining state `H = E(H1)` that an attacker can measure with one query.
- CBC-MAC's chaining is linear in the XOR of state and next-block, so the attacker can XOR away the contribution of `H` in any subsequent block.
- Two cache queries are enough to splice any multi-block forbidden plaintext.

The right fix is HMAC, which uses key prefixing in a way that doesn't admit this cancellation. The next-best fix is CMAC (NIST SP 800-38B), which uses two derived subkeys for the last block and breaks the suffix-prefix interoperability that makes the cache-to-resume splice work. The bare-minimum fix that still uses CBC-MAC is to prepend a *secret* domain tag to every message before MAC'ing, so that no chosen-message oracle can probe the state after the prefix.

The author's intent of "a fixed prefix block separates the domains" is wrong by the same argument that broke CBC-MAC for variable-length messages in the early 1990s. Bellare, Kilian, and Rogaway's original CBC-MAC paper (1994) and the subsequent EMAC/CMAC line of work all exist because raw CBC-MAC under chosen messages is dangerous. Anyone shipping CBC-MAC in 2026 needs to be using a fully-domain-separated construction like CMAC or HMAC, and even then they need to think about cross-protocol attacks where two different services share an authentication key.

## Cross-cutting defender notes

Three patterns recur across the crypto track and the wider Anti-Slop event.

**Partial nonce leaks are key compromises.** Polynomial Drift leaks 24 of 256 nonce bits per signature. That's well below the historically-quoted 8-bit-per-signature threshold for HNP attacks on a 256-bit curve. Modern lattice tools (`fpylll`, BKZ-20) handle 24-bit leaks in 11 signatures without breaking a sweat. Anywhere ECDSA's `k` is derived from anything observable (a per-call counter, a session ID, a timestamp, a VM preview byte), assume the key is recoverable from polynomial-many signatures. The threshold has been getting lower as lattice reduction matures.

**Chosen-message MAC oracles cross domains.** Sealed Signal's cache signer is a chosen-message CBC-MAC oracle. Its existence in the same key as the resume MAC is the bug, regardless of any filter the cache signer applies. The filter is a *content* check; the splice happens at the *chaining-state* level, below the content the filter sees. The right defence is to keep the key fully separated (different AES keys for different domains) or to use a MAC construction that's secure under chosen messages (HMAC, CMAC, GMAC with proper nonce hygiene).

**The "diagnostic" surface is rarely the bug.** Polynomial Drift's diag key is a decoy. Anchorpoint's seal-nonce-freeze command exists for testing. Real flags hide behind production paths. Auditors should follow the data flow into the gated endpoint and look for the cheapest leak on that path, not on the diagnostic path. Decoys waste hours.

## Frequently asked questions

### What is Anti-Slop CTF?

Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source or reverse-engineering a custom format. The flag prefix is `slopped{...}` and the writeup compilation is at [Abdelkad3r/Anti-SlopCTF-2026](https://github.com/Abdelkad3r/Anti-SlopCTF-2026).

### What's the bug in Polynomial Drift?

The Rust signing service runs a small capsule VM. For a capsule that pushes the integers `(1, 2, 3, 4)` onto the VM stack, the low 24 bits of the ECDSA nonce equal `(4 << 16) | (3 << 8) | preview_byte`, where `preview_byte` is returned in the response. That's a 24-bit-per-signature leak on a 256-bit curve, which is well within the Hidden Number Problem regime. Collect 11+ signatures, build a CVP lattice, solve with `fpylll`, recover the private key, sign the `auth` challenge to win.

### How does the Hidden Number Problem lattice work?

ECDSA gives `k_i = z_i / s_i + (r_i / s_i) · d (mod n)`. Split `k_i = K_i + 2^24 · t_i` where `K_i` is the known low 24 bits. Then `2^24 · t_i ≡ a_i · d + b_i (mod n)` with `a_i = r_i/s_i` and `b_i = z_i/s_i − K_i`. The unknowns are `d` (shared across signatures) and one `t_i` per signature (each ~232 bits, much smaller than `n`). That's a CVP on an `(m+1)`-dimensional lattice, solvable in seconds by `fpylll` BKZ-20 with `m = 11` signatures.

### Why are 11 signatures enough for secp256k1?

The HNP success threshold is roughly `signatures × leaked_bits > 2n`. For secp256k1, `n` is 256 bits, so `2n = 512`. With 24 bits leaked per signature, you need `512 / 24 ≈ 22` signatures in the naive bound, but the lattice typically succeeds well below that. Eleven was sufficient in practice; it's a balance between collection time and lattice dimension (which costs reduction time). Add a few extra signatures if the first attempt finds the wrong sign of `d`.

### Why is the diag key a decoy in Polynomial Drift?

The diag endpoint signs status payloads with a separate key whose nonces look random. There's no leak on that path. The commit-signing path uses the main key and has the VM-preview leak baked in. The challenge is set up to reward attackers who pick the right target. Diag is the obvious-looking signing surface; the main commit signer is the actual surface with the bug. A first-pass solver burned forty minutes trying to attack diag before pivoting.

### What's the bug in Sealed Signal?

Two capsule families (resume and cache) share the same CBC-MAC key. The cache signer is a chosen-message oracle: it computes `MAC("CACHE::SIGNME::!" || attacker_blob)` for any attacker blob (except those containing the literal `scope=flag` substring). The fixed 16-byte header was meant to separate the domains, but it's exactly one AES block, so its CBC-MAC contribution is a single chaining state `H` that the attacker can measure. Sending `B0 = P0 XOR H` cancels `H` in the chaining, and from that point the cache signer's output state matches the resume MAC's output state on the same plaintext.

### Why doesn't the `scope=flag` filter stop the splice?

The filter runs on the literal cache-signing request blob. The splice never asks the signer to sign anything containing `scope=flag`; it asks the signer to sign `(P0 XOR H)`, then `(T1 XOR P2 XOR H)`, etc. Both look like pseudorandom blocks at the content layer (`H` is `AES_K("CACHE::SIGNME::!")`, attacker-known but pseudorandom in appearance). The forbidden substring only appears in the resume capsule plaintext that the splice constructs the MAC for, which the cache signer never sees.

### Why is `admin` not enough? Why does the flag gate require `root`?

The resume state machine accepts several role strings and reports the resumed role back to the client. `admin` resumes successfully and the server confirms `role=admin`. But the `FLAGREQ` handler checks specifically for `role=root`, not for any "privileged" or "admin-like" role. The plaintext substitution is straightforward (change `role=admin` to `role=root` and rebuild the splice), but it's a real trap for the first attempt because the resumed-state line is misleadingly affirming.

### Could you fix Sealed Signal without changing the MAC construction?

Not robustly. The fundamental problem is that the cache signer's chaining state is interoperable with the resume MAC's chaining state under one XOR cancellation. Any defence that keeps both MACs sharing the same AES key is at risk of related variants of the splice. The principled fix is HMAC or CMAC for both MACs, with key separation between domains. A weaker but workable fix is a secret per-domain prefix (so the cache header itself becomes attacker-unknown), but that's brittle.

### Where can I find the full solver scripts?

Solvers for both crypto challenges are at [Abdelkad3r/Anti-SlopCTF-2026/crypto](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/crypto). Polynomial Drift's `solve.py` includes the capsule encoder, the signature collection loop, the CVP/lattice setup with `fpylll`, the key recovery and verification step, and the final `auth` flow. Sealed Signal's `exploit.py` includes the R1 frame builder with nibble swap and dialect XOR, the empty-blob probe for `H`, the two-query splice that constructs the forged MAC, and the resume-then-FLAGREQ chain.

### What's the broader lesson from the Anti-Slop CTF crypto track?

Both bugs are leaks at the seam between an authenticated layer and the layer underneath. ECDSA is sound; the VM that derives the nonce isn't disciplined about what it leaks. CBC-MAC is sound for fixed-domain messages; the cache and resume domains aren't actually separate. The pattern is consistent across the whole event: the cryptographic primitives are fine, but the integration layer leaks the inputs the primitive assumed were secret. Defenders should audit the integration layer at least as carefully as the primitive.

## Closing notes

Polynomial Drift was an afternoon's work once I stopped attacking the diag key. Sealed Signal took longer because the relay framing (R1 + nibble-swap + dialect XOR + CRC16) is finicky enough to derail any solver that tries to skip it, but once the framing was right, the splice itself is a textbook construction.

This is the fourth and final per-category writeup in the Anti-Slop CTF 2026 series. The companion posts cover the [web](/ctf-writeups/anti-slopctf-2026-web-writeup/), [reverse](/ctf-writeups/anti-slopctf-2026-reverse-writeup/), and [pwn](/ctf-writeups/anti-slopctf-2026-pwn-writeup/) tracks. For more cryptography-flavoured CTF writeups on this site, the [DalCTF 2026 writeup](/ctf-writeups/dalctf-2026-writeup/) covers six classical crypto challenges (Playfair, Huffman, small-factor RSA, Bellcore, IEEE-754 type punning, LCG known-plaintext), the [SCTF 2026 writeup](/ctf-writeups/sctf-2026-writeup/) covers a Groth16 Poseidon-Merkle witness gated by Fermat-factorable RSA, and the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) covers four crypto challenges including the AVX2 lane-swap miscompile in `justfollowtherecipe`. Full [CTF writeups index](/ctf-writeups/) is also available.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is Anti-Slop CTF?","acceptedAnswer": {"@type": "Answer","text": "Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source or reverse-engineering a custom format. The flag prefix is slopped{...} and the writeup compilation is at github.com/Abdelkad3r/Anti-SlopCTF-2026."}},
    {"@type": "Question","name": "What's the bug in Polynomial Drift?","acceptedAnswer": {"@type": "Answer","text": "The Rust signing service runs a small capsule VM. For a capsule that pushes integers (1, 2, 3, 4) onto the VM stack, the low 24 bits of the ECDSA nonce equal (4 << 16) | (3 << 8) | preview_byte, where preview_byte is returned in the response. That's a 24-bit-per-signature leak on a 256-bit curve, well within the Hidden Number Problem regime. Collect 11+ signatures, build a CVP lattice, solve with fpylll, recover the private key, sign the auth challenge to win."}},
    {"@type": "Question","name": "How does the Hidden Number Problem lattice work?","acceptedAnswer": {"@type": "Answer","text": "ECDSA gives k_i = z_i / s_i + (r_i / s_i) · d (mod n). Split k_i = K_i + 2^24 · t_i where K_i is the known low 24 bits. Then 2^24 · t_i ≡ a_i · d + b_i (mod n). The unknowns are d (shared) and one t_i per signature (each ~232 bits, much smaller than n). That's a CVP on an (m+1)-dimensional lattice solvable by fpylll BKZ-20 with m = 11 signatures."}},
    {"@type": "Question","name": "Why are 11 signatures enough for secp256k1?","acceptedAnswer": {"@type": "Answer","text": "The HNP success threshold is roughly signatures × leaked_bits > 2n. For secp256k1, 2n = 512. With 24 bits leaked per signature you need ~22 signatures in the naive bound, but the lattice typically succeeds well below that. Eleven was sufficient in practice."}},
    {"@type": "Question","name": "Why is the diag key a decoy in Polynomial Drift?","acceptedAnswer": {"@type": "Answer","text": "The diag endpoint signs status payloads with a separate key whose nonces look random. The commit-signing path uses the main key and has the VM-preview leak. The challenge rewards attackers who pick the right target; a first-pass attempt against diag wastes time."}},
    {"@type": "Question","name": "What's the bug in Sealed Signal?","acceptedAnswer": {"@type": "Answer","text": "Two capsule families (resume and cache) share the same CBC-MAC key. The cache signer is a chosen-message oracle: it computes MAC(CACHE::SIGNME::! || attacker_blob). The fixed 16-byte header was meant to separate domains, but it's exactly one AES block, so its CBC-MAC contribution is a single chaining state H that the attacker measures. Sending B0 = P0 XOR H cancels H in the chaining, and the cache signer's output state matches the resume MAC's output state on the same plaintext."}},
    {"@type": "Question","name": "Why doesn't the scope=flag filter stop the splice?","acceptedAnswer": {"@type": "Answer","text": "The filter runs on the literal cache-signing request blob. The splice never asks the signer to sign anything containing scope=flag; it asks the signer to sign (P0 XOR H), then (T1 XOR P2 XOR H), etc. Both look pseudorandom at the content layer. The forbidden substring only appears in the resume capsule plaintext that the splice constructs the MAC for, which the cache signer never sees."}},
    {"@type": "Question","name": "Why is admin not enough? Why does the flag gate require root?","acceptedAnswer": {"@type": "Answer","text": "The resume state machine accepts several role strings and reports the resumed role back to the client. admin resumes successfully and the server confirms role=admin. But FLAGREQ checks specifically for role=root. The plaintext substitution is straightforward (change role=admin to role=root and rebuild the splice), but it's a real trap because the resumed-state line is misleadingly affirming."}},
    {"@type": "Question","name": "Could you fix Sealed Signal without changing the MAC construction?","acceptedAnswer": {"@type": "Answer","text": "Not robustly. The fundamental problem is that the cache signer's chaining state is interoperable with the resume MAC's chaining state under one XOR cancellation. The principled fix is HMAC or CMAC with key separation between domains. A weaker workable fix is a secret per-domain prefix, but that's brittle."}},
    {"@type": "Question","name": "Where can I find the full solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Solvers for both crypto challenges are at github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/crypto. Polynomial Drift's solve.py includes the capsule encoder, signature collection loop, CVP/lattice setup with fpylll, key recovery and verification, and the final auth flow. Sealed Signal's exploit.py includes the R1 frame builder with nibble swap and dialect XOR, the empty-blob probe for H, the two-query splice, and the resume-then-FLAGREQ chain."}},
    {"@type": "Question","name": "What is the broader lesson from the Anti-Slop CTF crypto track?","acceptedAnswer": {"@type": "Answer","text": "Both bugs are leaks at the seam between an authenticated layer and the layer underneath. ECDSA is sound; the VM that derives the nonce isn't disciplined about what it leaks. CBC-MAC is sound for fixed-domain messages; the cache and resume domains aren't actually separate. The cryptographic primitives are fine, but the integration layer leaks the inputs the primitive assumed were secret. Audit the integration layer at least as carefully as the primitive."}}
  ]
}
</script>
