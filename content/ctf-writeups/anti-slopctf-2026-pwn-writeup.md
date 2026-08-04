---
title: "Anti-Slop CTF 2026 Pwn Writeup: Paper Lantern, Graceful Exit, Anchorpoint"
slug: "anti-slopctf-2026-pwn-writeup"
description: "Step-by-step pwn writeups for Anti-Slop CTF 2026. Paper Lantern Bellcore CRT fault, Graceful Exit leak-and-overwrite, Anchorpoint five-stage VM-to-GCM forge chain."
date: 2026-06-22T20:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["Anti-Slop CTF 2026"]
tags:
  - "anti-slop ctf"
  - "anti-slopctf 2026"
  - "pwn"
  - "binary exploitation"
  - "bellcore fault attack"
  - "crt rsa fault"
  - "aes gcm nonce reuse"
  - "ghash recovery"
  - "ecdsa nonce recovery"
  - "heap object overwrite"
  - "leak primitive"
keywords:
  - "anti-slop ctf 2026 pwn writeup"
  - "anchorpoint writeup"
  - "graceful exit writeup"
  - "paper lantern writeup"
  - "bellcore rsa crt fault attack ctf"
  - "rsa fdh sign forge ctf"
  - "aes gcm nonce reuse ghash recovery"
  - "ecdsa affine nonce recurrence"
  - "stack vm output overflow"
  - "report pointer overwrite ctf"
  - "negative back reference leak"
  - "ctf pwn step by step"
toc: true
cover:
  image: "/images/articles/anti-slopctf-2026-pwn-writeup.png"
  alt: "Anti-Slop CTF 2026 pwn writeup — Paper Lantern Bellcore CRT, Graceful Exit leak-and-overwrite, Anchorpoint VM-to-GCM forge chain"
---

In this **CyberSecurity Elite** pwn writeup, we solve **Anti-Slop CTF 2026**'s three binary-exploitation challenges end to end. Third post in the Anti-Slop CTF 2026 series. The [web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/) covered HTTP parsers. The [reverse writeup](/ctf-writeups/anti-slopctf-2026-reverse-writeup/) covered an ECDSA nonce attack and a SHA-256 length extension. This one walks the three pwn challenges in the same step-by-step format.

The order below is roughly easiest to hardest. **Paper Lantern** is a clean single-chain CRT-fault attack against an RSA-FDH signer. **Graceful Exit** composes a negative-offset leak with a heap-object overwrite to convert an address disclosure into a controlled read through the legitimate output path. **Anchorpoint** is the marathon: a tiny stack-VM overflow unlocks ECDSA nonce recovery, a BIP340-style shadow proof, and an AES-GCM nonce-reuse GHASH forge, all chained into one connection. All three rewarded reading the binary and modelling the state machine before writing any exploit code.

Artefacts, the stripped ELFs, the capsule format helpers, and the full Python exploits are all at [Abdelkad3r/Anti-SlopCTF-2026/pwn](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/pwn).

## The three pwn challenges

| Challenge | Bug class | Points | Flag |
|---|---|---|---|
| Paper Lantern | CRT-RSA-FDH signer with a fault primitive in the comment path; one faulty signature factors `n` via Bellcore, then forge a signature on the `0x7f` opcode the SIGN path refused | unspec. | `slopped{faulted_crt_seams_burn_open}` |
| Graceful Exit | Signed back-reference in the VIEW preview stream leaks a flag pointer and length; symbol-name copy overwrites a 0x80-byte plan object so `fetch` returns the flag through the normal report path | 490 | `slopped{previewed_offsets_can_reseal_reports}` |
| Anchorpoint | Five composed primitives: VM opcode `0x50` writes past a 64-byte buffer into adjacent state, ECDSA quotes with affine nonces leak the key, BIP340 shadow proof, frozen GCM seal nonce lets a two-block GHASH forge stand in for the root capsule | 448 | `slopped{shadow_quote_ghash_rootcapsule}` |

Three different shapes of bug class. Paper Lantern is a pure cryptographic-fault attack with one entry point. Graceful Exit is the classic CTF leak-then-overwrite. Anchorpoint is a five-stage chain where each stage's primitive is harmless on its own and only the full composition reaches the flag. If you only read one section, read Anchorpoint. It's the clearest example I've seen of a memory-corruption bug used purely as a *state machine unlock* rather than as a control-flow primitive.

## Methodology — read the binary, model the state, then write exploit code

A pattern that worked across all three challenges: don't write a single line of exploit code until you can sketch the protocol state machine and identify exactly which transitions the bug unlocks. Pwn challenges that look like "find a buffer overflow" usually aren't; they're "find the buffer overflow, then notice that the bytes it lets you write are the ones that gate the cryptographic state machine three steps deeper." That's the entire Anchorpoint shape, and it shows up in milder forms in the other two.

The other pattern: cryptographic primitives in pwn challenges are almost always implemented with one specific weakness, not a generic break. CRT-RSA without verification is a 1996 attack. AES-GCM nonce reuse is a single-line catastrophic break. ECDSA with biased nonces collapses to a linear system. The pwn challenges in this track each pick one of those well-known weaknesses and ask you to compose it with a memory-corruption primitive that gets you into a position to trigger it.

Per-challenge walkthroughs below.

## Paper Lantern

### The setup

A capsule VM service listening over TCP. The handout includes `capsule.py` (the client-side framing helper), the stripped server binary `paper_lantern`, and a `public_params.json` advertising the signature scheme. The interesting frame types from `capsule.py`:

```
FT_HELLO       0x10
FT_ACK_STRICT  0x12
FT_NEWCAP      0x20
FT_APPEND      0x21
FT_SIGN        0x22
FT_COMMENT     0x23
FT_RUN         0x24
```

The wire protocol is simple. Send `HELLO`, ack into strict mode, then build capsules with `NEWCAP` + `APPEND` records, ask the server to sign the audit hash with `SIGN`, and execute with `RUN`. The flag opcode is `0x7f`. The `SIGN` path explicitly rejects capsules containing `0x7f`. The `RUN` path doesn't check the opcode list at all; it just verifies the audit signature.

So the win condition is "produce a valid signature for a capsule audit that includes opcode `0x7f`". The signer refuses to give it to you. You have to forge one.

### Step 1 — Read the signature scheme

`public_params.json`:

```json
{
  "scheme": "crt-rsa-fdh",
  "e": 65537,
  "signature_size": 64
}
```

CRT-RSA-FDH means the signer uses the Chinese Remainder Theorem to compute `s = m^d mod n` faster (signing once mod `p`, once mod `q`, combining via CRT) and the message representative `m` is a Full-Domain Hash mapped into `Z_n`. The FDH construction is documented in the binary's tagged-hash strings:

```
d = SHA256(audit)
m = SHA256("paper-lantern/v4:msg" + d) ||
    SHA256("paper-lantern/v4:aux" + d)
m = m mod n
```

For a signature `s` to verify:

```
s^e mod n == m
```

No padding, no salt. Once you have `(p, q)`, you can sign any audit you want.

### Step 2 — Trigger the CRT fault

CRT-based signing computes `s_p = m^d mod p` and `s_q = m^d mod q` then combines via Garner's formula. If either half is corrupted (a single bit flip, a wrong limb in the multiplication, anything), the final `s` verifies modulo one prime and not the other. That's the precondition for the Bellcore attack (Boneh–DeMillo–Lipton, 1996): given a single faulty signature, `gcd(s^e − m, n)` reveals one prime factor of `n`.

The challenge's fault primitive lives in the COMMENT/REPLAY path. Specifically, a `COMMENT` record's literal data plus a "braid fill" call can be made to write past the comment buffer into a small block of signer fault-control fields. Reversing the binary turns up four fields that gate the fault:

```
enable   = 1     # enable the fault injection branch
branch   = 0     # which CRT half to corrupt
amount   = 1     # bit count to flip
align    = 5     # offset within the limb
checksum = 107   # required to pass an internal sanity gate
```

Producing those values in the buffer right after the comment literal is a small dance. The recipe that worked:

```
comment_literal(64 zero bytes)
comment_braid_fill(17, 0)
# then explicit suffix XOR operations that land the four bytes above
```

After the comment frame settles, signing any safe audit produces a faulty CRT signature. A "safe audit" is anything that doesn't contain `0x7f` and that the signer is willing to sign. The smallest one I used was the audit for the bytes `T\x02hiH`.

### Step 3 — Factor `n` via Bellcore

With the faulty signature `s_bad` in hand, compute the expected message representative `m` from the same FDH derivation, then:

```python
from math import gcd

def bellcore_factor(n, e, m, s_bad):
    candidate = pow(s_bad, e, n)
    g = gcd((candidate - m) % n, n)
    if 1 < g < n:
        return g, n // g
    return None
```

The challenge's `n` factored into:

```
p = 82757585072455028579685401889888615758895788003223315567334952176806753515189
q = 71296171568667776680278779905104901035842966603378173362597119862250613420693
```

Compute the private exponent:

```python
from math import gcd
lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
d = pow(e, -1, lam)
```

`d` is now the actual signing key. The signer is moot.

### Step 4 — Forge the unsafe-capsule signature and RUN

The audit blob for a minimal single-`0x7f` capsule is just `b"F"` (the binary's hash derivation produces this short token for a one-record capsule with the flag opcode and a halt). Build the FDH representative:

```python
import hashlib

audit = b"F"
d_hash = hashlib.sha256(audit).digest()
m_bytes = (
    hashlib.sha256(b"paper-lantern/v4:msg" + d_hash).digest()
    + hashlib.sha256(b"paper-lantern/v4:aux" + d_hash).digest()
)
m = int.from_bytes(m_bytes, "big") % n
s_forged = pow(m, d, n)
```

Send a fresh `NEWCAP` with two records (the `0x7f` flag opcode plus a halt), submit the forged signature via `FT_RUN`, and the server executes the capsule:

```
slopped{faulted_crt_seams_burn_open}
```

### Why Paper Lantern works

Two design decisions compose into the win.

The unsafe opcode filter is on the signing path only, not on the execution path. The author's intent was probably "audit-time prevention is enough because anything we sign is known-safe." That assumption holds only if signatures are unforgeable. Bellcore says a CRT signer that doesn't sign-verify before returning is forgeable from a single faulty output. Either gate would have closed the chain on its own: a sign-verify before returning would refuse the faulty signature, or a per-opcode allow-list on the RUN path would refuse the flag opcode regardless of who signed it.

The fault primitive is the entry. The actual flag is the consequence. That's the shape this challenge teaches: memory corruption isn't always RIP control. Sometimes it's a single byte that switches a CRT branch into the fault branch, and the cryptographer takes it from there.

## Graceful Exit

### The setup

A capsule loader speaking GORF-framed packets. Every request looks like:

```
"GORF" || type:u16le || flags:u16le || length:u32le || crc:u32le || body
```

Pre-`hello` the CRC seed is the fixed constant `0x714a5c21`. After `hello`, the server responds with `nonce=<8 hex digits>` and that nonce becomes the CRC seed for every subsequent frame. Sending a frame with the pre-`hello` seed after the handshake produces "bad crc" responses that swallow real bugs.

Capsules are `GFC2`-headed blobs with a section table. The exploit only needs five sections:

```
LITR  literal data
CODE  bytecode entries
SYMS  symbol metadata
FIXS  fixup data
VIEW  preview stream
```

The intended use is "load a capsule, audit it, preview rendered output, fetch a report". The bug pair lives in the VIEW preview stream and the SEAL command's symbol-name copy.

### Step 1 — Build a leak capsule

The preview engine keeps a 16-byte seed block in memory immediately before the preview output buffer. The `VIEW` stream supports a back-reference opcode that copies bytes from earlier in the rendered output, with a *signed* offset. The signed-offset check is where the bug lives; negative offsets walk before the start of the output buffer into the seed block, and through it into whatever lies before.

The minimal leak stream is:

```
0x11               # back-copy opcode
sleb(-0x20)        # signed back offset: 32 bytes before the preview start
uleb(0x80)         # unsigned length: 128 bytes
0x00               # null terminator / record end
```

That asks the renderer to copy 128 bytes starting at `preview_buffer - 32`. In practice, the first 32 bytes of the leak are the most interesting:

```
leak[0:8]    XOR seed for the flag pointer (rotating obfuscation)
leak[8:16]   encoded flag page pointer
leak[24:28]  flag length
```

The pointer is XOR-encoded against the seed and a hardcoded tag. Decode:

```python
xor_seed = int.from_bytes(leak[0:8], "little")
encoded  = int.from_bytes(leak[8:16], "little")
flag_ptr = encoded ^ xor_seed ^ 0x736565645f676f72  # "_or_dees" backwards
flag_len = int.from_bytes(leak[24:28], "little")
```

### Step 2 — Land the leak through the live nonce

Roll the connection through `hello`, parse the `nonce=` token, switch the CRC seed to it for all subsequent frames. Load the leak capsule, send the VIEW render command, parse `flag_ptr` and `flag_len` from the response. These two values are everything you need; the leak capsule is otherwise harmless and audits clean.

### Step 3 — Build the overwrite capsule

The SEAL command produces a sealed report from a "plan" object allocated server-side. The plan object is 0x80 bytes and is laid out roughly as:

```
plan + 0x00..0x30   bookkeeping
plan + 0x30         cookie         (8 bytes)
plan + 0x38         report_ptr     (8 bytes)
plan + 0x40         report_len     (8 bytes)
plan + 0x48..0x7c   internal state
plan + 0x7c         finished flag  (1 byte)
```

`fetch` reads `report_ptr` for `report_len` bytes and returns the content to the client, gated by the cookie at `plan + 0x30` and the finished flag at `plan + 0x7c`.

The bug is that the SEAL path copies the SYMS record's symbol name over the plan allocation without bounding the copy to anything smaller than the plan size. The symbol name is attacker-controlled (it's metadata about a capsule symbol you defined). A symbol name of exactly the right length and content overwrites the plan object's `report_ptr`, `report_len`, `cookie`, and `finished flag` in one copy.

The crafted symbol name:

```
bytes 0x30..0x38     chosen cookie (we control it so we can pass it to fetch)
bytes 0x38..0x40     leaked flag_ptr (little-endian 8 bytes)
bytes 0x40..0x48     leaked flag_len (little-endian 8 bytes)
bytes 0x7c           0x01 (mark finished)
```

The padding bytes between can be zero. The overall symbol-name length plus the SYMS framing constants needs to land the controlled fields at the right plan offsets; one constant offset adjustment is the only fiddly part.

### Step 4 — Audit, seal, fetch

The standard flow finishes the chain:

1. Load the overwrite capsule.
2. `audit` the capsule.
3. `seal` the capsule, which triggers the symbol-name copy over the plan object.
4. `fetch` with the chosen cookie, which the server validates against `plan + 0x30` (now set to the value we baked in).

The server reads `plan + 0x38` as `report_ptr`, `plan + 0x40` as `report_len`, sees the finished flag set, and returns:

```
slopped{previewed_offsets_can_reseal_reports}
```

The flag is read out of the legitimate output path, with no shellcode, no ROP, no syscalls invoked from attacker-supplied bytecode. The plan-object overwrite turned the normal `fetch` command into a controlled read at the exact address we leaked.

### Why Graceful Exit works

Neither bug is exploitable alone.

The negative-offset leak alone gives you a few bytes of disclosed memory but no way to act on them. The encoded pointer is XOR'd against a seed in the same block, so even reading the leaked bytes requires knowing the obfuscation. The pointer-to-flag is in the same disclosure window, which is suspicious from a code-design perspective and is the kind of layout that an internal audit should flag.

The symbol-name-over-plan overwrite alone gives you control of `report_ptr` and `report_len`, but those are useless until you know where to point them. Without the leak, you'd be writing a wild pointer into the plan and getting a SEGV or a junk read.

Together they're the classic CTF leak-and-overwrite. The defender fix for either bug closes the chain. Bound the back-reference copy to a non-negative offset. Or bound the symbol-name copy to its declared length. Either one independently makes the other primitive harmless.

## Anchorpoint

### The setup

A multi-stage service speaking a tiny AP packet protocol:

```
"AP" || type:u8 || length:u16le || checksum:u8 || payload
```

The checksum is a non-cryptographic rotate-left mix of `(type, length, payload bytes)`. After the initial info packet, the service ships enough VM seed material to encode bytecode that runs inside a small per-connection VM. The wire interface exposes a handful of commands beyond the VM:

```
QUOTE       — request an ECDSA-style signed payload
SHADOW      — submit a BIP340-style proof tied to a chain of quotes
CAPSULE     — submit an AES-GCM sealed capsule
FREEZE      — freeze the seal nonce (gated by service state)
FLAG        — only returns the flag if shadow and a root capsule are both valid
```

Each command is gated by a corresponding "budget" or "unlock" byte in server-side state. The legitimate API exposes some of those budgets but not all. The bug is a tiny VM overflow that gives you the rest.

### Step 1 — Trigger the VM output overflow

The VM has three opcodes that matter:

```
0x10 <byte>   # load literal byte into the working register
0x50          # append working register to the response buffer
0x70          # halt
```

`0x50` writes to a 64-byte response buffer with no bounds check past 64. Writing 64 + N bytes spills into the N bytes of adjacent state immediately following the response buffer. Reversing that adjacent state surfaces three useful fields:

```
response[64]   quote budget       (write 1+ to enable QUOTE)
response[67]   shadow unlock byte (write 1 to enable SHADOW)
response[X]    capsule budget     (write 1+ to enable CAPSULE)
response[Y]    seal nonce freeze  (write 1 to freeze the GCM nonce)
```

A capsule containing `0x10 0x01 0x50` × 68 followed by `0x70` writes 68 bytes of `0x01` into the buffer, putting `1` at every overflowed state byte. That single capsule unlocks all four downstream commands. The actual offsets in the binary (X, Y, plus the precise byte values needed) come out of reading the VM's response-buffer struct in the disassembly; the README captures the practical recipe.

### Step 2 — Collect four quotes and recover the quote key

`QUOTE` returns a payload terminated by a 64-byte ECDSA-style `(r, s)` pair. The signing curve is secp256k1. The nonce follows an affine recurrence:

```
k[i+1] = a * k[i] + b   (mod n)
```

For any ECDSA signature, the relation is:

```
k[i] = (e[i] + r[i] * d) / s[i]   (mod n)
```

with `d` the unknown private key. Substituting the affine recurrence relation across three consecutive nonces produces a relation:

```
k[2] - k[1] = a * (k[1] - k[0])
k[3] - k[2] = a * (k[2] - k[1])
```

Dividing eliminates `a`:

```
(k[2] - k[1])^2 = (k[3] - k[2]) * (k[1] - k[0])
```

That's quadratic in `d` after substituting the ECDSA relation. Solving the quadratic modulo the secp256k1 order gives two candidate values of `d`; the right one is the value whose `d * G` matches the x-only public key from the service's info packet.

```python
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def candidate_d(quotes, public_x):
    # quotes is a list of (e_i, r_i, s_i); need 4 of them
    # build the quadratic in d, solve mod N, pick the candidate
    # whose d*G matches public_x
    ...
```

The recovered `d` matched the published quote public key.

### Step 3 — Build the shadow proof

The shadow gate is BIP340-style Schnorr. The message is derived from a rolling hash of quote payloads, the epoch, a counter, and a "crumb" intermediate:

```
chain[0]   = 32 zero bytes
chain[i+1] = sha256(chain[i] || quote_payload[i])
crumb      = tagged_hash("Anchorpoint/shadow-crumb",
                         epoch || counter || chain)
msg        = tagged_hash("Anchorpoint/shadow-msg",
                         epoch || counter || chain || crumb)
```

`tagged_hash(tag, data)` is the BIP340 construction `sha256(sha256(tag) || sha256(tag) || data)`. With `d` recovered, signing `msg` with `d` produces the Schnorr signature the verifier expects. Submit:

```
a7 34 || counter || crumb || schnorr_signature
```

The shadow gate is now open. Trying to claim the flag with a regular capsule at this point returns:

```
root capsule required
```

The shadow proof is necessary but not sufficient.

### Step 4 — Trigger the root capsule error to learn the AAD

Submitting a normal post-shadow capsule (the standard `capsule|epoch` AAD) returns:

```
root aad
```

That tells you the final capsule has to use a different AAD. Reversing the FLAG handler surfaces the expected AAD format:

```
rootcaps|epoch|counter_byte
```

You also need a capsule whose plaintext is whatever the FLAG handler expects to find inside. The plaintext is checked against a small server-side derivation that depends on the epoch and counter; for the live solve it's a 16-byte "root target" the handler regenerates per request. The exploit needs to forge an AES-GCM tag for that specific (AAD, plaintext) pair under the server's key.

### Step 5 — Reuse the frozen GCM nonce to recover GHASH material

This is where the VM overflow earns its keep. With `seal nonce freeze = 1`, the server reuses the same 12-byte GCM IV across capsule submissions. AES-GCM is catastrophically broken under nonce reuse, and the specific break is straightforward for known plaintexts.

The GCM tag for a one-block ciphertext `C` with AAD `A` and nonce `J0` is:

```
tag = E_K(J0) XOR GHASH(H, A, C)
```

where `H = E_K(0^128)` is the hash subkey. For two one-block capsules `(C_0, tag_0)` and `(C_1, tag_1)` sealed under the *same* nonce and the *same* AAD:

```
tag_0 XOR tag_1 = GHASH(H, A, C_0) XOR GHASH(H, A, C_1)
                = (C_0 XOR C_1) * H^2  in GF(2^128)
```

(The `H^2` factor comes from GHASH's polynomial evaluation; the AAD block contributes the same value to both GHASH computations because the AAD bytes are identical, so it cancels.)

That gives:

```
H^2 = (tag_0 XOR tag_1) / (C_0 XOR C_1)   in GF(2^128)
H   = sqrt(H^2)                            in GF(2^128)
```

GF(2^128) square roots are straightforward; the field has odd order minus one in the multiplicative group, so squaring is an automorphism and `sqrt(x) = x^(2^127)`. With `H` recovered:

```
E_K(J0) = tag_0 XOR GHASH(H, A_0, C_0)
```

Now the attacker has both `H` and `E_K(J0)`. They can compute the correct tag for any new `(AAD', C')` pair under the same nonce.

### Step 6 — Forge the root capsule

Use the recovered `H` and `E_K(J0)` to compute the GCM tag for the `rootcaps|epoch|counter_byte` AAD over the chosen root ciphertext (encrypted to match the expected root target). Encode as a capsule and submit it after the shadow proof in the same connection.

```python
def forge_gcm(H, EK_J0, aad, ciphertext):
    return EK_J0 ^ ghash(H, aad, ciphertext)
```

The full chain in a single connection:

1. Send the overflow capsule to unlock everything.
2. Collect four quotes, recover the quote private key, verify against the public key.
3. Compute the shadow message, sign with the recovered key, submit the shadow proof.
4. Submit two one-block capsules under the frozen GCM nonce with identical AAD and known plaintexts.
5. Recover `H` and `E_K(J0)` from the two tags.
6. Compute the forged tag for the root capsule `(rootcaps|epoch|counter_byte, root_ciphertext)`.
7. Submit the root capsule, then the FLAG request.

Response:

```
slopped{shadow_quote_ghash_rootcapsule}
```

### Why Anchorpoint works

The whole point of the challenge, and the lesson worth carrying out of it, is that memory corruption isn't the win. It's the unlock. A 4-byte overflow into adjacent state opened four gates simultaneously: quote budget, shadow unlock, capsule budget, seal-nonce freeze. Without any one of those four gates open, the chain stalls. With all four open, the actual flag requires three separate cryptographic exploitation primitives (ECDSA affine-nonce recovery, BIP340 signing with the recovered key, AES-GCM nonce-reuse GHASH forge), each of which is its own multi-page writeup in the wider CTF literature.

The defender lessons are layered. The VM should bounds-check writes to the response buffer (`memcpy`-with-explicit-size or `min(remaining, requested)`). The ECDSA signer should use RFC 6979 instead of an affine PRNG. The GCM seal path should never reuse a nonce, and if a "freeze" command exists for testing purposes it should be compiled out of production. The flag handler should check the root capsule's AAD format at the audit time, not in an error string after the fact.

Each one of those individually breaks the chain.

## Cross-cutting defender notes

Three patterns recur across all three pwn challenges, with direct analogues in production code.

**Memory corruption unlocks state, it doesn't always control flow.** The Anchorpoint VM overflow doesn't get you RIP; it gets you four bytes of attacker-chosen state at four specific server-side offsets. That's enough. Every modern code-review rubric still focuses on "can this overflow reach a return address" and underweights "can this overflow write into the field next door". Container objects, plan structs, configuration blocks, capability tables: all of those have adjacent gating fields that are far softer targets than the saved RIP. Review for adjacency, not just for overflow.

**Cryptographic primitives in custom protocols almost always pick the one historically-weak variant.** Paper Lantern's CRT-RSA-FDH without sign-verify is the 1996 Bellcore bug. Anchorpoint's ECDSA with affine-recurrence nonces is the broader family of polynomially-biased nonces. The AES-GCM nonce reuse in Anchorpoint's seal path is the single-line catastrophic-break case for GCM. None of these are subtle; all of them are catalogued in any textbook chapter on the relevant primitive. Reviewers should treat any custom signature scheme or AEAD usage as a yellow flag and run through the textbook attacks for the specific primitive before clearing the design.

**Audit-time checks need to apply at run-time too.** Paper Lantern's `0x7f` filter was on `SIGN` only; `RUN` trusted any valid signature. Graceful Exit's plan-object integrity check was on a `cookie` field that the same overwrite controlled. The principle is "any check that's not redundant with a runtime check is bypassable as soon as one signing or authentication path leaks". Bind the check to the actual usage site, not to an earlier gate.

## Frequently asked questions

### What is Anti-Slop CTF?

Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source or reverse-engineering a custom format. The flag prefix is `slopped{...}` and the writeup compilation is at [Abdelkad3r/Anti-SlopCTF-2026](https://github.com/Abdelkad3r/Anti-SlopCTF-2026).

### What's the bug in Paper Lantern?

The CRT-based RSA-FDH signer doesn't verify its own output before returning it. A fault primitive in the COMMENT path lets you trigger a single-prime CRT computation fault. The resulting faulty signature gives `gcd(s^e − m, n) = p`, factoring the modulus by the Bellcore attack (Boneh–DeMillo–Lipton, 1996). With `(p, q)` you compute the private exponent and forge a valid signature for any audit, including a capsule containing the `0x7f` flag opcode that the `SIGN` path refused.

### How does Bellcore factor an RSA modulus from one faulty signature?

If the CRT signer computes `s_p = m^d mod p` correctly but `s_q` incorrectly, the combined signature `s` satisfies `s^e ≡ m (mod p)` but not `(mod q)`. So `s^e − m` is a multiple of `p` and not a multiple of `q`. Therefore `gcd(s^e − m, n) = p`. Defended by sign-then-verify before returning, which costs one extra modular exponentiation and turns the attack into a denial of service instead of a key compromise.

### What's the bug pair in Graceful Exit?

Two independent bugs that compose. The VIEW preview engine accepts a signed back-reference offset, including negative values, which lets you copy bytes from before the preview buffer — including a 16-byte seed block containing an XOR-obfuscated pointer to the flag page and the flag length. Separately, the SEAL path copies a SYMS record's symbol name over the 0x80-byte plan object, letting an attacker overwrite the plan's `report_ptr` (offset 0x38), `report_len` (offset 0x40), `cookie` (offset 0x30), and `finished` flag (offset 0x7c). Combining: leak the flag pointer, overwrite the plan with that pointer, call `fetch` to read through the normal output path.

### Why does the GORF nonce matter for the CRC seed?

Pre-`hello` frames use a fixed CRC seed (`0x714a5c21`). The `hello` response contains a `nonce=<8 hex digits>` token that becomes the CRC seed for every subsequent frame. If your exploit keeps using the pre-`hello` seed after handshake, every later frame returns "bad crc" and you'll waste time hunting nonexistent bugs. Parse the nonce, swap the seed, then send your exploit frames.

### What's the bug chain in Anchorpoint?

A 4-byte VM overflow on opcode `0x50` writes past a 64-byte response buffer into adjacent server state, unlocking four downstream gates: quote budget, shadow unlock, capsule budget, and seal-nonce freeze. With QUOTE open, the ECDSA signer leaks four signatures whose nonces follow an affine recurrence `k[i+1] = a*k[i] + b`; the recurrence reduces to a quadratic in `d` solvable modulo the secp256k1 order. With the quote key recovered, the BIP340-style shadow proof signs. The frozen GCM seal nonce lets two same-AAD same-nonce capsules leak `H^2` and `E_K(J0)` via the standard GHASH attack, enabling a tag forge on the root capsule AAD. Submit shadow and forged root capsule, get the flag.

### How does AES-GCM nonce reuse leak the hash subkey?

For two one-block GCM ciphertexts `C_0` and `C_1` sealed under the same nonce and same AAD, `tag_0 XOR tag_1 = (C_0 XOR C_1) * H^2` in GF(2^128), because the `E_K(J0)` term cancels and the AAD contribution is identical. Dividing gives `H^2`; the square root in GF(2^128) is `(H^2)^(2^127)` since squaring is an automorphism. With `H` you can compute `E_K(J0) = tag_0 XOR GHASH(H, AAD_0, C_0)` and then forge tags for any new `(AAD', C')` under the same nonce.

### Why does the VM overflow only need four bytes?

The four adjacent state bytes I needed (quote budget, shadow unlock, capsule budget, seal-nonce freeze) all happen to live within the same small struct that follows the response buffer in memory. Writing 68 bytes of value `1` covers all four offsets in one go. The exact offsets come from reversing the response-buffer struct in the binary; the layout is stable across connections because the allocator places the struct in the same arena each time.

### Could you bypass Paper Lantern's signer without the Bellcore fault?

In principle, anything that gives you the private key works. Padding-oracle attacks on FDH are interesting but FDH with `m mod n` has no padding oracle. Direct factoring of the modulus is computationally infeasible for the 256-bit primes used here. RSA-FDH is otherwise sound. The Bellcore fault is the intended (and only practical) path because the signer's CRT implementation provides the fault primitive.

### Where can I find the full solver scripts?

All three solvers, the stripped binaries, the capsule format helpers, and the original handout zips are at [Abdelkad3r/Anti-SlopCTF-2026/pwn](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/pwn). Anchorpoint's `exploit.py` includes the AP framing, the VM encoder, the quote-key recovery, the BIP340 shadow signature, and the GHASH forge helpers. Graceful Exit's `solve.py` includes the GORF framing with nonce handling and the GFC2 capsule builder. Paper Lantern's `solve.py` includes the capsule.py-compatible client, the fault-trigger sequence, the Bellcore factoring step, and the FDH forge.

### What's the broader lesson from the Anti-Slop CTF pwn track?

Memory corruption in modern services is rarely a direct RIP-control bug. It's an unlock for the cryptographic or state-machine surface behind the memory layer. All three challenges punish solvers who fixate on "find the overflow, write shellcode". The actual flag in every case requires modelling the state machine, identifying which transitions the corruption unlocks, then composing the unlocked transitions with whatever cryptographic weakness the protocol shipped. The reviewers' takeaway is that exploit chains in 2026 look more like multi-step protocol forges than like classic stack-smash-and-pivot.

## Closing notes

The pwn track was the longest of the three categories I've written up so far, partly because each challenge composed three or four distinct primitives instead of one. Paper Lantern was an afternoon of reading and a couple of hours of fault-trigger fiddling. Graceful Exit was a clean evening once the nonce-seed quirk stopped wasting frames. Anchorpoint was the engineering challenge: not because any single stage was hard, but because the chain only succeeds when all five stages land in one connection without timing out.

For more pwn writeups on this site, the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) covers `recipe-for-disaster` (a `gets()` overflow into an adjacent `int` price field) which is the same "adjacent-field overwrite" pattern at the cheap end of the spectrum. The companion [Anti-Slop CTF web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/) and [reverse writeup](/ctf-writeups/anti-slopctf-2026-reverse-writeup/) cover the other four challenges from this event. Full [CTF writeups index](/ctf-writeups/) for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is Anti-Slop CTF?","acceptedAnswer": {"@type": "Answer","text": "Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source or reverse-engineering a custom format. The flag prefix is slopped{...} and the writeup compilation is at github.com/Abdelkad3r/Anti-SlopCTF-2026."}},
    {"@type": "Question","name": "What's the bug in Paper Lantern?","acceptedAnswer": {"@type": "Answer","text": "The CRT-based RSA-FDH signer doesn't verify its own output before returning. A fault primitive in the COMMENT path triggers a single-prime CRT computation fault. The faulty signature gives gcd(s^e − m, n) = p, factoring the modulus by the Bellcore attack. With (p, q) you forge a valid signature for any audit, including a capsule containing the 0x7f flag opcode."}},
    {"@type": "Question","name": "How does Bellcore factor an RSA modulus from one faulty signature?","acceptedAnswer": {"@type": "Answer","text": "If the CRT signer computes s_p correctly but s_q incorrectly, the combined signature s satisfies s^e ≡ m (mod p) but not (mod q). So s^e − m is a multiple of p and not q. Therefore gcd(s^e − m, n) = p. Defended by sign-then-verify before returning."}},
    {"@type": "Question","name": "What's the bug pair in Graceful Exit?","acceptedAnswer": {"@type": "Answer","text": "Two bugs compose. The VIEW preview engine accepts signed back-reference offsets including negative values, leaking a 16-byte seed block with an XOR-obfuscated flag pointer and length. The SEAL path copies a SYMS record's symbol name over the 0x80-byte plan object, letting you overwrite report_ptr (0x38), report_len (0x40), cookie (0x30), and finished flag (0x7c). Leak then overwrite then fetch through the normal output path."}},
    {"@type": "Question","name": "Why does the GORF nonce matter for the CRC seed?","acceptedAnswer": {"@type": "Answer","text": "Pre-hello frames use a fixed CRC seed (0x714a5c21). The hello response contains nonce=<8 hex digits>, which becomes the CRC seed for every subsequent frame. Using the pre-hello seed after handshake produces bad crc responses on every later frame."}},
    {"@type": "Question","name": "What's the bug chain in Anchorpoint?","acceptedAnswer": {"@type": "Answer","text": "A 4-byte VM overflow on opcode 0x50 writes past a 64-byte response buffer into adjacent state, unlocking quote budget, shadow unlock, capsule budget, and seal-nonce freeze. ECDSA quote nonces follow k[i+1] = a*k[i] + b, reducing to a quadratic in d solvable modulo the secp256k1 order. Recovered key signs the BIP340 shadow proof. Frozen GCM seal nonce lets two same-AAD same-nonce capsules leak H^2 and E_K(J0) via the standard GHASH attack, enabling a tag forge on the root capsule AAD."}},
    {"@type": "Question","name": "How does AES-GCM nonce reuse leak the hash subkey?","acceptedAnswer": {"@type": "Answer","text": "For two one-block GCM ciphertexts under the same nonce and AAD, tag_0 XOR tag_1 = (C_0 XOR C_1) * H^2 in GF(2^128) because E_K(J0) cancels and AAD contribution is identical. Dividing gives H^2; the square root in GF(2^128) is (H^2)^(2^127). With H you compute E_K(J0) = tag_0 XOR GHASH(H, AAD_0, C_0) and forge tags for any (AAD', C') under the same nonce."}},
    {"@type": "Question","name": "Why does the VM overflow only need four bytes?","acceptedAnswer": {"@type": "Answer","text": "The four adjacent state bytes — quote budget, shadow unlock, capsule budget, seal-nonce freeze — all live in the same small struct following the response buffer. Writing 68 bytes of value 1 covers all four offsets at once. Exact offsets come from reversing the response-buffer struct; the layout is stable because the allocator places the struct in the same arena each connection."}},
    {"@type": "Question","name": "Could you bypass Paper Lantern's signer without the Bellcore fault?","acceptedAnswer": {"@type": "Answer","text": "Anything that recovers the private key works. Padding-oracle attacks on FDH don't apply because FDH with m mod n has no padding oracle. Direct factoring of 256-bit primes is computationally infeasible. RSA-FDH is otherwise sound. The Bellcore fault is the intended and only practical path because the signer's CRT implementation provides the fault primitive."}},
    {"@type": "Question","name": "Where can I find the full solver scripts?","acceptedAnswer": {"@type": "Answer","text": "All three solvers, the stripped binaries, the capsule format helpers, and the original handout zips are at github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/pwn. Anchorpoint's exploit.py includes AP framing, VM encoder, quote-key recovery, BIP340 shadow signature, GHASH forge. Graceful Exit's solve.py includes GORF framing and the GFC2 capsule builder. Paper Lantern's solve.py includes the capsule.py-compatible client, fault-trigger sequence, Bellcore factoring, FDH forge."}},
    {"@type": "Question","name": "What is the broader lesson from the Anti-Slop CTF pwn track?","acceptedAnswer": {"@type": "Answer","text": "Memory corruption in modern services is rarely a direct RIP-control bug. It's an unlock for the cryptographic or state-machine surface behind the memory layer. All three challenges punish solvers who fixate on find the overflow, write shellcode. The actual flag requires modelling the state machine, identifying which transitions the corruption unlocks, then composing the unlocked transitions with whatever cryptographic weakness the protocol shipped."}}
  ]
}
</script>
