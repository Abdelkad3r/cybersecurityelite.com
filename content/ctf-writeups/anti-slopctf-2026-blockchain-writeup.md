---
title: "Anti-Slop CTF 2026 Blockchain Writeup: Finality Cache + Canopy Cache"
slug: "anti-slopctf-2026-blockchain-writeup"
description: "Step-by-step blockchain-track writeups for Anti-Slop CTF 2026. Finality Cache: bridge receipt commitment patch. Canopy Cache: PackBits decompression overwrites the bind table after validation."
date: 2026-06-22T22:30:00Z
lastmod: 2026-06-22T22:30:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["Anti-Slop CTF 2026"]
tags:
  - "anti-slop ctf"
  - "anti-slopctf 2026"
  - "blockchain ctf"
  - "bridge protocol"
  - "vm commitment"
  - "packbits decompression overflow"
  - "time of check time of use"
  - "varint patch"
  - "guardian binary"
  - "session lcg xor"
keywords:
  - "anti-slop ctf 2026 blockchain writeup"
  - "finality cache writeup"
  - "canopy cache writeup"
  - "bridge receipt vm commitment patch ctf"
  - "packbits expand overflow bind table"
  - "validator vs consumer split ctf"
  - "session lcg xor stream recovery"
  - "guardian gdb digest recompute"
  - "varint mutation 20000 to 80000"
  - "ctf blockchain step by step"
toc: true
cover:
  image: "/images/articles/anti-slopctf-2026-blockchain-writeup.png"
  alt: "Anti-Slop CTF 2026 blockchain writeup — Finality Cache receipt commitment patch and Canopy Cache PackBits overflow into the bind table"
---

Fifth and final per-category post in the Anti-Slop CTF 2026 series. The earlier writeups covered [web](/ctf-writeups/anti-slopctf-2026-web-writeup/) (HTTP parsers), [reverse](/ctf-writeups/anti-slopctf-2026-reverse-writeup/) (ECDSA nonce attack + SHA-256 length extension), [pwn](/ctf-writeups/anti-slopctf-2026-pwn-writeup/) (Bellcore CRT fault + leak-and-overwrite + GCM forge chain), and [crypto](/ctf-writeups/anti-slopctf-2026-crypto-writeup/) (HNP CVP + CBC-MAC splice). This one walks the two blockchain-track challenges in the same step-by-step format.

A note before starting: "blockchain" here means *bridge-style protocol with custom commitments*, not Solidity smart contracts. There's no Solidity, no Foundry, no EVM. Both challenges ship a custom binary that plays the role of a guardian/relayer service. The bugs are in how those guardians validate and consume bytes, not in any on-chain contract. If you came looking for a reentrancy bug or a TWAP oracle attack, the [SCTF 2026 writeup](/ctf-writeups/sctf-2026-writeup/) is the post you want.

**Finality Cache** is a bridge-receipt forge: edit the claim amount, edit the header amount, recompute the VM commitment to match, redeem the high-value claim. **Canopy Cache** is a TOCTOU between two parsers in different validators, exploited via a PackBits decompression that overwrites the bind table after the bind has already been validated. Both reward reading the binary and treating "the guardian recomputes the commitment locally" as a feature you can use, not a barrier.

Artefacts and per-challenge READMEs live at [Abdelkad3r/Anti-SlopCTF-2026/blockchain](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/blockchain).

## The two blockchain challenges

| Challenge | Bug class | Points | Flag |
|---|---|---|---|
| Finality Cache | Bridge receipt with three-way consistency between lane varint, header amount, and VM commitment digest; guardian recomputes the digest locally so patching all three keeps the receipt valid | 447 | `slopped{wrapped_lane_offsets_expose_seal_keys_then_sign_recursive_checkpoints}` |
| Canopy Cache | Validators disagree about acceptable image offsets; PackBits `expand` opcode passes a compressed-length check but decompresses past the bind-table boundary, retargeting an already-validated bind entry to a forbidden route | 490 | `slopped{packbits_lookup_routes_rethread_the_owner_lane}` |

The shape that connects both: **the trusted commitment is local, and trust comes from "the local commitment matches what I just received".** Bridge protocols and L1 relayers routinely use this pattern because they have to verify state from another chain without trusting the messenger. The bug is the same in both challenges: once an attacker can also locally recompute the commitment over their mutated data, the commitment isn't authenticating anything that the attacker didn't already control.

## Methodology — model the validator-to-consumer pipeline, then find the gap

A pattern that worked for both challenges: don't reach for chain-state manipulation. Reach for *validator-to-consumer diff*. The challenges expose a two-stage flow where the first stage (bind decoder, receipt audit, attest) verifies some property of incoming bytes, and the second stage (route patcher, redeem, audit invocation) acts on those bytes assuming the first stage's property still holds. The bug is always in the gap between stages: a value the first stage trusted that the second stage interprets differently, or a buffer the first stage validated that the second stage lets you rewrite after the fact.

That's the entire shape. Receipt commitments, RLE decompressors, varint-encoded amounts, image offsets. Every one of them is a "second stage trusts first-stage validation" arrangement, and every one of them breaks the same way once you find a primitive that lets the second stage's input drift from the first stage's checked input.

Per-challenge walkthroughs below.

## Finality Cache

### The setup

A guardian binary verifies a bridge receipt and lets the relayer attest + redeem. The receipt is a binary blob carrying:

- A header with a committed amount (little-endian).
- One or more lane programs that reconstruct the claim in the receipt VM.
- A 32-byte VM commitment over the lane programs and metadata.

The guardian:

1. Parses the header amount.
2. Runs the lane programs in the receipt VM to reconstruct the claim.
3. Recomputes the 32-byte commitment locally and compares it to the embedded one.
4. If all three match, signs an attestation and the relayer redeems the claim against an upstream contract.

The challenge gives you a sample receipt for a 20,000-unit claim and asks for an 80,000-unit redemption to win the flag. The naïve "just change the number" attempt fails:

- Change only the header amount: `preview amount mismatch` (the VM-reconstructed claim doesn't match).
- Change only the lane bytes: `ERR bad vm commitment` (the commitment over the lane programs no longer matches the embedded digest).
- Change both header and lanes but leave the commitment alone: same `bad vm commitment` error.

So the exploit has to mutate three things consistently: lane varint, header amount, and VM commitment. The first two are trivial. The third is the work.

### Step 1 — Decode the sample receipt structure

The sample receipt the service hands out is a fixed binary blob with a small header, one or more lane records, and the 32-byte commitment somewhere in a stable position. A quick hexdump and a comparison against the README's offset table give:

```
offset    field
0x00      magic + tiny header
0x??      committed amount (little-endian, header)
0x??..    lane programs (TLV-ish, each lane has a varint amount)
0x3c..0x5b   32-byte VM commitment (the embedded digest)
```

The exact offsets depend on the receipt version, but they're stable across the session sample and the live sample because the format is deterministic.

### Step 2 — Patch the lane varint from 20,000 to 80,000

The lane program contains the claim amount as a varint. For our sample:

```
a0 9c 01    # decoded varint = 20000
```

The varint encoding uses 7 data bits per byte with the high bit as a continuation flag. Decoding `a0 9c 01`:

```
a0 = 1010 0000  -> low 7 bits = 010 0000  = 0x20
9c = 1001 1100  -> low 7 bits = 001 1100  = 0x1c
01 = 0000 0001  -> low 7 bits = 000 0001  = 0x01
combined (LSB-first 7-bit groups):  0x01 << 14 | 0x1c << 7 | 0x20 = 20000
```

Re-encoding 80,000 as a varint:

```
80000 = 0x13880
binary = 0001 0011 1000 1000 0000
7-bit groups (LSB-first):
  group 0: 0000000  -> 0x00
  group 1: 1110001  -> 0x71
  group 2: 0000100  -> 0x04
bytes (set continuation bit on all but last):
  0x80 | 0x00 = 0x80
  0x80 | 0x71 = 0xf1
  0x00 | 0x04 = 0x04
varint = 80 f1 04
```

Both encodings are 3 bytes long, so the patch is a clean in-place 3-byte overwrite at the lane varint offset.

### Step 3 — Patch the header committed amount

The header carries the same amount as a fixed-width little-endian integer (typically 4 or 8 bytes). For 80,000:

```
4-byte LE:  80 38 01 00
8-byte LE:  80 38 01 00 00 00 00 00
```

The README points at the header offset; substitute the bytes in place. The receipt VM's preview now reconstructs an 80,000-unit claim and the header amount matches.

At this point the guardian rejects the receipt with `ERR bad vm commitment`. The commitment at `0x3c..0x5b` is the old digest over the unmutated lane programs.

### Step 4 — Recompute the VM commitment locally

The guardian recomputes the commitment internally during verification. The path of least resistance is to let the guardian do the computation and then dump it back. Run the local guardian under `gdb`, break on the recomputation, single-step until the new digest is in a register or on the stack, and dump it:

```
$ gdb ./guardian
(gdb) break *0x401a7a
(gdb) run --receipt /tmp/patched-receipt.bin
Breakpoint 1, 0x401a7a in ?? ()
(gdb) x/32xb $rsi   # or wherever the recomputed digest lives — check the disasm
```

The 32 bytes that come out are the correct commitment for the mutated lane programs. Patch them into the receipt at offsets `0x3c..0x5b`.

This is the "trust commitment is local" lesson in action. The guardian implements the commitment routine. Anyone with the binary can run that routine on any input. The commitment is therefore *not* an authenticator. It's a self-consistency check that the receipt is internally well-formed. Self-consistency is not authenticity.

A purist alternative is to reverse the commitment routine into Python and recompute without `gdb`. For this challenge it's not worth it. The `gdb` approach takes five minutes; reversing a sponge-style hash with custom personalisation bytes takes hours.

### Step 5 — Submit attest, then redeem

With all three fields consistent, submit the patched receipt to the `attest` command. The guardian verifies header, lanes, and commitment all match, signs the attestation, and the relayer redeems the 80,000-unit claim against the upstream service. The service returns:

```
slopped{wrapped_lane_offsets_expose_seal_keys_then_sign_recursive_checkpoints}
```

The flag's middle phrase is the give-away: "expose seal keys then sign recursive checkpoints." The guardian's commitment routine is the seal key here, and we used it locally to sign a higher-value receipt than any legitimate relayer could produce.

### Why Finality Cache works

The design failure is treating the local commitment recomputation as a source of authority. The guardian believes "if my local recompute matches the embedded commitment, the receipt is genuine." That belief only holds if the embedded commitment came from a source the guardian trusts and the recompute key isn't recoverable from the guardian itself.

Both halves of that fall down here. The commitment is computed from the lane programs and metadata using a function the guardian has in its own binary. There's no MAC key. There's no signature from an upstream chain. The "commitment" is a hash, and the guardian's own implementation of that hash is the only thing it checks against. Anyone with the binary can recompute.

The correct fix is to bind the commitment to something the attacker can't reproduce locally. A signature from an upstream chain validator is the standard one (then verifying the signature is the actual security gate). A keyed MAC with a key the guardian doesn't expose is the minimal version. An unsigned hash over self-contained data is a self-consistency check pretending to be an authentication.

## Canopy Cache

### The setup

A more involved bridge service mixing a WASM-like helper module, a session-encrypted protocol, and a hidden route table. The goal is to make the `audit` command invoke a route the attacker controls while preserving the capability mask the bless step requires.

The architecture has three moving parts:

1. **A mesh module** the attacker uploads. Routes inside this module determine what `audit` actually executes.
2. **A session-encrypted transport** for `warm`, `quote`, and `attest`. Payloads are XOR'd with a key stream derived from a session-LCG seed.
3. **A witness layer** that validates bind operations on the route table. The validator and the patcher have different rules about acceptable image offsets, which is where the bug lives.

The flag requires invoking the controlled route while the slot still has `cap_mask = 0x01` (the blessable bit). Both must hold simultaneously.

### Step 1 — Diff the two validators

The `bind` decoder rejects image offsets above `0x0f`. So any direct bind operation that points the route table at a higher-offset image is refused at validation time.

The later route patcher needs an offset above `0x17` to land in the warm-image region where the desired route bytes can be staged.

Those two rules are mutually exclusive for a single-stage bind. The validator says "below 0x10"; the patcher needs "above 0x17". A direct bind with the desired offset fails. A bind with the validator-acceptable offset doesn't reach the patcher target. The gap between them is the bug, and the exploit has to land an offset above `0x17` *after* the validator has already accepted a bind with offset below `0x10`.

### Step 2 — Recover the session XOR stream

Before any useful command works against the live service, the encrypted-payload layer needs to be inverted. The session uses an LCG to derive a XOR key stream, and the `status` command leaks enough state to recover the LCG seed.

A typical LCG has the form `s_{i+1} = a · s_i + c (mod m)`. The `status` response reveals one or more state samples (the protocol calls them "session hints"); with the public `(a, c, m)` constants embedded in the helper module, recovering the seed is a matter of running the LCG backwards or forwards from the known samples to align with the expected output position.

Once the seed is known, you can compute the XOR stream for any later offset and prepare valid encrypted `warm`, `quote`, and `attest` payloads. None of this is the bug; it's protocol plumbing the solver has to get right before the rest of the chain works.

### Step 3 — Stage the route bytes in the warm image

The warm image is an arena that subsequent operations can index into. The bytes at offset `0x18` need to be the desired route descriptor:

```
02 01 01 01
```

Decoded as `[route_kind=2, quote_idx=1, cap_mask=0x01, flags=0x01]`. The critical field is `cap_mask = 0x01`, which keeps the slot blessable after the swap. Without it, the bless step refuses the slot and the audit invocation never reaches the controlled route.

Upload the patched helper module and call `warm` with the route bytes positioned at offset `0x18`. The session-XOR layer encrypts the payload; the LCG-derived stream from Step 2 produces the right encryption.

### Step 4 — Find the PackBits overflow

The helper module exposes an `expand` opcode that decompresses PackBits-encoded data. PackBits is the run-length-encoding scheme used in TIFF and PICT files. Each control byte either says "the next N bytes are literal" or "repeat the next byte N times." The expand opcode checks the *compressed input* length against an allowed maximum, but the *decompressed output* can be much larger and the opcode doesn't bound it.

That's the primitive. A compressed input that passes the length check produces a decompressed output that runs past the intended region in the arena and overwrites the bind table.

To use this primitive against the bind table, the exploit needs:

- A bind table entry already in place that the validator accepted.
- A PackBits compressed payload whose decompression lands the desired bytes on top of that bind entry.
- The mutated bytes to form a valid bind entry with `image_off = 0x18` (above the validator's `0x0f` ceiling).

Order matters. The validator runs on the bind operation, not on the expand operation. If the bind is validated first with a benign `image_off = 0x05` (or any acceptable value), and the expand runs afterwards and overwrites the bind entry's `image_off` byte with `0x18`, the route patcher reads the mutated value and accepts it because the patcher's own checks are looser.

### Step 5 — Build the expand payload

The exploit uses four RLE fragments staged in the arena. Each fragment is a compressed-input chunk that, when concatenated and run through the PackBits decoder, produces output that lands exactly on the bind-table offsets. The first fragments fill harmless regions and the last fragment overwrites the bind entry's metadata fields:

```
[route=1, quote=0, image_off=0x18, flags=0]
```

The exact PackBits encoding to land these four bytes at the right arena offsets is what the helper module's `expand` decoder consumes. There's no clever trick beyond "count the offsets carefully and pad until the overflow lines up."

### Step 6 — Validate the harmless bind first

Before the expand can overwrite the bind table, the table needs to contain a bind entry. Create one with an `image_off` the validator accepts. The decoder approves it and writes it into the bind table at a stable offset. The arena is now in the state where a follow-up expand can rewrite that entry's `image_off` byte to `0x18`.

This is the TOCTOU pattern. Time of check: the bind decoder sees `image_off = 0x05` (acceptable). Time of use: the route patcher reads `image_off = 0x18` (acceptable to it). The check and the use look at the same byte at different points in time, and the expand opcode runs between them.

### Step 7 — Trigger the expansion to retarget the bind

Invoke `expand` on the staged RLE fragments. The decompressor walks the compressed input, produces the decompressed output, and writes it into the arena past the intended region. The bind table entry now contains the attacker-chosen `image_off = 0x18` while still passing whatever sanity checks the route patcher does (because the entry shape is otherwise valid).

### Step 8 — Bless, activate, audit, and pull the flag

With the bind table rewritten:

1. `bless` the slot. The bless step checks `cap_mask & 0x01`, which is set in the route bytes at offset `0x18`. The slot is blessable.
2. `activate` the slot. Activation locks in the route table for the audit step.
3. `audit`. The audit invocation looks up the route table entry, sees `route=1` pointing at the controlled image, and executes the attacker-staged route.
4. Request the flag. The service confirms the audit completed against the controlled route and returns:

```
slopped{packbits_lookup_routes_rethread_the_owner_lane}
```

### Why Canopy Cache works

The validator and the consumer trust different snapshots of the same memory. The bind decoder trusts the bind table at decode time. The route patcher trusts the bind table at patch time. The expand opcode runs between those two trusts and changes the bind table while neither validator is watching.

That's the classic shape of a check-vs-use bug in any system with mutable state. The fix has two ergonomic options:

The first is to enforce the validator's rules on every mutation of the bind table, not just on the bind operation itself. If `expand` had a post-decompression check that the bind-table region hadn't been written into, the overflow would be detected.

The second is to make the bind table immutable after validation. Allocate a separate buffer for `expand` output that can't overlap the bind table by construction. Decompression bombs and overflows are a known class of bug; PackBits in particular has a documented "decompressed size can exceed compressed size by 128×" worst case, and any decoder that doesn't bound the output against an explicit consumer-provided buffer is at risk.

The defender's mental model here is "validators run on stable input." In a system where any opcode can rewrite the arena, no input is stable. Either bound the writeable region, or re-validate every dependent structure after any mutation.

## Cross-cutting defender notes

Two patterns recur across the blockchain track and the wider Anti-Slop event.

**Local commitment recomputation is a self-consistency check, not authentication.** Finality Cache's guardian recomputes the receipt digest from the lane programs and compares it to the embedded value. There is no key, no signature, no external authority. Anyone with the binary can run the same recompute on any input and produce a matching digest. Bridges and relayers that rely on local hash recomputation as the integrity gate are auditing themselves, not the message. The fix is to require an upstream signature (with a key that the guardian doesn't hold) over the same data, and to make the signature the gate.

**Validators and consumers must read the same bytes at the same time.** Canopy Cache's bind decoder and route patcher disagree about acceptable image offsets, and the expand opcode runs between them. This is the same shape as PHP's `phar://` auto-deserialize bug (one consumer parses metadata, another consumes objects), the JWT `alg=none` confusion (one parser trusts the header, another doesn't reverify), and dozens of production race conditions in caching layers. The defender pattern is to either share a single canonicalisation step between every consumer of the buffer, or to immutably snapshot the buffer at validation time and have all consumers read from the snapshot.

## Frequently asked questions

### What is Anti-Slop CTF?

Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source or reverse-engineering a custom format. The flag prefix is `slopped{...}` and the writeup compilation is at [Abdelkad3r/Anti-SlopCTF-2026](https://github.com/Abdelkad3r/Anti-SlopCTF-2026).

### Are these EVM smart-contract challenges?

No. "Blockchain" here means bridge-style and relayer-style protocol challenges. Both challenges ship a custom guardian binary that plays the role of a bridge validator, but there's no Solidity, no Foundry, no EVM, and no on-chain state to attack. The bugs are in how the binary validates and consumes byte sequences. If you want EVM/DeFi-flavoured writeups on this site, the [SCTF 2026 writeup](/ctf-writeups/sctf-2026-writeup/) covers a TWAP oracle eviction attack and a Groth16 Poseidon-Merkle witness.

### What's the bug in Finality Cache?

The bridge receipt has three fields that must stay consistent: the lane varint encoding the claim amount, the header's little-endian committed amount, and a 32-byte VM commitment over the lane programs. The guardian recomputes the commitment locally and compares to the embedded value. Because the commitment routine lives in the guardian binary itself with no MAC key or upstream signature, anyone with the binary can recompute. Patch the lane varint, patch the header amount, then either reimplement the commitment routine or run the local guardian under `gdb` to dump the recomputed digest and patch it into the receipt.

### Why does the guardian binary recompute the commitment locally?

That's actually a reasonable design choice for a bridge guardian, which has to validate receipts produced by an upstream system. The bug isn't that the guardian recomputes; it's that the recompute is the *only* check. If the embedded commitment were also signed by an upstream chain validator and the guardian verified the signature against a pinned public key, the local recompute would become a sanity check and the signature would be the security gate. As shipped, the guardian audits the receipt against itself.

### How do you handle the VM commitment recomputation in Finality Cache?

Two viable approaches. Reimplement the commitment routine in Python (a few hours of reversing for a sponge-style hash with custom personalisation bytes), or let the guardian compute it for you under `gdb`. The `gdb` approach is faster: break at the recompute address (`0x401a7a` in this binary), feed the patched receipt, single-step until the digest is in a register or on the stack, dump 32 bytes, paste back into the receipt at `0x3c..0x5b`. Five minutes vs several hours.

### What's the bug in Canopy Cache?

Two validators on the bind table disagree. The `bind` decoder rejects image offsets above `0x0f`. The route patcher needs offsets above `0x17`. A direct bind with the desired offset fails validation. The exploit is a PackBits decompression that runs after a benign bind has been validated and overwrites the bind table's image-offset byte from `0x05` (or whatever you used) to `0x18` (the warm-image route). The route patcher reads the mutated byte and accepts it because its own rules are looser, and the audit invocation routes through the attacker-controlled image.

### Why doesn't the PackBits expand opcode bound its output?

The expand opcode validates the compressed input length but not the decompressed output length. PackBits has a worst-case expansion of 128× (one literal byte plus a single 0x80 control byte produces 128 output bytes), so any opcode that bounds only the compressed input is at risk. The challenge's design probably traced to "we validate input size so it can't be too large" without modelling the expansion ratio. The fix is to bound the output against the size of a consumer-provided destination buffer, or to allocate the destination from a region that can't overlap any validated structure.

### Why does `cap_mask = 0x01` matter for Canopy Cache?

The bless step refuses any slot whose route bytes don't have `cap_mask & 0x01` set. If the attacker-staged route bytes at offset `0x18` are `[route=1, quote=0, image_off=0x18, flags=0]` *without* the `cap_mask` byte set to `0x01`, the slot can't be blessed and the chain fails one step before the flag. The exact byte layout `02 01 01 01` is `[route_kind=2, quote_idx=1, cap_mask=0x01, flags=0x01]`. Lose either `0x01` and the bless step refuses you.

### How do you recover the session XOR stream?

The session uses an LCG (`s_{i+1} = a · s_i + c mod m`) to derive a XOR key stream. The `status` command leaks one or more state samples. Combined with the public `(a, c, m)` constants from the helper module, you can recover the seed by walking the LCG forwards or backwards to align with the leaked sample, then derive the key stream for any subsequent offset. None of this is the bug; it's protocol plumbing the solver has to get right before the rest of the chain works.

### Where can I find the full writeups?

Per-challenge READMEs for both blockchain challenges are at [Abdelkad3r/Anti-SlopCTF-2026/blockchain](https://github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/blockchain). The challenges were remote-only services, so the repository's writeups document the reliable exploit flow rather than bundling full client scripts.

### What's the broader lesson from the Anti-Slop CTF blockchain track?

Bridge protocols routinely rely on local recomputation and multi-stage validation. Both patterns are correct in principle and routinely buggy in practice. Local recomputation only authenticates if the recompute key isn't available to the attacker, which means either an actual signature from an upstream chain or a MAC key the guardian doesn't expose. Multi-stage validation only holds if every consumer reads the same canonical snapshot of the input, which means either shared canonicalisation logic or an immutable post-validation snapshot. Production bridge audits should focus on both classes by default.

## Closing notes

Finality Cache was an afternoon's work, mostly waiting for `gdb` to break at the right address and pattern-matching the digest output back into the receipt at the right offset. Canopy Cache was longer because the protocol plumbing (LCG key-stream recovery, encrypted-payload framing) had to land before any cryptographic bug exploration. Once the framing was right and the PackBits primitive was identified, the rest was alignment arithmetic.

This is the fifth post in the Anti-Slop CTF 2026 series. The full set covers:

- [Web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/): Slipstream Cache TLV parser-split + blind RSA, SloppedRider SSRF-to-HMAC-key leak.
- [Reverse writeup](/ctf-writeups/anti-slopctf-2026-reverse-writeup/): Audit Spiral quadratic ECDSA nonce, Parallax Cartridge SHA-256 length extension.
- [Pwn writeup](/ctf-writeups/anti-slopctf-2026-pwn-writeup/): Paper Lantern Bellcore CRT fault, Graceful Exit leak-and-overwrite, Anchorpoint five-stage VM-to-GCM forge chain.
- [Crypto writeup](/ctf-writeups/anti-slopctf-2026-crypto-writeup/): Polynomial Drift HNP CVP, Sealed Signal CBC-MAC splice.
- This post: Finality Cache + Canopy Cache.

For more bridge and blockchain CTF writeups elsewhere on this site, the [SCTF 2026 writeup](/ctf-writeups/sctf-2026-writeup/) covers a Uniswap V2 TWAP oracle eviction attack against an EIP-7540-style async LP vault and a Groth16 Poseidon-Merkle witness gated by Fermat-factorable RSA. Full [CTF writeups index](/ctf-writeups/) for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is Anti-Slop CTF?","acceptedAnswer": {"@type": "Answer","text": "Anti-Slop CTF is a Jeopardy-style CTF whose challenges are explicitly designed to defeat low-effort, tool-driven, or pattern-matched solving. Most challenges require reading source or reverse-engineering a custom format. The flag prefix is slopped{...} and the writeup compilation is at github.com/Abdelkad3r/Anti-SlopCTF-2026."}},
    {"@type": "Question","name": "Are these EVM smart-contract challenges?","acceptedAnswer": {"@type": "Answer","text": "No. Blockchain here means bridge-style and relayer-style protocol challenges. Both challenges ship a custom guardian binary that plays the role of a bridge validator. There's no Solidity, no Foundry, no EVM, and no on-chain state to attack. The bugs are in how the binary validates and consumes byte sequences."}},
    {"@type": "Question","name": "What's the bug in Finality Cache?","acceptedAnswer": {"@type": "Answer","text": "The bridge receipt has three fields that must stay consistent: the lane varint encoding the claim amount, the header's little-endian committed amount, and a 32-byte VM commitment over the lane programs. The guardian recomputes the commitment locally. Because the commitment routine lives in the guardian binary with no MAC key or upstream signature, anyone with the binary can recompute. Patch all three fields consistently and the receipt validates."}},
    {"@type": "Question","name": "Why does the guardian binary recompute the commitment locally?","acceptedAnswer": {"@type": "Answer","text": "Bridge guardians have to validate receipts produced by an upstream system. The bug isn't local recomputation; it's that local recomputation is the only check. If the embedded commitment were also signed by an upstream chain validator with a pinned public key, the local recompute would become a sanity check and the signature would be the security gate. As shipped, the guardian audits the receipt against itself."}},
    {"@type": "Question","name": "How do you handle the VM commitment recomputation in Finality Cache?","acceptedAnswer": {"@type": "Answer","text": "Two approaches. Reimplement the commitment routine in Python (hours of reversing for a sponge-style hash with custom personalisation), or let the guardian compute it for you under gdb. The gdb approach is faster: break at the recompute address (0x401a7a), feed the patched receipt, single-step until the digest is in a register or on the stack, dump 32 bytes, paste back at receipt offsets 0x3c..0x5b."}},
    {"@type": "Question","name": "What's the bug in Canopy Cache?","acceptedAnswer": {"@type": "Answer","text": "Two validators on the bind table disagree. The bind decoder rejects image offsets above 0x0f. The route patcher needs offsets above 0x17. A direct bind with the desired offset fails. The exploit is a PackBits decompression that runs after a benign bind has been validated and overwrites the bind table's image-offset byte from 0x05 to 0x18. The route patcher reads the mutated byte and accepts it; audit then routes through the attacker-controlled image."}},
    {"@type": "Question","name": "Why doesn't the PackBits expand opcode bound its output?","acceptedAnswer": {"@type": "Answer","text": "The expand opcode validates compressed input length but not decompressed output length. PackBits has a worst-case 128× expansion (one literal plus a 0x80 control byte produces 128 output bytes), so bounding only the input is insufficient. Fix: bound the output against a consumer-provided destination buffer, or allocate the destination from a region that can't overlap any validated structure."}},
    {"@type": "Question","name": "Why does cap_mask = 0x01 matter for Canopy Cache?","acceptedAnswer": {"@type": "Answer","text": "The bless step refuses any slot whose route bytes don't have cap_mask & 0x01 set. The attacker-staged route bytes 02 01 01 01 decode to [route_kind=2, quote_idx=1, cap_mask=0x01, flags=0x01]. Lose either 0x01 and the bless step refuses you, breaking the chain one step before the flag."}},
    {"@type": "Question","name": "How do you recover the session XOR stream?","acceptedAnswer": {"@type": "Answer","text": "The session uses an LCG (s_{i+1} = a · s_i + c mod m) to derive a XOR key stream. The status command leaks one or more state samples. With the public (a, c, m) constants from the helper module, recover the seed by walking the LCG to align with the leaked sample, then derive the key stream for any subsequent offset. Not the bug; just protocol plumbing the solver has to land before the rest of the chain works."}},
    {"@type": "Question","name": "Where can I find the full writeups?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs for both blockchain challenges are at github.com/Abdelkad3r/Anti-SlopCTF-2026/tree/main/blockchain. The challenges were remote-only services, so the writeups document the reliable exploit flow rather than bundling full client scripts."}},
    {"@type": "Question","name": "What's the broader lesson from the Anti-Slop CTF blockchain track?","acceptedAnswer": {"@type": "Answer","text": "Bridge protocols routinely rely on local recomputation and multi-stage validation. Both patterns are correct in principle and routinely buggy in practice. Local recomputation only authenticates if the recompute key isn't available to the attacker (actual upstream signature or MAC key the guardian doesn't expose). Multi-stage validation only holds if every consumer reads the same canonical snapshot (shared canonicalisation logic or immutable post-validation snapshot)."}}
  ]
}
</script>
