---
title: "z0d1akCTF 2026 Qualifiers Cryptography Writeup: All 6 Challenges Solved"
slug: "z0d1akctf-2026-qualifiers-crypto-writeup"
description: "Complete z0d1akCTF 2026 Qualifiers Cryptography writeup covering all six Crypto challenges. siren — ECDSA (secp256k1) signing oracle whose nonce fixes its top 10 bits to public_pitch(msg), the SHA-256 prefix of a public song_id; 40-plus signatures feed a Hidden Number Problem lattice, LLL recovers the private key D, and a forged signature for the forbidden unlock message returns the flag. Rewind — stream cipher rewinds the counter every encryption so the oracle response for 44 zero bytes is the raw keystream; XOR against secret_ct yields the flag. Rewind Revenge — AES-GCM nonce reuse (Joux forbidden attack); with one block per command, the tag is affine T equals C times H-squared XOR P; two seals cancel P and expose H-squared, a third seal validates the model, then forge a valid seal for the forbidden print_the_flag command. You Have Not Seen My Colors — 100 by 100 RGB PNG whose red and green channels use values 1 to 255 with no zeros, but blue has 166 pixels equal to zero forming Elian script that reads ZEK (signature) then MASTER OF CTF (answer). cyclotomic-echo — NTRU-style signature over Z bracket x close-bracket over x-to-128 plus 1 where recovery.json ships the private basis f g F G with f G minus g F equal to 1 and B times B star equal to public Q; sign by mapping the parity target through B, reducing coefficient-wise modulo 2, mapping back via the integral inverse; norm 133 against a bound of 16384. THESEUS — EIP-1967 Ethereum proxy across five destroyed implementations; slots 2 3 4 8 9 10 and 11 hold every mark and root the final unlock function compares against, so only a three-node Merkle path and one keccak commitment need reconstructing; the literal flag is embedded in the Setup contract's creation input on the immutable blockchain history."
date: 2026-08-30T20:00:00Z
lastmod: 2026-08-30T20:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["z0d1akCTF 2026 Qualifiers"]
tags:
  - "z0d1akctf"
  - "z0d1akctf 2026"
  - "z0d1ak ctf"
  - "z0d1akctf qualifiers"
  - "ctf writeup"
  - "cryptography"
  - "crypto"
  - "ecdsa"
  - "secp256k1"
  - "biased nonce"
  - "hidden number problem"
  - "lll lattice"
  - "stream cipher"
  - "keystream reuse"
  - "two-time pad"
  - "aes-gcm"
  - "nonce reuse"
  - "forbidden attack"
  - "ghash"
  - "gf128"
  - "tag forgery"
  - "png steganography"
  - "channel sentinel"
  - "elian script"
  - "cyclotomic ring"
  - "ntru trapdoor"
  - "unimodular basis"
  - "parity coset"
  - "ethereum proxy"
  - "eip-1967"
  - "storage inspection"
  - "merkle path"
  - "keccak-256"
  - "chain history"
  - "ctf 2026"
keywords:
  - "z0d1akctf 2026 qualifiers crypto writeup"
  - "z0d1akctf 2026 cryptography writeup"
  - "z0d1akctf siren writeup"
  - "z0d1akctf rewind writeup"
  - "z0d1akctf rewind revenge writeup"
  - "z0d1akctf you have not seen my colors writeup"
  - "z0d1akctf cyclotomic-echo writeup"
  - "z0d1akctf theseus writeup"
  - "ecdsa biased nonce hnp lattice attack ctf"
  - "aes-gcm nonce reuse forbidden attack joux tag forgery"
  - "stream cipher keystream reuse two time pad ctf"
  - "png channel sentinel elian script transliteration ctf"
  - "ntru unimodular private basis parity coset short signature"
  - "cyclotomic z-mod-x-128-plus-1 signature forgery ctf"
  - "eip-1967 proxy storage inspection merkle keccak ctf"
  - "ethereum setup constructor input flag recovery"
  - "z0d1akctf 2026 solutions"
  - "ctf crypto step by step 2026"
toc: true
cover:
  image: "/images/articles/z0d1akctf-2026-qualifiers-crypto-writeup.png"
  alt: "z0d1akCTF 2026 Qualifiers Cryptography writeup cover — all six Crypto challenges solved. siren exploits an ECDSA signing oracle whose secp256k1 nonce has 10 public high bits derived from the session song_id; 40-plus signatures feed a Hidden Number Problem lattice and LLL recovers the private key D so a forged signature unlocks the forbidden message. Rewind reads the raw keystream by encrypting 44 zero bytes through an oracle whose counter is reset every call, then XORs against the secret ciphertext. Rewind Revenge exploits AES-GCM nonce reuse; single-block tags are affine over GF128 so two seals cancel the constant P and reveal H-squared, a third seal validates the model, then a forged tag opens print_the_flag. You Have Not Seen My Colors filters a 100 by 100 RGB PNG on blue equals zero to reveal 166 sentinel pixels forming Elian script that transliterates to MASTER OF CTF with a ZEK signature to discard. cyclotomic-echo uses the private NTRU-style basis in recovery.json (fG minus gF equals 1) to sign the parity target by mapping through B, reducing each coefficient modulo 2, and mapping back with the integral inverse; norm 133 against bound 16384. THESEUS reads seven expected marks out of EIP-1967 proxy storage slots 2 3 4 8 9 10 and 11, verifies a three-node Merkle path with keccak-256, computes one commitment, calls unlock, and scans the immutable blockchain for the flag embedded in the Setup contract's creation input">
---

**z0d1akCTF 2026 Qualifiers**'s Cryptography track is a six-challenge lesson in one discipline: **don't attack the primitive — attack the parameters, the oracle, or the storage.** Every crypto challenge in the set ships with a nominally strong core — ECDSA over secp256k1, AES-GCM authenticated encryption, an NTRU-style lattice signature over a cyclotomic ring, keccak-Merkle proofs on an Ethereum chain — and in every one of them the intended solve leaves that primitive completely unbroken. The break is always upstream of the cipher: a biased nonce turns ECDSA into the Hidden Number Problem, a rewound counter turns a stream cipher into a two-time pad, a repeated GCM nonce turns single-block authentication into an affine `T = C·H² ⊕ P` that two seals recover, a leaked private basis turns a public quadratic form back into ordinary coefficient norm, an EIP-1967 proxy's public storage turns a "prove seven witnesses" scheme into "read seven storage slots and call `unlock`."

The unifying pattern is that in every one of these challenges the *inputs* the service exposes make the primitive's guarantee irrelevant. siren computes its nonce prefix from the `song_id` it hands us. Rewind rewinds its counter each encryption so `enc(0x00×n)` returns the keystream. Rewind Revenge repeats its nonce so two `(C, T)` pairs share `P` and cancel it. You Have Not Seen My Colors reserves the value `0` in the blue channel and paints the flag there. cyclotomic-echo publishes a `recovery.json` whose `(f,g,F,G)` are the exact private NTRU basis behind the public form. THESEUS ships every "expected mark" in publicly-readable proxy storage. **The crypto is theatre — the answer is already in front of you.**

Handouts, per-challenge READMEs, solvers, and captured session artifacts live at [Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers). This **CyberSecurity Elite** z0d1akCTF 2026 Qualifiers Cryptography writeup walks all six challenges end to end. Read alongside the paired [z0d1akCTF 2026 Qualifiers Miscellaneous writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-misc-writeup/) and the [z0d1akCTF 2026 Qualifiers Forensics writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-forensics-writeup/) for twelve more challenges from the same event.

## All six Cryptography challenges at a glance

| Challenge | Points | Sub-genre | Parameter to attack | Flag |
|---|---:|---|---|---|
| [siren](#sirenbiased-ecdsa-nonce-into-the-hidden-number-problem) | 116 | ECDSA nonce bias | Public 10-bit nonce prefix `public_pitch(msg)` | `zdk{4_feW_8ltS_PeR_5LGNA7UR3_sLNkS_The_KEy}` |
| [Rewind](#rewindstream-cipher-counter-reset-is-a-twotime-pad) | 120 | Stream cipher | Reset counter → shared keystream | `zdk{ReWlnDiNg_thE_C0UNt3r_rEUs3s_Th3_sTRE4m}` |
| [Rewind Revenge](#rewind-revengeaesgcm-nonce-reuse-and-the-forbidden-attack) | 123 | AES-GCM nonce reuse | Fixed nonce → affine tag `T = C·H² ⊕ P` | `zdk{LoCaL_REWinD_R3VenGE_F1Ag}` |
| [You Have Not Seen My Colors](#you-have-not-seen-my-colorssentinel-in-the-blue-channel) | 137 | PNG channel-sentinel stego | Blue channel `B == 0` reserved | `zdk{m4S7er_OF_C0l0rs_4nD_C7f}` |
| [cyclotomic-echo](#cyclotomic-echontru-private-basis-leaked-as-recovery-json) | 139 | Lattice signature | `recovery.json` = private basis with `fG − gF = 1` | `zdk{cyc10T0mic_eCho_on3_BA5IS_biNdS_3verY_TeAM_ARcHIvE}` |
| [THESEUS](#theseus-ethereum-proxy-storage-and-blockchain-history) | 154 | Ethereum proxy | EIP-1967 storage slots 2, 3, 4, 8, 9, 10, 11 | `zdk{an_4DDrESS_Ls_A_l0C4TLoN_NoT_aN_Ld3nTl7Y}` |

Six challenges, six different primitives (ECDSA / stream cipher / AES-GCM / PNG stego / NTRU-style lattice / EVM), one repeated discipline.

---

## siren — biased ECDSA nonce into the Hidden Number Problem

> *Flag:* `zdk{4_feW_8ltS_PeR_5LGNA7UR3_sLNkS_The_KEy}`
>
> *Prompt:* "The Siren will sing any sailor's words back to him, sealed in her own hand… Give her enough verses and the silence in every breath spells her name."

The service is an ECDSA (secp256k1) signing oracle over TLS. It signs any message except the privileged one, `unlock:release-the-tide`; a valid signature for that message unlocks the flag. Standard ECDSA otherwise — but the nonce generation is broken:

```python
PITCH_BITS  = 10
SUFFIX_BITS = 246

def public_pitch(msg):
    material = (SONG_ID + ":" + msg).encode()
    h = int.from_bytes(hashlib.sha256(material).digest(), "big")
    return h >> (256 - PITCH_BITS)      # top 10 bits of the hash

def shaped_nonce(msg):
    prefix = public_pitch(msg) << SUFFIX_BITS
    while True:
        k = prefix | (rng_below(SUFFIX_BOUND) - 1)
        if 1 <= k < N:
            return k
```

Every nonce is `k = prefix | random246`, and **`prefix` is public** — it is determined entirely by `song_id` (banner-disclosed) and `msg` (attacker-chosen). The top 10 bits of every signing nonce are known. That is the *silence in every breath* the prompt hints at.

### From known nonce bits to HNP

For each signature `i`, the ECDSA relation gives:

```text
k_i = s_i⁻¹ (z_i + r_i · D)   (mod n)
```

Write `a_i = public_pitch(msgᵢ) << 246` and `e_i = k_i − a_i` (small, `0 ≤ e_i < 2²⁴⁶`). With `t_i = r_i · s_i⁻¹` and `u_i = z_i · s_i⁻¹`:

```text
t_i · D + (u_i − a_i)  ≡  e_i   (mod n),      0 ≤ e_i < 2²⁴⁶
```

Textbook **Hidden Number Problem**: recover `D` given many `(t_i, c_i)` where `t_i·D + c_i` is small modulo `n`. Each signature pins ~10 bits of `D`, so `⌈256/10⌉ ≈ 26` signatures are information-theoretically sufficient; the solver collects 40–45 for lattice comfort.

### The lattice

Centre the errors about `B/2` (with `B = 2²⁴⁶`) and build the standard HNP lattice of dimension `m + 2`. The critical trick is column weighting: the `D`-marker column has weight 1, all others are scaled by `K = 2¹⁰`, so `D·1 ≈ 2²⁵⁶` is *comparable in size* to `K·e_i ≈ 2²⁵⁶`. Without this balancing the `D` coordinate would dominate and the solution would not be the shortest vector.

LLL surfaces the target vector. From any recovered centred error `e'_i` reconstruct the nonce and read `D` straight off the ECDSA relation:

```text
D = (s_i · k_i − z_i) · r_i⁻¹   (mod n)
```

Each candidate is confirmed by `D·G == Q`, which makes the recovery self-verifying and robust to sign/coordinate ambiguity in the reduced basis.

### Forging the unlock

```python
z = H("unlock:release-the-tide")
k = random_nonce()
r = (k·G).x mod n
s = k⁻¹ (z + r·D) mod n
```

Sending `unlock{r, s}` verifies against `PRIV_MSG` and the service returns `zdk{4_feW_8ltS_PeR_5LGNA7UR3_sLNkS_The_KEy}` — the flag literally states the lesson.

**Takeaway:** a biased nonce is a broken nonce. "Only 10 known bits" sounds harmless; it is a full key-recovery primitive once the leak is systematic across signatures. Recognise the HNP shape (`t·D + c ≈ 0 (mod n)` with a small bounded error) and reach for a lattice. Make recovery self-verifying by checking each candidate `D` against `D·G == Q`.

---

## Rewind — stream cipher counter reset is a two-time pad

> *Flag:* `zdk{ReWlnDiNg_thE_C0UNt3r_rEUs3s_Th3_sTRE4m}`
>
> *Prompt:* "easy to slop"

The service is a stream cipher whose banner hands us `secret_ct` (the flag encrypted under the current keystream) and whose menu exposes an oracle that encrypts attacker-controlled bytes *under the very same keystream*. The counter that should advance is "rewound" to the same starting value each call.

```text
The operator swears the stream is fresh every time.
Watch what happens when the counter keeps rewinding.

secret_ct = c50ccaacbdb7ccf995d89847efd1bcf9ea3c9981315ec3ca3ae6a1dcddabb095f9700de99eece96c6e72689a

[1] Show encrypted token
[2] Encrypt attacker-controlled bytes (hex)
[3] Exit
```

Three facts settle the whole solve:

- `secret_ct` is 92 hex = 44 bytes, so the plaintext is 44 bytes (hallmark of a stream cipher / XOR keystream).
- Option `[2]` is an encryption oracle.
- The prompt states the bug outright — same counter every call ⇒ same keystream ⇒ two-time pad.

### Recover the keystream

For a stream cipher `ct = pt ⊕ keystream`. Encrypt 44 zero bytes:

```text
enc(0x00 × 44) = 0x00 × 44 ⊕ keystream = keystream
```

The returned ciphertext **is** the keystream. XOR against `secret_ct`:

```python
secret_ct = bytes.fromhex("c50ccaacbdb7ccf995d89847efd1bcf9ea3c9981315ec3ca3ae6a1dcddabb095f9700de99eece96c6e72689a")
keystream = bytes.fromhex("bf68a1d7efd29b95fb9cf109888ec891af63dab16410b7f948b9d39988d883e6a62465dac19fbd3e2b4605e7")
flag = bytes(a ^ b for a, b in zip(secret_ct, keystream))
# b'zdk{ReWlnDiNg_thE_C0UNt3r_rEUs3s_Th3_sTRE4m}'
```

Every byte lands in printable ASCII and the string is `zdk{…}` — free sanity check that alignment is correct.

**Takeaway:** a reused keystream is not encryption — it's a mask you can subtract. Ciphertext length equal to plaintext length + an encrypt-anything oracle = two-time pad, regardless of the underlying primitive. Read the flavour text literally; it usually names the bug.

---

## Rewind Revenge — AES-GCM nonce reuse and the forbidden attack

> *Flag:* `zdk{LoCaL_REWinD_R3VenGE_F1Ag}`
>
> *Prompt:* "easy to slop returns!!"

Rewind's sequel upgrades the primitive to **AES-GCM — but reuses the nonce every time**. Nonce reuse is the single unforgivable sin of GCM: it collapses the authentication guarantee entirely and enables tag **forgery** — Joux's *"forbidden attack."*

```text
The maintainer rewinds the same AES-GCM nonce every time a command is sealed.
All commands are exactly 16 bytes long; privileged commands cannot be sealed.
Forge a valid sealed `print_the_flag!!` command.

[1] Seal a non-privileged 16-byte command (hex)
[2] Submit a sealed command
[3] Exit
```

Every command is exactly one 16-byte block, so for a fixed nonce the GCM authentication tag is an **affine function of the ciphertext** over `GF(2¹²⁸)`:

```text
T = C · H²  ⊕  P
```

where `H = E_K(0)` is the GHASH subkey and `P = L·H ⊕ E_K(J₀)` is a constant that depends only on the fixed nonce, key, and length block. Two seals cancel `P` and expose `H²`; a third seal validates the recovered model exactly.

### Recovering H² and P

Take two seals `A` and `B`; XOR eliminates the constant `P`:

```text
T_A ⊕ T_B = (C_A ⊕ C_B) · H²
      H²  = (T_A ⊕ T_B) · (C_A ⊕ C_B)⁻¹     (inverse in GF(2¹²⁸))
```

Then `P = T_A ⊕ C_A · H²`. Field inversion is `x⁻¹ = x^(2¹²⁸−2)` via square-and-multiply. All of this uses the GCM field convention (blocks big-endian, reduction polynomial `x¹²⁸+x⁷+x²+x+1`, identity `0x80…00`), implemented dependency-free in a small `gf128.py`.

**Validation on a held-out seal.** The recovery used only two of the three sealed pairs; the third is a held-out check. Predict its tag as `C₀ · H² ⊕ P` and compare against the captured value — exact match confirms both the recovered `H²` and the fiddly bit-ordering before we spend our one forgery.

### Forging `print_the_flag!!`

The keystream comes free from `enc(0x00×16)` (since `C = pt ⊕ keystream`). So:

```text
C_t = "print_the_flag!!" ⊕ keystream = 95591d991a7db897328b7ac8a8bb24b4
T_t = C_t · H² ⊕ P                  = 2d569092e04a258dca912d586c7c4f32
```

Submitting `(C_t, T_t)` to option `[2]` decrypts to exactly `print_the_flag!!`, the tag verifies, and the server returns the flag. **Three encryption queries; no attack on the key or the nonce.**

**Takeaway:** a repeated GCM nonce is total authentication failure, not a small leak. One duplicate nonce hands over `H²` outright. Single-block GCM tags are affine (`T = C·H² ⊕ P`) — two points give the line, the third confirms it. Refusing to *sign* privileged commands is meaningless once forgery is possible. Validate the model on held-out data before spending your one shot — it catches any `GF(2¹²⁸)` convention mistake for free.

---

## You Have Not Seen My Colors — sentinel in the blue channel

> *Flag:* `zdk{m4S7er_OF_C0l0rs_4nD_C7f}`
>
> *Prompt:* "Elian gave you this challenge. Find meaning in the noise, then prove what you decoded to the private endpoint."

The handout is a 100×100 RGB PNG of apparent uniform colour noise. Standard first checks are dead: no useful metadata, `IEND` terminates normally, `strings` returns PNG debris, individual bit planes look random. But the title and prompt both emphasise *colours* and *noise*, so treat the RGB values as structured data instead of viewing the render.

### The per-channel anomaly

| Channel | Minimum | Maximum | Distinct values | Pixels equal to zero |
| --- | ---: | ---: | ---: | ---: |
| Red | 1 | 255 | 255 | 0 |
| Green | 1 | 255 | 255 | 0 |
| Blue | 0 | 255 | 256 | **166** |

Two signals: red and green use every byte value **except zero** (background sampled from `[1, 255]`, not unconstrained random), and blue has 166 pixels equal to exactly zero — a *reserved sentinel value* written into one channel. The other two random channel values keep those pixels colourful on screen, hiding the sentinel from a normal RGB render.

An exact-equality test is essential here; `B < 16` would include hundreds of legitimate dark-blue background values. `B == 0` gives a sparse, clean carrier.

### Extract

Mask on `blue == 0`, crop to the bounding box `(23, 1, 84, 40)`, render marked pixels white on black. The 166 pixels immediately form straight-line glyphs.

### Recognise the alphabet

The prompt begins with *"Elian gave you this challenge"*. Once the angular carrier is visible, "Elian" is not a character name — it points to the **Elian writing system**, whose glyphs are grid-position-derived: right-angle strokes, unequal arms, closed squares, isolated dots. The carrier contains exactly those features. Reading left to right:

| Pixel region | Elian letters | Interpretation |
| --- | --- | --- |
| `x=23..55, y=1..4` | `Z E K` | Signature (top line, isolated) |
| `x=23..83, y=11..18` | `M A S T E R` | Answer word 1 |
| `x=24..40, y=24..31` | `O F` | Answer word 2 |
| `x=24..55, y=36..39` | `C T F` | Answer word 3 |

Repeated shapes cross-validate: `E` in `ZEK` and `MASTER`, `F` in `OF` and `CTF`, `T` in `MASTER` and `CTF`. Pixel-exact match rules out ambiguity.

### Separate signature from answer

`answer=zek_master_of_ctf` returns HTTP `403 incorrect`. The layout tells the reason: `ZEK` is centred on its own top line, separated from the three-line statement beneath it — it is the writer's signature, not part of the answer. `answer=master_of_ctf` returns HTTP `200` and the flag.

**Takeaway:** measure before guessing. A random-looking image becomes structured as soon as each channel's minimum and zero count are compared. Exact sentinel values beat broad thresholds (LSB extraction over `B < 16` would have added noise, not removed it). Use every word of the prompt — "colors" points to channel analysis, "noise" describes the cover, "Elian" names the alphabet. Layout carries semantics; a correctly transliterated top line was still the wrong answer until it was recognised as a signature.

---

## cyclotomic-echo — NTRU private basis leaked as recovery.json

> *Flag:* `zdk{cyc10T0mic_eCho_on3_BA5IS_biNdS_3verY_TeAM_ARcHIvE}`
>
> *Prompt:* "Some keys disappear. Their geometry does not."

The service asks for a short signature in the cyclotomic integer ring `R = Z[x] / (x^128 + 1)`. Its public key is a positive-definite Hermitian form `Q`. The verifier hashes a fixed target message plus a chosen salt to two binary ring elements `(x, y)`, then accepts a short vector `(e0, e1)` in the parity class `(e0, e1) = (x, y) mod 2R²`. Only the compressed second component `s1 = (y − e1) / 2` is submitted.

### The recovery file *is* the private basis

The second handout file, `recovery.json`, contains four polynomials `f, g, F, G`. They are not incidental recovery data — they form the exact private NTRU basis:

```text
    [ f  g ]
B = [      ]
    [ F  G ]
```

Two checks prove this against the live public form:

```text
fG - gF = 1
Q = B * B^*
```

The determinant is the unit `1`, so the basis is **unimodular over the ring** — its inverse is integral:

```text
         [  G  -g ]
B^-1  = [        ]
         [ -F   f ]
```

Both checks are computed dependency-free with plain integer lists implementing negacyclic multiplication (`x^128 = -1`) and cyclotomic conjugation.

### Sign by modulo-2 reduction in the private basis

Choose the deterministic all-zero salt. For the captured instance, hashing the domain + target + salt with SHAKE-256 gives binary polynomials `x` and `y`. Let `h = (x, y)` and map through the private basis:

```text
w  = h·B          (w0 = x·f + y·F, w1 = x·g + y·G)
z  = w mod 2      (each coefficient reduced to {0, 1})
e  = z·B^-1
```

Because `z = h·B (mod 2)` and `B^-1` is integral:

```text
e ≡ h (mod 2)
```

so `e` lands in the required parity coset. The first-nonzero-`e1` sign check is a global negation if needed (which preserves parity and norm). Finally emit only `s1 = (y − e1) / 2`.

### Why the forgery is tiny

The Gram identity eliminates the public quadratic form:

```text
norm_Q(e) = coefficient_norm(e·B)² = coefficient_norm(z)²
```

Before optional negation every coefficient of `z0, z1` is 0 or 1, so the squared norm is simply the Hamming weight sum. For the captured instance:

```text
wt(z0) = 71, wt(z1) = 62
norm_Q(e) = 71 + 62 = 133
bound     = 16384
```

Enormous margin. No LLL/BKZ needed — the handout gave a unimodular private basis, and modulo-2 reduction in that basis constructs a tiny coset representative immediately.

**Takeaway:** a Gram matrix hides orientation, not geometry. Knowing a short basis `B` with `Q = B·B^*` converts the public norm back into ordinary coefficient norm. Check the determinant first — `fG − gF = 1` immediately reveals that the recovery tuple is an integral change of basis, making `B^-1` exact and cheap. Parity cosets are easy in a unimodular basis: map through `B`, reduce each coefficient modulo two, map back. Validate the leaked material against the live public key before submitting — matching every `q00` and `q10` coefficient prevents forging from a decoy tuple.

---

## THESEUS — Ethereum proxy storage and blockchain history

> *Flag:* `zdk{an_4DDrESS_Ls_A_l0C4TLoN_NoT_aN_Ld3nTl7Y}`
>
> *Prompt:* "One address. Five hulls. Four funerals. The ledger remembers what the bytecode forgets."

THESEUS is an Ethereum history / authenticated-data challenge built around a single EIP-1967 proxy. The proxy keeps one address while its implementation is replaced five times. Four old implementations are destroyed, but the proxy's storage, transaction history, and event logs remain — the *Ship of Theseus* in concrete form.

The final implementation exposes:

```solidity
function unlock(
    bytes32 firstMark,
    bytes32 secondMark,
    bytes32 selectedLeaf,
    bytes32[3] calldata siblings,
    bytes32 stateProofMark,
    bytes32 blockWitnessMark,
    bytes32 executionMark
) external;
```

The advertised path involves reconstructing historical ledger records, Merkle proofs, storage proofs, block witnesses, receipt proofs, and an execution trace. **Almost all of that is unnecessary.** The final hull compares the submitted values against commitments already retained in the proxy's public storage.

### The storage map is the exploit

Following deployment and upgrade transactions in the standard EIP-1967 implementation slot reveals five implementations, with the fifth being the live one. Disassembling its `unlock` path gives:

| Slot | Meaning |
| ---: | --- |
| `0` | Player address and `opened` flag, packed |
| `1` | Owner address |
| `2` | First historical mark |
| `3` | Second historical mark |
| `4` | Authenticated ledger root (`harbourRoot`) |
| `5` | `Chart` program address |
| `6` | `BlockWitness` program address |
| `7` | `ExecutionWitness` program address |
| `8` | Selected ledger leaf |
| `9` | State-proof salt |
| `10` | Expected block witness mark |
| `11` | Expected execution witness mark |

Ethereum contract storage is public; `eth_getStorageAt` works on the live challenge endpoint. So `firstMark`, `secondMark`, `harbourRoot`, `selectedLeaf`, `proofSalt`, `blockWitnessMark`, and `executionMark` are all directly readable.

### The only work that remains

Two derivations, no witness reconstruction:

**1. Merkle path for the selected leaf.** Historical logs contain one batch of eight records emitted at checkpoint block 13. The canonical input is `uint8(i) || eventData[i]` per record. Each leaf is `keccak256(canonicalRecord[i])`; adjacent nodes are `keccak256(left || right)` (no sorting). Record `3` is the selected leaf, so the three-node path uses left/right based on the low bit of the current index:

```python
node = selected_leaf
index = 3
for sibling in siblings:
    if index & 1:
        node = keccak256(sibling + node)
    else:
        node = keccak256(node + sibling)
    index >>= 1
```

The resulting root matches `harbourRoot` from storage slot `4`.

**2. State-proof commitment.** Four `bytes32` words, packed:

```text
stateProofMark = keccak256(firstMark || secondMark || harbourRoot || proofSalt)
```

### Open the hull, then read the flag

Call `unlock` from the player account with all seven arguments. Receipt status `1`, `opened()` = `true`, `Setup.isSolved()` = `true`.

But the flag is not returned by any call. It belongs to the `Setup` deployment. Scan blocks for a contract-creation receipt whose `contractAddress` equals the setup address (block 27 on the captured chain). Decode its input as bytes and search the constructor arguments for `zdk{…}`. The printable fragment:

```text
-zdk{an_4DDrESS_Ls_A_l0C4TLoN_NoT_aN_Ld3nTl7Y}
```

Do not replace Ethereum Keccak-256 with Python's `hashlib.sha3_256` — they use different padding and produce different digests. Use `cast keccak` (Foundry) or a matching implementation.

**Takeaway:** an address is a location, not an identity — a proxy hosts multiple implementations over time while retaining one address and one storage namespace. Destroyed bytecode does not erase history: earlier transactions, logs, receipts, and proxy-side state remain. Public commitments are not authorisation secrets — comparing a submitted value to a publicly stored hash only proves the caller copied it. Inspect the final verifier before implementing every advertised proof; the interfaces describe possible workflows, but the final comparison determines what is actually required.

---

## Cross-cutting lessons from the z0d1akCTF 2026 Qualifiers Cryptography set

Six challenges, six different primitives, one repeated discipline. **Don't attack the primitive — attack the parameters, the oracle, or the storage:**

- **A biased nonce is a broken nonce.** siren's 10-bit prefix is a full ECDSA key-recovery primitive across 40 signatures. Any leak that lets you write `t·D + c ≈ 0 (mod n)` with a small bounded error is a Hidden Number Problem lattice away from disaster.
- **A reused counter is a two-time pad.** Rewind's stream cipher is unbroken; the counter reset is what leaks. The moment plaintext length matches ciphertext length and an encrypt-anything oracle is available under the same keystream, you own the plaintext.
- **A repeated GCM nonce is total authentication failure.** Rewind Revenge's `T = C·H² ⊕ P` is affine over `GF(2¹²⁸)`; two points give the line, the third confirms it, and forgery is arithmetic. Refusing to *sign* the privileged plaintext is meaningless once tag forgery is possible.
- **Read the parameters the challenge exposes.** cyclotomic-echo's `recovery.json` is not "recovery data" — it is the private NTRU basis with `fG − gF = 1`. THESEUS's expected marks are in slots `10` and `11`. siren's `song_id` seeds the nonce prefix. In every case the challenge hands over the material the primitive was supposed to protect.
- **Exact sentinel values beat broad thresholds.** You Have Not Seen My Colors encodes its carrier as `B == 0`; `B < 16` would drown the signal in noise. Any time a per-pixel or per-byte anomaly is used to hide data, look for a *single reserved value* rather than a threshold band.
- **Validate the model on held-out data before spending your one shot.** Rewind Revenge's third seal, cyclotomic-echo's Gram-matrix cross-check, siren's `D·G == Q` check — every solver in this set carries a self-verifying step that turns "does this look right?" into "this is right." Design forgeries around these oracles.
- **Public commitments are not authorisation secrets.** THESEUS demonstrates the whole failure mode: a verifier that compares a submitted value to a publicly stored hash proves only that the caller copied it. The proof procedure can look elaborate; if the *final comparison* uses public state, the proof is a bearer token.
- **Read the flavour text as spec.** *"The silence in every breath"* names siren's bias. *"The counter keeps rewinding"* names Rewind's bug. *"The maintainer rewinds the same AES-GCM nonce"* names Rewind Revenge's bug. *"Elian gave you this challenge"* names YHNSMC's alphabet. *"Their geometry does not"* names cyclotomic-echo's `Q = B·B^*` observation. *"One address. Five hulls."* names THESEUS's proxy. The prompts are not decoration.

## Reproduce it yourself

Each challenge ships a standalone solver in the [z0d1akCTF 2026 Qualifiers repository](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers) under `Crypto/<challenge>/`:

- [`Crypto/siren/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Crypto/siren) — end-to-end remote exploit, HNP lattice construction, dependency-free secp256k1 (`ec.py`), LLL with fpylll fallback to pure-python integer LLL (`lll.py`), offline simulator self-test.
- [`Crypto/rewind/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Crypto/rewind) — end-to-end remote exploit (stdlib only), offline reproduction from captured `secret_ct` / `keystream` pair, byte-by-byte derivation table.
- [`Crypto/rewind-revenge/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Crypto/rewind-revenge) — end-to-end remote exploit, dependency-free `GF(2¹²⁸)` GCM field arithmetic (`gf128.py`), captured three-seal set, offline verifier.
- [`Crypto/you-have-not-seen-my-colors/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Crypto/you-have-not-seen-my-colors) — dependency-free PNG parser + IDAT decompress + filter reversal + `B == 0` mask extractor + 10× enlargement writer + optional endpoint client.
- [`Crypto/cyclotomic-echo/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Crypto/cyclotomic-echo) — end-to-end stdlib TLS forgery, basis validation (`fG − gF = 1`, `B·B^* = Q`), SHAKE-256 hash construction, parity-coset reduction, captured `(salt, s1)` forgery.
- [`Crypto/theseus/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Crypto/theseus) — instance-independent solver (discovers every address, block, event topic, and commitment at runtime), Foundry `cast` for Ethereum Keccak, offline Merkle + commitment verifier, captured accepted-solution JSON, Setup constructor-input flag fragment.

All six solvers are Python standard library only, except cyclotomic-echo optionally checks against the supplied Sage verifier and THESEUS needs Foundry's `cast` command for Ethereum-compatible keccak.

Browse the full [CTF writeups](/ctf-writeups/) archive for more cryptography walkthroughs, or continue the z0d1akCTF 2026 Qualifiers series with the [Miscellaneous writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-misc-writeup/) and the [Forensics writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-forensics-writeup/) — twelve more challenges under the same read-the-substrate discipline.

---

*This writeup is part of the CyberSecurity Elite [z0d1akCTF 2026 Qualifiers](/series/z0d1akctf-2026-qualifiers/) series. Handouts, per-challenge READMEs, and dependency-conscious solvers for all six Cryptography challenges are published at [github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers).*
