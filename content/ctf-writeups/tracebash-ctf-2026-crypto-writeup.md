---
title: "TraceBash CTF 2026 Crypto Writeup: 4 Challenges Solved"
slug: "tracebash-ctf-2026-crypto-writeup"
description: "TraceBash CTF 2026 crypto track writeup — DH small-subgroup attack, audio-derived XOR key, shared 512-bit prime RSA, and an exhaustive 16-bit state-machine cipher recovery."
date: 2026-06-27T11:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["TraceBash CTF 2026"]
tags:
  - "tracebash ctf"
  - "tracebash ctf 2026"
  - "cryptography"
  - "diffie-hellman small subgroup"
  - "rsa shared prime"
  - "gcd factorisation rsa"
  - "repeating xor key"
  - "audio side channel"
  - "state machine cipher"
  - "exhaustive seed search"
keywords:
  - "tracebash ctf 2026 crypto writeup"
  - "tracebash crypto writeup"
  - "broken trust protocol writeup"
  - "harmonic cipher writeup"
  - "quantum echo writeup"
  - "state desync writeup"
  - "diffie hellman small subgroup attack ctf"
  - "shared rsa prime gcd factor ctf"
  - "common factor rsa attack writeup"
  - "audio frequency xor key ctf"
  - "16 bit seed brute force stream cipher"
  - "tbctf crypto writeup"
  - "ctf crypto step by step"
toc: true
cover:
  image: "/images/articles/tracebash-ctf-2026-crypto-writeup.png"
  alt: "TraceBash CTF 2026 crypto writeup — small-subgroup DH, harmonic XOR key, shared RSA prime, and stream-cipher seed brute"
---

Welcome to a **CyberSecurity Elite** TraceBash CTF 2026 crypto writeup on a Jeopardy-style CTF with a clean, well-curated challenge set. The crypto track has four challenges, three at 100 points and one at 440 points. This writeup covers all four step-by-step.

Each challenge is a different shape of cryptographic mistake. **state-desync** hides a 16-bit-seed stream cipher behind a noisy update function. **broken-trust-protocol** is a textbook Diffie-Hellman implementation that forgets to validate the peer public value. **harmonic-cipher** hides an 8-byte XOR key inside an audio file. **quantum-echo** ships two RSA-1024 public keys that share a 512-bit prime, where a single `gcd` factors both moduli in milliseconds. None of them requires sage, lattice work, or anything more exotic than a careful read and a small Python brute. All four exist in production code somewhere in the wild.

Per-challenge READMEs, solver scripts, and the original handouts live at [Abdelkad3r/TraceBash-CTF-2026/crypto](https://github.com/Abdelkad3r/TraceBash-CTF-2026/tree/main/crypto).

## The four crypto challenges

| Challenge | Bug class | Points | Flag |
|---|---|---|---|
| state-desync | Stateful XOR keystream with two 8-bit seeds; 65,536 total states, encrypt() is its own inverse, brute the seed pair and look for `TBCTF{` | 100 | `TBCTF{h1dd3n_st4t3_m4chin3_f4il}` |
| broken-trust-protocol | Finite-field DH server accepts `B = p-1` as a peer public key (order-2 element). Shared secret collapses to `(-1)^a mod p`, so it's either `1` or `p-1`. Try both AES keys | 100 | `TBCTF{Sm4ll_Subgr0up_Att4cks_Ar3_D34dly}` |
| harmonic-cipher | 8-second mono WAV, split into 8 one-second pure tones. Each frequency mod 256 gives one byte of an 8-byte repeating XOR key over the 39-byte ciphertext | 100 | `TBCTF{h4rm0n1c_fr3qu3nc13s_4r3_m3l0d1c}` |
| quantum-echo | Two 1024-bit RSA public keys with the same `e=65537`. `gcd(n1, n2)` is a 512-bit factor that divides both moduli; private key for either side falls out in microseconds | 440 | `TBCTF{C0mm0n_Pr1m3s_Ar3_D34dly}` |

Every flag wording is the lesson: small subgroups, common primes, hidden state machines, harmonic frequencies. The author isn't being subtle. The challenge is that each lesson requires you to *see* the structural mistake before the math becomes tractable.

## Methodology — recognise the bug class first, then reach for the math

A pattern that worked across all four challenges: don't open Sage until you've figured out what the bug class is. Crypto challenges fall into a small number of named families (small-subgroup attacks, shared factors, polynomial-bias HNP, partial-information attacks, padding oracles, AEAD nonce reuse, multiplicative-blinding RSA blind signatures, the lot). Each family has a textbook attack with two-line solver code once you've identified it. The work is identification, not derivation.

That's why this article spends most of its words on the *recognition* step for each challenge: what observation in the handout tells you which family this is. Once the family is named, the solve is mechanical. Per-challenge walkthroughs follow.

## state-desync

### The setup

A single Python file `challenge.py` containing a custom stream cipher and the target ciphertext in a comment:

```python
# ciphertext = binascii.unhexlify("1ad9756e666a336be1388c7d132c0a83aecfb9735366374196e187f78e38ece6")
```

The cipher itself looks elaborate. There's a clock-stepped LFSR-style update on `state_b`, an S-box mixing step, and a derived keystream byte per plaintext byte:

```python
def encrypt(data, seed_a, seed_b):
    state_a = seed_a
    state_b = seed_b
    ciphertext = bytearray()

    for byte in data:
        clock_steps = (state_a & 0x0F) + 1
        for _ in range(clock_steps):
            feedback = ((state_b >> 7) ^ (state_b >> 5) ^ (state_b >> 2) ^ (state_b >> 1)) & 1
            state_b = ((state_b << 1) | feedback) & 0xFF

        state_a = custom_sbox(state_a ^ state_b)
        keystream_byte = custom_sbox(state_b) ^ state_a
        ciphertext.append(byte ^ keystream_byte)

    return ciphertext
```

Reading the function carefully, two properties matter way more than the noise.

### Step 1 — Notice the keyspace is only 16 bits

The two seeds are both single bytes:

```python
state_a = seed_a   # 8 bits
state_b = seed_b   # 8 bits
```

That's `256 × 256 = 65,536` total starting states. The clock-stepping, the S-boxes, and the feedback function all look serious, but none of that matters if you can just try every possible initial state in milliseconds. A 16-bit secret state is a 16-bit key, full stop. The update function's complexity is decoration.

### Step 2 — Notice encrypt() is its own inverse

Every plaintext byte is XORed with a keystream byte derived from the current state, and the state update never reads the plaintext or ciphertext. The keystream sequence depends only on `(seed_a, seed_b)`, not on the data. That means:

```python
plain_byte = cipher_byte ^ keystream_byte
```

Running `encrypt()` on the ciphertext with the correct seed pair produces the plaintext. No separate `decrypt()` function is needed; the same routine is its own inverse.

### Step 3 — Brute the 65,536 states

The candidate filter is the flag format. The plaintext is known to start with `TBCTF{` and to be printable ASCII end to end:

```python
def is_printable(b: bytes) -> bool:
    return all(32 <= c < 127 or c in (9, 10, 13) for c in b)

for seed_a in range(256):
    for seed_b in range(256):
        plaintext = bytes(encrypt(ciphertext, seed_a, seed_b))
        if plaintext.startswith(b"TBCTF{") and is_printable(plaintext):
            print(seed_a, seed_b, plaintext.decode())
            return
```

Only one candidate matches:

```
seed_a = 66
seed_b = 19
TBCTF{h1dd3n_st4t3_m4chin3_f4il}
```

Total runtime: a couple of seconds in pure Python.

### Why state-desync works

The bug class here is **insufficient key entropy**, and the lesson is "measure the size of the secret state, not the complexity of the update function." A stream cipher whose initial state fits in two bytes is broken regardless of how interesting its keystream looks. The same shape shows up in production whenever someone wraps `random.seed(short_value)` around any non-trivial generator and treats the wrapper as a cipher.

For a real construction, use a vetted stream cipher (ChaCha20, AES-CTR) or an AEAD (AES-GCM, ChaCha20-Poly1305) with a key large enough that exhaustive search is computationally infeasible. The flag itself is the cleanest summary of the moral: hidden state machine fails.

## broken-trust-protocol

### The setup

Two handout files: `capture.txt` (a captured protocol run) and `protocol.py` (the code that produced it). The code looks like textbook Diffie-Hellman over a finite field:

```python
p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031
g = 2

a = randint(2, p - 2)
A = pow(g, a, p)

B = p - 1
shared = pow(B, a, p)

key = sha256(str(shared).encode()).digest()[:16]
ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(flag, 16))
```

Encryption is plain AES-CBC with PKCS#7 padding. The bug is not in the cipher; it's three lines above.

### Step 1 — Spot the missing public-key validation

The server computes `shared = pow(B, a, p)` where `B` is supplied by the peer. Nothing in the code checks that `B` is a valid Diffie-Hellman public key. In a sound implementation, you'd verify that `B` is in the right range (typically `2 ≤ B ≤ p-2`) and that it belongs to the expected large-order subgroup, but this code skips both.

Then look at `capture.txt`:

```
B = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690030
```

That's exactly `p - 1`, also known as `-1 mod p`. Order 2. The smallest possible attacker-supplied public value that still passes any "is this in range" sanity check (if there had been one).

### Step 2 — Compute the only two possible shared secrets

For an order-2 element, exponentiation collapses to parity:

```
shared = B^a mod p
       = (p - 1)^a mod p
       = (-1)^a mod p
```

That leaves exactly two possible shared secrets:

```
if a is even: shared = 1
if a is odd:  shared = p - 1
```

The attacker doesn't need to solve a discrete logarithm. They don't even need to know whether `a` is odd or even. They just need to try two AES keys.

### Step 3 — Derive both keys and try them

The key derivation is:

```python
key = sha256(str(shared).encode()).digest()[:16]
```

So the two candidate AES keys are:

```python
key1 = sha256(b"1").digest()[:16]
key2 = sha256(str(p - 1).encode()).digest()[:16]
```

Decrypting the captured ciphertext with each and checking PKCS#7 padding immediately picks the winner. The `shared = 1` candidate decrypts to random bytes with invalid padding (Python's `unpad` raises `ValueError`). The `shared = p - 1` candidate produces clean plaintext:

```python
for shared in (1, p - 1):
    try:
        print(decrypt(shared, iv, ct).decode())
        return
    except ValueError:
        continue
```

Output:

```
TBCTF{Sm4ll_Subgr0up_Att4cks_Ar3_D34dly}
```

### Why broken-trust-protocol works

This is the classical **public-key validation** failure in finite-field Diffie-Hellman. Any party that exponentiates an attacker-controlled group element and uses the result as a symmetric key has to verify the element first, full stop. The validation has two parts: range check (the value is a legitimate field element in `[2, p-2]`), and subgroup check (the value belongs to the expected large prime-order subgroup of `Z_p*`).

Without those, three classes of small-subgroup attack become viable:

- The trivial order-1 element: `B = 1` gives `shared = 1` deterministically.
- The trivial order-2 element: `B = p - 1` gives `shared ∈ {1, p-1}`, the case used here.
- Larger small-subgroup elements: if `p-1` has small factors, attackers can pick generators of those small subgroups and learn the plaintext after at most as many AES trials as the subgroup order.

The defender pattern is to use a well-reviewed key-exchange implementation rather than rolling your own, and to prefer modern protocols (X25519, X448, the TLS 1.3 key shares) that perform the required validation internally. If you must use raw integer DH for some legacy reason, the validation needs to be in the route handler, not in a code comment.

## harmonic-cipher

### The setup

Two handout files: `ciphertext.bin` (39 bytes) and `melody.wav`. The ciphertext is short enough to print:

```
ec ac 48 1f d5 c1 78 44 ca 83 3b 25 a2 d9 4f 16
ca dd 7a 3e a0 d4 73 41 8b 9d 54 7f e1 89 4f 1d
8b 82 3b 2f a2 d9 6d
```

The WAV is mono 16-bit PCM, 44,100 Hz, exactly 8 seconds. The challenge title and the 8-second duration are the structural hints.

### Step 1 — Listen, then segment

A quick play of the WAV reveals it's a sequence of pure tones. Eight seconds of audio + the "harmonic cipher" title together imply one tone per second, eight tones total. That gives an 8-element vector of frequencies to recover, and the most natural place to use such a vector is as a repeating XOR key over the 39-byte ciphertext (39 isn't aligned to any block-cipher block size, so a block cipher would be a poor fit).

### Step 2 — Estimate each tone's frequency

For a pure sine wave at frequency `f`, the most robust estimator that doesn't need scipy is a zero-crossing count. For each one-second segment:

```python
import math, wave, struct

with wave.open("melody.wav") as w:
    rate = w.getframerate()
    frames = w.readframes(w.getnframes())
samples = struct.unpack(f"<{len(frames)//2}h", frames)

segment_length = rate                       # one second
frequencies = []
for start in range(0, len(samples), segment_length):
    seg = samples[start:start + segment_length]
    if len(seg) < segment_length:
        break
    signs = [1 if s >= 0 else -1 for s in seg]
    crossings = sum(1 for a, b in zip(signs, signs[1:]) if a != b)
    raw = crossings / (2 * (len(seg) / rate))
    frequencies.append(math.floor(raw + 0.5))
```

The `math.floor(raw + 0.5)` rather than Python's built-in `round()` matters. Generated tone segments produce raw frequencies like `522.5` (half-integer values from off-grid samples), and `round()` uses banker's rounding to even, which rounds `522.5` down to `522`. Off by one byte, the final XOR key is wrong, the plaintext is junk, and you waste ten minutes wondering why the math is wrong when it's the rounding mode.

The eight recovered tones are:

```
440, 494, 523, 587, 659, 698, 784, 880
```

Which is the A-major scale starting at A4: A4, B4, C5, D5, E5, F5, G5, A5.

### Step 3 — Reduce frequencies to a key

The 39-byte ciphertext isn't block-aligned and the implied key is 8 numbers. The natural reduction is `frequency mod 256` per tone:

| Tone | Hz | mod 256 | Hex |
|---|---:|---:|---|
| A4 | 440 | 184 | `b8` |
| B4 | 494 | 238 | `ee` |
| C5 | 523 | 11 | `0b` |
| D5 | 587 | 75 | `4b` |
| E5 | 659 | 147 | `93` |
| F5 | 698 | 186 | `ba` |
| G5 | 784 | 16 | `10` |
| A5 | 880 | 112 | `70` |

Key: `b8 ee 0b 4b 93 ba 10 70`.

### Step 4 — Repeating-XOR decrypt

Standard repeating-key XOR:

```python
key = bytes.fromhex("b8ee0b4b93ba1070")
plaintext = bytes(b ^ key[i % len(key)] for i, b in enumerate(ciphertext))
print(plaintext.decode())
# TBCTF{h4rm0n1c_fr3qu3nc13s_4r3_m3l0d1c}
```

### Why harmonic-cipher works

The bug class here is **secrecy through obscure encoding**, which is not secrecy. Any encoding the recipient can derive (a melody, an image, a EXIF chunk, a file name) is recoverable by anyone with the file. The "side channel" looks clever, but it's deterministic: same WAV in, same key out, same plaintext for any listener.

A short repeating-key XOR over a string with known plaintext (`TBCTF{`) is even more broken, because the first six key bytes drop out from a single XOR against the known prefix. If the ciphertext had been longer or the key shorter, basic frequency analysis would also have worked.

For real encryption, use a high-entropy secret key with an authenticated cipher like AES-GCM or ChaCha20-Poly1305, and treat any "covert" media file as a public artifact.

## quantum-echo

The headline of the crypto track at 440 points. The handout has three files: `public1.pem`, `public2.pem`, and `ciphertext.txt`. The flavour text is the giveaway:

> Two keys. One message. Can you hear the echo?

In RSA-attack land, "two keys, one message" maps to a very short list of classical attacks. The work is choosing the right one.

### Step 1 — Read both keys and rule out the easy options

```python
from Crypto.PublicKey import RSA
k1 = RSA.import_key(open("public1.pem").read())
k2 = RSA.import_key(open("public2.pem").read())
print(f"e1={k1.e}  e2={k2.e}")
print(f"n1.bit_length() = {k1.n.bit_length()}")
print(f"n2.bit_length() = {k2.n.bit_length()}")
print(f"n1 == n2? {k1.n == k2.n}")
```

Output:

```
e1=65537  e2=65537
n1.bit_length() = 1023
n2.bit_length() = 1023
n1 == n2? False
```

That rules out two of the three "two keys, one message" RSA classics:

- **Same modulus, different exponents (Common Modulus Attack):** requires `n1 == n2`. Not the case here.
- **Same small exponent encrypting the same plaintext under multiple moduli (Håstad broadcast):** requires *at least three* ciphertexts under three different moduli for `e=3`, more for larger `e`. We have one ciphertext and `e=65537`. Not viable.
- **Two moduli that share a prime factor:** the only remaining classical attack. One Euclidean-algorithm pass between `n1` and `n2` tells you immediately.

### Step 2 — Compute `gcd(n1, n2)`

```python
import math
p = math.gcd(k1.n, k2.n)
print(p.bit_length())
```

Output:

```
512
```

A non-trivial GCD of two RSA moduli is catastrophic. It means `n1 = p · q1` and `n2 = p · q2` for the *same* `p`, and the Euclidean algorithm has just handed you that shared `p` in microseconds. Both moduli are now factored.

### Step 3 — Build the matching private key and decrypt

The ciphertext was encrypted under one of the two keys (we don't know which yet). Build the private exponent for `n1` first:

```python
q1  = k1.n // p
phi = (p - 1) * (q1 - 1)
d1  = pow(k1.e, -1, phi)
m   = pow(ct, d1, k1.n)
```

Convert `m` back to bytes:

```python
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(m).decode())
```

Output:

```
TBCTF{C0mm0n_Pr1m3s_Ar3_D34dly}
```

If the first decryption produces garbage, repeat against `n2` (`d2 = pow(e, -1, (p-1)*(q2-1))`). One of the two will be the right side and the other will return non-printable bytes that you'd recognise immediately.

### Why quantum-echo works

The "quantum" in the title is the flavour, not the attack. There's nothing quantum here. The real bug is a shared 512-bit prime between two independently-generated keys, which is a known production failure mode at significant scale:

- **Mining your Ps and Qs (Heninger et al., USENIX Security 2012)** scanned the entire IPv4 HTTPS space and found ~0.5% of TLS certificates and ~1% of SSH host keys shared an RSA factor with at least one other host. The cause was almost universally embedded devices generating keys before their entropy pool was seeded.
- **CVE-2017-15361 (ROCA)** in Infineon's RSALib: structurally weak primes meant millions of fielded keys could be factored. Different mechanism, same observable: two RSA keys you'd expect to be independent share hidden structure.

The defender side is mostly a generation-time problem. Seed your CSPRNG with sufficient entropy *before* any key material is produced (on Linux, prefer `getrandom(2)` over raw `/dev/urandom` at boot). Use vetted prime generation from a reviewed library, not your own. For fleets of devices or certificates, periodically run a pairwise-GCD audit; the batch-GCD algorithm finds all shared factors in a million-key corpus in seconds. If any two of your moduli ever share a prime, you want to be the first to know rather than the attacker.

A single `math.gcd` between two of your public keys should always return `1`. If it doesn't, both private keys are already gone.

## Cross-cutting defender notes

Three patterns recur across the TraceBash crypto track and travel into production work.

**Measure the size of the secret state, not the complexity of the update function.** state-desync looks like a serious cipher and is brute-forceable in seconds because the initial state is 16 bits. The same antipattern appears in production whenever someone seeds a stateful generator from a short integer (a session ID, a timestamp, a UID) and treats the generator's output as cryptographically random. The state is whatever can be brute-forced; the rest is decoration.

**Validate every attacker-supplied public-key value before exponentiating against it.** broken-trust-protocol's bug is the absence of any check on `B`. The same shape recurs in TLS implementations that accept malformed peer key shares, in WebAuthn flows that don't validate attestation certificates, in Bitcoin signature verifications that accept non-canonical encodings. Any time an attacker-supplied value is the base of an exponentiation, that value needs a range check and a subgroup check before it's safe to use the result.

**Pairwise-GCD audit any RSA key population.** quantum-echo's bug is in the field at scale (Heninger 2012, ROCA 2017, anywhere else two independently-generated keys turned out to share structure). For any fleet of RSA keys you operate (TLS certificates across edge nodes, SSH host keys across embedded devices, signing keys in a CI/CD pipeline), the batch-GCD algorithm is cheap to run and catches the exact failure quantum-echo demonstrates. If you can't run batch-GCD yourself, sign up to a third party that does (Censys has historically published these audits).

## Frequently asked questions

### What is TraceBash CTF?

TraceBash CTF is a Jeopardy-style CTF whose 2026 edition shipped challenges across cryptography, web, reverse, forensics, pwn, misc, and OSINT. This writeup covers the four cryptography challenges. The flag prefix is `TBCTF{...}`. Per-challenge READMEs and solver scripts live at [Abdelkad3r/TraceBash-CTF-2026](https://github.com/Abdelkad3r/TraceBash-CTF-2026).

### What's the bug in state-desync?

The custom stream cipher uses two 8-bit seeds for its entire secret state, which is only 65,536 possible starting points. The clock-stepped LFSR-style update and S-box mixing all look serious, but the cipher's encrypt() routine is its own inverse (because every plaintext byte is XORed with a state-derived keystream byte that doesn't depend on the data). Brute every `(seed_a, seed_b)` pair and check whether the "decryption" starts with `TBCTF{` and is printable ASCII. One pair matches: `(66, 19)`.

### What's the small-subgroup attack on broken-trust-protocol?

The server accepts the peer's public value `B = p - 1` without validation. `p - 1` is an order-2 element (`-1 mod p`), so `shared = B^a mod p = (-1)^a mod p` is either `1` (if `a` is even) or `p - 1` (if `a` is odd). Two possible shared secrets means two candidate AES keys. Trying both against the captured ciphertext, the `shared = p - 1` candidate decrypts to valid PKCS#7-padded plaintext. The attack doesn't require knowing `a` or solving a discrete logarithm.

### How do you defend against small-subgroup attacks in finite-field DH?

Validate the peer's public value before using it as a base for exponentiation. Two checks: range (the value is in `[2, p-2]`) and subgroup membership (the value belongs to the expected prime-order subgroup, typically `pow(B, q, p) == 1` for subgroup order `q`). Modern protocols like X25519 do this validation as part of the standard implementation, which is why they're preferred for new designs. Rolling raw integer DH without these checks is dangerous.

### How does the harmonic-cipher key derivation work?

The 8-second WAV splits into eight one-second pure tones. For each segment, count zero-crossings and divide by twice the duration to estimate the dominant frequency. Use `math.floor(raw + 0.5)` rather than `round()` because Python's banker's rounding turns half-integer raw values like `522.5` into `522`, which is off by one byte. The eight integer frequencies (`440, 494, 523, 587, 659, 698, 784, 880`, an A-major scale) mod 256 produce an 8-byte repeating XOR key over the 39-byte ciphertext.

### Why doesn't Python's `round()` work for harmonic-cipher?

`round()` in Python 3 uses banker's rounding (round-half-to-even). For a raw frequency of `522.5`, banker's rounding goes to `522` (even), but the correct frequency is `523`. Off-by-one frequency means off-by-one byte in the XOR key, and the entire plaintext comes out as garbage at every 8-byte boundary. `math.floor(raw + 0.5)` does standard half-up rounding and produces the correct integer.

### What's the bug in quantum-echo?

Two RSA-1024 public keys share a 512-bit prime. `gcd(n1, n2)` returns the shared prime `p` in microseconds. With `p` recovered, both moduli factor immediately (`q1 = n1 / p`, `q2 = n2 / p`), and either private key can be reconstructed (`d = pow(e, -1, (p-1)*(q-1))`). The flavour text "two keys, one message" plus same exponent `e=65537` and different moduli rules out Common Modulus Attack and Håstad broadcast, leaving the shared-prime attack as the only classical "two keys, one message" RSA bug.

### How does the shared-prime attack scale in real-world RSA deployments?

Pairwise GCD between two keys is constant-time, but auditing a fleet of N keys with pairwise GCD is O(N²), which doesn't scale past a few thousand keys. The **batch-GCD algorithm** (Bernstein 2013) computes all pairwise GCDs across a corpus of N keys in roughly O(N log² N) time. Heninger et al. (2012) used batch-GCD to scan the entire IPv4 HTTPS and SSH key space in hours and found ~0.5–1% of keys shared factors with at least one other key. Any large RSA key population should be batch-GCD'd periodically.

### Why isn't this challenge actually "quantum"?

The "Quantum Echo Research Facility" framing and the title are pure flavour. No quantum algorithm is needed and no post-quantum primitive is involved. The classical attack on shared RSA primes (Euclidean GCD) has been the standard textbook attack since RSA was first formalised. Calling it "quantum" is the kind of misdirection that makes the challenge fun once you recognise that "two keys, one message" maps to a classical RSA pitfall, not a quantum one.

### Where can I find the solver scripts?

Per-challenge READMEs and complete Python solvers live at [Abdelkad3r/TraceBash-CTF-2026/crypto](https://github.com/Abdelkad3r/TraceBash-CTF-2026/tree/main/crypto). Each challenge directory has a `handout/` with the original files, a `solve.py` reproducing the end-to-end attack, and a `README.md` documenting the reasoning. The state-desync solver is twenty lines. The broken-trust-protocol solver is shorter. quantum-echo's is a one-line `gcd` plus the standard RSA decryption.

### What's the broader lesson from the TraceBash crypto track?

All four bugs reduce to a single recognition step: name the bug class, then run the textbook attack. state-desync = insufficient key entropy → exhaustive search. broken-trust-protocol = missing public-key validation → two-candidate brute. harmonic-cipher = repeating XOR with deterministically-recoverable key → standard XOR-with-known-key. quantum-echo = shared RSA prime → batch-GCD. None of these requires Sage, fpylll, or a lattice. They require reading the handout carefully enough to identify which named family of attack applies, then writing five to twenty lines of solver code.

## Closing notes

Four challenges, four classical crypto pitfalls. state-desync at 100 points teaches "measure the keyspace, not the cipher." broken-trust-protocol at 100 points teaches "validate public-key inputs." harmonic-cipher at 100 points teaches "encoding is not encryption." quantum-echo at 440 points teaches "audit your RSA key populations for shared primes." All four are well-suited as warm-ups for newer crypto players because the bug classes are named, the attacks are documented in any cryptography textbook, and the solver code in each case is short enough to fit in a single article section.

For more cryptography-flavoured CTF coverage on this site, the [DalCTF 2026 writeup](/ctf-writeups/dalctf-2026-writeup/) covers six classical-crypto challenges (Playfair, Huffman tiebreak, small-factor RSA, IEEE-754 type punning, LCG known-plaintext, Bellcore fault on RSA-FDH), the [Anti-Slop CTF 2026 crypto writeup](/ctf-writeups/anti-slopctf-2026-crypto-writeup/) covers a 24-bit ECDSA nonce HNP attack solved with `fpylll` CVP and a CBC-MAC splice past a fixed domain header, and the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) covers four crypto challenges including the AVX2 lane-swap miscompile in `justfollowtherecipe` and the missing-mod-q NTRU bug in `guess-the-taste`. Full [CTF writeups index](/ctf-writeups/) for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is TraceBash CTF?","acceptedAnswer": {"@type": "Answer","text": "TraceBash CTF is a Jeopardy-style CTF whose 2026 edition shipped challenges across cryptography, web, reverse, forensics, pwn, misc, and OSINT. This writeup covers the four cryptography challenges. The flag prefix is TBCTF{...}. Per-challenge READMEs and solver scripts live at github.com/Abdelkad3r/TraceBash-CTF-2026."}},
    {"@type": "Question","name": "What's the bug in state-desync?","acceptedAnswer": {"@type": "Answer","text": "The custom stream cipher uses two 8-bit seeds, which is only 65,536 possible starting states. The cipher's encrypt() is its own inverse (every plaintext byte is XORed with a state-derived keystream byte). Brute every (seed_a, seed_b) and check for TBCTF{ printable plaintext. The match is (66, 19)."}},
    {"@type": "Question","name": "What's the small-subgroup attack on broken-trust-protocol?","acceptedAnswer": {"@type": "Answer","text": "The server accepts B = p - 1 without validation. p - 1 is an order-2 element, so shared = B^a mod p = (-1)^a mod p is either 1 or p - 1. Two possible AES keys means two candidate decrypts. The shared = p - 1 candidate decrypts to valid PKCS#7-padded plaintext."}},
    {"@type": "Question","name": "How do you defend against small-subgroup attacks in finite-field DH?","acceptedAnswer": {"@type": "Answer","text": "Validate the peer's public value: range check (value in [2, p-2]) and subgroup membership (value belongs to the expected prime-order subgroup). Modern protocols like X25519 do this validation as part of the standard implementation, which is why they're preferred for new designs."}},
    {"@type": "Question","name": "How does the harmonic-cipher key derivation work?","acceptedAnswer": {"@type": "Answer","text": "The 8-second WAV splits into eight one-second pure tones. Zero-crossing counts give the dominant frequency per segment. Use math.floor(raw + 0.5) rather than round() because banker's rounding turns 522.5 into 522, which is off by one byte. The eight frequencies (440, 494, 523, 587, 659, 698, 784, 880, an A-major scale) mod 256 produce an 8-byte repeating XOR key over the 39-byte ciphertext."}},
    {"@type": "Question","name": "Why doesn't Python's round() work for harmonic-cipher?","acceptedAnswer": {"@type": "Answer","text": "round() in Python 3 uses banker's rounding (round-half-to-even). For raw frequency 522.5, banker's rounding goes to 522, but the correct frequency is 523. Off-by-one frequency means off-by-one byte in the XOR key. math.floor(raw + 0.5) does standard half-up rounding."}},
    {"@type": "Question","name": "What's the bug in quantum-echo?","acceptedAnswer": {"@type": "Answer","text": "Two RSA-1024 public keys share a 512-bit prime. gcd(n1, n2) returns the shared prime in microseconds. With p recovered, both moduli factor, either private key can be reconstructed, and the ciphertext decrypts. The flavour text 'two keys, one message' plus same e=65537 and different moduli rules out Common Modulus and Håstad, leaving shared-prime as the only classical attack."}},
    {"@type": "Question","name": "How does the shared-prime attack scale in real-world deployments?","acceptedAnswer": {"@type": "Answer","text": "Pairwise GCD across N keys is O(N²), but batch-GCD (Bernstein 2013) computes all pairwise GCDs in O(N log² N). Heninger et al. (2012) used batch-GCD to scan the entire IPv4 HTTPS and SSH space in hours and found ~0.5–1% of keys shared factors with at least one other key. Large RSA key populations should be batch-GCD'd periodically."}},
    {"@type": "Question","name": "Why isn't this challenge actually quantum?","acceptedAnswer": {"@type": "Answer","text": "The 'Quantum Echo Research Facility' framing and title are flavour. No quantum algorithm is needed and no post-quantum primitive is involved. The classical attack on shared RSA primes (Euclidean GCD) has been the textbook attack since RSA was formalised. The 'quantum' label is misdirection."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs and complete Python solvers live at github.com/Abdelkad3r/TraceBash-CTF-2026/tree/main/crypto. Each challenge directory has handout/ with the original files, solve.py reproducing the end-to-end attack, and README.md documenting the reasoning."}},
    {"@type": "Question","name": "What's the broader lesson from the TraceBash crypto track?","acceptedAnswer": {"@type": "Answer","text": "All four bugs reduce to recognising a named family of cryptographic mistake and running the textbook attack. state-desync = insufficient key entropy. broken-trust-protocol = missing public-key validation. harmonic-cipher = repeating XOR with derivable key. quantum-echo = shared RSA prime. None require Sage, fpylll, or a lattice; they require careful reading and 5–20 lines of solver code each."}}
  ]
}
</script>
