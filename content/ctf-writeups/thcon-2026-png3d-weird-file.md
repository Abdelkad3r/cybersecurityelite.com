---
title: "THCON 2026 PNG3D: Hidden PNG Inside Two Emojis (weird_file.thc)"
slug: "thcon-2026-png3d-weird-file"
description: "THCON 2026 PNG3D walkthrough — a 40 MB .thc file looks like noise but is binary-encoded with thumbs-up/down emojis. Decoding MSB-first reveals a full PNG."
date: 2026-05-16T12:00:00Z
lastmod: 2026-05-16T12:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["thcon", "thcon-ctf", "steganography", "encoding", "png", "frequency analysis"]
series: ["THCON CTF 2026"]
keywords: ["thcon 2026 png3d writeup", "weird_file.thc thcon", "emoji binary encoding ctf", "png lsb steganography ctf", "thumbs up thumbs down ctf"]
toc: true
cover:
  image: "/images/thcon.jpg"
  alt: "THCON 2026 PNG3D weird_file.thc writeup"
---

{{< ctf-meta platform="THCON 2026 (Toulouse Hacking Convention)" difficulty="Medium" os="Steganography" skills="Frequency analysis, binary encoding, PNG carving, LSB steganography" >}}

PNG3D is the steganography challenge that rewards the simplest possible recon move — frequency analysis — and punishes anyone who tries fancy stego tools first. The challenge file is ~40 MB of UTF-8 text that looks like noise; the trick is to notice that **two** specific characters make up nearly all of it, in roughly equal numbers, and that's a binary encoding screaming to be decoded.

Source: [Abdelkad3r/thcon-ctf-2026 · 03-stego-weird-file/](https://github.com/Abdelkad3r/thcon-ctf-2026/tree/main/03-stego-weird-file).

## The File

`weird_file.thc`, ~40 MB. `file` reports it as UTF-8 text with very long lines. First 64 bytes:

```text
👍hOv👎Vq👎DgIsm👎S👍UjfSP👎R👎YnOt👍OEeMz👎bE…
```

ASCII letters and 👍 / 👎 emojis. There's no obvious structure on the surface — no headers, no magic bytes, nothing that looks like a known format.

## Step 1 — Frequency Analysis

When in doubt, count. Frequency analysis on the full file is the cheapest possible recon and almost always tells you the encoding family.

```python
from collections import Counter

data = open('weird_file.thc', 'r', encoding='utf-8').read()
counts = Counter(data)
print(counts.most_common(15))
```

| Char | Count |
|------|------:|
| 👍 (U+1F44D) | 2,848,721 |
| 👎 (U+1F44E) | 2,832,927 |
| `e`, `d`, `R`, `Y`, `n`, `C`, `T`, `A`, `N`, `j`, … | ~328,000 each |

Two observations jump out:

1. **The two emojis dominate** — they make up >75% of the file.
2. **They appear in nearly equal counts** (2.85M vs 2.83M, within 0.6%).

Almost-balanced pair of dominant symbols is the canonical fingerprint of a **binary encoding**: 👍 = 1, 👎 = 0. The ASCII letters in between are filler — visually-noisy padding meant to confuse you into trying letter-frequency analysis or substitution ciphers. Their run lengths between emojis are uniformly distributed 1–5 characters, so they encode nothing meaningful.

Total emoji count: 5,681,648 → 710 KB of data once we pack 8 bits per byte. More than enough for an embedded image.

## Step 2 — Decode the Bit Stream

```python
data = open('weird_file.thc', 'r', encoding='utf-8').read()

bits = []
for ch in data:
    if   ch == '\U0001f44d': bits.append(1)   # 👍
    elif ch == '\U0001f44e': bits.append(0)   # 👎
    # everything else (ASCII filler) is ignored

# Pack MSB-first
out = bytearray()
for i in range(0, len(bits) // 8 * 8, 8):
    b = 0
    for j in range(8):
        b = (b << 1) | bits[i + j]
    out.append(b)

print(out[:8].hex())     # → 89504e470d0a1a0a
```

`89 50 4E 47 0D 0A 1A 0A` — the **PNG signature**. We have a PNG embedded in the emoji stream. Trim to `IEND` plus the trailing 8 bytes and write it out:

```python
end = out.find(b'IEND') + 8
open('hidden.png', 'wb').write(out[:end])
```

{{< callout type="tip" title="MSB-first vs LSB-first is always a coin flip" >}}
When you reconstruct a bit stream from any source — emojis, dotting patterns, audio samples — both packing orders are worth trying. PNG, JPEG, ELF, ZIP all start with high bytes that look obviously like a magic when packed correctly and like uniform noise when packed wrong. If the first 4-8 bytes don't pattern-match a known file format in *either* direction, the encoding probably isn't simple bit-packing.
{{< /callout >}}

## Step 3 — The PNG

A complete 1000×1000 RGB PNG opens cleanly. It's a cyberpunk robot face with red glowing eyes, the text **`M4terM4xima`** rendered in a heavy-metal font, and a tagline reading *"much you dying, vewy fun"*. Top-right corner, in small white letters:

```
THC{PNG3D}
```

`PNG3D` reads as "PNG-ed" — i.e. *you got PNG'd*. THCON's writeup confirms it: the challenge name is the joke.

## Flag

```
THC{PNG3D}
```

## Phase 2 — Unsolved (Worth Noting)

The challenge has a follow-up phase. Quoting the prompt:

> Well, now we know for certain that something lies in this file. We have sent your image to an elite steganographer here at SNAFU. He has since become totally insane and keeps repeating that *"the music's URL is the key"* — do with this as you please.

The PNG's per-channel **LSBs** clearly contain another layer. Mask them and you can see structure:

```python
from PIL import Image
import numpy as np

arr = np.array(Image.open('hidden.png').convert('RGB'))
lsb_any = (arr[:,:,0] & 1) | (arr[:,:,1] & 1) | (arr[:,:,2] & 1)
Image.fromarray(((1 - lsb_any) * 255).astype('uint8')).save('qr.png')
```

The result is a stylised **art-style QR code** — circular finder patterns instead of the standard square ones — that I couldn't get any decoder to read (OpenCV's `QRCodeDetector`, `zxing-cpp`, WeChat's QR module with the model files, all failed on the non-standard finders).

The intended path seems to be:

1. Identify the song referenced by **M4terM4xima** (heavy-metal font + the typography is doing a Metallica impression).
2. Take the song's YouTube URL.
3. Use the URL (or a hash/transform of it) as the **AES key** to decrypt the LSB payload, or to reveal a custom QR decoding orientation.

I didn't get past song identification in the live session. If you crack this, ping me.

## Lessons learned

1. **Frequency analysis is the cheapest, highest-ROI first move on any stego challenge.** A 1-second `Counter` on the file tells you the alphabet, and the alphabet usually telegraphs the encoding.

2. **"Almost-balanced pair of dominant symbols" = binary encoding.** Two emojis, two punctuation marks, two case-variants of the same letter — the pattern is the same. The remaining characters are noise.

3. **PNG signatures are easy to spot.** `89504E470D0A1A0A` should be muscle memory. Other common magics worth knowing for stego: `FFD8FF` (JPEG), `1F8B` (gzip), `504B0304` (ZIP), `425A68` (bzip2), `7F454C46` (ELF).

4. **Stylised "art-style" QR codes break every off-the-shelf decoder.** Solving them either requires manual reconstruction of the bit matrix (counting modules with image-processing) or recognising it as a clue pointing somewhere else — in this case, the song lyrics / URL.

5. **Don't fight obfuscated tools when the meta-clue is clearer.** The phase-2 hint *"the music's URL is the key"* is the actual puzzle; the QR is the carrier. Recognising which is which saves hours.

## References

- [PNG file format specification](https://www.w3.org/TR/PNG/)
- [Aperi'Solve](https://www.aperisolve.com/) — automated multi-tool stego analysis (good for sanity checks)
- [zsteg](https://github.com/zed-0xff/zsteg) — PNG/BMP LSB stego detector
- [stegsolve](http://www.caesum.com/handbook/Stegsolve.jar) — bit-plane viewer
- Source writeup: [thcon-ctf-2026/03-stego-weird-file/README.md](https://github.com/Abdelkad3r/thcon-ctf-2026/blob/main/03-stego-weird-file/README.md)
