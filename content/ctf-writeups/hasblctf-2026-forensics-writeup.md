---
title: "HASBLCTF 2026 Forensics Writeup: All 5 Challenges Solved"
slug: "hasblctf-2026-forensics-writeup"
description: "HASBLCTF 2026 forensics writeup — all 5 challenges solved: QR decode, bit-stream JPEG, base64-wrapped JPEG, EXIF vs COM metadata, and magic-byte repair."
date: 2026-06-01T05:00:00Z
lastmod: 2026-06-01T05:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "hasblctf"
  - "hasbl ctf"
  - "ctf 2026"
  - "forensics"
  - "digital forensics"
  - "jpeg forensics"
  - "qr code forensics"
  - "exif metadata"
  - "jfif"
  - "base64"
  - "base32"
  - "reed-solomon"
  - "magic bytes"
  - "file carving"
  - "pyzbar"
  - "xmp metadata"
series: ["HASBL CTF 2026"]
keywords:
  - "hasblctf 2026 forensics writeup"
  - "hasblctf forensics writeup"
  - "hasbl ctf forensic challenges"
  - "hasblctf quick response writeup"
  - "hasblctf logo writeup"
  - "hasblctf digits writeup"
  - "hasblctf pamuk forensic writeup"
  - "hasblctf magic numbers writeup"
  - "jpeg magic byte repair"
  - "exif imagedescription base64"
  - "jpeg com segment vs exif"
  - "bit stream to jpeg ctf"
  - "pyzbar qr code overlay"
  - "base64 fingerprint /9j/4A"
  - "jpeg magic ffd8ffe0"
  - "xmp metadata flag ctf"
  - "reed solomon qr error correction"
toc: true
cover:
  image: "/images/articles/hasblctf-2026-forensics-writeup.png"
  alt: "HASBLCTF 2026 forensics writeup — all 5 challenges (Quick Response, Logo, Digits, Pamuk, Magic Numbers)"
---

{{< ctf-meta platform="HASBL CTF 2026" difficulty="Mixed (Easy → Medium)" os="Jeopardy — Forensics (Linux toolchain)" skills="QR-code decoding with Reed-Solomon tolerance, JPEG metadata extraction (EXIF, COM, XMP), base64/base32 encoding fingerprints, bit-stream-to-JPEG reconstruction, magic-byte surgical repair, file-header recognition" >}}

**HASBL CTF 2026** is a multi-category jeopardy event with Reverse Engineering, Pwn, Web, and Forensics tracks. This writeup is dedicated to the **Forensics track** — the five forensics challenges (`Quick Response`, `Logo`, `Digits`, `our sweet cat, Pamuk`, and `The Magic of "Magic Numbers"`) were all solved, and each one teaches a different file-forensics primitive: QR-code decoding despite a visual overlay, JPEG metadata extraction across EXIF and COM segments, bit-stream-to-JPEG byte reconstruction, base64-wrapped JPEG with hex content, and surgical magic-byte repair plus XMP metadata walking.

This is the master writeup for the forensics track. Each challenge below covers the file's structure, the hidden layer, and the recovered flag. Full per-challenge reproductions — solver scripts and handout files — live in the source repository: [Abdelkad3r/hasblctf-2026](https://github.com/Abdelkad3r/hasblctf-2026).

## The forensics track at a glance

| Challenge                          | File                                   | Core technique                                                                                  |
|------------------------------------|----------------------------------------|-------------------------------------------------------------------------------------------------|
| Quick Response                     | 222×222 JPEG (Terry Davis QR)          | `pyzbar` decodes the QR despite the dithered portrait overlay — Reed-Solomon ECC absorbs the damage |
| Logo                               | 1150×646 JPEG (school logo)            | Two encoded blobs in two segments — base64 in EXIF `ImageDescription` (flag), base32 in JFIF `COM` (decoy) |
| Digits                             | 169 800-byte ASCII `0`/`1` stream      | 8-bit MSB-first repack → JPEG header `FF D8 FF E0`; reconstructed image contains the flag text |
| our sweet cat, Pamuk               | 821 KB single-line `.txt`               | Base64 prefix `/9j/4A` ⇒ encoded JPEG; image has a 50-char hex overlay = ASCII flag             |
| The Magic of "Magic Numbers"       | 198 113-byte `Aphelios.bin`            | Bytes `[0:4]` zeroed and `[6:10]` rewritten to `"XXXX"` — patch back to `FF D8 FF E0 … JFIF`, read XMP for flag |

## Methodology — a forensics checklist

The four-step framework for forensics challenges:

1. **Identify.** `file` for type signature, `xxd | head -c 64` for the first 32-64 bytes. The header bytes are the entire identity of most file formats — JPEG starts `FF D8 FF E0`, PNG starts `89 50 4E 47`, ZIP starts `50 4B 03 04`, PDF starts `25 50 44 46`. Half the forensics challenges in this set hide *behind* a missing or wrong header; recognising the canonical bytes lets you spot the absence as easily as the presence.
2. **Decode.** Recognise encoding fingerprints. Base64 of `HASBL{...}` always starts `SEFTQkx7...`. Base64 of a JPEG always starts `/9j/4A`. Base32 uses the alphabet `[A-Z2-7]` with `=` padding. ASCII `0`/`1` streams divisible by 8 are bit-packed bytes. Peel the wrapper before you try to interpret the contents.
3. **Extract.** Walk into metadata containers — EXIF, JFIF `COM`, XMP, ICC profiles. The flag is almost never in the rendered image; it's in a segment three layers deep that `xdg-open` doesn't surface.
4. **Read.** OCR text out of images (`tesseract`), eyeball short hex strings, decode base64/base32 to ASCII. Verify against the expected format prefix (`HASBL{` for this event) so you know you've landed.

{{< callout type="info" title="The recurring pattern: it's always a JPEG" >}}
Four of the five HASBL CTF 2026 forensics challenges are JPEGs — wrapped, encoded, bit-packed, or with the magic bytes surgically removed. If your forensics toolkit doesn't include a 30-second checklist for "is this a JPEG with X done to it?" you'll burn the easy ones. The JPEG SOI marker (`FF D8`) and the JFIF APP0 marker (`FF E0` + `"JFIF\0"` at offset 6) are the two fingerprints that recur in every challenge.
{{< /callout >}}

---

## Quick Response — Reed-Solomon ECC eats the portrait

```bash
$ file QR_Code_Holy
JPEG image data, JFIF standard 1.01, …, 222x222, components 3
```

A small JPEG of a QR code with **Terry A. Davis's portrait dithered over the data modules**. The three big corner squares (finder patterns) are intact, the timing patterns are recognisable, and despite the visual overlay the decoder pulls the payload on the first try.

### The solve

```python
from pyzbar import pyzbar
from PIL import Image

print(pyzbar.decode(Image.open("QR_Code_Holy"))[0].data)
# b'Terry_Davis_1s_th3_b35t'
```

Wrap with the event's flag format → `HASBL{Terry_Davis_1s_th3_b35t}`.

### Why this works despite the overlay

QR codes ship with one of four error-correction levels — **L (~7%), M (~15%), Q (~25%), H (~30%)** — using Reed-Solomon. The portrait covers data modules but the *bounding* structure is intact:

- The three **finder patterns** (the high-contrast 7×7 bullseyes in the top-left, top-right, and bottom-left corners) are preserved exactly. The decoder uses them to find the code's centre and rotation.
- The **timing patterns** — the alternating black/white run across row 6 and column 6 — survive enough for zbar to estimate the module size.
- The **format-information ring** around each finder, with mask + ECC level encoded twice for redundancy, is mostly intact, so the decoder knows which XOR mask to apply *before* it tries to recover data bits.

The data modules are visually destroyed by the portrait but only need *enough* surviving modules to fall under the ECC budget. The string `Terry_Davis_1s_th3_b35t` is 23 alphanumeric characters; with QR alphanumeric encoding that's ~127 bits of data plus a small mode/length header. Even at ECC level H, the overlay's dithered perturbation leaves most modules readable on average.

**Flag:** `HASBL{Terry_Davis_1s_th3_b35t}`

**Forensics takeaway:** QR codes were designed to absorb exactly this kind of stunt. The same logo-in-QR design is used commercially — restaurant menus, ad campaigns, the "scan to pay" QRs in coffee shops. If `pyzbar` refuses to lock on a heavier overlay, the fallback chain is *upscale + threshold* (`Image.resize(..., NEAREST)` then a binary point-filter at 128) → *median filter* to suppress per-pixel noise → *manual module extraction* by sampling the centre pixel of each `module_size × module_size` cell.

---

## Logo — base64 in EXIF, base32 in COM (one's a decoy)

```bash
$ file HASBL_Logo.jpg
JPEG image data, JFIF standard 1.01, …,
  Exif Standard: [..., description=SEFTQkx7VGg0bmtfMHVyX3RlYWNoM3JzX01zS3VicmFfNG5kX01yS2FkaXJ9, ...],
  comment: "JZUWGZJAORZHSIJB", …
```

`file(1)` alone surfaces both encoded strings. Two metadata containers, two different encodings, two different destinations:

| Container | Encoded blob | Decoded |
|---|---|---|
| **EXIF `ImageDescription`** (TIFF tag `0x010E`) | `SEFTQkx7VGg0bmtfMHVyX3RlYWNoM3JzX01zS3VicmFfNG5kX01yS2FkaXJ9` (base64) | **`HASBL{Th4nk_0ur_teach3rs_MsKubra_4nd_MrKadir}`** ← flag |
| **JFIF `COM`** (`0xFFFE`) | `JZUWGZJAORZHSIJB` (base32) | `Nice try!!` ← decoy |

### Recognising the encodings on shape

You can tell them apart without decoding:

- `SEFTQkx7…J9` — the `SEFTQkx7` prefix is the **canonical base64 fingerprint for any string starting `HASBL{`**:
  - `'H' = 0x48 = 01001000`, `'A' = 0x41 = 01000001`, `'S' = 0x53 = 01010011`
  - First 24 bits: `010010 000100 000101 010011`
  - Base64 indices `18, 4, 5, 19` → `S, E, F, T`

  Whenever you see `SEFT...` in this CTF, it's base64 of `HAS...`. The trailing `J9` corresponds to `}\0\0` in the last triplet group.

- `JZUWGZJAORZHSIJB` — base32's alphabet is `[A-Z2-7]`. 16 characters, all `[A-Z]`, no padding → a clean `16/8 × 5 = 10` byte payload, which is exactly the length of `"Nice try!!"`. Recognisable before you decode.

### Why the EXIF one matters and the COM one doesn't

Both segments are technically "comments" but they live in completely different parts of the file:

- The **JPEG `COM` segment (`FF FE` marker)** is a top-level JPEG metadata segment. `file(1)` and `strings(1)` surface it immediately. Putting the *real* flag here would be obvious.
- The **EXIF `ImageDescription` tag** lives inside an **APP1 segment**, which contains a TIFF header (with its own endianness) and an **Image File Directory (IFD)** of `(tag, type, count, value)` entries. To reach `ImageDescription` you parse APP1 → identify `Exif\0\0` → parse TIFF → walk the IFD → follow the offset to the string data. Three layers deeper than `COM`.

The author put the flag where extraction takes one extra step.

```python
from PIL import Image
im = Image.open("HASBL_Logo.jpg")
exif = im._getexif()
import base64
print(base64.b64decode(exif[0x010E]).decode())
# HASBL{Th4nk_0ur_teach3rs_MsKubra_4nd_MrKadir}
```

**Flag:** `HASBL{Th4nk_0ur_teach3rs_MsKubra_4nd_MrKadir}`

**Forensics takeaway:** when a JPEG carries multiple metadata payloads, the *deepest* one is almost always the answer. JFIF `COM` is surfaced by every tool by default; EXIF requires parsing a TIFF inside an APP1; XMP requires XML parsing inside an APP1; ICC profile data requires walking yet another encoding. CTF authors put decoys in shallow containers and flags in deep ones — exactly inverse to the difficulty curve.

---

## Digits — bit-stream of a JPEG

```bash
$ file digits.bin
ASCII text, with very long lines (65536), with no line terminators

$ head -c 80 digits.bin
1111111111011000111111111110000000000000000100000100101001000110010010
```

169 800 ASCII `0` and `1` characters on a single line. Read 8 chars at a time MSB-first → a clean JPEG.

### Picking the encoding without guessing

Three shape checks land you on "8-bit MSB-first" instantly:

1. **Length divisibility.** `169 800 / 8 = 21 225` (clean). `/16` → not integer. `/7` → not integer. Only natural width that fits is **8**.

2. **First-32-bit fingerprint.** The first 32 characters are:

   ```text
   11111111  11011000  11111111  11100000
        FF        D8        FF        E0
   ```

   `FF D8 FF E0` is the **JPEG SOI marker followed by JFIF APP0** — the most recognisable file header in forensics. Confirms MSB-first: LSB-first would produce `FF 1B FF 07`, which is nothing.

3. **Segment-length sanity.** Bytes 4–5 are `00 10` = 16, the standard JFIF APP0 segment length. Bytes 6–9 are `4A 46 49 46` = `"JFIF"`. So you're inside a well-formed JPEG, not just a coincidental header.

### The solve

```python
bits = open("digits.bin").read().strip()
data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
open("digits.jpg", "wb").write(data)
```

The reconstructed 1600×1131 JPEG is a Word-style page with a single line of black text on a white background: `HASBL{Istanbul_1s_b3atiful_c1ty}`.

**Flag:** `HASBL{Istanbul_1s_b3atiful_c1ty}`

**Forensics takeaway:** when a forensics challenge hands you a string of binary digits, the four standard moves are *8-bit MSB-first* (default), *8-bit LSB-first*, *7-bit ASCII*, and *6-bit base64*. Test against the file-header fingerprint of the most common formats — JPEG, PNG, PDF, ZIP, ELF. The first 32 bits eliminate three of four packings without needing to write the rest to disk. The JFIF version field `01 01` two segments later is the fast confirm — if you got the packing wrong, that field is garbage.

---

## our sweet cat, Pamuk — base64-wrapped JPEG with a hex overlay

```bash
$ head -c 16 pamuk.txt
/9j/4AAQSkZJRg
```

`/9j/4A` is **the most common base64 fingerprint in the world**. Bytes `FF D8 FF E0` (JPEG SOI + JFIF APP0) in binary are `11111111 11011000 11111111 11100000`. Take 6 bits at a time:

```text
111111 111101 100011 111111 111000 0000…
  63     61     35     63     56    0…
   /      9      j      /      4    A…
```

Any base64 string that starts with `/9j/4A` is the encoding of a JPEG.

```python
import base64
img = base64.b64decode(open("pamuk.txt").read().strip())
assert img[:4] == b"\xff\xd8\xff\xe0"
open("pamuk.jpg", "wb").write(img)
```

The decoded image is a 1408×768 photo of Pamuk the Scottish-fold cat in sunglasses (the same cat from the [`PamukTheCat`](/ctf-writeups/hasblctf-2026-reverse-engineering-writeup/) rev challenge in the same event) with a thin red string overlay:

```text
484153424c7b50346d756b5f773174685f676c34733565357d
```

50 lowercase hex characters. `bytes.fromhex(...)` gives the ASCII flag directly:

```text
48 41 53 42 4c 7b 50 34 6d 75 6b 5f 77 31 74 68 5f 67 6c 34 73 35 65 35 7d
 H  A  S  B  L  {  P  4  m  u  k  _  w  1  t  h  _  g  l  4  s  5  e  5  }
```

The hint *"we recommend using OCR, but you can also achieve the same result in other ways"* invites the human path — 50 hex chars is the same volume as typing a phone number twice. Tesseract handles it in one pass:

```bash
tesseract pamuk.jpg - --psm 6
# 484153424c7b50346d756b5f773174685f676c34733565357d
```

**Flag:** `HASBL{P4muk_w1th_gl4s5e5}`

**Forensics takeaway:** mixed-medium challenges (base64 wrapper + image content + hex overlay inside the image) reward toolchain breadth more than depth. Each layer's identification is a single fingerprint check; the chain solves itself once you recognise where you are. Pamuk being in *both* the rev and forensics tracks is the author's continuity joke — find one writeup, you've seen the cat.

---

## The Magic of "Magic Numbers" — surgical header repair

```bash
$ file Aphelios.bin
Aphelios.bin: data
```

`file(1)` says nothing because the magic bytes have been surgically removed. Look at the raw bytes:

```text
$ xxd Aphelios.bin | head -1
00000000: 0000 0000 0010 5858 5858 0001 0101 0048  ......XXXX.....H
```

### Comparing against the JFIF expected header

A clean JFIF JPEG opens with:

```text
offset:      0 1 2 3   4 5    6 7 8 9   10  11 12   13   14 15
expected:   FF D8 FF E0  00 10  4A 46 49 46  00  01 01   00   00 48
got:        00 00 00 00  00 10  58 58 58 58  00  01 01   01   00 48
            └─ broken ─┘                └─ "XXXX" ─┘                ↑ off by 1
```

Two clean swaps:

- Bytes **0..3** zeroed — should be `FF D8 FF E0` (SOI + APP0 markers).
- Bytes **6..9** rewritten to ASCII `"XXXX"` — should be `"JFIF"` (`4A 46 49 46`).

Everything else lines up: segment length `0x0010` at bytes 4–5 is correct, JFIF version `01 01` is intact, density bytes `00 48 00 48` decode to **72 DPI**, and the segment at offset `0x14` is a valid APP2 ICC profile. The corruption is *purely cosmetic* — it kills `file(1)` identification without breaking any actual structure.

### The patch

```python
b = bytearray(open("Aphelios.bin", "rb").read())
b[0:4]  = b"\xFF\xD8\xFF\xE0"
b[6:10] = b"JFIF"
open("aphelios.jpg", "wb").write(b)
```

```bash
$ file aphelios.jpg
JPEG image data, JFIF standard 1.01, …, 1215x717,
  comment: "SEFTQkxfTmljZS1UcnkhIQ=="
```

The image is Aphelios and Alune from League of Legends. The COM comment `SEFTQkxfTmljZS1UcnkhIQ==` is base64 of `HASBL_Nice-Try!!` — a **decoy**, mirroring the Logo challenge's pattern of *decoy in shallow segment, flag in deeper one*.

### Walking the segment chain

Five metadata containers in the file:

| Offset | Marker | Length | Content |
|---|:---:|---|---|
| `0x00014` | APP2 | `0xC58` | ICC color profile (sRGB / IEC, HP-authored) |
| `0x00C6E` | APP13 | `0x24` | Photoshop 3.0 Image Resource Block (empty) |
| `0x00C94` | **APP1** | **`0xEF8`** | **XMP** — `<x:xmpmeta xmlns:x='adobe:ns:meta/'>` |
| `0x01B90` | COM | `…` | Base64 decoy `HASBL_Nice-Try!!` |

XMP is XML wrapped inside an APP1 with the prefix `http://ns.adobe.com/xap/1.0/`. The flag lives in `<xmpRights:UsageTerms>`:

```python
import base64
encoded = "SEFTQkx7TDNhZ3VlXzBmX0xlZzRuZDV9"
print(base64.b64decode(encoded).decode())
# HASBL{L3ague_0f_Leg4nd5}
```

**Flag:** `HASBL{L3ague_0f_Leg4nd5}`

**Forensics takeaway:** *"file says it's data"* means **the magic bytes have been broken, not the file**. Compare offset by offset against the canonical header of the most likely format; the structural fields downstream of the magic (segment lengths, version bytes, density, identifiable sub-segments) tell you what the format *should be*. Once you recognise the surgical zero-out at `[0:4]` and the `"XXXX"` overwrite at `[6:10]`, the patch is two `memcpy`s.

---

## Lessons learned — what HASBL CTF 2026 forensics rewarded

Five patterns recur across these five solves; they generalise to most file-forensics CTFs:

1. **File-header recognition is the entire first move.** `FF D8 FF E0` = JPEG, `89 50 4E 47` = PNG, `25 50 44 46` = PDF, `50 4B 03 04` = ZIP. If `file(1)` says `data`, the magic has been zeroed or rewritten — compare offsets. If `file(1)` says `ASCII text`, check whether the text is base64, base32, hex, or a binary digit stream.
2. **Encoding fingerprints precede decoding.** `SEFT...` = base64 of `HAS...`. `/9j/4A` = base64 of JPEG header. `[A-Z2-7]{N×8}` = base32 padded to bytes. The fingerprint tells you the answer before the decoder confirms it.
3. **The decoy goes in the shallow segment, the flag in the deeper one.** JFIF `COM` is two `xxd` lines from the start; EXIF `ImageDescription` is buried three layers in. XMP is XML wrapped in APP1. ICC profile data is yet another container. CTF authors invert the difficulty curve on purpose.
4. **The visible image is almost never the answer.** Quick Response's QR code contains the flag in the *modules*, not the pixels. Logo's flag is in EXIF, not the school crest. Pamuk's flag is in the *overlay text*, not the photo. Magic Numbers' flag is in the XMP, not the splash art. The image is decoration; the metadata is content.
5. **Reed-Solomon and other ECC eat surface damage.** QR error correction is exactly why logo-in-QR designs work in production. If a CTF hands you a code with visual interference, decode first, ask questions later.

## Source repository

Every per-challenge writeup includes solver scripts, intermediate decode steps, and the JPEG-segment walks:

**Repo:** [github.com/Abdelkad3r/hasblctf-2026](https://github.com/Abdelkad3r/hasblctf-2026)

The repo also contains the [reverse engineering](/ctf-writeups/hasblctf-2026-reverse-engineering-writeup/) and [pwn](/ctf-writeups/hasblctf-2026-pwn-writeup/) writeups from the same event, plus the web track (`T/I Forum`, `Anatolian Atlas`). This article is scoped to the forensics category only.

If you're building a forensics learning progression from this writeup, the five challenges form a clean order: **Digits (bit packing, simplest) → Quick Response (image content via library) → Pamuk (base64 wrapper + OCR) → Logo (metadata extraction with decoy) → Magic Numbers (surgical repair + segment walking)**. That order maps to *"recognise the bytes"* → *"recognise the format"* → *"peel one wrapper"* → *"choose the right container"* → *"rebuild the format from scratch."*

{{< faq >}}
[
  {
    "q": "What is HASBL CTF 2026?",
    "a": "HASBL CTF 2026 is a multi-category jeopardy-style capture-the-flag competition covering Reverse Engineering, Pwn, Web, and Forensics. The flag prefix is HASBL{...} for every challenge. This writeup is dedicated to the Forensics track only."
  },
  {
    "q": "How many forensics challenges does HASBL CTF 2026 have?",
    "a": "Five forensics challenges in this writeup's scope: Quick Response, Logo, Digits, our sweet cat Pamuk, and The Magic of Magic Numbers. All five were solved and are documented here. The full event also includes reverse engineering, pwn, and web tracks covered separately."
  },
  {
    "q": "Where can I find the HASBL CTF 2026 forensics solver scripts?",
    "a": "All five per-challenge writeups and solver scripts live in the source repository at github.com/Abdelkad3r/hasblctf-2026 under the forensic/ directory. Each challenge has its own README and standalone solver."
  },
  {
    "q": "How is the Quick Response QR code challenge solved?",
    "a": "The file is a JPEG of a QR code with Terry A. Davis's portrait dithered over the data modules. The QR code's Reed-Solomon error correction absorbs the visual overlay because the finder patterns (three corner bullseyes), timing patterns, and format-information ring survive intact. pyzbar.decode(Image.open('QR_Code_Holy'))[0].data returns b'Terry_Davis_1s_th3_b35t' on the first try. Wrap with the format → HASBL{Terry_Davis_1s_th3_b35t}."
  },
  {
    "q": "How is the Logo challenge solved?",
    "a": "The JPEG carries two encoded strings in two different metadata segments. The EXIF ImageDescription tag (TIFF tag 0x010E) contains base64 SEFTQkx7VGg0bmtfMHVyX3RlYWNoM3JzX01zS3VicmFfNG5kX01yS2FkaXJ9 which decodes to the flag HASBL{Th4nk_0ur_teach3rs_MsKubra_4nd_MrKadir}. The JFIF COM segment contains base32 JZUWGZJAORZHSIJB which decodes to 'Nice try!!' — a decoy. Author hid the decoy in the shallow container and the flag in the deeper one."
  },
  {
    "q": "How is the Digits challenge solved?",
    "a": "The file is 169,800 ASCII '0' and '1' characters on a single line. Read 8 characters at a time MSB-first to repack into bytes. The first 32 bits decode to FF D8 FF E0 — the JPEG SOI marker plus JFIF APP0 — confirming both the packing and the file format. Write the bytes to digits.jpg, open it, and read the single line of text on the page: HASBL{Istanbul_1s_b3atiful_c1ty}."
  },
  {
    "q": "How is the our sweet cat Pamuk forensic challenge solved?",
    "a": "The .txt file is secretly a base64-encoded JPEG — the prefix /9j/4A is the canonical base64 fingerprint for any string whose decoded bytes start with FF D8 FF E0. base64-decode the file to produce pamuk.jpg, a 1408x768 photo of Pamuk the Scottish-fold cat in sunglasses with a red text overlay. The overlay is 50 lowercase hex characters: 484153424c7b50346d756b5f773174685f676c34733565357d. bytes.fromhex decodes that directly to HASBL{P4muk_w1th_gl4s5e5}. Tesseract OCR handles the hex string in one pass."
  },
  {
    "q": "How is The Magic of Magic Numbers challenge solved?",
    "a": "The Aphelios.bin file has its JPEG magic bytes surgically removed — bytes [0:4] are zeroed (should be FF D8 FF E0) and bytes [6:10] are rewritten to the literal ASCII 'XXXX' (should be 'JFIF'). Everything else is intact: segment length 0x0010, version 01 01, density 0x00480048 = 72 DPI, and a valid APP2 ICC profile at offset 0x14. Patch the magic bytes back, open as JPEG to get the Aphelios + Alune League of Legends splash, walk the JPEG segment chain to the XMP block in APP1, and decode the base64 SEFTQkx7TDNhZ3VlXzBmX0xlZzRuZDV9 to HASBL{L3ague_0f_Leg4nd5}. The JFIF COM has a base64 decoy that decodes to HASBL_Nice-Try!!."
  },
  {
    "q": "What does the base64 prefix /9j/4A mean?",
    "a": "/9j/4A is the canonical base64 encoding of the bytes FF D8 FF E0 — the JPEG SOI marker (FF D8) immediately followed by the JFIF APP0 marker (FF E0). Any base64 string starting with /9j/4A is base64 of a JFIF JPEG. Recognising this fingerprint lets you identify a wrapped JPEG without running base64 -d to confirm."
  },
  {
    "q": "What does the base64 prefix SEFTQkx7 indicate?",
    "a": "SEFTQkx7 is the canonical base64 encoding of HASBL{. The mapping: 'H' = 0x48 = 01001000, 'A' = 0x41 = 01000001, 'S' = 0x53 = 01010011, '{' = 0x7B = 01111011. Take 6 bits at a time and look up the base64 alphabet — indices 18, 4, 5, 19, 2, 11, 3, 11 → S, E, F, T, Q, k, x, 7. Whenever you see SEFTQkx7 in a HASBL CTF challenge, it's base64 of a flag string."
  },
  {
    "q": "Are HASBL CTF forensics challenges beginner-friendly?",
    "a": "Yes — the five form a clean intro-forensics curriculum. Digits is the simplest (recognise the bit pattern, repack to bytes). Quick Response is a one-line pyzbar call. Pamuk needs base64 recognition and OCR. Logo introduces JPEG metadata containers and decoy identification. Magic Numbers is the most advanced — it requires byte-offset comparison against the JFIF header and walking the JPEG segment chain to find XMP. None of the five require expensive tooling; everything runs on Python with PIL, pyzbar, and base64."
  },
  {
    "q": "What tools should I use for HASBL CTF forensics challenges?",
    "a": "Python is enough for all five: PIL/Pillow for image handling, pyzbar for QR decoding, base64 and base32 stdlib modules for encoding, bytes.fromhex for hex strings. Add Tesseract for OCR on the Pamuk overlay. Command-line: file(1) for type identification, xxd for raw byte inspection, exiftool or identify for JPEG metadata, strings for grep-able payloads. No commercial forensics suite is required — the challenges are built around bytes and metadata, not full disk forensics."
  }
]
{{< /faq >}}
