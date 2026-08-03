---
title: "VuwCTF 2026 Forensics Writeup: Byte-Pair RLE Decoding & FIGlet ASCII-Art Flag Recovery (compression)"
slug: "vuwctf-2026-forensics-writeup"
description: "VuwCTF 2026 forensics writeup for the challenge 'compression': an unknown compressed.dat that file(1) reports as raw data turns out to be a custom (count, byte) run-length-encoded stream. Decoding the byte pairs expands to a seven-line ASCII-art banner, which is a FIGlet rendering (varsity font) of the flag — confirmed exactly by re-rendering the candidate flag with pyfiglet."
date: 2026-08-03T15:00:00Z
lastmod: 2026-08-03T15:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["VuwCTF 2026"]
tags:
  - "vuwctf"
  - "vuwctf 2026"
  - "ctf writeup"
  - "forensics"
  - "run-length encoding"
  - "rle"
  - "custom compression"
  - "file carving"
  - "hex analysis"
  - "xxd"
  - "figlet"
  - "pyfiglet"
  - "ascii art"
  - "banner font"
  - "varsity font"
  - "unknown file format"
  - "ctf 2026"
keywords:
  - "vuwctf 2026 forensics writeup"
  - "compression vuwctf writeup"
  - "custom rle decode ctf"
  - "byte pair run length encoding ctf"
  - "file reports data unknown format ctf"
  - "figlet ascii art flag ctf"
  - "pyfiglet identify font ctf"
  - "varsity figlet font ctf flag"
  - "decompress compressed.dat ctf"
  - "count byte value byte rle stream"
  - "ascii art banner flag recovery"
  - "weissman score ctf flag"
  - "vuwctf forensics challenge"
  - "reverse a custom compressor ctf"
  - "hex dump run length pattern"
toc: true
cover:
  image: "/images/articles/vuwctf-2026-forensics-writeup.png"
  alt: "VuwCTF 2026 forensics writeup — the compression challenge ships an unknown file compressed.dat that the file command reports only as data with no recognizable archive or image magic bytes, but a hex dump reveals a repeating pattern of a small integer byte followed by a printable ASCII byte such as space underscore and backslash which is a custom run-length encoding where each pair is a count and a value; decoding the (count, byte) pairs and appending count copies of value expands the 1900-byte stream into a 2182-byte seven-line ASCII-art banner that is a FIGlet rendering in the varsity font of the flag confirmed exactly by re-rendering the candidate flag with pyfiglet and comparing line by line after trimming trailing whitespace"
---

VuwCTF 2026's forensics entry, **compression** (100 pts, Easy), is a clean two-layer puzzle: first identify a *homemade* compression format that no tool recognizes, then realize the decompressed payload isn't text you read — it's text you *render*. The file is a custom byte-pair run-length encoding, and once expanded it's a FIGlet ASCII-art banner spelling the flag. This writeup walks the full chain: triage → recognizing the RLE from a hex dump → writing the four-line decompressor → identifying the FIGlet font → verifying the flag exactly with `pyfiglet`.

Challenge files and the solver are at [Abdelkad3r/VuwCTF-2026](https://github.com/Abdelkad3r/VuwCTF-2026/tree/master/Forensics/compression). Companion post from the same event: [VuwCTF 2026 Cryptography Writeup](/ctf-writeups/vuwctf-2026-crypto-writeup/).

## Challenge at a glance

| Field | Value |
|---|---|
| Category | Forensics |
| Points | 100 |
| Difficulty | Easy |
| Prompt | *"They wouldn't let me put quotes on this"* |
| Artifact | `compressed.dat` (1,900 bytes) |
| Techniques | Custom (count, byte) RLE · FIGlet font identification |
| Flag | `VuwCTF{weissman_score_of_at_least_seven}` |

---

## Step 1 — Triage an unknown file

The only artifact is `compressed.dat`, and nothing recognizes it:

```console
$ file compressed.dat
compressed.dat: data

$ shasum -a 256 compressed.dat
21c8289e6e4e3636be16d6e058d7005618b33fadf8e198073798ce61c81add73  compressed.dat
```

`file` reports plain `data` — no archive, image, or compressor magic bytes. When
a format is unrecognized, the next move is always to *look at the actual bytes*
rather than keep guessing tools.

## Step 2 — Read the hex dump structurally

```console
$ xxd -g1 -l 32 compressed.dat
00000000: 01 20 04 5f 03 20 04 5f 04 20 02 5c 08 20 07 5f  . ._. ._. .\. ._
00000010: 03 20 02 5c 04 20 03 5c 03 20 03 5f 04 20 01 5c  . .\. .\. ._. .\
```

A pattern jumps out: the bytes alternate between a **small integer** (`01`, `04`,
`03`, `04`, `08`, `07`, …) and a **printable ASCII** byte (`0x20` space, `0x5f`
`_`, `0x5c` `\`). That is the signature of a tiny run-length encoding — a
`(count, value)` stream — not a standard compressor. This also explains why the
file has so many printable bytes yet fails every format sniff.

## Step 3 — Decode the byte pairs by hand

Reading the head as `(count, byte)` pairs decodes cleanly:

| Bytes | Meaning | Output |
|---|---|---|
| `01 20` | space × 1 | ` ` |
| `04 5f` | `_` × 4 | `____` |
| `03 20` | space × 3 | `   ` |
| `04 5f` | `_` × 4 | `____` |
| `08 20` | space × 8 | `        ` |
| `07 5f` | `_` × 7 | `_______` |

So the whole format is simply: for each pair, append `count` copies of `value` to
the output.

## Step 4 — Write the decompressor

The entire decoder is four lines:

```python
out = bytearray()
for i in range(0, len(data), 2):
    count = data[i]
    value = data[i + 1]
    out.extend(bytes([value]) * count)
```

Running it expands the 1,900-byte stream to a 2,182-byte, seven-line ASCII banner
(note: the "compression" here actually *inflates* — a wink at the flag):

```console
$ python3 solve.py
[+] input:  compressed.dat (1900 bytes)
[+] output: decompressed.txt (2182 bytes)
[+] decoded art: 7 lines, max width 309
[+] flag: VuwCTF{weissman_score_of_at_least_seven}
```

## Step 5 — Recognize the payload is ASCII art, not text

The decoded output isn't a readable string — it's a large figlet-style banner. The
left portion alone shows the `VuwCTF{` prefix drawn in a decorative font:

```text
 ____   ____                     ______  _____
|_  _| |_  _|                  .' ___  ||  _  
  \ \   / /__   _  _   _   __ / .'   \_||_/ | 
   \ \ / /[  | | |[ \ [ \ [  ]| |           | 
    \ ' /  | \_/ |,\ \/\ \/ / \ `.___.'\   _| 
     \_/   '.__.'_/ \__/\__/   `.____ .'  |___
```

This is exactly what the prompt hints at — *"they wouldn't let me put quotes on
this."* You can't wrap the flag in quotes, so instead of storing it as a string,
the author drew it as art. (`V-Y-W`... the whole banner spells the flag; the
snippet above is just the first few characters.)

## Step 6 — Identify the font and verify exactly

Rather than eyeball the banner character by character, compare it against FIGlet
renderings to pin the font. The match is FIGlet's **`varsity`** font. The
confirmation re-renders the candidate flag and does a line-by-line comparison
(trimming trailing whitespace, which the RLE preserves but is cosmetically
irrelevant):

```python
import pyfiglet
from pathlib import Path

flag = "VuwCTF{weissman_score_of_at_least_seven}"
figlet = pyfiglet.Figlet(font="varsity", width=1000)
rendered = [l.rstrip() for l in figlet.renderText(flag).splitlines()]
decoded  = [l.rstrip() for l in Path("decompressed.txt").read_text().splitlines()]

assert rendered == decoded          # exact match → font + flag confirmed
```

The assertion passes, confirming both the font and the exact flag text — no
guessing from the banner shape. (`pyfiglet` is optional: without it the RLE
decompression still writes `decompressed.txt` for manual reading.)

## Flag

```text
VuwCTF{weissman_score_of_at_least_seven}
```

The flag is a nod to HBO's *Silicon Valley* — the "Weissman score" is the show's
fictional compression-quality metric — which ties the whole custom-compression
theme together.

---

## Cross-cutting notes

**When `file` says `data`, read the bytes yourself.** An unrecognized format is a
prompt to open a hex editor, not to keep running detection tools. The alternating
small-integer / printable-ASCII rhythm in the first 16 bytes was enough to
identify a custom RLE without any tooling.

**Custom RLE is the most common homemade CTF compressor.** A stream of
`(count, value)` pairs — or its cousins `(value, count)` and escape-run schemes —
is trivial to spot from a hex dump: one byte varies over a small range, the next
is meaningful data. If a pairwise reading decodes the head cleanly, decode the
whole thing; you rarely need to reverse a "real" compressor in an easy forensics
task.

**Decompressed output isn't always text to read — sometimes it's text to
render.** The payload here is only meaningful when displayed as a monospaced
banner. FIGlet/figlet-style ASCII art shows up whenever the value bytes are
dominated by drawing characters (`_`, `\`, `/`, `|`, `.`, `'`) and the line width
is large. The prompt's "no quotes" clue pointed straight at rendering the flag
instead of storing it.

**Identify banner fonts by matching, not by eye.** With `pyfiglet` you can render
a candidate string in every installed font and diff against the artifact. That
turns "which font is this?" and "did I read the flag right?" into a single exact
equality check — far more reliable than transcribing decorative glyphs manually.

---

## Frequently Asked Questions

**Q: How do you recognize a custom RLE stream from a hex dump?**

Look for a regular two-byte rhythm where one position holds a small integer and
the adjacent position holds meaningful data. In `compressed.dat` the even offsets
were small counts (`01`, `04`, `08`, …) and the odd offsets were printable ASCII
(`0x20` space, `0x5f` `_`, `0x5c` `\`). Reading the stream as `(count, value)`
pairs and expanding the head decodes cleanly, which confirms it's run-length
encoding rather than a standard compressor.

**Q: Why does `file` report the artifact as just `data`?**

`file` identifies formats by magic bytes and known signatures. A homemade RLE
stream has no standard header, so it matches nothing and falls back to the generic
`data` label. That's a signal to inspect the bytes directly with `xxd`/`hexdump`
rather than to try more format detectors.

**Q: How do you decode a (count, byte) run-length stream?**

Iterate over the data two bytes at a time. The first byte of each pair is the
repeat count and the second is the value; append `count` copies of `value` to the
output. In Python: `for i in range(0, len(data), 2): out.extend(bytes([data[i+1]]) * data[i])`.
A stream with an odd number of bytes would indicate a different framing.

**Q: The decompressed file isn't readable text — what is it?**

It's ASCII art: a FIGlet-style banner that spells the flag using drawing
characters. The decompressed payload is only meaningful when viewed in a
monospaced font as a seven-line banner. The challenge prompt — "they wouldn't let
me put quotes on this" — hints that the flag was rendered as art instead of stored
as a quoted string.

**Q: How do you identify which FIGlet font was used and confirm the flag?**

Use `pyfiglet` to re-render your candidate flag in a specific font and compare it
line-by-line against the decompressed art (after trimming trailing whitespace).
Here the font is `varsity`, and rendering `VuwCTF{weissman_score_of_at_least_seven}`
in `varsity` reproduces the banner exactly, confirming both the font and the flag
without transcribing glyphs by hand.

**Q: What is the flag for the VuwCTF 2026 compression challenge?**

`VuwCTF{weissman_score_of_at_least_seven}` — a reference to the fictional
"Weissman score" compression metric from HBO's *Silicon Valley*.

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "How do you recognize a custom RLE stream from a hex dump?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Look for a regular two-byte rhythm where one position holds a small integer and the adjacent position holds meaningful data. In compressed.dat the even offsets were small counts (01, 04, 08, ...) and the odd offsets were printable ASCII (0x20 space, 0x5f underscore, 0x5c backslash). Reading the stream as count-value pairs and expanding the head decodes cleanly, which confirms it is run-length encoding rather than a standard compressor."
      }
    },
    {
      "@type": "Question",
      "name": "Why does the file command report the artifact as just data?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The file command identifies formats by magic bytes and known signatures. A homemade RLE stream has no standard header, so it matches nothing and falls back to the generic data label. That is a signal to inspect the bytes directly with xxd or hexdump rather than to try more format detectors."
      }
    },
    {
      "@type": "Question",
      "name": "How do you decode a count-byte run-length stream?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Iterate over the data two bytes at a time. The first byte of each pair is the repeat count and the second is the value; append count copies of value to the output. In Python: for i in range(0, len(data), 2): out.extend(bytes([data[i+1]]) * data[i]). A stream with an odd number of bytes would indicate a different framing."
      }
    },
    {
      "@type": "Question",
      "name": "The decompressed file is not readable text — what is it?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "It is ASCII art: a FIGlet-style banner that spells the flag using drawing characters. The decompressed payload is only meaningful when viewed in a monospaced font as a seven-line banner. The challenge prompt, they wouldn't let me put quotes on this, hints that the flag was rendered as art instead of stored as a quoted string."
      }
    },
    {
      "@type": "Question",
      "name": "How do you identify which FIGlet font was used and confirm the flag?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Use pyfiglet to re-render your candidate flag in a specific font and compare it line by line against the decompressed art after trimming trailing whitespace. Here the font is varsity, and rendering VuwCTF{weissman_score_of_at_least_seven} in varsity reproduces the banner exactly, confirming both the font and the flag without transcribing glyphs by hand."
      }
    },
    {
      "@type": "Question",
      "name": "What is the flag for the VuwCTF 2026 compression challenge?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "VuwCTF{weissman_score_of_at_least_seven}, a reference to the fictional Weissman score compression metric from HBO's Silicon Valley."
      }
    }
  ]
}
```
