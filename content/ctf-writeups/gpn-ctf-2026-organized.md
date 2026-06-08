---
title: "GPN CTF 2026 — Organized: Ternary Amplitude-Modulated UART in Popcount Density"
slug: "gpn-ctf-2026-organized"
description: "GPN CTF 2026 Misc: 7.65 MB of apparent noise carries a ternary-amplitude UART signal. Per-12,500-byte window popcount density is the carrier; demodulate to 49 frames of ASCII."
date: 2026-06-07T19:45:00Z
lastmod: 2026-06-07T19:45:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "gpn ctf 2026"
  - "organized"
  - "ternary modulation"
  - "uart decoding"
  - "popcount density"
  - "amplitude modulation"
  - "signal recovery"
  - "high entropy file analysis"
  - "misc challenge"
series: ["GPN CTF 2026"]
keywords:
  - "gpn ctf organized writeup"
  - "ternary amplitude modulation ctf"
  - "popcount per window carrier"
  - "uart frame ctf"
  - "high entropy file decoding"
  - "ternary alphabet signal recovery"
toc: true
cover:
  image: "/images/articles/gpn-ctf-2026-organized.png"
  alt: "GPN CTF 2026 Organized writeup — ternary amplitude-modulated UART hidden in per-12,500-byte window popcount density"
---

{{< ctf-meta platform="GPN CTF 2026 (kitctf)" difficulty="Medium" os="Misc — signal recovery from high-entropy file, ternary amplitude modulation" skills="rejecting the 'random noise' default hypothesis, computing per-window popcount means and run-lengths, plotting a 200-bin histogram to spot three peaks instead of two, recognising the structure as UART (start bit, 8 data bits LSB-first, stop bit) framed by a mid-amplitude idle marker, decoding 49 frames to ASCII" >}}

**Organized** is the GPN CTF 2026 misc challenge whose entire trick is recognising the carrier's organization. The handout is a 7,650,000-byte file that looks like noise — `file(1)` calls it `data`, every bit position is 1 with probability ≈ 0.287. The "organization" is hidden in the **bit-density of windows**, not in the bytes themselves: per-12,500-byte window popcount falls into one of three sharp levels, giving a 612-trit string. Past a 24-trit preamble, the rest is 49 UART-style frames of 12 trits each. Decode → ASCII → flag:

```
GPNCTF{tHaNK_YOU_tO_entropia_FoR_Or64niZ1N6_GPN!}
```

The flag thanks Entropia e.V. for *organizing* GPN — fitting payoff for a challenge that's about recognising organization in noise. This is the standalone deep-dive on `misc/organized` from the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/). Full source at [`misc/organized`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/misc/organized).

## Recon

```
$ wc -c data
 7650000 data
$ file data
data: data
```

`7,650,000 = 2⁴ · 3² · 5⁵ · 17` — no clean image dimensions. Byte-value frequencies are very uneven:

```
popcount=0  (byte 0x00):           1,573,858   ← way over uniform (29,883)
popcount=1  (8 single-bit bytes):  ~214,900 each
popcount=2  (28 two-bit bytes):    ~42,400 each
popcount=8  (byte 0xFF):           12,681       ← way under uniform
```

The 8 bit positions are each set with density ≈ 0.287, but the `0x00` byte is over-represented 3×. So the bits are *positively correlated* — when one bit in a byte is 0, others tend to be 0 too. That's the smoking gun: the file has **slowly-varying bit-density across positions**.

## Spotting the carrier

Renders of `data` as a 1-bpp bitmap at every plausible width all show horizontal stripes — the row-to-row popcount oscillates. So look at popcount averaged in fixed windows:

```python
import numpy as np
d   = np.frombuffer(open("data","rb").read(), dtype=np.uint8)
pop = np.unpackbits(d).reshape(-1, 8).sum(1)
avg = pop.reshape(-1, 100).mean(1)               # 76,500 windows of 100 bytes
classes = (avg > 2).astype(int)
```

Run-length the binary class signal — every run is a multiple of **125 windows = 12,500 bytes**:

```
len  125: 188 runs
len  250:  45
len  375:  48
len  500:  25
len  625:  12
len  750:   1
len  875:   3
```

The carrier has a fixed block size of **12,500 bytes per symbol**, and `7,650,000 / 12,500 = 612` blocks total.

## Three levels, not two

Recomputing the popcount means per 12,500-byte block at full precision:

| level | mean popcount/byte | density | count |
| -: | -: | -: | -: |
| `0` | 0.795 ± 0.01 | 0.099 | 252 |
| `1` | 1.60  ± 0.02 | 0.200 |  98 |
| `2` | 4.00  ± 0.02 | 0.500 | 262 |

Three sharp peaks, nothing else — confirmed by a 200-bin histogram. The file is amplitude-modulated in three steps. Map by rounding the mean to the nearest multiple of 0.8 (`{1, 2, 5} → {0, 1, 2}`) and you get a 612-character ternary string.

## Reading the ternary stream

First 80 trits:

```
000222000222002020002200 102220002021100000202021100222002021102200002021
└───── preamble ───────┘ └─ frame ──┘└─ frame ──┘└─ frame ──┘└─ frame ──┘
```

Past the 24-trit preamble, slice in widths of 12. Every single 12-trit slice satisfies:

- trit `0` and trit `11` are `1` (mid-level idle markers)
- trits `1..10` are only `0` or `2`

That's 49 frames after a header. The mid-level `1` appears exactly **98** times in the whole file — 49 frames × 2 boundary markers — and **nowhere** else. The carrier is using its mid amplitude as an inter-frame idle / break signal.

Within a frame, the natural reading is **UART**: start bit, 8 data bits LSB-first, stop bit, framed by idle. Mapping `0 → bit 0`, `2 → bit 1`, trits `2..9` are the byte (LSB-first):

```
frame "1 0 2 2 2 0 0 0 2 0 2 1"  →  data trits "2 2 2 0 0 0 2 0"
                                  →  bits LSB→MSB  1 1 1 0 0 0 1 0
                                  →  byte 0x47  =  'G'
```

That's the 'G' of `GPNCTF{`. Repeat for all 49 frames and the flag falls out.

## Solver

```python
import numpy as np

d = np.frombuffer(open("data","rb").read(), dtype=np.uint8)
pop = np.unpackbits(d).reshape(-1, 8).sum(1)
per_block = pop.reshape(-1, 12_500).mean(1)
syms = "".join({1:"0", 2:"1", 5:"2"}[x]
               for x in np.round(per_block / 0.8).astype(int))

frames = syms[24:]                                   # drop 24-trit preamble
flag = "".join(
    chr(int("".join("1" if c=="2" else "0" for c in frames[i+2:i+10])[::-1], 2))
    for i in range(0, len(frames), 12)
)
print(flag)
```

```
$ python3 solve.py data
GPNCTF{tHaNK_YOU_tO_entropia_FoR_Or64niZ1N6_GPN!}
```

## The preamble

The 24-trit preamble (`000222000222002020002200`) sits before the first frame and is *not* framed by `1` idle markers. As bits it spells the three bytes `1c 72 8c` — not text. Most likely a synchronisation pre-roll: enough alternation between low and high amplitudes for a receiver to lock onto the symbol rate before the framed UART stream starts. The decoder doesn't need it; just skip 24 trits.

## Why this challenge teaches a real lesson

The default reading of "high-entropy file" is "encrypted data." The second-default is "compressed data." Both are wrong here — the carrier is *not* uniform random; it's three-amplitude-modulated, and the modulation is invisible at the byte level. **Reading the popcount density at the right window size is the entire diagnosis.**

The discovery path that worked, in three steps:

1. *"Is this image data?"* — render 25 candidate widths at 1 bpp. All show horizontal stripes. Not an image.
2. *"What's the smallest periodic structure in popcount?"* — compute per-window popcount means and run-lengths. Every run is a multiple of 125 windows = 12,500 bytes.
3. *"Three peaks or two?"* — 200-bin histogram of per-block popcount. Three clear peaks. Ternary.

Each step rules out a hypothesis; nothing is brute-forced. By the time the third step lands, the carrier structure is fully recovered and the UART framing is the only natural reading.

## Defender takeaway

The lesson is generic across DFIR and reverse engineering: **don't anchor on the first hypothesis.** A file that looks like noise to `file(1)` and to byte-frequency analysis can still carry structured information at a window scale that neither tool examines. Tools that compute window statistics — `binwalk -E` for entropy, custom popcount-per-window scripts — are the first line of defence against this class of bug.

The class is broader than CTFs. Side-channel exfiltration via cache-line popcount, USB power-line modulation, fan-speed-encoded covert channels — all reduce to the same recognition problem: *"what's the carrier's smallest periodic structure, and what alphabet does it speak?"*

## Frequently asked questions

### Why is the file 7,650,000 bytes?

`7,650,000 = 612 × 12,500`. The carrier is 612 ternary symbols, each encoded as 12,500 bytes of amplitude-modulated data. The factorisation `2⁴ · 3² · 5⁵ · 17` rules out common image dimensions (no clean width/height pair), which is the first hint that the file isn't a bitmap.

### Why does `file(1)` say `data`?

The file has no magic bytes and high byte-entropy (~7.x bits/byte). `file(1)` falls back to its catch-all `data` classification when no recognisable format matches. The bytes look uniformly distributed at first glance — but their *bit-density per window* is correlated, which `file(1)` does not check.

### How do you spot the three amplitude levels?

Plot a 200-bin histogram of per-12,500-byte-window popcount means. Three sharp peaks at means 0.795, 1.60, 4.00 (densities 0.099, 0.200, 0.500). The middle peak is much rarer (98 windows) than the outer two (252, 262) — that's the giveaway that the middle level is special (idle/break marker), not equiprobable.

### Why UART specifically?

The framing is `1 0_or_2_×8 1` — the mid-level idle marker, eight 0-or-2 data trits (binary in disguise), the mid-level idle marker. That's exactly UART's start-stop framing with the data bits LSB-first. The choice of "ternary amplitude with the middle as idle" is a clever way to embed a binary UART stream in a ternary symbol space — the idle marker carries no data but signals frame boundaries.

### What is the 24-trit preamble?

`000222000222002020002200` — three bytes (`1c 72 8c`) that aren't ASCII. Most likely a synchronisation pre-roll giving the receiver enough amplitude alternation to lock onto the symbol rate before the framed stream starts. Real UART transmitters use a similar `BREAK` signal followed by an idle pattern. Decoder doesn't need it; skip 24 trits.

### What's the broader pattern for "high-entropy" files in CTFs?

Don't anchor on "encrypted." Compute window statistics — `binwalk -E` for entropy, custom popcount-per-window scripts, FFT of per-window means for periodic carriers. Window size guesses: 100, 1000, 12500, 65536 bytes. Plot histograms of window statistics; look for peaks. If three or more peaks emerge cleanly, the file is amplitude-modulated, not encrypted.

### Where can I find the solver?

Full source at [`misc/organized/solve.py`](https://github.com/Abdelkad3r/gpn-ctf-2026/tree/master/misc/organized). Master writeup at [/ctf-writeups/gpn-ctf-2026-writeup/](/ctf-writeups/gpn-ctf-2026-writeup/).

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "Why is the file 7,650,000 bytes?","acceptedAnswer": {"@type": "Answer","text": "7,650,000 = 612 × 12,500. The carrier is 612 ternary symbols, each encoded as 12,500 bytes of amplitude-modulated data. The factorisation 2⁴ · 3² · 5⁵ · 17 rules out common image dimensions, which is the first hint that the file isn't a bitmap."}},
    {"@type": "Question","name": "Why does file(1) say data?","acceptedAnswer": {"@type": "Answer","text": "The file has no magic bytes and high byte-entropy (~7.x bits/byte). file(1) falls back to data when no recognisable format matches. The bytes look uniformly distributed at first glance, but bit-density per window is correlated and file(1) does not check that."}},
    {"@type": "Question","name": "How do you spot the three amplitude levels?","acceptedAnswer": {"@type": "Answer","text": "Plot a 200-bin histogram of per-12,500-byte-window popcount means. Three sharp peaks at means 0.795, 1.60, 4.00 (densities 0.099, 0.200, 0.500). The middle peak is much rarer (98 windows) than the outer two — the giveaway that the middle level is the idle/break marker, not equiprobable."}},
    {"@type": "Question","name": "Why UART specifically?","acceptedAnswer": {"@type": "Answer","text": "The framing is 1 0_or_2_×8 1 — mid-level idle marker, eight 0-or-2 data trits (binary in disguise), mid-level idle marker. That's exactly UART start-stop framing with data bits LSB-first. Ternary amplitude with middle as idle is a clever way to embed a binary UART stream in a ternary symbol space."}},
    {"@type": "Question","name": "What is the 24-trit preamble?","acceptedAnswer": {"@type": "Answer","text": "000222000222002020002200 — three bytes (1c 72 8c) that aren't ASCII. Most likely a synchronisation pre-roll giving the receiver enough amplitude alternation to lock onto the symbol rate before the framed stream starts. Real UART transmitters use a similar BREAK signal."}},
    {"@type": "Question","name": "What's the broader pattern for high-entropy files in CTFs?","acceptedAnswer": {"@type": "Answer","text": "Don't anchor on encrypted. Compute window statistics — binwalk -E for entropy, popcount-per-window scripts, FFT of per-window means. Try window sizes 100, 1000, 12500, 65536. Plot histograms. If three or more peaks emerge cleanly, the file is amplitude-modulated, not encrypted."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Full source at misc/organized/solve.py in github.com/Abdelkad3r/gpn-ctf-2026. Master writeup at cybersecurityelite.com/ctf-writeups/gpn-ctf-2026-writeup/."}}
  ]
}
</script>
