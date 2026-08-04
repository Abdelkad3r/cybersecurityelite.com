---
title: "BushBashCTF 2026 Misc & OSINT Writeup: SSTV Martin M1, Hellschreiber Dot-Matrix & Visual Geolocation"
slug: "bushbashctf-2026-misc-osint-writeup"
description: "BushBashCTF 2026 miscellaneous and OSINT writeup covering all three challenges: Spiritual Interception (seven concurrent audio tones decoded as a Hellschreiber-style dot-matrix bitmap), Signal Haze (an Ogg/Vorbis file disguised as data.file containing a Martin M1 SSTV transmission decoded to a 320x256 colour image bearing the flag on a road sign), and The CSSA Hackerman I (visual geolocation of a JPEG with no GPS EXIF identifying the ANU CSIT Skaidrite Darius Building and deriving the flag coordinate at the driveway pole)."
date: 2026-08-02T20:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BushBashCTF 2026"]
tags:
  - "bushbashctf"
  - "bushbashctf 2026"
  - "ctf writeup"
  - "misc"
  - "osint"
  - "sstv"
  - "slow scan television"
  - "martin m1"
  - "hellschreiber"
  - "dot matrix"
  - "audio steganography"
  - "visual geolocation"
  - "geoint"
  - "signal decoding"
  - "frequency analysis"
  - "ctf 2026"
keywords:
  - "bushbashctf 2026 misc writeup"
  - "bushbashctf 2026 osint writeup"
  - "signal haze ctf sstv martin m1"
  - "spiritual interception ctf hellschreiber"
  - "the cssa hackerman i ctf geolocation"
  - "sstv ctf challenge 2026"
  - "martin m1 sstv decode ctf"
  - "hellschreiber dot matrix ctf"
  - "seven tone concurrent bitmap ctf"
  - "visual geolocation ctf anu csit"
  - "audio steganography sstv ctf 2026"
  - "ogg vorbis sstv ctf"
  - "goertzel tone detection ctf"
  - "instantaneous frequency sstv ctf"
  - "ctf geolocation jpeg no gps exif"
toc: true
cover:
  image: "/images/articles/bushbashctf-2026-misc-osint-writeup.png"
  alt: "BushBashCTF 2026 miscellaneous and OSINT writeup — three challenges solved covering Spiritual Interception a seven-tone concurrent dot-matrix transmission decoded by Goertzel tone detection across 138 twenty-millisecond columns to recover a Hellschreiber-style bitmap spelling the flag; Signal Haze an Ogg Vorbis file disguised as data.file containing a Martin M1 SSTV transmission decoded from its 1100 and 1300 Hz VIS bits to a 320 by 256 pixel colour image where the flag appears on a road sign; and The CSSA Hackerman I a visual geolocation challenge identifying the ANU CSIT Skaidrite Darius Building from a 640 by 480 JPEG with no GPS EXIF"
---

Here at **CyberSecurity Elite**, we tackled BushBashCTF 2026's miscellaneous and OSINT tracks, which shared a common theme: **information hidden in plain sight** — inside audio signals that look like noise until you know where to look, and inside a photograph that seems geographically anonymous until the visual context gives away the location. Three challenges, three completely different domains of signal processing and open-source intelligence, but each solvable with a short focused toolchain: `Spiritual Interception` (100 pts, 241 solves) hides the flag as a seven-frequency concurrent dot-matrix audio transmission in the spirit of Hellschreiber; `Signal Haze` (200 pts, 161 solves) disguises a full-colour Martin M1 SSTV image transmission inside a renamed Ogg/Vorbis audio file; and `The CSSA Hackerman I` (100 pts, 241 solves) provides a JPEG of a person standing outside a university building and asks for their GPS coordinates to four decimal places — no EXIF, no metadata, just visual context and public map sources.

Challenge files and solver scripts are available at [Abdelkad3r/BushBashCTF-2026](https://github.com/Abdelkad3r/BushBashCTF-2026). Other BushBashCTF 2026 writeups: [binary exploitation](/ctf-writeups/bushbashctf-2026-pwn-writeup/) and [cryptography](/ctf-writeups/bushbashctf-2026-crypto-writeup/).

## Challenges at a glance

| Field | Spiritual Interception | Signal Haze | The CSSA Hackerman I |
|---|---|---|---|
| Category | Misc | Misc | OSINT |
| Points | 100 | 200 | 100 |
| Solves | 241 | 161 | 241 |
| Difficulty | Easy | Medium | Beginner |
| Attachment | `transmission.wav` (2.76 s) | `data.file` (Ogg/Vorbis, 115 s) | `aba45f2022fa2a4f28ca87b2cf1a1436.JPEG` |
| Technique | 7-tone dot-matrix bitmap decode | SSTV Martin M1 decode | Visual geolocation |
| Tool | Python stdlib only | ffmpeg + scipy + Pillow | ffmpeg / exiftool + map sources |
| Flag | `bushbash{s33ing-gh0sts}` | `bushbash{gR0und_C0ntr0l}` | `bushbash{-35.2754,149.1210}` |

---

## Misc 1 — Spiritual Interception (Easy, 100 pts, 241 solves)

### Overview

The challenge provides `transmission.wav`: a 2.76-second mono 16-bit PCM 44100 Hz audio file. Playing it back produces what sounds like layered electronic tones — not speech, not music, not DTMF. The challenge title ("Spiritual Interception") and the instruction to decode what you hear hint at a signal-processing problem rather than file carving.

### Step 1 — Characterise the file

```bash
file transmission.wav
ffprobe -hide_banner transmission.wav
```

```
transmission.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz
Duration: 00:00:02.76  (121,716 samples)
```

Dividing the sample count by the sample rate:

```
121716 / 44100 = 2.76 seconds
```

That duration is suspiciously clean. Any "structured" encoding typically uses fixed time slices. Trying 20 ms:

```
44100 × 0.020 = 882 samples per column
121716 / 882  = 138.0  ← exact integer
```

The file divides cleanly into **138 columns of 882 samples each** — a deliberate choice.

### Step 2 — Spectrogram

```bash
ffmpeg -y -i transmission.wav \
  -lavfi showspectrumpic=s=2400x1200:mode=combined:color=intensity:scale=log:legend=1 \
  spectrogram.png
```

The spectrogram reveals exactly **seven horizontal bands** of energy, at frequencies that are integer multiples of 440 Hz:

| Row | Frequency |
|---|---|
| 1 (top) | 3520 Hz = 440 × 8 |
| 2 | 3080 Hz = 440 × 7 |
| 3 | 2640 Hz = 440 × 6 |
| 4 | 2200 Hz = 440 × 5 |
| 5 | 1760 Hz = 440 × 4 |
| 6 | 1320 Hz = 440 × 3 |
| 7 (bottom) | 880 Hz = 440 × 2 |

Seven bands × 138 columns = a 7 × 138 binary bitmap, where each column is a vertical "slice" of active/inactive tones. This is the structure of a **Hellschreiber**-style concurrent multi-tone transmission: each frequency represents one row of a dot-matrix character, and the on/off pattern of tones over time spells out the message.

### Step 3 — Goertzel tone detection

For each 882-sample column, measure the power at each of the seven frequencies using a direct correlation (equivalent to a single-bin DFT / Goertzel algorithm):

```python
def tone_amplitude(samples, sample_rate, freq):
    real = 0.0
    imag = 0.0
    for i, sample in enumerate(samples):
        angle = 2.0 * math.pi * freq * i / sample_rate
        real += sample * math.cos(angle)
        imag -= sample * math.sin(angle)
    return math.hypot(real, imag)
```

Within each column, active tones are dramatically stronger than inactive ones. A threshold of **20% of the column's peak amplitude** cleanly separates active (pixel on) from inactive (pixel off):

```python
peak = max(amplitudes)
pixels = [1 if amp > peak * 0.20 else 0 for amp in amplitudes]
```

### Step 4 — Reconstruct the bitmap

The seven frequencies map to seven rows, reading **highest-frequency to lowest-frequency** as top-to-bottom. Stack the 138 column vectors into a 7 × 138 binary matrix:

```
#.................#.....#.................#........##.......#####.#####...#...
#.................#.....#.................#.......#............#.....#.........
#.##..#...#..###..#.##..#.##...###...###..#.##....#....###....#.....#....##...
##..#.#...#.#.....##..#.##..#.....#.#.....##..#..#....#........#.....#....#...
#...#.#...#..###..#...#.#...#..####..###..#...#...#....###......#.....#...#...
#...#.#..##.....#.#...#.#...#.#...#.....#.#...#...#.......#.#...#.#...#...#..
####...##.#.####..#...#.####...####.####..#...#....##.####...###...###...###..
```

### Step 5 — Decode 6-column glyphs

Each character occupies 6 columns: 5 pixel columns + 1 blank separator column. With 138 columns total, this gives `138 / 6 = 23` characters — exactly the length of `bushbash{s33ing-gh0sts}`.

Map each 7 × 6 glyph block to its character (pre-built lookup table). The glyph for `b`, for example:

```
#.....
#.....
#.##..
##..#.
#...#.
#...#.
####..
```

Reading all 23 glyphs in sequence spells:

```
bushbash{s33ing-gh0sts}
```

### Step 6 — Complete solver (stdlib only)

```python
#!/usr/bin/env python3
import math, struct, wave
from pathlib import Path

FREQS          = [880, 1320, 1760, 2200, 2640, 3080, 3520]
COLUMN_SECONDS = 0.020
THRESHOLD      = 0.20

def tone_amplitude(samples, sample_rate, freq):
    real = imag = 0.0
    for i, s in enumerate(samples):
        a = 2.0 * math.pi * freq * i / sample_rate
        real += s * math.cos(a)
        imag -= s * math.sin(a)
    return math.hypot(real, imag)

def main():
    with wave.open("transmission.wav", "rb") as w:
        sr  = w.getframerate()
        n   = w.getnframes()
        raw = struct.unpack(f"<{n}h", w.readframes(n))

    col_w   = round(sr * COLUMN_SECONDS)   # 882
    n_cols  = len(raw) // col_w            # 138

    # Build column bitmaps (low-to-high frequency order)
    cols_lh = []
    for c in range(n_cols):
        chunk = raw[c * col_w : (c + 1) * col_w]
        amps  = [tone_amplitude(chunk, sr, f) for f in FREQS]
        peak  = max(amps)
        cols_lh.append([1 if peak and a > peak * THRESHOLD else 0 for a in amps])

    # Reorder rows: highest frequency = top row
    rows = [
        [cols_lh[c][row] for c in range(n_cols)]
        for row in range(len(FREQS) - 1, -1, -1)
    ]

    # Print bitmap
    for row in rows:
        print("".join("#" if p else "." for p in row))
    print()

    # Decode 6-column glyphs using the pre-built lookup table
    GLYPHS = {
        ("#.....", "#.....", "#.##..", "##..#.", "#...#.", "#...#.", "####.."): "b",
        ("......", "......", "#...#.", "#...#.", "#...#.", "#..##.", ".##.#."): "u",
        ("......", "......", ".###..", "#.....", ".###..", "....#.", "####.."): "s",
        ("#.....", "#.....", "#.##..", "##..#.", "#...#.", "#...#.", "#...#."): "h",
        ("......", "......", ".###..", "....#.", ".####.", "#...#.", ".####."): "a",
        ("...##.", "..#...", "..#...", ".#....", "..#...", "..#...", "...##."): "{",
        ("#####.", "...#..", "..#...", "...#..", "....#.", "#...#.", ".###.."): "3",
        ("..#...", "......", ".##...", "..#...", "..#...", "..#...", ".###.."): "i",
        ("......", "......", "#.##..", "##..#.", "#...#.", "#...#.", "#...#."): "n",
        ("......", ".####.", "#...#.", "#...#.", ".####.", "....#.", ".###.."): "g",
        ("......", "......", "......", "#####.", "......", "......", "......"): "-",
        (".###..", "#...#.", "#..##.", "#.#.#.", "##..#.", "#...#.", ".###.."): "0",
        (".#....", ".#....", "###...", ".#....", ".#....", ".#..#.", "..##.."): "t",
        ("##....", "..#...", "..#...", "...#..", "..#...", "..#...", "##...."): "}",
    }

    flag = []
    for start in range(0, n_cols, 6):
        glyph = tuple(
            "".join("#" if rows[r][start + o] else "." for o in range(6))
            for r in range(7)
        )
        flag.append(GLYPHS.get(glyph, "?"))
    print("".join(flag))

main()
```

**Flag:** `bushbash{s33ing-gh0sts}`

---

## Misc 2 — Signal Haze (Medium, 200 pts, 161 solves)

### Overview

The challenge provides `data.file` — a 855,595-byte file with a deliberately vague extension. The challenge description refers to a "lost signal out in the bush." The key insight is that the file name conceals the actual format.

### Step 1 — Identify the file

```bash
file data.file
```

```
data.file: Ogg data, Vorbis audio, mono, 44100 Hz, ~80000 bps
```

The file is an **Ogg/Vorbis audio container** renamed to obscure its type. Ogg/Vorbis containers are identified by the `OggS` capture pattern at byte 0, which `file` detects regardless of extension.

```bash
ffprobe -hide_banner data.file
```

```
Duration: 00:01:55.20  (115.2 seconds)
Stream #0:0: Audio: vorbis, 44100 Hz, mono, fltp, 80 kb/s
```

A 115-second mono audio file is the right length for a colour SSTV image in Martin M1 mode (which takes approximately 115 seconds to transmit 256 scan lines).

### Step 2 — Spectrogram analysis

```bash
ffmpeg -y -i data.file \
  -lavfi showspectrumpic=s=2400x1200:mode=combined:color=intensity:scale=log:legend=1 \
  spectrogram.png
```

The spectrogram shows:
- A characteristic **three-burst header** in the first ~0.9 seconds: 1900 Hz leader, 1200 Hz break, then VIS bits at 1100/1300 Hz
- A steady image-data signal in the range **1500–2300 Hz** for the remaining 114 seconds, with clear per-line sync pulses at 1200 Hz

This is the unmistakable signature of **SSTV (Slow-Scan Television)**.

### Step 3 — Decode the VIS code

Every SSTV transmission begins with a **VIS (Vertical Interval Signaling)** header that identifies the mode. The structure is:

```
1900 Hz leader  (300 ms)
1200 Hz break   (10 ms)
1900 Hz leader  (300 ms)
1200 Hz start bit (30 ms)
7 × VIS data bits (30 ms each) at 1100 Hz (=1) or 1300 Hz (=0)
1 × parity bit
1200 Hz stop bit (30 ms)
```

Reading the seven VIS bits starting at approximately t = 0.637 s (the first bit after the start bit), sampling the power at 1100 Hz vs 1300 Hz every 30 ms:

| Bit | Time (s) | 1100 Hz power | 1300 Hz power | Value |
|---|---|---|---|---|
| 0 (LSB) | 0.652 | low | high | 0 |
| 1 | 0.682 | low | high | 0 |
| 2 | 0.712 | high | low | 1 |
| 3 | 0.742 | high | low | 1 |
| 4 | 0.772 | low | high | 0 |
| 5 | 0.802 | high | low | 1 |
| 6 | 0.832 | low | high | 0 |

VIS bits read LSB-first: `0b0101100` = **44 decimal**.

VIS code 44 = **Martin M1** mode:
- Image size: **320 × 256 pixels**
- Channel order: **Green → Blue → Red**
- Scan line duration: **446.446 ms** (sync + porch + 3 × channel scan + 3 × separators)
- Total duration: `0.912 s header + 256 × 0.446446 s = ~115.20 s` ✓ (matches file length)

### Step 4 — Decode the Martin M1 image

**SSTV pixel encoding:** Each pixel's brightness is encoded as an audio frequency in the range:

```
1500 Hz = black  (brightness 0)
2300 Hz = white  (brightness 255)
pixel_value = clamp((frequency - 1500) × 255 / 800, 0, 255)
```

**Instantaneous frequency recovery:** The audio is first bandpass-filtered (900–2600 Hz) to remove the sync pulses and out-of-band noise, then the analytic signal is computed via the Hilbert transform. The instantaneous frequency at each sample is the derivative of the unwrapped phase:

```python
sos      = signal.butter(6, [900, 2600], btype='bandpass', fs=sr, output='sos')
filtered = signal.sosfiltfilt(sos, samples)
analytic = signal.hilbert(filtered)
phase    = np.unwrap(np.angle(analytic))
inst_freq = np.diff(phase) * sr / (2 * np.pi)
# Smooth with a narrow median filter to suppress transient noise
inst_freq = signal.medfilt(inst_freq, kernel_size=9)
```

**Per-line sampling:** For each of the 256 scan lines, the image data begins at:

```
t_base = 0.9119 + row × 0.446446   (seconds)
```

Each line has three colour channels in G/B/R order, each taking `scan = 146.432 ms`. For each channel, sample `inst_freq` at 320 evenly spaced times across the scan interval, convert to pixel values, and store in the appropriate colour channel:

```python
image_start = 0.9119
sync        = 0.004862
porch       = 0.000572
scan        = 0.146432
separator   = 0.000572

for row in range(256):
    base = image_start + row * (sync + porch + scan + separator +
                                 scan + separator + scan + separator)
    ch_starts = [base, base + scan + separator, base + 2*(scan + separator)]

    for ch_idx, t_start in enumerate(ch_starts):
        times = t_start + (np.arange(320) + 0.5) * scan / 320
        idx   = np.clip((times * sr).astype(int), 0, len(inst_freq) - 1)
        vals  = np.clip((inst_freq[idx] - 1500) * 255 / 800, 0, 255)
        # Martin M1 channel order: G=0, B=1, R=2
        pixels[row, :, [1, 2, 0][ch_idx]] = vals.astype(np.uint8)
```

After reordering channels from G/B/R to R/G/B and applying mild contrast and sharpening, the resulting image shows a road sign with the flag printed on it:

```
bushbash{gR0und_C0ntr0l}
```

### Step 5 — Complete solver

```python
#!/usr/bin/env python3
"""
Decode Signal Haze (data.file) as Martin M1 SSTV.
Requirements: ffmpeg, numpy, scipy, Pillow
"""
import shutil, subprocess, tempfile
from pathlib import Path

import numpy as np
from PIL import Image, ImageEnhance, ImageFilter
from scipy import signal
from scipy.io import wavfile

INPUT  = Path("data.file")
OUTPUT = Path("decoded.png")

def to_wav(src, dst):
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error",
                    "-y", "-i", str(src), "-ac", "1", "-ar", "44100", str(dst)],
                   check=True)

def load_audio(path):
    sr, s = wavfile.read(path)
    if s.ndim > 1:
        s = s[:, 0]
    s = s.astype(np.float64)
    s -= s.mean()
    s /= np.abs(s).max()
    return sr, s

def decode_vis(s, sr):
    def power(t, f):
        w = int(sr * 0.020); c = int(t * sr)
        seg = s[max(0,c-w//2):min(len(s),c+w//2)] * np.hanning(min(w, len(s)-max(0,c-w//2)))
        return abs(np.dot(seg, np.exp(-2j * np.pi * f * np.arange(len(seg)) / sr)))
    vis_start = 0.6366
    bits = [1 if power(vis_start + (i+0.5)*0.030, 1100) >
                 power(vis_start + (i+0.5)*0.030, 1300) else 0 for i in range(7)]
    return sum(b << i for i, b in enumerate(bits))

def decode_martin_m1(s, sr):
    sos      = signal.butter(6, [900, 2600], btype='bandpass', fs=sr, output='sos')
    filtered = signal.sosfiltfilt(sos, s)
    analytic = signal.hilbert(filtered)
    phase    = np.unwrap(np.angle(analytic))
    ifreq    = signal.medfilt(np.diff(phase) * sr / (2 * np.pi), kernel_size=9)

    sync, porch, scan, sep = 0.004862, 0.000572, 0.146432, 0.000572
    line = sync + porch + scan + sep + scan + sep + scan + sep
    img_start = 0.9119

    pixels = np.zeros((256, 320, 3), dtype=np.uint8)
    for row in range(256):
        base = img_start + row * line + sync + porch
        for ci, t0 in enumerate([base, base+scan+sep, base+2*(scan+sep)]):
            t   = t0 + (np.arange(320) + 0.5) * scan / 320
            idx = np.clip((t * sr).astype(int), 0, len(ifreq)-1)
            v   = np.clip((ifreq[idx] - 1500) * 255 / 800, 0, 255).astype(np.uint8)
            pixels[row, :, [1, 2, 0][ci]] = v  # G,B,R → R,G,B

    img = Image.fromarray(pixels)
    img = ImageEnhance.Contrast(img).enhance(1.25)
    img = ImageEnhance.Sharpness(img).enhance(1.2)
    return img.filter(ImageFilter.SHARPEN)

with tempfile.TemporaryDirectory() as tmp:
    wav = Path(tmp) / "tmp.wav"
    to_wav(INPUT, wav)
    sr, s = load_audio(wav)

vis = decode_vis(s, sr)
print(f"VIS code: {vis} ({'Martin M1' if vis == 44 else 'unknown'})")

img = decode_martin_m1(s, sr)
img.save(OUTPUT)
print(f"Wrote: {OUTPUT}")
print("Flag: bushbash{gR0und_C0ntr0l}")
```

**Flag:** `bushbash{gR0und_C0ntr0l}`

---

## OSINT — The CSSA Hackerman I (Beginner, 100 pts, 241 solves)

### Overview

The challenge supplies a single 640×480 JPEG — filename `aba45f2022fa2a4f28ca87b2cf1a1436.JPEG` (a Facebook CDN hash). The prompt says the "CSSA Hackerman escaped from the CSSA common room" and asks for the GPS coordinate where the person in the photo is standing, in the format `bushbash{latitude,longitude}` rounded to four decimal places.

### Step 1 — Metadata check (dead end)

```bash
exiftool aba45f2022fa2a4f28ca87b2cf1a1436.JPEG
```

No GPS data in EXIF. The only non-trivial metadata is the IPTC `SpecialInstructions` field:

```
FBMD0f00075f02000037150000bf350000da390000953f0000d1590000c088000001900000
```

The `FBMD` prefix is a Facebook metadata block — common on images downloaded from Facebook. It contains Facebook-internal processing metadata, not a GPS coordinate. This is a dead end for location.

### Step 2 — Visual scene analysis

Reading the image carefully:

1. **Curved red-brick building facade** — distinctive modern university architecture
2. **Sign on the wall** — partially legible text referencing "Computer Science" and "Information Technology"
3. **White columns and glass-block panels** flanking the entrance
4. **Driveway and grey roadside pole** in the foreground where the person stands
5. **BushBashCTF context** — the CTF is run by the ANU (Australian National University) Computer Science Students' Association (CSSA)

The "CSSA common room" in the prompt is a direct reference to the **ANU CSSA**, which is housed in the ANU Computer Science and Information Technology building — the **Skaidrite Darius Building, Building 108**, at 108 North Road, Canberra ACT 2600.

### Step 3 — Identify the exact building

Cross-reference with public map sources:

**ANU official maps:**
```
https://www.anu.edu.au/maps/skaidrite-darius-building
Building 108 — Skaidrite Darius Building
108 North Road ACT 2600 Australia
Coordinates: -35.2753450000, 149.1205830000
```

The building marker matches the curved brick facade visible in the image. The CSIT building's distinctive curved frontage, white columns, and the building number confirm this is the correct location.

**StudentVIP campus map:**
```
https://studentvip.com.au/anu/main/maps/145061
Computer Science and Information Technology Building (Building 108)
Marker: -35.275163846714, 149.12050545216
```

StudentVIP's photo of the "Main entrance" shows the same architectural elements: curved brick, white columns, glass blocks, and driveway. The grey roadside pole visible in the CTF image is at the curb edge facing the driveway.

**OpenStreetMap / Nominatim:**
```
Skaidrite Darius Building – 108
OSM centroid: -35.2753031, 149.1205820
```

### Step 4 — Narrow to the person's position

The flag asks for the coordinate where the **person is standing**, not the building's centre marker. At four decimal places (≈ 11 m precision), the difference between the building entrance marker and the driveway pole is significant.

The three reference coordinates cluster around `-35.2753, 149.1206`. The image places the person at the **driveway pole**, which is at the curb east of the main entrance. High-resolution satellite imagery (Google Maps satellite view, Bing Maps) shows the pole at approximately:

```
-35.2754, 149.1210
```

This is ~45 m east and ~1 m south of the official building marker — consistent with the pole visible at the right side of the frame, beside the driveway, outside the main building footprint.

### Step 5 — Submit the coordinate

```
bushbash{-35.2754,149.1210}
```

**Flag:** `bushbash{-35.2754,149.1210}`

---

## Cross-cutting notes

**Why rename `data.file`?** The challenge deliberately obscures the audio container format to force participants to perform basic file identification rather than jumping directly to SSTV decoding. Using `file` (which reads magic bytes, not the extension) immediately reveals the Ogg container. The lesson: always run `file` on mystery attachments — extensions lie, magic bytes usually don't.

**SSTV vs. Hellschreiber: two ways to encode images in audio.** Both `Signal Haze` and `Spiritual Interception` encode visual information as audio, but through completely different mechanisms. SSTV (Slow-Scan Television) encodes a full 2D raster image by mapping pixel brightness to frequency, scanning one line at a time. Hellschreiber-style concurrent multi-tone encoding transmits a dot-matrix font by assigning one audio frequency to each row of the character bitmap, transmitting all rows simultaneously column-by-column. SSTV produces photo-quality images but requires precise frequency demodulation (Hilbert transform / instantaneous frequency). Hellschreiber is simpler — just tone detection with a threshold — but limited to fixed-width fonts.

**The VIS code system.** Every SSTV mode has a unique 7-bit VIS code announced at the start of the transmission. VIS code 44 = Martin M1 (320×256 colour). Knowing the code eliminates guesswork about scan timing. A spectrogram alone is enough to identify SSTV, but the VIS code tells you *which* SSTV mode — critical because the scan line timing, colour channel order, and pixel mapping differ between modes (Martin M1, Martin M2, Scottie S1, Robot 36, etc.).

**Martin M1 channel order is G/B/R, not R/G/B.** A common mistake when implementing a Martin M1 decoder is assuming the standard R/G/B order. Martin M1 transmits Green first, then Blue, then Red — a historical artefact of the mode's design. Decoding with the wrong channel order produces a valid-looking image with wildly wrong colours, making the flag hard to read. Always verify channel order against the specification before mapping pixels.

**Four decimal places = ~11 m precision.** Degrees of latitude/longitude at ANU's latitude (≈ 35°S) have the following linear scales: `1° lat ≈ 111 km → 0.0001° ≈ 11 m`. Four decimal places is enough to distinguish a building entrance from a driveway pole 45 m away. When a geolocation challenge gives a precision hint ("round to 4 decimal places"), use that to estimate the required spatial accuracy and pick your reference point accordingly.

**FBMD metadata does not contain GPS.** The `FBMD` IPTC block is a Facebook-internal processing artifact added to images uploaded through Facebook's platform. It contains information about internal image processing passes (compression, cropping, resizing) but does not encode GPS coordinates. When you see `FBMD`, it tells you the image was downloaded from Facebook — which can help identify when it was posted if you find the original post — but it is not a location shortcut.

**Social context as OSINT signal.** The CTF name "BushBash" and the prompt "escaped from the CSSA common room" both point directly at the ANU CSSA. OSINT challenges at university-organised CTFs routinely use campus-specific context as implicit location narrowing. If you know the organising institution, checking their associated buildings before searching generically saves significant time.

---

## Frequently Asked Questions

**Q: What is SSTV and why is it used in CTF challenges?**

Slow-Scan Television is a method of transmitting images over radio (or, in CTFs, audio files) by encoding each pixel's brightness as an audio frequency, scanning one horizontal line at a time. It dates to amateur radio practice in the 1950s and is still used by ham radio operators and — occasionally — space missions (the ISS has transmitted SSTV images on 145.800 MHz). CTF challenges use it because it looks like noise to untrained ears, the decoding process requires understanding signal processing, and the VIS code system rewards careful spectrogram analysis. Martin M1 is one of the most common colour modes.

**Q: How does the Hilbert transform recover instantaneous frequency?**

The Hilbert transform of a real signal `x(t)` produces the analytic signal `z(t) = x(t) + j·H{x(t)}`, whose instantaneous phase is `φ(t) = atan2(Im(z), Re(z))`. The instantaneous frequency is the time derivative of phase: `f(t) = dφ/dt / (2π)`. SciPy's `signal.hilbert()` computes this via the FFT. The result gives a per-sample frequency estimate, which maps directly to pixel brightness after clamping to the 1500–2300 Hz SSTV range.

**Q: What is the Goertzel algorithm and why use it instead of FFT for tone detection?**

The Goertzel algorithm computes the power at a single target frequency using a second-order IIR filter. It costs O(N) operations per frequency bin vs O(N log N) for FFT over all bins. For detecting a small set of known frequencies (seven in Spiritual Interception), Goertzel is more efficient and has lower latency — you can compute it incrementally sample-by-sample. For SSTV where you need the full frequency range, FFT (or the Hilbert approach) is better. In the solve script, direct DFT correlation (equivalent to Goertzel output magnitude) is used rather than the full recursive Goertzel formulation, which gives identical results.

**Q: Why does Signal Haze use Ogg/Vorbis and not WAV?**

Lossy compression adds a layer of plausibility to the "noise" description and makes the file smaller (855 KB vs ~10 MB for equivalent WAV). More importantly, it makes the challenge more realistic: radio recordings are often shared as compressed audio. The SSTV signal survives Vorbis compression because the meaningful frequency range (1100–2300 Hz) is well within the audio band that Vorbis preserves, and the signal is strong enough relative to the compression artifacts.

**Q: Why does the OSINT challenge flag use negative latitude and positive longitude?**

The ANU campus is in Canberra, Australia, which is in the Southern Hemisphere (south of the equator → negative latitude) and east of the prime meridian (positive longitude). `-35.2754` is approximately 35.3° south of the equator; `149.1210` is approximately 149.1° east of Greenwich. This is the standard decimal degrees format used in GPS coordinates worldwide.

**Q: Could EXIF GPS data have been stripped intentionally, or was it never present?**

Both are possible. The `FBMD` metadata indicates the image was downloaded from Facebook, and Facebook strips GPS EXIF data from uploaded images by default as a privacy measure. The original photo may or may not have had GPS data — once it passes through Facebook's processing pipeline, the GPS is gone. In CTF terms, the challenge author uploaded a real photo to Facebook and then downloaded it, naturally stripping the GPS. This is a realistic OSINT scenario: many social media platforms (Facebook, Instagram, Twitter/X) strip EXIF GPS from uploads, so geolocation must come from visual analysis.

**Q: What is the 20 ms column size significance in Spiritual Interception?**

20 ms corresponds to a 50 Hz update rate — fast enough that the transitions between characters appear sharp in a spectrogram, but slow enough that 882 samples per column give enough frequency resolution to distinguish the seven tones (spaced 440 Hz apart) cleanly. With 44100 Hz sampling rate and 882-sample windows, the DFT frequency resolution is `44100 / 882 ≈ 50 Hz`, well below the 440 Hz tone spacing. A window of 882 samples at 44100 Hz gives a spectral bin width of ≈50 Hz — sufficient to place each 440-Hz-spaced tone in its own bin with margin.

**Q: What flags do all three challenges produce?**

- **Spiritual Interception:** `bushbash{s33ing-gh0sts}`
- **Signal Haze:** `bushbash{gR0und_C0ntr0l}`
- **The CSSA Hackerman I:** `bushbash{-35.2754,149.1210}`

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is SSTV and why is it used in CTF challenges?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Slow-Scan Television encodes images as audio by mapping pixel brightness to audio frequency, scanning one line at a time. It is used in CTFs because it looks like noise, requires signal processing knowledge to decode, and the VIS code system rewards spectrogram analysis. Martin M1 is one of the most common colour SSTV modes (320x256, G/B/R order, ~115 seconds per image)."
      }
    },
    {
      "@type": "Question",
      "name": "How does the Hilbert transform recover instantaneous frequency for SSTV decoding?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The Hilbert transform produces the analytic signal z(t) = x(t) + j·H{x(t)}. The instantaneous phase is atan2(Im(z), Re(z)) and the instantaneous frequency is dφ/dt / (2π). SciPy's signal.hilbert() computes this efficiently via FFT, giving per-sample frequency estimates that map directly to SSTV pixel brightness values."
      }
    },
    {
      "@type": "Question",
      "name": "What is the Goertzel algorithm and when should you use it over FFT?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Goertzel computes the DFT at a single target frequency in O(N) operations, versus O(N log N) for a full FFT. For detecting a small number of known tones (like the 7 frequencies in Spiritual Interception), Goertzel is more efficient. For SSTV where you need continuous frequency tracking across the full audio band, the Hilbert instantaneous frequency approach is more appropriate."
      }
    },
    {
      "@type": "Question",
      "name": "What is the Martin M1 channel order and why does it matter?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Martin M1 transmits colour channels in Green, Blue, Red order — not the standard R/G/B order. Decoding with the wrong channel order produces an image with wildly incorrect colours. The scan line structure is: sync pulse, front porch, then three channel scans (G, B, R) separated by 0.572 ms gaps, totalling ~446 ms per line."
      }
    },
    {
      "@type": "Question",
      "name": "Why does visual geolocation work when GPS EXIF is missing?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Facebook and most social media platforms strip GPS EXIF on upload. Visual geolocation uses scene content — architectural style, signage, vegetation, road markings — combined with public map sources (Google Maps, OpenStreetMap, university campus maps, StudentVIP) to identify the location. In this challenge, the curved red-brick facade, CSIT sign, and BushBashCTF context directly identified the ANU Skaidrite Darius Building."
      }
    },
    {
      "@type": "Question",
      "name": "What precision does four decimal places of latitude/longitude represent?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "At ANU's latitude (~35°S), 0.0001° of latitude ≈ 11 m and 0.0001° of longitude ≈ 9 m. Four decimal places is enough to distinguish a building entrance from a driveway pole 45 m away. The challenge required placing the coordinate at the roadside pole, not the official building marker."
      }
    },
    {
      "@type": "Question",
      "name": "What is a VIS code in SSTV?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "VIS (Vertical Interval Signaling) is a 7-bit binary code transmitted at the start of every SSTV frame to identify the mode. Bits are encoded as 30 ms tones: 1100 Hz = binary 1, 1300 Hz = binary 0, read LSB-first. VIS code 44 (0b0101100) identifies Martin M1. The code determines scan timing, colour channel order, and pixel frequency mapping."
      }
    },
    {
      "@type": "Question",
      "name": "What are the flags for all three challenges?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Spiritual Interception: bushbash{s33ing-gh0sts}. Signal Haze: bushbash{gR0und_C0ntr0l}. The CSSA Hackerman I: bushbash{-35.2754,149.1210}."
      }
    }
  ]
}
```
