---
title: "STARPWN CTF 2026 Writeup Part 1: Misc, Image Ciphers, CCSDS Steganography & RF Signals"
slug: "starpwn-ctf-2026-writeup-part-1"
description: "STARPWN CTF 2026 writeup part 1 covering eight challenges across Misc and Space Communications: ROT13 on a Doctor Who graffiti quote hidden behind a C2PA JUMBF provenance manifest, Vigenere key HAL decoded from a neon 2001: A Space Odyssey billboard, Caesar shift +10 recovering a Hitchhiker's Guide phrase, CCSDS Space Packet Protocol covert channel in out-of-range APID 100 mode bytes, LSB steganography in the red channel of an anomalously large PNG with a two-byte length prefix, Morse code on-off keying at 600 Hz decoded to B34C0N D3C0D3D V14 R4D10, MAVLink v2 drone GPS tracks visualized to reveal aerial BVLOS skywriting by drone 4, and GPS jammer geolocation by circumcenter trilateration from three downed ArduCopter vehicles in a 207 MB MAVLink pcap identified as Echo Trail Park Las Vegas."
date: 2026-08-10T10:00:00Z
lastmod: 2026-08-10T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["STARPWN CTF 2026"]
tags:
  - "starpwn ctf"
  - "starpwn ctf 2026"
  - "ctf writeup"
  - "space ctf"
  - "misc"
  - "image steganography"
  - "caesar cipher"
  - "vigenere cipher"
  - "rot13"
  - "ccsds"
  - "lsb steganography"
  - "morse code"
  - "rf decoding"
  - "on-off keying"
  - "mavlink"
  - "drone"
  - "gps jammer"
  - "trilateration"
  - "c2pa"
  - "jumbf"
  - "png analysis"
  - "space packet protocol"
  - "ctf 2026"
keywords:
  - "starpwn ctf 2026 writeup"
  - "starpwn ctf 2026 part 1"
  - "strange holos ctf writeup"
  - "silent beacon ccsds ctf"
  - "oversized downlink lsb steganography ctf"
  - "beaconing from above morse ctf"
  - "connect the dots mavlink ctf"
  - "deadly parade gps jammer ctf"
  - "ccsds covert channel ctf"
  - "vigenere hal 9000 ctf"
  - "rot13 graffiti ctf"
  - "c2pa png chunk distraction ctf"
  - "gps jammer trilateration ctf writeup"
  - "mavlink v2 drone track visualization ctf"
  - "space communications ctf 2026"
toc: true
cover:
  image: "/images/articles/starpwn-ctf-2026-writeup-part-1.png"
  alt: "STARPWN CTF 2026 writeup Part 1 cover — eight challenges solved across Misc and Space Communications including ROT13 graffiti, Vigenere HAL 9000, Caesar cipher, CCSDS covert channel, LSB steganography, Morse code beacon, MAVLink drone skywriting, and GPS jammer trilateration"
---

STARPWN CTF 2026 leaned harder into real space infrastructure than any competition we have covered before. The challenge designers did not use space as a theme coat of paint — they pulled actual protocols off the wire: CCSDS Space Packet Protocol headers straight from CCSDS 133.0-B-2, MAVLink v2 frame structure as you would capture it from an ArduCopter fleet, and genuine on-off keying waveforms at 600 Hz. The Misc track ran alongside the Space Comms category and the two shared a philosophy: every challenge had an obvious rabbit hole that ate hours, and a correct path that required methodically ruling the obvious hole out. If you ran five independent steganography tests and all came back negative, that *was* the deliverable — the flag was on the wall behind you.

This Part 1 writeup covers eight challenges. Part 2 covers the remaining challenges in the web, cryptography, and binary exploitation tracks. Challenge files, solver scripts, and interactive HTML writeups are at the [STARPWN CTF 2026 GitHub repository](https://github.com/Abdelkad3r/STARPWN-CTF-2026).

## Challenges covered in Part 1

| Challenge | Category | Points | Flag |
|---|---|---|---|
| Strange Holos 3 | Misc | 491 | `STARPWN{Bow ties are cool!}` |
| Strange Holos 4 | Misc | 495 | `STARPWN{I AM SORRY DAVE, I CANT DO THAT}` |
| Strange Holos 5 | Misc | 492 | `STARPWN{SO LONG AND THANKS FOR ALL THE PHISH}` |
| Silent Beacon | Space Comms / RF | 492 | `STARPWN{h0us3k33p1ng_4n0m4ly}` |
| Oversized Downlink | Misc | 491 | `STARPWN{lsb_st3g0_1n_th3_d0wnl1nk_ch4nnel}` |
| Beaconing from Above | Space Comms / RF | 491 | `STARPWN{B34C0N_D3C0D3D_V14_R4D10}` |
| Connect the Dots | Space Comms / RF | 478 | `starpwn{Beyond_Visual_Line_Of_Sight}` |
| Deadly Parade | Communications / RF | 498 | `starpwn{Echo_Trail_Park}` |

---

## Strange Holos 3 (Misc, 491 pts)

> *Flag:* `STARPWN{Bow ties are cool!}`

**Challenge file:** `space3-glitter.png` — a cyberpunk rooftop render rendered in glittery neon style.

### The distraction: C2PA provenance manifest

The first thing any steganography player does is run `pngcheck` and scan the chunk list. `space3-glitter.png` contained a non-standard `caBX` chunk that decoded to a complete C2PA JUMBF provenance manifest, including an OpenAI signing certificate and a valid RSA-PSS signature over the image data. This is a sophisticated technical distraction. The manifest is syntactically correct and cryptographically valid — everything about it demands attention.

We ran five independent steganography tests and documented each result explicitly:

1. **LSB plane analysis** (R, G, B channels, bit 0) — no structure, chi-square p-value uniform across all three planes.
2. **Chi-square test on 8×8 blocks** — no anomalous blocks; distribution consistent with compressed render artefacts.
3. **FFT of each colour channel** — no periodic component injected into spatial frequencies; spectrum matches typical photorealistic render.
4. **Block duplication scan** (copy-move forgery detection) — no matching blocks found.
5. **Cross-image correlation against challenge files 1 and 2** — no correlated regions.

All five negative. That result is not a failure — it is the deliverable. The C2PA manifest was placed precisely to trigger steganography investigation and waste solver time.

### The actual solution: look at the image

With steganography ruled out, we actually read the graffiti on the wall visible in the cyberpunk rooftop scene. A tag on a concrete wall reads:

```
Obj gvrf ner pbby!
```

This is recognisably ROT13 — the letter distribution is English-shaped, the spacing is English-shaped, the exclamation mark is unaffected. A solver that tests all 26 Caesar rotations and scores each result against an English word list will flag rotation 13 uniquely, but you can also just read it:

```python
import codecs
ciphertext = "Obj gvrf ner pbby!"
plaintext = codecs.decode(ciphertext, "rot_13")
# → "Bow ties are cool!"
```

A TARDIS outline stencil visible on the same wall corroborates the Doctor Who reference: *"Bow ties are cool!"* is the Eleventh Doctor's catchphrase. The flag follows directly.

**Takeaway:** negative steganography results are the deliverable. The complexity of a C2PA manifest is a deliberate distraction engineered to stop solvers from reading what is literally written on the wall.

---

## Strange Holos 4 (Misc, 495 pts)

> *Flag:* `STARPWN{I AM SORRY DAVE, I CANT DO THAT}`

**Challenge file:** `space4-glitter.png` — a neon billboard scene with a weathered Space Station V poster in the background.

### Cipher classification

The billboard ciphertext is:

```
P AX ZOCYY OHVP, P CLUT OV TSHT
```

The classification step is the critical first move. A solver who jumps straight to Caesar will waste time. The key observation: the ciphertext contains `YY` (in `ZOCYY`), but the only English word in the right position is `SORRY` (which contains `RR`). No monoalphabetic substitution cipher can map two different plaintext letters (`R`, `R`) to two different ciphertext letters (`Y`, `Y`) while also mapping `R` → one fixed letter. That doubled-letter mismatch proves this is **not** a simple Caesar or any monoalphabetic bijection — it must be **polyalphabetic**.

### Vigenere key recovery

With Vigenere confirmed, we ran an exhaustive search over all 1–4 character ASCII alphabetic keys (26 + 676 + 17,576 + 456,976 = 475,254 combinations). The scoring lexicon deliberately excluded franchise-specific words (`SORRY`, `DAVE`, `CANT`) to avoid circular reasoning — if we included the expected plaintext words in our scoring function, we would be finding what we expected, not what is there.

Key `HAL` emerged uniquely. Decryption:

```python
def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    result = []
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            dec = chr((ord(c.upper()) - ord('A') - shift) % 26 + ord('A'))
            result.append(dec)
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

print(vigenere_decrypt("P AX ZOCYY OHVP, P CLUT OV TSHT", "HAL"))
# → I AM SORRY DAVE, I CANT DO THAT
```

HAL 9000's iconic line from *2001: A Space Odyssey*, confirmed by the weathered Space Station V poster visible in the background.

### Critical detail on flag format

The flag has **no apostrophe** in `CANT`. The exact punctuation and case must match: `STARPWN{I AM SORRY DAVE, I CANT DO THAT}`. Apostrophes are stripped, the comma is present, all uppercase.

**Script approach in three stages:**

1. Stage 1 proves polyalphabetic by finding the doubled letters that no bijection can produce.
2. Stage 2 runs exhaustive Vigenere key recovery with a franchise-neutral lexicon.
3. Stage 3 re-derives the full keystream from key `HAL` and verifies the decryption deterministically.

**Takeaway:** cipher classification before attempted decryption saves hours. One doubled-letter mismatch eliminates the entire monoalphabetic cipher family.

---

## Strange Holos 5 (Misc, 492 pts)

> *Flag:* `STARPWN{SO LONG AND THANKS FOR ALL THE PHISH}`

**Challenge file:** `space5-glitter.png` — a 1536×1024 RGB PNG billboard referencing *The Hitchhiker's Guide to the Galaxy* (`DON'T PANIC`, `TOWEL DAY` visible in the background).

### Short-word test confirms Caesar shift

The billboard ciphertext is:

```
IE BEDW QDT JXQDAI VEH QBB JXU FXYIX
```

The two-letter word `IE` and the four-letter word `BEDW` give us everything we need. Testing all 26 shifts on `IE`:

- Shift +10: `IE` → `SO` (a common English two-letter word)

Applying shift +10 to `BEDW`: `B+10=L`, `E+10=O`, `D+10=N`, `W+10=G` → `LONG`. That is definitive — shift +10 with two independent short-word confirmations cannot be a coincidence.

### The critical detail: PHISH not FISH

The full decryption:

```python
def caesar_decrypt(text, shift=10):
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)

print(caesar_decrypt("IE BEDW QDT JXQDAI VEH QBB JXU FXYIX"))
# → SO LONG AND THANKS FOR ALL THE PHISH
```

The final word is **`PHISH`** — not `FISH`. This is the trap. Every solver who has read *Hitchhiker's Guide* expects the last word to be `FISH` (the Babel fish, the dolphins' farewell). But the ciphertext is `FXYIX`:

- `F+10` = `P`
- `X+10` = `H`
- `Y+10` = `I`
- `I+10` = `S`
- `X+10` = `H`

That gives `PHISH`. Four characters in: the `I` maps to `S`, not `L`. The solver who types `FISH` from memory rather than decoding character-by-character will submit a wrong flag.

**Takeaway:** always derive each character from the ciphertext — do not fill in expected words from cultural knowledge. The +10 shift is also +10 applied to your assumptions.

---

## Silent Beacon (Space Comms / RF, 492 pts)

> *Flag:* `STARPWN{h0us3k33p1ng_4n0m4ly}`

**Challenge files:** `capture.bin`, `packet_ids.txt`, `telemetry_dictionary.json`

### Protocol: CCSDS Space Packet Protocol

The capture uses CCSDS 133.0-B-2 (Space Packet Protocol). Synchronisation uses the standard Attached Synchronization Marker (ASM): `0x1ACFFC1D`. After the ASM, each frame contains a standard 6-byte CCSDS primary header:

```
Bits [0:10]  = APID (Application Process Identifier)
Bits [11]    = Sequence Flags
Bits [12:27] = Packet Sequence Count
Bits [28:43] = Packet Data Length (value = length - 1)
```

Three packet types are defined in `telemetry_dictionary.json`:

| APID | Name | Description | Payload |
|---|---|---|---|
| 50 | SYSLOG | System log messages | Free-form ASCII |
| 100 | HK_NOMINAL | Housekeeping telemetry | 14 bytes fixed; mode field documented range 0–7 |
| 200 | ADCS_STATUS | Attitude control | 8 bytes fixed |

### Finding the covert channel

The `HK_NOMINAL` packets (APID 100) contain a `mode` field. The `telemetry_dictionary.json` documents valid values as **0 through 7**. During analysis, packets with mode values exceeding 7 appeared throughout the capture. Out-of-range mode bytes whose values fall in the printable ASCII range (32–126) are the covert channel.

The extraction procedure:

1. Scan `capture.bin` for ASM bytes `0x1A 0xCF 0xFC 0x1D`.
2. Parse the 6-byte CCSDS primary header following each ASM.
3. Filter for APID 100 packets.
4. Sort packets by **Packet Sequence Count** (0 through 88).
5. Extract the `mode` byte from each HK_NOMINAL payload (offset 0 of the secondary header).
6. Collect mode bytes where value > 7.
7. Decode the collected bytes as ASCII.

```python
import struct

ASM = b'\x1a\xcf\xfc\x1d'

def parse_ccsds(data):
    records = []
    pos = 0
    while pos < len(data) - 10:
        idx = data.find(ASM, pos)
        if idx == -1:
            break
        hdr = data[idx + 4 : idx + 10]
        if len(hdr) < 6:
            break
        word0, word1, word2 = struct.unpack('>HHH', hdr)
        apid = word0 & 0x07FF
        seq_count = word1 & 0x3FFF
        pkt_len = word2 + 1
        payload_start = idx + 10
        payload = data[payload_start : payload_start + pkt_len]

        if apid == 100 and len(payload) >= 1:
            mode_byte = payload[0]
            records.append((seq_count, mode_byte))
        pos = idx + 1
    return records

with open('capture.bin', 'rb') as f:
    raw = f.read()

records = parse_ccsds(raw)
records.sort(key=lambda r: r[0])

covert = bytes(mode for _, mode in records if mode > 7)
print(covert.decode('ascii'))
# → h0us3k33p1ng_4n0m4ly
```

**Takeaway:** when a protocol defines a bounded value range, out-of-range values are almost always intentional. Sort by sequence count before decoding or the message is scrambled.

---

## Oversized Downlink (Misc, 491 pts)

> *Flag:* `STARPWN{lsb_st3g0_1n_th3_d0wnl1nk_ch4nnel}`

**Challenge file:** `downlink.png` — a 256×256 Earth limb thumbnail, anomalously large for its dimensions.

### The wrong anomaly

The file size anomaly is real and visible immediately. A 256×256 synthetic RGB image should compress to a few tens of kilobytes. This file is much larger. The instinct is to look for appended data or hidden chunks.

We ran a full audit:

- CRC validation on every PNG chunk: all passed.
- Decompressed data size: exactly 256 × (1 + 256 × 3) = 197,633 bytes — a perfect 256×256 RGB image with filter bytes. No extra bytes.
- Data after IEND chunk: none.

The size anomaly has a mundane explanation: smooth, saturated synthetic colour gradients (an Earth limb is exactly this — clean gradients of blue against black) compress poorly with PNG's deflate algorithm. The compression ratio was approximately 88.7%. This is not hidden data — it is just a poorly compressible image.

### Finding the actual steganography

With the size anomaly explained away, we searched for payload in the pixel data itself. The standard approach: extract LSB planes for each channel in each bit order.

The key finding: the first 16 bits of the red channel's LSB plane (row-major, MSB-first) decode to `0x002A` = 42. That is a plausible length prefix — 42 bytes is exactly flag-length for a STARPWN flag string.

```python
import numpy as np
from PIL import Image

img = np.array(Image.open('downlink.png'))
height, width, _ = img.shape

def extract_lsb_plane(channel_data, msb_first=True):
    bits = (channel_data & 1).flatten()
    if not msb_first:
        # reverse bit order within each byte
        bits = bits.reshape(-1, 8)[:, ::-1].flatten()
    n_bytes = len(bits) // 8
    byte_vals = np.packbits(bits[:n_bytes * 8])
    return bytes(byte_vals)

channels = {'R': img[:, :, 0], 'G': img[:, :, 1], 'B': img[:, :, 2]}

for name, ch in channels.items():
    for msb in (True, False):
        order = 'big' if msb else 'little'
        raw = extract_lsb_plane(ch, msb_first=msb)
        length = int.from_bytes(raw[:2], 'big')
        if 20 <= length <= 80:
            candidate = raw[2 : 2 + length]
            try:
                text = candidate.decode('ascii')
                if text.startswith('STARPWN{') and text.endswith('}'):
                    print(f"Channel {name} ({order}-endian): {text}")
            except UnicodeDecodeError:
                pass
```

Only the **red channel, MSB-first, with 2-byte length prefix** produces valid ASCII matching the flag format. The other five combinations produce either non-ASCII bytes or lengths that do not self-consistently decode a flag.

**Takeaway:** when a file size anomaly exists, explain it before assuming it means hidden data. Then search all six channel/bit-order combinations systematically — the self-consistent length prefix is the strongest validator.

---

## Beaconing from Above (Space Comms / RF, 491 pts)

> *Flag:* `STARPWN{B34C0N_D3C0D3D_V14_R4D10}`

**Challenge file:** `beacon.wav` — an 82-second recording at 22.05 kHz, mono.

### Signal analysis

The first step is confirming the carrier frequency. An FFT of the first two seconds shows a single dominant peak at **600 Hz**. The signal is on-off keyed (OOK): the carrier switches fully on and fully off with no modulation beyond amplitude — no Doppler drift, no frequency shift. This is a synthetic capture.

### Demodulation

```python
import numpy as np
import scipy.io.wavfile as wav

rate, samples = wav.read('beacon.wav')
samples = samples.astype(float) / 32768.0

# Shift to baseband by mixing with complex exponential at 600 Hz
t = np.arange(len(samples)) / rate
analytic = samples * np.exp(-2j * np.pi * 600 * t)

# 20 ms moving average filter to get envelope
window = int(0.020 * rate)
kernel = np.ones(window) / window
envelope = np.abs(np.convolve(analytic.real, kernel, mode='same'))

# Threshold at 0.35
binary = (envelope > 0.35).astype(int)
```

### Morse decoding

Run-length encoding of the binary signal gives element durations. The fundamental unit (dit) is 100 ms, giving dah = 300 ms and standard inter-element gaps of 100 ms (between elements), 300 ms (between characters), and 700 ms (between words). This is 12 WPM International Morse Code.

The full decoded transmission:

```
VVV VVV VVV DE STARPWN STARPWN STARPWN B34C0N D3C0D3D V14 R4D10 73 DE STARPWN K
```

This is a textbook amateur radio beacon format:
- `VVV VVV VVV` — tuning sequence (carrier identification)
- `DE STARPWN` — "from station STARPWN"
- `B34C0N D3C0D3D V14 R4D10` — leetspeak payload: BEACON DECODED VIA RADIO
- `73` — best regards (standard sign-off)
- `DE STARPWN K` — station identification, over

### Robustness verification

The solver sweeps 18 parameter combinations (6 threshold values × 3 smoothing window sizes) to confirm the decoded text is stable across the parameter space. All 18 combinations decode identically, confirming the signal is clean and the parameters are not sensitive.

```python
# cwlib.py: run-length to Morse symbols
MORSE_CODE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
}
```

The flag uses the leetspeak content words: `B34C0N_D3C0D3D_V14_R4D10`.

**Takeaway:** sweep the parameter space to verify robustness before committing to a decode. A signal that only decodes for one specific threshold is suspect; a signal that decodes identically across 18 combinations is reliable.

---

## Connect the Dots (Space Comms / RF, 478 pts)

> *Flag:* `starpwn{Beyond_Visual_Line_Of_Sight}`

**Challenge file:** `PRISM_S03_B10-30_20260830.raw.zst` (Zstandard compressed, 149 MB raw)

### The category misdirection

The file is named `.raw.zst` and categorised under Space Comms / RF. Every RF solver instinct says SDR capture. After decompressing with `zstd -d`, the magic byte of the raw data is `0xFD` — not a SIGMF or complex-float header. `0xFD` is the MAVLink v2 frame magic byte. This is not an RF capture. It contains **4.1 million MAVLink v2 frames** from a drone fleet.

### MAVLink v2 frame parsing

MAVLink v2 frame structure:

```
0xFD        magic byte
uint8_t     payload_len
uint8_t     incompat_flags
uint8_t     compat_flags
uint8_t     seq
uint8_t     sysid
uint8_t     compid
uint24_t    msgid (3 bytes, little-endian)
uint8_t[]   payload (payload_len bytes)
uint16_t    checksum
```

Critical implementation note: **MAVLink v2 trims trailing zero bytes from payloads**. The declared `payload_len` may be less than the struct's full size. The parser must pad the payload to the declared length and then to the full struct size before unpacking.

```python
def mavlink_frames(data):
    MAGIC = 0xFD
    pos = 0
    while pos < len(data) - 12:
        if data[pos] != MAGIC:
            pos += 1
            continue
        payload_len = data[pos + 1]
        frame_len = 10 + payload_len + 2
        if pos + frame_len > len(data):
            pos += 1
            continue
        frame = data[pos : pos + frame_len]
        seq = frame[4]
        sysid = frame[5]
        compid = frame[6]
        msgid = frame[7] | (frame[8] << 8) | (frame[9] << 16)
        payload = frame[10 : 10 + payload_len]
        yield sysid, compid, msgid, seq, payload
        pos += frame_len
```

### Extracting GPS tracks

Message ID 33 is `GLOBAL_POSITION_INT`. The struct (MAVLink common dialect) is:

```
int32_t  time_boot_ms
int32_t  lat          (degE7)
int32_t  lon          (degE7)
int32_t  alt          (mm)
int32_t  relative_alt (mm)
int16_t  vx, vy, vz  (cm/s)
uint16_t hdg         (cdeg)
```

Total struct size: 28 bytes. Payloads shorter than 28 bytes must be zero-padded before unpacking with `struct.unpack('<iiiiihhhhH', ...)`.

The capture contains **10 system IDs (1–10)** with **146,547 GPS position messages** total.

### Visualising the anomaly

We projected all tracks to a local equirectangular plane:

```python
import math

LAT0 = lat_center  # mean latitude of all fixes
LON0 = lon_center  # mean longitude of all fixes

def project(lat_e7, lon_e7):
    lat = lat_e7 / 1e7
    lon = lon_e7 / 1e7
    x = (lon - LON0) * 111320 * math.cos(math.radians(LAT0))
    y = (lat - LAT0) * 111320
    return x, y
```

Nine of the ten drones trace structured patrol rectangles. **System ID 4** deviates significantly — its track is irregular and much larger in extent. Plotting drone 4's track in isolation and scaling it to fill the frame, the path spells **BVLOS** — Beyond Visual Line Of Sight, the regulatory term for drone operations beyond the pilot's direct line of sight.

The three SVG outputs (fleet routes, per-drone panel grid, anomaly highlight) are generated by `mavlink_parse.py` in the repository. The BVLOS skywriting only becomes legible when drone 4's track is isolated and the aspect ratio is preserved.

**Takeaway:** when a file's category and name disagree with its actual magic bytes, trust the bytes. MAVLink v2 trailing-zero trimming is the implementation trap that breaks naive parsers.

---

## Deadly Parade (Communications / RF, 498 pts)

> *Flag:* `starpwn{Echo_Trail_Park}`

**Challenge file:** `PRISM_S05_DNCN_20260831.pcap`
- Size: 207,743,808 bytes
- SHA256: `ea784a729e14e55299e3551b04526c2f96f0eab878c9fcaf67674ad1cc98333b`
- Contents: 2,079,339 packets over 3,159 seconds
- Link layer: Linux cooked-mode v2 (`LINKTYPE_LINUX_SLL2`)
- Transport: UDP port 14550 (MAVLink default), loopback interface

### Parsing the pcap without scapy

The pcap uses standard global header + per-packet header format. The per-packet header in this capture uses Linux SLL2 (cooked mode v2), which has a 20-byte header before the IP datagram. A minimal stdlib parser:

```python
import struct

PCAP_GLOBAL_HDR = 24
PCAP_PKT_HDR = 16
SLL2_HDR = 20
IP_HDR_MIN = 20
UDP_HDR = 8
MAVLINK_OFFSET = PCAP_PKT_HDR + SLL2_HDR + IP_HDR_MIN + UDP_HDR

def iter_pcap_mavlink(path):
    with open(path, 'rb') as f:
        f.read(PCAP_GLOBAL_HDR)
        while True:
            hdr = f.read(PCAP_PKT_HDR)
            if not hdr or len(hdr) < PCAP_PKT_HDR:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', hdr)
            pkt = f.read(incl_len)
            ts = ts_sec + ts_usec / 1e6
            mav_data = pkt[SLL2_HDR + IP_HDR_MIN + UDP_HDR:]
            # Parse MAVLink v2 frames from mav_data
            yield ts, mav_data
```

### Fleet composition

- **System IDs 1–10:** ArduCopter SITL vehicles
- **System ID 255:** Ground Control Station (GCS)
- **Message types used:** `GLOBAL_POSITION_INT` (33), `GPS_RAW_INT` (24), `EKF_STATUS_REPORT` (193), `STATUSTEXT` (253)

### Identifying the GPS jamming incident

Three vehicles (sysids 2, 3, 5) experienced GPS denial during the flight. The signature:

- `GPS_RAW_INT.satellites_visible` dropped from 10 → 3
- `GPS_RAW_INT.fix_type` dropped from 6 (RTK_FIXED) → 1 (NO_FIX)
- Subsequent `EKF_STATUS_REPORT` messages showed velocity and position variance exceeding failsafe thresholds
- `STATUSTEXT` messages reported EKF failsafe triggered, followed by crash

### Critical: non-sequential timestamps

The pcap contains packets with **non-sequential timestamps** — a common artefact when multiple vehicles write to the same UDP capture stream and system-level buffering reorders packets. Sorting each vehicle's telemetry chronologically before analysis is mandatory:

```python
from collections import defaultdict

vehicle_gps = defaultdict(list)
vehicle_raw = defaultdict(list)

for ts, mav_data in iter_pcap_mavlink('PRISM_S05_DNCN_20260831.pcap'):
    for sysid, compid, msgid, seq, payload in mavlink_frames(mav_data):
        if msgid == 33:  # GLOBAL_POSITION_INT
            vehicle_gps[sysid].append((ts, payload))
        if msgid == 24:  # GPS_RAW_INT
            vehicle_raw[sysid].append((ts, payload))

# Sort each vehicle's records by timestamp before analysis
for sysid in vehicle_gps:
    vehicle_gps[sysid].sort(key=lambda r: r[0])
for sysid in vehicle_raw:
    vehicle_raw[sysid].sort(key=lambda r: r[0])
```

### Extracting the jammer boundary points

For each of the three downed vehicles (sysids 2, 3, 5), the last valid GPS fix before `NO_FIX` is the exact moment the vehicle crossed the jammer's coverage boundary. These three points lie on a circle whose centre is the jammer.

```python
def find_last_good_fix(sysid, gps_records, raw_records):
    """Return the last GPS position before satellites dropped below 6."""
    last_good = None
    for ts, payload in gps_records:
        padded = payload.ljust(28, b'\x00')
        time_boot, lat, lon, alt, rel_alt, vx, vy, vz, hdg = struct.unpack('<iiiiihhhhH', padded)
        # Find corresponding GPS_RAW_INT for this timestamp
        sats = get_satellites_at(sysid, raw_records, ts)
        if sats >= 6:
            last_good = (lat / 1e7, lon / 1e7)
        else:
            if last_good:
                return last_good
    return last_good
```

### Circumcenter trilateration

Three points on a circle uniquely determine the circle's centre and radius. The circumcenter formula in Cartesian coordinates:

```python
import math

def haversine(lat1, lon1, lat2, lon2):
    R = 6371000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

def circumcenter(p1, p2, p3):
    """
    p1, p2, p3: (lat, lon) tuples
    Returns (center_lat, center_lon, radius_m)
    """
    # Project to local tangent plane
    lat0, lon0 = p1
    cos_lat = math.cos(math.radians(lat0))

    def to_xy(lat, lon):
        x = (lon - lon0) * 111320 * cos_lat
        y = (lat - lat0) * 111320
        return x, y

    x1, y1 = to_xy(*p1)
    x2, y2 = to_xy(*p2)
    x3, y3 = to_xy(*p3)

    ax, ay = x2 - x1, y2 - y1
    bx, by = x3 - x1, y3 - y1
    D = 2 * (ax * by - ay * bx)
    ux = (by * (ax**2 + ay**2) - ay * (bx**2 + by**2)) / D
    uy = (ax * (bx**2 + by**2) - bx * (ax**2 + ay**2)) / D

    cx = x1 + ux
    cy = y1 + uy
    center_lat = lat0 + cy / 111320
    center_lon = lon0 + cx / (111320 * cos_lat)
    radius = math.sqrt(ux**2 + uy**2)
    return center_lat, center_lon, radius

# Result: 36.086802, -115.263313, radius 2000.0 m
```

The radius of **exactly 2000.0 m** (a suspiciously round number) confirms the jammer model and validates the calculation.

### Geolocating the centre

The coordinates `36.086802, -115.263313` fall in Las Vegas, Nevada. We query the Overpass API for the nearest named place:

```python
import urllib.request, json

def reverse_geocode(lat, lon, radius=100):
    endpoints = [
        "https://overpass-api.de/api/interpreter",
        "https://overpass.kumi.systems/api/interpreter",
        "https://overpass.private.coffee/api/interpreter",
        "https://overpass.openstreetmap.ru/api/interpreter",
    ]
    query = f"""
    [out:json][timeout:25];
    (
      node["name"](around:{radius},{lat},{lon});
      way["name"](around:{radius},{lat},{lon});
      relation["name"](around:{radius},{lat},{lon});
    );
    out center;
    """
    for endpoint in endpoints:
        try:
            req = urllib.request.Request(
                endpoint,
                data=query.encode(),
                method='POST',
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
                if data.get('elements'):
                    return data['elements'][0].get('tags', {}).get('name', '')
        except Exception:
            continue
    return None

result = reverse_geocode(36.086802, -115.263313)
# → "Echo Trail Park"
```

The Overpass API places the jammer centre 11.5 m from the calculated circumcenter — within GPS fix precision. The location is **Echo Trail Park**, Spring Valley, Las Vegas.

**Takeaway:** circumcenter trilateration from three boundary points on a jammer's coverage circle is exact in the noise-free case. Non-sequential pcap timestamps are the trap — sort before you analyse or the boundary points are wrong.

---

## Cross-cutting lessons from the STARPWN CTF 2026 Part 1 set

Eight challenges, two categories, one underlying philosophy:

- **Rule out the rabbit hole explicitly.** Strange Holos 3 required documenting five negative steganography results before the graffiti became visible. Oversized Downlink required explaining the file size anomaly before finding the actual LSB payload. The ruling-out is the work.
- **Cipher classification before decryption.** One doubled-letter mismatch in Strange Holos 4 collapsed the entire monoalphabetic cipher family. Two short words in Strange Holos 5 pinned the Caesar shift in under a minute. Classification costs 30 seconds; wrong-cipher attempts cost hours.
- **Magic bytes over file names and categories.** Connect the Dots was named `.raw.zst` and tagged RF — the first byte of the decompressed data told the truth. Trust the bytes.
- **Protocols have out-of-range values for a reason.** CCSDS documented mode field range 0–7; out-of-range bytes were the message. Any time a protocol spec defines a bounded value, examine what lives outside the bounds.
- **Sort before you analyse.** Both MAVLink challenges punished parsers that processed frames in file order. Chronological sorting is not optional in pcap analysis.
- **Self-consistent validation beats single-source trust.** The two-byte length prefix in Oversized Downlink and the exact 2000.0 m jammer radius in Deadly Parade both acted as built-in checksums — they turned a plausible answer into a certain one.

---

## FAQ

**What is STARPWN CTF 2026?**
STARPWN CTF 2026 is a cybersecurity capture-the-flag competition with a space and RF theme, featuring challenges built around real space protocols including CCSDS Space Packet Protocol and MAVLink v2 drone telemetry. Part 1 of this writeup covers eight Misc and Space Comms challenges.

**How do you decode a CCSDS covert channel in Silent Beacon?**
Sync on the ASM (`0x1ACFFC1D`), parse 6-byte CCSDS primary headers to extract APID and sequence count, filter for APID 100 (`HK_NOMINAL`) packets, sort by sequence count, and collect mode bytes whose values exceed the documented range of 0–7. Those out-of-range bytes are printable ASCII that spell the flag when concatenated in sequence order.

**Why is the final word PHISH and not FISH in Strange Holos 5?**
The Caesar cipher operates on the actual ciphertext characters — it does not fill in expected words from cultural knowledge. The ciphertext word `FXYIX` decodes character-by-character under shift +10 to `PHISH`. The fourth ciphertext character `I` shifts to `S`, not `L`. The *Hitchhiker's Guide* reference is real, but the challenge deliberately substitutes `PHISH` for `FISH` to catch solvers who fill in expected answers.

**How do you geolocate a GPS jammer from MAVLink telemetry?**
Identify the vehicles that lost GPS lock, find each vehicle's last valid GPS fix before losing lock (these points lie on the jammer's coverage circle boundary), then compute the circumcenter of the three boundary points. The circumcenter is the jammer's position. Reverse geocode it with the Overpass API.

**What is the MAVLink v2 trailing-zero trimming issue in Connect the Dots?**
MAVLink v2 omits trailing zero bytes from payloads to save bandwidth. The parser must pad the received payload to the declared struct length with zero bytes before calling `struct.unpack`. Failing to do this corrupts the last fields of messages like `GLOBAL_POSITION_INT` whose trailing fields happen to be zero, producing lat/lon values of 0.0 that look like valid coordinates at the Gulf of Guinea.

**What tools do you need for Beaconing from Above?**
NumPy and SciPy for signal processing (FFT, moving average filter, envelope detection), a Morse decoder library or a dictionary-based symbol mapper, and `scipy.io.wavfile` for reading the WAV file. The solver sweeps 18 parameter combinations to confirm robustness before committing to the decoded text.

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is STARPWN CTF 2026?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "STARPWN CTF 2026 is a cybersecurity capture-the-flag competition with a space and RF theme, featuring challenges built around real space protocols including CCSDS Space Packet Protocol and MAVLink v2 drone telemetry. Part 1 of this writeup covers eight Misc and Space Comms challenges."
      }
    },
    {
      "@type": "Question",
      "name": "How do you decode a CCSDS covert channel in Silent Beacon?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Sync on the ASM (0x1ACFFC1D), parse 6-byte CCSDS primary headers to extract APID and sequence count, filter for APID 100 (HK_NOMINAL) packets, sort by sequence count, and collect mode bytes whose values exceed the documented range of 0–7. Those out-of-range bytes are printable ASCII that spell the flag when concatenated in sequence order."
      }
    },
    {
      "@type": "Question",
      "name": "Why is the final word PHISH and not FISH in Strange Holos 5?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The Caesar cipher operates on the actual ciphertext characters. The ciphertext word FXYIX decodes character-by-character under shift +10 to PHISH. The fourth ciphertext character I shifts to S, not L. The Hitchhiker's Guide reference is real, but the challenge deliberately substitutes PHISH for FISH to catch solvers who fill in expected answers from cultural knowledge."
      }
    },
    {
      "@type": "Question",
      "name": "How do you geolocate a GPS jammer from MAVLink telemetry?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Identify the vehicles that lost GPS lock, find each vehicle's last valid GPS fix before losing lock (these points lie on the jammer's coverage circle boundary), then compute the circumcenter of the three boundary points. The circumcenter is the jammer's position. Reverse geocode it with the Overpass API."
      }
    },
    {
      "@type": "Question",
      "name": "What is the MAVLink v2 trailing-zero trimming issue in Connect the Dots?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "MAVLink v2 omits trailing zero bytes from payloads to save bandwidth. The parser must pad the received payload to the declared struct length with zero bytes before calling struct.unpack. Failing to do this corrupts the last fields of messages like GLOBAL_POSITION_INT, producing lat/lon values of 0.0 that look like valid coordinates at the Gulf of Guinea."
      }
    },
    {
      "@type": "Question",
      "name": "What tools do you need for Beaconing from Above?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "NumPy and SciPy for signal processing (FFT, moving average filter, envelope detection), a Morse decoder library or dictionary-based symbol mapper, and scipy.io.wavfile for reading the WAV file. The solver sweeps 18 parameter combinations across 6 thresholds and 3 smoothing windows to confirm robustness before committing to the decoded text."
      }
    }
  ]
}
```

---

Continue with [STARPWN CTF 2026 Writeup Part 2](/ctf-writeups/starpwn-ctf-2026-writeup-part-2/) for the web, cryptography, and binary exploitation challenges.

Browse all challenge files, solver scripts, and interactive HTML writeups at [github.com/Abdelkad3r/STARPWN-CTF-2026](https://github.com/Abdelkad3r/STARPWN-CTF-2026).

---

*Part 1 of the CyberSecurity Elite STARPWN CTF 2026 series. This writeup covers eight challenges across the Misc and Space Communications tracks: Strange Holos 3, Strange Holos 4, Strange Holos 5, Silent Beacon, Oversized Downlink, Beaconing from Above, Connect the Dots, and Deadly Parade. Part 2 covers the remaining challenges in the web, cryptography, and binary exploitation tracks.*
