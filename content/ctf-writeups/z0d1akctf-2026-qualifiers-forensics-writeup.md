---
title: "z0d1akCTF 2026 Qualifiers Forensics Writeup: All 8 Challenges Solved"
slug: "z0d1akctf-2026-qualifiers-forensics-writeup"
description: "Complete z0d1akCTF 2026 Qualifiers Forensics writeup covering all eight Forensics challenges. Black Box — 245 fixed-size 16-byte big-endian records where five out-of-order flag fragments carry a 0xDEAD XOR key in the trailer slot that other record types use for a sequence-derived checksum. Dead Current — CRIU 4.x checkpoint of a Go relay whose stripped ELF still ships gopclntab; carve a deleted ghost IRF1 record, recover the master secret from pages-2.img after an empty type-4 length-zero incident marker, derive SHA-256 KDF and XOR keystream to decrypt. Dead Letter Wake — reassemble seven RFC message-partial fragments (one crossed TLS but was retained as Postfix deferred queue item DLW214704) into a PDF whose PIX-8 mosaic is inverted by beam-searching DejaVu Sans 32 px through an RGB-channel-shifted forward model with 0.226 MSE. Ghost in the GPU — 32 MiB scrubbed VRAM dump whose single 1.5 MiB low-entropy survivor at 0x900000 is an fp16 mask tensor of only 0x3C00 and 0xBC00 halfwords that reshapes to 1024 x 768 and renders six copies of the flag as 5 by 7 bitmap glyphs. Hydra FC — WebSocket msgpack telemetry where a leaked source map documents a naive seq greater-than comparison; CAM-EAST injects 326 confidence-equals-1.0 frames near the uint16 ceiling with the ball parked on 25-module grid centers, plotting to a mirrored QR code that decodes to the flag. layer-eight — OCI image with nine layers; layer 8 stores whiteouts .wh.deploy_key, .wh.postinstall.sh, .wh.provenance.py that mark files deleted but do not remove bytes from layers 4 and 6, and three image labels part-a, part-b, part-c shard an AES-256-GCM envelope in the layout order c-a-b. 99.8% — interrupted qBittorrent session salted with five plaintext pH4K3_ and d3c0Y_ decoys; recover the qbcn scheme (SHA-256 KDF over domain, piece_window, piece_length_word) with domain in the memory dump, piece_window as the first sixteen SHA-1 piece hashes, and a keycheck-verified HREG container in the .!qB partfile's final piece that XOR-decrypts to a QBCN record holding the flag. Unrotated — seven-part incident-response chain across identity, application, governance, host journal, container OCI whiteouts, network firewall CSV, physical patch panel PNG, and ANSI cursor cast replay — the report is seven line-oriented values submitted to a TLS service."
date: 2026-08-30T19:00:00Z
lastmod: 2026-08-30T19:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["z0d1akCTF 2026 Qualifiers"]
tags:
  - "z0d1akctf"
  - "z0d1akctf 2026"
  - "z0d1ak ctf"
  - "z0d1akctf qualifiers"
  - "ctf writeup"
  - "forensics"
  - "digital forensics"
  - "binary parsing"
  - "big-endian records"
  - "criu checkpoint"
  - "criu ghost file"
  - "gopclntab"
  - "stripped go binary"
  - "mime message partial"
  - "postfix deferred queue"
  - "pdf carving"
  - "pix-8 mosaic"
  - "vram dump"
  - "entropy carving"
  - "fp16 mask tensor"
  - "5x7 bitmap glyphs"
  - "websocket msgpack"
  - "source map leak"
  - "sequence rollover bug"
  - "qr reconstruction"
  - "oci image layer"
  - "whiteout carving"
  - "aes-256-gcm envelope"
  - "qbittorrent partfile"
  - "torrent forensics"
  - "keystream cipher"
  - "systemd journal"
  - "ansi cursor cast"
  - "asciinema replay"
  - "patch panel tracing"
  - "incident timeline"
  - "cross-layer correlation"
  - "ctf 2026"
keywords:
  - "z0d1akctf 2026 qualifiers forensics writeup"
  - "z0d1akctf 2026 forensics writeup"
  - "z0d1akctf black box writeup"
  - "z0d1akctf dead current writeup"
  - "z0d1akctf dead letter wake writeup"
  - "z0d1akctf ghost in the gpu writeup"
  - "z0d1akctf hydra fc writeup"
  - "z0d1akctf layer-eight writeup"
  - "z0d1akctf 99.8 percent writeup"
  - "z0d1akctf unrotated writeup"
  - "criu checkpoint forensics ghost file carving ctf"
  - "gopclntab stripped go binary symbol recovery"
  - "mime message partial rfc reassembly ctf"
  - "postfix deferred queue tls dead letter"
  - "vram dump entropy carve fp16 tensor ctf"
  - "websocket msgpack telemetry naive seq rollover"
  - "oci docker layer whiteout carve deleted secret"
  - "qbittorrent partfile qbcn hreg container ctf"
  - "aes-256-gcm envelope sharded image labels"
  - "ansi cursor cast asciinema replay ctf"
  - "systemd journalctl compact journal decode"
  - "patch panel physical trace ctf"
  - "z0d1akctf 2026 solutions"
  - "ctf forensics step by step 2026"
toc: true
cover:
  image: "/images/articles/z0d1akctf-2026-qualifiers-forensics-writeup.png"
  alt: "z0d1akCTF 2026 Qualifiers Forensics writeup cover — all eight Forensics challenges solved. Black Box parses 245 big-endian 16-byte records and XOR-decrypts five out-of-order flag fragments with the 0xDEAD key sitting in the trailer slot. Dead Current carves a deleted CRIU ghost IRF1 record, parses gopclntab from a stripped Go binary, and recovers the master secret from pages-2.img after an empty type-4 length-zero incident marker. Dead Letter Wake reassembles seven MIME message-partial fragments across a PCAP and a Postfix deferred queue into a PDF whose PIX-8 mosaic is inverted by beam-searching DejaVu Sans 32 pixel through an RGB-channel-shifted forward model. Ghost in the GPU carves the single 1.5 MiB low-entropy survivor from a 32 MiB scrubbed VRAM dump, reads it as an fp16 mask of only positive and negative one, and reshapes to a 1024 by 768 framebuffer rendering the flag as 5 by 7 bitmap glyphs. Hydra FC exploits a source map that documents a naive sequence comparison, isolates 326 confidence-equals-1.0 frames injected by CAM-EAST near the uint16 ceiling, and plots them onto a mirrored QR code. layer-eight carves the deploy_key, postinstall script, and provenance script from OCI layers 4 and 6 despite layer 8 whiteouts, and reassembles three sharded image labels into an AES-256-GCM envelope in the layout order c then a then b. 99.8% ignores five plaintext decoys tagged pH4K3 and d3c0Y, derives the qbcn key from a memory-dump domain plus torrent piece window plus piece-length word, and decrypts an HREG container in the partfile's final piece. Unrotated correlates seven artifacts — identity rotation manifest, gateway session, misused change record, delegated runner job, OCI whiteout route file, ANSI cursor cast replay, patch panel physical trace — into a seven-line incident report accepted by the TLS service"
---

**z0d1akCTF 2026 Qualifiers**'s Forensics track is an eight-challenge master class in one shared discipline: **read the wake, not the labels.** In every one of these challenges the system claims to have removed, scrubbed, obscured, or overwritten the evidence — and every one of them fails at exactly one layer that a careful analyst can reach. Black Box scrambles five flag fragments through impact damage but leaves each fragment's own sequence number intact. Dead Current is a *CRIU checkpoint*, which the flag calls an "afterimage" outright — deleted files persist as ghost images, freed heap pages persist as pages, and "zeroised" secrets sit frozen in the migration blob. Dead Letter Wake obscures one of seven MIME fragments behind TLS on the wire, but Postfix retained the same message as deferred queue item `DLW214704`. Ghost in the GPU scrubs 30.5 MiB of a VRAM capture with uniform noise but the surviving 1.5 MiB fp16 allocation is a low-entropy island in a random ocean. Hydra FC's gateway serves a *source map* that documents the vulnerable `shouldReplace()` function verbatim. layer-eight's flag reads `whltEOUt_1AyErs_5TlL1_r3MeMBer_SECrETs` — the OCI whiteout in layer 8 marks the secret deleted, but its bytes still live in the earlier layer that added them. 99.8% salts the evidence tree with five plaintext decoy flags labelled `pH4K3_` and `d3c0Y_` and hides the real one inside a keystream-encrypted container in the `.!qB` partfile's final piece. Unrotated's flag names the whole discipline: `a_HuM4n_REaD5_7HE_W4ke_nO7_7h3_14Bel5` — a human reads the wake, not the labels.

The unifying pattern is that every challenge in the set has an obvious "primary" reading — the corrupted recorder, the checkpointed process, the encrypted wire, the scrubbed dump, the streamed telemetry, the deleted secret, the interrupted download, the incident summary — and in every case, the flag lives one layer *underneath* that primary reading. The forensic technique is always the same: identify what the system's own actions failed to overwrite (a sequence number, a ghost file, a queue entry, a low-entropy allocation, a source map, an earlier layer, a keystream container, an ANSI cursor cast), then read *that*.

Handouts, per-challenge READMEs, solver scripts, and captured session artifacts live at [Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers). This **CyberSecurity Elite** z0d1akCTF 2026 Qualifiers Forensics writeup covers all eight challenges end to end. Read alongside the companion [z0d1akCTF 2026 Qualifiers Miscellaneous writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-misc-writeup/) for four more challenges from the same event.

## All eight Forensics challenges at a glance

| Challenge | Points | Sub-genre | The wake to read | Flag |
|---|---:|---|---|---|
| [Black Box](#black-boxbigendian-record-carving-and-a-checksum-shaped-xor-key) | 118 | Binary record parsing | Big-endian sequence numbers + `0xDEAD` in the checksum slot | `zdk{ElEmeN74ry_bLnArY_par5LnG_MAS73r}` |
| [Dead Current](#dead-currentcriu-checkpoint-afterimage-and-a-stripped-go-relay) | 148 | CRIU checkpoint carving | Ghost file + freed heap pages + `gopclntab` | `zdk{CRIU_4fT3RIMAGE_sOA7Et3zoBl083TbCD96185oCqDD59c4}` |
| [Dead Letter Wake](#dead-letter-wakemime-messagepartial-reassembly-and-a-pix8-forward-model) | 149 | Network / mail / PDF / renderer inversion | Postfix queue item `DLW214704` + PIX-8 mosaic + calibration | `zdk{D3Ad_L3tTeRs_5pE4k_afTer_THE_wAke}` |
| [Ghost in the GPU](#ghost-in-the-gpuentropy-carving-in-a-scrubbed-vram-dump) | 131 | Memory forensics | The 1.5 MiB survivor at `0x900000` | `zdk{MemOrY_1Eak_found}` |
| [Hydra FC](#hydra-fca-source-map-leaks-the-vulnerable-gateway-function) | 122 | Network / WebSocket / QR reconstruction | `replay.js.map` + `confidence == 1.0` frames | `zdk{Mess1_0R_RONa1d0}` |
| [layer-eight](#layereightoci-whiteouts-still-remember-secrets) | 120 | Container image forensics | Layers 4 and 6 (whiteouts in layer 8) + label shards | `zdk{whltEOUt_1AyErs_5TlL1_r3MeMBer_SECrETs}` |
| [99.8%](#998-qbcn-container-inside-a-torrent-partfile) | 162 | Torrent client forensics | `.!qB` partfile final piece + memory-dump `domain` | `zdk{Q8IT_hI6H_g0a7ED}` |
| [Unrotated](#unrotatedsevenpart-incident-response-chain-across-eight-log-classes) | 137 | Incident response | Whichever log class *isn't* the label | `zdk{a_HuM4n_REaD5_7HE_W4ke_nO7_7h3_14Bel5}` |

Eight challenges, eight different substrates, one repeated discipline.

---

## Black Box — big-endian record carving and a checksum-shaped XOR key

> *Flag:* `zdk{ElEmeN74ry_bLnArY_par5LnG_MAS73r}`
>
> *Prompt:* "A survey drone crashed during a test flight… Standard analytical utilities report raw binary garbage."

The handout is a single 3,920-byte file with no signature and no `strings` hits. `3920 = 16 × 245` is the first useful signal: a whole number of small fixed-size records is the shape of a flight recorder.

A hexdump confirms the 16-byte period, with `BX` magic at every boundary. Reading the columns rather than the rows exposes the layout:

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | magic `BX` |
| 2 | 1 | record type (values 1, 2, 3) |
| 3 | 1 | flags (always `0x00`) |
| 4 | 2 | sequence number — **big-endian** |
| 6 | 8 | payload (type-dependent) |
| 14 | 2 | trailer |

The sequence number is the decisive endianness tell. Read big-endian it counts `0, 1, 2, 3, …`; read little-endian it would jump `0, 256, 512, …`. That is what the brief means by "unclassified architecture" — plain network byte order on a little-endian analyst workstation.

Filtering by record type gives:

- **type 1** — 120 GPS records (two big-endian float32 → Vellore, Tamil Nadu; perfectly linear track — synthetic filler);
- **type 2** — 120 telemetry records (four big-endian `uint16`: altitude, battery, barometric ref, tick counter — also synthetic filler);
- **type 3** — five records, sequence numbers 0–4, appearing in **physical order 3, 0, 1, 4, 2**.

The trailer field of types 1 and 2 is `(seq × multiplier) & 0xFFFF` — a trivial per-record checksum. For type 3 the trailer is the constant `0xDEAD`. A field that is variable everywhere except in one record type is the challenge handing over the key.

Sort by sequence number, concatenate the five 8-byte payloads, XOR with repeating `DE AD`:

```python
fragments = sorted((r for r in records if r.type == 3), key=lambda r: r.seq)
blob      = b"".join(r.payload for r in fragments)
plaintext = bytes(b ^ b"\xde\xad"[i % 2] for i, b in enumerate(blob))
# b'zdk{ElEmeN74ry_bLnArY_par5LnG_MAS73r}\x00\x00\x00'
```

The three trailing `\x00` bytes are a free correctness check — a wrong key would produce arbitrary bytes there. The flag itself contains the literal decode `bLnArY` and `par5LnG` (the author's leetspeak generator substitutes `i → l` before randomising case).

**Takeaway:** size factorisation is triage (`3920 = 16 × 245`). Verify the container before hunting the payload — confirming that all 240 telemetry trailers checksum correctly rules out three-quarters of the file in one step. A field that is variable everywhere but constant in one type is a message, not decoration.

---

## Dead Current — CRIU checkpoint afterimage and a stripped Go relay

> *Flag:* `zdk{CRIU_4fT3RIMAGE_sOA7Et3zoBl083TbCD96185oCqDD59c4}`
>
> *Prompt:* "A Pelagos oceanographic beacon went silent during a live migration from an offshore research vessel to shore."

The evidence is a **CRIU 4.x checkpoint** of a Go relay process plus the stripped ELF that owned it. The flag calls the whole exercise an *afterimage* — CRIU captures *everything*, including deleted files (as ghost images), queued/freed buffers, and secrets a process "zeroised" a moment later.

Three parallel recoveries compose:

**1. Reverse the relay's crypto from the stripped Go binary.** Go embeds its own metadata in `.gopclntab` (magic `0xFFFFFFF1`) which survives ELF stripping. Parsing it recovers every `main.*` function name and address, including `main.deriveIncidentKey` and `main.xorStream`. Rather than fight the disassembly, run the ELF under gdb in a `linux/amd64` container, break at `main.main`, and `jump` into `main.selfTest` — which is never called at runtime but wires the routines together with labelled test vectors. The exact scheme:

```text
incidentKey  = SHA256(state32[32] ‖ streamID[16] ‖ ctx8[8])
keystream[i] = SHA256(incidentKey ‖ uint32le(i))
plaintext    = ciphertext XOR keystream
```

**2. Carve the deleted ghost file.** `ghost-file-1.img` is a CRIU ghost with `common+ghost magic (8) | u32 size | GhostFileEntry | raw content`. `files.img` names the deleted path `/tmp/.relay-case-LM-a3febe5e3ae7`. The 207-byte content is an `IRF1` record:

```text
"IRF1"(4) | ver/hdr(4) | streamID(16) | nonce(12) | len=167(u32) | ciphertext(167)
```

**3. Recover the master secret from memory.** `state32` is a `RelayState` field in the captured heap (`pages-2.img`). The state serialises an incident record as `{u32 type=4, u32 len}` immediately followed by the 32-byte secret. In the live state the incident had already been spooled, so the record is empty (`{4,0}`) and the secret follows the 8-byte marker `04 00 00 00 00 00 00 00`:

```text
pages-2 @ 0xb8058:  04 00 00 00 00 00 00 00              <- {type=4, len=0}
pages-2 @ 0xb8060:  07393d2c6c9054f4de142a3a8de74558
                    887c7211d6166370b0b48b8134f02247    <- state32 (master secret)
```

Deriving `incidentKey = SHA256(state32 ‖ streamID ‖ nonce[0:8])` and running the keystream XOR produces `b"INC15\x00zdk{CRIU_4fT3RIMAGE_..._oCqDD59c4}"`.

**Takeaway:** a checkpoint is an afterimage. Treat migration images as sensitive as the live process memory. Stripped Go isn't opaque — `.gopclntab` survives stripping. And rather than fight the disassembly, jumping into the binary's own `selfTest` under gdb produces exact, labelled test vectors for its own crypto.

---

## Dead Letter Wake — MIME message/partial reassembly and a PIX-8 forward model

> *Flag:* `zdk{D3Ad_L3tTeRs_5pE4k_afTer_THE_wAke}`
>
> *Prompt:* "auth-…wake?"

This challenge combines network forensics, mail-queue recovery, MIME reassembly, PDF object extraction, and a small renderer-inversion problem. The handout is a `.pcap` plus a Postfix `mail-queue.tar.gz`.

**Step 1 — the missing fragment.** The PCAP contains six of seven RFC `message/partial` deliveries sharing identity `<wake.2147.deadletter@relay.pelagos.invalid>`. The seventh (part 4/7) crossed a TLS SMTP session so its wire body is inaccessible. The mail log correlates:

```text
Aug 17 02:31:35 mx postfix/cleanup[6220]: DLW214704:
    message-id=<2147-recovery.part4@relay.pelagos.invalid>
```

The deferred queue file's outer MIME headers identify it as `number=4; total=7` of the same identity. **The inaccessible wire content survives beyond the TLS boundary as a queue entry.**

**Step 2 — reassemble.** RFC `message/partial` is unusual: each wrapper body is a raw byte range of the enclosed message. Join **raw bodies** (not wrappers) in numeric order. No newline or MIME boundary may be inserted between fragments — that would change the base64 attachment. The result is 113,343 bytes containing `recovery-authorization.pdf` (82,328 bytes).

**Step 3 — extract losslessly.** The PDF text spells out the recovery path: *"Extract the document's raster objects **losslessly**. The PIX-8 target and its same-renderer calibration capture use gamma-encoded RGB averages."* `pdfimages -png` extracts a 728×56 target and a 1864×256 calibration.

**Step 4 — decode the calibration.** The calibration text starts `334353A3D3E3H3L3R3T3_3a3d3e3f3k3p3r3s3t3w3z3{3}4454A4D4E4...`. Its alphabet is 24 symbols; `24² = 576` characters is exactly an order-2 de Bruijn cycle that exercises every glyph and every adjacent kerning pair. Matching the capture establishes:

| Property | Value |
|---|---|
| Font | DejaVu Sans 2.37, 32 px |
| Origin | `(0, 2)` |
| Renderer | Pillow / FreeType |
| Channel model | `R(x) = G(x-1)`, `B(x) = G(x+1)` |

**Step 5 — beam search.** The 728×56 target is an 8×8-block mosaic. Each target block is the arithmetic mean of one 8×8 source block in gamma-encoded channel space. Beam-search the calibration alphabet, render candidate prefixes through the calibrated model, score their block averages against the target, keep the 16 lowest-error, extend. Final full-image MSE is `0.225977` — the recovered text is `zdk{D3Ad_L3tTeRs_5pE4k_afTer_THE_wAke}` ("Dead letters speak after the wake" in leetspeak).

**Takeaway:** the word *losslessly* in the PDF is not decoration — a screenshot / render / resize / JPEG would change the per-block values used later. The exact-renderer calibration lets you invert the mosaic without OCR, which is essential because each glyph has been reduced to a few coloured blocks and capitalisation is significant.

---

## Ghost in the GPU — entropy carving in a scrubbed VRAM dump

> *Flag:* `zdk{MemOrY_1Eak_found}`
>
> *Prompt:* "The inference job crashed and left behind a raw VRAM dump. The accelerator was scrubbed, but the memory capture survived."

`vram_dump.bin` is a 32 MiB raw VRAM capture. No signature, no strings, and 488 of its 512 64 KiB blocks sit at Shannon entropy ~8.0 bits/byte (indistinguishable from random). Signature-based tools return chance hits scattered uniformly through the file.

The brief reframes the problem: the accelerator was *scrubbed* but the capture *survived*, so don't look for a known format — look for **whatever is not noise.**

**Entropy localisation:**

```console
vram_dump.bin: 33,554,432 bytes
  entropy: 488/512 blocks of 64 KiB at >= 7.6 bits/byte (scrubbed noise)
  survivor: 0x00900000 - 0x00a80000  (1,572,864 bytes)
```

488 of 512 blocks are noise; the remaining 24 form one contiguous, page-aligned 1.5 MiB run. Re-running at 4 KiB granularity gives identical boundaries — one clean allocation, not a smeared remnant.

**Identify the encoding.** The region's byte histogram has only three entries:

```text
0x00 -> 786,432    (50.00%)
0x3c -> 778,683
0xbc ->   7,749

first bytes:  00 3c 00 3c 00 3c 00 3c 00 3c 00 3c ...
```

A strictly alternating `00 XX` pattern with a two-valued high byte is a 16-bit type. Read little-endian:

- `0x3C00` — IEEE-754 binary16 `+1.0` (778,683 halfwords)
- `0xBC00` — IEEE-754 binary16 `-1.0` (7,749 halfwords)

Textbook fp16 `±1.0`. The buffer is a half-precision **mask tensor** with 0.99% sparsity — consistent with the "inference job" framing.

**Reshape.** `786,432 = 1024 × 768` is the only candidate width that renders as coherent horizontal text (also the only standard display resolution). Mapping `+1.0` → black and `-1.0` → white gives a 1024×768 frame carrying the same line of text six times (two columns × three rows).

**Recover glyphs mechanically.** The font is a small bitmap upscaled non-uniformly (10/7 stretch); each 10- or 11-row band collapses to 7 distinct scanlines. Recovering the base grid per copy (the two copies sit at *different sub-pixel phases* — a global duplicate-row search finds nothing) yields clean 5×7 glyphs. All 6 copies collapse to one identical bitmap (verified independently).

**Takeaway:** when signature carving finds nothing, invert the question. An entropy profile located the survivor in one pass. A byte histogram identifies numeric types (three values with exactly 50 % zeros ⇒ 16-bit; `0x3C00`/`0xBC00` ⇒ fp16 `±1.0` on sight). De-scale per instance rather than globally when copies sit at different sub-pixel phases.

---

## Hydra FC — a source map leaks the vulnerable gateway function

> *Flag:* `zdk{Mess1_0R_RONa1d0}`
>
> *Prompt:* "Hydra FC scored at 90+13 after the Floating Stadium tracking network desynchronized… Recover what the analytics gateway accepted beneath the waves."

`hydra_uplink.pcapng` captures four ball-tracking cameras (**CAM-NORTH / SOUTH / EAST / WEST**) streaming **msgpack** telemetry over WebSocket to an analytics gateway. Ten HTTP frames set the scene; 3,942 WebSocket frames are the payload. Four WebSocket upgrades plus one asset fetch: `GET /assets/replay.js.map → 200 application/json`.

**The source map is the whole exploit.** Its `sourcesContent` contains the client `telemetry.js`, including the vulnerable comparator with its own `FIXME`:

```js
// Gateway v3.1: sequence is uint16. FIXME: make rollover-aware.
export function shouldReplace(current, incoming) {
  return current === undefined || incoming.seq > current.seq;   // naive
}
```

Each 40 ms bucket keeps the frame with the highest 16-bit `seq`, compared as a plain integer. A sender that wraps `seq` past 65535 — or simply parks it near the ceiling — overrides legitimate frames in the same time bucket.

**The anomaly.** Per-stream stats immediately flag the odd one out:

```text
CAM-NORTH  frames= 900  seq[min=12000 max=12899]   conf==1.0 frames=0
CAM-SOUTH  frames= 900  seq[min=28000 max=28899]   conf==1.0 frames=0
CAM-EAST   frames=1226  seq[min=    0 max=65535]   conf==1.0 frames=326   <-- anomaly
CAM-WEST   frames= 900  seq[min=43000 max=43899]   conf==1.0 frames=0
```

CAM-EAST has 326 extra frames spanning the entire uint16 range. In buckets where CAM-EAST sent two frames:

```text
bucket=154502 seq=    0 conf=0.970 ball=(-3.03,-10.84) grid=(11,16)  <- real
bucket=154502 seq=65400 conf=1.000 ball=(-52.50, 34.00) grid=( 0, 0) <- injected
```

Every injected frame is unmistakable: `confidence == 1.0` exactly, `seq` near the uint16 ceiling, and `BALL` parked on an exact grid-cell centre. The clean selector is **CAM-EAST frames with `confidence == 1.0`**.

**Plot.** 326 injected modules paint onto the code's own 25×25 grid — QR version 2, with the three finder patterns, timing rows, and alignment pattern all intact. A raw scan fails because the code is drawn **mirrored**; brute-forcing all eight orientations, `zbarimg` locks on: `zdk{Mess1_0R_RONa1d0}` — Messi or Ronaldo, a fitting football pun for the "90+13" stoppage-time desync.

**Takeaway:** read the source map. Shipping `.map` files hands an attacker the exact protocol, field names, and here the vulnerable function with its own `FIXME` documenting the bug. Anomalies live in the metadata — frame counts, seq ranges, and a suspiciously perfect `confidence == 1.0` isolate the malicious stream before any pixel is plotted. A structurally perfect QR that refuses to scan is usually mirrored or rotated; brute-force the eight orientations before suspecting the data.

---

## layer-eight — OCI whiteouts still remember secrets

> *Flag:* `zdk{whltEOUt_1AyErs_5TlL1_r3MeMBer_SECrETs}`
>
> *Prompt:* "can someone please tell me what happened to the oceanographic beacon? … i think it might have been trying to tell us something"

The "garbled last transmission" is `app-image.tar`, an OCI image (`nimbusnotes:1.4.2`). The challenge name is the whole hint: layer 8 is the layer that *deletes* the build secrets, and the flag explicitly states the lesson.

**Build history.** The config blob has two decisive entries:

```text
LAYER 4  install -m600 /run/secrets/deploy_key /app/.secrets/deploy_key
LAYER 8  rm -f /app/.secrets/deploy_key /app/scripts/postinstall.sh /usr/lib/nimbus/provenance.py
```

Plus four provenance labels:

```text
com.nimbusnotes.provenance.layout = c,a,b
com.nimbusnotes.provenance.part-a = dZ4Ranut8tzxp+B9+sZ7H+8XGSdtBFAK
com.nimbusnotes.provenance.part-b = XcH39DQsNt67UAbE90W4KrXkQc0DyVT8
com.nimbusnotes.provenance.part-c = AU5pbWJ1c05vdGVzIUHvlVyex5o1USWI
com.nimbusnotes.provenance.step   = sha256:25df7c6f...642383d8
```

**Why "deleted" isn't deleted.** Container layers are stacked diffs. Removing a file writes a **whiteout** (`.wh.<file>`) in the newer layer; the bytes remain in the older layer. Layer 8's `.wh.deploy_key`, `.wh.postinstall.sh`, and `.wh.provenance.py` only *mark* the files gone. Carve them back from layers 4 and 6.

**The recovered scheme.** The carved `provenance.py` spells out the key management:

```python
key_bytes = open('/app/.secrets/deploy_key','rb').read()
step = os.environ['NIMBUS_STEP_DIGEST']
k = hashlib.sha256(key_bytes + bytes.fromhex(step.split(':',1)[1])).digest()
aad = ('nimbusnotes:1.4.2|' + step).encode()
# envelope v1: version || nonce[12] || ciphertext || tag[16]
```

Everything is recoverable — `key_bytes` is the carved 139-byte deploy key, `step` is the public `provenance.step` label, and the base64-encoded envelope is `part-c || part-a || part-b` per the `layout` label.

**Decrypt.** Concatenate the three 32-char base64 shards in `c,a,b` order and decode to a 72-byte envelope (`version(1) || nonce(12) || ciphertext(43) || tag(16)`). Derive `key = sha256(deploy_key_bytes || step_hex)`, set `aad = "nimbusnotes:1.4.2|sha256:25df7c6f..."`, and AES-256-GCM decrypt. **The GCM tag verifies** — which authenticates every recovered input in one step — and the plaintext is the flag.

**Takeaway:** whiteouts are not shredders. `docker history`, a raw `tar`, or `dive` expose every "deleted" file; layer removal is metadata, not erasure. Treat the image config as evidence: history lines and labels reconstruct the build, name the secret, and here handed over the entire decryption recipe. A verifying GCM tag is proof you got everything right (secret, step, AAD, shard order all confirmed at once).

---

## 99.8% — qbcn container inside a torrent partfile

> *Flag:* `zdk{Q8IT_hI6H_g0a7ED}`
>
> *Prompt:* "so my torrent stopped downloading randomly…idk why my claude couldn't help, could yours?"

The handout is a captured qBittorrent session for an interrupted download of `ubuntu_docs_backup_2025.iso` (stopped at "99.8%"). The evidence tree is deliberately salted with **five plaintext decoy flags** — every one tagged `pH4K3_*` or `d3c0Y_*`. `grep -r 'zdk{'` returns:

| Token | Tell |
|---|---|
| `zdk{pH4K3_crc_fix}` | **pH4K3** = "fake" |
| `zdk{d3c0Y_malf_toc}` | **d3c0Y** = "decoy" |
| `zdk{d3c0Y_tracker_noise}` | **d3c0Y** = "decoy" |

*"idk why my claude couldn't help"* is the taunt: an assistant that just `grep`s for `zdk{` hands back a decoy.

**The qbcn scheme.** Three log/temp files spell it out across three separate files:

```text
memory/carved_strings.txt : qbcn_kdf = sha256(domain || piece_window || piece_length_word)
fragments/media_index.tmp : qbcn_piece_window = pieces[0:16] ; piece_length_word = uint32le
session/logs/disk_io.log  : keycheck = sha256(key)[0:8]
                            stream_block[n] = sha256(key || uint32le(n))
```

- `piece_length_word` = `uint32le(131072)` = `00 00 02 00`.
- `piece_window` = first 16 SHA-1 piece hashes from the `.torrent` (320 bytes).
- `domain` is in the memory dump, spelled out plainly at the end:

```text
QKDF_TRACE_BEGIN
domain_ascii=ninety-eight/qbcn/v1
domain_terminator=00
```

**Derive and verify.**

```python
domain = b"ninety-eight/qbcn/v1\x00"
key = hashlib.sha256(domain + piece_window + plw).digest()
# d2515578cf57736215ed384a7f75ee07e34fc38378be4fd454c9d52cffa40e68
keycheck = hashlib.sha256(key).digest()[:8]  # 32de14e7f9606b68
```

**Find the container.** The `.!qB` partfile's final partial piece (offset `16 × 131072 = 2097152`) has an `HREG` header:

```text
4852 4547 0200 3d00 32de 14e7 f960 6b68 …
H R E G  ver  len  <keycheck 32de14e7f9606b68>
```

The stored `keycheck` **exactly matches** the derived one — the key is right, and the flag lives in this `HREG` container, not in piece 5 (which the `.fastresume` conspicuously flags as unfinished).

**Decrypt.** XOR the 61-byte ciphertext with `sha256(key || uint32le(0)) || sha256(key || uint32le(1)) || …` and reveal a second container: `QBCN | ver=1 | flaglen=0x15=21 | flag`. The `QBCN` magic and the exact `flaglen == 21` are an unambiguous "correct decrypt" signal.

Leetspeak: `Q8IT` = QBIT, `hI6H` = HIGH, `g0a7ED` = GOATED.

**Takeaway:** decoys are labelled — the challenge itself tells you every fake is `pH4K3_` or `d3c0Y_`. Keying material is *split* across evidence classes on purpose (memory + torrent + logs); each supplies exactly one input. The `keycheck` field is the oracle that confirms every input is correct before you decrypt.

---

## Unrotated — seven-part incident-response chain across eight log classes

> *Flag:* `zdk{a_HuM4n_REaD5_7HE_W4ke_nO7_7h3_14Bel5}`
>
> *Prompt:* "the last transmission was a bit garbled… BUT I DUNNO"

The handout expands to ~8.9 MB and 16 evidence files across identity, application, governance, host journal, container image, network firewall CSV, and a physical patch-panel PNG. The service accepts exactly seven line-oriented answers over TLS.

**1. `depth-chart-archive`** — the credential that escaped rotation. `rotation_manifest.csv` shows three entries with blank `completed_utc`. Two are documented in `partner_registry.csv` (legitimate temporary exceptions with source, validity, user agent). The third has no partner authorisation and the review note *"owner reported connector retired."*

**2. `2026-06-11T09:26:41Z`** — the first confirmed stale-token session. `gateway/access.log` shows a session start from `198.51.100.73` (outside both approved partner CIDRs) with a browser UA (no registered relay agent) using the rotation manifest fingerprint `af6717eb72a9c4eeb79b`. `collaboration/audit.csv` independently records the same request as `session_start` with detail `integration token accepted`.

**3. `mara.venn`** — the persistence identity. The stale credential's principal (`svc-depth-archive`) performed two admin actions on 12 June: created principal `aa839c52-…` and added it to `platform-admins`. Resolving the UUID through `collaboration/directory.db` yields `mara.venn` (human, currently disabled).

**4. `CHG-2147`** — the misused change record. Both persistence actions cited `change_ref=CHG-2147`. The governance ledger shows `CHG-2147` actually authorised `amina.rao` to promote `nora.alves` between 13:30 and 14:30. The legitimate sequence is visible at 13:43/13:51. Seventeen minutes later, `svc-depth-archive` repeats the pattern for `mara.venn` inside the approved window but with the *wrong actor and wrong subject*. This is misappropriation, not authorisation.

**5. `OR-7312`** — the delegated runner job. On 18 June `mara.venn` submits one runner job targeting `collab-app-01`. The systemd journal is compact-format (`strings` omits it); `journalctl --file=host/system.journal` recovers the chain: worker PID 24144 starts, then an outbound connection accepted from `proc-7ae13f0c35d8`.

**6. `BLUEFIN@203.0.113.86:8448`** — the rendezvous. Three destinations touched by that process ref in ten minutes: `203.0.113.18:443` (allowed, `partner-egress` — Tethys Forecast cover), `203.0.113.86:8448` (allowed, `legacy-general-egress` — not on approved list), `10.43.18.61:22` (denied). The operation name requires *three* representations of the same route:

- `runner-cache.oci.tar` has six cache manifests; each has an OCI whiteout `.wh.route.json` hiding a lower-layer `route.json`. The survey route's `screen_ref = watch-64a7a9d8bbd9`.
- `host/watch-console.cast` is an asciinema recording that looks garbled because characters are emitted individually via ANSI `ESC[row;columnH` absolute-cursor commands. Replaying into a 120×24 buffer recovers the row `watch-64a7a9d8bbd9  starboard-3  pel-8  LEAD-E  cached`.
- The patch-panel PNG traces `LEAD-E` through the amber line to `SOCKET-6`. The CSV socket legend gives `SOCKET-6,BLUEFIN`.

**7. `console-cpt-03`** — the follow-on hostname. The denied SSH attempt to `10.43.18.61` resolves through `network/host_inventory.csv` to a non-production `network-lab` console (the shared process ref prevents confusion with recurring backup probes to other lab consoles).

Submit the seven values line-oriented over TLS; the service returns the flag. The flag body — *"a human reads the wake, not the labels"* — is the entire methodological lesson: `CHG-2147` is a label the attacker attached, `legacy-general-egress` is a label the firewall attached, `.wh.route.json` is a label OCI attached. In every case the answer is behind the label, not the label itself.

**Takeaway:** no single log proves the whole incident — credential fingerprint, UUID, session ID, change ref, job ID, process ref, screen ref, patch lead, and socket number form the complete chain. When a change ref appears in a suspicious action, verify actor, action, and subject against the governance ledger — not just the timestamp window. OCI cache "cleanup" via whiteouts leaves historical bytes intact; a compact journal needs `journalctl` (not `strings`); an asciinema cast with absolute-cursor updates needs a buffer replay.

---

## Cross-cutting lessons from the z0d1akCTF 2026 Qualifiers Forensics set

Eight challenges, eight different substrates, one repeated discipline. **Read the wake, not the labels:**

- **Physical reordering is losslessly reversible when the artifact is self-describing.** Black Box's out-of-order flag fragments each carry their own sequence number. Any container that pairs data with metadata about that data can be sorted post-mortem.
- **Checkpoints are afterimages.** Dead Current's flag literally names it. CRIU / VM snapshots / core dumps capture *everything* — deleted files, freed heap pages, secrets that a process "zeroised" a moment later. Treat migration images as sensitive as live process memory.
- **Encrypted wire content survives at intermediaries.** Dead Letter Wake's part 4 crossed TLS and Postfix retained it as a deferred queue item. Any store-and-forward hop in the delivery chain is a copy that outlasts wire secrecy.
- **When signature carving finds nothing, invert the question.** Ghost in the GPU had no header to find; the payload was identifiable purely as *the part that is not random*. An entropy profile located it in one pass.
- **A byte histogram identifies numeric types.** Three distinct byte values with exactly 50 % zeros is a 16-bit type; `0x3C00`/`0xBC00` is fp16 `±1.0` on sight. This is a triage move worth memorising.
- **Read the source map.** Hydra FC's gateway shipped `.map` files that documented the vulnerable function verbatim, complete with its own `FIXME`. Any build that ships production source maps hands over the protocol, field names, and often the bug.
- **Whiteouts are not shredders.** layer-eight's flag is the whole lesson. OCI whiteouts / undelete markers / journal tombstones are metadata, not erasure — the underlying bytes remain until physical reclamation.
- **A verifying MAC / GCM tag is a correctness oracle for every recovered input at once.** layer-eight's GCM tag authenticates the secret, step digest, AAD string, and shard order simultaneously. 99.8%'s `keycheck` authenticates the derived key before you decrypt. Design solvers around these oracles — they eliminate "does this decode look right?" guessing.
- **Split key material is a challenge shape.** 99.8% scatters `domain` (memory) + `piece_window` (`.torrent`) + `piece_length_word` (constant) across three evidence classes. Each class supplies exactly one input; the container header confirms you've assembled them correctly.
- **Decoys are labelled by their authors.** `pH4K3_` and `d3c0Y_` are the loudest tells you will ever get. Any `zdk{}` string is a candidate, but a plaintext one is almost always bait.
- **Cross-layer correlation is essential in incident response.** Unrotated proves it — no single log settled the case, but nine correlated identifiers (fingerprint / UUID / session / change / job / process / screen / lead / socket) formed the complete chain of custody.
- **Trust the substrate the challenge documents.** Every Forensics challenge in this set contains its own instructions — `PORT.md` for genie's sibling in the Misc track, the PDF's "extract losslessly" for Dead Letter Wake, the `provenance.py` for layer-eight, the source map for Hydra FC, the qbcn trace for 99.8%. Read the docs the challenge ships with — they are attack surface.

## Reproduce it yourself

Each challenge ships a standalone solver in the [z0d1akCTF 2026 Qualifiers repository](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers) under `Forensics/<challenge>/`:

- [`Forensics/black-box/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Forensics/black-box) — pure-stdlib big-endian record parser, checksum verifier, XOR decoder; ships the 3,920-byte handout.
- [`Forensics/dead-current/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Forensics/dead-current) — CRIU image parser, `.gopclntab` symbol recovery, ghost-file carver, `pages-2.img` master-secret locator, SHA-256 KDF + XOR keystream.
- [`Forensics/dead-letter-wake/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Forensics/dead-letter-wake) — TShark-driven SMTP reassembly, MIME `message/partial` combiner, `pdfimages` extraction, DejaVu-Sans PIX-8 beam search; ships a Docker environment for reproducible fonts.
- [`Forensics/ghost-in-the-gpu/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Forensics/ghost-in-the-gpu) — pure-stdlib entropy scan, fp16 validator, tensor reshape, per-copy de-scaling, 5×7 glyph recovery; minimal stdlib-only PNG writer.
- [`Forensics/hydra-fc/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Forensics/hydra-fc) — pure-stdlib msgpack decoder, WebSocket unmask, sync-offset aligner, `confidence == 1.0` filter, 25×25 grid painter; needs `tshark` and `zbarimg`.
- [`Forensics/layer-eight/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Forensics/layer-eight) — OCI image parser, whiteout carver, label-shard assembler, pure-python AES-256-GCM (`aesgcm.py`, NIST-validated); ships the image tarball.
- [`Forensics/ninety-eight/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Forensics/ninety-eight) — bencode parser, memory-dump `domain` extractor, key derivation, `keycheck` verifier, HREG/QBCN container decrypter.
- [`Forensics/unrotated/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Forensics/unrotated) — ZIP / CSV / SQLite / OCI tar / asciinema cast / firewall correlator + optional TLS submission client; needs `journalctl` (or Docker with `archlinux:latest`).

All eight live solvers use only the Python standard library except Dead Letter Wake (Pillow + NumPy for the PIX-8 forward model, pinned via Docker).

Browse the full [CTF writeups](/ctf-writeups/) archive for more forensics and incident-response walkthroughs, or continue the z0d1akCTF 2026 Qualifiers series with the [Miscellaneous writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-misc-writeup/) covering genie, ihateDAA, Control Plane, and Sanity Check.

---

*This writeup is part of the CyberSecurity Elite [z0d1akCTF 2026 Qualifiers](/series/z0d1akctf-2026-qualifiers/) series. Handouts, per-challenge READMEs, and dependency-conscious solvers for all eight Forensics challenges are published at [github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers).*
