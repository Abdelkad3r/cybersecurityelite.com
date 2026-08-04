---
title: "Junior.Crypt 2026 Forensic + Misc + OSINT Writeup: 8 Solved"
slug: "junior-crypt-2026-forensic-misc-osint-writeup"
description: "Step-by-step Junior.Crypt 2026 forensic, misc, and OSINT writeup — two forensic challenges (Invoice Without a Bank: WinZip-AES phishing corpus filtered by the Portuguese Fatura Emitida subject template; Philologist: Cyrillic acrostic ГИТЛОГ hint pointing at git log first-byte SHA-1 abbreviations), four misc challenges (1000-7: MIDI pitch-wheel +2304/-2304 pair steganography over a Tokyo Ghoul theme; Ghost Layers: SVG glyph paths referenced only through clip-path so they never reach the raster; Invisible Editor: DOCX customXml/item1.xml carrying a fake revisionLog whose per-step inserted chunks replay the flag one character at a time; Pickles: model.pkl calling payload.install_supply_chain_probe with a LedgerModel.infer backdoor triggered by a four-word history hash), and two OSINT challenges (Fire Mural: Grodno fire watchtower mural by Vladimir Kachan; FOOTBALLchik: Neman vs ML Vitebsk broadcast clock timestamp of the first goal)."
date: 2026-07-15T14:20:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["Junior.Crypt 2026"]
tags:
  - "junior.crypt"
  - "junior.crypt 2026"
  - "grodno ctf"
  - "ctf writeup"
  - "forensic"
  - "misc"
  - "osint"
  - "phishing email analysis"
  - "eml mime attachment"
  - "winzip aes"
  - "git log covert channel"
  - "sha-1 prefix mining"
  - "acrostic cyrillic"
  - "midi steganography"
  - "pitch wheel encoding"
  - "svg clippath ghost text"
  - "docx customxml"
  - "revisionlog replay"
  - "pickle supply chain"
  - "payload pyc backdoor"
  - "yandex reverse image search"
  - "landmark osint grodno"
  - "broadcast clock osint"
keywords:
  - "junior.crypt 2026 forensic writeup"
  - "junior.crypt 2026 misc writeup"
  - "junior.crypt 2026 osint writeup"
  - "grodno ctf forensic writeup"
  - "invoice without a bank writeup"
  - "philologist writeup git log"
  - "1000-7 midi pitch wheel writeup"
  - "ghost layers svg clippath writeup"
  - "invisible editor docx writeup"
  - "pickles supply chain writeup"
  - "fire mural vladimir kachan writeup"
  - "footballchik neman vitebsk writeup"
  - "eml portuguese fatura emitida filter"
  - "cyrillic acrostic gitlog first byte sha1"
  - "midi pitch wheel bit encoding"
  - "svg clip-path never painted glyph"
  - "docx customxml revision log replay"
  - "pickle payload.pyc ledgermodel infer backdoor"
  - "grodno fire watchtower mural artist"
  - "belarusian betera higher league goal clock"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/junior-crypt-2026-forensic-misc-osint-writeup.png"
  alt: "Junior.Crypt 2026 forensic + misc + OSINT writeup — eight challenges solved covering a WinZip-AES phishing corpus filtered by the Portuguese Fatura Emitida subject template, a Cyrillic acrostic ГИТЛОГ hint pointing at git log first-byte SHA-1 abbreviations, MIDI pitch-wheel +2304/-2304 pair steganography over a Tokyo Ghoul theme, SVG glyph paths referenced only through clip-path so they never reach the raster, DOCX customXml/item1.xml carrying a fake revisionLog whose per-step inserted chunks replay the flag, model.pkl calling payload.install_supply_chain_probe with a LedgerModel.infer backdoor triggered by a four-word history hash, Grodno fire watchtower mural identification, and Belarusian Higher League broadcast clock reading"
---

Junior.Crypt 2026 (grodno flag prefix) rounded out its web, crypto, pwn, and reverse tracks with three softer categories; in this **CyberSecurity Elite** forensic, misc, and OSINT writeup we work through all eight, which are still surprisingly rich: forensic (two challenges), misc (four), and OSINT (two). None of them require heavy tooling: every solve in this writeup is either a stdlib Python script, a browser render of an extracted SVG fragment, an `unzip -l` size disparity, or a bilingual Yandex reverse-image query. What the eight challenges do share is a *pattern-recognition* discipline that a defender's eye can be trained on: password-protected malware zips (`Infected` password → live samples), first-byte-of-SHA-1 covert channels in `git log`, pitch-wheel event pairs as a MIDI bit channel, `clip-path` references that consume glyph geometry without painting it, `customXml/item1.xml` outweighing `document.xml` in a near-empty DOCX, `.pyc` shipped next to a `.pkl` that hands the loader RCE, and OSINT chains that lean on Russian-language search over English for post-Soviet targets.

This writeup pairs with the [Junior.Crypt 2026 web + crypto writeup](/ctf-writeups/junior-crypt-2026-web-crypto-writeup/) (Pulse newline injection, Wrodle JWT + coordinate flag, MeowMeow timestamp-seeded RSA, Neurotoxin Diagnostics offline Vaudenay, Still Alive Franklin-Reiter, Stream Calibration 20-bit LCG, Weighted Companion Cube many-time pad) and the [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/) (Clockwork Vault negative-index bug, House of Mirage session-to-sink UAF, Museum of Echoes reclassify-without-realloc heap OOB, Write The "Кодэ" modified-TCC-compiler VM). Handouts, per-challenge READMEs, and pure-stdlib Python solvers live at [Abdelkad3r/Junior.Crypt.2026-CTF](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF).

## The eight Junior.Crypt 2026 forensic + misc + OSINT challenges

| Challenge | Category | Bug class / primitive | Flag |
|---|---|---|---|
| Invoice Without a Bank | Forensic | WinZip-AES archive (password `Infected`) with 10 `.eml` phishing samples. Half impersonate a bank; only one matches the Portuguese subject template `Fatura Emitida - <id>`. Extract `Content-Disposition: filename=` PDF name and the subject suffix from `sample-717.eml`. | `grodno{Vl6s3kCIKaUvwaUAeY.pdf_6ZFYeMmltso}` |
| Philologist | Forensic | Six-line Cyrillic poem whose first-letter acrostic reads `ГИТЛОГ` = `git log`. Seven mined commits; first byte of every abbreviated SHA-1 lands in printable ASCII and spells `1o9f1a9` (leetspeak `logflag`). Everything in the working tree is a decoy (`red_herring_flag`, `clickbait_flag`, etc.). | `grodno{1o9f1a9}` |
| 1000-7 | Misc | Standard MIDI file with an *Unravel* / Tokyo Ghoul theme. Every note is bracketed by a `+2304, -2304` pitch-wheel pair (or the reverse). 752 pitch events = 376 pairs = 47 bytes; `(+, -)` = 1, `(-, +)` = 0, MSB-first ASCII carries the flag. | `grodno{U1tr@_m3g@_5up3r_Gul_M1d_SF_1000-7}` |
| Ghost Layers | Misc | SVG of a beaver with a mug. One `<g id="s17">` holds 39 glyph-shaped paths (FreeType-style negative y-scale transform); it is referenced only from a `<clipPath>`, so its fill/stroke never reach the raster. Extract `#s17`, paint it directly on a dark background, read the flag. | `grodno{9l0ry_t0_Al1v@r1@_9l0ry_t0_b33r}` |
| Invisible Editor | Misc | `.docx` visible body is a single sentence, but `customXml/item1.xml` is 44 KB in a package of otherwise-boilerplate parts. That file carries a fake `<revisionLog>` whose per-step `<inserted>` chunks reconstruct the flag one character at a time, then erode it back to the visible taunt. Replay the log; scan states for `grodno{...}`. | `grodno{F1@g_W@5_H3r3_0nc3}` |
| Pickles | Misc | `model.pkl` calls `payload.install_supply_chain_probe(cipher, weights, seal)` returning a `LedgerModel` whose `infer(text, history)` has a hidden branch. If `sha256("|".join(history[-4:])) == seal`, derive a blake2s CTR keystream from `weights + sequence + b"inference-cache"`, XOR-decrypt `cipher`. `_WORDS = (snow, candle, tangerine, clock)` → 256 candidate orderings. | `grodno{p@ckl$s_are_so_yUmmy}` |
| Fire Mural | OSINT | Photograph of a single-storey pink-stucco building in Grodno with a monumental arched mural spanning the historical eras of firefighting uniforms. Building = Пожарная каланча (Fire Watchtower), Замковая 19. Mural = *Огнеборцы — история и традиции мужества* by Владимир Качан. | `grodno{Vladimir_Kachan}` |
| FOOTBALLchik | OSINT | Grodno football photo, sponsors + kits + scoreboard identify Neman vs ML Vitebsk (Betera Higher League, 30 May 2026). Public match reports round to `37'`; the exact `MM:SS` needs frame-by-frame extraction from the official first-goal YouTube clip. Ball crosses the line at broadcast clock 36:28. | `grodno{36:28}` |

The eight challenges are held together by a single defensive theme: **payload lives in the part of the file the tool you're using does not render**. `unzip -l` sizes for a DOCX. Pitch-wheel events for a MIDI. `git log --oneline` for a repo. `<clipPath>` referents for an SVG. Not `sample-*.eml.subject` but the `Content-Disposition: filename=` sub-header for the phishing corpus. `customXml/item1.xml` for a Word document. `LedgerModel.infer` for a pickle. Broadcast clock frames for a public football match rounded to the minute. Every case is a "look one layer past the default view."

## Methodology — read the metadata, read the flag hint, then read the artefact

The Junior.Crypt 2026 forensic/misc/OSINT tracks reward a specific reading order.

**Read the prompt like a spec.** Every challenge in these three tracks names the technique explicitly, if you take the prompt as a literal instruction. *Invoice Without a Bank* tells you to filter on `Fatura Emitida`; only one message in the corpus uses that template. *Philologist* names the category (a philologist studies the *form* of a text) and hands you a six-line poem whose acrostic reads `ГИТЛОГ`. *Invisible Editor* explicitly says the flag can't be seen, i.e. it used to be there and was edited out; you're being told to reconstruct a prior state. *Ghost Layers* leads with "what stays visible is not always what matters most," which is a plain-language pointer at the SVG paint model. *1000-7*'s "some melodies leave something else behind" is the steg tell. *Pickles*'s prompt describes pickle-loading a model from an unofficial mirror, which is the entire CVE class. *Fire Mural* asks for the artist by name in Russian and points at a real Grodno landmark. *FOOTBALLchik*'s "end of spring" plus the flag format `MM:SS` narrows the search to a single Belarusian league fixture and tells you to consult a video, not a match report.

**File-size disparities are the first-order filter.** In a package of otherwise-boilerplate parts, one 44 KB file among ten 200-byte files is the payload. In a repo of eleven decoy-flag text files and one screenshot of an ASCII table, the seven-commit `git log` is the signal. In a MIDI file with a 20 KB body but a note-count that fits in 4 KB, the pitch-wheel event stream is where a bit-carrier hides.

**"Compiled Python next to a pickle" is a red flag by itself.** Any archive that ships a `.pyc` alongside a `.pkl` is telegraphing that the pickle imports the pyc. Static disassembly (`pickletools.dis`, `dis.dis(marshal.loads(...))`) reveals what will happen at load time without executing the file, and reveals author hints like the unused `_WORDS` tuple that the challenge uses as a wordlist.

**OSINT starts with EXIF and Yandex, then narrows by language.** Baseline for any image challenge is `exiftool artifact.jpg | grep -Ei 'gps|date|make|model|comment'`. If nothing lands, describe the picture in concrete terms (architecture era + uniform eras + emblem style + sponsor names) and query in the language the target is documented in. For post-Soviet landmarks, Yandex reverse image + Russian-language search returns 10× the useful hits of any English pipeline.

**Steganography = "two distinct symbols repeated N times."** The MIDI challenge has 752 pitch-wheel events, but only two distinct values (`+2304` and `-2304`), always in pairs. Two symbols in pairs is a binary carrier by construction; the only remaining question is which pair is the 1 and which is the 0. The SVG challenge has one `<clipPath>` + one `<mask>` + one `<filter>` in an otherwise vanilla document; one of each in an illustration is atypical, so their `url(#...)` referents are where the payload hides.

Per-challenge walkthroughs follow.

## Forensic track

### 1. Invoice Without a Bank

A password-protected zip of 10 phishing emails. The prompt narrows the target to a Portuguese banking template; only one message matches, and the two flag components are one MIME sub-header apart.

#### Step 1 — Open the AES-256 zip

`Infected` is the MalwareBazaar / VX-Underground / VirusTotal convention for a live-sample container. Stock `unzip` on macOS/Linux still cannot handle WinZip-AES:

```
$ unzip -P Infected "Invoice Without a Bank.protected.zip"
   skipping: public/emails/sample-1000.eml  need PK compat. v5.1 (can do v4.5)
   ...
```

`7z` handles AES-256 zips natively:

```
$ 7z x -pInfected "Invoice Without a Bank.protected.zip" -o./out
```

Ten `.eml` samples under `public/emails/`.

#### Step 2 — Enumerate subjects and attachments

A single shell pass with `grep -aiE` per header field prints a triage table across the corpus. The Portuguese banking theme shows up in five of the ten messages (Itaú, Banco do Brasil, `Fatura`, `IRPF`, `Notificacao`). The prompt anchors the query on a specific string:

```
$ grep -lE 'Fatura Emitida' public/emails/*.eml
public/emails/sample-717.eml
```

Exactly one hit. That's the target.

#### Step 3 — Dissect `sample-717.eml`

MIME layout:

```
[0] multipart/mixed
[1]  multipart/alternative
[2]   text/plain                 183 B
[3]   text/html                  560 B
[4] application/pdf              74 427 B   filename=Vl6s3kCIKaUvwaUAeY.pdf
```

Relevant headers:

```
From    : "Itaucard - Pague sua fatura | Cod. 2374614215181323" <watw96708@gmail.com>
Subject : Fatura Emitida - 6ZFYeMmltso
```

- Content-Disposition filename: `Vl6s3kCIKaUvwaUAeY.pdf`
- Subject suffix (after `Fatura Emitida - `): `6ZFYeMmltso`

Both look like base62 tokens (20 chars and 11 chars respectively), which is what spam kits generate to keep each recipient's copy unique and duck hash-based blocklists.

#### Step 4 — Assemble the flag

Slot into the `grodno{filename_subjectid}` template:

```
grodno{Vl6s3kCIKaUvwaUAeY.pdf_6ZFYeMmltso}
```

Everything past this point is optional reading value. The actual PDF is RC4-encrypted with the password `123` printed in the mail body (a common evasion trick: outer scanners see ciphertext, the human user performs the decryption), a single 566×800 JPEG (no OCR-able text), and a hidden `/URI` action pointing at a credential-harvesting Itaú-lookalike. `pdfinfo -upw 123` confirms the RC4 crypt; nothing else about the PDF changes the flag.

Per-challenge README + solver: [forensic/invoice-without-a-bank](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/forensic/invoice-without-a-bank).

The three defender takeaways from this challenge: (1) stock zip still can't do WinZip-AES-256, budget for `7z`/`pyzipper` in analysis pipelines; (2) `Fatura Emitida - <id>` is a template used by a specific Brazilian banking phishing cluster (Itaú/Bradesco/BB), so alerting on that exact string catches the entire family; (3) password-locked lure PDFs are a boundary-scanner bypass by design and the password is almost always in the same HTML body as the attachment.

### 2. Philologist

A git repo full of decoy flags with a Cyrillic poem in the prompt. The acrostic is the tool. The commit hashes are the payload.

#### Step 1 — Read the poem like a philologist

Read down the first Cyrillic letter of each line:

```
Г ероев детства мы не судим,
И  ведь не правы вовсе тут:
Т огдашних дней грехи забудем,
Л аскаясь тем, что те не врут.
О днажды павши в ноги к смуте,
Г раницы догмы нас сожрут.
```

`Г - И - Т - Л - О - Г` → transliterated `G I T L O G` → **`git log`**.

Every file in the working tree is a decoy: `red_herring_flag`, `clickbait_flag`, `not_real_flag`, `keep_looking_flag`, a fake SHA-256 checker with an unbounded preimage space, a base64 blob that decodes to `definitely_not_grodno{...}`, and an untracked screenshot of the Linux `ascii(7)` table. The screenshot is a cheat sheet: it reminds the reader that "hex → ASCII" is in play.

#### Step 2 — Read the first byte of every abbreviated hash

```
$ git log --reverse --oneline
31dbe94 part 0
6fdfa43 part 1
395b794 part 2
66bc2a3 part 3
3192d4c part 4
610f42d part 5
39a0f97 part 6
```

Two hex digits are one byte:

| commit  | prefix    | byte   | ASCII |
|---------|-----------|--------|-------|
| part 0  | `31dbe94` | `0x31` | `1`   |
| part 1  | `6fdfa43` | `0x6f` | `o`   |
| part 2  | `395b794` | `0x39` | `9`   |
| part 3  | `66bc2a3` | `0x66` | `f`   |
| part 4  | `3192d4c` | `0x31` | `1`   |
| part 5  | `610f42d` | `0x61` | `a`   |
| part 6  | `39a0f97` | `0x39` | `9`   |

Concatenation in commit order: `1o9f1a9`. Read as leetspeak: `logflag`. Flag: `grodno{1o9f1a9}`.

Every first-byte lands in printable ASCII (0x30–0x6f). The probability of seven random SHA-1 first-bytes all being printable ASCII is roughly `(95/256)^7 ≈ 4%`; the actual sub-range here is much tighter. This is a mined pattern, not a coincidence.

#### Step 3 — How the author mined the hashes

`git` lets the author set `GIT_AUTHOR_DATE` and `GIT_COMMITTER_DATE` to arbitrary values, so mining a specific one-byte SHA-1 prefix is a matter of retrying `git commit --amend` (or rebase) with different timestamps. Hit rate `1/256`, seven commits → ~1800 attempts on average. Nothing on a laptop. The commit timestamps in this repo are `22, 271, 289, 423, 457, 459, 936` seconds past a fixed epoch base, which is exactly the "close-but-not-evenly-spaced" fingerprint of a timestamp brute force.

Per-challenge README + solver: [forensic/philologist](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/forensic/philologist).

Two defensive lessons: (1) the abbreviated hash in `git log --oneline` is an *un-authenticated covert channel*; anyone with commit rights can encode small messages into the first N bytes of a chain of commits at roughly `256^N` cost per message; (2) files in a working tree can be regenerated arbitrarily, but the git history is content-addressed, so any audit of "what does this repo actually contain" must include the log, not just the tree.

## Misc track

### 3. 1000-7

A MIDI file whose audible content is the Tokyo Ghoul opening theme. The payload is inside a channel your ear cannot hear.

#### Step 1 — Look past the melody

```
$ file chal.mid
chal.mid: Standard MIDI data (format 1) using 2 tracks at 1/480

$ strings chal.mid | head
MThd
MTrk
Unravel - Tokyo Ghoul
MTrk
```

Nothing weird about size or type. `xxd chal.mid | head` shows the two track headers, a tempo meta, and then the event stream in track 2. No trailing bytes after the second `End of Track`.

#### Step 2 — Parse events with `mido`

Every note in track 2 is bracketed by a pair of pitch-wheel events:

```
pitchwheel channel=0 pitch=2304   time=1680
pitchwheel channel=0 pitch=-2304  time=0
note_on    channel=0 note=70 velocity=80  time=0
pitchwheel channel=0 pitch=2304   time=240
pitchwheel channel=0 pitch=-2304  time=0
note_off   channel=0 note=70 velocity=64  time=0
```

Two things are diagnostic: pitch is applied and *immediately* undone inside a single tick (inaudible), and the values are only ever `+2304` or `-2304`. Two symbols in pairs is the classic bit-carrier shape.

#### Step 3 — Bit-pack the pairs

```python
pitches = [m.pitch for t in mid.tracks for m in t if m.type == "pitchwheel"]
# 752 pitch events -> 376 pairs -> 47 bytes
pairs = list(zip(pitches[::2], pitches[1::2]))
# set(pairs) = {(2304, -2304), (-2304, 2304)}
```

Two mappings to try. MSB-first, `(+, -) = 1` yields:

```
b'\xc0\xde*grodno{U1tr@_m3g@_5up3r_Gul_M1d_SF_1000-7}\xc5\x11'
```

Middle is the flag; leading `\xc0\xde*` and trailing `\xc5\x11` are the setup and tail pairs that fall before/after any note (framing noise, not payload).

Flag: `grodno{U1tr@_m3g@_5up3r_Gul_M1d_SF_1000-7}`. Read as *"Ultra mega super Ghoul MIDI (Standard File) 1000-7"*, a wink at the Tokyo Ghoul track name.

Per-challenge README + solver: [misc/1000-7](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/misc/1000-7).

The generalisable pattern: any MIDI event whose value can carry N distinct settings and always fires in pairs is a bit channel. Pitch-wheel, controller-change values, aftertouch, sysex bytes, and velocity LSBs are all fair game. The audible song is a red herring for the *rhythm* of the hidden channel; the payload rides on events that cancel out inside one tick and the ear will never notice.

### 4. Ghost Layers

An SVG of a beaver holding a mug. The whole document renders normally in any browser. But one node's shape is referenced through `<clipPath>` and never gets painted.

#### Step 1 — Element census

```
$ grep -oE '<[a-zA-Z]+' beaver.svg | sort | uniq -c | sort -rn
    111 <path       103 <polyline   ...
      1 <clipPath   1 <mask   1 <filter   1 <use
```

Exactly one `<clipPath>`, one `<mask>`, one `<filter>`, one `<use>` in the whole document. A cartoon illustration doesn't need clip + mask + filter simultaneously; that combination almost always indicates an author hiding something. Grep the `url(#...)` referents.

#### Step 2 — Read the suspect defs

```xml
<g id="s17">
  <g transform="translate(62.500,454.000) scale(0.009400,-0.009400)"
     fill="#f8efc9" stroke="#f8efc9" stroke-width="36"
     stroke-linejoin="round">
    <path d="M803 578Q803 728 746 818Q689 909 596 909..."/>
    ... 38 more paths ...
  </g>
</g>

<clipPath id="cp4"><use href="#s17"/></clipPath>
```

Two immediate tells that `#s17` is text: it has 39 paths (not the count you'd draw water ripples with), the fill and stroke are the same cream colour (a font-hinting artefact where outline and fill agree), and the transform includes a *negative y-scale* (`-0.009400`). FreeType and PostScript-derived font engines emit that transform when they flip the em-square (y-up) into SVG space (y-down). No human hand-writes that. This is a rendered typeface.

#### Step 3 — Understand what SVG paints

The only reference to `#s17` in the entire document is from `<clipPath id="cp4">`. Inside `<g id="ghost-wash">`:

```xml
<g id="ghost-wash" opacity="0.72"
                   mask="url(#mk9)"
                   filter="url(#glowSoft)">
  <g clip-path="url(#cp4)">
    <rect x="52" y="400" width="473" height="84" fill="url(#ghostGrad)"/>
  </g>
</g>
```

`clip-path` uses the *shape* of its argument, not its paint. `#s17` is never actually drawn; the browser walks the paths to build an alpha stencil, then discards the fill/stroke. Then `mask="url(#mk9)"` further clips to water ripples, `filter="url(#glowSoft)"` blurs the result, and `opacity="0.72"` on `#1e4b59` water background makes the whole thing indistinguishable from the water.

But the *geometry* of `#s17` is fully specified in the document and easy to render directly.

#### Step 4 — Paint `#s17` yourself

Extract `<g id="s17">` (with balanced depth counting for nested `<g>`) and drop it into a minimal SVG with a dark background:

```python
open('s17-only.svg','w').write(
    '<?xml version="1.0"?>'
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'viewBox="0 0 577 635" width="1732" height="1905">'
    '<rect width="100%" height="100%" fill="#111"/>'
    f'{body}</svg>')
```

Rasterise:

```
$ rsvg-convert s17-only.svg -o s17-only.png
```

The glyphs land where `translate(62.5, 454)` puts them and the flag reads out cleanly.

Flag: `grodno{9l0ry_t0_Al1v@r1@_9l0ry_t0_b33r}`. Past the leetspeak: *"glory to Alivaria, glory to beer"*. Alivaria (Аліварыя) is Belarus's oldest brewery, founded 1864 in Minsk. The beaver holds a mug of it. The beaver was the misdirection; the beer toast was the ghost layer.

Per-challenge README + solver: [misc/ghost-layers](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/misc/ghost-layers).

The generalisable defender rule: SVG's `clip-path` is a shape-geometry primitive; anything referenced only as a `clip-path` target is content-addressable but unpainted. Chained with `mask` (luminance-driven alpha), `filter` (blur), and `opacity`, an author can drive the "reveal by naked eye" barrier arbitrarily high without ever touching CSS `display` or `visibility`. Any SVG with exactly one clipPath + one mask + one filter deserves a look at what those defs reference. The generalisable *attacker* rule is symmetric: dark UI regions (water, fog, film grain) are natural cover for ghost content since the eye is primed to filter them as noise.

### 5. Invisible Editor

A `.docx` whose visible body is one sentence. The 44 KB `customXml/item1.xml` is the payload.

#### Step 1 — `unzip -l` first

```
$ unzip -l invisible_editor.docx
      819  ...  [Content_Types].xml
      590  ...  _rels/.rels
     1442  ...  word/document.xml
      280  ...  word/_rels/document.xml.rels
      239  ...  word/settings.xml
      609  ...  docProps/core.xml
      760  ...  docProps/app.xml
    43879  ...  customXml/item1.xml         <-- ??
```

Every part is boilerplate-sized except `customXml/item1.xml` (44 KB) in a document whose visible body is 21 characters. That's the target.

#### Step 2 — Read `customXml/item1.xml`

The file is not Office customXml at all. It's a fake `<revisionLog>`:

```xml
<revisionLog>
  <initial>grodno</initial>
  <revision step="1" author="Invisible Editor" at="2026-02-19T10:01:00Z">
    <deleted>
      <chunk>gro</chunk><chunk>dn</chunk><chunk>o</chunk>
    </deleted>
    <inserted>
      <chunk>grod</chunk><chunk>no{</chunk>
    </inserted>
  </revision>
  ...
```

Two structural facts fall out after two revisions: the concatenation of `<deleted>` chunks always equals the current buffer (i.e. every revision rewrites the whole buffer), so the chunk boundaries are pure obfuscation; and each rewrite adds exactly one character to the buffer, so the flag is being *typed out one character per revision*.

#### Step 3 — Replay

```python
state  = re.search(r'<initial>([^<]*)</initial>', xml).group(1)
states = [state]
for _, deleted, inserted in re.findall(
    r'<revision step="(\d+)".*?<deleted>(.*?)</deleted>'
    r'<inserted>(.*?)</inserted></revision>', xml, re.S):
    assert ''.join(re.findall(r'<chunk>([^<]*)</chunk>', deleted)) == state
    state = ''.join(re.findall(r'<chunk>([^<]*)</chunk>', inserted))
    states.append(state)
for s in states:
    if re.fullmatch(r'grodno\{[^{}]+\}', s):
        print(s); break
```

Output:

```
[+] replayed 100 revisions
[+] final visible state : 'Did you see the flag?'
[+] flag found at step 20: grodno{F1@g_W@5_H3r3_0nc3}
```

Flag exists as the whole buffer for exactly one revision (step 20), then step 21 begins mutating it back into the innocuous taunt. Reads as *"Flag was here once"*, which is exactly what happened.

Per-challenge README + solver: [misc/invisible-editor](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/misc/invisible-editor).

The general pattern: any Office file (`.docx`, `.xlsx`, `.pptx`) is a zip full of XML parts, and `document.xml` is only the visible layer. `customXml/` was designed for third-party content-type schemas (SharePoint, form data, custom taxonomies); Word will carry whatever you put in there without rendering it. Comments, footnotes, `docProps/`, embedded objects, and revision metadata are all payload-friendly slots. `unzip -l` first, size disparity next.

### 6. Pickles

The classic pickle-RCE via a side-shipped `.pyc`, plus a magic-input backdoor in the `LedgerModel.infer` method. Solvable entirely offline.

#### Step 1 — Look at what "the model" actually is

```
$ file model.pkl payload.pyc
model.pkl:   data
payload.pyc: data
```

Any archive that ships a `.pkl` next to a `.pyc` is telegraphing that the pickle imports the pyc.

#### Step 2 — Disassemble the pickle without executing it

`pickletools.dis` walks the opcode stream without evaluation:

```
$ python3 -c "import pickletools; pickletools.dis(open('model.pkl','rb').read())"
   11: \x8c SHORT_BINUNICODE 'payload'
   21: \x8c SHORT_BINUNICODE 'install_supply_chain_probe'
   50: \x93 STACK_GLOBAL
   52: C    SHORT_BINBYTES b'\xbf\x1d...'   (28 bytes)   # cipher
   83: B    BINBYTES    b'\x1c\xeb...'      (1536 bytes) # weights
 1625: C    SHORT_BINBYTES b'\x0b8\x07\xaa...' (32 bytes) # seal
 1660: \x87 TUPLE3
 1662: R    REDUCE
```

One `REDUCE`, one call: `payload.install_supply_chain_probe(cipher, weights, seal)`. The 32-byte `seal` screams SHA-256; the 1536-byte `weights` is fake model data; the 28-byte `cipher` is the encrypted payload.

#### Step 3 — Disassemble `payload.pyc`

Header magic `6f 0d 0d 0a` = Python 3.10:

```
$ python3.10 -c "
import dis, marshal
data = open('payload.pyc','rb').read()
dis.dis(marshal.loads(data[16:]))"
```

The `LedgerModel.infer` method reconstructed from disassembly:

```python
def infer(self, text: str, history: list[str]) -> dict:
    score = (sum(text.encode()) + self.weights[0]) % 101
    sequence = b"|".join(x.encode() for x in history[-4:])
    if hashlib.sha256(sequence).digest() != self.seal:
        return {"score": score, "label": "invoice" if score > 50 else "receipt"}
    # backdoor branch
    key   = hashlib.blake2s(self.weights + sequence + b"inference-cache").digest()
    plain = bytes(a ^ b for a, b in zip(self.cipher, _stream(key, len(self.cipher))))
    return {"score": score, "label": "receipt",
            "ticket": base64.b85encode(plain).decode()}
```

Two stapled-together behaviours: the cover story (normal `score`/`label` output for any non-magic caller) and the backdoor branch that triggers when `sha256("|".join(history[-4:])) == seal`. Everything except `history` is server-side and deterministic.

Author hint: `_WORDS = (b"snow", b"candle", b"tangerine", b"clock")` is defined at module scope and referenced nowhere in the disassembly. Four English nouns; four history slots; that's a wordlist.

#### Step 4 — Recover arguments without executing the pickle

Stub `payload` before the pickle loads:

```python
captured = {}
def stub(cipher, weights, seal):
    captured.update(cipher=cipher, weights=weights, seal=seal)
sys.modules["payload"] = types.ModuleType("payload")
sys.modules["payload"].install_supply_chain_probe = stub

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "payload" and name == "install_supply_chain_probe":
            return stub
        raise pickle.UnpicklingError(f"blocked {module}.{name}")

SafeUnpickler(io.BytesIO(open("model.pkl","rb").read())).load()
```

#### Step 5 — Brute-force the 256-way trigger

```python
for combo in itertools.product(WORDS, repeat=4):
    if hashlib.sha256(b"|".join(combo)).digest() == captured["seal"]:
        print(combo); break
# (b'snow', b'candle', b'tangerine', b'clock')
```

Author was polite; the words come out in tuple order. A real attacker would shuffle.

#### Step 6 — Decrypt

```python
key    = hashlib.blake2s(weights + sequence + b"inference-cache").digest()
stream = b"".join(
    hashlib.blake2s(key + i.to_bytes(2, "little")).digest()
    for i in range((len(cipher) + 31) // 32)
)[:len(cipher)]
plain  = bytes(a ^ b for a, b in zip(cipher, stream))
# b'grodno{p@ckl$s_are_so_yUmmy}'
```

The same trigger drives the live `POST /infer` endpoint, but the offline path is authoritative; everything needed to open the backdoor is already inside `model.pkl`.

Flag: `grodno{p@ckl$s_are_so_yUmmy}`.

Per-challenge README + solver: [misc/pickles](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/misc/pickles).

The two defender lessons compound: (1) pickle is a code-execution format, not a serialisation format, so any `pickle.load()` on an attacker-influenced file is RCE, and `torch.load`, `joblib.load`, `dill.load` are all pickle under the hood; use safetensors, ONNX, or another code-free format when you didn't build the artefact yourself. (2) ML supply-chain backdoors don't have to be adversarial examples in weight space; sometimes the "adversarial example" is literally a Python function shipped in the same archive that decrypts a payload only when the runtime input matches a KDF trigger. Threat-model the loader, not just the model.

## OSINT track

### 7. Fire Mural

An image of a mural on a real Grodno building; identify the artist.

#### Step 1 — Baseline EXIF check

```
$ exiftool artifact.jpg | grep -Ei 'gps|make|model|date|comment'
(nothing useful)
```

No GPS, no camera, no XMP. We're solving from pixels only.

#### Step 2 — Describe the picture concretely

A single-storey pink-stucco building, arched pediment above the entrance, adjacent old red-brick structure, wide monumental mural spanning firefighter uniforms across historical eras: a tsarist brass-helmet fireman at the left, Russian Imperial officer, Soviet military and militia uniforms, and modern Belarusian МЧС rescue uniforms at the right. Centrepiece is the МЧС shield emblem. Red plaque with a coat of arms and gold lettering under the mural (Belarusian state-institution signage style).

Target: a Grodno building tied to the fire service / МЧС with an arched-pediment mural showing the history of firefighting. Extremely specific.

#### Step 3 — Landmark ID

This is the **Пожарная каланча** (Fire Watchtower) on **улица Замковая, 19** in Grodno, built 1902, now hosting the МЧС museum. The famous tourist detail: the mural on the pediment includes a Mona Lisa easter egg (one of the МЧС rescuers on the far right is painted with Gioconda's face). Locally nicknamed *"the Mona Lisa of Grodno"*.

If you don't recognise the building on sight, either Yandex reverse image search or a text query in Russian (`Гродно арочная роспись пожарные история фасад`) surfaces it in one hop. Yandex is dramatically stronger than Google for post-Soviet targets.

#### Step 4 — Find the artist

```
Гродно пожарная каланча роспись фасад художник
```

Multiple independent sources (Lenin district administration `grodnolen.gov.by`, the МЧС museum page on `mchs.gov.by`, local travel blogs `poshyk.info` / `grodno.in` / `planetabelarus.by`) agree:

> Фронтон старейшей пожарной части города украшен монументальной росписью *«Огнеборцы — история и традиции мужества»*, выполненной гродненским художником **Владимиром Качаном**.

Painter: **Владимир Качан** / *Vladimir Kachan*. The Mona Lisa detail is Kachan's signature on the piece and independently verifies the attribution.

Flag: `grodno{Vladimir_Kachan}`. Fallbacks if the checker is Cyrillic-strict: `grodno{Владимир_Качан}`; Belarusian transliteration `grodno{Uladzimir_Kachan}` / `grodno{Уладзімір_Качан}`.

Per-challenge README: [osint/fire-mural](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/osint/fire-mural).

OSINT lesson: always start with `exiftool`; sometimes the challenge is one command. For any post-Soviet landmark, describe the picture in concrete visual terms first (architecture era, uniforms, emblem style, sponsor style); that description *is* the query. Yandex reverse image search over the local language beats an English pipeline by an order of magnitude for anything east of the Neman.

### 8. FOOTBALLchik

A stadium photo of a Belarusian league match. The flag needs `MM:SS` precision, which means video, not match reports.

#### Step 1 — EXIF check first

```
$ exiftool artifact.jpg | grep -Ei 'gps|date|make|model|comment'
(nothing useful)
```

No metadata. Read the image.

#### Step 2 — Extract clues (sponsors + kits + scoreboard)

The photo shows:

- Scoreboard `0:0`, stadium clock ~`17:06`.
- Yellow/green kits vs black kits.
- Sponsor boards `FONBET`, `БЕЛКАРД`, `Гродно Азот`.
- Betera Higher League scoreboard aesthetic.

Sponsor boards in the raw photo are mirrored (the camera side of a stadium has the ads flipped as seen from the field-side). `magick artifact.jpg -flop flipped.jpg` unflips them:

- `Гродно Азот` is a Grodno industrial sponsor → venue is Neman / Grodno's home stadium.
- Team on scoreboard `Неман`, opponent abbreviation `МЛВ` = `МЛ Витебск`.

Match: **Неман — МЛ Витебск**.

#### Step 3 — Date the match

Prompt says "at the end of spring." The relevant Betera Higher League fixture:

```
Неман — МЛ Витебск
30 May 2026
Grodno
Final: 1:2
```

Public reports (ABFF, FC Neman) give the goal list:

```
1:0 — Сергей Пушняков, 37'
1:1 — Абдуллахи Оде, 64'
1:2 — Владислав Жук, 90+3'
```

`37'` is minute-rounded; a goal at `36:28` is reported as `37'`. Flag wants `MM:SS`; report precision isn't enough.

#### Step 4 — Read the broadcast clock

Official first-goal clip:

```
https://www.youtube.com/watch?v=ks3idqApraw
Title: 1:0 — Пушняков, Неман — МЛ Витебск, BETERA-Высшая лига
```

Download video-only, extract frames at 5 fps around the goal:

```
$ yt-dlp -f 398 -o 'goalclip.%(ext)s' \
    'https://www.youtube.com/watch?v=ks3idqApraw'
$ ffmpeg -i goalclip.mp4 -vf fps=5 goalclip_frames/f_%04d.jpg
```

Frame reading:

- `36:27`: ball in the goalmouth scramble.
- `36:28`: ball visibly over the line.
- `36:29`: broadcast score bug updates from `0:0` to `1:0`.

Broadcast clock at cross-line: `36:28`. Sanity check: `36:28` belongs to the 37th minute → matches the public `37'` report.

Flag: `grodno{36:28}`.

Per-challenge README: [osint/footballchik](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF/tree/main/osint/footballchik).

OSINT lesson: mirrored text in stadium photos is still text; flip before OCRing sponsor boards. Public match reports round to the minute (`N'`), so any challenge asking for `MM:SS` is telling you to consult the official broadcast video, not a report. A goal reported at the 37th minute has an `MM:SS` timestamp in the range `36:00`–`36:59`.

## Cross-cutting defender notes

Six patterns recur across the Junior.Crypt 2026 forensic / misc / OSINT tracks and translate directly into review or triage heuristics.

**Pickle is a code-execution format, always.** `pickle.load`, `torch.load`, `joblib.load`, `dill.load`, and every "ML model loader" that isn't safetensors/ONNX/GGUF is a pickle under the hood. Any archive shipping `.pyc` next to `.pkl` is telegraphing that the pickle imports the pyc, and the pyc is trivially decompilable with `dis` + `marshal`. Threat-model the loader itself, not just the "weights". Static analysis of pickles is cheap: `pickletools.dis` walks opcodes without evaluation. If the disassembly calls a symbol you did not put there, treat the archive as hostile and stop.

**Office files are zips; `document.xml` is the visible layer only.** `unzip -l` any `.docx` / `.xlsx` / `.pptx` first. Anything sized well past what a near-empty document should carry is where the payload lives. `customXml/` was designed for third-party schemas and will carry arbitrary XML that Word never renders. Other payload-friendly slots: comments (`word/comments.xml`), footnotes/endnotes, headers/footers, `docProps/`, embedded objects (`word/embeddings/`), and revision metadata. When the visible surface says "no flag here," the ZIP structure is the second-order surface.

**SVG's paint model has multiple ways to reference geometry without rendering it.** `clip-path` uses shape only (fill/stroke ignored). `mask` uses luminance. `<defs>` alone doesn't paint anything. `visibility: hidden` and `display: none` both hide content but leave it queryable. A `<use href="#s17"/>` inside a `<clipPath>` is content-addressable but unpainted. Chained with `mask` + `filter` + `opacity`, an author can lower the "reveal by naked eye" barrier arbitrarily. Element census (`grep -oE '<[a-zA-Z]+'`) is a fast triage: any SVG with exactly one clipPath + one mask + one filter combined is doing something atypical and worth grepping the `url(#...)` references for.

**Git's abbreviated hash is a covert channel.** `git log --oneline` prints a hex stream one byte per two chars. Mining a one-byte prefix costs ~256 attempts (via `GIT_AUTHOR_DATE` / `GIT_COMMITTER_DATE`); an N-byte message costs ~256N. The trick shows up in real-world git vanity commits (`0000000` corporate signatures), torrent info-hash vanities, TLS session-id vanities, and Bitcoin vanity addresses (same class, harder search). Any repo where every commit's abbreviated hash lands in printable ASCII deserves an ASCII-decode of the log.

**MIDI event streams and other "audible" formats have inaudible channels.** Pitch-wheel, controller-change values, aftertouch, sysex bytes, and velocity LSBs are all invisible to the ear but visible to `mido`. The audible song is a decoy for the *rhythm* of the hidden channel; the payload rides on events that fire in pairs inside one tick, so the ear never notices. Same pattern applies to `.flac`/`.wav` LSBs, PNG alpha channels, PDF `/Info` metadata, and pretty much any container designed for a specific sensory bandwidth.

**Password-protected malware zips + password-locked lure PDFs are boundary-scanner bypasses by design.** `Infected` on a zip is the MalwareBazaar convention for live samples; treat everything inside as hostile. Stock `unzip` still can't do WinZip-AES-256; budget for `7z` / `pyzipper` / `python-libarchive`. Password-locked lure PDFs are a two-stage evasion: the mail server sees encrypted PDF, so signature scanners whiff; the mail body prints the password so the human user performs the decryption locally. When triaging a mail with an "encrypted invoice" attachment, always render the mail body first; the password is usually one `<strong>` tag away.

**OSINT baseline: EXIF, then landmark ID by concrete visual description, then bilingual query.** For image challenges, always start with `exiftool | grep -Ei 'gps|date|make|model|comment'`; sometimes the challenge is one command. If nothing lands, describe the picture in concrete terms (architecture era + uniform eras + emblem style + sponsor names + mirrored-text unflipping) before jumping to search. Post-Soviet targets are documented much better in Russian than English; Yandex reverse image search plus a native-language query returns ~10× the useful hits of a Google-only pipeline. For time-precision challenges (broadcast clocks, satellite pass times, security-camera timestamps), the media source with the finest granularity wins; public match reports round to the minute, the video does not.

## Frequently asked questions

### What is Junior.Crypt 2026?

Junior.Crypt is a Belarusian junior-tier CTF (hosted in Grodno; flag prefix `grodno{...}`). The 2026 edition ran categories including crypto, forensic, misc, osint, pwn, reverse, and web. This writeup covers the two forensic challenges (Invoice Without a Bank, Philologist), four misc challenges (1000-7, Ghost Layers, Invisible Editor, Pickles), and two OSINT challenges (Fire Mural, FOOTBALLchik) I solved. The paired web + crypto writeup is at [Junior.Crypt 2026 web + crypto writeup](/ctf-writeups/junior-crypt-2026-web-crypto-writeup/), and the pwn + reverse writeup is at [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/). Per-challenge READMEs, handouts, and pure-stdlib Python solvers are mirrored at [Abdelkad3r/Junior.Crypt.2026-CTF](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF).

### Why does the Invoice Without a Bank challenge use the password `Infected` on the archive?

`Infected` is the MalwareBazaar / VirusTotal / VX-Underground / abuse.ch convention for a password-protected zip that carries a live malware sample or spam corpus. It's a machine-readable signal that whatever is inside should be treated as hostile: extract to a sandboxed directory, don't render attachments, don't visit URLs. In this challenge the ten `.eml` samples are all real phishing (Brazilian banking Trojan lures, IRS impersonation, crypto withdrawal spam, and one Amazon-lookalike using Unicode confusables in the sender domain). Stock `unzip` on Linux/macOS still can't decode WinZip-AES-256; the practical baseline for password-locked malware zips is `7z` or `pyzipper`.

### How do you narrow a 10-email phishing corpus to a single target?

The prompt anchors the query on `Fatura Emitida - <id>` (Portuguese for "Invoice Issued"). A single `grep -lE 'Fatura Emitida' *.eml` returns exactly one match (`sample-717.eml`). Half the corpus impersonates *some* bank, but only one uses that specific subject template. The lesson: read the prompt as a filter spec. Anchoring on the literal string the challenge author gives you is faster than any content-based heuristic.

### What does the Cyrillic acrostic in Philologist spell, and where does the flag actually live?

Reading down the first Cyrillic letter of each line of the six-line poem: `Г - И - Т - Л - О - Г` → transliterated `G I T L O G` → `git log`. That's the entire strategic instruction. Every file in the working tree is a decoy (11 fake flags: `red_herring_flag{...}`, `clickbait_flag{...}`, `keep_looking_flag{...}`, a fake SHA-256 checker, a base64 blob that decodes to `definitely_not_grodno{...}`, and so on). The actual flag is in the git log itself. The author mined the seven commits' abbreviated SHA-1 prefixes so the first byte of each lands in printable ASCII; concatenated in commit order, the bytes spell `1o9f1a9` (leetspeak for `logflag`). At ~1800 attempts per commit and 7 commits, mining is trivial on a laptop.

### How does the 1000-7 MIDI steganography encode bits?

Every note in track 2 is bracketed by a pair of pitch-wheel events, always either `(+2304, -2304)` or `(-2304, +2304)`. Both pairs cancel out inside a single tick, so they're inaudible. Two symbols in pairs is a binary carrier by construction. 752 pitch events → 376 pairs → 47 bytes. MSB-first, mapping `(+, -) = 1` and `(-, +) = 0`, decoding starts with 3 bytes of setup noise (`\xc0\xde*`), the flag proper (`grodno{U1tr@_m3g@_5up3r_Gul_M1d_SF_1000-7}`), and 2 bytes of tail noise (`\xc5\x11`). The Tokyo Ghoul melody is a red herring for the *rhythm* of the covert channel; the payload rides on events that never fire outside a single tick.

### How does Ghost Layers hide text inside an SVG the browser renders normally?

The SVG contains `<g id="s17">` with 39 glyph-shaped paths (giveaway: negative y-scale in the transform, matching fill and stroke colours; both are FreeType/PostScript font-emission artefacts). But `#s17` is referenced only through `<clipPath id="cp4"><use href="#s17"/></clipPath>`. `clip-path` uses the *shape* of its argument, not its paint, so `#s17` builds an alpha stencil that gates a low-contrast rectangle, but is never rendered directly. Layered further under `mask="url(#mk9)"` (water-ripple luminance mask), `filter="url(#glowSoft)"` (Gaussian blur), and `opacity="0.72"`, the shape barely registers on the raster. Extract `<g id="s17">` verbatim into a fresh SVG with a dark background, rasterise with `rsvg-convert`, and the flag reads out cleanly.

### Why is `customXml/item1.xml` the payload in Invisible Editor?

The `.docx` package is a zip. `unzip -l` shows every part is boilerplate-sized (~200 B to ~1.4 KB) except `customXml/item1.xml` at 44 KB, in a document whose visible body is 21 characters. `customXml/` was designed for third-party content-type schemas (SharePoint, form data); Word doesn't render its contents. Here it carries a fake `<revisionLog>` where each `<revision>` deletes the current buffer and inserts a new one, adding exactly one character per step. Replaying the log and scanning states for `grodno\{[^{}]+\}` finds the completed flag at step 20 (of 100 revisions); steps 21+ erode it back to the visible "Did you see the flag?" taunt.

### How does the Pickles ML supply-chain backdoor actually work?

The pickle disassembly (`pickletools.dis`) shows a single `REDUCE` call: `payload.install_supply_chain_probe(cipher, weights, seal)`. When `pickle.load()` executes that, Python imports the side-shipped `payload.pyc` and runs the function. The returned `LedgerModel` has a benign `infer(text, history)` method that returns fake classifier output for any normal input. But the method also computes `sha256("|".join(history[-4:]))` and compares to the stored `seal`; if the history matches, it derives a blake2s CTR keystream from `weights + sequence + b"inference-cache"` and XOR-decrypts `cipher` into a base85 ticket. The trigger space is `_WORDS = (snow, candle, tangerine, clock)` combinations: 256 candidate orderings, brute-forced instantly. Everything except `history` is server-side and deterministic. No network callback, no `os.system`; just a magic-input branch inside a "normal" ML inference method.

### How do you brute-force the Pickles trigger without running the malicious pickle?

Provide a stub `payload` module before `pickle.load()`, and use a `SafeUnpickler` subclass that overrides `find_class` to accept only `payload.install_supply_chain_probe` and blocks anything else. The stub captures the three arguments (`cipher`, `weights`, `seal`) into a dict without executing the real `payload.pyc`. Once captured, brute-force `history` combinations against `sha256(b"|".join(combo)).digest() == seal` in one line of `itertools.product`. All 256 combinations of `_WORDS` × 4 slots hash in under a second; the winning tuple is `(snow, candle, tangerine, clock)` in exactly the order declared in the module. From there, offline decrypt with blake2s CTR yields `grodno{p@ckl$s_are_so_yUmmy}` without ever hitting the live service.

### Which building is in the Fire Mural challenge and who painted the mural?

The building is the **Пожарная каланча** (Fire Watchtower) on улица Замковая 19 in Grodno, built 1902, now hosting the МЧС museum. The mural on the arched pediment is *«Огнеборцы — история и традиции мужества»* ("Firefighters — history and traditions of courage"), painted by **Владимир Качан** (Vladimir Kachan). The mural includes a widely-cited Mona Lisa easter egg: one of the МЧС rescuers on the right side is painted with Gioconda's face, which serves as Kachan's signature on the piece. Sources: Belarusian Wikipedia, `mchs.gov.by`, `grodnolen.gov.by`, `poshyk.info`, `grodno.in`, `planetabelarus.by`, Atlas Obscura. Flag: `grodno{Vladimir_Kachan}`.

### How do you get MM:SS precision on the FOOTBALLchik first goal?

Public match reports round football goals to the minute (`37'` in this case). The Belarusian ABFF match page for Neman vs ML Vitebsk (30 May 2026) reports the first goal by Pushnyakov at minute 37, but the flag format `MM:SS` requires the broadcast clock. The official first-goal YouTube clip (`ks3idqApraw`) is titled "1:0 — Пушняков, Неман — МЛ Витебск, BETERA-Высшая лига". Download video-only with `yt-dlp -f 398`, extract frames at 5 fps with `ffmpeg -vf fps=5`, and step through: at `36:27` the ball is in the goalmouth scramble, at `36:28` the ball is visibly over the line, at `36:29` the broadcast score bug updates from `0:0` to `1:0`. `36:28` belongs to the 37th minute, matching the public `37'` report. Flag: `grodno{36:28}`.

### What's the broader lesson from the Junior.Crypt 2026 forensic + misc + OSINT tracks?

Every challenge in these three tracks is a "look one layer past the default view" exercise. Forensic: the phishing corpus is one MIME sub-header past the visible subject; the philologist repo is one `git log` past the working tree. Misc: the MIDI carrier is one event-type past the notes; the SVG ghost text is one `clip-path` reference past the raster; the DOCX payload is one XML part past `document.xml`; the pickle backdoor is one `find_class` past the innocent-looking classifier surface. OSINT: the artist's name is one bilingual query past the initial landmark ID; the goal time is one video source past the minute-rounded match report. In every case the tool's default view is not the payload surface. Trained triage means always asking "what layer am I not looking at?" and reaching for `unzip -l`, `pickletools.dis`, `strings`, `git log`, `mido`, `<clip-path>` referents, EXIF, or video frame extraction as appropriate.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and pure-stdlib Python solvers are at [Abdelkad3r/Junior.Crypt.2026-CTF](https://github.com/Abdelkad3r/Junior.Crypt.2026-CTF). Each challenge has a `solve.py` that reproduces the flag from the handout. All solvers use only the Python standard library (no PyCryptodome, no `mido` requirement beyond an optional install, no `gmpy2`, no Sage). The Pickles solver targets Python 3.10 to match the shipped `.pyc` magic. The Ghost Layers solver optionally shells out to `rsvg-convert` for rasterisation; any modern browser is a fine fallback. The Invoice Without a Bank solver needs `7z` or `pyzipper` for the WinZip-AES archive.

## Closing notes

Eight challenges across three softer categories, but the same underlying discipline as the pwn / reverse / web / crypto tracks: look at the artefact through the *right* tool. `7z` for AES zips. `pickletools.dis` for pickles. `dis` + `marshal.loads` for `.pyc`. `mido` for MIDI events. `unzip -l` for Office files. `grep -oE '<[a-zA-Z]+'` for SVG element census. `git log --reverse --oneline` for content-addressed history. `exiftool` for image metadata. `yt-dlp` + `ffmpeg -vf fps=N` for broadcast-clock precision. Every one of these is a two-word invocation that reveals a layer the default view does not. Half the challenge is knowing which invocation matches the artefact type; the other half is being disciplined enough to read the prompt as a spec instead of a flavour note.

For more of this event's content on the same site, the [Junior.Crypt 2026 web + crypto writeup](/ctf-writeups/junior-crypt-2026-web-crypto-writeup/) covers the seven challenges that ride the Aperture Science / Portal theme (Franklin-Reiter e=3, Vaudenay CBC via timing trace, LCG seed truncation, many-time pad via multiset match, SplitMix64 timestamp-seeded RSA, plus two web bugs: newline injection through a first-line-only validator and an HS256 JWT wordlist-cracked secret). The [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/) walks the four native challenges (negative-index array OOB, session-to-sink UAF with fake vtable, reclassify-without-realloc heap OOB, modified-TCC-compiler VM with ELF-relocation-derived key). Adjacent CTFs on the site: the [NoHackNoCTF 2026 master writeup](/ctf-writeups/nohacknoctf-2026-writeup/) covers AES-CTR keystream reuse and ECDSA nonce-prefix HNP; the [R3CTF 2026 master writeup](/ctf-writeups/r3ctf-2026-writeup/) has Microsoft SEAL CKKS, .NET xoshiro256** state recovery, and Lagrange-basis oracle abuse; the [SEKAI CTF 2026 master writeup](/ctf-writeups/sekai-ctf-2026-writeup/) walks a single-assertion crypto puzzle and a Next.js triple-bug chain; the [LYKNCTF web writeup](/ctf-writeups/lyknctf-2026-web-writeup/) covers a Legacy Profile Importer AES-CBC padding oracle. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is Junior.Crypt 2026?","acceptedAnswer": {"@type": "Answer","text": "Junior.Crypt is a Belarusian junior-tier CTF (hosted in Grodno; flag prefix grodno{...}). The 2026 edition ran categories including crypto, forensic, misc, osint, pwn, reverse, and web. This writeup covers the two forensic challenges (Invoice Without a Bank, Philologist), four misc challenges (1000-7, Ghost Layers, Invisible Editor, Pickles), and two OSINT challenges (Fire Mural, FOOTBALLchik) I solved. The paired web + crypto writeup is at /ctf-writeups/junior-crypt-2026-web-crypto-writeup/ and the pwn + reverse writeup is at /ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/. Per-challenge READMEs, handouts, and pure-stdlib Python solvers at github.com/Abdelkad3r/Junior.Crypt.2026-CTF."}},
    {"@type": "Question","name": "Why does the Invoice Without a Bank challenge use the password Infected on the archive?","acceptedAnswer": {"@type": "Answer","text": "Infected is the MalwareBazaar / VirusTotal / VX-Underground / abuse.ch convention for a password-protected zip that carries a live malware sample or spam corpus. It's a machine-readable signal that whatever is inside should be treated as hostile. Stock unzip on Linux/macOS still can't decode WinZip-AES-256; the practical baseline is 7z or pyzipper."}},
    {"@type": "Question","name": "How do you narrow a 10-email phishing corpus to a single target?","acceptedAnswer": {"@type": "Answer","text": "The prompt anchors the query on 'Fatura Emitida - <id>' (Portuguese for 'Invoice Issued'). A single grep -lE 'Fatura Emitida' *.eml returns exactly one match (sample-717.eml). Half the corpus impersonates some bank, but only one uses that specific subject template. Read the prompt as a filter spec; anchoring on the literal string the author gives you beats any content heuristic."}},
    {"@type": "Question","name": "What does the Cyrillic acrostic in Philologist spell, and where does the flag live?","acceptedAnswer": {"@type": "Answer","text": "First Cyrillic letters of the six-line poem spell Г-И-Т-Л-О-Г = git log. Every file in the working tree is a decoy (11 fake flags). The flag lives in the git log itself: the author mined the seven commits' abbreviated SHA-1 prefixes so the first byte of each lands in printable ASCII. Concatenated in commit order the bytes are 31 6f 39 66 31 61 39 = '1o9f1a9' = leetspeak 'logflag'. Flag: grodno{1o9f1a9}."}},
    {"@type": "Question","name": "How does the 1000-7 MIDI steganography encode bits?","acceptedAnswer": {"@type": "Answer","text": "Every note in track 2 is bracketed by a pair of pitch-wheel events, always (+2304, -2304) or (-2304, +2304). Both pairs cancel inside a single tick and are inaudible. 752 pitch events = 376 pairs = 47 bytes. MSB-first, (+,-) = 1 and (-,+) = 0 decodes to the flag. The Tokyo Ghoul melody is a red herring for the rhythm of the covert channel."}},
    {"@type": "Question","name": "How does Ghost Layers hide text inside an SVG the browser renders normally?","acceptedAnswer": {"@type": "Answer","text": "The SVG's <g id='s17'> contains 39 glyph-shaped paths (negative y-scale + matching fill/stroke are FreeType font-emission tells). It's referenced only from a <clipPath>, so it builds an alpha stencil but is never painted directly. Chained under mask, filter, and opacity=0.72 on a water background it doesn't reach the naked eye. Extract <g id='s17'> into a fresh SVG with a dark background and rasterise to read the flag."}},
    {"@type": "Question","name": "Why is customXml/item1.xml the payload in Invisible Editor?","acceptedAnswer": {"@type": "Answer","text": "The .docx is a zip. unzip -l shows every part is boilerplate-sized except customXml/item1.xml at 44 KB in a document whose visible body is 21 characters. That XML carries a fake revisionLog where each revision deletes the current buffer and inserts a new one adding one character per step. Replay 100 revisions; scan states for grodno\\{[^{}]+\\}. Flag appears as the whole buffer for exactly one revision (step 20)."}},
    {"@type": "Question","name": "How does the Pickles ML supply-chain backdoor actually work?","acceptedAnswer": {"@type": "Answer","text": "pickletools.dis shows a single REDUCE calling payload.install_supply_chain_probe(cipher, weights, seal). pickle.load imports the side-shipped payload.pyc and runs the function. The returned LedgerModel.infer(text, history) has a hidden branch: if sha256('|'.join(history[-4:])) == seal, derive a blake2s CTR keystream from weights + sequence + b'inference-cache' and XOR-decrypt cipher into a base85 ticket. Trigger space is _WORDS = (snow, candle, tangerine, clock) with 4^4 = 256 combinations."}},
    {"@type": "Question","name": "How do you brute-force the Pickles trigger without running the malicious pickle?","acceptedAnswer": {"@type": "Answer","text": "Provide a stub payload module before pickle.load, and use a SafeUnpickler subclass that overrides find_class to accept only payload.install_supply_chain_probe. The stub captures cipher, weights, seal without executing payload.pyc. Then brute-force with itertools.product(WORDS, repeat=4) against sha256(b'|'.join(combo)).digest() == seal. Winning tuple: (snow, candle, tangerine, clock) in declaration order."}},
    {"@type": "Question","name": "Which building is in the Fire Mural challenge and who painted the mural?","acceptedAnswer": {"@type": "Answer","text": "The building is the Пожарная каланча (Fire Watchtower) on Замковая 19 in Grodno, built 1902, now the МЧС museum. The mural on the arched pediment is 'Огнеборцы — история и традиции мужества' by Vladimir Kachan (Владимир Качан). A widely-cited detail: one of the МЧС rescuers on the right is painted with Mona Lisa's face, serving as Kachan's signature. Flag: grodno{Vladimir_Kachan}."}},
    {"@type": "Question","name": "How do you get MM:SS precision on the FOOTBALLchik first goal?","acceptedAnswer": {"@type": "Answer","text": "Public match reports round to the minute (37' for Pushnyakov's goal, Neman vs ML Vitebsk 30 May 2026). The flag format MM:SS needs the broadcast clock. Official first-goal YouTube clip ks3idqApraw. Download video-only with yt-dlp -f 398, extract frames at 5 fps with ffmpeg -vf fps=5. Ball crosses the line at broadcast clock 36:28. Sanity check: 36:28 belongs to the 37th minute, matching the public 37' report."}},
    {"@type": "Question","name": "What's the broader lesson from the Junior.Crypt 2026 forensic + misc + OSINT tracks?","acceptedAnswer": {"@type": "Answer","text": "Every challenge is a 'look one layer past the default view' exercise. The tool's default view is not the payload surface. Trained triage means always asking 'what layer am I not looking at?' and reaching for unzip -l for Office files, pickletools.dis for pickles, git log for content-addressed history, mido for MIDI events, clip-path referents for SVG, exiftool for images, or video frame extraction for broadcast clocks."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and pure-stdlib Python solvers at github.com/Abdelkad3r/Junior.Crypt.2026-CTF. Each challenge has a solve.py reproducing the flag from the handout. All solvers use only the Python standard library. The Pickles solver targets Python 3.10 to match the shipped .pyc magic; the Ghost Layers solver optionally shells out to rsvg-convert; the Invoice Without a Bank solver needs 7z or pyzipper for the WinZip-AES archive."}}
  ]
}
</script>
