---
title: "ASIS CTF Quals 2026 Misc Writeup: Mic Check (Seven-Segment ASCII with Drifted Top Row)"
slug: "asis-ctf-quals-2026-misc-writeup"
description: "Complete ASIS CTF Quals 2026 Misc writeup for Mic Check. Five three-row ASCII blocks render leetspeak words in a proportionally-spaced seven-segment font whose top-segment row drifts by one to two columns in three of the five blocks, enough to make a naive column-slicing decoder produce cl9ss1l and unc3rt4n1 instead of classic and uncertain. The fix is to stop treating the top row as position and start treating it as a count. Step one tiles the two pixel-accurate lower rows with variable-width glyph cells so single-column 1 and crossbar t are handled without a fixed pitch assumption. Step two enumerates the only three drift-sensitive twin pairs 4 versus 9, l versus c, and u versus 0 whose lower rows are identical. Step three filters candidates by matching the underscore count in the top row and cross-references the de-leeted reading against a system wordlist. Every block collapses to exactly one word — farewell classic hello uncertain era — and the flag ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!} falls out of joining them with underscores. The walkthrough covers building the font from the art itself, why the top-segment row is the exact place whitespace damage hides in copy-paste and terminal rendering, why counting survives horizontal drift where positional slicing does not, and the twenty-line solve.py that turns the whole decode into a proof rather than a preference."
date: 2026-09-01T18:00:00Z
lastmod: 2026-09-01T18:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["ASIS CTF Quals 2026"]
tags:
  - "asis ctf"
  - "asis ctf quals 2026"
  - "asis ctf 2026"
  - "ctf writeup"
  - "misc challenge"
  - "miscellaneous"
  - "mic check"
  - "seven segment display"
  - "seven segment ascii"
  - "ascii art decoding"
  - "leetspeak decoding"
  - "leet substitution cipher"
  - "warm up challenge"
  - "baby misc"
  - "font reconstruction"
  - "column tiling"
  - "proportional spacing"
  - "constraint satisfaction"
  - "dictionary attack"
  - "wordlist filter"
  - "ctf 2026"
keywords:
  - "asis ctf quals 2026 writeup"
  - "asis ctf 2026 misc writeup"
  - "asis ctf mic check writeup"
  - "asis ctf mic check solution"
  - "seven segment ascii decoder ctf"
  - "leetspeak seven segment ctf"
  - "proportional seven segment font ctf"
  - "ascii art leet ctf solve"
  - "asis ctf 2026 solutions"
  - "ctf misc step by step 2026"
toc: true
cover:
  image: "/images/articles/asis-ctf-quals-2026-misc-writeup.png"
  alt: "ASIS CTF Quals 2026 Misc Mic Check writeup cover. Five three-row ASCII blocks render leetspeak words in a proportionally-spaced seven-segment font whose top-segment row drifts by one to two columns in three of the five blocks, enough that a naive column-slicing decoder reads cl9ss1l instead of classic and unc3rt4n1 instead of uncertain. The solution stops treating the top row as position and starts treating it as a count: tile the two pixel-accurate lower rows with variable-width glyph cells that handle single-column one and crossbar t without a fixed pitch, enumerate the only three drift-sensitive twin pairs 4 versus 9 and l versus c and u versus 0 whose lower rows are identical, filter candidates by matching the underscore count in the top row, and cross-reference the de-leeted reading against a system wordlist. Every block collapses to exactly one word — farewell classic hello uncertain era — and the flag ASIS f4r3w3ll cl4ss1c h3ll0 unc3rt41n 3r4 falls out of joining them with underscores."
---

**ASIS CTF Quals 2026**'s Miscellaneous track opens with a `Baby`-rated warm-up called **Mic Check**: five three-row ASCII blocks that render leetspeak words in a hand-drawn seven-segment font. The prompt promises that "only kind human eyes can still decode the vintage LED displays," and by eye you can indeed read the five blocks in about a minute — `farewell`, `classic`, `hello`, `uncertain`, `era!`. The catch, and the reason this warm-up rewards a proper decoder rather than a Ctrl-F on Google, is that the art is **proportionally spaced** and its **top-segment row is misaligned by one to two columns in three of the five blocks**. A decoder that trusts the pixel position of every `_` produces `cl9ss1l` for block 2 and `unc3rt4n1` for block 4, neither of which is a word. This walkthrough builds the font from the art itself, explains why the top row is the exact place whitespace damage hides, and closes with a twenty-line solver that turns the decode into a proof rather than a preference.

Source repository with challenge, solver, and formatted writeup: [Abdelkad3r/ASIS-CTF-Quals-2026/Misc/MicCheck](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/tree/main/Misc/MicCheck).

## The Miscellaneous track at a glance

| Challenge | Difficulty | Sub-genre | Key insight | Flag |
|---|---|---|---|---|
| [Mic Check](#mic-check--seven-segment-ascii-with-a-drifted-top-row) | Baby | Seven-segment ASCII decoding | Top row is a count, not a position; only three twin-glyph pairs are ambiguous under drift | `ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}` |

Single-challenge Misc track this year — but the reasoning generalises to every ASCII-art decoding problem, and the resolve-ambiguity-with-a-count trick is worth carrying into other categories.

---

## Mic Check — seven-segment ASCII with a drifted top row

> *Flag:* `ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}`
>
> *Prompt:* "The analog signals have died out. Only kind human eyes can still decode the vintage LED displays before the machines take over. Read the following digital readouts below. Join the blocks with `_` inside `ASIS{...}` (all lowercase)."

The handout is a single file — [`readouts.txt`](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/blob/main/Misc/MicCheck/challenge/readouts.txt) — containing five three-row blocks numbered `[1]` through `[5]`:

```
[1]  _       _   _       _
    |_  |_| |_|  _| | |  _| |  |
    |     | |\   _| |/|  _| |_ |_

[2]  _       _   _   _
    |   |   |_| |_  |_   | |
    |_  |_    |  _|  _|  | |_

[3]      _            _
    |_|  _| |   |   | |
    | |  _| |_  |_  |_|

[4]      _   _   _   _  _|_      _
    | | | | |    _| |_|  |  |_| | | |
    |_| | | |_   _| |\   |    | | | |

[5]  _   _
     _| |_| |_| |
     _| |\    | .
```

Three rows per block is the visual giveaway: a seven-segment digit needs exactly three text rows to draw, one for the top segment, one for the upper verticals plus the middle bar, and one for the lower verticals plus the bottom bar.

### 1. Reading the prompt for what it actually says

The flavour text is not decoration — every phrase in it is a directive:

- **"vintage LED displays"** — seven-segment displays, the kind you find on a bench multimeter or a clock radio. Do not go looking for Braille, Morse, or a font on Google.
- **"Only kind human eyes can still decode"** — the art is hostile to naive OCR (proportional spacing, whitespace damage) but trivial for a human. There is no cipher, no key, no file hidden inside the whitespace. The plaintext is what you see.
- **"all lowercase"** — the words are English words in lowercase, some with digits substituted for vowels (leetspeak).

Combine those and the challenge collapses to *"decode five leetspeak words drawn as seven-segment ASCII."* Nothing else.

### 2. Building the font from the art itself

You could import a standard seven-segment font, but the challenge author added at least four glyphs no real seven-segment display can render — a diagonal `\` for `r`, a diagonal `/` for `w`, a crossbar `_|_` for `t`, and a stroke-over-dot `|` / `.` for `!`. Importing a font gets you `farewell` but not `r`, `w`, `t`, or `!` at their non-standard positions. Building the font from the art is faster and more reliable.

The seven segments follow the conventional `a`–`g` labelling:

```
 _     <- a          top
|_|    <- f g b      upper verticals + middle bar
|_|    <- e d c      lower verticals + bottom bar
```

Reading the blocks by hand yields sixteen glyphs — ten letters, five digits (leetspeak substitutions), and the exclamation mark:

```
 _           _     _                 _     _
|_    |_|   |_|    _|   | |   |     |     |_
|       |   |\     _|   |/|   |_    |_     _|
 f    4=a    r    3=e    w     l     c     s

             _           _    _|_    _
|     |_|   | |   | |   | |    |    |_|   |
|     | |   |_|   |_|   | |    |      |   .
1=i    h    0=o    u     n     t    9=g    !
```

Two properties of this font matter for the decode:

1. **Three glyph pairs differ only in the top segment.** `4` versus `9`, `l` versus `c`, and `u` versus `0` share identical lower two rows. Every other glyph is fully determined by its bottom two rows. So the top row disambiguates only three pairs; everywhere else it is redundant.
2. **Glyph widths vary.** `1` occupies a single column, `t` spans all three columns of the top row (`_|_`), and the rest sit in the usual 3-by-3 cell. There is no fixed character pitch to slice on. A decoder that assumes "every glyph is 4 columns wide, cells start at 4, 8, 12, …" will mis-tile any block that contains a `1` or a `t`.

Note that `s` is drawn as the letter `s`, not as `5`. The two glyphs are drawn identically in this font, and the surrounding words (`classic`, `farewell`) settle the ambiguity in favour of the letter form.

### 3. What a naive column-slicing decoder gets wrong

Block 1 decodes cleanly on the first try. Cells begin at columns 4, 8, 12, 16, 20, 24, 28, and 31 — a pitch of 4 that tightens at the end because the two trailing `l` glyphs are packed slightly closer:

```
[1]  f4r3w3ll    farewell
      col  4  ' _ ' '|_ ' '|  '  -> f
      col  8  '   ' '|_|' '  |'  -> 4
      col 12  ' _ ' '|_|' '|\ '  -> r
      col 16  ' _ ' ' _|' ' _|'  -> 3
      col 20  '   ' '| |' '|/|'  -> w
      col 24  ' _ ' ' _|' ' _|'  -> 3
      col 28  '   ' '|  ' '|_ '  -> l
      col 31  '   ' '|  ' '|_ '  -> l
```

Blocks 3 and 5 also decode cleanly — `h3ll0` and `3r4!`.

Blocks 2 and 4 do not. Both failures share one root cause: **the top-segment row of the published art is not aligned with the glyphs beneath it.** Copy-paste through GitHub, a terminal, or an HTML renderer can shave whitespace off the front of a line without touching the two rows below, and a decoder that slices by column will match the wrong glyph to the wrong top segment.

**Block 2** — the underscores sit at columns 5, 13, 17, 21, while the glyph cells start at 4, 8, 12, 16, 20, 25, 27. Read literally, the third glyph gains a top bar it should not have (`4` becomes `9`) and the last glyph loses the one it should have (`c` becomes `l`):

```
naive:  c l 9 s s 1 l     ->  "clgssil"   not a word
```

**Block 4** — worse. The final underscore sits at column 33, two columns left of where it belongs. That single stray `_` bridges the gap between the `1` at column 32 and the `n` at column 34, welding two glyphs into one run of ink. A decoder that segments on "runs of inked columns" reads the tail in the wrong order:

```
naive:  u n c 3 r t 4 n 1  ->  "uncertani"  not a word
```

Both are recoverable, but not by trusting pixel positions.

### 4. Two constraints that make the decode a proof

The fix is to stop treating the top row as **positional evidence** and start treating it as a **count**.

**Constraint A — the underscore count is drift-independent.** However far an underscore has slid sideways, it is still there. Block 2's top row holds exactly four underscores, so exactly four of its seven glyphs carry a top segment. Block 4 holds seven (note `t` contributes two, being drawn `_|_`).

**Constraint B — only three glyph pairs are ambiguous.** From the font in section 2, the lower two rows pin down every glyph except `4` versus `9`, `l` versus `c`, and `u` versus `0`. The search space over top-segment identity is therefore at most `2^k` where `k` is the number of twin-glyph positions in the block, which is small.

Apply both to block 2. The lower rows fix glyphs 4, 5, and 6 as `s`, `s`, `1` — contributing `1 + 1 + 0 = 2` top segments — leaving glyphs 1, 2, 3, and 7 free. The block's top row has four underscores total, so the four free glyphs must contribute `4 - 2 = 2` top segments between them. Enumerate:

| Reading | Top segments (`g1+g2+g3` + fixed `ss1` + `g7`) | De-leeted | Word? |
|---|---|---|---|
| `cl9ss1l` | 1+0+1+2+0 = 4 (satisfies count) | clgssil | no |
| `cc4ss1l` | 1+1+0+2+0 = 4 (satisfies count) | ccassil | no |
| `ll9ss1c` | 0+0+1+2+1 = 4 (satisfies count) | llgssic | no |
| **`cl4ss1c`** | **1+0+0+2+1 = 4 (satisfies count)** | **classic** | **yes** |

Only one of the four candidates survives the dictionary check. No guessing.

For block 4 the ambiguity is not glyph identity but **tiling** — the stray top underscore lets the decoder read the two trailing glyphs in either order:

| Tiling | Reading | Top segments | De-leeted | Word? |
|---|---|---|---|---|
| `n` at col 32, `1` at col 36 | `unc3rt4n1` | 7 (satisfies count) | uncertani | no |
| **`1` at col 32, `n` at col 34** | **`unc3rt41n`** | **7 (satisfies count)** | **uncertain** | **yes** |

Again, one survivor. Every block collapses to exactly one reading under the combined constraints.

### 5. The automated solver in twenty lines

The full [`solve.py`](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026/blob/main/Misc/MicCheck/solution/solve.py) is around 180 lines with docstrings and pretty-printing, but the load-bearing core is short enough to sit in one screen. The font is the reference table for every glyph's top-segment count and its two lower rows:

```python
# a glyph is (top_underscores, middle_row, bottom_row)
GLYPHS = {
    "0": (1, "| |", "|_|"),
    "1": (0, "|  ", "|  "),
    "3": (1, " _|", " _|"),
    "4": (0, "|_|", "  |"),
    "9": (1, "|_|", "  |"),
    "s": (1, "|_ ", " _|"),
    "c": (1, "|  ", "|_ "),
    "f": (1, "|_ ", "|  "),
    "h": (0, "|_|", "| |"),
    "l": (0, "|  ", "|_ "),
    "n": (1, "| |", "| |"),
    "r": (1, "|_|", "|\\ "),
    "t": (2, " | ", " | "),   # '_|_' across the whole top row
    "u": (0, "| |", "|_|"),
    "w": (0, "| |", "|/|"),
    "!": (0, "|  ", ".  "),
}

# glyphs sharing the same two lower rows differ only by the top segment
TWINS = {}
for ch, (_t, m, b) in GLYPHS.items():
    TWINS.setdefault((m, b), []).append(ch)

LEET = {"4": "a", "3": "e", "1": "i", "0": "o", "9": "g"}
```

The tiler walks the lower two rows left-to-right, and at each unclaimed column tries every glyph whose middle and bottom patterns match starting at that column. Cells can overlap on blank columns, so a one-column `1` followed by an ordinary cell is handled without a pitch assumption:

```python
def tile(mid, bot):
    width = max(len(mid), len(bot))
    mid, bot = mid.ljust(width), bot.ljust(width)
    ink = {c for c in range(width) if mid[c] != " " or bot[c] != " "}

    def walk(start, claimed):
        pending = sorted(c for c in ink if c >= start)
        if not pending:
            if claimed == ink:
                yield []
            return
        col = pending[0]
        for left in range(max(0, col - 2), col + 1):
            for ch, (_, m, b) in GLYPHS.items():
                cells, ok = set(), True
                for row, pattern in ((mid, m), (bot, b)):
                    for i, want in enumerate(pattern):
                        if want == " ":
                            continue
                        c = left + i
                        if c >= width or row[c] != want:
                            ok = False
                            break
                        cells.add(c)
                    if not ok:
                        break
                if not ok or min(cells) != col:
                    continue
                for rest in walk(max(cells) + 1, claimed | cells):
                    yield [(left, ch)] + rest

    return list(walk(0, set()))
```

The top-row filter and dictionary check close the loop:

```python
from itertools import product

def decode(block, words):
    top, mid, bot = ("    " + row[4:] for row in block)   # blank the [n] label
    want_tops = top.count("_")
    found = []
    for parse in tile(mid, bot):
        options = [TWINS[(GLYPHS[ch][1], GLYPHS[ch][2])] for _, ch in parse]
        for combo in product(*options):
            if sum(GLYPHS[c][0] for c in combo) != want_tops:
                continue
            leet = "".join(combo)
            word = "".join(LEET.get(ch, ch) for ch in leet).strip("!.,?")
            if word in words:
                found.append((leet, word))
    return found
```

Every block yields **exactly one** reading — the driver aborts if any block is ambiguous, so the output is a proof rather than a preference:

```
$ python3 solution/solve.py
  [1]  f4r3w3ll    farewell
  [2]  cl4ss1c     classic
  [3]  h3ll0       hello
  [4]  unc3rt41n   uncertain
  [5]  3r4!        era

  ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}
```

Run with `-v` to dump the per-glyph cell trace shown in section 3.

### 6. Why the reading is the right one

Two independent checks agree on the same five words:

- **Structural.** Every block has exactly one tiling of the lower two rows that consumes every inked column and produces glyphs from the font. Every ambiguous top-segment assignment has exactly one setting that matches the number of underscores in the top row and de-leets to an English word.
- **Semantic.** Concatenate the plaintext and it reads *"farewell classic, hello uncertain era!"* — a restatement of the challenge's own flavour text (*"The analog signals have died out"*). The plaintext is a comment on the encoding.

When the structural and semantic checks agree, the decode is correct. When they disagree — as they would if the fourth block were `uncertani` — the semantic check tells you the parser is wrong, not the wordlist.

### 7. Flag

```
ASIS{f4r3w3ll_cl4ss1c_h3ll0_unc3rt41n_3r4!}
```

### 8. Takeaways

- **Three-row ASCII art is almost always a seven-segment display.** Build the font from the art itself rather than importing one — challenge authors routinely add glyphs (`r`, `w`, `t`, `!` here) that no real seven-segment display can render.
- **Segment on the rows you trust.** The lower two rows carry the verticals and are self-aligning; the top row is a single sparse character per glyph and is exactly where whitespace damage hides — in copy-paste, in a terminal renderer, in the original art itself.
- **Turn a positional signal into a counting signal when position is unreliable.** The number of top segments survives any horizontal drift, and it was enough to close both ambiguities here.
- **Let the plaintext arbitrate.** With a leetspeak mapping and a wordlist, the search space of a warm-up encoding collapses to a single reading. If a decode is not a word, the decode is wrong — not the wordlist.

---

## Cross-cutting notes

Mic Check is a Baby-rated warm-up, but the discipline it teaches shows up in every category where the data on the wire disagrees with the data as rendered:

- **Web.** HTTP header canonicalisation, whitespace differences between an origin and a proxy, and Unicode NFC-versus-NFD normalisation all produce the same class of "the byte you see is not the byte the parser saw" bug.
- **Forensics.** Copy-pasted evidence from a terminal or a PDF viewer routinely loses leading whitespace, trailing carriage returns, or non-breaking spaces. The forensic value of the artefact is a function of what got preserved, not what got displayed.
- **Reversing.** Font-based ASCII encodings (Base65536, Base2048, whitespace steganography) rely on the reader trusting exact codepoint positions. A decoder that operates on the abstract structure (count of tokens, adjacency of tokens) rather than pixel positions is robust to display damage.

The general lesson is the one in section 8 above: when position is unreliable, prefer a signal that survives horizontal drift. Counting is the simplest such signal.

## Frequently asked questions

### What is ASIS CTF Quals 2026?

ASIS CTF Quals 2026 is the qualifier round for the ASIS Finals, run by the ASIS team out of Iran. The event is a Jeopardy-style CTF with the traditional five tracks — Crypto, Web, Reverse, Pwn, and Misc — and a small number of hard-rated challenges rather than a long tail of warm-ups. Flags use the `ASIS{...}` prefix. The Misc track this year contained a single warm-up, Mic Check, plus category-crossover challenges under other tracks. The compiled writeup repository lives at [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026).

### What is Mic Check and what is the bug class?

Mic Check is a warm-up (`Baby` difficulty) misc challenge that gives you five three-row ASCII blocks and asks for the flag as `ASIS{block1_block2_block3_block4_block5}` in lowercase. Each block is a run of hand-drawn seven-segment glyphs spelling one leetspeak word. The bug class is **whitespace-fragility in a positional encoding**: the top-segment row of the drawing has slid one to two columns off in three of the five blocks, breaking any decoder that relies on the exact column of every `_` character.

### Why does a naive decoder fail on blocks 2 and 4?

Because it trusts the pixel position of the top-segment row. On block 2 the underscores sit one column to the right of the glyph cells, so the third glyph gains a top segment it should not have (`4` becomes `9`) and the last glyph loses one it should have (`c` becomes `l`) — you read `cl9ss1l` instead of `cl4ss1c`. On block 4 a stray underscore two columns left of where it belongs welds two glyphs into one visual run, so a "segment on ink runs" decoder reads `unc3rt4n1` instead of `unc3rt41n`. Both are recoverable by treating the top row as a count of segments rather than a series of positions.

### How do you resolve the drift ambiguity without guessing?

Two constraints. First, the number of underscores in the top row is invariant under horizontal drift, so however far a segment slid it is still counted. Second, only three glyph pairs in the font differ solely in the top segment (`4`/`9`, `l`/`c`, `u`/`0`) — every other glyph is fully determined by its two lower rows, which are pixel-accurate in this challenge. Enumerate the small twin-assignment search space, keep only assignments whose top-segment total matches the underscore count, de-leet the result, and cross-check against a wordlist. Every block yields exactly one word.

### Why does the solver enforce "exactly one reading per block" and abort otherwise?

Because the challenge is under-constrained otherwise. Without the dictionary check, `cc4ss1l` and `ll9ss1c` also match the underscore count for block 2; without the twin enumeration, the tiler produces multiple candidate parses for block 4. Aborting on ambiguity makes the solver a proof: if it produces a flag, that flag is the unique reading of the art. If it aborts, the wordlist or the font is missing an entry, not the decode.

### Why is `s` written as the letter `s` and not as `5`?

Because the two glyphs are drawn identically in this seven-segment font — top bar, middle bar, bottom bar, upper-left vertical, lower-right vertical — and the challenge author picked the letter form. You could equally well read `farewell` as `f4r3w3ll` or as `f4r3w3ll` with `s` at either position (there is none in `farewell`, but there is one in `classic`), and the flag uses `s` verbatim. Reading `classic` as `cl4ss1c` gives the correct flag; reading it as `cl4551c` or `cl4s5ic` does not.

### Is there a scenario where an LLM OCR pass would solve this?

Probably not reliably. General-purpose OCR trained on rendered fonts is not tuned for hand-drawn ASCII art, and multimodal models will happily hallucinate the word they think you want (`classic`) even when the input encodes `clgssil`. The failure mode is worse than a purposeful decoder because there is no way to tell whether the model read the art or reconstructed it from context. A twenty-line font-plus-tiler-plus-dictionary decoder is faster to write and gives you a proof of correctness for free.

### Are there follow-up misc challenges in the same track?

Not in the 2026 qualifiers — Misc contained only Mic Check. The rest of the writeup compilation covers the Crypto, Reverse, and Web tracks (Hackel, Linchan, Mario, Headache, Pancake Stack, Less is More, Sultan; ASIS Arch and LeakMeAk; 2048 and Another Baby Web). See the top-level [README](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026) for the full table.

### What is the general lesson?

**When position is unreliable, prefer a signal that survives horizontal drift.** Counting is the simplest such signal, and it collapses the ambiguity in Mic Check to a search space of at most `2^k` twin-glyph settings — small enough to enumerate exhaustively and disambiguate with a wordlist. The same discipline applies to any parser that ingests hand-copied evidence from a terminal, a PDF, or a wiki page: build robustness against whitespace damage into the parser rather than trusting the source to be pristine.

## Closing notes

Mic Check is the smallest challenge in ASIS CTF Quals 2026 by difficulty, and it is a good example of a Baby-rated warm-up that still rewards a proper decoder. The naive column-slicing approach gets three of the five blocks and stalls on the other two; a font-plus-tiler-plus-dictionary approach solves all five in one pass and gives you a proof of correctness. Both approaches take about the same amount of time to write. The second one generalises.

Full challenge source, solver, and formatted writeup are in the [Abdelkad3r/ASIS-CTF-Quals-2026](https://github.com/Abdelkad3r/ASIS-CTF-Quals-2026) repository. Other ASIS 2026 writeups linked from the same README cover the Crypto, Reverse, and Web tracks.
