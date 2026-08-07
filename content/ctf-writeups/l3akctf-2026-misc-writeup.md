---
title: "L3akCTF 2026 Misc Writeup: All 4 Miscellaneous Challenges"
slug: "l3akctf-2026-misc-writeup"
description: "Full L3akCTF 2026 miscellaneous writeup covering all four misc challenges: decoding a QWERTY keyboard-shift cipher where the right hand typed one key too far right (me fr); reading letters drawn on an 8x8 board by the destination squares of White's queen across 24 rigged PGN chess games (Blunder); auto-solving 100 ANSI-rendered weighted mazes under a five-second deadline by parsing colored terminal cells, converting board-game pieces to tile costs, and running Dijkstra, then reading a FIGlet flag (Maze Captcha); and clearing 100 rotated image-tile mazes through a web API that leaks the full wall matrices, solved with BFS plus HTTP/1.1 request pipelining over one TLS connection (Cursed Maze Captcha)."
date: 2026-08-06T21:00:00Z
lastmod: 2026-08-06T21:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["L3akCTF 2026"]
tags:
  - "l3akctf"
  - "l3akctf 2026"
  - "ctf writeup"
  - "misc"
  - "miscellaneous"
  - "keyboard shift cipher"
  - "qwerty cipher"
  - "substitution cipher"
  - "pgn"
  - "chess"
  - "steganography"
  - "grid encoding"
  - "maze solving"
  - "dijkstra"
  - "bfs"
  - "shortest path"
  - "ansi parsing"
  - "terminal parsing"
  - "unicode width"
  - "figlet"
  - "proof of work"
  - "http pipelining"
  - "web api"
  - "automation"
  - "ctf 2026"
keywords:
  - "l3akctf 2026 misc writeup"
  - "l3akctf 2026 miscellaneous writeup"
  - "me fr ctf writeup"
  - "blunder ctf writeup"
  - "maze captcha ctf writeup"
  - "cursed maze captcha ctf writeup"
  - "qwerty keyboard shift cipher ctf"
  - "chess pgn queen path grid encoding ctf"
  - "automated maze captcha solver dijkstra ctf"
  - "http pipelining ctf maze api"
  - "ansi terminal maze parser ctf"
  - "figlet flag ctf"
  - "bfs maze wall matrix ctf"
  - "miscellaneous ctf 2026"
toc: true
cover:
  image: "/images/articles/l3akctf-2026-misc-writeup.png"
  alt: "L3akCTF 2026 miscellaneous writeup covering all four misc challenges — me fr decodes a QWERTY keyboard-shift cipher where the right hand typed one key too far to the right, Blunder reads letters drawn on an 8x8 board by the destination squares of White's queen across 24 rigged PGN chess games that spell HARDTOKEEPUPWITHTHEQUEEN, Maze Captcha auto-solves 100 ANSI-rendered weighted terminal mazes under a five-second deadline by parsing colored cells and double-width Unicode board pieces into tile costs and running Dijkstra before reading a FIGlet flag, and Cursed Maze Captcha clears 100 rotated image-tile mazes through a web API that leaks the full horizontal and vertical wall matrices, solved with breadth-first search plus HTTP/1.1 request pipelining over a single TLS connection to beat the per-round deadline"
---

Miscellaneous is where CTFs hide the challenges that don't fit a neat category — and L3akCTF 2026's four misc tasks are a perfect cross-section: a beginner cipher you solve by *looking* at it, a chess-notation steganography puzzle, and two "prove you're human" captchas that are really speed-automation problems. The through-line across all four is **separating presentation from payload** — the QWERTY typo, the FIGlet art, the rotated maze board, and the absurd chess games are all costumes over something simple underneath.

This **CyberSecurity Elite** L3akCTF 2026 misc writeup walks all four challenges end to end, focusing on the *reasoning* rather than just the final scripts. Challenge files and standalone solvers are published at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026). For the rest of the event, see the companion [binary exploitation](/ctf-writeups/l3akctf-2026-pwn-writeup/) and [cryptography](/ctf-writeups/l3akctf-2026-crypto-writeup/) writeups.

## All four challenges at a glance

| Challenge | Difficulty | Points | Solves | Core idea |
|---|---|---:|---:|---|
| [me fr](#me-fr--the-right-hand-typed-one-key-too-far) | Beginner | 65 | 198 | QWERTY keyboard-shift cipher (right hand off by one key) |
| [Blunder](#blunder--the-queen-is-drawing-letters) | Easy | 108 | 59 | White queen's destination squares draw letters on an 8×8 grid |
| [Maze Captcha](#maze-captcha--100-weighted-mazes-in-five-seconds-each) | Medium | 213 | 20 | Parse ANSI terminal maze → weighted graph → Dijkstra ×100 |
| [Cursed Maze Captcha](#cursed-maze-captcha--the-api-hands-you-the-whole-maze) | Hard | 299 | 11 | API leaks wall matrices → BFS + HTTP/1.1 pipelining ×100 |

---

## me fr — the right hand typed one key too far

> *Flag:* `L3AK{WHY_D0_1_dO_TH1S_s0_0f73N...}`

The attachment is a single line of near-English gibberish, and the description name-drops Monkeytype — a hint that this is a *typing* mistake, not a cipher:

```text
Jo! Sp O was tjomlomg/// tu[omg os kist sp jard mpwadaus!
```

Squinting at it, the pattern is unmistakable: `Jo!` → `Hi!`, `tjomlomg` → `thinking`, `tu[omg` → `typing`, `wjo;e` → `while`. The left-hand letters are correct, but the right-hand letters are each **one key too far to the right** on QWERTY — `j`→`h`, `o`→`i`, `[`→`p`, `;`→`l`, `/`→`.`. Someone typed with their right hand shifted one position over.

The fix is a substitution table covering only the right-hand keys (in both unshifted and shifted rows, since the flag has uppercase and punctuation), mapping each affected key one position left:

```python
rows = [
    ("`1234567890-=", "~!@#$%^&*()_+", "7890-=", "&*()_+"),
    ("qwertyuiop[]\\", "QWERTYUIOP{}|", "uiop[]\\", "UIOP{}|"),
    ("asdfghjkl;'", "ASDFGHJKL:\"", "jkl;'", "JKL:\""),
    ("zxcvbnm,./", "ZXCVBNM<>?", "m,./", "M<>?"),
]
```

Applying it reveals the plaintext and the flag: *"Hi! So I was thinking... typing is just so hard nowadays! ... heres the flag: `L3AK{WHY_D0_1_dO_TH1S_s0_0f73N...}`"*. **Takeaway:** when ciphertext looks *almost* readable, suspect a physical/keyboard transform before reaching for classical crypto — the structure is usually visible to the naked eye.

---

## Blunder — the queen is drawing letters

> *Flag:* `L3AK{HARDTOKEEPUPWITHTHEQUEEN}`

The handout `games.pgn` holds **24 chess games**, every one won by Black (`0-1`) with nonsensical play: White shoves the queen out on move 4 (`Qf3`, `Qf4`, `Qf5`, …) and then wanders it around the board while Black harvests material. Combined with the title *Blunder* and the hint "there's a lesson hidden in these games," the giveaway is that the queen's path is a **carrier channel**, not real chess.

The encoding: for each game, collect the **destination square of every White queen move** and mark it on an 8×8 grid (rank 8 on top). Each game's grid draws a single capital letter.

```python
QUEEN_MOVE = re.compile(r"Q(?:[a-h])?(?:[1-8])?x?([a-h][1-8])")

def plot(squares):
    grid = [["."] * 8 for _ in range(8)]
    for sq in squares:
        f = ord(sq[0]) - ord("a")   # file a..h → 0..7
        r = int(sq[1]) - 1          # rank 1..8 → 0..7
        grid[7 - r][f] = "X"
    return "\n".join("".join(row) for row in grid)
```

Game 1 draws an `H` (two verticals on files `b`/`f` joined by a crossbar), game 2 an `A`, game 3 an `R`, and so on. Reading all 24 grids spells:

```text
H A R D T O K E E P U P W I T H T H E Q U E E N
```

`HARDTOKEEPUPWITHTHEQUEEN`, wrapped per the description into `L3AK{HARDTOKEEPUPWITHTHEQUEEN}` — a pun on *Blunder*, since Black's real blunder is failing to keep up with a lone marauding queen. Note the two subtleties the solver respects: it's the queen's *destination* square that counts (`Qxf6` → `f6`), and a little edge noise from forced legal moves rarely obscures the letter shape. **Takeaway:** in PGN/chess stego, the moves themselves are the medium — plot piece trajectories on the board and read the picture.

---

## Maze Captcha — 100 weighted mazes in five seconds each

> *Flag:* `L3AK{d3Sp1T3_411_OuR_rAg3_w3'Re_A11_jU57_R47S_1n_a_M4Z3}`

"A simple captcha to prove you're not a robot" — which of course must be solved *by* a robot. The service serves **100 randomly generated 11×11 mazes** over a TLS socket, each with a five-second deadline, so this is an automation and parsing problem. Four wrinkles make it interesting:

- **Proof of work first.** The banner issues a redpwn PoW; the solver just shells out to the official `https://pwn.red/pow` runner and pipes the solution back over the same connection.
- **A weighted cost model.** Moving onto a tile costs 1 point *plus* the value of any board-game piece on it. Piece families map to costs compactly — chess (pawn 1 … king 100), playing cards (face value, 10 for tens/faces), dice (1–6), dominoes (sum of halves), mahjong (1–9). Several map directly from the Unicode code point, e.g. horizontal dominoes from `U+1F063`:

  ```python
  left, right = divmod(ord(piece) - 0x1F063, 7)
  cost = left + right
  ```

- **ANSI + double-width Unicode parsing.** The entrance/exit are only identifiable by ANSI colors (green `92`, red `91`), so escapes can't be stripped before parsing. And mahjong/domino/card glyphs occupy *two* terminal columns, so the parser must expand wide characters by East Asian width or every wall after the first piece shifts. Colored border segments also dictate the mandatory first and last moves (a green segment on the top border ⇒ start with `D`).

With the maze turned into a weighted graph — directed edge cost `1 + weight(v)` — **Dijkstra's algorithm** finds the minimum-cost path (the challenge guarantees a unique minimum, so the first pop of the exit is the answer). The solver clears all 100 rounds in a few seconds, then reads the flag rendered as **FIGlet art**. One deliberate trap: the font renders uppercase `O` and digit `0` identically; the phrase ("despite all our rage, we're all just rats in a maze") disambiguates it as `OuR`, confirmed by the case-sensitive submission. **Takeaway:** most "captcha" challenges are parsing + shortest-path under a clock — the real work is faithfully reconstructing the board (colors, widths, weights), not the search.

---

## Cursed Maze Captcha — the API hands you the whole maze

> *Flag:* `L3AK{I_H0pe_Y0u_D1dnT_5oLV3_i7_by_h4nD_B3C4u5E_tHAt_W0uLd_B3_trUlY_CuR53D}`

The "cursed" upgrade moves to a web frontend and piles on visual obfuscation: **100 mazes**, each cell an image, the whole board rotated by a random angle, and movement keys interpreted relative to the entrance. It looks nasty — until you look at the API instead of the UI.

### Presentation vs. state

`POST /api/start` returns the entire maze as JSON, including two Boolean wall matrices. Most fields are pure decoration:

| Field | Purpose | Needed? |
|---|---|---|
| `tiles`, `rotation`, `cell`, `start`, `exitOutside` | render the pretty, rotated board | No |
| `entrance`, `exit`, `hWalls`, `vWalls` | the actual graph | Yes |

The board rotation and rotated keyboard controls only affect *human* input — `/api/move` takes absolute `[x, y]` coordinates, so the solver ignores rotation entirely and never downloads a tile image. The wall matrices fully describe every legal edge:

```python
# hWalls[y][x] = boundary above row y ; vWalls[y][x] = boundary left of column x
if nx == x:
    wall = hWalls[max(y, ny)][x]      # vertical move
else:
    wall = vWalls[y][max(x, nx)]      # horizontal move
open_edge = not wall
```

Every move costs one step, so a plain **BFS** from `entrance` to `exit` yields the shortest path.

### Beating the deadline with HTTP pipelining

The catch: the API accepts only one coordinate per request and validates adjacency against the server's *current* position, so you can't jump straight to the exit, and you can't fire moves concurrently (each depends on the prior state update). A naive `requests.post()` loop would eat thousands of sequential round trips and blow the per-round deadline.

The elegant fix is **HTTP/1.1 pipelining**: write every move request for a round to one persistent TLS connection back-to-back, then read the responses in order. The server still sees individually framed requests (each with its own `Content-Length`) and applies them sequentially, but the client pays one round trip per *round* instead of per *move*:

```python
requests = bytearray()
for position in path:
    body = json.dumps({"position": position, "submitToken": token},
                      separators=(",", ":")).encode()
    requests.extend(headers + body)
sock.sendall(requests)                                   # all moves at once
# then parse len(path) ordered HTTPResponse objects off the same socket
```

The final response of round 100 carries `done: true` and the flag. All 100 rounds finish in ~20 seconds. **Takeaway:** when a UI drowns a simple graph in rotation and images, read the API — and when a protocol forces one dependent request per step, pipelining recovers throughput without breaking ordering.

---

## Cross-cutting lessons from the L3akCTF 2026 misc set

Four unrelated-looking challenges, one repeated discipline: **strip the costume, then solve the trivial problem underneath.**

- **Presentation is not payload.** A keyboard typo (me fr), FIGlet art (Maze Captcha), a rotated image board (Cursed Maze Captcha), and theatrical chess games (Blunder) are all wrappers. Identify the underlying object — plaintext, grid drawing, or plain weighted/unweighted graph — and the search or decode is easy.
- **Look before you compute.** me fr and Blunder are solved primarily by *recognizing a pattern* (a physical shift, a letter drawn on a board), not by brute force.
- **Right algorithm for the cost model.** Weighted tiles ⇒ Dijkstra (Maze Captcha); uniform steps ⇒ BFS (Cursed Maze Captcha). Matching the algorithm to the metric keeps both well within the deadline.
- **Automation is a first-class skill.** Half the misc points here came from faithful parsing (ANSI colors, double-width Unicode) and transport engineering (PoW automation, HTTP pipelining) rather than clever math.

## Reproduce it yourself

Every challenge ships a standalone, standard-library-only Python solver at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026) under `misc/<challenge>/`. me fr and Blunder run offline against their handout files; Maze Captcha and Cursed Maze Captcha connect to a live instance (pass the current instance URL as an argument, since the platform rotates hostnames). Each per-challenge `README.md` includes the full decoding tables, per-game letter grids, and reproduction commands.

Pair this with the companion [L3akCTF 2026 pwn writeup](/ctf-writeups/l3akctf-2026-pwn-writeup/) and [L3akCTF 2026 crypto writeup](/ctf-writeups/l3akctf-2026-crypto-writeup/), or browse the full [CTF writeups](/ctf-writeups/) archive.

---

*This writeup is part of the CyberSecurity Elite [L3akCTF 2026](/series/l3akctf-2026/) series. Challenge files and complete solver scripts for all four miscellaneous challenges are published at [github.com/Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026).*
