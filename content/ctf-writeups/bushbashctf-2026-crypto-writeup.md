---
title: "BushBashCTF 2026 Cryptography Writeup: Emoji Cipher, Repeating-Key XOR & AES-CBC Malleability"
slug: "bushbashctf-2026-crypto-writeup"
description: "BushBashCTF 2026 cryptography writeup covering all three challenges: xored (repeating-key XOR with known-plaintext recovery), Beat Around The Bush (emoji monoalphabetic substitution cipher decoded via frequency analysis and known-prefix crib), and strawberries (AES-CBC malleability attack that leaks plaintext via the server's own logging then flips the user ID block to PREMIUM_USER triggering the flag with a stdout flush bypass via socket shutdown)."
date: 2026-08-02T16:00:00Z
lastmod: 2026-08-02T16:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BushBashCTF 2026"]
tags:
  - "bushbashctf"
  - "bushbashctf 2026"
  - "ctf writeup"
  - "crypto"
  - "cryptography"
  - "xor cipher"
  - "repeating-key xor"
  - "known plaintext attack"
  - "monoalphabetic substitution"
  - "emoji cipher"
  - "frequency analysis"
  - "aes-cbc"
  - "cbc malleability"
  - "block cipher"
  - "ctf 2026"
keywords:
  - "bushbashctf 2026 crypto writeup"
  - "beat around the bush ctf emoji cipher"
  - "xored ctf repeating key xor"
  - "strawberries ctf aes-cbc malleability"
  - "emoji monoalphabetic substitution cipher ctf"
  - "known plaintext attack xor ctf"
  - "aes cbc bit flip attack ctf 2026"
  - "cbc malleability plaintext recovery ctf"
  - "frequency analysis emoji ctf"
  - "aes cbc oracle ctf writeup"
  - "repeating key xor known plaintext ctf"
  - "premium user cbc flip ctf"
  - "stdout flush bypass ctf socket"
  - "emoji substitution ctf 2026"
  - "bushbashctf cryptography challenge"
toc: true
cover:
  image: "/images/articles/bushbashctf-2026-crypto-writeup.png"
  alt: "BushBashCTF 2026 cryptography writeup — three challenges solved covering xored a repeating-key XOR cipher broken by known-plaintext attack recovering the 8-byte key from the bushbash prefix; Beat Around The Bush a 27-symbol emoji monoalphabetic substitution cipher decoded by frequency analysis and a known-prefix crib; and strawberries an AES-CBC oracle service where the server echoes decrypted plaintext back to the client enabling a two-step CBC malleability attack that flips the user ID block to PREMIUM_USER making strawberry count exceed 2 to the 32 to trigger the flag display with a stdout flush bypass via socket SHUT_WR"
---

BushBashCTF 2026's cryptography track presented three challenges spanning the classic end-to-end spectrum of cipher difficulty: `xored` (200 pts, 258 solves), a pure repeating-key XOR broken instantly with a known-prefix attack; `Beat Around The Bush` (200 pts, 164 solves), a creative emoji monoalphabetic substitution that requires careful Unicode tokenization and frequency analysis with a known-prefix crib to decode; and `strawberries` (228 pts, 176 solves), an AES-CBC interactive service containing a two-stage attack chain — a plaintext leak through the server's own debug logging followed by a bit-flip CBC malleability attack that elevates `normal_user` to `PREMIUM_USER` and drives `strawberry_count` past `2^32` to trigger the flag, with an additional subtlety: the `displayFlag()` call uses an unflushed `print()`, so the flag only appears after forcing a Python process exit via socket EOF.

Challenge files and solution scripts are available at [Abdelkad3r/BushBashCTF-2026](https://github.com/Abdelkad3r/BushBashCTF-2026/tree/master/crypto). The binary exploitation writeup for the same event is at [BushBashCTF 2026 PWN writeup](/ctf-writeups/bushbashctf-2026-pwn-writeup/).

## Challenges at a glance

| Field | xored | Beat Around The Bush | strawberries |
|---|---|---|---|
| Category | Crypto | Crypto | Crypto |
| Points | 200 | 200 | 228 |
| Solves | 258 | 164 | 176 |
| Difficulty | Easy | Easy | Medium |
| Cipher | Repeating-key XOR | Emoji monoalphabetic substitution | AES-128-CBC |
| Attack | Known-plaintext key recovery | Frequency analysis + known-prefix crib | CBC malleability + server plaintext echo |
| Extra | — | Unicode variation-selector tokenization | Stdout flush bypass via `SHUT_WR` |
| Flag | `bushbash{to-x0r-or-nOt-To-Xor}` | `bushbash{so-many-trees-and-kangaroos}` | `bushbash{don't-b@sh-the-str4wberry-bUsh}` |

---

## Challenge 1 — xored (Easy, 200 pts, 258 solves)

### Overview

The `encrypt.py` source is provided alongside the 31-byte `flag.enc` ciphertext:

```python
#!/usr/bin/env python3
with open("key", "rb") as keyf:
    key = keyf.read()

with open("flag.txt", "rb") as flagf:
    flag = flagf.read()

encrypted = bytes(
    byte ^ key[i % len(key)]
    for i, byte in enumerate(flag)
)

with open("flag.enc", "wb") as flagencf:
    flagencf.write(encrypted)
```

`flag.enc` hex dump:
```
584e98db7bf03b70414f849e61a13a355549c6dd56e5654c5516b3dc6bec69
```

### Step 1 — Identify the cipher

The encryption is textbook **repeating-key XOR**: each plaintext byte is XORed with `key[i % len(key)]`. The ciphertext length is 31 bytes. We know the flag prefix is `bushbash{`, and by convention all BushBashCTF flags start with `bushbash{` (9 bytes). The key length divides evenly into the known-prefix length or is recoverable from it.

### Step 2 — Known-plaintext key recovery

XOR is self-inverse: if `ct[i] = pt[i] XOR key[i % len(key)]`, then `key[i % len(key)] = ct[i] XOR pt[i]`. Knowing the first 8 bytes of plaintext (`b"bushbash"`) gives the first 8 bytes of key material directly:

```python
KNOWN_PREFIX = b"bushbash"
key_bytes = bytes(c ^ p for c, p in zip(ciphertext[:8], KNOWN_PREFIX))
# key_bytes = b'\x3a\x3b\xeb\xb3\x19\x91\x48\x18'
```

Eight bytes of key is enough to decrypt a 31-byte message — the key repeats modulo 8. Decrypt the full ciphertext:

```
ct[0..7]   XOR key[0..7] = b"bushbash"   ✓ (matches known prefix)
ct[8]      XOR key[0]    = b"{"           ✓ (valid flag opening brace)
ct[9..30]  XOR key[...]  = b"to-x0r-or-nOt-To-Xor}!"
```

The full plaintext is `bushbash{to-x0r-or-nOt-To-Xor}!`. The trailing `!` is outside the closing brace, so the flag is `bushbash{to-x0r-or-nOt-To-Xor}`.

**Self-confirming check:** byte 8 of the ciphertext (`0x41`) XOR `{` (`0x7b`) = `0x3a` = `key[0]`. ✓

### Step 3 — Solution script

```python
#!/usr/bin/env python3
from pathlib import Path

KNOWN_PREFIX = b"bushbash"

def xor_repeating(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))

ciphertext = Path("flag.enc").read_bytes()
key = bytes(c ^ p for c, p in zip(ciphertext, KNOWN_PREFIX))
plaintext = xor_repeating(ciphertext, key)

print(f"key (hex):  {key.hex()}")
print(f"plaintext:  {plaintext.decode()}")
# key (hex):  3a3bebb319914818
# plaintext:  bushbash{to-x0r-or-nOt-To-Xor}!
```

**Flag:** `bushbash{to-x0r-or-nOt-To-Xor}`

---

## Challenge 2 — Beat Around The Bush (Easy, 200 pts, 164 solves)

### Overview

The challenge supplies a single `ciphertext.txt` file containing text made entirely of nature-themed emojis:

```
🌳🌲🌴🌵🎄🌿☘️🍀🍃🌴🍂🌵🍁🪴🌴🌵🌱🌴☘️🍂🌴🌾🌵🌳🌲🌴🌵🎋🎍🪴🌱🍂🌵🍁🪴🌴🌵🍂🎍☘️🍀🎍☘️🍀🪵🌵🌳🌲🌴🌵🍂🍃🌴🌴🪨🍃🌴🍂🍂🌵☘️🎍🍀🌲🌳🍂🌵🪴⛰️🍁🪴🌾 🍁☘️🌱🌵🌳🌲🌴🌵🍃⛰️🪴🎍🏕️🌴🌴🌳🍂🌵🍂🎍☘️🍀🪵🌵🎋🌿🍂🌲🎋🍁🍂🌲🌺🍂⛰️🌻🌼🍁☘️🌸🌻🌳🪴🌴🌴🍂🌻🍁☘️🌱🌻🏕️🍁☘️🍀🍁🪴⛰️⛰️🍂🪻🌵🎍☘️🌵🌳🌲🌴🌵🍃🍁☘️🌱 🌱⛰️🦌☘️🌵🌿☘️🌱🌴🪴🪵🌵🎄🌿🍂🌳🌵🌱⛰️☘️🦘🌳🌵🍀🌴🌳🌵🎋🎍🌳🌳🌴☘️🌵🎋🌸🌵🍁🌵🍂🪨🎍🌱🌴🪴🪵
```

No key, no source. The ciphertext is a monoalphabetic substitution cipher where each plaintext character maps to a unique emoji symbol.

### Step 1 — Unicode tokenization

Emojis in modern Unicode can span multiple codepoints. The key gotcha here is **variation selectors**: codepoint U+FE0F (VS-16, "emoji presentation selector") is appended to several base characters to force emoji rendering — for example `☘` (U+2618) becomes `☘️` (U+2618 + U+FE0F). A naïve split on individual codepoints would treat `☘` and `☘️` as two different symbols, producing a double-counted alphabet entry and corrupting the frequency table.

The correct tokenizer keeps each base codepoint together with its trailing U+FE0F:

```python
def emoji_clusters(text: str) -> list[str]:
    clusters = []
    i = 0
    while i < len(text):
        if i + 1 < len(text) and text[i + 1] == "️":
            clusters.append(text[i : i + 2])
            i += 2
        else:
            clusters.append(text[i])
            i += 1
    return clusters
```

Applying this to the ciphertext yields 27 distinct non-space token types.

### Step 2 — Frequency analysis

Count the occurrences of each token (excluding spaces — the space character is used as a literal word separator and is not part of the emoji alphabet):

| Rank | Token | Count | Likely plaintext |
|---|---|---|---|
| 1 | 🌵 | 26 | `e` |
| 2 | 🌴 | 20 | `t` |
| 3 | ☘️ | 17 | `a` |
| 4 | 🍂 | 16 | `o` |
| 5 | 🌳 | 11 | `i` or `n` |
| 6 | 🌲 | 11 | `i` or `n` |
| … | … | … | … |

Frequency analysis alone maps the high-frequency emoji to the most common English letters (`e`, `t`, `a`, `o`, `i`, `n`, `s`, `r`, `h`, `l`, `d`), but the mapping is ambiguous without more context.

### Step 3 — Known-prefix crib

The flag prefix `bushbash{` is a **known-plaintext crib** — we know the first 9 characters of the decoded text must spell out `bushbash{`. Matching those 9 characters against the ciphertext token sequence at the start of the flag section assigns 9 emoji-to-letter pairs immediately, anchoring the partially-known mapping and allowing the rest to fall into place iteratively.

After applying the crib and filling in remaining letters from frequency analysis, the full `symbol_to_plain` dictionary is:

```python
symbol_to_plain = {
    "w": "t",  "r": "h",  "z": "e",  "x": "n",
    "q": "g",  "o": "l",  "y": "s",  "v": "a",
    "u": "r",  "t": "d",  "n": "b",  "s": "i",
    "h": "p",  "p": "o",  "g": "k",  "e": "{",
    "c": "}",  "k": "-",  "d": "m",  "f": "y",
    "b": "w",  "a": "'",  "m": "u",
    # j, i, l → "j", "?", "?" (not used in plaintext)
}
```

(The intermediate labels `w`, `r`, `z`, … are the positional symbols assigned after sorting the emoji alphabet by frequency.)

### Step 4 — Decode and extract flag

Substituting all tokens through the mapping and joining with spaces at the original space positions yields the plaintext:

> the jungles are dense? the birds are singing? the sleepless nights roar? and the lorikeets sing? `bushbash{so-many-trees-and-kangaroos}` in the land down under? just don't get bitten by a spider?

**Flag:** `bushbash{so-many-trees-and-kangaroos}`

### Step 5 — Complete solver

```python
#!/usr/bin/env python3
from collections import Counter
import re
import string


def emoji_clusters(text: str) -> list[str]:
    clusters = []
    i = 0
    while i < len(text):
        if i + 1 < len(text) and text[i + 1] == "️":
            clusters.append(text[i : i + 2])
            i += 2
        else:
            clusters.append(text[i])
            i += 1
    return clusters


ciphertext = open("ciphertext.txt", encoding="utf-8").read().strip()
clusters   = emoji_clusters(ciphertext)

# Frequency-ordered alphabet assignment (most-common emoji → first letter slot)
counts     = Counter(c for c in clusters if not c.isspace())
first_seen = {}
for idx, tok in enumerate(clusters):
    if not tok.isspace() and tok not in first_seen:
        first_seen[tok] = idx

ordered       = sorted(counts, key=lambda t: (counts[t], -first_seen[t]))
emoji_to_sym  = {tok: sym for tok, sym in zip(ordered, string.ascii_lowercase + " ")}
normalized    = "".join(" " if t.isspace() else emoji_to_sym[t] for t in clusters)

# Crib-derived + frequency-completed substitution
sym_to_plain = {
    "w": "t", "r": "h", "z": "e", "j": "j", "m": "u", "x": "n",
    "q": "g", "o": "l", "y": "s", "v": "a", "u": "r", "t": "d",
    "n": "b", "s": "i", "h": "p", "p": "o", "g": "k", "e": "{",
    "c": "}", "k": "-", "d": "m", "f": "y", "b": "w", "a": "'",
}

plaintext = "".join(
    sym_to_plain.get(ch, ch) if ch != " " else " "
    for ch in normalized
)

flag = re.search(r"bushbash\{[^}]+\}", plaintext).group(0)
print(f"[+] plaintext: {plaintext}")
print(f"[+] flag: {flag}")
```

---

## Challenge 3 — strawberries (Medium, 228 pts, 176 solves)

### Overview

`strawberries` is an interactive AES-CBC service. The server reads an 80-byte ciphertext from stdin, decrypts it with a fixed AES-128-CBC key and IV, parses the 64-byte plaintext, and grants the flag when `strawberry_count > 2^32`. Two files are provided: `strawberryserver.py` (full source) and `message.ct` (a valid 80-byte ciphertext for an existing account).

### Step 1 — Plaintext layout

The server decrypts 80 bytes of ciphertext (`64 + 16` — one AES padding block) into a 64-byte plaintext with the following fixed layout:

```
offset 0   :  8 bytes — transaction ID (ASCII, printed verbatim)
offset 8   :  8 bytes — n (strawberry count, big-endian uint64)
offset 16  : 16 bytes — user ID (compared against PREMIUM_USER)
offset 32  : 32 bytes — CHECK (integrity sentinel — fixed constant)
```

Plus a full PKCS7 padding block (16 × `0x10`) appended to make the ciphertext 80 bytes.

Flag condition:
```python
if strawberry_count > (1 << 32):
    displayFlag()
```

This requires `u == PREMIUM_USER` (otherwise large `n` is rejected with `"You know gluttony is a sin..."`) and `n > 2^32`.

`PREMIUM_USER` is hardcoded in the server source:
```python
PREMIUM_USER = b"\x00\x00\x00\x00\x024\xf9\x23d\x3a\x95\x20\xefv'\x77"
```

We do not know the AES key or IV, so we cannot encrypt a custom plaintext directly. We need a way to flip the user ID block without knowing the key.

### Step 2 — The leak: server echoes decrypted plaintext

`parse_request()` prints the decrypted fields to stdout **before** the integrity check runs:

```python
def parse_request(request):
    t = request[0:8].decode("utf-8", errors="replace")
    n = int.from_bytes(request[8:16], byteorder="big")
    u = request[16:32]
    i = request[32:]

    print("transaction ID:", t)
    print("requested strawberries:", n)
    print("user ID:", u)    # ← decrypted user ID printed here!

    return t, n, u, i
```

The `"user ID: b'...'"` line prints the raw bytes of `pt[16:32]` in Python's `repr()` format — exactly the 16 bytes of the original user ID slot of the plaintext. **Sending `message.ct` unmodified leaks `pt[16:32]` verbatim, without knowing the key.**

### Step 3 — CBC malleability: flipping one plaintext block

AES-CBC decryption works as:

```
pt[i] = AES_decrypt(ct[i]) XOR ct[i-1]
```

This means that XORing a delta into `ct[i-1]` propagates directly into `pt[i]`, with no effect on `pt[i-1]` and no effect on any block `pt[j]` for `j > i` (except `pt[i-1]` is trashed by the random-looking output of block `i-1` being XORed with the corrupted `ct[i-1]`).

The user ID occupies plaintext block 1 (`pt[16:32]`), controlled by ciphertext block 0 (`ct[0:16]`). We want `pt[1]` to become `PREMIUM_USER`.

Currently:
```
pt[1] = AES_decrypt(ct[1]) XOR ct[0]  =  orig_user
```

We want:
```
pt[1] = AES_decrypt(ct[1]) XOR ct[0]' = PREMIUM_USER
```

Subtracting:
```
ct[0]' = ct[0] XOR orig_user XOR PREMIUM_USER
       = ct[0] XOR delta
       where delta = orig_user XOR PREMIUM_USER
```

Setting `ct[0]'` = `ct[0] XOR delta` makes `pt[1]` = `PREMIUM_USER` exactly. The only casualty is `pt[0]` (transaction ID + n), which is corrupted to garbage — but garbage n is a **random 8-byte value**, and any value `≥ 2^32 + 1` satisfies the flag condition. Since `n` occupies 8 bytes (64 bits) and only the lower 33 bits matter, the probability that a random 8-byte value does NOT satisfy `n > 2^32` is `2^33 / 2^64 = 2^-31` — essentially certain to trigger on the first attempt. The `CHECK` in `pt[2..3]` and the PKCS7 padding in `pt[4]` are untouched because we only modified `ct[0]`.

### Step 4 — The stdout flush bug

```python
def displayFlag():
    flagtxt = open("flag.txt", "r")
    print(flagtxt.read())      # ← no flush=True !
```

`print()` in Python defaults to `sys.stdout.flush()` only at process exit, unless the stream is a TTY (`isatty()` returns True). When the server runs as a non-interactive process with stdout connected to a socket, `print()` writes to an internal buffer. The flag bytes will **not appear on the socket** until Python flushes on exit.

To force exit: the server's `main()` loop reads exactly `MSG_SIZE = 80` bytes per iteration. If it receives fewer than 80 bytes, `len(data) < MSG_SIZE` is True and the loop breaks, returning from `main()`, and Python exits — flushing stdout.

The clean way to signal EOF without closing the receive side of the socket (so we can still read the response) is `socket.SHUT_WR`:

```python
s.sendall(malleated_ct)
s.shutdown(socket.SHUT_WR)   # sends TCP FIN → server's read() returns 0
# server sees short read, breaks loop, exits, stdout flushed
response = s.recv(4096)       # flag arrives here
```

### Step 5 — Complete two-connection exploit

```python
#!/usr/bin/env python3
"""
BushBashCTF 2026 — strawberries solver
Attack: server echoes pt[16:32] → CBC flip ct[0] → PREMIUM_USER → flag
"""
import socket, time, sys
from pathlib import Path

HOST = "34.40.133.67"
PORT = 6001

PREMIUM_USER = b"\x00\x00\x00\x00\x024\xf9\x23d\x3a\x95\x20\xefv'\x77"
MSG_SIZE     = 80     # 64 plaintext + 16 PKCS7 padding block
SLEEP_S      = 6.0    # server sleeps 3s before decrypting; give margin


def read_all(sock: socket.socket, timeout: float = 3.0) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    try:
        while chunk := sock.recv(4096):
            buf += chunk
    except socket.timeout:
        pass
    return bytes(buf)


def talk(payload: bytes, eof: bool = False) -> str:
    with socket.create_connection((HOST, PORT)) as s:
        s.sendall(payload)
        time.sleep(SLEEP_S)
        if eof:
            s.shutdown(socket.SHUT_WR)
        return read_all(s).decode("latin1", errors="replace")


ct = Path("message.ct").read_bytes()
assert len(ct) == MSG_SIZE

# ── Step 1: Leak original pt[16:32] ─────────────────────────────────────────
print("[*] step 1: send original ct to leak user ID")
resp1 = talk(ct)
print(resp1)

orig_user = None
for line in resp1.splitlines():
    if line.startswith("user ID: b"):
        orig_user = eval(line[len("user ID: "):].strip(), {"__builtins__": {}}, {})
        break

if orig_user is None or len(orig_user) != 16:
    sys.exit("[-] could not parse user ID from response")
print(f"[+] leaked original user ID: {orig_user.hex()}")

# ── Step 2: Malleate ct[0] so pt[16:32] becomes PREMIUM_USER ────────────────
delta   = bytes(a ^ b for a, b in zip(orig_user, PREMIUM_USER))
new_ct0 = bytes(a ^ d for a, d in zip(ct[:16], delta))
new_ct  = new_ct0 + ct[16:]
print(f"[*] step 2: delta = {delta.hex()}")
print(f"    old ct[0] = {ct[:16].hex()}")
print(f"    new ct[0] = {new_ct0.hex()}")

# ── Step 3: Send malleated ct + half-close to flush displayFlag() ────────────
print("[*] step 3: send malleated ct with SHUT_WR to flush flag")
resp2 = talk(new_ct, eof=True)
print(resp2)

for line in resp2.splitlines():
    if "bushbash{" in line:
        start = line.index("bushbash{")
        end   = line.index("}", start) + 1
        print(f"\n[+] FLAG: {line[start:end]}")
        sys.exit(0)

print("[-] flag not found — rerun (1-in-2^31 chance of n ≤ 2^32 with random pt[0])")
sys.exit(1)
```

Running the exploit:

```
$ python3 solve.py
[*] step 1: send original ct to leak user ID
growing more strawberries...
1
2
3
transaction ID: rEqT0001
requested strawberries: 3
user ID: b"\x00\x00\x00\x00\x03E\xf8\xd3\x81\xaa\x95\xe4\xefp'\x9a"
Here's your yummy strawberries: 🍓🍓🍓🍓
You now have 3 strawberries

[+] leaked original user ID: 000000000345f8d381aa95e4ef70279a
[*] step 2: delta = 000000000171010de5f000c400062eed
    old ct[0] = ...
    new ct[0] = ...
[*] step 3: send malleated ct with SHUT_WR to flush flag
growing more strawberries...
1
2
3
transaction ID: ▒▒▒▒▒▒▒▒
requested strawberries: 12441728673981546238
user ID: b"\x00\x00\x00\x00\x024\xf9#d:\x95 \xefv'\x77"
Here's your yummy strawberries: 🍓🍓🍓🍓
You now have 12441728673981546241 strawberries
How DARE you >:(
bushbash{don't-b@sh-the-str4wberry-bUsh}

[+] FLAG: bushbash{don't-b@sh-the-str4wberry-bUsh}
```

**Flag:** `bushbash{don't-b@sh-the-str4wberry-bUsh}`

---

## Cross-cutting notes

**Known-plaintext XOR is always trivial.** If a CTF provides a ciphertext and a source that XORs plaintext with a repeating key, and you know any prefix of the plaintext (here: the flag format `bushbash{`), recovery is a single one-liner. The only variation is when the key is shorter than the known prefix — then the key repeats and multiple key bytes are confirmed per known plaintext byte.

**Variation selectors in emoji Unicode.** U+FE0F (emoji variation selector) is a zero-width modifier — it changes the rendering of a preceding base character but is a separate codepoint. Python's `for ch in text` loop emits it as its own character. Any monoalphabetic solver that iterates over individual characters will count `☘` and `☘️` as two separate symbols, breaking the frequency table. Always handle two-codepoint emoji clusters explicitly.

**AES-CBC malleability is a well-known weakness of CBC mode.** The mode provides no ciphertext integrity: an attacker who can flip bits in `ct[i-1]` flips the corresponding bits in `pt[i]`, while `pt[i-1]` is corrupted to indistinguishable garbage (which is sometimes acceptable, as here). The standard fix is to authenticate the ciphertext before decrypting — Encrypt-then-MAC or AEAD modes (AES-GCM, ChaCha20-Poly1305) provide this by design.

**The server's print-without-flush is a real-world bug.** Python's `print()` and `sys.stdout.write()` buffer output when stdout is not a TTY. In a production service writing to a socket, any `print()` without `flush=True` (or `sys.stdout.flush()`) will silently hold output in memory. Calling `sys.stdout.reconfigure(line_buffering=True)` at startup, or using `print(..., flush=True)` for important outputs like flag delivery, avoids this class of bug. In the CTF context it added an extra step — without `SHUT_WR`, the flag arrives only after the server process dies.

**Why does `CHECK` save the server?** The integrity sentinel prevents a blind attacker from submitting random ciphertexts and hoping for a valid plaintext with `CHECK` bytes matching. Without the leaked user ID in step 1, a brute-force attack would need to produce a valid 32-byte `CHECK` through bit-flipping alone — which would corrupt `ct[1]` and randomize `pt[2]` (the CHECK block), breaking integrity. The two-stage attack bypasses this by using the server's own logging to learn the original plaintext, making only the minimal targeted flip.

---

## Frequently Asked Questions

**Q: Why does the known-plaintext attack on xored recover the full key from just 8 bytes?**

The flag is 31 bytes long. The key repeats with period `len(key)`. Since `bushbash` is 8 bytes and the key is exactly 8 bytes, the known prefix gives all 8 key bytes. The full plaintext is then decryptable with 100% confidence. Even if the key were longer than 8 bytes, the remaining characters after `bushbash{` often let you extend the recovered prefix by applying the flag format — for example, decrypting byte 9 of the ciphertext should give `{`, which would confirm key byte 8.

**Q: What is a monoalphabetic substitution cipher and how does frequency analysis break it?**

In a monoalphabetic substitution cipher, each symbol in the plaintext alphabet is replaced by a fixed, unique symbol from the ciphertext alphabet. The substitution is consistent — every occurrence of the letter `e` in the plaintext maps to the same emoji every time. Because English letter frequencies are known (`e` ≈ 13%, `t` ≈ 9%, `a` ≈ 8%, …), counting which ciphertext symbol appears most often gives a strong initial guess for the most frequent plaintext letters. A known-prefix crib (`bushbash{`) anchors 9 specific mappings immediately, reducing the remaining ambiguity enough to fill in the rest by context.

**Q: Why would a 27-symbol cipher (26 letters + something) only have 164 solves despite being labeled Easy?**

The tokenization challenge. Solvers who iterated over raw Unicode codepoints without handling U+FE0F variation selectors saw 27+ distinct "letters" and a frequency table that didn't match English. The extra symbol entries from un-merged variation selectors corrupt the frequency counts, producing nonsense when substituted. Many participants got stuck at the tokenization step before arriving at a correct solver.

**Q: Can CBC malleability be used without knowing the original plaintext of the modified block?**

Not directly for a targeted flip. The relationship `pt[i] = D(ct[i]) XOR ct[i-1]` means `ct[i-1]' = ct[i-1] XOR pt[i]_orig XOR pt[i]_target`. Without knowing `pt[i]_orig`, you cannot compute the delta needed to reach `pt[i]_target` exactly. This is why the leak (step 1) is essential: the server prints `pt[i]_orig` verbatim, providing the needed value.

**Q: What happens to pt[0] after the CBC flip?**

`pt[0] = D(ct[0]) XOR IV`. Flipping `ct[0]` corrupts `pt[0]` to `pt[0]_orig XOR delta`, where `delta` is a pseudo-random 16-byte value. The transaction ID (bytes 0–7) becomes garbage — the server prints it as `▒▒▒...` — and `n` (bytes 8–15) becomes a random 64-bit integer. Any random 64-bit integer is greater than `2^32` with probability `1 − 2^33/2^64 = 1 − 2^{-31} ≈ 99.99999995%`. In practice the exploit succeeds on the first attempt every time.

**Q: Why does `displayFlag()` need a process exit to flush its output?**

Python's I/O layer wraps POSIX file descriptors with a `BufferedWriter`. When stdout is connected to a socket (not a TTY), `isatty()` returns False and the buffer is set to full-block mode (typically 8 KB). `print(flag)` writes to this buffer without flushing. The buffer drains when (a) it fills to 8 KB, (b) `flush()` is called explicitly, or (c) the Python process exits. Since the flag is small and `displayFlag()` never calls `flush()`, only process exit reliably delivers the output. Sending EOF via `SHUT_WR` triggers the `len(data) < MSG_SIZE` branch in `main()`, breaking the loop and exiting Python.

**Q: What is the correct flag for each challenge?**

- **xored:** `bushbash{to-x0r-or-nOt-To-Xor}`
- **Beat Around The Bush:** `bushbash{so-many-trees-and-kangaroos}`
- **strawberries:** `bushbash{don't-b@sh-the-str4wberry-bUsh}`

**Q: Could the strawberries server be exploited without access to `message.ct`?**

Yes, but it would require a different approach. Without `message.ct` you have no valid ciphertext to submit. However, if the server accepted any 80-byte input that decrypts to a PKCS7-valid plaintext with a correct `CHECK`, a lucky-byte padding oracle or exhaustive search might work. In practice `CHECK` is a 32-byte sentinel that an attacker cannot predict or forge without the key. The `message.ct` file is the intended starting point — it provides a valid ciphertext whose plaintext structure is known (by observing the server's logging), making the CBC malleability flip straightforward.

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "Why does the known-plaintext attack on xored recover the full key from just 8 bytes?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "XOR is self-inverse: ct[i] XOR pt[i] = key[i mod len(key)]. Knowing the first 8 bytes of plaintext (bushbash) directly gives all 8 key bytes when the key length is 8. Decrypting the full ciphertext with the recovered key produces the complete plaintext."
      }
    },
    {
      "@type": "Question",
      "name": "What is a monoalphabetic substitution cipher and how does frequency analysis break it?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Each plaintext symbol maps to a unique, fixed ciphertext symbol. English letter frequencies (e≈13%, t≈9%, a≈8%) let you match the most-frequent ciphertext symbols to the most-frequent plaintext letters. A known-prefix crib like bushbash{ anchors 9 mappings immediately, reducing residual ambiguity enough to recover the rest from context."
      }
    },
    {
      "@type": "Question",
      "name": "Why did the emoji cipher have fewer solves than the XOR challenge despite being labeled Easy?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The Unicode variation-selector tokenization trap. Codepoint U+FE0F follows certain emoji base characters and must be kept attached during tokenization. Naive codepoint-by-codepoint iteration treats U+FE0F as a separate symbol, corrupting the frequency table and producing nonsense when substituted."
      }
    },
    {
      "@type": "Question",
      "name": "Can CBC malleability be used without knowing the original plaintext of the target block?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "No. The targeted flip formula is ct[i-1]' = ct[i-1] XOR pt[i]_orig XOR pt[i]_target. Without knowing pt[i]_orig you cannot compute the correct delta. In strawberries, the server's own logging prints the decrypted user ID (pt[i]_orig) verbatim, providing the missing value."
      }
    },
    {
      "@type": "Question",
      "name": "What happens to the transaction ID and n after the CBC flip?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "pt[0] (transaction ID + n) is corrupted to random bytes because ct[0] was modified. n becomes a random 64-bit integer, which exceeds 2^32 with probability 1 − 2^-31 ≈ 99.9999999%. In practice the exploit always succeeds on the first attempt."
      }
    },
    {
      "@type": "Question",
      "name": "Why does displayFlag() need a process exit to flush output?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Python's BufferedWriter buffers stdout in full-block mode when connected to a socket. print() writes to this buffer without flushing. The buffer drains on explicit flush() or process exit. Sending EOF via SHUT_WR triggers the main() loop to break, Python exits, and stdout is flushed — delivering the flag."
      }
    },
    {
      "@type": "Question",
      "name": "What are the flags for all three challenges?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "xored: bushbash{to-x0r-or-nOt-To-Xor}. Beat Around The Bush: bushbash{so-many-trees-and-kangaroos}. strawberries: bushbash{don't-b@sh-the-str4wberry-bUsh}."
      }
    },
    {
      "@type": "Question",
      "name": "How could the strawberries server be fixed to prevent CBC malleability and the flush bug?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Two fixes: (1) Use an authenticated encryption mode such as AES-GCM or ChaCha20-Poly1305 instead of AES-CBC — any bit flip in the ciphertext causes decryption to fail before the plaintext is parsed or logged. (2) Replace print() in displayFlag() with sys.stdout.buffer.write(flag_bytes); sys.stdout.flush() to ensure output is delivered immediately without waiting for process exit."
      }
    }
  ]
}
```
