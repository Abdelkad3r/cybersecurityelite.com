---
title: "z0d1akCTF 2026 Qualifiers Web Exploitation Writeup: All 4 Web Challenges Solved"
slug: "z0d1akctf-2026-qualifiers-web-writeup"
description: "Complete z0d1akCTF 2026 Qualifiers Web Exploitation writeup covering all four Web challenges. captcha — a four-check human-verification gate whose verify endpoint mints a JWT proof scoped to session and attempt asserting human equals true but containing no reference to which check was solved, so one proof minted by solving the trivial pipe puzzle replays across all four accepts including the physically infeasible race lap. hydra-fc-will-come-back — VAR telemetry appeal service whose compare endpoint refuses to return restricted fixtures alone but happily includes them when a public anchor match is bundled in the same request, leaking the validated EAST-CAL-042 profile at kick frame 154828 so replacing the bad CAM-EAST profile turns a plus-11 mm offside into a minus-37 mm onside appeal. Middle-Out — browser to gateway to native worker Pied Piper parody where three implementation mismatches compose (gateway identifies fields by full key string but worker dispatches by 32-bit FNV-1a fingerprint only, gateway permits unknown lowercase extension keys so lowercase FNV-1a collisions of center and radius survive preflight but overwrite the privileged fields in the worker via later-wins ordering, and the worker checks center plus radius against payload end but never checks center greater or equal radius so center equals zero and radius equals 1024 reads 1 KiB before the payload pointer); leaked WSC4 capsules yield Shamir shares that interpolate to the HMAC signing key which forges a founder token. Sprout and About — Next.js plant shop whose sprout_session cookie is a JWT with role in payload; the server accepts an unsigned JWT with header alg equals none, so forging role equals ADMIN grants access to slash admin where a leaked preview token calls slash api slash admin slash preview-context that returns a moderation JSON blob containing finalFlag."
date: 2026-08-30T23:00:00Z
lastmod: 2026-08-30T23:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["z0d1akCTF 2026 Qualifiers"]
tags:
  - "z0d1akctf"
  - "z0d1akctf 2026"
  - "z0d1ak ctf"
  - "z0d1akctf qualifiers"
  - "ctf writeup"
  - "web exploitation"
  - "web"
  - "web security"
  - "jwt bypass"
  - "alg none"
  - "unsigned jwt"
  - "next.js"
  - "next.js session cookie"
  - "role escalation"
  - "authorization scoping"
  - "missing scope in token"
  - "captcha bypass"
  - "websocket challenge"
  - "access control bypass"
  - "response filter bypass"
  - "restricted fixture leak"
  - "parser differential"
  - "fnv-1a hash collision"
  - "gateway vs worker mismatch"
  - "wasm reverse engineering"
  - "shamir secret sharing"
  - "gf256 interpolation"
  - "hmac token forgery"
  - "preview token leak"
  - "moderation context disclosure"
  - "captcha"
  - "hydra fc will come back"
  - "middle-out"
  - "sprout and about"
  - "ctf 2026"
keywords:
  - "z0d1akctf 2026 qualifiers web writeup"
  - "z0d1akctf 2026 web exploitation writeup"
  - "z0d1akctf captcha writeup"
  - "z0d1akctf hydra-fc-will-come-back writeup"
  - "z0d1akctf middle-out writeup"
  - "z0d1akctf sprout and about writeup"
  - "jwt alg none bypass next.js ctf"
  - "captcha proof replay across checks ctf"
  - "compare endpoint restricted fixture leak via public anchor ctf"
  - "fnv-1a lowercase collision gateway vs worker ctf"
  - "wsc4 shamir shares gf256 hmac key recovery ctf"
  - "preview token moderation context flag disclosure"
  - "z0d1akctf 2026 solutions"
  - "ctf web exploitation step by step 2026"
toc: true
cover:
  image: "/images/articles/z0d1akctf-2026-qualifiers-web-writeup.png"
  alt: "z0d1akCTF 2026 Qualifiers Web Exploitation writeup cover — all four Web challenges solved. captcha replays a single JWT proof across all four verification checks because the proof asserts human equals true but never names which check produced it. hydra-fc-will-come-back exploits a compare endpoint that returns restricted fixtures when bundled with a public anchor match, leaking the validated EAST-CAL-042 profile to correct a bad plus-11 mm offside call into a minus-37 mm onside appeal. Middle-Out chains three implementation mismatches (gateway identifies fields by full name but worker dispatches by 32-bit FNV-1a hash, lowercase collisions of center and radius survive preflight, and the worker never checks that center is greater than or equal to radius) to read 1 KiB before the payload pointer, leak WSC4 sealed Shamir shares, interpolate the HMAC key in GF256, and forge a founder license token. Sprout and About forges an alg-none JWT in the sprout_session cookie to escalate to admin, then uses a leaked preview token against the admin preview-context endpoint to read the moderation JSON blob containing the flag"
---

**z0d1akCTF 2026 Qualifiers**'s Web Exploitation track is a four-challenge lesson in one classical security aphorism: **sign what you check; check what you signed.** Every challenge in this set ships with a credential, token, or response that is *cryptographically or structurally bound to something* — a session, a request, a match ID, a JWT — but the binding covers *the wrong thing*. captcha mints a JWT proof scoped to session and attempt that asserts `human: true` but never mentions which of four checks produced it — so one proof, minted by the trivial pipe puzzle, unlocks the physically infeasible race lap. hydra-fc-will-come-back binds fixture responses to the request that produced them but does not check that each fixture in the bundle is separately accessible, so a public "anchor" match drags restricted calibration profiles into the same payload. Middle-Out binds a metadata field by its full name string in the gateway but by a 32-bit FNV-1a hash in the native worker, so a lowercase collision that survives preflight overwrites the privileged `center` and `radius` fields inside the worker. Sprout & About binds the `sprout_session` cookie with an HS256 signature — but also accepts `alg: none` unsigned tokens, so a payload with `role: ADMIN` unlocks the admin catalog and its `previewToken`-gated moderation context returns `finalFlag` verbatim.

The pattern that binds all four is that each service performs *a* check but not *the* check. captcha checks that the proof was minted; it never checks that the proof's scope matches the check being accepted. hydra-fc-will-come-back checks that the requester can see the anchor; it never re-checks each companion fixture individually. Middle-Out's gateway checks the field name; the worker's dispatcher checks the field hash. Sprout & About checks that the JWT parses; it never checks that the algorithm was actually cryptographically enforced. In every case the exploit fits into the exact space between the check that ran and the check that would have blocked it.

Handouts, per-challenge READMEs, and dependency-conscious solvers live at [Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers). This **CyberSecurity Elite** z0d1akCTF 2026 Qualifiers Web Exploitation writeup covers all four challenges end to end. Read alongside the paired [z0d1akCTF 2026 Qualifiers Miscellaneous writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-misc-writeup/), the [z0d1akCTF 2026 Qualifiers Forensics writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-forensics-writeup/), the [z0d1akCTF 2026 Qualifiers Cryptography writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-crypto-writeup/), the [z0d1akCTF 2026 Qualifiers Binary Exploitation writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-pwn-writeup/), and the [z0d1akCTF 2026 Qualifiers Reverse Engineering writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-reverse-engineering-writeup/) — the complete series across every category.

## All four Web Exploitation challenges at a glance

| Challenge | Points | Sub-genre | The unchecked binding | Flag |
|---|---:|---|---|---|
| [captcha](#captcha--replay-one-jwt-proof-across-all-four-checks) | 174 | Broken authorization scope | JWT proof asserts `human: true` but never names the check that produced it | `zdk{53Ems_HuMAN_3NoU6H_7o_m3}` |
| [hydra-fc-will-come-back](#hydra-fc-will-come-back--public-anchor-drags-restricted-fixtures-into-the-response) | Unknown | Response filter bypass | `compare` bundles restricted fixtures whenever a public anchor is included | `zdk{FE3LinG_8aD_fOR_CroAtiA}` |
| [Middle-Out](#middle-out--gateway-vs-worker-fnv-1a-parser-differential-into-hmac-forgery) | 378 | Parser differential + hash collision | Gateway identifies fields by full name; worker dispatches by 32-bit FNV-1a | `zdk{TH3_6A7EwaY_and_W0rker_5QuEEZ3d_dLfFeR3NT_MIdD1e5}` |
| [Sprout & About](#sprout--about--alg-none-jwt-plus-preview-token-moderation-leak) | 152 | Classic `alg:none` JWT | Server accepts unsigned JWT when header is `{"alg":"none"}` | `zdk{0C3AN_DLviNG_i5_fUN}` |

Four completely different technology stacks — a WebSocket four-game gate, a Football offside gateway, a Pied-Piper-parody browser-to-WASM-to-native pipeline, a Next.js plant shop — and one repeated pattern.

---

## captcha — replay one JWT proof across all four checks

> *Flag:* `zdk{53Ems_HuMAN_3NoU6H_7o_m3}`
>
> *Prompt:* "Complete all four checks before time runs out."

A "human verification" gate. A single attempt assigns four independent mini-games — a file-sort, a pipe-rotation puzzle, a sliding-tile puzzle, and a top-down **race lap** — that must all be completed within a **10-second server-enforced window**. Each check additionally enforces a *minimum observation period*: a result cannot be submitted faster than it could plausibly have been produced.

Solving the four games honestly is a dead end by design. The race-lap observation period equals its own simulated duration (`ticks / hz`), and the shortest lap the track physically permits is longer than the entire 10-second window. No amount of driving skill completes the race inside the deadline.

### The `verify` proof is not scoped to the check

The intended solution is a **broken-authorization** flaw. The `verify` endpoint returns a `proof` that is a JWT scoped to the session and attempt and asserts:

```json
{"human": true, "session": "...", "attempt": "..."}
```

It contains **no reference to which check was solved**. The `accept` endpoint honours *any* valid proof for whatever check is named in the URL. Therefore a single proof, minted by solving the trivial pipe puzzle once, replays to `accept` all four checks — the race lap included, without ever driving it.

### The exploit

```text
[+ 1.45s] registered 4: ['cable-box', 'desktop-cleanup', 'tile-scramble', 'race-lap']
[+ 3.24s] setup done ws=4, 8.2s left
[+ 6.49s] minted proof via cable-box: 200 ok
[+ 7.20s] accept cable-box       200 completed=1
[+ 7.86s] accept desktop-cleanup 200 completed=2
[+ 8.66s] accept tile-scramble   200 completed=3
[+ 9.46s] accept race-lap        200 completed=4
[+10.20s] UNLOCK 200 {"ok": true, "flag": "zdk{53Ems_HuMAN_3NoU6H_7o_m3}"}
```

Twenty seconds from `register` to `unlock`. One trivial puzzle solved. Every heavy client-side racing physics engine, pure-pursuit controller, and centre-line planner in the repository (`race.py`, `plan.py`, `plan2.py`) is preserved as *the honest-but-infeasible path* — the actual solve is 30 lines of `win.py`.

### Takeaway

**A token is only as good as the scope in it.** When a proof asserts a *property* (`human: true`) without also naming the *object* the property was proven for (which check), the property is trivially transferable. This is the exact same shape as OAuth token-scope bugs, JWT-audience-mismatch bugs, and STS-role-assumption bugs — and here it is deliberate, because the race lap is deliberately infeasible so the challenge *forces* you to notice the missing scope. If a token doesn't say what it unlocks, it unlocks everything.

---

## hydra-fc-will-come-back — public anchor drags restricted fixtures into the response

> *Flag:* `zdk{FE3LinG_8aD_fOR_CroAtiA}`
>
> *Prompt:* "Webex follow-up for Hydra FC."

A sequel to the [Hydra FC forensics challenge](/ctf-writeups/z0d1akctf-2026-qualifiers-forensics-writeup/#hydra-fc--a-source-map-leaks-the-vulnerable-gateway-function). This time you interrogate a live VAR telemetry gateway and file a successful appeal against a bad offside call.

The public landing endpoint exposes the incident:

```json
{
  "match_id": "HYD-SS-FINAL",
  "subject": "Shakes equalizer review",
  "published_decision": "OFFSIDE",
  "published_margin_mm": 11
}
```

The attached spec defines the offside calculation and documents two API operations that are not listed on the landing page: `POST /api/v1/compare` and `POST /api/v1/appeal`.

### The access-control gap

Restricted fixtures cannot be retrieved on their own. But if a `compare` request includes a public "anchor" match, the gateway includes restricted calibration and rehearsal fixtures in the same response payload. That leaks the validated East camera profile:

```text
EAST-MATCH-043  CAM-EAST  longitudinal_offset_mm = 48  status = match-active
EAST-CAL-042    CAM-EAST  longitudinal_offset_mm =  0  status = validated
```

At the real kick frame `154828`, the published `EAST-MATCH-043` profile moves Shakes' CAM-EAST right shoulder from `1000 mm` to `1048 mm`, making him appear **+11 mm offside**. Replacing only that bad profile with validated `EAST-CAL-042` moves Shakes' line back to `1000 mm`; the second defender's line remains `1037 mm`, so the correct margin is:

```text
1000 − 1037 = −37 mm
```

### The appeal

```json
{
  "match_id": "HYD-SS-FINAL",
  "kick_frame": 154828,
  "bad_sensor": "CAM-EAST",
  "correct_profile": "EAST-CAL-042",
  "corrected_margin_mm": -37
}
```

The service accepts the appeal, flips the decision to onside, and returns the flag.

### Takeaway

**A response filter that groups by request, not by record, leaks records that should be restricted individually.** Any endpoint that says "you can see A, and here's A plus B in one payload" without re-authorising B is the same bug — think GraphQL nested-resolver leaks, Elasticsearch `_source` include-all bugs, and every "expand" query parameter that unexpectedly enumerates children. The gateway *does* have per-fixture access control; it just doesn't apply it inside the compare-response bundle.

---

## Middle-Out — gateway vs worker FNV-1a parser differential into HMAC forgery

> *Flag:* `zdk{TH3_6A7EwaY_and_W0rker_5QuEEZ3d_dLfFeR3NT_MIdD1e5}`
>
> *Prompt:* "Pied Piper has put its middle-out compression service online. Gilfoyle says the production license is safe. Richard believed him. Prove them wrong."

A browser-to-gateway-to-native-worker challenge. The browser wraps an uploaded file into a binary `PPJB` job, the JavaScript gateway performs a preflight validation, and a native worker compresses a window around a declared centre. Founder licenses are signed with a secret that is present in the worker's memory but is supposed to remain unreachable.

The exploit chains **three implementation mismatches**:

**1. Field identity in two different alphabets.** Metadata records carry both a full key and its 32-bit FNV-1a fingerprint. The gateway identifies security-sensitive fields by *full key string*; the native worker dispatches them using *only the fingerprint*.

**2. Lowercase extension keys are unfiltered.** The gateway permits unknown lowercase extension keys. Lowercase FNV-1a collisions for `center` and `radius` therefore survive preflight but become those privileged fields in the native worker. Because later fields win, the collisions overwrite the already-validated values.

**3. Missing lower-bound check.** The worker checks that `center + radius` does not pass the end of the payload, but does not check that `center >= radius`. The colliding values `center = 0` and `radius = 1024` pass the upper-bound check for a 1024-byte payload and make the worker read 1024 bytes **before** the payload pointer.

### From heap under-read to HMAC key

The leaked 1024 bytes contain four sealed `WSC4` records. An unused browser-WASM export reveals their format and decryption algorithm. Hex-decoding the public build ID gives the 8-byte capsule key, and decryption produces four 32-byte **Shamir shares over GF(2⁸)**. Two shares are authentic and two are decoys. Interpolating each pair and checking the reconstructed key against the known trial-token HMAC identifies the authentic pair and recovers the license signing key.

Changing the signed claim from `"tier":"trial"` to `"tier":"founder"` then produces a valid license token. The activation endpoint returns the flag.

### The chain

```text
malicious PPJB
    |
    v
gateway: exact names -> center=512, radius=256 -> accepted
    |
    v
worker: FNV only -> center=0, radius=1024 -> 1 KiB heap under-read
    |
    v
WSC4 capsules -> build-key decryption -> Shamir shares
    |
    v
HMAC signing key -> forged founder token -> flag
```

### Takeaway

Every step of this chain is a *parser differential* in disguise. The gateway parses field names; the worker parses field hashes. The gateway parses upper bounds; the worker parses only upper bounds and forgets lower bounds. Two parses of the same object should agree — or one of them should be authoritative. When they disagree and neither is authoritative, the exploit is arithmetic on the difference. The flag body — *"the gateway and worker squeezed different middles"* — states the bug outright.

---

## Sprout & About — alg:none JWT plus preview-token moderation leak

> *Flag:* `zdk{0C3AN_DLviNG_i5_fUN}`
>
> *Prompt:* "The plant shop owners heard JWTs were 'industry standard' and immediately stopped worrying about security."

A Next.js plant-shop application with a customer nursery catalog and an admin-only "Tide Desk" for previewing catalog entries. The interesting trust boundary is the `sprout_session` cookie: it is a JWT whose payload contains the user's `role`.

Registering a normal account gives a signed **HS256** JWT with `role: "USER"`:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "role": "USER",
  "email": "...",
  "iat": 1735...
}
```

### The classic `alg:none` bypass

The server accepts an **unsigned** JWT if the header is changed to `{"alg":"none"}`. Forging the same cookie with `role: "ADMIN"` and dropping the signature grants access to `/admin`:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiQURNSU4iLCJlbWFpbCI6Ii4uLiJ9.
```

(Note the trailing dot with no signature after it — canonical unsigned JWT.)

### The preview-token disclosure

The admin product catalog exposes a second weakness. Each rendered product row contains a `previewToken` in the HTML, and the client-side preview dialog uses it to call:

```text
GET /api/admin/preview-context?productId=<id>&previewToken=<uuid>
```

That endpoint returns the moderation context as JSON. When reached with the forged admin session and a leaked preview token, the context includes `finalFlag`:

```json
{
  "mode": "moderation",
  "finalFlag": "zdk{0C3AN_DLviNG_i5_fUN}",
  "productId": 1,
  "note": "internal-only"
}
```

### The chain

```text
register user -> USER JWT -> replace header {"alg":"none"} -> role: ADMIN
             -> GET /admin -> scrape previewToken from product row
             -> GET /api/admin/preview-context?productId=1&previewToken=<uuid>
             -> {"finalFlag": "zdk{0C3AN_DLviNG_i5_fUN}"}
```

### Takeaway

`alg: none` remains the classic JWT foot-gun a decade after RFC 7519. Any library that parses the header algorithm string from the token itself and then dispatches to a "verify" routine keyed on that string will silently accept an unsigned token when the string is `"none"`. **The library must select the verification algorithm from the trust configuration, not from the header.** The preview-token disclosure is the secondary bug — an internal moderation identifier that grants read access to internal data is only safe if the token is unguessable AND the endpoint requires strong caller authentication. Sprout & About satisfies neither: the tokens are UUIDs pasted into HTML, and the caller authentication is the very JWT the algorithm bypass forges.

---

## Cross-cutting lessons from the z0d1akCTF 2026 Qualifiers Web Exploitation set

Four challenges, four completely different stacks, one repeated pattern — **sign what you check; check what you signed**:

- **A token that asserts a property must also name the object the property was proven for.** captcha's `human: true` proof is transferable across checks because it never names the check. OAuth `scope`, JWT `aud`, and OpenID `nonce` claims exist for exactly this reason.
- **Access control on requests is not access control on records.** hydra-fc-will-come-back authorises the compare request via the public anchor but doesn't re-authorise each fixture in the bundled response. Any endpoint that returns multiple records must apply access control per-record, not per-request.
- **Two parsers of the same object is a bug class, not an edge case.** Middle-Out's gateway (full-name) and worker (FNV-1a fingerprint) parses of the same field disagree by design. Any pipeline where an approving component and an executing component parse the same input independently is a parser-differential waiting to be exploited. Share one parser or assert they agree.
- **`alg: none` is not a "modern JWT library" bug — it's a specification permissiveness.** Every JWT library still ships with `none` as a valid algorithm option (RFC 7519 lists it), and any application code that selects the verification algorithm from the header rather than from configuration will accept unsigned tokens. Pin the algorithm at library initialisation; reject any token whose header algorithm differs from the pinned one.
- **Preview / moderation / debug endpoints leak flag-shaped data.** Sprout & About's `/api/admin/preview-context` returns `finalFlag` — a field that only makes sense inside the moderation pipeline. Any internal endpoint that concatenates *external representation* fields with *internal-only* fields is a disclosure primitive as soon as any authentication bug exists.
- **Read the flag body.** The z0d1akCTF flags spell out the bug: *"the gateway and worker squeezed different middles"* (Middle-Out), *"the stale audit record rewrites the route"* (House XIII), *"a human reads the wake, not the labels"* (Unrotated). The pattern extends across every category. If a flag reads like a technical assertion, it usually names the underlying bug directly.
- **Bind-what-you-check is a routine checklist.** Whenever a service issues a signed artifact, the checklist is: what did you sign (subject, scope, audience, algorithm, expiry, key ID) and what does the receiver check (same list, same values). Missing entries on either side are exploits. All four challenges here are one missing checklist entry away from being unexploitable.

## Reproduce it yourself

Each challenge ships a standalone solver in the [z0d1akCTF 2026 Qualifiers repository](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers) under `Web/<challenge>/`:

- [`Web/captcha/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Web/captcha) — end-to-end exploit (`solver/win.py`) that mints one JWT proof and accepts all four checks with time to spare; dependency-free WebSocket client, honest solvers for the three tractable games, and the honest-but-infeasible race-lap physics port are all preserved as reference material.
- [`Web/hydra-fc-will-come-back/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Web/hydra-fc-will-come-back) — live exploit + offline evidence verifier; captures of every relevant compare call (public, calibration, rehearsal), derived kick frame + line calculations, and the accepted appeal response containing the flag.
- [`Web/middle-out/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Web/middle-out) — end-to-end remote exploit + offline `verify_offline.py`; recovered browser codec WASM, full WAT disassembly and readable decompile revealing the hidden export, compact PPJB/MOZ1/WSC4 format reference, exact 1135-byte collision job, preserved 2048-byte decompressed worker response, decrypted Shamir shares, recovered HMAC key, and forged founder token.
- [`Web/sprout-and-about/`](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers/tree/master/Web/sprout-and-about) — end-to-end stdlib exploit; decoded USER and forged unsigned ADMIN JWTs, admin-products evidence with leaked preview tokens, client preview-dialog snippet, captured flag-bearing preview-context response, minimal curl reproduction notes.

All four solvers are Python standard library only.

Browse the full [CTF writeups](/ctf-writeups/) archive for more web exploitation walkthroughs, or continue the z0d1akCTF 2026 Qualifiers series with the [Miscellaneous writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-misc-writeup/), the [Forensics writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-forensics-writeup/), the [Cryptography writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-crypto-writeup/), the [Binary Exploitation writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-pwn-writeup/), and the [Reverse Engineering writeup](/ctf-writeups/z0d1akctf-2026-qualifiers-reverse-engineering-writeup/) — thirty more challenges under the same read-the-substrate discipline.

---

*This writeup is part of the CyberSecurity Elite [z0d1akCTF 2026 Qualifiers](/series/z0d1akctf-2026-qualifiers/) series. Handouts, per-challenge READMEs, and dependency-conscious solvers for all four Web Exploitation challenges are published at [github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers](https://github.com/Abdelkad3r/z0d1akCTF-2026-Qualifiers). With this writeup the series is complete — all six tracks and all 34 challenges from the event are now covered.*
