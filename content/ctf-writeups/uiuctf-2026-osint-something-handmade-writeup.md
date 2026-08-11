---
title: "UIUCTF 2026 OSINT Writeup: Something Handmade — Wedding Site to Private RSVP"
slug: "uiuctf-2026-osint-something-handmade-writeup"
description: "Complete UIUCTF 2026 Something Handmade OSINT writeup. A public Zola wedding site for Belda Byrule and Bink Hyaa mentions Mipha documenting welcome-bag prep on @miphamakes — a specific handle in a sea of altered fictional Zelda names is the pivot signal. That DeviantArt account has three posts each thanking a craft helper by first name (Carl, Tessa, Nolan). Zola's public wedding endpoint /web-api/v1/publicwedding/slug/beldaandbink exposes the wedding_account_uuid 98298caa-11a9-4c3e-83c2-197f59ec8235, and /web-api/v1/publicwedding/rsvp/guest/wedding-account/uuid/.../search-groups accepts a first name and returns the matching guest-group UUID without authentication. Carl's guest-group query against /web-api/v2/publicwedding/rsvp/guest-group/uuid/.../wedding-account/uuid/... returns four events instead of the three Tessa and Nolan see; the extra event Royal Banquet and Byrulian Bappy Hour has meal_options whose first entry is the flag uiuctf{handmade_with_a_hidden_detail_7c4e1d}."
date: 2026-08-12T12:00:00Z
lastmod: 2026-08-12T12:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["UIUCTF 2026"]
tags:
  - "uiuctf"
  - "uiuctf 2026"
  - "uiuc ctf"
  - "ctf writeup"
  - "osint"
  - "something handmade"
  - "osint pivot"
  - "handle discovery"
  - "wedding website osint"
  - "zola wedding"
  - "zola api"
  - "public api enumeration"
  - "guest search endpoint"
  - "deviantart osint"
  - "guest group uuid"
  - "rsvp enumeration"
  - "wedding_account_uuid"
  - "cross-platform pivot"
  - "attribution osint"
  - "readonly api abuse"
  - "meal options flag"
  - "ctf 2026"
keywords:
  - "uiuctf 2026 osint writeup"
  - "uiuctf 2026 something handmade writeup"
  - "something handmade uiuctf writeup"
  - "zola wedding rsvp api osint ctf"
  - "zola guest search-groups api enumeration"
  - "zola web-api v1 publicwedding slug endpoint"
  - "zola web-api v2 publicwedding rsvp guest-group uuid endpoint"
  - "deviantart handle pivot osint ctf"
  - "miphamakes deviantart osint ctf"
  - "wedding_account_uuid extraction ctf"
  - "belda byrule bink hyaa uiuctf osint"
  - "royal banquet byrulian bappy hour meal options ctf"
  - "horizontal access control wedding rsvp ctf"
  - "cross-platform osint craft helper name recovery"
  - "uiuctf 2026 solutions"
  - "ctf osint step by step 2026"
toc: true
cover:
  image: "/images/articles/uiuctf-2026-osint-something-handmade-writeup.png"
  alt: "UIUCTF 2026 Something Handmade OSINT writeup cover — a public Zola wedding site for Belda Byrule and Bink Hyaa mentions Mipha documenting welcome-bag preparation on the DeviantArt handle miphamakes, a specific handle in a sea of intentionally altered fictional Zelda names which is the pivot signal. The three DeviantArt posts each thank a craft helper by first name yielding Carl, Tessa, and Nolan. Zola's public wedding endpoint slash web-api slash v1 slash publicwedding slash slug slash beldaandbink exposes the wedding_account_uuid 98298caa-11a9-4c3e-83c2-197f59ec8235, and the guest-search endpoint slash web-api slash v1 slash publicwedding slash rsvp slash guest slash wedding-account slash uuid slash ... slash search-groups accepts a first name unauthenticated and returns the matching guest-group UUID. Carl White's guest-group query against slash web-api slash v2 slash publicwedding slash rsvp slash guest-group slash uuid slash ... slash wedding-account slash uuid slash ... returns four events instead of the three that Tessa and Nolan see, and the extra event Royal Banquet and Byrulian Bappy Hour has meal_options whose first entry is uiuctf{handmade_with_a_hidden_detail_7c4e1d}"
---

**UIUCTF 2026**'s Something Handmade is a compact OSINT chain that trains one specific reflex: **the pivot is a specific string in a sea of altered ones.** The challenge starts on a public Zola wedding site for "Belda Byrule and Bink Hyaa" — every proper noun in that fictional universe is a deliberate Zelda misspelling, so nothing on the page is directly searchable. Everything, that is, except one line under Welcome Bags that says *"Mipha documented the process over on @miphamakes"*. That handle is unaltered, is specific enough to have exactly one owner on the whole internet, and is the entire pivot. The moment you notice a real handle inside a fictional site, the shape of the solve is fixed.

The rest of the chain is a horizontal-privilege enumeration against Zola's own public RSVP API. The `@miphamakes` DeviantArt account has three posts, each thanking a craft helper by first name (**Carl**, **Tessa**, **Nolan**). Zola's public wedding endpoint exposes `wedding_account_uuid = 98298caa-11a9-4c3e-83c2-197f59ec8235`; its read-only guest-search endpoint accepts an unauthenticated first name and returns the matching guest-group UUID. Querying each guest group's event list reveals that Carl (guest group `46bdaeb5-…`) sees **four** events while Tessa and Nolan see **three** — the extra event *Royal Banquet and Byrulian Bappy Hour* has three `meal_options` whose first entry is the flag `uiuctf{handmade_with_a_hidden_detail_7c4e1d}`. No login, no RSVP submission, no page scraping beyond the initial `@miphamakes` pivot — just calling the API the wedding site's own JavaScript would call.

Handout narrative, full HTTP transcript, and a Python-standard-library solver live at [Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/something-handmade). This **CyberSecurity Elite** UIUCTF 2026 OSINT writeup walks the complete chain, with an emphasis on the *pivot recognition* that turns a fictional wedding site into a solvable challenge and on the *read-only API enumeration* that avoids ever touching the RSVP state. Read alongside the paired [UIUCTF 2026 Cryptography writeup](/ctf-writeups/uiuctf-2026-crypto-writeup/), [UIUCTF 2026 Reverse Engineering writeup](/ctf-writeups/uiuctf-2026-reverse-engineering-writeup/), [UIUCTF 2026 Miscellaneous writeup](/ctf-writeups/uiuctf-2026-misc-writeup/), and [UIUCTF 2026 Nabi AI web writeup](/ctf-writeups/uiuctf-2026-web-nabi-ai-writeup/).

## Something Handmade at a glance

| Property | Value |
|---|---|
| Category | OSINT |
| Points | 421 |
| Author | Emma |
| Attack chain | Cross-platform handle pivot (Zola → DeviantArt) → three-name enumeration → Zola public guest-search → horizontal event-scope enumeration |
| Flag | `uiuctf{handmade_with_a_hidden_detail_7c4e1d}` |

The advertised difficulty is real: the challenge blocks every naive path (reverse-image searches on the photos surface old Zelda-wedding content, not the flag), and the fictional Zelda names cannot be searched literally. The intended path is exactly one non-obvious observation — *the handle is not fictional* — followed by three routine `curl` calls against Zola's own API.

---

## Step 1 — inspect the public wedding site

The prompt hands over a single URL:

```text
https://www.zola.com/wedding/beldaandbink
```

The visible site introduces "Belda Byrule" (Zelda → Belda) marrying "Bink Hyaa" (Link, Hyrule → Bink Hyaa) with the usual public wedding sections: story, venue, registry, welcome bags. Every proper noun is a *Zelda* pun cushion — none of them will produce useful hits on their own.

The **Welcome Bags** section contains the pivot:

> *Our welcome bags were assembled with lots of help, several snack breaks, and only one ribbon-related meltdown. Mipha documented the process over on @miphamakes…*

Two features of that sentence separate it from every other line on the page:

1. **`@miphamakes` is unaltered.** The rest of the site is Zelda-with-typos; this handle is a normal DeviantArt-shaped identifier that could belong to a real person.
2. **The handle is directly actionable.** The visible ecosystem for artist handles (DeviantArt, Instagram, Behance, ArtStation) can be queried by handle without password or login, and DeviantArt was made explicit by the "documented over on" phrasing plus the URL structure `deviantart.com/{handle}`.

Following that pivot:

```text
https://www.deviantart.com/miphamakes
```

The account was created for the challenge. It contains three posts, and every post credits a craft helper by first name.

## Step 2 — extract the craft helpers' first names

The three post descriptions contain a "thanks to X" line each:

| Post | Relevant sentence | Name recovered |
| --- | --- | --- |
| Our Wedding Bags | "huge thanks to **Carl** for dropping off the gem cutouts" | Carl |
| Triforce Florals | "huge thanks to **Tessa** for keeping me sane" | Tessa |
| Bout of Doubt | "shoutout to **Nolan** for laser-cutting the crest pieces" | Nolan |

**The photographs themselves are a distraction.** Reverse-image searches surface older Zelda-themed wedding material — not the flag. The reusable data supplied by the posts is exclusively the three first names:

```text
Carl
Tessa
Nolan
```

At this point the challenge shifts from a research problem (find the DeviantArt) to an enumeration problem (three names against an unknown lookup). The prompt says *"Someone involved in the handmade details knows a bit more"* — a wedding-site guest that "knows more" is a guest who has RSVPed, and Zola's RSVP page is a public form that accepts guest names.

## Step 3 — extract the wedding account UUID from Zola's public API

The Zola RSVP flow needs a `wedding_account_uuid`. It is embedded in the site's Next.js state, but the cleanest way to obtain it is a single unauthenticated GET against Zola's own public wedding endpoint:

```bash
curl -sS \
  https://www.zola.com/web-api/v1/publicwedding/slug/beldaandbink \
  | jq -r .wedding_account_uuid
```

```text
98298caa-11a9-4c3e-83c2-197f59ec8235
```

This is the ID the wedding site's own JavaScript uses; nothing about the request is privileged. It is worth noting the endpoint shape — `/web-api/v1/publicwedding/slug/{slug}` — because every remaining call in the chain follows the same `/web-api/vN/publicwedding/...` namespace. The API is designed to be called from the browser; the surface is unauthenticated because the "protection" is knowing which UUIDs to ask about.

## Step 4 — enumerate the three craft helpers via search-groups

Reviewing Zola's public JavaScript bundles reveals the guest-lookup endpoint:

```text
POST /web-api/v1/publicwedding/rsvp/guest/wedding-account/uuid/{wedding_account_uuid}/search-groups

Content-Type: application/json
Body: {"guest_name": "..."}
```

This is exactly the same call the RSVP page makes when a guest types their name into the "find your invitation" box. It accepts partial name matches and returns any matching guest groups.

Querying Carl:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  --data '{"guest_name":"Carl"}' \
  'https://www.zola.com/web-api/v1/publicwedding/rsvp/guest/wedding-account/uuid/98298caa-11a9-4c3e-83c2-197f59ec8235/search-groups' \
  | jq .
```

```json
[
  {
    "guests": [
      {
        "first_name": "Carl",
        "family_name": "White",
        "relationship_type": "PRIMARY"
      }
    ],
    "uuid": "46bdaeb5-ba84-4d91-ad7b-29301af31562"
  }
]
```

The three searches resolve to three complete records:

| Search | Full name | Guest-group UUID |
| --- | --- | --- |
| Carl | Carl White | `46bdaeb5-ba84-4d91-ad7b-29301af31562` |
| Tessa | Tessa Viola | `f59be3eb-9999-46ec-a6f8-c0668f2d727e` |
| Nolan | Nolan North | `57b90e69-9920-420f-9bb1-d6bd52939307` |

Each name resolves to a dedicated guest group. That is confirmation that the three DeviantArt names are intentional entries in the synthetic wedding rather than search-engine false positives. If any of the three had returned zero hits, the pivot would still be alive but the specific guest would not be a valid RSVP target.

## Step 5 — pull each guest group's event list

Selecting a guest on the RSVP page triggers a second read-only endpoint:

```text
GET /web-api/v2/publicwedding/rsvp/guest-group/uuid/{guest_group_uuid}/wedding-account/uuid/{wedding_account_uuid}
```

Requesting Carl's events:

```bash
curl -sS \
  'https://www.zola.com/web-api/v2/publicwedding/rsvp/guest-group/uuid/46bdaeb5-ba84-4d91-ad7b-29301af31562/wedding-account/uuid/98298caa-11a9-4c3e-83c2-197f59ec8235' \
  | jq '.events[] | {name, meal_options}'
```

Carl's guest group has access to **four** events. Tessa's and Nolan's queries return **three** events each — welcome event, ceremony, vows. Carl additionally sees a private banquet:

```json
{
  "name": "Royal Banquet and Byrulian Bappy Hour",
  "meal_options": [
    { "name": "uiuctf{handmade_with_a_hidden_detail_7c4e1d}" },
    { "name": "chicken" },
    { "name": "fish" }
  ]
}
```

The flag is the first meal option of the fourth event, visible only to Carl's guest group. This is a **horizontal access-control gap**: the extra event is not protected by authentication, only by knowing which guest group to ask about. Once the three DeviantArt names are enumerated, the extra scope is one HTTP GET away.

## Step 6 — automated solver

The [`solve.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/something-handmade/solve.py) reproduces the API portion of the investigation in about 60 lines of Python standard library. Its steps:

1. GET `/web-api/v1/publicwedding/slug/beldaandbink` and extract `wedding_account_uuid`.
2. For each of `["Carl", "Tessa", "Nolan"]`, POST to `search-groups` and record the guest-group UUID.
3. For each guest-group UUID, GET the events endpoint.
4. Walk the JSON responses recursively for anything matching the `uiuctf{...}` pattern.

```bash
python3 solve.py
```

```text
[+] Carl: Carl White
[+] flag: uiuctf{handmade_with_a_hidden_detail_7c4e1d}
```

No RSVP submission is made. The solver performs only the read-only guest search and event-detail retrieval that Zola's public interface performs when a guest opens the RSVP page. The DeviantArt account is not queried at all — its role is exclusively the human-in-the-loop discovery of the three names.

## Root cause and remediation

Two distinct issues combine into the challenge, and both are common in real wedding / event platforms:

### 1. Guest name enumeration on an unauthenticated endpoint

`search-groups` accepts arbitrary name queries against a public wedding account and returns a matching guest group's UUID and members' full names. That is a *feature* — the whole point is that a guest without an account can find their invitation by typing their name — but it also means anyone with a list of candidate names can enumerate the entire guest list. Common mitigations that platforms actually deploy:

- **Rate limit per IP** and per wedding_account_uuid, sharply. A wedding has O(200) guests, so 1 request/second is generous for a legitimate guest and prohibitive for an enumerator.
- **Require an "authentication code"** for the search — a short numeric or alphanumeric code sent on the paper invitation. The RSVP page then becomes a two-input form (name + code), and the wedding_account_uuid alone is no longer sufficient.
- **Return a static "if you're on the list, you'll see it after RSVP" page** on the first miss, without disclosing whether the name matched.

### 2. Horizontal access control on event scopes

The extra banquet event is protected only by "you have to know Carl's guest-group UUID to see it." That UUID is not a secret — it is returned to anyone who can call `search-groups` with a matching name. In a production system, an event marked as VIP or private should either:

- **Require an out-of-band token** (email link with a signed token) to view its details;
- **Return only the summary** (name, date) to non-invited guests and hide `meal_options` / venue behind an RSVP confirmation; or
- **Not exist as a separate JSON field on the same endpoint at all.** Serving VIP data to non-VIP callers over the same endpoint is the direct cause of the leak.

The CTF chose the direct object reference intentionally, but real Zola-style platforms hit exactly this gap when the "hidden event" feature is added later than the initial guest-scope model.

## Takeaway

**A specific string in a sea of altered ones is the pivot.** Every fictional CTF wedding site is inhabited by proper nouns that will not survive a search engine query — that is the whole point of the fiction. The exception, when it appears, is deliberate: it is either the pivot itself, or an artifact the designer forgot to alter. In Something Handmade, `@miphamakes` is that exception, and everything downstream (the DeviantArt account, the three craft helpers, the guest enumeration, the banquet event) is available exactly because the challenge author put a real-shaped handle at the top.

Portable heuristics from this solve:

- **Count the alterations, then look for the un-altered.** When a page is "themed" with obviously modified names, a normal-looking identifier stands out. Search for what does not fit the theme.
- **Photos are a distraction unless they carry EXIF.** Reverse-image search is the wrong first move on a synthetic OSINT site because the assets are usually stock or repurposed from unrelated events. Text is the primary carrier.
- **Read the platform's own JavaScript for API shapes.** Every browser-facing endpoint the site's own JS calls is available to `curl` with the same headers. The wedding UI's `search-groups` request is the entire attack — it just took reading the site's bundle to know it existed.
- **Enumerate horizontally, not vertically.** The extra event is protected only by "which guest are you?" Enumerating a small set of *plausible guests* (Carl, Tessa, Nolan) beats trying to escalate privilege on a known guest.
- **Stay read-only.** The solver never submits an RSVP. Every step in the chain is a GET or a search POST that the wedding page's own JavaScript makes without a login. Modifying state is neither necessary nor sportsmanlike.

## Reproduce it yourself

The [`something-handmade/`](https://github.com/Abdelkad3r/UIUCTF-2026/tree/main/something-handmade) directory contains everything needed:

- [`README.md`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/something-handmade/README.md) — the full investigation narrative including the DeviantArt pivot and every HTTP endpoint used.
- [`solve.py`](https://github.com/Abdelkad3r/UIUCTF-2026/blob/main/something-handmade/solve.py) — dependency-free Python standard library solver that reproduces the API portion of the chain.

Browse the full [CTF writeups](/ctf-writeups/) archive for more OSINT and cross-platform pivot walkthroughs, including the paired [KaliTeam CTF 2026 OSINT writeup](/ctf-writeups/kaliteam-ctf-2026-osint-writeup/) (torn newspaper reconstruction + leetspeak scoreboard fuzzy-scan) for a very different flavour of the same *"the pivot is metadata, not the picture"* pattern. The full [UIUCTF 2026](/series/uiuctf-2026/) series covers the Miscellaneous jail escapes, the Nabi AI web SSRF, the Cryptography plactic-monoid / CKKS / Elder Futhark set, and the Reverse Engineering SIGILL / firmware / lambda-calculus / bitmap-interpreter track.

---

*This writeup is part of the CyberSecurity Elite [UIUCTF 2026](/series/uiuctf-2026/) series. The narrative README and the read-only Python solver for Something Handmade are published at [github.com/Abdelkad3r/UIUCTF-2026](https://github.com/Abdelkad3r/UIUCTF-2026).*
