---
title: "KaliTeam CTF 2026 OSINT Writeup: The Unbroken Shelf & Guests"
slug: "kaliteam-ctf-2026-osint-writeup"
description: "Full KaliTeam CTF 2026 OSINT writeup covering both OSINT challenges: OCR'ing a torn 1920 newspaper clipping, clearing a Cloudflare block with a headed Playwright browser to search Chronicling America, and pinning the New-York Tribune of 21 August 1920 — then proving it with a 23-line tear-alignment checksum to recover 157 Eighth Avenue at 8:40 p.m. (The Unbroken Shelf); and locating Team Havok on the Black Hat MEA CTF scoreboards with a leetspeak-tolerant fuzzy regex that matches the real registration H@vOK, placing them 83rd in the 2024 Final in Riyadh (Guests)."
date: 2026-08-10T00:00:00Z
lastmod: 2026-08-10T00:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["KaliTeam CTF 2026"]
tags:
  - "kaliteam ctf"
  - "kaliteam ctf 2026"
  - "ctf writeup"
  - "osint"
  - "geoint"
  - "newspaper osint"
  - "chronicling america"
  - "archive research"
  - "cloudflare bypass"
  - "playwright"
  - "ocr"
  - "tesseract"
  - "image reconstruction"
  - "ctftime"
  - "scoreboard osint"
  - "fuzzy matching"
  - "leetspeak"
  - "black hat mea"
  - "reverse image research"
  - "ctf 2026"
keywords:
  - "kaliteam ctf 2026 osint writeup"
  - "the unbroken shelf ctf writeup"
  - "guests ctf writeup"
  - "chronicling america osint ctf"
  - "torn newspaper reconstruction ctf"
  - "cloudflare 403 playwright headed browser osint"
  - "ctftime scoreboard fuzzy search leetspeak"
  - "black hat mea team havok h@vok"
  - "newspaper archive geolocation ctf"
  - "osint tradecraft ctf 2026"
  - "kaliteam ctf writeup"
  - "osint ctf 2026"
toc: true
cover:
  image: "/images/articles/kaliteam-ctf-2026-osint-writeup.png"
  alt: "KaliTeam CTF 2026 OSINT writeup covering both challenges — The Unbroken Shelf OCRs a torn 1920 newspaper clipping, clears a Cloudflare block with a headed Playwright browser to search Chronicling America, pins the New-York Tribune of 21 August 1920 page 1, and proves it with a 23-line tear-alignment checksum to recover the address 157 Eighth Avenue and the time 8:40 p.m.; and Guests locates Team Havok across the ten Black Hat MEA CTF scoreboards on CTFtime with a leetspeak-tolerant fuzzy regex that matches the real registration H@vOK, placing them 83rd in the Black Hat MEA CTF Final 2024 held in Riyadh"
---

OSINT at KaliTeam CTF 2026 was a two-challenge track that shares a deceptively simple lesson: **the hard part of an open-source hunt is rarely finding the fact — it's getting to the source, or realizing the string isn't spelled the way you think.** One challenge hides its answer behind a Cloudflare wall and a physically torn page; the other hides it behind a single `@` in a team name. Both are won less by clever queries than by disciplined tradecraft — and by knowing exactly which dead end you're standing in.

This **CyberSecurity Elite** KaliTeam CTF 2026 OSINT writeup walks both challenges end to end, emphasizing the *methodology and the wrong turns* (which, as the source writeups note, are usually the part worth reading). Challenge files, solver scripts, and interactive HTML writeups are at [Abdelkad3r/KaliTeam-CTF26](https://github.com/Abdelkad3r/KaliTeam-CTF26).

## Both challenges at a glance

| Challenge | Author | Flag format | Core obstacle |
|---|---|---|---|
| [The Unbroken Shelf](#the-unbroken-shelf--reconstructing-a-1920-blast) | S1l3nt | `KaliTeam{NEWSPAPER_YYYY_MM_DD_STREET_NUMBER_STREET_TIME}` | Archive access (Cloudflare) + reconstruction |
| [Guests](#guests--one-character-that-defeats-every-search) | Havok | `KaliTeam{YEAR_CITY_RANK}` | Obfuscated spelling (leetspeak) |

---

## The Unbroken Shelf — reconstructing a 1920 blast

> *Flag:* `KaliTeam{NEW_YORK_TRIBUNE_1920_08_21_157_EIGHTH_2040}`

The artifact is a 1500×1150 PNG of a torn newspaper clipping: a headline strip up top, one surviving column of body text on the right, and a left column torn away vertically — leaving only a ragged strip of line *endings*. The flag needs five fields, and the first realization reframes the whole task: **four of the five aren't on the clipping.**

| Field | On the clipping? |
|---|---|
| Newspaper | no — no masthead |
| Year / month / day | no — "the date was torn away" |
| Street number | no — destroyed with the left column |
| Street | **yes** — "Eighth Avenue" survives |
| Time | no — destroyed with the left column |

So the clipping is a **search key, not an answer**. A 30-second check of the PNG chunk list (`IHDR`, `IDAT×33`, `IEND` — no `tEXt`, no `eXIf`) rules out any metadata shortcut and justifies the expensive path: a genuine archive hunt.

### Reading the fragment

Enhanced crops through `tesseract --psm 6` recover the surviving column, yielding three strong search anchors: the headline **"Blows Firemen Out of Drug Store"**, a named officer **Battalion Chief Law·rence McGuire**, and a location — **Eighth Avenue** with streetcar tracks. Eighth Avenue + a Battalion Chief + car tracks places it in **Manhattan**, narrowing the field to the New York dailies digitized in the Library of Congress's *Chronicling America*.

### The real obstacle is access, not identification

This is the part worth documenting. **Every major newspaper archive returned HTTP 403** — and critically, it was *Cloudflare*, not a paywall:

- The old ChronAm JSON API is gone (308-redirects to a URL that 404s).
- A full Chrome header fingerprint still got the `Just a moment…` interstitial.
- Reader/CORS proxies (`r.jina.ai`, `allorigins`, `codetabs`) forwarded the interstitial or timed out.
- **Headless** Chrome (`--headless=new --dump-dom`) was detected outright.

The one thing that worked was **Playwright driving a real, *headed* Chromium with a persistent profile** — Cloudflare cleared in about four seconds, and the profile cookie made every later request cheap:

```js
const ctx = await chromium.launchPersistentContext('/tmp/chronam-profile', {
  headless: false,                 // the load-bearing line
  args: ['--disable-blink-features=AutomationControlled'],
});
```

The tradecraft nugget here is diagnostic: a **403 with a Cloudflare body** is a bot check you can sometimes clear; a **403 with the site's own error page** is a real block. Only the first is worth spending a browser on.

### The search and the reconstruction proof

Through the interstitial, the exact headline phrase returns **exactly one hit** across the entire corpus — the *New-York Tribune*, page 1, **21 August 1920**. Fetching that page with `?st=text` renders the OCR of the column the tear removed, and both missing values sit in the first two paragraphs: *"…wrecked Slater Halpern's drug store, **157 Eighth Avenue**"* and *"It was about **8:40 p. m.**"*

A single search hit is suggestive, not conclusive — so the clipping supplies its own checksum that needs no archive access at all. Because the left column was torn *vertically*, every surviving sliver must be the exact tail of the corresponding recovered line, **in order**. Aligning them ([`verify_alignment.py`](https://github.com/Abdelkad3r/KaliTeam-CTF26/tree/main/osint/the-unbroken-shelf)):

```text
OK  ...rocked      157 Eighth Avenue. The shock rocked      <- street number
OK  ...muel        It was about 8:40 p. m. Samuel           <- time of blast
...
22 exact + 1 punctuation-clipped = 23/23 aligned
```

**Twenty-three consecutive line-endings match** — including the two lines carrying the flag values. A wrong article does not reproduce 23 consecutive line-breaks of a 1920 column. An independent geographic check corroborates it: the alarm box at 17th Street "two doors away" and a bystander at 246 West 18th Street both place #157 between West 17th and 18th, exactly where Eighth Avenue numbering predicts — so `157` isn't an OCR misread.

### Assembling the flag

| Field | Value | Source |
|---|---|---|
| `NEWSPAPER` | `NEW_YORK_TRIBUNE` | matched masthead (hyphen treated as a word separator) |
| `YYYY_MM_DD` | `1920_08_21` | issue date |
| `STREET_NUMBER` | `157` | "…drug store, 157 Eighth Avenue" |
| `STREET` | `EIGHTH` | per the format's `72_MAIN` example, no "Avenue" |
| `TIME` | `2040` | "about 8:40 p. m." → 24-hour |

**Takeaway:** separate the search key from the answer, verify metadata then move on, and — the elegant part — read what the *destruction preserves*, not only what it removes. The shape of the tear became a 23-point checksum on the reconstruction.

---

## Guests — one character that defeats every search

> *Flag:* `KaliTeam{2024_RIYADH_83}`

"Team Havok left its mark in one of the Black Hat MEA CTF competitions… Find the year they competed, the host city, and their final ranking." The three facts have very different difficulty — the host city is trivial once the year is known, so the whole challenge reduces to **locating Team Havok on one specific scoreboard**. The prompt's *"the internet remembers everything… if you know where to look"* reads like a Wayback Machine nudge — and that's the misdirection. The data was never deleted; it was only ever *spelled differently*.

### Scoping the target

Black Hat MEA's CTF series is tracked on CTFtime as [ctf/826](https://ctftime.org/ctf/826/), which enumerates exactly **ten events** — a qualification and a final for 2022–2026. That's the complete, enumerable search space: ten scoreboards.

### Four dead ends worth recording

1. **Literal search-engine queries** (`"Team Havok Black Hat MEA CTF"`, etc.) returned only general coverage and two unrelated CTFtime teams (HAVOC, hav0k), neither on any BH MEA board.
2. **WebFetch against CTFtime → 403** — but only a User-Agent problem; a normal browser UA serves it fine.
3. **The CTFtime JSON API** (`/api/v1/results/2024/`) returns complete standings but with **`team_name: null`** for every entry — only numeric IDs. The *HTML* event page is the better source because it embeds names (`<a href="/team/302650">H@vOK</a>`).
4. **Grepping the obvious spellings** across all ten downloaded pages: `grep -ci "havo"` → **zero** everywhere. Even `havoc` → zero. The platform's own board (`ctf.sa/scoreboard`) 302-redirects to `/login` in every Wayback snapshot, so it was never archived.

### The pivot: question the spelling, not the source

The assumption to challenge was never *"where"* — it was *"how is it spelled."* CTF teams routinely register with leetspeak and punctuation, so instead of a literal match, scan with a substitution-tolerant pattern ([`find_team.py`](https://github.com/Abdelkad3r/KaliTeam-CTF26/tree/main/osint/guests)):

```python
LEET = {"a": "[a4@]", "o": "[o0]", "k": "[kcq]", "e": "[e3]", "i": "[i1l!]", "s": "[s5$]", "t": "[t7]"}
def fuzzy(name):
    parts = [LEET.get(c.lower(), re.escape(c)) for c in name if c.isalnum()]
    return re.compile(r"\W?".join(parts), re.I)   # \W? tolerates . _ - spaces
# "Havok" -> H\W?[a4@]\W?v\W?[o0]\W?[kcq]
```

Run over all ten scoreboards, the result is decisive: **`literal=0` on every event, `fuzzy=1` on exactly two** (2024 Final and 2024 Qualification). The team registered as **`H@vOK`** — `a → @` plus irregular capitalization. That single character defeats every search engine query, every `grep`, and every Wayback hunt. Printing `literal=0` next to `fuzzy=1` in the same table is what *proves* the obfuscation is real rather than a fetch bug.

### Pinning the three facts

- **Year — 2024.** [Team H@vOK (ID 302650)](https://ctftime.org/team/302650/) has only three events ever, one BH MEA appearance: 2024. No ambiguity.
- **Rank — 83.** They placed 119th in the Qualification and **83rd in the Final**; the prompt asks for the *final* ranking. One honest caveat: 83rd sits inside a 14-team block all tied on 600 points, so the rank comes from the organizer's published tie-break ordering, taken as published.
- **City — Riyadh.** Every edition runs in Riyadh (the 2024 event, 26–28 November, at the Riyadh Exhibition & Convention Centre in Malham) — confirmation, not discovery.

**Takeaway:** when a target is known to be inside a small, bounded set, stop querying search engines and scan the set directly — and question the *spelling* before you question the source. A literal `grep` is a weak instrument against a human-chosen, leetspeaked handle.

---

## Cross-cutting lessons from the KaliTeam CTF 2026 OSINT set

Two very different hunts, one mindset — **the fact is the easy part; access and representation are the challenge:**

- **The obstacle is usually not "where," it's "how."** The Unbroken Shelf's data sat in a public archive behind Cloudflare; Guests' data sat on a public scoreboard behind an `@`. Neither needed a secret source — both needed the right *access method* or the right *spelling*.
- **A 403 is a diagnosis, not a verdict.** Read the response body: a Cloudflare interstitial can sometimes be cleared with a headed browser; a User-Agent block just needs a browser UA; an origin error page is final. Each demands a different response.
- **Scan the bounded set, don't query the web.** Ten scoreboards and one newspaper corpus are enumerable. Once your target is provably inside a small space, direct scanning beats search-engine roulette.
- **Verify with something the source can't fake.** The 23-line tear alignment and the `literal=0`/`fuzzy=1` contrast are both self-contained proofs — they turn a plausible hit into a certain one without trusting a single lucky query.
- **Don't follow a hint off a cliff.** "The internet remembers everything" pointed hard at archive.org, which had nothing. A hint names the *theme*, not necessarily the tool.

## Reproduce it yourself

Both challenges ship a reproducible solver at [Abdelkad3r/KaliTeam-CTF26](https://github.com/Abdelkad3r/KaliTeam-CTF26) under `osint/<challenge>/`. The Unbroken Shelf includes `find_issue.js` (Playwright — clears Cloudflare, finds the issue, extracts the address and time) and `verify_alignment.py` (the independent 23-sliver tear-alignment proof), plus the original clipping. Guests ships `find_team.py`, which enumerates the Black Hat MEA series and fuzzy-scans every scoreboard. Each challenge folder also carries a standalone interactive HTML writeup.

Browse the full [CTF writeups](/ctf-writeups/) archive for more OSINT and geolocation walkthroughs, including our companion [L3akCTF 2026 OSINT writeup](/ctf-writeups/l3akctf-2026-osint-writeup/).

---

*This writeup is part of the CyberSecurity Elite [KaliTeam CTF 2026](/series/kaliteam-ctf-2026/) series. Challenge files, solver scripts, and interactive writeups for both OSINT challenges are published at [github.com/Abdelkad3r/KaliTeam-CTF26](https://github.com/Abdelkad3r/KaliTeam-CTF26).*
