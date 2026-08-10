---
title: "TraceBash CTF 2026 OSINT Writeup: 4 Challenges Solved"
slug: "tracebash-ctf-2026-osint-writeup"
description: "TraceBash CTF 2026 OSINT track writeup — geocaching lookup, Plus Code geolocation, NYC DOB open-data query, and cross-platform handle pivoting from a chat screenshot."
date: 2026-06-27T13:30:00Z
lastmod: 2026-08-04T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["TraceBash CTF 2026"]
tags:
  - "tracebash ctf"
  - "tracebash ctf 2026"
  - "osint"
  - "geocaching osint"
  - "plus code geolocation"
  - "exif metadata"
  - "nyc dob open data"
  - "handle pivoting"
  - "image anchor geolocation"
  - "open data api"
keywords:
  - "tracebash ctf 2026 osint writeup"
  - "tracebash osint writeup"
  - "echo chamber writeup"
  - "missing friend writeup"
  - "permit pending writeup"
  - "retired hacker writeup"
  - "ftf cache geocaching osint"
  - "plus code open location code lookup"
  - "nyc dob job filing number osint"
  - "komoot github threads handle pivot"
  - "mandalika motogp osint"
  - "image anchor geolocation osint"
  - "tbctf osint writeup"
  - "ctf osint step by step"
toc: true
cover:
  image: "/images/articles/tracebash-ctf-2026-osint-writeup.png"
  alt: "TraceBash CTF 2026 OSINT writeup — geocaching, Plus Codes, NYC DOB open data, and cross-platform handle pivoting"
---

**TraceBash CTF 2026**'s OSINT track covered four distinct public-record techniques: **echo-chamber** requires filtering a geocaching FTF log out of a noisy forum post and looking up cache code `GCK4GH`; **missing-friend** chains a MotoGP Pertamina signage anchor to Lombok and matches a Mexican bar's interior to compute a Google Plus Code; **permit-pending** queries the NYC Department of Buildings Open Data API to match a street-scene photo's signage to DOB job filing `120033169`; and **retired-hacker** pivots a Komoot profile URL through GitHub to a Threads post, then geolocates an image anchor in Timișoara to find the tram stop. This is the second post in the TraceBash CTF 2026 series on this site; the [crypto writeup](/ctf-writeups/tracebash-ctf-2026-crypto-writeup/) covered four cryptographic mistakes (small-subgroup DH, shared RSA prime, harmonic-XOR key recovery, 16-bit-seed brute).

The TraceBash OSINT track is a careful mix of techniques. **echo-chamber** is about filtering one specific clue out of a noisy forum post. **missing-friend** chains visual anchors in two photos into a Google Plus Code. **permit-pending** is the 310-point headline: a single street-scene photo plus the NYC Department of Buildings open-data API. **retired-hacker** is cross-platform handle pivoting (Komoot → GitHub → Threads → a Romanian tram stop). None of these challenges requires private databases, paid scrapers, or shady tools. All four use public web records, official open-data APIs, or open-source platforms in their normal documented modes.

Per-challenge READMEs, solver scripts, and the original handouts live at [Abdelkad3r/TraceBash-CTF-2026/osint](https://github.com/Abdelkad3r/TraceBash-CTF-2026/tree/main/osint).

## The four OSINT challenges

| Challenge | Bug class / technique | Points | Flag |
|---|---|---|---|
| echo-chamber | Filter a relevant clue (`FTF on the <cache name>`) out of a noisy forum post; geocaching lookup returns cache code `GCK4GH` | 100 | `TBCTF{gck4gh}` |
| missing-friend | Two phone photos with EXIF timestamps; visual anchor `PERTAMINA` brand → Mandalika circuit (Lombok); Mexican bar layout → Cantina Mexicana - Satu Lagi; Plus Code from pin coordinates | 100 | `TBCTF{475G+QQ}` |
| permit-pending | Manhattan street-scene photo with `W 25 ST` + `AVE OF THE AMERICAS` signs; NYC DOB Open Data query filtered on `WEST 25 STREET` + `3rd and 4th floor` matches job filing `120033169` at 130 W 25 St | 310 | `TBCTF{120033169}` |
| retired-hacker | Chat screenshot with a visible Komoot URL; profile name → GitHub handle `jiml33t` → Threads post May 7 2026; image anchor `IRIGATII.RO` → Calea Buziasului 13, Timișoara; tram stop near Auchan = `Piața Gheorghe Domășneanu` | 100 | `TBCTF{Piața_Gheorghe_Domășneanu}` |

The common thread is that each challenge asks for a verifiable, public identifier (a cache code, a Plus Code, a permit number, a transit-stop name). The flag format is the verification: if you've reached the right artifact through the right chain, the canonical identifier is the canonical answer.

## Methodology — public records first, paid tools never

A pattern that worked across all four challenges: when an OSINT task asks for a "unique public code" or "official permit number" or "Plus Code," the right starting point is the canonical source that issues those codes, not a generic search engine. Geocaching has a single public listing site. Plus Codes are defined by Open Location Code and computed deterministically from coordinates. NYC DOB filings are a single Open Data dataset. Tram stops in Timișoara are listed by the local public transport authority and aggregated by community sites like `ro.busti.me`. The right query against the right canonical source returns an exact match in seconds.

The trap is the opposite habit: throwing keywords at Google, hoping the right page surfaces in the first ten results. That works for celebrity addresses but rarely for the kind of verifiable, structured identifier these challenges ask for. The artifact ladder is: image / screenshot → distinctive textual or visual anchor → canonical platform that indexes that anchor → record ID. Each rung is shorter than the previous one when you climb in that order.

Detailed per-challenge walkthroughs follow.

## echo-chamber

### The setup

A short briefing and an HTML snapshot of a local forum thread. The target username is `rainyhike22`, the goal is to identify a real-world outdoor activity they recently logged, and the flag format asks for the activity's unique public code. The briefing notes explicitly that "not every detail in the post is a verifiable clue."

### Step 1 — Read the comment, ignore the noise

The relevant comment in `forum_thread.html`:

```
ugh, aerocascadia flight 1142 delayed AGAIN, another 3 hour wait
in the terminal lol. at least it's not pouring like last tuesday
though. anyway finally logged that tricky FTF on the son of
gasworks scrabble cache, took me 3 tries lmao
```

Two halves of the comment, two very different signal-to-noise ratios.

The first half (`aerocascadia flight 1142 delayed`, `3 hour wait`, `not pouring like last tuesday`) reads like a verifiable trail of clues, but none of it produces a unique public code. There's no airline-issued public ID for a passenger's complaint; the flight number maps to many flights across many dates; the weather quip doesn't anchor anything. This is the noise the briefing warned about.

The second half is structurally different. Three words matter:

- **`logged`**: the user is describing an activity they recorded somewhere.
- **`FTF`**: well-known geocaching shorthand for "first to find."
- **`cache`**: the geocaching unit of activity.

`FTF` plus `cache` plus a specific name (`son of gasworks scrabble`) is unambiguous. The activity is geocaching, and the canonical platform issues a unique cache code for every listing.

### Step 2 — Look up the cache on Geocaching.com

Search for the exact phrase `"Son of Gasworks Scrabble" geocache`. The public listing returns:

```
https://www.geocaching.com/geocache/GCK4GH_son-of-gasworks-scrabble
```

The cache code is in the URL slug: `GCK4GH`. The challenge flag format expects lowercase:

```
TBCTF{gck4gh}
```

### Why echo-chamber works as a teaching challenge

The lesson is signal-versus-noise. Most OSINT posts in the wild contain irrelevant filler around the one verifiable detail that maps to a public record. The trained reader's first pass is to identify which detail in the post is *uniquely indexable in a canonical platform* and discard everything else. `FTF cache` is uniquely indexable on Geocaching.com. `aerocascadia flight 1142` isn't uniquely indexable anywhere. The decision tree is short.

For real-world OSINT, the same heuristic catches credential leaks in pasted error messages (the stack trace is noise; the database password in the connection string is the signal), bot reports on social media (the bot's biography is noise; its API-key fragment in the pinned post is the signal), and threat-intel screenshots (the chrome theme is noise; the C2 hostname in the address bar is the signal).

## missing-friend

### The setup

Two recovered phone photos: `MotoGP.jpg` and `food.jpg`. The task is to identify the bar visited after a 2025 motorsport event and submit the bar's Google Maps Plus Code. The images don't carry GPS metadata, but they do carry EXIF timestamps:

```
MotoGP.jpg  2025:10:05 12:33:12
food.jpg    2025:10:05 19:55:30
```

Same day, motorsport in the early afternoon, bar visit around dinner time.

### Step 1 — Anchor the motorsport event to a place

`MotoGP.jpg` shows a motorcycle on track beside a large `PERTAMINA` sign. Pertamina is the Indonesian national oil company, and its branding appears at the **Pertamina Mandalika International Circuit** on the island of Lombok. The filename matches: the Indonesian round of the 2025 MotoGP World Championship at Mandalika is on October 5, 2025.

That fact pin-points the day's geography to the Kuta/Mandalika area of Lombok, not a generic MotoGP destination. The bar must be somewhere within a reasonable evening's travel of the circuit, which restricts the search to a few square kilometres of southern Lombok.

### Step 2 — Identify the bar from visual features

`food.jpg` shows a Mexican-themed venue:

- papel-picado banners hanging from the ceiling
- bright red, blue, green, and yellow bar fixtures
- long white tables and benches
- casual open-air dining

Searching for a Mexican bar in Kuta Lombok with those visual features surfaces **Cantina Mexicana - Satu Lagi** ([cantinamexicanalombok.com](https://www.cantinamexicanalombok.com/)). The venue's own gallery and embedded Google map confirm the interior styling matches.

The site's embedded map shows the Google Place ID for the venue:

```
0x2dcda948998aed77:0x76be8830436ddf38
```

### Step 3 — Compute the Plus Code (use the pin, not the viewport)

Google Maps shows the venue's pin coordinates as approximately:

```
-8.890527, 116.276995
```

[Open Location Code](https://maps.google.com/pluscodes/) encodes those coordinates as:

```
6P3R475G+QQ      (full Plus Code)
475G+QQ          (short Plus Code, local context)
```

The challenge format expects the short `XXXX+XX` form (Google Maps' default display for a named place), so the answer is:

```
TBCTF{475G+QQ}
```

**One trap worth flagging.** The venue's own website embeds a Google Maps iframe with both a pin (for the place itself) and a viewport center (for the map's framing). Encoding the viewport center instead of the pin produces a Plus Code that differs by the last two characters. Use the place pin coordinates, not the viewport center. The challenge's expected answer matches the pin; using the viewport flags an obvious off-by-one in the final code.

### Why missing-friend works

The chain is "anchor an event → narrow the geography → identify a specific venue from visual features → compute the canonical identifier." Each step is short and uses publicly indexed information: the MotoGP calendar, Google Maps Place index, Open Location Code conversion. The skill being tested is **chaining anchors**, not finding any single anchor in isolation.

For defenders, the implication is that any photo posted from a known business or event venue is geo-identifiable even when GPS metadata is stripped, as long as the venue has distinctive visual branding (signage, interior decor, distinctive layout). Stripping EXIF doesn't anonymise a photo whose contents are visually unique.

## retired-hacker

### The setup

One image, `chat.jpeg`, a Discord-style screenshot of a conversation. The target says he's moved on from hacking to outdoor activity logging. The goal is to identify where the trail leads on May 7, 2026, and submit the tram station where he got off.

### Step 1 — Read the screenshot text, don't waste time on metadata

The useful clue is not hidden in EXIF or steganography. It's in the chat body, in plain text:

```
https://www.komoot.com/user/5667624959835
```

Komoot is a real outdoor-activity platform, the URL is a public profile, and opening it identifies the user as `Jim Lee`. The profile bio links to a GitHub account:

```
https://github.com/jiml33t
```

Stable handle: `jiml33t`. That's the pivot point for everything that follows.

### Step 2 — Pivot the handle across platforms

`jiml33t` on GitHub presents an ex-hacker turned avid runner and security consultant. Same persona, same handle. Searching the handle elsewhere surfaces public posts on Threads, the relevant one dated May 7, 2026:

```
https://www.threads.com/@jiml33t/post/DYCg8B1iMAl
```

The post text describes the user finishing a run and "hopping on the tram for coffee at a French supermarket." That gives the action (took a tram), the destination type (French supermarket), and a date. The post's attached image then geolocates the rest.

### Step 3 — Geolocate the image anchor

The attached image shows a sign reading `IRIGATII.RO` (Romanian for "irrigations"). One search for the business name surfaces:

```
Irigatii.ro
Calea Buziasului nr. 13, Timișoara
```

That places the run in Timișoara, Romania. "French supermarket" in Timișoara strongly implies an **Auchan** location (Auchan is a French retail chain with a presence in Romanian cities).

### Step 4 — Find the tram stop, not the supermarket

The challenge asks for the tram station, not the store. Timișoara's public transport authority publishes the stop list at [smtt.ro](https://smtt.ro/statii-transport-public/); the relevant area has two stops named:

```
Piața Gheorghe Domășneanu (Auchan)
Piața Gheorghe Domășneanu (Liviu Rebreanu - AEM)
```

The tram-9 route page (community-aggregated at `ro.busti.me`) confirms the terminal stop near the Auchan as:

```
Piața Gheorghe Domășneanu (Liviu Rebreanu)
```

The flag format uses underscores between words and preserves Romanian diacritics:

```
TBCTF{Piața_Gheorghe_Domășneanu}
```

The parenthetical route/location modifier is dropped because the station name is the canonical anchor; the parenthetical only disambiguates between two physically-adjacent stops.

### Why retired-hacker works

The skill is **handle persistence**. A single handle that recurs across platforms is the OSINT investigator's gold; one platform's bio links to another platform's profile, which links to another platform's posts, until you've traced a verifiable timeline. None of the individual platforms here is unusual (Komoot, GitHub, Threads), and none of the lookups requires anything beyond the public web. The chain works because the target persona is consistent across all three.

For real-world OPSEC, the lesson is symmetric: pick handles that don't trivially link across platforms. The persona-portability that makes social platforms convenient also makes them collectively a single profile to a determined investigator. The Komoot-to-GitHub link in the bio is the entire pivot here; without it, the chain would never have started.

## permit-pending

The 310-point headline of the OSINT track. The handout is a single image of a building under renovation. The goal is to identify the building, locate the official public DOB filing for an interior renovation on its 3rd and 4th floors, and submit the 9-digit job filing number.

### Step 1 — Read the visible street signs

The photo shows a Manhattan street scene with several useful details:

- a green street sign for `W 25 ST`
- a second sign for `AVE OF THE AMERICAS`
- scaffolding along the sidewalk
- a Chelsea-style commercial/office building with fire escapes and renovation coverage

The street signs are the reliable anchor. The scene is on **West 25th Street in Chelsea**, near Avenue of the Americas (Sixth Avenue). Some of the smaller façade text in the image is blurry or angled and easy to misread; the safer move is to treat the visible street location as the search area and let the structured data identify the exact building.

### Step 2 — Pick the right canonical dataset

The challenge asks for a 9-digit job filing number, which is the format New York City's Department of Buildings uses for legacy job filings. NYC Open Data publishes this as the `DOB Job Application Filings` table:

```
https://data.cityofnewyork.us/resource/ic3t-wcy2.json
```

That dataset is a Socrata endpoint with full SQL-ish filtering via `$where`. Filtering on Manhattan, the right street name, and the renovation wording from the challenge prompt produces a tractable result set.

### Step 3 — Build a tight filter query

Two filter clauses do the work:

```bash
curl -sG 'https://data.cityofnewyork.us/resource/ic3t-wcy2.json' \
  --data-urlencode '$limit=50000' \
  --data-urlencode '$where=borough="MANHATTAN" AND upper(street_name) like "%25 STREET%"' \
| jq -r '.[] |
    select((.street_name|ascii_upcase|gsub(" ";""))=="WEST25STREET") |
    select((.job_description // "") | test("3rd and 4th|3RD AND 4TH|third and fourth"; "i")) |
    [.job__, .house__, .street_name, .owner_s_business_name, .job_description] |
    @tsv'
```

The `$where` clause narrows to Manhattan filings whose street name contains `25 STREET`. The first `jq` filter rejects East-25th and similar near-matches by collapsing whitespace and matching `WEST25STREET` exactly. The second `jq` filter matches the challenge wording about a third-and-fourth-floor renovation.

The output is one row:

```
120033169  130  WEST   25 STREET  25 BUILDING ASSOCIATES LLC
  PROPOSE INTERIOR RENOVATION TO THE 3RD AND 4TH FLOOR
  NO CHANGE TO USE EGRESS OR OCCUPANCY
```

That identifies the building as **130 West 25 Street**, owned by `25 BUILDING ASSOCIATES LLC`, with a job description that matches the challenge prompt's 3rd-and-4th-floor wording exactly.

### Step 4 — Verify and submit

Cross-checking the job number against the same dataset confirms the record:

```
job__: 120033169
house__: 130
street_name: WEST   25 STREET
owner_s_business_name: 25 BUILDING ASSOCIATES LLC
job_description: PROPOSE INTERIOR RENOVATION TO THE 3RD AND 4TH FLOOR
                 NO CHANGE TO USE EGRESS OR OCCUPANCY
```

The 9-digit job filing number is `120033169`:

```
TBCTF{120033169}
```

### Why permit-pending works

The chain is "read the street signs → identify the right canonical dataset → write a tight query → verify." None of the steps requires guessing the building number from the photo (which would be fragile because the façade text is hard to read). The canonical NYC DOB Open Data API does the identification for you once the query is specific enough.

This pattern generalises to most jurisdictional OSINT. **Building permits, business registrations, court filings, property records, vehicle registrations, tax assessor data, license filings**: almost every major municipality in the world publishes some subset of these as structured open data, with documented APIs. For US OSINT specifically: NYC Open Data, LA Open Data, SF DataSF, Chicago Data Portal, federal SAM.gov, USAspending, EDGAR (SEC filings), Patents.gov, the FAA aircraft registry, FCC license database. For a particular kind of identifier, there's almost always one canonical dataset, and writing a filter query against it returns matches in seconds instead of hours of guessing.

For OSINT defenders (or anyone advising sources on operational security), the implication is that public records that look obscure individually are catastrophic to pseudonymity in aggregate. A permit filing, an LLC registration, a property record, and a court filing on the same address can de-anonymise a deliberately-disguised owner in minutes via cross-reference, all using only publicly-published structured data.

## Cross-cutting OSINT notes

Three patterns recur across the TraceBash OSINT track and travel into real investigations.

**Canonical sources beat search engines for structured identifiers.** Cache codes (Geocaching.com), Plus Codes (Open Location Code), DOB job numbers (NYC Open Data), transit stop names (local PTA + community aggregators). Every one of these is a single authoritative source. The investigator's job is to recognise which identifier is being asked for and skip Google entirely.

**Handle persistence is the cheapest pivot in social-platform OSINT.** retired-hacker's chain works because `jiml33t` is the same handle across Komoot, GitHub, and Threads. The Komoot bio links to GitHub; the GitHub profile establishes the handle's authenticity; Threads has the dated post that anchors the timeline. None of the platforms is unusual; the chain is what matters. Recommended OPSEC reading: pick uncorrelated handles for any persona you want to keep distinct, including ones you think no one will ever care about.

**Photos without GPS are still geolocatable when the contents are visually unique.** missing-friend's bar identification doesn't use a single byte of metadata. The papel-picado banners, the colour palette, the layout: these are the equivalent of a fingerprint to anyone who's seen the venue's own gallery. permit-pending uses the same property: the building façade is identifiable from street signage even when EXIF is stripped. Stripping metadata is necessary but not sufficient for anonymising a photo whose subject is visually distinctive.

## Frequently asked questions

### What is TraceBash CTF?

TraceBash CTF is a Jeopardy-style CTF whose 2026 edition shipped challenges across cryptography, web, reverse, forensics, pwn, misc, and OSINT. This writeup covers the four OSINT challenges. The flag prefix is `TBCTF{...}`. Per-challenge READMEs and solver scripts live at [Abdelkad3r/TraceBash-CTF-2026](https://github.com/Abdelkad3r/TraceBash-CTF-2026).

### What's the trick in echo-chamber?

The forum post mixes three categories of detail: airline complaints, weather chatter, and an outdoor-activity log. Only the third category has a unique public identifier; the other two don't index to anything specific. The phrase `FTF on the son of gasworks scrabble cache` is unambiguous geocaching shorthand. Searching the cache name on Geocaching.com surfaces the public listing with code `GCK4GH`. The flag format uses lowercase.

### What is `FTF` in geocaching?

`FTF` stands for "first to find." Geocachers compete to be the first person to locate a newly-published cache, and "FTF" status is a small community honour. The shorthand is universal on geocaching forums and posts, which makes the term a reliable signal for the activity in OSINT contexts.

### How do you identify the bar in missing-friend?

Two photos with EXIF timestamps give the day. The first photo shows a `PERTAMINA` sign at the Mandalika International Circuit (Lombok, Indonesia); the 2025 Indonesian MotoGP weekend was October 5. That narrows the search to the Kuta Lombok area. The second photo's visual features (papel-picado banners, bright Mexican-themed colour scheme, open-air seating) match Cantina Mexicana - Satu Lagi. The bar's website confirms the venue.

### Why pin coordinates instead of viewport center for the Plus Code?

A Google Maps embedded iframe carries two coordinate pairs: the place pin (where the named venue actually is) and the viewport center (where the map frames the view). The two can differ by tens of metres for a venue near the edge of the displayed area. Open Location Code is precise enough that this difference changes the last two characters of the short Plus Code. The challenge expects the pin's encoding, not the viewport's.

### How do you pivot from a Komoot URL to a Romanian tram stop?

The Komoot profile links to a GitHub handle (`jiml33t`). The handle recurs on Threads, where a May 7 post describes a run and a tram ride. The attached image shows an `IRIGATII.RO` business sign, which geolocates to Calea Buziasului 13 in Timișoara. "French supermarket" matches the nearby Auchan, and the tram stops near that Auchan are listed by the Timișoara public transport authority. The relevant stop is `Piața Gheorghe Domășneanu`.

### What's the NYC DOB Open Data query for permit-pending?

A Socrata `$where` filter on the `DOB Job Application Filings` resource at `ic3t-wcy2.json`, narrowing to Manhattan filings whose street name contains `25 STREET`. A subsequent `jq` filter rejects East-25th matches by collapsing whitespace and comparing exactly to `WEST25STREET`, then matches the job description against the challenge's "3rd and 4th floor" wording. The unique result is job `120033169` at 130 West 25 Street, owned by 25 BUILDING ASSOCIATES LLC.

### Why use the API instead of guessing the building number from the photo?

The street signs in the photo are reliable; the building façade text is partially obscured by scaffolding and easy to misread. Guessing a building number from the photo gives a confidence-weighted candidate that needs verification anyway. Querying the canonical NYC DOB dataset with the unambiguous parts of the prompt (street, renovation wording) returns a verified match in one step.

### What public datasets are useful for jurisdictional OSINT in general?

For US contexts: NYC Open Data, LA Open Data, SF DataSF, Chicago Data Portal, federal SAM.gov, USAspending, EDGAR (SEC filings), Patents.gov, FAA aircraft registry, FCC license database. For international contexts: most large municipalities publish some subset of building permits, business registrations, property records, and court filings as structured open data, often via a Socrata-style API. The investigator's first move on any jurisdictional question should be to identify the relevant canonical dataset.

### Where can I find the solver scripts?

Per-challenge READMEs and Python solvers live at [Abdelkad3r/TraceBash-CTF-2026/osint](https://github.com/Abdelkad3r/TraceBash-CTF-2026/tree/main/osint). Each challenge directory has the original handout, a `solve.py` that reproduces the evidence chain and prints the flag, and a `README.md` documenting the reasoning step by step.

### What's the broader lesson from the TraceBash OSINT track?

Public records and platforms with well-known identifier formats are the OSINT primary surface in 2026. Geocaching cache codes, Plus Codes, DOB job filings, transit stop names: each is a single authoritative source with an unambiguous answer. Recognise which identifier the challenge is asking for, find the canonical platform that issues it, and query it directly. Generic search engines are a fallback, not a first move.

## Closing notes

Four challenges, four shapes of public-record OSINT. echo-chamber at 100 points filters one signal out of a noisy post. missing-friend at 100 points chains a motorsport anchor with a venue-feature lookup and a Plus Code conversion. retired-hacker at 100 points pivots a handle across Komoot, GitHub, and Threads to a Romanian tram stop. permit-pending at 310 points uses the NYC DOB Open Data API to identify a Chelsea building from a single street-scene photo.

For more OSINT writeups on this site, the [Anti-Slop CTF 2026 OSINT writeup](/ctf-writeups/anti-slopctf-2026-osint-writeup/) covers two distinct OSINT shapes (a GitHub artifact-trail flag-fragment hunt and a Geoguessr-style game with client-side H3-cell-derived Argon2 keys). The [GPN CTF 2026 master writeup](/ctf-writeups/gpn-ctf-2026-writeup/) includes the misc track challenge `organized` whose 7.65 MB "noise" file decodes to a ternary amplitude-modulated UART stream, and the [BhAcKAri CTF 2026 writeup](/ctf-writeups/bhackari-ctf-2026-writeup/) covers an LSB stego challenge whose seed key is the name of a Venetian *bacaro*. Full [CTF writeups index](/ctf-writeups/) for everything else.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {"@type": "Question","name": "What is TraceBash CTF?","acceptedAnswer": {"@type": "Answer","text": "TraceBash CTF is a Jeopardy-style CTF whose 2026 edition shipped challenges across cryptography, web, reverse, forensics, pwn, misc, and OSINT. This writeup covers the four OSINT challenges. The flag prefix is TBCTF{...}. Per-challenge READMEs and solver scripts live at github.com/Abdelkad3r/TraceBash-CTF-2026."}},
    {"@type": "Question","name": "What's the trick in echo-chamber?","acceptedAnswer": {"@type": "Answer","text": "The forum post mixes airline complaints, weather chatter, and an outdoor-activity log. Only the third has a unique public identifier. The phrase FTF on the son of gasworks scrabble cache is unambiguous geocaching shorthand. Searching the cache name on Geocaching.com surfaces the public listing with code GCK4GH."}},
    {"@type": "Question","name": "What is FTF in geocaching?","acceptedAnswer": {"@type": "Answer","text": "FTF stands for first to find. Geocachers compete to be the first person to locate a newly-published cache, and FTF status is a small community honour. The shorthand is universal on geocaching forums."}},
    {"@type": "Question","name": "How do you identify the bar in missing-friend?","acceptedAnswer": {"@type": "Answer","text": "Two EXIF timestamps give the day. The first photo's PERTAMINA sign matches the Mandalika International Circuit (Lombok), and the 2025 Indonesian MotoGP was October 5. That narrows the search to Kuta Lombok. The second photo's papel-picado banners and Mexican colour scheme match Cantina Mexicana - Satu Lagi. The venue's own website confirms it."}},
    {"@type": "Question","name": "Why pin coordinates instead of viewport center for the Plus Code?","acceptedAnswer": {"@type": "Answer","text": "A Google Maps embedded iframe carries both a place pin and a viewport center. The two can differ by tens of metres for a venue near the edge of the displayed area. Open Location Code is precise enough that this difference changes the last two characters of the short Plus Code. The challenge expects the pin's encoding."}},
    {"@type": "Question","name": "How do you pivot from a Komoot URL to a Romanian tram stop?","acceptedAnswer": {"@type": "Answer","text": "The Komoot profile links to a GitHub handle (jiml33t). The handle recurs on Threads, where a May 7 post describes a tram ride to a French supermarket with an attached image showing an IRIGATII.RO sign. That sign geolocates to Calea Buziasului 13 in Timișoara. The nearby Auchan tram stops are listed by the Timișoara public transport authority; the relevant stop is Piața Gheorghe Domășneanu."}},
    {"@type": "Question","name": "What's the NYC DOB Open Data query for permit-pending?","acceptedAnswer": {"@type": "Answer","text": "A Socrata $where filter on the DOB Job Application Filings resource (ic3t-wcy2.json), narrowing to Manhattan filings whose street name contains 25 STREET. A jq filter rejects East-25th matches by collapsing whitespace and comparing to WEST25STREET, then matches the job description against the 3rd and 4th floor wording. The unique result is job 120033169 at 130 West 25 Street, owned by 25 BUILDING ASSOCIATES LLC."}},
    {"@type": "Question","name": "Why use the API instead of guessing the building number?","acceptedAnswer": {"@type": "Answer","text": "The street signs in the photo are reliable; the façade text is partially obscured and easy to misread. Querying the canonical NYC DOB dataset with the unambiguous parts of the prompt (street, renovation wording) returns a verified match in one step."}},
    {"@type": "Question","name": "What public datasets are useful for jurisdictional OSINT?","acceptedAnswer": {"@type": "Answer","text": "US: NYC Open Data, LA Open Data, SF DataSF, Chicago Data Portal, federal SAM.gov, USAspending, EDGAR (SEC filings), Patents.gov, FAA aircraft registry, FCC license database. International: most large municipalities publish some subset of building permits, business registrations, property records, and court filings as structured open data, often via a Socrata-style API."}},
    {"@type": "Question","name": "Where can I find the solver scripts?","acceptedAnswer": {"@type": "Answer","text": "Per-challenge READMEs and Python solvers live at github.com/Abdelkad3r/TraceBash-CTF-2026/tree/main/osint. Each challenge directory has the original handout, a solve.py that reproduces the evidence chain, and a README.md documenting the reasoning."}},
    {"@type": "Question","name": "What's the broader lesson from the TraceBash OSINT track?","acceptedAnswer": {"@type": "Answer","text": "Public records and platforms with well-known identifier formats are the OSINT primary surface in 2026. Geocaching codes, Plus Codes, DOB filings, transit stop names — each is a single authoritative source with an unambiguous answer. Recognise which identifier the challenge is asking for, find the canonical platform, and query it directly."}}
  ]
}
</script>
