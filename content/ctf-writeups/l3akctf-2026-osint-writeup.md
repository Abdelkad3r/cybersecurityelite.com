---
title: "L3akCTF 2026 OSINT Writeup: Crossroads & Overgrown Ruins"
slug: "l3akctf-2026-osint-writeup"
description: "Full L3akCTF 2026 OSINT writeup covering both geolocation challenges: reading a road sign (TRAIL CR RD) and a realty phone number (208-588-2707) off a 360-degree panorama to pin an intersection on Trail Creek Road near Mackay, Idaho (Crossroads); and matching ivy-covered ruins with a lakeside car park and UK signage to Old Wardour Castle in Wiltshire — the Robin Hood: Prince of Thieves filming location (Overgrown Ruins). Both are solved by extracting text and landmark clues from the panorama, pivoting to public records and OpenStreetMap, and submitting coordinates to the challenge's JSON endpoint."
date: 2026-08-06T19:00:00Z
lastmod: 2026-08-06T19:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
series: ["L3akCTF 2026"]
tags:
  - "l3akctf"
  - "l3akctf 2026"
  - "ctf writeup"
  - "osint"
  - "geoint"
  - "geosint"
  - "geolocation"
  - "geoguessr"
  - "image geolocation"
  - "panorama analysis"
  - "openstreetmap"
  - "street view"
  - "reverse image search"
  - "phone number osint"
  - "photo sphere viewer"
  - "leaflet"
  - "ctf 2026"
keywords:
  - "l3akctf 2026 osint writeup"
  - "l3akctf 2026 geolocation writeup"
  - "crossroads ctf writeup"
  - "overgrown ruins ctf writeup"
  - "geosint ctf writeup"
  - "ctf geolocation methodology"
  - "trail creek road mackay idaho osint"
  - "old wardour castle robin hood osint"
  - "panorama sign geolocation ctf"
  - "phone number area code osint pivot"
  - "openstreetmap way coordinate ctf"
  - "osint ctf 2026"
toc: true
cover:
  image: "/images/articles/l3akctf-2026-osint-writeup.png"
  alt: "L3akCTF 2026 OSINT writeup covering both geolocation challenges — Crossroads reads a green road sign reading TRAIL CR RD and a Trail Creek Realty sign with the phone number 208-588-2707 off a 360-degree panorama, uses the 208 area code and the phone number to identify Trail Creek Road near Mackay Idaho, and submits the accepted coordinate on OpenStreetMap; and Overgrown Ruins matches ivy-covered stone ruins with a surviving tower, a lakeside car park, an estate access road, and UK-style parking signage plus a 2020 Google Street View watermark to Old Wardour Castle in Wiltshire England, the filming location for Robin Hood Prince of Thieves, submitting its coordinate to the challenge JSON endpoint"
---

OSINT at L3akCTF 2026 was a two-challenge geolocation track built on the same self-hosted "geosint" engine — a 360° panorama, a Leaflet map, and a JSON endpoint that accepts a coordinate and hands back the flag if you're close enough. No metadata to scrape, no EXIF GPS: the whole game is **reading the scene, extracting a clue that anchors it to the real world, and pivoting through public records** until the map agrees with you.

This **CyberSecurity Elite** L3akCTF 2026 OSINT writeup walks both challenges end to end, emphasizing the geolocation *methodology* — which clue to trust, and what to pivot into — rather than just the final coordinates. Challenge evidence images and solve scripts are at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026). For the rest of the event, see the [binary exploitation](/ctf-writeups/l3akctf-2026-pwn-writeup/), [cryptography](/ctf-writeups/l3akctf-2026-crypto-writeup/), [miscellaneous](/ctf-writeups/l3akctf-2026-misc-writeup/), and [web](/ctf-writeups/l3akctf-2026-web-writeup/) writeups.

## Both challenges at a glance

| Challenge | Difficulty | Points | Solves | Location | Key clue |
|---|---|---:|---:|---|---|
| [Crossroads](#crossroads--let-the-signs-do-the-work) | Beginner | 78 | 114 | Trail Creek Road, Mackay, Idaho | Road sign + realty phone number |
| [Overgrown Ruins](#overgrown-ruins--a-castle-a-lake-and-a-hollywood-footnote) | Medium | 105 | 62 | Old Wardour Castle, Wiltshire, England | Distinctive ruin + lakeside layout |

## Reading the geosint engine

Before either scene, it pays to understand the harness. Every geosint challenge is a small Leaflet + Photo Sphere Viewer app that pulls its metadata from a `/<challenge>/config` endpoint, for example:

```json
{"title":"Crossroads","maxZ":5,"width":32,"height":16,"heading":45.91933402249994}
```

Two practical takeaways. First, the panorama is served as a grid of WebP tiles (here 32×16), and a full-resolution `preview.webp` is usually enough to read signage — you rarely need to stitch tiles by hand. Second, the checker is just a `POST /<challenge>/submit` with a `[lat, lon]` body that replies `yes, <flag>`. That means once you've narrowed a location to a road or a landmark, you can **test candidate coordinates directly** instead of pixel-hunting for the exact pin:

```bash
curl -sS -X POST https://geosint.ctf.l3ak.team/crossroads/submit \
  -H 'Content-Type: application/json' --data '[44.064631,-113.8787496]'
```

That "test the geometry against the endpoint" trick is what turns both challenges from precise pin-dropping into ordinary OSINT.

---

## Crossroads — let the signs do the work

> *Flag:* `L3AK{S1gNs_M4k3_051Nt_RaTh3R_SimPLE!}`

The panorama is a scenic rural mountain-valley intersection — the kind of wide, featureless landscape that looks impossible until you zoom into the signage. Two signs carry the entire solve.

**Clue 1 — the road sign.** A green road marker near the intersection reads `TRAIL CR RD` (Trail Creek Road). On its own that's a common name, but it narrows the search enormously when combined with the second clue.

**Clue 2 — the realty phone number.** A Trail Creek Realty sign in the field shows the phone number `208-588-2707`. This is the anchor: the `208` area code is **Idaho**, and searching the full number identifies *Trail Creek Realty in Mackay, Idaho*. A phone number is one of the strongest OSINT pivots available — unlike a place name it's globally unique, so it collapses "some Trail Creek Road" into a specific valley.

**The pivot.** With "Trail Creek Road, Mackay, Idaho" as the hypothesis, OpenStreetMap has the matching [way](https://www.openstreetmap.org/way/210960398). The obvious first guess — the US-93 intersection east of the road — was *rejected* by the checker, a good reminder that the intended pin is often a quieter crossing, not the most prominent junction. Walking the road geometry and testing candidate points against the submit endpoint quickly landed the accepted coordinate:

```text
44.064631, -113.8787496  →  yes, L3AK{S1gNs_M4k3_051Nt_RaTh3R_SimPLE!}
```

**Takeaway:** in geolocation, prioritize clues by *uniqueness*. A phone number or business name beats a road sign, which beats generic terrain — and when the checker is queryable, brute-check the road geometry rather than agonizing over the exact pixel.

---

## Overgrown Ruins — a castle, a lake, and a Hollywood footnote

> *Flag:* `L3AK{D1d_y0U_kNow_th3y_f1lM3D_R0b1N_hOoD_H3r3?_https://movie-locations.com/movies/r/Robin-Hood-Prince-Of-Thieves.php}`

No text this time — just architecture and layout. The panorama shows a distinctive **ivy-covered stone ruin with a surviving tower and wall sections**, a small paved car park, a narrow estate-style access road, a body of water beside the path, UK-style parking and path signage, and a cloudy winter Street View scene watermarked `2020 Google`.

**Building the fingerprint.** The winning move is to treat the scene as a *set of simultaneous constraints* rather than chasing the ruin alone:

- overgrown medieval stonework with a tall surviving tower;
- a lake or pond **immediately beside** the access road (this single detail eliminates most castle ruins);
- a small visitor car park and estate paths;
- British signage and a Google Street View watermark → UK, and Street View coverage means a road/estate car park, not deep backcountry.

The first instinct — Scottish and Irish lochside ruins (Mugdock, Invergarry, Loch an Eilein, Lochmaben, Scotney) — was tested and rejected. The combination of *tower + lake-beside-the-road + visitor car park + Street View access* is what points to **Old Wardour Castle in Wiltshire, England**: a 14th-century ruin with an adjacent lake, a small car park, and narrow estate paths.

**The confirming detail.** Old Wardour was a filming location for *Robin Hood: Prince of Thieves* — a fact the flag itself rewards, embedding the [movie-locations.com reference](https://movie-locations.com/movies/r/Robin-Hood-Prince-Of-Thieves.php). English Heritage and OpenStreetMap both confirm the site, and the accepted coordinate closed it out:

```text
51.0373000, -2.0896402  →  yes, L3AK{D1d_y0U_kNow_th3y_f1lM3D_R0b1N_hOoD_H3r3?_...}
```

**Takeaway:** when there's no readable text, geolocate by *conjunction of features*. Any one of "ruin," "lake," or "car park" matches thousands of places; the intersection of all three — plus a Street View watermark bounding the country and era — resolves to one. Distinctive ruins also tend to have a filming or heritage footprint worth a targeted search.

---

## Cross-cutting lessons from the L3akCTF 2026 OSINT set

Two very different scenes, one methodology:

- **Rank clues by uniqueness.** A phone number (Crossroads) or a named heritage ruin (Overgrown Ruins) anchors a location far faster than terrain or a common road name. Find the most globally-unique element in frame and pivot on that first.
- **Geolocate by conjunction.** When no single clue is decisive, stack constraints — tower *and* lakeside *and* car park *and* Street View watermark — until only one candidate survives.
- **Read the harness.** The `/config` metadata and a queryable `/submit` endpoint mean you can test coordinates directly. Narrow to a road or landmark, then let the checker confirm the exact pin.
- **The obvious junction is often wrong.** Both scenes rewarded the *quieter* pin (a minor crossing; a specific castle among many lakeside ruins) over the first prominent guess — expect to test and reject a few candidates.

## Reproduce it yourself

Both challenges ship their extracted evidence images and a `solve.sh` at [Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026) under `osint/<challenge>/` — the Trail Creek road and realty signs for Crossroads, and the stitched panorama strip, ruin, car park, and path-and-water crops for Overgrown Ruins. Each per-challenge `README.md` records the config metadata, the reference links (OpenStreetMap ways, English Heritage, movie-locations.com), and the exact accepted coordinates.

Pair this with the [L3akCTF 2026 pwn](/ctf-writeups/l3akctf-2026-pwn-writeup/), [crypto](/ctf-writeups/l3akctf-2026-crypto-writeup/), [misc](/ctf-writeups/l3akctf-2026-misc-writeup/), and [web](/ctf-writeups/l3akctf-2026-web-writeup/) writeups, or browse the full [CTF writeups](/ctf-writeups/) archive for more OSINT and geolocation walkthroughs.

---

*This writeup is part of the CyberSecurity Elite [L3akCTF 2026](/series/l3akctf-2026/) series. Evidence images and solve scripts for both OSINT challenges are published at [github.com/Abdelkad3r/L3akCTF-2026](https://github.com/Abdelkad3r/L3akCTF-2026).*
