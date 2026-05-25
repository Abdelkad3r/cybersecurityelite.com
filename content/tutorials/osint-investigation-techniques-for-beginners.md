---
title: "OSINT Investigation Techniques for Beginners"
slug: "osint-investigation-techniques-for-beginners"
description: "Find the person behind a username, geolocate a photo, pivot through breach data — practical OSINT techniques investigators actually run on live cases."
date: 2026-04-29T11:00:00Z
lastmod: 2026-04-29T11:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tutorials"]
tags: ["osint", "investigation", "recon", "threat intelligence"]
keywords: ["osint", "open source intelligence", "osint techniques"]
toc: true
cover:
  image: "/images/articles/osint-investigation-techniques-for-beginners.png"
  alt: "OSINT investigation techniques for beginners"
---

OSINT — open-source intelligence — is the systematic collection of public data to answer a specific question. Done well, it's the single highest-leverage skill in incident response, threat intel, due diligence, and bug bounty recon. Done poorly, it's hours of dead Google links.

## The Investigation Framework

Every OSINT investigation begins with a question and a pivot graph.

```text
Question → Selectors → Pivots → Selectors → ... → Answer
```

A **selector** is an identifier — username, email, phone, image, domain, hash. A **pivot** is a service or technique that turns one selector into others. The skill is choosing which pivots will yield the next useful selector.

## Common Pivots

### Email Address

1. **HaveIBeenPwned** — which breaches?
2. **Hunter.io** — pattern detection (`first.last@company.com`) implies other employees.
3. **Account presence** — Pinterest, Spotify, Skype all leak signal when you query unauthenticated.
4. **Gravatar** — `MD5(lower(email))` → public profile photo if registered.

### Username

1. **Sherlock / WhatsMyName** — scan hundreds of platforms automatically.
2. **GitHub search** — code, gists, commits. Old commits often expose real names and personal emails.
3. **Reverse image** of profile photos via Google Lens, Yandex, TinEye.

### Phone Number

1. **TrueCaller / GetContact** (regional coverage varies).
2. **PhoneInfoga** for carrier and country metadata.
3. **WhatsApp / Telegram / Signal** — presence checks reveal account existence on those platforms.

### Domain Name

1. **WHOIS** (note GDPR redactions are heavy for EU registrants).
2. **Certificate Transparency** via `crt.sh` — every issued TLS certificate, hostname-rich.
3. **DNS history** via SecurityTrails or DNSDumpster.
4. **Wayback Machine** for historical content.
5. **Same-IP neighbors** (Censys, Shodan) — often more useful than ASN.

### Image

1. **Reverse image search** — Yandex consistently outperforms Google for face matches.
2. **EXIF metadata** — GPS coordinates, camera, timestamps. Strip-on-upload is standard now, but legacy images are everywhere.
3. **Geolocation by content** — sun position, license plates, road signs, shop chains. The Bellingcat playbook.

### Person

1. **LinkedIn** — employer, location, skills. Always pivot on what employer permits you to see (network connections).
2. **Twitter/X advanced search** — geolocated old posts.
3. **Public records** — varies wildly by country.

## Tools Worth Installing

```bash
# Username enumeration
sherlock <username>

# Phone metadata
phoneinfoga scan -n +14155552671

# Email enumeration
holehe email@example.com

# Domain pivots
amass intel -org "Target Inc"
crt.sh search → CSV

# Image geolocation help
geospy / GeoSpy (commercial), exiftool (metadata)
```

## Working With Breach Data

Breach corpora (DeHashed, IntelX, public combo lists) are the most powerful OSINT pivot — and the legally riskiest. In most jurisdictions, **reading aggregated public breach data is legal**; using it to access an account is not.

For investigators:

- HaveIBeenPwned's enterprise API delivers breach lists without raw passwords.
- Domain-search on HaveIBeenPwned reveals which corporate emails have appeared in breaches — invaluable for incident scoping.

## OPSEC for OSINT

You leave fingerprints when collecting:

- **Use a dedicated research browser.** Firefox Containers or a separate profile, never your daily driver.
- **Disposable accounts** for platforms requiring login. Don't reuse names.
- **VPN or residential proxy** for sensitive targets — Tor stands out for some sites and is blocked by many.
- **No logged-in Google searches** on the target.
- **Never query the target's own resources** (their support portal, their booking system) from your tracked accounts.

Operational mistake of the year: investigators using their personal LinkedIn to scope hostile actors — making themselves the target.

## Ethics and Law

OSINT lives in tension between freedom-of-information and stalking. A short rule of thumb:

- **Aggregated public data** about a public-figure capacity (work email, public posts) — generally fine.
- **Aggregated public data** about a private individual — depends heavily on jurisdiction and purpose.
- **Doxxing for harassment** — illegal in most countries.

Get explicit authorization for OSINT inside engagements. Insurance for security companies often excludes findings outside written scope.

## A Sample Investigation Flow

Question: "Who runs this scam crypto site?"

1. Domain → WHOIS (redacted) → CT logs → 14 sibling domains
2. Sibling domains → shared analytics ID in HTML
3. Analytics ID → reverse-lookup tool → 60 unrelated sites with same ID (likely shared developer)
4. Pick most-active site → contact page → email
5. Email → HIBP → 4 breaches → reuse passwords found in dumps
6. Email → Gravatar → photo → Yandex → personal Instagram
7. Instagram → username → other accounts via Sherlock → real name

90 minutes of work; one selector at a time.

## References

- [OSINT Framework](https://osintframework.com/) — directory of tools
- [Bellingcat's Online Investigations Toolkit](https://www.bellingcat.com/category/resources/)
- [Trace Labs OSINT Search Party](https://www.tracelabs.org/) — practice on missing persons CTFs
