---
title: "THCON 2026: Socials Writeup — Stitching Two Halves of a Flag From LinkedIn and X"
slug: "thcon-2026-socials"
description: "THCON 2026 Socials walkthrough — the THCON team posted the same announcement on LinkedIn and X/Twitter with an ellipsis in each version; the flag is the concatenation of the two visible halves, leetspeak for 'subscribe'."
date: 2026-05-16T11:00:00Z
lastmod: 2026-05-16T11:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["thcon", "thcon-ctf", "osint", "social media osint", "leetspeak"]
series: ["THCON CTF 2026"]
keywords: ["thcon 2026 socials writeup", "thcon ctf 2026", "social media osint ctf", "toulouse hacking convention ctf"]
toc: true
cover:
  image: "/images/thcon.jpg"
  alt: "THCON 2026 Socials writeup"
---

{{< ctf-meta platform="THCON 2026 (Toulouse Hacking Convention)" difficulty="Easy" os="OSINT" skills="Social media OSINT, leetspeak" >}}

THCON's *Socials* is the kind of warm-up OSINT challenge that's not about tooling — it's about reading the prompt twice and noticing the CTF authors have done something cute with their social media presence. The flag is split between two posts on two platforms, with each post hiding the other half behind an ellipsis. Visit both, stitch the halves, done.

Source: [Abdelkad3r/thcon-ctf-2026 · 01-socials/](https://github.com/Abdelkad3r/thcon-ctf-2026/tree/main/01-socials).

## The Prompt

> The SNAFU wants y'all to be well informed in the long run so you can go to our main socials (LinkedIn and Twitter) and give us a little love there (and of course find your flag!)

The challenge supplies two real links:

- LinkedIn: [Toulouse Hacking Convention](https://www.linkedin.com/company/toulouse-hacking-convention/)
- X / Twitter: [@ToulouseHacking](https://x.com/ToulouseHacking)

## Solution — the split-flag trick

Both pages carry the **same** announcement, but each version reveals only half the flag — with a literal `...` ellipsis hiding the rest. You have to visit both and concatenate the visible halves.

### LinkedIn post

> [THCON 2026 CTF] If you're reading this tweet you already hold half a flag : **`...r1b3}`**
> Go ahead now and create an account on `https://buff.ly/nr1bTlL`!

### X / Twitter post

> [THCON 2026 CTF] If you're reading this tweet you already hold half a flag : **`THC{5uB5C...`**
> Go ahead now and create ...

X/Twitter increasingly returns HTTP 402 to unauthenticated scrapers, but for OSINT pivots like this you don't need to render the page itself — DuckDuckGo's `site:x.com ToulouseHacking "THCON 2026 CTF"` search snippet leaks the visible characters of the post directly into the SERP excerpt.

### Stitch the halves

```text
LinkedIn  :          ...r1b3}
Twitter/X : THC{5uB5C...
                ─────────────
Flag      : THC{5uB5Cr1b3}
```

`5uB5Cr1b3` is leetspeak for **subscribe** — exactly what the prompt is nagging you to do on their socials.

## Flag

```
THC{5uB5Cr1b3}
```

## Lessons learned

1. **OSINT challenges often reward visiting every linked resource.** When a prompt explicitly tells you to "go to" multiple places, the puzzle is usually about combining what you find there — not picking one.

2. **Search-engine snippets are an OSINT pivot, not just a recon shortcut.** When a target page is gated or rate-limiting you (Twitter's 402, Instagram's login wall, LinkedIn's view limits), the SERP excerpt is often enough to recover the literal visible text without ever loading the original page.

3. **Read the flag content as a hint.** Leet-encoded flags frequently spell out the intended action or theme of the challenge. Decoding the flag is sometimes the confirmation that you solved the *intended* path rather than stumbling into one.

## References

- [DuckDuckGo Search Operators](https://duckduckgo.com/duckduckgo-help-pages/results/syntax/) — `site:`, `intitle:`, quoted phrases
- [Sherlock](https://github.com/sherlock-project/sherlock) — username discovery across hundreds of platforms (the bigger toolkit version of what we did here manually)
- Source writeup: [thcon-ctf-2026/01-socials/README.md](https://github.com/Abdelkad3r/thcon-ctf-2026/blob/main/01-socials/README.md)
