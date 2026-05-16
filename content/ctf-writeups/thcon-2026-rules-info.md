---
title: "THCON 2026: Rules / Info Page Writeup — When the 'Info Page' Is the CTF Platform's Own Info Page"
slug: "thcon-2026-rules-info"
description: "THCON 2026 Rules walkthrough — the prompt names a generic 'info page with the rules' that points away from the obvious linked Code of Conduct and toward the CTF platform's own /info page, where the flag is hidden in tiny grey italic text at the bottom."
date: 2026-05-16T11:30:00Z
lastmod: 2026-05-16T11:30:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["thcon", "thcon-ctf", "osint", "ctf platform recon", "misdirection"]
series: ["THCON CTF 2026"]
keywords: ["thcon 2026 rules writeup", "thcon ctf 2026 info page", "ctf platform osint", "ctf.thcon.party info"]
toc: true
cover:
  image: "/images/og-default.svg"
  alt: "THCON 2026 Rules / Info Page writeup"
---

{{< ctf-meta platform="THCON 2026 (Toulouse Hacking Convention)" difficulty="Easy" os="OSINT" skills="Reading prompts literally, CTF platform recon" >}}

Most "find the hidden flag on a webpage" challenges teach you to look harder. This one teaches the opposite — that the most-obvious destination in the prompt is a decoy, and the answer is whatever a literal reading of the wording actually points at. The trick is recognising the misdirection before sinking thirty minutes into the wrong target.

Source: [Abdelkad3r/thcon-ctf-2026 · 02-rules-info/](https://github.com/Abdelkad3r/thcon-ctf-2026/tree/main/02-rules-info).

## The Prompt

> The SNAFU wants all you guys well aware of the situation so read the info page with the rules:
> 🇦 Respect the Code of Conduct of this event: <https://thcon.party/code-of-conduct> ; be respectful and courteous
> 🇧 No spam or advertising allowed on this server.
> 🇨 You can chat and ask questions in the conferences' dedicated channels […]
> React to accept these rules

## The Obvious Path (a Dead End)

The first instinct is to follow the linked **Code of Conduct** URL and look for the flag there. I went down this route and exhausted it:

- Rendered text content — no flag
- View-source HTML — no flag, no comments
- Hidden CSS (`display: none`, `visibility: hidden`, off-screen positioning) — clean
- Inline SVG logo — no embedded text
- `favicon.ico` — clean
- Linked stylesheets — checked for embedded `THC{...}` strings — nothing

`https://thcon.party/code-of-conduct` is a real page hosted on a real domain. It's not the puzzle target.

## The Trick — Read the Prompt Literally

Re-read the wording:

> *"… read the **info page with the rules** …"*

The prompt isn't asking about the Code of Conduct *link*. It's referring to **the info page** — and CTF platforms (CTFd, ECTF, rCTF, the THCON custom platform here) all expose an **Information** page at `/info` containing the event's rules. The linked CoC URL inside the rules is just *also* a rule item, not the destination.

The actual target is `https://ctf.thcon.party/info`. A two-line curl confirms it:

{{< terminal title="kali ~/ctf/thcon" >}}
$ curl -sL https://ctf.thcon.party/info | grep -oE 'THC\{[^}]+\}'
THC{Y0u_kN0w_d4_Rul3z_4nD_50_d0_1}
{{< /terminal >}}

In the rendered page, the flag lives in tiny grey italic text at the very bottom — `<p class="text-xs"><i>…</i></p>` — easy to scroll past.

## Reading the Flag

```
THC{Y0u_kN0w_d4_Rul3z_4nD_50_d0_1}
```

`Y0u_kN0w_d4_Rul3z_4nD_50_d0_1` is leetspeak for *"You know the rules and so do I"* — the opening line of Rick Astley's **Never Gonna Give You Up**. The challenge is a rules-page rickroll.

{{< callout type="tip" title="Where to check before chasing external links" >}}
On any CTF platform, before assuming a challenge points at some external page, enumerate the platform's own routes first. Common paths worth bookmarking:
- `/info` — event rules, FAQ
- `/about`, `/contact`, `/sponsors` — admin-controlled content
- `/users`, `/teams`, `/scoreboard` — sometimes have flavour text
- `/api/v1/*` — platform-internal endpoints
The flag for a "read the rules" challenge is almost always on the platform itself, not on a third-party site the rules happen to link to.
{{< /callout >}}

## Flag

```
THC{Y0u_kN0w_d4_Rul3z_4nD_50_d0_1}
```

## Lessons learned

1. **The "obvious link" is sometimes a decoy.** When a challenge prompt contains a hyperlink AND a generic phrase like "info page" / "rules page" / "this page", check whether the phrase matches a *platform-internal* route before following the link.

2. **CTF platforms expose their own info pages.** CTFd, rCTF, FBCTF, and most custom platforms all have a `/info` or `/about` route. Always grep these for the flag format on every CTF — sometimes there's a 50-point freebie waiting.

3. **Tiny grey italic text is the modern hidden-in-plain-sight pattern.** "View Source" finds it instantly, but it's invisible to anyone reading the rendered page casually. `grep -oE '<flag_format>'` against the served HTML is a reliable first move on any web challenge.

## References

- [CTFd platform documentation](https://docs.ctfd.io/)
- Source writeup: [thcon-ctf-2026/02-rules-info/README.md](https://github.com/Abdelkad3r/thcon-ctf-2026/blob/main/02-rules-info/README.md)
