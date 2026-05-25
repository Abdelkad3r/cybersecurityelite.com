---
title: "TryHackMe: Pickle Rick Walkthrough — Web Exploitation for Beginners"
slug: "tryhackme-pickle-rick-walkthrough"
description: "Pickle Rick walkthrough — robots.txt and source review, command injection in a hidden portal, and sudo-based privilege escalation to all three ingredients."
date: 2026-04-18T09:00:00Z
lastmod: 2026-04-18T09:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["CTF Writeups"]
tags: ["tryhackme", "web exploitation", "command injection", "privilege escalation", "easy"]
keywords: ["tryhackme pickle rick", "pickle rick walkthrough", "command injection ctf"]
toc: true
cover:
  image: "/images/articles/tryhackme-pickle-rick-walkthrough.png"
  alt: "THM PICKLE RICK WALKTHROUGH writeup — CTF challenge breakdown"
---

{{< ctf-meta platform="TryHackMe" difficulty="Easy" os="Linux" points="10" release="2019-08-29" skills="Web enum, command injection, sudo abuse" >}}

Pickle Rick is the room every new TryHackMe user solves first. It's a perfect introduction to the full pentest loop on a single host — enumeration, exploitation, and post-exploitation — with a forgiving difficulty curve.

## Enumeration

A quick `nmap` of the box shows only two open ports: 22/tcp (SSH) and 80/tcp (Apache). Web first.

Browse the site → "View Source" reveals a comment with a username:

```html
<!-- Note to self, remember username: R1ckRul3s -->
```

Now check `/robots.txt`:

```text
Wubbalubbadubdub
```

That string is a common Rick & Morty reference and looks suspiciously like a password.

A directory brute-force with `gobuster` finds the login portal:

{{< terminal title="kali@kali" >}}
$ gobuster dir -u http://10.10.X.X -w /usr/share/wordlists/dirb/common.txt
/login.php (Status: 200)
/assets    (Status: 301)
/portal.php (Status: 302)
{{< /terminal >}}

`R1ckRul3s:Wubbalubbadubdub` logs into `/login.php`, redirecting to a command portal.

## Foothold via Command Injection

The portal accepts arbitrary commands. It's not a shell — each request runs in isolation — but it executes as `www-data`. We discover a few commands are filtered (`cat` is blocked) but alternatives like `less`, `head`, `tail`, `nl`, and `more` are not.

```bash
ls           # → Sup3rS3cretPickl3Ingred.txt, clue.txt, ...
less Sup3rS3cretPickl3Ingred.txt    # → First ingredient
```

The first flag is in plain sight. The second hides in `/home/rick/`:

```bash
ls /home/rick/
# 'second ingredients'        <-- note the space
less /home/rick/second\ ingredients
```

{{< callout type="tip" title="Filename quoting" >}}
When file names contain spaces, escape with `\` or wrap in quotes. Many beginners get stuck here because the form interprets unquoted spaces as argument separators.
{{< /callout >}}

## Privilege Escalation

`sudo -l` reveals the killshot:

```text
User www-data may run the following commands on ip:
    (ALL) NOPASSWD: ALL
```

Trivial root via `sudo ls /root` → recover the third ingredient.

```bash
sudo less /root/3rd.txt
```

Three ingredients, room complete.

## Lessons Learned

- **Always read robots.txt, source comments, and `/sitemap.xml`.** Authentication credentials in HTML comments are still common in CTFs and, surprisingly, in real audits.
- **`sudo -l` is the single most valuable post-foothold command on Linux** — it answers "what can I do as another user?" in one line and frequently ends the box.
- **Filtered command portals are rarely impervious.** Filters that block specific binaries (`cat`) usually leave equivalents (`less`, `nl`, `more`, `vi`, `awk`) available.

## References

- [TryHackMe: Pickle Rick](https://tryhackme.com/room/picklerick)
- [GTFOBins — sudo abuse cheat sheet](https://gtfobins.github.io/)
