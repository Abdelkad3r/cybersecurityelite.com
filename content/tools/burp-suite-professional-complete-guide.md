---
title: "Burp Suite Professional: The Complete Workflow Guide"
slug: "burp-suite-professional-complete-guide"
description: "Master Burp Suite Pro like a working bug bounty hunter — Repeater chains, Intruder configs, Collaborator workflows, and the extensions that actually pay off."
date: 2026-04-12T11:00:00Z
lastmod: 2026-04-12T11:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Tools"]
tags: ["burp suite", "web pentest", "intruder", "repeater", "appsec"]
keywords: ["burp suite tutorial", "burp pro guide", "burp intruder", "burp collaborator"]
toc: true
cover:
  image: "/images/articles/burp-suite-professional-complete-guide.png"
  alt: "Burp Suite Professional — bug bounty hunter workflow deep dive"
---

Burp Suite Professional is the web pentest workhorse. Once you've moved past clicking "Intercept On", the difference between an average tester and a great one is *Burp fluency* — how quickly you can pivot between Repeater, Intruder, and Collaborator without losing context.

## Setting Up Your Workspace

Bind to `127.0.0.1:8080`, import the CA into Firefox via FoxyProxy. Set scope **immediately** — Burp's defaults log everything, which means hours of irrelevant data in larger projects.

```text
Target → Scope → Include in scope
  https://target.example.com/.*
  https://*.target.example.com/.*
```

Now flip "Show only in-scope items" in HTTP history. Critical for noise control.

## The Core Loop: Proxy → Repeater → Intruder

A clean Burp workflow looks like this:

1. **Browse** the application with intercept off, building HTTP history.
2. **Send to Repeater** any request that looks parameter-rich or auth-relevant.
3. **Send to Intruder** when you need to fuzz or brute-force.
4. **Send to Collaborator** payloads via Repeater when testing blind injection.

### Repeater

Repeater is where 80% of real testing happens. Shortcuts to memorize:

- `Ctrl+R` — Send request to Repeater
- `Ctrl+Space` — Send request inside Repeater
- `Ctrl+I` — Send to Intruder
- `Ctrl+Shift+B` — Base64 decode highlighted bytes
- `Ctrl+Shift+U` — URL decode

### Intruder Attack Types

| Type | When to use |
|------|-------------|
| Sniper | One position, one wordlist — most common |
| Battering ram | Same payload across multiple positions |
| Pitchfork | Parallel lists across positions (creds: user[i] + pass[i]) |
| Cluster bomb | All combinations — credential stuffing exhaustive |

### Intruder Throttling

The community edition throttles Intruder heavily. Pro edition supports **Resource Pools** — create one with 20 concurrent requests and a 50 ms delay for most apps; drop to 1 concurrent for stateful flows.

## Collaborator — The Blind Bug Multiplier

Collaborator gives you a unique DNS/HTTP/SMTP listener. Drop it into any parameter and watch for callbacks. This is how blind SSRF, blind XXE, OOB SQLi, and Log4Shell are confirmed.

```http
GET /api/preview?url=http://abcdef.burpcollaborator.net HTTP/1.1
```

DNS callback → SSRF confirmed even without a response body.

{{< callout type="tip" title="Self-hosted Collaborator" >}}
Sensitive engagements often forbid traffic to PortSwigger's Collaborator. Pro lets you stand up a private Collaborator on your own DNS/wildcard certificate. Worth the 30-minute setup for any consulting engagement.
{{< /callout >}}

## Macros & Session Handling

Token-rotating apps break Intruder. Configure a **Macro** that re-authenticates and extracts the new token, then a **Session Handling Rule** that re-runs the macro when a 401/403 is seen. Once configured, Intruder and Scanner work transparently against expiring sessions.

## Essential Extensions

- **Logger++** — Searchable, exportable request log
- **Autorize** — One-click IDOR / vertical privilege escalation testing
- **JWT Editor** — Algorithm confusion attacks, weak-key cracking
- **Hackvertor** — Inline encoding/decoding inside any tab
- **Active Scan++** — Adds checks the built-in scanner misses
- **Param Miner** — Brute-forces hidden parameters and headers

## Scanner Workflow

Burp's active scanner is excellent for **first-pass coverage** but should never be your only testing. Run it in audit mode on a few representative requests, triage findings, then continue manual testing — never scan the whole site blindly on production.

## References

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
