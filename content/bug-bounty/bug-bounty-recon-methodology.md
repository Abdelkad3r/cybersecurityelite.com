---
title: "The Bug Bounty Recon Methodology That Actually Finds Bugs"
slug: "bug-bounty-recon-methodology"
description: "A reproducible bug bounty recon pipeline — subdomain discovery, content discovery, parameter mining, and the prioritization framework that turns recon into findings."
date: 2026-04-30T10:00:00Z
lastmod: 2026-04-30T10:00:00Z
draft: false
author: "CyberSecurity Elite Team"
categories: ["Bug Bounty"]
tags: ["bug bounty", "recon", "subdomain enumeration", "fuzzing", "automation"]
keywords: ["bug bounty recon", "subdomain enumeration", "bug bounty methodology"]
toc: true
cover:
  image: "/images/og-default.svg"
  alt: "Bug bounty recon methodology"
---

Recon is the single highest-leverage activity in bug bounty hunting — but most beginners do it wrong. They run every tool, collect 200,000 subdomains, and then stare at the wall. This is the recon pipeline used by hunters who consistently hit the leaderboard.

## The Mental Model

Recon has three stages and you should never skip ahead:

1. **Asset discovery** — what exists?
2. **Surface analysis** — what does it do?
3. **Bug discovery** — where does it break?

Most beginners go straight from step 1 to step 3 with `nuclei -t cves/`. The 6-figure hunters spend most of their time in step 2.

## Stage 1: Asset Discovery

### Subdomain Enumeration

```bash
# Passive — pull from public CT logs, search engines, scrape DBs
subfinder -d target.com -all -silent > passive.txt
amass enum -passive -d target.com -o amass.txt
assetfinder --subs-only target.com >> passive.txt

# Active — DNS brute force against your list of resolvers
puredns bruteforce wordlist.txt target.com -r resolvers.txt -w bruted.txt

# Permutation — alterations of known names (api-dev, api-staging)
gotator -sub passive.txt -perm permutations.txt -depth 1 -numbers 5 | puredns resolve -r resolvers.txt
```

Deduplicate and dedupe: `sort -u all_subs.txt > final.txt`.

### Resolution & Probing

```bash
# Resolve to IPs
dnsx -l final.txt -a -resp -o resolved.txt

# Probe HTTP(S)
httpx -l final.txt -tech-detect -title -status-code -threads 200 -o probed.txt
```

### Port Surface

For each in-scope IP/ASN:

```bash
naabu -iL ips.txt -top-ports 1000 -o ports.txt
nmap -sV -p- --min-rate 5000 -iL hot_ips.txt -oA full_tcp
```

## Stage 2: Surface Analysis

This is where the money is. For every "interesting" subdomain (admin panels, API docs, login portals):

### Content Discovery

```bash
# Common content
ffuf -u https://target/FUZZ -w wordlist.txt -mc 200,204,301,302,401,403 \
     -ac -o content.json -of json

# Backup/sensitive extensions
ffuf -u https://target/FUZZ -w wordlist.txt -e .bak,.old,.zip,.tar.gz,.swp,.txt
```

Wordlists that matter: **SecLists** `Discovery/Web-Content/`, `assetnote` wordlists, and Jhaddix's `all.txt` for subdomains.

### JavaScript Mining

Modern apps leak API endpoints, secrets, and feature flags in JS bundles.

```bash
# Pull every JS reference
katana -u https://target -d 5 -jc -kf all -o crawl.txt

# Extract endpoints from JS
cat crawl.txt | grep -E '\.js(\?|$)' | uniq > js_files.txt
xargs -I{} curl -s "{}" < js_files.txt | grep -Eo '"/[a-zA-Z0-9_/-]{4,}"' | sort -u

# Find secrets
trufflehog filesystem ./downloaded_js/
```

### Parameter Mining

```bash
# Hidden GET parameters
arjun -u https://target/api/users -t 50

# From request body
arjun -u https://target/api/users -m POST -d '{}' -t 50
```

### History

Wayback and CommonCrawl URLs:

```bash
gau target.com | sort -u > history.txt
waybackurls target.com | sort -u >> history.txt
```

History reveals:
- Deprecated endpoints still serving
- Parameters no longer in current code
- Files that should have been deleted

## Stage 3: Bug Discovery

Now and *only* now do you run targeted scanners.

```bash
# Nuclei with curated templates
nuclei -l probed.txt -t ~/nuclei-templates/ -severity medium,high,critical -rate-limit 50

# Custom templates for the program's tech stack
nuclei -l probed.txt -t custom-templates/jira/ -t custom-templates/aws/
```

Nuclei is a force multiplier *for known issues* — it will never find a logic flaw, an IDOR, or a privilege escalation. Those come from manual testing of the surfaces you discovered in Stage 2.

## Prioritization

You will end Stage 2 with hundreds of candidate URLs. Prioritize by:

1. **Authentication mismatches** — endpoints with both authenticated and unauthenticated handlers
2. **Admin/internal endpoints leaked** to public domains
3. **API endpoints with object IDs** (IDOR / BOLA candidates)
4. **File upload / download** functionality
5. **Endpoints that accept URLs** (SSRF / open redirect)

## Common Mistakes

- **Recon-only loops** — collecting subdomains forever, never reading one
- **No notes** — re-doing the same recon every session
- **Ignoring scope** — `*.target.com` doesn't always include `*.target-foo.com`
- **Running scanners without throttling** — getting banned and losing access to the program

## References

- [ProjectDiscovery Tools](https://github.com/projectdiscovery)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [HackTricks](https://book.hacktricks.xyz/)
