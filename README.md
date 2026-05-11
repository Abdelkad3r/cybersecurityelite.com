# CyberSecurity Elite

[![Deploy](https://github.com/cybersecurityelite/cybersecurityelite.com/actions/workflows/hugo.yml/badge.svg)](https://github.com/cybersecurityelite/cybersecurityelite.com/actions/workflows/hugo.yml)

> Elite Cybersecurity Knowledge, Tutorials, and CTF Writeups.
> A production-ready Hugo + PaperMod static site, deployed to GitHub Pages, and built for technical SEO from day one.

**Live site:** https://cybersecurityelite.com

---

## What's Inside

- **Hugo extended** static-site generator + **PaperMod** theme
- **20 high-quality sample articles** covering CTF writeups, web security, malware analysis, forensics, cloud, and certifications
- **Custom shortcodes** for callouts, terminal blocks, CVSS badges, CTF metadata, Mermaid diagrams, and downloads
- **Enterprise-grade SEO**: JSON-LD (Organization, WebSite, BlogPosting, BreadcrumbList), Open Graph, Twitter cards, sitemap, robots, canonical URLs
- **Dark / light mode**, mobile-first, accessibility-conscious CSS layered on PaperMod
- **GitHub Actions** workflow that builds and deploys on every push to `main`
- **CNAME, manifest, browserconfig, favicons, Open Graph image** — all provided

## Quick Start

### Prerequisites

- [Hugo extended](https://gohugo.io/installation/) **≥ 0.140.0**
- [Git](https://git-scm.com/) (with submodule support)
- (Optional) [Node.js](https://nodejs.org/) for ecosystem tooling

### Clone and Run Locally

```bash
git clone --recurse-submodules https://github.com/cybersecurityelite/cybersecurityelite.com.git
cd cybersecurityelite.com

# If you already cloned without submodules:
git submodule update --init --recursive

hugo server -D
```

Open <http://localhost:1313/> — the site is live with hot reload.

### Add PaperMod (first-time setup)

If you forked or downloaded this repo without the submodule, install the theme:

```bash
git submodule add --depth=1 https://github.com/adityatelange/hugo-PaperMod.git themes/PaperMod
git submodule update --init --recursive
```

## Project Structure

```
cybersecurityelite.com/
├── .github/workflows/hugo.yml        # CI/CD: build + deploy to Pages
├── archetypes/                       # Front-matter templates
├── assets/css/extended/custom.css    # Custom theme overrides
├── content/                          # Articles, sections, pages
│   ├── _index.md                     # Home page metadata
│   ├── about.md, contact.md, ...     # Static pages
│   ├── posts/                        # General posts section
│   ├── ctf-writeups/                 # CTF walkthroughs
│   ├── tutorials/                    # Hands-on tutorials
│   ├── tools/                        # Tool deep-dives
│   ├── certifications/               # Cert prep
│   ├── malware-analysis/             # Malware analysis
│   ├── reverse-engineering/          # RE tutorials
│   ├── forensics/                    # DFIR
│   ├── bug-bounty/                   # Bug bounty
│   ├── cloud-security/               # AWS / Azure / GCP
│   ├── web-security/                 # OWASP, XSS, SQLi
│   ├── network-security/             # AD, Wireshark, pivoting
│   ├── career/                       # Career advice
│   └── news/                         # CVE coverage, trends
├── layouts/                          # Custom layouts & partials
│   ├── 404.html                      # Custom 404
│   ├── partials/                     # Head, footer, hero, schema
│   └── shortcodes/                   # callout, terminal, cvss, ctf-meta, ...
├── static/                           # CNAME, robots, manifest, logos
│   ├── CNAME                         # cybersecurityelite.com
│   ├── robots.txt
│   ├── humans.txt
│   ├── logo.svg, favicon.svg
│   └── images/og-default.svg
├── themes/PaperMod/                  # Git submodule
├── hugo.toml                         # Site config
├── .gitignore
├── .gitmodules
└── README.md
```

## Creating Content

### A New CTF Writeup

```bash
hugo new ctf-writeups/my-machine-walkthrough.md
```

Uses `archetypes/ctf-writeups.md` automatically, which seeds the CTF metadata shortcode and section headings.

### A General Article

```bash
hugo new tutorials/my-tutorial.md
```

Uses `archetypes/default.md`. Edit the front matter, set `draft: false`, and add content.

### Front Matter Reference

```yaml
---
title: "Article title (SEO-optimized, ≤ 60 chars)"
slug: "url-slug"
description: "Meta description, 150-160 chars."
date: 2026-05-12T10:00:00Z
lastmod: 2026-05-12T10:00:00Z
draft: false
author: "Author Name"
categories: ["Web Security"]
tags: ["xss", "appsec"]
series: ["OWASP Top 10 Series"]
keywords: ["xss tutorial", "stored xss"]
weight: 1
canonicalURL: ""
toc: true
cover:
  image: "/images/og-default.svg"
  alt: "Cover alt text"
---
```

### Custom Shortcodes

```markdown
{{< callout type="info" title="Heads up" >}}
Multi-line **markdown** inside a callout.
Types: info, tip, warning, danger.
{{< /callout >}}

{{< terminal title="kali@kali" >}}
$ nmap -sC -sV 10.10.10.10
{{< /terminal >}}

{{< cvss score="9.8" vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" >}}

{{< ctf-meta platform="Hack The Box" difficulty="Easy" os="Linux" points="20" release="2024-03-15" skills="Web, AD" >}}

{{< downloads title="Lab Files" >}}
[exploit.py](/files/exploit.py) | 4 KB
[capture.pcap](/files/capture.pcap) | 2.1 MB
{{< /downloads >}}

{{< mermaid >}}
graph LR; Attacker-->Beacon-->C2;
{{< /mermaid >}}
```

For Mermaid, add `mermaid: true` to the page front matter so the loader gets injected.

## Deployment

### GitHub Pages (default)

1. Create a GitHub repository.
2. Push this code to the `main` branch.
3. In **Settings → Pages**, set **Source = GitHub Actions**.
4. The workflow in `.github/workflows/hugo.yml` builds and publishes automatically on every push.

The custom domain comes from `static/CNAME` (which Hugo copies to the build output). After the first deploy, configure your DNS:

```text
A     @     185.199.108.153
A     @     185.199.109.153
A     @     185.199.110.153
A     @     185.199.111.153
CNAME www   <your-github-username>.github.io.
```

Once DNS propagates, enable **"Enforce HTTPS"** in repository Settings → Pages.

## Domain Setup with Cloudflare (Recommended)

For better performance, security, and analytics:

1. Add the domain to Cloudflare (free plan is sufficient).
2. Set Cloudflare DNS to **Proxied** (orange cloud) for the apex record.
3. SSL/TLS mode: **Full (strict)**.
4. Configure these rules:
   - **Always Use HTTPS** — on
   - **HSTS** — Max-Age 12 months, includeSubDomains, preload
   - **Automatic HTTPS Rewrites** — on
   - **Brotli** — on
   - **Auto Minify**: HTML on, CSS/JS off (Hugo already minifies)
   - **Caching Level** — Standard
   - **Browser Cache TTL** — 4 hours
5. Enable **Cloudflare Bot Fight Mode**.
6. Configure DNSSEC at the registrar.

### Recommended Security Headers (via Cloudflare Transform Rules)

```text
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self' https://www.google-analytics.com; frame-ancestors 'none'; base-uri 'self';
X-Frame-Options: DENY
```

Tighten the CSP once you finalize which analytics/embeds you actually use.

## SEO Checklist

Before launch:

- [ ] Replace `REPLACE_WITH_GSC_TOKEN` in `hugo.toml` with your Google Search Console verification token
- [ ] Replace `REPLACE_WITH_BING_TOKEN` with your Bing Webmaster Tools token
- [ ] Replace `G-XXXXXXXXXX` with your GA4 Measurement ID (or remove the `services.googleAnalytics` block to disable GA4)
- [ ] Replace `REPLACE_WITH_CLARITY_ID` with your Microsoft Clarity project ID (or remove to disable)
- [ ] Submit `https://cybersecurityelite.com/sitemap.xml` to Google Search Console
- [ ] Submit the sitemap to Bing Webmaster Tools
- [ ] Set up Cloudflare in front of GitHub Pages for HTTPS and edge caching
- [ ] Verify Open Graph rendering with [opengraph.xyz](https://www.opengraph.xyz/)
- [ ] Validate structured data at [Schema Validator](https://validator.schema.org/)
- [ ] Run Lighthouse on the home page — target ≥ 95 across the board
- [ ] Add the site to Cloudflare Web Analytics or Plausible

Ongoing:

- [ ] Publish at minimum one substantive article per week
- [ ] Run periodic broken-link checks
- [ ] Re-test mobile usability quarterly
- [ ] Monitor Core Web Vitals in Search Console
- [ ] Update `lastmod` whenever you edit an article

## Analytics & Monitoring

The repo wires up four analytics integrations — all optional, all off by default:

| Service | How to enable | Privacy notes |
|---------|---------------|---------------|
| Google Analytics 4 | Set `ga4` / `services.googleAnalytics.ID` in `hugo.toml` to your `G-XXXX` ID | Loads gtag with `anonymize_ip: true` |
| Plausible | Set `plausibleDomain` and uncomment the `<script>` in `layouts/partials/extend_footer.html` | Cookieless, GDPR-friendly |
| Microsoft Clarity | Set `microsoftClarity` to your Clarity ID | Heatmaps and session recordings; review their privacy policy |
| Cloudflare Web Analytics | Add the Cloudflare beacon snippet to `extend_footer.html` | Cookieless |

## Monetization Hooks

The project is structured to support multiple monetization paths without rebuilding:

- **Affiliate links** — disclose in the article front matter (`affiliate: true`) and at the start of the article body
- **Sponsored content** — create a `sponsored: true` flag in front matter and a custom partial that injects a "Sponsored" badge into post entries
- **Display ads** — drop ad slots into `layouts/partials/extend_footer.html` or create a custom partial referenced from a content layout
- **Premium content / gated downloads** — wire the `cse-downloads` shortcode to a token-gated CDN URL
- **Newsletter monetization** — the newsletter signup is form-based and provider-agnostic; point it at Buttondown, ConvertKit, Beehiiv, or Mailchimp

## Security Hardening

Beyond the security headers above:

- **DNSSEC** at the registrar — protects against DNS hijacking
- **Cloudflare WAF Managed Rules** — free plan offers OWASP CRS-equivalent
- **Cloudflare Rate Limiting** — protect the contact form and any future API endpoints
- **GitHub repository secrets** — never commit API keys; use Actions secrets
- **Dependabot** for the GitHub Actions workflow and the PaperMod submodule
- **Branch protection** on `main` — require pull-request reviews if multiple authors

## Maintenance

```bash
# Update the PaperMod theme
git submodule update --remote --merge themes/PaperMod
git add themes/PaperMod
git commit -m "Bump PaperMod theme"

# Upgrade Hugo locally
# macOS: brew upgrade hugo
# Linux: download the latest release from https://github.com/gohugoio/hugo/releases

# Verify the build before pushing
hugo --gc --minify

# Check for broken internal links
hugo --printPathWarnings --printUnusedTemplates
```

## Troubleshooting

- **Build fails with "theme not found"** — run `git submodule update --init --recursive`.
- **Pages 404 after first deploy** — wait 5-10 minutes for the GitHub Pages CDN to propagate; check Settings → Pages.
- **CNAME keeps getting reset** — make sure `static/CNAME` is committed; GitHub strips the file from the gh-pages branch if not built by Actions.
- **Search returns nothing** — confirm `outputs.home = ["HTML", "RSS", "JSON"]` in `hugo.toml`; this generates the search index.

## Roadmap

- [ ] Multilingual support (i18n)
- [ ] Author pages with per-author RSS feeds
- [ ] Comment system (Giscus or Cusdis)
- [ ] PWA install prompt
- [ ] Generated PNG OG images per article

## License

- **Code, layouts, shortcodes, and configuration** — MIT, see [LICENSE](./LICENSE)
- **Articles and editorial content** — Creative Commons Attribution-NonCommercial-ShareAlike 4.0 ([CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/))

## Acknowledgments

- [Hugo](https://gohugo.io/) — the fastest static-site generator
- [PaperMod](https://github.com/adityatelange/hugo-PaperMod) — the theme this site builds on
- The open-source security community

---

If you find a typo, broken link, or technical inaccuracy, please open an issue or send a pull request. We acknowledge corrections in the article footer.
