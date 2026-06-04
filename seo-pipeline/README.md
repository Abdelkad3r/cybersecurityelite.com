# SEO Article Pipeline — CyberSecurity Elite

Python pipeline that produces **non-CTF** articles for the CyberSecurity
Elite Hugo blog: tutorials, deep-dive analyses, tool comparisons, threat-
intel news posts, troubleshooting guides. Given a topic + target Hugo
section, it produces a finished article (front-matter + body + cover
SVG/PNG/WebP) in the same format the blog already uses, then optionally
commits + pushes to GitHub.

**CTF master writeups are written by hand** — they live in the same blog
under `content/ctf-writeups/` but a different workflow generates them.
This pipeline is deliberately scoped to *everything else*.

---

## Architecture

```
seo-pipeline/
├── article.py             # entry point (~500 lines, one Python file)
├── prompts/
│   └── article.md         # LLM prompt template
├── covers/
│   └── template.svg       # cover SVG with {{PLACEHOLDER}} fields
├── .env.example
├── requirements.txt
└── README.md              # this file
```

Pipeline stages (each idempotent):

```
        topic + section + intent
                  │
                  ▼
         1. classify_intent          (auto if not specified)
                  │
                  ▼
         2. build_prompt             (prompts/article.md + inputs)
                  │
                  ▼
         3. call_llm                 (OpenAI gpt-4o, response_format=json_object)
                  │
                  ▼
         4. write_article            (front-matter + body → content/<section>/<slug>.md)
                  │
                  ▼
         5. write_cover              (template.svg → rsvg-convert → cwebp)
                  │
                  ▼
         6. verify                   (hugo build + H1=1, H2≥3, FAQPage schema)
                  │
                  ▼
         7. commit                   (single structured git commit)
                  │
                  ▼
         8. push                     (only if --publish)
```

---

## Setup

```bash
cd seo-pipeline
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
$EDITOR .env       # fill in OPENAI_API_KEY
```

External tools (all already on most security workstations):

```bash
# librsvg for SVG → PNG
brew install librsvg          # macOS
sudo apt install librsvg2-bin # Debian/Ubuntu

# webp for PNG → WebP
brew install webp
sudo apt install webp

# hugo extended (≥0.158)
brew install hugo
```

The pipeline checks for `rsvg-convert`, `cwebp`, and `hugo` on every run
and refuses to start if any are missing.

---

## Usage

### Single article — direct topic

```bash
python article.py "Kerberoasting Detection in Splunk" \
    --section network-security \
    --intent tutorial
```

The article lands at `content/network-security/<slug>.md` with `draft:
true`. Read it, edit it, flip `draft: false`, commit by hand.

### Single article — let the pipeline classify intent

```bash
python article.py "How to Disable LLMNR in Active Directory" \
    --section tutorials
# intent → "tutorial" (matched on "how to")
```

The `classify_intent()` regex auto-picks `tutorial`, `comparison`,
`troubleshooting`, `analysis`, `news`, or defaults to `guide`.

### Batch mode — TSV of topics

```bash
python article.py --from-file topics.tsv
```

Where `topics.tsv` is one job per line, fields separated by `<TAB>` or
`|`:

```text
# topic <TAB> section <TAB> intent (intent optional)
NTLM Relay Detection with Zeek            <TAB> network-security <TAB> tutorial
Defender for Endpoint vs CrowdStrike Falcon <TAB> tools          <TAB> comparison
LockBit 5 Affiliate Playbook              <TAB> malware-analysis <TAB> analysis
Hardening Windows 11 Pro for Endpoints     <TAB> tutorials       <TAB> tutorial
```

### Smoke-test the prompt without spending tokens

```bash
python article.py "Kerberoasting Detection in Splunk" \
    --section network-security --prompt-only
```

Prints the rendered prompt to stdout; no LLM call, no file writes.

### Full autonomous mode — commit + push

```bash
python article.py "..." --section ... --publish
```

`--publish` flips the article to `draft: false`, commits, and pushes to
`origin/main`. Use only after you've reviewed a few drafts and trust the
output (see *Operating model* below).

---

## Allowed sections + intents

The pipeline refuses jobs that target a section or intent it doesn't
know about.

**Sections** (must have a corresponding `content/<section>/` directory):

```
tutorials, posts, news, tools, certifications,
bug-bounty, career, cloud-security, forensics,
malware-analysis, network-security, reverse-engineering,
web-security
```

**Intents** (drive the article's structure + cover badge):

| Intent           | Structure                                         | Schema emitted          |
|------------------|---------------------------------------------------|--------------------------|
| `tutorial`       | Concept → prereqs → step-by-step → verify → FAQ   | `HowTo` + `FAQPage`     |
| `guide`          | Concept → "X for Y" → decision matrix → FAQ       | `FAQPage`               |
| `analysis`       | Background → breakdown → detection → IOCs → FAQ   | `FAQPage`               |
| `comparison`     | At-a-glance table → per-option → verdict → FAQ    | `FAQPage`               |
| `news`           | TLDR → details → impact → mitigation → FAQ        | `FAQPage` + `NewsArticle` (via PaperMod) |
| `troubleshooting`| Symptoms → root cause → fix → prevention → FAQ    | `FAQPage`               |

---

## Configuration reference

All settings live in `seo-pipeline/.env`. See `.env.example` for the
canonical set.

| Variable | Default | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | *(required)* | OpenAI API key (use a `sk-proj-…` project key for revocability) |
| `OPENAI_MODEL` | `gpt-4o` | Model id (`gpt-4o-mini` for cheap batch runs) |
| `OPENAI_MAX_TOKENS` | `12000` | Output cap (12k ≈ 9k-word ceiling) |
| `SITE_ROOT` | parent dir of pipeline | Hugo project root |
| `DEFAULT_AUTHOR` | `CyberSecurity Elite Team` | Front-matter `author` |
| `GIT_BRANCH` | `main` | Branch to push to with `--publish` |
| `GIT_COMMIT_AUTHOR_NAME` | `Article Pipeline` | Commit author |
| `GIT_COMMIT_AUTHOR_EMAIL` | `article-pipeline@cybersecurityelite.com` | Commit email |
| `LOG_LEVEL` | `INFO` | `DEBUG` for verbose tracing |

---

## Operating model

### Default is draft

Generated articles ship with `draft: true` so they appear in your local
review queue but are not built into the live site. Open them, fact-check
every command/CVE/event-ID, polish the prose, then flip the flag.

Why: Google's helpful-content system targets sites that publish
unreviewed LLM-generated content at scale. The pipeline solves keyword
research, schema markup, internal-link patterns, and cover-image
generation for you — but a human reviewer still has to verify technical
claims before the article hits production.

### Promoting drafts to published

```bash
$EDITOR content/network-security/kerberoasting-detection-splunk.md
# - flip draft: false
# - fix any factual nits
# - check that the cover doesn't say something weird

git add content/network-security/kerberoasting-detection-splunk.md \
        static/images/articles/kerberoasting-detection-splunk.{svg,png,webp}
git commit -m "network-security: publish kerberoasting detection in splunk"
git push
```

### Scheduling

Daily cron at 06:00 to drain a batch file:

```cron
0 6 * * * cd /Users/apple/cybersecurityelite/seo-pipeline && \
          /Users/apple/cybersecurityelite/seo-pipeline/.venv/bin/python \
          article.py --from-file topics.queue.tsv \
          >> logs/cron.log 2>&1
```

After the run, manually triage the new drafts in
`content/<section>/`. Append additional topics to
`topics.queue.tsv` as they come to mind.

---

## Front-matter shape

Generated front-matter matches the existing blog's pattern (see any
`content/tutorials/*.md`):

```yaml
---
title: "Kerberoasting Detection in Splunk: 5 SPL Queries (2026)"
slug: "kerberoasting-detection-splunk"
description: "Detect Kerberoasting in Splunk with five SPL queries..."
date: 2026-06-02T03:00:00Z       # back-dated 2h to avoid buildFuture=false
lastmod: 2026-06-02T03:00:00Z
draft: true                       # promoted to false with --publish
author: "CyberSecurity Elite Team"
categories: ["Network Security"]
tags: ["kerberoasting", "splunk", "active directory", "siem", ...]
keywords: ["detect kerberoasting splunk spl", "event id 4769", ...]
toc: true
cover:
  image: "/images/articles/kerberoasting-detection-splunk.png"
  alt: "Kerberoasting Detection in Splunk — five SPL queries for SOC teams"
---
```

The body always includes `{{< faq >}}` at the bottom (FAQPage schema)
and, for tutorial-intent articles, `{{< howto title="..." totalTime="..." >}}`
around the step-by-step block (HowTo schema). Hugo's `_partials/head.html`
handles the BreadcrumbList and BlogPosting schemas automatically.

---

## Cover template

`covers/template.svg` is the same dark-grid / cyan-violet brand that
runs across every existing article cover. The pipeline substitutes
these placeholders per-article:

| Placeholder | Source | Notes |
|---|---|---|
| `{{ALT}}` | `payload.alt_text` | Image alt-text |
| `{{EYEBROW}}` | `payload.cover.eyebrow` | `[ TYPE · SECTION · YEAR ]` |
| `{{BADGE}}` | `payload.cover.badge` | Right-side pill, e.g. `TUTORIAL` |
| `{{TITLE}}` | `payload.cover.title` | Big centred title (1-3 words) |
| `{{TITLE_FONT_SIZE}}` | auto-sized if missing | 130/120/110/95 by char count |
| `{{SUBTITLE}}` | `payload.cover.subtitle` | E.g. `DETECTION GUIDE` |
| `{{TAGLINE}}` | `payload.cover.tagline` | 4–5 concept dots |
| `{{PROMPT_USER}}` | `payload.cover.prompt_user` | Shell prompt user, e.g. `soc@detect` |
| `{{TERMINAL_LINE_1}}` | `payload.cover.terminal_line_1` | Realistic command |
| `{{TERMINAL_LINE_2}}` | `payload.cover.terminal_line_2` | Follow-up or `# summary` |

PNG is rendered at 1200×630, WebP at quality 85.

---

## Debugging

| Symptom | Likely cause |
|---|---|
| `config: OPENAI_API_KEY missing` | `.env` not loaded — run from `seo-pipeline/` or set `--env-file` |
| `hugo did not render the page` | `date:` is in the future (`buildFuture = false` in hugo.toml) or `draft: true` with hugo not built with `-D` |
| `H2 count N (expected ≥3 sections)` | Model produced a short article; check the prompt rendering with `--prompt-only` |
| `FAQPage JSON-LD schema not found` | Model forgot `{{< faq >}}`; the prompt mandates it but the model occasionally drops it on short articles |
| `git diff --cached … pre-existing staged files` | You have unrelated staged changes — `git stash` first |
| `rsvg-convert: command not found` | `brew install librsvg` |

For verbose tracing of the LLM prompt and HTTP responses:

```bash
LOG_LEVEL=DEBUG python article.py "..." --section ...
```

---

## Extending

- **Add a new section** — append to `ALLOWED_SECTIONS` in `article.py`
  and create `content/<new-section>/_index.md`.
- **Add a new intent** — append to `ALLOWED_INTENTS` and add an
  `### Intent = <new>` block to `prompts/article.md` describing the
  structure.
- **Swap model** — change `OPENAI_MODEL` in `.env`. `gpt-4o-mini` is
  about 10× cheaper for batch runs but weaker on long-form structure;
  `gpt-4o` is the recommended default; `gpt-4.1` (if available on your
  account) gives the tightest JSON-schema adherence.
- **Tune the cover** — `covers/template.svg` is the single source of
  visual truth. Update it; the next run renders the new template.

---

## Running it from GitHub Actions

Two workflows live under `.github/workflows/`:

| Workflow file | Backed by | Cost per article | Quality |
|---|---|---|---|
| `generate-article.yml` | OpenAI `gpt-4o` / `gpt-4o-mini` | ~$0.003 – $0.05 | Good |
| `generate-article-claude.yml` | Claude Code with your Max-plan OAuth token | **$0 extra** (uses your Max quota) | Best |

If you're already paying for **Claude Max ($100-200/mo)**, the Claude
workflow is the right default — articles cost nothing on top of your
existing subscription, and the quality is noticeably higher than
`gpt-4o`. Keep the OpenAI workflow around as a fallback for when you
want to triage quota or run a different style of test.

### Claude workflow setup (one-time)

1. **Generate a long-lived OAuth token from your local Claude Code:**
   ```bash
   claude setup-token
   ```
   This prints an `sk-ant-oat01-…` value. The token is bound to your
   account and consumes your Max plan's quota (not API credit).

2. **Add it as a repository secret:**
   - Settings → Secrets and variables → Actions → New repository secret
   - Name: `CLAUDE_CODE_OAUTH_TOKEN`
   - Secret: paste the `sk-ant-oat01-…` value

3. **Done.** Open the Actions tab → **Generate Article (Claude)** → Run
   workflow → fill `topic` + `section` → ~3 minutes later you have a
   draft PR.

### OpenAI workflow setup (one-time)

A workflow at `.github/workflows/generate-article.yml` runs the same
pipeline in CI so you can trigger article generation from the GitHub
Actions tab — no local Python venv required.

### One-time setup

1. **Add the OpenAI key as a repository secret.**
   - Go to **Settings → Secrets and variables → Actions → New repository
     secret**.
   - Name: `OPENAI_API_KEY`
   - Value: your `sk-proj-…` key (use a project key so you can revoke
     just this pipeline if it ever leaks).

   That's it — no other secrets are needed. The runner's `GITHUB_TOKEN`
   handles git auth automatically.

### Triggering a run

1. Open the **Actions** tab → **Generate Article** workflow → **Run
   workflow**.
2. Fill the inputs:

   | Input     | Notes |
   |-----------|-------|
   | `topic`   | Free-form article topic, e.g. *"Kerberoasting Detection in Splunk"* |
   | `section` | One of the 13 allowed sections (dropdown) |
   | `intent`  | Leave blank for auto-classify; override with one of the six types if needed |
   | `publish` | `false` (default) opens a draft PR for review. `true` commits straight to main and the Hugo deploy workflow picks it up. |
   | `model`   | `gpt-4o` by default. Switch to `gpt-4o-mini` for cheap batch runs. |

3. Click **Run workflow**. The job takes 60–120 seconds end-to-end (most
   of it is the model call).

### What happens behind the scenes

```
Run workflow → checkout repo → install hugo + librsvg2 + webp + Python deps
            ↓
           python article.py <topic> --section X [--intent Y] [--publish]
            ↓
            ├─ publish=true:  pipeline commits + pushes to main
            │                 → hugo.yml deploy workflow rebuilds the site
            │                 → live in ~1 minute
            │
            └─ publish=false: pipeline commits locally (draft:true article)
                              → workflow pushes to draft/<timestamp>-<slug> branch
                              → workflow opens a PR with a review checklist
                              → you review, flip draft:false, merge
```

### Reviewing draft PRs

Each draft PR includes:

- A populated **review checklist** (title/description length, no invented
  CVEs, code-block languages, cover image preview).
- The full article (front-matter + body) as one markdown file under
  `content/<section>/`.
- The cover SVG/PNG/WebP in `static/images/articles/`.

To publish:

```bash
gh pr checkout <PR-number>
$EDITOR content/<section>/<slug>.md     # flip `draft: true` → `draft: false`
git commit -am "<section>: publish <slug>"
git push
gh pr merge --merge      # or use the web UI
```

The deploy workflow takes over from the merge.

### Scheduled (cron) generation — Monday 14:00 UTC

A third workflow at `.github/workflows/generate-article-scheduled.yml`
fires on a cron schedule (default: every Monday at 14:00 UTC). It:

1. Reads the **first uncommented line** of `seo-pipeline/topics.queue.tsv`
2. Calls the same Claude agent as `generate-article-claude.yml`
3. Opens a draft PR with the new article + cover
4. Commits a queue update on `main` that comments-out the processed line
   so the next run picks the next uncommented topic

The cron uses the same `CLAUDE_CODE_OAUTH_TOKEN` secret as the manual
Claude workflow — no extra setup if that's already configured.

#### Queue file format

`seo-pipeline/topics.queue.tsv`:

```text
# Lines starting with # are skipped. Blank lines are skipped.
# Format: topic <TAB> section <TAB> intent  (intent optional)

ASREProasting Detection in Splunk            network-security  tutorial
LLMNR and NBT-NS Disabling via Group Policy  tutorials         tutorial
Pass-the-Hash Detection with Sysmon          network-security  tutorial
```

`seo-pipeline/topics.queue.example.tsv` is committed for reference (it's
never processed; only `topics.queue.tsv` is drained).

#### Operational discipline

- **Curate the queue weekly.** Spend ~15 minutes on Sunday adding 4-8
  topics. The cron only ships what you've queued; an empty queue means
  no articles get published that week. That's a feature.
- **Review each PR.** Every Monday morning there's an open PR. The
  review checklist is in the PR body. Flip `draft: true` → `draft: false`
  before merging if you want the article live.
- **Watch Google Search Console weekly.** If impressions drop, indexed
  pages shrink, or "Crawled — currently not indexed" surges past 20%,
  pause the cron immediately by either:
  1. Commenting out every active line in `topics.queue.tsv`, or
  2. Commenting out the `schedule:` block in the workflow file
- **Don't exceed 3 articles/week.** Even if the queue is full. Google's
  helpful-content classifier treats sudden volume surges from young blogs
  as content-farm signals. Stay at 1/week for the first 8 weeks; ramp
  to 2/week only if Search Console signals are clean.

#### Adjusting the schedule

Edit the `cron:` line in
`.github/workflows/generate-article-scheduled.yml`. Standard cron
syntax, UTC:

| Cadence | cron expression |
|---|---|
| Weekly (Monday 14:00 UTC) — default | `'0 14 * * 1'` |
| Twice weekly (Mon + Thu 14:00 UTC) | `'0 14 * * 1,4'` |
| Daily (every day 14:00 UTC) | `'0 14 * * *'` — **not recommended** |

#### Failure / recovery semantics

The queue update commit only fires after the article PR is successfully
opened. If the agent step or PR step fails, the queue file is
**unchanged**, so the next run (manual or scheduled) re-attempts the
same topic. No silent topic loss.

If you want to skip a topic that's failing repeatedly, edit
`topics.queue.tsv` manually — comment it out or delete the line.

---

## What this pipeline does NOT do

By design:

- **No keyword discovery.** You provide the topic. Topic generation is a
  human-curation task; a pipeline that scrapes Google Autocomplete just
  produces content that already exists.
- **No CTF master writeups.** Those have a different workflow (manual,
  in conversation with a researcher), different structure (per-
  challenge sections, ctf-meta shortcode, "X/X SOLVED" cover badge), and
  different scope (event-driven, not topic-driven).
- **No image generation beyond the cover.** Body images, screenshots,
  and diagrams stay a human responsibility.
- **No cross-posting.** No Dev.to / Medium / Hashnode mirroring. The
  blog is the primary; syndication is a separate concern.
