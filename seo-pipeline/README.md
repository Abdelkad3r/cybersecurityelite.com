# SEO Automation Pipeline — CyberSecurity Elite

Production-ready Python pipeline that discovers long-tail cybersecurity
keywords, ranks them by intent, generates Hugo articles with an LLM, writes
them into `content/<section>/`, and (optionally) auto-commits + pushes them
to GitHub.

Built for the `cybersecurityelite.com` Hugo + PaperMod site. Default mode is
**draft** so generated articles land in a review queue rather than going
straight live — Google penalises unreviewed AI content at scale, and a
human-in-the-loop checkpoint costs you almost nothing.

---

## Architecture

```
seo-pipeline/
├── run.py                          # entry point / orchestrator
├── config.py                       # .env → frozen Config dataclass
├── requirements.txt
├── .env.example
├── prompts/
│   └── article_prompt.md           # system prompt for the LLM
├── modules/
│   ├── log_config.py               # rotating-file + rich-console logger
│   ├── retry.py                    # exponential-backoff decorator
│   ├── state.py                    # dedup (keywords, slugs) + run history
│   ├── keyword_generator.py        # Google Autocomplete + PAA scrape
│   ├── keyword_filter.py           # intent classify + score + cluster
│   ├── article_generator.py        # Anthropic | OpenAI provider
│   ├── markdown_builder.py         # Hugo YAML front-matter + body
│   └── git_publisher.py            # GitPython commit + push
├── state/                          # *.json — git-ignored runtime state
└── logs/                           # rotating logs — git-ignored
```

Data flow:

```
seeds (.env)
   │
   ▼
keyword_generator   ── Google Autocomplete (alphabet pivot + question modifiers)
                       People-Also-Ask scrape (best-effort)
   │
   ▼
keyword_filter      ── blocklist, intent classifier, score, dedup vs state
   │
   ▼  top-N
article_generator   ── LLM (Claude or GPT) → JSON contract
   │
   ▼
markdown_builder    ── Hugo front-matter + body → content/<section>/<slug>.md
   │
   ▼  (only if PUBLISH_MODE=publish)
git_publisher       ── stage + commit + push HEAD:main
   │
   ▼
state               ── keywords_seen.json, slugs_seen.json, runs.jsonl
```

---

## Setup

```bash
cd seo-pipeline
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
$EDITOR .env       # fill in ANTHROPIC_API_KEY (or OPENAI_API_KEY)
```

The `SITE_ROOT` in `.env.example` is already set to this repo's root. Adjust
if you move the pipeline.

---

## Usage

### Default run (draft mode)

```bash
python run.py
```

Generates up to `MAX_ARTICLES_PER_RUN` articles, writes them with
`draft: true`, **does not commit anything**. Open them in your editor, flip
`draft: false` once happy, commit by hand.

### Just discover keywords (no LLM cost)

```bash
python run.py --keywords-only
```

### Fully autonomous (commit + push to main)

```bash
python run.py --publish
```

Equivalent to setting `PUBLISH_MODE=publish` in `.env`. Each article becomes
its own commit, signed with `GIT_COMMIT_AUTHOR_*` from `.env`. Aborts if the
git index has pre-existing staged changes.

### Smoke-test the pipeline without burning credits

```bash
python run.py --dry-run
```

Discovers keywords (real HTTP calls), filters them, generates **synthetic**
stub articles, doesn't write files, doesn't touch git.

### Override seeds for a one-off topic push

```bash
python run.py --seed "active directory privilege escalation" --max-articles 1
```

### Force a section

```bash
python run.py --section ctf-writeups --seed "hackthebox sherlocks walkthrough"
```

---

## Configuration reference

All knobs live in `.env`. See `.env.example` for the canonical set.

| Variable                 | Default                | Purpose |
|--------------------------|------------------------|---------|
| `LLM_PROVIDER`           | `anthropic`            | `anthropic` or `openai` |
| `ANTHROPIC_MODEL`        | `claude-opus-4-7`      | Claude model id |
| `OPENAI_MODEL`           | `gpt-4o`               | OpenAI model id |
| `SITE_ROOT`              | parent of pipeline dir | Hugo project root |
| `DEFAULT_SECTION`        | `tutorials`            | Fallback section if classifier doesn't route |
| `DEFAULT_AUTHOR`         | `CyberSecurity Elite Team` | Must match a key in `data/authors.yaml` |
| `SEED_KEYWORDS`          | (8 cybersecurity seeds)| Comma-separated discovery seeds |
| `MAX_KEYWORDS_PER_RUN`   | `20`                   | Hard cap after filter+rank |
| `MAX_ARTICLES_PER_RUN`   | `3`                    | LLM calls per run |
| `TARGET_WORD_COUNT_MIN/MAX` | `1800`/`3500`       | Passed to the LLM as guidance |
| `PUBLISH_MODE`           | `draft`                | `draft` (review queue) or `publish` (auto-commit) |
| `DRY_RUN`                | `0`                    | `1` = no writes, no LLM bills, no git |
| `LOG_LEVEL`              | `INFO`                 | Standard Python log levels |

---

## Operating model

### Why default draft?

Google's helpful-content system explicitly targets sites that publish
unreviewed AI content at scale. The pipeline solves keyword discovery,
structure, schema markup, and Hugo front-matter for you — but a human still
needs to fact-check claims (CVE numbers, registry keys, command flags) before
the article hits production. Draft mode gives you that checkpoint without
slowing discovery down.

### Promoting drafts to published

Open the generated file under `content/<section>/<slug>.md`, edit anything
that needs fixing, flip `draft: true` → `draft: false`, then commit normally:

```bash
git add content/tutorials/disable-ntlm-windows.md
git commit -m "tutorial: publish disable-ntlm-windows after review"
git push
```

### Scheduling

Cron the pipeline to run once a day at 06:00 local:

```cron
0 6 * * * cd /Users/apple/cybersecurityelite/seo-pipeline && /Users/apple/cybersecurityelite/seo-pipeline/.venv/bin/python run.py >> logs/cron.log 2>&1
```

For full autonomous mode, append `--publish` (review the first week of
output before you trust it unsupervised).

### Cover images

The pipeline does **not** generate covers — the user produces SVG/PNG/WebP
covers per the site's existing template (black bg + cyan grid + sub-category
eyebrow). Drafts ship without `cover:` in front matter; add it when you
publish. PaperMod's `extend_post_content` and `cover.html` overrides handle
the rest.

---

## State files

- **`state/keywords_seen.json`** — normalized lowercase strings of every
  keyword the pipeline has ever processed (successful or failed). Prevents
  re-generation on subsequent runs.
- **`state/slugs_seen.json`** — every slug ever written. Used together with
  filesystem checks to uniquify new slugs.
- **`state/runs.jsonl`** — append-only run history. One JSON object per run
  with timestamp, candidate count, write count, push status, failures.

Delete these to reset the pipeline. They're git-ignored on purpose — sharing
them across machines would defeat dedup.

---

## Logs

`logs/pipeline.log` — 2 MB rotating, 5 backups. Also mirrored to the console
via `rich`. Set `LOG_LEVEL=DEBUG` in `.env` for verbose tracing (LLM prompts,
HTTP responses, retry timing).

---

## Debugging

| Symptom                                      | Likely cause                                                                 |
|----------------------------------------------|------------------------------------------------------------------------------|
| `Config error: ANTHROPIC_API_KEY is required`| `.env` not loaded — check you're running from `seo-pipeline/`               |
| `SITE_ROOT does not look like a Hugo project`| `SITE_ROOT` points somewhere without `hugo.toml`                            |
| Discovery returns 0 keywords                 | Google IP-rate-limited you — wait an hour, or rotate network                |
| LLM response missing required fields         | Model returned prose instead of JSON — check `prompts/article_prompt.md`    |
| `git index is dirty; resolve before re-running` | You have unrelated staged changes — `git stash` or commit them first      |
| Push fails with "permission denied"          | SSH key / gh CLI auth missing — `gh auth status` to diagnose                |

---

## Extending

- **Add a new section** — append a `(section, [tokens])` tuple to
  `_SECTION_RULES` in `modules/keyword_filter.py`. Order matters: first match
  wins, so put specific sections above general ones.
- **Tune intent classifier** — edit `_INTENT_PATTERNS` in the same file.
- **Swap LLM** — implement a `_generate_<provider>` in
  `modules/article_generator.py` and route on `CONFIG.llm_provider`.
- **Add a quality gate** — extend `GeneratedArticle.from_dict` or add a
  post-validation step in `generate_article` (e.g. minimum word count check).

---

## What this pipeline does NOT do

By design:

- **No image generation.** Covers are part of the brand and stay in the
  user's hands.
- **No cross-posting.** No Twitter / LinkedIn auto-share. The site's
  newsletter handles distribution.
- **No A/B testing of titles or descriptions.** The keyword-first
  title contract from the prompt is the rule, not a hypothesis to test.
- **No paid-API keyword tools** (SemRush, Ahrefs). Discovery is 100% free
  surfaces. If you eventually want volume/KD data, add a `serpapi` provider
  in `keyword_generator.py` and key it off an env var so it stays optional.
