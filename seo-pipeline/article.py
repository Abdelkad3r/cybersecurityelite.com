#!/usr/bin/env python3
"""SEO article pipeline for CyberSecurity Elite (non-CTF content).

Given a topic + target Hugo section, produce a finished article (front-matter
+ body + cover SVG/PNG/WebP) in the same format the blog already uses,
then optionally commit + push.

This pipeline is for **everything that is not a CTF master writeup** —
tutorials, deep dives, tool reviews, news analyses, threat-intel posts,
career guides, certification breakdowns. CTF writeups are written by hand
in conversation (separate workflow).

Usage
-----
    python article.py "TOPIC" --section SECTION [options]

Examples
--------
    # Tutorial on a specific topic
    python article.py "How to Detect Kerberoasting with Splunk" \\
        --section network-security --intent tutorial

    # Tool review
    python article.py "Burp Suite vs OWASP ZAP in 2026" \\
        --section tools --intent comparison

    # Threat analysis
    python article.py "Lockbit 5 Affiliate Playbook" \\
        --section malware-analysis --intent analysis

    # Batch mode: one article per line of `topics.tsv`
    #   format: topic<TAB>section<TAB>intent
    python article.py --from-file topics.tsv

    # Smoke-test the prompt rendering without spending an API call
    python article.py "..." --section ... --prompt-only

    # Full auto-publish (commits + pushes)
    python article.py "..." --section ... --publish

Pipeline stages
---------------
    1. classify       — derive intent (tutorial | guide | analysis | comparison | news | troubleshooting) if not given
    2. build_prompt   — render prompts/article.md with topic + section + intent
    3. call_llm       — OpenAI gpt-4o with response_format=json_object
    4. write_article  — front-matter + body → content/<section>/<slug>.md
    5. write_cover    — substitute SVG template → rsvg-convert + cwebp
    6. verify         — hugo build + H1=1, H2≥3, FAQPage schema
    7. commit         — single structured git commit
    8. push           — git push origin <branch>  (only if --publish)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# ── 3rd-party imports ──────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    from slugify import slugify
    from openai import OpenAI
    import yaml
except ImportError as e:
    print(f"missing dep: {e}\n  → pip install -r requirements.txt", file=sys.stderr)
    sys.exit(2)

# ── Logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("article")
for noisy in ("httpx", "openai", "urllib3"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

# ── Paths ──────────────────────────────────────────────────────────────
PIPE_ROOT = Path(__file__).resolve().parent
load_dotenv(PIPE_ROOT / ".env")

SITE_ROOT = Path(os.getenv("SITE_ROOT", PIPE_ROOT.parent))
CONTENT   = SITE_ROOT / "content"
IMAGES    = SITE_ROOT / "static" / "images" / "articles"
PROMPT    = PIPE_ROOT / "prompts" / "article.md"
SVG_TPL   = PIPE_ROOT / "covers"  / "template.svg"

# Hugo sections that this pipeline can write into. Anything in this list
# must have a corresponding content/<section>/ directory.
ALLOWED_SECTIONS = {
    "tutorials", "posts", "news", "tools", "certifications",
    "bug-bounty", "career", "cloud-security", "forensics",
    "malware-analysis", "network-security", "reverse-engineering",
    "web-security",
}

# Intents drive the article's structure (HowTo schema for tutorials, etc.)
ALLOWED_INTENTS = {"tutorial", "guide", "analysis", "comparison", "news", "troubleshooting"}

# ── Config ─────────────────────────────────────────────────────────────
@dataclass
class Config:
    api_key:   str  = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    model:     str  = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o"))
    max_toks:  int  = field(default_factory=lambda: int(os.getenv("OPENAI_MAX_TOKENS", "12000")))
    git_user:  str  = field(default_factory=lambda: os.getenv("GIT_COMMIT_AUTHOR_NAME", "Article Pipeline"))
    git_email: str  = field(default_factory=lambda: os.getenv("GIT_COMMIT_AUTHOR_EMAIL", "article-pipeline@cybersecurityelite.com"))
    branch:    str  = field(default_factory=lambda: os.getenv("GIT_BRANCH", "main"))
    author:    str  = field(default_factory=lambda: os.getenv("DEFAULT_AUTHOR", "CyberSecurity Elite Team"))

    def validate(self, *, full: bool = True) -> list[str]:
        """When `full=False`, only check static config (used by --prompt-only)."""
        errs: list[str] = []
        if not SITE_ROOT.exists():
            errs.append(f"SITE_ROOT does not exist: {SITE_ROOT}")
        if not (SITE_ROOT / "hugo.toml").exists():
            errs.append(f"{SITE_ROOT} is not a Hugo project (no hugo.toml)")
        if full:
            if not self.api_key:
                errs.append("OPENAI_API_KEY missing (set in seo-pipeline/.env)")
            for tool in ("rsvg-convert", "cwebp", "hugo"):
                if not shutil.which(tool):
                    errs.append(f"{tool} not on PATH")
        return errs


CONFIG = Config()

# ════════════════════════════════════════════════════════════════════════
# 1. classify intent
# ════════════════════════════════════════════════════════════════════════
_INTENT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("tutorial",        re.compile(r"\b(how\s+to|step[- ]by[- ]step|tutorial|configure|install|deploy|setup|enable|disable|harden)\b", re.I)),
    ("comparison",      re.compile(r"\b(vs|versus|compare|comparison|or\s|alternatives?|which\s+is)\b", re.I)),
    ("troubleshooting", re.compile(r"\b(fix|error|not\s+working|debug|troubleshoot|issue|problem|broken|fails?)\b", re.I)),
    ("analysis",        re.compile(r"\b(analy(sis|sing|zing)|deep[- ]dive|breakdown|walkthrough|reverse|teardown|inside|dissect)\b", re.I)),
    ("news",            re.compile(r"\b(cve-?\d{4}|breach|disclosed|zero[- ]?day|0day|patch|advisory|report|in\s+the\s+wild)\b", re.I)),
)


def classify_intent(topic: str) -> str:
    for label, pat in _INTENT_PATTERNS:
        if pat.search(topic):
            return label
    return "guide"  # safe default


# ════════════════════════════════════════════════════════════════════════
# 2. build_prompt
# ════════════════════════════════════════════════════════════════════════
def build_prompt(topic: str, section: str, intent: str, year: str) -> str:
    tpl = PROMPT.read_text(encoding="utf-8")
    return (tpl
            .replace("{topic}",   topic)
            .replace("{section}", section)
            .replace("{intent}",  intent)
            .replace("{year}",    year))


# ════════════════════════════════════════════════════════════════════════
# 3. call_llm
# ════════════════════════════════════════════════════════════════════════
def call_llm(prompt: str) -> dict[str, Any]:
    """Call OpenAI Chat Completions with response_format=json_object.

    The prompt instructs the model to return strict JSON; we enforce it
    server-side too so a stray ```json fence never appears. With JSON
    mode on, the model fails fast on schema violations rather than
    silently returning prose.
    """
    client = OpenAI(api_key=CONFIG.api_key)
    for attempt in range(1, 4):
        try:
            log.info("calling %s (attempt %d/3) — prompt is %d chars",
                     CONFIG.model, attempt, len(prompt))
            resp = client.chat.completions.create(
                model=CONFIG.model,
                max_tokens=CONFIG.max_toks,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
            )
            text = (resp.choices[0].message.content or "").strip()
            if not text:
                raise RuntimeError("empty response from model")
            return _parse_json(text)
        except Exception as exc:
            if attempt == 3:
                raise
            wait = 4 * attempt
            log.warning("attempt %d failed (%s) — retrying in %ds", attempt, exc, wait)
            time.sleep(wait)
    raise RuntimeError("unreachable")


def _parse_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object in LLM response")
    return json.loads(text[start:end + 1])


# ════════════════════════════════════════════════════════════════════════
# 4. write_article
# ════════════════════════════════════════════════════════════════════════
def _safe_slug(s: str) -> str:
    return slugify(s, max_length=80, word_boundary=True, save_order=True)


def write_article(payload: dict[str, Any], section: str, publish: bool) -> Path:
    slug      = _safe_slug(payload["slug"])
    now       = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 7200))
    cover_img = f"/images/articles/{slug}.png"

    fm: dict[str, Any] = {
        "title":       payload["title"],
        "slug":        slug,
        "description": payload["description"],
        "date":        now,
        "lastmod":     now,
        "draft":       not publish,
        "author":      CONFIG.author,
        "categories":  payload.get("categories") or [section.replace("-", " ").title()],
        "tags":        payload.get("tags", []),
        "keywords":    payload.get("keywords", []),
        "toc":         True,
        "cover":       {"image": cover_img, "alt": payload.get("alt_text", payload["title"])},
    }

    body = payload["markdown_body"].strip() + "\n"
    out  = CONTENT / section / f"{slug}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "---\n" + yaml.safe_dump(fm, sort_keys=False, allow_unicode=True, width=1000) + "---\n\n" + body,
        encoding="utf-8",
    )
    log.info("wrote %s (%d bytes, draft=%s)", out.relative_to(SITE_ROOT), out.stat().st_size, fm["draft"])

    for w in _validate_seo(fm):
        log.warning("SEO: %s", w)
    return out


def _validate_seo(fm: dict[str, Any]) -> list[str]:
    warns: list[str] = []
    tlen = len(fm["title"])
    if not 50 <= tlen <= 65:
        warns.append(f"title is {tlen} chars (target 50-65)")
    dlen = len(fm["description"])
    if not 140 <= dlen <= 160:
        warns.append(f"description is {dlen} chars (target 140-160)")
    if len(fm.get("keywords") or []) < 8:
        warns.append("fewer than 8 keywords — long-tail SEO surface is thin")
    if len(fm.get("tags") or []) < 5:
        warns.append("fewer than 5 tags")
    return warns


# ════════════════════════════════════════════════════════════════════════
# 5. write_cover
# ════════════════════════════════════════════════════════════════════════
def write_cover(payload: dict[str, Any]) -> tuple[Path, Path, Path]:
    slug  = _safe_slug(payload["slug"])
    cover = payload["cover"]
    tpl   = SVG_TPL.read_text(encoding="utf-8")

    if "title_font_size" not in cover:
        n = len(cover["title"])
        cover["title_font_size"] = "130" if n <= 13 else ("120" if n <= 15 else ("110" if n <= 18 else "95"))

    fill = {
        "{{ALT}}":             payload.get("alt_text", payload["title"]),
        "{{EYEBROW}}":         cover["eyebrow"],
        "{{BADGE}}":           cover["badge"],
        "{{TITLE_FONT_SIZE}}": str(cover["title_font_size"]),
        "{{TITLE}}":           cover["title"],
        "{{SUBTITLE}}":        cover["subtitle"],
        "{{TAGLINE}}":         cover["tagline"],
        "{{PROMPT_USER}}":     cover["prompt_user"],
        "{{TERMINAL_LINE_1}}": cover["terminal_line_1"],
        "{{TERMINAL_LINE_2}}": cover["terminal_line_2"],
    }
    svg_str = tpl
    for k, v in fill.items():
        svg_str = svg_str.replace(k, str(v))

    IMAGES.mkdir(parents=True, exist_ok=True)
    svg  = IMAGES / f"{slug}.svg"
    png  = IMAGES / f"{slug}.png"
    webp = IMAGES / f"{slug}.webp"
    svg.write_text(svg_str, encoding="utf-8")

    subprocess.run(["rsvg-convert", "-w", "1200", "-h", "630", str(svg), "-o", str(png)],
                   check=True, capture_output=True)
    subprocess.run(["cwebp", "-quiet", "-q", "85", str(png), "-o", str(webp)],
                   check=True, capture_output=True)
    for p in (svg, png, webp):
        log.info("cover: %s (%d KB)", p.relative_to(SITE_ROOT), p.stat().st_size // 1024)
    return svg, png, webp


# ════════════════════════════════════════════════════════════════════════
# 6. verify
# ════════════════════════════════════════════════════════════════════════
def verify(article: Path, section: str) -> None:
    # --buildDrafts so we can verify draft:true articles too; public/ is
    # gitignored so this has no impact on what ships to the live site.
    p = subprocess.run(["hugo", "--quiet", "--buildDrafts"], cwd=SITE_ROOT,
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"hugo build failed:\n{p.stderr}")

    slug = article.stem
    page = SITE_ROOT / "public" / section / slug / "index.html"
    if not page.exists():
        raise RuntimeError(
            f"hugo did not render the page — check `draft:` and `date:` front matter.\n"
            f"Expected: {page}"
        )

    html = page.read_text(encoding="utf-8", errors="replace")
    h1   = len(re.findall(r"<h1\b", html))
    h2   = len(re.findall(r"<h2\b", html))
    faq  = "FAQPage" in html
    howto = "HowTo" in html
    if h1 != 1:
        raise AssertionError(f"H1 count {h1} (expected 1)")
    if h2 < 3:
        raise AssertionError(f"H2 count {h2} (expected ≥3 sections)")
    if not faq:
        log.warning("no FAQPage schema — long-tail snippet potential is reduced. Did the body include {{< faq >}}?")
    if howto:
        log.info("HowTo schema present (good for tutorial-intent articles)")
    log.info("verify: H1=%d, H2=%d, FAQ=%s, HowTo=%s ✓", h1, h2, faq, howto)


# ════════════════════════════════════════════════════════════════════════
# 7/8. commit + push
# ════════════════════════════════════════════════════════════════════════
def _git(*args: str) -> str:
    p = subprocess.run(["git", *args], cwd=SITE_ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{p.stderr}")
    return p.stdout


def commit_and_push(article: Path, covers: tuple[Path, Path, Path],
                    payload: dict[str, Any], section: str, publish: bool) -> None:
    paths = [article, *covers]
    rels  = [str(p.relative_to(SITE_ROOT)) for p in paths]

    dirty = _git("diff", "--cached", "--name-only").strip()
    if dirty:
        raise RuntimeError(f"refusing to commit: pre-existing staged files\n{dirty}")

    _git("add", *rels)

    title = payload["title"]
    slug  = payload["slug"]
    msg = textwrap.dedent(f"""\
        {section}: add {slug} ({title})

        Auto-generated by seo-pipeline/article.py.

        Co-Authored-By: OpenAI {CONFIG.model} <noreply@openai.com>
        """)

    env = os.environ.copy()
    env.update({
        "GIT_AUTHOR_NAME":    CONFIG.git_user,
        "GIT_AUTHOR_EMAIL":   CONFIG.git_email,
        "GIT_COMMITTER_NAME": CONFIG.git_user,
        "GIT_COMMITTER_EMAIL": CONFIG.git_email,
    })
    p = subprocess.run(["git", "commit", "-m", msg], cwd=SITE_ROOT,
                       capture_output=True, text=True, env=env)
    if p.returncode != 0:
        raise RuntimeError(f"git commit failed:\n{p.stderr}")
    log.info("committed: %s", msg.splitlines()[0])

    if publish:
        log.info("pushing to origin/%s …", CONFIG.branch)
        _git("push", "origin", CONFIG.branch)
        log.info("pushed.")
    else:
        log.info("skipped push (use --publish to push)")


# ════════════════════════════════════════════════════════════════════════
# Job runner — one topic at a time, or a TSV batch
# ════════════════════════════════════════════════════════════════════════
@dataclass
class Job:
    topic:   str
    section: str
    intent:  str


def _iter_jobs(args: argparse.Namespace) -> Iterable[Job]:
    if args.from_file:
        for raw in Path(args.from_file).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Accept TAB- or pipe-separated for human ergonomics.
            parts = [p.strip() for p in (line.split("\t") if "\t" in line else line.split("|"))]
            if len(parts) < 2:
                log.warning("skipping malformed line in %s: %s", args.from_file, line)
                continue
            topic   = parts[0]
            section = parts[1].lower()
            intent  = (parts[2].lower() if len(parts) > 2 else classify_intent(topic))
            yield Job(topic=topic, section=section, intent=intent)
    else:
        yield Job(
            topic=args.topic,
            section=args.section.lower(),
            intent=(args.intent or classify_intent(args.topic)).lower(),
        )


def run_one(job: Job, args: argparse.Namespace) -> int:
    if job.section not in ALLOWED_SECTIONS:
        log.error("section %r not in allowed set %s", job.section, sorted(ALLOWED_SECTIONS))
        return 2
    if not (CONTENT / job.section).exists():
        log.error("content/%s/ does not exist — create it before writing into it", job.section)
        return 2
    if job.intent not in ALLOWED_INTENTS:
        log.error("intent %r not in allowed set %s", job.intent, sorted(ALLOWED_INTENTS))
        return 2

    log.info("─" * 60)
    log.info("topic   : %s", job.topic)
    log.info("section : %s", job.section)
    log.info("intent  : %s", job.intent)
    log.info("─" * 60)

    prompt = build_prompt(job.topic, job.section, job.intent, args.year)

    if args.prompt_only:
        print(prompt)
        return 0

    payload = call_llm(prompt)
    article = write_article(payload, section=job.section, publish=args.publish)
    covers  = write_cover(payload)
    verify(article, section=job.section)
    commit_and_push(article, covers, payload, section=job.section, publish=args.publish)
    log.info("done: %s", article.relative_to(SITE_ROOT))
    return 0


# ════════════════════════════════════════════════════════════════════════
# main
# ════════════════════════════════════════════════════════════════════════
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("topic", nargs="?",
                   help='Article topic, e.g. "How to Detect Kerberoasting with Splunk".'
                        ' Omit when using --from-file.')
    p.add_argument("--section",
                   help=f"Target Hugo section. Allowed: {sorted(ALLOWED_SECTIONS)}")
    p.add_argument("--intent", default=None,
                   help=f"Override the auto-classified intent. Allowed: {sorted(ALLOWED_INTENTS)}")
    p.add_argument("--year", default=time.strftime("%Y"),
                   help="Year used in cover eyebrow and freshness signals. Default: current year.")
    p.add_argument("--from-file", default=None,
                   help="TSV / pipe-separated file: 'topic <TAB> section [<TAB> intent]' per line.")
    p.add_argument("--prompt-only", action="store_true",
                   help="Render the prompt and print it. No LLM call, no file writes.")
    p.add_argument("--publish", action="store_true",
                   help="Commit AND push. Without this flag, draft=true and we don't push.")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not args.from_file and not (args.topic and args.section):
        log.error("provide either a topic + --section, or --from-file <path>")
        return 2

    errs = CONFIG.validate(full=not args.prompt_only)
    if errs:
        for e in errs:
            log.error("config: %s", e)
        return 2

    fail = 0
    for job in _iter_jobs(args):
        try:
            rc = run_one(job, args)
            if rc != 0:
                fail += 1
        except Exception as exc:
            log.exception("job failed: %s — %s", job.topic, exc)
            fail += 1
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
