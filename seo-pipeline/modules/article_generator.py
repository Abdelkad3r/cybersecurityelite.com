"""LLM-backed article generator. Pluggable provider (Anthropic | OpenAI).

The provider returns a JSON object that conforms to prompts/article_prompt.md.
We validate the shape here so downstream code (markdown_builder) can trust the
schema.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List

from config import CONFIG
from modules.log_config import get_logger
from modules.retry import retry

log = get_logger(__name__)


@dataclass
class GeneratedArticle:
    title: str
    slug: str
    description: str
    keywords: List[str]
    tags: List[str]
    categories: List[str]
    toc: bool
    content_markdown: str

    @classmethod
    def from_dict(cls, payload: Dict) -> "GeneratedArticle":
        missing = [k for k in ("title", "slug", "description", "keywords", "content_markdown") if k not in payload]
        if missing:
            raise ValueError(f"LLM response missing required fields: {missing}")
        return cls(
            title=str(payload["title"]).strip(),
            slug=str(payload["slug"]).strip().lower(),
            description=str(payload["description"]).strip(),
            keywords=[str(k).strip().lower() for k in payload.get("keywords", []) if str(k).strip()],
            tags=[str(t).strip().lower() for t in payload.get("tags", []) if str(t).strip()],
            categories=[str(c).strip() for c in payload.get("categories", []) if str(c).strip()] or ["Tutorials"],
            toc=bool(payload.get("toc", True)),
            content_markdown=str(payload["content_markdown"]),
        )


def _load_prompt_template() -> str:
    return (CONFIG.prompts_dir / "article_prompt.md").read_text(encoding="utf-8")


def _render_prompt(primary: str, related: List[str], intent: str, section: str) -> str:
    template = _load_prompt_template()
    return (template
            .replace("{primary_keyword}", primary)
            .replace("{related_keywords}", ", ".join(related) if related else "(none)")
            .replace("{intent}", intent)
            .replace("{section}", section)
            .replace("{word_count_min}", str(CONFIG.target_words_min))
            .replace("{word_count_max}", str(CONFIG.target_words_max)))


def _extract_json(text: str) -> Dict:
    """LLMs sometimes wrap JSON in ```json fences despite instructions. Strip them."""
    text = text.strip()
    if text.startswith("```"):
        # Drop the first line (``` or ```json) and the closing fence.
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    # Find first { and last } as a final safety net.
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found in LLM response")
    return json.loads(text[start : end + 1])


# ---- Providers -----------------------------------------------------------

@retry(attempts=3, base_delay=4.0, exceptions=(Exception,))
def _generate_anthropic(prompt: str) -> str:
    try:
        from anthropic import Anthropic
    except ImportError as exc:
        raise RuntimeError("anthropic package not installed — pip install anthropic") from exc

    client = Anthropic(api_key=CONFIG.anthropic_api_key)
    resp = client.messages.create(
        model=CONFIG.anthropic_model,
        max_tokens=CONFIG.anthropic_max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    # response.content is a list of blocks; we want the text block(s) concatenated.
    parts: List[str] = []
    for block in resp.content:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "".join(parts)


@retry(attempts=3, base_delay=4.0, exceptions=(Exception,))
def _generate_openai(prompt: str) -> str:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("openai package not installed — pip install openai") from exc

    client = OpenAI(api_key=CONFIG.openai_api_key)
    resp = client.chat.completions.create(
        model=CONFIG.openai_model,
        max_tokens=CONFIG.openai_max_tokens,
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )
    return resp.choices[0].message.content or ""


def generate_article(primary: str, related: List[str], intent: str, section: str) -> GeneratedArticle:
    """Generate one article. Raises on validation or API failure (after retries)."""
    prompt = _render_prompt(primary, related, intent, section)
    log.info("Generating article for primary keyword: %r (intent=%s, section=%s)", primary, intent, section)

    if CONFIG.dry_run:
        # Synthetic article so the rest of the pipeline can be smoke-tested
        # without burning API credits.
        log.info("DRY_RUN=1 — returning synthetic article")
        slug = "-".join(primary.lower().split())[:60]
        return GeneratedArticle(
            title=f"{primary.title()} (Draft Stub)",
            slug=slug,
            description=f"Placeholder description for {primary}. Replace before publish.",
            keywords=[primary] + related[:5],
            tags=[primary.split()[0]] if primary else [],
            categories=[section.replace("-", " ").title()],
            toc=True,
            content_markdown=(
                "## Introduction\n\n"
                f"DRY-RUN stub for `{primary}`. The real generator would expand "
                "this into a full article here.\n"
            ),
        )

    raw = (_generate_anthropic if CONFIG.llm_provider == "anthropic" else _generate_openai)(prompt)
    payload = _extract_json(raw)
    article = GeneratedArticle.from_dict(payload)

    # Post-validation: catch the most common quality regressions before we
    # waste a git commit on them.
    if len(article.title) > 75:
        log.warning("Title is %d chars (>75) — will truncate in SERP", len(article.title))
    if not 100 <= len(article.description) <= 170:
        log.warning("Description is %d chars (target 140-160)", len(article.description))
    if "# " in article.content_markdown.splitlines()[0] if article.content_markdown else False:
        log.warning("Article body starts with H1 — Hugo will produce duplicate H1s")

    return article
