"""Render a GeneratedArticle into a Hugo content file with YAML front matter.

Front-matter shape matches the existing articles in this repo (see
content/tutorials/*.md). Critically:

  - ISO 8601 dates with Z suffix (date, lastmod)
  - draft defaults true unless PUBLISH_MODE=publish
  - cover block omitted; the user generates cover SVG/PNG/WebP manually
  - slug deduplication against state + filesystem
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from slugify import slugify

from config import CONFIG
from modules.article_generator import GeneratedArticle
from modules.log_config import get_logger
from modules.state import load_seen_slugs, mark_slug_seen, slug_exists_on_disk

log = get_logger(__name__)


def _safe_slug(base: str) -> str:
    s = slugify(base, max_length=70, word_boundary=True, save_order=True)
    return s or "untitled"


def _ensure_unique_slug(slug: str, section: str) -> str:
    """If slug collides with state or filesystem, append -2, -3, ..."""
    seen = load_seen_slugs()
    candidate = slug
    n = 2
    while candidate in seen or slug_exists_on_disk(candidate, section):
        candidate = f"{slug}-{n}"
        n += 1
        if n > 50:
            raise RuntimeError(f"Could not find unique slug from base '{slug}' after 50 tries")
    return candidate


def _build_front_matter(article: GeneratedArticle, section: str) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    draft = CONFIG.publish_mode != "publish"
    fm: dict = {
        "title": article.title,
        "slug": article.slug,
        "description": article.description,
        "date": now,
        "lastmod": now,
        "draft": draft,
        "author": CONFIG.default_author,
        "categories": article.categories or [section.replace("-", " ").title()],
        "tags": article.tags,
        "keywords": article.keywords,
        "toc": article.toc,
    }
    return fm


def _dump_front_matter(fm: dict) -> str:
    body = yaml.safe_dump(
        fm,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=1000,  # don't wrap long descriptions onto multiple lines
    )
    return f"---\n{body}---\n"


def build_markdown(article: GeneratedArticle, section: Optional[str] = None) -> Path:
    """Write the article to content/<section>/<slug>.md and return the path.

    Slug is uniquified against state and the live filesystem before writing.
    State is updated only after the file is successfully on disk.
    """
    section = section or CONFIG.default_section

    raw_slug = _safe_slug(article.slug or article.title)
    final_slug = _ensure_unique_slug(raw_slug, section)
    if final_slug != article.slug:
        log.info("Slug normalized: %r → %r", article.slug, final_slug)
        # Mutate the dataclass in-place so the caller sees the final slug.
        object.__setattr__(article, "slug", final_slug)

    fm = _build_front_matter(article, section)
    fm["slug"] = final_slug

    out_dir = CONFIG.content_dir / section
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{final_slug}.md"

    content = _dump_front_matter(fm) + "\n" + article.content_markdown.strip() + "\n"

    if CONFIG.dry_run:
        log.info("DRY_RUN=1 — skipping write of %s (%d chars)", out_path, len(content))
        return out_path

    out_path.write_text(content, encoding="utf-8")
    mark_slug_seen(final_slug)
    log.info("Wrote %s (%d chars, draft=%s)", out_path, len(content), fm["draft"])
    return out_path
