"""Pipeline orchestrator — entry point.

Flow:
  1. Validate config.
  2. Discover keywords (seed expansion via Autocomplete + PAA scrape).
  3. Filter + classify + rank candidates.
  4. For top-N candidates: generate article → write markdown → optionally git commit/push.
  5. Update state (seen keywords, runs.jsonl).

Usage:
  python run.py                     # full run, honours .env PUBLISH_MODE
  python run.py --publish           # force PUBLISH_MODE=publish for this run
  python run.py --dry-run           # honour DRY_RUN=1 regardless of .env
  python run.py --max-articles 1    # override per-run cap
  python run.py --seed "active directory privilege escalation"  # override seeds
  python run.py --section tools     # force section for this run
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from pathlib import Path
from typing import List

# Make `modules.*` importable when invoked as `python run.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import CONFIG  # noqa: E402
from modules.log_config import get_logger  # noqa: E402

log = get_logger("seo-pipeline")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CyberSecurity Elite — SEO automation pipeline")
    p.add_argument("--publish", action="store_true",
                   help="Force PUBLISH_MODE=publish (commits + pushes). Overrides .env.")
    p.add_argument("--dry-run", action="store_true",
                   help="No file writes, no git ops, no LLM calls. Keyword discovery still runs.")
    p.add_argument("--max-articles", type=int, default=None,
                   help="Cap on articles generated this run (overrides .env).")
    p.add_argument("--max-keywords", type=int, default=None,
                   help="Cap on keywords processed this run (overrides .env).")
    p.add_argument("--seed", action="append", default=None,
                   help="Override seed keyword(s); pass multiple times for multiple seeds.")
    p.add_argument("--section", default=None,
                   help="Force a single Hugo section for all generated articles this run.")
    p.add_argument("--keywords-only", action="store_true",
                   help="Discover + filter keywords, print them, exit without generating.")
    return p.parse_args()


def _apply_overrides(args: argparse.Namespace) -> None:
    """Mutate process env so the (frozen) CONFIG seen by submodules reflects CLI flags.

    Because CONFIG was already loaded by the time argparse runs, we re-export
    overridden vars and re-read into a fresh Config. Cheaper than threading
    flags through every module signature.
    """
    if args.publish:
        os.environ["PUBLISH_MODE"] = "publish"
    if args.dry_run:
        os.environ["DRY_RUN"] = "1"
    if args.max_articles is not None:
        os.environ["MAX_ARTICLES_PER_RUN"] = str(args.max_articles)
    if args.max_keywords is not None:
        os.environ["MAX_KEYWORDS_PER_RUN"] = str(args.max_keywords)
    if args.seed:
        os.environ["SEED_KEYWORDS"] = ",".join(args.seed)
    if args.section:
        os.environ["DEFAULT_SECTION"] = args.section


def main() -> int:
    args = _parse_args()
    _apply_overrides(args)

    # Re-import to pick up env overrides into a fresh CONFIG.
    import importlib
    import config as config_module
    importlib.reload(config_module)
    from config import CONFIG as CFG  # noqa: E402

    errors = CFG.validate()
    if errors:
        for e in errors:
            log.error("Config error: %s", e)
        return 2

    log.info("=" * 60)
    log.info("Run start | provider=%s | publish_mode=%s | dry_run=%s",
             CFG.llm_provider, CFG.publish_mode, CFG.dry_run)
    log.info("Seeds: %s", CFG.seed_keywords)
    log.info("Caps: %d keywords, %d articles", CFG.max_keywords_per_run, CFG.max_articles_per_run)
    log.info("=" * 60)

    # ---- 1. Discover -------------------------------------------------
    from modules.keyword_generator import generate_keywords
    candidates_raw = generate_keywords(CFG.seed_keywords)
    if not candidates_raw:
        log.warning("No keywords discovered — exiting")
        return 0

    # ---- 2. Filter ---------------------------------------------------
    from modules.keyword_filter import filter_and_classify, cluster_related
    candidates = filter_and_classify(candidates_raw, limit=CFG.max_keywords_per_run)
    if not candidates:
        log.warning("No candidates survived filter — exiting")
        return 0

    if args.keywords_only:
        log.info("--keywords-only set; printing top candidates:")
        for c in candidates:
            print(f"  [{c.score:>2}] {c.intent:<16} {c.section:<22} {c.keyword}")
        return 0

    # ---- 3. Generate -------------------------------------------------
    from modules.article_generator import generate_article
    from modules.markdown_builder import build_markdown
    from modules.state import mark_keywords_seen, record_run

    to_generate = candidates[: CFG.max_articles_per_run]
    log.info("Generating %d article(s) from %d candidates", len(to_generate), len(candidates))

    written: List[Path] = []
    successful_kws: List[str] = []
    failures: List[str] = []

    for cand in to_generate:
        section = args.section or cand.section
        related = cluster_related(candidates, cand)
        try:
            article = generate_article(cand.keyword, related, cand.intent, section)
            path = build_markdown(article, section=section)
            written.append(path)
            successful_kws.append(cand.keyword)
            log.info("✓ %s", path.relative_to(CFG.site_root) if not CFG.dry_run else "(dry-run)")
        except Exception as exc:  # one bad article should not kill the run
            log.error("Failed on keyword %r: %s", cand.keyword, exc)
            log.debug(traceback.format_exc())
            failures.append(cand.keyword)
            continue

    # Mark every candidate we attempted as seen, success or not — we don't
    # want to retry the same keyword next run and hit the same failure.
    mark_keywords_seen([c.keyword for c in to_generate])

    # ---- 4. Publish --------------------------------------------------
    pushed = False
    if CFG.publish_mode == "publish" and written and not CFG.dry_run:
        from modules.git_publisher import commit_and_push
        summary = (
            f"seo: auto-publish {len(written)} article(s) — "
            + ", ".join(p.stem for p in written)
        )
        try:
            pushed = commit_and_push(written, summary)
        except Exception as exc:
            log.error("Publish step failed: %s", exc)
            failures.append(f"<publish>: {exc}")

    # ---- 5. Record ---------------------------------------------------
    record_run({
        "candidates": len(candidates),
        "attempted": len(to_generate),
        "written": [str(p.relative_to(CFG.site_root)) for p in written] if not CFG.dry_run else [],
        "pushed": pushed,
        "failures": failures,
        "dry_run": CFG.dry_run,
        "publish_mode": CFG.publish_mode,
    })

    log.info("=" * 60)
    log.info("Run done | written=%d | pushed=%s | failures=%d", len(written), pushed, len(failures))
    log.info("=" * 60)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
