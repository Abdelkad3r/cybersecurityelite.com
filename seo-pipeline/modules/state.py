"""Persistent state — dedup of already-processed keywords and slugs.

state/keywords_seen.json     — set of normalized keyword strings ever processed
state/slugs_seen.json        — set of slugs ever generated
state/runs.jsonl             — append-only run history (one JSON object per run)

We use plain JSON files (not SQLite) because the volume is tiny and JSON is
trivial to inspect and edit by hand if something goes sideways.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Set

from config import CONFIG
from modules.log_config import get_logger

log = get_logger(__name__)

_LOCK = threading.Lock()

_KEYWORDS_FILE = CONFIG.state_dir / "keywords_seen.json"
_SLUGS_FILE = CONFIG.state_dir / "slugs_seen.json"
_RUNS_FILE = CONFIG.state_dir / "runs.jsonl"


def _ensure_dir() -> None:
    CONFIG.state_dir.mkdir(parents=True, exist_ok=True)


def _load_set(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    try:
        return set(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not read %s (%s) — starting empty", path.name, exc)
        return set()


def _save_set(path: Path, data: Set[str]) -> None:
    _ensure_dir()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(sorted(data), indent=2), encoding="utf-8")
    tmp.replace(path)


# ---- Keyword dedup ---------------------------------------------------------

def _normalize_kw(kw: str) -> str:
    return " ".join(kw.lower().split())


def load_seen_keywords() -> Set[str]:
    with _LOCK:
        return _load_set(_KEYWORDS_FILE)


def mark_keywords_seen(keywords: Iterable[str]) -> None:
    with _LOCK:
        seen = _load_set(_KEYWORDS_FILE)
        seen.update(_normalize_kw(k) for k in keywords)
        _save_set(_KEYWORDS_FILE, seen)


def filter_unseen_keywords(keywords: Iterable[str]) -> list[str]:
    seen = load_seen_keywords()
    out: list[str] = []
    seen_in_batch: Set[str] = set()
    for kw in keywords:
        norm = _normalize_kw(kw)
        if norm and norm not in seen and norm not in seen_in_batch:
            seen_in_batch.add(norm)
            out.append(kw)
    return out


# ---- Slug dedup ------------------------------------------------------------

def load_seen_slugs() -> Set[str]:
    with _LOCK:
        return _load_set(_SLUGS_FILE)


def mark_slug_seen(slug: str) -> None:
    with _LOCK:
        seen = _load_set(_SLUGS_FILE)
        seen.add(slug)
        _save_set(_SLUGS_FILE, seen)


def slug_exists_on_disk(slug: str, section: str) -> bool:
    """Cross-check the generated slug against actual files under content/<section>/.

    We dedup against state AND the live filesystem because a clone might have
    a fresh state file but the article already exists in content/.
    """
    md = CONFIG.content_dir / section / f"{slug}.md"
    return md.exists()


# ---- Run history -----------------------------------------------------------

def record_run(summary: dict) -> None:
    _ensure_dir()
    payload = {"ts": datetime.now(timezone.utc).isoformat(), **summary}
    with _LOCK:
        with _RUNS_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
