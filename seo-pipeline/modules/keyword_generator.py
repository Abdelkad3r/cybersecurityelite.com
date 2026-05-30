"""Keyword discovery via free public surfaces.

Sources used:
  1. Google Autocomplete (suggestqueries.google.com) — returns up to 10
     long-tail completions per query. Public, unauthenticated, alphabet-pivot
     friendly. Not officially documented, but stable for ~15 years.
  2. Google's "People Also Ask" / related-searches HTML — best-effort scrape.
     Google's SERP HTML changes often; we degrade gracefully when selectors
     fail rather than crashing the whole run.

Returned keywords are NOT deduped against state here — that's the filter step.
"""

from __future__ import annotations

import string
import time
from typing import Iterable, List
from urllib.parse import quote_plus

import requests
from bs4 import BeautifulSoup

from config import CONFIG
from modules.log_config import get_logger
from modules.retry import retry

log = get_logger(__name__)

# A real-looking UA. Google blocks obvious python-requests user-agents quickly.
_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15"
)

_AUTOCOMPLETE_URL = "https://suggestqueries.google.com/complete/search"
_SERP_URL = "https://www.google.com/search"


@retry(attempts=3, base_delay=2.0, exceptions=(requests.RequestException,))
def _autocomplete(query: str) -> List[str]:
    """One Autocomplete call. Returns up to ~10 completions."""
    params = {
        "client": "firefox",  # JSON array response: [query, [suggestions...]]
        "q": query,
        "hl": CONFIG.autocomplete_hl,
        "gl": CONFIG.autocomplete_gl,
    }
    resp = requests.get(
        _AUTOCOMPLETE_URL,
        params=params,
        headers={"User-Agent": _UA, "Accept": "application/json"},
        timeout=8,
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, list) and len(data) >= 2 and isinstance(data[1], list):
        return [str(s).strip() for s in data[1] if s]
    return []


def _expand_seed(seed: str) -> List[str]:
    """Expand a seed via alphabet-pivot: '<seed> a', '<seed> b', ..., plus question modifiers."""
    out: List[str] = []
    pivots = list(string.ascii_lowercase) + ["how", "what", "why", "when", "best", "vs"]
    for p in pivots:
        q = f"{seed} {p}".strip()
        try:
            out.extend(_autocomplete(q))
        except requests.RequestException as exc:
            log.warning("Autocomplete pivot '%s' failed: %s", q, exc)
            continue
        # Polite delay — Google will rate-limit anonymous clients.
        time.sleep(0.4)
    return out


@retry(attempts=2, base_delay=3.0, exceptions=(requests.RequestException,))
def _scrape_paa(query: str) -> List[str]:
    """Best-effort People-Also-Ask scrape. Returns [] silently on failure."""
    params = {"q": query, "hl": CONFIG.autocomplete_hl, "gl": CONFIG.autocomplete_gl}
    try:
        resp = requests.get(
            _SERP_URL,
            params=params,
            headers={"User-Agent": _UA, "Accept-Language": "en-US,en;q=0.9"},
            timeout=10,
        )
        if resp.status_code != 200:
            return []
        soup = BeautifulSoup(resp.text, "lxml")
        # PAA accordion items historically use role="heading" with question text.
        # Selector is fragile by nature — wrap in try/except and return [].
        questions: List[str] = []
        for el in soup.select('[role="heading"]'):
            text = el.get_text(strip=True)
            if text.endswith("?") and 6 < len(text) < 140:
                questions.append(text)
        # Related searches block
        for el in soup.select("a"):
            href = el.get("href", "") or ""
            if "/search?" in href and "q=" in href:
                text = el.get_text(strip=True)
                if text and text.endswith("?") and text not in questions:
                    questions.append(text)
        return questions[:20]
    except (requests.RequestException, ValueError) as exc:
        log.debug("PAA scrape for '%s' failed (non-fatal): %s", query, exc)
        return []


def generate_keywords(seeds: Iterable[str] | None = None) -> List[str]:
    """Run discovery across all seeds; returns a deduped, ordered list of candidates."""
    seeds = list(seeds) if seeds is not None else CONFIG.seed_keywords
    if not seeds:
        log.warning("No seeds — keyword generation is a no-op")
        return []

    all_candidates: List[str] = []
    seen_local: set[str] = set()

    for seed in seeds:
        log.info("Discovering keywords for seed: %r", seed)
        suggestions = _expand_seed(seed)
        paa = _scrape_paa(seed)
        for kw in suggestions + paa:
            norm = " ".join(kw.lower().split())
            if norm and norm not in seen_local:
                seen_local.add(norm)
                all_candidates.append(kw.strip())
        log.info("  ⇒ %d unique candidates so far", len(all_candidates))

    log.info("Keyword discovery complete: %d total candidates", len(all_candidates))
    return all_candidates
