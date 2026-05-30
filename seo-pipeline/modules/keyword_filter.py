"""Keyword filtering: intent classification, quality gates, light clustering.

We don't need SemRush's KD score to be useful. The goal here is to drop low-
signal keywords (branded, transactional, junk) and keep informational/tutorial
long-tail that maps cleanly to article ideas.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

from modules.log_config import get_logger
from modules.state import filter_unseen_keywords

log = get_logger(__name__)

# Keywords containing any of these tokens are filtered out — they're either
# off-topic, transactional (we don't sell), or noise we can't usefully target.
_BLOCKLIST = {
    "buy", "discount", "coupon", "torrent", "crack", "free download",
    "for sale", "cheap", "salary", "job", "jobs", "hiring",
    "lyrics", "meme", "memes", "tiktok",
}

# Section routing — match keyword tokens to Hugo content section.
# Order matters: first match wins, so more specific sections come first.
_SECTION_RULES: List[Tuple[str, List[str]]] = [
    ("ctf-writeups", ["ctf", "hackthebox", "tryhackme", "picoctf", "writeup", "walkthrough"]),
    ("malware-analysis", ["malware", "ransomware", "rat ", "trojan", "stealer", "rootkit"]),
    ("reverse-engineering", ["reverse engineering", "ghidra", "ida pro", "binary analysis", "disassembl"]),
    ("forensics", ["forensics", "memory dump", "volatility", "autopsy", "incident response"]),
    ("bug-bounty", ["bug bounty", "hackerone", "bugcrowd", "responsible disclosure"]),
    ("cloud-security", ["aws security", "azure security", "gcp security", "kubernetes", "k8s", "container security"]),
    ("web-security", ["xss", "sql injection", "csrf", "owasp", "burp suite", "ssrf"]),
    ("network-security", ["firewall", "vpn", "network", "dns ", "tls ", "ssl ", "ids ", "ips "]),
    ("certifications", ["oscp", "ceh", "cissp", "security+", "comptia", "cysa"]),
    ("tools", ["nmap", "metasploit", "wireshark", "tool", "scanner"]),
    ("news", ["cve-", "vulnerability disclosed", "zero day", "0day"]),
    ("tutorials", []),  # default fallback
]


@dataclass(frozen=True)
class KeywordCandidate:
    keyword: str
    intent: str         # "informational" | "tutorial" | "comparison" | "troubleshooting" | "navigational"
    section: str        # Hugo section the article should land in
    score: int          # higher = more attractive (length, intent, modifier weight)


# ---- Intent --------------------------------------------------------------

_INTENT_PATTERNS = (
    ("tutorial", re.compile(r"\b(how to|tutorial|step by step|guide|setup|install|configure|build|create|deploy|enable|disable)\b")),
    ("comparison", re.compile(r"\b(vs|versus|compare|comparison|alternative|alternatives|best)\b")),
    ("troubleshooting", re.compile(r"\b(fix|error|not working|troubleshoot|debug|issue|problem)\b")),
    ("informational", re.compile(r"\b(what is|what are|why|when|definition|meaning|explained)\b")),
)


def _classify_intent(kw: str) -> str:
    low = kw.lower()
    for label, pat in _INTENT_PATTERNS:
        if pat.search(low):
            return label
    # Default for long-tail with no explicit modifier: assume informational.
    return "informational"


def _route_section(kw: str) -> str:
    low = kw.lower()
    for section, tokens in _SECTION_RULES:
        if not tokens:
            return section  # fallback
        if any(tok in low for tok in tokens):
            return section
    return "tutorials"


def _score(kw: str, intent: str) -> int:
    """Heuristic ranking. Higher = better article candidate."""
    words = kw.split()
    score = 0
    # Long-tail (3-6 words) ranks highest; very short queries are ambiguous,
    # very long ones rarely have meaningful search volume.
    if 3 <= len(words) <= 6:
        score += 5
    elif len(words) == 2:
        score += 1
    # Tutorial/troubleshooting intent converts best for a how-to blog.
    score += {"tutorial": 6, "troubleshooting": 4, "informational": 3, "comparison": 2}.get(intent, 0)
    # Question-shaped queries often map cleanly to FAQ-rich articles.
    if kw.strip().endswith("?"):
        score += 2
    return score


# ---- Public API ----------------------------------------------------------

def _is_blocked(kw: str) -> bool:
    low = kw.lower()
    if any(tok in low for tok in _BLOCKLIST):
        return True
    if not re.search(r"[a-zA-Z]", kw):
        return True
    if len(kw) < 10 or len(kw) > 120:
        return True
    return False


def filter_and_classify(keywords: Iterable[str], limit: int) -> List[KeywordCandidate]:
    """Returns top-`limit` candidates sorted by score desc, with dedup against state."""
    fresh = filter_unseen_keywords(keywords)
    log.info("Keyword filter: %d unseen of %d input", len(fresh), len(list(keywords) if not isinstance(keywords, list) else keywords))

    cands: List[KeywordCandidate] = []
    for kw in fresh:
        if _is_blocked(kw):
            continue
        intent = _classify_intent(kw)
        if intent == "navigational":
            continue
        section = _route_section(kw)
        cands.append(KeywordCandidate(
            keyword=kw,
            intent=intent,
            section=section,
            score=_score(kw, intent),
        ))

    cands.sort(key=lambda c: c.score, reverse=True)
    selected = cands[:limit]
    log.info("Selected %d/%d candidates after filter+rank", len(selected), len(cands))
    return selected


def cluster_related(candidates: List[KeywordCandidate], primary: KeywordCandidate) -> List[str]:
    """Return up to 12 sibling keywords from the same section that share tokens with primary.

    Used to give the article generator a richer context: a primary keyword
    plus a list of semantically related questions/queries to weave in.
    """
    tokens = set(primary.keyword.lower().split())
    by_overlap: Dict[int, List[str]] = defaultdict(list)
    for c in candidates:
        if c.keyword == primary.keyword or c.section != primary.section:
            continue
        overlap = len(tokens & set(c.keyword.lower().split()))
        if overlap == 0:
            continue
        by_overlap[overlap].append(c.keyword)
    out: List[str] = []
    for overlap in sorted(by_overlap.keys(), reverse=True):
        out.extend(by_overlap[overlap])
        if len(out) >= 12:
            break
    return out[:12]
