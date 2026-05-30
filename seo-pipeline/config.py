"""Central configuration loaded from .env once at import time.

Importing modules read from `config` instead of os.environ so we get a single
source of truth, type coercion, and validation at startup rather than at the
first failed API call.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parent
load_dotenv(_ROOT / ".env")


def _csv(name: str, default: str = "") -> List[str]:
    raw = os.getenv(name, default)
    return [s.strip() for s in raw.split(",") if s.strip()]


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    # Paths
    pipeline_root: Path = _ROOT
    site_root: Path = field(default_factory=lambda: Path(os.getenv("SITE_ROOT", str(_ROOT.parent))))

    # LLM
    llm_provider: str = os.getenv("LLM_PROVIDER", "anthropic").strip().lower()
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-7")
    anthropic_max_tokens: int = _int("ANTHROPIC_MAX_TOKENS", 8000)
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o")
    openai_max_tokens: int = _int("OPENAI_MAX_TOKENS", 8000)

    # Content
    default_section: str = os.getenv("DEFAULT_SECTION", "tutorials").strip()
    default_author: str = os.getenv("DEFAULT_AUTHOR", "CyberSecurity Elite Team")
    target_words_min: int = _int("TARGET_WORD_COUNT_MIN", 1800)
    target_words_max: int = _int("TARGET_WORD_COUNT_MAX", 3500)

    # Keywords
    seed_keywords: List[str] = field(default_factory=lambda: _csv("SEED_KEYWORDS"))
    max_keywords_per_run: int = _int("MAX_KEYWORDS_PER_RUN", 20)
    max_articles_per_run: int = _int("MAX_ARTICLES_PER_RUN", 3)
    autocomplete_hl: str = os.getenv("AUTOCOMPLETE_HL", "en")
    autocomplete_gl: str = os.getenv("AUTOCOMPLETE_GL", "us")

    # Publishing
    publish_mode: str = os.getenv("PUBLISH_MODE", "draft").strip().lower()
    git_branch: str = os.getenv("GIT_BRANCH", "main")
    git_remote: str = os.getenv("GIT_REMOTE", "origin")
    git_author_name: str = os.getenv("GIT_COMMIT_AUTHOR_NAME", "SEO Pipeline")
    git_author_email: str = os.getenv("GIT_COMMIT_AUTHOR_EMAIL", "seo-pipeline@example.com")

    # Misc
    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()
    dry_run: bool = _bool("DRY_RUN", False)

    # Derived paths (set in __post_init__ via object.__setattr__ since frozen)
    state_dir: Path = field(init=False)
    logs_dir: Path = field(init=False)
    prompts_dir: Path = field(init=False)
    content_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "state_dir", self.pipeline_root / "state")
        object.__setattr__(self, "logs_dir", self.pipeline_root / "logs")
        object.__setattr__(self, "prompts_dir", self.pipeline_root / "prompts")
        object.__setattr__(self, "content_dir", self.site_root / "content")

    # ---- Validation -----------------------------------------------------
    def validate(self) -> List[str]:
        """Returns a list of human-readable errors. Empty list = config OK."""
        errors: List[str] = []

        if self.llm_provider not in {"anthropic", "openai"}:
            errors.append(f"LLM_PROVIDER must be 'anthropic' or 'openai', got '{self.llm_provider}'")
        if self.llm_provider == "anthropic" and not self.anthropic_api_key:
            errors.append("ANTHROPIC_API_KEY is required when LLM_PROVIDER=anthropic")
        if self.llm_provider == "openai" and not self.openai_api_key:
            errors.append("OPENAI_API_KEY is required when LLM_PROVIDER=openai")

        if not self.site_root.exists():
            errors.append(f"SITE_ROOT does not exist: {self.site_root}")
        if not (self.site_root / "hugo.toml").exists() and not (self.site_root / "config.toml").exists():
            errors.append(f"SITE_ROOT does not look like a Hugo project (no hugo.toml/config.toml): {self.site_root}")

        if not self.content_dir.exists():
            errors.append(f"Content directory missing: {self.content_dir}")
        elif not (self.content_dir / self.default_section).exists():
            errors.append(
                f"DEFAULT_SECTION '{self.default_section}' has no folder under content/. "
                f"Create {self.content_dir / self.default_section}/ first."
            )

        if not self.seed_keywords:
            errors.append("SEED_KEYWORDS must not be empty")

        if self.publish_mode not in {"draft", "publish"}:
            errors.append(f"PUBLISH_MODE must be 'draft' or 'publish', got '{self.publish_mode}'")

        return errors


CONFIG = Config()
