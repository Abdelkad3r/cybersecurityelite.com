"""Rotating file + rich-console logger used across the pipeline."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.logging import RichHandler

from config import CONFIG

_CONFIGURED = False


def get_logger(name: str = "seo-pipeline") -> logging.Logger:
    """Returns a configured logger. Safe to call repeatedly — handlers attach once."""
    global _CONFIGURED
    logger = logging.getLogger(name)

    if _CONFIGURED:
        return logger

    CONFIG.logs_dir.mkdir(parents=True, exist_ok=True)
    log_file: Path = CONFIG.logs_dir / "pipeline.log"

    file_handler = RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")
    )

    console_handler = RichHandler(
        rich_tracebacks=True,
        show_time=False,
        show_path=False,
        markup=False,
    )

    root = logging.getLogger()
    root.setLevel(CONFIG.log_level)
    # Wipe any pre-existing handlers from libraries that called basicConfig early.
    root.handlers.clear()
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    # Tame chatty libraries.
    for noisy in ("urllib3", "openai", "anthropic", "httpx", "git"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True
    return logger
