#!/usr/bin/env python3
"""Fail safely when common credentials appear in source or generated output.

The checker reports paths and rule names only; it never prints matched values.
It deliberately excludes article prose from generic key/value checks because CTF
writeups often discuss sample credentials. High-confidence token formats are
checked throughout the generated site.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


TOKEN_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("stripe-live-secret", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
)

GA4_SECRET_FIELD = re.compile(r"(?i)\bga4\s*MP\s*Secret\b")
ASSIGNED_SECRET = re.compile(
    r"(?i)\b(?:api[_-]?secret|client[_-]?secret|access[_-]?token|"
    r"secret[_-]?key|private[_-]?key)\s*[:=]\s*[\"']"
    r"[A-Za-z0-9_-]{16,}[\"']"
)

SOURCE_PATHS = (".",)
EXCLUDED_DIRS = {".git", "node_modules", "public", "resources", ".venv"}
TEXT_SUFFIXES = {
    ".css", ".html", ".js", ".json", ".md", ".py", ".toml", ".txt",
    ".webmanifest", ".xml", ".yaml", ".yml",
}


def files_under(paths: list[Path]):
    for path in paths:
        if path.is_file():
            if path.suffix.lower() in TEXT_SUFFIXES or path.name == "Dockerfile" or path.name.startswith(".env"):
                yield path
        elif path.is_dir():
            yield from (
                p for p in path.rglob("*")
                if p.is_file()
                and not any(part in EXCLUDED_DIRS for part in p.parts)
                and (p.suffix.lower() in TEXT_SUFFIXES or p.name == "Dockerfile" or p.name.startswith(".env"))
            )


def scan(paths: list[Path], *, source_mode: bool) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for path in files_under(paths):
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue

        if GA4_SECRET_FIELD.search(content):
            findings.append((str(path), "GA4 Measurement Protocol secret field"))
        if source_mode and "content" not in path.parts and ASSIGNED_SECRET.search(content):
            findings.append((str(path), "literal credential assignment"))
        for rule, pattern in TOKEN_PATTERNS:
            if pattern.search(content):
                findings.append((str(path), rule))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source", action="store_true", help="scan source/configuration")
    mode.add_argument("--output", metavar="DIR", help="scan generated output directory")
    args = parser.parse_args()

    if args.source:
        paths = [Path(p) for p in SOURCE_PATHS]
        source_mode = True
    else:
        paths = [Path(args.output)]
        source_mode = False

    findings = scan(paths, source_mode=source_mode)
    if findings:
        print("Secret check failed (matched values are suppressed):", file=sys.stderr)
        for path, rule in findings:
            print(f"  {path}: {rule}", file=sys.stderr)
        return 1

    print("Secret check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
