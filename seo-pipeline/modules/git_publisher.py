"""Stage, commit, and push generated articles via GitPython.

Behaviour:
  - Only invoked when PUBLISH_MODE=publish (run.py enforces this).
  - Commits each article individually so the git log is readable and
    individual articles can be reverted without affecting others.
  - Never force-pushes. Never amends. Never operates on a dirty index it
    didn't create — if there are pre-existing staged changes, we bail.
  - Push uses the configured remote and branch. Credentials come from the
    user's normal git config (SSH key, gh CLI auth, or stored HTTPS creds).
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from git import GitCommandError, Repo

from config import CONFIG
from modules.log_config import get_logger

log = get_logger(__name__)


def _open_repo() -> Repo:
    repo = Repo(CONFIG.site_root)
    if repo.bare:
        raise RuntimeError(f"{CONFIG.site_root} is a bare repo")
    return repo


def commit_and_push(paths: List[Path], summary: str) -> bool:
    """Stage `paths`, commit with `summary`, push to configured remote/branch.

    Returns True on a successful push, False if there was nothing to commit.
    Raises on actual git errors.
    """
    if not paths:
        log.info("Nothing to commit (empty paths list)")
        return False

    if CONFIG.dry_run:
        log.info("DRY_RUN=1 — would commit %d file(s): %s", len(paths), [str(p) for p in paths])
        return False

    repo = _open_repo()

    # Refuse to operate if the index already has staged changes — we don't
    # want to accidentally bundle the user's in-progress work into our commit.
    if repo.index.diff("HEAD"):
        log.error("Repo has pre-existing staged changes — aborting auto-commit")
        raise RuntimeError("git index is dirty; resolve before re-running with PUBLISH_MODE=publish")

    rel_paths = [str(p.relative_to(CONFIG.site_root)) for p in paths]
    repo.index.add(rel_paths)
    log.info("Staged %d path(s): %s", len(rel_paths), rel_paths)

    actor_kwargs = {
        "author_date": None,
        "commit_date": None,
    }

    # GitPython's commit() takes author/committer via env-style overrides on
    # the Repo.git command, so we set them explicitly per-commit.
    with repo.git.custom_environment(
        GIT_AUTHOR_NAME=CONFIG.git_author_name,
        GIT_AUTHOR_EMAIL=CONFIG.git_author_email,
        GIT_COMMITTER_NAME=CONFIG.git_author_name,
        GIT_COMMITTER_EMAIL=CONFIG.git_author_email,
    ):
        repo.index.commit(summary, **actor_kwargs)
    log.info("Committed: %s", summary)

    try:
        remote = repo.remote(CONFIG.git_remote)
    except ValueError as exc:
        raise RuntimeError(f"Git remote '{CONFIG.git_remote}' not configured") from exc

    try:
        push_info = remote.push(refspec=f"HEAD:{CONFIG.git_branch}")
    except GitCommandError as exc:
        log.error("git push failed: %s", exc)
        raise

    # GitPython returns a list of PushInfo objects; check for errors.
    for info in push_info:
        if info.flags & info.ERROR:
            raise RuntimeError(f"git push reported error: {info.summary}")
    log.info("Pushed to %s/%s", CONFIG.git_remote, CONFIG.git_branch)
    return True
