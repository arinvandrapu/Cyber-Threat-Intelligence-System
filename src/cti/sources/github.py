"""Pin git-hosted data to the commit that was the branch head at the end of a date.

The GitHub commits API's ``until`` filter is not enough: it filters by committer date
over everything reachable from the branch, so a pull-request commit made before the
cutoff but merged after it would be returned, and its tree could contain files that
were not on the branch at the cutoff (leakage). Instead we make a tiny treeless clone
(commit objects only) and walk the branch's *first-parent* history, which is the
sequence of states the branch head actually had.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from datetime import UTC, date, datetime, time, timedelta

API = "https://api.github.com"
# Shallow history kept before the requested date, widened on a miss: --shallow-since cuts by
# commit date, and a merge whose first parent is older than the margin ends the walk early.
HISTORY_MARGINS = (timedelta(days=60), timedelta(days=365), timedelta(days=1095))


def repo_url(repo: str) -> str:
    return f"https://github.com/{repo}.git"


def raw_url(repo: str, sha: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"


def archive_url(repo: str, sha: str) -> str:
    return f"https://codeload.github.com/{repo}/tar.gz/{sha}"


def _git(*args: str, cwd: str | None = None) -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to pin repository data to a date")
    result = subprocess.run(  # noqa: S603 - argv list, values validated by callers
        [git, *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=900
    )
    return result.stdout.strip()


def head_at(url: str, branch: str, on: date) -> tuple[str, str]:
    """Return ``(sha, committer_date)`` of ``branch``'s head at the end of ``on`` (UTC)."""
    if not branch.replace("-", "").replace("_", "").replace("/", "").isalnum():
        raise ValueError(f"suspicious branch name: {branch!r}")
    end = datetime.combine(on, time(23, 59, 59), tzinfo=UTC)
    for margin in HISTORY_MARGINS:
        if out := _first_parent_head(url, branch, end, (end - margin).date()):
            break
    if not out:
        raise LookupError(f"no commit on {branch} at or before {on} in {url}")
    sha, committed = out.split()
    return sha, committed


def _first_parent_head(url: str, branch: str, end: datetime, since: date) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        _git(
            "clone",
            "--quiet",
            "--bare",
            "--single-branch",
            "--branch",
            branch,
            "--filter=tree:0",
            f"--shallow-since={since.isoformat()}",
            url,
            tmp,
        )
        return _git(
            "rev-list",
            "-1",
            "--first-parent",
            f"--before={end.isoformat()}",
            "--format=%H %cI",
            "--no-commit-header",
            branch,
            cwd=tmp,
        )
