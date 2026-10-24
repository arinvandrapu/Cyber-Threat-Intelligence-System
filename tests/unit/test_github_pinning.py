"""head_at must return the branch head at a date via first-parent history, so a feature
commit made before the cutoff but merged after it is never chosen."""

import os
import shutil
import subprocess
from datetime import date

import pytest

from cti.sources.github import head_at

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def git(repo, *args, when=None):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    if when:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"{when}T12:00:00+00:00"
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def commit(repo, name, when):
    (repo / name).write_text(name)
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", name, when=when)
    return git(repo, "rev-parse", "HEAD")


def test_first_parent_head_excludes_late_merged_feature(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    base = commit(repo, "base", "2026-04-01")
    git(repo, "checkout", "-q", "-b", "feature")
    feature = commit(repo, "feature", "2026-04-20")  # authored before the cutoff...
    git(repo, "checkout", "-q", "main")
    on_main = commit(repo, "main-work", "2026-04-25")
    git(
        repo, "merge", "-q", "--no-ff", "feature", "-m", "merge", when="2026-05-10"
    )  # ...merged later

    sha, _ = head_at(f"file://{repo}", "main", date(2026, 4, 28))
    assert sha == on_main
    assert sha not in (feature, base)

    sha_after, _ = head_at(f"file://{repo}", "main", date(2026, 5, 11))
    assert sha_after == git(repo, "rev-parse", "HEAD")


def test_rejects_odd_branch_names():
    with pytest.raises(ValueError):
        head_at("file:///nonexistent", "main; rm -rf /", date(2026, 1, 1))
