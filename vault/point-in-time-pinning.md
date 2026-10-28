---
tags: [design, evaluation, leakage, gotcha]
---

# Point-in-Time Pinning

Cutoff signals must contain only what was known at the cutoff (snapshot − 180 days).
See [[risk-scoring-design]].

## Git-hosted feeds (Vulnrichment, Metasploit, Nuclei)

- **Gotcha:** GitHub's commits API `until=` filters by committer date over every commit
  reachable from the branch. A PR commit made before the cutoff but merged after it is
  returned, and its tree contains files that weren't on the branch at the cutoff.
- **Fix (`sources/github.py`):** a treeless, shallow clone (`--filter=tree:0
  --shallow-since=<cutoff-60d>`, commit objects only, ~1 s) and
  `git rev-list -1 --first-parent --before=<end of day>`: the branch head at that time.
- Tested with a local repo where a feature commit dated before the cutoff is merged after.
- **Gotcha (2026-10-28):** `--shallow-since` cuts by commit date, not along first-parent
  history. Metasploit has a merge (PR #19369, 2024-11-07) whose first parent is older than
  the 60-day margin, so the walk ended there and 2024-11-05 found no commit. `head_at` now
  retries with 365- and 1095-day margins. A shallow cut only loses commits, so a miss is an
  error, never a wrong pin.

## GitLab (ExploitDB)

- Commits API with `first_parent=true&until=...` for the same reason. Two copies of
  `files_exploits.csv`: cutoff and snapshot. Features come from the cutoff copy only.

## Other sources

- EPSS: dated daily file; fallback only goes to *earlier* days. `cti enrich` refuses a
  cutoff whose EPSS score date isn't exactly snapshot − k·180 d, so a fallback can't
  silently shift a window.
- Vulnrichment: per-record timestamps are overwritten on rescoring, so only git history works.
- NVD: snapshot-time records; reference tags and `cisa*` fields are dropped.

Related: [[ingest-once-snapshot]], [[data-sources]].
