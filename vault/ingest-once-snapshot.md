---
tags: [design, ingest, data]
---

# Ingest Once: Raw Snapshot

The full data pull runs **exactly once**. Everything downstream reads the snapshot.

## Rules

- `cti ingest` writes raw source responses **unmodified** (gzip'd) plus a manifest:
  source, URL, fetch time, byte size, SHA-256, source version (e.g. ATT&CK v20.0,
  EPSS model version).
- Parsing to `Document`s is a separate offline step, so a parser bug means re-parse,
  not re-fetch.
- A second `cti ingest` is refused if a manifest exists. The only exception is
  `--refetch <source>`, which is recorded in the manifest with a reason.
- Tests use recorded fixtures; CI has no network access to feeds.

## Where it runs

- From the owner's laptop: `cti ingest` downloads directly from each source into local
  `data/snapshots/<date>/`. Nothing is downloaded twice: after `cti parse` validates the
  snapshot, `cti upload` (Phase 3) copies it to the private S3 bucket.
- `cti probe` does a cheap reachability/key check first, so there is no separate smoke
  download.
- `references` runs last: it chooses pages from NVD/KEV/EPSS already in the snapshot
  and stores the target list (`targets.json.gz`) next to the page shards. A crash
  mid-scrape means `--resume` re-scrapes everything under a new attempt (~10–15 min);
  the partial shards stay as orphaned, logged entries.
- Per-source completion is recorded in the manifest. `--resume` skips completed sources
  and re-fetches a partially written one under a new logged attempt.
- No AWS compute. S3 cost at this size is cents per month.

## Implementation (`src/cti/snapshot.py`)

- `Snapshot.create` fails with `SnapshotExistsError` if any key exists for that date.
- Raw keys: `<id>/raw/<source>/<attempt>/<name>`, written with no-overwrite
  (S3 `IfNoneMatch: *`). Only `manifest.json` is rewritten.
- Retries are safe: `put_once` accepts identical bytes already stored and rejects
  different bytes. `MirroredStorage` uses it so a write that reached local disk but not
  S3 completes S3 on retry. `create` writes the manifest with no-overwrite, so two
  racing ingests can't both succeed. Snapshot ids must be real dates (`fullmatch`; a
  trailing `\n` once slipped through `re.match` + `$`).
- `begin_refetch(source, reason)` logs the reason and bumps the attempt number;
  old attempts are kept. Reads verify SHA-256.
- Storage has no delete operation at all.

## Why

- Keeps API usage and cost minimal and the dataset reproducible.
- Point-in-time data (EPSS at a cutoff date, KEV `dateAdded`) is what makes the
  [[risk-scoring-design]] evaluation honest; it must be captured in the same run.

## Consequences

- Anything a later phase needs must be listed in the data contract
  (`tasks/todo.md`) **before** the real run, including scraped reference pages.
- Smoke-test every source with small limits first; owner approves the real run.
- Storage location: [[aws-cost-and-security]]; why S3 is only an archive:
  [[s3-archive-not-live-store]]. Sources: [[data-sources]].

## The 2026-10-26 run

- Ingest ran once (≈ 25 min, 202 MB, all 12 sources complete). EPSS model differs
  between cutoff (v2025.03.14) and snapshot (v2026.06.15): don't compare scores across them.
- References attempt 1 lost 527 of 2,000 slots to CISA's KEV catalog page
  (`cisa.gov/known-exploited-vulnerabilities-catalog?search=…`): it restates the KEV feed
  and cisa.gov returns 403 to non-browser clients. The classifier now treats it as a
  self-reference (like NVD), and references was refetched as attempt 2 (logged in the
  manifest). Attempt 1 is kept as the audit trail.

## 2026-10-28: extra cutoffs (Phase 7a, owner approved)

- EPSS, ExploitDB, Metasploit, Nuclei, Vulnrichment refetched as attempt 2 with
  `cti ingest --refetch <src> --new-dates-only`: the attempt-1 `cutoff`/`snapshot` files
  are copied byte for byte (SHA-256 verified identical) and only `cutoff2..4` are fetched.
- Why not a plain refetch: re-pinning "head at end of 2026-10-26" two days later gives a
  newer commit than the 16:15 UTC ingest saw (Vulnrichment `46b2fff` vs `9b12f55`),
  which would silently change Phase 5/6 inputs.
- Design and positives: [[risk-scoring-design]]; pinning: [[point-in-time-pinning]].
