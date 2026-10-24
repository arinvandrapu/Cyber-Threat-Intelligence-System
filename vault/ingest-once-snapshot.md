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

## Why

- Keeps API usage and cost minimal and the dataset reproducible.
- Point-in-time data (EPSS at a cutoff date, KEV `dateAdded`) is what makes the
  [[risk-scoring-design]] evaluation honest; it must be captured in the same run.

## Consequences

- Anything a later phase needs must be listed in the data contract
  (`tasks/todo.md`) **before** the real run, including scraped reference pages.
- Smoke-test every source with small limits first; owner approves the real run.
- Storage location: [[aws-cost-and-security]]. Sources: [[data-sources]].
