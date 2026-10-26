---
tags: [design, aws, storage, decision]
---

# S3: Archive, Not Live Store

Decided 2026-10-26. Full write-up: `docs/decisions.md` (decision 2).

## Decision

- Ingest writes to local `data/snapshots/<date>/`; `cti parse` reads local.
- `cti upload` copies the validated raw snapshot + gold set to S3 once, write-once.
- No pipeline stage reads from S3. Processed output is not stored there.

## Prototype contrast (capstone)

- Capstone used S3 as the live store: each stage `put_object`'d output as it ran
  (`nist/cve/YYYY/MM/DD/`, `enriched/…`, `osint/corpus/`, `nlp/enriched/{date}/`) and the
  next stage `get_object`'d it back.
- No refetch guard, no manifest/checksums, overwrite allowed: results could not be tied
  to a fixed dataset.
- Shared bucket made sense there: 5 people, several machines.

## Why not here

- Single machine, local compute: S3 round trips add latency, request cost, network
  dependency, no benefit.
- Cost grows with requests/egress per iteration, not storage. Archive = one upload.
- Forward-looking KEV evaluation needs frozen point-in-time data
  ([[point-in-time-pinning]], [[risk-scoring-design]]).
- Credentials used only at upload time; cannot overwrite or delete.

## Revisit if

- Scheduled cloud ingest, multiple collaborators, or data outgrows a laptop. The key
  layout `<id>/raw/<source>/<attempt>/…` carries over unchanged.

Related: [[ingest-once-snapshot]], [[aws-cost-and-security]].
