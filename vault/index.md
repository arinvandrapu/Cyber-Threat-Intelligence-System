---
tags: [index]
---

# Vault Index

Map of notes. Every topic note is linked from here.
Current status and next steps: `tasks/session-handoff.md`.
Public, reader-facing docs: `docs/architecture.md`, `docs/decisions.md`.

## Design decisions

- [[ingest-once-snapshot]] — single ingest, raw snapshot, offline parsing, refetch rules
- [[data-sources]] — feeds, access method, keys, licensing constraints
- [[risk-scoring-design]] — why tiers must discriminate; forward-looking KEV evaluation;
  Phase 4 per-CVE join (`features_at` only, label-biased `context_snapshot`)
- [[gold-set-provenance]] — the classification gold set is rule-generated; how results are reported
- [[point-in-time-pinning]] — how cutoff-date data is pinned without leakage
- [[nlp-design]] — where NLP applies; SecureBERT 2.0 vs scikit-learn roles; evaluation;
  Phase 4 reference corpus (`cti enrich`: trafilatura cleaning, `js_shell`/`pdf_skipped`
  flags, why the 25%/own-CVE fallback checks were dropped)

## Code

- [[code-layout]] — package modules, test and CI conventions

## Security & cloud

- [[aws-cost-and-security]] — S3-only footprint, bucket hardening, `cti` profile, budget
- [[s3-archive-not-live-store]] — why S3 is a write-once archive, not the working store (vs capstone)
- [[ssrf-safe-fetching]] — how the reference scraper avoids SSRF
