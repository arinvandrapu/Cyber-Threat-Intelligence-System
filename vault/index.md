---
tags: [index]
---

# Vault Index

Map of notes. Every topic note is linked from here.

## Design decisions

- [[ingest-once-snapshot]] — single ingest, raw snapshot, offline parsing, refetch rules
- [[data-sources]] — feeds, access method, keys, licensing constraints
- [[risk-scoring-design]] — why tiers must discriminate; forward-looking KEV evaluation
- [[gold-set-provenance]] — the classification gold set is rule-generated; how results are reported
- [[nlp-design]] — where NLP applies; SecureBERT 2.0 vs scikit-learn roles; evaluation (proposed)

## Security & cloud

- [[aws-cost-and-security]] — S3-only footprint, bucket hardening, `cti` profile, budget
- [[ssrf-safe-fetching]] — how the reference scraper avoids SSRF
