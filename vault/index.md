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
  and 5b-2 SecureBERT practice (pinning + weight hashes, CyNER labels, BPE span fixes, NER gold check)
- [[ioc-extraction]] — Phase 5a `cti extract`: IPv4-vs-version and code-vs-domain rules,
  offline PSL, alias matching guards, review-sample and gold-set evaluation
- [[risk-eval]] — Phase 7b `cti risk-eval`: rolling-origin folds, pre-registered features,
  models, metrics and tiers (`nlp/risk_config.py`)
- [[dashboard]] — Phase 8: Vite + React over `cti export` JSON, `cti serve` on
  127.0.0.1 with strict CSP, seven views incl. three relationship graphs
- [[dashboard-web]] — the `web/` UI: types contract, synthetic fixture, static and
  headless-Chrome CSP checks, CI job
- [[threat-catalog]] — `cti threats` implementation: inputs, owner sheets, first-run rules and counts
- [[threat-layer]] — Phase 10a: family categories (MISP galaxies, STIX
  malware types), CVE links, priority heuristic; abuse.ch §7.3 no-AI-training rule
- [[attack-mapping-v2-results]] — 10b run: combiner passes narrowly (+0.035 hit@5), gain from the CVSS rule at T1189
- [[attack-mapping-v2]] — Phase 10b (planned): fresh CTID `attack_to_cve` test,
  population-shift framing, shared-logistic combiner, CAPEC and CVSS data gaps
- [[cwe-classification]] — Phase 6 main eval: CWE label provenance (nvd/cna/adp), mapping
  Usage, label-source shift and name leakage that shape the evaluation; 6b `cti cwe-eval`
  pre-registered in `nlp/cwe_config.py`
- [[attack-mapping]] — Phase 5b `cti attack-eval`: CTID KEV ground truth (pinned, leaky
  fields dropped), dev/test split, technique-level metrics, baselines

## Code

- [[code-layout]] — package modules, test and CI conventions

## Security & cloud

- [[aws-cost-and-security]] — S3-only footprint, bucket hardening, `cti` profile, budget
- [[s3-archive-not-live-store]] — why S3 is a write-once archive, not the working store (vs capstone)
- [[ssrf-safe-fetching]] — how the reference scraper avoids SSRF
