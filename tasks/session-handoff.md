# Session Handoff

**Last session:** 2026-10-27. **Read this first, then `tasks/todo.md` and `tasks/lessons.md`.**

## Where we are

| Phase | Status | PR |
|---|---|---|
| 0. Docs (README, plan, vault) | ✅ merged | #1, #2 |
| 1. Foundation + core (config, HTTP, SSRF fetcher, storage, snapshot) | ✅ merged | #3, #4 |
| 2a. Source fetchers + parsers + `cti` CLI | ✅ merged | #5, #6 |
| 2b. Reference scraper, frozen gold set, data contract | ✅ merged | #7 |
| 3. AWS setup + the one ingest | ✅ done 2026-10-26 | #9, #11 |
| 4. Enrichment (CVE joins, reference cleaning) | ✅ merged | #14, #15 |
| 5a. Regex IOCs + aliases (`cti extract`) | ✅ merged | #17 |
| 5b-1. ATT&CK grading harness + baselines (`cti attack-eval`) | ✅ merged | #18 |
| 5b-2. SecureBERT NER + embeddings + prior+bi-encoder | ✅ PR open | — |
| **6. Classification + evaluation** | **⏭ next** | — |
| 6–9 | not started | — |

`main` is green (226 offline tests, CI on Python 3.12 + 3.14). **The one ingest has run** (snapshot `2026-10-26`).

## Phase 3 result (2026-10-26)

- AWS: $5 budget `cti-project-5usd` (account-wide), hardened bucket (name in `.env`),
  account-level Block Public Access, IAM user `cti` (write-once enforced by IAM). Setup
  steps: `infra/README.md`. **Owner priority: AWS cost at an absolute minimum.**
- Ingest: snapshot `2026-10-26`, all 12 sources complete. References refetched once
  (attempt 2: 1,653/2,000 pages, 1,043 CVEs; reason in the manifest, see
  `vault/ingest-once-snapshot.md`). `cti parse` OK for all sources.
- Uploaded: 37 raw files + manifest + gold (≈ 297 MB, 39 objects); remote SHA-256 of gold
  and manifest verified. **`cti` access key is now Inactive**; reactivate only if a refetch
  needs uploading (`aws iam update-access-key --user-name cti --status Active ...`).
- Noted for Phase 7: EPSS model differs between cutoff (v2025.03.14) and snapshot
  (v2026.06.15).

## Phase 4 result (2026-10-26)

- `cti enrich --date 2026-10-26` (≈2 min, offline) writes `data/enriched/2026-10-26/`:
  `cves.jsonl.gz` + `cves-summary.json`, `references.jsonl.gz` + `references-summary.json`
  (each summary carries the output's SHA-256; both outputs are byte-deterministic).
- **cves:** 168,393 rows; 102,772 eligible at the cutoff `2026-04-29`; 17 forward KEV
  positives (cutoff → snapshot); 0 unknown CWEs; CNA CVSS on 75.5%. Risk features come
  only through `features_at(record, "cutoff")`; `context_snapshot` (NVD status, CVSS,
  CWEs, references) is label-biased and only for a labelled ablation
  (`vault/risk-scoring-design.md`).
- **references:** 1,653 pages → **1,280 in the NLP corpus (842 CVEs)**; 366 `js_shell`,
  7 `pdf_skipped`; trafilatura 1,233, fallback 35; median 6.7k → 2.8k chars.
  The `enrich` extra (trafilatura, lxml) is required.
- Owner decisions: JS-rendered pages are flagged and excluded (no new fetching); PDFs
  skipped; the Phase 7 "17 positives" question is **deferred** (join already supports
  more `as_of` cutoffs).

## Phase 5a result (2026-10-27)

- `cti extract --date 2026-10-26` (≈1 min) → `data/extracted/2026-10-26/iocs.jsonl.gz`,
  `aliases.jsonl.gz` + summaries. `cti extract-eval` → `data/eval/2026-10-26/extract-eval.json`.
- Precision (200-item review sample, labels in `data/reference/`): pages 98.5%, NVD 89.1%.
  Weak spot: NVD IPv4 (version lists). Details and disclosures: `vault/ioc-extraction.md`.
- **Owner to do:** spot-check the assistant's labels. The review sheet with defanged
  context is `data/eval/2026-10-26/ioc-review-sample-seed20261027.csv` (local).
- Vault corrected: NVD description text is snapshot-time (KEV language), not a safe feature.

## Phase 5b result (2026-10-27)

- `cti attack-eval` (CTID KEV, test 2024+ n=132, exploitation): majority hit@5 0.41;
  bi-encoder alone 0.20; **prior + bi-encoder 0.57, +0.16 vs majority (0.10–0.23)**.
  β = 0.2 picked on dev only. Disclosed: the hybrid was designed after the zero-shot test
  results were seen. Details: `vault/attack-mapping.md`.
- `cti ner` (≈10 min) → `data/extracted/2026-10-26/entities.jsonl.gz`; noisy on code and
  tables, so displays use score ≥ 0.9 or alias-linked spans (`vault/nlp-design.md`).
- `cti embed` (≈47 min) → `nvd-embeddings.npy` (168,393 × 768 float16) + index with a
  `kev_language` flag (181 rows) for Phase 7.
- SecureBERT runs in `.venv-nlp/` (`requirements-nlp.lock`); weights are in the HF cache,
  pinned and re-hashed on load (`cti models verify`).

## Pick up here: Phase 6 (classification + evaluation)

- Plan first: SecureBERT-embedding classifier vs text rules vs baselines (majority,
  source-only, TF-IDF + LR) on the rule-generated gold set (a sanity check; see
  `vault/gold-set-provenance.md`). Reuse `nlp/embed.Encoder` and the paired-bootstrap
  helpers in `nlp/attack_eval.py`.
- Owner context: may present this project at a MITRE final-round interview, so keep every
  choice defensible and disclosed.

## Local state that is NOT in git

| What | Where | Notes |
|---|---|---|
| abuse.ch key, contact, bucket, profile | `.env` | gitignored |
| Gold fixture | `data/gold/gold.jsonl.gz` | SHA-256 `4a612d2f…ceb5` (in `cti/gold.py`); also in S3 `gold/` |
| **Snapshot, parsed, enriched data** | `data/snapshots/`, `data/processed/`, `data/enriched/` (all `2026-10-26`) | working copy; raw also in S3; parsed/enriched regenerable via `cti parse` / `cti enrich`. **Don't delete `data/`.** |
| Python venv | `.venv/` | `python3 -m venv .venv && .venv/bin/pip install -c requirements.lock -e '.[dev,enrich,ml]'` to rebuild |
| AWS CLI | `default` = owner's admin IAM user, us-east-1; `cti` = pipeline user | `cti` key in `~/.aws/credentials`, **Inactive** |

The prototype repo used for porting was a temporary clone. If it's needed again:
`git clone https://github.com/YussefAlta/ML-Threat-Intelligence-System` (reference commit `faa35b3`).

## Resume commands

```bash
cd ~/Projects/Threat-Intel-Project
git checkout main && git pull
.venv/bin/pytest -q          # expect 347 passed
.venv/bin/cti status --date 2026-10-26   # all 12 complete
```

## Open items for later phases

- Phase 7: features via `features_at(record, "cutoff")` only; decide whether 17 forward
  positives is enough or add more cutoffs (EPSS history is the main extra cost); EPSS model
  differs between cutoff and snapshot. See `vault/risk-scoring-design.md`.
- Phase 7: NVD descriptions are snapshot-time (35/549 KEV vs 46/~168k others carry
  "exploited in the wild" wording); report the text ablation with and without them.

## Working agreements (from the owner)

- Every change goes through a PR; the **owner merges**. Never push to `main`.
- Run the implementation audit **before** opening a PR (the owner merges quickly).
- Check `gh pr view <n> --json state` before pushing to an existing PR branch.
- README describes the project only; no mention of its origins.
- Ingest runs **once**. S3 is the only AWS service. Keep cost low.
