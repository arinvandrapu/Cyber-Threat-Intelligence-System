# Session Handoff

**Last session:** 2026-10-27 → 10-28 (Phases 5 and 6). **Read this first, then `tasks/todo.md` and `tasks/lessons.md`.**

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
| 5b-2. SecureBERT NER + embeddings + prior+bi-encoder | ✅ merged | #19 |
| 6a. CWE label provenance | ✅ merged | #21 |
| 6b. `cti cwe-eval` (CWE classification) | ✅ merged | #22 |
| CI: cancel superseded PR runs | ✅ merged | #20 |
| 7a. Extra cutoffs (rolling-origin data) | ✅ merged | #24, #25 |
| 7b. Risk scoring evaluation (`cti risk-eval`) | ✅ PR open | #26 |
| **8. Dashboard** | **⏭ next** | — |
| 9 | not started | — |

`main` is green (388 offline tests on the 7b branch, CI on Python 3.12 + 3.14; `nlp` lock audited in CI, not
installed). **The one ingest has run** (snapshot `2026-10-26`).

**Next session, in order:**
1. `git checkout main && git pull`, then read this file, `tasks/lessons.md`, `tasks/todo.md`.
2. Start Phase 8 (dashboard) with the staged pipeline. It reads pipeline-exported JSON
   only; it needs a scoring export (current-snapshot scores + tiers) designed first.
3. Owner context: may present this project at a MITRE final-round interview. Offer mock
   Q&A on the ATT&CK, CWE and risk results when asked.

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
- Owner spot-checked the assistant's labels (2026-10-28): fine. Review sheet:
  `data/eval/2026-10-26/ioc-review-sample-seed20261027.csv` (local).
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

## Phase 6 result (2026-10-27)

- `cti cwe-eval` (≈8 min, `ml` extra): headline test name-absent macro-F1 TF-IDF + LR
  0.394, SecureBERT embeddings + LR 0.265 (paired −0.13), centroid 0.14, majority 0.002.
  Pre-registered in `nlp/cwe_config.py` (`2e69e14`). Both ch## Phase 7a result (2026-10-28)

- Owner decisions: rolling-origin evaluation over four 180-day cutoffs; EPSS from each
  cutoff's file only (percentile, model version per fold, disclosed); text features only
  in a labelled ablation (with/without the 181 `kev_language` rows). IOC review labels
  spot-checked by the owner: fine.
- Refetch (`--refetch <src> --new-dates-only`, attempt 2 for epss/exploitdb/metasploit/
  nuclei/vulnrichment): attempt-1 dated files copied byte-identical; `cutoff2..4` fetched.
  `cti parse` + `cti enrich --only cves` rerun; existing cutoff/snapshot numbers unchanged.
- Forward KEV positives: cutoff4 (2024-11-05) 20, cutoff3 (2025-05-04) 21, cutoff2
  (2025-10-31) 30, cutoff (2026-04-29) 17 → **68 in rolling test windows**. Table:
  `vault/risk-scoring-design.md`. cutoff4 uses EPSS v3 (v2023.03.01).
- Uploaded to S3 2026-10-28 with owner approval: 25 new objects (38.0 MB), 37 already
  present; remote manifest SHA-256 matches local (63 objects, ≈335 MB). `cti` key is
  **Inactive** again.

## Phase 7b result (2026-10-28)

- Pre-registered `nlp/risk_config.py` (`c528d07`, pushed before scoring) after external +
  internal due diligence and a plan audit (12 required changes applied). Implementation
  `1ff8527` (clean tree) after an implementation audit; run once, ≈30 s.
- Pooled over 3 folds (68 positives), hits in top 100: logistic 6, boosting 8, EPSS 2.
  Decision rule met: +4 (CI +1 to +8). Not at 1% (+1, CI −6 to +9); EPSS higher mean AP.
  Tiers monotonic (critical 2.6%). No-EPSS ablation catches 9. Details:
  `vault/risk-eval.md`, README section.

## Pick up here: Phase 8 (dashboard)

- Next.js static export on 127.0.0.1 reading pipeline-exported JSON (`tasks/todo.md`).
  First design a `cti export` step: current-snapshot risk scores + tiers (model refit on
  all windows; EPSS v2026.06.15 at the snapshot differs: disclose), IOCs, eval summaries.
- Owner context: may present this project at a MITRE final-round interview.

## Local state that is NOT in git

| What | Where | Notes |
|---|---|---|
| abuse.ch key, contact, bucket, profile | `.env` | gitignored |
| Gold fixture | `data/gold/gold.jsonl.gz` | SHA-256 `4a612d2f…ceb5` (in `cti/gold.py`); also in S3 `gold/` |
| **Snapshot, parsed, enriched data** | `data/snapshots/`, `data/processed/`, `data/enriched/` (all `2026-10-26`) | working copy; raw also in S3; parsed/enriched regenerable via `cti parse` / `cti enrich`. **Don't delete `data/`.** |
| Python venv | `.venv/` | `python3 -m venv .venv && .venv/bin/pip install -c requirements.lock -e '.[dev,enrich,ml]'` to rebuild |
| **Extracted + eval outputs** | `data/extracted/2026-10-26/` (iocs, aliases, entities, `nvd-embeddings.npy` ≈259 MB, masked subset), `data/eval/2026-10-26/` (extract-, attack-, ner-, cwe-eval JSON) | regenerable; `cti embed` takes ≈47 min, so keep the `.npy` |
| SecureBERT env + models | `.venv-nlp/` (`requirements-nlp.lock`); weights in `~/.cache/huggingface/hub/` (pinned; `cti models verify`) | rebuild: `python3 -m venv .venv-nlp && .venv-nlp/bin/pip install -c requirements-nlp.lock -e '.[dev,enrich,ml,nlp]'` |
| AWS CLI | `default` = owner's admin IAM user, us-east-1; `cti` = pipeline user | `cti` key in `~/.aws/credentials`, **Inactive** |

The prototype repo used for porting was a temporary clone. If it's needed again:
`git clone https://github.com/YussefAlta/ML-Threat-Intelligence-System` (reference commit `faa35b3`).

## Resume commands

```bash
cd ~/Projects/Threat-Intel-Project
git checkout main && git pull
.venv/bin/pytest -q          # expect 358 passed
.venv/bin/cti status --date 2026-10-26   # all 12 complete
```

## Open items for later phases

- Phase 8: scoring the live snapshot uses EPSS v2026.06.15, unseen in training; tiers are
  rank fractions, so they transfer, but say so on the dashboard.

## Working agreements (from the owner)

- Every change goes through a PR; the **owner merges**. Never push to `main`.
- Run the implementation audit **before** opening a PR (the owner merges quickly).
- Check `gh pr view <n> --json state` before pushing to an existing PR branch.
- README describes the project only; no mention of its origins.
- Ingest runs **once**. S3 is the only AWS service. Keep cost low.
