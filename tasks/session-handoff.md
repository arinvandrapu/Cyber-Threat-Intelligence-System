# Session Handoff

**Last session:** 2026-10-26. **Read this first, then `tasks/todo.md` and `tasks/lessons.md`.**

## Where we are

| Phase | Status | PR |
|---|---|---|
| 0. Docs (README, plan, vault) | ✅ merged | #1, #2 |
| 1. Foundation + core (config, HTTP, SSRF fetcher, storage, snapshot) | ✅ merged | #3, #4 |
| 2a. Source fetchers + parsers + `cti` CLI | ✅ merged | #5, #6 |
| 2b. Reference scraper, frozen gold set, data contract | ✅ merged | #7 |
| 3. AWS setup + the one ingest | ✅ done 2026-10-26 | #9, #11 |
| **4. Enrichment** | **⏭ next** | — |
| 5–9 | not started | — |

`main` is green (193 offline tests, CI on Python 3.12 + 3.14). **The one ingest has run** (snapshot `2026-10-26`).

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

## Pick up here: Phase 4 (enrichment, all offline, no AWS)

- Content cleaner for scraped pages (navigation boilerplate); PDF text extraction
  (`pypdf`, page/size limits); CWE/KEV/EPSS/ExploitDB joins onto CVEs.
- Inputs: `data/snapshots/2026-10-26/` (raw) and `data/processed/2026-10-26/` (parsed).
- Outputs go under `data/enriched/<date>/` (local only; see `vault/s3-archive-not-live-store.md`).

## Local state that is NOT in git

| What | Where | Notes |
|---|---|---|
| abuse.ch key, contact, bucket, profile | `.env` | gitignored |
| Gold fixture | `data/gold/gold.jsonl.gz` | SHA-256 `4a612d2f…ceb5` (in `cti/gold.py`); also in S3 `gold/` |
| **Snapshot + parsed data** | `data/snapshots/2026-10-26/`, `data/processed/2026-10-26/` | working copy; raw also in S3. **Don't delete `data/`.** |
| Python venv | `.venv/` | `python3 -m venv .venv && .venv/bin/pip install -c requirements.lock -e '.[dev]'` to rebuild |
| AWS CLI | `default` = owner's admin IAM user, us-east-1; `cti` = pipeline user | `cti` key in `~/.aws/credentials`, **Inactive** |

The prototype repo used for porting was a temporary clone. If it's needed again:
`git clone https://github.com/YussefAlta/ML-Threat-Intelligence-System` (reference commit `faa35b3`).

## Resume commands

```bash
cd ~/Projects/Threat-Intel-Project
git checkout main && git pull
.venv/bin/pytest -q          # expect 193 passed
.venv/bin/cti status --date 2026-10-26   # all 12 complete
```

## Open items for later phases

- Phase 4: content cleaner (scraped pages still contain navigation boilerplate), PDF
  text extraction (`pypdf`, page/size limits), CWE/KEV/EPSS joins.
- Phase 5: confirm the SecureBERT 2.0 **base** model ID for embeddings
  (`cisco-ai/SecureBERT2.0-NER` is confirmed); confirm MITRE CTID CVE→ATT&CK mapping
  coverage for grading.
- Phase 7: features from `as_of="cutoff"` only; see `vault/risk-scoring-design.md`.

## Working agreements (from the owner)

- Every change goes through a PR; the **owner merges**. Never push to `main`.
- Run the implementation audit **before** opening a PR (the owner merges quickly).
- Check `gh pr view <n> --json state` before pushing to an existing PR branch.
- README describes the project only; no mention of its origins.
- Ingest runs **once**. S3 is the only AWS service. Keep cost low.
