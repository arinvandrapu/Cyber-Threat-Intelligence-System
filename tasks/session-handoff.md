# Session Handoff

**Last session:** 2026-10-26. **Read this first, then `tasks/todo.md` and `tasks/lessons.md`.**

## Where we are

| Phase | Status | PR |
|---|---|---|
| 0. Docs (README, plan, vault) | ✅ merged | #1, #2 |
| 1. Foundation + core (config, HTTP, SSRF fetcher, storage, snapshot) | ✅ merged | #3, #4 |
| 2a. Source fetchers + parsers + `cti` CLI | ✅ merged | #5, #6 |
| 2b. Reference scraper, frozen gold set, data contract | ✅ merged | #7 |
| **3. AWS setup + the one ingest** | **🟡 AWS + upload done; ingest next** | #9 |
| 4–9 | not started | — |

`main` is green (176 offline tests, CI on Python 3.12 + 3.14). **No real ingest has run yet.**

## Phase 3 status (2026-10-26)

Done and verified live: $5 budget `cti-project-5usd` (account-wide), bucket
(name in `.env`, `CTI_S3_BUCKET`) hardened per `infra/README.md`, account-level Block Public
Access, IAM user `cti` + local profile `cti` (write-once enforced by IAM), `.env` has
`CTI_S3_BUCKET` and `CTI_AWS_PROFILE=cti`. `cti upload` code in PR #9.

**Remaining:** the one ingest (owner approves the moment), then `cti upload --date D --gold`,
then deactivate the `cti` access key. **Owner priority: AWS cost at an absolute minimum.**

## Original Phase 3 plan (for reference)

1. **Bucket name.** Ask the owner; suggest `cti-snapshots-<random suffix>` (globally unique).
2. **Budget alert first:** AWS Budgets, $5/month, actual + forecast, email alert. Also
   enable Cost Anomaly Detection (free).
3. **Bucket:** us-east-1, Block Public Access on, ACLs disabled (bucket owner enforced),
   SSE-S3 default, bucket policy denying `aws:SecureTransport=false`, versioning on with
   lifecycle (expire noncurrent versions, remove expired delete markers, abort incomplete
   multipart after 1 day). No KMS, no CloudTrail data events.
4. **`cti` principal:** Get/Put/List on that bucket only, explicit Deny `s3:DeleteObject*`.
   Local AWS profile `cti`. Policy JSON goes in `infra/` (no account ID or bucket name
   committed). Setup runs with the owner's admin profile, never root.
5. **Code still needed for Phase 3** (one PR, audit before opening):
   - `cti upload --date D` (copy the local snapshot to S3 with `put_once`, verify checksums)
     and gold upload to `gold/`.
   - `infra/` policy templates and a setup README.
   - Set `CTI_S3_BUCKET` in `.env`.
6. **The one ingest** (owner approves the moment): `cti probe` → `cti ingest` (today's
   date; about 20–30 min, mostly the reference scrape) → `cti status` → `cti parse` → `cti upload`.

## Local state that is NOT in git

| What | Where | Notes |
|---|---|---|
| abuse.ch key + contact | `.env` | gitignored; `cti probe` passed for all 11 sources on 2026-10-24 |
| **Gold fixture (only copy)** | `data/gold/gold.jsonl.gz` | SHA-256 `4a612d2f…ceb5` (in `cti/gold.py`). **Don't delete `data/`.** Upload in Phase 3. |
| Python venv | `.venv/` | `python3 -m venv .venv && .venv/bin/pip install -c requirements.lock -e '.[dev]'` to rebuild |
| AWS CLI | `default` = owner's admin IAM user, us-east-1; `cti` = pipeline user | `cti` key in `~/.aws/credentials`; deactivate after upload |

The prototype repo used for porting was a temporary clone. If it's needed again:
`git clone https://github.com/YussefAlta/ML-Threat-Intelligence-System` (reference commit `faa35b3`).

## Resume commands

```bash
cd ~/Projects/Threat-Intel-Project
git checkout main && git pull
.venv/bin/pytest -q          # expect 176 passed
.venv/bin/cti probe          # expect 11 x OK
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
