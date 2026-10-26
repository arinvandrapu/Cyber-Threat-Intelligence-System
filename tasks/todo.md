# Build Plan — Cyber Threat Intelligence System

Phase-by-phase build. **One PR per phase**; each PR is reviewed and merged by the repo
owner before the next phase starts. Nothing is pushed to `main` directly.

## Ground rules

- **Ingest runs once.** A single `cti ingest` run captures everything later phases need
  (see the [data contract](#data-contract)). Raw source responses are stored unmodified;
  parsing into documents happens offline, so a parser bug means re-parsing, not re-fetching.
  Re-running is refused unless a specific source is re-fetched with `--refetch <source>`,
  which is logged in the snapshot manifest. Tests and CI never touch the network.
- **Low cost.** S3 is the only AWS service: one private bucket, S3 Standard, gzip'd files,
  well under 1 GB. No EC2, Lambda, SageMaker, KMS, or CloudTrail data events. Model
  inference runs locally on CPU. Budget alert is created before the bucket.
- **Least privilege.** The pipeline uses a dedicated `cti` AWS profile that can only
  read/write the one bucket and cannot delete objects. Bucket setup is a separate,
  one-time admin step. No credentials in code, `.env` files, or the repo.
- **Licensing.** Raw feed data is never committed to this public repo (abuse.ch,
  ExploitDB, and others restrict redistribution). Only code, aggregates, and small
  defanged samples are published.
- **Prioritization must discriminate.** Risk tiers are only useful if few items land at
  the top. Tier thresholds come from a forward-looking evaluation (Phase 7), and the
  per-tier distribution and hit rate are reported.
- **Honest metrics.** Every number in the README is produced by a script in the repo.
  No hardcoded results. Evaluation limitations are stated plainly.
- **Security posture.** SSRF-safe fetching, a single honest User-Agent, robots.txt
  respected, API keys in headers (never URLs), live IOCs defanged at rest and in display.

## Data contract (signed off in Phase 2b)

What the one ingest captures. Dates: **snapshot** = ingest day; **cutoff** = snapshot − 180 days.
"Both" = two copies, pinned to the source's state at the cutoff and at the snapshot.

| Source | Captured | Pinned by | Key | Est. size (gz) |
|---|---|---|---|---|
| NVD | Yearly CVE 2.0 feeds, 2023 → snapshot year; parse keeps CVEs published ≥ 2024-01-01 | `.meta` SHA-256 + `lastModifiedDate` | none | ~120 MB |
| CISA KEV | Full catalog incl. `dateAdded` | `catalogVersion` | none | <1 MB |
| EPSS | Daily scores, both dates | file date + model version | none | ~6 MB |
| ExploitDB | `files_exploits.csv`, both | GitLab first-parent commit | none | ~4 MB |
| Metasploit | `modules_metadata_base.json`, both | git first-parent commit | none | ~3 MB |
| Nuclei | `cves.json`, both | git first-parent commit | none | ~1 MB |
| CISA Vulnrichment | SSVC extract, both | git first-parent commit | none | ~2 MB |
| MITRE ATT&CK | Enterprise v20.0 STIX bundle | release version | none | ~5 MB |
| MITRE CWE | v4.20 XML | release version | none | ~2 MB |
| ThreatFox | IOCs, last 6 months (`full.csv.zip`) | fetch time | abuse.ch | ~10 MB |
| URLhaus | URLs, last 30 days (`recent.csv`) | fetch time | abuse.ch | ~5 MB |
| Reference pages | ≤ 2,000 pages (KEV CVEs first, then top EPSS; ≤ 3 per CVE, 1 per host) | fetch time + target list | none | ~70 MB |
| Gold set | 299 docs (frozen once, separate from the snapshot) | SHA-256 in `cti/gold.py` | n/a | <1 MB |

Total ≈ 250 MB → S3 Standard ≈ $0.01/month. Raw feed data never enters the repo.

Run order: `cti probe` → `cti ingest` (references runs last; it needs NVD, KEV, EPSS) →
`cti status` → `cti parse` → upload (Phase 3).

## Phases

- [x] **0. Docs** — README, this build plan, lessons file, `vault/` design notes.
- [x] **1. Foundation + core** — `pyproject.toml` (pinned deps, extras), `src/cti/`
      layout, pytest/ruff/CI (tests, lint, pip-audit, secret scanning), typed config,
      HTTP client (retry on 429/5xx only, rate limiter), SSRF-safe fetcher with tests
      (redirects, private/link-local/IPv6/decimal/octal IPs, non-http schemes),
      `Document` model, storage backends (local + S3), snapshot manifest.
- [x] **2a. Sources** — fetch + offline parse for all 11 sources, `cti` CLI
      (probe/ingest/status/parse), resume and logged refetch, defanging.
- [x] **2b. Scraper + gold set + contract sign-off** — reference classifier (ported),
      target selection, SSRF-safe + robots-respecting scraper, `cti gold-import`
      (frozen, checksummed), data contract above.
- [ ] ~~**2. Sources + data contract**~~ (split into 2a/2b above) — one module per source fetching raw data and an
      offline parser to `Document`s; recorded-fixture tests; IOC defanging; reference
      scraper (robots.txt, honest UA); finalize the data contract; gold-set fixture
      (frozen text + labels, deduplicated, defanged, checksummed, kept private).
- [x] **3. AWS setup + the one ingest** — *(done 2026-10-26: snapshot `2026-10-26`, references refetched once, uploaded)* budget alert, bucket (Block Public Access,
      ACLs disabled, TLS-only policy, versioning + lifecycle), `cti` IAM policy in
      `infra/`, `cti probe`, then the single real ingest to local disk (owner approves
      first), `cti parse` to validate, then `cti upload` to S3.
- [ ] **4. Enrichment** — *(4a per-CVE join merged #14; 4b reference cleaning in review)* reference-link classifier, content cleaner, CWE lookup,
      KEV/EPSS/ExploitDB joins onto CVEs.
- [ ] **5. NLP extraction** — regex for structured IOCs (correct IPv4 boundaries, strict
      CVSS patterns); **SecureBERT 2.0 NER** (`cisco-ai/SecureBERT2.0-NER`, local CPU
      batch) for malware, products, and organizations; alias normalizer; ATT&CK
      technique mapping via SecureBERT embeddings, graded against MITRE CTID
      CVE→ATT&CK mappings (verify availability). Tests for all.
- [ ] **6. Classification + evaluation** — SecureBERT-embedding classifier vs
      text-only rules vs baselines (majority, source-only, TF-IDF + logistic regression),
      evaluation script. Gold set is rule-generated, so its result is reported as a
      sanity check next to the source-only baseline, with that limitation disclosed.
- [ ] **7. Risk scoring** — scikit-learn model over CVSS, EPSS, SSVC, exploit
      availability (ExploitDB, Metasploit, Nuclei), recency, and SecureBERT text features;
      ablation with vs without the text features.
      Forward-looking evaluation: score with cutoff-date data only, measure which CVEs
      were added to KEV after the cutoff; precision@k and PR-AUC vs CVSS-only and
      EPSS-only baselines. Tier thresholds set from these results.
- [ ] **8. Dashboard** — Next.js 16 static export served on 127.0.0.1, reading
      pipeline-exported JSON; ~4 views (overview, prioritized CVEs, IOCs, evaluation);
      defanged IOCs; no hardcoded metrics.
- [ ] **9. Security deliverables + polish** — STRIDE threat model of the pipeline,
      STIX 2.1 export, a sample analyst-style intel report, SBOM, dashboard screenshots,
      limitations section, final README.

Stretch (only if time allows): relation extraction,
detection-rule generation, a small hand-labeled evaluation set.

## Review

_(filled in as phases complete)_
