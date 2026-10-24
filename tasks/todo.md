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

## Data contract

What the one ingest must capture (finalized in Phase 2 before the real run):

| Source | What | How | Key |
|---|---|---|---|
| NVD | CVE records + reference URLs, bounded publish window (proposed: 2024-01-01 → snapshot) | Yearly CVE 2.0 JSON feeds (`.json.gz`) | none |
| CISA KEV | Full catalog incl. `dateAdded` | JSON feed | none |
| EPSS | Scores at snapshot date **and** at cutoff date (snapshot − 180 days), model version recorded | Bulk CSV | none |
| ExploitDB | Exploit index with CVE codes | `files_exploits.csv` | none |
| MITRE ATT&CK | Enterprise STIX 2.1 bundle, pinned version (v20.0) | attack-stix-data | none |
| MITRE CWE | Catalog, pinned version (4.20) | XML zip | none |
| CISA Vulnrichment | SSVC (exploitation, automatable, technical impact) at **cutoff** and snapshot | Archive of the last `develop` commit before each date (pinned SHA; extract SSVC fields only, drop the ADP KEV block) | none |
| Metasploit | `db/modules_metadata_base.json` at cutoff and snapshot (CVE refs, `disclosure_date`; ignore `mod_time`) | File at pinned commit | none |
| Nuclei templates | `cves.json` (JSONL) at cutoff and snapshot; drop `kev`/`epss` tags | File at pinned commit | none |
| ThreatFox | IOC export (last 6 months), `full.csv.zip` | abuse.ch v2 export (key in URL path) | free abuse.ch Auth-Key |
| URLhaus | Malicious URLs (last 30 days), `recent.csv` | abuse.ch v2 export (key in URL path) | same key |
| Reference pages | Scraped text for a bounded CVE subset (proposed: KEV CVEs + top EPSS, capped ~2,000 pages) | SSRF-safe fetcher | none |

Git-hosted sources are pinned by commit SHA in the manifest, so the exact state can
always be re-derived. Only the extracted fields are stored, which keeps the bucket small.

Before the real run: smoke-test each source with small limits, confirm keys work, and
get owner approval.

## Phases

- [x] **0. Docs** — README, this build plan, lessons file, `vault/` design notes.
- [x] **1. Foundation + core** — `pyproject.toml` (pinned deps, extras), `src/cti/`
      layout, pytest/ruff/CI (tests, lint, pip-audit, secret scanning), typed config,
      HTTP client (retry on 429/5xx only, rate limiter), SSRF-safe fetcher with tests
      (redirects, private/link-local/IPv6/decimal/octal IPs, non-http schemes),
      `Document` model, storage backends (local + S3), snapshot manifest.
- [ ] **2a. Sources** — fetch + offline parse for all 11 sources, `cti` CLI
      (probe/ingest/status/parse), resume and logged refetch, defanging. *(in review)*
- [ ] **2b. Scraper + gold set + contract sign-off** — reference scraper, gold fixture,
      final data contract.
- [ ] ~~**2. Sources + data contract**~~ (split into 2a/2b above) — one module per source fetching raw data and an
      offline parser to `Document`s; recorded-fixture tests; IOC defanging; reference
      scraper (robots.txt, honest UA); finalize the data contract; gold-set fixture
      (frozen text + labels, deduplicated, defanged, checksummed, kept private).
- [ ] **3. AWS setup + the one ingest** — budget alert, bucket (Block Public Access,
      ACLs disabled, TLS-only policy, versioning + lifecycle), `cti` IAM policy in
      `infra/`, `cti probe`, then the single real ingest to local disk (owner approves
      first), `cti parse` to validate, then `cti upload` to S3.
- [ ] **4. Enrichment** — reference-link classifier, content cleaner, CWE lookup,
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
