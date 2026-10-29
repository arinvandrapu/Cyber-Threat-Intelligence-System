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
- [x] **4. Enrichment** — *(4a per-CVE join #14; 4b reference cleaning #15)* reference-link classifier, content cleaner, CWE lookup,
      KEV/EPSS/ExploitDB joins onto CVEs.
- [x] **5. NLP extraction** — regex for structured IOCs (correct IPv4 boundaries, strict
      CVSS patterns); **SecureBERT 2.0 NER** (`cisco-ai/SecureBERT2.0-NER`, local CPU
      batch) for malware, products, and organizations; alias normalizer; ATT&CK
      technique mapping via SecureBERT embeddings, graded against MITRE CTID
      CVE→ATT&CK mappings (verify availability). Tests for all.
      *Plan (audited 2026-10-27; owner decisions: CTID file committed under
      `data/reference/`, one-time model download approved, IOC sample labelled by an AI
      assistant and disclosed):*
  - [x] **5a. `cti extract`** *(2026-10-27; see `vault/ioc-extraction.md`)* — regex IOCs on original-text offsets (strict IPv4,
        IPv6 via `ipaddress`, defanged forms, domains via tldextract's bundled PSL with no
        network plus a code-extension denylist, URLs, hashes, CVE IDs, CVSS v3.x/v4.0 grammar);
        `refang` extended, with an invariant test; alias normalizer (ATT&CK v20 + ThreatFox,
        ambiguous aliases return every candidate). Rows tagged `origin`; NVD-origin IOCs kept
        out of headline counts. Eval: a seeded, stratified 200-IOC precision sample; gold P/R
        for `cve_id`/`domain` only (gold CVSS spans counted as label errors); no alias P/R
        on gold (circular).
  - [x] **5b. SecureBERT + ATT&CK** *(5b-1 grading harness #18; 5b-2 SecureBERT NER,
        embeddings, prior+bi-encoder mapping 2026-10-27; `vault/attack-mapping.md`)* — `ml` extra (numpy, sklearn; in CI) and `nlp` extra
        (torch, transformers `<6`; not in CI, lock audited with `pip-audit --no-deps`).
        `cti models fetch` (pinned revisions, safetensors only, no `trust_remote_code`).
        NER on the reference corpus + CTID subset (pipeline stride, fragment merge).
        Bi-encoder embeddings for all NVD descriptions and active v20 techniques.
        KEV-language leakage flag on descriptions (35/549 KEV vs 46/~168k non-KEV).
        ATT&CK mapping graded on CTID KEV attack-16.1: dev set = 284 out-of-corpus CVEs,
        test set = 135 in-corpus CVEs; primary metric hit@5/recall@5 on
        `exploitation_technique` at technique level, with bootstrap CIs vs majority and
        TF-IDF baselines; selection bias and pretraining contamination disclosed.
- [x] **6. Classification + evaluation** — *re-scoped 2026-10-27 (owner): the gold set's
      primary label equals its source feed for 298/299 docs, so the main evaluation is CWE
      classification of NVD descriptions (human labels); see `vault/cwe-classification.md`.*
  - [x] **6a. Label provenance** — parser keeps who assigned each CWE by role (nvd/cna/cisa_adp/other_adp,
        Primary/Secondary); CWE catalog keeps MITRE's mapping `Usage`.
  - [x] **6b. `cti cwe-eval`** *(2026-10-27: TF-IDF+LR 0.394 vs SecureBERT+LR 0.265 macro-F1)* — choices committed before test scoring; labels NVD > CNA >
        CISA-ADP, single-label; time split (train 2024–25, dev to the 2026-04-29 cutoff, test
        after); 118 classes (≥50 train) + other; headline = macro-F1 on the name-absent test
        stratum; majority / TF-IDF+LR / SecureBERT+LR / nearest centroid; C on dev, refit
        train+dev; bootstrap + paired CIs; breakdowns by label source and assigner. Gold set:
        one circular sanity row (source-only vs TF-IDF).
- [x] **7. Risk scoring** — scikit-learn model over CVSS, EPSS, SSVC, exploit
      availability (ExploitDB, Metasploit, Nuclei), recency, and SecureBERT text features;
      ablation with vs without the text features.
      Forward-looking evaluation: score with cutoff-date data only, measure which CVEs
      were added to KEV after the cutoff; precision@k and PR-AUC vs CVSS-only and
      EPSS-only baselines. Tier thresholds set from these results.
      *Owner decisions 2026-10-28: rolling-origin evaluation over four 180-day cutoffs;
      EPSS features from each cutoff's file only (percentile, model version recorded and
      disclosed); text features only in a labelled ablation (with and without the 181
      `kev_language` rows), never in the headline model.*
  - [x] **7a. Extra cutoffs** *(2026-10-28: fetched; 20/21/30/17 positives)* — pin EPSS, ExploitDB, Metasploit, Nuclei, Vulnrichment at
        `cutoff2..4` = snapshot − k·180 d (2025-10-31, 2025-05-04, 2024-11-05) via a logged
        refetch of those five sources (new attempt re-downloads every date; existing dates
        must reproduce attempt-1 SHA-256s); `cti parse` + `cti enrich`. Expected forward
        KEV positives: 20 / 21 / 30 / 17 (68 in rolling test windows).
  - [x] **7b. Pre-registered risk evaluation** *(2026-10-28: LR 6 vs EPSS 2 of 68 @100, CI +1..+8)* — plan + plan audit (2026-10-28, 12 required
        changes applied), config committed (`nlp/risk_config.py`) before any test score,
        then `cti risk-eval` + tests + implementation audit, run, document. See
        `vault/risk-eval.md`.
- [x] **8. Dashboard** *(2026-10-28: PR 1 #27, PR 2)* — local, read-only dashboard over pipeline-exported JSON; 4 views
      (overview, prioritized CVEs, IOCs, evaluation); defanged IOCs; no hardcoded metrics.
      *Stack changed 2026-10-28 (owner approved): Vite + React instead of a Next.js static
      export, because Next's inline scripts rule out a strict CSP without a post-build
      hashing step; Vite also pulls about half the npm packages.*
  - [x] **8a. `cti export --date`** *(2026-10-28, PR 1)* → `data/export/<date>/` (gitignored, never committed;
        it holds abuse.ch-derived aggregates). Deterministic JSON, `write_json`, validated
        by pydantic models before writing; every number comes from pipeline outputs.
        Refuses to run if `risk_config.py`'s SHA-256 differs from `risk-eval.json`
        `provenance.config_sha256`.
        - `meta.json`: snapshot date, as_of dates, KEV catalog version, EPSS model version
          per as_of, git state, input SHA-256s, config SHA-256.
        - `risk.json`: the pre-registered logistic model **refit on all four labelled
          windows** (cutoff4..cutoff, 88 positives; `risk_config.py` unchanged), scored
          on `eligible["snapshot"]` (≈167.8k CVEs published 2024-01-01 onward, not in
          KEV) via `featurize(r, "snapshot", date)`. Tiers by rank fraction through a
          shared `assign_tiers` helper that `tiers()` also uses (post-scoring refactor,
          logged in `vault/risk-eval.md`; regression test rebuilds `tiers_logistic`
          numbers from fixed arrays). Rows for critical/high/elevated (≈8.4k, cumulative
          5%); baseline as a count. Per row: rank, tier, EPSS probability + percentile,
          SSVC inputs, exploit flags, age, per-feature contribution in log-odds vs the
          training mean (intercept excluded; imputed values flagged). **No model
          probability is shown** (fit at ~0.03% prevalence, newer EPSS version): rank
          and tier only. Display-only context, labelled never used by the model: CVSS
          (NVD/CNA), CWE IDs, published, assigner, NVD description (URL/IP/domain spans
          from `iocs.extract` defanged, then truncated on a word boundary). Plus refit
          coefficients next to the last-fold ones from `risk-eval.json`, iterations,
          positives per window.
          Disclosures carried in the JSON: only CVEs published from 2024-01-01 are
          ranked; snapshot EPSS is v2026.06.15 (training saw v2023.03.01/v2025.03.14);
          the snapshot ranking itself is not evaluated; tier hit rates are "historical
          rate for this procedure's tier over the next 180 days, evaluation folds"
          (`risk-eval.json`), e.g. ≈97% of critical-tier CVEs did not enter KEV within
          180 days; logistic (not boosting) because it was the pre-registered headline
          and is explainable.
        - `iocs.json`: reference-page "indicator-type strings from CVE references (not
          vetted as malicious)": unique (type, value) with CVE list and count; `cve`/
          `cvss` types excluded; IPv4/IPv6 carry `public`; NVD-origin as counts only.
          abuse.ch feeds as aggregates only (by type, threat type, malware family top
          25, month); no feed IOC values. Fail-closed per-type defang check naming the
          bad value: url = scheme not http(s) and no bare `.` in the host; domain = no
          bare `.`; ipv4 contains `[.]`; ipv6 contains `[:]`.
        - `graphs.json`: weakness graph (pillar → CWE → tiered CVE, from
          `context_snapshot.cwes`, display only); ATT&CK graph (KEV CVE → technique →
          tactic from the pinned CTID mappings in `data/reference/ctid/`, by mapping
          type); shared-host graph (reference-page url/domain hosts shared by ≥2 CVEs,
          capped at the top hosts, values defanged). Node/edge counts capped so the file
          stays small.
        - `eval.json`: headline numbers copied by explicit key path from the five
          `data/eval/<date>/*-eval.json` files (no recomputation) + their SHA-256s.
  - [x] **8b. `cti serve [--date] [--port]`** *(2026-10-28, PR 1)* — `BaseHTTPRequestHandler` (not
        `SimpleHTTPRequestHandler`) on 127.0.0.1 only. At startup it builds an allowlist
        dict URL → file from resolved `web/dist/` and `data/export/<date>/` (symlinks
        out of those roots rejected); requests are exact lookups, so traversal,
        encoded dots, NUL bytes and directory listings can't happen. Explicit MIME map.
        Host must be exactly `127.0.0.1:<port>`/`localhost:<port>` (missing → 400).
        GET/HEAD only (else 405 + `Allow`). Fixed plain-text error bodies (never echo
        the path). Handler timeout. Security headers in `end_headers()` so errors get
        them too: CSP `default-src 'none'; script-src 'self'; style-src 'self';
        img-src 'self' data:; font-src 'none'; connect-src 'self'; base-uri 'none';
        form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'`,
        `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP same-origin,
        `Permissions-Policy` (clipboard-write=self, rest off), `no-store` on `/data/`.
        Missing export/dist → clear "run `cti export` / `npm run build`" error; `--date`
        validated, default newest export.
  - [x] **8c. `web/`** *(2026-10-28, PR 2)* — Vite 8.3.4, React/ReactDOM 19.3.1, TypeScript 7.0.2,
        @vitejs/plugin-react 6.1.2 (exact pins, all ≥14 days old); no UI kit, chart or
        table library, no router (hash routes), system fonts, no remote resources, no
        favicon fetch. `.npmrc`: `save-exact=true`, `ignore-scripts=true`,
        `min-release-age=14`; lockfile generated from a clean tree (check it lists the
        linux native binaries). Fetches `/data/*.json` at runtime; TS types mirror the
        pydantic models. Dark theme (design canvas "CTI Dashboard Design", 2026-10-28):
        neutral black surfaces; tiers one ordinal pink→cherry ramp (baseline #f6b8c4, elevated #f07c92, high #e8405a, critical #d90f33); model blue / EPSS aqua; ATT&CK-graph KEV CVE dots orange #f59a23; validated for CVD; brand "CTI Console".
        Seven views:
        1. Overview: headline tiles, tier ladder with historical rates + "≈97% did not
           enter KEV", top of queue, data sources/versions/hashes, disclosures.
        2. Risk queue: sortable, paginated 100/page, tier filter, search, detail panel
           with contribution bars; EPSS as "p% (Nth pct)" + model version; context
           columns greyed and labelled.
        3. Risk landscape: model rank vs EPSS percentile scatter (by tier), coefficient
           bars (refit next to evaluated last fold), signal-coverage heatmap by tier,
           critical+high by publication month.
        4. Weakness graph: CWE pillar → CWE → critical/high CVEs (layered, click to trace).
        5. ATT&CK graph: KEV CVE → technique → tactic from CTID mappings (radial; toggle
           exploitation / primary / secondary impact).
        6. Indicators: warning title, type tiles, shared-host graph (CVEs linked by a
           common reference host, single-CVE hosts hidden), abuse.ch aggregates,
           searchable table (non-public IPs hidden by default, copy defanged value).
        7. Evaluation: decision-rule banner, recall@100 / top-1% dot+CI chart with
           random baseline, per-fold table, AP/base rate/power, tier hit rates (log),
           ATT&CK/CWE/IOC/NER headlines, limitations.
        Graphs are hand-rolled SVG with deterministic layouts computed in the export or
        the client (layered/radial), no graph library.
  - [x] **8d. Tests + CI** *(2026-10-28)* — pytest: export (synthetic records → schema-valid,
        deterministic, defang refusal per type, no snapshot labels, refit uses only
        cutoff windows, config-SHA guard), `assign_tiers` parity, serve (bind refusal,
        Host check, headers on errors, traversal/encoded/symlink, 404/405, HEAD).
        Committed fixture `web/fixtures/` (synthetic; pytest validates it against the
        pydantic models and that every network value is RFC 5737/3849/2606
        documentation space). `web/scripts/check.mjs` (`node --test`): dist has no
        inline scripts/styles/`on*=`, no external URLs; no `dangerouslySetInnerHTML`/
        `innerHTML` in `src/`. CI job `web`: setup-node pinned by SHA with npm cache,
        `npm ci`, `npm audit signatures`, `npm audit --audit-level=high`, `tsc
        --noEmit`, `vite build` against the fixture, checks. Drop stale `.next/`/`out/`
        from `.gitignore`.
  - [x] **8e. Docs** *(2026-10-28)* — README dashboard section + run commands + skills; vault
        `dashboard.md` (+ index, code-layout, risk-eval refactor note);
        `docs/architecture.md`, `docs/decisions.md` (stack change); handoff. Phase 9
        note: screenshots from real data with the abuse.ch panel cropped (no
        abuse.ch-derived content committed); the fixture is for CI only.
- [ ] **10. Threats + better ATT&CK mapping** *(planned 2026-10-28, owner-approved; runs
      before Phase 9)* — the system classifies bugs (CWE) but not threats, and the
      CVE → ATT&CK mapping is weak. Owner decisions: a fresh held-out mapping test;
      threats are categorised, linked and prioritised, and explain CVEs but **do not feed
      the CVE risk score**. Notes: [[threat-layer]], [[attack-mapping-v2]]. One PR each:
  - [x] **10-0. Licence fix + reference data** — abuse.ch terms §7.3 (2026-10-21) forbid
        training AI models on ThreatFox/URLhaus data: drop abuse.ch rows from
        `cwe_eval.gold_check()` (`nlp/cwe_eval.py:453`), re-run the gold row, add a guard
        test. Commit CTID `attack_to_cve` CSV, CAPEC 3.9 XML, MISP galaxy subset (SHA-256
        pinned in code, licence/NOTICE). NVD 2002–2022 yearly feeds into a separate
        gitignored `data/reference-snapshots/<date>/` (existing `Snapshot` manifest,
        `.meta` SHA check, never uploaded; size checked first).
        Done 2026-10-29: `cti.reference.PINNED` + `test_reference.py`; CAPEC committed as
        the 3.9 zip; `cti fetch-nvd-archive` fetched 21 feeds (125 MB, 203,721 CVEs;
        830/836 CTID CVEs, 6 NVD-Rejected).
  - [ ] **10a. Threat layer** — ThreatFox parse keeps `fk_malware` (logged re-parse);
        ATT&CK `uses` read from the raw bundle (like `revocations_from_bundle`).
        `threats/catalog.py`: family → STIX `malware-type-ov` categories (+ infostealer,
        loader, c2-framework, web-skimmer, fake-update) from MISP galaxies; family →
        ATT&CK software (`alias_index()`) → techniques/tactics. Owner labels the top 34
        families **blind**, then compares (per-category agreement with CIs). CVE ↔ threat
        links with provenance (ThreatFox CVE tags; KEV ransomware use = category only;
        malware alias mentions), precision from a blind review sample. Threat priority =
        pre-declared heuristic (linked high-tier CVEs, ransomware, 30-day IOC growth, then
        volume) with a "why" per row, labelled unvalidated. `cti threats`, deterministic.
  - [ ] **10b. Mapping re-evaluation** — pre-register `nlp/attack2_config.py` (config SHA +
        git state in output) before any test score; disclose that test label counts were
        seen while planning. Train: all 419 CTID KEV CVEs. Test: CTID `attack_to_cve`
        (839 CVEs, 2008–2020) minus 27 overlaps; exploitation primary (~195), impact
        types secondary and flagged circular; a **CVE-disjoint, non-KEV population-shift
        test, not a time split**. Unfiltered NVD parse path; keep CVSS v2
        `userInteractionRequired`/`obtain*Privilege`. Methods (`nlp/attack_eval2.py`,
        old `attack-eval` untouched): majority; prior+biencoder (β by CV on train);
        **combiner** = one shared logistic over (CVE, technique) pairs (log prior,
        bi-encoder, TF-IDF, CAPEC path count, CVSS-flow rule; CV grouped by CVE);
        capec-chain row; methodology-replay reference row (not a baseline). Decision:
        combiner vs prior+biencoder, paired bootstrap hit@5 (MDE ≈ 0.08–0.10). Also hit@1,
        MRR, per technique, per CVSS version, near-duplicate check.
  - [ ] **10c. Dashboard** — `threats.json` (schema, types, fixture, vite/smoke lists);
        Threats view (categories, priority table with "why", family detail); "Linked
        threats" in the CVE detail; predicted techniques only if the combiner passes,
        labelled "predicted". abuse.ch values stay aggregates.

- [ ] **9. Security deliverables + polish** — STRIDE threat model of the pipeline,
      STIX 2.1 export, a sample analyst-style intel report, SBOM, dashboard screenshots,
      limitations section, final README.

Stretch (only if time allows): relation extraction,
detection-rule generation, a small hand-labeled evaluation set.

After Phase 10, before Phase 9 screenshots: dashboard clarity (E3: CVE name, Overview tab descriptions) in
[future-extensions.md](future-extensions.md).

## Review

_(filled in as phases complete)_
