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
- [x] **10. Threats + better ATT&CK mapping** *(planned 2026-10-28, owner-approved; runs
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
  - [x] **10a. Threat layer** — ThreatFox parse keeps `fk_malware` (logged re-parse);
        ATT&CK `uses` read from the raw bundle (like `revocations_from_bundle`).
        `threats/catalog.py`: family → STIX `malware-type-ov` categories (+ infostealer,
        loader, c2-framework, web-skimmer, fake-update) from MISP galaxies; family →
        ATT&CK software (`alias_index()`) → techniques/tactics. Owner labels the top 34
        families **blind**, then compares (per-category agreement with CIs). CVE ↔ threat
        links with provenance (ThreatFox CVE tags; KEV ransomware use = category only;
        malware alias mentions), precision from a blind review sample. Threat priority =
        pre-declared heuristic (linked high-tier CVEs, ransomware, 30-day IOC growth, then
        volume) with a "why" per row, labelled unvalidated. `cti threats`, deterministic.
    - [x] Pre-declared `threats/config.py`; `fk_malware` kept; blank blind sheet committed
    - [x] `cti threats`: catalog, ATT&CK `uses`, CVE links + evidence, priority, link sheet
          (36 links). Deviations, decided before any owner label: ATT&CK join by own name
          only (alias fallback merged Bashlite into QakBot); mentions from reference pages
          only (NVD text names the vulnerable product); "banker" added to the vocabulary;
          `linked_kev_cves` added as the first priority key (owner decision)
    - [x] Review sheets filled (owner delegated to Claude; disclosed in `REVIEW_LABELLER`):
          links 22/36 correct (mentions 12/26, tags 10/10; 35/53 after the 2026-10-29
          ATT&CK software links: ATT&CK 13/17, the XLoader platform collision rejected); ranking now uses only
          reviewed-correct or ThreatFox-tag links (`TRUSTED_LINKS`)
    - [x] Manual categories for the priority top 20 (`PRIORITY_REVIEW_TOP_N`; Havoc C2
          had MISP `ransomware`): 17 families added, converged, top 20 all manual
    - [x] Follow-up: Phase 5a alias index merged ThreatFox families into ATT&CK software
          via secondary aliases (Bashlite → QakBot, Houdini → njRAT). Fixed 2026-10-29:
          alias joins only through the ATT&CK entry's own title; extract + ner re-run
  - [x] **10b. Mapping re-evaluation** — pre-register `nlp/attack2_config.py` (config SHA +
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
    - Done 2026-10-29: pre-registered (`2a34423`), audited twice, run once. Combiner
      passes: hit@5 +0.035 [+0.005, +0.070] vs prior+biencoder (= majority, β=1.0);
      gain is the CVSS rule at T1189. See vault/attack-mapping-v2-results.md.
  - [x] **10c. Dashboard** — `threats.json` (schema, types, fixture, vite/smoke lists);
        Threats view (categories, priority table with "why", family detail); "Linked
        threats" in the CVE detail. No predicted techniques (owner decision 2026-10-29: the
        combiner passed narrowly via a post-hoc-informed rule; results shown on the
        Evaluation page only). abuse.ch values stay aggregates.

- [ ] **11. Review fixes** *(from the 2026-10-29 end-to-end review: pipeline, methods,
      security, dashboard/docs; runs before Phase 9)* — the project works end to end
      (hash chain verified, deterministic re-runs, no leakage, numbers match outputs);
      fixes are about claims, docs, UX and robustness. Three batches, one PR each; verify
      each claim against the outputs before editing.
  - [ ] **11a. Credibility**
    - [x] README: drop or mark planned "threat modeling (STRIDE)" (skills table, ~:291)
          and "a documented threat model" (~:413); STIX 2.1 listed as a skill (~:289)
          but planned (~:37)
    - [x] Overview guide (`web/src/views/Overview.tsx` risk-queue "how"): "+4 … in each
          period's top 100" is wrong; +4 is the total over 3 periods (0, +2, +2), CI +1
          to +8. Same check for the "Better than EPSS" tile (add the CI; note EPSS wins
          on mean AP)
    - [x] Link precision: report judged links separately: 25/43 (58%) judged from
          evidence; the 10 ThreatFox tags were accepted as reporter attributions. Update
          Threats fold, Overview guide, README Results, vault/threat-links.md
    - [x] Threat "why" wording: "linked to N CVEs in CISA KEV (confirmed exploited)"
          reads as the family exploited them. Name the source; owner decided 2026-11-04: wording only, no rule change. Cobalt Strike is
          "4 CISA KEV CVEs: 3 cited by ATT&CK, 1 cited in reference pages" (one of ATT&CK's
          four Java CVEs is not in KEV; the fourth KEV CVE is CVE-2024-1709)
    - [x] One framing for tier lift: Overview "≈159× likelier than the rest" (vs baseline
          tier, 6 positives) vs README "≈90× the overall rate"; pick one, add the CI
    - [x] Wording: "not yet known to be exploited" → "not in CISA KEV"; "more exploited
          CVEs caught" → "more later KEV additions caught"
    - [x] Disclose ATT&CK 10b hit@10: combiner 0.845 < majority 0.865 (results +
          README); call the pass "marginal". (Corrected from "rank-5 specific": the combiner leads at
          hit@1, @3 and @5, and falls behind only at hit@10)
    - [ ] Re-stamp outputs from a clean `main`: `cti extract` (iocs.jsonl.gz predates the
          `ftp://`→`fxp://` defang fix, 3 rows), `cti extract-eval --labels …`, `cti
          threats`, `cti export` (meta.json says commit e3a8528 + uncommitted changes)
  - [ ] **11b. Docs catch-up**
    - [ ] README: `--date 2026-10-25` (18×) → 2026-10-26; command order (parse → enrich
          → extract → … → export → threats-sheet/label → threats → export); threat
          layer in "What it does", the diagram and Results; layout section says 7 views;
          abuse.ch wording ("aggregates only" vs a few cited tag links in the link sheet)
    - [ ] docs/architecture.md (stops at Phase 8; add threats, threats-sheet,
          attack-eval2, fetch-nvd-archive); docs/data-sources.md (MISP, CAPEC, CTID
          attack_to_cve); docs/decisions.md (threat-priority heuristic, threats kept out
          of the risk score, Claude as labeller, abuse.ch no-training)
    - [ ] Vault: threat-links.md counts (3 queued; 30 KEV + 2 NVD cards; 56 labelled),
          threat-layer.md:21 ("owner labels blind" → Claude, not fully blind),
          dashboard.md (7 views; truncated "Brand:" line), dashboard-web.md:15,
          index.md (attack-mapping-v2 "planned"); split risk-scoring-design.md (88) and
          ingest-once-snapshot.md (82)
    - [ ] `cli.py` module docstring (lists 7 commands); future-extensions.md status;
          this file's Review section
    - **Plan (2026-11-06, after due diligence on `main` 51d932c)** — branch
      `docs/11b-catch-up`, one PR, docs only (no code paths change except the `cli.py`
      docstring). Already fixed by Phase 12/11c: view counts. Every number is checked
      against `data/export/2026-10-26/` before it is written.
      - [x] README: 18× `--date 2026-10-25` → 2026-10-26; Usage in true pipeline order
            (probe → ingest/status → parse → enrich → extract → extract-eval → models →
            attack-eval → ner/ner-eval/embed → cwe-eval → risk-eval → fetch-nvd-archive →
            attack-eval2 → export → threats-sheet/label → threats → export → build →
            serve → upload); a threat-layer bullet in "What it does" and a threat node in
            the diagram; layout tree (`web/` and `threats/` placed right); abuse.ch
            wording: aggregates, family names and 10 cited ThreatFox tag links, no raw
            IOCs; Threats row names all priority keys; one sentence "167,844 scored,
            8,392 in the queue"
      - [x] docs/architecture.md: status (Phases 0–12, 11a/c done); stage rows for
            fetch-nvd-archive, attack-eval2, threats-sheet, threats; Export row lists
            every file (incl. kev.json order/why, threats.json, cves.json, schema v2);
            "ingest is the only download" → exceptions (`fetch-nvd-archive`, `models
            fetch`, never uploaded); storage table (reference-snapshots, misp-galaxy,
            capec, threat CSVs); code map (`threats/`, `nlp/`, `dashboard/`, cli)
      - [x] docs/data-sources.md: "Reference data (pinned, outside the snapshot)": MISP
            galaxy, CAPEC, CTID attack_to_cve, NVD 2002–2022 archive, with licences;
            "captured twice" → four cutoffs + snapshot
      - [x] docs/decisions.md: new entries, each with its cost: threat priority is a
            declared heuristic, kept out of the risk score; Claude as labeller for the
            owner (not fully blind, disclosed); KEV triage order (fixed rule signed off
            before output); display honesty (no age sign flip, no "≈ 0", "scored" vs
            "in the queue"); index updated
      - [x] Vault: threat-links.md (56 labelled; 4 link rows on 3 queued CVEs, 1
            accepted; 30 KEV + 2 NVD cards), threat-catalog.md:36 count, threat-layer.md:21
            (Claude for the owner, not fully blind), dashboard.md "Recency" → "Age",
            index.md (attack-mapping-v2 not "planned"; threat-queue-overlap built),
            code-layout.md cli list; split the 4 notes over 80 lines
            (risk-scoring-design, dashboard-web, ingest-once-snapshot, dashboard)
      - [x] `cli.py` docstring lists all 22 commands by stage; future-extensions.md (E1
            done in 10b #33, marginal; E2 steps 1–2 done #32/#34); todo.md: Phase 12
            boxes, Review section filled (phases, PRs, outcomes); session-handoff.md
            (12 merged #44, 11c #45–#47, 11b in review, next steps, 562 tests)
      - [ ] Verify: every README/docs number re-checked against the export; `pytest`,
            `ruff`; markdown links resolve; mermaid renders (GitHub preview)
  - [x] **11c. Dashboard**
    - [ ] Every referenced CVE opens a detail: 154 Indicators-table CVEs are neither
          queued nor KEV (export a small NVD card for every CVE the export references);
          make "+N more" expandable; normal link colour
    - [ ] Threats "Indicators by category" bars render ~80px tall (`.chart{height:auto}` +
          `preserveAspectRatio="none"`); fixed height or the bar-row pattern
    - [ ] Terminology: "CVEs ranked 167,844" vs the queue's 8,392 ("scored" vs
          "ranked"/"below the queue"); one term each for KEV / exploited / tier / family
    - [ ] Explanations that look contradictory: "ExploitDB entry −0.19" (public exploit
          lowers rank), age sign on Landscape vs queue, refit EPSS weight 0.22 vs tested
          0.63 — one plain sentence each, consistent sign convention
    - [ ] Jargon left: SSVC values ("none/yes/total") → "Exploited? / Automatable? /
          Impact"; raw assigner UUIDs → CNA names where known
    - [ ] Small: truncated CWE names on the Weakness graph; Evaluation CI wrapping and two
          "Limitations" panels; family names in a CVE's detail link to Threats; queue
          overflow on narrow screens; chart vs filter category lists on Threats; MimiKatz
          category "unknown"; rows 17–20 show only "ransomware" as the reason
    - [x] Optional (owner liked the idea): "Used by malware" badge + "Linked to a threat"
          filter in the queue (CVE-2026-109618) — done as Phase 12.2 (#44)
    - **Plan (2026-11-06, after due diligence on `main`)** — branch
      plus gap 3 from the problem-statement review (vendor/product filter). Two PRs, in
      order, each from `main` (owner, 2026-11-06; no stacking): **PR 1 UI**
      (`feat/11c-ui`) = the UI items below; **PR 2 data/export** (`feat/11c-data`,
      after PR 1 merges) = the data/export items. UI items, all confirmed open:
      - [x] Indicator bars (`Threats.tsx:152`): plain div bars, fixed 8px height
      - [x] Signs read consistently. Changed after the plan audit: no sign flip (it would
            print "+0.57" for a −0.57 weight) and no "≈ 0" (a −0.01 weight still
            contributes −0.19 on 90 rows; hiding it would misstate bars that add up).
            Instead: age label "Age (older ranks lower)", which reads right for both the
            weight and a contribution; a queue note when ExploitDB or "SSVC: PoC / exploited"
            pulls down; Landscape caption: bar = refit today, bracket = tested fold, why
            weights move; README/vault "recency" → "age"
      - [x] SSVC in plain words: header "Exploited? · Automatable? · Impact"; none→no,
            poc→PoC, active→yes, total→full control, partial→partial (`RiskQueue.tsx`,
            `format.ts` labels)
      - [x] Weakness graph: full CWE name in `<title>`, wider label column
      - [x] Evaluation: CI on one line; one "Limitations" panel (second renamed "Data
            versions & disclosures", duplicate EPSS point removed)
      - [x] Family names link to Threats: `#/threats/<family>` focus route; route arg
            decoded and validated per view (CVE ID for queue/kev, membership in
            `threats.families` for threats); used in CveCard, queue detail, KEV table
      - [x] Queue on narrow screens: hide context columns + SSVC below ~900px
      - [x] Threats categories: caption that the chart covers all ThreatFox families and
            the filter the 20 shown; bars without a filter greyed
      - [x] Header on one line at ≥1280px with 9 tabs (tighter tab padding, one chip)
      - [x] KEV CVEs opened as `#/queue/<CVE>` redirect to `#/kev/<CVE>` in `App` with
            `location.replace` (Back doesn't bounce; `cveHref` stays pure)
      - [x] Smoke adds `#/threats/Agent%20Tesla` and a malformed `%E0%A4` route
      Data/export items (all open on `main`; no new data needed except as noted):
      - [x] Every clickable CVE opens a detail: 155 have none today (154 from indicators,
            CVE-2025-66478 from a threat link). NVD cards for every CVE the export
            references (~85 KB) in a top-level list that doesn't depend on threats
            (schema, types, loadAll, fixture, smoke). Plan audit: a card's status comes
            from membership in the scored set ("scored, below the queue" vs "outside the
            scored window", e.g. 31 are 2023 IDs); CVE-2025-66478 gets a "no record in
            our NVD snapshot" card; `focusCard` looks them up.
            Indicators: "+N more" expands, CVEs in normal link colour; indicators past the
            10-CVE export cap say "+N not exported"
      - [x] Terms: "scored" = the 167,844 CVEs given a tier, "in the queue" = the 8,392
            critical/high/elevated, "below the queue" = baseline. Fix every use
            (Overview, RiskQueue, Indicators, Evaluation, RiskLandscape, export
            disclosures, README); missing EPSS/SSVC reads "no EPSS/SSVC data", not "not
            scored"
      - [x] Vendor/product (gap 3): export `context.vendor`/`product` for queue rows
            (`_real()`, NVD affected, 89% coverage); queue search covers name + vendor +
            product; vendor type-ahead (`<datalist>`) on Risk queue and Known exploited
            (1,985 / 291 vendors: too many for a dropdown); match case-insensitively;
            plan audit: check how much the derived name already covers first; defang
            vendor/product consistently (`_linked_cves` doesn't today); first affected
            entry only, say so; `vault/dashboard.md:43` "ranked" → "scored"
      - [x] Assigners: no CNA-name source on disk (93.8% of queue rows are emails, 6.2%
            UUIDs). Owner 2026-11-06: emails as is, UUIDs as "CNA (ID 416baaa9…)"; no
            outside name map (keeps the one ingest)
      - [x] Threats rows with no linked CVE: reason reads "ransomware family (no linked
            CVEs)" (`threats/catalog.py:184`) and the table shows the second reason
            line; plan audit: say "no linked CVEs in our data" and build the line in the
            export/UI rather than rerun `cti threats` (which may pick a newer reference
            snapshot, 11d)
      - [x] MimiKatz category: owner 2026-11-06: keep the "unknown" label (no post-hoc
            relabel); Threats view explains it: "a tool, not malware: outside the
            category list" (from the owner's note in the labels CSV)
      - Done 2026-11-06 (PR 2, `feat/11c-data`): `cves.json` (154 cards, all "scored,
        below the queue"; 31 2023-ID CVEs were published in 2024, so status from data
        mattered); every one of 10,304 clickable CVEs now opens a detail.
        CVE-2025-66478 is only in description text (rejected CVE), not clickable, so no
        card. Indicators "+N more" counts the true total. MimiKatz: the reviewer's note
        isn't exported (rerunning `cti threats` was ruled out), so the view says "none of
        the categories fits", not "a tool, not malware"

  - [ ] **11d. Robustness + hygiene** — due diligence 2026-11-07 on `main` (`b9b462c`):
        every item below is still open. Owner picked **MIT** (2026-11-07). Two PRs, not
        stacked: (a) first, (b) branched from `main` after (a) merges.
    - [x] Docs: `tasks/session-handoff.md` row "11b in review" → merged #48 (#49)
    - **PR (a) `chore/11d-robustness`: licence, CI supply chain, scraper**
      - [x] a1 `LICENSE` (MIT, "Copyright (c) 2026 Arin Vandrapu"); `pyproject.toml`
            `license = "MIT"`, `license-files = ["LICENSE"]`, build `setuptools>=77`;
            README attribution: MIT covers the code only, `data/reference/*` keep their
            terms (CTID Apache-2.0, MISP CC0/BSD-2, CAPEC MITRE terms), SecureBERT 2.0
            models Apache-2.0 (HF cards, checked 2026-11-07)
      - [x] a2 Hashed locks: regenerate both with `uv pip compile --universal
            --generate-hashes`, constrained to today's pins (`-c` old lock) so no version
            changes; `setuptools` in the `dev` extra (hashed build backend); pip in its own
            hashed `requirements-pip.lock`, installed first (impl. audit: bundled pip 25.3
            has advisories; plan audit: not inside the main lock); nlp lock macOS arm64 + 3.14 only (no CUDA wheels); command
            in each lock's header; drop the unhashed `--upgrade pip`; `pip check`. Install everywhere as `pip install --require-hashes -r <lock>`
            then `pip install --no-deps --no-build-isolation -e .` (CI, README, handoff)
      - [x] a3 CI: `persist-credentials: false` on all three checkouts (gitleaks keeps
            `fetch-depth: 0`, passes the token via env); exact tag comments on the same
            SHAs (checkout v4.4.0, setup-python v5.6.0, gitleaks-action v2.3.9); pip-audit
            of the hashed nlp lock still parses
      - [x] a4 `safe_fetch.fetch`: refuse an https→http redirect (`BlockedURLError`);
            per-hop hook so `scraper.scrape_one` checks robots (and throttles) on every
            hop, not just first + final; fix the `scraper.py` docstring claim
      - [x] a5 S3 manifest overwrite: compare-and-swap `Storage.replace(key, data,
            expected=)`; S3 re-reads, compares bytes, writes with `IfMatch` on that ETag;
            412/409/404 → `StaleWriteError` → `RemoteConflictError`; moto test that fails
            without `IfMatch` (checked)
      - [x] a6 `http/client.py` docstring: abuse.ch v2 puts the key in the URL path;
            say what protects it (`FetchContext.redact`, httpx loggers at WARNING)
      - [x] Docs: README (setup, supply chain, skills table), `docs/architecture.md`,
            vault `ssrf-safe-fetching` (+ disclosure: 0/2,000 https→http finals per
            attempt), `aws-cost-and-security`, `code-layout`; handoff rebuild commands
      - [ ] Verify: pytest, ruff, CI green on 3.12 + 3.14, fresh local venv from the
            hashed lock (done: 569 passed on 3.12 and 3.14, `pip check` clean, pip-audit
            clean); no export change (no re-stamp needed); implementation audit
    - **PR (b) `chore/11d-correctness`: recovery, version checks, refactors**
      - [x] b1 export/threats loop: when tiers changed, write the whole export with
            threats `available:false, stale:true`, then **exit non-zero** with the
            recovery commands (plan audit: KEV order and Overview change without threats;
            smoke can't tell). Schema + `types.ts` + contract test + a stale message in the
            view; fixtures if the schema changes. The unlabelled-top-N check stays a hard
            error (only labelling fixes it). Test the loop end to end
      - [x] b2 `cmd_risk_eval` refuses when the snapshot's KEV `source_version` ≠
            `KEV_CATALOG_VERSION` (both `2026.10.23` today)
      - [x] b3 `cti threats --archive-date` (default: newest reference snapshot, as now);
            refuse an archive without an `nvd` feed
      - [x] b4 cwe-eval output gains `provenance` (`config_sha256`, `_git_state()`,
            library versions), like risk-eval
      - [x] b5 one `wilson()` in a neutral `cti/stats.py` (not `nlp/evaluate.py`: risk-eval
            importing from IOC eval read oddly); risk_eval passes `Z95 = 1.959964`
      - [x] b6 public `nvd.affected`, `attack_eval.per_cve`
      - [ ] ~~b7~~ **deferred** (plan audit: move-only refactor, low value, some risk before the
            interview; noted in `vault/code-layout.md`). Was: move `cmd_threats` and `cmd_attack_eval2` orchestration into
            `threats/` and `nlp/attack_eval2.py`; `build_parser` stays (declarative)
      - [x] b8 `embed.mean_pool(hidden, mask)` written to work on NumPy arrays too, so
            its test runs in CI without torch (plan audit)
      - [ ] Verify: pytest, ruff, rerun risk-eval/threats/export on real data and diff
            outputs (expect identical except provenance), re-stamp export from clean
            `main` after merge, smoke both exports; implementation audit

- [x] **12. Connect threats to what to patch** *(merged #44)* *(from the 2026-11-06 problem-statement
      review; finding: `vault/threat-queue-overlap.md`)* — 47 of 53 threat links point at
      KEV CVEs, which the queue excludes, so "threats explain CVEs" holds for KEV and
      almost never for the queue (1 queued CVE: CVE-2026-109618, rank 3). Fix within the
      one ingest: no new data. One branch (`feat/connect-threats-kev`), one commit per
      step, one PR after an implementation audit.
  - [x] **12.1 KEV triage view** — rank all 1,756 KEV CVEs ("patch first") by a fixed,
        pre-declared sort, not a model (there are no labels to evaluate it against):
    - [x] Owner signed off 2026-11-06, before any output (and chose a new tab before
          Risk queue over a mode inside it). Sort keys, in order:
          (1) linked to a threat family by a link that counts for priority
          (26 KEV CVEs; 4 more have only rejected links); (2) CISA known ransomware use (361 Known);
          (3) newest `date_added` first; tie → CVE ID
    - [x] `cti export`: add `priority_rank` + one-line `why` (names its source, as the
          Threats "why" does) to each `kev.json` entry; families from accepted links only;
          schema (`dashboard/schema.py`) + `web/src/types.ts` + contract test; unit tests
          for the sort and the why text; regenerate `web/fixtures`
    - [x] New view "Known exploited" (before Risk queue): sortable table (rank, CVE, name,
          vendor/product, ransomware, linked threats, date added, due date), filters
          (linked to a threat / ransomware), search; row opens the existing KEV card;
          caption: a sort order, not a prediction; KEV = exploited by someone, not
          necessarily the linked family
    - [x] `smoke.py` VIEWS gets the new view
    - Done 2026-11-06 after a plan audit: one rule for "linked" (a card lists a family
      only for a link that counts for priority; that list is the sort's first key), so
      26 linked, not 30; neutral source wording (`KEV_LINK_SOURCES`: "cited in its ATT&CK
      entry", "named on a reference page"); due date labelled as a US federal deadline;
      row opens its card inline (the `#/queue/<CVE>` route prefers the threats card)
  - [x] **12.2 "Linked to a threat" in the risk queue** — badge on queued CVEs with a
        link not reviewed as wrong, plus a filter next to "public exploit only"; the
        detail already lists linked threats. Today this flags 1 CVE; the caption says so
        and calls it an early warning (exploitation evidence before CISA lists it), and
        that threats never feed the rank
    - Done 2026-11-06: badge + filter use the KEV view's rule (a link that counts for
      priority), so both views agree; the detail still lists every non-rejected link with
      its review state. Badge is neutral grey: KEV orange would read as "in KEV"
  - [x] **12.3 Overview + docs say what the data shows** — "How they connect": threats
        explain KEV CVEs (patch first, ranked on the new view); a threat link on a queued
        CVE is an early warning. Overview briefing gains the KEV list; tab guide entry for
        the new view (numbers from the export). README (views table, view count,
        Overview row), `vault/dashboard.md`, `vault/dashboard-web.md`,
        `vault/threat-queue-overlap.md` ("proposed" → built), handoff
    - Done 2026-11-06: three-column briefing (one column under 1100px); footer and tab
      guide numbers computed from the export; README "Where links land" bullet
  - [x] Verify each step: `pytest`, `ruff`, `npm run build`, `npm run check`, `smoke.py`
        on fixture + real export, screenshots; plan audit before 12.1, implementation
        audit before the PR

- [ ] **9. Security deliverables + polish** — STRIDE threat model of the pipeline,
      STIX 2.1 export, a sample analyst-style intel report, SBOM, dashboard screenshots,
      limitations section, final README. Order (owner, 2026-11-06), one PR each:
  - [ ] 9.1 **Sample intel report** first: a short analyst brief generated from the export
        (patch-now KEV CVEs in the Known exploited order, queue CVEs likeliest next, early
        warnings, top threats, each with its "why" and the honest limits). The clearest
        demonstration of the problem statement; numbers read from the export, not typed
    - Owner 2026-11-07: Markdown in `docs/` (no dashboard tab, no PDF). Due diligence done
      (external: CISA/ICD 203/TLP 2.0 conventions; internal: field map + current values)
    - [x] B1 `src/cti/report/brief.py`: `render(export_dir) -> str`, pure and deterministic
          (no clock: dates from `meta.json`, commit from `meta.git`); inputs validated with
          `schema.FILES`; `cti report [--date D | --export-dir P] [--out F]` (default
          `data/export/<date>/brief.md`; atomic write)
    - [x] B2 Sections (~1–2 pages): `TLP:CLEAR` first and last line; title, data cut-off,
          versions (KEV catalog, EPSS model, commit), "portfolio sample from public data,
          not an operational product"; **BLUF** 3–4 bullets, facts only (counts and the
          forward-test result), no likelihood words on model output; **1 Patch now**: top
          10 `kev.json` entries in `priority_rank` order with their `why` (no due dates:
          1,751/1,756 past due); **2 Watch list**: top 10 queue rows (rank, tier, EPSS +
          percentile, top 3 drivers via a Python copy of `FEATURE_LABEL`, tested against
          `web/src/format.ts`), framed as a sort order, plus tier back-test hit rates with
          Wilson CIs; **3 Early warnings**: queued CVEs with a link that counts (Overview
          rule), "never changes the rank; not evaluated as a predictor"; **4 Threat context**:
          top 5 families, "co-mentioned / tagged", never "exploits"; rejected links skipped;
          link-review precision + "labelled by Claude for the owner"; **5 Recommended
          actions** (patch, mitigate/monitor, hunt) generic to the data, no invented product
          advice; **6 Confidence & method**: top-100 hits model vs EPSS + CI from
          `eval.json`, "not a probability"; **7 Limitations**: `meta.disclosures` verbatim;
          **8 Sources**: each feed with its snapshot/version and a one-line reliability note
    - [x] B3 No indicators, no descriptions (defang/licence: abuse.ch only as family names,
          counts and tag-page citations; no "threatfox" source-string literal in the module)
    - [x] B4 Tests on `web/fixtures`: deterministic; TLP first/last; every CVE and number in
          the brief appears in the export; no URL/IP/domain patterns; FEATURE_LABEL sync;
          CLI writes the file. Generate `docs/sample-intel-brief.md` from the clean real
          export (`13b4fc5`) and commit it
    - [x] B5 Docs: README (link the brief near the top; skills row: intelligence reporting,
          TLP, ICD 203-style confidence), `docs/architecture.md` component row, new
          `vault/intel-brief.md` + index, handoff (also the stale "next" lines), hub note
    - Plan audit (2026-11-07) changed the plan: module is `dashboard/brief.py` (not a
      `report/` package); default output `data/reports/<date>/brief.md` (not the export
      dir, which `cti export` doesn't clean); `facts()`/`render()` split; golden fixture
      test + `--check` (export SHA-256) instead of "every number in the export"; forward
      test stated as the pre-registered verdict + counter-evidence; "Known exploited:
      threat-linked first" not "Patch now"; ransomware field and due-date scope explained;
      newness + EPSS version gap in the watch-list header; two labelled ICD 203 judgements
      in the BLUF; per-source link wording (`KEV_LINK_SOURCES`, moved to
      `threats/config.py`); unavailable/stale threats paths tested. Details:
      `vault/intel-brief.md`
    - [x] Verify: pytest (592), ruff; brief read end to end; implementation audit applied (8 required + most optional); CI on the PR
  - [ ] 9.2 STRIDE threat model of the pipeline (ingest/scraper, storage/S3, export,
        `cti serve`, browser) with the controls already built and the gaps
  - [ ] 9.3 STIX 2.1 export (bundle of vulnerabilities, malware, relationships; validated)
  - [ ] 9.4 SBOM (Python + npm) and dashboard screenshots from real data (abuse.ch panel
        cropped per licence)
  - [ ] 9.5 Limitations section and final README pass (recruiter-facing: problem, skills,
        how to run, what it demonstrates)

Stretch (only if time allows): relation extraction,
detection-rule generation, a small hand-labeled evaluation set.

After Phase 10, before Phase 9 screenshots: dashboard clarity (E3: CVE name, Overview tab descriptions) in
[future-extensions.md](future-extensions.md). Done 2026-10-29 (CVE names, Overview guide, plain labels).

Dashboard Guide tab (2026-11-07, `feat/guide-tab`; owner approved name "Guide",
per-tab "How to read this" links, ~1–2 screens per tab, methods link to Evaluation):

- [x] G1 Due diligence: per-view fact briefs (every panel, encoding, caveat) + docs-page UX
- [x] G2 Plan audit
- [x] G3 `guide` view last in `VIEWS`; `#/guide/<section>` deep links; sticky sidebar
      (tabs → panels) with scroll-spy; dropdown under 900px
- [x] G4 Content per tab: purpose, how to read each panel, how it's computed, caveats,
      live-number example; Concepts glossary; Data & freshness (`src/guide/sections/`).
      Overview keeps its own short cards (the Guide intros are longer, so no shared module)
- [x] G5 "How to read this →" link in each tab's header
- [x] G6 Smoke marker, build, `npm run check`, screenshots at 1280px and phone width
- [x] G7 Implementation audit (code) + fact-check audit (every claim vs view code/export):
      2 scroll-spy fixes; ~40 wording fixes (overclaims on threat coverage, calibration,
      ATT&CK mapper and IOC precision; wrong SSVC owner, bootstrap and bar-scale details)
- [x] G8 Vault (`dashboard.md`, `dashboard-web.md`, new `dashboard-guide.md`) + README — merged #51
- [x] Follow-ups merged: #52 Guide sidebar section links stay in place while scrolling;
      #53 floating "Top" button on every view
- [x] Post-merge fact check (2026-11-07, `fix/guide-accuracy`): ATT&CK v2 wording (older
      non-KEV CVEs; formally passed, gain rests on a post-hoc rule), "MD5 and IPv4" not
      "hashes and IPs", KEV sort says a *shown* family, CWE says frozen embeddings; vault
      note admits the few typed qualitative claims. Not done: export `TOP_THREATS` (schema change)

## Review

As of 2026-11-06 (`main` 51d932c; export re-stamped clean, schema 2; 562 tests).

| Phase | PRs | Outcome |
|---|---|---|
| 0–2 Docs, foundation, sources | #1–#7 | Typed config, SSRF-safe fetcher, write-once storage, 12 source parsers, frozen gold set |
| 3 Ingest | #9, #11 | One ingest (2026-10-26), all 12 sources; raw + gold in S3 (≈335 MB), `cti` key inactive |
| 4 Enrichment | #14, #15 | 168,393 CVE rows with point-in-time features; 1,280 cleaned reference pages |
| 5a IOCs | #17 | Precision 98.5% pages / 89.1% NVD (AI-labelled sample; mostly CVE IDs) |
| 5b ATT&CK, SecureBERT | #18, #19 | Prior + bi-encoder hit@5 0.57 vs majority 0.41 (hybrid designed after test, disclosed) |
| 6 CWE classification | #21, #22 | TF-IDF macro-F1 0.394 beats frozen SecureBERT 0.265 (pre-registered) |
| 7 Risk scoring | #24–#26 | Beats EPSS at top 100: +4 (CI +1 to +8) over 68 KEV additions; not at 1%; EPSS higher mean AP; tiers monotonic |
| 8 Dashboard | #27, #28 | `cti export` + `cti serve` (loopback, strict CSP), React UI, CI smoke |
| 10 Threat layer, ATT&CK re-test | #30–#34, #36, #38 | 467 families, top 20 by a declared rule; links 25/43 judged correct; 10b combiner passes marginally |
| Clarity (E3) | #35, #39 | CVE names, tab guide, plain language, every CVE opens a detail |
| 11a Credibility | #40, #41 | Overclaims corrected (KEV wording, link precision, tier lift) |
| Overview redesign | #42, #43 | One briefing panel; queue card matches tiers card |
| 12 Threats → what to patch | #44 | Known exploited view (fixed order, 26 threat-linked first); queue early-warning badge; Overview counts |
| 11c Dashboard | #45–#47 | One sign convention without changing numbers; scored vs in the queue; every one of 10,304 clickable CVEs opens a detail (154 new NVD cards); vendor search; equal Evaluation panels |

Lessons from these phases are in `tasks/lessons.md` (stranded pushes, stacked PRs,
pre-registration before results, checking third-party data before committing).
