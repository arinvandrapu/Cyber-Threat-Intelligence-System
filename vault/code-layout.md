---
tags: [architecture, code]
---

# Code Layout

Package `cti` under `src/`. Python ≥ 3.12.4 (ipaddress fixes), installed with `pip install -c requirements.lock -e '.[dev,enrich,ml]'`.

| Module | Role |
|---|---|
| `config.py` | `Settings` from `CTI_*` env vars / `.env`; `require()` fails fast listing every missing name; secrets are `SecretStr`. Blank values (`CTI_X=`) count as unset: a blank key once became `SecretStr("")` and passed the check |
| `models.py` | `Document`, an immutable normalized record; id = `<source>:<source_id>` |
| `snapshot.py` | Raw snapshot + manifest, see [[ingest-once-snapshot]] |
| `http/client.py` | `get_with_retry`: retries transport errors, 429, and 5xx only; honors `Retry-After`; keys go in headers |
| `http/ratelimit.py` | Sliding-window limiter (ported from the prototype; injectable clock) |
| `http/safe_fetch.py` | SSRF-safe fetcher, see [[ssrf-safe-fetching]] |
| `sources/` | One module per feed. `fetch(ctx)` writes raw to the snapshot (network); `parse(snapshot)` yields `Document`s or `CveSignal`s (offline). `registry.py` lists them in ingest order |
| `ingest.py` | One-time ingest: per-source isolation, completion markers, resume, logged refetch, secret redaction |
| `cli.py` | `cti probe / ingest / status / parse / enrich / extract / extract-eval / attack-eval / cwe-eval / models fetch\|verify / ner / ner-eval / embed / risk-eval / export / serve / upload / gold-import`; `_git_state()` (commit + dirty flag, pathspec `:(top)src`) |
| `enrich/` | `cves.py`: per-CVE join, `signals[as_of]` vs `context_snapshot`, `features_at` (see [[risk-scoring-design]]); `cwe.py`: full catalog incl. categories/deprecated, View-1000 pillar, MITRE mapping `usage`; `cleaner.py` + `references.py`: trafilatura cleaning of raw pages (`iter_pages` shared with the parser), js_shell/PDF flags. Plain dicts, deterministic gzip, atomic writes |
| `nlp/` | `iocs.py`: regex IOCs on original-text offsets, defanged values, validation (ipaddress, bundled PSL, CVSS grammar); `aliases.py`: ATT&CK + ThreatFox alias index, strict in-text matching; `extract.py`: `cti extract` rows tagged `origin`; `evaluate.py`: stratified review sample + gold P/R (see [[ioc-extraction]]); `attack_catalog.py` + `attack_eval.py`: ATT&CK candidates, revoked-ID remap, CTID grading, majority/TF-IDF/prior+X baselines (see [[attack-mapping]]; needs the `ml` extra); `models.py`: pinned SecureBERT specs, offline load, weights SHA-256 re-checked on load; `embed.py`: bi-encoder encoder (masked mean pooling) + `BiencoderRanker`; `ner.py`: windowed token classification, own BPE-fragment grouping + word snapping, defanged entity text; `semantic.py`: `cti ner` / `ner-eval` / `embed` builders, KEV-language flag (these four need the `nlp` extra); `cwe_config.py` (pre-registered choices) + `cwe_eval.py`: `cti cwe-eval` (`ml` extra only; see [[cwe-classification]]); `risk_config.py` (pre-registered) + `risk_eval.py`: `cti risk-eval`, rolling-origin KEV prediction (`ml` extra; see [[risk-eval]]) |
| `dashboard/` | `schema.py`: pydantic models for every export file (`extra=forbid`); `export.py`: `cti export` (refit on all windows, snapshot ranking, per-type defang check, feed aggregates, graphs, eval copy by key path, deterministic compact JSON); `serve.py`: `cti serve` allowlist server on 127.0.0.1 (see [[dashboard]]) |
| `upload.py` | Finished snapshot → S3, write-once: local SHA-256 re-check, keys already present compared via `sha256()` (S3 HEAD checksum, no download), manifest last and only overwritten if the remote one is a subset, final key listing; gold to `gold/` |
| `references/` | `classifier.py` (ported rule-based URL typing; `EXPLOIT` for exploit-db/Packet Storm, never scraped; added after the 2026-10-26 scrape, so re-running selection on that snapshot no longer reproduces `targets.json`, which stays authoritative), `selection.py` (KEV-first, then EPSS; capped), `scraper.py` (robots + throttle + SafeFetcher), `text.py` (stdlib HTML→text) |
| `gold.py` | `cti gold-import` → frozen fixture; `read_verified` / `load_gold` check the committed SHA-256 |
| `defang.py` | `hxxp://evil[.]com`, `203.0.113[.]7`, IPv6 `2001[:]db8…`; `refang` undoes `(.)`, `{.}`, `[dot]`, `[:]`, `[@]`, `hxxp`/`fxp` anywhere |
| `storage/` | `LocalStorage`, `S3Storage`, `MirroredStorage`; no delete, no overwrite by default; `sha256(key)` without download on S3; see [[aws-cost-and-security]] |

## Conventions

- Tests are offline: `respx` mocks HTTP, `moto` mocks S3. `testpaths = ["tests"]`.
- CI: ruff lint + format, pytest on 3.12 and 3.14, pip-audit, gitleaks. Actions pinned
  by commit SHA.
  A newer push to a PR cancels that PR's older run (`concurrency`); runs on `main` always
  finish.
- Dependencies: ranges in `pyproject.toml`, exact pins in `requirements.lock`.
- gitleaks: a 64-hex hash next to a key containing "token" trips `generic-api-key`. Mark the
  line `# gitleaks:allow` (see `nlp/models.py`); for a commit already pushed, add its
  fingerprint to `.gitleaksignore` with a reason. Never weaken the repo-wide config.
- `nlp` extra (torch, transformers) lives in `.venv-nlp/` (gitignored), pinned in
  `requirements-nlp.lock` (a superset of `requirements.lock`, same shared pins). CI never
  installs it; it runs `pip-audit -r requirements-nlp.lock --no-deps` instead. Torch-dependent
  logic is tested torch-free with fake taggers and encoders (`test_semantic.py`).
