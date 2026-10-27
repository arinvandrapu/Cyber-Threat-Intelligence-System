---
tags: [architecture, code]
---

# Code Layout

Package `cti` under `src/`. Python ≥ 3.12.4 (ipaddress fixes), installed with `pip install -c requirements.lock -e '.[dev]'`.

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
| `cli.py` | `cti probe / ingest / status / parse / enrich / upload` |
| `enrich/` | `cves.py`: per-CVE join, `signals[as_of]` vs `context_snapshot`, `features_at` (see [[risk-scoring-design]]); `cwe.py`: full catalog incl. categories/deprecated, View-1000 pillar; `cleaner.py` + `references.py`: trafilatura cleaning of raw pages (`iter_pages` shared with the parser), js_shell/PDF flags. Plain dicts, deterministic gzip, atomic writes |
| `nlp/` | `iocs.py`: regex IOCs on original-text offsets, defanged values, validation (ipaddress, bundled PSL, CVSS grammar); `aliases.py`: ATT&CK + ThreatFox alias index, strict in-text matching; `extract.py`: `cti extract` rows tagged `origin`; `evaluate.py`: stratified review sample + gold P/R (see [[ioc-extraction]]) |
| `upload.py` | Finished snapshot → S3, write-once: local SHA-256 re-check, keys already present compared via `sha256()` (S3 HEAD checksum, no download), manifest last and only overwritten if the remote one is a subset, final key listing; gold to `gold/` |
| `references/` | `classifier.py` (ported rule-based URL typing; `EXPLOIT` for exploit-db/Packet Storm, never scraped; added after the 2026-10-26 scrape, so re-running selection on that snapshot no longer reproduces `targets.json`, which stays authoritative), `selection.py` (KEV-first, then EPSS; capped), `scraper.py` (robots + throttle + SafeFetcher), `text.py` (stdlib HTML→text) |
| `gold.py` | `cti gold-import` → frozen fixture; `read_verified` / `load_gold` check the committed SHA-256 |
| `defang.py` | `hxxp://evil[.]com`, `203.0.113[.]7`, IPv6 `2001[:]db8…`; `refang` undoes `(.)`, `{.}`, `[dot]`, `[:]`, `[@]`, `hxxp`/`fxp` anywhere |
| `storage/` | `LocalStorage`, `S3Storage`, `MirroredStorage`; no delete, no overwrite by default; `sha256(key)` without download on S3; see [[aws-cost-and-security]] |

## Conventions

- Tests are offline: `respx` mocks HTTP, `moto` mocks S3. `testpaths = ["tests"]`.
- CI: ruff lint + format, pytest on 3.12 and 3.14, pip-audit, gitleaks. Actions pinned
  by commit SHA.
- Dependencies: ranges in `pyproject.toml`, exact pins in `requirements.lock`.
