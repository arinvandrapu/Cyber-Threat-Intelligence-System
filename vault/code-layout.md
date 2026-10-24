---
tags: [architecture, code]
---

# Code Layout

Package `cti` under `src/`. Python 3.12+, installed with `pip install -c requirements.lock -e '.[dev]'`.

| Module | Role |
|---|---|
| `config.py` | `Settings` from `CTI_*` env vars / `.env`; `require()` fails fast listing every missing name; secrets are `SecretStr` |
| `models.py` | `Document`, an immutable normalized record; id = `<source>:<source_id>` |
| `snapshot.py` | Raw snapshot + manifest, see [[ingest-once-snapshot]] |
| `http/client.py` | `get_with_retry`: retries transport errors, 429, and 5xx only; honors `Retry-After`; keys go in headers |
| `http/ratelimit.py` | Sliding-window limiter (ported from the prototype; injectable clock) |
| `http/safe_fetch.py` | SSRF-safe fetcher, see [[ssrf-safe-fetching]] |
| `storage/` | `LocalStorage`, `S3Storage`, `MirroredStorage`; no delete, no overwrite by default; see [[aws-cost-and-security]] |

## Conventions

- Tests are offline: `respx` mocks HTTP, `moto` mocks S3. `testpaths = ["tests"]`.
- CI: ruff lint + format, pytest on 3.12 and 3.14, pip-audit, gitleaks.
- Dependencies: ranges in `pyproject.toml`, exact pins in `requirements.lock`.
