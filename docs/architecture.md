# Architecture

How the Cyber Threat Intelligence System is put together: what runs where, how data
moves, and where it is stored. The reasoning behind each choice is in
[decisions.md](decisions.md).

> Phases 0–7 are built (ingest through the risk evaluation); Phase 8 (dashboard) is in
> progress. Stages marked *planned* are designed but not implemented yet. Progress: [`tasks/todo.md`](../tasks/todo.md).

## Overview

```mermaid
flowchart LR
    SRC[Public sources<br/>NVD · KEV · EPSS · Vulnrichment<br/>ExploitDB · Metasploit · Nuclei<br/>ATT&CK · CWE · abuse.ch<br/>CVE reference pages]
    subgraph LAPTOP[Owner's laptop: all compute]
        ING[cti ingest<br/>one-time fetch]
        SNAP[(Raw snapshot<br/>data/snapshots/DATE/)]
        PARSE[cti parse<br/>offline]
        PROC[(Parsed records<br/>data/processed/DATE/)]
        ENR[(Per-CVE join · cleaned pages<br/>data/enriched/DATE/)]
        EXT[(Regex IOCs · aliases<br/>data/extracted/DATE/)]
        DOWN[SecureBERT NER · embeddings · ATT&CK<br/>CWE + risk evaluations]
        OUT[cti export JSON → cti serve<br/>dashboard on 127.0.0.1<br/>STIX 2.1 planned]
    end
    S3[(Private S3 bucket<br/>write-once archive)]

    SRC -->|HTTPS, rate-limited,<br/>SSRF-safe scraper| ING --> SNAP
    SNAP --> PARSE --> PROC -->|cti enrich| ENR -->|cti extract| EXT --> DOWN --> OUT
    SNAP -->|cti upload<br/>after parse validates| S3
```

Three properties shape everything:

1. **The network is touched once.** `cti ingest` is the only command that downloads
   source data. Every later stage reads the stored snapshot.
2. **All compute is local.** Parsing, NLP (SecureBERT 2.0 on CPU), and modeling run on
   one machine. There is no EC2, Lambda, or SageMaker.
3. **S3 is an archive, not a workspace.** It receives a write-once, checksummed copy of
   the finished raw snapshot and the gold set. No pipeline stage reads from it.

## Pipeline stages

| Stage | Command / module | Network | Input → output |
|---|---|---|---|
| Probe | `cti probe` | yes (cheap) | Checks each source is reachable and keys work |
| Ingest | `cti ingest` → `ingest.py`, `sources/*.fetch` | yes | Sources → raw snapshot + manifest |
| Status | `cti status` | no | Prints the manifest: files, sizes, pinned versions, refetches |
| Parse | `cti parse` → `sources/*.parse` | no | Raw snapshot → `Document` / `CveSignal` records (`.jsonl.gz`) |
| Upload | `cti upload` → `upload.py` | S3 only | Raw snapshot + gold set → S3, write-once |
| Enrich | Phase 4 | no | `cti enrich`: one record per CVE joining KEV, EPSS, ExploitDB, Metasploit, Nuclei, Vulnrichment, CWE names and pillars, and reference-link types; point-in-time features kept apart from snapshot-time context. Cleans reference pages (trafilatura boilerplate removal; pages with no content without JavaScript or a login, and PDFs, flagged and kept out of the corpus) |
| Extract | `cti extract` → `nlp/` | no | Cleaned pages + NVD descriptions → regex IOCs (offsets, defanged values, `origin` tag) and alias mentions normalized to ATT&CK IDs; `cti extract-eval` scores precision on a labelled review sample and recall on the gold set |
| ATT&CK grading | `cti attack-eval` → `nlp/attack_eval.py` | no | CVE text → ranked ATT&CK techniques, graded on MITRE CTID's KEV mappings (pinned copy in `data/reference/ctid/`); majority, TF-IDF, SecureBERT bi-encoder, and label prior + similarity |
| NLP | `cti models` / `ner` / `ner-eval` / `embed` → `nlp/models.py`, `ner.py`, `embed.py`, `semantic.py` | `models fetch` only (once) | SecureBERT 2.0 on CPU: NER over reference pages (entities linked to ATT&CK/ThreatFox names), bi-encoder embeddings of every NVD description with a KEV-language flag. Models pinned by commit and weight SHA-256, loaded offline |
| Classify + evaluate | `cti cwe-eval` → `nlp/cwe_config.py`, `nlp/cwe_eval.py` | no | NVD descriptions → 118 CWE classes (human labels with assigner kept), time split, pre-registered choices; majority, TF-IDF + LR, SecureBERT embeddings + LR, nearest centroid; plus one circular gold-set row |
| Risk evaluation | `cti risk-eval` → `nlp/risk_config.py`, `nlp/risk_eval.py` | no | Pre-registered rolling-origin KEV prediction: logistic model vs EPSS, SSVC and CVSS baselines, rank-based tiers |
| Export | `cti export` → `dashboard/export.py`, `dashboard/schema.py` | no | The pre-registered model refit on all labelled windows ranks the snapshot; defanged IOCs, feed aggregates, CWE/ATT&CK/shared-host graphs, evaluation summaries → schema-validated JSON in `data/export/<date>/` |
| Serve | `cti serve` → `dashboard/serve.py` | loopback only | Built dashboard + export over HTTP on 127.0.0.1: exact-match file allowlist, Host-header check, strict CSP and security headers |
| Dashboard *(in progress)* | `web/` (Phase 8) | no | Vite + React UI over the exported JSON |
| STIX *(planned)* | Phase 9 | no | STIX 2.1 export |

Every source module has two halves: `fetch(ctx)` writes raw bytes to the snapshot
(network), and `parse(snapshot)` turns them into records (offline). A parser bug is fixed
by re-running `cti parse`, never by re-downloading.

## Storage

| Location | Contents | Mutability |
|---|---|---|
| `data/snapshots/<date>/` (local) | Raw source responses, gzip'd, plus `manifest.json` | Write-once; only the manifest is rewritten |
| `data/processed/<date>/` (local) | Parsed records, one `.jsonl.gz` per source | Regenerated freely from the snapshot |
| `data/enriched/<date>/` (local) | `cves.jsonl.gz`, `references.jsonl.gz`, and a `*-summary.json` for each | Regenerated freely (cves from processed records, references from the raw snapshot); never uploaded |
| `data/extracted/<date>/` (local) | `iocs`, `aliases`, `entities` (`.jsonl.gz` + `*-summary.json`; values defanged), `nvd-embeddings.npy` (float16) + `nvd-embeddings-index` | Regenerated freely; never uploaded |
| `~/.cache/huggingface/` (local) | SecureBERT 2.0 weights at pinned revisions | Fetched once; SHA-256 checked on every load |
| `data/eval/<date>/` (local) | Evaluation outputs (aggregates) and review sheets (defanged context) | Regenerated freely; never uploaded |
| `data/reference/` (in git) | IOC review labels (document ID, span, y/n; no feed content) and the CTID KEV → ATT&CK mapping file with its Apache-2.0 notice | Committed; the CTID file's SHA-256 is pinned in code |
| `data/gold/gold.jsonl.gz` (local) | Frozen evaluation gold set | Frozen; SHA-256 committed in `cti/gold.py` |
| S3 `snapshots/<date>/…` | Copy of the raw snapshot | Write-once, enforced by code **and** IAM |
| S3 `gold/` | Copy of the gold set | Write-once |

Snapshot key layout (same locally and in S3):

```
<snapshot_id>/manifest.json
<snapshot_id>/raw/<source>/<attempt>/<file>
```

- The manifest records, per file: source, URL (secrets redacted), fetch time, size,
  SHA-256, and the source version (e.g. ATT&CK v20.0, EPSS model version).
- `attempt` increases only through a logged `--refetch <source> --reason …`; older
  attempts are kept, so the history of a source is never lost.
- The storage layer (`storage/`) has no delete operation. Writes use no-overwrite by
  default (S3 `If-None-Match: *`); retrying with identical bytes is accepted, different
  bytes are rejected.
- `data/` is gitignored. Raw feed data never enters the public repo (licensing).

## Point-in-time data

Risk scoring is evaluated forward-looking: score CVEs with data known at a **cutoff**
(snapshot − 180 days), then check which were added to CISA KEV after it. Three earlier
cutoffs (each a further 180 days back) support a rolling-origin evaluation. So the
snapshot holds a copy of each time-sensitive source per cutoff, plus the snapshot copy:

| Source | Cutoff copy | Snapshot copy |
|---|---|---|
| EPSS | Dated daily file | Dated daily file |
| ExploitDB | GitLab first-parent commit at cutoff | Current |
| Metasploit, Nuclei, Vulnrichment | Git first-parent commit at cutoff | Current |
| KEV | `dateAdded` splits before/after | Full catalog |

Leakage rules (fields that would reveal KEV status) are enforced at parse time. The
enriched per-CVE record then keeps point-in-time `signals[<as_of>]` apart from
`context_snapshot` (NVD status, scores, CWEs, reference lists as known at the snapshot).
NVD analyzes KEV-listed CVEs first, so those NVD fields are biased toward the label: all
17 forward positives at the latest cutoff are "Analyzed" vs about half of other CVEs. Details:
`vault/point-in-time-pinning.md`, `vault/risk-scoring-design.md`.

## Security boundaries

```mermaid
flowchart LR
    U[Untrusted input<br/>feed data, CVE reference URLs,<br/>live IOCs] --> F[SafeFetcher<br/>http/https · 80/443 · public IPs only<br/>IP pinning · per-hop redirect checks]
    F --> L[Local snapshot]
    L -->|cti IAM user:<br/>Get/Put/List one bucket,<br/>no delete, no overwrite| S[(S3: Block Public Access,<br/>SSE-S3, TLS-only, versioned)]
```

- **Untrusted URLs.** Reference URLs come from public CVE records, so the scraper
  validates every hop and connects to the validated IP to defeat DNS rebinding and SSRF
  (`http/safe_fetch.py`, `vault/ssrf-safe-fetching.md`). robots.txt is honored.
- **Malicious content.** IOCs are defanged for display (`hxxp://evil[.]com`); the gold set
  keeps unmodified text privately because entity offsets index into it.
- **Secrets.** Typed settings from `CTI_*` env vars; keys are `SecretStr`; the abuse.ch
  key (which must go in the URL path) is redacted from manifests and errors.
- **Cloud.** One private bucket; a dedicated `cti` IAM user that cannot delete and cannot
  PUT without `If-None-Match` (except the manifest). AWS Budgets alert at $5/month.
  Setup: [`infra/README.md`](../infra/README.md).
- **Supply chain.** Pinned dependencies (`requirements.lock`), pip-audit, gitleaks, and
  GitHub Actions pinned by commit SHA in CI.

## Code map

```
src/cti/
  cli.py             `cti` command: probe / ingest / status / parse / enrich / upload / gold-import
  config.py          typed settings from CTI_* env vars; fail fast on missing values
  models.py          Document: the normalized record every source produces
  ingest.py          one-time ingest: per-source isolation, resume, logged refetch
  snapshot.py        raw snapshot + manifest, write-once
  upload.py          finished snapshot → S3, checksum-verified
  enrich/            offline per-CVE join (cves.py), CWE lookup (cwe.py), page cleaning
                     (cleaner.py, references.py)
  sources/           one module per feed (fetch + parse); registry.py sets ingest order
  references/        reference-link classifier, target selection, scraper, HTML→text
  http/              retrying client, rate limiter, SSRF-safe fetcher
  storage/           LocalStorage, S3Storage, MirroredStorage (no delete)
  gold.py            frozen, checksummed gold set
  defang.py          IOC defanging
```

Module-level detail: `vault/code-layout.md`.
