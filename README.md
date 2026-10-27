# Cyber Threat Intelligence System

A threat intelligence pipeline that collects vulnerability and indicator-of-compromise (IOC)
data from public sources, enriches and prioritizes it, and presents it in a local analyst
dashboard.

> **Status: in development.** The project is being built in phases. See the
> [build plan](tasks/todo.md) for scope and progress. Sections marked *planned* describe
> work that is not implemented yet.

## The problem

Security teams face tens of thousands of new CVEs and a constant stream of IOCs every
year. Severity scores alone don't say what to fix first: most "high" and "critical"
vulnerabilities are never exploited. This project answers a practical analyst question:
**which threats deserve attention first, and why?**

## What it does *(planned)*

- **Collects** CVEs (NVD), known-exploited vulnerabilities (CISA KEV), exploit-likelihood
  scores (FIRST EPSS), public exploits (ExploitDB), attacker techniques (MITRE ATT&CK),
  weakness types (MITRE CWE), CISA SSVC triage (Vulnrichment), weaponized exploits
  (Metasploit, Nuclei), and IOCs (abuse.ch ThreatFox and URLhaus), all in a single
  reproducible ingest.
- **Enriches** each CVE with exploit availability, KEV status, EPSS, CWE, and the content
  of its reference pages, fetched with an SSRF-safe scraper.
- **Extracts IOCs** (IPs, domains, URLs, file hashes, CVE IDs, CVSS vectors) from advisory
  and threat-report text with validated, defang-aware regexes, and normalizes threat-actor
  and malware names (APT28 = Fancy Bear = Sednit) to MITRE ATT&CK IDs.
- **Understands text** with SecureBERT 2.0, a cybersecurity language model: extracts
  malware, products, and organizations, and maps CVEs to ATT&CK techniques.
- **Prioritizes** vulnerabilities with a risk score validated against real-world
  exploitation, so the top tier is small and meaningful.
- **Presents** the results in a localhost Next.js dashboard and as STIX 2.1 output.

## Architecture

```mermaid
flowchart LR
    A[Public sources<br/>NVD · KEV · EPSS · Vulnrichment<br/>ExploitDB · Metasploit · Nuclei<br/>ATT&CK · CWE · abuse.ch] -->|one-time ingest| B[(Raw snapshot<br/>local disk)]
    B -->|write-once copy| S[(S3 archive)]
    B --> C[Parse to documents]
    C --> D[Enrich]
    D --> X[Extract<br/>regex IOCs · aliases]
    X --> E[NLP: SecureBERT 2.0<br/>NER · ATT&CK mapping]
    E --> F[Risk scoring]
    F --> G[Exports<br/>JSON · STIX 2.1]
    G --> H[Localhost dashboard]
```

Ingest, snapshot, parse, S3 upload, enrichment (per-CVE join, reference-page cleaning),
and IOC/alias extraction are built; SecureBERT NER, ATT&CK mapping, and scoring are
*planned*.

## Results so far

IOC extraction over the 2026-10-26 snapshot (1,280 cleaned reference pages and 168,393 NVD
descriptions). Numbers come from `cti extract` and `cti extract-eval`.

| Measure | Result |
|---|---|
| IOCs from reference pages | 25,681 (CVE IDs 14,433, SHA-256 4,654, URLs 2,330, IPv4 1,446, CVSS vectors 1,594, domains 938) |
| Precision, reference pages (200-IOC review sample) | 99.3% (95% CI 89.4–100%) |
| Precision, NVD descriptions | 88.0% (95% CI 79.6–96.3%); weakest: IPv4, 2 of 12, because version numbers like `11.0.32.1` look like addresses |
| Gold-set recall | CVE IDs 59/59; domains 132/140 (94.3%) |

The review sample is stratified by IOC type and text origin and was labelled by the
author with an AI assistant. "Correct" means the span really is a value of that type
(an address, hostname, digest), not that it is malicious. The gold set is rule-generated,
so it is a sanity check only; its IPv4 and CVSS labels are not scored (see
[`vault/ioc-extraction.md`](vault/ioc-extraction.md)).

- [Architecture](docs/architecture.md): stages, storage layout, point-in-time data,
  security boundaries.
- [Data sources](docs/data-sources.md): every source, why it is ingested, and corpus size.
- [Design decisions](docs/decisions.md): why each choice was made and what it costs,
  e.g. why S3 is a write-once archive rather than the pipeline's working store.

## Security skills and tools

| Area | Skills | Tools |
|---|---|---|
| Threat intelligence | CVE/KEV/EPSS analysis, IOC extraction and defanging, threat-actor alias normalization, MITRE ATT&CK mapping, STIX 2.1 | NVD, CISA KEV, FIRST EPSS, MITRE ATT&CK/CWE, abuse.ch, tldextract (Public Suffix List) |
| Vulnerability management | Risk-based prioritization, forward-looking evaluation | Python, pandas, scikit-learn |
| Secure engineering | SSRF defense, secrets management, least-privilege IAM, threat modeling (STRIDE) | httpx, pydantic, GitHub Actions, pip-audit, secret scanning |
| Cloud security | Private, encrypted, TLS-only storage; cost guardrails | AWS S3, IAM, AWS Budgets |
| NLP / ML | Security-domain NER and embeddings, risk modeling, baselines and ablations, boilerplate removal on untrusted HTML | SecureBERT 2.0, Hugging Face Transformers, scikit-learn, trafilatura, lxml |
| Visualization | Analyst dashboard | Next.js, TypeScript, Tailwind CSS |

## Design principles

- **Ingest once.** A single, auditable data pull. Everything downstream is reproducible
  from the stored snapshot without touching the network again.
- **Low cost.** S3 is the only cloud service; all compute runs locally.
- **Honest metrics.** Every reported number is produced by a script in this repo, next to
  the baselines it should beat.
- **Safe handling of malicious data.** IOCs are defanged, and the scraper refuses
  internal and cloud-metadata addresses.
- **Responsible data use.** Raw feed data is never redistributed; feed terms of use are
  respected.

## Setup

Requirements: Python 3.12+. Later phases add Node.js 20+ (dashboard), an AWS account
(S3 only), and a free abuse.ch Auth-Key.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -c requirements.lock -e '.[dev,enrich]'
cp .env.example .env   # fill in values; .env is gitignored
pytest                 # offline: no network or AWS access needed
ruff check .
```

## Usage

```bash
cti probe                       # cheap check that every source is reachable / keys work
cti ingest --date 2026-10-25    # the one-time fetch into data/snapshots/<date>/
cti ingest --date 2026-10-25 --resume                       # continue after a failure
cti ingest --date 2026-10-25 --refetch kev --reason "..."   # logged, keeps old copy
cti status --date 2026-10-25    # manifest: files, sizes, pinned versions, refetches
cti parse  --date 2026-10-25    # offline: raw snapshot -> data/processed/<date>/*.jsonl.gz
cti enrich --date 2026-10-25    # offline: per-CVE join + cleaned reference pages -> data/enriched/<date>/
cti extract --date 2026-10-25   # offline: regex IOCs + alias mentions -> data/extracted/<date>/
cti extract-eval --date 2026-10-25 --labels data/reference/ioc-review-2026-10-26.csv  # precision
cti upload --date 2026-10-25 --gold  # write-once copy to S3 (checksums verified)
cti gold-import --gold ... --entities ... --corpus ...  # one-time: freeze the gold set
```

One-time AWS setup (budget alert, hardened bucket, least-privilege `cti` user):
[`infra/README.md`](infra/README.md).

## Project layout

```
src/cti/
  config.py          typed settings from CTI_* env vars; fail fast on missing values
  models.py          Document: the normalized record every source produces
  snapshot.py        immutable raw snapshot + manifest (ingest runs once)
  http/
    client.py        retrying HTTP client (429/5xx only, Retry-After aware)
    ratelimit.py     sliding-window rate limiter
    safe_fetch.py    SSRF-safe fetcher for untrusted URLs
  storage/           local, S3, and mirrored backends (no delete operation)
  sources/           one module per feed: fetch raw (network) + parse (offline)
  ingest.py, cli.py  one-time ingest orchestration and the `cti` command
  upload.py          write-once, checksum-verified copy of a snapshot to S3
  enrich/            per-CVE join with leakage-safe point-in-time features; CWE lookup;
                     reference-page cleaning (boilerplate removal, JS-shell detection)
  nlp/               regex IOC extraction, alias normalizer, extraction evaluation
  defang.py          make IOCs non-clickable (hxxp, [.]) and undo common defang forms
  references/        reference-link classifier, page selection, polite SSRF-safe scraper
  gold.py            frozen, checksummed evaluation gold set
tests/unit/          offline unit tests
docs/                architecture, design decisions, data sources
infra/               AWS policy templates + one-time setup steps
vault/               design notes
tasks/todo.md        build plan and progress
```

## What this project demonstrates

- Turning raw threat feeds into **prioritized, explainable** intelligence.
- **Secure-by-design** engineering: SSRF protection, least-privilege cloud access, secret
  hygiene, and a documented threat model.
- **Measurement discipline**: risk scores evaluated against real exploitation outcomes,
  not assumed.
- Building **end to end**: ingestion, processing, cloud storage, evaluation, and UI.
