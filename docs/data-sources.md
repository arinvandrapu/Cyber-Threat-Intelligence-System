# Data Sources

What the pipeline ingests, why each source is there, and how big the resulting corpus
is. How the data flows through the system: [architecture.md](architecture.md). Why it is
captured once: [decisions.md §1](decisions.md#1-ingest-once-into-an-immutable-raw-snapshot).

## The snapshot

All data comes from a **single ingest run** on **2026-10-26** (snapshot `2026-10-26`).
The **cutoff date** is the snapshot minus 180 days, **2026-04-29**. Sources that change
over time are captured **twice**, pinned to their state at the cutoff and at the
snapshot, so the risk model can be scored with cutoff-only data and checked against
what happened afterwards ([decisions.md §4](decisions.md#4-forward-looking-risk-evaluation-with-point-in-time-data)).

| | |
|---|---|
| Sources | 12 (11 feeds + reference pages), all complete |
| Raw snapshot | ≈ 235 MB gzip'd (297 MB including the kept first references attempt) |
| Parsed records | ≈ 70 MB gzip'd JSONL |
| Documents | **≈ 455,900** |
| Point-in-time signal rows | **≈ 1,138,000** |

## Sources

| Source | Provider | Captured | Pinned by | Raw (gz) |
|---|---|---|---|---|
| NVD CVE 2.0 | NIST | Yearly feeds 2023–2026; CVEs published ≥ 2024-01-01 kept | `.meta` SHA-256 + `lastModifiedDate` | 111.9 MB |
| CISA KEV | CISA | Full catalog with `dateAdded` | `catalogVersion` 2026.10.23 | 0.2 MB |
| EPSS | FIRST | Daily scores at cutoff and snapshot | file date + model (v2025.03.14, v2026.06.15) | 5.0 MB |
| CISA Vulnrichment | CISA | SSVC decisions at cutoff and snapshot | git first-parent commit | 4.5 MB |
| ExploitDB | OffSec | `files_exploits.csv` at cutoff and snapshot | GitLab first-parent commit | 4.8 MB |
| Metasploit | Rapid7 | Module metadata at cutoff and snapshot | git first-parent commit | 2.7 MB |
| Nuclei templates | ProjectDiscovery | `cves.json` at cutoff and snapshot | git first-parent commit | 0.9 MB |
| MITRE ATT&CK | MITRE | Enterprise STIX 2.1 bundle | release v20.0 | 9.3 MB |
| MITRE CWE | MITRE | Full catalog XML | release v4.20 | 2.0 MB |
| ThreatFox | abuse.ch | IOCs, last 6 months | fetch time | 4.3 MB |
| URLhaus | abuse.ch | Malicious URLs, last 30 days | fetch time | 4.3 MB |
| Reference pages | many (vendors, researchers) | ≤ 2,000 pages linked from CVE records | fetch time + target list | 84.9 MB |

## Why each source was ingested

### Vulnerabilities: what exists

- **NVD**: the backbone. Every CVE with its description, CVSS, CWE, and reference
  links. The descriptions are the main text corpus for NLP and classification; the
  reference links drive the page scraper. Window starts 2024-01-01 to keep the corpus
  recent and the size manageable.
- **MITRE CWE**: names and descriptions for the weakness IDs NVD attaches to each CVE,
  so a CVE can be explained ("CWE-79: Cross-site Scripting"), not just coded.

### Exploitation: what is being used

- **CISA KEV**: confirmed in-the-wild exploitation. `dateAdded` is the **ground truth**
  for the forward-looking evaluation: CVEs added to KEV after the cutoff are the ones
  the risk model should have ranked highly.
- **EPSS**: FIRST's predicted probability of exploitation in the next 30 days. A strong
  input feature and the main **baseline** the risk model must beat. The model version
  changed between cutoff and snapshot, so the two score sets are never compared directly.

### Prioritization signals: how urgent

- **CISA Vulnrichment**: SSVC decisions (exploitation, automatable, technical impact),
  CISA's own triage of CVEs. Point-in-time state comes only from git history, because
  per-record timestamps are overwritten on rescoring.
- **ExploitDB, Metasploit, Nuclei**: public exploit code, ready-made attack modules,
  and scanner templates. Each lowers the bar for attackers, so their availability *at
  the cutoff* is a risk feature. Captured at both dates to measure what appeared later.

### Adversary behavior: how attacks work

- **MITRE ATT&CK**: 706 techniques and sub-techniques, 842 malware and tool entries,
  178 threat groups. The target vocabulary for technique mapping, and the alias list
  for normalizing malware and group names found by NER.

### Threat activity: what is live right now

- **ThreatFox**: 126,917 IOCs (hashes, domains, IP:port, URLs) tagged with malware
  family and threat type. Feeds IOC extraction tests, the IOC dashboard view, and
  links between malware families and ATT&CK software.
- **URLhaus**: 107,325 malware-distribution URLs. Complements ThreatFox with delivery
  infrastructure. Both are defanged at rest and in display.

### Context: the long-form text

- **Reference pages**: advisories, write-ups, and mailing-list posts linked from CVE
  records, KEV CVEs first, then top EPSS. They carry the detail NVD's one-paragraph
  descriptions lack: affected products, attack chains, malware names, mitigations.
  This is the richest NER input. Scraped politely: robots.txt respected, one honest
  User-Agent, per-host throttling, SSRF-safe fetching.

## Corpus size

Counts from `cti parse` on the 2026-10-26 snapshot.

**Documents** (records with text or IOC content):

| Source | Documents | What they are |
|---|---|---|
| NVD | 168,393 | CVE records with descriptions (published 2024+) |
| ThreatFox | 126,917 | IOCs (last 6 months) |
| URLhaus | 107,325 | malicious URLs (last 30 days) |
| ExploitDB | 47,181 | exploit entries |
| KEV | 1,756 | known-exploited CVEs |
| ATT&CK | 1,726 | techniques, groups, malware, tools |
| Reference pages | 1,653 | full-text advisories and write-ups |
| CWE | 944 | weakness definitions |
| **Total** | **≈ 455,900** | |

**Point-in-time signals** (risk features, not documents):

| Source | Rows (cutoff / snapshot) |
|---|---|
| EPSS | 329,633 / 395,492 |
| Vulnrichment (SSVC) | 145,031 / 202,941 |
| ExploitDB | 24,941 / 25,094 |
| Nuclei | 4,059 / 4,530 |
| Metasploit | 3,100 / 3,200 |
| **Total** | **≈ 1,138,000** |

**Compared with the prototype's ~10k-document corpus:**

- Overall: about **45×** larger.
- Prose text (NVD descriptions + reference pages, ≈ 170k): about **17×**. This is the
  part that matters for NLP and classification.
- IOC feeds (≈ 234k) are short structured records: good for extraction and the
  dashboard, not prose.
- Long-form text is the 1,653 reference pages, deliberately capped at 2,000 targets.
- The evaluation gold set is the same 299 documents, so results stay comparable.

At this scale, transformer inference on CPU over all prose takes hours, so Phase 5
batches and caches it.

## Reference-page coverage

The scraper targets up to 3 pages per CVE (at most 1 per host), 2,000 pages in total.

| | Pages fetched | CVEs with ≥ 1 page |
|---|---|---|
| Final (attempt 2) | 1,653 / 2,000 (83%) | 1,043 / 1,166 |

The first attempt lost 527 slots to CISA's KEV catalog page. That page restates the KEV
feed, and cisa.gov returns 403 to non-browser clients. Selection now skips it, and the
references source was refetched once (logged in the manifest; the first attempt is kept).
The remaining gaps (403s, robots.txt disallows, bot-check pages, 404s) are left alone:
closing them would mean working around a site's wishes.

Pages by type: 696 articles, 654 vendor advisories, 153 GitHub advisories, 123
mailing-list posts, 27 GitHub issues.

**Usable text after cleaning** (`cti enrich`): **1,280 pages covering 842 CVEs**. The
other 373 are 366 pages with no content for a client that doesn't run JavaScript or log in
(application shells such as MSRC's 135, redirect stubs, bot checks, login walls) and 7
PDFs, which are not extracted. Boilerplate removal cuts the median HTML page from 6.7k to 2.8k characters;
35 pages fall back to whole-page text.

## Sources considered and not used

- **PhishTank**: new registrations are disabled.
- **Ransomwatch**: archived in March 2026. Its replacements publish victim names, which
  this project avoids for ethical reasons.
- **Feodo Tracker**: no update since March 2026, and no CVE link.
- **AlienVault OTX**: active, but overlaps the abuse.ch feeds; cut for scope.

See [decisions.md §9](decisions.md#9-drop-sources-that-are-stale-closed-or-ethically-problematic).

## Handling and licensing

- **Raw data never enters this repository.** Several sources restrict redistribution
  (ExploitDB is GPL-2.0; abuse.ch data is under its own terms; scraped pages belong to
  their publishers). Raw data lives on local disk and in a private, write-once S3
  archive. Only code, aggregates, and small defanged samples are published.
- **Attribution**: NVD (NIST), KEV and Vulnrichment (CISA, CC0), EPSS (FIRST), ATT&CK
  and CWE (MITRE), Metasploit (Rapid7, BSD-3), Nuclei templates (ProjectDiscovery, MIT),
  ThreatFox and URLhaus (abuse.ch).
- **Live IOCs are defanged** (`hxxp://`, `[.]`) at rest and in display.
- **abuse.ch keys** travel in the URL path, so recorded URLs and error messages are
  redacted.
