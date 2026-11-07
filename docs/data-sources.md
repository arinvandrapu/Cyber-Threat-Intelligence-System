# Data Sources

What the pipeline ingests, why each source is there, and how big the resulting corpus
is. How the data flows through the system: [architecture.md](architecture.md). Why it is
captured once: [decisions.md §1](decisions.md#1-ingest-once-into-an-immutable-raw-snapshot).

## The snapshot

All data comes from a **single ingest run** on **2026-10-26** (snapshot `2026-10-26`).
The **cutoff date** is the snapshot minus 180 days, **2026-04-29**. Sources that change
over time are captured at **five dates**: four cutoffs 180 days apart (2024-11-05,
2025-05-04, 2025-10-31, 2026-04-29) and the snapshot. The risk model is scored with
cutoff-only data and checked against what happened afterwards, one rolling-origin fold
per later cutoff ([decisions.md §4](decisions.md#4-forward-looking-risk-evaluation-with-point-in-time-data)).

| | |
|---|---|
| Sources | 12 (11 feeds + reference pages), all complete |
| Raw snapshot | ≈ 335 MB gzip'd with all five capture dates (63 objects in S3); per-source sizes below are from the first two-date capture |
| Parsed records | ≈ 70 MB gzip'd JSONL |
| Documents | **≈ 455,900** |
| Point-in-time signal rows (latest cutoff + snapshot) | **≈ 1,138,000** |

## Sources

| Source | Provider | Captured | Pinned by | Raw (gz, first capture) |
|---|---|---|---|---|
| NVD CVE 2.0 | NIST | Yearly feeds 2023–2026; CVEs published ≥ 2024-01-01 kept | `.meta` SHA-256 + `lastModifiedDate` | 111.9 MB |
| CISA KEV | CISA | Full catalog with `dateAdded` | `catalogVersion` 2026.10.23 | 0.2 MB |
| EPSS | FIRST | Daily scores at each cutoff and the snapshot | file date + model (v2023.03.01, v2025.03.14, v2026.06.15) | 5.0 MB |
| CISA Vulnrichment | CISA | SSVC decisions at each cutoff and the snapshot | git first-parent commit | 4.5 MB |
| ExploitDB | OffSec | `files_exploits.csv` at each cutoff and the snapshot | GitLab first-parent commit | 4.8 MB |
| Metasploit | Rapid7 | Module metadata at each cutoff and the snapshot | git first-parent commit | 2.7 MB |
| Nuclei templates | ProjectDiscovery | `cves.json` at each cutoff and the snapshot | git first-parent commit | 0.9 MB |
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
  changes between dates, so scores from different dates are never compared directly.

### Prioritization signals: how urgent

- **CISA Vulnrichment**: SSVC decisions (exploitation, automatable, technical impact),
  CISA's own triage of CVEs. Point-in-time state comes only from git history, because
  per-record timestamps are overwritten on rescoring.
- **ExploitDB, Metasploit, Nuclei**: public exploit code, ready-made attack modules,
  and scanner templates. Each lowers the bar for attackers, so their availability *at
  the cutoff* is a risk feature. Captured at every date to measure what appeared later.

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

**Point-in-time signals** (risk features, not documents; latest cutoff and snapshot only):

| Source | Rows (2026-04-29 / snapshot) |
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

## Reference data (pinned, outside the snapshot)

Fixed reference files used by the ATT&CK evaluations and the threat layer. They are not
part of the 2026-10-26 snapshot and are not uploaded to S3. Files under `data/reference/`
are committed, each with a `NOTICE.md` (source, commit, licence), and every read checks
the SHA-256 pinned in code (`cti.reference.PINNED`; `attack_eval.CTID_SHA256` for the KEV
mappings), so an edited or updated copy cannot change a result.

| Data | Provider | Used for | Pinned by | Licence |
|---|---|---|---|---|
| KEV → ATT&CK mappings (Mappings Explorer, ATT&CK 16.1) | MITRE CTID | Ground truth for `cti attack-eval`; training labels for `cti attack-eval2` | commit `e51d7f5` + SHA-256 | Apache-2.0 |
| `attack_to_cve` | MITRE CTID | Held-out test set for `cti attack-eval2` (CVEs not in the KEV mappings) | commit `191e870` + SHA-256 | Apache-2.0 |
| CAPEC 3.9 | MITRE | CWE → CAPEC → ATT&CK chain in `cti attack-eval2` | release zip SHA-256 | MITRE CAPEC terms of use (copyright notice kept) |
| MISP galaxy, 9 clusters (ransomware, stealer, rat, botnet, banker, backdoor, tool, exploit-kit, cryptominers) | MISP project | Family → category labels in `cti threats` for families without a manual label | commit `24877de` + SHA-256 of the trimmed files | CC0 1.0 or BSD-2-Clause |
| NVD yearly feeds 2002–2022 | NIST | CVE text for the `cti attack-eval2` test CVEs (2008–2020) and NVD cards for older linked CVEs | `.meta` SHA-256 + `lastModifiedDate` | As the main NVD feeds |

- **MISP clusters are trimmed, not byte copies.** `cti.reference.trim_misp_cluster()` keeps
  names, synonyms, descriptions and links and drops ransom notes, leak-site links, prices,
  payment methods, suspected victims and Tor (.onion) links. The upstream SHA-256s are in
  the notice. Malpedia's cluster is not used: CC BY-NC-SA, and it has no category field.
- **The NVD archive** is fetched once by `cti fetch-nvd-archive` into
  `data/reference-snapshots/2026-10-29/`: 21 feeds, ≈ 125 MiB (131 MB) gzip'd, 203,721 non-rejected
  CVEs. It is local only (NVD data stays out of the repository like the main snapshot) and
  is not a risk source.

## Handling and licensing

- **Raw data never enters this repository.** Several sources restrict redistribution
  (ExploitDB is GPL-2.0; abuse.ch data is under its own terms; scraped pages belong to
  their publishers). Raw data lives on local disk and in a private, write-once S3
  archive. Only code, aggregates, and small defanged samples are published.
- **Attribution**: NVD (NIST), KEV and Vulnrichment (CISA, CC0), EPSS (FIRST), ATT&CK,
  CWE and CAPEC (MITRE), CTID Mappings Explorer and `attack_to_cve` (MITRE Center for
  Threat-Informed Defense, Apache-2.0), MISP galaxy (MISP project, CC0 / BSD-2-Clause),
  Metasploit (Rapid7, BSD-3), Nuclei templates (ProjectDiscovery, MIT), ThreatFox and
  URLhaus (abuse.ch).
- **Live IOCs are defanged** (`hxxp://`, `[.]`) at rest and in display.
- **abuse.ch keys** travel in the URL path, so recorded URLs and error messages are
  redacted.
