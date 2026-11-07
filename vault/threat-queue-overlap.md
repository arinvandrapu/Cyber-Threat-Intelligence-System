---
tags: [threats, risk-queue, links, gotcha, dashboard]
---

# Why threats barely link to the risk queue

Finding 2026-11-06 (snapshot 2026-10-26). Sources: [[threat-links]], [[threat-catalog]],
[[risk-scoring-design]], [[dashboard]].

## Counts (all 467 families, 53 links)

| Where the link points | Links |
|---|---|
| CVE already in CISA KEV | 47 |
| Not KEV, pre-2024 (outside the queue): Cobalt Strike CVE-2013-2460, PoshC2 CVE-2016-9192 | 2 |
| Queued CVE, reviewed `rejected`: Meterpreter CVE-2026-2329, Medusa CVE-2024-8877 | 2 |
| Queued CVE, `correct`: CVE-2026-109618 (Mirai, RedTail; ThreatFox tags) | 2 |

1 of 8,392 queued CVEs has an accepted threat link. That CVE is queue rank 3 (critical).

## Root causes

- **Population, by construction.** The queue holds 2024+ CVEs **not** in KEV. A source
  tying a family to a CVE is exploitation evidence, and such CVEs are usually in KEV
  already, so a linked CVE has typically left the queue.
- **Reference pages (26 links).** Scrape selection was KEV first, then snapshot EPSS
  (`references/selection.py`). Of the 1,043 CVEs with pages, 476 are KEV, 262 queued,
  305 other: 3.1% of the queue has any page to search for family names.
- **ATT&CK software (17 links).** It cites mostly 2011–2018 CVEs, outside the queue window.
- **ThreatFox tags (10 links).** Only 16 CVEs are tagged in the whole ThreatFox dataset.
- More coverage for queued CVEs would need a new scrape, which breaks ingest-once
  ([[ingest-once-snapshot]]).

## Consequence

- The Overview's "Threats explain CVEs" is true for KEV, almost never for the queue.
- A threat link on a queued CVE is an early-warning signal (exploitation evidence before
  CISA lists it), not a ranking input: threats never feed the risk score.

## Proposed fixes (not yet approved or built)

1. KEV triage view: rank KEV CVEs by ransomware use + linked active threats (the join
   that actually exists).
2. "Linked to a threat" badge + filter in the queue (11c optional item).
3. Rewrite Overview "How they connect" to match the counts above.
