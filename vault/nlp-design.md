---
tags: [design, nlp, ml]
---

# NLP Design

Status: **in the build plan (2026-10-24)**. SecureBERT 2.0 is a core Phase 5
deliverable, not a stretch goal.

## Where NLP applies

Structured fields (CVSS, EPSS, KEV, ExploitDB) are tabular features, not NLP.
NLP works on free text: CVE descriptions, scraped reference pages, ATT&CK technique text.

| Job | Tool |
|---|---|
| Entity extraction | Regex for structured IOCs; `cisco-ai/SecureBERT2.0-NER` for malware, products, orgs |
| ATT&CK technique mapping | SecureBERT 2.0 embeddings, similarity to technique descriptions |
| Text risk signals | NER and embedding features fed into the risk model |
| Category classification | Gold-set sanity check only; see [[gold-set-provenance]] |

## Reference-page corpus (Phase 4, `data/enriched/<date>/references.jsonl.gz`)

- `in_corpus` = at least 200 chars of cleaned text. 2026-10-26: 1,280 of 1,653 pages, 842
  CVEs. Excluded rows stay, flagged: `js_shell` (366: no content without JavaScript or a
  login: app shells like MSRC 135, redirect stubs, bot checks, login walls) and
  `pdf_skipped` (7); `too_short` for anything else under 200 chars.
- Cleaning: trafilatura (tables kept, links/comments dropped, `deduplicate=False` for
  determinism); fallback only when it returns < 200 chars (35 pages). "Kept < 25%" and
  "own CVE dropped" checks were rejected: they misfired on 40% of correct extractions.
- A page's CVE is in its row (`cve`), not necessarily in its text (697/1,268 mention it).
- Never a risk feature (see [[risk-scoring-design]]).

## Role split

- **SecureBERT 2.0**: language understanding. Runs locally on CPU; ~150M params,
  one-time batch.
- **scikit-learn**: tabular risk model (LR/GBM), TF-IDF baseline, and metrics. A
  transformer is the wrong tool for tabular scoring.

## Evaluation

- Risk: an ablation with and without SecureBERT text features, using the
  forward-looking KEV evaluation in [[risk-scoring-design]].
- ATT&CK mapping: graded against the MITRE CTID Mappings Explorer CVE→ATT&CK
  mappings (to verify).
- Classification: SecureBERT vs TF-IDF vs the source-only baseline, disclosed as a
  sanity check.

## Open items

- Verify the base-model ID for embeddings.
- Verify Mappings Explorer coverage and format.
