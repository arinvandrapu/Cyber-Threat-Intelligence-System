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
| Entity extraction | Regex for structured IOCs; `cisco-ai/SecureBERT2.0-NER` (labels: Indicator, Malware, Organization, System, Vulnerability) |
| ATT&CK technique mapping | `cisco-ai/SecureBERT2.0-biencoder` embeddings (the base model is MLM-only), similarity to technique descriptions |
| Text risk signals | Description-derived features only, KEV-language flagged ([[risk-scoring-design]]) |
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
- ATT&CK mapping: graded against the MITRE CTID Mappings Explorer KEV file (ATT&CK 16.1,
  419 CVEs, Apache-2.0). Dev = 284 CVEs outside the corpus; test = 135 in the corpus
  (82 with corpus pages). Primary: hit@5/recall@5 on `exploitation_technique`, technique
  level, vs majority and TF-IDF baselines. KEV-only, so results don't generalize to all CVEs.
- Classification: SecureBERT vs TF-IDF vs the source-only baseline, disclosed as a
  sanity check.

## Open items

- None for model choice (verified 2026-10-27). Phase 5 plan: `tasks/todo.md`.
