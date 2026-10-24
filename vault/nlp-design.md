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
