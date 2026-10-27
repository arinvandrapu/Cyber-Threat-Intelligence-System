---
tags: [design, nlp, ml]
---

# NLP Design

Status (2026-10-27): regex IOCs and aliases built (Phase 5a, [[ioc-extraction]]);
ATT&CK grading harness and baselines built (5b-1, [[attack-mapping]]); SecureBERT 2.0
NER, embeddings and prior+bi-encoder ATT&CK mapping built (5b-2).

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

## SecureBERT 2.0 in practice (5b-2, 2026-10-27)

- Pinning: NER `cisco-ai/SecureBERT2.0-NER@792db5b`, bi-encoder `@b42d43a`; safetensors +
  JSON only, no `trust_remote_code`, `local_files_only`. The SHA-256 of every loaded file
  (weights, config, tokenizer) is pinned in `nlp/models.py` and re-checked on every load
  (`cti models verify`). The cache already
  held the NER weights; they matched the pin.
- NER label scheme (CyNER): **CVE IDs are tagged Indicator**, not Vulnerability.
  Vulnerability marks bug descriptions ("Missing Authorization Vulnerability"). Spans
  often include context words ("exploiting", "the FBI"). APT names can come out as
  Malware ("Volt Typhoon").
- The stock pipeline's "simple" aggregation splits words at byte-level BPE pieces
  (`X`/`-`/`Agent`). Token offsets include the leading space, so a "same word" fragment is
  one that touches the previous token and doesn't start with whitespace. Output is
  padding-invariant (same spans alone or batched).
- Gold sanity check (`cti ner-eval`, text-derived spans, overlap recall): Indicator 1.0,
  Malware 0.78, Organization 0.29, System 0.26. Precision is a lower bound (the gold set is
  incomplete and rule-generated; [[gold-set-provenance]]).
- Corpus run (`cti ner`, 1,280 pages, 10 min CPU): noisy on code, tables and logs (far
  from CyNER prose). Indicator 181k spans, 46k of them on 5 pages. Top "Malware" spans
  include "for", "CWE", "exposed". All spans are kept with scores. Displays use score ≥ 0.9
  (`CONFIDENT`) or an alias link; spot sample: junk median 0.61, real families 0.94.
- `link()` respects the alias stoplist (66 "payload" spans had linked to ThreatFox
  "Payload" through `lookup()`).
- ATT&CK: the bi-encoder alone loses to the label prior. Prior + bi-encoder wins on
  test, almost all of it through T1068 under a time shift, and it is β-sensitive
  ([[attack-mapping]]).
