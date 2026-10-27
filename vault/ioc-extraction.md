---
tags: [nlp, ioc, evaluation, gotchas]
---

# IOC Extraction (Phase 5a, `cti extract`)

Regex extraction in `src/cti/nlp/iocs.py`; aliases in `nlp/aliases.py`. Design context:
[[nlp-design]]. Outputs never feed risk features: [[risk-scoring-design]].

## Rules worth knowing

- Match on the original text (offsets stay valid); defanged forms (`[.]`, `(.)`, `[dot]`,
  `[:]`, `hxxp`) are matched directly, then `refang`ed. Values stored defanged.
- **Defanged in the source = indicator.** Version and TLD heuristics apply only to plain text.
- **IPv4 vs versions:** reject a version keyword before (`versions … through …`, `up to, and
  including,`), version words after (`through`, `and earlier`, `-r1`, `iFix`), a three-part
  version within 60 chars, or a product name right before (`Netgear EX6200 1.0.3.94`).
  "to" after an address is *not* a cue ("from 8.8.8.8 to 10.0.0.1").
- **Domains:** most plain-text names on new gTLDs are code (`subprocess.run`, `Foo.java`,
  `list.next`). Plain names need a legacy gTLD, a ccTLD, or a TLD common in abuse.ch data
  (≥30 hosts, minus code words). Also rejected: file-extension ccTLDs when bare (`.py`, `.md`,
  `.pl`, `.do`, `.in`), camelCase, `ASP.NET`, `supported.You`, numeric inner labels.
- **tldextract** must be built with `suffix_list_urls=()`, `cache_dir=None`: by default it
  fetches the PSL on first use. A test blocks sockets to prove it.
- **Hashes:** reject commit-ID context (`commit`, `before`, `up to`, `@`, `#`) and digit-only runs.
- **CVSS:** v3.x any order, all 8 base metrics once; v4.0 fixed order, case-sensitive.
- `defang_ip` for IPv6 now brackets colons (`2001[:]db8…`). `[…]` would read as a URL host.

## Aliases

- ATT&CK v20 groups/software plus ThreatFox families. Lookup keys ignore case, spaces and
  hyphens; an ambiguous key returns every candidate (47 such keys).
- Text matching is stricter: the known spelling's case and word count, no match after an
  apostrophe, a stoplist, and a threat cue for plain words. Without these, "in C" matched
  INC, "or at" matched oRAT, and "James" matched a malware alias.

## Evaluation (2026-10-26)

- Review sample: 200 IOCs, seeded, equal allocation over type × origin. Labels are in
  `data/reference/ioc-review-2026-10-26.csv` (doc ID, span, y/n only), labelled by the
  author with an AI assistant. "Correct" = a value of that type, not malicious. Hashes =
  digests (git object and build IDs count; keys, IVs, secrets and Message-IDs don't).
- Results: pages 99.3% (CI 89–100), NVD 88.0% (CI 80–96). NVD IPv4 is 2/12: lists of
  plain version quads (Oracle, IBM) have no keyword to catch.
- Disclosures: the rules were tuned by reading corpus matches before sampling. One rule
  (the "to" cue) was removed after labelling. That only adds candidates (+19 IPv4 of
  about 3,000), and every labelled span still matches.
- Gold set ([[gold-set-provenance]]): only sources that carry a type's labels are scored
  (domains = ThreatFox "Malicious domains" lists). Domain recall 132/140; precision is a
  lower bound, because other real names in those records are unlabelled. IPv4 (circular)
  and CVSS (68 of 103 spans label a version or sub-score) are counted, not scored.
