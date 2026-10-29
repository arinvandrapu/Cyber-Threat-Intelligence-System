---
tags: [nlp, ioc, evaluation, gotchas]
---

# IOC Extraction (Phase 5a, `cti extract`)

Regex extraction in `src/cti/nlp/iocs.py`; aliases in `nlp/aliases.py`. Design context:
[[nlp-design]]. Feature rules (page rows never; NVD rows only in the snapshot-time
ablation): [[risk-scoring-design]].

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
- 2026-10-28: `defang_url` also defangs `ftp`/`sftp` → `fxp`/`sfxp` (`defang_scheme`;
  `refang` undoes both). It had only handled http(s). The current extraction holds 3
  `ftp://` URLs (of ~3.9k); `cti export` normalizes them, and its per-type check refuses
  any live scheme. A re-extract would change `iocs_sha256`.

## Aliases

- ATT&CK v20 groups/software plus ThreatFox families. Lookup keys ignore case, spaces and
  hyphens; an ambiguous key returns every candidate (43 such keys, 2026-10-29).
- Text matching is stricter: the known spelling's case and word count, no match after an
  apostrophe, a stoplist, and a threat cue for plain words. Without these, "in C" matched
  INC, "or at" matched oRAT, and "James" matched a malware alias.
- Fixed 2026-10-29: a ThreatFox family whose own name matched no ATT&CK software joined
  one through any ThreatFox alias, so Bashlite ("Qbot") merged into S0650 QakBot and
  Houdini ("Njw0rm") into S0385 njRAT. Now an alias joins only if it is the ATT&CK entry's
  own title (11 correct joins kept; Tsundere via "DinDoor" lost, conservative). Index:
  `threatfox` 371 → 374 entities, ambiguous keys 40 → 43; one row changed (2 "Gafgyt"
  matches on CVE-2026-34910 → Bashlite). Match counts unchanged.

## Evaluation (2026-10-26)

- Review sample: 200 items, equal allocation over type × origin, taken in seeded-hash
  order of each item's identity (`draw_sample`). That makes it reproducible from code and
  stable when the extractor adds or drops items. Labels are in
  `data/reference/ioc-review-2026-10-26.csv` (doc ID, span, y/n only), made by an AI
  assistant (Claude) and not yet reviewed by the owner.
- Criterion: "correct" = a value of that type, not malicious. Hashes = digests: file
  hashes, git commit/patch IDs, module build IDs and JA3 count. Keys, IVs, secrets,
  Message-IDs, anonymized researcher IDs (ZDI credits) and the hex after `#N` in a kernel
  oops header don't. NVD SHA-1 items are almost all commit or build IDs, not file hashes.
- Results: pages 98.5% (approx. CI 89–100), NVD 89.1% (approx. CI 81–97). Weak strata:
  NVD IPv4 1/12 (plain version lists, RFC or IEEE section numbers), NVD MD5 0/5, page
  SHA-1 7/11. Precision is population-weighted, so CVE IDs carry 56% of the page weight.
- Disclosures: the rules were tuned by reading corpus matches before sampling. After the
  first labelling round, audit fixes changed the extractor (the "to" cue, hash at sentence
  end) and the sampler; the sample was redrawn and 181 items labelled anew.
- Gold set ([[gold-set-provenance]]): an agreement check only, not accuracy. Gold domains
  are regex spans in ThreatFox records (as circular as IPv4) and 59 of 62 CVE spans are
  the record's own ID. Scored only where a source carries that type's labels: domains
  132/140, CVE 59/59. CVSS (68 of 103 spans label a version or sub-score) is counted, not
  scored.
