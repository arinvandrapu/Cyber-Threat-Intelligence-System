# Future Extensions (after Phase 8 ships)

> E1 and E2 are now **Phase 10** in [todo.md](todo.md) (approved 2026-10-28), which
> supersedes the details below. E2 step 3 is dropped: abuse.ch terms §7.3 forbid
> training AI models on ThreatFox data. E3 follows Phase 10, before Phase 9.

Not started. Pick up only once the dashboard is merged and the current state is stable.
Each extension gets its own pre-registration commit before any test score, like 6b and 7b.

## E1. Better CVE → ATT&CK mapping

Why the current mapping is weak: [vault/attack-mapping.md](../vault/attack-mapping.md)
(bug text vs. behaviour text, 419 labelled CVEs, T1190 + T1068 = half of test, frozen encoder).

### Evaluation hygiene (do first)

- [ ] The current CTID test split (135 CVEs) has been scored. Pick a clean test before
      designing anything: (a) CTID KEV mappings added after commit `e51d7f5`, if a newer
      release exists, or (b) dev-only cross-validation with no new test claim.
- [ ] Pre-register methods, β/weights grid, metrics (hit@1, hit@5, MRR) and the decision
      rule vs. `majority` and the current `prior+biencoder`.

### Methods (structured signals instead of free text)

- [ ] **CVSS rule baseline.** `AV:N` → T1190, `AV:L` + privilege gain → T1068,
      `UI:R` → T1203/T1204. Fields already parsed from NVD (`cvss_nvd`, `cvss_cna`).
- [ ] **CWE → CAPEC → ATT&CK chain.** CWE 4.20 XML already has 1,212
      `Related_Attack_Pattern` links. ATT&CK v20 has **no** CAPEC references (0 of 706),
      so the CAPEC → ATT&CK hop needs CAPEC XML (`Taxonomy_Mappings`) as new pinned
      reference data, committed like the CTID file (SHA-256, licence notice).
      Use the labelled CWE when present, else the Phase 6 classifier's top prediction.
- [ ] **Supervised combiner.** Small logistic model per technique over: CVSS fields,
      CWE/CAPEC candidates, label prior, bi-encoder similarity. Train on dev only.
- [ ] Report per-technique results, not just pooled; check whether gains are still only T1068.

### Stretch

- [ ] Fine-tuning the encoder on CTID pairs is out of scope on CPU with 284 dev CVEs; note why.

## E2. ThreatFox threat categories ("what kind of threat")

Facts from the 2026-10-26 snapshot (`raw/threatfox/*/full.csv.zip`, already parsed in
`sources/abusech.py`):

- 126,917 IOCs, 481 malware families (`fk_malware`, Malpedia-style, e.g. `win.vidar`).
- `threat_type` is coarse and infrastructure-only: payload 47k, botnet_cc 47k,
  payload_delivery 33k, cc_skimming 252. It is **not** phishing/ransomware/stealer.
- Top families: ClearFake 19k, AsyncRAT 17k, Unknown 14k, Vidar 11k, Mirai 8k, Cobalt Strike 4k.
- Only 166 rows (16 CVEs) carry a CVE tag: ThreatFox will **not** link IOCs to the CVE queue
  at scale.
- 39,572 rows have a `reference` URL (threat reports).

### Step 1: family → category taxonomy

- [ ] Define a small category set: ransomware, infostealer, RAT, loader/dropper, botnet,
      banking trojan, C2 framework, web skimmer, fake-update/social engineering, other.
- [ ] Map families to categories for the families covering ~95% of rows (likely <100).
      Sources: Malpedia family descriptions, ATT&CK software entries (match via the existing
      alias index), ThreatFox tags. **Owner reviews every mapping** (human labels, not
      Claude-only), committed as versioned reference data with the source per row.
- [ ] Keep `Unknown malware` as unknown; report its share.

### Step 2: use it in the product (no ML needed)

- [ ] `cti export`: IOC aggregates by category and family (aggregates only, per licence).
- [ ] Dashboard Indicators view: filter by category; trend by `first_seen_utc`.
- [ ] Link families to ATT&CK software IDs and their techniques where the alias index matches.

### Step 3: real threat-report classification (optional, needs new data)

- [ ] ThreatFox `reference` URLs are threat reports labelled by family → category: a
      human-curated label source for **text** classification, which the rule-generated gold set never was.
- [ ] Scraping them breaks "ingest once": it needs an owner-approved, logged supplemental
      fetch (SSRF-safe scraper, robots, caps), recorded in the manifest.
- [ ] Split by time (`first_seen_utc`); group by family so no family is in both train and
      test; baselines: majority, keyword rule, TF-IDF + LR; pre-register first.
- [ ] Licence: abuse.ch content is aggregates-only; report text stays local, never committed.

## E3. Dashboard clarity (owner feedback 2026-10-28)

- [x] **CVE common name.** The CVE detail shows context but nothing says what the CVE is.
      Show a one-line name, not a summary: KEV `vulnerabilityName` when present (e.g.
      "Apache Log4j2 Remote Code Execution Vulnerability"), otherwise a name built from
      data we hold (CWE name + vendor/product), labelled as derived. Exported by `cti export`.
- [x] **Overview page.** Add a description for every tab: what it is, why it's there, and
      how it's calculated, in plain language. Numbers quoted must come from the export.
- Done 2026-10-29: KEV CVEs show CISA's name (10c card); queue CVEs a derived name
  (`export.derived_name`, CNA affected vendor/product + first CWE). Overview opens with
  the two-lists model and a tab guide; jargon labels replaced ("What moved this CVE up
  or down", plain signal names).

## E4. Phishing source (researched 2026-10-29, deferred by the owner)

The capstone's sixth category has no source here (PhishTank closed registrations).
Licences checked 2026-10-29:

- **CERT Polska warning list** (`hole.cert.pl/domains/v2/domains.json`, ~22 MB): "may be
  used by any user for any purpose, including commercial purposes". Domains with
  `InsertDate`/`DeleteDate`, so a point-in-time view is possible. **Only phishing aimed at
  Polish users**: label it that way. Best licence of the options.
- **OpenPhish community**: global, but terms forbid displaying or sharing derived data.
- **Phishing.Database** (MIT): global lists, no timestamps, upstream provenance unclear.
- **PhishStats**: site down (HTTP 502) at check time; terms unknown.
- If built: a separate reference snapshot (like `cti fetch-nvd-archive`), aggregates on the
  Indicators view, not a malware category in the threat catalog.

