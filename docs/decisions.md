# Design Decisions

Each entry records a decision, why it was made, the alternatives considered, and what it
costs. The system itself is described in [architecture.md](architecture.md).

Several decisions respond to lessons from an earlier team prototype of a similar
pipeline (a university capstone), referred to below as *the prototype*.

## Index

1. [Ingest once into an immutable raw snapshot](#1-ingest-once-into-an-immutable-raw-snapshot)
2. [S3 as a write-once archive, not a live working store](#2-s3-as-a-write-once-archive-not-a-live-working-store)
3. [All compute runs locally](#3-all-compute-runs-locally)
4. [Forward-looking risk evaluation with point-in-time data](#4-forward-looking-risk-evaluation-with-point-in-time-data)
5. [Pin git-hosted feeds by first-parent history](#5-pin-git-hosted-feeds-by-first-parent-history)
6. [A custom, minimal SSRF-safe fetcher](#6-a-custom-minimal-ssrf-safe-fetcher)
7. [SecureBERT 2.0 for text, scikit-learn for tabular risk](#7-securebert-20-for-text-scikit-learn-for-tabular-risk)
8. [Report the gold set as a sanity check, not accuracy](#8-report-the-gold-set-as-a-sanity-check-not-accuracy)
9. [Drop sources that are stale, closed, or ethically problematic](#9-drop-sources-that-are-stale-closed-or-ethically-problematic)

---

## 1. Ingest once into an immutable raw snapshot

**Decision.** `cti ingest` runs once and stores raw source responses unmodified (gzip'd)
with a manifest of SHA-256, fetch time, and source version. Parsing is a separate offline
step. A second ingest is refused; the only exception is a logged
`--refetch <source> --reason …`, which keeps the old copy.

**Why.**
- A parser bug costs a re-parse, not a re-download. Sources rate-limit, and some (EPSS,
  KEV, live IOC feeds) change daily, so a re-download gives *different* data.
- The dataset behind every reported number is fixed and auditable.
- Minimal API load on public sources.

**Alternatives.** Fetch-and-parse in one pass (the prototype's model); scheduled
incremental ingests. Both make results depend on when the pipeline last ran.

**Cost.** Everything a later phase needs must be in the data contract
(`tasks/todo.md`) before the real run, including scraped reference pages.

## 2. S3 as a write-once archive, not a live working store

**Decision.** The ingest writes to local disk. After `cti parse` validates the snapshot,
`cti upload` copies it to S3 once. Uploads cannot overwrite (`If-None-Match: *`, also
enforced in IAM), the storage layer has no delete, and reads verify SHA-256. No pipeline
stage reads from S3, and processed output is not stored there.

**How the prototype differed.** It used S3 as its live store: every stage wrote to the
bucket with `put_object` as it ran (raw CVEs under `nist/cve/YYYY/MM/DD/`, enrichment
under `enriched/…`, then corpus and NLP output), and later stages read their input back
with `get_object`. Nothing prevented re-fetching, so each run added new dated folders
and there was no record of exactly which data a result came from.

**Why not do the same here.**
1. **Compute is local** ([decision 3](#3-all-compute-runs-locally)). With one machine,
   routing every parse, re-parse, and NLP run through S3 adds latency, request charges,
   and a network dependency, with no benefit. In the prototype a shared bucket made
   sense because several people and machines worked on the same data.
2. **Cost.** At ~250 MB, storage is cents. What grows with iteration is requests and
   egress. A live store is hit on every run; an archive gets one upload (~2–3k PUTs,
   ≈ $0.015) and is almost never read.
3. **Reproducibility.** The forward-looking evaluation
   ([decision 4](#4-forward-looking-risk-evaluation-with-point-in-time-data)) is only
   valid if the data is frozen at a point in time. A live store that gains new data and
   overwritten objects on every run is what made the prototype's metrics untraceable.
   A write-once, checksummed snapshot is evidence.
4. **Blast radius.** A live store needs credentials that can write and overwrite all the
   time. Here S3 credentials are used only during `cti upload`, and even then cannot
   overwrite or delete.

**When a live store would be right.** A scheduled cloud ingest (Lambda/ECS), several
collaborators or machines sharing data, or data too large for a laptop. None apply. If a
scheduled ingest is added later, the snapshot layout (`<id>/raw/<source>/<attempt>/…`)
carries over unchanged; only where the code runs would change.

## 3. All compute runs locally

**Decision.** S3 is the only AWS service. Parsing, SecureBERT 2.0 inference (~150M
params, CPU, one-time batch), and modeling run on the owner's laptop. No EC2, Lambda,
SageMaker, KMS, or CloudTrail data events.

**Why.** Near-zero spend (expected well under $1/month; Budgets alert at $5), a smaller
cloud attack surface, and the workload fits on one machine.

**Cost.** Not suitable for continuous collection; this is a reproducible batch study.

## 4. Forward-looking risk evaluation with point-in-time data

**Decision.** Score CVEs using only data as of a cutoff (snapshot − 180 days), then
measure which were added to CISA KEV after the cutoff. Report precision@50/100 and
PR-AUC against CVSS-only and EPSS-only baselines. Tier thresholds come from these
results.

**Why.** The prototype tiered ~94% of items "high" using hand-tuned weights that were
never validated, so the tiers ranked nothing. Predicting future KEV additions is an
honest test that the score finds what attackers actually exploit.

**Cost.** The ingest must capture cutoff copies of EPSS, ExploitDB, Metasploit, Nuclei,
and Vulnrichment, and fields that leak KEV status (NVD `cisa*`, Vulnrichment ADP `kev`,
Nuclei `kev`/`epss` tags) are dropped at parse time. KEV additions are rare, so counts
and intervals are reported with the metrics.

## 5. Pin git-hosted feeds by first-parent history

**Decision.** For Vulnrichment, Metasploit, and Nuclei, the cutoff state is the branch
head found with `git rev-list -1 --first-parent --before=<cutoff>` on a treeless,
shallow clone. ExploitDB uses GitLab's `first_parent=true&until=…`.

**Why.** GitHub's commits API `until=` filters by committer date over every reachable
commit. A PR commit dated before the cutoff but merged after it would be returned, and
its tree contains files that were not on the branch at the cutoff: leakage.

## 6. A custom, minimal SSRF-safe fetcher

**Decision.** Reference URLs from public CVE records are untrusted, so they are fetched
through a ~150-line fetcher on httpx (`http/safe_fetch.py`): http/https on ports 80/443
only, every resolved address must be globally routable, connections go to the validated
IP (Host header and SNI carry the real name), and redirects are followed manually and
re-validated (max 3).

**Why.** Each control is visible and tested. Advocate is archived (2023); `httpx-secure`
hides the controls inside a dependency.

**Cost.** Extra review found subtle issues that had to be fixed (pooled TLS connections
skipping cert checks, proxy env vars, slow-drip responses), now covered by tests.

## 7. SecureBERT 2.0 for text, scikit-learn for tabular risk

**Decision.** SecureBERT 2.0 handles language: NER (malware, products, orgs) and ATT&CK
technique mapping by embedding similarity. scikit-learn handles the tabular risk model
(LR/GBM), the TF-IDF baseline, and metrics.

**Why.** CVSS, EPSS, KEV, and exploit availability are tabular features; a transformer
is the wrong tool for them. Text features are added to the risk model and their value is
measured by an ablation, not assumed.

## 8. Report the gold set as a sanity check, not accuracy

**Decision.** The 299-document classification gold set (inherited from the prototype)
is frozen and checksummed, and results on it are reported next to source-only and
majority baselines as a sanity check.

**Why.** Its labels are rule-generated, not hand-labeled, and most equal the label
implied by the document's source feed, so a source-only predictor scores very high. Presenting that as real-world
accuracy would be misleading. The stronger evaluation is
[decision 4](#4-forward-looking-risk-evaluation-with-point-in-time-data).

## 9. Drop sources that are stale, closed, or ethically problematic

**Decision.** Not used: PhishTank (registrations closed), Ransomwatch (archived; its
replacements publish victim names), Feodo Tracker (no updates since 2026-03, no CVE
link), AlienVault OTX (overlaps abuse.ch; cut for scope).

**Why.** Fewer, maintained sources with clear terms beat a long list of stale ones, and
publishing ransomware victim names is not something this project does.
