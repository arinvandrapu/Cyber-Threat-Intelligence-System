---
tags: [aws, security, cost]
---

# AWS: Cost and Security

S3 is the **only** AWS service. All compute runs locally. S3 holds a write-once
archive copy, not the working data: [[s3-archive-not-live-store]].

## Bucket

- One private bucket in us-east-1, S3 Standard (cheapest at <1 GB; IA and
  Intelligent-Tiering add minimums and fees).
- Block Public Access at account and bucket level; ACLs disabled (bucket owner enforced).
- Default SSE-S3 encryption (free). No SSE-KMS (per-request cost).
- Bucket policy denies requests without TLS (`aws:SecureTransport = false`).
- Versioning on, with lifecycle rules: expire noncurrent versions, remove expired delete
  markers, abort incomplete multipart uploads after 1 day.

## Access

- Pipeline uses a dedicated `cti` IAM user/profile: Get/Put/List on this bucket only,
  explicit Deny on `DeleteObject`, `DeleteObjectVersion`, `DeleteBucket`, and on
  `PutObject` without `If-None-Match` except `*/manifest.json` (write-once in IAM; verified
  live 2026-10-26). Templates and
  setup steps: `infra/`. boto3 default credential chain; no keys in code or repo.
- Bucket setup is a one-time admin step, separate from `cti`, never run as root.
- Account ID and bucket name are not committed; they come from local config.

## Cost guardrails

- AWS Budgets alert at $5/month (80% actual, 100% forecast), created **before** the
  bucket. Free (first two budgets per account). It counts the whole account, not only
  this bucket, so it is stricter than needed.
- Cost Anomaly Detection (free; the default monitor is on in new accounts).
- Account-level Block Public Access is on too (it affects every bucket in the account).
- Expected spend: ~2–3k PUTs on upload (≈ $0.015) + ~250 MB stored (≈ $0.006/month).
- No CloudTrail data events.

Used by [[ingest-once-snapshot]]. Data handling: [[data-sources]].
